// SPDX-License-Identifier: AGPL-3.0-or-later
package zkapi_e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const apiBodyLimit = 1 << 20

type apiHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type apiResult struct {
	Format   string      `json:"format"`
	Method   string      `json:"method"`
	Path     string      `json:"path"`
	Upstream string      `json:"upstream"`
	Status   int         `json:"status"`
	Headers  []apiHeader `json:"headers"`
	Body     string      `json:"body_base64"`
}
type capture struct {
	method string
	header http.Header
	body   []byte
}

// This test reaches only an owned local TLS fixture, never a real external API.
func TestZKAPIGatewayIntegration(t *testing.T) {
	cli := os.Getenv("ZKWEB_ZK_CLI")
	if cli == "" {
		t.Skip("make test-zk builds the optional real ZK API gateway")
	}
	if !filepath.IsAbs(cli) {
		t.Fatal("explicit absolute CLI required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	directory := t.TempDir()
	var calls atomic.Int32
	var fixtureFailure atomic.Bool
	const credential = "Bearer fixture-server-only"
	defaultBody := []byte{0, 255, 128, 1}
	upstream, rootCA := caIssuedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS == nil || r.Header.Get("Authorization") != credential || r.Header.Get("X-Unbound") != "" {
			fixtureFailure.Store(true)
		}
		for name := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-zkweb-") {
				fixtureFailure.Store(true)
			}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, apiBodyLimit+1))
		if err != nil || len(body) > apiBodyLimit {
			fixtureFailure.Store(true)
			http.Error(w, "invalid fixture body", 400)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Upstream", "visible")
		w.Header().Set("Set-Cookie", "fixture-private-session=value")
		w.Header().Set("Authorization", "fixture-response-secret")
		w.Header().Set("Connection", "X-Private-Hop")
		w.Header().Set("X-Private-Hop", "must-be-stripped")
		switch r.URL.Path {
		case "/v1/redirect":
			w.Header().Set("Location", "/v1/redirected")
			w.WriteHeader(307)
			_, _ = w.Write([]byte("redirect"))
			return
		case "/v1/redirected":
			fixtureFailure.Store(true)
			http.Error(w, "unexpected redirect follow", 500)
			return
		case "/v1/unauthorized":
			w.WriteHeader(401)
			_, _ = w.Write([]byte("provider credentials rejected"))
			return
		case "/v1/failure":
			w.WriteHeader(503)
			_, _ = w.Write([]byte("provider unavailable"))
			return
		case "/v1/oversized":
			_, _ = w.Write(make([]byte, apiBodyLimit+1))
			return
		case "/v1/drop":
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		if r.URL.Path != "/v1/echo" || r.URL.RawQuery != "raw=%2F&same=1&same=2" {
			fixtureFailure.Store(true)
		}
		if got := r.Header.Values("X-Echo"); len(got) != 2 || got[0] != "first" || got[1] != "second" {
			fixtureFailure.Store(true)
		}
		if len(body) == 0 {
			body = defaultBody
		}
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	ca := filepath.Join(directory, "upstream-ca.pem")
	if err := os.WriteFile(ca, rootCA, 0600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(directory, "operator-headers.json")
	if err := os.WriteFile(credentials, []byte(`{"Authorization":"`+credential+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	setup, err := run(ctx, cli, "zk-setup", "--output", filepath.Join(directory, "profile"), "--members", "2")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ServerDir  string   `json:"server_dir"`
		ClientDirs []string `json:"client_dirs"`
		ProfileID  string   `json:"profile_id"`
	}
	if json.Unmarshal(setup, &profile) != nil || len(profile.ClientDirs) != 2 {
		t.Fatal("invalid setup")
	}
	base := []string{"--server-dir", profile.ServerDir, "--upstream", upstream.URL, "--allow-private-upstream", "--allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS", "--upstream-path-prefix", "/v1/", "--upstream-headers-file", credentials}
	gateway, stop := startGateway(t, ctx, cli, append(append([]string{}, base...), "--upstream-ca-file", ca))
	defer stop()
	var mode atomic.Int32
	var mu sync.Mutex
	var captured []capture
	var responseFailures atomic.Bool
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	forward := &http.Client{Transport: transport, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, apiBodyLimit+1))
		if err != nil || len(body) > apiBodyLimit {
			responseFailures.Store(true)
			http.Error(w, "test body invalid", 400)
			return
		}
		headers := r.Header.Clone()
		if r.URL.Path == "/api" {
			mu.Lock()
			captured = append(captured, capture{r.Method, headers.Clone(), append([]byte(nil), body...)})
			mu.Unlock()
			switch mode.Load() {
			case 1:
				body = append(body, 1)
			case 2:
				headers.Set("X-ZkWeb-Api-Method", "PATCH")
			case 3:
				headers.Set("X-ZkWeb-Api-Path", base64.StdEncoding.EncodeToString([]byte("/v1/changed")))
			case 4:
				headers.Set("X-ZkWeb-Api-Headers", base64.StdEncoding.EncodeToString([]byte(`[{"name":"x-echo","value":"changed"}]`)))
			case 5:
				proof, _ := base64.StdEncoding.DecodeString(headers.Get("X-ZkWeb-Proof"))
				if len(proof) > 0 {
					proof[len(proof)/2] ^= 1
				}
				headers.Set("X-ZkWeb-Proof", base64.StdEncoding.EncodeToString(proof))
			}
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, gateway+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			responseFailures.Store(true)
			http.Error(w, "test forward invalid", 502)
			return
		}
		request.Header = headers
		request.Header.Set("X-Unbound", "not signed and must not escape")
		response, err := forward.Do(request)
		if err != nil {
			responseFailures.Store(true)
			http.Error(w, "test forwarding failed", 502)
			return
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 3<<20))
		if err != nil {
			responseFailures.Store(true)
			http.Error(w, "test read failed", 502)
			return
		}
		if r.URL.Path == "/challenge" && mode.Load() == 6 {
			var challenge map[string]any
			if json.Unmarshal(raw, &challenge) == nil {
				challenge["upstream_origin"] = "https://wrong.example"
				raw, _ = json.Marshal(challenge)
			}
		}
		for name, values := range response.Header {
			w.Header()[name] = append([]string(nil), values...)
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(raw)
	}))
	defer spy.Close()
	const echoPath = "/v1/echo?raw=%2F&same=1&same=2"
	headers := []string{"--header", "X-Echo: first", "--header", "X-Echo: second", "--header", "Content-Type: application/octet-stream"}
	requestArgs := func(member int, method, path string, body []byte) []string {
		args := []string{"zk-api", "--client-dir", profile.ClientDirs[member], "--url", spy.URL, "--upstream", upstream.URL, "--method", method, "--path", path}
		args = append(args, headers...)
		if body != nil || method == "POST" || method == "PUT" || method == "PATCH" {
			filename := filepath.Join(directory, fmt.Sprintf("body-%d-%d.dat", member, time.Now().UnixNano()))
			if err := os.WriteFile(filename, body, 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "--data-file", filename)
		}
		return args
	}
	call := func(member int, method, path string, body []byte, status int, want []byte) apiResult {
		t.Helper()
		started := time.Now()
		output, err := run(ctx, cli, requestArgs(member, method, path, body)...)
		if err != nil {
			t.Fatalf("API %s failed: %v", method, err)
		}
		var result apiResult
		if json.Unmarshal(output, &result) != nil || result.Format != "zkweb-zk-api-result-v1" || result.Method != method || result.Path != path || result.Upstream != upstream.URL || result.Status != status {
			t.Fatal("API result context/status changed")
		}
		decoded, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil || !bytes.Equal(decoded, want) {
			t.Fatalf("API %s response bytes changed", method)
		}
		for _, header := range result.Headers {
			switch strings.ToLower(header.Name) {
			case "set-cookie", "authorization", "connection", "x-private-hop", "x-zkweb-proof", "x-zkweb-tag", "x-zkweb-challenge":
				t.Fatal("private or hop response header leaked")
			}
		}
		t.Logf("proof-authorized %s %s: upstream %d (%s)", method, path, status, time.Since(started).Round(time.Millisecond))
		return result
	}
	for index, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		body := []byte(nil)
		want := defaultBody
		if method == "HEAD" {
			want = nil
		}
		if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" || method == "OPTIONS" {
			body = []byte{0, 255, 128, byte(index)}
			want = body
		}
		call(index%2, method, echoPath, body, 200, want)
	}
	large := make([]byte, apiBodyLimit)
	for index := range large {
		large[index] = byte(index)
	}
	call(0, "POST", echoPath, large, 200, large)
	redirect := call(0, "GET", "/v1/redirect", nil, 307, []byte("redirect"))
	foundLocation := false
	for _, header := range redirect.Headers {
		if header.Name == "location" && header.Value == "/v1/redirected" {
			foundLocation = true
		}
	}
	if !foundLocation {
		t.Fatal("redirect status/header lost")
	}
	call(1, "GET", "/v1/unauthorized", nil, 401, []byte("provider credentials rejected"))
	call(0, "GET", "/v1/failure", nil, 503, []byte("provider unavailable"))
	for _, tamper := range []int32{1, 2, 3, 4, 5, 6} {
		before := calls.Load()
		mode.Store(tamper)
		output, err := run(ctx, cli, requestArgs(0, "POST", echoPath, []byte("bound-body"))...)
		mode.Store(0)
		if err == nil || len(output) != 0 || calls.Load() != before {
			t.Fatalf("tamper mode %d reached upstream or produced success", tamper)
		}
	}
	for _, path := range []string{"/v1/drop", "/v1/oversized"} {
		before := calls.Load()
		output, err := run(ctx, cli, requestArgs(0, "POST", path, []byte("once"))...)
		if err == nil || len(output) != 0 || calls.Load() != before+1 {
			t.Fatal("uncertain upstream request retried or returned partial success")
		}
	}
	before := calls.Load()
	output, err := run(ctx, cli, requestArgs(0, "GET", "/admin", nil)...)
	if err == nil || len(output) != 0 || calls.Load() != before {
		t.Fatal("upstream path scope escaped")
	}
	mu.Lock()
	first := captured[0]
	all := append([]capture(nil), captured...)
	mu.Unlock()
	replay, err := http.NewRequestWithContext(ctx, first.method, gateway+"/api", bytes.NewReader(first.body))
	if err != nil {
		t.Fatal(err)
	}
	replay.Header = first.header.Clone()
	response, err := forward.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 401 || calls.Load() != before {
		t.Fatal("replayed authorization reached upstream")
	}
	for _, request := range all {
		if request.method != "POST" {
			t.Fatal("outer gateway transport must POST even for HEAD")
		}
		proof, err := base64.StdEncoding.DecodeString(request.header.Get("X-ZkWeb-Proof"))
		if err != nil || len(proof) != 128 {
			t.Fatal("request lacked a real Groth16 proof")
		}
		if request.header.Get("Authorization") != "" || request.header.Get("Cookie") != "" {
			t.Fatal("operator credentials appeared on client transport")
		}
		for name := range request.header {
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "x-zkweb-") {
				switch lower {
				case "x-zkweb-challenge", "x-zkweb-proof", "x-zkweb-tag", "x-zkweb-api-method", "x-zkweb-api-path", "x-zkweb-api-headers":
				default:
					t.Fatal("unknown credential-bearing header")
				}
			}
		}
	}
	// Without the explicit CA, the self-signed HTTPS upstream must fail TLS.
	noCA, stopNoCA := startGateway(t, ctx, cli, base)
	defer stopNoCA()
	before = calls.Load()
	noCAArgs := requestArgs(0, "GET", echoPath, nil)
	for index := range noCAArgs {
		if noCAArgs[index] == spy.URL {
			noCAArgs[index] = noCA
		}
	}
	output, err = run(ctx, cli, noCAArgs...)
	if err == nil || len(output) != 0 || calls.Load() != before {
		t.Fatal("upstream TLS verification was bypassed")
	}
	if fixtureFailure.Load() || responseFailures.Load() {
		t.Fatal("upstream or capture fixture detected an invalid boundary")
	}
	t.Logf("verified seven upstream methods, 1 MiB binary round trip, six tamper rejections, TLS verification, no redirects and no retries")
}

// Use a distinct CA and non-CA server leaf suitable for strict WebPKI validation.
func caIssuedTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zkWeb owned API fixture CA"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "zkWeb owned HTTPS upstream"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: false,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCertificate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	if _, err := leafCertificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("invalid fixture chain: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey, Leaf: leafCertificate}},
	}
	server.StartTLS()
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func run(ctx context.Context, cli string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, cli, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 2 * time.Second
	var output, stderr bytes.Buffer
	command.Stdout = &output
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return output.Bytes(), fmt.Errorf("%s: %w", strings.TrimSpace(stderr.String()), err)
	}
	return output.Bytes(), nil
}

func startGateway(t *testing.T, ctx context.Context, cli string, options []string) (string, func()) {
	t.Helper()
	serverCtx, cancel := context.WithCancel(ctx)
	args := append([]string{"zk-listen"}, options...)
	args = append(args, "--listen", "127.0.0.1:0")
	command := exec.CommandContext(serverCtx, cli, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 2 * time.Second
	command.Stderr = io.Discard
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				_ = command.Process.Kill()
				t.Error("gateway failed to stop")
			}
		})
	}
	t.Cleanup(stop)
	line := make(chan []byte, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024), 64<<10)
		if scanner.Scan() {
			line <- append([]byte(nil), scanner.Bytes()...)
		} else {
			line <- nil
		}
	}()
	select {
	case raw := <-line:
		var ready struct {
			Event    string `json:"event"`
			URL      string `json:"url"`
			Protocol string `json:"protocol"`
		}
		if json.Unmarshal(raw, &ready) != nil || ready.Event != "ready" || ready.Protocol != "zkweb-zk-authorized-crud-v1" {
			stop()
			t.Fatal("gateway did not become ready")
		}
		return ready.URL, stop
	case <-ctx.Done():
		stop()
		t.Fatal("gateway startup timed out")
	}
	return "", stop
}
