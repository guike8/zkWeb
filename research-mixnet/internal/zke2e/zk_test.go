// SPDX-License-Identifier: AGPL-3.0-or-later
package zke2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

const bodyLimit = 64 << 10
const protocol = "zkweb-zk-authorized-crud-v1"

type capturedRequest struct {
	method, path string
	body         []byte
	headers      http.Header
	status       int
}

// Opt-in: this invokes the real binary and generates/proves/verifies Groth16.
func TestZKListenerIntegration(t *testing.T) {
	cli := os.Getenv("ZKWEB_ZK_CLI")
	if cli == "" {
		t.Skip("make test-zk builds and exercises the real ZK listener")
	}
	if !filepath.IsAbs(cli) {
		t.Fatal("CLI must be an explicit absolute path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute+30*time.Second)
	defer cancel()
	directory := t.TempDir()
	setup, err := run(ctx, cli, "zk-setup", "--output", filepath.Join(directory, "profile"), "--members", "2")
	if err != nil {
		t.Fatalf("real ZK setup failed: %v", err)
	}
	var profile struct {
		Format     string   `json:"format"`
		ServerDir  string   `json:"server_dir"`
		ClientDirs []string `json:"client_dirs"`
		ProfileID  string   `json:"profile_id"`
		Protocol   string   `json:"protocol"`
		Members    int      `json:"members"`
	}
	if json.Unmarshal(setup, &profile) != nil || profile.Format != "zkweb-zk-setup-v1" || profile.Protocol != protocol || profile.Members != 2 || len(profile.ClientDirs) != 2 || len(profile.ProfileID) != 64 {
		t.Fatal("invalid ZK setup metadata")
	}
	entries, err := os.ReadDir(profile.ServerDir)
	if err != nil || len(entries) != 2 {
		t.Fatal("server profile should contain only manifest and verifying key")
	}
	for _, entry := range entries {
		if entry.Name() != "manifest.json" && entry.Name() != "verifying-key.g16" {
			t.Fatal("server profile received client proof or credential material")
		}
	}
	manifest, err := os.ReadFile(filepath.Join(profile.ServerDir, "manifest.json"))
	if err != nil || bytes.Contains(manifest, []byte("credential_sha256")) {
		t.Fatal("server manifest contains an individual credential pin")
	}
	stateFile := filepath.Join(directory, "records.json")
	target, stop := startServer(t, ctx, cli, profile.ServerDir, stateFile, profile.ProfileID)
	var active atomic.Value
	active.Store(target)
	var tamper atomic.Int32 // 1=body, 2=method, 3=path, 4=proof.
	var spyFailure atomic.Bool
	var mu sync.Mutex
	var captured []capturedRequest
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	forward := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, bodyLimit+1))
		if err != nil || len(body) > bodyLimit {
			spyFailure.Store(true)
			http.Error(w, "invalid test body", 400)
			return
		}
		path, method := request.URL.Path, request.Method
		if request.URL.RawQuery != "" || (path != "/challenge" && !strings.HasPrefix(path, "/records/")) {
			spyFailure.Store(true)
			http.Error(w, "unexpected route", 400)
			return
		}
		if request.Header.Get("Cookie") != "" || request.Header.Get("Authorization") != "" {
			spyFailure.Store(true)
		}
		proofHeaders := 0
		for name := range request.Header {
			switch strings.ToLower(name) {
			case "accept", "accept-encoding", "user-agent", "connection", "content-type", "content-length", "x-zkweb-challenge", "x-zkweb-tag", "x-zkweb-proof":
			default:
				spyFailure.Store(true)
			}
			if strings.HasPrefix(strings.ToLower(name), "x-zkweb-") {
				lower := strings.ToLower(name)
				if lower != "x-zkweb-challenge" && lower != "x-zkweb-tag" && lower != "x-zkweb-proof" {
					spyFailure.Store(true)
				}
				proofHeaders++
			}
		}
		index := -1
		if path == "/challenge" {
			if method != "GET" || proofHeaders != 0 {
				spyFailure.Store(true)
			}
		} else {
			if proofHeaders != 3 {
				spyFailure.Store(true)
			}
			for _, name := range []string{"X-ZkWeb-Challenge", "X-ZkWeb-Tag", "X-ZkWeb-Proof"} {
				if len(request.Header.Values(name)) != 1 {
					spyFailure.Store(true)
				}
			}
			mu.Lock()
			index = len(captured)
			captured = append(captured, capturedRequest{method: method, path: path, body: append([]byte(nil), body...), headers: request.Header.Clone()})
			mu.Unlock()
			switch tamper.Load() {
			case 1:
				body = append([]byte(nil), body...)
				if len(body) == 0 {
					spyFailure.Store(true)
					http.Error(w, "empty tamper input", 400)
					return
				}
				body[0] ^= 1
			case 2:
				method = "DELETE"
			case 3:
				path = "/records/other"
			case 4:
				proof, err := base64.StdEncoding.DecodeString(request.Header.Get("X-ZkWeb-Proof"))
				if err != nil || len(proof) != 128 {
					spyFailure.Store(true)
					http.Error(w, "invalid test proof", 400)
					return
				}
				proof[len(proof)/2] ^= 1
				request.Header.Set("X-ZkWeb-Proof", base64.StdEncoding.EncodeToString(proof))
			}
		}
		outgoing, err := http.NewRequestWithContext(request.Context(), method, active.Load().(string)+path, bytes.NewReader(body))
		if err != nil {
			spyFailure.Store(true)
			http.Error(w, "forward failure", 502)
			return
		}
		for _, name := range []string{"Content-Type", "X-ZkWeb-Challenge", "X-ZkWeb-Tag", "X-ZkWeb-Proof"} {
			if value := request.Header.Get(name); value != "" {
				outgoing.Header.Set(name, value)
			}
		}
		response, err := forward.Do(outgoing)
		if err != nil {
			spyFailure.Store(true)
			http.Error(w, "forward failure", 502)
			return
		}
		defer response.Body.Close()
		reply, err := io.ReadAll(io.LimitReader(response.Body, bodyLimit+1))
		if err != nil || len(reply) > bodyLimit {
			spyFailure.Store(true)
			http.Error(w, "response failure", 502)
			return
		}
		if index >= 0 {
			mu.Lock()
			captured[index].status = response.StatusCode
			mu.Unlock()
		}
		if contentType := response.Header.Get("Content-Type"); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(reply)
	}))
	defer spy.Close()
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(captured) }
	request := func(member int, method, key string, status int, expected []byte, input ...string) {
		t.Helper()
		started := time.Now()
		args := []string{"zk-request", "--wire", "legacy", "--client-dir", profile.ClientDirs[member], "--url", spy.URL, "--method", method, "--key", key}
		args = append(args, input...)
		before := count()
		output, err := run(ctx, cli, args...)
		if err != nil {
			t.Fatalf("ZK %s failed: %v", method, err)
		}
		var result struct {
			Format string `json:"format"`
			Method string `json:"method"`
			Key    string `json:"key"`
			Status int    `json:"status"`
			Body   string `json:"body_base64"`
		}
		if json.Unmarshal(output, &result) != nil || result.Format != "zkweb-zk-result-v1" || result.Method != method || result.Key != key || result.Status != status {
			t.Fatalf("incorrect %s result", method)
		}
		body, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil || (expected != nil && !bytes.Equal(body, expected)) {
			t.Fatalf("incorrect %s result bytes", method)
		}
		if count() != before+1 {
			t.Fatal("a ZK request was automatically retried")
		}
		t.Logf("member %d %s %s: HTTP %d (%s)", member, method, key, status, time.Since(started).Round(time.Millisecond))
	}
	binary := []byte{0, 255, 128, 10, 0}
	binaryFile := filepath.Join(directory, "binary.dat")
	if err := os.WriteFile(binaryFile, binary, 0600); err != nil {
		t.Fatal(err)
	}
	request(0, "POST", "alpha", 201, binary, "--data-file", binaryFile)
	request(1, "GET", "alpha", 200, binary)
	maximum := make([]byte, bodyLimit)
	for index := range maximum {
		maximum[index] = byte(index * 31)
	}
	maximumFile := filepath.Join(directory, "maximum.dat")
	if err := os.WriteFile(maximumFile, maximum, 0600); err != nil {
		t.Fatal(err)
	}
	request(1, "PUT", "alpha", 200, maximum, "--data-file", maximumFile)
	request(0, "GET", "alpha", 200, maximum)
	request(0, "POST", "alpha", 409, nil, "--data", "duplicate")
	request(1, "DELETE", "alpha", 200, maximum)
	request(0, "GET", "alpha", 404, nil)
	request(0, "POST", "empty", 201, []byte{}, "--data", "")
	request(1, "GET", "empty", 200, []byte{})
	request(1, "POST", "alpha", 201, []byte("stable"), "--data", "stable")
	mu.Lock()
	old := captured[0]
	mu.Unlock()
	replay := func(target string) {
		t.Helper()
		outgoing, err := http.NewRequestWithContext(ctx, old.method, target+old.path, bytes.NewReader(old.body))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"Content-Type", "X-ZkWeb-Challenge", "X-ZkWeb-Tag", "X-ZkWeb-Proof"} {
			outgoing.Header.Set(name, old.headers.Get(name))
		}
		response, err := forward.Do(outgoing)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Fatal("listener accepted a consumed or old-instance proof")
		}
	}
	replay(target)
	stop()
	target, _ = startServer(t, ctx, cli, profile.ServerDir, stateFile, profile.ProfileID)
	active.Store(target)
	replay(target)
	request(0, "GET", "alpha", 200, []byte("stable"))
	request(1, "GET", "empty", 200, []byte{})
	for _, modification := range []struct {
		mode          int32
		label, method string
		input         []string
	}{
		{1, "body", "PUT", []string{"--data", "must-not-commit"}},
		{2, "method", "GET", nil},
		{3, "path", "PUT", []string{"--data", "must-not-commit"}},
		{4, "proof", "PUT", []string{"--data", "must-not-commit"}},
	} {
		tamper.Store(modification.mode)
		before := count()
		args := []string{"zk-request", "--wire", "legacy", "--client-dir", profile.ClientDirs[0], "--url", spy.URL, "--method", modification.method, "--key", "alpha"}
		output, err := run(ctx, cli, append(args, modification.input...)...)
		if err == nil || len(output) != 0 || count() != before+1 {
			t.Fatalf("tampered %s was accepted, printed a result, or retried", modification.label)
		}
		mu.Lock()
		status := captured[len(captured)-1].status
		mu.Unlock()
		if status != 401 {
			t.Fatalf("tampered %s reached application processing: HTTP %d", modification.label, status)
		}
		tamper.Store(0)
		request(1, "GET", "alpha", 200, []byte("stable"))
	}
	if spyFailure.Load() {
		t.Fatal("HTTP observer could not preserve the authorized protocol")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captured) == 0 || !bytes.Equal(captured[0].body, binary) {
		t.Fatal("this stage must send the intended plaintext record bytes")
	}
	nonces, tags := make(map[string]bool), make(map[string]bool)
	for _, request := range captured {
		proof, err := base64.StdEncoding.DecodeString(request.headers.Get("X-ZkWeb-Proof"))
		if err != nil || len(proof) != 128 {
			t.Fatal("request did not carry a real compressed Groth16 proof")
		}
		for _, value := range []string{request.headers.Get("X-ZkWeb-Challenge"), request.headers.Get("X-ZkWeb-Tag")} {
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != 32 || value != strings.ToLower(value) {
				t.Fatal("noncanonical authorization context")
			}
		}
		nonce, tag := request.headers.Get("X-ZkWeb-Challenge"), request.headers.Get("X-ZkWeb-Tag")
		if nonces[nonce] || tags[tag] {
			t.Fatal("client reused a challenge or authorization tag")
		}
		nonces[nonce], tags[tag] = true, true
	}
	t.Logf("verified %d proof-authorized requests across two group members, with four independent tamper rejections", len(captured))
}

func startServer(t *testing.T, ctx context.Context, cli, serverDir, stateFile, profileID string) (string, func()) {
	t.Helper()
	serverCtx, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(serverCtx, cli, "zk-listen", "--server-dir", serverDir, "--state-file", stateFile, "--listen", "127.0.0.1:0")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 2 * time.Second
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		cancel()
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
				t.Error("ZK listener did not stop promptly")
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
			Event     string `json:"event"`
			URL       string `json:"url"`
			ProfileID string `json:"profile_id"`
			Protocol  string `json:"protocol"`
		}
		if json.Unmarshal(raw, &ready) != nil || ready.Event != "ready" || ready.ProfileID != profileID || ready.Protocol != protocol {
			t.Fatal("ZK listener did not become ready")
		}
		return ready.URL, stop
	case <-ctx.Done():
		t.Fatal("ZK listener startup timed out")
	}
	return "", stop
}

func run(ctx context.Context, cli string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, cli, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 2 * time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("command failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
