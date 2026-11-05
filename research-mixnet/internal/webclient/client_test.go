// SPDX-License-Identifier: AGPL-3.0-or-later
package webclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureHost = "origin.example.invalid"

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *lockedBuffer) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.Buffer.Bytes()...)
}

// The fixture proxy maps an unresolvable destination name to a local TLS
// server. It observes SOCKS metadata and raw encrypted bytes, never HTTP fields.
type fixtureProxy struct {
	listener    net.Listener
	capture     lockedBuffer
	mu          sync.Mutex
	hosts       []string
	identities  []string
	wg          sync.WaitGroup
	connections map[net.Conn]struct{}
}

func newFixtureProxy(t *testing.T, destination string) *fixtureProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fixtureProxy{listener: listener, connections: make(map[net.Conn]struct{})}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.connections[conn] = struct{}{}
			p.mu.Unlock()
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer conn.Close()
				defer func() { p.mu.Lock(); delete(p.connections, conn); p.mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				var greeting [3]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 5 || greeting[1] != 1 {
					return
				}
				if greeting[2] != 0 && greeting[2] != 2 {
					return
				}
				_, _ = conn.Write([]byte{5, greeting[2]})
				identity := ""
				if greeting[2] == 2 {
					var auth [2]byte
					if _, err := io.ReadFull(conn, auth[:]); err != nil || auth[0] != 1 {
						return
					}
					username := make([]byte, int(auth[1]))
					if _, err := io.ReadFull(conn, username); err != nil {
						return
					}
					if string(username) != "<torS0X>0" {
						return
					}
					var size [1]byte
					if _, err := io.ReadFull(conn, size[:]); err != nil {
						return
					}
					password := make([]byte, int(size[0]))
					if _, err := io.ReadFull(conn, password); err != nil {
						return
					}
					identity = string(password)
					_, _ = conn.Write([]byte{1, 0})
				}
				var connect [5]byte
				if _, err := io.ReadFull(conn, connect[:]); err != nil || connect[0] != 5 || connect[1] != 1 || connect[2] != 0 || connect[3] != 3 {
					return
				}
				name := make([]byte, int(connect[4]))
				if _, err := io.ReadFull(conn, name); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, conn, 2); err != nil {
					return
				}
				p.mu.Lock()
				p.hosts = append(p.hosts, string(name))
				p.identities = append(p.identities, identity)
				p.mu.Unlock()
				upstream, err := net.DialTimeout("tcp", destination, time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				_ = conn.SetDeadline(time.Time{})
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, io.TeeReader(conn, &p.capture))
					upstream.Close()
					close(done)
				}()
				_, _ = io.Copy(conn, upstream)
				conn.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		p.mu.Lock()
		for conn := range p.connections {
			conn.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func tlsFixture(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: fixtureHost},
		DNSNames: []string{fixtureHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("test root unavailable")
	}
	return server, roots
}

func fixtureClient(t *testing.T, proxy *fixtureProxy, roots *x509.CertPool, mode string, limit int64) *Client {
	t.Helper()
	client, err := New(Options{Target: "https://" + fixtureHost, Proxy: mode + "://" + proxy.listener.Addr().String(), Timeout: 5 * time.Second, MaxRequestBytes: limit, MaxResponseBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	if roots != nil {
		client.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	}
	return client
}

func TestExactBytesAndTLSStayBetweenClientAndOrigin(t *testing.T) {
	body := bytes.Repeat([]byte{0, 255, 1, 128, 13, 10}, 1024)
	responseBody := append([]byte{255, 0, 254}, body...)
	var calls atomic.Int32
	server, roots := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		got, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.URL.EscapedPath() != "/items/a%2Fb" || r.URL.RawQuery != "tag=a%2Fb&tag=c+d" || !bytes.Equal(got, body) {
			t.Error("HTTP request bytes or path/query changed")
		}
		if r.Header.Get("Authorization") != "Bearer fixture-secret" || len(r.Header.Values("X-Tag")) != 2 || r.Header.Get("User-Agent") != "" {
			t.Error("explicit headers changed or ambient user agent added")
		}
		if r.TLS == nil || r.TLS.ServerName != fixtureHost || r.ProtoMajor != 1 {
			t.Error("TLS did not authenticate the origin or unexpected retry-capable protocol")
		}
		w.Header().Add("X-Result", "one")
		w.Header().Add("X-Result", "two")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(responseBody)
	})
	proxy := newFixtureProxy(t, server.Listener.Addr().String())
	client := fixtureClient(t, proxy, roots, "tor", 64<<10)
	response, err := client.Do(context.Background(), Request{Method: "POST", Path: "/items/a%2Fb?tag=a%2Fb&tag=c+d", Headers: http.Header{"authorization": {"Bearer fixture-secret"}, "x-tag": {"a", "b"}}, Body: body})
	if err != nil || response.Status != 201 || !bytes.Equal(response.Body, responseBody) || len(response.Headers.Values("X-Result")) != 2 || calls.Load() != 1 {
		t.Fatalf("exact-byte TLS exchange failed: status=%d err=%v calls=%d", response.Status, err, calls.Load())
	}
	proxy.mu.Lock()
	if len(proxy.hosts) != 1 || proxy.hosts[0] != fixtureHost || len(proxy.identities[0]) != 64 {
		t.Error("destination DNS or Tor identity was not sent to proxy")
	}
	proxy.mu.Unlock()
	if bytes.Contains(proxy.capture.snapshot(), []byte("fixture-secret")) || bytes.Contains(proxy.capture.snapshot(), body) {
		t.Fatal("proxy observed plaintext credentials or body")
	}
	if client.http.Jar != nil || client.http.Transport.(*http.Transport).Proxy != nil || client.Mode() != "tor" {
		t.Fatal("ambient network state inherited")
	}
}

func TestTLSCertificateFailureDoesNotReachHTTPOrigin(t *testing.T) {
	var calls atomic.Int32
	server, _ := tlsFixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	proxy := newFixtureProxy(t, server.Listener.Addr().String())
	client := fixtureClient(t, proxy, nil, "socks5", 1024)
	_, err := client.Do(context.Background(), Request{Method: "GET", Path: "/", Headers: http.Header{"Authorization": {"Bearer undisclosed"}}})
	if !errors.Is(err, ErrDeliveryUnknown) || calls.Load() != 0 {
		t.Fatal("untrusted TLS certificate accepted")
	}
	if strings.Contains(err.Error(), fixtureHost) || bytes.Contains(proxy.capture.snapshot(), []byte("undisclosed")) {
		t.Fatal("TLS failure exposed request details")
	}
}

func TestMethodsStatusAndExplicitContextHeaders(t *testing.T) {
	var calls atomic.Int32
	server, roots := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "Bearer "+r.Method {
			t.Error("credentials or cookies crossed requests")
		}
		http.SetCookie(w, &http.Cookie{Name: "ignored", Value: "no-jar"})
		if r.Method == "HEAD" || r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte("missing"))
	})
	proxy := newFixtureProxy(t, server.Listener.Addr().String())
	client := fixtureClient(t, proxy, roots, "tor", 1024)
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		response, err := client.Do(context.Background(), Request{Method: method, Path: "/item", Headers: http.Header{"Authorization": {"Bearer " + method}}})
		if err != nil {
			t.Fatal(err)
		}
		want := 404
		if method == "HEAD" || method == "DELETE" {
			want = 204
		}
		if response.Status != want || len(response.Headers.Values("Set-Cookie")) != 1 {
			t.Fatal("upstream status or headers lost")
		}
	}
	if calls.Load() != 7 {
		t.Fatal("HTTP request was repeated")
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	for _, identity := range proxy.identities {
		if identity != proxy.identities[0] {
			t.Fatal("one client changed Tor context identity")
		}
	}
}

func TestLostMutationAndRedirectAreNeverRetried(t *testing.T) {
	var calls atomic.Int32
	server, roots := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://other.example/path")
			w.WriteHeader(307)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close() // A committed mutation whose HTTP reply is lost.
	})
	proxy := newFixtureProxy(t, server.Listener.Addr().String())
	client := fixtureClient(t, proxy, roots, "socks5", 1024)
	response, err := client.Do(context.Background(), Request{Method: "POST", Path: "/redirect", Body: []byte("create")})
	if err != nil || response.Status != 307 || calls.Load() != 1 {
		t.Fatal("redirect was followed or not returned")
	}
	_, err = client.Do(context.Background(), Request{Method: "POST", Path: "/commit", Headers: http.Header{"Idempotency-Key": {"explicit-key"}}, Body: []byte("commit once")})
	if !errors.Is(err, ErrDeliveryUnknown) || calls.Load() != 2 {
		t.Fatal("ambiguous mutation retried or reported as definite failure")
	}
}

func TestAdmissionAndResponseLimits(t *testing.T) {
	var calls atomic.Int32
	server, roots := tlsFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1025))
	})
	proxy := newFixtureProxy(t, server.Listener.Addr().String())
	client := fixtureClient(t, proxy, roots, "socks5", 1024)
	for _, input := range []Request{
		{Method: "POST", Path: "/", Body: make([]byte, 1025)},
		{Method: "TRACE", Path: "/"},
		{Method: "GET", Path: "//other.example/"},
		{Method: "GET", Path: "/", Headers: http.Header{"Host": {"other.example"}}},
		{Method: "GET", Path: "/", Headers: http.Header{"Authorization": {"secret\r\nX-Injected: true"}}},
		{Method: "GET", Path: "/", Headers: http.Header{"X-Large": {strings.Repeat("x", MaxHeaderBytes)}}},
		{Method: "GET", Path: "/" + strings.Repeat("x", maxPathBytes)},
	} {
		if _, err := client.Do(context.Background(), input); !errors.Is(err, ErrRequestRejected) {
			t.Fatal("unsafe request was not rejected before admission")
		}
	}
	proxy.mu.Lock()
	connections := len(proxy.hosts)
	proxy.mu.Unlock()
	if calls.Load() != 0 || connections != 0 {
		t.Fatal("rejected request reached proxy/origin")
	}
	response, err := client.Do(context.Background(), Request{Method: "GET", Path: "/"})
	if !errors.Is(err, ErrDeliveryUnknown) || response.Status != 200 || len(response.Body) != 0 || calls.Load() != 1 {
		t.Fatal("oversized response silently truncated or retried")
	}
}

func TestCanceledContextAndBodyReadStopPromptly(t *testing.T) {
	server, roots := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	proxy := newFixtureProxy(t, server.Listener.Addr().String())
	client := fixtureClient(t, proxy, roots, "socks5", 1024)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Do(canceled, Request{Method: "GET", Path: "/"}); !errors.Is(err, ErrRequestRejected) || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled request was admitted")
	}
	ctx, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer stop()
	started := time.Now()
	_, err := client.Do(ctx, Request{Method: "GET", Path: "/"})
	if !errors.Is(err, ErrDeliveryUnknown) || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatal("body read ignored request cancellation")
	}
}

func TestClientConfigurationRequiresSafeExplicitRoute(t *testing.T) {
	for _, options := range []Options{
		{Target: "https://api.example.com"},
		{Target: "http://api.example.com", Proxy: "socks5://127.0.0.1:9050"},
		{Target: "https://localhost", Proxy: "socks5://127.0.0.1:9050"},
		{Target: "https://127.0.0.1", Proxy: "socks5://127.0.0.1:9050"},
		{Target: "https://api.example.com", Proxy: "socks5://remote.example.com:9050"},
		{Target: "https://api.example.com", Proxy: "socks5://127.0.0.1:9050", MaxResponseBytes: MaxBodyBytes + 1},
		{Target: "https://api.example.com", Proxy: "socks5://127.0.0.1:9050", Timeout: 11 * time.Minute},
	} {
		if _, err := New(options); !errors.Is(err, ErrRequestRejected) {
			t.Fatal("unsafe client configuration accepted")
		}
	}
}
