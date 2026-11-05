// SPDX-License-Identifier: AGPL-3.0-or-later
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/lab"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Production never accepts loopback targets. Tests alone replace the transport
// with a trusted local HTTPS server and retain the worker's client policy.
func testWorker(t *testing.T, handler http.HandlerFunc) *Worker {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	worker, err := New("https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	upstream := server.Client().Transport
	local, _ := url.Parse(server.URL)
	worker.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.URL.Host = local.Host
		return upstream.RoundTrip(copy)
	})
	return worker
}

func call(t *testing.T, worker *Worker, ctx context.Context, request Request) Response {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	encoded := worker.Handle(ctx, raw)
	if len(encoded) > MaxMessageBytes {
		t.Fatalf("oversized encoded response: %d", len(encoded))
	}
	var response Response
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestMethodsPreserveInputsAndUpstreamStatus(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			worker := testWorker(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.Method != method || r.URL.RequestURI() != "/items/a%2Fb?q=one%20two&v=2" || string(body) != "{\"name\":\"café & tea\"}" {
					t.Errorf("unexpected request: %s %s %q", r.Method, r.URL.RequestURI(), body)
				}
				if r.Header.Get("Authorization") != "Bearer explicit-token" || r.Header.Get("X-Request-Tag") != "test" {
					t.Error("explicit headers were changed")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Add("X-Result", "one")
				w.Header().Add("X-Result", "two")
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":"missing"}`)
			})
			response := call(t, worker, context.Background(), Request{Method: method, Path: "/items/a%2Fb?q=one%20two&v=2", Headers: map[string]string{
				"Authorization": "Bearer explicit-token", "X-Request-Tag": "test",
			}, Body: "{\"name\":\"café & tea\"}"})
			if response.Error != "" || response.Status != 404 || calls.Load() != 1 || len(response.Headers.Values("X-Result")) != 2 {
				t.Fatalf("unexpected response: %+v; calls=%d", response, calls.Load())
			}
			if method != http.MethodHead && response.Body != `{"error":"missing"}` {
				t.Fatalf("body changed: %q", response.Body)
			}
		})
	}
}

func TestNoContent(t *testing.T) {
	worker := testWorker(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	response := call(t, worker, context.Background(), Request{Method: "DELETE", Path: "/items/1"})
	if response.Status != 204 || response.Body != "" || response.Error != "" {
		t.Fatal(response)
	}
}

func TestValidationPreventsEgress(t *testing.T) {
	worker, _ := New("https://api.example")
	worker.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached transport")
		return nil, errors.New("unexpected request")
	})
	invalid := []string{
		``, `null`, `[]`, `{}`, `{"method":"TRACE","path":"/"}`,
		`{"method":"post","path":"/"}`, `{"method":"GET","path":"https://evil.example/"}`,
		`{"method":"GET","path":"//evil.example/"}`, `{"method":"GET","path":"relative"}`,
		`{"method":"GET","path":"/a#fragment"}`, `{"method":"GET","path":"/a\\b"}`,
		`{"method":"GET","path":"/%xx"}`, `{"method":"GET","path":"/","unknown":true}`,
		`{"method":"GET","path":"/"} {}`, `{"method":"GET","path":"/","body":123}`,
		`{"METHOD":"GET","path":"/"}`, `{"method":"GET","method":"POST","path":"/"}`,
		`{"method":"GET","path":"/","headers":null}`, `{"method":"GET","path":"/","body":null}`,
		`{"method":"GET","path":"/","headers":{"Authorization":"one","Authorization":"two"}}`,
		`{"method":"GET","path":"/","headers":{"X-Foo":"a\r\nb"}}`,
		`{"method":"GET","path":"/","headers":{"Bad Header":"a"}}`,
		`{"method":"GET","path":"/","headers":{"X-Foo":"one","x-foo":"two"}}`,
		strings.Repeat(" ", MaxMessageBytes+1),
	}
	for _, header := range []string{"Host", "Content-Length", "Connection", "Proxy-Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Authorization"} {
		raw, _ := json.Marshal(Request{Method: "GET", Path: "/", Headers: map[string]string{header: "x"}})
		invalid = append(invalid, string(raw))
	}
	invalid = append(invalid, string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}))
	for _, raw := range invalid {
		if worker.Validate([]byte(raw)) == nil {
			t.Errorf("accepted invalid input: %q", raw)
		}
		var response Response
		if err := json.Unmarshal(worker.Handle(context.Background(), []byte(raw)), &response); err != nil || response.Error == "" {
			t.Errorf("invalid input did not produce bounded error: %q", raw)
		}
	}
}

func TestOriginValidation(t *testing.T) {
	for _, target := range []string{
		"http://example.com", "https://example.com/", "https://example.com/path", "https://user:pass@example.com",
		"https://example.com?q=1", "https://example.com?", "https://example.com/#fragment", "https://example.com:",
		"https://example.com:0", "https://example.com:65536", "https://127.0.0.1", "https://10.0.0.1",
		"https://[::1]", "https://[::ffff:127.0.0.1]", "https://[fe80::1%25en0]", "https://100.100.100.200",
	} {
		if _, err := New(target); err == nil {
			t.Errorf("accepted origin %q", target)
		}
	}
	for _, target := range []string{"https://example.com", "https://example.com:8443", "https://8.8.8.8", "https://[2606:4700:4700::1111]"} {
		worker, err := New(target)
		if err != nil {
			t.Errorf("refused origin %q: %v", target, err)
			continue
		}
		transport := worker.client.Transport.(*http.Transport)
		if transport.Proxy != nil || worker.client.Jar != nil || !transport.DisableKeepAlives || !transport.DisableCompression || transport.MaxResponseHeaderBytes == 0 {
			t.Error("transport inherited ambient state or lacks bounds")
		}
	}
}

func TestPublicAddressPolicyAndLoopbackDial(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "192.168.1.1", "198.18.0.1", "192.0.2.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fd00::1", "fe80::1", "2001:db8::1", "2002:7f00:1::", "::ffff:10.1.1.1"} {
		if publicIP(netip.MustParseAddr(address)) {
			t.Errorf("accepted nonpublic address %s", address)
		}
	}
	// Translation prefixes must not carry loopback, private or metadata IPv4
	// addresses past the IPv6 public-address gate.
	for _, address := range []string{"64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "64:ff9b:1::7f00:1"} {
		if publicIP(netip.MustParseAddr(address)) {
			t.Errorf("accepted translated private address %s", address)
		}
		if _, err := New("https://[" + address + "]"); err == nil {
			t.Errorf("accepted translated private origin %s", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(address)) {
			t.Errorf("refused public address %s", address)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if conn, err := dialPublic(context.Background(), "tcp", listener.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("dialed private address")
	}
}

func TestRedirectIsReturnedAndMutationIsNeverRetried(t *testing.T) {
	var calls atomic.Int32
	worker := testWorker(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "https://another.example/mutation")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	response := call(t, worker, context.Background(), Request{Method: "POST", Path: "/mutation", Body: "one"})
	if calls.Load() != 1 || response.Status != 307 || response.Error != "" || response.Headers.Get("Location") != "https://another.example/mutation" {
		t.Fatalf("redirect followed or lost: %+v, calls=%d", response, calls.Load())
	}
	worker.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("private transport failure including credentials")
	})
	response = call(t, worker, context.Background(), Request{Method: "POST", Path: "/mutation"})
	if calls.Load() != 2 || response.Error != "upstream request failed" {
		t.Fatalf("mutation retried or error leaked: %+v, calls=%d", response, calls.Load())
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	worker, _ := New("https://api.example")
	var calls atomic.Int32
	worker.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Error("missing worker deadline")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	response := call(t, worker, canceled, Request{Method: "GET", Path: "/"})
	if calls.Load() != 0 || response.Error != "request canceled or timed out" {
		t.Fatal(response, calls.Load())
	}
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	response = call(t, worker, ctx, Request{Method: "PATCH", Path: "/"})
	if calls.Load() != 1 || response.Error != "request canceled or timed out" {
		t.Fatal(response, calls.Load())
	}
}

func TestResponseBoundsAndUTF8(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		headers    http.Header
		want       string
	}{
		{name: "body", body: strings.Repeat("a", MaxMessageBytes+1), want: "response exceeds cell capacity"},
		{name: "JSON escaping", body: strings.Repeat("<", 1000), want: "response exceeds cell capacity"},
		{name: "headers", body: "ok", headers: http.Header{"X-Big": {strings.Repeat("x", MaxMessageBytes)}}, want: "response exceeds cell capacity"},
		{name: "binary", body: string([]byte{0xff, 0xfe}), want: "response body is not UTF-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			worker := testWorker(t, func(w http.ResponseWriter, r *http.Request) {
				for name, values := range tc.headers {
					w.Header()[name] = values
				}
				w.WriteHeader(201)
				_, _ = io.WriteString(w, tc.body)
			})
			response := call(t, worker, context.Background(), Request{Method: "POST", Path: "/"})
			if response.Status != 201 || response.Error != tc.want || response.Body != "" {
				t.Fatalf("unbounded or silently truncated response: %+v", response)
			}
		})
	}
}

func TestHopByHopResponseHeadersRemoved(t *testing.T) {
	worker, _ := New("https://api.example")
	worker.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{
			"Connection": {"X-Internal, Keep-Alive"}, "X-Internal": {"private"},
			"Keep-Alive": {"timeout=5"}, "X-Public": {"yes"}, "Content-Length": {"2"},
		}, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
	})
	response := call(t, worker, context.Background(), Request{Method: "GET", Path: "/"})
	if len(response.Headers) != 1 || response.Headers.Get("X-Public") != "yes" || response.Body != "ok" {
		t.Fatal(response)
	}
}

func TestPOSTOverScheduledSphinxAndSURB(t *testing.T) {
	var calls atomic.Int32
	worker := testWorker(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.RequestURI() != "/items?draft=true" ||
			string(body) != `{"name":"first"}` || r.Header.Get("Authorization") != "Bearer explicit" {
			t.Errorf("HTTP request changed in transport: %s %s %s", r.Method, r.URL.RequestURI(), body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":1}`)
	})
	raw, _ := json.Marshal(Request{Method: "POST", Path: "/items?draft=true", Body: `{"name":"first"}`,
		Headers: map[string]string{"Authorization": "Bearer explicit"}})
	result, err := lab.Exchange(context.Background(), lab.Config{
		Clients: 1, Jobs: 1, Rate: 20, Duration: 3 * time.Second,
	}, raw, worker.Handle)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(result.Response, &response); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || result.Report.Completed != 1 || response.Status != 201 || response.Body != `{"id":1}` || response.Error != "" {
		t.Fatalf("unexpected end-to-end result: calls=%d, response=%+v, completed=%d", calls.Load(), response, result.Report.Completed)
	}
}
