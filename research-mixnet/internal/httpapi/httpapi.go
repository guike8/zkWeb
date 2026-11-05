// SPDX-License-Identifier: AGPL-3.0-or-later
// Package httpapi executes bounded HTTP requests at the research worker.
// Requests and replies fit a single lab cell. This is not a billing adapter.
package httpapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxMessageBytes = 4090

type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

type Response struct {
	Status  int         `json:"status,omitempty"`
	Headers http.Header `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type Worker struct {
	target *url.URL
	client *http.Client
}

// New pins an HTTPS origin; request payloads cannot change the destination.
func New(target string) (*Worker, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || u.Opaque != "" || strings.HasSuffix(u.Host, ":") || strings.Contains(u.Hostname(), "%") {
		return nil, errors.New("target must be an HTTPS origin without credentials, path, query, or fragment")
	}
	if u.Port() != "" {
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, errors.New("invalid target port")
		}
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicIP(ip) {
		return nil, errors.New("target must use a public address")
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialPublic,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 8 << 10,
	}
	return &Worker{target: u, client: &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

var excludedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" {
		return false
	}
	// Only the assigned global-unicast space is eligible for IPv6 egress.
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range excludedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// Resolve once per dial, reject mixed public/private answers, and dial the
// validated numeric address. TLS still verifies the configured origin's name.
func dialPublic(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid destination")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("destination unavailable")
	}
	for _, ip := range addresses {
		if !publicIP(ip) {
			return nil, errors.New("destination is not public")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
}

func (w *Worker) Validate(raw []byte) error {
	_, err := decodeRequest(raw)
	return err
}

func decodeRequest(raw []byte) (Request, error) {
	var request Request
	if len(raw) == 0 || len(raw) > MaxMessageBytes || !utf8.Valid(raw) {
		return request, errors.New("request must be valid UTF-8 JSON fitting one cell")
	}
	if err := strictFields(raw, false); err != nil {
		return request, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, errors.New("invalid HTTP request JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return request, errors.New("expected exactly one request")
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		return request, errors.New("unsupported HTTP method")
	}
	path, err := url.Parse(request.Path)
	if err != nil || !strings.HasPrefix(request.Path, "/") || strings.HasPrefix(request.Path, "//") ||
		strings.ContainsAny(request.Path, "\\#\r\n") || path.IsAbs() || path.Host != "" || path.User != nil || path.Fragment != "" {
		return request, errors.New("path must be relative to the configured origin and begin with one slash")
	}
	seen := make(map[string]bool)
	for name, value := range request.Headers {
		canonical := http.CanonicalHeaderKey(name)
		if !validHeaderName(name) || forbiddenHeader(canonical) || !validHeaderValue(value) || seen[canonical] {
			return request, errors.New("invalid or reserved request header")
		}
		seen[canonical] = true
	}
	return request, nil
}

// encoding/json otherwise accepts duplicate fields, case-insensitive struct
// keys, and null for strings. Refuse ambiguous shapes before typed decoding.
func strictFields(raw []byte, headers bool) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("expected a JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return errors.New("invalid or duplicate JSON field")
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errors.New("invalid JSON field")
		}
		if !headers && name == "headers" {
			if err := strictFields(value, true); err != nil {
				return err
			}
		} else {
			if !headers && name != "method" && name != "path" && name != "body" {
				return errors.New("unknown HTTP request field")
			}
			if len(value) == 0 || value[0] != '"' {
				return errors.New("expected a JSON string")
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("invalid JSON object")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("expected exactly one JSON object")
	}
	return nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for i := range value {
		if value[i] == 127 || (value[i] < 32 && value[i] != '\t') {
			return false
		}
	}
	return true
}

func forbiddenHeader(name string) bool {
	switch name {
	case "Host", "Content-Length", "Connection", "Proxy-Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Authorization", "Proxy-Authenticate":
		return true
	}
	return false
}

// Handle returns a complete encoded response or a bounded error; it never
// truncates a body silently and never retries an ambiguous mutation.
func (w *Worker) Handle(ctx context.Context, raw []byte) []byte {
	input, err := decodeRequest(raw)
	if err != nil {
		return encode(Response{Error: "invalid request"})
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return encode(Response{Error: "request canceled or timed out"})
	}
	path, _ := url.Parse(input.Path)
	destination := *w.target
	destination.Path, destination.RawPath = path.Path, path.RawPath
	destination.RawQuery, destination.ForceQuery = path.RawQuery, path.ForceQuery
	request, err := http.NewRequestWithContext(ctx, input.Method, destination.String(), strings.NewReader(input.Body))
	if err != nil {
		return encode(Response{Error: "invalid request"})
	}
	for name, value := range input.Headers {
		request.Header.Set(name, value)
	}
	response, err := w.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return encode(Response{Error: "request canceled or timed out"})
		}
		return encode(Response{Error: "upstream request failed"})
	}
	defer response.Body.Close()
	result := Response{Status: response.StatusCode}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxMessageBytes+1))
	if err != nil {
		result.Error = "upstream response could not be read"
		return encode(result)
	}
	if len(body) > MaxMessageBytes {
		result.Error = "response exceeds cell capacity"
		return encode(result)
	}
	if !utf8.Valid(body) {
		result.Error = "response body is not UTF-8"
		return encode(result)
	}
	result.Headers = responseHeaders(response.Header)
	result.Body = string(body)
	return encode(result)
}

func responseHeaders(headers http.Header) http.Header {
	blocked := make(map[string]bool)
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			blocked[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	clean := make(http.Header)
	for name, values := range headers {
		if !forbiddenHeader(http.CanonicalHeaderKey(name)) && !blocked[http.CanonicalHeaderKey(name)] {
			clean[name] = values
		}
	}
	return clean
}

func encode(response Response) []byte {
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > MaxMessageBytes {
		raw, _ = json.Marshal(Response{Status: response.Status, Error: "response exceeds cell capacity"})
	}
	return raw
}
