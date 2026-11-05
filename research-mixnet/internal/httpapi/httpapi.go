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
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/httppolicy"
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
	u, err := httppolicy.ParseOrigin(target)
	if err != nil {
		return nil, err
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

func publicIP(ip netip.Addr) bool {
	return httppolicy.PublicIP(ip)
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
	headers := make(http.Header, len(request.Headers))
	for name, value := range request.Headers {
		headers[name] = []string{value}
	}
	if err := httppolicy.ValidateRequest(request.Method, request.Path, headers); err != nil {
		return request, err
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
	result.Headers = httppolicy.ResponseHeaders(response.Header)
	result.Body = string(body)
	return encode(result)
}

func encode(response Response) []byte {
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > MaxMessageBytes {
		raw, _ = json.Marshal(Response{Status: response.Status, Error: "response exceeds cell capacity"})
	}
	return raw
}
