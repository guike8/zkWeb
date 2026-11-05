// SPDX-License-Identifier: AGPL-3.0-or-later
// Package webclient executes bounded, byte-preserving HTTPS requests locally
// over an explicit SOCKS route. TLS terminates at this client and the origin.
package webclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/httppolicy"
	"github.com/Mirai8888/zkapi/research-mixnet/internal/transport"
)

const (
	DefaultBodyBytes = 1 << 20
	MaxBodyBytes     = 16 << 20
	MaxHeaderBytes   = 64 << 10
	maxPathBytes     = 8 << 10
)

var (
	ErrRequestRejected = errors.New("request_rejected")
	// ErrDeliveryUnknown includes all failures after handing a request to the
	// HTTP transport. The origin may have committed a mutation. Never retry it
	// automatically, including when the response is incomplete or oversized.
	ErrDeliveryUnknown = errors.New("delivery_unknown: the operation may have executed; do not automatically retry")
)

type Options struct {
	Target           string
	Proxy            string
	Timeout          time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int64
}

type Request struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
}

type Response struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// A Client is one origin-scoped context. It owns a fresh Tor isolation identity
// when configured with tor://. Reuse it only for requests belonging to that
// context. Credentials and cookies are explicit per request; no cookie jar is
// created. SOCKS mode cannot verify the proxy's implementation or egress policy.
type Client struct {
	origin  *url.URL
	http    *http.Client
	options Options
	mode    string
}

func New(options Options) (*Client, error) {
	origin, err := httppolicy.ParseOrigin(options.Target)
	if err != nil {
		return nil, rejected("target must be a public HTTPS origin without credentials, path, query or fragment")
	}
	if options.Timeout == 0 {
		options.Timeout = 45 * time.Second
	}
	if options.MaxRequestBytes == 0 {
		options.MaxRequestBytes = DefaultBodyBytes
	}
	if options.MaxResponseBytes == 0 {
		options.MaxResponseBytes = DefaultBodyBytes
	}
	if options.Timeout < time.Second || options.Timeout > 10*time.Minute ||
		options.MaxRequestBytes < 1 || options.MaxRequestBytes > MaxBodyBytes ||
		options.MaxResponseBytes < 1 || options.MaxResponseBytes > MaxBodyBytes {
		return nil, rejected("timeout or body limit is outside the supported range")
	}
	route, err := transport.NewSOCKS(options.Proxy)
	if err != nil {
		return nil, rejected("an explicit numeric loopback tor:// or socks5:// proxy is required")
	}
	httpTransport := &http.Transport{
		Proxy:                  nil,
		DialContext:            route.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    min(options.Timeout, 20*time.Second),
		ResponseHeaderTimeout:  options.Timeout,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		// HTTP/1.1 and fresh connections avoid implicit HTTP/2 stream retries
		// and HTTP transport retries on previously used connections.
		ForceAttemptHTTP2: false,
	}
	return &Client{
		origin:  origin,
		options: options,
		mode:    route.Mode(),
		http: &http.Client{
			Transport: httpTransport,
			Timeout:   options.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) Mode() string { return c.mode }

// Do performs at most one request. It returns upstream HTTP error statuses as
// responses. Transport/read errors preserve available status and headers but
// never return a partial body as a complete response.
func (c *Client) Do(ctx context.Context, input Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, errors.Join(rejected("request context is already canceled"), err)
	}
	if int64(len(input.Body)) > c.options.MaxRequestBytes || len(input.Path) > maxPathBytes {
		return Response{}, rejected("request exceeds the configured body or path limit")
	}
	if err := httppolicy.ValidateRequest(input.Method, input.Path, input.Headers); err != nil {
		return Response{}, rejected("invalid method, relative path or request headers")
	}
	headerBytes := 0
	for name, values := range input.Headers {
		headerBytes += len(name) + 2
		if headerBytes > MaxHeaderBytes {
			return Response{}, rejected("request headers exceed the supported limit")
		}
		for _, value := range values {
			headerBytes += len(name) + len(value) + 4
			if headerBytes > MaxHeaderBytes {
				return Response{}, rejected("request headers exceed the supported limit")
			}
		}
	}
	path, _ := url.Parse(input.Path) // The shared policy has validated it.
	destination := *c.origin
	destination.Path, destination.RawPath = path.Path, path.RawPath
	destination.RawQuery, destination.ForceQuery = path.RawQuery, path.ForceQuery
	body := append([]byte(nil), input.Body...)
	request, err := http.NewRequestWithContext(ctx, input.Method, destination.String(), bytes.NewReader(body))
	if err != nil {
		return Response{}, rejected("invalid request")
	}
	request.Header = canonicalHeaders(input.Headers.Clone())
	if _, explicit := request.Header["User-Agent"]; !explicit {
		request.Header["User-Agent"] = []string{""}
	}
	// Disable replayable-body support even for requests with Idempotency-Key.
	request.GetBody = nil
	response, err := c.http.Do(request)
	if err != nil {
		return Response{}, unknown(ctx, "proxy, TLS or HTTP request failed")
	}
	defer response.Body.Close()
	result := Response{
		Status:  response.StatusCode,
		Headers: httppolicy.ResponseHeaders(response.Header).Clone(),
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, c.options.MaxResponseBytes+1))
	if err != nil {
		return result, unknown(ctx, "response could not be read completely")
	}
	if int64(len(data)) > c.options.MaxResponseBytes {
		return result, unknown(ctx, "response exceeds the configured body limit")
	}
	result.Body = data
	return result, nil
}

func canonicalHeaders(headers http.Header) http.Header {
	canonical := make(http.Header, len(headers))
	for name, values := range headers {
		canonical[http.CanonicalHeaderKey(name)] = values
	}
	return canonical
}

func rejected(message string) error {
	return fmt.Errorf("%w: %s", ErrRequestRejected, message)
}

func unknown(ctx context.Context, message string) error {
	err := fmt.Errorf("%w: %s", ErrDeliveryUnknown, message)
	if ctx.Err() != nil {
		return errors.Join(err, ctx.Err())
	}
	return err
}
