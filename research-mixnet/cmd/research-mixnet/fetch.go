// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/webclient"
)

type fetchClient interface {
	Do(context.Context, webclient.Request) (webclient.Response, error)
}

type fetchFactory func(webclient.Options) (fetchClient, error)

func fetch(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	return fetchWithFactory(ctx, args, in, out, func(options webclient.Options) (fetchClient, error) {
		return webclient.New(options)
	})
}

func fetchWithFactory(ctx context.Context, args []string, in io.Reader, out io.Writer, newClient fetchFactory) error {
	options := webclient.Options{
		Timeout:          45 * time.Second,
		MaxRequestBytes:  webclient.DefaultBodyBytes,
		MaxResponseBytes: webclient.DefaultBodyBytes,
	}
	f := flag.NewFlagSet("fetch", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&options.Target, "target", "", "allowed HTTPS origin, such as https://api.example.com")
	f.StringVar(&options.Proxy, "proxy", "", "required loopback tor:// or socks5:// proxy, such as tor://127.0.0.1:9050")
	input := f.String("input", "-", "request JSON file, or - for stdin; keep credentials in this input")
	f.DurationVar(&options.Timeout, "timeout", options.Timeout, "request deadline (1s–10m)")
	f.Int64Var(&options.MaxRequestBytes, "max-request-bytes", options.MaxRequestBytes, "maximum decoded request body bytes (1–16777216)")
	f.Int64Var(&options.MaxResponseBytes, "max-response-bytes", options.MaxResponseBytes, "maximum response body bytes (1–16777216)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := fmt.Fprintln(out, "usage: zkweb fetch --target HTTPS_ORIGIN --proxy tor://127.0.0.1:9050 --input FILE|- [--timeout 45s --max-request-bytes 1048576 --max-response-bytes 1048576]"); err != nil {
				return errors.New("cannot write fetch help")
			}
			f.SetOutput(out)
			f.PrintDefaults()
			return nil
		}
		return errors.New("invalid fetch arguments; use fetch --help")
	}
	if f.NArg() != 0 || options.Target == "" || options.Proxy == "" || *input == "" {
		return errors.New("fetch requires --target HTTPS_ORIGIN and --proxy LOOPBACK_PROXY; no positional arguments")
	}
	if options.Timeout < time.Second || options.Timeout > 10*time.Minute ||
		options.MaxRequestBytes < 1 || options.MaxRequestBytes > webclient.MaxBodyBytes ||
		options.MaxResponseBytes < 1 || options.MaxResponseBytes > webclient.MaxBodyBytes {
		return errors.New("fetch requires a 1s–10m deadline and body limits of 1–16777216 bytes")
	}
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			return errors.New("cannot open fetch input")
		}
		defer file.Close()
		in = file
	}
	// JSON strings may need six source bytes for each decoded byte (\u00xx).
	// Base64 is smaller, while headers and fixed fields have their own allowance.
	maxEnvelope := 6*options.MaxRequestBytes + 6*int64(webclient.MaxHeaderBytes) + 8192
	raw, err := io.ReadAll(io.LimitReader(in, maxEnvelope+1))
	if err != nil {
		return errors.New("cannot read fetch input")
	}
	if len(raw) == 0 || int64(len(raw)) > maxEnvelope {
		return errors.New("fetch input exceeds the configured envelope limit")
	}
	request, err := decodeFetchRequest(raw, options.MaxRequestBytes)
	if err != nil {
		return errors.New("invalid fetch JSON: use method, path, optional headers and either body or body_base64 within the configured limits")
	}
	client, err := newClient(options)
	if err != nil {
		return errors.New("invalid fetch configuration; use an HTTPS origin and an explicit numeric loopback Tor/SOCKS5 proxy")
	}
	response, err := client.Do(ctx, request)
	if err != nil {
		if errors.Is(err, webclient.ErrRequestRejected) {
			return errors.New("fetch request rejected before transmission; check the method, path, headers and configured limits")
		}
		code := "request_failed"
		if errors.Is(err, webclient.ErrDeliveryUnknown) {
			code = "delivery_unknown"
		}
		if outputErr := writeFetchResponse(out, response, code); outputErr != nil {
			return outputErr
		}
		return errors.New("fetch did not complete; the operation may already have executed; do not retry automatically")
	}
	if response.Status < 100 || response.Status > 599 || int64(len(response.Body)) > options.MaxResponseBytes {
		if err := writeFetchResponse(out, webclient.Response{Status: response.Status}, "delivery_unknown"); err != nil {
			return err
		}
		return errors.New("delivery_unknown: invalid or oversized response; do not retry automatically")
	}
	if err := writeFetchResponse(out, response, ""); err != nil {
		return err
	}
	if response.Status >= 400 {
		return errors.New("upstream returned an HTTP error; inspect the response status and body")
	}
	return nil
}

func decodeFetchRequest(raw []byte, maxBodyBytes int64) (webclient.Request, error) {
	var request webclient.Request
	if !utf8.Valid(raw) {
		return request, errors.New("invalid UTF-8 JSON")
	}
	fields, err := fetchObject(raw)
	if err != nil {
		return request, err
	}
	for name := range fields {
		switch name {
		case "method", "path", "headers", "body", "body_base64":
		default:
			return request, errors.New("unknown field")
		}
	}
	if request.Method, err = fetchString(fields["method"]); err != nil {
		return request, err
	}
	if request.Path, err = fetchString(fields["path"]); err != nil {
		return request, err
	}
	request.Headers = make(http.Header)
	if rawHeaders, present := fields["headers"]; present {
		headers, err := fetchObject(rawHeaders)
		if err != nil {
			return request, err
		}
		seen := make(map[string]bool)
		var total int64
		for name, rawValue := range headers {
			canonical := http.CanonicalHeaderKey(name)
			if seen[canonical] {
				return request, errors.New("duplicate header")
			}
			seen[canonical] = true
			var values []string
			if len(rawValue) > 0 && rawValue[0] == '[' {
				var items []json.RawMessage
				if json.Unmarshal(rawValue, &items) != nil || len(items) == 0 {
					return request, errors.New("invalid header values")
				}
				for _, item := range items {
					value, err := fetchString(item)
					if err != nil {
						return request, err
					}
					values = append(values, value)
				}
			} else {
				value, err := fetchString(rawValue)
				if err != nil {
					return request, err
				}
				values = []string{value}
			}
			for _, value := range values {
				total += int64(len(name) + len(value) + 4)
			}
			if total > int64(webclient.MaxHeaderBytes) {
				return request, errors.New("headers exceed limit")
			}
			request.Headers[canonical] = values
		}
	}
	text, hasText := fields["body"]
	encoded, hasEncoded := fields["body_base64"]
	if hasText && hasEncoded {
		return request, errors.New("ambiguous body")
	}
	if hasText {
		body, err := fetchString(text)
		if err != nil {
			return request, err
		}
		request.Body = []byte(body)
	}
	if hasEncoded {
		body, err := fetchString(encoded)
		if err != nil || strings.ContainsAny(body, " \t\r\n") || int64(len(body)) > int64(base64.StdEncoding.EncodedLen(int(maxBodyBytes))) {
			return request, errors.New("invalid base64 body")
		}
		request.Body, err = base64.StdEncoding.Strict().DecodeString(body)
		if err != nil {
			return request, errors.New("invalid base64 body")
		}
	}
	if int64(len(request.Body)) > maxBodyBytes {
		return request, errors.New("body exceeds limit")
	}
	return request, nil
}

// Unlike struct/map decoding, token iteration rejects duplicate and null fields.
func fetchObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid object key")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return nil, errors.New("invalid object value")
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, errors.New("invalid object")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("expected one object")
	}
	return fields, nil
}

func fetchString(raw []byte) (string, error) {
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return "", errors.New("expected string")
	}
	return value, nil
}

func writeFetchResponse(out io.Writer, response webclient.Response, code string) error {
	wire := struct {
		Status     int         `json:"status,omitempty"`
		Headers    http.Header `json:"headers,omitempty"`
		Body       *string     `json:"body,omitempty"`
		BodyBase64 string      `json:"body_base64,omitempty"`
		Error      string      `json:"error,omitempty"`
	}{Status: response.Status, Headers: response.Headers, Error: code}
	if code == "" {
		if utf8.Valid(response.Body) {
			body := string(response.Body)
			wire.Body = &body
		} else {
			wire.BodyBase64 = base64.StdEncoding.EncodeToString(response.Body)
		}
	}
	if err := json.NewEncoder(out).Encode(wire); err != nil {
		return errors.New("cannot write fetch response; the operation may already have executed")
	}
	return nil
}
