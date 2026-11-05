// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/webclient"
)

type fakeFetchClient func(context.Context, webclient.Request) (webclient.Response, error)

func (f fakeFetchClient) Do(ctx context.Context, request webclient.Request) (webclient.Response, error) {
	return f(ctx, request)
}

func fetchArgs(extra ...string) []string {
	return append([]string{"--target", "https://api.example.com", "--proxy", "tor://127.0.0.1:9050"}, extra...)
}

func TestFetchPreservesBinaryBodiesHeadersAndOptions(t *testing.T) {
	body := []byte{0, 255, 128, 1, '\r', '\n'}
	input := `{"method":"POST","path":"/files?name=example","headers":{"Content-Type":"application/octet-stream","Authorization":"Bearer private-test","X-Tag":["one","two"]},"body_base64":"` + base64.StdEncoding.EncodeToString(body) + `"}`
	calls := 0
	factory := func(options webclient.Options) (fetchClient, error) {
		if options.Target != "https://api.example.com" || options.Proxy != "tor://127.0.0.1:9050" || options.Timeout != 45*time.Second || options.MaxRequestBytes != webclient.DefaultBodyBytes || options.MaxResponseBytes != webclient.DefaultBodyBytes {
			t.Fatal("fetch altered explicit routing or default limits")
		}
		return fakeFetchClient(func(_ context.Context, request webclient.Request) (webclient.Response, error) {
			calls++
			if request.Method != "POST" || request.Path != "/files?name=example" || !bytes.Equal(request.Body, body) || request.Headers.Get("Authorization") != "Bearer private-test" || !reflect.DeepEqual(request.Headers.Values("X-Tag"), []string{"one", "two"}) {
				t.Fatal("fetch changed request bytes, path or headers")
			}
			return webclient.Response{Status: 201, Headers: http.Header{"X-Tag": {"response-one", "response-two"}}, Body: body}, nil
		}), nil
	}
	var output bytes.Buffer
	if err := fetchWithFactory(context.Background(), fetchArgs(), strings.NewReader(input), &output, factory); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Status     int         `json:"status"`
		Headers    http.Header `json:"headers"`
		Body       *string     `json:"body"`
		BodyBase64 string      `json:"body_base64"`
	}
	if json.Unmarshal(output.Bytes(), &response) != nil || response.Status != 201 || response.Body != nil || response.BodyBase64 != base64.StdEncoding.EncodeToString(body) || calls != 1 || len(response.Headers.Values("X-Tag")) != 2 {
		t.Fatal("fetch did not preserve the binary response envelope")
	}
}

func TestFetchRejectsAmbiguousOrInvalidJSONBeforeClient(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `{}`, `{"method":"GET","path":null}`,
		`{"method":"GET","path":"/","path":"/other"}`,
		`{"Method":"GET","path":"/"}`,
		`{"method":"GET","path":"/","unknown":"private-test"}`,
		`{"method":"GET","path":"/"} {"private-test":true}`,
		`{"method":"GET","path":"/","headers":null}`,
		`{"method":"GET","path":"/","headers":{"X-Test":"one","X-Test":"two"}}`,
		`{"method":"GET","path":"/","headers":{"x-test":"one","X-Test":"two"}}`,
		`{"method":"GET","path":"/","headers":{"X-Test":null}}`,
		`{"method":"GET","path":"/","headers":{"X-Test":[]}}`,
		`{"method":"GET","path":"/","headers":{"X-Test":["one",null]}}`,
		`{"method":"GET","path":"/","headers":{"X-Test":7}}`,
		`{"method":"POST","path":"/","body":null}`,
		`{"method":"POST","path":"/","body":"one","body_base64":"dHdv"}`,
		`{"method":"POST","path":"/","body_base64":"%%%private-test"}`,
		`{"method":"POST","path":"/","body_base64":"AB=="}`,
		`{"method":"POST","path":"/","body_base64":"dA==\n"}`,
		string([]byte{'{', '"', 255, '"', ':', '1', '}'}),
	} {
		var output bytes.Buffer
		factory := func(webclient.Options) (fetchClient, error) {
			t.Fatal("invalid JSON reached client construction")
			return nil, nil
		}
		err := fetchWithFactory(context.Background(), fetchArgs(), strings.NewReader(input), &output, factory)
		if err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 {
			t.Fatal("invalid fetch input was accepted or disclosed")
		}
	}
}

func TestFetchBoundsDecodedBodyHeadersAndEnvelope(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		input string
	}{
		{fetchArgs("--max-request-bytes", "2"), `{"method":"POST","path":"/","body":"abc"}`},
		{fetchArgs("--max-request-bytes", "2"), `{"method":"POST","path":"/","body_base64":"YWJj"}`},
		{fetchArgs(), `{"method":"GET","path":"/","headers":{"X-Test":"` + strings.Repeat("x", int(webclient.MaxHeaderBytes)) + `"}}`},
		{fetchArgs("--max-request-bytes", "1"), strings.Repeat(" ", 6*int(webclient.MaxHeaderBytes)+9000)},
	} {
		factory := func(webclient.Options) (fetchClient, error) {
			t.Fatal("oversized input reached client construction")
			return nil, nil
		}
		var output bytes.Buffer
		if err := fetchWithFactory(context.Background(), tc.args, strings.NewReader(tc.input), &output, factory); err == nil || output.Len() != 0 {
			t.Fatal("oversized fetch input was accepted")
		}
	}
	request, err := decodeFetchRequest([]byte(`{"method":"POST","path":"/","body":"\u0061\u0062"}`), 2)
	if err != nil || string(request.Body) != "ab" {
		t.Fatal("a fitting escaped body was rejected")
	}
}

func TestFetchRequiresExplicitProxyAndBoundedOptions(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--target", "https://api.example.com"}, {"--proxy", "tor://127.0.0.1:9050"},
		fetchArgs("--timeout", "0s"), fetchArgs("--timeout", "11m"),
		fetchArgs("--max-request-bytes", "0"), fetchArgs("--max-request-bytes", "16777217"),
		fetchArgs("--max-response-bytes", "0"), fetchArgs("--max-response-bytes", "16777217"),
		fetchArgs("--private-test"), fetchArgs("private-test"),
	} {
		factory := func(webclient.Options) (fetchClient, error) {
			t.Fatal("invalid arguments reached client construction")
			return nil, nil
		}
		var output bytes.Buffer
		err := fetchWithFactory(context.Background(), args, strings.NewReader(`{"method":"GET","path":"/"}`), &output, factory)
		if err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 {
			t.Fatal("unsafe fetch arguments were accepted or disclosed")
		}
	}
}

func TestFetchPreservesHTTPErrorAndTextBody(t *testing.T) {
	factory := func(webclient.Options) (fetchClient, error) {
		return fakeFetchClient(func(context.Context, webclient.Request) (webclient.Response, error) {
			return webclient.Response{Status: 404, Body: []byte("missing\n")}, nil
		}), nil
	}
	var output bytes.Buffer
	err := fetchWithFactory(context.Background(), fetchArgs(), strings.NewReader(`{"method":"GET","path":"/"}`), &output, factory)
	if err == nil || output.String() != "{\"status\":404,\"body\":\"missing\\n\"}\n" {
		t.Fatal("HTTP error status/body was lost")
	}
}

func TestFetchUnknownDeliveryDoesNotRetryOrExposeError(t *testing.T) {
	calls := 0
	factory := func(webclient.Options) (fetchClient, error) {
		return fakeFetchClient(func(context.Context, webclient.Request) (webclient.Response, error) {
			calls++
			return webclient.Response{Status: 201, Body: []byte("private-test partial body")}, fmt.Errorf("%w: private-test URL and credentials", webclient.ErrDeliveryUnknown)
		}), nil
	}
	var output bytes.Buffer
	err := fetchWithFactory(context.Background(), fetchArgs(), strings.NewReader(`{"method":"POST","path":"/"}`), &output, factory)
	if err == nil || strings.Contains(err.Error(), "private-test") || strings.Contains(output.String(), "private-test") || calls != 1 || output.String() != "{\"status\":201,\"error\":\"delivery_unknown\"}\n" {
		t.Fatal("ambiguous mutation was retried or sensitive partial data was disclosed")
	}
}

func TestFetchRejectedRequestHasNoResponse(t *testing.T) {
	factory := func(webclient.Options) (fetchClient, error) {
		return fakeFetchClient(func(context.Context, webclient.Request) (webclient.Response, error) {
			return webclient.Response{}, fmt.Errorf("%w: private-test", webclient.ErrRequestRejected)
		}), nil
	}
	var output bytes.Buffer
	err := fetchWithFactory(context.Background(), fetchArgs(), strings.NewReader(`{"method":"GET","path":"/"}`), &output, factory)
	if err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 {
		t.Fatal("request rejection was mislabeled or exposed details")
	}
}

func TestFetchReadsFileWithExplicitOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fetch.json")
	if err := os.WriteFile(path, []byte(`{"method":"PUT","path":"/items/1","body":"updated"}`), 0600); err != nil {
		t.Fatal(err)
	}
	factory := func(options webclient.Options) (fetchClient, error) {
		if options.Timeout != 90*time.Second || options.MaxRequestBytes != 4096 || options.MaxResponseBytes != 8192 {
			t.Fatal("configured fetch limits were lost")
		}
		return fakeFetchClient(func(_ context.Context, request webclient.Request) (webclient.Response, error) {
			if request.Method != "PUT" || string(request.Body) != "updated" {
				t.Fatal("file request was changed")
			}
			return webclient.Response{Status: 204}, nil
		}), nil
	}
	var output bytes.Buffer
	err := fetchWithFactory(context.Background(), fetchArgs("--input", path, "--timeout", "90s", "--max-request-bytes", "4096", "--max-response-bytes", "8192"), strings.NewReader("unused"), &output, factory)
	if err != nil || output.String() != "{\"status\":204,\"body\":\"\"}\n" {
		t.Fatal("file fetch failed")
	}
}

func TestFetchHelpAndConfigurationErrorsAreSafe(t *testing.T) {
	var output bytes.Buffer
	factory := func(webclient.Options) (fetchClient, error) {
		return nil, errors.New("private-test configuration detail")
	}
	if err := fetchWithFactory(context.Background(), []string{"--help"}, strings.NewReader(""), &output, factory); err != nil || !strings.Contains(output.String(), "zkweb fetch") {
		t.Fatal("fetch help failed")
	}
	output.Reset()
	err := fetchWithFactory(context.Background(), fetchArgs(), strings.NewReader(`{"method":"GET","path":"/"}`), &output, factory)
	if err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 {
		t.Fatal("configuration error leaked details")
	}
}

type failedFetchWriter struct{}

func (failedFetchWriter) Write([]byte) (int, error) {
	return 0, errors.New("private-test writer detail")
}

func TestFetchWriterFailureDoesNotRepeatRequest(t *testing.T) {
	calls := 0
	factory := func(webclient.Options) (fetchClient, error) {
		return fakeFetchClient(func(context.Context, webclient.Request) (webclient.Response, error) {
			calls++
			return webclient.Response{Status: 201}, nil
		}), nil
	}
	err := fetchWithFactory(context.Background(), fetchArgs(), strings.NewReader(`{"method":"POST","path":"/"}`), failedFetchWriter{}, factory)
	if err == nil || strings.Contains(err.Error(), "private-test") || calls != 1 {
		t.Fatal("output failure repeated request or exposed writer detail")
	}
}

var _ io.Writer = failedFetchWriter{}
