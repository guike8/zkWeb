// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func apiArgs() []string {
	return []string{"--client-dir", "/profiles/client-0", "--url", "http://127.0.0.1:8080", "--upstream", "https://api.example.com", "--method", "POST", "--path", "/v1/items?a=%2F", "--data", ""}
}
func apiReport(method, path string, status int, body []byte) []byte {
	encoded, _ := json.Marshal(map[string]any{"format": "zkweb-zk-api-result-v1", "method": method, "path": path, "upstream": "https://api.example.com", "status": status, "headers": []zkAPIHeader{{Name: "content-type", Value: "application/octet-stream"}}, "body_base64": base64.StdEncoding.EncodeToString(body)})
	return encoded
}
func argValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func TestZKAPIBinaryBodyIsPrivateTemporaryFileAndCleaned(t *testing.T) {
	body := make([]byte, zkAPIBodyLimit)
	for index := range body {
		body[index] = byte(index)
	}
	input := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(input, body, 0600); err != nil {
		t.Fatal(err)
	}
	args := apiArgs()
	args = append(args[:len(args)-2], "--data-file", input, "--header", "X-Zebra: last", "--header", "Accept: first", "--header", "Accept: second")
	var output bytes.Buffer
	var temporary string
	calls := 0
	err := zkAPIWithBackend(context.Background(), args, &output, func(ctx context.Context, backend string, args []string, destination io.Writer) error {
		calls++
		if backend != "/opt/zkweb/bin/zkweb-zk-listener" || args[0] != "api-request" {
			t.Fatal("unexpected backend")
		}
		if _, exists := ctx.Deadline(); !exists {
			t.Fatal("request lacks deadline")
		}
		temporary = argValue(args, "--body-file")
		if temporary == input || !filepath.IsAbs(temporary) {
			t.Fatal("body was not privately staged")
		}
		staged, err := os.ReadFile(temporary)
		if err != nil || !bytes.Equal(staged, body) {
			t.Fatal("body bytes changed")
		}
		info, err := os.Stat(temporary)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("temporary body is not private")
		}
		if argValue(args, "--data-base64") != "" {
			t.Fatal("large body leaked into arguments")
		}
		raw, err := base64.StdEncoding.DecodeString(argValue(args, "--headers-base64"))
		if err != nil {
			t.Fatal(err)
		}
		var headers []zkAPIHeader
		if json.Unmarshal(raw, &headers) != nil || !reflect.DeepEqual(headers, []zkAPIHeader{{"accept", "first"}, {"accept", "second"}, {"x-zebra", "last"}}) {
			t.Fatal("header canonicalization changed repeated order")
		}
		_, err = destination.Write(apiReport("POST", "/v1/items?a=%2F", 201, body))
		return err
	}, zkExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !json.Valid(output.Bytes()) {
		t.Fatal("request retried or invalid output")
	}
	if _, err := os.Stat(temporary); !os.IsNotExist(err) {
		t.Fatal("temporary plaintext body was retained")
	}
}

func TestZKAPIBackendFailuresAreUnknownAndCleanUp(t *testing.T) {
	for _, result := range [][]byte{nil, []byte(`{"secret":"do not print"}`), apiReport("POST", "/v1/items?a=%2F", 200, nil)} {
		var output bytes.Buffer
		var temporary string
		calls := 0
		err := zkAPIWithBackend(context.Background(), apiArgs(), &output, func(_ context.Context, _ string, args []string, destination io.Writer) error {
			calls++
			temporary = argValue(args, "--body-file")
			_, _ = destination.Write(result)
			return errors.New("crashed after possible delivery")
		}, zkExecutable)
		if err == nil || !strings.Contains(err.Error(), "delivery unknown") || output.Len() != 0 || calls != 1 {
			t.Fatal("uncertain request was retried, exposed or called definite")
		}
		if _, err := os.Stat(temporary); !os.IsNotExist(err) {
			t.Fatal("failed request kept its body file")
		}
	}
}

func TestZKAPIUpstreamErrorStatusesRemainResults(t *testing.T) {
	for _, status := range []int{200, 301, 401, 429, 500, 503} {
		var output bytes.Buffer
		err := zkAPIWithBackend(context.Background(), apiArgs(), &output, func(_ context.Context, _ string, _ []string, destination io.Writer) error {
			_, err := destination.Write(apiReport("POST", "/v1/items?a=%2F", status, []byte("upstream response")))
			return err
		}, zkExecutable)
		if err != nil || !json.Valid(output.Bytes()) {
			t.Fatalf("upstream status %d confused with gateway failure: %v", status, err)
		}
	}
}

func TestZKAPIInvalidInputsNeverLaunch(t *testing.T) {
	cases := [][]string{
		{"--client-dir", "/client", "--url", "http://localhost:80", "--upstream", "https://example.com", "--path", "/"},
		{"--client-dir", "/client", "--url", "http://127.0.0.1:80", "--upstream", "http://example.com", "--path", "/"},
		append(apiArgs(), "--wire", "automatic"),
	}
	for _, option := range [][]string{{"--method", "CONNECT"}, {"--path", "//evil.test/x"}, {"--path", "/x/../admin"}, {"--path", "/%2e%2e/admin"}, {"--path", "/%252e/admin"}, {"--path", "/bad\\path"}, {"--path", "/bad#fragment"}, {"--header", "Authorization: secret"}, {"--header", "Cookie: session=x"}, {"--header", "X-ZkWeb-Proof: copied"}, {"--header", "Host: evil.test"}, {"--header", "Connection: close"}, {"--header", "X-Test: bad\r\nInjected: yes"}, {"--header", "not a header"}, {"--data-file", "/missing"}} {
		cases = append(cases, append(apiArgs(), option...))
	}
	for _, args := range cases {
		calls := 0
		var out bytes.Buffer
		err := zkAPIWithBackend(context.Background(), args, &out, func(context.Context, string, []string, io.Writer) error { calls++; return nil }, zkExecutable)
		if err == nil || calls != 0 || out.Len() != 0 {
			t.Fatalf("invalid request launched: %v", args)
		}
	}
	large := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(large, make([]byte, zkAPIBodyLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := zkAPIReadBody(large); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestZKGatewayListenModeArgumentsAndExclusivity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	err := zkWithBackend(ctx, "listen", []string{"--server-dir", "/server", "--upstream", "https://127.0.0.1:9443", "--allow-methods", "get,post", "--allow-private-upstream", "--upstream-ca-file", "/ca.pem", "--upstream-headers-file", "/headers.json"}, &out, func(_ context.Context, _ string, args []string, destination io.Writer) error {
		if argValue(args, "--state-file") != "" || argValue(args, "--upstream") != "https://127.0.0.1:9443" || argValue(args, "--allow-methods") != "GET,POST" || argValue(args, "--allow-private-upstream") != "true" || argValue(args, "--upstream-ca-file") != "/ca.pem" {
			t.Fatal("gateway policy arguments changed")
		}
		_, err := io.WriteString(destination, `{"event":"ready","url":"http://127.0.0.1:8001","profile_id":"`+strings.Repeat("a", 64)+`","protocol":"`+zkProtocol+`"}`+"\n")
		return err
	}, zkExecutable)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--server-dir", "/server", "--state-file", "/db", "--upstream", "https://example.com"}, {"--server-dir", "/server", "--state-file", "/db", "--allow-methods", "POST"}, {"--server-dir", "/server", "--upstream", "https://example.com", "--allow-methods", "TRACE"}} {
		called := false
		err := zkWithBackend(context.Background(), "listen", args, io.Discard, func(context.Context, string, []string, io.Writer) error { called = true; return nil }, zkExecutable)
		if err == nil || called {
			t.Fatal("invalid gateway configuration launched")
		}
	}
}
