// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const privateTestProfile = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func privateTestExecutable() (string, error) { return "/test/bin/zkweb", nil }

func privateSetupFixture() string {
	return `{"format":"zkweb-private-setup-v1","client_dir":"/test/client","server_dir":"/test/server","profile_id":"` + privateTestProfile + `","protocol":"zkweb-private-query-v1"}`
}

func privateReadyFixture() string {
	return `{"event":"ready","url":"http://127.0.0.1:12345","profile_id":"` + privateTestProfile + `","protocol":"zkweb-private-query-v1"}` + "\n"
}

func TestPrivateSetupPassesAbsoluteArgumentsToFixedBackend(t *testing.T) {
	var output bytes.Buffer
	calls := 0
	runner := func(ctx context.Context, backend string, args []string, out io.Writer) error {
		calls++
		expected, err := filepath.Abs("private-fixture")
		if err != nil {
			t.Fatal(err)
		}
		if backend != "/test/bin/zkweb-private" || !reflect.DeepEqual(args, []string{"setup", "--output", expected}) {
			t.Fatal("backend path or structured setup arguments changed")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Minute || time.Until(deadline) < 9*time.Minute {
			t.Fatal("setup timeout missing")
		}
		if output.Len() != 0 {
			t.Fatal("output preceded backend completion")
		}
		_, err = io.WriteString(out, privateSetupFixture())
		return err
	}
	if err := privateWithBackend(context.Background(), "setup", []string{"--output", "private-fixture"}, &output, runner, privateTestExecutable); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !json.Valid(output.Bytes()) {
		t.Fatal("setup result missing or repeated")
	}
}

func TestPrivateQueryPreservesSelectorOnlyInLocalBackendArguments(t *testing.T) {
	for _, index := range []string{"0", "3"} {
		var output bytes.Buffer
		runner := func(ctx context.Context, backend string, args []string, out io.Writer) error {
			clientDir, _ := filepath.Abs("client-fixture")
			if backend != "/test/bin/zkweb-private" || !reflect.DeepEqual(args, []string{"query", "--client-dir", clientDir, "--url", "http://127.0.0.1:12345", "--index", index}) {
				t.Fatal("private query arguments changed")
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) < 4*time.Second {
				t.Fatal("query deadline missing")
			}
			_, err := io.WriteString(out, `{"format":"zkweb-private-result-v1","index":`+index+`,"value":33}`)
			return err
		}
		if err := privateWithBackend(context.Background(), "query", []string{"--client-dir", "client-fixture", "--url", "http://127.0.0.1:12345", "--index", index, "--timeout", "5s"}, &output, runner, privateTestExecutable); err != nil {
			t.Fatal(err)
		}
		if !json.Valid(output.Bytes()) {
			t.Fatal("query result missing")
		}
	}
}

func TestPrivateServeForwardsOnlyValidatedReadyBeforeCompletion(t *testing.T) {
	var output bytes.Buffer
	runner := func(ctx context.Context, backend string, args []string, out io.Writer) error {
		serverDir, _ := filepath.Abs("server-fixture")
		if backend != "/test/bin/zkweb-private" || !reflect.DeepEqual(args, []string{"serve", "--server-dir", serverDir, "--listen", "127.0.0.1:0"}) {
			t.Fatal("server arguments changed")
		}
		if _, hasDeadline := ctx.Deadline(); hasDeadline {
			t.Fatal("server unexpectedly has a fixed deadline")
		}
		ready := privateReadyFixture()
		if _, err := io.WriteString(out, ready[:20]); err != nil {
			return err
		}
		if output.Len() != 0 {
			t.Fatal("partial readiness line escaped")
		}
		if _, err := io.WriteString(out, ready[20:]); err != nil {
			return err
		}
		if !json.Valid(bytes.TrimSpace(output.Bytes())) {
			t.Fatal("ready result did not stream while server runs")
		}
		return nil
	}
	if err := privateWithBackend(context.Background(), "serve", []string{"--server-dir", "server-fixture"}, &output, runner, privateTestExecutable); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateArgumentValidationStopsBeforeBackend(t *testing.T) {
	for _, tc := range []struct {
		mode string
		args []string
	}{
		{"setup", nil}, {"setup", []string{"--output", ""}}, {"setup", []string{"--output", "x", "--timeout", "29s"}}, {"setup", []string{"--output", "x", "--timeout", "31m"}},
		{"serve", nil}, {"serve", []string{"--server-dir", "x", "--listen", "example.com:1"}}, {"serve", []string{"--server-dir", "x", "--listen", "0.0.0.0:80"}}, {"serve", []string{"--server-dir", "x", "--listen", "127.0.0.1:65536"}},
		{"query", nil}, {"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80", "--index", "4"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80", "--index", "-1"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80", "--index", "0", "--timeout", "0s"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80", "--index", "0", "--timeout", "11m"}},
		{"query", []string{"--client-dir", "x", "--url", "http://user:private-test@127.0.0.1:80", "--index", "0"}},
		{"query", []string{"--client-dir", "x", "--url", "http://example.com:80", "--index", "0"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:0", "--index", "0"}},
		{"query", []string{"--client-dir", "x", "--url", "https://127.0.0.1:80", "--index", "0"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80/private-test", "--index", "0"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80?private-test", "--index", "0"}},
		{"query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80#", "--index", "0"}},
		{"setup", []string{"--private-test"}}, {"setup", []string{"--output", "x", "private-test"}}, {"setup", []string{"--output", "x", "--backend", "/private-test"}},
	} {
		var output bytes.Buffer
		runner := func(context.Context, string, []string, io.Writer) error {
			t.Fatal("invalid arguments reached backend")
			return nil
		}
		err := privateWithBackend(context.Background(), tc.mode, tc.args, &output, runner, privateTestExecutable)
		if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "private-test") {
			t.Fatalf("unsafe private arguments accepted or exposed: mode=%s", tc.mode)
		}
	}
}

func TestPrivateOutputValidationRejectsSecretsAndMalformedResults(t *testing.T) {
	for _, result := range []string{
		`{"format":"zkweb-private-result-v1","index":0,"value":33,"client_key":"private-test"}`,
		`{"format":"zkweb-private-result-v1","index":0,"index":0,"value":33}`,
		`{"format":"zkweb-private-result-v1","value":33}`,
		`{"format":"zkweb-private-result-v1","index":null,"value":33}`,
		`{"format":"zkweb-private-result-v1","index":1,"value":33}`,
		`{"format":"zkweb-private-result-v1","index":0,"value":256}`,
		`{"format":"zkweb-private-result-v1","index":0,"value":33} {}`,
		"private-test",
		strings.Repeat("x", privateOutputLimit+1),
	} {
		var output bytes.Buffer
		runner := func(_ context.Context, _ string, _ []string, out io.Writer) error {
			_, err := io.WriteString(out, result)
			return err
		}
		err := privateWithBackend(context.Background(), "query", []string{"--client-dir", "x", "--url", "http://127.0.0.1:80", "--index", "0"}, &output, runner, privateTestExecutable)
		if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "private-test") {
			t.Fatal("invalid or secret-bearing result escaped")
		}
	}
}

func TestPrivateServeRejectsInvalidReadyAndFurtherOutput(t *testing.T) {
	for _, result := range []string{
		strings.Replace(privateReadyFixture(), "http://127.0.0.1:12345", "http://other.example:12345", 1),
		strings.Replace(privateReadyFixture(), privateTestProfile, "private-test", 1),
		strings.Replace(privateReadyFixture(), `"event":"ready"`, `"event":"private-test"`, 1),
		strings.TrimSuffix(privateReadyFixture(), "\n"),
		privateReadyFixture() + `{"secret":"private-test"}` + "\n",
	} {
		var output bytes.Buffer
		runner := func(_ context.Context, _ string, _ []string, out io.Writer) error {
			_, err := io.WriteString(out, result)
			return err
		}
		err := privateWithBackend(context.Background(), "serve", []string{"--server-dir", "x"}, &output, runner, privateTestExecutable)
		if err == nil || strings.Contains(output.String(), "private-test") || strings.Contains(err.Error(), "private-test") {
			t.Fatal("invalid server output escaped")
		}
	}
}

func TestPrivateHelpMissingBackendAndCancellation(t *testing.T) {
	for _, mode := range []string{"setup", "serve", "query"} {
		var output bytes.Buffer
		runner := func(context.Context, string, []string, io.Writer) error { t.Fatal("help ran backend"); return nil }
		if err := privateWithBackend(context.Background(), mode, []string{"--help"}, &output, runner, privateTestExecutable); err != nil || !strings.Contains(output.String(), "zkweb private-"+mode) {
			t.Fatal("private help failed")
		}
	}
	var output bytes.Buffer
	missing := func(context.Context, string, []string, io.Writer) error { return errPrivateBackendUnavailable }
	if err := privateWithBackend(context.Background(), "setup", []string{"--output", "x"}, &output, missing, privateTestExecutable); err == nil || !strings.Contains(err.Error(), "make build-private") || output.Len() != 0 {
		t.Fatal("missing optional backend not explained")
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- privateWithBackend(ctx, "serve", []string{"--server-dir", "x"}, &output, func(ctx context.Context, _ string, _ []string, _ io.Writer) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}, privateTestExecutable)
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "canceled") {
			t.Fatal("server cancellation ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("server did not join after cancellation")
	}
}

func privateTestScript(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backend")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+content+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPrivateProcessBoundaryClearsEnvironmentBoundsOutputAndReaps(t *testing.T) {
	t.Setenv("ZKWEB_PRIVATE_SECRET", "private-test")
	backend := privateTestScript(t, "exec /usr/bin/env")
	var output bytes.Buffer
	if err := runPrivateBackend(context.Background(), backend, nil, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "private-test") || strings.Contains(output.String(), "ZKWEB_PRIVATE_SECRET") || !strings.Contains(output.String(), "RAYON_NUM_THREADS=4") {
		t.Fatal("private backend inherited environment")
	}
	large := privateTestScript(t, "exec /usr/bin/head -c 1100000 /dev/zero")
	output.Reset()
	if err := runPrivateBackend(context.Background(), large, nil, &output); err == nil || output.Len() > privateOutputLimit {
		t.Fatal("backend output unbounded")
	}
	slow := privateTestScript(t, "exec /bin/sleep 60")
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if err := runPrivateBackend(ctx, slow, nil, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("backend process not canceled")
	}
	if err := runPrivateBackend(context.Background(), "relative", nil, io.Discard); !errors.Is(err, errPrivateBackendUnavailable) {
		t.Fatal("relative backend accepted")
	}
}
