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
	"time"
)

func zkExecutable() (string, error) { return "/opt/zkweb/bin/zkweb", nil }
func zkReport(method, key string, status int, body []byte) []byte {
	encoded, _ := json.Marshal(map[string]any{"format": "zkweb-zk-result-v1", "method": method, "key": key, "status": status, "body_base64": base64.StdEncoding.EncodeToString(body)})
	return encoded
}
func zkRequestArgs(method string) []string {
	args := []string{"--client-dir", "/profiles/client-0", "--url", "http://127.0.0.1:8080", "--method", method, "--key", "note-1"}
	if method == "POST" || method == "PUT" {
		args = append(args, "--data", "")
	}
	return args
}

func TestZKSetupUsesFixedBackendAndValidatesMetadata(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	runner := func(ctx context.Context, path string, args []string, destination io.Writer) error {
		calls++
		if path != "/opt/zkweb/bin/zkweb-zk-listener" || !reflect.DeepEqual(args, []string{"setup", "--output", "/profiles/new", "--members", "4"}) {
			t.Fatal("unexpected backend selection or setup arguments")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("setup has no deadline")
		}
		_, err := io.WriteString(destination, `{"format":"zkweb-zk-setup-v1","server_dir":"/profiles/new/server","client_dirs":["/profiles/new/client-0","/profiles/new/client-1","/profiles/new/client-2","/profiles/new/client-3"],"profile_id":"`+strings.Repeat("a", 64)+`","protocol":"`+zkProtocol+`","members":4}`)
		return err
	}
	if err := zkWithBackend(context.Background(), "setup", []string{"--output", "/profiles/new"}, &out, runner, zkExecutable); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !json.Valid(out.Bytes()) {
		t.Fatal("setup was retried or returned invalid metadata")
	}
}

func TestZKRequestPreservesBinaryAndEmptyBodies(t *testing.T) {
	binary := []byte{0, 255, 128, 10, 0}
	file := filepath.Join(t.TempDir(), "body.dat")
	if err := os.WriteFile(file, binary, 0600); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"POST", "PUT", "GET", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			args := zkRequestArgs(method)
			want := []byte(nil)
			status := 200
			if method == "POST" {
				args = append(args[:len(args)-2], "--data-file", file)
				want = binary
				status = 201
			}
			var out bytes.Buffer
			calls := 0
			runner := func(ctx context.Context, path string, backend []string, destination io.Writer) error {
				calls++
				if path != "/opt/zkweb/bin/zkweb-zk-listener" || backend[0] != "request" {
					t.Fatal("wrong backend")
				}
				if backend[len(backend)-2] != "--data-base64" {
					t.Fatal("body was not forwarded as an explicit argument")
				}
				body, err := base64.StdEncoding.DecodeString(backend[len(backend)-1])
				if err != nil || !bytes.Equal(body, want) {
					t.Fatal("body bytes changed")
				}
				_, err = destination.Write(zkReport(method, "note-1", status, want))
				return err
			}
			if err := zkWithBackend(context.Background(), "request", args, &out, runner, zkExecutable); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !json.Valid(out.Bytes()) {
				t.Fatal("request retried or invalid result")
			}
		})
	}
}

func TestZKInvalidArgumentsNeverLaunchBackend(t *testing.T) {
	cases := []struct {
		mode string
		args []string
	}{
		{"setup", []string{"--output", "/profiles/new", "--members", "0"}},
		{"setup", []string{"--output", "/profiles/new", "--members", "17"}},
		{"listen", []string{"--server-dir", "/profiles/server"}},
		{"listen", []string{"--server-dir", "/profiles/server", "--state-file", "/state/db", "--listen", "0.0.0.0:80"}},
		{"request", []string{"--client-dir", "/client", "--url", "https://127.0.0.1:8080", "--method", "GET", "--key", "x"}},
		{"request", []string{"--client-dir", "/client", "--url", "http://localhost:8080", "--method", "GET", "--key", "x"}},
		{"request", []string{"--client-dir", "/client", "--url", "http://127.0.0.1:8080?x=1", "--method", "GET", "--key", "x"}},
		{"request", []string{"--client-dir", "/client", "--url", "http://127.0.0.1:8080", "--method", "PATCH", "--key", "x"}},
		{"request", []string{"--client-dir", "/client", "--url", "http://127.0.0.1:8080", "--method", "GET", "--key", "../secret"}},
		{"request", append(zkRequestArgs("GET"), "--data", "")},
		{"request", append(zkRequestArgs("PUT"), "--data-file", "/body")},
		{"request", []string{"--client-dir", "/client", "--url", "http://127.0.0.1:8080", "--method", "POST", "--key", "x"}},
		{"request", append(zkRequestArgs("POST"), "extra")},
	}
	for _, test := range cases {
		var out bytes.Buffer
		calls := 0
		err := zkWithBackend(context.Background(), test.mode, test.args, &out, func(context.Context, string, []string, io.Writer) error { calls++; return nil }, zkExecutable)
		if err == nil || calls != 0 || out.Len() != 0 {
			t.Fatalf("invalid %s arguments reached backend: %v", test.mode, test.args)
		}
	}
	oversize := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(oversize, make([]byte, zkBodyLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := zkReadDataFile(oversize); err == nil {
		t.Fatal("oversized body accepted")
	}
	if _, err := zkReadDataFile(filepath.Dir(oversize)); err == nil {
		t.Fatal("directory accepted as body")
	}
}

func TestZKBackendFailureNeverPrintsResultOrRetries(t *testing.T) {
	for _, body := range [][]byte{nil, []byte(`{"credential":"secret-do-not-print"}`), zkReport("POST", "note-1", 201, []byte("saved"))} {
		var out bytes.Buffer
		calls := 0
		err := zkWithBackend(context.Background(), "request", zkRequestArgs("POST"), &out, func(_ context.Context, _ string, _ []string, destination io.Writer) error {
			calls++
			_, _ = destination.Write(body)
			return errors.New("abrupt child failure secret-do-not-print")
		}, zkExecutable)
		if err == nil || !strings.Contains(err.Error(), "delivery unknown") || strings.Contains(err.Error(), "secret-do-not-print") || calls != 1 || out.Len() != 0 {
			t.Fatal("unsafe backend failure handling")
		}
	}
	var out bytes.Buffer
	err := zkWithBackend(context.Background(), "request", zkRequestArgs("POST"), &out, func(context.Context, string, []string, io.Writer) error { return errZKBackendUnavailable }, zkExecutable)
	if err == nil || !strings.Contains(err.Error(), "build-zk") || strings.Contains(err.Error(), "unknown") || out.Len() != 0 {
		t.Fatal("missing backend should be a definite local error")
	}
}

func TestZKResultWhitelistAndLimits(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"format":"zkweb-zk-result-v1","method":"POST","key":"note-1","status":201,"body_base64":"","credential":"secret"}`),
		zkReport("PUT", "note-1", 200, nil),
		zkReport("POST", "different", 201, nil),
		zkReport("POST", "note-1", 500, nil),
		zkReport("POST", "note-1", 201, make([]byte, zkBodyLimit+1)),
		[]byte(`{"format":"zkweb-zk-result-v1","method":"POST","key":"note-1","status":201,"body_base64":"Zh=="}`),
	} {
		var out bytes.Buffer
		err := zkWithBackend(context.Background(), "request", zkRequestArgs("POST"), &out, func(_ context.Context, _ string, _ []string, destination io.Writer) error {
			_, err := destination.Write(raw)
			return err
		}, zkExecutable)
		if err == nil || !strings.Contains(err.Error(), "delivery unknown") || out.Len() != 0 {
			t.Fatal("untrusted backend result escaped whitelist")
		}
	}
	for _, status := range []int{201, 409, 507} {
		if _, err := validateZKResult("request", zkReport("POST", "note-1", status, nil), "POST", "note-1", 0); err != nil {
			t.Fatal("known CRUD status rejected")
		}
	}
}

func TestZKListenerReadyIsValidatedAndStreamsBeforeShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out bytes.Buffer
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- zkWithBackend(ctx, "listen", []string{"--server-dir", "/server", "--state-file", "/state/db"}, &out, func(ctx context.Context, _ string, args []string, destination io.Writer) error {
			if !reflect.DeepEqual(args, []string{"listen", "--server-dir", "/server", "--state-file", "/state/db", "--listen", "127.0.0.1:0"}) {
				return errors.New("wrong listen arguments")
			}
			_, err := io.WriteString(destination, `{"event":"ready","url":"http://127.0.0.1:3456","profile_id":"`+strings.Repeat("a", 64)+`","protocol":"`+zkProtocol+`"}`+"\n")
			if err != nil {
				return err
			}
			close(ready)
			<-ctx.Done()
			return ctx.Err()
		}, zkExecutable)
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("ready was not streamed")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled listener reported normal exit")
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not join")
	}
	if !json.Valid(bytes.TrimSpace(out.Bytes())) {
		t.Fatal("invalid readiness output")
	}
}

func TestZKRunnerClearsEnvironmentAndSuppressesStderr(t *testing.T) {
	t.Setenv("ZK_TEST_SECRET", "must-not-reach-child")
	backend := filepath.Join(t.TempDir(), "backend")
	script := "#!/bin/sh\nprintf '%s|%s|%s|%s' \"$PATH\" \"$LANG\" \"$LC_ALL\" \"${ZK_TEST_SECRET-absent}\"\nprintf 'secret diagnostic' >&2\n"
	if err := os.WriteFile(backend, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runZKBackend(context.Background(), backend, nil, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "/usr/bin:/bin|C|C|absent" {
		t.Fatal("ambient environment or stderr escaped")
	}
}
