// SPDX-License-Identifier: AGPL-3.0-or-later
package privatee2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This test is opt-in because it performs real TFHE key generation, ZK proof
// generation/verification and FHE evaluation. Ordinary Go builds need no FHE.
func TestPrivateBackendIntegration(t *testing.T) {
	cli := os.Getenv("ZKWEB_PRIVATE_CLI")
	if cli == "" {
		t.Skip("make test-private builds and exercises the optional ZK/FHE endpoint")
	}
	if !filepath.IsAbs(cli) {
		t.Fatal("CLI must be an explicitly selected absolute path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	root := filepath.Join(t.TempDir(), "profile")
	setup, err := run(ctx, cli, "private-setup", "--output", root)
	if err != nil {
		t.Fatalf("real private setup failed: %v", err)
	}
	var profile struct {
		Format    string `json:"format"`
		ClientDir string `json:"client_dir"`
		ServerDir string `json:"server_dir"`
		ProfileID string `json:"profile_id"`
	}
	if json.Unmarshal(setup, &profile) != nil || profile.Format != "zkweb-private-setup-v1" || profile.ClientDir == "" || profile.ServerDir == "" || len(profile.ProfileID) != 64 {
		t.Fatal("invalid setup metadata")
	}
	if _, err := os.Stat(filepath.Join(profile.ClientDir, "client-key.tfhe")); err != nil {
		t.Fatal("client secret key missing from client profile")
	}
	if _, err := os.Stat(filepath.Join(profile.ServerDir, "client-key.tfhe")); !os.IsNotExist(err) {
		t.Fatal("server received a client secret-key file")
	}
	manifest, err := os.ReadFile(filepath.Join(profile.ServerDir, "manifest.json"))
	if err != nil || bytes.Contains(manifest, []byte("client_key_sha256")) {
		t.Fatal("server manifest contains private-key material")
	}

	serverCtx, stopServer := context.WithCancel(ctx)
	server := exec.CommandContext(serverCtx, cli, "private-serve", "--server-dir", profile.ServerDir, "--listen", "127.0.0.1:0")
	server.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	server.Cancel = func() error { return server.Process.Signal(os.Interrupt) }
	server.WaitDelay = 2 * time.Second
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server.Stderr = io.Discard
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Wait() }()
	t.Cleanup(func() {
		stopServer()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			_ = server.Process.Kill()
			t.Error("private server did not stop promptly")
		}
	})
	readyLine := make(chan []byte, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024), 64<<10)
		if scanner.Scan() {
			readyLine <- append([]byte(nil), scanner.Bytes()...)
		} else {
			readyLine <- nil
		}
	}()
	var ready struct{ Event, URL, ProfileID, Protocol string }
	select {
	case line := <-readyLine:
		var wire struct {
			Event     string `json:"event"`
			URL       string `json:"url"`
			ProfileID string `json:"profile_id"`
			Protocol  string `json:"protocol"`
		}
		if json.Unmarshal(line, &wire) != nil || wire.Event != "ready" || wire.ProfileID != profile.ProfileID || wire.Protocol != "zkweb-private-query-v1" {
			t.Fatal("private server did not become ready")
		}
		ready.Event, ready.URL, ready.ProfileID, ready.Protocol = wire.Event, wire.URL, wire.ProfileID, wire.Protocol
	case <-ctx.Done():
		t.Fatal("private server startup timed out")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	forward := &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	var mu sync.Mutex
	var queries [][]byte
	var responses [][]byte
	var corrupt atomic.Bool
	var spyFailure atomic.Bool
	spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/challenge" && r.URL.Path != "/query" {
			spyFailure.Store(true)
			http.Error(w, "unexpected route", 400)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, (8<<20)+1))
		if err != nil || len(body) > 8<<20 {
			spyFailure.Store(true)
			http.Error(w, "invalid body", 400)
			return
		}
		if r.URL.Path == "/query" {
			mu.Lock()
			queries = append(queries, append([]byte(nil), body...))
			mu.Unlock()
			if corrupt.Load() {
				var query map[string]json.RawMessage
				var encoded string
				if json.Unmarshal(body, &query) != nil || json.Unmarshal(query["proof_base64"], &encoded) != nil {
					spyFailure.Store(true)
					http.Error(w, "invalid query", 400)
					return
				}
				proof, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil || len(proof) == 0 {
					spyFailure.Store(true)
					http.Error(w, "invalid proof", 400)
					return
				}
				proof[len(proof)/2] ^= 1
				query["proof_base64"], _ = json.Marshal(base64.StdEncoding.EncodeToString(proof))
				body, _ = json.Marshal(query)
			}
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, ready.URL+r.URL.Path, bytes.NewReader(body))
		if err != nil {
			spyFailure.Store(true)
			http.Error(w, "forward failed", 502)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := forward.Do(req)
		if err != nil {
			spyFailure.Store(true)
			http.Error(w, "forward failed", 502)
			return
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		if err != nil || len(raw) > 8<<20 {
			spyFailure.Store(true)
			http.Error(w, "response failed", 502)
			return
		}
		if r.URL.Path == "/query" && response.StatusCode == 200 {
			mu.Lock()
			responses = append(responses, append([]byte(nil), raw...))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(raw)
	}))
	defer spy.Close()
	for index, want := range []int{11, 22, 33, 44} {
		output, err := run(ctx, cli, "private-query", "--client-dir", profile.ClientDir, "--url", spy.URL, "--index", strconv.Itoa(index))
		if err != nil {
			t.Fatalf("real private query %d failed: %v", index, err)
		}
		var result struct {
			Format       string `json:"format"`
			Index, Value int
		}
		if json.Unmarshal(output, &result) != nil || result.Format != "zkweb-private-result-v1" || result.Index != index || result.Value != want {
			t.Fatalf("wrong decrypted local result for selector %d", index)
		}
	}
	if spyFailure.Load() {
		t.Fatal("HTTP observer could not forward the encrypted protocol")
	}
	mu.Lock()
	captured := append([][]byte(nil), queries...)
	replies := append([][]byte(nil), responses...)
	mu.Unlock()
	if len(captured) != 4 || len(replies) != 4 {
		t.Fatal("valid request was retried or response shape changed")
	}
	for _, body := range captured {
		var query map[string]json.RawMessage
		if json.Unmarshal(body, &query) != nil || len(query) != 2 || query["challenge_id"] == nil || query["proof_base64"] == nil {
			t.Fatal("destination received fields other than the public challenge and encrypted proof")
		}
		var encoded string
		if json.Unmarshal(query["proof_base64"], &encoded) != nil {
			t.Fatal("invalid encrypted request encoding")
		}
		if proof, err := base64.StdEncoding.DecodeString(encoded); err != nil || len(proof) < 128 {
			t.Fatal("request did not carry a real serialized proven ciphertext")
		}
	}
	for _, body := range replies {
		var reply map[string]json.RawMessage
		if json.Unmarshal(body, &reply) != nil || len(reply) != 5 || reply["ciphertext_base64"] == nil || reply["index"] != nil || reply["value"] != nil {
			t.Fatal("destination returned plaintext instead of the encrypted result")
		}
	}
	// Replaying a successful proven request is rejected at the destination.
	replay, err := forward.Post(ready.URL+"/query", "application/json", bytes.NewReader(captured[0]))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, replay.Body)
	replay.Body.Close()
	if replay.StatusCode < 400 {
		t.Fatal("destination accepted a replayed proven request")
	}
	// Corrupt a fresh encrypted proof in transit. No success/result or retry is
	// permitted, including when all HTTP metadata and profile pins still match.
	corrupt.Store(true)
	output, err := run(ctx, cli, "private-query", "--client-dir", profile.ClientDir, "--url", spy.URL, "--index", "2")
	if err == nil || len(output) != 0 {
		t.Fatal("tampered ciphertext/proof produced a successful client result")
	}
	mu.Lock()
	count := len(queries)
	mu.Unlock()
	if count != 5 {
		t.Fatal("failed encrypted request was automatically retried")
	}
}

func run(ctx context.Context, cli string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, cli, args...)
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 2 * time.Second
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("command failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
