// SPDX-License-Identifier: AGPL-3.0-or-later
package zkapi_e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const liveOrigin = "https://api.github.com"
const liveRepository = "/repos/guike8/zkWeb"
const liveCommit = "d2a4e2d707af9c7c33fc611c448895847cfa8d17"

type liveResponseEvidence struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Status        int    `json:"upstream_status"`
	RequestID     string `json:"github_request_id"`
	Date          string `json:"upstream_date"`
	BodyBytes     int    `json:"body_bytes"`
	BodySHA256    string `json:"body_sha256"`
	ElapsedMillis int64  `json:"elapsed_ms"`
	Assertion     string `json:"assertion"`
}

type liveRejectionEvidence struct {
	Case   string `json:"case"`
	Status int    `json:"gateway_status"`
}

// Explicitly opt in: this consumes public GitHub rate limit, but never sends a
// token or a mutating upstream method. Normal tests remain network independent.
func TestZKAPIGatewayLiveExternal(t *testing.T) {
	if os.Getenv("ZKWEB_ZK_LIVE") != "1" {
		t.Skip("set ZKWEB_ZK_LIVE=1 to contact the public GitHub HTTPS API")
	}
	cli := os.Getenv("ZKWEB_ZK_CLI")
	if !filepath.IsAbs(cli) {
		t.Fatal("ZKWEB_ZK_CLI must name an absolute built zkweb CLI")
	}
	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	setup, err := run(ctx, cli, "zk-setup", "--output", filepath.Join(t.TempDir(), "profile"), "--members", "2")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ServerDir  string   `json:"server_dir"`
		ClientDirs []string `json:"client_dirs"`
	}
	if json.Unmarshal(setup, &profile) != nil || len(profile.ClientDirs) != 2 {
		t.Fatal("invalid fresh two-member setup")
	}
	// No private-address override, custom CA, injected credentials or proxy.
	gateway, stop := startGateway(t, ctx, cli, []string{
		"--server-dir", profile.ServerDir, "--upstream", liveOrigin,
		"--allow-methods", "GET,HEAD", "--upstream-path-prefix", liveRepository,
	})
	defer stop()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	forward := &http.Client{Transport: transport, Timeout: 40 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var mode atomic.Int32
	var spyFailed atomic.Bool
	var mu sync.Mutex
	var captured []capture
	var statuses []int
	spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, apiBodyLimit+1))
		if err != nil || len(body) > apiBodyLimit || (r.URL.Path != "/challenge" && r.URL.Path != "/api") {
			spyFailed.Store(true)
			http.Error(w, "invalid live probe transport", 502)
			return
		}
		headers := r.Header.Clone()
		if r.URL.Path == "/api" {
			mu.Lock()
			captured = append(captured, capture{r.Method, headers.Clone(), append([]byte(nil), body...)})
			mu.Unlock()
			switch mode.Load() {
			case 1:
				headers.Set("X-ZkWeb-Api-Method", "HEAD")
			case 2:
				headers.Set("X-ZkWeb-Api-Path", base64.StdEncoding.EncodeToString([]byte(liveRepository+"?zkweb_tampered=1")))
			case 3:
				var list []apiHeader
				raw, decodeErr := base64.StdEncoding.DecodeString(headers.Get("X-ZkWeb-Api-Headers"))
				if decodeErr != nil || json.Unmarshal(raw, &list) != nil {
					spyFailed.Store(true)
				}
				changed := false
				for index := range list {
					if list[index].Name == "accept" {
						list[index].Value = "application/json"
						changed = true
					}
				}
				if !changed {
					spyFailed.Store(true)
				}
				raw, _ = json.Marshal(list)
				headers.Set("X-ZkWeb-Api-Headers", base64.StdEncoding.EncodeToString(raw))
			case 4:
				proof, decodeErr := base64.StdEncoding.DecodeString(headers.Get("X-ZkWeb-Proof"))
				if decodeErr != nil || len(proof) != 128 {
					spyFailed.Store(true)
				} else {
					proof[len(proof)/2] ^= 1
				}
				headers.Set("X-ZkWeb-Proof", base64.StdEncoding.EncodeToString(proof))
			case 5:
				headers.Del("X-ZkWeb-Proof")
			}
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, gateway+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			spyFailed.Store(true)
			http.Error(w, "live probe construction failed", 502)
			return
		}
		request.Header = headers
		response, err := forward.Do(request)
		if err != nil {
			spyFailed.Store(true)
			http.Error(w, "live probe forwarding failed", 502)
			return
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, (3<<20)+1))
		if err != nil || len(raw) > 3<<20 {
			spyFailed.Store(true)
			http.Error(w, "live probe response failed", 502)
			return
		}
		if r.URL.Path == "/api" {
			mu.Lock()
			statuses = append(statuses, response.StatusCode)
			mu.Unlock()
		}
		for name, values := range response.Header {
			w.Header()[name] = append([]string(nil), values...)
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(raw)
	}))
	defer spy.Close()
	requestArgs := func(member int, method, path string) []string {
		return []string{"zk-api", "--client-dir", profile.ClientDirs[member], "--url", spy.URL,
			"--upstream", liveOrigin, "--method", method, "--path", path,
			"--header", "Accept: application/vnd.github+json",
			"--header", "User-Agent: zkWeb-live-test",
			"--header", "X-GitHub-Api-Version: 2022-11-28"}
	}
	var responses []liveResponseEvidence
	call := func(member int, method, path string, status int, assertion string, check func([]byte) bool) {
		t.Helper()
		before := time.Now()
		output, err := run(ctx, cli, requestArgs(member, method, path)...)
		if err != nil {
			t.Fatalf("live %s %s: %v", method, path, err)
		}
		var result apiResult
		if json.Unmarshal(output, &result) != nil || result.Format != "zkweb-zk-api-result-v1" || result.Upstream != liveOrigin || result.Method != method || result.Path != path || result.Status != status {
			t.Fatalf("live %s %s: unexpected result context/status (want %d, got %d)", method, path, status, result.Status)
		}
		body, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil || !check(body) {
			t.Fatalf("live %s %s: response assertion failed: %s", method, path, assertion)
		}
		metadata := map[string]string{}
		for _, header := range result.Headers {
			metadata[strings.ToLower(header.Name)] = header.Value
		}
		if metadata["x-github-request-id"] == "" || metadata["date"] == "" {
			t.Fatal("live response missing GitHub request ID/date")
		}
		digest := sha256.Sum256(body)
		responses = append(responses, liveResponseEvidence{method, path, result.Status,
			metadata["x-github-request-id"], metadata["date"], len(body), hex.EncodeToString(digest[:]),
			time.Since(before).Milliseconds(), assertion})
		t.Logf("live proof-authorized %s %s: upstream %d, %d bytes, GitHub request %s (%s)",
			method, path, result.Status, len(body), metadata["x-github-request-id"], time.Since(before).Round(time.Millisecond))
	}
	call(0, "GET", liveRepository, 200, "full_name is guike8/zkWeb and repository is public", func(body []byte) bool {
		var repository struct {
			FullName string `json:"full_name"`
			Private  bool   `json:"private"`
		}
		return json.Unmarshal(body, &repository) == nil && repository.FullName == "guike8/zkWeb" && !repository.Private
	})
	call(1, "GET", liveRepository+"/commits/"+liveCommit, 200, "commit SHA matches pinned gateway implementation", func(body []byte) bool {
		var commit struct {
			SHA string `json:"sha"`
		}
		return json.Unmarshal(body, &commit) == nil && commit.SHA == liveCommit
	})
	call(0, "GET", liveRepository+"/commits?per_page=1", 200, "per_page=1 returns exactly one commit", func(body []byte) bool {
		var commits []struct {
			SHA string `json:"sha"`
		}
		return json.Unmarshal(body, &commits) == nil && len(commits) == 1 && len(commits[0].SHA) == 40
	})
	call(1, "HEAD", liveRepository, 200, "HEAD response body is empty", func(body []byte) bool { return len(body) == 0 })
	call(0, "GET", liveRepository+"/contents/zkweb-live-probe-missing-"+liveCommit, 404,
		"provider 404 is returned as upstream data", func(body []byte) bool {
			var failure struct {
				Message string `json:"message"`
			}
			return json.Unmarshal(body, &failure) == nil && failure.Message == "Not Found"
		})

	var rejected []liveRejectionEvidence
	for index, name := range []string{"signed_method", "signed_path_query", "signed_headers", "proof", "missing_proof"} {
		mu.Lock()
		before := len(statuses)
		mu.Unlock()
		mode.Store(int32(index + 1))
		output, err := run(ctx, cli, requestArgs(0, "GET", liveRepository)...)
		mode.Store(0)
		mu.Lock()
		valid := len(statuses) == before+1 && statuses[len(statuses)-1] == 401
		mu.Unlock()
		if err == nil || len(output) != 0 || !valid {
			t.Fatalf("live %s tampering did not produce a gateway 401 and empty CLI stdout", name)
		}
		rejected = append(rejected, liveRejectionEvidence{name, 401})
		t.Logf("live %s tampering: gateway 401, no success output", name)
	}
	mu.Lock()
	first := captured[0]
	mu.Unlock()
	replay, err := http.NewRequestWithContext(ctx, first.method, gateway+"/api", bytes.NewReader(first.body))
	if err != nil {
		t.Fatal(err)
	}
	replay.Header = first.header.Clone()
	response, err := forward.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("live replay returned gateway %d, want 401", response.StatusCode)
	}
	rejected = append(rejected, liveRejectionEvidence{"replay", 401})
	t.Log("live replay: gateway 401")
	mu.Lock()
	before := len(statuses)
	mu.Unlock()
	output, err := run(ctx, cli, requestArgs(0, "GET", "/users/guike8")...)
	mu.Lock()
	denied := len(statuses) == before+1 && statuses[len(statuses)-1] == 403
	all := append([]capture(nil), captured...)
	mu.Unlock()
	if err == nil || len(output) != 0 || !denied {
		t.Fatal("out-of-scope path did not return gateway 403 and empty CLI stdout")
	}
	rejected = append(rejected, liveRejectionEvidence{"path_scope", 403})
	challenges, tags := map[string]bool{}, map[string]bool{}
	for _, request := range all {
		proof, err := base64.StdEncoding.DecodeString(request.header.Get("X-ZkWeb-Proof"))
		challenge, tag := request.header.Get("X-ZkWeb-Challenge"), request.header.Get("X-ZkWeb-Tag")
		if request.method != "POST" || err != nil || len(proof) != 128 || challenge == "" || tag == "" || challenges[challenge] || tags[tag] {
			t.Fatal("live transport lacked a fresh 128-byte Groth16 authorization")
		}
		if request.header.Get("Authorization") != "" || request.header.Get("Cookie") != "" {
			t.Fatal("live transport unexpectedly contains credentials")
		}
		challenges[challenge], tags[tag] = true, true
	}
	if spyFailed.Load() {
		t.Fatal("live capture proxy failed")
	}
	if filename := os.Getenv("ZKWEB_ZK_LIVE_REPORT"); filename != "" {
		binaries := map[string]string{}
		for _, filename := range []string{cli, filepath.Join(filepath.Dir(cli), "zkweb-zk-listener")} {
			raw, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			binaries[filepath.Base(filename)] = hex.EncodeToString(digest[:])
		}
		report := map[string]any{
			"format": "zkweb-zk-live-api-evidence-v1", "started_utc": started.Format(time.RFC3339Nano),
			"completed_utc": time.Now().UTC().Format(time.RFC3339Nano), "upstream": liveOrigin,
			"fresh_profile_members": 2, "groth16_proof_bytes": 128, "fresh_authorizations": len(all),
			"public_dns_and_webpki_defaults": true, "upstream_authorization": "public API; no token or injected credentials",
			"binary_sha256": binaries, "responses": responses, "rejections": rejected,
			"limitations": "Read-only external API calls. Rejections are observed at the gateway; no upstream-side request counter or proof of upstream execution is available. Request contents are visible to the gateway and GitHub.",
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("verified %d real external HTTPS responses and %d authorization/policy rejections; %d fresh 128-byte proofs", len(responses), len(rejected), len(all))
}
