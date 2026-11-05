// SPDX-License-Identifier: AGPL-3.0-or-later
package zkapi_e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in check sends disposable test data to a public request-inspection
// API. Echoing methods and bodies does not demonstrate durable CRUD storage.
func TestZKAPIGatewayLiveMethods(t *testing.T) {
	if os.Getenv("ZKWEB_ZK_LIVE") != "1" {
		t.Skip("set ZKWEB_ZK_LIVE=1 to contact the public httpbingo HTTPS API")
	}
	cli := os.Getenv("ZKWEB_ZK_CLI")
	if !filepath.IsAbs(cli) {
		t.Fatal("ZKWEB_ZK_CLI must name an absolute built zkweb CLI")
	}
	const origin = "https://httpbingo.org"
	const path = "/anything?raw=%2F&same=first&same=second"
	const payload = `{"message":"zkWeb disposable external method test","value":7}`
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
	// Public DNS/IP policy and ordinary WebPKI validation stay enabled.
	gateway, stop := startGateway(t, ctx, cli, []string{
		"--server-dir", profile.ServerDir, "--upstream", origin,
		"--allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
		"--upstream-path-prefix", "/anything",
	})
	defer stop()
	var responses []map[string]any
	for index, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		args := []string{"zk-api", "--client-dir", profile.ClientDirs[index%2], "--url", gateway,
			"--upstream", origin, "--method", method, "--path", path,
			"--header", "User-Agent: zkWeb-live-test", "--header", "Accept: application/json",
			"--header", "Content-Type: application/json",
			"--header", "X-Live-Echo: first", "--header", "X-Live-Echo: second"}
		want := ""
		if method != "GET" && method != "HEAD" {
			want = payload
			args = append(args, "--data", payload)
		}
		before := time.Now()
		output, err := run(ctx, cli, args...)
		if err != nil {
			t.Fatalf("live %s: %v", method, err)
		}
		var result apiResult
		if json.Unmarshal(output, &result) != nil || result.Format != "zkweb-zk-api-result-v1" || result.Upstream != origin || result.Method != method || result.Path != path || result.Status != 200 {
			t.Fatalf("live %s: unexpected result context/status (got %d)", method, result.Status)
		}
		body, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil {
			t.Fatal("invalid response encoding")
		}
		assertion := "HEAD response body is empty"
		corsMethods := ""
		if method == "HEAD" {
			if len(body) != 0 {
				t.Fatal("live HEAD returned a body")
			}
		} else if method == "OPTIONS" {
			// go-httpbin's preflight middleware returns before its echo handler:
			// https://github.com/mccutchen/go-httpbin/blob/main/httpbin/middleware.go
			if len(body) != 0 {
				t.Fatal("live OPTIONS preflight unexpectedly returned a body")
			}
			for _, header := range result.Headers {
				if strings.EqualFold(header.Name, "Access-Control-Allow-Methods") {
					corsMethods = header.Value
				}
			}
			allowed := map[string]bool{}
			for _, value := range strings.Split(corsMethods, ",") {
				allowed[strings.TrimSpace(value)] = true
			}
			for _, value := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
				if !allowed[value] {
					t.Fatalf("live OPTIONS preflight does not advertise %s", value)
				}
			}
			assertion = "OPTIONS preflight has an empty body and advertises all seven tested methods; payload echo is unavailable"
		} else {
			var echo struct {
				Method  string              `json:"method"`
				URL     string              `json:"url"`
				Args    map[string][]string `json:"args"`
				Headers map[string][]string `json:"headers"`
				Data    string              `json:"data"`
			}
			if json.Unmarshal(body, &echo) != nil || echo.Method != method || echo.URL != origin+path || echo.Data != want {
				t.Fatalf("live %s: provider did not echo the exact method, URL/query and payload", method)
			}
			if values := echo.Args["raw"]; len(values) != 1 || values[0] != "/" {
				t.Fatalf("live %s: escaped query value changed", method)
			}
			if values := echo.Args["same"]; len(values) != 2 || values[0] != "first" || values[1] != "second" {
				t.Fatalf("live %s: repeated query values changed", method)
			}
			var repeated []string
			for name, values := range echo.Headers {
				lower := strings.ToLower(name)
				if strings.HasPrefix(lower, "x-zkweb-") || lower == "authorization" || lower == "cookie" {
					t.Fatalf("live %s: private authorization metadata reached provider", method)
				}
				if lower == "x-live-echo" {
					repeated = values
				}
			}
			if len(repeated) != 2 || repeated[0] != "first" || repeated[1] != "second" {
				t.Fatalf("live %s: repeated signed headers changed", method)
			}
			assertion = "provider echoed exact method, URL/query, ordered repeated headers and payload; no proof, Authorization or Cookie headers"
		}
		digest := sha256.Sum256(body)
		responses = append(responses, map[string]any{
			"method": method, "path": path, "upstream_status": result.Status,
			"body_bytes": len(body), "body_sha256": hex.EncodeToString(digest[:]),
			"elapsed_ms": time.Since(before).Milliseconds(), "assertion": assertion,
		})
		if corsMethods != "" {
			responses[len(responses)-1]["access_control_allow_methods"] = corsMethods
		}
		t.Logf("live proof-authorized %s: upstream 200, %d bytes (%s); %s", method, len(body), time.Since(before).Round(time.Millisecond), assertion)
	}
	if filename := os.Getenv("ZKWEB_ZK_LIVE_METHODS_REPORT"); filename != "" {
		report := map[string]any{
			"format": "zkweb-zk-live-methods-evidence-v1", "started_utc": started.Format(time.RFC3339Nano),
			"completed_utc": time.Now().UTC().Format(time.RFC3339Nano), "upstream": origin,
			"fresh_profile_members": 2, "public_dns_and_webpki_defaults": true,
			"upstream_authorization": "public API; no token or injected credentials", "responses": responses,
			"limitations": "Request-inspection API echo validation, not durable CRUD storage or a proof of upstream execution. Request contents are visible to the gateway and provider. Echoed source addresses and response bodies are not saved.",
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("verified all seven real external HTTPS methods with disposable payloads")
}
