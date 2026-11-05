// SPDX-License-Identifier: AGPL-3.0-or-later
package zkapi_e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
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

type compactPacket struct {
	path        string
	header      http.Header
	body, reply []byte
	status      int
}
type compactProbe struct {
	mu          sync.Mutex
	packets     []compactPacket
	challenges  [][]byte
	mutate      func([]byte) []byte
	connections atomic.Int32
}

// Only this observer sees proof bytes; reports contain sizes and assertions.
func compactProxy(t *testing.T, ctx context.Context, target string) (*httptest.Server, *compactProbe) {
	t.Helper()
	probe := &compactProbe{}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
		if err != nil || len(body) > 2<<20 {
			t.Error("compact observer request limit")
			http.Error(w, "observer error", 502)
			return
		}
		index := -1
		if r.URL.Path == "/b1/a" || r.URL.Path == "/b1/r" {
			if r.Method != "POST" || len(body) < 192 {
				t.Error("compact request missing binary authorization")
			}
			for name := range r.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-zkweb-") {
					t.Error("text authorization header on compact transport")
				}
			}
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("client credential header on compact transport")
			}
			probe.mu.Lock()
			index = len(probe.packets)
			probe.packets = append(probe.packets, compactPacket{path: r.URL.Path, header: r.Header.Clone(), body: append([]byte(nil), body...)})
			mutate := probe.mutate
			probe.mu.Unlock()
			if mutate != nil {
				body = mutate(append([]byte(nil), body...))
			}
		} else if r.URL.Path != "/b1/c" || r.Method != "GET" {
			t.Error("unexpected compact route")
			http.Error(w, "observer route", 502)
			return
		}
		request, err := http.NewRequestWithContext(ctx, r.Method, target+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			t.Error(err)
			return
		}
		request.Header = r.Header.Clone()
		request.Header.Del("Content-Length")
		response, err := client.Do(request)
		if err != nil {
			t.Error(err)
			http.Error(w, "observer forwarding", 502)
			return
		}
		defer response.Body.Close()
		reply, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
		if err != nil || len(reply) > 2<<20 {
			t.Error("compact observer response limit")
			return
		}
		probe.mu.Lock()
		if index >= 0 {
			probe.packets[index].status = response.StatusCode
			probe.packets[index].reply = append([]byte(nil), reply...)
		} else {
			if response.StatusCode != 200 || len(reply) != 72 {
				t.Errorf("compact challenge: status %d, %d bytes", response.StatusCode, len(reply))
			}
			probe.challenges = append(probe.challenges, append([]byte(nil), reply...))
		}
		probe.mu.Unlock()
		for name, values := range response.Header {
			if strings.EqualFold(name, "Connection") || strings.EqualFold(name, "Keep-Alive") {
				continue
			}
			w.Header()[name] = append([]string(nil), values...)
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(reply)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			probe.connections.Add(1)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	return server, probe
}

type compactFields struct {
	method                                       byte
	resource                                     string
	headers                                      []apiHeader
	resourceOffset, bodyOffset, firstValueOffset int
}

// Parse trusted captured client packets for mutation offsets and byte accounting.
func compactFieldsOf(t *testing.T, raw []byte, api bool) compactFields {
	t.Helper()
	if len(raw) < 194 {
		t.Fatal("short captured compact packet")
	}
	position := 193
	readString := func() (string, int) {
		length, count := binary.Uvarint(raw[position:])
		if count <= 0 || length > uint64(len(raw)-position-count) {
			t.Fatal("invalid captured length")
		}
		position += count
		offset := position
		value := string(raw[position : position+int(length)])
		position += int(length)
		return value, offset
	}
	result := compactFields{method: raw[192]}
	result.resource, result.resourceOffset = readString()
	if api {
		result.method = raw[192] / 33
		count := int(raw[192] % 33)
		for i := 0; i < count; i++ {
			name, _ := readString()
			value, offset := readString()
			result.headers = append(result.headers, apiHeader{name, value})
			if i == 0 {
				result.firstValueOffset = offset
			}
		}
	}
	result.bodyOffset = position
	return result
}

func compactProfile(t *testing.T, ctx context.Context, cli string) (string, []string, string) {
	t.Helper()
	output, err := run(ctx, cli, "zk-setup", "--output", filepath.Join(t.TempDir(), "profile"), "--members", "2")
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ServerDir  string   `json:"server_dir"`
		ClientDirs []string `json:"client_dirs"`
		ProfileID  string   `json:"profile_id"`
	}
	if json.Unmarshal(output, &profile) != nil || len(profile.ClientDirs) != 2 {
		t.Fatal("invalid compact setup")
	}
	return profile.ServerDir, profile.ClientDirs, profile.ProfileID
}

func TestZKCompactIntegration(t *testing.T) {
	cli := os.Getenv("ZKWEB_ZK_CLI")
	if cli == "" {
		t.Skip("make test-zk builds the compact proof transport")
	}
	if !filepath.IsAbs(cli) {
		t.Fatal("absolute CLI required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	serverDir, members, profileID := compactProfile(t, ctx, cli)
	var calls atomic.Int32
	upstream, rootCA := caIssuedTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer compact-fixture" {
			t.Error("operator credential missing")
		}
		for name := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), "x-zkweb-") {
				t.Error("proof header leaked upstream")
			}
		}
		if r.URL.RawQuery != "raw=%2F&same=1&same=2" {
			t.Error("compact query changed")
		}
		if values := r.Header.Values("X-Echo"); len(values) != 2 || values[0] != "first" || values[1] != "second" {
			t.Error("compact repeated headers changed")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, apiBodyLimit+1))
		if err != nil || len(body) > apiBodyLimit {
			t.Error("upstream body limit")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Set-Cookie", "must-not-return=1")
		if r.URL.Path == "/v1/drop" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		if r.URL.Path == "/v1/oversized" {
			_, _ = w.Write(make([]byte, apiBodyLimit+1))
			return
		}
		if r.URL.Path == "/v1/status" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte("provider unauthorized"))
			return
		}
		if r.URL.Path == "/v1/redirect" {
			w.Header().Set("Location", "/must-not-follow")
			w.WriteHeader(307)
			return
		}
		if r.URL.Path != "/v1/echo" {
			t.Error("unexpected upstream path")
		}
		if len(body) == 0 {
			body = []byte{0, 255, 128, 10}
		}
		_, _ = w.Write(body)
	}))
	defer upstream.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, rootCA, 0600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(t.TempDir(), "headers.json")
	if err := os.WriteFile(credentials, []byte(`{"Authorization":"Bearer compact-fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	gateway, stop := startGateway(t, ctx, cli, []string{"--server-dir", serverDir, "--upstream", upstream.URL, "--allow-private-upstream", "--upstream-ca-file", ca, "--upstream-headers-file", credentials, "--allow-methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS", "--upstream-path-prefix", "/v1/"})
	defer stop()
	spy, probe := compactProxy(t, ctx, gateway)
	const path = "/v1/echo?raw=%2F&same=1&same=2"
	args := func(member int, method, resource string, body []byte) []string {
		result := []string{"zk-api", "--client-dir", members[member], "--url", spy.URL, "--upstream", upstream.URL, "--method", method, "--path", resource, "--header", "X-Echo: first", "--header", "X-Echo: second", "--header", "Content-Type: application/octet-stream"}
		if body != nil {
			filename := filepath.Join(t.TempDir(), "body.dat")
			if err := os.WriteFile(filename, body, 0600); err != nil {
				t.Fatal(err)
			}
			result = append(result, "--data-file", filename)
		}
		return result
	}
	call := func(member int, method, resource string, body []byte, status int, want []byte) {
		t.Helper()
		output, err := run(ctx, cli, args(member, method, resource, body)...)
		if err != nil {
			t.Fatalf("compact %s: %v", method, err)
		}
		var result apiResult
		if json.Unmarshal(output, &result) != nil || result.Format != "zkweb-zk-api-result-v1" || result.Status != status || result.Path != resource || result.Method != method || result.Upstream != upstream.URL {
			t.Fatal("compact result context/status")
		}
		decoded, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil || !bytes.Equal(decoded, want) {
			t.Fatal("compact response bytes changed")
		}
		for _, header := range result.Headers {
			if header.Name == "set-cookie" || header.Name == "authorization" || strings.HasPrefix(header.Name, "x-zkweb-") {
				t.Fatal("private compact reply header")
			}
		}
	}
	for index, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		var body []byte
		want := []byte{0, 255, 128, 10}
		if method == "HEAD" {
			want = nil
		}
		if index >= 2 {
			body = []byte{0, 255, 128, byte(index)}
			want = body
		}
		call(index%2, method, path, body, 200, want)
	}
	large := make([]byte, apiBodyLimit)
	for i := range large {
		large[i] = byte(i * 31)
	}
	call(0, "PUT", path, large, 200, large)
	call(1, "GET", "/v1/status?raw=%2F&same=1&same=2", nil, 401, []byte("provider unauthorized"))
	call(0, "GET", "/v1/redirect?raw=%2F&same=1&same=2", nil, 307, nil)
	probe.mu.Lock()
	first := probe.packets[0]
	probe.mu.Unlock()
	fields := compactFieldsOf(t, first.body, true)
	if fields.method != 0 || fields.resource != path || len(first.body[64:192]) != 128 {
		t.Fatal("compact wire layout")
	}
	if len(first.body) != fields.bodyOffset {
		t.Fatal("GET had a payload")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	replay := func(packet compactPacket) {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, "POST", gateway+packet.path, bytes.NewReader(packet.body))
		request.Header.Set("Content-Type", "application/octet-stream")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Fatalf("replay/malformed original returned %d", response.StatusCode)
		}
	}
	replay(first)
	mutations := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"body", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		{"method", func(b []byte) []byte { b[192] = 4*33 + b[192]%33; return b }},
		{"path", func(b []byte) []byte { f := compactFieldsOf(t, b, true); b[f.resourceOffset+3] = '2'; return b }},
		{"headers", func(b []byte) []byte { f := compactFieldsOf(t, b, true); b[f.firstValueOffset] ^= 1; return b }},
		{"proof", func(b []byte) []byte { b[100] ^= 1; return b }},
		{"tag", func(b []byte) []byte { b[33] ^= 1; return b }},
		{"nonce", func(b []byte) []byte { b[0] ^= 1; return b }},
		{"truncated", func(b []byte) []byte { return b[:48] }},
		{"nonminimal_length", func(b []byte) []byte { return append(append(append([]byte{}, b[:193]...), b[193]|0x80, 0), b[194:]...) }},
		{"overflow_length", func(b []byte) []byte {
			return append(append(append([]byte{}, b[:193]...), 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f), b[194:]...)
		}},
		{"header_count", func(b []byte) []byte { b[192] = (b[192]/33)*33 + 32; return b }},
	}
	for _, test := range mutations {
		before := calls.Load()
		probe.mu.Lock()
		probe.mutate = test.mutate
		probe.mu.Unlock()
		output, err := run(ctx, cli, args(0, "POST", path, []byte("must-not-execute"))...)
		probe.mu.Lock()
		probe.mutate = nil
		last := probe.packets[len(probe.packets)-1]
		probe.mu.Unlock()
		if err == nil || len(output) != 0 || last.status != 401 || calls.Load() != before {
			t.Fatalf("compact %s was accepted or reached upstream: gateway %d", test.name, last.status)
		}
		if test.name != "nonce" {
			replay(last)
			if calls.Load() != before {
				t.Fatal("malformed authorization nonce was not consumed")
			}
		}
	}
	before := calls.Load()
	wrong := args(0, "GET", path, nil)
	for i := range wrong {
		if wrong[i] == upstream.URL {
			wrong[i] = "https://wrong.example"
		}
	}
	if output, err := run(ctx, cli, wrong...); err == nil || len(output) != 0 || calls.Load() != before {
		t.Fatal("wrong configured upstream accepted")
	}
	_, otherMembers, _ := compactProfile(t, ctx, cli)
	wrong = args(0, "GET", path, nil)
	for i := range wrong {
		if wrong[i] == members[0] {
			wrong[i] = otherMembers[0]
		}
	}
	if output, err := run(ctx, cli, wrong...); err == nil || len(output) != 0 || calls.Load() != before {
		t.Fatal("wrong configured profile accepted")
	}
	for _, resource := range []string{"/v1/drop", "/v1/oversized"} {
		before = calls.Load()
		output, err := run(ctx, cli, args(0, "POST", resource+"?raw=%2F&same=1&same=2", []byte("once"))...)
		probe.mu.Lock()
		last := probe.packets[len(probe.packets)-1]
		probe.mu.Unlock()
		if err == nil || len(output) != 0 || calls.Load() != before+1 || last.status != 502 || len(last.reply) != 0 {
			t.Fatal("compact unknown delivery retried, leaked partial data or returned an error envelope")
		}
	}
	before = calls.Load()
	if output, err := run(ctx, cli, args(0, "GET", "/admin", nil)...); err == nil || len(output) != 0 || calls.Load() != before {
		t.Fatal("compact scope denial reached upstream or produced a success result")
	}
	probe.mu.Lock()
	nonces, tags := map[string]bool{}, map[string]bool{}
	for _, packet := range probe.packets {
		nonce, tag := string(packet.body[:32]), string(packet.body[32:64])
		if nonces[nonce] || tags[tag] {
			t.Error("compact client reused a nonce or randomized public tag")
		}
		nonces[nonce], tags[tag] = true, true
	}
	probe.mu.Unlock()
	measure := compactMeasurements(t, first, probe.challenges[0], profileID, upstream.URL)
	t.Logf("compact gateway byte accounting: %v", measure)

	// The record client uses the same proof format without an API header count.
	records, stopRecords := startGateway(t, ctx, cli, []string{"--server-dir", serverDir, "--state-file", filepath.Join(t.TempDir(), "records.json")})
	defer stopRecords()
	// A wrong listener mode must be a protocol failure, not a legitimate record
	// 404 or upstream application result.
	before = calls.Load()
	if output, err := run(ctx, cli, "zk-request", "--client-dir", members[0], "--url", gateway, "--method", "GET", "--key", "missing"); err == nil || len(output) != 0 {
		t.Fatal("record client treated a gateway-mode route as an application result")
	}
	if output, err := run(ctx, cli, "zk-api", "--client-dir", members[0], "--url", records, "--upstream", upstream.URL, "--method", "GET", "--path", path); err == nil || len(output) != 0 || calls.Load() != before {
		t.Fatal("gateway client accepted a record-mode listener or reached upstream")
	}
	recordSpy, recordProbe := compactProxy(t, ctx, records)
	recordCall := func(member int, method string, body []byte, status int, want []byte) {
		t.Helper()
		argv := []string{"zk-request", "--client-dir", members[member], "--url", recordSpy.URL, "--method", method, "--key", "note"}
		if body != nil {
			filename := filepath.Join(t.TempDir(), "record.dat")
			if err := os.WriteFile(filename, body, 0600); err != nil {
				t.Fatal(err)
			}
			argv = append(argv, "--data-file", filename)
		}
		output, err := run(ctx, cli, argv...)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Status int    `json:"status"`
			Body   string `json:"body_base64"`
		}
		if json.Unmarshal(output, &result) != nil || result.Status != status {
			t.Fatal("compact record status")
		}
		decoded, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil || (want != nil && !bytes.Equal(decoded, want)) {
			t.Fatal("compact record payload")
		}
	}
	value := []byte{0, 255, 128, 10}
	recordCall(0, "POST", value, 201, value)
	recordCall(1, "GET", nil, 200, value)
	replacement := large[:64<<10]
	recordCall(1, "PUT", replacement, 200, replacement)
	recordCall(0, "GET", nil, 200, replacement)
	recordCall(0, "DELETE", nil, 200, replacement)
	recordCall(1, "GET", nil, 404, nil)
	recordProbe.mu.Lock()
	packet := recordProbe.packets[0]
	recordProbe.mu.Unlock()
	recordFields := compactFieldsOf(t, packet.body, false)
	if len(packet.body) != 192+1+1+len("note")+len(value) || recordFields.resource != "note" || !bytes.Equal(packet.body[recordFields.bodyOffset:], value) {
		t.Fatal("record compact overhead differs from expected minimal envelope")
	}
	t.Logf("verified compact two-member record CRUD, seven upstream methods, 1 MiB binary reply, %d tamper rejections, nonce burn, profile/origin binding", len(mutations))
}

// Compare identical operation/auth values using reproducible HTTP/1 request
// serialization. These counts exclude TCP/TLS and are not packet captures.
func compactMeasurements(t *testing.T, packet compactPacket, challenge []byte, profileID, origin string) map[string]int {
	t.Helper()
	fields := compactFieldsOf(t, packet.body, true)
	size := func(path string, headers http.Header, body []byte) int {
		request, _ := http.NewRequest("POST", "http://127.0.0.1:12345"+path, bytes.NewReader(body))
		request.Header = headers.Clone()
		request.Header.Del("Content-Length")
		var buffer bytes.Buffer
		if err := request.Write(&buffer); err != nil {
			t.Fatal(err)
		}
		return buffer.Len()
	}
	headers := packet.header.Clone()
	headers.Set("X-ZkWeb-Challenge", hex.EncodeToString(packet.body[:32]))
	headers.Set("X-ZkWeb-Tag", hex.EncodeToString(packet.body[32:64]))
	headers.Set("X-ZkWeb-Proof", base64.StdEncoding.EncodeToString(packet.body[64:192]))
	headers.Set("X-ZkWeb-Api-Method", []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}[fields.method])
	headers.Set("X-ZkWeb-Api-Path", base64.StdEncoding.EncodeToString([]byte(fields.resource)))
	encoded, _ := json.Marshal(fields.headers)
	headers.Set("X-ZkWeb-Api-Headers", base64.StdEncoding.EncodeToString(encoded))
	legacyChallenge, _ := json.Marshal(map[string]any{"protocol": "zkweb-zk-authorized-crud-v1", "profile_id": profileID, "server_instance": hex.EncodeToString(challenge[:32]), "challenge_id": hex.EncodeToString(challenge[32:64]), "expires_unix": binary.BigEndian.Uint64(challenge[64:]), "upstream_origin": origin})
	statusAndCount, position := binary.Uvarint(packet.reply)
	if position <= 0 || statusAndCount > 13199 {
		t.Fatal("invalid captured compact response prefix")
	}
	count := int(statusAndCount % 33)
	var replyHeaders []apiHeader
	readString := func() string {
		length, n := binary.Uvarint(packet.reply[position:])
		if n <= 0 || length > uint64(len(packet.reply)-position-n) {
			t.Fatal("invalid compact reply")
		}
		position += n
		value := string(packet.reply[position : position+int(length)])
		position += int(length)
		return value
	}
	for i := 0; i < count; i++ {
		name := readString()
		value := readString()
		replyHeaders = append(replyHeaders, apiHeader{name, value})
	}
	legacyReply, _ := json.Marshal(struct {
		Format   string      `json:"format"`
		Upstream string      `json:"upstream"`
		Status   uint16      `json:"status"`
		Headers  []apiHeader `json:"headers"`
		Body     string      `json:"body_base64"`
	}{"zkweb-zk-api-response-v1", origin, uint16(200 + statusAndCount/33), replyHeaders, base64.StdEncoding.EncodeToString(packet.reply[position:])})
	return map[string]int{"authorization_raw_bytes": 192, "challenge_compact_bytes": len(challenge), "challenge_legacy_json_bytes": len(legacyChallenge), "request_compact_body_bytes": len(packet.body), "request_compact_http1_serialized_bytes": size(packet.path, packet.header, packet.body), "request_legacy_http1_serialized_bytes": size("/api", headers, packet.body[fields.bodyOffset:]), "response_compact_body_bytes": len(packet.reply), "response_legacy_json_bytes": len(legacyReply)}
}

func TestZKAPIGatewayLiveCompact(t *testing.T) {
	if os.Getenv("ZKWEB_ZK_LIVE") != "1" {
		t.Skip("set ZKWEB_ZK_LIVE=1 to contact public GitHub with compact transport")
	}
	cli := os.Getenv("ZKWEB_ZK_CLI")
	if !filepath.IsAbs(cli) {
		t.Fatal("absolute CLI required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	serverDir, members, profileID := compactProfile(t, ctx, cli)
	gateway, stop := startGateway(t, ctx, cli, []string{"--server-dir", serverDir, "--upstream", liveOrigin, "--upstream-path-prefix", liveRepository})
	defer stop()
	spy, probe := compactProxy(t, ctx, gateway)
	var responses []map[string]any
	for i, method := range []string{"GET", "HEAD"} {
		before := time.Now()
		output, err := run(ctx, cli, "zk-api", "--client-dir", members[i], "--url", spy.URL, "--upstream", liveOrigin, "--method", method, "--path", liveRepository, "--header", "User-Agent: zkWeb-live-test", "--header", "Accept: application/vnd.github+json", "--header", "X-GitHub-Api-Version: 2022-11-28")
		if err != nil {
			t.Fatal(err)
		}
		var result apiResult
		if json.Unmarshal(output, &result) != nil || result.Status != 200 || result.Method != method || result.Upstream != liveOrigin || result.Path != liveRepository {
			t.Fatal("compact live result context")
		}
		body, err := base64.StdEncoding.DecodeString(result.Body)
		if err != nil {
			t.Fatal(err)
		}
		if method == "HEAD" {
			if len(body) != 0 {
				t.Fatal("live HEAD body")
			}
		} else {
			var repository struct {
				FullName string `json:"full_name"`
			}
			if json.Unmarshal(body, &repository) != nil || repository.FullName != "guike8/zkWeb" {
				t.Fatal("live repository mismatch")
			}
		}
		requestID := ""
		for _, header := range result.Headers {
			if header.Name == "x-github-request-id" {
				requestID = header.Value
			}
		}
		if requestID == "" {
			t.Fatal("missing GitHub request ID")
		}
		digest := sha256.Sum256(body)
		responses = append(responses, map[string]any{"method": method, "upstream_status": result.Status, "github_request_id": requestID, "response_body_bytes": len(body), "body_sha256": hex.EncodeToString(digest[:]), "elapsed_ms": time.Since(before).Milliseconds()})
		t.Logf("compact live %s: GitHub 200, %d result bytes, request ID %s", method, len(body), requestID)
	}
	probe.mu.Lock()
	measurement := compactMeasurements(t, probe.packets[0], probe.challenges[0], profileID, liveOrigin)
	packetCount := len(probe.packets)
	challengeCount := len(probe.challenges)
	probe.mu.Unlock()
	if packetCount != 2 || challengeCount != 2 || probe.connections.Load() != 2 {
		t.Fatalf("compact challenge/request did not reuse one client connection per call: packets=%d challenges=%d connections=%d", packetCount, challengeCount, probe.connections.Load())
	}
	if filename := os.Getenv("ZKWEB_ZK_COMPACT_REPORT"); filename != "" {
		binaries := map[string]string{}
		for _, executable := range []string{cli, filepath.Join(filepath.Dir(cli), "zkweb-zk-listener")} {
			raw, err := os.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			binaries[filepath.Base(executable)] = hex.EncodeToString(digest[:])
		}
		report := map[string]any{"format": "zkweb-zk-compact-live-evidence-v1", "wire": "compact-b1", "started_utc": started.Format(time.RFC3339Nano), "completed_utc": time.Now().UTC().Format(time.RFC3339Nano), "upstream": liveOrigin, "fresh_profile_members": 2, "public_dns_and_webpki_defaults": true, "client_http_connections": probe.connections.Load(), "binary_sha256": binaries, "responses": responses, "byte_comparison": measurement, "limitations": "HTTP/1 sizes are reproducible serialization comparisons, not TCP/TLS packet captures. Client connection counts measure client to test observer; direct TCP reuse and idle limits are checked separately. Request contents remain visible to the gateway and upstream. This is authorization, not a proof of response correctness."}
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, append(encoded, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("compact live byte comparison: %v", measurement)
}
