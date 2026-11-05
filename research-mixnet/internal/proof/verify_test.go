// SPDX-License-Identifier: AGPL-3.0-or-later
package proof

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These tests validate the local process/policy protocol, not cryptography.
// Real TLSN signature/provenance fixtures are tested by proof-verifier.
func policyFixture() Policy {
	return Policy{ServerName: "tlsnotary.org", NotaryKeyHex: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", MinTime: 10, MaxTime: 20}
}

func reportFixture(policy Policy) Report {
	return Report{Format: OutputFormat, BackendCommit: BackendCommit, ServerName: policy.ServerName, NotaryKeyHex: policy.NotaryKeyHex, Time: 15, SentLength: 64, ReceivedLength: 64, Sent: []Disclosure{}, Received: []Disclosure{}}
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func quoteShell(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func script(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backend")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+content+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunnerForwardsOnlyBoundedInputAndPolicy(t *testing.T) {
	policy := policyFixture()
	report := reportFixture(policy)
	dir := t.TempDir()
	inputPath, envPath, resultPath := filepath.Join(dir, "input.json"), filepath.Join(dir, "env.txt"), filepath.Join(dir, "result.json")
	if err := os.WriteFile(resultPath, marshal(t, report), 0600); err != nil {
		t.Fatal(err)
	}
	backend := script(t, "/usr/bin/env > "+quoteShell(envPath)+"\n/bin/cat > "+quoteShell(inputPath)+"\n/bin/cat "+quoteShell(resultPath))
	t.Setenv("ZKWEB_TEST_SECRET", "must-not-be-inherited")
	presentation := []byte(`{"test_only":"private-fixture-data"}`)
	got, err := Verify(context.Background(), presentation, policy, backend)
	if err != nil || !reflect.DeepEqual(got, report) {
		t.Fatalf("runner failed: %v", err)
	}
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Format       string `json:"format"`
		Presentation string `json:"presentation_base64"`
		Policy       Policy `json:"policy"`
	}
	if json.Unmarshal(raw, &input) != nil || input.Format != InputFormat || input.Presentation != base64.StdEncoding.EncodeToString(presentation) || input.Policy.ServerName != policy.ServerName || input.Policy.MinTime != 10 || input.Policy.MaxTime != 20 || input.Policy.NotaryKeyHex != policy.NotaryKeyHex {
		t.Fatal("proof bytes or independently supplied trust policy changed")
	}
	environment, err := os.ReadFile(envPath)
	if err != nil || strings.Contains(string(environment), "must-not-be-inherited") || strings.Contains(string(environment), "ZKWEB_TEST_SECRET") {
		t.Fatal("backend inherited caller credentials")
	}
}

func TestRejectsPolicyBeforeStartingBackend(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "called")
	backend := script(t, "/bin/echo called > "+quoteShell(marker))
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.NotaryKeyHex = "" },
		func(p *Policy) { p.NotaryKeyHex = strings.ToUpper(p.NotaryKeyHex) },
		func(p *Policy) { p.ServerName = "https://tlsnotary.org" },
		func(p *Policy) { p.ServerName = "localhost" },
		func(p *Policy) { p.MinTime = 0 },
		func(p *Policy) { p.MinTime = 21 },
		func(p *Policy) { p.SentRanges = []Range{{4, 4}} },
		func(p *Policy) { p.SentRanges = []Range{{4, 6}, {5, 8}} },
		func(p *Policy) { p.SentRanges = []Range{{0, MaxTranscriptBytes + 1}} },
		func(p *Policy) { p.SentRanges = []Range{{0, MaxTranscriptBytes}}; p.ReceivedRanges = []Range{{0, 1}} },
		func(p *Policy) {
			for i := uint64(0); i <= MaxRanges; i++ {
				p.SentRanges = append(p.SentRanges, Range{2 * i, 2*i + 1})
			}
		},
	} {
		policy := policyFixture()
		mutate(&policy)
		if _, err := Verify(context.Background(), []byte(`{}`), policy, backend); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatal("invalid policy reached backend")
		}
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected input started a process")
	}
}

func TestPresentationAndExecutableAdmission(t *testing.T) {
	for _, input := range [][]byte{nil, []byte("not-json"), {255}, []byte(strings.Repeat(" ", MaxPresentationBytes+1))} {
		if _, err := Verify(context.Background(), input, policyFixture(), "/missing"); !errors.Is(err, ErrInvalidPresentation) {
			t.Fatal("invalid proof was not rejected")
		}
	}
	for _, path := range []string{"relative-backend", "/a/nonexistent/zkweb-proof-backend"} {
		if _, err := Verify(context.Background(), []byte(`{}`), policyFixture(), path); !errors.Is(err, ErrBackendUnavailable) {
			t.Fatal("backend path was not checked")
		}
	}
}

func TestReportsCannotOverrideTrustPolicyOrDisclosure(t *testing.T) {
	policy := policyFixture()
	policy.ReceivedRanges = []Range{{2, 5}}
	valid := reportFixture(policy)
	valid.Received = []Disclosure{{2, 5, base64.StdEncoding.EncodeToString([]byte("yes"))}}
	if _, err := parseReport(marshal(t, valid), policy); err != nil {
		t.Fatal("matching report rejected")
	}
	for _, mutate := range []func(*Report){
		func(r *Report) { r.Format = "unverified" },
		func(r *Report) { r.BackendCommit = "latest" },
		func(r *Report) { r.ServerName = "other.example" },
		func(r *Report) { r.NotaryKeyHex = "another-key" },
		func(r *Report) { r.Time = 9 },
		func(r *Report) { r.Time = 21 },
		func(r *Report) { r.ReceivedLength = MaxTranscriptBytes + 1 },
		func(r *Report) { r.ReceivedLength = 4 },
		func(r *Report) { r.Received = nil },
		func(r *Report) { r.Received = []Disclosure{{0, 3, "eWVz"}} },
		func(r *Report) { r.Received = []Disclosure{{2, 5, "eWVz\n"}} },
		func(r *Report) { r.Received = []Disclosure{{2, 5, "bm8="}} },
		func(r *Report) { r.Sent = []Disclosure{{0, 6, "c2VjcmV0"}} },
	} {
		report := valid
		mutate(&report)
		if _, err := parseReport(marshal(t, report), policy); err == nil {
			t.Fatal("malformed/mismatched backend report was accepted")
		}
	}
	metadataOnly := policyFixture()
	if _, err := parseReport(marshal(t, valid), metadataOnly); err == nil {
		t.Fatal("backend disclosed bytes without caller selection")
	}
}

func TestStrictReportJSON(t *testing.T) {
	valid := string(marshal(t, reportFixture(policyFixture())))
	for _, raw := range []string{
		valid + ` {}`,
		strings.Replace(valid, `"format":`, `"format":"ignored","format":`, 1),
		strings.Replace(valid, `"format":`, `"secret-unknown-field":"private","format":`, 1),
		`null`,
		strings.Repeat("[", 34) + `0` + strings.Repeat("]", 34),
	} {
		if _, err := parseReport([]byte(raw), policyFixture()); err == nil {
			t.Fatal("ambiguous report JSON accepted")
		}
	}
}

func TestBackendFailuresAreBoundedAndSanitized(t *testing.T) {
	backend := script(t, "/bin/echo private-proof-data >&2\nexit 1")
	_, err := Verify(context.Background(), []byte(`{}`), policyFixture(), backend)
	if !errors.Is(err, ErrVerificationFailed) || strings.Contains(err.Error(), "private-proof-data") {
		t.Fatal("backend failure exposed raw diagnostics")
	}
	large := script(t, "exec /usr/bin/head -c 2200000 /dev/zero")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := Verify(ctx, []byte(`{}`), policyFixture(), large); !errors.Is(err, ErrVerificationFailed) {
		t.Fatal("unbounded backend output accepted")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("oversized backend was not stopped promptly")
	}
	slow := script(t, "exec /bin/sleep 60")
	deadline, stop := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer stop()
	if _, err := Verify(deadline, []byte(`{}`), policyFixture(), slow); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("backend process ignored cancellation")
	}
}
