// SPDX-License-Identifier: AGPL-3.0-or-later
package proof

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTLSNBackendIntegration(t *testing.T) {
	backend := os.Getenv("ZKWEB_TLSN_BACKEND")
	if backend == "" {
		t.Skip("make test-proof builds and exercises the optional cryptographic backend")
	}
	if !filepath.IsAbs(backend) {
		t.Fatal("backend must be an explicitly selected absolute path")
	}
	presentation, err := os.ReadFile("../../proof-verifier/tests/fixtures/presentation.json")
	if err != nil {
		t.Fatal(err)
	}
	// Public upstream compatibility vector: the private signing key is known.
	// This fixture is never configured as a default trusted notary.
	policy := Policy{
		ServerName:   "tlsnotary.org",
		NotaryKeyHex: "035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c",
		MinTime:      1671637529,
		MaxTime:      1671637529,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := Verify(ctx, presentation, policy, backend)
	if err != nil {
		t.Fatalf("real TLSN fixture did not verify: %v", err)
	}
	if report.Time != policy.MinTime || report.SentLength != 35 || report.ReceivedLength != 145 || len(report.Sent) != 0 || len(report.Received) != 0 {
		t.Fatal("authenticated metadata or metadata-only disclosure changed")
	}
	policy.SentRanges = []Range{{Start: 0, End: 3}}
	policy.ReceivedRanges = []Range{{Start: 0, End: 8}}
	report, err = Verify(ctx, presentation, policy, backend)
	if err != nil {
		t.Fatal(err)
	}
	sent, _ := base64.StdEncoding.DecodeString(report.Sent[0].DataBase64)
	received, _ := base64.StdEncoding.DecodeString(report.Received[0].DataBase64)
	if string(sent) != "GET" || string(received) != "HTTP/1.1" || strings.Contains(string(marshal(t, report)), "very-secret-cookie") {
		t.Fatal("selected authenticated ranges changed or unselected fixture data escaped")
	}
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.NotaryKeyHex = policyFixture().NotaryKeyHex },
		func(p *Policy) { p.ServerName = "example.com" },
		func(p *Policy) { p.MinTime++; p.MaxTime++ },
		func(p *Policy) { p.ReceivedRanges = []Range{{Start: 144, End: 146}} },
	} {
		wrong := policy
		mutate(&wrong)
		if _, err := Verify(ctx, presentation, wrong, backend); !errors.Is(err, ErrVerificationFailed) {
			t.Fatal("real backend accepted wrong trust policy or unavailable range")
		}
	}
	// Change the signed connection time inside the proof, while allowing both
	// times in caller policy. Rejection must therefore come from cryptography.
	policy.MinTime--
	policy.MaxTime++
	tampered := replaceField(t, presentation, []string{"attestation", "body", "body", "connection_info", "data", "time"}, json.RawMessage("1671637530"))
	if _, err := Verify(ctx, tampered, policy, backend); !errors.Is(err, ErrVerificationFailed) {
		t.Fatal("tampered signed TLSN metadata was accepted")
	}
}

func replaceField(t *testing.T, raw []byte, path []string, replacement json.RawMessage) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(path) == 0 {
		t.Fatal("invalid fixture path")
	}
	value, exists := object[path[0]]
	if !exists {
		t.Fatal("missing fixture field")
	}
	if len(path) == 1 {
		object[path[0]] = replacement
	} else {
		object[path[0]] = replaceField(t, value, path[1:], replacement)
	}
	return marshal(t, object)
}
