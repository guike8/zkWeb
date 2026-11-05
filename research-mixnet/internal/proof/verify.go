// SPDX-License-Identifier: AGPL-3.0-or-later
// Package proof runs the separately built, pinned TLSNotary verifier. It does
// not create proofs or turn an ordinary fetched response into an attestation.
package proof

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/httppolicy"
)

const (
	InputFormat           = "zkweb-tlsn-verify-v1"
	OutputFormat          = "zkweb-tlsn-verified-v1"
	BackendCommit         = "47aee45b53e06648c1b2ad3689b367b8c923fdec"
	MaxPresentationBytes  = 16 << 20
	MaxTranscriptBytes    = 1 << 20
	MaxDisclosureBytes    = 1 << 20
	MaxRanges             = 64
	maxBackendOutputBytes = 2 << 20
)

var (
	ErrInvalidPolicy       = errors.New("invalid verification policy")
	ErrInvalidPresentation = errors.New("invalid or oversized TLSNotary JSON presentation")
	ErrBackendUnavailable  = errors.New("optional TLSNotary verifier is unavailable; build it with make build-proof")
	ErrVerificationFailed  = errors.New("TLSNotary presentation verification failed")
)

type Range struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// Policy is independent trusted input, never inferred from an artifact.
type Policy struct {
	ServerName     string  `json:"server_name"`
	NotaryKeyHex   string  `json:"notary_key_hex"`
	MinTime        uint64  `json:"min_time"`
	MaxTime        uint64  `json:"max_time"`
	SentRanges     []Range `json:"sent_ranges"`
	ReceivedRanges []Range `json:"received_ranges"`
}

type Disclosure struct {
	Start      uint64 `json:"start"`
	End        uint64 `json:"end"`
	DataBase64 string `json:"data_base64"`
}

type Report struct {
	Format         string       `json:"format"`
	BackendCommit  string       `json:"backend_commit"`
	ServerName     string       `json:"server_name"`
	NotaryKeyHex   string       `json:"notary_key_hex"`
	Time           uint64       `json:"time"`
	SentLength     uint64       `json:"sent_length"`
	ReceivedLength uint64       `json:"received_length"`
	Sent           []Disclosure `json:"sent"`
	Received       []Disclosure `json:"received"`
}

func ValidatePolicy(policy Policy) error {
	if policy.ServerName != strings.ToLower(policy.ServerName) || !httppolicy.PublicHostname(policy.ServerName) ||
		policy.MinTime == 0 || policy.MaxTime < policy.MinTime || len(policy.NotaryKeyHex) != 66 ||
		policy.NotaryKeyHex != strings.ToLower(policy.NotaryKeyHex) {
		return ErrInvalidPolicy
	}
	key, err := hex.DecodeString(policy.NotaryKeyHex)
	if err != nil || len(key) != 33 || (key[0] != 2 && key[0] != 3) {
		return ErrInvalidPolicy
	}
	var total uint64
	for _, ranges := range [][]Range{policy.SentRanges, policy.ReceivedRanges} {
		if len(ranges) > MaxRanges {
			return ErrInvalidPolicy
		}
		var previous uint64
		for i, span := range ranges {
			if span.Start >= span.End || span.End > MaxTranscriptBytes || (i > 0 && span.Start < previous) {
				return ErrInvalidPolicy
			}
			total += span.End - span.Start
			if total > MaxDisclosureBytes {
				return ErrInvalidPolicy
			}
			previous = span.End
		}
	}
	return nil
}

// Verify invokes only the absolute backend executable chosen by the local
// caller. The CLI chooses a fixed sibling binary, never PATH or artifact input.
// Its input/output protocol is bounded and checked again here. Cryptographic
// attestation/identity/authenticated-range verification occurs in the backend.
func Verify(ctx context.Context, presentation []byte, policy Policy, backendPath string) (Report, error) {
	policy.SentRanges = append([]Range(nil), policy.SentRanges...)
	policy.ReceivedRanges = append([]Range(nil), policy.ReceivedRanges...)
	if err := ValidatePolicy(policy); err != nil {
		return Report{}, err
	}
	if len(presentation) == 0 || len(presentation) > MaxPresentationBytes || !utf8.Valid(presentation) || !json.Valid(presentation) {
		return Report{}, ErrInvalidPresentation
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if !filepath.IsAbs(backendPath) {
		return Report{}, ErrBackendUnavailable
	}
	info, err := os.Stat(backendPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return Report{}, ErrBackendUnavailable
	}
	request := struct {
		Format             string `json:"format"`
		PresentationBase64 string `json:"presentation_base64"`
		Policy             Policy `json:"policy"`
	}{Format: InputFormat, PresentationBase64: base64.StdEncoding.EncodeToString(presentation), Policy: policy}
	// Arrays are always encoded as arrays, including metadata-only policy.
	if request.Policy.SentRanges == nil {
		request.Policy.SentRanges = []Range{}
	}
	if request.Policy.ReceivedRanges == nil {
		request.Policy.ReceivedRanges = []Range{}
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return Report{}, ErrInvalidPolicy
	}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	output := &boundedOutput{limit: maxBackendOutputBytes, cancel: cancel}
	command := exec.CommandContext(runCtx, backendPath)
	command.Stdin = bytes.NewReader(raw)
	command.Stdout = output
	command.Stderr = io.Discard
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return Report{}, errors.Join(ErrVerificationFailed, ctx.Err())
		}
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return Report{}, errors.Join(ErrVerificationFailed, context.DeadlineExceeded)
		}
		return Report{}, ErrVerificationFailed
	}
	report, err := parseReport(output.Bytes(), policy)
	if err != nil {
		return Report{}, ErrVerificationFailed
	}
	return report, nil
}

type boundedOutput struct {
	bytes.Buffer
	limit  int
	cancel context.CancelFunc
}

func (out *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > out.limit-out.Len() {
		out.cancel()
		return 0, ErrVerificationFailed
	}
	return out.Buffer.Write(data)
}

func parseReport(raw []byte, policy Policy) (Report, error) {
	if len(raw) == 0 || len(raw) > maxBackendOutputBytes || !utf8.Valid(raw) || strictJSON(raw) != nil {
		return Report{}, ErrVerificationFailed
	}
	fields, err := requiredObject(raw, "format", "backend_commit", "server_name", "notary_key_hex", "time", "sent_length", "received_length", "sent", "received")
	if err != nil {
		return Report{}, err
	}
	for _, name := range []string{"sent", "received"} {
		var values []json.RawMessage
		if json.Unmarshal(fields[name], &values) != nil {
			return Report{}, ErrVerificationFailed
		}
		for _, value := range values {
			if _, err := requiredObject(value, "start", "end", "data_base64"); err != nil {
				return Report{}, err
			}
		}
	}
	var report Report
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || report.Format != OutputFormat || report.BackendCommit != BackendCommit ||
		report.ServerName != policy.ServerName || report.NotaryKeyHex != policy.NotaryKeyHex ||
		report.Time < policy.MinTime || report.Time > policy.MaxTime || report.SentLength > MaxTranscriptBytes || report.ReceivedLength > MaxTranscriptBytes {
		return Report{}, ErrVerificationFailed
	}
	for _, direction := range []struct {
		requested []Range
		actual    []Disclosure
		length    uint64
	}{
		{policy.SentRanges, report.Sent, report.SentLength},
		{policy.ReceivedRanges, report.Received, report.ReceivedLength},
	} {
		if len(direction.actual) != len(direction.requested) {
			return Report{}, ErrVerificationFailed
		}
		for i, span := range direction.requested {
			data := direction.actual[i]
			if span.End > direction.length || data.Start != span.Start || data.End != span.End || strings.ContainsAny(data.DataBase64, "\r\n \t") {
				return Report{}, ErrVerificationFailed
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(data.DataBase64)
			if err != nil || uint64(len(decoded)) != span.End-span.Start {
				return Report{}, ErrVerificationFailed
			}
		}
	}
	// Keep metadata-only reports stable as JSON arrays rather than nulls.
	if report.Sent == nil {
		report.Sent = []Disclosure{}
	}
	if report.Received == nil {
		report.Received = []Disclosure{}
	}
	return report, nil
}

func requiredObject(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return nil, ErrVerificationFailed
	}
	for _, name := range names {
		value, present := fields[name]
		if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrVerificationFailed
		}
	}
	return fields, nil
}

// Reject duplicate fields and extra values before typed backend-report parsing.
func strictJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return ErrVerificationFailed
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return ErrVerificationFailed
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return ErrVerificationFailed
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrVerificationFailed
	}
	return nil
}
