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

	"github.com/Mirai8888/zkapi/research-mixnet/internal/proof"
)

const verifyTestKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func verifyArgs(extra ...string) []string {
	return append([]string{"--server", "tlsnotary.org", "--notary-key", verifyTestKey, "--not-before", "1671637500", "--not-after", "1671637600"}, extra...)
}

func verifyExecutable() (string, error) {
	return filepath.Join(string(filepath.Separator), "test", "bin", "zkweb"), nil
}

func fakeVerifyReport() proof.Report {
	return proof.Report{
		Format: proof.OutputFormat, BackendCommit: proof.BackendCommit,
		ServerName: "tlsnotary.org", NotaryKeyHex: verifyTestKey,
		Time: 1671637529, SentLength: 40, ReceivedLength: 50,
	}
}

func TestVerifyPassesIndependentPolicyAndFixedSiblingBackend(t *testing.T) {
	presentation := `{"test_fixture":"private-test presentation"}`
	var output bytes.Buffer
	calls := 0
	check := func(ctx context.Context, raw []byte, policy proof.Policy, backend string) (proof.Report, error) {
		calls++
		deadline, exists := ctx.Deadline()
		remaining := time.Until(deadline)
		if !exists || remaining > 30*time.Second || remaining < 28*time.Second {
			t.Fatal("verification deadline missing or changed")
		}
		if string(raw) != presentation || policy.ServerName != "tlsnotary.org" || policy.NotaryKeyHex != verifyTestKey || policy.MinTime != 1671637500 || policy.MaxTime != 1671637600 || len(policy.SentRanges) != 0 || len(policy.ReceivedRanges) != 0 {
			t.Fatal("verification policy was taken from artifact or changed")
		}
		if backend != filepath.Join(string(filepath.Separator), "test", "bin", "zkweb-tlsn-verify") || output.Len() != 0 {
			t.Fatal("backend was not a fixed sibling or output preceded verification")
		}
		return fakeVerifyReport(), nil
	}
	if err := verifyWithBackend(context.Background(), verifyArgs(), strings.NewReader(presentation), &output, check, verifyExecutable); err != nil {
		t.Fatal(err)
	}
	var report proof.Report
	if json.Unmarshal(output.Bytes(), &report) != nil || report.Format != proof.OutputFormat || calls != 1 || strings.Contains(output.String(), "private-test") {
		t.Fatal("verification report missing or presentation leaked")
	}
}

func TestVerifyPassesRequestedRangesAndExplicitTimeout(t *testing.T) {
	check := func(ctx context.Context, _ []byte, policy proof.Policy, _ string) (proof.Report, error) {
		if !reflect.DeepEqual(policy.SentRanges, []proof.Range{{Start: 0, End: 4}, {Start: 4, End: 8}}) || !reflect.DeepEqual(policy.ReceivedRanges, []proof.Range{{Start: 8, End: 16}}) {
			t.Fatal("authenticated byte range policy changed")
		}
		deadline, exists := ctx.Deadline()
		if !exists || time.Until(deadline) > 5*time.Second || time.Until(deadline) < 4*time.Second {
			t.Fatal("explicit timeout changed")
		}
		return fakeVerifyReport(), nil
	}
	var output bytes.Buffer
	if err := verifyWithBackend(context.Background(), verifyArgs("--sent-range", "0:4", "--sent-range", "4:8", "--received-range", "8:16", "--timeout", "5s"), strings.NewReader(`{}`), &output, check, verifyExecutable); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsUnsafeArgumentsAndPolicyBeforeBackend(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--server", "tlsnotary.org"},
		verifyArgs("--not-before", "0"), verifyArgs("--not-after", "0"),
		verifyArgs("--not-before", "1671637601"),
		verifyArgs("--server", "https://private-test.example"),
		verifyArgs("--notary-key", "private-test"),
		verifyArgs("--notary-key", strings.ToUpper(verifyTestKey)),
		verifyArgs("--sent-range", "private-test"), verifyArgs("--received-range", "3:3"),
		verifyArgs("--sent-range", "-1:3"), verifyArgs("--sent-range", "0:1048577"),
		verifyArgs("--sent-range", "0:8", "--sent-range", "4:10"),
		verifyArgs("--sent-range", "8:10", "--sent-range", "0:4"),
		verifyArgs("--timeout", "0s"), verifyArgs("--timeout", "3m"),
		verifyArgs("--backend", "/private-test/verifier"),
		verifyArgs("--input", ""), verifyArgs("private-test"),
	} {
		var output bytes.Buffer
		check := func(context.Context, []byte, proof.Policy, string) (proof.Report, error) {
			t.Fatal("invalid argument or policy reached backend")
			return proof.Report{}, nil
		}
		err := verifyWithBackend(context.Background(), args, strings.NewReader(`{}`), &output, check, verifyExecutable)
		if err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 {
			t.Fatal("invalid policy accepted or private flag value disclosed")
		}
	}
}

func TestVerifyCapsRangeCountAndDisclosureBeforeBackend(t *testing.T) {
	for _, args := range [][]string{
		verifyArgs("--sent-range", "0:1048576", "--received-range", "0:1"),
		func() []string {
			args := verifyArgs()
			for range proof.MaxRanges + 1 {
				args = append(args, "--sent-range", "0:1")
			}
			return args
		}(),
	} {
		var output bytes.Buffer
		check := func(context.Context, []byte, proof.Policy, string) (proof.Report, error) {
			t.Fatal("oversized disclosure policy reached backend")
			return proof.Report{}, nil
		}
		if err := verifyWithBackend(context.Background(), args, strings.NewReader(`{}`), &output, check, verifyExecutable); err == nil || output.Len() != 0 {
			t.Fatal("oversized disclosure policy accepted")
		}
	}
}

func TestVerifyBoundsPresentationAndInputFailures(t *testing.T) {
	for _, input := range []io.Reader{
		strings.NewReader(""),
		io.LimitReader(zeroVerifyReader{}, int64(proof.MaxPresentationBytes)+1),
		errVerifyReader{},
	} {
		var output bytes.Buffer
		check := func(context.Context, []byte, proof.Policy, string) (proof.Report, error) {
			t.Fatal("invalid input reached backend")
			return proof.Report{}, nil
		}
		if err := verifyWithBackend(context.Background(), verifyArgs(), input, &output, check, verifyExecutable); err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 {
			t.Fatal("invalid presentation input accepted or leaked")
		}
	}
}

func TestVerifyFailuresNeverEmitReportOrBackendDetails(t *testing.T) {
	for _, resolve := range []executableResolver{
		verifyExecutable,
		func() (string, error) { return "", errors.New("private-test executable") },
		func() (string, error) { return "relative/private-test", nil },
	} {
		var output bytes.Buffer
		calls := 0
		check := func(context.Context, []byte, proof.Policy, string) (proof.Report, error) {
			calls++
			return fakeVerifyReport(), errors.New("private-test backend transcript and credentials")
		}
		err := verifyWithBackend(context.Background(), verifyArgs(), strings.NewReader(`{}`), &output, check, resolve)
		if err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 || calls > 1 {
			t.Fatal("backend failure retried, leaked details or emitted partial report")
		}
	}
}

func TestVerifyCancellationReachesBackendAndEmitsNoReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	check := func(ctx context.Context, _ []byte, _ proof.Policy, _ string) (proof.Report, error) {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("verification context was detached from caller cancellation")
		}
		return proof.Report{}, ctx.Err()
	}
	err := verifyWithBackend(ctx, verifyArgs(), strings.NewReader(`{}`), &output, check, verifyExecutable)
	if err == nil || output.Len() != 0 || !strings.Contains(err.Error(), "canceled") {
		t.Fatal("canceled verification emitted a report")
	}
}

func TestVerifyReadsFileAndPrintsHelpWithoutBackend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "presentation.json")
	if err := os.WriteFile(path, []byte(`{"fixture":"private-test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(_ context.Context, raw []byte, _ proof.Policy, _ string) (proof.Report, error) {
		if string(raw) != `{"fixture":"private-test"}` {
			t.Fatal("presentation file changed")
		}
		return fakeVerifyReport(), nil
	}
	var output bytes.Buffer
	if err := verifyWithBackend(context.Background(), verifyArgs("--input", path), strings.NewReader("unused"), &output, check, verifyExecutable); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	never := func(context.Context, []byte, proof.Policy, string) (proof.Report, error) {
		t.Fatal("help invoked backend")
		return proof.Report{}, nil
	}
	if err := verifyWithBackend(context.Background(), []string{"--help"}, nil, &output, never, verifyExecutable); err != nil || !strings.Contains(output.String(), "zkweb verify") || !strings.Contains(output.String(), "notary-key") {
		t.Fatal("verify help missing or invoked backend")
	}
}

func TestVerifyHandlesOutputFailure(t *testing.T) {
	check := func(context.Context, []byte, proof.Policy, string) (proof.Report, error) {
		return fakeVerifyReport(), nil
	}
	if err := verifyWithBackend(context.Background(), verifyArgs(), strings.NewReader(`{}`), errVerifyWriter{}, check, verifyExecutable); err == nil || strings.Contains(err.Error(), "private-test") {
		t.Fatal("output error was ignored or disclosed writer details")
	}
}

type zeroVerifyReader struct{}

func (zeroVerifyReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type errVerifyReader struct{}

func (errVerifyReader) Read([]byte) (int, error) { return 0, errors.New("private-test reader") }

type errVerifyWriter struct{}

func (errVerifyWriter) Write([]byte) (int, error) { return 0, errors.New("private-test writer") }
