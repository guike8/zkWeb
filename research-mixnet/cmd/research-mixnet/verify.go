// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/proof"
)

type verifyFunc func(context.Context, []byte, proof.Policy, string) (proof.Report, error)
type executableResolver func() (string, error)

func verify(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	return verifyWithBackend(ctx, args, in, out, proof.Verify, os.Executable)
}

func verifyWithBackend(ctx context.Context, args []string, in io.Reader, out io.Writer, check verifyFunc, executable executableResolver) error {
	var policy proof.Policy
	var sent, received verifyRanges
	f := flag.NewFlagSet("verify", flag.ContinueOnError)
	f.SetOutput(io.Discard) // Parse failures may otherwise repeat private input.
	input := f.String("input", "-", "TLSNotary alpha15 Presentation JSON file, or - for stdin")
	f.StringVar(&policy.ServerName, "server", "", "required independently expected TLS server name")
	f.StringVar(&policy.NotaryKeyHex, "notary-key", "", "required trusted compressed secp256k1 public key (66 lowercase hex characters)")
	f.Uint64Var(&policy.MinTime, "not-before", 0, "required earliest accepted session time, Unix seconds (inclusive)")
	f.Uint64Var(&policy.MaxTime, "not-after", 0, "required latest accepted session time, Unix seconds (inclusive)")
	f.Var(&sent, "sent-range", "authenticated sent byte range start:end, end exclusive; repeat in sorted order")
	f.Var(&received, "received-range", "authenticated received byte range start:end, end exclusive; repeat in sorted order")
	timeout := f.Duration("timeout", 30*time.Second, "verification deadline (1s–2m)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := fmt.Fprintln(out, "usage: zkweb verify --input PRESENTATION_JSON|- --server DNSNAME --notary-key HEX --not-before UNIX_SECONDS --not-after UNIX_SECONDS [--sent-range START:END --received-range START:END --timeout 30s]"); err != nil {
				return errors.New("cannot write verify help")
			}
			f.SetOutput(out)
			f.PrintDefaults()
			return nil
		}
		return errors.New("invalid verify arguments; use verify --help")
	}
	if f.NArg() != 0 || *input == "" || policy.ServerName == "" || policy.NotaryKeyHex == "" || policy.MinTime == 0 || policy.MaxTime == 0 {
		return errors.New("verify requires a presentation, expected server, trusted notary key and explicit nonzero session time window; no positional arguments")
	}
	if *timeout < time.Second || *timeout > 2*time.Minute {
		return errors.New("verify requires a deadline from 1 second to 2 minutes")
	}
	policy.SentRanges = append([]proof.Range(nil), sent...)
	policy.ReceivedRanges = append([]proof.Range(nil), received...)
	if err := proof.ValidatePolicy(policy); err != nil {
		return errors.New("invalid verification policy; check the expected server, trusted key, time window and sorted nonoverlapping byte ranges")
	}
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			return errors.New("cannot open presentation input")
		}
		defer file.Close()
		in = file
	}
	presentation, err := io.ReadAll(io.LimitReader(in, proof.MaxPresentationBytes+1))
	if err != nil {
		return errors.New("cannot read presentation input")
	}
	if len(presentation) == 0 || len(presentation) > proof.MaxPresentationBytes {
		return errors.New("presentation input must contain 1–16777216 bytes of TLSNotary Presentation JSON")
	}
	path, err := executable()
	if err != nil || !filepath.IsAbs(path) {
		return errors.New("cannot locate the optional proof backend beside zkweb")
	}
	// Never search PATH or let an artifact or command-line flag choose a verifier.
	backend := filepath.Join(filepath.Dir(path), "zkweb-tlsn-verify")
	verifyCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	report, err := check(verifyCtx, presentation, policy, backend)
	if err != nil {
		if errors.Is(err, proof.ErrBackendUnavailable) {
			return errors.New("optional TLSNotary verifier is unavailable; run make build-proof and keep the verifier beside zkweb")
		}
		if verifyCtx.Err() != nil {
			return errors.New("verification timed out or was canceled")
		}
		return errors.New("verification failed; check the presentation, trusted policy and optional proof backend")
	}
	// Encode only the checked report, never the presentation or backend stderr.
	encoded, err := json.Marshal(report)
	if err != nil {
		return errors.New("cannot encode verification report")
	}
	encoded = append(encoded, '\n')
	if n, err := out.Write(encoded); err != nil || n != len(encoded) {
		return errors.New("cannot write verification report")
	}
	return nil
}

type verifyRanges []proof.Range

func (r *verifyRanges) String() string {
	var values []string
	for _, selected := range *r {
		values = append(values, strconv.FormatUint(selected.Start, 10)+":"+strconv.FormatUint(selected.End, 10))
	}
	return strings.Join(values, ",")
}

func (r *verifyRanges) Set(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(*r) >= proof.MaxRanges {
		return errors.New("invalid byte range")
	}
	start, startErr := strconv.ParseUint(parts[0], 10, 64)
	end, endErr := strconv.ParseUint(parts[1], 10, 64)
	if startErr != nil || endErr != nil || start >= end || end > proof.MaxTranscriptBytes {
		return errors.New("invalid byte range")
	}
	*r = append(*r, proof.Range{Start: start, End: end})
	return nil
}
