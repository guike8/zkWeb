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
	"time"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/httpapi"
	"github.com/Mirai8888/zkapi/research-mixnet/internal/lab"
)

type exchangeFunc func(context.Context, lab.Config, []byte, func(context.Context, []byte) []byte) (lab.ExchangeResult, error)

func request(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	return requestWithExchange(ctx, args, in, out, lab.Exchange)
}

// The injectable exchange keeps CLI checks independent from real API calls.
func requestWithExchange(ctx context.Context, args []string, in io.Reader, out io.Writer, exchange exchangeFunc) error {
	cfg := lab.DefaultConfig()
	cfg.Clients, cfg.Jobs, cfg.Duration = 1, 1, 12*time.Second
	f := flag.NewFlagSet("request", flag.ContinueOnError)
	// Parse errors can contain caller-provided values. Only fixed errors leave
	// this boundary; request bodies and credentials never enter diagnostics.
	f.SetOutput(io.Discard)
	target := f.String("target", "", "allowed public HTTPS origin, such as https://api.example.com")
	input := f.String("input", "-", "request JSON file, or - for stdin; keep credentials in this input")
	f.IntVar(&cfg.Rate, "rate", cfg.Rate, "fixed cells/sec per direction (1–20)")
	f.DurationVar(&cfg.Duration, "duration", cfg.Duration, "fixed experiment epoch (3–30s)")
	f.DurationVar(&cfg.MeanDelay, "mean-delay", cfg.MeanDelay, "mean residence time (0–250ms)")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := fmt.Fprintln(out, "usage: research-mixnet request --target HTTPS_ORIGIN --input FILE|- [--rate 8 --duration 12s --mean-delay 50ms]"); err != nil {
				return errors.New("cannot write request help")
			}
			f.SetOutput(out)
			f.PrintDefaults()
			return nil
		}
		return errors.New("invalid request arguments; use request --help")
	}
	if f.NArg() != 0 || *target == "" || *input == "" {
		return errors.New("request requires --target HTTPS_ORIGIN and --input FILE|-; no positional arguments")
	}
	if cfg.Rate < 1 || cfg.Rate > 20 || cfg.Duration < 3*time.Second || cfg.Duration > 30*time.Second || cfg.MeanDelay < 0 || cfg.MeanDelay > 250*time.Millisecond {
		return errors.New("request requires 1–20 cells/s, a 3–30s epoch and 0–250ms mean delay")
	}
	worker, err := httpapi.New(*target)
	if err != nil {
		return errors.New("request target must be a public HTTPS origin without a path, query, fragment or credentials")
	}
	if *input != "-" {
		file, err := os.Open(*input)
		if err != nil {
			return errors.New("cannot open request input")
		}
		defer file.Close()
		in = file
	}
	raw, err := io.ReadAll(io.LimitReader(in, httpapi.MaxMessageBytes+1))
	if err != nil {
		return errors.New("cannot read request input")
	}
	if len(raw) == 0 || len(raw) > httpapi.MaxMessageBytes {
		return errors.New("request input must contain at most 4090 bytes; the request and reply route must fit one cell")
	}
	if err := worker.Validate(raw); err != nil {
		return errors.New("invalid request JSON: use method, path, optional headers and body; see the request documentation")
	}
	result, err := exchange(ctx, cfg, raw, worker.Handle)
	if err != nil {
		if errors.Is(err, lab.ErrDeliveryUnknown) {
			return errors.New("delivery_unknown: no verified reply; the operation may already have committed; do not retry automatically")
		}
		return errors.New("request was not admitted to the transport; check the schedule and reduce the input to fit one cell with its reply route")
	}
	var response struct {
		Status int    `json:"status"`
		Error  string `json:"error"`
	}
	if len(result.Response) == 0 || json.Unmarshal(result.Response, &response) != nil || (response.Error == "" && (response.Status < 100 || response.Status > 599)) {
		return errors.New("delivery_unknown: invalid reply; the operation may already have committed; do not retry automatically")
	}
	if _, err := out.Write(append(result.Response, '\n')); err != nil {
		return errors.New("cannot write API response; the operation may already have committed")
	}
	if response.Error != "" {
		return errors.New("API request failed; inspect the response error; do not retry automatically")
	}
	if response.Status >= 400 {
		return errors.New("upstream API returned an HTTP error; inspect the response status and body")
	}
	return nil
}
