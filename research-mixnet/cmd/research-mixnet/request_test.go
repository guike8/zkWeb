// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mirai8888/zkapi/research-mixnet/internal/lab"
)

func TestRequestPassesEnvelopeAndFixedEpochToExchange(t *testing.T) {
	body := `{"method":"POST","path":"/items","headers":{"Content-Type":"application/json","Authorization":"Bearer private-test"},"body":"{\"name\":\"first\"}"}`
	var output bytes.Buffer
	called := false
	exchange := func(_ context.Context, cfg lab.Config, raw []byte, worker func(context.Context, []byte) []byte) (lab.ExchangeResult, error) {
		called = true
		if output.Len() != 0 {
			t.Fatal("response was printed before the exchange completed")
		}
		if string(raw) != body || cfg.Clients != 1 || cfg.Jobs != 1 || cfg.Duration != 12*time.Second || worker == nil {
			t.Fatal("request or fixed epoch was changed")
		}
		return lab.ExchangeResult{Response: []byte(`{"status":201,"body":"created"}`)}, nil
	}
	err := requestWithExchange(context.Background(), []string{"--target", "https://api.example.com", "--input", "-"}, strings.NewReader(body), &output, exchange)
	if err != nil || !called || output.String() != "{\"status\":201,\"body\":\"created\"}\n" {
		t.Fatalf("request output failed: called=%v, err=%v", called, err)
	}
}

func TestRequestRejectsInvalidInputBeforeExchangeWithoutLeakingIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		input string
	}{
		{"missing target", nil, `{"method":"GET","path":"/"}`},
		{"credential target", []string{"--target", "https://private-test@example.com"}, `{}`},
		{"target path", []string{"--target", "https://api.example.com/private-test"}, `{}`},
		{"unsupported method", nil, `{"method":"TRACE","path":"/private-test"}`},
		{"absolute path", nil, `{"method":"GET","path":"https://private-test.example/"}`},
		{"unknown field", nil, `{"method":"GET","path":"/","private-test":true}`},
		{"trailing JSON", nil, `{"method":"GET","path":"/"} {"private-test":true}`},
		{"oversized", nil, strings.Repeat("private-test", 400)},
		{"bad flag", []string{"--private-test"}, `{}`},
		{"positional", []string{"private-test"}, `{}`},
		{"invalid rate", []string{"--rate", "0"}, `{}`},
		{"invalid duration", []string{"--duration", "1s"}, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"--target", "https://api.example.com"}
			if tc.name == "missing target" {
				args = nil
			}
			args = append(args, tc.args...)
			var output bytes.Buffer
			exchange := func(context.Context, lab.Config, []byte, func(context.Context, []byte) []byte) (lab.ExchangeResult, error) {
				t.Fatal("invalid request reached exchange")
				return lab.ExchangeResult{}, nil
			}
			err := requestWithExchange(context.Background(), args, strings.NewReader(tc.input), &output, exchange)
			if err == nil || strings.Contains(err.Error(), "private-test") || output.Len() != 0 {
				t.Fatal("invalid request was accepted or exposed input in diagnostics")
			}
		})
	}
}

func TestRequestPrintsWorkerAndUpstreamFailures(t *testing.T) {
	for _, response := range []string{
		`{"status":404,"body":"missing"}`,
		`{"error":"transport_failed"}`,
	} {
		var output bytes.Buffer
		exchange := func(context.Context, lab.Config, []byte, func(context.Context, []byte) []byte) (lab.ExchangeResult, error) {
			return lab.ExchangeResult{Response: []byte(response)}, nil
		}
		err := requestWithExchange(context.Background(), []string{"--target", "https://api.example.com"}, strings.NewReader(`{"method":"GET","path":"/items/1"}`), &output, exchange)
		if err == nil || strings.TrimSpace(output.String()) != response {
			t.Fatal("failed API response must still be printed and fail the command")
		}
	}
}

func TestRequestDoesNotRetryAmbiguousDelivery(t *testing.T) {
	var output bytes.Buffer
	calls := 0
	exchange := func(context.Context, lab.Config, []byte, func(context.Context, []byte) []byte) (lab.ExchangeResult, error) {
		calls++
		return lab.ExchangeResult{}, fmt.Errorf("%w: private-test transport detail", lab.ErrDeliveryUnknown)
	}
	err := requestWithExchange(context.Background(), []string{"--target", "https://api.example.com"}, strings.NewReader(`{"method":"DELETE","path":"/items/1"}`), &output, exchange)
	if err == nil || !strings.Contains(err.Error(), "delivery_unknown") || strings.Contains(err.Error(), "private-test") || calls != 1 || output.Len() != 0 {
		t.Fatal("ambiguous delivery must fail once without exposing transport details")
	}
}

func TestRequestReadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	input := `{"method":"PATCH","path":"/items/1","body":"updated"}`
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	exchange := func(_ context.Context, cfg lab.Config, raw []byte, _ func(context.Context, []byte) []byte) (lab.ExchangeResult, error) {
		if string(raw) != input || cfg.Rate != 4 || cfg.Duration != 9*time.Second || cfg.MeanDelay != 0 {
			t.Fatal("file input or scheduling options were lost")
		}
		return lab.ExchangeResult{Response: []byte(`{"status":204}`)}, nil
	}
	var output bytes.Buffer
	if err := requestWithExchange(context.Background(), []string{"--target", "https://api.example.com", "--input", path, "--rate", "4", "--duration", "9s", "--mean-delay", "0"}, strings.NewReader("unused"), &output, exchange); err != nil {
		t.Fatal(err)
	}
}
