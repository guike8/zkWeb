// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func exchangeConfig() Config {
	cfg := DefaultConfig()
	cfg.Clients, cfg.Jobs, cfg.Rate = 1, 1, 20
	cfg.MeanDelay, cfg.Duration = 0, 3*time.Second
	return cfg
}

func TestExchangeReturnsWorkerReplyWithoutShorteningCoverEpoch(t *testing.T) {
	t.Parallel()
	request := []byte(`{"method":"POST","path":"/items","body":"example"}`)
	response := []byte(`{"status":201,"body":"created"}`)
	var calls atomic.Int32
	var wrongPayload atomic.Bool
	cfg := exchangeConfig()
	started := time.Now()
	result, err := Exchange(context.Background(), cfg, request, func(ctx context.Context, raw []byte) []byte {
		calls.Add(1)
		if !bytes.Equal(raw, request) {
			wrongPayload.Store(true)
		}
		return response
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrongPayload.Load() || calls.Load() != 1 || !bytes.Equal(result.Response, response) {
		t.Fatal("worker request or reply mismatch, or worker retried")
	}
	if time.Since(started) < cfg.Duration || result.Report.Completed != 1 || result.Report.Submitted != 1 {
		t.Fatal("exchange did not complete inside its fixed cover epoch")
	}
	if result.Report.IdleUploadCover == 0 || result.Report.IdleDownloadCover == 0 {
		t.Fatal("exchange skipped idle cover")
	}
	for _, stats := range result.Report.Links {
		if stats.Cover == 0 || stats.Bytes != stats.Sent*uint64(result.Report.CellBytes) {
			t.Fatal("exchange changed fixed-size cover links")
		}
	}
}

func TestExchangeRejectsOversizedEnvelopeBeforeWorker(t *testing.T) {
	t.Parallel()
	code := newCodec()
	surbLength := code.s.Geometry().SURBLength
	limit := 0
	for size := 1; size <= payloadBytes-6; size++ {
		if validateExchangeSize(make([]byte, size), surbLength) != nil {
			break
		}
		limit = size
	}
	if limit == 0 || limit >= payloadBytes-6 {
		t.Fatal("request size did not account for reply capability")
	}
	if err := validateExchangeSize(make([]byte, limit), surbLength); err != nil {
		t.Fatal("last fitting payload rejected")
	}
	for _, request := range [][]byte{nil, make([]byte, limit+1), make([]byte, payloadBytes)} {
		var calls int
		_, err := Exchange(context.Background(), exchangeConfig(), request, func(context.Context, []byte) []byte {
			calls++
			return nil
		})
		if err == nil || calls != 0 || errors.Is(err, ErrDeliveryUnknown) {
			t.Fatal("oversize input reached the worker or was reported as ambiguous delivery")
		}
	}
}

func TestExchangeLostResponseDoesNotRepeatMutation(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	result, err := Exchange(context.Background(), exchangeConfig(), []byte("mutation"), func(context.Context, []byte) []byte {
		calls.Add(1)
		// Simulate a result that cannot be delivered in one response cell.
		return make([]byte, payloadBytes)
	})
	if !errors.Is(err, ErrDeliveryUnknown) || calls.Load() != 1 || result.Report.Completed != 0 {
		t.Fatal("ambiguous worker outcome retried or reported as a definite failure")
	}
}

func TestExchangeCancellationStopsWorkerAndJoinsTransport(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started, stopped := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	cfg := exchangeConfig()
	cfg.Duration = 6 * time.Second
	go func() {
		_, err := Exchange(ctx, cfg, []byte("request"), func(ctx context.Context, _ []byte) []byte {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil
		})
		done <- err
	}()
	select {
	case <-started:
		cancel()
	case <-ctx.Done():
		t.Fatal("worker never started")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrDeliveryUnknown) {
			t.Fatal("in-flight cancellation lost ambiguous delivery status")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not join transport and worker")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("worker was not joined")
	}
}
