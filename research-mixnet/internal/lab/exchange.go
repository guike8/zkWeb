// SPDX-License-Identifier: AGPL-3.0-or-later
package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrDeliveryUnknown means the worker may have completed a side effect even
// though its response was not received. Callers must not automatically retry.
var ErrDeliveryUnknown = errors.New("delivery_unknown: the request may have executed; inspect the target before retrying")

// ExchangeResult holds a single-cell response and aggregate transport counters.
// Report retains the lab schema; its latency field measures this request rather
// than a synthetic job when used by Exchange.
type ExchangeResult struct {
	Response []byte
	Report   Report
}

type exchangeJob struct {
	payload []byte
	handle  func(context.Context, []byte) []byte
	receive func([]byte)
}

// Exchange carries one bounded request to an explicit worker over the lab's
// scheduled loopback Sphinx links, then carries its response over a SURB. The
// handler must obey cancellation and return at most 4090 bytes. Completion does
// not shorten the configured epoch. There are no retries or direct fallbacks.
// HTTP egress policy belongs to the worker; the transport itself stays local.
func Exchange(parent context.Context, cfg Config, request []byte, handle func(context.Context, []byte) []byte) (ExchangeResult, error) {
	if err := cfg.validate(); err != nil {
		return ExchangeResult{}, err
	}
	if cfg.Clients != 1 || cfg.Jobs != 1 || handle == nil {
		return ExchangeResult{}, errors.New("exchange requires one client, one job and a worker")
	}
	if err := parent.Err(); err != nil {
		return ExchangeResult{}, err
	}
	// Account for JSON/base64 and the reply capability before any network work.
	// The application payload alone cannot use the entire forward cell.
	code := newCodec()
	if err := validateExchangeSize(request, code.s.Geometry().SURBLength); err != nil {
		return ExchangeResult{}, err
	}
	replies := make(chan []byte, 1)
	job := &exchangeJob{
		payload: append([]byte(nil), request...),
		handle:  handle,
		receive: func(raw []byte) {
			select {
			case replies <- raw:
			default:
			}
		},
	}
	report, err := run(parent, cfg, job)
	result := ExchangeResult{Report: report}
	if err != nil {
		return result, fmt.Errorf("%w: %w", ErrDeliveryUnknown, err)
	}
	select {
	case result.Response = <-replies:
		return result, nil
	default:
		return result, ErrDeliveryUnknown
	}
}

func validateExchangeSize(request []byte, surbLength int) error {
	if len(request) == 0 || len(request) > payloadBytes-6 {
		return errors.New("request_too_large_or_empty: request must fit one cell including its reply capability")
	}
	raw, err := json.Marshal(researchRequest{Payload: request, Reply: make([]byte, surbLength)})
	if err != nil || len(raw) > payloadBytes-6 {
		return errors.New("request_too_large: encoded request and reply capability exceed one cell")
	}
	return nil
}

func queueReply(code *codec, firstHop nodeID, out *link, surb, response []byte) {
	frame, err := encodeFrame(responseKind, response)
	if err != nil {
		return
	}
	packet, first, err := code.s.NewPacketFromSURB(surb, frame)
	if err != nil || first == nil || *first != firstHop {
		return
	}
	out.enqueue(packet, time.Now())
}
