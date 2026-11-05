# Compact ZK client/server exchange

This is a transport design target, not an implemented binary protocol. The current
listener uses HTTP, JSON challenges and text-encoded authorization headers.
The [live API tests](zk-api.md#live-public-api-test) exercise that implementation.

The client proves group membership and binds its proof to the exact operation.
The server verifies the proof, executes the operation and returns its result.
Member secrets, membership paths, proving keys and verification keys are not
sent with each request. An ordinary result is not a proof of correct server
computation; that would require an additional statement and proof.

## Current authorization size

| Field | Raw bytes | Current encoding |
| --- | ---: | ---: |
| Compressed Groth16 proof | 128 | 172 base64 bytes |
| Randomized public tag | 32 | 64 hex bytes |
| One-use challenge identifier | 32 | 64 hex bytes |
| Total | 192 | 300 bytes of values |

The three complete authorization header lines use 353 bytes, including names,
separators and CRLF. Other HTTP headers, operation metadata, payload and response
are additional. These are implementation sizes, not a minimum across ZK systems.

The server already knows the group root and derives the two public digest limbs
from the actual operation and stored challenge. Those inputs do not need another
copy on the wire. The randomized tag remains a required public input to the
existing circuit.

## Candidate binary exchange

Install the profile and keys once, and configure the expected protocol and
upstream/service on both sides. Preserve the current logical transcript and
canonicalization when decoding compact messages so existing circuit semantics
and setup can remain unchanged.

1. Challenge: server instance (32 bytes), nonce (32 bytes), expiry (8 bytes).
   This totals 72 bytes. A persistent authenticated session could send the
   instance once, leaving 40 bytes per subsequent challenge.
2. Request: nonce (32 bytes), tag (32 bytes), proof (128 bytes), operation code,
   length-prefixed resource/path and selected headers, and the required raw
   payload. The authorization portion totals 192 bytes without text expansion.
3. Response: status, necessary metadata and raw result bytes. Preserve the
   distinction between upstream responses, authorization errors and unknown
   delivery. Avoid repeating the known origin or base64-encoding the body.

A persistent connection with exactly one pending challenge could make the nonce
implicit, reducing request authorization to 160 bytes. That requires a session
protocol and restricts concurrency; it is not part of the current HTTP transport.
Binary encoding alone does not remove HTTP, TLS or network framing overhead.

Keep one-use challenge consumption before verification, expiry, server-instance
and destination binding, strict canonical decoding, field/point validation, size
limits and the current no-retry behavior. Retain fresh randomized tags; replacing
them with a stable member handle would change the privacy property.

## What the server learns

For ordinary CRUD, the server receives the operation, resource identifier and
input required to execute it. ZK hides the authorization witness; it does not
hide those inputs. HTTPS protects traffic in transit. Hiding operation inputs
from a cooperating server is separate encrypted-computation work.

The current listener accepts numeric-loopback HTTP endpoints. A hosted client
and server need authenticated HTTPS support before this can become a remotely
usable service. The compact transport described here is separate from that
deployment work.
