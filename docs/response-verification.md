# Offline TLSNotary response verification

`zkweb verify` checks an existing TLSNotary presentation against a caller's
expected server, notary public key and time window. It can return explicitly
selected, authenticated transcript bytes. Verification is offline: it does not
make another HTTP request, start Tor, or turn a previous `fetch` response into a
proof.

This is an experimental integration with TLSNotary **alpha.15**, pinned to
commit `47aee45b53e06648c1b2ad3689b367b8c923fdec`. The optional Rust backend uses
the upstream attestation/core verifier; it does not implement its own TLS or
proof cryptography. TLSNotary remains development software, and accepting its
attestation means trusting the selected notary under that protocol's model.
Successful verification does not establish that the notary operated honestly.
[Pinned upstream source](https://github.com/tlsnotary/tlsn/tree/47aee45b53e06648c1b2ad3689b367b8c923fdec),
[TLSNotary introduction](https://tlsnotary.org/docs/intro/).

## Build the optional verifier

```sh
cd research-mixnet
make build
make build-proof
./bin/zkweb verify --help
```

The ordinary `make build` builds the Go client. `make build-proof` separately
builds `bin/zkweb-tlsn-verify` using the repository's Rustup 1.99.0 toolchain,
which must be installed. `make test-proof` runs the Rust cryptographic tests and
the Go-to-backend fixture integration. The Go command uses that fixed sibling executable;
installing an arbitrary command on `PATH` does not select a verification backend.
The backend accepts the pinned upstream presentation format, not arbitrary
notary receipts or presentations from other TLSNotary versions.

## Supply trusted verification policy

Choose the expected notary key and server independently of the presentation.
Likewise, choose a time window appropriate for the application rather than
copying the presentation's own timestamp into policy. These arguments are
required even when requesting metadata only.

```sh
# Set these public policy values from a trusted source before running.
./bin/zkweb verify --input presentation.json \
  --server tlsnotary.org \
  --notary-key "$EXPECTED_NOTARY_KEY" \
  --not-before "$EARLIEST_ACCEPTABLE_TIME" \
  --not-after "$LATEST_ACCEPTABLE_TIME"
```

`--server` is the expected authenticated server name, without a URL scheme or
path. `--notary-key` is a lowercase, compressed K256 public key: 66 hexadecimal
characters, without a `0x` prefix. The time bounds are Unix seconds. The
attested connection time must satisfy that window; it is not proof that the
origin's application data was freshly generated or remains current.

The input is an upstream alpha.15 **JSON presentation**, with a maximum file
size of 16 MiB. Binary/bincode input is not supported. Declared transcript
lengths are checked before typed decoding and are limited to 1 MiB per
direction. Verification does not contact an issuer, notary or origin to obtain
additional evidence.

## Request authenticated bytes explicitly

Without range flags, output contains metadata only. To obtain bytes, add
`--sent-range START:END` and/or `--received-range START:END`, repeating flags for
additional ranges. Indices are zero-based and the end is exclusive. Supply
ranges in increasing order without overlap within each direction.

```sh
./bin/zkweb verify --input presentation.json \
  --server tlsnotary.org \
  --notary-key "$EXPECTED_NOTARY_KEY" \
  --not-before "$EARLIEST_ACCEPTABLE_TIME" \
  --not-after "$LATEST_ACCEPTABLE_TIME" \
  --sent-range 0:32 --received-range 100:132 --timeout 30s
```

Those offsets are examples, not HTTP field locations. A requested range must
be within the transcript and covered completely by authenticated disclosure in
the presentation. Hidden gaps are rejected; redacted bytes are not represented
as fabricated zeroes, `X` characters or other substitute data. At most 64 ranges
per direction are accepted, with a total selected-byte output budget of 1 MiB.

The flags control what zkWeb returns. **They do not redact the input
presentation.** Its producer determines what the artifact discloses, and anyone
who receives that artifact may inspect its existing disclosures. Handle the
presentation as potentially sensitive even when requesting metadata only.

## Output and verification meaning

Successful stdout is a JSON result with format `zkweb-tlsn-verified-v1`, the
pinned `backend_commit`, `server_name`, `notary_key_hex`, attested `time`,
`sent_length`, `received_length`, and `sent`/`received` range arrays. Each range
contains `start`, `end` and `data_base64`. Metadata-only results have empty range
arrays. Only successful, policy-matching verification produces this result.

The selected ranges are authenticated transcript data under the pinned
TLSNotary presentation and the caller's notary policy. This command does not
parse them into an HTTP status, method, Host header or application claim. Such
claims require additional complete-message parsing and an explicit statement
about which fields must be disclosed and bound together.

In particular, acceptance does not establish:

- That the proof belongs to a separate `zkweb fetch` result or caller request.
- That an application challenge or nonce was echoed by the origin.
- That a mutation executed exactly once or was not replayed.
- That traffic was anonymous or used a particular network route.

The existing `delivery_unknown` rule for HTTP mutations remains separate.
Never repeat a write merely to obtain a proof after its response was lost.

## Synthetic compatibility fixtures

The upstream compatibility fixture is cryptographic test material. Its disclosed
HTTP content includes a fake `Host: localhost` and a cookie, and its test
notary's private key is publicly known. Passing that fixture checks compatibility
and tamper rejection; it is not evidence of an authentic receipt from the named
real-world origin or a trustworthy notary deployment.
See the [backend notes](../research-mixnet/proof-verifier/README.md) for its pinned
source and fixture-specific verification policy.

Use fixture-specific expected policy only in tests. Do not place the development
notary key in a production allowlist. An application accepting real artifacts
must obtain the intended notary's key and define its server, time and disclosure
policy independently.

## Why this first adapter uses TLSNotary

Reclaim's exported `assertValidClaimSignatures` checks signatures against the
receipt's supplied attestor address. It does not itself establish that signer's
trust or rerun TLS/ZK transcript verification. The current handler also removes
the transcript from ordinary returned claim results. A pinned-signer Reclaim
receipt adapter would therefore have a different trust and verification
statement from this upstream presentation verifier.
[Reclaim signature verifier](https://github.com/reclaimprotocol/attestor-core/blob/8f7804e553900dff57c57e9d9394773d884f68b0/src/utils/claims.ts),
[claim handler](https://github.com/reclaimprotocol/attestor-core/blob/8f7804e553900dff57c57e9d9394773d884f68b0/src/server/handlers/claimTunnel.ts).

The chosen milestone is offline verification of already-produced presentations.
Proof capture/generation, automated selective-disclosure policy, request/fetch
binding and stronger application statements remain separate work. See the
[implementation research](web-request-research.md) and
[architecture](../research-mixnet/ARCHITECTURE.md).
