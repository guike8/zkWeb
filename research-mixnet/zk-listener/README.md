# ZK authorization listener

This standalone backend closes the client → ZK proof → listener verification →
CRUD loop. It uses a real BN254 Groth16 circuit and a private Merkle credential.
The listener receives a verification key and public group profile, never a
member secret, leaf position or membership path. It verifies authorization
before accessing records.

Request contents and stored records are plaintext. FHE for hidden-input
computation is deferred. This backend has no TFHE, wallet-payment or chain
oracle dependency.

## Build and run

From `research-mixnet/` with Go and Rust 1.99 installed:

```sh
make build
make build-zk
./bin/zkweb zk-setup --output /tmp/zkweb-zk-demo --members 4
./bin/zkweb zk-listen \
  --server-dir /tmp/zkweb-zk-demo/server \
  --state-file /tmp/zkweb-zk-records.json \
  --listen 127.0.0.1:0
```

Use the listener's READY URL in a second terminal:

```sh
./bin/zkweb zk-request --client-dir /tmp/zkweb-zk-demo/client-0 \
  --url http://127.0.0.1:PORT --method POST --key note --data 'hello'
./bin/zkweb zk-request --client-dir /tmp/zkweb-zk-demo/client-0 \
  --url http://127.0.0.1:PORT --method GET --key note
./bin/zkweb zk-request --client-dir /tmp/zkweb-zk-demo/client-0 \
  --url http://127.0.0.1:PORT --method PUT --key note --data 'updated'
./bin/zkweb zk-request --client-dir /tmp/zkweb-zk-demo/client-0 \
  --url http://127.0.0.1:PORT --method DELETE --key note
make test-zk
```

POST creates; GET reads; PUT replaces an existing value; DELETE removes it.
`--data-file` preserves arbitrary binary bytes. Keys contain 1–128 ASCII
letters, digits, underscores or hyphens. Bodies are bounded to 64 KiB and the
store to 1024 records. Client results encode returned bytes as base64.

The Go wrappers invoke the fixed sibling executable `zkweb-zk-listener` without
a shell. The Rust crate is an independent workspace, so the ordinary Go build
and other proof backends do not compile its dependencies.

## Exact proof statement

The circuit's public inputs, in order, are:

1. Authorized group Merkle root.
2. First 128-bit big-endian half of the SHA-256 request digest.
3. Second 128-bit big-endian half, preserving all 256 digest bits.
4. Authorization tag.

The private witnesses are a nonzero member secret, four path siblings, four
leaf-position bits and fresh per-proof tag blinding. A domain-separated
Poseidon leaf derived from the secret must reach the public root through the
private path. Both digest limbs are constrained to 128 bits. The same secret,
both limbs and fresh private blinding enter the constrained Poseidon tag.
Thus the request digest participates in constraints; it is not an unused public
input.

The listener recomputes the digest from the method, exact record path and body
it will execute, together with the protocol/profile, server instance, nonce and
expiry. The encoding is domain-separated and length-prefixed. A proof made for
a different body, method, key, profile, listener instance or challenge does not
authorize this request.

Proof generation uses Groth16's randomized zero-knowledge prover. The wire
proof is exactly 128 compressed bytes. Deserialization validates curve points
and rejects trailing bytes; canonical field encodings reject values outside
BN254 Fr. Fresh private tag blinding avoids a stable member-specific tag even
when a request context is repeated. Replay prevention comes from the listener's
one-use challenge cache rather than a deterministic spending nullifier.

Native and R1CS Poseidon use BN254 rate 2, capacity 1, alpha 5, eight full rounds
and 57 partial rounds. The small helpers follow the existing repository's
`protocol/rust/crates/zkapi-proof/src/groth16.rs`, with new listener-specific
domains. The new circuit does not reuse that wallet circuit's payment statement.
See [crypto.rs](src/crypto.rs) for the constraints and native counterparts.

## Provisioning and trust

`zk-setup` provisions 1–16 members, defaulting to four, under a fixed depth-four
tree. It creates a fresh setup directory with 0700 role directories and 0600
files, rejecting existing output paths.

| Role directory | Material |
| --- | --- |
| `server/` | Public manifest and verifying key only |
| `client-N/` | Public proving key, private credential and client manifest |

Give a listener operator only `server/`. The offline provisioner temporarily
knows every credential secret and can impersonate members. It must generate
Groth16 setup parameters honestly and protect or discard sensitive copies. This
example has no multiparty production ceremony or forensic memory-erasure claim.
A trusted profile distribution channel is required: hashes detect disagreement
with a pinned manifest but do not make an attacker-chosen manifest trustworthy.

The shared profile pins protocol, parameter identity, group root, member count
and proving/verifying-key hashes. Client-only credential hashes are absent from
the server manifest. Local key objects have size limits, validated compressed
deserialization and no trailing bytes; a proving key's embedded verifying key
must match the registered key hash.

Separate processes and filesystem modes are not an isolation boundary against
a common host administrator. Credential enrollment, rotation/revocation and
independent client-generated identities need further application design.

## HTTP listener and CRUD state

The default [compact transport](../../docs/compact-zk-client-server.md) uses
GET `/b1/c` for a 72-byte challenge: a 256-bit server-instance identifier,
256-bit nonce and 120-second expiry. The cache is bounded. POST `/b1/r` carries
192 raw authorization bytes plus the operation, key and raw body. Keys and
expected context are installed once; the credential witness stays local.
One connection can carry the challenge and operation, with a two-request cap
and five-second header/idle limit.

`--wire legacy` explicitly selects the earlier JSON `/challenge` and
`/records/KEY` transport with `x-zkweb-challenge`, `x-zkweb-proof` and
`x-zkweb-tag` headers. There is no automatic downgrade. Both transports preserve
the same circuit and logical request transcript.

The listener consumes a recognized challenge before costly verification.
Only a valid proof reaches record lookup or mutation. Challenges fail after
consumption or expiry; restarting creates a fresh instance. Unknown or malformed
authorization never becomes an application CRUD request.

Records are durably stored in a private local snapshot under an exclusive
sidecar lock. The data is plaintext; base64 represents binary values. Atomic
replacement and synchronization protect honest-process mutation recovery, not
malicious-server honesty or rollback of operator-controlled backups. A lost
reply can follow an already committed mutation. No client request is retried
automatically, and ambiguous delivery must be reconciled deliberately.

All authorized members can access every listener record. This is common-group
admission, not per-user ownership. Remote TLS deployment, rate eligibility,
payment, network anonymity and proofs of server execution are separate concerns.
The current listener/client accept numeric loopback addresses only. Endpoint,
IP, timing, sizes, profile and ordinary request contents remain visible.
