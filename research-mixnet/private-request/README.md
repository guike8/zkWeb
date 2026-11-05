# Cooperative private web query

This executable demonstrates a destination processing an HTTP request without
learning which of four records the client selected. The client sends a TFHE
encrypted two-bit selector with a real zero-knowledge proof of correct
encryption. The destination verifies that proof, computes a lookup over
`[11, 22, 33, 44]` homomorphically, and returns an encrypted eight-bit result.
Only the client decrypts it.

ZK is mandatory input validation here; FHE supplies input confidentiality. This
is a fixed, cooperating application endpoint. Ordinary HTTP servers must be
changed to support encrypted computations; this prototype does not hide an
arbitrary URL, HTTP method, JSON body, or CRUD operation from an unchanged server.
There is no proof that the destination evaluated the lookup honestly.

## Build and run

From this directory, with Rust 1.99 installed:

```sh
cargo +1.99.0 build --release --locked
cargo +1.99.0 test --release --locked -- --nocapture
./target/release/zkweb-private setup --output /absolute/nonexistent/profile
./target/release/zkweb-private serve --server-dir /absolute/nonexistent/profile/server --listen 127.0.0.1:0
./target/release/zkweb-private query --client-dir /absolute/nonexistent/profile/client --url http://127.0.0.1:PORT --index 2
```

The server prints one ready JSON line containing its allocated loopback URL.
The client prints `{"format":"zkweb-private-result-v1","index":2,"value":33}`.
The repository's Go wrapper and Makefile use the same backend with explicit
Rust compiler paths. `CARGO_TARGET_DIR` changes the binary location.

## Provisioning and trust

Run `setup` on a trusted offline provisioner. It generates a fresh CRS, client
secret key, compact public key, and homomorphic evaluation key. The CRS setup
uses the upstream trusted setup; its secret setup randomness must not be retained
or controlled by an adversary. The library does not provide a multiparty setup
ceremony here. Setup is randomized, and the setup process exits after writing
its outputs. This application makes no claim of forensic memory erasure.

Deploy the two directories to separate roles:

| Client host | Destination host |
| --- | --- |
| `client-key.tfhe` (secret, never uploaded) | `server-key.tfhe` (evaluation key; cannot decrypt) |
| `compact-public-key.tfhe` | `compact-public-key.tfhe` |
| `crs.tfhe` | `crs.tfhe` |
| `manifest.json` with role `client` | `manifest.json` with role `server` |

The destination directory contains neither the client key nor its hash. The
provisioner knows the client key and must be trusted not to give it to the
destination. Running setup on the destination gives that destination the secret
and defeats the intended privacy boundary. Keys remain outside request payloads.

Directories are created with mode 0700 and files with mode 0600, using
create-new semantics. A preexisting output directory is rejected. An interrupted
setup can leave a partial directory; remove that directory deliberately and
choose a new output before retrying. Paths in the manifest are fixed by the
program. Each role verifies file size limits and SHA-256 hashes before loading
keys. Both manifests share a profile identifier derived from the exact parameter
names and CRS/public/evaluation-key hashes. A manifest is a trusted provisioning
artifact, not an independently authenticated signature: transfer and pin it
through a trusted channel. File hashes detect corruption or substitution against
that trusted manifest.

## Request and proof contract

`GET /challenge` returns `protocol`, `profile_id`, `server_instance`,
`challenge_id`, and `expires_unix`. Nonces and instance identifiers each contain
256 CSPRNG bits. Challenges expire after 120 seconds; at most 1024 active
challenges are retained. Restarting creates a new server instance and empty
challenge cache.

`POST /query` accepts exactly two JSON fields:

```json
{"challenge_id":"64 lowercase hexadecimal characters","proof_base64":"TFHE safe-serialized proven ciphertext list"}
```

The ZK transcript metadata binds the protocol version, lookup function identifier,
profile, server instance, challenge, and expiration using fixed-order,
length-prefixed fields. The server reconstructs this context from its own cached
challenge. It accepts exactly one `FheUint2`, applies bounded safe deserialization
and upstream parameter conformance checks, and calls `verify_and_expand` before
executing the FHE lookup. Empty lists, wrong types/lengths, modified proofs, and
incorrect contexts fail. The client uses `ZkComputeLoad::Proof`; conformance
forbids verifier-heavy `ZkComputeLoad::Verify` proofs before cryptographic
verification/expansion. A recognized challenge is consumed before proof decoding
or verification, including on failure. A replay cannot repeat expensive proof
verification or execute the lookup. There is deliberately no verification bypass.
Fresh challenges remain obtainable up to the bounded cache limit; production
eligibility and proof-verification quotas are outside this prototype.

Success returns `protocol`, `profile_id`, `server_instance`, `challenge_id`, and
`ciphertext_base64` only. The result is a safely serialized `FheUint8` of fixed
type and shape. Its numerical value and selector are absent from the plaintext
response. The client checks response context and conformance before local
decryption. Invalid requests produce a generic error without query logging.

## Visible information and limits

The destination sees the fixed `/challenge` and `/query` routes, public profile
identifier, challenge metadata, ciphertext/proof bytes, request size, source
address, and timing. It does not receive the plaintext selector, selected value,
or client secret. This does not provide traffic anonymity or a hiding transport
for general web requests. The destination can deny service, alter its table,
return an incorrect result, or correlate repeated use of a profile. Proofs
establish well-formed encryption and bind a request context, not authorization,
rate eligibility, or honest execution.

The listener and client accept numeric loopback addresses only. HTTP has no
transport authentication; loopback is a development boundary. Clients disable
proxies, redirects, and automatic retries, and use timeouts. The service rejects
browser `Origin` headers, unknown routes, query strings, unknown JSON fields,
and oversized bodies. Application processing is serial on the thread that holds
TFHE's thread-local evaluation key. HTTP parsing is provided by Hyper on a
single-thread Tokio runtime, with one active connection and no per-connection
task spawning. Headers are bounded to 32 fields and a 16 KiB parser buffer with
a 5 second read timeout. Bodies are bounded to 8 MiB with a 10 second read
timeout; connections have a 60 second overall deadline and keep-alive is disabled.
These bounds do not provide service fairness or authorization against a local
process repeatedly opening new connections/challenges. The four-record table is
public; database-owner privacy is outside this experiment.

Proof payloads are bounded to 4 MiB, JSON bodies to 8 MiB, results to 1 MiB,
CRS files to 32 MiB, and local key objects to 2 GiB. Real full-security TFHE key
generation, proof creation, and evaluation require substantial CPU and memory.
The fixture generates keys once, tests all four values, checks failed-proof and
replay execution counters, and exercises actual HTTP. No reduced-security test
parameters or fake proofs are used.

## Cryptographic provenance

`Cargo.lock` pins registry versions and package checksums. The direct TFHE
dependency is exactly `1.8.2`, with default features disabled and only `integer`
and `zk-pok` enabled. The upstream release tag `tfhe-rs-1.8.2` resolves to commit
`e8f3926bb53d7eea95e8a7f581f60aae1c7aba16` (release 2026-10-19). This is the
upstream implementation rather than a circuit simulated in application code.
The dependency includes `tfhe-zk-pok 0.9.0`, implementing the compact-PKE ZK
relation; setup generates a fresh CRS for this profile instead of downloading
an unpinned proving asset.

Registry package SHA-256 checksums from the committed lockfile:

| Package | Checksum |
| --- | --- |
| `tfhe 1.8.2` | `f7c68a185ef0d2287eeb9ae3123e6d0f927dc3a33cc9ff393e59987104dcb816` |
| `tfhe-zk-pok 0.9.0` | `cd4d91594d5434b3328f435ed77db1b7d0584e91128521a0014dab923ddcffc9` |

All three parameter constants use upstream's `2M128` parameter family (the
suffix denotes a target failure probability of approximately `2^-128`):

- `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`
- `PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`
- `PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`

The compact-PKE CRS is sized for two selector bits. The upstream packed message
capacity rounds to its block size; protocol-level checks still require one
two-bit unsigned selector. Proof verification alone does not enforce an
application's list length or type, so this program checks both explicitly.

Primary sources for the exact release:

- [TFHE-rs 1.8.2 release](https://github.com/zama-ai/tfhe-rs/releases/tag/tfhe-rs-1.8.2)
- [ZK proof API and relation documentation](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.2/tfhe/docs/fhe-computation/advanced-features/zk-pok.md)
- [High-level proof creation/verification implementation](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.2/tfhe/src/high_level_api/compact_list.rs)
- [Proof conformance and list representation](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.2/tfhe/src/integer/ciphertext/compact_list.rs)
- [Actual compact-PKE ZK implementation](https://github.com/zama-ai/tfhe-rs/tree/tfhe-rs-1.8.2/tfhe-zk-pok/src)
- [Safe serialization documentation](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.2/tfhe/docs/fhe-computation/data-handling/serialization.md)
- [Encrypted match implementation](https://github.com/zama-ai/tfhe-rs/blob/tfhe-rs-1.8.2/tfhe/src/high_level_api/integers/unsigned/base.rs)

The application follows the parent project's AGPL-3.0-or-later license. TFHE-rs
and TFHE-ZK-PoK carry BSD-3-Clause-Clear licenses, reproduced in `licenses/`.
Other dependencies retain their upstream licenses recorded in their packages.
