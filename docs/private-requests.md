# Requests whose input stays hidden from the destination

zkWeb's `private-*` commands demonstrate a real HTTP request whose selected
record stays encrypted at the destination. The client encrypts an index, proves
that it is a valid two-bit encryption, and sends the ciphertext with its
zero-knowledge proof. The cooperating server verifies the proof, performs a
homomorphic lookup, and returns an encrypted value. Only the client decrypts it.

This is an experimental private-read protocol over a fixed public table:

| Private index | Returned value |
| --- | --- |
| 0 | 11 |
| 1 | 22 |
| 2 | 33 |
| 3 | 44 |

The index is the hidden request content. The endpoint and lookup operation are
public. This first implementation does not hide arbitrary URLs, headers,
credentials or CRUD bodies from existing web servers. A destination must be
adapted to compute on encrypted inputs; ordinary HTTP handlers cannot execute
arbitrary hidden requests unchanged.

## What ZK does here

Fully homomorphic encryption (FHE) supplies input and result confidentiality.
The zero-knowledge proof checks that the input ciphertext was correctly formed
under the agreed compact public key and parameters, without disclosing which
index it contains. Proof verification gates the computation; it is not an
optional receipt attached after processing.

The statement uses the registered compact public key, common reference string
(CRS), compact ciphertext and bound request metadata as public inputs. The
witness includes the index and encryption randomness. Mandatory ciphertext
conformance and the requirement for exactly one `FheUint2` element fix the
selector domain to `0..3`. The encryption proof establishes validity under that
configuration. The server does not accept an eight-bit value and merely assume
that it is less than four.

TFHE-rs implements this compact-encryption proof. Its documentation explains
the CRS and verification-before-computation flow, including binding arbitrary
metadata into the proof.
[Pinned TFHE-rs zero-knowledge proof API](https://github.com/zama-ai/tfhe-rs/blob/e8f3926bb53d7eea95e8a7f581f60aae1c7aba16/tfhe/docs/fhe-computation/advanced-features/zk-pok.md).

This proof does not establish the requester's identity, authorization, payment,
or membership. It also does not prove that the server evaluated the lookup
correctly. A malicious server can return a wrong ciphertext or withhold its
reply. Conformance checks on the result are structural checks, not a proof of
correct computation or data freshness.

## Build and run

The backend is the standalone Rust crate
[`research-mixnet/private-request`](../research-mixnet/private-request/).
Its executable is `zkweb-private`; the Go `zkweb private-*` commands invoke it.
The ordinary Go build does not download or compile FHE dependencies.

From the repository root:

```sh
cd research-mixnet
make build
make build-private

# Choose a fresh output directory. Provisioning is an offline step.
./bin/zkweb private-setup --output /tmp/zkweb-private-demo

# Keep this process running. Port 0 asks the OS to choose a free port.
./bin/zkweb private-serve \
  --server-dir /tmp/zkweb-private-demo/server \
  --listen 127.0.0.1:0
```

The server prints a READY JSON record containing its actual URL. In another
terminal, replace `PORT` with that port and run from `research-mixnet`:

```sh
./bin/zkweb private-query \
  --client-dir /tmp/zkweb-private-demo/client \
  --url http://127.0.0.1:PORT \
  --index 2
```

The client decrypts `33` locally. Its output includes the index and plaintext
value for the person running the client. Neither plaintext field is sent to the
server. Protect client-side command history and output if the selection itself
is sensitive.

The prototype accepts numeric loopback addresses only. This keeps the example
local; it does not establish a remote authenticated deployment or combine this
mode with Tor. Key generation, proving and FHE evaluation use the full upstream
parameter sets and can be expensive. There is no reduced-security toy mode and
no performance claim based on an unmeasured run.

Run the backend cryptographic checks and real HTTP integration with:

```sh
make test-private
```

## Key material and provisioning trust

`private-setup` creates two separate directories:

| Directory | Material | Who should receive it |
| --- | --- | --- |
| `client/` | Secret `ClientKey`, compact public key, CRS and manifest | Client only |
| `server/` | FHE evaluation `ServerKey`, compact public key, CRS and manifest | Cooperating destination |

An FHE `ServerKey` is evaluation material; it is not the client's decryption
key. The server directory never includes a `ClientKey`. For a destination run
by another operator, transfer only the server directory. A complete setup
directory or its client subdirectory gives that operator the secret needed to
decrypt selections and replies.

The manifest pins the cryptographic configuration, CRS and registered keys in
a profile hash. These pins detect disagreement with the provisioned profile;
they do not make an untrusted setup trustworthy. The offline provisioner sees
the client secret during key generation and must be trusted to generate the
material honestly and protect or discard its secret copies. CRS generation
also has a trust assumption. This example has no production ceremony, external
key-registration service or proof of honest setup.

Running both processes on one machine tests the protocol, not isolation from a
host administrator. Filesystem permissions and separate process arguments do
not prevent a common machine operator from reading client files or memory.
Separate hosts and a trusted client environment are needed to exercise a real
operator boundary. Upstream TFHE-rs also documents limitations concerning
side-channel protection; this prototype adds no general side-channel defense.
[Pinned TFHE-rs source and security model](https://github.com/zama-ai/tfhe-rs/tree/e8f3926bb53d7eea95e8a7f581f60aae1c7aba16).

## What crosses HTTP

1. `GET /challenge` returns a public protocol identifier, profile identifier,
   fresh server-instance identifier, challenge identifier and expiry time.
2. The client checks the profile and challenge, encrypts its index, and binds
   the proof to the protocol, fixed lookup function, profile, server instance,
   challenge and expiry.
3. `POST /query` carries only `challenge_id` and the base64-encoded proven
   ciphertext list. It contains no plaintext index or selected table value.
4. For a decoded query naming an existing challenge, the server consumes that
   challenge before attempting expensive verification,
   checks bounded decoding and cryptographic
   conformance, requires a nonempty one-element `FheUint2` list, and verifies
   the ZK proof before expanding the selector or evaluating the lookup.
5. The server evaluates `MatchValues` over the encrypted selector and returns
   an encrypted `FheUint8`, together with public protocol/context fields. The
   client checks that context and ciphertext conformance, then decrypts locally.

The proof context has a domain separator, explicit field lengths and a fixed
field order. A proof made for another profile, function, server instance,
challenge or expiry does not verify against this request's context. Challenges
expire after 120 seconds; the server bounds outstanding challenges. A decoded
query burns its recognized challenge, including a failed proof, so the same challenge
cannot trigger repeated verification. A fresh server-instance identifier on restart prevents
old proofs from becoming valid again under a new challenge store.

The client generates prover-heavy `ZkComputeLoad::Proof` proofs. Conformance
rejects verifier-heavy `Verify` encodings before cryptographic verification.
HTTP handling bounds header count and buffering, header/body read times and
body size, with one connection processed at a time. These bounds do not supply
production admission control: clients can still request new challenges and
consume substantial proving or evaluation resources.

These checks constrain replay at the accepting server. They are not a general
exactly-once execution protocol, a proof of response freshness, or protection
against a malicious destination returning a stale or fabricated result.

Successful replies have the same ciphertext type and response structure for
all four selections. The server does not branch its HTTP status on a decrypted
index, because it has no decryption key. Invalid public protocol inputs can
still produce errors. Constant wire structure is not a constant-time execution
claim.

## What the destination can still learn

The destination sees its endpoint, method, public lookup operation, source IP,
request count, timing, sizes, profile/key identifiers, challenge fields,
ciphertext and proof. A reused key/profile can link sessions. The public table
and its four possible outputs are known; the intended hidden fact is which
entry was selected. Encryption does not supply network anonymity.

The client receives plaintext only locally and does not send a success/failure
callback based on the decrypted value. Applications built on this prototype
must consider whether later requests, retries or other observable actions
would reveal that value or expose a decryption oracle.

## Why this implementation

Research on November 5, 2026 compared original project documentation and source
through OpenCLI searches and reads. Existing PIR systems are useful alternatives
for larger private reads, but private retrieval alone is not evidence that a
request carries a ZK input proof.

| Existing implementation | Relevant capability | Difference from this prototype |
| --- | --- | --- |
| [SimplePIR / DoublePIR](https://github.com/ahenzinger/simplepir) | Single-server LWE-based private retrieval with published Go/C research code. | A practical PIR baseline, but its documented API does not provide this ZK compact-encryption admission check. |
| [Blyss SDK](https://github.com/blyssprivacy/sdk) | Homomorphic private reads with Rust server code and client SDKs using Spiral and DoublePIR. | Demonstrates application-oriented private reads; that is not the same claim as a verified ZK input relation. Its repository describes a research/beta readiness boundary. |
| [Authenticated PIR](https://github.com/dedis/apir-code) | Private retrieval with integrity: either an authentic record or detection of misbehavior. | Its multi-server variant needs an honest noncolluding server; its single-server variant needs a trusted database digest obtained separately. This is a possible direction for result integrity, not something the present input proof supplies. [Author publication page](https://people.eecs.berkeley.edu/~henrycg/pubs/authpir/). |

TFHE-rs was selected here because it supplies both encrypted integer evaluation
and a proof of correct compact encryption in one existing library. We use it to
complete a small private request from proof generation through HTTP acceptance,
encrypted computation and local decryption. This is a starting point for a
cooperating backend, not a claim of private execution for arbitrary website
logic. More complex reads or writes require their own encrypted computation or
MPC design, state protocol, authorization and correctness guarantees.

The crate pins `tfhe = "=1.8.2"` and its registry checksum in `Cargo.lock`; the
corresponding upstream source is commit
`e8f3926bb53d7eea95e8a7f581f60aae1c7aba16`. The selected computation, compact-PKE
and key-switching parameters are the upstream `MESSAGE_2_CARRY_2` uniform
`2M128` family. The suffix describes a failure-probability bound of
`2^-128`; it should not be read as a substitute for the library's complete
security assumptions. The dependency's source includes its
[BSD-3-Clause-Clear license](https://github.com/zama-ai/tfhe-rs/blob/e8f3926bb53d7eea95e8a7f581f60aae1c7aba16/LICENSE);
upstream separately describes patent-licensing conditions in its
[README](https://github.com/zama-ai/tfhe-rs/tree/e8f3926bb53d7eea95e8a7f581f60aae1c7aba16#license).

The existing `fetch`, mixnet `request` and offline `verify` commands have their
own guarantees. They do not become destination-blind when the optional private
backend is installed.
