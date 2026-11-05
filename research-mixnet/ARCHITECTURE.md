# zkWeb: architecture and milestones

The current priority is a complete ZK authorization loop: a client proves
membership, the listener verifies the proof against the exact HTTP request and
an issued one-use challenge, then it executes CRUD or forwards to a configured
HTTPS API. Request bodies and the
listener's database remain plaintext at this stage. FHE for hidden-input
computation is deferred separately.

The listener has a distinct BN254 Groth16 circuit and profile; it does not
require the inherited wallet's note/deposit/state machinery or TFHE. The
retained Tor/SOCKS, Sphinx/SURB, earlier FHE lookup and TLSNotary tools keep their
own boundaries. See the [listener guide](../docs/zk-listener.md).

## Separate responsibilities

| Part | Intended responsibility | Current status |
| --- | --- | --- |
| ZK authorization | Prove possession of an authorized secret without sending the member identity or Merkle path. | A depth-four membership circuit and randomized, request-bound authorization tag; listener verifies before CRUD. |
| Application CRUD | Create, read, replace and delete bounded binary records. | POST/GET/PUT/DELETE at the listener; request contents and durable records are plaintext. All authorized members share access to the records. |
| External API gateway | Authorize an exact upstream request before HTTPS egress. | `zk-api` binds origin, target method, escaped path/query, explicit headers and body; fixed-origin async forwarding with validated/pinned DNS, verified TLS, scoped methods/paths and bounded binary envelopes. |
| Profiles and replay | Pin the verification statement and reject reused or wrong-context authorization. | Trusted offline setup, hash-pinned roles, verifying material only at the listener, and bounded expiring one-use challenges bound to a fresh server instance. |
| Private computation | Compute over request inputs while hiding them from the destination. | Deferred. The retained optional FHE mode is a four-value lookup; separate encrypted-CRUD work is not bundled into this listener milestone. |
| General HTTP interface | Preserve ordinary HTTP method, origin/path, headers, body, status and bytes. | Separate fetch/request modes; destinations receive ordinary plaintext inputs. |
| Transport | Address network linkage under an explicit adversary model. | Explicit Tor/SOCKS route or scheduled local Sphinx experiment; neither inherits anonymity from the authorization proof. |
| Session and credential controls | Scope destination credentials and retained state. | Transport contexts remain separate from a member credential; no ambient proxy or cookie jar is used by the listener client. |
| Wallet/payment | Prove spending authority and integrate funded usage. | Inherited zkAPI components remain separate; group authorization does not spend deposits or bypass wallet deployment gates. |
| Response verification | Authenticate selected web transcript facts under a stated trust model. | Optional offline TLSNotary verification; it does not prove this listener's CRUD execution or bind a separate fetch automatically. |

## ZK authorization protocol

### Setup and roles

The isolated `zk-listener/` Rust workspace builds `zkweb-zk-listener` through
`make build-zk`; `make test-zk` is its acceptance entry point. The Go wrappers
`zk-setup`, `zk-listen`, `zk-request` and `zk-api` invoke that fixed sibling executable.
The ordinary Go build includes help/wrappers without compiling Rust. The
backend has no TFHE or wallet-workspace dependency.

Trusted offline setup creates one common depth-four Merkle group with 1–16
members, defaulting to four. It generates nonzero random secrets, each member's
private path and a fresh circuit-specific Groth16 setup. The listener receives
only its verifying key and public manifest. A client receives its own credential
and public proving key. Role directories/files use create-new semantics and
0700/0600 modes. Keys and credential files are bounded, hash-pinned and validated
before use; compressed cryptographic objects reject trailing bytes.

The provisioner knows member secrets and can impersonate members. The common
reference string must be generated honestly; no production multiparty ceremony
is claimed. Giving a destination the whole setup exposes client credentials.
A shared operating-system administrator is outside the process/file boundary.

### Circuit statement

Private witnesses are a nonzero credential secret, four Merkle siblings, four
leaf-position bits, and fresh per-proof tag blinding. Public inputs, in order,
are the authorization root, two 128-bit limbs preserving a complete SHA-256
request digest, and an authorization tag. The circuit constrains:

1. The secret's domain-separated Poseidon leaf and private path reach the root.
2. Both digest limbs are 128-bit values.
3. The tag equals Poseidon of its authorization domain, that same secret, both
   digest limbs and the fresh private blinding.

The public request digest participates in constraints; an unused public signal
would not bind a proof. The native and R1CS Poseidon helpers share BN254 rate 2,
capacity 1, alpha 5, eight full rounds and 57 partial rounds, following the
existing repository primitives with separate listener domains. Groth16 proofs
use the randomized prover, compressed 128-byte encoding and validated curve
points. This statement is distinct from wallet funding and correct encryption.

Fresh private tag blinding avoids a stable credential tag even if a request
context is repeated. The nonce cache still supplies replay rejection; the tag
is not a wallet-spend nullifier. No claim follows about IP, timing, request
contents or a colluding endpoint's other identifying observations.

### HTTP acceptance and state

1. GET `/challenge` returns the pinned protocol/profile, fresh server instance,
   random nonce and expiry. The client validates the profile and lifetime.
2. The client hashes a length-prefixed, domain-separated transcript containing
   the actual method, record path and body plus that challenge context.
3. The client creates a membership proof and sends the ordinary HTTP CRUD
   request with proof, tag and challenge headers; it sends no credential witness.
4. The listener reconstructs the digest from the actual received bytes and its
   cached challenge. It consumes a recognized challenge before expensive proof
   verification and rejects incorrect profiles, contexts, tags and proofs.
5. Only successful authorization reaches record lookup or mutation. POST
   creates, GET reads, PUT replaces and DELETE removes a record. The durable
   store uses an exclusive lock and atomic snapshot replacement.

Challenges expire after 120 seconds and the cache is bounded. Restarting uses a
new server instance, preventing an old proof from becoming valid in a fresh
cache. The client never automatically repeats a request: a lost response can
follow a committed mutation. Persistence failure must stop the instance until
recovery rather than permit divergent in-memory and durable state.

Only numeric loopback HTTP endpoints are enabled. The listener sees the method,
path, body and results, and all group members may access every record. This is
not a per-user ownership policy, network anonymity, proof of honest server
execution, or authenticated remote deployment. Those are separate requirements.

## Retained FHE input-proof prototype

This optional v1 lookup is retained independently. Expanded encrypted CRUD is
deferred on local development branch `feat/encrypted-crud` at `c7d9cb9`; it is
not merged into this authorization-listener branch.

### Setup and pinned context

The isolated Rust workspace `private-request/` produces `zkweb-private`. The Go
CLI invokes that fixed sibling backend for `private-setup`, `private-serve` and
`private-query`. Ordinary `make build` and private command help do not need
TFHE-rs; `make build-private` and `make test-private` build and exercise the
optional backend. The crate pins TFHE-rs 1.8.2 and its registry checksum, using
full upstream parameter sets with no toy reduction.

An offline provisioner generates a `ClientKey`, compact public key, evaluation
`ServerKey` and CRS. The client profile contains the secret decryption key;
the server profile contains only public/evaluation material. Only that server
profile should be transferred to a destination operator. A profile hash pins
the configuration, CRS and registered keys. The provisioner sees the secret
during setup and must be trusted; the hashes do not prove honest key or CRS
generation. There is no production setup ceremony.

Both processes on one machine demonstrate protocol messages, not an operating
system isolation boundary. A common administrator can read client files or
memory. Separate hosts and a trusted client are required for an actual
operator boundary. Upstream side-channel limitations remain outside this
prototype's guarantees.

### Proof relation and acceptance

The public statement consists of the registered compact public key, CRS,
compact ciphertext and proof metadata. The witness contains the selector
`index` and encryption randomness. The relation is correct TFHE compact public
key encryption, including its required bounds, of `index ∈ {0, 1, 2, 3}`. The
two-bit encrypted type establishes that exact range. The application also
requires a one-element `FheUint2` list; an empty list or different type is not a
request for this function.

The HTTP flow uses two public endpoints:

1. `GET /challenge` returns the protocol, pinned profile, server instance,
   fresh challenge identifier and expiry. The client validates the context.
2. The client encrypts and proves its selector, binding metadata to the
   protocol, fixed lookup function, profile, server instance, challenge and
   expiry. The context uses a domain separator and unambiguous field encoding.
3. `POST /query` sends only the challenge identifier and base64-encoded proven
   ciphertext. The server checks the challenge, size limits, safe conformant
   deserialization, list length/type and ZK proof before expanding the selector
   or performing FHE evaluation.
4. The server uses `MatchValues` to select the encrypted `FheUint8` result. It
   has no `ClientKey` and never decrypts the index or result. Every successful
   selection uses the same response structure and ciphertext type.
5. The client checks the response context and ciphertext conformance, decrypts
   locally and prints the index/value only to its local output.

Challenges expire after 120 seconds, the outstanding challenge store is bounded,
and every decoded query consumes its recognized challenge before expensive verification,
including failed proofs. A fresh instance identifier on
restart prevents proofs for the old process from becoming valid in a new
store. This constrains replay at the accepting server; it does not establish
exactly-once execution or prevent a malicious server from returning arbitrary
or stale ciphertexts. Result conformance is not a proof of correct evaluation.

Only numeric loopback HTTP addresses are enabled. The destination sees the
endpoint, method, fixed operation, public table, IP, timing, sizes and
profile/session context. Reused profiles may link sessions. The private fact is
which table entry was selected. The client sends no callback based on the
decrypted result; future applications must avoid turning their observable
reactions into a decryption oracle.

## Separate ordinary HTTP transport flow

1. A client submits a request and explicit context over a local interface. The
   context scopes destinations, credentials, budgets and any retained session
   state. The current CLI is the initial interface; a local daemon API is future
   work.
2. The engine validates the request, target policy and resource budget. It
   preserves HTTP semantics. Optional application-specific transformations must
   not silently rewrite arbitrary URLs, JSON, binary data or authentication.
3. A caller selects a transport whose documented threat model and latency fit
   the task. Covered asynchronous delivery and interactive streaming have
   different scheduling requirements; neither inherits the other's guarantees.
4. A worker or egress endpoint reaches the configured destination. An optional
   access/payment adapter may authorize service independently of request
   contents; that adapter must not give relays custody of a wallet.
5. Responses return through the selected transport with bounded resource use and
   explicit completion or unknown-delivery semantics. Optional selective
   verification is a separate protocol step, with its own trust assumptions.
6. Applications consume the response. A research application may retain a local
   objective, minimize questions, restore local context and verify citations; an
   API client may need exact bytes and session continuity instead.

This flow describes ordinary HTTP transport and its broader design target.
The destination processes plaintext application inputs in these modes. It is
separate from the fixed encrypted lookup above; adding Tor, an eligibility
proof or a response attestation does not turn it into private computation.

## Local client-to-origin TLS mode

`fetch` uses an origin-scoped `webclient.Client` and explicit loopback SOCKS
route. HTTP executes locally and TLS terminates at that client and the origin;
there is no application worker receiving the plaintext body or credentials.
Destination names use SOCKS domain addressing, so no local destination DNS query
is made. The client blocks private literals and known local names statically;
the trusted proxy must enforce egress policy on remotely resolved addresses.

Tor mode uses modern SOCKS authentication: username `<torS0X>0` and a fresh
64-hex-character password for each client context, retained across its dials.
It requires the Tor port's `IsolateSOCKSAuth` behavior. The client cannot verify
the proxy implementation/configuration or promise different exits. Plain
`socks5://` mode provides no Tor authentication isolation.
[Tor SOCKS extensions](https://spec.torproject.org/socks-extensions.html).

Both body limits default to 1 MiB and support 1 byte–16 MiB; request paths are
bounded to 8 KiB and headers to 64 KiB. The deadline defaults to 45 seconds and
supports 1 second–10 minutes. No ambient proxy, cookie jar or authentication is
inherited. Fresh connections, no redirects and no replayable request-body
support prevent automatic HTTP retries. Failures after handing a request to
the transport report `delivery_unknown`; incomplete bodies are not returned as
complete responses.

The configured proxy must already be running; the client does not start or
attest Tor. This route has no Sphinx cover or ZK proof and currently supports
bounded HTTPS HTTP/1.1 exchanges, not WebSockets, HTTP/3 or browser interception.
Operators can observe hostnames/timing, and origins see request/account data.
See the [local HTTPS client guide](../docs/local-https-client.md).

## Optional offline response verification

`zkweb verify` accepts a previously produced TLSNotary alpha.15 JSON presentation
and an independent policy: the expected server, a trusted notary's compressed
K256 public key and an explicit inclusive time window. The Go CLI bounds its
input and invokes only the fixed sibling `zkweb-tlsn-verify` executable. The
optional Rust backend rechecks policy and uses the upstream attestation/core
verifier pinned to commit `47aee45b53e06648c1b2ad3689b367b8c923fdec`.

Success returns metadata by default. Explicit, sorted ranges may return only
fully authenticated transcript bytes, with at most 64 ranges per direction and
1 MiB combined output. Full transcript lengths are capped at 1 MiB per direction
before upstream deserialization; presentation JSON is capped at 16 MiB. A range
through a hidden gap fails rather than producing substitute plaintext. Range
selection controls the result, not disclosures already present in the input
artifact.

This is experimental TLSNotary attestation verification relative to the chosen
notary, not a SNARK execution proof. It performs no network request and does not
parse an HTTP status/body, verify a JSON predicate, bind an artifact to a
separate `fetch` result or caller challenge, or establish exactly-once mutation
execution. Proof capture/generation and application-specific complete-message
and freshness/replay rules remain separate work. It supplies no anonymity or
access/payment admission.

`make build` remains Go-only. `make build-proof` builds the isolated Rust
workspace and installs its release binary beside the client. `make test-proof`
runs ten Rust cryptographic tests and the Go integration tests against that
binary; ordinary `make test` skips the actual-backend integration unless
`ZKWEB_TLSN_BACKEND` is set. The compatibility fixture's notary private key is
public test material and its HTTP content is synthetic, so a passing fixture is
not an authenticated receipt from a real website. See the
[verification guide](../docs/response-verification.md) for the format, policy
and test provenance.

## Opt-in HTTP adapter experiment

`request` admits one strict JSON envelope containing an HTTP method, relative
path, optional headers and a UTF-8 body string. A command-line target fixes the
allowed public HTTPS origin before the epoch begins. Inputs are validated before
transport starts and revalidated at the worker. The encrypted forward envelope
includes a one-use SURB, and the actual serialized request must fit one cell.

The existing fixed schedules carry work in place of cover through three local
forward mixes to the worker. Bounded worker execution makes one HTTPS request
to the configured origin. A bounded UTF-8 status/header/body envelope returns
through three local reverse mixes to the client using its SURB. The epoch
continues after completion; the CLI prints the response only when it ends.
`demo` and `compare` continue to execute synthetic work without Internet egress.

The HTTP adapter rejects local/private targets, URL credentials and redirects.
It does not inherit environment proxies, cookies or caller process credentials.
Request credentials are accepted only as explicit envelope headers and are
visible to the worker and target. Target behavior can still expose intent or
account identity. The worker's HTTPS connection is direct, and all mix nodes
remain on one machine under one operator.

No layer automatically retries a request. Losing a reply after a mutation leaves
its outcome unknown, so epoch exhaustion reports `delivery_unknown`; it does
not imply that the operation failed. Large/binary responses, fragmentation,
streaming, application-level idempotency and recovery are outside this adapter.
It has no payment authorization, wallet custody or zkAPI lease integration.

## Decisions made for the prototype

| Decision | Reason and limitation |
| --- | --- |
| Distinct Groth16 membership authorization circuit | Bind an authorized secret and private path to the exact request digest with a fresh privately blinded tag. All public digest limbs are constrained; this is not the wallet's payment circuit. |
| Separate verifier and member profiles | Give the listener only verification material while clients keep credential witnesses. A trusted offline provisioner can impersonate members; hash pins are not an honest-setup proof. |
| Retain the separate TFHE input-proof lookup | Preserve earlier work while FHE is deferred. The two-bit selector hides one of four choices; this proves neither authorization nor server output correctness. |
| FHE offline pinned client/server profiles | Keep the client decryption secret out of destination material and bind verification to configured keys/CRS. Honest provisioning is assumed; the example is not a ceremony or host sandbox. |
| Fresh instance and expiring one-use challenges | Bind proofs to one server context and constrain request replay. Does not provide general response freshness, exactly-once writes or verifiable evaluation. |
| Use Katzenpost Sphinx/SURBs | Reuse packet cryptography rather than invent an onion format; does not reuse a complete deployed mixnet or inherit its anonymity analysis. |
| Independent forward and reverse schedules | A variable or direct response stream would expose job completion patterns. |
| Fixed cell bodies, random padding | Prevent application body length from directly encoding the task; HTTP/TCP and packet counts remain visible. |
| Fixed epoch, bounded pools, no catch-up | Jobs do not create extra scheduled slots; overload reduces availability instead of increasing rate. |
| Random eligible selection with residence delay | Introduces reordering; the static single-host comparison cannot establish anonymity. |
| Replay cache without eviction in a key epoch | Reject repeated packets; capacity exhaustion stops admissions. Production needs authenticated epochs, freshness and restart-safe replay handling. |
| Synthetic `demo`/`compare` worker | Exercise the lab without leaking prompts or issuing paid calls; real HTTP work uses the separate opt-in `request` or `fetch` command with its documented route. |
| Optional pinned TLSNotary verifier | Reuse upstream attestation verification for offline artifacts while keeping Rust proof dependencies out of ordinary Go builds; caller-selected notary trust remains necessary, and no capture or HTTP claim is implied. |

## What a transport adversary still sees

In the transport lab, the operator can inspect every key and node. A network observer can see
endpoints, connection establishment, the chosen rate, session start/end, loss and
OS scheduling effects. The worker sees its plaintext task. A research target can
infer intent from rare facts, document identifiers or repeated questions even
after names are removed. An active attacker can drop traffic or exhaust bounded
capacity. The lab has no admission, Sybil-resistance or multi-operator trust model.

Continuous cover must be shared by a real population and a reviewed topology.
Just adding more dummy requests, or adding this scheduler around a single Tor
circuit, does not establish resistance to an actively colluding provider/guard.
Long-term intersection and confirmation attacks need evaluation too.

## Milestones with evidence required

| Stage | Deliverable | Evidence before advancing |
| --- | --- | --- |
| 0: ZK listener loop | Client membership proof → challenge-bound listener verification → durable CRUD | Real Groth16 proofs; all CRUD methods; unauthorized, tampered, replayed and wrong-context requests rejected before application execution; binary values and mutation recovery. |
| 1: credential lifecycle | Reviewed enrollment, group updates and member-secret handling | Explicit revocation/rotation, pinned setup/profile distribution, issuer trust and independent credential generation where required. |
| 2: remote deployment | Authenticated transport and reviewed operating boundary | Separate-host tests, resource/admission controls, clear IP/timing/profile leakage and trusted profile distribution; loopback is not this evidence. |
| 3: application policy and integrity | Required ownership scopes and response/state guarantees | Define which authorized member may affect which data, concurrent mutation semantics, lost-reply reconciliation and malicious-server behavior. Input authorization alone is not an execution proof. |
| 4: resume FHE | Cooperating encrypted reads/writes layered with the required authorization | Revisit the separate encrypted-CRUD work, its exact input proof, operation/access leakage, key/CRS trust, state consistency and measured cost. |
| 5: reviewed release | Reproducible packages and independently reviewed proof/setup/deployment boundaries | Dependency pins, setup review, lifecycle/recovery tests and an explicit adversary model. Funded-wallet integration retains its separate release gates. |

This branch closes the authorization loop first. The optional FHE lookup has a
different statement and acceptance entry point (`make test-private`). Neither
source presence nor local tests establish a production security review.

### Separate transport and verification work

The existing process-isolated, synthetic 16-client comparison covers clean,
provider-delay, worker-ingress-loss and client-disconnect scenarios. It measures
two timestamp heuristics, completion, completed-job latency and TCP stream bytes,
not independent operators or a comprehensive active attacker. The complete
Katzenpost reference remains blocked by its private-key file requirements; see
[assessment](REFERENCE.md). Independent-host evaluation, authenticated links and
directory, key rotation and restart-safe replay remain transport work.

`fetch` supplies a TLS-preserving proxy route, bounded binary bodies and
per-client Tor isolation. Covered fragmentation, persistent session/daemon
APIs, streaming and WebSocket/browser integration require separate designs.
The offline TLSNotary adapter checks existing artifacts; capture, HTTP claims,
request binding and anonymous admission remain separate. None of these
milestones substitutes for destination-side encrypted computation.

The [first process comparison](evidence/process-comparison/report.md) found an
unfinished clean job and queued cover/work at epoch end. The remaining transport
work includes evaluating fixed capacity headroom and return-cover routing, then a
bounded recovery protocol that uses predetermined slots. Low scores for two
timestamp heuristics do not justify bypassing that work or the complete transport
reference assessment.

There is no production private-computation, anonymity or funded-service release
claim in this branch. The privacy features are independent from changing a vault
address: existing notes always require their original compatible stack.

## Positioning

The product direction is useful encrypted requests processed by cooperating
destinations. General web scope means extending the set of supported private
functions and backend integrations, with explicit statements about what stays
public. It does not imply that a universal client can make an unchanged website
compute on inputs that website cannot read.

FHE, PIR, MPC, ZK proofs, mixnets and anonymous credentials are established
techniques with different guarantees. Reuse existing implementations and assess
the complete protocol against its stated attacker. Existing transport and
verification tools remain useful on their own terms. The scope change does not
alter legacy vault compatibility: existing notes require their original
protocol, deployment and proving artifacts.
