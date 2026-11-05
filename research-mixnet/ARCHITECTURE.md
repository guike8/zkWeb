# zkWeb: architecture and milestones

zkWeb's primary goal is to let a cooperating web destination process a request
without learning its private input. The current prototype combines TFHE-rs
fully homomorphic encryption with a mandatory zero-knowledge proof of correct
input encryption. The destination verifies the proof before computing over an
encrypted selector and returns an encrypted result for local decryption.

The implemented function is a read from the public table `[11, 22, 33, 44]` with
a hidden index in `0..3`. This fixed function is the first complete private
request, not generic encrypted CRUD or compatibility with unchanged websites.
Useful private reads and writes require destination logic and state protocols
designed for encrypted computation. See the
[private-request guide](../docs/private-requests.md) for commands and trust
boundaries.

The existing Tor/SOCKS5 HTTPS client, local Sphinx/SURB experiment and offline
TLSNotary verifier remain separate tools. Transport privacy does not conceal a
plaintext HTTP payload from the destination, and transcript attestation does
not make its source execute an encrypted request. The
[implementation research](../docs/web-request-research.md) compares these roles.

## Separate responsibilities

| Part | Intended responsibility | Current status |
| --- | --- | --- |
| Private computation | Keep private inputs encrypted during destination processing and return an encrypted result. | `private-query` proves encryption of a two-bit selector; `private-serve` verifies it and evaluates a four-record lookup using TFHE-rs. Loopback HTTP only; no proof of correct server evaluation. |
| Proof admission and profiles | Accept only conformant, verified encrypted inputs under registered keys, parameters and request context. | Offline setup separates client secret from server evaluation material; profile hashes pin configuration/CRS/keys. Expiring one-use challenges bind proofs to a fresh server instance. Honest provisioning/CRS generation is assumed. |
| General HTTP interface | Preserve HTTP method, origin/path/query, allowed headers, body, status and response data when the destination processes ordinary HTTP. | Seven methods and a pinned HTTPS origin; `fetch` preserves bounded binary bytes, while `request` supports small UTF-8 bodies and one request per fixed epoch. Destinations receive plaintext application inputs. |
| Transport | Hide client/request linkage under an explicit adversary model, with mode-specific latency and bandwidth tradeoffs. | `fetch` uses an explicit loopback Tor/SOCKS5 route with client-to-origin TLS and no direct fallback; `request` uses scheduled loopback Sphinx links with cover. Neither is an independently evaluated anonymity service operated by this project. |
| Session and credential controls | Scope credentials, cookies, destinations and retained state to a caller-selected context. | Origin-scoped reusable client with per-client Tor isolation state, explicit headers and no ambient cookie jar or environment proxy; persistent session/daemon APIs remain future work. |
| Anonymous access or payment | Prove eligibility or spending authority without exposing unnecessary identity. | Inherited zkAPI wallet/proof components exist separately; the HTTP worker has no access-proof or billing integration. |
| Optional response verification | Authenticate selected web transcript data with a defined verifier and trust model, then support explicit application claims. | Partially implemented: optional `zkweb verify` checks existing TLSNotary alpha.15 presentations offline against caller-pinned notary/server/time policy and returns selected authenticated byte ranges. Capture, HTTP claims and request/challenge binding remain future work. |
| Applications | Offer useful private functions and client interfaces above the relevant protocol. | Private lookup CLI plus separate `fetch`, `request`, verification and transport tools; general encrypted state updates and browser integration remain future work. |

FHE supplies confidentiality for the selector and result. The ZK input proof
enforces a relation about correct encryption; it supplies neither account
authorization nor proof of the server's output. Anonymous eligibility and
payment proofs are different statements. Each mode must state which property
it actually supplies.

## Private request protocol

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
| ZK-proven TFHE compact encryption and FHE lookup | Reuse an existing library for private input processing and mandatory proof admission. The two-bit selector hides one of four choices; this proves neither authorization nor server output correctness. |
| Offline pinned client/server profiles | Keep the client decryption secret out of destination material and bind proof verification to configured keys/CRS. Honest provisioning and CRS generation are assumed; the demo is not a ceremony or host sandbox. |
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
| 0: complete private read | Current four-record lookup with ZK-verified encrypted input, HTTP acceptance, FHE evaluation and local result decryption | Real cryptographic checks and HTTP round trips for all selectors; reject tampered/wrong-context proofs, empty or wrong-type lists, malformed objects, expired/replayed challenges and incompatible profiles before evaluation. Measure setup/proving/evaluation cost without weakening parameters. |
| 1: independent operator boundary | Reviewed provisioning, profile/key registration, authenticated remote deployment and client secret handling | Separate-host runs with destination material containing no client secret; explicit CRS/key trust and rotation model, resource/DoS limits, session linkage and metadata measurements. Loopback integration is not this evidence. |
| 2: useful private reads and result integrity | Larger/private query functions plus a selected integrity design for malicious destinations | Specify the public/private inputs and precise proof relation per function. Evaluate output-correctness proofs or authenticated retrieval against the required trust model; demonstrate detection of wrong or stale results rather than relying on input proof verification. |
| 3: encrypted state and CRUD | Cooperating-server create/update/delete protocols with encrypted inputs and explicit public leakage | Define state consistency, authorization, access-pattern leakage, concurrency, replay, idempotency, exactly-once limits and recovery. Prove the required input relations and validate state transitions; no automatic retry of ambiguous mutations. |
| 4: usable private service interfaces | Local client API and selected transport integration for supported encrypted functions | Separate concurrent callers and keys, preserve client secrets, bound resources and cancellation, and assess what IP/timing/session identifiers disclose. Transport anonymity and payment admission require independent evidence. |
| 5: broader service adaptation | Reusable encrypted functions and integration patterns for additional cooperating backends | Establish per-function semantics, computation cost and privacy/correctness guarantees. Ordinary unmodified websites remain outside this capability unless their protocol changes. |
| 6: reviewed release | Reproducible optional backend packages and reviewed cryptographic, setup and deployment boundaries | Independent review, dependency/parameter pins, side-channel assessment and lifecycle/recovery tests. Compatible zkAPI funding is separate and requires its own ceremony/deployment/proof compatibility; no development setup substitution. |

The current private-read implementation is intentionally small enough to state
its exact relation and leakage. `make test-private` is the acceptance entry
point for its cryptography and real HTTP path. The protocol is experimental;
no production security review, remote deployment or benchmark is implied by
the code being present.

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
