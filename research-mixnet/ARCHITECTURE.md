# zkWeb: architecture and milestones

zkWeb is the working name for a general web request privacy toolkit. The request
engine is the product foundation: API CRUD, web fetching, private application
egress and AI/research workflows use the same method, destination, headers,
body and response interface. Supporting the breadth of web requests is the
direction, rather than a claim of universal compatibility today.

The current implementation has a local HTTPS client over an explicit Tor/SOCKS5
route, alongside the local Sphinx/SURB experiment with a bounded HTTPS worker.
The local client supports bounded binary bodies. An optional offline verifier
checks existing TLSNotary presentations; it is separate from both HTTP modes.
Covered fragmentation, streaming, persistent browser sessions, proof capture
and application-specific proof binding remain design work. The
[implementation research](../docs/web-request-research.md) compares existing
systems and their trust boundaries.

## Separate responsibilities

| Part | Intended responsibility | Current status |
| --- | --- | --- |
| Request interface | Preserve HTTP method, origin/path/query, allowed headers, body, status and response data. | Seven methods and a pinned HTTPS origin; `fetch` preserves bounded binary bytes, while `request` supports small UTF-8 bodies and one request per fixed epoch. |
| Transport | Hide client/request linkage under an explicit adversary model, with mode-specific latency and bandwidth tradeoffs. | `fetch` uses an explicit loopback Tor/SOCKS5 route with client-to-origin TLS and no direct fallback; `request` uses scheduled loopback Sphinx links with cover. Neither is an independently evaluated anonymity service operated by this project. |
| Session and credential controls | Scope credentials, cookies, destinations and retained state to a caller-selected context. | Origin-scoped reusable client with per-client Tor isolation state, explicit headers and no ambient cookie jar or environment proxy; persistent session/daemon APIs remain future work. |
| Anonymous access or payment | Prove eligibility or spending authority without exposing unnecessary identity. | Inherited zkAPI wallet/proof components exist separately; the HTTP worker has no access-proof or billing integration. |
| Optional response verification | Authenticate selected web transcript data with a defined verifier and trust model, then support explicit application claims. | Partially implemented: optional `zkweb verify` checks existing TLSNotary alpha.15 presentations offline against caller-pinned notary/server/time policy and returns selected authenticated byte ranges. Capture, HTTP claims and request/challenge binding remain future work. |
| Applications | Offer browser/tool interfaces, private research and other workflows above the request engine. | CLI `fetch` and `request` modes plus synthetic transport experiments; browser integration and research planning remain future work. |

A zero-knowledge eligibility proof does not hide authenticated account identity
from an API, and a proof about selected response data does not itself anonymize
the request. Sphinx encryption supplies neither of those proofs. The engine must
state which property a selected mode provides rather than labeling all web
traffic as zero knowledge.

## Intended general request flow

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

This flow is a design target. The local HTTPS client and bounded loopback request
exchange below implement its initial request paths. Offline artifact verification
implements a separate first proof step. The previous headless
research-daemon concept is an application on top of this engine, not a restriction
on general request operations.

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
| Use Katzenpost Sphinx/SURBs | Reuse packet cryptography rather than invent an onion format; does not reuse a complete deployed mixnet or inherit its anonymity analysis. |
| Independent forward and reverse schedules | A variable or direct response stream would expose job completion patterns. |
| Fixed cell bodies, random padding | Prevent application body length from directly encoding the task; HTTP/TCP and packet counts remain visible. |
| Fixed epoch, bounded pools, no catch-up | Jobs do not create extra scheduled slots; overload reduces availability instead of increasing rate. |
| Random eligible selection with residence delay | Introduces reordering; the static single-host comparison cannot establish anonymity. |
| Replay cache without eviction in a key epoch | Reject repeated packets; capacity exhaustion stops admissions. Production needs authenticated epochs, freshness and restart-safe replay handling. |
| Synthetic `demo`/`compare` worker | Exercise the lab without leaking prompts or issuing paid calls; real HTTP work uses the separate opt-in `request` or `fetch` command with its documented route. |
| Optional pinned TLSNotary verifier | Reuse upstream attestation verification for offline artifacts while keeping Rust proof dependencies out of ordinary Go builds; caller-selected notary trust remains necessary, and no capture or HTTP claim is implied. |

## What an adversary still sees

The lab operator can inspect every key and node. A network observer can see
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
| 0: local transport | Current headless loopback lab | Fixed sizes, idle traffic in both directions, real SURB replies, replay rejection, queue bounds, no catch-up, cancellation; race tests and captured aggregate demo results. |
| 1: network experiment | Separate relay processes and independently operated hosts; authenticated links and directory | Test operator compromise, active timing perturbation, drops, flooding, route churn, replay across restart, key rotation and population size. Prefer using the complete Katzenpost/Nym transport stack where possible. |
| 2: general bounded HTTP protocol | Large/binary request and response framing, expiring reply capabilities, bounded reassembly and explicit completion | Exact-byte HTTP fixtures; malformed/reordered/duplicate fragment tests; resource caps, cancellation, replay and lost epochs. Mutation outcomes remain unknown without a reply; no automatic retry of ambiguous writes. |
| 3: contexts and useful request alpha | A local request API with scoped credentials, sessions, target capabilities and transport selection | Separate concurrent callers and accounts; prevent cookie/auth cross-context leakage; test CRUD, document fetches, SSRF/DNS policies and redirect policy. Measure cost/latency without claiming all-site compatibility. |
| 4: extended web semantics | Reviewed streaming, WebSocket/CONNECT and browser integration designs where justified by transport choice | Long-lived cancellation/backpressure tests, bounded buffers, replay and recovery analysis, and mode-specific metadata/timing measurements. Do not apply asynchronous cover claims to interactive modes without evidence. |
| 5: optional proof adapters | Extend offline TLSNotary verification with proof capture, application claims and request/challenge binding; separately integrate anonymous access/payment where selected | Offline verification already checks upstream cryptography and caller-selected policy. Capture and application claims need complete-message parsing, explicit trust/freshness/replay statements and independent review tests. Anonymous admission remains separate from the generic HTTP path. |
| 6: release and optional funded integration | Reviewed transport deployment and reproducible packages; compatible zkAPI stack only when that payment adapter is selected | Independent-host adversary evaluation and release recovery tests; for zkAPI funding, ceremony/code/proof pins, exact-release deposit/request/settlement/exit tests and conservative spend caps. No development setup substitution. |

Stage 1 now has a process-isolated, synthetic 16-client comparison with clean,
provider-delay, worker-ingress-loss and client-disconnect scenarios. It measures
two timestamp heuristics, completion, completed-job latency and TCP stream bytes.
It has no independent hosts, authenticated directory/links or comprehensive active
attacker. The complete Katzenpost reference remains blocked by its private-key
file requirements; see [assessment](REFERENCE.md). The first part of stage 1 is
implemented; independent-host evaluation remains open. `fetch` now supplies a
TLS-preserving proxy route, bounded binary bodies and per-client Tor isolation,
which are initial pieces of stages 2 and 3. Covered fragmentation, persistent
session/daemon APIs and release work remain open. Stage 5 has an initial offline
TLSNotary verification adapter with cryptographic tamper and policy tests;
proof capture, application claims, request/challenge binding and anonymous
admission remain open.

The [first process comparison](evidence/process-comparison/report.md) found an
unfinished clean job and queued cover/work at epoch end. The immediate transport
priority is to evaluate fixed capacity headroom and return-cover routing, then a
bounded recovery protocol that uses predetermined slots. Low scores for two
timestamp heuristics do not justify bypassing that work or the complete transport
reference assessment.

There is no production anonymity or funded-service release
claim in this branch. The privacy features are independent from changing a vault
address: existing notes always require their original compatible stack.

## Positioning

The product opportunity is a usable request engine with explicit transport,
credential and verification boundaries across ordinary web workloads. Research
and AI applications can add local intent minimization and task-specific content
controls above it. Such transformations must preserve their task's semantics;
a universal rewrite is unsuitable for arbitrary HTTP bodies.

Mixnets, private proxies, anonymous credentials, web-data proofs and redaction
are established prior art. Reuse reviewed implementations where their trust
model fits, evaluate complete requests against explicit attackers, and do not
market the composition as a new cryptographic guarantee. The broader scope
does not change legacy vault compatibility: existing notes require their
original protocol, deployment and proving artifacts.
