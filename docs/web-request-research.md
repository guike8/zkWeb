# zkWeb: general private and verifiable web requests

Research date: **2026-11-05**. zkWeb is the working product name for this fork.
This brief compares original specifications, project documentation and source
repositories. It is an implementation shortlist, not an independent audit or
an exhaustive survey. Research used OpenCLI searches and original-page reads.

## Product decision

Broaden the product from an AI/research API wrapper to a **general web request
privacy toolkit**. API CRUD, document fetching, application egress and agent
tools share a request engine. AI inference and private research are applications
above that engine.

The compatibility goal is broad HTTP(S) support: methods, destinations, paths,
queries, explicit headers, exact request/response bytes, session contexts and,
where the selected transport permits it, streams and WebSockets. This is a goal,
not a claim that the current prototype supports all websites or web protocols.

Use the product description **private and verifiable web requests**. Describe
which privacy and verification properties each mode actually provides. An
ordinary destination still receives the request content and credentials needed
to serve it; these technologies do not turn arbitrary existing websites into
servers that execute hidden requests.

## Three separate properties

| Property | Mechanism to evaluate | Boundary |
| --- | --- | --- |
| Hide network linkage between a client and request | Tor, a deployed mixnet, or an appropriately separated oblivious relay/gateway | Does not remove identifiers in accounts, cookies, headers, bodies or request timing. |
| Prove permission, membership or spending authority without unnecessary identity disclosure | Anonymous credentials, Privacy Pass, or a compatible zkAPI payment adapter | The admitting service must support the chosen protocol. It does not replace arbitrary website logins. |
| Prove selected facts about authenticated web data | TLSNotary, Reclaim, zkPass or a related zkTLS/notary construction | Has a specific prover/verifier/notary trust model and disclosure statement. It does not itself anonymize transport. |

Privacy Pass explicitly treats token issuance/redemption privacy separately from
IP addresses and other identifying request context. TLSNotary documents
selective transcript verification rather than an anonymous web proxy.
[Privacy Pass architecture](https://www.rfc-editor.org/rfc/rfc9576.html),
[TLSNotary introduction](https://tlsnotary.org/docs/intro/).

## Current implementations

| Implementation | What is available | Fit for zkWeb and material limits |
| --- | --- | --- |
| **Nym** | Developer documentation updated November 3, 2026 lists native TCP/UDP APIs, SOCKS5, Go/C FFI, browser `mix-fetch`, `mix-websocket` and DNS support. The network separately uses anonymous `zk-nym` credentials for bandwidth. | Closest existing feature set to the proposed transport-plus-anonymous-access direction. Evaluate its SDK or SOCKS integration rather than build another relay network. Ordinary account identity remains visible to the destination. [SDK matrix](https://nym.com/docs/developers), [network architecture](https://nym.com/docs/network). |
| **Tor / Arti** | The official FAQ, with a January 2026 readiness statement, supports using Arti as a proxy or embedded Rust client. Client anticensorship and onion-service support are documented; relay operation is not supported by Arti. | Practical initial candidate for general HTTPS TCP traffic with TLS terminating at the client and destination. This is onion routing, not a ZK proof or a continuously covered mixnet. [Arti FAQ](https://arti.torproject.org/FAQs/). |
| **Katzenpost** | Full mixnet daemon/server/directory software and Go/Rust/Python thin-client integration, beyond the Sphinx packet primitive. | Strong asynchronous-transport research candidate. Documentation does not establish a universal browser/HTTP proxy. Using its Sphinx library locally does not inherit the deployed system's operational guarantees. [Integration documentation](https://katzenpost.network/docs/). |
| **Oblivious HTTP / Cloudflare** | OHTTP is standardized in RFC 9458. Cloudflare's October 2, 2026 managed gateway announcement describes a closed beta, including chunked OHTTP support, restricted to the customer's zone/subdomains. | Optional route for configured cooperating APIs. Separate relay/gateway operators split source-IP and plaintext visibility. The gateway decrypts the request; this is not client-to-arbitrary-origin TLS or ZK. The managed gateway is not a general Internet forward proxy. [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458), [current gateway announcement](https://blog.cloudflare.com/announcing-cloudflare-ohttp-gateway/). |
| **MASQUE / quic-go** | `quic-go/masque-go` implements CONNECT-UDP client and proxy behavior under RFC 9298; v0.6.0 was released September 22, 2026. CONNECT-IP is a separate standard. | Potential later UDP/HTTP/3 capability. A tunnel through one proxy is not automatically anonymous or zero knowledge. Do not describe this CONNECT-UDP library as a CONNECT-IP implementation. [Library](https://github.com/quic-go/masque-go), [CONNECT-IP RFC 9484](https://www.rfc-editor.org/rfc/rfc9484.html). |
| **Privacy Pass / Cloudflare TypeScript** | Standardized anonymous authorization architecture; the TypeScript library implements blind-RSA, VOPRF and issuance variants. | Candidate for unlinkable gateway admission or credits. Requires the origin/gateway to accept the issuer and token protocol. Does not encrypt HTTP content or substitute for network privacy. [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html), [implementation](https://github.com/cloudflare/privacypass-ts). |
| **TLSNotary / TLSN** | Rust MPC-TLS and an alternative proxy mode provide selectively disclosed transcript verification. Current docs specify TLS 1.2, with TLS 1.3 on the roadmap. The repository warns against production use. | Transparent baseline for an optional response-proof adapter, evaluated on a pinned release. A portable attestation depends on its notary/verifier assumptions; proxy mode also has a network-path assumption. It is not a universal anonymous request client. [Introduction](https://tlsnotary.org/docs/intro/), [source and readiness warning](https://github.com/tlsnotary/tlsn), [proxy protocol](https://tlsnotary.org/docs/protocol/proxy-mode). |
| **Reclaim Protocol** | `attestor-core` supplies an actual HTTP claim provider with URL, method, headers, body, secret parameters and extraction rules. Current hosted documentation describes both ZK and TEEs. | Directly relevant request/claim interface to compare with TLSN. Redaction, provider rules and attestor trust are part of the model. The provider forces connection closure and identity content encoding; it is not unrestricted browsing. Evaluate the self-hosted library separately from the hosted product. [Source](https://github.com/reclaimprotocol/attestor-core), [HTTP provider](https://github.com/reclaimprotocol/attestor-core/blob/main/docs/provider.md), [current product docs](https://docs.reclaimprotocol.org/). |
| **zkPass** | TransGate client, JS SDK and validator infrastructure use schemas to select web responses and produce verified claims. | Useful comparison for proof UX and provider schemas. The ordinary source site still handles the user's login/request. Its broad website-compatibility claim is not evidence of a headless universal HTTP tunnel. [SDK](https://docs.zkpass.org/developer-guides/js-sdk), [documented flow](https://docs.zkpass.org/developer-guides/js-sdk/how-it-works). |
| **DECO** | Foundational web-data provenance/predicate protocol; Chainlink announced a public Sandbox on October 30, 2024. | Architectural prior art. The paper and dated Sandbox announcement do not establish a current general-purpose production HTTP dependency. [Original paper](https://arxiv.org/abs/1909.00938), [Sandbox announcement](https://chain.link/blog/deco-sandbox). |

Nym's documented limitations matter: its mixnet mode is unsuitable for sustained
video/voice, large downloads and tight interactive latency. Its separate bulk
path uses a different transport and does not retain mixnet timing protection.
The documentation also identifies long-flow correlation and application
identifiers as open or remaining privacy issues. This is why zkWeb needs explicit
transport modes rather than one guarantee attached to every kind of request.
[Nym limitations](https://nym.com/docs/developers/limitations).

Apple's Private Cloud Compute provides an existing composition precedent:
chunked OHTTP with third-party relays, plus unlinkable blind-signature Privacy
Pass tokens for authorization. This demonstrates separation of routing and
authorization in a specific service; it does not establish universal website
compatibility. [Apple anonymous routing](https://security.apple.com/documentation/private-cloud-compute/requestflow).

Do not choose an OHTTP library solely because a current product announcement
links to it. Cloudflare's sample client still describes demonstration code and
an older draft. Protocol version, interoperability and maintenance must be
checked for the exact library adopted.
[Sample client](https://github.com/cloudflare/privacy-gateway-client-library).

## Recommended architecture

The following is our engineering inference from these sources, not a measured
result or a claim that any one dependency has been independently audited here.

1. **Keep HTTP semantics in a general local client.** Define a byte-preserving
   request interface and explicit context for origin permissions, credentials,
   cookies, budgets, deadlines and response limits. Applications must choose
   their state scope; do not infer it from chat history or rewrite arbitrary
   bodies as prose.
2. **Separate the network stream from HTTP execution.** For a general transport
   mode, prefer a stream route that lets TLS terminate locally and at the real
   destination. This avoids giving an application-layer worker the request's
   plaintext credentials. Prototype Tor/Arti first and evaluate Nym's maintained
   native/SOCKS interfaces for traffic that can tolerate mixnet costs. Verify the
   exact TLS termination and DNS behavior of each chosen integration.
3. **Keep delegated HTTPS work explicit.** The current worker mode is useful for
   bounded asynchronous tasks, but the worker receives the HTTP request and
   credentials. Treat OHTTP as another specifically configured gateway mode,
   with documented gateway visibility and non-collusion assumptions.
4. **Make anonymous authorization an independent adapter.** Compare Privacy Pass
   gateway tokens with Nym bandwidth credentials and inherited zkAPI funding.
   Define the actual statement, audience, spend/replay protection and metadata
   leakage. Supporting one does not imply support for the others.
5. **Make response proofs opt-in.** Evaluate TLSN and Reclaim against the same
   fixtures before choosing a dependency. Bind the disclosed fact to the origin,
   request/context, freshness and verifier's intended statement. Proving a
   response predicate is not proof that an arbitrary side effect executed
   exactly once.
6. **Publish capabilities by mode.** Report supported protocols and body limits,
   TLS endpoints, parties seeing credentials, timing assumptions, proof backend
   and disclosed fields. Use an explicit unsupported result instead of silently
   bypassing a selected privacy route.

## Where this repository stands

Implementation follow-through on 2026-11-05 provides two HTTP modes and a
separate optional verifier:

| Mode | Implemented behavior | Boundary |
| --- | --- | --- |
| `zkweb fetch` | Local HTTP/1.1 over an explicit Tor/SOCKS5 TCP route, client-to-origin TLS, remote destination DNS, exact binary bodies, repeated headers and an origin-scoped reusable client. | Requires an already-running trusted loopback proxy and its resolved-address policy. Bodies default to 1 MiB, configurable up to 16 MiB. No cover schedule or ZK proof is attached to this mode. |
| `zkweb request` | Seven methods and bounded UTF-8 requests through scheduled local Sphinx/SURB links to a direct HTTPS worker. | Worker receives plaintext requests and credentials. Frames carry at most 4,090 bytes of application data including the request's reply envelope; all mix nodes remain on one machine. |
| `zkweb verify` | Offline verification of TLSNotary alpha.15 JSON presentations against an external notary key, expected server name and explicit time window; optionally exports authenticated transcript ranges. | Requires a separately built pinned Rust backend. No proof capture, fetch binding, HTTP statement parser or network anonymity claim is added. |

The local route uses fresh per-client Tor isolation parameters and explicit
per-request credentials, with no ambient proxy or cookie jar. It does not
operate a relay network or independently verify the local proxy's Tor identity
or configuration. Local SOCKS/TLS tests are evidence of protocol behavior, not a
live-network anonymity or performance evaluation.

The initial verification adapter uses `tlsn-attestation` and `tlsn-core` from
alpha.15 commit `47aee45b53e06648c1b2ad3689b367b8c923fdec`, independently of
the wallet workspaces. It validates the upstream attestation, server identity
and transcript commitments, then applies caller-selected authenticated ranges.
The implementation checks sparse transcript sizes before typed deserialization
and accepts JSON rather than an arbitrary bincode import. Its test vectors
include a public development signing key and synthetic HTTP data; they establish
compatibility and tamper rejection, not a real website receipt.
[Pinned presentation verifier](https://github.com/tlsnotary/tlsn/blob/47aee45b53e06648c1b2ad3689b367b8c923fdec/crates/attestation/src/presentation.rs),
[pinned transcript representation](https://github.com/tlsnotary/tlsn/blob/47aee45b53e06648c1b2ad3689b367b8c923fdec/crates/core/src/transcript.rs).

This choice also reflects a concrete Reclaim boundary: its exported signature
checker does not itself rerun the TLS/ZK verification, and ordinary returned
claim results omit the transcript. A future Reclaim receipt adapter would need
an explicit trusted-attestor claim model rather than the same verification
statement as a TLSN presentation.
[Signature checker](https://github.com/reclaimprotocol/attestor-core/blob/8f7804e553900dff57c57e9d9394773d884f68b0/src/utils/claims.ts),
[claim handler](https://github.com/reclaimprotocol/attestor-core/blob/8f7804e553900dff57c57e9d9394773d884f68b0/src/server/handlers/claimTunnel.ts).

Proof capture/generation, automatic request/fetch binding, anonymous HTTP
access/payment, a persistent session API, HTTP/2 or HTTP/3, WebSockets and
browser-wide interception remain open. Covered-mode binary fragmentation is
also separate from the local route's bounded binary transfers. The inherited
zkAPI wallet/proof stack remains separate. See the
[local HTTPS guide](local-https-client.md),
[offline verification guide](response-verification.md),
[prototype modes](../research-mixnet/README.md) and
[milestones](../research-mixnet/ARCHITECTURE.md).

The rebrand changes the product documentation and public executable to `zkweb`.
The `research-mixnet` executable remains a compatibility alias. Existing module
paths, deployed protocol/circuit identifiers, wallet formats and upstream
provenance retain their names so branding cannot invalidate existing notes or
deployment pins.

## Next implementation milestones

| Priority | Deliverable | Evidence required |
| --- | --- | --- |
| 1 | Extend the implemented origin-scoped client and Tor/SOCKS route into additional backends and a local context API | Existing exact-byte, certificate, header, DNS, limit and no-fallback tests cover the first route. Add independent concurrent-context and daemon-boundary evidence as that API is implemented. |
| 2 | Extend bounded binary transfers to covered mode and streaming interfaces | Binary bodies now work in the local TLS route. Covered mode still needs fragment ordering/replay/resource limits; future streaming needs backpressure/cancellation bounds. |
| 3 | Compare a deployed mixnet integration with the existing lab and a Tor route | Independent-host tests, measured completion/latency/bandwidth, fault behavior and explicit adversary assumptions. Do not equate synthetic timing scores with anonymity. |
| 4 | Optional anonymous admission/credits | Pin one protocol; test issuance/redemption, replay and linkability boundaries; retain existing wallet release gates for any funded adapter. |
| 5 | Extend initial offline TLSN verification into capture and explicit application statements | The pinned backend has actual signature/identity/commitment and tamper tests. Capture must define route, disclosures, challenge/fetch binding, notary trust and mutation recovery without refetching writes. |
| 6 | Streaming, WebSockets and browser integration where feasible | Protocol-specific conformance, session isolation and long-lived-flow measurements. Declare unsupported combinations and different timing guarantees. |

The existing mutation rule remains: a lost response can leave the remote side
effect committed. ZK provenance does not fix this. Preserve `delivery_unknown`
and no automatic retry; reliable mutation recovery needs an application-defined
idempotency or reconciliation mechanism.

The working name is not exclusive: an unrelated ZKWeb .NET framework already
exists. This change uses the name for this fork's product direction and does not
assert domain/package availability.
[Existing framework](https://github.com/zkweb-framework/zkweb).
