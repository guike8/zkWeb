# zkWeb: request authorization and private computation

Research date: **2026-11-05**. The repository is now `guike8/zkWeb`.
This brief compares original specifications, project documentation and source
repositories. It is an implementation shortlist, not an independent audit or
an exhaustive survey. Research used OpenCLI searches and original-page reads.

## Product decision

The immediate priority is a **ZK authorization listener**: close the loop from
client proof generation through listener verification to persistent HTTP CRUD.
The client proves membership in an authorized group without sending its member
secret, tree path or index. The proof binds the exact method, path and body to
the listener profile and a fresh one-use challenge. Request contents are visible
to this listener; this is the explicitly selected first stage.

Keeping request contents hidden while the destination computes remains a
separate encrypted-computation goal. Further FHE work is deferred while the ZK
listener path is established. The earlier FHE lookup remains an independent
experiment, rather than a dependency of authorization.

The compatibility goal is broad HTTP(S) support: methods, destinations, paths,
queries, explicit headers, exact request/response bytes, session contexts and,
where the selected transport permits it, streams and WebSockets. This is a goal,
not a claim that the current prototype supports all websites or web protocols.

An unchanged HTTP server cannot execute arbitrary hidden paths, credentials and
bodies using ZK alone. A proof can establish a statement about a secret input;
FHE or MPC supplies the ability to compute without revealing that input. Our
chosen FHE implementation evaluates a fixed function over encrypted inputs.
Its input proof does not prove that a malicious server returned the right result.
[TFHE encrypted computation and ZK input proofs](https://github.com/zama-ai/tfhe-rs/blob/e8f3926bb53d7eea95e8a7f581f60aae1c7aba16/tfhe/docs/fhe-computation/advanced-features/zk-pok.md).

## Separate properties

| Property | Mechanism to evaluate | Boundary |
| --- | --- | --- |
| Hide selected inputs from the computing destination | FHE or MPC with a cooperating backend; ZK can enforce valid input and policy | The public function, endpoint and traffic metadata remain visible. Existing websites need backend changes. |
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
| **TFHE-rs 1.8.2** | Rust FHE integer operations, compact public-key encryption and ZK proofs of correct compact encryption; the implementation pins version 1.8.2. | Selected for the first destination-private request backend: one encrypted two-bit selector with a mandatory proof, four-record encrypted lookup and local decryption. This is a cooperating fixed-function service, not arbitrary encrypted HTTP execution or a proof of output correctness. [Pinned release](https://github.com/zama-ai/tfhe-rs/releases/tag/tfhe-rs-1.8.2), [ZK input proof API](https://github.com/zama-ai/tfhe-rs/blob/e8f3926bb53d7eea95e8a7f581f60aae1c7aba16/tfhe/docs/fhe-computation/advanced-features/zk-pok.md). |
| **SimplePIR / DoublePIR, Blyss, authenticated PIR** | Implementations and research for private record retrieval, with authenticated variants addressing response integrity. | Relevant for private reads and scaling the initial lookup. Private retrieval alone does not supply this prototype's ZK input proof or general encrypted writes. [SimplePIR](https://github.com/ahenzinger/simplepir), [Blyss SDK](https://github.com/blyssprivacy/sdk), [authenticated PIR](https://people.eecs.berkeley.edu/~henrycg/pubs/authpir/). |
| **Nym** | Developer documentation updated November 3, 2026 lists native TCP/UDP APIs, SOCKS5, Go/C FFI, browser `mix-fetch`, `mix-websocket` and DNS support. The network separately uses anonymous `zk-nym` credentials for bandwidth. | Optional network privacy layer. It does not hide request contents from the computing destination. Evaluate its maintained SDK or SOCKS integration for network linkage protection. [SDK matrix](https://nym.com/docs/developers), [network architecture](https://nym.com/docs/network). |
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

1. **Implement destination-private functions first.** A client encrypts its
   selector and proves valid input under a pinned public profile and fresh server
   challenge. The server verifies before homomorphic evaluation; only the client
   holds the decryption key. Extend the fixed lookup through explicit encrypted
   operation schemas rather than claiming arbitrary HTTP compatibility.
2. **Keep HTTP semantics in a general local client.** Define a byte-preserving
   request interface and explicit context for origin permissions, credentials,
   cookies, budgets, deadlines and response limits. Applications must choose
   their state scope; do not infer it from chat history or rewrite arbitrary
   bodies as prose.
3. **Separate the network stream from HTTP execution.** For a general transport
   mode, prefer a stream route that lets TLS terminate locally and at the real
   destination. This avoids giving an application-layer worker the request's
   plaintext credentials. Prototype Tor/Arti first and evaluate Nym's maintained
   native/SOCKS interfaces for traffic that can tolerate mixnet costs. Verify the
   exact TLS termination and DNS behavior of each chosen integration.
4. **Keep delegated HTTPS work explicit.** The current worker mode is useful for
   bounded asynchronous tasks, but the worker receives the HTTP request and
   credentials. Treat OHTTP as another specifically configured gateway mode,
   with documented gateway visibility and non-collusion assumptions.
5. **Make anonymous authorization an independent adapter.** Compare Privacy Pass
   gateway tokens with Nym bandwidth credentials and inherited zkAPI funding.
   Define the actual statement, audience, spend/replay protection and metadata
   leakage. Supporting one does not imply support for the others.
6. **Make response proofs opt-in.** Evaluate TLSN and Reclaim against the same
   fixtures before choosing a dependency. Bind the disclosed fact to the origin,
   request/context, freshness and verifier's intended statement. Proving a
   response predicate is not proof that an arbitrary side effect executed
   exactly once.
7. **Publish capabilities by mode.** Report supported protocols and body limits,
   TLS endpoints, parties seeing credentials, timing assumptions, proof backend
   and disclosed fields. Use an explicit unsupported result instead of silently
   bypassing a selected privacy route.

## Where this repository stands

Implementation follow-through on 2026-11-05 adds a ZK authorization listener
alongside the existing encrypted-query experiment, HTTP transports and verifier:

| Mode | Implemented behavior | Boundary |
| --- | --- | --- |
| `zkweb zk-setup`, `zk-listen`, `zk-request` | A distinct BN254 Groth16 circuit proves secret-credential Merkle membership and constrains both 128-bit halves of the exact HTTP request digest. A fresh privately blinded tag is public; the listener consumes its nonce before verifying and executes CRUD only after acceptance. | Trusted offline setup and credential provisioning, 1–16 members, loopback HTTP and bounded binary records. The listener sees the request and stored values; IP/timing/profile remain visible. All group members share record access. See the [listener guide](zk-listener.md). |
| `zkweb private-setup`, `private-serve`, `private-query` | TFHE-rs encrypted selector, mandatory context-bound input proof, server-side homomorphic lookup and client-only decryption. Client and server profiles are separated. | Four public records, one private selector in 0–3, loopback HTTP prototype, trusted offline setup. No arbitrary hidden HTTP/CRUD, network anonymity or proof of correct server output. See the [private request guide](private-requests.md). |
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

Response-proof capture/generation, automatic request/fetch binding, anonymous HTTP
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
| 1 | Establish the ZK authorization listener loop | Real proofs from different authorized members, altered method/path/body and wrong-group rejection, one-use challenges, persistent CRUD, recovery and real CLI integration. |
| 2 | Extend listener deployment and admission policy | Authenticated remote transport, credential rotation/revocation, service quotas and application-specific group scopes. |
| 3 | Resume encrypted state and CRUD after the authorization loop | Define each encrypted input/output and proof statement; measure computation and wire cost; specify access-pattern leakage, state commitments and mutation recovery. |
| 4 | Authenticate encrypted computation results | Define the malicious-server model and prove or otherwise authenticate the selected function and returned result. An input authorization proof alone cannot do this. |
| 5 | Extend network privacy and response attestations as distinct adapters | Preserve byte, TLS, replay, context and verifier checks; document which adapter protects which party's information. |

The existing mutation rule remains: a lost response can leave the remote side
effect committed. ZK provenance does not fix this. Preserve `delivery_unknown`
and no automatic retry; reliable mutation recovery needs an application-defined
idempotency or reconciliation mechanism.

The working name is not exclusive: an unrelated ZKWeb .NET framework already
exists. This change uses the name for this fork's product direction and does not
assert domain/package availability.
[Existing framework](https://github.com/zkweb-framework/zkweb).
