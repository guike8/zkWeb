# zkWeb

zkWeb is building web requests authorized by zero-knowledge proofs. The current
priority is a complete client → proof → listener verification → CRUD loop.
The repository is [guike8/zkWeb](https://github.com/guike8/zkWeb).

The new listener uses an actual BN254 Groth16 circuit. A client proves knowledge
of a secret belonging to the listener's authorized Merkle group without sending
the secret, member index or membership path. The proof binds the exact HTTP
method, record path and body to the pinned profile and a fresh, one-use server
challenge. Only then does the listener create, read, update or delete a record.

**The listener sees request contents and stores ordinary plaintext records.**
This milestone supplies anonymous group authorization. FHE for computing on
hidden request contents is deferred and is a separate layer. Group membership
authorizes access to all listener records; there is no per-member record owner.

## ZK listener quick start

The [headless client](research-mixnet/README.md) supplies `zk-setup`, `zk-listen`
and `zk-request`. The Rust proof backend is optional and independent of TFHE,
wallet funding and the transport experiments.

```sh
cd research-mixnet
make build
make build-zk

# Trusted offline setup; choose a fresh directory.
./bin/zkweb zk-setup --output /tmp/zkweb-zk-demo --members 4

# Give the listener only this server directory, never the complete setup.
./bin/zkweb zk-listen \
  --server-dir /tmp/zkweb-zk-demo/server \
  --state-file /tmp/zkweb-zk-records.json \
  --listen 127.0.0.1:0
```

Use the READY URL in another terminal. Each `zk-request` obtains a challenge,
generates a new proof, and sends one request without automatic retries:

```sh
./bin/zkweb zk-request \
  --client-dir /tmp/zkweb-zk-demo/client-0 \
  --url http://127.0.0.1:PORT --method POST --key note --data 'hello'

# GET reads, PUT replaces and DELETE removes the same record.
./bin/zkweb zk-request \
  --client-dir /tmp/zkweb-zk-demo/client-0 \
  --url http://127.0.0.1:PORT --method GET --key note
```

Values are bounded binary bytes; `--data-file` preserves file contents. Proofs
are 128 compressed bytes. Client results use base64 to preserve returned bytes.
See the [listener guide](docs/zk-listener.md) for the full lifecycle, exact proof
statement, provisioning and failure semantics. `make test-zk` is the dedicated
cryptographic and real HTTP acceptance entry point.

Setup provisions 1–16 members, defaulting to four. The listener receives only a
verifying key and public profile. Each client receives its own private credential
and the public proving key. The trusted offline provisioner temporarily knows
all credential secrets and can impersonate members; this example has no
multiparty production ceremony. Hash pins do not make an untrusted setup honest.
Fresh private tag blinding prevents repeated request contexts from exposing a
stable credential tag, but this is no network-anonymity claim: contents, IP,
timing, sizes and the shared profile remain visible. Numeric loopback endpoints
are enabled for development; authenticated remote deployment is separate work.

## Other experimental tools

The earlier optional `private-*` backend remains a four-entry FHE lookup. It is
not a dependency of the ZK listener. Its [guide](docs/private-requests.md) describes
its distinct encryption, input-proof and trusted-setup boundaries. Expanded
FHE CRUD work is deferred separately from this listener milestone.

Separate HTTP modes support `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` and
`OPTIONS`. `fetch` preserves bounded binary HTTP through an explicit, already
running Tor/SOCKS5 proxy, with TLS terminating at the client and destination.
`request` carries a small UTF-8 exchange through the local Sphinx/SURB experiment
to an HTTPS worker. Those ordinary destinations receive request contents;
network routing and this listener's authorization proof are different properties.
Both modes disable automatic retries and preserve unknown-delivery outcomes.

The optional `zkweb verify` backend checks existing TLSNotary alpha.15 JSON
presentations offline against caller-pinned notary, server and time policy.
It does not generate a request proof or capture a web response. See the
[verification guide](docs/response-verification.md).

```sh
make test
make vet
# Optional backends, each in its own Rust workspace:
make test-zk
make test-private
make test-proof
```

The source directory remains `research-mixnet/`, with `research-mixnet` retained
as a compatibility executable. Inherited wallet protocol identifiers, module
paths and deployment pins keep their existing names. See the
[architecture](research-mixnet/ARCHITECTURE.md),
[transport research](docs/web-request-research.md) and
[local HTTPS guide](docs/local-https-client.md).

## Upstream zkAPI compatibility

The sections below document the inherited zkAPI wallet, billing and operator
components. Their original names, protocol identifiers, deployment pins and
provenance are retained for compatibility. Their proofs concern funding and
authorization; those proofs do not hide HTTP content from its destination.

zkAPI lets you pay for AI and other APIs with ETH and make unlinkable requests.
It keeps API usage separate from your on-chain deposit: the service can verify
that you can pay without learning which deposit is yours.

Built by Open Anonymity in collaboration with the Ethereum Foundation, zkAPI
uses zero-knowledge proofs to make this possible. Deposit ETH, pay only for what
you use, and withdraw your remaining balance on-chain.

Live web app: [**chat.openanonymity.ai**](https://chat.openanonymity.ai/) —
try zkAPI in OA Chat by choosing the Ethereum wallet option.

Documentation: [**zkapi.openanonymity.ai**](https://zkapi.openanonymity.ai/).

The protocol is experimental; see
[the note-binding review](docs/note-bound-commitments.md) and
[the concession exit design](docs/design/concession-exit.md), which lets a
user withdraw without any cooperation from the operator.

Releases follow [semantic versioning](docs/versioning.md) on major version 0:
until 1.0.0, any interface may change in any release. See the
[changelog](CHANGELOG.md).

### Privacy-enabled client development branch

This branch adds native Tor conversation isolation, canonical prompt rewriting,
separate target-side history, bounded cover traffic and saved vault-protocol
selection to the local client. Start with [the client README](zkapi-clientd/README.md)
and [build instructions](zkapi-clientd/docs/DEVELOPMENT.md).

**Not a production release:** concession network manifests are undeployed and
production proving keys are missing; legacy needs its matching historical wallet
bundle. Neither protocol selection nor privacy features bypass these checks.
Local wallets, binaries, proving assets and scratch outputs are excluded from Git.

### Local OpenAI-compatible API

Use [zkapi-clientd](zkapi-clientd/README.md) to configure an ETH wallet and serve
inference to Open WebUI or another local OpenAI-compatible client. Its
withdrawals can pay their network fee from the payout (`withdraw --fees
payout`, through an ERC-4337 paymaster), so the payout address needs no ETH;
the vault is unchanged.

### Build and test

```sh
npm ci
npm test
npm run verify:assets
npm run verify:builds   # the placeholder profiles must refuse to build
cargo build --release --workspace
cargo test --release --workspace
cargo test --release --manifest-path protocol/rust/Cargo.toml --workspace
(cd protocol/contracts && forge test)
```

The protocol and required Solidity libraries are ordinary files in this repository.
No submodule initialization, Cairo compiler or STARK prover is needed. See
[source provenance](protocol/VENDORED.md).

### Browser SDK

`@openanonymity/zkapi-browser-sdk` owns native ETH funding, wallet persistence,
proof generation, lease recovery, settlement and withdrawals. Mainnet and Sepolia
have independent deployment pins, signing keys and wallet state. Applications
configure the SDK before initializing a wallet; see [SDK integration](sdk/README.md)
and [native billing](docs/native-eth-billing.md). A withdrawal can pay its
network fee from the payout (`fees: 'payout'`, through an ERC-4337 paymaster),
so the payout address needs no ETH; the vault is unchanged.

The packaged WASM and proving keys support the current circuit
`zkapi-v2-concession-v1` (vault revision 3), with the development setup until
the multi-party ceremony has run. Until a revision-3 vault is deployed, the
packaged network profiles are placeholders and `npm run build:browser` and
`npm run build:mainnet` refuse them by design (`deployment_not_deployed`);
`npm run verify:builds` checks exactly that. Notes of the earlier circuit
`zkapi-v2-note-bound-v1` are served by the release line
`release/v2-note-bound`. Ordinary SDK consumers do not need Rust. To rebuild
WASM deliberately, use `scripts/build-browser-client.sh` and review the changed
artifact hashes; `npm run verify:wasm` rebuilds it reproducibly and compares.

### Full local lifecycle acceptance

Run `npm run test:e2e:v2` to build and test circuit `zkapi-v2-concession-v1`
end to end on a fresh local chain. It covers the honest flow and the Sepolia
drill scenarios that run locally, and writes a gas report. The drill scenarios
include withholding, bad successor anchors, a lying expiry check, forced and
conceding escapes with raises and defeats, the bounded pause, a missed
defeat with leaf retirement, and gasless withdrawals through a local
bundler.

The contracts, proofs, server, indexer, challenger, signer sidecar, browser SDK
and clientd companion are real. The provider, OA org and price feed are
mocked. See the [acceptance process and coverage limits](docs/v2-acceptance.md).
`node scripts/check-withdrawal-golden.mjs` submits the Rust, JS and Go
withdrawal encoders' calldata to an Anvil vault.

### Operator services

- `zkapi serverd`: native ETH lease authorization, settlement and Schnorr signing.
- `zkapi-indexerd` / `zkapi indexer`: vault event indexing and Merkle paths
  from a view verified against the vault.
- `zkapi db init`: create the server database with its append-only request
  evidence and bind it to the deployment manifest, before any daemon starts.
- `zkapi-challenged`: durable escape monitoring; defeats escapes from spent
  states, raises under-conceded escapes, and retires a closed note's leaf
  after a missed defeat; private status endpoints.
- `zkapi signing-keys`: derive deployment public keys from operator seeds
  (the published development keys are rejected).
- `zkapi settlement reopen`: with the API server stopped, verify, repair and
  reopen a lease cancelled for a corrupt binding.
- `zkapi setup --output-dir NEW_DIRECTORY`: generate a fresh single-party
  development setup, which release builds refuse.

Native server startup requires a pinned oracle RPC/feed, a lease issuer, the
deployment manifest, and both `ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED`; there
are no default seeds. The server refuses to start unless their keys equal the
vault's immutable keys and the vault, adapter and Poseidon library match the
manifest. Use [deployment instructions](docs/deployment.md),
[Docker operation](docker/aws/README.md),
[challenge service operation](docs/challenge-service.md) and the
[concession-vault migration runbook](docs/migration-concession-vault.md). The
browser sends prompts directly to the inference provider; the server handles
authorization and settlement.

The keys in `protocol/setup/v2-concession` (the ceremony's, once G-SETUP has
run) must match the vault's immutable verifier and the client's pinned proof
artifacts; `protocol/setup/v2-concession-dev` holds the development keys for
tests, the drill vault and vaults deliberately deployed on a single-party setup
([Single-party setup](docs/deployment.md#single-party-setup)). The `setup`
command generates new development keys;
it is not part of connecting a client to the configured vault.

### Protocol details

The active protocol uses Groth16 over BN254, Poseidon, note-bound Baby-JubJub
commitments and Schnorr signatures, a nullifier chain whose successor anchors
are derived from the spent nullifier, and a 32-level append-only Merkle tree.
The ledger uses integer gwei. An escape concedes at most the request budget of
the state it leaves and needs no operator cooperation. Production keys need
the multi-party setup described in
[the ceremony setup](protocol/setup/v2-concession/README.md); the committed
keys are a single-party development setup.

### Source layout

| Directory | Purpose |
| --- | --- |
| `research-mixnet/` | Headless zkWeb commands, private requests and separate transport experiments |
| `research-mixnet/zk-listener/` | Optional Groth16 group-authorization listener and plaintext CRUD backend |
| `docs/zk-listener.md` | ZK listener statement, credential provisioning, HTTP flow and run instructions |
| `research-mixnet/private-request/` | Optional TFHE-rs backend for ZK-verified encrypted queries and FHE evaluation |
| `docs/private-requests.md` | Private-request protocol, setup, run instructions and trust boundaries |
| `docs/web-request-research.md` | Current implementation research and general web request direction |
| `docs/response-verification.md` | Optional offline TLSNotary verification, policy and limits |
| `zkapi-clientd/` | Local ETH-funded OpenAI-compatible client and installer |
| `sdk/` | Browser native ETH wallet, public artifacts and SDK tests |
| `protocol/rust/` | Shared v2 types, BN254 helpers, circuits and Rust/WASM wallets |
| `protocol/contracts/` | Native ETH vault, Groth16 verifier and contract tests |
| `protocol/setup/v2-concession/`, `v2-concession-dev/` | Ceremony and development setups of the current circuit |
| `protocol/setup/v2/` | Setup of the legacy circuit, for `release/v2-note-bound` |
| `crates/` | Operator CLI, server, indexer, challenger and the clientd wallet companion |
| `demo/contracts/` | Native ETH verifier/vault deployment script |
| `docker/aws/` | API/indexer/challenger image configuration and restricted signer |
