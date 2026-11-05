# zkWeb headless prototype

zkWeb is the working name for web requests whose private inputs stay encrypted
while a cooperating destination processes them. The first private-request
prototype combines TFHE-rs FHE with a mandatory zero-knowledge proof of correct
input encryption. The destination verifies the proof, performs an encrypted
lookup and returns a ciphertext that only the client decrypts.

The hidden input is an index `0..3` selecting one of `[11, 22, 33, 44]`. The
endpoint and operation remain public. This is a real cryptographic prototype,
not a production service or private CRUD support for unchanged websites. See
the [private-request guide](../docs/private-requests.md) for the exact relation,
key/CRS trust assumptions and limits.

The transport work builds on
[Vitalik's zkAPI/Tor/rewriting experiment](https://x.com/VitalikButerin/status/2111046730959433793)
and his suggestion to trade bandwidth and latency for continuous cover traffic.
The fork starts at `vbuterin/zkapi` commit
`0fb263b0da04986cfe5c63b12340c1581018ae9b`. The source directory, Go module path
and upstream protocol identifiers retain their historical names.

The other headless tools retain separate roles:

| Commands | Implemented role | Destination visibility |
| --- | --- | --- |
| `private-setup`, `private-serve`, `private-query` | Offline provisioned, ZK-verified encrypted selector and FHE lookup over loopback HTTP | Ciphertext, proof and public protocol context; no plaintext selector or client secret key |
| `fetch` | Bounded binary HTTPS over an already-running Tor/SOCKS5 proxy, with TLS between local client and origin | Ordinary HTTP request contents and account identity |
| `request` | Small UTF-8 HTTP exchange over the loopback Sphinx/SURB experiment to an HTTPS worker | Worker and destination see ordinary HTTP request contents |
| `verify` | Offline verification of an existing TLSNotary presentation | No request is issued; this does not hide inputs from their source website |
| `demo`, `compare` | Synthetic transport jobs and aggregate measurements | Single-machine lab, not a production anonymity network |

FHE hides the private selector; the ZK proof admits correctly formed encrypted
inputs. It does not prove authorization or correct server computation. See the
[current implementation research](../docs/web-request-research.md) for the
different trust boundaries.

## Run

Requirements: Go 1.27.2, CGO enabled, a C compiler, and `make`. The upstream
Katzenpost algorithm registry includes C-backed dependencies even though this
experiment selects classical X25519. First builds can take several minutes.
Go module checksums remain enabled; no external services run during tests/demo.

```sh
cd research-mixnet
make test
make vet
make build
./bin/zkweb fetch --help
./bin/zkweb private-query --help
./bin/zkweb demo

# Same fixed schedules, with no jobs at all:
./bin/zkweb demo --jobs 0 --duration 6s

# Explore the latency/bandwidth tradeoff, without inference charges:
./bin/zkweb demo --rate 4 --mean-delay 100ms --duration 12s

# Separate OS processes; 16 clients and four fault scenarios (~4 minutes):
make compare

# Smaller process smoke run; aggregate files only:
./bin/zkweb compare --clients 4 --disconnect-clients 1 \
  --jobs-per-client 2 --rate 4 --duration 12s --cases clean \
  --output-dir evidence/local-process-smoke

./bin/zkweb reference-check
```

`make build` produces `bin/zkweb` and the compatible `bin/research-mixnet`
executable from the same source. This ordinary build includes the private
command wrappers and help without Rust or TFHE dependencies. Each optional
backend has its own Rust workspace: [private requests](#private-requests-with-a-cooperating-destination)
use `make build-private`; [offline response verification](#offline-response-verification)
uses `make build-proof`.

Build dependencies download over the network. `demo` and `compare` bind only
literal `127.0.0.1` addresses and contact only those listeners. They accept no
real prompts, keys or wallet profiles. No command launches a browser or GUI.
Ctrl+C cancels the run and joins workers and peer subprocesses. The `demo` command
returns a nonzero status for incomplete jobs. The `compare` command records
incomplete jobs as measurements, since loss and disconnection are deliberate.
Dropped observation events invalidate that trial's attack scores.

## Private requests with a cooperating destination

The optional `zkweb-private` backend pins TFHE-rs 1.8.2. It uses full upstream
computation, compact-public-key-encryption and key-switching parameters, with no
toy reduction. The build requires the Rust 1.99 toolchain through `rustup`.
Key generation, proving and homomorphic evaluation can take substantial time
and resources; no benchmark is implied by this example.

```sh
# From research-mixnet, after make build:
make build-private
./bin/zkweb private-setup --output /tmp/zkweb-private-demo
./bin/zkweb private-serve \
  --server-dir /tmp/zkweb-private-demo/server \
  --listen 127.0.0.1:0
```

Choose a fresh setup output directory. The server prints a READY JSON record
with its actual URL. Keep it running; in another terminal, replace `PORT` with
the chosen port:

```sh
./bin/zkweb private-query \
  --client-dir /tmp/zkweb-private-demo/client \
  --url http://127.0.0.1:PORT \
  --index 2

# Cryptographic checks and real HTTP integration against the optional backend:
make test-private
```

The client prints index `2` and decrypted value `33` locally. HTTP carries only
the challenge identifier and a proven ciphertext as the query payload. The
server safely decodes and checks conformance, requires one encrypted `FheUint2`,
and verifies its ZK proof before FHE evaluation. Successful replies use the same
ciphertext type and response structure for all four choices.

Provisioning creates `client/` with the secret `ClientKey` and `server/` with
evaluation/public material only; the server directory never contains the
decryption key. Give a destination operator only the server directory. The
offline provisioner and CRS generation must be trusted; profile hashes pin the
configuration, CRS and registered keys but do not prove honest setup. Both
processes on one machine are not isolated from that machine's administrator.

Public proof metadata binds the protocol, fixed lookup function, profile,
server instance, challenge and expiry. Bounded, expiring one-use challenges and
a new instance on restart constrain replay. The endpoint, operation, source IP,
profile/session identity, timings and sizes remain visible. The input proof
does not establish correct evaluation or a fresh answer from a malicious server.

Only numeric loopback HTTP endpoints are enabled. More general encrypted reads
or writes require a cooperating backend designed for encrypted computation;
this protocol does not privately forward an arbitrary REST request. Read the
[private-request guide](../docs/private-requests.md) before using or extending it.

## Local HTTPS through Tor/SOCKS5

`fetch` preserves request and response bytes while HTTP and TLS execute on this
machine. It requires an explicit numeric loopback proxy; `tor://` requests
Tor authentication isolation, while `socks5://` uses plain SOCKS5 without that
isolation. The proxy must already be running and configured. zkWeb does not
start Tor, verify that the process is Tor, or fall back to a direct connection.

```sh
# After starting your configured Tor SOCKS port, read from an API you control.
printf '%s\n' '{"method":"GET","path":"/items/1"}' |
  ./bin/zkweb fetch --target https://api.example.com \
    --proxy tor://127.0.0.1:9050 --input -

# Binary request bytes use standard base64; this body is 00 01 ff.
printf '%s\n' '{"method":"POST","path":"/files","headers":{"Content-Type":"application/octet-stream"},"body_base64":"AAH/"}' |
  ./bin/zkweb fetch --target https://api.example.com \
    --proxy tor://127.0.0.1:9050 --input -

# Configure bounds for a request envelope stored in a protected file.
./bin/zkweb fetch --target https://api.example.com \
  --proxy socks5://127.0.0.1:1080 --input fetch.json \
  --timeout 90s --max-request-bytes 4194304 --max-response-bytes 4194304
```

The input fields are `method`, relative `path` (including query), optional
`headers`, and either a UTF-8 `body` string or `body_base64`. Header values may
be strings or arrays of strings. The output has `status`, end-to-end `headers`,
and a UTF-8 `body` or binary `body_base64`; failures can return an `error`.
Unknown, duplicate, null or oversized input fields are rejected. Keep request
credentials in stdin or a protected file, rather than command arguments.

Request and response body limits each default to 1 MiB and may be configured
from 1 byte to 16 MiB. Headers are bounded to 64 KiB and the path to 8 KiB. The
default deadline is 45 seconds, configurable from 1 second to 10 minutes.
There is no ambient cookie jar, environment proxy or inherited authentication.
Redirects and automatic retries are disabled. A failure after transport begins
is `delivery_unknown`, with no partial body returned as complete; a write may
already have executed. HTTP statuses of 400 or greater preserve the response
and make the command exit nonzero.

Each new client context has fresh Tor SOCKS authentication state. The Tor port
must enforce `IsolateSOCKSAuth`; a successful handshake cannot prove that setting
or guarantee a different exit. Destination names go to the proxy without local
DNS queries. Static checks reject private IP literals and known local names,
but the trusted proxy must enforce policy on addresses resolved remotely.

The proxy sees destinations and timing, and the origin sees normal request
contents and any account identity. This path supplies no Sphinx cover or ZK
proof, and does not yet support WebSockets, HTTP/3 or browser-wide interception.
Read the [local HTTPS client guide](../docs/local-https-client.md) for the trust
boundary, configuration and full limits.

## Offline response verification

`zkweb verify` verifies an existing TLSNotary alpha.15 JSON presentation without
contacting an origin or notary. It uses the upstream cryptographic verifier,
pinned to commit `47aee45b53e06648c1b2ad3689b367b8c923fdec`, through the fixed
`zkweb-tlsn-verify` executable beside `zkweb`. The integration is experimental
and retains upstream's non-production status.

```sh
# Requires the separately installed Rust 1.99 toolchain.
make build-proof
./bin/zkweb verify --help

# Build the release backend, run ten Rust cryptographic tests, then run
# the Go integration tests against that backend.
make test-proof
```

The verifier requires the expected server, trusted notary public key and an
explicit inclusive time window from the caller, independently of the artifact.
It emits metadata only by default. Repeatable `--sent-range` and
`--received-range` flags select authenticated transcript bytes with exclusive
end offsets. A missing or unauthenticated byte makes verification fail; output
contains no fabricated redaction bytes. Ordinary `make test` skips the actual
backend integration tests unless `ZKWEB_TLSN_BACKEND` is set.

This verifies an attestation under the selected notary's trust model, rather
than a SNARK execution proof. It does not parse complete HTTP messages, bind a
proof to a separate `fetch` result or application challenge, or establish
exactly-once execution. Proof capture/generation, access admission and stronger
application claims remain future work. The compatibility fixture uses a
publicly known test notary private key and synthetic HTTP content; it is not a
real website receipt.
Read the [verification guide](../docs/response-verification.md) for policy flags,
input format, limits and examples.

## Bounded HTTP requests

`request` supports `GET`, `POST`, `PUT`, `PATCH` and `DELETE` against one explicitly
selected public HTTPS origin, plus `HEAD` and `OPTIONS`. It sends the request
through the local forward mixes, executes it at the worker, and returns the result through the reverse mixes
using a single-use SURB. The worker makes the HTTPS connection directly. All mix
links still run on this machine; this does not provide a production anonymity
service or zkAPI payment/lease integration.

Pass an origin without a path or trailing slash, query, fragment or URL
credentials. The JSON input supplies a relative path, optional headers and a
UTF-8 body string. Inputs reject unknown fields and additional JSON values.
Paths may include a query string. Explicit `Authorization`, `Cookie`, content
type and custom headers are accepted; `Host`, `Content-Length` and hop-by-hop or
proxy-control headers are reserved. Header values cannot contain line breaks.
Use stdin or a protected input file for credentials; keep them out of command
arguments. The configured origin is the only allowed target. Redirects are not
followed, and private/local destinations are refused.

```sh
# Create. Replace the origin and path with an API you control.
printf '%s\n' '{"method":"POST","path":"/items","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"first\"}"}' |
  ./bin/zkweb request --target https://api.example.com --input -

# Read.
printf '%s\n' '{"method":"GET","path":"/items/1"}' |
  ./bin/zkweb request --target https://api.example.com --input -

# Replace.
printf '%s\n' '{"method":"PUT","path":"/items/1","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"replacement\"}"}' |
  ./bin/zkweb request --target https://api.example.com --input -

# Update selected fields.
printf '%s\n' '{"method":"PATCH","path":"/items/1","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"updated\"}"}' |
  ./bin/zkweb request --target https://api.example.com --input -

# Delete.
printf '%s\n' '{"method":"DELETE","path":"/items/1"}' |
  ./bin/zkweb request --target https://api.example.com --input -

# Read an envelope from a protected file and select the schedule in advance.
./bin/zkweb request --target https://api.example.com \
  --input request.json --rate 8 --duration 12s --mean-delay 50ms
```

The default fixed epoch is 12 seconds, with one client and one request. Cover
continues until the epoch ends, even if the API response arrives sooner. Only
then is the response JSON written to stdout. Its fields are `status`, selected
response `headers`, UTF-8 `body`, and an `error` when the worker could not return
a complete API response. An upstream HTTP status of 400 or greater and worker
errors make the command exit nonzero while preserving the response on stdout.
The command does not persist inputs or responses; shell redirection can save
them if desired.

In `request` mode, requests and replies must each fit one padded cell: 4,090 bytes
of application frame data. A request also carries the SURB and JSON/base64 overhead, so its
usable input budget is smaller. Oversized envelopes are rejected before egress;
large or non-UTF-8 responses return a bounded error. There is no fragmentation,
binary transfer or streaming. Automatic retries are disabled. If the epoch ends
without a verified reply, `delivery_unknown` means the operation may already
have committed. Check the API's state before deciding whether to submit again.
The worker's HTTP timeout is five seconds, further bounded by the epoch.

Caller-supplied credentials and bodies are disclosed to the worker and target.
They do not become anonymous by being inside a Sphinx cell. The operator of this
single-process lab can inspect every node. Use test data when evaluating it.

## What runs in the transport lab

```text
client upload clocks -> mix F1 -> mix F2 -> mix F3 -> synthetic worker
client download clocks <- mix R3 <- mix R2 <- mix R1 <- worker return clock
```

The single-process `demo` uses two synthetic clients by default. All edges use actual loopback
HTTP with constant-size Sphinx bodies. Each outgoing edge has its own clock,
bounded pool, and cover generator. The worker uses an opaque single-use reply
block (SURB), not a client callback URL. A fixed run duration keeps both traffic
directions active before, during and after a job.

- Unmodified [Katzenpost Sphinx](https://github.com/katzenpost/katzenpost/tree/v0.0.107/core/sphinx)
  packet and SURB implementation; pinned Go modules and checksums.
- Four-hop packet geometry: three mixes plus the worker or client terminal.
  Cover, forward work and replies have the same cell length.
- CSPRNG-selected eligible packets and capped exponential residence delays.
- Fixed scheduled send slots. Work replaces cover; it does not trigger a send.
  Expired slots are skipped. Failed sends have no retry, redirect or direct route.
- Queue, terminal-work and replay-cache bounds. Replay entries are retained for
  the whole disposable key epoch; a full cache fails closed rather than evicting.
- No plaintext, IDs, keys or per-cell timestamps in the report. Keys live in
  memory. The report contains aggregate lab diagnostics, not a production metric API.

## Separate-process comparison

`compare` runs 16 independent client processes, six relay processes and one worker
for the covered backend. The direct control uses 17 processes and the same
4,522-byte Sphinx geometry on one-hop request/reply paths, without cover or mix
delays. This controls cell framing; it is not a typical unpadded Internet request.
Every peer generates its own disposable private key in memory. Only public
directory data crosses the bootstrap pipe. Children receive a minimal environment
and do not inherit wallet profiles or application credentials.

Clients issue four sequential synthetic jobs, with 20 ms of synthetic thinking
between a reply and its followup. Initial arrivals are staggered. The fixed
24-second epoch includes idle cover after work finishes. Cases change one factor:

- `clean`: no injected faults.
- `watermark`: a synthetic provider delays each reply by 0, 375 or 750 ms.
- `loss`: seeded 2% loss at worker ingress, affecting work and cover alike.
- `disconnect`: two clients stop one-third into the epoch.

The public seed controls workload, fault selection and predefined clock phases;
packet entropy and pool selection always use the OS CSPRNG. Jobs are not retried.
A lost reply stops that client's remaining sequential jobs. The report separates
planned, submitted and completed jobs, and reports latency for completed jobs only.
Synthetic nonces change between runs, so the exact watermark pattern also changes.

Two deliberately limited attacker rules match provider receive times to the
nearest preceding client-edge full write, or provider release times to the nearest
following write. Inputs contain no client-edge job label. The supervisor joins
synthetic ground truth only to score guesses. Followup scoring includes only jobs
whose next round was actually submitted. The report includes sample counts and
the average uniform-guess baseline for the connected population. These are fixed,
untrained heuristics with a five-second search window, not a comprehensive
colluding provider/guard attack. Raw observations remain in memory.

Reports contain actual TCP stream read/write counters, including HTTP. They omit
TCP/IP headers, retransmission and physical wire overhead. Per-link pending cells,
rejected cells, failed slots and missed slots help explain availability limits.
Single runs have small, correlated samples and do not establish anonymity.

The complete Katzenpost reference is **not run**: its pinned stock generator and
server persist identity/link private keys, conflicting with the instruction to
keep credentials out of files. `reference-check` reports that constraint; it does
not fabricate a third backend. See [reference assessment](REFERENCE.md).

## Read the measurements correctly

The rate is **scheduled application cells**, not a physical constant-bit-rate
link. HTTP/TCP overhead, kernel buffering, clock jitter, losses, pauses and setup
are not hidden. `missed_clock_slots` and `failed_slots` expose these limitations.
`cancellation_interrupted_slots` separates ambiguous sends interrupted by the
fixed epoch ending or cancellation; those sends are not retried either.
`successful_cells` means HTTP acceptance; the receiver deliberately does not
reveal whether a cell was invalid, replayed, dropped or accepted internally.
End-to-end synthetic reply completion is checked separately.

For cell length `C` and client rate `r`, the scheduled upload-plus-download
cell budget is `2 × C × r × 3600` bytes/hour per client, including idle periods.
The report gives this in MiB. Relay hops add more aggregate network traffic.
This is not a cap on TCP wire bytes and not a provider-cost estimate.

## Limits and next work

The private-request priority is to extend useful cooperating-server functions,
evaluate malicious-server behavior and result integrity, and define encrypted
state updates before claiming private CRUD. Input-proof verification alone
does not prove correct FHE execution. A remote deployment also needs a reviewed
profile-registration/provisioning and authenticated transport design. The
current loopback example exposes endpoint/session/IP/timing/size metadata and
adds no network anonymity or production ceremony.

The separate transport experiments have their own remaining work.
The demo uses one process; the comparison uses separate address spaces under one
OS user on one machine. Those processes are not a sandbox or independent operators.
This demonstrates protocol plumbing, **not an anonymity set**, and does not
defeat a colluding provider and guard. The opt-in HTTP worker adds bounded CRUD
egress, but no directory/PKI, remote link authentication, packet-expiry protocol,
persistent replay store, SURB replenishment, delivery/retry protocol, real
inference, local LLM rewriter or zkAPI integration.
Sphinx `request` payloads are bounded to one cell. Larger or binary covered
transfers need a reviewed fragmentation/reassembly protocol with independent
response scheduling, resource limits and explicit completion semantics. The
separate `fetch` mode already supports bounded binary HTTPS through a proxy,
with different timing and trust assumptions. Streaming, WebSockets, CONNECT,
persistent application sessions and integrated proof capture require separate
designs and acceptance tests. The offline TLSNotary verifier is an initial
response-verification adapter; HTTP/application claims, request binding and
anonymous access/payment admission are not integrated. X25519 here is not
post-quantum protection, and Sphinx encryption is not a ZK execution proof.

See [architecture and production milestones](ARCHITECTURE.md),
[candidate applications](APPLICATIONS.md), and [validation evidence](evidence/README.md).
The [prepared CI workflow](ci/README.md) needs an authorized workflow upload
before it can run on GitHub; the current credential can publish source only.
Do not connect a funded wallet to this lab. The existing native app and its
custody, Tor and funding configuration are untouched.

## Provenance and licensing

This directory's prototype source is AGPL-3.0-or-later; see [LICENSE](LICENSE).
It links Katzenpost's AGPL Sphinx implementation. Upstream `zkapi-clientd` keeps
its own MIT license. This does not apply a new license to the rest of zkapi.
Review the complete distribution's notices and licenses before packaging it.
The optional private backend pins a separate TFHE-rs dependency; its provenance
and upstream licensing references are in the
[private-request guide](../docs/private-requests.md#why-this-implementation).

Loopix and Echomix supply prior designs and analysis; their guarantees do not
automatically apply to this experiment:

- [The Loopix Anonymity System](https://arxiv.org/abs/1703.00536)
- [Echomix: a Strong Anonymity System with Messaging](https://arxiv.org/abs/2501.02933)
