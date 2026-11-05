# zkWeb headless prototype

zkWeb is the working name for a general web request privacy toolkit. This module
is its first transport and HTTP adapter prototype. API CRUD, web fetching,
private application egress and AI/research tools share the request engine; the
product scope extends beyond an AI API wrapper or research daemon.

The transport work builds on
[Vitalik's zkAPI/Tor/rewriting experiment](https://x.com/VitalikButerin/status/2111046730959433793)
and his suggestion to trade bandwidth and latency for continuous cover traffic.
The fork starts at `vbuterin/zkapi` commit
`0fb263b0da04986cfe5c63b12340c1581018ae9b`. The source directory, Go module path
and upstream protocol identifiers retain their historical names.

It is a working **loopback transport experiment**, not a production anonymity
service. It runs headlessly. `demo` and `compare` use synthetic jobs and emit
aggregate JSON. The separate opt-in `request` command carries a bounded HTTP
request over the same local Sphinx/SURB transport to an HTTPS worker. The current
HTTP path does not generate ZK proofs of access, execution or response contents.
See the [current implementation research](../docs/web-request-research.md) for the
roles of private transport, anonymous access and selective data verification.

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
executable from the same source.

Build dependencies download over the network. `demo` and `compare` bind only
literal `127.0.0.1` addresses and contact only those listeners. They accept no
real prompts, keys or wallet profiles. No command launches a browser or GUI.
Ctrl+C cancels the run and joins workers and peer subprocesses. The `demo` command
returns a nonzero status for incomplete jobs. The `compare` command records
incomplete jobs as measurements, since loss and disconnection are deliberate.
Dropped observation events invalidate that trial's attack scores.

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

Requests and replies must each fit one padded cell: 4,090 bytes of application
frame data. A request also carries the SURB and JSON/base64 overhead, so its
usable input budget is smaller. Oversized envelopes are rejected before egress;
large or non-UTF-8 responses return a bounded error. There is no fragmentation,
binary transfer or streaming. Automatic retries are disabled. If the epoch ends
without a verified reply, `delivery_unknown` means the operation may already
have committed. Check the API's state before deciding whether to submit again.
The worker's HTTP timeout is five seconds, further bounded by the epoch.

Caller-supplied credentials and bodies are disclosed to the worker and target.
They do not become anonymous by being inside a Sphinx cell. The operator of this
single-process lab can inspect every node. Use test data when evaluating it.

## What runs

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

The demo uses one process; the comparison uses separate address spaces under one
OS user on one machine. Those processes are not a sandbox or independent operators.
This demonstrates protocol plumbing, **not an anonymity set**, and does not
defeat a colluding provider and guard. The opt-in HTTP worker adds bounded CRUD
egress, but no directory/PKI, remote link authentication, packet-expiry protocol,
persistent replay store, SURB replenishment, delivery/retry protocol, real
inference, local LLM rewriter or zkAPI integration.
Payloads are bounded to one cell. Large and binary bodies need a reviewed
fragmentation/reassembly protocol with independent response scheduling, resource
limits and explicit completion semantics. Streaming, WebSockets, CONNECT,
application sessions and optional proof adapters require separate designs and
acceptance tests; none is available in this prototype. X25519 here is not
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

Loopix and Echomix supply prior designs and analysis; their guarantees do not
automatically apply to this experiment:

- [The Loopix Anonymity System](https://arxiv.org/abs/1703.00536)
- [Echomix: a Strong Anonymity System with Messaging](https://arxiv.org/abs/2501.02933)
