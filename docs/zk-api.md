# Experimental ZK authorization for external APIs

The ZK listener can act as a gateway to one configured HTTPS API. A client
proves membership in its authorized group; the gateway verifies the proof and
then forwards the permitted request. The API does not need to understand the
Groth16 proof protocol.

The proof binds the expected upstream origin, target method, exact path/query,
explicit caller headers and binary body to a fresh gateway challenge. Member
secrets and membership paths stay on the client. The gateway and upstream see
the request contents. This is an authorization experiment; FHE remains separate.

## Run the gateway

Build and provision the existing listener backend:

```sh
cd research-mixnet
make build
make build-zk
./bin/zkweb zk-setup --output /tmp/zkweb-api-demo --members 4

./bin/zkweb zk-listen \
  --server-dir /tmp/zkweb-api-demo/server \
  --upstream https://api.example.com \
  --allow-methods GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS \
  --upstream-path-prefix /v1/ \
  --listen 127.0.0.1:0
```

Choose either `--state-file` for the local record store or `--upstream` for API
gateway mode. The default gateway method allowlist is `GET,HEAD`; writes require
an explicit operator opt-in. The upstream origin and policy stay fixed for the
listener process. The listener prints its READY URL after initialization.

In another terminal, use that URL and the expected upstream origin:

```sh
./bin/zkweb zk-api \
  --client-dir /tmp/zkweb-api-demo/client-0 \
  --url http://127.0.0.1:PORT \
  --upstream https://api.example.com \
  --method GET --path '/v1/items?limit=10'

./bin/zkweb zk-api \
  --client-dir /tmp/zkweb-api-demo/client-0 \
  --url http://127.0.0.1:PORT \
  --upstream https://api.example.com \
  --method POST --path /v1/items \
  --header 'Content-Type: application/json' \
  --data '{"name":"example"}'
```

Use PUT, PATCH or DELETE for the corresponding API operation. POST, PUT and
PATCH require exactly one of `--data` or `--data-file`, including an explicit
empty value. DELETE and OPTIONS may carry a body; GET and HEAD do not. Binary
files are supported up to 1 MiB. The Go wrapper stages the body in a private
temporary file instead of putting large plaintext bodies in process arguments,
and removes that file after normal completion or failure.

Requests use the [compact binary transport](compact-zk-client-server.md) by
default: a 72-byte challenge and 192 raw authorization bytes, followed by the
necessary operation metadata and payload. Gateway responses carry raw binary
bytes. Use `--wire legacy` only for an older listener; there is no automatic
downgrade. The CLI still prints JSON with base64 bodies locally for scripts.

## Headers and gateway-held credentials

Each `--header 'Name: value'` is part of the proof-bound request. Names are
lowercased and stably sorted; repeated values retain their order. The serialized
header list is limited to 32 entries and 8 KiB. The gateway forwards only this
explicit list, not unrelated incoming HTTP headers.

Caller headers cannot override authority, framing, hop-by-hop routing, cookies,
authorization, forwarded client identity or the ZK protocol headers. The gateway
can inject its own API credentials from a private `0600` JSON file, supplied at
startup with `--upstream-headers-file /secure/api-headers.json`:

```json
{"Authorization":"Bearer YOUR_SERVICE_TOKEN"}
```

Restrict that file before starting the gateway: `chmod 600 /secure/api-headers.json`.

A list of `{"name":"...","value":"..."}` objects is also supported. The
file is loaded once. Caller headers that collide with injected names are
rejected rather than silently replaced. Injected credential values are an
operator-controlled addition, not values the client proves knowledge of.

Proof and challenge headers never reach the upstream. Hop-by-hop fields,
connection-nominated fields, cookies and configured credential headers are
removed from returned header metadata. An upstream can still return sensitive
data or reflect credentials in its response body. Configure only trusted API
origins and paths that every authorized group member should be allowed to use;
the gateway does not provide a general response-data redaction policy.

## Origin and delivery boundaries

The upstream must be a configured HTTPS origin without credentials or a URL
suffix. DNS answers are checked and pinned for that listener process while TLS
continues to verify the original hostname. Private and special-use destinations
are rejected by default. `--allow-private-upstream` explicitly permits trusted
self-hosted destinations; `--upstream-ca-file` adds an operator-selected PEM
trust anchor for verified TLS. There is no option to disable TLS verification.

Paths must remain relative to the configured origin. Normalization changes,
dot-segment escapes, encoded separators and fragment/authority tricks are
rejected. The path-prefix allowlist applies to the validated path. Neither the
gateway nor client follows redirects or automatically retries requests.

The compact gateway transport uses POST `/b1/a`, including for an upstream HEAD.
Its binary body contains authorization, target method, exact path/query, selected
headers and raw payload. A complete reply carries upstream status, cleaned
headers and raw body. Legacy mode uses POST `/api`, text metadata headers and a
JSON/base64 response envelope. Both formats distinguish an upstream 401,
redirect or 503 from a gateway authorization or delivery failure.

The CLI result has `format`, `method`, `path`, `upstream`, numeric `status`,
`headers` and `body_base64`. The body limit is 1 MiB in both directions.
Transport failure, a partial/oversized response or cancellation can occur after
the API has already executed a write. Such outcomes are reported as unknown
delivery and are never retried automatically. Use the API's idempotency or
reconciliation mechanism before resubmitting a mutation.

The same group/profile trust assumptions as the [local listener](zk-listener.md)
apply. Authorized members share the configured API scope and gateway account.
The gateway sees source addresses, timing and contents. Remote authenticated
gateway deployment, per-user API ownership, credential revocation and proofs of
upstream execution are further work.

## Verification

The opt-in fixture at
[`internal/zkapi_e2e`](../research-mixnet/internal/zkapi_e2e/zk_api_test.go) starts
an owned local HTTPS upstream and a real proof-verifying gateway. It exercises
the seven target methods, repeated headers, path/query preservation, a 1 MiB
binary round trip, upstream statuses and redirects, TLS trust, tampering,
replay and unknown-delivery behavior. It makes no requests to a real external
API account.

### Live public API test

Run the actual CLI and proof-verifying gateway against GitHub's public API and
the [httpbingo request-inspection service](https://httpbingo.org/):

```sh
cd research-mixnet
make test-zk-live

# Optionally save sanitized evidence to an existing directory:
ZKWEB_ZK_LIVE_REPORT=/absolute/path/github-live.json \
ZKWEB_ZK_LIVE_METHODS_REPORT=/absolute/path/methods-live.json \
ZKWEB_ZK_COMPACT_REPORT=/absolute/path/compact-live.json \
  make test-zk-live
```

The GitHub check provisions a fresh two-member group and configures only
GET/HEAD under `/repos/guike8/zkWeb`. It uses the default public-address checks
and HTTPS certificate verification, with no token, custom CA, private-network
override, proxy or upstream mutations. It checks the repository, a pinned
commit, query parameters, an empty HEAD body, and the distinction between an
upstream error and a gateway rejection. Fresh proofs are altered to check method,
path/query, header and proof binding; a captured successful authorization is also
replayed and rejected.

A compact GitHub check separately captures the default binary GET/HEAD exchange,
checks the exact challenge and proof-envelope sizes, compares equivalent legacy
message sizes, and verifies one client-to-observer connection per
challenge/request pair. A separate direct TCP test checks actual listener
connection reuse and idle bounds.
The legacy GitHub authorization regression explicitly selects `--wire legacy`.

A fresh compact client/server group sends all seven HTTP methods to
`https://httpbingo.org/anything`, with disposable test data. It checks echoed
methods, queries, headers and payloads for GET/POST/PUT/PATCH/DELETE, an empty
HEAD body, and OPTIONS preflight metadata. The provider's
[preflight middleware](https://github.com/mccutchen/go-httpbin/blob/main/httpbin/middleware.go)
returns an empty OPTIONS response with allowed methods instead of echoing its
payload. The echo checks also confirm that ZK protocol headers do not reach the
upstream. This tests real external method/body transport; the echo service does
not establish persistent CRUD storage.

The optional report records statuses, selected public response headers, response
sizes/hashes, timings and assertion results. It excludes credentials, setup files,
challenges, tags and proofs. Temporary setup files are removed when the test exits.
The test needs internet access and an available GitHub unauthenticated rate limit;
it fails on network/provider errors and makes no automatic retry.

The [GitHub live report](validation/zk-api-live-2026-11-05.json) and
[method echo report](validation/zk-api-methods-live-2026-11-05.json) record the
2026-11-05 runs. Rejection statuses are observed at the gateway; GitHub's internal
request count is not observable in this test. The owned fixture separately checks
that failed authorization does not call its upstream. These tests establish
request authorization and transport behavior, not a proof of upstream execution.

For a public GitHub request, ZK hides the member secret and membership path from
the gateway; it adds no request-content privacy. HTTPS supplies encryption in
transit. GitHub sees the gateway's IP because it proxies the request. Both the
gateway and GitHub see the request contents. None of those content or IP
properties are supplied by the ZK membership proof.

The [compact client/server format](compact-zk-client-server.md) documents the
implemented binary messages, byte accounting and compatibility behavior, with
[compact GitHub evidence](validation/zk-compact-live-2026-11-05.json) and
[compact method evidence](validation/zk-compact-methods-live-2026-11-05.json).
