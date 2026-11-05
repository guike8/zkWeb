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

The local gateway transport always uses POST `/api`, including for an upstream
HEAD. Signed metadata carries the target method, path/query and header list;
the proof is verified against those target values before forwarding. A complete
upstream reply is wrapped in a gateway success envelope containing the upstream
status, cleaned headers and base64 body. An upstream 401, redirect or 503 is
therefore distinct from a gateway authorization or delivery failure.

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
