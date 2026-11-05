# Local HTTPS requests through Tor or SOCKS5

`zkweb fetch` performs HTTP locally and carries the TLS connection through an
explicit loopback SOCKS proxy. TLS terminates in zkWeb and at the configured
origin. A proxy sees the destination and connection timing, but does not receive
the HTTP headers or body as plaintext. The destination still sees the request,
including any account credentials or identifying content.

This mode has no Sphinx cover schedule or ZK proof integration. The existing
`zkweb request` command remains the separate, single-cell Sphinx worker
experiment. Its worker receives plaintext HTTP instructions; `fetch` does not
send those instructions to an application-layer worker.

## Build and configure a route

```sh
cd research-mixnet
make build
./bin/zkweb fetch --help
```

The proxy must already be running. zkWeb does not install or start Tor, read
proxy credentials from the environment, or silently switch routes. Use one of:

- `tor://127.0.0.1:9050`: SOCKS5 with required username/password authentication
  carrying a fresh isolation parameter for each client context.
- `socks5://127.0.0.1:1080`: ordinary SOCKS5 without Tor isolation. Its privacy
  properties depend on the proxy selected by the caller.

Only numeric loopback proxy addresses with a port are accepted. Proxy URL
credentials, paths, queries and fragments are rejected. IPv6 loopback is also
supported, for example `tor://[::1]:9050`.

For C Tor, configure a loopback SOCKS listener with authentication isolation:

```text
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
ClientRejectInternalAddresses 1
```

Keep Tor's DNS internal-address rejection controls enabled as well. The Tor
manual describes their scope and exceptions; configure any other SOCKS proxy
with equivalent resolved-address egress controls.
[Tor manual](https://man.archlinux.org/man/tor.1).

Tor authentication uses the current extended isolation encoding: username
`<torS0X>0` and an opaque random password. That parameter stays stable for one
reusable `webclient.Client`; a new client gets a different parameter. Each CLI
invocation creates a new client. The parameter is not an account credential or
HTTP header. Tor mode rejects a proxy that selects no authentication instead.
The SOCKS handshake cannot prove that the proxy is Tor, that its isolation
configuration is correct, or that different contexts get different exit IPs.
[Tor SOCKS extensions](https://spec.torproject.org/socks-extensions.html).

## Send requests

The target is one HTTPS origin, without a path or trailing slash, credentials,
query or fragment. The input supplies the relative path and optional query.
ASCII DNS names or their punycode representation are accepted; ambiguous IPv4
spellings, trailing-dot names and known local names are rejected.

```sh
# Read through an existing Tor proxy.
printf '%s\n' '{"method":"GET","path":"/items/1"}' |
  ./bin/zkweb fetch --target https://api.example.com \
    --proxy tor://127.0.0.1:9050 --input -

# Explicit credentials and repeated custom headers live in the input.
# Use an input file with permissions appropriate for its contents.
./bin/zkweb fetch --target https://api.example.com \
  --proxy tor://127.0.0.1:9050 --input request.json

# Arbitrary binary body: AAH/ decodes to bytes 00 01 ff.
printf '%s\n' '{"method":"POST","path":"/upload","headers":{"Content-Type":"application/octet-stream"},"body_base64":"AAH/"}' |
  ./bin/zkweb fetch --target https://api.example.com \
    --proxy tor://127.0.0.1:9050 --input -
```

Example `request.json`:

```json
{
  "method": "PATCH",
  "path": "/items/1?revision=2",
  "headers": {
    "Authorization": "Bearer YOUR_TEST_TOKEN",
    "Content-Type": "application/json",
    "X-Tag": ["one", "two"]
  },
  "body": "{\"name\":\"updated\"}"
}
```

Methods are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` and `OPTIONS`.
Header values can be a string or a nonempty string array. Names are
case-insensitive; duplicate spellings are rejected. `Host`, `Content-Length`,
hop-by-hop headers and proxy-control headers are reserved. Credentials and
cookies are sent only when explicitly supplied; responses do not populate a
cookie jar. Use either `body` or strict standard `body_base64`, never both.
Unknown, duplicate and null JSON fields are rejected.

## Responses, limits and failures

Stdout contains a JSON envelope with upstream `status`, end-to-end `headers`,
and either UTF-8 `body` or `body_base64` for other bytes. Upstream errors such as
404 preserve their status and body while making the command exit nonzero.
Redirect responses are returned without following their `Location`.

Request and response bodies default to a **1 MiB** limit each. Set
`--max-request-bytes` and `--max-response-bytes` independently, from 1 byte to
**16 MiB**. Request paths are limited to 8 KiB and headers to 64 KiB. The default
deadline is 45 seconds; `--timeout` accepts 1 second through 10 minutes. Bodies
are buffered within these bounds; this is not a streaming or file-download API.

Requests exceeding limits fail before transmission. After admission to the
HTTP transport, failures conservatively report `delivery_unknown`; a mutation
may already have executed. If available, the upstream status and headers are
retained, but an incomplete or oversized body is not returned as a complete
response. There is no automatic retry, including for a request containing an
idempotency header. Inspect or reconcile remote state before resubmitting.

The client uses fresh HTTP/1.1 connections, validates the destination's TLS
certificate, disables automatic response decompression, and inherits neither
environment proxies nor a cookie jar. No direct route exists in this mode.

## DNS and context boundaries

Destination hostnames are sent to the proxy using SOCKS domain addressing;
zkWeb performs no local destination DNS lookup. It rejects private/special IP
literals and statically known local names. It cannot inspect the proxy's DNS
results without changing that privacy boundary. **The trusted proxy must reject
resolved internal/private destinations.** The SOCKS bound-address reply is not
the resolved target address and is not used as evidence of public egress.

Create a distinct `webclient.Client` for each origin-scoped caller/job context.
The Go API supports repeated requests in one context, but no persistent session
store or browser cookie synchronization is implemented. Requests carry their
own explicit credentials; no previous request's authorization is copied.

## Validation and remaining work

Local tests use a SOCKS fixture forwarding opaque bytes to a TLS fixture. They
check certificate/SNI validation, an unresolvable destination hostname, binary
and repeated-header preservation, credential opacity at the proxy, context
isolation, no-auth downgrade refusal, limits, cancellation and no mutation retry
after a lost response. No live Tor anonymity or performance result is claimed.

HTTP/2, HTTP/3, WebSockets, browser-wide routing, a persistent session API, Nym
integration, anonymous authorization and proof capture remain future work.
The optional [offline TLSNotary verifier](response-verification.md) checks
already-produced presentations separately; it does not attach a proof to
`fetch` or repeat the request.
The [architecture](../research-mixnet/ARCHITECTURE.md) and
[implementation comparison](web-request-research.md) describe those boundaries.
