# Compact ZK client/server exchange

`zk-request` and `zk-api` use the compact binary transport by default. Keys,
credentials, profile identifiers and expected destinations are configured once.
They are not repeated in request envelopes. The existing Groth16 circuit,
trusted setup and logical request digests remain unchanged.

Use `--wire legacy` explicitly when talking to an older listener. There is no
automatic downgrade or retry after a failed compact request. CLI output remains
JSON with `body_base64` for scripts; that local output format is separate from
the binary messages exchanged with the listener.

Rust library callers use `client::request_compact` or
`client::api_request_compact`; the original `request` and `api_request` functions
retain the legacy transport for compatibility.

## Wire format

Versioned HTTP routes define the format without another magic or version field
in every body. All integers below are unsigned. Lengths use canonical unsigned
LEB128: redundant encodings, overflow and lengths beyond the field limits are
rejected. HTTP Content-Length frames each complete message, so the final body
needs no redundant length prefix.

| Exchange | Route | Binary body |
| --- | --- | --- |
| Challenge | GET `/b1/c` | server instance: 32 bytes; nonce: 32 bytes; expiry: 8 bytes, big endian |
| Record request | POST `/b1/r` | nonce: 32; tag: 32; proof: 128; method: 1; key length + key; remaining raw payload |
| Gateway request | POST `/b1/a` | nonce: 32; tag: 32; proof: 128; packed method/count: 1; path/query length + bytes; header pairs; remaining raw payload |
| Record response | HTTP application status | raw record/result bytes |
| Gateway response | HTTP 200 | packed status/count: 1–2 bytes; header pairs; remaining raw upstream body |

Each header pair is name length + name bytes + value length + value bytes.
Selected request headers retain their canonical lowercase names, stable name
ordering and repeated-value ordering. A record request has no header-count field.
The method codes are GET=0, HEAD=1, POST=2, PUT=3, PATCH=4, DELETE=5, OPTIONS=6.
Record mode accepts GET, POST, PUT and DELETE.

Gateway requests combine method and header count as `method_code * 33 + count`
in one byte. Counts range from 0 to 32; codes above 230 are rejected. Replies
combine status and count as `(status - 200) * 33 + count`, encoded as canonical
unsigned LEB128. Codes above 13199 are rejected. An empty HTTP 200 upstream
reply therefore needs only one envelope byte; the format never repeats the
known origin or a format string.

Request and response bodies use `application/octet-stream`. There are no text
proof headers, JSON envelopes, base64 body expansion or repeated upstream URLs
on this transport. Provider error bodies remain raw application data. Protocol
rejections use HTTP error status and an empty body. An upstream 401, redirect or
503 remains distinct from a gateway authorization or delivery failure.

## Size and connection behavior

| Authorization field | Binary bytes | Legacy text value bytes |
| --- | ---: | ---: |
| Compressed Groth16 proof | 128 | 172 base64 |
| Randomized public tag | 32 | 64 hex |
| One-use challenge identifier | 32 | 64 hex |
| Total | 192 | 300 |

The legacy authorization header lines occupy 353 bytes including names and
separators; compact mode puts the 192 raw bytes in the body. Operation metadata,
HTTP framing and the actual payload are additional. A four-byte record key has
198 bytes of total compact request overhead before its payload.

A challenge is exactly 72 bytes. Challenge and operation can reuse one HTTP/1
connection within a CLI call. They remain two exchanges; there is no persistent
session with an implicit nonce. A connection accepts at most two HTTP requests,
with a five-second header/idle deadline. The current implementation does not claim the
160-byte session design discussed earlier, or a minimum across all ZK schemes.

The end-to-end tests compare captured application-message sizes and reproducible
HTTP/1 request serialization for identical operation and proof values. These
measurements exclude TCP/TLS framing and are not network packet captures.

## Authorization and delivery boundaries

The server derives the group root and request digest locally. The client
reconstructs the protocol/profile/destination context from its configuration
instead of receiving another copy in the challenge. A mismatched profile or
expected upstream therefore fails proof verification; compact mode does not
advertise the upstream for a pre-proof string comparison.

The server consumes a recognized nonce before decoding the rest of its compact
request. Malformed metadata or proof bytes cannot leave that nonce reusable.
Expiry, instance/destination binding, canonical field and curve-point decoding,
size limits and the current no-retry behavior remain enforced.

ZK hides the member secret and membership path. Ordinary CRUD still requires the
server to receive the operation and its inputs. Responses are ordinary results;
the server does not produce a proof of correct computation. Request encryption
from a cooperating destination remains separate work.

The listener still accepts numeric-loopback HTTP endpoints. Remote authenticated
HTTPS deployment is separate from this transport change. See the
[gateway guide](zk-api.md) and [listener guide](zk-listener.md) for setup and
trust assumptions.

## Verification

`make test-zk` runs the real two-member client/server loop, persistent record
CRUD, all seven gateway methods, 1 MiB binary payloads, malformed encodings,
fresh-proof tampering, replay, nonce consumption and profile/destination binding.
Legacy tests explicitly select `--wire legacy`.

`make test-zk-live` additionally checks compact GET/HEAD against GitHub and all
seven methods against httpbingo using disposable inputs. Set
`ZKWEB_ZK_COMPACT_REPORT=/absolute/path/compact-live.json` to save sanitized
GitHub compact sizes and public response identifiers. No proof, credential,
challenge, tag, echoed source address or response body is written to the report.

The [2026-11-05 compact GitHub run](validation/zk-compact-live-2026-11-05.json)
and [compact method run](validation/zk-compact-methods-live-2026-11-05.json)
passed against the real public HTTPS APIs. For the captured GitHub GET, the
equivalent legacy and compact messages measured:

| Component | Legacy bytes | Compact bytes |
| --- | ---: | ---: |
| Challenge body | 358 | 72 |
| Serialized HTTP/1 operation request | 810 | 459 |
| Gateway response body/envelope | 21,385 | 15,866 |

The request is 43.3% smaller in this comparison. Header contents and payloads
affect the totals; these are one run's message sizes, not a general throughput
benchmark or TCP/TLS packet measurement. The response contains the same 14,629
upstream body bytes plus header metadata, without base64 expansion.
