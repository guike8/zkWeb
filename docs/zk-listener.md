# ZK authorization listener

zkWeb's listener closes the request loop: a client proves authorization, the
listener verifies the proof against the exact HTTP request, and only then does
it execute create, read, update or delete. A different authorized group member
can use the same service without sending a member identifier or credential.

This stage protects the authorization secret and its membership witness. The
listener sees the request method, record key, body and result, and stores record
values in plaintext. FHE is deferred; its separate implementation is saved on
the local `feat/encrypted-crud` branch. Anonymous authorization does not provide
network anonymity: source addresses, timing, sizes and public group/profile
identifiers remain visible.

## Build and close the loop

From the repository root:

```sh
cd research-mixnet
make build
make build-zk

# Offline, trusted provisioning. The default is four members; maximum sixteen.
./bin/zkweb zk-setup --output /tmp/zkweb-listener-demo --members 4

# Keep this process running. A fresh state file is created on first start.
./bin/zkweb zk-listen \
  --server-dir /tmp/zkweb-listener-demo/server \
  --state-file /tmp/zkweb-listener-records.json \
  --listen 127.0.0.1:0
```

The listener prints a READY JSON line containing its allocated URL. In another
terminal, replace `PORT` below with that port. The setup output lists the actual
client directories; the example uses the first member's `client-0` directory.

```sh
./bin/zkweb zk-request \
  --client-dir /tmp/zkweb-listener-demo/client-0 \
  --url http://127.0.0.1:PORT --method POST --key note-1 --data 'hello'

./bin/zkweb zk-request \
  --client-dir /tmp/zkweb-listener-demo/client-0 \
  --url http://127.0.0.1:PORT --method GET --key note-1

./bin/zkweb zk-request \
  --client-dir /tmp/zkweb-listener-demo/client-0 \
  --url http://127.0.0.1:PORT --method PUT --key note-1 --data 'updated'

./bin/zkweb zk-request \
  --client-dir /tmp/zkweb-listener-demo/client-0 \
  --url http://127.0.0.1:PORT --method DELETE --key note-1
```

The client posts a compact binary envelope to `/b1/r`, carrying the selected
operation and key. POST creates a record, GET reads it, PUT replaces it and
DELETE removes it. All group
members are authorized for all records in this listener. There is no per-user
record isolation or hidden ownership rule.

Keys contain 1–128 ASCII letters, digits, underscores or hyphens. Values can be
arbitrary binary data up to 64 KiB, with at most 1024 live records. POST and PUT require exactly one of
`--data TEXT` or `--data-file /path/to/file`; `--data ''` creates or updates an
empty value. GET and DELETE take no data flag. The local result contains exactly
`format`, `method`, `key`, numeric HTTP `status` and `body_base64`, preserving
returned binary bytes. A missing record returns 404 and a duplicate create
returns 409. These application statuses are normal structured results.

The CLI only accepts numeric loopback HTTP origins. It disables ambient proxy
configuration, redirects and automatic retries. Its request deadline defaults
to 60 seconds, configurable from 1 second to 5 minutes. A failed or cancelled
request may have committed a write; launched backend failures are conservatively
reported as unknown delivery. Reconcile the record before retrying a mutation.

## The proof statement

This is a distinct Groth16 circuit over BN254 using Poseidon. It does not reuse
the wallet payment circuit or require funding a note. The private witness is:

- A nonzero authorization secret.
- Its Merkle membership path and four private index bits.
- Fresh private per-proof blinding randomness.

The four public inputs are the authorized group root, two 128-bit limbs of the
request's SHA-256 digest, and a blinded authorization tag. The circuit enforces
that the secret hashes to a leaf in the pinned authorization tree and that the
tag is Poseidon of its domain, secret, both digest limbs and private blinding.
The digest inputs participate in constraints; they are not unused public labels.
The two limbs preserve all 256 digest bits without reducing the full digest
modulo the field.

The tree has sixteen slots and a private four-level membership path. Provisioning
can authorize one to sixteen members; a small actual group offers a small
anonymity set. All members share the same public proving parameters and root.
Fresh proof randomness and private tag blinding avoid a stable member identifier,
including when a listener repeats a challenge. The listener never receives the
secret, leaf index, path or individual credential file.

The client and listener compute the same domain-separated, length-prefixed
request transcript. It binds the protocol and profile, fresh listener instance,
server challenge, expiry, exact method, exact record path, body length and body
bytes. The listener recomputes the digest from the bytes it actually handles.
Authorization therefore fails if an intermediary changes the method, key/path,
body or proof.

The proof is 128 compressed bytes. Canonical validated point deserialization and
exact-length checks apply before verification. The default
[compact transport](compact-zk-client-server.md) puts the proof, tag and nonce
into 192 raw bytes in the request body, followed by the operation and its inputs.
Use `--wire legacy` explicitly for the earlier `/records/KEY` transport with
`X-ZkWeb-Challenge`, `X-ZkWeb-Tag` and `X-ZkWeb-Proof` headers. There is no automatic
fallback. Record contents remain plaintext to this loopback service.
The [circuit implementation](../research-mixnet/zk-listener/src/crypto.rs)
contains the native and constrained statement.

## Challenges, persistence and trust

Challenges use 256-bit randomness, expire after 120 seconds and live in a bounded
server cache. A recognized challenge is consumed before decoding or verifying
its proof, including on a failed attempt. A replay cannot repeat CRUD execution.
A fresh instance identifier and empty challenge cache on restart reject proofs
from an earlier listener process.

The record store persists across restarts using an exclusive state lock and
atomic file replacement. A success response follows durable mutation storage.
An uncertain storage failure stops the instance until recovery. The state is
plaintext and its checksum/profile pins are not a proof of correct execution or
protection against a malicious server rolling back its own files. Cancellation
does not provide transaction rollback.

Provisioning is a trusted offline operation. It creates fresh Groth16 setup
material and credentials; there is no production multiparty ceremony or shipped
development credential. The provisioner knows the generated member secrets and
can impersonate those members. Honest setup and trustworthy distribution of the
pinned profile are required. Hash pins detect disagreement with that trusted
profile, not an untrusted provisioner's dishonesty.

Only the manifest and verifying key belong on the listener host. Each client
receives its proving key, private credential and manifest. Protect the client
directory, shell history and local process/output access. A shared machine's
administrator can read both roles' memory and files; local testing is not an
isolation boundary.

HTTP handling is bounded and loopback-only. This prototype does not supply a
remote authenticated deployment, production rate admission, general website
logins, authorization revocation, per-user data isolation or a proof that the
server honestly performed CRUD. Ordinary existing websites need an application
adapter to accept this proof protocol.

The experimental [API gateway](zk-api.md) supplies that adapter for configured
HTTPS origins: it verifies authorization and forwards permitted ordinary HTTP
requests. Existing APIs do not need to parse the Groth16 proof themselves.

## Verification

```sh
make test-zk
```

This target runs the cryptographic/backend checks and the opt-in real CLI
integration. Ordinary Go tests skip that integration unless `ZKWEB_ZK_CLI`
selects an explicit built executable. The
[CLI lifecycle fixture](../research-mixnet/internal/zke2e/zk_test.go) covers two
members, all four methods, binary and empty values, the 64 KiB body boundary,
restart persistence, replay rejection and independent method/path/body/proof
tampering. Its checks assert that request contents are visible by design while
credential fields stay out of the HTTP authorization envelope.

The [compact CLI fixture](../research-mixnet/internal/zkapi_e2e/zk_compact_test.go)
additionally checks compact record CRUD and gateway requests, raw 1 MiB bodies,
canonical length decoding, nonce consumption after malformed attempts,
profile/destination binding, delivery errors and byte comparisons. A direct TCP
test checks challenge/request connection reuse, the two-request cap and the
five-second idle bound.
