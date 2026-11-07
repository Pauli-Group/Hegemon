# Public submission for third-party wallets (v0.11.3 candidate)

`--rpc-methods=public-submit` is an explicit operator opt-in. The normal default
and `auto` remain `safe`. The public policy adds `hegemon_submitAction` to the
available safe method surface. It does not expose mining controls, topology,
bridge witness export, `da_submitCiphertexts`, or `da_submitProofs`. Inspect
`rpc_methods` on the selected node for its registered, capability-available
catalog. Disabled compatibility stubs are omitted from discovery; their existing
direct-call refusal payloads remain compatible. Permission to call a method
never grants permission to use an inactive proof route.

`0.11.3` is the product software label. Internal Cargo package versions remain
unchanged because the exact Cargo.lock bytes participate in the PrivateSpend
relation digest. This RPC change preserves those bytes and the existing proof
identity; the release checklist records the frozen lock hash.

The candidate is local implementation work. Release publication and live
operator deployment require their own approval after qualification; see
[the v0.11.3 release checklist](releases/v0.11.3.md).

## Wallet protocol and trust

The submission method is `hegemon_submitAction`, not `wallet_submitTransaction`.
The request is the existing `NativeActionRequest` and the response is the existing
`SubmitActionResponse`, or a JSON-RPC admission error. No key upload, hosted
prover, server note scanner, recovered-note telemetry, address-owner registration,
or replacement transaction format is introduced. Key custody, scanning,
decryption, witness construction and proof generation stay in the wallet.

The public route is the existing shielded-pool PrivateSpend family `1`, action
`15`. The source/network/circuit/crypto capability checks remain authoritative.
PrivateSpend deliberately hides its ordinary, HTLC, policy and treasury witness
branches. This RPC allowlist separates action families; it cannot determine
which private branch was proved. Filtering those hidden branches would require
a separate protocol design. It does not make other explicit protocol action
families publicly submitable.

Use the existing self-contained inline action, including its canonical proof and
ciphertext bytes. A client that first stages DA sidecars through
`da_submitCiphertexts` or `da_submitProofs` needs an inline-compatible path before
it can use this listener. The server does not substitute proof bytes, construct a
new action, or provide a privileged staging shortcut. Decoding, canonical
framing, network/version/source authorization, independent proof verification,
state validation, duplicate checks and mempool staging are still performed by
the existing production submission path.

A remote RPC operator can omit or misrepresent chain information and observe
connection/submission metadata, including network address and timing. This
feature does not provide independently authenticated light-client chain
integrity or network anonymity. The transport and the RPC operator remain part
of the wallet's trust model. Native RPC is plaintext HTTP; arrange the intended
remote transport outside the node and account for the browser extension's
transport and origin requirements. The native wallet's existing PQ-only URL
policy is unchanged by this third-party wallet access feature.

## Operator configuration

Use the selected network's verified manifest and a deliberately selected node
state directory. Add these options to that existing node command:

```text
--rpc-methods public-submit
--rpc-external
--rpc-cors chrome-extension://YOUR_EXTENSION_ID
```

`--rpc-external` explicitly binds beyond loopback. Without it, even a public-submit
listener remains loopback. Public-submit is public policy even when the transport
peer is loopback: a reverse proxy cannot turn a request into a privileged local
submission. External `unsafe` and `pool` remain rejected. Local `--wallet-rpc`
launcher behavior continues to select loopback `unsafe` for the local wallet.

The integrity-checked v0.11.3 launcher accepts:

```text
python3 start.py --public-submit-rpc --rpc-external --rpc-cors chrome-extension://YOUR_EXTENSION_ID
```

The launcher rejects combining `--wallet-rpc` with `--public-submit-rpc`, rejects
`--rpc-external` without the public option, and rejects using the new public option
with an older bundle. This command is for a separately approved v0.11.3 bundle;
editing a v0.11.2 bundle's label is not an upgrade.

Configure one exact browser `Origin` with `--rpc-cors`, without a path, credentials,
query or fragment. Use its canonical serialization: for example,
`https://wallet.example`, not `https://wallet.example/`, an uppercase hostname,
or an explicit default `:443` port. Omission leaves browser
access closed; wildcard is rejected for public-submit. This is not an
authentication mechanism: non-browser callers do not gain or lose authority
because of CORS. Obtain the browser's actual origin rather than substituting an
extension display name or URL path. Multi-origin lists are not supported.

The limiter keys clients by normalized transport IP. IPv4-mapped IPv6 addresses
share the corresponding IPv4 bucket. All forwarding headers, including
`Forwarded` and `X-Forwarded-For`, are ignored; v0.11.3 has no trusted-proxy
configuration. Clients behind a proxy or NAT share that transport IP's bucket.
Apply any per-end-user proxy controls at the proxy, without treating headers as
node authentication.

## Bounded admission

The public listener has these configurable defaults:

| Node option | Default | Meaning |
| --- | ---: | --- |
| `--rpc-public-requests-per-minute` | 60 | HTTP attempts plus additional batch items per normalized client IP in a fixed 60-second window |
| `--rpc-public-submissions-per-minute` | 6 | Submission attempts per normalized client IP in a fixed 60-second window |
| `--rpc-public-client-capacity` | 1024 | Maximum retained client buckets |
| `--rpc-public-client-ttl-secs` | 600 | Idle expiry before a bucket can be removed |
| `--rpc-public-request-concurrency` | 4 | Public requests admitted before body collection; held through worker and response-body lifetime |
| `--rpc-public-submission-concurrency` | 1 | Public submissions admitted concurrently |

There is no admission-permit waiting queue: exhausted capacity fails immediately.
Admitted work may still await Tokio scheduling or locks while holding its bounded
reservation. Public batches have at most eight items and retained response data
is capped at 8 MiB. The general rate limit charges each HTTP attempt before body
parsing, so malformed, oversized and timed-out bodies count; GET requests also
count. Each additional JSON-RPC batch item consumes another general request
charge, with no double charge for a single item. Each identified
`hegemon_submitAction` entry in a JSON-RPC batch consumes a submission attempt,
including malformed, duplicate and later capacity-denied attempts. A batch is not
one charge. Idle entries are expired before admitting a new client; a full table
rejects new clients rather than growing memory or evicting an active client's
rate history. The finite table and request limits are separate from the
per-client rate. Fixed windows can permit a burst across their boundary; they
are not a sliding-window guarantee.

Public verification uses a separate lane. It cannot acquire the reserved local
verifier permits. The existing peer/local/mining limits remain in force; the
default public lane permits one additional public verification, so the maximum
existing three plus public one is four concurrent verification reservations.
This reserves admission capacity, not CPU scheduling priority or a wall-clock
latency guarantee for local work.

Public safe reads share the bounded public request workers. Existing body,
decoded-byte, timestamp/page, action/proof-byte, proof-cache and mempool limits
still apply. Heavy safe reads can occupy those workers and exhaust public
capacity; adding submission permission does not make those reads cost-free.
The conservative one-verifier/no-permit-queue default limits accumulated expensive
work. Release qualification must record measured verifier latency and memory
on the intended hardware before increasing it; per-IP limits alone do not bound
global work from many clients.

Public HTTP body collection has a 10-second timeout, before method execution.
There is no hard CPU-time cutoff. HTTP timeout or disconnection cannot terminate
an already-running blocking verifier. Its reservation remains owned by the worker
until that work actually finishes, including failure. The public request
reservation also remains held while its response body is retained, and releases
when that body is consumed or dropped. Response frames are at most 16 KiB; socket
counts, operating-system buffers and remote acknowledgement are outside this
reservation bound. Limits do not prove
universal DoS resistance, operating-system fairness, socket/proxy correctness,
absolute wall-clock or RSS bounds, or network privacy.

## Responses, retry and uncertain spends

Stable JSON-RPC admission codes are:

| Code | Meaning |
| --- | --- |
| `-32055` | Response byte capacity exceeded; execution may already have completed |
| `-32056` | Public body collection timed out before method execution |
| `-32070` | Per-client submission rate exhausted |
| `-32071` | Finite client table full |
| `-32072` | Public request capacity exhausted |
| `-32073` | Public submission/verification capacity exhausted |
| `-32075` | Per-client general request rate exhausted |

A pre-execution admission error means the specified attempt did not enter the
denied stage. Response-capacity error `-32055` is different: the action may have
already been accepted and its outcome must be reconciled. A successful submission response means local node acceptance, not final
chain inclusion. Inspect the existing `SubmitActionResponse` success/error fields
as well as JSON-RPC errors; HTTP 200 alone does not mean acceptance.

A timeout, disconnected socket or lost response does **not** establish rejection.
The verifier or mempool operation may finish after the connection disappears.
Keep the original input reservation and exact action/proof bytes, reconcile the
same action identity against subsequent node/chain state, and retry only those
same bytes when appropriate. Do not automatically create another spend or free
uncertain inputs because a response was lost. Duplicate suppression remains the
existing production mechanism and does not replace wallet reconciliation.
