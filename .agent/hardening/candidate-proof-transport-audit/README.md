# Candidate proof transport audit (source-static, fail-closed)

Date: 2026-08-22

Verdict: the native inline transport already carries an opaque proof `Vec<u8>`
inside the exact canonical action bytes and re-runs the concrete verifier at
every validity boundary.  It does **not** yet constitute candidate integration:
V5/Delta and V6/Epsilon have no wallet/RPC/native route, both version bindings
remain outside backend and kernel dispatch, and their compiled verified proof
byte bounds remain zero.  No candidate profile was activated or frozen in this
audit.

## Exact byte path already available to a future inline route

1. The wallet owns `TransactionBundle.proof_bytes: Vec<u8>` and copies those
   bytes once into `ShieldedTransferInlineArgs.proof` before SCALE-encoding the
   action payload (`wallet/src/rpc.rs`, `wallet/src/node_rpc.rs`).
2. RPC base64-decodes one `public_args` byte vector.  Native admission exact-
   decodes that vector, validates its proof/statement binding, and retains the
   original `public_args`; it does not decode and re-encode the inline route
   payload (`node/src/native/node_impl.rs`).
3. Relay serializes the complete `PendingAction` once and peers exact-decode it.
   Peer admission invokes the independent proof verifier before durable group
   commit and rebroadcast (`node/src/native/service.rs`,
   `node/src/native/node_impl.rs`).
4. Sled stores the exact canonical `PendingAction` bytes.  Startup exact-decodes
   and re-encodes for equality; startup SmallWood sanitization invokes proof
   verification before a persisted transfer can become mineable
   (`node/src/native/storage.rs`, `node/src/native/node_impl.rs`).
5. Mining copies `PendingAction::encode()` directly into block `action_bytes`.
   Block import exact-decodes/re-encodes those bytes, extracts `args.proof` by
   value, binds it to the independently reconstructed transaction, and invokes
   `ParallelProofVerifier::verify_block_with_backend`
   (`node/src/native/node_impl.rs`, `node/src/native/block_flow.rs`).
6. Announce/range sync carries the canonical block body containing the same
   `action_bytes`.  Import, reorg suffix replay, and fresh-node canonical replay
   all converge on the same block verifier.  Persisted verification markers and
   process-local caches are diagnostic only and cannot skip proof verification.

The current V5/V6 envelope “lifecycle” unit tests compare caller-supplied cloned
byte arrays.  They are useful mutation comparators, but they are **not** evidence
that wallet, RPC, relay, sled, block transport, reorg, or restart ran.  The
release capability for lifecycle verification correctly remains false.

## Sidecars and caches

The candidate envelope source selectors reject sidecar, aggregate/receipt,
cache, and historical-wrapper substitution.  The native V3 sidecar transfer
route is rejected before payload decoding or proof-queue reservation.  Existing
unsafe `da_submitProofs` support is proposer-local legacy coordination and must
not be connected to a future candidate route.

## Remaining production blocker

There is intentionally no candidate action adapter to exercise end to end.
Adding one before the conventional-hash/QROM tournament chooses an identity
would freeze the wrong statement and route.  After selection, the required
integration test must use a retained real proof artifact and traverse actual
wallet request construction, RPC decoding, peer relay, sled reopen, mining,
block-body sync, reorg, and a fresh node while checking byte equality and exact
backend invocation counts at every stage.  Until then:

- V5/V6 backend dispatch: absent;
- V5/V6 kernel/action dispatch: absent;
- compiled verified proof byte bound: `0`;
- production authority: `false`.

Run the bounded source check with:

```text
python3 .agent/hardening/candidate-proof-transport-audit/check.py
```

The check pins topology only.  It must never be described as a proof, measured
artifact, runtime integration test, refinement theorem, or production gate.
