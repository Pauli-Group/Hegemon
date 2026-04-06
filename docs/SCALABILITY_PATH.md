# Scalability Path

This document records the current honest deployment path for Hegemon’s shipped shielded block lane. It is a topology and operations reference, not a consensus spec.

## Current shipping architecture

Hegemon now runs the shielded path on three layers:

- **Private or wallet-side proving edge**: wallets or trusted private services produce canonical native `tx_leaf` artifacts for shielded transfers.
- **Public authoring layer**: the authoring node selects verified native `tx_leaf` artifacts, builds one same-block native `receipt_root`, and seals only when that bundle is ready.
- **Public verification layer**: import verifies the commitment proof plus the same-block native `receipt_root`. The receipt-root verifier now defaults to the `verified_records` path, meaning it consumes the already-verified native leaf records instead of replaying every leaf verifier a second time.

The live low-TPS path is no longer `InlineTx`. The shipped path is:

- wallets submit native `tx_leaf` artifacts,
- the authoring node verifies and selects those native artifacts,
- the authoring node builds the commitment proof and native `receipt_root`,
- consensus verifies the commitment proof plus the native `receipt_root`.

There is no external public prover host in the normal shipping topology for this version.

## Immediate topology

The current deployment target is still simple:

- one public **authoring node** that accepts proof-ready shielded transactions, builds the commitment proof, builds the same-block native `receipt_root`, mines, and broadcasts blocks;
- any number of **full nodes** that sync, verify, relay, and optionally run wallets;
- users proving transactions locally or through private infrastructure they trust.

Current approved public join seed list for miners and full nodes:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:30333"
```

All miners and verifiers in the same testnet must use the same approved `HEGEMON_SEEDS` value to avoid peer partitions and forks. The first public authoring node after a full reset should not seed itself; bring it up first, then use the join seed list on every other node. All mining hosts must keep NTP/chrony time sync enabled because PoW headers beyond the future-skew bound are rejected.

## What scales now

The current scaling levers are no longer only “make more tx proofs.” They are:

- more user-side / private prover capacity, so more native `tx_leaf` artifacts are ready at block assembly time;
- faster authoring-time aggregation of those verified leaves into one `receipt_root`;
- cheaper import-time verification of that `receipt_root`.

The current product implementation already uses three practical levers on the block-artifact side:

- **Verified-record import**: the shipped receipt-root verifier consumes verified native leaf records by default. On the local `8`-leaf sample, the root step measured about `0.695s` on replay-heavy verification versus about `0.027s` on the records-only path, which is about a `26x` reduction for that step.
- **Mini-root hierarchy**: authoring now treats the native receipt-root build as deterministic `8`-leaf mini-roots plus an upper tree. This does not reduce fresh-build fold count by itself, but it sharply reduces recomputation after small changes.
- **Leaf and chunk caches**: repeated or near-repeated candidate sets can reuse verified leaves and cached chunk folds keyed by native artifact identity.

## What the current hierarchy buys

For a fresh full build, total fold count is still about `N - 1`. The hierarchy matters because it reduces recomputation and enables parallel work.

With `128` leaves and `8`-leaf mini-roots:

- one changed leaf touches at most `11` internal fold nodes instead of `127`, which is about `11.5x` less recomputation inside the block tree;
- exact-repeat candidates can skip the whole receipt-root build through the existing prepared-bundle cache;
- near-repeat candidates can reuse most lower-tree work through the native leaf/chunk caches.

At larger summary levels the savings get bigger. If an epoch root summarizes `1024` block roots, one changed block touches only the `10` parent nodes on its path to the epoch root instead of rebuilding the full `1023` internal-node tree.

## What parallelism buys

The native receipt-root builder now has a clear unit of work: deterministic mini-roots. That means the node can spread aggregation work across a dedicated local Rayon pool, controlled by `HEGEMON_RECEIPT_ROOT_WORKERS`.

The expected gain is wall-clock time, not fold-count reduction:

- on the fold stage of a `128`-leaf build, `16` workers should be materially faster than `1`;
- the realistic target remains roughly `11x` to `16x` fold-stage wall-clock improvement at `16` to `32` workers, depending on machine and cache warmth;
- the lower-tree caches are what turn that one-shot speedup into a practical repeated-authoring win.

The important honest caveat is that full cold-path timings are still dominated by native `tx_leaf` generation unless the benchmark uses a frozen leaf corpus. The clean product import question is therefore “how expensive is verifying and aggregating already-built native artifacts?”, not “how long does it take to generate all transaction proofs from scratch?”

`superneo-bench` now exposes that measurement path directly: `--emit-native-leaf-record-corpus <path>` writes a reusable native leaf-record corpus, and `--native-leaf-record-corpus <path>` reuses that corpus for `--measure-native-receipt-root-hierarchy`, `--measure-native-epoch-root-hierarchy`, and `--measure-native-receipt-root-build` so larger aggregation benchmarks do not accidentally charge fresh tx-proof generation. The repo-level regression entry point for that path is `./scripts/verify_native_receipt_root_scalability.sh`, and the native-backend-security CI job runs it on every change.

## Near-term roadmap

### Phase 0: ship native same-block aggregation

- one public authoring node;
- wallets and private provers produce proof-ready native `tx_leaf` artifacts;
- block authors attach a same-block native `receipt_root`;
- full nodes verify the commitment proof plus the native `receipt_root`;
- no external prover-worker market, no public recursive work queue, no pooled/private-prover desktop roles.

### Phase 1: make authoring cheaper operationally

Scale the part that now matters on the block-artifact side:

- keep the prepared-bundle cache hot for exact repeats;
- keep the native leaf and chunk caches hot for near repeats;
- schedule receipt-root work on a bounded local worker pool;
- keep proof-ready tx throughput high enough that authoring waits on aggregation rarely.

### Phase 2: extend the hierarchy

Once the block-level lane is stable:

- keep `transaction -> tx_leaf`,
- use deterministic `mini-root -> block root`,
- add `many block roots -> epoch root` off the hot path for archival, sync, or later compression work.

This remains an authoring and data-structure win even before any new succinct proof object exists.

### Phase 3: optional post-proof compression

If Hegemon later needs a compact block proof, it should sit on top of the current native `tx_leaf -> receipt_root` lane. That is a new cryptographic object, not an operational cleanup. It only becomes product-relevant if it beats the existing `verified_records` import path on bytes or verification time.

## What is explicitly not current product surface

The following are not part of the current shipping topology:

- `hegemon-prover` as a required deployment host,
- any external prover-worker market as part of the normal authoring path,
- pooled hash-worker participation in the desktop app,
- private-prover participation in the desktop app,
- recursive hot-path block proving as the default low-TPS lane.
