# Scalability Path

This document records the current honest deployment path for Hegemon `0.10.0`. It is an operator and topology reference, not a consensus specification.

## Current shipping architecture

The shipped shielded block path now has one canonical block-artifact lane:

- **Private or wallet-side proving edge**: wallets or private prover infrastructure produce canonical native `tx_leaf` artifacts for shielded transfers.
- **Public authoring layer**: the authoring node verifies and selects those native `tx_leaf` artifacts, derives the canonical semantic tuple from parent state plus tx order, builds one same-block `recursive_block_v1` artifact, and seals only when that recursive bundle is ready.
- **Public verification layer**: block import verifies the ordered native `tx_leaf` artifact stream plus the same-block `recursive_block_v1` artifact.

The shipped `0.10.0` path is therefore:

- wallets submit native `tx_leaf` artifacts,
- the authoring node verifies and selects those native artifacts,
- the authoring node builds one same-block `recursive_block_v1`,
- consensus verifies that recursive artifact against the canonical ordered verified-leaf stream.

There is no external public prover host in the normal shipping topology for this release.

## What is explicit experimental surface

Two block-proof lanes remain in-tree, but they are not the shipped product surface:

- **`ReceiptRoot`** is the explicit native comparison lane. It still carries a parent-bound commitment proof plus a native receipt-root artifact. It is useful for comparison, diagnostics, and research, but it is not the default shipped path.
- **`RecursiveBlockV2`** is the explicit experimental tree lane. It currently has a real bounded-domain invariant and explicit verification plumbing, but it is not the shipped default lane.

The old `InlineTx` label remains only as historical compatibility vocabulary and fail-closed handling. It is not a shipped non-empty shielded block mode.

## Immediate topology

The current deployment target stays simple:

- one public **authoring node** that accepts proof-ready shielded transactions, builds the same-block `recursive_block_v1`, mines, and broadcasts blocks;
- any number of **full nodes** that sync, verify, relay, and optionally run wallets;
- users proving transactions locally or through private infrastructure they trust.

Current approved public join seed list for miners and full nodes:

    HEGEMON_SEEDS="hegemon.pauli.group:30333"

All miners and verifiers in the same testnet must use the same approved `HEGEMON_SEEDS` value to avoid peer partitions and forks. The first public authoring node after a full reset should not seed itself; bring it up first, then use the join seed list on every other node. All mining hosts must keep NTP/chrony time sync enabled because PoW headers beyond the future-skew bound are rejected.

## What scales now

The main scaling levers on the shipped path are:

- more wallet-side or private-prover capacity, so more native `tx_leaf` artifacts are ready before block assembly;
- faster authoring-time compression of the ordered verified leaf stream into one `recursive_block_v1`;
- cheaper import-time verification of the ordered `tx_leaf` stream plus the recursive block artifact;
- lower ciphertext transport pressure through DA sidecars rather than inline payload growth.

This is the important architectural point: the fixed block artifact is not the only growth driver. Chain growth still scales with the ordered transaction set and ciphertext availability bytes. The recursive block artifact only keeps the block-validity proof component constant-width.

## What the current split buys

The current split is:

- `transaction -> tx_leaf`
- `ordered verified tx_leaf stream -> recursive_block_v1`

That keeps the system operationally sane:

- transaction proving stays parallelizable at the edge;
- the chain sees one canonical block-validity object per non-empty shielded block;
- consensus and runtime do not need to switch between multiple live-looking block-proof contracts during normal operation;
- experimental lanes can stay in-tree without confusing the default release story.

## Sidecar staging contract

DA sidecar staging is intentionally local and ephemeral:

- `da_submitCiphertexts` and `da_submitProofs` are unsafe-only proposer/local RPCs, not public consensus APIs;
- staged ciphertexts and staged proof bytes live in proposer-local RAM only;
- a node restart drops those staged sidecars, so wallets/provers must restage before proofless `*_sidecar` transfers can be authored again.

That is the current recovery contract. Restart recovery is deterministic because the authoring node fail-closes or defers when local sidecar bytes are missing; it does not pretend those sidecars are durable chain state.

## Near-term roadmap

### Phase 0: ship the canonical recursive block lane

- wallets and private provers produce proof-ready native `tx_leaf` artifacts;
- block authors attach a same-block `recursive_block_v1`;
- full nodes verify the ordered native `tx_leaf` artifacts plus the recursive block artifact;
- no external prover-worker market, no public recursive work queue, no pooled/private-prover desktop roles.

### Phase 1: improve authoring throughput without changing the on-chain contract

Scale the parts that matter on the shipped lane:

- keep the prepared-bundle cache hot for exact repeats;
- keep the tx-leaf verification cache hot for near repeats;
- reduce recursive block proving latency on the authoring node;
- keep proof-ready tx throughput high enough that authoring rarely waits on aggregation.

### Phase 2: keep comparison lanes explicit

If operators or researchers want to run `ReceiptRoot` or `RecursiveBlockV2`, they should do so explicitly and measure them explicitly. Those lanes should not blur back into the shipped `0.10.0` release story.

### Phase 3: future compression work

If Hegemon later wants a different block proof, it must beat the current shipped lane on bytes, verifier cost, or authoring latency without weakening the release surface. That is a future cryptographic change, not an operational prerequisite for `0.10.0`.

## What is explicitly not current product surface

The following are not part of the current shipped `0.10.0` topology:

- `ReceiptRoot` as the default low-TPS block lane;
- `RecursiveBlockV2` as the default block lane;
- `InlineTx` as a valid non-empty shielded block lane;
- `hegemon-prover` as a required deployment host;
- any external prover-worker market as part of the normal authoring path;
- pooled hash-worker participation in the desktop app;
- private-prover participation in the desktop app.
