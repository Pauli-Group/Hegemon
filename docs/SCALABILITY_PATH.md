# Scalability Path

This document records the current honest deployment path after the `InlineTx` pivot. It is a topology and operations reference, not a consensus spec.

## Current shipping architecture

Hegemon now runs on two planes:

- **Private proving edge**: users, wallets, or trusted private services produce canonical transaction proofs before the transaction becomes admissible.
- **Permissionless admission core**: the public network handles canonical tx proof bytes, ordered statement data, and the parent-bound commitment proof.

The live low-TPS path is `InlineTx`, not recursive hot-path aggregation. That means:

- wallets submit proof-ready transactions,
- the authoring node verifies and selects proof-ready traffic,
- the authoring node builds the commitment proof,
- consensus verifies ordered tx proofs directly during import.

There is no external public prover host in the normal shipping topology for this version.

## Immediate topology

The current deployment target is simple:

- one public **authoring node** that accepts proof-ready transactions, builds the commitment proof, mines, and broadcasts blocks;
- any number of **full nodes** that sync, verify, relay, and optionally run wallets;
- users proving transactions locally or through private infrastructure they trust.

Current approved public join seed list for miners and full nodes:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:30333"
```

All miners and verifiers in the same testnet must use the same approved `HEGEMON_SEEDS` value to avoid peer partitions and forks. The first public authoring node after a full reset should not seed itself; bring it up first, then use the join seed list on every other node. All mining hosts must keep NTP/chrony time sync enabled because PoW headers beyond the future-skew bound are rejected.

## What scales now

The current scaling lever is proof-ready transaction production.

- More user-side / private prover capacity means more proof-ready transactions.
- More proof-ready transactions means the authoring node has more admissible work ready at block assembly time.
- The parent-bound block step is only the commitment proof, not recursive tx-proof compression.

Local validation already resolved the low-TPS question: the dead recursive block-proof lane lost, so the live system should scale by parallel tx-proof generation and smaller native transaction artifacts before it revisits any post-proof compression idea.

## Near-term roadmap

### Phase 0: ship native direct verification

- one public authoring node;
- wallets and private provers produce proof-ready native `TxLeaf` artifacts;
- full nodes verify ordered native tx artifacts plus the commitment proof;
- no external prover-worker market, no public recursive work queue, no pooled/private-prover desktop roles.

### Phase 1: raise proof-ready throughput

Scale the part that actually matters:

- faster tx proving at the edge,
- smaller tx proofs,
- cleaner proof-ready admission semantics,
- better proof transport / DA placement for larger blocks.

### Phase 2: federated authoring

After the single-authoring-node deployment is stable, add more public authoring nodes or pools that all consume proof-ready txs and mine honestly on the same consensus rules.

### Phase 3: optional background compression

If Hegemon later needs recursive compression, it belongs off the hot admission path unless a new witness-free post-proof primitive beats `InlineTx` locally on bytes and active-path latency first.

## What is explicitly not current product surface

The following are not part of the current shipping topology:

- `hegemon-prover` as a required deployment host,
- any external prover-worker market as part of the normal authoring path,
- pooled hash-worker participation in the desktop app,
- private-prover participation in the desktop app,
- recursive hot-path block proving as the default low-TPS lane.
