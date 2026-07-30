# Hegemon scalability path

## Active block data model

New blocks carry an ordered list of independently verifiable native SmallWood
transaction proofs. There is no block-level proof, proof-of-proof, receipt root,
`proven_batch`, or recursive artifact in the active authoring path.

For a block with `n` shielded transactions:

```text
B_block(n) = B_header + B_coinbase + sum(i = 1..n, B_action_i + B_tx_proof_i)
```

The former fixed recursive-block surcharge was 523,736 bytes per non-empty
shielded block. It is now zero:

```text
B_active_aggregate = 0
```

The proof-size admission cap is not a size claim. Release qualification must
measure the exact canonical transaction artifact produced by the selected
SmallWood profile.

## Throughput equation

For average transaction action bytes `A`, average transaction proof bytes `P`,
and sustained throughput `T` transactions per second:

```text
G_on(T) = 86400 * T * (A + P) bytes/day
```

There is no `aggregate_size / transactions_per_block` term. Throughput improves
only when the canonical transaction action or transaction proof becomes smaller,
or when the protocol deliberately changes which data every full node must retain.

## Verification

Block authors preflight every ordered transaction proof before exposing mining
work. Import verifies the same artifacts through the consensus verifier, derives
their canonical claims, binds them to the parent state and ordered DA projection,
then applies the state transition. Independent proofs may be verified in parallel
and cached, but parallelism does not change validity.

The 60-second block interval does not permit aggregate construction to consume
the mining window. Removing aggregate construction also removes its fixed memory,
latency, and block-byte costs.

## Historical compatibility

`RecursiveBlockV1`, `RecursiveBlockV2`, `ReceiptRoot`,
`SelfContainedAggregation`, candidate-artifact wire types, and their decoders
remain for historical replay only. New nodes can validate old recursive blocks.
New blocks reject candidate artifacts, `proven_batch`, and `block_artifact`.

Because old nodes required the recursive candidate, activating this rule requires
a coordinated protocol upgrade. It does not require deleting chain history or
resetting genesis.

## Security boundary

Removing the aggregate does not weaken transaction validity: the old aggregate
path already verified every native transaction proof before checking the extra
recursive artifact. The active security statement is therefore the conjunction
of the independently verified transaction statements plus the canonical ordered
state transition.

The remaining cryptographic assumptions are those of the transaction proof and
its hashes, commitments, transcript, parser, and implementation refinement. No
security claim is attributed to the retired aggregate.
