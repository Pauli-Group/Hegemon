# Native Backend Verified Aggregation

This note defines the actual shipped security object of Hegemon's native `tx_leaf -> receipt_root` lane. It is not Neo/SuperNeo CCS soundness. It is the exact verified-leaf aggregation guarantee implemented by the current product path.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8"`

Exact code paths:

- tx-leaf verification: [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs)
- receipt-root verification: [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs)
- fold canonicalization: [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs)

## What The Shipped Lane Actually Verifies

The live native lane has two stages:

1. a `tx_leaf` artifact proves that one canonical public tx view, one canonical receipt, one serialized STARK public-input object, one STARK proof byte string, and one deterministic lattice commitment all agree under the active backend parameters;
2. a `receipt_root` artifact aggregates a list of those tx-leaf artifacts by replaying every tx-leaf verification and then replaying every fold recomputation over the verified leaves.

The key fact is that `receipt_root` verification does not trust precomputed leaf summaries. It reconstructs them.

## The Verified-Leaf Aggregation Guarantee

Call a native tx-leaf artifact `valid` if `verify_native_tx_leaf_artifact_bytes_with_params` accepts it under the active parameter set. Call a receipt-root artifact `valid` if `verify_native_tx_leaf_receipt_root_artifact_bytes_with_params` accepts it for a given ordered list of tx-leaf artifacts.

### Theorem

If `verify_native_tx_leaf_receipt_root_artifact_bytes_with_params(params, artifacts, artifact_bytes)` accepts, then all of the following are true:

1. every supplied tx-leaf artifact in `artifacts` individually passes `verify_native_tx_leaf_artifact_bytes_with_params` under the same `params`;
2. for every accepted leaf, the verifier rechecks:
   - artifact version
   - parameter fingerprint
   - `spec_digest`
   - relation id
   - shape digest
   - canonical public tx view
   - canonical receipt
   - serialized STARK public inputs
   - STARK proof verification
   - deterministic witness reconstruction
   - deterministic commitment rows and digest
   - tx-leaf statement digest
   - tx-leaf proof digest
3. the receipt-root verifier rebuilds the ordered leaf list used for aggregation from those verified leaves, not from unauthenticated root metadata;
4. for every fold step, the verifier recomputes:
   - the fold challenge vector
   - the parent commitment rows
   - the parent commitment digest
   - the parent statement digest
   - the fold proof digest
5. the verifier rejects if any leaf digest, any parent row, any parent digest, or any fold proof digest differs from the recomputed value;
6. the accepted root statement digest and root commitment digest are exactly the ones obtained by replaying that full deterministic process over the verified leaves.

### Why This Is Stronger Than A Hash Chain

The root lane does not merely hash whatever leaf metadata the artifact provides. It uses the full tx-leaf verifier on each supplied child artifact before that child is allowed into the aggregation state. That means the root is closed over verified leaves, not only over claimed leaves.

### Why This Is Still Not CCS Soundness

The fold layer does not independently prove that an arbitrary witness satisfies a generic CCS relation. The current `FoldedInstance` type carries only:

- `relation_id`
- `shape_digest`
- `statement_digest`
- `witness_commitment`

It does not carry folded residual vectors, evaluation claims, or sum-check state. The fold verifier therefore proves deterministic recomputation correctness for the shipped aggregation object, not Neo/SuperNeo-style CCS knowledge soundness.

## Exact Code-Level Replay

The receipt-root verifier in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs):

1. decodes and version-checks the root artifact,
2. rechecks parameter fingerprint and `spec_digest`,
3. rebuilds the active backend keys from the live params and `TxLeafPublicRelation`,
4. iterates through the supplied tx-leaf artifacts and calls the tx-leaf verifier for each one,
5. checks that each root-artifact leaf record matches the verified child statement digest, commitment digest, and proof digest,
6. rebuilds the fold tree by calling `backend.fold_pair` on the verified children,
7. checks the recorded fold challenge vector, parent rows, parent commitment digest, parent statement digest, and fold proof digest against the recomputed values,
8. runs `backend.verify_fold` on that recomputed proof state,
9. rejects if any unused fold steps remain,
10. checks the recorded root statement digest and root commitment digest against the replayed root.

That replay is the actual shipped guarantee.

## Review Consequence

External reviewers should evaluate the native lane as two composed claims:

1. tx-leaf verification is sound only because the tx-leaf verifier replays the STARK verification and deterministic commitment reconstruction;
2. receipt-root verification is sound as verified-leaf aggregation because it replays every tx-leaf verification and every fold recomputation over those verified leaves.

This is the exact object the current review package should package and attack.
