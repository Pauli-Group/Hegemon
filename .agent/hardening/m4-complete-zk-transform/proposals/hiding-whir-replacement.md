# Proposal: replace, do not patch, the M4 opening layer

## Security objective

For any two witnesses satisfying the same public M4 statement, the distribution of the complete serialized proof view must be identical or bounded by an explicit negligible function when conditioned on the verifier's public coins. The simulator must emit roots, every scalar message, every opened leaf/tape/path, OOD values, folds, terminal data, retries, and aborts in verifier order without a witness.

## Route A: odd-field Boolean/R1CS compiler plus Hiding-WHIR

This route reuses the most complete existing theorem stack.

1. Define an odd two-adic base/extension field profile with at least the required concrete security.
2. Compile every retained Boolean/M4 constraint and chip call into a canonical R1CS instance, with range/Boolean constraints and a proved acceptance-preserving map.
3. Replace additive BaseFold commitments, folds, OOD samples, and terminal opening with the full CFW26/Plonky3 Hiding-WHIR carried relation.
4. Replace the benchmark hash/challenger with SHA-512/SHAKE256-512 commitments and transcript domain separation.
5. Instantiate the paper's simulator and RBR extractor for the exact field, code, query counts, mask budgets, and serializer.
6. Apply the exact BCS/CMS QROM theorem only after its premise map is complete.

Cost: a new arithmetization and PCS/IOP stack; current E384/E512 B128 wire totals do not apply.

## Route B: new characteristic-two additive theorem

This route preserves B128 arithmetic but requires new cryptographic work.

1. Prove t-query privacy for an additive Gao–Mateer randomized encoder that appends random coefficients *inside one codeword*, rather than interleaving separately opened message/mask lanes.
2. Construct characteristic-two private zero-evaders, masked sumcheck, code switching, and masked base case for the exact M4 committed relation.
3. Prove composable HVZK and RBR/special soundness for every round.
4. Implement the exact public-only whole-view simulator and canonical SHA-512/SHAKE256-512 transcript.
5. Recompute every tree, query, authentication, and proof-byte term from the resulting serializer.

Cost: a new theorem and implementation. E384 needs three B128 coordinate masks locally; E512 needs four. These ranks are necessary conditions only.

## Decision

Neither route is a source-local repair. Route A has the stronger existing theorem base but changes the field and arithmetization; Route B preserves M4's field but has the larger research-proof burden. Retain all production and complete-ZK flags as false until one route closes every row in `THEOREM_MAP.md`.

