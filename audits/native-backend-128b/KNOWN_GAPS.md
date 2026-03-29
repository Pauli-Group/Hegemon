# Native Backend 128-Bit Known Gaps

1. This package is still an in-repo construction, not a claim of paper-equivalent Neo / SuperNeo implementation.
2. The active family now defines the exact bounded-kernel Module-SIS reduction for the implemented message class and computes one explicit coefficient-space Euclidean SIS estimate for the live instance, but that concretization and estimator choice still need independent external review and cryptanalysis.
3. The active floor is still tied to the explicit bounded-message cap `max_commitment_message_ring_elems = 513` and the explicit receipt-root cap `max_claimed_receipt_root_leaves = 128`; if either cap grows, the floor must be recomputed and may fall.
4. The timing harness is a regression screen, not a proof of constant time.
5. The review package prepares external cryptanalysis; it does not replace external cryptanalysis.
6. The chain architecture still has linear receipt-root verification and does not solve cold import.
