# Native Backend 128-Bit Known Gaps

1. This package is still an in-repo construction, not a claim of paper-equivalent Neo/SuperNeo implementation.
2. `commitment_binding_bits` still enters the floor through the explicit `commitment_assumption_bits` input.
3. The repo now computes and exposes the raw bounded-message random-matrix term, and that structural term is currently `0` bits for the implemented `8 x 8` geometry plus `max_commitment_message_ring_elems = 513`.
4. The timing harness is a regression screen, not a proof of constant time.
5. The review package prepares external cryptanalysis; it does not replace external cryptanalysis.
6. The chain architecture still has linear receipt-root verification and does not solve cold import.
