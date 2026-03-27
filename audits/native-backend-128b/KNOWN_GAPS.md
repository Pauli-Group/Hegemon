# Native Backend 128-Bit Known Gaps

1. This package is still an in-repo construction, not a claim of paper-equivalent Neo/SuperNeo implementation.
2. `commitment_binding_bits` currently enters the floor through the explicit `commitment_assumption_bits` input; the repo does not yet derive that bound directly from the ring geometry alone.
3. The timing harness is a regression screen, not a proof of constant time.
4. The review package prepares external cryptanalysis; it does not replace external cryptanalysis.
5. The chain architecture still has linear receipt-root verification and does not solve cold import.
