# Native Backend 128-Bit Review Questions

1. Does the claimed 128-bit floor follow from the exact implemented challenge schedule, deterministic public-commitment reconstruction, the bounded-kernel Module-SIS reduction for the implemented message class, and the in-repo coefficient-space Euclidean SIS estimate of the active instance, or is there hidden composition loss or estimator slippage?
2. Does `attack_model.json` contain all of the exact numeric inputs needed to recompute `current_claim.json`, and does `native-backend-ref verify-claim --package-dir ...` agree with the packaged claim with zero mismatches?
3. Does `claim_sweep.json` show a locally stable claim surface around the active point, or is the `128`-bit floor balanced on a fragile cap choice for `max_commitment_message_ring_elems` or `max_claimed_receipt_root_leaves`?
4. Does the packaged verified-aggregation note accurately describe the shipped `tx_leaf -> receipt_root` lane, or does the implementation prove less than the note claims?
5. Is the bounded live message class in [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md) and `message_class.json` the exact class accepted by the product verifier, including coefficient bounds and message-length cap?
6. Can any accepted artifact encoding be rewritten into a distinct accepted encoding with the same meaning?
7. Can two distinct proof states collide under the implemented Fiat-Shamir transcript bytes?
8. Can the deterministic public-witness reconstruction accept mismatched public tx data, serialized STARK public inputs, commitment rows, or commitment digest?
9. Do the packaged reference verifier report and packaged production verifier report ever disagree on the bundled valid or invalid vectors?
10. Does the timing harness show gross class-dependent separation on the deterministic tx-leaf build path?
11. The active ring is now `Z_q[X]/(X^54 + X^27 + 1)` under the `GoldilocksFrog` profile. The in-repo claim still operates at the flattened coefficient-space Euclidean SIS level rather than claiming ring-structured hardness. Does this quotient enable any algebraic or combinatorial attack on the exact flattened `(n_eq=594, m=4104, q, B_2=16336)` SIS instance that would place it below the stated 872-bit quantum floor?
