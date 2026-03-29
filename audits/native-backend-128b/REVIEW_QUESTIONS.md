# Native Backend 128-Bit Review Questions

1. Does the claimed 128-bit floor follow from the exact implemented challenge schedule, deterministic public-commitment reconstruction, the bounded-kernel Module-SIS reduction for the implemented message class, and the in-repo coefficient-space Euclidean SIS estimate of the active instance, or is there hidden composition loss or estimator slippage?
2. Is the bounded live message class in [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md) the exact class accepted by the product verifier, including coefficient bounds and message-length cap?
3. Can any accepted artifact encoding be rewritten into a distinct accepted encoding with the same meaning?
4. Can two distinct proof states collide under the implemented Fiat-Shamir transcript bytes?
5. Can the deterministic public-witness reconstruction accept mismatched public tx data, serialized STARK public inputs, commitment rows, or commitment digest?
6. Do the reference verifier and production verifier ever disagree on the bundled valid or invalid vectors?
7. Does the timing harness show gross class-dependent separation on the deterministic tx-leaf build path?
