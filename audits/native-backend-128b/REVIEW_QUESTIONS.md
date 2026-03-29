# Native Backend 128-Bit Review Questions

1. Does the claimed 128-bit floor follow from the exact implemented challenge schedule, deterministic public-commitment reconstruction, and commitment geometry, or is there hidden composition loss?
2. Can any accepted artifact encoding be rewritten into a distinct accepted encoding with the same meaning?
3. Can two distinct proof states collide under the implemented Fiat-Shamir transcript bytes?
4. Can the commitment-opening path accept mismatched witness/seed/rows under the active parameter set?
5. Can the fold verifier accept parent rows or parent digests that are not the exact challenge-mixed children?
6. Do the reference verifier and production verifier ever disagree on the bundled valid or invalid vectors?
7. Does the timing harness show gross class-dependent separation on the deterministic tx-leaf build path?
