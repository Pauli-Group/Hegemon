# Native Backend 128-Bit Break-It Rules

A reviewer wins if they can do any of the following against the packaged artifacts and claims:

1. Produce a verifying `NativeTxLeafArtifact` without the claimed witness/opening relation.
2. Produce a verifying `ReceiptRootArtifact` without the claimed fold relation.
3. Make the production verifier and the reference verifier disagree on the same vector.
4. Find a noncanonical encoding that is still accepted.
5. Find a transcript/domain-separation alias that changes semantics without changing accepted transcript bytes.
6. Show that the code-derived 128-bit floor is mathematically overstated for the exact implemented construction.
7. Show gross secret-dependent timing separation on the exercised tx-leaf build path that the timing harness misses or understates.
