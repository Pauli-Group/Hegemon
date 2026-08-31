# Native M4 selected-wire Pay1x2 frontier

This artifact composes the exact full single-main M4 Pay1x2 circuit with the previously verified terminal-message, compact-Merkle-frontier, and verifier-known-FRI-value wire patch. It is a real full-relation measurement, not a geometry model.

Starting from pinned Binius64 revision `3f96163049f680b2909f6545690bd929f1b48c44`, apply [`../selected-value-patch/codex-terminal-compact-selected-v1.patch`](../selected-value-patch/codex-terminal-compact-selected-v1.patch), whose SHA-256 is `fa442ca4fd18fec239e874134c4cd41d82e2caafacfe987c9ea5867ededd45ee`. Then build [`../m4-full-pay1x2-prototype`](../m4-full-pay1x2-prototype) against that patched tree with Rust 1.97.1, Cargo offline and locked, incremental compilation disabled, and release/test debug information disabled.

The exact rate sweep was:

| log inverse rate | raw proof bytes |
|---:|---:|
| 1 | 95,280 |
| 2 | 78,576 |
| 3 | **72,880** |
| 4 | 72,912 |

Rate 3 is the verified minimum. With the fixed 12-byte research envelope, the selected result is **72,892 bytes**. This is 171,360 bytes (70.1571%) below the previous 244,252-byte frontier and 49,234 bytes below the requested half-size threshold of 122,126 bytes. The emitted raw proof SHA-256 is `cdad1f6b7039d6a74a4e470f91a89c6d4f8750f3fb53e0c62adb27201c9b785f`.

The circuit remains the exact 2,448-byte private witness and 478-byte canonical public statement, with 40 inline SHAKE256 permutations in a single M4 main circuit and no numbered chips. It has 24,160 AND constraints in a `2^15` committed tier. Honest verification, all public mutations, proof mutation, and trailing-byte rejection passed at every measured rate. The scalar relation additionally rejects its 30-case mutation matrix and agrees with 16 deterministic scalar-to-M4 differential fixtures.

This is prototype-only evidence. Pinned upstream M4 is transparent, not zero knowledge, and uses a nonqualifying 96-bit/SHA-256/GF(2^128) profile. `strict_pq128` and `production_authorized` remain false. Proof size is the only promoted metric here.
