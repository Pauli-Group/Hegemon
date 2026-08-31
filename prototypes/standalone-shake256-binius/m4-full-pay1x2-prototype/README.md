# Full single-main M4 Pay1x2 prototype

This isolated crate translates the complete 2,448-byte private Pay1x2 witness and exact 478-byte `HGS2` public statement into native 64-bit Binius M4 operations. All 40 SHAKE256 Keccak-f permutations are inlined in one main circuit; there are no numbered chips and therefore no dependency on M4's currently unconstrained chip-call seam.

The circuit checks the fixed profile and native asset, 61-bit values, depth-32 position, one-call spend-key derivation, input/change authorization, three note commitments, full-digest nonzero rules, nullifier, depth-32 membership, exact public outputs, and non-modular integer conservation. The final public transport word contains six canonical statement bytes followed by two constrained zero bytes. All 478 canonical bytes remain verifier-supplied public inputs, including ciphertext hashes, network binding, and balance tag; the authoritative action adapter remains responsible for deriving those external fields.

Run the disk-light circuit build and scalar/M4 KAT:

    CARGO_TARGET_DIR=/private/tmp/hegemon-m4-full-pay1x2-target \
      cargo +1.97.1 run --release --locked --offline \
      --manifest-path prototypes/standalone-shake256-binius/m4-full-pay1x2-prototype/Cargo.toml

Only run a proof after `df -k .` shows at least 30,064,771,072 free bytes, and never run two heavy proving jobs concurrently:

    CARGO_TARGET_DIR=/private/tmp/hegemon-m4-full-pay1x2-target \
      cargo +1.97.1 run --release --locked --offline \
      --manifest-path prototypes/standalone-shake256-binius/m4-full-pay1x2-prototype/Cargo.toml \
      -- --prove --rate 3 --proof-out /private/tmp/hegemon-pay1x2-m4.proof

`--proof-out` is accepted only with `--prove`, and the file is written only after the honest roundtrip and every public/proof/trailing negative gate pass. The JSON report includes the exact proof SHA-256. Delete the disposable proof after independently recording its size and digest.

Acceptance requires the honest proof to verify, mutations in every public field to reject, a changed proof to reject, and trailing proof bytes to reject. The scalar relation's 30-case mutation matrix and representative mutations of every private region are unit tests.

The stock pinned backend compiled the complete circuit to 24,160 AND constraints in a `2^15` allocation, 566 ZERO constraints in a `2^10` allocation, no integer or binary-field multiplication constraints, and a `2^15` committed trace. The supervised rate sweep produced 129,424 / 109,264 / 110,864 / 119,728 proof bytes at inverse-rate logs 1 / 2 / 3 / 4. Rate two is the measured stock optimum. Adding the unchanged 12-byte direct-envelope geometry would be 109,276 bytes, but that is explicitly a projection rather than an encoded route because the current prototype envelope has no M4 backend identifier. The exact measurement and validation flags are frozen in `measurements/stock-rate-sweep-2026-08-21.json`.

This prototype is deliberately not a security claim. Pinned upstream M4 is transparent rather than zero knowledge and uses the nonqualifying 96-bit/SHA-256/GF(2^128) profile. `strict_pq128` and `production_authorized` therefore remain false regardless of proof size.
