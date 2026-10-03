# Native M4 HEG-S4V2 Merkle-parent prototype

This isolated crate implements one exact `HEG-S4V2` `merk.nd1` invocation as a single native-word
M4 main circuit. It absorbs the canonical 133-byte frame, applies SHAKE256 padding (`0x1f` plus the
final `0x80` bit), runs one full Keccak-f[1600] permutation, and exposes exactly seven 64-bit output
words. The two 56-byte children are private witness words. There are no M4 chip calls, so the
upstream warning that chip calls are not connected to main does not apply to this circuit.

The hard-coded KAT uses `left[i] = i` and `right[i] = 0x80 + i`. Both the scalar Hegemon semantic
implementation and the native circuit produce:

    9516d20f587a6a037ba7fa9f9321a9d3fa45faf786aa48b927f6d18e95c36b390fa8f38f5292ede553bdc1188bc518782567c04e1ec4db0c

The prototype is not a security win. Upstream M4 is transparent (not zero knowledge), uses the
upstream 96-bit query profile, SHA-256 commitments/transcript, and `B128`. The purpose of this slice
is to validate the exact byte-to-native-word seam before inlining all 40 permutations in Pay1x2.

## Disk-safe validation

From the repository root, use a task-specific target and check the configured 30,064,771,072-byte
admission floor before building:

    test "$(($(df -Pk . | awk 'NR==2 {print $4}') * 1024))" -ge 30064771072
    CARGO_TARGET_DIR=/private/tmp/hegemon-m4-merkle-target \
      cargo +1.97.1 test --locked --offline \
      --manifest-path prototypes/standalone-shake256-binius/m4-pay1x2-prototype/Cargo.toml

That runs the scalar KAT, generates the native witness, checks every local M4 constraint, and checks
that the only public main-circuit in/out values are the seven digest words. It does not generate a
cryptographic proof.

After the same disk gate admits a proof run, execute the ignored release test:

    CARGO_TARGET_DIR=/private/tmp/hegemon-m4-merkle-target \
      cargo +1.97.1 test --release --locked --offline \
      --manifest-path prototypes/standalone-shake256-binius/m4-pay1x2-prototype/Cargo.toml \
      proof_binds_public_output_and_rejects_mutation_and_trailing_bytes -- --ignored --nocapture

The test requires a valid proof to verify, then requires a changed public output, a changed proof
byte, and trailing proof data all to reject. The equivalent JSON-producing command is:

    CARGO_TARGET_DIR=/private/tmp/hegemon-m4-merkle-target \
      cargo +1.97.1 run --release --locked --offline \
      --manifest-path prototypes/standalone-shake256-binius/m4-pay1x2-prototype/Cargo.toml -- --prove

Remove only `/private/tmp/hegemon-m4-merkle-target` after preserving the report. Never run a broad
`cargo clean`. The full Pay1x2 work remains governed by
`.agent/STANDALONE_SHAKE256_BINARY_PROOF_EXECPLAN.md`; this crate neither activates consensus nor
changes the verified 244,252-byte weak-profile frontier.
