# Frozen prototype measurements

These reports were produced on 2026-08-19 from the pinned backend revision in this directory after
the scalar registry froze the `HEG-S4V2` profile. They are prototype evidence, not release
authorization.

The exact one-permutation report used an OS-seeded prover and the backend's real inverse-rate sweep:

    CARGO_TARGET_DIR=/private/tmp/hegemon-binius-prototype-target \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
      cargo +1.97.1 build --release --locked
    python3 scripts/measure_standalone_shake256_prototype.py \
      --allow-unsupported-prototype --min-free-gib 16 -- \
      /private/tmp/hegemon-binius-prototype-target/release/hegemon-standalone-shake256-binius-backend

The 40-permutation report repeated the exact Merkle-parent circuit at the winning inverse-rate log
3. It is only a proof-geometry proxy for the scalar Pay1x2 hash floor; it is not the full Pay1x2
relation:

    python3 scripts/measure_standalone_shake256_prototype.py \
      --allow-unsupported-prototype --min-free-gib 16 -- \
      /private/tmp/hegemon-binius-prototype-target/release/hegemon-standalone-shake256-binius-backend \
      --parents 40 --rate 3 --deterministic-test

The wrapper's capacity values are mechanical consequences of measured envelope bytes. They are not
launch capacity claims because upstream still uses the unsupported 96-bit/SHA-256/GF(2^128)
profile, and the 40-permutation measurement omits the non-hash Pay1x2 constraints.
