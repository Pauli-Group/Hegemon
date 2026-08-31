# Standalone SHAKE256 Binius backend prototype

This isolated executable proves one fixed-layout `HEG-S4V2` SHAKE256-448 Merkle-parent relation
with direct IronSpartan at pinned Binius64 revision
`3f96163049f680b2909f6545690bd929f1b48c44`. The two 56-byte children are private precommit bits;
the 56-byte parent is public. The circuit absorbs the exact 133-byte Hegemon frame and SHAKE suffix
in one 136-byte rate block, executes one bit-constrained Keccak-f[1600] permutation, and checks the
public output.

It is a real proof roundtrip, not a proof-size model. The executable also rejects a changed public
parent, a changed proof byte, and an appended proof byte; the last check calls verifier transcript
finalization so acceptance requires exact byte consumption.

This is **not** a production backend. Upstream currently fixes `SECURITY_BITS = 96`, uses the
SHA-256 `StdHashSuite`, and uses `BinaryField128bGhash`. Those parameters do not meet Hegemon's
composed strict-PQ128 requirement, whose selected target is SHAKE256-512 proof hashing and
GF(2^384). The executable emits this nonqualification in its JSON result.

From this directory, run with a disposable target directory so the prototype cannot consume the
repository build volume:

    df -h /private/tmp
    CARGO_TARGET_DIR=/private/tmp/hegemon-binius-prototype-target \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
      cargo +1.97.1 run --release --locked

The default uses an OS-seeded thread CSPRNG and proves the one-permutation component at inverse-rate
logs 1 through 4, returning the smallest real canonical transcript. A repeatable benchmark may add
`--deterministic-test`; that seed is measurement-only and is forbidden for a production prover.
To measure a repeated-component geometry proxy (not the full Pay1x2 relation), reuse the selected
rate from the default result, for example:

    cargo +1.97.1 run --release --locked -- --parents 40 --rate 3

Standard output is exactly one compact
`hegemon.standalone-shake256.backend-measurement.v1` JSON object for
`scripts/measure_standalone_shake256_prototype.py`. Compiler diagnostics remain on standard error.

Stop and remove the disposable target if free space falls below 16 GiB. The crate is deliberately
not a member of Hegemon's root Cargo workspace and does not activate or modify consensus.
