# Native Backend Constant-Time And Canonicality Notes

This document is the repository's explicit constant-time and canonicality note for the active native backend package. It is not a proof of constant-time behavior. It is the exact list of secret-bearing values, the current code paths that touch them, the canonicality rules the code enforces, and the timing harness that screens for gross secret-dependent drift.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v3"`

Covered code paths:

- native witness packing in `circuits/superneo-ring`
- deterministic commitment/opening generation in `circuits/superneo-backend-lattice`
- native tx-leaf artifact construction in `circuits/superneo-hegemon`

## Secret-Bearing Inputs

The prover-side native tx-leaf path carries these secret-bearing values:

1. `sk_spend`
2. input note openings
3. output note openings before ciphertext exposure
4. Merkle witness siblings
5. commitment-opening randomness seed before canonicalization
6. packed witness coefficients derived from the private witness

These values are never meant to leave the proving path except through the explicitly defined native-opening and commitment-opening artifacts.

## Canonicality Rules

Current fail-closed canonicality checks:

1. `spec_digest` must match the manifest-owned parameter regime exactly.
2. `params_fingerprint` must match the active backend params exactly.
3. commitment-opening randomness is canonicalized to the configured entropy width and verification rejects noncanonical stored encodings.
4. fixed-width arrays reject truncation and trailing bytes.
5. Merkle siblings reject noncanonical 48-byte encodings.
6. packed witness width metadata must match the declared witness schema.

## Secret-Bearing Loops

The current implementation already keeps the hot prover loops in explicit fixed-iteration forms:

- packed-bit expansion iterates over `used_bits`
- digit expansion iterates over `digit_bits`
- commitment kernel iterates over fixed ring degree and configured matrix dimensions
- randomizer-row derivation iterates over fixed matrix rows and ring degree

The code still uses normal Rust arithmetic and normal equality checks, so this note does **not** claim strict constant time in the formal sense. It claims only that the repo now exposes the exact paths and a timing harness that can catch gross regressions.

## Timing Harness

Run:

```bash
cargo run -p native-backend-timing --release
```

The harness:

1. builds two controlled witness classes over the same public shape,
2. fixes the commitment-opening seeds so OS randomness does not dominate the measurement,
3. runs warmup rounds that are discarded from the final sample set,
4. interleaves class-A and class-B samples so run-order drift does not masquerade as a class signal,
5. computes a Welch-style t-statistic over the two timing distributions, and
6. fails closed if the statistic or relative deltas exceed the current screening threshold.

Current screening thresholds:

- `abs(t) < 5.0`
- `relative_mean_delta < 0.25`
- `relative_median_delta < 0.25`

These thresholds are still crude. They are only guards against obvious secret-dependent timing separation in the exercised path.

Latest local rerun on this branch:

- `sample_count = 64`
- `class_a_mean_ns = 1,101,892.64`
- `class_b_mean_ns = 1,115,794.98`
- `class_a_median_ns = 946,917.0`
- `class_b_median_ns = 945,437.5`
- `relative_mean_delta = 0.01246`
- `relative_median_delta = 0.00156`
- `welch_t_statistic = -0.0913`
- result: `pass`

## What This Note Does Not Claim

This document does not claim:

- perfect constant-time behavior,
- microarchitectural side-channel resistance,
- cache-attack resistance,
- or that all supporting crates are constant time.

It only states the exact current screening discipline the repository now enforces around the active native backend package.
