# Native Backend Security Analysis

This document describes the current code-derived security claim for Hegemon's active native backend family. It is not a paper. It is the repository's exact statement of what the code currently claims, what assumptions that claim depends on, what verification package now exists in-tree, and why the current review state is still not `accepted`.

## Scope

Active family:

- `family_label = "goldilocks_128b_rewrite"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-rewrite.v1"`
- `commitment_scheme_label = "neo_class_linear_commitment_128b_masking"`
- `challenge_schedule_label = "triple_goldilocks_fs_challenge_negacyclic_mix"`
- `maturity_label = "rewrite_candidate"`

The exact wire/transcript surface for that family is frozen in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md). The current `spec_digest` is derived from the full parameter regime in code and currently evaluates to:

- `spec_digest = c8e67688913af08b80d7011e2a7225ac467fb3e12cdd1ba69e533823b75b64b4`

## Claim Model

The backend exports one `NativeSecurityClaim` from [superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). The claim is computed mechanically from the active `NativeBackendParams`.

For the active family the code currently computes:

- `claimed_security_bits = 128`
- `transcript_soundness_bits = challenge_bits * fold_challenge_count = 63 * 3 = 189`
- `opening_hiding_bits = min(opening_randomness_bits, 128) = min(128, 128) = 128`
- `commitment_binding_bits = 128`
- `composition_loss_bits = 0`
- `soundness_floor_bits = min(189, 128, 128) - 0 = 128`
- `review_state = candidate_under_review`

The code rejects setup whenever `claimed_security_bits > soundness_floor_bits`.

The current code also emits this claim directly through:

```bash
cargo run -p superneo-bench -- --print-native-security-claim
```

## Assumption IDs

The active family currently emits these `assumption_ids`:

1. `random_oracle.blake3_fiat_shamir`
2. `serialization.canonical_native_artifact_bytes`
3. `fs.triple_goldilocks_negacyclic_fold_challenges`
4. `opening.canonical_128b_mask_seed`
5. `commitment.neo_class_linear_binding`

These mean:

1. `random_oracle.blake3_fiat_shamir`
   The Fiat-Shamir transcript is modeled as a random oracle over the exact domain-separated BLAKE3 transcript bytes implemented in the repo.

2. `serialization.canonical_native_artifact_bytes`
   The security claim assumes the byte encodings described in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md) are canonical, injective over accepted inputs, and rejected on malformed or noncanonical encodings.

3. `fs.triple_goldilocks_negacyclic_fold_challenges`
   Soundness for the fold schedule assumes three independently derived transcript challenges over Goldilocks, mixed through the implemented negacyclic linear fold schedule.

4. `opening.canonical_128b_mask_seed`
   Hiding for the current commitment-opening path assumes the canonicalized mask seed contributes a full 128 bits of entropy and is rejected when noncanonical.

5. `commitment.neo_class_linear_binding`
   Binding for the current linear commitment path is claimed under the repo's Neo-class commitment model for this exact family and parameter set. This is still an in-repo approximation, not a claim that the implementation is paper-equivalent to Neo/SuperNeo.

## What The Claim Does Not Say

This claim does not say:

- that the backend is already externally cryptanalyzed,
- that the in-repo construction is paper-equivalent to Neo, SuperNeo, or any final Module-SIS commitment construction,
- that the timing harness proves constant time,
- that a one-minute local fuzz smoke test is the same thing as exhaustive parser verification,
- or that the current line is production-ready.

Those limits remain even though the repository now carries the full in-tree review package.

## Why `review_state = candidate_under_review`

The current review state is intentionally not `accepted`.

Reasons:

- the repo still does not have completed external cryptanalysis,
- the public break-it phase has been packaged but not yet closed,
- the timing harness is only a regression screen, not a proof,
- and the backend remains an in-repo approximation rather than a paper-equivalent Neo/SuperNeo implementation.

So the current meaning of the claim is:

- the repository can now state one exact code-derived 128-bit target,
- the code can now reject overclaims mechanically,
- the repository now has fixed vectors, an independent reference verifier, local and CI fuzz smoke, a timing harness, and a reproducible external-review package,
- but the package is still under review and not yet a settled cryptographic result.

## Current Review Package Evidence

The current in-tree review package now includes:

- exact protocol spec: [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md)
- attack ledger: [native_backend_attack_worksheet.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_attack_worksheet.md)
- constant-time note plus timing harness: [native_backend_constant_time.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_constant_time.md), `cargo run -p native-backend-timing --release`
- fixed vectors: [testdata/native_backend_vectors/bundle.json](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors/bundle.json)
- independent verifier: [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref)
- external-review tarball: [native-backend-128b-review-package.tar.gz](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/native-backend-128b-review-package.tar.gz)
- review-package checksum file: [package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256)

The fixed vector bundle currently contains `11` cases: 2 valid acceptance cases and 9 explicit rejection cases. The reference verifier and production verifier agree on the full set.

## Historical Baseline

The frozen `heuristic_goldilocks_baseline` still exists only as a comparison line. Its code-derived claim is intentionally weak:

- `claimed_security_bits = 63`
- `transcript_soundness_bits = 63`
- `opening_hiding_bits = 16`
- `commitment_binding_bits = 63`
- `composition_loss_bits = 0`
- `soundness_floor_bits = 16`
- `review_state = killed`

That family remains useful only as a historical baseline and regression target.
