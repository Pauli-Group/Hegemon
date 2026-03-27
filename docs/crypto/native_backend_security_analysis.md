# Native Backend Security Analysis

This document describes the current code-derived security claim for Hegemon's active native backend family. It is not a paper. It is the repository's exact statement of what the code currently claims, what assumptions that claim depends on, what verification package now exists in-tree, and why the current review state is still not `accepted`.

## Scope

Active family:

- `family_label = "goldilocks_128b_rewrite"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-rewrite.v2"`
- `commitment_scheme_label = "neo_class_linear_commitment_128b_masking"`
- `challenge_schedule_label = "quint_goldilocks_fs_challenge_negacyclic_mix"`
- `maturity_label = "rewrite_candidate"`

The exact wire/transcript surface for that family is frozen in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md). The current `spec_digest` is derived from the full parameter regime in code and currently evaluates to:

- `spec_digest = 44c57f55d010b7f1c96b7405c4c262394d7cff5fe765089040a7e36d211f068d`

## Claim Model

The backend exports one `NativeSecurityClaim` from [superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). The claim is computed mechanically from the active `NativeBackendParams`, including the configured challenge schedule, opening entropy, explicit commitment-assumption bound, and explicit receipt-root composition bound.

For the active family the code currently computes:

- `claimed_security_bits = 128`
- `transcript_soundness_bits = floor(challenge_bits * fold_challenge_count / 2) = floor(63 * 5 / 2) = 157`
- `opening_hiding_bits = min(opening_randomness_bits / 2, 128) = min(256 / 2, 128) = 128`
- `commitment_binding_bits = commitment_assumption_bits = 128`
- `composition_loss_bits = ceil(log2(max_claimed_receipt_root_leaves)) = ceil(log2(128)) = 7`
- `soundness_floor_bits = min(157 - 7, 128, 128) = 128`
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
3. `fs.quint_goldilocks_negacyclic_fold_challenges`
4. `opening.canonical_256b_mask_seed`
5. `commitment.neo_class_linear_binding`

These mean:

1. `random_oracle.blake3_fiat_shamir`
   The Fiat-Shamir transcript is modeled as a random oracle over the exact domain-separated BLAKE3 transcript bytes implemented in the repo.

2. `serialization.canonical_native_artifact_bytes`
   The security claim assumes the byte encodings described in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md) are canonical, injective over accepted inputs, and rejected on malformed or noncanonical encodings.

3. `fs.quint_goldilocks_negacyclic_fold_challenges`
   Soundness for the fold schedule assumes five independently derived transcript challenges over Goldilocks, mixed through the implemented negacyclic linear fold schedule.

4. `opening.canonical_256b_mask_seed`
   Hiding for the current commitment-opening path assumes the canonicalized 256-bit mask seed contributes at least 128 bits after the conservative halving rule in the code-derived claim model.

5. `commitment.neo_class_linear_binding`
   Binding for the current linear commitment path is claimed under the repo's Neo-class commitment model for this exact family and parameter set. In code, this currently enters the floor through the explicit `commitment_assumption_bits` field. That makes the claim honest about its input assumptions, but it also means the repository still does not derive the binding floor directly from the ring geometry alone.

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
- independent verifier: [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref) using its own parsers, transcript builder, challenge derivation, commitment-opening check, and fold checks without calling the production verification helpers
- external-review tarball: [native-backend-128b-review-package.tar.gz](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/native-backend-128b-review-package.tar.gz)
- review-package checksum file: [package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256)
- packaged code fingerprint: `code_fingerprint.json`, which now records `HEAD`, tracked/staged diff hashes, untracked file hashes, and a composite `worktree_fingerprint`

The fixed vector bundle currently contains `11` cases: 2 valid acceptance cases and 9 explicit rejection cases. The reference verifier and production verifier agree on the full set.

## Historical Baseline

The frozen `heuristic_goldilocks_baseline` still exists only as a comparison line. Its code-derived claim is intentionally weak:

- `claimed_security_bits = 63`
- `transcript_soundness_bits = 31`
- `opening_hiding_bits = 16`
- `commitment_binding_bits = 63`
- `composition_loss_bits = 7`
- `soundness_floor_bits = 16`
- `review_state = killed`

That family remains useful only as a historical baseline and regression target.
