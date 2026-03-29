# Native Backend Security Analysis

This document describes the current code-derived security claim for Hegemon's active native backend family. It is not a paper. It is the repository's exact statement of what the code currently claims, what assumptions that claim depends on, what verification package now exists in-tree, and why the current review state is still not `accepted`.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v4"`
- `commitment_scheme_label = "bounded_message_random_matrix_commitment"`
- `challenge_schedule_label = "quint_goldilocks_fs_challenge_negacyclic_mix"`
- `maturity_label = "structural_candidate"`

The exact wire/transcript surface for that family is frozen in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md). The current `spec_digest` is derived from the full parameter regime in code and currently evaluates to:

- `spec_digest = 08eae1920eaf6e3cc1a8f9a149885221aed8172a5d33ae21a264d239b4b2cf88`

## Claim Model

The backend exports one `NativeSecurityClaim` from [superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). The claim is computed mechanically from the active `NativeBackendParams`, including the configured challenge schedule, explicit commitment message cap, and explicit receipt-root composition bound. Historical families may still count opening entropy when their live artifact path actually uses an explicit mask-seed commitment-opening flow, but the active tx-leaf/receipt-root product lane does not.

For the active family the code currently computes:

- `claimed_security_bits = 128`
- `transcript_soundness_bits = floor(challenge_bits * fold_challenge_count / 2) = floor(63 * 5 / 2) = 157`
- `opening_hiding_bits = 0` because the shipped tx-leaf/receipt-root lane reconstructs its commitment deterministically from public witness data instead of using a live public opening/seed path
- `commitment_codomain_bits = 63 * matrix_rows * ring_degree = 63 * 74 * 8 = 37,296`
- `commitment_same_seed_search_bits = max_commitment_message_ring_elems * ring_degree * (decomposition_bits + 1) = 513 * 8 * 9 = 36,936`
- `commitment_random_matrix_bits = max(commitment_codomain_bits - commitment_same_seed_search_bits, 0) = 360`
- `commitment_binding_bits = commitment_random_matrix_bits = 360`
- `composition_loss_bits = ceil(log2(max_claimed_receipt_root_leaves)) = ceil(log2(128)) = 7`
- `soundness_floor_bits = min(157 - 7, 360) = 150`
- `review_state = candidate_under_review`

The code rejects setup whenever `claimed_security_bits > soundness_floor_bits`.

The important structural facts are explicit now:

- the active family no longer relies on `commitment_assumption_bits` to hit the claimed floor,
- the active tx-leaf/receipt-root lane does not count any opening-hiding term because it does not use a live public opening/seed path,
- and the current `74 x 8` bounded-message linear map yields a positive first-principles random-matrix term of `360` bits under the repo's conservative union bound, so the active `128`-bit claim is bounded by transcript soundness and geometry-derived commitment binding, not by an opening term.

The live tx-leaf artifact surface is also now witness-free. The public bytes contain:

- the canonical receipt,
- serialized STARK public inputs,
- the public tx view,
- the STARK proof bytes,
- the derived lattice commitment,
- and the native leaf proof.

They do **not** contain `sk_spend`, note witnesses, Merkle paths, packed-witness coefficients, or a public commitment-opening object.

The current code also emits this claim directly through:

```bash
cargo run -p superneo-bench -- --print-native-security-claim
```

## Assumption IDs

The active family currently emits these `assumption_ids`:

1. `random_oracle.blake3_fiat_shamir`
2. `serialization.canonical_native_artifact_bytes`
3. `fs.quint_goldilocks_negacyclic_fold_challenges`
4. `commitment.deterministic_public_witness_reconstruction`
5. `commitment.bounded_message_random_matrix_union_bound`

These mean:

1. `random_oracle.blake3_fiat_shamir`
   The Fiat-Shamir transcript is modeled as a random oracle over the exact domain-separated BLAKE3 transcript bytes implemented in the repo.

2. `serialization.canonical_native_artifact_bytes`
   The security claim assumes the byte encodings described in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md) are canonical, injective over accepted inputs, and rejected on malformed or noncanonical encodings.

3. `fs.quint_goldilocks_negacyclic_fold_challenges`
   Soundness for the fold schedule assumes five independently derived transcript challenges over Goldilocks, mixed through the implemented negacyclic linear fold schedule.

4. `commitment.deterministic_public_witness_reconstruction`
   The live tx-leaf verifier must reconstruct the exact packed witness and deterministic commitment from the public tx view, serialized STARK public inputs, and fixed relation layout. The active security floor assumes that this reconstruction is canonical and that the verifier rejects mismatches.

5. `commitment.bounded_message_random_matrix_union_bound`
   Binding for the current commitment path is claimed under the repository's conservative bounded-message random-matrix union bound for this exact family and parameter set. In code, the active family now sets `commitment_binding_bits = commitment_random_matrix_bits`, and that structural term is currently `360` bits for the implemented `74 x 8` geometry with `max_commitment_message_ring_elems = 513`. So the repo is no longer relying on a separate commitment-assumption override on the active family.

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
- the current commitment binding floor is derived from a conservative in-repo model, not from a paper-equivalent Neo/SuperNeo reduction,
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
- independent verifier: [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref) using its own parsers, tx/public-input reconstruction, STARK-proof check, commitment reconstruction, and fold checks without calling the production verification helpers
- external-review tarball: [native-backend-128b-review-package.tar.gz](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/native-backend-128b-review-package.tar.gz)
- review-package checksum file: [package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256)
- packaged code fingerprint: `code_fingerprint.json`, which now records `HEAD`, tracked/staged diff hashes, untracked file hashes, and a composite `worktree_fingerprint`
- packaged source snapshot: `source/`, which now carries the exact review-relevant source tree staged into the tarball

The fixed vector bundle currently contains `11` cases: 2 valid acceptance cases and 9 explicit rejection cases. The reference verifier and production verifier agree on the full set.

## Historical Baseline

The frozen `heuristic_goldilocks_baseline` still exists only as a comparison line. Its code-derived claim is intentionally weak:

- `claimed_security_bits = 63`
- `transcript_soundness_bits = 31`
- `opening_hiding_bits = 16`
- `commitment_codomain_bits = 4032`
- `commitment_same_seed_search_bits = 36,936`
- `commitment_random_matrix_bits = 0`
- `commitment_binding_bits = 63`
- `composition_loss_bits = 7`
- `soundness_floor_bits = 16`
- `review_state = killed`

That family remains useful only as a historical baseline and regression target.
