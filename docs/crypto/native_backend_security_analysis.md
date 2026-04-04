# Native Backend Security Analysis

This document describes the current code-derived security claim for Hegemon's active native backend family. It is the repository's exact statement of what the code currently claims, what assumptions that claim depends on, what reduction the commitment claim is tied to, and why the current review state is still not `accepted`.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8"`
- `commitment_scheme_label = "bounded_message_random_matrix_commitment"`
- `challenge_schedule_label = "quint_goldilocks_fs_challenge_profile_mix"`
- `maturity_label = "structural_candidate"`

The exact wire and transcript surface for that family is frozen in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md). The exact commitment reduction note for the active family is [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md). The current `spec_digest` derived from the live parameter regime is:

- `spec_digest = c441d06521bf6e604fda75378aea05e341ad3f4a8769d74a9cca4e3ff582eb23`

The theorem-grade derivations for the active line are in [native_backend_formal_theorems.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_formal_theorems.md).
The exact shipped `tx_leaf -> receipt_root` aggregation object is defined in [native_backend_verified_aggregation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_verified_aggregation.md).
The repo-local cryptanalysis of the exact flattened SIS instance and the `GoldilocksFrog` quotient is in [native_backend_cryptanalysis_note.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_cryptanalysis_note.md).

## Claim Model

The backend exports one `NativeSecurityClaim` from [superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). The claim is computed mechanically from the active `NativeBackendParams`, including:

- the configured challenge schedule,
- the explicit bounded-kernel Module-SIS target for the implemented commitment class,
- the exact bounded live message-space parameters,
- and the explicit receipt-root composition cap.

Historical families may still count opening entropy when their live artifact path uses an explicit mask-seed opening flow. The active tx-leaf / receipt-root product lane does not.

For the active family the code currently computes:

- `claimed_security_bits = 128`
- `soundness_scope_label = verified_leaf_aggregation`
- `transcript_soundness_bits = floor(320 - 5 log2(3)) = 312`

  **Rationale for the active value:** each fold challenge is derived from an indexed uniform 64-bit BLAKE3 XOF word reduced by `raw mod (2^63 - 1) + 1`. Because `2^64 = 2(2^63 - 1) + 2`, every challenge value has at most `3` preimages, so the exact indexed five-tuple has point probability at most `3^5 / 2^320`. The theorem note proves this exact bound and the corresponding `312`-bit tuple min-entropy. This is the correct theorem-backed replacement for the old blanket halving rule. It is a bound on the exact challenge-tuple law of the implemented schedule, not a claim that the folding layer implements Neo/SuperNeo CCS soundness.
- `opening_hiding_bits = 0` because the shipped tx-leaf / receipt-root lane reconstructs its commitment deterministically from public witness data instead of using a live public opening / seed path
- `commitment_codomain_bits = 63 * matrix_rows * ring_degree = 63 * 11 * 54 = 37,422`
- `commitment_same_seed_search_bits = max_commitment_message_ring_elems * ring_degree * (decomposition_bits + 1) = 76 * 54 * 9 = 36,936`
- `commitment_random_matrix_bits = max(commitment_codomain_bits - commitment_same_seed_search_bits, 0) = 486`
- `commitment_problem_equations = matrix_rows * ring_degree = 11 * 54 = 594`
- `commitment_problem_dimension = max_commitment_message_ring_elems * ring_degree = 76 * 54 = 4104`
- `commitment_problem_coeff_bound = 2^decomposition_bits - 1 = 255`
- `commitment_problem_l2_bound = ceil(255 * sqrt(4104)) = 16,336`
- `commitment_estimator_dimension = 4104`
- `commitment_estimator_block_size = 3294`
- `commitment_estimator_classical_bits = 961`
- `commitment_estimator_quantum_bits = 872`
- `commitment_estimator_paranoid_bits = 683`
- `commitment_reduction_loss_bits = 0`
- `commitment_binding_bits = commitment_estimator_quantum_bits - commitment_reduction_loss_bits = 872 - 0 = 872`
- `composition_loss_bits = ceil(log2(max_claimed_receipt_root_leaves)) = ceil(log2(128)) = 7`
- `soundness_floor_bits = min(312 - 7, 872) = 305`
- `review_state = candidate_under_review`

The code rejects setup whenever `claimed_security_bits > soundness_floor_bits`.

## Commitment Reduction Model

The active family no longer derives its live binding claim from the repository's geometry-only union bound. Instead, it defines the exact live bounded message class, the exact bounded-kernel target problem, and a direct reduction from commitment collisions in that class to that target problem.

The exact reduction note is [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md). In repository terms, the active claim now means:

1. the verifier reconstructs the exact live message class canonically from public tx data and serialized STARK public inputs,
2. any accepted collision in that implemented message class yields a nonzero bounded kernel vector for the same commitment matrix,
3. the repository flattens that exact BK-MSIS instance into coefficient-space Euclidean SIS with `n_eq = 594`, `m = 4104`, `q = 18446744069414584321`, and `B_2 = 16336`,
4. the repository models that reduction with `commitment_reduction_loss_bits = 0`,
5. and the concrete binding floor comes from the in-repo `sis_lattice_euclidean_adps16` estimate of that exact instance.

For the exact currently shipped `TxLeafPublicRelation`, the live witness schema occupies only `4935` bits, which means `617` digits and `12` ring elements before zero padding. The exported claim deliberately keeps the conservative manifest-owned ambient cap `76` rather than publishing the tighter live subclass.

That makes the claim materially different from the earlier geometry-proxy story:

- the live tx-leaf / receipt-root lane still reports `commitment_random_matrix_bits = 486` as a structural statistic,
- but the live `commitment_binding_bits` no longer equals that statistic,
- and the active floor is now bounded by the explicit coefficient-space SIS estimate plus transcript-composition accounting, not by the old random-matrix union-bound proxy.

The live tx-leaf artifact surface is also witness-free. The public bytes contain:

- the canonical receipt,
- serialized STARK public inputs,
- the public tx view,
- the STARK proof bytes,
- the derived lattice commitment,
- and the native leaf proof.

They do **not** contain `sk_spend`, note witnesses, Merkle paths, packed-witness coefficients, or a public commitment-opening object.

## Assumption IDs

The active family currently emits these `assumption_ids`:

1. `random_oracle.blake3_fiat_shamir`
2. `serialization.canonical_native_artifact_bytes`
3. `fs.quint_goldilocks_profile_fold_challenges`
4. `aggregation.native_receipt_root_replays_verified_tx_leaves`
5. `commitment.deterministic_public_witness_reconstruction`
6. `commitment.bounded_kernel_module_sis_exact_reduction`
7. `commitment.sis_lattice_euclidean_adps16_quantum_estimator`

These mean:

1. `random_oracle.blake3_fiat_shamir`
   The Fiat-Shamir transcript is modeled as a random oracle over the exact domain-separated BLAKE3 transcript bytes implemented in the repo.

2. `serialization.canonical_native_artifact_bytes`
   The security claim assumes the byte encodings described in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md) are canonical, injective over accepted inputs, and rejected on malformed or noncanonical encodings.

3. `fs.quint_goldilocks_profile_fold_challenges`
   The active schedule derives five indexed transcript challenges over Goldilocks, interprets them as the coefficients of a low-degree challenge polynomial in `Z_q[X] / (X^54 + X^27 + 1)`, and relies on the theorem note's exact tuple-min-entropy bound for that derivation. Accepted folds themselves are deterministic canonicalization checks, not a separate CCS soundness protocol.

4. `aggregation.native_receipt_root_replays_verified_tx_leaves`
   The shipped `receipt_root` lane is not treated as generic fold soundness. Its claim scope is explicitly `verified_leaf_aggregation`: receipt-root verification must replay every tx-leaf verification under the same params and then replay every fold recomputation over those verified leaves. That exact security object is defined in [native_backend_verified_aggregation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_verified_aggregation.md).

5. `commitment.deterministic_public_witness_reconstruction`
   The live tx-leaf verifier must reconstruct the exact packed witness and deterministic commitment from the public tx view, serialized STARK public inputs, and fixed relation layout. The active security floor assumes that this reconstruction is canonical and that the verifier rejects mismatches.

6. `commitment.bounded_kernel_module_sis_exact_reduction`
   Binding for the current commitment path is claimed through the exact reduction stated in [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md): a collision in the implemented bounded live message class yields a bounded nonzero kernel vector for the same commitment matrix. The theorem note proves that exact reduction and the zero-loss flattening from the active ring/module kernel to the coefficient-space SIS instance the repository estimates.

7. `commitment.sis_lattice_euclidean_adps16_quantum_estimator`
   The concrete binding floor is taken from the coefficient-space Euclidean SIS estimate the repository computes for the exact active instance. For the current parameters this yields `β = 3294`, `classical = 961`, `quantum = 872`, and `paranoid = 683`, and the live claim uses the quantum line.

## What The Claim Does Not Say

This claim does not say:

- that the backend implements the Neo/SuperNeo sum-check interactive reduction (Π_CCS), random-linear-combination reduction (Π_RLC), or decomposition reduction (Π_DEC) — it does not,
- that the folding layer alone provides knowledge soundness over the CCS relation — it does not; live-path soundness depends on the STARK-verification gate at leaf construction and import,
- that the backend is already externally cryptanalyzed,
- that the in-repo construction is paper-equivalent to Neo, SuperNeo, or any final Module-SIS commitment construction,
- that the active ring `Z_q[X]/(X^54 + X^27 + 1)` provides ring-structured hardness — the claim deliberately operates at the flattened coefficient-space SIS level, and external review is still expected to confirm that the frog quotient does not introduce an easier algebraic attack than the stated coefficient-space estimate,
- that the timing harness proves constant time,
- that a one-minute local fuzz smoke test is the same thing as exhaustive parser verification,
- or that the current line is production-ready.

The current claim is narrower and more honest:

- the repository now states one exact live bounded-message collision problem for the commitment path,
- the repository now proves the active GoldilocksFrog fold schedule's exact challenge-tuple law and canonicality properties,
- the repository now has a direct cryptanalysis note for the split `GoldilocksFrog` quotient showing why the simplest one-component zero-divisor shortcut is outside the claimed bounded coefficient class,
- the repository now packages the actual shipped `receipt_root` guarantee as verified-leaf aggregation instead of leaving that property implicit in code,
- the repository now states one exact in-repo reduction from that collision problem to a bounded-kernel Module-SIS style target,
- the code now propagates only the explicit reduction loss and receipt-root composition loss into the final floor,
- the code now computes the binding cap from one explicit coefficient-space Euclidean SIS estimate for the exact active instance,
- and the remaining open question is independent review of that concretization and estimator choice rather than a missing in-repo derivation.

## Why `review_state = candidate_under_review`

The current review state is intentionally not `accepted`.

Reasons:

- the repo still does not have completed external cryptanalysis,
- the active coefficient-space Euclidean SIS estimate is still an in-repo concretization rather than a completed external cryptanalytic conclusion,
- the current commitment reduction note is exact for the implemented message class but still not a paper-equivalent Neo / SuperNeo proof,
- the public break-it phase has been packaged but not yet closed,
- the timing harness is only a regression screen, not a proof.

So the current meaning of the claim is:

- the repository can now state one exact code-derived 128-bit target,
- the code can reject overclaims mechanically,
- the repository now has fixed vectors, a separate reference verifier, local and CI fuzz smoke, a timing harness, and a reproducible external-review package,
- but the package is still under review and not yet a settled cryptographic result.

## Current Review Package Evidence

The current in-tree review package includes:

- exact protocol spec: [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md)
- verified-leaf aggregation note: [native_backend_verified_aggregation.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_verified_aggregation.md)
- exact commitment reduction note: [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md)
- attack ledger: [native_backend_attack_worksheet.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_attack_worksheet.md)
- constant-time note plus timing harness: [native_backend_constant_time.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_constant_time.md), `cargo run -p native-backend-timing --release`
- fixed vectors: [testdata/native_backend_vectors/bundle.json](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors/bundle.json)
- independent verifier: [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref)
- packaged attack-model artifact: `attack_model.json`
- packaged live message-class artifact: `message_class.json`
- packaged claim-sensitivity sweep: `claim_sweep.json`
- generated review manifest: `review_manifest.json`
- packaged independent claim-verifier report: `reference_claim_verifier_report.json`
- packaged production verifier parity report: `production_verifier_report.json`
- external-review tarball: [native-backend-128b-review-package.tar.gz](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/native-backend-128b-review-package.tar.gz)
- review-package checksum file: [package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256)
- packaged code fingerprint: `code_fingerprint.json`
- packaged source snapshot: `source/`

The fixed vector bundle currently contains valid and invalid cases for both production and reference verification, and both verifiers are expected to agree on the full set.

## Historical Baseline

The frozen `heuristic_goldilocks_baseline` still exists only as a comparison line. Its code-derived claim is intentionally weak and remains useful only as a historical baseline and regression target.
