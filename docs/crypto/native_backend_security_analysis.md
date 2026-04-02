# Native Backend Security Analysis

This document describes the current code-derived security claim for Hegemon's active native backend family. It is the repository's exact statement of what the code currently claims, what assumptions that claim depends on, what reduction the commitment claim is tied to, and why the current review state is still not `accepted`.

## Scope

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v7"`
- `commitment_scheme_label = "bounded_message_random_matrix_commitment"`
- `challenge_schedule_label = "quint_goldilocks_fs_challenge_negacyclic_mix"`
- `maturity_label = "structural_candidate"`

The exact wire and transcript surface for that family is frozen in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md). The exact commitment reduction note for the active family is [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md). The current `spec_digest` derived from the live parameter regime is:

- `spec_digest = fc4112b4aed172f792b8440e0d9f098bdc172a4575c138953d92518b63f5f212`

## Claim Model

The backend exports one `NativeSecurityClaim` from [superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs). The claim is computed mechanically from the active `NativeBackendParams`, including:

- the configured challenge schedule,
- the explicit bounded-kernel Module-SIS target for the implemented commitment class,
- the exact bounded live message-space parameters,
- and the explicit receipt-root composition cap.

Historical families may still count opening entropy when their live artifact path uses an explicit mask-seed opening flow. The active tx-leaf / receipt-root product lane does not.

For the active family the code currently computes:

- `claimed_security_bits = 128`
- `transcript_soundness_bits = floor(challenge_bits * fold_challenge_count / 2) = floor(63 * 5 / 2) = 157`

  **Rationale for the `/2` divisor:** the repository currently uses `floor(k * b / 2)` as a conservative engineering cap for transcript soundness pending theorem-backed analysis of the exact composed Fiat-Shamir fold schedule. This is not derived from a specific birthday-bound theorem for this construction; it is a blanket halving applied as a safety margin. Tightening or replacing this term with a proven bound for the exact negacyclic multi-challenge fold schedule is an open review item.
- `opening_hiding_bits = 0` because the shipped tx-leaf / receipt-root lane reconstructs its commitment deterministically from public witness data instead of using a live public opening / seed path
- `commitment_codomain_bits = 63 * matrix_rows * ring_degree = 63 * 74 * 8 = 37,296`
- `commitment_same_seed_search_bits = max_commitment_message_ring_elems * ring_degree * (decomposition_bits + 1) = 513 * 8 * 9 = 36,936`
- `commitment_random_matrix_bits = max(commitment_codomain_bits - commitment_same_seed_search_bits, 0) = 360`
- `commitment_problem_equations = matrix_rows * ring_degree = 74 * 8 = 592`
- `commitment_problem_dimension = max_commitment_message_ring_elems * ring_degree = 513 * 8 = 4104`
- `commitment_problem_coeff_bound = 2^decomposition_bits - 1 = 255`
- `commitment_problem_l2_bound = ceil(255 * sqrt(4104)) = 16,336`
- `commitment_estimator_dimension = 4104`
- `commitment_estimator_block_size = 3267`
- `commitment_estimator_classical_bits = 953`
- `commitment_estimator_quantum_bits = 865`
- `commitment_estimator_paranoid_bits = 677`
- `commitment_reduction_loss_bits = 0`
- `commitment_binding_bits = commitment_estimator_quantum_bits - commitment_reduction_loss_bits = 865 - 0 = 865`
- `composition_loss_bits = ceil(log2(max_claimed_receipt_root_leaves)) = ceil(log2(128)) = 7`
- `soundness_floor_bits = min(157 - 7, 865) = 150`
- `review_state = candidate_under_review`

The code rejects setup whenever `claimed_security_bits > soundness_floor_bits`.

## Commitment Reduction Model

The active family no longer derives its live binding claim from the repository's geometry-only union bound. Instead, it defines the exact live bounded message class, the exact bounded-kernel target problem, and a direct reduction from commitment collisions in that class to that target problem.

The exact reduction note is [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md). In repository terms, the active claim now means:

1. the verifier reconstructs the exact live message class canonically from public tx data and serialized STARK public inputs,
2. any accepted collision in that implemented message class yields a nonzero bounded kernel vector for the same commitment matrix,
3. the repository flattens that exact BK-MSIS instance into coefficient-space Euclidean SIS with `n_eq = 592`, `m = 4104`, `q = 18446744069414584321`, and `B_2 = 16336`,
4. the repository models that reduction with `commitment_reduction_loss_bits = 0`,
5. and the concrete binding floor comes from the in-repo `sis_lattice_euclidean_adps16` estimate of that exact instance.

That makes the claim materially different from the earlier geometry-proxy story:

- the live tx-leaf / receipt-root lane still reports `commitment_random_matrix_bits = 360` as a structural statistic,
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
3. `fs.quint_goldilocks_negacyclic_fold_challenges`
4. `commitment.deterministic_public_witness_reconstruction`
5. `commitment.bounded_kernel_module_sis_exact_reduction`
6. `commitment.sis_lattice_euclidean_adps16_quantum_estimator`

These mean:

1. `random_oracle.blake3_fiat_shamir`
   The Fiat-Shamir transcript is modeled as a random oracle over the exact domain-separated BLAKE3 transcript bytes implemented in the repo.

2. `serialization.canonical_native_artifact_bytes`
   The security claim assumes the byte encodings described in [native_backend_spec.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_spec.md) are canonical, injective over accepted inputs, and rejected on malformed or noncanonical encodings.

3. `fs.quint_goldilocks_negacyclic_fold_challenges`
   Soundness for the fold schedule assumes five independently derived transcript challenges over Goldilocks, mixed through the implemented negacyclic linear fold schedule.

4. `commitment.deterministic_public_witness_reconstruction`
   The live tx-leaf verifier must reconstruct the exact packed witness and deterministic commitment from the public tx view, serialized STARK public inputs, and fixed relation layout. The active security floor assumes that this reconstruction is canonical and that the verifier rejects mismatches.

5. `commitment.bounded_kernel_module_sis_exact_reduction`
   Binding for the current commitment path is claimed through the exact reduction stated in [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md): a collision in the implemented bounded live message class yields a bounded nonzero kernel vector for the same commitment matrix. That reduction feeds the exact coefficient-space SIS instance the repository estimates for the active parameter set.

6. `commitment.sis_lattice_euclidean_adps16_quantum_estimator`
   The concrete binding floor is taken from the coefficient-space Euclidean SIS estimate the repository computes for the exact active instance. For the current parameters this yields `β = 3267`, `classical = 953`, `quantum = 865`, and `paranoid = 677`, and the live claim uses the quantum line.

## What The Claim Does Not Say

This claim does not say:

- that the backend implements the Neo/SuperNeo sum-check interactive reduction (Π_CCS), random-linear-combination reduction (Π_RLC), or decomposition reduction (Π_DEC) — it does not,
- that the folding layer alone provides knowledge soundness over the CCS relation — it does not; live-path soundness depends on the STARK-verification gate at leaf construction and import,
- that the backend is already externally cryptanalyzed,
- that the in-repo construction is paper-equivalent to Neo, SuperNeo, or any final Module-SIS commitment construction,
- that the active ring `Z_q[X]/(X^8 + 1)` provides ring-structured hardness — it is fully splitting over the Goldilocks field, and the claim deliberately operates at the flattened coefficient-space SIS level,
- that the timing harness proves constant time,
- that a one-minute local fuzz smoke test is the same thing as exhaustive parser verification,
- or that the current line is production-ready.

The current claim is narrower and more honest:

- the repository now states one exact live bounded-message collision problem for the commitment path,
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
- exact commitment reduction note: [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md)
- attack ledger: [native_backend_attack_worksheet.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_attack_worksheet.md)
- constant-time note plus timing harness: [native_backend_constant_time.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_constant_time.md), `cargo run -p native-backend-timing --release`
- fixed vectors: [testdata/native_backend_vectors/bundle.json](/Users/pldd/Projects/Reflexivity/Hegemon/testdata/native_backend_vectors/bundle.json)
- independent verifier: [tools/native-backend-ref](/Users/pldd/Projects/Reflexivity/Hegemon/tools/native-backend-ref)
- external-review tarball: [native-backend-128b-review-package.tar.gz](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/native-backend-128b-review-package.tar.gz)
- review-package checksum file: [package.sha256](/Users/pldd/Projects/Reflexivity/Hegemon/audits/native-backend-128b/package.sha256)
- packaged code fingerprint: `code_fingerprint.json`
- packaged source snapshot: `source/`

The fixed vector bundle currently contains valid and invalid cases for both production and reference verification, and both verifiers are expected to agree on the full set.

## Historical Baseline

The frozen `heuristic_goldilocks_baseline` still exists only as a comparison line. Its code-derived claim is intentionally weak and remains useful only as a historical baseline and regression target.
