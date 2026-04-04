# Native Backend 128-Bit Claims

Active family:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v8"`

Current code-derived claim:

- `claimed_security_bits = 128`
- `transcript_soundness_bits = 312`
- `opening_hiding_bits = 0`
- `commitment_codomain_bits = 37422`
- `commitment_same_seed_search_bits = 36936`
- `commitment_random_matrix_bits = 486`
- `commitment_problem_equations = 594`
- `commitment_problem_dimension = 4104`
- `commitment_problem_coeff_bound = 255`
- `commitment_problem_l2_bound = 16336`
- `commitment_estimator_dimension = 4104`
- `commitment_estimator_block_size = 3294`
- `commitment_estimator_classical_bits = 961`
- `commitment_estimator_quantum_bits = 872`
- `commitment_estimator_paranoid_bits = 683`
- `commitment_reduction_loss_bits = 0`
- `commitment_binding_bits = 872`
- `composition_loss_bits = 7`
- `soundness_floor_bits = 305`
- `review_state = candidate_under_review`

Interpretation:

- The live `128`-bit floor no longer comes from the old geometry-only union-bound proxy or the old `/2` transcript heuristic.
- The active `transcript_soundness_bits = 312` line is the theorem-backed exact min-entropy bound of the indexed five-challenge reduction rule `raw mod (2^63 - 1) + 1`, not a blanket halving rule.
- The live tx-leaf / receipt-root lane does not count an opening-hiding term because the shipped artifact path reconstructs its commitment deterministically from public witness data.
- The active commitment claim is now tied to the exact bounded-kernel Module-SIS reduction note for the implemented bounded live message class plus an explicit coefficient-space Euclidean SIS estimate of that exact instance.
- The structural `commitment_random_matrix_bits = 486` term remains reported as a geometry statistic, but it is no longer the live binding floor.
- The exact currently shipped `TxLeafPublicRelation` occupies only `12` ring elements after pack-then-digit embedding; the exported `76`-element instance is a deliberate conservative cap.
- The live tx-leaf artifact surface is public-only: it does not ship `sk_spend`, note witnesses, or commitment-opening bytes.

Exact assumption ids:

1. `random_oracle.blake3_fiat_shamir`
2. `serialization.canonical_native_artifact_bytes`
3. `fs.quint_goldilocks_profile_fold_challenges`
4. `commitment.deterministic_public_witness_reconstruction`
5. `commitment.bounded_kernel_module_sis_exact_reduction`
6. `commitment.sis_lattice_euclidean_adps16_quantum_estimator`

Source documents:

- `docs/crypto/native_backend_spec.md`
- `docs/crypto/native_backend_formal_theorems.md`
- `docs/crypto/native_backend_commitment_reduction.md`
- `docs/crypto/native_backend_security_analysis.md`
- `docs/crypto/native_backend_attack_worksheet.md`
- `docs/crypto/native_backend_constant_time.md`

Current packaged review checksum file:

- `audits/native-backend-128b/package.sha256`

Current packaged code fingerprint file:

- `code_fingerprint.json`

Current packaged source snapshot:

- `source/`
