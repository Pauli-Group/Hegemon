# Native Backend 128-Bit Claims

Active family:

- `family_label = "goldilocks_128b_rewrite"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-rewrite.v2"`

Current code-derived claim:

- `claimed_security_bits = 128`
- `transcript_soundness_bits = 157`
- `opening_hiding_bits = 128`
- `commitment_binding_bits = 128`
- `composition_loss_bits = 7`
- `soundness_floor_bits = 128`
- `review_state = candidate_under_review`

Exact assumption ids:

1. `random_oracle.blake3_fiat_shamir`
2. `serialization.canonical_native_artifact_bytes`
3. `fs.quint_goldilocks_negacyclic_fold_challenges`
4. `opening.canonical_256b_mask_seed`
5. `commitment.neo_class_linear_binding`

Source documents:

- `docs/crypto/native_backend_spec.md`
- `docs/crypto/native_backend_security_analysis.md`
- `docs/crypto/native_backend_attack_worksheet.md`
- `docs/crypto/native_backend_constant_time.md`

Current packaged review checksum file:

- `audits/native-backend-128b/package.sha256`

Current packaged code fingerprint file:

- `code_fingerprint.json`
