# Native Backend Exact Specification

This document freezes the exact current protocol surface for the experimental native backend family carried under `circuits/superneo-*`. It is the source document for what the code means when it says “spec identity.” If the artifact bytes, transcript inputs, or rejection rules change, this document must change and the backend `spec_digest` must change with it.

This document does not claim the current backend is paper-equivalent to Neo or SuperNeo. It describes the exact in-repo construction that exists today.

## Scope

This specification covers:

- the backend manifest and parameter object in [circuits/superneo-backend-lattice/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs)
- the deterministic commitment derivation and fold challenge derivation in that backend
- the native `TxLeaf` and `ReceiptRoot` artifact byte formats in [circuits/superneo-hegemon/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs)
- the exact rejection rules that apply at decode and verification time

This specification does not define the full transaction AIR or the full STARK proof format. It assumes the existing Hegemon transaction proof objects and focuses on the post-proof native backend layer.

## Current Active Family

The active family at the time this document was written is:

- `family_label = "goldilocks_128b_structural_commitment"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v5"`
- `commitment_scheme_label = "bounded_message_random_matrix_commitment"`
- `challenge_schedule_label = "quint_goldilocks_fs_challenge_negacyclic_mix"`
- `maturity_label = "structural_candidate"`

Frozen comparison families are:

- `family_label = "heuristic_goldilocks_baseline"`
- `spec_label = "hegemon.superneo.native-backend-spec.heuristic-goldilocks-baseline.v1"`
- `commitment_scheme_label = "ajtai_linear_masked_commitment"`
- `challenge_schedule_label = "single_goldilocks_fs_challenge"`
- `maturity_label = "experimental_baseline"`

- `family_label = "goldilocks_128b_rewrite"`
- `spec_label = "hegemon.superneo.native-backend-spec.goldilocks-128b-rewrite.v2"`
- `commitment_scheme_label = "neo_class_linear_commitment_128b_masking"`
- `challenge_schedule_label = "quint_goldilocks_fs_challenge_negacyclic_mix"`
- `maturity_label = "rewrite_candidate"`

The current active parameter object also carries:

- `security_bits = 128`
- `ring_profile = GoldilocksCyclotomic24`
- `matrix_rows = 74`
- `matrix_cols = 8`
- `challenge_bits = 63`
- `fold_challenge_count = 5`
- `max_fold_arity = 2`
- `transcript_domain_label = "hegemon.superneo.fold.v3"`
- `decomposition_bits = 8`
- `opening_randomness_bits = 256`
- `commitment_security_model = "bounded_kernel_module_sis"`
- `commitment_bkmsis_target_bits = 128`
- `max_commitment_message_ring_elems = 513`
- `max_claimed_receipt_root_leaves = 128`

## Global Encoding Rules

All integer encodings are little-endian.

All fixed-size byte arrays are written exactly in the order shown in this document. A verifier must reject any artifact with trailing bytes after the final expected field.

All counted sequences are encoded as:

- `u32` little-endian count
- followed by exactly that many elements

The artifact parser must reject any sequence whose count exceeds the configured repository limits, including:

- `MAX_INPUTS` for native tx-leaf nullifier and input-flag counts
- `MAX_OUTPUTS` for native tx-leaf commitment/ciphertext-hash and output-flag counts
- `BALANCE_SLOTS` for serialized STARK balance-slot arrays
- `max_claimed_receipt_root_leaves` for receipt-root leaf counts

Canonicality matters. When this document says a field is canonicalized before use, both the builder and verifier must apply the same canonicalization rule, and the verifier must reject an artifact whose stored field is not already canonical.

## Backend Manifest, Fingerprint, and Spec Identity

The backend manifest is the tuple:

- `family_label`
- `spec_label`
- `commitment_scheme_label`
- `challenge_schedule_label`
- `maturity_label`

The parameter fingerprint is a 48-byte Blake3-derived digest over:

1. domain tag `hegemon.superneo.native-backend-params.v2`
2. `family_label`
3. `spec_label`
4. `commitment_scheme_label`
5. `challenge_schedule_label`
6. `maturity_label`
7. `security_bits`
8. `ring_profile`
9. `matrix_rows`
10. `matrix_cols`
11. `challenge_bits`
12. `fold_challenge_count`
13. `max_fold_arity`
14. `transcript_domain_label`
15. `decomposition_bits`
16. `opening_randomness_bits`
17. `commitment_security_model`
18. `commitment_bkmsis_target_bits`
19. `max_commitment_message_ring_elems`
20. `max_claimed_receipt_root_leaves`

The spec digest is a separate 32-byte Blake3-derived digest over the same ordered fields under a distinct domain tag:

- `hegemon.superneo.native-backend-spec-digest.v1`

The parameter fingerprint and spec digest are both carried in native artifacts. The verifier must reject:

- a mismatched parameter fingerprint
- a mismatched spec digest
- an artifact version that does not match the current parameter set

## Security Parameters Used By The Backend

The backend converts the parameter object into `SecurityParams` using:

- `target_security_bits = security_bits`
- `max_fold_arity = max_fold_arity`
- `transcript_domain = transcript_domain_label.as_bytes()`

The current backend also computes a security claim from:

- transcript challenge width and count
- the exact bounded-kernel Module-SIS target for the implemented commitment class
- explicit maximum commitment message length
- composition loss from the configured maximum receipt-root leaf count

Historical families may also count opening entropy if their live artifact path uses an explicit commitment-opening flow. The active tx-leaf/receipt-root lane does not.

For the active family, the code defines the exact live bounded message class, exact bounded-kernel target problem, and exact reduction note in [native_backend_commitment_reduction.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/native_backend_commitment_reduction.md). Historical families may still use different commitment-security models, but the active family binds its live claim to `commitment_security_model = "bounded_kernel_module_sis"` with `commitment_bkmsis_target_bits = 128`. The security-analysis document records the resulting floor explicitly.

This specification freezes the wire and transcript surface. The security-analysis document is the place where those ingredients are translated into a security claim.

## Packed Witness Message Space

The backend still commits to `PackedWitness<u64>` values produced by the pay-per-bit packer in [circuits/superneo-ring/src/lib.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-ring/src/lib.rs), but the packed witness is now an internal verifier reconstruction, not a serialized artifact field.

The verifier derives the packed witness from:

- the public `TxLeaf` transaction view,
- the serialized STARK public inputs,
- the fixed `TxLeafPublicRelation` witness layout,
- and the active backend parameters.

The artifact no longer carries:

- `sk_spend`
- note openings
- Merkle paths
- packed witness coefficients
- commitment-opening objects

The verifier recomputes the expected packed witness from the public artifact fields and rejects if the resulting commitment or leaf proof does not match.

## Internal Commitment API

`opening_randomness_bits` remains part of the backend parameter set because the backend still exposes a randomized commitment-opening API for non-product review/testing paths. That API canonicalizes the mask seed to the configured entropy width and checks it during `verify_opening`.

The active tx-leaf/receipt-root product lane does **not** use that randomized opening flow and does **not** count an opening-hiding term in its live security floor.

The product verifier therefore does **not** accept a public commitment-opening object. Instead it recomputes the deterministic commitment implied by the public witness and rejects any artifact whose commitment rows or digest do not match that reconstruction.

When the non-product randomized opening API is used, its randomizer rows are derived from:

- `ring_profile.label()`
- `shape_digest`
- `security_bits`
- `challenge_bits`
- `max_fold_arity`
- `transcript_domain_digest`
- `commitment_rows`
- `ring_degree`
- `digit_bits`
- `opening_randomness_bits`
- `row_index`
- `col_index`
- `coeff_index`

## Fold Challenge Derivation

The fold challenge transcript is the concatenation of:

1. `params_fingerprint`
2. `ring_profile.label()`
3. `shape_digest`
4. `left.relation_id`
5. `security_bits`
6. `challenge_bits`
7. `fold_challenge_count`
8. `max_fold_arity`
9. `transcript_domain_digest`
10. `commitment_rows`
11. `ring_degree`
12. `digit_bits`
13. `opening_randomness_bits`
14. `left.statement_digest`
15. `right.statement_digest`
16. `left.witness_commitment.digest`
17. `right.witness_commitment.digest`

Each challenge is then derived with Blake3 XOF over:

- domain tag `hegemon.superneo.fold-challenge.v3`
- the transcript bytes above
- `challenge_index` as `u64`

Each challenge is reduced into the configured `challenge_bits` width using the backend’s current reduction rule. The current family derives exactly `fold_challenge_count = 5` challenges.

The fold verifier must reject if:

- the stored challenge vector differs from the expected vector
- the parent statement digest, commitment digest, parent rows, or proof digest do not match the recomputed fold

## Native TxLeaf Artifact Byte Format

The native tx-leaf artifact is encoded in this exact order:

1. `version: u16`
2. `params_fingerprint: [u8; 48]`
3. `spec_digest: [u8; 32]`
4. `relation_id: [u8; 32]`
5. `shape_digest: [u8; 32]`
6. `statement_digest: [u8; 48]`
7. canonical receipt:
   - `statement_hash: [u8; 48]`
   - `proof_digest: [u8; 48]`
   - `public_inputs_digest: [u8; 48]`
   - `verifier_profile: [u8; 48]`
8. serialized STARK public inputs:
   - `input_flags_count: u32`
   - `input_flags` bytes
   - `output_flags_count: u32`
   - `output_flags` bytes
   - `fee: u64`
   - `value_balance_sign: u8`
   - `value_balance_magnitude: u64`
   - `merkle_root: [u8; 48]`
   - `balance_slot_asset_ids_count: u32`
   - each `asset_id: u64`
   - `stablecoin_enabled: u8`
   - `stablecoin_asset_id: u64`
   - `stablecoin_policy_version: u32`
   - `stablecoin_issuance_sign: u8`
   - `stablecoin_issuance_magnitude: u64`
   - `stablecoin_policy_hash: [u8; 48]`
   - `stablecoin_oracle_commitment: [u8; 48]`
   - `stablecoin_attestation_commitment: [u8; 48]`
9. public tx view:
   - `nullifier_count: u32`
   - each nullifier as `[u8; 48]`
   - `commitment_count: u32`
   - each commitment as `[u8; 48]`
   - `ciphertext_hash_count: u32`
   - each ciphertext hash as `[u8; 48]`
   - `balance_tag: [u8; 48]`
   - `version.circuit: u16`
   - `version.crypto: u16`
10. `stark_proof_len: u32`
11. `stark_proof` bytes
12. lattice commitment:
   - `digest: [u8; 48]`
   - `row_count: u32`
   - for each row:
     - `coeff_count: u32`
     - each `coeff: u64`
13. leaf artifact:
   - `version: u16`
   - `relation_id: [u8; 32]`
   - `shape_digest: [u8; 32]`
   - `statement_digest: [u8; 48]`
   - `witness_commitment_digest: [u8; 48]`
   - `proof_digest: [u8; 48]`

The verifier must reject the native tx-leaf artifact if any of the following fail:

- version mismatch
- parameter fingerprint mismatch
- spec digest mismatch
- relation id mismatch
- shape digest mismatch
- canonical receipt mismatch
- receipt verifier-profile mismatch
- public tx mismatch
- serialized STARK public inputs mismatch
- STARK proof verification failure
- reconstructed statement hash or public-input digest mismatch
- deterministic commitment mismatch
- proof digest mismatch
- trailing bytes

## ReceiptRoot Artifact Byte Format

The receipt-root artifact is encoded in this exact order:

1. `version: u16`
2. `params_fingerprint: [u8; 48]`
3. `spec_digest: [u8; 32]`
4. `relation_id: [u8; 32]`
5. `shape_digest: [u8; 32]`
6. `leaf_count: u32`
7. `fold_count: u32`
8. each leaf:
   - `statement_digest: [u8; 48]`
   - `witness_commitment: [u8; 48]`
   - `proof_digest: [u8; 48]`
9. each fold step:
   - `challenge_count: u32`
   - each challenge as `u64`
   - `parent_statement_digest: [u8; 48]`
   - `parent_commitment: [u8; 48]`
   - `parent_row_count: u32`
   - for each parent row:
     - `coeff_count: u32`
     - each `coeff: u64`
   - `proof_digest: [u8; 48]`
10. `root_statement_digest: [u8; 48]`
11. `root_commitment: [u8; 48]`

The verifier must reject the receipt-root artifact if any of the following fail:

- version mismatch
- parameter fingerprint mismatch
- spec digest mismatch
- relation id mismatch
- shape digest mismatch
- leaf count mismatch against the supplied leaf set
- any leaf statement digest, commitment digest, or proof digest mismatch
- any fold challenge vector mismatch
- any fold parent statement digest mismatch
- any fold parent commitment mismatch
- any fold parent row mismatch
- any fold proof digest mismatch
- root statement digest mismatch
- root commitment mismatch
- unused fold steps remain after reconstruction
- trailing bytes

## Native Artifact Size Bounds

The repository also carries exact upper bounds for current native artifact sizes. Those bounds now include the `spec_digest` field. A verifier must reject any native artifact whose encoded byte length exceeds the current bound before attempting deep validation.

## Relationship To The Spec Digest

The `spec_digest` does not replace the parameter fingerprint. The two fields serve different purposes:

- the parameter fingerprint binds the full manifest and parameter regime
- the spec digest binds the exact protocol surface that this document describes

The current implementation chooses to derive both from the same ordered backend data under different domain tags. That means changing the protocol surface or changing the parameter regime rotates both values. This is acceptable for the current experimental branch because the goal is strict mismatch rejection, not protocol continuity.
