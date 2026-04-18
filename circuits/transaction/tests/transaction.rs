use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_versioning::{
    LEGACY_PLONKY3_FRI_VERSION_BINDING, SMALLWOOD_CANDIDATE_VERSION_BINDING,
};
use serde::{Deserialize, Serialize};
use std::fs;
use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, Felt, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::p3_prover::TransactionProofParams;
use transaction_circuit::p3_verifier::{
    verify_transaction_proof_bytes_p3, verify_transaction_proof_bytes_p3_for_version,
};
use transaction_circuit::proof::{
    prove, prove_with_params, stark_public_inputs_p3,
    transaction_public_inputs_digest_from_serialized,
    transaction_statement_hash_from_public_inputs, verify,
};
use transaction_circuit::{
    analyze_smallwood_candidate_profile_for_arithmetization,
    analyze_smallwood_semantic_bridge_lower_bound_frontier_from_witness,
    analyze_smallwood_semantic_helper_aux_frontier_from_witness,
    analyze_smallwood_semantic_helper_floor_frontier_from_witness,
    analyze_smallwood_semantic_lppc_auxiliary_poseidon_spike_from_witness,
    analyze_smallwood_semantic_lppc_frontier_from_witness,
    build_smallwood_semantic_lppc_material_from_witness, decode_smallwood_proof_trace_v1,
    encode_smallwood_proof_trace_v1,
    exact_smallwood_candidate_backend_opening_surface_report_from_witness,
    exact_smallwood_candidate_profile_report_from_witness,
    exact_smallwood_semantic_bridge_lower_bound_report_from_witness,
    exact_smallwood_semantic_helper_aux_report_from_witness,
    exact_smallwood_semantic_helper_floor_report_from_witness,
    exact_smallwood_semantic_lppc_auxiliary_poseidon_spike_report_from_witness,
    exact_smallwood_semantic_lppc_identity_spike_report_from_witness,
    project_smallwood_candidate_lvcs_planner_report_from_witness,
    projected_smallwood_candidate_proof_bytes,
    projected_smallwood_candidate_proof_bytes_for_arithmetization, prove_smallwood_candidate,
    report_smallwood_candidate_proof_size, InputNoteWitness, OutputNoteWitness,
    SmallwoodArithmetization, SmallwoodLvcsPlannerGeometryKindV1, SmallwoodNoGrindingProfileV1,
    SmallwoodSemanticBridgeLowerBoundShape, SmallwoodSemanticHelperAuxShape,
    SmallwoodSemanticHelperFloorShape, SmallwoodSemanticLppcShape, StablecoinPolicyBinding,
    TransactionCircuitError, TransactionWitness, ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MirrorSmallwoodCandidateProof {
    #[serde(default = "default_mirror_smallwood_arithmetization")]
    arithmetization: SmallwoodArithmetization,
    ark_proof: Vec<u8>,
    #[serde(default)]
    auxiliary_witness_words: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LegacyMirrorSmallwoodCandidateProof {
    #[serde(default = "default_mirror_smallwood_arithmetization")]
    arithmetization: SmallwoodArithmetization,
    ark_proof: Vec<u8>,
}

fn default_mirror_smallwood_arithmetization() -> SmallwoodArithmetization {
    SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
}

fn decode_mirror_smallwood_candidate_proof(proof_bytes: &[u8]) -> MirrorSmallwoodCandidateProof {
    bincode::deserialize(proof_bytes).unwrap_or_else(|_| {
        let legacy: LegacyMirrorSmallwoodCandidateProof =
            bincode::deserialize(proof_bytes).expect("decode legacy candidate wrapper");
        MirrorSmallwoodCandidateProof {
            arithmetization: legacy.arithmetization,
            ark_proof: legacy.ark_proof,
            auxiliary_witness_words: Vec::new(),
        }
    })
}

fn encode_mirror_smallwood_candidate_proof(wrapper: &MirrorSmallwoodCandidateProof) -> Vec<u8> {
    if wrapper.auxiliary_witness_words.is_empty() {
        return bincode::serialize(&LegacyMirrorSmallwoodCandidateProof {
            arithmetization: wrapper.arithmetization,
            ark_proof: wrapper.ark_proof.clone(),
        })
        .expect("reencode legacy candidate wrapper");
    }
    bincode::serialize(wrapper).expect("reencode candidate wrapper")
}

fn read_compact_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
    let end = *cursor + 2;
    let mut word = [0u8; 2];
    word.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    u16::from_le_bytes(word)
}

fn advance_compact_smallwood_matrix(bytes: &[u8], cursor: &mut usize) {
    let rows = read_compact_u16(bytes, cursor) as usize;
    let cols = read_compact_u16(bytes, cursor) as usize;
    *cursor += rows * cols * 8;
}

fn advance_compact_smallwood_auth_paths(bytes: &[u8], cursor: &mut usize) {
    let rows = read_compact_u16(bytes, cursor) as usize;
    let lengths = &bytes[*cursor..*cursor + rows];
    *cursor += rows;
    let total_nodes = lengths.iter().map(|&len| len as usize).sum::<usize>();
    *cursor += total_nodes * 32;
}

fn compact_smallwood_masking_header_offset(inner_proof: &[u8]) -> usize {
    let mut cursor = 4 + 32 + 4 + 32;
    advance_compact_smallwood_matrix(inner_proof, &mut cursor);
    advance_compact_smallwood_matrix(inner_proof, &mut cursor);
    advance_compact_smallwood_matrix(inner_proof, &mut cursor);
    advance_compact_smallwood_matrix(inner_proof, &mut cursor);
    advance_compact_smallwood_matrix(inner_proof, &mut cursor);
    advance_compact_smallwood_auth_paths(inner_proof, &mut cursor);
    cursor
}

fn compact_smallwood_row_scalars_header_offset(inner_proof: &[u8]) -> usize {
    let mut cursor = compact_smallwood_masking_header_offset(inner_proof);
    advance_compact_smallwood_matrix(inner_proof, &mut cursor);
    advance_compact_smallwood_matrix(inner_proof, &mut cursor);
    cursor += 1;
    cursor
}

/// Compute the Merkle root from a leaf and path using CIRCUIT_MERKLE_DEPTH levels.
/// This matches what the STARK circuit actually verifies.
fn compute_merkle_root(leaf: HashFelt, position: u64, path: &[HashFelt]) -> HashFelt {
    let mut current = leaf;
    let mut pos = position;
    for (_level, sibling) in path.iter().enumerate().take(CIRCUIT_MERKLE_DEPTH) {
        current = if pos & 1 == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
        pos >>= 1;
    }
    current
}

/// Build a minimal Merkle tree with 2 leaves at positions 0 and 1.
/// Returns paths and root consistent with CIRCUIT_MERKLE_DEPTH.
fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    // At level 0: leaf0 at position 0, leaf1 at position 1 (siblings of each other)
    let mut siblings0 = vec![leaf1]; // For position 0, sibling is leaf1
    let mut siblings1 = vec![leaf0]; // For position 1, sibling is leaf0

    // Compute parent and continue up the tree with zero siblings
    let mut current = merkle_node(leaf0, leaf1);

    // Fill remaining levels up to CIRCUIT_MERKLE_DEPTH with zeros
    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        let zero = [Felt::ZERO; 6];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }

    let path0 = MerklePath {
        siblings: siblings0,
    };
    let path1 = MerklePath {
        siblings: siblings1,
    };

    (path0, path1, current)
}

fn sample_witness() -> TransactionWitness {
    let sk_spend = [42u8; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [2u8; 32],
        pk_auth,
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: 1,
        pk_recipient: [5u8; 32],
        pk_auth,
        rho: [6u8; 32],
        r: [7u8; 32],
    };

    // Build proper Merkle tree with both input notes using CIRCUIT_MERKLE_DEPTH
    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);
    // Verify paths compute to root correctly
    assert_eq!(
        compute_merkle_root(leaf0, 0, &merkle_path0.siblings),
        merkle_root
    );
    assert_eq!(
        compute_merkle_root(leaf1, 1, &merkle_path1.siblings),
        merkle_root
    );

    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 3,
            asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
            pk_recipient: [11u8; 32],
            pk_auth: [111u8; 32],
            rho: [12u8; 32],
            r: [13u8; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [21u8; 32],
            pk_auth: [121u8; 32],
            rho: [22u8; 32],
            r: [23u8; 32],
        },
    };
    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [9u8; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [8u8; 32],
                merkle_path: merkle_path1,
            },
        ],
        outputs: vec![output_native, output_asset],
        ciphertext_hashes: vec![[0u8; 48]; 2],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    }
}

fn stablecoin_witness() -> TransactionWitness {
    let sk_spend = [8u8; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 5,
        asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_recipient: [1u8; 32],
        pk_auth,
        rho: [2u8; 32],
        r: [3u8; 32],
    };

    let leaf0 = input_note_native.commitment();
    let leaf1 = [Felt::ZERO; 6];
    let (merkle_path0, _merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let output_stablecoin = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: 4242,
            pk_recipient: [4u8; 32],
            pk_auth: [104u8; 32],
            rho: [5u8; 32],
            r: [6u8; 32],
        },
    };

    TransactionWitness {
        inputs: vec![InputNoteWitness {
            note: input_note_native,
            position: 0,
            rho_seed: [7u8; 32],
            merkle_path: merkle_path0,
        }],
        outputs: vec![output_stablecoin],
        ciphertext_hashes: vec![[0u8; 48]; 1],
        sk_spend,
        merkle_root: felts_to_bytes48(&merkle_root),
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding {
            enabled: true,
            asset_id: 4242,
            policy_hash: [10u8; 48],
            oracle_commitment: [11u8; 48],
            attestation_commitment: [12u8; 48],
            issuance_delta: -5,
            policy_version: 1,
        },
        version: TransactionWitness::default_version_binding(),
    }
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
fn proving_and_verification_succeeds() -> Result<(), TransactionCircuitError> {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let proof = prove(&witness, &proving_key)?;
    assert!(
        proof.has_stark_proof(),
        "Proof should have real STARK proof bytes"
    );
    let report = verify(&proof, &verifying_key)?;
    assert!(report.verified);
    Ok(())
}

#[test]
fn verification_fails_for_bad_balance() {
    let mut witness = sample_witness();
    witness.version = LEGACY_PLONKY3_FRI_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let public_inputs = witness.public_inputs().expect("public inputs");
    let trace =
        transaction_circuit::trace::TransactionTrace::from_witness(&witness).expect("trace");
    let mut proof = transaction_circuit::proof::TransactionProof {
        nullifiers: public_inputs.nullifiers.clone(),
        commitments: public_inputs.commitments.clone(),
        balance_slots: trace.padded_balance_slots(),
        public_inputs,
        backend: transaction_circuit::TxProofBackend::Plonky3Fri,
        stark_proof: Vec::new(),
        stark_public_inputs: None,
    };
    proof.balance_slots[1].delta = 1; // corrupt non-native slot
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    assert!(matches!(err, TransactionCircuitError::BalanceMismatch(_)));
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
fn verification_fails_for_nullifier_mutation() {
    let witness = sample_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    proof.nullifiers[0][0] ^= 0x01; // tamper with nullifier
                                    // With real STARK proofs, tampering with public inputs causes verification failure.
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    // STARK proofs return generic constraint violation for any tampering
    assert!(
        matches!(
            err,
            TransactionCircuitError::ConstraintViolation(_)
                | TransactionCircuitError::ConstraintViolationOwned(_)
        ),
        "Expected STARK verification failure, got: {:?}",
        err
    );
}

#[test]
#[ignore = "experimental SmallWood packed candidate release proving is still too slow for the default test profile"]
fn smallwood_candidate_roundtrip_verifies() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");
    eprintln!(
        "smallwood candidate proof bytes: {}",
        proof.stark_proof.len()
    );
    let report = verify(&proof, &verifying_key).expect("smallwood verification");
    assert!(report.verified);
}

#[test]
#[ignore = "experimental SmallWood packed candidate release proving is still too slow for the default test profile"]
fn smallwood_candidate_proof_size_report_matches_current_release_bytes() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");
    let report =
        report_smallwood_candidate_proof_size(&proof.stark_proof).expect("size report for proof");
    let projected_bytes = projected_smallwood_candidate_proof_bytes(&witness)
        .expect("projected smallwood candidate proof bytes");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize proof size report")
    );
    assert_eq!(
        report.total_bytes,
        proof.stark_proof.len(),
        "reported total bytes must match the exact proof length"
    );
    assert_eq!(
        report.total_bytes,
        report.wrapper_bytes
            + report.transcript_bytes
            + report.commitment_bytes
            + report.opened_values_bytes
            + report.opening_payload_bytes
            + report.other_bytes,
        "proof size report sections must sum back to the exact proof length"
    );
    assert!(
        report.total_bytes <= projected_bytes,
        "measured proof bytes must stay at or below the current structural SmallWood candidate upper bound: measured={} projected={projected_bytes}",
        report.total_bytes
    );
}

#[test]
#[ignore = "experimental SmallWood backend opening-surface report is release-only and writes a checked JSON artifact"]
fn smallwood_backend_opening_surface_report() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let report = exact_smallwood_candidate_backend_opening_surface_report_from_witness(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )
    .expect("backend opening-surface report");
    let output_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json");
    let serialized =
        serde_json::to_string_pretty(&report).expect("serialize backend opening-surface report");
    fs::write(&output_path, format!("{serialized}\n"))
        .expect("write backend opening-surface report");
    eprintln!("{serialized}");
    assert!(
        report.exact_total_bytes <= report.structural_upper_bound_bytes,
        "exact wrapped candidate bytes must stay at or below the projected structural upper bound: exact={} projected={}",
        report.exact_total_bytes,
        report.structural_upper_bound_bytes
    );
    assert_eq!(
        report.backend.decs_opened_leaf_count,
        report.backend.decs_distinct_leaf_count + report.backend.decs_duplicate_leaf_count,
        "DECS leaf accounting must balance"
    );
    assert!(
        report.backend.decs_total_auth_nodes >= report.backend.decs_unique_auth_nodes,
        "auth-node dedup accounting must be monotone"
    );
    assert_eq!(
        report.backend.total_inner_proof_bytes, report.exact_ark_proof_bytes,
        "backend inner proof bytes must match the exact unwrapped proof length"
    );
    assert_eq!(
        report.backend.opened_witness_row_scalar_floor_raw_bytes,
        report.backend.opened_row_count
            * report.backend.opened_row_width
            * std::mem::size_of::<u64>(),
        "opened row-scalar bytes must stay pinned to one scalar per opened polynomial"
    );
    assert_eq!(
        report.backend.opened_witness_partial_raw_bytes,
        report.backend.opened_row_count
            * report.backend.pcs_partial_eval_width
            * std::mem::size_of::<u64>(),
        "opened-witness partial bytes must equal the planner-local width spill"
    );
    assert_eq!(
        report.backend.opened_witness_partial_extra_slot_count,
        report.backend.nb_unstacked_cols - report.backend.nb_polys,
        "planner-local partial slots must match the width spill over the one-scalar-per-poly floor"
    );
    assert!(
        report
            .backend
            .subset_eval_shape_matches_beta_packing_identity,
        "subset-eval width must stay pinned to beta * packing_factor for the current planner"
    );
    assert!(
        report.backend.pcs_subset_evals_bytes >= report.backend.subset_eval_shape_floor_raw_bytes,
        "serialized subset-eval bytes must stay at or above the raw shape floor"
    );
    assert_eq!(
        report.backend.subset_eval_shape_floor_raw_bytes,
        report.backend.decs_opened_leaf_count
            * report.backend.pcs_subset_eval_width
            * std::mem::size_of::<u64>(),
        "subset-eval raw payload must be fixed by the opened-leaf count and the beta*packing row width"
    );
    assert_eq!(
        report.backend.opened_witness_partial_raw_bytes, 384,
        "the current planner can only save the 16 extra width slots in opened witness, i.e. 384 raw bytes"
    );
}

#[test]
#[ignore = "experimental LVCS planner projection report writes a checked JSON artifact"]
fn smallwood_lvcs_planner_projection_report() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let report = project_smallwood_candidate_lvcs_planner_report_from_witness(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )
    .expect("LVCS planner projection report");
    let output_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/crypto/tx_proof_smallwood_lvcs_planner_projection_report.json");
    let serialized =
        serde_json::to_string_pretty(&report).expect("serialize LVCS planner projection report");
    fs::write(&output_path, format!("{serialized}\n"))
        .expect("write LVCS planner projection report");
    eprintln!("{serialized}");
    assert_eq!(
        report.planners.len(),
        2,
        "expected current and shared-row planners"
    );
    let current = report
        .planners
        .iter()
        .find(|entry| entry.planner == SmallwoodLvcsPlannerGeometryKindV1::CurrentTiledRowsV1)
        .expect("current tiled planner");
    let shared = report
        .planners
        .iter()
        .find(|entry| {
            entry.planner == SmallwoodLvcsPlannerGeometryKindV1::SharedPackingRowsProjectionV1
        })
        .expect("shared-row planner");
    assert_eq!(current.projected_total_bytes, 90_830);
    assert_eq!(current.inner.subset_eval_width, 128);
    assert_eq!(shared.inner.nb_lvcs_rows, 70);
    assert_eq!(shared.inner.subset_eval_width, 64);
    assert!(
        shared.projected_total_bytes > current.projected_total_bytes,
        "shared-row planner is a measured negative result and should stay above the current tiled planner"
    );
    assert!(
        !shared.inner.soundness.meets_128_bit_floor,
        "shared-row planner should stay below the no-grinding 128-bit floor on the current backend"
    );
}

#[test]
#[ignore = "experimental exact SmallWood profile proving is still too slow for the default test profile"]
fn smallwood_candidate_exact_best_projected_profile_matches_projection() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let profile = SmallwoodNoGrindingProfileV1 {
        rho: 2,
        nb_opened_evals: 3,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 32768,
        decs_nb_opened_evals: 23,
        decs_eta: 3,
        decs_pow_bits: 0,
    };
    let report = exact_smallwood_candidate_profile_report_from_witness(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
        profile,
    )
    .expect("exact report for best projected smallwood profile");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize exact profile report")
    );
    assert!(
        report.exact_total_bytes <= report.projected_total_bytes,
        "exact smallwood candidate profile bytes must stay at or below the structural projection: exact={} projected={}",
        report.exact_total_bytes,
        report.projected_total_bytes,
    );
    assert_eq!(
        report.projected_total_bytes,
        projected_smallwood_candidate_proof_bytes(&witness)
            .expect("projected current smallwood proof bytes"),
        "the shipped structural upper bound should stay pinned to the default projection helper",
    );
}

#[test]
fn smallwood_candidate_proof_stays_below_shipped_plonky3_baseline() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof_bytes = projected_smallwood_candidate_proof_bytes(&witness)
        .expect("projected smallwood candidate proof bytes");
    eprintln!("smallwood candidate projected proof bytes: {proof_bytes}");
    assert!(
        proof_bytes < 354_081,
        "expected smallwood candidate proof to stay below the shipped plonky3 baseline, got {} bytes",
        proof_bytes
    );
}

#[test]
fn smallwood_candidate_proof_stays_below_native_tx_leaf_cap() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof_bytes = projected_smallwood_candidate_proof_bytes(&witness)
        .expect("projected smallwood candidate proof bytes");
    eprintln!("smallwood candidate projected proof bytes: {proof_bytes}");
    assert!(
        proof_bytes < 524_288,
        "expected smallwood candidate proof to stay below the native tx-leaf cap, got {} bytes",
        proof_bytes
    );
}

#[test]
fn smallwood_candidate_default_projection_tracks_inline_merkle_skip_initial_mds_arithmetization() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let default_bytes = projected_smallwood_candidate_proof_bytes(&witness)
        .expect("projected smallwood candidate proof bytes");
    let inline_merkle_skip_initial_mds_bytes =
        projected_smallwood_candidate_proof_bytes_for_arithmetization(
            &witness,
            SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
        )
        .expect("projected inline-merkle skip-initial-mds smallwood candidate proof bytes");
    assert_eq!(
        default_bytes, inline_merkle_skip_initial_mds_bytes,
        "default SmallWood candidate projection should stay pinned to the inline-merkle skip-initial-mds arithmetization"
    );
}

#[test]
fn smallwood_candidate_explicit_direct_proof_wrapper_tracks_direct_arithmetization() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64V1,
    )
    .expect("smallwood candidate direct proof");
    let mirror = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    assert_eq!(
        mirror.arithmetization,
        SmallwoodArithmetization::DirectPacked64V1,
        "explicit direct SmallWood proof should carry the direct arithmetization tag"
    );
}

#[test]
fn smallwood_candidate_direct_projection_stays_at_or_below_bridge_baseline() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let direct_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64V1,
    )
    .expect("projected direct smallwood candidate proof bytes");
    let bridge_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::Bridge64V1,
    )
    .expect("projected bridge smallwood candidate proof bytes");
    assert!(
        direct_bytes <= bridge_bytes,
        "direct SmallWood candidate projection should stay at or below the bridge baseline: direct={direct_bytes} bridge={bridge_bytes}"
    );
}

#[test]
fn smallwood_candidate_compact_bindings_projection_beats_direct_baseline() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let compact_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
    )
    .expect("projected compact-binding smallwood candidate proof bytes");
    let direct_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64V1,
    )
    .expect("projected direct smallwood candidate proof bytes");
    eprintln!(
        "smallwood candidate compact projection bytes: compact={compact_bytes} direct={direct_bytes}"
    );
    assert!(
        compact_bytes < direct_bytes,
        "compact-binding SmallWood candidate projection should beat the existing direct baseline: compact={compact_bytes} direct={direct_bytes}"
    );
}

#[test]
fn smallwood_candidate_compact_binding_geometry_frontier_report() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let candidates = [
        (
            "packed16_compact",
            SmallwoodArithmetization::DirectPacked16CompactBindingsV1,
        ),
        (
            "packed32_compact",
            SmallwoodArithmetization::DirectPacked32CompactBindingsV1,
        ),
        (
            "packed64_compact",
            SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
        ),
        (
            "packed64_compact_skip_initial_mds",
            SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1,
        ),
        (
            "packed64_compact_inline_merkle_skip_initial_mds",
            SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
        ),
        (
            "packed128_compact_inline_merkle_skip_initial_mds",
            SmallwoodArithmetization::DirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1,
        ),
        (
            "packed128_compact",
            SmallwoodArithmetization::DirectPacked128CompactBindingsV1,
        ),
    ];
    let mut projections = Vec::new();
    for (label, arithmetization) in candidates {
        let projected = projected_smallwood_candidate_proof_bytes_for_arithmetization(
            &witness,
            arithmetization,
        )
        .unwrap_or_else(|err| panic!("projected {label} compact-binding bytes: {err}"));
        projections.push((label, arithmetization, projected));
    }
    eprintln!(
        "smallwood compact-binding geometry frontier: {:?}",
        projections
    );
    let packed64_bytes = projections
        .iter()
        .find(|(_, arithmetization, _)| {
            *arithmetization == SmallwoodArithmetization::DirectPacked64CompactBindingsV1
        })
        .map(|(_, _, bytes)| *bytes)
        .expect("packed64 compact frontier point");
    let packed64_skip_initial_mds_bytes = projections
        .iter()
        .find(|(_, arithmetization, _)| {
            *arithmetization
                == SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1
        })
        .map(|(_, _, bytes)| *bytes)
        .expect("packed64 compact skip-initial-mds frontier point");
    let packed64_inline_merkle_skip_initial_mds_bytes = projections
        .iter()
        .find(|(_, arithmetization, _)| {
            *arithmetization
                == SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        })
        .map(|(_, _, bytes)| *bytes)
        .expect("packed64 compact inline-merkle skip-initial-mds frontier point");
    let packed128_bytes = projections
        .iter()
        .find(|(_, arithmetization, _)| {
            *arithmetization == SmallwoodArithmetization::DirectPacked128CompactBindingsV1
        })
        .map(|(_, _, bytes)| *bytes)
        .expect("packed128 compact frontier point");
    let packed128_inline_merkle_bytes = projections
        .iter()
        .find(|(_, arithmetization, _)| {
            *arithmetization
                == SmallwoodArithmetization::DirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1
        })
        .map(|(_, _, bytes)| *bytes)
        .expect("packed128 inline-merkle compact frontier point");
    assert!(
        packed128_bytes > packed64_bytes,
        "packed128 compact-binding is a measured negative result on the current engine and should stay above packed64 until a real backend change lands: packed128={packed128_bytes} packed64={packed64_bytes}"
    );
    assert!(
        packed64_skip_initial_mds_bytes < packed64_bytes,
        "skip-initial-mds should beat the current compact64 frontier point: skip-initial-mds={packed64_skip_initial_mds_bytes} packed64={packed64_bytes}"
    );
    assert!(
        packed64_inline_merkle_skip_initial_mds_bytes < packed64_skip_initial_mds_bytes,
        "inline-merkle + skip-initial-mds should beat the explicit-merkle helper frontier point: inline-merkle={packed64_inline_merkle_skip_initial_mds_bytes} explicit-merkle={packed64_skip_initial_mds_bytes}"
    );
    assert!(
        packed128_inline_merkle_bytes < packed128_bytes,
        "inline-merkle + skip-initial-mds should beat the explicit-merkle 128x point if the auxiliary move is still real at 128x: inline-merkle={packed128_inline_merkle_bytes} explicit-merkle={packed128_bytes}"
    );
    assert!(
        packed128_inline_merkle_bytes > packed64_inline_merkle_skip_initial_mds_bytes,
        "128x inline-merkle is a measured negative result on the current engine and should stay above the shipped 64x inline-merkle winner until a real backend change lands: packed128_inline={packed128_inline_merkle_bytes} packed64_inline={packed64_inline_merkle_skip_initial_mds_bytes}"
    );
}

#[test]
fn smallwood_candidate_active_no_grinding_profile_clears_128_bits() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let profile = transaction_circuit::smallwood_no_grinding_profile_for_arithmetization(
        SmallwoodArithmetization::Bridge64V1,
    );
    let analysis = analyze_smallwood_candidate_profile_for_arithmetization(
        &witness,
        SmallwoodArithmetization::Bridge64V1,
        profile,
    )
    .expect("analyze active smallwood profile");
    assert!(
        analysis.soundness.meets_128_bit_floor,
        "active profile must clear the 128-bit no-grinding floor: {:?}",
        analysis.soundness
    );
}

#[test]
#[ignore = "negative-result profile frontier scan; confirms that two opening evaluations have no >=128-bit no-grinding candidate on the shipped line"]
fn smallwood_candidate_two_opening_eval_profile_frontier_is_empty() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let arithmetization =
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1;
    let active_bytes =
        projected_smallwood_candidate_proof_bytes_for_arithmetization(&witness, arithmetization)
            .expect("active projected proof bytes");
    let mut candidates = Vec::new();
    for rho in [2usize, 3] {
        for beta in [1usize, 2, 3, 4] {
            for decs_nb_evals in [8192usize, 16384, 32768] {
                for decs_nb_opened_evals in 18usize..=28 {
                    for decs_eta in 2usize..=4 {
                        let profile = SmallwoodNoGrindingProfileV1 {
                            rho,
                            nb_opened_evals: 2,
                            beta,
                            opening_pow_bits: 0,
                            decs_nb_evals,
                            decs_nb_opened_evals,
                            decs_eta,
                            decs_pow_bits: 0,
                        };
                        let analysis = match analyze_smallwood_candidate_profile_for_arithmetization(
                            &witness,
                            arithmetization,
                            profile,
                        ) {
                            Ok(analysis) => analysis,
                            Err(_) => continue,
                        };
                        if analysis.soundness.meets_128_bit_floor {
                            candidates.push((
                                analysis.projected_total_bytes,
                                analysis.profile,
                                analysis.soundness.security_floor_bits,
                                analysis.soundness.n_rows,
                                analysis.soundness.n_cols,
                            ));
                        }
                    }
                }
            }
        }
    }
    candidates.sort_by_key(|entry| entry.0);
    eprintln!(
        "smallwood two-opening frontier active={active_bytes} top={:?}",
        candidates.iter().take(10).collect::<Vec<_>>()
    );
    assert!(
        candidates.is_empty(),
        "two-opening frontier should stay empty at the >=128-bit no-grinding bar; found {:?}",
        candidates.iter().take(10).collect::<Vec<_>>()
    );
}

#[test]
fn smallwood_semantic_lppc_recommended_material_matches_expected_shape() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let material = build_smallwood_semantic_lppc_material_from_witness(
        &witness,
        SmallwoodSemanticLppcShape::recommended_v1(),
    )
    .expect("build semantic LPPC material");
    assert_eq!(material.statement.public_value_count, 18);
    assert_eq!(material.statement.raw_witness_elements, 3_991);
    assert_eq!(material.statement.padded_witness_elements, 4_096);
    assert_eq!(material.statement.witness_rows, 512);
    assert_eq!(material.statement.packing_factor, 8);
    assert_eq!(material.packed_witness_matrix.len(), 4_096);
    assert_eq!(material.transcript_binding.len() % 8, 0);
}

#[test]
fn smallwood_semantic_lppc_statement_binds_expected_native_digests() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let material = build_smallwood_semantic_lppc_material_from_witness(
        &witness,
        SmallwoodSemanticLppcShape::recommended_v1(),
    )
    .expect("build semantic LPPC material");
    let public_inputs = witness.public_inputs().expect("derive public inputs");
    let serialized = transaction_circuit::proof::SerializedStarkInputs {
        input_flags: vec![1, 1],
        output_flags: vec![1, 1],
        fee: witness.fee,
        value_balance_sign: 0,
        value_balance_magnitude: 0,
        merkle_root: witness.merkle_root,
        balance_slot_asset_ids: public_inputs
            .balance_slots
            .iter()
            .map(|slot| Felt::from_u64(slot.asset_id).as_canonical_u64())
            .collect(),
        stablecoin_enabled: 0,
        stablecoin_asset_id: 0,
        stablecoin_policy_version: 0,
        stablecoin_issuance_sign: 0,
        stablecoin_issuance_magnitude: 0,
        stablecoin_policy_hash: [0u8; 48],
        stablecoin_oracle_commitment: [0u8; 48],
        stablecoin_attestation_commitment: [0u8; 48],
    };
    assert_eq!(
        material.statement.statement_hash,
        transaction_statement_hash_from_public_inputs(&public_inputs)
    );
    assert_eq!(
        material.statement.public_inputs_digest,
        transaction_public_inputs_digest_from_serialized(&serialized)
            .expect("hash serialized public inputs")
    );
}

#[test]
fn smallwood_semantic_lppc_frontier_reports_current_engine_projections() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let reports = analyze_smallwood_semantic_lppc_frontier_from_witness(
        &witness,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )
    .expect("analyze semantic LPPC frontier");
    eprintln!("smallwood semantic LPPC frontier: {:?}", reports);
    assert_eq!(reports.len(), 3);
    assert!(reports
        .iter()
        .all(|report| report.soundness.meets_128_bit_floor));
    assert_eq!(
        reports[0].shape,
        SmallwoodSemanticLppcShape::packed_1024x4_v1()
    );
    assert_eq!(reports[0].projected_total_bytes, 54_240);
    assert_eq!(
        reports[1].shape,
        SmallwoodSemanticLppcShape::packed_512x8_v1()
    );
    assert_eq!(reports[1].projected_total_bytes, 37_776);
    assert_eq!(
        reports[2].shape,
        SmallwoodSemanticLppcShape::packed_256x16_v1()
    );
    assert_eq!(reports[2].projected_total_bytes, 32_712);
}

#[test]
#[ignore = "experimental semantic LPPC identity spike proving is still too slow for the default test profile"]
fn smallwood_semantic_lppc_identity_spike_frontier_matches_projection() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let reports = [
        SmallwoodSemanticLppcShape::packed_1024x4_v1(),
        SmallwoodSemanticLppcShape::packed_512x8_v1(),
        SmallwoodSemanticLppcShape::packed_256x16_v1(),
    ]
    .into_iter()
    .map(|shape| exact_smallwood_semantic_lppc_identity_spike_report_from_witness(&witness, shape))
    .collect::<Result<Vec<_>, _>>()
    .expect("build exact semantic LPPC identity frontier");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&reports).expect("serialize semantic LPPC identity frontier")
    );
    assert_eq!(reports.len(), 3);
    assert_eq!(
        reports[0].shape,
        SmallwoodSemanticLppcShape::packed_1024x4_v1()
    );
    assert_eq!(
        reports[0].exact_total_bytes,
        reports[0].projected_total_bytes
    );
    assert_eq!(reports[0].exact_total_bytes, 54_240);
    assert_eq!(
        reports[1].shape,
        SmallwoodSemanticLppcShape::packed_512x8_v1()
    );
    assert_eq!(
        reports[1].exact_total_bytes,
        reports[1].projected_total_bytes
    );
    assert_eq!(reports[1].exact_total_bytes, 37_776);
    assert_eq!(
        reports[2].shape,
        SmallwoodSemanticLppcShape::packed_256x16_v1()
    );
    assert_eq!(
        reports[2].exact_total_bytes,
        reports[2].projected_total_bytes
    );
    assert_eq!(reports[2].exact_total_bytes, 32_712);
}

#[test]
fn smallwood_semantic_lppc_auxiliary_poseidon_spike_projection_shows_aux_path_loses() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let reports = [
        SmallwoodSemanticLppcShape::packed_1024x4_v1(),
        SmallwoodSemanticLppcShape::packed_512x8_v1(),
        SmallwoodSemanticLppcShape::packed_256x16_v1(),
    ]
    .into_iter()
    .map(|shape| {
        analyze_smallwood_semantic_lppc_auxiliary_poseidon_spike_from_witness(
            &witness,
            shape,
            ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
        )
    })
    .collect::<Result<Vec<_>, _>>()
    .expect("analyze semantic LPPC auxiliary poseidon spike");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&reports)
            .expect("serialize semantic LPPC auxiliary poseidon spike report")
    );
    assert_eq!(reports.len(), 3);
    assert!(reports
        .iter()
        .all(|report| report.auxiliary_poseidon_words == 54_912));
    assert!(reports
        .iter()
        .all(|report| { report.projected_total_bytes > report.shipped_smallwood_candidate_bytes }));
}

#[test]
fn smallwood_semantic_lppc_auxiliary_poseidon_exact_spike_matches_projection_and_still_loses() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let report = exact_smallwood_semantic_lppc_auxiliary_poseidon_spike_report_from_witness(
        &witness,
        SmallwoodSemanticLppcShape::recommended_v1(),
    )
    .expect("build exact semantic LPPC auxiliary poseidon report");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report)
            .expect("serialize semantic LPPC auxiliary poseidon exact report")
    );
    assert!(
        report.exact_total_bytes == report.projected_total_bytes,
        "the exact auxiliary poseidon spike should match the structural projection on the fixed engine path"
    );
    assert!(
        report.exact_total_bytes > 400_000,
        "the full auxiliary poseidon transport should remain obviously unshippable"
    );
}

#[test]
fn smallwood_semantic_bridge_lower_bound_frontier_quantifies_current_backend_floor() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let reports = analyze_smallwood_semantic_bridge_lower_bound_frontier_from_witness(
        &witness,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )
    .expect("analyze semantic bridge lower-bound frontier");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&reports)
            .expect("serialize semantic bridge lower-bound frontier")
    );
    assert_eq!(reports.len(), 3);
    assert_eq!(
        reports[0].shape,
        SmallwoodSemanticBridgeLowerBoundShape::packed_32x_v1()
    );
    assert_eq!(
        reports[1].shape,
        SmallwoodSemanticBridgeLowerBoundShape::packed_64x_v1()
    );
    assert_eq!(
        reports[2].shape,
        SmallwoodSemanticBridgeLowerBoundShape::packed_128x_v1()
    );
    assert!(reports[0].projected_total_bytes > reports[1].projected_total_bytes);
    assert!(reports[2].projected_total_bytes > reports[1].projected_total_bytes);
    assert_eq!(reports[1].projected_total_bytes, 99_456);
    assert!(
        reports[1].projected_total_bytes >= reports[1].shipped_smallwood_candidate_bytes,
        "after promoting the 98,532-byte branch, the pure semantic lower bound should no longer beat the shipped default"
    );
}

#[test]
#[ignore = "experimental semantic lower-bound identity proving is still too slow for the default test profile"]
fn smallwood_semantic_bridge_lower_bound_exact_report_matches_projection() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let report = exact_smallwood_semantic_bridge_lower_bound_report_from_witness(
        &witness,
        SmallwoodSemanticBridgeLowerBoundShape::recommended_v1(),
    )
    .expect("build exact semantic bridge lower-bound report");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report)
            .expect("serialize semantic bridge lower-bound report")
    );
    assert_eq!(report.exact_total_bytes, report.projected_total_bytes);
    assert!(
        report.exact_total_bytes >= report.shipped_smallwood_candidate_bytes,
        "after promoting the 98,532-byte branch, the exact lower-bound identity spike should no longer beat the shipped default"
    );
}

#[test]
fn smallwood_semantic_helper_floor_frontier_exposes_lane_visible_semantic_tax() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let reports = analyze_smallwood_semantic_helper_floor_frontier_from_witness(
        &witness,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )
    .expect("analyze semantic helper floor frontier");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&reports).expect("serialize semantic helper floor frontier")
    );
    assert_eq!(reports.len(), 3);
    assert_eq!(
        reports[0].shape,
        SmallwoodSemanticHelperFloorShape::packed_32x_v1()
    );
    assert_eq!(
        reports[1].shape,
        SmallwoodSemanticHelperFloorShape::packed_64x_v1()
    );
    assert_eq!(
        reports[2].shape,
        SmallwoodSemanticHelperFloorShape::packed_128x_v1()
    );
    assert!(
        reports[1].projected_total_bytes > 99_456,
        "once lane-visible nonlinear helper rows return, the current-backend floor should sit above the pure semantic lower bound"
    );
    assert!(
        reports[1].projected_total_bytes >= reports[1].shipped_smallwood_candidate_bytes,
        "if the helper floor is still below the shipped bridge there is still a live current-backend semantic-adapter path to pursue"
    );
}

#[test]
#[ignore = "experimental semantic helper-floor identity proving is still too slow for the default test profile"]
fn smallwood_semantic_helper_floor_exact_report_matches_projection() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let report = exact_smallwood_semantic_helper_floor_report_from_witness(
        &witness,
        SmallwoodSemanticHelperFloorShape::recommended_v1(),
    )
    .expect("build exact semantic helper floor report");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize semantic helper floor report")
    );
    assert_eq!(report.exact_total_bytes, report.projected_total_bytes);
    assert!(
        report.exact_total_bytes >= report.shipped_smallwood_candidate_bytes,
        "if the exact helper floor stays below the shipped bridge then the current backend still has a semantic-adapter path left"
    );
}

#[test]
fn smallwood_semantic_helper_aux_frontier_quantifies_auxiliary_escape_hatch() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let reports = analyze_smallwood_semantic_helper_aux_frontier_from_witness(
        &witness,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )
    .expect("analyze semantic helper-aux frontier");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&reports).expect("serialize semantic helper-aux frontier")
    );
    assert_eq!(reports.len(), 9);
    assert_eq!(
        reports[0].shape,
        SmallwoodSemanticHelperAuxShape::packed_32x_v1()
    );
    assert_eq!(
        reports[1].shape,
        SmallwoodSemanticHelperAuxShape::packed_64x_v1()
    );
    assert_eq!(
        reports[2].shape,
        SmallwoodSemanticHelperAuxShape::packed_128x_v1()
    );
    assert!(
        reports[3].shape
            == SmallwoodSemanticHelperAuxShape::packed_32x_inline_merkle_skip_initial_mds_v1()
    );
    assert!(
        reports[4].shape
            == SmallwoodSemanticHelperAuxShape::packed_64x_inline_merkle_skip_initial_mds_v1()
    );
    assert!(
        reports[5].shape
            == SmallwoodSemanticHelperAuxShape::packed_128x_inline_merkle_skip_initial_mds_v1()
    );
    assert!(
        reports[6].shape == SmallwoodSemanticHelperAuxShape::packed_32x_semantic_adapter_floor_v1()
    );
    assert!(
        reports[7].shape == SmallwoodSemanticHelperAuxShape::packed_64x_semantic_adapter_floor_v1()
    );
    assert!(
        reports[8].shape
            == SmallwoodSemanticHelperAuxShape::packed_128x_semantic_adapter_floor_v1()
    );
    assert!(
        reports[4].projected_total_bytes < reports[1].projected_total_bytes,
        "inline merkle + skip-initial-mds should beat the legacy 64x helper-aux branch"
    );
    assert!(
        reports[7].projected_total_bytes < reports[4].projected_total_bytes,
        "a semantic-adapter floor that derives lane-local helpers should beat the inline-merkle helper-aux branch"
    );
    assert!(
        reports[7].projected_total_bytes > 88_500,
        "the current semantic-adapter floor should still miss the Branch A keep gate on this backend"
    );
}

#[test]
#[ignore = "experimental semantic helper-aux identity proving is still too slow for the default test profile"]
fn smallwood_semantic_helper_aux_exact_report_matches_projection() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let report = exact_smallwood_semantic_helper_aux_report_from_witness(
        &witness,
        SmallwoodSemanticHelperAuxShape::recommended_v1(),
    )
    .expect("build exact semantic helper-aux report");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize semantic helper-aux report")
    );
    let output_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/crypto/tx_proof_smallwood_semantic_adapter_floor_report.json");
    let serialized =
        serde_json::to_string_pretty(&report).expect("serialize semantic adapter floor report");
    fs::write(&output_path, format!("{serialized}\n"))
        .expect("write semantic adapter floor report");
    assert!(
        report.exact_total_bytes <= report.projected_total_bytes,
        "exact semantic-adapter floor should stay at or below its structural projection"
    );
    assert!(
        report.exact_total_bytes < report.shipped_smallwood_candidate_bytes,
        "the current semantic-adapter floor should still beat the shipped proof slightly once measured exactly"
    );
    assert!(
        report.exact_total_bytes > 85_500,
        "the exact semantic-adapter floor should still miss the Branch A material keep gate on this backend"
    );
}

#[test]
fn smallwood_candidate_active_profile_beats_previous_decs_point() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let previous_profile = SmallwoodNoGrindingProfileV1 {
        rho: 2,
        nb_opened_evals: 3,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 16_384,
        decs_nb_opened_evals: 29,
        decs_eta: 3,
        decs_pow_bits: 0,
    };
    let previous = analyze_smallwood_candidate_profile_for_arithmetization(
        &witness,
        SmallwoodArithmetization::Bridge64V1,
        previous_profile,
    )
    .expect("analyze previous smallwood profile");
    let active = analyze_smallwood_candidate_profile_for_arithmetization(
        &witness,
        SmallwoodArithmetization::Bridge64V1,
        transaction_circuit::smallwood_no_grinding_profile_for_arithmetization(
            SmallwoodArithmetization::Bridge64V1,
        ),
    )
    .expect("analyze active smallwood profile");
    eprintln!(
        "smallwood candidate bridge profile bytes: previous={} active={}",
        previous.projected_total_bytes, active.projected_total_bytes
    );
    assert!(
        active.soundness.meets_128_bit_floor,
        "active profile must clear the 128-bit no-grinding floor: {:?}",
        active.soundness
    );
    assert!(
        active.projected_total_bytes < previous.projected_total_bytes,
        "active profile should beat the previous DECS point: previous={} active={}",
        previous.projected_total_bytes,
        active.projected_total_bytes
    );
}

#[test]
fn smallwood_candidate_direct_wrapper_uses_succinct_row_scalar_openings() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64V1,
    )
    .expect("smallwood candidate direct proof");
    let outer = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    let inner = decode_smallwood_proof_trace_v1(&outer.ark_proof)
        .expect("decode inner smallwood proof trace");
    assert!(
        !inner.opened_witness_row_scalars.is_empty(),
        "row-scalar openings must be present"
    );
}

#[test]
#[ignore = "experimental negative-result geometry measurement; proves correctly but is materially larger than the compact64 winner"]
fn smallwood_candidate_packed32_compact_roundtrip_verifies_but_loses_to_compact64() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked32CompactBindingsV1,
    )
    .expect("smallwood candidate packed32 compact proof");
    let wrapper = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    assert_eq!(
        wrapper.arithmetization,
        SmallwoodArithmetization::DirectPacked32CompactBindingsV1,
        "packed32 compact SmallWood proof should carry the packed32 compact arithmetization tag"
    );
    let size_report =
        report_smallwood_candidate_proof_size(&proof.stark_proof).expect("packed32 size report");
    let projected_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked32CompactBindingsV1,
    )
    .expect("projected packed32 compact bytes");
    let compact64_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
    )
    .expect("projected compact64 bytes");
    eprintln!(
        "packed32 compact actual bytes={} compact64 baseline={compact64_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes <= projected_bytes,
        "packed32 compact actual bytes should stay at or below the structural projection: actual={} projected={projected_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes > compact64_bytes,
        "packed32 compact is a measured negative result and should stay above the compact64 winner: packed32={} compact64={compact64_bytes}",
        size_report.total_bytes
    );
    let report = verify(&proof, &generate_keys().1).expect("packed32 compact verification");
    assert!(report.verified);
}

#[test]
#[ignore = "experimental negative-result geometry measurement; proves correctly but is materially larger than the compact64 winner"]
fn smallwood_candidate_packed128_compact_roundtrip_verifies_but_loses_to_compact64() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked128CompactBindingsV1,
    )
    .expect("smallwood candidate packed128 compact proof");
    let wrapper = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    assert_eq!(
        wrapper.arithmetization,
        SmallwoodArithmetization::DirectPacked128CompactBindingsV1,
        "packed128 compact SmallWood proof should carry the packed128 compact arithmetization tag"
    );
    let size_report =
        report_smallwood_candidate_proof_size(&proof.stark_proof).expect("packed128 size report");
    let projected_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked128CompactBindingsV1,
    )
    .expect("projected packed128 compact bytes");
    let compact64_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
    )
    .expect("projected compact64 bytes");
    eprintln!(
        "packed128 compact actual bytes={} compact64 baseline={compact64_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes <= projected_bytes,
        "packed128 compact actual bytes should stay at or below the structural projection: actual={} projected={projected_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes > compact64_bytes,
        "packed128 compact is a measured negative result and should stay above the compact64 winner: packed128={} compact64={compact64_bytes}",
        size_report.total_bytes
    );
    let report = verify(&proof, &generate_keys().1).expect("packed128 compact verification");
    assert!(report.verified);
}

#[test]
#[ignore = "experimental SmallWood compact-binding release proving is still too slow for the default test profile"]
fn smallwood_candidate_compact_bindings_roundtrip_verifies() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
    )
    .expect("smallwood candidate compact-binding proof");
    eprintln!(
        "smallwood candidate compact-binding proof bytes: {}",
        proof.stark_proof.len()
    );
    let report =
        verify(&proof, &generate_keys().1).expect("smallwood compact-binding verification");
    assert!(report.verified);
}

#[test]
#[ignore = "experimental near-miss geometry measurement; proves correctly and beats compact64 slightly, but is not promoted unless the exact win is worth the extra surface"]
fn smallwood_candidate_compact_bindings_skip_initial_mds_roundtrip_verifies_and_beats_compact64() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1,
    )
    .expect("smallwood candidate compact-binding skip-initial-mds proof");
    let wrapper = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    assert_eq!(
        wrapper.arithmetization,
        SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1,
        "skip-initial-mds proof should carry the skip-initial-mds arithmetization tag"
    );
    let size_report = report_smallwood_candidate_proof_size(&proof.stark_proof)
        .expect("skip-initial-mds size report");
    let projected_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1,
    )
    .expect("projected skip-initial-mds bytes");
    let compact64_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
    )
    .expect("projected compact64 bytes");
    eprintln!(
        "skip-initial-mds actual bytes={} compact64 baseline={compact64_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes <= projected_bytes,
        "skip-initial-mds actual bytes should stay at or below the structural projection: actual={} projected={projected_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes < compact64_bytes,
        "skip-initial-mds should beat the current compact64 geometry on exact bytes: skip-initial-mds={} compact64={compact64_bytes}",
        size_report.total_bytes
    );
    let report = verify(&proof, &generate_keys().1)
        .expect("smallwood compact-binding skip-initial-mds verification");
    assert!(report.verified);
}

#[test]
#[ignore = "experimental inline-merkle backend branch is still too slow for the default test profile"]
fn smallwood_candidate_compact_bindings_inline_merkle_skip_initial_mds_roundtrip_verifies_and_beats_skip_initial_mds(
) {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
    )
    .expect("smallwood candidate inline-merkle compact-binding proof");
    let wrapper = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    assert_eq!(
        wrapper.arithmetization,
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
        "inline-merkle proof should carry the inline-merkle arithmetization tag"
    );
    let size_report = report_smallwood_candidate_proof_size(&proof.stark_proof)
        .expect("inline-merkle size report");
    let projected_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
    )
    .expect("projected inline-merkle bytes");
    let skip_initial_mds_bytes = projected_smallwood_candidate_proof_bytes_for_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1,
    )
    .expect("projected skip-initial-mds bytes");
    eprintln!(
        "inline-merkle actual bytes={} skip-initial-mds baseline={skip_initial_mds_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes <= projected_bytes,
        "inline-merkle actual bytes should stay at or below the structural projection: actual={} projected={projected_bytes}",
        size_report.total_bytes
    );
    assert!(
        size_report.total_bytes < skip_initial_mds_bytes,
        "inline-merkle should beat the explicit-merkle helper geometry on exact bytes: inline-merkle={} explicit-merkle={skip_initial_mds_bytes}",
        size_report.total_bytes
    );
    let report = verify(&proof, &generate_keys().1)
        .expect("smallwood compact-binding inline-merkle verification");
    assert!(report.verified);
}

#[test]
#[ignore = "experimental SmallWood compact-binding release proving is still too slow for the default test profile"]
fn smallwood_candidate_compact_bindings_proof_size_report_beats_current_release_bytes() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof = transaction_circuit::prove_smallwood_candidate_with_arithmetization(
        &witness,
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
    )
    .expect("smallwood candidate compact-binding proof");
    let report =
        report_smallwood_candidate_proof_size(&proof.stark_proof).expect("size report for proof");
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize compact proof size report")
    );
    assert!(
        report.total_bytes < 100_956,
        "expected compact-binding SmallWood proof to beat the current release baseline, got {} bytes",
        report.total_bytes
    );
}

#[test]
fn smallwood_candidate_verification_fails_for_active_ciphertext_hash_mutation() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");
    proof.public_inputs.ciphertext_hashes[0][0] ^= 0x01;
    let err =
        verify(&proof, &generate_keys().1).expect_err("expected SmallWood verification failure");
    assert!(
        matches!(
            err,
            TransactionCircuitError::ConstraintViolation(_)
                | TransactionCircuitError::ConstraintViolationOwned(_)
        ),
        "unexpected verifier error: {err:?}"
    );
}

#[test]
fn smallwood_candidate_verification_fails_for_enabled_stablecoin_binding_mutation() {
    let mut witness = stablecoin_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let verifying_key = generate_keys().1;
    for mutate in 0..4 {
        let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");
        match mutate {
            0 => proof.public_inputs.stablecoin.policy_version ^= 1,
            1 => proof.public_inputs.stablecoin.policy_hash[0] ^= 0x01,
            2 => proof.public_inputs.stablecoin.oracle_commitment[0] ^= 0x01,
            _ => proof.public_inputs.stablecoin.attestation_commitment[0] ^= 0x01,
        }
        let err =
            verify(&proof, &verifying_key).expect_err("expected SmallWood verification failure");
        assert!(
            matches!(
                err,
                TransactionCircuitError::ConstraintViolation(_)
                    | TransactionCircuitError::ConstraintViolationOwned(_)
            ),
            "unexpected verifier error: {err:?}"
        );
    }
}

#[test]
fn smallwood_candidate_proof_reaches_three_x_reduction_against_shipped_plonky3() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let proof_bytes = projected_smallwood_candidate_proof_bytes(&witness)
        .expect("projected smallwood candidate proof bytes");
    const SHIPPED_PLONKY3_PROOF_BYTES: usize = 354_081;
    const THREE_X_THRESHOLD: usize = SHIPPED_PLONKY3_PROOF_BYTES / 3;
    eprintln!("smallwood candidate projected proof bytes: {proof_bytes}");
    assert!(
        proof_bytes < THREE_X_THRESHOLD,
        "expected smallwood candidate proof to beat the 3x reduction threshold of {} bytes, got {} bytes",
        THREE_X_THRESHOLD,
        proof_bytes
    );
}

#[test]
#[ignore = "experimental SmallWood packed candidate release proving is still too slow for the default test profile"]
fn smallwood_candidate_rejects_semantic_mutation() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");
    proof.public_inputs.balance_tag[0] ^= 0x5a;
    let err = verify(&proof, &verifying_key).expect_err("tampered candidate must fail");
    assert!(
        err.to_string().contains("smallwood candidate") || err.to_string().contains("mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
#[ignore = "redteam regression for verifier hardening on the experimental SmallWood backend"]
fn smallwood_candidate_rejects_partial_eval_tampering() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");

    let mut outer = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    let mut inner =
        decode_smallwood_proof_trace_v1(&outer.ark_proof).expect("decode inner smallwood proof");
    inner.pcs.partial_evals_mut_v1()[0][0] ^= 0xdead_beef_u64;
    outer.ark_proof =
        encode_smallwood_proof_trace_v1(&inner).expect("reencode inner smallwood proof");
    proof.stark_proof = encode_mirror_smallwood_candidate_proof(&outer);

    let err =
        verify(&proof, &verifying_key).expect_err("tampered partial_evals unexpectedly verified");
    assert!(
        err.to_string().contains("shape mismatch") || err.to_string().contains("smallwood"),
        "unexpected error: {err}"
    );
}

#[test]
#[ignore = "redteam probe for malformed-proof panic behavior on the experimental SmallWood backend"]
fn smallwood_candidate_malformed_inner_shapes_do_not_panic() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");

    let mut outer = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    let mut inner = outer.ark_proof.clone();
    let masking_header = compact_smallwood_masking_header_offset(&inner);
    inner[masking_header + 2] = 0;
    inner[masking_header + 3] = 0;
    outer.ark_proof = inner;
    proof.stark_proof = encode_mirror_smallwood_candidate_proof(&outer);

    let result = std::panic::catch_unwind(|| verify(&proof, &verifying_key));
    match result {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("malformed proof unexpectedly verified"),
        Err(_) => panic!("malformed proof triggered a verifier panic"),
    }
}

#[test]
#[ignore = "redteam probe for malformed all_evals panic behavior on the experimental SmallWood backend"]
fn smallwood_candidate_malformed_all_evals_do_not_panic() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");

    let mut outer = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    let mut inner = outer.ark_proof.clone();
    let row_scalars_header = compact_smallwood_row_scalars_header_offset(&inner);
    inner[row_scalars_header + 2] = 0;
    inner[row_scalars_header + 3] = 0;
    outer.ark_proof = inner;
    proof.stark_proof = encode_mirror_smallwood_candidate_proof(&outer);

    let result = std::panic::catch_unwind(|| verify(&proof, &verifying_key));
    match result {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("malformed proof unexpectedly verified"),
        Err(_) => panic!("malformed all_evals triggered a verifier panic"),
    }
}

#[test]
fn smallwood_candidate_rejects_opened_witness_mode_mismatch() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let mut proof = prove_smallwood_candidate(&witness).expect("smallwood candidate proof");

    let mut outer = decode_mirror_smallwood_candidate_proof(&proof.stark_proof);
    let mut inner =
        decode_smallwood_proof_trace_v1(&outer.ark_proof).expect("decode inner smallwood proof");
    inner.opened_witness_row_scalars.clear();
    outer.ark_proof =
        encode_smallwood_proof_trace_v1(&inner).expect("reencode inner smallwood proof");
    proof.stark_proof = encode_mirror_smallwood_candidate_proof(&outer);

    let err =
        verify(&proof, &verifying_key).expect_err("mode-mismatched proof unexpectedly verified");
    assert!(
        err.to_string().contains("opened witness mode")
            || err.to_string().contains("row-scalar")
            || err.to_string().contains("smallwood"),
        "unexpected error: {err}"
    );
}

#[test]
#[ignore = "redteam probe for PCS/semantic binding on the experimental SmallWood backend"]
fn smallwood_candidate_rejects_spliced_pcs_layer() {
    let mut witness = sample_witness();
    witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
    let (_proving_key, verifying_key) = generate_keys();
    let proof_a = prove_smallwood_candidate(&witness).expect("smallwood candidate proof a");
    let proof_b = prove_smallwood_candidate(&witness).expect("smallwood candidate proof b");

    let mut outer_a = decode_mirror_smallwood_candidate_proof(&proof_a.stark_proof);
    let outer_b = decode_mirror_smallwood_candidate_proof(&proof_b.stark_proof);
    let mut inner_a = decode_smallwood_proof_trace_v1(&outer_a.ark_proof).expect("decode inner a");
    let inner_b = decode_smallwood_proof_trace_v1(&outer_b.ark_proof).expect("decode inner b");

    inner_a.pcs = inner_b.pcs;
    inner_a.salt = inner_b.salt;
    outer_a.ark_proof = encode_smallwood_proof_trace_v1(&inner_a).expect("reencode inner a");

    let mut spliced = proof_a.clone();
    spliced.stark_proof = encode_mirror_smallwood_candidate_proof(&outer_a);

    let err = verify(&spliced, &verifying_key).expect_err("spliced PCS unexpectedly verified");
    assert!(
        err.to_string().contains("smallwood") || err.to_string().contains("mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
fn verification_fails_for_stablecoin_policy_hash_mutation() {
    let witness = stablecoin_witness();
    let (proving_key, verifying_key) = generate_keys();
    let mut proof = prove(&witness, &proving_key).expect("proof generation");
    let mut stark_inputs = proof
        .stark_public_inputs
        .clone()
        .expect("stark public inputs");
    stark_inputs.stablecoin_policy_hash[0] ^= 0x01;
    proof.stark_public_inputs = Some(stark_inputs);
    let err = verify(&proof, &verifying_key).expect_err("expected failure");
    assert!(
        matches!(
            err,
            TransactionCircuitError::ConstraintViolation(_)
                | TransactionCircuitError::ConstraintViolationOwned(_)
        ),
        "Expected STARK verification failure, got: {:?}",
        err
    );
}

#[test]
#[cfg_attr(
    not(feature = "plonky3-e2e"),
    ignore = "slow: generates a full Plonky3 proof; run with --features plonky3-e2e --release"
)]
fn low_query_proof_is_rejected_by_release_profile() {
    let witness = sample_witness();
    let (proving_key, _verifying_key) = generate_keys();
    let proof = prove_with_params(
        &witness,
        &proving_key,
        TransactionProofParams {
            log_blowup: 4,
            num_queries: 16,
        },
    )
    .expect("proof generation");
    let stark_public_inputs = stark_public_inputs_p3(&proof).expect("decode public inputs");
    verify_transaction_proof_bytes_p3(&proof.stark_proof, &stark_public_inputs)
        .expect("shape-specific verifier should accept the proof");
    let err = verify_transaction_proof_bytes_p3_for_version(
        &proof.stark_proof,
        &stark_public_inputs,
        witness.version,
    )
    .expect_err("release verifier should reject low-query proof");
    assert!(
        err.to_string().contains("proof FRI profile mismatch"),
        "unexpected verifier error: {err}"
    );
}
