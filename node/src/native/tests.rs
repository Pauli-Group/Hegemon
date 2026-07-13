use super::*;
use protocol_shielded_pool::types::{
    ReceiptRootMetadata, ReceiptRootProofPayload, TxValidityReceipt,
};

#[derive(Debug, Clone, Copy)]
struct NormalizedScaleByte;

impl Encode for NormalizedScaleByte {
    fn size_hint(&self) -> usize {
        1
    }

    fn encode_to<T: codec::Output + ?Sized>(&self, dest: &mut T) {
        dest.push_byte(0);
    }
}

impl Decode for NormalizedScaleByte {
    fn decode<I: codec::Input>(input: &mut I) -> std::result::Result<Self, codec::Error> {
        let _ = input.read_byte()?;
        Ok(Self)
    }
}

#[derive(Debug, Clone, Copy)]
struct NormalizedBincodeByte;

impl Serialize for NormalizedBincodeByte {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(0)
    }
}

impl<'de> Deserialize<'de> for NormalizedBincodeByte {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let _ = u8::deserialize(deserializer)?;
        Ok(Self)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSupplyVectorFile {
    schema_version: u32,
    monetary_constants: serde_json::Value,
    subsidy_schedule_cases: Vec<serde_json::Value>,
    consensus_supply_cases: Vec<serde_json::Value>,
    native_supply_cases: Vec<LeanNativeSupplyCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanConsensusVectorFile {
    schema_version: u32,
    fork_choice_cases: Vec<LeanForkChoiceCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanForkChoiceCase {
    name: String,
    current_work: String,
    current_height: u64,
    current_hash: String,
    candidate_work: String,
    candidate_height: u64,
    candidate_hash: String,
    select_candidate: bool,
    selected_source: String,
    selected_work: String,
    selected_height: u64,
    selected_hash: String,
    selected_work_at_least_current: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanNativeSupplyCase {
    name: String,
    parent_supply: String,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
    expected_delta: Option<String>,
    expected_supply: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionOrderVectorFile {
    schema_version: u32,
    action_order_cases: Vec<LeanActionOrderCase>,
    transfer_order_preimage_cases: Vec<LeanTransferOrderPreimageCase>,
    non_transfer_order_preimage_cases: Vec<LeanNonTransferOrderPreimageCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionOrderCase {
    name: String,
    actions: Vec<LeanOrderedAction>,
    expected_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanOrderedAction {
    is_transfer: bool,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanTransferOrderPreimageCase {
    name: String,
    route: String,
    binding_hash: String,
    nullifiers: Vec<String>,
    received_ms: u64,
    resampled_received_ms: u64,
    expected_preimage: String,
    expected_preimage_len: usize,
    expected_same_after_resample: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanNonTransferOrderPreimageCase {
    name: String,
    route: String,
    family_id: u16,
    action_id: u16,
    semantic_hash: String,
    nullifiers: Vec<String>,
    received_ms: u64,
    resampled_received_ms: u64,
    tx_hash: String,
    resampled_tx_hash: String,
    expected_preimage: String,
    expected_preimage_len: usize,
    expected_same_after_resample: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionHashAdmissionVectorFile {
    schema_version: u32,
    action_hash_admission_cases: Vec<LeanActionHashAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionHashAdmissionCase {
    name: String,
    action_count_matches: bool,
    action_hashes_match: bool,
    action_hashes_unique: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionRootTranscriptVectorFile {
    schema_version: u32,
    action_root_transcript_cases: Vec<LeanActionRootTranscriptCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionRootTranscriptCase {
    name: String,
    action_hashes_hex: Vec<String>,
    expected_preimage_hex: String,
    expected_preimage_len: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanAnnouncedBlockAdmissionVectorFile {
    schema_version: u32,
    announced_block_admission_cases: Vec<LeanAnnouncedBlockAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanAnnouncedBlockAdmissionCase {
    name: String,
    parent_height: u64,
    announced_height: u64,
    parent_hash_matches: bool,
    parent_timestamp_ms: u64,
    announced_timestamp_ms: u64,
    now_ms: u64,
    max_future_skew_ms: u64,
    hash_matches_work_hash: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockIndexReloadVectorFile {
    schema_version: u32,
    block_index_reload_cases: Vec<LeanBlockIndexReloadCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockIndexReloadCase {
    name: String,
    chain_reconstructed: bool,
    chain_nonempty: bool,
    genesis_matches_expected: bool,
    best_metadata_matches_chain: bool,
    canonical_heights_contiguous: bool,
    canonical_chain_ids_match: bool,
    canonical_rules_hashes_match: bool,
    canonical_hashes_match_work_hashes: bool,
    canonical_parent_hashes_contiguous: bool,
    height_keys_well_formed: bool,
    height_values_well_formed: bool,
    no_extra_height_indexes: bool,
    height_index_heights_match_chain: bool,
    height_index_hashes_match_chain: bool,
    all_canonical_heights_indexed: bool,
    genesis_marker_present: bool,
    genesis_marker_length_valid: bool,
    genesis_marker_matches_expected: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
    expected_repairs_genesis_marker: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCanonicalReorgChainAdmissionVectorFile {
    schema_version: u32,
    canonical_reorg_chain_admission_cases: Vec<LeanCanonicalReorgChainAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCanonicalReorgChainAdmissionCase {
    name: String,
    chain_nonempty: bool,
    genesis_matches_expected: bool,
    best_metadata_matches_chain: bool,
    canonical_heights_contiguous: bool,
    canonical_chain_ids_match: bool,
    canonical_rules_hashes_match: bool,
    canonical_hashes_match_work_hashes: bool,
    canonical_parent_hashes_contiguous: bool,
    block_record_count_matches_chain: bool,
    block_records_match_chain: bool,
    height_entry_count_matches_chain: bool,
    height_entries_match_chain: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCanonicalStateReloadVectorFile {
    schema_version: u32,
    canonical_state_reload_cases: Vec<LeanCanonicalStateReloadCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCanonicalStateReloadCase {
    name: String,
    nullifier_keys_well_formed: bool,
    nullifier_markers_valid: bool,
    commitment_keys_well_formed: bool,
    commitment_values_well_formed: bool,
    commitment_indexes_contiguous: bool,
    commitment_tree_rebuilt: bool,
    commitment_root_matches_best: bool,
    nullifier_root_matches_best: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeReplayReloadVectorFile {
    schema_version: u32,
    bridge_replay_reload_cases: Vec<LeanBridgeReplayReloadCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeReplayReloadCase {
    name: String,
    replay_keys_well_formed: bool,
    replay_markers_valid: bool,
    canonical_replay_keys_unique: bool,
    no_missing_loaded_replay_keys: bool,
    no_extra_loaded_replay_keys: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeWitnessExportAdmissionVectorFile {
    schema_version: u32,
    bridge_witness_export_admission_cases: Vec<LeanBridgeWitnessExportAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeWitnessExportAdmissionCase {
    name: String,
    block_hash_parameter_valid: bool,
    explicit_block_hash: bool,
    block_known: bool,
    canonical_height_present: bool,
    block_is_canonical: bool,
    block_actions_decoded: bool,
    message_index_in_bounds: bool,
    parent_known: bool,
    best_height: u64,
    message_height: u64,
    max_explicit_history: u64,
    max_materialized_history: u64,
    expected_valid: bool,
    expected_confirmations_checked: Option<u32>,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanInboundBridgeReceiptAdmissionVectorFile {
    schema_version: u32,
    inbound_bridge_receipt_admission_cases: Vec<LeanInboundBridgeReceiptAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanInboundBridgeReceiptAdmissionCase {
    name: String,
    source_chain_matches: bool,
    rules_hash_matches: bool,
    message_nonce_matches: bool,
    message_hash_matches: bool,
    checkpoint_height: u64,
    canonical_tip_height: u64,
    canonical_tip_work: String,
    confirmations_checked: u32,
    min_confirmations: u32,
    min_work_checked: String,
    min_tip_work: String,
    expected_valid: bool,
    expected_height_confirmations: Option<u32>,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeWitnessBackscanVectorFile {
    schema_version: u32,
    bridge_witness_backscan_cases: Vec<LeanBridgeWitnessBackscanCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeWitnessBackscanCase {
    name: String,
    entries: Vec<LeanBridgeWitnessBackscanEntry>,
    expected_valid: bool,
    expected_selected_height: Option<u64>,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeWitnessBackscanEntry {
    height: u64,
    canonical_hash_present: bool,
    block_known: bool,
    block_actions_decoded: bool,
    message_index_in_bounds: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionReloadVectorFile {
    schema_version: u32,
    pending_action_reload_cases: Vec<LeanPendingActionReloadCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionReloadCase {
    name: String,
    key_well_formed: bool,
    embedded_hash_matches_key: bool,
    recomputed_hash_matches_embedded: bool,
    action_hash_unique: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStagedCiphertextReloadVectorFile {
    schema_version: u32,
    staged_ciphertext_reload_cases: Vec<LeanStagedCiphertextReloadCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStagedCiphertextReloadCase {
    name: String,
    key_well_formed: bool,
    ciphertext_within_limit: bool,
    ciphertext_hash_matches_key: bool,
    capacity_available: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStagedProofReloadVectorFile {
    schema_version: u32,
    staged_proof_reload_cases: Vec<LeanStagedProofReloadCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStagedProofReloadCase {
    name: String,
    key_well_formed: bool,
    proof_nonempty: bool,
    proof_within_limit: bool,
    capacity_available: bool,
    byte_capacity_available: bool,
    proof_binding_hash_matches_key: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMinedWorkAdmissionVectorFile {
    schema_version: u32,
    mined_work_admission_cases: Vec<LeanMinedWorkAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanNativeMinerIdentityVectorFile {
    schema_version: u32,
    native_miner_identity_cases: Vec<LeanNativeMinerIdentityCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanNativeMinerIdentityCase {
    name: String,
    height: u64,
    public_key_len: usize,
    signature_len: usize,
    public_key_bytes_parse: bool,
    miner_commitment_matches: bool,
    signature_bytes_parse: bool,
    signature_verifies: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMinedWorkAdmissionCase {
    name: String,
    best_height: u64,
    work_height: u64,
    parent_hash_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMinedBlockCommitPublicationVectorFile {
    schema_version: u32,
    mined_block_commit_publication_cases: Vec<LeanMinedBlockCommitPublicationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMinedBlockCommitPublicationCase {
    name: String,
    best_height: u64,
    work_height: u64,
    parent_hash_matches: bool,
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
    supply_digest_matches: bool,
    commit_kind: String,
    action_count: usize,
    planned_action_count: usize,
    chain_block_count: usize,
    height_entry_count: usize,
    pending_entry_count: usize,
    source_commitment_count: usize,
    source_nullifier_count: usize,
    source_bridge_replay_count: usize,
    source_ciphertext_index_count: usize,
    source_ciphertext_archive_count: usize,
    source_staged_ciphertext_removal_count: usize,
    block_record_writes: usize,
    height_index_writes: usize,
    best_pointer_writes: usize,
    canonical_index_cleared: bool,
    pending_tree_cleared: bool,
    pending_action_removals: usize,
    pending_action_writes: usize,
    commitment_writes: usize,
    nullifier_writes: usize,
    bridge_replay_writes: usize,
    ciphertext_index_writes: usize,
    ciphertext_archive_writes: usize,
    staged_ciphertext_removals: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanWorkTemplateAdmissionVectorFile {
    schema_version: u32,
    work_template_admission_cases: Vec<LeanWorkTemplateAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanWorkTemplateAdmissionCase {
    name: String,
    best_height: u64,
    cumulative_work_advances: bool,
    expected_height: Option<u64>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRecursiveArtifactContextAdmissionVectorFile {
    schema_version: u32,
    recursive_artifact_context_admission_cases: Vec<LeanRecursiveArtifactContextAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRecursiveArtifactContextAdmissionCase {
    name: String,
    best_height: u64,
    expected_height: Option<u64>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCodecAdmissionVectorFile {
    schema_version: u32,
    sync_codec_cases: Vec<LeanSyncCodecCase>,
    exact_decode_cases: Vec<LeanExactDecodeCase>,
    block_action_decode_cases: Vec<LeanBlockActionDecodeCase>,
    native_metadata_decode_cases: Vec<LeanNativeMetadataDecodeCase>,
    native_metadata_bincode_budget_cases: Vec<LeanNativeMetadataBincodeBudgetCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionRequestProjectionAdmissionVectorFile {
    schema_version: u32,
    action_request_projection_admission_cases: Vec<LeanActionRequestProjectionAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionRequestRawJsonProjectionVectorFile {
    schema_version: u32,
    action_request_raw_json_projection_cases: Vec<LeanActionRequestRawJsonProjectionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionRequestProjectionAdmissionCase {
    name: String,
    fixture: String,
    json_decode_accepts: bool,
    kernel_envelope_fields_absent: bool,
    route_supported: bool,
    nullifier_scope_valid: bool,
    nullifier_count_within_limit: bool,
    nullifier_hex_valid: bool,
    public_args_encoded_within_limit: bool,
    public_args_base64_decodes: bool,
    public_args_decoded_within_limit: bool,
    route_payload_decodes_exactly: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionRequestRawJsonProjectionCase {
    name: String,
    raw_json_bytes: Vec<u8>,
    json_decode_accepts: bool,
    kernel_envelope_fields_absent: bool,
    route_supported: bool,
    nullifier_scope_valid: bool,
    nullifier_count_within_limit: bool,
    nullifier_hex_valid: bool,
    public_args_encoded_within_limit: bool,
    public_args_base64_decodes: bool,
    public_args_decoded_within_limit: bool,
    route_payload_decodes_exactly: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncCodecCase {
    name: String,
    fixture: String,
    bounded_wire_decode_accepts: bool,
    consumed_all_bytes: bool,
    legacy_bincode_payload: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanExactDecodeCase {
    name: String,
    codec: String,
    fixture: String,
    parser_accepts: bool,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionDecodeCase {
    name: String,
    fixture: String,
    declared_tx_count: usize,
    actual_action_payload_count: usize,
    every_action_decodes_exactly: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanNativeMetadataDecodeCase {
    name: String,
    fixture: String,
    current_parser_accepts: bool,
    current_consumed_all_bytes: bool,
    current_canonical_reencode_matches: bool,
    legacy_parser_accepts: bool,
    legacy_consumed_all_bytes: bool,
    legacy_canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_source: Option<String>,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanNativeMetadataBincodeBudgetCase {
    name: String,
    fixture: String,
    metadata_bytes: usize,
    max_metadata_bytes: usize,
    action_count: usize,
    max_action_count: usize,
    largest_action_payload_bytes: usize,
    max_action_payload_bytes: usize,
    action_payload_bytes_total: usize,
    max_action_payload_bytes_total: usize,
    miner_public_key_bytes: usize,
    max_miner_public_key_bytes: usize,
    miner_signature_bytes: usize,
    max_miner_signature_bytes: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionScaleWireVectorFile {
    schema_version: u32,
    pending_action_scale_wire_cases: Vec<LeanPendingActionScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    tx_hash_bytes: usize,
    binding_bytes: usize,
    family_id_bytes: usize,
    action_id_bytes: usize,
    anchor_bytes: usize,
    nullifier_count: usize,
    nullifier_element_bytes: usize,
    commitment_count: usize,
    commitment_element_bytes: usize,
    ciphertext_hash_count: usize,
    ciphertext_hash_element_bytes: usize,
    ciphertext_size_count: usize,
    ciphertext_size_element_bytes: usize,
    public_args_bytes: usize,
    public_args_compact_prefix_bytes: usize,
    compact_prefixes_canonical: bool,
    fee_bytes: usize,
    candidate_option_tag_bytes: usize,
    candidate_artifact_none: bool,
    candidate_artifact_payload_bytes: usize,
    candidate_artifact_version_bytes: usize,
    candidate_artifact_tx_count_bytes: usize,
    candidate_artifact_tx_statements_commitment_bytes: usize,
    candidate_artifact_da_root_bytes: usize,
    candidate_artifact_da_chunk_count_bytes: usize,
    candidate_artifact_commitment_proof_bytes: usize,
    candidate_artifact_proof_mode_bytes: usize,
    candidate_artifact_proof_kind_bytes: usize,
    candidate_artifact_verifier_profile_bytes: usize,
    candidate_artifact_receipt_root_option_tag_bytes: usize,
    candidate_artifact_receipt_root_none: bool,
    candidate_artifact_receipt_root_proof_bytes: usize,
    candidate_artifact_receipt_root_proof_compact_prefix_bytes: usize,
    candidate_artifact_receipt_root_relation_id_bytes: usize,
    candidate_artifact_receipt_root_shape_digest_bytes: usize,
    candidate_artifact_receipt_root_leaf_count_bytes: usize,
    candidate_artifact_receipt_root_fold_count_bytes: usize,
    candidate_artifact_receipt_root_receipt_count: usize,
    candidate_artifact_receipt_root_receipt_compact_prefix_bytes: usize,
    candidate_artifact_receipt_root_receipt_element_bytes: usize,
    candidate_artifact_recursive_block_option_tag_bytes: usize,
    candidate_artifact_recursive_block_present: bool,
    candidate_artifact_recursive_proof_bytes: usize,
    received_ms_bytes: usize,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactScaleWireVectorFile {
    schema_version: u32,
    candidate_artifact_scale_wire_cases: Vec<LeanCandidateArtifactScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    version_bytes: usize,
    tx_count_bytes: usize,
    tx_statements_commitment_bytes: usize,
    da_root_bytes: usize,
    da_chunk_count_bytes: usize,
    commitment_proof_compact_prefix_bytes: usize,
    commitment_proof_bytes: usize,
    proof_mode_bytes: usize,
    proof_mode_tag_valid: bool,
    proof_kind_bytes: usize,
    proof_kind_tag_valid: bool,
    verifier_profile_bytes: usize,
    receipt_root_option_tag_bytes: usize,
    receipt_root_option_tag_valid: bool,
    receipt_root_none: bool,
    receipt_root_proof_compact_prefix_bytes: usize,
    receipt_root_proof_bytes: usize,
    receipt_root_relation_id_bytes: usize,
    receipt_root_shape_digest_bytes: usize,
    receipt_root_leaf_count_bytes: usize,
    receipt_root_fold_count_bytes: usize,
    receipt_root_receipt_compact_prefix_bytes: usize,
    receipt_root_receipt_count: usize,
    receipt_root_receipt_element_bytes: usize,
    recursive_block_option_tag_bytes: usize,
    recursive_block_option_tag_valid: bool,
    recursive_block_present: bool,
    recursive_proof_compact_prefix_bytes: usize,
    recursive_proof_bytes: usize,
    compact_prefixes_canonical: bool,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStorageDurabilityAdmissionVectorFile {
    schema_version: u32,
    storage_durability_admission_cases: Vec<LeanStorageDurabilityAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStorageDurabilityAdmissionCase {
    name: String,
    operation: String,
    operation_supported: bool,
    transaction_accepted: bool,
    durability_flushed: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanAtomicCommitManifestAdmissionVectorFile {
    schema_version: u32,
    atomic_commit_manifest_admission_cases: Vec<LeanAtomicCommitManifestAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanAtomicCommitManifestAdmissionCase {
    name: String,
    kind: String,
    action_count: usize,
    planned_action_count: usize,
    chain_block_count: usize,
    height_entry_count: usize,
    pending_entry_count: usize,
    source_commitment_count: usize,
    source_nullifier_count: usize,
    source_bridge_replay_count: usize,
    source_ciphertext_index_count: usize,
    source_ciphertext_archive_count: usize,
    source_staged_ciphertext_removal_count: usize,
    block_record_writes: usize,
    height_index_writes: usize,
    best_pointer_writes: usize,
    canonical_index_cleared: bool,
    pending_tree_cleared: bool,
    pending_action_removals: usize,
    pending_action_writes: usize,
    commitment_writes: usize,
    nullifier_writes: usize,
    bridge_replay_writes: usize,
    ciphertext_index_writes: usize,
    ciphertext_archive_writes: usize,
    staged_ciphertext_removals: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionScopeAdmissionVectorFile {
    schema_version: u32,
    action_scope_admission_cases: Vec<LeanActionScopeAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionScopeAdmissionCase {
    name: String,
    candidate_artifact_payload_scoped: bool,
    bridge_route: bool,
    bridge_scope_valid: bool,
    candidate_artifact_route: bool,
    candidate_scope_valid: bool,
    candidate_payload_present: bool,
    coinbase_route: bool,
    coinbase_scope_valid: bool,
    transfer_route: bool,
    transfer_scope_valid: bool,
    expected_valid: bool,
    expected_route: Option<String>,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeActionPayloadAdmissionVectorFile {
    schema_version: u32,
    bridge_action_payload_admission_cases: Vec<LeanBridgeActionPayloadAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeActionPayloadAdmissionCase {
    name: String,
    bridge_route: bool,
    state_deltas_absent: bool,
    action_kind: String,
    outbound_payload_nonempty: bool,
    inbound_proof_receipt_nonempty: bool,
    inbound_replay_key_matches: bool,
    inbound_destination_matches: bool,
    inbound_payload_hash_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeActionResourceAdmissionVectorFile {
    schema_version: u32,
    bridge_action_resource_admission_cases: Vec<LeanBridgeActionResourceAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeActionResourceAdmissionCase {
    name: String,
    action_kind: String,
    public_args_bytes: usize,
    outbound_payload_bytes: usize,
    inbound_proof_receipt_bytes: usize,
    inbound_message_payload_bytes: usize,
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    expected_raw_bytes: usize,
    expected_decoded_bytes: usize,
    expected_item_count: usize,
    expected_max_item_bytes: usize,
    expected_aggregate_bytes: usize,
    expected_work_units: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeMintReplayPolicyVectorFile {
    schema_version: u32,
    bridge_mint_replay_cases: Vec<LeanBridgeMintReplayPolicyCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeMintReplayPolicyCase {
    name: String,
    inbound_bridge_mint: bool,
    state_deltas_absent: bool,
    receipt_envelope_present: bool,
    receipt_verified: bool,
    receipt_payload_matches: bool,
    initial_consumed: Vec<String>,
    initial_pending: Vec<String>,
    replay_key: String,
    mint_authorized: bool,
    amount_matches_receipt: bool,
    amount_within_bound: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
    expected_next_consumed: Option<Vec<String>>,
    expected_next_pending: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeMintPayloadAdmissionVectorFile {
    schema_version: u32,
    bridge_mint_payload_admission_cases: Vec<LeanBridgeMintPayloadAdmissionCase>,
    cashvm_mint_binding_cases: Vec<LeanCashVmMintBindingCase>,
    cashvm_proof_admission_cases: Vec<LeanCashVmProofAdmissionCase>,
    cashvm_replay_update_cases: Vec<LeanCashVmReplayUpdateCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeMintPayloadAdmissionCase {
    name: String,
    payload_decoded: bool,
    payload_hash_matches: bool,
    receipt_message_hash_matches: bool,
    version_matches: bool,
    source_app_family_matches: bool,
    destination_matches: bool,
    mint_nonce_matches: bool,
    recipient_commitment_nonzero: bool,
    amount_nonzero: bool,
    amount_within_bound: bool,
    asset_non_native: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCashVmMintBindingCase {
    name: String,
    version_matches: bool,
    source_app_family_matches: bool,
    destination_matches: bool,
    mint_nonce_matches: bool,
    recipient_commitment_nonzero: bool,
    amount_nonzero: bool,
    amount_within_bound: bool,
    asset_non_native: bool,
    destination_matches_bridge_policy: bool,
    bridge_instance_matches_token_category: bool,
    token_category_matches_payload_asset: bool,
    recipient_hash_matches_payload_recipient: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCashVmProofAdmissionCase {
    name: String,
    proof_nonempty: bool,
    statement_digest_matches: bool,
    verifier_script_matches: bool,
    pq_soundness_at_least_policy: bool,
    verifier_available: bool,
    verifier_accepts: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCashVmReplayUpdateCase {
    name: String,
    witness_depth_valid: bool,
    previous_root_matches: bool,
    replay_leaf_absent: bool,
    next_root_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeMintPayloadRawAdmissionVectorFile {
    schema_version: u32,
    bridge_mint_payload_raw_admission_cases: Vec<LeanBridgeMintPayloadRawAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeMintPayloadRawAdmissionCase {
    name: String,
    fixture: String,
    raw_hex: String,
    parser_accepts: bool,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    payload_hash_matches: bool,
    receipt_message_hash_matches: bool,
    version_matches: bool,
    source_app_family_matches: bool,
    destination_matches: bool,
    mint_nonce_matches: bool,
    recipient_commitment_nonzero: bool,
    amount_nonzero: bool,
    amount_within_bound: bool,
    asset_non_native: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeVerifierRegistrationPolicyVectorFile {
    schema_version: u32,
    bridge_verifier_registration_policy_cases: Vec<LeanBridgeVerifierRegistrationPolicyCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeVerifierRegistrationPolicyCase {
    name: String,
    bridge_verifier_registration: bool,
    state_deltas_absent: bool,
    registration_decoded: bool,
    descriptor_matches_release: bool,
    activation_height_reached: bool,
    pq_clean_verifier_bound: bool,
    external_verifier_soundness_accepted: bool,
    positive_minting_enabled: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
    expected_effect: Option<LeanBridgeVerifierRegistrationPolicyEffect>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeVerifierRegistrationPolicyEffect {
    registration_observed: bool,
    production_mint_verifier_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRisc0ReleaseVerifierVectorFile {
    schema_version: u32,
    risc0_release_verifier_cases: Vec<LeanRisc0ReleaseVerifierCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRisc0ReleaseVerifierCase {
    name: String,
    image_id_matches: bool,
    journal_decodes: bool,
    verifier_enabled: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanTransferActionPayloadAdmissionVectorFile {
    schema_version: u32,
    transfer_action_payload_admission_cases: Vec<LeanTransferActionPayloadAdmissionCase>,
    inline_transfer_ciphertext_resource_cases: Vec<LeanInlineTransferCiphertextResourceCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanTransferActionPayloadAdmissionCase {
    name: String,
    proof_bytes: usize,
    max_proof_bytes: usize,
    anchor_matches: bool,
    commitments_match: bool,
    inline_ciphertext_bytes: usize,
    max_ciphertext_bytes: usize,
    ciphertext_hashes_match: bool,
    ciphertext_sizes_match: bool,
    binding_hash_matches: bool,
    #[serde(default = "default_true")]
    proof_binding_hash_matches_key: bool,
    fee_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanInlineTransferCiphertextResourceCase {
    name: String,
    route_payload_bytes: usize,
    proof_bytes: usize,
    ciphertext_count: usize,
    max_ciphertext_bytes_observed: usize,
    aggregate_ciphertext_bytes: usize,
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanTransferStateAdmissionVectorFile {
    schema_version: u32,
    transfer_state_admission_cases: Vec<LeanTransferStateAdmissionCase>,
    transfer_nullifier_row_cases: Vec<LeanTransferNullifierRowCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanTransferStateAdmissionCase {
    name: String,
    anchor_known: bool,
    nullifier_state: String,
    commitments_nonzero: bool,
    stablecoin_policy_authorized: bool,
    sidecar_route: bool,
    sidecar_ciphertexts_available: bool,
    sidecar_ciphertext_sizes_present: bool,
    sidecar_ciphertext_sizes_match: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanTransferNullifierRowCase {
    name: String,
    spent_nullifiers: Vec<String>,
    pending_nullifiers: Vec<String>,
    action_nullifiers: Vec<String>,
    expected_mempool_nullifier_state: String,
    expected_block_nullifier_state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStablecoinPolicyAuthorizationVectorFile {
    schema_version: u32,
    stablecoin_policy_authorization_cases: Vec<LeanStablecoinPolicyAuthorizationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStablecoinPolicyAuthorizationCase {
    name: String,
    stablecoin_present: bool,
    policy_known: bool,
    policy_active: bool,
    policy_lifecycle_open: bool,
    asset_matches: bool,
    policy_hash_matches: bool,
    policy_version_matches: bool,
    oracle_commitment_matches: bool,
    attestation_commitment_matches: bool,
    attestation_not_disputed: bool,
    oracle_fresh: bool,
    issuance_nonzero: bool,
    issuance_within_limit: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionStateEffectVectorFile {
    schema_version: u32,
    action_state_effect_cases: Vec<LeanActionStateEffectCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionStateEffectCase {
    name: String,
    leaf_start: u64,
    commitment_count: usize,
    ciphertext_count: usize,
    nullifier_count: usize,
    nullifier_state: String,
    bridge_replay_state: String,
    expected_next_leaf_count: Option<u64>,
    expected_imported_nullifier_count: Option<usize>,
    expected_imported_bridge_replay: Option<bool>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionStreamEffectVectorFile {
    schema_version: u32,
    action_stream_effect_cases: Vec<LeanActionStreamEffectCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionStreamEffectCase {
    name: String,
    leaf_start: u64,
    spent_nullifiers: Vec<u64>,
    consumed_bridge_replays: Vec<u64>,
    actions: Vec<LeanActionStreamActionCase>,
    expected_next_leaf_count: Option<u64>,
    expected_imported_nullifier_count: Option<usize>,
    expected_imported_bridge_replay_count: Option<usize>,
    expected_planned_starts: Option<Vec<u64>>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionStreamActionCase {
    commitment_count: usize,
    ciphertext_count: usize,
    nullifiers: Vec<u64>,
    bridge_replay_key: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionPlanApplicationAdmissionVectorFile {
    schema_version: u32,
    action_plan_application_admission_cases: Vec<LeanActionPlanApplicationAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionPlanApplicationAdmissionCase {
    name: String,
    leaf_start: u64,
    action_commitment_counts: Vec<usize>,
    planned_starts: Vec<u64>,
    expected_next_leaf_count: Option<u64>,
    expected_applied_action_count: Option<usize>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionWireReplayProjectionAdmissionVectorFile {
    schema_version: u32,
    action_wire_replay_projection_admission_cases: Vec<LeanActionWireReplayProjectionAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionWireReplayProjectionAdmissionCase {
    name: String,
    action_count: usize,
    planned_count: usize,
    actions: Vec<LeanActionWireReplayProjectionActionCase>,
    expected_projected_action_count: Option<usize>,
    expected_projected_ciphertext_row_count: Option<usize>,
    expected_projected_bridge_replay_row_count: Option<usize>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanActionWireReplayProjectionActionCase {
    ciphertext_hash_count: usize,
    ciphertext_size_count: usize,
    planned_ciphertext_count: usize,
    ciphertext_hashes_match: bool,
    ciphertext_sizes_match: bool,
    planned_replay_present: bool,
    replay_key_matches: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionFieldProjectionVectorFile {
    schema_version: u32,
    pending_action_field_projection_cases: Vec<LeanPendingActionFieldProjectionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionFieldProjectionCase {
    name: String,
    actions: Vec<LeanPendingActionProjectionActionSpec>,
    expected_commitment_rows: Vec<LeanPendingActionProjectionRowRef>,
    expected_nullifier_rows: Vec<LeanPendingActionProjectionRowRef>,
    expected_bridge_replay_rows: Vec<usize>,
    expected_ciphertext_index_rows: Vec<LeanPendingActionProjectionRowRef>,
    expected_ciphertext_archive_rows: Vec<LeanPendingActionProjectionRowRef>,
    expected_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionProjectionActionSpec {
    fixture_name: String,
    commitment_count: usize,
    nullifier_count: usize,
    ciphertext_count: usize,
    has_bridge_replay: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingActionProjectionRowRef {
    action_index: usize,
    offset: usize,
    commitment_index: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionValidationVectorFile {
    schema_version: u32,
    block_action_validation_cases: Vec<LeanBlockActionValidationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionValidationCase {
    name: String,
    action_count_matches: bool,
    action_hashes_match: bool,
    action_hashes_unique: bool,
    consumed_bridge_replays: Vec<u64>,
    actions: Vec<LeanBlockActionValidationActionCase>,
    expected_valid: bool,
    expected_rejection: Option<String>,
    expected_validated_action_count: Option<usize>,
    expected_imported_bridge_replay_count: Option<usize>,
    expected_last_transfer_key: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionValidationActionCase {
    scope: LeanBlockActionValidationScopeCase,
    payload_valid: bool,
    transfer_key: u64,
    transfer_state: LeanBlockActionValidationTransferStateCase,
    bridge_replay_key: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionValidationScopeCase {
    candidate_artifact_payload_scoped: bool,
    bridge_route: bool,
    bridge_scope_valid: bool,
    candidate_artifact_route: bool,
    candidate_scope_valid: bool,
    candidate_payload_present: bool,
    coinbase_route: bool,
    coinbase_scope_valid: bool,
    transfer_route: bool,
    transfer_scope_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionValidationTransferStateCase {
    anchor_known: bool,
    nullifier_state: String,
    commitments_nonzero: bool,
    stablecoin_policy_authorized: bool,
    sidecar_route: bool,
    sidecar_ciphertexts_available: bool,
    sidecar_ciphertext_sizes_present: bool,
    sidecar_ciphertext_sizes_match: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactAdmissionVectorFile {
    schema_version: u32,
    candidate_artifact_admission_cases: Vec<LeanCandidateArtifactAdmissionCase>,
    candidate_artifact_resource_projection_cases: Vec<LeanCandidateArtifactResourceProjectionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactAdmissionCase {
    name: String,
    state_deltas_absent: bool,
    route_payload_decodes_exactly: bool,
    route_payload_matches_artifact: bool,
    artifact_present: bool,
    schema_matches: bool,
    tx_count: u32,
    max_tx_count: u32,
    da_chunk_count: u32,
    proof_mode_recursive_block: bool,
    proof_kind_recursive_block_v2: bool,
    verifier_profile_matches: bool,
    commitment_proof_empty: bool,
    receipt_root_absent: bool,
    recursive_payload_present: bool,
    recursive_proof_bytes: usize,
    max_recursive_proof_bytes: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactResourceProjectionCase {
    name: String,
    declared_bytes: usize,
    proof_bytes: usize,
    receipt_bytes: usize,
    recursive_bytes: usize,
    tx_count: usize,
    da_chunk_count: usize,
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    expected_raw_bytes: usize,
    expected_decoded_bytes: usize,
    expected_item_count: usize,
    expected_max_item_bytes: usize,
    expected_aggregate_bytes: usize,
    expected_work_units: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactCouplingAdmissionVectorFile {
    schema_version: u32,
    candidate_artifact_coupling_admission_cases: Vec<LeanCandidateArtifactCouplingAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactCouplingAdmissionCase {
    name: String,
    transfer_count: usize,
    candidate_artifact_count: usize,
    candidate_tx_count_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMineableActionAdmissionVectorFile {
    schema_version: u32,
    mineable_action_admission_cases: Vec<LeanMineableActionAdmissionCase>,
    #[serde(default)]
    mineable_selection_cases: Vec<LeanMineableSelectionCase>,
    #[serde(default)]
    pending_candidate_prune_cases: Vec<LeanPendingCandidatePruneCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMineableActionAdmissionCase {
    name: String,
    candidate_artifact_route: bool,
    candidate_artifact_selected: bool,
    sidecar_transfer_route: bool,
    sidecar_ciphertexts_available: bool,
    sidecar_ciphertext_sizes_present: bool,
    sidecar_ciphertext_sizes_match: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMineableSelectionCase {
    name: String,
    transfer_count: usize,
    selected_candidate_action_id: Option<usize>,
    actions: Vec<LeanMineableSelectionAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMineableSelectionAction {
    label: String,
    fixture: String,
    action_id: usize,
    transfer_route: bool,
    transfer_mineable: bool,
    candidate_artifact_route: bool,
    candidate_tx_count: usize,
    expected_selected: bool,
    expected_accepted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingCandidatePruneCase {
    name: String,
    transfer_pending: bool,
    actions: Vec<LeanPendingCandidatePruneAction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPendingCandidatePruneAction {
    label: String,
    fixture: String,
    action_id: usize,
    transfer_route: bool,
    candidate_artifact_route: bool,
    expected_survives_after_transfer_prune: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockArtifactBindingAdmissionVectorFile {
    schema_version: u32,
    tx_leaf_action_binding_cases: Vec<LeanTxLeafActionBindingAdmissionCase>,
    candidate_artifact_binding_cases: Vec<LeanCandidateArtifactBindingAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanTxLeafActionBindingAdmissionCase {
    name: String,
    nullifiers_match: bool,
    commitments_match: bool,
    ciphertext_hashes_match: bool,
    input_count_matches: bool,
    output_count_matches: bool,
    version_matches: bool,
    fee_matches: bool,
    #[serde(default = "default_true")]
    stablecoin_payload_matches: bool,
    balance_tag_matches: bool,
    receipt_statement_hash_matches: bool,
    public_inputs_digest_matches: bool,
    proof_digest_matches: bool,
    proof_backend_matches: bool,
    ciphertext_payload_hashes_match: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCandidateArtifactBindingAdmissionCase {
    name: String,
    da_root_matches: bool,
    da_chunk_count_matches: bool,
    tx_statements_commitment_matches: bool,
    recursive_state_root_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockCommitmentAdmissionVectorFile {
    schema_version: u32,
    block_commitment_admission_cases: Vec<LeanBlockCommitmentAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockReplayRefinementVectorFile {
    schema_version: u32,
    block_replay_refinement_cases: Vec<LeanBlockReplayRefinementCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionReplayPublicationVectorFile {
    schema_version: u32,
    block_action_replay_publication_cases: Vec<LeanBlockActionReplayPublicationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockActionReplayPublicationCase {
    name: String,
    validation_action_count_matches: bool,
    validation_action_hashes_match: bool,
    validation_action_hashes_unique: bool,
    validation_consumed_bridge_replays: Vec<u64>,
    validation_actions: Vec<LeanBlockActionValidationActionCase>,
    replay_leaf_start: u64,
    replay_spent_nullifiers: Vec<u64>,
    replay_consumed_bridge_replays: Vec<u64>,
    replay_actions: Vec<LeanActionStreamActionCase>,
    replay_parent_supply: String,
    replay_height: u64,
    replay_fee_total: u64,
    replay_has_coinbase: bool,
    replay_claimed_supply: String,
    replay_tx_count_matches: bool,
    replay_state_root_matches: bool,
    replay_kernel_root_matches: bool,
    replay_nullifier_root_matches: bool,
    replay_extrinsics_root_matches: bool,
    replay_message_root_matches: bool,
    replay_message_count_matches: bool,
    replay_header_mmr_root_matches: bool,
    replay_header_mmr_len_matches: bool,
    wire_action_count: usize,
    wire_planned_count: usize,
    wire_actions: Vec<LeanActionWireReplayProjectionActionCase>,
    expected_valid: bool,
    expected_rejection: Option<String>,
    expected_validated_action_count: Option<usize>,
    expected_replay_action_count: Option<usize>,
    expected_wire_projected_action_count: Option<usize>,
    expected_imported_bridge_replay_count: Option<usize>,
    expected_wire_projected_bridge_replay_count: Option<usize>,
    expected_replay_next_leaf_count: Option<String>,
    expected_replay_supply: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockReplayRefinementCase {
    name: String,
    leaf_start: u64,
    spent_nullifiers: Vec<u64>,
    consumed_bridge_replays: Vec<u64>,
    actions: Vec<LeanActionStreamActionCase>,
    parent_supply: String,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
    claimed_supply: String,
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
    expected_next_leaf_count: Option<String>,
    expected_imported_nullifier_count: Option<String>,
    expected_imported_bridge_replay_count: Option<String>,
    expected_planned_starts: Option<Vec<u64>>,
    expected_supply: Option<String>,
    expected_valid: bool,
    expected_rejection: Option<String>,
    expected_trace: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockCommitmentAdmissionCase {
    name: String,
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
    supply_digest_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCoinbaseAccountingAdmissionVectorFile {
    schema_version: u32,
    coinbase_accounting_admission_cases: Vec<LeanCoinbaseAccountingAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCoinbaseAccountingAdmissionCase {
    name: String,
    coinbase_count: usize,
    height: u64,
    transfer_fee_total: Option<String>,
    observed_coinbase_amount: Option<String>,
    expected_coinbase_amount: Option<String>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCoinbaseActionPayloadAdmissionVectorFile {
    schema_version: u32,
    coinbase_action_payload_admission_cases: Vec<LeanCoinbaseActionPayloadAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCoinbaseActionPayloadAdmissionCase {
    name: String,
    amount_nonzero: bool,
    commitment_matches: bool,
    commitment_nonzero: bool,
    ciphertext_bytes: usize,
    max_ciphertext_bytes: usize,
    ciphertext_hash_matches: bool,
    ciphertext_size_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCoinbaseActionPayloadScaleWireVectorFile {
    schema_version: u32,
    coinbase_action_payload_scale_wire_cases: Vec<LeanCoinbaseActionPayloadScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanCoinbaseActionPayloadScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    commitment_bytes: usize,
    note_ciphertext_bytes: usize,
    kem_ciphertext_compact_prefix_bytes: usize,
    kem_ciphertext_bytes: usize,
    kem_ciphertext_compact_prefix_canonical: bool,
    recipient_address_bytes: usize,
    amount_bytes: usize,
    public_seed_bytes: usize,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanOutboundBridgeActionPayloadScaleWireVectorFile {
    schema_version: u32,
    outbound_bridge_action_payload_scale_wire_cases:
        Vec<LeanOutboundBridgeActionPayloadScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanOutboundBridgeActionPayloadScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    destination_chain_id_bytes: usize,
    app_family_id_bytes: usize,
    payload_compact_prefix_bytes: usize,
    payload_bytes: usize,
    payload_compact_prefix_canonical: bool,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanInboundBridgeActionPayloadScaleWireVectorFile {
    schema_version: u32,
    inbound_bridge_action_payload_scale_wire_cases:
        Vec<LeanInboundBridgeActionPayloadScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanInboundBridgeActionPayloadScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    source_chain_id_bytes: usize,
    source_message_nonce_bytes: usize,
    verifier_program_hash_bytes: usize,
    proof_receipt_compact_prefix_bytes: usize,
    proof_receipt_bytes: usize,
    proof_receipt_compact_prefix_canonical: bool,
    message_source_chain_id_bytes: usize,
    message_destination_chain_id_bytes: usize,
    message_app_family_id_bytes: usize,
    message_nonce_bytes: usize,
    message_source_height_bytes: usize,
    message_payload_hash_bytes: usize,
    message_payload_compact_prefix_bytes: usize,
    message_payload_bytes: usize,
    message_payload_compact_prefix_canonical: bool,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeVerifierRegistrationScaleWireVectorFile {
    schema_version: u32,
    bridge_verifier_registration_scale_wire_cases: Vec<LeanBridgeVerifierRegistrationScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBridgeVerifierRegistrationScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    source_chain_id_bytes: usize,
    verifier_program_hash_bytes: usize,
    rules_hash_bytes: usize,
    enabled_at_height_bytes: usize,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanShieldedTransferInlineScaleWireVectorFile {
    schema_version: u32,
    shielded_transfer_inline_scale_wire_cases: Vec<LeanShieldedTransferInlineScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanShieldedTransferInlineScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    proof_compact_prefix_bytes: usize,
    proof_bytes: usize,
    proof_compact_prefix_canonical: bool,
    commitment_compact_prefix_bytes: usize,
    commitment_count: usize,
    commitment_element_bytes: usize,
    commitment_compact_prefix_canonical: bool,
    ciphertext_compact_prefix_bytes: usize,
    ciphertext_count: usize,
    encrypted_note_ciphertext_bytes: usize,
    kem_ciphertext_compact_prefix_bytes: usize,
    kem_ciphertext_bytes: usize,
    ciphertext_compact_prefix_canonical: bool,
    kem_ciphertext_compact_prefix_canonical: bool,
    anchor_bytes: usize,
    balance_slot_count: usize,
    balance_slot_bytes: usize,
    binding_hash_bytes: usize,
    stablecoin_option_tag_bytes: usize,
    stablecoin_some_payload_bytes: usize,
    fee_bytes: usize,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanShieldedTransferSidecarScaleWireVectorFile {
    schema_version: u32,
    shielded_transfer_sidecar_scale_wire_cases: Vec<LeanShieldedTransferSidecarScaleWireCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanShieldedTransferSidecarScaleWireCase {
    name: String,
    fixture: String,
    raw_hex: String,
    proof_compact_prefix_bytes: usize,
    proof_bytes: usize,
    proof_compact_prefix_canonical: bool,
    commitment_compact_prefix_bytes: usize,
    commitment_count: usize,
    commitment_element_bytes: usize,
    commitment_compact_prefix_canonical: bool,
    ciphertext_hash_compact_prefix_bytes: usize,
    ciphertext_hash_count: usize,
    ciphertext_hash_element_bytes: usize,
    ciphertext_hash_compact_prefix_canonical: bool,
    ciphertext_size_compact_prefix_bytes: usize,
    ciphertext_size_count: usize,
    ciphertext_size_element_bytes: usize,
    ciphertext_size_compact_prefix_canonical: bool,
    anchor_bytes: usize,
    balance_slot_count: usize,
    balance_slot_bytes: usize,
    binding_hash_bytes: usize,
    stablecoin_option_tag_bytes: usize,
    stablecoin_some_payload_bytes: usize,
    fee_bytes: usize,
    total_bytes: usize,
    consumed_all_bytes: bool,
    canonical_reencode_matches: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanResourceBudgetAdmissionVectorFile {
    schema_version: u32,
    mempool_budget_cases: Vec<LeanMempoolBudgetCase>,
    staged_proof_budget_cases: Vec<LeanStagedProofBudgetCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBoundedRequestAdmissionVectorFile {
    schema_version: u32,
    bounded_request_cases: Vec<LeanBoundedRequestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBoundedRequestCase {
    name: String,
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    raw_bytes: usize,
    decoded_bytes: usize,
    item_count: usize,
    max_item_bytes: usize,
    aggregate_bytes: usize,
    work_units: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMempoolBudgetCase {
    name: String,
    pending_bytes: usize,
    candidate_bytes: usize,
    max_bytes: usize,
    expected_total_bytes: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStagedProofBudgetCase {
    name: String,
    staged_bytes: usize,
    existing_bytes: usize,
    proof_bytes: usize,
    max_bytes: usize,
    expected_total_bytes: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanPreHeavyResourceBoundSurfaceVectorFile {
    schema_version: u32,
    staged_proof_upload_preheavy_cases: Vec<LeanStagedProofUploadPreHeavyCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanStagedProofUploadPreHeavyCase {
    name: String,
    binding_hash_present: bool,
    binding_hash_valid: bool,
    proof_present: bool,
    staged_bytes: usize,
    existing_bytes: usize,
    proof_bytes: usize,
    max_bytes: usize,
    expected_total_bytes: usize,
    decoded_proof_bytes: usize,
    decoded_max_proof_bytes: usize,
    proof_binding_hash_matches_key: bool,
    expected_valid: bool,
    expected_rejection_stage: Option<String>,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRpcAdmissionVectorFile {
    schema_version: u32,
    policy_cases: Vec<LeanRpcPolicyCase>,
    method_gate_cases: Vec<LeanRpcMethodGateCase>,
    method_list_cases: Vec<LeanRpcMethodListCase>,
    timestamp_range_cases: Vec<LeanRpcTimestampRangeCase>,
    byte_parse_cases: Vec<LeanRpcByteParseCase>,
    batch_cases: Vec<LeanRpcBatchCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRpcPolicyCase {
    name: String,
    raw: String,
    raw_tag: String,
    rpc_external: bool,
    expected_valid: bool,
    expected_policy: Option<String>,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRpcMethodGateCase {
    name: String,
    policy: String,
    method: String,
    is_unsafe_method: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRpcMethodListCase {
    name: String,
    policy: String,
    expected_unsafe_methods_visible: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRpcTimestampRangeCase {
    name: String,
    start_height: u64,
    end_height: u64,
    max_rows: u64,
    expected_requested_rows: Option<String>,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRpcByteParseCase {
    name: String,
    encoding: String,
    raw_text_bytes: usize,
    decoded_bytes: usize,
    max_decoded_bytes: usize,
    expected_encoded_len_limit: usize,
    expected_hex_len_limit: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanRpcBatchCase {
    name: String,
    request_count: usize,
    max_requests: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSidecarUploadAdmissionVectorFile {
    schema_version: u32,
    request_count_cases: Vec<LeanSidecarRequestCountCase>,
    capacity_cases: Vec<LeanSidecarCapacityCase>,
    proof_metadata_cases: Vec<LeanProofSidecarMetadataCase>,
    proof_decoded_cases: Vec<LeanProofSidecarDecodedCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSidecarUploadRawJsonProjectionVectorFile {
    schema_version: u32,
    sidecar_upload_raw_json_projection_cases: Vec<LeanSidecarUploadRawJsonProjectionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSidecarUploadRawJsonProjectionCase {
    name: String,
    kind: String,
    raw_json_bytes: Vec<u8>,
    json_decode_accepts: bool,
    upload_field_present: bool,
    item_count: usize,
    max_items: usize,
    ciphertext_item_present: bool,
    ciphertext_bytes_decode: bool,
    proof_item_present: bool,
    binding_hash_present: bool,
    binding_hash_valid: bool,
    proof_present: bool,
    proof_bytes_decode: bool,
    proof_bytes: usize,
    max_proof_bytes: usize,
    proof_binding_hash_matches_key: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSidecarRequestCountCase {
    name: String,
    kind: String,
    item_count: usize,
    max_items: usize,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSidecarCapacityCase {
    name: String,
    kind: String,
    staged_count: usize,
    max_staged_count: usize,
    replaces_existing: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanProofSidecarMetadataCase {
    name: String,
    binding_hash_present: bool,
    binding_hash_valid: bool,
    proof_present: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanProofSidecarDecodedCase {
    name: String,
    proof_bytes: usize,
    max_proof_bytes: usize,
    #[serde(default = "default_true")]
    proof_binding_hash_matches_key: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncAdmissionVectorFile {
    schema_version: u32,
    sync_response_range_cases: Vec<LeanSyncResponseRangeCase>,
    sync_missing_request_cases: Vec<LeanSyncMissingRequestCase>,
    sync_response_count_cases: Vec<LeanSyncResponseCountCase>,
    sync_request_rate_cases: Vec<LeanSyncRequestRateCase>,
    sync_request_rate_state_cases: Vec<LeanSyncRequestRateStateCase>,
    mining_sync_evidence_cases: Vec<LeanMiningSyncEvidenceCase>,
    mining_gate_cases: Vec<LeanMiningGateCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncRawIngressVectorFile {
    schema_version: u32,
    sync_raw_ingress_cases: Vec<LeanSyncRawIngressCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncResponseImportVectorFile {
    schema_version: u32,
    sync_response_import_cases: Vec<LeanSyncResponseImportCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncBlockRangePublicationAdmissionVectorFile {
    schema_version: u32,
    sync_block_range_publication_cases: Vec<LeanSyncBlockRangePublicationAdmissionCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncResponseRangeCase {
    name: String,
    from_height: u64,
    to_height: u64,
    best_height: u64,
    max_blocks: u64,
    expected_has_range: bool,
    expected_from_height: Option<u64>,
    expected_to_height: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncMissingRequestCase {
    name: String,
    best_height: u64,
    announced_height: u64,
    max_blocks: u64,
    expected_has_request: bool,
    expected_from_height: Option<u64>,
    expected_to_height: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncResponseCountCase {
    name: String,
    block_count: usize,
    max_blocks: usize,
    expected_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncRequestRateCase {
    name: String,
    requests_in_window: u32,
    max_requests: u32,
    window_elapsed_ms: u64,
    window_ms: u64,
    expected_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncRequestRateStateCase {
    name: String,
    current_entries: usize,
    max_entries: usize,
    expected_retained_before_insert: usize,
    expected_entries_after_insert: usize,
    expected_valid: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMiningSyncEvidenceCase {
    name: String,
    verified_new_progress: bool,
    verified_known_at_or_below_local_best: bool,
    local_best_height: u64,
    peer_best_height: u64,
    stopped_on_error: bool,
    expected_observed_height: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanMiningGateCase {
    name: String,
    has_seeds: bool,
    dev: bool,
    bootstrap_authoring: bool,
    observed_gate_open: bool,
    expected_allows_work: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncRawIngressCase {
    name: String,
    raw_bytes: Vec<u8>,
    expected_kind: String,
    from_height: u64,
    to_height: u64,
    request_best_height: u64,
    max_blocks: usize,
    response_best_height: u64,
    response_heights: Vec<u64>,
    outcomes: Vec<String>,
    local_best_height: u64,
    peer_best_height: u64,
    expected_has_range: bool,
    expected_from_height: Option<u64>,
    expected_to_height: Option<u64>,
    expected_sorted_heights: Vec<u64>,
    expected_attempted_blocks: usize,
    expected_imported_blocks: u64,
    expected_stopped_on_error: bool,
    expected_request_more: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncResponseImportCase {
    name: String,
    response_heights: Vec<u64>,
    max_blocks: usize,
    outcomes: Vec<String>,
    local_best_height: u64,
    peer_best_height: u64,
    expected_valid: bool,
    expected_rejection: Option<String>,
    expected_sorted_heights: Vec<u64>,
    expected_attempted_blocks: usize,
    expected_imported_blocks: u64,
    expected_stopped_on_error: bool,
    expected_request_more: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanSyncBlockRangePublicationAdmissionCase {
    name: String,
    range_admitted: bool,
    served_count_matches_range: bool,
    first_height_matches_range: bool,
    last_height_matches_range: bool,
    served_heights_contiguous: bool,
    previous_parent_anchor_verified: bool,
    parent_hashes_contiguous: bool,
    canonical_rows_verified: bool,
    action_bodies_verified: bool,
    expected_valid: bool,
    expected_rejection: Option<String>,
}

#[test]
fn native_genesis_is_stable() {
    let a = genesis_meta(NATIVE_DEV_POW_BITS).expect("genesis");
    let b = genesis_meta(NATIVE_DEV_POW_BITS).expect("genesis");
    assert_eq!(a.hash, b.hash);
    assert_eq!(a.height, 0);
}

fn mining_test_work(pow_bits: u32) -> NativeWork {
    NativeWork {
        height: 1,
        parent_hash: [0u8; 32],
        pre_hash: [0u8; 32],
        state_root: [0u8; 48],
        kernel_root: [0u8; 48],
        nullifier_root: [0u8; 48],
        extrinsics_root: [0u8; 32],
        message_root: [0u8; 48],
        message_count: 0,
        header_mmr_root: [0u8; 32],
        header_mmr_len: 1,
        cumulative_work: [0u8; 48],
        supply_digest: 0,
        tx_count: 0,
        timestamp_ms: 1,
        pow_bits,
        prepared_actions: None,
    }
}

#[test]
fn native_mining_rounds_count_all_attempted_hashes_without_sleep_gap() {
    let work = mining_test_work(0);
    let rounds = 3;
    let result = mine_native_rounds(work, 7, rounds);

    assert!(result.seal.is_none());
    assert_eq!(result.hashes, rounds * HASHES_PER_ROUND);
}

#[test]
fn native_mining_rounds_count_until_found_seal() {
    let work = mining_test_work(0x207f_ffff);
    let result = mine_native_rounds(work.clone(), 0, MINING_ROUNDS_PER_WORK);
    let seal = result.seal.expect("easy test target should find a seal");
    let counter = u64::from_le_bytes(
        seal.nonce[..8]
            .try_into()
            .expect("nonce counter prefix has 8 bytes"),
    );

    assert!(native_seal_meets_target(&seal.work_hash, work.pow_bits));
    assert_eq!(result.hashes, counter + 1);
    assert!(result.hashes <= MINING_ROUNDS_PER_WORK * HASHES_PER_ROUND);
}

#[test]
fn parse_block_hash_height_params() {
    assert_eq!(parse_height("15"), Some(15));
    assert_eq!(parse_height("0xf"), Some(15));
}

#[test]
fn submit_action_returns_exact_rejection_response() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = NativeConfig {
        dev: true,
        tmp: false,
        base_path: tmp.path().to_path_buf(),
        db_path: tmp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "test".to_string(),
        rpc_methods: "unsafe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits: 0x207f_ffff,
    };
    let node = NativeNode::open(config).expect("node");

    let response = node.submit_action(json!({}));
    let object = response.as_object().expect("rejection response object");
    assert_eq!(object.len(), 3);
    assert_eq!(object.get("success"), Some(&json!(false)));
    assert_eq!(object.get("tx_hash"), Some(&Value::Null));
    assert!(object.get("error").and_then(Value::as_str).is_some());
}

#[test]
fn submit_action_stages_and_imports_shielded_transfer() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = NativeConfig {
        dev: true,
        tmp: false,
        base_path: tmp.path().to_path_buf(),
        db_path: tmp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "test".to_string(),
        rpc_methods: "unsafe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits: test_pow_bits,
    };
    let node = NativeNode::open(config).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let nullifier = [1u8; 48];
    let commitment = [2u8; 48];
    let note = protocol_shielded_pool::types::EncryptedNote {
        ciphertext: [3u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
        kem_ciphertext: vec![4u8; 32],
    };
    let mut note_bytes = Vec::new();
    note_bytes.extend_from_slice(&note.ciphertext);
    note_bytes.extend_from_slice(&note.kem_ciphertext);
    let ciphertext_hash = ciphertext_hash_bytes(&note_bytes);
    let inputs = ShieldedTransferInputs {
        anchor,
        nullifiers: vec![nullifier],
        commitments: vec![commitment],
        ciphertext_hashes: vec![ciphertext_hash],
        balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
        fee: 7,
        value_balance: 0,
        stablecoin: None,
    };
    let binding_hash = StarkVerifier::compute_binding_hash(&inputs).data;
    let binding = KernelVersionBinding {
        circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
    };
    let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
    let proof = test_transfer_proof_artifact(
        anchor,
        &[nullifier],
        &[commitment],
        &[ciphertext_hash],
        balance_slot_asset_ids,
        7,
        None,
        binding,
    );
    let args = ShieldedTransferInlineArgs {
        proof,
        commitments: vec![commitment],
        ciphertexts: vec![note],
        anchor,
        balance_slot_asset_ids,
        binding_hash,
        stablecoin: None,
        fee: 7,
    };
    let request = json!({
        "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        "family_id": FAMILY_SHIELDED_POOL,
        "action_id": ACTION_SHIELDED_TRANSFER_INLINE,
        "new_nullifiers": [hex48(&nullifier)],
        "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
    });

    let action = node
        .validate_and_stage_action(request.clone())
        .expect("stage action");
    assert_eq!(node.state.read().pending_actions.len(), 1);
    assert!(node.validate_and_stage_action(request).is_err());

    let candidate = CandidateArtifact {
        version: BLOCK_PROOF_BUNDLE_SCHEMA,
        tx_count: 1,
        tx_statements_commitment: [5u8; 48],
        da_root: [6u8; 48],
        da_chunk_count: 1,
        commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
        proof_mode: BlockProofMode::RecursiveBlock,
        proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
        verifier_profile: consensus::proof::recursive_block_artifact_verifier_profile(),
        receipt_root: None,
        recursive_block: Some(protocol_shielded_pool::types::RecursiveBlockProofPayload {
            proof: protocol_shielded_pool::types::StarkProof {
                data: vec![8u8; 32],
            },
        }),
    };
    let candidate_args = SubmitCandidateArtifactArgs { payload: candidate };
    let err = node.validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": ACTION_SUBMIT_CANDIDATE_ARTIFACT,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(candidate_args.encode()),
        }))
        .expect_err("candidate artifacts must not be user-staged while transfers are pending");
    assert!(
        err.to_string()
            .contains("candidate artifact submissions are disabled"),
        "unexpected candidate staging error: {err}"
    );

    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(
        work.tx_count, 0,
        "synthetic transfer fixture must not be mined without a valid recursive candidate"
    );
    let seal = mine_native_round(work.clone(), 0).expect("test seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("empty fallback block should import")
        .expect("empty fallback block");
    assert_eq!(imported.tx_count, 0);
    assert_eq!(node.state.read().pending_actions.len(), 1);
    assert!(!node.state.read().nullifiers.contains(&action.nullifiers[0]));
    assert_eq!(node.state.read().commitment_tree.leaf_count(), 0);
}

#[test]
fn submit_transfer_evicts_stale_candidate_artifact_from_mempool() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let stale_candidate = test_candidate_artifact_action(1, 82);
    node.action_tree
        .insert(stale_candidate.tx_hash.as_slice(), stale_candidate.encode())
        .expect("persist stale candidate");
    node.action_tree.flush().expect("flush stale candidate");
    node.state
        .write()
        .pending_actions
        .insert(stale_candidate.tx_hash, stale_candidate.clone());

    let anchor = node.state.read().commitment_tree.root();
    let transfer = test_inline_transfer_action(anchor, [83u8; 48], [84u8; 48], 0);
    let staged = node
        .validate_and_stage_action(action_request_projection_request_from_action(&transfer))
        .expect("stage transfer");
    assert_eq!(staged.nullifiers, transfer.nullifiers);
    assert_eq!(staged.commitments, transfer.commitments);
    let staged_transfer_hash = staged.tx_hash;

    let state = node.state.read();
    assert!(state.pending_actions.contains_key(&staged_transfer_hash));
    assert!(!state.pending_actions.contains_key(&stale_candidate.tx_hash));
    assert_eq!(state.pending_actions.len(), 1);
    drop(state);
    assert!(node
        .action_tree
        .get(stale_candidate.tx_hash.as_slice())
        .expect("read stale candidate")
        .is_none());
    assert!(node
        .action_tree
        .get(staged_transfer_hash.as_slice())
        .expect("read staged transfer")
        .is_some());

    let fresh_candidate = test_candidate_artifact_action(1, 85);
    let err = node
        .validate_and_stage_action(action_request_projection_request_from_action(
            &fresh_candidate,
        ))
        .expect_err("candidate artifact submissions must stay disabled while transfer pending");
    assert!(
        err.to_string()
            .contains("candidate artifact submissions are disabled"),
        "unexpected candidate staging error: {err}"
    );
}

#[test]
fn relayed_pending_action_stages_persists_and_deduplicates_inline_transfer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [86u8; 48], [87u8; 48], 3);
    let staged = node
        .stage_relayed_pending_action(action.clone())
        .expect("stage relayed action")
        .expect("new relayed action");
    assert_eq!(staged.tx_hash, action.tx_hash);

    let state = node.state.read();
    assert!(state.pending_actions.contains_key(&action.tx_hash));
    assert_eq!(state.pending_actions.len(), 1);
    drop(state);
    assert!(node
        .action_tree
        .get(action.tx_hash.as_slice())
        .expect("read relayed action")
        .is_some());

    assert!(node
        .stage_relayed_pending_action(action.clone())
        .expect("duplicate hash relay should be ignored")
        .is_none());

    let mut semantic_duplicate = action.clone();
    semantic_duplicate.received_ms = semantic_duplicate.received_ms.saturating_add(1);
    semantic_duplicate.tx_hash = pending_action_hash(&semantic_duplicate);
    assert!(node
        .stage_relayed_pending_action(semantic_duplicate)
        .expect("semantic duplicate relay should be ignored")
        .is_none());
    assert_eq!(node.state.read().pending_actions.len(), 1);
}

#[test]
fn relayed_transfer_evicts_stale_candidate_artifact_from_mempool() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let stale_candidate = test_candidate_artifact_action(1, 88);
    node.action_tree
        .insert(stale_candidate.tx_hash.as_slice(), stale_candidate.encode())
        .expect("persist stale candidate");
    node.action_tree.flush().expect("flush stale candidate");
    node.state
        .write()
        .pending_actions
        .insert(stale_candidate.tx_hash, stale_candidate.clone());

    let anchor = node.state.read().commitment_tree.root();
    let transfer = test_inline_transfer_action(anchor, [89u8; 48], [90u8; 48], 0);
    node.stage_relayed_pending_action(transfer.clone())
        .expect("stage relayed transfer")
        .expect("new relayed transfer");

    let state = node.state.read();
    assert!(state.pending_actions.contains_key(&transfer.tx_hash));
    assert!(!state.pending_actions.contains_key(&stale_candidate.tx_hash));
    assert_eq!(state.pending_actions.len(), 1);
    drop(state);
    assert!(node
        .action_tree
        .get(stale_candidate.tx_hash.as_slice())
        .expect("read stale candidate")
        .is_none());
}

#[test]
fn relayed_pending_action_rejects_miner_local_artifacts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");

    let candidate = test_candidate_artifact_action(1, 91);
    let err = node
        .stage_relayed_pending_action(candidate)
        .expect_err("candidate artifacts must not be peer-relayed");
    assert!(
        err.to_string().contains("not peer-relayable"),
        "unexpected candidate relay error: {err}"
    );

    let coinbase = test_coinbase_action(42);
    let err = node
        .stage_relayed_pending_action(coinbase)
        .expect_err("coinbase actions must not be peer-relayed");
    assert!(
        err.to_string().contains("not peer-relayable"),
        "unexpected coinbase relay error: {err}"
    );
}

#[test]
fn relayed_pending_action_rejects_hash_binding_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [92u8; 48], [93u8; 48], 0);
    action.received_ms = action.received_ms.saturating_add(1);
    let err = node
        .stage_relayed_pending_action(action)
        .expect_err("relay must reject stale embedded tx hash");
    assert!(
        err.to_string().contains("hash binding mismatch"),
        "unexpected hash binding error: {err}"
    );
}

#[test]
fn peer_relayable_pending_action_rebroadcast_batch_excludes_miner_local_artifacts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let transfer_a = test_inline_transfer_action(anchor, [94u8; 48], [95u8; 48], 0);
    let transfer_b = test_inline_transfer_action(anchor, [96u8; 48], [97u8; 48], 0);
    let coinbase = test_coinbase_action(43);
    let candidate = test_candidate_artifact_action(1, 98);
    {
        let mut state = node.state.write();
        for action in [transfer_a.clone(), transfer_b.clone(), coinbase, candidate] {
            state.pending_actions.insert(action.tx_hash, action);
        }
    }

    let rebroadcast = node.peer_relayable_pending_actions_from(0, 8, usize::MAX);
    let rebroadcast_hashes = rebroadcast
        .iter()
        .map(|action| action.tx_hash)
        .collect::<BTreeSet<_>>();

    assert_eq!(rebroadcast.len(), 2);
    assert!(rebroadcast_hashes.contains(&transfer_a.tx_hash));
    assert!(rebroadcast_hashes.contains(&transfer_b.tx_hash));
}

#[test]
fn peer_relayable_pending_action_rebroadcast_batch_rotates_with_limit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let actions = (0..4u8)
        .map(|offset| {
            test_inline_transfer_action(
                anchor,
                [100u8.saturating_add(offset); 48],
                [110u8.saturating_add(offset); 48],
                0,
            )
        })
        .collect::<Vec<_>>();
    {
        let mut state = node.state.write();
        for action in actions {
            state.pending_actions.insert(action.tx_hash, action);
        }
    }
    let ordered_hashes = node
        .state
        .read()
        .pending_actions
        .values()
        .map(|action| action.tx_hash)
        .collect::<Vec<_>>();

    let first = node.peer_relayable_pending_actions_from(0, 2, usize::MAX);
    let rotated = node.peer_relayable_pending_actions_from(2, 2, usize::MAX);

    assert_eq!(
        first
            .iter()
            .map(|action| action.tx_hash)
            .collect::<Vec<_>>(),
        ordered_hashes[0..2]
    );
    assert_eq!(
        rotated
            .iter()
            .map(|action| action.tx_hash)
            .collect::<Vec<_>>(),
        ordered_hashes[2..4]
    );
}

#[test]
fn peer_relayable_pending_action_rebroadcast_batch_respects_byte_budget() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let actions = (0..3u8)
        .map(|offset| {
            let mut action = test_inline_transfer_action(
                anchor,
                [120u8.saturating_add(offset); 48],
                [130u8.saturating_add(offset); 48],
                0,
            );
            action.ciphertext_sizes = vec![1024, 1024, 1024];
            action.tx_hash = pending_action_hash(&action);
            action
        })
        .collect::<Vec<_>>();
    let one_action_bytes = pending_action_mempool_bytes(&actions[0]);
    {
        let mut state = node.state.write();
        for action in actions {
            state.pending_actions.insert(action.tx_hash, action);
        }
    }

    let selected =
        node.peer_relayable_pending_actions_from(0, 8, one_action_bytes.saturating_add(1));
    let selected_bytes = selected.iter().fold(0usize, |total, action| {
        total.saturating_add(pending_action_mempool_bytes(action))
    });

    assert_eq!(selected.len(), 1);
    assert!(selected_bytes <= one_action_bytes.saturating_add(1));
}

#[test]
fn submit_action_rejects_inline_ciphertext_resource_before_binding_hashing() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [19u8; 48], [20u8; 48], 0);
    let mut args: ShieldedTransferInlineArgs =
        decode_scale_exact(&action.public_args, "test inline transfer args")
            .expect("decode inline args");
    args.ciphertexts = (0..=transaction_core::constants::MAX_OUTPUTS)
        .map(|idx| {
            let mut note = test_transfer_encrypted_note();
            note.kem_ciphertext[0] = idx as u8;
            note
        })
        .collect();
    args.binding_hash = [0x99u8; 64];
    let err = node
        .validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": ACTION_SHIELDED_TRANSFER_INLINE,
            "new_nullifiers": [hex48(&action.nullifiers[0])],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        }))
        .expect_err("inline ciphertext resource overflow must reject before staging");
    assert!(
        err.to_string().contains("inline ciphertext count"),
        "unexpected inline resource error: {err}"
    );
    assert_eq!(node.state.read().pending_actions.len(), 0);
}

#[test]
fn side_branch_with_more_work_reorganizes_canonical_chain() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = NativeConfig {
        dev: true,
        tmp: false,
        base_path: tmp.path().to_path_buf(),
        db_path: tmp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "test".to_string(),
        rpc_methods: "unsafe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits: test_pow_bits,
    };
    let node = NativeNode::open(config).expect("node");
    let genesis = node.best_meta();

    let canonical_work = node.prepare_work().expect("prepare canonical native work");
    let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
    let canonical = node
        .import_mined_block(&canonical_work, canonical_seal)
        .expect("canonical import")
        .expect("canonical block");
    assert_eq!(node.best_meta().hash, canonical.hash);

    let side_one = mined_empty_child(&genesis, 1, test_pow_bits, 1);
    node.import_announced_block(side_one.clone())
        .expect("side one import");
    let side_two = mined_empty_child(&side_one, 2, test_pow_bits, 2);
    assert!(node
        .import_announced_block(side_two.clone())
        .expect("side two import"));

    let best = node.best_meta();
    assert_eq!(best.hash, side_two.hash);
    assert_eq!(best.height, 2);
    assert_eq!(
        node.hash_by_height(1).expect("height one"),
        Some(side_one.hash)
    );
    assert_eq!(
        node.hash_by_height(2).expect("height two"),
        Some(side_two.hash)
    );
    assert_eq!(
        node.header_by_hash(&canonical.hash)
            .expect("old block")
            .unwrap()
            .hash,
        canonical.hash
    );
}

#[test]
fn canonical_reorg_chain_admission_rejects_write_set_drift() {
    let pow_bits = 0x207f_ffff;
    let genesis = genesis_meta(pow_bits).expect("genesis");
    let child = mined_empty_child(&genesis, 1, pow_bits, 11);
    let chain = vec![genesis.clone(), child.clone()];
    let block_entries = chain
        .iter()
        .map(|meta| {
            (
                meta.hash,
                bincode::serialize(meta).expect("serialize block"),
            )
        })
        .collect::<Vec<_>>();
    let height_entries = chain
        .iter()
        .map(|meta| (meta.height, meta.hash))
        .collect::<Vec<_>>();
    let valid_input = native_canonical_reorg_chain_admission_input(
        &chain,
        &block_entries,
        &height_entries,
        Some(&child),
        pow_bits,
    )
    .expect("valid reorg input");
    assert!(evaluate_native_canonical_reorg_chain_admission(valid_input).is_ok());

    let mut bad_height_entries = height_entries.clone();
    bad_height_entries[1].1 = genesis.hash;
    let input = native_canonical_reorg_chain_admission_input(
        &chain,
        &block_entries,
        &bad_height_entries,
        Some(&child),
        pow_bits,
    )
    .expect("height mismatch input");
    assert_eq!(
        evaluate_native_canonical_reorg_chain_admission(input).err(),
        Some(NativeCanonicalReorgChainAdmissionRejection::HeightEntryMismatch)
    );

    let mut bad_block_entries = block_entries.clone();
    bad_block_entries[1].0 = genesis.hash;
    let input = native_canonical_reorg_chain_admission_input(
        &chain,
        &bad_block_entries,
        &height_entries,
        Some(&child),
        pow_bits,
    )
    .expect("block mismatch input");
    assert_eq!(
        evaluate_native_canonical_reorg_chain_admission(input).err(),
        Some(NativeCanonicalReorgChainAdmissionRejection::BlockRecordMismatch)
    );

    let input = native_canonical_reorg_chain_admission_input(
        &chain,
        &block_entries,
        &height_entries,
        Some(&genesis),
        pow_bits,
    )
    .expect("best mismatch input");
    assert_eq!(
        evaluate_native_canonical_reorg_chain_admission(input).err(),
        Some(NativeCanonicalReorgChainAdmissionRejection::BestMetadataMismatch)
    );
}

#[test]
fn reorg_replay_revalidates_historical_parent_metadata_before_publish() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let first = mined_empty_child(&genesis, 1, pow_bits, 0);
    assert!(node
        .import_announced_block(first.clone())
        .expect("first block import"));
    assert_eq!(node.best_meta().hash, first.hash);

    let unsigned_first = unsigned_native_meta(first.clone());
    persist_block_record(&node.block_tree, &unsigned_first)
        .expect("replace persisted parent with unsigned metadata");
    let second = mined_empty_child(&first, 2, pow_bits, 1);
    let err = node
        .import_announced_block(second)
        .expect_err("historical parent metadata must be revalidated during replay");
    let err = format!("{err:?}");
    assert!(err.contains("invalid_miner_public_key_length"), "{err}");
    assert_eq!(node.best_meta().hash, first.hash);
    assert!(node.hash_by_height(2).expect("height two").is_none());
}

#[test]
fn nonwinning_announced_side_branch_record_reloads_without_canonicalizing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), test_pow_bits, "unsafe", false);

    let (canonical, side_one) = {
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();

        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = strongest_test_seal(&canonical_work, 0..512);
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.best_meta().hash, canonical.hash);

        let side_one = (1..128)
            .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
            .find(|candidate| !native_meta_better_than(candidate, &canonical))
            .expect("side child that does not beat canonical tip");
        assert!(
            !node
                .import_announced_block(side_one.clone())
                .expect("side branch import"),
            "nonwinning side branch must not reorganize the canonical chain"
        );
        assert_eq!(node.best_meta().hash, canonical.hash);
        assert_eq!(
            node.hash_by_height(1).expect("canonical height index"),
            Some(canonical.hash)
        );
        assert_eq!(
            node.header_by_hash(&side_one.hash)
                .expect("side branch block record")
                .expect("side branch block should be hash-addressable"),
            side_one
        );
        node.db.flush().expect("flush side branch record");
        (canonical, side_one)
    };

    let reopened = NativeNode::open(config).expect("reopen node");
    assert_eq!(reopened.best_meta().hash, canonical.hash);
    assert_eq!(
        reopened
            .hash_by_height(1)
            .expect("height index after reopen"),
        Some(canonical.hash),
        "nonwinning side branch must not replace the canonical height index"
    );
    assert_eq!(
        reopened
            .header_by_hash(&canonical.hash)
            .expect("canonical block record after reopen")
            .expect("canonical block remains addressable"),
        canonical
    );
    assert_eq!(
        reopened
            .header_by_hash(&side_one.hash)
            .expect("side branch block record after reopen")
            .expect("nonwinning side branch block remains addressable"),
        side_one
    );
}

#[test]
fn sync_response_skips_unknown_nonwinning_backfill_without_replay() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");
    let genesis = node.best_meta();

    let canonical_work = node.prepare_work().expect("prepare canonical native work");
    let canonical_seal = strongest_test_seal(&canonical_work, 0..512);
    let canonical = node
        .import_mined_block(&canonical_work, canonical_seal)
        .expect("canonical import")
        .expect("canonical block");
    assert_eq!(node.best_meta().hash, canonical.hash);

    let stale_side = (1..128)
        .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
        .find(|candidate| !native_meta_better_than(candidate, &canonical))
        .expect("nonwinning side child");
    assert!(
        node.header_by_hash(&stale_side.hash)
            .expect("side child lookup")
            .is_none(),
        "test setup should start with an unknown stale side block"
    );

    let report = import_native_sync_response_blocks(
        &node,
        vec![stale_side.clone()],
        canonical.height,
        NativeSyncResponseImportProgress::new(1),
    );

    assert!(
        report.failure.is_none(),
        "unexpected sync import failure: {:?}",
        report.failure.as_ref().map(|failure| (
            failure.height,
            hex32(&failure.hash),
            failure.error.clone()
        ))
    );
    assert_eq!(report.progress.attempted_blocks, 1);
    assert_eq!(report.progress.imported_blocks, 0);
    assert_eq!(node.best_meta().hash, canonical.hash);
    assert!(
        node.header_by_hash(&stale_side.hash)
            .expect("side child lookup after sync import")
            .is_none(),
        "sync backfill must not replay or persist unknown nonwinning side branches"
    );
}

#[test]
fn sync_response_higher_peer_tip_imports_reorg_prefix() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");
    let genesis = node.best_meta();

    for height in 1..=3 {
        let work = node.prepare_work().expect("prepare local branch work");
        let seal = strongest_test_seal(&work, (height * 16)..(height * 16 + 16));
        let local = node
            .import_mined_block(&work, seal)
            .expect("local branch mined import")
            .expect("local branch block");
        assert_eq!(local.height, height);
    }
    let local_best = node.best_meta();
    assert_eq!(local_best.height, 3);

    let peer_tmp = tempfile::tempdir().expect("peer tempdir");
    let peer_node = NativeNode::open(test_config(peer_tmp.path(), test_pow_bits, "unsafe", false))
        .expect("peer node");
    assert_eq!(peer_node.best_meta().hash, genesis.hash);
    let mut peer_blocks = Vec::new();
    for height in 1..=5 {
        let work = peer_node.prepare_work().expect("prepare peer branch work");
        let seal = strongest_test_seal(&work, (100 + height * 16)..(116 + height * 16));
        let peer = peer_node
            .import_mined_block(&work, seal)
            .expect("peer branch mined import")
            .expect("peer branch block");
        assert_eq!(peer.height, height);
        peer_blocks.push(peer);
    }
    let peer_tip = peer_node.best_meta();
    assert!(
        !native_meta_better_than(&peer_blocks[0], &local_best),
        "first peer prefix block should not individually beat the local tip"
    );

    let report = import_native_sync_response_blocks(
        &node,
        peer_blocks.clone(),
        peer_tip.height,
        NativeSyncResponseImportProgress::new(peer_blocks.len()),
    );

    assert!(
        report.failure.is_none(),
        "unexpected sync import failure: {:?}",
        report.failure.as_ref().map(|failure| (
            failure.height,
            hex32(&failure.hash),
            failure.error.clone()
        ))
    );
    assert_eq!(report.progress.attempted_blocks, peer_blocks.len());
    assert!(report.progress.imported_blocks >= 2);
    assert_eq!(node.best_meta().hash, peer_tip.hash);
    assert_eq!(node.best_meta().height, peer_tip.height);
    for peer in peer_blocks {
        assert_eq!(
            node.header_by_hash(&peer.hash)
                .expect("peer block lookup")
                .expect("peer block stored")
                .hash,
            peer.hash
        );
        assert_eq!(
            node.hash_by_height(peer.height)
                .expect("canonical height lookup"),
            Some(peer.hash),
            "peer branch should become canonical at height {}",
            peer.height
        );
    }
}

#[test]
fn sync_response_tip_extension_imports_contiguous_chunk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");

    let peer_tmp = tempfile::tempdir().expect("peer tempdir");
    let peer_node = NativeNode::open(test_config(peer_tmp.path(), test_pow_bits, "unsafe", false))
        .expect("peer node");
    assert_eq!(node.best_meta().hash, peer_node.best_meta().hash);

    let mut peer_blocks = Vec::new();
    for height in 1..=3 {
        let work = peer_node.prepare_work().expect("prepare peer branch work");
        let seal = strongest_test_seal(&work, (height * 32)..(height * 32 + 32));
        let peer = peer_node
            .import_mined_block(&work, seal)
            .expect("peer branch mined import")
            .expect("peer branch block");
        assert_eq!(peer.height, height);
        peer_blocks.push(peer);
    }
    let peer_tip = peer_node.best_meta();

    let report = import_native_sync_response_blocks(
        &node,
        peer_blocks.clone(),
        peer_tip.height,
        NativeSyncResponseImportProgress::new(peer_blocks.len()),
    );

    assert!(
        report.failure.is_none(),
        "unexpected sync import failure: {:?}",
        report.failure.as_ref().map(|failure| (
            failure.height,
            hex32(&failure.hash),
            failure.error.clone()
        ))
    );
    assert_eq!(report.progress.attempted_blocks, peer_blocks.len());
    assert_eq!(report.progress.imported_blocks, peer_blocks.len() as u64);
    assert_eq!(node.best_meta().hash, peer_tip.hash);
    assert_eq!(node.best_meta().height, peer_tip.height);
}

#[test]
fn reorg_replay_rechecks_historical_side_branch_artifacts_before_publish() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), test_pow_bits, "unsafe", false);

    let (canonical, side_parent, side_child) = {
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();

        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = strongest_test_seal(&canonical_work, 0..512);
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.best_meta().hash, canonical.hash);

        let invalid_transfer =
            test_inline_transfer_action(genesis.state_root, [71u8; 48], [72u8; 48], 0);
        let invalid_candidate = test_candidate_artifact_action(1, 73);
        let side_parent = (1..1024)
            .map(|round| {
                mined_child_with_actions(
                    &genesis,
                    1,
                    test_pow_bits,
                    round,
                    vec![invalid_transfer.clone(), invalid_candidate.clone()],
                )
            })
            .find(|candidate| !native_meta_better_than(candidate, &canonical))
            .expect("side parent that does not beat canonical tip");
        persist_block_record(&node.block_tree, &side_parent).expect("persist side parent");
        node.db.flush().expect("flush persisted side parent");

        let side_child = mined_empty_child(&side_parent, 2, test_pow_bits, 2048);
        (canonical, side_parent, side_child)
    };

    let node = NativeNode::open(config).expect("reopen node with side branch parent");
    assert_eq!(node.best_meta().hash, canonical.hash);
    assert_eq!(
        node.header_by_hash(&side_parent.hash)
            .expect("side parent record")
            .expect("persisted side parent reloads"),
        side_parent
    );

    let err = node
        .import_announced_block(side_child.clone())
        .expect_err("reorg replay must recheck historical side-branch artifacts");
    let err_text = err.to_string();
    assert!(
        err_text.contains("native tx-leaf artifact") || err_text.contains("candidate artifact"),
        "unexpected replay artifact error: {err_text}"
    );
    assert_eq!(node.best_meta().hash, canonical.hash);
    assert_eq!(
        node.hash_by_height(1)
            .expect("height one after failed reorg"),
        Some(canonical.hash),
        "failed replay artifact verification must not replace canonical height index"
    );
    assert_eq!(node.commitment_tree.len(), 0);
    assert!(
        node.header_by_hash(&side_child.hash)
            .expect("side child lookup after failed import")
            .is_none(),
        "failed reorg child must not be persisted"
    );
}

#[test]
fn reorg_replay_rejects_exact_decodable_action_byte_drift_before_publish() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), test_pow_bits, "safe", false);

    let (canonical, side_parent, side_child) = {
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();

        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = strongest_test_seal(&canonical_work, 0..512);
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.best_meta().hash, canonical.hash);

        let original = test_outbound_bridge_action(b"reorg action-byte original");
        let substitute = test_outbound_bridge_action(b"reorg action-byte substitute");
        let side_parent = (1..1024)
            .map(|round| {
                mined_child_with_actions(&genesis, 1, test_pow_bits, round, vec![original.clone()])
            })
            .find(|candidate| !native_meta_better_than(candidate, &canonical))
            .expect("side parent that does not beat canonical tip");
        let mut corrupted_parent = side_parent.clone();
        replace_single_action_body_with_exact_decodable_substitute(
            &mut corrupted_parent,
            &substitute,
        );
        persist_block_record(&node.block_tree, &corrupted_parent)
            .expect("persist corrupted side parent");
        node.db.flush().expect("flush corrupted side parent");

        let side_child = mined_empty_child(&side_parent, 2, test_pow_bits, 2048);
        (canonical, side_parent, side_child)
    };

    let node = NativeNode::open(config).expect("reopen node with corrupted side branch parent");
    assert_eq!(node.best_meta().hash, canonical.hash);
    assert!(
        node.header_by_hash(&side_parent.hash)
            .expect("side parent record")
            .is_some(),
        "corrupted side parent remains hash-addressable"
    );

    let err = node
        .import_announced_block(side_child.clone())
        .expect_err("reorg replay must reject exact-decodable action-byte drift");
    let err = format!("{err:?}");
    assert!(err.contains("native replay action root"), "{err}");
    assert!(err.contains("extrinsics_root_mismatch"), "{err}");
    assert_eq!(node.best_meta().hash, canonical.hash);
    assert_eq!(
        node.hash_by_height(1)
            .expect("height one after failed reorg"),
        Some(canonical.hash),
        "failed replay action-root verification must not replace canonical height index"
    );
    assert_eq!(
        node.hash_by_height(2)
            .expect("height two after failed reorg"),
        None,
        "failed replay action-root verification must not publish the winning child height"
    );
    assert!(
        node.header_by_hash(&side_child.hash)
            .expect("side child lookup after failed import")
            .is_none(),
        "failed reorg child must not be persisted"
    );
}

#[test]
fn reorg_rejects_missing_old_canonical_chain_before_publish() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");
    let genesis = node.best_meta();

    stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [81u8; 48]);
    let canonical_work = node.prepare_work().expect("prepare canonical native work");
    let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
    let canonical = node
        .import_mined_block(&canonical_work, canonical_seal)
        .expect("canonical import")
        .expect("canonical block");
    assert_eq!(node.best_meta().hash, canonical.hash);
    let old_height_one = node.hash_by_height(1).expect("height one before reorg");
    let old_pending_len = node.state.read().pending_actions.len();
    let old_state_root = node.state.read().commitment_tree.root();

    let side_one = (1..128)
        .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
        .find(|candidate| !native_meta_better_than(candidate, &canonical))
        .expect("side child that does not beat canonical tip");
    persist_block_record(&node.block_tree, &side_one).expect("persist side parent");

    node.block_tree
        .remove(canonical.hash)
        .expect("remove old canonical best block record");
    node.block_tree.flush().expect("flush corrupted old chain");

    let side_two = mined_empty_child(&side_one, 2, test_pow_bits, 129);
    let err = node
        .import_announced_block(side_two.clone())
        .expect_err("missing old canonical chain must reject winning reorg");
    let err_text = err.to_string();
    assert!(
        err_text.contains("missing native block"),
        "unexpected reorg error: {err_text}"
    );
    assert_eq!(node.best_meta().hash, canonical.hash);
    assert_eq!(
        node.hash_by_height(1)
            .expect("height index after rejected reorg"),
        old_height_one,
        "failed reorg must not replace the old canonical height index"
    );
    assert_eq!(
        node.hash_by_height(2)
            .expect("height two after rejected reorg"),
        None,
        "failed reorg must not publish the side tip height index"
    );
    assert_eq!(node.state.read().pending_actions.len(), old_pending_len);
    assert_eq!(node.state.read().commitment_tree.root(), old_state_root);
    assert!(
        node.header_by_hash(&side_two.hash)
            .expect("side tip lookup after rejected reorg")
            .is_none(),
        "failed reorg child must not be persisted"
    );
}

#[test]
fn reorg_action_block_commit_reloads_canonical_sled_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), test_pow_bits, "safe", false);
    let canonical_reward = consensus::reward::block_subsidy(1);
    let side_reward = consensus::reward::block_subsidy(2);

    let (canonical, old_action_hash, side_one, side_two, side_action_hash, side_commitment) = {
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();

        stage_test_coinbase(&node, canonical_reward, [31u8; 48]);
        let old_action_hash = *node
            .state
            .read()
            .pending_actions
            .keys()
            .next()
            .expect("staged canonical action");
        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = strongest_test_seal(&canonical_work, 0..512);
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.commitment_tree.len(), 1);
        assert_eq!(node.ciphertext_archive_tree.len(), 1);

        let side_one = (1..128)
            .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
            .find(|candidate| !native_meta_better_than(candidate, &canonical))
            .expect("side child that does not beat canonical tip");
        persist_block_record(&node.block_tree, &side_one).expect("persist side parent");

        let side_action = test_coinbase_action(side_reward);
        let side_action_hash = side_action.tx_hash;
        let side_commitment = side_action.commitments[0];
        let side_two =
            mined_child_with_actions(&side_one, 2, test_pow_bits, 129, vec![side_action]);
        assert!(
            node.header_by_hash(&side_two.hash)
                .expect("read side tip before import")
                .is_none(),
            "winning announced side tip should not be pre-persisted by this test"
        );
        assert!(
            node.import_announced_block(side_two.clone())
                .expect("side two import"),
            "side action block must trigger reorg"
        );
        assert_eq!(node.best_meta().hash, side_two.hash);
        assert_eq!(node.commitment_tree.len(), 1);
        assert_eq!(node.ciphertext_archive_tree.len(), 1);
        assert!(node
            .action_tree
            .get(side_action_hash.as_slice())
            .expect("read side action")
            .is_none());

        (
            canonical,
            old_action_hash,
            side_one,
            side_two,
            side_action_hash,
            side_commitment,
        )
    };

    let reopened = NativeNode::open(config).expect("reopen node after reorg commit");
    let state = reopened.state.read();
    assert_eq!(state.best.hash, side_two.hash);
    assert_eq!(state.best.height, 2);
    assert_eq!(state.best.supply_digest, side_reward as u128);
    assert_eq!(state.commitment_tree.leaf_count(), 1);
    assert_eq!(state.commitment_tree.root(), side_two.state_root);
    assert!(
        state.pending_actions.contains_key(&old_action_hash),
        "orphaned old canonical action should be pending after reorg"
    );
    assert!(
        !state.pending_actions.contains_key(&side_action_hash),
        "canonical side action must not remain pending after reorg"
    );
    drop(state);

    assert_eq!(
        reopened.hash_by_height(1).expect("height one"),
        Some(side_one.hash)
    );
    assert_eq!(
        reopened.hash_by_height(2).expect("height two"),
        Some(side_two.hash)
    );
    assert_eq!(
        reopened
            .header_by_hash(&canonical.hash)
            .expect("old canonical header")
            .expect("old canonical block remains addressable")
            .hash,
        canonical.hash
    );
    assert_eq!(
        reopened
            .header_by_hash(&side_two.hash)
            .expect("side tip header")
            .expect("winning side tip block record reloads")
            .hash,
        side_two.hash
    );
    assert_eq!(reopened.commitment_tree.len(), 1);
    assert_eq!(reopened.ciphertext_archive_tree.len(), 1);
    assert_eq!(
        reopened
            .commitment_tree
            .get(0u64.to_be_bytes())
            .expect("read canonical commitment")
            .expect("canonical commitment")
            .as_ref(),
        side_commitment.as_slice()
    );
    assert!(reopened
        .action_tree
        .get(side_action_hash.as_slice())
        .expect("read side action after reopen")
        .is_none());
    assert!(reopened
        .action_tree
        .get(old_action_hash.as_slice())
        .expect("read orphaned action after reopen")
        .is_some());
}

#[test]
fn reorg_preserves_valid_pending_sidecar_when_staged_ciphertext_survives() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");
    let genesis = node.best_meta();

    stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [81u8; 48]);
    let canonical_work = node.prepare_work().expect("prepare canonical native work");
    let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
    let canonical = node
        .import_mined_block(&canonical_work, canonical_seal)
        .expect("canonical import")
        .expect("canonical block");
    assert_eq!(node.best_meta().hash, canonical.hash);

    let pending_template =
        test_sidecar_transfer_action(genesis.state_root, [82u8; 48], [83u8; 48], 0);
    let ciphertext_hex = format!("0x{}", hex::encode(test_transfer_ciphertext_bytes()));
    node.submit_ciphertexts(json!({ "ciphertexts": [ciphertext_hex] }))
        .expect("stage pending sidecar ciphertext");
    let staged_pending = node
        .validate_and_stage_action(json!({
            "binding_circuit": pending_template.binding.circuit,
            "binding_crypto": pending_template.binding.crypto,
            "family_id": pending_template.family_id,
            "action_id": pending_template.action_id,
            "new_nullifiers": pending_template
                .nullifiers
                .iter()
                .map(hex48)
                .collect::<Vec<_>>(),
            "public_args": base64::engine::general_purpose::STANDARD
                .encode(pending_template.public_args.clone()),
        }))
        .expect("stage pending sidecar transfer");
    assert!(node
        .state
        .read()
        .pending_actions
        .contains_key(&staged_pending.tx_hash));

    let side_one = (1..128)
        .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
        .find(|candidate| !native_meta_better_than(candidate, &canonical))
        .expect("side child that does not beat canonical tip");
    persist_block_record(&node.block_tree, &side_one).expect("persist side parent");
    let side_two = mined_empty_child(&side_one, 2, test_pow_bits, 129);
    assert!(
        node.import_announced_block(side_two.clone())
            .expect("side two import"),
        "side two must trigger canonical reorg"
    );
    assert_eq!(node.best_meta().hash, side_two.hash);
    let state = node.state.read();
    assert!(
        state.pending_actions.contains_key(&staged_pending.tx_hash),
        "valid pending sidecar must survive reorg revalidation"
    );
    assert!(
        state
            .staged_ciphertexts
            .contains_key(&hex48(&staged_pending.ciphertext_hashes[0])),
        "pending sidecar ciphertext marker must remain staged after reorg"
    );
}

#[test]
fn mixed_restart_reorg_rejects_sidecar_nullifier_bridge_replay_before_publication() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), test_pow_bits, "safe", false);
    let shared_nullifier = [90u8; 48];
    let side_commitment = [92u8; 48];

    let (canonical, side_one, old_archive_len) = {
        let node = NativeNode::open(config.clone()).expect("node");
        let genesis = node.best_meta();

        stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [91u8; 48]);
        let canonical_work = node.prepare_work().expect("prepare canonical native work");
        let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
        let canonical = node
            .import_mined_block(&canonical_work, canonical_seal)
            .expect("canonical import")
            .expect("canonical block");
        assert_eq!(node.best_meta().hash, canonical.hash);
        assert_eq!(node.ciphertext_archive_tree.len(), 1);

        let side_one = (1..128)
            .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
            .find(|candidate| !native_meta_better_than(candidate, &canonical))
            .expect("side parent that does not beat canonical tip");
        assert!(
            !node
                .import_announced_block(side_one.clone())
                .expect("side parent import"),
            "side parent should persist without reorganizing"
        );
        assert_eq!(node.best_meta().hash, canonical.hash);
        node.db.flush().expect("flush mixed side parent");

        (canonical, side_one, node.ciphertext_archive_tree.len())
    };

    let reopened = NativeNode::open(config.clone()).expect("reopen before mixed reorg attempt");
    {
        let state = reopened.state.read();
        assert_eq!(state.best.hash, canonical.hash);
        assert_eq!(state.best.height, 1);
        assert_eq!(state.commitment_tree.leaf_count(), 1);
        assert_eq!(state.commitment_tree.root(), canonical.state_root);
        assert!(!state.nullifiers.contains(&shared_nullifier));
        assert!(state.consumed_bridge_messages.is_empty());
    }
    assert_eq!(
        reopened.hash_by_height(1).expect("reopened height one"),
        Some(canonical.hash)
    );
    assert!(
        reopened
            .header_by_hash(&side_one.hash)
            .expect("side parent record after restart")
            .is_some(),
        "nonwinning side parent must survive restart for reorg replay"
    );
    assert_eq!(reopened.ciphertext_archive_tree.len(), old_archive_len);

    let sidecar =
        test_sidecar_transfer_action(side_one.state_root, shared_nullifier, side_commitment, 0);
    let sidecar_ciphertext_hash = sidecar.ciphertext_hashes[0];
    let sidecar_hash = sidecar.tx_hash;
    let inbound = test_disabled_risc0_inbound_bridge_action(b"mixed restart reorg inbound");
    let inbound_replay_key = bridge_inbound_replay_key_from_action(&inbound)
        .expect("derive inbound replay key")
        .expect("inbound bridge action replay key");
    let candidate = test_candidate_artifact_action(1, 91);
    stage_test_sidecar_ciphertext(&reopened, &sidecar);
    assert!(
        reopened
            .state
            .read()
            .staged_ciphertexts
            .contains_key(&hex48(&sidecar_ciphertext_hash)),
        "test must present the same sidecar marker the mempool path requires"
    );

    let bad_side_tip = mined_child_with_actions(
        &side_one,
        2,
        test_pow_bits,
        129,
        vec![sidecar.clone(), inbound, candidate],
    );
    let err = reopened
        .import_announced_block(bad_side_tip.clone())
        .expect_err("mixed sidecar/nullifier/bridge replay candidate must fail before publish");
    let err = format!("{err:?}");
    assert!(err.contains("verification is disabled"), "{err}");
    assert_eq!(
        reopened.best_meta().hash,
        canonical.hash,
        "failed mixed reorg must not publish a new best block"
    );
    assert_eq!(
        reopened
            .hash_by_height(1)
            .expect("height one after bad reorg"),
        Some(canonical.hash),
        "failed mixed reorg must not replace the canonical height-one index"
    );
    assert_eq!(
        reopened
            .hash_by_height(2)
            .expect("height two after bad reorg"),
        None
    );
    assert!(
        reopened
            .header_by_hash(&bad_side_tip.hash)
            .expect("bad side tip lookup")
            .is_none(),
        "failed mixed side tip must not be persisted"
    );
    assert!(
        reopened
            .nullifier_tree
            .get(shared_nullifier.as_slice())
            .expect("read rejected sidecar nullifier")
            .is_none(),
        "failed mixed reorg must not publish transfer nullifier rows"
    );
    assert!(
        reopened
            .ciphertext_index_tree
            .get(sidecar_ciphertext_hash.as_slice())
            .expect("read rejected sidecar ciphertext index")
            .is_none(),
        "failed mixed reorg must not publish sidecar ciphertext index rows"
    );
    assert!(
        reopened
            .bridge_inbound_tree
            .get(inbound_replay_key.as_slice())
            .expect("read disabled inbound replay key")
            .is_none(),
        "failed mixed reorg must not publish inbound bridge replay rows"
    );
    assert_eq!(reopened.ciphertext_archive_tree.len(), old_archive_len);
    assert_eq!(reopened.bridge_inbound_tree.len(), 0);
    assert!(
        reopened
            .state
            .read()
            .staged_ciphertexts
            .contains_key(&hex48(&sidecar_ciphertext_hash)),
        "failed mixed reorg must not clear staged sidecar markers for rejected actions"
    );

    drop(reopened);
    let reopened_after_failure = NativeNode::open(config).expect("reopen after failed mixed reorg");
    assert_eq!(reopened_after_failure.best_meta().hash, canonical.hash);
    assert_eq!(
        reopened_after_failure
            .hash_by_height(1)
            .expect("height one after failed mixed reorg restart"),
        Some(canonical.hash)
    );
    assert_eq!(
        reopened_after_failure
            .hash_by_height(2)
            .expect("height two after failed mixed reorg restart"),
        None
    );
    assert_eq!(
        reopened_after_failure.ciphertext_archive_tree.len(),
        old_archive_len
    );
    assert_eq!(reopened_after_failure.bridge_inbound_tree.len(), 0);
    assert!(reopened_after_failure
        .nullifier_tree
        .get(shared_nullifier.as_slice())
        .expect("read rejected nullifier after restart")
        .is_none());
    assert!(reopened_after_failure
        .ciphertext_index_tree
        .get(sidecar_ciphertext_hash.as_slice())
        .expect("read rejected ciphertext index after restart")
        .is_none());
    assert!(reopened_after_failure
        .bridge_inbound_tree
        .get(inbound_replay_key.as_slice())
        .expect("read rejected replay key after restart")
        .is_none());
    assert!(reopened_after_failure
        .state
        .read()
        .staged_ciphertexts
        .contains_key(&hex48(&sidecar_ciphertext_hash)));
    assert!(reopened_after_failure
        .action_tree
        .get(sidecar_hash.as_slice())
        .expect("read rejected sidecar pending action after restart")
        .is_none());
}

#[test]
fn reorg_pending_revalidation_prioritizes_existing_pending_over_orphaned_duplicate_nullifier() {
    let test_pow_bits = 0x207f_ffff;
    let canonical_state = test_state(genesis_meta(test_pow_bits).expect("genesis"));
    let anchor = canonical_state.commitment_tree.root();
    let nullifier = [73u8; 48];
    let orphaned = test_inline_transfer_action(anchor, nullifier, [74u8; 48], 0);
    let existing = test_inline_transfer_action(anchor, nullifier, [75u8; 48], 0);
    assert_ne!(existing.tx_hash, orphaned.tx_hash);

    let mut existing_pending = BTreeMap::new();
    existing_pending.insert(existing.tx_hash, existing.clone());
    let revalidated = revalidate_reorg_pending_actions(
        &canonical_state,
        existing_pending,
        vec![orphaned.clone()],
    );

    assert!(
        revalidated.contains_key(&existing.tx_hash),
        "existing pending action should keep priority"
    );
    assert!(
        !revalidated.contains_key(&orphaned.tx_hash),
        "orphaned duplicate nullifier must be quarantined before reorg persistence"
    );
    assert_eq!(revalidated.len(), 1);
}

#[test]
fn post_block_pending_revalidation_drops_now_spent_nullifier_sibling() {
    let test_pow_bits = 0x207f_ffff;
    let mut canonical_state = test_state(genesis_meta(test_pow_bits).expect("genesis"));
    let anchor = canonical_state.commitment_tree.root();
    let mined = test_inline_transfer_action(anchor, [76u8; 48], [77u8; 48], 0);
    let stale = test_inline_transfer_action(anchor, [76u8; 48], [78u8; 48], 0);
    let fresh = test_inline_transfer_action(anchor, [79u8; 48], [80u8; 48], 0);
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

    apply_actions_to_memory(
        &da_ciphertext_tree,
        &mut canonical_state,
        std::slice::from_ref(&mined),
    )
    .expect("mined action should advance canonical state");

    let mut existing_pending = BTreeMap::new();
    existing_pending.insert(stale.tx_hash, stale.clone());
    existing_pending.insert(fresh.tx_hash, fresh.clone());
    let revalidated =
        revalidate_pending_actions_after_state_advance(&canonical_state, existing_pending);

    assert!(
        !revalidated.contains_key(&stale.tx_hash),
        "pending action spending a now-spent nullifier must be pruned"
    );
    assert!(
        revalidated.contains_key(&fresh.tx_hash),
        "unrelated pending action should survive post-block revalidation"
    );
    assert_eq!(revalidated.len(), 1);
}

#[test]
fn post_block_pending_revalidation_drops_orphan_candidate_artifact() {
    let test_pow_bits = 0x207f_ffff;
    let canonical_state = test_state(genesis_meta(test_pow_bits).expect("genesis"));
    let candidate = test_candidate_artifact_action(1, 81);

    let mut existing_pending = BTreeMap::new();
    existing_pending.insert(candidate.tx_hash, candidate.clone());
    let revalidated =
        revalidate_pending_actions_after_state_advance(&canonical_state, existing_pending);

    assert!(
        !revalidated.contains_key(&candidate.tx_hash),
        "candidate artifact without matching transfers must be pruned"
    );
    assert!(revalidated.is_empty());
}

#[test]
fn auto_coinbase_prune_drops_persisted_coinbase_action() {
    let test_pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(test_pow_bits).expect("genesis"));
    let coinbase = test_coinbase_action(42);
    state
        .pending_actions
        .insert(coinbase.tx_hash, coinbase.clone());

    prune_auto_coinbase_actions_from_pending(&mut state, "test");

    assert!(
        !state.pending_actions.contains_key(&coinbase.tx_hash),
        "auto-coinbase nodes must not keep persisted coinbase actions in the mempool"
    );
    assert!(state.pending_actions.is_empty());
}

#[test]
fn reorg_rebuild_failure_preserves_canonical_indexes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");
    let genesis = node.best_meta();

    stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [61u8; 48]);
    let canonical_work = node.prepare_work().expect("prepare canonical native work");
    let canonical_seal = mine_native_round(canonical_work.clone(), 0).expect("canonical seal");
    let canonical = node
        .import_mined_block(&canonical_work, canonical_seal)
        .expect("canonical import")
        .expect("canonical block");
    assert_eq!(node.best_meta().hash, canonical.hash);
    assert_eq!(node.commitment_tree.len(), 1);
    assert_eq!(node.ciphertext_archive_tree.len(), 1);

    let side_one = (1..128)
        .map(|round| mined_empty_child(&genesis, 1, test_pow_bits, round))
        .find(|candidate| !native_meta_better_than(candidate, &canonical))
        .expect("side child that does not beat canonical tip");
    persist_block_record(&node.block_tree, &side_one).expect("persist side parent");

    let parent_state = test_state(side_one.clone());
    let sidecar = test_sidecar_transfer_action(
        parent_state.commitment_tree.root(),
        [62u8; 48],
        [63u8; 48],
        0,
    );
    let candidate = test_candidate_artifact_action(1, 64);
    let side_two =
        mined_child_with_actions(&side_one, 2, test_pow_bits, 129, vec![sidecar, candidate]);
    persist_block_record(&node.block_tree, &side_two).expect("persist side tip");

    let old_height_one = node.hash_by_height(1).expect("height index before reorg");
    let old_commitments = node.commitment_tree.len();
    let old_ciphertexts = node.ciphertext_archive_tree.len();
    let old_best = node.best_meta().hash;
    let err = {
        let mut state = node.state.write();
        let new_chain = node
            .chain_to_hash(side_two.hash)
            .expect("load side chain for reorg");
        let err = node
            .reorganize_chain_to_best_locked(&mut state, new_chain)
            .expect_err("missing sidecar ciphertext must reject before canonical clear");
        assert_eq!(state.best.hash, old_best);
        err
    };
    let err_text = err.to_string();
    assert!(
        err_text.contains("missing canonical DA ciphertext")
            || err_text.contains("canonical DA ciphertext hash mismatch"),
        "unexpected reorg error: {err_text}"
    );
    assert_eq!(node.best_meta().hash, old_best);
    assert_eq!(
        node.hash_by_height(1)
            .expect("height index after failed reorg"),
        old_height_one,
        "failed reorg must leave canonical height index untouched"
    );
    assert_eq!(
        node.commitment_tree.len(),
        old_commitments,
        "failed reorg must not clear canonical commitments"
    );
    assert_eq!(
        node.ciphertext_archive_tree.len(),
        old_ciphertexts,
        "failed reorg must not clear canonical ciphertext archive"
    );
}

#[test]
fn coinbase_action_mints_shielded_output_and_updates_supply() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let config = NativeConfig {
        dev: true,
        tmp: false,
        base_path: tmp.path().to_path_buf(),
        db_path: tmp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "test".to_string(),
        rpc_methods: "unsafe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits: test_pow_bits,
    };
    let node = NativeNode::open(config).expect("node");
    let reward = consensus::reward::block_subsidy(1);
    let coinbase = test_coinbase_action(reward);
    let args: MintCoinbaseArgs = decode_scale_exact(&coinbase.public_args, "coinbase args")
        .expect("decode test coinbase args");
    node.validate_and_stage_action(json!({
        "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        "family_id": FAMILY_SHIELDED_POOL,
        "action_id": ACTION_MINT_COINBASE,
        "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
    }))
    .expect("stage coinbase");

    let work = node.prepare_work().expect("prepare native work");
    let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("coinbase import")
        .expect("coinbase block");
    assert_eq!(imported.supply_digest, reward as u128);
    assert_eq!(node.state.read().commitment_tree.leaf_count(), 1);
    assert_eq!(node.state.read().pending_actions.len(), 0);
}

#[test]
fn prepare_work_auto_coinbase_is_imported_and_wallet_decryptable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let keys = wallet::RootSecret::from_bytes([7u8; 32]).derive();
    let material = keys.address(0).expect("address material");
    let address = material.shielded_address();
    let mut config = test_config(tmp.path(), pow_bits, "unsafe", false);
    config.miner_address = Some(address.encode().expect("encode miner address"));
    let node = NativeNode::open(config).expect("node");

    let reward = consensus::reward::block_subsidy(1);
    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(work.tx_count, 1);
    let seal = mine_native_round(work.clone(), 0).expect("auto coinbase seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("auto coinbase import")
        .expect("auto coinbase block");
    assert_eq!(imported.supply_digest, reward as u128);
    assert_eq!(node.state.read().commitment_tree.leaf_count(), 1);

    let actions = decode_block_actions(&imported).expect("decode imported actions");
    assert_eq!(actions.len(), 1);
    assert!(is_coinbase_action(&actions[0]));
    let args: MintCoinbaseArgs = decode_scale_exact(&actions[0].public_args, "auto coinbase args")
        .expect("decode auto coinbase args");
    let miner_note = &args.reward_bundle.miner_note;
    assert_eq!(miner_note.amount, reward);
    assert_eq!(
        miner_note.recipient_address,
        coinbase_recipient_address_bytes(&address)
    );
    assert_eq!(
        miner_note.commitment,
        coinbase_note_data_commitment(miner_note)
    );

    let ciphertext = NoteCiphertext::from_chain_bytes(&miner_note.encrypted_note.encode())
        .expect("wallet decode auto coinbase ciphertext");
    let recovered = ciphertext
        .decrypt(&material)
        .expect("decrypt auto coinbase note");
    assert_eq!(recovered.value, reward);
    assert_eq!(recovered.asset_id, 0);
    assert_eq!(recovered.memo.as_bytes(), b"");
}

#[test]
fn prepared_work_import_survives_action_cache_eviction() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let keys = wallet::RootSecret::from_bytes([9u8; 32]).derive();
    let material = keys.address(0).expect("address material");
    let address = material.shielded_address();
    let mut config = test_config(tmp.path(), pow_bits, "unsafe", false);
    config.miner_address = Some(address.encode().expect("encode miner address"));
    let node = NativeNode::open(config).expect("node");

    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(work.tx_count, 1);
    node.prepared_mining_actions.lock().clear();

    let seal = mine_native_round(work.clone(), 0).expect("auto coinbase seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("prepared work import")
        .expect("prepared work block");

    let actions = decode_block_actions(&imported).expect("decode imported actions");
    assert_eq!(actions.len(), 1);
    assert!(is_coinbase_action(&actions[0]));
    assert_eq!(node.state.read().commitment_tree.leaf_count(), 1);
}

#[test]
fn prepare_work_auto_coinbase_ignores_staged_coinbase_recipient() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let keys = wallet::RootSecret::from_bytes([8u8; 32]).derive();
    let material = keys.address(0).expect("address material");
    let address = material.shielded_address();
    let mut config = test_config(tmp.path(), pow_bits, "unsafe", false);
    config.miner_address = Some(address.encode().expect("encode miner address"));
    let node = NativeNode::open(config).expect("node");
    let reward = consensus::reward::block_subsidy(1);
    stage_test_coinbase(&node, reward, [0xe5u8; 48]);

    let staged = node
        .state
        .read()
        .pending_actions
        .values()
        .next()
        .cloned()
        .expect("staged coinbase");
    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(work.tx_count, 1);
    let seal = mine_native_round(work.clone(), 0).expect("auto coinbase seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("auto coinbase import")
        .expect("auto coinbase block");
    let actions = decode_block_actions(&imported).expect("decode imported actions");
    assert_eq!(actions.len(), 1);
    assert_ne!(actions[0].tx_hash, staged.tx_hash);
    let args: MintCoinbaseArgs = decode_scale_exact(&actions[0].public_args, "auto coinbase args")
        .expect("decode auto coinbase args");
    assert_eq!(
        args.reward_bundle.miner_note.recipient_address,
        coinbase_recipient_address_bytes(&address)
    );
}

#[test]
fn mined_action_block_commit_reloads_canonical_sled_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let reward = consensus::reward::block_subsidy(1);
    let commitment = [17u8; 48];
    let imported = {
        let node = NativeNode::open(config.clone()).expect("node");
        stage_test_coinbase(&node, reward, commitment);
        let action_hash = *node
            .state
            .read()
            .pending_actions
            .keys()
            .next()
            .expect("staged coinbase action");
        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("coinbase import")
            .expect("coinbase block");
        assert_eq!(node.best_meta().hash, imported.hash);
        assert_eq!(node.commitment_tree.len(), 1);
        assert_eq!(node.ciphertext_archive_tree.len(), 1);
        assert!(node
            .action_tree
            .get(action_hash.as_slice())
            .expect("read action tree")
            .is_none());
        imported
    };

    let reopened = NativeNode::open(config).expect("reopen node after mined commit");
    let state = reopened.state.read();
    assert_eq!(state.best.hash, imported.hash);
    assert_eq!(state.best.height, 1);
    assert_eq!(state.best.supply_digest, reward as u128);
    assert_eq!(state.commitment_tree.leaf_count(), 1);
    assert_eq!(state.commitment_tree.root(), imported.state_root);
    assert_eq!(state.pending_actions.len(), 0);
    drop(state);
    assert_eq!(
        reopened.hash_by_height(1).expect("height index"),
        Some(imported.hash)
    );
    assert_eq!(
        reopened
            .header_by_hash(&imported.hash)
            .expect("header lookup")
            .expect("persisted header")
            .hash,
        imported.hash
    );
    assert_eq!(reopened.commitment_tree.len(), 1);
    assert_eq!(reopened.ciphertext_archive_tree.len(), 1);
    assert_eq!(reopened.action_tree.len(), 0);
}

#[test]
fn startup_canonical_index_repair_rebuilds_archive_atomically() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let reward = consensus::reward::block_subsidy(1);
    let stale_ciphertext_hash = [99u8; 48];
    let (
        imported,
        expected_commitment,
        expected_archive,
        expected_index_hash,
        expected_index_value,
    ) = {
        let node = NativeNode::open(config.clone()).expect("node");
        stage_test_coinbase(&node, reward, [23u8; 48]);
        let action = node
            .state
            .read()
            .pending_actions
            .values()
            .next()
            .expect("staged coinbase")
            .clone();
        let expected_commitment = action.commitments[0];
        let expected_index_hash = action.ciphertext_hashes[0];
        let mut expected_index_value = Vec::with_capacity(32 + 4 + 8);
        expected_index_value.extend_from_slice(&action.tx_hash);
        expected_index_value.extend_from_slice(&action.ciphertext_sizes[0].to_le_bytes());
        expected_index_value.extend_from_slice(&0u64.to_le_bytes());

        let work = node.prepare_work().expect("prepare native work");
        let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("coinbase import")
            .expect("coinbase block");
        assert_eq!(node.commitment_tree.len(), 1);
        assert_eq!(node.ciphertext_index_tree.len(), 1);
        assert_eq!(node.ciphertext_archive_tree.len(), 1);
        let expected_archive = node
            .ciphertext_archive_tree
            .get(0u64.to_be_bytes())
            .expect("read canonical archive")
            .expect("canonical archive entry")
            .to_vec();
        node.db.flush().expect("flush mined test db");
        (
            imported,
            expected_commitment,
            expected_archive,
            expected_index_hash,
            expected_index_value,
        )
    };

    {
        let db = sled::open(&config.db_path).expect("open test db for repair corruption");
        let ciphertext_index_tree = db
            .open_tree("shielded_ciphertext_index")
            .expect("ciphertext index tree");
        let ciphertext_archive_tree = db
            .open_tree("shielded_ciphertexts_by_index")
            .expect("ciphertext archive tree");
        ciphertext_index_tree
            .remove(expected_index_hash.as_slice())
            .expect("remove canonical index");
        ciphertext_index_tree
            .insert(stale_ciphertext_hash.as_slice(), b"stale".as_slice())
            .expect("insert stale index");
        ciphertext_archive_tree
            .remove(0u64.to_be_bytes())
            .expect("remove canonical archive");
        db.flush().expect("flush repair corruption");
    }

    let reopened = NativeNode::open(config).expect("reopen with canonical index repair");
    let state = reopened.state.read();
    assert_eq!(state.best.hash, imported.hash);
    assert_eq!(state.best.height, 1);
    assert_eq!(state.best.supply_digest, reward as u128);
    assert_eq!(state.commitment_tree.leaf_count(), 1);
    assert_eq!(state.commitment_tree.root(), imported.state_root);
    drop(state);

    assert_eq!(reopened.commitment_tree.len(), 1);
    assert_eq!(
        reopened
            .commitment_tree
            .get(0u64.to_be_bytes())
            .expect("read repaired commitment")
            .expect("repaired commitment")
            .as_ref(),
        expected_commitment.as_slice()
    );
    assert_eq!(reopened.ciphertext_archive_tree.len(), 1);
    assert_eq!(
        reopened
            .ciphertext_archive_tree
            .get(0u64.to_be_bytes())
            .expect("read repaired archive")
            .expect("repaired archive")
            .as_ref(),
        expected_archive.as_slice()
    );
    assert_eq!(reopened.ciphertext_index_tree.len(), 1);
    assert_eq!(
        reopened
            .ciphertext_index_tree
            .get(expected_index_hash.as_slice())
            .expect("read repaired ciphertext index")
            .expect("repaired ciphertext index")
            .as_ref(),
        expected_index_value.as_slice()
    );
    assert!(
        reopened
            .ciphertext_index_tree
            .get(stale_ciphertext_hash.as_slice())
            .expect("read stale ciphertext index")
            .is_none(),
        "startup repair must remove stale ciphertext index rows in the same replacement"
    );
}

#[test]
fn startup_replays_canonical_block_actions_before_accepting_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let imported = {
        let node = NativeNode::open(config.clone()).expect("node");
        let work = node.prepare_work().expect("prepare empty work");
        let seal = mine_native_round(work.clone(), 0).expect("empty seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("empty import")
            .expect("empty block");
        node.db.flush().expect("flush empty block");
        imported
    };

    {
        let db = sled::open(&config.db_path).expect("open test db for body corruption");
        let meta_tree = db.open_tree("meta").expect("meta tree");
        let block_tree = db.open_tree("block_meta_by_hash").expect("block tree");
        let mut corrupted = imported;
        corrupted.action_bytes.push(vec![0xaa]);
        let encoded = bincode::serialize(&corrupted).expect("serialize corrupted metadata");
        meta_tree
            .insert(META_BEST_KEY, encoded.clone())
            .expect("corrupt best body");
        block_tree
            .insert(corrupted.hash.as_slice(), encoded)
            .expect("corrupt block body");
        db.flush().expect("flush body corruption");
    }

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("startup must replay canonical block bodies"),
        Err(err) => err,
    };
    let err = format!("{err:?}");
    assert!(err.contains("block action payload count mismatch"), "{err}");
}

#[test]
fn startup_rejects_nonempty_exact_decodable_action_byte_drift_before_accepting_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let imported = {
        let node = NativeNode::open(config.clone()).expect("node");
        let subsidy = consensus::reward::block_subsidy(1);
        stage_test_coinbase(&node, subsidy, [31u8; 48]);
        let work = node.prepare_work().expect("prepare coinbase work");
        let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("coinbase import")
            .expect("coinbase block");
        assert_eq!(imported.tx_count, 1);
        assert_eq!(imported.action_bytes.len(), 1);
        node.db.flush().expect("flush coinbase block");
        imported
    };

    {
        let db = sled::open(&config.db_path).expect("open test db for body corruption");
        let meta_tree = db.open_tree("meta").expect("meta tree");
        let block_tree = db.open_tree("block_meta_by_hash").expect("block tree");
        let substitute = test_coinbase_action_with_seed(
            consensus::reward::block_subsidy(imported.height),
            [91u8; 32],
        );
        let mut corrupted = imported;
        replace_single_action_body_with_exact_decodable_substitute(&mut corrupted, &substitute);
        let encoded = bincode::serialize(&corrupted).expect("serialize corrupted metadata");
        meta_tree
            .insert(META_BEST_KEY, encoded.clone())
            .expect("corrupt best body");
        block_tree
            .insert(corrupted.hash.as_slice(), encoded)
            .expect("corrupt block body");
        db.flush().expect("flush body corruption");
    }

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("startup must reject exact-decodable action-byte drift"),
        Err(err) => err,
    };
    let err = format!("{err:?}");
    assert!(err.contains("native replay action root"), "{err}");
    assert!(err.contains("extrinsics_root_mismatch"), "{err}");
}

#[test]
fn startup_rejects_committed_sidecar_archive_hash_drift() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    {
        let node = NativeNode::open(config.clone()).expect("node");
        let parent = node.best_meta();
        let action = test_sidecar_transfer_action(parent.state_root, [69u8; 48], [70u8; 48], 0);
        insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
        let replay_state = test_state(parent.clone());
        let candidate = test_candidate_artifact_action(1, 72);
        let actions = vec![action.clone(), candidate];
        let meta = mined_child_with_actions(&parent, 1, pow_bits, 0, actions.clone());
        let planned =
            plan_materialized_action_effects(&node.da_ciphertext_tree, &replay_state, &actions)
                .expect("plan sidecar commit");
        node.commit_mined_block_atomically(&actions, &planned, &meta)
            .expect("commit sidecar action");
        node.db.flush().expect("flush sidecar commit");
    }

    {
        let db = sled::open(&config.db_path).expect("open test db for archive corruption");
        let ciphertext_archive_tree = db
            .open_tree("shielded_ciphertexts_by_index")
            .expect("ciphertext archive tree");
        let mut corrupted = test_transfer_ciphertext_bytes();
        corrupted[0] ^= 1;
        ciphertext_archive_tree
            .insert(0u64.to_be_bytes(), corrupted)
            .expect("corrupt canonical archive");
        db.flush().expect("flush archive corruption");
    }

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("startup must reject committed sidecar archive hash drift"),
        Err(err) => err,
    };
    let err = format!("{err:?}");
    assert!(
        err.contains("canonical DA ciphertext hash mismatch"),
        "{err}"
    );
}

#[test]
fn wallet_archive_rpcs_are_paginated_and_wallet_compatible() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "safe", false)).expect("node");

    stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [21u8; 48]);
    let work = node.prepare_work().expect("prepare native work");
    let seal = mine_native_round(work.clone(), 0).expect("first seal");
    node.import_mined_block(&work, seal)
        .expect("first import")
        .expect("first block");

    stage_test_coinbase(&node, consensus::reward::block_subsidy(2), [22u8; 48]);
    let work = node.prepare_work().expect("prepare native work");
    let seal = mine_native_round(work.clone(), 0).expect("second seal");
    node.import_mined_block(&work, seal)
        .expect("second import")
        .expect("second block");

    {
        let mut state = node.state.write();
        state.nullifiers.insert([31u8; 48]);
        state.nullifiers.insert([32u8; 48]);
    }

    let commitments = node
        .wallet_commitments(json!({"start": 0, "limit": 1}))
        .expect("commitments page");
    assert_eq!(commitments["total"], json!(2));
    assert_eq!(commitments["has_more"], json!(true));
    let commitment_entry = commitments["entries"][0].as_object().expect("entry object");
    assert!(commitment_entry.contains_key("value"));
    assert!(commitment_entry.contains_key("commitment"));
    assert_eq!(commitment_entry["source"], json!("mining_reward"));

    let ciphertexts = node
        .wallet_ciphertexts(json!({"start": 0, "limit": 1}))
        .expect("ciphertexts page");
    assert_eq!(ciphertexts["total"], json!(2));
    assert_eq!(ciphertexts["has_more"], json!(true));
    let ciphertext = ciphertexts["entries"][0]["ciphertext"]
        .as_str()
        .expect("ciphertext string");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .expect("base64 ciphertext");
    assert_eq!(
        decoded.len(),
        protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE + 32
    );
    assert_eq!(node.ciphertext_archive_tree.len(), 2);
    let best_hash = node.best_meta().hash;
    node.block_tree
        .remove(best_hash.as_slice())
        .expect("remove block record");
    let archived_ciphertexts = node
        .wallet_ciphertexts(json!({"start": 1, "limit": 1}))
        .expect("ciphertexts from archive");
    assert_eq!(archived_ciphertexts["total"], json!(2));
    assert_eq!(
        archived_ciphertexts["entries"]
            .as_array()
            .expect("archive entries")
            .len(),
        1
    );

    let nullifiers = node
        .wallet_nullifiers(json!({"start": 1, "limit": 1}))
        .expect("nullifier page");
    assert_eq!(nullifiers["total"], json!(2));
    assert_eq!(nullifiers["has_more"], json!(false));
    assert_eq!(nullifiers["nullifiers"].as_array().expect("array").len(), 1);

    let footprint = node.storage_footprint();
    assert_eq!(footprint["exact_bytes_available"], json!(false));
    assert_eq!(footprint["total_bytes"], Value::Null);
    assert!(footprint["blocks_entries"].as_u64().is_some());
}

#[test]
fn wallet_commitments_ignore_unrequested_malformed_commitment_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    node.commitment_tree
        .insert(b"bad-key", [1u8; 48].as_slice())
        .expect("insert malformed commitment key");

    let commitments = node
        .wallet_commitments(json!({"start": 0, "limit": 1024}))
        .expect("unrequested malformed key must not force a full archive scan");
    assert_eq!(commitments["total"], json!(0));
    assert_eq!(commitments["entries"], json!([]));
}

#[test]
fn wallet_commitments_rejects_malformed_commitment_value() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    seed_native_commitment_leaf_count(&node, 1);
    node.commitment_tree
        .insert(0u64.to_be_bytes(), vec![2u8; 47])
        .expect("insert malformed commitment value");

    let err = node
        .wallet_commitments(json!({"start": 0, "limit": 1024}))
        .expect_err("malformed commitment value must reject wallet RPC");
    assert!(err
        .to_string()
        .contains("native commitment archive value has invalid length"));
}

#[test]
fn wallet_commitments_rejects_commitment_index_gap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    seed_native_commitment_leaf_count(&node, 2);
    node.commitment_tree
        .insert(1u64.to_be_bytes(), [3u8; 48].as_slice())
        .expect("insert gapped commitment value");

    let err = node
        .wallet_commitments(json!({"start": 0, "limit": 1024}))
        .expect_err("commitment index gap must reject wallet RPC");
    assert!(err.to_string().contains("missing 0"));
}

fn seed_native_commitment_leaf_count(node: &NativeNode, leaf_count: u64) {
    let mut state = node.state.write();
    for index in 0..leaf_count {
        state
            .commitment_tree
            .append([index as u8; 48])
            .expect("append test commitment leaf");
    }
}

fn insert_test_ciphertext_archive_indices(node: &NativeNode, indices: &[u64]) {
    for index in indices {
        node.ciphertext_archive_tree
            .insert(
                index.to_be_bytes(),
                vec![*index as u8; MIN_NATIVE_WALLET_CIPHERTEXT_BYTES],
            )
            .expect("insert test ciphertext archive row");
    }
}

#[derive(Debug, Deserialize)]
struct LeanCiphertextArchiveBoundaryVectorFile {
    schema_version: u32,
    ciphertext_archive_boundary_cases: Vec<LeanCiphertextArchiveBoundaryCase>,
    wallet_page_admission_cases: Vec<LeanCiphertextArchiveWalletPageAdmissionCase>,
    wallet_sync_snapshot_admission_cases: Vec<LeanWalletSyncSnapshotAdmissionCase>,
}

#[derive(Debug, Deserialize)]
struct LeanCiphertextArchiveBoundaryCase {
    name: String,
    leaf_count: u64,
    archive_indices: Vec<u64>,
    expected_valid: bool,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LeanCiphertextArchiveWalletPageAdmissionCase {
    name: String,
    requested_limit: u64,
    returned_entries: u64,
    expected_valid: bool,
    expected_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LeanWalletSyncSnapshotAdmissionCase {
    name: String,
    expected_depth: u64,
    depth: u64,
    leaf_count: u64,
    next_index: u64,
    commitment_cursor: u64,
    ciphertext_cursor: u64,
    tree_capacity: u128,
    max_snapshot_gap: u64,
    expected_valid: bool,
    expected_error: Option<String>,
}

#[test]
fn lean_generated_ciphertext_archive_boundary_vectors_match_native_rpc() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_CIPHERTEXT_ARCHIVE_BOUNDARY_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean ciphertext archive vectors");
    let vectors: LeanCiphertextArchiveBoundaryVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean ciphertext archive vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        vectors.ciphertext_archive_boundary_cases.len() >= 6,
        "expected archive gap and leaf-count boundary coverage"
    );
    assert!(
        vectors.wallet_page_admission_cases.len() >= 5,
        "expected wallet page admission boundary coverage"
    );
    assert!(
        vectors.wallet_sync_snapshot_admission_cases.len() >= 7,
        "expected wallet sync snapshot admission boundary coverage"
    );
    for case in &vectors.wallet_page_admission_cases {
        let expected_valid = case.returned_entries <= case.requested_limit;
        assert_eq!(
            expected_valid, case.expected_valid,
            "Lean wallet page case {} validity should bind response length to request limit",
            case.name
        );
        assert_eq!(
            case.expected_error.as_deref(),
            if expected_valid {
                None
            } else {
                Some("page_too_large")
            },
            "Lean wallet page case {} rejection drifted",
            case.name
        );
    }

    for case in &vectors.wallet_sync_snapshot_admission_cases {
        let actual_error = if case.depth != case.expected_depth {
            Some("depth_mismatch")
        } else if case.tree_capacity < u128::from(case.leaf_count) {
            Some("leaf_count_exceeds_tree_capacity")
        } else if case.tree_capacity < u128::from(case.next_index) {
            Some("ciphertext_index_exceeds_tree_capacity")
        } else if case.max_snapshot_gap < case.leaf_count.saturating_sub(case.commitment_cursor) {
            Some("commitment_snapshot_too_large")
        } else if case.max_snapshot_gap < case.next_index.saturating_sub(case.ciphertext_cursor) {
            Some("ciphertext_snapshot_too_large")
        } else {
            None
        };
        assert_eq!(
            actual_error.is_none(),
            case.expected_valid,
            "Lean wallet sync snapshot case {} validity drifted",
            case.name
        );
        assert_eq!(
            actual_error,
            case.expected_error.as_deref(),
            "Lean wallet sync snapshot case {} rejection drifted",
            case.name
        );
    }

    for case in &vectors.ciphertext_archive_boundary_cases {
        let tmp = tempfile::tempdir().expect("tempdir");
        let node =
            NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
        seed_native_commitment_leaf_count(&node, case.leaf_count);
        insert_test_ciphertext_archive_indices(&node, &case.archive_indices);

        let page_limit = u64::try_from(case.archive_indices.len())
            .unwrap_or(u64::MAX)
            .max(1);
        let result = node.wallet_ciphertexts(json!({"start": 0, "limit": page_limit}));
        if case.expected_valid {
            let response = result.unwrap_or_else(|err| {
                panic!(
                    "Lean ciphertext archive boundary case {} rejected: {err}",
                    case.name
                )
            });
            assert_eq!(
                response["total"],
                json!(case.leaf_count),
                "native ciphertext archive total drifted from Lean case {}",
                case.name
            );
        } else {
            let err = match result {
                Ok(_) => panic!(
                    "Lean ciphertext archive boundary case {} expected rejection",
                    case.name
                ),
                Err(err) => err,
            };
            let err = err.to_string();
            match case.expected_error.as_deref() {
                Some("index_gap") => {
                    assert!(err.contains("native ciphertext archive index gap"), "{err}")
                }
                Some("index_beyond_leaf_count") => {
                    assert!(err.contains("exceeds commitment leaf_count"), "{err}")
                }
                other => panic!(
                    "unexpected Lean expected_error for {}: {other:?}",
                    case.name
                ),
            }
        }
    }
}

#[test]
fn wallet_ciphertexts_ignore_unrequested_malformed_archive_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    node.ciphertext_archive_tree
        .insert(b"bad-key", vec![4u8; MIN_NATIVE_WALLET_CIPHERTEXT_BYTES])
        .expect("insert malformed ciphertext key");

    let ciphertexts = node
        .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
        .expect("unrequested malformed key must not force a full archive scan");
    assert_eq!(ciphertexts["total"], json!(0));
    assert_eq!(ciphertexts["entries"], json!([]));
}

#[test]
fn wallet_ciphertexts_rejects_malformed_archive_value() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    seed_native_commitment_leaf_count(&node, 1);
    node.ciphertext_archive_tree
        .insert(
            0u64.to_be_bytes(),
            vec![5u8; MIN_NATIVE_WALLET_CIPHERTEXT_BYTES - 1],
        )
        .expect("insert short ciphertext value");

    let short_err = node
        .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
        .expect_err("short ciphertext value must reject wallet RPC");
    assert!(short_err
        .to_string()
        .contains("native ciphertext archive value is too short"));

    node.ciphertext_archive_tree
        .insert(0u64.to_be_bytes(), vec![6u8; MAX_CIPHERTEXT_BYTES + 1])
        .expect("insert oversized ciphertext value");
    let oversize_err = node
        .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
        .expect_err("oversized ciphertext value must reject wallet RPC");
    assert!(oversize_err
        .to_string()
        .contains("native ciphertext archive value exceeds max"));
}

#[test]
fn wallet_ciphertexts_rejects_archive_index_gap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    seed_native_commitment_leaf_count(&node, 2);
    insert_test_ciphertext_archive_indices(&node, &[1]);

    let err = node
        .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
        .expect_err("gapped ciphertext archive must reject wallet RPC");
    assert!(err
        .to_string()
        .contains("native ciphertext archive index gap"));
}

#[test]
fn wallet_ciphertexts_ignore_unrequested_archive_index_beyond_leaf_count() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    seed_native_commitment_leaf_count(&node, 1);
    insert_test_ciphertext_archive_indices(&node, &[0, 1]);

    let ciphertexts = node
        .wallet_ciphertexts(json!({"start": 0, "limit": 1024}))
        .expect("unrequested extra ciphertext row must not force a full archive scan");
    assert_eq!(ciphertexts["total"], json!(1));
    assert_eq!(ciphertexts["entries"].as_array().expect("entries").len(), 1);
}

#[test]
fn empty_block_does_not_advance_supply_digest() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");

    let work = node.prepare_work().expect("prepare native work");
    let seal = mine_native_round(work.clone(), 0).expect("empty seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("empty import")
        .expect("empty block");

    assert_eq!(imported.supply_digest, 0);
    assert_eq!(node.best_meta().supply_digest, 0);
}

#[test]
fn mined_block_rejects_supply_digest_template_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");

    let mut work = node.prepare_work().expect("prepare native work");
    work.supply_digest = work.supply_digest.saturating_add(1);
    let seal = mine_native_round(work.clone(), 0).expect("mismatched supply seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("supply mismatch should fail as stale work");

    assert!(imported.is_none());
    assert_eq!(node.best_meta().height, 0);
    assert_eq!(node.best_meta().supply_digest, 0);
}

#[test]
fn prepare_work_drops_actions_after_supply_digest_overflow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");

    let subsidy = consensus::reward::block_subsidy(1);
    let mut parent = node.best_meta();
    parent.supply_digest = u128::MAX - u128::from(subsidy) + 1;
    {
        let mut state = node.state.write();
        state.best = parent.clone();
    }
    stage_test_coinbase(&node, subsidy, [55u8; 48]);

    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(work.tx_count, 0);
    assert_eq!(work.state_root, parent.state_root);
    assert_eq!(work.nullifier_root, parent.nullifier_root);
    assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
    assert_eq!(work.message_count, 0);
    assert_eq!(work.message_root, empty_bridge_message_root());
    assert_eq!(work.supply_digest, parent.supply_digest);

    let expected_kernel_root = consensus::types::kernel_root_from_shielded_root(&parent.state_root);
    let expected_pre_header = native_pow_header_from_parts(
        work.height,
        work.timestamp_ms,
        parent.hash,
        test_pow_bits,
        [0u8; 32],
        work.cumulative_work,
        &parent.state_root,
        &expected_kernel_root,
        &parent.nullifier_root,
        &actions_extrinsics_root(&[]),
        &empty_bridge_message_root(),
        0,
        &work.header_mmr_root,
        work.header_mmr_len,
        parent.supply_digest,
        0,
    );
    assert_eq!(work.pre_hash, expected_pre_header.pre_hash());
}

#[test]
fn prepare_work_rejects_missing_header_mmr_history() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");
    let best = node.best_meta();
    node.block_tree
        .remove(best.hash)
        .expect("remove best block record");
    node.block_tree.flush().expect("flush block tree");

    let err = node
        .prepare_work()
        .expect_err("missing header-MMR history must reject work template");

    assert!(err.to_string().contains("missing native block"));
    assert_eq!(node.best_meta().height, best.height);
    assert_eq!(node.best_meta().hash, best.hash);
}

#[test]
fn mined_invalid_pow_does_not_mutate_pending_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let test_pow_bits = 0x207f_ffff;
    let node =
        NativeNode::open(test_config(tmp.path(), test_pow_bits, "unsafe", false)).expect("node");

    let reward = consensus::reward::block_subsidy(1);
    stage_test_coinbase(&node, reward, [42u8; 48]);

    let work = node.prepare_work().expect("prepare native work");
    let mut invalid_seal = mine_native_round(work.clone(), 0).expect("valid seal");
    invalid_seal.work_hash[0] ^= 0x80;

    let err = node
        .import_mined_block(&work, invalid_seal)
        .expect_err("invalid mined PoW must reject before mutation");
    assert!(err.to_string().contains("native"));

    let state = node.state.read();
    assert_eq!(state.best.height, 0);
    assert_eq!(state.best.supply_digest, 0);
    assert_eq!(state.pending_actions.len(), 1);
    assert_eq!(state.commitment_tree.leaf_count(), 0);
}

#[test]
fn native_mined_block_carries_valid_miner_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");

    let imported = mine_empty_native_block(&node);

    assert_eq!(imported.miner_public_key.len(), ML_DSA_PUBLIC_KEY_LEN);
    assert_eq!(imported.miner_signature.len(), ML_DSA_SIGNATURE_LEN);
    assert_eq!(
        imported.miner_commitment,
        native_miner_commitment(&imported.miner_public_key)
    );
    verify_native_miner_identity(&imported).expect("mined block signature verifies");
}

#[test]
fn native_pow_schedule_retargets_fast_window_and_rejects_stale_bits() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let mut chain = vec![node.best_meta()];
    let genesis_timestamp = chain[0].timestamp_ms;

    for height in 1..consensus::reward::RETARGET_WINDOW {
        let parent = chain.last().expect("parent").clone();
        let timestamp_ms = genesis_timestamp + height * 1_000;
        let child = mined_empty_child_at(&parent, height, pow_bits, height, timestamp_ms);
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist deterministic fast child");
        chain.push(child);
    }
    node.state.write().best = chain.last().expect("fast parent").clone();

    let first_boundary_bits =
        native_expected_child_pow_bits_from_chain(&chain, pow_bits).expect("scheduled bits");
    assert_eq!(
        first_boundary_bits, pow_bits,
        "the first retarget boundary must not use genesis as a stale timing anchor"
    );

    for height in consensus::reward::RETARGET_WINDOW..(consensus::reward::RETARGET_WINDOW * 2) {
        let parent = chain.last().expect("parent").clone();
        let timestamp_ms = parent.timestamp_ms.saturating_add(1_000);
        let child = mined_empty_child_at(&parent, height, pow_bits, height, timestamp_ms);
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist deterministic fast child");
        chain.push(child);
    }
    node.state.write().best = chain.last().expect("fast parent").clone();

    let expected_bits =
        native_expected_child_pow_bits_from_chain(&chain, pow_bits).expect("scheduled bits");
    let expected_target = consensus_light_client::compact_to_target(expected_bits)
        .expect("scheduled compact target decodes");
    let stale_target =
        consensus_light_client::compact_to_target(pow_bits).expect("stale compact target decodes");
    assert!(
        expected_target < stale_target,
        "a fast retarget window must lower the target instead of easing difficulty"
    );

    let work = node.prepare_work().expect("prepare retargeted work");
    assert_eq!(work.height, consensus::reward::RETARGET_WINDOW * 2);
    assert_eq!(work.pow_bits, expected_bits);

    let parent = chain.last().expect("fast parent");
    let stale = mined_empty_child_at(
        parent,
        consensus::reward::RETARGET_WINDOW * 2,
        pow_bits,
        consensus::reward::RETARGET_WINDOW * 2,
        parent.timestamp_ms.saturating_add(1_000),
    );
    let err = validate_announced_block(parent, &stale, expected_bits)
        .expect_err("stale fixed-difficulty child must reject at retarget");
    assert!(err.to_string().contains("PoW bits mismatch"), "{err:?}");
}

#[test]
fn native_pow_schedule_recovers_after_slow_window_at_bounded_factor() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let mut chain = vec![node.best_meta()];
    let genesis_timestamp = chain[0].timestamp_ms;

    for height in 1..consensus::reward::RETARGET_WINDOW {
        let parent = chain.last().expect("parent").clone();
        let timestamp_ms = genesis_timestamp + height * 1_000;
        let child = mined_empty_child_at(&parent, height, pow_bits, height, timestamp_ms);
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist deterministic bootstrap child");
        chain.push(child);
    }

    for height in consensus::reward::RETARGET_WINDOW..(consensus::reward::RETARGET_WINDOW * 2) {
        let parent = chain.last().expect("parent").clone();
        let timestamp_ms = parent.timestamp_ms.saturating_add(1_000);
        let child = mined_empty_child_at(&parent, height, pow_bits, height, timestamp_ms);
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist deterministic fast child");
        chain.push(child);
    }

    let tightened_bits =
        native_expected_child_pow_bits_from_chain(&chain, pow_bits).expect("scheduled bits");
    let initial_target = consensus_light_client::compact_to_target(pow_bits)
        .expect("initial compact target decodes");
    let tightened_target = consensus_light_client::compact_to_target(tightened_bits)
        .expect("tightened compact target decodes");
    assert!(
        tightened_target < initial_target,
        "fast window must tighten before the recovery window"
    );

    let slow_delta_ms =
        consensus::reward::TARGET_BLOCK_INTERVAL_MS * consensus::reward::MAX_ADJUSTMENT_FACTOR * 2;
    for height in (consensus::reward::RETARGET_WINDOW * 2)..(consensus::reward::RETARGET_WINDOW * 3)
    {
        let parent = chain.last().expect("parent").clone();
        let timestamp_ms = parent.timestamp_ms.saturating_add(slow_delta_ms);
        let child = mined_empty_child_at(
            &parent,
            height,
            tightened_bits,
            height.saturating_add(100),
            timestamp_ms,
        );
        persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
            .expect("persist deterministic slow child");
        chain.push(child);
    }
    node.state.write().best = chain.last().expect("slow parent").clone();

    let loosened_bits =
        native_expected_child_pow_bits_from_chain(&chain, pow_bits).expect("scheduled bits");
    let loosened_target = consensus_light_client::compact_to_target(loosened_bits)
        .expect("loosened compact target decodes");
    assert!(
        loosened_target > tightened_target,
        "a slow retarget window must ease difficulty instead of staying pinned"
    );
    assert!(
        loosened_target <= initial_target,
        "recovery must remain bounded by the maximum retarget factor"
    );

    let work = node.prepare_work().expect("prepare recovered work");
    assert_eq!(work.height, consensus::reward::RETARGET_WINDOW * 3);
    assert_eq!(work.pow_bits, loosened_bits);

    let parent = chain.last().expect("slow parent");
    let stale = mined_empty_child_at(
        parent,
        consensus::reward::RETARGET_WINDOW * 3,
        tightened_bits,
        consensus::reward::RETARGET_WINDOW * 3,
        parent.timestamp_ms.saturating_add(slow_delta_ms),
    );
    let err = validate_announced_block(parent, &stale, loosened_bits)
        .expect_err("stale tightened child must reject after slow retarget recovery");
    assert!(err.to_string().contains("PoW bits mismatch"), "{err:?}");
}

#[test]
fn native_miner_identity_rejects_unsigned_non_genesis() {
    let pow_bits = 0x207f_ffff;
    let parent = genesis_meta(pow_bits).expect("genesis");
    let mut block = mined_empty_child(&parent, 1, pow_bits, 0);
    block.miner_public_key.clear();
    block.miner_signature.clear();
    block.miner_commitment = [0u8; 48];

    let err = validate_announced_block(&parent, &block, pow_bits)
        .expect_err("unsigned non-genesis announced block must reject");
    assert!(
        err.to_string().contains("invalid_miner_public_key_length"),
        "{err:?}"
    );
    assert!(verify_native_miner_identity(&parent).is_ok());
}

#[test]
fn native_miner_identity_binds_commitment_nonce_and_work_hash() {
    let pow_bits = 0x207f_ffff;
    let parent = genesis_meta(pow_bits).expect("genesis");
    let block = mined_empty_child(&parent, 1, pow_bits, 0);

    let mut bad_commitment = block.clone();
    bad_commitment.miner_commitment[0] ^= 1;
    let err = validate_announced_block(&parent, &bad_commitment, pow_bits)
        .expect_err("miner commitment mismatch must reject");
    assert!(err.to_string().contains("miner_commitment_mismatch"));

    let mut bad_nonce = block.clone();
    bad_nonce.nonce[0] ^= 1;
    let err = validate_announced_block(&parent, &bad_nonce, pow_bits)
        .expect_err("nonce tamper must invalidate miner signature before PoW");
    assert!(err
        .to_string()
        .contains("native_miner_signature_verification_failed"));

    let mut bad_work_hash = block.clone();
    bad_work_hash.work_hash[0] ^= 1;
    bad_work_hash.hash = bad_work_hash.work_hash;
    let err = validate_announced_block(&parent, &bad_work_hash, pow_bits)
        .expect_err("work-hash tamper must invalidate miner signature before PoW");
    assert!(err
        .to_string()
        .contains("native_miner_signature_verification_failed"));
}

#[test]
fn native_miner_identity_rejects_wrong_public_key() {
    let pow_bits = 0x207f_ffff;
    let parent = genesis_meta(pow_bits).expect("genesis");
    let mut block = mined_empty_child(&parent, 1, pow_bits, 0);
    let other = NativeMinerIdentity::from_seed(b"other native miner identity");
    block.miner_public_key = other.public_key.to_bytes();
    block.miner_commitment = native_miner_commitment(&block.miner_public_key);

    let err = validate_announced_block(&parent, &block, pow_bits)
        .expect_err("wrong public key must fail signature verification");
    assert!(err
        .to_string()
        .contains("native_miner_signature_verification_failed"));
}

#[test]
fn legacy_native_block_metadata_decodes_without_miner_identity() {
    let current = mined_empty_child(
        &genesis_meta(0x207f_ffff).expect("genesis"),
        1,
        0x207f_ffff,
        0,
    );
    let legacy = legacy_meta_from_current(&current);
    let encoded = bincode::serialize(&legacy).expect("serialize legacy native metadata");
    let decoded = bincode_deserialize_native_block_meta_exact(&encoded, "legacy native metadata")
        .expect("decode legacy native metadata");

    assert_eq!(decoded.height, current.height);
    assert_eq!(decoded.hash, current.hash);
    assert!(decoded.miner_public_key.is_empty());
    assert!(decoded.miner_signature.is_empty());
    assert_eq!(decoded.miner_commitment, [0u8; 48]);
}

#[test]
fn native_metadata_projection_rejects_legacy_unsigned_startup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    {
        let node =
            NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
        let imported = mine_empty_native_block(&node);
        assert_eq!(imported.height, 1);
        let legacy = legacy_meta_from_current(&imported);
        let encoded = bincode::serialize(&legacy).expect("serialize legacy metadata");
        node.block_tree
            .insert(imported.hash.as_slice(), encoded.clone())
            .expect("replace block row with legacy metadata");
        node.meta_tree
            .insert(META_BEST_KEY, encoded)
            .expect("replace best row with legacy metadata");
        node.block_tree.flush().expect("flush block tree");
        node.meta_tree.flush().expect("flush meta tree");
    }

    let err = match NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)) {
        Ok(_) => panic!("legacy unsigned non-genesis metadata must fail startup"),
        Err(err) => err,
    };
    let err = format!("{err:?}");
    assert!(err.contains("invalid_miner_public_key_length"), "{err}");
}

#[test]
fn native_metadata_projection_rejects_unsigned_sync_range() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let imported = mine_empty_native_block(&node);
    let unsigned = unsigned_native_meta(imported.clone());
    persist_block_record(&node.block_tree, &unsigned).expect("replace signed block row");

    let err = node
        .block_range(imported.height, imported.height)
        .expect_err("unsigned canonical metadata must not be served over sync");
    let err = format!("{err:?}");
    assert!(err.contains("invalid_miner_public_key_length"), "{err}");
}

#[test]
fn announced_block_rejects_future_timestamp_skew() {
    let pow_bits = 0x207f_ffff;
    let parent = genesis_meta(pow_bits).expect("genesis");
    let timestamp_ms =
        current_time_ms().saturating_add(consensus::reward::MAX_FUTURE_SKEW_MS + 10_000);
    let future = mined_empty_child_at(&parent, 1, pow_bits, 0, timestamp_ms);

    let err = validate_announced_block(&parent, &future, pow_bits)
        .expect_err("future-dated block should be rejected");
    assert!(err.to_string().contains("future skew"));
}

#[test]
fn announced_block_rejects_height_overflow() {
    let pow_bits = 0x207f_ffff;
    let mut parent = genesis_meta(pow_bits).expect("genesis");
    parent.height = u64::MAX;
    parent.timestamp_ms = 1000;
    parent.hash = [3u8; 32];
    let mut announced = parent.clone();
    announced.parent_hash = parent.hash;
    announced.timestamp_ms = parent.timestamp_ms + 1;
    announced.hash = [4u8; 32];
    announced.work_hash = announced.hash;

    let err = validate_announced_block(&parent, &announced, pow_bits)
        .expect_err("height overflow must fail closed");
    assert!(err.to_string().contains("height_not_next"));
}

#[test]
fn mined_work_rejects_height_overflow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let mut best = node.best_meta();
    best.height = u64::MAX;
    best.hash = [9u8; 32];
    best.timestamp_ms = 1000;
    {
        let mut state = node.state.write();
        state.best = best.clone();
    }
    let work = NativeWork {
        height: u64::MAX,
        parent_hash: best.hash,
        pre_hash: [0u8; 32],
        state_root: best.state_root,
        kernel_root: best.kernel_root,
        nullifier_root: best.nullifier_root,
        extrinsics_root: actions_extrinsics_root(&[]),
        message_root: empty_bridge_message_root(),
        message_count: 0,
        header_mmr_root: [0u8; 32],
        header_mmr_len: 0,
        cumulative_work: best.cumulative_work,
        supply_digest: best.supply_digest,
        tx_count: 0,
        timestamp_ms: best.timestamp_ms.saturating_add(1),
        pow_bits,
        prepared_actions: None,
    };
    let imported = node
        .import_mined_block(
            &work,
            NativeSeal {
                nonce: [0u8; 32],
                work_hash: [0u8; 32],
            },
        )
        .expect("overflow work admission should fail closed");
    assert!(imported.is_none());
    assert_eq!(node.best_meta().height, u64::MAX);
}

#[test]
fn prepare_work_rejects_height_overflow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    {
        let mut state = node.state.write();
        state.best.height = u64::MAX;
    }

    let err = node
        .prepare_work()
        .expect_err("max-height tip must not produce a native work template");
    assert!(err.to_string().contains("height_not_next"));
}

#[test]
fn prepare_work_rejects_cumulative_work_overflow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    {
        let mut state = node.state.write();
        state.best.cumulative_work = [0xff; 48];
    }

    let err = node
        .prepare_work()
        .expect_err("work48 overflow must not produce a native work template");
    assert!(err.to_string().contains("cumulative_work_overflow"));
}

#[test]
fn announced_block_rejects_counterfeit_body_commitments() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let parent = node.best_meta();
    let cases = [
        (TestCommitmentMutation::StateRoot, "state_root_mismatch"),
        (TestCommitmentMutation::KernelRoot, "kernel_root_mismatch"),
        (
            TestCommitmentMutation::NullifierRoot,
            "nullifier_root_mismatch",
        ),
        (
            TestCommitmentMutation::ExtrinsicsRoot,
            "extrinsics_root_mismatch",
        ),
        (TestCommitmentMutation::MessageRoot, "message_root_mismatch"),
        (
            TestCommitmentMutation::MessageCount,
            "message_count_mismatch",
        ),
        (
            TestCommitmentMutation::SupplyDigest,
            "supply_digest_mismatch",
        ),
    ];

    for (idx, (mutation, expected)) in cases.into_iter().enumerate() {
        let block =
            mined_empty_child_with_commitment_mutation(&parent, pow_bits, idx as u64, mutation);
        let err = node
            .import_announced_block(block)
            .expect_err("counterfeit body commitment should be rejected");
        assert!(
            err.to_string().contains(expected),
            "{mutation:?} should reject with {expected}, got {err}"
        );
    }
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn announced_block_replay_commitment_mismatch_precedes_payload_validation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let parent = node.best_meta();
    let height = parent.height.saturating_add(1);
    let mut coinbase = test_coinbase_action(consensus::reward::block_subsidy(height));
    tamper_coinbase_public_seed_without_rebinding(&mut coinbase);
    let mut block = mined_child_with_actions(&parent, height, pow_bits, 0, vec![coinbase]);
    block.state_root[0] ^= 1;
    let pre_header = native_pow_header_from_parts(
        block.height,
        block.timestamp_ms,
        block.parent_hash,
        block.pow_bits,
        [0u8; 32],
        block.cumulative_work,
        &block.state_root,
        &block.kernel_root,
        &block.nullifier_root,
        &block.extrinsics_root,
        &block.message_root,
        block.message_count,
        &block.header_mmr_root,
        block.header_mmr_len,
        block.supply_digest,
        block.tx_count,
    );
    let work = NativeWork {
        height: block.height,
        parent_hash: block.parent_hash,
        pre_hash: pre_header.pre_hash(),
        state_root: block.state_root,
        kernel_root: block.kernel_root,
        nullifier_root: block.nullifier_root,
        extrinsics_root: block.extrinsics_root,
        message_root: block.message_root,
        message_count: block.message_count,
        header_mmr_root: block.header_mmr_root,
        header_mmr_len: block.header_mmr_len,
        cumulative_work: block.cumulative_work,
        supply_digest: block.supply_digest,
        tx_count: block.tx_count,
        timestamp_ms: block.timestamp_ms,
        pow_bits: block.pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work, 1).expect("reseal mutated announced block");
    block.hash = seal.work_hash;
    block.work_hash = seal.work_hash;
    block.nonce = seal.nonce;
    sign_test_block_meta(&mut block);

    let err = node
        .import_announced_block(block)
        .expect_err("counterfeit commitment must reject before payload validation");

    assert!(
        err.to_string().contains("state_root_mismatch"),
        "state-root replay mismatch should not be masked by payload validation: {err}"
    );
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn announced_block_action_root_mismatch_precedes_payload_materialization() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let parent = node.best_meta();
    let height = parent.height.saturating_add(1);
    let mut coinbase = test_coinbase_action(consensus::reward::block_subsidy(height));
    tamper_coinbase_public_seed_without_rebinding(&mut coinbase);
    let mut block = mined_child_with_actions(&parent, height, pow_bits, 0, vec![coinbase]);
    block.extrinsics_root[0] ^= 1;
    let pre_header = native_pow_header_from_parts(
        block.height,
        block.timestamp_ms,
        block.parent_hash,
        block.pow_bits,
        [0u8; 32],
        block.cumulative_work,
        &block.state_root,
        &block.kernel_root,
        &block.nullifier_root,
        &block.extrinsics_root,
        &block.message_root,
        block.message_count,
        &block.header_mmr_root,
        block.header_mmr_len,
        block.supply_digest,
        block.tx_count,
    );
    let work = NativeWork {
        height: block.height,
        parent_hash: block.parent_hash,
        pre_hash: pre_header.pre_hash(),
        state_root: block.state_root,
        kernel_root: block.kernel_root,
        nullifier_root: block.nullifier_root,
        extrinsics_root: block.extrinsics_root,
        message_root: block.message_root,
        message_count: block.message_count,
        header_mmr_root: block.header_mmr_root,
        header_mmr_len: block.header_mmr_len,
        cumulative_work: block.cumulative_work,
        supply_digest: block.supply_digest,
        tx_count: block.tx_count,
        timestamp_ms: block.timestamp_ms,
        pow_bits: block.pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work, 2).expect("reseal action-root mutation");
    block.hash = seal.work_hash;
    block.work_hash = seal.work_hash;
    block.nonce = seal.nonce;
    sign_test_block_meta(&mut block);

    let err = node
        .import_announced_block(block)
        .expect_err("action-root mismatch must reject before payload validation");

    assert!(
        err.to_string().contains("extrinsics_root_mismatch"),
        "action-root mismatch should not be masked by payload validation: {err}"
    );
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn announced_block_rejects_exact_decodable_action_byte_drift_before_persist_or_publish() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let parent = node.best_meta();
    let height = parent.height.saturating_add(1);
    let original = test_outbound_bridge_action(b"announced action-byte original");
    let substitute = test_outbound_bridge_action(b"announced action-byte substitute");
    let mut block = mined_child_with_actions(&parent, height, pow_bits, 0, vec![original]);
    replace_single_action_body_with_exact_decodable_substitute(&mut block, &substitute);

    let err = node
        .import_announced_block(block.clone())
        .expect_err("announced block must reject exact-decodable action-byte drift");
    let err = format!("{err:?}");
    assert!(err.contains("announced block action root"), "{err}");
    assert!(err.contains("extrinsics_root_mismatch"), "{err}");
    assert_eq!(node.best_meta().hash, parent.hash);
    assert_eq!(
        node.hash_by_height(height)
            .expect("height index after rejected announced block"),
        None,
        "failed announced action-root verification must not write a height index"
    );
    assert!(
        node.header_by_hash(&block.hash)
            .expect("block lookup after rejected announced block")
            .is_none(),
        "failed announced action-root verification must not persist the block"
    );
}

#[test]
fn replay_rejects_counterfeit_message_commitment() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let parent = node.best_meta();
    let block = mined_empty_child_with_commitment_mutation(
        &parent,
        pow_bits,
        0,
        TestCommitmentMutation::MessageCount,
    );
    persist_block_record(&node.block_tree, &block).expect("persist counterfeit block");

    let err = node
        .replay_state_to_hash(block.hash)
        .expect_err("replay must reject counterfeit message commitment");
    assert!(err.to_string().contains("message_count_mismatch"));
}

#[test]
fn rpc_policy_gates_unsafe_methods() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let safe_node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("safe node");
    let err = dispatch_rpc_method(
        &safe_node,
        "da_submitCiphertexts",
        json!({"ciphertexts": []}),
    )
    .expect_err("safe RPC should reject DA staging");
    assert!(err.to_string().contains("unsafe RPC method"));
    let err = dispatch_rpc_method(&safe_node, "hegemon_submitAction", json!({}))
        .expect_err("safe RPC should reject action staging");
    assert!(err.to_string().contains("unsafe RPC method"));
    let err = dispatch_rpc_method(&safe_node, "hegemon_peerGraph", Value::Array(Vec::new()))
        .expect_err("safe RPC should reject peer topology");
    assert!(err.to_string().contains("unsafe RPC method"));
    let err = dispatch_rpc_method(&safe_node, "system_peers", Value::Array(Vec::new()))
        .expect_err("safe RPC should reject peer topology");
    assert!(err.to_string().contains("unsafe RPC method"));
    assert_eq!(safe_node.state.read().pending_actions.len(), 0);
    assert_eq!(safe_node.action_tree.len(), 0);

    assert_eq!(
        rpc_method_policy("auto", true).expect("external auto"),
        RpcMethodPolicy::Safe
    );
    assert_eq!(
        rpc_method_policy("auto", false).expect("local auto"),
        RpcMethodPolicy::Safe
    );
    let external_unsafe =
        rpc_method_policy("unsafe", true).expect_err("external unsafe RPC policy must be rejected");
    assert!(
        external_unsafe
            .to_string()
            .contains("cannot be combined with --rpc-external"),
        "{external_unsafe}"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let unsafe_node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false))
        .expect("unsafe node");
    let allowed = dispatch_rpc_method(
        &unsafe_node,
        "da_submitCiphertexts",
        json!({"ciphertexts": []}),
    )
    .expect("unsafe RPC should allow DA staging");
    assert_eq!(allowed, Value::Array(Vec::new()));

    let methods = native_rpc_methods(RpcMethodPolicy::Safe);
    assert!(!methods.contains(&"da_submitCiphertexts"));
    assert!(!methods.contains(&"hegemon_startMining"));
    assert!(!methods.contains(&"hegemon_submitAction"));
    assert!(!methods.contains(&"hegemon_peerGraph"));
    assert!(!methods.contains(&"hegemon_peerList"));
    assert!(!methods.contains(&"hegemon_exportBridgeWitness"));
    assert!(!methods.contains(&"system_peers"));
    let unsafe_methods = native_rpc_methods(RpcMethodPolicy::Unsafe);
    assert!(unsafe_methods.contains(&"hegemon_submitAction"));
    assert!(unsafe_methods.contains(&"hegemon_peerGraph"));
    assert!(unsafe_methods.contains(&"hegemon_exportBridgeWitness"));
}

#[test]
fn unsafe_peer_topology_rpc_exposes_connected_peer_snapshot() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let local_peer_id = [9u8; 32];
    let remote_peer_id = [7u8; 32];
    let remote_addr: SocketAddr = "198.51.100.7:30333".parse().expect("addr");
    node.set_network_local_peer_id(local_peer_id);
    node.network_peer_count.store(1, Ordering::Relaxed);
    *node
        .network_peer_snapshot
        .write()
        .expect("peer snapshot write") = vec![ConnectedPeerSnapshot {
        peer_id: remote_peer_id,
        addr: remote_addr,
    }];

    let health = dispatch_rpc_method(&node, "system_health", Value::Array(Vec::new()))
        .expect("system health");
    assert_eq!(health.get("peers"), Some(&json!(1)));

    let system_peers =
        dispatch_rpc_method(&node, "system_peers", Value::Array(Vec::new())).expect("system peers");
    let system_peers = system_peers.as_array().expect("system peers array");
    assert_eq!(system_peers.len(), 1);
    assert_eq!(
        system_peers[0].get("peerId"),
        Some(&json!(hex32(&remote_peer_id)))
    );
    assert_eq!(
        system_peers[0].get("endpoint"),
        Some(&json!(remote_addr.to_string()))
    );

    let peer_list = dispatch_rpc_method(&node, "hegemon_peerList", Value::Array(Vec::new()))
        .expect("peer list");
    let peer_list = peer_list.as_array().expect("peer list array");
    assert_eq!(peer_list.len(), 1);
    assert_eq!(
        peer_list[0].get("peer_id"),
        Some(&json!(hex32(&remote_peer_id)))
    );
    assert_eq!(
        peer_list[0].get("addr"),
        Some(&json!(remote_addr.to_string()))
    );

    let graph = dispatch_rpc_method(&node, "hegemon_peerGraph", Value::Array(Vec::new()))
        .expect("peer graph");
    assert_eq!(
        graph.get("local_peer_id"),
        Some(&json!(hex32(&local_peer_id)))
    );
    assert_eq!(
        graph.get("peers").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    assert_eq!(
        graph.get("links").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
}

#[test]
fn safe_node_config_redacts_local_paths_and_topology() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("198.51.100.7:30333".to_string());
    let node = NativeNode::open(config).expect("node");

    let safe_snapshot = dispatch_rpc_method(&node, "hegemon_nodeConfig", Value::Array(Vec::new()))
        .expect("safe config snapshot");
    assert_eq!(safe_snapshot.get("redacted"), Some(&json!(true)));
    assert_eq!(safe_snapshot.get("chainSpecName"), Some(&json!("Hegemon")));
    assert_eq!(
        dispatch_rpc_method(&node, "system_chain", Value::Array(Vec::new())).expect("system chain"),
        json!("Hegemon")
    );
    for sensitive_key in [
        "nodeName",
        "basePath",
        "p2pListenAddr",
        "rpcListenAddr",
        "rpcExternal",
        "bootstrapNodes",
        "pqVerbose",
        "maxPeers",
    ] {
        assert!(
            safe_snapshot.get(sensitive_key).is_none(),
            "safe config must not expose {sensitive_key}"
        );
    }

    let unsafe_tmp = tempfile::tempdir().expect("tempdir");
    let unsafe_node =
        NativeNode::open(test_config(unsafe_tmp.path(), 0x207f_fffe, "unsafe", false))
            .expect("unsafe node");
    let unsafe_snapshot =
        dispatch_rpc_method(&unsafe_node, "hegemon_nodeConfig", Value::Array(Vec::new()))
            .expect("unsafe config snapshot");
    assert_eq!(unsafe_snapshot.get("redacted"), Some(&json!(false)));
    assert_eq!(
        unsafe_snapshot.get("chainSpecName"),
        Some(&json!("Hegemon"))
    );
    assert!(unsafe_snapshot.get("basePath").is_some());
    assert!(unsafe_snapshot.get("p2pListenAddr").is_some());
}

#[test]
fn approved_seeded_dev_profile_reports_public_testnet_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push(APPROVED_PUBLIC_JOIN_SEED_OVH.to_string());
    let node = NativeNode::open(config).expect("node");

    let safe_snapshot = dispatch_rpc_method(&node, "hegemon_nodeConfig", Value::Array(Vec::new()))
        .expect("safe config snapshot");
    assert_eq!(
        safe_snapshot.get("chainSpecId"),
        Some(&json!("hegemon-native-testnet"))
    );
    assert_eq!(safe_snapshot.get("chainType"), Some(&json!("testnet")));
    assert_eq!(
        dispatch_rpc_method(&node, "system_chain", Value::Array(Vec::new())).expect("system chain"),
        json!("Hegemon")
    );

    let private_tmp = tempfile::tempdir().expect("tempdir");
    let private_node =
        NativeNode::open(test_config(private_tmp.path(), 0x207f_fffe, "safe", false))
            .expect("private dev node");
    let private_snapshot = dispatch_rpc_method(
        &private_node,
        "hegemon_nodeConfig",
        Value::Array(Vec::new()),
    )
    .expect("private config snapshot");
    assert_eq!(
        private_snapshot.get("chainSpecId"),
        Some(&json!("hegemon-native-dev"))
    );
    assert_eq!(private_snapshot.get("chainType"), Some(&json!("dev")));
}

#[test]
fn rpc_cors_defaults_closed_and_rejects_wildcard_for_unsafe_policy() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let response = with_cors(&node, StatusCode::NO_CONTENT.into_response());
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "default RPC must not expose browser CORS"
    );

    let tmp_safe = tempfile::tempdir().expect("tempdir");
    let mut safe_config = test_config(tmp_safe.path(), 0x207f_ffff, "safe", false);
    safe_config.rpc_cors = Some("*".to_string());
    let safe_node = NativeNode::open(safe_config).expect("safe cors node");
    let response = with_cors(&safe_node, StatusCode::NO_CONTENT.into_response());
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("*"))
    );

    let tmp_unsafe = tempfile::tempdir().expect("tempdir");
    let mut unsafe_config = test_config(tmp_unsafe.path(), 0x207f_ffff, "unsafe", false);
    unsafe_config.rpc_cors = Some("*".to_string());
    let unsafe_node = NativeNode::open(unsafe_config).expect("unsafe cors node");
    let response = with_cors(&unsafe_node, StatusCode::NO_CONTENT.into_response());
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "unsafe RPC must not accept wildcard CORS"
    );
}

#[test]
fn is_valid_anchor_rpc_matches_commitment_tree() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();

    let valid = dispatch_rpc_method(&node, "hegemon_isValidAnchor", json!([hex::encode(anchor)]))
        .expect("valid anchor RPC");
    assert_eq!(valid, json!(true));

    let unknown = dispatch_rpc_method(&node, "hegemon_isValidAnchor", json!([hex48(&[9u8; 48])]))
        .expect("unknown anchor RPC");
    assert_eq!(unknown, json!(false));

    let err = dispatch_rpc_method(&node, "hegemon_isValidAnchor", json!(["aa"]))
        .expect_err("malformed anchor must reject");
    assert!(err.to_string().contains("invalid anchor hex"));

    let methods = native_rpc_methods(RpcMethodPolicy::Safe);
    assert!(methods.contains(&"hegemon_isValidAnchor"));
}

#[test]
fn chain_get_block_rejects_oversized_action_body_before_hex_encoding() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let mut small = node.best_meta();
    small.action_bytes = vec![vec![0u8; MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES]];
    admit_chain_get_block_response(&small).expect("cap-sized block should be admitted");

    let mut oversized = node.best_meta();
    oversized.action_bytes = vec![vec![0u8; MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES + 1]];
    let err = admit_chain_get_block_response(&oversized)
        .expect_err("oversized block must reject before hex encoding");
    assert!(
        err.to_string()
            .contains("chain_getBlock action bytes exceed"),
        "{err}"
    );
}

#[test]
fn submit_action_rejects_non_transfer_or_excess_nullifiers_before_parsing() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let args = OutboundBridgeArgsV1 {
        destination_chain_id: [7u8; 32],
        app_family_id: 9,
        payload: b"unexpected nullifier".to_vec(),
    };
    let err = node
        .validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_OUTBOUND,
            "new_nullifiers": ["not-hex"],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        }))
        .expect_err("non-transfer routes must reject nullifier lists");
    assert!(err.to_string().contains("new_nullifiers must be empty"));

    let too_many = vec!["00".repeat(48); transaction_core::constants::MAX_INPUTS + 1];
    let err = node
        .validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_SHIELDED_POOL,
            "action_id": ACTION_SHIELDED_TRANSFER_INLINE,
            "new_nullifiers": too_many,
            "public_args": "not-base64",
        }))
        .expect_err("oversized nullifier list must reject before public_args decode");
    assert!(err.to_string().contains("exceeds MAX_INPUTS"));
    assert_eq!(node.state.read().pending_actions.len(), 0);
}

#[test]
fn submit_action_rejects_inactive_legacy_binding_before_staging() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let args = OutboundBridgeArgsV1 {
        destination_chain_id: [7u8; 32],
        app_family_id: 9,
        payload: b"legacy binding".to_vec(),
    };
    let legacy = protocol_versioning::LEGACY_PLONKY3_FRI_VERSION_BINDING;
    let err = node
        .validate_and_stage_action(json!({
            "binding_circuit": legacy.circuit,
            "binding_crypto": legacy.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_OUTBOUND,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        }))
        .expect_err("inactive legacy binding must reject before staging");
    assert!(
        err.to_string().contains("is not active"),
        "unexpected inactive-binding error: {err}"
    );
    assert_eq!(node.state.read().pending_actions.len(), 0);
}

#[test]
fn submit_action_rejects_unknown_or_nonempty_kernel_projection_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

    let accepted = node
        .validate_and_stage_action(action_request_projection_fixture(
            "valid_empty_wallet_envelope_fields",
        ))
        .expect("empty wallet envelope compatibility fields must be accepted");
    assert_eq!(node.state.read().pending_actions.len(), 1);
    assert_eq!(accepted.tx_hash, pending_action_hash(&accepted));

    let unknown = node
        .validate_and_stage_action(action_request_projection_fixture("unknown_field"))
        .expect_err("unknown action request fields must reject");
    assert!(
        unknown.to_string().contains("decode submit action request"),
        "unexpected unknown-field error: {unknown}"
    );

    for fixture in [
        "object_ref_present",
        "authorization_proof_present",
        "authorization_signature_present",
        "aux_data_present",
    ] {
        let err = node
            .validate_and_stage_action(action_request_projection_fixture(fixture))
            .expect_err("non-empty kernel envelope projection fields must reject");
        assert!(
            err.to_string().contains("kernel envelope fields"),
            "unexpected projection error for {fixture}: {err}"
        );
    }
}

#[test]
fn submit_action_rejects_trailing_public_args() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let args = OutboundBridgeArgsV1 {
        destination_chain_id: [7u8; 32],
        app_family_id: 9,
        payload: b"trailing-byte exploit".to_vec(),
    };
    let mut encoded = args.encode();
    encoded.push(0xaa);
    let err = node
        .validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_OUTBOUND,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(encoded),
        }))
        .expect_err("trailing bytes must be rejected");
    assert!(err.to_string().contains("trailing bytes"));
    assert_eq!(node.state.read().pending_actions.len(), 0);
}

#[test]
fn native_metadata_rejects_trailing_bincode_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let mut block_record = bincode::serialize(&genesis).expect("serialize genesis metadata");
    block_record.push(0xaa);
    node.block_tree
        .insert(genesis.hash.as_slice(), block_record)
        .expect("corrupt block record");

    let err = node
        .header_by_hash(&genesis.hash)
        .expect_err("trailing block metadata bytes must fail");
    assert!(err.to_string().contains("trailing bytes"));

    let mut best_record = bincode::serialize(&genesis).expect("serialize best metadata");
    best_record.push(0xbb);
    node.meta_tree
        .insert(META_BEST_KEY, best_record)
        .expect("corrupt best record");
    drop(node);

    let err = match NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)) {
        Ok(_) => panic!("trailing best metadata bytes must fail on reload"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("trailing bytes"));
}

#[test]
fn chain_rpc_rejects_malformed_explicit_hash_without_latest_fallback() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

    let latest_header = chain_get_header(&node, Value::Array(Vec::new()))
        .expect("no explicit header hash should return latest");
    assert_ne!(latest_header, Value::Null);
    let latest_block = chain_get_block(&node, Value::Array(Vec::new()))
        .expect("no explicit block hash should return latest");
    assert_ne!(latest_block, Value::Null);

    assert_eq!(
        chain_get_header(&node, json!(["0x1234"])).expect("malformed header hash"),
        Value::Null
    );
    assert_eq!(
        chain_get_header(&node, json!([42])).expect("wrong header param type"),
        Value::Null
    );
    assert_eq!(
        chain_get_block(&node, json!(["0x1234"])).expect("malformed block hash"),
        Value::Null
    );
    assert_eq!(
        chain_get_block(&node, json!([{"hash": hex32(&node.best_meta().hash)}]))
            .expect("wrong block param type"),
        Value::Null
    );
}

#[test]
fn chain_rpc_rejects_block_record_key_hash_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let mut forged = genesis.clone();
    forged.hash[0] ^= 1;
    forged.work_hash = forged.hash;
    node.block_tree
        .insert(
            genesis.hash.as_slice(),
            bincode::serialize(&forged).expect("serialize forged metadata"),
        )
        .expect("forge block record");

    let params = json!([hex32(&genesis.hash)]);
    let err =
        chain_get_header(&node, params.clone()).expect_err("header RPC must reject key/hash drift");
    assert!(err
        .to_string()
        .contains("stored native block hash mismatch"));
    let err = chain_get_block(&node, params).expect_err("block RPC must reject key/hash drift");
    assert!(err
        .to_string()
        .contains("stored native block hash mismatch"));
}

#[test]
fn chain_rpc_rejects_block_record_work_hash_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let mut forged = genesis.clone();
    forged.work_hash[0] ^= 1;
    node.block_tree
        .insert(
            genesis.hash.as_slice(),
            bincode::serialize(&forged).expect("serialize forged metadata"),
        )
        .expect("forge block record");

    let err = chain_get_block(&node, json!([hex32(&genesis.hash)]))
        .expect_err("block RPC must reject hash/work-hash drift");
    assert!(err
        .to_string()
        .contains("stored native block work-hash mismatch"));
}

#[test]
fn start_mining_thread_param_accepts_default_and_valid_threads() {
    assert_eq!(start_mining_threads_from_params(&json!({})).unwrap(), 1);
    assert_eq!(
        start_mining_threads_from_params(&Value::Array(Vec::new())).unwrap(),
        1
    );
    assert_eq!(
        start_mining_threads_from_params(&json!({"threads": 1})).unwrap(),
        1
    );
    assert_eq!(
        start_mining_threads_from_params(&json!([{"threads": 2}])).unwrap(),
        2
    );
    assert_eq!(
        start_mining_threads_from_params(&json!({"threads": MAX_NATIVE_MINING_THREADS})).unwrap(),
        MAX_NATIVE_MINING_THREADS
    );
}

#[test]
fn start_mining_thread_param_rejects_malformed_explicit_threads() {
    let err = start_mining_threads_from_params(&json!(["bad params"]))
        .expect_err("non-object explicit params must reject");
    assert!(err.to_string().contains("params must be an object"));

    let err = start_mining_threads_from_params(&json!({"threads": "many"}))
        .expect_err("string thread count must reject");
    assert!(err.to_string().contains("unsigned integer"));

    let err = start_mining_threads_from_params(&json!({"threads": 0}))
        .expect_err("zero thread count must reject");
    assert!(err.to_string().contains("at least 1"));

    let err = start_mining_threads_from_params(
        &json!({"threads": u64::from(MAX_NATIVE_MINING_THREADS) + 1}),
    )
    .expect_err("overlarge thread count must reject");
    assert!(err.to_string().contains("exceeds maximum mining threads"));

    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let err = dispatch_rpc_method(&node, "hegemon_startMining", json!({"threads": "many"}))
        .expect_err("malformed start mining RPC must reject before side effects");
    let message = err.to_string();
    assert!(
        message.contains("unsigned integer"),
        "unexpected start-mining RPC error: {message}"
    );
    assert!(!node.mining.load(Ordering::SeqCst));
}

#[test]
fn native_mining_threads_preserve_service_headroom() {
    assert_eq!(effective_native_mining_threads(8, 4), 1);
    assert_eq!(effective_native_mining_threads(8, 2), 1);
    assert_eq!(effective_native_mining_threads(1, 4), 1);
    assert_eq!(effective_native_mining_threads(8, 16), 2);
    assert_eq!(
        effective_native_mining_threads(MAX_NATIVE_MINING_THREADS, 16),
        NATIVE_MINING_BACKGROUND_THREAD_CAP
    );
}

#[tokio::test]
async fn start_mining_spawns_requested_task_count() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "unsafe", false);
    config.seeds = vec!["127.0.0.1:1".to_string()];
    let node = NativeNode::open(config).expect("node");

    node.start_mining(3);
    tokio::task::yield_now().await;
    let expected = effective_native_mining_threads(3, native_available_parallelism());
    assert!(node.mining.load(Ordering::SeqCst));
    assert_eq!(node.mining_threads.load(Ordering::Relaxed), expected);
    assert_eq!(node.mining_tasks.lock().len(), expected as usize);

    node.start_mining(2);
    tokio::task::yield_now().await;
    let expected = effective_native_mining_threads(2, native_available_parallelism());
    assert_eq!(node.mining_threads.load(Ordering::Relaxed), expected);
    assert_eq!(node.mining_tasks.lock().len(), expected as usize);

    node.stop_mining();
    assert!(!node.mining.load(Ordering::SeqCst));
    assert_eq!(node.mining_threads.load(Ordering::Relaxed), 0);
    assert!(node.mining_tasks.lock().is_empty());
}

#[test]
fn timestamp_rpc_rejects_unbounded_ranges() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

    let err = block_timestamps(&node, json!([0, MAX_NATIVE_TIMESTAMP_ROWS]), false)
        .expect_err("range one larger than cap must fail");
    assert!(err.to_string().contains("timestamp range too large"));

    let err = block_timestamps(&node, json!([9, 8]), false).expect_err("inverted range must fail");
    assert!(err.to_string().contains("before start"));

    let mined = block_timestamps(&node, Value::Array(Vec::new()), true)
        .expect("genesis-only mined timestamps");
    assert_eq!(mined, Value::Array(Vec::new()));
}

#[test]
fn timestamp_rpc_rejects_corrupt_explicit_range_header() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let mut block_record = bincode::serialize(&genesis).expect("serialize genesis metadata");
    block_record.push(0xaa);
    node.block_tree
        .insert(genesis.hash.as_slice(), block_record)
        .expect("corrupt block record");

    let err = block_timestamps(&node, json!([genesis.height, genesis.height]), false)
        .expect_err("explicit timestamp range must reject corrupt header metadata");
    assert!(err.to_string().contains("trailing bytes"));
}

#[test]
fn timestamp_rpc_rejects_missing_canonical_height_inside_best_range() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let future =
        block_timestamps(&node, json!([1, 1]), false).expect("future timestamp rows may be absent");
    assert_eq!(
        future,
        json!([{
            "height": 1,
            "timestamp_ms": Value::Null,
        }])
    );

    let genesis = node.best_meta();
    node.height_tree
        .remove(height_key(genesis.height))
        .expect("remove canonical genesis height index");
    node.height_tree.flush().expect("flush height tree");

    let err = block_timestamps(&node, json!([genesis.height, genesis.height]), false)
        .expect_err("timestamp RPC must reject missing canonical height inside best range");
    assert!(err.to_string().contains("missing canonical height index"));
}

#[test]
fn timestamp_rpc_rejects_canonical_record_height_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let mut forged = genesis.clone();
    forged.height = 1;
    node.block_tree
        .insert(
            genesis.hash.as_slice(),
            bincode::serialize(&forged).expect("serialize forged metadata"),
        )
        .expect("forge canonical block record");

    let err = block_timestamps(&node, json!([0, 0]), false)
        .expect_err("timestamp RPC must reject height/hash metadata drift");
    assert!(err
        .to_string()
        .contains("points to block metadata at height 1"));
}

#[test]
fn timestamp_rpc_rejects_canonical_record_work_hash_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let mut forged = genesis.clone();
    forged.work_hash[0] ^= 1;
    node.block_tree
        .insert(
            genesis.hash.as_slice(),
            bincode::serialize(&forged).expect("serialize forged metadata"),
        )
        .expect("forge canonical block record");

    let err = block_timestamps(&node, json!([0, 0]), false)
        .expect_err("timestamp RPC must reject hash/work-hash metadata drift");
    assert!(err
        .to_string()
        .contains("stored native block work-hash mismatch"));
}

#[test]
fn mempool_byte_budget_rejects_aggregate_overflow() {
    let state = test_state(genesis_meta(0x207f_ffff).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let first = test_inline_transfer_action(anchor, [41u8; 48], [51u8; 48], 0);
    let second = test_inline_transfer_action(anchor, [42u8; 48], [52u8; 48], 0);
    let mut pending = BTreeMap::new();
    pending.insert(first.tx_hash, first);
    let max = pending_mempool_bytes(&pending)
        .saturating_add(pending_action_mempool_bytes(&second))
        .saturating_sub(1);

    let err = validate_mempool_byte_budget(&pending, &second, max)
        .expect_err("aggregate byte budget must reject over-limit candidate");
    assert!(err.to_string().contains("mempool byte budget"));
}

#[test]
fn staged_proof_byte_budget_rejects_aggregate_overflow() {
    let mut staged = BTreeMap::new();
    staged.insert("first".to_string(), vec![0u8; 4]);

    let err = validate_staged_proof_byte_budget(&staged, "second", 2, 5)
        .expect_err("aggregate staged proof bytes must be capped");
    assert!(err.to_string().contains("staged proof byte budget"));

    validate_staged_proof_byte_budget(&staged, "first", 5, 5)
        .expect("replacement should subtract existing proof bytes");
}

#[test]
fn sidecar_upload_capacity_replacement_accepts_full_staging() {
    evaluate_native_ciphertext_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
        staged_count: 4,
        max_staged_count: 4,
        replaces_existing: true,
    })
    .expect("ciphertext replacement at capacity should be accepted");
    evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
        staged_count: 4,
        max_staged_count: 4,
        replaces_existing: true,
    })
    .expect("proof replacement at capacity should be accepted");

    let ciphertext_err = evaluate_native_ciphertext_sidecar_capacity_admission(
        NativeSidecarCapacityAdmissionInput {
            staged_count: 4,
            max_staged_count: 4,
            replaces_existing: false,
        },
    )
    .expect_err("new ciphertext at capacity must reject");
    assert_eq!(
        ciphertext_err,
        NativeSidecarUploadAdmissionRejection::StagedCiphertextCapacityReached
    );

    let proof_err =
        evaluate_native_proof_sidecar_capacity_admission(NativeSidecarCapacityAdmissionInput {
            staged_count: 4,
            max_staged_count: 4,
            replaces_existing: false,
        })
        .expect_err("new proof at capacity must reject");
    assert_eq!(
        proof_err,
        NativeSidecarUploadAdmissionRejection::StagedProofCapacityReached
    );
}

#[test]
fn submit_ciphertexts_rejects_too_many_uploads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let ciphertexts = vec![json!(""); MAX_NATIVE_DA_CIPHERTEXT_UPLOADS + 1];
    let err = node
        .submit_ciphertexts(json!({ "ciphertexts": ciphertexts }))
        .expect_err("too many ciphertext uploads must reject before decode");
    assert!(err.to_string().contains("too many ciphertexts"));
}

#[test]
fn submit_proofs_rejects_too_many_uploads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let proofs = vec![json!({}); MAX_NATIVE_DA_PROOF_UPLOADS + 1];
    let err = node
        .submit_proofs(json!({ "proofs": proofs }))
        .expect_err("too many proof uploads must reject before item decode");
    assert!(err.to_string().contains("too many proofs"));
}

#[test]
fn submit_ciphertexts_rejects_mixed_batch_atomically() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");

    let err = node
        .submit_ciphertexts(json!({ "ciphertexts": ["0x010203", "!!!!"] }))
        .expect_err("invalid second ciphertext must reject the whole batch");
    assert!(err.to_string().contains("decode base64 bytes"));
    assert!(node.state.read().staged_ciphertexts.is_empty());
    assert_eq!(node.da_ciphertext_tree.len(), 0);
}

#[test]
fn submit_proofs_rejects_mixed_batch_atomically() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let (binding_hash, proof) = staged_proof_fixture();

    let err = node
        .submit_proofs(json!({
            "proofs": [
                {
                    "binding_hash": format!("0x{}", hex::encode(binding_hash)),
                    "proof": format!("0x{}", hex::encode(proof)),
                },
                { "proof": "AA==" }
            ]
        }))
        .expect_err("invalid second proof must reject the whole batch");
    assert!(err.to_string().contains("missing binding_hash"));
    assert!(node.state.read().staged_proofs.is_empty());
    assert_eq!(node.da_proof_tree.len(), 0);
}

#[test]
fn submit_proofs_rejects_invalid_metadata_and_empty_proof() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let err = node
        .submit_proofs(json!({ "proofs": [{ "proof": "AA==" }] }))
        .expect_err("missing binding hash must reject first");
    assert!(err.to_string().contains("missing binding_hash"));

    let err = node
        .submit_proofs(json!({
            "proofs": [{ "binding_hash": "0x12", "proof": "AA==" }]
        }))
        .expect_err("invalid binding hash must reject before proof parsing");
    assert!(err.to_string().contains("invalid binding_hash"));

    let valid_binding_hash = format!("0x{}", "11".repeat(64));
    let err = node
        .submit_proofs(json!({
            "proofs": [{ "binding_hash": valid_binding_hash, "proof": "" }]
        }))
        .expect_err("empty proof must reject after metadata admission");
    assert!(err.to_string().contains("must be non-empty"));
}

#[test]
fn submit_proofs_rejects_staged_byte_budget_before_binding_decode() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    node.state.write().staged_proofs.insert(
        "existing".to_owned(),
        vec![0u8; MAX_NATIVE_STAGED_PROOF_BYTES],
    );

    let err = node
        .submit_proofs(json!({
            "proofs": [{
                "binding_hash": format!("0x{}", "11".repeat(64)),
                "proof": "0xaa",
            }]
        }))
        .expect_err("staged byte budget must reject before artifact binding decode");
    let err = err.to_string();
    assert!(
        err.contains("staged proof byte budget"),
        "unexpected staged proof upload error: {err}"
    );
    assert!(
        !err.contains("proof binding hash"),
        "oversized staged proof upload reached proof binding decode: {err}"
    );
    assert_eq!(node.da_proof_tree.len(), 0);
}

#[test]
fn submit_sidecars_accepts_valid_uploads_and_replacements() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");

    let ciphertexts = node
        .submit_ciphertexts(json!({ "ciphertexts": ["0x010203"] }))
        .expect("valid ciphertext sidecar should stage");
    let ciphertexts = ciphertexts
        .as_array()
        .expect("ciphertext result should be array");
    assert_eq!(ciphertexts.len(), 1);
    assert_eq!(ciphertexts[0]["size"].as_u64(), Some(3));
    assert!(ciphertexts[0]["hash"].as_str().unwrap().starts_with("0x"));

    let (binding_hash, proof) = staged_proof_fixture();
    let binding_hash = format!("0x{}", hex::encode(binding_hash));
    let proof_hex = format!("0x{}", hex::encode(&proof));
    let proofs = node
        .submit_proofs(json!({
            "proofs": [{ "binding_hash": binding_hash, "proof": proof_hex }]
        }))
        .expect("valid proof sidecar should stage");
    let proofs = proofs.as_array().expect("proof result should be array");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0]["size"].as_u64(), Some(proof.len() as u64));
    assert!(proofs[0]["proof_hash"].as_str().unwrap().starts_with("0x"));
    assert_eq!(proofs[0]["binding_hash"], json!(binding_hash));

    let replacement_binding_hash = proofs[0]["binding_hash"].clone();
    node.submit_proofs(json!({
            "proofs": [{ "binding_hash": replacement_binding_hash, "proof": format!("0x{}", hex::encode(&proof)) }]
        }))
        .expect("same binding hash replacement should be accepted");

    let state = node.state.read();
    assert_eq!(state.staged_ciphertexts.len(), 1);
    assert_eq!(state.staged_proofs.len(), 1);
    assert_eq!(
        state.staged_proofs.values().next().unwrap().len(),
        proof.len()
    );
}

#[test]
fn submit_sidecar_action_consumes_embedded_staged_proof_atomically() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_sidecar_transfer_action(anchor, [71u8; 48], [72u8; 48], 0);
    let mut args: ShieldedTransferSidecarArgs =
        decode_scale_exact(&action.public_args, "test sidecar args").expect("decode args");
    let proof = args.proof.clone();
    let binding_hash = args.binding_hash;
    let binding_hex = format!("0x{}", hex::encode(binding_hash));

    node.submit_ciphertexts(json!({
        "ciphertexts": [format!("0x{}", hex::encode(test_transfer_ciphertext_bytes()))],
    }))
    .expect("stage sidecar ciphertext");
    node.submit_proofs(json!({
        "proofs": [{
            "binding_hash": binding_hex,
            "proof": format!("0x{}", hex::encode(&proof)),
        }]
    }))
    .expect("stage proof sidecar");
    assert_eq!(node.state.read().staged_proofs.len(), 1);
    assert_eq!(node.da_proof_tree.len(), 1);

    args.proof.clear();
    let staged = node
        .validate_and_stage_action(json!({
            "binding_circuit": action.binding.circuit,
            "binding_crypto": action.binding.crypto,
            "family_id": action.family_id,
            "action_id": action.action_id,
            "new_nullifiers": action
                .nullifiers
                .iter()
                .map(hex48)
                .collect::<Vec<_>>(),
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        }))
        .expect("stage sidecar action by embedding staged proof");

    assert!(node.state.read().staged_proofs.is_empty());
    assert_eq!(node.da_proof_tree.len(), 0);
    assert!(node
        .action_tree
        .get(staged.tx_hash.as_slice())
        .expect("read staged action")
        .is_some());
    let staged_args: ShieldedTransferSidecarArgs =
        decode_scale_exact(&staged.public_args, "staged sidecar args").expect("decode staged args");
    assert_eq!(staged_args.proof, proof);
}

#[test]
fn submit_proofs_canonicalizes_binding_hash_before_response_hashing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let (binding_hash, proof) = staged_proof_fixture();
    let prefixed_binding_hash = format!("0x{}", hex::encode(binding_hash));
    let uppercase_unprefixed_binding_hash = hex::encode(binding_hash).to_uppercase();
    let proof_hex = format!("0x{}", hex::encode(&proof));

    let prefixed_response = node
        .submit_proofs(json!({
            "proofs": [{ "binding_hash": prefixed_binding_hash, "proof": proof_hex }]
        }))
        .expect("prefixed proof sidecar");
    let prefixed = prefixed_response
        .as_array()
        .expect("prefixed response")
        .first()
        .expect("prefixed response entry")
        .clone();
    let uppercase_response = node
            .submit_proofs(json!({
                "proofs": [{ "binding_hash": uppercase_unprefixed_binding_hash, "proof": format!("0x{}", hex::encode(&proof)) }]
            }))
            .expect("uppercase unprefixed proof sidecar");
    let uppercase_unprefixed = uppercase_response
        .as_array()
        .expect("uppercase response")
        .first()
        .expect("uppercase response entry")
        .clone();

    assert_eq!(
        prefixed["binding_hash"],
        json!(format!("0x{}", hex::encode(binding_hash)))
    );
    assert_eq!(
        uppercase_unprefixed["binding_hash"],
        prefixed["binding_hash"]
    );
    assert_eq!(uppercase_unprefixed["proof_hash"], prefixed["proof_hash"]);
    assert_eq!(node.state.read().staged_proofs.len(), 1);
}

#[test]
fn submit_proofs_rejects_binding_hash_mismatch_before_staging() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let (mut binding_hash, proof) = staged_proof_fixture();
    binding_hash[0] ^= 0xff;

    let err = node
        .submit_proofs(json!({
            "proofs": [{
                "binding_hash": format!("0x{}", hex::encode(binding_hash)),
                "proof": format!("0x{}", hex::encode(proof)),
            }]
        }))
        .expect_err("mismatched proof binding hash must reject before staging");
    assert!(err.to_string().contains("proof binding hash"));
    assert!(node.state.read().staged_proofs.is_empty());
    assert_eq!(node.da_proof_tree.len(), 0);
}

#[test]
fn submit_proofs_rejects_non_native_tx_leaf_artifact() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let err = node
        .submit_proofs(json!({
            "proofs": [{
                "binding_hash": format!("0x{}", "11".repeat(64)),
                "proof": "0x01020304",
            }]
        }))
        .expect_err("non-native tx leaf artifact must reject before staging");
    assert!(err.to_string().contains("proof binding hash"));
    assert!(node.state.read().staged_proofs.is_empty());
    assert_eq!(node.da_proof_tree.len(), 0);
}

#[test]
fn submit_proofs_rejects_repartitioned_tx_leaf_binding_alias() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let (binding_hash, proof) = repartitioned_tx_leaf_binding_alias_fixture();

    let err = node
        .submit_proofs(json!({
            "proofs": [{
                "binding_hash": format!("0x{}", hex::encode(binding_hash)),
                "proof": format!("0x{}", hex::encode(proof)),
            }]
        }))
        .expect_err("repartitioned tx-leaf artifact must not alias binding hash");
    assert!(err.to_string().contains("proof binding hash"));
    assert!(node.state.read().staged_proofs.is_empty());
    assert_eq!(node.da_proof_tree.len(), 0);
}

#[test]
fn submit_proofs_rejects_value_balance_binding_alias() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let anchor = [45u8; 48];
    let nullifier = [46u8; 48];
    let commitment = [47u8; 48];
    let ciphertext_hash = [48u8; 48];
    let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
    let fee = 3;
    let binding = KernelVersionBinding {
        circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
    };
    let zero_value_binding_hash = StarkVerifier::compute_binding_hash(&ShieldedTransferInputs {
        anchor,
        nullifiers: vec![nullifier],
        commitments: vec![commitment],
        ciphertext_hashes: vec![ciphertext_hash],
        balance_slot_asset_ids,
        fee,
        value_balance: 0,
        stablecoin: None,
    })
    .data;
    let proof = test_transfer_proof_artifact_with_value_balance(
        anchor,
        &[nullifier],
        &[commitment],
        &[ciphertext_hash],
        balance_slot_asset_ids,
        fee,
        -17,
        None,
        binding,
    );
    assert!(
        !native_tx_leaf_artifact_binding_hash_matches_key(zero_value_binding_hash, &proof),
        "artifact binding must bind decoded value balance"
    );

    let err = node
        .submit_proofs(json!({
            "proofs": [{
                "binding_hash": format!("0x{}", hex::encode(zero_value_binding_hash)),
                "proof": format!("0x{}", hex::encode(proof)),
            }]
        }))
        .expect_err("value-balance alias must not stage proof sidecar");
    assert!(err.to_string().contains("proof binding hash"));
    assert!(node.state.read().staged_proofs.is_empty());
    assert_eq!(node.da_proof_tree.len(), 0);
}

#[test]
fn rpc_byte_parser_rejects_oversized_strings_before_trust_boundary_decode() {
    use base64::Engine;

    let oversized_base64 = "A".repeat(encoded_len_limit(4) + 1);
    let err = parse_bytes_value(&json!(oversized_base64), 4, "test base64")
        .expect_err("oversized base64 text should be rejected before decode");
    assert!(err.to_string().contains("base64 length"));

    let oversized_hex = format!("0x{}", "00".repeat(5));
    let err = parse_bytes_value(&json!(oversized_hex), 4, "test hex")
        .expect_err("oversized hex text should be rejected before decode");
    assert!(err.to_string().contains("hex length"));

    let encoded_five = base64::engine::general_purpose::STANDARD.encode([0u8; 5]);
    let err = parse_bytes_value(&json!(encoded_five), 4, "test decoded")
        .expect_err("decoded bytes above cap should be rejected");
    assert!(err.to_string().contains("decoded length"));

    let encoded_four = base64::engine::general_purpose::STANDARD.encode([7u8; 4]);
    assert_eq!(
        parse_bytes_value(&json!(encoded_four), 4, "test exact").expect("exact limit"),
        vec![7u8; 4]
    );
    assert_eq!(
        parse_bytes_value(&json!("0x01020304"), 4, "test exact hex").expect("exact hex"),
        vec![1, 2, 3, 4]
    );
}

#[test]
fn native_sync_codec_rejects_legacy_or_trailing_bytes() {
    let message = NativeSyncMessage::Request {
        from_height: 1,
        to_height: 2,
    };
    let encoded = encode_sync_message(&message).expect("encode native sync message");
    assert!(decode_sync_message(&encoded).is_ok());

    let legacy = bincode::serialize(&message).expect("legacy bincode sync message");
    assert!(decode_sync_message(&legacy).is_err());

    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_sync_message(&trailing).is_err());
}

#[tokio::test]
async fn rpc_handler_rejects_oversized_batches() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let payload = Value::Array(
        (0..=MAX_NATIVE_RPC_BATCH_REQUESTS)
            .map(|idx| {
                json!({
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "system_health",
                    "params": [],
                })
            })
            .collect(),
    );

    let response = rpc_handler(State(node), Json(payload)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let decoded: Value = serde_json::from_slice(&body).expect("json body");
    assert!(decoded["error"]["message"]
        .as_str()
        .expect("error message")
        .contains("batch too large"));
}

#[test]
fn native_rpc_http_caps_bound_preparse_resource_use() {
    assert_eq!(MAX_NATIVE_RPC_BODY_BYTES, 8 * 1024 * 1024);
    assert_eq!(MAX_NATIVE_RPC_CONCURRENT_REQUESTS, 8);
    let http_body_cap = MAX_NATIVE_RPC_BODY_BYTES;
    let mempool_action_cap = MAX_NATIVE_MEMPOOL_ACTION_BYTES;
    assert!(
        http_body_cap > encoded_len_limit(MAX_NATIVE_RPC_ACTION_BYTES),
        "body cap must still admit a max-sized submitAction public_args payload"
    );
    assert!(
        http_body_cap < mempool_action_cap,
        "HTTP JSON parser cap must stay below the aggregate mempool action budget"
    );
}

#[test]
fn identity_seed_is_random_persisted_and_reloaded() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("pq-identity.seed");
    let first = load_or_create_identity_seed(&path).expect("create seed");
    let second = load_or_create_identity_seed(&path).expect("reload seed");
    assert_eq!(first, second);
    assert_eq!(parse_identity_seed_hex(&hex::encode(first)), Some(first));

    let old_deterministic = hash32_with_parts(&[
        b"hegemon-native-peer-v1",
        b"test",
        tmp.path().display().to_string().as_bytes(),
    ]);
    assert_ne!(first, old_deterministic);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn imported_block_actions_require_canonical_transfer_order() {
    let pow_bits = 0x207f_ffff;
    let best = genesis_meta(pow_bits).expect("genesis");
    let state = test_state(best.clone());
    let anchor = state.commitment_tree.root();
    let first = test_inline_transfer_action(anchor, [1u8; 48], [11u8; 48], 0);
    let second = test_inline_transfer_action(anchor, [2u8; 48], [22u8; 48], 0);
    let mut ordered = vec![first, second];
    ordered.sort_by_key(action_order_key);
    validate_block_actions_locked(&state, &ordered).expect("ordered actions should validate");

    let mut reversed = ordered.clone();
    reversed.reverse();
    if action_order_key(&reversed[0]) != action_order_key(&reversed[1]) {
        let err = validate_block_actions_locked(&state, &reversed)
            .expect_err("reversed actions should fail ordering");
        assert!(err.to_string().contains("canonical order"));
    }
}

#[test]
fn transfer_action_order_key_preimage_ignores_received_ms_for_inline_and_sidecar() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let inline = test_inline_transfer_action(anchor, [31u8; 48], [41u8; 48], 0);
    let sidecar = test_sidecar_transfer_action(anchor, [32u8; 48], [42u8; 48], 0);

    for (idx, action) in [inline, sidecar].into_iter().enumerate() {
        validate_transfer_action_payload(&action).expect("test transfer validates");
        let mut resampled = action.clone();
        resampled.received_ms = u64::MAX - u64::try_from(idx).expect("idx fits u64");
        resampled.tx_hash = pending_action_hash(&resampled);

        assert_ne!(
            action.tx_hash, resampled.tx_hash,
            "raw pending-action identity still records local arrival metadata"
        );
        assert_eq!(
            pending_action_semantic_hash(&action),
            pending_action_semantic_hash(&resampled),
            "semantic identity must ignore local arrival metadata"
        );
        assert_eq!(
            action_order_key_preimage(&action),
            action_order_key_preimage(&resampled),
            "accepted transfer order-key preimage must ignore local arrival metadata"
        );
        assert_eq!(
            action_order_key(&action),
            action_order_key(&resampled),
            "accepted transfer order key must ignore local arrival metadata"
        );
        assert_eq!(
            action_order_key_preimage(&action).len(),
            64 + 48 * action.nullifiers.len(),
            "accepted transfer order preimage is binding_hash || nullifiers"
        );
    }
}

#[test]
fn mineable_transfer_relative_order_ignores_received_ms_resampling() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut inline = test_inline_transfer_action(anchor, [33u8; 48], [43u8; 48], 0);
    let mut sidecar = test_sidecar_transfer_action(anchor, [34u8; 48], [44u8; 48], 0);
    inline.received_ms = 10;
    inline.tx_hash = pending_action_hash(&inline);
    sidecar.received_ms = 20;
    sidecar.tx_hash = pending_action_hash(&sidecar);

    for (hash, size) in sidecar
        .ciphertext_hashes
        .iter()
        .zip(sidecar.ciphertext_sizes.iter())
    {
        state.staged_ciphertexts.insert(hex48(hash), *size);
    }
    state.pending_actions.insert(inline.tx_hash, inline.clone());
    state
        .pending_actions
        .insert(sidecar.tx_hash, sidecar.clone());

    let selected = select_mineable_actions(&state);
    let transfer_projection = selected_transfer_order_projection(&selected);
    assert_eq!(
        transfer_projection.len(),
        2,
        "both test transfers must be mineable"
    );

    let mut resampled_state = state.clone();
    resampled_state.pending_actions.clear();
    let mut resampled_inline = inline.clone();
    let mut resampled_sidecar = sidecar.clone();
    resampled_inline.received_ms = 9001;
    resampled_sidecar.received_ms = 1;
    resampled_inline.tx_hash = pending_action_hash(&resampled_inline);
    resampled_sidecar.tx_hash = pending_action_hash(&resampled_sidecar);
    resampled_state
        .pending_actions
        .insert(resampled_inline.tx_hash, resampled_inline);
    resampled_state
        .pending_actions
        .insert(resampled_sidecar.tx_hash, resampled_sidecar);

    let resampled_selected = select_mineable_actions(&resampled_state);
    assert_eq!(
        selected_transfer_order_projection(&resampled_selected),
        transfer_projection,
        "mineable accepted transfer relative order must ignore local arrival metadata"
    );
}

#[test]
fn non_transfer_action_order_key_preimage_ignores_received_ms_for_public_routes() {
    let cases = vec![
        (
            "bridge-outbound",
            test_outbound_bridge_action(b"arrival metadata bridge payload"),
        ),
        ("candidate-artifact", test_candidate_artifact_action(1, 47)),
        ("coinbase", test_coinbase_action(50)),
    ];

    for (idx, (name, action)) in cases.into_iter().enumerate() {
        let mut resampled = action.clone();
        resampled.received_ms = u64::MAX - u64::try_from(idx).expect("idx fits u64");
        resampled.tx_hash = pending_action_hash(&resampled);

        assert_ne!(
            action.tx_hash, resampled.tx_hash,
            "{name} raw pending-action identity still records local arrival metadata"
        );
        assert_eq!(
            pending_action_semantic_hash(&action),
            pending_action_semantic_hash(&resampled),
            "{name} semantic identity must ignore local arrival metadata"
        );

        let expected_preimage = non_transfer_action_order_key_preimage(
            action.family_id,
            action.action_id,
            pending_action_semantic_hash(&action),
            &action.nullifiers,
        );
        assert_eq!(
            action_order_key_preimage(&action),
            expected_preimage,
            "{name} non-transfer order preimage must be domain/family/action/semantic-hash bound"
        );
        assert_eq!(
            action_order_key_preimage(&action),
            action_order_key_preimage(&resampled),
            "{name} non-transfer order-key preimage must ignore local arrival metadata"
        );
        assert_eq!(
            action_order_key(&action),
            action_order_key(&resampled),
            "{name} non-transfer order key must ignore local arrival metadata"
        );
    }
}

#[test]
fn pending_non_transfer_relative_order_ignores_received_ms_resampling() {
    let pow_bits = 0x207f_ffff;
    let best = genesis_meta(pow_bits).expect("genesis");
    let mut state = test_state(best);
    let bridge = test_outbound_bridge_action(b"stable non-transfer bridge order");
    let candidate = test_candidate_artifact_action(1, 53);
    let coinbase = test_coinbase_action(75);

    for action in [&bridge, &candidate, &coinbase] {
        state.pending_actions.insert(action.tx_hash, action.clone());
    }
    let projection = selected_action_order_projection(&ordered_pending_actions(&state));

    let mut resampled_state = state.clone();
    resampled_state.pending_actions.clear();
    for (idx, action) in [bridge, candidate, coinbase].into_iter().enumerate() {
        let mut resampled = action.clone();
        resampled.received_ms = 10_000 + u64::try_from(idx).expect("idx fits u64");
        resampled.tx_hash = pending_action_hash(&resampled);
        resampled_state
            .pending_actions
            .insert(resampled.tx_hash, resampled);
    }

    assert_eq!(
        selected_action_order_projection(&ordered_pending_actions(&resampled_state)),
        projection,
        "pending non-transfer relative order must ignore local arrival metadata"
    );
}

fn selected_transfer_order_projection(
    actions: &[PendingAction],
) -> Vec<(Vec<u8>, [u8; 32], [u8; 32])> {
    actions
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .map(|action| {
            (
                action_order_key_preimage(action),
                action_order_key(action),
                pending_action_semantic_hash(action),
            )
        })
        .collect()
}

fn selected_action_order_projection(
    actions: &[PendingAction],
) -> Vec<(Vec<u8>, [u8; 32], [u8; 32])> {
    actions
        .iter()
        .map(|action| {
            (
                action_order_key_preimage(action),
                action_order_key(action),
                pending_action_semantic_hash(action),
            )
        })
        .collect()
}

#[test]
fn lean_generated_native_fork_choice_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CONSENSUS_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_CONSENSUS_VECTORS not set; skipping generated Lean consensus vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read generated Lean consensus vectors");
    let vectors: LeanConsensusVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean consensus vectors");
    assert_eq!(vectors.schema_version, 2);
    assert!(
        !vectors.fork_choice_cases.is_empty(),
        "Lean fork-choice cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.fork_choice_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_native_fork_choice_case(case);
    }
}

fn verify_lean_native_fork_choice_case(case: &LeanForkChoiceCase) {
    let current = native_fork_choice_meta(
        case.current_height,
        parse_lean_hash32(&case.current_hash),
        parse_lean_work48(&case.current_work),
    );
    let candidate = native_fork_choice_meta(
        case.candidate_height,
        parse_lean_hash32(&case.candidate_hash),
        parse_lean_work48(&case.candidate_work),
    );
    let production_selected_candidate = native_meta_better_than(&candidate, &current);
    assert_eq!(
        production_selected_candidate, case.select_candidate,
        "{} native fork-choice wrapper drifted from Lean preference",
        case.name
    );

    let selected = if production_selected_candidate {
        &candidate
    } else {
        &current
    };
    let expected_source = if production_selected_candidate {
        "candidate"
    } else {
        "current"
    };
    assert_eq!(
        case.selected_source, expected_source,
        "{} native selected source drifted from Lean selectBest",
        case.name
    );
    assert_eq!(
        selected.height, case.selected_height,
        "{} native selected height drifted from Lean selectBest",
        case.name
    );
    assert_eq!(
        selected.hash,
        parse_lean_hash32(&case.selected_hash),
        "{} native selected hash drifted from Lean selectBest",
        case.name
    );
    assert_eq!(
        selected.cumulative_work,
        parse_lean_work48(&case.selected_work),
        "{} native selected Work48 drifted from Lean selectBest",
        case.name
    );
    assert!(
        case.selected_work_at_least_current,
        "{} Lean selected-work monotonicity flag must be true",
        case.name
    );
    assert!(
        matches!(
            compare_work(&selected.cumulative_work, &current.cumulative_work),
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater
        ),
        "{} native fork-choice selection must not lower cumulative work",
        case.name
    );
}

fn native_fork_choice_meta(
    height: u64,
    hash: [u8; 32],
    cumulative_work: [u8; 48],
) -> NativeBlockMeta {
    NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        hash,
        parent_hash: [0u8; 32],
        state_root: [0u8; 48],
        kernel_root: [0u8; 48],
        nullifier_root: [0u8; 48],
        extrinsics_root: [0u8; 32],
        message_root: [0u8; 48],
        message_count: 0,
        header_mmr_root: [0u8; 32],
        header_mmr_len: 0,
        timestamp_ms: 0,
        pow_bits: 0,
        nonce: [0u8; 32],
        work_hash: hash,
        cumulative_work,
        supply_digest: 0,
        tx_count: 0,
        action_bytes: Vec::new(),
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    }
}

fn parse_lean_work48(raw: &str) -> [u8; 48] {
    let value = raw
        .parse::<num_bigint::BigUint>()
        .expect("Lean work value must be decimal BigUint");
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 48, "Lean Work48 value must fit in 48 bytes");
    let mut out = [0u8; 48];
    out[48 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn parse_lean_hash32(raw: &str) -> [u8; 32] {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).expect("Lean hash must be valid hex");
    assert_eq!(bytes.len(), 32, "Lean hash must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn lean_generated_action_order_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_ORDER_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_ACTION_ORDER_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read generated Lean action-order vectors");
    let vectors: LeanActionOrderVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean action-order vectors");
    assert_eq!(vectors.schema_version, 3);
    assert!(
        !vectors.action_order_cases.is_empty(),
        "Lean action-order cases must not be empty"
    );
    assert!(
        !vectors.transfer_order_preimage_cases.is_empty(),
        "Lean transfer-order preimage cases must not be empty"
    );
    assert!(
        !vectors.non_transfer_order_preimage_cases.is_empty(),
        "Lean non-transfer-order preimage cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_order_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_order_case(case);
    }
    for case in &vectors.transfer_order_preimage_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_transfer_order_preimage_case(case);
    }
    for case in &vectors.non_transfer_order_preimage_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_non_transfer_order_preimage_case(case);
    }
}

fn verify_lean_action_order_case(case: &LeanActionOrderCase) {
    let transfer_keys = case
        .actions
        .iter()
        .filter(|action| action.is_transfer)
        .map(|action| parse_hash32(&action.key).expect("Lean action-order key must be 32-byte hex"))
        .collect::<Vec<_>>();
    assert_eq!(
        lean_transfer_keys_are_canonical_order(&transfer_keys),
        case.expected_valid,
        "{} native transfer-order predicate drifted from Lean spec",
        case.name
    );
}

fn lean_transfer_keys_are_canonical_order(keys: &[[u8; 32]]) -> bool {
    let mut previous: Option<[u8; 32]> = None;
    for key in keys {
        if !transfer_key_extends_canonical_order(previous.as_ref(), key) {
            return false;
        }
        previous = Some(*key);
    }
    true
}

fn verify_lean_transfer_order_preimage_case(case: &LeanTransferOrderPreimageCase) {
    let action = transfer_order_preimage_case_action(case, case.received_ms);
    let expected_preimage =
        decode_lean_hex_bytes(&case.expected_preimage).expect("decode Lean preimage hex");
    let actual_preimage = action_order_key_preimage(&action);
    assert_eq!(
        actual_preimage.len(),
        case.expected_preimage_len,
        "{} transfer action-order preimage length drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_preimage, expected_preimage,
        "{} transfer action-order preimage bytes drifted from Lean spec",
        case.name
    );

    let resampled = transfer_order_preimage_case_action(case, case.resampled_received_ms);
    let resampled_preimage = action_order_key_preimage(&resampled);
    assert_eq!(
        actual_preimage == resampled_preimage,
        case.expected_same_after_resample,
        "{} transfer action-order local-arrival resampling predicate drifted from Lean spec",
        case.name
    );
    assert_eq!(
        action_order_key(&action) == action_order_key(&resampled),
        case.expected_same_after_resample,
        "{} transfer action-order key local-arrival resampling predicate drifted from Lean spec",
        case.name
    );
}

fn transfer_order_preimage_case_action(
    case: &LeanTransferOrderPreimageCase,
    received_ms: u64,
) -> PendingAction {
    let binding_hash =
        parse_hex64(&case.binding_hash).expect("Lean binding_hash must be 64-byte hex");
    let nullifiers = case
        .nullifiers
        .iter()
        .map(|raw| parse_hex48(raw).expect("Lean nullifier must be 48-byte hex"))
        .collect::<Vec<_>>();
    let first_nullifier = nullifiers.first().copied().unwrap_or([31u8; 48]);
    let mut action = match case.route.as_str() {
        "inline" => test_inline_transfer_action([9u8; 48], first_nullifier, [10u8; 48], 0),
        "sidecar" => test_sidecar_transfer_action([9u8; 48], first_nullifier, [10u8; 48], 0),
        other => panic!("unknown Lean transfer-order route {other}"),
    };
    match case.route.as_str() {
        "inline" => {
            let mut args: ShieldedTransferInlineArgs =
                decode_scale_exact(&action.public_args, "Lean transfer-order inline args")
                    .expect("decode inline transfer args");
            args.binding_hash = binding_hash;
            action.public_args = args.encode();
        }
        "sidecar" => {
            let mut args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&action.public_args, "Lean transfer-order sidecar args")
                    .expect("decode sidecar transfer args");
            args.binding_hash = binding_hash;
            action.public_args = args.encode();
        }
        _ => unreachable!("route matched above"),
    }
    action.nullifiers = nullifiers;
    action.received_ms = received_ms;
    action.tx_hash = pending_action_hash(&action);
    action
}

fn verify_lean_non_transfer_order_preimage_case(case: &LeanNonTransferOrderPreimageCase) {
    match case.route.as_str() {
        "bridge_outbound" | "candidate_artifact" | "coinbase" => {}
        other => panic!("unknown Lean non-transfer-order route {other}"),
    }
    let semantic_hash =
        parse_hash32(&case.semantic_hash).expect("Lean semantic_hash must be 32-byte hex");
    let tx_hash = parse_hash32(&case.tx_hash).expect("Lean tx_hash must be 32-byte hex");
    let resampled_tx_hash =
        parse_hash32(&case.resampled_tx_hash).expect("Lean resampled_tx_hash must be 32-byte hex");
    assert_ne!(
        (case.received_ms, tx_hash),
        (case.resampled_received_ms, resampled_tx_hash),
        "{} Lean non-transfer local metadata fixture must resample arrival identity",
        case.name
    );
    let nullifiers = case
        .nullifiers
        .iter()
        .map(|raw| parse_hex48(raw).expect("Lean nullifier must be 48-byte hex"))
        .collect::<Vec<_>>();
    let expected_preimage =
        decode_lean_hex_bytes(&case.expected_preimage).expect("decode Lean preimage hex");
    let actual_preimage = non_transfer_action_order_key_preimage(
        case.family_id,
        case.action_id,
        semantic_hash,
        &nullifiers,
    );
    assert_eq!(
        actual_preimage.len(),
        case.expected_preimage_len,
        "{} non-transfer action-order preimage length drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_preimage, expected_preimage,
        "{} non-transfer action-order preimage bytes drifted from Lean spec",
        case.name
    );

    let resampled_preimage = non_transfer_action_order_key_preimage(
        case.family_id,
        case.action_id,
        semantic_hash,
        &nullifiers,
    );
    assert_eq!(
        actual_preimage == resampled_preimage,
        case.expected_same_after_resample,
        "{} non-transfer action-order local-metadata resampling predicate drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_action_hash_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_HASH_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_HASH_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean action-hash admission vectors");
    let vectors: LeanActionHashAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean action-hash vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_hash_admission_cases.is_empty(),
        "Lean action-hash admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_hash_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_hash_admission_case(case);
    }
}

fn verify_lean_action_hash_admission_case(case: &LeanActionHashAdmissionCase) {
    let input = NativeActionHashAdmissionInput {
        action_count_matches: case.action_count_matches,
        action_hashes_match: case.action_hashes_match,
        action_hashes_unique: case.action_hashes_unique,
    };
    let actual_rejection = evaluate_native_action_hash_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native action-hash admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native action-hash admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_action_root_transcript_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_ROOT_TRANSCRIPT_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean action-root transcript vectors");
    let vectors: LeanActionRootTranscriptVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean action-root vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_root_transcript_cases.is_empty(),
        "Lean action-root transcript cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_root_transcript_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_root_transcript_case(case);
    }
}

fn verify_lean_action_root_transcript_case(case: &LeanActionRootTranscriptCase) {
    let action_hashes = case
        .action_hashes_hex
        .iter()
        .map(|raw| parse_hash32(raw).expect("Lean action hash must be 32-byte hex"))
        .collect::<Vec<_>>();
    let expected_preimage =
        decode_lean_hex_bytes(&case.expected_preimage_hex).expect("decode Lean preimage hex");
    let actual_preimage = action_root_transcript_preimage(&action_hashes);
    assert_eq!(
        actual_preimage.len(),
        case.expected_preimage_len,
        "{} native action-root preimage length drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_preimage, expected_preimage,
        "{} native action-root preimage bytes drifted from Lean spec",
        case.name
    );
}

fn decode_lean_hex_bytes(raw: &str) -> Option<Vec<u8>> {
    hex::decode(raw.strip_prefix("0x").unwrap_or(raw)).ok()
}

#[test]
fn lean_generated_announced_block_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ANNOUNCED_BLOCK_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean announced-block admission vectors");
    let vectors: LeanAnnouncedBlockAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean announced-block vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.announced_block_admission_cases.is_empty(),
        "Lean announced-block admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.announced_block_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_announced_block_admission_case(case);
    }
}

fn verify_lean_announced_block_admission_case(case: &LeanAnnouncedBlockAdmissionCase) {
    let input = NativeAnnouncedBlockAdmissionInput {
        parent_height: case.parent_height,
        announced_height: case.announced_height,
        parent_hash_matches: case.parent_hash_matches,
        parent_timestamp_ms: case.parent_timestamp_ms,
        announced_timestamp_ms: case.announced_timestamp_ms,
        now_ms: case.now_ms,
        max_future_skew_ms: case.max_future_skew_ms,
        hash_matches_work_hash: case.hash_matches_work_hash,
    };
    let actual_rejection = evaluate_native_announced_block_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native announced-block admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native announced-block admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_block_index_reload_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_INDEX_RELOAD_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_BLOCK_INDEX_RELOAD_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean block-index reload vectors");
    let vectors: LeanBlockIndexReloadVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean block-index reload vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.block_index_reload_cases.is_empty(),
        "Lean block-index reload cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.block_index_reload_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_block_index_reload_case(case);
    }
}

fn verify_lean_block_index_reload_case(case: &LeanBlockIndexReloadCase) {
    let input = NativeBlockIndexReloadInput {
        chain_reconstructed: case.chain_reconstructed,
        chain_nonempty: case.chain_nonempty,
        genesis_matches_expected: case.genesis_matches_expected,
        best_metadata_matches_chain: case.best_metadata_matches_chain,
        canonical_heights_contiguous: case.canonical_heights_contiguous,
        canonical_chain_ids_match: case.canonical_chain_ids_match,
        canonical_rules_hashes_match: case.canonical_rules_hashes_match,
        canonical_hashes_match_work_hashes: case.canonical_hashes_match_work_hashes,
        canonical_parent_hashes_contiguous: case.canonical_parent_hashes_contiguous,
        height_keys_well_formed: case.height_keys_well_formed,
        height_values_well_formed: case.height_values_well_formed,
        no_extra_height_indexes: case.no_extra_height_indexes,
        height_index_heights_match_chain: case.height_index_heights_match_chain,
        height_index_hashes_match_chain: case.height_index_hashes_match_chain,
        all_canonical_heights_indexed: case.all_canonical_heights_indexed,
        genesis_marker_present: case.genesis_marker_present,
        genesis_marker_length_valid: case.genesis_marker_length_valid,
        genesis_marker_matches_expected: case.genesis_marker_matches_expected,
    };
    let actual = evaluate_native_block_index_reload(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    let actual_repairs_genesis_marker = actual
        .as_ref()
        .ok()
        .map(|admission| admission.repair_missing_genesis_marker)
        .unwrap_or(false);
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native block-index reload validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native block-index reload rejection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_repairs_genesis_marker, case.expected_repairs_genesis_marker,
        "{} native block-index reload repair decision drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_canonical_reorg_chain_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_CANONICAL_REORG_CHAIN_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean canonical reorg chain admission vectors");
    let vectors: LeanCanonicalReorgChainAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean canonical reorg chain admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.canonical_reorg_chain_admission_cases.is_empty(),
        "Lean canonical reorg chain admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.canonical_reorg_chain_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_canonical_reorg_chain_admission_case(case);
    }
}

fn verify_lean_canonical_reorg_chain_admission_case(case: &LeanCanonicalReorgChainAdmissionCase) {
    let input = NativeCanonicalReorgChainAdmissionInput {
        chain_nonempty: case.chain_nonempty,
        genesis_matches_expected: case.genesis_matches_expected,
        best_metadata_matches_chain: case.best_metadata_matches_chain,
        canonical_heights_contiguous: case.canonical_heights_contiguous,
        canonical_chain_ids_match: case.canonical_chain_ids_match,
        canonical_rules_hashes_match: case.canonical_rules_hashes_match,
        canonical_hashes_match_work_hashes: case.canonical_hashes_match_work_hashes,
        canonical_parent_hashes_contiguous: case.canonical_parent_hashes_contiguous,
        block_record_count_matches_chain: case.block_record_count_matches_chain,
        block_records_match_chain: case.block_records_match_chain,
        height_entry_count_matches_chain: case.height_entry_count_matches_chain,
        height_entries_match_chain: case.height_entries_match_chain,
    };
    let actual_rejection = evaluate_native_canonical_reorg_chain_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native canonical reorg chain admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native canonical reorg chain admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_canonical_state_reload_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CANONICAL_STATE_RELOAD_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_CANONICAL_STATE_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean canonical-state reload vectors");
    let vectors: LeanCanonicalStateReloadVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean canonical-state reload vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.canonical_state_reload_cases.is_empty(),
        "Lean canonical-state reload cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.canonical_state_reload_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_canonical_state_reload_case(case);
    }
}

fn verify_lean_canonical_state_reload_case(case: &LeanCanonicalStateReloadCase) {
    let input = NativeCanonicalStateReloadInput {
        nullifier_keys_well_formed: case.nullifier_keys_well_formed,
        nullifier_markers_valid: case.nullifier_markers_valid,
        commitment_keys_well_formed: case.commitment_keys_well_formed,
        commitment_values_well_formed: case.commitment_values_well_formed,
        commitment_indexes_contiguous: case.commitment_indexes_contiguous,
        commitment_tree_rebuilt: case.commitment_tree_rebuilt,
        commitment_root_matches_best: case.commitment_root_matches_best,
        nullifier_root_matches_best: case.nullifier_root_matches_best,
    };
    let actual_rejection = evaluate_native_canonical_state_reload(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native canonical-state reload validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native canonical-state reload rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_bridge_replay_reload_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_REPLAY_RELOAD_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_REPLAY_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean bridge-replay reload vectors");
    let vectors: LeanBridgeReplayReloadVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean bridge-replay reload vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_replay_reload_cases.is_empty(),
        "Lean bridge-replay reload cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_replay_reload_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_replay_reload_case(case);
    }
}

fn verify_lean_bridge_replay_reload_case(case: &LeanBridgeReplayReloadCase) {
    let input = NativeBridgeReplayReloadInput {
        replay_keys_well_formed: case.replay_keys_well_formed,
        replay_markers_valid: case.replay_markers_valid,
        canonical_replay_keys_unique: case.canonical_replay_keys_unique,
        no_missing_loaded_replay_keys: case.no_missing_loaded_replay_keys,
        no_extra_loaded_replay_keys: case.no_extra_loaded_replay_keys,
    };
    let actual_rejection = evaluate_native_bridge_replay_reload(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native bridge-replay reload validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge-replay reload rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_bridge_witness_export_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_WITNESS_EXPORT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge witness export admission vectors");
    let vectors: LeanBridgeWitnessExportAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean bridge witness export admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_witness_export_admission_cases.is_empty(),
        "Lean bridge witness export admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_witness_export_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_witness_export_admission_case(case);
    }
}

fn verify_lean_bridge_witness_export_admission_case(case: &LeanBridgeWitnessExportAdmissionCase) {
    let input = NativeBridgeWitnessExportAdmissionInput {
        block_hash_parameter_valid: case.block_hash_parameter_valid,
        explicit_block_hash: case.explicit_block_hash,
        block_known: case.block_known,
        canonical_height_present: case.canonical_height_present,
        block_is_canonical: case.block_is_canonical,
        block_actions_decoded: case.block_actions_decoded,
        message_index_in_bounds: case.message_index_in_bounds,
        parent_known: case.parent_known,
        best_height: case.best_height,
        message_height: case.message_height,
        max_explicit_history: case.max_explicit_history,
        max_materialized_history: case.max_materialized_history,
    };
    let actual = evaluate_native_bridge_witness_export_admission(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native bridge witness export admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.ok(),
        case.expected_confirmations_checked,
        "{} native bridge witness confirmations drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge witness export admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_inbound_bridge_receipt_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_INBOUND_BRIDGE_RECEIPT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean inbound bridge receipt admission vectors");
    let vectors: LeanInboundBridgeReceiptAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean inbound bridge receipt admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.inbound_bridge_receipt_admission_cases.is_empty(),
        "Lean inbound bridge receipt admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.inbound_bridge_receipt_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_inbound_bridge_receipt_admission_case(case);
    }
}

fn verify_lean_inbound_bridge_receipt_admission_case(case: &LeanInboundBridgeReceiptAdmissionCase) {
    let input = NativeInboundBridgeReceiptAdmissionInput {
        source_chain_matches: case.source_chain_matches,
        rules_hash_matches: case.rules_hash_matches,
        message_nonce_matches: case.message_nonce_matches,
        message_hash_matches: case.message_hash_matches,
        checkpoint_height: case.checkpoint_height,
        canonical_tip_height: case.canonical_tip_height,
        canonical_tip_work: parse_lean_work48(&case.canonical_tip_work),
        confirmations_checked: case.confirmations_checked,
        min_confirmations: case.min_confirmations,
        min_work_checked: parse_lean_work48(&case.min_work_checked),
        min_tip_work: parse_lean_work48(&case.min_tip_work),
    };
    let actual = evaluate_native_inbound_bridge_receipt_admission(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native inbound bridge receipt admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.ok(),
        case.expected_height_confirmations,
        "{} native inbound bridge receipt height-confirmation count drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native inbound bridge receipt admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn inbound_bridge_receipt_confirmation_count_overflow_fails_closed() {
    let input = NativeInboundBridgeReceiptAdmissionInput {
        source_chain_matches: true,
        rules_hash_matches: true,
        message_nonce_matches: true,
        message_hash_matches: true,
        checkpoint_height: 0,
        canonical_tip_height: u32::MAX as u64,
        canonical_tip_work: [0u8; 48],
        confirmations_checked: u32::MAX,
        min_confirmations: 1,
        min_work_checked: [0u8; 48],
        min_tip_work: [0u8; 48],
    };

    assert_eq!(
        evaluate_native_inbound_bridge_receipt_admission(input),
        Err(NativeInboundBridgeReceiptAdmissionRejection::ConfirmationsOverflow)
    );
}

#[test]
fn inbound_bridge_receipt_work_policy_fails_closed() {
    let mut min_work = [0u8; 48];
    min_work[47] = 2;
    let mut checked_work = [0u8; 48];
    checked_work[47] = 1;
    let input = NativeInboundBridgeReceiptAdmissionInput {
        source_chain_matches: true,
        rules_hash_matches: true,
        message_nonce_matches: true,
        message_hash_matches: true,
        checkpoint_height: 40,
        canonical_tip_height: 44,
        canonical_tip_work: min_work,
        confirmations_checked: 5,
        min_confirmations: 2,
        min_work_checked: checked_work,
        min_tip_work: min_work,
    };

    assert_eq!(
        evaluate_native_inbound_bridge_receipt_admission(input),
        Err(NativeInboundBridgeReceiptAdmissionRejection::WorkPolicyMismatch)
    );
}

#[test]
fn lean_generated_bridge_witness_backscan_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_WITNESS_BACKSCAN_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge witness backscan vectors");
    let vectors: LeanBridgeWitnessBackscanVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean bridge witness backscan vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_witness_backscan_cases.is_empty(),
        "Lean bridge witness backscan cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_witness_backscan_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_witness_backscan_case(case);
    }
}

fn verify_lean_bridge_witness_backscan_case(case: &LeanBridgeWitnessBackscanCase) {
    let entries = case
        .entries
        .iter()
        .map(|entry| NativeBridgeWitnessBackscanEntry {
            height: entry.height,
            canonical_hash_present: entry.canonical_hash_present,
            block_known: entry.block_known,
            block_actions_decoded: entry.block_actions_decoded,
            message_index_in_bounds: entry.message_index_in_bounds,
        })
        .collect::<Vec<_>>();
    let actual = evaluate_native_bridge_witness_backscan(&entries);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native bridge witness backscan validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.ok(),
        case.expected_selected_height,
        "{} native bridge witness backscan selected height drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge witness backscan rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_pending_action_reload_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_PENDING_ACTION_RELOAD_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_PENDING_ACTION_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean pending-action reload vectors");
    let vectors: LeanPendingActionReloadVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean pending-action reload vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.pending_action_reload_cases.is_empty(),
        "Lean pending-action reload cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.pending_action_reload_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_pending_action_reload_case(case);
    }
}

fn verify_lean_pending_action_reload_case(case: &LeanPendingActionReloadCase) {
    let input = NativePendingActionReloadInput {
        key_well_formed: case.key_well_formed,
        embedded_hash_matches_key: case.embedded_hash_matches_key,
        recomputed_hash_matches_embedded: case.recomputed_hash_matches_embedded,
        action_hash_unique: case.action_hash_unique,
    };
    let actual_rejection = evaluate_native_pending_action_reload(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native pending-action reload validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native pending-action reload rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_staged_ciphertext_reload_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_STAGED_CIPHERTEXT_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean staged-ciphertext reload vectors");
    let vectors: LeanStagedCiphertextReloadVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean staged-ciphertext reload vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.staged_ciphertext_reload_cases.is_empty(),
        "Lean staged-ciphertext reload cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.staged_ciphertext_reload_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_staged_ciphertext_reload_case(case);
    }
}

fn verify_lean_staged_ciphertext_reload_case(case: &LeanStagedCiphertextReloadCase) {
    let input = NativeStagedCiphertextReloadInput {
        key_well_formed: case.key_well_formed,
        ciphertext_within_limit: case.ciphertext_within_limit,
        ciphertext_hash_matches_key: case.ciphertext_hash_matches_key,
        capacity_available: case.capacity_available,
    };
    let actual_rejection = evaluate_native_staged_ciphertext_reload(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native staged-ciphertext reload validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native staged-ciphertext reload rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_staged_proof_reload_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_STAGED_PROOF_RELOAD_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_STAGED_PROOF_RELOAD_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean staged-proof reload vectors");
    let vectors: LeanStagedProofReloadVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean staged-proof reload vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.staged_proof_reload_cases.is_empty(),
        "Lean staged-proof reload cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.staged_proof_reload_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_staged_proof_reload_case(case);
    }
}

fn verify_lean_staged_proof_reload_case(case: &LeanStagedProofReloadCase) {
    let input = NativeStagedProofReloadInput {
        key_well_formed: case.key_well_formed,
        proof_nonempty: case.proof_nonempty,
        proof_within_limit: case.proof_within_limit,
        capacity_available: case.capacity_available,
        byte_capacity_available: case.byte_capacity_available,
        proof_binding_hash_matches_key: case.proof_binding_hash_matches_key,
    };
    let actual_rejection = evaluate_native_staged_proof_reload(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native staged-proof reload validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native staged-proof reload rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_mined_work_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_MINED_WORK_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_MINED_WORK_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean mined-work admission vectors");
    let vectors: LeanMinedWorkAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean mined-work vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.mined_work_admission_cases.is_empty(),
        "Lean mined-work admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.mined_work_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_mined_work_admission_case(case);
    }
}

fn verify_lean_mined_work_admission_case(case: &LeanMinedWorkAdmissionCase) {
    let input = NativeMinedWorkAdmissionInput {
        best_height: case.best_height,
        work_height: case.work_height,
        parent_hash_matches: case.parent_hash_matches,
    };
    let actual_rejection = evaluate_native_mined_work_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native mined-work admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native mined-work admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_mined_block_commit_publication_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_MINED_BLOCK_COMMIT_PUBLICATION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_MINED_BLOCK_COMMIT_PUBLICATION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean mined-block commit publication vectors");
    let vectors: LeanMinedBlockCommitPublicationVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean mined-block commit publication vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.mined_block_commit_publication_cases.is_empty(),
        "Lean mined-block commit publication cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.mined_block_commit_publication_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_mined_block_commit_publication_case(case);
    }
}

fn verify_lean_mined_block_commit_publication_case(case: &LeanMinedBlockCommitPublicationCase) {
    let mined_work = NativeMinedWorkAdmissionInput {
        best_height: case.best_height,
        work_height: case.work_height,
        parent_hash_matches: case.parent_hash_matches,
    };
    let block_commitment = NativeBlockCommitmentAdmissionInput {
        tx_count_matches: case.tx_count_matches,
        state_root_matches: case.state_root_matches,
        kernel_root_matches: case.kernel_root_matches,
        nullifier_root_matches: case.nullifier_root_matches,
        extrinsics_root_matches: case.extrinsics_root_matches,
        message_root_matches: case.message_root_matches,
        message_count_matches: case.message_count_matches,
        header_mmr_root_matches: case.header_mmr_root_matches,
        header_mmr_len_matches: case.header_mmr_len_matches,
        supply_digest_matches: case.supply_digest_matches,
    };
    let commit_manifest = NativeAtomicCommitManifestAdmissionInput {
        kind: native_atomic_commit_kind_from_label(&case.commit_kind),
        action_count: case.action_count,
        planned_action_count: case.planned_action_count,
        chain_block_count: case.chain_block_count,
        height_entry_count: case.height_entry_count,
        pending_entry_count: case.pending_entry_count,
        source_commitment_count: case.source_commitment_count,
        source_nullifier_count: case.source_nullifier_count,
        source_bridge_replay_count: case.source_bridge_replay_count,
        source_ciphertext_index_count: case.source_ciphertext_index_count,
        source_ciphertext_archive_count: case.source_ciphertext_archive_count,
        source_staged_ciphertext_removal_count: case.source_staged_ciphertext_removal_count,
        block_record_writes: case.block_record_writes,
        height_index_writes: case.height_index_writes,
        best_pointer_writes: case.best_pointer_writes,
        canonical_index_cleared: case.canonical_index_cleared,
        pending_tree_cleared: case.pending_tree_cleared,
        pending_action_removals: case.pending_action_removals,
        pending_action_writes: case.pending_action_writes,
        commitment_writes: case.commitment_writes,
        nullifier_writes: case.nullifier_writes,
        bridge_replay_writes: case.bridge_replay_writes,
        ciphertext_index_writes: case.ciphertext_index_writes,
        ciphertext_archive_writes: case.ciphertext_archive_writes,
        staged_ciphertext_removals: case.staged_ciphertext_removals,
    };
    let actual_rejection = evaluate_native_mined_block_commit_publication_rejection(
        mined_work,
        block_commitment,
        commit_manifest,
    );
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native mined-block commit publication validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native mined-block commit publication rejection drifted from Lean spec",
        case.name
    );
}

fn evaluate_native_mined_block_commit_publication_rejection(
    mined_work: NativeMinedWorkAdmissionInput,
    block_commitment: NativeBlockCommitmentAdmissionInput,
    commit_manifest: NativeAtomicCommitManifestAdmissionInput,
) -> Option<String> {
    if evaluate_native_mined_work_admission(mined_work).is_err() {
        Some("mined_work_rejected".to_owned())
    } else if evaluate_native_block_commitment_admission(block_commitment).is_err() {
        Some("block_commitment_rejected".to_owned())
    } else if !matches!(
        commit_manifest.kind,
        NativeAtomicCommitKind::MinedBlockCommit
    ) {
        Some("commit_kind_mismatch".to_owned())
    } else if evaluate_native_atomic_commit_manifest_admission(commit_manifest).is_err() {
        Some("commit_manifest_rejected".to_owned())
    } else {
        None
    }
}

#[test]
fn lean_generated_native_miner_identity_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_NATIVE_MINER_IDENTITY_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_NATIVE_MINER_IDENTITY_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean native miner identity vectors");
    let vectors: LeanNativeMinerIdentityVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean native miner identity vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        vectors.native_miner_identity_cases.len() >= 10,
        "Lean native miner identity cases cover too few policy branches"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.native_miner_identity_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_native_miner_identity_case(case);
    }
}

fn verify_lean_native_miner_identity_case(case: &LeanNativeMinerIdentityCase) {
    let input = NativeMinerIdentityAdmissionInput {
        height: case.height,
        public_key_len: case.public_key_len,
        signature_len: case.signature_len,
        public_key_bytes_parse: case.public_key_bytes_parse,
        miner_commitment_matches: case.miner_commitment_matches,
        signature_bytes_parse: case.signature_bytes_parse,
        signature_verifies: case.signature_verifies,
    };
    let actual_rejection = evaluate_native_miner_identity_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native miner identity validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native miner identity rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_work_template_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_WORK_TEMPLATE_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_WORK_TEMPLATE_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean work-template admission vectors");
    let vectors: LeanWorkTemplateAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean work-template vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.work_template_admission_cases.is_empty(),
        "Lean work-template admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.work_template_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_work_template_admission_case(case);
    }
}

fn verify_lean_work_template_admission_case(case: &LeanWorkTemplateAdmissionCase) {
    let input = NativeWorkTemplateAdmissionInput {
        best_height: case.best_height,
        cumulative_work_advances: case.cumulative_work_advances,
    };
    let actual = evaluate_native_work_template_admission(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native work-template admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.ok(),
        case.expected_height,
        "{} native work-template height drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native work-template admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_recursive_artifact_context_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_RECURSIVE_ARTIFACT_CONTEXT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean recursive artifact context admission vectors");
    let vectors: LeanRecursiveArtifactContextAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean recursive artifact context vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors
            .recursive_artifact_context_admission_cases
            .is_empty(),
        "Lean recursive artifact context admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.recursive_artifact_context_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_recursive_artifact_context_admission_case(case);
    }
}

fn verify_lean_recursive_artifact_context_admission_case(
    case: &LeanRecursiveArtifactContextAdmissionCase,
) {
    let input = NativeRecursiveArtifactContextAdmissionInput {
        best_height: case.best_height,
    };
    let actual = evaluate_native_recursive_artifact_context_admission(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native recursive artifact context admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.ok(),
        case.expected_height,
        "{} native recursive artifact context height drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native recursive artifact context rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_action_request_projection_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_REQUEST_PROJECTION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean action request projection admission vectors");
    let vectors: LeanActionRequestProjectionAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean action request projection admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_request_projection_admission_cases.is_empty(),
        "Lean action request projection admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_request_projection_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_request_projection_admission_case(case);
    }
}

fn verify_lean_action_request_projection_admission_case(
    case: &LeanActionRequestProjectionAdmissionCase,
) {
    let input = NativeActionRequestProjectionAdmissionInput {
        json_decode_accepts: case.json_decode_accepts,
        kernel_envelope_fields_absent: case.kernel_envelope_fields_absent,
        route_supported: case.route_supported,
        nullifier_scope_valid: case.nullifier_scope_valid,
        nullifier_count_within_limit: case.nullifier_count_within_limit,
        nullifier_hex_valid: case.nullifier_hex_valid,
        public_args_encoded_within_limit: case.public_args_encoded_within_limit,
        public_args_base64_decodes: case.public_args_base64_decodes,
        public_args_decoded_within_limit: case.public_args_decoded_within_limit,
        route_payload_decodes_exactly: case.route_payload_decodes_exactly,
    };
    let model = evaluate_native_action_request_projection_admission(input);
    let model_rejection = model
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        model.is_ok(),
        case.expected_valid,
        "{} Lean action request projection predicate fields disagree with expected validity",
        case.name
    );
    assert_eq!(
        model_rejection, case.expected_rejection,
        "{} Lean action request projection rejection drifted from Rust model",
        case.name
    );

    let request = action_request_projection_fixture(&case.fixture);
    let actual = decode_submit_action_rpc_request(request)
        .map_err(|_| NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected)
        .and_then(|request| evaluate_native_action_request_projection(&request).map(|_| ()));
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native action request projection validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native action request projection rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_action_request_raw_json_projection_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_REQUEST_RAW_JSON_PROJECTION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_REQUEST_RAW_JSON_PROJECTION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean action request raw JSON projection vectors");
    let vectors: LeanActionRequestRawJsonProjectionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean action request raw JSON projection vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_request_raw_json_projection_cases.is_empty(),
        "Lean action request raw JSON projection cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_request_raw_json_projection_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_request_raw_json_projection_case(case);
    }
}

fn verify_lean_action_request_raw_json_projection_case(
    case: &LeanActionRequestRawJsonProjectionCase,
) {
    let input = NativeActionRequestProjectionAdmissionInput {
        json_decode_accepts: case.json_decode_accepts,
        kernel_envelope_fields_absent: case.kernel_envelope_fields_absent,
        route_supported: case.route_supported,
        nullifier_scope_valid: case.nullifier_scope_valid,
        nullifier_count_within_limit: case.nullifier_count_within_limit,
        nullifier_hex_valid: case.nullifier_hex_valid,
        public_args_encoded_within_limit: case.public_args_encoded_within_limit,
        public_args_base64_decodes: case.public_args_base64_decodes,
        public_args_decoded_within_limit: case.public_args_decoded_within_limit,
        route_payload_decodes_exactly: case.route_payload_decodes_exactly,
    };
    let model = evaluate_native_action_request_projection_admission(input);
    let model_rejection = model
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        model.is_ok(),
        case.expected_valid,
        "{} Lean raw action request predicate fields disagree with expected validity",
        case.name
    );
    assert_eq!(
        model_rejection, case.expected_rejection,
        "{} Lean raw action request rejection drifted from Rust model",
        case.name
    );

    let raw_json = String::from_utf8(case.raw_json_bytes.clone())
        .unwrap_or_else(|err| panic!("{} raw JSON is not UTF-8: {err}", case.name));
    let actual = serde_json::from_str::<Value>(&raw_json)
        .map_err(|_| NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected)
        .and_then(|request| {
            decode_submit_action_rpc_request(request)
                .map_err(|_| NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected)
        })
        .and_then(|request| evaluate_native_action_request_projection(&request).map(|_| ()));
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native raw action request projection validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native raw action request projection rejection drifted from Lean spec",
        case.name
    );
}

fn action_request_projection_request_from_action(action: &PendingAction) -> Value {
    use base64::Engine;

    json!({
        "binding_circuit": action.binding.circuit,
        "binding_crypto": action.binding.crypto,
        "family_id": action.family_id,
        "action_id": action.action_id,
        "new_nullifiers": action.nullifiers.iter().map(hex48).collect::<Vec<_>>(),
        "public_args": base64::engine::general_purpose::STANDARD
            .encode(&action.public_args),
    })
}

fn test_bridge_verifier_registration_action() -> PendingAction {
    let args = BridgeVerifierRegistrationV1 {
        source_chain_id: [1u8; 32],
        verifier_program_hash: [2u8; 32],
        rules_hash: [3u8; 32],
        enabled_at_height: 42,
    };
    let mut action = test_empty_action(FAMILY_BRIDGE, ACTION_REGISTER_BRIDGE_VERIFIER, 0);
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_sidecar_transfer_empty_proof_action() -> PendingAction {
    let mut action = test_sidecar_transfer_action([31u8; 48], [32u8; 48], [33u8; 48], 7);
    let mut args: ShieldedTransferSidecarArgs =
        decode_scale_exact(&action.public_args, "test sidecar transfer args")
            .expect("decode sidecar transfer args");
    args.proof.clear();
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);
    action
}

fn action_request_projection_fixture(fixture: &str) -> Value {
    use base64::Engine;

    let outbound = OutboundBridgeArgsV1 {
        destination_chain_id: [7u8; 32],
        app_family_id: 9,
        payload: b"lean action projection".to_vec(),
    };
    let mut valid_payload = outbound.encode();
    let mut request = json!({
        "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        "family_id": FAMILY_BRIDGE,
        "action_id": ACTION_BRIDGE_OUTBOUND,
        "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD
            .encode(&valid_payload),
    });

    match fixture {
        "valid_empty_native_request" => request,
        "valid_empty_wallet_envelope_fields" => {
            let object = request.as_object_mut().expect("request object");
            object.insert("object_refs".to_owned(), json!([]));
            object.insert("authorization_proof".to_owned(), Value::Null);
            object.insert("authorization_signatures".to_owned(), json!([]));
            object.insert("aux_data".to_owned(), Value::Null);
            request
        }
        "valid_outbound_bridge_request" => action_request_projection_request_from_action(
            &test_outbound_bridge_action(b"lean outbound bridge"),
        ),
        "valid_inbound_bridge_request" => action_request_projection_request_from_action(
            &test_inbound_bridge_action(b"lean inbound bridge"),
        ),
        "valid_bridge_verifier_registration_request" => {
            action_request_projection_request_from_action(
                &test_bridge_verifier_registration_action(),
            )
        }
        "valid_inline_transfer_request" => action_request_projection_request_from_action(
            &test_inline_transfer_action([21u8; 48], [22u8; 48], [23u8; 48], 3),
        ),
        "valid_sidecar_transfer_request" => action_request_projection_request_from_action(
            &test_sidecar_transfer_action([24u8; 48], [25u8; 48], [26u8; 48], 5),
        ),
        "valid_sidecar_empty_proof_request" => action_request_projection_request_from_action(
            &test_sidecar_transfer_empty_proof_action(),
        ),
        "valid_candidate_artifact_request" => {
            action_request_projection_request_from_action(&test_candidate_artifact_action(1, 0x5a))
        }
        "valid_coinbase_request" => {
            action_request_projection_request_from_action(&test_coinbase_action(42))
        }
        "unknown_field" => {
            request
                .as_object_mut()
                .expect("request object")
                .insert("statement_hash".to_owned(), json!("00"));
            request
        }
        "object_ref_present" => {
            request.as_object_mut().expect("request object").insert(
                "object_refs".to_owned(),
                json!([{
                    "family_id": FAMILY_SHIELDED_POOL,
                    "object_id": "00",
                    "expected_root": "00",
                }]),
            );
            request
        }
        "authorization_proof_present" => {
            request
                .as_object_mut()
                .expect("request object")
                .insert("authorization_proof".to_owned(), json!("AA=="));
            request
        }
        "authorization_signature_present" => {
            request.as_object_mut().expect("request object").insert(
                "authorization_signatures".to_owned(),
                json!([{
                    "key_id": "00",
                    "signature_scheme": 1,
                    "signature_bytes": "AA==",
                }]),
            );
            request
        }
        "aux_data_present" => {
            request
                .as_object_mut()
                .expect("request object")
                .insert("aux_data".to_owned(), json!("AA=="));
            request
        }
        "unsupported_route" => {
            request
                .as_object_mut()
                .expect("request object")
                .insert("action_id".to_owned(), json!(u16::MAX));
            request
        }
        "non_transfer_nullifiers" => {
            request
                .as_object_mut()
                .expect("request object")
                .insert("new_nullifiers".to_owned(), json!([hex::encode([0u8; 48])]));
            request
        }
        "too_many_nullifiers" => {
            let nullifiers =
                vec![hex::encode([0u8; 48]); transaction_core::constants::MAX_INPUTS + 1];
            let object = request.as_object_mut().expect("request object");
            object.insert("family_id".to_owned(), json!(FAMILY_SHIELDED_POOL));
            object.insert(
                "action_id".to_owned(),
                json!(ACTION_SHIELDED_TRANSFER_INLINE),
            );
            object.insert("new_nullifiers".to_owned(), json!(nullifiers));
            request
        }
        "invalid_nullifier_hex" => {
            let object = request.as_object_mut().expect("request object");
            object.insert("family_id".to_owned(), json!(FAMILY_SHIELDED_POOL));
            object.insert(
                "action_id".to_owned(),
                json!(ACTION_SHIELDED_TRANSFER_INLINE),
            );
            object.insert("new_nullifiers".to_owned(), json!(["not-hex"]));
            request
        }
        "encoded_public_args_too_large" => {
            request.as_object_mut().expect("request object").insert(
                "public_args".to_owned(),
                json!("A".repeat(encoded_len_limit(MAX_NATIVE_RPC_ACTION_BYTES) + 1)),
            );
            request
        }
        "base64_public_args_rejected" => {
            request
                .as_object_mut()
                .expect("request object")
                .insert("public_args".to_owned(), json!("not base64!"));
            request
        }
        "decoded_public_args_too_large" => {
            request.as_object_mut().expect("request object").insert(
                "public_args".to_owned(),
                json!(base64::engine::general_purpose::STANDARD.encode(vec![
                    0u8;
                    MAX_NATIVE_RPC_ACTION_BYTES
                        + 1
                ])),
            );
            request
        }
        "route_payload_decode_rejected" => {
            valid_payload.push(0xaa);
            request.as_object_mut().expect("request object").insert(
                "public_args".to_owned(),
                json!(base64::engine::general_purpose::STANDARD.encode(valid_payload)),
            );
            request
        }
        other => panic!("unknown Lean action request projection fixture {other}"),
    }
}

#[test]
fn action_request_projection_accepts_supported_route_fixtures() {
    let fixtures = [
        "valid_outbound_bridge_request",
        "valid_inbound_bridge_request",
        "valid_bridge_verifier_registration_request",
        "valid_inline_transfer_request",
        "valid_sidecar_transfer_request",
        "valid_sidecar_empty_proof_request",
        "valid_candidate_artifact_request",
        "valid_coinbase_request",
    ];

    for fixture in fixtures {
        let request = action_request_projection_fixture(fixture);
        let request = decode_submit_action_rpc_request(request)
            .unwrap_or_else(|err| panic!("{fixture} request decode failed: {err:#}"));
        evaluate_native_action_request_projection(&request).unwrap_or_else(|rejection| {
            panic!("{fixture} projection rejected: {}", rejection.label())
        });
    }
}

#[test]
fn lean_generated_codec_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CODEC_ADMISSION_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_CODEC_ADMISSION_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read generated Lean codec admission vectors");
    let vectors: LeanCodecAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean codec admission vectors");
    assert_eq!(vectors.schema_version, 3);
    assert!(
        !vectors.sync_codec_cases.is_empty()
            && !vectors.exact_decode_cases.is_empty()
            && !vectors.block_action_decode_cases.is_empty()
            && !vectors.native_metadata_decode_cases.is_empty()
            && !vectors.native_metadata_bincode_budget_cases.is_empty(),
        "Lean codec admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.sync_codec_cases {
        assert!(names.insert(format!("sync:{}", case.name)));
        verify_lean_sync_codec_case(case);
    }
    for case in &vectors.exact_decode_cases {
        assert!(names.insert(format!("exact:{}", case.name)));
        verify_lean_exact_decode_case(case);
    }
    for case in &vectors.block_action_decode_cases {
        assert!(names.insert(format!("block-action:{}", case.name)));
        verify_lean_block_action_decode_case(case);
    }
    for case in &vectors.native_metadata_decode_cases {
        assert!(names.insert(format!("native-metadata:{}", case.name)));
        verify_lean_native_metadata_decode_case(case);
    }
    for case in &vectors.native_metadata_bincode_budget_cases {
        assert!(names.insert(format!("native-metadata-budget:{}", case.name)));
        verify_lean_native_metadata_bincode_budget_case(case);
    }
}

fn verify_lean_sync_codec_case(case: &LeanSyncCodecCase) {
    assert_eq!(
        case.bounded_wire_decode_accepts && case.consumed_all_bytes,
        case.expected_valid,
        "{} Lean sync codec predicate fields disagree with expected validity",
        case.name
    );
    if case.legacy_bincode_payload {
        assert_eq!(
            case.fixture, "legacy_bincode_request",
            "{} legacy bincode flag must only be used by the legacy fixture",
            case.name
        );
    }

    let message = NativeSyncMessage::Request {
        from_height: 1,
        to_height: 2,
    };
    let payload = match case.fixture.as_str() {
        "valid_request" => encode_sync_message(&message).expect("encode native sync message"),
        "legacy_bincode_request" => {
            bincode::serialize(&message).expect("legacy bincode sync message")
        }
        "valid_request_trailing" => {
            let mut encoded = encode_sync_message(&message).expect("encode native sync message");
            encoded.push(0);
            encoded
        }
        other => panic!("unknown Lean sync codec fixture {other}"),
    };
    let actual = decode_sync_message(&payload);
    let actual_rejection = if actual.is_ok() {
        None
    } else if case.fixture == "valid_request_trailing" {
        Some("trailing_bytes".to_owned())
    } else {
        Some("wire_decode_rejected".to_owned())
    };
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native sync codec validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native sync codec rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_exact_decode_case(case: &LeanExactDecodeCase) {
    assert_eq!(
        case.parser_accepts && case.consumed_all_bytes && case.canonical_reencode_matches,
        case.expected_valid,
        "{} Lean exact-decode predicate fields disagree with expected validity",
        case.name
    );
    let actual = match (case.codec.as_str(), case.fixture.as_str()) {
        ("scale_pending_action", "valid_pending_action") => {
            let action = test_outbound_bridge_action(b"lean codec admission");
            decode_scale_exact::<PendingAction>(&action.encode(), "Lean pending action").map(|_| ())
        }
        ("scale_pending_action", "trailing_pending_action") => {
            let action = test_outbound_bridge_action(b"lean codec admission");
            let mut encoded = action.encode();
            encoded.push(0xaa);
            decode_scale_exact::<PendingAction>(&encoded, "Lean pending action").map(|_| ())
        }
        ("scale_normalizing_fixture", "noncanonical_byte") => {
            decode_scale_exact::<NormalizedScaleByte>(&[1], "Lean normalized SCALE byte")
                .map(|_| ())
        }
        ("bincode_native_meta", "valid_genesis_meta") => {
            let meta = genesis_meta(0x207f_ffff).expect("genesis");
            let encoded = bincode::serialize(&meta).expect("serialize native meta");
            bincode_deserialize_exact::<NativeBlockMeta>(&encoded, "Lean native metadata")
                .map(|_| ())
        }
        ("bincode_native_meta", "trailing_genesis_meta") => {
            let meta = genesis_meta(0x207f_ffff).expect("genesis");
            let mut encoded = bincode::serialize(&meta).expect("serialize native meta");
            encoded.push(0xbb);
            bincode_deserialize_exact::<NativeBlockMeta>(&encoded, "Lean native metadata")
                .map(|_| ())
        }
        ("bincode_normalizing_fixture", "noncanonical_byte") => {
            let encoded = bincode::serialize(&1u8).expect("serialize noncanonical byte");
            bincode_deserialize_exact::<NormalizedBincodeByte>(
                &encoded,
                "Lean normalized bincode byte",
            )
            .map(|_| ())
        }
        (codec, fixture) => {
            panic!("unknown Lean exact-decode case codec={codec} fixture={fixture}")
        }
    };
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native exact-decode validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native exact-decode rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_native_metadata_decode_case(case: &LeanNativeMetadataDecodeCase) {
    let current_exact_accepts = case.current_parser_accepts
        && case.current_consumed_all_bytes
        && case.current_canonical_reencode_matches;
    let legacy_exact_accepts = case.legacy_parser_accepts
        && case.legacy_consumed_all_bytes
        && case.legacy_canonical_reencode_matches;
    let expected_source = if current_exact_accepts {
        Some("current".to_owned())
    } else if legacy_exact_accepts {
        Some("legacy".to_owned())
    } else {
        None
    };
    assert_eq!(
        expected_source.is_some(),
        case.expected_valid,
        "{} Lean native metadata decode fields disagree with expected validity",
        case.name
    );
    assert_eq!(
        expected_source, case.expected_source,
        "{} Lean native metadata source drifted from current-first/legacy-fallback spec",
        case.name
    );

    let parent = genesis_meta(0x207f_ffff).expect("genesis");
    let current = mined_empty_child(&parent, 1, 0x207f_ffff, 0);
    let legacy = legacy_meta_from_current(&current);
    let payload = match case.fixture.as_str() {
        "current_signed_meta" => bincode::serialize(&current).expect("serialize current meta"),
        "legacy_unsigned_meta" => bincode::serialize(&legacy).expect("serialize legacy meta"),
        "current_signed_meta_trailing" => {
            let mut encoded = bincode::serialize(&current).expect("serialize current meta");
            encoded.push(0xcc);
            encoded
        }
        "legacy_unsigned_meta_trailing" => {
            let mut encoded = bincode::serialize(&legacy).expect("serialize legacy meta");
            encoded.push(0xdd);
            encoded
        }
        other => panic!("unknown Lean native metadata fixture {other}"),
    };
    let current_exact =
        bincode_deserialize_exact::<NativeBlockMeta>(&payload, "Lean current native metadata")
            .is_ok();
    let legacy_exact = bincode_deserialize_exact::<LegacyNativeBlockMetaV1>(
        &payload,
        "Lean legacy native metadata",
    )
    .is_ok();
    let actual_source = if current_exact {
        Some("current".to_owned())
    } else if legacy_exact {
        Some("legacy".to_owned())
    } else {
        None
    };
    let actual = bincode_deserialize_native_block_meta_exact(&payload, "Lean native metadata");
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|_| "current_and_legacy_rejected".to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native metadata decode validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_source, case.expected_source,
        "{} native metadata decode source drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native metadata decode rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_native_metadata_bincode_budget_case(case: &LeanNativeMetadataBincodeBudgetCase) {
    assert_eq!(case.max_metadata_bytes, MAX_NATIVE_BLOCK_META_BYTES);
    assert_eq!(case.max_action_count, MAX_NATIVE_BLOCK_ACTIONS);
    assert_eq!(
        case.max_action_payload_bytes,
        MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES
    );
    assert_eq!(
        case.max_action_payload_bytes_total,
        MAX_NATIVE_BLOCK_ACTION_BYTES
    );
    assert_eq!(case.max_miner_public_key_bytes, ML_DSA_PUBLIC_KEY_LEN);
    assert_eq!(case.max_miner_signature_bytes, ML_DSA_SIGNATURE_LEN);

    let actual_rejection = lean_native_metadata_bincode_budget_rejection(case);
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} Lean native metadata bincode budget validity drifted from production constants",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} Lean native metadata bincode budget rejection drifted from production constants",
        case.name
    );

    if let Some(actual) = production_native_metadata_bincode_budget_fixture_rejection(case) {
        assert_eq!(
            actual, case.expected_rejection,
            "{} production native metadata bincode pre-scan rejection drifted from Lean fixture",
            case.name
        );
    }
}

fn lean_native_metadata_bincode_budget_rejection(
    case: &LeanNativeMetadataBincodeBudgetCase,
) -> Option<String> {
    if case.metadata_bytes > case.max_metadata_bytes {
        Some("metadata_bytes_over_limit".to_owned())
    } else if case.action_count > case.max_action_count {
        Some("action_count_over_limit".to_owned())
    } else if case.largest_action_payload_bytes > case.max_action_payload_bytes {
        Some("action_payload_over_limit".to_owned())
    } else if case.action_payload_bytes_total > case.max_action_payload_bytes_total {
        Some("action_payload_bytes_over_limit".to_owned())
    } else if case.miner_public_key_bytes > case.max_miner_public_key_bytes {
        Some("miner_public_key_over_limit".to_owned())
    } else if case.miner_signature_bytes > case.max_miner_signature_bytes {
        Some("miner_signature_over_limit".to_owned())
    } else {
        None
    }
}

fn production_native_metadata_bincode_budget_fixture_rejection(
    case: &LeanNativeMetadataBincodeBudgetCase,
) -> Option<Option<String>> {
    let bytes = match case.fixture.as_str() {
        "valid_current_metadata" => {
            let meta = genesis_meta(0x207f_ffff).expect("genesis");
            bincode::serialize(&meta).expect("serialize current metadata")
        }
        "action_count_overrun" => {
            let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
            bytes.extend_from_slice(&((MAX_NATIVE_BLOCK_ACTIONS as u64) + 1).to_le_bytes());
            bytes
        }
        "action_payload_overrun" => {
            let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
            bytes.extend_from_slice(&1u64.to_le_bytes());
            bytes.extend_from_slice(
                &((MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES as u64) + 1).to_le_bytes(),
            );
            bytes
        }
        "miner_public_key_overrun" => {
            let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&48u64.to_le_bytes());
            bytes.extend_from_slice(&[0u8; 48]);
            bytes.extend_from_slice(&((ML_DSA_PUBLIC_KEY_LEN as u64) + 1).to_le_bytes());
            bytes
        }
        "miner_signature_overrun" => {
            let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&48u64.to_le_bytes());
            bytes.extend_from_slice(&[0u8; 48]);
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&((ML_DSA_SIGNATURE_LEN as u64) + 1).to_le_bytes());
            bytes
        }
        "metadata_bytes_overrun" | "action_payload_bytes_overrun" => return None,
        other => panic!("unknown Lean native metadata bincode budget fixture {other}"),
    };
    let actual = validate_native_block_meta_bincode_budget(&bytes, "Lean native metadata budget")
        .err()
        .map(|err| {
            let message = err.to_string();
            if message.contains("metadata limit") {
                "metadata_bytes_over_limit".to_owned()
            } else if message.contains("action byte count exceeds") {
                "action_count_over_limit".to_owned()
            } else if message.contains("action payload") {
                "action_payload_over_limit".to_owned()
            } else if message.contains("action bytes exceed aggregate") {
                "action_payload_bytes_over_limit".to_owned()
            } else if message.contains("miner public key") {
                "miner_public_key_over_limit".to_owned()
            } else if message.contains("miner signature") {
                "miner_signature_over_limit".to_owned()
            } else {
                panic!("unknown native metadata bincode budget rejection: {message}")
            }
        });
    Some(actual)
}

fn verify_lean_block_action_decode_case(case: &LeanBlockActionDecodeCase) {
    assert_eq!(
        (case.declared_tx_count == case.actual_action_payload_count)
            && case.every_action_decodes_exactly,
        case.expected_valid,
        "{} Lean block-action decode predicate fields disagree with expected validity",
        case.name
    );

    let mut block = genesis_meta(0x207f_ffff).expect("genesis");
    let action = test_outbound_bridge_action(b"lean codec admission");
    match case.fixture.as_str() {
        "valid_one_action" => {
            block.tx_count =
                u32::try_from(case.declared_tx_count).expect("test tx_count must fit u32");
            block.action_bytes = vec![action.encode()];
        }
        "count_mismatch" => {
            block.tx_count =
                u32::try_from(case.declared_tx_count).expect("test tx_count must fit u32");
            block.action_bytes = Vec::new();
        }
        "trailing_action_payload" => {
            block.tx_count =
                u32::try_from(case.declared_tx_count).expect("test tx_count must fit u32");
            let mut encoded = action.encode();
            encoded.push(0xcc);
            block.action_bytes = vec![encoded];
        }
        other => panic!("unknown Lean block-action decode fixture {other}"),
    }
    assert_eq!(
        block.action_bytes.len(),
        case.actual_action_payload_count,
        "{} fixture action payload count drifted from Lean vector",
        case.name
    );

    let actual = decode_block_actions(&block);
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("count mismatch") {
            "action_count_mismatch".to_owned()
        } else {
            "action_decode_not_exact".to_owned()
        }
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native block-action decode validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native block-action decode rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_pending_action_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_PENDING_ACTION_SCALE_WIRE_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_PENDING_ACTION_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean pending-action SCALE wire vectors");
    let vectors: LeanPendingActionScaleWireVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean pending-action SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.pending_action_scale_wire_cases.is_empty(),
        "Lean pending-action SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.pending_action_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_pending_action_scale_wire_case(case);
    }
}

fn expected_candidate_artifact_payload_len(case: &LeanPendingActionScaleWireCase) -> usize {
    if case.candidate_artifact_none {
        0
    } else {
        let receipt_root_payload_len = if case.candidate_artifact_receipt_root_none {
            0
        } else {
            case.candidate_artifact_receipt_root_proof_compact_prefix_bytes
                + case.candidate_artifact_receipt_root_proof_bytes
                + case.candidate_artifact_receipt_root_relation_id_bytes
                + case.candidate_artifact_receipt_root_shape_digest_bytes
                + case.candidate_artifact_receipt_root_leaf_count_bytes
                + case.candidate_artifact_receipt_root_fold_count_bytes
                + case.candidate_artifact_receipt_root_receipt_compact_prefix_bytes
                + case.candidate_artifact_receipt_root_receipt_count
                    * case.candidate_artifact_receipt_root_receipt_element_bytes
        };
        let recursive_block_payload_len = if case.candidate_artifact_recursive_block_present {
            1 + case.candidate_artifact_recursive_proof_bytes
        } else {
            0
        };
        1 + 4
            + case.candidate_artifact_tx_statements_commitment_bytes
            + case.candidate_artifact_da_root_bytes
            + 4
            + (1 + case.candidate_artifact_commitment_proof_bytes)
            + case.candidate_artifact_proof_mode_bytes
            + case.candidate_artifact_proof_kind_bytes
            + case.candidate_artifact_verifier_profile_bytes
            + case.candidate_artifact_receipt_root_option_tag_bytes
            + receipt_root_payload_len
            + case.candidate_artifact_recursive_block_option_tag_bytes
            + recursive_block_payload_len
    }
}

fn expected_pending_action_encoded_len(case: &LeanPendingActionScaleWireCase) -> usize {
    32 + 4
        + 2
        + 2
        + 48
        + (1 + 48 * case.nullifier_count)
        + (1 + 48 * case.commitment_count)
        + (1 + 48 * case.ciphertext_hash_count)
        + (1 + 4 * case.ciphertext_size_count)
        + (case.public_args_compact_prefix_bytes + case.public_args_bytes)
        + 8
        + 1
        + case.candidate_artifact_payload_bytes
        + 8
}

fn decode_lean_hex(raw_hex: &str) -> Vec<u8> {
    let clean = raw_hex.strip_prefix("0x").unwrap_or(raw_hex);
    hex::decode(clean).expect("Lean vector raw_hex must be valid hex")
}

fn expected_pending_action_scale_wire_fixture(
    case: &LeanPendingActionScaleWireCase,
) -> PendingAction {
    match case.fixture.as_str() {
        "valid_empty_no_candidate" => PendingAction {
            tx_hash: [0u8; 32],
            binding: KernelVersionBinding {
                circuit: 0,
                crypto: 0,
            },
            family_id: 0,
            action_id: 0,
            anchor: [0u8; 48],
            nullifiers: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            public_args: Vec::new(),
            fee: 0,
            candidate_artifact: None,
            received_ms: 0,
        },
        "valid_one_each_no_candidate" => PendingAction {
            tx_hash: [9u8; 32],
            binding: KernelVersionBinding {
                circuit: 7,
                crypto: 8,
            },
            family_id: 10,
            action_id: 11,
            anchor: [12u8; 48],
            nullifiers: vec![[1u8; 48]],
            commitments: vec![[2u8; 48]],
            ciphertext_hashes: vec![[3u8; 48]],
            ciphertext_sizes: vec![4],
            public_args: vec![0xaa, 0xbb, 0xcc],
            fee: 5,
            candidate_artifact: None,
            received_ms: 6,
        },
        "valid_candidate_artifact_some" => {
            let artifact = CandidateArtifact {
                version: BLOCK_PROOF_BUNDLE_SCHEMA,
                tx_count: 1,
                tx_statements_commitment: [5u8; 48],
                da_root: [6u8; 48],
                da_chunk_count: 1,
                commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
                proof_mode: BlockProofMode::RecursiveBlock,
                proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
                verifier_profile: [7u8; 48],
                receipt_root: None,
                recursive_block: Some(protocol_shielded_pool::types::RecursiveBlockProofPayload {
                    proof: protocol_shielded_pool::types::StarkProof {
                        data: vec![8u8; 32],
                    },
                }),
            };
            PendingAction {
                tx_hash: [13u8; 32],
                binding: KernelVersionBinding {
                    circuit: 0,
                    crypto: 0,
                },
                family_id: FAMILY_SHIELDED_POOL,
                action_id: ACTION_SUBMIT_CANDIDATE_ARTIFACT,
                anchor: [0u8; 48],
                nullifiers: Vec::new(),
                commitments: Vec::new(),
                ciphertext_hashes: Vec::new(),
                ciphertext_sizes: Vec::new(),
                public_args: SubmitCandidateArtifactArgs {
                    payload: artifact.clone(),
                }
                .encode(),
                fee: 0,
                candidate_artifact: Some(artifact),
                received_ms: 9,
            }
        }
        "valid_candidate_artifact_some_receipt_root_slice" => {
            let artifact = CandidateArtifact {
                version: BLOCK_PROOF_BUNDLE_SCHEMA,
                tx_count: 1,
                tx_statements_commitment: [0x15u8; 48],
                da_root: [0x16u8; 48],
                da_chunk_count: 1,
                commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
                proof_mode: BlockProofMode::ReceiptRoot,
                proof_kind: PoolProofArtifactKind::ReceiptRoot,
                verifier_profile: [0x17u8; 48],
                receipt_root: Some(ReceiptRootProofPayload {
                    root_proof: protocol_shielded_pool::types::StarkProof {
                        data: vec![0x21, 0x22, 0x23],
                    },
                    metadata: ReceiptRootMetadata {
                        relation_id: [0x24u8; 32],
                        shape_digest: [0x25u8; 32],
                        leaf_count: 1,
                        fold_count: 0,
                    },
                    receipts: vec![TxValidityReceipt {
                        statement_hash: [0x31u8; 48],
                        proof_digest: [0x32u8; 48],
                        public_inputs_digest: [0x33u8; 48],
                        verifier_profile: [0x34u8; 48],
                    }],
                }),
                recursive_block: None,
            };
            PendingAction {
                tx_hash: [14u8; 32],
                binding: KernelVersionBinding {
                    circuit: 0,
                    crypto: 0,
                },
                family_id: FAMILY_SHIELDED_POOL,
                action_id: ACTION_SUBMIT_CANDIDATE_ARTIFACT,
                anchor: [0u8; 48],
                nullifiers: Vec::new(),
                commitments: Vec::new(),
                ciphertext_hashes: Vec::new(),
                ciphertext_sizes: Vec::new(),
                public_args: SubmitCandidateArtifactArgs {
                    payload: artifact.clone(),
                }
                .encode(),
                fee: 0,
                candidate_artifact: Some(artifact),
                received_ms: 10,
            }
        }
        other => panic!("no valid PendingAction fixture for {other}"),
    }
}

fn verify_lean_pending_action_scale_wire_case(case: &LeanPendingActionScaleWireCase) {
    let fixed_fields_ok = case.tx_hash_bytes == 32
        && case.binding_bytes == 4
        && case.family_id_bytes == 2
        && case.action_id_bytes == 2
        && case.anchor_bytes == 48
        && case.fee_bytes == 8
        && case.candidate_option_tag_bytes == 1
        && case.received_ms_bytes == 8;
    let vector_elements_ok = case.nullifier_element_bytes == 48
        && case.commitment_element_bytes == 48
        && case.ciphertext_hash_element_bytes == 48
        && case.ciphertext_size_element_bytes == 4;
    let candidate_artifact_some_fields_ok = case.candidate_artifact_version_bytes == 1
        && case.candidate_artifact_tx_count_bytes == 4
        && case.candidate_artifact_tx_statements_commitment_bytes == 48
        && case.candidate_artifact_da_root_bytes == 48
        && case.candidate_artifact_da_chunk_count_bytes == 4
        && case.candidate_artifact_proof_mode_bytes == 1
        && case.candidate_artifact_proof_kind_bytes == 1
        && case.candidate_artifact_verifier_profile_bytes == 48
        && case.candidate_artifact_receipt_root_option_tag_bytes == 1
        && case.candidate_artifact_recursive_block_option_tag_bytes == 1;
    let receipt_root_payload_ok = case.candidate_artifact_receipt_root_none
        || (case.candidate_artifact_receipt_root_proof_compact_prefix_bytes == 1
            && case.candidate_artifact_receipt_root_relation_id_bytes == 32
            && case.candidate_artifact_receipt_root_shape_digest_bytes == 32
            && case.candidate_artifact_receipt_root_leaf_count_bytes == 4
            && case.candidate_artifact_receipt_root_fold_count_bytes == 4
            && case.candidate_artifact_receipt_root_receipt_compact_prefix_bytes == 1
            && case.candidate_artifact_receipt_root_receipt_element_bytes == 192);
    let candidate_artifact_optional_payload_ok = !case.candidate_artifact_receipt_root_none
        || case.candidate_artifact_recursive_block_present;
    let expected_candidate_payload_len = expected_candidate_artifact_payload_len(case);
    let candidate_payload_ok = case.candidate_artifact_payload_bytes
        == expected_candidate_payload_len
        && (case.candidate_artifact_none
            || (candidate_artifact_some_fields_ok
                && receipt_root_payload_ok
                && candidate_artifact_optional_payload_ok));
    let expected_len = expected_pending_action_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && vector_elements_ok
        && candidate_payload_ok
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.compact_prefixes_canonical
        && case.canonical_reencode_matches;
    assert_eq!(
        lean_predicate_accepts, case.expected_valid,
        "{} Lean pending-action SCALE predicate fields disagree with expected validity",
        case.name
    );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_pending_action_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production PendingAction::encode",
            case.name
        );
    }

    let actual = decode_scale_exact::<PendingAction>(&raw, "Lean pending action SCALE wire");
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} production PendingAction exact decode validity drifted from Lean wire spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} production PendingAction exact decode rejection drifted from Lean wire spec",
        case.name
    );

    if let Ok(action) = actual {
        assert_eq!(action.nullifiers.len(), case.nullifier_count);
        assert_eq!(action.commitments.len(), case.commitment_count);
        assert_eq!(action.ciphertext_hashes.len(), case.ciphertext_hash_count);
        assert_eq!(action.ciphertext_sizes.len(), case.ciphertext_size_count);
        assert_eq!(action.public_args.len(), case.public_args_bytes);
        assert_eq!(
            action.candidate_artifact.is_none(),
            case.candidate_artifact_none
        );
        if let Some(artifact) = action.candidate_artifact.as_ref() {
            let args: SubmitCandidateArtifactArgs =
                decode_scale_exact(&action.public_args, "Lean candidate action args")
                    .expect("valid Lean candidate action args must exact-decode");
            assert_eq!(
                args.payload, *artifact,
                "{} candidate public_args must match candidate_artifact",
                case.name
            );
            assert_eq!(usize::from(artifact.version), 2);
            assert_eq!(artifact.tx_count, 1);
            assert_eq!(
                artifact.commitment_proof.data.len(),
                case.candidate_artifact_commitment_proof_bytes
            );
            assert_eq!(
                artifact.receipt_root.is_none(),
                case.candidate_artifact_receipt_root_none
            );
            if let Some(receipt_root) = artifact.receipt_root.as_ref() {
                assert_eq!(
                    receipt_root.root_proof.data.len(),
                    case.candidate_artifact_receipt_root_proof_bytes
                );
                assert_eq!(
                    receipt_root.metadata.relation_id.len(),
                    case.candidate_artifact_receipt_root_relation_id_bytes
                );
                assert_eq!(
                    receipt_root.metadata.shape_digest.len(),
                    case.candidate_artifact_receipt_root_shape_digest_bytes
                );
                assert_eq!(case.candidate_artifact_receipt_root_leaf_count_bytes, 4);
                assert_eq!(case.candidate_artifact_receipt_root_fold_count_bytes, 4);
                assert_eq!(
                    receipt_root.receipts.len(),
                    case.candidate_artifact_receipt_root_receipt_count
                );
                for receipt in &receipt_root.receipts {
                    assert_eq!(
                        receipt.encoded_size(),
                        case.candidate_artifact_receipt_root_receipt_element_bytes
                    );
                }
            }
            assert_eq!(
                artifact.recursive_block.is_some(),
                case.candidate_artifact_recursive_block_present
            );
            assert_eq!(
                artifact
                    .recursive_block
                    .as_ref()
                    .map_or(0, |recursive| recursive.proof.data.len()),
                case.candidate_artifact_recursive_proof_bytes
            );
        }
        assert_eq!(action.encode().len(), case.total_bytes);
    }
}

#[test]
fn lean_generated_candidate_artifact_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CANDIDATE_ARTIFACT_SCALE_WIRE_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_CANDIDATE_ARTIFACT_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean candidate-artifact SCALE wire vectors");
    let vectors: LeanCandidateArtifactScaleWireVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean candidate-artifact SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.candidate_artifact_scale_wire_cases.is_empty(),
        "Lean candidate-artifact SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.candidate_artifact_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_candidate_artifact_scale_wire_case(case);
    }
}

fn expected_candidate_artifact_scale_wire_encoded_len(
    case: &LeanCandidateArtifactScaleWireCase,
) -> usize {
    let commitment_proof_len =
        case.commitment_proof_compact_prefix_bytes + case.commitment_proof_bytes;
    let receipt_root_payload_len = if case.receipt_root_none {
        0
    } else {
        case.receipt_root_proof_compact_prefix_bytes
            + case.receipt_root_proof_bytes
            + case.receipt_root_relation_id_bytes
            + case.receipt_root_shape_digest_bytes
            + case.receipt_root_leaf_count_bytes
            + case.receipt_root_fold_count_bytes
            + case.receipt_root_receipt_compact_prefix_bytes
            + case.receipt_root_receipt_count * case.receipt_root_receipt_element_bytes
    };
    let recursive_payload_len = if case.recursive_block_present {
        case.recursive_proof_compact_prefix_bytes + case.recursive_proof_bytes
    } else {
        0
    };
    case.version_bytes
        + case.tx_count_bytes
        + case.tx_statements_commitment_bytes
        + case.da_root_bytes
        + case.da_chunk_count_bytes
        + commitment_proof_len
        + case.proof_mode_bytes
        + case.proof_kind_bytes
        + case.verifier_profile_bytes
        + case.receipt_root_option_tag_bytes
        + receipt_root_payload_len
        + case.recursive_block_option_tag_bytes
        + recursive_payload_len
}

fn expected_candidate_artifact_scale_wire_fixture(
    case: &LeanCandidateArtifactScaleWireCase,
) -> CandidateArtifact {
    match case.fixture.as_str() {
        "valid_recursive_block_v2" => CandidateArtifact {
            version: BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 1,
            tx_statements_commitment: [5u8; 48],
            da_root: [6u8; 48],
            da_chunk_count: 1,
            commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
            proof_mode: BlockProofMode::RecursiveBlock,
            proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
            verifier_profile: [7u8; 48],
            receipt_root: None,
            recursive_block: Some(protocol_shielded_pool::types::RecursiveBlockProofPayload {
                proof: protocol_shielded_pool::types::StarkProof {
                    data: vec![8u8; 32],
                },
            }),
        },
        "valid_receipt_root" => CandidateArtifact {
            version: BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 1,
            tx_statements_commitment: [0x15u8; 48],
            da_root: [0x16u8; 48],
            da_chunk_count: 1,
            commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
            proof_mode: BlockProofMode::ReceiptRoot,
            proof_kind: PoolProofArtifactKind::ReceiptRoot,
            verifier_profile: [0x17u8; 48],
            receipt_root: Some(ReceiptRootProofPayload {
                root_proof: protocol_shielded_pool::types::StarkProof {
                    data: vec![0x21, 0x22, 0x23],
                },
                metadata: ReceiptRootMetadata {
                    relation_id: [0x24u8; 32],
                    shape_digest: [0x25u8; 32],
                    leaf_count: 1,
                    fold_count: 0,
                },
                receipts: vec![TxValidityReceipt {
                    statement_hash: [0x31u8; 48],
                    proof_digest: [0x32u8; 48],
                    public_inputs_digest: [0x33u8; 48],
                    verifier_profile: [0x34u8; 48],
                }],
            }),
            recursive_block: None,
        },
        "valid_custom_proof_kind" => CandidateArtifact {
            version: BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 1,
            tx_statements_commitment: [5u8; 48],
            da_root: [6u8; 48],
            da_chunk_count: 1,
            commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
            proof_mode: BlockProofMode::RecursiveBlock,
            proof_kind: PoolProofArtifactKind::Custom([0x42u8; 16]),
            verifier_profile: [7u8; 48],
            receipt_root: None,
            recursive_block: Some(protocol_shielded_pool::types::RecursiveBlockProofPayload {
                proof: protocol_shielded_pool::types::StarkProof {
                    data: vec![8u8; 32],
                },
            }),
        },
        other => panic!("no valid CandidateArtifact fixture for {other}"),
    }
}

fn candidate_artifact_scale_wire_rejection_label(
    result: &Result<CandidateArtifact>,
) -> Option<String> {
    result.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    })
}

fn verify_lean_candidate_artifact_scale_wire_case(case: &LeanCandidateArtifactScaleWireCase) {
    let fixed_fields_ok = case.version_bytes == 1
        && case.tx_count_bytes == 4
        && case.tx_statements_commitment_bytes == 48
        && case.da_root_bytes == 48
        && case.da_chunk_count_bytes == 4
        && case.proof_mode_bytes == 1
        && case.proof_mode_tag_valid
        && (case.proof_kind_bytes == 1 || case.proof_kind_bytes == 17)
        && case.proof_kind_tag_valid
        && case.verifier_profile_bytes == 48
        && case.receipt_root_option_tag_bytes == 1
        && case.receipt_root_option_tag_valid
        && case.recursive_block_option_tag_bytes == 1
        && case.recursive_block_option_tag_valid;
    let receipt_root_payload_ok = case.receipt_root_none
        || (case.receipt_root_proof_compact_prefix_bytes >= 1
            && case.receipt_root_relation_id_bytes == 32
            && case.receipt_root_shape_digest_bytes == 32
            && case.receipt_root_leaf_count_bytes == 4
            && case.receipt_root_fold_count_bytes == 4
            && case.receipt_root_receipt_compact_prefix_bytes >= 1
            && case.receipt_root_receipt_element_bytes == 192);
    let recursive_block_payload_ok =
        !case.recursive_block_present || case.recursive_proof_compact_prefix_bytes >= 1;
    let expected_len = expected_candidate_artifact_scale_wire_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && receipt_root_payload_ok
        && recursive_block_payload_ok
        && case.compact_prefixes_canonical
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.canonical_reencode_matches;
    assert_eq!(
        lean_predicate_accepts, case.expected_valid,
        "{} Lean candidate-artifact SCALE predicate fields disagree with expected validity",
        case.name
    );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_candidate_artifact_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production CandidateArtifact::encode",
            case.name
        );
        assert_eq!(
            SubmitCandidateArtifactArgs {
                payload: expected.clone()
            }
            .encode(),
            raw,
            "{} Lean raw bytes drifted from production SubmitCandidateArtifactArgs::encode",
            case.name
        );
    }

    let actual_artifact =
        decode_scale_exact::<CandidateArtifact>(&raw, "Lean candidate artifact SCALE wire");
    let actual_rejection = candidate_artifact_scale_wire_rejection_label(&actual_artifact);
    assert_eq!(
        actual_artifact.is_ok(),
        case.expected_valid,
        "{} production CandidateArtifact exact decode validity drifted from Lean wire spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} production CandidateArtifact exact decode rejection drifted from Lean wire spec",
        case.name
    );

    let actual_submit = decode_scale_exact::<SubmitCandidateArtifactArgs>(
        &raw,
        "Lean submit candidate artifact args SCALE wire",
    );
    assert_eq!(
            actual_submit.is_ok(),
            case.expected_valid,
            "{} production SubmitCandidateArtifactArgs exact decode validity drifted from Lean wire spec",
            case.name
        );

    if let (Ok(artifact), Ok(args)) = (&actual_artifact, &actual_submit) {
        assert_eq!(
            args.payload, *artifact,
            "{} route payload must match decoded candidate artifact",
            case.name
        );
        assert_eq!(artifact.encoded_size(), case.total_bytes);
        assert_eq!(usize::from(artifact.version), 2);
        assert_eq!(artifact.tx_count, 1);
        assert_eq!(
            artifact.commitment_proof.data.len(),
            case.commitment_proof_bytes
        );
        assert_eq!(artifact.receipt_root.is_none(), case.receipt_root_none);
        if let Some(receipt_root) = artifact.receipt_root.as_ref() {
            assert_eq!(
                receipt_root.root_proof.data.len(),
                case.receipt_root_proof_bytes
            );
            assert_eq!(
                receipt_root.metadata.relation_id.len(),
                case.receipt_root_relation_id_bytes
            );
            assert_eq!(
                receipt_root.metadata.shape_digest.len(),
                case.receipt_root_shape_digest_bytes
            );
            assert_eq!(case.receipt_root_leaf_count_bytes, 4);
            assert_eq!(case.receipt_root_fold_count_bytes, 4);
            assert_eq!(receipt_root.receipts.len(), case.receipt_root_receipt_count);
            for receipt in &receipt_root.receipts {
                assert_eq!(
                    receipt.encoded_size(),
                    case.receipt_root_receipt_element_bytes
                );
            }
        }
        assert_eq!(
            artifact.recursive_block.is_some(),
            case.recursive_block_present
        );
        assert_eq!(
            artifact
                .recursive_block
                .as_ref()
                .map_or(0, |recursive| recursive.proof.data.len()),
            case.recursive_proof_bytes
        );
    }
}

#[test]
fn pending_action_exact_decode_matches_scale_decode_oracle_on_mutation_corpus() {
    let corpus = pending_action_exact_decode_equivalence_corpus();
    assert_scale_exact_decode_matches_raw_oracle::<PendingAction>("PendingAction", &corpus, 512);
}

#[test]
fn consensus_route_scale_exact_decoders_match_raw_decode_oracle_on_mutation_corpus() {
    let coinbase_a: MintCoinbaseArgs = decode_scale_exact(
        &test_coinbase_action(42).public_args,
        "coinbase corpus fixture",
    )
    .expect("coinbase fixture exact-decodes");
    let coinbase_b: MintCoinbaseArgs = decode_scale_exact(
        &test_coinbase_action_with_seed(77, [0x29u8; 32]).public_args,
        "coinbase corpus fixture with seed",
    )
    .expect("coinbase fixture with seed exact-decodes");
    assert_scale_exact_decode_matches_raw_oracle::<MintCoinbaseArgs>(
        "MintCoinbaseArgs",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x4d49_4e54,
            vec![coinbase_a.encode(), coinbase_b.encode()],
        ),
        192,
    );

    let inline_a: ShieldedTransferInlineArgs = decode_scale_exact(
        &test_inline_transfer_action([1u8; 48], [2u8; 48], [3u8; 48], 5).public_args,
        "inline transfer corpus fixture",
    )
    .expect("inline transfer fixture exact-decodes");
    let inline_b: ShieldedTransferInlineArgs = decode_scale_exact(
        &test_inline_transfer_action([4u8; 48], [5u8; 48], [6u8; 48], 8).public_args,
        "inline transfer second corpus fixture",
    )
    .expect("inline transfer second fixture exact-decodes");
    assert_scale_exact_decode_matches_raw_oracle::<ShieldedTransferInlineArgs>(
        "ShieldedTransferInlineArgs",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x494e_4c49_4e45,
            vec![inline_a.encode(), inline_b.encode()],
        ),
        192,
    );

    let sidecar_a: ShieldedTransferSidecarArgs = decode_scale_exact(
        &test_sidecar_transfer_action([7u8; 48], [8u8; 48], [9u8; 48], 11).public_args,
        "sidecar transfer corpus fixture",
    )
    .expect("sidecar transfer fixture exact-decodes");
    let sidecar_b: ShieldedTransferSidecarArgs = decode_scale_exact(
        &test_sidecar_transfer_action([10u8; 48], [11u8; 48], [12u8; 48], 13).public_args,
        "sidecar transfer second corpus fixture",
    )
    .expect("sidecar transfer second fixture exact-decodes");
    assert_scale_exact_decode_matches_raw_oracle::<ShieldedTransferSidecarArgs>(
        "ShieldedTransferSidecarArgs",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x0053_4944_4543_4152,
            vec![sidecar_a.encode(), sidecar_b.encode()],
        ),
        192,
    );

    let outbound_a: OutboundBridgeArgsV1 = decode_scale_exact(
        &test_outbound_bridge_action(b"").public_args,
        "outbound bridge empty corpus fixture",
    )
    .expect("outbound bridge empty fixture exact-decodes");
    let outbound_b: OutboundBridgeArgsV1 = decode_scale_exact(
        &test_outbound_bridge_action(b"outbound bridge payload corpus").public_args,
        "outbound bridge corpus fixture",
    )
    .expect("outbound bridge fixture exact-decodes");
    assert_scale_exact_decode_matches_raw_oracle::<OutboundBridgeArgsV1>(
        "OutboundBridgeArgsV1",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x4f55_5442_5249_4447,
            vec![outbound_a.encode(), outbound_b.encode()],
        ),
        192,
    );

    let inbound_a: InboundBridgeArgsV1 = decode_scale_exact(
        &test_inbound_bridge_action(b"").public_args,
        "inbound bridge empty corpus fixture",
    )
    .expect("inbound bridge empty fixture exact-decodes");
    let inbound_b: InboundBridgeArgsV1 = decode_scale_exact(
        &test_inbound_bridge_action(b"inbound bridge payload corpus").public_args,
        "inbound bridge corpus fixture",
    )
    .expect("inbound bridge fixture exact-decodes");
    assert_scale_exact_decode_matches_raw_oracle::<InboundBridgeArgsV1>(
        "InboundBridgeArgsV1",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x0049_4e42_4f55_4e44,
            vec![inbound_a.encode(), inbound_b.encode()],
        ),
        192,
    );

    let registration_a = BridgeVerifierRegistrationV1 {
        source_chain_id: [1u8; 32],
        verifier_program_hash: [2u8; 32],
        rules_hash: [3u8; 32],
        enabled_at_height: 42,
    };
    let registration_b = BridgeVerifierRegistrationV1 {
        source_chain_id: [4u8; 32],
        verifier_program_hash: [5u8; 32],
        rules_hash: [6u8; 32],
        enabled_at_height: 99,
    };
    assert_scale_exact_decode_matches_raw_oracle::<BridgeVerifierRegistrationV1>(
        "BridgeVerifierRegistrationV1",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x5245_4749_5354_4552,
            vec![registration_a.encode(), registration_b.encode()],
        ),
        192,
    );

    let candidate_a = test_candidate_artifact(1);
    let candidate_b = test_candidate_artifact(2);
    let submit_a = SubmitCandidateArtifactArgs {
        payload: candidate_a.clone(),
    };
    let submit_b = SubmitCandidateArtifactArgs {
        payload: candidate_b.clone(),
    };
    assert_scale_exact_decode_matches_raw_oracle::<CandidateArtifact>(
        "CandidateArtifact",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x4341_4e44_4944_4154,
            vec![candidate_a.encode(), candidate_b.encode()],
        ),
        192,
    );
    assert_scale_exact_decode_matches_raw_oracle::<SubmitCandidateArtifactArgs>(
        "SubmitCandidateArtifactArgs",
        &exact_decode_equivalence_corpus_from_valid_encodings(
            0x5355_424d_4954,
            vec![submit_a.encode(), submit_b.encode()],
        ),
        192,
    );
}

#[test]
fn native_block_meta_bincode_budget_rejects_unbounded_lengths_before_deserialize() {
    let mut oversized_count = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    oversized_count.extend_from_slice(&((MAX_NATIVE_BLOCK_ACTIONS as u64) + 1).to_le_bytes());
    let err = validate_native_block_meta_bincode_budget(&oversized_count, "test native metadata")
        .expect_err("oversized action count must reject before bincode decode");
    assert!(err
        .to_string()
        .contains("action byte count exceeds limit before bincode decode"));

    let mut oversized_payload = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    oversized_payload.extend_from_slice(&1u64.to_le_bytes());
    oversized_payload
        .extend_from_slice(&((MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES as u64) + 1).to_le_bytes());
    let err = validate_native_block_meta_bincode_budget(&oversized_payload, "test native metadata")
        .expect_err("oversized action payload must reject before bincode decode");
    assert!(err
        .to_string()
        .contains("action payload 0 exceeds limit before bincode decode"));

    let mut oversized_miner_key = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    oversized_miner_key.extend_from_slice(&0u64.to_le_bytes());
    oversized_miner_key.extend_from_slice(&48u64.to_le_bytes());
    oversized_miner_key.extend_from_slice(&[0u8; 48]);
    oversized_miner_key.extend_from_slice(&((ML_DSA_PUBLIC_KEY_LEN as u64) + 1).to_le_bytes());
    let err =
        validate_native_block_meta_bincode_budget(&oversized_miner_key, "test native metadata")
            .expect_err("oversized miner public key must reject before bincode decode");
    assert!(err
        .to_string()
        .contains("miner public key exceeds limit before bincode decode"));

    let mut oversized_miner_signature = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    oversized_miner_signature.extend_from_slice(&0u64.to_le_bytes());
    oversized_miner_signature.extend_from_slice(&48u64.to_le_bytes());
    oversized_miner_signature.extend_from_slice(&[0u8; 48]);
    oversized_miner_signature.extend_from_slice(&0u64.to_le_bytes());
    oversized_miner_signature.extend_from_slice(&((ML_DSA_SIGNATURE_LEN as u64) + 1).to_le_bytes());
    let err = validate_native_block_meta_bincode_budget(
        &oversized_miner_signature,
        "test native metadata",
    )
    .expect_err("oversized miner signature must reject before bincode decode");
    assert!(err
        .to_string()
        .contains("miner signature exceeds limit before bincode decode"));
}

#[test]
fn native_block_meta_bincode_budget_allows_current_and_legacy_metadata() {
    let current = genesis_meta(0x207f_ffff).expect("genesis");
    let current_bytes = bincode::serialize(&current).expect("serialize current metadata");
    validate_native_block_meta_bincode_budget(&current_bytes, "current native metadata")
        .expect("current metadata budget must pass");
    bincode_deserialize_native_block_meta_exact(&current_bytes, "current native metadata")
        .expect("current metadata exact decode must pass");

    let legacy = legacy_meta_from_current(&current);
    let legacy_bytes = bincode::serialize(&legacy).expect("serialize legacy metadata");
    validate_native_block_meta_bincode_budget(&legacy_bytes, "legacy native metadata")
        .expect("legacy metadata budget must pass");
    bincode_deserialize_native_block_meta_exact(&legacy_bytes, "legacy native metadata")
        .expect("legacy metadata exact decode must pass");

    let signed = mined_empty_child(&current, 1, 0x207f_ffff, 0);
    let signed_bytes = bincode::serialize(&signed).expect("serialize signed metadata");
    validate_native_block_meta_bincode_budget(&signed_bytes, "signed native metadata")
        .expect("signed metadata budget must pass");
    bincode_deserialize_native_block_meta_exact(&signed_bytes, "signed native metadata")
        .expect("signed metadata exact decode must pass");
}

#[test]
fn native_block_meta_exact_decode_matches_bincode_oracle_on_mutation_corpus() {
    let corpus = native_block_meta_exact_decode_equivalence_corpus();
    assert!(
        corpus.len() >= 192,
        "native metadata exact-decode corpus must stay broad enough to catch parser drift"
    );
    for (idx, raw) in corpus.iter().enumerate() {
        let expected = native_block_meta_bincode_oracle_accepts(raw);
        let actual =
            bincode_deserialize_native_block_meta_exact(raw, "native metadata corpus").is_ok();
        assert_eq!(
            actual,
            expected,
            "NativeBlockMeta exact-decode oracle mismatch at corpus index {idx}, len={}, prefix={}",
            raw.len(),
            hex::encode(&raw[..raw.len().min(16)])
        );
    }
}

fn assert_scale_exact_decode_matches_raw_oracle<T: Decode + Encode>(
    label: &str,
    corpus: &[Vec<u8>],
    min_cases: usize,
) {
    assert!(
        corpus.len() >= min_cases,
        "{label} exact-decode corpus must stay broad enough to catch parser drift"
    );
    for (idx, raw) in corpus.iter().enumerate() {
        let expected = scale_decode_oracle_accepts::<T>(raw);
        let actual = decode_scale_exact::<T>(raw, label).is_ok();
        assert_eq!(
            actual,
            expected,
            "{label} exact-decode oracle mismatch at corpus index {idx}, len={}, prefix={}",
            raw.len(),
            hex::encode(&raw[..raw.len().min(16)])
        );
    }
}

fn scale_decode_oracle_accepts<T: Decode + Encode>(raw: &[u8]) -> bool {
    let mut cursor = raw;
    let Ok(value) = T::decode(&mut cursor) else {
        return false;
    };
    cursor.is_empty() && value.encode().as_slice() == raw
}

fn native_block_meta_bincode_oracle_accepts(raw: &[u8]) -> bool {
    if validate_native_block_meta_bincode_budget(raw, "oracle native metadata").is_err() {
        return false;
    }
    bincode_fixint_exact_oracle::<NativeBlockMeta>(raw, MAX_NATIVE_BLOCK_META_BYTES)
        || bincode_fixint_exact_oracle::<LegacyNativeBlockMetaV1>(raw, MAX_NATIVE_BLOCK_META_BYTES)
}

fn bincode_fixint_exact_oracle<T: DeserializeOwned + Serialize>(
    raw: &[u8],
    max_bytes: usize,
) -> bool {
    if raw.len() > max_bytes {
        return false;
    }
    let mut cursor = Cursor::new(raw);
    let value: T = match bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(max_bytes as u64)
        .deserialize_from(&mut cursor)
    {
        Ok(value) => value,
        Err(_) => return false,
    };
    if cursor.position() as usize != raw.len() {
        return false;
    }
    let Ok(canonical) = bincode::serialize(&value) else {
        return false;
    };
    canonical.as_slice() == raw
}

fn native_block_meta_exact_decode_equivalence_corpus() -> Vec<Vec<u8>> {
    let current = genesis_meta(0x207f_ffff).expect("genesis metadata");
    let signed = mined_empty_child(&current, 1, 0x207f_ffff, 0);
    let legacy = legacy_meta_from_current(&current);
    let valid_encodings = vec![
        bincode::serialize(&current).expect("serialize current metadata"),
        bincode::serialize(&signed).expect("serialize signed metadata"),
        bincode::serialize(&legacy).expect("serialize legacy metadata"),
    ];

    let mut corpus = vec![
        Vec::new(),
        vec![0],
        vec![0xff],
        vec![0; 32],
        vec![0xff; 32],
        vec![0x01, 0x00],
        vec![0xff, 0xff, 0xff, 0xff],
        native_block_meta_action_count_overrun_bytes(),
        native_block_meta_action_payload_overrun_bytes(),
        native_block_meta_miner_commitment_overrun_bytes(),
        native_block_meta_miner_public_key_overrun_bytes(),
        native_block_meta_miner_signature_overrun_bytes(),
        vec![0u8; MAX_NATIVE_BLOCK_META_BYTES + 1],
    ];
    for len in [
        1usize, 2, 3, 4, 5, 8, 16, 31, 32, 33, 48, 64, 95, 96, 127, 128, 129, 255, 256, 257, 384,
        512, 768, 1024,
    ] {
        corpus.push(deterministic_pending_action_noise(
            0x4e42_4d45_5441 ^ len as u64,
            len,
        ));
    }

    for encoded in valid_encodings {
        extend_native_block_meta_decode_corpus_from_valid_encoding(&mut corpus, &encoded);
    }
    corpus
}

fn extend_native_block_meta_decode_corpus_from_valid_encoding(
    corpus: &mut Vec<Vec<u8>>,
    encoded: &[u8],
) {
    corpus.push(encoded.to_vec());

    for byte in [0x00, 0x55, 0xaa, 0xff] {
        let mut trailing = encoded.to_vec();
        trailing.push(byte);
        corpus.push(trailing);
    }

    for cut in native_block_meta_decode_cut_points(encoded.len()) {
        corpus.push(encoded[..cut].to_vec());
    }

    for offset in native_block_meta_decode_mutation_offsets(encoded.len()) {
        let mut mutated = encoded.to_vec();
        mutated[offset] ^= 0xff;
        corpus.push(mutated);
    }
}

fn native_block_meta_decode_cut_points(len: usize) -> BTreeSet<usize> {
    let mut cuts = generic_exact_decode_cut_points(len);
    for boundary in [
        NATIVE_BLOCK_META_ACTION_BYTES_OFFSET,
        NATIVE_BLOCK_META_ACTION_BYTES_OFFSET + BINCODE_FIXINT_VEC_LEN_BYTES,
        len,
    ] {
        for delta in [0usize, 1, 2, 3, 8, 16] {
            if let Some(cut) = boundary.checked_sub(delta) {
                if cut <= len {
                    cuts.insert(cut);
                }
            }
            let cut = boundary.saturating_add(delta);
            if cut <= len {
                cuts.insert(cut);
            }
        }
    }
    cuts
}

fn native_block_meta_decode_mutation_offsets(len: usize) -> BTreeSet<usize> {
    let mut offsets = generic_exact_decode_mutation_offsets(len);
    for offset in [
        NATIVE_BLOCK_META_ACTION_BYTES_OFFSET,
        NATIVE_BLOCK_META_ACTION_BYTES_OFFSET + 1,
        NATIVE_BLOCK_META_ACTION_BYTES_OFFSET + 7,
        NATIVE_BLOCK_META_ACTION_BYTES_OFFSET + BINCODE_FIXINT_VEC_LEN_BYTES,
        NATIVE_BLOCK_META_ACTION_BYTES_OFFSET + BINCODE_FIXINT_VEC_LEN_BYTES + 1,
    ] {
        if offset < len {
            offsets.insert(offset);
        }
    }
    offsets
}

fn native_block_meta_action_count_overrun_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    bytes.extend_from_slice(&((MAX_NATIVE_BLOCK_ACTIONS as u64) + 1).to_le_bytes());
    bytes
}

fn native_block_meta_action_payload_overrun_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    bytes.extend_from_slice(&1u64.to_le_bytes());
    bytes.extend_from_slice(&((MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES as u64) + 1).to_le_bytes());
    bytes
}

fn native_block_meta_miner_commitment_overrun_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&49u64.to_le_bytes());
    bytes
}

fn native_block_meta_miner_public_key_overrun_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&48u64.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 48]);
    bytes.extend_from_slice(&((ML_DSA_PUBLIC_KEY_LEN as u64) + 1).to_le_bytes());
    bytes
}

fn native_block_meta_miner_signature_overrun_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; NATIVE_BLOCK_META_ACTION_BYTES_OFFSET];
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&48u64.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 48]);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&((ML_DSA_SIGNATURE_LEN as u64) + 1).to_le_bytes());
    bytes
}

fn exact_decode_equivalence_corpus_from_valid_encodings(
    seed: u64,
    valid_encodings: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let mut corpus = vec![
        Vec::new(),
        vec![0],
        vec![0xff],
        vec![0x01, 0x00],
        vec![0xff, 0xff, 0xff, 0xff],
    ];
    for len in [
        1usize, 2, 3, 4, 5, 8, 16, 31, 32, 33, 48, 64, 96, 127, 128, 129, 255, 256, 257,
    ] {
        corpus.push(deterministic_pending_action_noise(seed ^ len as u64, len));
    }
    for encoded in valid_encodings {
        extend_exact_decode_corpus_from_valid_encoding(&mut corpus, &encoded);
    }
    corpus
}

fn extend_exact_decode_corpus_from_valid_encoding(corpus: &mut Vec<Vec<u8>>, encoded: &[u8]) {
    corpus.push(encoded.to_vec());

    for byte in [0x00, 0x55, 0xaa, 0xff] {
        let mut trailing = encoded.to_vec();
        trailing.push(byte);
        corpus.push(trailing);
    }

    for cut in generic_exact_decode_cut_points(encoded.len()) {
        corpus.push(encoded[..cut].to_vec());
    }

    for offset in generic_exact_decode_mutation_offsets(encoded.len()) {
        let mut mutated = encoded.to_vec();
        mutated[offset] ^= 0xff;
        corpus.push(mutated);
    }

    for offset in 0..encoded.len().min(8) {
        if let Some(mutated) =
            replace_pending_action_byte_with_noncanonical_zero_prefix(encoded, offset)
        {
            corpus.push(mutated);
        }
    }
}

fn generic_exact_decode_cut_points(len: usize) -> BTreeSet<usize> {
    let mut cuts = BTreeSet::new();
    for cut in 0..=len.min(64) {
        cuts.insert(cut);
    }
    for boundary in [1usize, 2, 4, 8, 16, 32, 48, 64, 96, 128, len] {
        for delta in [0usize, 1, 2, 3] {
            if let Some(cut) = boundary.checked_sub(delta) {
                if cut <= len {
                    cuts.insert(cut);
                }
            }
            let cut = boundary.saturating_add(delta);
            if cut <= len {
                cuts.insert(cut);
            }
        }
    }
    cuts
}

fn generic_exact_decode_mutation_offsets(len: usize) -> BTreeSet<usize> {
    let mut offsets = BTreeSet::new();
    if len == 0 {
        return offsets;
    }
    for offset in 0..len.min(64) {
        offsets.insert(offset);
    }
    for offset in [
        0usize,
        1,
        2,
        3,
        4,
        7,
        8,
        15,
        16,
        31,
        32,
        47,
        48,
        63,
        64,
        95,
        96,
        len - 1,
    ] {
        if offset < len {
            offsets.insert(offset);
        }
    }
    offsets
}

fn pending_action_exact_decode_equivalence_corpus() -> Vec<Vec<u8>> {
    let mut corpus = Vec::new();
    corpus.extend([
        Vec::new(),
        vec![0],
        vec![0xff],
        vec![0; 32],
        vec![0xff; 88],
        vec![0x01, 0x00],
        vec![0xff, 0xff, 0xff, 0xff],
    ]);
    for len in [
        1usize, 2, 3, 4, 5, 8, 16, 31, 32, 33, 48, 64, 87, 88, 89, 96, 110, 127, 128, 129, 255,
        256, 257, 384, 512,
    ] {
        corpus.push(deterministic_pending_action_noise(
            0x9e37_79b9_7f4a_7c15 ^ len as u64,
            len,
        ));
    }

    let mut generic = test_empty_action(0x1234, 0x5678, 99);
    generic.nullifiers = vec![[1u8; 48], [2u8; 48]];
    generic.commitments = vec![[3u8; 48], [4u8; 48]];
    generic.ciphertext_hashes = vec![[5u8; 48]];
    generic.ciphertext_sizes = vec![7, 11, 13];
    generic.public_args = (0u8..64).collect();
    generic.received_ms = 17;
    generic.tx_hash = pending_action_hash(&generic);

    let valid_actions = vec![
        test_empty_action(0, 0, 0),
        test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE, 3),
        test_outbound_bridge_action(b"pending-action exact-decode corpus"),
        test_inbound_bridge_action(b"pending-action inbound corpus"),
        test_coinbase_action(42),
        test_inline_transfer_action([1u8; 48], [2u8; 48], [3u8; 48], 5),
        test_sidecar_transfer_action([4u8; 48], [5u8; 48], [6u8; 48], 7),
        test_candidate_artifact_action(1, 0x44),
        generic,
    ];
    for action in valid_actions {
        extend_pending_action_decode_corpus_from_valid_action(&mut corpus, &action);
    }
    corpus
}

fn deterministic_pending_action_noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 32) as u8);
    }
    out
}

fn extend_pending_action_decode_corpus_from_valid_action(
    corpus: &mut Vec<Vec<u8>>,
    action: &PendingAction,
) {
    let encoded = action.encode();
    corpus.push(encoded.clone());

    for byte in [0x00, 0x55, 0xaa, 0xff] {
        let mut trailing = encoded.clone();
        trailing.push(byte);
        corpus.push(trailing);
    }

    for cut in pending_action_decode_cut_points(encoded.len()) {
        corpus.push(encoded[..cut].to_vec());
    }

    for offset in pending_action_decode_mutation_offsets(encoded.len()) {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 0xff;
        corpus.push(mutated);
    }

    for offset in [88usize, 89, 90, 91, 92] {
        if let Some(mutated) =
            replace_pending_action_byte_with_noncanonical_zero_prefix(&encoded, offset)
        {
            corpus.push(mutated);
        }
    }
}

fn pending_action_decode_cut_points(len: usize) -> BTreeSet<usize> {
    let mut cuts = BTreeSet::new();
    for cut in 0..=len.min(64) {
        cuts.insert(cut);
    }
    for boundary in [32usize, 36, 38, 40, 88, 89, 90, 91, 92, 93, 101, 102, len] {
        for delta in [0usize, 1, 2, 3] {
            if let Some(cut) = boundary.checked_sub(delta) {
                if cut <= len {
                    cuts.insert(cut);
                }
            }
            let cut = boundary.saturating_add(delta);
            if cut <= len {
                cuts.insert(cut);
            }
        }
    }
    cuts
}

fn pending_action_decode_mutation_offsets(len: usize) -> BTreeSet<usize> {
    let mut offsets = BTreeSet::new();
    if len == 0 {
        return offsets;
    }
    for offset in 0..len.min(64) {
        offsets.insert(offset);
    }
    for offset in [
        31usize,
        32,
        35,
        36,
        37,
        38,
        39,
        40,
        87,
        88,
        89,
        90,
        91,
        92,
        93,
        100,
        101,
        102,
        len - 1,
    ] {
        if offset < len {
            offsets.insert(offset);
        }
    }
    offsets
}

fn replace_pending_action_byte_with_noncanonical_zero_prefix(
    encoded: &[u8],
    offset: usize,
) -> Option<Vec<u8>> {
    if offset >= encoded.len() {
        return None;
    }
    let mut mutated = Vec::with_capacity(encoded.len() + 1);
    mutated.extend_from_slice(&encoded[..offset]);
    mutated.extend_from_slice(&[0x01, 0x00]);
    mutated.extend_from_slice(&encoded[offset + 1..]);
    Some(mutated)
}

#[test]
fn lean_generated_storage_durability_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_STORAGE_DURABILITY_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean storage durability admission vectors");
    let vectors: LeanStorageDurabilityAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean storage durability admission vectors");
    assert_eq!(vectors.schema_version, 2);
    assert!(
        !vectors.storage_durability_admission_cases.is_empty(),
        "Lean storage durability admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.storage_durability_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_storage_durability_admission_case(case);
    }
}

fn verify_lean_storage_durability_admission_case(case: &LeanStorageDurabilityAdmissionCase) {
    let operation = NativeStorageDurabilityOperation::from_label(&case.operation);
    assert_eq!(
        operation.is_some(),
        case.operation_supported,
        "{} Lean storage durability operation support drifted from production parser",
        case.name
    );
    if let Some(operation) = operation {
        assert_eq!(operation.label(), case.operation);
    }
    assert_eq!(
        case.operation_supported && case.transaction_accepted && case.durability_flushed,
        case.expected_valid,
        "{} Lean storage durability predicate fields disagree with expected validity",
        case.name
    );
    let actual =
        evaluate_native_storage_durability_admission(NativeStorageDurabilityAdmissionInput {
            operation_supported: case.operation_supported,
            transaction_accepted: case.transaction_accepted,
            durability_flushed: case.durability_flushed,
        });
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native storage durability validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native storage durability rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_atomic_commit_manifest_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ATOMIC_COMMIT_MANIFEST_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean atomic commit manifest admission vectors");
    let vectors: LeanAtomicCommitManifestAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean atomic commit manifest admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.atomic_commit_manifest_admission_cases.is_empty(),
        "Lean atomic commit manifest admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.atomic_commit_manifest_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_atomic_commit_manifest_admission_case(case);
    }
}

fn native_atomic_commit_kind_from_label(label: &str) -> NativeAtomicCommitKind {
    match label {
        "mined_block_commit" => NativeAtomicCommitKind::MinedBlockCommit,
        "tip_extension_batch_commit" => NativeAtomicCommitKind::TipExtensionBatchCommit,
        "canonical_reorg_commit" => NativeAtomicCommitKind::CanonicalReorgCommit,
        "canonical_index_repair" => NativeAtomicCommitKind::CanonicalIndexRepair,
        "noncanonical_block_record" => NativeAtomicCommitKind::NoncanonicalBlockRecord,
        other => panic!("unknown Lean atomic commit kind {other}"),
    }
}

fn verify_lean_atomic_commit_manifest_admission_case(case: &LeanAtomicCommitManifestAdmissionCase) {
    let input = NativeAtomicCommitManifestAdmissionInput {
        kind: native_atomic_commit_kind_from_label(&case.kind),
        action_count: case.action_count,
        planned_action_count: case.planned_action_count,
        chain_block_count: case.chain_block_count,
        height_entry_count: case.height_entry_count,
        pending_entry_count: case.pending_entry_count,
        source_commitment_count: case.source_commitment_count,
        source_nullifier_count: case.source_nullifier_count,
        source_bridge_replay_count: case.source_bridge_replay_count,
        source_ciphertext_index_count: case.source_ciphertext_index_count,
        source_ciphertext_archive_count: case.source_ciphertext_archive_count,
        source_staged_ciphertext_removal_count: case.source_staged_ciphertext_removal_count,
        block_record_writes: case.block_record_writes,
        height_index_writes: case.height_index_writes,
        best_pointer_writes: case.best_pointer_writes,
        canonical_index_cleared: case.canonical_index_cleared,
        pending_tree_cleared: case.pending_tree_cleared,
        pending_action_removals: case.pending_action_removals,
        pending_action_writes: case.pending_action_writes,
        commitment_writes: case.commitment_writes,
        nullifier_writes: case.nullifier_writes,
        bridge_replay_writes: case.bridge_replay_writes,
        ciphertext_index_writes: case.ciphertext_index_writes,
        ciphertext_archive_writes: case.ciphertext_archive_writes,
        staged_ciphertext_removals: case.staged_ciphertext_removals,
    };
    let actual = evaluate_native_atomic_commit_manifest_admission(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native atomic commit manifest validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native atomic commit manifest rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_action_scope_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_SCOPE_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_SCOPE_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean action-scope admission vectors");
    let vectors: LeanActionScopeAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean action-scope vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_scope_admission_cases.is_empty(),
        "Lean action-scope admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_scope_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_scope_admission_case(case);
    }
}

fn verify_lean_action_scope_admission_case(case: &LeanActionScopeAdmissionCase) {
    let input = NativeActionScopeAdmissionInput {
        candidate_artifact_payload_scoped: case.candidate_artifact_payload_scoped,
        bridge_route: case.bridge_route,
        bridge_scope_valid: case.bridge_scope_valid,
        candidate_artifact_route: case.candidate_artifact_route,
        candidate_scope_valid: case.candidate_scope_valid,
        candidate_payload_present: case.candidate_payload_present,
        coinbase_route: case.coinbase_route,
        coinbase_scope_valid: case.coinbase_scope_valid,
        transfer_route: case.transfer_route,
        transfer_scope_valid: case.transfer_scope_valid,
    };
    let actual = evaluate_native_action_scope_admission(input);
    let actual_route = actual.as_ref().ok().map(|route| route.label().to_owned());
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_route.is_some(),
        case.expected_valid,
        "{} native action-scope admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_route, case.expected_route,
        "{} native action-scope admission route drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native action-scope admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_bridge_action_payload_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_ACTION_PAYLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge action payload admission vectors");
    let vectors: LeanBridgeActionPayloadAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean bridge action payload admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_action_payload_admission_cases.is_empty(),
        "Lean bridge action payload admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_action_payload_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_action_payload_admission_case(case);
    }
}

fn verify_lean_bridge_action_payload_admission_case(case: &LeanBridgeActionPayloadAdmissionCase) {
    let input = NativeBridgeActionPayloadAdmissionInput {
        bridge_route: case.bridge_route,
        state_deltas_absent: case.state_deltas_absent,
        action_kind: lean_bridge_action_payload_kind(&case.action_kind, &case.name),
        outbound_payload_nonempty: case.outbound_payload_nonempty,
        inbound_proof_receipt_nonempty: case.inbound_proof_receipt_nonempty,
        inbound_replay_key_matches: case.inbound_replay_key_matches,
        inbound_destination_matches: case.inbound_destination_matches,
        inbound_payload_hash_matches: case.inbound_payload_hash_matches,
    };
    let actual_rejection = evaluate_native_bridge_action_payload_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native bridge action payload admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge action payload admission rejection drifted from Lean spec",
        case.name
    );
}

fn lean_bridge_action_payload_kind(
    action_kind: &str,
    case_name: &str,
) -> NativeBridgeActionPayloadKind {
    match action_kind {
        "outbound" => NativeBridgeActionPayloadKind::Outbound,
        "inbound" => NativeBridgeActionPayloadKind::Inbound,
        "register" => NativeBridgeActionPayloadKind::Register,
        "unsupported" => NativeBridgeActionPayloadKind::Unsupported,
        other => panic!("{case_name} has unknown bridge action kind {other}"),
    }
}

#[test]
fn lean_generated_bridge_action_resource_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_ACTION_RESOURCE_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_ACTION_RESOURCE_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge action resource admission vectors");
    let vectors: LeanBridgeActionResourceAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean bridge action resource admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_action_resource_admission_cases.is_empty(),
        "Lean bridge action resource admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    let mut native_cap_cases = BTreeSet::new();
    for case in &vectors.bridge_action_resource_admission_cases {
        assert!(names.insert(case.name.clone()));
        if verify_lean_bridge_action_resource_admission_case(case) {
            native_cap_cases.insert(case.name.clone());
        }
    }
    assert!(
        native_cap_cases.contains("valid-inbound-bridge-resource-accepted"),
        "Lean bridge action resource vectors must bind valid inbound caps to production constants"
    );
    assert!(
        native_cap_cases.contains("valid-outbound-bridge-resource-accepted"),
        "Lean bridge action resource vectors must bind valid outbound caps to production constants"
    );
    assert!(
            native_cap_cases.contains("exact-inbound-receipt-and-payload-limits-accepted"),
            "Lean bridge action resource vectors must bind exact inbound limits to production constants"
        );
}

fn verify_lean_bridge_action_resource_admission_case(
    case: &LeanBridgeActionResourceAdmissionCase,
) -> bool {
    let input = NativeBridgeActionResourceAdmissionInput {
        raw_byte_cap: case.raw_byte_cap,
        decoded_byte_cap: case.decoded_byte_cap,
        item_count_cap: case.item_count_cap,
        item_byte_cap: case.item_byte_cap,
        aggregate_byte_cap: case.aggregate_byte_cap,
        work_unit_cap: case.work_unit_cap,
        action_kind: lean_bridge_action_payload_kind(&case.action_kind, &case.name),
        public_args_bytes: case.public_args_bytes,
        outbound_payload_bytes: case.outbound_payload_bytes,
        inbound_proof_receipt_bytes: case.inbound_proof_receipt_bytes,
        inbound_message_payload_bytes: case.inbound_message_payload_bytes,
    };
    let bounded = bridge_action_resource_bounded_request(input);
    let uses_native_caps = case.raw_byte_cap == MAX_NATIVE_RPC_ACTION_BYTES
        && case.decoded_byte_cap == MAX_NATIVE_RPC_ACTION_BYTES
        && case.item_count_cap == 2
        && case.item_byte_cap == MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES
        && case.aggregate_byte_cap == MAX_NATIVE_BRIDGE_ACTION_DYNAMIC_BYTES
        && case.work_unit_cap == MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES;
    if uses_native_caps {
        let production_input = native_bridge_action_resource_projection_input(
            input.action_kind,
            input.public_args_bytes,
            input.outbound_payload_bytes,
            input.inbound_proof_receipt_bytes,
            input.inbound_message_payload_bytes,
        );
        assert_eq!(
            production_input, input,
            "{} Lean bridge action resource policy caps drifted from production constants",
            case.name
        );
        assert_eq!(
            bridge_action_resource_bounded_request(production_input),
            bounded,
            "{} production bridge action resource projection drifted from Lean spec",
            case.name
        );
    }
    assert_eq!(
        bounded.raw_bytes, case.expected_raw_bytes,
        "{} bridge action public_args projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.decoded_bytes, case.expected_decoded_bytes,
        "{} bridge action decoded-byte projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.item_count, case.expected_item_count,
        "{} bridge action dynamic item-count projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.max_item_bytes, case.expected_max_item_bytes,
        "{} bridge action max item-byte projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.aggregate_bytes, case.expected_aggregate_bytes,
        "{} bridge action aggregate-byte projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.work_units, case.expected_work_units,
        "{} bridge action work-unit projection drifted from Lean spec",
        case.name
    );

    let actual = evaluate_native_bounded_request_admission(bounded);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native bridge action resource validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge action resource rejection drifted from Lean spec",
        case.name
    );
    uses_native_caps
}

#[test]
fn lean_generated_bridge_mint_replay_policy_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_MINT_REPLAY_POLICY_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge mint/replay policy vectors");
    let vectors: LeanBridgeMintReplayPolicyVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean bridge mint/replay policy vectors");
    assert_eq!(vectors.schema_version, 2);
    assert!(
        !vectors.bridge_mint_replay_cases.is_empty(),
        "Lean bridge mint/replay policy cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_mint_replay_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_mint_replay_policy_case(case);
    }
}

fn verify_lean_bridge_mint_replay_policy_case(case: &LeanBridgeMintReplayPolicyCase) {
    let replay_key = parse_hex48(&case.replay_key)
        .unwrap_or_else(|| panic!("{} has invalid replay_key", case.name));
    let initial_consumed =
        parse_lean_bridge_replay_key_set(&case.initial_consumed, &case.name, "consumed");
    let initial_pending =
        parse_lean_bridge_replay_key_set(&case.initial_pending, &case.name, "pending");
    assert!(
        initial_consumed.is_disjoint(&initial_pending),
        "{} initial replay consumed and pending sets must be disjoint",
        case.name
    );
    let input = NativeBridgeMintReplayPolicyInput {
        inbound_bridge_mint: case.inbound_bridge_mint,
        state_deltas_absent: case.state_deltas_absent,
        receipt_envelope_present: case.receipt_envelope_present,
        receipt_verified: case.receipt_verified,
        receipt_payload_matches: case.receipt_payload_matches,
        replay_state: InboundReplayState::new(initial_consumed, initial_pending),
        replay_key,
        mint_authorized: case.mint_authorized,
        amount_matches_receipt: case.amount_matches_receipt,
        amount_within_bound: case.amount_within_bound,
    };
    let actual = evaluate_native_bridge_mint_replay_policy(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native bridge mint/replay policy validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge mint/replay policy rejection drifted from Lean spec",
        case.name
    );
    if case.expected_valid {
        let expected_consumed = case
            .expected_next_consumed
            .as_ref()
            .map(|values| parse_lean_bridge_replay_key_set(values, &case.name, "expected consumed"))
            .expect("accepted bridge mint/replay case must include expected consumed set");
        let expected_pending = case
            .expected_next_pending
            .as_ref()
            .map(|values| parse_lean_bridge_replay_key_set(values, &case.name, "expected pending"))
            .expect("accepted bridge mint/replay case must include expected pending set");
        let next = actual.expect("accepted bridge mint/replay policy");
        assert_eq!(
            next.consumed(),
            &expected_consumed,
            "{} accepted bridge mint/replay policy consumed set drifted from Lean spec",
            case.name
        );
        assert_eq!(
            next.pending(),
            &expected_pending,
            "{} accepted bridge mint/replay policy pending set drifted from Lean spec",
            case.name
        );
        assert!(
            next.consumed().contains(&replay_key),
            "{} accepted bridge mint/replay policy did not consume replay key",
            case.name
        );
        assert!(
            !next.pending().contains(&replay_key),
            "{} accepted bridge mint/replay policy left replay key pending",
            case.name
        );
    } else {
        assert!(
            case.expected_next_consumed.is_none() && case.expected_next_pending.is_none(),
            "{} rejected bridge mint/replay case must not include expected next replay state",
            case.name
        );
    }
}

#[test]
fn lean_generated_bridge_mint_payload_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_MINT_PAYLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge mint payload admission vectors");
    let vectors: LeanBridgeMintPayloadAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean bridge mint payload admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_mint_payload_admission_cases.is_empty(),
        "Lean bridge mint payload admission cases must not be empty"
    );
    assert!(
        !vectors.cashvm_mint_binding_cases.is_empty(),
        "Lean CashVM mint binding cases must not be empty"
    );
    assert!(
        !vectors.cashvm_proof_admission_cases.is_empty(),
        "Lean CashVM proof admission cases must not be empty"
    );
    assert!(
        !vectors.cashvm_replay_update_cases.is_empty(),
        "Lean CashVM replay update cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_mint_payload_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_mint_payload_admission_case(case);
    }
    for case in &vectors.cashvm_mint_binding_cases {
        assert!(names.insert(case.name.clone()));
        let expected_valid = case.version_matches
            && case.source_app_family_matches
            && case.destination_matches
            && case.mint_nonce_matches
            && case.recipient_commitment_nonzero
            && case.amount_nonzero
            && case.amount_within_bound
            && case.asset_non_native
            && case.destination_matches_bridge_policy
            && case.bridge_instance_matches_token_category
            && case.token_category_matches_payload_asset
            && case.recipient_hash_matches_payload_recipient;
        assert_eq!(
            expected_valid, case.expected_valid,
            "{} CashVM mint binding validity drifted from Lean preconditions",
            case.name
        );
        let expected_rejection = if !case.version_matches {
            Some("version_mismatch")
        } else if !case.source_app_family_matches {
            Some("source_app_family_mismatch")
        } else if !case.destination_matches {
            Some("destination_mismatch")
        } else if !case.mint_nonce_matches {
            Some("mint_nonce_mismatch")
        } else if !case.recipient_commitment_nonzero {
            Some("recipient_commitment_zero")
        } else if !case.amount_nonzero {
            Some("amount_zero")
        } else if !case.amount_within_bound {
            Some("amount_out_of_bounds")
        } else if !case.asset_non_native {
            Some("native_asset_not_allowed")
        } else if !case.destination_matches_bridge_policy {
            Some("destination_policy_mismatch")
        } else if !case.bridge_instance_matches_token_category
            || !case.token_category_matches_payload_asset
        {
            Some("asset_binding_mismatch")
        } else if !case.recipient_hash_matches_payload_recipient {
            Some("recipient_binding_mismatch")
        } else {
            None
        };
        assert_eq!(
            case.expected_rejection.as_deref(),
            expected_rejection,
            "{} CashVM mint binding rejection drifted from Lean order",
            case.name
        );
    }
    for case in &vectors.cashvm_proof_admission_cases {
        assert!(names.insert(case.name.clone()));
        let expected_valid = case.proof_nonempty
            && case.statement_digest_matches
            && case.verifier_script_matches
            && case.pq_soundness_at_least_policy
            && case.verifier_available
            && case.verifier_accepts;
        assert_eq!(
            expected_valid, case.expected_valid,
            "{} CashVM proof admission validity drifted from Lean preconditions",
            case.name
        );
        let expected_rejection = if !case.proof_nonempty {
            Some("empty_proof")
        } else if !case.statement_digest_matches {
            Some("proof_statement_mismatch")
        } else if !case.verifier_script_matches {
            Some("verifier_script_mismatch")
        } else if !case.pq_soundness_at_least_policy {
            Some("insufficient_pq_soundness")
        } else if !case.verifier_available {
            Some("proof_verification_unavailable")
        } else if !case.verifier_accepts {
            Some("proof_verification_failed")
        } else {
            None
        };
        assert_eq!(
            case.expected_rejection.as_deref(),
            expected_rejection,
            "{} CashVM proof admission rejection drifted from Lean order",
            case.name
        );
    }
    for case in &vectors.cashvm_replay_update_cases {
        assert!(names.insert(case.name.clone()));
        let expected_valid = case.witness_depth_valid
            && case.previous_root_matches
            && case.replay_leaf_absent
            && case.next_root_matches;
        assert_eq!(
            expected_valid, case.expected_valid,
            "{} CashVM replay update validity drifted from Lean preconditions",
            case.name
        );
        let expected_rejection = if !case.witness_depth_valid {
            Some("replay_witness_depth_mismatch")
        } else if !case.previous_root_matches {
            Some("previous_replay_root_mismatch")
        } else if !case.replay_leaf_absent {
            Some("replay_already_spent")
        } else if !case.next_root_matches {
            Some("next_replay_root_mismatch")
        } else {
            None
        };
        assert_eq!(
            case.expected_rejection.as_deref(),
            expected_rejection,
            "{} CashVM replay update rejection drifted from Lean order",
            case.name
        );
    }
}

fn verify_lean_bridge_mint_payload_admission_case(case: &LeanBridgeMintPayloadAdmissionCase) {
    let input = NativeBridgeMintPayloadAdmissionInput {
        payload_decoded: case.payload_decoded,
        payload_hash_matches: case.payload_hash_matches,
        receipt_message_hash_matches: case.receipt_message_hash_matches,
        version_matches: case.version_matches,
        source_app_family_matches: case.source_app_family_matches,
        destination_matches: case.destination_matches,
        mint_nonce_matches: case.mint_nonce_matches,
        recipient_commitment_nonzero: case.recipient_commitment_nonzero,
        amount_nonzero: case.amount_nonzero,
        amount_within_bound: case.amount_within_bound,
        asset_non_native: case.asset_non_native,
    };
    let actual_rejection = evaluate_native_bridge_mint_payload_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native bridge mint payload admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge mint payload admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_bridge_mint_payload_raw_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_MINT_PAYLOAD_RAW_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_MINT_PAYLOAD_RAW_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge mint payload raw admission vectors");
    let vectors: LeanBridgeMintPayloadRawAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean bridge mint payload raw admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_mint_payload_raw_admission_cases.is_empty(),
        "Lean bridge mint payload raw admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_mint_payload_raw_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_mint_payload_raw_admission_case(case);
    }
}

fn verify_lean_bridge_mint_payload_raw_admission_case(
    case: &LeanBridgeMintPayloadRawAdmissionCase,
) {
    let raw = decode_lean_hex(&case.raw_hex);
    let (parser_accepts, consumed_all_bytes, canonical_reencode_matches, parsed_payload) =
        bridge_mint_payload_raw_decode_surface(&raw);
    assert_eq!(
        parser_accepts, case.parser_accepts,
        "{} production BridgeMintPayloadV1 parser acceptance drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        consumed_all_bytes, case.consumed_all_bytes,
        "{} production BridgeMintPayloadV1 consumed-all-bytes fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        canonical_reencode_matches, case.canonical_reencode_matches,
        "{} production BridgeMintPayloadV1 canonical re-encode fact drifted from Lean raw spec",
        case.name
    );

    let exact_payload = decode_scale_exact::<BridgeMintPayloadV1>(
        &raw,
        "Lean bridge mint payload raw admission bytes",
    )
    .ok();
    assert_eq!(
        exact_payload.is_some(),
        case.parser_accepts && case.consumed_all_bytes && case.canonical_reencode_matches,
        "{} production BridgeMintPayloadV1 exact-decode predicate drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        exact_payload.as_ref(),
        parsed_payload
            .as_ref()
            .filter(|_| case.consumed_all_bytes && case.canonical_reencode_matches),
        "{} exact decode and raw parser surface disagree for BridgeMintPayloadV1",
        case.name
    );

    if let Some(payload) = &exact_payload {
        assert_bridge_mint_payload_fixture_fields(case, payload);
        assert_eq!(
            payload.encode(),
            raw,
            "{} decoded BridgeMintPayloadV1 does not canonically re-encode to Lean raw bytes",
            case.name
        );
    }

    let (args, output) = inbound_bridge_args_and_output_for_raw_mint_payload(case, raw);
    let input = bridge_mint_payload_admission_input(&args, &output, exact_payload.as_ref());
    assert_eq!(
        input.payload_decoded,
        case.parser_accepts && case.consumed_all_bytes && case.canonical_reencode_matches,
        "{} production payload_decoded fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.payload_hash_matches, case.payload_hash_matches,
        "{} production payload_hash_matches fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.receipt_message_hash_matches, case.receipt_message_hash_matches,
        "{} production receipt_message_hash_matches fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.version_matches, case.version_matches,
        "{} production version_matches fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.source_app_family_matches, case.source_app_family_matches,
        "{} production source_app_family_matches fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.destination_matches, case.destination_matches,
        "{} production destination_matches fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.mint_nonce_matches, case.mint_nonce_matches,
        "{} production mint_nonce_matches fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.recipient_commitment_nonzero, case.recipient_commitment_nonzero,
        "{} production recipient_commitment_nonzero fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.amount_nonzero, case.amount_nonzero,
        "{} production amount_nonzero fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.amount_within_bound, case.amount_within_bound,
        "{} production amount_within_bound fact drifted from Lean raw spec",
        case.name
    );
    assert_eq!(
        input.asset_non_native, case.asset_non_native,
        "{} production asset_non_native fact drifted from Lean raw spec",
        case.name
    );

    let actual_rejection = evaluate_native_bridge_mint_payload_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native bridge mint raw payload admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge mint raw payload admission rejection drifted from Lean spec",
        case.name
    );
}

fn bridge_mint_payload_raw_decode_surface(
    raw: &[u8],
) -> (bool, bool, bool, Option<BridgeMintPayloadV1>) {
    let mut input = raw;
    match BridgeMintPayloadV1::decode(&mut input) {
        Ok(payload) => {
            let consumed_all_bytes = input.is_empty();
            let canonical_reencode_matches = payload.encode() == raw;
            (
                true,
                consumed_all_bytes,
                canonical_reencode_matches,
                Some(payload),
            )
        }
        Err(_) => (false, false, false, None),
    }
}

fn inbound_bridge_args_and_output_for_raw_mint_payload(
    case: &LeanBridgeMintPayloadRawAdmissionCase,
    payload: Vec<u8>,
) -> (InboundBridgeArgsV1, BridgeCheckpointOutputV1) {
    let mut message = BridgeMessageV1 {
        source_chain_id: HEGEMON_CHAIN_ID_V1,
        destination_chain_id: HEGEMON_CHAIN_ID_V1,
        app_family_id: FAMILY_BRIDGE,
        message_nonce: 42,
        source_height: 9,
        payload_hash: bridge_payload_hash(&payload),
        payload,
    };
    if !case.source_app_family_matches {
        message.app_family_id = BRIDGE_MINT_APP_FAMILY_ID_V1.saturating_add(1);
    }
    let mut output = test_bridge_checkpoint_output_for_message(&message);
    if !case.payload_hash_matches {
        message.payload_hash = [0x5au8; 48];
    }
    if case.payload_hash_matches && !case.receipt_message_hash_matches {
        output.message_hash = [0x5bu8; 48];
    }
    (
        InboundBridgeArgsV1 {
            source_chain_id: HEGEMON_CHAIN_ID_V1,
            source_message_nonce: message.message_nonce,
            verifier_program_hash: HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
            proof_receipt: vec![0x01],
            message,
        },
        output,
    )
}

fn assert_bridge_mint_payload_fixture_fields(
    case: &LeanBridgeMintPayloadRawAdmissionCase,
    payload: &BridgeMintPayloadV1,
) {
    match case.fixture.as_str() {
        "valid_payload"
        | "payload_hash_mismatch"
        | "receipt_message_hash_mismatch"
        | "source_app_family_mismatch"
        | "mint_nonce_mismatch" => {
            assert_eq!(payload.version, BRIDGE_MINT_PAYLOAD_VERSION_V1);
            assert_eq!(payload.destination_chain_id, HEGEMON_CHAIN_ID_V1);
            assert_eq!(payload.recipient_commitment, [0x42u8; 48]);
            assert_eq!(payload.asset_id, 7);
            assert_eq!(payload.amount, 42);
            let expected_nonce = if case.fixture == "mint_nonce_mismatch" {
                99
            } else {
                42
            };
            assert_eq!(payload.mint_nonce, expected_nonce);
        }
        "version_mismatch" => assert_eq!(payload.version, 2),
        "destination_mismatch" => assert_eq!(payload.destination_chain_id, [0x9au8; 32]),
        "zero_recipient" => assert_eq!(payload.recipient_commitment, [0u8; 48]),
        "zero_amount" => assert_eq!(payload.amount, 0),
        "over_bound_amount" => {
            assert_eq!(payload.amount, MAX_NATIVE_BRIDGE_MINT_AMOUNT + 1)
        }
        "native_asset" => {
            assert_eq!(
                payload.asset_id,
                transaction_core::constants::NATIVE_ASSET_ID
            )
        }
        "short_payload" | "trailing_payload" | "short_payload_hash_mismatch" => {
            panic!(
                "{} fixture should not exact-decode as BridgeMintPayloadV1",
                case.fixture
            )
        }
        other => panic!("unknown BridgeMintPayloadV1 raw fixture {other}"),
    }
}

#[test]
fn lean_generated_bridge_verifier_registration_policy_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_VERIFIER_REGISTRATION_POLICY_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge verifier registration policy vectors");
    let vectors: LeanBridgeVerifierRegistrationPolicyVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean bridge verifier registration policy vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bridge_verifier_registration_policy_cases.is_empty(),
        "Lean bridge verifier registration policy cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_verifier_registration_policy_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_verifier_registration_policy_case(case);
    }
}

fn verify_lean_bridge_verifier_registration_policy_case(
    case: &LeanBridgeVerifierRegistrationPolicyCase,
) {
    let input = NativeBridgeVerifierRegistrationPolicyInput {
        bridge_verifier_registration: case.bridge_verifier_registration,
        state_deltas_absent: case.state_deltas_absent,
        registration_decoded: case.registration_decoded,
        descriptor_matches_release: case.descriptor_matches_release,
        activation_height_reached: case.activation_height_reached,
        pq_clean_verifier_bound: case.pq_clean_verifier_bound,
        external_verifier_soundness_accepted: case.external_verifier_soundness_accepted,
        positive_minting_enabled: case.positive_minting_enabled,
    };
    let actual = evaluate_native_bridge_verifier_registration_policy(input);
    let actual_rejection = actual
        .as_ref()
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native bridge verifier registration policy validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bridge verifier registration policy rejection drifted from Lean spec",
        case.name
    );
    match (actual, &case.expected_effect) {
        (Ok(effect), Some(expected_effect)) => {
            assert_eq!(
                effect.registration_observed, expected_effect.registration_observed,
                "{} registration-observed effect drifted from Lean spec",
                case.name
            );
            assert_eq!(
                effect.production_mint_verifier_enabled,
                expected_effect.production_mint_verifier_enabled,
                "{} production mint-verifier effect drifted from Lean spec",
                case.name
            );
        }
        (Err(_), None) => {}
        (Ok(_), None) => panic!(
            "{} accepted bridge verifier registration policy without expected effect",
            case.name
        ),
        (Err(_), Some(_)) => panic!(
            "{} rejected bridge verifier registration policy with expected effect",
            case.name
        ),
    }
}

fn parse_lean_bridge_replay_key_set(
    values: &[String],
    case_name: &str,
    field: &str,
) -> BTreeSet<[u8; 48]> {
    let mut parsed = BTreeSet::new();
    for raw in values {
        let key = parse_hex48(raw)
            .unwrap_or_else(|| panic!("{case_name} has invalid {field} replay key {raw}"));
        assert!(
            parsed.insert(key),
            "{case_name} has duplicate {field} replay key {raw}"
        );
    }
    parsed
}

#[test]
fn lean_generated_risc0_release_verifier_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_RISC0_RELEASE_VERIFIER_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_RISC0_RELEASE_VERIFIER_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean RISC0 release verifier vectors");
    let vectors: LeanRisc0ReleaseVerifierVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean RISC0 verifier vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.risc0_release_verifier_cases.is_empty(),
        "Lean RISC0 release verifier cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.risc0_release_verifier_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_risc0_release_verifier_case(case);
    }
}

fn verify_lean_risc0_release_verifier_case(case: &LeanRisc0ReleaseVerifierCase) {
    let input = NativeRisc0ReleaseVerifierInput {
        image_id_matches: case.image_id_matches,
        journal_decodes: case.journal_decodes,
        verifier_enabled: case.verifier_enabled,
    };
    let actual_rejection = evaluate_native_risc0_release_verifier(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native RISC0 release verifier validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native RISC0 release verifier rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_transfer_action_payload_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_TRANSFER_ACTION_PAYLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean transfer action payload admission vectors");
    let vectors: LeanTransferActionPayloadAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean transfer action payload admission vectors");
    assert_eq!(vectors.schema_version, 2);
    assert!(
        !vectors.transfer_action_payload_admission_cases.is_empty(),
        "Lean transfer action payload admission cases must not be empty"
    );
    assert!(
        !vectors.inline_transfer_ciphertext_resource_cases.is_empty(),
        "Lean inline transfer ciphertext resource cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.transfer_action_payload_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_transfer_action_payload_admission_case(case);
    }
    for case in &vectors.inline_transfer_ciphertext_resource_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_inline_transfer_ciphertext_resource_case(case);
    }
}

fn verify_lean_transfer_action_payload_admission_case(
    case: &LeanTransferActionPayloadAdmissionCase,
) {
    assert_eq!(
        case.max_proof_bytes, NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        "{} Lean proof cap must match the production native tx-leaf cap",
        case.name
    );
    assert_eq!(
        case.max_ciphertext_bytes, MAX_CIPHERTEXT_BYTES,
        "{} Lean ciphertext cap must match the production native cap",
        case.name
    );
    let input = NativeTransferPayloadAdmissionInput {
        proof_bytes: case.proof_bytes,
        max_proof_bytes: case.max_proof_bytes,
        anchor_matches: case.anchor_matches,
        commitments_match: case.commitments_match,
        inline_ciphertext_bytes: case.inline_ciphertext_bytes,
        max_ciphertext_bytes: case.max_ciphertext_bytes,
        ciphertext_hashes_match: case.ciphertext_hashes_match,
        ciphertext_sizes_match: case.ciphertext_sizes_match,
        binding_hash_matches: case.binding_hash_matches,
        proof_binding_hash_matches_key: case.proof_binding_hash_matches_key,
        fee_matches: case.fee_matches,
    };
    let actual_rejection = evaluate_native_transfer_payload_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native transfer payload admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native transfer payload admission rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_inline_transfer_ciphertext_resource_case(
    case: &LeanInlineTransferCiphertextResourceCase,
) {
    assert_eq!(
        case.raw_byte_cap, MAX_NATIVE_RPC_ACTION_BYTES,
        "{} Lean raw byte cap must match production submit-action public_args cap",
        case.name
    );
    assert_eq!(
        case.decoded_byte_cap, MAX_NATIVE_RPC_ACTION_BYTES,
        "{} Lean decoded byte cap must match production submit-action public_args cap",
        case.name
    );
    assert_eq!(
        case.item_count_cap,
        transaction_core::constants::MAX_OUTPUTS,
        "{} Lean item count cap must match production MAX_OUTPUTS",
        case.name
    );
    assert_eq!(
        case.item_byte_cap, MAX_CIPHERTEXT_BYTES,
        "{} Lean item byte cap must match production ciphertext cap",
        case.name
    );
    assert_eq!(
        case.aggregate_byte_cap,
        transaction_core::constants::MAX_OUTPUTS.saturating_mul(MAX_CIPHERTEXT_BYTES),
        "{} Lean aggregate byte cap must match production output-count ciphertext cap",
        case.name
    );
    assert_eq!(
        case.work_unit_cap,
        transaction_core::constants::MAX_OUTPUTS,
        "{} Lean work unit cap must match production MAX_OUTPUTS",
        case.name
    );
    let input = NativeInlineTransferCiphertextResourceInput {
        raw_byte_cap: case.raw_byte_cap,
        decoded_byte_cap: case.decoded_byte_cap,
        item_count_cap: case.item_count_cap,
        item_byte_cap: case.item_byte_cap,
        aggregate_byte_cap: case.aggregate_byte_cap,
        work_unit_cap: case.work_unit_cap,
        route_payload_bytes: case.route_payload_bytes,
        proof_bytes: case.proof_bytes,
        ciphertext_count: case.ciphertext_count,
        max_ciphertext_bytes_observed: case.max_ciphertext_bytes_observed,
        aggregate_ciphertext_bytes: case.aggregate_ciphertext_bytes,
    };
    let actual = evaluate_native_bounded_request_admission(
        inline_transfer_ciphertext_resource_bounded_request(input),
    );
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native inline transfer ciphertext resource validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native inline transfer ciphertext resource rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_transfer_state_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_TRANSFER_STATE_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_TRANSFER_STATE_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean transfer state admission vectors");
    let vectors: LeanTransferStateAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean transfer state admission vectors");
    assert_eq!(vectors.schema_version, 2);
    assert!(
        !vectors.transfer_state_admission_cases.is_empty(),
        "Lean transfer state admission cases must not be empty"
    );
    assert!(
        !vectors.transfer_nullifier_row_cases.is_empty(),
        "Lean transfer nullifier row cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.transfer_state_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_transfer_state_admission_case(case);
    }
    for case in &vectors.transfer_nullifier_row_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_transfer_nullifier_row_case(case);
    }
}

fn verify_lean_transfer_state_admission_case(case: &LeanTransferStateAdmissionCase) {
    let input = NativeTransferStateAdmissionInput {
        anchor_known: case.anchor_known,
        nullifier_state: lean_transfer_nullifier_state(&case.nullifier_state, &case.name),
        commitments_nonzero: case.commitments_nonzero,
        stablecoin_policy_authorized: case.stablecoin_policy_authorized,
        sidecar_route: case.sidecar_route,
        sidecar_ciphertexts_available: case.sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present: case.sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match: case.sidecar_ciphertext_sizes_match,
    };
    let actual_rejection = evaluate_native_transfer_state_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native transfer state admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native transfer state admission rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_transfer_nullifier_row_case(case: &LeanTransferNullifierRowCase) {
    let spent_nullifiers = parse_lean_nullifier_set(&case.spent_nullifiers, &case.name);
    let pending_nullifiers = parse_lean_nullifier_set(&case.pending_nullifiers, &case.name);
    let action_nullifiers = parse_lean_nullifier_vec(&case.action_nullifiers, &case.name);

    let mut mempool_state =
        NullifierState::new(spent_nullifiers.clone(), pending_nullifiers.clone());
    let actual_mempool = mempool_transfer_nullifier_admission_state_from_nullifiers(
        &mut mempool_state,
        &action_nullifiers,
    )
    .label()
    .to_owned();
    assert_eq!(
        actual_mempool, case.expected_mempool_nullifier_state,
        "{} mempool nullifier row admission drifted from Lean spec",
        case.name
    );

    let mut block_state = NullifierState::new(spent_nullifiers, pending_nullifiers);
    let actual_block = block_transfer_nullifier_admission_state_from_nullifiers(
        &mut block_state,
        &action_nullifiers,
    )
    .label()
    .to_owned();
    assert_eq!(
        actual_block, case.expected_block_nullifier_state,
        "{} block nullifier row admission drifted from Lean spec",
        case.name
    );
}

fn parse_lean_nullifier_set(values: &[String], case_name: &str) -> BTreeSet<[u8; 48]> {
    let mut out = BTreeSet::new();
    for value in values {
        let parsed = parse_hex48(value)
            .unwrap_or_else(|| panic!("{case_name} has invalid 48-byte nullifier {value}"));
        assert!(
            out.insert(parsed),
            "{case_name} repeats initial nullifier {value}"
        );
    }
    out
}

fn parse_lean_nullifier_vec(values: &[String], case_name: &str) -> Vec<[u8; 48]> {
    values
        .iter()
        .map(|value| {
            parse_hex48(value)
                .unwrap_or_else(|| panic!("{case_name} has invalid 48-byte nullifier {value}"))
        })
        .collect()
}

#[test]
fn lean_generated_stablecoin_policy_authorization_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_STABLECOIN_POLICY_AUTHORIZATION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_STABLECOIN_POLICY_AUTHORIZATION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean stablecoin policy authorization vectors");
    let vectors: LeanStablecoinPolicyAuthorizationVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean stablecoin policy authorization vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.stablecoin_policy_authorization_cases.is_empty(),
        "Lean stablecoin policy authorization cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.stablecoin_policy_authorization_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_stablecoin_policy_authorization_case(case);
    }
}

fn verify_lean_stablecoin_policy_authorization_case(case: &LeanStablecoinPolicyAuthorizationCase) {
    let input = NativeStablecoinPolicyAuthorizationInput {
        stablecoin_present: case.stablecoin_present,
        policy_known: case.policy_known,
        policy_active: case.policy_active,
        policy_lifecycle_open: case.policy_lifecycle_open,
        asset_matches: case.asset_matches,
        policy_hash_matches: case.policy_hash_matches,
        policy_version_matches: case.policy_version_matches,
        oracle_commitment_matches: case.oracle_commitment_matches,
        attestation_commitment_matches: case.attestation_commitment_matches,
        attestation_not_disputed: case.attestation_not_disputed,
        oracle_fresh: case.oracle_fresh,
        issuance_nonzero: case.issuance_nonzero,
        issuance_within_limit: case.issuance_within_limit,
    };
    let actual_rejection = evaluate_native_stablecoin_policy_authorization(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native stablecoin policy authorization validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native stablecoin policy authorization rejection drifted from Lean spec",
        case.name
    );
}

fn lean_transfer_nullifier_state(
    state: &str,
    case_name: &str,
) -> NativeTransferNullifierAdmissionState {
    match state {
        "valid" => NativeTransferNullifierAdmissionState::Valid,
        "zero" => NativeTransferNullifierAdmissionState::Zero,
        "already_spent" => NativeTransferNullifierAdmissionState::AlreadySpent,
        "duplicate" => NativeTransferNullifierAdmissionState::Duplicate,
        "already_pending" => NativeTransferNullifierAdmissionState::AlreadyPending,
        other => panic!("{case_name} has unknown transfer nullifier state {other}"),
    }
}

#[test]
fn lean_generated_action_state_effect_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_STATE_EFFECT_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_STATE_EFFECT_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean action state effect vectors");
    let vectors: LeanActionStateEffectVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean action state effect vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_state_effect_cases.is_empty(),
        "Lean action state effect cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_state_effect_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_state_effect_case(case);
    }
}

fn verify_lean_action_state_effect_case(case: &LeanActionStateEffectCase) {
    let (spent_nullifiers, nullifiers) =
        synthetic_action_effect_nullifiers(&case.nullifier_state, case.nullifier_count, &case.name);
    let (consumed_replays, replay_key) =
        synthetic_action_effect_replay(&case.bridge_replay_state, &case.name);
    let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
    let mut bridge_replay_state = InboundReplayState::new(consumed_replays, BTreeSet::new());

    let actual = evaluate_native_action_state_effect(
        case.leaf_start,
        case.commitment_count,
        case.ciphertext_count,
        &nullifiers,
        replay_key,
        &mut nullifier_state,
        &mut bridge_replay_state,
    );
    match actual {
        Ok(effect) => {
            assert!(
                case.expected_valid,
                "{} action state effect unexpectedly accepted",
                case.name
            );
            assert_eq!(
                Some(effect.next_leaf_count),
                case.expected_next_leaf_count,
                "{} next leaf count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(effect.imported_nullifier_count),
                case.expected_imported_nullifier_count,
                "{} imported nullifier count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(effect.imported_bridge_replay),
                case.expected_imported_bridge_replay,
                "{} imported bridge replay flag drifted from Lean spec",
                case.name
            );
        }
        Err(rejection) => {
            assert!(
                !case.expected_valid,
                "{} action state effect unexpectedly rejected: {}",
                case.name,
                rejection.label()
            );
            assert_eq!(
                Some(rejection.label().to_owned()),
                case.expected_rejection,
                "{} rejection drifted from Lean spec",
                case.name
            );
        }
    }
}

#[test]
fn lean_generated_action_stream_effect_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_STREAM_EFFECT_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_STREAM_EFFECT_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean action stream effect vectors");
    let vectors: LeanActionStreamEffectVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean action stream effect vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_stream_effect_cases.is_empty(),
        "Lean action stream effect cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_stream_effect_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_stream_effect_case(case);
    }
}

fn verify_lean_action_stream_effect_case(case: &LeanActionStreamEffectCase) {
    let spent_nullifiers = case
        .spent_nullifiers
        .iter()
        .map(|key| synthetic_stream_nullifier(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let consumed_bridge_replays = case
        .consumed_bridge_replays
        .iter()
        .map(|key| synthetic_stream_replay_key(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let action_nullifiers = case
        .actions
        .iter()
        .map(|action| {
            action
                .nullifiers
                .iter()
                .map(|key| synthetic_stream_nullifier(*key, &case.name))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let replay_keys = case
        .actions
        .iter()
        .map(|action| {
            action
                .bridge_replay_key
                .map(|key| synthetic_stream_replay_key(key, &case.name))
        })
        .collect::<Vec<_>>();
    let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
    let mut bridge_replay_state = InboundReplayState::new(consumed_bridge_replays, BTreeSet::new());

    let actual = evaluate_native_action_stream_effect(
        case.leaf_start,
        case.actions
            .iter()
            .zip(action_nullifiers.iter())
            .zip(replay_keys.iter())
            .map(
                |((action, nullifiers), replay_key)| NativeActionStreamStep {
                    commitment_count: action.commitment_count,
                    ciphertext_count: action.ciphertext_count,
                    nullifiers: nullifiers.as_slice(),
                    replay_key: *replay_key,
                },
            ),
        &mut nullifier_state,
        &mut bridge_replay_state,
    );
    match actual {
        Ok(effect) => {
            assert!(
                case.expected_valid,
                "{} action stream effect unexpectedly accepted",
                case.name
            );
            assert_eq!(
                Some(effect.next_leaf_count),
                case.expected_next_leaf_count,
                "{} stream next leaf count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(effect.imported_nullifier_count),
                case.expected_imported_nullifier_count,
                "{} stream imported nullifier count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(effect.imported_bridge_replay_count),
                case.expected_imported_bridge_replay_count,
                "{} stream imported bridge replay count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(effect.planned_starts),
                case.expected_planned_starts,
                "{} stream planned starts drifted from Lean spec",
                case.name
            );
        }
        Err(rejection) => {
            assert!(
                !case.expected_valid,
                "{} action stream effect unexpectedly rejected: {}",
                case.name,
                rejection.label()
            );
            assert_eq!(
                Some(rejection.label().to_owned()),
                case.expected_rejection,
                "{} stream rejection drifted from Lean spec",
                case.name
            );
        }
    }
}

#[test]
fn lean_generated_action_plan_application_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_PLAN_APPLICATION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean action plan application admission vectors");
    let vectors: LeanActionPlanApplicationAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean action plan application admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.action_plan_application_admission_cases.is_empty(),
        "Lean action plan application admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_plan_application_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_plan_application_admission_case(case);
    }
}

fn verify_lean_action_plan_application_admission_case(
    case: &LeanActionPlanApplicationAdmissionCase,
) {
    let actual = evaluate_native_action_plan_application_admission(
        case.leaf_start,
        &case.action_commitment_counts,
        &case.planned_starts,
    );
    match actual {
        Ok(summary) => {
            assert!(
                case.expected_valid,
                "{} action plan application unexpectedly accepted",
                case.name
            );
            assert_eq!(
                Some(summary.next_leaf_count),
                case.expected_next_leaf_count,
                "{} plan application next leaf count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.applied_action_count),
                case.expected_applied_action_count,
                "{} plan application action count drifted from Lean spec",
                case.name
            );
        }
        Err(rejection) => {
            assert!(
                !case.expected_valid,
                "{} action plan application unexpectedly rejected: {}",
                case.name,
                rejection.label()
            );
            assert_eq!(
                Some(rejection.label().to_owned()),
                case.expected_rejection,
                "{} plan application rejection drifted from Lean spec",
                case.name
            );
        }
    }
}

#[test]
fn lean_generated_action_wire_replay_projection_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_ACTION_WIRE_REPLAY_PROJECTION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean action wire replay projection admission vectors");
    let vectors: LeanActionWireReplayProjectionAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean action wire replay projection admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors
            .action_wire_replay_projection_admission_cases
            .is_empty(),
        "Lean action wire replay projection cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.action_wire_replay_projection_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_action_wire_replay_projection_admission_case(case);
    }
}

fn verify_lean_action_wire_replay_projection_admission_case(
    case: &LeanActionWireReplayProjectionAdmissionCase,
) {
    let steps = case
        .actions
        .iter()
        .map(|action| NativeActionWireReplayProjectionStep {
            ciphertext_hash_count: action.ciphertext_hash_count,
            ciphertext_size_count: action.ciphertext_size_count,
            planned_ciphertext_count: action.planned_ciphertext_count,
            ciphertext_hashes_match: action.ciphertext_hashes_match,
            ciphertext_sizes_match: action.ciphertext_sizes_match,
            planned_replay_present: action.planned_replay_present,
            replay_key_matches: action.replay_key_matches,
        })
        .collect::<Vec<_>>();
    let actual = evaluate_native_action_wire_replay_projection_admission(
        case.action_count,
        case.planned_count,
        &steps,
    );
    match actual {
        Ok(summary) => {
            assert!(
                case.expected_valid,
                "{} action wire replay projection unexpectedly accepted",
                case.name
            );
            assert_eq!(
                Some(summary.projected_action_count),
                case.expected_projected_action_count,
                "{} wire replay projected action count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.projected_ciphertext_row_count),
                case.expected_projected_ciphertext_row_count,
                "{} wire replay projected ciphertext rows drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.projected_bridge_replay_row_count),
                case.expected_projected_bridge_replay_row_count,
                "{} wire replay projected bridge replay rows drifted from Lean spec",
                case.name
            );
        }
        Err(rejection) => {
            assert!(
                !case.expected_valid,
                "{} action wire replay projection unexpectedly rejected: {}",
                case.name,
                rejection.label()
            );
            assert_eq!(
                Some(rejection.label().to_owned()),
                case.expected_rejection,
                "{} wire replay projection rejection drifted from Lean spec",
                case.name
            );
        }
    }
}

#[test]
fn lean_generated_pending_action_field_projection_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_PENDING_ACTION_FIELD_PROJECTION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_PENDING_ACTION_FIELD_PROJECTION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean pending-action field projection vectors");
    let vectors: LeanPendingActionFieldProjectionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean pending-action field projection vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.pending_action_field_projection_cases.is_empty(),
        "Lean pending-action field projection cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.pending_action_field_projection_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_pending_action_field_projection_case(case);
    }
}

fn verify_lean_pending_action_field_projection_case(case: &LeanPendingActionFieldProjectionCase) {
    assert!(
        case.expected_valid,
        "{} generated field projection case is expected to accept",
        case.name
    );
    let pow_bits = 0x207f_ffff;
    let genesis = genesis_meta(pow_bits).expect("genesis");
    let anchor = test_state(genesis.clone()).commitment_tree.root();
    let actions = case
        .actions
        .iter()
        .map(|spec| lean_pending_action_projection_fixture(&spec.fixture_name, anchor))
        .collect::<Vec<_>>();
    assert_eq!(
        actions.len(),
        case.actions.len(),
        "{} action fixture count drifted",
        case.name
    );

    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    for action in &actions {
        insert_test_sidecar_ciphertext(&da_ciphertext_tree, action);
    }

    let mut block = genesis.clone();
    block.height = genesis.height + 1;
    block.parent_hash = genesis.hash;
    block.tx_count = u32::try_from(actions.len()).expect("fixture action count fits u32");
    block.action_bytes = actions.iter().map(Encode::encode).collect();
    let chain = vec![genesis, block];
    let decoded_actions = chain
        .iter()
        .skip(1)
        .flat_map(|meta| {
            decode_block_actions(meta)
                .unwrap_or_else(|err| panic!("{}: decode canonical action bytes: {err}", case.name))
        })
        .collect::<Vec<_>>();
    assert_eq!(decoded_actions.len(), case.actions.len(), "{}", case.name);

    for (spec, action) in case.actions.iter().zip(decoded_actions.iter()) {
        assert_eq!(
            action.commitments.len(),
            spec.commitment_count,
            "{} fixture {} commitment count drifted",
            case.name,
            spec.fixture_name
        );
        assert_eq!(
            action.nullifiers.len(),
            spec.nullifier_count,
            "{} fixture {} nullifier count drifted",
            case.name,
            spec.fixture_name
        );
        assert_eq!(
            canonical_ciphertext_count_for_action(action).expect("canonical ciphertext count"),
            spec.ciphertext_count,
            "{} fixture {} ciphertext count drifted",
            case.name,
            spec.fixture_name
        );
        assert_eq!(
            bridge_inbound_replay_key_from_action(action)
                .expect("bridge replay projection")
                .is_some(),
            spec.has_bridge_replay,
            "{} fixture {} bridge replay projection drifted",
            case.name,
            spec.fixture_name
        );
    }

    let materialized = materialize_native_action_payloads(&da_ciphertext_tree, &decoded_actions)
        .unwrap_or_else(|err| panic!("{}: materialize decoded actions: {err}", case.name));
    let plan = plan_canonical_index_rebuild(&chain, &da_ciphertext_tree, None)
        .unwrap_or_else(|err| panic!("{}: canonical index rebuild plan: {err}", case.name));

    let expected_commitment_entries = case
        .expected_commitment_rows
        .iter()
        .map(|row| {
            let action = decoded_actions
                .get(row.action_index)
                .unwrap_or_else(|| panic!("{}: commitment row action index", case.name));
            let commitment = action
                .commitments
                .get(row.offset)
                .unwrap_or_else(|| panic!("{}: commitment row offset", case.name));
            (row.commitment_index, *commitment)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        plan.commitment_entries, expected_commitment_entries,
        "{} commitment rows drifted from Lean projection",
        case.name
    );

    let expected_nullifier_entries = case
        .expected_nullifier_rows
        .iter()
        .map(|row| {
            let action = decoded_actions
                .get(row.action_index)
                .unwrap_or_else(|| panic!("{}: nullifier row action index", case.name));
            *action
                .nullifiers
                .get(row.offset)
                .unwrap_or_else(|| panic!("{}: nullifier row offset", case.name))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        plan.nullifier_entries, expected_nullifier_entries,
        "{} nullifier rows drifted from Lean projection",
        case.name
    );

    let expected_bridge_replay_entries = case
        .expected_bridge_replay_rows
        .iter()
        .map(|action_index| {
            let action = decoded_actions
                .get(*action_index)
                .unwrap_or_else(|| panic!("{}: bridge replay row action index", case.name));
            bridge_inbound_replay_key_from_action(action)
                .expect("bridge replay projection")
                .unwrap_or_else(|| panic!("{}: missing expected bridge replay key", case.name))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        plan.bridge_replay_entries, expected_bridge_replay_entries,
        "{} bridge replay rows drifted from Lean projection",
        case.name
    );

    let expected_ciphertext_index_entries = case
        .expected_ciphertext_index_rows
        .iter()
        .map(|row| {
            let action = decoded_actions
                .get(row.action_index)
                .unwrap_or_else(|| panic!("{}: ciphertext index row action index", case.name));
            let hash = action
                .ciphertext_hashes
                .get(row.offset)
                .unwrap_or_else(|| panic!("{}: ciphertext index row offset", case.name));
            let size = action
                .ciphertext_sizes
                .get(row.offset)
                .copied()
                .unwrap_or_else(|| panic!("{}: ciphertext size row offset", case.name));
            let mut value = Vec::with_capacity(32 + 4 + 8);
            value.extend_from_slice(&action.tx_hash);
            value.extend_from_slice(&size.to_le_bytes());
            value.extend_from_slice(&(row.offset as u64).to_le_bytes());
            (*hash, value)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        plan.ciphertext_index_entries, expected_ciphertext_index_entries,
        "{} ciphertext index rows drifted from Lean projection",
        case.name
    );

    let expected_ciphertext_archive_entries = case
        .expected_ciphertext_archive_rows
        .iter()
        .map(|row| {
            let payload = materialized
                .get(row.action_index)
                .unwrap_or_else(|| panic!("{}: ciphertext archive action index", case.name));
            let bytes = payload
                .ciphertexts
                .get(row.offset)
                .unwrap_or_else(|| panic!("{}: ciphertext archive row offset", case.name));
            (row.commitment_index, bytes.clone())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        plan.ciphertext_archive_entries, expected_ciphertext_archive_entries,
        "{} ciphertext archive rows drifted from Lean projection",
        case.name
    );
}

fn lean_pending_action_projection_fixture(name: &str, anchor: [u8; 48]) -> PendingAction {
    match name {
        "sidecar-a" => test_sidecar_transfer_action(anchor, [77u8; 48], [78u8; 48], 0),
        "sidecar-b" => test_sidecar_transfer_action(anchor, [87u8; 48], [88u8; 48], 0),
        "outbound-a" => test_outbound_bridge_action(b"lean projection outbound"),
        "inbound-a" => test_inbound_bridge_action(b"lean projection inbound"),
        "candidate-a" => test_candidate_artifact_action(1, 89),
        other => panic!("unknown Lean pending-action projection fixture {other}"),
    }
}

#[test]
fn lean_generated_block_action_validation_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_ACTION_VALIDATION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BLOCK_ACTION_VALIDATION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean block action validation vectors");
    let vectors: LeanBlockActionValidationVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean block action validation vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.block_action_validation_cases.is_empty(),
        "Lean block action validation cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.block_action_validation_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_block_action_validation_case(case);
    }
}

fn verify_lean_block_action_validation_case(case: &LeanBlockActionValidationCase) {
    let consumed_bridge_replays = case
        .consumed_bridge_replays
        .iter()
        .map(|key| synthetic_stream_replay_key(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let mut actual_rejection = None;
    let mut validation_state = match evaluate_native_block_action_validation_start(
        case.action_count_matches,
        case.action_hashes_match,
        case.action_hashes_unique,
        consumed_bridge_replays,
    ) {
        Ok(state) => Some(state),
        Err(rejection) => {
            assert!(
                !case.expected_valid,
                "{} block action validation unexpectedly rejected at hash gate: {}",
                case.name,
                rejection.label()
            );
            actual_rejection = Some(rejection);
            None
        }
    };
    if let Some(ref mut validation_state) = validation_state {
        for action in &case.actions {
            let step = NativeBlockActionValidationStep {
                scope_input: lean_block_action_validation_scope(&action.scope),
                payload_valid: action.payload_valid,
                transfer_key: synthetic_transfer_order_key(action.transfer_key),
                transfer_state_input: lean_block_action_validation_transfer_state(
                    &action.transfer_state,
                ),
                bridge_replay_key: action
                    .bridge_replay_key
                    .map(|key| synthetic_stream_replay_key(key, &case.name)),
            };
            if let Err(rejection) =
                evaluate_native_block_action_validation_step(validation_state, step)
            {
                actual_rejection = Some(rejection);
                break;
            }
        }
    }

    match actual_rejection {
        Some(rejection) => {
            assert!(
                !case.expected_valid,
                "{} block action validation unexpectedly rejected: {}",
                case.name,
                rejection.label()
            );
            assert_eq!(
                Some(rejection.label().to_owned()),
                case.expected_rejection,
                "{} block action validation rejection drifted from Lean spec",
                case.name
            );
        }
        None => {
            let summary = native_block_action_validation_summary(
                validation_state.expect("accepted block action validation state"),
            );
            assert!(
                case.expected_valid,
                "{} block action validation unexpectedly accepted",
                case.name
            );
            assert_eq!(
                Some(summary.validated_action_count),
                case.expected_validated_action_count,
                "{} validated action count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.imported_bridge_replay_count),
                case.expected_imported_bridge_replay_count,
                "{} imported bridge replay count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                summary.last_transfer_key.map(observed_transfer_order_key),
                case.expected_last_transfer_key,
                "{} last transfer key drifted from Lean spec",
                case.name
            );
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeBlockActionReplayPublicationRejection {
    ValidationRejected,
    ReplayRejected,
    WireProjectionRejected,
    ValidationWireActionCountMismatch,
    WireReplayActionCountMismatch,
    ValidationBridgeReplayCountMismatch,
    ReplayBridgeReplayCountMismatch,
}

impl NativeBlockActionReplayPublicationRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ValidationRejected => "validation_rejected",
            Self::ReplayRejected => "replay_rejected",
            Self::WireProjectionRejected => "wire_projection_rejected",
            Self::ValidationWireActionCountMismatch => "validation_wire_action_count_mismatch",
            Self::WireReplayActionCountMismatch => "wire_replay_action_count_mismatch",
            Self::ValidationBridgeReplayCountMismatch => "validation_bridge_replay_count_mismatch",
            Self::ReplayBridgeReplayCountMismatch => "replay_bridge_replay_count_mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeBlockActionReplayPublicationSummary {
    validated_action_count: usize,
    replay_action_count: usize,
    wire_projected_action_count: usize,
    imported_bridge_replay_count: usize,
    wire_projected_bridge_replay_count: usize,
    replay_next_leaf_count: u64,
    replay_supply: u128,
}

#[test]
fn lean_generated_block_action_replay_publication_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_ACTION_REPLAY_PUBLICATION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BLOCK_ACTION_REPLAY_PUBLICATION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean block-action replay publication vectors");
    let vectors: LeanBlockActionReplayPublicationVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean block-action replay publication vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.block_action_replay_publication_cases.is_empty(),
        "Lean block-action replay publication cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.block_action_replay_publication_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_block_action_replay_publication_case(case);
    }
}

fn verify_lean_block_action_replay_publication_case(case: &LeanBlockActionReplayPublicationCase) {
    match evaluate_native_block_action_replay_publication_case(case) {
        Ok(summary) => {
            assert!(
                case.expected_valid,
                "{} block-action replay publication unexpectedly accepted",
                case.name
            );
            assert_eq!(
                Some(summary.validated_action_count),
                case.expected_validated_action_count,
                "{} validated action count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.replay_action_count),
                case.expected_replay_action_count,
                "{} replay action count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.wire_projected_action_count),
                case.expected_wire_projected_action_count,
                "{} wire projected action count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.imported_bridge_replay_count),
                case.expected_imported_bridge_replay_count,
                "{} imported bridge replay count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.wire_projected_bridge_replay_count),
                case.expected_wire_projected_bridge_replay_count,
                "{} wire projected bridge replay count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.replay_next_leaf_count.to_string()),
                case.expected_replay_next_leaf_count,
                "{} replay next leaf count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.replay_supply.to_string()),
                case.expected_replay_supply,
                "{} replay supply drifted from Lean spec",
                case.name
            );
        }
        Err(rejection) => {
            assert!(
                !case.expected_valid,
                "{} block-action replay publication unexpectedly rejected: {}",
                case.name,
                rejection.label()
            );
            assert_eq!(
                Some(rejection.label().to_owned()),
                case.expected_rejection,
                "{} block-action replay publication rejection drifted from Lean spec",
                case.name
            );
        }
    }
}

fn evaluate_native_block_action_replay_publication_case(
    case: &LeanBlockActionReplayPublicationCase,
) -> Result<NativeBlockActionReplayPublicationSummary, NativeBlockActionReplayPublicationRejection>
{
    let consumed_bridge_replays = case
        .validation_consumed_bridge_replays
        .iter()
        .map(|key| synthetic_stream_replay_key(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let mut validation_state = evaluate_native_block_action_validation_start(
        case.validation_action_count_matches,
        case.validation_action_hashes_match,
        case.validation_action_hashes_unique,
        consumed_bridge_replays,
    )
    .map_err(|_| NativeBlockActionReplayPublicationRejection::ValidationRejected)?;
    for action in &case.validation_actions {
        let step = NativeBlockActionValidationStep {
            scope_input: lean_block_action_validation_scope(&action.scope),
            payload_valid: action.payload_valid,
            transfer_key: synthetic_transfer_order_key(action.transfer_key),
            transfer_state_input: lean_block_action_validation_transfer_state(
                &action.transfer_state,
            ),
            bridge_replay_key: action
                .bridge_replay_key
                .map(|key| synthetic_stream_replay_key(key, &case.name)),
        };
        evaluate_native_block_action_validation_step(&mut validation_state, step)
            .map_err(|_| NativeBlockActionReplayPublicationRejection::ValidationRejected)?;
    }
    let validation_summary = native_block_action_validation_summary(validation_state);

    let spent_nullifiers = case
        .replay_spent_nullifiers
        .iter()
        .map(|key| synthetic_stream_nullifier(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let consumed_replays = case
        .replay_consumed_bridge_replays
        .iter()
        .map(|key| synthetic_stream_replay_key(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let action_nullifiers = case
        .replay_actions
        .iter()
        .map(|action| {
            action
                .nullifiers
                .iter()
                .map(|key| synthetic_stream_nullifier(*key, &case.name))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let replay_keys = case
        .replay_actions
        .iter()
        .map(|action| {
            action
                .bridge_replay_key
                .map(|key| synthetic_stream_replay_key(key, &case.name))
        })
        .collect::<Vec<_>>();
    let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
    let mut bridge_replay_state = InboundReplayState::new(consumed_replays, BTreeSet::new());
    let replay_input = NativeBlockReplayRefinementInput {
        leaf_start: case.replay_leaf_start,
        parent_supply: parse_u128(&case.replay_parent_supply),
        height: case.replay_height,
        fee_total: case.replay_fee_total,
        has_coinbase: case.replay_has_coinbase,
        claimed_supply: parse_u128(&case.replay_claimed_supply),
        tx_count_matches: case.replay_tx_count_matches,
        state_root_matches: case.replay_state_root_matches,
        kernel_root_matches: case.replay_kernel_root_matches,
        nullifier_root_matches: case.replay_nullifier_root_matches,
        extrinsics_root_matches: case.replay_extrinsics_root_matches,
        message_root_matches: case.replay_message_root_matches,
        message_count_matches: case.replay_message_count_matches,
        header_mmr_root_matches: case.replay_header_mmr_root_matches,
        header_mmr_len_matches: case.replay_header_mmr_len_matches,
    };
    let (_trace, replay_result) = evaluate_native_block_replay_refinement_with_trace(
        replay_input,
        case.replay_actions
            .iter()
            .zip(action_nullifiers.iter())
            .zip(replay_keys.iter())
            .map(
                |((action, nullifiers), replay_key)| NativeActionStreamStep {
                    commitment_count: action.commitment_count,
                    ciphertext_count: action.ciphertext_count,
                    nullifiers: nullifiers.as_slice(),
                    replay_key: *replay_key,
                },
            ),
        &mut nullifier_state,
        &mut bridge_replay_state,
    );
    let replay_summary =
        replay_result.map_err(|_| NativeBlockActionReplayPublicationRejection::ReplayRejected)?;

    let wire_steps = case
        .wire_actions
        .iter()
        .map(|action| NativeActionWireReplayProjectionStep {
            ciphertext_hash_count: action.ciphertext_hash_count,
            ciphertext_size_count: action.ciphertext_size_count,
            planned_ciphertext_count: action.planned_ciphertext_count,
            ciphertext_hashes_match: action.ciphertext_hashes_match,
            ciphertext_sizes_match: action.ciphertext_sizes_match,
            planned_replay_present: action.planned_replay_present,
            replay_key_matches: action.replay_key_matches,
        })
        .collect::<Vec<_>>();
    let wire_summary = evaluate_native_action_wire_replay_projection_admission(
        case.wire_action_count,
        case.wire_planned_count,
        &wire_steps,
    )
    .map_err(|_| NativeBlockActionReplayPublicationRejection::WireProjectionRejected)?;

    if case.wire_action_count != case.validation_actions.len() {
        return Err(NativeBlockActionReplayPublicationRejection::ValidationWireActionCountMismatch);
    }
    if wire_summary.projected_action_count != case.replay_actions.len() {
        return Err(NativeBlockActionReplayPublicationRejection::WireReplayActionCountMismatch);
    }
    if validation_summary.imported_bridge_replay_count
        != wire_summary.projected_bridge_replay_row_count
    {
        return Err(
            NativeBlockActionReplayPublicationRejection::ValidationBridgeReplayCountMismatch,
        );
    }
    if replay_summary.imported_bridge_replay_count != wire_summary.projected_bridge_replay_row_count
    {
        return Err(NativeBlockActionReplayPublicationRejection::ReplayBridgeReplayCountMismatch);
    }

    Ok(NativeBlockActionReplayPublicationSummary {
        validated_action_count: validation_summary.validated_action_count,
        replay_action_count: case.replay_actions.len(),
        wire_projected_action_count: wire_summary.projected_action_count,
        imported_bridge_replay_count: validation_summary.imported_bridge_replay_count,
        wire_projected_bridge_replay_count: wire_summary.projected_bridge_replay_row_count,
        replay_next_leaf_count: replay_summary.next_leaf_count,
        replay_supply: replay_summary.expected_supply,
    })
}

fn lean_block_action_validation_scope(
    scope: &LeanBlockActionValidationScopeCase,
) -> NativeActionScopeAdmissionInput {
    NativeActionScopeAdmissionInput {
        candidate_artifact_payload_scoped: scope.candidate_artifact_payload_scoped,
        bridge_route: scope.bridge_route,
        bridge_scope_valid: scope.bridge_scope_valid,
        candidate_artifact_route: scope.candidate_artifact_route,
        candidate_scope_valid: scope.candidate_scope_valid,
        candidate_payload_present: scope.candidate_payload_present,
        coinbase_route: scope.coinbase_route,
        coinbase_scope_valid: scope.coinbase_scope_valid,
        transfer_route: scope.transfer_route,
        transfer_scope_valid: scope.transfer_scope_valid,
    }
}

fn lean_block_action_validation_transfer_state(
    state: &LeanBlockActionValidationTransferStateCase,
) -> NativeTransferStateAdmissionInput {
    NativeTransferStateAdmissionInput {
        anchor_known: state.anchor_known,
        nullifier_state: match state.nullifier_state.as_str() {
            "valid" => NativeTransferNullifierAdmissionState::Valid,
            "zero" => NativeTransferNullifierAdmissionState::Zero,
            "already_spent" => NativeTransferNullifierAdmissionState::AlreadySpent,
            "duplicate" => NativeTransferNullifierAdmissionState::Duplicate,
            "already_pending" => NativeTransferNullifierAdmissionState::AlreadyPending,
            other => panic!("unknown block action transfer nullifier state {other}"),
        },
        commitments_nonzero: state.commitments_nonzero,
        stablecoin_policy_authorized: state.stablecoin_policy_authorized,
        sidecar_route: state.sidecar_route,
        sidecar_ciphertexts_available: state.sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present: state.sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match: state.sidecar_ciphertext_sizes_match,
    }
}

fn synthetic_transfer_order_key(key: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&key.to_be_bytes());
    bytes
}

fn observed_transfer_order_key(key: [u8; 32]) -> u64 {
    u64::from_be_bytes(
        key[24..32]
            .try_into()
            .expect("synthetic transfer order key has 8 trailing bytes"),
    )
}

fn synthetic_action_effect_nullifiers(
    state: &str,
    count: usize,
    case_name: &str,
) -> (BTreeSet<[u8; 48]>, Vec<[u8; 48]>) {
    match state {
        "valid" => (
            BTreeSet::new(),
            (0..count)
                .map(|idx| synthetic_hash48(0x20, idx, case_name))
                .collect(),
        ),
        "zero" => (BTreeSet::new(), vec![[0u8; 48]; count.max(1)]),
        "duplicate" => {
            let duplicate = synthetic_hash48(0x40, 0, case_name);
            let mut spent = BTreeSet::new();
            spent.insert(duplicate);
            (spent, vec![duplicate; count.max(1)])
        }
        other => panic!("{case_name} has unknown action-effect nullifier state {other}"),
    }
}

fn synthetic_action_effect_replay(
    state: &str,
    case_name: &str,
) -> (BTreeSet<[u8; 48]>, Option<[u8; 48]>) {
    match state {
        "absent" => (BTreeSet::new(), None),
        "valid" => (BTreeSet::new(), Some(synthetic_hash48(0x60, 0, case_name))),
        "already_consumed" => {
            let replay_key = synthetic_hash48(0x70, 0, case_name);
            let mut consumed = BTreeSet::new();
            consumed.insert(replay_key);
            (consumed, Some(replay_key))
        }
        other => panic!("{case_name} has unknown bridge replay state {other}"),
    }
}

fn synthetic_stream_nullifier(key: u64, case_name: &str) -> [u8; 48] {
    if key == 0 {
        return [0u8; 48];
    }
    synthetic_stream_key(0x81, key, case_name)
}

fn synthetic_stream_replay_key(key: u64, case_name: &str) -> [u8; 48] {
    synthetic_stream_key(0x82, key, case_name)
}

fn synthetic_stream_key(domain: u8, key: u64, case_name: &str) -> [u8; 48] {
    let mut hash = [0u8; 48];
    hash[0] = domain;
    hash[1..9].copy_from_slice(&key.to_le_bytes());
    let name_bytes = case_name.as_bytes();
    for (idx, byte) in name_bytes.iter().take(39).enumerate() {
        hash[idx + 9] = *byte;
    }
    hash
}

fn synthetic_hash48(domain: u8, index: usize, case_name: &str) -> [u8; 48] {
    let mut hash = [0u8; 48];
    hash[0] = domain;
    hash[1] = u8::try_from(index).unwrap_or(u8::MAX);
    let name_bytes = case_name.as_bytes();
    for (idx, byte) in name_bytes.iter().take(46).enumerate() {
        hash[idx + 2] = *byte;
    }
    hash
}

#[test]
fn lean_generated_candidate_artifact_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_CANDIDATE_ARTIFACT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean candidate artifact admission vectors");
    let vectors: LeanCandidateArtifactAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean candidate artifact admission vectors");
    assert_eq!(vectors.schema_version, 2);
    assert!(
        !vectors.candidate_artifact_admission_cases.is_empty(),
        "Lean candidate artifact admission cases must not be empty"
    );
    assert!(
        !vectors
            .candidate_artifact_resource_projection_cases
            .is_empty(),
        "Lean candidate artifact resource projection cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.candidate_artifact_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_candidate_artifact_admission_case(case);
    }
    for case in &vectors.candidate_artifact_resource_projection_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_candidate_artifact_resource_projection_case(case);
    }
}

fn verify_lean_candidate_artifact_admission_case(case: &LeanCandidateArtifactAdmissionCase) {
    let input = NativeCandidateArtifactAdmissionInput {
        state_deltas_absent: case.state_deltas_absent,
        route_payload_decodes_exactly: case.route_payload_decodes_exactly,
        route_payload_matches_artifact: case.route_payload_matches_artifact,
        artifact_present: case.artifact_present,
        schema_matches: case.schema_matches,
        tx_count: case.tx_count,
        max_tx_count: case.max_tx_count,
        da_chunk_count: case.da_chunk_count,
        proof_mode_recursive_block: case.proof_mode_recursive_block,
        proof_kind_recursive_block_v2: case.proof_kind_recursive_block_v2,
        verifier_profile_matches: case.verifier_profile_matches,
        commitment_proof_empty: case.commitment_proof_empty,
        receipt_root_absent: case.receipt_root_absent,
        recursive_payload_present: case.recursive_payload_present,
        recursive_proof_bytes: case.recursive_proof_bytes,
        max_recursive_proof_bytes: case.max_recursive_proof_bytes,
    };
    let actual_rejection = evaluate_native_candidate_artifact_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native candidate-artifact admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native candidate-artifact admission rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_candidate_artifact_resource_projection_case(
    case: &LeanCandidateArtifactResourceProjectionCase,
) {
    let input = NativeCandidateArtifactResourceProjectionInput {
        raw_byte_cap: case.raw_byte_cap,
        decoded_byte_cap: case.decoded_byte_cap,
        item_count_cap: case.item_count_cap,
        item_byte_cap: case.item_byte_cap,
        aggregate_byte_cap: case.aggregate_byte_cap,
        work_unit_cap: case.work_unit_cap,
        declared_bytes: case.declared_bytes,
        proof_bytes: case.proof_bytes,
        receipt_bytes: case.receipt_bytes,
        recursive_bytes: case.recursive_bytes,
        tx_count: case.tx_count,
        da_chunk_count: case.da_chunk_count,
    };
    let bounded = native_candidate_artifact_resource_bounded_request(input);
    assert_eq!(
        bounded.raw_bytes, case.expected_raw_bytes,
        "{} candidate-artifact declared-byte projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.decoded_bytes, case.expected_decoded_bytes,
        "{} candidate-artifact decoded-byte projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.item_count, case.expected_item_count,
        "{} candidate-artifact tx-count projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.max_item_bytes, case.expected_max_item_bytes,
        "{} candidate-artifact proof-like max-byte projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.aggregate_bytes, case.expected_aggregate_bytes,
        "{} candidate-artifact proof-like aggregate projection drifted from Lean spec",
        case.name
    );
    assert_eq!(
        bounded.work_units, case.expected_work_units,
        "{} candidate-artifact DA chunk projection drifted from Lean spec",
        case.name
    );

    let actual = evaluate_native_bounded_request_admission(bounded);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} candidate-artifact bounded-resource validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} candidate-artifact bounded-resource rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_candidate_artifact_coupling_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_CANDIDATE_ARTIFACT_COUPLING_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean candidate artifact coupling admission vectors");
    let vectors: LeanCandidateArtifactCouplingAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean candidate artifact coupling admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors
            .candidate_artifact_coupling_admission_cases
            .is_empty(),
        "Lean candidate artifact coupling admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.candidate_artifact_coupling_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_candidate_artifact_coupling_admission_case(case);
    }
}

fn verify_lean_candidate_artifact_coupling_admission_case(
    case: &LeanCandidateArtifactCouplingAdmissionCase,
) {
    let input = NativeCandidateArtifactCouplingAdmissionInput {
        transfer_count: case.transfer_count,
        candidate_artifact_count: case.candidate_artifact_count,
        candidate_tx_count_matches: case.candidate_tx_count_matches,
    };
    let actual_rejection = evaluate_native_candidate_artifact_coupling_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native candidate-artifact coupling admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native candidate-artifact coupling admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_mineable_action_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_MINEABLE_ACTION_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_MINEABLE_ACTION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean mineable action admission vectors");
    let vectors: LeanMineableActionAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean mineable action admission vectors");
    assert_eq!(vectors.schema_version, 3);
    assert!(
        !vectors.mineable_action_admission_cases.is_empty(),
        "Lean mineable action admission cases must not be empty"
    );
    assert!(
        !vectors.mineable_selection_cases.is_empty(),
        "Lean mineable selection cases must not be empty"
    );
    assert!(
        !vectors.pending_candidate_prune_cases.is_empty(),
        "Lean pending-candidate prune cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.mineable_action_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_mineable_action_admission_case(case);
    }
    for case in &vectors.mineable_selection_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_mineable_selection_case(case);
    }
    for case in &vectors.pending_candidate_prune_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_pending_candidate_prune_case(case);
    }
}

fn verify_lean_mineable_action_admission_case(case: &LeanMineableActionAdmissionCase) {
    let input = NativeMineableActionAdmissionInput {
        candidate_artifact_route: case.candidate_artifact_route,
        candidate_artifact_selected: case.candidate_artifact_selected,
        sidecar_transfer_route: case.sidecar_transfer_route,
        sidecar_ciphertexts_available: case.sidecar_ciphertexts_available,
        sidecar_ciphertext_sizes_present: case.sidecar_ciphertext_sizes_present,
        sidecar_ciphertext_sizes_match: case.sidecar_ciphertext_sizes_match,
    };
    let actual_rejection = evaluate_native_mineable_action_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native mineable action admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native mineable action admission rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_mineable_selection_case(case: &LeanMineableSelectionCase) {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut label_by_hash = BTreeMap::<[u8; 32], String>::new();
    let mut label_by_action_id = BTreeMap::<usize, String>::new();

    for action_case in &case.actions {
        let action = lean_mineable_selection_fixture_action(action_case, anchor);
        assert_eq!(
            is_shielded_transfer_action(&action),
            action_case.transfer_route,
            "{} {} transfer-route fixture drifted from Lean spec",
            case.name,
            action_case.label
        );
        assert_eq!(
            is_candidate_artifact_action(&action),
            action_case.candidate_artifact_route,
            "{} {} candidate-route fixture drifted from Lean spec",
            case.name,
            action_case.label
        );
        if let Some(candidate) = action.candidate_artifact.as_ref() {
            assert_eq!(
                usize::try_from(candidate.tx_count).expect("tx_count fits usize"),
                action_case.candidate_tx_count,
                "{} {} candidate tx_count fixture drifted from Lean spec",
                case.name,
                action_case.label
            );
        }
        if action_case.transfer_route && action_case.transfer_mineable {
            stage_ciphertext_metadata_for_action(&mut state, &action);
        }

        let preselection_input = native_mineable_action_admission_input(&state, &action, None);
        if action_case.transfer_route {
            assert_eq!(
                evaluate_native_mineable_action_admission(preselection_input).is_ok(),
                action_case.transfer_mineable,
                "{} {} transfer preselection mineability drifted from Lean spec",
                case.name,
                action_case.label
            );
        }

        assert!(
            label_by_hash
                .insert(action.tx_hash, action_case.label.clone())
                .is_none(),
            "{} duplicate fixture tx_hash for {}",
            case.name,
            action_case.label
        );
        assert!(
            label_by_action_id
                .insert(action_case.action_id, action_case.label.clone())
                .is_none(),
            "{} duplicate Lean action_id {}",
            case.name,
            action_case.action_id
        );
        state.pending_actions.insert(action.tx_hash, action);
    }

    let transfer_count = ordered_pending_actions(&state)
        .iter()
        .filter(|action| is_shielded_transfer_action(action))
        .filter(|action| {
            let input = native_mineable_action_admission_input(&state, action, None);
            evaluate_native_mineable_action_admission(input).is_ok()
        })
        .count();
    assert_eq!(
        transfer_count, case.transfer_count,
        "{} mineable transfer count drifted from Lean spec",
        case.name
    );

    let selected = select_mineable_actions(&state);
    let actual_labels = selected
        .iter()
        .map(|action| {
            label_by_hash
                .get(&action.tx_hash)
                .unwrap_or_else(|| panic!("{} selected unknown action", case.name))
                .clone()
        })
        .collect::<Vec<_>>();
    let expected_labels = case
        .actions
        .iter()
        .filter(|action| action.expected_accepted)
        .map(|action| action.label.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        actual_labels, expected_labels,
        "{} selected mineable action order drifted from Lean spec",
        case.name
    );

    let actual_selected_candidate = selected
        .iter()
        .find(|action| is_candidate_artifact_action(action))
        .map(|action| {
            case.actions
                .iter()
                .find(|candidate| {
                    label_by_hash
                        .get(&action.tx_hash)
                        .is_some_and(|label| label == &candidate.label)
                })
                .expect("selected candidate has Lean case")
                .action_id
        });
    assert_eq!(
        actual_selected_candidate, case.selected_candidate_action_id,
        "{} selected candidate action id drifted from Lean spec",
        case.name
    );

    for action_case in &case.actions {
        let actual_accepted = actual_labels
            .iter()
            .any(|label| label == &action_case.label);
        assert_eq!(
            actual_accepted, action_case.expected_accepted,
            "{} {} accepted flag drifted from Lean spec",
            case.name, action_case.label
        );
        let actual_selected = actual_selected_candidate
            .is_some_and(|selected_id| selected_id == action_case.action_id);
        assert_eq!(
            actual_selected, action_case.expected_selected,
            "{} {} selected-candidate flag drifted from Lean spec",
            case.name, action_case.label
        );
    }
}

fn lean_mineable_selection_fixture_action(
    action_case: &LeanMineableSelectionAction,
    anchor: [u8; 48],
) -> PendingAction {
    lean_mineable_fixture_action(&action_case.fixture, anchor)
}

fn verify_lean_pending_candidate_prune_case(case: &LeanPendingCandidatePruneCase) {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut label_by_hash = BTreeMap::<[u8; 32], String>::new();
    let mut label_by_action_id = BTreeMap::<usize, String>::new();

    for action_case in &case.actions {
        let action = lean_mineable_fixture_action(&action_case.fixture, anchor);
        assert_eq!(
            is_shielded_transfer_action(&action),
            action_case.transfer_route,
            "{} {} transfer-route fixture drifted from Lean prune spec",
            case.name,
            action_case.label
        );
        assert_eq!(
            is_candidate_artifact_action(&action),
            action_case.candidate_artifact_route,
            "{} {} candidate-route fixture drifted from Lean prune spec",
            case.name,
            action_case.label
        );
        assert!(
            label_by_hash
                .insert(action.tx_hash, action_case.label.clone())
                .is_none(),
            "{} duplicate fixture tx_hash for {}",
            case.name,
            action_case.label
        );
        assert!(
            label_by_action_id
                .insert(action_case.action_id, action_case.label.clone())
                .is_none(),
            "{} duplicate Lean prune action_id {}",
            case.name,
            action_case.action_id
        );
        state.pending_actions.insert(action.tx_hash, action);
    }

    let transfer_pending = state
        .pending_actions
        .values()
        .any(is_shielded_transfer_action);
    assert_eq!(
        transfer_pending, case.transfer_pending,
        "{} transfer-pending predicate drifted from Lean prune spec",
        case.name
    );

    prune_candidate_artifacts_when_transfers_pending(&mut state, "lean vector");
    let actual_labels = state
        .pending_actions
        .keys()
        .map(|hash| {
            label_by_hash
                .get(hash)
                .unwrap_or_else(|| panic!("{} survivor has unknown hash", case.name))
                .clone()
        })
        .collect::<BTreeSet<_>>();
    let expected_labels = case
        .actions
        .iter()
        .filter(|action| action.expected_survives_after_transfer_prune)
        .map(|action| action.label.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_labels, expected_labels,
        "{} pending-candidate prune survivor set drifted from Lean spec",
        case.name
    );
}

fn lean_mineable_fixture_action(fixture: &str, anchor: [u8; 48]) -> PendingAction {
    match fixture {
        "inline-a" => test_inline_transfer_action(anchor, [161u8; 48], [162u8; 48], 0),
        "sidecar-a" => test_sidecar_transfer_action(anchor, [163u8; 48], [164u8; 48], 0),
        "sidecar-missing" => test_sidecar_transfer_action(anchor, [165u8; 48], [166u8; 48], 0),
        "candidate-one-a" => test_candidate_artifact_action(1, 171),
        "candidate-one-b" => test_candidate_artifact_action(1, 172),
        "candidate-two" => test_candidate_artifact_action(2, 173),
        "bridge-a" => test_outbound_bridge_action(b"lean mineable selection bridge-a"),
        other => panic!("unknown Lean mineable selection fixture {other}"),
    }
}

fn stage_ciphertext_metadata_for_action(state: &mut NativeState, action: &PendingAction) {
    for (hash, size) in action
        .ciphertext_hashes
        .iter()
        .zip(action.ciphertext_sizes.iter())
    {
        state.staged_ciphertexts.insert(hex48(hash), *size);
    }
}

#[test]
fn lean_generated_block_artifact_binding_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BLOCK_ARTIFACT_BINDING_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean block artifact binding admission vectors");
    let vectors: LeanBlockArtifactBindingAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean block artifact binding admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.tx_leaf_action_binding_cases.is_empty(),
        "Lean tx-leaf action binding cases must not be empty"
    );
    assert!(
        !vectors.candidate_artifact_binding_cases.is_empty(),
        "Lean candidate artifact binding cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.tx_leaf_action_binding_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_tx_leaf_action_binding_admission_case(case);
    }
    for case in &vectors.candidate_artifact_binding_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_candidate_artifact_binding_admission_case(case);
    }
}

fn verify_lean_tx_leaf_action_binding_admission_case(case: &LeanTxLeafActionBindingAdmissionCase) {
    let input = NativeTxLeafActionBindingAdmissionInput {
        nullifiers_match: case.nullifiers_match,
        commitments_match: case.commitments_match,
        ciphertext_hashes_match: case.ciphertext_hashes_match,
        input_count_matches: case.input_count_matches,
        output_count_matches: case.output_count_matches,
        version_matches: case.version_matches,
        fee_matches: case.fee_matches,
        stablecoin_payload_matches: case.stablecoin_payload_matches,
        balance_tag_matches: case.balance_tag_matches,
        receipt_statement_hash_matches: case.receipt_statement_hash_matches,
        public_inputs_digest_matches: case.public_inputs_digest_matches,
        proof_digest_matches: case.proof_digest_matches,
        proof_backend_matches: case.proof_backend_matches,
        ciphertext_payload_hashes_match: case.ciphertext_payload_hashes_match,
    };
    let actual_rejection = evaluate_native_tx_leaf_action_binding_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native tx-leaf action binding validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native tx-leaf action binding rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_candidate_artifact_binding_admission_case(
    case: &LeanCandidateArtifactBindingAdmissionCase,
) {
    let input = NativeCandidateArtifactBindingAdmissionInput {
        da_root_matches: case.da_root_matches,
        da_chunk_count_matches: case.da_chunk_count_matches,
        tx_statements_commitment_matches: case.tx_statements_commitment_matches,
        recursive_state_root_matches: case.recursive_state_root_matches,
    };
    let actual_rejection = evaluate_native_candidate_artifact_binding_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native candidate artifact binding validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native candidate artifact binding rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn block_artifact_binding_rejects_tx_leaf_action_mismatches_in_order() {
    let valid = NativeTxLeafActionBindingAdmissionInput {
        nullifiers_match: true,
        commitments_match: true,
        ciphertext_hashes_match: true,
        input_count_matches: true,
        output_count_matches: true,
        version_matches: true,
        fee_matches: true,
        stablecoin_payload_matches: true,
        balance_tag_matches: true,
        receipt_statement_hash_matches: true,
        public_inputs_digest_matches: true,
        proof_digest_matches: true,
        proof_backend_matches: true,
        ciphertext_payload_hashes_match: true,
    };
    assert!(evaluate_native_tx_leaf_action_binding_admission(valid).is_ok());
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            nullifiers_match: false,
            commitments_match: false,
            ..valid
        })
        .expect_err("nullifier mismatch must reject")
        .label(),
        "nullifiers_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            version_matches: false,
            fee_matches: false,
            ciphertext_payload_hashes_match: false,
            ..valid
        })
        .expect_err("version mismatch must reject before fee or payload hashes")
        .label(),
        "version_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            fee_matches: false,
            stablecoin_payload_matches: false,
            balance_tag_matches: false,
            ciphertext_payload_hashes_match: false,
            ..valid
        })
        .expect_err("fee mismatch must reject before stablecoin or payload hashes")
        .label(),
        "fee_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            stablecoin_payload_matches: false,
            balance_tag_matches: false,
            receipt_statement_hash_matches: false,
            ..valid
        })
        .expect_err("stablecoin mismatch must reject before balance tag or receipt fields")
        .label(),
        "stablecoin_payload_mismatch"
    );
}

#[test]
fn block_artifact_binding_rejects_extended_tx_leaf_mismatches_in_order() {
    let valid = NativeTxLeafActionBindingAdmissionInput {
        nullifiers_match: true,
        commitments_match: true,
        ciphertext_hashes_match: true,
        input_count_matches: true,
        output_count_matches: true,
        version_matches: true,
        fee_matches: true,
        stablecoin_payload_matches: true,
        balance_tag_matches: true,
        receipt_statement_hash_matches: true,
        public_inputs_digest_matches: true,
        proof_digest_matches: true,
        proof_backend_matches: true,
        ciphertext_payload_hashes_match: true,
    };
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            input_count_matches: false,
            output_count_matches: false,
            version_matches: false,
            ..valid
        })
        .expect_err("input count mismatch must reject before output count or version")
        .label(),
        "input_count_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            output_count_matches: false,
            version_matches: false,
            ..valid
        })
        .expect_err("output count mismatch must reject before version")
        .label(),
        "output_count_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            stablecoin_payload_matches: false,
            balance_tag_matches: false,
            receipt_statement_hash_matches: false,
            public_inputs_digest_matches: false,
            proof_digest_matches: false,
            proof_backend_matches: false,
            ciphertext_payload_hashes_match: false,
            ..valid
        })
        .expect_err("balance tag mismatch must reject before receipt and digest fields")
        .label(),
        "stablecoin_payload_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            balance_tag_matches: false,
            receipt_statement_hash_matches: false,
            public_inputs_digest_matches: false,
            proof_digest_matches: false,
            proof_backend_matches: false,
            ciphertext_payload_hashes_match: false,
            ..valid
        })
        .expect_err("balance tag mismatch must reject before receipt and digest fields")
        .label(),
        "balance_tag_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            receipt_statement_hash_matches: false,
            public_inputs_digest_matches: false,
            proof_digest_matches: false,
            proof_backend_matches: false,
            ..valid
        })
        .expect_err("statement hash mismatch must reject before digest fields")
        .label(),
        "receipt_statement_hash_mismatch"
    );
    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(NativeTxLeafActionBindingAdmissionInput {
            proof_digest_matches: false,
            proof_backend_matches: false,
            ciphertext_payload_hashes_match: false,
            ..valid
        })
        .expect_err("proof digest mismatch must reject before backend or payload")
        .label(),
        "proof_digest_mismatch"
    );
}

#[test]
fn block_artifact_binding_rejects_candidate_artifact_mismatches_in_order() {
    let valid = NativeCandidateArtifactBindingAdmissionInput {
        da_root_matches: true,
        da_chunk_count_matches: true,
        tx_statements_commitment_matches: true,
        recursive_state_root_matches: true,
    };
    assert!(evaluate_native_candidate_artifact_binding_admission(valid).is_ok());
    assert_eq!(
        evaluate_native_candidate_artifact_binding_admission(
            NativeCandidateArtifactBindingAdmissionInput {
                da_root_matches: false,
                da_chunk_count_matches: false,
                tx_statements_commitment_matches: false,
                ..valid
            }
        )
        .expect_err("DA root mismatch must reject first")
        .label(),
        "da_root_mismatch"
    );
    assert_eq!(
        evaluate_native_candidate_artifact_binding_admission(
            NativeCandidateArtifactBindingAdmissionInput {
                da_chunk_count_matches: false,
                tx_statements_commitment_matches: false,
                recursive_state_root_matches: false,
                ..valid
            }
        )
        .expect_err("DA chunk count mismatch must reject before statement or state root")
        .label(),
        "da_chunk_count_mismatch"
    );
    assert_eq!(
        evaluate_native_candidate_artifact_binding_admission(
            NativeCandidateArtifactBindingAdmissionInput {
                tx_statements_commitment_matches: false,
                recursive_state_root_matches: false,
                ..valid
            }
        )
        .expect_err("statement mismatch must reject before state root")
        .label(),
        "tx_statement_commitment_mismatch"
    );
}

#[test]
fn lean_generated_block_commitment_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BLOCK_COMMITMENT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean block commitment admission vectors");
    let vectors: LeanBlockCommitmentAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean block commitment vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.block_commitment_admission_cases.is_empty(),
        "Lean block commitment admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.block_commitment_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_block_commitment_admission_case(case);
    }
}

fn verify_lean_block_commitment_admission_case(case: &LeanBlockCommitmentAdmissionCase) {
    let input = NativeBlockCommitmentAdmissionInput {
        tx_count_matches: case.tx_count_matches,
        state_root_matches: case.state_root_matches,
        kernel_root_matches: case.kernel_root_matches,
        nullifier_root_matches: case.nullifier_root_matches,
        extrinsics_root_matches: case.extrinsics_root_matches,
        message_root_matches: case.message_root_matches,
        message_count_matches: case.message_count_matches,
        header_mmr_root_matches: case.header_mmr_root_matches,
        header_mmr_len_matches: case.header_mmr_len_matches,
        supply_digest_matches: case.supply_digest_matches,
    };
    let actual_rejection = evaluate_native_block_commitment_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native block commitment admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native block commitment admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_block_replay_refinement_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BLOCK_REPLAY_REFINEMENT_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean block replay refinement vectors");
    let vectors: LeanBlockReplayRefinementVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean block replay refinement vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.block_replay_refinement_cases.is_empty(),
        "Lean block replay refinement cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.block_replay_refinement_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_block_replay_refinement_case(case);
    }
}

fn verify_lean_block_replay_refinement_case(case: &LeanBlockReplayRefinementCase) {
    let spent_nullifiers = case
        .spent_nullifiers
        .iter()
        .map(|key| synthetic_stream_nullifier(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let consumed_replays = case
        .consumed_bridge_replays
        .iter()
        .map(|key| synthetic_stream_replay_key(*key, &case.name))
        .collect::<BTreeSet<_>>();
    let action_nullifiers = case
        .actions
        .iter()
        .map(|action| {
            action
                .nullifiers
                .iter()
                .map(|key| synthetic_stream_nullifier(*key, &case.name))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let replay_keys = case
        .actions
        .iter()
        .map(|action| {
            action
                .bridge_replay_key
                .map(|key| synthetic_stream_replay_key(key, &case.name))
        })
        .collect::<Vec<_>>();
    let mut nullifier_state = NullifierState::new(spent_nullifiers, BTreeSet::new());
    let mut bridge_replay_state = InboundReplayState::new(consumed_replays, BTreeSet::new());
    let input = NativeBlockReplayRefinementInput {
        leaf_start: case.leaf_start,
        parent_supply: parse_u128(&case.parent_supply),
        height: case.height,
        fee_total: case.fee_total,
        has_coinbase: case.has_coinbase,
        claimed_supply: parse_u128(&case.claimed_supply),
        tx_count_matches: case.tx_count_matches,
        state_root_matches: case.state_root_matches,
        kernel_root_matches: case.kernel_root_matches,
        nullifier_root_matches: case.nullifier_root_matches,
        extrinsics_root_matches: case.extrinsics_root_matches,
        message_root_matches: case.message_root_matches,
        message_count_matches: case.message_count_matches,
        header_mmr_root_matches: case.header_mmr_root_matches,
        header_mmr_len_matches: case.header_mmr_len_matches,
    };

    let (actual_trace, actual) = evaluate_native_block_replay_refinement_with_trace(
        input,
        case.actions
            .iter()
            .zip(action_nullifiers.iter())
            .zip(replay_keys.iter())
            .map(
                |((action, nullifiers), replay_key)| NativeActionStreamStep {
                    commitment_count: action.commitment_count,
                    ciphertext_count: action.ciphertext_count,
                    nullifiers: nullifiers.as_slice(),
                    replay_key: *replay_key,
                },
            ),
        &mut nullifier_state,
        &mut bridge_replay_state,
    );
    assert_eq!(
        actual_trace, case.expected_trace,
        "{} replay transition trace drifted from Lean spec",
        case.name
    );
    match actual {
        Ok(summary) => {
            assert!(
                case.expected_valid,
                "{} block replay refinement unexpectedly accepted",
                case.name
            );
            assert_eq!(
                Some(summary.next_leaf_count.to_string()),
                case.expected_next_leaf_count,
                "{} replay next leaf count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.imported_nullifier_count.to_string()),
                case.expected_imported_nullifier_count,
                "{} replay imported nullifier count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.imported_bridge_replay_count.to_string()),
                case.expected_imported_bridge_replay_count,
                "{} replay imported bridge count drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.planned_starts),
                case.expected_planned_starts,
                "{} replay planned starts drifted from Lean spec",
                case.name
            );
            assert_eq!(
                Some(summary.expected_supply.to_string()),
                case.expected_supply,
                "{} replay expected supply drifted from Lean spec",
                case.name
            );
        }
        Err(rejection) => {
            assert!(
                !case.expected_valid,
                "{} block replay refinement unexpectedly rejected: {}",
                case.name,
                rejection.label()
            );
            assert_eq!(
                Some(rejection.label().to_owned()),
                case.expected_rejection,
                "{} replay rejection drifted from Lean spec",
                case.name
            );
        }
    }
}

#[test]
fn lean_generated_coinbase_accounting_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_COINBASE_ACCOUNTING_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean coinbase accounting admission vectors");
    let vectors: LeanCoinbaseAccountingAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean coinbase accounting admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.coinbase_accounting_admission_cases.is_empty(),
        "Lean coinbase accounting admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.coinbase_accounting_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_coinbase_accounting_admission_case(case);
    }
}

fn verify_lean_coinbase_accounting_admission_case(case: &LeanCoinbaseAccountingAdmissionCase) {
    let input = NativeCoinbaseAccountingAdmissionInput {
        coinbase_count: case.coinbase_count,
        height: case.height,
        transfer_fee_total: case.transfer_fee_total.as_deref().map(parse_u64),
        observed_coinbase_amount: case.observed_coinbase_amount.as_deref().map(parse_u64),
    };
    assert_eq!(
        expected_coinbase_amount_from_input(input).map(|amount| amount.to_string()),
        case.expected_coinbase_amount,
        "{} expected coinbase amount drifted from Lean spec",
        case.name
    );
    let actual_rejection = evaluate_native_coinbase_accounting_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native coinbase accounting validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native coinbase accounting rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_coinbase_action_payload_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean coinbase action payload admission vectors");
    let vectors: LeanCoinbaseActionPayloadAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean coinbase action payload admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.coinbase_action_payload_admission_cases.is_empty(),
        "Lean coinbase action payload admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.coinbase_action_payload_admission_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_coinbase_action_payload_admission_case(case);
    }
}

fn verify_lean_coinbase_action_payload_admission_case(
    case: &LeanCoinbaseActionPayloadAdmissionCase,
) {
    assert_eq!(
        case.max_ciphertext_bytes, MAX_CIPHERTEXT_BYTES,
        "{} Lean ciphertext cap must match the production native cap",
        case.name
    );
    let input = NativeCoinbaseActionPayloadAdmissionInput {
        amount_nonzero: case.amount_nonzero,
        commitment_matches: case.commitment_matches,
        commitment_nonzero: case.commitment_nonzero,
        ciphertext_bytes: case.ciphertext_bytes,
        max_ciphertext_bytes: case.max_ciphertext_bytes,
        ciphertext_hash_matches: case.ciphertext_hash_matches,
        ciphertext_size_matches: case.ciphertext_size_matches,
    };
    let actual_rejection = evaluate_native_coinbase_action_payload_admission(input)
        .err()
        .map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native coinbase action payload admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native coinbase action payload admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_coinbase_action_payload_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_COINBASE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean coinbase action payload SCALE wire vectors");
    let vectors: LeanCoinbaseActionPayloadScaleWireVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean coinbase action payload SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.coinbase_action_payload_scale_wire_cases.is_empty(),
        "Lean coinbase action payload SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.coinbase_action_payload_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_coinbase_action_payload_scale_wire_case(case);
    }
}

fn expected_coinbase_action_payload_scale_wire_fixture(
    case: &LeanCoinbaseActionPayloadScaleWireCase,
) -> MintCoinbaseArgs {
    let (commitment, ciphertext, kem_ciphertext, recipient, amount, seed) =
        match case.fixture.as_str() {
            "valid_short_kem_payload" => (
                [1u8; 48],
                [2u8; ENCRYPTED_NOTE_SIZE],
                vec![0xaa, 0xbb, 0xcc],
                [3u8; DIVERSIFIED_ADDRESS_SIZE],
                4,
                [5u8; 32],
            ),
            "valid_zero_kem_payload" => (
                [6u8; 48],
                [7u8; ENCRYPTED_NOTE_SIZE],
                Vec::new(),
                [8u8; DIVERSIFIED_ADDRESS_SIZE],
                9,
                [10u8; 32],
            ),
            other => panic!("no valid MintCoinbaseArgs fixture for {other}"),
        };
    MintCoinbaseArgs {
        reward_bundle: BlockRewardBundle {
            miner_note: CoinbaseNoteData {
                commitment,
                encrypted_note: EncryptedNote {
                    ciphertext,
                    kem_ciphertext,
                },
                recipient_address: recipient,
                amount,
                public_seed: seed,
            },
        },
    }
}

fn expected_coinbase_action_payload_encoded_len(
    case: &LeanCoinbaseActionPayloadScaleWireCase,
) -> usize {
    case.commitment_bytes
        + case.note_ciphertext_bytes
        + case.kem_ciphertext_compact_prefix_bytes
        + case.kem_ciphertext_bytes
        + case.recipient_address_bytes
        + case.amount_bytes
        + case.public_seed_bytes
}

fn verify_lean_coinbase_action_payload_scale_wire_case(
    case: &LeanCoinbaseActionPayloadScaleWireCase,
) {
    let fixed_fields_ok = case.commitment_bytes == 48
        && case.note_ciphertext_bytes == ENCRYPTED_NOTE_SIZE
        && case.recipient_address_bytes == DIVERSIFIED_ADDRESS_SIZE
        && case.amount_bytes == 8
        && case.public_seed_bytes == 32;
    let expected_len = expected_coinbase_action_payload_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && case.kem_ciphertext_compact_prefix_canonical
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.canonical_reencode_matches;
    assert_eq!(
        lean_predicate_accepts, case.expected_valid,
        "{} Lean coinbase SCALE predicate fields disagree with expected validity",
        case.name
    );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_coinbase_action_payload_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production MintCoinbaseArgs::encode",
            case.name
        );
    }

    let actual =
        decode_scale_exact::<MintCoinbaseArgs>(&raw, "Lean coinbase action payload SCALE wire");
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} production MintCoinbaseArgs exact decode validity drifted from Lean wire spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} production MintCoinbaseArgs exact decode rejection drifted from Lean wire spec",
        case.name
    );

    if let Ok(args) = actual {
        let note = &args.reward_bundle.miner_note;
        assert_eq!(note.commitment.len(), case.commitment_bytes);
        assert_eq!(
            note.encrypted_note.ciphertext.len(),
            case.note_ciphertext_bytes
        );
        assert_eq!(
            note.encrypted_note.kem_ciphertext.len(),
            case.kem_ciphertext_bytes
        );
        assert_eq!(note.recipient_address.len(), case.recipient_address_bytes);
        assert_eq!(note.public_seed.len(), case.public_seed_bytes);
        assert_eq!(args.encode().len(), case.total_bytes);
    }
}

#[test]
fn lean_generated_outbound_bridge_action_payload_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_OUTBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_OUTBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean outbound bridge action payload SCALE wire vectors");
    let vectors: LeanOutboundBridgeActionPayloadScaleWireVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean outbound bridge action payload SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors
            .outbound_bridge_action_payload_scale_wire_cases
            .is_empty(),
        "Lean outbound bridge action payload SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.outbound_bridge_action_payload_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_outbound_bridge_action_payload_scale_wire_case(case);
    }
}

fn expected_outbound_bridge_action_payload_scale_wire_fixture(
    case: &LeanOutboundBridgeActionPayloadScaleWireCase,
) -> OutboundBridgeArgsV1 {
    let (destination_chain_id, app_family_id, payload) = match case.fixture.as_str() {
        "valid_short_payload" => ([1u8; 32], 7u16, vec![0xaa, 0xbb, 0xcc]),
        "valid_empty_payload" => ([2u8; 32], 9u16, Vec::new()),
        other => panic!("no valid OutboundBridgeArgsV1 fixture for {other}"),
    };
    OutboundBridgeArgsV1 {
        destination_chain_id,
        app_family_id,
        payload,
    }
}

fn expected_outbound_bridge_action_payload_encoded_len(
    case: &LeanOutboundBridgeActionPayloadScaleWireCase,
) -> usize {
    case.destination_chain_id_bytes
        + case.app_family_id_bytes
        + case.payload_compact_prefix_bytes
        + case.payload_bytes
}

fn verify_lean_outbound_bridge_action_payload_scale_wire_case(
    case: &LeanOutboundBridgeActionPayloadScaleWireCase,
) {
    let fixed_fields_ok = case.destination_chain_id_bytes == 32 && case.app_family_id_bytes == 2;
    let expected_len = expected_outbound_bridge_action_payload_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && case.payload_compact_prefix_canonical
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.canonical_reencode_matches;
    assert_eq!(
        lean_predicate_accepts, case.expected_valid,
        "{} Lean outbound bridge SCALE predicate fields disagree with expected validity",
        case.name
    );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_outbound_bridge_action_payload_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production OutboundBridgeArgsV1::encode",
            case.name
        );
    }

    let actual = decode_scale_exact::<OutboundBridgeArgsV1>(
        &raw,
        "Lean outbound bridge action payload SCALE wire",
    );
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} production OutboundBridgeArgsV1 exact decode validity drifted from Lean wire spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} production OutboundBridgeArgsV1 exact decode rejection drifted from Lean wire spec",
        case.name
    );

    if let Ok(args) = actual {
        assert_eq!(
            args.destination_chain_id.len(),
            case.destination_chain_id_bytes
        );
        assert_eq!(
            std::mem::size_of_val(&args.app_family_id),
            case.app_family_id_bytes
        );
        assert_eq!(args.payload.len(), case.payload_bytes);
        assert_eq!(args.encode().len(), case.total_bytes);
    }
}

#[test]
fn lean_generated_inbound_bridge_action_payload_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_INBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_INBOUND_BRIDGE_ACTION_PAYLOAD_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean inbound bridge action payload SCALE wire vectors");
    let vectors: LeanInboundBridgeActionPayloadScaleWireVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean inbound bridge action payload SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors
            .inbound_bridge_action_payload_scale_wire_cases
            .is_empty(),
        "Lean inbound bridge action payload SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.inbound_bridge_action_payload_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_inbound_bridge_action_payload_scale_wire_case(case);
    }
}

fn expected_inbound_bridge_action_payload_scale_wire_fixture(
    case: &LeanInboundBridgeActionPayloadScaleWireCase,
) -> InboundBridgeArgsV1 {
    match case.fixture.as_str() {
        "valid_short_receipt_payload" => InboundBridgeArgsV1 {
            source_chain_id: [1u8; 32],
            source_message_nonce: 42,
            verifier_program_hash: [3u8; 32],
            proof_receipt: vec![0xaa, 0xbb],
            message: BridgeMessageV1 {
                source_chain_id: [1u8; 32],
                destination_chain_id: [4u8; 32],
                app_family_id: 7,
                message_nonce: 42,
                source_height: 99,
                payload_hash: [5u8; 48],
                payload: vec![0xcc, 0xdd, 0xee],
            },
        },
        "valid_empty_receipt_payload" => InboundBridgeArgsV1 {
            source_chain_id: [2u8; 32],
            source_message_nonce: 0,
            verifier_program_hash: [6u8; 32],
            proof_receipt: Vec::new(),
            message: BridgeMessageV1 {
                source_chain_id: [2u8; 32],
                destination_chain_id: [8u8; 32],
                app_family_id: 9,
                message_nonce: 0,
                source_height: 0,
                payload_hash: [9u8; 48],
                payload: Vec::new(),
            },
        },
        other => panic!("no valid InboundBridgeArgsV1 fixture for {other}"),
    }
}

fn expected_inbound_bridge_action_payload_encoded_len(
    case: &LeanInboundBridgeActionPayloadScaleWireCase,
) -> usize {
    case.source_chain_id_bytes
        + case.source_message_nonce_bytes
        + case.verifier_program_hash_bytes
        + case.proof_receipt_compact_prefix_bytes
        + case.proof_receipt_bytes
        + case.message_source_chain_id_bytes
        + case.message_destination_chain_id_bytes
        + case.message_app_family_id_bytes
        + case.message_nonce_bytes
        + case.message_source_height_bytes
        + case.message_payload_hash_bytes
        + case.message_payload_compact_prefix_bytes
        + case.message_payload_bytes
}

fn verify_lean_inbound_bridge_action_payload_scale_wire_case(
    case: &LeanInboundBridgeActionPayloadScaleWireCase,
) {
    let fixed_fields_ok = case.source_chain_id_bytes == 32
        && case.source_message_nonce_bytes == 16
        && case.verifier_program_hash_bytes == 32
        && case.message_source_chain_id_bytes == 32
        && case.message_destination_chain_id_bytes == 32
        && case.message_app_family_id_bytes == 2
        && case.message_nonce_bytes == 16
        && case.message_source_height_bytes == 8
        && case.message_payload_hash_bytes == 48;
    let expected_len = expected_inbound_bridge_action_payload_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && case.proof_receipt_compact_prefix_canonical
        && case.message_payload_compact_prefix_canonical
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.canonical_reencode_matches;
    assert_eq!(
        lean_predicate_accepts, case.expected_valid,
        "{} Lean inbound bridge SCALE predicate fields disagree with expected validity",
        case.name
    );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_inbound_bridge_action_payload_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production InboundBridgeArgsV1::encode",
            case.name
        );
    }

    let actual = decode_scale_exact::<InboundBridgeArgsV1>(
        &raw,
        "Lean inbound bridge action payload SCALE wire",
    );
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} production InboundBridgeArgsV1 exact decode validity drifted from Lean wire spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} production InboundBridgeArgsV1 exact decode rejection drifted from Lean wire spec",
        case.name
    );

    if let Ok(args) = actual {
        assert_eq!(args.source_chain_id.len(), case.source_chain_id_bytes);
        assert_eq!(
            std::mem::size_of_val(&args.source_message_nonce),
            case.source_message_nonce_bytes
        );
        assert_eq!(
            args.verifier_program_hash.len(),
            case.verifier_program_hash_bytes
        );
        assert_eq!(args.proof_receipt.len(), case.proof_receipt_bytes);
        assert_eq!(
            args.message.source_chain_id.len(),
            case.message_source_chain_id_bytes
        );
        assert_eq!(
            args.message.destination_chain_id.len(),
            case.message_destination_chain_id_bytes
        );
        assert_eq!(
            std::mem::size_of_val(&args.message.app_family_id),
            case.message_app_family_id_bytes
        );
        assert_eq!(
            std::mem::size_of_val(&args.message.message_nonce),
            case.message_nonce_bytes
        );
        assert_eq!(
            std::mem::size_of_val(&args.message.source_height),
            case.message_source_height_bytes
        );
        assert_eq!(
            args.message.payload_hash.len(),
            case.message_payload_hash_bytes
        );
        assert_eq!(args.message.payload.len(), case.message_payload_bytes);
        assert_eq!(args.encode().len(), case.total_bytes);
    }
}

#[test]
fn lean_generated_bridge_verifier_registration_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BRIDGE_VERIFIER_REGISTRATION_SCALE_WIRE_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_BRIDGE_VERIFIER_REGISTRATION_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bridge verifier registration SCALE wire vectors");
    let vectors: LeanBridgeVerifierRegistrationScaleWireVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean bridge verifier registration SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors
            .bridge_verifier_registration_scale_wire_cases
            .is_empty(),
        "Lean bridge verifier registration SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bridge_verifier_registration_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bridge_verifier_registration_scale_wire_case(case);
    }
}

fn expected_bridge_verifier_registration_scale_wire_fixture(
    case: &LeanBridgeVerifierRegistrationScaleWireCase,
) -> BridgeVerifierRegistrationV1 {
    match case.fixture.as_str() {
        "valid_registration" => BridgeVerifierRegistrationV1 {
            source_chain_id: [1u8; 32],
            verifier_program_hash: [2u8; 32],
            rules_hash: [3u8; 32],
            enabled_at_height: 42,
        },
        other => panic!("no valid BridgeVerifierRegistrationV1 fixture for {other}"),
    }
}

fn expected_bridge_verifier_registration_encoded_len(
    case: &LeanBridgeVerifierRegistrationScaleWireCase,
) -> usize {
    case.source_chain_id_bytes
        + case.verifier_program_hash_bytes
        + case.rules_hash_bytes
        + case.enabled_at_height_bytes
}

fn verify_lean_bridge_verifier_registration_scale_wire_case(
    case: &LeanBridgeVerifierRegistrationScaleWireCase,
) {
    let fixed_fields_ok = case.source_chain_id_bytes == 32
        && case.verifier_program_hash_bytes == 32
        && case.rules_hash_bytes == 32
        && case.enabled_at_height_bytes == 8;
    let expected_len = expected_bridge_verifier_registration_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.canonical_reencode_matches;
    assert_eq!(
            lean_predicate_accepts, case.expected_valid,
            "{} Lean bridge verifier registration SCALE predicate fields disagree with expected validity",
            case.name
        );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_bridge_verifier_registration_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production BridgeVerifierRegistrationV1::encode",
            case.name
        );
    }

    let actual = decode_scale_exact::<BridgeVerifierRegistrationV1>(
        &raw,
        "Lean bridge verifier registration SCALE wire",
    );
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} production BridgeVerifierRegistrationV1 exact decode validity drifted from Lean wire spec",
            case.name
        );
    assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} production BridgeVerifierRegistrationV1 exact decode rejection drifted from Lean wire spec",
            case.name
        );

    if let Ok(args) = actual {
        assert_eq!(args.source_chain_id.len(), case.source_chain_id_bytes);
        assert_eq!(
            args.verifier_program_hash.len(),
            case.verifier_program_hash_bytes
        );
        assert_eq!(args.rules_hash.len(), case.rules_hash_bytes);
        assert_eq!(
            std::mem::size_of_val(&args.enabled_at_height),
            case.enabled_at_height_bytes
        );
        assert_eq!(args.encode().len(), case.total_bytes);
    }
}

#[test]
fn lean_generated_shielded_transfer_inline_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SHIELDED_TRANSFER_INLINE_SCALE_WIRE_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_SHIELDED_TRANSFER_INLINE_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean shielded transfer inline SCALE wire vectors");
    let vectors: LeanShieldedTransferInlineScaleWireVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean shielded transfer inline SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.shielded_transfer_inline_scale_wire_cases.is_empty(),
        "Lean shielded transfer inline SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.shielded_transfer_inline_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_shielded_transfer_inline_scale_wire_case(case);
    }
}

fn expected_shielded_transfer_inline_scale_wire_fixture(
    case: &LeanShieldedTransferInlineScaleWireCase,
) -> ShieldedTransferInlineArgs {
    match case.fixture.as_str() {
        "valid_one_output_inline" => ShieldedTransferInlineArgs {
            proof: vec![1, 2, 3],
            commitments: vec![[4u8; 48]],
            ciphertexts: vec![protocol_shielded_pool::types::EncryptedNote {
                ciphertext: [5u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
                kem_ciphertext: vec![6u8; 32],
            }],
            anchor: [7u8; 48],
            balance_slot_asset_ids: [0, 1, 2, 3],
            binding_hash: [8u8; 64],
            stablecoin: None,
            fee: 9,
        },
        "valid_empty_inline" => ShieldedTransferInlineArgs {
            proof: Vec::new(),
            commitments: Vec::new(),
            ciphertexts: Vec::new(),
            anchor: [1u8; 48],
            balance_slot_asset_ids: [0, 0, 0, 0],
            binding_hash: [2u8; 64],
            stablecoin: None,
            fee: 0,
        },
        "valid_stablecoin_inline" => ShieldedTransferInlineArgs {
            proof: vec![1, 2, 3],
            commitments: vec![[4u8; 48]],
            ciphertexts: vec![protocol_shielded_pool::types::EncryptedNote {
                ciphertext: [5u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
                kem_ciphertext: vec![6u8; 32],
            }],
            anchor: [7u8; 48],
            balance_slot_asset_ids: [0, 1, 2, 3],
            binding_hash: [8u8; 64],
            stablecoin: Some(StablecoinPolicyBinding {
                asset_id: 11,
                policy_hash: [12u8; 48],
                oracle_commitment: [13u8; 48],
                attestation_commitment: [14u8; 48],
                issuance_delta: 15,
                policy_version: 16,
            }),
            fee: 9,
        },
        other => panic!("no valid ShieldedTransferInlineArgs fixture for {other}"),
    }
}

fn expected_shielded_transfer_inline_encoded_len(
    case: &LeanShieldedTransferInlineScaleWireCase,
) -> usize {
    case.proof_compact_prefix_bytes
        + case.proof_bytes
        + case.commitment_compact_prefix_bytes
        + case.commitment_count * case.commitment_element_bytes
        + case.ciphertext_compact_prefix_bytes
        + case.ciphertext_count
            * (case.encrypted_note_ciphertext_bytes
                + case.kem_ciphertext_compact_prefix_bytes
                + case.kem_ciphertext_bytes)
        + case.anchor_bytes
        + case.balance_slot_bytes
        + case.binding_hash_bytes
        + case.stablecoin_option_tag_bytes
        + case.stablecoin_some_payload_bytes
        + case.fee_bytes
}

fn verify_lean_shielded_transfer_inline_scale_wire_case(
    case: &LeanShieldedTransferInlineScaleWireCase,
) {
    let fixed_fields_ok = case.commitment_element_bytes == 48
        && case.encrypted_note_ciphertext_bytes
            == protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE
        && case.anchor_bytes == 48
        && case.balance_slot_count == transaction_core::constants::BALANCE_SLOTS
        && case.balance_slot_bytes == transaction_core::constants::BALANCE_SLOTS * 8
        && case.binding_hash_bytes == 64
        && case.stablecoin_option_tag_bytes == 1
        && case.fee_bytes == 8;
    let compact_prefixes_ok = case.proof_compact_prefix_canonical
        && case.commitment_compact_prefix_canonical
        && case.ciphertext_compact_prefix_canonical
        && case.kem_ciphertext_compact_prefix_canonical;
    let expected_len = expected_shielded_transfer_inline_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && compact_prefixes_ok
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.canonical_reencode_matches;
    assert_eq!(
        lean_predicate_accepts, case.expected_valid,
        "{} Lean shielded transfer inline SCALE predicate fields disagree with expected validity",
        case.name
    );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_shielded_transfer_inline_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production ShieldedTransferInlineArgs::encode",
            case.name
        );
    }

    let actual = decode_scale_exact::<ShieldedTransferInlineArgs>(
        &raw,
        "Lean shielded transfer inline SCALE wire",
    );
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} production ShieldedTransferInlineArgs exact decode validity drifted from Lean wire spec",
            case.name
        );
    assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} production ShieldedTransferInlineArgs exact decode rejection drifted from Lean wire spec",
            case.name
        );

    if let Ok(args) = actual {
        assert_eq!(args.proof.len(), case.proof_bytes);
        assert_eq!(args.commitments.len(), case.commitment_count);
        assert_eq!(args.ciphertexts.len(), case.ciphertext_count);
        for commitment in &args.commitments {
            assert_eq!(commitment.len(), case.commitment_element_bytes);
        }
        for note in &args.ciphertexts {
            assert_eq!(note.ciphertext.len(), case.encrypted_note_ciphertext_bytes);
            assert_eq!(note.kem_ciphertext.len(), case.kem_ciphertext_bytes);
        }
        assert_eq!(args.anchor.len(), case.anchor_bytes);
        assert_eq!(args.balance_slot_asset_ids.len(), case.balance_slot_count);
        assert_eq!(case.balance_slot_bytes, case.balance_slot_count * 8);
        assert_eq!(args.binding_hash.len(), case.binding_hash_bytes);
        assert_eq!(
            args.stablecoin.is_some(),
            case.stablecoin_some_payload_bytes > 0
        );
        assert_eq!(std::mem::size_of_val(&args.fee), case.fee_bytes);
        assert_eq!(args.encode().len(), case.total_bytes);
    }
}

#[test]
fn lean_generated_shielded_transfer_sidecar_scale_wire_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SHIELDED_TRANSFER_SIDECAR_SCALE_WIRE_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_SHIELDED_TRANSFER_SIDECAR_SCALE_WIRE_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean shielded transfer sidecar SCALE wire vectors");
    let vectors: LeanShieldedTransferSidecarScaleWireVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean shielded transfer sidecar SCALE wire vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors
            .shielded_transfer_sidecar_scale_wire_cases
            .is_empty(),
        "Lean shielded transfer sidecar SCALE wire cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.shielded_transfer_sidecar_scale_wire_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_shielded_transfer_sidecar_scale_wire_case(case);
    }
}

fn expected_shielded_transfer_sidecar_scale_wire_fixture(
    case: &LeanShieldedTransferSidecarScaleWireCase,
) -> ShieldedTransferSidecarArgs {
    match case.fixture.as_str() {
        "valid_one_output_sidecar" => ShieldedTransferSidecarArgs {
            proof: vec![1, 2, 3],
            commitments: vec![[4u8; 48]],
            ciphertext_hashes: vec![[5u8; 48]],
            ciphertext_sizes: vec![6],
            anchor: [7u8; 48],
            balance_slot_asset_ids: [0, 1, 2, 3],
            binding_hash: [8u8; 64],
            stablecoin: None,
            fee: 9,
        },
        "valid_empty_sidecar" => ShieldedTransferSidecarArgs {
            proof: Vec::new(),
            commitments: Vec::new(),
            ciphertext_hashes: Vec::new(),
            ciphertext_sizes: Vec::new(),
            anchor: [1u8; 48],
            balance_slot_asset_ids: [0, 0, 0, 0],
            binding_hash: [2u8; 64],
            stablecoin: None,
            fee: 0,
        },
        "valid_stablecoin_sidecar" => ShieldedTransferSidecarArgs {
            proof: vec![1, 2, 3],
            commitments: vec![[4u8; 48]],
            ciphertext_hashes: vec![[5u8; 48]],
            ciphertext_sizes: vec![6],
            anchor: [7u8; 48],
            balance_slot_asset_ids: [0, 1, 2, 3],
            binding_hash: [8u8; 64],
            stablecoin: Some(StablecoinPolicyBinding {
                asset_id: 11,
                policy_hash: [12u8; 48],
                oracle_commitment: [13u8; 48],
                attestation_commitment: [14u8; 48],
                issuance_delta: 15,
                policy_version: 16,
            }),
            fee: 9,
        },
        other => panic!("no valid ShieldedTransferSidecarArgs fixture for {other}"),
    }
}

fn expected_shielded_transfer_sidecar_encoded_len(
    case: &LeanShieldedTransferSidecarScaleWireCase,
) -> usize {
    case.proof_compact_prefix_bytes
        + case.proof_bytes
        + case.commitment_compact_prefix_bytes
        + case.commitment_count * case.commitment_element_bytes
        + case.ciphertext_hash_compact_prefix_bytes
        + case.ciphertext_hash_count * case.ciphertext_hash_element_bytes
        + case.ciphertext_size_compact_prefix_bytes
        + case.ciphertext_size_count * case.ciphertext_size_element_bytes
        + case.anchor_bytes
        + case.balance_slot_bytes
        + case.binding_hash_bytes
        + case.stablecoin_option_tag_bytes
        + case.stablecoin_some_payload_bytes
        + case.fee_bytes
}

fn verify_lean_shielded_transfer_sidecar_scale_wire_case(
    case: &LeanShieldedTransferSidecarScaleWireCase,
) {
    let fixed_fields_ok = case.commitment_element_bytes == 48
        && case.ciphertext_hash_element_bytes == 48
        && case.ciphertext_size_element_bytes == 4
        && case.anchor_bytes == 48
        && case.balance_slot_count == transaction_core::constants::BALANCE_SLOTS
        && case.balance_slot_bytes == transaction_core::constants::BALANCE_SLOTS * 8
        && case.binding_hash_bytes == 64
        && case.stablecoin_option_tag_bytes == 1
        && case.fee_bytes == 8;
    let compact_prefixes_ok = case.proof_compact_prefix_canonical
        && case.commitment_compact_prefix_canonical
        && case.ciphertext_hash_compact_prefix_canonical
        && case.ciphertext_size_compact_prefix_canonical;
    let expected_len = expected_shielded_transfer_sidecar_encoded_len(case);
    let lean_predicate_accepts = fixed_fields_ok
        && compact_prefixes_ok
        && case.total_bytes == expected_len
        && case.consumed_all_bytes
        && case.canonical_reencode_matches;
    assert_eq!(
        lean_predicate_accepts, case.expected_valid,
        "{} Lean shielded transfer sidecar SCALE predicate fields disagree with expected validity",
        case.name
    );

    let raw = decode_lean_hex(&case.raw_hex);
    if case.expected_valid {
        let expected = expected_shielded_transfer_sidecar_scale_wire_fixture(case);
        assert_eq!(
            expected.encode(),
            raw,
            "{} Lean raw bytes drifted from production ShieldedTransferSidecarArgs::encode",
            case.name
        );
    }

    let actual = decode_scale_exact::<ShieldedTransferSidecarArgs>(
        &raw,
        "Lean shielded transfer sidecar SCALE wire",
    );
    let actual_rejection = actual.as_ref().err().map(|err| {
        let message = err.to_string();
        if message.contains("trailing bytes") {
            "trailing_bytes".to_owned()
        } else if message.contains("not canonical") {
            "non_canonical_encoding".to_owned()
        } else {
            "parser_rejected".to_owned()
        }
    });
    assert_eq!(
            actual.is_ok(),
            case.expected_valid,
            "{} production ShieldedTransferSidecarArgs exact decode validity drifted from Lean wire spec",
            case.name
        );
    assert_eq!(
            actual_rejection, case.expected_rejection,
            "{} production ShieldedTransferSidecarArgs exact decode rejection drifted from Lean wire spec",
            case.name
        );

    if let Ok(args) = actual {
        assert_eq!(args.proof.len(), case.proof_bytes);
        assert_eq!(args.commitments.len(), case.commitment_count);
        assert_eq!(args.ciphertext_hashes.len(), case.ciphertext_hash_count);
        assert_eq!(args.ciphertext_sizes.len(), case.ciphertext_size_count);
        for commitment in &args.commitments {
            assert_eq!(commitment.len(), case.commitment_element_bytes);
        }
        for ciphertext_hash in &args.ciphertext_hashes {
            assert_eq!(ciphertext_hash.len(), case.ciphertext_hash_element_bytes);
        }
        for ciphertext_size in &args.ciphertext_sizes {
            assert_eq!(
                std::mem::size_of_val(ciphertext_size),
                case.ciphertext_size_element_bytes
            );
        }
        assert_eq!(args.anchor.len(), case.anchor_bytes);
        assert_eq!(args.balance_slot_asset_ids.len(), case.balance_slot_count);
        assert_eq!(case.balance_slot_bytes, case.balance_slot_count * 8);
        assert_eq!(args.binding_hash.len(), case.binding_hash_bytes);
        assert_eq!(
            args.stablecoin.is_some(),
            case.stablecoin_some_payload_bytes > 0
        );
        assert_eq!(std::mem::size_of_val(&args.fee), case.fee_bytes);
        assert_eq!(args.encode().len(), case.total_bytes);
    }
}

#[test]
fn lean_generated_resource_budget_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_RESOURCE_BUDGET_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean resource budget admission vectors");
    let vectors: LeanResourceBudgetAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean resource budget admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.mempool_budget_cases.is_empty(),
        "Lean mempool budget admission cases must not be empty"
    );
    assert!(
        !vectors.staged_proof_budget_cases.is_empty(),
        "Lean staged proof budget admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.mempool_budget_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_mempool_budget_case(case);
    }
    for case in &vectors.staged_proof_budget_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_staged_proof_budget_case(case);
    }
}

#[test]
fn lean_generated_bounded_request_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_BOUNDED_REQUEST_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean bounded request admission vectors");
    let vectors: LeanBoundedRequestAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean bounded request admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.bounded_request_cases.is_empty(),
        "Lean bounded-request admission cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.bounded_request_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_bounded_request_case(case);
    }
}

fn verify_lean_bounded_request_case(case: &LeanBoundedRequestCase) {
    let input = NativeBoundedRequestAdmissionInput {
        raw_byte_cap: case.raw_byte_cap,
        decoded_byte_cap: case.decoded_byte_cap,
        item_count_cap: case.item_count_cap,
        item_byte_cap: case.item_byte_cap,
        aggregate_byte_cap: case.aggregate_byte_cap,
        work_unit_cap: case.work_unit_cap,
        raw_bytes: case.raw_bytes,
        decoded_bytes: case.decoded_bytes,
        item_count: case.item_count,
        max_item_bytes: case.max_item_bytes,
        aggregate_bytes: case.aggregate_bytes,
        work_units: case.work_units,
    };
    let actual = evaluate_native_bounded_request_admission(input);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native bounded-request admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native bounded-request admission rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_mempool_budget_case(case: &LeanMempoolBudgetCase) {
    let input = NativeMempoolByteBudgetAdmissionInput {
        pending_bytes: case.pending_bytes,
        candidate_bytes: case.candidate_bytes,
        max_bytes: case.max_bytes,
    };
    let total = case.pending_bytes.saturating_add(case.candidate_bytes);
    assert_eq!(
        total, case.expected_total_bytes,
        "{} native mempool saturated total drifted from Lean spec",
        case.name
    );
    let actual = evaluate_native_mempool_byte_budget_admission(input);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native mempool budget admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native mempool budget admission rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_staged_proof_budget_case(case: &LeanStagedProofBudgetCase) {
    let input = NativeStagedProofByteBudgetAdmissionInput {
        staged_bytes: case.staged_bytes,
        existing_bytes: case.existing_bytes,
        proof_bytes: case.proof_bytes,
        max_bytes: case.max_bytes,
    };
    let total = case
        .staged_bytes
        .saturating_sub(case.existing_bytes)
        .saturating_add(case.proof_bytes);
    assert_eq!(
        total, case.expected_total_bytes,
        "{} native staged-proof saturated total drifted from Lean spec",
        case.name
    );
    let actual = evaluate_native_staged_proof_byte_budget_admission(input);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native staged-proof budget admission validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native staged-proof budget admission rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_preheavy_resource_bound_surface_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_PREHEAVY_RESOURCE_BOUND_SURFACE_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_PREHEAVY_RESOURCE_BOUND_SURFACE_VECTORS not set; skipping generated Lean pre-heavy resource-bound surface vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean pre-heavy resource-bound surface vectors");
    let vectors: LeanPreHeavyResourceBoundSurfaceVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean pre-heavy resource-bound surface vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.staged_proof_upload_preheavy_cases.is_empty(),
        "Lean staged-proof pre-heavy cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.staged_proof_upload_preheavy_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_staged_proof_upload_preheavy_case(case);
    }
}

fn verify_lean_staged_proof_upload_preheavy_case(case: &LeanStagedProofUploadPreHeavyCase) {
    let metadata_input = NativeProofSidecarMetadataAdmissionInput {
        binding_hash_present: case.binding_hash_present,
        binding_hash_valid: case.binding_hash_valid,
        proof_present: case.proof_present,
    };
    let budget_input = NativeStagedProofByteBudgetAdmissionInput {
        staged_bytes: case.staged_bytes,
        existing_bytes: case.existing_bytes,
        proof_bytes: case.proof_bytes,
        max_bytes: case.max_bytes,
    };
    let total = case
        .staged_bytes
        .saturating_sub(case.existing_bytes)
        .saturating_add(case.proof_bytes);
    assert_eq!(
        total, case.expected_total_bytes,
        "{} native staged-proof pre-heavy total drifted from Lean spec",
        case.name
    );
    let decoded_input = NativeProofSidecarDecodedAdmissionInput {
        proof_bytes: case.decoded_proof_bytes,
        max_proof_bytes: case.decoded_max_proof_bytes,
        proof_binding_hash_matches_key: case.proof_binding_hash_matches_key,
    };

    let (actual_stage, actual_rejection) =
        match evaluate_native_proof_sidecar_metadata_admission(metadata_input) {
            Err(rejection) => (
                Some("metadata".to_owned()),
                Some(rejection.label().to_owned()),
            ),
            Ok(()) => match evaluate_native_staged_proof_byte_budget_admission(budget_input) {
                Err(rejection) => (
                    Some("staged_proof_budget".to_owned()),
                    Some(rejection.label().to_owned()),
                ),
                Ok(_) => match evaluate_native_proof_sidecar_decoded_admission(decoded_input) {
                    Err(rejection) => (
                        Some("decoded".to_owned()),
                        Some(rejection.label().to_owned()),
                    ),
                    Ok(()) => (None, None),
                },
            },
        };
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native staged-proof pre-heavy validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_stage, case.expected_rejection_stage,
        "{} native staged-proof pre-heavy rejection stage drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native staged-proof pre-heavy rejection label drifted from Lean spec",
        case.name
    );
}

#[tokio::test]
async fn lean_generated_rpc_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_RPC_ADMISSION_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_RPC_ADMISSION_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read generated Lean RPC admission vectors");
    let vectors: LeanRpcAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean RPC admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.policy_cases.is_empty(),
        "Lean RPC policy cases must not be empty"
    );
    assert!(
        !vectors.method_gate_cases.is_empty(),
        "Lean RPC method-gate cases must not be empty"
    );
    assert!(
        !vectors.method_list_cases.is_empty(),
        "Lean RPC method-list cases must not be empty"
    );
    assert!(
        !vectors.timestamp_range_cases.is_empty(),
        "Lean RPC timestamp range cases must not be empty"
    );
    assert!(
        !vectors.byte_parse_cases.is_empty(),
        "Lean RPC byte-parse cases must not be empty"
    );
    assert!(
        !vectors.batch_cases.is_empty(),
        "Lean RPC batch cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.policy_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_rpc_policy_case(case);
    }
    for case in &vectors.method_gate_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_rpc_method_gate_case(case);
    }
    for case in &vectors.method_list_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_rpc_method_list_case(case);
    }
    for case in &vectors.timestamp_range_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_rpc_timestamp_range_case(case);
    }
    for case in &vectors.byte_parse_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_rpc_byte_parse_case(case);
    }
    for case in &vectors.batch_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_rpc_batch_case(case).await;
    }
}

fn verify_lean_rpc_policy_case(case: &LeanRpcPolicyCase) {
    assert!(
        matches!(
            case.raw_tag.as_str(),
            "safe" | "unsafe" | "auto" | "empty" | "invalid"
        ),
        "{} unknown Lean RPC raw policy tag {}",
        case.name,
        case.raw_tag
    );
    let actual = rpc_method_policy(&case.raw, case.rpc_external);
    let actual_policy = actual.as_ref().ok().map(|policy| policy.label().to_owned());
    let actual_rejection = actual.as_ref().err().map(|err| {
        if err
            .to_string()
            .contains("cannot be combined with --rpc-external")
        {
            "external_unsafe_policy".to_string()
        } else {
            "invalid_policy".to_string()
        }
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} RPC policy validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_policy, case.expected_policy,
        "{} RPC policy resolution drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} RPC policy rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_rpc_method_gate_case(case: &LeanRpcMethodGateCase) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, &case.policy, false)).expect("node");
    let params = rpc_test_params_for_method(&case.method);
    let actual = dispatch_rpc_method(&node, &case.method, params);
    let actual_rejection = actual
        .as_ref()
        .err()
        .and_then(|err| rpc_method_gate_rejection_label(&err.to_string()));
    assert_eq!(
        is_unsafe_rpc_method(&case.method),
        case.is_unsafe_method,
        "{} RPC unsafe-method classification drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} RPC method gate validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} RPC method gate rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_rpc_method_list_case(case: &LeanRpcMethodListCase) {
    let policy = rpc_policy_from_label(&case.policy);
    let methods = native_rpc_methods(policy);
    let unsafe_methods = [
        "da_submitCiphertexts",
        "da_submitProofs",
        "hegemon_exportBridgeWitness",
        "hegemon_peerGraph",
        "hegemon_peerList",
        "hegemon_startMining",
        "hegemon_stopMining",
        "hegemon_submitAction",
        "system_peers",
    ];
    for method in unsafe_methods {
        assert_eq!(
            methods.contains(&method),
            case.expected_unsafe_methods_visible,
            "{} RPC method-list unsafe visibility drifted for {method}",
            case.name
        );
    }
    assert!(
        methods.contains(&"system_health"),
        "{} RPC method-list must keep safe health method visible",
        case.name
    );
}

fn verify_lean_rpc_timestamp_range_case(case: &LeanRpcTimestampRangeCase) {
    assert_eq!(
        case.max_rows, MAX_NATIVE_TIMESTAMP_ROWS,
        "{} Lean timestamp cap must match production native RPC cap",
        case.name
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let actual = block_timestamps(&node, json!([case.start_height, case.end_height]), false);
    let actual_rejection = actual
        .as_ref()
        .err()
        .and_then(|err| rpc_timestamp_rejection_label(&err.to_string()));
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} RPC timestamp range validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} RPC timestamp range rejection drifted from Lean spec",
        case.name
    );
    if let Ok(value) = actual {
        let rows = value
            .as_array()
            .expect("timestamp response should be an array")
            .len()
            .to_string();
        assert_eq!(
            Some(rows),
            case.expected_requested_rows,
            "{} RPC timestamp requested-row count drifted from Lean spec",
            case.name
        );
    }
}

fn verify_lean_rpc_byte_parse_case(case: &LeanRpcByteParseCase) {
    assert_eq!(
        encoded_len_limit(case.max_decoded_bytes),
        case.expected_encoded_len_limit,
        "{} RPC base64 encoded length limit drifted from Lean spec",
        case.name
    );
    assert_eq!(
        case.max_decoded_bytes.saturating_mul(2),
        case.expected_hex_len_limit,
        "{} RPC hex length limit drifted from Lean spec",
        case.name
    );
    let value = rpc_byte_parse_value(case);
    if case.encoding == "base64" {
        assert_eq!(
            value.as_str().expect("base64 test value").len(),
            case.raw_text_bytes,
            "{} RPC base64 raw text length fixture drifted from Lean spec",
            case.name
        );
    } else if case.encoding == "hex" {
        assert_eq!(
            value
                .as_str()
                .expect("hex test value")
                .strip_prefix("0x")
                .expect("hex prefix")
                .len(),
            case.raw_text_bytes,
            "{} RPC hex raw text length fixture drifted from Lean spec",
            case.name
        );
    } else {
        panic!("{} unknown byte encoding {}", case.name, case.encoding);
    }
    let actual = parse_bytes_value(&value, case.max_decoded_bytes, "Lean RPC byte case");
    let actual_rejection = actual
        .as_ref()
        .err()
        .and_then(|err| rpc_byte_parse_rejection_label(&err.to_string()));
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} RPC byte parser validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} RPC byte parser rejection drifted from Lean spec",
        case.name
    );
    if let Ok(bytes) = actual {
        assert_eq!(
            bytes.len(),
            case.decoded_bytes,
            "{} RPC byte parser decoded length drifted from Lean spec",
            case.name
        );
    }
}

async fn verify_lean_rpc_batch_case(case: &LeanRpcBatchCase) {
    assert_eq!(
        case.max_requests, MAX_NATIVE_RPC_BATCH_REQUESTS,
        "{} Lean batch cap must match production native RPC cap",
        case.name
    );
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let payload = Value::Array(
        (0..case.request_count)
            .map(|idx| {
                json!({
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "system_health",
                    "params": [],
                })
            })
            .collect(),
    );
    let response = rpc_handler(State(node), Json(payload)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("RPC response body");
    let decoded: Value = serde_json::from_slice(&body).expect("RPC JSON body");
    let actual_rejection = decoded
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .and_then(rpc_batch_rejection_label);
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} RPC batch validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} RPC batch rejection drifted from Lean spec",
        case.name
    );
    if case.expected_valid {
        assert_eq!(
            decoded.as_array().expect("batch response array").len(),
            case.request_count,
            "{} RPC batch response count drifted from Lean spec",
            case.name
        );
    }
}

fn rpc_policy_from_label(label: &str) -> RpcMethodPolicy {
    match label {
        "safe" => RpcMethodPolicy::Safe,
        "unsafe" => RpcMethodPolicy::Unsafe,
        other => panic!("unknown RPC method policy label {other}"),
    }
}

fn rpc_test_params_for_method(method: &str) -> Value {
    match method {
        "da_submitCiphertexts" => json!({ "ciphertexts": [] }),
        "da_submitProofs" => json!({ "proofs": [] }),
        "hegemon_startMining" => json!({ "threads": 1 }),
        "hegemon_stopMining" => Value::Array(Vec::new()),
        "hegemon_submitAction" => json!({}),
        "hegemon_exportBridgeWitness" => json!({ "start_height": 0, "end_height": 0 }),
        _ => Value::Array(Vec::new()),
    }
}

fn rpc_method_gate_rejection_label(message: &str) -> Option<String> {
    if message.contains("unsafe RPC method") {
        Some("unsafe_method_disabled".to_string())
    } else {
        None
    }
}

fn rpc_timestamp_rejection_label(message: &str) -> Option<String> {
    if message.contains("before start") {
        Some("end_before_start".to_string())
    } else if message.contains("timestamp range overflow") {
        Some("range_overflow".to_string())
    } else if message.contains("timestamp range too large") {
        Some("range_too_large".to_string())
    } else {
        None
    }
}

fn rpc_byte_parse_rejection_label(message: &str) -> Option<String> {
    if message.contains("hex length") {
        Some("hex_text_too_long".to_string())
    } else if message.contains("base64 length") {
        Some("base64_text_too_long".to_string())
    } else if message.contains("decoded length") {
        Some("decoded_too_long".to_string())
    } else {
        None
    }
}

fn rpc_batch_rejection_label(message: &str) -> Option<String> {
    if message.contains("empty JSON-RPC batch") {
        Some("empty_batch".to_string())
    } else if message.contains("batch too large") {
        Some("batch_too_large".to_string())
    } else {
        None
    }
}

fn rpc_byte_parse_value(case: &LeanRpcByteParseCase) -> Value {
    match case.encoding.as_str() {
        "base64" => {
            if case.expected_rejection.as_deref() == Some("base64_text_too_long") {
                json!("A".repeat(case.raw_text_bytes))
            } else {
                use base64::Engine;
                json!(
                    base64::engine::general_purpose::STANDARD.encode(vec![0u8; case.decoded_bytes])
                )
            }
        }
        "hex" => json!(format!("0x{}", "00".repeat(case.decoded_bytes))),
        other => panic!("{} unknown byte encoding {other}", case.name),
    }
}

#[test]
fn lean_generated_sidecar_upload_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_SIDECAR_UPLOAD_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean sidecar upload admission vectors");
    let vectors: LeanSidecarUploadAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean sidecar upload admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.request_count_cases.is_empty(),
        "Lean sidecar request-count cases must not be empty"
    );
    assert!(
        !vectors.capacity_cases.is_empty(),
        "Lean sidecar capacity cases must not be empty"
    );
    assert!(
        !vectors.proof_metadata_cases.is_empty(),
        "Lean proof sidecar metadata cases must not be empty"
    );
    assert!(
        !vectors.proof_decoded_cases.is_empty(),
        "Lean proof sidecar decoded cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.request_count_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sidecar_request_count_case(case);
    }
    for case in &vectors.capacity_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sidecar_capacity_case(case);
    }
    for case in &vectors.proof_metadata_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_proof_sidecar_metadata_case(case);
    }
    for case in &vectors.proof_decoded_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_proof_sidecar_decoded_case(case);
    }
}

fn verify_lean_sidecar_request_count_case(case: &LeanSidecarRequestCountCase) {
    let input = NativeSidecarRequestCountAdmissionInput {
        item_count: case.item_count,
        max_items: case.max_items,
    };
    let actual = match case.kind.as_str() {
        "ciphertexts" => evaluate_native_ciphertext_sidecar_request_admission(input),
        "proofs" => evaluate_native_proof_sidecar_request_admission(input),
        other => panic!("{} unknown request-count kind {other}", case.name),
    };
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native sidecar request-count validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native sidecar request-count rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_sidecar_capacity_case(case: &LeanSidecarCapacityCase) {
    let input = NativeSidecarCapacityAdmissionInput {
        staged_count: case.staged_count,
        max_staged_count: case.max_staged_count,
        replaces_existing: case.replaces_existing,
    };
    let actual = match case.kind.as_str() {
        "ciphertext" => evaluate_native_ciphertext_sidecar_capacity_admission(input),
        "proof" => evaluate_native_proof_sidecar_capacity_admission(input),
        other => panic!("{} unknown capacity kind {other}", case.name),
    };
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native sidecar capacity validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native sidecar capacity rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_proof_sidecar_metadata_case(case: &LeanProofSidecarMetadataCase) {
    let input = NativeProofSidecarMetadataAdmissionInput {
        binding_hash_present: case.binding_hash_present,
        binding_hash_valid: case.binding_hash_valid,
        proof_present: case.proof_present,
    };
    let actual = evaluate_native_proof_sidecar_metadata_admission(input);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native proof sidecar metadata validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native proof sidecar metadata rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_proof_sidecar_decoded_case(case: &LeanProofSidecarDecodedCase) {
    assert_eq!(
        case.max_proof_bytes, NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        "{} Lean proof sidecar cap must match the production native tx-leaf cap",
        case.name
    );
    let input = NativeProofSidecarDecodedAdmissionInput {
        proof_bytes: case.proof_bytes,
        max_proof_bytes: case.max_proof_bytes,
        proof_binding_hash_matches_key: case.proof_binding_hash_matches_key,
    };
    let actual = evaluate_native_proof_sidecar_decoded_admission(input);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native proof sidecar decoded validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native proof sidecar decoded rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn lean_generated_sidecar_upload_raw_json_projection_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_SIDECAR_UPLOAD_RAW_JSON_PROJECTION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean sidecar upload raw JSON projection vectors");
    let vectors: LeanSidecarUploadRawJsonProjectionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean sidecar upload raw JSON projection vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.sidecar_upload_raw_json_projection_cases.is_empty(),
        "Lean sidecar raw JSON projection cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.sidecar_upload_raw_json_projection_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sidecar_upload_raw_json_projection_case(case);
    }
}

fn verify_lean_sidecar_upload_raw_json_projection_case(
    case: &LeanSidecarUploadRawJsonProjectionCase,
) {
    let actual_rejection = match serde_json::from_slice::<Value>(&case.raw_json_bytes) {
        Ok(value) => match case.kind.as_str() {
            "ciphertexts" => verify_lean_ciphertext_upload_raw_json_projection(case, value),
            "proofs" => verify_lean_proof_upload_raw_json_projection(case, value),
            other => panic!("{} unknown raw sidecar upload kind {other}", case.name),
        },
        Err(_) => {
            assert!(
                !case.json_decode_accepts,
                "{} Lean expected JSON decode acceptance, but serde_json rejected bytes",
                case.name
            );
            Some("json_decode_rejected".to_owned())
        }
    };
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} raw sidecar upload validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} raw sidecar upload rejection drifted from Lean spec",
        case.name
    );
}

fn verify_lean_ciphertext_upload_raw_json_projection(
    case: &LeanSidecarUploadRawJsonProjectionCase,
    value: Value,
) -> Option<String> {
    let request = match decode_submit_ciphertexts_rpc_request(value) {
        Ok(request) => {
            assert!(
                    case.json_decode_accepts,
                    "{} Lean expected JSON decode rejection, but production accepted ciphertext upload request shape",
                    case.name
                );
            request
        }
        Err(_) => {
            assert!(
                    !case.json_decode_accepts,
                    "{} Lean expected JSON decode acceptance, but production rejected ciphertext upload request shape",
                    case.name
                );
            return Some("json_decode_rejected".to_owned());
        }
    };
    let Some(ciphertexts) = request.ciphertexts.as_ref() else {
        assert!(
            !case.upload_field_present,
            "{} Lean expected ciphertext upload field, but production decoded it as missing",
            case.name
        );
        return Some("upload_field_missing".to_owned());
    };
    assert!(case.upload_field_present);
    assert_eq!(case.item_count, ciphertexts.len(), "{}", case.name);
    assert_eq!(
        case.max_items, MAX_NATIVE_DA_CIPHERTEXT_UPLOADS,
        "{} Lean ciphertext upload cap drifted from production",
        case.name
    );
    let request_admission = evaluate_native_ciphertext_sidecar_request_admission(
        NativeSidecarRequestCountAdmissionInput {
            item_count: ciphertexts.len(),
            max_items: MAX_NATIVE_DA_CIPHERTEXT_UPLOADS,
        },
    );
    if let Err(rejection) = request_admission {
        return Some(rejection.label().to_owned());
    }
    let Some(first) = ciphertexts.first() else {
        assert!(
            !case.ciphertext_item_present,
            "{} Lean expected a ciphertext item, but production decoded none",
            case.name
        );
        return None;
    };
    assert!(case.ciphertext_item_present);
    let decoded = parse_bytes_value(first, MAX_CIPHERTEXT_BYTES, "Lean ciphertext upload item");
    assert_eq!(
        decoded.is_ok(),
        case.ciphertext_bytes_decode,
        "{} ciphertext byte decoding drifted from Lean projection",
        case.name
    );
    if decoded.is_err() {
        return Some("ciphertext_bytes_rejected".to_owned());
    }
    None
}

fn verify_lean_proof_upload_raw_json_projection(
    case: &LeanSidecarUploadRawJsonProjectionCase,
    value: Value,
) -> Option<String> {
    let request = match decode_submit_proofs_rpc_request(value) {
        Ok(request) => {
            assert!(
                    case.json_decode_accepts,
                    "{} Lean expected JSON decode rejection, but production accepted proof upload request shape",
                    case.name
                );
            request
        }
        Err(_) => {
            assert!(
                    !case.json_decode_accepts,
                    "{} Lean expected JSON decode acceptance, but production rejected proof upload request shape",
                    case.name
                );
            return Some("json_decode_rejected".to_owned());
        }
    };
    let Some(proofs) = request.proofs.as_ref() else {
        assert!(
            !case.upload_field_present,
            "{} Lean expected proof upload field, but production decoded it as missing",
            case.name
        );
        return Some("upload_field_missing".to_owned());
    };
    assert!(case.upload_field_present);
    assert_eq!(case.item_count, proofs.len(), "{}", case.name);
    assert_eq!(
        case.max_items, MAX_NATIVE_DA_PROOF_UPLOADS,
        "{} Lean proof upload cap drifted from production",
        case.name
    );
    let request_admission =
        evaluate_native_proof_sidecar_request_admission(NativeSidecarRequestCountAdmissionInput {
            item_count: proofs.len(),
            max_items: MAX_NATIVE_DA_PROOF_UPLOADS,
        });
    if let Err(rejection) = request_admission {
        return Some(rejection.label().to_owned());
    }
    let Some(first) = proofs.first() else {
        assert!(
            !case.proof_item_present,
            "{} Lean expected a proof item, but production decoded none",
            case.name
        );
        return None;
    };
    assert!(case.proof_item_present);
    let binding_hash_value = first.binding_hash.as_deref();
    let binding_hash_bytes = binding_hash_value.and_then(parse_hex64);
    assert_eq!(
        binding_hash_value.is_some(),
        case.binding_hash_present,
        "{} proof binding-hash presence drifted from Lean projection",
        case.name
    );
    assert_eq!(
        binding_hash_bytes.is_some(),
        case.binding_hash_valid,
        "{} proof binding-hash hex validity drifted from Lean projection",
        case.name
    );
    assert_eq!(
        first.proof.is_some(),
        case.proof_present,
        "{} proof byte field presence drifted from Lean projection",
        case.name
    );
    let metadata_admission = evaluate_native_proof_sidecar_metadata_admission(
        NativeProofSidecarMetadataAdmissionInput {
            binding_hash_present: binding_hash_value.is_some(),
            binding_hash_valid: binding_hash_bytes.is_some(),
            proof_present: first.proof.is_some(),
        },
    );
    if let Err(rejection) = metadata_admission {
        return Some(rejection.label().to_owned());
    }
    let binding_hash_bytes = binding_hash_bytes.expect("validated binding_hash hex shape");
    let proof_value = first.proof.as_ref().expect("validated proof presence");
    let proof = match parse_bytes_value(
        proof_value,
        NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        "Lean proof upload item",
    ) {
        Ok(proof) => {
            assert!(
                case.proof_bytes_decode,
                "{} Lean expected proof byte rejection, but production decoded bytes",
                case.name
            );
            proof
        }
        Err(_) => {
            assert!(
                !case.proof_bytes_decode,
                "{} Lean expected proof byte decode, but production rejected bytes",
                case.name
            );
            return Some("proof_bytes_rejected".to_owned());
        }
    };
    assert_eq!(
        case.max_proof_bytes, NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        "{} Lean proof upload byte cap drifted from production",
        case.name
    );
    assert_eq!(
        case.proof_bytes,
        proof.len(),
        "{} proof byte length drifted from Lean projection",
        case.name
    );
    let matches_key = native_tx_leaf_artifact_binding_hash_matches_key(binding_hash_bytes, &proof);
    if !proof.is_empty() && proof.len() <= NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE {
        assert_eq!(
            matches_key, case.proof_binding_hash_matches_key,
            "{} proof binding hash/key match drifted from Lean projection",
            case.name
        );
    }
    let decoded_admission =
        evaluate_native_proof_sidecar_decoded_admission(NativeProofSidecarDecodedAdmissionInput {
            proof_bytes: proof.len(),
            max_proof_bytes: NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
            proof_binding_hash_matches_key: matches_key,
        });
    decoded_admission
        .err()
        .map(|rejection| rejection.label().to_owned())
}

#[test]
fn lean_generated_sync_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SYNC_ADMISSION_VECTORS") else {
        eprintln!(
            "HEGEMON_LEAN_SYNC_ADMISSION_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read generated Lean sync admission vectors");
    let vectors: LeanSyncAdmissionVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean sync admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.sync_response_range_cases.is_empty(),
        "Lean sync response-range cases must not be empty"
    );
    assert!(
        !vectors.sync_missing_request_cases.is_empty(),
        "Lean sync missing-request cases must not be empty"
    );
    assert!(
        !vectors.sync_response_count_cases.is_empty(),
        "Lean sync response-count cases must not be empty"
    );
    assert!(
        !vectors.sync_request_rate_cases.is_empty(),
        "Lean sync request-rate cases must not be empty"
    );
    assert!(
        !vectors.sync_request_rate_state_cases.is_empty(),
        "Lean sync request-rate state cases must not be empty"
    );
    assert!(
        !vectors.mining_sync_evidence_cases.is_empty(),
        "Lean mining sync evidence cases must not be empty"
    );
    assert!(
        !vectors.mining_gate_cases.is_empty(),
        "Lean mining gate cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.sync_response_range_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_response_range_case(case);
    }
    for case in &vectors.sync_missing_request_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_missing_request_case(case);
    }
    for case in &vectors.sync_response_count_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_response_count_case(case);
    }
    for case in &vectors.sync_request_rate_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_request_rate_case(case);
    }
    for case in &vectors.sync_request_rate_state_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_request_rate_state_case(case);
    }
    for case in &vectors.mining_sync_evidence_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_mining_sync_evidence_case(case);
    }
    for case in &vectors.mining_gate_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_mining_gate_case(case);
    }
}

fn verify_lean_sync_response_range_case(case: &LeanSyncResponseRangeCase) {
    let actual = native_sync_response_range(NativeSyncResponseRangeInput {
        from_height: case.from_height,
        to_height: case.to_height,
        best_height: case.best_height,
        max_blocks: case.max_blocks,
    });
    assert_eq!(
        actual.is_some(),
        case.expected_has_range,
        "{} native sync response-range validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.map(|range| range.from_height),
        case.expected_from_height,
        "{} native sync response-range start drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.map(|range| range.to_height),
        case.expected_to_height,
        "{} native sync response-range end drifted from Lean spec",
        case.name
    );
}

fn verify_lean_sync_missing_request_case(case: &LeanSyncMissingRequestCase) {
    let actual = native_sync_missing_request_range(NativeSyncMissingRequestInput {
        best_height: case.best_height,
        announced_height: case.announced_height,
        max_blocks: case.max_blocks,
    });
    assert_eq!(
        actual.is_some(),
        case.expected_has_request,
        "{} native sync missing-request validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.map(|range| range.from_height),
        case.expected_from_height,
        "{} native sync missing-request start drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual.map(|range| range.to_height),
        case.expected_to_height,
        "{} native sync missing-request end drifted from Lean spec",
        case.name
    );
}

fn verify_lean_sync_response_count_case(case: &LeanSyncResponseCountCase) {
    let actual =
        evaluate_native_sync_response_count_admission(NativeSyncResponseCountAdmissionInput {
            block_count: case.block_count,
            max_blocks: case.max_blocks,
        });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native sync response-count validity drifted from Lean spec",
        case.name
    );
    if !case.expected_valid {
        assert_eq!(
            actual.err(),
            Some(NativeSyncAdmissionRejection::ResponseBlockCountTooLarge),
            "{} native sync response-count rejection drifted from expected cap rejection",
            case.name
        );
    }
}

fn verify_lean_sync_request_rate_case(case: &LeanSyncRequestRateCase) {
    let actual = evaluate_native_sync_request_rate_admission(NativeSyncRequestRateAdmissionInput {
        requests_in_window: case.requests_in_window,
        max_requests: case.max_requests,
        window_elapsed_ms: case.window_elapsed_ms,
        window_ms: case.window_ms,
    });
    assert_eq!(
        actual.is_ok(),
        case.expected_valid,
        "{} native sync request-rate validity drifted from Lean spec",
        case.name
    );
    if !case.expected_valid {
        assert_eq!(
            actual.err(),
            Some(NativeSyncAdmissionRejection::RequestRateLimited),
            "{} native sync request-rate rejection drifted from expected rate-limit rejection",
            case.name
        );
    }
}

fn verify_lean_sync_request_rate_state_case(case: &LeanSyncRequestRateStateCase) {
    let retained = NativeNode::sync_request_rate_limit_entries_before_insert(
        case.current_entries,
        case.max_entries,
    );
    let after_insert = NativeNode::sync_request_rate_limit_entries_after_insert(
        case.current_entries,
        case.max_entries,
    );
    assert_eq!(
        retained, case.expected_retained_before_insert,
        "{} native sync request-rate state pre-insert retention drifted from Lean spec",
        case.name
    );
    assert_eq!(
        after_insert, case.expected_entries_after_insert,
        "{} native sync request-rate state post-insert count drifted from Lean spec",
        case.name
    );
    assert_eq!(
        after_insert <= case.max_entries,
        case.expected_valid,
        "{} native sync request-rate state validity drifted from Lean spec",
        case.name
    );
}

fn verify_lean_mining_sync_evidence_case(case: &LeanMiningSyncEvidenceCase) {
    let actual = native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
        verified_new_progress: case.verified_new_progress,
        verified_known_at_or_below_local_best: case.verified_known_at_or_below_local_best,
        local_best_height: case.local_best_height,
        peer_best_height: case.peer_best_height,
        stopped_on_error: case.stopped_on_error,
    });
    assert_eq!(
        actual, case.expected_observed_height,
        "{} native mining sync evidence observation drifted from Lean spec",
        case.name
    );
}

fn verify_lean_mining_gate_case(case: &LeanMiningGateCase) {
    let actual = native_mining_gate_allows_work(NativeMiningGateInput {
        has_seeds: case.has_seeds,
        dev: case.dev,
        bootstrap_mining_authoring: case.bootstrap_authoring,
        observed_gate_open: case.observed_gate_open,
    });
    assert_eq!(
        actual, case.expected_allows_work,
        "{} native mining gate policy drifted from Lean spec",
        case.name
    );
}

#[test]
fn native_sync_catch_up_target_only_when_observed_target_is_ahead() {
    assert_eq!(native_sync_catch_up_target(0, false, 512), None);
    assert_eq!(native_sync_catch_up_target(512, true, 512), None);
    assert_eq!(native_sync_catch_up_target(768, true, 512), None);
    assert_eq!(
        native_sync_catch_up_target(512, true, 768),
        Some((512, 768))
    );
}

#[test]
fn lean_generated_sync_raw_ingress_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SYNC_RAW_INGRESS_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_SYNC_RAW_INGRESS_VECTORS not set; skipping generated Lean sync raw-ingress vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read generated Lean sync raw-ingress vectors");
    let vectors: LeanSyncRawIngressVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean sync raw-ingress vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.sync_raw_ingress_cases.is_empty(),
        "Lean sync raw-ingress cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.sync_raw_ingress_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_raw_ingress_case(case);
    }
}

fn verify_lean_sync_raw_ingress_case(case: &LeanSyncRawIngressCase) {
    let actual = match decode_sync_message(&case.raw_bytes) {
        Err(_) => Some("wire_decode_rejected".to_owned()),
        Ok(NativeSyncMessage::Request {
            from_height,
            to_height,
        }) => {
            assert_eq!(
                case.expected_kind, "request",
                "{} decoded to request but Lean expected {}",
                case.name, case.expected_kind
            );
            assert_eq!(
                from_height, case.from_height,
                "{} raw sync request from_height drifted from Lean bytes",
                case.name
            );
            assert_eq!(
                to_height, case.to_height,
                "{} raw sync request to_height drifted from Lean bytes",
                case.name
            );
            let canonical = encode_sync_message(&NativeSyncMessage::Request {
                from_height,
                to_height,
            })
            .expect("re-encode decoded sync request");
            assert_eq!(
                canonical, case.raw_bytes,
                "{} raw sync request bytes are not canonical production bytes",
                case.name
            );

            let max_blocks = u64::try_from(case.max_blocks)
                .expect("Lean sync max_blocks must fit u64 for range admission");
            let range = native_sync_response_range(NativeSyncResponseRangeInput {
                from_height,
                to_height,
                best_height: case.request_best_height,
                max_blocks,
            });
            assert_eq!(
                range.is_some(),
                case.expected_has_range,
                "{} sync request range admission drifted from Lean",
                case.name
            );
            assert_eq!(
                range.map(|range| range.from_height),
                case.expected_from_height,
                "{} sync request range from_height drifted from Lean",
                case.name
            );
            assert_eq!(
                range.map(|range| range.to_height),
                case.expected_to_height,
                "{} sync request range to_height drifted from Lean",
                case.name
            );
            None
        }
        Ok(NativeSyncMessage::Response {
            best_height,
            blocks,
        }) => {
            assert_eq!(
                case.expected_kind, "response",
                "{} decoded to response but Lean expected {}",
                case.name, case.expected_kind
            );
            assert_eq!(
                best_height, case.response_best_height,
                "{} raw sync response best_height drifted from Lean",
                case.name
            );
            let decoded_heights: Vec<_> = blocks.iter().map(|block| block.height).collect();
            assert_eq!(
                decoded_heights, case.response_heights,
                "{} raw sync response block heights drifted from Lean",
                case.name
            );
            let canonical = encode_sync_message(&NativeSyncMessage::Response {
                best_height,
                blocks: blocks.clone(),
            })
            .expect("re-encode decoded sync response");
            assert_eq!(
                canonical, case.raw_bytes,
                "{} raw sync response bytes are not canonical production bytes",
                case.name
            );

            let mut blocks = blocks;
            match admit_and_sort_native_sync_response_blocks(&mut blocks, case.max_blocks) {
                Err(rejection) => Some(rejection.label().to_owned()),
                Ok(()) => {
                    let sorted_heights: Vec<_> = blocks.iter().map(|block| block.height).collect();
                    assert_eq!(
                        sorted_heights, case.expected_sorted_heights,
                        "{} raw sync response sorted heights drifted from Lean",
                        case.name
                    );

                    let outcomes = case
                        .outcomes
                        .iter()
                        .map(|outcome| lean_sync_response_import_outcome_from_label(case, outcome));
                    let progress =
                        native_sync_response_import_progress(case.response_heights.len(), outcomes);
                    assert_eq!(
                        progress.attempted_blocks, case.expected_attempted_blocks,
                        "{} raw sync response attempted-block count drifted from Lean",
                        case.name
                    );
                    assert_eq!(
                        progress.imported_blocks, case.expected_imported_blocks,
                        "{} raw sync response imported-block count drifted from Lean",
                        case.name
                    );
                    assert_eq!(
                        progress.stopped_on_error, case.expected_stopped_on_error,
                        "{} raw sync response stopped-on-error flag drifted from Lean",
                        case.name
                    );
                    assert_eq!(
                        progress.should_request_more(case.local_best_height, case.peer_best_height),
                        case.expected_request_more,
                        "{} raw sync response continuation decision drifted from Lean",
                        case.name
                    );
                    None
                }
            }
        }
        Ok(NativeSyncMessage::Announce(meta)) => {
            assert_eq!(
                case.expected_kind, "announce",
                "{} decoded to announce at height {} but Lean expected {}",
                case.name, meta.height, case.expected_kind
            );
            None
        }
        Ok(NativeSyncMessage::PendingAction { action }) => {
            assert_eq!(
                case.expected_kind, "pending_action",
                "{} decoded to pending action relay but Lean expected {}",
                case.name, case.expected_kind
            );
            let canonical = encode_sync_message(&NativeSyncMessage::PendingAction {
                action: action.clone(),
            })
            .expect("re-encode decoded sync pending action");
            assert_eq!(
                canonical, case.raw_bytes,
                "{} raw sync pending action bytes are not canonical production bytes",
                case.name
            );
            match decode_scale_exact::<PendingAction>(&action, "Lean pending action relay") {
                Ok(_) => None,
                Err(_) => Some("pending_action_decode_rejected".to_owned()),
            }
        }
    };
    assert_eq!(
        actual.is_none(),
        case.expected_valid,
        "{} raw sync ingress validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual, case.expected_rejection,
        "{} raw sync ingress rejection drifted from Lean spec",
        case.name
    );
}

fn lean_sync_response_import_outcome_from_label(
    case: &LeanSyncRawIngressCase,
    label: &str,
) -> NativeSyncResponseImportOutcome {
    match label {
        "imported" => NativeSyncResponseImportOutcome::Imported,
        "already_known" => NativeSyncResponseImportOutcome::AlreadyKnown,
        "error" => NativeSyncResponseImportOutcome::Error,
        other => panic!(
            "{} unknown raw-ingress sync-response import outcome {other}",
            case.name
        ),
    }
}

#[test]
fn lean_generated_sync_response_import_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SYNC_RESPONSE_IMPORT_VECTORS") else {
        eprintln!(
                "HEGEMON_LEAN_SYNC_RESPONSE_IMPORT_VECTORS not set; skipping generated Lean sync-response import vector check"
            );
        return;
    };
    let raw =
        std::fs::read_to_string(&path).expect("read generated Lean sync-response import vectors");
    let vectors: LeanSyncResponseImportVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean sync-response import vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.sync_response_import_cases.is_empty(),
        "Lean sync-response import cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.sync_response_import_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_response_import_case(case);
    }
}

fn verify_lean_sync_response_import_case(case: &LeanSyncResponseImportCase) {
    let count_admission =
        evaluate_native_sync_response_count_admission(NativeSyncResponseCountAdmissionInput {
            block_count: case.response_heights.len(),
            max_blocks: case.max_blocks,
        });
    let actual_rejection = match count_admission {
        Err(rejection) => Some(rejection.label().to_owned()),
        Ok(()) if case.outcomes.len() > case.response_heights.len() => {
            Some("outcome_count_over_response".to_owned())
        }
        Ok(()) => None,
    };
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native sync-response import validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native sync-response import rejection drifted from Lean spec",
        case.name
    );
    if !case.expected_valid {
        return;
    }

    let blocks: Vec<_> = case
        .response_heights
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, height)| lean_sync_response_import_meta(height, idx as u8))
        .collect();
    let mut sorted = blocks;
    admit_and_sort_native_sync_response_blocks(&mut sorted, case.max_blocks)
        .expect("valid Lean sync-response import case should sort");
    let sorted_heights: Vec<_> = sorted.iter().map(|meta| meta.height).collect();
    assert_eq!(
        sorted_heights, case.expected_sorted_heights,
        "{} native sync-response import sorted-height order drifted from Lean spec",
        case.name
    );

    let outcomes = case
        .outcomes
        .iter()
        .map(|outcome| lean_sync_response_import_outcome(case, outcome));
    let progress = native_sync_response_import_progress(case.response_heights.len(), outcomes);
    assert_eq!(
        progress.attempted_blocks, case.expected_attempted_blocks,
        "{} native sync-response import attempted-block count drifted from Lean spec",
        case.name
    );
    assert_eq!(
        progress.imported_blocks, case.expected_imported_blocks,
        "{} native sync-response import imported-block count drifted from Lean spec",
        case.name
    );
    assert_eq!(
        progress.stopped_on_error, case.expected_stopped_on_error,
        "{} native sync-response import stopped-on-error flag drifted from Lean spec",
        case.name
    );
    assert_eq!(
        progress.should_request_more(case.local_best_height, case.peer_best_height),
        case.expected_request_more,
        "{} native sync-response import continuation decision drifted from Lean spec",
        case.name
    );
}

fn lean_sync_response_import_outcome(
    case: &LeanSyncResponseImportCase,
    label: &str,
) -> NativeSyncResponseImportOutcome {
    match label {
        "imported" => NativeSyncResponseImportOutcome::Imported,
        "already_known" => NativeSyncResponseImportOutcome::AlreadyKnown,
        "error" => NativeSyncResponseImportOutcome::Error,
        other => panic!("{} unknown sync-response import outcome {other}", case.name),
    }
}

fn lean_sync_response_import_meta(height: u64, discriminator: u8) -> NativeBlockMeta {
    let mut meta = genesis_meta(0x207f_ffff).expect("genesis metadata");
    meta.height = height;
    meta.hash = [discriminator; 32];
    meta.hash[..8].copy_from_slice(&height.to_le_bytes());
    meta.parent_hash = [discriminator.wrapping_add(1); 32];
    meta
}

#[test]
fn stale_known_sync_response_requests_more_without_reorg_escalation() {
    let mut progress = NativeSyncResponseImportProgress::new(128);
    for _ in 0..128 {
        assert!(progress.record(NativeSyncResponseImportOutcome::AlreadyKnown));
    }

    assert!(progress.completed_with_only_known_blocks());
    assert!(progress.should_request_more(128, 6_132));
    assert!(!native_sync_response_should_escalate_reorg_backfill(
        progress, 128, 6_132
    ));
}

#[test]
fn unproductive_unknown_sync_response_escalates_reorg_backfill() {
    let mut progress = NativeSyncResponseImportProgress::new(128);
    for _ in 0..127 {
        assert!(progress.record(NativeSyncResponseImportOutcome::AlreadyKnown));
    }

    assert!(!progress.completed_with_only_known_blocks());
    assert!(progress.should_request_more(128, 6_132));
    assert!(native_sync_response_should_escalate_reorg_backfill(
        progress, 128, 6_132
    ));
}

#[test]
fn lean_generated_sync_block_range_publication_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SYNC_BLOCK_RANGE_PUBLICATION_ADMISSION_VECTORS")
    else {
        eprintln!(
                "HEGEMON_LEAN_SYNC_BLOCK_RANGE_PUBLICATION_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean sync block-range publication admission vectors");
    let vectors: LeanSyncBlockRangePublicationAdmissionVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean sync block-range publication admission vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        !vectors.sync_block_range_publication_cases.is_empty(),
        "Lean sync block-range publication cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.sync_block_range_publication_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_sync_block_range_publication_admission_case(case);
    }
}

fn verify_lean_sync_block_range_publication_admission_case(
    case: &LeanSyncBlockRangePublicationAdmissionCase,
) {
    let input = NativeSyncBlockRangePublicationAdmissionInput {
        range_admitted: case.range_admitted,
        served_count_matches_range: case.served_count_matches_range,
        first_height_matches_range: case.first_height_matches_range,
        last_height_matches_range: case.last_height_matches_range,
        served_heights_contiguous: case.served_heights_contiguous,
        previous_parent_anchor_verified: case.previous_parent_anchor_verified,
        parent_hashes_contiguous: case.parent_hashes_contiguous,
        canonical_rows_verified: case.canonical_rows_verified,
        action_bodies_verified: case.action_bodies_verified,
    };
    let actual = evaluate_native_sync_block_range_publication_admission(input);
    let actual_rejection = actual.err().map(|rejection| rejection.label().to_owned());
    assert_eq!(
        actual_rejection.is_none(),
        case.expected_valid,
        "{} native sync block-range publication validity drifted from Lean spec",
        case.name
    );
    assert_eq!(
        actual_rejection, case.expected_rejection,
        "{} native sync block-range publication rejection drifted from Lean spec",
        case.name
    );
}

#[test]
fn sync_block_range_publication_input_rejects_truncated_or_unverified_rows() {
    let mut genesis = genesis_meta(0x207f_ffff).expect("genesis metadata");
    genesis.height = 0;
    genesis.hash = [1u8; 32];
    let mut child = genesis.clone();
    child.height = 1;
    child.parent_hash = genesis.hash;
    child.hash = [2u8; 32];
    let range = NativeSyncRange {
        from_height: 0,
        to_height: 1,
    };

    let truncated =
        native_sync_block_range_publication_admission_input(range, &[genesis.clone()], 1, 0, true);
    assert_eq!(
        evaluate_native_sync_block_range_publication_admission(truncated),
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ServedCountMismatch)
    );

    let unverified_body = native_sync_block_range_publication_admission_input(
        range,
        &[genesis.clone(), child.clone()],
        2,
        0,
        true,
    );
    assert_eq!(
        evaluate_native_sync_block_range_publication_admission(unverified_body),
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ActionBodiesUnverified)
    );

    let anchored_range = NativeSyncRange {
        from_height: 1,
        to_height: 1,
    };
    let anchor_mismatch =
        native_sync_block_range_publication_admission_input(anchored_range, &[child], 1, 1, false);
    assert_eq!(
        evaluate_native_sync_block_range_publication_admission(anchor_mismatch),
        Err(NativeSyncBlockRangePublicationAdmissionRejection::ParentHashMismatch)
    );
}

#[test]
fn native_sync_admission_rejects_oversized_responses() {
    assert_eq!(
        evaluate_native_sync_response_count_admission(NativeSyncResponseCountAdmissionInput {
            block_count: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE + 1,
            max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
        },),
        Err(NativeSyncAdmissionRejection::ResponseBlockCountTooLarge)
    );
}

#[test]
fn native_sync_request_rate_admission_limits_peer_requests_per_window() {
    assert_eq!(
        evaluate_native_sync_request_rate_admission(NativeSyncRequestRateAdmissionInput {
            requests_in_window: MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW,
            max_requests: MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW,
            window_elapsed_ms: 0,
            window_ms: duration_millis_u64(NATIVE_SYNC_REQUEST_RATE_WINDOW),
        }),
        Err(NativeSyncAdmissionRejection::RequestRateLimited)
    );
    assert_eq!(
        evaluate_native_sync_request_rate_admission(NativeSyncRequestRateAdmissionInput {
            requests_in_window: MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW,
            max_requests: MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW,
            window_elapsed_ms: duration_millis_u64(NATIVE_SYNC_REQUEST_RATE_WINDOW),
            window_ms: duration_millis_u64(NATIVE_SYNC_REQUEST_RATE_WINDOW),
        }),
        Ok(())
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let peer = [42u8; 32];
    for _ in 0..MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW {
        node.admit_sync_request_from_peer(peer)
            .expect("request inside peer window must admit");
    }
    assert_eq!(
        node.admit_sync_request_from_peer(peer),
        Err(NativeSyncAdmissionRejection::RequestRateLimited)
    );
}

#[test]
fn native_sync_request_rate_state_is_bounded() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

    for i in 0..(MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS + 32) {
        let mut peer = [0u8; 32];
        peer[..8].copy_from_slice(&(i as u64).to_le_bytes());
        node.admit_sync_request_from_peer(peer)
            .expect("first request for each peer admits");
    }

    assert!(
        node.sync_request_rate_limits.lock().len() <= MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS,
        "sync request rate-limit state must stay bounded"
    );
}

#[test]
fn native_sync_response_count_uses_bounded_request_item_gate() {
    let input = NativeSyncResponseCountAdmissionInput {
        block_count: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE + 1,
        max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
    };
    let bounded = native_sync_response_count_bounded_request(input);
    assert_eq!(bounded.item_count, input.block_count);
    assert_eq!(bounded.item_count_cap, input.max_blocks);
    assert_eq!(bounded.raw_bytes, 0);
    assert_eq!(bounded.decoded_bytes, 0);
    assert_eq!(
        evaluate_native_bounded_request_admission(bounded),
        Err(NativeBoundedRequestAdmissionRejection::ItemCount)
    );
    assert_eq!(
        evaluate_native_sync_response_count_admission(input),
        Err(NativeSyncAdmissionRejection::ResponseBlockCountTooLarge)
    );
}

#[test]
fn native_sync_ranges_fail_closed_when_cap_zero() {
    assert_eq!(
        native_sync_response_range(NativeSyncResponseRangeInput {
            from_height: 1,
            to_height: 1,
            best_height: 1,
            max_blocks: 0,
        }),
        None
    );
    assert_eq!(
        native_sync_missing_request_range(NativeSyncMissingRequestInput {
            best_height: 1,
            announced_height: 2,
            max_blocks: 0,
        }),
        None
    );
}

#[test]
fn native_sync_near_tip_request_backfills_reorg_window() {
    let range = native_sync_missing_request_range_with_reorg_backfill(
        NativeSyncMissingRequestInput {
            best_height: 20592,
            announced_height: 20618,
            max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        },
        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
    )
    .expect("near-tip announced fork should request a bounded backfill range");
    assert_eq!(range.from_height, 20561);
    assert_eq!(range.to_height, 20618);

    let straight_sync = native_sync_missing_request_range_with_reorg_backfill(
        NativeSyncMissingRequestInput {
            best_height: 0,
            announced_height: MAX_NATIVE_SYNC_RESPONSE_BLOCKS + 100,
            max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        },
        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
    )
    .expect("bulk sync should still start after local best");
    assert_eq!(straight_sync.from_height, 1);
    assert_eq!(straight_sync.to_height, MAX_NATIVE_SYNC_RESPONSE_BLOCKS);
}

#[test]
fn native_sync_large_gap_request_still_backfills_reorg_window() {
    let range = native_sync_missing_request_range_with_reorg_backfill(
        NativeSyncMissingRequestInput {
            best_height: 4614,
            announced_height: 4960,
            max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        },
        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
    )
    .expect("higher peer branch should request enough local prefix to find a fork point");

    let expected_from = 4583;
    assert_eq!(range.from_height, expected_from);
    assert_eq!(
        range.to_height,
        expected_from + MAX_NATIVE_SYNC_RESPONSE_BLOCKS - 1
    );
}

#[test]
fn native_sync_bootstrap_request_after_first_chunk_starts_after_local_best() {
    let best_height = MAX_NATIVE_SYNC_RESPONSE_BLOCKS + 17;
    let range = native_sync_missing_request_range(NativeSyncMissingRequestInput {
        best_height,
        announced_height: 21_971,
        max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
    })
    .expect("post-bootstrap catch-up should request the next bounded window");
    assert_eq!(range.from_height, best_height + 1);
    assert_eq!(
        range.to_height,
        best_height + MAX_NATIVE_SYNC_RESPONSE_BLOCKS
    );
}

#[test]
fn live_native_sync_request_window_is_smaller_than_protocol_admission_cap() {
    let range = native_sync_missing_request_range(NativeSyncMissingRequestInput {
        best_height: 0,
        announced_height: 10_000,
        max_blocks: NATIVE_SYNC_REQUEST_BLOCKS,
    })
    .expect("fresh public join should request a bounded live chunk");
    assert_eq!(range.from_height, 1);
    assert_eq!(range.to_height, NATIVE_SYNC_REQUEST_BLOCKS);
    assert!(range.to_height < MAX_NATIVE_SYNC_RESPONSE_BLOCKS);
}

#[test]
fn live_mining_requires_shared_seeds_or_explicit_bootstrap_authoring() {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_LOCK.lock().expect("env test lock");
    let saved_mine = std::env::var("HEGEMON_MINE").ok();
    let saved_seeds = std::env::var("HEGEMON_SEEDS").ok();
    let saved_bootstrap = std::env::var("HEGEMON_BOOTSTRAP_AUTHORING").ok();

    let tmp = tempfile::tempdir().expect("tempdir");
    let cli = |base_path: PathBuf| NativeCli {
        dev: false,
        tmp: false,
        base_path: Some(base_path),
        rpc_port: 0,
        rpc_external: false,
        rpc_methods: "safe".to_string(),
        rpc_cors: None,
        port: 30333,
        listen_addr: Some("127.0.0.1:0".to_string()),
        name: Some("test-live-miner".to_string()),
    };

    std::env::set_var("HEGEMON_MINE", "1");
    std::env::remove_var("HEGEMON_SEEDS");
    std::env::remove_var("HEGEMON_BOOTSTRAP_AUTHORING");
    let err = NativeConfig::from_cli(cli(tmp.path().join("no-seeds")))
        .expect_err("live mining without seeds must fail closed");
    assert!(err.to_string().contains("empty HEGEMON_SEEDS"));

    std::env::set_var("HEGEMON_BOOTSTRAP_AUTHORING", "1");
    let bootstrap = NativeConfig::from_cli(cli(tmp.path().join("bootstrap")))
        .expect("explicit bootstrap authoring admits empty-seed mining");
    assert!(bootstrap.bootstrap_mining_authoring);

    std::env::remove_var("HEGEMON_BOOTSTRAP_AUTHORING");
    std::env::set_var("HEGEMON_SEEDS", APPROVED_PUBLIC_JOIN_SEEDS);
    let seeded = NativeConfig::from_cli(cli(tmp.path().join("seeded")))
        .expect("seeded live mining is admitted");
    assert_eq!(
        seeded.seeds,
        vec![
            APPROVED_PUBLIC_JOIN_SEED_OVH.to_string(),
            APPROVED_PUBLIC_JOIN_SEED_DEV.to_string()
        ]
    );

    match saved_mine {
        Some(value) => std::env::set_var("HEGEMON_MINE", value),
        None => std::env::remove_var("HEGEMON_MINE"),
    }
    match saved_seeds {
        Some(value) => std::env::set_var("HEGEMON_SEEDS", value),
        None => std::env::remove_var("HEGEMON_SEEDS"),
    }
    match saved_bootstrap {
        Some(value) => std::env::set_var("HEGEMON_BOOTSTRAP_AUTHORING", value),
        None => std::env::remove_var("HEGEMON_BOOTSTRAP_AUTHORING"),
    }
}

#[test]
fn seeded_mining_waits_until_sync_target_is_reached() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");

    assert!(!node.mining_sync_gate_allows_work());
    node.observe_verified_sync_peer_height(3);
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(node.sync_target_height.load(Ordering::Relaxed), 3);

    for _ in 0..3 {
        mine_empty_native_block(&node);
    }
    node.refresh_mining_sync_gate();
    assert!(node.mining_sync_gate_allows_work());
}

#[test]
fn seeded_mining_gate_opens_on_verified_genesis_sync_evidence() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");

    assert!(!node.mining_sync_gate_allows_work());
    node.observe_verified_sync_peer_height(0);
    assert_eq!(node.sync_target_height.load(Ordering::Relaxed), 0);
    assert!(node.mining_sync_gate_allows_work());
    let (syncing, target) = node.sync_status_fields();
    assert!(!syncing);
    assert_eq!(target, 0);
}

#[test]
fn bootstrap_authoring_with_seed_starts_open_until_higher_target_observed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push(APPROVED_PUBLIC_JOIN_SEED_OVH.to_string());
    config.bootstrap_mining_authoring = true;
    let node = NativeNode::open(config).expect("node");

    assert!(node.mining_sync_gate_allows_work());
    let (syncing, target) = node.sync_status_fields();
    assert!(!syncing);
    assert_eq!(target, 0);

    node.observe_pending_sync_peer_height(node.best_meta().height + 1);
    assert!(!node.mining_sync_gate_allows_work());
}

#[test]
fn pending_sync_target_keeps_status_syncing_without_opening_mining_gate() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }

    let target = node.best_meta().height + 10;
    node.observe_pending_sync_peer_height(target);

    let (syncing, observed_target) = node.sync_status_fields();
    assert!(syncing);
    assert_eq!(observed_target, target);
    assert!(!node.mining_sync_gate_allows_work());
}

#[test]
fn empty_seed_live_mining_gate_ignores_observed_open_without_bootstrap_authoring() {
    assert!(!native_mining_gate_allows_work(NativeMiningGateInput {
        has_seeds: false,
        dev: false,
        bootstrap_mining_authoring: false,
        observed_gate_open: true,
    }));
    assert!(native_mining_gate_allows_work(NativeMiningGateInput {
        has_seeds: false,
        dev: false,
        bootstrap_mining_authoring: true,
        observed_gate_open: false,
    }));
    assert!(!native_mining_gate_allows_work(NativeMiningGateInput {
        has_seeds: true,
        dev: true,
        bootstrap_mining_authoring: true,
        observed_gate_open: false,
    }));
}

#[test]
fn seeded_mining_gate_opens_on_known_equal_height_sync_evidence() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }
    let best = node.best_meta();
    assert!(!node.mining_sync_gate_allows_work());
    assert!(node
        .has_verified_header_hash(&best.hash)
        .expect("known header"));

    let observed = native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
        verified_new_progress: false,
        verified_known_at_or_below_local_best: true,
        local_best_height: best.height,
        peer_best_height: best.height,
        stopped_on_error: false,
    });
    assert_eq!(observed, Some(best.height));
    node.observe_verified_sync_peer_height(observed.expect("observed local tip"));
    assert_eq!(node.sync_target_height.load(Ordering::Relaxed), best.height);
    assert!(node.mining_sync_gate_allows_work());
    let (syncing, target) = node.sync_status_fields();
    assert!(!syncing);
    assert_eq!(target, best.height);
}

#[test]
fn seeded_mining_gate_stays_closed_after_partial_sync_progress() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }
    let local_best = node.best_meta();
    let peer_best_height = local_best.height + 4_096;

    let observed = native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
        verified_new_progress: true,
        verified_known_at_or_below_local_best: false,
        local_best_height: local_best.height,
        peer_best_height,
        stopped_on_error: false,
    })
    .expect("verified partial sync progress should produce sync evidence");
    node.observe_verified_sync_peer_height(observed);

    assert_eq!(
        node.sync_target_height.load(Ordering::Relaxed),
        peer_best_height
    );
    assert!(!node.mining_sync_gate_allows_work());
    let (syncing, target) = node.sync_status_fields();
    assert!(syncing);
    assert_eq!(target, peer_best_height);
}

#[test]
fn same_height_unknown_peer_tip_keeps_seeded_node_syncing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }

    let best = node.best_meta();
    let mut peer_hash = [0x42; 32];
    if peer_hash == best.hash {
        peer_hash[0] ^= 1;
    }
    node.observe_pending_sync_peer_tip(Some([0x24; 32]), best.height, Some(peer_hash));

    let (syncing, target) = node.sync_status_fields();
    assert!(syncing);
    assert_eq!(target, best.height);
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_target_peer.lock(), Some([0x24; 32]));
}

#[test]
fn verified_equal_height_sync_evidence_clears_stale_fork_target() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }

    let best = node.best_meta();
    let mut peer_hash = [0x42; 32];
    if peer_hash == best.hash {
        peer_hash[0] ^= 1;
    }
    node.observe_pending_sync_peer_tip(Some([0x24; 32]), best.height, Some(peer_hash));
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_target_peer.lock(), Some([0x24; 32]));
    assert_eq!(*node.sync_target_hash.lock(), Some(peer_hash));

    node.observe_verified_sync_peer_height(best.height);

    let (syncing, target) = node.sync_status_fields();
    assert!(!syncing);
    assert_eq!(target, best.height);
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_target_peer.lock(), None);
    assert_eq!(*node.sync_target_hash.lock(), None);
}

#[test]
fn verified_local_tip_evidence_clears_height_only_sync_target() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }

    let best = node.best_meta();
    node.observe_pending_sync_peer_height(best.height + 1);
    assert!(!node.mining_sync_gate_allows_work());

    node.observe_verified_sync_peer_height(best.height);

    let (syncing, target) = node.sync_status_fields();
    assert!(!syncing);
    assert_eq!(target, best.height);
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_target_peer.lock(), None);
    assert_eq!(*node.sync_target_hash.lock(), None);
}

#[test]
fn empty_response_clear_keeps_hash_anchored_sync_target_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }

    let best = node.best_meta();
    let mut peer_hash = [0x42; 32];
    if peer_hash == best.hash {
        peer_hash[0] ^= 1;
    }
    node.observe_pending_sync_peer_tip(Some([0x24; 32]), best.height + 1, Some(peer_hash));

    assert!(!node.clear_unanchored_sync_target_to_local_tip(best.height + 1, "test empty response"));
    let (syncing, target) = node.sync_status_fields();
    assert!(syncing);
    assert_eq!(target, best.height + 1);
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_target_peer.lock(), Some([0x24; 32]));
    assert_eq!(*node.sync_target_hash.lock(), Some(peer_hash));
}

#[test]
fn nonwinning_hash_anchored_sync_response_clears_target() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }

    let best = node.best_meta();
    let mut target = best.clone();
    target.height = best.height + 1;
    target.hash = [0x51; 32];
    target.parent_hash = best.hash;
    target.cumulative_work = [0; 48];
    assert!(!native_meta_better_than(&target, &best));
    node.observe_pending_sync_peer_tip(Some([0x24; 32]), target.height, Some(target.hash));
    assert!(!node.mining_sync_gate_allows_work());

    assert!(node.clear_nonwinning_sync_target_response_to_local_tip(
        target.height,
        std::slice::from_ref(&target)
    ));

    let (syncing, observed_target) = node.sync_status_fields();
    assert!(!syncing);
    assert_eq!(observed_target, best.height);
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_target_peer.lock(), None);
    assert_eq!(*node.sync_target_hash.lock(), None);
}

#[test]
fn better_hash_anchored_sync_response_keeps_target() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    config.seeds.push("127.0.0.1:30333".to_string());
    let node = NativeNode::open(config).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }

    let best = node.best_meta();
    let mut target = best.clone();
    target.height = best.height + 1;
    target.hash = [0x52; 32];
    target.parent_hash = best.hash;
    target.cumulative_work = [0xff; 48];
    assert!(native_meta_better_than(&target, &best));
    node.observe_pending_sync_peer_tip(Some([0x24; 32]), target.height, Some(target.hash));

    assert!(!node.clear_nonwinning_sync_target_response_to_local_tip(
        target.height,
        std::slice::from_ref(&target)
    ));

    let (syncing, observed_target) = node.sync_status_fields();
    assert!(syncing);
    assert_eq!(observed_target, target.height);
    assert!(!node.mining_sync_gate_allows_work());
    assert_eq!(*node.sync_target_peer.lock(), Some([0x24; 32]));
    assert_eq!(*node.sync_target_hash.lock(), Some(target.hash));
}

#[test]
fn same_height_fork_tip_requests_bounded_reorg_window() {
    let best_hash = [0x11; 32];
    let peer_hash = [0x22; 32];
    let range = native_sync_observed_tip_request_range(
        5_016,
        best_hash,
        5_016,
        Some(peer_hash),
        MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
    )
    .expect("same-height fork tip should request reorg backfill");
    assert_eq!(range.from_height, 4_985);
    assert_eq!(range.to_height, 5_016);

    assert_eq!(
        native_sync_observed_tip_request_range(
            5_016,
            best_hash,
            5_016,
            Some(best_hash),
            MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
            NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
        ),
        None
    );
}

#[test]
fn large_gap_observed_tip_requests_straight_catch_up_window() {
    let range = native_sync_observed_tip_request_range(
        896,
        [0x11; 32],
        5_039,
        Some([0x22; 32]),
        MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        NATIVE_SYNC_REORG_BACKFILL_BLOCKS,
    )
    .expect("large-gap public join should request the next catch-up chunk");

    assert_eq!(range.from_height, 897);
    assert_eq!(range.to_height, 896 + MAX_NATIVE_SYNC_RESPONSE_BLOCKS);
}

#[test]
fn native_sync_escalated_large_gap_observed_tip_requests_reorg_context() {
    let range = native_sync_observed_tip_request_range(
        5_940,
        [0x31; 32],
        6_077,
        Some([0x07; 32]),
        MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
        NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS,
    )
    .expect("escalated large-gap fork recovery should request ancestor context");

    let expected_from = 5_940u64
        .saturating_sub(NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS)
        .saturating_add(1);
    assert_eq!(range.from_height, expected_from);
    assert_eq!(
        range.to_height,
        expected_from + MAX_NATIVE_SYNC_RESPONSE_BLOCKS - 1
    );
}

#[test]
fn native_sync_reorg_backfill_escalates_and_resets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");

    assert_eq!(
        node.sync_reorg_backfill_blocks(),
        NATIVE_SYNC_REORG_BACKFILL_BLOCKS
    );
    assert!(node.escalate_sync_reorg_backfill() > NATIVE_SYNC_REORG_BACKFILL_BLOCKS);
    while node.sync_reorg_backfill_blocks() < NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS {
        node.escalate_sync_reorg_backfill();
    }
    assert_eq!(
        node.sync_reorg_backfill_blocks(),
        NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS
    );
    node.reset_sync_reorg_backfill();
    assert_eq!(
        node.sync_reorg_backfill_blocks(),
        NATIVE_SYNC_REORG_BACKFILL_BLOCKS
    );
}

#[test]
fn native_sync_response_in_flight_deduplicates_peer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let peer = [0x44; 32];
    let range = NativeSyncRange {
        from_height: 1,
        to_height: 128,
    };

    assert_eq!(
        node.begin_sync_response_for_peer(peer, range),
        NativeSyncResponseStart::Started
    );
    assert_eq!(
        node.begin_sync_response_for_peer(peer, range),
        NativeSyncResponseStart::DuplicateRange
    );
    assert_eq!(
        node.begin_sync_response_for_peer(
            peer,
            NativeSyncRange {
                from_height: 129,
                to_height: 256,
            },
        ),
        NativeSyncResponseStart::Started
    );
    node.end_sync_response_for_peer(
        peer,
        NativeSyncRange {
            from_height: 129,
            to_height: 256,
        },
    );
    assert_eq!(
        node.begin_sync_response_for_peer(peer, range),
        NativeSyncResponseStart::DuplicateRange
    );
    node.end_sync_response_for_peer(peer, range);
    assert_eq!(
        node.begin_sync_response_for_peer(peer, range),
        NativeSyncResponseStart::Started
    );
    node.end_sync_response_for_peer(peer, range);
}

#[test]
fn outbound_native_sync_request_deduplicates_peer_range() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let peer = [0x45; 32];
    let other_peer = [0x46; 32];
    let range = NativeSyncRange {
        from_height: 769,
        to_height: 1_280,
    };

    assert!(node.begin_outbound_sync_request(Some(peer), range));
    assert!(!node.begin_outbound_sync_request(Some(peer), range));
    assert!(!node.begin_outbound_sync_request(Some(other_peer), range));
    assert!(!node.begin_outbound_sync_request(None, range));
    assert!(!node.begin_outbound_sync_request(None, range));
    assert!(!node.begin_outbound_sync_request(
        Some(other_peer),
        NativeSyncRange {
            from_height: 1_153,
            to_height: 1_664,
        },
    ));
    assert!(node.begin_outbound_sync_request(
        Some(other_peer),
        NativeSyncRange {
            from_height: 1_281,
            to_height: 1_536,
        },
    ));
    node.complete_outbound_sync_request(peer);
    assert!(node.begin_outbound_sync_request(Some(peer), range));
    assert!(!node.begin_outbound_sync_request(None, range));
    node.complete_outbound_sync_request(peer);
    node.complete_outbound_sync_request_target(None);
    assert!(node.begin_outbound_sync_request(None, range));
}

#[test]
fn outbound_native_sync_request_retries_after_live_timeout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let peer = [0x47; 32];
    let range = NativeSyncRange {
        from_height: 385,
        to_height: 448,
    };

    assert!(node.begin_outbound_sync_request(Some(peer), range));
    assert!(!node.begin_outbound_sync_request(Some(peer), range));
    {
        let mut requests = node.outbound_sync_requests.lock();
        let request = requests.get_mut(&Some(peer)).expect("tracked request");
        request.requested_at = Instant::now()
            .checked_sub(NATIVE_SYNC_REQUEST_RETRY_AFTER + Duration::from_millis(1))
            .expect("past instant");
    }
    assert!(node.begin_outbound_sync_request(Some(peer), range));
}

#[test]
fn outbound_native_sync_response_completion_is_range_aware() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let peer = [0x46; 32];
    let range = NativeSyncRange {
        from_height: 129,
        to_height: 256,
    };

    assert!(node.begin_outbound_sync_request(Some(peer), range));
    assert!(!node.complete_outbound_sync_response(
        peer,
        Some(NativeSyncRange {
            from_height: 1,
            to_height: 128,
        }),
    ));
    assert!(!node.begin_outbound_sync_request(Some(peer), range));
    node.complete_outbound_sync_request(peer);
    assert!(node.begin_outbound_sync_request(Some(peer), range));

    assert!(!node.complete_outbound_sync_response(
        peer,
        Some(NativeSyncRange {
            from_height: 257,
            to_height: 384,
        }),
    ));
    assert!(!node.begin_outbound_sync_request(Some(peer), range));

    assert!(node.complete_outbound_sync_response(
        peer,
        Some(NativeSyncRange {
            from_height: 128,
            to_height: 384,
        }),
    ));
    assert!(node.begin_outbound_sync_request(Some(peer), range));
}

#[test]
fn stale_native_sync_response_is_dropped_before_import() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    for _ in 0..2 {
        mine_empty_native_block(&node);
    }
    let best = node.best_meta();

    assert!(native_sync_response_stale_for_local_tip(
        &node,
        best.height,
        &[]
    ));
    assert!(native_sync_response_stale_for_local_tip(
        &node,
        best.height,
        std::slice::from_ref(&best)
    ));

    let mut better_same_height = best.clone();
    better_same_height.hash = [0x7a; 32];
    better_same_height.cumulative_work = [0xff; 48];
    assert!(!native_sync_response_stale_for_local_tip(
        &node,
        best.height,
        &[better_same_height]
    ));

    assert!(!native_sync_response_stale_for_local_tip(
        &node,
        best.height + 1,
        &[]
    ));
}

#[test]
fn seeded_mining_gate_rejects_unverified_or_ahead_known_sync_evidence() {
    assert_eq!(
        native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
            verified_new_progress: false,
            verified_known_at_or_below_local_best: false,
            local_best_height: 10,
            peer_best_height: 10,
            stopped_on_error: false,
        }),
        None
    );
    assert_eq!(
        native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
            verified_new_progress: false,
            verified_known_at_or_below_local_best: true,
            local_best_height: 10,
            peer_best_height: 10,
            stopped_on_error: false,
        }),
        Some(10)
    );
    assert_eq!(
        native_mining_sync_observed_peer_height(NativeMiningSyncEvidenceInput {
            verified_new_progress: false,
            verified_known_at_or_below_local_best: true,
            local_best_height: 10,
            peer_best_height: 9,
            stopped_on_error: false,
        }),
        Some(10)
    );
}

#[test]
fn native_sync_response_range_caps_overwide_response_with_bounded_request_item_facts() {
    let range = native_sync_response_range(NativeSyncResponseRangeInput {
        from_height: 0,
        to_height: u64::MAX,
        best_height: MAX_NATIVE_SYNC_RESPONSE_BLOCKS + 100,
        max_blocks: MAX_NATIVE_SYNC_RESPONSE_BLOCKS,
    })
    .expect("overwide request should still produce a capped range");
    assert_eq!(range.from_height, 0);
    assert_eq!(range.to_height, MAX_NATIVE_SYNC_RESPONSE_BLOCKS - 1);

    let range_count =
        usize::try_from(range.to_height - range.from_height + 1).expect("range count");
    assert_eq!(range_count, MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE);
    assert_eq!(
        evaluate_native_bounded_request_admission(NativeBoundedRequestAdmissionInput {
            raw_byte_cap: usize::MAX,
            decoded_byte_cap: usize::MAX,
            item_count_cap: MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE,
            item_byte_cap: usize::MAX,
            aggregate_byte_cap: usize::MAX,
            work_unit_cap: usize::MAX,
            raw_bytes: 0,
            decoded_bytes: 0,
            item_count: range_count,
            max_item_bytes: 0,
            aggregate_bytes: 0,
            work_units: 0,
        }),
        Ok(())
    );
}

#[test]
fn block_range_rejects_missing_canonical_height_inside_admitted_range() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let first = mine_empty_native_block(&node);
    let second = mine_empty_native_block(&node);
    assert_eq!(first.height, 1);
    assert_eq!(second.height, 2);

    node.height_tree
        .remove(height_key(1))
        .expect("remove height index");
    node.height_tree.flush().expect("flush height tree");

    let err = node
        .block_range(0, 2)
        .expect_err("missing admitted canonical height must reject sync range");
    assert!(err.to_string().contains("missing canonical height index"));
}

#[test]
fn block_range_rejects_missing_header_inside_admitted_range() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let first = mine_empty_native_block(&node);
    let second = mine_empty_native_block(&node);
    assert_eq!(second.height, 2);

    node.block_tree
        .remove(first.hash.as_slice())
        .expect("remove block record");
    node.block_tree.flush().expect("flush block tree");

    let err = node
        .block_range(0, 2)
        .expect_err("missing admitted block record must reject sync range");
    assert!(err.to_string().contains("missing native block record"));
}

#[test]
fn block_range_rejects_height_index_pointing_to_wrong_header() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let first = mine_empty_native_block(&node);
    let second = mine_empty_native_block(&node);
    assert_eq!(first.height, 1);
    assert_eq!(second.height, 2);

    node.height_tree
        .insert(height_key(1), second.hash.as_slice())
        .expect("forge height index");
    node.height_tree.flush().expect("flush height tree");

    let err = node
        .block_range(0, 2)
        .expect_err("wrong admitted block metadata must reject sync range");
    assert!(err
        .to_string()
        .contains("points to block metadata at height 2"));
}

#[test]
fn block_range_rejects_corrupt_canonical_action_body_inside_admitted_range() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let first = mine_empty_native_block(&node);
    let second = mine_empty_native_block(&node);
    assert_eq!(first.height, 1);
    assert_eq!(second.height, 2);

    let mut corrupted = first.clone();
    corrupted.action_bytes.push(vec![0xaa]);
    let encoded = bincode::serialize(&corrupted).expect("serialize corrupted block body");
    node.block_tree
        .insert(first.hash.as_slice(), encoded)
        .expect("replace canonical block body");
    node.block_tree.flush().expect("flush block tree");

    let err = node
        .block_range(0, 2)
        .expect_err("corrupt canonical action body must reject sync range");
    let err = format!("{err:?}");
    assert!(
        err.contains("validate canonical native sync block body"),
        "{err}"
    );
    assert!(err.contains("block action payload count mismatch"), "{err}");
}

#[test]
fn block_range_rejects_exact_decodable_action_byte_drift_inside_admitted_range() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let node = NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "safe", false)).expect("node");
    let subsidy = consensus::reward::block_subsidy(1);
    stage_test_coinbase(&node, subsidy, [41u8; 48]);
    let work = node.prepare_work().expect("prepare coinbase native work");
    let seal = mine_native_round(work.clone(), 0).expect("coinbase native seal");
    let first = node
        .import_mined_block(&work, seal)
        .expect("coinbase native import")
        .expect("coinbase native block");
    assert_eq!(first.height, 1);
    assert_eq!(first.tx_count, 1);

    let substitute = test_coinbase_action_with_seed(subsidy, [92u8; 32]);
    let mut corrupted = first.clone();
    replace_single_action_body_with_exact_decodable_substitute(&mut corrupted, &substitute);
    let encoded = bincode::serialize(&corrupted).expect("serialize corrupted block body");
    node.block_tree
        .insert(first.hash.as_slice(), encoded)
        .expect("replace canonical block body");
    node.block_tree.flush().expect("flush block tree");

    let err = node
        .block_range(0, 1)
        .expect_err("exact-decodable canonical action-byte drift must reject sync range");
    let err = format!("{err:?}");
    assert!(
        err.contains("validate canonical native sync block body"),
        "{err}"
    );
    assert!(
        err.contains("canonical native sync block action root"),
        "{err}"
    );
    assert!(err.contains("extrinsics_root_mismatch"), "{err}");
    assert_eq!(node.best_meta().hash, first.hash);
}

#[test]
fn imported_block_actions_reject_hash_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [21u8; 48], [121u8; 48], 0);
    action.tx_hash[0] ^= 1;

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("mutated action hash should fail admission");
    assert!(err.to_string().contains("block action hash mismatch"));
}

#[test]
fn imported_block_actions_reject_duplicate_hashes() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [22u8; 48], [122u8; 48], 0);

    let err = validate_block_actions_locked(&state, &[action.clone(), action])
        .expect_err("duplicate action hash should fail admission");
    assert!(err.to_string().contains("duplicate action in block"));
}

#[test]
fn semantic_action_hash_ignores_received_time_for_duplicate_policy() {
    let first = test_outbound_bridge_action(b"same outbound body");
    let mut second = first.clone();
    second.received_ms = first.received_ms.saturating_add(42);
    second.tx_hash = pending_action_hash(&second);

    assert_ne!(first.tx_hash, second.tx_hash);
    assert_eq!(
        pending_action_semantic_hash(&first),
        pending_action_semantic_hash(&second)
    );
}

#[test]
fn imported_block_actions_reject_semantic_duplicate_with_different_received_time() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let first = test_outbound_bridge_action(b"same semantic outbound body");
    let mut second = first.clone();
    second.received_ms = first.received_ms.saturating_add(1);
    second.tx_hash = pending_action_hash(&second);
    assert_ne!(first.tx_hash, second.tx_hash);

    let err = validate_block_actions_locked(&state, &[first, second])
        .expect_err("semantic duplicate must fail even when tx_hash differs");
    assert!(err.to_string().contains("duplicate semantic action"));
}

#[test]
fn decode_block_actions_rejects_action_count_mismatch() {
    let pow_bits = 0x207f_ffff;
    let mut block = genesis_meta(pow_bits).expect("genesis");
    block.tx_count = 1;

    let err = decode_block_actions(&block).expect_err("count mismatch should fail admission");
    assert!(err
        .to_string()
        .contains("block action payload count mismatch"));
}

#[test]
fn block_action_byte_budget_rejects_count_item_and_aggregate_caps() {
    let err = validate_block_action_byte_budget(
        (MAX_NATIVE_BLOCK_ACTIONS + 1) as u32,
        0,
        std::iter::empty(),
    )
    .expect_err("declared block action count over cap must reject before decode");
    assert!(err.to_string().contains("block action count exceeds limit"));

    let err = validate_block_action_byte_budget(1, 1, [MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES + 1])
        .expect_err("single block action payload over cap must reject before decode");
    assert!(err
        .to_string()
        .contains("block action payload exceeds per-action limit"));

    let item_len = MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES;
    let item_count = (MAX_NATIVE_BLOCK_ACTION_BYTES / item_len) + 1;
    let err = validate_block_action_byte_budget(
        item_count as u32,
        item_count,
        std::iter::repeat_n(item_len, item_count),
    )
    .expect_err("aggregate block action bytes over cap must reject before decode");
    assert!(err
        .to_string()
        .contains("block action bytes exceed aggregate limit"));
}

#[test]
fn block_action_byte_budget_rejects_oversized_payload_before_decode() {
    let pow_bits = 0x207f_ffff;
    let mut block = genesis_meta(pow_bits).expect("genesis");
    block.tx_count = 1;
    block.action_bytes = vec![vec![0u8; MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES + 1]];

    let err = decode_block_actions(&block)
        .expect_err("oversized block action payload must reject before SCALE decode");
    let message = err.to_string();
    assert!(message.contains("block action payload exceeds per-action limit"));
    assert!(!message.contains("decode native block action failed"));
}

#[test]
fn decode_block_actions_rejects_action_hash_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [23u8; 48], [123u8; 48], 0);
    action.tx_hash[0] ^= 1;

    let mut block = genesis_meta(pow_bits).expect("genesis");
    block.tx_count = 1;
    block.action_bytes = vec![action.encode()];

    let err = decode_block_actions(&block).expect_err("mutated action hash should fail admission");
    assert!(err.to_string().contains("block action hash mismatch"));
}

#[test]
fn decode_block_actions_rejects_duplicate_hashes() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [24u8; 48], [124u8; 48], 0);

    let mut block = genesis_meta(pow_bits).expect("genesis");
    block.tx_count = 2;
    block.action_bytes = vec![action.encode(), action.encode()];

    let err =
        decode_block_actions(&block).expect_err("duplicate action hash should fail admission");
    assert!(err.to_string().contains("duplicate action in block"));
}

#[test]
fn load_pending_actions_accepts_valid_hash_binding() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("pending_actions")
        .expect("pending action tree");
    let action = test_outbound_bridge_action(b"persisted pending action");
    tree.insert(action.tx_hash.as_slice(), action.encode())
        .expect("insert pending action");

    let loaded = load_pending_actions(&tree).expect("load pending actions");
    let loaded_action = loaded.get(&action.tx_hash).expect("loaded action");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded_action.tx_hash, action.tx_hash);
    assert_eq!(pending_action_hash(loaded_action), action.tx_hash);
}

#[test]
fn load_pending_actions_rejects_malformed_key() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("pending_actions")
        .expect("pending action tree");
    let action = test_outbound_bridge_action(b"persisted malformed key");
    tree.insert([7u8; 31], action.encode())
        .expect("insert malformed pending action key");

    let err = load_pending_actions(&tree).expect_err("malformed pending action key must reject");
    assert!(err
        .to_string()
        .contains("stored pending action key has invalid length"));
}

#[test]
fn load_pending_actions_rejects_key_hash_mismatch() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("pending_actions")
        .expect("pending action tree");
    let action = test_outbound_bridge_action(b"persisted wrong key");
    let mut wrong_key = action.tx_hash;
    wrong_key[0] ^= 0x80;
    tree.insert(wrong_key.as_slice(), action.encode())
        .expect("insert mismatched pending action");

    let err =
        load_pending_actions(&tree).expect_err("stored action under the wrong key must reject");
    assert!(err
        .to_string()
        .contains("stored pending action key/hash mismatch"));
}

#[test]
fn load_pending_actions_rejects_stale_embedded_hash() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("pending_actions")
        .expect("pending action tree");
    let mut action = test_outbound_bridge_action(b"persisted stale body");
    let key = action.tx_hash;
    action.received_ms = action.received_ms.saturating_add(1);
    tree.insert(key.as_slice(), action.encode())
        .expect("insert stale pending action");

    let err = load_pending_actions(&tree)
        .expect_err("stored action with stale embedded hash must reject");
    assert!(err
        .to_string()
        .contains("stored pending action hash mismatch"));
}

#[test]
fn load_pending_actions_rejects_semantic_duplicate_received_time() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("pending_actions")
        .expect("pending action tree");
    let first = test_outbound_bridge_action(b"persisted duplicate semantic body");
    let mut second = first.clone();
    second.received_ms = first.received_ms.saturating_add(1);
    second.tx_hash = pending_action_hash(&second);
    assert_ne!(first.tx_hash, second.tx_hash);
    assert_eq!(
        pending_action_semantic_hash(&first),
        pending_action_semantic_hash(&second)
    );
    tree.insert(first.tx_hash.as_slice(), first.encode())
        .expect("insert first pending action");
    tree.insert(second.tx_hash.as_slice(), second.encode())
        .expect("insert second pending action");

    let err = load_pending_actions(&tree)
        .expect_err("semantic duplicate persisted pending action must reject");
    assert!(err
        .to_string()
        .contains("duplicate semantic stored pending action"));
}

#[test]
fn load_staged_sizes_accepts_hash_bound_ciphertext() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("staged_ciphertexts")
        .expect("staged ciphertext tree");
    let raw = vec![1u8, 2, 3, 4, 5];
    let hash = ciphertext_hash_bytes(&raw);
    tree.insert(hash.as_slice(), raw.as_slice())
        .expect("insert staged ciphertext");

    let loaded = load_staged_sizes(&db, &tree).expect("load staged ciphertext sizes");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.get(&hex48(&hash)), Some(&(raw.len() as u32)));
    assert!(tree
        .get(hash.as_slice())
        .expect("read ciphertext")
        .is_some());
}

#[test]
fn load_staged_sizes_drops_hash_mismatch() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("staged_ciphertexts")
        .expect("staged ciphertext tree");
    let raw = vec![1u8, 2, 3];
    let wrong_hash = [9u8; 48];
    assert_ne!(ciphertext_hash_bytes(&raw), wrong_hash);
    tree.insert(wrong_hash.as_slice(), raw.as_slice())
        .expect("insert mismatched staged ciphertext");

    let loaded = load_staged_sizes(&db, &tree).expect("load staged ciphertext sizes");

    assert!(loaded.is_empty());
    assert!(tree
        .get(wrong_hash.as_slice())
        .expect("read dropped ciphertext")
        .is_none());
}

#[test]
fn load_staged_sizes_drops_hash_mismatch_across_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let raw = vec![1u8, 2, 3];
    let wrong_hash = [9u8; 48];
    assert_ne!(ciphertext_hash_bytes(&raw), wrong_hash);

    {
        let db = sled::Config::new()
            .path(tmp.path())
            .open()
            .expect("sled db");
        let tree = db
            .open_tree("staged_ciphertexts")
            .expect("staged ciphertext tree");
        tree.insert(wrong_hash.as_slice(), raw.as_slice())
            .expect("insert mismatched staged ciphertext");

        let loaded = load_staged_sizes(&db, &tree).expect("load staged ciphertext sizes");
        assert!(loaded.is_empty());
    }

    let db = sled::Config::new()
        .path(tmp.path())
        .open()
        .expect("reopen sled db");
    let tree = db
        .open_tree("staged_ciphertexts")
        .expect("reopen staged ciphertext tree");
    assert!(tree
        .get(wrong_hash.as_slice())
        .expect("read dropped ciphertext after reopen")
        .is_none());
}

#[test]
fn load_staged_sizes_drops_oversized_ciphertext() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("staged_ciphertexts")
        .expect("staged ciphertext tree");
    let raw = vec![7u8; 5];
    let hash = ciphertext_hash_bytes(&raw);
    tree.insert(hash.as_slice(), raw.as_slice())
        .expect("insert oversized staged ciphertext");

    let loaded =
        load_staged_sizes_with_limits(&db, &tree, MAX_NATIVE_STAGED_CIPHERTEXTS, raw.len() - 1)
            .expect("load staged ciphertext sizes");

    assert!(loaded.is_empty());
    assert!(tree
        .get(hash.as_slice())
        .expect("read dropped ciphertext")
        .is_none());
}

#[test]
fn load_staged_sizes_drops_capacity_overflow() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("staged_ciphertexts")
        .expect("staged ciphertext tree");
    let first = vec![1u8];
    let second = vec![2u8];
    let first_hash = ciphertext_hash_bytes(&first);
    let second_hash = ciphertext_hash_bytes(&second);
    tree.insert(first_hash.as_slice(), first.as_slice())
        .expect("insert first staged ciphertext");
    tree.insert(second_hash.as_slice(), second.as_slice())
        .expect("insert second staged ciphertext");

    let loaded = load_staged_sizes_with_limits(&db, &tree, 1, MAX_CIPHERTEXT_BYTES)
        .expect("load staged ciphertext sizes");

    assert_eq!(loaded.len(), 1);
    assert_eq!(tree.len(), 1);
}

#[test]
fn load_staged_proofs_accepts_valid_proof() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("staged_proofs").expect("staged proof tree");
    let (binding_hash, proof) = staged_proof_fixture();
    tree.insert(binding_hash.as_slice(), proof.as_slice())
        .expect("insert staged proof");

    let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded.get(&hex64(&binding_hash)), Some(&proof));
    assert!(tree
        .get(binding_hash.as_slice())
        .expect("read staged proof")
        .is_some());
}

#[test]
fn load_staged_proofs_drops_malformed_key() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("staged_proofs").expect("staged proof tree");
    tree.insert([7u8; 63], [1u8, 2, 3].as_slice())
        .expect("insert malformed proof key");

    let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

    assert!(loaded.is_empty());
    assert_eq!(tree.len(), 0);
}

#[test]
fn load_staged_proofs_drops_empty_proof() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("staged_proofs").expect("staged proof tree");
    let binding_hash = [2u8; 64];
    tree.insert(binding_hash.as_slice(), [].as_slice())
        .expect("insert empty staged proof");

    let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

    assert!(loaded.is_empty());
    assert!(tree
        .get(binding_hash.as_slice())
        .expect("read dropped proof")
        .is_none());
}

#[test]
fn load_staged_proofs_drops_empty_proof_across_reopen() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let binding_hash = [2u8; 64];

    {
        let db = sled::Config::new()
            .path(tmp.path())
            .open()
            .expect("sled db");
        let tree = db.open_tree("staged_proofs").expect("staged proof tree");
        tree.insert(binding_hash.as_slice(), [].as_slice())
            .expect("insert empty staged proof");

        let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");
        assert!(loaded.is_empty());
    }

    let db = sled::Config::new()
        .path(tmp.path())
        .open()
        .expect("reopen sled db");
    let tree = db
        .open_tree("staged_proofs")
        .expect("reopen staged proof tree");
    assert!(tree
        .get(binding_hash.as_slice())
        .expect("read dropped proof after reopen")
        .is_none());
}

#[test]
fn load_staged_proofs_drops_oversized_proof() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("staged_proofs").expect("staged proof tree");
    let (binding_hash, proof) = staged_proof_fixture();
    tree.insert(binding_hash.as_slice(), proof.as_slice())
        .expect("insert oversized staged proof");

    let loaded = load_staged_proofs_with_limits(
        &db,
        &tree,
        MAX_NATIVE_STAGED_PROOFS,
        proof.len() - 1,
        MAX_NATIVE_STAGED_PROOF_BYTES,
    )
    .expect("load staged proofs");

    assert!(loaded.is_empty());
    assert!(tree
        .get(binding_hash.as_slice())
        .expect("read dropped proof")
        .is_none());
}

#[test]
fn load_staged_proofs_drops_binding_hash_mismatch() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("staged_proofs").expect("staged proof tree");
    let (mut binding_hash, proof) = staged_proof_fixture();
    binding_hash[0] ^= 0xff;
    tree.insert(binding_hash.as_slice(), proof.as_slice())
        .expect("insert mismatched staged proof");

    let loaded = load_staged_proofs(&db, &tree).expect("load staged proofs");

    assert!(loaded.is_empty());
    assert!(tree
        .get(binding_hash.as_slice())
        .expect("read dropped proof")
        .is_none());
}

#[test]
fn load_staged_proofs_drops_capacity_overflow() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("staged_proofs").expect("staged proof tree");
    let (binding_hash, proof) = staged_proof_fixture();
    tree.insert(binding_hash.as_slice(), proof.as_slice())
        .expect("insert staged proof");

    let loaded = load_staged_proofs_with_limits(
        &db,
        &tree,
        0,
        NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        MAX_NATIVE_STAGED_PROOF_BYTES,
    )
    .expect("load staged proofs");

    assert!(loaded.is_empty());
    assert!(tree
        .get(binding_hash.as_slice())
        .expect("read dropped proof")
        .is_none());
}

#[test]
fn load_staged_proofs_drops_byte_capacity_overflow() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("staged_proofs").expect("staged proof tree");
    let (binding_hash, proof) = staged_proof_fixture();
    tree.insert(binding_hash.as_slice(), proof.as_slice())
        .expect("insert staged proof");

    let loaded = load_staged_proofs_with_limits(
        &db,
        &tree,
        MAX_NATIVE_STAGED_PROOFS,
        NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE,
        proof.len() - 1,
    )
    .expect("load staged proofs");

    assert!(loaded.is_empty());
    assert!(tree
        .get(binding_hash.as_slice())
        .expect("read dropped proof")
        .is_none());
}

fn staged_proof_fixture() -> ([u8; 64], Vec<u8>) {
    let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/native_backend_vectors/bundle.json");
    let bundle_bytes = std::fs::read(&bundle_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", bundle_path.display()));
    let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
        .unwrap_or_else(|err| panic!("parse {}: {err}", bundle_path.display()));
    let artifact_hex = bundle["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["name"].as_str() == Some("native_tx_leaf_valid"))
        })
        .and_then(|case| case["artifact_hex"].as_str())
        .expect("bundle must contain native_tx_leaf_valid artifact_hex");
    let artifact_bytes =
        hex::decode(artifact_hex).expect("native_tx_leaf_valid artifact hex must decode");
    let decoded =
        consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&artifact_bytes)
            .expect("native_tx_leaf_valid artifact must decode");
    let binding_hash = native_tx_leaf_artifact_binding_hash(&decoded)
        .expect("native_tx_leaf_valid artifact binding hash");
    assert!(native_tx_leaf_artifact_binding_hash_matches_key(
        binding_hash,
        &artifact_bytes
    ));
    (binding_hash, artifact_bytes)
}

fn repartitioned_tx_leaf_binding_alias_fixture() -> ([u8; 64], Vec<u8>) {
    let anchor = [41u8; 48];
    let nullifier = [42u8; 48];
    let commitment = [43u8; 48];
    let ciphertext_hash = [44u8; 48];
    let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
    let fee = 0;
    let stablecoin = None;
    let binding = KernelVersionBinding {
        circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
    };
    let intended = ShieldedTransferInputs {
        anchor,
        nullifiers: vec![nullifier],
        commitments: vec![commitment],
        ciphertext_hashes: vec![ciphertext_hash],
        balance_slot_asset_ids,
        fee,
        value_balance: 0,
        stablecoin: stablecoin.clone(),
    };
    let intended_binding_hash = StarkVerifier::compute_binding_hash(&intended).data;
    let alias_bytes = test_repartitioned_transfer_proof_alias(
        anchor,
        nullifier,
        commitment,
        ciphertext_hash,
        balance_slot_asset_ids,
        fee,
        stablecoin,
        binding,
    );
    assert!(
        !native_tx_leaf_artifact_binding_hash_matches_key(intended_binding_hash, &alias_bytes),
        "length-tagged binding hash must reject repartitioned tx-leaf public fields"
    );
    (intended_binding_hash, alias_bytes)
}

#[test]
fn canonical_state_reload_accepts_contiguous_commitments() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("commitments").expect("commitment tree");
    let first = [1u8; 48];
    let second = [2u8; 48];
    tree.insert(0u64.to_be_bytes(), first.as_slice())
        .expect("insert first commitment");
    tree.insert(1u64.to_be_bytes(), second.as_slice())
        .expect("insert second commitment");
    let expected = CommitmentTreeState::from_leaves(
        COMMITMENT_TREE_DEPTH,
        consensus::DEFAULT_ROOT_HISTORY_LIMIT,
        vec![first, second],
    )
    .expect("expected commitment tree");

    let loaded = load_commitment_tree(&tree).expect("load commitment tree");

    assert_eq!(loaded.leaf_count(), 2);
    assert_eq!(loaded.root(), expected.root());
}

#[test]
fn canonical_state_reload_rejects_malformed_commitment_key() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("commitments").expect("commitment tree");
    tree.insert(b"bad-key", [1u8; 48].as_slice())
        .expect("insert malformed commitment key");

    let err = load_commitment_tree(&tree).expect_err("malformed commitment key must fail reload");

    assert!(err
        .to_string()
        .contains("stored commitment key has invalid length"));
}

#[test]
fn canonical_state_reload_rejects_malformed_commitment_value() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("commitments").expect("commitment tree");
    tree.insert(0u64.to_be_bytes(), [1u8; 47].as_slice())
        .expect("insert malformed commitment value");

    let err = load_commitment_tree(&tree).expect_err("malformed commitment value must fail reload");

    assert!(err
        .to_string()
        .contains("stored commitment value has invalid length"));
}

#[test]
fn canonical_state_reload_rejects_commitment_index_gap() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("commitments").expect("commitment tree");
    tree.insert(1u64.to_be_bytes(), [1u8; 48].as_slice())
        .expect("insert commitment at nonzero index");

    let err = load_commitment_tree(&tree).expect_err("commitment index gap must fail reload");

    assert!(err
        .to_string()
        .contains("stored commitment index is not contiguous"));
}

#[test]
fn canonical_state_reload_rejects_commitment_root_mismatch_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.commitment_tree
        .insert(0u64.to_be_bytes(), [3u8; 48].as_slice())
        .expect("insert forged commitment");
    node.commitment_tree.flush().expect("flush commitment tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("commitment root mismatch must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored commitment tree root mismatch"));
}

#[test]
fn canonical_state_reload_rejects_malformed_nullifier_key_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.nullifier_tree
        .insert(b"bad-nullifier-key".as_slice(), b"1")
        .expect("insert malformed nullifier key");
    node.nullifier_tree.flush().expect("flush nullifier tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("malformed nullifier key must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored nullifier key has invalid length"));
}

#[test]
fn canonical_state_reload_rejects_invalid_nullifier_marker_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.nullifier_tree
        .insert([5u8; 48].as_slice(), b"bad")
        .expect("insert invalid nullifier marker");
    node.nullifier_tree.flush().expect("flush nullifier tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("invalid nullifier marker must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored nullifier marker is invalid"));
}

#[test]
fn canonical_state_reload_rejects_nullifier_root_mismatch_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.nullifier_tree
        .insert([4u8; 48].as_slice(), b"1")
        .expect("insert forged nullifier");
    node.nullifier_tree.flush().expect("flush nullifier tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("nullifier root mismatch must fail startup"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("stored nullifier root mismatch"));
}

#[test]
fn block_index_reload_rejects_missing_best_block_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let best = node.best_meta();
    node.block_tree
        .remove(best.hash.as_slice())
        .expect("remove best block record");
    node.block_tree.flush().expect("flush block tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("missing best block record must fail startup"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("missing native block"));
}

#[test]
fn block_index_reload_rejects_best_metadata_mismatch_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let mut forged_best = node.best_meta();
    forged_best.timestamp_ms = forged_best.timestamp_ms.saturating_add(1);
    node.meta_tree
        .insert(
            META_BEST_KEY,
            bincode::serialize(&forged_best)
                .expect("serialize forged best")
                .as_slice(),
        )
        .expect("insert forged best metadata");
    node.meta_tree.flush().expect("flush meta tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("best metadata drift must fail startup"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("stored best metadata mismatch"));
}

#[test]
fn block_index_reload_rejects_height_hash_mismatch_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.height_tree
        .insert(height_key(0), [7u8; 32].as_slice())
        .expect("insert forged height hash");
    node.height_tree.flush().expect("flush height tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("height hash mismatch must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored canonical height hash mismatch"));
}

#[test]
fn block_index_reload_rejects_extra_height_index_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.height_tree
        .insert(height_key(1), [8u8; 32].as_slice())
        .expect("insert extra height index");
    node.height_tree.flush().expect("flush height tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("extra height index must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored extra canonical height index"));
}

#[test]
fn block_index_reload_rejects_malformed_height_key_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.height_tree
        .insert(b"bad-key", [9u8; 32].as_slice())
        .expect("insert malformed height key");
    node.height_tree.flush().expect("flush height tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("malformed height key must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored canonical height key has invalid length"));
}

#[test]
fn block_index_reload_rejects_non_contiguous_parent_height_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let genesis = node.best_meta();
    let mut child = mined_empty_child(&genesis, 1, pow_bits, 0);
    child.height = 2;
    persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
        .expect("persist non-contiguous child");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("non-contiguous canonical height must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored canonical block height mismatch"));
}

#[test]
fn block_index_reload_repairs_missing_genesis_marker_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.meta_tree
        .remove(META_GENESIS_KEY)
        .expect("remove genesis marker");
    node.meta_tree.flush().expect("flush meta tree");
    drop(node);

    let reopened = NativeNode::open(config).expect("missing genesis marker should repair");
    let expected = genesis_meta(pow_bits).expect("genesis");
    let marker = reopened
        .meta_tree
        .get(META_GENESIS_KEY)
        .expect("read genesis marker")
        .expect("genesis marker restored");

    assert_eq!(marker.as_ref(), expected.hash.as_slice());
}

#[test]
fn block_index_reload_rejects_short_genesis_marker_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.meta_tree
        .insert(META_GENESIS_KEY, [1u8; 31].as_slice())
        .expect("insert short genesis marker");
    node.meta_tree.flush().expect("flush meta tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("short genesis marker must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored native genesis marker has invalid length"));
}

#[test]
fn block_index_reload_rejects_genesis_marker_mismatch_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.meta_tree
        .insert(META_GENESIS_KEY, [2u8; 32].as_slice())
        .expect("insert mismatched genesis marker");
    node.meta_tree.flush().expect("flush meta tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("mismatched genesis marker must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored native genesis marker mismatch"));
}

#[test]
fn bridge_replay_reload_rejects_malformed_key_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.bridge_inbound_tree
        .insert(b"bad-key", b"1")
        .expect("insert malformed bridge replay key");
    node.bridge_inbound_tree
        .flush()
        .expect("flush bridge replay tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("malformed bridge replay key must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored bridge replay key has invalid length"));
}

#[test]
fn bridge_replay_reload_rejects_invalid_marker_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.bridge_inbound_tree
        .insert([9u8; 48].as_slice(), b"0")
        .expect("insert invalid bridge replay marker");
    node.bridge_inbound_tree
        .flush()
        .expect("flush bridge replay tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("invalid bridge replay marker must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored bridge replay marker is invalid"));
}

#[test]
fn bridge_replay_reload_rejects_extra_consumed_key_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = test_config(tmp.path(), 0x207f_ffff, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    node.bridge_inbound_tree
        .insert([10u8; 48].as_slice(), b"1")
        .expect("insert extra bridge replay key");
    node.bridge_inbound_tree
        .flush()
        .expect("flush bridge replay tree");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("extra bridge replay key must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored bridge replay set mismatch"));
    assert!(err.to_string().contains("first_extra"));
}

#[test]
fn bridge_replay_reload_rejects_missing_consumed_key_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let genesis = node.best_meta();
    let action = test_inbound_bridge_action(b"startup replay reload");
    let child = mined_child_with_actions(&genesis, 1, pow_bits, 0, vec![action]);
    persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &child)
        .expect("persist crafted inbound bridge block");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("missing bridge replay key must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("stored bridge replay set mismatch"));
    assert!(err.to_string().contains("first_missing"));
}

#[test]
fn bridge_replay_reload_rejects_duplicate_canonical_replay_key_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let genesis = node.best_meta();
    let action = test_inbound_bridge_action(b"duplicate startup replay reload");
    let first = mined_child_with_actions(&genesis, 1, pow_bits, 0, vec![action.clone()]);
    let second = mined_child_with_actions(&first, 2, pow_bits, 0, vec![action]);
    persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &first)
        .expect("persist first inbound bridge block");
    persist_block(
        &node.meta_tree,
        &node.height_tree,
        &node.block_tree,
        &second,
    )
    .expect("persist duplicate inbound bridge block");
    drop(node);

    let err = match NativeNode::open(config) {
        Ok(_) => panic!("duplicate canonical bridge replay key must fail startup"),
        Err(err) => err,
    };

    assert!(err
        .to_string()
        .contains("canonical chain contains duplicate inbound bridge replay key"));
}

#[test]
fn pending_action_startup_drops_unknown_anchor_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let action = test_inline_transfer_action([99u8; 48], [101u8; 48], [102u8; 48], 0);
    persist_pending_action_for_startup(&node, &action);
    drop(node);

    let reopened =
        NativeNode::open(config).expect("unknown-anchor pending action should be quarantined");

    assert!(reopened.state.read().pending_actions.is_empty());
    assert_eq!(reopened.action_tree.len(), 0);
}

#[test]
fn pending_action_startup_drops_duplicate_pending_nullifier_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let first = test_inline_transfer_action(anchor, [103u8; 48], [104u8; 48], 0);
    let second = test_inline_transfer_action(anchor, [103u8; 48], [105u8; 48], 0);
    persist_pending_action_for_startup(&node, &first);
    persist_pending_action_for_startup(&node, &second);
    drop(node);

    let reopened =
        NativeNode::open(config).expect("duplicate pending nullifier should quarantine one action");

    assert_eq!(reopened.state.read().pending_actions.len(), 1);
    assert_eq!(reopened.action_tree.len(), 1);
}

#[test]
fn pending_action_startup_drops_disabled_risc0_inbound_bridge_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let action =
        test_disabled_risc0_inbound_bridge_action(b"startup disabled RISC0 inbound bridge");
    persist_pending_action_for_startup(&node, &action);
    drop(node);

    let reopened = NativeNode::open(config)
        .expect("disabled RISC Zero inbound bridge action should be quarantined");

    assert!(reopened.state.read().pending_actions.is_empty());
    assert_eq!(reopened.action_tree.len(), 0);
}

#[test]
fn pending_action_startup_drops_sidecar_transfer_without_reloaded_ciphertext_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_sidecar_transfer_action(anchor, [106u8; 48], [107u8; 48], 0);
    persist_pending_action_for_startup(&node, &action);
    drop(node);

    let reopened = NativeNode::open(config)
        .expect("sidecar pending action without ciphertext should be quarantined");

    assert!(reopened.state.read().pending_actions.is_empty());
    assert_eq!(reopened.action_tree.len(), 0);
}

#[test]
fn pending_action_startup_accepts_sidecar_transfer_with_matching_reloaded_ciphertext_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_sidecar_transfer_action(anchor, [108u8; 48], [109u8; 48], 0);
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
    persist_pending_action_for_startup(&node, &action);
    drop(node);

    let reopened = NativeNode::open(config)
        .expect("sidecar pending action with reloaded ciphertext should pass startup");
    assert!(reopened
        .state
        .read()
        .pending_actions
        .contains_key(&action.tx_hash));
}

#[test]
fn pending_action_startup_keeps_transfer_and_drops_stale_candidate_on_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "safe", false);
    let node = NativeNode::open(config.clone()).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let transfer = test_inline_transfer_action(anchor, [110u8; 48], [111u8; 48], 0);
    let candidate = test_candidate_artifact_action(1, 112);
    persist_pending_action_for_startup(&node, &candidate);
    persist_pending_action_for_startup(&node, &transfer);
    drop(node);

    let reopened = NativeNode::open(config)
        .expect("startup should quarantine stale candidates but keep transfers");
    let state = reopened.state.read();
    assert!(state.pending_actions.contains_key(&transfer.tx_hash));
    assert!(!state.pending_actions.contains_key(&candidate.tx_hash));
    assert_eq!(state.pending_actions.len(), 1);
    drop(state);
    assert!(reopened
        .action_tree
        .get(candidate.tx_hash.as_slice())
        .expect("read candidate action")
        .is_none());
    assert!(reopened
        .action_tree
        .get(transfer.tx_hash.as_slice())
        .expect("read transfer action")
        .is_some());
}

#[test]
fn pending_action_startup_drops_mempool_byte_budget_with_small_limit() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let action = test_outbound_bridge_action(b"startup byte budget");
    let max_bytes = pending_action_mempool_bytes(&action).saturating_sub(1);
    let mut pending_actions = BTreeMap::new();
    pending_actions.insert(action.tx_hash, action);
    let (db, action_tree) = temporary_action_tree_with_pending(&pending_actions);

    let startup = build_validated_startup_state_with_limits(
        &db,
        &action_tree,
        state.best.clone(),
        state.header_mmr_peaks.clone(),
        pending_actions,
        state.commitment_tree,
        state.nullifiers,
        state.consumed_bridge_messages,
        state.staged_ciphertexts,
        state.staged_proofs,
        false,
        MAX_NATIVE_MEMPOOL_ACTIONS,
        max_bytes,
    )
    .expect("startup pending action byte budget should quarantine over-budget action");

    assert!(startup.pending_actions.is_empty());
    assert_eq!(action_tree.len(), 0);
}

#[test]
fn pending_action_startup_drops_mempool_count_with_small_limit() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let action = test_outbound_bridge_action(b"startup count budget");
    let mut pending_actions = BTreeMap::new();
    pending_actions.insert(action.tx_hash, action);
    let (db, action_tree) = temporary_action_tree_with_pending(&pending_actions);

    let startup = build_validated_startup_state_with_limits(
        &db,
        &action_tree,
        state.best.clone(),
        state.header_mmr_peaks.clone(),
        pending_actions,
        state.commitment_tree,
        state.nullifiers,
        state.consumed_bridge_messages,
        state.staged_ciphertexts,
        state.staged_proofs,
        false,
        0,
        MAX_NATIVE_MEMPOOL_ACTION_BYTES,
    )
    .expect("startup pending action count budget should quarantine over-count action");

    assert!(startup.pending_actions.is_empty());
    assert_eq!(action_tree.len(), 0);
}

#[test]
fn imported_block_actions_recompute_binding_hash() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [3u8; 48], [33u8; 48], 0);
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    args.binding_hash = [99u8; 64];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("mismatched binding hash should fail");
    assert!(err.to_string().contains("binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_inline_proof_binding_hash_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [30u8; 48], [130u8; 48], 0);
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    let (_, wrong_proof) = staged_proof_fixture();
    args.proof = wrong_proof;
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("misbound inline proof must fail transfer payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_sidecar_proof_binding_hash_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_sidecar_transfer_action(anchor, [31u8; 48], [131u8; 48], 0);
    let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
        .expect("decode test args");
    let (_, wrong_proof) = staged_proof_fixture();
    args.proof = wrong_proof;
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("misbound sidecar proof must fail transfer payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_inline_repartitioned_tx_leaf_binding_alias() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [32u8; 48], [132u8; 48], 0);
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    args.proof = test_repartitioned_transfer_proof_alias(
        anchor,
        action.nullifiers[0],
        action.commitments[0],
        action.ciphertext_hashes[0],
        args.balance_slot_asset_ids,
        args.fee,
        args.stablecoin.clone(),
        action.binding,
    );
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("repartitioned inline proof must fail transfer payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_inline_value_balance_binding_alias() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [36u8; 48], [136u8; 48], 0);
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    args.proof = test_transfer_proof_artifact_with_value_balance(
        anchor,
        &action.nullifiers,
        &action.commitments,
        &action.ciphertext_hashes,
        args.balance_slot_asset_ids,
        args.fee,
        29,
        args.stablecoin.clone(),
        action.binding,
    );
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("inline proof with aliased value balance must fail payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_sidecar_repartitioned_tx_leaf_binding_alias() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_sidecar_transfer_action(anchor, [33u8; 48], [133u8; 48], 0);
    let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
        .expect("decode test args");
    args.proof = test_repartitioned_transfer_proof_alias(
        anchor,
        action.nullifiers[0],
        action.commitments[0],
        action.ciphertext_hashes[0],
        args.balance_slot_asset_ids,
        args.fee,
        args.stablecoin.clone(),
        action.binding,
    );
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("repartitioned sidecar proof must fail transfer payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_sidecar_value_balance_binding_alias() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_sidecar_transfer_action(anchor, [37u8; 48], [137u8; 48], 0);
    let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
        .expect("decode test args");
    args.proof = test_transfer_proof_artifact_with_value_balance(
        anchor,
        &action.nullifiers,
        &action.commitments,
        &action.ciphertext_hashes,
        args.balance_slot_asset_ids,
        args.fee,
        29,
        args.stablecoin.clone(),
        action.binding,
    );
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("sidecar proof with aliased value balance must fail payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_inline_stablecoin_proof_binding_alias() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action_with_stablecoin(
        anchor,
        [38u8; 48],
        [138u8; 48],
        0,
        Some(test_stablecoin_policy_binding(10)),
    );
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    args.proof = test_transfer_proof_artifact(
        anchor,
        &action.nullifiers,
        &action.commitments,
        &action.ciphertext_hashes,
        args.balance_slot_asset_ids,
        args.fee,
        Some(test_stablecoin_policy_binding(11)),
        action.binding,
    );
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("inline proof with aliased stablecoin payload must fail payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_rejects_sidecar_stablecoin_proof_binding_alias() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_sidecar_transfer_action_with_stablecoin(
        anchor,
        [39u8; 48],
        [139u8; 48],
        0,
        Some(test_stablecoin_policy_binding(10)),
    );
    let mut args = ShieldedTransferSidecarArgs::decode(&mut &action.public_args[..])
        .expect("decode test args");
    args.proof = test_transfer_proof_artifact(
        anchor,
        &action.nullifiers,
        &action.commitments,
        &action.ciphertext_hashes,
        args.balance_slot_asset_ids,
        args.fee,
        Some(test_stablecoin_policy_binding(11)),
        action.binding,
    );
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("sidecar proof with aliased stablecoin payload must fail payload admission");
    assert!(err.to_string().contains("proof binding hash mismatch"));
}

#[test]
fn transfer_action_accepts_stablecoin_bound_inline_proof() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let binding = test_stablecoin_policy_binding(10);
    authorize_test_stablecoin_policy(&mut state, &binding);
    let action = test_inline_transfer_action_with_stablecoin(
        anchor,
        [34u8; 48],
        [134u8; 48],
        0,
        Some(binding),
    );

    validate_block_actions_locked(&state, &[action])
        .expect("stablecoin-bound inline transfer should pass action validation");
}

#[test]
fn transfer_action_rejects_unauthorized_stablecoin_policy_in_block() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_inline_transfer_action_with_stablecoin(
        anchor,
        [58u8; 48],
        [158u8; 48],
        0,
        Some(test_stablecoin_policy_binding(10)),
    );

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("unauthorized stablecoin policy must fail block validation");
    assert!(err.to_string().contains("stablecoin policy unauthorized"));
}

#[test]
fn transfer_action_rejects_unauthorized_stablecoin_sidecar_policy_in_block() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_sidecar_transfer_action_with_stablecoin(
        anchor,
        [61u8; 48],
        [161u8; 48],
        0,
        Some(test_stablecoin_policy_binding(10)),
    );

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("unauthorized stablecoin sidecar policy must fail block validation");
    assert!(err.to_string().contains("stablecoin policy unauthorized"));
}

#[test]
fn block_artifact_binding_rejects_decoded_stablecoin_public_field_mismatch() {
    let anchor = [44u8; 48];
    let action_stablecoin = test_stablecoin_policy_binding(11);
    let decoded_stablecoin = test_stablecoin_policy_binding(12);
    let action = test_inline_transfer_action_with_stablecoin(
        anchor,
        [35u8; 48],
        [135u8; 48],
        3,
        Some(action_stablecoin),
    );
    let args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    let proof = test_transfer_proof_artifact(
        anchor,
        &action.nullifiers,
        &action.commitments,
        &action.ciphertext_hashes,
        args.balance_slot_asset_ids,
        args.fee,
        Some(decoded_stablecoin),
        action.binding,
    );
    let decoded = consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&proof)
        .expect("decode native tx-leaf artifact");
    let tx = Transaction {
        id: [0u8; 32],
        nullifiers: decoded.tx.nullifiers.clone(),
        commitments: decoded.tx.commitments.clone(),
        balance_tag: decoded.tx.balance_tag,
        version: decoded.tx.version,
        ciphertexts: Vec::new(),
        ciphertext_hashes: decoded.tx.ciphertext_hashes.clone(),
    };
    let input = native_tx_leaf_action_binding_admission_input(&decoded, &action, &tx);

    assert_eq!(
        evaluate_native_tx_leaf_action_binding_admission(input)
            .expect_err("decoded stablecoin payload mismatch must reject")
            .label(),
        "stablecoin_payload_mismatch"
    );
}

#[test]
fn transfer_action_rejects_missing_inline_proof() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [34u8; 48], [35u8; 48], 0);
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    args.proof.clear();
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("missing inline proof must fail transfer payload admission");
    assert!(err.to_string().contains("missing proof"));
}

#[test]
fn transfer_action_rejects_oversized_inline_proof() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [36u8; 48], [37u8; 48], 0);
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    args.proof = vec![0x44u8; NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE + 1];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("oversized inline proof must fail transfer payload admission");
    assert!(err.to_string().contains("proof size"));
}

#[test]
fn transfer_action_rejects_oversized_inline_ciphertext() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [38u8; 48], [39u8; 48], 0);
    let mut args =
        ShieldedTransferInlineArgs::decode(&mut &action.public_args[..]).expect("decode test args");
    args.ciphertexts[0].kem_ciphertext =
        vec![0x55u8; protocol_shielded_pool::types::MAX_KEM_CIPHERTEXT_LEN as usize + 1];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("oversized inline ciphertext must fail transfer payload admission");
    assert!(err.to_string().contains("inline ciphertext size"));
}

#[test]
fn transfer_action_rejects_inline_fee_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [40u8; 48], [41u8; 48], 7);
    action.fee = 8;
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("action fee must agree with decoded inline payload fee");
    assert!(err.to_string().contains("fee mismatch"));
}

#[test]
fn transfer_state_rejects_unknown_anchor_in_block() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let action = test_inline_transfer_action([99u8; 48], [42u8; 48], [43u8; 48], 0);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("unknown transfer anchor must reject block action");
    assert!(err.to_string().contains("unknown anchor"));
}

#[test]
fn transfer_state_rejects_duplicate_nullifier_in_block() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let first = test_inline_transfer_action(anchor, [44u8; 48], [45u8; 48], 0);
    let second = test_inline_transfer_action(anchor, [44u8; 48], [46u8; 48], 0);
    let mut actions = vec![first, second];
    actions.sort_by_key(action_order_key);

    let err = validate_block_actions_locked(&state, &actions)
        .expect_err("duplicate transfer nullifier must reject block action");
    assert!(err.to_string().contains("duplicate nullifier"));
}

#[test]
fn transfer_nullifier_row_derivation_distinguishes_pending_and_action_duplicates() {
    let nullifier = [47u8; 48];
    let mut pending = BTreeSet::new();
    pending.insert(nullifier);

    let mut mempool_with_prior_pending = NullifierState::new(BTreeSet::new(), pending.clone());
    assert_eq!(
        mempool_transfer_nullifier_admission_state_from_nullifiers(
            &mut mempool_with_prior_pending,
            &[nullifier, nullifier],
        ),
        NativeTransferNullifierAdmissionState::AlreadyPending
    );

    let mut mempool_without_prior_pending = NullifierState::default();
    assert_eq!(
        mempool_transfer_nullifier_admission_state_from_nullifiers(
            &mut mempool_without_prior_pending,
            &[nullifier, nullifier],
        ),
        NativeTransferNullifierAdmissionState::Duplicate
    );

    let mut block_with_prior_pending = NullifierState::new(BTreeSet::new(), pending);
    assert_eq!(
        block_transfer_nullifier_admission_state_from_nullifiers(
            &mut block_with_prior_pending,
            &[nullifier],
        ),
        NativeTransferNullifierAdmissionState::Valid
    );

    let mut block_working_state = NullifierState::default();
    assert_eq!(
        block_transfer_nullifier_admission_state_from_nullifiers(
            &mut block_working_state,
            &[nullifier],
        ),
        NativeTransferNullifierAdmissionState::Valid
    );
    assert_eq!(
        block_transfer_nullifier_admission_state_from_nullifiers(
            &mut block_working_state,
            &[nullifier],
        ),
        NativeTransferNullifierAdmissionState::Duplicate
    );
}

#[test]
fn action_state_effect_rejects_duplicate_before_memory_mutation() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let first = test_inline_transfer_action(anchor, [48u8; 48], [49u8; 48], 0);
    let second = test_inline_transfer_action(anchor, [48u8; 48], [50u8; 48], 0);
    let before_leaf_count = state.commitment_tree.leaf_count();
    let before_root = state.commitment_tree.root();
    let before_nullifiers = state.nullifiers.clone();
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

    let err = apply_actions_to_memory(&da_ciphertext_tree, &mut state, &[first, second])
        .expect_err("duplicate nullifier must reject before memory mutation");
    assert!(err.to_string().contains("duplicate_nullifier"));
    assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
    assert_eq!(state.commitment_tree.root(), before_root);
    assert_eq!(state.nullifiers, before_nullifiers);
}

#[test]
fn action_state_effect_preview_rejects_duplicate_bridge_replay_before_roots() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let first = test_inbound_bridge_action(b"inbound replay one");
    let second = test_inbound_bridge_action(b"inbound replay two");
    assert_ne!(
        first.tx_hash, second.tx_hash,
        "test actions should differ while sharing the replay key"
    );
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

    let err = preview_pending_roots(&da_ciphertext_tree, &state, &[first, second])
        .expect_err("duplicate bridge replay must reject before root preview");
    assert!(err.to_string().contains("bridge_replay_duplicate"));
}

#[test]
fn action_state_effect_preview_requires_materialized_sidecar_ciphertext() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [54u8; 48], [55u8; 48], 0);
    let candidate = test_candidate_artifact_action(1, 56);
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

    let err = preview_pending_roots(&da_ciphertext_tree, &state, &[transfer, candidate])
        .expect_err("sidecar preview must materialize DA ciphertexts");

    assert!(
        err.to_string().contains("missing canonical DA ciphertext"),
        "unexpected preview error: {err}"
    );
}

#[test]
fn action_state_effect_memory_replay_requires_materialized_sidecar_ciphertext() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [57u8; 48], [58u8; 48], 0);
    let candidate = test_candidate_artifact_action(1, 59);
    let before_leaf_count = state.commitment_tree.leaf_count();
    let before_root = state.commitment_tree.root();
    let before_nullifiers = state.nullifiers.clone();
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

    let err = apply_actions_to_memory(&da_ciphertext_tree, &mut state, &[transfer, candidate])
        .expect_err("sidecar memory replay must materialize DA ciphertexts");

    assert!(
        err.to_string().contains("missing canonical DA ciphertext"),
        "unexpected memory replay error: {err}"
    );
    assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
    assert_eq!(state.commitment_tree.root(), before_root);
    assert_eq!(state.nullifiers, before_nullifiers);
}

#[test]
fn block_replay_refinement_rejects_unmaterialized_sidecar_ciphertext() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [60u8; 48], [61u8; 48], 0);
    let candidate = test_candidate_artifact_action(1, 62);
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();

    let err = evaluate_native_block_replay_refinement_for_actions(
        "test replay",
        &da_ciphertext_tree,
        None,
        &state,
        &[transfer, candidate],
        NativeBlockReplayRefinementInput {
            leaf_start: state.commitment_tree.leaf_count(),
            parent_supply: 0,
            height: 1,
            fee_total: 0,
            has_coinbase: false,
            claimed_supply: 0,
            tx_count_matches: true,
            state_root_matches: true,
            kernel_root_matches: true,
            nullifier_root_matches: true,
            extrinsics_root_matches: true,
            message_root_matches: true,
            message_count_matches: true,
            header_mmr_root_matches: true,
            header_mmr_len_matches: true,
        },
    )
    .expect_err("replay refinement must not self-fulfill sidecar ciphertext count");

    assert!(
        err.to_string().contains("missing canonical DA ciphertext"),
        "unexpected replay refinement error: {err}"
    );
}

#[test]
fn block_artifact_binding_rejects_size_mismatched_materialized_sidecar_ciphertext() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut transfer = test_sidecar_transfer_action(anchor, [62u8; 48], [63u8; 48], 0);
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &transfer);
    transfer.ciphertext_sizes[0] = transfer.ciphertext_sizes[0].saturating_add(1);
    let candidate = test_candidate_artifact_action(1, 64);
    let meta = mined_empty_child(&state.best, 1, pow_bits, 0);

    let err = verify_native_block_artifacts_locked(&node, &state, &[transfer, candidate], &meta)
        .expect_err("artifact verification must canonicalize sidecar size metadata");

    assert!(
        err.to_string()
            .contains("canonical DA ciphertext size mismatch"),
        "unexpected artifact verification error: {err}"
    );
}

#[test]
fn block_artifact_binding_rejects_hash_mismatched_materialized_sidecar_ciphertext() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [65u8; 48], [66u8; 48], 0);
    let mut wrong_ciphertext = test_transfer_ciphertext_bytes();
    wrong_ciphertext[0] ^= 0xff;
    node.da_ciphertext_tree
        .insert(transfer.ciphertext_hashes[0].as_slice(), wrong_ciphertext)
        .expect("insert mismatched sidecar ciphertext");
    node.da_ciphertext_tree
        .flush()
        .expect("flush mismatched sidecar ciphertext");
    let candidate = test_candidate_artifact_action(1, 67);
    let meta = mined_empty_child(&state.best, 1, pow_bits, 0);

    let err = verify_native_block_artifacts_locked(&node, &state, &[transfer, candidate], &meta)
        .expect_err("artifact verification must canonicalize sidecar hash binding");

    assert!(
        err.to_string()
            .contains("canonical DA ciphertext hash mismatch"),
        "unexpected artifact verification error: {err}"
    );
}

#[test]
fn materialized_sidecar_transfer_payload_builds_consensus_da_blob() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let binding = KernelVersionBinding {
        circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
    };
    let nullifiers = vec![[71u8; 48]];
    let commitments = vec![[72u8; 48], [73u8; 48]];

    let first_ciphertext = test_transfer_ciphertext_bytes();
    let mut second_note = test_transfer_encrypted_note();
    second_note.ciphertext[0] ^= 0x5a;
    second_note.kem_ciphertext[0] ^= 0xa5;
    let second_ciphertext = encrypted_note_da_bytes(&second_note).expect("second ciphertext bytes");
    let ciphertexts = vec![first_ciphertext, second_ciphertext];
    let ciphertext_hashes = ciphertexts
        .iter()
        .map(|ciphertext| ciphertext_hash_bytes(ciphertext))
        .collect::<Vec<_>>();
    let ciphertext_sizes = ciphertexts
        .iter()
        .map(|ciphertext| u32::try_from(ciphertext.len()).expect("ciphertext size"))
        .collect::<Vec<_>>();
    let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
    let fee = 0;
    let inputs = ShieldedTransferInputs {
        anchor,
        nullifiers: nullifiers.clone(),
        commitments: commitments.clone(),
        ciphertext_hashes: ciphertext_hashes.clone(),
        balance_slot_asset_ids,
        fee,
        value_balance: 0,
        stablecoin: None,
    };
    let binding_hash = StarkVerifier::compute_binding_hash(&inputs).data;
    let proof = test_transfer_proof_artifact(
        anchor,
        &nullifiers,
        &commitments,
        &ciphertext_hashes,
        balance_slot_asset_ids,
        fee,
        None,
        binding,
    );
    let args = ShieldedTransferSidecarArgs {
        proof,
        commitments: commitments.clone(),
        ciphertext_hashes: ciphertext_hashes.clone(),
        ciphertext_sizes: ciphertext_sizes.clone(),
        anchor,
        balance_slot_asset_ids,
        binding_hash,
        stablecoin: None,
        fee,
    };
    let mut action = PendingAction {
        tx_hash: [0u8; 32],
        binding,
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_SHIELDED_TRANSFER_SIDECAR,
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes: ciphertext_hashes.clone(),
        ciphertext_sizes,
        public_args: args.encode(),
        fee,
        candidate_artifact: None,
        received_ms: 0,
    };
    action.tx_hash = pending_action_hash(&action);
    validate_transfer_action_payload(&action).expect("valid sidecar transfer payload");

    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    for (hash, ciphertext) in action.ciphertext_hashes.iter().zip(ciphertexts.iter()) {
        da_ciphertext_tree
            .insert(hash.as_slice(), ciphertext.as_slice())
            .expect("insert sidecar ciphertext");
    }
    da_ciphertext_tree
        .flush()
        .expect("flush sidecar ciphertexts");

    let materialized =
        materialize_native_action_payloads(&da_ciphertext_tree, std::slice::from_ref(&action))
            .expect("materialize sidecar payload");
    let payload = materialized
        .first()
        .expect("one materialized sidecar payload");
    assert_eq!(payload.ciphertexts, ciphertexts);
    assert_eq!(payload.replay_key, None);

    let (tx, _artifact) = consensus_tx_and_artifact_from_action(&action, payload)
        .expect("build consensus transaction from materialized payload");
    assert_eq!(tx.nullifiers, action.nullifiers);
    assert_eq!(tx.commitments, action.commitments);
    assert_eq!(tx.version, action.binding.into());
    assert_eq!(tx.ciphertexts, ciphertexts);
    assert_eq!(tx.ciphertext_hashes, action.ciphertext_hashes);
    assert_eq!(tx.hash(), tx.id);

    let mut expected_blob = Vec::new();
    expected_blob.extend_from_slice(&1u32.to_le_bytes());
    expected_blob.extend_from_slice(&2u32.to_le_bytes());
    for ciphertext in &ciphertexts {
        let len = u32::try_from(ciphertext.len()).expect("ciphertext len");
        expected_blob.extend_from_slice(&len.to_le_bytes());
        expected_blob.extend_from_slice(ciphertext);
    }
    assert_eq!(
        consensus::types::build_da_blob(std::slice::from_ref(&tx)),
        expected_blob
    );
    assert_eq!(
        consensus::types::da_root(std::slice::from_ref(&tx), native_da_params())
            .expect("consensus DA root"),
        state_da::da_root(&expected_blob, native_da_params()).expect("expected DA root")
    );
}

#[test]
fn materialized_sidecar_da_blob_excludes_inbound_bridge_replay_rows() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [82u8; 48], [83u8; 48], 0);
    let inbound = test_inbound_bridge_action(b"da blob replay separation");
    let inbound_replay_key = bridge_inbound_replay_key_from_action(&inbound)
        .expect("project inbound bridge replay key")
        .expect("inbound bridge replay key");
    assert_eq!(
        bridge_inbound_replay_key_from_action(&transfer).expect("transfer replay projection"),
        None
    );

    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    insert_test_sidecar_ciphertext(&da_ciphertext_tree, &transfer);
    let actions = vec![transfer.clone(), inbound.clone()];

    let materialized = materialize_native_action_payloads(&da_ciphertext_tree, &actions)
        .expect("materialize mixed sidecar/bridge payloads");
    assert_eq!(materialized.len(), actions.len());
    let transfer_payload = materialized.first().expect("transfer payload");
    let inbound_payload = materialized.get(1).expect("inbound bridge payload");
    assert_eq!(
        transfer_payload.ciphertexts.len(),
        transfer.ciphertext_hashes.len()
    );
    assert_eq!(transfer_payload.replay_key, None);
    assert!(inbound_payload.ciphertexts.is_empty());
    assert_eq!(inbound_payload.replay_key, Some(inbound_replay_key));

    let planned = plan_materialized_action_effects(&da_ciphertext_tree, &state, &actions)
        .expect("plan mixed sidecar/bridge effects");
    assert_eq!(planned.len(), actions.len());
    let transfer_effect = planned.first().expect("transfer effect");
    let inbound_effect = planned.get(1).expect("inbound bridge effect");
    assert_eq!(transfer_effect.ciphertexts, transfer_payload.ciphertexts);
    assert_eq!(transfer_effect.replay_key, None);
    assert!(inbound_effect.ciphertexts.is_empty());
    assert_eq!(inbound_effect.replay_key, Some(inbound_replay_key));

    let projection = admit_native_action_wire_replay_projection(
        "mixed sidecar DA blob bridge replay separation",
        &actions,
        &planned,
    )
    .expect("project mixed sidecar/bridge replay rows");
    assert_eq!(projection.projected_action_count, actions.len());
    assert_eq!(
        projection.projected_ciphertext_row_count,
        transfer.ciphertext_hashes.len()
    );
    assert_eq!(projection.projected_bridge_replay_row_count, 1);

    let sidecar_only_payload =
        materialize_native_action_payloads(&da_ciphertext_tree, std::slice::from_ref(&transfer))
            .expect("materialize transfer-only payload")
            .pop()
            .expect("one transfer-only payload");
    assert_eq!(
        sidecar_only_payload.ciphertexts,
        transfer_payload.ciphertexts
    );
    assert_eq!(sidecar_only_payload.replay_key, None);

    let (mixed_tx, _mixed_artifact) =
        consensus_tx_and_artifact_from_action(&transfer, transfer_payload)
            .expect("mixed transfer consensus transaction");
    let (sidecar_only_tx, _sidecar_only_artifact) =
        consensus_tx_and_artifact_from_action(&transfer, &sidecar_only_payload)
            .expect("transfer-only consensus transaction");
    assert_eq!(mixed_tx.nullifiers, sidecar_only_tx.nullifiers);
    assert_eq!(mixed_tx.commitments, sidecar_only_tx.commitments);
    assert_eq!(
        mixed_tx.ciphertext_hashes,
        sidecar_only_tx.ciphertext_hashes
    );
    assert_eq!(mixed_tx.ciphertexts, sidecar_only_tx.ciphertexts);

    let inbound_tx_err = consensus_tx_and_artifact_from_action(&inbound, inbound_payload)
        .expect_err("inbound bridge replay rows must not become DA transactions");
    assert!(
        inbound_tx_err
            .to_string()
            .contains("action is not a shielded transfer"),
        "unexpected inbound bridge transaction error: {inbound_tx_err}"
    );

    assert_eq!(
        consensus::types::build_da_blob(std::slice::from_ref(&mixed_tx)),
        consensus::types::build_da_blob(std::slice::from_ref(&sidecar_only_tx))
    );
    assert_eq!(
        consensus::types::da_root(std::slice::from_ref(&mixed_tx), native_da_params())
            .expect("mixed consensus DA root"),
        consensus::types::da_root(std::slice::from_ref(&sidecar_only_tx), native_da_params())
            .expect("transfer-only consensus DA root")
    );
}

#[test]
fn materialized_sidecar_da_blob_bridge_first_excludes_replay_rows() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [84u8; 48], [85u8; 48], 0);
    let inbound = test_inbound_bridge_action(b"bridge first da blob replay separation");
    let inbound_replay_key = bridge_inbound_replay_key_from_action(&inbound)
        .expect("project inbound bridge replay key")
        .expect("inbound bridge replay key");

    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    insert_test_sidecar_ciphertext(&da_ciphertext_tree, &transfer);
    let actions = vec![inbound.clone(), transfer.clone()];

    let materialized = materialize_native_action_payloads(&da_ciphertext_tree, &actions)
        .expect("materialize bridge-first mixed payloads");
    assert_eq!(materialized.len(), actions.len());
    let inbound_payload = materialized.first().expect("inbound bridge payload");
    let transfer_payload = materialized.get(1).expect("transfer payload");
    assert!(inbound_payload.ciphertexts.is_empty());
    assert_eq!(inbound_payload.replay_key, Some(inbound_replay_key));
    assert_eq!(
        transfer_payload.ciphertexts.len(),
        transfer.ciphertext_hashes.len()
    );
    assert_eq!(transfer_payload.replay_key, None);

    let planned = plan_materialized_action_effects(&da_ciphertext_tree, &state, &actions)
        .expect("plan bridge-first mixed effects");
    assert_eq!(planned.len(), actions.len());
    let inbound_effect = planned.first().expect("inbound bridge effect");
    let transfer_effect = planned.get(1).expect("transfer effect");
    assert!(inbound_effect.ciphertexts.is_empty());
    assert_eq!(inbound_effect.replay_key, Some(inbound_replay_key));
    assert_eq!(transfer_effect.ciphertexts, transfer_payload.ciphertexts);
    assert_eq!(transfer_effect.replay_key, None);

    let projection = admit_native_action_wire_replay_projection(
        "bridge-first sidecar DA blob replay separation",
        &actions,
        &planned,
    )
    .expect("project bridge-first sidecar/bridge replay rows");
    assert_eq!(projection.projected_action_count, actions.len());
    assert_eq!(
        projection.projected_ciphertext_row_count,
        transfer.ciphertext_hashes.len()
    );
    assert_eq!(projection.projected_bridge_replay_row_count, 1);

    let inbound_tx_err = consensus_tx_and_artifact_from_action(&inbound, inbound_payload)
        .expect_err("bridge-first inbound replay rows must not become DA transactions");
    assert!(
        inbound_tx_err
            .to_string()
            .contains("action is not a shielded transfer"),
        "unexpected inbound bridge transaction error: {inbound_tx_err}"
    );

    let sidecar_only_payload =
        materialize_native_action_payloads(&da_ciphertext_tree, std::slice::from_ref(&transfer))
            .expect("materialize transfer-only payload")
            .pop()
            .expect("one transfer-only payload");
    let (mixed_tx, _mixed_artifact) =
        consensus_tx_and_artifact_from_action(&transfer, transfer_payload)
            .expect("bridge-first mixed transfer consensus transaction");
    let (sidecar_only_tx, _sidecar_only_artifact) =
        consensus_tx_and_artifact_from_action(&transfer, &sidecar_only_payload)
            .expect("transfer-only consensus transaction");
    assert_eq!(mixed_tx.ciphertexts, sidecar_only_tx.ciphertexts);
    assert_eq!(
        consensus::types::build_da_blob(std::slice::from_ref(&mixed_tx)),
        consensus::types::build_da_blob(std::slice::from_ref(&sidecar_only_tx))
    );
    assert_eq!(
        consensus::types::da_root(std::slice::from_ref(&mixed_tx), native_da_params())
            .expect("bridge-first mixed consensus DA root"),
        consensus::types::da_root(std::slice::from_ref(&sidecar_only_tx), native_da_params())
            .expect("transfer-only consensus DA root")
    );
}

#[test]
fn materialized_sidecar_observer_projection_ignores_received_time() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let first = test_sidecar_transfer_action(anchor, [80u8; 48], [81u8; 48], 0);
    let mut second = first.clone();
    second.received_ms = 987_654_321;
    second.tx_hash = pending_action_hash(&second);

    assert_ne!(
        first.tx_hash, second.tx_hash,
        "arrival metadata must remain visible only in the raw pending-action hash"
    );
    assert_eq!(
        pending_action_semantic_hash(&first),
        pending_action_semantic_hash(&second),
        "sidecar semantic action identity must ignore arrival-time metadata"
    );
    assert_eq!(first.ciphertext_sizes, second.ciphertext_sizes);

    validate_transfer_action_payload(&first).expect("first sidecar payload validates");
    validate_transfer_action_payload(&second).expect("second sidecar payload validates");

    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    insert_test_sidecar_ciphertext(&da_ciphertext_tree, &first);

    let first_planned =
        plan_materialized_action_effects(&da_ciphertext_tree, &state, std::slice::from_ref(&first))
            .expect("plan first sidecar replay projection");
    let second_planned = plan_materialized_action_effects(
        &da_ciphertext_tree,
        &state,
        std::slice::from_ref(&second),
    )
    .expect("plan second sidecar replay projection");
    assert_eq!(first_planned.len(), 1);
    assert_eq!(second_planned.len(), 1);
    let first_effect = first_planned.first().expect("first planned effect");
    let second_effect = second_planned.first().expect("second planned effect");
    assert_eq!(
        first_effect.commitment_start,
        second_effect.commitment_start
    );
    assert_eq!(first_effect.ciphertexts, second_effect.ciphertexts);
    assert_eq!(first_effect.replay_key, second_effect.replay_key);

    let first_payloads =
        materialize_native_action_payloads(&da_ciphertext_tree, std::slice::from_ref(&first))
            .expect("materialize first sidecar payload");
    let second_payloads =
        materialize_native_action_payloads(&da_ciphertext_tree, std::slice::from_ref(&second))
            .expect("materialize second sidecar payload");
    assert_eq!(first_payloads.len(), 1);
    assert_eq!(second_payloads.len(), 1);
    let first_payload = first_payloads.first().expect("first payload");
    let second_payload = second_payloads.first().expect("second payload");
    assert_eq!(first_payload.ciphertexts, second_payload.ciphertexts);
    assert_eq!(first_payload.replay_key, second_payload.replay_key);

    let (first_tx, _first_artifact) =
        consensus_tx_and_artifact_from_action(&first, first_payload).expect("first consensus tx");
    let (second_tx, _second_artifact) =
        consensus_tx_and_artifact_from_action(&second, second_payload)
            .expect("second consensus tx");

    assert_eq!(first_tx.nullifiers, second_tx.nullifiers);
    assert_eq!(first_tx.commitments, second_tx.commitments);
    assert_eq!(first_tx.balance_tag, second_tx.balance_tag);
    assert_eq!(first_tx.version, second_tx.version);
    assert_eq!(first_tx.ciphertext_hashes, second_tx.ciphertext_hashes);
    assert_eq!(first_tx.ciphertexts, second_tx.ciphertexts);
    assert_eq!(first_tx.id, second_tx.id);
    assert_eq!(first_tx.hash(), second_tx.hash());
    assert_eq!(
        consensus::types::build_da_blob(std::slice::from_ref(&first_tx)),
        consensus::types::build_da_blob(std::slice::from_ref(&second_tx))
    );
    assert_eq!(
        consensus::types::da_root(std::slice::from_ref(&first_tx), native_da_params())
            .expect("first consensus DA root"),
        consensus::types::da_root(std::slice::from_ref(&second_tx), native_da_params())
            .expect("second consensus DA root")
    );
}

#[test]
fn pending_action_raw_bytes_project_to_validated_materialized_replay_rows() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let inline_transfer = test_inline_transfer_action(anchor, [72u8; 48], [73u8; 48], 0);
    let sidecar_transfer = test_sidecar_transfer_action(anchor, [74u8; 48], [75u8; 48], 0);
    let outbound = test_outbound_bridge_action(b"projection outbound");
    let coinbase = test_coinbase_action(consensus::reward::block_subsidy(1));
    let candidate = test_candidate_artifact_action(2, 76);
    let mut transfers = vec![inline_transfer, sidecar_transfer];
    transfers.sort_by_key(action_order_key);
    let actions = vec![
        transfers.remove(0),
        transfers.remove(0),
        outbound,
        coinbase,
        candidate,
    ];
    let meta = mined_child_with_actions(&state.best, 1, pow_bits, 0, actions.clone());
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    for action in &actions {
        insert_test_sidecar_ciphertext(&da_ciphertext_tree, action);
    }

    let decoded = decode_block_actions(&meta).expect("decode canonical block action bytes");
    assert_eq!(decoded.len(), actions.len());
    assert_eq!(meta.action_bytes.len(), decoded.len());
    assert_eq!(usize::try_from(meta.tx_count).unwrap(), decoded.len());
    for ((decoded_action, expected_action), raw_bytes) in decoded
        .iter()
        .zip(actions.iter())
        .zip(meta.action_bytes.iter())
    {
        assert_pending_action_fields_eq(decoded_action, expected_action);
        assert_eq!(decoded_action.encode(), *raw_bytes);
        assert_eq!(decoded_action.tx_hash, pending_action_hash(decoded_action));
        assert_eq!(
            pending_action_semantic_hash(decoded_action),
            pending_action_semantic_hash(expected_action)
        );
        assert_route_payload_fields_eq(decoded_action, expected_action, meta.height);
    }

    let validation_steps = validation_steps_from_decoded_actions(&state, &decoded)
        .expect("projection validation steps from decoded actions");
    assert_eq!(validation_steps.len(), decoded.len());
    for (action, step) in decoded.iter().zip(validation_steps.iter()) {
        assert_validation_step_projects_action_fields(action, step);
    }
    validate_block_actions_locked(&state, &decoded).expect("decoded actions validate");
    let materialized = materialize_native_action_payloads(&da_ciphertext_tree, &decoded)
        .expect("materialize from same decoded actions");
    assert_eq!(materialized.len(), decoded.len());
    for (action, payload) in decoded.iter().zip(materialized.iter()) {
        assert_eq!(payload.ciphertexts.len(), action.ciphertext_hashes.len());
        assert_eq!(
            payload.replay_key,
            bridge_inbound_replay_key_from_action(action).expect("project replay key")
        );
        for ((bytes, expected_hash), expected_size) in payload
            .ciphertexts
            .iter()
            .zip(action.ciphertext_hashes.iter())
            .zip(action.ciphertext_sizes.iter())
        {
            assert_eq!(ciphertext_hash_bytes(bytes), *expected_hash);
            assert_eq!(bytes.len(), usize::try_from(*expected_size).unwrap());
        }
    }

    let planned = plan_materialized_action_effects(&da_ciphertext_tree, &state, &decoded)
        .expect("plan effects from same decoded actions");
    assert_eq!(planned.len(), decoded.len());
    let mut expected_commitment_start = state.commitment_tree.leaf_count();
    for ((action, payload), effect) in decoded.iter().zip(materialized.iter()).zip(planned.iter()) {
        assert_eq!(effect.commitment_start, expected_commitment_start);
        assert_eq!(effect.ciphertexts, payload.ciphertexts);
        assert_eq!(effect.replay_key, payload.replay_key);
        expected_commitment_start = expected_commitment_start
            .checked_add(u64::try_from(action.commitments.len()).expect("commitment count"))
            .expect("expected commitment cursor");
    }
    let projection =
        admit_native_action_wire_replay_projection("projection equivalence", &decoded, &planned)
            .expect("wire replay projection from same decoded actions");
    let materialized_ciphertext_rows = materialized
        .iter()
        .map(|payload| payload.ciphertexts.len())
        .sum::<usize>();
    let planned_ciphertext_rows = planned
        .iter()
        .map(|effect| effect.ciphertexts.len())
        .sum::<usize>();
    let planned_replay_rows = planned
        .iter()
        .filter(|effect| effect.replay_key.is_some())
        .count();
    assert_eq!(projection.projected_action_count, decoded.len());
    assert_eq!(projection.projected_action_count, materialized.len());
    assert_eq!(
        projection.projected_ciphertext_row_count,
        materialized_ciphertext_rows
    );
    assert_eq!(
        projection.projected_ciphertext_row_count,
        planned_ciphertext_rows
    );
    assert_eq!(
        projection.projected_bridge_replay_row_count,
        planned_replay_rows
    );
}

fn assert_pending_action_fields_eq(actual: &PendingAction, expected: &PendingAction) {
    assert_eq!(actual.tx_hash, expected.tx_hash);
    assert_eq!(actual.binding.circuit, expected.binding.circuit);
    assert_eq!(actual.binding.crypto, expected.binding.crypto);
    assert_eq!(actual.family_id, expected.family_id);
    assert_eq!(actual.action_id, expected.action_id);
    assert_eq!(actual.anchor, expected.anchor);
    assert_eq!(actual.nullifiers, expected.nullifiers);
    assert_eq!(actual.commitments, expected.commitments);
    assert_eq!(actual.ciphertext_hashes, expected.ciphertext_hashes);
    assert_eq!(actual.ciphertext_sizes, expected.ciphertext_sizes);
    assert_eq!(actual.public_args, expected.public_args);
    assert_eq!(actual.fee, expected.fee);
    assert_eq!(actual.received_ms, expected.received_ms);
    assert_eq!(actual.candidate_artifact, expected.candidate_artifact);
}

fn assert_route_payload_fields_eq(
    actual: &PendingAction,
    expected: &PendingAction,
    source_height: u64,
) {
    match (actual.family_id, actual.action_id) {
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            let actual_args: ShieldedTransferInlineArgs =
                decode_scale_exact(&actual.public_args, "actual inline transfer args")
                    .expect("decode actual inline transfer args");
            let expected_args: ShieldedTransferInlineArgs =
                decode_scale_exact(&expected.public_args, "expected inline transfer args")
                    .expect("decode expected inline transfer args");
            assert_eq!(actual_args.anchor, actual.anchor);
            assert_eq!(actual_args.anchor, expected_args.anchor);
            assert_eq!(actual_args.commitments, actual.commitments);
            assert_eq!(actual_args.commitments, expected_args.commitments);
            assert_eq!(actual_args.fee, actual.fee);
            assert_eq!(actual_args.fee, expected_args.fee);
            assert_eq!(actual_args.binding_hash, expected_args.binding_hash);
            assert_eq!(actual_args.stablecoin, expected_args.stablecoin);
            let (hashes, sizes) = inline_ciphertext_metadata(&actual_args.ciphertexts)
                .1
                .expect("inline ciphertext metadata");
            assert_eq!(hashes, actual.ciphertext_hashes);
            assert_eq!(sizes, actual.ciphertext_sizes);
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
            let actual_args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&actual.public_args, "actual sidecar transfer args")
                    .expect("decode actual sidecar transfer args");
            let expected_args: ShieldedTransferSidecarArgs =
                decode_scale_exact(&expected.public_args, "expected sidecar transfer args")
                    .expect("decode expected sidecar transfer args");
            assert_eq!(actual_args.anchor, actual.anchor);
            assert_eq!(actual_args.anchor, expected_args.anchor);
            assert_eq!(actual_args.commitments, actual.commitments);
            assert_eq!(actual_args.commitments, expected_args.commitments);
            assert_eq!(actual_args.ciphertext_hashes, actual.ciphertext_hashes);
            assert_eq!(actual_args.ciphertext_sizes, actual.ciphertext_sizes);
            assert_eq!(actual_args.fee, actual.fee);
            assert_eq!(actual_args.fee, expected_args.fee);
            assert_eq!(actual_args.binding_hash, expected_args.binding_hash);
            assert_eq!(actual_args.stablecoin, expected_args.stablecoin);
        }
        (FAMILY_BRIDGE, ACTION_BRIDGE_OUTBOUND) => {
            let actual_args: OutboundBridgeArgsV1 =
                decode_scale_exact(&actual.public_args, "actual outbound bridge args")
                    .expect("decode actual outbound bridge args");
            let expected_args: OutboundBridgeArgsV1 =
                decode_scale_exact(&expected.public_args, "expected outbound bridge args")
                    .expect("decode expected outbound bridge args");
            assert_eq!(
                actual_args.destination_chain_id,
                expected_args.destination_chain_id
            );
            assert_eq!(actual_args.app_family_id, expected_args.app_family_id);
            assert_eq!(actual_args.payload, expected_args.payload);
            let messages =
                bridge_messages_from_actions(std::slice::from_ref(actual), source_height)
                    .expect("project outbound bridge message");
            let message = messages.first().expect("one outbound bridge message");
            assert_eq!(message.source_chain_id, HEGEMON_CHAIN_ID_V1);
            assert_eq!(
                message.destination_chain_id,
                actual_args.destination_chain_id
            );
            assert_eq!(message.app_family_id, actual_args.app_family_id);
            assert_eq!(message.source_height, source_height);
            assert_eq!(message.message_nonce, (u128::from(source_height)) << 64);
            assert_eq!(
                message.payload_hash,
                bridge_payload_hash(&actual_args.payload)
            );
            assert_eq!(message.payload, actual_args.payload);
        }
        (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => {
            let actual_args: MintCoinbaseArgs =
                decode_scale_exact(&actual.public_args, "actual coinbase args")
                    .expect("decode actual coinbase args");
            let expected_args: MintCoinbaseArgs =
                decode_scale_exact(&expected.public_args, "expected coinbase args")
                    .expect("decode expected coinbase args");
            let actual_note = &actual_args.reward_bundle.miner_note;
            let expected_note = &expected_args.reward_bundle.miner_note;
            assert_eq!(actual_note.amount, expected_note.amount);
            assert_eq!(
                actual_note.recipient_address,
                expected_note.recipient_address
            );
            assert_eq!(actual_note.public_seed, expected_note.public_seed);
            assert_eq!(actual_note.commitment, actual.commitments[0]);
            assert_eq!(actual_note.commitment, expected_note.commitment);
            assert_eq!(
                actual_note.commitment,
                coinbase_note_data_commitment(actual_note)
            );
            let (_, metadata) = coinbase_ciphertext_metadata(&actual_note.encrypted_note);
            let (ciphertext_hash, ciphertext_size) =
                metadata.expect("coinbase ciphertext metadata");
            assert_eq!(actual.ciphertext_hashes, vec![ciphertext_hash]);
            assert_eq!(actual.ciphertext_sizes, vec![ciphertext_size]);
        }
        (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT) => {
            let actual_artifact = actual
                .candidate_artifact
                .as_ref()
                .expect("actual candidate artifact");
            let expected_artifact = expected
                .candidate_artifact
                .as_ref()
                .expect("expected candidate artifact");
            assert_eq!(actual_artifact, expected_artifact);
            assert_eq!(actual_artifact.version, BLOCK_PROOF_BUNDLE_SCHEMA);
            assert_ne!(actual_artifact.tx_count, 0);
            assert_ne!(actual_artifact.da_chunk_count, 0);
        }
        _ => {}
    }
}

fn validation_steps_from_decoded_actions(
    state: &NativeState,
    actions: &[PendingAction],
) -> Result<Vec<NativeBlockActionValidationStep>> {
    let mut nullifier_state = NullifierState::new(state.nullifiers.clone(), BTreeSet::new());
    actions
        .iter()
        .map(|action| {
            let scope_input = native_action_scope_admission_input(action);
            let route = evaluate_native_action_scope_admission(scope_input)
                .map_err(native_action_scope_admission_error)?;
            let mut transfer_key = [0u8; 32];
            let mut transfer_state_input = NativeTransferStateAdmissionInput {
                anchor_known: true,
                nullifier_state: NativeTransferNullifierAdmissionState::Valid,
                commitments_nonzero: true,
                stablecoin_policy_authorized: true,
                sidecar_route: false,
                sidecar_ciphertexts_available: true,
                sidecar_ciphertext_sizes_present: true,
                sidecar_ciphertext_sizes_match: true,
            };
            let bridge_replay_key = match route {
                NativeActionScopeAdmissionRoute::Bridge => {
                    validate_bridge_action_payload(action)?;
                    bridge_inbound_replay_key_from_action(action)?
                }
                NativeActionScopeAdmissionRoute::CandidateArtifact => {
                    validate_candidate_action_payload(action)?;
                    None
                }
                NativeActionScopeAdmissionRoute::Coinbase => {
                    validate_coinbase_action_payload(action)?;
                    None
                }
                NativeActionScopeAdmissionRoute::Transfer => {
                    validate_transfer_action_payload(action)?;
                    transfer_key = action_order_key(action);
                    transfer_state_input = native_transfer_state_admission_input_for_block(
                        state,
                        &mut nullifier_state,
                        action,
                    );
                    None
                }
            };
            Ok(NativeBlockActionValidationStep {
                scope_input,
                payload_valid: true,
                transfer_key,
                transfer_state_input,
                bridge_replay_key,
            })
        })
        .collect()
}

fn assert_validation_step_projects_action_fields(
    action: &PendingAction,
    step: &NativeBlockActionValidationStep,
) {
    assert_eq!(
        step.scope_input,
        native_action_scope_admission_input(action)
    );
    assert!(step.payload_valid);
    assert_eq!(
        step.bridge_replay_key,
        bridge_inbound_replay_key_from_action(action).expect("project bridge replay key")
    );
    if is_shielded_transfer_action(action) {
        assert_eq!(step.transfer_key, action_order_key(action));
        assert_eq!(
            step.transfer_state_input.anchor_known,
            action.anchor != [0u8; 48]
        );
        assert_eq!(
            step.transfer_state_input.commitments_nonzero,
            action
                .commitments
                .iter()
                .all(|commitment| *commitment != [0u8; 48])
        );
        assert!(
            !step.transfer_state_input.sidecar_route,
            "block validation intentionally checks sidecar availability before replay"
        );
    } else {
        assert_eq!(step.transfer_key, [0u8; 32]);
        assert_eq!(
            step.transfer_state_input.nullifier_state,
            NativeTransferNullifierAdmissionState::Valid
        );
    }
}

fn projection_equivalence_action_mix_block(
    parent: &NativeBlockMeta,
    pow_bits: u32,
) -> (NativeBlockMeta, Vec<PendingAction>) {
    let parent_state = test_state(parent.clone());
    let anchor = parent_state.commitment_tree.root();
    let actions = vec![
        test_sidecar_transfer_action(anchor, [77u8; 48], [78u8; 48], 0),
        test_outbound_bridge_action(b"projection surface outbound"),
        test_inbound_bridge_action(b"projection surface inbound"),
        test_candidate_artifact_action(1, 79),
    ];
    let block = mined_child_with_actions(parent, parent.height + 1, pow_bits, 0, actions.clone());
    (block, actions)
}

fn assert_canonical_projection_rows_match(
    label: &'static str,
    da_ciphertext_tree: &sled::Tree,
    chain: &[NativeBlockMeta],
) {
    let genesis = chain.first().expect("projection chain genesis").clone();
    let state = test_state(genesis);
    let decoded_actions = chain
        .iter()
        .skip(1)
        .flat_map(|meta| {
            decode_block_actions(meta)
                .unwrap_or_else(|err| panic!("{label}: decode canonical action bytes: {err}"))
        })
        .collect::<Vec<_>>();
    let materialized = materialize_native_action_payloads(da_ciphertext_tree, &decoded_actions)
        .unwrap_or_else(|err| panic!("{label}: materialize decoded actions: {err}"));
    let planned = plan_materialized_action_effects(da_ciphertext_tree, &state, &decoded_actions)
        .unwrap_or_else(|err| panic!("{label}: plan decoded actions: {err}"));
    let projection = admit_native_action_wire_replay_projection(label, &decoded_actions, &planned)
        .unwrap_or_else(|err| panic!("{label}: project decoded actions: {err}"));
    let plan = plan_canonical_index_rebuild(chain, da_ciphertext_tree, None)
        .unwrap_or_else(|err| panic!("{label}: canonical index rebuild plan: {err}"));
    let decoded_commitment_rows = decoded_actions
        .iter()
        .map(|action| action.commitments.len())
        .sum::<usize>();
    let decoded_nullifier_rows = decoded_actions
        .iter()
        .map(|action| action.nullifiers.len())
        .sum::<usize>();
    let decoded_ciphertext_index_rows = decoded_actions
        .iter()
        .map(|action| action.ciphertext_hashes.len())
        .sum::<usize>();
    let materialized_ciphertext_rows = materialized
        .iter()
        .map(|payload| payload.ciphertexts.len())
        .sum::<usize>();
    let planned_ciphertext_rows = planned
        .iter()
        .map(|effect| effect.ciphertexts.len())
        .sum::<usize>();
    let planned_replay_rows = planned
        .iter()
        .filter(|effect| effect.replay_key.is_some())
        .count();
    let expected_commitment_entries = decoded_actions
        .iter()
        .zip(planned.iter())
        .flat_map(|(action, effect)| {
            action
                .commitments
                .iter()
                .enumerate()
                .map(|(offset, commitment)| {
                    let offset = u64::try_from(offset).expect("commitment offset");
                    (
                        effect
                            .commitment_start
                            .checked_add(offset)
                            .expect("commitment index"),
                        *commitment,
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected_nullifier_entries = decoded_actions
        .iter()
        .flat_map(|action| action.nullifiers.iter().copied())
        .collect::<Vec<_>>();
    let expected_bridge_replay_entries = planned
        .iter()
        .filter_map(|effect| effect.replay_key)
        .collect::<Vec<_>>();
    let expected_ciphertext_archive_entries = materialized
        .iter()
        .zip(planned.iter())
        .flat_map(|(payload, effect)| {
            payload
                .ciphertexts
                .iter()
                .enumerate()
                .map(|(offset, bytes)| {
                    let offset = u64::try_from(offset).expect("ciphertext offset");
                    (
                        effect
                            .commitment_start
                            .checked_add(offset)
                            .expect("ciphertext archive index"),
                        bytes.clone(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected_ciphertext_index_entries = decoded_actions
        .iter()
        .flat_map(|action| {
            action
                .ciphertext_hashes
                .iter()
                .enumerate()
                .map(|(idx, hash)| {
                    let idx_u64 = u64::try_from(idx).expect("ciphertext index offset");
                    let size = action
                        .ciphertext_sizes
                        .get(idx)
                        .copied()
                        .expect("ciphertext index size");
                    let mut value = Vec::with_capacity(32 + 4 + 8);
                    value.extend_from_slice(&action.tx_hash);
                    value.extend_from_slice(&size.to_le_bytes());
                    value.extend_from_slice(&idx_u64.to_le_bytes());
                    (*hash, value)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        projection.projected_action_count,
        decoded_actions.len(),
        "{label}"
    );
    assert_eq!(
        projection.projected_ciphertext_row_count, materialized_ciphertext_rows,
        "{label}"
    );
    assert_eq!(
        projection.projected_ciphertext_row_count, planned_ciphertext_rows,
        "{label}"
    );
    assert_eq!(
        projection.projected_bridge_replay_row_count, planned_replay_rows,
        "{label}"
    );
    assert_eq!(
        plan.commitment_entries.len(),
        decoded_commitment_rows,
        "{label}"
    );
    assert_eq!(
        plan.commitment_entries, expected_commitment_entries,
        "{label}"
    );
    assert_eq!(
        plan.nullifier_entries.len(),
        decoded_nullifier_rows,
        "{label}"
    );
    assert_eq!(
        plan.nullifier_entries, expected_nullifier_entries,
        "{label}"
    );
    assert_eq!(
        plan.ciphertext_index_entries.len(),
        decoded_ciphertext_index_rows,
        "{label}"
    );
    assert_eq!(
        plan.ciphertext_index_entries, expected_ciphertext_index_entries,
        "{label}"
    );
    assert_eq!(
        plan.ciphertext_archive_entries.len(),
        materialized_ciphertext_rows,
        "{label}"
    );
    assert_eq!(
        plan.ciphertext_archive_entries.len(),
        planned_ciphertext_rows,
        "{label}"
    );
    assert_eq!(
        plan.bridge_replay_entries.len(),
        planned_replay_rows,
        "{label}"
    );
    assert_eq!(
        plan.bridge_replay_entries, expected_bridge_replay_entries,
        "{label}"
    );
    assert_eq!(
        plan.ciphertext_archive_entries, expected_ciphertext_archive_entries,
        "{label}"
    );
}

fn assert_canonical_index_plans_eq(
    label: &'static str,
    actual: &NativeCanonicalIndexPlan,
    expected: &NativeCanonicalIndexPlan,
) {
    assert_eq!(
        actual.commitment_entries, expected.commitment_entries,
        "{label}: commitment rows drifted"
    );
    assert_eq!(
        actual.nullifier_entries, expected.nullifier_entries,
        "{label}: nullifier rows drifted"
    );
    assert_eq!(
        actual.bridge_replay_entries, expected.bridge_replay_entries,
        "{label}: bridge replay rows drifted"
    );
    assert_eq!(
        actual.ciphertext_index_entries, expected.ciphertext_index_entries,
        "{label}: ciphertext index rows drifted"
    );
    assert_eq!(
        actual.ciphertext_archive_entries, expected.ciphertext_archive_entries,
        "{label}: ciphertext archive rows drifted"
    );
}

#[test]
fn action_state_effect_preview_drops_consumed_bridge_replay_from_work() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let action = test_inbound_bridge_action(b"already consumed inbound replay");
    let replay_key = bridge_inbound_replay_key_from_action(&action)
        .expect("decode replay key")
        .expect("inbound replay key");
    {
        let mut state = node.state.write();
        state.consumed_bridge_messages.insert(replay_key);
        state.pending_actions.insert(action.tx_hash, action);
    }

    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(work.tx_count, 0);
    assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
    assert_eq!(work.message_count, 0);
    assert_eq!(work.message_root, empty_bridge_message_root());
}

#[test]
fn canonical_index_rebuild_rejects_duplicate_before_sled_mutation() {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let commitment_tree = db.open_tree("commitments").expect("commitment tree");
    let nullifier_tree = db.open_tree("nullifiers").expect("nullifier tree");
    let bridge_inbound_tree = db.open_tree("bridge_inbound").expect("bridge inbound tree");
    let ciphertext_index_tree = db
        .open_tree("ciphertext_index")
        .expect("ciphertext index tree");
    let ciphertext_archive_tree = db
        .open_tree("ciphertext_archive")
        .expect("ciphertext archive tree");
    let da_ciphertext_tree = db.open_tree("da_ciphertexts").expect("da ciphertext tree");
    let pow_bits = 0x207f_ffff;
    let genesis = genesis_meta(pow_bits).expect("genesis");
    let anchor = genesis.state_root;
    let first = test_inline_transfer_action(anchor, [52u8; 48], [53u8; 48], 0);
    let second = test_inline_transfer_action(anchor, [52u8; 48], [54u8; 48], 0);
    let mut block = genesis.clone();
    block.height = 1;
    block.tx_count = 2;
    block.action_bytes = vec![first.encode(), second.encode()];

    let err = plan_canonical_index_rebuild(&[genesis, block], &da_ciphertext_tree, None)
        .expect_err("duplicate nullifier must reject before rebuilding sled indexes");
    assert!(err.to_string().contains("duplicate_nullifier"));
    assert_eq!(
        commitment_tree.len(),
        0,
        "failed rebuild must not partially write commitments"
    );
    assert_eq!(
        nullifier_tree.len(),
        0,
        "failed rebuild must not partially write nullifiers"
    );
    assert_eq!(
        bridge_inbound_tree.len(),
        0,
        "failed rebuild must not partially write bridge replay entries"
    );
    assert_eq!(
        ciphertext_index_tree.len(),
        0,
        "failed rebuild must not partially write ciphertext index entries"
    );
    assert_eq!(
        ciphertext_archive_tree.len(),
        0,
        "failed rebuild must not partially write ciphertext archive entries"
    );
}

#[test]
fn canonical_index_rebuild_rejects_hash_mismatched_materialized_sidecar_ciphertext() {
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    let pow_bits = 0x207f_ffff;
    let genesis = genesis_meta(pow_bits).expect("genesis");
    let anchor = genesis.state_root;
    let transfer = test_sidecar_transfer_action(anchor, [69u8; 48], [70u8; 48], 0);
    let mut wrong_ciphertext = test_transfer_ciphertext_bytes();
    wrong_ciphertext[0] ^= 0x7f;
    da_ciphertext_tree
        .insert(transfer.ciphertext_hashes[0].as_slice(), wrong_ciphertext)
        .expect("insert mismatched sidecar ciphertext");
    da_ciphertext_tree
        .flush()
        .expect("flush mismatched sidecar ciphertext");
    let mut block = genesis.clone();
    block.height = 1;
    block.tx_count = 1;
    block.action_bytes = vec![transfer.encode()];

    let err = plan_canonical_index_rebuild(&[genesis, block], &da_ciphertext_tree, None)
        .expect_err("canonical index rebuild must canonicalize sidecar hash binding");

    assert!(
        err.to_string()
            .contains("canonical DA ciphertext hash mismatch"),
        "unexpected canonical rebuild error: {err}"
    );
}

#[test]
fn canonical_index_rebuild_projects_decoded_materialized_wire_rows() {
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    let pow_bits = 0x207f_ffff;
    let genesis = genesis_meta(pow_bits).expect("genesis");
    let (block, actions) = projection_equivalence_action_mix_block(&genesis, pow_bits);
    for action in &actions {
        insert_test_sidecar_ciphertext(&da_ciphertext_tree, action);
    }
    let chain = vec![genesis, block];

    assert_canonical_projection_rows_match(
        "canonical rebuild projection equivalence",
        &da_ciphertext_tree,
        &chain,
    );
}

#[test]
fn canonical_index_rebuild_rejects_malleable_action_bytes_before_projection_rows() {
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    let pow_bits = 0x207f_ffff;
    let genesis = genesis_meta(pow_bits).expect("genesis");
    let (block, actions) = projection_equivalence_action_mix_block(&genesis, pow_bits);
    for action in &actions {
        insert_test_sidecar_ciphertext(&da_ciphertext_tree, action);
    }
    let canonical_chain = vec![genesis.clone(), block.clone()];
    assert_canonical_projection_rows_match(
        "canonical action-byte projection fixture",
        &da_ciphertext_tree,
        &canonical_chain,
    );

    let mut corrupted = block;
    corrupted
        .action_bytes
        .first_mut()
        .expect("projection fixture has actions")
        .push(0xaa);
    let decode_err = decode_block_actions(&corrupted)
        .expect_err("trailing action bytes must reject before projection");
    assert!(
        decode_err.to_string().contains("trailing bytes"),
        "unexpected action decode error: {decode_err}"
    );

    let corrupted_chain = vec![genesis, corrupted];
    let rebuild_err = plan_canonical_index_rebuild(&corrupted_chain, &da_ciphertext_tree, None)
        .expect_err("canonical rebuild must reject malleable action bytes");
    assert!(
        rebuild_err.to_string().contains("trailing bytes"),
        "unexpected rebuild error: {rebuild_err}"
    );
}

#[test]
fn canonical_index_rebuild_projects_decoded_materialized_wire_rows_replay_sets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let (block, actions) = projection_equivalence_action_mix_block(&genesis, pow_bits);
    for action in &actions {
        insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, action);
    }
    let chain = vec![genesis, block];

    assert_canonical_projection_rows_match(
        "canonical rebuild replay-set projection equivalence",
        &node.da_ciphertext_tree,
        &chain,
    );

    let state = test_state(chain.first().expect("genesis").clone());
    let decoded_actions = chain
        .iter()
        .skip(1)
        .flat_map(|meta| decode_block_actions(meta).expect("decode canonical action bytes"))
        .collect::<Vec<_>>();
    let materialized =
        materialize_native_action_payloads(&node.da_ciphertext_tree, &decoded_actions)
            .expect("materialize decoded actions");
    let planned =
        plan_materialized_action_effects(&node.da_ciphertext_tree, &state, &decoded_actions)
            .expect("plan decoded actions");
    let projection = admit_native_action_wire_replay_projection(
        "canonical rebuild replay-set wire projection",
        &decoded_actions,
        &planned,
    )
    .expect("project planned replay rows");
    let rebuild_output = plan_canonical_index_rebuild(&chain, &node.da_ciphertext_tree, None)
        .expect("canonical index rebuild output");

    let decoded_nullifier_rows = decoded_actions
        .iter()
        .flat_map(|action| action.nullifiers.iter().copied())
        .collect::<Vec<_>>();
    let materialized_action_nullifier_rows = decoded_actions
        .iter()
        .zip(materialized.iter())
        .flat_map(|(action, payload)| {
            assert_eq!(
                payload.replay_key,
                bridge_inbound_replay_key_from_action(action)
                    .expect("project materialized replay key")
            );
            action.nullifiers.to_vec()
        })
        .collect::<Vec<_>>();
    let materialized_replay_keys = materialized
        .iter()
        .filter_map(|payload| payload.replay_key)
        .collect::<Vec<_>>();
    let planned_replay_keys = planned
        .iter()
        .filter_map(|effect| effect.replay_key)
        .collect::<Vec<_>>();

    assert!(
        !decoded_nullifier_rows.is_empty(),
        "fixture must exercise canonical nullifier rows"
    );
    assert!(
        !planned_replay_keys.is_empty(),
        "fixture must exercise canonical bridge replay rows"
    );
    assert_eq!(
        materialized_action_nullifier_rows, decoded_nullifier_rows,
        "materialized action order must preserve decoded nullifier rows"
    );
    assert_eq!(
        materialized_replay_keys, planned_replay_keys,
        "planned replay keys must preserve materialized replay-key order"
    );
    assert_eq!(
        projection.projected_bridge_replay_row_count,
        planned_replay_keys.len(),
        "wire replay row count must match planned replay-key rows"
    );
    assert_eq!(
        rebuild_output.nullifier_entries, decoded_nullifier_rows,
        "canonical rebuild nullifier rows must match decoded row order"
    );
    assert_eq!(
        rebuild_output.bridge_replay_entries, planned_replay_keys,
        "canonical rebuild bridge replay rows must match planned row order"
    );

    node.commit_canonical_index_repair_atomically(rebuild_output.clone())
        .expect("commit canonical index rebuild output");
    assert!(
        node.canonical_index_matches_plan(&rebuild_output)
            .expect("canonical index repair output matches plan"),
        "persisted canonical indexes must match rebuild output"
    );
    let persisted_nullifier_rows = rebuild_output
        .nullifier_entries
        .iter()
        .map(|nullifier| {
            let marker = node
                .nullifier_tree
                .get(nullifier.as_slice())
                .expect("read persisted nullifier marker");
            assert_eq!(marker.as_deref(), Some(b"1".as_slice()));
            *nullifier
        })
        .collect::<Vec<_>>();
    let persisted_bridge_replay_rows = rebuild_output
        .bridge_replay_entries
        .iter()
        .map(|replay_key| {
            let marker = node
                .bridge_inbound_tree
                .get(replay_key.as_slice())
                .expect("read persisted bridge replay marker");
            assert_eq!(marker.as_deref(), Some(b"1".as_slice()));
            *replay_key
        })
        .collect::<Vec<_>>();
    assert_eq!(
        persisted_nullifier_rows, decoded_nullifier_rows,
        "persisted canonical nullifier rows must match decoded row order"
    );
    assert_eq!(
        persisted_bridge_replay_rows, planned_replay_keys,
        "persisted canonical bridge replay rows must match planned row order"
    );
}

#[test]
fn block_range_projects_decoded_materialized_wire_rows() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let genesis = node.best_meta();
    let (block, actions) = projection_equivalence_action_mix_block(&genesis, pow_bits);
    for action in &actions {
        insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, action);
    }
    persist_block(&node.meta_tree, &node.height_tree, &node.block_tree, &block)
        .expect("persist coherent sync block");
    node.state.write().best = block.clone();

    let served = node.block_range(0, 1).expect("serve canonical sync range");
    assert_eq!(served.len(), 2);
    assert_eq!(served[0].height, 0);
    assert_eq!(served[0].hash, genesis.hash);
    assert_eq!(served[1].height, 1);
    assert_eq!(served[1].hash, block.hash);
    assert_eq!(served[1].action_bytes, block.action_bytes);

    assert_canonical_projection_rows_match(
        "sync block_range projection equivalence",
        &node.da_ciphertext_tree,
        &served,
    );
}

#[test]
fn mined_commit_startup_replay_matches_canonical_publication_rows() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let config = test_config(tmp.path(), pow_bits, "unsafe", false);
    let reward = consensus::reward::block_subsidy(1);
    let (imported, expected_plan) = {
        let node = NativeNode::open(config.clone()).expect("node");
        stage_test_coinbase(&node, reward, [90u8; 48]);
        let staged = node
            .state
            .read()
            .pending_actions
            .values()
            .next()
            .cloned()
            .expect("staged coinbase");
        let work = node.prepare_work().expect("prepare native work");
        assert_eq!(work.tx_count, 1);
        let seal = mine_native_round(work.clone(), 0).expect("coinbase seal");
        let imported = node
            .import_mined_block(&work, seal)
            .expect("coinbase import")
            .expect("coinbase block");
        let decoded = decode_block_actions(&imported).expect("decode imported action bytes");
        assert_eq!(decoded.len(), 1);
        assert_pending_action_fields_eq(&decoded[0], &staged);
        assert_eq!(imported.action_bytes, vec![staged.encode()]);
        assert_eq!(imported.supply_digest, u128::from(reward));

        let chain = node
            .chain_to_hash(imported.hash)
            .expect("load imported canonical chain");
        let expected_plan = plan_canonical_index_rebuild(
            &chain,
            &node.da_ciphertext_tree,
            Some(&node.ciphertext_archive_tree),
        )
        .expect("canonical plan from imported raw bytes");
        assert!(
            node.canonical_index_matches_plan(&expected_plan)
                .expect("compare mined canonical indexes"),
            "mined atomic commit rows must match canonical rebuild plan"
        );
        assert_eq!(expected_plan.commitment_entries.len(), 1);
        assert_eq!(expected_plan.ciphertext_archive_entries.len(), 1);
        assert_eq!(expected_plan.ciphertext_index_entries.len(), 1);
        assert!(expected_plan.nullifier_entries.is_empty());
        assert!(expected_plan.bridge_replay_entries.is_empty());
        {
            let state = node.state.read();
            assert_eq!(state.best, imported);
            assert_eq!(
                state.commitment_tree.leaf_count(),
                expected_plan.commitment_entries.len() as u64
            );
            assert!(state.pending_actions.is_empty());
            assert!(state.nullifiers.is_empty());
            assert!(state.consumed_bridge_messages.is_empty());
        }
        node.db.flush().expect("flush imported native block");
        (imported, expected_plan)
    };

    let reopened = NativeNode::open(config).expect("reopen node");
    assert_eq!(reopened.best_meta(), imported);
    let reopened_chain = reopened
        .chain_to_hash(imported.hash)
        .expect("load reopened canonical chain");
    let reopened_plan = plan_canonical_index_rebuild(
        &reopened_chain,
        &reopened.da_ciphertext_tree,
        Some(&reopened.ciphertext_archive_tree),
    )
    .expect("canonical plan after startup replay");
    assert_canonical_index_plans_eq("startup replay publication", &reopened_plan, &expected_plan);
    assert!(
        reopened
            .canonical_index_matches_plan(&expected_plan)
            .expect("compare reopened canonical indexes"),
        "startup-loaded canonical rows must match mined publication plan"
    );
    {
        let state = reopened.state.read();
        assert_eq!(state.best, imported);
        assert_eq!(
            state.commitment_tree.leaf_count(),
            expected_plan.commitment_entries.len() as u64
        );
        assert!(state.pending_actions.is_empty());
        assert!(state.nullifiers.is_empty());
        assert!(state.consumed_bridge_messages.is_empty());
    }
}

#[test]
fn transfer_state_rejects_zero_commitment_in_block() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [47u8; 48], [0u8; 48], 0);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("zero transfer commitment must reject block action");
    assert!(err.to_string().contains("zero commitment"));
}

#[test]
fn transfer_state_sidecar_requires_staged_ciphertext_in_mempool() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_sidecar_transfer_action(anchor, [48u8; 48], [49u8; 48], 0);

    let err = node
        .validate_action_state(&action)
        .expect_err("sidecar transfer without staged ciphertext must reject");
    assert!(err.to_string().contains("missing staged ciphertext"));
}

#[test]
fn transfer_state_sidecar_rejects_staged_ciphertext_size_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_sidecar_transfer_action(anchor, [50u8; 48], [51u8; 48], 0);
    {
        let mut state = node.state.write();
        state.staged_ciphertexts.insert(
            hex48(&action.ciphertext_hashes[0]),
            action.ciphertext_sizes[0].saturating_add(1),
        );
    }

    let err = node
        .validate_action_state(&action)
        .expect_err("sidecar transfer with wrong staged size must reject");
    assert!(err.to_string().contains("staged ciphertext size mismatch"));
}

#[test]
fn transfer_state_sidecar_accepts_matching_staged_ciphertext() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_sidecar_transfer_action(anchor, [52u8; 48], [53u8; 48], 0);
    {
        let mut state = node.state.write();
        state.staged_ciphertexts.insert(
            hex48(&action.ciphertext_hashes[0]),
            action.ciphertext_sizes[0],
        );
    }

    node.validate_action_state(&action)
        .expect("matching staged sidecar ciphertext should pass state admission");
}

#[test]
fn transfer_state_rejects_unauthorized_stablecoin_policy_in_mempool() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let action = test_inline_transfer_action_with_stablecoin(
        anchor,
        [54u8; 48],
        [55u8; 48],
        0,
        Some(test_stablecoin_policy_binding(10)),
    );

    let err = node
        .validate_action_state(&action)
        .expect_err("unauthorized stablecoin policy must reject mempool state admission");
    assert!(err.to_string().contains("stablecoin policy unauthorized"));
}

#[test]
fn stablecoin_policy_manifest_authorization_accepts_exact_active_policy() {
    let height = 20;
    let (entry, binding) = test_manifest_authorized_stablecoin_policy(10, height);

    assert!(native_stablecoin_policy_binding_authorized_by_entries(
        height,
        &binding,
        &[entry]
    ));
}

#[test]
fn stablecoin_policy_manifest_authorization_uses_live_duplicate_candidate() {
    let height = 20;
    let (live, binding) = test_manifest_authorized_stablecoin_policy(10, height);

    let mut retired = live.clone();
    retired.retired_at = Some(height);
    assert!(
        native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &binding,
            &[retired, live.clone()]
        ),
        "retired duplicate must not mask a later live policy"
    );

    let mut not_yet_enabled = live.clone();
    not_yet_enabled.enabled_at = height.saturating_add(1);
    assert!(
        native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &binding,
            &[not_yet_enabled, live]
        ),
        "not-yet-enabled duplicate must not mask a later live policy"
    );
}

#[test]
fn stablecoin_policy_manifest_authorization_rejects_invalid_records() {
    let height = 20;
    let (entry, binding) = test_manifest_authorized_stablecoin_policy(11, height);
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(height, &binding, &[]),
        "missing policy must reject"
    );

    let mut inactive = entry.clone();
    inactive.active = false;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(height, &binding, &[inactive]),
        "inactive policy must reject"
    );

    let mut not_yet_enabled = entry.clone();
    not_yet_enabled.enabled_at = height.saturating_add(1);
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &binding,
            &[not_yet_enabled]
        ),
        "not-yet-enabled policy must reject"
    );

    let mut retired = entry.clone();
    retired.retired_at = Some(height);
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(height, &binding, &[retired]),
        "retired policy must reject at and after retired_at"
    );

    let mut stale = entry.clone();
    stale.oracle_submitted_at = height
        .saturating_sub(stale.oracle_max_age)
        .saturating_sub(1);
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(height, &binding, &[stale]),
        "stale oracle commitment must reject"
    );

    let mut disputed = entry.clone();
    disputed.attestation_disputed = true;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(height, &binding, &[disputed]),
        "disputed attestation must reject"
    );

    let mut over_limit = binding.clone();
    over_limit.issuance_delta = entry.max_mint_per_epoch as i128 + 1;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &over_limit,
            std::slice::from_ref(&entry)
        ),
        "issuance above policy limit must reject"
    );

    let mut zero_issuance = binding.clone();
    zero_issuance.issuance_delta = 0;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &zero_issuance,
            std::slice::from_ref(&entry)
        ),
        "zero issuance must reject"
    );

    let mut bad_hash = binding.clone();
    bad_hash.policy_hash[0] ^= 1;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &bad_hash,
            std::slice::from_ref(&entry)
        ),
        "policy hash mismatch must reject"
    );

    let mut bad_oracle = binding.clone();
    bad_oracle.oracle_commitment[0] ^= 1;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &bad_oracle,
            std::slice::from_ref(&entry)
        ),
        "oracle commitment mismatch must reject"
    );

    let mut bad_attestation = binding.clone();
    bad_attestation.attestation_commitment[0] ^= 1;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &bad_attestation,
            std::slice::from_ref(&entry)
        ),
        "attestation commitment mismatch must reject"
    );

    let mut bad_version = binding.clone();
    bad_version.policy_version ^= 1;
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(
            height,
            &bad_version,
            std::slice::from_ref(&entry)
        ),
        "policy version mismatch must reject"
    );

    let mut bad_asset = binding;
    bad_asset.asset_id = bad_asset.asset_id.saturating_add(1);
    assert!(
        !native_stablecoin_policy_binding_authorized_by_entries(height, &bad_asset, &[entry]),
        "asset mismatch against a known policy hash must reject"
    );
}

#[test]
fn transfer_state_accepts_authorized_stablecoin_policy_in_mempool() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let binding = test_stablecoin_policy_binding(10);
    let action = test_inline_transfer_action_with_stablecoin(
        anchor,
        [59u8; 48],
        [60u8; 48],
        0,
        Some(binding.clone()),
    );
    {
        let mut state = node.state.write();
        authorize_test_stablecoin_policy(&mut state, &binding);
    }

    node.validate_action_state(&action)
        .expect("authorized stablecoin policy should pass mempool state admission");
}

#[test]
fn apply_planned_actions_clears_staged_sidecar_markers() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let action =
        test_sidecar_transfer_action(state.commitment_tree.root(), [56u8; 48], [57u8; 48], 0);
    state.staged_ciphertexts.insert(
        hex48(&action.ciphertext_hashes[0]),
        action.ciphertext_sizes[0],
    );
    state.pending_actions.insert(action.tx_hash, action.clone());
    let planned = vec![NativePlannedActionEffect {
        commitment_start: state.commitment_tree.leaf_count(),
        ciphertexts: vec![test_transfer_ciphertext_bytes()],
        replay_key: None,
    }];

    apply_planned_actions_to_memory(&mut state, std::slice::from_ref(&action), &planned)
        .expect("apply planned sidecar action");

    assert!(!state.pending_actions.contains_key(&action.tx_hash));
    assert!(!state
        .staged_ciphertexts
        .contains_key(&hex48(&action.ciphertext_hashes[0])));
}

#[test]
fn apply_planned_actions_rejects_plan_length_mismatch() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [63u8; 48], [64u8; 48], 0);
    let before_leaf_count = state.commitment_tree.leaf_count();
    let before_root = state.commitment_tree.root();

    let err = apply_planned_actions_to_memory(&mut state, &[action], &[])
        .expect_err("missing plan entry must reject");

    assert!(err.to_string().contains("plan_length_mismatch"));
    assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
    assert_eq!(state.commitment_tree.root(), before_root);
}

#[test]
fn apply_planned_actions_rejects_planned_start_mismatch() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [65u8; 48], [66u8; 48], 0);
    let before_leaf_count = state.commitment_tree.leaf_count();
    let before_root = state.commitment_tree.root();
    let planned = vec![NativePlannedActionEffect {
        commitment_start: before_leaf_count.saturating_add(1),
        ciphertexts: vec![test_transfer_ciphertext_bytes()],
        replay_key: None,
    }];

    let err = apply_planned_actions_to_memory(&mut state, &[action], &planned)
        .expect_err("wrong planned start must reject");

    assert!(err.to_string().contains("planned_start_mismatch"));
    assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
    assert_eq!(state.commitment_tree.root(), before_root);
}

#[test]
fn apply_planned_actions_rejects_ciphertext_hash_projection_mismatch() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let action = test_inline_transfer_action(anchor, [67u8; 48], [68u8; 48], 0);
    let before_leaf_count = state.commitment_tree.leaf_count();
    let before_root = state.commitment_tree.root();
    let mut ciphertext = test_transfer_ciphertext_bytes();
    ciphertext[0] ^= 1;
    let planned = vec![NativePlannedActionEffect {
        commitment_start: before_leaf_count,
        ciphertexts: vec![ciphertext],
        replay_key: None,
    }];

    let err = apply_planned_actions_to_memory(&mut state, &[action], &planned)
        .expect_err("planned ciphertext hash drift must reject");

    assert!(err.to_string().contains("ciphertext_hash_mismatch"));
    assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
    assert_eq!(state.commitment_tree.root(), before_root);
}

#[test]
fn apply_planned_actions_rejects_replay_key_projection_mismatch() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let action = test_inbound_bridge_action(b"wire replay key mismatch");
    let before_leaf_count = state.commitment_tree.leaf_count();
    let before_root = state.commitment_tree.root();
    let planned = vec![NativePlannedActionEffect {
        commitment_start: before_leaf_count,
        ciphertexts: Vec::new(),
        replay_key: Some([99u8; 48]),
    }];

    let err = apply_planned_actions_to_memory(&mut state, &[action], &planned)
        .expect_err("planned replay key drift must reject");

    assert!(err.to_string().contains("replay_key_mismatch"));
    assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
    assert_eq!(state.commitment_tree.root(), before_root);
    assert!(state.consumed_bridge_messages.is_empty());
}

#[test]
fn apply_planned_actions_rejects_commitment_batch_overflow_atomically() {
    let pow_bits = 0x207f_ffff;
    let mut state = test_state(genesis_meta(pow_bits).expect("genesis"));
    state.commitment_tree =
        CommitmentTreeState::new_empty(1, consensus::DEFAULT_ROOT_HISTORY_LIMIT)
            .expect("small commitment tree");
    state
        .commitment_tree
        .append([11u8; 48])
        .expect("prefill first leaf");
    let anchor = state.commitment_tree.root();
    let first = test_inline_transfer_action(anchor, [69u8; 48], [70u8; 48], 0);
    let second = test_inline_transfer_action(anchor, [71u8; 48], [72u8; 48], 0);
    state.pending_actions.insert(first.tx_hash, first.clone());
    state.pending_actions.insert(second.tx_hash, second.clone());
    let before_leaf_count = state.commitment_tree.leaf_count();
    let before_root = state.commitment_tree.root();
    let planned = vec![
        NativePlannedActionEffect {
            commitment_start: before_leaf_count,
            ciphertexts: vec![test_transfer_ciphertext_bytes()],
            replay_key: None,
        },
        NativePlannedActionEffect {
            commitment_start: before_leaf_count + 1,
            ciphertexts: vec![test_transfer_ciphertext_bytes()],
            replay_key: None,
        },
    ];

    let err =
        apply_planned_actions_to_memory(&mut state, &[first.clone(), second.clone()], &planned)
            .expect_err("commitment batch overflow must reject atomically");

    assert!(
        err.to_string()
            .contains("append native commitment batch failed"),
        "unexpected apply error: {err}"
    );
    assert_eq!(state.commitment_tree.leaf_count(), before_leaf_count);
    assert_eq!(state.commitment_tree.root(), before_root);
    assert!(state.nullifiers.is_empty());
    assert!(state.pending_actions.contains_key(&first.tx_hash));
    assert!(state.pending_actions.contains_key(&second.tx_hash));
}

#[test]
fn mined_commit_removes_pending_sidecar_ciphertext() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let parent = node.best_meta();
    let action = test_sidecar_transfer_action(parent.state_root, [58u8; 48], [59u8; 48], 0);
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
    assert!(node
        .da_ciphertext_tree
        .get(action.ciphertext_hashes[0])
        .expect("read staged sidecar")
        .is_some());
    let mut meta = mined_empty_child(&parent, 1, pow_bits, 0);
    meta.action_bytes = vec![action.encode()];
    meta.tx_count = 1;
    let planned = vec![NativePlannedActionEffect {
        commitment_start: 0,
        ciphertexts: vec![test_transfer_ciphertext_bytes()],
        replay_key: None,
    }];

    node.commit_mined_block_atomically(std::slice::from_ref(&action), &planned, &meta)
        .expect("commit sidecar action");

    assert!(node
        .da_ciphertext_tree
        .get(action.ciphertext_hashes[0])
        .expect("read staged sidecar after commit")
        .is_none());
}

#[test]
fn mined_commit_rejects_meta_action_bytes_not_matching_planned_actions() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let parent = node.best_meta();
    let action = test_sidecar_transfer_action(parent.state_root, [60u8; 48], [61u8; 48], 0);
    let substitute = test_sidecar_transfer_action(parent.state_root, [62u8; 48], [63u8; 48], 0);
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
    let mut meta = mined_empty_child(&parent, 1, pow_bits, 0);
    meta.action_bytes = vec![substitute.encode()];
    meta.tx_count = 1;
    let planned = vec![NativePlannedActionEffect {
        commitment_start: 0,
        ciphertexts: vec![test_transfer_ciphertext_bytes()],
        replay_key: None,
    }];

    let err = node
        .commit_mined_block_atomically(std::slice::from_ref(&action), &planned, &meta)
        .expect_err("mismatched mined action bytes must reject before sled mutation");

    assert!(
        err.to_string()
            .contains("native mined block action bytes mismatch committed actions"),
        "unexpected commit error: {err}"
    );
    assert!(node
        .block_tree
        .get(meta.hash)
        .expect("read rejected block record")
        .is_none());
    assert_eq!(node.best_meta(), parent);
    assert_eq!(node.commitment_tree.len(), 0);
    assert_eq!(node.ciphertext_archive_tree.len(), 0);
    assert!(node
        .da_ciphertext_tree
        .get(action.ciphertext_hashes[0])
        .expect("read staged sidecar after rejected commit")
        .is_some());
}

#[test]
fn mined_commit_rejects_ciphertext_hash_size_count_mismatch_before_sled_mutation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let parent = node.best_meta();
    let mut action = test_sidecar_transfer_action(parent.state_root, [66u8; 48], [67u8; 48], 0);
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
    action.ciphertext_sizes.clear();
    action.tx_hash = pending_action_hash(&action);

    let mut meta = mined_empty_child(&parent, 1, pow_bits, 0);
    meta.action_bytes = vec![action.encode()];
    meta.tx_count = 1;
    let planned = vec![NativePlannedActionEffect {
        commitment_start: 0,
        ciphertexts: vec![test_transfer_ciphertext_bytes()],
        replay_key: None,
    }];

    let err = node
        .commit_mined_block_atomically(std::slice::from_ref(&action), &planned, &meta)
        .expect_err("mismatched ciphertext metadata must reject before sled mutation");

    assert!(
        err.to_string()
            .contains("native mined block ciphertext metadata count mismatch"),
        "unexpected commit error: {err}"
    );
    assert!(node
        .block_tree
        .get(meta.hash)
        .expect("read rejected block record")
        .is_none());
    assert_eq!(node.best_meta(), parent);
    assert_eq!(node.commitment_tree.len(), 0);
    assert_eq!(node.ciphertext_archive_tree.len(), 0);
    assert_eq!(node.ciphertext_index_tree.len(), 0);
    assert!(node
        .da_ciphertext_tree
        .get(action.ciphertext_hashes[0])
        .expect("read staged sidecar after rejected commit")
        .is_some());
}

#[test]
fn committed_sidecar_replay_materializes_ciphertext_from_archive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let parent = node.best_meta();
    let action = test_sidecar_transfer_action(parent.state_root, [64u8; 48], [65u8; 48], 0);
    let expected_ciphertext = test_transfer_ciphertext_bytes();
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &action);
    let mut meta = mined_empty_child(&parent, 1, pow_bits, 0);
    meta.action_bytes = vec![action.encode()];
    meta.tx_count = 1;
    let planned = vec![NativePlannedActionEffect {
        commitment_start: 0,
        ciphertexts: vec![expected_ciphertext.clone()],
        replay_key: None,
    }];

    node.commit_mined_block_atomically(std::slice::from_ref(&action), &planned, &meta)
        .expect("commit sidecar action");
    assert!(node
        .da_ciphertext_tree
        .get(action.ciphertext_hashes[0])
        .expect("read staged sidecar after commit")
        .is_none());

    let replay_state = test_state(parent.clone());
    let materialized = materialize_native_action_payloads_from_state(
        &node.da_ciphertext_tree,
        Some(&node.ciphertext_archive_tree),
        &replay_state,
        std::slice::from_ref(&action),
    )
    .expect("materialize committed sidecar from canonical archive");
    assert_eq!(
        materialized[0].ciphertexts,
        vec![expected_ciphertext.clone()]
    );

    let mut applied = test_state(parent.clone());
    apply_actions_to_memory_with_archive(
        &node.da_ciphertext_tree,
        Some(&node.ciphertext_archive_tree),
        &mut applied,
        std::slice::from_ref(&action),
    )
    .expect("replay committed sidecar from canonical archive");
    assert_eq!(applied.commitment_tree.leaf_count(), 1);
    assert_eq!(applied.nullifiers, BTreeSet::from([action.nullifiers[0]]));

    let plan = plan_canonical_index_rebuild(
        &[parent, meta],
        &node.da_ciphertext_tree,
        Some(&node.ciphertext_archive_tree),
    )
    .expect("rebuild canonical rows from archived sidecar");
    assert_eq!(
        plan.ciphertext_archive_entries,
        vec![(0, expected_ciphertext)]
    );
    assert_eq!(plan.ciphertext_index_entries.len(), 1);
}

#[test]
fn transfer_action_validation_requires_shielded_family() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [5u8; 48], [55u8; 48], 0);
    action.family_id = FAMILY_SHIELDED_POOL.saturating_add(99);
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("non-shielded family must not be accepted as a transfer");
    assert!(err.to_string().contains("not a shielded transfer"));
}

#[test]
fn candidate_artifact_payload_is_candidate_action_scoped() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [6u8; 48], [66u8; 48], 0);
    action.candidate_artifact = Some(test_candidate_artifact(1));
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("transfer action must not carry candidate artifact payload");
    assert!(err.to_string().contains("candidate artifact payload"));
}

#[test]
fn candidate_artifact_action_carries_no_state_deltas() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let mut action = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
    action.candidate_artifact = Some(test_candidate_artifact(1));
    action.commitments.push([77u8; 48]);
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("candidate artifact action must not carry commitments");
    assert!(err.to_string().contains("state deltas"));
}

#[test]
fn candidate_artifact_action_requires_payload() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let mut action = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
    action.public_args = SubmitCandidateArtifactArgs {
        payload: test_candidate_artifact(1),
    }
    .encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("candidate artifact action must carry a payload");
    assert!(err.to_string().contains("missing payload"));
}

#[test]
fn candidate_artifact_action_rejects_malformed_route_payload() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let mut action = test_candidate_artifact_action(1, 9);
    action.public_args.push(0xaa);
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("candidate artifact route payload must exact-decode");
    assert!(err.to_string().contains("args must decode exactly"));
}

#[test]
fn candidate_artifact_action_rejects_route_payload_artifact_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let mut action = test_candidate_artifact_action(1, 10);
    let mut mismatched = test_candidate_artifact(1);
    mismatched.tx_statements_commitment = [11u8; 48];
    mismatched.da_root = [12u8; 48];
    action.public_args = SubmitCandidateArtifactArgs {
        payload: mismatched,
    }
    .encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("candidate artifact route payload must match action payload");
    assert!(err.to_string().contains("do not match"));
}

#[test]
fn candidate_artifact_rejects_legacy_recursive_v1_route() {
    let mut artifact = test_candidate_artifact(1);
    artifact.proof_kind = PoolProofArtifactKind::RecursiveBlockV1;

    let err = validate_candidate_artifact(&artifact)
        .expect_err("native candidate artifacts must use the shipped v2 route");
    assert!(err.to_string().contains("recursive_block_v2"));
}

#[test]
fn candidate_artifact_rejects_custom_proof_kind_route() {
    let mut artifact = test_candidate_artifact(1);
    artifact.proof_kind = PoolProofArtifactKind::Custom([0x42u8; 16]);

    let err = validate_candidate_artifact(&artifact)
        .expect_err("native candidate artifacts must reject custom proof artifact routes");
    assert!(err.to_string().contains("recursive_block_v2"));
}

#[test]
fn candidate_artifact_rejects_zero_tx_count() {
    let artifact = test_candidate_artifact(0);

    let err = validate_candidate_artifact(&artifact)
        .expect_err("native candidate artifacts must bind at least one tx");
    assert!(err.to_string().contains("tx_count must be non-zero"));
}

#[test]
fn candidate_artifact_rejects_wrong_verifier_profile() {
    let mut artifact = test_candidate_artifact(1);
    artifact.verifier_profile = [0x77u8; 48];

    let err = validate_candidate_artifact(&artifact)
        .expect_err("native candidate artifacts must bind shipped verifier profile");
    assert!(err.to_string().contains("verifier profile mismatch"));
}

#[test]
fn candidate_artifact_rejects_oversized_recursive_proof() {
    let mut artifact = test_candidate_artifact(1);
    artifact
        .recursive_block
        .as_mut()
        .expect("test recursive payload")
        .proof
        .data = vec![0x42u8; RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE + 1];

    let err = validate_candidate_artifact(&artifact)
        .expect_err("oversized recursive candidate proof must fail admission");
    assert!(err.to_string().contains("recursive proof size"));
}

#[test]
fn candidate_artifact_acceptance_projects_resource_bytes_to_bounded_request() {
    let artifact = test_candidate_artifact(1);
    let input = native_candidate_artifact_resource_projection_input(&artifact);
    assert_eq!(input.proof_bytes, 0);
    assert_eq!(input.receipt_bytes, 0);
    assert_eq!(input.recursive_bytes, 32);
    assert_eq!(input.tx_count, 1);
    assert_eq!(input.da_chunk_count, 1);

    let bounded = native_candidate_artifact_resource_bounded_request(input);
    assert_eq!(bounded.raw_bytes, input.declared_bytes);
    assert_eq!(bounded.decoded_bytes, artifact.encoded_size());
    assert_eq!(bounded.item_count, input.tx_count);
    assert_eq!(bounded.max_item_bytes, input.recursive_bytes);
    assert_eq!(bounded.aggregate_bytes, input.recursive_bytes);
    assert_eq!(bounded.work_units, input.da_chunk_count);
    assert_eq!(evaluate_native_bounded_request_admission(bounded), Ok(()));
    validate_candidate_artifact(&artifact).expect("valid candidate artifact");
}

#[test]
fn candidate_artifact_resource_projection_rejects_proof_like_bytes_by_bounded_item_gate() {
    let input = NativeCandidateArtifactResourceProjectionInput {
        raw_byte_cap: 200,
        decoded_byte_cap: 1024,
        item_count_cap: MAX_BATCH_SIZE as usize,
        item_byte_cap: 512,
        aggregate_byte_cap: 600,
        work_unit_cap: usize::MAX,
        declared_bytes: 158,
        proof_bytes: 0,
        receipt_bytes: 0,
        recursive_bytes: 513,
        tx_count: 1,
        da_chunk_count: 1,
    };
    let bounded = native_candidate_artifact_resource_bounded_request(input);
    assert_eq!(
        evaluate_native_bounded_request_admission(bounded),
        Err(NativeBoundedRequestAdmissionRejection::ItemBytes)
    );
}

#[test]
fn candidate_artifact_requires_shielded_transfers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let action = test_candidate_artifact_action(1, 12);
    validate_block_actions_locked(&state, std::slice::from_ref(&action))
        .expect("candidate artifact payload is structurally valid");

    let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
    let err = verify_native_block_artifacts_locked(&node, &state, &[action], &meta)
        .expect_err("candidate artifact without transfers must be rejected");
    assert!(err.to_string().contains("requires shielded transfer"));
}

#[test]
fn shielded_transfer_requires_candidate_artifact() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let transfer =
        test_inline_transfer_action(state.commitment_tree.root(), [7u8; 48], [8u8; 48], 0);
    validate_block_actions_locked(&state, std::slice::from_ref(&transfer))
        .expect("transfer action is structurally valid");

    let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
    let err = verify_native_block_artifacts_locked(&node, &state, &[transfer], &meta)
        .expect_err("non-empty shielded block without candidate artifact must be rejected");
    assert!(err
        .to_string()
        .contains("requires exactly one matching recursive candidate artifact"));
}

#[test]
fn shielded_transfer_rejects_multiple_candidate_artifacts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let transfer =
        test_inline_transfer_action(state.commitment_tree.root(), [9u8; 48], [10u8; 48], 0);
    let first_candidate = test_candidate_artifact_action(1, 21);
    let second_candidate = test_candidate_artifact_action(1, 22);
    let actions = vec![transfer, first_candidate, second_candidate];
    validate_block_actions_locked(&state, &actions)
        .expect("multiple candidate artifacts are structurally valid before coupling");

    let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
    let err = verify_native_block_artifacts_locked(&node, &state, &actions, &meta)
        .expect_err("non-empty shielded block with multiple candidates must be rejected");
    assert!(err
        .to_string()
        .contains("requires exactly one matching recursive candidate artifact"));
}

#[test]
fn shielded_transfer_rejects_candidate_tx_count_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let transfer =
        test_inline_transfer_action(state.commitment_tree.root(), [11u8; 48], [12u8; 48], 0);
    let candidate = test_candidate_artifact_action(2, 23);
    let actions = vec![transfer, candidate];
    validate_block_actions_locked(&state, &actions)
        .expect("mismatched candidate artifact is structurally valid before coupling");

    let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
    let err = verify_native_block_artifacts_locked(&node, &state, &actions, &meta)
        .expect_err("candidate artifact tx_count mismatch must be rejected");
    assert!(err.to_string().contains("tx_count mismatch"));
}

#[test]
fn shielded_transfer_rejects_candidate_da_chunk_count_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let transfer =
        test_inline_transfer_action(state.commitment_tree.root(), [13u8; 48], [14u8; 48], 0);
    let materialized = materialize_native_action_payloads(
        &node.da_ciphertext_tree,
        std::slice::from_ref(&transfer),
    )
    .expect("materialize inline transfer");
    let (tx, _) = consensus_tx_and_artifact_from_action(&transfer, &materialized[0])
        .expect("build consensus transaction");
    let da_encoding = consensus::encode_da_blob(std::slice::from_ref(&tx), native_da_params())
        .expect("encode test DA blob");
    let expected_count =
        u32::try_from(da_encoding.chunks().len()).expect("test DA chunk count fits u32");

    let mut candidate = test_candidate_artifact_action(1, 24);
    {
        let artifact = candidate
            .candidate_artifact
            .as_mut()
            .expect("candidate artifact payload");
        artifact.da_root = da_encoding.root();
        artifact.da_chunk_count = expected_count
            .checked_add(1)
            .unwrap_or(expected_count.saturating_sub(1))
            .max(1);
        candidate.public_args = SubmitCandidateArtifactArgs {
            payload: artifact.clone(),
        }
        .encode();
    }
    candidate.tx_hash = pending_action_hash(&candidate);
    let actions = vec![transfer, candidate];
    validate_block_actions_locked(&state, &actions)
        .expect("DA count mismatch is a block artifact binding error");

    let meta = mined_empty_child(&state.best, 1, pow_bits, 0);
    let err = verify_native_block_artifacts_locked(&node, &state, &actions, &meta)
        .expect_err("candidate artifact DA chunk count mismatch must be rejected");
    assert!(
        err.to_string()
            .contains("candidate artifact DA chunk count mismatch"),
        "unexpected artifact verification error: {err}"
    );
}

#[test]
fn recursive_artifact_context_rejects_height_overflow() {
    let err = evaluate_native_recursive_artifact_context_admission(
        NativeRecursiveArtifactContextAdmissionInput {
            best_height: u64::MAX,
        },
    )
    .expect_err("max-height best state must not emit a recursive artifact context height");

    assert_eq!(
        err,
        NativeRecursiveArtifactContextAdmissionRejection::HeightNotNext
    );
}

#[test]
fn prepare_work_ignores_candidate_artifact_without_transfers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let mut action = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
    action.candidate_artifact = Some(test_candidate_artifact(1));
    action.tx_hash = pending_action_hash(&action);
    node.state
        .write()
        .pending_actions
        .insert(action.tx_hash, action);

    let work = node.prepare_work().expect("prepare native work");

    assert_eq!(work.tx_count, 0);
    assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
}

#[test]
fn prepare_work_drops_sidecar_transfer_without_staged_ciphertext() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [24u8; 48], [25u8; 48], 0);
    let candidate = test_candidate_artifact_action(1, 26);
    {
        let mut state = node.state.write();
        state.pending_actions.insert(transfer.tx_hash, transfer);
        state.pending_actions.insert(candidate.tx_hash, candidate);
    }

    let work = node.prepare_work().expect("prepare native work");

    assert_eq!(work.tx_count, 0);
    assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
}

#[test]
fn prepare_work_drops_sidecar_transfer_with_staged_size_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [27u8; 48], [28u8; 48], 0);
    let hash = transfer.ciphertext_hashes[0];
    let mismatched_size = transfer.ciphertext_sizes[0].saturating_add(1);
    let candidate = test_candidate_artifact_action(1, 29);
    {
        let mut state = node.state.write();
        state
            .staged_ciphertexts
            .insert(hex48(&hash), mismatched_size);
        state.pending_actions.insert(transfer.tx_hash, transfer);
        state.pending_actions.insert(candidate.tx_hash, candidate);
    }

    let work = node.prepare_work().expect("prepare native work");

    assert_eq!(work.tx_count, 0);
    assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
}

#[test]
fn prepare_work_keeps_sidecar_transfer_with_matching_staged_ciphertext() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let transfer = test_sidecar_transfer_action(anchor, [30u8; 48], [31u8; 48], 0);
    let hash = transfer.ciphertext_hashes[0];
    let size = transfer.ciphertext_sizes[0];
    let candidate = test_candidate_artifact_action(1, 32);
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, &transfer);
    {
        let mut state = node.state.write();
        state.staged_ciphertexts.insert(hex48(&hash), size);
        state.pending_actions.insert(transfer.tx_hash, transfer);
        state.pending_actions.insert(candidate.tx_hash, candidate);
    }

    let work = node.prepare_work().expect("prepare native work");

    assert_eq!(work.tx_count, 2);
}

#[test]
fn coinbase_action_carries_no_extra_state_deltas() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    stage_test_coinbase(&node, consensus::reward::block_subsidy(1), [88u8; 48]);
    let mut action = node
        .state
        .read()
        .pending_actions
        .values()
        .next()
        .cloned()
        .expect("pending coinbase");
    action.nullifiers.push([89u8; 48]);
    action.tx_hash = pending_action_hash(&action);
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("coinbase action must not carry nullifiers");
    assert!(err.to_string().contains("no other state deltas"));
}

#[test]
fn coinbase_action_rejects_zero_or_semantically_mismatched_commitment() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let subsidy = consensus::reward::block_subsidy(1);
    let mut action = test_coinbase_action(subsidy);
    let mut args: MintCoinbaseArgs =
        decode_scale_exact(&action.public_args, "coinbase action args")
            .expect("decode test coinbase args");
    args.reward_bundle.miner_note.commitment = [0u8; 48];
    action.commitments[0] = [0u8; 48];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("zero coinbase commitment must reject");
    assert!(err.to_string().contains("coinbase commitment mismatch"));
}

#[test]
fn coinbase_action_rejects_public_seed_commitment_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let subsidy = consensus::reward::block_subsidy(1);
    let mut action = test_coinbase_action(subsidy);
    let mut args: MintCoinbaseArgs =
        decode_scale_exact(&action.public_args, "coinbase action args")
            .expect("decode test coinbase args");
    args.reward_bundle.miner_note.public_seed[0] ^= 1;
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("coinbase public seed tamper must reject");
    assert!(err.to_string().contains("coinbase commitment mismatch"));
}

#[test]
fn coinbase_action_rejects_ciphertext_hash_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let subsidy = consensus::reward::block_subsidy(1);
    let mut action = test_coinbase_action(subsidy);
    action.ciphertext_hashes[0][0] ^= 1;
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("coinbase ciphertext hash mismatch must reject");
    assert!(err.to_string().contains("ciphertext hash mismatch"));
}

#[test]
fn coinbase_action_rejects_ciphertext_size_mismatch() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let subsidy = consensus::reward::block_subsidy(1);
    let mut action = test_coinbase_action(subsidy);
    action.ciphertext_sizes[0] = action.ciphertext_sizes[0].saturating_add(1);
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("coinbase ciphertext size mismatch must reject");
    assert!(err.to_string().contains("ciphertext size mismatch"));
}

#[test]
fn coinbase_action_rejects_oversized_ciphertext() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let subsidy = consensus::reward::block_subsidy(1);
    let mut action = test_coinbase_action(subsidy);
    let mut args: MintCoinbaseArgs =
        decode_scale_exact(&action.public_args, "coinbase action args")
            .expect("decode test coinbase args");
    args.reward_bundle.miner_note.encrypted_note.kem_ciphertext =
        vec![0x55u8; MAX_CIPHERTEXT_BYTES + 1];
    let total_len = args
        .reward_bundle
        .miner_note
        .encrypted_note
        .ciphertext
        .len()
        .saturating_add(
            args.reward_bundle
                .miner_note
                .encrypted_note
                .kem_ciphertext
                .len(),
        );
    action.public_args = args.encode();
    action.ciphertext_hashes[0] = NATIVE_EMPTY_DIGEST48;
    action.ciphertext_sizes[0] = u32::try_from(total_len).unwrap_or(u32::MAX);
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("oversized coinbase ciphertext must reject");
    assert!(err.to_string().contains("coinbase ciphertext size"));
    assert!(err.to_string().contains("exceeds limit"));
}

#[test]
fn transfer_action_requires_ciphertext_metadata_shape() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let anchor = state.commitment_tree.root();
    let mut action = test_inline_transfer_action(anchor, [91u8; 48], [92u8; 48], 0);
    action.ciphertext_sizes.clear();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("transfer action metadata shape must match commitments");
    assert!(err.to_string().contains("invalid public metadata shape"));
}

#[test]
fn bridge_action_carries_no_state_deltas() {
    let pow_bits = 0x207f_ffff;
    let state = test_state(genesis_meta(pow_bits).expect("genesis"));
    let mut action = test_outbound_bridge_action(b"bridge fee smuggle");
    action.fee = 1;
    action.anchor = [90u8; 48];
    action.tx_hash = pending_action_hash(&action);

    let err = validate_block_actions_locked(&state, &[action])
        .expect_err("bridge action must not carry fee or anchor deltas");
    assert!(err.to_string().contains("state deltas"));
}

#[test]
fn bridge_outbound_payload_must_be_non_empty() {
    let action = test_outbound_bridge_action(b"");

    let err = validate_bridge_action_payload(&action)
        .expect_err("empty outbound bridge payload must be rejected");
    assert!(err.to_string().contains("payload must be non-empty"));
}

#[test]
fn bridge_inbound_proof_receipt_must_be_non_empty() {
    let mut action = test_inbound_bridge_action(b"inbound payload");
    let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge test args");
    args.proof_receipt.clear();
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_bridge_action_payload(&action)
        .expect_err("empty inbound bridge receipt must be rejected before receipt decode");
    assert!(err.to_string().contains("proof receipt must be non-empty"));
}

#[test]
fn bridge_inbound_replay_key_must_match_message() {
    let mut action = test_inbound_bridge_action(b"inbound payload");
    let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge test args");
    args.source_message_nonce = args.source_message_nonce.saturating_add(1);
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_bridge_action_payload(&action)
        .expect_err("inbound bridge replay key mismatch must be rejected before receipt verify");
    assert!(err.to_string().contains("replay key does not match"));
}

#[test]
fn bridge_inbound_destination_must_be_hegemon() {
    let mut action = test_inbound_bridge_action(b"inbound payload");
    let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge test args");
    args.message.destination_chain_id = [19u8; 32];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_bridge_action_payload(&action)
        .expect_err("wrong inbound bridge destination must be rejected before receipt verify");
    assert!(err.to_string().contains("not addressed to Hegemon"));
}

#[test]
fn bridge_inbound_payload_hash_must_match_payload() {
    let mut action = test_inbound_bridge_action(b"inbound payload");
    let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge test args");
    args.message.payload_hash = [29u8; 48];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_bridge_action_payload(&action)
        .expect_err("wrong inbound bridge payload hash must be rejected before receipt verify");
    assert!(err.to_string().contains("payload hash mismatch"));
}

#[test]
fn bridge_inbound_resource_projection_uses_native_caps() {
    let action = test_inbound_bridge_action(b"inbound payload");
    let args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge test args");
    let input = native_bridge_action_resource_projection_input(
        NativeBridgeActionPayloadKind::Inbound,
        action.public_args.len(),
        0,
        args.proof_receipt.len(),
        args.message.payload.len(),
    );
    assert_eq!(input.raw_byte_cap, MAX_NATIVE_RPC_ACTION_BYTES);
    assert_eq!(input.decoded_byte_cap, MAX_NATIVE_RPC_ACTION_BYTES);
    assert_eq!(input.item_count_cap, 2);
    assert_eq!(input.item_byte_cap, MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES);
    assert_eq!(
        input.aggregate_byte_cap,
        MAX_NATIVE_BRIDGE_ACTION_DYNAMIC_BYTES
    );
    assert_eq!(input.work_unit_cap, MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES);

    let bounded = bridge_action_resource_bounded_request(input);
    assert_eq!(bounded.raw_bytes, action.public_args.len());
    assert_eq!(bounded.decoded_bytes, action.public_args.len());
    assert_eq!(bounded.item_count, 2);
    assert_eq!(
        bounded.max_item_bytes,
        args.proof_receipt.len().max(args.message.payload.len())
    );
    assert_eq!(
        bounded.aggregate_bytes,
        args.proof_receipt.len() + args.message.payload.len()
    );
    assert_eq!(bounded.work_units, args.message.payload.len());
    assert_eq!(evaluate_native_bounded_request_admission(bounded), Ok(()));
}

#[test]
fn bridge_inbound_proof_receipt_resource_rejects_before_receipt_decode_or_verify() {
    let mut action = test_inbound_bridge_action(b"inbound payload");
    let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge test args");
    args.proof_receipt = vec![0x42; MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES + 1];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_bridge_action_payload(&action)
        .expect_err("oversized inbound bridge receipt must reject before receipt decode");
    let err = err.to_string();
    assert!(
        err.contains("proof receipt or payload item byte count"),
        "unexpected error: {err}"
    );
    assert!(err.contains("exceeds cap"), "unexpected error: {err}");
    assert!(
        !err.contains("RISC Zero"),
        "oversized receipt reached nested receipt decode/verify: {err}"
    );
}

#[test]
fn bridge_inbound_message_payload_resource_rejects_before_receipt_verify() {
    let oversized_payload = vec![0x2a; MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES + 1];
    let mut action = test_inbound_bridge_action(&oversized_payload);
    let mut args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge test args");
    args.message.payload_hash = [0x33; 48];
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(&action);

    let err = validate_bridge_action_payload(&action).expect_err(
            "oversized inbound bridge message payload must reject before payload-hash or receipt verify",
        );
    let err = err.to_string();
    assert!(
        err.contains("message payload byte count"),
        "unexpected error: {err}"
    );
    assert!(err.contains("exceeds cap"), "unexpected error: {err}");
    assert!(
        !err.contains("payload hash mismatch"),
        "oversized payload reached payload hash binding before resource gate: {err}"
    );
    assert!(
        !err.contains("verification is disabled"),
        "oversized payload reached receipt verifier: {err}"
    );
}

#[test]
fn verified_inbound_bridge_receipt_requires_mint_replay_policy_state_and_authorization() {
    let payload = test_bridge_mint_payload_bytes();
    let action = test_disabled_risc0_inbound_bridge_action(&payload);
    let args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge args");
    let output = test_bridge_checkpoint_output_for_message(&args.message);

    let err = enforce_verified_inbound_bridge_mint_replay_policy(&action, &args, &output, None)
        .expect_err("verified bridge receipt must require replay state");
    assert!(err.to_string().contains("replay state is required"));

    let replay_state = InboundReplayState::default();
    let err = enforce_verified_inbound_bridge_mint_replay_policy(
        &action,
        &args,
        &output,
        Some(replay_state),
    )
    .expect_err("verified bridge receipt must still require explicit mint authorization");
    assert!(err.to_string().contains("mint authorization is disabled"));
    assert!(err.to_string().contains("mint_not_authorized"));

    let replay_key = inbound_replay_key(args.source_chain_id, args.source_message_nonce);
    let consumed_replay_state =
        InboundReplayState::new(BTreeSet::from([replay_key]), BTreeSet::new());
    let err = enforce_verified_inbound_bridge_mint_replay_policy(
        &action,
        &args,
        &output,
        Some(consumed_replay_state),
    )
    .expect_err("consumed bridge replay key must reject before mint authorization");
    assert!(err.to_string().contains("already consumed"));
    assert!(err.to_string().contains("replay_already_consumed"));

    let mut mismatched_output = output;
    mismatched_output.message_hash = [0x5au8; 48];
    let err = enforce_verified_inbound_bridge_mint_replay_policy(
        &action,
        &args,
        &mismatched_output,
        Some(InboundReplayState::default()),
    )
    .expect_err("receipt/message mismatch must reject through mint payload admission");
    assert!(err.to_string().contains("receipt/message hash mismatch"));
    assert!(err.to_string().contains("receipt_message_hash_mismatch"));
}

#[test]
fn verified_inbound_bridge_receipt_requires_exact_mint_payload() {
    let action = test_disabled_risc0_inbound_bridge_action(b"not a SCALE mint payload");
    let args = InboundBridgeArgsV1::decode(&mut &action.public_args[..])
        .expect("decode inbound bridge args");
    let output = test_bridge_checkpoint_output_for_message(&args.message);

    let err = enforce_verified_inbound_bridge_mint_replay_policy(
        &action,
        &args,
        &output,
        Some(InboundReplayState::default()),
    )
    .expect_err("malformed bridge mint payload must reject before mint policy");
    assert!(err.to_string().contains("exact decode failed"));
    assert!(err.to_string().contains("payload_decode_failed"));
}

#[test]
fn bridge_mint_payload_admission_rejects_invalid_payload_fields() {
    let base = test_bridge_mint_payload(42, transaction_core::constants::NATIVE_ASSET_ID + 7, 0x42);

    let mut zero_amount = base.clone();
    zero_amount.amount = 0;
    let input = bridge_mint_payload_admission_input_from_payload(&zero_amount);
    let rejection = evaluate_native_bridge_mint_payload_admission(input)
        .expect_err("zero bridge mint amount must reject");
    assert_eq!(
        rejection,
        NativeBridgeMintPayloadAdmissionRejection::AmountZero
    );

    let mut over_bound = base.clone();
    over_bound.amount = MAX_NATIVE_BRIDGE_MINT_AMOUNT + 1;
    let input = bridge_mint_payload_admission_input_from_payload(&over_bound);
    let rejection = evaluate_native_bridge_mint_payload_admission(input)
        .expect_err("over-bound bridge mint amount must reject");
    assert_eq!(
        rejection,
        NativeBridgeMintPayloadAdmissionRejection::AmountOutOfBounds
    );

    let mut native_asset = base.clone();
    native_asset.asset_id = transaction_core::constants::NATIVE_ASSET_ID;
    let input = bridge_mint_payload_admission_input_from_payload(&native_asset);
    let rejection = evaluate_native_bridge_mint_payload_admission(input)
        .expect_err("native-asset bridge mint payload must reject");
    assert_eq!(
        rejection,
        NativeBridgeMintPayloadAdmissionRejection::NativeAssetNotAllowed
    );

    let mut wrong_nonce = base;
    wrong_nonce.mint_nonce = 43;
    let input = bridge_mint_payload_admission_input_from_payload(&wrong_nonce);
    let rejection = evaluate_native_bridge_mint_payload_admission(input)
        .expect_err("mint nonce must bind the inbound replay key");
    assert_eq!(
        rejection,
        NativeBridgeMintPayloadAdmissionRejection::MintNonceMismatch
    );
}

#[test]
fn bridge_mint_payload_admission_rejects_wrong_source_app_family() {
    let payload =
        test_bridge_mint_payload(42, transaction_core::constants::NATIVE_ASSET_ID + 7, 0x42);
    let payload_bytes = payload.encode();
    let mut args = test_disabled_risc0_bridge_inbound_args(&payload_bytes);
    args.message.app_family_id = BRIDGE_MINT_APP_FAMILY_ID_V1.saturating_add(1);
    let output = test_bridge_checkpoint_output_for_message(&args.message);
    let input = bridge_mint_payload_admission_input(&args, &output, Some(&payload));

    let rejection = evaluate_native_bridge_mint_payload_admission(input)
        .expect_err("bridge mint payload must bind the source app family");
    assert_eq!(
        rejection,
        NativeBridgeMintPayloadAdmissionRejection::SourceAppFamilyMismatch
    );
}

#[test]
fn bridge_mint_policy_authorization_precedes_fresh_replay_import() {
    let replay_key = [0x4du8; 48];
    let replay_state = InboundReplayState::new(BTreeSet::new(), BTreeSet::from([replay_key]));
    let input = NativeBridgeMintReplayPolicyInput {
        inbound_bridge_mint: true,
        state_deltas_absent: true,
        receipt_envelope_present: true,
        receipt_verified: true,
        receipt_payload_matches: true,
        replay_state: replay_state.clone(),
        replay_key,
        mint_authorized: false,
        amount_matches_receipt: true,
        amount_within_bound: true,
    };

    let rejection = evaluate_native_bridge_mint_replay_policy(input)
        .expect_err("disabled mint authorization must reject before replay import");
    assert_eq!(
        rejection,
        NativeBridgeMintReplayPolicyRejection::MintNotAuthorized
    );
    assert!(replay_state.pending().contains(&replay_key));
    assert!(!replay_state.consumed().contains(&replay_key));
}

#[test]
fn bridge_mint_policy_consumed_replay_still_precedes_authorization() {
    let replay_key = [0x5eu8; 48];
    let input = NativeBridgeMintReplayPolicyInput {
        inbound_bridge_mint: true,
        state_deltas_absent: true,
        receipt_envelope_present: true,
        receipt_verified: true,
        receipt_payload_matches: true,
        replay_state: InboundReplayState::new(BTreeSet::from([replay_key]), BTreeSet::new()),
        replay_key,
        mint_authorized: false,
        amount_matches_receipt: true,
        amount_within_bound: true,
    };

    let rejection = evaluate_native_bridge_mint_replay_policy(input)
        .expect_err("consumed replay key must reject before disabled authorization");
    assert_eq!(
        rejection,
        NativeBridgeMintReplayPolicyRejection::ReplayAlreadyConsumed
    );
}

#[test]
fn submit_action_routes_bridge_payload_admission_before_staging() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let node =
        NativeNode::open(test_config(tmp.path(), 0x207f_ffff, "unsafe", false)).expect("node");
    let outbound = OutboundBridgeArgsV1 {
        destination_chain_id: [41u8; 32],
        app_family_id: 77,
        payload: Vec::new(),
    };
    let err = node
        .validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_OUTBOUND,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(outbound.encode()),
        }))
        .expect_err("empty outbound bridge payload must reject before staging");
    assert!(err.to_string().contains("payload must be non-empty"));
    assert_eq!(node.state.read().pending_actions.len(), 0);

    let mut inbound = test_disabled_risc0_bridge_inbound_args(b"bound bridge payload");
    inbound.proof_receipt.clear();
    let err = node
        .validate_and_stage_action(json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_INBOUND,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(inbound.encode()),
        }))
        .expect_err("empty inbound bridge receipt must reject before staging");
    assert!(err.to_string().contains("proof receipt must be non-empty"));
    assert_eq!(node.state.read().pending_actions.len(), 0);
}

#[test]
fn bridge_messages_reject_malformed_outbound_payload() {
    let bad = malformed_outbound_bridge_action(b"malformed bridge message");
    let good = test_outbound_bridge_action(b"good bridge message after malformed one");

    let err = bridge_messages_from_actions(&[bad, good], 1)
        .expect_err("malformed outbound bridge args must reject");

    assert!(err.to_string().contains("outbound bridge action args"));
}

#[test]
fn prepare_work_rejects_malformed_outbound_bridge_message() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let action = malformed_outbound_bridge_action(b"bad message-root payload");
    node.state
        .write()
        .pending_actions
        .insert(action.tx_hash, action);

    let err = node
        .prepare_work()
        .expect_err("malformed outbound bridge payload must block template construction");

    assert!(err.to_string().contains("outbound bridge action args"));
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn announced_block_rejects_malformed_outbound_payload_before_message_commitment() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let parent = node.best_meta();
    let malformed = malformed_outbound_bridge_action(b"bad announced bridge payload");
    let parent_state = test_state(parent.clone());
    let (state_root, nullifier_root, extrinsics_root, tx_count) = preview_pending_roots(
        &node.da_ciphertext_tree,
        &parent_state,
        std::slice::from_ref(&malformed),
    )
    .expect("preview malformed action roots");
    let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
    let header_history = node
        .header_hashes_to_hash(parent.hash)
        .expect("header history");
    let header_mmr_root = header_mmr_root_from_hashes(&header_history);
    let header_mmr_len = header_history.len() as u64;
    let cumulative_work = cumulative_work_after(&parent.cumulative_work, pow_bits).expect("work");
    let height = parent.height.saturating_add(1);
    let timestamp_ms = parent.timestamp_ms.saturating_add(1);
    let message_root = empty_bridge_message_root();
    let message_count = 1;
    let pre_header = native_pow_header_from_parts(
        height,
        timestamp_ms,
        parent.hash,
        pow_bits,
        [0u8; 32],
        cumulative_work,
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        message_count,
        &header_mmr_root,
        header_mmr_len,
        parent.supply_digest,
        tx_count,
    );
    let work = NativeWork {
        height,
        parent_hash: parent.hash,
        pre_hash: pre_header.pre_hash(),
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        cumulative_work,
        supply_digest: parent.supply_digest,
        tx_count,
        timestamp_ms,
        pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work, 0).expect("malformed announced bridge seal");
    let meta = signed_test_block_meta(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        hash: seal.work_hash,
        parent_hash: parent.hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        timestamp_ms,
        pow_bits,
        nonce: seal.nonce,
        work_hash: seal.work_hash,
        cumulative_work,
        supply_digest: parent.supply_digest,
        tx_count,
        action_bytes: vec![malformed.encode()],
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    });

    let err = node
        .import_announced_block(meta)
        .expect_err("malformed outbound payload must reject before message count mismatch");

    assert!(err.to_string().contains("outbound bridge action args"));
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn prepare_work_drops_actions_after_preview_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let anchor = node.state.read().commitment_tree.root();
    let transfer = test_inline_transfer_action(anchor, [4u8; 48], [44u8; 48], 0);
    let bridge = test_outbound_bridge_action(b"phantom bridge message");
    {
        let mut state = node.state.write();
        state.pending_actions.insert(transfer.tx_hash, transfer);
        state.pending_actions.insert(bridge.tx_hash, bridge);
    }

    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(work.tx_count, 0);
    assert_eq!(work.extrinsics_root, actions_extrinsics_root(&[]));
    assert_eq!(work.message_count, 0);
    assert_eq!(work.message_root, empty_bridge_message_root());
}

#[test]
fn mined_empty_block_rejects_phantom_bridge_message_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "safe", false)).expect("node");
    let parent = node.best_meta();
    let state_root = parent.state_root;
    let kernel_root = parent.kernel_root;
    let nullifier_root = parent.nullifier_root;
    let extrinsics_root = actions_extrinsics_root(&[]);
    let bridge = test_outbound_bridge_action(b"message without action bytes");
    let bridge_messages = bridge_messages_from_actions(&[bridge], 1).expect("bridge messages");
    let message_root = bridge_message_root(&bridge_messages);
    let message_count = u32::try_from(bridge_messages.len()).expect("message count");
    assert_ne!(message_root, empty_bridge_message_root());
    let header_history = node
        .header_hashes_to_hash(parent.hash)
        .expect("header history");
    let header_mmr_root = header_mmr_root_from_hashes(&header_history);
    let header_mmr_len = header_history.len() as u64;
    let cumulative_work =
        cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
    let pre_header = native_pow_header_from_parts(
        1,
        parent.timestamp_ms.saturating_add(1),
        parent.hash,
        pow_bits,
        [0u8; 32],
        cumulative_work,
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        message_count,
        &header_mmr_root,
        header_mmr_len,
        parent.supply_digest,
        0,
    );
    let work = NativeWork {
        height: 1,
        parent_hash: parent.hash,
        pre_hash: pre_header.pre_hash(),
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        cumulative_work,
        supply_digest: parent.supply_digest,
        tx_count: 0,
        timestamp_ms: parent.timestamp_ms.saturating_add(1),
        pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work.clone(), 0).expect("phantom bridge seal");

    let imported = node
        .import_mined_block(&work, seal)
        .expect("phantom bridge work should be stale");
    assert!(imported.is_none());
    assert_eq!(node.best_meta().height, 0);
}

#[test]
fn bridge_outbound_message_root_and_witness_are_exported() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let args = OutboundBridgeArgsV1 {
        destination_chain_id: [41u8; 32],
        app_family_id: 77,
        payload: b"bridge payload".to_vec(),
    };
    node.validate_and_stage_action(json!({
        "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        "family_id": FAMILY_BRIDGE,
        "action_id": ACTION_BRIDGE_OUTBOUND,
        "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
    }))
    .expect("stage outbound bridge message");

    let work = node.prepare_work().expect("prepare native work");
    assert_eq!(work.message_count, 1);
    assert_ne!(work.message_root, empty_bridge_message_root());
    let seal = mine_native_round(work.clone(), 0).expect("bridge seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("bridge import")
        .expect("bridge block");
    assert_eq!(imported.message_count, 1);
    assert_eq!(imported.message_root, work.message_root);

    let actions = decode_block_actions(&imported).expect("decode block actions");
    let messages =
        bridge_messages_from_actions(&actions, imported.height).expect("bridge messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].source_chain_id, HEGEMON_CHAIN_ID_V1);
    assert_eq!(messages[0].message_nonce, 1u128 << 64);
    assert_eq!(bridge_message_root(&messages), imported.message_root);

    let witness = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
        .expect("export bridge witness");
    assert_eq!(witness["schema"], json!("hegemon.bridge-witness.v1"));
    assert_eq!(
        witness["output"]["message_root"],
        json!(hex48(&imported.message_root))
    );
    assert_eq!(witness["output"]["confirmations_checked"], json!(1));
    assert_eq!(
        witness["output"]["message_hash"],
        witness["messages"][0]["message_hash"]
    );
    assert!(witness["canonical"]["header"]
        .as_str()
        .expect("canonical header hex")
        .starts_with("0x"));
    assert!(witness["canonical"]["output"]
        .as_str()
        .expect("canonical output hex")
        .starts_with("0x"));
}

fn node_with_exportable_bridge_block(
    payload: &[u8],
) -> (tempfile::TempDir, Arc<NativeNode>, NativeBlockMeta) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let action = test_outbound_bridge_action(payload);
    node.state
        .write()
        .pending_actions
        .insert(action.tx_hash, action);
    let work = node.prepare_work().expect("prepare native work");
    let seal = mine_native_round(work.clone(), 0).expect("bridge seal");
    let imported = node
        .import_mined_block(&work, seal)
        .expect("bridge import")
        .expect("bridge block");
    assert_eq!(imported.message_count, 1);
    (tmp, node, imported)
}

#[test]
fn bridge_witness_rejects_noncanonical_block_hash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pow_bits = 0x207f_ffff;
    let node = NativeNode::open(test_config(tmp.path(), pow_bits, "unsafe", false)).expect("node");
    let genesis = node.best_meta();
    let side_action = test_outbound_bridge_action(b"side branch bridge payload");
    let side = mined_child_with_actions(&genesis, 1, pow_bits, 0, vec![side_action]);
    node.import_announced_block(side.clone())
        .expect("side bridge block import");
    assert_eq!(node.best_meta().hash, side.hash);

    let canonical = (1..=256)
        .find_map(|round| {
            let candidate = mined_empty_child(&genesis, 1, pow_bits, round);
            if candidate.hash < side.hash {
                Some(candidate)
            } else {
                None
            }
        })
        .expect("find better same-height canonical block");
    assert!(node
        .import_announced_block(canonical.clone())
        .expect("canonical reorg import"));
    assert_eq!(node.best_meta().hash, canonical.hash);

    let err = export_bridge_witness(&node, json!([hex32(&side.hash), 0]))
        .expect_err("side-branch bridge witness must be rejected");
    assert!(err.to_string().contains("is not canonical"));
}

#[test]
fn bridge_witness_rejects_malformed_explicit_block_hash() {
    let (_tmp, node, _imported) =
        node_with_exportable_bridge_block(b"malformed hash should not backscan");

    let err = export_bridge_witness(&node, json!(["0x1234", 0]))
        .expect_err("malformed explicit hash must not fall back to latest witness");

    assert!(err
        .to_string()
        .contains("malformed bridge witness block hash"));
}

#[test]
fn bridge_witness_rejects_unknown_explicit_block_hash() {
    let (_tmp, node, _imported) = node_with_exportable_bridge_block(b"unknown bridge witness hash");

    let err = export_bridge_witness(&node, json!([hex32(&[0xabu8; 32]), 0]))
        .expect_err("unknown explicit hash must be rejected");

    assert!(err.to_string().contains("unknown bridge witness block"));
}

#[test]
fn bridge_witness_admission_rejects_explicit_history_over_cap() {
    let input = NativeBridgeWitnessExportAdmissionInput {
        block_hash_parameter_valid: true,
        explicit_block_hash: true,
        block_known: true,
        canonical_height_present: true,
        block_is_canonical: true,
        block_actions_decoded: true,
        message_index_in_bounds: true,
        parent_known: true,
        best_height: 4_200,
        message_height: 1,
        max_explicit_history: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
        max_materialized_history: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
    };
    let rejection = evaluate_native_bridge_witness_export_admission(input)
        .expect_err("explicit old witness must reject before full history export");
    assert_eq!(
        rejection,
        NativeBridgeWitnessExportAdmissionRejection::ExplicitHistoryTooLong
    );

    let latest_backscan_input = NativeBridgeWitnessExportAdmissionInput {
        explicit_block_hash: false,
        ..input
    };
    assert_eq!(
        evaluate_native_bridge_witness_export_admission(latest_backscan_input)
            .expect_err("safe RPC must reject oversized materialized history"),
        NativeBridgeWitnessExportAdmissionRejection::MaterializedHistoryTooLong
    );

    let bounded_tip_input = NativeBridgeWitnessExportAdmissionInput {
        best_height: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
        message_height: MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS,
        ..latest_backscan_input
    };
    assert_eq!(
        evaluate_native_bridge_witness_export_admission(bounded_tip_input)
            .expect("bounded latest backscan admission"),
        1
    );
}

#[test]
fn bridge_witness_rejects_missing_canonical_height_index() {
    let (_tmp, node, imported) =
        node_with_exportable_bridge_block(b"missing canonical height index");
    node.height_tree
        .remove(height_key(imported.height))
        .expect("remove height index");
    node.height_tree.flush().expect("flush height tree");

    let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
        .expect_err("missing canonical height index must reject witness export");

    assert!(err.to_string().contains("missing canonical block"));
}

#[test]
fn native_metadata_projection_rejects_unsigned_bridge_witness() {
    let (_tmp, node, imported) =
        node_with_exportable_bridge_block(b"unsigned bridge witness metadata");
    let unsigned = unsigned_native_meta(imported.clone());
    persist_block_record(&node.block_tree, &unsigned)
        .expect("replace bridge block with unsigned metadata");

    let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
        .expect_err("unsigned canonical metadata must not be projected into bridge witness");
    let err = format!("{err:?}");
    assert!(err.contains("invalid_miner_public_key_length"), "{err}");
}

#[test]
fn bridge_witness_rejects_message_index_out_of_bounds() {
    let (_tmp, node, imported) = node_with_exportable_bridge_block(b"message index out of bounds");

    let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 1]))
        .expect_err("missing bridge message index must reject witness export");

    assert!(err
        .to_string()
        .contains("bridge message index out of bounds"));
}

#[test]
fn bridge_witness_rejects_missing_parent_header() {
    let (_tmp, node, imported) =
        node_with_exportable_bridge_block(b"missing bridge witness parent");
    node.block_tree
        .remove(imported.parent_hash.as_slice())
        .expect("remove parent header");
    node.block_tree.flush().expect("flush block tree");

    let err = export_bridge_witness(&node, json!([hex32(&imported.hash), 0]))
        .expect_err("missing parent header must reject witness export");

    assert!(err
        .to_string()
        .contains("missing parent for bridge witness"));
}

#[test]
fn bridge_witness_latest_backscan_rejects_corrupt_newer_canonical_block() {
    let (_tmp, node, older_bridge) =
        node_with_exportable_bridge_block(b"older bridge message behind corrupt tip");

    let work = node.prepare_work().expect("prepare empty child");
    assert_eq!(work.height, older_bridge.height + 1);
    assert_eq!(work.message_count, 0);
    let seal = mine_native_round(work.clone(), 0).expect("empty child seal");
    let mut newer = node
        .import_mined_block(&work, seal)
        .expect("import empty child")
        .expect("empty child block");
    assert_eq!(node.best_meta().hash, newer.hash);
    newer.action_bytes.push(vec![0xff]);
    persist_block_record(&node.block_tree, &newer).expect("persist corrupt canonical child");

    let err = export_bridge_witness(&node, json!([Value::Null, 0]))
        .expect_err("latest backscan must fail closed on corrupt canonical block actions");

    assert!(err
        .to_string()
        .contains("decode bridge witness backscan block actions"));
}

#[test]
fn bridge_witness_latest_backscan_rejects_malformed_outbound_payload() {
    let (_tmp, node, older_bridge) =
        node_with_exportable_bridge_block(b"older bridge behind malformed payload");
    let pow_bits = 0x207f_ffff;
    let malformed = malformed_outbound_bridge_action(b"corrupt newer bridge payload");
    let parent_state = node.state.read().clone();
    let (state_root, nullifier_root, extrinsics_root, tx_count) = preview_pending_roots(
        &node.da_ciphertext_tree,
        &parent_state,
        std::slice::from_ref(&malformed),
    )
    .expect("preview malformed action roots");
    let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
    let header_history = node
        .header_hashes_to_hash(older_bridge.hash)
        .expect("header history");
    let header_mmr_root = header_mmr_root_from_hashes(&header_history);
    let header_mmr_len = header_history.len() as u64;
    let cumulative_work =
        cumulative_work_after(&older_bridge.cumulative_work, pow_bits).expect("work");
    let height = older_bridge.height.saturating_add(1);
    let timestamp_ms = older_bridge.timestamp_ms.saturating_add(1);
    let message_root = empty_bridge_message_root();
    let message_count = 0;
    let pre_header = native_pow_header_from_parts(
        height,
        timestamp_ms,
        older_bridge.hash,
        pow_bits,
        [0u8; 32],
        cumulative_work,
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        message_count,
        &header_mmr_root,
        header_mmr_len,
        older_bridge.supply_digest,
        tx_count,
    );
    let work = NativeWork {
        height,
        parent_hash: older_bridge.hash,
        pre_hash: pre_header.pre_hash(),
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        cumulative_work,
        supply_digest: older_bridge.supply_digest,
        tx_count,
        timestamp_ms,
        pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work, 0).expect("malformed bridge child seal");
    let malformed_meta = signed_test_block_meta(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        hash: seal.work_hash,
        parent_hash: older_bridge.hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        timestamp_ms,
        pow_bits,
        nonce: seal.nonce,
        work_hash: seal.work_hash,
        cumulative_work,
        supply_digest: older_bridge.supply_digest,
        tx_count,
        action_bytes: vec![malformed.encode()],
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    });
    let malformed_hash = malformed_meta.hash;
    persist_block_record(&node.block_tree, &malformed_meta)
        .expect("persist malformed canonical block");
    node.height_tree
        .insert(height_key(height), malformed_meta.hash.as_slice())
        .expect("persist malformed canonical height");
    node.height_tree.flush().expect("flush height tree");
    node.state.write().best = malformed_meta;

    let explicit_err = export_bridge_witness(&node, json!([hex32(&malformed_hash), 0]))
        .expect_err("explicit witness export must fail on malformed outbound payload");
    assert!(explicit_err
        .to_string()
        .contains("outbound bridge action args"));

    let err = export_bridge_witness(&node, json!([Value::Null, 0]))
        .expect_err("latest backscan must fail on malformed outbound payload");

    assert!(err.to_string().contains("outbound bridge action args"));
}

#[test]
fn inbound_bridge_rejects_message_binding_tampering() {
    use base64::Engine;

    let tmp = tempfile::tempdir().expect("tempdir");
    let destination_path = tmp.path().join("destination");
    fs::create_dir_all(&destination_path).expect("destination dir");
    let pow_bits = 0x207f_ffff;
    let destination = NativeNode::open(test_config(&destination_path, pow_bits, "unsafe", false))
        .expect("destination node");
    let args = test_disabled_risc0_bridge_inbound_args(b"bound bridge payload");

    let request_for = |args: &InboundBridgeArgsV1| {
        json!({
            "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
            "family_id": FAMILY_BRIDGE,
            "action_id": ACTION_BRIDGE_INBOUND,
            "new_nullifiers": [],
            "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
        })
    };

    let mut bad_nonce = args.clone();
    bad_nonce.source_message_nonce = bad_nonce.source_message_nonce.wrapping_add(1);
    let err = destination
        .validate_and_stage_action(request_for(&bad_nonce))
        .expect_err("source nonce must bind to message nonce");
    assert!(err.to_string().contains("replay key does not match"));

    let mut wrong_destination = args.clone();
    wrong_destination.message.destination_chain_id = [0x55u8; 32];
    let err = destination
        .validate_and_stage_action(request_for(&wrong_destination))
        .expect_err("inbound bridge message must target Hegemon");
    assert!(err.to_string().contains("not addressed"));

    let mut bad_payload_hash = args.clone();
    bad_payload_hash.message.payload.push(0x99);
    let err = destination
        .validate_and_stage_action(request_for(&bad_payload_hash))
        .expect_err("payload hash must bind payload bytes");
    assert!(err.to_string().contains("payload hash mismatch"));

    let err = destination
        .validate_and_stage_action(request_for(&args))
        .expect_err("default native node must not stage RISC Zero bridge receipts");
    assert!(err.to_string().contains("verification is disabled"));
    assert_eq!(destination.state.read().pending_actions.len(), 0);
}

fn test_disabled_risc0_bridge_inbound_args(payload: &[u8]) -> InboundBridgeArgsV1 {
    let message = BridgeMessageV1 {
        source_chain_id: HEGEMON_CHAIN_ID_V1,
        destination_chain_id: HEGEMON_CHAIN_ID_V1,
        app_family_id: FAMILY_BRIDGE,
        message_nonce: 42,
        source_height: 9,
        payload_hash: bridge_payload_hash(payload),
        payload: payload.to_vec(),
    };
    let output = test_bridge_checkpoint_output_for_message(&message);
    let receipt = RiscZeroBridgeReceiptV1 {
        proof_system_id: consensus_light_client::RISC0_STARK_BRIDGE_PROOF_SYSTEM_ID_V1,
        image_id: HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
        journal: consensus_light_client::bridge_checkpoint_output_wire_bytes_v1(&output),
        receipt: vec![0],
    };
    InboundBridgeArgsV1 {
        source_chain_id: message.source_chain_id,
        source_message_nonce: message.message_nonce,
        verifier_program_hash: HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
        proof_receipt: receipt.encode(),
        message,
    }
}

fn test_bridge_mint_payload(amount: u64, asset_id: u64, recipient_tag: u8) -> BridgeMintPayloadV1 {
    BridgeMintPayloadV1 {
        version: BRIDGE_MINT_PAYLOAD_VERSION_V1,
        destination_chain_id: HEGEMON_CHAIN_ID_V1,
        recipient_commitment: [recipient_tag.max(1); 48],
        asset_id,
        amount,
        mint_nonce: 42,
    }
}

fn test_bridge_mint_payload_bytes() -> Vec<u8> {
    test_bridge_mint_payload(42, transaction_core::constants::NATIVE_ASSET_ID + 7, 0x42).encode()
}

fn bridge_mint_payload_admission_input_from_payload(
    payload: &BridgeMintPayloadV1,
) -> NativeBridgeMintPayloadAdmissionInput {
    let payload_bytes = payload.encode();
    let args = test_disabled_risc0_bridge_inbound_args(&payload_bytes);
    let output = test_bridge_checkpoint_output_for_message(&args.message);
    bridge_mint_payload_admission_input(&args, &output, Some(payload))
}

fn test_bridge_checkpoint_output_for_message(
    message: &BridgeMessageV1,
) -> BridgeCheckpointOutputV1 {
    BridgeCheckpointOutputV1 {
        source_chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        trusted_checkpoint_digest: [0xaau8; 32],
        checkpoint_height: message.source_height,
        checkpoint_header_hash: [0x11u8; 32],
        checkpoint_cumulative_work: [0x22u8; 48],
        canonical_tip_height: message
            .source_height
            .saturating_add(u64::from(MIN_INBOUND_BRIDGE_CONFIRMATIONS))
            .saturating_sub(1),
        canonical_tip_header_hash: [0x33u8; 32],
        canonical_tip_cumulative_work: [0x44u8; 48],
        message_root: bridge_message_root(std::slice::from_ref(message)),
        message_hash: message.message_hash(),
        message_nonce: message.message_nonce,
        confirmations_checked: MIN_INBOUND_BRIDGE_CONFIRMATIONS,
        min_work_checked: [0u8; 48],
    }
}

fn test_miner_identity() -> NativeMinerIdentity {
    NativeMinerIdentity::from_seed(b"hegemon native miner identity test seed")
}

fn sign_test_block_meta(meta: &mut NativeBlockMeta) {
    sign_native_block_meta(meta, &test_miner_identity());
}

fn signed_test_block_meta(mut meta: NativeBlockMeta) -> NativeBlockMeta {
    sign_test_block_meta(&mut meta);
    meta
}

fn unsigned_native_meta(mut meta: NativeBlockMeta) -> NativeBlockMeta {
    meta.miner_commitment = [0u8; 48];
    meta.miner_public_key.clear();
    meta.miner_signature.clear();
    meta
}

fn legacy_meta_from_current(meta: &NativeBlockMeta) -> LegacyNativeBlockMetaV1 {
    LegacyNativeBlockMetaV1 {
        chain_id: meta.chain_id,
        rules_hash: meta.rules_hash,
        height: meta.height,
        hash: meta.hash,
        parent_hash: meta.parent_hash,
        state_root: meta.state_root,
        kernel_root: meta.kernel_root,
        nullifier_root: meta.nullifier_root,
        extrinsics_root: meta.extrinsics_root,
        message_root: meta.message_root,
        message_count: meta.message_count,
        header_mmr_root: meta.header_mmr_root,
        header_mmr_len: meta.header_mmr_len,
        timestamp_ms: meta.timestamp_ms,
        pow_bits: meta.pow_bits,
        nonce: meta.nonce,
        work_hash: meta.work_hash,
        cumulative_work: meta.cumulative_work,
        supply_digest: meta.supply_digest,
        tx_count: meta.tx_count,
        action_bytes: meta.action_bytes.clone(),
    }
}

fn mined_empty_child(
    parent: &NativeBlockMeta,
    height: u64,
    pow_bits: u32,
    round: u64,
) -> NativeBlockMeta {
    mined_empty_child_at(
        parent,
        height,
        pow_bits,
        round,
        parent.timestamp_ms.saturating_add(1),
    )
}

fn strongest_test_seal(work: &NativeWork, rounds: std::ops::Range<u64>) -> NativeSeal {
    rounds
        .filter_map(|round| mine_native_round(work.clone(), round))
        .min_by(|left, right| left.work_hash.cmp(&right.work_hash))
        .expect("test mining rounds must produce at least one seal")
}

fn mined_empty_child_at(
    parent: &NativeBlockMeta,
    height: u64,
    pow_bits: u32,
    round: u64,
    timestamp_ms: u64,
) -> NativeBlockMeta {
    let state_root = parent.state_root;
    let kernel_root = parent.kernel_root;
    let nullifier_root = parent.nullifier_root;
    let extrinsics_root = actions_extrinsics_root(&[]);
    let message_root = empty_bridge_message_root();
    let message_count = 0;
    let header_history = if parent.height == 0 {
        vec![parent.hash]
    } else if parent.height == 1 {
        vec![parent.parent_hash, parent.hash]
    } else {
        vec![parent.hash]
    };
    let header_mmr_root = header_mmr_root_from_hashes(&header_history);
    let header_mmr_len = header_history.len() as u64;
    let cumulative_work =
        cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
    let pre_header = native_pow_header_from_parts(
        height,
        timestamp_ms,
        parent.hash,
        pow_bits,
        [0u8; 32],
        cumulative_work,
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        message_count,
        &header_mmr_root,
        header_mmr_len,
        parent.supply_digest,
        0,
    );
    let pre_hash = pre_header.pre_hash();
    let work = NativeWork {
        height,
        parent_hash: parent.hash,
        pre_hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        cumulative_work,
        supply_digest: parent.supply_digest,
        tx_count: 0,
        timestamp_ms,
        pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work, round).expect("side seal");
    signed_test_block_meta(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        hash: seal.work_hash,
        parent_hash: parent.hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        timestamp_ms,
        pow_bits,
        nonce: seal.nonce,
        work_hash: seal.work_hash,
        cumulative_work,
        supply_digest: parent.supply_digest,
        tx_count: 0,
        action_bytes: Vec::new(),
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    })
}

#[derive(Clone, Copy, Debug)]
enum TestCommitmentMutation {
    StateRoot,
    KernelRoot,
    NullifierRoot,
    ExtrinsicsRoot,
    MessageRoot,
    MessageCount,
    SupplyDigest,
}

fn mined_empty_child_with_commitment_mutation(
    parent: &NativeBlockMeta,
    pow_bits: u32,
    round: u64,
    mutation: TestCommitmentMutation,
) -> NativeBlockMeta {
    let height = parent.height.saturating_add(1);
    let timestamp_ms = parent.timestamp_ms.saturating_add(1);
    let mut state_root = parent.state_root;
    let mut kernel_root = parent.kernel_root;
    let mut nullifier_root = parent.nullifier_root;
    let mut extrinsics_root = actions_extrinsics_root(&[]);
    let mut message_root = empty_bridge_message_root();
    let mut message_count = 0;
    let header_history = if parent.height == 0 {
        vec![parent.hash]
    } else if parent.height == 1 {
        vec![parent.parent_hash, parent.hash]
    } else {
        vec![parent.hash]
    };
    let header_mmr_root = header_mmr_root_from_hashes(&header_history);
    let header_mmr_len = header_history.len() as u64;
    let cumulative_work =
        cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
    let mut supply_digest = parent.supply_digest;

    match mutation {
        TestCommitmentMutation::StateRoot => state_root[0] ^= 1,
        TestCommitmentMutation::KernelRoot => kernel_root[0] ^= 1,
        TestCommitmentMutation::NullifierRoot => nullifier_root[0] ^= 1,
        TestCommitmentMutation::ExtrinsicsRoot => extrinsics_root[0] ^= 1,
        TestCommitmentMutation::MessageRoot => message_root[0] ^= 1,
        TestCommitmentMutation::MessageCount => message_count = 1,
        TestCommitmentMutation::SupplyDigest => supply_digest = supply_digest.saturating_add(1),
    }

    let pre_header = native_pow_header_from_parts(
        height,
        timestamp_ms,
        parent.hash,
        pow_bits,
        [0u8; 32],
        cumulative_work,
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        message_count,
        &header_mmr_root,
        header_mmr_len,
        supply_digest,
        0,
    );
    let pre_hash = pre_header.pre_hash();
    let work = NativeWork {
        height,
        parent_hash: parent.hash,
        pre_hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        cumulative_work,
        supply_digest,
        tx_count: 0,
        timestamp_ms,
        pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work, round).expect("mutated seal");
    signed_test_block_meta(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        hash: seal.work_hash,
        parent_hash: parent.hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        timestamp_ms,
        pow_bits,
        nonce: seal.nonce,
        work_hash: seal.work_hash,
        cumulative_work,
        supply_digest,
        tx_count: 0,
        action_bytes: Vec::new(),
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    })
}

fn mined_child_with_actions(
    parent: &NativeBlockMeta,
    height: u64,
    pow_bits: u32,
    round: u64,
    actions: Vec<PendingAction>,
) -> NativeBlockMeta {
    let parent_state = test_state(parent.clone());
    let (_db, da_ciphertext_tree) = test_da_ciphertext_tree();
    for action in &actions {
        insert_test_sidecar_ciphertext(&da_ciphertext_tree, action);
    }
    let (state_root, nullifier_root, extrinsics_root, tx_count) =
        preview_pending_roots(&da_ciphertext_tree, &parent_state, &actions)
            .expect("preview action roots");
    let kernel_root = consensus::types::kernel_root_from_shielded_root(&state_root);
    let bridge_messages = bridge_messages_from_actions(&actions, height).expect("bridge messages");
    let message_root = bridge_message_root(&bridge_messages);
    let message_count = u32::try_from(bridge_messages.len()).expect("message count");
    let header_history = if parent.height == 0 {
        vec![parent.hash]
    } else if parent.height == 1 {
        vec![parent.parent_hash, parent.hash]
    } else {
        vec![parent.hash]
    };
    let header_mmr_root = header_mmr_root_from_hashes(&header_history);
    let header_mmr_len = header_history.len() as u64;
    let cumulative_work =
        cumulative_work_after(&parent.cumulative_work, pow_bits).expect("cumulative work");
    let supply_digest = advance_native_supply_digest(parent.supply_digest, &actions, height)
        .expect("supply digest");
    let pre_header = native_pow_header_from_parts(
        height,
        parent.timestamp_ms.saturating_add(1),
        parent.hash,
        pow_bits,
        [0u8; 32],
        cumulative_work,
        &state_root,
        &kernel_root,
        &nullifier_root,
        &extrinsics_root,
        &message_root,
        message_count,
        &header_mmr_root,
        header_mmr_len,
        supply_digest,
        tx_count,
    );
    let pre_hash = pre_header.pre_hash();
    let work = NativeWork {
        height,
        parent_hash: parent.hash,
        pre_hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        cumulative_work,
        supply_digest,
        tx_count,
        timestamp_ms: parent.timestamp_ms.saturating_add(1),
        pow_bits,
        prepared_actions: None,
    };
    let seal = mine_native_round(work, round).expect("action child seal");
    signed_test_block_meta(NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_V1,
        height,
        hash: seal.work_hash,
        parent_hash: parent.hash,
        state_root,
        kernel_root,
        nullifier_root,
        extrinsics_root,
        message_root,
        message_count,
        header_mmr_root,
        header_mmr_len,
        timestamp_ms: parent.timestamp_ms.saturating_add(1),
        pow_bits,
        nonce: seal.nonce,
        work_hash: seal.work_hash,
        cumulative_work,
        supply_digest,
        tx_count,
        action_bytes: actions.iter().map(Encode::encode).collect(),
        miner_commitment: [0u8; 48],
        miner_public_key: Vec::new(),
        miner_signature: Vec::new(),
    })
}

fn test_config(path: &Path, pow_bits: u32, rpc_methods: &str, rpc_external: bool) -> NativeConfig {
    NativeConfig {
        dev: true,
        tmp: false,
        base_path: path.to_path_buf(),
        db_path: path.join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "test".to_string(),
        rpc_methods: rpc_methods.to_string(),
        rpc_external,
        rpc_cors: None,
        seeds: Vec::new(),
        max_peers: 0,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: false,
        miner_address: None,
        pow_bits,
    }
}

fn mine_empty_native_block(node: &NativeNode) -> NativeBlockMeta {
    let work = node.prepare_work().expect("prepare empty native work");
    let seal = mine_native_round(work.clone(), 0).expect("empty native seal");
    node.import_mined_block(&work, seal)
        .expect("empty native import")
        .expect("empty native block")
}

fn test_state(best: NativeBlockMeta) -> NativeState {
    let header_mmr_peaks = header_mmr_peaks_from_hashes(&[best.hash]);
    NativeState {
        best,
        header_mmr_peaks,
        pending_actions: BTreeMap::new(),
        commitment_tree: CommitmentTreeState::default(),
        nullifiers: BTreeSet::new(),
        consumed_bridge_messages: BTreeSet::new(),
        stablecoin_policy_authorizations: BTreeSet::new(),
        staged_ciphertexts: BTreeMap::new(),
        staged_proofs: BTreeMap::new(),
    }
}

fn test_da_ciphertext_tree() -> (sled::Db, sled::Tree) {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db.open_tree("da_ciphertexts").expect("da ciphertext tree");
    (db, tree)
}

fn temporary_action_tree_with_pending(
    pending_actions: &BTreeMap<[u8; 32], PendingAction>,
) -> (sled::Db, sled::Tree) {
    let db = sled::Config::new()
        .temporary(true)
        .open()
        .expect("temporary sled db");
    let tree = db
        .open_tree("pending_actions")
        .expect("pending action tree");
    for (hash, action) in pending_actions {
        tree.insert(hash.as_slice(), action.encode())
            .expect("insert temporary pending action");
    }
    tree.flush().expect("flush temporary pending actions");
    (db, tree)
}

fn persist_pending_action_for_startup(node: &NativeNode, action: &PendingAction) {
    node.action_tree
        .insert(action.tx_hash.as_slice(), action.encode())
        .expect("insert persisted pending action");
    node.action_tree
        .flush()
        .expect("flush persisted pending action");
}

fn test_transfer_encrypted_note() -> protocol_shielded_pool::types::EncryptedNote {
    protocol_shielded_pool::types::EncryptedNote {
        ciphertext: [3u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
        kem_ciphertext: vec![4u8; 32],
    }
}

fn test_transfer_ciphertext_bytes() -> Vec<u8> {
    let note = test_transfer_encrypted_note();
    let mut note_bytes = Vec::new();
    note_bytes.extend_from_slice(&note.ciphertext);
    note_bytes.extend_from_slice(&note.kem_ciphertext);
    note_bytes
}

fn insert_test_sidecar_ciphertext(tree: &sled::Tree, action: &PendingAction) {
    if action.family_id != FAMILY_SHIELDED_POOL
        || action.action_id != ACTION_SHIELDED_TRANSFER_SIDECAR
    {
        return;
    }
    let bytes = test_transfer_ciphertext_bytes();
    let hash = ciphertext_hash_bytes(&bytes);
    assert_eq!(
        action.ciphertext_hashes.as_slice(),
        [hash].as_slice(),
        "test sidecar action must use the deterministic test ciphertext"
    );
    tree.insert(hash.as_slice(), bytes)
        .expect("insert test sidecar ciphertext");
    tree.flush().expect("flush test sidecar ciphertext");
}

fn stage_test_sidecar_ciphertext(node: &NativeNode, action: &PendingAction) {
    insert_test_sidecar_ciphertext(&node.da_ciphertext_tree, action);
    let mut state = node.state.write();
    for (hash, size) in action
        .ciphertext_hashes
        .iter()
        .zip(action.ciphertext_sizes.iter())
    {
        state.staged_ciphertexts.insert(hex48(hash), *size);
    }
}

fn test_transfer_proof_artifact(
    anchor: [u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    stablecoin: Option<StablecoinPolicyBinding>,
    binding: KernelVersionBinding,
) -> Vec<u8> {
    test_transfer_proof_artifact_with_value_balance(
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes,
        balance_slot_asset_ids,
        fee,
        0,
        stablecoin,
        binding,
    )
}

fn test_transfer_proof_artifact_with_value_balance(
    anchor: [u8; 48],
    nullifiers: &[[u8; 48]],
    commitments: &[[u8; 48]],
    ciphertext_hashes: &[[u8; 48]],
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    value_balance: i128,
    stablecoin: Option<StablecoinPolicyBinding>,
    binding: KernelVersionBinding,
) -> Vec<u8> {
    let (_, fixture_bytes) = staged_proof_fixture();
    let mut decoded =
        consensus::backend_interface::decode_native_tx_leaf_artifact_bytes(&fixture_bytes)
            .expect("decode native tx-leaf fixture");
    let value_balance_magnitude =
        u64::try_from(value_balance.unsigned_abs()).expect("test value balance magnitude fits u64");
    decoded.tx.nullifiers = nullifiers.to_vec();
    decoded.tx.commitments = commitments.to_vec();
    decoded.tx.ciphertext_hashes = ciphertext_hashes.to_vec();
    decoded.tx.version = binding.into();
    decoded.proof_backend = protocol_versioning::tx_proof_backend_for_version(decoded.tx.version)
        .unwrap_or(protocol_versioning::DEFAULT_TX_PROOF_BACKEND);
    decoded.stark_public_inputs.input_flags = vec![1; nullifiers.len()];
    decoded.stark_public_inputs.output_flags = vec![1; commitments.len()];
    decoded.stark_public_inputs.fee = fee;
    decoded.stark_public_inputs.value_balance_sign = u8::from(value_balance < 0);
    decoded.stark_public_inputs.value_balance_magnitude = value_balance_magnitude;
    decoded.stark_public_inputs.merkle_root = anchor;
    decoded.stark_public_inputs.balance_slot_asset_ids = balance_slot_asset_ids.to_vec();
    match stablecoin {
        Some(stablecoin) => {
            let issuance_magnitude = u64::try_from(stablecoin.issuance_delta.unsigned_abs())
                .expect("test stablecoin issuance delta magnitude fits u64");
            decoded.stark_public_inputs.stablecoin_enabled = 1;
            decoded.stark_public_inputs.stablecoin_asset_id = stablecoin.asset_id;
            decoded.stark_public_inputs.stablecoin_policy_version = stablecoin.policy_version;
            decoded.stark_public_inputs.stablecoin_issuance_sign =
                u8::from(stablecoin.issuance_delta < 0);
            decoded.stark_public_inputs.stablecoin_issuance_magnitude = issuance_magnitude;
            decoded.stark_public_inputs.stablecoin_policy_hash = stablecoin.policy_hash;
            decoded.stark_public_inputs.stablecoin_oracle_commitment = stablecoin.oracle_commitment;
            decoded
                .stark_public_inputs
                .stablecoin_attestation_commitment = stablecoin.attestation_commitment;
        }
        None => {
            decoded.stark_public_inputs.stablecoin_enabled = 0;
            decoded.stark_public_inputs.stablecoin_asset_id = 0;
            decoded.stark_public_inputs.stablecoin_policy_version = 0;
            decoded.stark_public_inputs.stablecoin_issuance_sign = 0;
            decoded.stark_public_inputs.stablecoin_issuance_magnitude = 0;
            decoded.stark_public_inputs.stablecoin_policy_hash = [0u8; 48];
            decoded.stark_public_inputs.stablecoin_oracle_commitment = [0u8; 48];
            decoded
                .stark_public_inputs
                .stablecoin_attestation_commitment = [0u8; 48];
        }
    }
    decoded.receipt.statement_hash =
        native_tx_leaf_statement_hash_from_decoded(&decoded).expect("statement hash");
    decoded.receipt.verifier_profile =
        consensus::proof_interface::experimental_native_tx_leaf_verifier_profile();
    decoded.receipt.public_inputs_digest =
        consensus::backend_interface::transaction_public_inputs_digest_from_serialized(
            &decoded.stark_public_inputs,
        )
        .expect("public input digest");
    decoded.receipt.proof_digest = transaction_circuit::proof::transaction_proof_digest_from_parts(
        decoded.proof_backend,
        &decoded.stark_proof,
    );
    let proof = consensus::backend_interface::encode_native_tx_leaf_artifact_bytes(&decoded)
        .expect("encode native tx-leaf fixture");
    let binding_hash =
        native_tx_leaf_artifact_binding_hash(&decoded).expect("derive native tx-leaf binding hash");
    assert!(native_tx_leaf_artifact_binding_hash_matches_key(
        binding_hash,
        &proof
    ));
    proof
}

fn test_repartitioned_transfer_proof_alias(
    anchor: [u8; 48],
    nullifier: [u8; 48],
    commitment: [u8; 48],
    ciphertext_hash: [u8; 48],
    balance_slot_asset_ids: [u64; transaction_core::constants::BALANCE_SLOTS],
    fee: u64,
    stablecoin: Option<StablecoinPolicyBinding>,
    binding: KernelVersionBinding,
) -> Vec<u8> {
    test_transfer_proof_artifact(
        anchor,
        &[nullifier, commitment],
        &[],
        &[ciphertext_hash],
        balance_slot_asset_ids,
        fee,
        stablecoin,
        binding,
    )
}

fn test_stablecoin_policy_binding(seed: u8) -> StablecoinPolicyBinding {
    StablecoinPolicyBinding {
        asset_id: u64::from(seed),
        policy_hash: [seed; 48],
        oracle_commitment: [seed.wrapping_add(1); 48],
        attestation_commitment: [seed.wrapping_add(2); 48],
        issuance_delta: i128::from(seed) - 20,
        policy_version: u32::from(seed),
    }
}

fn test_manifest_authorized_stablecoin_policy(
    seed: u8,
    height: u64,
) -> (StablecoinPolicyManifestEntry, StablecoinPolicyBinding) {
    let entry = StablecoinPolicyManifestEntry {
        asset_id: u32::from(seed),
        oracle_feed: u32::from(seed).saturating_add(1),
        attestation_id: u64::from(seed).saturating_add(2),
        min_collateral_ratio_ppm: 1_500_000,
        max_mint_per_epoch: 100,
        oracle_max_age: 10,
        oracle_submitted_at: height.saturating_sub(1),
        enabled_at: height.saturating_sub(5),
        retired_at: None,
        policy_version: u32::from(seed).saturating_add(3),
        active: true,
        oracle_commitment: [seed.wrapping_add(4); 48],
        attestation_commitment: [seed.wrapping_add(5); 48],
        attestation_disputed: false,
    };
    let binding = StablecoinPolicyBinding {
        asset_id: u64::from(entry.asset_id),
        policy_hash: entry.policy_hash(),
        oracle_commitment: entry.oracle_commitment,
        attestation_commitment: entry.attestation_commitment,
        issuance_delta: 42,
        policy_version: entry.policy_version,
    };
    (entry, binding)
}

fn authorize_test_stablecoin_policy(state: &mut NativeState, binding: &StablecoinPolicyBinding) {
    state
        .stablecoin_policy_authorizations
        .insert(stablecoin_policy_authorization_key(binding));
}

fn test_inline_transfer_action(
    anchor: [u8; 48],
    nullifier: [u8; 48],
    commitment: [u8; 48],
    fee: u64,
) -> PendingAction {
    test_inline_transfer_action_with_stablecoin(anchor, nullifier, commitment, fee, None)
}

fn test_inline_transfer_action_with_stablecoin(
    anchor: [u8; 48],
    nullifier: [u8; 48],
    commitment: [u8; 48],
    fee: u64,
    stablecoin: Option<StablecoinPolicyBinding>,
) -> PendingAction {
    let note = test_transfer_encrypted_note();
    let note_bytes = test_transfer_ciphertext_bytes();
    let ciphertext_hash = ciphertext_hash_bytes(&note_bytes);
    let inputs = ShieldedTransferInputs {
        anchor,
        nullifiers: vec![nullifier],
        commitments: vec![commitment],
        ciphertext_hashes: vec![ciphertext_hash],
        balance_slot_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
        fee,
        value_balance: 0,
        stablecoin: stablecoin.clone(),
    };
    let binding_hash = StarkVerifier::compute_binding_hash(&inputs).data;
    let binding = KernelVersionBinding {
        circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
    };
    let balance_slot_asset_ids = [0, u64::MAX, u64::MAX, u64::MAX];
    let proof = test_transfer_proof_artifact(
        anchor,
        &[nullifier],
        &[commitment],
        &[ciphertext_hash],
        balance_slot_asset_ids,
        fee,
        stablecoin.clone(),
        binding,
    );
    let args = ShieldedTransferInlineArgs {
        proof,
        commitments: vec![commitment],
        ciphertexts: vec![note],
        anchor,
        balance_slot_asset_ids,
        binding_hash,
        stablecoin,
        fee,
    };
    let ciphertext_size = u32::try_from(
        args.ciphertexts[0].ciphertext.len() + args.ciphertexts[0].kem_ciphertext.len(),
    )
    .expect("ciphertext size");
    let mut action = PendingAction {
        tx_hash: [0u8; 32],
        binding,
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_SHIELDED_TRANSFER_INLINE,
        anchor,
        nullifiers: vec![nullifier],
        commitments: vec![commitment],
        ciphertext_hashes: vec![ciphertext_hash],
        ciphertext_sizes: vec![ciphertext_size],
        public_args: args.encode(),
        fee,
        candidate_artifact: None,
        received_ms: 0,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_sidecar_transfer_action(
    anchor: [u8; 48],
    nullifier: [u8; 48],
    commitment: [u8; 48],
    fee: u64,
) -> PendingAction {
    test_sidecar_transfer_action_with_stablecoin(anchor, nullifier, commitment, fee, None)
}

fn test_sidecar_transfer_action_with_stablecoin(
    anchor: [u8; 48],
    nullifier: [u8; 48],
    commitment: [u8; 48],
    fee: u64,
    stablecoin: Option<StablecoinPolicyBinding>,
) -> PendingAction {
    let inline =
        test_inline_transfer_action_with_stablecoin(anchor, nullifier, commitment, fee, stablecoin);
    let inline_args: ShieldedTransferInlineArgs =
        decode_scale_exact(&inline.public_args, "test inline transfer args")
            .expect("decode inline args");
    let args = ShieldedTransferSidecarArgs {
        proof: inline_args.proof,
        commitments: inline_args.commitments,
        ciphertext_hashes: inline.ciphertext_hashes.clone(),
        ciphertext_sizes: inline.ciphertext_sizes.clone(),
        anchor,
        balance_slot_asset_ids: inline_args.balance_slot_asset_ids,
        binding_hash: inline_args.binding_hash,
        stablecoin: inline_args.stablecoin,
        fee,
    };
    let mut action = PendingAction {
        action_id: ACTION_SHIELDED_TRANSFER_SIDECAR,
        public_args: args.encode(),
        ..inline
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_outbound_bridge_action(payload: &[u8]) -> PendingAction {
    let args = OutboundBridgeArgsV1 {
        destination_chain_id: [42u8; 32],
        app_family_id: FAMILY_BRIDGE,
        payload: payload.to_vec(),
    };
    let mut action = PendingAction {
        tx_hash: [0u8; 32],
        binding: KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        },
        family_id: FAMILY_BRIDGE,
        action_id: ACTION_BRIDGE_OUTBOUND,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: Vec::new(),
        ciphertext_sizes: Vec::new(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
        received_ms: 0,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn malformed_outbound_bridge_action(payload: &[u8]) -> PendingAction {
    let mut action = test_outbound_bridge_action(payload);
    action.public_args.push(0xaa);
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_inbound_bridge_action(payload: &[u8]) -> PendingAction {
    let source_chain_id = HEGEMON_CHAIN_ID_V1;
    let source_message_nonce = 17u128;
    let message = BridgeMessageV1 {
        source_chain_id,
        destination_chain_id: HEGEMON_CHAIN_ID_V1,
        app_family_id: FAMILY_BRIDGE,
        message_nonce: source_message_nonce,
        source_height: 42,
        payload_hash: bridge_payload_hash(payload),
        payload: payload.to_vec(),
    };
    let args = InboundBridgeArgsV1 {
        source_chain_id,
        source_message_nonce,
        verifier_program_hash: [7u8; 32],
        proof_receipt: vec![1, 2, 3],
        message,
    };
    let mut action = PendingAction {
        tx_hash: [0u8; 32],
        binding: KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        },
        family_id: FAMILY_BRIDGE,
        action_id: ACTION_BRIDGE_INBOUND,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: Vec::new(),
        ciphertext_sizes: Vec::new(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
        received_ms: 0,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_disabled_risc0_inbound_bridge_action(payload: &[u8]) -> PendingAction {
    let args = test_disabled_risc0_bridge_inbound_args(payload);
    let mut action = PendingAction {
        tx_hash: [0u8; 32],
        binding: KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        },
        family_id: FAMILY_BRIDGE,
        action_id: ACTION_BRIDGE_INBOUND,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: Vec::new(),
        ciphertext_sizes: Vec::new(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
        received_ms: 0,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_candidate_artifact(tx_count: u32) -> CandidateArtifact {
    CandidateArtifact {
        version: BLOCK_PROOF_BUNDLE_SCHEMA,
        tx_count,
        tx_statements_commitment: [5u8; 48],
        da_root: [6u8; 48],
        da_chunk_count: 1,
        commitment_proof: protocol_shielded_pool::types::StarkProof::default(),
        proof_mode: BlockProofMode::RecursiveBlock,
        proof_kind: PoolProofArtifactKind::RecursiveBlockV2,
        verifier_profile: consensus::proof::recursive_block_artifact_verifier_profile(),
        receipt_root: None,
        recursive_block: Some(protocol_shielded_pool::types::RecursiveBlockProofPayload {
            proof: protocol_shielded_pool::types::StarkProof {
                data: vec![8u8; 32],
            },
        }),
    }
}

fn test_candidate_artifact_action(tx_count: u32, tag: u8) -> PendingAction {
    let mut artifact = test_candidate_artifact(tx_count);
    artifact.tx_statements_commitment = [tag; 48];
    artifact.da_root = [tag.wrapping_add(1); 48];
    if let Some(recursive) = artifact.recursive_block.as_mut() {
        recursive.proof.data = vec![tag; 32];
    }
    let mut action = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT, 0);
    action.public_args = SubmitCandidateArtifactArgs {
        payload: artifact.clone(),
    }
    .encode();
    action.candidate_artifact = Some(artifact);
    action.received_ms = u64::from(tag);
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_empty_action(family_id: u16, action_id: u16, fee: u64) -> PendingAction {
    let mut action = PendingAction {
        tx_hash: [0u8; 32],
        binding: KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        },
        family_id,
        action_id,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: Vec::new(),
        ciphertext_sizes: Vec::new(),
        public_args: Vec::new(),
        fee,
        candidate_artifact: None,
        received_ms: 0,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn test_coinbase_action(amount: u64) -> PendingAction {
    test_coinbase_action_with_seed(amount, [15u8; 32])
}

fn test_coinbase_action_with_seed(amount: u64, public_seed: [u8; 32]) -> PendingAction {
    let note = protocol_shielded_pool::types::EncryptedNote {
        ciphertext: [11u8; protocol_shielded_pool::types::ENCRYPTED_NOTE_SIZE],
        kem_ciphertext: vec![12u8; 32],
    };
    let mut miner_note = protocol_shielded_pool::types::CoinbaseNoteData {
        commitment: [0u8; 48],
        encrypted_note: note,
        recipient_address: [14u8; protocol_shielded_pool::types::DIVERSIFIED_ADDRESS_SIZE],
        amount,
        public_seed,
    };
    let commitment = coinbase_note_data_commitment(&miner_note);
    miner_note.commitment = commitment;
    let args = MintCoinbaseArgs {
        reward_bundle: protocol_shielded_pool::types::BlockRewardBundle { miner_note },
    };
    let (_, ciphertext_metadata) =
        coinbase_ciphertext_metadata(&args.reward_bundle.miner_note.encrypted_note);
    let (ciphertext_hash, ciphertext_size) =
        ciphertext_metadata.expect("test coinbase ciphertext should fit the native cap");
    let mut action = PendingAction {
        tx_hash: [0u8; 32],
        binding: KernelVersionBinding {
            circuit: protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
            crypto: protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        },
        family_id: FAMILY_SHIELDED_POOL,
        action_id: ACTION_MINT_COINBASE,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: vec![commitment],
        ciphertext_hashes: vec![ciphertext_hash],
        ciphertext_sizes: vec![ciphertext_size],
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
        received_ms: 0,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn tamper_coinbase_public_seed_without_rebinding(action: &mut PendingAction) {
    let mut args: MintCoinbaseArgs =
        decode_scale_exact(&action.public_args, "coinbase action args")
            .expect("decode test coinbase args");
    args.reward_bundle.miner_note.public_seed[0] ^= 1;
    action.public_args = args.encode();
    action.tx_hash = pending_action_hash(action);
}

fn replace_single_action_body_with_exact_decodable_substitute(
    meta: &mut NativeBlockMeta,
    substitute: &PendingAction,
) {
    assert_eq!(
        meta.tx_count, 1,
        "test helper only models one-for-one action-byte substitution"
    );
    assert_eq!(
        meta.action_bytes.len(),
        1,
        "test helper requires exactly one committed action body"
    );
    let replacement = substitute.encode();
    let decoded: PendingAction =
        decode_scale_exact(&replacement, "exact-decodable substitute action")
            .expect("substitute action must decode exactly");
    assert_eq!(
        decoded.tx_hash,
        pending_action_hash(&decoded),
        "substitute action must be internally hash-bound"
    );
    assert_eq!(
        decoded.encode(),
        replacement,
        "substitute action encoding must be canonical"
    );
    assert_ne!(
        actions_extrinsics_root(&[decoded]),
        meta.extrinsics_root,
        "substitute action must differ from the committed action root"
    );
    meta.action_bytes[0] = replacement;
}

#[test]
fn coinbase_accounting_is_family_scoped() {
    let height = 9;
    let subsidy = consensus::reward::block_subsidy(height);
    let bridge_transfer_id_collision =
        test_empty_action(FAMILY_BRIDGE, ACTION_SHIELDED_TRANSFER_INLINE, 1_337);
    assert_eq!(
        expected_coinbase_amount(std::slice::from_ref(&bridge_transfer_id_collision), height)
            .expect("expected coinbase amount"),
        subsidy
    );
    assert_eq!(
        native_block_supply_delta(&[bridge_transfer_id_collision], height).expect("supply delta"),
        0
    );

    let bridge_coinbase_id_collision = test_empty_action(FAMILY_BRIDGE, ACTION_MINT_COINBASE, 0);
    validate_coinbase_accounting(std::slice::from_ref(&bridge_coinbase_id_collision), height)
        .expect("non-shielded coinbase action id is ignored");
    assert_eq!(
        native_block_supply_delta(&[bridge_coinbase_id_collision], height).expect("supply delta"),
        0
    );
}

#[test]
fn coinbase_accounting_rejects_multiple_coinbase_actions() {
    let height = 1;
    let subsidy = consensus::reward::block_subsidy(height);
    let err = validate_coinbase_accounting(
        &[test_coinbase_action(subsidy), test_coinbase_action(subsidy)],
        height,
    )
    .expect_err("multiple coinbase actions must reject");
    assert!(
        err.to_string().contains("multiple coinbase"),
        "unexpected error: {err}"
    );
}

#[test]
fn coinbase_accounting_rejects_reward_mismatch() {
    let height = 1;
    let subsidy = consensus::reward::block_subsidy(height);
    let err = validate_coinbase_accounting(&[test_coinbase_action(subsidy + 1)], height)
        .expect_err("wrong coinbase amount must reject");
    assert!(
        err.to_string().contains("coinbase amount mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn coinbase_accounting_rejects_fee_total_overflow_when_coinbase_claims_fees() {
    let height = 1;
    let subsidy = consensus::reward::block_subsidy(height);
    let max_fee = test_empty_action(
        FAMILY_SHIELDED_POOL,
        ACTION_SHIELDED_TRANSFER_INLINE,
        u64::MAX,
    );
    let one_fee = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE, 1);
    let err =
        validate_coinbase_accounting(&[max_fee, one_fee, test_coinbase_action(subsidy)], height)
            .expect_err("overflowing fee total with coinbase must reject");
    assert!(
        err.to_string().contains("block fee total overflow"),
        "unexpected error: {err}"
    );
}

#[test]
fn coinbase_accounting_allows_no_coinbase_fee_burn_without_summing_fees() {
    let height = 1;
    let max_fee = test_empty_action(
        FAMILY_SHIELDED_POOL,
        ACTION_SHIELDED_TRANSFER_INLINE,
        u64::MAX,
    );
    let one_fee = test_empty_action(FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE, 1);
    validate_coinbase_accounting(&[max_fee.clone(), one_fee.clone()], height)
        .expect("no coinbase burns fees without minting");
    assert_eq!(
        native_block_supply_delta(&[max_fee, one_fee], height).expect("supply delta"),
        0
    );
}

#[test]
fn native_supply_digest_rejects_overflow() {
    let height = 1;
    let subsidy = consensus::reward::block_subsidy(height) as u128;
    let parent = u128::MAX - subsidy + 1;
    let actions = vec![test_coinbase_action(subsidy as u64)];
    assert!(
        advance_native_supply_digest(parent, &actions, height).is_err(),
        "native supply digest overflow must reject instead of saturating"
    );
}

#[test]
fn lean_generated_native_supply_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_SUPPLY_VECTORS") else {
        eprintln!("HEGEMON_LEAN_SUPPLY_VECTORS not set; skipping generated Lean vector check");
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read generated Lean supply vectors");
    let vectors: LeanSupplyVectorFile =
        serde_json::from_str(&raw).expect("parse generated Lean supply vectors");
    assert_eq!(vectors.schema_version, 1);
    assert!(
        vectors.monetary_constants.is_object(),
        "Lean monetary constants must be present"
    );
    assert!(
        !vectors.subsidy_schedule_cases.is_empty(),
        "Lean subsidy schedule cases must not be empty"
    );
    assert!(
        !vectors.consensus_supply_cases.is_empty(),
        "Lean consensus supply cases must not be empty"
    );
    assert!(
        !vectors.native_supply_cases.is_empty(),
        "Lean native supply cases must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.native_supply_cases {
        assert!(names.insert(case.name.clone()));
        verify_lean_native_supply_case(case);
    }
}

fn verify_lean_native_supply_case(case: &LeanNativeSupplyCase) {
    let parent_supply = parse_u128(&case.parent_supply);
    let expected_delta = case.expected_delta.as_deref().map(parse_u128);
    let expected_supply = case.expected_supply.as_deref().map(parse_u128);
    let mut actions = Vec::new();
    if case.fee_total > 0 {
        actions.push(test_empty_action(
            FAMILY_SHIELDED_POOL,
            ACTION_SHIELDED_TRANSFER_INLINE,
            case.fee_total,
        ));
    }
    if case.has_coinbase {
        let amount =
            expected_delta.expect("Lean native coinbase case must expose a checked reward amount");
        let amount = u64::try_from(amount).expect("Lean native reward amount fits u64");
        actions.push(test_coinbase_action(amount));
    }

    validate_coinbase_accounting(&actions, case.height)
        .expect("Lean native supply case should have valid coinbase accounting");
    assert_eq!(
        native_block_supply_delta(&actions, case.height)
            .ok()
            .as_ref()
            .map(u128::to_string),
        expected_delta.as_ref().map(u128::to_string),
        "{} native supply delta drifted from Lean spec",
        case.name
    );
    assert_eq!(
        advance_native_supply_digest(parent_supply, &actions, case.height)
            .ok()
            .as_ref()
            .map(u128::to_string),
        expected_supply.as_ref().map(u128::to_string),
        "{} native checked supply digest drifted from Lean spec",
        case.name
    );
}

fn parse_u128(raw: &str) -> u128 {
    raw.parse::<u128>()
        .expect("Lean supply value must be a decimal u128")
}

fn parse_u64(raw: &str) -> u64 {
    raw.parse::<u64>()
        .expect("Lean native value must be a decimal u64")
}

fn stage_test_coinbase(node: &NativeNode, amount: u64, commitment_hint: [u8; 48]) {
    use base64::Engine;

    let public_seed = [commitment_hint[0]; 32];
    let action = test_coinbase_action_with_seed(amount, public_seed);
    let args: MintCoinbaseArgs = decode_scale_exact(&action.public_args, "coinbase action args")
        .expect("decode test coinbase args");
    node.validate_and_stage_action(json!({
        "binding_circuit": protocol_versioning::DEFAULT_VERSION_BINDING.circuit,
        "binding_crypto": protocol_versioning::DEFAULT_VERSION_BINDING.crypto,
        "family_id": FAMILY_SHIELDED_POOL,
        "action_id": ACTION_MINT_COINBASE,
        "new_nullifiers": [],
        "public_args": base64::engine::general_purpose::STANDARD.encode(args.encode()),
    }))
    .expect("stage test coinbase");
}
