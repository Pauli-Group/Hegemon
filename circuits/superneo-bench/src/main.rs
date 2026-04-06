use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
    time::Instant,
};

use anyhow::{ensure, Context, Result};
use blake3::Hasher;
use clap::{Parser, ValueEnum};
use consensus::{clear_verified_native_tx_leaf_store, native_receipt_root_verify_mode_label};
use native_backend_ref::{
    verify_case as reference_verify_case, ReviewVectorCase as RefReviewVectorCase,
};
use p3_goldilocks::Goldilocks;
use rayon::{prelude::*, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use superneo_backend_lattice::{
    centered_goldilocks_value, clear_prepared_matrix_cache, derive_commitment_ring_matrix,
    goldilocks_frog_quotient_model, left_multiplication_operator_matrix,
    reset_kernel_runtime_state, take_kernel_cost_report, BackendKey, CommitmentEstimatorModel,
    CommitmentSecurityModel, FoldDigestProof, GoldilocksFrogQuotientModel, KernelCostReport,
    LatticeBackend, LatticeCommitment, LeafDigestProof, NativeBackendParams, NativeSecurityClaim,
    ReviewState, RingElem,
};
use superneo_ccs::{Relation, RelationId, ShapeDigest, StatementDigest};
use superneo_core::{Backend, FoldArtifact, FoldStep, FoldedInstance, LeafArtifact};
use superneo_hegemon::{
    build_native_receipt_root_hierarchy_from_records_with_params,
    build_native_tx_leaf_artifact_bytes, build_native_tx_leaf_artifact_bytes_with_params,
    build_native_tx_leaf_receipt_root_artifact_bytes,
    build_native_tx_leaf_receipt_root_artifact_bytes_with_params,
    build_receipt_root_artifact_bytes, build_tx_leaf_artifact_bytes, build_tx_proof_receipt,
    build_verified_tx_proof_receipt_root_artifact_bytes,
    canonical_tx_validity_receipt_from_transaction_proof, clear_native_receipt_root_build_caches,
    decode_native_tx_leaf_artifact_bytes, decode_receipt_root_artifact_bytes,
    encode_native_tx_leaf_artifact_bytes, encode_receipt_root_artifact_bytes,
    fold_native_receipt_root_instances_with_params, native_backend_params,
    native_receipt_root_leaf_instance_from_record_with_params, native_receipt_root_mini_root_size,
    native_tx_leaf_commitment_stats_with_params, native_tx_leaf_record_from_artifact,
    native_tx_validity_statement_from_witness, tx_leaf_public_tx_from_transaction_proof,
    tx_leaf_public_tx_from_witness, verify_native_tx_leaf_artifact_bytes,
    verify_native_tx_leaf_artifact_bytes_with_params,
    verify_native_tx_leaf_receipt_root_artifact_bytes,
    verify_native_tx_leaf_receipt_root_artifact_from_records_with_params,
    verify_receipt_root_artifact_bytes, verify_tx_leaf_artifact_bytes,
    verify_verified_tx_proof_receipt_root_artifact_bytes, CanonicalTxValidityReceipt,
    NativeReceiptRootHierarchy, NativeTxLeafCommitmentStats, NativeTxLeafRecord,
    NativeTxValidityRelation, ToyBalanceRelation, ToyBalanceStatement, ToyBalanceWitness,
    TxLeafPublicRelation, TxProofReceiptRelation, TxProofReceiptWitness,
};
use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use transaction_circuit::proof::{prove, TransactionProof};
use transaction_circuit::{StablecoinPolicyBinding, TransactionWitness};

const GOLDILOCKS_MODULUS_U64: u64 = 18_446_744_069_414_584_321;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum RelationChoice {
    #[value(help = "Diagnostic toy lane; crate-level plumbing only")]
    ToyBalance,
    #[value(help = "Diagnostic synthetic receipt lane; crate-level regression only")]
    TxReceipt,
    #[value(help = "Diagnostic native witness lane; relation-only measurements")]
    NativeTxValidity,
    #[value(
        help = "Canonical experimental lane: native witness -> native tx-leaf -> receipt-root"
    )]
    NativeTxLeafReceiptRoot,
    #[value(help = "Diagnostic bridge lane: proof-ready tx-leaf -> receipt-root")]
    TxLeafReceiptRoot,
    #[value(help = "Diagnostic bridge lane: inline proofs -> receipt-root")]
    VerifiedTxReceipt,
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Benchmark the experimental SuperNeo stack",
    after_help = "The canonical experimental surface is native_tx_leaf_receipt_root. Every other relation is diagnostic-only and requires --allow-diagnostic-relation."
)]
struct Cli {
    #[arg(long, value_enum, default_value_t = RelationChoice::NativeTxLeafReceiptRoot)]
    relation: RelationChoice,
    #[arg(
        long,
        help = "Allow a non-canonical diagnostic relation instead of the native mainline lane"
    )]
    allow_diagnostic_relation: bool,
    #[arg(long, value_delimiter = ',', default_values_t = vec![1usize])]
    k: Vec<usize>,
    #[arg(long)]
    compare_inline_tx: bool,
    #[arg(
        long,
        help = "Print the current native backend params and security claim as JSON and exit"
    )]
    print_native_security_claim: bool,
    #[arg(
        long,
        help = "Print the current native backend review manifest as JSON and exit"
    )]
    print_native_review_manifest: bool,
    #[arg(
        long,
        help = "Print the current native backend attack-model artifact as JSON and exit"
    )]
    print_native_attack_model: bool,
    #[arg(
        long,
        help = "Print the current native backend live message-class artifact as JSON and exit"
    )]
    print_native_message_class: bool,
    #[arg(
        long,
        help = "Print the current native backend claim-sensitivity sweep as JSON and exit"
    )]
    print_native_claim_sweep: bool,
    #[arg(
        long,
        help = "Print the current native backend structured-lattice review model as JSON and exit"
    )]
    print_native_structured_lattice_model: bool,
    #[arg(
        long,
        help = "Export the exact active conservative ring and flattened SIS matrices into this directory"
    )]
    export_native_flattened_sis_instance: Option<PathBuf>,
    #[arg(
        long,
        help = "Run reduced-instance CRT/subfield/low-norm kernel search spikes and print JSON"
    )]
    run_native_reduced_cryptanalysis_spikes: bool,
    #[arg(
        long,
        help = "Emit deterministic native backend review vectors into this directory"
    )]
    emit_review_vectors: Option<PathBuf>,
    #[arg(
        long,
        help = "Emit a deterministic native tx-leaf record corpus JSON file and exit; uses --leaf-count as the record count"
    )]
    emit_native_leaf_record_corpus: Option<PathBuf>,
    #[arg(
        long,
        help = "Load a deterministic native tx-leaf record corpus JSON file for hierarchy/build measurements"
    )]
    native_leaf_record_corpus: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = 16usize,
        help = "When emitting a native tx-leaf record corpus, build at most this many real seed records before deterministic synthetic expansion"
    )]
    native_leaf_record_corpus_seed_count: usize,
    #[arg(
        long,
        help = "Replay a review bundle through the production verifier and print a JSON report"
    )]
    verify_review_bundle_production: Option<PathBuf>,
    #[arg(
        long,
        help = "Run a malformed-artifact differential fuzz pass against this review bundle directory"
    )]
    differential_fuzz_native_review_bundle: Option<PathBuf>,
    #[arg(
        long,
        help = "Run the targeted native review-bundle mutation campaign against this directory"
    )]
    attack_native_review_bundle: Option<PathBuf>,
    #[arg(
        long,
        help = "Build a native receipt-root instance once and measure verify-only cost"
    )]
    measure_native_receipt_root_verify_only: bool,
    #[arg(
        long,
        help = "Report deterministic mini-root reuse and touched-node counts for one changed leaf"
    )]
    measure_native_receipt_root_hierarchy: bool,
    #[arg(
        long,
        help = "Report deterministic epoch-root parent-path reuse for one changed block root"
    )]
    measure_native_epoch_root_hierarchy: bool,
    #[arg(
        long,
        help = "Measure native receipt-root aggregation build cost with mini-root caches and worker parallelism"
    )]
    measure_native_receipt_root_build: bool,
    #[arg(
        long,
        default_value_t = 128usize,
        help = "Leaf count for the verify-only native receipt-root measurement harness"
    )]
    leaf_count: usize,
    #[arg(
        long,
        default_value_t = 3usize,
        help = "Number of verify-only timing runs for the measurement harness"
    )]
    verify_runs: usize,
    #[arg(
        long,
        default_value_t = 8usize,
        help = "Mini-root size for hierarchy measurement commands"
    )]
    mini_root_size: usize,
    #[arg(
        long,
        default_value_t = 0usize,
        help = "Changed leaf index for hierarchy measurement commands"
    )]
    mutate_leaf_index: usize,
    #[arg(
        long,
        default_value_t = 1024usize,
        help = "Block count for epoch hierarchy measurement commands"
    )]
    block_count: usize,
    #[arg(
        long,
        default_value_t = 1usize,
        help = "Worker count for native receipt-root aggregation build measurement"
    )]
    workers: usize,
    #[arg(
        long,
        default_value_t = 0usize,
        help = "When positive, run one exact-repeat warm build after the cold aggregation build"
    )]
    warm_repeat: usize,
    #[arg(
        long,
        default_value_t = 0usize,
        help = "Changed block index for epoch hierarchy measurement commands"
    )]
    mutate_block_index: usize,
    #[arg(
        long,
        default_value_t = 128usize,
        help = "Number of malformed mutations to generate in the differential fuzz pass"
    )]
    mutation_count: usize,
    #[arg(
        long,
        default_value_t = 20_260_404u64,
        help = "Deterministic seed for malformed-artifact mutation passes"
    )]
    mutation_seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InlineTxBaseline {
    bytes_per_tx: usize,
    total_active_path_prove_ns: u128,
    total_active_path_verify_ns: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchResult {
    relation: String,
    k: usize,
    parameter_fingerprint: Option<String>,
    native_backend_params: Option<BenchNativeBackendParams>,
    native_security_claim: Option<BenchNativeSecurityClaim>,
    bytes_per_tx: usize,
    total_active_path_prove_ns: u128,
    total_active_path_verify_ns: u128,
    packed_witness_bits: usize,
    shape_digest: String,
    note: String,
    edge_prepare_ns: Option<u128>,
    peak_rss_bytes: Option<u64>,
    kernel_report: Option<KernelCostReport>,
    inline_tx_baseline: Option<InlineTxBaseline>,
    import_comparison: Option<ImportComparison>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchNativeBackendParams {
    family_label: String,
    spec_label: String,
    spec_digest: String,
    commitment_scheme_label: String,
    challenge_schedule_label: String,
    maturity_label: String,
    security_bits: u32,
    ring_profile: String,
    matrix_rows: usize,
    matrix_cols: usize,
    challenge_bits: u32,
    fold_challenge_count: u32,
    max_fold_arity: u32,
    transcript_domain_label: String,
    decomposition_bits: u32,
    opening_randomness_bits: u32,
    commitment_security_model: String,
    commitment_estimator_model: String,
    max_commitment_message_ring_elems: u32,
    max_claimed_receipt_root_leaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchNativeSecurityClaim {
    claimed_security_bits: u32,
    #[serde(default)]
    soundness_scope_label: String,
    transcript_soundness_bits: u32,
    opening_hiding_bits: u32,
    commitment_codomain_bits: u32,
    commitment_same_seed_search_bits: u32,
    commitment_random_matrix_bits: u32,
    commitment_problem_equations: u32,
    commitment_problem_dimension: u32,
    commitment_problem_coeff_bound: u32,
    commitment_problem_l2_bound: u32,
    commitment_estimator_dimension: u32,
    commitment_estimator_block_size: u32,
    commitment_estimator_classical_bits: u32,
    commitment_estimator_quantum_bits: u32,
    commitment_estimator_paranoid_bits: u32,
    commitment_reduction_loss_bits: u32,
    commitment_binding_bits: u32,
    composition_loss_bits: u32,
    soundness_floor_bits: u32,
    assumption_ids: Vec<String>,
    review_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NativeAttackModelReport {
    parameter_fingerprint: String,
    native_backend_params: BenchNativeBackendParams,
    native_security_claim: BenchNativeSecurityClaim,
    exact_live_tx_leaf_commitment: NativeTxLeafCommitmentStats,
    transcript_model: TranscriptAttackModel,
    estimator_trace: EstimatorTraceReport,
    theorem_documents: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NativeStructuredLatticeReport {
    parameter_fingerprint: String,
    native_backend_params: BenchNativeBackendParams,
    native_security_claim: BenchNativeSecurityClaim,
    exact_live_tx_leaf_commitment: NativeTxLeafCommitmentStats,
    conservative_instance: FlattenedSisInstanceReport,
    quotient_model: GoldilocksFrogQuotientReport,
    inverse_crt_report: InverseCrtReport,
    threshold_table: Vec<SecurityThresholdRow>,
    reviewer_artifacts: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FlattenedSisInstanceReport {
    modulus: u64,
    ring_profile: String,
    ring_rows: usize,
    message_ring_elems: usize,
    ring_degree: usize,
    equation_dimension: usize,
    witness_dimension: usize,
    coeff_bound: u32,
    l2_bound: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct GoldilocksFrogQuotientReport {
    modulus: u64,
    omega: u64,
    omega_squared: u64,
    omega_squared_centered: i128,
    denominator: u64,
    denominator_centered: i128,
    denominator_inverse: u64,
    denominator_inverse_centered: i128,
    e1_x27_coeff: u64,
    e1_x27_coeff_centered: i128,
    e1_const_coeff: u64,
    e1_const_coeff_centered: i128,
    e2_x27_coeff: u64,
    e2_x27_coeff_centered: i128,
    e2_const_coeff: u64,
    e2_const_coeff_centered: i128,
}

#[derive(Debug, Serialize, Deserialize)]
struct InverseCrtReport {
    component_box_bound: i32,
    balanced_pair_example: PairLiftExample,
    min_one_component_max_coeff_abs: i128,
    min_one_component_example: PairLiftExample,
    min_nonzero_component_difference_max_coeff_abs: i128,
    min_nonzero_component_difference_example: PairLiftExample,
    min_abs_x27_coeff_for_nonzero_component_difference: i128,
    min_abs_x27_coeff_delta_example: PairDeltaExample,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairLiftExample {
    left_component: i32,
    right_component: i32,
    const_coeff_centered: i128,
    x27_coeff_centered: i128,
    max_coeff_abs: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairDeltaExample {
    component_difference: i32,
    x27_coeff_centered: i128,
    abs_x27_coeff: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityThresholdRow {
    target_bits: u32,
    minimum_block_size: u32,
    block_size_haircut: u32,
    fraction_of_active_block_size: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct FlattenedSisExportReport {
    output_dir: String,
    parameter_fingerprint: String,
    matrix_metadata_path: String,
    ring_matrix_path: String,
    flat_matrix_path: String,
    ring_matrix_bytes: usize,
    flat_matrix_bytes: usize,
    metadata: FlattenedSisMatrixMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
struct FlattenedSisMatrixMetadata {
    parameter_fingerprint: String,
    relation_id_hex: String,
    shape_digest_hex: String,
    modulus: u64,
    byte_order: String,
    ring_matrix_layout: String,
    flat_matrix_layout: String,
    ring_rows: usize,
    ring_cols: usize,
    ring_degree: usize,
    flat_rows: usize,
    flat_cols: usize,
    ring_matrix_file: String,
    flat_matrix_file: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReducedCryptanalysisSpikesReport {
    parameter_fingerprint: String,
    native_backend_params: BenchNativeBackendParams,
    reduced_matrix: ReducedMatrixDescriptor,
    cases: Vec<ReducedCryptanalysisCase>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReducedMatrixDescriptor {
    ring_rows: usize,
    ring_cols: usize,
    ring_degree: usize,
    flat_rows: usize,
    flat_cols: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReducedCryptanalysisCase {
    name: String,
    description: String,
    variable_count: usize,
    searched_candidates: u128,
    found_nonzero_kernel: bool,
    first_kernel_vector: Option<Vec<SearchCoordinate>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchCoordinate {
    index: usize,
    coeff: i16,
}

#[derive(Debug, Serialize, Deserialize)]
struct TranscriptAttackModel {
    challenge_bits: u32,
    fold_challenge_count: u32,
    support_size: u64,
    raw_space_bits: u32,
    max_preimage_count: u64,
    transcript_soundness_bits: u32,
    tuple_min_entropy_bits: f64,
    composition_loss_bits: u32,
    transcript_floor_bits: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct EstimatorTraceReport {
    equation_dimension: u32,
    witness_dimension: u32,
    modulus: u64,
    l2_bound: u32,
    log2_q: f64,
    log2_bound: f64,
    log_delta: f64,
    reduced_dimension: u32,
    target_delta: f64,
    block_size: u32,
    classical_bits: u32,
    quantum_bits: u32,
    paranoid_bits: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct NativeClaimSweepReport {
    fixed_security_target_bits: u32,
    active_message_cap: u32,
    active_receipt_root_leaf_cap: u32,
    message_cap_rows: Vec<ClaimSweepRow>,
    receipt_root_leaf_rows: Vec<ClaimSweepRow>,
    first_message_cap_failure: Option<ClaimSweepRow>,
    first_receipt_root_leaf_failure: Option<ClaimSweepRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaimSweepRow {
    max_commitment_message_ring_elems: u32,
    max_claimed_receipt_root_leaves: u32,
    transcript_soundness_bits: u32,
    commitment_binding_bits: u32,
    soundness_floor_bits: u32,
    claim_supported: bool,
    claim_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProductionReviewReport {
    summary: ProductionReviewVerificationSummary,
    results: Vec<ProductionReviewCaseResult>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProductionReviewVerificationSummary {
    bundle_path: String,
    case_count: usize,
    passed_cases: usize,
    failed_cases: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProductionReviewCaseResult {
    name: String,
    expected_valid: bool,
    passed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct VerifierParityReport {
    campaign: String,
    bundle_path: String,
    seed: Option<u64>,
    summary: VerifierParitySummary,
    results: Vec<VerifierParityCaseResult>,
}

#[derive(Debug, Serialize)]
struct VerifierParitySummary {
    case_count: usize,
    agreement_rejections: usize,
    agreement_acceptances: usize,
    disagreements: usize,
    unexpected_acceptances: usize,
}

#[derive(Debug, Serialize)]
struct VerifierParityCaseResult {
    name: String,
    kind: String,
    mutation: String,
    production: VerificationOutcome,
    reference: VerificationOutcome,
    agreed: bool,
    unexpected_acceptance: bool,
}

#[derive(Debug, Clone, Serialize)]
struct VerificationOutcome {
    accepted: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct NativeVerifyOnlyReport {
    parameter_fingerprint: String,
    leaf_count: usize,
    verify_runs: usize,
    product_default_root_verify_mode: String,
    tx_leaf_artifacts_bytes_total: usize,
    receipt_root_artifact_bytes: usize,
    prepare_artifacts_ns: u128,
    extract_records_ns: u128,
    cold_cache_between_runs: bool,
    leaf_verify: TimingStats,
    receipt_root_replay_verify: TimingStats,
    receipt_root_records_verify: TimingStats,
    full_block_verify: TimingStats,
}

#[derive(Debug, Serialize)]
struct ReceiptRootHierarchyReport {
    parameter_fingerprint: String,
    record_source: String,
    leaf_count: usize,
    mini_root_size: usize,
    changed_leaf_index: usize,
    layer_widths: Vec<usize>,
    mini_roots_total: usize,
    mini_roots_reused: usize,
    mini_roots_rebuilt: usize,
    changed_mini_root_leaf_count: usize,
    block_internal_nodes_touched: usize,
    flat_internal_nodes_touched: usize,
    baseline_root_statement_digest: String,
    mutated_root_statement_digest: String,
}

#[derive(Debug, Serialize)]
struct EpochRootHierarchyReport {
    parameter_fingerprint: String,
    record_source: String,
    block_count: usize,
    changed_block_index: usize,
    layer_widths: Vec<usize>,
    epoch_internal_nodes_touched: usize,
    flat_epoch_internal_nodes: usize,
    baseline_epoch_root_statement_digest: String,
    mutated_epoch_root_statement_digest: String,
}

#[derive(Debug, Serialize)]
struct NativeReceiptRootBuildReport {
    parameter_fingerprint: String,
    record_source: String,
    leaf_count: usize,
    mini_root_size: usize,
    workers: usize,
    cold: AggregationBuildRunReport,
    exact_repeat: Option<AggregationBuildRunReport>,
    mutated_repeat: Option<AggregationBuildRunReport>,
}

#[derive(Debug, Serialize)]
struct AggregationBuildRunReport {
    label: String,
    total_ns: u128,
    mini_roots_total: usize,
    mini_root_cache_hits: usize,
    mini_root_cache_misses: usize,
    upper_tree_cache_hits: usize,
    upper_tree_cache_misses: usize,
    internal_fold_nodes_rebuilt: usize,
    root_statement_digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NativeLeafRecordCorpus {
    parameter_fingerprint: String,
    record_count: usize,
    seed_record_count: usize,
    synthetic_expansion: bool,
    records: Vec<BenchNativeLeafRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchNativeLeafRecord {
    params_fingerprint_hex: String,
    spec_digest_hex: String,
    relation_id_hex: String,
    shape_digest_hex: String,
    statement_digest_hex: String,
    commitment: LatticeCommitment,
    proof_digest_hex: String,
}

impl From<&NativeTxLeafRecord> for BenchNativeLeafRecord {
    fn from(record: &NativeTxLeafRecord) -> Self {
        Self {
            params_fingerprint_hex: hex48(record.params_fingerprint),
            spec_digest_hex: hex::encode(record.spec_digest),
            relation_id_hex: hex::encode(record.relation_id),
            shape_digest_hex: hex::encode(record.shape_digest),
            statement_digest_hex: hex48(record.statement_digest),
            commitment: record.commitment.clone(),
            proof_digest_hex: hex48(record.proof_digest),
        }
    }
}

impl BenchNativeLeafRecord {
    fn decode(self) -> Result<NativeTxLeafRecord> {
        Ok(NativeTxLeafRecord {
            params_fingerprint: decode_hex_array::<48>(&self.params_fingerprint_hex)?,
            spec_digest: decode_hex_array::<32>(&self.spec_digest_hex)?,
            relation_id: decode_hex_array::<32>(&self.relation_id_hex)?,
            shape_digest: decode_hex_array::<32>(&self.shape_digest_hex)?,
            statement_digest: decode_hex_array::<48>(&self.statement_digest_hex)?,
            commitment: self.commitment,
            proof_digest: decode_hex_array::<48>(&self.proof_digest_hex)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MiniRootLeafIdentity {
    statement_digest: [u8; 48],
    commitment_digest: [u8; 48],
    proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct MiniRootCacheKey {
    params_fingerprint: [u8; 48],
    leaves: Vec<MiniRootLeafIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UpperTreeChildIdentity {
    statement_digest: [u8; 48],
    commitment_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UpperTreeCacheKey {
    params_fingerprint: [u8; 48],
    children: Vec<UpperTreeChildIdentity>,
}

#[derive(Default)]
struct NativeReceiptRootBuildCaches {
    mini_roots: HashMap<MiniRootCacheKey, FoldedInstance<LatticeCommitment>>,
    upper_tree: HashMap<UpperTreeCacheKey, FoldedInstance<LatticeCommitment>>,
}

#[derive(Debug, Serialize)]
struct TimingStats {
    runs_ns: Vec<u128>,
    min_ns: u128,
    max_ns: u128,
    avg_ns: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct NativeSecurityClaimReport {
    parameter_fingerprint: String,
    native_backend_params: BenchNativeBackendParams,
    native_security_claim: BenchNativeSecurityClaim,
}

#[derive(Debug, Serialize, Deserialize)]
struct NativeReviewGuaranteeSummary {
    security_object: String,
    verified_tx_leaf_replay: bool,
    leaf_statement_digest_rechecked: bool,
    leaf_commitment_digest_rechecked: bool,
    leaf_proof_digest_rechecked: bool,
    fold_challenges_recomputed: bool,
    fold_parent_rows_recomputed: bool,
    fold_parent_statement_digest_recomputed: bool,
    fold_parent_commitment_recomputed: bool,
    fold_proof_digest_recomputed: bool,
    ccs_soundness_from_fold_layer_alone: bool,
    external_cryptanalysis_completed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct NativeReviewManifestReport {
    parameter_fingerprint: String,
    native_backend_params: BenchNativeBackendParams,
    native_security_claim: BenchNativeSecurityClaim,
    exact_live_tx_leaf_commitment: NativeTxLeafCommitmentStats,
    guarantee_summary: NativeReviewGuaranteeSummary,
    theorem_documents: Vec<String>,
    review_workflow_documents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewVectorBundle {
    parameter_fingerprint: String,
    native_backend_params: BenchNativeBackendParams,
    native_security_claim: BenchNativeSecurityClaim,
    cases: Vec<ReviewVectorCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewVectorCase {
    name: String,
    kind: String,
    expected_valid: bool,
    expected_error_substring: Option<String>,
    artifact_hex: String,
    tx_context: Option<ReviewTxContext>,
    block_context: Option<ReviewBlockContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewBackendParams {
    family_label: String,
    spec_label: String,
    commitment_scheme_label: String,
    challenge_schedule_label: String,
    maturity_label: String,
    security_bits: u32,
    ring_profile: String,
    matrix_rows: usize,
    matrix_cols: usize,
    challenge_bits: u32,
    fold_challenge_count: u32,
    max_fold_arity: u32,
    transcript_domain_label: String,
    decomposition_bits: u32,
    opening_randomness_bits: u32,
    commitment_security_model: String,
    commitment_estimator_model: String,
    max_commitment_message_ring_elems: u32,
    max_claimed_receipt_root_leaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewReceipt {
    statement_hash_hex: String,
    proof_digest_hex: String,
    public_inputs_digest_hex: String,
    verifier_profile_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewSerializedStarkInputs {
    input_flags: Vec<u8>,
    output_flags: Vec<u8>,
    fee: u64,
    value_balance_sign: u8,
    value_balance_magnitude: u64,
    merkle_root_hex: String,
    balance_slot_asset_ids: Vec<u64>,
    stablecoin_enabled: u8,
    stablecoin_asset_id: u64,
    stablecoin_policy_version: u32,
    stablecoin_issuance_sign: u8,
    stablecoin_issuance_magnitude: u64,
    stablecoin_policy_hash_hex: String,
    stablecoin_oracle_commitment_hex: String,
    stablecoin_attestation_commitment_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewTxPublicTx {
    nullifiers_hex: Vec<String>,
    commitments_hex: Vec<String>,
    ciphertext_hashes_hex: Vec<String>,
    balance_tag_hex: String,
    version_circuit: u16,
    version_crypto: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewTxContext {
    backend_params: ReviewBackendParams,
    expected_version: u16,
    params_fingerprint_hex: String,
    spec_digest_hex: String,
    relation_id_hex: String,
    shape_digest_hex: String,
    statement_digest_hex: String,
    receipt: ReviewReceipt,
    tx: ReviewTxPublicTx,
    stark_public_inputs: ReviewSerializedStarkInputs,
    commitment_rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewReceiptLeafContext {
    statement_digest_hex: String,
    witness_commitment_hex: String,
    proof_digest_hex: String,
    commitment_rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReviewBlockContext {
    backend_params: ReviewBackendParams,
    expected_version: u16,
    params_fingerprint_hex: String,
    spec_digest_hex: String,
    relation_id_hex: String,
    shape_digest_hex: String,
    root_statement_digest_hex: String,
    root_commitment_hex: String,
    leaves: Vec<ReviewReceiptLeafContext>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportComparison {
    baseline_verify_ns: u128,
    accumulation_prewarm_ns: Option<u128>,
    accumulation_warm_verify_ns: Option<u128>,
    cold_residual_verify_ns: Option<u128>,
    cold_residual_artifact_bytes: Option<usize>,
    cold_residual_replayed_leaf_verifications: Option<usize>,
    cold_residual_used_old_aggregation_backend: Option<bool>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure!(cli.leaf_count > 0, "--leaf-count must be strictly positive");
    ensure!(
        cli.verify_runs > 0,
        "--verify-runs must be strictly positive"
    );
    ensure!(
        cli.mini_root_size > 0,
        "--mini-root-size must be strictly positive"
    );
    ensure!(
        cli.mini_root_size.is_power_of_two(),
        "--mini-root-size must be a power of two"
    );
    ensure!(
        cli.block_count > 0,
        "--block-count must be strictly positive"
    );
    ensure!(cli.workers > 0, "--workers must be strictly positive");
    ensure!(
        cli.native_leaf_record_corpus_seed_count > 0,
        "--native-leaf-record-corpus-seed-count must be strictly positive"
    );
    ensure!(
        cli.mutation_count > 0,
        "--mutation-count must be strictly positive"
    );
    ensure!(
        !(cli.emit_native_leaf_record_corpus.is_some() && cli.native_leaf_record_corpus.is_some()),
        "--emit-native-leaf-record-corpus and --native-leaf-record-corpus are mutually exclusive"
    );
    if cli.print_native_security_claim {
        let report = NativeSecurityClaimReport {
            parameter_fingerprint: current_parameter_fingerprint_hex(),
            native_backend_params: current_bench_native_backend_params(),
            native_security_claim: current_bench_native_security_claim()?,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.print_native_review_manifest {
        let report = current_native_review_manifest()?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.print_native_attack_model {
        let report = current_native_attack_model()?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.print_native_message_class {
        let report = current_native_tx_leaf_message_class();
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.print_native_claim_sweep {
        let report = current_native_claim_sweep()?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.print_native_structured_lattice_model {
        let report = current_native_structured_lattice_model()?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Some(dir) = &cli.export_native_flattened_sis_instance {
        let report = export_native_flattened_sis_instance(dir)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.run_native_reduced_cryptanalysis_spikes {
        let report = run_native_reduced_cryptanalysis_spikes()?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if let Some(dir) = &cli.emit_review_vectors {
        emit_review_vectors(dir)?;
        return Ok(());
    }
    if let Some(path) = &cli.emit_native_leaf_record_corpus {
        emit_native_leaf_record_corpus(
            path,
            cli.leaf_count,
            cli.native_leaf_record_corpus_seed_count,
        )?;
        return Ok(());
    }
    if let Some(dir) = &cli.verify_review_bundle_production {
        let report = verify_review_bundle_production(dir)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        ensure!(
            report.summary.failed_cases == 0,
            "one or more production review cases failed"
        );
        return Ok(());
    }
    if let Some(dir) = &cli.differential_fuzz_native_review_bundle {
        let report =
            differential_fuzz_native_review_bundle(dir, cli.mutation_seed, cli.mutation_count)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        ensure!(
            report.summary.disagreements == 0 && report.summary.unexpected_acceptances == 0,
            "differential malformed-artifact fuzzing found {} disagreements and {} unexpected acceptances",
            report.summary.disagreements,
            report.summary.unexpected_acceptances
        );
        return Ok(());
    }
    if let Some(dir) = &cli.attack_native_review_bundle {
        let report = attack_native_review_bundle(dir)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        ensure!(
            report.summary.disagreements == 0 && report.summary.unexpected_acceptances == 0,
            "targeted native attack campaign found {} disagreements and {} unexpected acceptances",
            report.summary.disagreements,
            report.summary.unexpected_acceptances
        );
        return Ok(());
    }
    if cli.measure_native_receipt_root_verify_only {
        let report = measure_native_receipt_root_verify_only(cli.leaf_count, cli.verify_runs)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.measure_native_receipt_root_hierarchy {
        let report = measure_native_receipt_root_hierarchy(
            cli.leaf_count,
            cli.mini_root_size,
            cli.mutate_leaf_index,
            cli.native_leaf_record_corpus.as_deref(),
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.measure_native_epoch_root_hierarchy {
        let report = measure_native_epoch_root_hierarchy(
            cli.block_count,
            cli.mutate_block_index,
            cli.native_leaf_record_corpus.as_deref(),
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if cli.measure_native_receipt_root_build {
        let report = measure_native_receipt_root_build(
            cli.leaf_count,
            cli.mini_root_size,
            cli.workers,
            cli.warm_repeat,
            cli.mutate_leaf_index,
            cli.native_leaf_record_corpus.as_deref(),
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    ensure!(!cli.k.is_empty(), "at least one k value is required");
    ensure!(
        cli.k.iter().all(|k| *k > 0),
        "k values must be strictly positive"
    );
    validate_relation_selection(cli.relation, cli.allow_diagnostic_relation)?;

    if cli.k.len() > 1 {
        let mut results = Vec::with_capacity(cli.k.len());
        for k in cli.k {
            results.push(run_isolated_benchmark_case(
                cli.relation,
                cli.allow_diagnostic_relation,
                cli.compare_inline_tx,
                k,
            )?);
        }
        println!("{}", serde_json::to_string_pretty(&results)?);
        return Ok(());
    }

    let baselines = if cli.compare_inline_tx {
        load_inline_tx_baselines()?
    } else {
        HashMap::new()
    };

    let mut results = Vec::with_capacity(cli.k.len());
    for k in cli.k {
        let inline_tx_baseline = baselines.get(&k).cloned();
        let result = match cli.relation {
            RelationChoice::ToyBalance => benchmark_toy_balance(k, inline_tx_baseline)?,
            RelationChoice::TxReceipt => benchmark_tx_receipt(k, inline_tx_baseline)?,
            RelationChoice::NativeTxValidity => {
                benchmark_native_tx_validity(k, inline_tx_baseline)?
            }
            RelationChoice::NativeTxLeafReceiptRoot => {
                benchmark_native_tx_leaf_receipt_root(k, inline_tx_baseline)?
            }
            RelationChoice::TxLeafReceiptRoot => {
                benchmark_tx_leaf_receipt_root(k, inline_tx_baseline)?
            }
            RelationChoice::VerifiedTxReceipt => {
                benchmark_verified_tx_receipt(k, inline_tx_baseline)?
            }
        };
        results.push(result);
    }

    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

fn run_isolated_benchmark_case(
    relation: RelationChoice,
    allow_diagnostic_relation: bool,
    compare_inline_tx: bool,
    k: usize,
) -> Result<BenchResult> {
    let exe = std::env::current_exe().context("failed to locate current benchmark executable")?;
    let mut command = Command::new(exe);
    command
        .arg("--relation")
        .arg(
            relation
                .to_possible_value()
                .expect("relation enum value")
                .get_name(),
        )
        .arg("--k")
        .arg(k.to_string());
    if allow_diagnostic_relation {
        command.arg("--allow-diagnostic-relation");
    }
    if compare_inline_tx {
        command.arg("--compare-inline-tx");
    }

    let output = command
        .output()
        .with_context(|| format!("failed to spawn isolated benchmark process for k={k}"))?;
    ensure!(
        output.status.success(),
        "isolated benchmark process failed for k={k}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut results: Vec<BenchResult> = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("failed to parse isolated benchmark JSON for k={k}"))?;
    ensure!(
        results.len() == 1,
        "isolated benchmark process for k={} returned {} result rows",
        k,
        results.len()
    );
    Ok(results.pop().expect("single isolated benchmark result"))
}

fn is_canonical_relation(choice: RelationChoice) -> bool {
    matches!(choice, RelationChoice::NativeTxLeafReceiptRoot)
}

fn relation_lane_label(choice: RelationChoice) -> &'static str {
    if is_canonical_relation(choice) {
        "canonical experimental lane"
    } else {
        "diagnostic lane"
    }
}

fn relation_description(choice: RelationChoice) -> &'static str {
    match choice {
        RelationChoice::ToyBalance => {
            "toy fold backend plumbing; useful only for crate-level regression coverage"
        }
        RelationChoice::TxReceipt => "synthetic receipt fold path; not a planning-grade topology",
        RelationChoice::NativeTxValidity => {
            "native witness relation without the tx-leaf -> receipt-root topology"
        }
        RelationChoice::NativeTxLeafReceiptRoot => {
            "native witness -> native tx-leaf -> receipt-root baseline topology"
        }
        RelationChoice::TxLeafReceiptRoot => {
            "bridge topology built from proof-ready tx-leaf artifacts"
        }
        RelationChoice::VerifiedTxReceipt => {
            "bridge topology built from verified inline transaction proofs"
        }
    }
}

fn note_prefix(choice: RelationChoice) -> String {
    format!(
        "{}: {}",
        relation_lane_label(choice),
        relation_description(choice)
    )
}

fn current_native_backend_params() -> NativeBackendParams {
    native_backend_params()
}

fn current_parameter_fingerprint_hex() -> String {
    hex48(current_native_backend_params().parameter_fingerprint())
}

fn current_bench_native_backend_params() -> BenchNativeBackendParams {
    let params = current_native_backend_params();
    BenchNativeBackendParams {
        family_label: params.manifest.family_label.to_owned(),
        spec_label: params.manifest.spec_label.to_owned(),
        spec_digest: hex32(params.spec_digest()),
        commitment_scheme_label: params.manifest.commitment_scheme_label.to_owned(),
        challenge_schedule_label: params.manifest.challenge_schedule_label.to_owned(),
        maturity_label: params.manifest.maturity_label.to_owned(),
        security_bits: params.security_bits,
        ring_profile: format!("{:?}", params.ring_profile),
        matrix_rows: params.matrix_rows,
        matrix_cols: params.matrix_cols,
        challenge_bits: params.challenge_bits,
        fold_challenge_count: params.fold_challenge_count,
        max_fold_arity: params.max_fold_arity,
        transcript_domain_label: params.transcript_domain_label.to_owned(),
        decomposition_bits: params.decomposition_bits,
        opening_randomness_bits: params.opening_randomness_bits,
        commitment_security_model: commitment_security_model_label(
            params.commitment_security_model,
        )
        .to_owned(),
        commitment_estimator_model: commitment_estimator_model_label(
            params.commitment_estimator_model,
        )
        .to_owned(),
        max_commitment_message_ring_elems: params.max_commitment_message_ring_elems,
        max_claimed_receipt_root_leaves: params.max_claimed_receipt_root_leaves,
    }
}

fn current_bench_native_security_claim() -> Result<BenchNativeSecurityClaim> {
    let NativeSecurityClaim {
        claimed_security_bits,
        soundness_scope_label,
        transcript_soundness_bits,
        opening_hiding_bits,
        commitment_codomain_bits,
        commitment_same_seed_search_bits,
        commitment_random_matrix_bits,
        commitment_problem_equations,
        commitment_problem_dimension,
        commitment_problem_coeff_bound,
        commitment_problem_l2_bound,
        commitment_estimator_dimension,
        commitment_estimator_block_size,
        commitment_estimator_classical_bits,
        commitment_estimator_quantum_bits,
        commitment_estimator_paranoid_bits,
        commitment_reduction_loss_bits,
        commitment_binding_bits,
        composition_loss_bits,
        soundness_floor_bits,
        assumption_ids,
        review_state,
    } = current_native_backend_params().security_claim()?;
    Ok(BenchNativeSecurityClaim {
        claimed_security_bits,
        soundness_scope_label: soundness_scope_label.to_owned(),
        transcript_soundness_bits,
        opening_hiding_bits,
        commitment_codomain_bits,
        commitment_same_seed_search_bits,
        commitment_random_matrix_bits,
        commitment_problem_equations,
        commitment_problem_dimension,
        commitment_problem_coeff_bound,
        commitment_problem_l2_bound,
        commitment_estimator_dimension,
        commitment_estimator_block_size,
        commitment_estimator_classical_bits,
        commitment_estimator_quantum_bits,
        commitment_estimator_paranoid_bits,
        commitment_reduction_loss_bits,
        commitment_binding_bits,
        composition_loss_bits,
        soundness_floor_bits,
        assumption_ids: assumption_ids.iter().map(|id| (*id).to_owned()).collect(),
        review_state: review_state_label(review_state).to_owned(),
    })
}

fn current_native_review_manifest() -> Result<NativeReviewManifestReport> {
    let params = current_native_backend_params();
    Ok(NativeReviewManifestReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        native_backend_params: current_bench_native_backend_params(),
        native_security_claim: current_bench_native_security_claim()?,
        exact_live_tx_leaf_commitment: native_tx_leaf_commitment_stats_with_params(&params),
        guarantee_summary: NativeReviewGuaranteeSummary {
            security_object: "verified_leaf_aggregation".to_owned(),
            verified_tx_leaf_replay: true,
            leaf_statement_digest_rechecked: true,
            leaf_commitment_digest_rechecked: true,
            leaf_proof_digest_rechecked: true,
            fold_challenges_recomputed: true,
            fold_parent_rows_recomputed: true,
            fold_parent_statement_digest_recomputed: true,
            fold_parent_commitment_recomputed: true,
            fold_proof_digest_recomputed: true,
            ccs_soundness_from_fold_layer_alone: false,
            external_cryptanalysis_completed: false,
        },
        theorem_documents: vec![
            "docs/crypto/native_backend_formal_theorems.md".to_owned(),
            "docs/crypto/native_backend_verified_aggregation.md".to_owned(),
        ],
        review_workflow_documents: vec![
            "docs/SECURITY_REVIEWS.md".to_owned(),
            "docs/crypto/native_backend_security_analysis.md".to_owned(),
            "docs/crypto/native_backend_commitment_reduction.md".to_owned(),
        ],
    })
}

fn current_native_tx_leaf_message_class() -> NativeTxLeafCommitmentStats {
    native_tx_leaf_commitment_stats_with_params(&current_native_backend_params())
}

fn current_native_attack_model() -> Result<NativeAttackModelReport> {
    let params = current_native_backend_params();
    let claim = current_bench_native_security_claim()?;
    let exact_live_tx_leaf_commitment = native_tx_leaf_commitment_stats_with_params(&params);
    Ok(NativeAttackModelReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        native_backend_params: current_bench_native_backend_params(),
        native_security_claim: claim,
        transcript_model: current_transcript_attack_model(&params)?,
        estimator_trace: current_estimator_trace(&params)?,
        exact_live_tx_leaf_commitment,
        theorem_documents: vec![
            "docs/crypto/native_backend_formal_theorems.md".to_owned(),
            "docs/crypto/native_backend_verified_aggregation.md".to_owned(),
        ],
    })
}

fn current_native_structured_lattice_model() -> Result<NativeStructuredLatticeReport> {
    let params = current_native_backend_params();
    let claim = current_bench_native_security_claim()?;
    let exact_live_tx_leaf_commitment = native_tx_leaf_commitment_stats_with_params(&params);
    let quotient_model = goldilocks_frog_quotient_model();
    Ok(NativeStructuredLatticeReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        native_backend_params: current_bench_native_backend_params(),
        native_security_claim: claim.clone(),
        exact_live_tx_leaf_commitment,
        conservative_instance: FlattenedSisInstanceReport {
            modulus: GOLDILOCKS_MODULUS_U64,
            ring_profile: "GoldilocksFrog".to_owned(),
            ring_rows: params.matrix_rows,
            message_ring_elems: params.max_commitment_message_ring_elems as usize,
            ring_degree: params.ring_degree(),
            equation_dimension: claim.commitment_problem_equations as usize,
            witness_dimension: claim.commitment_problem_dimension as usize,
            coeff_bound: claim.commitment_problem_coeff_bound,
            l2_bound: claim.commitment_problem_l2_bound,
        },
        quotient_model: quotient_report(&quotient_model),
        inverse_crt_report: inverse_crt_report(
            claim.commitment_problem_coeff_bound as i32,
            &quotient_model,
        ),
        threshold_table: security_threshold_table(claim.commitment_estimator_block_size),
        reviewer_artifacts: vec![
            "attack_model.json".to_owned(),
            "message_class.json".to_owned(),
            "claim_sweep.json".to_owned(),
            "structured_lattice_model.json".to_owned(),
            "structured_lattice/matrix_metadata.json".to_owned(),
            "structured_lattice/ring_commitment_matrix_u64_le.bin".to_owned(),
            "structured_lattice/flat_commitment_matrix_u64_le.bin".to_owned(),
            "reduced_cryptanalysis_spikes.json".to_owned(),
        ],
    })
}

fn quotient_report(model: &GoldilocksFrogQuotientModel) -> GoldilocksFrogQuotientReport {
    GoldilocksFrogQuotientReport {
        modulus: model.modulus,
        omega: model.omega,
        omega_squared: model.omega_squared,
        omega_squared_centered: centered_goldilocks_value(model.omega_squared),
        denominator: model.denominator,
        denominator_centered: centered_goldilocks_value(model.denominator),
        denominator_inverse: model.denominator_inverse,
        denominator_inverse_centered: model.denominator_inverse_centered,
        e1_x27_coeff: model.e1_x27_coeff,
        e1_x27_coeff_centered: model.e1_x27_coeff_centered,
        e1_const_coeff: model.e1_const_coeff,
        e1_const_coeff_centered: model.e1_const_coeff_centered,
        e2_x27_coeff: model.e2_x27_coeff,
        e2_x27_coeff_centered: model.e2_x27_coeff_centered,
        e2_const_coeff: model.e2_const_coeff,
        e2_const_coeff_centered: model.e2_const_coeff_centered,
    }
}

fn security_threshold_table(active_block_size: u32) -> Vec<SecurityThresholdRow> {
    [305u32, 256, 192, 128]
        .into_iter()
        .map(|target_bits| {
            let minimum_block_size = ((f64::from(target_bits) / 0.265).ceil()) as u32;
            SecurityThresholdRow {
                target_bits,
                minimum_block_size,
                block_size_haircut: active_block_size.saturating_sub(minimum_block_size),
                fraction_of_active_block_size: f64::from(minimum_block_size)
                    / f64::from(active_block_size.max(1)),
            }
        })
        .collect()
}

fn inverse_crt_report(
    component_box_bound: i32,
    model: &GoldilocksFrogQuotientModel,
) -> InverseCrtReport {
    let balanced_pair_example = pair_lift_example(-1, -1, model);

    let mut min_one_component_example = None;
    let mut min_nonzero_component_difference_example = None;
    let mut min_abs_x27_coeff_delta_example = None;

    for left in -component_box_bound..=component_box_bound {
        for right in -component_box_bound..=component_box_bound {
            if left == 0 && right == 0 {
                continue;
            }
            let example = pair_lift_example(left, right, model);
            if (left == 0) != (right == 0) {
                let replace = min_one_component_example
                    .as_ref()
                    .map(|current: &PairLiftExample| example.max_coeff_abs < current.max_coeff_abs)
                    .unwrap_or(true);
                if replace {
                    min_one_component_example = Some(example.clone());
                }
            }
            if left != right {
                let replace = min_nonzero_component_difference_example
                    .as_ref()
                    .map(|current: &PairLiftExample| example.max_coeff_abs < current.max_coeff_abs)
                    .unwrap_or(true);
                if replace {
                    min_nonzero_component_difference_example = Some(example);
                }
            }
        }
    }

    for delta in -component_box_bound..=component_box_bound {
        if delta == 0 {
            continue;
        }
        let (_, x27_coeff) = lift_component_pair_mod_q(delta, 0, model);
        let x27_centered = centered_goldilocks_value(x27_coeff);
        let candidate = PairDeltaExample {
            component_difference: delta,
            x27_coeff_centered: x27_centered,
            abs_x27_coeff: x27_centered.abs(),
        };
        let replace = min_abs_x27_coeff_delta_example
            .as_ref()
            .map(|current: &PairDeltaExample| candidate.abs_x27_coeff < current.abs_x27_coeff)
            .unwrap_or(true);
        if replace {
            min_abs_x27_coeff_delta_example = Some(candidate);
        }
    }

    let min_one_component_example =
        min_one_component_example.expect("one-component example must exist");
    let min_nonzero_component_difference_example = min_nonzero_component_difference_example
        .expect("nonzero component-difference example must exist");
    let min_abs_x27_coeff_delta_example = min_abs_x27_coeff_delta_example
        .expect("nonzero component-difference delta example must exist");

    InverseCrtReport {
        component_box_bound,
        balanced_pair_example,
        min_one_component_max_coeff_abs: min_one_component_example.max_coeff_abs,
        min_one_component_example,
        min_nonzero_component_difference_max_coeff_abs: min_nonzero_component_difference_example
            .max_coeff_abs,
        min_nonzero_component_difference_example,
        min_abs_x27_coeff_for_nonzero_component_difference: min_abs_x27_coeff_delta_example
            .abs_x27_coeff,
        min_abs_x27_coeff_delta_example,
    }
}

fn pair_lift_example(
    left_component: i32,
    right_component: i32,
    model: &GoldilocksFrogQuotientModel,
) -> PairLiftExample {
    let (const_coeff, x27_coeff) =
        lift_component_pair_mod_q(left_component, right_component, model);
    let const_coeff_centered = centered_goldilocks_value(const_coeff);
    let x27_coeff_centered = centered_goldilocks_value(x27_coeff);
    PairLiftExample {
        left_component,
        right_component,
        const_coeff_centered,
        x27_coeff_centered,
        max_coeff_abs: const_coeff_centered.abs().max(x27_coeff_centered.abs()),
    }
}

fn lift_component_pair_mod_q(
    left_component: i32,
    right_component: i32,
    model: &GoldilocksFrogQuotientModel,
) -> (u64, u64) {
    let left = encode_small_centered_to_goldilocks(left_component);
    let right = encode_small_centered_to_goldilocks(right_component);
    let x27_coeff = mod_mul_u64(model.denominator_inverse, mod_sub_u64(left, right));
    let const_coeff = mod_mul_u64(
        model.denominator_inverse,
        mod_sub_u64(
            mod_mul_u64(model.omega, right),
            mod_mul_u64(model.omega_squared, left),
        ),
    );
    (const_coeff, x27_coeff)
}

fn export_native_flattened_sis_instance(out_dir: &Path) -> Result<FlattenedSisExportReport> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create export directory {}", out_dir.display()))?;
    let params = current_native_backend_params();
    let message_len = params.max_commitment_message_ring_elems as usize;
    let (pk, ring_matrix, flat_matrix) = build_active_commitment_matrices(message_len)?;
    let relation = TxLeafPublicRelation::default();
    let metadata = FlattenedSisMatrixMetadata {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        relation_id_hex: hex32(relation.relation_id().0),
        shape_digest_hex: shape_hex(pk.shape_digest),
        modulus: GOLDILOCKS_MODULUS_U64,
        byte_order: "little_endian_u64".to_owned(),
        ring_matrix_layout: "row-major ring rows, then row-major message ring elements, then coefficient index 0..ring_degree-1".to_owned(),
        flat_matrix_layout: "row-major flattened rows, with row index = ring_row * ring_degree + coeff and column index = message_ring_elem * ring_degree + coeff".to_owned(),
        ring_rows: ring_matrix.len(),
        ring_cols: ring_matrix.first().map(Vec::len).unwrap_or(0),
        ring_degree: pk.ring_degree,
        flat_rows: ring_matrix.len() * pk.ring_degree,
        flat_cols: ring_matrix.first().map(Vec::len).unwrap_or(0) * pk.ring_degree,
        ring_matrix_file: "ring_commitment_matrix_u64_le.bin".to_owned(),
        flat_matrix_file: "flat_commitment_matrix_u64_le.bin".to_owned(),
    };
    let ring_matrix_path = out_dir.join(&metadata.ring_matrix_file);
    let flat_matrix_path = out_dir.join(&metadata.flat_matrix_file);
    let matrix_metadata_path = out_dir.join("matrix_metadata.json");
    let ring_matrix_bytes = serialize_ring_matrix_u64_le(&ring_matrix);
    let flat_matrix_bytes = serialize_u64_le(&flat_matrix);
    fs::write(&ring_matrix_path, &ring_matrix_bytes)
        .with_context(|| format!("failed to write {}", ring_matrix_path.display()))?;
    fs::write(&flat_matrix_path, &flat_matrix_bytes)
        .with_context(|| format!("failed to write {}", flat_matrix_path.display()))?;
    fs::write(&matrix_metadata_path, serde_json::to_vec_pretty(&metadata)?)
        .with_context(|| format!("failed to write {}", matrix_metadata_path.display()))?;
    Ok(FlattenedSisExportReport {
        output_dir: out_dir.display().to_string(),
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        matrix_metadata_path: matrix_metadata_path.display().to_string(),
        ring_matrix_path: ring_matrix_path.display().to_string(),
        flat_matrix_path: flat_matrix_path.display().to_string(),
        ring_matrix_bytes: ring_matrix_bytes.len(),
        flat_matrix_bytes: flat_matrix_bytes.len(),
        metadata,
    })
}

fn current_transcript_attack_model(params: &NativeBackendParams) -> Result<TranscriptAttackModel> {
    Ok(transcript_attack_model(params))
}

fn transcript_attack_model(params: &NativeBackendParams) -> TranscriptAttackModel {
    let support_size = (1u64 << params.challenge_bits.min(63)) - 1;
    let raw_space = 1u128 << 64;
    let max_preimage_count = raw_space.div_ceil(u128::from(support_size)) as u64;
    let tuple_min_entropy_bits = 64.0 * f64::from(params.fold_challenge_count)
        - f64::from(params.fold_challenge_count) * (max_preimage_count as f64).log2();
    let transcript_soundness_bits = tuple_min_entropy_bits.floor().max(0.0) as u32;
    let composition_loss_bits = params.max_claimed_receipt_root_leaves.ilog2()
        + u32::from(!params.max_claimed_receipt_root_leaves.is_power_of_two());
    let transcript_floor_bits = transcript_soundness_bits.saturating_sub(composition_loss_bits);
    TranscriptAttackModel {
        challenge_bits: params.challenge_bits,
        fold_challenge_count: params.fold_challenge_count,
        support_size,
        raw_space_bits: 64,
        max_preimage_count,
        transcript_soundness_bits,
        tuple_min_entropy_bits,
        composition_loss_bits,
        transcript_floor_bits,
    }
}

fn current_estimator_trace(params: &NativeBackendParams) -> Result<EstimatorTraceReport> {
    let claim = params.security_claim()?;
    Ok(estimator_trace(
        claim.commitment_problem_equations,
        claim.commitment_problem_dimension,
        claim.commitment_problem_l2_bound,
    ))
}

fn estimator_trace(
    equation_dimension: u32,
    witness_dimension: u32,
    l2_bound: u32,
) -> EstimatorTraceReport {
    let n = equation_dimension as f64;
    let m = witness_dimension as f64;
    let q = GOLDILOCKS_MODULUS_U64 as f64;
    let bound = l2_bound as f64;
    let log2_q = q.log2();
    let log2_bound = bound.log2();
    let log_delta = (log2_bound * log2_bound) / (4.0 * n * log2_q);
    let d = (n * log2_q / log_delta).sqrt().floor().min(m).max(2.0) as u32;
    let d_f = f64::from(d);
    let target_delta = 2f64.powf((log2_bound - ((n / d_f) * log2_q)) / (d_f - 1.0));
    let block_size = beta_from_root_hermite_factor(target_delta);
    EstimatorTraceReport {
        equation_dimension,
        witness_dimension,
        modulus: GOLDILOCKS_MODULUS_U64,
        l2_bound,
        log2_q,
        log2_bound,
        log_delta,
        reduced_dimension: d,
        target_delta,
        block_size,
        classical_bits: (0.2920 * f64::from(block_size)).floor() as u32,
        quantum_bits: (0.2650 * f64::from(block_size)).floor() as u32,
        paranoid_bits: (0.2075 * f64::from(block_size)).floor() as u32,
    }
}

fn build_active_commitment_matrices(
    message_len: usize,
) -> Result<(BackendKey, Vec<Vec<RingElem>>, Vec<u64>)> {
    let params = current_native_backend_params();
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&params.security_params(), relation.shape())?;
    let ring_matrix = derive_commitment_ring_matrix(&pk, message_len);
    let flat_matrix = flatten_ring_commitment_matrix(pk.ring_profile, &ring_matrix)?;
    Ok((pk, ring_matrix, flat_matrix))
}

fn flatten_ring_commitment_matrix(
    ring_profile: superneo_backend_lattice::RingProfile,
    ring_matrix: &[Vec<RingElem>],
) -> Result<Vec<u64>> {
    let ring_rows = ring_matrix.len();
    let ring_cols = ring_matrix.first().map(Vec::len).unwrap_or(0);
    let ring_degree = ring_profile.degree();
    let flat_cols = ring_cols * ring_degree;
    let mut flat = vec![0u64; ring_rows * ring_degree * flat_cols];
    for (ring_row_index, ring_row) in ring_matrix.iter().enumerate() {
        ensure!(
            ring_row.len() == ring_cols,
            "ring commitment matrix row {} has {} columns but expected {}",
            ring_row_index,
            ring_row.len(),
            ring_cols
        );
        for (ring_col_index, ring_elem) in ring_row.iter().enumerate() {
            let block = left_multiplication_operator_matrix(ring_profile, ring_elem)?;
            for block_row in 0..ring_degree {
                let flat_row_index = ring_row_index * ring_degree + block_row;
                let dest_offset = flat_row_index * flat_cols + ring_col_index * ring_degree;
                let block_offset = block_row * ring_degree;
                flat[dest_offset..dest_offset + ring_degree]
                    .copy_from_slice(&block[block_offset..block_offset + ring_degree]);
            }
        }
    }
    Ok(flat)
}

fn serialize_ring_matrix_u64_le(ring_matrix: &[Vec<RingElem>]) -> Vec<u8> {
    let total_coeffs = ring_matrix
        .iter()
        .flat_map(|row| row.iter())
        .map(|elem| elem.coeffs.len())
        .sum::<usize>();
    let mut out = Vec::with_capacity(total_coeffs * 8);
    for row in ring_matrix {
        for elem in row {
            out.extend(serialize_u64_le(&elem.coeffs));
        }
    }
    out
}

fn serialize_u64_le(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 8);
    for value in values {
        out.extend(value.to_le_bytes());
    }
    out
}

fn run_native_reduced_cryptanalysis_spikes() -> Result<ReducedCryptanalysisSpikesReport> {
    let ring_rows = 2usize;
    let ring_cols = 2usize;
    let ring_degree = current_native_backend_params().ring_degree();
    let (_, _, full_flat_matrix) = build_active_commitment_matrices(ring_cols)?;
    let total_rows = current_native_backend_params().matrix_rows * ring_degree;
    let total_cols = ring_cols * ring_degree;
    let flat_rows = ring_rows * ring_degree;
    let flat_cols = ring_cols * ring_degree;
    let reduced_flat_matrix = prefix_flat_matrix(
        &full_flat_matrix,
        total_rows,
        total_cols,
        flat_rows,
        flat_cols,
    )?;

    let split_pair_positions = vec![0usize, 27, 54, 81];
    let fq3_like_positions = vec![0usize, 9, 18, 27, 36, 45, 54, 63, 72, 81, 90, 99];
    let split_pair_case = exhaustive_box_subspace_search(
        "crt_component_pair_box2",
        "Search the exact first 2x2 ring-row/column slice on the {0,27}-coefficient subspace with coefficient box [-2,2].",
        &reduced_flat_matrix,
        flat_rows,
        flat_cols,
        &split_pair_positions,
        &[-2, -1, 0, 1, 2],
    );
    let fq3_like_case = exhaustive_box_subspace_search(
        "fq3_like_subspace_box1",
        "Search the exact first 2x2 ring-row/column slice on the coefficient positions {0,9,18,27,36,45} per column with coefficient box [-1,1].",
        &reduced_flat_matrix,
        flat_rows,
        flat_cols,
        &fq3_like_positions,
        &[-1, 0, 1],
    );
    let sparse_case = sparse_low_norm_search(
        "sparse_two_term_box2",
        "Search the exact first 2x2 ring-row/column slice for vectors with at most two nonzero coefficients across the 108 flattened columns and coefficients in {±1, ±2}.",
        &reduced_flat_matrix,
        flat_rows,
        flat_cols,
        2,
        &[-2, -1, 1, 2],
    );
    Ok(ReducedCryptanalysisSpikesReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        native_backend_params: current_bench_native_backend_params(),
        reduced_matrix: ReducedMatrixDescriptor {
            ring_rows,
            ring_cols,
            ring_degree,
            flat_rows,
            flat_cols,
        },
        cases: vec![split_pair_case, fq3_like_case, sparse_case],
    })
}

fn prefix_flat_matrix(
    flat_matrix: &[u64],
    total_rows: usize,
    total_cols: usize,
    row_limit: usize,
    col_limit: usize,
) -> Result<Vec<u64>> {
    ensure!(
        flat_matrix.len() == total_rows * total_cols,
        "flat matrix length {} does not match {} x {}",
        flat_matrix.len(),
        total_rows,
        total_cols
    );
    ensure!(
        row_limit <= total_rows && col_limit <= total_cols,
        "requested prefix {} x {} exceeds matrix {} x {}",
        row_limit,
        col_limit,
        total_rows,
        total_cols
    );
    let mut out = Vec::with_capacity(row_limit * col_limit);
    for row in 0..row_limit {
        let start = row * total_cols;
        out.extend_from_slice(&flat_matrix[start..start + col_limit]);
    }
    Ok(out)
}

fn exhaustive_box_subspace_search(
    name: &str,
    description: &str,
    flat_matrix: &[u64],
    rows: usize,
    cols: usize,
    variable_positions: &[usize],
    coeff_values: &[i16],
) -> ReducedCryptanalysisCase {
    let columns = variable_positions
        .iter()
        .map(|position| flat_matrix_column(flat_matrix, rows, cols, *position))
        .collect::<Vec<_>>();
    let mut residual = vec![0i128; rows];
    let mut assignment = vec![0i16; variable_positions.len()];
    let mut searched_candidates = 0u128;
    let mut first_kernel_vector = None;
    search_box_subspace_recursive(
        0,
        variable_positions,
        coeff_values,
        &columns,
        &mut residual,
        &mut assignment,
        &mut searched_candidates,
        &mut first_kernel_vector,
    );
    ReducedCryptanalysisCase {
        name: name.to_owned(),
        description: description.to_owned(),
        variable_count: variable_positions.len(),
        searched_candidates,
        found_nonzero_kernel: first_kernel_vector.is_some(),
        first_kernel_vector,
    }
}

fn search_box_subspace_recursive(
    index: usize,
    variable_positions: &[usize],
    coeff_values: &[i16],
    columns: &[Vec<i128>],
    residual: &mut [i128],
    assignment: &mut [i16],
    searched_candidates: &mut u128,
    first_kernel_vector: &mut Option<Vec<SearchCoordinate>>,
) {
    if first_kernel_vector.is_some() {
        return;
    }
    if index == variable_positions.len() {
        if assignment.iter().all(|coeff| *coeff == 0) {
            return;
        }
        *searched_candidates += 1;
        if residual
            .iter()
            .all(|value| reduce_goldilocks_i128(*value) == 0)
        {
            *first_kernel_vector = Some(nonzero_assignment(variable_positions, assignment));
        }
        return;
    }

    for coeff in coeff_values {
        assignment[index] = *coeff;
        if *coeff != 0 {
            add_scaled_column(residual, &columns[index], i128::from(*coeff));
        }
        search_box_subspace_recursive(
            index + 1,
            variable_positions,
            coeff_values,
            columns,
            residual,
            assignment,
            searched_candidates,
            first_kernel_vector,
        );
        if *coeff != 0 {
            add_scaled_column(residual, &columns[index], -i128::from(*coeff));
        }
        if first_kernel_vector.is_some() {
            return;
        }
    }
}

fn sparse_low_norm_search(
    name: &str,
    description: &str,
    flat_matrix: &[u64],
    rows: usize,
    cols: usize,
    max_nonzero_terms: usize,
    coeff_values: &[i16],
) -> ReducedCryptanalysisCase {
    let columns = (0..cols)
        .map(|position| flat_matrix_column(flat_matrix, rows, cols, position))
        .collect::<Vec<_>>();
    let mut searched_candidates = 0u128;
    let mut first_kernel_vector = None;

    for (position, column) in columns.iter().enumerate().take(cols) {
        for coeff in coeff_values {
            searched_candidates += 1;
            let mut residual = vec![0i128; rows];
            add_scaled_column(&mut residual, column, i128::from(*coeff));
            if residual
                .iter()
                .all(|value| reduce_goldilocks_i128(*value) == 0)
            {
                first_kernel_vector = Some(vec![SearchCoordinate {
                    index: position,
                    coeff: *coeff,
                }]);
                break;
            }
        }
        if first_kernel_vector.is_some() {
            break;
        }
    }

    if first_kernel_vector.is_none() && max_nonzero_terms >= 2 {
        'outer: for left in 0..cols {
            for right in left + 1..cols {
                for left_coeff in coeff_values {
                    for right_coeff in coeff_values {
                        searched_candidates += 1;
                        let mut residual = vec![0i128; rows];
                        add_scaled_column(&mut residual, &columns[left], i128::from(*left_coeff));
                        add_scaled_column(&mut residual, &columns[right], i128::from(*right_coeff));
                        if residual
                            .iter()
                            .all(|value| reduce_goldilocks_i128(*value) == 0)
                        {
                            first_kernel_vector = Some(vec![
                                SearchCoordinate {
                                    index: left,
                                    coeff: *left_coeff,
                                },
                                SearchCoordinate {
                                    index: right,
                                    coeff: *right_coeff,
                                },
                            ]);
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    ReducedCryptanalysisCase {
        name: name.to_owned(),
        description: description.to_owned(),
        variable_count: cols,
        searched_candidates,
        found_nonzero_kernel: first_kernel_vector.is_some(),
        first_kernel_vector,
    }
}

fn flat_matrix_column(
    flat_matrix: &[u64],
    rows: usize,
    cols: usize,
    col_index: usize,
) -> Vec<i128> {
    (0..rows)
        .map(|row| i128::from(flat_matrix[row * cols + col_index]))
        .collect()
}

fn add_scaled_column(accumulator: &mut [i128], column: &[i128], scale: i128) {
    for (slot, value) in accumulator.iter_mut().zip(column) {
        *slot += scale * value;
    }
}

fn nonzero_assignment(variable_positions: &[usize], assignment: &[i16]) -> Vec<SearchCoordinate> {
    variable_positions
        .iter()
        .copied()
        .zip(assignment.iter().copied())
        .filter(|(_, coeff)| *coeff != 0)
        .map(|(index, coeff)| SearchCoordinate { index, coeff })
        .collect()
}

fn encode_small_centered_to_goldilocks(value: i32) -> u64 {
    reduce_goldilocks_i128(i128::from(value))
}

fn mod_mul_u64(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(GOLDILOCKS_MODULUS_U64)) as u64
}

fn mod_sub_u64(left: u64, right: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        GOLDILOCKS_MODULUS_U64 - (right - left)
    }
}

fn reduce_goldilocks_i128(value: i128) -> u64 {
    let mut reduced = value % i128::from(GOLDILOCKS_MODULUS_U64);
    if reduced < 0 {
        reduced += i128::from(GOLDILOCKS_MODULUS_U64);
    }
    reduced as u64
}

fn current_native_claim_sweep() -> Result<NativeClaimSweepReport> {
    let params = current_native_backend_params();
    let message_cap_values = [
        12u32, 16, 24, 32, 48, 64, 76, 96, 128, 160, 192, 256, 384, 512, 768, 1024,
    ];
    let receipt_root_values = [1u32, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096];
    let message_cap_rows = message_cap_values
        .into_iter()
        .map(|message_cap| {
            claim_sweep_row(&NativeBackendParams {
                max_commitment_message_ring_elems: message_cap,
                ..params.clone()
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let receipt_root_leaf_rows = receipt_root_values
        .into_iter()
        .map(|leaf_cap| {
            claim_sweep_row(&NativeBackendParams {
                max_claimed_receipt_root_leaves: leaf_cap,
                ..params.clone()
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(NativeClaimSweepReport {
        fixed_security_target_bits: params.security_bits,
        active_message_cap: params.max_commitment_message_ring_elems,
        active_receipt_root_leaf_cap: params.max_claimed_receipt_root_leaves,
        first_message_cap_failure: first_message_cap_failure(&params)?,
        first_receipt_root_leaf_failure: first_receipt_root_leaf_failure(&params)?,
        message_cap_rows,
        receipt_root_leaf_rows,
    })
}

fn claim_sweep_row(params: &NativeBackendParams) -> Result<ClaimSweepRow> {
    let transcript = transcript_attack_model(params);
    Ok(match params.security_claim() {
        Ok(claim) => ClaimSweepRow {
            max_commitment_message_ring_elems: params.max_commitment_message_ring_elems,
            max_claimed_receipt_root_leaves: params.max_claimed_receipt_root_leaves,
            transcript_soundness_bits: claim.transcript_soundness_bits,
            commitment_binding_bits: claim.commitment_binding_bits,
            soundness_floor_bits: claim.soundness_floor_bits,
            claim_supported: params.security_bits <= claim.soundness_floor_bits,
            claim_error: None,
        },
        Err(err) => ClaimSweepRow {
            max_commitment_message_ring_elems: params.max_commitment_message_ring_elems,
            max_claimed_receipt_root_leaves: params.max_claimed_receipt_root_leaves,
            transcript_soundness_bits: transcript.transcript_soundness_bits,
            commitment_binding_bits: 0,
            soundness_floor_bits: 0,
            claim_supported: false,
            claim_error: Some(err.to_string()),
        },
    })
}

fn first_message_cap_failure(params: &NativeBackendParams) -> Result<Option<ClaimSweepRow>> {
    first_failure_monotone(params.max_commitment_message_ring_elems, |probe| {
        NativeBackendParams {
            max_commitment_message_ring_elems: probe,
            ..params.clone()
        }
    })
}

fn first_receipt_root_leaf_failure(params: &NativeBackendParams) -> Result<Option<ClaimSweepRow>> {
    first_failure_monotone(params.max_claimed_receipt_root_leaves, |probe| {
        NativeBackendParams {
            max_claimed_receipt_root_leaves: probe,
            ..params.clone()
        }
    })
}

fn first_failure_monotone<F>(start: u32, mut build: F) -> Result<Option<ClaimSweepRow>>
where
    F: FnMut(u32) -> NativeBackendParams,
{
    let start_row = claim_sweep_row(&build(start))?;
    if !start_row.claim_supported {
        return Ok(Some(start_row));
    }
    let mut lo = start;
    let mut hi = start.max(1);
    loop {
        if hi == u32::MAX {
            return Ok(None);
        }
        let next = hi.saturating_mul(2);
        let row = claim_sweep_row(&build(next))?;
        if !row.claim_supported {
            hi = next;
            break;
        }
        if next == u32::MAX {
            return Ok(None);
        }
        lo = next;
        hi = next;
    }

    let mut best = claim_sweep_row(&build(hi))?;
    while lo.saturating_add(1) < hi {
        let mid = lo + (hi - lo) / 2;
        let row = claim_sweep_row(&build(mid))?;
        if row.claim_supported {
            lo = mid;
        } else {
            hi = mid;
            best = row;
        }
    }
    Ok(Some(best))
}

fn beta_from_root_hermite_factor(delta: f64) -> u32 {
    let mut beta = 40u32;
    while reduction_delta((beta.saturating_mul(2)) as f64) > delta {
        beta = beta.saturating_mul(2);
    }
    while reduction_delta((beta.saturating_add(10)) as f64) > delta {
        beta = beta.saturating_add(10);
    }
    while reduction_delta(beta as f64) >= delta {
        beta = beta.saturating_add(1);
    }
    beta
}

fn reduction_delta(beta: f64) -> f64 {
    const SMALL: &[(u32, f64)] = &[
        (2, 1.02190),
        (5, 1.01862),
        (10, 1.01616),
        (15, 1.01485),
        (20, 1.01420),
        (25, 1.01342),
        (28, 1.01331),
        (40, 1.01295),
    ];

    if beta <= 2.0 {
        return 1.02190;
    }
    if beta < 40.0 {
        for window in SMALL.windows(2) {
            if f64::from(window[1].0) > beta {
                return window[0].1;
            }
        }
        return SMALL[SMALL.len() - 2].1;
    }
    if (beta - 40.0).abs() < f64::EPSILON {
        return SMALL[SMALL.len() - 1].1;
    }
    (beta / (2.0 * std::f64::consts::PI * std::f64::consts::E)
        * (std::f64::consts::PI * beta).powf(1.0 / beta))
    .powf(1.0 / (2.0 * (beta - 1.0)))
}

fn review_backend_params(params: &NativeBackendParams) -> ReviewBackendParams {
    ReviewBackendParams {
        family_label: params.manifest.family_label.to_owned(),
        spec_label: params.manifest.spec_label.to_owned(),
        commitment_scheme_label: params.manifest.commitment_scheme_label.to_owned(),
        challenge_schedule_label: params.manifest.challenge_schedule_label.to_owned(),
        maturity_label: params.manifest.maturity_label.to_owned(),
        security_bits: params.security_bits,
        ring_profile: format!("{:?}", params.ring_profile),
        matrix_rows: params.matrix_rows,
        matrix_cols: params.matrix_cols,
        challenge_bits: params.challenge_bits,
        fold_challenge_count: params.fold_challenge_count,
        max_fold_arity: params.max_fold_arity,
        transcript_domain_label: params.transcript_domain_label.to_owned(),
        decomposition_bits: params.decomposition_bits,
        opening_randomness_bits: params.opening_randomness_bits,
        commitment_security_model: commitment_security_model_label(
            params.commitment_security_model,
        )
        .to_owned(),
        commitment_estimator_model: commitment_estimator_model_label(
            params.commitment_estimator_model,
        )
        .to_owned(),
        max_commitment_message_ring_elems: params.max_commitment_message_ring_elems,
        max_claimed_receipt_root_leaves: params.max_claimed_receipt_root_leaves,
    }
}

fn commitment_security_model_label(model: CommitmentSecurityModel) -> &'static str {
    match model {
        CommitmentSecurityModel::GeometryProxy => "geometry_proxy",
        CommitmentSecurityModel::BoundedKernelModuleSis => "bounded_kernel_module_sis",
    }
}

fn commitment_estimator_model_label(model: CommitmentEstimatorModel) -> &'static str {
    match model {
        CommitmentEstimatorModel::SisLatticeEuclideanAdps16 => "sis_lattice_euclidean_adps16",
    }
}

fn review_receipt(receipt: &CanonicalTxValidityReceipt) -> ReviewReceipt {
    ReviewReceipt {
        statement_hash_hex: hex48(receipt.statement_hash),
        proof_digest_hex: hex48(receipt.proof_digest),
        public_inputs_digest_hex: hex48(receipt.public_inputs_digest),
        verifier_profile_hex: hex48(receipt.verifier_profile),
    }
}

fn review_stark_inputs(
    stark: &transaction_circuit::proof::SerializedStarkInputs,
) -> ReviewSerializedStarkInputs {
    ReviewSerializedStarkInputs {
        input_flags: stark.input_flags.clone(),
        output_flags: stark.output_flags.clone(),
        fee: stark.fee,
        value_balance_sign: stark.value_balance_sign,
        value_balance_magnitude: stark.value_balance_magnitude,
        merkle_root_hex: hex48(stark.merkle_root),
        balance_slot_asset_ids: stark.balance_slot_asset_ids.clone(),
        stablecoin_enabled: stark.stablecoin_enabled,
        stablecoin_asset_id: stark.stablecoin_asset_id,
        stablecoin_policy_version: stark.stablecoin_policy_version,
        stablecoin_issuance_sign: stark.stablecoin_issuance_sign,
        stablecoin_issuance_magnitude: stark.stablecoin_issuance_magnitude,
        stablecoin_policy_hash_hex: hex48(stark.stablecoin_policy_hash),
        stablecoin_oracle_commitment_hex: hex48(stark.stablecoin_oracle_commitment),
        stablecoin_attestation_commitment_hex: hex48(stark.stablecoin_attestation_commitment),
    }
}

fn review_tx_public(tx: &superneo_hegemon::TxLeafPublicTx) -> ReviewTxPublicTx {
    ReviewTxPublicTx {
        nullifiers_hex: tx.nullifiers.iter().map(|bytes| hex48(*bytes)).collect(),
        commitments_hex: tx.commitments.iter().map(|bytes| hex48(*bytes)).collect(),
        ciphertext_hashes_hex: tx
            .ciphertext_hashes
            .iter()
            .map(|bytes| hex48(*bytes))
            .collect(),
        balance_tag_hex: hex48(tx.balance_tag),
        version_circuit: tx.version.circuit,
        version_crypto: tx.version.crypto,
    }
}

fn build_review_tx_context(
    params: &NativeBackendParams,
    artifact: &superneo_hegemon::NativeTxLeafArtifact,
) -> ReviewTxContext {
    ReviewTxContext {
        backend_params: review_backend_params(params),
        expected_version: artifact.version,
        params_fingerprint_hex: hex48(artifact.params_fingerprint),
        spec_digest_hex: hex32(artifact.spec_digest),
        relation_id_hex: hex::encode(artifact.relation_id),
        shape_digest_hex: hex::encode(artifact.shape_digest),
        statement_digest_hex: hex48(artifact.statement_digest),
        receipt: review_receipt(&artifact.receipt),
        tx: review_tx_public(&artifact.tx),
        stark_public_inputs: review_stark_inputs(&artifact.stark_public_inputs),
        commitment_rows: artifact
            .commitment
            .rows
            .iter()
            .map(|row| row.coeffs.clone())
            .collect(),
    }
}

fn build_review_block_context(
    params: &NativeBackendParams,
    artifact: &superneo_hegemon::ReceiptRootArtifact,
    leaves: &[superneo_hegemon::NativeTxLeafArtifact],
) -> ReviewBlockContext {
    ReviewBlockContext {
        backend_params: review_backend_params(params),
        expected_version: artifact.version,
        params_fingerprint_hex: hex48(artifact.params_fingerprint),
        spec_digest_hex: hex32(artifact.spec_digest),
        relation_id_hex: hex::encode(artifact.relation_id),
        shape_digest_hex: hex::encode(artifact.shape_digest),
        root_statement_digest_hex: hex48(artifact.root_statement_digest),
        root_commitment_hex: hex48(artifact.root_commitment),
        leaves: leaves
            .iter()
            .map(|leaf| ReviewReceiptLeafContext {
                statement_digest_hex: hex48(leaf.statement_digest),
                witness_commitment_hex: hex48(leaf.commitment.digest),
                proof_digest_hex: hex48(leaf.leaf.proof.proof_digest),
                commitment_rows: leaf
                    .commitment
                    .rows
                    .iter()
                    .map(|row| row.coeffs.clone())
                    .collect(),
            })
            .collect(),
    }
}

fn review_case(
    name: &str,
    kind: &str,
    expected_valid: bool,
    expected_error_substring: Option<&str>,
    artifact_bytes: &[u8],
    tx_context: Option<ReviewTxContext>,
    block_context: Option<ReviewBlockContext>,
) -> ReviewVectorCase {
    ReviewVectorCase {
        name: name.to_owned(),
        kind: kind.to_owned(),
        expected_valid,
        expected_error_substring: expected_error_substring.map(str::to_owned),
        artifact_hex: hex::encode(artifact_bytes),
        tx_context,
        block_context,
    }
}

fn emit_review_vectors(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create review vector directory {}", dir.display()))?;
    let params = current_native_backend_params();

    let leaf_witness = sample_witness(1);
    let built_leaf = build_native_tx_leaf_artifact_bytes_with_params(&params, &leaf_witness)?;
    let valid_leaf = decode_native_tx_leaf_artifact_bytes(&built_leaf.artifact_bytes)?;
    let valid_leaf_context = build_review_tx_context(&params, &valid_leaf);

    let mut invalid_leaf_spec = valid_leaf.clone();
    invalid_leaf_spec.spec_digest[0] ^= 0x01;
    let invalid_leaf_spec_bytes = encode_native_tx_leaf_artifact_bytes(&invalid_leaf_spec)?;

    let mut invalid_leaf_params = valid_leaf.clone();
    invalid_leaf_params.params_fingerprint[0] ^= 0x01;
    let invalid_leaf_params_bytes = encode_native_tx_leaf_artifact_bytes(&invalid_leaf_params)?;

    let mut invalid_leaf_stark_proof = valid_leaf.clone();
    invalid_leaf_stark_proof.stark_proof[0] ^= 0x80;
    let invalid_leaf_stark_proof_bytes =
        encode_native_tx_leaf_artifact_bytes(&invalid_leaf_stark_proof)?;

    let mut invalid_leaf_proof = valid_leaf.clone();
    invalid_leaf_proof.leaf.proof.proof_digest[0] ^= 0x01;
    let invalid_leaf_proof_bytes = encode_native_tx_leaf_artifact_bytes(&invalid_leaf_proof)?;

    let mut invalid_leaf_trailing = built_leaf.artifact_bytes.clone();
    invalid_leaf_trailing.push(0xff);

    let leaf_witness_2 = sample_witness(2);
    let built_leaf_2 = build_native_tx_leaf_artifact_bytes_with_params(&params, &leaf_witness_2)?;
    let valid_leaf_2 = decode_native_tx_leaf_artifact_bytes(&built_leaf_2.artifact_bytes)?;

    let built_root = build_native_tx_leaf_receipt_root_artifact_bytes(&[
        valid_leaf.clone(),
        valid_leaf_2.clone(),
    ])?;
    let valid_root = decode_receipt_root_artifact_bytes(&built_root.artifact_bytes)?;
    let valid_root_context = build_review_block_context(
        &params,
        &valid_root,
        &[valid_leaf.clone(), valid_leaf_2.clone()],
    );

    let mut invalid_root_rows = valid_root.clone();
    if let Some(first_fold) = invalid_root_rows.folds.first_mut() {
        if let Some(first_row) = first_fold.parent_rows.first_mut() {
            if let Some(first_coeff) = first_row.coeffs.first_mut() {
                *first_coeff ^= 1;
            }
        }
    }
    let invalid_root_rows_bytes = encode_receipt_root_artifact_bytes(&invalid_root_rows);

    let mut invalid_root_spec = valid_root.clone();
    invalid_root_spec.spec_digest[0] ^= 0x01;
    let invalid_root_spec_bytes = encode_receipt_root_artifact_bytes(&invalid_root_spec);

    let mut invalid_root_commitment = valid_root.clone();
    invalid_root_commitment.root_commitment[0] ^= 0x01;
    let invalid_root_commitment_bytes =
        encode_receipt_root_artifact_bytes(&invalid_root_commitment);

    let mut invalid_root_trailing = built_root.artifact_bytes.clone();
    invalid_root_trailing.push(0xaa);

    let bundle = ReviewVectorBundle {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        native_backend_params: current_bench_native_backend_params(),
        native_security_claim: current_bench_native_security_claim()?,
        cases: vec![
            review_case(
                "native_tx_leaf_valid",
                "native_tx_leaf",
                true,
                None,
                &built_leaf.artifact_bytes,
                Some(valid_leaf_context.clone()),
                None,
            ),
            review_case(
                "native_tx_leaf_invalid_spec_digest",
                "native_tx_leaf",
                false,
                Some("spec digest mismatch"),
                &invalid_leaf_spec_bytes,
                Some(valid_leaf_context.clone()),
                None,
            ),
            review_case(
                "native_tx_leaf_invalid_params_fingerprint",
                "native_tx_leaf",
                false,
                Some("parameter fingerprint mismatch"),
                &invalid_leaf_params_bytes,
                Some(valid_leaf_context.clone()),
                None,
            ),
            review_case(
                "native_tx_leaf_invalid_stark_proof",
                "native_tx_leaf",
                false,
                Some("canonical receipt mismatch"),
                &invalid_leaf_stark_proof_bytes,
                Some(valid_leaf_context),
                None,
            ),
            review_case(
                "native_tx_leaf_invalid_proof_digest",
                "native_tx_leaf",
                false,
                Some("proof digest mismatch"),
                &invalid_leaf_proof_bytes,
                Some(build_review_tx_context(&params, &valid_leaf)),
                None,
            ),
            review_case(
                "native_tx_leaf_invalid_trailing_bytes",
                "native_tx_leaf",
                false,
                Some("trailing bytes"),
                &invalid_leaf_trailing,
                Some(build_review_tx_context(&params, &valid_leaf)),
                None,
            ),
            review_case(
                "receipt_root_valid",
                "receipt_root",
                true,
                None,
                &built_root.artifact_bytes,
                None,
                Some(valid_root_context.clone()),
            ),
            review_case(
                "receipt_root_invalid_spec_digest",
                "receipt_root",
                false,
                Some("spec digest mismatch"),
                &invalid_root_spec_bytes,
                None,
                Some(valid_root_context.clone()),
            ),
            review_case(
                "receipt_root_invalid_fold_rows",
                "receipt_root",
                false,
                Some("parent rows mismatch"),
                &invalid_root_rows_bytes,
                None,
                Some(valid_root_context.clone()),
            ),
            review_case(
                "receipt_root_invalid_root_commitment",
                "receipt_root",
                false,
                Some("root commitment mismatch"),
                &invalid_root_commitment_bytes,
                None,
                Some(valid_root_context.clone()),
            ),
            review_case(
                "receipt_root_invalid_trailing_bytes",
                "receipt_root",
                false,
                Some("trailing bytes"),
                &invalid_root_trailing,
                None,
                Some(valid_root_context),
            ),
        ],
    };

    let bundle_path = dir.join("bundle.json");
    fs::write(&bundle_path, serde_json::to_vec_pretty(&bundle)?).with_context(|| {
        format!(
            "failed to write review vectors to {}",
            bundle_path.display()
        )
    })?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "review_vector_bundle": bundle_path,
            "case_count": bundle.cases.len(),
            "parameter_fingerprint": bundle.parameter_fingerprint,
            "spec_digest": bundle.native_backend_params.spec_digest,
        }))?
    );
    Ok(())
}

fn verify_review_bundle_production(dir: &Path) -> Result<ProductionReviewReport> {
    let bundle_path = dir.join("bundle.json");
    let bundle: ReviewVectorBundle = serde_json::from_slice(&fs::read(&bundle_path)?)
        .with_context(|| {
            format!(
                "failed to parse production review bundle {}",
                bundle_path.display()
            )
        })?;
    let mut results = Vec::with_capacity(bundle.cases.len());
    let mut passed_cases = 0usize;
    for case in &bundle.cases {
        match verify_production_review_case(case) {
            Ok(()) if case.expected_valid => {
                passed_cases += 1;
                results.push(ProductionReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: true,
                    passed: true,
                    detail: "accepted".to_owned(),
                });
            }
            Ok(()) => {
                results.push(ProductionReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: false,
                    passed: false,
                    detail: "unexpected acceptance".to_owned(),
                });
            }
            Err(err) if !case.expected_valid => {
                let detail = err.to_string();
                let passed = case
                    .expected_error_substring
                    .as_deref()
                    .map(|expected| detail.contains(expected))
                    .unwrap_or(true);
                if passed {
                    passed_cases += 1;
                }
                results.push(ProductionReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: false,
                    passed,
                    detail,
                });
            }
            Err(err) => {
                results.push(ProductionReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: true,
                    passed: false,
                    detail: err.to_string(),
                });
            }
        }
    }
    Ok(ProductionReviewReport {
        summary: ProductionReviewVerificationSummary {
            bundle_path: bundle_path.display().to_string(),
            case_count: results.len(),
            passed_cases,
            failed_cases: results.len().saturating_sub(passed_cases),
        },
        results,
    })
}

fn verify_production_review_case(case: &ReviewVectorCase) -> Result<()> {
    let artifact_bytes =
        hex::decode(&case.artifact_hex).context("case artifact_hex must be valid hex")?;
    match case.kind.as_str() {
        "native_tx_leaf" => {
            let ctx = case
                .tx_context
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_tx_leaf case missing tx_context"))?;
            let params = current_native_backend_params();
            let tx = tx_from_review(ctx)?;
            let receipt = CanonicalTxValidityReceipt {
                statement_hash: decode_hex_array::<48>(&ctx.receipt.statement_hash_hex)?,
                proof_digest: decode_hex_array::<48>(&ctx.receipt.proof_digest_hex)?,
                public_inputs_digest: decode_hex_array::<48>(
                    &ctx.receipt.public_inputs_digest_hex,
                )?,
                verifier_profile: decode_hex_array::<48>(&ctx.receipt.verifier_profile_hex)?,
            };
            verify_native_tx_leaf_artifact_bytes_with_params(
                &params,
                &tx,
                &receipt,
                &artifact_bytes,
            )
            .map(|_| ())
        }
        "receipt_root" => {
            let ctx = case
                .block_context
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("receipt_root case missing block_context"))?;
            let params = current_native_backend_params();
            let records = receipt_root_records_from_review(ctx)?;
            verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(
                &params,
                &records,
                &artifact_bytes,
            )
            .map(|_| ())
        }
        other => Err(anyhow::anyhow!("unsupported review case kind {other}")),
    }
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("hex string has {} bytes, expected {}", len, N))
}

fn tx_from_review(ctx: &ReviewTxContext) -> Result<superneo_hegemon::TxLeafPublicTx> {
    Ok(superneo_hegemon::TxLeafPublicTx {
        nullifiers: ctx
            .tx
            .nullifiers_hex
            .iter()
            .map(|value| decode_hex_array::<48>(value))
            .collect::<Result<Vec<_>>>()?,
        commitments: ctx
            .tx
            .commitments_hex
            .iter()
            .map(|value| decode_hex_array::<48>(value))
            .collect::<Result<Vec<_>>>()?,
        ciphertext_hashes: ctx
            .tx
            .ciphertext_hashes_hex
            .iter()
            .map(|value| decode_hex_array::<48>(value))
            .collect::<Result<Vec<_>>>()?,
        balance_tag: decode_hex_array::<48>(&ctx.tx.balance_tag_hex)?,
        version: protocol_versioning::VersionBinding::new(
            ctx.tx.version_circuit,
            ctx.tx.version_crypto,
        ),
    })
}

fn receipt_root_records_from_review(
    ctx: &ReviewBlockContext,
) -> Result<Vec<superneo_hegemon::NativeTxLeafRecord>> {
    Ok(ctx
        .leaves
        .iter()
        .map(|leaf| superneo_hegemon::NativeTxLeafRecord {
            params_fingerprint: decode_hex_array::<48>(&ctx.params_fingerprint_hex)
                .expect("params fingerprint"),
            spec_digest: decode_hex_array::<32>(&ctx.spec_digest_hex).expect("spec digest"),
            relation_id: decode_hex_array::<32>(&ctx.relation_id_hex).expect("relation id"),
            shape_digest: decode_hex_array::<32>(&ctx.shape_digest_hex).expect("shape digest"),
            statement_digest: decode_hex_array::<48>(&leaf.statement_digest_hex)
                .expect("statement digest"),
            commitment: LatticeCommitment::from_rows(
                leaf.commitment_rows
                    .iter()
                    .cloned()
                    .map(RingElem::from_coeffs)
                    .collect(),
            ),
            proof_digest: decode_hex_array::<48>(&leaf.proof_digest_hex).expect("proof digest"),
        })
        .collect())
}

fn load_review_vector_bundle(dir: &Path) -> Result<ReviewVectorBundle> {
    let bundle_path = dir.join("bundle.json");
    serde_json::from_slice(&fs::read(&bundle_path)?).with_context(|| {
        format!(
            "failed to parse native review bundle {}",
            bundle_path.display()
        )
    })
}

fn valid_review_case(bundle: &ReviewVectorBundle, kind: &str) -> Result<ReviewVectorCase> {
    bundle
        .cases
        .iter()
        .find(|case| case.kind == kind && case.expected_valid)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("review bundle is missing a valid {kind} case"))
}

fn reference_review_case(case: &ReviewVectorCase) -> Result<RefReviewVectorCase> {
    serde_json::from_value(serde_json::to_value(case)?)
        .context("failed to convert local review case into reference verifier case")
}

fn verification_outcome(result: Result<()>) -> VerificationOutcome {
    match result {
        Ok(()) => VerificationOutcome {
            accepted: true,
            detail: "accepted".to_owned(),
        },
        Err(err) => VerificationOutcome {
            accepted: false,
            detail: err.to_string(),
        },
    }
}

fn run_verifier_parity_case(
    case: &ReviewVectorCase,
) -> Result<(VerificationOutcome, VerificationOutcome)> {
    let production = verification_outcome(verify_production_review_case(case));
    let reference = verification_outcome(reference_verify_case(&reference_review_case(case)?));
    Ok((production, reference))
}

fn differential_fuzz_native_review_bundle(
    dir: &Path,
    seed: u64,
    mutation_count: usize,
) -> Result<VerifierParityReport> {
    let bundle = load_review_vector_bundle(dir)?;
    let valid_leaf = valid_review_case(&bundle, "native_tx_leaf")?;
    let valid_root = valid_review_case(&bundle, "receipt_root")?;
    let mut rng = MutationRng::new(seed);
    let mut cases = Vec::with_capacity(mutation_count);
    for index in 0..mutation_count {
        let base = if index % 2 == 0 {
            &valid_leaf
        } else {
            &valid_root
        };
        let (mutation, artifact_bytes) = random_malformed_artifact_mutation(
            base.kind.as_str(),
            &hex::decode(&base.artifact_hex)?,
            &mut rng,
        )?;
        let mut case = base.clone();
        case.name = format!(
            "fuzz_{index:03}_{}_{}",
            base.kind,
            mutation.replace(':', "_")
        );
        case.expected_valid = false;
        case.expected_error_substring = None;
        case.artifact_hex = hex::encode(artifact_bytes);
        cases.push((mutation, case));
    }
    verifier_parity_report(
        "differential_malformed_artifact_fuzz",
        &dir.join("bundle.json"),
        Some(seed),
        cases,
    )
}

fn attack_native_review_bundle(dir: &Path) -> Result<VerifierParityReport> {
    let bundle = load_review_vector_bundle(dir)?;
    let valid_leaf = valid_review_case(&bundle, "native_tx_leaf")?;
    let valid_root = valid_review_case(&bundle, "receipt_root")?;

    let valid_leaf_bytes = hex::decode(&valid_leaf.artifact_hex)?;
    let valid_root_bytes = hex::decode(&valid_root.artifact_hex)?;
    let decoded_leaf = decode_native_tx_leaf_artifact_bytes(&valid_leaf_bytes)?;
    let decoded_root = decode_receipt_root_artifact_bytes(&valid_root_bytes)?;

    let mut cases = Vec::new();

    cases.push((
        "truncate_to_zero".to_owned(),
        mutated_review_case(&valid_leaf, "target_leaf_truncate_to_zero", Vec::new()),
    ));
    cases.push((
        "truncate_to_half".to_owned(),
        mutated_review_case(
            &valid_leaf,
            "target_leaf_truncate_to_half",
            valid_leaf_bytes[..valid_leaf_bytes.len() / 2].to_vec(),
        ),
    ));
    cases.push((
        "delete_middle_byte".to_owned(),
        mutated_review_case(
            &valid_leaf,
            "target_leaf_delete_middle_byte",
            remove_byte(&valid_leaf_bytes, valid_leaf_bytes.len() / 2),
        ),
    ));
    let mut short_leaf_row = decoded_leaf.clone();
    short_leaf_row.commitment.rows[0].coeffs.pop();
    cases.push((
        "shorten_commitment_row_coeffs".to_owned(),
        mutated_review_case(
            &valid_leaf,
            "target_leaf_shorten_commitment_row",
            encode_native_tx_leaf_artifact_bytes(&short_leaf_row)?,
        ),
    ));
    let mut long_leaf_row = decoded_leaf.clone();
    long_leaf_row.commitment.rows[0].coeffs.push(0);
    cases.push((
        "extend_commitment_row_coeffs".to_owned(),
        mutated_review_case(
            &valid_leaf,
            "target_leaf_extend_commitment_row",
            encode_native_tx_leaf_artifact_bytes(&long_leaf_row)?,
        ),
    ));

    cases.push((
        "truncate_to_zero".to_owned(),
        mutated_review_case(&valid_root, "target_root_truncate_to_zero", Vec::new()),
    ));
    cases.push((
        "truncate_to_half".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_truncate_to_half",
            valid_root_bytes[..valid_root_bytes.len() / 2].to_vec(),
        ),
    ));
    cases.push((
        "delete_middle_byte".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_delete_middle_byte",
            remove_byte(&valid_root_bytes, valid_root_bytes.len() / 2),
        ),
    ));

    let mut fewer_folds = decoded_root.clone();
    fewer_folds.folds.pop();
    cases.push((
        "drop_last_fold".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_drop_last_fold",
            encode_receipt_root_artifact_bytes(&fewer_folds),
        ),
    ));

    let mut extra_fold = decoded_root.clone();
    extra_fold.folds.push(extra_fold.folds[0].clone());
    cases.push((
        "append_duplicate_fold".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_append_duplicate_fold",
            encode_receipt_root_artifact_bytes(&extra_fold),
        ),
    ));

    let mut flip_challenge = decoded_root.clone();
    flip_challenge.folds[0].challenges[0] ^= 1;
    cases.push((
        "flip_first_challenge".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_flip_first_challenge",
            encode_receipt_root_artifact_bytes(&flip_challenge),
        ),
    ));

    let mut shorten_challenges = decoded_root.clone();
    shorten_challenges.folds[0].challenges.pop();
    cases.push((
        "truncate_challenge_vector".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_truncate_challenge_vector",
            encode_receipt_root_artifact_bytes(&shorten_challenges),
        ),
    ));

    let mut extend_challenges = decoded_root.clone();
    extend_challenges.folds[0].challenges.push(1);
    cases.push((
        "extend_challenge_vector".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_extend_challenge_vector",
            encode_receipt_root_artifact_bytes(&extend_challenges),
        ),
    ));

    let mut shorten_row = decoded_root.clone();
    shorten_row.folds[0].parent_rows[0].coeffs.pop();
    cases.push((
        "shorten_parent_row_coeffs".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_shorten_parent_row",
            encode_receipt_root_artifact_bytes(&shorten_row),
        ),
    ));

    let mut extend_row = decoded_root.clone();
    extend_row.folds[0].parent_rows[0].coeffs.push(0);
    cases.push((
        "extend_parent_row_coeffs".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_extend_parent_row",
            encode_receipt_root_artifact_bytes(&extend_row),
        ),
    ));

    let mut fewer_leaves = decoded_root.clone();
    fewer_leaves.leaves.pop();
    cases.push((
        "drop_last_leaf".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_drop_last_leaf",
            encode_receipt_root_artifact_bytes(&fewer_leaves),
        ),
    ));

    let mut extra_leaf = decoded_root.clone();
    extra_leaf.leaves.push(extra_leaf.leaves[0].clone());
    cases.push((
        "append_duplicate_leaf".to_owned(),
        mutated_review_case(
            &valid_root,
            "target_root_append_duplicate_leaf",
            encode_receipt_root_artifact_bytes(&extra_leaf),
        ),
    ));

    verifier_parity_report(
        "targeted_native_attack_campaign",
        &dir.join("bundle.json"),
        None,
        cases,
    )
}

fn verifier_parity_report(
    campaign: &str,
    bundle_path: &Path,
    seed: Option<u64>,
    cases: Vec<(String, ReviewVectorCase)>,
) -> Result<VerifierParityReport> {
    let mut results = Vec::with_capacity(cases.len());
    let mut agreement_rejections = 0usize;
    let mut agreement_acceptances = 0usize;
    let mut disagreements = 0usize;
    let mut unexpected_acceptances = 0usize;

    for (mutation, case) in cases {
        let (production, reference) = run_verifier_parity_case(&case)?;
        let agreed = production.accepted == reference.accepted;
        let accepted_by_any = production.accepted || reference.accepted;
        if agreed {
            if accepted_by_any {
                agreement_acceptances += 1;
                unexpected_acceptances += 1;
            } else {
                agreement_rejections += 1;
            }
        } else {
            disagreements += 1;
            if accepted_by_any {
                unexpected_acceptances += 1;
            }
        }
        results.push(VerifierParityCaseResult {
            name: case.name,
            kind: case.kind,
            mutation,
            production,
            reference,
            agreed,
            unexpected_acceptance: accepted_by_any,
        });
    }

    Ok(VerifierParityReport {
        campaign: campaign.to_owned(),
        bundle_path: bundle_path.display().to_string(),
        seed,
        summary: VerifierParitySummary {
            case_count: results.len(),
            agreement_rejections,
            agreement_acceptances,
            disagreements,
            unexpected_acceptances,
        },
        results,
    })
}

#[derive(Clone)]
struct MiniRootMissJob {
    index: usize,
    key: MiniRootCacheKey,
    instances: Vec<FoldedInstance<LatticeCommitment>>,
    rebuilt_folds: usize,
}

#[derive(Clone)]
struct UpperTreeMissJob {
    index: usize,
    key: UpperTreeCacheKey,
    left: FoldedInstance<LatticeCommitment>,
    right: FoldedInstance<LatticeCommitment>,
}

fn run_jobs_with_workers<T, R, F>(workers: usize, jobs: Vec<T>, func: F) -> Result<Vec<R>>
where
    T: Send,
    R: Send,
    F: Fn(T) -> Result<R> + Sync,
{
    let func_ref = &func;
    if workers <= 1 {
        jobs.into_iter().map(func_ref).collect()
    } else {
        let pool = ThreadPoolBuilder::new()
            .num_threads(workers)
            .build()
            .context("failed to build native receipt-root worker pool")?;
        pool.install(|| jobs.into_par_iter().map(func_ref).collect())
    }
}

fn derive_synthetic_native_leaf_record(
    base: &NativeTxLeafRecord,
    unique_index: usize,
) -> NativeTxLeafRecord {
    let mut material = Vec::with_capacity(64 + (48 * 3));
    material.extend_from_slice(b"hegemon.native-leaf-record-corpus.synthetic.v1");
    material.extend_from_slice(&(unique_index as u64).to_le_bytes());
    material.extend_from_slice(&base.statement_digest);
    material.extend_from_slice(&base.proof_digest);
    material.extend_from_slice(&base.commitment.digest);
    let digest = blake3_384(&material);

    let mut proof_material = Vec::with_capacity(64 + (48 * 2));
    proof_material.extend_from_slice(b"hegemon.native-leaf-record-corpus.synthetic-proof.v1");
    proof_material.extend_from_slice(&(unique_index as u64).to_le_bytes());
    proof_material.extend_from_slice(&base.proof_digest);
    proof_material.extend_from_slice(&digest);
    let proof_digest = blake3_384(&proof_material);

    let mut record = base.clone();
    record.statement_digest = digest;
    record.proof_digest = proof_digest;
    record
}

fn emit_native_leaf_record_corpus(
    path: &Path,
    record_count: usize,
    seed_record_count: usize,
) -> Result<()> {
    ensure!(
        record_count > 0,
        "native leaf-record corpus must contain at least one record"
    );
    let seed_record_count = seed_record_count.min(record_count).max(1);
    let mut records = build_native_leaf_records_for_measurement(seed_record_count, None)?;
    while records.len() < record_count {
        let base_index = records.len() % seed_record_count;
        let unique_index = records.len();
        let synthetic = derive_synthetic_native_leaf_record(&records[base_index], unique_index);
        records.push(synthetic);
    }
    let corpus = NativeLeafRecordCorpus {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        record_count: records.len(),
        seed_record_count,
        synthetic_expansion: records.len() > seed_record_count,
        records: records.iter().map(BenchNativeLeafRecord::from).collect(),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create corpus directory {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_vec_pretty(&corpus)?).with_context(|| {
        format!(
            "failed to write native leaf-record corpus {}",
            path.display()
        )
    })
}

fn load_native_leaf_record_corpus(path: &Path) -> Result<NativeLeafRecordCorpus> {
    let corpus: NativeLeafRecordCorpus =
        serde_json::from_slice(&fs::read(path).with_context(|| {
            format!(
                "failed to read native leaf-record corpus {}",
                path.display()
            )
        })?)
        .with_context(|| {
            format!(
                "failed to decode native leaf-record corpus {}",
                path.display()
            )
        })?;
    ensure!(
        corpus.parameter_fingerprint == current_parameter_fingerprint_hex(),
        "native leaf-record corpus parameter fingerprint {} does not match current {}",
        corpus.parameter_fingerprint,
        current_parameter_fingerprint_hex()
    );
    ensure!(
        corpus.record_count == corpus.records.len(),
        "native leaf-record corpus count {} does not match payload {}",
        corpus.record_count,
        corpus.records.len()
    );
    ensure!(
        corpus.seed_record_count > 0 && corpus.seed_record_count <= corpus.record_count,
        "native leaf-record corpus seed count {} is invalid for record count {}",
        corpus.seed_record_count,
        corpus.record_count
    );
    Ok(corpus)
}

fn measurement_record_source_label(corpus_path: Option<&Path>) -> String {
    corpus_path
        .map(|path| format!("corpus:{}", path.display()))
        .unwrap_or_else(|| "generated".to_string())
}

fn build_native_leaf_records_for_measurement(
    leaf_count: usize,
    corpus_path: Option<&Path>,
) -> Result<Vec<NativeTxLeafRecord>> {
    if let Some(path) = corpus_path {
        let corpus = load_native_leaf_record_corpus(path)?;
        ensure!(
            corpus.records.len() >= leaf_count,
            "native leaf-record corpus {} has {} records but measurement needs at least {}",
            path.display(),
            corpus.records.len(),
            leaf_count
        );
        return corpus.records[..leaf_count]
            .iter()
            .cloned()
            .map(BenchNativeLeafRecord::decode)
            .collect();
    }
    let params = current_native_backend_params();
    (0..leaf_count)
        .map(|seed| {
            let built = build_native_tx_leaf_artifact_bytes_with_params(
                &params,
                &sample_witness(seed as u64 + 1),
            )?;
            let artifact = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes)?;
            Ok(native_tx_leaf_record_from_artifact(&artifact))
        })
        .collect()
}

fn mutate_native_leaf_records_for_measurement(
    records: &[NativeTxLeafRecord],
    changed_leaf_index: usize,
    corpus_path: Option<&Path>,
) -> Result<Vec<NativeTxLeafRecord>> {
    ensure!(
        changed_leaf_index < records.len(),
        "changed leaf index {} must be smaller than leaf count {}",
        changed_leaf_index,
        records.len()
    );
    if let Some(path) = corpus_path {
        let corpus = load_native_leaf_record_corpus(path)?;
        let replacement_index = records.len() + changed_leaf_index;
        ensure!(
            corpus.records.len() > replacement_index,
            "native leaf-record corpus {} has {} records but mutated measurement needs index {} (emit at least {})",
            path.display(),
            corpus.records.len(),
            replacement_index,
            replacement_index + 1
        );
        let mut mutated = records.to_vec();
        mutated[changed_leaf_index] = corpus.records[replacement_index].clone().decode()?;
        return Ok(mutated);
    }
    let params = current_native_backend_params();
    let mut mutated = records.to_vec();
    let seed = 50_000u64 + changed_leaf_index as u64 + records.len() as u64;
    let built = build_native_tx_leaf_artifact_bytes_with_params(&params, &sample_witness(seed))?;
    let artifact = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes)?;
    mutated[changed_leaf_index] = native_tx_leaf_record_from_artifact(&artifact);
    Ok(mutated)
}

fn hierarchy_layer_widths(hierarchy: &NativeReceiptRootHierarchy) -> Vec<usize> {
    hierarchy
        .layers
        .iter()
        .map(|layer| layer.nodes.len())
        .collect()
}

fn changed_hierarchy_internal_nodes(
    baseline: &NativeReceiptRootHierarchy,
    mutated: &NativeReceiptRootHierarchy,
) -> Result<usize> {
    ensure!(
        baseline.layers.len() == mutated.layers.len(),
        "hierarchy layer count mismatch"
    );
    let mut changed = 0usize;
    for (baseline_layer, mutated_layer) in baseline.layers.iter().zip(&mutated.layers).skip(1) {
        ensure!(
            baseline_layer.nodes.len() == mutated_layer.nodes.len(),
            "hierarchy layer width mismatch"
        );
        changed += baseline_layer
            .nodes
            .iter()
            .zip(&mutated_layer.nodes)
            .filter(|(left, right)| {
                left.statement_digest != right.statement_digest
                    || left.commitment_digest != right.commitment_digest
            })
            .count();
    }
    Ok(changed)
}

fn changed_mini_root_counts(
    baseline: &NativeReceiptRootHierarchy,
    mutated: &NativeReceiptRootHierarchy,
) -> Result<(usize, usize, usize)> {
    ensure!(
        baseline.mini_roots.len() == mutated.mini_roots.len(),
        "mini-root count mismatch"
    );
    let mut reused = 0usize;
    let mut rebuilt = 0usize;
    let mut changed_leaf_count = 0usize;
    for (left, right) in baseline.mini_roots.iter().zip(&mutated.mini_roots) {
        if left.statement_digest == right.statement_digest
            && left.commitment_digest == right.commitment_digest
        {
            reused += 1;
        } else {
            rebuilt += 1;
            if changed_leaf_count == 0 {
                changed_leaf_count = right.leaf_count as usize;
            }
        }
    }
    Ok((reused, rebuilt, changed_leaf_count))
}

fn build_instance_hierarchy_layers(
    params: &NativeBackendParams,
    instances: &[FoldedInstance<LatticeCommitment>],
) -> Result<Vec<Vec<FoldedInstance<LatticeCommitment>>>> {
    ensure!(
        !instances.is_empty(),
        "instance hierarchy requires at least one instance"
    );
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let security = params.security_params();
    let (pk, _) = backend.setup(&security, relation.shape())?;
    for instance in instances {
        ensure!(
            instance.relation_id == relation.relation_id(),
            "instance hierarchy relation id mismatch"
        );
        ensure!(
            instance.shape_digest == pk.shape_digest,
            "instance hierarchy shape digest mismatch"
        );
    }

    let mut current = instances.to_vec();
    let mut layers = vec![current.clone()];
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, _) = backend.fold_pair(&pk, &left, &right)?;
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        layers.push(next.clone());
        current = next;
    }
    Ok(layers)
}

fn changed_instance_internal_nodes(
    baseline: &[Vec<FoldedInstance<LatticeCommitment>>],
    mutated: &[Vec<FoldedInstance<LatticeCommitment>>],
) -> Result<usize> {
    ensure!(
        baseline.len() == mutated.len(),
        "instance hierarchy layer count mismatch"
    );
    let mut changed = 0usize;
    for (baseline_layer, mutated_layer) in baseline.iter().zip(mutated).skip(1) {
        ensure!(
            baseline_layer.len() == mutated_layer.len(),
            "instance hierarchy layer width mismatch"
        );
        changed += baseline_layer
            .iter()
            .zip(mutated_layer)
            .filter(|(left, right)| {
                left.statement_digest != right.statement_digest
                    || left.witness_commitment.digest != right.witness_commitment.digest
            })
            .count();
    }
    Ok(changed)
}

fn instance_layer_widths(layers: &[Vec<FoldedInstance<LatticeCommitment>>]) -> Vec<usize> {
    layers.iter().map(Vec::len).collect()
}

fn mini_root_cache_key(
    params: &NativeBackendParams,
    records: &[NativeTxLeafRecord],
) -> MiniRootCacheKey {
    MiniRootCacheKey {
        params_fingerprint: params.parameter_fingerprint(),
        leaves: records
            .iter()
            .map(|record| MiniRootLeafIdentity {
                statement_digest: record.statement_digest,
                commitment_digest: record.commitment.digest,
                proof_digest: record.proof_digest,
            })
            .collect(),
    }
}

fn upper_tree_cache_key(
    params: &NativeBackendParams,
    children: &[FoldedInstance<LatticeCommitment>],
) -> UpperTreeCacheKey {
    UpperTreeCacheKey {
        params_fingerprint: params.parameter_fingerprint(),
        children: children
            .iter()
            .map(|child| UpperTreeChildIdentity {
                statement_digest: child.statement_digest.0,
                commitment_digest: child.witness_commitment.digest,
            })
            .collect(),
    }
}

fn build_native_receipt_root_aggregation_run(
    label: &str,
    params: &NativeBackendParams,
    records: &[NativeTxLeafRecord],
    mini_root_size: usize,
    workers: usize,
    caches: &mut NativeReceiptRootBuildCaches,
) -> Result<AggregationBuildRunReport> {
    let started = Instant::now();
    let leaf_instances = records
        .iter()
        .map(|record| native_receipt_root_leaf_instance_from_record_with_params(params, record))
        .collect::<Result<Vec<_>>>()?;

    let mini_roots_total = records.len().div_ceil(mini_root_size);
    let mut mini_root_cache_hits = 0usize;
    let mut mini_root_cache_misses = 0usize;
    let mut upper_tree_cache_hits = 0usize;
    let mut upper_tree_cache_misses = 0usize;
    let mut internal_fold_nodes_rebuilt = 0usize;

    let mut chunk_roots = vec![None; mini_roots_total];
    let mut mini_root_miss_jobs = Vec::new();
    for (index, (record_chunk, instance_chunk)) in records
        .chunks(mini_root_size)
        .zip(leaf_instances.chunks(mini_root_size))
        .enumerate()
    {
        let key = mini_root_cache_key(params, record_chunk);
        if let Some(cached) = caches.mini_roots.get(&key) {
            mini_root_cache_hits += 1;
            chunk_roots[index] = Some(cached.clone());
        } else {
            mini_root_cache_misses += 1;
            mini_root_miss_jobs.push(MiniRootMissJob {
                index,
                key,
                instances: instance_chunk.to_vec(),
                rebuilt_folds: instance_chunk.len().saturating_sub(1),
            });
        }
    }

    let mini_root_results = run_jobs_with_workers(workers, mini_root_miss_jobs, |job| {
        let root = fold_native_receipt_root_instances_with_params(params, &job.instances)?;
        Ok((job.index, job.key, job.rebuilt_folds, root))
    })?;
    for (index, key, rebuilt_folds, root) in mini_root_results {
        internal_fold_nodes_rebuilt += rebuilt_folds;
        caches.mini_roots.insert(key, root.clone());
        chunk_roots[index] = Some(root);
    }

    let mut current = chunk_roots
        .into_iter()
        .map(|root| root.expect("every mini-root slot should be populated"))
        .collect::<Vec<_>>();
    while current.len() > 1 {
        let mut next = vec![None; current.len().div_ceil(2)];
        let mut miss_jobs = Vec::new();
        let mut iter = current.into_iter();
        let mut next_index = 0usize;
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let key = upper_tree_cache_key(params, &[left.clone(), right.clone()]);
                if let Some(cached) = caches.upper_tree.get(&key) {
                    upper_tree_cache_hits += 1;
                    next[next_index] = Some(cached.clone());
                } else {
                    upper_tree_cache_misses += 1;
                    miss_jobs.push(UpperTreeMissJob {
                        index: next_index,
                        key,
                        left,
                        right,
                    });
                }
            } else {
                next[next_index] = Some(left);
            }
            next_index += 1;
        }

        let upper_results = run_jobs_with_workers(workers, miss_jobs, |job| {
            let root = fold_native_receipt_root_instances_with_params(
                params,
                &[job.left.clone(), job.right.clone()],
            )?;
            Ok((job.index, job.key, root))
        })?;
        for (index, key, root) in upper_results {
            internal_fold_nodes_rebuilt += 1;
            caches.upper_tree.insert(key, root.clone());
            next[index] = Some(root);
        }
        current = next
            .into_iter()
            .map(|root| root.expect("every upper-tree slot should be populated"))
            .collect::<Vec<_>>();
    }

    let root = current
        .pop()
        .expect("aggregation run must produce one receipt-root instance");
    Ok(AggregationBuildRunReport {
        label: label.to_owned(),
        total_ns: started.elapsed().as_nanos(),
        mini_roots_total,
        mini_root_cache_hits,
        mini_root_cache_misses,
        upper_tree_cache_hits,
        upper_tree_cache_misses,
        internal_fold_nodes_rebuilt,
        root_statement_digest: hex48(root.statement_digest.0),
    })
}

fn measure_native_receipt_root_hierarchy(
    leaf_count: usize,
    mini_root_size: usize,
    changed_leaf_index: usize,
    corpus_path: Option<&Path>,
) -> Result<ReceiptRootHierarchyReport> {
    let params = current_native_backend_params();
    let records = build_native_leaf_records_for_measurement(leaf_count, corpus_path)?;
    let mutated_records =
        mutate_native_leaf_records_for_measurement(&records, changed_leaf_index, corpus_path)?;
    let baseline = build_native_receipt_root_hierarchy_from_records_with_params(
        &params,
        &records,
        mini_root_size,
    )?;
    let mutated = build_native_receipt_root_hierarchy_from_records_with_params(
        &params,
        &mutated_records,
        mini_root_size,
    )?;
    let (mini_roots_reused, mini_roots_rebuilt, changed_mini_root_leaf_count) =
        changed_mini_root_counts(&baseline.hierarchy, &mutated.hierarchy)?;
    Ok(ReceiptRootHierarchyReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        record_source: measurement_record_source_label(corpus_path),
        leaf_count,
        mini_root_size,
        changed_leaf_index,
        layer_widths: hierarchy_layer_widths(&baseline.hierarchy),
        mini_roots_total: baseline.hierarchy.mini_roots.len(),
        mini_roots_reused,
        mini_roots_rebuilt,
        changed_mini_root_leaf_count,
        block_internal_nodes_touched: changed_hierarchy_internal_nodes(
            &baseline.hierarchy,
            &mutated.hierarchy,
        )?,
        flat_internal_nodes_touched: leaf_count.saturating_sub(1),
        baseline_root_statement_digest: hex48(baseline.hierarchy.root_statement_digest),
        mutated_root_statement_digest: hex48(mutated.hierarchy.root_statement_digest),
    })
}

fn measure_native_epoch_root_hierarchy(
    block_count: usize,
    changed_block_index: usize,
    corpus_path: Option<&Path>,
) -> Result<EpochRootHierarchyReport> {
    ensure!(
        changed_block_index < block_count,
        "changed block index {} must be smaller than block count {}",
        changed_block_index,
        block_count
    );
    let params = current_native_backend_params();
    let block_leaf_count = native_receipt_root_mini_root_size();
    let base_block_records =
        build_native_leaf_records_for_measurement(block_leaf_count, corpus_path)?;
    let changed_block_records = mutate_native_leaf_records_for_measurement(
        &base_block_records,
        block_leaf_count / 2,
        corpus_path,
    )?;
    let base_block = build_native_receipt_root_hierarchy_from_records_with_params(
        &params,
        &base_block_records,
        native_receipt_root_mini_root_size(),
    )?;
    let changed_block = build_native_receipt_root_hierarchy_from_records_with_params(
        &params,
        &changed_block_records,
        native_receipt_root_mini_root_size(),
    )?;
    let baseline_blocks = vec![base_block.root.clone(); block_count];
    let mut mutated_blocks = baseline_blocks.clone();
    mutated_blocks[changed_block_index] = changed_block.root.clone();
    let baseline_layers = build_instance_hierarchy_layers(&params, &baseline_blocks)?;
    let mutated_layers = build_instance_hierarchy_layers(&params, &mutated_blocks)?;
    Ok(EpochRootHierarchyReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        record_source: measurement_record_source_label(corpus_path),
        block_count,
        changed_block_index,
        layer_widths: instance_layer_widths(&baseline_layers),
        epoch_internal_nodes_touched: changed_instance_internal_nodes(
            &baseline_layers,
            &mutated_layers,
        )?,
        flat_epoch_internal_nodes: block_count.saturating_sub(1),
        baseline_epoch_root_statement_digest: hex48(
            baseline_layers
                .last()
                .and_then(|layer| layer.first())
                .expect("epoch hierarchy must produce one root")
                .statement_digest
                .0,
        ),
        mutated_epoch_root_statement_digest: hex48(
            mutated_layers
                .last()
                .and_then(|layer| layer.first())
                .expect("epoch hierarchy must produce one root")
                .statement_digest
                .0,
        ),
    })
}

fn measure_native_receipt_root_build(
    leaf_count: usize,
    mini_root_size: usize,
    workers: usize,
    warm_repeat: usize,
    changed_leaf_index: usize,
    corpus_path: Option<&Path>,
) -> Result<NativeReceiptRootBuildReport> {
    let params = current_native_backend_params();
    let records = build_native_leaf_records_for_measurement(leaf_count, corpus_path)?;
    let mutated_records =
        mutate_native_leaf_records_for_measurement(&records, changed_leaf_index, corpus_path)?;
    let mut caches = NativeReceiptRootBuildCaches::default();
    let cold = build_native_receipt_root_aggregation_run(
        "cold",
        &params,
        &records,
        mini_root_size,
        workers,
        &mut caches,
    )?;
    let exact_repeat = if warm_repeat > 0 {
        Some(build_native_receipt_root_aggregation_run(
            "exact_repeat",
            &params,
            &records,
            mini_root_size,
            workers,
            &mut caches,
        )?)
    } else {
        None
    };
    let mutated_repeat = Some(build_native_receipt_root_aggregation_run(
        "mutated_repeat",
        &params,
        &mutated_records,
        mini_root_size,
        workers,
        &mut caches,
    )?);
    Ok(NativeReceiptRootBuildReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        record_source: measurement_record_source_label(corpus_path),
        leaf_count,
        mini_root_size,
        workers,
        cold,
        exact_repeat,
        mutated_repeat,
    })
}

fn measure_native_receipt_root_verify_only(
    leaf_count: usize,
    verify_runs: usize,
) -> Result<NativeVerifyOnlyReport> {
    let params = current_native_backend_params();
    let witnesses = (0..leaf_count)
        .map(|seed| sample_witness(seed as u64 + 1))
        .collect::<Vec<_>>();

    clear_native_receipt_root_build_caches();
    let prepare_start = Instant::now();
    let built_leaves = witnesses
        .iter()
        .map(|witness| {
            let tx = tx_leaf_public_tx_from_witness(witness)?;
            let built = build_native_tx_leaf_artifact_bytes_with_params(&params, witness)?;
            let receipt = built.receipt.clone();
            Ok((tx, receipt, built))
        })
        .collect::<Result<Vec<_>>>()?;
    let native_artifacts = built_leaves
        .iter()
        .map(|(_, _, built)| decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes))
        .collect::<Result<Vec<_>>>()?;
    let built_root =
        build_native_tx_leaf_receipt_root_artifact_bytes_with_params(&params, &native_artifacts)?;
    let prepare_artifacts_ns = prepare_start.elapsed().as_nanos();

    let tx_leaf_artifacts_bytes_total = built_leaves
        .iter()
        .map(|(_, _, built)| built.artifact_bytes.len())
        .sum::<usize>();
    let receipt_root_artifact_bytes = built_root.artifact_bytes.len();

    let extract_start = Instant::now();
    let records = native_artifacts
        .iter()
        .map(native_tx_leaf_record_from_artifact)
        .collect::<Vec<_>>();
    let extract_records_ns = extract_start.elapsed().as_nanos();

    let mut leaf_runs = Vec::with_capacity(verify_runs);
    let mut root_replay_runs = Vec::with_capacity(verify_runs);
    let mut root_records_runs = Vec::with_capacity(verify_runs);
    let mut full_block_runs = Vec::with_capacity(verify_runs);

    for _ in 0..verify_runs {
        clear_prepared_matrix_cache();
        clear_verified_native_tx_leaf_store();
        let start = Instant::now();
        for (tx, receipt, built) in &built_leaves {
            verify_native_tx_leaf_artifact_bytes(tx, receipt, &built.artifact_bytes)?;
        }
        leaf_runs.push(start.elapsed().as_nanos());

        clear_prepared_matrix_cache();
        clear_verified_native_tx_leaf_store();
        let start = Instant::now();
        verify_native_tx_leaf_receipt_root_artifact_bytes(
            &native_artifacts,
            &built_root.artifact_bytes,
        )?;
        root_replay_runs.push(start.elapsed().as_nanos());

        clear_prepared_matrix_cache();
        clear_verified_native_tx_leaf_store();
        let start = Instant::now();
        verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(
            &params,
            &records,
            &built_root.artifact_bytes,
        )?;
        root_records_runs.push(start.elapsed().as_nanos());

        clear_prepared_matrix_cache();
        clear_verified_native_tx_leaf_store();
        let start = Instant::now();
        for (tx, receipt, built) in &built_leaves {
            verify_native_tx_leaf_artifact_bytes(tx, receipt, &built.artifact_bytes)?;
        }
        verify_native_tx_leaf_receipt_root_artifact_bytes(
            &native_artifacts,
            &built_root.artifact_bytes,
        )?;
        full_block_runs.push(start.elapsed().as_nanos());
    }

    Ok(NativeVerifyOnlyReport {
        parameter_fingerprint: current_parameter_fingerprint_hex(),
        leaf_count,
        verify_runs,
        product_default_root_verify_mode: native_receipt_root_verify_mode_label().to_string(),
        tx_leaf_artifacts_bytes_total,
        receipt_root_artifact_bytes,
        prepare_artifacts_ns,
        extract_records_ns,
        cold_cache_between_runs: true,
        leaf_verify: timing_stats(leaf_runs),
        receipt_root_replay_verify: timing_stats(root_replay_runs),
        receipt_root_records_verify: timing_stats(root_records_runs),
        full_block_verify: timing_stats(full_block_runs),
    })
}

fn timing_stats(runs_ns: Vec<u128>) -> TimingStats {
    let min_ns = *runs_ns.iter().min().expect("non-empty timing runs");
    let max_ns = *runs_ns.iter().max().expect("non-empty timing runs");
    let avg_ns = runs_ns.iter().sum::<u128>() as f64 / runs_ns.len() as f64;
    TimingStats {
        runs_ns,
        min_ns,
        max_ns,
        avg_ns,
    }
}

fn mutated_review_case(
    base: &ReviewVectorCase,
    name: &str,
    artifact_bytes: Vec<u8>,
) -> ReviewVectorCase {
    let mut case = base.clone();
    case.name = name.to_owned();
    case.expected_valid = false;
    case.expected_error_substring = None;
    case.artifact_hex = hex::encode(artifact_bytes);
    case
}

fn random_malformed_artifact_mutation(
    kind: &str,
    artifact_bytes: &[u8],
    rng: &mut MutationRng,
) -> Result<(String, Vec<u8>)> {
    ensure!(
        !artifact_bytes.is_empty(),
        "cannot mutate an empty {kind} artifact"
    );
    Ok(match rng.pick(6) {
        0 => {
            let pos = rng.pick(artifact_bytes.len());
            let mut mutated = artifact_bytes.to_vec();
            mutated[pos] ^= rng.nonzero_byte();
            (format!("byte_flip:{kind}:{pos}"), mutated)
        }
        1 => {
            let new_len = rng.pick(artifact_bytes.len());
            (
                format!("truncate:{kind}:{new_len}"),
                artifact_bytes[..new_len].to_vec(),
            )
        }
        2 => {
            let pos = rng.pick(artifact_bytes.len());
            (
                format!("delete_byte:{kind}:{pos}"),
                remove_byte(artifact_bytes, pos),
            )
        }
        3 => {
            let pos = rng.pick(artifact_bytes.len() + 1);
            let count = 1 + rng.pick(8);
            let mut mutated = artifact_bytes.to_vec();
            let mut noise = Vec::with_capacity(count);
            for _ in 0..count {
                noise.push(rng.next_u8());
            }
            mutated.splice(pos..pos, noise);
            (format!("insert_noise:{kind}:{pos}:{count}"), mutated)
        }
        4 => {
            let start = rng.pick(artifact_bytes.len());
            let width = 1 + rng.pick((artifact_bytes.len() - start).clamp(1, 8));
            let mut mutated = artifact_bytes.to_vec();
            for byte in mutated.iter_mut().skip(start).take(width) {
                *byte = rng.next_u8();
            }
            (format!("overwrite_span:{kind}:{start}:{width}"), mutated)
        }
        _ => {
            let start = rng.pick(artifact_bytes.len());
            let width = 1 + rng.pick((artifact_bytes.len() - start).clamp(1, 8));
            let pos = rng.pick(artifact_bytes.len() + 1);
            let mut mutated = artifact_bytes.to_vec();
            let window = artifact_bytes[start..start + width].to_vec();
            mutated.splice(pos..pos, window);
            (
                format!("duplicate_window:{kind}:{start}:{width}:{pos}"),
                mutated,
            )
        }
    })
}

fn remove_byte(bytes: &[u8], index: usize) -> Vec<u8> {
    let mut mutated = bytes.to_vec();
    mutated.remove(index);
    mutated
}

struct MutationRng {
    state: u64,
}

impl MutationRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 7;
        self.state ^= self.state >> 9;
        self.state = self.state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        self.state
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn nonzero_byte(&mut self) -> u8 {
        let mut byte = self.next_u8();
        if byte == 0 {
            byte = 0x5a;
        }
        byte
    }

    fn pick(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            0
        } else {
            (self.next_u64() % upper as u64) as usize
        }
    }
}

fn review_state_label(state: ReviewState) -> &'static str {
    match state {
        ReviewState::Experimental => "experimental",
        ReviewState::CandidateUnderReview => "candidate_under_review",
        ReviewState::Accepted => "accepted",
        ReviewState::Blocked => "blocked",
        ReviewState::Killed => "killed",
    }
}

fn timing_caveat() -> &'static str {
    "total_active_path_*_ns are single-run wall-clock measurements; rerun on your target host before treating them as decision-grade latency numbers"
}

fn validate_relation_selection(
    choice: RelationChoice,
    allow_diagnostic_relation: bool,
) -> Result<()> {
    ensure!(
        is_canonical_relation(choice) || allow_diagnostic_relation,
        "{} is diagnostic-only; rerun with --allow-diagnostic-relation to benchmark it explicitly",
        choice
            .to_possible_value()
            .expect("value enum name")
            .get_name()
    );
    Ok(())
}

fn benchmark_toy_balance(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let relation = ToyBalanceRelation::default();
    let backend = LatticeBackend::default();
    let security = backend.security_params();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());

    let mut leaf_payloads = Vec::with_capacity(k);
    let mut total_bytes = 0usize;
    let mut packed_witness_bits = 0usize;

    reset_kernel_runtime_state();
    let prove_start = Instant::now();
    for idx in 0..k {
        let input_a = 10 + idx as u64;
        let input_b = 20 + idx as u64;
        let fee = 1 + (idx as u64 % 3);
        let total_inputs = input_a + input_b;
        let total_outputs = total_inputs - fee;
        let statement = ToyBalanceStatement {
            total_inputs,
            total_outputs,
            fee,
        };
        let witness = ToyBalanceWitness {
            inputs: [input_a, input_b],
            outputs: [total_outputs / 2, total_outputs - (total_outputs / 2)],
            fee,
        };
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, &witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        packed_witness_bits += packed.used_bits;
        let relation_id = relation.relation_id();
        let commitment = backend.commit_witness(&pk, &packed)?;
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed, &commitment)?;
        let artifact = LeafArtifact {
            version: 1,
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: proof.clone(),
        };
        total_bytes += leaf_artifact_bytes(&artifact);
        let instance = FoldedInstance {
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: commitment,
        };
        leaf_payloads.push((encoding, packed, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, _, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (encoding, packed, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, packed, proof)?;
    }
    for step in &fold_steps {
        backend.verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)?;
    }
    let total_verify_ns = verify_start.elapsed().as_nanos();

    Ok(BenchResult {
        relation: "toy_balance".to_owned(),
        k,
        parameter_fingerprint: Some(current_parameter_fingerprint_hex()),
        native_backend_params: Some(current_bench_native_backend_params()),
        native_security_claim: Some(current_bench_native_security_claim()?),
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(pk.shape_digest),
        note: format!(
            "{}; superneo fold backend root={}",
            note_prefix(RelationChoice::ToyBalance),
            root.witness_commitment.to_hex()
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn benchmark_tx_receipt(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let relation = TxProofReceiptRelation::default();
    let backend = LatticeBackend::default();
    let security = backend.security_params();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());

    let mut leaf_payloads = Vec::with_capacity(k);
    let mut total_bytes = 0usize;
    let mut packed_witness_bits = 0usize;

    reset_kernel_runtime_state();
    let prove_start = Instant::now();
    for idx in 0..k {
        let proof_bytes = synthetic_bytes(48 + (idx % 8), idx as u64 + 11);
        let public_inputs = synthetic_bytes(32, idx as u64 + 101);
        let verifier_profile = format!("inline-tx-receipt-v{}", idx).into_bytes();
        let witness = TxProofReceiptWitness {
            receipt_bytes: proof_bytes.clone(),
            verification_trace_bits: bytes_to_bits(&proof_bytes, 128),
        };
        let statement = build_tx_proof_receipt(
            &proof_bytes,
            &public_inputs,
            &verifier_profile,
            &witness.verification_trace_bits,
        )?;
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, &witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        packed_witness_bits += packed.used_bits;
        let relation_id = relation.relation_id();
        let commitment = backend.commit_witness(&pk, &packed)?;
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed, &commitment)?;
        let artifact = LeafArtifact {
            version: 1,
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: proof.clone(),
        };
        total_bytes += leaf_artifact_bytes(&artifact);
        let instance = FoldedInstance {
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: commitment,
        };
        leaf_payloads.push((encoding, packed, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, _, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (encoding, packed, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, packed, proof)?;
    }
    for step in &fold_steps {
        backend.verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)?;
    }
    let total_verify_ns = verify_start.elapsed().as_nanos();

    Ok(BenchResult {
        relation: "tx_receipt".to_owned(),
        k,
        parameter_fingerprint: Some(current_parameter_fingerprint_hex()),
        native_backend_params: Some(current_bench_native_backend_params()),
        native_security_claim: Some(current_bench_native_security_claim()?),
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(pk.shape_digest),
        note: format!(
            "{}; superneo fold backend root={}",
            note_prefix(RelationChoice::TxReceipt),
            root.witness_commitment.to_hex()
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn benchmark_native_tx_validity(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let relation = NativeTxValidityRelation::default();
    let backend = LatticeBackend::default();
    let security = backend.security_params();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());

    let witnesses = (0..k)
        .map(|seed| sample_witness(seed as u64 + 1))
        .collect::<Vec<_>>();
    let mut leaf_payloads = Vec::with_capacity(k);
    let mut total_bytes = 0usize;
    let mut packed_witness_bits = 0usize;

    reset_kernel_runtime_state();
    let prove_start = Instant::now();
    for witness in &witnesses {
        let statement = native_tx_validity_statement_from_witness(witness)?;
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        packed_witness_bits += packed.used_bits;
        let relation_id = relation.relation_id();
        let commitment = backend.commit_witness(&pk, &packed)?;
        let proof = backend.prove_leaf(&pk, &relation_id, &encoding, &packed, &commitment)?;
        let artifact = LeafArtifact {
            version: 1,
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: proof.clone(),
        };
        total_bytes += leaf_artifact_bytes(&artifact) + packed_witness_transport_bytes(&packed);
        let instance = FoldedInstance {
            relation_id,
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: commitment,
        };
        leaf_payloads.push((encoding, packed, instance, proof));
    }
    let leaf_prove_ns = prove_start.elapsed().as_nanos();

    let fold_start = Instant::now();
    let (root, fold_steps, fold_bytes) = fold_to_root(
        &backend,
        &pk,
        leaf_payloads
            .iter()
            .map(|(_, _, instance, _)| instance.clone())
            .collect(),
    )?;
    total_bytes += fold_bytes;
    let total_prove_ns = leaf_prove_ns + fold_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (encoding, packed, _, proof) in &leaf_payloads {
        backend.verify_leaf(&vk, &relation.relation_id(), encoding, packed, proof)?;
    }
    for step in &fold_steps {
        backend.verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)?;
    }
    let total_verify_ns = verify_start.elapsed().as_nanos();

    Ok(BenchResult {
        relation: "native_tx_validity".to_owned(),
        k,
        parameter_fingerprint: Some(current_parameter_fingerprint_hex()),
        native_backend_params: Some(current_bench_native_backend_params()),
        native_security_claim: Some(current_bench_native_security_claim()?),
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(pk.shape_digest),
        note: format!(
            "{}; bytes include packed witness transport; root={}",
            note_prefix(RelationChoice::NativeTxValidity),
            root.witness_commitment.to_hex()
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn benchmark_native_tx_leaf_receipt_root(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let witnesses = (0..k)
        .map(|seed| sample_witness(seed as u64 + 1))
        .collect::<Vec<_>>();
    let relation = NativeTxValidityRelation::default();
    let packed_witness_bits = relation.shape().witness_schema.total_witness_bits() * k;

    reset_kernel_runtime_state();
    let edge_prepare_start = Instant::now();
    let built_leaves = witnesses
        .iter()
        .map(|witness| {
            let tx = tx_leaf_public_tx_from_witness(witness)?;
            let built = build_native_tx_leaf_artifact_bytes(witness)?;
            let receipt = built.receipt.clone();
            Ok((tx, receipt, built))
        })
        .collect::<Result<Vec<_>>>()?;
    let edge_prepare_ns = edge_prepare_start.elapsed().as_nanos();

    let native_artifacts = built_leaves
        .iter()
        .map(|(_, _, built)| decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes))
        .collect::<Result<Vec<_>>>()?;
    let tx_leaf_bytes_total = built_leaves
        .iter()
        .map(|(_, _, built)| built.artifact_bytes.len())
        .sum::<usize>();

    clear_native_receipt_root_build_caches();
    let prove_start = Instant::now();
    let built_root = build_native_tx_leaf_receipt_root_artifact_bytes(&native_artifacts)?;
    let total_prove_ns = prove_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (tx, receipt, built) in &built_leaves {
        verify_native_tx_leaf_artifact_bytes(tx, receipt, &built.artifact_bytes)?;
    }
    let metadata = verify_native_tx_leaf_receipt_root_artifact_bytes(
        &native_artifacts,
        &built_root.artifact_bytes,
    )?;
    let total_verify_ns = verify_start.elapsed().as_nanos();
    clear_verified_native_tx_leaf_store();

    let total_bytes = tx_leaf_bytes_total + built_root.artifact_bytes.len();

    Ok(BenchResult {
        relation: "native_tx_leaf_receipt_root".to_owned(),
        k,
        parameter_fingerprint: Some(hex48(metadata.params_fingerprint)),
        native_backend_params: Some(current_bench_native_backend_params()),
        native_security_claim: Some(current_bench_native_security_claim()?),
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(ShapeDigest(metadata.shape_digest)),
        note: format!(
            "{}; native tx-leaf artifacts={}B root_artifact={}B; {}",
            note_prefix(RelationChoice::NativeTxLeafReceiptRoot),
            tx_leaf_bytes_total,
            built_root.artifact_bytes.len(),
            timing_caveat()
        ),
        edge_prepare_ns: Some(edge_prepare_ns),
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: Some(ImportComparison {
            baseline_verify_ns: total_verify_ns,
            accumulation_prewarm_ns: None,
            accumulation_warm_verify_ns: None,
            cold_residual_verify_ns: None,
            cold_residual_artifact_bytes: None,
            cold_residual_replayed_leaf_verifications: None,
            cold_residual_used_old_aggregation_backend: None,
        }),
    })
}

fn benchmark_tx_leaf_receipt_root(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let proofs = (0..k)
        .map(|seed| sample_transaction_proof(seed as u64 + 1))
        .collect::<Vec<_>>();
    let leaf_relation = TxLeafPublicRelation::default();
    let packed_witness_bits = leaf_relation.shape().witness_schema.total_witness_bits() * k;

    reset_kernel_runtime_state();
    let edge_prepare_start = Instant::now();
    let built_leaves = proofs
        .iter()
        .map(|proof| {
            let tx = tx_leaf_public_tx_from_transaction_proof(proof)?;
            let receipt = canonical_tx_validity_receipt_from_transaction_proof(proof)?;
            let built = build_tx_leaf_artifact_bytes(proof)?;
            Ok((tx, receipt, built))
        })
        .collect::<Result<Vec<_>>>()?;
    let edge_prepare_ns = edge_prepare_start.elapsed().as_nanos();

    let receipts = built_leaves
        .iter()
        .map(|(_, receipt, _)| receipt.clone())
        .collect::<Vec<_>>();
    let tx_leaf_bytes_total = built_leaves
        .iter()
        .map(|(_, _, built)| built.artifact_bytes.len())
        .sum::<usize>();

    let prove_start = Instant::now();
    let built_root = build_receipt_root_artifact_bytes(&receipts)?;
    let total_prove_ns = prove_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    for (tx, receipt, built) in &built_leaves {
        verify_tx_leaf_artifact_bytes(tx, receipt, &built.artifact_bytes)?;
    }
    let metadata = verify_receipt_root_artifact_bytes(&receipts, &built_root.artifact_bytes)?;
    let total_verify_ns = verify_start.elapsed().as_nanos();

    let total_bytes = tx_leaf_bytes_total + built_root.artifact_bytes.len();

    Ok(BenchResult {
        relation: "tx_leaf_receipt_root".to_owned(),
        k,
        parameter_fingerprint: Some(hex48(metadata.params_fingerprint)),
        native_backend_params: Some(current_bench_native_backend_params()),
        native_security_claim: Some(current_bench_native_security_claim()?),
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits,
        shape_digest: shape_hex(ShapeDigest(metadata.shape_digest)),
        note: format!(
            "{}; proof-ready txs; tx_leaf_artifacts={}B root_artifact={}B",
            note_prefix(RelationChoice::TxLeafReceiptRoot),
            tx_leaf_bytes_total,
            built_root.artifact_bytes.len()
        ),
        edge_prepare_ns: Some(edge_prepare_ns),
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn benchmark_verified_tx_receipt(
    k: usize,
    inline_tx_baseline: Option<InlineTxBaseline>,
) -> Result<BenchResult> {
    let proofs = (0..k)
        .map(|seed| sample_transaction_proof(seed as u64 + 1))
        .collect::<Vec<_>>();
    let relation = TxLeafPublicRelation::default();

    reset_kernel_runtime_state();
    let prove_start = Instant::now();
    let built = build_verified_tx_proof_receipt_root_artifact_bytes(&proofs)?;
    let total_prove_ns = prove_start.elapsed().as_nanos();
    let kernel_report = take_kernel_cost_report();

    clear_prepared_matrix_cache();
    let verify_start = Instant::now();
    let metadata =
        verify_verified_tx_proof_receipt_root_artifact_bytes(&proofs, &built.artifact_bytes)?;
    let total_verify_ns = verify_start.elapsed().as_nanos();

    let tx_proof_bytes_total = proofs
        .iter()
        .map(|proof| bincode::serialize(proof).map(|bytes| bytes.len()))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    let receipt_bytes_total = proofs.len() * (48 * 4);
    let total_bytes = tx_proof_bytes_total + receipt_bytes_total + built.artifact_bytes.len();

    Ok(BenchResult {
        relation: "verified_tx_receipt".to_owned(),
        k,
        parameter_fingerprint: Some(hex48(metadata.params_fingerprint)),
        native_backend_params: Some(current_bench_native_backend_params()),
        native_security_claim: Some(current_bench_native_security_claim()?),
        bytes_per_tx: total_bytes.div_ceil(k),
        total_active_path_prove_ns: total_prove_ns,
        total_active_path_verify_ns: total_verify_ns,
        packed_witness_bits: relation.shape().witness_schema.total_witness_bits() * k,
        shape_digest: shape_hex(ShapeDigest(metadata.shape_digest)),
        note: format!(
            "{}; verified inline tx proofs + receipt_root artifact={}B tx_artifacts={}B",
            note_prefix(RelationChoice::VerifiedTxReceipt),
            built.artifact_bytes.len(),
            tx_proof_bytes_total + receipt_bytes_total
        ),
        edge_prepare_ns: None,
        peak_rss_bytes: Some(current_peak_rss_bytes()?),
        kernel_report: Some(kernel_report),
        inline_tx_baseline,
        import_comparison: None,
    })
}

fn fold_to_root(
    backend: &LatticeBackend,
    pk: &<LatticeBackend as Backend<Goldilocks>>::ProverKey,
    leaves: Vec<FoldedInstance<<LatticeBackend as Backend<Goldilocks>>::Commitment>>,
) -> Result<(
    FoldedInstance<<LatticeBackend as Backend<Goldilocks>>::Commitment>,
    Vec<
        FoldStep<
            <LatticeBackend as Backend<Goldilocks>>::Commitment,
            <LatticeBackend as Backend<Goldilocks>>::FoldProof,
        >,
    >,
    usize,
)> {
    ensure!(!leaves.is_empty(), "fold tree requires at least one leaf");
    let mut current = leaves;
    let mut steps = Vec::new();
    let mut total_bytes = 0usize;

    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(pk, &left, &right)?;
                let artifact = FoldArtifact {
                    version: 1,
                    parent_statement_digest: parent.statement_digest,
                    left_statement_digest: left.statement_digest,
                    right_statement_digest: right.statement_digest,
                    proof: proof.clone(),
                };
                total_bytes += fold_artifact_bytes(&artifact);
                steps.push(FoldStep {
                    parent: parent.clone(),
                    left: left.clone(),
                    right: right.clone(),
                    proof,
                });
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    Ok((current.pop().unwrap(), steps, total_bytes))
}

fn load_inline_tx_baselines() -> Result<HashMap<usize, InlineTxBaseline>> {
    let path = baseline_path();
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read baseline metrics from {}", path.display()))?;
    let mut baselines = HashMap::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 6 || cols[0] != "raw_active" || cols[2] != "ok" {
            continue;
        }
        let k = cols[1].parse::<usize>()?;
        baselines.insert(
            k,
            InlineTxBaseline {
                bytes_per_tx: cols[3].parse()?,
                total_active_path_prove_ns: cols[4].parse()?,
                total_active_path_verify_ns: cols[5].parse()?,
            },
        );
    }
    Ok(baselines)
}

fn sample_transaction_proof(seed: u64) -> TransactionProof {
    static SAMPLE_PROOFS: OnceLock<std::sync::Mutex<HashMap<u64, TransactionProof>>> =
        OnceLock::new();
    let proofs = SAMPLE_PROOFS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut guard = proofs.lock().expect("sample tx proof cache poisoned");
    if let Some(proof) = guard.get(&seed) {
        return proof.clone();
    }
    let witness = sample_witness(seed);
    let (proving_key, _) = generate_keys();
    let proof = prove(&witness, &proving_key).expect("sample tx proof");
    guard.insert(seed, proof.clone());
    proof
}

fn sample_witness(seed: u64) -> TransactionWitness {
    let sk_spend = [seed as u8 + 42; 32];
    let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
    let input_note_native = NoteData {
        value: 8,
        asset_id: NATIVE_ASSET_ID,
        pk_recipient: [seed as u8 + 2; 32],
        pk_auth,
        rho: [seed as u8 + 3; 32],
        r: [seed as u8 + 4; 32],
    };
    let input_note_asset = NoteData {
        value: 5,
        asset_id: seed + 100,
        pk_recipient: [seed as u8 + 5; 32],
        pk_auth,
        rho: [seed as u8 + 6; 32],
        r: [seed as u8 + 7; 32],
    };

    let leaf0 = input_note_native.commitment();
    let leaf1 = input_note_asset.commitment();
    let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

    let output_native = OutputNoteWitness {
        note: NoteData {
            value: 3,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 11; 32],
            pk_auth: [seed as u8 + 12; 32],
            rho: [seed as u8 + 13; 32],
            r: [seed as u8 + 14; 32],
        },
    };
    let output_asset = OutputNoteWitness {
        note: NoteData {
            value: 5,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 21; 32],
            pk_auth: [seed as u8 + 22; 32],
            rho: [seed as u8 + 23; 32],
            r: [seed as u8 + 24; 32],
        },
    };

    TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [seed as u8 + 9; 32],
                merkle_path: merkle_path0,
            },
            InputNoteWitness {
                note: input_note_asset,
                position: 1,
                rho_seed: [seed as u8 + 10; 32],
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

fn build_two_leaf_merkle_tree(
    leaf0: HashFelt,
    leaf1: HashFelt,
) -> (MerklePath, MerklePath, HashFelt) {
    let mut siblings0 = vec![leaf1];
    let mut siblings1 = vec![leaf0];
    let mut current = merkle_node(leaf0, leaf1);
    for _ in 1..CIRCUIT_MERKLE_DEPTH {
        let zero = [Goldilocks::new(0); 6];
        siblings0.push(zero);
        siblings1.push(zero);
        current = merkle_node(current, zero);
    }
    (
        MerklePath {
            siblings: siblings0,
        },
        MerklePath {
            siblings: siblings1,
        },
        current,
    )
}

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../output/prover-recovery/2026-03-14/active-lanes/metrics.tsv")
}

fn shape_hex(shape: ShapeDigest) -> String {
    shape.to_hex()
}

fn hex48(bytes: [u8; 48]) -> String {
    hex::encode(bytes)
}

fn blake3_384(bytes: &[u8]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    let mut output = hasher.finalize_xof();
    let mut out = [0u8; 48];
    output.fill(&mut out);
    out
}

fn hex32(bytes: [u8; 32]) -> String {
    hex::encode(bytes)
}

fn synthetic_bytes(len: usize, seed: u64) -> Vec<u8> {
    (0..len)
        .map(|idx| (((seed as usize * 17) + idx * 29) & 0xff) as u8)
        .collect()
}

fn bytes_to_bits(bytes: &[u8], limit: usize) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |shift| (byte >> shift) & 1))
        .take(limit)
        .collect()
}

fn leaf_artifact_bytes(artifact: &LeafArtifact<LeafDigestProof>) -> usize {
    u16::BITS as usize / 8
        + RelationId::BYTES
        + ShapeDigest::BYTES
        + StatementDigest::BYTES
        + artifact.proof.byte_size()
}

fn fold_artifact_bytes(artifact: &FoldArtifact<FoldDigestProof>) -> usize {
    u16::BITS as usize / 8 + (StatementDigest::BYTES * 3) + artifact.proof.byte_size()
}

fn packed_witness_transport_bytes(packed: &superneo_ring::PackedWitness<u64>) -> usize {
    4 + (packed.coeffs.len() * 8) + 4 + 4 + 2
}

fn current_peak_rss_bytes() -> Result<u64> {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        ensure!(rc == 0, "getrusage failed");
        let usage = unsafe { usage.assume_init() };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            return Ok(usage.ru_maxrss as u64);
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            return Ok((usage.ru_maxrss as u64) * 1024);
        }
    }
    #[allow(unreachable_code)]
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use native_backend_ref::verify_bundle_dir;
    use std::fs;
    use superneo_backend_lattice::{LatticeCommitment, RingElem};
    use superneo_ccs::digest_statement;
    use superneo_hegemon::{
        verify_native_tx_leaf_artifact_bytes_with_params,
        verify_native_tx_leaf_receipt_root_artifact_from_records_with_params,
    };

    #[test]
    fn default_cli_relation_is_canonical_native_receipt_root() {
        let cli = Cli::try_parse_from(["superneo-bench"]).expect("cli parses");
        assert_eq!(cli.relation, RelationChoice::NativeTxLeafReceiptRoot);
        assert!(!cli.allow_diagnostic_relation);
        validate_relation_selection(cli.relation, cli.allow_diagnostic_relation)
            .expect("default relation stays canonical");
    }

    #[test]
    fn diagnostic_relations_require_explicit_opt_in() {
        let cli = Cli::try_parse_from(["superneo-bench", "--relation", "verified_tx_receipt"])
            .expect("cli parses");
        let error = validate_relation_selection(cli.relation, cli.allow_diagnostic_relation)
            .expect_err("diagnostic relation should be rejected without opt-in");
        assert!(
            error.to_string().contains("--allow-diagnostic-relation"),
            "unexpected error: {error}"
        );

        let opted_in = Cli::try_parse_from([
            "superneo-bench",
            "--relation",
            "verified_tx_receipt",
            "--allow-diagnostic-relation",
        ])
        .expect("cli parses with diagnostic opt-in");
        validate_relation_selection(opted_in.relation, opted_in.allow_diagnostic_relation)
            .expect("opted-in diagnostic relation should be accepted");
    }

    #[test]
    fn note_prefix_labels_canonical_and_diagnostic_lanes() {
        assert!(note_prefix(RelationChoice::NativeTxLeafReceiptRoot)
            .starts_with("canonical experimental lane:"),);
        assert!(note_prefix(RelationChoice::ToyBalance).starts_with("diagnostic lane:"),);
    }

    #[test]
    fn native_review_manifest_reports_verified_aggregation_surface() {
        let manifest = current_native_review_manifest().expect("review manifest");
        assert_eq!(
            manifest.guarantee_summary.security_object,
            "verified_leaf_aggregation"
        );
        assert!(manifest.guarantee_summary.verified_tx_leaf_replay);
        assert!(manifest.guarantee_summary.fold_parent_rows_recomputed);
        assert!(
            !manifest
                .guarantee_summary
                .ccs_soundness_from_fold_layer_alone
        );
        assert_eq!(manifest.exact_live_tx_leaf_commitment.witness_bits, 4_935);
        assert_eq!(
            manifest
                .exact_live_tx_leaf_commitment
                .live_message_ring_elems,
            12
        );
        assert_eq!(
            manifest.exact_live_tx_leaf_commitment.live_problem_l2_bound,
            6_492
        );
        assert!(manifest
            .theorem_documents
            .contains(&"docs/crypto/native_backend_formal_theorems.md".to_owned()));
        assert!(manifest
            .theorem_documents
            .contains(&"docs/crypto/native_backend_verified_aggregation.md".to_owned()));
    }

    #[test]
    fn fold_to_root_handles_odd_leaf_count() {
        let backend = LatticeBackend::default();
        let relation = ToyBalanceRelation::default();
        let security = backend.security_params();
        let (pk, vk) = backend.setup(&security, relation.shape()).unwrap();
        let relation_id = relation.relation_id();

        let leaves = vec![
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"a"),
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![1u64; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
            },
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"b"),
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![2u64; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
            },
            FoldedInstance {
                relation_id,
                shape_digest: pk.shape_digest,
                statement_digest: digest_statement(b"c"),
                witness_commitment: LatticeCommitment::from_rows(vec![
                    RingElem::from_coeffs(
                        vec![3u64; pk.ring_degree]
                    );
                    pk.commitment_rows
                ]),
            },
        ];

        let (root, steps, _) = fold_to_root(&backend, &pk, leaves).unwrap();
        assert_eq!(steps.len(), 2);
        for step in &steps {
            backend
                .verify_fold(&vk, &step.parent, &step.left, &step.right, &step.proof)
                .unwrap();
        }
        assert_eq!(root.shape_digest, pk.shape_digest);
    }

    #[test]
    fn review_vectors_agree_between_production_and_reference_verifiers() {
        let dir = std::env::temp_dir().join(format!(
            "hegemon-native-backend-vectors-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let _ = fs::remove_dir_all(&dir);
        emit_review_vectors(&dir).expect("emit review vectors");
        let (summary, reference_results) =
            verify_bundle_dir(&dir).expect("reference verifier should run");
        assert_eq!(
            summary.failed_cases, 0,
            "reference verifier failures: {:?}",
            reference_results
        );
        let bundle: ReviewVectorBundle =
            serde_json::from_slice(&fs::read(dir.join("bundle.json")).expect("read bundle"))
                .expect("parse local review bundle");
        for case in &bundle.cases {
            let production_result = verify_production_review_case(case);
            if case.expected_valid {
                production_result.as_ref().unwrap_or_else(|err| {
                    panic!("production verifier rejected {}: {err}", case.name)
                });
            } else {
                let expected = case
                    .expected_error_substring
                    .as_deref()
                    .expect("invalid case should declare expected substring");
                let production_err =
                    production_result.expect_err("production verifier should reject");
                assert!(
                    production_err.to_string().contains(expected),
                    "production verifier error mismatch for {}: {}",
                    case.name,
                    production_err
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    fn verify_production_review_case(case: &ReviewVectorCase) -> Result<()> {
        let artifact_bytes =
            hex::decode(&case.artifact_hex).context("case artifact_hex must be valid hex")?;
        match case.kind.as_str() {
            "native_tx_leaf" => {
                let ctx = case
                    .tx_context
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("native_tx_leaf case missing tx_context"))?;
                let params = current_native_backend_params();
                let tx = tx_from_review(ctx)?;
                let receipt = CanonicalTxValidityReceipt {
                    statement_hash: decode_hex_array_for_test::<48>(
                        &ctx.receipt.statement_hash_hex,
                    )?,
                    proof_digest: decode_hex_array_for_test::<48>(&ctx.receipt.proof_digest_hex)?,
                    public_inputs_digest: decode_hex_array_for_test::<48>(
                        &ctx.receipt.public_inputs_digest_hex,
                    )?,
                    verifier_profile: decode_hex_array_for_test::<48>(
                        &ctx.receipt.verifier_profile_hex,
                    )?,
                };
                verify_native_tx_leaf_artifact_bytes_with_params(
                    &params,
                    &tx,
                    &receipt,
                    &artifact_bytes,
                )
                .map(|_| ())
            }
            "receipt_root" => {
                let ctx = case
                    .block_context
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("receipt_root case missing block_context"))?;
                let params = current_native_backend_params();
                let records = receipt_root_records_from_review(ctx)?;
                verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(
                    &params,
                    &records,
                    &artifact_bytes,
                )
                .map(|_| ())
            }
            other => Err(anyhow::anyhow!("unsupported review case kind {other}")),
        }
    }

    fn decode_hex_array_for_test<const N: usize>(value: &str) -> Result<[u8; N]> {
        let bytes = hex::decode(value)?;
        let len = bytes.len();
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("hex string has {} bytes, expected {}", len, N))
    }

    fn tx_from_review(ctx: &ReviewTxContext) -> Result<superneo_hegemon::TxLeafPublicTx> {
        Ok(superneo_hegemon::TxLeafPublicTx {
            nullifiers: ctx
                .tx
                .nullifiers_hex
                .iter()
                .map(|value| decode_hex_array_for_test::<48>(value))
                .collect::<Result<Vec<_>>>()?,
            commitments: ctx
                .tx
                .commitments_hex
                .iter()
                .map(|value| decode_hex_array_for_test::<48>(value))
                .collect::<Result<Vec<_>>>()?,
            ciphertext_hashes: ctx
                .tx
                .ciphertext_hashes_hex
                .iter()
                .map(|value| decode_hex_array_for_test::<48>(value))
                .collect::<Result<Vec<_>>>()?,
            balance_tag: decode_hex_array_for_test::<48>(&ctx.tx.balance_tag_hex)?,
            version: protocol_versioning::VersionBinding::new(
                ctx.tx.version_circuit,
                ctx.tx.version_crypto,
            ),
        })
    }

    fn receipt_root_records_from_review(
        ctx: &ReviewBlockContext,
    ) -> Result<Vec<superneo_hegemon::NativeTxLeafRecord>> {
        Ok(ctx
            .leaves
            .iter()
            .map(|leaf| superneo_hegemon::NativeTxLeafRecord {
                params_fingerprint: decode_hex_array_for_test::<48>(&ctx.params_fingerprint_hex)
                    .expect("params fingerprint"),
                spec_digest: decode_hex_array_for_test::<32>(&ctx.spec_digest_hex)
                    .expect("spec digest"),
                relation_id: decode_hex_array_for_test::<32>(&ctx.relation_id_hex)
                    .expect("relation id"),
                shape_digest: decode_hex_array_for_test::<32>(&ctx.shape_digest_hex)
                    .expect("shape digest"),
                statement_digest: decode_hex_array_for_test::<48>(&leaf.statement_digest_hex)
                    .expect("statement digest"),
                commitment: LatticeCommitment::from_rows(
                    leaf.commitment_rows
                        .iter()
                        .cloned()
                        .map(RingElem::from_coeffs)
                        .collect(),
                ),
                proof_digest: decode_hex_array_for_test::<48>(&leaf.proof_digest_hex)
                    .expect("proof digest"),
            })
            .collect())
    }
}
