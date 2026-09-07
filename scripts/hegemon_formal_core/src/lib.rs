use anyhow::{anyhow, ensure, Context, Result};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

const CLAIM_STATUSES: &[&str] = &[
    "enforced",
    "model_checked",
    "candidate_under_review",
    "disabled_fail_closed",
    "research_only",
];
const CLAIM_CLASSES: &[&str] = &[
    "binary_primitive_gate",
    "dependency_gate",
    "formal_model",
    "canonical_codec",
    "reference_vector",
    "proof_verifier_boundary",
    "fail_closed_runtime",
    "cryptographic_assumption",
    "lean_theorem",
];
const CONJECTURAL_MODELS: &[&str] = &["conjectural_research", "heuristic_only"];
const BLUEPRINT_NODE_KINDS: &[&str] = &["target_claim", "supporting_claim", "residual_risk"];
const BLUEPRINT_REVIEW_SOURCE_BYTE_EXCLUSIONS: &[&str] = &[
    "config/formal-security-blueprint.json",
    "audits/native-backend-128b/native-backend-128b-review-package.tar.gz",
    "audits/native-backend-128b/package.sha256",
];
const MAX_BLUEPRINT_REVIEW_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BLUEPRINT_REVIEW_EXPANDED_SOURCE_BYTES: u64 = 64 * 1024 * 1024;
const EXPECTED_V8_ATOMIC_RUNTIME_GATE_AST_BLAKE3: &str =
    "5420f41a3ec88b209e294193065ec23840e09bcfc57ec313996f1d12d066aaf2";
const V8_ATOMIC_MANIFEST_RUNTIME_FUNCTIONS: &[&str] = &[
    "evaluate_native_atomic_commit_manifest_admission",
    "expected_atomic_block_record_writes",
    "expected_atomic_height_index_writes",
    "expected_atomic_best_pointer_writes",
    "expected_atomic_canonical_index_cleared",
    "expected_atomic_pending_tree_cleared",
    "expected_atomic_pending_action_removals",
    "expected_atomic_pending_action_writes",
    "expected_atomic_commitment_writes",
    "expected_atomic_nullifier_writes",
    "expected_atomic_bridge_replay_writes",
    "expected_atomic_ciphertext_index_writes",
    "expected_atomic_ciphertext_archive_writes",
    "expected_atomic_staged_ciphertext_removals",
    "native_mined_block_commit_manifest",
];
const V8_ATOMIC_NODE_IMPL_RUNTIME_FUNCTIONS: &[&str] = &[
    "native_canonical_suffix_reorg_commit_manifest",
    "apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction",
];
const TARGET_REVIEW_STATUSES: &[&str] = &["needs_review", "blocked"];
const STABLE_GOAL_MEASUREMENT_STATUSES: &[&str] = &["paused", "blocked", "complete"];
const REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES: &[&str] = &[
    "da-retention",
    "storage-durability",
    "global-privacy-boundary",
    "release-infrastructure",
    "dependency-scanner-completeness",
    "performance-budget",
];
const MAX_SYSTEM_MODEL_GATE_FRESHNESS_SLA_HOURS: u64 = 168;
const REQUIRED_HIGHEST_STANDARD_PROPERTIES: &[(&str, u64)] = &[
    ("ledger.no-counterfeiting-supply-integrity", 9),
    ("ledger.no-double-spend-nullifier-uniqueness", 7),
    ("ledger.spend-authorization-no-theft", 7),
    ("ledger.commitment-tree-integrity", 6),
    ("ledger.per-asset-transaction-conservation", 7),
    ("ledger.asset-isolation-authorized-mint", 5),
    ("proof.statement-binding", 6),
    ("proof.proof-system-soundness-boundary", 10),
    ("privacy.zero-knowledge-unlinkability", 8),
    ("privacy.ciphertext-correctness-confidentiality", 5),
    ("codec.canonical-encoding-non-malleability", 5),
    ("node.replay-reorg-startup-refinement", 6),
    ("consensus.admission-safety", 4),
    ("availability.da-sidecar-binding", 4),
    ("bridge.mint-replay-safety", 4),
    ("network.pq-channel-safety", 3),
    ("resource.dos-bounds", 2),
    ("release.dependency-posture", 2),
];
const REQUIRED_MECHANIZED_ASSUMPTION_TRACKS: &[(&str, &[&str])] = &[
    (
        "transaction.smallwood-semantic-implication",
        &["Hegemon.Transaction.SmallWoodSemanticClosure.accepted_proof_and_semantic_constraints_imply_transaction_relation"],
    ),
    (
        "transaction.smallwood-profile-drift-binding",
        &["Hegemon.Transaction.SmallWoodTranscriptBinding.active_profile_binding_rejects_all_named_in_range_single_field_mutations"],
    ),
    (
        "transaction.recursive-admission-local-facts",
        &[
            "Hegemon.Transaction.SmallWoodNoCounterfeit.accepted_recursive_v2_artifact_still_requires_semantic_replay",
            "Hegemon.Transaction.TxValidityClaimMatching.claimMatchAccepts_implies_exact_surface",
            "Hegemon.Consensus.ProvenBatchBinding.accepts_iff_binding_preconditions",
        ],
    ),
    (
        "transaction.independent-cross-object-identity-refinement",
        &["Hegemon.Consensus.AcceptedSmallWoodBlockComposition.accepted_independent_cross_object_identity_refines_one_canonical_block"],
    ),
    (
        "consensus.accepted-chain-supply-composition",
        &[],
    ),
    (
        "native.raw-ingress-canonical-publication",
        &["Hegemon.Native.RawIngressFullBytePublicationSurface.accepted_raw_ingress_full_byte_publication_surface_binds_production_projection_rows"],
    ),
    (
        "native.reorg-startup-row-equivalence",
        &["Hegemon.Native.NativePublicationRowEquivalence.accepted_native_publication_path_family_binds_native_publication_rows"],
    ),
    (
        "native.challenge-reduction-entropy-arithmetic",
        &[
            "Hegemon.Native.NativeBackendAlgebra.active_tuple_preimage_bound_is_243",
            "Hegemon.Native.NativeBackendAlgebra.active_tuple_probability_bound_supports_312_bits",
            "Hegemon.Native.NativeBackendAlgebra.active_tuple_probability_bound_does_not_support_313_bits",
            "Hegemon.Native.NativeBackendAlgebra.active_receipt_root_composition_loss_is_exact",
            "Hegemon.Native.NativeBackendAlgebra.active_composed_probability_bound_supports_305_bits",
            "Hegemon.Native.NativeBackendAlgebra.active_composed_probability_bound_does_not_support_306_bits",
            "Hegemon.Native.NativeBackendAlgebra.reduced_active_fold_challenge_positive",
            "Hegemon.Native.NativeBackendAlgebra.reduced_active_fold_challenge_at_most_value_count",
            "Hegemon.Native.NativeBackendAlgebra.active_reducer_preimage_quotient_at_most_two",
            "Hegemon.Native.NativeBackendAlgebra.active_reducer_preimage_has_one_of_three_representatives",
            "Hegemon.Native.NativeBackendAlgebra.active_challenge_polynomial_is_nonzero",
        ],
    ),
    (
        "native.fold-output-equality-model",
        &["Hegemon.Native.NativeBackendAlgebra.fold_output_matches_recomputed_iff_equality"],
    ),
    ("native.fold-verifier-implementation-equivalence", &[]),
    (
        "native.digit-bound-euclidean-arithmetic",
        &[
            "Hegemon.Native.NativeBackendAlgebra.active_ambient_coefficient_dimension_is_4104",
            "Hegemon.Native.NativeBackendAlgebra.active_conservative_euclidean_bound_is_sound",
            "Hegemon.Native.NativeBackendAlgebra.active_live_coefficient_dimension_is_648",
            "Hegemon.Native.NativeBackendAlgebra.active_live_euclidean_bound_is_sound",
            "Hegemon.Native.NativeBackendAlgebra.bounded_digits_have_bounded_centered_difference",
        ],
    ),
    (
        "proof.statement-wrapper-binding",
        &["Hegemon.Transaction.ProofWrapperAdmission.proofWrapperAccepts_implies_no_metadata_projection_or_row_extension"],
    ),
    (
        "transaction.accepted-proof-exact-constraint-extraction",
        &[],
    ),
    (
        "transaction.smallwood-air-row-implementation-equivalence",
        &[],
    ),
    ("native.complete-parser-node-refinement", &[]),
    ("native.low-degree-unit-irreducibility", &[]),
    ("native.backend-collision-reduction-and-pok", &[]),
    ("privacy.zero-knowledge-unlinkability-game", &[]),
    ("bridge.external-receipt-soundness", &[]),
    ("system.da-storage-runtime-semantics", &[]),
];
const EXPECTED_MECHANIZED_ASSUMPTION_PROPOSITION_BLAKE3: &str =
    "51512c473f20c40c3a88b9f2a1ba0d2e81b9a25a6591c025967b306121801657";
const EXPECTED_FORMAL_SOURCE_TREE_BLAKE3: &str =
    "11b7a884cc7e16156192a9d4846c266cf060b29c2928b74c86445270a9043616";
const PROGRESS_PERCENT_EPSILON: f64 = 0.0001;
const CLAIMS_SCHEMA_VERSION: u32 = 2;
const BLUEPRINT_SCHEMA_VERSION: u32 = 2;
const ACTIVE_GOAL_SCHEMA_VERSION: u32 = 2;
const CLAIM_BASELINE_ID: &str = "hegemon-formal-security-claims-2026-08-17-v1";
const EXPECTED_CLAIM_BASELINE_BLAKE3: &str =
    "c27b47f4d9e82a86ad82b1a0b0d116586a35b7af47ea5755d98fd9e440d4841d";
const CONDITIONAL_SMALLWOOD_CLAIM_ID: &str =
    "formal.deployed-smallwood-no-counterfeit-critical-path";
const REQUIRED_GOVERNANCE_GATE_ID: &str = "formal-governance-focused-tests";
const REQUIRED_GOVERNANCE_GATE_COMMAND: &str =
    "cargo test --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml governance_";
const REQUIRED_GOVERNANCE_TEST_COUNT: u64 = 14;
const GOVERNANCE_POLICY_INPUT_PATHS: &[&str] = &[
    "scripts/hegemon_formal_core/Cargo.toml",
    "scripts/hegemon_formal_core/Cargo.lock",
    "scripts/hegemon_formal_core/src/lib.rs",
    "scripts/hegemon_formal_core/src/main.rs",
    "scripts/check_formal_core.sh",
    "scripts/test_formal_gate_cli_args.sh",
    "protocol/kernel/src/manifest.rs",
    "protocol/versioning/src/lib.rs",
    "formal/lean/Hegemon/Native/AtomicCommitManifestAdmission.lean",
    "formal/lean/Hegemon/Native/GenerateAtomicCommitManifestAdmissionVectors.lean",
    "node/src/native/mod.rs",
    "node/src/native/block_flow.rs",
    "node/src/native/node_impl.rs",
    "node/src/native/poseidon2_v8_state.rs",
];
const MAX_GOVERNANCE_POLICY_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const CONDITIONAL_SMALLWOOD_ASSUMPTIONS: &[&str] = &[
    "Hegemon.Consensus.AcceptedSmallWoodBlockComposition.DeployedSmallWoodBlockKnowledgeSoundnessEvidence",
    "Hegemon.Transaction.SmallWoodProductionConstraintRefinement.DeployedSmallWoodKnowledgeSoundnessEvidence",
    "Hegemon.Consensus.AcceptedSmallWoodBlockComposition.DeployedSmallWoodBlockCanonicalSemanticRefinementEvidence",
    "Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionSmallWoodCanonicalSemanticRefinementAssumption",
    "Hegemon.Consensus.AcceptedSmallWoodBlockComposition.DeployedSmallWoodBlockPoseidon2OutputSecurityAssumptions",
    "Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionPoseidon2OutputSecurityAssumptions",
    "Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionPoseidon2ConstraintDigestRefinementAssumption",
    "Hegemon.Transaction.SmallWoodProductionConstraintRefinement.ProductionPoseidon2AcceptedOutputNoCollisionAssumption",
];

#[derive(Debug, Serialize)]
pub struct ClaimsReport {
    pub claims: usize,
    pub tombstones: usize,
    pub lean_theorem_claims: usize,
    pub named_lean_theorems: usize,
    pub production_eligible: usize,
    pub residual_risks: usize,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct BridgeVectorReport {
    pub cases: usize,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct InventoryReport {
    pub required_files: Vec<String>,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct SystemModelGateReport {
    pub gates: usize,
    pub required_categories: Vec<String>,
    pub evidence_paths: usize,
    pub max_freshness_sla_hours: u64,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct ActiveGoalProgressReport {
    pub goal_thread_id: String,
    pub branch: String,
    pub goal_status_when_measured: String,
    pub matrix_properties: usize,
    pub completed_properties: usize,
    pub total_weight: u64,
    pub weighted_completion_percent: f64,
    pub overall_completion_percent: f64,
    pub formal_surface_coverage_percent: f64,
    pub mechanized_assumption_tracks: usize,
    pub closed_mechanized_assumption_tracks: usize,
    pub mechanized_assumption_closure_percent: f64,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct BlueprintReport {
    pub nodes: usize,
    pub edges: usize,
    pub production_nodes: usize,
    pub implementation_bindings: usize,
    pub implementation_result_obligations: usize,
    pub implementation_order_constraints: usize,
    pub implementation_order_edges: usize,
    pub implementation_theorem_indexed_order_constraints: usize,
    pub implementation_theorem_indexed_order_edges: usize,
    pub full_claim_order_constraints: usize,
    pub full_claim_order_constraint_theorem_refs: usize,
    pub implementation_dominance_constraints: usize,
    pub implementation_dominance_edges: usize,
    pub implementation_theorem_indexed_dominance_constraints: usize,
    pub implementation_theorem_indexed_dominance_edges: usize,
    pub falsification_cases: usize,
    pub pending_external_review_nodes: usize,
    pub passed: bool,
}

#[derive(Debug, Clone)]
struct ClaimProjection {
    production_eligible: bool,
    evidence_paths: BTreeSet<String>,
    lean_theorems: BTreeSet<String>,
    authority: Option<ClaimAuthority>,
}

#[derive(Debug)]
struct ClaimIndex {
    generated_for_branch: String,
    claims: BTreeMap<String, ClaimProjection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimsLedger {
    schema_version: u32,
    generated_for_branch: String,
    claim_baseline: ClaimBaseline,
    governance_gate_evidence: Vec<ExecutedGateEvidence>,
    claims: Vec<SecurityClaim>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBaseline {
    baseline_id: String,
    baseline_claim_count: usize,
    baseline_claim_ids_blake3: String,
    tombstones: Vec<ClaimTombstone>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimTombstone {
    claim_id: String,
    retired_at: String,
    reason: String,
    approved_by: String,
    approval_reference: String,
    #[serde(default)]
    replacement_claim_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClaimAuthority {
    kind: String,
    production_authorized: bool,
    shipped_rust_verifier_refinement_proved: bool,
    qrom_failure_bound_composed: bool,
    deployed_hash_instantiation_loss_bounded: bool,
    concrete_pq_security_bits: Option<u16>,
    required_assumptions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutedGateEvidence {
    id: String,
    evidence_kind: String,
    command: String,
    status: String,
    exit_code: i32,
    executed_at: String,
    policy_inputs_blake3: String,
    report: serde_json::Value,
    report_blake3: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityClaim {
    id: String,
    component: String,
    claim_class: String,
    summary: String,
    status: String,
    proof_model: String,
    production_eligible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<ClaimAuthority>,
    #[serde(default)]
    lean_theorems: Vec<String>,
    assumptions: Vec<String>,
    evidence_paths: Vec<String>,
    gates: Vec<String>,
    residual_risks: Vec<ResidualRisk>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidualRisk {
    id: String,
    description: String,
    status: String,
    tracking: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormalBlueprint {
    schema_version: u32,
    generated_for_branch: String,
    methodology: BlueprintMethodology,
    #[serde(default)]
    policy: BlueprintPolicy,
    governance_gate_evidence: Vec<ExecutedGateEvidence>,
    nodes: Vec<BlueprintNode>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlueprintPolicy {
    #[serde(default)]
    require_theorem_indexed_order_constraints: bool,
    #[serde(default)]
    max_full_claim_order_constraints: Option<usize>,
    #[serde(default)]
    max_full_claim_order_constraint_theorem_refs: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlueprintMethodology {
    name: String,
    summary: String,
    source_of_record: String,
    gate: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlueprintNode {
    id: String,
    claim_id: String,
    kind: String,
    formal_statement: String,
    informal_argument: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<ClaimAuthority>,
    depends_on: Vec<String>,
    implementation_paths: Vec<String>,
    #[serde(default)]
    implementation_bindings: Vec<ImplementationBinding>,
    evidence_paths: Vec<String>,
    target_review: TargetReview,
    falsification_cases: Vec<FalsificationCase>,
    scope_boundary: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImplementationBinding {
    path: String,
    callee: String,
    required_callers: Vec<String>,
    #[serde(default)]
    result_obligation: Option<String>,
    #[serde(default)]
    call_order_constraints: Vec<ImplementationCallOrderConstraint>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImplementationCallOrderConstraint {
    caller: String,
    callee_must_precede: Vec<String>,
    #[serde(default)]
    result_obligation: Option<String>,
    #[serde(default)]
    must_dominate_successors: bool,
    #[serde(default)]
    lean_theorems: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetReview {
    status: String,
    reviewer: String,
    reviewed_at: String,
    notes: String,
    #[serde(default)]
    content_blake3: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FalsificationCase {
    id: String,
    description: String,
    gate: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeVectorFile {
    schema_version: u32,
    cases: Vec<BridgeVectorCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeVectorCase {
    name: String,
    source_chain_id: String,
    destination_chain_id: String,
    app_family_id: u16,
    message_nonce: String,
    source_height: u64,
    payload_hex: String,
    expected_payload_hash: String,
    expected_message_hash: String,
    expected_message_root: String,
    expected_replay_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemModelGateLedger {
    schema_version: u32,
    generated_for_branch: String,
    gates: Vec<SystemModelGate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemModelGate {
    id: String,
    category: String,
    assumption_class: String,
    fail_closed: bool,
    release_blocking: bool,
    monitor: String,
    enforcement_gate: String,
    freshness_sla_hours: u64,
    alert_route: String,
    evidence_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGoalProgressLedger {
    schema_version: u32,
    generated_for_branch: String,
    goal_thread_id: String,
    goal_status_when_measured: String,
    measurement_timestamp: String,
    formal_source_tree_blake3: String,
    objective: String,
    objective_must_contain: Vec<String>,
    source_matrix_path: String,
    measurement_method: String,
    overall_completion_percent: f64,
    weighted_completion_percent: f64,
    total_property_count: usize,
    completed_property_count: usize,
    total_weight: u64,
    external_assumption_boundary: String,
    claim_authority: ActiveGoalClaimAuthority,
    acceptance_gates: Vec<ExecutedGateEvidence>,
    evidence_paths: Vec<String>,
    required_properties: Vec<ActiveGoalRequiredProperty>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGoalClaimAuthority {
    claim_id: String,
    authority: ClaimAuthority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGoalRequiredProperty {
    id: String,
    weight: u64,
    target_completion_percent: f64,
}

#[derive(Debug, Deserialize)]
struct HighestStandardMatrix {
    schema_version: u32,
    branch: String,
    goal: String,
    completion_method: String,
    overall_completion_percent: f64,
    formal_surface_coverage_percent: f64,
    mechanized_assumption_closure: MechanizedAssumptionClosure,
    properties: Vec<HighestStandardMatrixProperty>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MechanizedAssumptionClosure {
    measurement_method: String,
    total_tracks: usize,
    closed_tracks: usize,
    closure_percent: f64,
    tracks: Vec<MechanizedAssumptionTrack>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MechanizedAssumptionTrack {
    id: String,
    status: String,
    evidence_paths: Vec<String>,
    #[serde(default)]
    lean_theorems: Vec<String>,
    remaining_work: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HighestStandardMatrixProperty {
    id: String,
    weight: u64,
    completion_percent: f64,
    #[serde(default)]
    current_evidence: Vec<String>,
    #[serde(default)]
    missing_work: Vec<String>,
    #[serde(default)]
    remaining_work: Vec<String>,
    #[serde(default)]
    explicit_external_assumptions: Vec<String>,
}

pub fn check_claims_file(path: &Path) -> Result<ClaimsReport> {
    let root = repository_root_from(path);
    let ledger = read_claims_ledger(path)?;
    validate_claims_ledger(&root, path, &ledger)
}

pub fn check_blueprint_file(path: &Path, claims_path: &Path) -> Result<BlueprintReport> {
    let root = repository_root_from(path);
    let claim_index = validate_claims_for_blueprint(&root, claims_path)?;
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let blueprint: FormalBlueprint =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    validate_blueprint(&root, path, &blueprint, &claim_index)
}

pub fn blueprint_review_digests_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let root = repository_root_from(path);
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let blueprint: FormalBlueprint =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    blueprint
        .nodes
        .iter()
        .map(|node| Ok((node.id.clone(), blueprint_node_content_blake3(&root, node)?)))
        .collect()
}

pub fn governance_policy_inputs_digest_file(path: &Path) -> Result<String> {
    let root = repository_root_from(path);
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let policy: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    let evidence_field = if policy.get("governance_gate_evidence").is_some() {
        "governance_gate_evidence"
    } else if policy.get("acceptance_gates").is_some() {
        "acceptance_gates"
    } else {
        return Err(anyhow!(
            "governance policy {} has neither governance_gate_evidence nor acceptance_gates",
            path.display()
        ));
    };
    governance_policy_inputs_blake3(&root, path, evidence_field)
}

fn read_claims_ledger(path: &Path) -> Result<ClaimsLedger> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn claim_id_set_blake3<'a>(ids: impl IntoIterator<Item = &'a str>) -> String {
    let mut ids = ids.into_iter().collect::<Vec<_>>();
    ids.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.formal-security-claim-baseline.v1\0");
    for id in ids {
        hasher.update(&(id.len() as u64).to_le_bytes());
        hasher.update(id.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn expected_claim_baseline_blake3(baseline: &ClaimBaseline) -> Result<&str> {
    if baseline.baseline_id == CLAIM_BASELINE_ID {
        return Ok(EXPECTED_CLAIM_BASELINE_BLAKE3);
    }
    #[cfg(test)]
    if baseline.baseline_id.starts_with("test-") {
        return Ok(&baseline.baseline_claim_ids_blake3);
    }
    Err(anyhow!(
        "unknown claim baseline id {}; update the independent Rust baseline policy before replacing it",
        baseline.baseline_id
    ))
}

fn validate_claim_baseline(baseline: &ClaimBaseline, active_ids: &BTreeSet<String>) -> Result<()> {
    let expected_digest = expected_claim_baseline_blake3(baseline)?;
    ensure!(
        baseline.baseline_claim_ids_blake3 == expected_digest,
        "claim baseline digest changed across the independent Rust policy boundary: expected {}, got {}",
        expected_digest,
        baseline.baseline_claim_ids_blake3
    );
    ensure!(
        baseline.baseline_claim_count > 0,
        "claim baseline count must be positive"
    );

    let mut tombstone_ids = BTreeSet::new();
    for tombstone in &baseline.tombstones {
        validate_id("claim tombstone id", &tombstone.claim_id)?;
        ensure!(
            tombstone_ids.insert(tombstone.claim_id.clone()),
            "duplicate claim tombstone {}",
            tombstone.claim_id
        );
        ensure!(
            !active_ids.contains(&tombstone.claim_id),
            "claim {} cannot be both active and tombstoned",
            tombstone.claim_id
        );
        ensure!(
            tombstone.retired_at.len() == 10
                && tombstone.retired_at.as_bytes().get(4) == Some(&b'-')
                && tombstone.retired_at.as_bytes().get(7) == Some(&b'-'),
            "claim tombstone {} retired_at must be YYYY-MM-DD",
            tombstone.claim_id
        );
        for (label, value) in [
            ("reason", tombstone.reason.as_str()),
            ("approved_by", tombstone.approved_by.as_str()),
            ("approval_reference", tombstone.approval_reference.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "claim tombstone {} {} must be nonempty",
                tombstone.claim_id,
                label
            );
        }
        if let Some(replacement) = &tombstone.replacement_claim_id {
            validate_id("claim tombstone replacement id", replacement)?;
            ensure!(
                replacement != &tombstone.claim_id && active_ids.contains(replacement),
                "claim tombstone {} replacement {} must name a different active claim",
                tombstone.claim_id,
                replacement
            );
        }
    }

    let baseline_ids = active_ids
        .iter()
        .map(String::as_str)
        .chain(tombstone_ids.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    ensure!(
        baseline_ids.len() == baseline.baseline_claim_count,
        "active claims plus tombstones total {}, expected pinned baseline count {}; deleted claims require explicit tombstones",
        baseline_ids.len(),
        baseline.baseline_claim_count
    );
    let actual_digest = claim_id_set_blake3(baseline_ids.iter().copied());
    ensure!(
        actual_digest == baseline.baseline_claim_ids_blake3,
        "active claims plus tombstones do not match the pinned claim baseline: expected {}, got {}; deleted claims require explicit tombstones",
        baseline.baseline_claim_ids_blake3,
        actual_digest
    );
    Ok(())
}

fn validate_pinned_conditional_claim_presence(
    baseline_id: &str,
    active_ids: &BTreeSet<String>,
) -> Result<()> {
    if baseline_id == CLAIM_BASELINE_ID {
        ensure!(
            active_ids.contains(CONDITIONAL_SMALLWOOD_CLAIM_ID),
            "required conditional claim {} must remain active and cannot be tombstoned",
            CONDITIONAL_SMALLWOOD_CLAIM_ID
        );
    }
    Ok(())
}

fn executed_gate_report_blake3(report: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(report).context("serialize executed gate report")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.executed-gate-report.v1\0");
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn update_domain_separated_bytes(hasher: &mut blake3::Hasher, label: &str, bytes: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn governance_policy_relative_path(root: &Path, policy_path: &Path) -> Result<String> {
    let root_path = if root.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root
    };
    let root = root_path
        .canonicalize()
        .context("canonicalize governance policy repository root")?;
    let candidate = if policy_path.is_absolute() {
        policy_path.to_path_buf()
    } else {
        root.join(policy_path)
    };
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("inspect governance policy input {}", candidate.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "governance policy input must be a non-symlink regular file: {}",
        candidate.display()
    );
    let canonical = candidate.canonicalize().with_context(|| {
        format!(
            "canonicalize governance policy input {}",
            candidate.display()
        )
    })?;
    let relative = canonical.strip_prefix(&root).with_context(|| {
        format!(
            "governance policy input resolves outside repository: {}",
            candidate.display()
        )
    })?;
    relative.to_str().map(str::to_owned).ok_or_else(|| {
        anyhow!(
            "governance policy input path is not UTF-8: {}",
            relative.display()
        )
    })
}

fn governance_policy_inputs_blake3_for_value(
    root: &Path,
    policy_relative_path: &str,
    evidence_field: &str,
    policy: &serde_json::Value,
) -> Result<String> {
    let mut policy = policy.clone();
    let object = policy
        .as_object_mut()
        .ok_or_else(|| anyhow!("governance policy input must be a JSON object"))?;
    ensure!(
        object.remove(evidence_field).is_some(),
        "governance policy input is missing self-referential evidence field {}",
        evidence_field
    );
    let policy_bytes = serde_json::to_vec(&policy).context("serialize governance policy input")?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.governance-policy-inputs.v1\0");
    for input_path in GOVERNANCE_POLICY_INPUT_PATHS {
        let bytes = read_repo_relative_regular_file_bounded(
            root,
            input_path,
            "governance checker policy input",
            MAX_GOVERNANCE_POLICY_INPUT_BYTES,
        )?;
        update_domain_separated_bytes(&mut hasher, input_path, &bytes);
    }
    if evidence_field == "acceptance_gates" {
        for (input_path, excluded_field) in [
            (
                "config/formal-security-claims.json",
                Some("governance_gate_evidence"),
            ),
            (
                "config/highest-standard-formal-verification-matrix.json",
                None,
            ),
        ] {
            let bytes = read_repo_relative_regular_file_bounded(
                root,
                input_path,
                "active-goal governance policy input",
                MAX_GOVERNANCE_POLICY_INPUT_BYTES,
            )?;
            let mut input: serde_json::Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse active-goal governance input {input_path}"))?;
            if let Some(excluded_field) = excluded_field {
                let object = input.as_object_mut().ok_or_else(|| {
                    anyhow!("active-goal governance input {input_path} must be a JSON object")
                })?;
                ensure!(
                    object.remove(excluded_field).is_some(),
                    "active-goal governance input {} is missing excluded evidence field {}",
                    input_path,
                    excluded_field
                );
            }
            let canonical = serde_json::to_vec(&input)
                .with_context(|| format!("serialize active-goal governance input {input_path}"))?;
            update_domain_separated_bytes(&mut hasher, input_path, &canonical);
        }
    }
    update_domain_separated_bytes(
        &mut hasher,
        &format!("{policy_relative_path}#{evidence_field}"),
        &policy_bytes,
    );
    Ok(hasher.finalize().to_hex().to_string())
}

fn governance_policy_inputs_blake3(
    root: &Path,
    policy_path: &Path,
    evidence_field: &str,
) -> Result<String> {
    let policy_relative_path = governance_policy_relative_path(root, policy_path)?;
    let raw = fs::read_to_string(policy_path)
        .with_context(|| format!("read governance policy input {}", policy_path.display()))?;
    let policy: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse governance policy input {}", policy_path.display()))?;
    governance_policy_inputs_blake3_for_value(root, &policy_relative_path, evidence_field, &policy)
}

fn validate_governance_gate_evidence(
    context: &str,
    root: &Path,
    policy_path: &Path,
    evidence_field: &str,
    evidence: &[ExecutedGateEvidence],
) -> Result<()> {
    ensure!(
        !evidence.is_empty(),
        "{} must contain machine-readable executed gate evidence",
        context
    );
    let mut ids = BTreeSet::new();
    for gate in evidence {
        validate_id(&format!("{} gate evidence id", context), &gate.id)?;
        ensure!(
            ids.insert(gate.id.as_str()),
            "{} repeats gate evidence id {}",
            context,
            gate.id
        );
        ensure!(
            gate.evidence_kind == "executed_command",
            "{} gate {} evidence_kind must be executed_command",
            context,
            gate.id
        );
        ensure!(
            gate.status == "passed" && gate.exit_code == 0,
            "{} gate {} must record passed status and exit_code 0",
            context,
            gate.id
        );
        ensure!(
            gate.executed_at.ends_with('Z') && gate.executed_at.contains('T'),
            "{} gate {} executed_at must be an ISO-8601 UTC timestamp",
            context,
            gate.id
        );
        ensure!(
            gate.policy_inputs_blake3.len() == 64
                && gate
                    .policy_inputs_blake3
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "{} gate {} policy_inputs_blake3 must be a lowercase 64-character BLAKE3 digest",
            context,
            gate.id
        );
        ensure!(
            gate.report
                .get("passed")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
            "{} gate {} report must contain passed=true",
            context,
            gate.id
        );
        let actual_report_blake3 = executed_gate_report_blake3(&gate.report)?;
        ensure!(
            gate.report_blake3 == actual_report_blake3,
            "{} gate {} report_blake3 mismatch: recorded {}, actual {}",
            context,
            gate.id,
            gate.report_blake3,
            actual_report_blake3
        );
    }
    let required = evidence
        .iter()
        .find(|gate| gate.id == REQUIRED_GOVERNANCE_GATE_ID)
        .ok_or_else(|| {
            anyhow!(
                "{} is missing required executed gate evidence {}",
                context,
                REQUIRED_GOVERNANCE_GATE_ID
            )
        })?;
    ensure!(
        required.command == REQUIRED_GOVERNANCE_GATE_COMMAND,
        "{} gate {} command must be {:?}",
        context,
        REQUIRED_GOVERNANCE_GATE_ID,
        REQUIRED_GOVERNANCE_GATE_COMMAND
    );
    ensure!(
        required
            .report
            .get("test_filter")
            .and_then(serde_json::Value::as_str)
            == Some("governance_")
            && required
                .report
                .get("tests_failed")
                .and_then(serde_json::Value::as_u64)
                == Some(0)
            && required
                .report
                .get("tests_passed")
                .and_then(serde_json::Value::as_u64)
                == Some(REQUIRED_GOVERNANCE_TEST_COUNT),
        "{} gate {} report must record test_filter=governance_, tests_failed=0, and tests_passed={}",
        context,
        REQUIRED_GOVERNANCE_GATE_ID,
        REQUIRED_GOVERNANCE_TEST_COUNT
    );
    let actual_policy_inputs_blake3 =
        governance_policy_inputs_blake3(root, policy_path, evidence_field)?;
    ensure!(
        required.policy_inputs_blake3 == actual_policy_inputs_blake3,
        "{} gate {} policy_inputs_blake3 mismatch: recorded {}, actual {}; rerun the gate after checker or policy changes",
        context,
        REQUIRED_GOVERNANCE_GATE_ID,
        required.policy_inputs_blake3,
        actual_policy_inputs_blake3
    );
    Ok(())
}

fn validate_claims_ledger(
    root: &Path,
    policy_path: &Path,
    ledger: &ClaimsLedger,
) -> Result<ClaimsReport> {
    ensure!(
        ledger.schema_version == CLAIMS_SCHEMA_VERSION,
        "unsupported claims schema version"
    );
    ensure!(
        !ledger.generated_for_branch.trim().is_empty(),
        "generated_for_branch must be set"
    );
    ensure!(!ledger.claims.is_empty(), "claims ledger must not be empty");
    validate_governance_gate_evidence(
        "formal security claims",
        root,
        policy_path,
        "governance_gate_evidence",
        &ledger.governance_gate_evidence,
    )?;

    let mut ids = BTreeSet::new();
    let mut lean_theorem_claims = 0usize;
    let mut named_lean_theorems = BTreeSet::new();
    let mut residual_risks = 0usize;
    let mut production_eligible = 0usize;
    for claim in &ledger.claims {
        let theorem_names = validate_claim(root, claim)?;
        ensure!(
            ids.insert(claim.id.clone()),
            "duplicate claim id {}",
            claim.id
        );
        if claim.claim_class == "lean_theorem" {
            lean_theorem_claims += 1;
        }
        named_lean_theorems.extend(theorem_names);
        residual_risks += claim.residual_risks.len();
        if claim.production_eligible {
            production_eligible += 1;
        }
    }
    validate_pinned_conditional_claim_presence(&ledger.claim_baseline.baseline_id, &ids)?;
    validate_claim_baseline(&ledger.claim_baseline, &ids)?;

    Ok(ClaimsReport {
        claims: ledger.claims.len(),
        tombstones: ledger.claim_baseline.tombstones.len(),
        lean_theorem_claims,
        named_lean_theorems: named_lean_theorems.len(),
        production_eligible,
        residual_risks,
        passed: true,
    })
}

fn validate_claims_for_blueprint(root: &Path, claims_path: &Path) -> Result<ClaimIndex> {
    let ledger = read_claims_ledger(claims_path)?;
    validate_claims_ledger(root, claims_path, &ledger)?;
    let generated_for_branch = ledger.generated_for_branch.clone();
    let mut claims = BTreeMap::new();
    for claim in ledger.claims {
        claims.insert(
            claim.id,
            ClaimProjection {
                production_eligible: claim.production_eligible,
                evidence_paths: claim.evidence_paths.into_iter().collect(),
                lean_theorems: claim.lean_theorems.into_iter().collect(),
                authority: claim.authority,
            },
        );
    }
    Ok(ClaimIndex {
        generated_for_branch,
        claims,
    })
}

pub fn verify_bridge_vectors_file(path: &Path) -> Result<BridgeVectorReport> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let vectors: BridgeVectorFile =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        vectors.schema_version == 1,
        "unsupported bridge vector schema"
    );
    ensure!(
        !vectors.cases.is_empty(),
        "bridge vector set must not be empty"
    );

    let mut names = BTreeSet::new();
    for case in &vectors.cases {
        ensure!(!case.name.trim().is_empty(), "bridge vector name is empty");
        ensure!(
            names.insert(&case.name),
            "duplicate bridge vector name {}",
            case.name
        );
        verify_bridge_case(case)?;
    }

    Ok(BridgeVectorReport {
        cases: vectors.cases.len(),
        passed: true,
    })
}

pub fn check_system_model_gates_file(path: &Path) -> Result<SystemModelGateReport> {
    let root = repository_root_from(path);
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let ledger: SystemModelGateLedger =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    validate_system_model_gates(&root, &ledger)
}

pub fn check_active_goal_progress_file(path: &Path) -> Result<ActiveGoalProgressReport> {
    verify_formal_source_tree_digest(path)?;
    verify_mechanized_assumption_proposition_digest(&repository_root_from(path))?;
    let report =
        check_active_goal_progress_file_with_policy(path, REQUIRED_MECHANIZED_ASSUMPTION_TRACKS)?;
    verify_mechanized_assumption_theorems_with_lean(&repository_root_from(path))?;
    Ok(report)
}

fn collect_lean_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("read Lean source directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("enumerate Lean source directory {}", directory.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("read file type for {}", path.display()))?;
        if file_type.is_symlink() {
            return Err(anyhow!(
                "formal Lean source tree contains symlink: {}",
                path.display()
            ));
        } else if file_type.is_dir() {
            collect_lean_files(&path, files)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "lean") {
            files.push(path);
        } else if !file_type.is_file() {
            return Err(anyhow!(
                "formal Lean source tree contains special filesystem entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn formal_source_tree_blake3(root: &Path) -> Result<String> {
    let formal_root = root.join("formal/lean");
    let mut files = Vec::new();
    collect_lean_files(&formal_root, &mut files)?;
    ensure!(
        !files.is_empty(),
        "formal Lean source tree must not be empty"
    );

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.formal-lean-source-tree.v1\0");
    for path in files {
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("relativize Lean source {}", path.display()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| anyhow!("Lean source path is not UTF-8: {}", path.display()))?;
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn required_mechanized_assumption_theorems() -> Result<Vec<&'static str>> {
    let mut names = BTreeSet::new();
    let mut listed = 0usize;
    for (_, track_theorems) in REQUIRED_MECHANIZED_ASSUMPTION_TRACKS {
        for theorem in *track_theorems {
            listed += 1;
            ensure!(
                names.insert(*theorem),
                "independent mechanized-assumption policy repeats theorem {}",
                theorem
            );
        }
    }
    ensure!(
        names.len() == listed && !names.is_empty(),
        "independent mechanized-assumption proposition policy must be nonempty and duplicate-free"
    );
    Ok(names.into_iter().collect())
}

pub fn mechanized_assumption_proposition_blake3(root: &Path) -> Result<String> {
    let names = required_mechanized_assumption_theorems()?;
    let mut query = String::from("import Hegemon\nset_option pp.all true\n");
    for theorem in &names {
        query.push_str("#check @");
        query.push_str(theorem);
        query.push('\n');
    }

    let lean_root = root.join("formal/lean");
    let build = Command::new("lake")
        .args(["build", "Hegemon"])
        .current_dir(&lean_root)
        .output()
        .with_context(|| {
            format!(
                "build the pinned Lean library before proposition query from {}",
                lean_root.display()
            )
        })?;
    ensure!(
        build.status.success(),
        "pinned Lean library build failed before proposition query (status {}):\nstdout:\n{}\nstderr:\n{}",
        build.status,
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let mut child = Command::new("lake")
        .args(["env", "lean", "--stdin"])
        .current_dir(&lean_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "start aggregate Lean proposition query from {}",
                lean_root.display()
            )
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("aggregate Lean proposition query stdin was not piped"))?
        .write_all(query.as_bytes())
        .context("write aggregate Lean proposition query")?;
    let output = child
        .wait_with_output()
        .context("wait for aggregate Lean proposition query")?;
    ensure!(
        output.status.success(),
        "aggregate Lean proposition query failed (status {}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let proposition_report = String::from_utf8(output.stdout)
        .context("aggregate Lean proposition query emitted non-UTF-8 output")?
        .replace("\r\n", "\n");
    ensure!(
        !proposition_report.trim().is_empty(),
        "aggregate Lean proposition query emitted no theorem types"
    );
    let toolchain = fs::read(lean_root.join("lean-toolchain"))
        .context("read pinned Lean toolchain for proposition policy")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.mechanized-assumption-propositions.v1\0");
    for bytes in [
        toolchain.as_slice(),
        query.as_bytes(),
        proposition_report.as_bytes(),
    ] {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn verify_mechanized_assumption_proposition_digest(root: &Path) -> Result<()> {
    let actual = mechanized_assumption_proposition_blake3(root)?;
    ensure!(
        actual == EXPECTED_MECHANIZED_ASSUMPTION_PROPOSITION_BLAKE3,
        "elaborated closed-track theorem propositions changed: expected {}, got {}; review the exact proposition diff before updating the independent Rust policy",
        EXPECTED_MECHANIZED_ASSUMPTION_PROPOSITION_BLAKE3,
        actual
    );
    Ok(())
}

fn verify_formal_source_tree_digest(path: &Path) -> Result<()> {
    let root = repository_root_from(path);
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let ledger: ActiveGoalProgressLedger =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        ledger.formal_source_tree_blake3.len() == 64
            && ledger
                .formal_source_tree_blake3
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "formal_source_tree_blake3 must be a lowercase 64-character BLAKE3 digest"
    );
    let actual = formal_source_tree_blake3(&root)?;
    ensure!(
        ledger.formal_source_tree_blake3 == actual,
        "formal Lean source tree changed without renewing the active-goal digest: recorded {}, current {}",
        ledger.formal_source_tree_blake3,
        actual
    );
    ensure!(
        actual == EXPECTED_FORMAL_SOURCE_TREE_BLAKE3,
        "formal Lean source tree changed across the independent Rust policy boundary: expected {}, got {}; review all model and theorem-body changes before updating the Rust-held digest",
        EXPECTED_FORMAL_SOURCE_TREE_BLAKE3,
        actual
    );
    Ok(())
}

fn check_active_goal_progress_file_with_policy(
    path: &Path,
    required_tracks: &[(&str, &[&str])],
) -> Result<ActiveGoalProgressReport> {
    let root = repository_root_from(path);
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let ledger: ActiveGoalProgressLedger =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    let claims_path = root.join("config/formal-security-claims.json");
    let claims = read_claims_ledger(&claims_path)?;
    validate_active_goal_progress(&root, path, &claims_path, &ledger, &claims, required_tracks)
}

fn verify_mechanized_assumption_theorems_with_lean(root: &Path) -> Result<()> {
    let script = root.join("scripts/check_lean_claim_axioms.py");
    let claims = root.join("config/formal-security-claims.json");
    let matrix = root.join("config/highest-standard-formal-verification-matrix.json");
    let waivers = root.join("config/lean-axiom-waivers.json");
    let output = Command::new("python3")
        .arg(&script)
        .arg("--claims")
        .arg(&claims)
        .arg("--matrix")
        .arg(&matrix)
        .arg("--waivers")
        .arg(&waivers)
        .current_dir(root)
        .output()
        .with_context(|| format!("run aggregate Lean closure audit via {}", script.display()))?;
    ensure!(
        output.status.success(),
        "aggregate Lean closure audit rejected mechanized assumption evidence (status {}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn validate_system_model_gates(
    root: &Path,
    ledger: &SystemModelGateLedger,
) -> Result<SystemModelGateReport> {
    ensure!(
        ledger.schema_version == 1,
        "unsupported system-model gate schema version"
    );
    ensure!(
        !ledger.generated_for_branch.trim().is_empty(),
        "generated_for_branch must be set"
    );
    ensure!(
        !ledger.gates.is_empty(),
        "system-model gate ledger must not be empty"
    );

    let required: BTreeSet<&str> = REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES
        .iter()
        .copied()
        .collect();
    let mut seen_ids = BTreeSet::new();
    let mut seen_categories = BTreeSet::new();
    let mut evidence_paths = 0usize;
    let mut max_freshness_sla_hours = 0u64;

    for gate in &ledger.gates {
        validate_id("system-model gate id", &gate.id)?;
        ensure!(
            seen_ids.insert(&gate.id),
            "duplicate system-model gate id {}",
            gate.id
        );
        ensure!(
            required.contains(gate.category.as_str()),
            "{} has unknown system-model category {}",
            gate.id,
            gate.category
        );
        ensure!(
            seen_categories.insert(gate.category.as_str()),
            "duplicate system-model category {}",
            gate.category
        );
        ensure!(
            gate.assumption_class == "system_model",
            "{} must use assumption_class system_model",
            gate.id
        );
        ensure!(gate.fail_closed, "{} must fail closed", gate.id);
        ensure!(gate.release_blocking, "{} must block release", gate.id);
        ensure!(
            !gate.monitor.trim().is_empty(),
            "{} must name a monitor",
            gate.id
        );
        ensure!(
            !gate.enforcement_gate.trim().is_empty(),
            "{} must name an enforcement gate",
            gate.id
        );
        ensure!(
            !gate.alert_route.trim().is_empty(),
            "{} must name an alert route",
            gate.id
        );
        ensure!(
            gate.freshness_sla_hours > 0
                && gate.freshness_sla_hours <= MAX_SYSTEM_MODEL_GATE_FRESHNESS_SLA_HOURS,
            "{} freshness_sla_hours must be in 1..={}",
            gate.id,
            MAX_SYSTEM_MODEL_GATE_FRESHNESS_SLA_HOURS
        );
        ensure!(
            !gate.evidence_paths.is_empty(),
            "{} must list evidence paths",
            gate.id
        );
        for evidence in &gate.evidence_paths {
            ensure_repo_relative_existing(root, evidence, &format!("{} evidence path", gate.id))?;
            evidence_paths += 1;
        }
        max_freshness_sla_hours = max_freshness_sla_hours.max(gate.freshness_sla_hours);
    }

    let missing: Vec<_> = required
        .difference(&seen_categories)
        .copied()
        .map(str::to_owned)
        .collect();
    ensure!(
        missing.is_empty(),
        "missing required system-model categories: {missing:?}"
    );

    Ok(SystemModelGateReport {
        gates: ledger.gates.len(),
        required_categories: REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES
            .iter()
            .map(|category| (*category).to_owned())
            .collect(),
        evidence_paths,
        max_freshness_sla_hours,
        passed: true,
    })
}

fn validate_active_goal_progress(
    root: &Path,
    progress_path: &Path,
    claims_path: &Path,
    ledger: &ActiveGoalProgressLedger,
    claims: &ClaimsLedger,
    required_tracks: &[(&str, &[&str])],
) -> Result<ActiveGoalProgressReport> {
    ensure!(
        ledger.schema_version == ACTIVE_GOAL_SCHEMA_VERSION,
        "unsupported active-goal progress schema version"
    );
    ensure!(
        !ledger.generated_for_branch.trim().is_empty(),
        "generated_for_branch must be set"
    );
    ensure!(
        !ledger.goal_thread_id.trim().is_empty(),
        "goal_thread_id must be set"
    );
    ensure!(
        STABLE_GOAL_MEASUREMENT_STATUSES.contains(&ledger.goal_status_when_measured.as_str()),
        "active goal progress must be measured while the goal is paused, blocked, or complete"
    );
    ensure!(
        ledger.measurement_timestamp.ends_with('Z') && ledger.measurement_timestamp.contains('T'),
        "measurement_timestamp must be an ISO-8601 UTC timestamp"
    );
    ensure!(!ledger.objective.trim().is_empty(), "objective must be set");
    ensure!(
        !ledger.objective_must_contain.is_empty(),
        "objective_must_contain must not be empty"
    );
    for required in &ledger.objective_must_contain {
        ensure!(
            !required.trim().is_empty(),
            "objective_must_contain entries must be nonempty"
        );
        ensure!(
            ledger.objective.contains(required),
            "active goal objective does not contain required phrase {:?}",
            required
        );
    }
    ensure!(
        !ledger.measurement_method.trim().is_empty(),
        "measurement_method must be set"
    );
    ensure!(
        ledger.source_matrix_path == "config/highest-standard-formal-verification-matrix.json",
        "active-goal progress source_matrix_path must be config/highest-standard-formal-verification-matrix.json"
    );
    ensure!(
        ledger.external_assumption_boundary.contains("explicit")
            || ledger.external_assumption_boundary.contains("named"),
        "external_assumption_boundary must state the explicit/named assumption boundary"
    );
    ensure!(
        !ledger.acceptance_gates.is_empty(),
        "acceptance_gates must not be empty"
    );
    validate_governance_gate_evidence(
        "active-goal progress",
        root,
        progress_path,
        "acceptance_gates",
        &ledger.acceptance_gates,
    )?;
    ensure!(
        !ledger.evidence_paths.is_empty(),
        "evidence_paths must not be empty"
    );
    for evidence in &ledger.evidence_paths {
        ensure_repo_relative_existing(root, evidence, "active-goal progress evidence path")?;
    }
    ensure_repo_relative_existing(
        root,
        &ledger.source_matrix_path,
        "active-goal progress source matrix",
    )?;
    let matrix_path = root.join(&ledger.source_matrix_path);
    let matrix = read_highest_standard_matrix(&matrix_path)?;
    validate_claims_ledger(root, claims_path, claims)?;
    ensure!(
        ledger.claim_authority.claim_id == CONDITIONAL_SMALLWOOD_CLAIM_ID,
        "active-goal claim_authority must target the pinned conditional claim {}",
        CONDITIONAL_SMALLWOOD_CLAIM_ID
    );
    let authority_claim = claims
        .claims
        .iter()
        .find(|claim| claim.id == ledger.claim_authority.claim_id)
        .ok_or_else(|| {
            anyhow!(
                "active-goal claim_authority references missing claim {}",
                ledger.claim_authority.claim_id
            )
        })?;
    ensure!(
        authority_claim.authority.as_ref() == Some(&ledger.claim_authority.authority),
        "active-goal claim_authority must exactly match claims-ledger authority for {}",
        authority_claim.id
    );
    validate_progress_against_matrix(root, ledger, &matrix, claims, required_tracks)
}

fn read_highest_standard_matrix(path: &Path) -> Result<HighestStandardMatrix> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn validate_progress_against_matrix(
    root: &Path,
    ledger: &ActiveGoalProgressLedger,
    matrix: &HighestStandardMatrix,
    claims: &ClaimsLedger,
    required_tracks: &[(&str, &[&str])],
) -> Result<ActiveGoalProgressReport> {
    ensure!(
        matrix.schema_version == 1,
        "unsupported highest-standard matrix schema version"
    );
    ensure!(
        matrix.branch == ledger.generated_for_branch,
        "active-goal progress branch {} does not match matrix branch {}",
        ledger.generated_for_branch,
        matrix.branch
    );
    ensure!(
        claims.schema_version == CLAIMS_SCHEMA_VERSION,
        "unsupported formal security claims schema version"
    );
    ensure!(
        claims.generated_for_branch == matrix.branch,
        "formal security claims branch {} does not match matrix branch {}",
        claims.generated_for_branch,
        matrix.branch
    );
    ensure!(!matrix.goal.trim().is_empty(), "matrix goal must be set");
    ensure!(
        !matrix.completion_method.trim().is_empty(),
        "matrix completion_method must be set"
    );
    validate_percent(
        "highest-standard matrix formal_surface_coverage_percent",
        matrix.formal_surface_coverage_percent,
    )?;
    let claimed_lean_theorems = claimed_lean_theorem_names(claims)?;
    let assumption_closure = validate_mechanized_assumption_closure(
        root,
        &matrix.mechanized_assumption_closure,
        required_tracks,
        &claimed_lean_theorems,
    )?;
    ensure!(
        ledger.total_property_count == matrix.properties.len(),
        "active-goal progress total_property_count {} does not match matrix property count {}",
        ledger.total_property_count,
        matrix.properties.len()
    );
    ensure!(
        ledger.required_properties.len() == matrix.properties.len(),
        "active-goal progress required property count {} does not match matrix property count {}",
        ledger.required_properties.len(),
        matrix.properties.len()
    );
    ensure!(
        ledger.required_properties.len() == REQUIRED_HIGHEST_STANDARD_PROPERTIES.len(),
        "active-goal progress must list the full highest-standard property set"
    );

    let required_index: BTreeMap<&str, u64> = REQUIRED_HIGHEST_STANDARD_PROPERTIES
        .iter()
        .copied()
        .collect();
    let mut ledger_ids = BTreeSet::new();
    for property in &ledger.required_properties {
        validate_id("active-goal progress property id", &property.id)?;
        ensure!(
            ledger_ids.insert(property.id.as_str()),
            "duplicate active-goal progress property {}",
            property.id
        );
        let expected_weight = required_index
            .get(property.id.as_str())
            .ok_or_else(|| anyhow!("unknown active-goal progress property {}", property.id))?;
        ensure!(
            property.weight == *expected_weight,
            "active-goal progress property {} has weight {}, expected {}",
            property.id,
            property.weight,
            expected_weight
        );
        validate_percent(
            &format!("active-goal progress property {} target", property.id),
            property.target_completion_percent,
        )?;
    }
    for (id, _) in REQUIRED_HIGHEST_STANDARD_PROPERTIES {
        ensure!(
            ledger_ids.contains(id),
            "active-goal progress missing required property {}",
            id
        );
    }

    let ledger_property_index: BTreeMap<&str, &ActiveGoalRequiredProperty> = ledger
        .required_properties
        .iter()
        .map(|property| (property.id.as_str(), property))
        .collect();
    let mut matrix_ids = BTreeSet::new();
    let mut weighted_sum = 0.0f64;
    let mut total_weight = 0u64;
    let mut completed_properties = 0usize;
    for property in &matrix.properties {
        validate_id("highest-standard matrix property id", &property.id)?;
        ensure!(
            matrix_ids.insert(property.id.as_str()),
            "duplicate highest-standard matrix property {}",
            property.id
        );
        let expected_weight = required_index
            .get(property.id.as_str())
            .ok_or_else(|| anyhow!("matrix lists unknown property {}", property.id))?;
        ensure!(
            property.weight == *expected_weight,
            "matrix property {} has weight {}, expected {}",
            property.id,
            property.weight,
            expected_weight
        );
        let required = ledger_property_index
            .get(property.id.as_str())
            .ok_or_else(|| anyhow!("ledger missing matrix property {}", property.id))?;
        validate_percent(
            &format!("highest-standard matrix property {}", property.id),
            property.completion_percent,
        )?;
        ensure!(
            approx_percent_eq(
                property.completion_percent,
                required.target_completion_percent
            ),
            "property {} completion {} does not match active-goal target {}",
            property.id,
            property.completion_percent,
            required.target_completion_percent
        );
        if approx_percent_eq(property.completion_percent, 100.0) {
            ensure!(
                property.missing_work.is_empty(),
                "completed property {} still lists missing_work",
                property.id
            );
            ensure!(
                property.remaining_work.is_empty(),
                "completed property {} still lists remaining_work",
                property.id
            );
            ensure!(
                !property.current_evidence.is_empty(),
                "completed property {} must list current_evidence",
                property.id
            );
            ensure!(
                !property.explicit_external_assumptions.is_empty(),
                "completed property {} must state explicit external assumptions",
                property.id
            );
            completed_properties += 1;
        }
        weighted_sum += property.completion_percent * property.weight as f64;
        total_weight += property.weight;
    }
    for (id, _) in REQUIRED_HIGHEST_STANDARD_PROPERTIES {
        ensure!(
            matrix_ids.contains(id),
            "highest-standard matrix missing required property {}",
            id
        );
    }
    ensure!(
        total_weight > 0,
        "highest-standard matrix total weight is zero"
    );
    let weighted_completion_percent = weighted_sum / total_weight as f64;
    ensure!(
        ledger.total_weight == total_weight,
        "active-goal progress total_weight {} does not match matrix total weight {}",
        ledger.total_weight,
        total_weight
    );
    ensure!(
        ledger.completed_property_count == completed_properties,
        "active-goal progress completed_property_count {} does not match matrix completed properties {}",
        ledger.completed_property_count,
        completed_properties
    );
    validate_percent(
        "active-goal progress overall_completion_percent",
        ledger.overall_completion_percent,
    )?;
    validate_percent(
        "active-goal progress weighted_completion_percent",
        ledger.weighted_completion_percent,
    )?;
    validate_percent(
        "highest-standard matrix overall_completion_percent",
        matrix.overall_completion_percent,
    )?;
    ensure!(
        approx_percent_eq(
            ledger.weighted_completion_percent,
            weighted_completion_percent
        ),
        "active-goal progress weighted percent {} does not match recomputed {}",
        ledger.weighted_completion_percent,
        weighted_completion_percent
    );
    ensure!(
        approx_percent_eq(
            ledger.overall_completion_percent,
            matrix.overall_completion_percent
        ),
        "active-goal progress overall percent {} does not match matrix {}",
        ledger.overall_completion_percent,
        matrix.overall_completion_percent
    );
    ensure!(
        approx_percent_eq(
            matrix.formal_surface_coverage_percent,
            weighted_completion_percent
        ),
        "matrix formal surface coverage {} does not match recomputed weighted property percent {}",
        matrix.formal_surface_coverage_percent,
        weighted_completion_percent
    );
    let recomputed_overall = matrix
        .formal_surface_coverage_percent
        .min(assumption_closure.2);
    ensure!(
        approx_percent_eq(matrix.overall_completion_percent, recomputed_overall),
        "matrix overall percent {} does not match min(formal surface {}, mechanized assumption closure {}) = {}",
        matrix.overall_completion_percent,
        matrix.formal_surface_coverage_percent,
        assumption_closure.2,
        recomputed_overall
    );
    if ledger.goal_status_when_measured == "complete" {
        ensure!(
            approx_percent_eq(ledger.overall_completion_percent, 100.0)
                && approx_percent_eq(matrix.formal_surface_coverage_percent, 100.0)
                && assumption_closure.0 == assumption_closure.1
                && approx_percent_eq(assumption_closure.2, 100.0),
            "active goal cannot be marked complete until overall completion, formal-surface coverage, and mechanized-assumption closure are all 100% with every required track closed"
        );
    }

    Ok(ActiveGoalProgressReport {
        goal_thread_id: ledger.goal_thread_id.clone(),
        branch: ledger.generated_for_branch.clone(),
        goal_status_when_measured: ledger.goal_status_when_measured.clone(),
        matrix_properties: matrix.properties.len(),
        completed_properties,
        total_weight,
        weighted_completion_percent,
        overall_completion_percent: ledger.overall_completion_percent,
        formal_surface_coverage_percent: matrix.formal_surface_coverage_percent,
        mechanized_assumption_tracks: assumption_closure.0,
        closed_mechanized_assumption_tracks: assumption_closure.1,
        mechanized_assumption_closure_percent: assumption_closure.2,
        passed: true,
    })
}

fn validate_mechanized_assumption_closure(
    root: &Path,
    closure: &MechanizedAssumptionClosure,
    required_tracks: &[(&str, &[&str])],
    claimed_lean_theorems: &BTreeSet<String>,
) -> Result<(usize, usize, f64)> {
    ensure!(
        !closure.measurement_method.trim().is_empty(),
        "mechanized assumption closure measurement_method must be set"
    );
    let required: BTreeMap<&str, &[&str]> = required_tracks.iter().copied().collect();
    ensure!(
        required.len() == required_tracks.len(),
        "required mechanized assumption track policy contains duplicate ids"
    );
    ensure!(
        closure.total_tracks == required.len(),
        "mechanized assumption closure total_tracks {} does not match required track count {}",
        closure.total_tracks,
        required.len()
    );
    ensure!(
        closure.tracks.len() == required.len(),
        "mechanized assumption closure lists {} tracks, expected the required {}",
        closure.tracks.len(),
        required.len()
    );
    let mut ids = BTreeSet::new();
    let mut closed_tracks = 0usize;
    for track in &closure.tracks {
        validate_id("mechanized assumption track id", &track.id)?;
        ensure!(
            ids.insert(track.id.as_str()),
            "duplicate mechanized assumption track {}",
            track.id
        );
        let expected_theorems = required.get(track.id.as_str()).ok_or_else(|| {
            anyhow!(
                "unknown mechanized assumption track {}; update the independent required-track policy before changing the matrix",
                track.id
            )
        })?;
        let expected_status = if expected_theorems.is_empty() {
            "open"
        } else {
            "closed"
        };
        ensure!(
            track.status == expected_status,
            "mechanized assumption track {} has status {}, expected {} from the independent closure policy",
            track.id,
            track.status,
            expected_status
        );
        ensure!(
            !track.evidence_paths.is_empty(),
            "mechanized assumption track {} must list evidence_paths",
            track.id
        );
        for evidence in &track.evidence_paths {
            ensure_repo_relative_existing_file(
                root,
                evidence,
                &format!("mechanized assumption track {} evidence path", track.id),
            )?;
        }
        let actual_theorems: BTreeSet<&str> =
            track.lean_theorems.iter().map(String::as_str).collect();
        ensure!(
            actual_theorems.len() == track.lean_theorems.len(),
            "mechanized assumption track {} lists duplicate Lean theorem identities",
            track.id
        );
        let expected_theorems: BTreeSet<&str> = expected_theorems.iter().copied().collect();
        ensure!(
            actual_theorems == expected_theorems,
            "mechanized assumption track {} theorem identities do not match the independent closure policy; expected {:?}, got {:?}",
            track.id,
            expected_theorems,
            actual_theorems
        );
        if track.status == "closed" {
            closed_tracks += 1;
            for theorem in &track.lean_theorems {
                ensure!(
                    claimed_lean_theorems.contains(theorem),
                    "closed mechanized assumption track {} theorem {} is not covered by the formal security claims Lean theorem set",
                    track.id,
                    theorem
                );
                ensure_lean_theorem_declared_in_evidence(root, theorem, &track.evidence_paths)
                    .with_context(|| {
                        format!(
                            "closed mechanized assumption track {} theorem evidence",
                            track.id
                        )
                    })?;
            }
            ensure!(
                track.remaining_work.is_empty(),
                "closed mechanized assumption track {} still lists remaining_work",
                track.id
            );
        } else {
            ensure!(
                !track.remaining_work.is_empty(),
                "open mechanized assumption track {} must list remaining_work",
                track.id
            );
            for remaining in &track.remaining_work {
                ensure!(
                    !remaining.trim().is_empty(),
                    "mechanized assumption track {} has empty remaining_work",
                    track.id
                );
            }
        }
    }
    for id in required.keys() {
        ensure!(
            ids.contains(id),
            "mechanized assumption closure is missing required track {}",
            id
        );
    }
    ensure!(
        closure.closed_tracks == closed_tracks,
        "mechanized assumption closure closed_tracks {} does not match recomputed {}",
        closure.closed_tracks,
        closed_tracks
    );
    let recomputed = closed_tracks as f64 * 100.0 / closure.total_tracks as f64;
    validate_percent(
        "mechanized assumption closure closure_percent",
        closure.closure_percent,
    )?;
    ensure!(
        approx_percent_eq(closure.closure_percent, recomputed),
        "mechanized assumption closure percent {} does not match recomputed {}",
        closure.closure_percent,
        recomputed
    );
    Ok((closure.total_tracks, closed_tracks, recomputed))
}

fn claimed_lean_theorem_names(claims: &ClaimsLedger) -> Result<BTreeSet<String>> {
    let mut theorems = BTreeSet::new();
    for claim in &claims.claims {
        if claim.claim_class != "lean_theorem" {
            continue;
        }
        for theorem in &claim.lean_theorems {
            validate_lean_theorem_name("formal security claims closure coverage", theorem)?;
            theorems.insert(theorem.clone());
        }
    }
    ensure!(
        !theorems.is_empty(),
        "formal security claims must contain Lean theorem identities"
    );
    Ok(theorems)
}

fn ensure_lean_theorem_declared_in_evidence(
    root: &Path,
    theorem: &str,
    evidence_paths: &[String],
) -> Result<()> {
    validate_lean_theorem_name("mechanized assumption closure", theorem)?;
    let mut lean_evidence = 0usize;
    let mut declared_theorems = BTreeSet::new();
    for evidence in evidence_paths
        .iter()
        .filter(|path| is_non_generator_lean_evidence(path))
    {
        lean_evidence += 1;
        declared_theorems.extend(lean_theorem_names(&root.join(evidence))?);
    }
    ensure!(
        lean_evidence > 0,
        "Lean theorem {} has no non-generator .lean evidence path",
        theorem
    );
    ensure!(
        declared_theorems.contains(theorem),
        "Lean theorem {} is not declared in the listed evidence paths",
        theorem
    );
    Ok(())
}

fn validate_percent(label: &str, value: f64) -> Result<()> {
    ensure!(value.is_finite(), "{} must be finite", label);
    ensure!(
        (0.0..=100.0).contains(&value),
        "{} must be between 0 and 100, got {}",
        label,
        value
    );
    Ok(())
}

fn approx_percent_eq(left: f64, right: f64) -> bool {
    (left - right).abs() <= PROGRESS_PERCENT_EPSILON
}

pub fn check_formal_inventory(root: &Path) -> Result<InventoryReport> {
    let required = [
        "circuits/formal/README.md",
        "circuits/formal/transaction_balance.tla",
        "circuits/formal/transaction_balance.cfg",
        "consensus/spec/formal/README.md",
        "consensus/spec/formal/pow_longest_chain.tla",
        "consensus/spec/formal/pow_longest_chain.cfg",
        "formal/lean/README.md",
        "formal/lean/lean-toolchain",
        "formal/lean/lakefile.lean",
        "formal/lean/Hegemon/Bytes.lean",
        "formal/lean/Hegemon.lean",
        "scripts/check_lean_claim_axioms.py",
        "scripts/test_check_lean_claim_axioms.py",
        "scripts/check_ci_release_gate_policy.py",
        "config/lean-axiom-waivers.json",
        "config/active-goal-progress.json",
        "formal/lean/Hegemon/Privacy/Observer.lean",
        "formal/lean/Hegemon/Privacy/CiphertextPrivacy.lean",
        "formal/lean/Hegemon/Privacy/NativeObserverSurface.lean",
        "formal/lean/Hegemon/Privacy/NativeSidecarObserverSurface.lean",
        "formal/lean/Hegemon/Privacy/WalletOutputBatch.lean",
        "formal/lean/Hegemon/Privacy/GenerateWalletOutputBatchVectors.lean",
        "formal/lean/Hegemon/Wallet/NoteCiphertextDecrypt.lean",
        "formal/lean/Hegemon/Wallet/NotePlaintextCommitment.lean",
        "formal/lean/Hegemon/Wallet/NoteCiphertextWire.lean",
        "formal/lean/Hegemon/Wallet/GenerateNoteCiphertextWireVectors.lean",
        "formal/lean/Hegemon/Bridge/CheckpointOutput.lean",
        "formal/lean/Hegemon/Bridge/GenerateCheckpointOutputVectors.lean",
        "formal/lean/Hegemon/Bridge/Encoding.lean",
        "formal/lean/Hegemon/Bridge/FlyClient.lean",
        "formal/lean/Hegemon/Bridge/GenerateFlyClientVectors.lean",
        "formal/lean/Hegemon/Bridge/HeaderMmr.lean",
        "formal/lean/Hegemon/Bridge/GenerateHeaderMmrVectors.lean",
        "formal/lean/Hegemon/Bridge/HeaderMmrTranscript.lean",
        "formal/lean/Hegemon/Bridge/GenerateHeaderMmrTranscriptVectors.lean",
        "formal/lean/Hegemon/Bridge/LongRange.lean",
        "formal/lean/Hegemon/Bridge/GenerateLongRangeVectors.lean",
        "formal/lean/Hegemon/Bridge/MessageRoot.lean",
        "formal/lean/Hegemon/Bridge/MintReplayPolicy.lean",
        "formal/lean/Hegemon/Bridge/GenerateMintReplayPolicyVectors.lean",
        "formal/lean/Hegemon/Bridge/Replay.lean",
        "formal/lean/Hegemon/Bridge/GenerateVectors.lean",
        "formal/lean/Hegemon/Consensus/DaRoot.lean",
        "formal/lean/Hegemon/Consensus/GenerateDaRootVectors.lean",
        "formal/lean/Hegemon/Consensus/ForkChoice.lean",
        "formal/lean/Hegemon/Consensus/GenerateVectors.lean",
        "formal/lean/Hegemon/Consensus/Header.lean",
        "formal/lean/Hegemon/Consensus/GenerateHeaderVectors.lean",
        "formal/lean/Hegemon/Consensus/MinerIdentity.lean",
        "formal/lean/Hegemon/Consensus/GenerateMinerIdentityVectors.lean",
        "formal/lean/Hegemon/Consensus/NativeTxLeafAdmission.lean",
        "formal/lean/Hegemon/Consensus/GenerateNativeTxLeafAdmissionVectors.lean",
        "formal/lean/Hegemon/Consensus/PowRules.lean",
        "formal/lean/Hegemon/Consensus/GeneratePowVectors.lean",
        "formal/lean/Hegemon/Consensus/ProofPolicy.lean",
        "formal/lean/Hegemon/Consensus/GenerateProofPolicyVectors.lean",
        "formal/lean/Hegemon/Consensus/ProvenBatchBinding.lean",
        "formal/lean/Hegemon/Consensus/GenerateProvenBatchBindingVectors.lean",
        "formal/lean/Hegemon/Consensus/ReceiptRootAdmission.lean",
        "formal/lean/Hegemon/Consensus/GenerateReceiptRootAdmissionVectors.lean",
        "formal/lean/Hegemon/Consensus/RecursiveBlockAdmission.lean",
        "formal/lean/Hegemon/Consensus/GenerateRecursiveBlockAdmissionVectors.lean",
        "formal/lean/Hegemon/Consensus/RecursiveBlockV2VerifierSurface.lean",
        "formal/lean/Hegemon/Consensus/GenerateRecursiveBlockV2VerifierSurfaceVectors.lean",
        "formal/lean/Hegemon/Consensus/RecursivePublicReplay.lean",
        "formal/lean/Hegemon/Consensus/GenerateRecursivePublicReplayVectors.lean",
        "formal/lean/Hegemon/Consensus/RecursiveSemanticInputs.lean",
        "formal/lean/Hegemon/Consensus/GenerateRecursiveSemanticInputVectors.lean",
        "formal/lean/Hegemon/Consensus/StatementAnchorAdmission.lean",
        "formal/lean/Hegemon/Consensus/GenerateStatementAnchorAdmissionVectors.lean",
        "formal/lean/Hegemon/Consensus/Supply.lean",
        "formal/lean/Hegemon/Consensus/GenerateSupplyVectors.lean",
        "formal/lean/Hegemon/Consensus/SupplyInvariant.lean",
        "formal/lean/Hegemon/Consensus/GenerateSupplyInvariantVectors.lean",
        "formal/lean/Hegemon/Consensus/TreeTransition.lean",
        "formal/lean/Hegemon/Consensus/GenerateTreeTransitionVectors.lean",
        "formal/lean/Hegemon/Consensus/VersionPolicy.lean",
        "formal/lean/Hegemon/Consensus/GenerateVersionPolicyVectors.lean",
        "formal/lean/Hegemon/Native/ActionOrder.lean",
        "formal/lean/Hegemon/Native/GenerateActionOrderVectors.lean",
        "formal/lean/Hegemon/Native/ActionRequestProjectionAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateActionRequestProjectionAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/AtomicCommitManifestAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateAtomicCommitManifestAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/CanonicalReorgPersistenceAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateCanonicalReorgPersistenceAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ActionHashAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateActionHashAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ActionRootTranscript.lean",
        "formal/lean/Hegemon/Native/GenerateActionRootTranscriptVectors.lean",
        "formal/lean/Hegemon/Native/ActionStateEffect.lean",
        "formal/lean/Hegemon/Native/GenerateActionStateEffectVectors.lean",
        "formal/lean/Hegemon/Native/ActionStreamEffect.lean",
        "formal/lean/Hegemon/Native/GenerateActionStreamEffectVectors.lean",
        "formal/lean/Hegemon/Native/ActionPlanApplicationAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateActionPlanApplicationAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ActionWireReplayProjectionAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateActionWireReplayProjectionAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/AnnouncedBlockAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateAnnouncedBlockAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/BlockIndexReload.lean",
        "formal/lean/Hegemon/Native/GenerateBlockIndexReloadVectors.lean",
        "formal/lean/Hegemon/Native/CanonicalStateReload.lean",
        "formal/lean/Hegemon/Native/GenerateCanonicalStateReloadVectors.lean",
        "formal/lean/Hegemon/Native/BridgeReplayReload.lean",
        "formal/lean/Hegemon/Native/GenerateBridgeReplayReloadVectors.lean",
        "formal/lean/Hegemon/Native/PendingActionReload.lean",
        "formal/lean/Hegemon/Native/GeneratePendingActionReloadVectors.lean",
        "formal/lean/Hegemon/Native/StagedCiphertextReload.lean",
        "formal/lean/Hegemon/Native/GenerateStagedCiphertextReloadVectors.lean",
        "formal/lean/Hegemon/Native/StagedProofReload.lean",
        "formal/lean/Hegemon/Native/GenerateStagedProofReloadVectors.lean",
        "formal/lean/Hegemon/Native/StorageDurabilityAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateStorageDurabilityAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ActionScopeAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateActionScopeAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/BlockActionValidation.lean",
        "formal/lean/Hegemon/Native/BlockActionReplayPublication.lean",
        "formal/lean/Hegemon/Native/GenerateBlockActionReplayPublicationVectors.lean",
        "formal/lean/Hegemon/Native/GenerateBlockActionValidationVectors.lean",
        "formal/lean/Hegemon/Native/BridgeActionPayloadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBridgeActionPayloadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/BridgeActionResourceAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBridgeActionResourceAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/InboundBridgeReceiptAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateInboundBridgeReceiptAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/Risc0ReleaseVerifier.lean",
        "formal/lean/Hegemon/Native/GenerateRisc0ReleaseVerifierVectors.lean",
        "formal/lean/Hegemon/Native/NativeBackendReviewPolicy.lean",
        "formal/lean/Hegemon/Native/GenerateNativeBackendReviewPolicyVectors.lean",
        "formal/lean/Hegemon/Native/NativeBackendAlgebra.lean",
        "formal/lean/Hegemon/Native/GenerateNativeBackendAlgebraVectors.lean",
        "formal/lean/Hegemon/Native/NativeBackendReleasePosture.lean",
        "formal/lean/Hegemon/Native/GenerateNativeBackendReleasePostureVectors.lean",
        "formal/lean/Hegemon/Native/TransferActionPayloadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateTransferActionPayloadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/TransferStateAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateTransferStateAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/StablecoinPolicyAuthorization.lean",
        "formal/lean/Hegemon/Native/GenerateStablecoinPolicyAuthorizationVectors.lean",
        "formal/lean/Hegemon/Native/BlockArtifactBindingAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBlockArtifactBindingAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/BlockCommitmentAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBlockCommitmentAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/AcceptedChain.lean",
        "formal/lean/Hegemon/Native/BlockReplayRefinement.lean",
        "formal/lean/Hegemon/Native/GenerateBlockReplayRefinementVectors.lean",
        "formal/lean/Hegemon/Native/CommitmentTreeRefinement.lean",
        "formal/lean/Hegemon/Native/CommitmentTreeMembershipRefinement.lean",
        "formal/lean/Hegemon/Native/CommitmentTreeContentRefinement.lean",
        "formal/lean/Hegemon/Native/CandidateArtifactAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateCandidateArtifactAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/CandidateArtifactScaleWire.lean",
        "formal/lean/Hegemon/Native/GenerateCandidateArtifactScaleWireVectors.lean",
        "formal/lean/Hegemon/Native/CandidateArtifactCouplingAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateCandidateArtifactCouplingAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/CodecAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateCodecAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/CoinbaseAccountingAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateCoinbaseAccountingAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/CoinbaseActionPayloadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateCoinbaseActionPayloadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/CoinbaseActionPayloadScaleWire.lean",
        "formal/lean/Hegemon/Native/GenerateCoinbaseActionPayloadScaleWireVectors.lean",
        "formal/lean/Hegemon/Native/MineableActionAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateMineableActionAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/MinedWorkAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateMinedWorkAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/MinedBlockCommitPublication.lean",
        "formal/lean/Hegemon/Native/GenerateMinedBlockCommitPublicationVectors.lean",
        "formal/lean/Hegemon/Native/WorkTemplateAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateWorkTemplateAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/RecursiveArtifactContextAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateRecursiveArtifactContextAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ResourceBudgetAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateResourceBudgetAdmissionVectors.lean",
        "formal/lean/Hegemon/Resource/BoundedRequestAdmission.lean",
        "formal/lean/Hegemon/Resource/GenerateBoundedRequestAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/RpcAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateRpcAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/PreHeavyWorkResourceBoundSurface.lean",
        "formal/lean/Hegemon/Native/GeneratePreHeavyWorkResourceBoundSurfaceVectors.lean",
        "formal/lean/Hegemon/Native/DaSidecarReplayBinding.lean",
        "formal/lean/Hegemon/Native/RawIngressSidecarReplayRecoverability.lean",
        "formal/lean/Hegemon/Native/CanonicalPublicationRefinement.lean",
        "formal/lean/Hegemon/Native/PendingActionScaleWire.lean",
        "formal/lean/Hegemon/Native/GeneratePendingActionScaleWireVectors.lean",
        "formal/lean/Hegemon/Native/PendingActionByteParserRefinement.lean",
        "formal/lean/Hegemon/Native/PendingActionBytePublicationRefinement.lean",
        "formal/lean/Hegemon/Native/CodecCanonicalPublicationBoundary.lean",
        "formal/lean/Hegemon/Native/PreHeavyCodecCanonicalPublication.lean",
        "formal/lean/Hegemon/Native/PendingActionByteReplayRowCountBinding.lean",
        "formal/lean/Hegemon/Native/PendingActionFieldProjectionVectors.lean",
        "formal/lean/Hegemon/Native/GeneratePendingActionFieldProjectionVectors.lean",
        "formal/lean/Hegemon/Native/RawIngressPendingActionPublicationRefinement.lean",
        "formal/lean/Hegemon/Native/RawIngressActionHashTxLeafPublication.lean",
        "formal/lean/Hegemon/Native/RawIngressDaSidecarCanonicalPublication.lean",
        "formal/lean/Hegemon/Native/RawIngressFullBytePublicationSurface.lean",
        "formal/lean/Hegemon/Native/AcceptedBlockAdmissionSafety.lean",
        "formal/lean/Hegemon/Native/MaterializedSidecarDaBlobPublication.lean",
        "formal/lean/Hegemon/Native/MaterializedConsensusDaBlobRefinement.lean",
        "formal/lean/Hegemon/Native/MaterializedTransferNoTheftPublication.lean",
        "formal/lean/Hegemon/Native/NativePublicationRowEquivalence.lean",
        "formal/lean/Hegemon/Native/RawIngressBridgePendingActionPublication.lean",
        "formal/lean/Hegemon/Native/RawIngressTransferNoTheftPublication.lean",
        "formal/lean/Hegemon/Native/SidecarUploadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateSidecarUploadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/SyncAdmission.lean",
        "formal/lean/Hegemon/Native/SyncBlockChunkAdmission.lean",
        "formal/lean/Hegemon/Native/SyncBlockReplayPublication.lean",
        "formal/lean/Hegemon/Native/SyncBlockRangePublicationAdmission.lean",
        "formal/lean/Hegemon/Native/SyncRawIngress.lean",
        "formal/lean/Hegemon/Native/SyncResponseImport.lean",
        "formal/lean/Hegemon/Native/GenerateSyncAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/GenerateSyncBlockChunkAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/GenerateSyncBlockRangePublicationAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/GenerateSyncRawIngressVectors.lean",
        "formal/lean/Hegemon/Native/GenerateSyncResponseImportVectors.lean",
        "formal/lean/Hegemon/Network/SecureChannel.lean",
        "formal/lean/Hegemon/Network/GenerateSecureChannelVectors.lean",
        "formal/lean/Hegemon/Network/PqNoise.lean",
        "formal/lean/Hegemon/Network/PqNoiseHandshakeChannel.lean",
        "formal/lean/Hegemon/Network/GeneratePqNoiseVectors.lean",
        "formal/lean/Hegemon/Network/FrameResourceAdmission.lean",
        "formal/lean/Hegemon/Network/GenerateFrameResourceAdmissionVectors.lean",
        "formal/lean/Hegemon/Network/QueueResourceAdmission.lean",
        "formal/lean/Hegemon/Network/GenerateQueueResourceAdmissionVectors.lean",
        "formal/lean/Hegemon/Release/CiReleaseGate.lean",
        "formal/lean/Hegemon/Release/GenerateCiReleaseGateVectors.lean",
        "formal/lean/Hegemon/Release/DependencyAuditPolicy.lean",
        "formal/lean/Hegemon/Release/GenerateDependencyAuditPolicyVectors.lean",
        "formal/lean/Hegemon/Release/PqBinaryPolicy.lean",
        "formal/lean/Hegemon/Release/GeneratePqBinaryPolicyVectors.lean",
        "formal/lean/Hegemon/Release/SystemModelAssumptionGate.lean",
        "config/system-model-assumption-gates.json",
        "docs/SYSTEM_MODEL_ASSUMPTION_GATES.md",
        "formal/lean/Hegemon/Native/TxLeafArtifact.lean",
        "formal/lean/Hegemon/Native/TxLeafArtifactProjectionRefinement.lean",
        "formal/lean/Hegemon/Native/GenerateTxLeafArtifactVectors.lean",
        "formal/lean/Hegemon/Native/ReceiptRoot.lean",
        "formal/lean/Hegemon/Native/GenerateReceiptRootVectors.lean",
        "formal/lean/Hegemon/Shielded/Nullifier.lean",
        "formal/lean/Hegemon/Shielded/GenerateVectors.lean",
        "formal/lean/Hegemon/Transaction/Balance.lean",
        "formal/lean/Hegemon/Transaction/GenerateVectors.lean",
        "formal/lean/Hegemon/Transaction/NoteCommitmentInputs.lean",
        "formal/lean/Hegemon/Transaction/GenerateNoteCommitmentInputVectors.lean",
        "formal/lean/Hegemon/Transaction/NullifierInputs.lean",
        "formal/lean/Hegemon/Transaction/GenerateNullifierInputVectors.lean",
        "formal/lean/Hegemon/Transaction/GenerateSmallWoodSpendAuthorizationVectors.lean",
        "formal/lean/Hegemon/Transaction/GenerateSmallWoodCandidateWrapperAdmissionVectors.lean",
        "formal/lean/Hegemon/Transaction/GenerateSmallWoodPublicStatementBindingVectors.lean",
        "formal/lean/Hegemon/Transaction/GenerateSmallWoodVerifierStatementProjectionVectors.lean",
        "formal/lean/Hegemon/Transaction/GenerateSmallWoodTranscriptBindingVectors.lean",
        "formal/lean/Hegemon/Transaction/MerklePath.lean",
        "formal/lean/Hegemon/Transaction/GenerateMerkleVectors.lean",
        "formal/lean/Hegemon/Transaction/PublicInputs.lean",
        "formal/lean/Hegemon/Transaction/GeneratePublicInputVectors.lean",
        "formal/lean/Hegemon/Transaction/PublicInputBinding.lean",
        "formal/lean/Hegemon/Transaction/GeneratePublicInputBindingVectors.lean",
        "formal/lean/Hegemon/Transaction/ProofStatementBinding.lean",
        "formal/lean/Hegemon/Transaction/GenerateProofStatementBindingVectors.lean",
        "formal/lean/Hegemon/Transaction/ProofSystemBoundary.lean",
        "formal/lean/Hegemon/Transaction/ProofWrapperAdmission.lean",
        "formal/lean/Hegemon/Transaction/GenerateProofWrapperAdmissionVectors.lean",
        "formal/lean/Hegemon/Transaction/ProofWrapperWire.lean",
        "formal/lean/Hegemon/Transaction/GenerateProofWrapperWireVectors.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodBalanceBoundary.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodCandidateWrapperAdmission.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodPublicStatementBinding.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodVerifierStatementProjection.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodRecursiveEnvelopeWire.lean",
        "formal/lean/Hegemon/Transaction/GenerateSmallWoodRecursiveEnvelopeWireVectors.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodSpendAuthorization.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodSemanticClosure.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodNoCounterfeit.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodTranscriptBinding.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodVerifierSoundnessEnvelope.lean",
        "formal/lean/Hegemon/Transaction/StatementHash.lean",
        "formal/lean/Hegemon/Transaction/GenerateStatementHashVectors.lean",
        "wallet/tests/note_ciphertext_wire_vectors.rs",
        "config/formal-security-claims.json",
        "testdata/formal_core_vectors/bridge_messages.json",
        "config/formal-security-blueprint.json",
    ];
    let mut missing = Vec::new();
    for file in required {
        let path = root.join(file);
        if !path.is_file() {
            missing.push(file.to_owned());
        }
    }
    ensure!(
        missing.is_empty(),
        "missing formal inventory files: {missing:?}"
    );

    let tx_tla = fs::read_to_string(root.join("circuits/formal/transaction_balance.tla"))?;
    ensure!(
        tx_tla.contains("BalanceInvariant") && tx_tla.contains("NullifierUniqueness"),
        "transaction_balance.tla must define balance and nullifier invariants"
    );
    let pow_tla = fs::read_to_string(root.join("consensus/spec/formal/pow_longest_chain.tla"))?;
    ensure!(
        pow_tla.contains("ForkChoiceInvariant") && pow_tla.contains("FinalityInvariant"),
        "pow_longest_chain.tla must define fork-choice and finality invariants"
    );

    Ok(InventoryReport {
        required_files: required.into_iter().map(str::to_owned).collect(),
        passed: true,
    })
}

fn validate_claim(root: &Path, claim: &SecurityClaim) -> Result<BTreeSet<String>> {
    validate_id("claim id", &claim.id)?;
    ensure!(
        !claim.component.trim().is_empty(),
        "{} component missing",
        claim.id
    );
    ensure!(
        !claim.summary.trim().is_empty(),
        "{} summary missing",
        claim.id
    );
    ensure!(
        CLAIM_CLASSES.contains(&claim.claim_class.as_str()),
        "{} has unknown claim_class {}",
        claim.id,
        claim.claim_class
    );
    ensure!(
        CLAIM_STATUSES.contains(&claim.status.as_str()),
        "{} has unknown status {}",
        claim.id,
        claim.status
    );
    ensure!(
        !claim.proof_model.trim().is_empty(),
        "{} proof_model missing",
        claim.id
    );
    ensure!(
        !claim.assumptions.is_empty(),
        "{} must list at least one assumption",
        claim.id
    );
    ensure!(
        !claim.evidence_paths.is_empty(),
        "{} must list evidence paths",
        claim.id
    );
    for evidence in &claim.evidence_paths {
        ensure_repo_relative_existing(root, evidence, &format!("{} evidence path", claim.id))?;
    }
    let theorem_names = validate_lean_theorem_evidence(root, claim)?;
    if claim.production_eligible {
        production_claim_checks(claim)?;
    } else {
        ensure!(
            !claim.residual_risks.is_empty(),
            "{} is not production eligible and must state residual risk",
            claim.id
        );
    }
    for risk in &claim.residual_risks {
        validate_residual_risk(&claim.id, risk)?;
    }
    if let Some(authority) = &claim.authority {
        validate_claim_authority(&claim.id, authority)?;
        ensure!(
            claim.production_eligible == authority.production_authorized,
            "{} production_eligible must match machine-readable authority",
            claim.id
        );
    }
    if claim.id == CONDITIONAL_SMALLWOOD_CLAIM_ID {
        validate_conditional_smallwood_claim(claim)?;
    }
    Ok(theorem_names)
}

fn validate_claim_authority(claim_id: &str, authority: &ClaimAuthority) -> Result<()> {
    ensure!(
        authority.kind == "conditional_lean",
        "{} authority kind must be conditional_lean",
        claim_id
    );
    ensure!(
        !authority.required_assumptions.is_empty(),
        "{} authority must list required assumptions",
        claim_id
    );
    let mut assumptions = BTreeSet::new();
    for assumption in &authority.required_assumptions {
        ensure!(
            !assumption.trim().is_empty(),
            "{} authority contains an empty required assumption",
            claim_id
        );
        ensure!(
            assumptions.insert(assumption.as_str()),
            "{} authority repeats required assumption {}",
            claim_id,
            assumption
        );
    }
    if !authority.production_authorized {
        ensure!(
            authority.concrete_pq_security_bits.is_none(),
            "{} cannot state concrete PQ security bits without production authority",
            claim_id
        );
    }
    Ok(())
}

fn validate_conditional_smallwood_claim(claim: &SecurityClaim) -> Result<()> {
    ensure!(
        claim.status == "research_only" && !claim.production_eligible,
        "{} must remain research_only and not production eligible until its explicit assumptions are discharged",
        claim.id
    );
    ensure!(
        claim.proof_model
            == "conditional_lean_reduction_with_explicit_knowledge_soundness_semantic_refinement_and_poseidon_assumptions",
        "{} proof_model must identify the conditional Lean authority",
        claim.id
    );
    let authority = claim
        .authority
        .as_ref()
        .ok_or_else(|| anyhow!("{} must carry machine-readable claim authority", claim.id))?;
    ensure!(
        !authority.production_authorized
            && !authority.shipped_rust_verifier_refinement_proved
            && !authority.qrom_failure_bound_composed
            && !authority.deployed_hash_instantiation_loss_bounded
            && authority.concrete_pq_security_bits.is_none(),
        "{} authority overstates production, Rust-refinement, QROM-composition, hash-instantiation, or concrete-bit closure",
        claim.id
    );
    let actual_assumptions = authority
        .required_assumptions
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_assumptions = CONDITIONAL_SMALLWOOD_ASSUMPTIONS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    ensure!(
        actual_assumptions == expected_assumptions,
        "{} authority assumptions must exactly match the independent conditional-boundary policy",
        claim.id
    );
    ensure!(
        claim.summary.contains("conditional")
            && claim.summary.contains("does not")
            && claim
                .summary
                .contains("exact-map-to-canonical-semantic bridge is an explicit assumption")
            && claim.summary.contains("128-bit"),
        "{} summary must state its conditional and non-128-bit authority",
        claim.id
    );
    ensure!(
        !claim.residual_risks.is_empty(),
        "{} must retain residual risks",
        claim.id
    );
    Ok(())
}

fn validate_lean_theorem_evidence(root: &Path, claim: &SecurityClaim) -> Result<BTreeSet<String>> {
    if claim.claim_class != "lean_theorem" {
        ensure!(
            claim.lean_theorems.is_empty(),
            "{} lean_theorems is only valid for lean_theorem claims",
            claim.id
        );
        return Ok(BTreeSet::new());
    }

    let mut checked_lean_sources = Vec::new();
    let mut declared_theorem_names = BTreeSet::new();
    for evidence in &claim.evidence_paths {
        if !is_non_generator_lean_evidence(evidence) {
            continue;
        }
        checked_lean_sources.push(evidence.as_str());
        let path = root.join(evidence);
        for theorem in lean_theorem_names(&path)? {
            declared_theorem_names.insert(theorem);
        }
    }

    ensure!(
        !checked_lean_sources.is_empty(),
        "{} lean_theorem claim must list at least one non-generator Lean evidence path",
        claim.id
    );
    ensure!(
        !declared_theorem_names.is_empty(),
        "{} lean_theorem claim must be backed by a named theorem declaration in non-generator Lean evidence: {:?}",
        claim.id,
        checked_lean_sources
    );
    ensure!(
        !claim.lean_theorems.is_empty(),
        "{} lean_theorem claim must list explicit lean_theorems",
        claim.id
    );
    let mut listed_theorem_names = BTreeSet::new();
    for theorem in &claim.lean_theorems {
        validate_lean_theorem_name(&claim.id, theorem)?;
        ensure!(
            listed_theorem_names.insert(theorem.clone()),
            "{} lists duplicate Lean theorem {}",
            claim.id,
            theorem
        );
        ensure!(
            declared_theorem_names.contains(theorem),
            "{} lists Lean theorem {} that is not declared by its non-generator Lean evidence",
            claim.id,
            theorem
        );
    }
    Ok(listed_theorem_names)
}

fn is_non_generator_lean_evidence(raw: &str) -> bool {
    if !raw.starts_with("formal/lean/") || !raw.ends_with(".lean") {
        return false;
    }
    let Some(file_name) = Path::new(raw).file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    !file_name.starts_with("Generate")
}

fn lean_theorem_names(path: &Path) -> Result<Vec<String>> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("read Lean theorem evidence {}", path.display()))?;
    let source = strip_lean_comments(&source);
    let mut names = BTreeSet::new();
    let mut namespaces: Vec<String> = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let Some(first) = tokens.first().copied() else {
            continue;
        };
        if first == "namespace" {
            if let Some(namespace) = tokens.get(1).copied() {
                namespaces.push(namespace.trim_end_matches(',').to_owned());
            }
            continue;
        }
        if first == "end" {
            if !namespaces.is_empty() {
                namespaces.pop();
            }
            continue;
        }
        let name = (first == "theorem")
            .then(|| tokens.get(1).copied())
            .flatten();
        let Some(raw_name) = name else {
            continue;
        };
        let theorem = raw_name.trim_end_matches(':');
        if !theorem.is_empty() {
            names.insert(theorem.to_owned());
            if !theorem.contains('.') {
                let namespace = namespaces.join(".");
                if !namespace.is_empty() {
                    names.insert(format!("{namespace}.{theorem}"));
                }
            }
        }
    }
    Ok(names.into_iter().collect())
}

fn strip_lean_comments(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut stripped = String::with_capacity(source.len());
    let mut index = 0usize;
    let mut block_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    while index < chars.len() {
        let current = chars[index];
        let next = chars.get(index + 1).copied();

        if block_depth > 0 {
            if current == '/' && next == Some('-') {
                block_depth += 1;
                index += 2;
                continue;
            }
            if current == '-' && next == Some('/') {
                block_depth -= 1;
                index += 2;
                continue;
            }
            if current == '\n' {
                stripped.push('\n');
            }
            index += 1;
            continue;
        }

        if in_string {
            if current == '\n' {
                stripped.push('\n');
            } else {
                stripped.push(' ');
            }
            if escaped {
                escaped = false;
            } else if current == '\\' {
                escaped = true;
            } else if current == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if current == '"' {
            in_string = true;
            stripped.push(' ');
            index += 1;
            continue;
        }

        if current == '-' && next == Some('-') {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            if index < chars.len() {
                stripped.push('\n');
                index += 1;
            }
            continue;
        }

        if current == '/' && next == Some('-') {
            block_depth = 1;
            index += 2;
            continue;
        }

        stripped.push(current);
        index += 1;
    }

    stripped
}

fn validate_lean_theorem_name(claim_id: &str, theorem: &str) -> Result<()> {
    ensure!(
        theorem.starts_with("Hegemon."),
        "{} Lean theorem {} must be fully qualified under Hegemon",
        claim_id,
        theorem
    );
    ensure!(
        theorem
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'),
        "{} Lean theorem {} must use alphanumeric, underscore, or dot characters",
        claim_id,
        theorem
    );
    ensure!(
        theorem.split('.').all(|part| !part.is_empty()),
        "{} Lean theorem {} has an empty namespace segment",
        claim_id,
        theorem
    );
    Ok(())
}

fn validate_blueprint(
    root: &Path,
    blueprint_path: &Path,
    blueprint: &FormalBlueprint,
    claim_index: &ClaimIndex,
) -> Result<BlueprintReport> {
    ensure!(
        blueprint.schema_version == BLUEPRINT_SCHEMA_VERSION,
        "unsupported blueprint schema version"
    );
    ensure!(
        !blueprint.generated_for_branch.trim().is_empty(),
        "blueprint generated_for_branch must be set"
    );
    ensure!(
        blueprint.generated_for_branch == claim_index.generated_for_branch,
        "blueprint generated_for_branch {} does not match claims ledger {}",
        blueprint.generated_for_branch,
        claim_index.generated_for_branch
    );
    validate_methodology(&blueprint.methodology)?;
    validate_governance_gate_evidence(
        "formal security blueprint",
        root,
        blueprint_path,
        "governance_gate_evidence",
        &blueprint.governance_gate_evidence,
    )?;
    ensure!(
        !blueprint.nodes.is_empty(),
        "blueprint node set must not be empty"
    );

    let mut node_ids = BTreeSet::new();
    for node in &blueprint.nodes {
        validate_id("blueprint node id", &node.id)?;
        ensure!(
            node.id == node.claim_id,
            "{} claim_id must match node id",
            node.id
        );
        ensure!(
            claim_index.claims.contains_key(&node.claim_id),
            "blueprint node {} has no matching claims-ledger entry",
            node.id
        );
        ensure!(
            node_ids.insert(node.id.clone()),
            "duplicate blueprint node id {}",
            node.id
        );
    }
    for claim_id in claim_index.claims.keys() {
        ensure!(
            node_ids.contains(claim_id),
            "claims-ledger entry {} has no blueprint node",
            claim_id
        );
    }

    let mut edges = 0usize;
    let mut production_nodes = 0usize;
    let mut implementation_bindings = 0usize;
    let mut implementation_result_obligations = 0usize;
    let mut implementation_order_constraints = 0usize;
    let mut implementation_order_edges = 0usize;
    let mut implementation_theorem_indexed_order_constraints = 0usize;
    let mut implementation_theorem_indexed_order_edges = 0usize;
    let mut full_claim_order_constraints = 0usize;
    let mut full_claim_order_constraint_theorem_refs = 0usize;
    let mut implementation_dominance_constraints = 0usize;
    let mut implementation_dominance_edges = 0usize;
    let mut implementation_theorem_indexed_dominance_constraints = 0usize;
    let mut implementation_theorem_indexed_dominance_edges = 0usize;
    let mut falsification_cases = 0usize;
    let mut pending_external_review_nodes = 0usize;
    let mut dependents: BTreeMap<String, usize> =
        node_ids.iter().map(|id| (id.clone(), 0usize)).collect();

    for node in &blueprint.nodes {
        let claim = claim_index
            .claims
            .get(&node.claim_id)
            .expect("claim existence checked before node validation");
        validate_blueprint_node(root, &blueprint.policy, node, claim)?;
        let mut deps = BTreeSet::new();
        for dep in &node.depends_on {
            validate_id(&format!("{} dependency id", node.id), dep)?;
            ensure!(dep != &node.id, "{} must not depend on itself", node.id);
            ensure!(
                node_ids.contains(dep),
                "{} depends on unknown node {}",
                node.id,
                dep
            );
            ensure!(
                deps.insert(dep),
                "{} lists duplicate dependency {}",
                node.id,
                dep
            );
            *dependents
                .get_mut(dep)
                .expect("dependency existence checked above") += 1;
            edges += 1;
        }
        if claim.production_eligible {
            production_nodes += 1;
        }
        if node.target_review.status == "needs_review" {
            pending_external_review_nodes += 1;
        }
        implementation_bindings += node.implementation_bindings.len();
        for binding in &node.implementation_bindings {
            if binding.result_obligation.is_some() {
                implementation_result_obligations += 1;
            }
            implementation_order_constraints += binding.call_order_constraints.len();
            implementation_order_edges += binding
                .call_order_constraints
                .iter()
                .map(|constraint| constraint.callee_must_precede.len())
                .sum::<usize>();
            for constraint in &binding.call_order_constraints {
                if !constraint.lean_theorems.is_empty() {
                    implementation_theorem_indexed_order_constraints += 1;
                    implementation_theorem_indexed_order_edges +=
                        constraint.callee_must_precede.len();
                }
                if claim.production_eligible && is_full_claim_order_constraint(claim, constraint) {
                    full_claim_order_constraints += 1;
                    full_claim_order_constraint_theorem_refs += constraint.lean_theorems.len();
                }
                if constraint.result_obligation.is_some() {
                    implementation_result_obligations += 1;
                }
                if constraint.must_dominate_successors {
                    implementation_dominance_constraints += 1;
                    implementation_dominance_edges += constraint.callee_must_precede.len();
                    if !constraint.lean_theorems.is_empty() {
                        implementation_theorem_indexed_dominance_constraints += 1;
                        implementation_theorem_indexed_dominance_edges +=
                            constraint.callee_must_precede.len();
                    }
                }
            }
        }
        falsification_cases += node.falsification_cases.len();
    }

    for node in &blueprint.nodes {
        if node.kind == "supporting_claim" {
            ensure!(
                dependents.get(&node.id).copied().unwrap_or_default() > 0,
                "{} is a supporting_claim but no other node depends on it",
                node.id
            );
        }
    }
    detect_blueprint_cycles(&blueprint.nodes)?;
    enforce_blueprint_policy_budgets(
        &blueprint.policy,
        full_claim_order_constraints,
        full_claim_order_constraint_theorem_refs,
    )?;

    Ok(BlueprintReport {
        nodes: blueprint.nodes.len(),
        edges,
        production_nodes,
        implementation_bindings,
        implementation_result_obligations,
        implementation_order_constraints,
        implementation_order_edges,
        implementation_theorem_indexed_order_constraints,
        implementation_theorem_indexed_order_edges,
        full_claim_order_constraints,
        full_claim_order_constraint_theorem_refs,
        implementation_dominance_constraints,
        implementation_dominance_edges,
        implementation_theorem_indexed_dominance_constraints,
        implementation_theorem_indexed_dominance_edges,
        falsification_cases,
        pending_external_review_nodes,
        passed: true,
    })
}

fn is_full_claim_order_constraint(
    claim: &ClaimProjection,
    constraint: &ImplementationCallOrderConstraint,
) -> bool {
    if constraint.lean_theorems.is_empty() {
        return false;
    }
    let theorem_refs = constraint
        .lean_theorems
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    theorem_refs.len() == claim.lean_theorems.len()
        && theorem_refs
            .iter()
            .all(|theorem| claim.lean_theorems.contains(*theorem))
}

fn enforce_blueprint_policy_budgets(
    policy: &BlueprintPolicy,
    full_claim_order_constraints: usize,
    full_claim_order_constraint_theorem_refs: usize,
) -> Result<()> {
    if let Some(max) = policy.max_full_claim_order_constraints {
        ensure!(
            full_claim_order_constraints <= max,
            "blueprint full-claim order constraints {} exceeds max_full_claim_order_constraints {}",
            full_claim_order_constraints,
            max
        );
    }
    if let Some(max) = policy.max_full_claim_order_constraint_theorem_refs {
        ensure!(
            full_claim_order_constraint_theorem_refs <= max,
            "blueprint full-claim order constraint theorem refs {} exceeds max_full_claim_order_constraint_theorem_refs {}",
            full_claim_order_constraint_theorem_refs,
            max
        );
    }
    Ok(())
}

fn validate_methodology(methodology: &BlueprintMethodology) -> Result<()> {
    ensure!(
        !methodology.name.trim().is_empty(),
        "blueprint methodology name missing"
    );
    ensure!(
        !methodology.summary.trim().is_empty(),
        "blueprint methodology summary missing"
    );
    ensure!(
        !methodology.source_of_record.trim().is_empty(),
        "blueprint methodology source_of_record missing"
    );
    ensure!(
        !methodology.gate.trim().is_empty(),
        "blueprint methodology gate missing"
    );
    Ok(())
}

fn validate_blueprint_node(
    root: &Path,
    policy: &BlueprintPolicy,
    node: &BlueprintNode,
    claim: &ClaimProjection,
) -> Result<()> {
    ensure!(
        BLUEPRINT_NODE_KINDS.contains(&node.kind.as_str()),
        "{} has unknown blueprint kind {}",
        node.id,
        node.kind
    );
    ensure!(
        !node.formal_statement.trim().is_empty(),
        "{} formal_statement missing",
        node.id
    );
    ensure!(
        !node.informal_argument.trim().is_empty(),
        "{} informal_argument missing",
        node.id
    );
    ensure!(
        !node.scope_boundary.trim().is_empty(),
        "{} scope_boundary missing",
        node.id
    );
    ensure!(
        node.authority == claim.authority,
        "{} blueprint authority must exactly match its claims-ledger authority",
        node.id
    );
    if node.id == CONDITIONAL_SMALLWOOD_CLAIM_ID {
        ensure!(
            node.formal_statement.contains("conditional")
                && node.scope_boundary.contains("does not")
                && node.scope_boundary.contains("128-bit"),
            "{} blueprint must state its conditional, non-128-bit authority boundary",
            node.id
        );
    }
    validate_target_review(root, node)?;
    ensure!(
        !node.implementation_paths.is_empty(),
        "{} implementation_paths must not be empty",
        node.id
    );
    ensure!(
        !node.evidence_paths.is_empty(),
        "{} evidence_paths must not be empty",
        node.id
    );
    let mut path_coverage = BTreeSet::new();
    for path in &node.implementation_paths {
        ensure_repo_relative_existing(root, path, &format!("{} implementation path", node.id))?;
        path_coverage.insert(path.clone());
    }
    for path in &node.evidence_paths {
        ensure_repo_relative_existing(root, path, &format!("{} evidence path", node.id))?;
        path_coverage.insert(path.clone());
    }
    for claim_evidence in &claim.evidence_paths {
        ensure!(
            path_coverage.contains(claim_evidence),
            "{} blueprint must cover claims-ledger evidence path {}",
            node.id,
            claim_evidence
        );
    }
    validate_implementation_bindings(root, policy, node, claim)?;
    validate_falsification_cases(node)?;
    if claim.production_eligible {
        ensure!(
            node.kind != "residual_risk",
            "{} production claim cannot be a residual_risk blueprint node",
            node.id
        );
        ensure!(
            !node.falsification_cases.is_empty(),
            "{} production claim must include at least one falsification case",
            node.id
        );
    }
    Ok(())
}

fn validate_implementation_bindings(
    root: &Path,
    policy: &BlueprintPolicy,
    node: &BlueprintNode,
    claim: &ClaimProjection,
) -> Result<()> {
    for binding in &node.implementation_bindings {
        ensure!(
            node.implementation_paths.contains(&binding.path),
            "{} implementation binding path {} must be listed in implementation_paths",
            node.id,
            binding.path
        );
        ensure_repo_relative_existing(
            root,
            &binding.path,
            &format!("{} implementation binding path", node.id),
        )?;
        validate_rust_symbol(&node.id, "implementation binding callee", &binding.callee)?;
        ensure!(
            !binding.required_callers.is_empty(),
            "{} implementation binding for {} must list required_callers",
            node.id,
            binding.callee
        );
        for caller in &binding.required_callers {
            validate_rust_caller_symbol(&node.id, "implementation binding caller", caller)?;
            ensure!(
                rust_caller_symbol_leaf(caller) != binding.callee,
                "{} implementation binding for {} cannot list itself as required caller {}",
                node.id,
                binding.callee,
                caller
            );
        }
        parse_result_obligation(
            &node.id,
            &binding.callee,
            binding.result_obligation.as_deref(),
        )?;
        for constraint in &binding.call_order_constraints {
            validate_rust_caller_symbol(
                &node.id,
                "implementation binding ordered caller",
                &constraint.caller,
            )?;
            ensure!(
                binding.required_callers.contains(&constraint.caller),
                "{} implementation binding order constraint caller {} must also be listed in required_callers",
                node.id,
                constraint.caller
            );
            ensure!(
                !constraint.callee_must_precede.is_empty(),
                "{} implementation binding order constraint for {} must list callee_must_precede",
                node.id,
                constraint.caller
            );
            for successor in &constraint.callee_must_precede {
                validate_rust_call_selector(
                    &node.id,
                    "implementation binding order successor",
                    successor,
                )?;
                let successor_selector = parse_rust_call_selector(successor)
                    .expect("successor selector validated above");
                ensure!(
                    successor_selector.last_segment() != binding.callee,
                    "{} implementation binding order constraint for {} cannot list bound callee {} as its own successor",
                    node.id,
                    constraint.caller,
                    binding.callee
                );
            }
            parse_result_obligation(
                &node.id,
                &binding.callee,
                constraint.result_obligation.as_deref(),
            )?;
            validate_implementation_call_order_theorems(&node.id, policy, claim, constraint)?;
        }
        validate_rust_implementation_binding(root, &node.id, binding)?;
    }
    Ok(())
}

fn validate_implementation_call_order_theorems(
    node_id: &str,
    policy: &BlueprintPolicy,
    claim: &ClaimProjection,
    constraint: &ImplementationCallOrderConstraint,
) -> Result<()> {
    if constraint.lean_theorems.is_empty() {
        ensure!(
            !(policy.require_theorem_indexed_order_constraints && claim.production_eligible),
            "{} implementation binding order constraint for {} must list lean_theorems because blueprint policy requires theorem-indexed production order constraints",
            node_id,
            constraint.caller
        );
        return Ok(());
    }

    let mut theorem_refs = BTreeSet::new();
    for theorem in &constraint.lean_theorems {
        validate_lean_theorem_name(node_id, theorem)?;
        ensure!(
            theorem_refs.insert(theorem.as_str()),
            "{} implementation binding order constraint for {} lists duplicate Lean theorem {}",
            node_id,
            constraint.caller,
            theorem
        );
    }
    ensure!(
        !claim.lean_theorems.is_empty(),
        "{} implementation binding order constraint for {} lists Lean theorem refs but claim has no Lean theorem evidence",
        node_id,
        constraint.caller
    );
    for theorem in &constraint.lean_theorems {
        ensure!(
            claim.lean_theorems.contains(theorem),
            "{} implementation binding order constraint for {} lists Lean theorem {} that is not listed by claim {}",
            node_id,
            constraint.caller,
            theorem,
            node_id
        );
    }
    Ok(())
}

fn validate_rust_symbol(claim_id: &str, label: &str, symbol: &str) -> Result<()> {
    ensure!(!symbol.trim().is_empty(), "{} {} missing", claim_id, label);
    ensure!(
        is_plain_rust_identifier(symbol),
        "{} {} {} must be a plain Rust identifier",
        claim_id,
        label,
        symbol
    );
    Ok(())
}

fn is_plain_rust_identifier(symbol: &str) -> bool {
    let mut chars = symbol.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn validate_rust_call_selector(claim_id: &str, label: &str, selector: &str) -> Result<()> {
    ensure!(
        !selector.trim().is_empty(),
        "{} {} missing",
        claim_id,
        label
    );
    ensure!(
        parse_rust_call_selector(selector).is_some(),
        "{} {} {} must be a bare Rust identifier or conservative path-qualified call selector",
        claim_id,
        label,
        selector
    );
    Ok(())
}

fn validate_rust_caller_symbol(claim_id: &str, label: &str, symbol: &str) -> Result<()> {
    if let Some((impl_type, method)) = symbol.split_once("::") {
        ensure!(
            !method.contains("::"),
            "{} {} {} must be either a Rust identifier or TypeName::method_name",
            claim_id,
            label,
            symbol
        );
        validate_rust_symbol(claim_id, "implementation binding caller type", impl_type)?;
        validate_rust_symbol(claim_id, label, method)?;
        return Ok(());
    }
    validate_rust_symbol(claim_id, label, symbol)
}

fn rust_caller_symbol_leaf(symbol: &str) -> &str {
    symbol
        .rsplit_once("::")
        .map_or(symbol, |(_, method)| method)
}

fn rust_module_is_exactly_test_only(
    attrs: &[syn::Attribute],
    source_path: &Path,
    module_name: &str,
) -> Result<bool> {
    let mut test_only = false;
    for attr in attrs {
        if attr.path().is_ident("path") || attr.path().is_ident("cfg_attr") {
            let attr_name = if attr.path().is_ident("path") {
                "path"
            } else {
                "cfg_attr"
            };
            return Err(anyhow!(
                "implementation binding module {module_name} in {} uses unsupported compiler-selected attribute {}",
                source_path.display(),
                attr_name
            ));
        }
        if attr.path().is_ident("cfg") {
            let is_exact_test = matches!(
                &attr.meta,
                syn::Meta::List(list) if list.tokens.to_string() == "test"
            );
            ensure!(
                is_exact_test,
                "implementation binding module {module_name} in {} uses unsupported production cfg; only #[cfg(test)] file modules may be excluded",
                source_path.display()
            );
            test_only = true;
        }
    }
    Ok(test_only)
}

/// Collect ordinary non-test file-module declarations in source order.
#[cfg(test)]
fn rust_non_test_file_submodules(source: &str, source_path: &Path) -> Result<Vec<String>> {
    let parsed = syn::parse_file(source).with_context(|| {
        format!(
            "parse {} implementation binding module source",
            source_path.display()
        )
    })?;
    let mut submodules = Vec::new();
    for item in parsed.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module.content.is_some()
            || rust_module_is_exactly_test_only(
                &module.attrs,
                source_path,
                &module.ident.to_string(),
            )?
        {
            continue;
        }
        submodules.push(module.ident.to_string());
    }
    Ok(submodules)
}

fn rust_child_module_directory(source_path: &Path) -> Result<PathBuf> {
    let parent = source_path.parent().unwrap_or_else(|| Path::new(""));
    let file_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow!(
                "implementation binding module path is not UTF-8: {}",
                source_path.display()
            )
        })?;
    if matches!(file_name, "lib.rs" | "main.rs" | "mod.rs") {
        return Ok(parent.to_path_buf());
    }
    let stem = source_path.file_stem().ok_or_else(|| {
        anyhow!(
            "implementation binding module path has no file stem: {}",
            source_path.display()
        )
    })?;
    Ok(parent.join(stem))
}

fn rust_module_candidate_exists(root: &Path, relative: &Path) -> Result<bool> {
    match fs::symlink_metadata(root.join(relative)) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| {
            format!(
                "inspect implementation binding module candidate {}",
                relative.display()
            )
        }),
    }
}

fn parse_rust_binding_module_source(source: &str, source_path: &Path) -> Result<syn::File> {
    let sanitized = sanitize_rust_source(source);
    let mut cursor = 0usize;
    while let Some(include_start) = find_rust_token(&sanitized, "include", cursor) {
        let bang = skip_ascii_whitespace(&sanitized, include_start + "include".len());
        ensure!(
            sanitized.as_bytes().get(bang) != Some(&b'!'),
            "implementation binding source {} uses unsupported include! source injection",
            source_path.display()
        );
        cursor = include_start + "include".len();
    }
    syn::parse_file(source).with_context(|| {
        format!(
            "parse {} implementation binding module source",
            source_path.display()
        )
    })
}

fn collect_rust_external_module_sources(
    root: &Path,
    source_path: &Path,
    items: &[syn::Item],
    module_dir: &Path,
    seen: &mut BTreeSet<PathBuf>,
    expanded_bytes: &mut u64,
    sources: &mut Vec<(String, String)>,
) -> Result<()> {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let module_name = module.ident.to_string();
        if rust_module_is_exactly_test_only(&module.attrs, source_path, &module_name)? {
            continue;
        }
        if let Some((_, inline_items)) = &module.content {
            collect_rust_external_module_sources(
                root,
                source_path,
                inline_items,
                &module_dir.join(&module_name),
                seen,
                expanded_bytes,
                sources,
            )?;
            continue;
        }

        let flat = module_dir.join(format!("{module_name}.rs"));
        let directory = module_dir.join(&module_name).join("mod.rs");
        let mut candidates = Vec::new();
        for candidate in [flat, directory] {
            if rust_module_candidate_exists(root, &candidate)? {
                candidates.push(candidate);
            }
        }
        ensure!(
            candidates.len() == 1,
            "implementation binding module {module_name} declared in {} must resolve to exactly one ordinary source file; found {}",
            source_path.display(),
            candidates.len()
        );
        let relative = candidates.pop().expect("one candidate established");
        ensure!(
            seen.insert(relative.clone()),
            "implementation binding module source is selected more than once: {}",
            relative.display()
        );
        ensure!(
            sources.len() < 4096,
            "implementation binding module expansion exceeds file bound 4096"
        );
        let relative_raw = relative.to_str().ok_or_else(|| {
            anyhow!(
                "implementation binding module path is not UTF-8: {}",
                relative.display()
            )
        })?;
        let bytes = read_repo_relative_regular_file_bounded(
            root,
            relative_raw,
            "implementation binding module member",
            MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
        )?;
        let child_source = String::from_utf8(bytes).with_context(|| {
            format!("decode {relative_raw} implementation binding module member as UTF-8")
        })?;
        *expanded_bytes = expanded_bytes
            .checked_add(child_source.len() as u64)
            .ok_or_else(|| anyhow!("implementation binding expanded source size overflow"))?;
        ensure!(
            *expanded_bytes <= MAX_BLUEPRINT_REVIEW_EXPANDED_SOURCE_BYTES,
            "implementation binding expanded source exceeds byte bound {} at {}",
            MAX_BLUEPRINT_REVIEW_EXPANDED_SOURCE_BYTES,
            relative_raw
        );
        let parsed = parse_rust_binding_module_source(&child_source, &relative)?;
        let child_module_dir = rust_child_module_directory(&relative)?;
        sources.push((relative_raw.to_owned(), child_source));
        collect_rust_external_module_sources(
            root,
            &relative,
            &parsed.items,
            &child_module_dir,
            seen,
            expanded_bytes,
            sources,
        )?;
    }
    Ok(())
}

/// Load every compiler-selected ordinary source file denoted by a Rust binding
/// path. Compiler-selection attributes are rejected because this checker does
/// not evaluate Cargo/rustc cfg state. Callers reuse this exact file set for
/// semantic analysis and target-review hashing.
fn rust_binding_module_sources(root: &Path, raw_path: &str) -> Result<Vec<(String, String)>> {
    let source_bytes = read_repo_relative_regular_file_bounded(
        root,
        raw_path,
        "implementation binding source",
        MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
    )?;
    let source = String::from_utf8(source_bytes)
        .with_context(|| format!("decode {raw_path} implementation binding source as UTF-8"))?;
    let source_path = Path::new(raw_path);
    let parsed = parse_rust_binding_module_source(&source, source_path)?;
    let module_dir = rust_child_module_directory(source_path)?;
    let mut expanded_bytes = source.len() as u64;
    let mut seen = BTreeSet::from([source_path.to_path_buf()]);
    let mut sources = vec![(raw_path.to_owned(), source)];
    collect_rust_external_module_sources(
        root,
        source_path,
        &parsed.items,
        &module_dir,
        &mut seen,
        &mut expanded_bytes,
        &mut sources,
    )?;
    Ok(sources)
}

/// Prove that a direct-file implementation binding is reached from the crate's
/// library root through only ordinary, unconditional external module
/// declarations. This is deliberately stricter than Rust's full module
/// selection grammar: a reviewed production caller must not disappear behind
/// `cfg`, `cfg_attr`, `path`, an inline replacement module, or a different
/// default source file while the checker continues to inspect stale text.
fn validate_unconditional_rust_module_inclusion_chain(
    root: &Path,
    raw_path: &str,
    claim_id: &str,
    callee: &str,
) -> Result<()> {
    let source_path = Path::new(raw_path);
    let src_dir = source_path
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "src"))
        .ok_or_else(|| {
            anyhow!(
                "{} implementation binding for {} must live below a crate src directory",
                claim_id,
                callee
            )
        })?;
    let crate_root = src_dir.join("lib.rs");
    ensure!(
        rust_module_candidate_exists(root, &crate_root)?,
        "{} implementation binding for {} requires an ordinary crate library root at {}",
        claim_id,
        callee,
        crate_root.display()
    );

    let relative_target = source_path.strip_prefix(src_dir).with_context(|| {
        format!(
            "resolve {} implementation binding below {}",
            source_path.display(),
            src_dir.display()
        )
    })?;
    let mut module_segments = relative_target
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("implementation binding module segment is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    let file_name = relative_target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("implementation binding target file name is not UTF-8"))?;
    match file_name {
        "lib.rs" => ensure!(
            module_segments.is_empty(),
            "{} implementation binding for {} has a nested lib.rs target",
            claim_id,
            callee
        ),
        "mod.rs" => {}
        _ => {
            let stem = relative_target
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| anyhow!("implementation binding target stem is not UTF-8"))?;
            module_segments.push(stem.to_owned());
        }
    }

    let mut current = crate_root;
    if module_segments.is_empty() {
        ensure!(
            current == source_path,
            "{} implementation binding for {} is not the ordinary crate root",
            claim_id,
            callee
        );
        return Ok(());
    }
    for module_name in module_segments {
        let current_raw = current.to_str().ok_or_else(|| {
            anyhow!(
                "implementation binding inclusion path is not UTF-8: {}",
                current.display()
            )
        })?;
        let current_bytes = read_repo_relative_regular_file_bounded(
            root,
            current_raw,
            "implementation binding module inclusion source",
            MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
        )?;
        let current_source = String::from_utf8(current_bytes)
            .with_context(|| format!("decode {current_raw} module inclusion source as UTF-8"))?;
        let parsed = parse_rust_binding_module_source(&current_source, &current)?;
        ensure!(
            !parsed
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr")),
            "{} implementation binding for {} requires an unconditional enclosing Rust module file {}",
            claim_id,
            callee,
            current.display()
        );
        let declarations = parsed
            .items
            .iter()
            .filter_map(|item| {
                let syn::Item::Mod(module) = item else {
                    return None;
                };
                (module.ident == module_name).then_some(module)
            })
            .collect::<Vec<_>>();
        ensure!(
            declarations.len() == 1,
            "{} implementation binding for {} requires exactly one top-level module declaration for {} in {}",
            claim_id,
            callee,
            module_name,
            current.display()
        );
        let declaration = declarations[0];
        ensure!(
            declaration.attrs.is_empty() && declaration.content.is_none(),
            "{} implementation binding for {} requires an attribute-free ordinary external module declaration for {} in {}",
            claim_id,
            callee,
            module_name,
            current.display()
        );
        let module_dir = rust_child_module_directory(&current)?;
        let flat = module_dir.join(format!("{module_name}.rs"));
        let directory = module_dir.join(&module_name).join("mod.rs");
        let mut candidates = Vec::new();
        for candidate in [flat, directory] {
            if rust_module_candidate_exists(root, &candidate)? {
                candidates.push(candidate);
            }
        }
        ensure!(
            candidates.len() == 1,
            "{} implementation binding for {} module {} in {} must resolve to exactly one ordinary source file; found {}",
            claim_id,
            callee,
            module_name,
            current.display(),
            candidates.len()
        );
        current = candidates.pop().expect("one module source established");
    }
    ensure!(
        current == source_path,
        "{} implementation binding for {} ordinary module chain resolves to {}, not {}",
        claim_id,
        callee,
        current.display(),
        source_path.display()
    );
    Ok(())
}

fn canonical_path(path: &Path, context: &str) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("canonicalize {context} {}", path.display()))
}

fn validate_native_node_parent_struct(root: &Path) -> Result<()> {
    let raw_path = "node/src/native/mod.rs";
    let source = String::from_utf8(read_repo_relative_regular_file_bounded(
        root,
        raw_path,
        "native parent type source",
        MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
    )?)
    .context("decode native parent type source as UTF-8")?;
    let parsed = parse_rust_binding_module_source(&source, Path::new(raw_path))?;
    let structures = parsed
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Struct(structure) = item else {
                return None;
            };
            (structure.ident == "NativeNode").then_some(structure)
        })
        .collect::<Vec<_>>();
    ensure!(
        structures.len() == 1,
        "native binding requires exactly one top-level NativeNode struct declaration"
    );
    let structure = structures[0];
    ensure!(
        structure.attrs.is_empty()
            && matches!(structure.vis, syn::Visibility::Public(_))
            && structure.generics.params.is_empty()
            && structure.generics.where_clause.is_none(),
        "native binding requires one unconditional nongeneric public NativeNode struct"
    );
    let syn::Fields::Named(fields) = &structure.fields else {
        return Err(anyhow!("native binding requires named NativeNode fields"));
    };
    for expected in [
        "meta_tree",
        "height_tree",
        "block_tree",
        "commitment_tree",
        "nullifier_tree",
        "bridge_inbound_tree",
        "ciphertext_index_tree",
        "ciphertext_archive_tree",
        "da_ciphertext_tree",
        "action_tree",
        "poseidon2_v8_tree",
    ] {
        let matches = fields
            .named
            .iter()
            .filter(|field| field.ident.as_ref().is_some_and(|ident| ident == expected))
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1
                && matches[0].attrs.is_empty()
                && matches!(matches[0].vis, syn::Visibility::Inherited)
                && syn_type_path_is_segments(&matches[0].ty, &["sled", "Tree"]),
            "native binding requires private attribute-free sled::Tree field {} on NativeNode",
            expected
        );
    }
    ensure!(
        !parsed.items.iter().any(|item| {
            matches!(item, syn::Item::Type(alias) if alias.ident == "NativeNode")
                || matches!(item, syn::Item::Enum(item) if item.ident == "NativeNode")
                || matches!(item, syn::Item::Union(item) if item.ident == "NativeNode")
        }),
        "native binding rejects aliases or alternate top-level NativeNode declarations"
    );
    Ok(())
}

fn v8_atomic_runtime_gate_ast_blake3(
    block_flow_functions: &[(&str, &syn::ItemFn)],
    raw_apply: &syn::ImplItemFn,
) -> String {
    let mut hasher = blake3::Hasher::new();
    for (name, function) in block_flow_functions {
        update_domain_separated_bytes(
            &mut hasher,
            "v8-atomic-runtime-function-name-v1",
            name.as_bytes(),
        );
        update_domain_separated_bytes(
            &mut hasher,
            "v8-atomic-runtime-function-signature-v1",
            function.sig.to_token_stream().to_string().as_bytes(),
        );
        update_domain_separated_bytes(
            &mut hasher,
            "v8-atomic-runtime-function-body-v1",
            function.block.to_token_stream().to_string().as_bytes(),
        );
    }
    update_domain_separated_bytes(
        &mut hasher,
        "v8-atomic-runtime-function-name-v1",
        b"Poseidon2V8StateStore::apply_canonical_plan_in_transaction",
    );
    update_domain_separated_bytes(
        &mut hasher,
        "v8-atomic-runtime-function-signature-v1",
        raw_apply.sig.to_token_stream().to_string().as_bytes(),
    );
    update_domain_separated_bytes(
        &mut hasher,
        "v8-atomic-runtime-function-body-v1",
        raw_apply.block.to_token_stream().to_string().as_bytes(),
    );
    hasher.finalize().to_hex().to_string()
}

fn validate_v8_atomic_runtime_gate_sources(
    block_flow_source: &str,
    node_impl_source: &str,
    state_source: &str,
) -> Result<()> {
    let block_flow_raw = "node/src/native/block_flow.rs";
    let block_flow =
        parse_rust_binding_module_source(&block_flow_source, Path::new(block_flow_raw))?;
    let mut bound_block_flow_functions =
        Vec::with_capacity(V8_ATOMIC_MANIFEST_RUNTIME_FUNCTIONS.len());
    for expected in V8_ATOMIC_MANIFEST_RUNTIME_FUNCTIONS {
        let functions = block_flow
            .items
            .iter()
            .filter_map(|item| {
                let syn::Item::Fn(function) = item else {
                    return None;
                };
                (function.sig.ident == expected).then_some(function)
            })
            .collect::<Vec<_>>();
        ensure!(
            functions.len() == 1
                && functions[0].sig.constness.is_none()
                && functions[0].sig.asyncness.is_none()
                && functions[0].sig.unsafety.is_none()
                && functions[0].sig.abi.is_none()
                && functions[0].sig.generics.params.is_empty()
                && functions[0].sig.generics.where_clause.is_none()
                && !syn_item_fn_has_runtime_gate_variance(functions[0]),
            "V8 atomic manifest source requires one synchronous macro-free cfg-invariant function {}",
            expected
        );
        bound_block_flow_functions.push((*expected, functions[0]));
    }

    let node_impl_raw = "node/src/native/node_impl.rs";
    let node_impl = parse_rust_binding_module_source(node_impl_source, Path::new(node_impl_raw))?;
    for expected in V8_ATOMIC_NODE_IMPL_RUNTIME_FUNCTIONS {
        let functions = node_impl
            .items
            .iter()
            .filter_map(|item| {
                let syn::Item::Fn(function) = item else {
                    return None;
                };
                (function.sig.ident == expected).then_some(function)
            })
            .collect::<Vec<_>>();
        ensure!(
            functions.len() == 1
                && functions[0].sig.constness.is_none()
                && functions[0].sig.asyncness.is_none()
                && functions[0].sig.unsafety.is_none()
                && functions[0].sig.abi.is_none()
                && functions[0].sig.generics.params.is_empty()
                && functions[0].sig.generics.where_clause.is_none()
                && !syn_item_fn_has_compiler_selection(functions[0]),
            "V8 atomic manifest source requires one synchronous cfg-invariant function {}",
            expected
        );
        bound_block_flow_functions.push((*expected, functions[0]));
    }

    let state_raw = "node/src/native/poseidon2_v8_state.rs";
    let state = parse_rust_binding_module_source(&state_source, Path::new(state_raw))?;
    let raw_apply = state
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Impl(item_impl) = item else {
                return None;
            };
            if item_impl.trait_.is_some()
                || !syn_impl_self_type_is_one_segment(item_impl, "Poseidon2V8StateStore")
            {
                return None;
            }
            Some(item_impl)
        })
        .flat_map(|item_impl| {
            item_impl.items.iter().filter_map(move |item| {
                let syn::ImplItem::Fn(function) = item else {
                    return None;
                };
                (function.sig.ident == "apply_canonical_plan_in_transaction")
                    .then_some((item_impl, function))
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        raw_apply.len() == 1
            && !syn_item_impl_has_compiler_selection_attribute(raw_apply[0].0)
            && raw_apply[0].1.sig.constness.is_none()
            && raw_apply[0].1.sig.asyncness.is_none()
            && raw_apply[0].1.sig.unsafety.is_none()
            && raw_apply[0].1.sig.abi.is_none()
            && raw_apply[0].1.sig.generics.params.is_empty()
            && raw_apply[0].1.sig.generics.where_clause.is_none()
            && !syn_impl_item_fn_has_runtime_gate_variance(raw_apply[0].1),
        "V8 atomic source requires one synchronous macro-free cfg-invariant raw typed-plan apply"
    );
    let actual_ast_blake3 =
        v8_atomic_runtime_gate_ast_blake3(&bound_block_flow_functions, raw_apply[0].1);
    ensure!(
        actual_ast_blake3 == EXPECTED_V8_ATOMIC_RUNTIME_GATE_AST_BLAKE3,
        "V8 atomic runtime AST changed without an explicit checker-policy update: expected {}, actual {}",
        EXPECTED_V8_ATOMIC_RUNTIME_GATE_AST_BLAKE3,
        actual_ast_blake3
    );
    Ok(())
}

fn validate_v8_atomic_runtime_gate_bodies(root: &Path) -> Result<()> {
    let block_flow_raw = "node/src/native/block_flow.rs";
    let block_flow_source = String::from_utf8(read_repo_relative_regular_file_bounded(
        root,
        block_flow_raw,
        "V8 atomic manifest evaluator source",
        MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
    )?)
    .context("decode V8 atomic manifest evaluator source as UTF-8")?;
    let node_impl_raw = "node/src/native/node_impl.rs";
    let node_impl_source = String::from_utf8(read_repo_relative_regular_file_bounded(
        root,
        node_impl_raw,
        "V8 transaction-local atomic commit source",
        MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
    )?)
    .context("decode V8 transaction-local atomic commit source as UTF-8")?;
    let state_raw = "node/src/native/poseidon2_v8_state.rs";
    let state_source = String::from_utf8(read_repo_relative_regular_file_bounded(
        root,
        state_raw,
        "V8 typed plan apply source",
        MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
    )?)
    .context("decode V8 typed plan apply source as UTF-8")?;
    validate_v8_atomic_runtime_gate_sources(&block_flow_source, &node_impl_source, &state_source)?;
    Ok(())
}

/// Pin the dedicated production binding to the workspace package and operator
/// binary selected by Cargo, rather than trusting default-path source text in
/// isolation. Cargo configuration, the Cargo executable, and final artifact
/// deployment remain explicit supply-chain boundaries.
fn validate_native_node_cargo_target_selection(root: &Path, raw_path: &str) -> Result<()> {
    if raw_path != "node/src/native/node_impl.rs" {
        return Ok(());
    }
    for required_source in [
        "Cargo.toml",
        "node/Cargo.toml",
        "node/src/lib.rs",
        "node/src/bin/native_node.rs",
    ] {
        let _ = read_repo_relative_regular_file_bounded(
            root,
            required_source,
            "native cargo target source",
            MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
        )?;
    }
    validate_native_node_parent_struct(root)?;
    validate_v8_atomic_runtime_gate_bodies(root)?;
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
        ])
        .current_dir(root)
        .output()
        .context("run locked offline cargo metadata for native binding")?;
    ensure!(
        output.status.success(),
        "native binding cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("parse native binding cargo metadata")?;
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .ok_or_else(|| anyhow!("native binding cargo metadata is missing workspace_members"))?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>();
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| anyhow!("native binding cargo metadata is missing packages"))?;
    let node_packages = packages
        .iter()
        .filter(|package| {
            package["name"].as_str() == Some("hegemon-node")
                && package["id"]
                    .as_str()
                    .is_some_and(|id| workspace_members.contains(id))
        })
        .collect::<Vec<_>>();
    ensure!(
        node_packages.len() == 1,
        "native binding cargo metadata must select exactly one hegemon-node workspace package"
    );
    let package = node_packages[0];
    let manifest = package["manifest_path"]
        .as_str()
        .ok_or_else(|| anyhow!("hegemon-node cargo metadata is missing manifest_path"))?;
    ensure!(
        canonical_path(Path::new(manifest), "native package manifest")?
            == canonical_path(
                &root.join("node/Cargo.toml"),
                "expected native package manifest"
            )?,
        "native binding cargo metadata selects the wrong hegemon-node manifest"
    );
    let targets = package["targets"]
        .as_array()
        .ok_or_else(|| anyhow!("hegemon-node cargo metadata is missing targets"))?;
    let target_matches = |kind: &str, name: &str, expected_source: &str| -> Result<usize> {
        let expected = canonical_path(&root.join(expected_source), "expected native target")?;
        targets
            .iter()
            .filter(|target| {
                target["name"].as_str() == Some(name)
                    && target["kind"]
                        .as_array()
                        .is_some_and(|kinds| kinds.iter().any(|value| value.as_str() == Some(kind)))
            })
            .try_fold(0usize, |count, target| {
                let source = target["src_path"]
                    .as_str()
                    .ok_or_else(|| anyhow!("native cargo target is missing src_path"))?;
                ensure!(
                    canonical_path(Path::new(source), "selected native target")? == expected,
                    "native binding cargo metadata selects the wrong {kind} source for {name}"
                );
                Ok(count + 1)
            })
    };
    ensure!(
        target_matches("lib", "hegemon_node", "node/src/lib.rs")? == 1,
        "native binding cargo metadata must select exactly one hegemon_node library"
    );
    ensure!(
        target_matches("bin", "hegemon-node", "node/src/bin/native_node.rs")? == 1,
        "native binding cargo metadata must select exactly one hegemon-node operator binary"
    );
    Ok(())
}

fn syn_impl_self_type_is_exact(item_impl: &syn::ItemImpl, expected: &str) -> bool {
    let syn::Type::Path(type_path) = item_impl.self_ty.as_ref() else {
        return false;
    };
    type_path.qself.is_none()
        && type_path.path.leading_colon.is_none()
        && type_path.path.segments.len() == 2
        && type_path.path.segments[0].ident == "super"
        && type_path.path.segments[1].ident == expected
        && type_path
            .path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, syn::PathArguments::None))
}

fn syn_impl_self_type_is_one_segment(item_impl: &syn::ItemImpl, expected: &str) -> bool {
    let syn::Type::Path(type_path) = item_impl.self_ty.as_ref() else {
        return false;
    };
    type_path.qself.is_none()
        && type_path.path.leading_colon.is_none()
        && type_path.path.segments.len() == 1
        && type_path.path.segments[0].ident == expected
        && matches!(
            type_path.path.segments[0].arguments,
            syn::PathArguments::None
        )
}

fn syn_plain_path_is(expression: &syn::Expr, expected: &str) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].ident == expected
        && matches!(path.path.segments[0].arguments, syn::PathArguments::None)
}

fn syn_path_is_segments(expression: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| {
                segment.ident == *expected && matches!(segment.arguments, syn::PathArguments::None)
            })
}

fn syn_expr_contains_pinned_sled_transaction(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Call(call) => {
            syn_path_is_segments(
                &call.func,
                &[
                    "self",
                    "__hegemon_pinned_sled",
                    "transaction",
                    "Transactional",
                    "transaction",
                ],
            ) || syn_expr_contains_pinned_sled_transaction(&call.func)
                || call
                    .args
                    .iter()
                    .any(syn_expr_contains_pinned_sled_transaction)
        }
        syn::Expr::MethodCall(call) => {
            syn_expr_contains_pinned_sled_transaction(&call.receiver)
                || call
                    .args
                    .iter()
                    .any(syn_expr_contains_pinned_sled_transaction)
        }
        syn::Expr::Try(try_expression) => {
            syn_expr_contains_pinned_sled_transaction(&try_expression.expr)
        }
        syn::Expr::Await(await_expression) => {
            syn_expr_contains_pinned_sled_transaction(&await_expression.base)
        }
        syn::Expr::Group(group) => syn_expr_contains_pinned_sled_transaction(&group.expr),
        syn::Expr::Paren(paren) => syn_expr_contains_pinned_sled_transaction(&paren.expr),
        syn::Expr::Reference(reference) => {
            syn_expr_contains_pinned_sled_transaction(&reference.expr)
        }
        _ => false,
    }
}

fn syn_direct_pinned_transaction_statement_indices(method: &syn::ImplItemFn) -> Vec<usize> {
    method
        .block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let syn::Stmt::Expr(expression, _) = statement else {
                return None;
            };
            syn_expr_contains_pinned_sled_transaction(expression).then_some(index)
        })
        .collect()
}

#[derive(Default)]
struct RustOuterSuccessfulEscapeVisitor {
    closure_depth: usize,
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for RustOuterSuccessfulEscapeVisitor {
    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.closure_depth += 1;
        syn::visit::visit_expr_closure(self, closure);
        self.closure_depth -= 1;
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        if self.closure_depth == 0
            && !expression
                .expr
                .as_deref()
                .and_then(|returned| syn_call_path_is(returned, &["Err"]))
                .is_some_and(|err| err.args.len() == 1)
        {
            self.found = true;
            return;
        }
        syn::visit::visit_expr_return(self, expression);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        if self.closure_depth == 0
            && !expression.mac.path.is_ident("anyhow")
            && !expression.mac.path.is_ident("format")
        {
            self.found = true;
            return;
        }
        syn::visit::visit_expr_macro(self, expression);
    }

    fn visit_stmt_macro(&mut self, _statement: &'ast syn::StmtMacro) {
        if self.closure_depth == 0 {
            self.found = true;
        }
    }
}

fn syn_statements_have_outer_successful_escape_or_unknown_macro(statements: &[syn::Stmt]) -> bool {
    use syn::visit::Visit;

    let mut visitor = RustOuterSuccessfulEscapeVisitor::default();
    for statement in statements {
        visitor.visit_stmt(statement);
        if visitor.found {
            return true;
        }
    }
    false
}

#[derive(Default)]
struct RustRuntimeGateVarianceVisitor {
    allow_atomic_kind_matches: bool,
    atomic_kind_matches_seen: usize,
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for RustRuntimeGateVarianceVisitor {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr") {
            self.found = true;
            return;
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let pinned_atomic_kind_matches = self.allow_atomic_kind_matches
            && mac.path.is_ident("matches")
            && compact_ascii_whitespace(&mac.tokens.to_string())
                == "input.kind,NativeAtomicCommitKind::MinedBlockCommit|NativeAtomicCommitKind::TipExtensionBatchCommit";
        if pinned_atomic_kind_matches {
            self.atomic_kind_matches_seen += 1;
            if self.atomic_kind_matches_seen > 1 {
                self.found = true;
            }
        } else {
            self.found = true;
        }
    }
}

fn syn_item_fn_has_runtime_gate_variance(function: &syn::ItemFn) -> bool {
    use syn::visit::Visit;

    let allow_atomic_kind_matches =
        function.sig.ident == "evaluate_native_atomic_commit_manifest_admission";
    let mut visitor = RustRuntimeGateVarianceVisitor {
        allow_atomic_kind_matches,
        ..RustRuntimeGateVarianceVisitor::default()
    };
    visitor.visit_item_fn(function);
    visitor.found || (allow_atomic_kind_matches && visitor.atomic_kind_matches_seen != 1)
}

fn syn_item_fn_has_compiler_selection(function: &syn::ItemFn) -> bool {
    use syn::visit::Visit;

    #[derive(Default)]
    struct CompilerSelectionVisitor {
        found: bool,
    }

    impl<'ast> Visit<'ast> for CompilerSelectionVisitor {
        fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
            if attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr") {
                self.found = true;
                return;
            }
            syn::visit::visit_attribute(self, attribute);
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("cfg")
                || mac.path.is_ident("env")
                || mac.path.is_ident("option_env")
            {
                self.found = true;
                return;
            }
            syn::visit::visit_macro(self, mac);
        }
    }

    let mut visitor = CompilerSelectionVisitor::default();
    visitor.visit_item_fn(function);
    visitor.found
}

fn syn_impl_item_fn_has_runtime_gate_variance(function: &syn::ImplItemFn) -> bool {
    use syn::visit::Visit;

    let mut visitor = RustRuntimeGateVarianceVisitor::default();
    visitor.visit_impl_item_fn(function);
    visitor.found
}

fn syn_item_impl_has_compiler_selection_attribute(item_impl: &syn::ItemImpl) -> bool {
    item_impl
        .attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

fn syn_parent_call_is<'a>(expression: &'a syn::Expr, expected: &str) -> Option<&'a syn::ExprCall> {
    let syn::Expr::Call(call) = expression else {
        return None;
    };
    (call.attrs.is_empty() && syn_path_is_segments(&call.func, &["super", expected]))
        .then_some(call)
}

fn syn_self_call_is<'a>(expression: &'a syn::Expr, expected: &str) -> Option<&'a syn::ExprCall> {
    let syn::Expr::Call(call) = expression else {
        return None;
    };
    (call.attrs.is_empty() && syn_path_is_segments(&call.func, &["self", expected])).then_some(call)
}

fn syn_type_path_is_segments(ty: &syn::Type, expected: &[&str]) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| {
                segment.ident == *expected && matches!(segment.arguments, syn::PathArguments::None)
            })
}

fn syn_fn_arg_is_reference_path(
    argument: &syn::FnArg,
    binding: &str,
    expected_type: &[&str],
) -> bool {
    let syn::FnArg::Typed(argument) = argument else {
        return false;
    };
    let syn::Type::Reference(reference) = argument.ty.as_ref() else {
        return false;
    };
    argument.attrs.is_empty()
        && syn_plain_pat_ident_is(&argument.pat, binding)
        && reference.lifetime.is_none()
        && reference.mutability.is_none()
        && syn_type_path_is_segments(&reference.elem, expected_type)
}

fn syn_fn_arg_is_reference_slice_path(
    argument: &syn::FnArg,
    binding: &str,
    expected_element: &[&str],
) -> bool {
    let syn::FnArg::Typed(argument) = argument else {
        return false;
    };
    let syn::Type::Reference(reference) = argument.ty.as_ref() else {
        return false;
    };
    let syn::Type::Slice(slice) = reference.elem.as_ref() else {
        return false;
    };
    argument.attrs.is_empty()
        && syn_plain_pat_ident_is(&argument.pat, binding)
        && reference.lifetime.is_none()
        && reference.mutability.is_none()
        && syn_type_path_is_segments(&slice.elem, expected_element)
}

fn syn_fn_arg_is_path(argument: &syn::FnArg, binding: &str, expected_type: &[&str]) -> bool {
    let syn::FnArg::Typed(argument) = argument else {
        return false;
    };
    argument.attrs.is_empty()
        && syn_plain_pat_ident_is(&argument.pat, binding)
        && syn_type_path_is_segments(&argument.ty, expected_type)
}

fn syn_fn_arg_is_owned_v8_reorg(argument: &syn::FnArg) -> bool {
    let syn::FnArg::Typed(argument) = argument else {
        return false;
    };
    let syn::Type::Path(option) = argument.ty.as_ref() else {
        return false;
    };
    if !argument.attrs.is_empty()
        || !syn_plain_pat_ident_is(&argument.pat, "poseidon2_v8_reorg")
        || option.qself.is_some()
        || option.path.leading_colon.is_some()
        || option.path.segments.len() != 1
        || option.path.segments[0].ident != "Option"
    {
        return false;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &option.path.segments[0].arguments else {
        return false;
    };
    let Some(syn::GenericArgument::Type(syn::Type::Tuple(tuple))) = arguments.args.first() else {
        return false;
    };
    arguments.args.len() == 1
        && tuple.elems.len() == 2
        && syn_type_path_is_segments(
            &tuple.elems[0],
            &["poseidon2_v8_state", "Poseidon2V8StateStore"],
        )
        && syn_type_path_is_segments(
            &tuple.elems[1],
            &["poseidon2_v8_state", "Poseidon2V8CanonicalPlan"],
        )
}

fn syn_return_type_is_result_unit(output: &syn::ReturnType) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    let syn::Type::Path(path) = ty.as_ref() else {
        return false;
    };
    if path.qself.is_some()
        || path.path.leading_colon.is_some()
        || path.path.segments.len() != 1
        || path.path.segments[0].ident != "Result"
    {
        return false;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &path.path.segments[0].arguments else {
        return false;
    };
    arguments.args.len() == 1
        && matches!(arguments.args.first(), Some(syn::GenericArgument::Type(syn::Type::Tuple(tuple)))
            if tuple.elems.is_empty())
}

fn validate_v8_atomic_method_signature(
    method_name: &str,
    method: &syn::ImplItemFn,
    claim_id: &str,
) -> Result<()> {
    let signature = &method.sig;
    let visibility_matches = match method_name {
        "commit_reorg_suffix_atomically" => matches!(method.vis, syn::Visibility::Inherited),
        "commit_mined_block_atomically" => {
            matches!(&method.vis, syn::Visibility::Restricted(restricted)
            if restricted.in_token.is_none()
                && restricted.path.leading_colon.is_none()
                && restricted.path.segments.len() == 1
                && restricted.path.segments[0].ident == "crate"
                && matches!(restricted.path.segments[0].arguments, syn::PathArguments::None))
        }
        _ => false,
    };
    ensure!(
        method.attrs.is_empty()
            && method.defaultness.is_none()
            && visibility_matches
            && signature.constness.is_none()
            && signature.asyncness.is_none()
            && signature.unsafety.is_none()
            && signature.abi.is_none()
            && signature.generics.params.is_empty()
            && signature.generics.where_clause.is_none()
            && signature.variadic.is_none()
            && syn_return_type_is_result_unit(&signature.output),
        "{} V8 atomic caller {} must keep its exact synchronous fallible signature",
        claim_id,
        method_name
    );
    let Some(syn::FnArg::Receiver(receiver)) = signature.inputs.first() else {
        return Err(anyhow!(
            "{} V8 atomic caller {} requires &self",
            claim_id,
            method_name
        ));
    };
    ensure!(
        receiver.attrs.is_empty()
            && receiver
                .reference
                .as_ref()
                .is_some_and(|(_, lifetime)| lifetime.is_none())
            && receiver.mutability.is_none()
            && receiver.colon_token.is_none(),
        "{} V8 atomic caller {} requires an immutable &self receiver",
        claim_id,
        method_name
    );
    let inputs = signature.inputs.iter().collect::<Vec<_>>();
    let exact = match method_name {
        "commit_reorg_suffix_atomically" => {
            inputs.len() == 6
                && syn_fn_arg_is_reference_path(inputs[1], "plan", &["NativeReorgSuffixCommitPlan"])
                && syn_fn_arg_is_reference_path(inputs[2], "best", &["NativeBlockMeta"])
                && syn_fn_arg_is_reference_path(
                    inputs[3],
                    "next_nullifier_accumulator",
                    &["NullifierAccumulator"],
                )
                && syn_fn_arg_is_owned_v8_reorg(inputs[4])
                && syn_fn_arg_is_path(inputs[5], "commit_kind", &["NativeAtomicCommitKind"])
        }
        "commit_mined_block_atomically" => {
            inputs.len() == 8
                && syn_fn_arg_is_reference_slice_path(inputs[1], "actions", &["PendingAction"])
                && syn_fn_arg_is_reference_slice_path(
                    inputs[2],
                    "planned",
                    &["NativePlannedActionEffect"],
                )
                && syn_fn_arg_is_reference_path(inputs[3], "meta", &["NativeBlockMeta"])
                && syn_fn_arg_is_reference_path(
                    inputs[4],
                    "parent_nullifier_accumulator",
                    &["NullifierAccumulator"],
                )
                && syn_fn_arg_is_reference_path(
                    inputs[5],
                    "next_nullifier_accumulator",
                    &["NullifierAccumulator"],
                )
                && syn_fn_arg_is_reference_path(
                    inputs[6],
                    "checkpoint_rows",
                    &["NativeCanonicalCheckpointRows"],
                )
                && syn_fn_arg_is_reference_slice_path(
                    inputs[7],
                    "additional_pending_action_removals",
                    &["ActionId48"],
                )
        }
        _ => false,
    };
    ensure!(
        exact,
        "{} V8 atomic caller {} parameter grammar changed",
        claim_id,
        method_name
    );
    Ok(())
}

fn syn_plain_reference_field_is(expression: &syn::Expr, base: &str, field: &str) -> bool {
    let syn::Expr::Reference(reference) = expression else {
        return false;
    };
    let syn::Expr::Field(field_expression) = reference.expr.as_ref() else {
        return false;
    };
    reference.attrs.is_empty()
        && field_expression.attrs.is_empty()
        && reference.mutability.is_none()
        && syn_plain_path_is(&field_expression.base, base)
        && matches!(&field_expression.member, syn::Member::Named(ident) if ident == field)
}

fn syn_plain_field_is(expression: &syn::Expr, base: &str, field: &str) -> bool {
    let syn::Expr::Field(field_expression) = expression else {
        return false;
    };
    field_expression.attrs.is_empty()
        && syn_plain_path_is(&field_expression.base, base)
        && matches!(&field_expression.member, syn::Member::Named(ident) if ident == field)
}

fn syn_plain_pat_ident_is(pattern: &syn::Pat, expected: &str) -> bool {
    let syn::Pat::Ident(ident) = pattern else {
        return false;
    };
    ident.attrs.is_empty()
        && ident.by_ref.is_none()
        && ident.mutability.is_none()
        && ident.subpat.is_none()
        && ident.ident == expected
}

fn syn_plain_pat_path_is(pattern: &syn::Pat, expected: &str) -> bool {
    if syn_plain_pat_ident_is(pattern, expected) {
        return true;
    }
    let syn::Pat::Path(path) = pattern else {
        return false;
    };
    path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].ident == expected
        && matches!(path.path.segments[0].arguments, syn::PathArguments::None)
}

fn syn_plain_pat_path_is_segments(pattern: &syn::Pat, expected: &[&str]) -> bool {
    let syn::Pat::Path(path) = pattern else {
        return false;
    };
    path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| {
                segment.ident == *expected && matches!(segment.arguments, syn::PathArguments::None)
            })
}

fn syn_tuple_struct_pat_is_one_ident(pattern: &syn::Pat, constructor: &str, binding: &str) -> bool {
    let syn::Pat::TupleStruct(tuple) = pattern else {
        return false;
    };
    tuple.attrs.is_empty()
        && tuple.qself.is_none()
        && tuple.path.leading_colon.is_none()
        && tuple.path.segments.len() == 1
        && tuple.path.segments[0].ident == constructor
        && matches!(tuple.path.segments[0].arguments, syn::PathArguments::None)
        && tuple.elems.len() == 1
        && syn_plain_pat_ident_is(&tuple.elems[0], binding)
}

fn syn_integer_literal_is(expression: &syn::Expr, expected: &str) -> bool {
    matches!(expression, syn::Expr::Lit(literal)
        if literal.attrs.is_empty()
            && matches!(&literal.lit, syn::Lit::Int(integer) if integer.base10_digits() == expected))
}

fn syn_string_literal_is(expression: &syn::Expr, expected: &str) -> bool {
    matches!(expression, syn::Expr::Lit(literal)
        if literal.attrs.is_empty()
            && matches!(&literal.lit, syn::Lit::Str(string) if string.value() == expected))
}

fn syn_call_path_is<'a>(expression: &'a syn::Expr, expected: &[&str]) -> Option<&'a syn::ExprCall> {
    let syn::Expr::Call(call) = expression else {
        return None;
    };
    (call.attrs.is_empty() && syn_path_is_segments(&call.func, expected)).then_some(call)
}

fn validate_transaction_local_v8_application_helper(
    helper: &syn::ItemFn,
    claim_id: &str,
) -> Result<()> {
    let statements = &helper.block.stmts;
    ensure!(
        statements.len() == 4,
        "{} V8 transaction-local helper requires exactly four ordered statements",
        claim_id
    );
    let syn::Stmt::Local(actual_local) = &statements[0] else {
        return Err(anyhow!(
            "{} V8 helper must bind the actual application count first",
            claim_id
        ));
    };
    ensure!(
        actual_local.attrs.is_empty()
            && syn_plain_pat_ident_is(&actual_local.pat, "actual_application_count"),
        "{} V8 helper actual application count binding is not canonical",
        claim_id
    );
    let Some(actual_init) = &actual_local.init else {
        return Err(anyhow!(
            "{} V8 helper actual count has no initializer",
            claim_id
        ));
    };
    let syn::Expr::Match(plan_match) = actual_init.expr.as_ref() else {
        return Err(anyhow!(
            "{} V8 helper actual count must match the plan",
            claim_id
        ));
    };
    ensure!(
        plan_match.attrs.is_empty()
            && syn_plain_path_is(&plan_match.expr, "plan")
            && plan_match.arms.len() == 2,
        "{} V8 helper plan match is not canonical",
        claim_id
    );
    let some_arm = &plan_match.arms[0];
    let none_arm = &plan_match.arms[1];
    ensure!(
        some_arm.attrs.is_empty()
            && some_arm.guard.is_none()
            && syn_tuple_struct_pat_is_one_ident(&some_arm.pat, "Some", "plan")
            && none_arm.attrs.is_empty()
            && none_arm.guard.is_none()
            && syn_plain_pat_path_is(&none_arm.pat, "None")
            && syn_integer_literal_is(&none_arm.body, "0"),
        "{} V8 helper Some/None application-count arms are not canonical",
        claim_id
    );
    let syn::Expr::Block(some_block) = some_arm.body.as_ref() else {
        return Err(anyhow!(
            "{} V8 helper Some arm must be an ordered block",
            claim_id
        ));
    };
    ensure!(
        some_block.attrs.is_empty()
            && some_block.label.is_none()
            && some_block.block.stmts.len() == 2,
        "{} V8 helper Some arm must contain only raw apply then literal one",
        claim_id
    );
    let syn::Stmt::Expr(syn::Expr::Try(raw_try), Some(_)) = &some_block.block.stmts[0] else {
        return Err(anyhow!(
            "{} V8 helper raw apply must propagate as its first Some-arm statement",
            claim_id
        ));
    };
    ensure!(
        raw_try.attrs.is_empty(),
        "{} V8 helper raw apply expression must be unconditional",
        claim_id
    );
    let Some(raw_apply) = syn_call_path_is(
        &raw_try.expr,
        &[
            "super",
            "poseidon2_v8_state",
            "Poseidon2V8StateStore",
            "apply_canonical_plan_in_transaction",
        ],
    ) else {
        return Err(anyhow!(
            "{} V8 helper calls the wrong raw typed apply",
            claim_id
        ));
    };
    ensure!(
        raw_apply.args.len() == 2
            && syn_plain_path_is(&raw_apply.args[0], "poseidon2_v8_tree")
            && syn_plain_path_is(&raw_apply.args[1], "plan")
            && matches!(&some_block.block.stmts[1], syn::Stmt::Expr(expression, None)
                if syn_integer_literal_is(expression, "1")),
        "{} V8 helper raw apply/count coupling is not canonical",
        claim_id
    );

    let syn::Stmt::Local(observed_local) = &statements[1] else {
        return Err(anyhow!(
            "{} V8 helper must bind the observed manifest second",
            claim_id
        ));
    };
    ensure!(
        observed_local.attrs.is_empty() && syn_plain_pat_ident_is(&observed_local.pat, "observed"),
        "{} V8 helper observed manifest binding is not canonical",
        claim_id
    );
    let Some(observed_init) = &observed_local.init else {
        return Err(anyhow!(
            "{} V8 helper observed manifest has no initializer",
            claim_id
        ));
    };
    let syn::Expr::Struct(observed) = observed_init.expr.as_ref() else {
        return Err(anyhow!(
            "{} V8 helper observed manifest must be a struct update",
            claim_id
        ));
    };
    ensure!(
        observed.attrs.is_empty()
            && observed.qself.is_none()
            && observed.path.leading_colon.is_none()
            && observed.path.segments.len() == 2
            && observed.path.segments[0].ident == "super"
            && observed.path.segments[1].ident == "NativeAtomicCommitManifestAdmissionInput"
            && observed.fields.len() == 1
            && observed.fields[0].attrs.is_empty()
            && matches!(&observed.fields[0].member, syn::Member::Named(ident)
                if ident == "poseidon2_v8_plan_application_count")
            && syn_plain_path_is(&observed.fields[0].expr, "actual_application_count")
            && observed
                .rest
                .as_ref()
                .is_some_and(|rest| syn_plain_path_is(rest, "manifest")),
        "{} V8 helper observed manifest must overwrite only the actual application count",
        claim_id
    );

    let syn::Stmt::Expr(syn::Expr::Try(admission_try), Some(_)) = &statements[2] else {
        return Err(anyhow!(
            "{} V8 helper must propagate manifest admission third",
            claim_id
        ));
    };
    let syn::Expr::MethodCall(map_err) = admission_try.expr.as_ref() else {
        return Err(anyhow!(
            "{} V8 helper admission must map only the rejection",
            claim_id
        ));
    };
    ensure!(
        admission_try.attrs.is_empty() && map_err.attrs.is_empty(),
        "{} V8 helper manifest admission must be unconditional",
        claim_id
    );
    let Some(admission) = syn_call_path_is(
        &map_err.receiver,
        &[
            "super",
            "block_flow",
            "evaluate_native_atomic_commit_manifest_admission",
        ],
    ) else {
        return Err(anyhow!(
            "{} V8 helper calls the wrong manifest evaluator",
            claim_id
        ));
    };
    let Some(syn::Expr::Closure(rejection_map)) = map_err.args.first() else {
        return Err(anyhow!(
            "{} V8 helper admission rejection must use one closure",
            claim_id
        ));
    };
    ensure!(
        map_err.method == "map_err"
            && map_err.turbofish.is_none()
            && map_err.args.len() == 1
            && rejection_map.attrs.is_empty()
            && rejection_map.inputs.len() == 1
            && rejection_map
                .inputs
                .first()
                .is_some_and(|pattern| syn_plain_pat_ident_is(pattern, "rejection"))
            && admission.args.len() == 1
            && syn_plain_path_is(&admission.args[0], "observed"),
        "{} V8 helper manifest admission is not canonical",
        claim_id
    );
    let syn::Expr::Block(rejection_block) = rejection_map.body.as_ref() else {
        return Err(anyhow!(
            "{} V8 helper must map rejection to a pinned sled transaction abort",
            claim_id
        ));
    };
    let abort_expression = match rejection_block.block.stmts.as_slice() {
        [syn::Stmt::Expr(expression, None)] => expression,
        _ => {
            return Err(anyhow!(
                "{} V8 helper must map rejection to a pinned sled transaction abort",
                claim_id
            ));
        }
    };
    ensure!(
        syn_call_path_is(
            abort_expression,
            &[
                "self",
                "__hegemon_pinned_sled",
                "transaction",
                "ConflictableTransactionError",
                "Abort",
            ],
        )
        .is_some_and(|abort| abort.args.len() == 1),
        "{} V8 helper must map rejection to a pinned sled transaction abort",
        claim_id
    );
    ensure!(
        matches!(&statements[3], syn::Stmt::Expr(expression, None)
        if syn_call_path_is(expression, &["Ok"]).is_some_and(|ok| {
            ok.args.len() == 1
                && syn_plain_path_is(&ok.args[0], "actual_application_count")
        })),
        "{} V8 helper must return only the transaction-produced application count",
        claim_id
    );
    Ok(())
}

fn syn_pat_binds_identifier(pattern: &syn::Pat, expected: &str) -> bool {
    match pattern {
        syn::Pat::Ident(ident) => ident.ident == expected,
        syn::Pat::Or(or) => or
            .cases
            .iter()
            .any(|pattern| syn_pat_binds_identifier(pattern, expected)),
        syn::Pat::Paren(paren) => syn_pat_binds_identifier(&paren.pat, expected),
        syn::Pat::Reference(reference) => syn_pat_binds_identifier(&reference.pat, expected),
        syn::Pat::Slice(slice) => slice
            .elems
            .iter()
            .any(|pattern| syn_pat_binds_identifier(pattern, expected)),
        syn::Pat::Struct(structure) => structure
            .fields
            .iter()
            .any(|field| syn_pat_binds_identifier(&field.pat, expected)),
        syn::Pat::Tuple(tuple) => tuple
            .elems
            .iter()
            .any(|pattern| syn_pat_binds_identifier(pattern, expected)),
        syn::Pat::TupleStruct(tuple) => tuple
            .elems
            .iter()
            .any(|pattern| syn_pat_binds_identifier(pattern, expected)),
        syn::Pat::Type(typed) => syn_pat_binds_identifier(&typed.pat, expected),
        _ => false,
    }
}

fn syn_pat_contains_macro(pattern: &syn::Pat) -> bool {
    match pattern {
        syn::Pat::Macro(_) => true,
        syn::Pat::Or(or) => or.cases.iter().any(syn_pat_contains_macro),
        syn::Pat::Paren(paren) => syn_pat_contains_macro(&paren.pat),
        syn::Pat::Reference(reference) => syn_pat_contains_macro(&reference.pat),
        syn::Pat::Slice(slice) => slice.elems.iter().any(syn_pat_contains_macro),
        syn::Pat::Struct(structure) => structure
            .fields
            .iter()
            .any(|field| syn_pat_contains_macro(&field.pat)),
        syn::Pat::Tuple(tuple) => tuple.elems.iter().any(syn_pat_contains_macro),
        syn::Pat::TupleStruct(tuple) => tuple.elems.iter().any(syn_pat_contains_macro),
        syn::Pat::Type(typed) => syn_pat_contains_macro(&typed.pat),
        _ => false,
    }
}

fn syn_direct_local_bindings<'a>(
    method: &'a syn::ImplItemFn,
    expected: &str,
) -> Vec<(usize, &'a syn::Local)> {
    method
        .block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            syn_pat_binds_identifier(&local.pat, expected).then_some((index, local))
        })
        .collect()
}

fn syn_v8_plan_projection_is(
    expression: &syn::Expr,
    receiver: &str,
    through_as_ref: bool,
    projected_binding: &str,
) -> bool {
    let syn::Expr::MethodCall(map) = expression else {
        return false;
    };
    if !map.attrs.is_empty()
        || map.method != "map"
        || !map.turbofish.is_none()
        || map.args.len() != 1
    {
        return false;
    }
    let receiver_matches = if through_as_ref {
        matches!(map.receiver.as_ref(), syn::Expr::MethodCall(as_ref)
            if as_ref.attrs.is_empty()
                && as_ref.method == "as_ref"
                && as_ref.turbofish.is_none()
                && as_ref.args.is_empty()
                && syn_plain_path_is(&as_ref.receiver, receiver))
    } else {
        syn_plain_path_is(&map.receiver, receiver)
    };
    if !receiver_matches {
        return false;
    }
    let Some(syn::Expr::Closure(closure)) = map.args.first() else {
        return false;
    };
    if !closure.attrs.is_empty()
        || closure.inputs.len() != 1
        || !syn_plain_path_is(&closure.body, projected_binding)
    {
        return false;
    }
    let Some(syn::Pat::Tuple(tuple)) = closure.inputs.first() else {
        return false;
    };
    tuple.attrs.is_empty()
        && tuple.elems.len() == 2
        && matches!(&tuple.elems[0], syn::Pat::Wild(_))
        && syn_plain_pat_ident_is(&tuple.elems[1], projected_binding)
}

fn syn_expression_is_fail_closed_return(expression: &syn::Expr) -> bool {
    let syn::Expr::Return(returned) = expression else {
        return false;
    };
    returned.attrs.is_empty()
        && returned
            .expr
            .as_deref()
            .and_then(|expression| syn_call_path_is(expression, &["Err"]))
            .is_some_and(|err| err.args.len() == 1)
}

fn syn_block_tail_is_propagated_self_call(
    block: &syn::ExprBlock,
    expected_statement_count: usize,
    expected_builder: &str,
) -> bool {
    if !block.attrs.is_empty()
        || block.label.is_some()
        || block.block.stmts.len() != expected_statement_count
    {
        return false;
    }
    let Some(syn::Stmt::Expr(syn::Expr::Try(propagated), None)) = block.block.stmts.last() else {
        return false;
    };
    propagated.attrs.is_empty()
        && syn_self_call_is(&propagated.expr, expected_builder).is_some_and(|call| {
            call.args.len() == 2
                && syn_plain_path_is(&call.args[0], "plan")
                && syn_plain_path_is(&call.args[1], "v8_plan")
        })
}

fn syn_canonical_suffix_tip_removal_guard_is(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::If(guard), None) = statement else {
        return false;
    };
    let syn::Expr::Unary(negation) = guard.cond.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(is_empty) = negation.expr.as_ref() else {
        return false;
    };
    guard.attrs.is_empty()
        && guard.else_branch.is_none()
        && matches!(negation.op, syn::UnOp::Not(_))
        && negation.attrs.is_empty()
        && is_empty.attrs.is_empty()
        && is_empty.method == "is_empty"
        && is_empty.turbofish.is_none()
        && is_empty.args.is_empty()
        && syn_plain_field_is(&is_empty.receiver, "plan", "tip_action_removals")
        && matches!(guard.then_branch.stmts.as_slice(), [syn::Stmt::Expr(expression, Some(_))]
            if syn_expression_is_fail_closed_return(expression))
}

fn syn_suffix_manifest_commit_kind_split_is(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(split) = expression else {
        return false;
    };
    if !split.attrs.is_empty()
        || !syn_plain_path_is(&split.expr, "commit_kind")
        || split.arms.len() != 3
        || split
            .arms
            .iter()
            .any(|arm| !arm.attrs.is_empty() || arm.guard.is_some())
    {
        return false;
    }
    let tip = &split.arms[0];
    let canonical = &split.arms[1];
    let invalid = &split.arms[2];
    syn_plain_pat_path_is_segments(
        &tip.pat,
        &["NativeAtomicCommitKind", "TipExtensionBatchCommit"],
    ) && matches!(tip.body.as_ref(), syn::Expr::Block(block)
    if syn_block_tail_is_propagated_self_call(
        block,
        1,
        "native_tip_extension_batch_commit_manifest",
    )) && syn_plain_pat_path_is_segments(
        &canonical.pat,
        &["NativeAtomicCommitKind", "CanonicalSuffixReorgCommit"],
    ) && matches!(canonical.body.as_ref(), syn::Expr::Block(block)
            if syn_block_tail_is_propagated_self_call(
                block,
                2,
                "native_canonical_suffix_reorg_commit_manifest",
            ) && syn_canonical_suffix_tip_removal_guard_is(&block.block.stmts[0]))
        && matches!(&invalid.pat, syn::Pat::Wild(wild) if wild.attrs.is_empty())
        && syn_expression_is_fail_closed_return(&invalid.body)
}

fn syn_mined_parent_projection_binding_is(local: &syn::Local) -> bool {
    let syn::Pat::Tuple(tuple) = &local.pat else {
        return false;
    };
    if !local.attrs.is_empty()
        || !tuple.attrs.is_empty()
        || tuple.elems.len() != 2
        || !syn_plain_pat_ident_is(&tuple.elems[0], "parent_projection")
        || !matches!(&tuple.elems[1], syn::Pat::Wild(wild) if wild.attrs.is_empty())
    {
        return false;
    }
    let Some(init) = &local.init else {
        return false;
    };
    let syn::Expr::Try(required_parent) = init.expr.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(ok_or_else) = required_parent.expr.as_ref() else {
        return false;
    };
    let syn::Expr::Try(inspected) = ok_or_else.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(inspect) = inspected.expr.as_ref() else {
        return false;
    };
    let Some(syn::Expr::Closure(missing_parent)) = ok_or_else.args.first() else {
        return false;
    };
    required_parent.attrs.is_empty()
        && ok_or_else.attrs.is_empty()
        && ok_or_else.method == "ok_or_else"
        && ok_or_else.turbofish.is_none()
        && ok_or_else.args.len() == 1
        && inspected.attrs.is_empty()
        && inspect.attrs.is_empty()
        && inspect.method == "inspect_stored_pow_metadata"
        && inspect.turbofish.is_none()
        && syn_plain_path_is(&inspect.receiver, "self")
        && inspect.args.len() == 3
        && syn_plain_reference_field_is(&inspect.args[0], "meta", "parent_hash")
        && syn_plain_path_is(&inspect.args[1], "None")
        && syn_string_literal_is(&inspect.args[2], "native mined-block V8 canonical parent")
        && missing_parent.attrs.is_empty()
        && missing_parent.inputs.is_empty()
        && matches!(missing_parent.body.as_ref(), syn::Expr::Macro(expression)
            if expression.attrs.is_empty() && expression.mac.path.is_ident("anyhow"))
}

fn syn_mined_parent_projection_check_is(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::If(check), None) = statement else {
        return false;
    };
    let syn::Expr::Binary(or) = check.cond.as_ref() else {
        return false;
    };
    let (syn::Expr::Binary(height_mismatch), syn::Expr::Binary(hash_mismatch)) =
        (or.left.as_ref(), or.right.as_ref())
    else {
        return false;
    };
    let syn::Expr::MethodCall(checked_add) = height_mismatch.left.as_ref() else {
        return false;
    };
    let Some(expected_height) = syn_call_path_is(&height_mismatch.right, &["Some"]) else {
        return false;
    };
    check.attrs.is_empty()
        && check.else_branch.is_none()
        && matches!(or.op, syn::BinOp::Or(_))
        && or.attrs.is_empty()
        && matches!(height_mismatch.op, syn::BinOp::Ne(_))
        && height_mismatch.attrs.is_empty()
        && checked_add.attrs.is_empty()
        && checked_add.method == "checked_add"
        && checked_add.turbofish.is_none()
        && checked_add.args.len() == 1
        && syn_plain_field_is(&checked_add.receiver, "parent_projection", "height")
        && syn_integer_literal_is(&checked_add.args[0], "1")
        && expected_height.args.len() == 1
        && syn_plain_field_is(&expected_height.args[0], "meta", "height")
        && matches!(hash_mismatch.op, syn::BinOp::Ne(_))
        && hash_mismatch.attrs.is_empty()
        && syn_plain_field_is(&hash_mismatch.left, "parent_projection", "hash")
        && syn_plain_field_is(&hash_mismatch.right, "meta", "parent_hash")
        && matches!(check.then_branch.stmts.as_slice(), [syn::Stmt::Expr(expression, Some(_))]
            if syn_expression_is_fail_closed_return(expression))
}

fn validate_v8_atomic_caller_provenance(
    method_name: &str,
    item_impl: &syn::ItemImpl,
    method: &syn::ImplItemFn,
    claim_id: &str,
    bound_helper: &str,
) -> Result<()> {
    ensure!(
        item_impl.attrs.is_empty()
            && item_impl.defaultness.is_none()
            && item_impl.unsafety.is_none()
            && item_impl.generics.params.is_empty()
            && item_impl.generics.where_clause.is_none(),
        "{} V8 atomic caller requires an unconditional nongeneric inherent NativeNode impl",
        claim_id
    );
    validate_v8_atomic_method_signature(method_name, method, claim_id)?;
    ensure!(
        syn_direct_local_bindings(method, bound_helper).is_empty(),
        "{} V8 atomic caller must not shadow the bound helper",
        claim_id
    );
    ensure!(
        !method.block.stmts.iter().any(|statement| {
            matches!(statement, syn::Stmt::Local(local) if syn_pat_contains_macro(&local.pat))
        }),
        "{} V8 atomic caller must not contain macro-expanded local patterns",
        claim_id
    );
    ensure!(
        !method
            .block
            .stmts
            .iter()
            .any(|statement| matches!(statement, syn::Stmt::Macro(_))),
        "{} V8 atomic caller must not contain direct statement macros",
        claim_id
    );
    let transaction_indices = syn_direct_pinned_transaction_statement_indices(method);
    ensure!(
        transaction_indices.len() == 1,
        "{} V8 atomic caller requires one direct pinned sled transaction statement",
        claim_id
    );
    let transaction_index = transaction_indices[0];
    ensure!(
        !syn_statements_have_outer_successful_escape_or_unknown_macro(
            &method.block.stmts[..transaction_index],
        ),
        "{} V8 atomic caller prefix must not bypass the transaction or use an unpinned macro outside closures",
        claim_id
    );
    let planner_name = match method_name {
        "commit_reorg_suffix_atomically" => "plan_poseidon2_v8_reorganization",
        "commit_mined_block_atomically" => "plan_poseidon2_v8_block_against_parent_tip",
        _ => {
            return Err(anyhow!(
                "{} shared sled binding names unsupported production caller {}",
                claim_id,
                method_name
            ));
        }
    };
    let planners = item_impl
        .items
        .iter()
        .filter_map(|item| {
            let syn::ImplItem::Fn(planner) = item else {
                return None;
            };
            (planner.sig.ident == planner_name).then_some(planner)
        })
        .collect::<Vec<_>>();
    ensure!(
        planners.len() == 1 && planners[0].attrs.is_empty(),
        "{} V8 atomic caller requires one attribute-free inherent source planner {}",
        claim_id,
        planner_name
    );
    match method_name {
        "commit_reorg_suffix_atomically" => {
            let reorgs = syn_direct_local_bindings(method, "poseidon2_v8_reorg");
            ensure!(
                reorgs.is_empty(),
                "{} V8 suffix caller must consume its exact externally prepared poseidon2_v8_reorg parameter without shadowing",
                claim_id
            );
            let v8_plans = syn_direct_local_bindings(method, "v8_plan");
            ensure!(
                v8_plans.len() == 1
                    && v8_plans[0].1.attrs.is_empty()
                    && syn_plain_pat_ident_is(&v8_plans[0].1.pat, "v8_plan")
                    && v8_plans[0].1.init.as_ref().is_some_and(|init| {
                        init.diverge.is_none()
                            && syn_v8_plan_projection_is(
                                &init.expr,
                                "poseidon2_v8_reorg",
                                true,
                                "v8_plan",
                            )
                    }),
                "{} V8 suffix caller must derive one immutable v8_plan reference from the external prepared plan",
                claim_id
            );
            let manifests = syn_direct_local_bindings(method, "suffix_manifest");
            ensure!(
                manifests.len() == 1
                    && manifests[0].1.attrs.is_empty()
                    && syn_plain_pat_ident_is(&manifests[0].1.pat, "suffix_manifest")
                    && v8_plans[0].0 < manifests[0].0
                    && manifests[0].0 < transaction_index,
                "{} V8 suffix caller requires one immutable suffix_manifest binding",
                claim_id
            );
            let Some(init) = &manifests[0].1.init else {
                return Err(anyhow!(
                    "{} V8 suffix manifest binding has no initializer",
                    claim_id
                ));
            };
            ensure!(
                init.diverge.is_none() && syn_suffix_manifest_commit_kind_split_is(&init.expr),
                "{} V8 suffix manifest must split commit_kind across the exact tip-extension and canonical-reorg builders",
                claim_id
            );
        }
        "commit_mined_block_atomically" => {
            let parents = syn_direct_local_bindings(method, "parent_projection");
            let parent_checks = method
                .block
                .stmts
                .iter()
                .enumerate()
                .filter(|(_, statement)| syn_mined_parent_projection_check_is(statement))
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let commits = syn_direct_local_bindings(method, "v8_commit");
            let manifests = syn_direct_local_bindings(method, "mined_manifest");
            ensure!(
                parents.len() == 1
                    && syn_mined_parent_projection_binding_is(parents[0].1)
                    && parent_checks.len() == 1
                    && syn_direct_local_bindings(method, "parent_meta").is_empty()
                    && commits.len() == 1
                    && commits[0].1.attrs.is_empty()
                    && syn_plain_pat_ident_is(&commits[0].1.pat, "v8_commit")
                    && manifests.len() == 1
                    && manifests[0].1.attrs.is_empty()
                    && syn_plain_pat_ident_is(&manifests[0].1.pat, "mined_manifest")
                    && parents[0].0 < parent_checks[0]
                    && parent_checks[0] < commits[0].0
                    && commits[0].0 < manifests[0].0
                    && manifests[0].0 < transaction_index,
                "{} V8 mined caller requires checked stored-parent inspection before ordered immutable v8_commit and mined_manifest bindings",
                claim_id
            );
            let Some(commit_init) = &commits[0].1.init else {
                return Err(anyhow!(
                    "{} V8 mined plan binding has no initializer",
                    claim_id
                ));
            };
            let syn::Expr::Try(commit_try) = commit_init.expr.as_ref() else {
                return Err(anyhow!(
                    "{} V8 mined planner must propagate failure",
                    claim_id
                ));
            };
            let syn::Expr::MethodCall(planner) = commit_try.expr.as_ref() else {
                return Err(anyhow!("{} V8 mined plan uses the wrong source", claim_id));
            };
            ensure!(
                commit_try.attrs.is_empty()
                    && planner.attrs.is_empty()
                    && planner.method == "plan_poseidon2_v8_block_against_parent_tip"
                    && planner.turbofish.is_none()
                    && syn_plain_path_is(&planner.receiver, "self")
                    && planner.args.len() == 4
                    && syn_plain_field_is(&planner.args[0], "parent_projection", "height")
                    && syn_plain_field_is(&planner.args[1], "parent_projection", "hash")
                    && syn_plain_path_is(&planner.args[2], "meta")
                    && syn_plain_path_is(&planner.args[3], "actions"),
                "{} V8 mined plan must come from the exact checked stored-parent tip",
                claim_id
            );
            let Some(manifest_init) = &manifests[0].1.init else {
                return Err(anyhow!(
                    "{} V8 mined manifest binding has no initializer",
                    claim_id
                ));
            };
            let Some(call) =
                syn_parent_call_is(&manifest_init.expr, "native_mined_block_commit_manifest")
            else {
                return Err(anyhow!(
                    "{} V8 mined manifest uses the wrong builder",
                    claim_id
                ));
            };
            ensure!(
                call.args.len() == 3
                    && syn_plain_path_is(&call.args[0], "actions")
                    && syn_plain_path_is(&call.args[1], "planned")
                    && syn_v8_plan_projection_is(&call.args[2], "v8_commit", true, "plan"),
                "{} V8 mined manifest must consume the exact mined plan projection",
                claim_id
            );
        }
        _ => unreachable!("caller kind checked before provenance validation"),
    }
    Ok(())
}

/// The dedicated sled obligation is intentionally scoped to ordinary symbols
/// in the checked file's top-level module. Text in an attributed impl or an
/// inline child module is not evidence that the production caller exists.
fn validate_unconditional_shared_sled_symbols(
    parsed: &syn::File,
    claim_id: &str,
    binding: &ImplementationBinding,
) -> Result<()> {
    let helpers = parsed
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Fn(function) = item else {
                return None;
            };
            (function.sig.ident == binding.callee).then_some(function)
        })
        .collect::<Vec<_>>();
    ensure!(
        helpers.len() == 1
            && helpers[0]
                .attrs
                .iter()
                .all(|attribute| attribute.path().is_ident("doc")),
        "{} implementation binding for {} requires one top-level helper with doc-only attributes",
        claim_id,
        binding.callee
    );
    if binding.callee == "apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction" {
        validate_transaction_local_v8_application_helper(helpers[0], claim_id)?;
        let suffix_builders = parsed
            .items
            .iter()
            .filter_map(|item| {
                let syn::Item::Fn(function) = item else {
                    return None;
                };
                (function.sig.ident == "native_canonical_suffix_reorg_commit_manifest")
                    .then_some(function)
            })
            .collect::<Vec<_>>();
        ensure!(
            suffix_builders.len() == 1 && suffix_builders[0].attrs.is_empty(),
            "{} V8 atomic source requires one attribute-free local suffix manifest builder",
            claim_id
        );
    }

    for caller in &binding.required_callers {
        let (expected_type, method_name) = caller
            .split_once("::")
            .map_or((None, caller.as_str()), |(ty, method)| (Some(ty), method));
        let mut matches = Vec::new();
        for item in &parsed.items {
            let syn::Item::Impl(item_impl) = item else {
                continue;
            };
            if item_impl.trait_.is_some()
                || expected_type.is_some_and(|expected| {
                    let exact_type = if binding.path == "node/src/native/node_impl.rs" {
                        syn_impl_self_type_is_one_segment(item_impl, expected)
                    } else {
                        syn_impl_self_type_is_exact(item_impl, expected)
                    };
                    !exact_type
                })
            {
                continue;
            }
            for impl_item in &item_impl.items {
                let syn::ImplItem::Fn(method) = impl_item else {
                    continue;
                };
                if method.sig.ident == method_name {
                    matches.push((item_impl, method));
                }
            }
        }
        ensure!(
            matches.len() == 1,
            "{} implementation binding caller {} requires one top-level inherent method in {}",
            claim_id,
            caller,
            binding.path
        );
        let (item_impl, method) = matches[0];
        ensure!(
            item_impl.attrs.is_empty() && method.attrs.is_empty(),
            "{} implementation binding caller {} requires an attribute-free top-level inherent impl and method",
            claim_id,
            caller
        );
        if expected_type == Some("NativeNode") {
            validate_v8_atomic_caller_provenance(
                method_name,
                item_impl,
                method,
                claim_id,
                &binding.callee,
            )?;
        }
    }
    Ok(())
}

fn validate_rust_implementation_binding(
    root: &Path,
    claim_id: &str,
    binding: &ImplementationBinding,
) -> Result<()> {
    let binding_sources = rust_binding_module_sources(root, &binding.path)?;
    let binding_source_count = binding_sources.len();
    let mut source = String::new();
    for (_, module_source) in binding_sources {
        if !source.is_empty() {
            source.push('\n');
        }
        source.push_str(&module_source);
    }
    let sanitized = sanitize_rust_source(&source);
    let test_module_spans = rust_cfg_test_module_spans(&sanitized);
    let macro_body_spans = rust_macro_body_spans(&sanitized);
    let functions = rust_function_spans(&sanitized)?;
    let result_obligation = parse_result_obligation(
        claim_id,
        &binding.callee,
        binding.result_obligation.as_deref(),
    )?;
    if result_obligation == ResultObligation::MustPropagateSharedSledTransactionResult {
        validate_native_node_cargo_target_selection(root, &binding.path)?;
        validate_unconditional_rust_module_inclusion_chain(
            root,
            &binding.path,
            claim_id,
            &binding.callee,
        )?;
        ensure!(
            binding_source_count == 1,
            "{} implementation binding for {} must target its single defining Rust source file",
            claim_id,
            binding.callee
        );
        let pinned_alias = "extern crate sled as __hegemon_pinned_sled;";
        ensure!(
            sanitized.matches(pinned_alias).count() == 1,
            "{} implementation binding for {} requires one module-local external sled pin",
            claim_id,
            binding.callee
        );
        let parsed_binding_source = syn::parse_file(&source)
            .context("parse single-source shared sled implementation binding")?;
        let enclosing_cfg_attrs = parsed_binding_source
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
            .count();
        ensure!(
            enclosing_cfg_attrs == 0,
            "{} implementation binding for {} requires an unconditional enclosing Rust source file",
            claim_id,
            binding.callee
        );
        let unconditional_top_level_pins = parsed_binding_source
            .items
            .iter()
            .filter(|item| {
                let syn::Item::ExternCrate(extern_crate) = item else {
                    return false;
                };
                extern_crate.attrs.is_empty()
                    && extern_crate.ident == "sled"
                    && extern_crate
                        .rename
                        .as_ref()
                        .is_some_and(|(_, rename)| rename == "__hegemon_pinned_sled")
            })
            .count();
        ensure!(
            unconditional_top_level_pins == 1,
            "{} implementation binding for {} requires an unconditional top-level external sled pin",
            claim_id,
            binding.callee
        );
        validate_unconditional_shared_sled_symbols(&parsed_binding_source, claim_id, binding)?;
    }
    let non_test_callees = functions
        .iter()
        .filter(|function| {
            function.name == binding.callee
                && !function.is_test_only(&sanitized, &test_module_spans)
                && !rust_position_is_inside_spans(function.start, &macro_body_spans)
        })
        .collect::<Vec<_>>();
    ensure!(
        !non_test_callees.is_empty(),
        "{} implementation binding callee {} is missing from non-test Rust code in {}",
        claim_id,
        binding.callee,
        binding.path
    );
    let free_callee_count = non_test_callees
        .iter()
        .filter(|function| function.impl_type.is_none())
        .count();
    ensure!(
        free_callee_count <= 1,
        "{} implementation binding callee {} is ambiguous across {} non-test free-function declarations in {}",
        claim_id,
        binding.callee,
        free_callee_count,
        binding.path
    );
    let mut method_counts = BTreeMap::<&str, usize>::new();
    for function in &non_test_callees {
        if let Some(impl_type) = function.impl_type.as_deref() {
            *method_counts.entry(impl_type).or_default() += 1;
        }
    }
    for (impl_type, count) in method_counts {
        ensure!(
            count <= 1,
            "{} implementation binding callee {} is ambiguous across {} non-test {} method declarations in {}",
            claim_id,
            binding.callee,
            count,
            impl_type,
            binding.path
        );
    }
    for function in &non_test_callees {
        let body = &sanitized[function.body_start..function.body_end];
        for caller in &binding.required_callers {
            ensure!(
                !rust_body_directly_calls_caller(body, caller),
                "{} implementation binding callee {} in {} directly calls required caller {}; binding is self-feeding",
                claim_id,
                binding.callee,
                binding.path,
                caller
            );
        }
    }
    for caller in &binding.required_callers {
        let non_test_callers = functions
            .iter()
            .filter(|function| {
                function.matches_caller(caller)
                    && !function.is_test_only(&sanitized, &test_module_spans)
                    && !rust_position_is_inside_spans(function.start, &macro_body_spans)
            })
            .collect::<Vec<_>>();
        ensure!(
            !non_test_callers.is_empty(),
            "{} implementation binding caller {} is missing from non-test Rust code in {}",
            claim_id,
            caller,
            binding.path
        );
        for function in non_test_callers {
            let body = &sanitized[function.body_start..function.body_end];
            let raw_body = &source[function.body_start..function.body_end];
            let closure_bodies = rust_closure_body_spans(body);
            let async_block_bodies = rust_async_block_body_spans(body);
            let macro_body_spans = rust_macro_body_spans(body);
            let local_shadow = if result_obligation
                == ResultObligation::MustPropagateSharedSledTransactionResult
            {
                rust_body_has_let_shadow(body, &binding.callee)
                    || rust_body_has_for_shadow(body, &binding.callee)
                    || rust_body_has_nested_fn_shadow(body, &binding.callee)
                    || rust_body_has_callable_value_item_shadow(body, &binding.callee)
                    || rust_body_has_use_shadow(body, &binding.callee)
            } else {
                rust_body_has_local_shadow_of_callee(body, &binding.callee)
            };
            ensure!(
                !rust_function_parameter_binds_callee(&sanitized, function, &binding.callee)
                    && !local_shadow,
                "{} implementation binding caller {} in {} locally shadows bound callee {} (let={}, for={}, nested_fn={}, value_item={}, use={}, closure_parameter={})",
                claim_id,
                caller,
                binding.path,
                binding.callee,
                rust_body_has_let_shadow(body, &binding.callee),
                rust_body_has_for_shadow(body, &binding.callee),
                rust_body_has_nested_fn_shadow(body, &binding.callee),
                rust_body_has_callable_value_item_shadow(body, &binding.callee),
                rust_body_has_use_shadow(body, &binding.callee),
                rust_body_has_closure_parameter_shadow(body, &binding.callee),
            );
            let call_sites = rust_bound_callee_call_sites(
                body,
                &binding.callee,
                function,
                &sanitized,
                &test_module_spans,
                &functions,
            );
            let allow_pinned_native_error_prefix = binding.path == "node/src/native/node_impl.rs"
                && binding.callee
                    == "apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction"
                && matches!(
                    caller.as_str(),
                    "NativeNode::commit_reorg_suffix_atomically"
                        | "NativeNode::commit_mined_block_atomically"
                );
            ensure!(
                !call_sites.is_empty()
                    && (result_obligation
                        != ResultObligation::MustPropagateSharedSledTransactionResult
                        || call_sites.len() == 1)
                    && call_sites.iter().all(|call| {
                        rust_call_is_direct_binding_evidence(
                            body,
                            raw_body,
                            call,
                            result_obligation,
                            &closure_bodies,
                            &async_block_bodies,
                            &macro_body_spans,
                            allow_pinned_native_error_prefix,
                        ) && call_satisfies_result_obligation(
                            body,
                            raw_body,
                            call,
                            result_obligation,
                        )
                    }),
                "{} implementation binding caller {} in {} does not call {}{} in non-test Rust code",
                claim_id,
                caller,
                binding.path,
                binding.callee,
                result_obligation_error_suffix(result_obligation)
            );
        }
    }
    for constraint in &binding.call_order_constraints {
        validate_rust_implementation_order(
            claim_id,
            binding,
            constraint,
            &sanitized,
            &source,
            &test_module_spans,
            &functions,
        )?;
    }
    Ok(())
}

fn rust_body_directly_calls_caller(body: &str, caller: &str) -> bool {
    let caller_leaf = rust_caller_symbol_leaf(caller);
    !rust_call_sites_for_selector(body, &RustCallSelector::bare(caller_leaf)).is_empty()
}

fn validate_rust_implementation_order(
    claim_id: &str,
    binding: &ImplementationBinding,
    constraint: &ImplementationCallOrderConstraint,
    source: &str,
    raw_source: &str,
    test_module_spans: &[(usize, usize)],
    functions: &[RustFunctionSpan],
) -> Result<()> {
    let binding_result_obligation = parse_result_obligation(
        claim_id,
        &binding.callee,
        binding.result_obligation.as_deref(),
    )?;
    let constraint_result_obligation = if constraint.result_obligation.is_some() {
        parse_result_obligation(
            claim_id,
            &binding.callee,
            constraint.result_obligation.as_deref(),
        )?
    } else {
        binding_result_obligation
    };
    let matching_callers = functions
        .iter()
        .filter(|function| {
            function.matches_caller(&constraint.caller)
                && !function.is_test_only(source, test_module_spans)
        })
        .collect::<Vec<_>>();
    ensure!(
        !matching_callers.is_empty(),
        "{} implementation binding order caller {} is missing from non-test Rust code in {}",
        claim_id,
        constraint.caller,
        binding.path
    );
    for function in matching_callers {
        let body = &source[function.body_start..function.body_end];
        let raw_body = &raw_source[function.body_start..function.body_end];
        let closure_bodies = rust_closure_body_spans(body);
        let async_block_bodies = rust_async_block_body_spans(body);
        let macro_body_spans = rust_macro_body_spans(body);
        let callee_calls = rust_bound_callee_call_sites(
            body,
            &binding.callee,
            function,
            source,
            test_module_spans,
            functions,
        )
        .into_iter()
        .filter(|call| {
            if constraint_result_obligation
                == ResultObligation::MustPropagateSharedSledTransactionResult
            {
                rust_call_is_direct_binding_evidence(
                    body,
                    raw_body,
                    call,
                    constraint_result_obligation,
                    &closure_bodies,
                    &async_block_bodies,
                    &macro_body_spans,
                    binding.path == "node/src/native/node_impl.rs"
                        && binding.callee
                            == "apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction"
                        && matches!(
                            constraint.caller.as_str(),
                            "NativeNode::commit_reorg_suffix_atomically"
                                | "NativeNode::commit_mined_block_atomically"
                        ),
                )
            } else {
                rust_call_is_direct_order_evidence(
                    body,
                    call,
                    &closure_bodies,
                    &async_block_bodies,
                    &macro_body_spans,
                )
            }
        })
        .filter(|call| {
            call_satisfies_result_obligation(body, raw_body, call, constraint_result_obligation)
        })
        .collect::<Vec<_>>();
        if callee_calls.is_empty() {
            return Err(anyhow!(
                "{} implementation binding order caller {} in {} does not call {}{} in non-test Rust code",
                claim_id,
                constraint.caller,
                binding.path,
                binding.callee,
                result_obligation_error_suffix(constraint_result_obligation)
            ));
        }
        for successor in &constraint.callee_must_precede {
            let successor_selector =
                parse_rust_call_selector(successor).expect("successor selector validated");
            let successor_calls = rust_call_sites_for_selector(body, &successor_selector);
            if successor_calls.is_empty() {
                return Err(anyhow!(
                    "{} implementation binding order caller {} in {} does not call required successor {}",
                    claim_id,
                    constraint.caller,
                    binding.path,
                    successor
                ));
            }
            if constraint.must_dominate_successors {
                for successor_call in &successor_calls {
                    ensure!(
                        callee_calls
                            .iter()
                            .any(|call| {
                                if constraint_result_obligation
                                    == ResultObligation::MustPropagateSharedSledTransactionResult
                                {
                                    rust_shared_sled_helper_dominates_successor(
                                        body,
                                        call,
                                        successor_call,
                                        &closure_bodies,
                                    )
                                } else {
                                    rust_call_dominates_successor(
                                        body,
                                        call,
                                        successor_call,
                                        &closure_bodies,
                                    )
                                }
                            }),
                        "{} implementation binding order caller {} in {} does not dominate {} before {}",
                        claim_id,
                        constraint.caller,
                        binding.path,
                        binding.callee,
                        successor
                    );
                }
            } else {
                let callee_index = callee_calls
                    .iter()
                    .map(|call| call.start)
                    .min()
                    .expect("callee_calls checked nonempty");
                let successor_index = successor_calls
                    .iter()
                    .map(|call| call.start)
                    .min()
                    .expect("successor_calls checked nonempty");
                ensure!(
                    callee_index < successor_index,
                    "{} implementation binding order caller {} in {} calls {} after {}",
                    claim_id,
                    constraint.caller,
                    binding.path,
                    binding.callee,
                    successor
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultObligation {
    None,
    MustPropagateResult,
    MustPropagateSharedSledTransactionResult,
    MustCheckResultFailClosed,
    MustReturnSubmitActionRejection,
    MustCheckResultLoopSkipFailClosed,
    MustFilterOkResult,
    MustContributeToMineableSelection,
    MustReturnTupleResultComponent,
    MustResetWorkTemplateOnErr,
    MustGuardFalseFailClosed,
    MustMatchSomeOrReturnSupplyDeltaInvalid,
    MustMatchSomeAndCompareSupplyClaim,
}

fn parse_result_obligation(
    claim_id: &str,
    callee: &str,
    raw: Option<&str>,
) -> Result<ResultObligation> {
    match raw {
        None => Ok(ResultObligation::None),
        Some("must_propagate_result") => Ok(ResultObligation::MustPropagateResult),
        Some("must_propagate_shared_sled_transaction_result") => {
            Ok(ResultObligation::MustPropagateSharedSledTransactionResult)
        }
        Some("must_check_result_fail_closed") => Ok(ResultObligation::MustCheckResultFailClosed),
        Some("must_return_submit_action_rejection") => {
            Ok(ResultObligation::MustReturnSubmitActionRejection)
        }
        Some("must_check_result_loop_skip_fail_closed") => {
            Ok(ResultObligation::MustCheckResultLoopSkipFailClosed)
        }
        Some("must_filter_ok_result") => Ok(ResultObligation::MustFilterOkResult),
        Some("must_contribute_to_mineable_selection") => {
            Ok(ResultObligation::MustContributeToMineableSelection)
        }
        Some("must_return_tuple_result_component") => {
            Ok(ResultObligation::MustReturnTupleResultComponent)
        }
        Some("must_reset_work_template_on_err") => Ok(ResultObligation::MustResetWorkTemplateOnErr),
        Some("must_guard_false_fail_closed") => Ok(ResultObligation::MustGuardFalseFailClosed),
        Some("must_match_some_or_return_supply_delta_invalid") => {
            Ok(ResultObligation::MustMatchSomeOrReturnSupplyDeltaInvalid)
        }
        Some("must_match_some_and_compare_supply_claim") => {
            Ok(ResultObligation::MustMatchSomeAndCompareSupplyClaim)
        }
        Some(other) => Err(anyhow!(
            "{} implementation binding for {} has unknown result_obligation {}",
            claim_id,
            callee,
            other
        )),
    }
}

fn result_obligation_error_suffix(obligation: ResultObligation) -> &'static str {
    match obligation {
        ResultObligation::None => "",
        ResultObligation::MustPropagateResult => " with propagated result",
        ResultObligation::MustPropagateSharedSledTransactionResult => {
            " with propagated shared sled transaction result"
        }
        ResultObligation::MustCheckResultFailClosed => " with fail-closed result handling",
        ResultObligation::MustReturnSubmitActionRejection => {
            " with an exact submit-action rejection response"
        }
        ResultObligation::MustCheckResultLoopSkipFailClosed => {
            " with loop-skip fail-closed result handling"
        }
        ResultObligation::MustFilterOkResult => " with filter Ok-result gating",
        ResultObligation::MustContributeToMineableSelection => {
            " with mineable-selection admission dataflow"
        }
        ResultObligation::MustReturnTupleResultComponent => " with returned tuple result component",
        ResultObligation::MustResetWorkTemplateOnErr => " with empty work-template fallback",
        ResultObligation::MustGuardFalseFailClosed => " with fail-closed false guard handling",
        ResultObligation::MustMatchSomeOrReturnSupplyDeltaInvalid => {
            " with supply-delta invalid match handling"
        }
        ResultObligation::MustMatchSomeAndCompareSupplyClaim => {
            " with checked supply-claim comparison"
        }
    }
}

#[derive(Debug, Clone)]
struct RustFunctionSpan {
    name: String,
    impl_type: Option<String>,
    qualified_name: Option<String>,
    start: usize,
    end: usize,
    parameters_start: usize,
    parameters_end: usize,
    body_start: usize,
    body_end: usize,
}

impl RustFunctionSpan {
    fn matches_caller(&self, caller: &str) -> bool {
        if caller.contains("::") {
            self.qualified_name.as_deref() == Some(caller)
        } else {
            self.name == caller
        }
    }

    fn is_test_only(&self, source: &str, test_module_spans: &[(usize, usize)]) -> bool {
        test_module_spans
            .iter()
            .any(|(start, end)| *start <= self.start && self.end <= *end)
            || preceding_rust_attrs_contain_non_production_cfg(source, self.start)
    }
}

fn rust_function_spans(source: &str) -> Result<Vec<RustFunctionSpan>> {
    let impl_spans = rust_impl_spans(source)?;
    let mut functions = Vec::new();
    let mut cursor = 0usize;
    while let Some(fn_start) = find_rust_token(source, "fn", cursor) {
        let Some((name, after_name)) = parse_rust_identifier_after(source, fn_start + 2) else {
            cursor = fn_start + 2;
            continue;
        };
        let Some(parameters_open) = find_rust_function_parameters_open(source, after_name) else {
            cursor = fn_start + 2;
            continue;
        };
        let parameters_close = match_rust_paren(source, parameters_open).with_context(|| {
            format!("match Rust function parameters for {name} starting at byte {parameters_open}")
        })?;
        let Some(body_start) = find_rust_body_start(source, after_name) else {
            cursor = fn_start + 2;
            continue;
        };
        let body_end = match_rust_brace(source, body_start).with_context(|| {
            format!("match Rust function body for {name} starting at byte {body_start}")
        })?;
        let impl_type = enclosing_impl_type(&impl_spans, fn_start, body_end + 1).map(str::to_owned);
        let qualified_name = impl_type
            .as_ref()
            .map(|impl_type| format!("{impl_type}::{name}"));
        functions.push(RustFunctionSpan {
            name,
            impl_type,
            qualified_name,
            start: fn_start,
            end: body_end + 1,
            parameters_start: parameters_open + 1,
            parameters_end: parameters_close,
            body_start,
            body_end: body_end + 1,
        });
        cursor = body_end + 1;
    }
    Ok(functions)
}

fn find_rust_function_parameters_open(source: &str, from: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut angle_depth = 0usize;
    let mut index = from;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.saturating_sub(1),
            b'(' if angle_depth == 0 => return Some(index),
            b'{' | b';' if angle_depth == 0 => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

fn rust_function_parameter_binds_callee(
    source: &str,
    function: &RustFunctionSpan,
    callee: &str,
) -> bool {
    rust_parameter_list_binds_identifier(
        &source[function.parameters_start..function.parameters_end],
        callee,
    )
}

fn rust_parameter_list_binds_identifier(parameters: &str, ident: &str) -> bool {
    let bytes = parameters.as_bytes();
    let mut segment_start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut index = 0usize;
    while index <= bytes.len() {
        let at_end = index == bytes.len();
        if at_end
            || (bytes[index] == b','
                && paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0
                && angle_depth == 0)
        {
            if rust_parameter_binds_identifier(&parameters[segment_start..index], ident) {
                return true;
            }
            segment_start = index.saturating_add(1);
            index += 1;
            continue;
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn rust_parameter_binds_identifier(parameter: &str, ident: &str) -> bool {
    let bytes = parameter.as_bytes();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut pattern_end = bytes.len();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.saturating_sub(1),
            b':' if paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0
                && angle_depth == 0
                && bytes.get(index.wrapping_sub(1)) != Some(&b':')
                && bytes.get(index + 1) != Some(&b':') =>
            {
                pattern_end = index;
                break;
            }
            _ => {}
        }
        index += 1;
    }
    rust_pattern_binds_identifier(&parameter[..pattern_end], ident)
}

fn rust_body_has_local_shadow_of_callee(source: &str, callee: &str) -> bool {
    rust_body_has_let_shadow(source, callee)
        || rust_body_has_for_shadow(source, callee)
        || rust_body_has_nested_fn_shadow(source, callee)
        || rust_body_has_callable_value_item_shadow(source, callee)
        || rust_body_has_use_shadow(source, callee)
        || rust_body_has_closure_parameter_shadow(source, callee)
}

fn rust_body_has_callable_value_item_shadow(source: &str, callee: &str) -> bool {
    for keyword in ["const", "static", "struct"] {
        let mut cursor = 0usize;
        while let Some(item_start) = find_rust_token(source, keyword, cursor) {
            let mut name_start = item_start + keyword.len();
            if keyword == "static" {
                let after_space = skip_ascii_whitespace(source, name_start);
                if let Some(after_mut) = rust_token_at(source, "mut", after_space) {
                    name_start = after_mut;
                }
            }
            if parse_rust_identifier_after(source, name_start)
                .is_some_and(|(name, _)| name == callee)
            {
                return true;
            }
            cursor = item_start + keyword.len();
        }
    }
    false
}

fn rust_body_has_let_shadow(source: &str, callee: &str) -> bool {
    let mut cursor = 0usize;
    while let Some(let_start) = find_rust_token(source, "let", cursor) {
        let statement_end = top_level_statement_end_after(source, let_start, source.len())
            .map(|(end, _)| end)
            .unwrap_or(source.len());
        let statement = &source[let_start + "let".len()..statement_end];
        let pattern_end = statement
            .find('=')
            .or_else(|| statement.find(':'))
            .unwrap_or(statement.len());
        if rust_pattern_binds_identifier(&statement[..pattern_end], callee) {
            return true;
        }
        cursor = statement_end.saturating_add(1);
    }
    false
}

fn rust_body_has_for_shadow(source: &str, callee: &str) -> bool {
    let mut cursor = 0usize;
    while let Some(for_start) = find_rust_token(source, "for", cursor) {
        let statement_end = top_level_statement_end_after(source, for_start, source.len())
            .map(|(end, _)| end)
            .unwrap_or(source.len());
        let statement = &source[for_start + "for".len()..statement_end];
        let pattern_end = statement.find(" in ").unwrap_or(statement.len());
        if rust_pattern_binds_identifier(&statement[..pattern_end], callee) {
            return true;
        }
        cursor = statement_end.saturating_add(1);
    }
    false
}

fn rust_body_has_nested_fn_shadow(source: &str, callee: &str) -> bool {
    let mut cursor = 0usize;
    while let Some(fn_start) = find_rust_token(source, "fn", cursor) {
        if let Some((name, _)) = parse_rust_identifier_after(source, fn_start + "fn".len()) {
            if name == callee {
                return true;
            }
        }
        cursor = fn_start + "fn".len();
    }
    false
}

fn rust_body_has_use_shadow(source: &str, callee: &str) -> bool {
    let mut cursor = 0usize;
    while let Some(use_start) = find_rust_token(source, "use", cursor) {
        let statement_end = top_level_statement_end_after(source, use_start, source.len())
            .map(|(end, _)| end)
            .unwrap_or(source.len());
        let statement = &source[use_start + "use".len()..statement_end];
        if statement
            .split(|c: char| !(c == '_' || c == ':' || c.is_ascii_alphanumeric()))
            .any(|token| token == callee)
        {
            return true;
        }
        cursor = statement_end.saturating_add(1);
    }
    false
}

fn rust_body_has_closure_parameter_shadow(source: &str, callee: &str) -> bool {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find('|') {
        let first_bar = cursor + relative;
        let Some(second_relative) = source[first_bar + 1..].find('|') else {
            break;
        };
        let second_bar = first_bar + 1 + second_relative;
        if second_bar - first_bar <= 256
            && rust_pattern_binds_identifier(&source[first_bar + 1..second_bar], callee)
        {
            return true;
        }
        cursor = second_bar + 1;
        if bytes.get(cursor) == Some(&b'|') {
            cursor += 1;
        }
    }
    false
}

fn rust_pattern_binds_identifier(pattern: &str, ident: &str) -> bool {
    let mut cursor = 0usize;
    while let Some(index) = find_rust_identifier_from(pattern, ident, cursor) {
        let before = pattern[..index].trim_end();
        if !before.ends_with("::") {
            return true;
        }
        cursor = index + ident.len();
    }
    false
}

#[derive(Debug, Clone)]
struct RustImplSpan {
    impl_type: String,
    body_start: usize,
    body_end: usize,
}

fn rust_impl_spans(source: &str) -> Result<Vec<RustImplSpan>> {
    let mut spans = Vec::new();
    let mut cursor = 0usize;
    while let Some(impl_start) = find_rust_token(source, "impl", cursor) {
        let Some(body_start) = find_rust_body_start(source, impl_start + 4) else {
            cursor = impl_start + 4;
            continue;
        };
        let body_end = match_rust_brace(source, body_start)
            .with_context(|| format!("match Rust impl body starting at byte {body_start}"))?;
        if let Some(impl_type) = parse_rust_impl_type(&source[impl_start + 4..body_start]) {
            spans.push(RustImplSpan {
                impl_type,
                body_start,
                body_end: body_end + 1,
            });
        }
        cursor = body_end + 1;
    }
    Ok(spans)
}

fn enclosing_impl_type(
    impl_spans: &[RustImplSpan],
    fn_start: usize,
    fn_end: usize,
) -> Option<&str> {
    impl_spans
        .iter()
        .filter(|span| span.body_start < fn_start && fn_end <= span.body_end)
        .min_by_key(|span| span.body_end - span.body_start)
        .map(|span| span.impl_type.as_str())
}

fn parse_rust_impl_type(header: &str) -> Option<String> {
    let self_type = if let Some(for_start) = find_top_level_for_keyword(header) {
        &header[for_start + "for".len()..]
    } else {
        strip_impl_generics_prefix(header)
    };
    parse_rust_type_name(self_type)
}

fn strip_impl_generics_prefix(header: &str) -> &str {
    let trimmed = header.trim_start();
    if !trimmed.starts_with('<') {
        return trimmed;
    }
    let Some(end) = match_rust_angle(trimmed, 0) else {
        return trimmed;
    };
    trimmed[end + 1..].trim_start()
}

fn find_top_level_for_keyword(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut found = None;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.saturating_sub(1),
            _ => {}
        }
        if paren_depth == 0
            && bracket_depth == 0
            && angle_depth == 0
            && rust_token_at(source, "for", index).is_some()
        {
            found = Some(index);
        }
        index += 1;
    }
    found
}

fn match_rust_angle(source: &str, open: usize) -> Option<usize> {
    if source.as_bytes().get(open) != Some(&b'<') {
        return None;
    }
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().copied().enumerate() {
        match byte {
            b'<' => depth += 1,
            b'>' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_rust_type_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim_start();
    let bytes = trimmed.as_bytes();
    let mut index = 0usize;
    while bytes
        .get(index)
        .is_some_and(|byte| is_rust_identifier_byte(*byte) || *byte == b':' || *byte == b'_')
    {
        index += 1;
    }
    let path = trimmed[..index].trim_end_matches(':');
    path.rsplit("::")
        .find(|segment| !segment.is_empty())
        .filter(|segment| {
            let mut chars = segment.chars();
            let Some(first) = chars.next() else {
                return false;
            };
            (first == '_' || first.is_ascii_alphabetic())
                && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        })
        .map(str::to_owned)
}

fn rust_cfg_test_module_spans(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut cursor = 0usize;
    while let Some(mod_start) = find_rust_token(source, "mod", cursor) {
        let Some((_module_name, after_name)) = parse_rust_identifier_after(source, mod_start + 3)
        else {
            cursor = mod_start + 3;
            continue;
        };
        let Some(body_start) = find_rust_body_start(source, after_name) else {
            cursor = mod_start + 3;
            continue;
        };
        let Ok(body_end) = match_rust_brace(source, body_start) else {
            cursor = mod_start + 3;
            continue;
        };
        if preceding_rust_attrs_contain_non_production_cfg(source, mod_start) {
            spans.push((mod_start, body_end + 1));
        }
        cursor = body_end + 1;
    }
    spans
}

fn sanitize_rust_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut index = 0usize;
    let mut block_depth = 0usize;
    let mut in_line_comment = false;
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;

    while index < bytes.len() {
        let current = bytes[index];
        let next = bytes.get(index + 1).copied();

        if in_line_comment {
            if current == b'\n' {
                in_line_comment = false;
            } else {
                out[index] = b' ';
            }
            index += 1;
            continue;
        }

        if block_depth > 0 {
            if current == b'/' && next == Some(b'*') {
                block_depth += 1;
                out[index] = b' ';
                out[index + 1] = b' ';
                index += 2;
                continue;
            }
            if current == b'*' && next == Some(b'/') {
                block_depth -= 1;
                out[index] = b' ';
                out[index + 1] = b' ';
                index += 2;
                continue;
            }
            if current != b'\n' {
                out[index] = b' ';
            }
            index += 1;
            continue;
        }

        if in_string || in_char {
            let terminator = if in_string { b'"' } else { b'\'' };
            if current == b'\n' {
                escaped = false;
            } else {
                out[index] = b' ';
                if escaped {
                    escaped = false;
                } else if current == b'\\' {
                    escaped = true;
                } else if current == terminator {
                    in_string = false;
                    in_char = false;
                }
            }
            index += 1;
            continue;
        }

        if let Some(raw_end) = rust_raw_string_literal_end(bytes, index) {
            for raw_index in index..raw_end {
                if bytes[raw_index] != b'\n' {
                    out[raw_index] = b' ';
                }
            }
            index = raw_end;
            continue;
        }

        if current == b'/' && next == Some(b'/') {
            in_line_comment = true;
            out[index] = b' ';
            out[index + 1] = b' ';
            index += 2;
            continue;
        }
        if current == b'/' && next == Some(b'*') {
            block_depth = 1;
            out[index] = b' ';
            out[index + 1] = b' ';
            index += 2;
            continue;
        }
        if current == b'"' {
            in_string = true;
            out[index] = b' ';
            index += 1;
            continue;
        }
        if current == b'\'' && looks_like_rust_char_literal_start(bytes, index) {
            in_char = true;
            out[index] = b' ';
            index += 1;
            continue;
        }

        index += 1;
    }
    String::from_utf8(out).expect("sanitized Rust source preserves valid UTF-8")
}

fn rust_raw_string_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let r_index = match (bytes.get(start), bytes.get(start + 1)) {
        (Some(b'r'), _) => start,
        (Some(b'b'), Some(b'r')) => start + 1,
        (Some(b'c'), Some(b'r')) => start + 1,
        _ => return None,
    };
    if start > 0 && is_rust_identifier_continuation_byte(bytes[start - 1]) {
        return None;
    }
    let mut quote = r_index + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return None;
    }
    let hash_count = quote - (r_index + 1);
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && bytes
                .get(cursor + 1..cursor + 1 + hash_count)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Some(cursor + 1 + hash_count);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn rust_macro_body_spans(source: &str) -> Vec<RustSourceSpan> {
    let bytes = source.as_bytes();
    let mut spans = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = source[cursor..].find('!') {
        let bang = cursor + relative;
        let before = skip_ascii_whitespace_back(source, bang);
        let Some(previous) = before
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .copied()
        else {
            cursor = bang + 1;
            continue;
        };
        if !is_rust_identifier_continuation_byte(previous) {
            cursor = bang + 1;
            continue;
        }
        let mut open = skip_ascii_whitespace(source, bang + 1);
        if !matches!(bytes.get(open), Some(b'(' | b'[' | b'{')) {
            let Some((_, after_name)) = parse_rust_identifier_after(source, open) else {
                cursor = bang + 1;
                continue;
            };
            open = skip_ascii_whitespace(source, after_name);
        }
        let Some(close) = (match bytes.get(open) {
            Some(b'(') => match_rust_paren(source, open).ok(),
            Some(b'{') => match_rust_brace(source, open).ok(),
            Some(b'[') => match_rust_bracket(source, open).ok(),
            _ => None,
        }) else {
            cursor = bang + 1;
            continue;
        };
        spans.push(RustSourceSpan {
            start: open + 1,
            end: close,
        });
        cursor = close + 1;
    }
    spans
}

fn match_rust_bracket(source: &str, open: usize) -> Result<usize> {
    ensure!(
        source.as_bytes().get(open) == Some(&b'['),
        "expected opening bracket at byte {open}"
    );
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().copied().enumerate() {
        match byte {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(open + offset);
                }
            }
            _ => {}
        }
    }
    Err(anyhow!("unclosed Rust bracket at byte {open}"))
}

fn looks_like_rust_char_literal_start(bytes: &[u8], index: usize) -> bool {
    let Some(next) = bytes.get(index + 1).copied() else {
        return false;
    };
    let prev = index
        .checked_sub(1)
        .and_then(|prev| bytes.get(prev).copied())
        .unwrap_or(b' ');
    let has_byte_literal_prefix = prev == b'b'
        && index
            .checked_sub(2)
            .and_then(|prev| bytes.get(prev).copied())
            .is_none_or(|byte| !is_rust_identifier_continuation_byte(byte));
    if is_rust_identifier_continuation_byte(prev) && !has_byte_literal_prefix {
        return false;
    }
    let close = if next == b'\\' {
        index + 3
    } else if next != b'\'' && next != b'\n' {
        index + 2
    } else {
        return false;
    };
    bytes.get(close) == Some(&b'\'')
}

fn find_rust_token(source: &str, token: &str, from: usize) -> Option<usize> {
    if from >= source.len() {
        return None;
    }
    let mut cursor = from;
    while let Some(relative) = source[cursor..].find(token) {
        let index = cursor + relative;
        let before = index
            .checked_sub(1)
            .and_then(|prev| source.as_bytes().get(prev).copied());
        let after = source.as_bytes().get(index + token.len()).copied();
        if !before.is_some_and(is_rust_identifier_continuation_byte)
            && !after.is_some_and(is_rust_identifier_continuation_byte)
        {
            return Some(index);
        }
        cursor = index + token.len();
    }
    None
}

fn parse_rust_identifier_after(source: &str, from: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut index = from;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    let first = *bytes.get(index)?;
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return None;
    }
    let start = index;
    index += 1;
    while bytes
        .get(index)
        .is_some_and(|byte| is_rust_identifier_continuation_byte(*byte))
    {
        index += 1;
    }
    Some((source[start..index].to_owned(), index))
}

fn find_rust_body_start(source: &str, from: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = from;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' if paren_depth == 0 && bracket_depth == 0 => return Some(index),
            b';' if paren_depth == 0 && bracket_depth == 0 => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

fn match_rust_brace(source: &str, open: usize) -> Result<usize> {
    ensure!(
        source.as_bytes().get(open) == Some(&b'{'),
        "expected opening brace at byte {open}"
    );
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().copied().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(open + offset);
                }
            }
            _ => {}
        }
    }
    Err(anyhow!("unclosed Rust brace at byte {open}"))
}

fn preceding_rust_attrs_contain_non_production_cfg(source: &str, item_start: usize) -> bool {
    let prefix = &source[..item_start];
    let mut saw_attr = false;
    for line in prefix.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if saw_attr {
                break;
            }
            continue;
        }
        if trimmed.starts_with("#[") {
            saw_attr = true;
            if trimmed.contains("cfg(") || trimmed.contains("cfg_attr(") {
                return true;
            }
            continue;
        }
        break;
    }
    false
}

#[derive(Debug, Clone)]
struct RustCallSite {
    start: usize,
    close_paren: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustCallSelector {
    segments: Vec<String>,
    separators: Vec<RustCallSelectorSeparator>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustCallSelectorSeparator {
    Path,
    Member,
}

impl RustCallSelector {
    fn bare(ident: &str) -> Self {
        Self {
            segments: vec![ident.to_owned()],
            separators: Vec::new(),
        }
    }

    fn is_bare(&self) -> bool {
        self.separators.is_empty()
    }

    fn last_segment(&self) -> &str {
        self.segments
            .last()
            .expect("call selector must contain at least one segment")
    }
}

fn parse_rust_call_selector(selector: &str) -> Option<RustCallSelector> {
    if selector.trim() != selector || selector.is_empty() {
        return None;
    }
    let bytes = selector.as_bytes();
    let mut index = 0usize;
    let mut segments = Vec::new();
    let mut separators = Vec::new();
    loop {
        let segment_start = index;
        let first = *bytes.get(index)?;
        if !(first == b'_' || first.is_ascii_alphabetic()) {
            return None;
        }
        index += 1;
        while bytes
            .get(index)
            .is_some_and(|byte| is_rust_identifier_byte(*byte))
        {
            index += 1;
        }
        let segment = &selector[segment_start..index];
        if !is_plain_rust_identifier(segment) {
            return None;
        }
        segments.push(segment.to_owned());
        if index == bytes.len() {
            break;
        }
        if selector[index..].starts_with("::") {
            separators.push(RustCallSelectorSeparator::Path);
            index += 2;
        } else if bytes.get(index) == Some(&b'.') {
            separators.push(RustCallSelectorSeparator::Member);
            index += 1;
        } else {
            return None;
        }
        if index == bytes.len() {
            return None;
        }
    }
    Some(RustCallSelector {
        segments,
        separators,
    })
}

fn rust_call_sites(source: &str, ident: &str) -> Vec<RustCallSite> {
    rust_call_sites_for_selector(source, &RustCallSelector::bare(ident))
}

fn rust_bound_callee_call_sites(
    body: &str,
    ident: &str,
    caller: &RustFunctionSpan,
    full_source: &str,
    test_module_spans: &[(usize, usize)],
    functions: &[RustFunctionSpan],
) -> Vec<RustCallSite> {
    let mut calls = rust_unqualified_call_sites(body, ident);
    calls.extend(rust_qualified_call_sites(
        body,
        &RustCallSelector {
            segments: vec!["self".to_owned(), ident.to_owned()],
            separators: vec![RustCallSelectorSeparator::Path],
        },
    ));
    if caller.impl_type.as_ref().is_some_and(|impl_type| {
        rust_same_impl_method_exists(full_source, test_module_spans, functions, impl_type, ident)
    }) {
        calls.extend(rust_qualified_call_sites(
            body,
            &RustCallSelector {
                segments: vec!["self".to_owned(), ident.to_owned()],
                separators: vec![RustCallSelectorSeparator::Member],
            },
        ));
        calls.extend(rust_qualified_call_sites(
            body,
            &RustCallSelector {
                segments: vec!["Self".to_owned(), ident.to_owned()],
                separators: vec![RustCallSelectorSeparator::Path],
            },
        ));
    }
    calls.sort_by_key(|call| (call.start, call.close_paren));
    calls.dedup_by_key(|call| (call.start, call.close_paren));
    calls
}

fn rust_same_impl_method_exists(
    full_source: &str,
    test_module_spans: &[(usize, usize)],
    functions: &[RustFunctionSpan],
    impl_type: &str,
    ident: &str,
) -> bool {
    functions.iter().any(|function| {
        function.name == ident
            && function.impl_type.as_deref() == Some(impl_type)
            && !function.is_test_only(full_source, test_module_spans)
    })
}

fn rust_call_sites_for_selector(source: &str, selector: &RustCallSelector) -> Vec<RustCallSite> {
    if selector.is_bare() {
        return rust_bare_call_sites(source, selector.last_segment());
    }
    rust_qualified_call_sites(source, selector)
}

fn rust_bare_call_sites(source: &str, ident: &str) -> Vec<RustCallSite> {
    let mut calls = Vec::new();
    let mut cursor = 0usize;
    while let Some(index) = find_rust_identifier_from(source, ident, cursor) {
        let Some(after_ident) = rust_call_paren_start_after_ident(source, index + ident.len())
        else {
            cursor = index + ident.len();
            continue;
        };
        if source.as_bytes().get(after_ident) == Some(&b'(') {
            if let Ok(close_paren) = match_rust_paren(source, after_ident) {
                calls.push(RustCallSite {
                    start: index,
                    close_paren,
                });
            }
        }
        cursor = index + ident.len();
    }
    calls
}

fn rust_unqualified_call_sites(source: &str, ident: &str) -> Vec<RustCallSite> {
    let mut calls = Vec::new();
    let mut cursor = 0usize;
    while let Some(index) = find_rust_identifier_from(source, ident, cursor) {
        if !rust_identifier_is_unqualified(source, index) {
            cursor = index + ident.len();
            continue;
        }
        let Some(after_ident) = rust_call_paren_start_after_ident(source, index + ident.len())
        else {
            cursor = index + ident.len();
            continue;
        };
        if source.as_bytes().get(after_ident) == Some(&b'(') {
            if let Ok(close_paren) = match_rust_paren(source, after_ident) {
                calls.push(RustCallSite {
                    start: index,
                    close_paren,
                });
            }
        }
        cursor = index + ident.len();
    }
    calls
}

fn rust_identifier_is_unqualified(source: &str, ident_start: usize) -> bool {
    let qualifier_end = skip_ascii_whitespace_back(source, ident_start);
    if qualifier_end >= 2 && &source[qualifier_end - 2..qualifier_end] == "::" {
        return false;
    }
    qualifier_end
        .checked_sub(1)
        .and_then(|index| source.as_bytes().get(index))
        != Some(&b'.')
}

fn rust_qualified_call_sites(source: &str, selector: &RustCallSelector) -> Vec<RustCallSite> {
    let mut calls = Vec::new();
    let ident = selector.last_segment();
    let mut cursor = 0usize;
    while let Some(index) = find_rust_identifier_from(source, ident, cursor) {
        let Some(after_ident) = rust_call_paren_start_after_ident(source, index + ident.len())
        else {
            cursor = index + ident.len();
            continue;
        };
        if source.as_bytes().get(after_ident) == Some(&b'(') {
            if let Some(start) = rust_qualified_call_selector_start(source, selector, index) {
                if let Ok(close_paren) = match_rust_paren(source, after_ident) {
                    calls.push(RustCallSite { start, close_paren });
                }
            }
        }
        cursor = index + ident.len();
    }
    calls
}

fn rust_call_paren_start_after_ident(source: &str, ident_end: usize) -> Option<usize> {
    let mut cursor = skip_ascii_whitespace(source, ident_end);
    if source[cursor..].starts_with("::<") {
        let open_angle = cursor + 2;
        cursor = match_rust_angle(source, open_angle)? + 1;
        cursor = skip_ascii_whitespace(source, cursor);
    }
    Some(cursor)
}

fn rust_qualified_call_selector_start(
    source: &str,
    selector: &RustCallSelector,
    last_ident_start: usize,
) -> Option<usize> {
    let mut cursor = last_ident_start;
    for segment_index in (1..selector.segments.len()).rev() {
        cursor = skip_ascii_whitespace_back(source, cursor);
        match selector.separators[segment_index - 1] {
            RustCallSelectorSeparator::Path => {
                if cursor < 2 || &source[cursor - 2..cursor] != "::" {
                    return None;
                }
                cursor -= 2;
            }
            RustCallSelectorSeparator::Member => {
                if source.as_bytes().get(cursor.checked_sub(1)?) != Some(&b'.') {
                    return None;
                }
                cursor -= 1;
            }
        }
        cursor = skip_ascii_whitespace_back(source, cursor);
        let segment = &selector.segments[segment_index - 1];
        if cursor < segment.len() || &source[cursor - segment.len()..cursor] != segment {
            return None;
        }
        let segment_start = cursor - segment.len();
        let before = segment_start
            .checked_sub(1)
            .and_then(|prev| source.as_bytes().get(prev).copied());
        if before.is_some_and(is_rust_identifier_continuation_byte) {
            return None;
        }
        cursor = segment_start;
    }
    let before = cursor
        .checked_sub(1)
        .and_then(|prev| source.as_bytes().get(prev).copied());
    if before.is_some_and(|byte| {
        is_rust_identifier_continuation_byte(byte) || byte == b':' || byte == b'.'
    }) {
        return None;
    }
    Some(cursor)
}

fn find_rust_identifier_from(source: &str, ident: &str, from: usize) -> Option<usize> {
    if from >= source.len() {
        return None;
    }
    let mut cursor = from;
    while let Some(relative) = source[cursor..].find(ident) {
        let index = cursor + relative;
        let before = index
            .checked_sub(1)
            .and_then(|prev| source.as_bytes().get(prev).copied());
        let after = source.as_bytes().get(index + ident.len()).copied();
        if !before.is_some_and(is_rust_identifier_continuation_byte)
            && !after.is_some_and(is_rust_identifier_continuation_byte)
        {
            return Some(index);
        }
        cursor = index + ident.len();
    }
    None
}

fn match_rust_paren(source: &str, open: usize) -> Result<usize> {
    ensure!(
        source.as_bytes().get(open) == Some(&b'('),
        "expected opening paren at byte {open}"
    );
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().copied().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(open + offset);
                }
            }
            _ => {}
        }
    }
    Err(anyhow!("unclosed Rust paren at byte {open}"))
}

fn skip_ascii_whitespace(source: &str, from: usize) -> usize {
    let mut index = from;
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn skip_ascii_whitespace_back(source: &str, from: usize) -> usize {
    let mut index = from;
    while index > 0
        && source
            .as_bytes()
            .get(index - 1)
            .is_some_and(u8::is_ascii_whitespace)
    {
        index -= 1;
    }
    index
}

fn call_satisfies_result_obligation(
    source: &str,
    raw_source: &str,
    call: &RustCallSite,
    obligation: ResultObligation,
) -> bool {
    debug_assert_eq!(source.len(), raw_source.len());
    match obligation {
        ResultObligation::None => true,
        ResultObligation::MustPropagateResult => call_result_is_propagated(source, call),
        ResultObligation::MustPropagateSharedSledTransactionResult => {
            call_result_is_propagated(source, call)
        }
        ResultObligation::MustCheckResultFailClosed => {
            call_result_is_propagated(source, call) || call_result_is_fail_closed(source, call)
        }
        ResultObligation::MustReturnSubmitActionRejection => {
            call_result_match_err_branch_returns_submit_action_rejection(source, raw_source, call)
        }
        ResultObligation::MustCheckResultLoopSkipFailClosed => {
            call_result_is_loop_skip_fail_closed(source, call)
        }
        ResultObligation::MustFilterOkResult => call_result_is_filter_ok_predicate(source, call),
        ResultObligation::MustContributeToMineableSelection => {
            call_result_contributes_to_mineable_selection(source, call)
        }
        ResultObligation::MustReturnTupleResultComponent => {
            call_tuple_result_component_is_tail_returned(source, call)
        }
        ResultObligation::MustResetWorkTemplateOnErr => {
            call_result_resets_work_template_on_err(source, call)
        }
        ResultObligation::MustGuardFalseFailClosed => {
            call_bool_false_guard_is_fail_closed(source, call)
        }
        ResultObligation::MustMatchSomeOrReturnSupplyDeltaInvalid => {
            call_option_matches_some_or_returns_supply_delta_invalid(source, call)
        }
        ResultObligation::MustMatchSomeAndCompareSupplyClaim => {
            call_option_matches_some_and_compares_supply_claim(source, call)
        }
    }
}

fn call_result_is_propagated(source: &str, call: &RustCallSite) -> bool {
    call_result_has_question_propagation(source, call)
        || call_result_is_tail_returned(source, call)
        || call_result_is_explicit_returned(source, call)
}

fn call_result_has_question_propagation(source: &str, call: &RustCallSite) -> bool {
    let Some(expression_end) = rust_tail_result_expression_end(source, call) else {
        return false;
    };
    let question = skip_ascii_whitespace(source, expression_end);
    source.as_bytes().get(question) == Some(&b'?')
}

fn call_result_is_tail_returned(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    if context.block_path.len() != 1 {
        return false;
    }
    let expression_start = rust_call_expression_start(source, call.start);
    if !source[context.current_statement_start()..expression_start]
        .trim()
        .is_empty()
    {
        return false;
    }
    let Some(expression_end) = rust_tail_result_expression_end(source, call) else {
        return false;
    };
    let expression_end = skip_ascii_whitespace(source, expression_end);
    let Some(block_start) = context.block_path.last().copied() else {
        return false;
    };
    let Ok(block_end) = match_rust_brace(source, block_start) else {
        return false;
    };
    expression_end == block_end
}

fn call_result_is_explicit_returned(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let expression_start = rust_call_expression_start(source, call.start);
    if source[context.current_statement_start()..expression_start].trim() != "return" {
        return false;
    }
    let Some(expression_end) = rust_tail_result_expression_end(source, call) else {
        return false;
    };
    let expression_end = skip_ascii_whitespace(source, expression_end);
    source.as_bytes().get(expression_end) == Some(&b';')
}

fn rust_call_expression_start(source: &str, call_start: usize) -> usize {
    let mut cursor = call_start;
    loop {
        let separator_end = skip_ascii_whitespace_back(source, cursor);
        if separator_end >= 2 && &source[separator_end - 2..separator_end] == "::" {
            let Some(segment_start) = rust_identifier_start_before(source, separator_end - 2)
            else {
                break;
            };
            cursor = segment_start;
            continue;
        }
        if separator_end >= 1 && source.as_bytes().get(separator_end - 1) == Some(&b'.') {
            let receiver_end = skip_ascii_whitespace_back(source, separator_end - 1);
            let Some(receiver_start) = rust_identifier_start_before(source, receiver_end) else {
                break;
            };
            cursor = receiver_start;
            continue;
        }
        break;
    }
    cursor
}

fn rust_identifier_start_before(source: &str, end: usize) -> Option<usize> {
    let end = skip_ascii_whitespace_back(source, end);
    if end == 0 {
        return None;
    }
    let bytes = source.as_bytes();
    let mut start = end;
    while start > 0
        && bytes
            .get(start - 1)
            .is_some_and(|byte| is_rust_identifier_byte(*byte))
    {
        start -= 1;
    }
    if start == end {
        return None;
    }
    let first = *bytes.get(start)?;
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return None;
    }
    Some(start)
}

fn rust_tail_result_expression_end(source: &str, call: &RustCallSite) -> Option<usize> {
    let mut cursor = call.close_paren + 1;
    loop {
        let method_dot = skip_ascii_whitespace(source, cursor);
        if source.as_bytes().get(method_dot) != Some(&b'.') {
            return Some(cursor);
        }
        let method_start = skip_ascii_whitespace(source, method_dot + 1);
        let Some(method_end) = rust_tail_result_method_end(source, method_start) else {
            return Some(cursor);
        };
        let paren_start = skip_ascii_whitespace(source, method_end);
        if source.as_bytes().get(paren_start) != Some(&b'(') {
            return None;
        }
        let paren_end = match_rust_paren(source, paren_start).ok()?;
        cursor = paren_end + 1;
    }
}

fn rust_tail_result_method_end(source: &str, method_start: usize) -> Option<usize> {
    rust_token_at(source, "map_err", method_start)
        .or_else(|| rust_token_at(source, "map", method_start))
        .or_else(|| rust_token_at(source, "context", method_start))
        .or_else(|| rust_token_at(source, "with_context", method_start))
}

fn call_result_is_fail_closed(source: &str, call: &RustCallSite) -> bool {
    call_result_is_err_branch_return(source, call)
        || call_result_if_let_err_branch_return(source, call)
        || call_result_match_err_branch_return(source, call)
        || call_result_bound_is_err_branch_return(source, call)
}

fn call_result_match_err_branch_returns_submit_action_rejection(
    source: &str,
    raw_source: &str,
    call: &RustCallSite,
) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if prefix != "match" && !prefix.ends_with("= match") {
        return false;
    }
    let branch_start = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(branch_start) != Some(&b'{') {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    match_body_has_only_submit_action_rejecting_err_arms(
        source,
        raw_source,
        branch_start + 1,
        branch_end,
    )
}

fn call_bool_false_guard_is_fail_closed(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if prefix != "if !" {
        return false;
    }
    fail_closed_branch_after(source, call.close_paren + 1)
}

fn call_result_is_err_branch_return(source: &str, call: &RustCallSite) -> bool {
    let after_call = skip_ascii_whitespace(source, call.close_paren + 1);
    if !source[after_call..].starts_with(".is_err") {
        return false;
    }
    fail_closed_branch_after(source, after_call)
}

fn call_result_if_let_err_branch_return(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = &source[context.current_statement_start()..call.start];
    if !prefix.contains("if let Err") {
        return false;
    }
    fail_closed_branch_after(source, call.close_paren + 1)
}

fn call_result_is_loop_skip_fail_closed(source: &str, call: &RustCallSite) -> bool {
    if !call_is_inside_loop(source, call.start) {
        return false;
    }
    call_result_if_let_err_branch_continues_loop(source, call)
        || call_result_match_err_branch_continues_loop(source, call)
}

fn call_result_if_let_err_branch_continues_loop(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if !prefix.starts_with("if let Err") {
        return false;
    }
    let Some((lhs, rhs)) = prefix.rsplit_once('=') else {
        return false;
    };
    if !lhs.trim_start().starts_with("if let Err") || !rhs.trim().is_empty() {
        return false;
    }
    let Some(branch_start) =
        next_top_level_rust_brace_before_statement_end(source, call.close_paren + 1)
    else {
        return false;
    };
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    rust_block_has_top_level_terminal_continue(source, branch_start + 1, branch_end)
}

fn call_result_match_err_branch_continues_loop(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if !prefix.ends_with("match") {
        return false;
    }
    let branch_start = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(branch_start) != Some(&b'{') {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    match_body_has_only_continuing_err_arms(source, branch_start + 1, branch_end)
}

fn call_result_is_filter_ok_predicate(source: &str, call: &RustCallSite) -> bool {
    let Some(filter_call) = call_result_direct_filter_ok_call(source, call) else {
        return false;
    };
    filter_call_result_is_used(source, &filter_call)
}

fn call_result_direct_filter_ok_call(source: &str, call: &RustCallSite) -> Option<RustCallSite> {
    let is_ok_end = call_result_direct_is_ok_end(source, call)?;
    let filter_call = enclosing_filter_call(source, call)?;
    let body = filter_closure_body(source, &filter_call)?;
    if call.start < body.start || is_ok_end > body.end {
        return None;
    }

    let expression_start = rust_call_expression_start(source, call.start);
    if expression_start < body.start {
        return None;
    }
    let statement_start = match body.kind {
        RustClosureBodyKind::Block => {
            top_level_statement_start_in_span(source, body.start, call.start)
        }
        RustClosureBodyKind::Expression => body.start,
    };
    if !source[statement_start..expression_start].trim().is_empty() {
        return None;
    }

    (skip_ascii_whitespace(source, is_ok_end) == body.end).then_some(filter_call)
}

fn call_result_contributes_to_mineable_selection(source: &str, call: &RustCallSite) -> bool {
    let Some(filter_call) = call_result_direct_filter_ok_call(source, call) else {
        return false;
    };
    let Some(filter_body) = filter_closure_body(source, &filter_call) else {
        return false;
    };
    let compact_body = compact_ascii_whitespace(&source[filter_body.start..filter_body.end]);
    let final_filter = "letinput=native_mineable_action_admission_input(state,action,selected_candidate_hash);evaluate_native_mineable_action_admission(input).is_ok()";
    if compact_body == final_filter {
        return filter_call_result_is_used(source, &filter_call);
    }

    let preliminary_filter = "letinput=native_mineable_action_admission_input(state,action,None);evaluate_native_mineable_action_admission(input).is_ok()";
    if compact_body != preliminary_filter {
        return false;
    }
    preliminary_mineable_filter_count_reaches_final_selection(source, call, &filter_call)
}

fn compact_ascii_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect()
}

fn preliminary_mineable_filter_count_reaches_final_selection(
    source: &str,
    call: &RustCallSite,
    filter_call: &RustCallSite,
) -> bool {
    let Some((terminal_method, terminal_end)) =
        filter_chain_terminal_method_and_end(source, filter_call)
    else {
        return false;
    };
    if terminal_method != "count" {
        return false;
    }
    let context = rust_statement_context(source, filter_call.start);
    let Some(block_start) = context.block_path.last().copied() else {
        return false;
    };
    let Ok(block_end) = match_rust_brace(source, block_start) else {
        return false;
    };
    let Some((count_statement_end, true)) =
        top_level_statement_end_after(source, terminal_end, block_end)
    else {
        return false;
    };
    if skip_ascii_whitespace(source, terminal_end) != count_statement_end {
        return false;
    }
    let count_prefix = source[context.current_statement_start()..filter_call.start].trim();
    if statement_prefix_named_let_binding(count_prefix).as_deref() != Some("transfer_count") {
        return false;
    }

    let mut selected_candidate_bound = false;
    let mut cursor = skip_ascii_whitespace(source, count_statement_end + 1);
    while cursor < block_end {
        let statement_start = cursor;
        let Some((statement_end, has_semicolon)) =
            top_level_statement_end_after(source, statement_start, block_end)
        else {
            return false;
        };
        let statement = source[statement_start..statement_end].trim();
        if statement_prefix_named_let_binding(statement).as_deref() == Some("transfer_count")
            || statement_assigns_identifier(statement, "transfer_count")
        {
            return false;
        }
        if selected_candidate_bound
            && (statement_prefix_named_let_binding(statement).as_deref()
                == Some("selected_candidate_hash")
                || statement_assigns_identifier(statement, "selected_candidate_hash"))
        {
            return false;
        }

        if statement_prefix_named_let_binding(statement).as_deref()
            == Some("selected_candidate_hash")
        {
            let compact = compact_ascii_whitespace(statement);
            if selected_candidate_bound
                || !compact.starts_with("letselected_candidate_hash=iftransfer_count==0{None}else{")
                || !compact.contains("artifact.tx_countasusize==transfer_count")
                || !compact.contains(".map(|action|action.tx_hash)")
            {
                return false;
            }
            selected_candidate_bound = true;
        }

        if !has_semicolon {
            if !selected_candidate_bound {
                return false;
            }
            return rust_call_sites(source, "evaluate_native_mineable_action_admission")
                .into_iter()
                .filter(|final_call| {
                    call.start < final_call.start
                        && statement_start <= final_call.start
                        && final_call.close_paren <= statement_end
                })
                .any(|final_call| {
                    call_result_contributes_to_mineable_selection(source, &final_call)
                });
        }
        cursor = skip_ascii_whitespace(source, statement_end + 1);
    }
    false
}

fn call_result_direct_is_ok_end(source: &str, call: &RustCallSite) -> Option<usize> {
    let dot = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(dot) != Some(&b'.') {
        return None;
    }
    let method_start = skip_ascii_whitespace(source, dot + 1);
    let after_method = rust_token_at(source, "is_ok", method_start)?;
    let paren_start = skip_ascii_whitespace(source, after_method);
    if source.as_bytes().get(paren_start) != Some(&b'(') {
        return None;
    }
    let paren_end = match_rust_paren(source, paren_start).ok()?;
    if !source[paren_start + 1..paren_end].trim().is_empty() {
        return None;
    }
    Some(paren_end + 1)
}

fn enclosing_filter_call(source: &str, call: &RustCallSite) -> Option<RustCallSite> {
    rust_call_sites(source, "filter")
        .into_iter()
        .filter(|filter_call| {
            rust_call_is_member_invocation(source, filter_call)
                && filter_call.start < call.start
                && call.close_paren < filter_call.close_paren
        })
        .min_by_key(|filter_call| filter_call.close_paren - filter_call.start)
}

fn rust_call_is_member_invocation(source: &str, call: &RustCallSite) -> bool {
    let before = skip_ascii_whitespace_back(source, call.start);
    before > 0 && source.as_bytes().get(before - 1) == Some(&b'.')
}

/// The dedicated shared-sled obligation recognizes only the canonical rooted
/// sled UFCS transaction over the native tuple carrying both legacy canonical
/// trees and the typed V8 tree. A wrapper, alias, incomplete tuple, deferred
/// closure, or locally supplied method named `transaction` is not
/// implementation-binding evidence. The ordinary result-obligation check
/// separately requires `?` (or another accepted propagation form) on the inner
/// helper.
fn rust_prefix_has_noncanonical_return(source: &str) -> bool {
    let mut cursor = 0usize;
    while let Some(return_start) = find_rust_token(source, "return", cursor) {
        let after_return = skip_ascii_whitespace(source, return_start + "return".len());
        let Some(after_err) = source[after_return..]
            .strip_prefix("Err")
            .map(|suffix| source.len() - suffix.len())
        else {
            return true;
        };
        let err_open = skip_ascii_whitespace(source, after_err);
        if source.as_bytes().get(err_open) != Some(&b'(') {
            return true;
        }
        cursor = err_open + 1;
    }
    false
}

fn call_is_in_propagated_shared_sled_transaction_closure(
    source: &str,
    raw_source: &str,
    call: &RustCallSite,
    enclosing_closure: &RustClosureBody,
    allow_pinned_native_error_prefix: bool,
) -> bool {
    debug_assert_eq!(source.len(), raw_source.len());
    let Some(transaction_call) = rust_call_sites(source, "transaction")
        .into_iter()
        .filter(|transaction_call| {
            transaction_call.start < call.start && call.close_paren < transaction_call.close_paren
        })
        .min_by_key(|transaction_call| transaction_call.close_paren - transaction_call.start)
    else {
        return false;
    };
    let Some(transaction_body) = call_closure_body(source, &transaction_call, "transaction") else {
        return false;
    };
    let context = rust_statement_context(source, transaction_call.start);
    let transaction_statement_start = context.current_statement_start();
    let prefix = &source[..transaction_statement_start];
    if if allow_pinned_native_error_prefix {
        rust_prefix_has_noncanonical_return(prefix)
    } else {
        find_rust_token(prefix, "return", 0).is_some()
    } {
        return false;
    }
    let rooted_ufcs_path =
        compact_ascii_whitespace(&source[transaction_statement_start..transaction_call.start])
            == "self::__hegemon_pinned_sled::transaction::Transactional::";
    let Some(open_paren) = rust_call_open_paren(source, &transaction_call, "transaction") else {
        return false;
    };
    let Some(first_closure_bar) =
        find_top_level_byte(source, open_paren + 1, transaction_call.close_paren, b'|')
    else {
        return false;
    };
    let Some(second_closure_bar) = find_top_level_byte(
        source,
        first_closure_bar + 1,
        transaction_call.close_paren,
        b'|',
    ) else {
        return false;
    };
    // This is intentionally an exact grammar, not a substring inventory. The
    // production commit transaction carries these eleven trees in this order
    // as the sole argument before the closure.
    let canonical_shared_tree_argument =
        compact_ascii_whitespace(&source[open_paren + 1..first_closure_bar])
            == "&(&self.meta_tree,&self.height_tree,&self.block_tree,&self.commitment_tree,\
        &self.nullifier_tree,&self.bridge_inbound_tree,&self.ciphertext_index_tree,\
        &self.ciphertext_archive_tree,&self.da_ciphertext_tree,&self.action_tree,\
        &self.poseidon2_v8_tree,),";
    let canonical_transactional_tree_pattern =
        compact_ascii_whitespace(&source[first_closure_bar + 1..second_closure_bar])
            == "(meta_tree,height_tree,block_tree,commitment_tree,nullifier_tree,\
        bridge_inbound_tree,ciphertext_index_tree,ciphertext_archive_tree,\
        da_ciphertext_tree,action_tree,poseidon2_v8_tree,)";
    let transaction_is_top_level_caller_statement = context.block_path.len() == 1;
    let helper_is_first_top_level_statement = transaction_body.kind == RustClosureBodyKind::Block
        && source[transaction_body.start..rust_call_expression_start(source, call.start)]
            .trim()
            .is_empty();
    let Some(helper_open_paren) = source[call.start..call.close_paren]
        .find('(')
        .map(|relative| call.start + relative)
    else {
        return false;
    };
    let compact_helper_path = compact_ascii_whitespace(&source[call.start..helper_open_paren]);
    let helper_is_module_anchored = compact_helper_path
        .strip_prefix("self::")
        .is_some_and(is_plain_rust_identifier);
    let Some(first_helper_comma) =
        find_top_level_byte(source, helper_open_paren + 1, call.close_paren, b',')
    else {
        return false;
    };
    let Some(second_helper_comma) =
        find_top_level_byte(source, first_helper_comma + 1, call.close_paren, b',')
    else {
        return false;
    };
    let Some(third_helper_comma) =
        find_top_level_byte(source, second_helper_comma + 1, call.close_paren, b',')
    else {
        return false;
    };
    let Some(fourth_helper_comma) =
        find_top_level_byte(source, third_helper_comma + 1, call.close_paren, b',')
    else {
        return false;
    };
    let helper_tree = compact_ascii_whitespace(&source[helper_open_paren + 1..first_helper_comma]);
    let helper_plan =
        compact_ascii_whitespace(&source[first_helper_comma + 1..second_helper_comma]);
    let helper_manifest =
        compact_ascii_whitespace(&source[second_helper_comma + 1..third_helper_comma]);
    let helper_context = raw_source[third_helper_comma + 1..fourth_helper_comma].trim();
    let helper_has_exact_four_arguments = source[fourth_helper_comma + 1..call.close_paren]
        .trim()
        .is_empty();
    let caller_specific_helper_arguments = helper_tree == "poseidon2_v8_tree"
        && ((helper_plan == "poseidon2_v8_reorg.as_ref().map(|(_,v8_plan)|v8_plan)"
            && helper_manifest == "suffix_manifest"
            && helper_context == "\"native canonical suffix reorg manifest\"")
            || (helper_plan == "v8_commit.as_ref().map(|(_,plan)|plan)"
                && helper_manifest == "mined_manifest"
                && helper_context == "\"native mined block commit manifest\""))
        && helper_has_exact_four_arguments;
    let helper_question = skip_ascii_whitespace(source, call.close_paren + 1);
    let helper_semicolon = skip_ascii_whitespace(source, helper_question.saturating_add(1));
    let helper_is_directly_propagated_statement = source.as_bytes().get(helper_question)
        == Some(&b'?')
        && source.as_bytes().get(helper_semicolon) == Some(&b';');
    let typed_tree_is_not_touched_after_helper = helper_semicolon < transaction_body.end
        && find_rust_identifier_from(
            &source[helper_semicolon + 1..transaction_body.end],
            "poseidon2_v8_tree",
            0,
        )
        .is_none();
    let accepted = rooted_ufcs_path
        && canonical_shared_tree_argument
        && canonical_transactional_tree_pattern
        && transaction_is_top_level_caller_statement
        && *enclosing_closure == transaction_body
        && helper_is_first_top_level_statement
        && helper_is_module_anchored
        && caller_specific_helper_arguments
        && helper_is_directly_propagated_statement
        && typed_tree_is_not_touched_after_helper
        && call_result_is_propagated(source, &transaction_call);
    #[cfg(test)]
    if !accepted {
        eprintln!(
            "shared sled rejection: rooted={rooted_ufcs_path} trees={canonical_shared_tree_argument} pattern={canonical_transactional_tree_pattern} top={transaction_is_top_level_caller_statement} closure={} first={helper_is_first_top_level_statement} args={caller_specific_helper_arguments} inner={helper_is_directly_propagated_statement} post_tree={typed_tree_is_not_touched_after_helper} outer={}",
            *enclosing_closure == transaction_body,
            call_result_is_propagated(source, &transaction_call),
        );
    }
    accepted
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustClosureBodyKind {
    Block,
    Expression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RustClosureBody {
    start: usize,
    end: usize,
    kind: RustClosureBodyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RustSourceSpan {
    start: usize,
    end: usize,
}

fn rust_call_is_direct_binding_evidence(
    source: &str,
    raw_source: &str,
    call: &RustCallSite,
    obligation: ResultObligation,
    closures: &[RustClosureBody],
    async_blocks: &[RustSourceSpan],
    macro_bodies: &[RustSourceSpan],
    allow_pinned_native_error_prefix: bool,
) -> bool {
    if rust_position_is_inside_spans(call.start, async_blocks)
        || rust_position_is_inside_spans(call.start, macro_bodies)
        || rust_call_is_in_statically_dead_short_circuit_rhs(source, call)
        || rust_call_is_in_statically_dead_control_flow(source, call)
    {
        return false;
    }

    let enclosing_closures = closures
        .iter()
        .filter(|closure| closure.start <= call.start && call.start < closure.end)
        .collect::<Vec<_>>();
    if obligation == ResultObligation::MustPropagateSharedSledTransactionResult {
        return enclosing_closures.len() == 1
            && call_is_in_propagated_shared_sled_transaction_closure(
                source,
                raw_source,
                call,
                enclosing_closures[0],
                allow_pinned_native_error_prefix,
            );
    }
    if enclosing_closures.is_empty() {
        return true;
    }
    if !matches!(
        obligation,
        ResultObligation::MustFilterOkResult | ResultObligation::MustContributeToMineableSelection
    ) || enclosing_closures.len() != 1
    {
        return false;
    }
    let Some(filter_call) = enclosing_filter_call(source, call) else {
        return false;
    };
    let Some(filter_body) = filter_closure_body(source, &filter_call) else {
        return false;
    };
    *enclosing_closures[0] == filter_body
        && call_result_direct_filter_ok_call(source, call).is_some()
}

fn rust_call_is_direct_order_evidence(
    source: &str,
    call: &RustCallSite,
    closures: &[RustClosureBody],
    async_blocks: &[RustSourceSpan],
    macro_bodies: &[RustSourceSpan],
) -> bool {
    !rust_call_is_inside_closure(call, closures)
        && !rust_position_is_inside_spans(call.start, async_blocks)
        && !rust_position_is_inside_spans(call.start, macro_bodies)
        && !rust_call_is_in_short_circuit_rhs(source, call)
        && !rust_call_is_in_statically_dead_control_flow(source, call)
}

fn rust_call_is_in_statically_dead_control_flow(source: &str, call: &RustCallSite) -> bool {
    rust_statement_context(source, call.start)
        .block_path
        .into_iter()
        .any(|block_start| {
            let prefix_start = rust_control_prefix_start_before_block(source, block_start);
            matches!(
                source[prefix_start..block_start].trim(),
                "if false" | "while false"
            )
        })
}

fn rust_position_is_inside_spans(position: usize, spans: &[RustSourceSpan]) -> bool {
    spans
        .iter()
        .any(|span| span.start <= position && position < span.end)
}

fn rust_call_is_inside_closure(call: &RustCallSite, closures: &[RustClosureBody]) -> bool {
    closures
        .iter()
        .any(|closure| closure.start <= call.start && call.start < closure.end)
}

fn rust_closure_body_spans(source: &str) -> Vec<RustClosureBody> {
    let bytes = source.as_bytes();
    let mut closures = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let Some(relative) = source[cursor..].find('|') else {
            break;
        };
        let first_bar = cursor + relative;
        if !rust_closure_can_start(source, first_bar) {
            cursor = first_bar + 1;
            continue;
        }
        let after_parameters = if bytes.get(first_bar + 1) == Some(&b'|') {
            first_bar + 2
        } else {
            let Some(second_bar) = rust_closure_parameter_end(source, first_bar + 1) else {
                cursor = first_bar + 1;
                continue;
            };
            if second_bar - first_bar > 4096 {
                cursor = first_bar + 1;
                continue;
            }
            second_bar + 1
        };
        let body_start = skip_ascii_whitespace(source, after_parameters);
        let Some(first_body_byte) = bytes.get(body_start).copied() else {
            break;
        };
        let (start, end, kind) = if first_body_byte == b'{' {
            let Ok(body_end) = match_rust_brace(source, body_start) else {
                cursor = first_bar + 1;
                continue;
            };
            (body_start + 1, body_end, RustClosureBodyKind::Block)
        } else if source[body_start..].starts_with("->") {
            let Some(relative_open) = source[body_start + 2..].find('{') else {
                cursor = first_bar + 1;
                continue;
            };
            let body_open = body_start + 2 + relative_open;
            let Ok(body_end) = match_rust_brace(source, body_open) else {
                cursor = first_bar + 1;
                continue;
            };
            (body_open + 1, body_end, RustClosureBodyKind::Block)
        } else {
            (
                body_start,
                rust_closure_expression_end(source, body_start),
                RustClosureBodyKind::Expression,
            )
        };
        if start < end {
            closures.push(RustClosureBody { start, end, kind });
        }
        cursor = first_bar + 1;
    }
    closures
}

fn rust_async_block_body_spans(source: &str) -> Vec<RustSourceSpan> {
    let mut spans = Vec::new();
    let mut cursor = 0usize;
    while let Some(async_start) = find_rust_token(source, "async", cursor) {
        let mut body_start = skip_ascii_whitespace(source, async_start + "async".len());
        if let Some(after_move) = rust_token_at(source, "move", body_start) {
            body_start = skip_ascii_whitespace(source, after_move);
        }
        if source.as_bytes().get(body_start) == Some(&b'{') {
            if let Ok(body_end) = match_rust_brace(source, body_start) {
                spans.push(RustSourceSpan {
                    start: body_start + 1,
                    end: body_end,
                });
                cursor = body_end + 1;
                continue;
            }
        }
        cursor = async_start + "async".len();
    }
    spans
}

fn rust_closure_parameter_end(source: &str, from: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut index = from;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.saturating_sub(1),
            b'|' if paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0
                && angle_depth == 0 =>
            {
                return Some(index);
            }
            b';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => return None,
            _ => {}
        }
        index += 1;
    }
    None
}

fn rust_closure_can_start(source: &str, first_bar: usize) -> bool {
    let prefix = source[..first_bar].trim_end();
    if prefix.is_empty() {
        return true;
    }
    if [
        "move", "async", "return", "mut", "else", "break", "yield", "const",
    ]
    .iter()
    .any(|token| rust_prefix_ends_with_token(prefix, token))
    {
        return true;
    }
    if prefix.ends_with("=>") {
        return true;
    }
    matches!(
        prefix.as_bytes().last(),
        Some(b'=')
            | Some(b'(')
            | Some(b'[')
            | Some(b'{')
            | Some(b',')
            | Some(b';')
            | Some(b':')
            | Some(b'!')
            | Some(b'?')
            | Some(b'&')
            | Some(b'+')
            | Some(b'-')
            | Some(b'*')
            | Some(b'/')
            | Some(b'%')
            | Some(b'^')
    )
}

fn rust_prefix_ends_with_token(prefix: &str, token: &str) -> bool {
    if !prefix.ends_with(token) {
        return false;
    }
    prefix
        .len()
        .checked_sub(token.len() + 1)
        .and_then(|index| prefix.as_bytes().get(index).copied())
        .is_none_or(|byte| !is_rust_identifier_continuation_byte(byte))
}

fn rust_closure_expression_end(source: &str, from: usize) -> usize {
    let bytes = source.as_bytes();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut index = from;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' if paren_depth == 0 => return index,
            b')' => paren_depth -= 1,
            b'[' => bracket_depth += 1,
            b']' if bracket_depth == 0 => return index,
            b']' => bracket_depth -= 1,
            b'{' => brace_depth += 1,
            b'}' if brace_depth == 0 => return index,
            b'}' => brace_depth -= 1,
            b'<' if angle_depth > 0 || source[..index].trim_end().ends_with("::") => {
                angle_depth += 1;
            }
            b'>' if angle_depth > 0 => angle_depth -= 1,
            b',' | b';'
                if paren_depth == 0
                    && bracket_depth == 0
                    && brace_depth == 0
                    && angle_depth == 0 =>
            {
                return index;
            }
            _ => {}
        }
        index += 1;
    }
    source.len()
}

fn filter_closure_body(source: &str, filter_call: &RustCallSite) -> Option<RustClosureBody> {
    call_closure_body(source, filter_call, "filter")
}

fn call_closure_body(
    source: &str,
    outer_call: &RustCallSite,
    method: &str,
) -> Option<RustClosureBody> {
    let open_paren = rust_call_open_paren(source, outer_call, method)?;
    let first_bar = find_top_level_byte(source, open_paren + 1, outer_call.close_paren, b'|')?;
    let second_bar = find_top_level_byte(source, first_bar + 1, outer_call.close_paren, b'|')?;
    let body_start = skip_ascii_whitespace(source, second_bar + 1);
    if source.as_bytes().get(body_start) == Some(&b'{') {
        let body_end = match_rust_brace(source, body_start).ok()?;
        if body_end > outer_call.close_paren {
            return None;
        }
        return Some(RustClosureBody {
            start: body_start + 1,
            end: body_end,
            kind: RustClosureBodyKind::Block,
        });
    }
    Some(RustClosureBody {
        start: body_start,
        end: outer_call.close_paren,
        kind: RustClosureBodyKind::Expression,
    })
}

fn filter_call_result_is_used(source: &str, filter_call: &RustCallSite) -> bool {
    let Some(terminal_end) = filter_chain_terminal_end(source, filter_call) else {
        return false;
    };
    let context = rust_statement_context(source, filter_call.start);
    let Some(block_start) = context.block_path.last().copied() else {
        return false;
    };
    let Ok(block_end) = match_rust_brace(source, block_start) else {
        return false;
    };
    let Some((statement_end, has_semicolon)) =
        top_level_statement_end_after(source, terminal_end, block_end)
    else {
        return false;
    };
    if skip_ascii_whitespace(source, terminal_end) != statement_end {
        return false;
    }

    let prefix = source[context.current_statement_start()..filter_call.start].trim();
    if has_semicolon {
        if prefix.starts_with("return ") {
            return true;
        }
        if let Some(binding) = statement_prefix_named_let_binding(prefix) {
            identifier_reaches_block_sink(source, &binding, statement_end, block_end)
        } else {
            false
        }
    } else {
        true
    }
}

fn filter_chain_terminal_end(source: &str, filter_call: &RustCallSite) -> Option<usize> {
    filter_chain_terminal_method_and_end(source, filter_call).map(|(_, end)| end)
}

fn filter_chain_terminal_method_and_end<'a>(
    source: &'a str,
    filter_call: &RustCallSite,
) -> Option<(&'a str, usize)> {
    let mut cursor = filter_call.close_paren + 1;
    loop {
        let method_dot = skip_ascii_whitespace(source, cursor);
        if source.as_bytes().get(method_dot) != Some(&b'.') {
            return None;
        }
        let method_start = skip_ascii_whitespace(source, method_dot + 1);
        let (method, method_end) = rust_method_name_at(source, method_start)?;
        let paren_start = rust_call_paren_start_after_ident(source, method_end)?;
        if source.as_bytes().get(paren_start) != Some(&b'(') {
            return None;
        }
        let paren_end = match_rust_paren(source, paren_start).ok()?;
        cursor = paren_end + 1;
        if iterator_terminal_method_consumes_filtered_result(method) {
            return Some((method, cursor));
        }
        if !iterator_method_preserves_filtered_result(method) {
            return None;
        }
    }
}

fn rust_method_name_at(source: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let first = *bytes.get(start)?;
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| is_rust_identifier_byte(*byte))
    {
        end += 1;
    }
    Some((&source[start..end], end))
}

fn iterator_terminal_method_consumes_filtered_result(method: &str) -> bool {
    matches!(
        method,
        "all"
            | "any"
            | "collect"
            | "count"
            | "find"
            | "fold"
            | "for_each"
            | "next"
            | "partition"
            | "try_collect"
            | "try_fold"
            | "try_for_each"
    )
}

fn iterator_method_preserves_filtered_result(method: &str) -> bool {
    matches!(
        method,
        "by_ref" | "cloned" | "copied" | "enumerate" | "fuse" | "inspect" | "take"
    )
}

fn statement_prefix_named_let_binding(prefix: &str) -> Option<String> {
    let rest = prefix.strip_prefix("let ")?;
    let (lhs, _rhs_prefix) = rest.split_once('=')?;
    let mut lhs = lhs.trim_start();
    if let Some(after_mut) = lhs.strip_prefix("mut ") {
        lhs = after_mut.trim_start();
    }
    let bytes = lhs.as_bytes();
    let first = bytes.first().copied()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let mut ident_end = 1usize;
    while bytes
        .get(ident_end)
        .is_some_and(|byte| is_rust_identifier_byte(*byte))
    {
        ident_end += 1;
    }
    let ident = &lhs[..ident_end];
    (!ident.starts_with('_')).then(|| ident.to_owned())
}

fn identifier_reaches_block_sink(source: &str, ident: &str, from: usize, to: usize) -> bool {
    let mut cursor = skip_ascii_whitespace(source, from);
    while cursor < to {
        let statement_start = cursor;
        let Some((statement_end, has_semicolon)) =
            top_level_statement_end_after(source, statement_start, to)
        else {
            return false;
        };
        let statement = source[statement_start..statement_end].trim();
        if statement_prefix_named_let_binding(statement).as_deref() == Some(ident)
            || statement_assigns_identifier(statement, ident)
        {
            return false;
        }
        let next = if has_semicolon {
            skip_ascii_whitespace(source, statement_end + 1)
        } else {
            to
        };
        if next >= to {
            return identifier_occurs_in_span(source, ident, statement_start, statement_end);
        }
        cursor = next;
    }
    false
}

fn statement_assigns_identifier(statement: &str, ident: &str) -> bool {
    let statement = statement.trim_start();
    let Some(after_ident) = statement.strip_prefix(ident) else {
        return false;
    };
    if statement
        .as_bytes()
        .get(ident.len())
        .is_some_and(|byte| is_rust_identifier_continuation_byte(*byte))
    {
        return false;
    }
    let suffix = after_ident.trim_start();
    suffix.starts_with('=')
        || ["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="]
            .iter()
            .any(|operator| suffix.starts_with(operator))
}

fn identifier_occurs_in_span(source: &str, ident: &str, from: usize, to: usize) -> bool {
    let bytes = source.as_bytes();
    let ident_bytes = ident.as_bytes();
    let mut cursor = from;
    while cursor < to {
        let Some(relative) = source[cursor..to].find(ident) else {
            return false;
        };
        let start = cursor + relative;
        let end = start + ident_bytes.len();
        let before_is_ident = start
            .checked_sub(1)
            .and_then(|idx| bytes.get(idx))
            .is_some_and(|byte| is_rust_identifier_continuation_byte(*byte));
        let after_is_ident = bytes
            .get(end)
            .is_some_and(|byte| is_rust_identifier_continuation_byte(*byte));
        if !before_is_ident && !after_is_ident {
            return true;
        }
        cursor = end;
    }
    false
}

fn rust_call_open_paren(source: &str, call: &RustCallSite, ident: &str) -> Option<usize> {
    let open_paren = skip_ascii_whitespace(source, call.start + ident.len());
    (source.as_bytes().get(open_paren) == Some(&b'(')).then_some(open_paren)
}

fn find_top_level_byte(source: &str, from: usize, end: usize, target: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = from;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < end {
        let byte = *bytes.get(index)?;
        if byte == target && paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 {
            return Some(index);
        }
        match byte {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    None
}

fn top_level_statement_start_in_span(source: &str, start: usize, target: usize) -> usize {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut statement_start = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < target && index < bytes.len() {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                statement_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    skip_ascii_whitespace(source, statement_start)
}

fn call_tuple_result_component_is_tail_returned(source: &str, call: &RustCallSite) -> bool {
    let Some(result_name) = direct_tuple_result_binding_name(source, call) else {
        return false;
    };
    let statement_end = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(statement_end) != Some(&b';') {
        return false;
    }
    let tail_start = skip_ascii_whitespace(source, statement_end + 1);
    let Some(after_result) = rust_identifier_at(source, &result_name, tail_start) else {
        return false;
    };
    let after_result = skip_ascii_whitespace(source, after_result);
    let context = rust_statement_context(source, call.start);
    let Some(block_start) = context.block_path.last().copied() else {
        return false;
    };
    let Ok(block_end) = match_rust_brace(source, block_start) else {
        return false;
    };
    after_result == block_end
}

fn direct_tuple_result_binding_name(source: &str, call: &RustCallSite) -> Option<String> {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    let rest = prefix.strip_prefix("let ")?.trim();
    let lhs = rest.strip_suffix('=')?.trim();
    let inner = lhs.strip_prefix('(')?.strip_suffix(')')?;
    let mut parts = inner.split(',').map(str::trim);
    let _first = parts.next()?;
    let second = parts.next()?;
    if parts.next().is_some() || !is_plain_rust_identifier(second) || second == "_" {
        return None;
    }
    Some(second.to_owned())
}

fn call_result_resets_work_template_on_err(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if prefix != "let supply_digest = match" {
        return false;
    }
    let branch_start = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(branch_start) != Some(&b'{') {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    match_body_has_work_template_supply_fallback(source, branch_start + 1, branch_end)
}

fn call_option_matches_some_or_returns_supply_delta_invalid(
    source: &str,
    call: &RustCallSite,
) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if prefix != "let expected_supply = match" {
        return false;
    }
    let branch_start = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(branch_start) != Some(&b'{') {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    match_body_has_expected_supply_or_delta_invalid(source, branch_start + 1, branch_end)
}

fn call_option_matches_some_and_compares_supply_claim(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if prefix != "let Some(expected_supply) =" {
        return false;
    }
    let after_call = skip_ascii_whitespace(source, call.close_paren + 1);
    let Some(after_else) = rust_token_at(source, "else", after_call) else {
        return false;
    };
    let branch_start = skip_ascii_whitespace(source, after_else);
    if source.as_bytes().get(branch_start) != Some(&b'{') {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    if !rust_block_has_top_level_statement_matching(
        source,
        branch_start + 1,
        branch_end,
        |statement| statement_returns_consensus_error_variant(statement, "InvalidCoinbase"),
    ) {
        return false;
    }
    let statement_end = skip_ascii_whitespace(source, branch_end + 1);
    if source.as_bytes().get(statement_end) != Some(&b';') {
        return false;
    }
    let next_statement = skip_ascii_whitespace(source, statement_end + 1);
    statement_compares_expected_supply_to_header_digest(source, next_statement)
}

fn statement_compares_expected_supply_to_header_digest(
    source: &str,
    statement_start: usize,
) -> bool {
    let Some(after_if) = rust_token_at(source, "if", statement_start) else {
        return false;
    };
    let Some(branch_start) =
        next_top_level_rust_brace_before_statement_end(source, statement_start)
    else {
        return false;
    };
    let condition = source[after_if..branch_start].trim();
    if condition != "expected_supply != block.header.supply_digest" {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    rust_block_has_top_level_statement_matching(source, branch_start + 1, branch_end, |statement| {
        statement_returns_consensus_error_variant(statement, "InvalidHeader")
    })
}

fn statement_returns_consensus_error_variant(statement: &str, variant: &str) -> bool {
    let compact = statement
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(char::from)
        .collect::<String>();
    let prefix = format!("returnErr(ConsensusError::{variant}(");
    compact.starts_with(&prefix) && compact.ends_with("))")
}

fn match_body_has_expected_supply_or_delta_invalid(
    source: &str,
    body_start: usize,
    body_end: usize,
) -> bool {
    let mut cursor = body_start;
    let mut saw_some = false;
    let mut saw_none = false;
    while cursor < body_end {
        cursor = skip_match_arm_separator(source, cursor, body_end);
        if cursor >= body_end {
            break;
        }
        let Some(arrow) = find_top_level_fat_arrow(source, cursor, body_end) else {
            return false;
        };
        let pattern = source[cursor..arrow].trim();
        let arm_body_start = skip_ascii_whitespace(source, arrow + 2);
        let arm_body_end = top_level_match_arm_end(source, arm_body_start, body_end);
        if match_pattern_binds_some(pattern, "expected_supply") {
            if saw_some
                || !match_arm_body_is_identifier(
                    source,
                    arm_body_start,
                    arm_body_end,
                    "expected_supply",
                )
            {
                return false;
            }
            saw_some = true;
        } else if match_pattern_is_plain_none(pattern) {
            if saw_none
                || !match_arm_body_returns_supply_delta_invalid(
                    source,
                    arm_body_start,
                    arm_body_end,
                )
            {
                return false;
            }
            saw_none = true;
        } else {
            return false;
        }
        cursor = arm_body_end.saturating_add(1);
    }
    saw_some && saw_none
}

fn match_body_has_work_template_supply_fallback(
    source: &str,
    body_start: usize,
    body_end: usize,
) -> bool {
    let mut cursor = body_start;
    let mut saw_ok = false;
    let mut saw_err = false;
    while cursor < body_end {
        cursor = skip_match_arm_separator(source, cursor, body_end);
        if cursor >= body_end {
            break;
        }
        let Some(arrow) = find_top_level_fat_arrow(source, cursor, body_end) else {
            return false;
        };
        let pattern = source[cursor..arrow].trim();
        let arm_body_start = skip_ascii_whitespace(source, arrow + 2);
        let arm_body_end = top_level_match_arm_end(source, arm_body_start, body_end);
        if match_pattern_binds_ok(pattern, "supply_digest") {
            if saw_ok
                || !match_arm_body_is_identifier(
                    source,
                    arm_body_start,
                    arm_body_end,
                    "supply_digest",
                )
            {
                return false;
            }
            saw_ok = true;
        } else if match_pattern_is_plain_err(pattern) {
            if saw_err || !match_arm_body_resets_work_template(source, arm_body_start, arm_body_end)
            {
                return false;
            }
            saw_err = true;
        } else {
            return false;
        }
        cursor = arm_body_end.saturating_add(1);
    }
    saw_ok && saw_err
}

fn match_pattern_binds_ok(pattern: &str, binding: &str) -> bool {
    if pattern.contains(" if ") {
        return false;
    }
    let pattern = pattern.trim();
    let Some(inner) = pattern
        .strip_prefix("Ok(")
        .and_then(|raw| raw.strip_suffix(')'))
    else {
        return false;
    };
    inner.trim() == binding
}

fn match_pattern_binds_some(pattern: &str, binding: &str) -> bool {
    if pattern.contains(" if ") {
        return false;
    }
    let pattern = pattern.trim();
    let Some(inner) = pattern
        .strip_prefix("Some(")
        .and_then(|raw| raw.strip_suffix(')'))
    else {
        return false;
    };
    inner.trim() == binding
}

fn match_pattern_is_plain_none(pattern: &str) -> bool {
    if pattern.contains(" if ") {
        return false;
    }
    pattern.trim() == "None"
}

fn match_arm_body_is_identifier(source: &str, start: usize, end: usize, ident: &str) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if start >= end {
        return false;
    }
    if source.as_bytes().get(start) == Some(&b'{') {
        let Ok(block_end) = match_rust_brace(source, start) else {
            return false;
        };
        return block_end <= end
            && top_level_block_tail_expression(source, start + 1, block_end) == Some(ident);
    }
    source[start..end].trim() == ident
}

fn match_arm_body_returns_supply_delta_invalid(source: &str, start: usize, end: usize) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if source.as_bytes().get(start) != Some(&b'{') {
        return false;
    }
    let Ok(block_end) = match_rust_brace(source, start) else {
        return false;
    };
    if block_end > end {
        return false;
    }
    let body_start = start + 1;
    rust_block_has_top_level_statement(
        source,
        body_start,
        block_end,
        "let rejection = NativeBlockReplayRefinementRejection::SupplyDeltaInvalid",
    ) && rust_block_has_top_level_statement(
        source,
        body_start,
        block_end,
        "return (trace, Err(rejection))",
    )
}

fn match_arm_body_resets_work_template(source: &str, start: usize, end: usize) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if source.as_bytes().get(start) != Some(&b'{') {
        return false;
    }
    let Ok(block_end) = match_rust_brace(source, start) else {
        return false;
    };
    if block_end > end {
        return false;
    }
    let body_start = start + 1;
    rust_block_has_top_level_statement(source, body_start, block_end, "actions = Vec::new()")
        && rust_block_has_top_level_statement(
            source,
            body_start,
            block_end,
            "state_root = best.state_root",
        )
        && rust_block_has_top_level_statement(
            source,
            body_start,
            block_end,
            "nullifier_root = best.nullifier_root",
        )
        && rust_block_has_top_level_statement(
            source,
            body_start,
            block_end,
            "extrinsics_root = actions_extrinsics_root(&[])",
        )
        && rust_block_has_top_level_statement(source, body_start, block_end, "tx_count = 0")
        && top_level_block_tail_expression(source, body_start, block_end)
            == Some("best.supply_digest")
}

fn top_level_block_tail_expression(
    source: &str,
    body_start: usize,
    block_end: usize,
) -> Option<&str> {
    let tail_start = top_level_statement_start_in_span(source, body_start, block_end);
    let tail = source[tail_start..block_end].trim();
    (!tail.is_empty()).then_some(tail)
}

fn rust_block_has_top_level_statement(
    source: &str,
    start: usize,
    end: usize,
    expected: &str,
) -> bool {
    let bytes = source.as_bytes();
    let mut cursor = start;
    let mut statement_start = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while cursor < end && cursor < bytes.len() {
        match bytes[cursor] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                if source[statement_start..cursor].trim() == expected {
                    return true;
                }
                statement_start = cursor + 1;
            }
            _ => {}
        }
        cursor += 1;
    }
    false
}

fn rust_block_has_top_level_statement_matching(
    source: &str,
    start: usize,
    end: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let bytes = source.as_bytes();
    let mut cursor = start;
    let mut statement_start = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while cursor < end && cursor < bytes.len() {
        match bytes[cursor] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                if predicate(source[statement_start..cursor].trim()) {
                    return true;
                }
                statement_start = cursor + 1;
            }
            _ => {}
        }
        cursor += 1;
    }
    false
}

fn call_result_match_err_branch_return(source: &str, call: &RustCallSite) -> bool {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    if prefix != "match" && !prefix.ends_with("= match") {
        return false;
    }
    let branch_start = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(branch_start) != Some(&b'{') {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    match_body_has_err_return_arm(source, branch_start + 1, branch_end)
}

fn call_result_bound_is_err_branch_return(source: &str, call: &RustCallSite) -> bool {
    let Some(result_name) = direct_result_binding_name(source, call) else {
        return false;
    };
    let statement_end = skip_ascii_whitespace(source, call.close_paren + 1);
    if source.as_bytes().get(statement_end) != Some(&b';') {
        return false;
    }
    let next_statement = skip_ascii_whitespace(source, statement_end + 1);
    statement_is_result_is_err_return(source, next_statement, &result_name)
        || statement_is_result_if_let_err_return(source, next_statement, &result_name)
        || statement_is_result_match_err_return(source, next_statement, &result_name)
}

fn direct_result_binding_name(source: &str, call: &RustCallSite) -> Option<String> {
    let context = rust_statement_context(source, call.start);
    let prefix = source[context.current_statement_start()..call.start].trim();
    let mut rest = prefix.strip_prefix("let ")?.trim_start();
    if let Some(after_mut) = rest.strip_prefix("mut ") {
        rest = after_mut.trim_start();
    }
    let bytes = rest.as_bytes();
    let first = *bytes.first()?;
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return None;
    }
    let mut ident_end = 1usize;
    while bytes
        .get(ident_end)
        .is_some_and(|byte| is_rust_identifier_byte(*byte))
    {
        ident_end += 1;
    }
    let name = &rest[..ident_end];
    let after_name = rest[ident_end..].trim_start();
    let after_equals = after_name.strip_prefix('=')?.trim();
    if !after_equals.is_empty() {
        return None;
    }
    Some(name.to_owned())
}

fn statement_is_result_is_err_return(
    source: &str,
    statement_start: usize,
    result_name: &str,
) -> bool {
    let Some(after_if) = rust_token_at(source, "if", statement_start) else {
        return false;
    };
    let condition_start = skip_ascii_whitespace(source, after_if);
    let Some(after_name) = rust_identifier_at(source, result_name, condition_start) else {
        return false;
    };
    let method_start = skip_ascii_whitespace(source, after_name);
    if source.as_bytes().get(method_start) != Some(&b'.') {
        return false;
    }
    let Some(after_method) = rust_token_at(source, "is_err", method_start + 1) else {
        return false;
    };
    let paren_start = skip_ascii_whitespace(source, after_method);
    if source.as_bytes().get(paren_start) != Some(&b'(') {
        return false;
    }
    let Ok(paren_end) = match_rust_paren(source, paren_start) else {
        return false;
    };
    if !source[paren_start + 1..paren_end].trim().is_empty() {
        return false;
    }
    fail_closed_branch_after(source, paren_end + 1)
}

fn statement_is_result_if_let_err_return(
    source: &str,
    statement_start: usize,
    result_name: &str,
) -> bool {
    let Some(branch_start) =
        next_top_level_rust_brace_before_statement_end(source, statement_start)
    else {
        return false;
    };
    let condition = source[statement_start..branch_start].trim();
    if !condition.starts_with("if let Err") {
        return false;
    }
    let Some((_, rhs)) = condition.rsplit_once('=') else {
        return false;
    };
    if rhs.trim() != result_name {
        return false;
    }
    fail_closed_branch_after(source, statement_start)
}

fn statement_is_result_match_err_return(
    source: &str,
    statement_start: usize,
    result_name: &str,
) -> bool {
    let Some(after_match) = rust_token_at(source, "match", statement_start) else {
        return false;
    };
    let match_operand_start = skip_ascii_whitespace(source, after_match);
    let Some(after_name) = rust_identifier_at(source, result_name, match_operand_start) else {
        return false;
    };
    let branch_start = skip_ascii_whitespace(source, after_name);
    if source.as_bytes().get(branch_start) != Some(&b'{') {
        return false;
    }
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    match_body_has_only_returning_err_arms(source, branch_start + 1, branch_end)
}

fn match_body_has_err_return_arm(source: &str, body_start: usize, body_end: usize) -> bool {
    let mut cursor = body_start;
    while cursor < body_end {
        cursor = skip_match_arm_separator(source, cursor, body_end);
        if cursor >= body_end {
            return false;
        }
        let Some(arrow) = find_top_level_fat_arrow(source, cursor, body_end) else {
            return false;
        };
        let pattern = source[cursor..arrow].trim();
        let arm_body_start = skip_ascii_whitespace(source, arrow + 2);
        let arm_body_end = top_level_match_arm_end(source, arm_body_start, body_end);
        if match_pattern_is_plain_err(pattern) {
            return match_arm_body_returns(source, arm_body_start, arm_body_end);
        }
        cursor = arm_body_end.saturating_add(1);
    }
    false
}

fn match_body_has_only_returning_err_arms(
    source: &str,
    body_start: usize,
    body_end: usize,
) -> bool {
    let mut cursor = body_start;
    let mut saw_err = false;
    while cursor < body_end {
        cursor = skip_match_arm_separator(source, cursor, body_end);
        if cursor >= body_end {
            break;
        }
        let Some(arrow) = find_top_level_fat_arrow(source, cursor, body_end) else {
            return false;
        };
        let pattern = source[cursor..arrow].trim();
        let arm_body_start = skip_ascii_whitespace(source, arrow + 2);
        let arm_body_end = top_level_match_arm_end(source, arm_body_start, body_end);
        if !saw_err && match_pattern_may_catch_result_err_before_plain_err(pattern) {
            return false;
        }
        if match_pattern_is_plain_err(pattern) {
            if !match_arm_body_returns(source, arm_body_start, arm_body_end) {
                return false;
            }
            saw_err = true;
        }
        cursor = arm_body_end.saturating_add(1);
    }
    saw_err
}

fn match_body_has_only_submit_action_rejecting_err_arms(
    source: &str,
    raw_source: &str,
    body_start: usize,
    body_end: usize,
) -> bool {
    let mut cursor = body_start;
    let mut saw_err = false;
    while cursor < body_end {
        cursor = skip_match_arm_separator(source, cursor, body_end);
        if cursor >= body_end {
            break;
        }
        let Some(arrow) = find_top_level_fat_arrow(source, cursor, body_end) else {
            return false;
        };
        let pattern = source[cursor..arrow].trim();
        let arm_body_start = skip_ascii_whitespace(source, arrow + 2);
        let arm_body_end = top_level_match_arm_end(source, arm_body_start, body_end);
        if !saw_err && match_pattern_may_catch_result_err_before_plain_err(pattern) {
            return false;
        }
        if match_pattern_is_plain_err(pattern) {
            if saw_err
                || !match_arm_body_returns_submit_action_rejection(
                    source,
                    raw_source,
                    arm_body_start,
                    arm_body_end,
                )
            {
                return false;
            }
            saw_err = true;
        }
        cursor = arm_body_end.saturating_add(1);
    }
    saw_err
}

fn match_arm_body_returns_submit_action_rejection(
    source: &str,
    raw_source: &str,
    start: usize,
    end: usize,
) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if start >= end {
        return false;
    }
    if source.as_bytes().get(start) == Some(&b'{') {
        let Ok(block_end) = match_rust_brace(source, start) else {
            return false;
        };
        if block_end > end {
            return false;
        }
        return rust_block_has_top_level_terminal_submit_action_rejection_return(
            source,
            raw_source,
            start + 1,
            block_end,
        );
    }
    span_is_terminal_submit_action_rejection_return(source, raw_source, start, end)
}

fn match_body_has_only_continuing_err_arms(
    source: &str,
    body_start: usize,
    body_end: usize,
) -> bool {
    let mut cursor = body_start;
    let mut saw_err = false;
    while cursor < body_end {
        cursor = skip_match_arm_separator(source, cursor, body_end);
        if cursor >= body_end {
            break;
        }
        let Some(arrow) = find_top_level_fat_arrow(source, cursor, body_end) else {
            return false;
        };
        let pattern = source[cursor..arrow].trim();
        let arm_body_start = skip_ascii_whitespace(source, arrow + 2);
        let arm_body_end = top_level_match_arm_end(source, arm_body_start, body_end);
        if !saw_err && match_pattern_may_catch_result_err_before_plain_err(pattern) {
            return false;
        }
        if match_pattern_is_plain_err(pattern) {
            if !match_arm_body_continues(source, arm_body_start, arm_body_end) {
                return false;
            }
            saw_err = true;
        }
        cursor = arm_body_end.saturating_add(1);
    }
    saw_err
}

fn skip_match_arm_separator(source: &str, mut cursor: usize, end: usize) -> usize {
    while cursor < end {
        match source.as_bytes().get(cursor).copied() {
            Some(byte) if byte.is_ascii_whitespace() => cursor += 1,
            Some(b',') => cursor += 1,
            _ => break,
        }
    }
    cursor
}

fn find_top_level_fat_arrow(source: &str, from: usize, end: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = from;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index + 1 < end {
        match bytes[index] {
            b'=' if bytes.get(index + 1) == Some(&b'>')
                && paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0 =>
            {
                return Some(index);
            }
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    None
}

fn top_level_match_arm_end(source: &str, from: usize, end: usize) -> usize {
    let arm_start = skip_ascii_whitespace(source, from);
    if source.as_bytes().get(arm_start) == Some(&b'{') {
        if let Ok(block_end) = match_rust_brace(source, arm_start) {
            return block_end.min(end);
        }
    }
    let bytes = source.as_bytes();
    let mut index = from;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < end {
        match bytes[index] {
            b',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => return index,
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    end
}

fn match_pattern_is_plain_err(pattern: &str) -> bool {
    if pattern.contains(" if ") {
        return false;
    }
    let pattern = pattern.trim();
    if pattern.contains('|') {
        return false;
    }
    pattern == "Err" || pattern.starts_with("Err(") || pattern.starts_with("Err {")
}

fn match_pattern_is_plain_ok(pattern: &str) -> bool {
    if pattern.contains(" if ") {
        return false;
    }
    let pattern = pattern.trim();
    if pattern.contains('|') {
        return false;
    }
    pattern == "Ok" || pattern.starts_with("Ok(") || pattern.starts_with("Ok {")
}

fn match_pattern_may_catch_result_err_before_plain_err(pattern: &str) -> bool {
    !match_pattern_is_plain_err(pattern) && !match_pattern_is_plain_ok(pattern)
}

fn match_arm_body_returns(source: &str, start: usize, end: usize) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if start >= end {
        return false;
    }
    if source.as_bytes().get(start) == Some(&b'{') {
        let Ok(block_end) = match_rust_brace(source, start) else {
            return false;
        };
        if block_end > end {
            return false;
        }
        return rust_block_has_top_level_terminal_return(source, start + 1, block_end);
    }
    span_is_terminal_return_statement(source, start, end)
}

fn match_arm_body_continues(source: &str, start: usize, end: usize) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if start >= end {
        return false;
    }
    if source.as_bytes().get(start) == Some(&b'{') {
        let Ok(block_end) = match_rust_brace(source, start) else {
            return false;
        };
        if block_end > end {
            return false;
        }
        return rust_block_has_top_level_terminal_continue(source, start + 1, block_end);
    }
    span_is_terminal_continue_statement(source, start, end)
}

fn fail_closed_branch_after(source: &str, from: usize) -> bool {
    let Some(branch_start) = next_top_level_rust_brace_before_statement_end(source, from) else {
        return false;
    };
    let Ok(branch_end) = match_rust_brace(source, branch_start) else {
        return false;
    };
    rust_block_has_top_level_terminal_return(source, branch_start + 1, branch_end)
}

fn call_is_inside_loop(source: &str, target: usize) -> bool {
    let context = rust_statement_context(source, target);
    context
        .block_path
        .iter()
        .copied()
        .any(|block_start| rust_block_is_loop_body(source, block_start))
}

fn rust_block_is_loop_body(source: &str, block_start: usize) -> bool {
    let prefix_start = rust_control_prefix_start_before_block(source, block_start);
    let prefix = source[prefix_start..block_start].trim();
    prefix.starts_with("for ")
        || prefix.starts_with("while ")
        || prefix.starts_with("while let ")
        || prefix == "loop"
        || prefix.ends_with(" loop")
}

fn rust_control_prefix_start_before_block(source: &str, block_start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = block_start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    while cursor > 0 {
        cursor -= 1;
        match bytes[cursor] {
            b')' => paren_depth += 1,
            b'(' => paren_depth = paren_depth.saturating_sub(1),
            b']' => bracket_depth += 1,
            b'[' => bracket_depth = bracket_depth.saturating_sub(1),
            b';' | b'{' | b'}' if paren_depth == 0 && bracket_depth == 0 => return cursor + 1,
            _ => {}
        }
    }
    0
}

fn rust_block_has_top_level_terminal_continue(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < end {
        if paren_depth == 0
            && bracket_depth == 0
            && brace_depth == 0
            && rust_token_at(source, "continue", index).is_some()
        {
            let after_continue = index + "continue".len();
            let after_continue = skip_ascii_whitespace(source, after_continue);
            if bytes.get(after_continue) != Some(&b';') {
                return false;
            }
            return source[after_continue + 1..end].trim().is_empty();
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn span_is_terminal_continue_statement(source: &str, start: usize, end: usize) -> bool {
    let start = skip_ascii_whitespace(source, start);
    let end = skip_ascii_whitespace_back(source, end);
    let Some(after_continue) = rust_token_at(source, "continue", start) else {
        return false;
    };
    let after_continue = skip_ascii_whitespace(source, after_continue);
    source.as_bytes().get(after_continue) == Some(&b';')
        && source[after_continue + 1..end].trim().is_empty()
}

fn rust_block_has_top_level_terminal_return(source: &str, start: usize, end: usize) -> bool {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < end {
        if paren_depth == 0
            && bracket_depth == 0
            && brace_depth == 0
            && rust_token_at(source, "return", index).is_some()
        {
            let Some((statement_end, has_semicolon)) =
                top_level_statement_end_after(source, index + "return".len(), end)
            else {
                return false;
            };
            if !terminal_return_expression_is_fail_closed(
                source,
                index + "return".len(),
                statement_end,
            ) {
                return false;
            }
            let tail_start = if has_semicolon {
                statement_end + 1
            } else {
                statement_end
            };
            return source[tail_start..end].trim().is_empty();
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn span_is_terminal_return_statement(source: &str, start: usize, end: usize) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if rust_token_at(source, "return", start).is_none() {
        return false;
    }
    let Some((statement_end, has_semicolon)) =
        top_level_statement_end_after(source, start + "return".len(), end)
    else {
        return false;
    };
    if !terminal_return_expression_is_fail_closed(source, start + "return".len(), statement_end) {
        return false;
    }
    let tail_start = if has_semicolon {
        statement_end + 1
    } else {
        statement_end
    };
    source[tail_start..end].trim().is_empty()
}

fn terminal_return_expression_is_fail_closed(source: &str, start: usize, end: usize) -> bool {
    let expression = source[start..end].trim();
    if expression.is_empty()
        || matches!(expression, "None" | "false")
        || exact_rust_parenthesized_constructor(expression, "Err")
        || exact_rust_braced_constructor(expression, "Err")
        || exact_rust_parenthesized_constructor(expression, "ControlFlow::Break")
    {
        return true;
    }
    if let Some(ok_payload) = expression
        .strip_prefix("Ok(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return matches!(ok_payload.trim(), "None" | "false");
    }
    two_component_tuple_returns_err(expression)
}

fn two_component_tuple_returns_err(expression: &str) -> bool {
    if expression.as_bytes().first() != Some(&b'(') {
        return false;
    }
    let Ok(close) = match_rust_paren(expression, 0) else {
        return false;
    };
    if close + 1 != expression.len() {
        return false;
    }
    let Some(comma) = find_top_level_byte(expression, 1, close, b',') else {
        return false;
    };
    if find_top_level_byte(expression, comma + 1, close, b',').is_some() {
        return false;
    }
    let trace = expression[1..comma].trim();
    let bytes = trace.as_bytes();
    if bytes.is_empty()
        || !(bytes[0] == b'_' || bytes[0].is_ascii_alphabetic())
        || !bytes
            .iter()
            .copied()
            .all(is_rust_identifier_continuation_byte)
    {
        return false;
    }
    let result = expression[comma + 1..close].trim();
    exact_rust_parenthesized_constructor(result, "Err")
        || exact_rust_braced_constructor(result, "Err")
}

fn exact_rust_parenthesized_constructor(expression: &str, constructor: &str) -> bool {
    let Some(after_constructor) = expression.strip_prefix(constructor) else {
        return false;
    };
    if after_constructor
        .as_bytes()
        .first()
        .is_some_and(|byte| is_rust_identifier_continuation_byte(*byte))
    {
        return false;
    }
    let open = skip_ascii_whitespace(expression, constructor.len());
    if expression.as_bytes().get(open) != Some(&b'(') {
        return false;
    }
    match_rust_paren(expression, open)
        .is_ok_and(|close| skip_ascii_whitespace(expression, close + 1) == expression.len())
}

fn exact_rust_braced_constructor(expression: &str, constructor: &str) -> bool {
    let Some(after_constructor) = expression.strip_prefix(constructor) else {
        return false;
    };
    if after_constructor
        .as_bytes()
        .first()
        .is_some_and(|byte| is_rust_identifier_continuation_byte(*byte))
    {
        return false;
    }
    let open = skip_ascii_whitespace(expression, constructor.len());
    if expression.as_bytes().get(open) != Some(&b'{') {
        return false;
    }
    match_rust_brace(expression, open)
        .is_ok_and(|close| skip_ascii_whitespace(expression, close + 1) == expression.len())
}

fn rust_block_has_top_level_terminal_submit_action_rejection_return(
    source: &str,
    raw_source: &str,
    start: usize,
    end: usize,
) -> bool {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < end {
        if paren_depth == 0
            && bracket_depth == 0
            && brace_depth == 0
            && rust_token_at(source, "return", index).is_some()
        {
            let Some((statement_end, has_semicolon)) =
                top_level_statement_end_after(source, index + "return".len(), end)
            else {
                return false;
            };
            if !terminal_return_expression_is_submit_action_rejection(
                source,
                raw_source,
                index + "return".len(),
                statement_end,
            ) {
                return false;
            }
            let tail_start = if has_semicolon {
                statement_end + 1
            } else {
                statement_end
            };
            return source[tail_start..end].trim().is_empty();
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn span_is_terminal_submit_action_rejection_return(
    source: &str,
    raw_source: &str,
    start: usize,
    end: usize,
) -> bool {
    let start = skip_ascii_whitespace(source, start);
    if rust_token_at(source, "return", start).is_none() {
        return false;
    }
    let Some((statement_end, has_semicolon)) =
        top_level_statement_end_after(source, start + "return".len(), end)
    else {
        return false;
    };
    if !terminal_return_expression_is_submit_action_rejection(
        source,
        raw_source,
        start + "return".len(),
        statement_end,
    ) {
        return false;
    }
    let tail_start = if has_semicolon {
        statement_end + 1
    } else {
        statement_end
    };
    source[tail_start..end].trim().is_empty()
}

fn terminal_return_expression_is_submit_action_rejection(
    source: &str,
    raw_source: &str,
    start: usize,
    end: usize,
) -> bool {
    debug_assert_eq!(source.len(), raw_source.len());
    let expression_start = skip_ascii_whitespace(source, start);
    let expression_end = skip_ascii_whitespace_back(source, end);
    let Some(after_serde_json) = rust_token_at(source, "serde_json", expression_start) else {
        return false;
    };
    let first_colon = skip_ascii_whitespace(source, after_serde_json);
    if source.as_bytes().get(first_colon..first_colon + 2) != Some(b"::") {
        return false;
    }
    let json_start = skip_ascii_whitespace(source, first_colon + 2);
    let Some(after_json) = rust_token_at(source, "json", json_start) else {
        return false;
    };
    let bang = skip_ascii_whitespace(source, after_json);
    if source.as_bytes().get(bang) != Some(&b'!') {
        return false;
    }
    let outer_start = skip_ascii_whitespace(source, bang + 1);
    if source.as_bytes().get(outer_start) != Some(&b'(') {
        return false;
    }
    let Ok(outer_end) = match_rust_paren(source, outer_start) else {
        return false;
    };
    if skip_ascii_whitespace(source, outer_end + 1) != expression_end {
        return false;
    }
    let object_start = skip_ascii_whitespace(source, outer_start + 1);
    if source.as_bytes().get(object_start) != Some(&b'{') {
        return false;
    }
    let Ok(object_end) = match_rust_brace(source, object_start) else {
        return false;
    };
    if skip_ascii_whitespace(source, object_end + 1) != outer_end {
        return false;
    }
    submit_action_rejection_object_fields_are_exact(
        source,
        raw_source,
        object_start + 1,
        object_end,
    )
}

fn submit_action_rejection_object_fields_are_exact(
    source: &str,
    raw_source: &str,
    start: usize,
    end: usize,
) -> bool {
    let bytes = source.as_bytes();
    let mut cursor = start;
    let mut first = true;
    let mut saw_success = false;
    let mut saw_tx_hash = false;
    let mut saw_error = false;

    loop {
        cursor = skip_ascii_whitespace(raw_source, cursor);
        if cursor >= end {
            break;
        }
        if !first {
            if bytes.get(cursor) != Some(&b',') {
                return false;
            }
            cursor = skip_ascii_whitespace(raw_source, cursor + 1);
            if cursor >= end {
                break;
            }
        }

        let key_start = cursor;
        let mut colon = None;
        while cursor < end {
            match bytes[cursor] {
                b':' => {
                    colon = Some(cursor);
                    break;
                }
                b',' => return false,
                _ => cursor += 1,
            }
        }
        let Some(colon) = colon else {
            return false;
        };
        let key = raw_source[key_start..colon].trim();
        let value_start = skip_ascii_whitespace(source, colon + 1);
        let mut value_end = value_start;
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        let mut brace_depth = 0usize;
        while value_end < end {
            match bytes[value_end] {
                b',' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => break,
                b'(' => paren_depth += 1,
                b')' => paren_depth = paren_depth.saturating_sub(1),
                b'[' => bracket_depth += 1,
                b']' => bracket_depth = bracket_depth.saturating_sub(1),
                b'{' => brace_depth += 1,
                b'}' => brace_depth = brace_depth.saturating_sub(1),
                _ => {}
            }
            value_end += 1;
        }
        let value = source[value_start..value_end].trim();
        match key {
            "\"success\"" if !saw_success && value == "false" => saw_success = true,
            "\"tx_hash\"" if !saw_tx_hash && value == "null" => saw_tx_hash = true,
            "\"error\"" if !saw_error && value == "err.to_string()" => saw_error = true,
            _ => return false,
        }
        cursor = value_end;
        first = false;
    }

    saw_success && saw_tx_hash && saw_error
}

fn top_level_statement_end_after(source: &str, from: usize, end: usize) -> Option<(usize, bool)> {
    let bytes = source.as_bytes();
    let mut index = from;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while index < end {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            b';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                return Some((index, true));
            }
            _ => {}
        }
        index += 1;
    }
    Some((end, false))
}

fn next_top_level_rust_brace_before_statement_end(source: &str, from: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = from;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'{' if paren_depth == 0 && bracket_depth == 0 => return Some(index),
            b';' if paren_depth == 0 && bracket_depth == 0 => return None,
            b'}' if paren_depth == 0 && bracket_depth == 0 => return None,
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    None
}

fn rust_token_at(source: &str, token: &str, index: usize) -> Option<usize> {
    if !source[index..].starts_with(token) {
        return None;
    }
    let before = index
        .checked_sub(1)
        .and_then(|prev| source.as_bytes().get(prev).copied());
    let after = source.as_bytes().get(index + token.len()).copied();
    if before.is_some_and(is_rust_identifier_continuation_byte)
        || after.is_some_and(is_rust_identifier_continuation_byte)
    {
        return None;
    }
    Some(index + token.len())
}

fn rust_identifier_at(source: &str, ident: &str, index: usize) -> Option<usize> {
    rust_token_at(source, ident, index)
}

#[derive(Debug, Clone)]
struct RustStatementContext {
    block_path: Vec<usize>,
    statement_starts: Vec<usize>,
}

impl RustStatementContext {
    fn current_statement_start(&self) -> usize {
        self.statement_starts.last().copied().unwrap_or_default()
    }
}

fn rust_call_is_in_statically_dead_short_circuit_rhs(source: &str, call: &RustCallSite) -> bool {
    let bytes = source.as_bytes();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut index = 0usize;
    while index + 1 < call.start && index + 1 < bytes.len() {
        let operator = (bytes[index], bytes[index + 1]);
        if matches!(operator, (b'&', b'&') | (b'|', b'|'))
            && rust_short_circuit_rhs_reaches_call(
                source,
                index + 2,
                call.start,
                paren_depth,
                bracket_depth,
                brace_depth,
            )
        {
            let context = rust_statement_context(source, index);
            let lhs_prefix = &source[context.current_statement_start()..index];
            if (operator == (b'|', b'|') && rust_prefix_ends_with_token(lhs_prefix, "true"))
                || (operator == (b'&', b'&') && rust_prefix_ends_with_token(lhs_prefix, "false"))
            {
                return true;
            }
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn rust_call_is_in_short_circuit_rhs(source: &str, call: &RustCallSite) -> bool {
    let bytes = source.as_bytes();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut index = 0usize;
    while index + 1 < call.start && index + 1 < bytes.len() {
        if matches!(
            (bytes[index], bytes[index + 1]),
            (b'&', b'&') | (b'|', b'|')
        ) && rust_short_circuit_rhs_reaches_call(
            source,
            index + 2,
            call.start,
            paren_depth,
            bracket_depth,
            brace_depth,
        ) {
            return true;
        }
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth += 1,
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    false
}

fn rust_short_circuit_rhs_reaches_call(
    source: &str,
    from: usize,
    call_start: usize,
    base_paren_depth: usize,
    base_bracket_depth: usize,
    base_brace_depth: usize,
) -> bool {
    let bytes = source.as_bytes();
    let operator_start = from.saturating_sub(2);
    let operator_context = rust_statement_context(source, operator_start);
    let operator_prefix = &source[operator_context.current_statement_start()..operator_start];
    let operator_is_in_control_condition = find_rust_token(operator_prefix, "if", 0).is_some()
        || find_rust_token(operator_prefix, "while", 0).is_some();
    let mut paren_depth = base_paren_depth;
    let mut bracket_depth = base_bracket_depth;
    let mut brace_depth = base_brace_depth;
    let mut index = from;
    while index < call_start && index < bytes.len() {
        match bytes[index] {
            b',' | b';'
                if paren_depth == base_paren_depth
                    && bracket_depth == base_bracket_depth
                    && brace_depth == base_brace_depth =>
            {
                return false;
            }
            b'=' if bytes.get(index + 1) == Some(&b'>')
                && paren_depth == base_paren_depth
                && bracket_depth == base_bracket_depth
                && brace_depth == base_brace_depth =>
            {
                return false;
            }
            b'{' if operator_is_in_control_condition
                && paren_depth == base_paren_depth
                && bracket_depth == base_bracket_depth
                && brace_depth == base_brace_depth
                && !rust_rhs_prefix_expects_block_operand(&source[from..index]) =>
            {
                return false;
            }
            b')' if paren_depth <= base_paren_depth => return false,
            b']' if bracket_depth <= base_bracket_depth => return false,
            b'}' if brace_depth <= base_brace_depth => return false,
            b'(' => paren_depth += 1,
            b')' => paren_depth -= 1,
            b'[' => bracket_depth += 1,
            b']' => bracket_depth -= 1,
            b'{' => brace_depth += 1,
            b'}' => brace_depth -= 1,
            _ => {}
        }
        index += 1;
    }
    index == call_start
}

fn rust_rhs_prefix_expects_block_operand(prefix: &str) -> bool {
    let prefix = prefix.trim_end();
    prefix.is_empty()
        || [
            "&&", "||", "+", "-", "*", "/", "%", "^", "&", "|", "=", "==", "!=", "<", ">", "<=",
            ">=", "=>", "(", "[", ",", ":",
        ]
        .iter()
        .any(|operator| prefix.ends_with(operator))
}

fn rust_call_dominates_successor(
    source: &str,
    callee: &RustCallSite,
    successor: &RustCallSite,
    closure_bodies: &[RustClosureBody],
) -> bool {
    if callee.start >= successor.start
        || rust_call_is_inside_closure(callee, closure_bodies)
        || rust_call_is_in_short_circuit_rhs(source, callee)
    {
        return false;
    }
    let callee_context = rust_statement_context(source, callee.start);
    let successor_context = rust_statement_context(source, successor.start);
    if callee_context.block_path == successor_context.block_path {
        return callee_context.current_statement_start()
            < successor_context.current_statement_start();
    }
    if rust_block_path_is_prefix(&callee_context.block_path, &successor_context.block_path) {
        let depth = callee_context.block_path.len();
        let Some(successor_ancestor_statement) = depth
            .checked_sub(1)
            .and_then(|index| successor_context.statement_starts.get(index))
            .copied()
        else {
            return false;
        };
        return callee_context.current_statement_start() < successor_ancestor_statement;
    }
    false
}

fn rust_shared_sled_helper_dominates_successor(
    source: &str,
    helper: &RustCallSite,
    successor: &RustCallSite,
    closure_bodies: &[RustClosureBody],
) -> bool {
    let enclosing_helper_closures = closure_bodies
        .iter()
        .filter(|closure| closure.start <= helper.start && helper.start < closure.end)
        .collect::<Vec<_>>();
    enclosing_helper_closures.len() == 1
        && enclosing_helper_closures[0].start <= successor.start
        && successor.start < enclosing_helper_closures[0].end
        && helper.start < successor.start
        && !rust_call_is_in_short_circuit_rhs(source, helper)
}

fn rust_block_path_is_prefix(prefix: &[usize], path: &[usize]) -> bool {
    prefix.len() < path.len() && path.starts_with(prefix)
}

fn rust_statement_context(source: &str, target: usize) -> RustStatementContext {
    let bytes = source.as_bytes();
    let mut block_path = Vec::new();
    let mut statement_starts = Vec::new();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut index = 0usize;
    while index < target && index < bytes.len() {
        match bytes[index] {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' if paren_depth == 0 && bracket_depth == 0 => {
                block_path.push(index);
                statement_starts.push(index + 1);
            }
            b'}' if paren_depth == 0 && bracket_depth == 0 => {
                block_path.pop();
                statement_starts.pop();
                if let Some(statement_start) = statement_starts.last_mut() {
                    *statement_start = index + 1;
                }
            }
            b';' if paren_depth == 0 && bracket_depth == 0 => {
                if let Some(statement_start) = statement_starts.last_mut() {
                    *statement_start = index + 1;
                }
            }
            _ => {}
        }
        index += 1;
    }
    for statement_start in &mut statement_starts {
        *statement_start = skip_ascii_whitespace(source, *statement_start);
    }
    RustStatementContext {
        block_path,
        statement_starts,
    }
}

fn is_rust_identifier_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn is_rust_identifier_continuation_byte(byte: u8) -> bool {
    is_rust_identifier_byte(byte) || !byte.is_ascii()
}

fn reviewable_node_value_bytes(mut value: serde_json::Value) -> Result<Vec<u8>> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("blueprint review content must be a JSON object"))?;
    let review = object
        .get_mut("target_review")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| anyhow!("blueprint review content must include target_review"))?;
    review.remove("content_blake3");
    serde_json::to_vec(&value).context("serialize blueprint review content")
}

#[cfg(test)]
fn reviewable_node_value_blake3(value: serde_json::Value) -> Result<String> {
    Ok(blake3::hash(&reviewable_node_value_bytes(value)?)
        .to_hex()
        .to_string())
}

fn blueprint_node_content_blake3(root: &Path, node: &BlueprintNode) -> Result<String> {
    let canonical = reviewable_node_value_bytes(
        serde_json::to_value(node).context("serialize blueprint node for target review")?,
    )?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.formal-blueprint-source-bound-review.v2\0");
    hasher.update(&(canonical.len() as u64).to_le_bytes());
    hasher.update(&canonical);

    let source_paths = node
        .implementation_paths
        .iter()
        .chain(node.evidence_paths.iter())
        .filter(|path| !BLUEPRINT_REVIEW_SOURCE_BYTE_EXCLUSIONS.contains(&path.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let rust_binding_roots = node
        .implementation_bindings
        .iter()
        .map(|binding| binding.path.as_str())
        .collect::<BTreeSet<_>>();
    let mut review_sources = BTreeMap::<String, Vec<u8>>::new();
    for relative in source_paths {
        let source_path = Path::new(&relative);
        let file_name = source_path.file_name().and_then(|name| name.to_str());
        let is_rust_module_root = source_path.extension().and_then(|ext| ext.to_str())
            == Some("rs")
            && (matches!(file_name, Some("lib.rs" | "main.rs" | "mod.rs"))
                || rust_binding_roots.contains(relative.as_str()));
        if is_rust_module_root {
            for (module_relative, source) in rust_binding_module_sources(root, &relative)? {
                let bytes = source.into_bytes();
                if let Some(existing) = review_sources.get(&module_relative) {
                    ensure!(
                        existing == &bytes,
                        "{} review source changed while reading {}",
                        node.id,
                        module_relative
                    );
                } else {
                    review_sources.insert(module_relative, bytes);
                }
            }
        } else {
            let bytes = read_repo_relative_regular_file_bounded(
                root,
                &relative,
                &format!("{} review source", node.id),
                MAX_BLUEPRINT_REVIEW_SOURCE_BYTES,
            )?;
            if let Some(existing) = review_sources.get(&relative) {
                ensure!(
                    existing == &bytes,
                    "{} review source changed while reading {}",
                    node.id,
                    relative
                );
            } else {
                review_sources.insert(relative, bytes);
            }
        }
    }
    for (relative, bytes) in review_sources {
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_target_review(root: &Path, node: &BlueprintNode) -> Result<()> {
    let claim_id = &node.id;
    let review = &node.target_review;
    ensure!(
        TARGET_REVIEW_STATUSES.contains(&review.status.as_str()),
        "{} has unknown target_review status {}",
        claim_id,
        review.status
    );
    ensure!(
        !review.reviewer.trim().is_empty(),
        "{} target_review reviewer missing",
        claim_id
    );
    ensure!(
        !review.reviewed_at.trim().is_empty(),
        "{} target_review reviewed_at missing",
        claim_id
    );
    ensure!(
        !review.notes.trim().is_empty(),
        "{} target_review notes missing",
        claim_id
    );
    ensure!(
        review.content_blake3.len() == 64
            && review
                .content_blake3
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "{} target_review content_blake3 must be a lowercase 64-character BLAKE3 digest",
        claim_id
    );
    let expected = blueprint_node_content_blake3(root, node)?;
    ensure!(
        review.content_blake3 == expected,
        "{} target_review content_blake3 mismatch: reviewed {}, current {}",
        claim_id,
        review.content_blake3,
        expected
    );
    Ok(())
}

fn validate_falsification_cases(node: &BlueprintNode) -> Result<()> {
    let mut ids = BTreeSet::new();
    for case in &node.falsification_cases {
        validate_id(&format!("{} falsification case id", node.id), &case.id)?;
        ensure!(
            ids.insert(&case.id),
            "{} lists duplicate falsification case {}",
            node.id,
            case.id
        );
        ensure!(
            !case.description.trim().is_empty(),
            "{} falsification case {} description missing",
            node.id,
            case.id
        );
        ensure!(
            !case.gate.trim().is_empty(),
            "{} falsification case {} gate missing",
            node.id,
            case.id
        );
    }
    Ok(())
}

fn detect_blueprint_cycles(nodes: &[BlueprintNode]) -> Result<()> {
    let deps: BTreeMap<&str, Vec<&str>> = nodes
        .iter()
        .map(|node| {
            (
                node.id.as_str(),
                node.depends_on.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in deps.keys() {
        visit_blueprint_node(node, &deps, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_blueprint_node<'a>(
    node: &'a str,
    deps: &BTreeMap<&'a str, Vec<&'a str>>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<()> {
    if visited.contains(node) {
        return Ok(());
    }
    ensure!(
        visiting.insert(node),
        "blueprint dependency cycle includes {}",
        node
    );
    for dep in deps.get(node).into_iter().flatten() {
        visit_blueprint_node(dep, deps, visiting, visited)?;
    }
    visiting.remove(node);
    visited.insert(node);
    Ok(())
}

fn validate_id(label: &str, id: &str) -> Result<()> {
    ensure!(!id.trim().is_empty(), "{} must be set", label);
    ensure!(
        id.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'),
        "{} {} must use lowercase ascii, digits, '-' or '.'",
        label,
        id
    );
    Ok(())
}

fn ensure_repo_relative_existing(root: &Path, raw: &str, context: &str) -> Result<()> {
    ensure!(!raw.trim().is_empty(), "{} is empty", context);
    let path = Path::new(raw);
    ensure!(
        !path.is_absolute(),
        "{} must be repository-relative: {}",
        context,
        raw
    );
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => {
                return Err(anyhow!(
                    "{} must not contain path traversal or root components: {}",
                    context,
                    raw
                ));
            }
        }
    }
    ensure!(
        root.join(path).exists(),
        "{} does not exist: {}",
        context,
        raw
    );
    Ok(())
}

fn ensure_repo_relative_existing_file(root: &Path, raw: &str, context: &str) -> Result<()> {
    ensure_repo_relative_existing(root, raw, context)?;
    let root_path = if root.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root
    };
    let root = root_path
        .canonicalize()
        .with_context(|| format!("canonicalize repository root for {context}"))?;
    let path = root.join(raw);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect {context} metadata: {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "{} must be a non-symlink regular file: {}",
        context,
        raw
    );
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize {context}: {}", path.display()))?;
    ensure!(
        canonical.starts_with(&root),
        "{} resolves outside the repository: {}",
        context,
        raw
    );
    Ok(())
}

fn read_repo_relative_regular_file_bounded(
    root: &Path,
    raw: &str,
    context: &str,
    maximum: u64,
) -> Result<Vec<u8>> {
    ensure_repo_relative_existing_file(root, raw, context)?;
    let root_path = if root.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root
    };
    let path = root_path.join(raw);
    let mut file = fs::File::open(&path)
        .with_context(|| format!("open bounded {context}: {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened {context}: {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "{} must remain a regular file after open: {}",
        context,
        raw
    );
    ensure!(
        metadata.len() <= maximum,
        "{} exceeds byte bound {}: {} has {} bytes",
        context,
        maximum,
        raw,
        metadata.len()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read bounded {context}: {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "{} exceeds byte bound {} while reading: {}",
        context,
        maximum,
        raw
    );
    Ok(bytes)
}

fn production_claim_checks(claim: &SecurityClaim) -> Result<()> {
    ensure!(
        claim.status == "enforced" || claim.status == "model_checked",
        "{} production claim must be enforced or model_checked, got {}",
        claim.id,
        claim.status
    );
    ensure!(
        !claim.gates.is_empty(),
        "{} production claim must name at least one gate",
        claim.id
    );
    ensure!(
        !CONJECTURAL_MODELS.contains(&claim.proof_model.as_str()),
        "{} cannot be production eligible under {}",
        claim.id,
        claim.proof_model
    );
    Ok(())
}

fn validate_residual_risk(claim_id: &str, risk: &ResidualRisk) -> Result<()> {
    ensure!(
        !risk.id.trim().is_empty(),
        "{} residual risk id missing",
        claim_id
    );
    ensure!(
        !risk.description.trim().is_empty(),
        "{} residual risk {} description missing",
        claim_id,
        risk.id
    );
    ensure!(
        !risk.status.trim().is_empty(),
        "{} residual risk {} status missing",
        claim_id,
        risk.id
    );
    ensure!(
        !risk.tracking.trim().is_empty(),
        "{} residual risk {} tracking missing",
        claim_id,
        risk.id
    );
    Ok(())
}

fn verify_bridge_case(case: &BridgeVectorCase) -> Result<()> {
    let source_chain_id = parse_hash32(&case.source_chain_id)?;
    let destination_chain_id = parse_hash32(&case.destination_chain_id)?;
    let payload = parse_hex_vec(&case.payload_hex)?;
    let expected_payload_hash = parse_hash48(&case.expected_payload_hash)?;
    let expected_message_hash = parse_hash48(&case.expected_message_hash)?;
    let expected_message_root = parse_hash48(&case.expected_message_root)?;
    let expected_replay_key = parse_hash48(&case.expected_replay_key)?;
    let message_nonce = case
        .message_nonce
        .parse::<u128>()
        .with_context(|| format!("parse {} message_nonce", case.name))?;

    let payload_hash = hash48_with_domain(b"hegemon.bridge.payload-v1", &[&payload]);
    ensure!(
        payload_hash == expected_payload_hash,
        "{} payload hash mismatch: expected {}, computed {}",
        case.name,
        hex48(&expected_payload_hash),
        hex48(&payload_hash)
    );

    let message = ReferenceBridgeMessage {
        source_chain_id,
        destination_chain_id,
        app_family_id: case.app_family_id,
        message_nonce,
        source_height: case.source_height,
        payload_hash,
        payload,
    };
    let message_hash = message_hash(&message);
    ensure!(
        message_hash == expected_message_hash,
        "{} message hash mismatch: expected {}, computed {}",
        case.name,
        hex48(&expected_message_hash),
        hex48(&message_hash)
    );
    let root = bridge_message_root(&[message_hash]);
    ensure!(
        root == expected_message_root,
        "{} message root mismatch: expected {}, computed {}",
        case.name,
        hex48(&expected_message_root),
        hex48(&root)
    );
    let replay_key = hash48_with_domain(
        b"hegemon.bridge.inbound-replay-v1",
        &[&source_chain_id, &message_nonce.to_le_bytes()],
    );
    ensure!(
        replay_key == expected_replay_key,
        "{} replay key mismatch: expected {}, computed {}",
        case.name,
        hex48(&expected_replay_key),
        hex48(&replay_key)
    );
    Ok(())
}

struct ReferenceBridgeMessage {
    source_chain_id: [u8; 32],
    destination_chain_id: [u8; 32],
    app_family_id: u16,
    message_nonce: u128,
    source_height: u64,
    payload_hash: [u8; 48],
    payload: Vec<u8>,
}

fn message_hash(message: &ReferenceBridgeMessage) -> [u8; 48] {
    let encoded = bridge_message_encoded_v1(message);
    hash48_with_domain(b"hegemon.bridge.message-v1", &[&encoded])
}

fn bridge_message_encoded_v1(message: &ReferenceBridgeMessage) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(170 + message.payload.len());
    encoded.extend_from_slice(&message.source_chain_id);
    encoded.extend_from_slice(&message.destination_chain_id);
    encoded.extend_from_slice(&message.app_family_id.to_le_bytes());
    encoded.extend_from_slice(&message.message_nonce.to_le_bytes());
    encoded.extend_from_slice(&message.source_height.to_le_bytes());
    encoded.extend_from_slice(&message.payload_hash);
    push_scale_compact_len(&mut encoded, message.payload.len() as u64);
    encoded.extend_from_slice(&message.payload);
    encoded
}

fn bridge_message_root(message_hashes: &[[u8; 48]]) -> [u8; 48] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.bridge.message-root-v1");
    let count = (message_hashes.len() as u32).to_le_bytes();
    hasher.update(&(count.len() as u32).to_le_bytes());
    hasher.update(&count);
    for hash in message_hashes {
        hasher.update(&(hash.len() as u32).to_le_bytes());
        hasher.update(hash);
    }
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hash48_with_domain(domain: &[u8], chunks: &[&[u8]]) -> [u8; 48] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for chunk in chunks {
        hasher.update(&(chunk.len() as u32).to_le_bytes());
        hasher.update(chunk);
    }
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn push_scale_compact_len(out: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        out.push((value as u8) << 2);
    } else if value < 1 << 14 {
        let encoded = ((value as u16) << 2) | 0b01;
        out.extend_from_slice(&encoded.to_le_bytes());
    } else if value < 1 << 30 {
        let encoded = ((value as u32) << 2) | 0b10;
        out.extend_from_slice(&encoded.to_le_bytes());
    } else {
        let value_bytes = value.to_le_bytes();
        let mut used = value_bytes.len();
        while used > 4 && value_bytes[used - 1] == 0 {
            used -= 1;
        }
        out.push((((used - 4) as u8) << 2) | 0b11);
        out.extend_from_slice(&value_bytes[..used]);
    }
}

fn parse_hash32(raw: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_vec(raw)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("expected 32 bytes, got {}", bytes.len()))
}

fn parse_hash48(raw: &str) -> Result<[u8; 48]> {
    let bytes = parse_hex_vec(raw)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("expected 48 bytes, got {}", bytes.len()))
}

fn parse_hex_vec(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    ensure!(trimmed.len().is_multiple_of(2), "hex string has odd length");
    hex::decode(trimmed).context("decode hex")
}

fn hex48(bytes: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn repository_root_from(path: &Path) -> PathBuf {
    let mut current = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };
    loop {
        if current.join("Cargo.toml").is_file() && current.join(".git").exists() {
            return if current.as_os_str().is_empty() {
                PathBuf::from(".")
            } else {
                current
            };
        }
        if !current.pop() {
            return PathBuf::from(".");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TARGET_ORDER_THEOREM: &str = "Hegemon.Native.ActionOrder.order_gate_precedes_mutation";
    const TARGET_ORDER_THEOREM_TWO: &str =
        "Hegemon.Native.ActionOrder.order_gate_precedes_publication";
    const TARGET_ORDER_THEOREM_PATH: &str = "formal/lean/Hegemon/Native/ActionOrder.lean";
    const TEST_MECHANIZED_ASSUMPTION_TRACKS: &[(&str, &[&str])] = &[
        (
            "test.closed-track",
            &["Hegemon.TestEvidence.test_closed_track"],
        ),
        ("test.open-track", &[]),
    ];

    #[test]
    fn compact_lengths_match_scale_shape() {
        let mut out = Vec::new();
        push_scale_compact_len(&mut out, 0);
        assert_eq!(out, vec![0]);
        out.clear();
        push_scale_compact_len(&mut out, 63);
        assert_eq!(out, vec![252]);
        out.clear();
        push_scale_compact_len(&mut out, 64);
        assert_eq!(out, vec![1, 1]);
    }

    #[test]
    fn replay_key_binds_nonce_and_chain() {
        let chain_a = [1u8; 32];
        let chain_b = [2u8; 32];
        let a7 = hash48_with_domain(
            b"hegemon.bridge.inbound-replay-v1",
            &[&chain_a, &7u128.to_le_bytes()],
        );
        let b7 = hash48_with_domain(
            b"hegemon.bridge.inbound-replay-v1",
            &[&chain_b, &7u128.to_le_bytes()],
        );
        let a8 = hash48_with_domain(
            b"hegemon.bridge.inbound-replay-v1",
            &[&chain_a, &8u128.to_le_bytes()],
        );
        assert_ne!(a7, b7);
        assert_ne!(a7, a8);
    }

    #[test]
    fn system_model_gates_accept_required_fail_closed_evidence() {
        let root = test_root("system-model-gates-valid");
        write_system_model_gate_evidence(&root);
        let gates_path = root.join("system-model-gates.json");
        write_json(&gates_path, system_model_gate_fixture());

        let report = check_system_model_gates_file(&gates_path).expect("valid system-model gates");
        assert_eq!(report.gates, REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES.len());
        assert_eq!(
            report.required_categories.len(),
            REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES.len()
        );
        assert_eq!(
            report.evidence_paths,
            REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES.len()
        );
        assert!(report.passed);
    }

    #[test]
    fn system_model_gates_reject_missing_required_category() {
        let root = test_root("system-model-gates-missing-category");
        write_system_model_gate_evidence(&root);
        let mut fixture = system_model_gate_fixture();
        fixture["gates"].as_array_mut().expect("gates array").pop();
        let gates_path = root.join("system-model-gates.json");
        write_json(&gates_path, fixture);

        let err = check_system_model_gates_file(&gates_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("missing required system-model categories"));
    }

    #[test]
    fn system_model_gates_reject_non_fail_closed_gate() {
        let root = test_root("system-model-gates-non-fail-closed");
        write_system_model_gate_evidence(&root);
        let mut fixture = system_model_gate_fixture();
        fixture["gates"][0]["fail_closed"] = json!(false);
        let gates_path = root.join("system-model-gates.json");
        write_json(&gates_path, fixture);

        let err = check_system_model_gates_file(&gates_path).unwrap_err();
        assert!(err.to_string().contains("must fail closed"));
    }

    #[test]
    fn active_goal_progress_accepts_matrix_measurement() {
        let root = test_root("active-goal-progress-valid");
        write_active_goal_progress_evidence(&root);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, highest_standard_matrix_fixture());
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let report = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .expect("valid active-goal progress");
        assert_eq!(report.goal_status_when_measured, "paused");
        assert_eq!(
            report.matrix_properties,
            REQUIRED_HIGHEST_STANDARD_PROPERTIES.len()
        );
        assert_eq!(
            report.completed_properties,
            REQUIRED_HIGHEST_STANDARD_PROPERTIES.len()
        );
        assert_eq!(report.total_weight, 100);
        assert_eq!(report.weighted_completion_percent, 100.0);
        assert_eq!(report.overall_completion_percent, 50.0);
        assert_eq!(report.formal_surface_coverage_percent, 100.0);
        assert_eq!(report.mechanized_assumption_tracks, 2);
        assert_eq!(report.closed_mechanized_assumption_tracks, 1);
        assert_eq!(report.mechanized_assumption_closure_percent, 50.0);
        assert!(report.passed);
    }

    #[test]
    fn required_native_compound_tracks_pin_every_component_theorem() {
        let policy: BTreeMap<&str, &[&str]> = REQUIRED_MECHANIZED_ASSUMPTION_TRACKS
            .iter()
            .copied()
            .collect();
        let challenge_actual: BTreeSet<&str> = policy
            ["native.challenge-reduction-entropy-arithmetic"]
            .iter()
            .copied()
            .collect();
        let challenge_expected: BTreeSet<&str> = [
            "Hegemon.Native.NativeBackendAlgebra.active_tuple_preimage_bound_is_243",
            "Hegemon.Native.NativeBackendAlgebra.active_tuple_probability_bound_supports_312_bits",
            "Hegemon.Native.NativeBackendAlgebra.active_tuple_probability_bound_does_not_support_313_bits",
            "Hegemon.Native.NativeBackendAlgebra.active_receipt_root_composition_loss_is_exact",
            "Hegemon.Native.NativeBackendAlgebra.active_composed_probability_bound_supports_305_bits",
            "Hegemon.Native.NativeBackendAlgebra.active_composed_probability_bound_does_not_support_306_bits",
            "Hegemon.Native.NativeBackendAlgebra.reduced_active_fold_challenge_positive",
            "Hegemon.Native.NativeBackendAlgebra.reduced_active_fold_challenge_at_most_value_count",
            "Hegemon.Native.NativeBackendAlgebra.active_reducer_preimage_quotient_at_most_two",
            "Hegemon.Native.NativeBackendAlgebra.active_reducer_preimage_has_one_of_three_representatives",
            "Hegemon.Native.NativeBackendAlgebra.active_challenge_polynomial_is_nonzero",
        ]
        .into_iter()
        .collect();
        assert_eq!(challenge_actual, challenge_expected);

        let digit_actual: BTreeSet<&str> = policy["native.digit-bound-euclidean-arithmetic"]
            .iter()
            .copied()
            .collect();
        let digit_expected: BTreeSet<&str> = [
            "Hegemon.Native.NativeBackendAlgebra.active_ambient_coefficient_dimension_is_4104",
            "Hegemon.Native.NativeBackendAlgebra.active_conservative_euclidean_bound_is_sound",
            "Hegemon.Native.NativeBackendAlgebra.active_live_coefficient_dimension_is_648",
            "Hegemon.Native.NativeBackendAlgebra.active_live_euclidean_bound_is_sound",
            "Hegemon.Native.NativeBackendAlgebra.bounded_digits_have_bounded_centered_difference",
        ]
        .into_iter()
        .collect();
        assert_eq!(digit_actual, digit_expected);
    }

    #[test]
    fn closed_track_propositions_match_independent_rust_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let actual = mechanized_assumption_proposition_blake3(&root)
            .expect("elaborated closed-track proposition digest");
        assert_eq!(
            actual, EXPECTED_MECHANIZED_ASSUMPTION_PROPOSITION_BLAKE3,
            "closed-track theorem types changed without an explicit Rust policy update"
        );
    }

    #[test]
    fn formal_source_tree_matches_independent_rust_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let actual = formal_source_tree_blake3(&root).expect("complete formal source tree digest");
        assert_eq!(
            actual, EXPECTED_FORMAL_SOURCE_TREE_BLAKE3,
            "formal model or theorem bodies changed without an explicit Rust policy update"
        );
    }

    #[cfg(unix)]
    #[test]
    fn formal_source_tree_rejects_symlinked_source() {
        use std::os::unix::fs::symlink;

        let root = test_root("formal-source-tree-symlink");
        write_repo_file(&root, "formal/lean/Real.lean", "def real := true\n");
        symlink("Real.lean", root.join("formal/lean/Alias.lean")).unwrap();

        let err = formal_source_tree_blake3(&root).unwrap_err();
        assert!(err.to_string().contains("contains symlink"));
    }

    #[test]
    fn active_goal_progress_rejects_stale_weighted_percent() {
        let root = test_root("active-goal-progress-stale-percent");
        write_active_goal_progress_evidence(&root);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, highest_standard_matrix_fixture());
        let mut fixture = active_goal_progress_fixture();
        fixture["weighted_completion_percent"] = json!(99.0);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, fixture);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("weighted percent"));
    }

    #[test]
    fn active_goal_progress_rejects_unpaused_measurement() {
        let root = test_root("active-goal-progress-unpaused");
        write_active_goal_progress_evidence(&root);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, highest_standard_matrix_fixture());
        let mut fixture = active_goal_progress_fixture();
        fixture["goal_status_when_measured"] = json!("in_progress");
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, fixture);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("while the goal is paused, blocked, or complete"));
    }

    #[test]
    fn active_goal_progress_rejects_alternate_matrix_path() {
        let root = test_root("active-goal-progress-alternate-matrix");
        write_active_goal_progress_evidence(&root);
        write_json(
            &root.join("config/highest-standard-formal-verification-matrix.json"),
            highest_standard_matrix_fixture(),
        );
        let matrix_path = root.join("config/alternate-matrix.json");
        write_json(&matrix_path, highest_standard_matrix_fixture());
        let mut fixture = active_goal_progress_fixture();
        fixture["source_matrix_path"] = json!("config/alternate-matrix.json");
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, fixture);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("source_matrix_path must be"));
    }

    #[test]
    fn active_goal_progress_rejects_missing_mechanized_track_evidence() {
        let root = test_root("active-goal-progress-missing-track-evidence");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"][0]["evidence_paths"] =
            json!(["formal/lean/DoesNotExist.lean"]);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("DoesNotExist.lean"));
    }

    #[test]
    fn active_goal_progress_rejects_commented_closed_track_theorem() {
        const POLICY: &[(&str, &[&str])] = &[
            ("test.closed-track", &["Hegemon.TestEvidence.comment_spoof"]),
            ("test.open-track", &[]),
        ];
        let root = test_root("active-goal-progress-commented-track-theorem");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"][0]["lean_theorems"] =
            json!(["Hegemon.TestEvidence.comment_spoof"]);
        let mut claims = active_goal_claims_fixture();
        claims["claims"][0]["lean_theorems"] = json!(["Hegemon.TestEvidence.comment_spoof"]);
        write_json(&root.join("config/formal-security-claims.json"), claims);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(&progress_path, POLICY).unwrap_err();
        assert!(format!("{err:#}").contains("not declared"));
    }

    #[test]
    fn active_goal_progress_rejects_string_literal_closed_track_theorem() {
        const POLICY: &[(&str, &[&str])] = &[
            ("test.closed-track", &["Hegemon.TestEvidence.string_spoof"]),
            ("test.open-track", &[]),
        ];
        let root = test_root("active-goal-progress-string-track-theorem");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"][0]["lean_theorems"] =
            json!(["Hegemon.TestEvidence.string_spoof"]);
        let mut claims = active_goal_claims_fixture();
        claims["claims"][0]["lean_theorems"] = json!(["Hegemon.TestEvidence.string_spoof"]);
        write_json(&root.join("config/formal-security-claims.json"), claims);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(&progress_path, POLICY).unwrap_err();
        assert!(format!("{err:#}").contains("not declared"));
    }

    #[test]
    fn active_goal_progress_rejects_private_closed_track_theorem() {
        const POLICY: &[(&str, &[&str])] = &[
            ("test.closed-track", &["Hegemon.TestEvidence.private_spoof"]),
            ("test.open-track", &[]),
        ];
        let root = test_root("active-goal-progress-private-track-theorem");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"][0]["lean_theorems"] =
            json!(["Hegemon.TestEvidence.private_spoof"]);
        let mut claims = active_goal_claims_fixture();
        claims["claims"][0]["lean_theorems"] = json!(["Hegemon.TestEvidence.private_spoof"]);
        write_json(&root.join("config/formal-security-claims.json"), claims);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(&progress_path, POLICY).unwrap_err();
        assert!(format!("{err:#}").contains("not declared"));
    }

    #[cfg(unix)]
    #[test]
    fn active_goal_progress_rejects_symlinked_track_evidence() {
        use std::os::unix::fs::symlink;

        let root = test_root("active-goal-progress-symlink-track-evidence");
        write_active_goal_progress_evidence(&root);
        let evidence = root.join("formal/lean/TestEvidence.lean");
        let target = root.join("formal/lean/RealEvidence.lean");
        fs::rename(&evidence, &target).unwrap();
        symlink("RealEvidence.lean", &evidence).unwrap();
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, highest_standard_matrix_fixture());
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("non-symlink regular file"));
    }

    #[test]
    fn active_goal_progress_rejects_deleted_required_track_with_recomputed_total() {
        let root = test_root("active-goal-progress-deleted-required-track");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"]
            .as_array_mut()
            .expect("tracks array")
            .pop();
        matrix["mechanized_assumption_closure"]["total_tracks"] = json!(1);
        matrix["mechanized_assumption_closure"]["closed_tracks"] = json!(1);
        matrix["mechanized_assumption_closure"]["closure_percent"] = json!(100.0);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("required track count 2"));
    }

    #[test]
    fn active_goal_progress_rejects_unknown_replacement_track() {
        let root = test_root("active-goal-progress-unknown-track");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"][1]["id"] = json!("test.unknown-track");
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("unknown mechanized assumption track"));
    }

    #[test]
    fn active_goal_progress_rejects_unrelated_declared_theorem_substitution() {
        let root = test_root("active-goal-progress-theorem-substitution");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"][0]["lean_theorems"] =
            json!(["Hegemon.TestEvidence.unrelated_closed_track"]);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("independent closure policy"));
    }

    #[test]
    fn active_goal_progress_rejects_closed_theorem_missing_from_claims() {
        let root = test_root("active-goal-progress-theorem-missing-claims");
        write_active_goal_progress_evidence(&root);
        let claims_path = root.join("config/formal-security-claims.json");
        let mut claims = active_goal_claims_fixture();
        claims["claims"][0]["lean_theorems"] =
            json!(["Hegemon.TestEvidence.unrelated_closed_track"]);
        write_json(&claims_path, claims);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, highest_standard_matrix_fixture());
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not covered by the formal security claims"));
    }

    #[test]
    fn governance_claims_reject_coordinated_deletion_without_tombstone() {
        let root = test_root("governance-claim-deletion");
        write_repo_file(&root, "evidence/support.txt", "support");
        let mut claims = claims_fixture();
        claims["claims"].as_array_mut().expect("claims array").pop();
        let claims_path = root.join("claims.json");
        write_json(&claims_path, claims);

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(format!("{err:#}").contains("deleted claims require explicit tombstones"));
    }

    #[test]
    fn governance_claims_reject_tombstoned_required_conditional_target() {
        let active_ids = BTreeSet::from(["some.other-claim".to_owned()]);
        let err =
            validate_pinned_conditional_claim_presence(CLAIM_BASELINE_ID, &active_ids).unwrap_err();
        assert!(format!("{err:#}").contains("must remain active and cannot be tombstoned"));
    }

    #[test]
    fn governance_claims_accept_explicit_tombstone_against_pinned_baseline() {
        let root = test_root("governance-claim-tombstone");
        write_repo_file(&root, "evidence/support.txt", "support");
        let mut claims = claims_fixture();
        claims["claims"].as_array_mut().expect("claims array").pop();
        claims["claim_baseline"]["tombstones"] = json!([{
            "claim_id": "target.prod",
            "retired_at": "2026-08-17",
            "reason": "superseded in test",
            "approved_by": "test-reviewer",
            "approval_reference": "TEST-1",
            "replacement_claim_id": "support.dep"
        }]);
        let claims_path = root.join("claims.json");
        write_json(&claims_path, claims);

        let report = check_claims_file(&claims_path).expect("explicit tombstone accepted");
        assert_eq!(report.claims, 1);
        assert_eq!(report.tombstones, 1);
    }

    #[test]
    fn governance_claims_reject_unexecuted_gate_record() {
        let root = test_root("governance-unexecuted-gate");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let mut claims = claims_fixture();
        claims["governance_gate_evidence"][0]["status"] = json!("not_run");
        let claims_path = root.join("claims.json");
        write_json(&claims_path, claims);

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(format!("{err:#}").contains("must record passed status and exit_code 0"));
    }

    #[test]
    fn governance_gate_evidence_rejects_incomplete_test_report() {
        let root = test_root("governance-incomplete-test-report");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let mut claims = claims_fixture();
        claims["governance_gate_evidence"][0]["report"]["tests_passed"] =
            json!(REQUIRED_GOVERNANCE_TEST_COUNT - 1);
        let report = claims["governance_gate_evidence"][0]["report"].clone();
        claims["governance_gate_evidence"][0]["report_blake3"] =
            json!(executed_gate_report_blake3(&report).expect("hash mutated test report"));
        let claims_path = root.join("claims.json");
        write_json(&claims_path, claims);

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("tests_passed={REQUIRED_GOVERNANCE_TEST_COUNT}"))
        );
    }

    #[test]
    fn governance_gate_evidence_rejects_policy_source_mutations() {
        for (case, path) in [
            ("checker", "scripts/hegemon_formal_core/src/lib.rs"),
            ("formal-core-runner", "scripts/check_formal_core.sh"),
            (
                "formal-gate-cli-args",
                "scripts/test_formal_gate_cli_args.sh",
            ),
            ("kernel-manifest", "protocol/kernel/src/manifest.rs"),
            ("protocol-versioning", "protocol/versioning/src/lib.rs"),
            (
                "atomic-manifest-lean",
                "formal/lean/Hegemon/Native/AtomicCommitManifestAdmission.lean",
            ),
            (
                "atomic-manifest-vectors",
                "formal/lean/Hegemon/Native/GenerateAtomicCommitManifestAdmissionVectors.lean",
            ),
            ("native-module", "node/src/native/mod.rs"),
            ("native-block-policy", "node/src/native/block_flow.rs"),
            ("native-atomic-commit", "node/src/native/node_impl.rs"),
            ("native-v8-state", "node/src/native/poseidon2_v8_state.rs"),
        ] {
            let root = test_root(&format!("governance-policy-source-mutation-{case}"));
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            let claims_path = root.join("claims.json");
            write_json(&claims_path, claims_fixture());

            check_claims_file(&claims_path).expect("fresh gate evidence must be accepted");
            write_repo_file(&root, path, "// mutated governance policy source\n");

            let err = check_claims_file(&claims_path).unwrap_err();
            assert!(
                format!("{err:#}").contains("policy_inputs_blake3 mismatch"),
                "{path} mutation must invalidate executed governance evidence"
            );
        }
    }

    #[test]
    fn governance_active_gate_evidence_rejects_matrix_mutation() {
        let root = test_root("governance-active-matrix-mutation");
        write_active_goal_progress_evidence(&root);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, highest_standard_matrix_fixture());
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, active_goal_progress_fixture());

        check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .expect("fresh active-goal gate evidence must be accepted");
        let mut matrix = highest_standard_matrix_fixture();
        matrix["goal"] = json!("mutated governance matrix");
        write_json(&matrix_path, matrix);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("policy_inputs_blake3 mismatch"));
    }

    #[test]
    fn governance_smallwood_conditional_tracks_remain_open_in_policy() {
        let policy: BTreeMap<&str, &[&str]> = REQUIRED_MECHANIZED_ASSUMPTION_TRACKS
            .iter()
            .copied()
            .collect();
        for id in [
            "consensus.accepted-chain-supply-composition",
            "transaction.accepted-proof-exact-constraint-extraction",
            "transaction.smallwood-air-row-implementation-equivalence",
        ] {
            assert!(
                policy[id].is_empty(),
                "{id} must remain open while its deployed evidence is assumption-bound"
            );
        }
    }

    #[test]
    fn governance_conditional_matrix_track_rejects_closed_relabeling() {
        let root = test_root("governance-conditional-track-relabeling");
        write_active_goal_progress_evidence(&root);
        let mut matrix = highest_standard_matrix_fixture();
        matrix["mechanized_assumption_closure"]["tracks"][1]["status"] = json!("closed");
        matrix["mechanized_assumption_closure"]["tracks"][1]["lean_theorems"] =
            json!(["Hegemon.TestEvidence.unrelated_closed_track"]);
        matrix["mechanized_assumption_closure"]["tracks"][1]["remaining_work"] = json!([]);
        matrix["mechanized_assumption_closure"]["closed_tracks"] = json!(2);
        matrix["mechanized_assumption_closure"]["closure_percent"] = json!(100.0);
        matrix["overall_completion_percent"] = json!(100.0);
        let matrix_path = root.join("config/highest-standard-formal-verification-matrix.json");
        write_json(&matrix_path, matrix);
        let mut progress = active_goal_progress_fixture();
        progress["overall_completion_percent"] = json!(100.0);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, progress);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("expected open from the independent closure policy"));
    }

    #[test]
    fn governance_active_goal_rejects_string_only_gate_recipe() {
        let root = test_root("governance-string-gate");
        write_active_goal_progress_evidence(&root);
        write_json(
            &root.join("config/highest-standard-formal-verification-matrix.json"),
            highest_standard_matrix_fixture(),
        );
        let mut progress = active_goal_progress_fixture();
        progress["acceptance_gates"] = json!(["bash scripts/check_formal_core.sh"]);
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, progress);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("parse"));
    }

    #[test]
    fn governance_active_goal_rejects_authority_redirection() {
        let root = test_root("governance-active-authority-redirection");
        write_active_goal_progress_evidence(&root);
        write_json(
            &root.join("config/highest-standard-formal-verification-matrix.json"),
            highest_standard_matrix_fixture(),
        );
        let mut progress = active_goal_progress_fixture();
        progress["claim_authority"]["claim_id"] = json!("formal.some-other-claim");
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, progress);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("must target the pinned conditional claim"));
    }

    #[test]
    fn governance_active_goal_rejects_complete_at_partial_closure() {
        let root = test_root("governance-active-incomplete-complete-status");
        write_active_goal_progress_evidence(&root);
        write_json(
            &root.join("config/highest-standard-formal-verification-matrix.json"),
            highest_standard_matrix_fixture(),
        );
        let mut progress = active_goal_progress_fixture();
        progress["goal_status_when_measured"] = json!("complete");
        let progress_path = root.join("config/active-goal-progress.json");
        write_json(&progress_path, progress);

        let err = check_active_goal_progress_file_with_policy(
            &progress_path,
            TEST_MECHANIZED_ASSUMPTION_TRACKS,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("cannot be marked complete"));
    }

    #[test]
    fn governance_conditional_authority_cannot_be_marked_production_eligible() {
        let root = test_root("governance-conditional-production");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let mut claims = claims_fixture();
        claims["claims"][1]["authority"] = conditional_authority_fixture();
        let claims_path = root.join("claims.json");
        write_json(&claims_path, claims);

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(format!("{err:#}")
            .contains("production_eligible must match machine-readable authority"));
    }

    #[test]
    fn governance_blueprint_rejects_claim_authority_mismatch() {
        let root = test_root("governance-blueprint-authority");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let mut claims = claims_fixture();
        claims["claims"][1]["status"] = json!("research_only");
        claims["claims"][1]["production_eligible"] = json!(false);
        claims["claims"][1]["authority"] = conditional_authority_fixture();
        claims["claims"][1]["residual_risks"] = json!([{
            "id": "test-authority-residual",
            "description": "test residual",
            "status": "open",
            "tracking": "evidence/target.txt"
        }]);
        let claims_path = root.join("claims.json");
        write_json(&claims_path, claims);
        let blueprint_path = root.join("blueprint.json");
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(format!("{err:#}").contains("blueprint authority must exactly match"));
    }

    #[test]
    fn blueprint_accepts_valid_claim_dag() {
        let root = test_root("valid-blueprint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path).expect("valid blueprint");
        assert_eq!(report.nodes, 2);
        assert_eq!(report.edges, 1);
        assert_eq!(report.production_nodes, 2);
        assert_eq!(report.falsification_cases, 2);
        assert_eq!(report.pending_external_review_nodes, 2);
    }

    #[test]
    fn blueprint_rejects_content_changed_after_target_review() {
        let root = test_root("stale-blueprint-review");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        let mut blueprint = blueprint_fixture("needs_review", &[], &["support.dep"]);
        refresh_blueprint_review_digests(&root, &mut blueprint);
        blueprint["nodes"][1]["formal_statement"] =
            json!("Target production claim changed after review.");
        refresh_governance_policy_input_digest(&root, &blueprint_path, &mut blueprint);
        write_json_without_review_refresh(&blueprint_path, blueprint);

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("target_review content_blake3 mismatch"));
    }

    #[test]
    fn blueprint_rejects_dependency_cycles() {
        let root = test_root("cycle-blueprint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &["target.prod"], &["support.dep"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn blueprint_accepts_pending_external_review_for_production_claims() {
        let root = test_root("review-blueprint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("pending review is explicit");
        assert_eq!(report.pending_external_review_nodes, 2);
    }

    #[test]
    fn blueprint_rejects_self_asserted_accepted_review() {
        let root = test_root("self-asserted-review-blueprint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("accepted", &[], &["support.dep"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("unknown target_review status accepted"));
    }

    #[test]
    fn blueprint_rejects_source_changed_after_review_digest() {
        let root = test_root("source-stale-blueprint-review");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );
        write_repo_file(&root, "evidence/target.txt", "weakened target");

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("target_review content_blake3 mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn blueprint_review_digest_rejects_symlink_source() {
        let root = test_root("symlink-blueprint-review-source");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(&root, "outside.txt", "outside");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );
        std::fs::remove_file(root.join("evidence/target.txt")).expect("remove target");
        std::os::unix::fs::symlink(root.join("outside.txt"), root.join("evidence/target.txt"))
            .expect("create target symlink");

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(format!("{err:#}").contains("non-symlink regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn blueprint_review_digest_rejects_fifo_source_without_opening_it() {
        let root = test_root("fifo-blueprint-review-source");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );
        let target = root.join("evidence/target.txt");
        std::fs::remove_file(&target).expect("remove target");
        let status = Command::new("mkfifo")
            .arg(&target)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status}");

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(format!("{err:#}").contains("non-symlink regular file"));
    }

    #[test]
    fn blueprint_review_digest_rejects_oversized_source() {
        let root = test_root("oversized-blueprint-review-source");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );
        std::fs::File::create(root.join("evidence/target.txt"))
            .expect("open target")
            .set_len(MAX_BLUEPRINT_REVIEW_SOURCE_BYTES + 1)
            .expect("extend target");

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(format!("{err:#}").contains("exceeds byte bound"));
    }

    #[test]
    fn blueprint_review_digest_excludes_self_referential_package_outputs() {
        let root = test_root("blueprint-package-cycle");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "audits/native-backend-128b/native-backend-128b-review-package.tar.gz",
            "package-v1",
        );
        write_repo_file(
            &root,
            "audits/native-backend-128b/package.sha256",
            "checksum-v1",
        );
        let mut blueprint = blueprint_fixture("needs_review", &[], &["support.dep"]);
        blueprint["nodes"][1]["evidence_paths"] = json!([
            "evidence/target.txt",
            "audits/native-backend-128b/native-backend-128b-review-package.tar.gz",
            "audits/native-backend-128b/package.sha256"
        ]);
        let node: BlueprintNode = serde_json::from_value(blueprint["nodes"][1].clone()).unwrap();
        let before = blueprint_node_content_blake3(&root, &node).unwrap();

        write_repo_file(
            &root,
            "audits/native-backend-128b/native-backend-128b-review-package.tar.gz",
            "package-v2",
        );
        write_repo_file(
            &root,
            "audits/native-backend-128b/package.sha256",
            "checksum-v2",
        );
        assert_eq!(before, blueprint_node_content_blake3(&root, &node).unwrap());

        write_repo_file(&root, "evidence/target.txt", "changed target");
        assert_ne!(before, blueprint_node_content_blake3(&root, &node).unwrap());
    }

    #[test]
    fn blueprint_rejects_repo_path_escape() {
        let root = test_root("escape-blueprint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        let mut claims = claims_fixture();
        claims["claims"][0]["evidence_paths"] = json!(["../outside.txt"]);
        write_json(&claims_path, claims);
        write_json(
            &blueprint_path,
            blueprint_fixture("needs_review", &[], &["support.dep"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn blueprint_accepts_non_test_implementation_binding() {
        let root = test_root("valid-implementation-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); }\n\
             fn import_announced_block() { if true { verified_helper(); } }\n\
             fn replay_state_to_hash() { verified_helper(); }\n\
             #[cfg(test)]\n\
             mod tests {\n\
                 fn import_mined_block() {}\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding(
                "verified_helper",
                &[
                    "import_mined_block",
                    "import_announced_block",
                    "replay_state_to_hash",
                ],
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("valid implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_constraints, 0);
        assert_eq!(report.implementation_order_edges, 0);
    }

    #[test]
    fn module_root_binding_resolves_across_split_module_files() {
        let root = test_root("module-split-implementation-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native/mod.rs",
            "mod admission;\n\
             mod node_impl;\n\
             pub(crate) use admission::*;\n\
             #[cfg(test)]\n\
             mod tests;\n",
        );
        write_repo_file(
            &root,
            "src/native/admission.rs",
            "pub(crate) fn verified_helper() {}\n",
        );
        write_repo_file(
            &root,
            "src/native/node_impl.rs",
            "struct NativeNode;\n\
             impl NativeNode {\n\
                 pub(crate) fn import_mined_block(&self) { verified_helper(); }\n\
             }\n",
        );
        write_repo_file(
            &root,
            "src/native/tests.rs",
            "fn test_only_helper() { verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding_at(
                "src/native/mod.rs",
                "verified_helper",
                &["NativeNode::import_mined_block"],
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("module-split implementation binding");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn module_root_review_digest_covers_declared_non_test_siblings() {
        let root = test_root("module-review-digest-sibling");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native/mod.rs",
            "mod admission;\nfn import_mined_block() { verified_helper(); }\n",
        );
        write_repo_file(
            &root,
            "src/native/admission.rs",
            "fn verified_helper() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding_at(
                "src/native/mod.rs",
                "verified_helper",
                &["import_mined_block"],
            ),
        );

        write_repo_file(
            &root,
            "src/native/admission.rs",
            "fn verified_helper() { let _semantic_change = true; }\n",
        );
        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("a declared module sibling change must stale target review");
        assert!(
            err.to_string()
                .contains("target_review content_blake3 mismatch"),
            "{err:#}"
        );
    }

    #[test]
    fn rust_review_digest_covers_children_for_every_source_root_form() {
        for (case, root_source, child_source) in [
            ("lib", "src/lib.rs", "src/admission.rs"),
            ("main", "src/main.rs", "src/admission.rs"),
            ("ordinary", "src/native.rs", "src/native/admission.rs"),
            ("mod", "src/native/mod.rs", "src/native/admission.rs"),
        ] {
            let root = test_root(&format!("module-review-digest-{case}-root"));
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            write_repo_file(
                &root,
                root_source,
                "mod admission;\nfn import_mined_block() { verified_helper(); }\n",
            );
            write_repo_file(&root, child_source, "fn verified_helper() {}\n");
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_binding_at(
                    root_source,
                    "verified_helper",
                    &["import_mined_block"],
                ),
            );

            write_repo_file(
                &root,
                child_source,
                "fn verified_helper() { let _semantic_change = true; }\n",
            );
            let err = check_blueprint_file(&blueprint_path, &claims_path)
                .expect_err("a declared Rust child change must stale target review");
            assert!(
                err.to_string()
                    .contains("target_review content_blake3 mismatch"),
                "{case}: {err:#}"
            );
        }
    }

    #[test]
    fn module_root_review_digest_excludes_cfg_test_siblings_with_analysis() {
        let root = test_root("module-review-digest-cfg-test-sibling");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native/mod.rs",
            "mod admission;\n#[cfg(test)]\nmod tests;\nfn import_mined_block() { verified_helper(); }\n",
        );
        write_repo_file(
            &root,
            "src/native/admission.rs",
            "fn verified_helper() {}\n",
        );
        write_repo_file(&root, "src/native/tests.rs", "fn test_only_helper() {}\n");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding_at(
                "src/native/mod.rs",
                "verified_helper",
                &["import_mined_block"],
            ),
        );

        write_repo_file(
            &root,
            "src/native/tests.rs",
            "fn changed_test_only_helper() {}\n",
        );
        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("cfg(test) sibling is excluded from analysis and review digest");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn module_root_binding_rejects_ambiguous_reexported_callee() {
        let root = test_root("module-ambiguous-reexported-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native/mod.rs",
            "mod reviewed;\nmod adversarial;\npub(crate) use adversarial::verified_helper;\nfn import_mined_block() { verified_helper(); }\n",
        );
        write_repo_file(
            &root,
            "src/native/reviewed.rs",
            "pub(crate) fn verified_helper() {}\n",
        );
        write_repo_file(
            &root,
            "src/native/adversarial.rs",
            "pub(crate) fn verified_helper() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding_at(
                "src/native/mod.rs",
                "verified_helper",
                &["import_mined_block"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("an ambiguous reexported callee must not receive review credit");
        assert!(err.to_string().contains("ambiguous across 2"), "{err:#}");
    }

    #[test]
    fn module_root_binding_ignores_cfg_test_module_files() {
        let root = test_root("module-split-test-file-excluded");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native/mod.rs",
            "mod admission;\n\
             #[cfg(test)]\n\
             mod test_support;\n",
        );
        write_repo_file(
            &root,
            "src/native/admission.rs",
            "pub(crate) fn verified_helper() {}\n",
        );
        // The only caller lives in the cfg(test) module file; test-only code
        // must not satisfy a module-root binding.
        write_repo_file(
            &root,
            "src/native/test_support.rs",
            "fn import_mined_block() { verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding_at(
                "src/native/mod.rs",
                "verified_helper",
                &["import_mined_block"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("test-module caller must not satisfy module binding");
        assert!(err
            .to_string()
            .contains("implementation binding caller import_mined_block is missing"));
    }

    #[test]
    fn rust_non_test_file_submodules_skips_tests_and_inline_modules() {
        let source = "mod admission;\npub(crate) mod util;\nmod inline_module { fn f() {} }\n#[cfg(test)]\nmod tests;\n";
        assert_eq!(
            rust_non_test_file_submodules(source, Path::new("src/native/mod.rs")).unwrap(),
            vec!["admission".to_owned(), "util".to_owned()]
        );
    }

    #[test]
    fn module_root_binding_rejects_compiler_selected_module_attributes() {
        for (name, declaration, expected) in [
            (
                "path-selected-module",
                "#[path = \"adversarial.rs\"]\nmod admission;",
                "unsupported compiler-selected attribute path",
            ),
            (
                "production-cfg-module",
                "#[cfg(not(test))]\nmod admission;",
                "unsupported production cfg",
            ),
            (
                "cfg-attr-selected-module",
                "#[cfg_attr(not(test), path = \"adversarial.rs\")]\nmod admission;",
                "unsupported compiler-selected attribute cfg_attr",
            ),
            (
                "include-selected-source",
                "include!(\"adversarial.rs\");\nmod admission;",
                "unsupported include! source injection",
            ),
        ] {
            let root = test_root(name);
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            let malicious_source =
                format!("{declaration}\nfn import_mined_block() {{ verified_helper(); }}\n");
            write_repo_file(
                &root,
                "src/native/mod.rs",
                "mod admission;\nfn import_mined_block() { verified_helper(); }\n",
            );
            write_repo_file(
                &root,
                "src/native/admission.rs",
                "fn verified_helper() {}\n",
            );
            write_repo_file(
                &root,
                "src/native/adversarial.rs",
                "fn unrelated_runtime_helper() {}\n",
            );
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_binding_at(
                    "src/native/mod.rs",
                    "verified_helper",
                    &["import_mined_block"],
                ),
            );
            write_repo_file(&root, "src/native/mod.rs", &malicious_source);

            let err = check_blueprint_file(&blueprint_path, &claims_path)
                .expect_err("compiler-selected module source must fail closed");
            assert!(err.to_string().contains(expected), "{name}: {err:#}");
        }
    }

    #[test]
    fn module_root_binding_resolves_directory_module_and_hashes_it() {
        let root = test_root("directory-module-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native/mod.rs",
            "mod admission;\nfn import_mined_block() { verified_helper(); }\n",
        );
        write_repo_file(
            &root,
            "src/native/admission/mod.rs",
            "fn verified_helper() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding_at(
                "src/native/mod.rs",
                "verified_helper",
                &["import_mined_block"],
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("directory-form module must be analyzed");
        assert_eq!(report.implementation_bindings, 1);

        write_repo_file(
            &root,
            "src/native/admission/mod.rs",
            "fn verified_helper() { let _changed = true; }\n",
        );
        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("directory-form module changes must stale target review");
        assert!(
            err.to_string()
                .contains("target_review content_blake3 mismatch"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_self_tautological_required_caller() {
        let root = test_root("self-tautological-required-caller");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() { verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["verified_helper"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("self-tautological caller must not satisfy binding");
        assert!(err
            .to_string()
            .contains("cannot list itself as required caller verified_helper"));
    }

    #[test]
    fn blueprint_rejects_qualified_same_method_required_caller() {
        let root = test_root("qualified-same-method-required-caller");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "struct Verifier;\n\
             impl Verifier { fn verified_helper(&self) { self.verified_helper(); } }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["Verifier::verified_helper"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("qualified self-tautological caller must not satisfy binding");
        assert!(err
            .to_string()
            .contains("cannot list itself as required caller Verifier::verified_helper"));
    }

    #[test]
    fn blueprint_rejects_self_feeding_callee_that_calls_required_caller() {
        let root = test_root("self-feeding-callee-calls-required-caller");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() { import_mined_block(); }\n\
             fn import_mined_block() { verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("self-feeding helper must not satisfy binding");
        assert!(err
            .to_string()
            .contains("directly calls required caller import_mined_block"));
    }

    #[test]
    fn blueprint_rejects_degenerate_order_successor_matching_callee() {
        let root = test_root("degenerate-order-successor-matching-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["verified_helper"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("callee-as-successor order constraint must not satisfy binding");
        assert!(err
            .to_string()
            .contains("cannot list bound callee verified_helper as its own successor"));
    }

    #[test]
    fn blueprint_rejects_missing_implementation_call() {
        let root = test_root("missing-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains("does not call verified_helper"));
    }

    #[test]
    fn blueprint_rejects_function_item_implementation_reference() {
        let root = test_root("function-item-implementation-reference");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { let _helper = verified_helper; }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains("does not call verified_helper"));
    }

    #[test]
    fn blueprint_rejects_qualified_caller_spoofed_by_same_named_method() {
        let root = test_root("qualified-caller-spoofed-by-same-named-method");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "trait Verifier { fn verify(&self); }\n\
             struct Wanted;\n\
             struct Other;\n\
             fn verified_helper() {}\n\
             impl Verifier for Wanted {\n\
                 fn verify(&self) {}\n\
             }\n\
             impl Verifier for Other {\n\
                 fn verify(&self) { verified_helper(); }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["Wanted::verify"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains("caller Wanted::verify"));
        assert!(err.to_string().contains("does not call verified_helper"));
    }

    #[test]
    fn blueprint_rejects_duplicate_bare_caller_when_one_matching_body_omits_gate() {
        let root = test_root("duplicate-bare-caller-one-body-omits-gate");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "trait Verifier { fn verify(&self); }\n\
             struct Wanted;\n\
             struct Other;\n\
             fn verified_helper() {}\n\
             impl Verifier for Wanted {\n\
                 fn verify(&self) {}\n\
             }\n\
             impl Verifier for Other {\n\
                 fn verify(&self) { verified_helper(); }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["verify"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper in non-test Rust code"));
    }

    #[test]
    fn blueprint_accepts_inherent_qualified_caller() {
        let root = test_root("inherent-qualified-caller");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "struct Wanted;\n\
             fn verified_helper() {}\n\
             impl Wanted {\n\
                 fn verify(&self) { verified_helper(); }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["Wanted::verify"]),
        );

        let report =
            check_blueprint_file(&blueprint_path, &claims_path).expect("inherent qualified caller");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn blueprint_accepts_qualified_order_and_result_obligation() {
        let root = test_root("qualified-order-and-result-obligation");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "trait Verifier { fn verify(&self); }\n\
             struct Wanted;\n\
             struct Other;\n\
             fn verified_helper() {}\n\
             fn mutate() {}\n\
             impl Verifier for Wanted {\n\
                 fn verify(&self) { verified_helper()?; mutate(); }\n\
             }\n\
             impl Verifier for Other {\n\
                 fn verify(&self) { mutate(); verified_helper(); }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["Wanted::verify"],
                "Wanted::verify",
                &["mutate"],
                Some("must_propagate_result"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("qualified caller order and result obligation");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_constraints, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_accepts_propagated_result_implementation_call() {
        let root = test_root("propagated-result-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper()?; }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("propagated result implementation binding");
        assert_eq!(report.implementation_bindings, 1);
    }

    fn shared_sled_ufcs_test_invocation(closure_body: &str) -> String {
        [
            "self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                 &(&self.meta_tree, &self.height_tree, &self.block_tree,\n\
                   &self.commitment_tree, &self.nullifier_tree, &self.bridge_inbound_tree,\n\
                   &self.ciphertext_index_tree, &self.ciphertext_archive_tree,\n\
                   &self.da_ciphertext_tree, &self.action_tree, &self.poseidon2_v8_tree,),\n\
                 |(meta_tree, height_tree, block_tree, commitment_tree, nullifier_tree,\n\
                   bridge_inbound_tree, ciphertext_index_tree, ciphertext_archive_tree,\n\
                   da_ciphertext_tree, action_tree, poseidon2_v8_tree,)| {\n",
            closure_body,
            "\n                 },\n\
             ).map_err(|_| ())?;\n",
        ]
        .concat()
    }

    fn shared_sled_test_helper_expression() -> &'static str {
        "self::verified_helper(\n\
             poseidon2_v8_tree,\n\
             poseidon2_v8_reorg.as_ref().map(|(_, v8_plan)| v8_plan),\n\
             suffix_manifest,\n\
             \"native canonical suffix reorg manifest\",\n\
         )"
    }

    fn shared_sled_test_node_source(method_body: &str) -> String {
        [
            "extern crate sled as __hegemon_pinned_sled;\n\
             fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             fn legacy_write() -> Result<(), ()> { Ok(()) }\n\
             struct Tree;\n\
             struct Node { meta_tree: Tree, height_tree: Tree, block_tree: Tree,\n\
                           commitment_tree: Tree, nullifier_tree: Tree, bridge_inbound_tree: Tree,\n\
                           ciphertext_index_tree: Tree, ciphertext_archive_tree: Tree,\n\
                           da_ciphertext_tree: Tree, action_tree: Tree, poseidon2_v8_tree: Tree }\n\
             impl Node {\n\
                 fn import_mined_block(&self) -> Result<(), ()> {\n",
            method_body,
            "\n                 }\n\
             }\n",
        ]
        .concat()
    }

    fn write_shared_sled_test_module_root(root: &Path) {
        write_repo_file(root, "src/lib.rs", "mod native;\n");
    }

    fn production_shared_sled_ast_fixture() -> String {
        "extern crate sled as __hegemon_pinned_sled;\n\
         /// Applies one typed plan and admits its manifest.\n\
         fn verified_helper() {}\n\
         fn native_canonical_suffix_reorg_commit_manifest(\n\
             plan: &Plan,\n\
             v8_plan: Option<&V8Plan>,\n\
         ) -> Result<Manifest, ()> { todo!() }\n\
         impl NativeNode {\n\
             fn plan_poseidon2_v8_reorganization(\n\
                 &self,\n\
                 old_blocks: &[Block],\n\
                 new_blocks: &[Block],\n\
             ) -> Result<Option<(Store, V8Plan)>, ()> { todo!() }\n\
             fn plan_poseidon2_v8_block_against_parent_tip(\n\
                 &self,\n\
                 parent_height: u64,\n\
                 parent_hash: [u8; 32],\n\
                 meta: &Meta,\n\
                 actions: &[PendingAction],\n\
             ) -> Result<Option<(Store, V8Plan)>, ()> { todo!() }\n\
             fn commit_reorg_suffix_atomically(\n\
                 &self,\n\
                 plan: &NativeReorgSuffixCommitPlan,\n\
                 best: &NativeBlockMeta,\n\
                 next_nullifier_accumulator: &NullifierAccumulator,\n\
                 poseidon2_v8_reorg: Option<(\n\
                     poseidon2_v8_state::Poseidon2V8StateStore,\n\
                     poseidon2_v8_state::Poseidon2V8CanonicalPlan,\n\
                 )>,\n\
                 commit_kind: NativeAtomicCommitKind,\n\
             ) -> Result<()> {\n\
                 let v8_plan = poseidon2_v8_reorg.as_ref().map(|(_, v8_plan)| v8_plan);\n\
                 let suffix_manifest = match commit_kind {\n\
                     NativeAtomicCommitKind::TipExtensionBatchCommit => {\n\
                         self::native_tip_extension_batch_commit_manifest(plan, v8_plan)?\n\
                     }\n\
                     NativeAtomicCommitKind::CanonicalSuffixReorgCommit => {\n\
                         if !plan.tip_action_removals.is_empty() {\n\
                             return Err(anyhow!(\"unexpected tip removals\"));\n\
                         }\n\
                         self::native_canonical_suffix_reorg_commit_manifest(plan, v8_plan)?\n\
                     }\n\
                     _ => return Err(anyhow!(\"invalid commit kind\")),\n\
                 };\n\
                 self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                     &(),\n\
                     |_| Ok(()),\n\
                 ).map_err(|_| ())?;\n\
                 Ok(())\n\
             }\n\
             pub(crate) fn commit_mined_block_atomically(\n\
                 &self,\n\
                 actions: &[PendingAction],\n\
                 planned: &[NativePlannedActionEffect],\n\
                 meta: &NativeBlockMeta,\n\
                 parent_nullifier_accumulator: &NullifierAccumulator,\n\
                 next_nullifier_accumulator: &NullifierAccumulator,\n\
                 checkpoint_rows: &NativeCanonicalCheckpointRows,\n\
                 additional_pending_action_removals: &[ActionId48],\n\
             ) -> Result<()> {\n\
                 let (parent_projection, _) = self\
                     .inspect_stored_pow_metadata(\n\
                         &meta.parent_hash,\n\
                         None,\n\
                         \"native mined-block V8 canonical parent\",\n\
                     )?\
                     .ok_or_else(|| anyhow!(\"missing parent\"))?;\n\
                 if parent_projection.height.checked_add(1) != Some(meta.height)\
                     || parent_projection.hash != meta.parent_hash\
                 {\n\
                     return Err(anyhow!(\"parent mismatch\"));\n\
                 }\n\
                 let v8_commit = self\
                     .plan_poseidon2_v8_block_against_parent_tip(\n\
                         parent_projection.height,\n\
                         parent_projection.hash,\n\
                         meta,\n\
                         actions,\n\
                     )?;\n\
                 let mined_manifest = super::native_mined_block_commit_manifest(\n\
                     actions,\n\
                     planned,\n\
                     v8_commit.as_ref().map(|(_, plan)| plan),\n\
                 );\n\
                 self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                     &(),\n\
                     |_| Ok(()),\n\
                 ).map_err(|_| ())?;\n\
                 Ok(())\n\
             }\n\
         }\n"
        .to_owned()
    }

    fn production_shared_sled_ast_binding() -> ImplementationBinding {
        ImplementationBinding {
            path: "node/src/native/node_impl.rs".to_owned(),
            callee: "verified_helper".to_owned(),
            required_callers: vec![
                "NativeNode::commit_reorg_suffix_atomically".to_owned(),
                "NativeNode::commit_mined_block_atomically".to_owned(),
            ],
            result_obligation: Some("must_propagate_shared_sled_transaction_result".to_owned()),
            call_order_constraints: Vec::new(),
        }
    }

    fn assert_production_shared_sled_ast_rejected(source: &str, expected: &str) {
        let parsed = syn::parse_file(source).expect("parse production shared sled AST fixture");
        let err = validate_unconditional_shared_sled_symbols(
            &parsed,
            "native.atomic-commit-manifest-admission",
            &production_shared_sled_ast_binding(),
        )
        .expect_err("mutated production shared sled AST must reject");
        assert!(err.to_string().contains(expected), "{err:#}");
    }

    fn transaction_local_v8_helper_fixture() -> String {
        "fn verified_helper(\n\
             poseidon2_v8_tree: &Tree,\n\
             plan: Option<&Plan>,\n\
             manifest: Manifest,\n\
             context: &'static str,\n\
         ) -> Result<usize> {\n\
             let actual_application_count = match plan {\n\
                 Some(plan) => {\n\
                     super::poseidon2_v8_state::Poseidon2V8StateStore::apply_canonical_plan_in_transaction(\n\
                         poseidon2_v8_tree,\n\
                         plan,\n\
                     )?;\n\
                     1\n\
                 }\n\
                 None => 0,\n\
             };\n\
             let observed = super::NativeAtomicCommitManifestAdmissionInput {\n\
                 poseidon2_v8_plan_application_count: actual_application_count,\n\
                 ..manifest\n\
             };\n\
             super::block_flow::evaluate_native_atomic_commit_manifest_admission(observed)\n\
                 .map_err(|rejection| {\n\
                     self::__hegemon_pinned_sled::transaction::ConflictableTransactionError::Abort(\n\
                         format!(\"{context}: {}\", rejection.label())\n\
                     )\n\
                 })?;\n\
             Ok(actual_application_count)\n\
         }"
            .to_owned()
    }

    fn assert_transaction_local_v8_helper_rejected(source: &str, expected: &str) {
        let parsed = syn::parse_file(source).expect("parse transaction-local V8 helper fixture");
        let helper = parsed
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Fn(function) = item else {
                    return None;
                };
                (function.sig.ident == "verified_helper").then_some(function)
            })
            .expect("transaction-local V8 helper fixture");
        let err = validate_transaction_local_v8_application_helper(
            helper,
            "native.atomic-commit-manifest-admission",
        )
        .expect_err("mutated transaction-local V8 helper must reject");
        assert!(err.to_string().contains(expected), "{err:#}");
    }

    #[test]
    fn transaction_local_v8_helper_ast_accepts_exact_apply_then_observe_then_admit() {
        let parsed = syn::parse_file(&transaction_local_v8_helper_fixture())
            .expect("parse transaction-local V8 helper fixture");
        let helper = parsed
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) => Some(function),
                _ => None,
            })
            .expect("transaction-local V8 helper fixture");
        validate_transaction_local_v8_application_helper(
            helper,
            "native.atomic-commit-manifest-admission",
        )
        .expect("exact transaction-local V8 helper");
    }

    #[test]
    fn transaction_local_v8_helper_ast_rejects_cfg_gated_security_steps() {
        let raw_cfg = transaction_local_v8_helper_fixture().replacen(
            "super::poseidon2_v8_state::Poseidon2V8StateStore::apply_canonical_plan_in_transaction(",
            "#[cfg(test)]\n                     super::poseidon2_v8_state::Poseidon2V8StateStore::apply_canonical_plan_in_transaction(",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &raw_cfg,
            "raw apply expression must be unconditional",
        );

        let field_cfg = transaction_local_v8_helper_fixture().replacen(
            "poseidon2_v8_plan_application_count: actual_application_count,",
            "#[cfg(test)]\n                 poseidon2_v8_plan_application_count: actual_application_count,",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &field_cfg,
            "overwrite only the actual application count",
        );

        let evaluator_cfg = transaction_local_v8_helper_fixture().replacen(
            "super::block_flow::evaluate_native_atomic_commit_manifest_admission(observed)",
            "#[cfg_attr(test, allow(dead_code))]\n             super::block_flow::evaluate_native_atomic_commit_manifest_admission(observed)",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &evaluator_cfg,
            "manifest admission must be unconditional",
        );
    }

    #[test]
    fn transaction_local_v8_helper_ast_rejects_application_count_or_evaluator_substitution() {
        let hard_coded_zero = transaction_local_v8_helper_fixture().replacen(
            "let actual_application_count = match plan {",
            "let actual_application_count = 0;\n             let _ignored_plan = match plan {",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &hard_coded_zero,
            "requires exactly four ordered statements",
        );

        let copied_source_count = transaction_local_v8_helper_fixture().replacen(
            "poseidon2_v8_plan_application_count: actual_application_count,",
            "poseidon2_v8_plan_application_count: manifest.source_poseidon2_v8_plan_count,",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &copied_source_count,
            "overwrite only the actual application count",
        );

        let count_two = transaction_local_v8_helper_fixture().replacen(")?;\n1\n", ")?;\n2\n", 1);
        assert_transaction_local_v8_helper_rejected(
            &count_two,
            "raw apply/count coupling is not canonical",
        );

        let wrong_apply = transaction_local_v8_helper_fixture().replacen(
            "apply_canonical_plan_in_transaction",
            "skip_canonical_plan_in_transaction",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &wrong_apply,
            "calls the wrong raw typed apply",
        );

        let wrong_evaluator = transaction_local_v8_helper_fixture().replacen(
            "evaluate_native_atomic_commit_manifest_admission",
            "pretend_native_atomic_commit_manifest_admission",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &wrong_evaluator,
            "calls the wrong manifest evaluator",
        );

        let non_abort_rejection = transaction_local_v8_helper_fixture().replacen(
            "ConflictableTransactionError::Abort(",
            "ConflictableTransactionError::Conflict(",
            1,
        );
        assert_transaction_local_v8_helper_rejected(
            &non_abort_rejection,
            "must map rejection to a pinned sled transaction abort",
        );
    }

    #[test]
    fn production_shared_sled_ast_accepts_exact_parent_type_and_plan_provenance() {
        let parsed = syn::parse_file(&production_shared_sled_ast_fixture())
            .expect("parse production shared sled AST fixture");
        validate_unconditional_shared_sled_symbols(
            &parsed,
            "native.atomic-commit-manifest-admission",
            &production_shared_sled_ast_binding(),
        )
        .expect("exact production shared sled AST");
    }

    #[test]
    fn production_shared_sled_provenance_accepts_current_node_source() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("canonical repository root");
        let source = std::fs::read_to_string(root.join("node/src/native/node_impl.rs"))
            .expect("read current native node source");
        let parsed = syn::parse_file(&source).expect("parse current native node source");
        validate_unconditional_shared_sled_symbols(
            &parsed,
            "native.atomic-commit-manifest-admission",
            &ImplementationBinding {
                callee: "apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction"
                    .to_owned(),
                ..production_shared_sled_ast_binding()
            },
        )
        .expect("current production V8 atomic caller provenance");
    }

    #[test]
    fn production_shared_sled_ast_rejects_async_atomic_caller() {
        let source = production_shared_sled_ast_fixture().replacen(
            "fn commit_reorg_suffix_atomically(",
            "async fn commit_reorg_suffix_atomically(",
            1,
        );
        assert_production_shared_sled_ast_rejected(
            &source,
            "must keep its exact synchronous fallible signature",
        );
    }

    #[test]
    fn production_shared_sled_ast_rejects_nested_outer_macro_before_transaction() {
        let source = production_shared_sled_ast_fixture().replacen(
            "self::__hegemon_pinned_sled::transaction::Transactional::transaction(",
            "if skip { crate::early_ok!(); }\n\
             self::__hegemon_pinned_sled::transaction::Transactional::transaction(",
            1,
        );
        assert_production_shared_sled_ast_rejected(
            &source,
            "prefix must not bypass the transaction or use an unpinned macro outside closures",
        );
    }

    #[test]
    fn production_shared_sled_ast_rejects_success_before_transaction() {
        let source = production_shared_sled_ast_fixture().replacen(
            "self::__hegemon_pinned_sled::transaction::Transactional::transaction(",
            "return Ok(());\n\
             self::__hegemon_pinned_sled::transaction::Transactional::transaction(",
            1,
        );
        assert_production_shared_sled_ast_rejected(
            &source,
            "prefix must not bypass the transaction",
        );
    }

    #[test]
    fn production_shared_sled_ast_rejects_reorg_parameter_or_commit_kind_drift() {
        let borrowed_plan = production_shared_sled_ast_fixture().replacen(
            "poseidon2_v8_reorg: Option<(",
            "poseidon2_v8_reorg: &Option<(",
            1,
        );
        assert_production_shared_sled_ast_rejected(&borrowed_plan, "parameter grammar changed");

        let forged_kind = production_shared_sled_ast_fixture().replacen(
            "match commit_kind {",
            "match NativeAtomicCommitKind::CanonicalSuffixReorgCommit {",
            1,
        );
        assert_production_shared_sled_ast_rejected(&forged_kind, "must split commit_kind");

        let swapped_builder = production_shared_sled_ast_fixture().replacen(
            "native_tip_extension_batch_commit_manifest",
            "native_canonical_suffix_reorg_commit_manifest",
            1,
        );
        assert_production_shared_sled_ast_rejected(&swapped_builder, "must split commit_kind");
    }

    #[test]
    fn production_shared_sled_ast_rejects_forged_mined_parent_provenance() {
        let unchecked_height = production_shared_sled_ast_fixture().replacen(
            "parent_projection.height.checked_add(1) != Some(meta.height)",
            "parent_projection.height + 1 != meta.height",
            1,
        );
        assert_production_shared_sled_ast_rejected(
            &unchecked_height,
            "requires checked stored-parent inspection",
        );

        let forged_hash =
            production_shared_sled_ast_fixture().replacen("&meta.parent_hash,", "&meta.hash,", 1);
        assert_production_shared_sled_ast_rejected(
            &forged_hash,
            "requires checked stored-parent inspection",
        );

        let obsolete_planner = production_shared_sled_ast_fixture().replacen(
            "plan_poseidon2_v8_block_against_parent_tip(",
            "plan_poseidon2_v8_block_against_parent(",
            2,
        );
        assert_production_shared_sled_ast_rejected(
            &obsolete_planner,
            "requires one attribute-free inherent source planner",
        );
    }

    #[test]
    fn production_shared_sled_binding_accepts_current_node_source_and_cargo_targets() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("canonical repository root");
        validate_rust_implementation_binding(
            &root,
            "native.atomic-commit-manifest-admission",
            &ImplementationBinding {
                path: "node/src/native/node_impl.rs".to_owned(),
                callee: "apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction"
                    .to_owned(),
                required_callers: vec![
                    "NativeNode::commit_reorg_suffix_atomically".to_owned(),
                    "NativeNode::commit_mined_block_atomically".to_owned(),
                ],
                result_obligation: Some("must_propagate_shared_sled_transaction_result".to_owned()),
                call_order_constraints: [
                    "NativeNode::commit_reorg_suffix_atomically",
                    "NativeNode::commit_mined_block_atomically",
                ]
                .into_iter()
                .map(|caller| ImplementationCallOrderConstraint {
                    caller: caller.to_owned(),
                    callee_must_precede: vec!["block_tree.insert".to_owned()],
                    result_obligation: None,
                    must_dominate_successors: true,
                    lean_theorems: Vec::new(),
                })
                .collect(),
            },
        )
        .expect("current production shared sled binding");
    }

    fn native_node_parent_struct_fixture() -> String {
        "pub struct NativeNode {\n\
             meta_tree: sled::Tree,\n\
             height_tree: sled::Tree,\n\
             block_tree: sled::Tree,\n\
             commitment_tree: sled::Tree,\n\
             nullifier_tree: sled::Tree,\n\
             bridge_inbound_tree: sled::Tree,\n\
             ciphertext_index_tree: sled::Tree,\n\
             ciphertext_archive_tree: sled::Tree,\n\
             da_ciphertext_tree: sled::Tree,\n\
             action_tree: sled::Tree,\n\
             poseidon2_v8_tree: sled::Tree,\n\
         }\n"
        .to_owned()
    }

    #[test]
    fn native_node_parent_struct_pin_rejects_alias_or_gated_tree_field() {
        let valid_root = test_root("native-node-parent-struct-valid");
        write_repo_file(
            &valid_root,
            "node/src/native/mod.rs",
            &native_node_parent_struct_fixture(),
        );
        validate_native_node_parent_struct(&valid_root).expect("exact native parent struct");

        let alias_root = test_root("native-node-parent-struct-alias");
        let alias = native_node_parent_struct_fixture().replacen(
            "pub struct NativeNode",
            "pub struct Decoy",
            1,
        ) + "type NativeNode = Decoy;\n";
        write_repo_file(&alias_root, "node/src/native/mod.rs", &alias);
        let err = validate_native_node_parent_struct(&alias_root)
            .expect_err("NativeNode alias must not satisfy production type binding");
        assert!(
            err.to_string()
                .contains("exactly one top-level NativeNode struct"),
            "{err:#}"
        );

        let gated_root = test_root("native-node-parent-struct-gated-tree");
        let gated = native_node_parent_struct_fixture().replacen(
            "poseidon2_v8_tree: sled::Tree,",
            "#[cfg(test)] poseidon2_v8_tree: sled::Tree,",
            1,
        );
        write_repo_file(&gated_root, "node/src/native/mod.rs", &gated);
        let err = validate_native_node_parent_struct(&gated_root)
            .expect_err("cfg-gated typed tree must not satisfy production type binding");
        assert!(err.to_string().contains("poseidon2_v8_tree"), "{err:#}");
    }

    #[test]
    fn v8_atomic_runtime_gate_variance_visitor_rejects_prod_test_divergence() {
        let parsed = syn::parse_file(
            "fn evaluator() { #[cfg(not(test))] return; }\n\
             impl Store { fn apply() { #[cfg_attr(test, allow(dead_code))] let _row = 1; } }",
        )
        .expect("parse compiler-selection mutation fixture");
        let evaluator = parsed
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) => Some(function),
                _ => None,
            })
            .expect("evaluator fixture");
        assert!(syn_item_fn_has_runtime_gate_variance(evaluator));
        let raw_apply = parsed
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Impl(item_impl) => item_impl.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(function) => Some(function),
                    _ => None,
                }),
                _ => None,
            })
            .expect("raw apply fixture");
        assert!(syn_impl_item_fn_has_runtime_gate_variance(raw_apply));

        let macro_selected = syn::parse_file(
            "fn evaluator() { let skip = || cfg!(feature = \"skip-v8-atomic\"); if skip() { return; } }",
        )
        .expect("parse nested compiler-selection macro fixture");
        let macro_selected = macro_selected
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) => Some(function),
                _ => None,
            })
            .expect("macro-selected evaluator fixture");
        assert!(syn_item_fn_has_runtime_gate_variance(macro_selected));

        let ordinary = syn::parse_file("fn evaluator() { let _row = 1; }")
            .expect("parse ordinary evaluator fixture");
        let ordinary = ordinary
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) => Some(function),
                _ => None,
            })
            .expect("ordinary evaluator fixture");
        assert!(!syn_item_fn_has_runtime_gate_variance(ordinary));
    }

    fn current_v8_atomic_runtime_gate_sources() -> (String, String, String) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("canonical repository root");
        (
            std::fs::read_to_string(root.join("node/src/native/block_flow.rs"))
                .expect("read production atomic manifest evaluator source"),
            std::fs::read_to_string(root.join("node/src/native/node_impl.rs"))
                .expect("read production transaction-local atomic manifest source"),
            std::fs::read_to_string(root.join("node/src/native/poseidon2_v8_state.rs"))
                .expect("read production raw typed-plan apply source"),
        )
    }

    fn assert_v8_atomic_runtime_gate_mutation_rejected(
        block_flow_source: &str,
        node_impl_source: &str,
        state_source: &str,
        expected: &str,
    ) {
        let err = validate_v8_atomic_runtime_gate_sources(
            block_flow_source,
            node_impl_source,
            state_source,
        )
        .expect_err("mutated V8 atomic runtime source must reject");
        assert!(err.to_string().contains(expected), "{err:#}");
    }

    #[test]
    fn v8_atomic_runtime_gate_rejects_profile_macros_constants_and_environment_bypasses() {
        let (block_flow, node_impl, state) = current_v8_atomic_runtime_gate_sources();
        validate_v8_atomic_runtime_gate_sources(&block_flow, &node_impl, &state)
            .expect("current V8 atomic runtime source");

        let evaluator_marker =
            ") -> ::core::result::Result<(), NativeAtomicCommitManifestAdmissionRejection> {\n    if matches!(";
        let evaluator_cfg = block_flow.replacen(
            evaluator_marker,
            ") -> ::core::result::Result<(), NativeAtomicCommitManifestAdmissionRejection> {\n    if cfg!(not(test)) { return ::core::result::Result::Ok(()); }\n    if matches!(",
            1,
        );
        assert_ne!(evaluator_cfg, block_flow);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &evaluator_cfg,
            &node_impl,
            &state,
            "macro-free cfg-invariant",
        );

        let raw_marker =
            ") -> ConflictableTransactionResult<(), String> {\n        let observed_tip";
        let raw_environment = state.replacen(
            raw_marker,
            ") -> ConflictableTransactionResult<(), String> {\n        if option_env!(\"HEGEMON_SKIP_V8_ATOMIC\").is_some() { return ::core::result::Result::Ok(()); }\n        let observed_tip",
            1,
        );
        assert_ne!(raw_environment, state);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &block_flow,
            &node_impl,
            &raw_environment,
            "macro-free cfg-invariant",
        );

        let raw_profile_constant = state
            .replacen(
                "impl Poseidon2V8StateStore {",
                "const SKIP_V8_ATOMIC: bool = cfg!(feature = \"skip-v8-atomic\");\n\nimpl Poseidon2V8StateStore {",
                1,
            )
            .replacen(
                raw_marker,
                ") -> ConflictableTransactionResult<(), String> {\n        if SKIP_V8_ATOMIC { return ::core::result::Result::Ok(()); }\n        let observed_tip",
                1,
            );
        assert_ne!(raw_profile_constant, state);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &block_flow,
            &node_impl,
            &raw_profile_constant,
            "runtime AST changed",
        );
    }

    #[test]
    fn v8_atomic_runtime_gate_rejects_semantic_admission_or_apply_noops() {
        let (block_flow, node_impl, state) = current_v8_atomic_runtime_gate_sources();
        let evaluator_marker =
            ") -> ::core::result::Result<(), NativeAtomicCommitManifestAdmissionRejection> {\n    if matches!(";
        let evaluator_noop = block_flow.replacen(
            evaluator_marker,
            ") -> ::core::result::Result<(), NativeAtomicCommitManifestAdmissionRejection> {\n    return ::core::result::Result::Ok(());\n    if matches!(",
            1,
        );
        assert_ne!(evaluator_noop, block_flow);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &evaluator_noop,
            &node_impl,
            &state,
            "runtime AST changed",
        );

        let widened_atomic_kind_match = block_flow.replacen(
            "NativeAtomicCommitKind::MinedBlockCommit | NativeAtomicCommitKind::TipExtensionBatchCommit",
            "_",
            1,
        );
        assert_ne!(widened_atomic_kind_match, block_flow);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &widened_atomic_kind_match,
            &node_impl,
            &state,
            "macro-free cfg-invariant",
        );

        let evaluator_err_shadow = block_flow
            .replacen(
                "use super::*;",
                "use super::*;\n#[allow(non_upper_case_globals)]\n#[cfg(not(test))]\nconst Err: fn(NativeAtomicCommitManifestAdmissionRejection) -> ::core::result::Result<(), NativeAtomicCommitManifestAdmissionRejection> = |_| ::core::result::Result::Ok(());",
                1,
            )
            .replacen("::core::result::Result::Err(", "Err(", 1);
        assert_ne!(evaluator_err_shadow, block_flow);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &evaluator_err_shadow,
            &node_impl,
            &state,
            "runtime AST changed",
        );

        let helper_noop = block_flow.replacen(
            "NativeAtomicCommitKind::MinedBlockCommit => 1,",
            "NativeAtomicCommitKind::MinedBlockCommit => input.block_record_writes,",
            1,
        );
        assert_ne!(helper_noop, block_flow);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &helper_noop,
            &node_impl,
            &state,
            "runtime AST changed",
        );

        let mined_manifest_tautology = block_flow.replacen(
            "poseidon2_v8_plan_application_count: UNOBSERVED_POSEIDON2_V8_PLAN_APPLICATION_COUNT,",
            "poseidon2_v8_plan_application_count: poseidon2_v8_plan_count,",
            1,
        );
        assert_ne!(mined_manifest_tautology, block_flow);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &mined_manifest_tautology,
            &node_impl,
            &state,
            "runtime AST changed",
        );

        let suffix_manifest_tautology = node_impl.replacen(
            "poseidon2_v8_plan_application_count: UNOBSERVED_POSEIDON2_V8_PLAN_APPLICATION_COUNT,",
            "poseidon2_v8_plan_application_count: poseidon2_v8_plan_count,",
            1,
        );
        assert_ne!(suffix_manifest_tautology, node_impl);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &block_flow,
            &suffix_manifest_tautology,
            &state,
            "runtime AST changed",
        );

        let helper_copies_source_count = node_impl.replacen(
            "poseidon2_v8_plan_application_count: actual_application_count,",
            "poseidon2_v8_plan_application_count: manifest.source_poseidon2_v8_plan_count,",
            1,
        );
        assert_ne!(helper_copies_source_count, node_impl);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &block_flow,
            &helper_copies_source_count,
            &state,
            "runtime AST changed",
        );

        let raw_marker =
            ") -> ConflictableTransactionResult<(), String> {\n        let observed_tip";
        let raw_noop = state.replacen(
            raw_marker,
            ") -> ConflictableTransactionResult<(), String> {\n        return ::core::result::Result::Ok(());\n        let observed_tip",
            1,
        );
        assert_ne!(raw_noop, state);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &block_flow,
            &node_impl,
            &raw_noop,
            "runtime AST changed",
        );

        let raw_err_shadow = state
            .replacen(
                "#![allow(dead_code)]",
                "#![allow(dead_code)]\n#[allow(non_upper_case_globals)]\n#[cfg(not(test))]\nconst Err: fn(ConflictableTransactionError<String>) -> ConflictableTransactionResult<(), String> = |_| ::core::result::Result::Ok(());",
                1,
            )
            .replacen("::core::result::Result::Err(", "Err(", 1);
        assert_ne!(raw_err_shadow, state);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &block_flow,
            &node_impl,
            &raw_err_shadow,
            "runtime AST changed",
        );
    }

    #[test]
    fn v8_atomic_runtime_gate_ast_ignores_comments_but_rejects_enclosing_cfg() {
        let (block_flow, node_impl, state) = current_v8_atomic_runtime_gate_sources();
        let evaluator_marker =
            ") -> ::core::result::Result<(), NativeAtomicCommitManifestAdmissionRejection> {\n    if matches!(";
        let commented = block_flow.replacen(
            evaluator_marker,
            ") -> ::core::result::Result<(), NativeAtomicCommitManifestAdmissionRejection> {\n    // Non-semantic review note.\n    if matches!(",
            1,
        );
        assert_ne!(commented, block_flow);
        validate_v8_atomic_runtime_gate_sources(&commented, &node_impl, &state)
            .expect("comments do not change normalized V8 runtime AST");

        let cfg_impl = state.replacen(
            "impl Poseidon2V8StateStore {",
            "#[cfg(not(test))]\nimpl Poseidon2V8StateStore {",
            1,
        );
        assert_ne!(cfg_impl, state);
        assert_v8_atomic_runtime_gate_mutation_rejected(
            &block_flow,
            &node_impl,
            &cfg_impl,
            "cfg-invariant raw typed-plan apply",
        );
    }

    #[test]
    fn production_shared_sled_ast_rejects_bare_or_qualified_decoy_type() {
        for replacement in ["impl super::NativeNode {", "impl adversary::NativeNode {"] {
            let source =
                production_shared_sled_ast_fixture().replacen("impl NativeNode {", replacement, 1);
            assert_production_shared_sled_ast_rejected(
                &source,
                "requires one top-level inherent method",
            );
        }
    }

    #[test]
    fn production_shared_sled_ast_rejects_plan_and_manifest_shadows() {
        let suffix_shadow = production_shared_sled_ast_fixture().replacen(
            "let suffix_manifest =",
            "let poseidon2_v8_reorg = None;\nlet suffix_manifest =",
            1,
        );
        assert_production_shared_sled_ast_rejected(
            &suffix_shadow,
            "externally prepared poseidon2_v8_reorg parameter without shadowing",
        );

        let mined_shadow = production_shared_sled_ast_fixture().replacen(
            "let mined_manifest =",
            "let v8_commit = None;\nlet mined_manifest =",
            1,
        );
        assert_production_shared_sled_ast_rejected(
            &mined_shadow,
            "checked stored-parent inspection before ordered immutable v8_commit",
        );

        let manifest_redirect = production_shared_sled_ast_fixture().replacen(
            "poseidon2_v8_reorg.as_ref().map(|(_, v8_plan)| v8_plan)",
            "None",
            1,
        );
        assert_production_shared_sled_ast_rejected(
            &manifest_redirect,
            "derive one immutable v8_plan reference",
        );
    }

    fn assert_shared_sled_binding_rejected(test_name: &str, method_body: &str) {
        assert_shared_sled_source_rejected(test_name, &shared_sled_test_node_source(method_body));
    }

    fn assert_shared_sled_source_rejected(test_name: &str, source: &str) {
        assert_shared_sled_source_rejected_with(
            test_name,
            source,
            "does not call verified_helper with propagated shared sled transaction result",
        );
    }

    fn assert_shared_sled_source_rejected_with(
        test_name: &str,
        source: &str,
        expected_error: &str,
    ) {
        let root = test_root(test_name);
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_shared_sled_test_module_root(&root);
        write_repo_file(&root, "src/native.rs", source);
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_shared_sled_transaction_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("invalid shared sled binding must reject");
        assert!(err.to_string().contains(expected_error), "{err:#}");
    }

    fn assert_nested_shared_sled_source_rejected_with(
        test_name: &str,
        source: &str,
        library_root: &str,
        native_module_root: &str,
        expected_error: &str,
    ) {
        let root = test_root(test_name);
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(&root, "src/lib.rs", library_root);
        write_repo_file(&root, "src/native/mod.rs", native_module_root);
        write_repo_file(&root, "src/native/node_impl.rs", source);
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        let mut blueprint = blueprint_fixture_with_result_binding(
            "verified_helper",
            &["import_mined_block"],
            "must_propagate_shared_sled_transaction_result",
        );
        blueprint["nodes"][1]["implementation_paths"] =
            json!(["evidence/target.txt", "src/native/node_impl.rs"]);
        blueprint["nodes"][1]["implementation_bindings"][0]["path"] =
            json!("src/native/node_impl.rs");
        write_json(&blueprint_path, blueprint);

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("invalid nested shared sled binding must reject");
        assert!(err.to_string().contains(expected_error), "{err:#}");
    }

    #[test]
    fn blueprint_accepts_propagated_helper_inside_propagated_transaction_closure() {
        let root = test_root("propagated-helper-inside-propagated-transaction");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_shared_sled_test_module_root(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "extern crate sled as __hegemon_pinned_sled;\n\
             fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             struct Tree;\n\
             struct Node {\n\
                 meta_tree: Tree,\n\
                 height_tree: Tree,\n\
                 block_tree: Tree,\n\
                 commitment_tree: Tree,\n\
                 nullifier_tree: Tree,\n\
                 bridge_inbound_tree: Tree,\n\
                 ciphertext_index_tree: Tree,\n\
                 ciphertext_archive_tree: Tree,\n\
                 da_ciphertext_tree: Tree,\n\
                 action_tree: Tree,\n\
                 poseidon2_v8_tree: Tree,\n\
             }\n\
             impl Node {\n\
                 fn import_mined_block(&self) -> Result<(), ()> {\n\
                     self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                         &(&self.meta_tree, &self.height_tree, &self.block_tree,\n\
                           &self.commitment_tree, &self.nullifier_tree, &self.bridge_inbound_tree,\n\
                           &self.ciphertext_index_tree, &self.ciphertext_archive_tree,\n\
                           &self.da_ciphertext_tree, &self.action_tree, &self.poseidon2_v8_tree,),\n\
                         |(meta_tree, height_tree, block_tree, commitment_tree, nullifier_tree,\n\
                           bridge_inbound_tree, ciphertext_index_tree, ciphertext_archive_tree,\n\
                           da_ciphertext_tree, action_tree, poseidon2_v8_tree,)| {\n\
                             self::verified_helper(\n\
                                 poseidon2_v8_tree,\n\
                                 poseidon2_v8_reorg.as_ref().map(|(_, v8_plan)| v8_plan),\n\
                                 suffix_manifest,\n\
                                 \"native canonical suffix reorg manifest\",\n\
                             )?;\n\
                             Ok(())\n\
                         },\n\
                     )\n\
                         .map_err(|_| ())?;\n\
                     Ok(())\n\
                 }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_shared_sled_transaction_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("synchronously executed transaction helper is propagated twice");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn blueprint_rejects_transaction_closure_when_outer_result_is_ignored() {
        let root = test_root("ignored-outer-transaction-result");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_shared_sled_test_module_root(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "extern crate sled as __hegemon_pinned_sled;\n\
             fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             struct Tree;\n\
             struct Node { meta_tree: Tree, height_tree: Tree, block_tree: Tree,\n\
                           commitment_tree: Tree, nullifier_tree: Tree, bridge_inbound_tree: Tree,\n\
                           ciphertext_index_tree: Tree, ciphertext_archive_tree: Tree,\n\
                           da_ciphertext_tree: Tree, action_tree: Tree, poseidon2_v8_tree: Tree }\n\
             impl Node {\n\
                 fn import_mined_block(&self) -> Result<(), ()> {\n\
                     let _ignored = self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                         &(&self.meta_tree, &self.height_tree, &self.block_tree,\n\
                           &self.commitment_tree, &self.nullifier_tree, &self.bridge_inbound_tree,\n\
                           &self.ciphertext_index_tree, &self.ciphertext_archive_tree,\n\
                           &self.da_ciphertext_tree, &self.action_tree, &self.poseidon2_v8_tree),\n\
                         |(meta_tree, height_tree, block_tree, commitment_tree, nullifier_tree,\n\
                           bridge_inbound_tree, ciphertext_index_tree, ciphertext_archive_tree,\n\
                           da_ciphertext_tree, action_tree, poseidon2_v8_tree,)| {\n\
                             verified_helper(\n\
                                 poseidon2_v8_tree,\n\
                                 poseidon2_v8_reorg.map(|(_, v8_plan)| v8_plan),\n\
                                 suffix_manifest,\n\
                                 \"native canonical suffix reorg manifest\",\n\
                             )?;\n\
                             Ok(())\n\
                         },\n\
                     );\n\
                     Ok(())\n\
                 }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_shared_sled_transaction_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("ignored transaction result must not satisfy propagation");
        assert!(
            err.to_string().contains(
                "does not call verified_helper with propagated shared sled transaction result"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_transaction_closure_when_inner_result_is_ignored() {
        let root = test_root("ignored-inner-transaction-helper-result");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_shared_sled_test_module_root(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "extern crate sled as __hegemon_pinned_sled;\n\
             fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             struct Tree;\n\
             struct Node { meta_tree: Tree, height_tree: Tree, block_tree: Tree,\n\
                           commitment_tree: Tree, nullifier_tree: Tree, bridge_inbound_tree: Tree,\n\
                           ciphertext_index_tree: Tree, ciphertext_archive_tree: Tree,\n\
                           da_ciphertext_tree: Tree, action_tree: Tree, poseidon2_v8_tree: Tree }\n\
             impl Node {\n\
                 fn import_mined_block(&self) -> Result<(), ()> {\n\
                     self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                         &(&self.meta_tree, &self.height_tree, &self.block_tree,\n\
                           &self.commitment_tree, &self.nullifier_tree, &self.bridge_inbound_tree,\n\
                           &self.ciphertext_index_tree, &self.ciphertext_archive_tree,\n\
                           &self.da_ciphertext_tree, &self.action_tree, &self.poseidon2_v8_tree),\n\
                         |(meta_tree, height_tree, block_tree, commitment_tree, nullifier_tree,\n\
                           bridge_inbound_tree, ciphertext_index_tree, ciphertext_archive_tree,\n\
                           da_ciphertext_tree, action_tree, poseidon2_v8_tree,)| {\n\
                             let _ignored = verified_helper(\n\
                                 poseidon2_v8_tree,\n\
                                 poseidon2_v8_reorg.map(|(_, v8_plan)| v8_plan),\n\
                                 suffix_manifest,\n\
                                 \"native canonical suffix reorg manifest\",\n\
                             );\n\
                             Ok(())\n\
                         },\n\
                     )\n\
                         .map_err(|_| ())?;\n\
                     Ok(())\n\
                 }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_shared_sled_transaction_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("ignored inner helper result must not satisfy propagation");
        assert!(
            err.to_string().contains(
                "does not call verified_helper with propagated shared sled transaction result"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_nested_deferred_helper_inside_transaction_closure() {
        let root = test_root("nested-deferred-helper-inside-transaction");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_shared_sled_test_module_root(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "extern crate sled as __hegemon_pinned_sled;\n\
             fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             struct Tree;\n\
             struct Node { meta_tree: Tree, height_tree: Tree, block_tree: Tree,\n\
                           commitment_tree: Tree, nullifier_tree: Tree, bridge_inbound_tree: Tree,\n\
                           ciphertext_index_tree: Tree, ciphertext_archive_tree: Tree,\n\
                           da_ciphertext_tree: Tree, action_tree: Tree, poseidon2_v8_tree: Tree }\n\
             impl Node {\n\
                 fn import_mined_block(&self) -> Result<(), ()> {\n\
                     self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                         &(&self.meta_tree, &self.height_tree, &self.block_tree,\n\
                           &self.commitment_tree, &self.nullifier_tree, &self.bridge_inbound_tree,\n\
                           &self.ciphertext_index_tree, &self.ciphertext_archive_tree,\n\
                           &self.da_ciphertext_tree, &self.action_tree, &self.poseidon2_v8_tree),\n\
                         |(meta_tree, height_tree, block_tree, commitment_tree, nullifier_tree,\n\
                           bridge_inbound_tree, ciphertext_index_tree, ciphertext_archive_tree,\n\
                           da_ciphertext_tree, action_tree, poseidon2_v8_tree,)| {\n\
                             let _deferred = || verified_helper(\n\
                                 poseidon2_v8_tree,\n\
                                 poseidon2_v8_reorg.map(|(_, v8_plan)| v8_plan),\n\
                                 suffix_manifest,\n\
                                 \"native canonical suffix reorg manifest\",\n\
                             )?;\n\
                             Ok(())\n\
                         },\n\
                     ).map_err(|_| ())?;\n\
                     Ok(())\n\
                 }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_shared_sled_transaction_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("nested deferred closure must not become transaction evidence");
        assert!(
            err.to_string().contains(
                "does not call verified_helper with propagated shared sled transaction result"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_transaction_result_recovery() {
        let root = test_root("recovered-transaction-result");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_shared_sled_test_module_root(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "extern crate sled as __hegemon_pinned_sled;\n\
             fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             struct Tree;\n\
             struct Node { meta_tree: Tree, height_tree: Tree, block_tree: Tree,\n\
                           commitment_tree: Tree, nullifier_tree: Tree, bridge_inbound_tree: Tree,\n\
                           ciphertext_index_tree: Tree, ciphertext_archive_tree: Tree,\n\
                           da_ciphertext_tree: Tree, action_tree: Tree, poseidon2_v8_tree: Tree }\n\
             impl Node {\n\
                 fn import_mined_block(&self) -> Result<(), ()> {\n\
                     self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                         &(&self.meta_tree, &self.height_tree, &self.block_tree,\n\
                           &self.commitment_tree, &self.nullifier_tree, &self.bridge_inbound_tree,\n\
                           &self.ciphertext_index_tree, &self.ciphertext_archive_tree,\n\
                           &self.da_ciphertext_tree, &self.action_tree, &self.poseidon2_v8_tree),\n\
                         |(meta_tree, height_tree, block_tree, commitment_tree, nullifier_tree,\n\
                           bridge_inbound_tree, ciphertext_index_tree, ciphertext_archive_tree,\n\
                           da_ciphertext_tree, action_tree, poseidon2_v8_tree,)| {\n\
                             verified_helper(\n\
                                 poseidon2_v8_tree,\n\
                                 poseidon2_v8_reorg.map(|(_, v8_plan)| v8_plan),\n\
                                 suffix_manifest,\n\
                                 \"native canonical suffix reorg manifest\",\n\
                             )?;\n\
                             Ok(())\n\
                         },\n\
                     )\n\
                         .unwrap_or(());\n\
                     Ok(())\n\
                 }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_shared_sled_transaction_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("transaction recovery must not satisfy propagation");
        assert!(
            err.to_string().contains(
                "does not call verified_helper with propagated shared sled transaction result"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_spoofed_transaction_receiver_for_shared_sled_obligation() {
        let root = test_root("spoofed-shared-sled-transaction-receiver");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_shared_sled_test_module_root(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "extern crate sled as __hegemon_pinned_sled;\n\
             fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             fn fake<T>(value: T) -> T { value }\n\
             struct Tree;\n\
             struct Node { meta_tree: Tree, height_tree: Tree, block_tree: Tree,\n\
                           commitment_tree: Tree, nullifier_tree: Tree, bridge_inbound_tree: Tree,\n\
                           ciphertext_index_tree: Tree, ciphertext_archive_tree: Tree,\n\
                           da_ciphertext_tree: Tree, action_tree: Tree, poseidon2_v8_tree: Tree }\n\
             impl Node {\n\
                 fn import_mined_block(&self) -> Result<(), ()> {\n\
                     self::__hegemon_pinned_sled::transaction::Transactional::transaction(\n\
                         &fake((&self.meta_tree, &self.height_tree, &self.block_tree,\n\
                               &self.commitment_tree, &self.nullifier_tree,\n\
                               &self.bridge_inbound_tree, &self.ciphertext_index_tree,\n\
                               &self.ciphertext_archive_tree, &self.da_ciphertext_tree,\n\
                               &self.action_tree, &self.poseidon2_v8_tree)),\n\
                         |(meta_tree, height_tree, block_tree, commitment_tree, nullifier_tree,\n\
                           bridge_inbound_tree, ciphertext_index_tree, ciphertext_archive_tree,\n\
                           da_ciphertext_tree, action_tree, poseidon2_v8_tree,)| {\n\
                             verified_helper(\n\
                                 poseidon2_v8_tree,\n\
                                 poseidon2_v8_reorg.map(|(_, v8_plan)| v8_plan),\n\
                                 suffix_manifest,\n\
                                 \"native canonical suffix reorg manifest\",\n\
                             )?;\n\
                             Ok(())\n\
                         },\n\
                     )\n\
                         .map_err(|_| ())?;\n\
                     Ok(())\n\
                 }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_shared_sled_transaction_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("arbitrary transaction method must not satisfy shared sled obligation");
        assert!(
            err.to_string().contains(
                "does not call verified_helper with propagated shared sled transaction result"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_conditional_helper_inside_shared_sled_transaction() {
        let helper = shared_sled_test_helper_expression();
        let invocation =
            shared_sled_ufcs_test_invocation(&format!("if skip_v8 {{ {helper}?; }}\nOk(())"));
        assert_shared_sled_binding_rejected(
            "conditional-helper-inside-shared-sled-transaction",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_helper_after_write_inside_shared_sled_transaction() {
        let helper = shared_sled_test_helper_expression();
        let invocation =
            shared_sled_ufcs_test_invocation(&format!("legacy_write()?;\n{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "helper-after-write-inside-shared-sled-transaction",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_typed_tree_write_after_shared_sled_helper() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!(
            "{helper}?;\nposeidon2_v8_tree.remove(b\"tip\")?;\nOk(())"
        ));
        assert_shared_sled_binding_rejected(
            "typed-tree-write-after-shared-sled-helper",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_captured_typed_tree_write_after_shared_sled_helper() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!(
            "{helper}?;\nself.poseidon2_v8_tree.remove(b\"tip\")?;\nOk(())"
        ));
        assert_shared_sled_binding_rejected(
            "captured-typed-tree-write-after-shared-sled-helper",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_shared_sled_helper_outside_transaction() {
        let helper = shared_sled_test_helper_expression();
        assert_shared_sled_binding_rejected(
            "shared-sled-helper-outside-transaction",
            &format!("{helper}?;\nOk(())"),
        );
    }

    #[test]
    fn blueprint_rejects_duplicate_shared_sled_transactions() {
        let helper = shared_sled_test_helper_expression();
        let first = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let second = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "duplicate-shared-sled-transactions",
            &format!("{first}{second}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_runtime_conditional_shared_sled_transaction() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "runtime-conditional-shared-sled-transaction",
            &format!("if skip_commit {{ {invocation} }}\nOk(())"),
        );
    }

    #[test]
    fn blueprint_rejects_success_return_before_shared_sled_transaction() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "success-return-before-shared-sled-transaction",
            &format!("if skip_commit {{ return Ok(()); }}\n{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_name_resolved_error_return_before_shared_sled_transaction() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "name-resolved-error-return-before-shared-sled-transaction",
            &format!("if skip_commit {{ return Err(()); }}\n{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_reordered_shared_sled_closure_binding() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())")).replacen(
            "da_ciphertext_tree, action_tree, poseidon2_v8_tree,",
            "da_ciphertext_tree, poseidon2_v8_tree, action_tree,",
            1,
        );
        assert_shared_sled_binding_rejected(
            "reordered-shared-sled-closure-binding",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_wrong_tree_passed_to_shared_sled_helper() {
        let helper =
            shared_sled_test_helper_expression().replacen("poseidon2_v8_tree,", "meta_tree,", 1);
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "wrong-tree-passed-to-shared-sled-helper",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_mismatched_shared_sled_plan_and_manifest_arguments() {
        let helper =
            shared_sled_test_helper_expression().replace("suffix_manifest", "mined_manifest");
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "mismatched-shared-sled-plan-and-manifest-arguments",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_shared_sled_helper_context_expression() {
        let helper = shared_sled_test_helper_expression().replace(
            "\"native canonical suffix reorg manifest\"",
            "{ return Ok(()) }",
        );
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_shared_sled_binding_rejected(
            "shared-sled-helper-context-expression",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_unpinned_root_sled_transaction_path() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())")).replacen(
            "self::__hegemon_pinned_sled::transaction::Transactional::transaction",
            "::sled::transaction::Transactional::transaction",
            1,
        );
        assert_shared_sled_binding_rejected(
            "unpinned-root-sled-transaction-path",
            &format!("{invocation}Ok(())"),
        );
    }

    #[test]
    fn blueprint_rejects_cfg_dead_sled_pin_with_live_fake_module() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = shared_sled_test_node_source(&format!("{invocation}Ok(())")).replacen(
            "extern crate sled as __hegemon_pinned_sled;",
            "#[cfg(any())]\nextern crate sled as __hegemon_pinned_sled;\n\
             mod __hegemon_pinned_sled { pub mod transaction { pub trait Transactional {} } }",
            1,
        );
        assert_shared_sled_source_rejected_with(
            "cfg-dead-sled-pin-with-live-fake-module",
            &source,
            "requires an unconditional top-level external sled pin",
        );
    }

    #[test]
    fn blueprint_rejects_nested_module_sled_pin() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = shared_sled_test_node_source(&format!("{invocation}Ok(())")).replacen(
            "extern crate sled as __hegemon_pinned_sled;",
            "mod dormant { extern crate sled as __hegemon_pinned_sled; }",
            1,
        );
        assert_shared_sled_source_rejected_with(
            "nested-module-sled-pin",
            &source,
            "requires an unconditional top-level external sled pin",
        );
    }

    #[test]
    fn blueprint_rejects_multiline_cfg_dead_sled_pin() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = shared_sled_test_node_source(&format!("{invocation}Ok(())")).replacen(
            "extern crate sled as __hegemon_pinned_sled;",
            "#[cfg(\n    any()\n)]\nextern crate sled as __hegemon_pinned_sled;",
            1,
        );
        assert_shared_sled_source_rejected_with(
            "multiline-cfg-dead-sled-pin",
            &source,
            "requires an unconditional top-level external sled pin",
        );
    }

    #[test]
    fn blueprint_rejects_cfg_dead_shared_sled_source_file() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = format!(
            "#![cfg(any())]\n{}",
            shared_sled_test_node_source(&format!("{invocation}Ok(())"))
        );
        assert_shared_sled_source_rejected_with(
            "cfg-dead-shared-sled-source-file",
            &source,
            "requires an unconditional enclosing Rust source file",
        );
    }

    #[test]
    fn blueprint_rejects_multiline_cfg_dead_shared_sled_source_file() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = format!(
            "#![cfg(\n    any()\n)]\n{}",
            shared_sled_test_node_source(&format!("{invocation}Ok(())"))
        );
        assert_shared_sled_source_rejected_with(
            "multiline-cfg-dead-shared-sled-source-file",
            &source,
            "requires an unconditional enclosing Rust source file",
        );
    }

    #[test]
    fn blueprint_rejects_cfg_attr_dead_shared_sled_source_file() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = format!(
            "#![cfg_attr(not(test), cfg(any()))]\n{}",
            shared_sled_test_node_source(&format!("{invocation}Ok(())"))
        );
        assert_shared_sled_source_rejected_with(
            "cfg-attr-dead-shared-sled-source-file",
            &source,
            "requires an unconditional enclosing Rust source file",
        );
    }

    #[test]
    fn blueprint_rejects_cfg_selected_crate_module_declaration() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_nested_shared_sled_source_rejected_with(
            "cfg-selected-crate-module-declaration",
            &shared_sled_test_node_source(&format!("{invocation}Ok(())")),
            "#[cfg(test)]\nmod native;\n",
            "mod node_impl;\n",
            "requires an attribute-free ordinary external module declaration",
        );
    }

    #[test]
    fn blueprint_rejects_path_selected_crate_module_declaration() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_nested_shared_sled_source_rejected_with(
            "path-selected-crate-module-declaration",
            &shared_sled_test_node_source(&format!("{invocation}Ok(())")),
            "#[path = \"alternate.rs\"]\nmod native;\n",
            "mod node_impl;\n",
            "requires an attribute-free ordinary external module declaration",
        );
    }

    #[test]
    fn blueprint_rejects_cfg_selected_intermediate_module_declaration() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_nested_shared_sled_source_rejected_with(
            "cfg-selected-intermediate-module-declaration",
            &shared_sled_test_node_source(&format!("{invocation}Ok(())")),
            "mod native;\n",
            "#[cfg(any())]\nmod node_impl;\n",
            "requires an attribute-free ordinary external module declaration",
        );
    }

    #[test]
    fn blueprint_rejects_cfg_dead_crate_module_file() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        assert_nested_shared_sled_source_rejected_with(
            "cfg-dead-crate-module-file",
            &shared_sled_test_node_source(&format!("{invocation}Ok(())")),
            "#![cfg(any())]\nmod native;\n",
            "mod node_impl;\n",
            "requires an unconditional enclosing Rust module file",
        );
    }

    #[test]
    fn blueprint_rejects_cfg_dead_enclosing_shared_sled_impl() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = shared_sled_test_node_source(&format!("{invocation}Ok(())")).replacen(
            "impl Node {",
            "#[cfg(any())]\nimpl Node {",
            1,
        );
        assert_shared_sled_source_rejected_with(
            "cfg-dead-enclosing-shared-sled-impl",
            &source,
            "requires an attribute-free top-level inherent impl and method",
        );
    }

    #[test]
    fn blueprint_rejects_cfg_attr_dead_enclosing_shared_sled_impl() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let source = shared_sled_test_node_source(&format!("{invocation}Ok(())")).replacen(
            "impl Node {",
            "#[cfg_attr(not(test), cfg(any()))]\nimpl Node {",
            1,
        );
        assert_shared_sled_source_rejected_with(
            "cfg-attr-dead-enclosing-shared-sled-impl",
            &source,
            "requires an attribute-free top-level inherent impl and method",
        );
    }

    #[test]
    fn blueprint_rejects_shared_sled_symbols_hidden_in_inline_module() {
        let helper = shared_sled_test_helper_expression();
        let invocation = shared_sled_ufcs_test_invocation(&format!("{helper}?;\nOk(())"));
        let nested = shared_sled_test_node_source(&format!("{invocation}Ok(())"));
        let source = format!(
            "extern crate sled as __hegemon_pinned_sled;\nmod hidden {{\n{}\n}}",
            nested.replacen("extern crate sled as __hegemon_pinned_sled;", "", 1)
        );
        assert_shared_sled_source_rejected_with(
            "shared-sled-symbols-hidden-in-inline-module",
            &source,
            "requires one top-level helper with doc-only attributes",
        );
    }

    #[test]
    fn blueprint_accepts_turbofish_propagated_result_implementation_call() {
        let root = test_root("turbofish-propagated-result-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>() {}\n\
             fn import_mined_block() { verified_helper::<PendingAction>()?; }\n\
             struct PendingAction;\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("turbofish propagated result implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_method_call_for_bare_bound_callee() {
        let root = test_root("method-call-bare-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             struct Dummy;\n\
             impl Dummy { fn verified_helper(&self) -> Result<(), ()> { Ok(()) } }\n\
             fn import_mined_block(dummy: Dummy) { dummy.verified_helper()?; }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("method call must not satisfy bare bound callee");
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_rejects_associated_call_for_bare_bound_callee() {
        let root = test_root("associated-call-bare-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             struct Dummy;\n\
             impl Dummy { fn verified_helper() -> Result<(), ()> { Ok(()) } }\n\
             fn import_mined_block() { Dummy::verified_helper()?; }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("associated call must not satisfy bare bound callee");
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_accepts_same_impl_self_call_for_bound_callee() {
        let root = test_root("same-impl-self-call-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "struct Verifier;\n\
             impl Verifier {\n\
                 fn verified_helper(&self) -> Result<(), ()> { Ok(()) }\n\
                 fn import_mined_block(&self) { self.verified_helper()?; }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["Verifier::import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("same-impl self call should satisfy bound callee");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_local_let_shadow_for_bound_callee() {
        let root = test_root("local-let-shadow-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let verified_helper = || Ok(());\n\
                 verified_helper()?;\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("local let shadow must not satisfy binding");
        assert!(
            err.to_string()
                .contains("locally shadows bound callee verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_nested_fn_shadow_for_bound_callee() {
        let root = test_root("nested-fn-shadow-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
                 verified_helper()?;\n\
                 persist_block();\n\
             }\n\
             fn persist_block() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["persist_block"],
                Some("must_propagate_result"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("nested fn shadow must not satisfy ordered binding");
        assert!(
            err.to_string()
                .contains("locally shadows bound callee verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_callable_const_and_static_shadows_for_bound_callee() {
        for (name, declaration) in [
            (
                "local-const-shadow-bound-callee",
                "const verified_helper: fn() -> Result<(), ()> = bypass;",
            ),
            (
                "local-static-shadow-bound-callee",
                "static verified_helper: fn() -> Result<(), ()> = bypass;",
            ),
        ] {
            let root = test_root(name);
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            write_repo_file(
                &root,
                "src/native.rs",
                &format!(
                    "fn verified_helper() -> Result<(), ()> {{ Err(()) }}\n\
                     fn bypass() -> Result<(), ()> {{ Ok(()) }}\n\
                     fn import_mined_block() -> Result<(), ()> {{\n\
                         {declaration}\n\
                         verified_helper()?;\n\
                         persist_block();\n\
                         Ok(())\n\
                     }}\n\
                     fn persist_block() {{}}\n"
                ),
            );
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_dominating_ordered_binding(
                    "verified_helper",
                    &["import_mined_block"],
                    "import_mined_block",
                    &["persist_block"],
                    Some("must_propagate_result"),
                ),
            );

            let err = check_blueprint_file(&blueprint_path, &claims_path)
                .expect_err("callable value-item shadow must not satisfy binding");
            assert!(
                err.to_string()
                    .contains("locally shadows bound callee verified_helper"),
                "{name}: {err:#}"
            );
        }
    }

    #[test]
    fn blueprint_rejects_tuple_struct_constructor_shadow_for_bound_callee() {
        let root = test_root("local-tuple-struct-shadow-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 struct verified_helper();\n\
                 let _constructed = verified_helper();\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("tuple-struct constructor shadow must not satisfy binding");
        assert!(
            err.to_string()
                .contains("locally shadows bound callee verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_closure_parameter_shadow_for_bound_callee() {
        let root = test_root("closure-parameter-shadow-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn expected_supply_after_transition() {}\n\
             fn apply_block() {\n\
                 callbacks().map(|expected_supply_after_transition| expected_supply_after_transition());\n\
             }\n\
             fn callbacks() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("expected_supply_after_transition", &["apply_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("closure parameter shadow must not satisfy binding");
        assert!(
            err.to_string()
                .contains("locally shadows bound callee expected_supply_after_transition"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_caller_parameter_shadow_for_bound_callee() {
        let root = test_root("caller-parameter-shadow-bound-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             fn import_mined_block(verified_helper: impl Fn() -> Result<(), ()>) -> Result<(), ()> {\n\
                 verified_helper()?;\n\
                 Ok(())\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("caller parameter shadow must not satisfy binding");
        assert!(
            err.to_string()
                .contains("locally shadows bound callee verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_uninvoked_closure_without_result_obligation() {
        let root = test_root("uninvoked-closure-no-result-obligation");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let _deferred = || verified_helper();\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("an uninvoked closure must not satisfy an ordinary binding");
        assert!(
            err.to_string().contains("does not call verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_retain_closure_as_binding_evidence() {
        let root = test_root("eager-retain-closure-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper(_value: &u8) -> bool { true }\n\
             fn import_mined_block() {\n\
                 let mut values = vec![1u8];\n\
                 values.retain(|value| verified_helper(value));\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("method-name trust cannot prove that retain invokes its predicate");
        assert!(
            err.to_string().contains("does not call verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_any_closure_as_binding_evidence() {
        let root = test_root("eager-any-closure-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper(_value: &u8) -> bool { true }\n\
             fn import_mined_block(values: &[u8]) -> bool {\n\
                 values.iter().any(|value| verified_helper(value))\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("method-name trust cannot prove that any invokes its predicate");
        assert!(
            err.to_string().contains("does not call verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_bare_any_function_as_eager_closure_spoof() {
        let root = test_root("bare-any-function-eager-closure-spoof");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn any<F>(_predicate: F) {}\n\
             fn import_mined_block() { any(|| verified_helper()); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("a bare same-named function cannot claim eager method semantics");
        assert!(
            err.to_string().contains("does not call verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_eager_method_nested_in_uninvoked_closure() {
        let root = test_root("eager-method-nested-in-uninvoked-closure");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper(_value: &u8) -> bool { true }\n\
             fn import_mined_block(values: &[u8]) {\n\
                 let _deferred = || values.iter().any(|value| verified_helper(value));\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("an eager method inside an uninvoked outer closure remains deferred");
        assert!(
            err.to_string().contains("does not call verified_helper"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_unpolled_async_block_with_propagated_result() {
        let root = test_root("unpolled-async-block-propagated-result");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             async fn import_mined_block() -> Result<(), ()> {\n\
                 let _deferred = async { verified_helper()?; Ok::<(), ()>(()) };\n\
                 Ok(())\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("an unpolled async block must not satisfy a propagated-result binding");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with propagated result"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_call_inside_statically_dead_if_body() {
        let root = test_root("statically-dead-if-body");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> Result<(), ()> { Ok(()) }\n\
             fn import_mined_block() -> Result<(), ()> {\n\
                 if false { verified_helper()?; }\n\
                 Ok(())\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("a statically dead branch must not satisfy a binding");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with propagated result"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_non_call_token_spoofs_for_bound_callee() {
        for (name, spoof) in [
            ("stringify-macro", "stringify!(verified_helper()?);"),
            ("stringify-bracket-macro", "stringify![verified_helper()?];"),
            ("raw-string", "let _text = r#\"verified_helper()?\"#;"),
            (
                "raw-byte-string",
                "let _text = br##\"verified_helper()?\"##;",
            ),
            ("raw-c-string", "let _text = cr\"verified_helper()?\";"),
            (
                "raw-hashed-c-string",
                "let _text = cr##\"verified_helper()?\"##;",
            ),
            ("unicode-prefix-identifier", "alpha_verified_helper()?;"),
            ("unicode-suffix-identifier", "verified_helper_alpha()?;"),
        ] {
            let root = test_root(&format!("non-call-token-spoof-{name}"));
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            let source = if name == "unicode-prefix-identifier" {
                format!(
                    "fn verified_helper() -> Result<(), ()> {{ Ok(()) }}\n\
                     fn alpha_verified_helper() -> Result<(), ()> {{ Ok(()) }}\n\
                     fn import_mined_block() -> Result<(), ()> {{ {spoof} Ok(()) }}\n"
                )
                .replace("alpha_verified_helper", "\u{03b1}verified_helper")
            } else if name == "unicode-suffix-identifier" {
                format!(
                    "fn verified_helper() -> Result<(), ()> {{ Ok(()) }}\n\
                     fn verified_helper_alpha() -> Result<(), ()> {{ Ok(()) }}\n\
                     fn import_mined_block() -> Result<(), ()> {{ {spoof} Ok(()) }}\n"
                )
                .replace("verified_helper_alpha", "verified_helper\u{03b1}")
            } else {
                format!(
                    "fn verified_helper() -> Result<(), ()> {{ Ok(()) }}\n\
                     fn import_mined_block() -> Result<(), ()> {{ {spoof} Ok(()) }}\n"
                )
            };
            write_repo_file(&root, "src/native.rs", &source);
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_result_binding(
                    "verified_helper",
                    &["import_mined_block"],
                    "must_propagate_result",
                ),
            );

            let err = check_blueprint_file(&blueprint_path, &claims_path)
                .expect_err("non-call tokens must not satisfy a propagated-result binding");
            assert!(
                err.to_string()
                    .contains("does not call verified_helper with propagated result"),
                "{name}: {err:#}"
            );
        }
    }

    #[test]
    fn blueprint_accepts_tail_returned_result_implementation_call() {
        let root = test_root("tail-returned-result-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 verified_helper()\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("tail-returned result implementation binding");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn blueprint_accepts_tail_map_err_result_implementation_call() {
        let root = test_root("tail-map-err-result-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn convert(_: ()) -> () {}\n\
             fn import_mined_block() {\n\
                 verified_helper().map_err(convert)\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("tail map_err result implementation binding");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn blueprint_accepts_tail_map_result_implementation_call() {
        let root = test_root("tail-map-result-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 verified_helper().map(|record| record.binding)\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("tail map result implementation binding");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn blueprint_accepts_context_propagated_result_implementation_call() {
        let root = test_root("context-propagated-result-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 verified_helper().with_context(|| \"decode block\")?;\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("context propagated result implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_accepts_explicit_returned_map_err_result_implementation_call() {
        let root = test_root("explicit-returned-map-err-result-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn convert(_: ()) -> () {}\n\
             fn import_mined_block() {\n\
                 return verified_helper().map_err(convert);\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("explicit returned map_err result implementation binding");
        assert_eq!(report.implementation_bindings, 1);
    }

    #[test]
    fn blueprint_rejects_ignored_fallible_implementation_call() {
        let root = test_root("ignored-fallible-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_rejects_tail_result_assigned_to_underscore() {
        let root = test_root("tail-result-assigned-to-underscore");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn convert(_: ()) -> () {}\n\
             fn import_mined_block() {\n\
                 let _ = verified_helper().map_err(convert);\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_rejects_tail_result_chain_with_semicolon() {
        let root = test_root("tail-result-chain-with-semicolon");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn convert(_: ()) -> () {}\n\
             fn import_mined_block() {\n\
                 verified_helper().map_err(convert);\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_rejects_explicit_return_block_with_discarded_result() {
        let root = test_root("explicit-return-block-with-discarded-result");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn convert(_: ()) -> () {}\n\
             fn import_mined_block() {\n\
                 return { verified_helper().map_err(convert); };\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_rejects_nested_tail_result_before_later_work() {
        let root = test_root("nested-tail-result-before-later-work");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn convert(_: ()) -> () {}\n\
             fn mutate() {}\n\
             fn import_mined_block() {\n\
                 {\n\
                     verified_helper().map_err(convert)\n\
                 };\n\
                 mutate();\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_rejects_mixed_checked_and_ignored_fallible_calls() {
        let root = test_root("mixed-fallible-implementation-calls");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper()?; verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_rejects_or_swallow_before_question_mark() {
        let root = test_root("or-swallow-before-question-mark");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 verified_helper().or(Ok(()))?;\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["import_mined_block"],
                "must_propagate_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with propagated result"));
    }

    #[test]
    fn blueprint_accepts_is_err_fail_closed_implementation_call() {
        let root = test_root("is-err-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { if verified_helper().is_err() { return Ok(None); } mutate(); }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("is_err fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_rejects_success_return_as_fail_closed_handling() {
        let root = test_root("success-return-as-fail-closed-handling");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> Result<(), ()> { Err(()) }\n\
             fn import_mined_block() {\n\
                 let accepted = Some(());\n\
                 if verified_helper().is_err() { return Ok(accepted); }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("returning an accepted value is not fail-closed handling");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with fail-closed result handling"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_chained_err_constructor_as_fail_closed_handling() {
        for (name, return_expression) in [
            (
                "chained-err-constructor-return",
                "Err(rejection).unwrap_or(accepted)",
            ),
            (
                "chained-trace-err-constructor-return",
                "(trace, Err(rejection).unwrap_or(Ok(accepted)))",
            ),
        ] {
            let root = test_root(name);
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            write_repo_file(
                &root,
                "src/native.rs",
                &format!(
                    "fn verified_helper() -> Result<(), ()> {{ Err(()) }}\n\
                     fn import_mined_block() {{\n\
                         let trace = Vec::new();\n\
                         let rejection = ();\n\
                         let accepted = Some(());\n\
                         if verified_helper().is_err() {{ return {return_expression}; }}\n\
                         mutate();\n\
                     }}\n\
                     fn mutate() {{}}\n"
                ),
            );
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_dominating_ordered_binding(
                    "verified_helper",
                    &["import_mined_block"],
                    "import_mined_block",
                    &["mutate"],
                    Some("must_check_result_fail_closed"),
                ),
            );

            let err = check_blueprint_file(&blueprint_path, &claims_path)
                .expect_err("a chained Err constructor can recover to success");
            assert!(
                err.to_string()
                    .contains("does not call verified_helper with fail-closed result handling"),
                "{name}: {err:#}"
            );
        }
    }

    #[test]
    fn blueprint_accepts_trace_tuple_err_as_fail_closed_handling() {
        let root = test_root("trace-tuple-err-as-fail-closed-handling");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> Result<(), ()> { Err(()) }\n\
             fn import_mined_block() {\n\
                 let mut trace = Vec::new();\n\
                 let value = match verified_helper() {\n\
                     Ok(value) => value,\n\
                     Err(rejection) => return (trace, Err(rejection)),\n\
                 };\n\
                 mutate(value);\n\
             }\n\
             fn mutate<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("trace plus Err tuple is fail-closed handling");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_rejects_trace_tuple_ok_as_fail_closed_handling() {
        let root = test_root("trace-tuple-ok-as-fail-closed-handling");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> Result<(), ()> { Err(()) }\n\
             fn import_mined_block() {\n\
                 let mut trace = Vec::new();\n\
                 let accepted = Some(());\n\
                 let value = match verified_helper() {\n\
                     Ok(value) => value,\n\
                     Err(_) => return (trace, Ok(accepted)),\n\
                 };\n\
                 mutate(value);\n\
             }\n\
             fn mutate<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("trace plus Ok tuple is not fail-closed handling");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with fail-closed result handling"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_accepts_exact_submit_action_rejection_response() {
        let root = test_root("exact-submit-action-rejection-response");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn submit_action() {\n\
                 let action = match verified_helper() {\n\
                     Ok(action) => action,\n\
                     Err(err) => {\n\
                         return serde_json::json!({\n\
                             \"success\": false,\n\
                             \"tx_hash\": null,\n\
                             \"error\": err.to_string(),\n\
                         });\n\
                     }\n\
                 };\n\
                 mutate(action);\n\
             }\n\
             fn mutate<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["submit_action"],
                "submit_action",
                &["mutate"],
                Some("must_return_submit_action_rejection"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("exact submit-action rejection implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_rejects_bare_submit_action_json_macro() {
        let root = test_root("bare-submit-action-json-macro");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn submit_action() {\n\
                 let action = match verified_helper() {\n\
                     Ok(action) => action,\n\
                     Err(err) => {\n\
                         macro_rules! json { ($($tt:tt)*) => { forged_success() }; }\n\
                         return json!({\"success\": false, \"tx_hash\": null, \"error\": err.to_string()});\n\
                     }\n\
                 };\n\
                 mutate(action);\n\
             }\n\
             fn forged_success() {}\n\
             fn mutate<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["submit_action"],
                "submit_action",
                &["mutate"],
                Some("must_return_submit_action_rejection"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("bare or locally shadowed json macro must fail closed");
        assert!(
            err.to_string().contains(
                "does not call verified_helper with an exact submit-action rejection response"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_success_shaped_submit_action_rejection_response() {
        for (name, fields) in [
            (
                "submit-action-rejection-success-true",
                "\"success\": true, \"tx_hash\": null, \"error\": err.to_string()",
            ),
            (
                "submit-action-rejection-duplicate-success",
                "\"success\": false, \"tx_hash\": null, \"error\": err.to_string(), \"success\": true",
            ),
            (
                "submit-action-rejection-nonnull-hash",
                "\"success\": false, \"tx_hash\": action_hash, \"error\": err.to_string()",
            ),
        ] {
            let root = test_root(name);
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            write_repo_file(
                &root,
                "src/native.rs",
                &format!(
                    "fn verified_helper() {{}}\n\
                     fn submit_action() {{\n\
                         let action = match verified_helper() {{\n\
                             Ok(action) => action,\n\
                             Err(err) => {{ return serde_json::json!({{{fields}}}); }}\n\
                         }};\n\
                         mutate(action);\n\
                     }}\n\
                     fn mutate<T>(_value: T) {{}}\n"
                ),
            );
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_dominating_ordered_binding(
                    "verified_helper",
                    &["submit_action"],
                    "submit_action",
                    &["mutate"],
                    Some("must_return_submit_action_rejection"),
                ),
            );

            let err = check_blueprint_file(&blueprint_path, &claims_path)
                .expect_err("success-shaped submit-action response must reject");
            assert!(
                err.to_string()
                    .contains("does not call verified_helper with an exact submit-action rejection response"),
                "{name}: {err:#}"
            );
        }
    }

    #[test]
    fn blueprint_accepts_if_let_err_fail_closed_implementation_call() {
        let root = test_root("if-let-err-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn verify_artifacts() { if let Err(rejection) = verified_helper() { return Err(rejection); } mutate(); }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["verify_artifacts"],
                "verify_artifacts",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("if-let Err fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_accepts_match_err_fail_closed_implementation_call() {
        let root = test_root("match-err-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn verify_artifacts() {\n\
                 match verified_helper() {\n\
                     Ok(()) => (),\n\
                     Err(rejection) => return Err(rejection),\n\
                 }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["verify_artifacts"],
                "verify_artifacts",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("match Err fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_accepts_bound_match_err_fail_closed_implementation_call() {
        let root = test_root("bound-match-err-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn verify_artifacts() {\n\
                 let result = match verified_helper() {\n\
                     Ok(value) => value,\n\
                     Err(rejection) => return Err(rejection),\n\
                 };\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["verify_artifacts"],
                "verify_artifacts",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("bound match Err fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_accepts_bound_result_is_err_fail_closed_implementation_call() {
        let root = test_root("bound-result-is-err-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let result = verified_helper();\n\
                 if result.is_err() { return Ok(None); }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("bound result is_err fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_accepts_bound_result_if_let_err_fail_closed_implementation_call() {
        let root = test_root("bound-result-if-let-err-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let helper_result = verified_helper();\n\
                 if let Err(rejection) = helper_result { return Err(rejection); }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("bound result if-let Err fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_accepts_bound_result_match_err_fail_closed_implementation_call() {
        let root = test_root("bound-result-match-err-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let helper_result = verified_helper();\n\
                 match helper_result {\n\
                     Ok(()) => {},\n\
                     Err(Recoverable) => return Ok(None),\n\
                     Err(Fatal) => return Err(()),\n\
                 }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("bound result match Err fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_rejects_bound_result_match_with_non_returning_err_arm() {
        let root = test_root("bound-result-match-with-non-returning-err-arm");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let helper_result = verified_helper();\n\
                 match helper_result {\n\
                     Ok(()) => {},\n\
                     Err(Recoverable) => warn(),\n\
                     Err(Fatal) => return Err(()),\n\
                 }\n\
                 mutate();\n\
             }\n\
             fn warn() {}\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_conditional_return_only_fail_closed_branch() {
        let root = test_root("conditional-return-only-fail-closed-branch");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 if verified_helper().is_err() {\n\
                     if should_abort() { return Err(()); }\n\
                 }\n\
                 mutate();\n\
             }\n\
             fn should_abort() {}\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_conditional_return_only_match_err_arm() {
        let root = test_root("conditional-return-only-match-err-arm");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn verify_artifacts() {\n\
                 match verified_helper() {\n\
                     Ok(()) => (),\n\
                     Err(rejection) => {\n\
                         if should_abort() { return Err(rejection); }\n\
                     },\n\
                 }\n\
                 mutate();\n\
             }\n\
             fn should_abort() {}\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["verify_artifacts"],
                "verify_artifacts",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_accepts_loop_skip_fail_closed_if_let_err() {
        let root = test_root("loop-skip-fail-closed-if-let-err");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     if let Err(rejection) = verified_helper() { warn(rejection); continue; }\n\
                     accept(item);\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("loop-skip fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_accepts_loop_drop_branch_with_match_then_continue() {
        let root = test_root("loop-drop-branch-with-match-then-continue");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for key in keys() {\n\
                     if let Err(rejection) = verified_helper() {\n\
                         match rejection { _ => warn(), }\n\
                         stale_keys_push(key);\n\
                         continue;\n\
                     }\n\
                     entries_insert(key);\n\
                 }\n\
             }\n\
             fn keys() {}\n\
             fn warn() {}\n\
             fn stale_keys_push<T>(_key: T) {}\n\
             fn entries_insert<T>(_key: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["entries_insert"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("loop drop branch with match then continue");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_accepts_loop_skip_fail_closed_match_err() {
        let root = test_root("loop-skip-fail-closed-match-err");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     let entry = match verified_helper() {\n\
                         Ok(entry) => entry,\n\
                         Err(rejection) => { warn(rejection); continue; }\n\
                     };\n\
                     accept(entry);\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("match Err loop-skip fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_match_err_loop_skip_without_continue() {
        let root = test_root("match-err-loop-skip-without-continue");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     let entry = match verified_helper() {\n\
                         Ok(entry) => entry,\n\
                         Err(rejection) => { warn(rejection); fallback() }\n\
                     };\n\
                     accept(entry);\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn fallback() {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("match Err without continue must not satisfy loop-skip obligation");
        assert!(
            err.to_string()
                .contains("with loop-skip fail-closed result handling"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_match_wildcard_before_err_loop_skip() {
        let root = test_root("match-wildcard-before-err-loop-skip");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     let entry = match verified_helper() {\n\
                         _ => fallback(),\n\
                         Err(rejection) => { warn(rejection); continue; }\n\
                     };\n\
                     accept(entry);\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn fallback() {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("wildcard before Err must not satisfy loop-skip obligation");
        assert!(
            err.to_string()
                .contains("with loop-skip fail-closed result handling"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_accepts_sync_response_continue_branch() {
        let root = test_root("sync-response-continue-branch");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "enum Message { Response(Vec<u8>), Other }\n\
             fn verified_helper() {}\n\
             fn native_sync_loop() {\n\
                 while let Some(msg) = recv() {\n\
                     match msg {\n\
                         Message::Response(mut blocks) => {\n\
                             if let Err(rejection) = verified_helper() { warn(rejection); continue; }\n\
                             blocks_sort_by_key(&mut blocks);\n\
                         }\n\
                         Message::Other => {}\n\
                     }\n\
                 }\n\
             }\n\
             fn recv() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn blocks_sort_by_key<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["native_sync_loop"],
                "native_sync_loop",
                &["blocks_sort_by_key"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("sync response continue branch");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_accepts_plain_loop_sync_response_continue_branch() {
        let root = test_root("plain-loop-sync-response-continue-branch");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "enum Message { Response(Vec<u8>), Other }\n\
             fn verified_helper() {}\n\
             fn native_sync_loop() {\n\
                 loop {\n\
                     match recv() {\n\
                         Message::Response(mut blocks) => {\n\
                             if let Err(rejection) = verified_helper() { warn(rejection); continue; }\n\
                             blocks_sort_by_key(&mut blocks);\n\
                         }\n\
                         Message::Other => {}\n\
                     }\n\
                 }\n\
             }\n\
             fn recv() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn blocks_sort_by_key<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["native_sync_loop"],
                "native_sync_loop",
                &["blocks_sort_by_key"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("plain loop sync response continue branch");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_loop_skip_branch_without_continue() {
        let root = test_root("loop-skip-branch-without-continue");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     if let Err(rejection) = verified_helper() { warn(rejection); }\n\
                     accept(item);\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with loop-skip fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_nested_continue_only() {
        let root = test_root("nested-continue-only");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     if let Err(_) = verified_helper() { if cond() { continue; } }\n\
                     accept(item);\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn cond() {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with loop-skip fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_break_or_return_for_loop_skip_obligation() {
        for (case, branch) in [
            ("break", "if let Err(_) = verified_helper() { break; }"),
            ("return", "if let Err(_) = verified_helper() { return; }"),
        ] {
            let root = test_root(&format!("{case}-for-loop-skip-obligation"));
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            write_repo_file(
                &root,
                "src/native.rs",
                &format!(
                    "fn verified_helper() {{}}\n\
                     fn load_entries() {{\n\
                         for item in items() {{\n\
                             {branch}\n\
                             accept(item);\n\
                         }}\n\
                     }}\n\
                     fn items() {{}}\n\
                     fn accept<T>(_value: T) {{}}\n"
                ),
            );
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_dominating_ordered_binding(
                    "verified_helper",
                    &["load_entries"],
                    "load_entries",
                    &["accept"],
                    Some("must_check_result_loop_skip_fail_closed"),
                ),
            );

            let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
            assert!(err.to_string().contains(
                "does not call verified_helper with loop-skip fail-closed result handling"
            ));
        }
    }

    #[test]
    fn blueprint_rejects_indirect_bound_result_loop_skip() {
        let root = test_root("indirect-bound-result-loop-skip");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     let result = verified_helper();\n\
                     if result.is_err() { continue; }\n\
                     accept(item);\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with loop-skip fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_loop_skip_admission_after_ordered_successor() {
        let root = test_root("loop-skip-admission-after-ordered-successor");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn load_entries() {\n\
                 for item in items() {\n\
                     accept(item);\n\
                     if let Err(rejection) = verified_helper() { warn(rejection); continue; }\n\
                 }\n\
             }\n\
             fn items() {}\n\
             fn warn<T>(_value: T) {}\n\
             fn accept<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["load_entries"],
                "load_entries",
                &["accept"],
                Some("must_check_result_loop_skip_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not dominate verified_helper before accept"));
    }

    #[test]
    fn blueprint_accepts_filter_ok_result_block_predicate() {
        let root = test_root("filter-ok-result-block-predicate");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 let selected = actions().into_iter().filter(|action| {\n\
                     let input = build_input(action);\n\
                     verified_helper(input).is_ok()\n\
                 }).collect();\n\
                 use_selected(selected);\n\
             }\n\
             fn actions() {}\n\
             fn build_input<T>(_value: T) {}\n\
             fn use_selected<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("filter Ok-result block predicate implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_accepts_mineable_preselection_count_dataflow() {
        let root = test_root("mineable-preselection-count-dataflow");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn evaluate_native_mineable_action_admission<T>(_value: T) -> Result<(), ()> { Ok(()) }\n\
             fn select_mineable_actions(state: &State) {\n\
                 let actions = ordered_pending_actions(state);\n\
                 let transfer_count = actions.iter().filter(|action| is_transfer(action)).filter(|action| {\n\
                     let input = native_mineable_action_admission_input(state, action, None);\n\
                     evaluate_native_mineable_action_admission(input).is_ok()\n\
                 }).count();\n\
                 let selected_candidate_hash = if transfer_count == 0 {\n\
                     None\n\
                 } else {\n\
                     actions.iter().find(|action| {\n\
                         is_candidate(action) && action.candidate_artifact.as_ref().is_some_and(|artifact| artifact.tx_count as usize == transfer_count)\n\
                     }).map(|action| action.tx_hash)\n\
                 };\n\
                 actions.into_iter().filter(|action| {\n\
                     let input = native_mineable_action_admission_input(state, action, selected_candidate_hash);\n\
                     evaluate_native_mineable_action_admission(input).is_ok()\n\
                 }).collect()\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "evaluate_native_mineable_action_admission",
                &["select_mineable_actions"],
                "must_contribute_to_mineable_selection",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("mineable preselection count must feed final admitted selection");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_disconnected_mineable_preselection_count() {
        let root = test_root("disconnected-mineable-preselection-count");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn evaluate_native_mineable_action_admission<T>(_value: T) -> Result<(), ()> { Ok(()) }\n\
             fn select_mineable_actions(state: &State) {\n\
                 let actions = ordered_pending_actions(state);\n\
                 let transfer_count = actions.iter().filter(|action| {\n\
                     let input = native_mineable_action_admission_input(state, action, None);\n\
                     evaluate_native_mineable_action_admission(input).is_ok()\n\
                 }).count();\n\
                 let selected_candidate_hash = unchecked_candidate_hash();\n\
                 actions.into_iter().filter(|action| {\n\
                     let input = native_mineable_action_admission_input(state, action, selected_candidate_hash);\n\
                     evaluate_native_mineable_action_admission(input).is_ok()\n\
                 }).collect()\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "evaluate_native_mineable_action_admission",
                &["select_mineable_actions"],
                "must_contribute_to_mineable_selection",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("disconnected mineable preselection count must reject");
        assert!(
            err.to_string().contains(
                "does not call evaluate_native_mineable_action_admission with mineable-selection admission dataflow"
            ),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_shadowed_filtered_result_at_block_sink() {
        let root = test_root("shadowed-filtered-result-at-block-sink");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) -> Result<(), ()> { Ok(()) }\n\
             fn unchecked_actions() -> Vec<u8> { Vec::new() }\n\
             fn select_mineable_actions() {\n\
                 let selected = actions().into_iter().filter(|action| verified_helper(action).is_ok()).collect::<Vec<_>>();\n\
                 let selected = unchecked_actions();\n\
                 selected\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("a shadowed filtered value must not satisfy the selection sink");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with filter Ok-result gating"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_accepts_filter_ok_result_expression_predicate() {
        let root = test_root("filter-ok-result-expression-predicate");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 actions().into_iter().filter(|action| verified_helper(action).is_ok()).collect()\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("filter Ok-result expression predicate implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_bare_filter_function_as_consumed_predicate_spoof() {
        let root = test_root("bare-filter-function-consumed-predicate-spoof");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) -> Result<(), ()> { Ok(()) }\n\
             fn filter<F>(_predicate: F) -> Vec<u8> { Vec::new() }\n\
             fn select_mineable_actions() {\n\
                 let selected = filter(|action| verified_helper(action).is_ok());\n\
                 use_selected(selected);\n\
             }\n\
             fn use_selected<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("a bare same-named function cannot claim Iterator::filter semantics");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with filter Ok-result gating"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_ignored_filter_helper_then_true() {
        let root = test_root("ignored-filter-helper-then-true");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 actions().into_iter().filter(|action| { verified_helper(action); true }).collect();\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_filter_is_err_predicate() {
        let root = test_root("filter-is-err-predicate");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 actions().into_iter().filter(|action| verified_helper(action).is_err()).collect();\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_filter_ok_or_true_predicate() {
        let root = test_root("filter-ok-or-true-predicate");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 actions().into_iter().filter(|action| verified_helper(action).is_ok() || true).collect();\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_filter_ok_side_effect_then_true() {
        let root = test_root("filter-ok-side-effect-then-true");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 actions().into_iter().filter(|action| { verified_helper(action).is_ok(); true }).collect();\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_ok_result_outside_filter() {
        let root = test_root("ok-result-outside-filter");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 verified_helper(input()).is_ok();\n\
                 actions().into_iter().filter(|_| true).collect();\n\
             }\n\
             fn actions() {}\n\
             fn input() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_dead_filter_ok_result_not_used_for_selection() {
        let root = test_root("dead-filter-ok-result-not-used-for-selection");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 let _ = actions().into_iter().filter(|action| verified_helper(action).is_ok()).collect();\n\
                 actions().to_vec()\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_dead_named_filter_ok_result_not_used_for_selection() {
        let root = test_root("dead-named-filter-ok-result-not-used-for-selection");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 let selected = actions().into_iter().filter(|action| verified_helper(action).is_ok()).collect::<Vec<_>>();\n\
                 actions().to_vec()\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_underscore_named_filter_ok_result() {
        let root = test_root("underscore-named-filter-ok-result");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 let _selected = actions().into_iter().filter(|action| verified_helper(action).is_ok()).collect::<Vec<_>>();\n\
                 _selected\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_filter_ok_result_mapped_to_unchecked_values() {
        let root = test_root("filter-ok-result-mapped-to-unchecked-values");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 actions().into_iter().filter(|action| verified_helper(action).is_ok()).map(|_| unchecked_action()).collect::<Vec<_>>()\n\
             }\n\
             fn actions() {}\n\
             fn unchecked_action() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_rejects_unconsumed_filter_ok_iterator() {
        let root = test_root("unconsumed-filter-ok-iterator");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper<T>(_value: T) {}\n\
             fn select_mineable_actions() {\n\
                 let selected = actions().into_iter().filter(|action| verified_helper(action).is_ok());\n\
                 selected\n\
             }\n\
             fn actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["select_mineable_actions"],
                "must_filter_ok_result",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with filter Ok-result gating"));
    }

    #[test]
    fn blueprint_accepts_returned_tuple_result_component() {
        let root = test_root("returned-tuple-result-component");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn wrapper() {\n\
                 let (_trace, result) = verified_helper();\n\
                 result\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["wrapper"],
                "must_return_tuple_result_component",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("returned tuple result component implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_tuple_result_component_not_tail_returned() {
        let root = test_root("tuple-result-component-not-tail-returned");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn wrapper() {\n\
                 let (_trace, result) = verified_helper();\n\
                 log(&result);\n\
                 result\n\
             }\n\
             fn log<T>(_value: &T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["wrapper"],
                "must_return_tuple_result_component",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with returned tuple result component"));
    }

    #[test]
    fn blueprint_rejects_tuple_helper_returning_ok_anyway() {
        let root = test_root("tuple-helper-returning-ok-anyway");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn wrapper() {\n\
                 let (_trace, _result) = verified_helper();\n\
                 Ok(())\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["wrapper"],
                "must_return_tuple_result_component",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with returned tuple result component"));
    }

    #[test]
    fn blueprint_rejects_returned_wrong_tuple_component() {
        let root = test_root("returned-wrong-tuple-component");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn wrapper() {\n\
                 let (trace, result) = verified_helper();\n\
                 trace\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "verified_helper",
                &["wrapper"],
                "must_return_tuple_result_component",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with returned tuple result component"));
    }

    #[test]
    fn blueprint_accepts_work_template_supply_fallback() {
        let root = test_root("work-template-supply-fallback");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn advance_native_supply_digest() {}\n\
             fn prepare_work() {\n\
                 let supply_digest = match advance_native_supply_digest() {\n\
                     Ok(supply_digest) => supply_digest,\n\
                     Err(err) => {\n\
                         warn(err);\n\
                         actions = Vec::new();\n\
                         state_root = best.state_root;\n\
                         nullifier_root = best.nullifier_root;\n\
                         extrinsics_root = actions_extrinsics_root(&[]);\n\
                         tx_count = 0;\n\
                         best.supply_digest\n\
                     }\n\
                 };\n\
                 native_pow_header_from_parts(supply_digest);\n\
             }\n\
             fn native_pow_header_from_parts<T>(_value: T) {}\n\
             fn warn<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "advance_native_supply_digest",
                &["prepare_work"],
                "must_reset_work_template_on_err",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("work-template supply fallback implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_work_template_supply_fallback_without_action_reset() {
        let root = test_root("work-template-supply-fallback-without-action-reset");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn advance_native_supply_digest() {}\n\
             fn prepare_work() {\n\
                 let supply_digest = match advance_native_supply_digest() {\n\
                     Ok(supply_digest) => supply_digest,\n\
                     Err(_) => {\n\
                         state_root = best.state_root;\n\
                         nullifier_root = best.nullifier_root;\n\
                         extrinsics_root = actions_extrinsics_root(&[]);\n\
                         tx_count = 0;\n\
                         best.supply_digest\n\
                     }\n\
                 };\n\
                 native_pow_header_from_parts(supply_digest);\n\
             }\n\
             fn native_pow_header_from_parts<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "advance_native_supply_digest",
                &["prepare_work"],
                "must_reset_work_template_on_err",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains(
            "does not call advance_native_supply_digest with empty work-template fallback"
        ));
    }

    #[test]
    fn blueprint_rejects_work_template_supply_fallback_with_wrong_tail_digest() {
        let root = test_root("work-template-supply-fallback-with-wrong-tail-digest");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn advance_native_supply_digest() {}\n\
             fn prepare_work() {\n\
                 let supply_digest = match advance_native_supply_digest() {\n\
                     Ok(supply_digest) => supply_digest,\n\
                     Err(_) => {\n\
                         actions = Vec::new();\n\
                         state_root = best.state_root;\n\
                         nullifier_root = best.nullifier_root;\n\
                         extrinsics_root = actions_extrinsics_root(&[]);\n\
                         tx_count = 0;\n\
                         supply_digest\n\
                     }\n\
                 };\n\
                 native_pow_header_from_parts(supply_digest);\n\
             }\n\
             fn native_pow_header_from_parts<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "advance_native_supply_digest",
                &["prepare_work"],
                "must_reset_work_template_on_err",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains(
            "does not call advance_native_supply_digest with empty work-template fallback"
        ));
    }

    #[test]
    fn blueprint_rejects_work_template_supply_fallback_with_extra_match_arm() {
        let root = test_root("work-template-supply-fallback-with-extra-match-arm");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn advance_native_supply_digest() {}\n\
             fn prepare_work() {\n\
                 let supply_digest = match advance_native_supply_digest() {\n\
                     Ok(supply_digest) => supply_digest,\n\
                     Err(_) => {\n\
                         actions = Vec::new();\n\
                         state_root = best.state_root;\n\
                         nullifier_root = best.nullifier_root;\n\
                         extrinsics_root = actions_extrinsics_root(&[]);\n\
                         tx_count = 0;\n\
                         best.supply_digest\n\
                     },\n\
                     _ => best.supply_digest,\n\
                 };\n\
                 native_pow_header_from_parts(supply_digest);\n\
             }\n\
             fn native_pow_header_from_parts<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "advance_native_supply_digest",
                &["prepare_work"],
                "must_reset_work_template_on_err",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains(
            "does not call advance_native_supply_digest with empty work-template fallback"
        ));
    }

    #[test]
    fn blueprint_accepts_expected_native_supply_delta_invalid_match() {
        let root = test_root("expected-native-supply-delta-invalid-match");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn expected_native_supply_from_parts() {}\n\
             fn evaluate_native_block_replay_refinement_with_trace() {\n\
                 let expected_supply = match expected_native_supply_from_parts() {\n\
                     Some(expected_supply) => expected_supply,\n\
                     None => {\n\
                         let rejection = NativeBlockReplayRefinementRejection::SupplyDeltaInvalid;\n\
                         trace.push(format!(\"rejected:{}\", rejection.label()));\n\
                         return (trace, Err(rejection));\n\
                     }\n\
                 };\n\
                 evaluate_native_block_commitment_admission(expected_supply);\n\
             }\n\
             fn evaluate_native_block_commitment_admission<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "expected_native_supply_from_parts",
                &["evaluate_native_block_replay_refinement_with_trace"],
                "must_match_some_or_return_supply_delta_invalid",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("native supply delta invalid match implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_expected_native_supply_delta_invalid_match_without_return() {
        let root = test_root("expected-native-supply-delta-invalid-match-without-return");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn expected_native_supply_from_parts() {}\n\
             fn evaluate_native_block_replay_refinement_with_trace() {\n\
                 let expected_supply = match expected_native_supply_from_parts() {\n\
                     Some(expected_supply) => expected_supply,\n\
                     None => {\n\
                         let rejection = NativeBlockReplayRefinementRejection::SupplyDeltaInvalid;\n\
                         trace.push(format!(\"rejected:{}\", rejection.label()));\n\
                         expected_supply\n\
                     }\n\
                 };\n\
                 evaluate_native_block_commitment_admission(expected_supply);\n\
             }\n\
             fn evaluate_native_block_commitment_admission<T>(_value: T) {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "expected_native_supply_from_parts",
                &["evaluate_native_block_replay_refinement_with_trace"],
                "must_match_some_or_return_supply_delta_invalid",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains(
            "does not call expected_native_supply_from_parts with supply-delta invalid match handling"
        ));
    }

    #[test]
    fn blueprint_accepts_expected_supply_claim_comparison() {
        let root = test_root("expected-supply-claim-comparison");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn expected_supply_after_transition() {}\n\
             fn apply_block() {\n\
                 let Some(expected_supply) =\n\
                     expected_supply_after_transition(parent_node.supply_digest, coinbase)\n\
                 else {\n\
                     return Err(ConsensusError::InvalidCoinbase(\"supply digest underflow\"));\n\
                 };\n\
                 if expected_supply != block.header.supply_digest {\n\
                     return Err(ConsensusError::InvalidHeader(\"supply digest mismatch\"));\n\
                 }\n\
                 evaluate_pow_admission()?;\n\
             }\n\
             fn evaluate_pow_admission() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "expected_supply_after_transition",
                &["apply_block"],
                "must_match_some_and_compare_supply_claim",
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("expected supply claim comparison implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_expected_supply_claim_comparison_against_wrong_field() {
        let root = test_root("expected-supply-claim-comparison-wrong-field");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn expected_supply_after_transition() {}\n\
             fn apply_block() {\n\
                 let Some(expected_supply) = expected_supply_after_transition(parent_node.supply_digest, coinbase) else {\n\
                     return Err(ConsensusError::InvalidCoinbase(\"supply digest underflow\"));\n\
                 };\n\
                 if expected_supply != claimed_supply {\n\
                     return Err(ConsensusError::InvalidHeader(\"supply digest mismatch\"));\n\
                 }\n\
                 evaluate_pow_admission()?;\n\
             }\n\
             fn evaluate_pow_admission() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "expected_supply_after_transition",
                &["apply_block"],
                "must_match_some_and_compare_supply_claim",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains(
            "does not call expected_supply_after_transition with checked supply-claim comparison"
        ));
    }

    #[test]
    fn blueprint_rejects_expected_supply_claim_comparison_without_else_return() {
        let root = test_root("expected-supply-claim-comparison-without-else-return");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn expected_supply_after_transition() {}\n\
             fn apply_block() {\n\
                 let Some(expected_supply) = expected_supply_after_transition(parent_node.supply_digest, coinbase) else {\n\
                     log_underflow();\n\
                 };\n\
                 if expected_supply != block.header.supply_digest {\n\
                     return Err(ConsensusError::InvalidHeader(\"supply digest mismatch\"));\n\
                 }\n\
                 evaluate_pow_admission()?;\n\
             }\n\
             fn evaluate_pow_admission() {}\n\
             fn log_underflow() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_result_binding(
                "expected_supply_after_transition",
                &["apply_block"],
                "must_match_some_and_compare_supply_claim",
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains(
            "does not call expected_supply_after_transition with checked supply-claim comparison"
        ));
    }

    #[test]
    fn blueprint_accepts_bool_false_guard_fail_closed_implementation_call() {
        let root = test_root("bool-false-guard-fail-closed-implementation-call");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> bool { true }\n\
             fn import_mined_block() {\n\
                 if !verified_helper() { return Err(()); }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_guard_false_fail_closed"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("bool false guard fail-closed implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_result_obligations, 1);
    }

    #[test]
    fn blueprint_rejects_non_returning_bool_false_guard() {
        let root = test_root("non-returning-bool-false-guard");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> bool { true }\n\
             fn import_mined_block() {\n\
                 if !verified_helper() { log_error(); }\n\
                 mutate();\n\
             }\n\
             fn log_error() {}\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_guard_false_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed false guard handling"));
    }

    #[test]
    fn blueprint_rejects_conditional_return_only_bool_false_guard() {
        let root = test_root("conditional-return-only-bool-false-guard");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> bool { true }\n\
             fn import_mined_block() {\n\
                 if !verified_helper() {\n\
                     if should_abort() { return Err(()); }\n\
                 }\n\
                 mutate();\n\
             }\n\
             fn should_abort() {}\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_guard_false_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed false guard handling"));
    }

    #[test]
    fn blueprint_rejects_non_negated_bool_guard() {
        let root = test_root("non-negated-bool-guard");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() -> bool { true }\n\
             fn import_mined_block() {\n\
                 if verified_helper() { return Err(()); }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_guard_false_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed false guard handling"));
    }

    #[test]
    fn blueprint_rejects_non_returning_fail_closed_branch() {
        let root = test_root("non-returning-fail-closed-branch");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { if verified_helper().is_err() { log_error(); } mutate(); }\n\
             fn log_error() {}\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_non_returning_match_err_branch() {
        let root = test_root("non-returning-match-err-branch");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn verify_artifacts() {\n\
                 match verified_helper() {\n\
                     Ok(()) => (),\n\
                     Err(rejection) => log_rejection(rejection),\n\
                 }\n\
                 mutate();\n\
             }\n\
             fn log_rejection(_: ()) {}\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["verify_artifacts"],
                "verify_artifacts",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_bound_result_checked_after_mutation() {
        let root = test_root("bound-result-checked-after-mutation");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let result = verified_helper();\n\
                 mutate();\n\
                 if result.is_err() { return Ok(None); }\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_spoofed_bound_result_check() {
        let root = test_root("spoofed-bound-result-check");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let result = verified_helper();\n\
                 if other_result.is_err() { return Ok(None); }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_spoofed_bound_if_let_result_check() {
        let root = test_root("spoofed-bound-if-let-result-check");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 let helper_result = verified_helper();\n\
                 if let Err(rejection) = other_result { return Err(rejection); }\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_rejects_mixed_fail_closed_and_ignored_calls() {
        let root = test_root("mixed-fail-closed-and-ignored-calls");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() {\n\
                 if verified_helper().is_err() { return Ok(None); }\n\
                 verified_helper();\n\
                 mutate();\n\
             }\n\
             fn mutate() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["mutate"],
                Some("must_check_result_fail_closed"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call verified_helper with fail-closed result handling"));
    }

    #[test]
    fn blueprint_accepts_ordered_implementation_binding() {
        let root = test_root("ordered-implementation-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); apply_actions(); persist_block(); }\n\
             fn apply_actions() {}\n\
             fn persist_block() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["apply_actions", "persist_block"],
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("valid ordered implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_constraints, 1);
        assert_eq!(report.implementation_order_edges, 2);
    }

    #[test]
    fn blueprint_accepts_theorem_indexed_order_constraint() {
        let root = test_root("theorem-indexed-order-constraint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_target_order_theorem(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); apply_actions(); }\n\
             fn apply_actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        let mut claims = claims_fixture();
        make_target_lean_theorem_claim(&mut claims, &[TARGET_ORDER_THEOREM]);
        write_json(&claims_path, claims);
        write_json(
            &blueprint_path,
            blueprint_fixture_with_theorem_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["apply_actions"],
                &[TARGET_ORDER_THEOREM],
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("theorem-indexed order constraint");
        assert_eq!(report.implementation_order_constraints, 1);
        assert_eq!(report.implementation_order_edges, 1);
        assert_eq!(report.implementation_theorem_indexed_order_constraints, 1);
        assert_eq!(report.implementation_theorem_indexed_order_edges, 1);
        assert_eq!(report.full_claim_order_constraints, 1);
        assert_eq!(report.full_claim_order_constraint_theorem_refs, 1);
    }

    #[test]
    fn blueprint_policy_rejects_full_claim_order_constraint_count_over_budget() {
        let root = test_root("policy-rejects-full-claim-order-constraint-count");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_target_order_theorem(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); apply_actions(); }\n\
             fn apply_actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        let mut claims = claims_fixture();
        make_target_lean_theorem_claim(&mut claims, &[TARGET_ORDER_THEOREM]);
        write_json(&claims_path, claims);
        let mut blueprint = blueprint_fixture_with_theorem_ordered_binding(
            "verified_helper",
            &["import_mined_block"],
            "import_mined_block",
            &["apply_actions"],
            &[TARGET_ORDER_THEOREM],
        );
        blueprint["policy"]["max_full_claim_order_constraints"] = json!(0);
        write_json(&blueprint_path, blueprint);

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("full-claim order constraint count must respect budget");
        assert!(err.to_string().contains("max_full_claim_order_constraints"));
    }

    #[test]
    fn blueprint_policy_rejects_full_claim_order_theorem_refs_over_budget() {
        let root = test_root("policy-rejects-full-claim-order-theorem-refs");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_target_order_theorem(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); apply_actions(); }\n\
             fn apply_actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        let mut claims = claims_fixture();
        make_target_lean_theorem_claim(
            &mut claims,
            &[TARGET_ORDER_THEOREM, TARGET_ORDER_THEOREM_TWO],
        );
        write_json(&claims_path, claims);
        let mut blueprint = blueprint_fixture_with_theorem_ordered_binding(
            "verified_helper",
            &["import_mined_block"],
            "import_mined_block",
            &["apply_actions"],
            &[TARGET_ORDER_THEOREM_TWO, TARGET_ORDER_THEOREM],
        );
        blueprint["policy"]["max_full_claim_order_constraints"] = json!(1);
        blueprint["policy"]["max_full_claim_order_constraint_theorem_refs"] = json!(1);
        write_json(&blueprint_path, blueprint);

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("full-claim order theorem ref count must respect budget");
        assert!(err
            .to_string()
            .contains("max_full_claim_order_constraint_theorem_refs"));
    }

    #[test]
    fn blueprint_rejects_unknown_theorem_ref_on_order_constraint() {
        let root = test_root("unknown-theorem-indexed-order-constraint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_target_order_theorem(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); apply_actions(); }\n\
             fn apply_actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        let mut claims = claims_fixture();
        make_target_lean_theorem_claim(&mut claims, &[TARGET_ORDER_THEOREM]);
        write_json(&claims_path, claims);
        write_json(
            &blueprint_path,
            blueprint_fixture_with_theorem_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["apply_actions"],
                &["Hegemon.Native.ActionOrder.unknown_order_theorem"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("unknown theorem ref must reject");
        assert!(err.to_string().contains("not listed by claim target.prod"));
    }

    #[test]
    fn blueprint_policy_rejects_unindexed_production_order_constraint() {
        let root = test_root("policy-rejects-unindexed-order-constraint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_target_order_theorem(&root);
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); apply_actions(); }\n\
             fn apply_actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        let mut claims = claims_fixture();
        make_target_lean_theorem_claim(&mut claims, &[TARGET_ORDER_THEOREM]);
        write_json(&claims_path, claims);
        let mut blueprint = blueprint_fixture_with_ordered_binding(
            "verified_helper",
            &["import_mined_block"],
            "import_mined_block",
            &["apply_actions"],
        );
        enable_theorem_index_policy(&mut blueprint);
        let nodes = blueprint["nodes"].as_array_mut().expect("nodes array");
        let target = nodes[1].as_object_mut().expect("target object");
        target.insert(
            "evidence_paths".to_owned(),
            json!(["evidence/target.txt", TARGET_ORDER_THEOREM_PATH]),
        );
        write_json(&blueprint_path, blueprint);

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("unindexed order constraint must reject under policy");
        assert!(err
            .to_string()
            .contains("requires theorem-indexed production order constraints"));
    }

    #[test]
    fn blueprint_accepts_path_qualified_order_successor() {
        let root = test_root("path-qualified-order-successor");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "struct Arc;\n\
             impl Arc { fn new() {} }\n\
             fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); Arc::new(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["Arc::new"],
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("path-qualified ordered successor");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_constraints, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_rejects_path_qualified_successor_spoofed_by_bare_or_other_type() {
        let root = test_root("path-qualified-successor-spoofed-by-bare-or-other-type");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "struct RwLock;\n\
             impl RwLock { fn new() {} }\n\
             fn verified_helper() {}\n\
             fn new() {}\n\
             fn import_mined_block() { verified_helper(); new(); RwLock::new(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["Arc::new"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call required successor Arc::new"));
    }

    #[test]
    fn blueprint_rejects_path_qualified_successor_spoofed_by_longer_path() {
        let root = test_root("path-qualified-successor-spoofed-by-longer-path");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "mod std { pub mod sync { pub struct Arc; impl Arc { pub fn new() {} } } }\n\
             fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); std::sync::Arc::new(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["Arc::new"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call required successor Arc::new"));
    }

    #[test]
    fn blueprint_rejects_receiver_qualified_successor_spoofed_by_other_receiver() {
        let root = test_root("receiver-qualified-successor-spoofed-by-other-receiver");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "struct Importer;\n\
             struct Other;\n\
             impl Other { fn persist_block(&self) {} }\n\
             fn verified_helper() {}\n\
             fn persist_block() {}\n\
             impl Importer {\n\
                 fn import_mined_block(&self, other: Other) {\n\
                     verified_helper();\n\
                     persist_block();\n\
                     other.persist_block();\n\
                 }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["Importer::import_mined_block"],
                "Importer::import_mined_block",
                &["self.persist_block"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not call required successor self.persist_block"));
    }

    #[test]
    fn blueprint_accepts_bare_order_successor_legacy_method_call_matching() {
        let root = test_root("bare-order-successor-legacy-method-call-matching");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "struct Importer;\n\
             fn verified_helper() {}\n\
             impl Importer {\n\
                 fn import_mined_block(&self) { verified_helper(); self.persist_block(); }\n\
                 fn persist_block(&self) {}\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["Importer::import_mined_block"],
                "Importer::import_mined_block",
                &["persist_block"],
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("bare ordered successor keeps legacy matching");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_constraints, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_rejects_late_ordered_implementation_binding() {
        let root = test_root("late-ordered-implementation-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_mined_block() { apply_actions(); verified_helper(); }\n\
             fn apply_actions() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_ordered_binding(
                "verified_helper",
                &["import_mined_block"],
                "import_mined_block",
                &["apply_actions"],
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("calls verified_helper after apply_actions"));
    }

    #[test]
    fn blueprint_accepts_dominating_ordered_implementation_binding() {
        let root = test_root("dominating-ordered-implementation-binding");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_announced_block() { verified_helper()?; if cond() { persist_block()?; } }\n\
             fn cond() {}\n\
             fn persist_block() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_announced_block"],
                "import_announced_block",
                &["persist_block"],
                Some("must_propagate_result"),
            ),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path)
            .expect("valid dominating ordered implementation binding");
        assert_eq!(report.implementation_bindings, 1);
        assert_eq!(report.implementation_order_constraints, 1);
        assert_eq!(report.implementation_order_edges, 1);
    }

    #[test]
    fn blueprint_rejects_guard_call_inside_uninvoked_expression_closure() {
        let root = test_root("expression-closure-dominance-bypass");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn publish_state() {}\n\
             fn import_announced_block() {\n\
                 let deferred = || Ok::<_, ()>(verified_helper()?);\n\
                 publish_state();\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_announced_block"],
                "import_announced_block",
                &["publish_state"],
                Some("must_propagate_result"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("an uninvoked expression closure must not satisfy a guard binding");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with propagated result"),
            "{err:#}"
        );
    }

    #[test]
    fn blueprint_rejects_guard_call_inside_uninvoked_block_closure() {
        let root = test_root("block-closure-dominance-bypass");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn publish_state() {}\n\
             fn import_announced_block() {\n\
                 let deferred = || { verified_helper()?; Ok::<_, ()>(()) };\n\
                 publish_state();\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_announced_block"],
                "import_announced_block",
                &["publish_state"],
                Some("must_propagate_result"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path)
            .expect_err("an uninvoked block closure must not satisfy a guard binding");
        assert!(
            err.to_string()
                .contains("does not call verified_helper with propagated result"),
            "{err:#}"
        );
    }

    #[test]
    fn rust_closure_spans_cover_adversarial_guard_wrappers() {
        for (name, source) in [
            (
                "moved-zero-argument",
                "let deferred = move || verified_helper()?; publish_state();",
            ),
            (
                "nested-or-pattern",
                "let deferred = |value @ (Some(_) | None)| verified_helper()?; publish_state();",
            ),
            (
                "explicit-return-type",
                "let deferred = || -> Result<(), ()> { verified_helper()?; Ok(()) }; publish_state();",
            ),
            (
                "else-expression",
                "let deferred = if flag { || Ok::<_, ()>(()) } else || verified_helper()?; publish_state();",
            ),
            (
                "async-closure",
                "let deferred = async || verified_helper().await; publish_state();",
            ),
        ] {
            let calls = rust_call_sites(source, "verified_helper");
            assert_eq!(calls.len(), 1, "{name}: expected one helper call");
            let closures = rust_closure_body_spans(source);
            assert!(
                rust_call_is_inside_closure(&calls[0], &closures),
                "{name}: closure-contained helper call escaped detection"
            );
        }
    }

    #[test]
    fn rust_closure_spans_do_not_treat_logical_or_rhs_as_closure() {
        let source = "let accepted = left() || verified_helper(); publish_state();";
        let calls = rust_call_sites(source, "verified_helper");
        assert_eq!(calls.len(), 1);
        assert!(!rust_call_is_inside_closure(
            &calls[0],
            &rust_closure_body_spans(source)
        ));
    }

    #[test]
    fn blueprint_rejects_short_circuit_rhs_as_dominating_guard() {
        for (name, expression) in [
            ("or", "true || (verified_helper()?, true).1"),
            ("and", "false && (verified_helper()?, true).1"),
        ] {
            let root = test_root(&format!("short-circuit-{name}-dominance-bypass"));
            write_repo_file(&root, "evidence/support.txt", "support");
            write_repo_file(&root, "evidence/target.txt", "target");
            write_repo_file(
                &root,
                "src/native.rs",
                &format!(
                    "fn verified_helper() -> Result<(), ()> {{ Ok(()) }}\n\
                     fn publish_state() {{}}\n\
                     fn import_announced_block() -> Result<(), ()> {{\n\
                         let _accepted = {expression};\n\
                         publish_state();\n\
                         Ok(())\n\
                     }}\n"
                ),
            );
            let claims_path = root.join("claims.json");
            let blueprint_path = root.join("blueprint.json");
            write_json(&claims_path, claims_fixture());
            write_json(
                &blueprint_path,
                blueprint_fixture_with_dominating_ordered_binding(
                    "verified_helper",
                    &["import_announced_block"],
                    "import_announced_block",
                    &["publish_state"],
                    Some("must_propagate_result"),
                ),
            );

            let err = check_blueprint_file(&blueprint_path, &claims_path)
                .expect_err("a short-circuited helper call must not satisfy a guard binding");
            assert!(
                err.to_string()
                    .contains("does not call verified_helper with propagated result"),
                "{name}: {err:#}"
            );
        }
    }

    #[test]
    fn blueprint_rejects_sibling_branch_implementation_order_false_positive() {
        let root = test_root("sibling-branch-implementation-order");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             fn import_announced_block() { if cond() { verified_helper()?; } else { persist_block()?; } }\n\
             fn cond() {}\n\
             fn persist_block() {}\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_dominating_ordered_binding(
                "verified_helper",
                &["import_announced_block"],
                "import_announced_block",
                &["persist_block"],
                Some("must_propagate_result"),
            ),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("does not dominate verified_helper before persist_block"));
    }

    #[test]
    fn blueprint_rejects_test_only_implementation_callee() {
        let root = test_root("test-only-implementation-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "#[cfg(test)]\n\
             fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("callee verified_helper is missing from non-test Rust code"));
    }

    #[test]
    fn blueprint_rejects_cfg_feature_implementation_callee() {
        let root = test_root("cfg-feature-implementation-callee");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "#[cfg(feature = \"formal-test-helper\")]\n\
             fn verified_helper() {}\n\
             fn import_mined_block() { verified_helper(); }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("callee verified_helper is missing from non-test Rust code"));
    }

    #[test]
    fn blueprint_rejects_test_only_implementation_caller() {
        let root = test_root("test-only-implementation-caller");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        write_repo_file(
            &root,
            "src/native.rs",
            "fn verified_helper() {}\n\
             #[cfg(test)]\n\
             mod tests {\n\
                 fn import_mined_block() { verified_helper(); }\n\
             }\n",
        );
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture_with_binding("verified_helper", &["import_mined_block"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("caller import_mined_block is missing from non-test Rust code"));
    }

    #[test]
    fn claims_accept_named_lean_theorem_evidence() {
        let root = test_root("lean-theorem-claim");
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Transaction/Balance.lean",
            "namespace Hegemon.Transaction\n\
             theorem balance_rule_accepts : True := by\n\
               trivial\n\
             end Hegemon.Transaction\n",
        );
        let claims_path = root.join("claims.json");
        write_json(
            &claims_path,
            lean_claims_fixture(
                &["formal/lean/Hegemon/Transaction/Balance.lean"],
                &["Hegemon.Transaction.balance_rule_accepts"],
            ),
        );

        let report = check_claims_file(&claims_path).expect("named theorem evidence accepted");
        assert_eq!(report.claims, 1);
        assert_eq!(report.lean_theorem_claims, 1);
        assert_eq!(report.named_lean_theorems, 1);
    }

    #[test]
    fn claims_reject_generator_only_lean_evidence() {
        let root = test_root("lean-generator-only-claim");
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Transaction/GenerateVectors.lean",
            "theorem generated_case : True := by\n  trivial\n",
        );
        let claims_path = root.join("claims.json");
        write_json(
            &claims_path,
            lean_claims_fixture(
                &["formal/lean/Hegemon/Transaction/GenerateVectors.lean"],
                &["Hegemon.Transaction.generated_case"],
            ),
        );

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(err.to_string().contains("non-generator Lean evidence"));
    }

    #[test]
    fn claims_reject_lean_evidence_without_theorem() {
        let root = test_root("lean-no-theorem-claim");
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Transaction/Balance.lean",
            "def balanceRuleAccepts : Bool := true\n",
        );
        let claims_path = root.join("claims.json");
        write_json(
            &claims_path,
            lean_claims_fixture(
                &["formal/lean/Hegemon/Transaction/Balance.lean"],
                &["Hegemon.Transaction.balanceRuleAccepts"],
            ),
        );

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(err.to_string().contains("named theorem declaration"));
    }

    #[test]
    fn claims_reject_theorem_name_in_line_comment() {
        let root = test_root("lean-line-comment-theorem-claim");
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Transaction/Balance.lean",
            "namespace Hegemon.Transaction\n\
             -- theorem spoofed_rule : True := by\n\
             --   trivial\n\
             theorem real_rule : True := by\n\
               trivial\n\
             end Hegemon.Transaction\n",
        );
        let claims_path = root.join("claims.json");
        write_json(
            &claims_path,
            lean_claims_fixture(
                &["formal/lean/Hegemon/Transaction/Balance.lean"],
                &["Hegemon.Transaction.spoofed_rule"],
            ),
        );

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(err.to_string().contains("is not declared"));
    }

    #[test]
    fn claims_reject_theorem_name_in_block_comment() {
        let root = test_root("lean-block-comment-theorem-claim");
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Transaction/Balance.lean",
            "namespace Hegemon.Transaction\n\
             /-\n\
             theorem spoofed_rule : True := by\n\
               trivial\n\
             /-\n\
             theorem nested_spoofed_rule : True := by\n\
               trivial\n\
             -/\n\
             -/\n\
             theorem real_rule : True := by\n\
               trivial\n\
             end Hegemon.Transaction\n",
        );
        let claims_path = root.join("claims.json");
        write_json(
            &claims_path,
            lean_claims_fixture(
                &["formal/lean/Hegemon/Transaction/Balance.lean"],
                &["Hegemon.Transaction.nested_spoofed_rule"],
            ),
        );

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(err.to_string().contains("is not declared"));
    }

    #[test]
    fn claims_reject_unlisted_lean_theorem() {
        let root = test_root("lean-unlisted-theorem-claim");
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Transaction/Balance.lean",
            "namespace Hegemon.Transaction\n\
             theorem balance_rule_accepts : True := by\n\
               trivial\n\
             end Hegemon.Transaction\n",
        );
        let claims_path = root.join("claims.json");
        write_json(
            &claims_path,
            lean_claims_fixture(
                &["formal/lean/Hegemon/Transaction/Balance.lean"],
                &["Hegemon.Transaction.other_rule"],
            ),
        );

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(err.to_string().contains("is not declared"));
    }

    #[test]
    fn claims_reject_missing_lean_theorem_list() {
        let root = test_root("lean-missing-theorem-list-claim");
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Transaction/Balance.lean",
            "namespace Hegemon.Transaction\n\
             theorem balance_rule_accepts : True := by\n\
               trivial\n\
             end Hegemon.Transaction\n",
        );
        let claims_path = root.join("claims.json");
        write_json(
            &claims_path,
            lean_claims_fixture(&["formal/lean/Hegemon/Transaction/Balance.lean"], &[]),
        );

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(err.to_string().contains("explicit lean_theorems"));
    }

    #[test]
    fn claims_reject_lean_theorems_on_non_lean_claims() {
        let root = test_root("non-lean-theorem-list-claim");
        write_repo_file(&root, "evidence/support.txt", "support");
        let claims_path = root.join("claims.json");
        let mut claims = claims_fixture();
        claims["claims"][0]["lean_theorems"] = json!(["Hegemon.Transaction.fake"]);
        claims["claims"].as_array_mut().expect("claims array").pop();
        write_json(&claims_path, claims);

        let err = check_claims_file(&claims_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("only valid for lean_theorem claims"));
    }

    fn test_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hegemon-formal-core-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join(".git")).expect("create .git");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("write Cargo.toml");
        write_repo_file(
            &root,
            "scripts/hegemon_formal_core/Cargo.toml",
            "[package]\nname = \"test-formal-core\"\nversion = \"0.0.0\"\n",
        );
        write_repo_file(
            &root,
            "scripts/hegemon_formal_core/Cargo.lock",
            "# test checker lock\n",
        );
        write_repo_file(
            &root,
            "scripts/hegemon_formal_core/src/lib.rs",
            "// test governance checker\n",
        );
        write_repo_file(
            &root,
            "scripts/hegemon_formal_core/src/main.rs",
            "fn main() {}\n",
        );
        write_repo_file(
            &root,
            "scripts/check_formal_core.sh",
            "#!/usr/bin/env bash\n",
        );
        write_repo_file(
            &root,
            "scripts/test_formal_gate_cli_args.sh",
            "#!/usr/bin/env bash\n",
        );
        write_repo_file(
            &root,
            "protocol/kernel/src/manifest.rs",
            "// test kernel manifest policy\n",
        );
        write_repo_file(
            &root,
            "protocol/versioning/src/lib.rs",
            "// test protocol version policy\n",
        );
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Native/AtomicCommitManifestAdmission.lean",
            "-- test atomic manifest policy\n",
        );
        write_repo_file(
            &root,
            "formal/lean/Hegemon/Native/GenerateAtomicCommitManifestAdmissionVectors.lean",
            "-- test atomic manifest vectors\n",
        );
        write_repo_file(
            &root,
            "node/src/native/mod.rs",
            "// test native module policy\n",
        );
        write_repo_file(
            &root,
            "node/src/native/block_flow.rs",
            "// test native block policy\n",
        );
        write_repo_file(
            &root,
            "node/src/native/node_impl.rs",
            "// test native atomic commit policy\n",
        );
        write_repo_file(
            &root,
            "node/src/native/poseidon2_v8_state.rs",
            "// test native V8 state policy\n",
        );
        root
    }

    fn write_repo_file(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("test path has parent"))
            .expect("create parent");
        std::fs::write(path, contents).expect("write test file");
    }

    fn refresh_blueprint_review_digests(root: &Path, value: &mut Value) {
        let Some(nodes) = value.get_mut("nodes").and_then(Value::as_array_mut) else {
            return;
        };
        for node in nodes {
            let digest = match serde_json::from_value::<BlueprintNode>(node.clone()) {
                Ok(node) => blueprint_node_content_blake3(root, &node)
                    .expect("hash typed blueprint fixture node"),
                Err(_) => reviewable_node_value_blake3(node.clone())
                    .expect("hash malformed blueprint fixture node"),
            };
            if let Some(review) = node.get_mut("target_review").and_then(Value::as_object_mut) {
                review.insert("content_blake3".to_owned(), json!(digest));
            }
        }
    }

    fn refresh_governance_policy_input_digest(root: &Path, path: &Path, value: &mut Value) {
        let evidence_field = if value.get("governance_gate_evidence").is_some() {
            "governance_gate_evidence"
        } else if value.get("acceptance_gates").is_some() {
            "acceptance_gates"
        } else {
            return;
        };
        let relative = path
            .strip_prefix(root)
            .expect("test policy path is inside repository")
            .to_str()
            .expect("test policy path is UTF-8");
        let digest =
            governance_policy_inputs_blake3_for_value(root, relative, evidence_field, value)
                .expect("hash test governance policy inputs");
        let Some(gates) = value.get_mut(evidence_field).and_then(Value::as_array_mut) else {
            return;
        };
        for gate in gates {
            if let Some(gate) = gate.as_object_mut() {
                gate.insert("policy_inputs_blake3".to_owned(), json!(digest));
            }
        }
    }

    fn write_json(path: &Path, mut value: Value) {
        let root = repository_root_from(path);
        refresh_blueprint_review_digests(&root, &mut value);
        refresh_governance_policy_input_digest(&root, path, &mut value);
        write_json_without_review_refresh(path, value);
    }

    fn write_json_without_review_refresh(path: &Path, value: Value) {
        std::fs::write(
            path,
            serde_json::to_string_pretty(&value).expect("serialize json"),
        )
        .expect("write json");
    }

    fn write_system_model_gate_evidence(root: &Path) {
        for category in REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES {
            write_repo_file(
                root,
                &format!("evidence/system-model-{category}.txt"),
                category,
            );
        }
    }

    fn write_active_goal_progress_evidence(root: &Path) {
        write_repo_file(root, "config/.keep", "");
        write_repo_file(root, "DESIGN.md", "design");
        write_repo_file(root, "METHODS.md", "methods");
        write_repo_file(
            root,
            ".agent/RESIDUAL_ASSUMPTION_CLOSURE_EXECPLAN.md",
            "plan",
        );
        write_repo_file(
            root,
            "scripts/check_formal_core.sh",
            "#!/usr/bin/env bash\n",
        );
        write_repo_file(
            root,
            "formal/lean/TestEvidence.lean",
            "namespace Hegemon\nnamespace TestEvidence\n-- theorem comment_spoof : True := by trivial\ndef theoremNameString := \"\"\"\ntheorem string_spoof : True := by trivial\n\"\"\"\nprivate theorem private_spoof : True := by trivial\ntheorem test_closed_track : True := by trivial\ntheorem unrelated_closed_track : True := by trivial\nend TestEvidence\nend Hegemon\n",
        );
        write_json(
            &root.join("config/formal-security-claims.json"),
            active_goal_claims_fixture(),
        );
    }

    fn conditional_authority_fixture() -> Value {
        json!({
            "kind": "conditional_lean",
            "production_authorized": false,
            "shipped_rust_verifier_refinement_proved": false,
            "qrom_failure_bound_composed": false,
            "deployed_hash_instantiation_loss_bounded": false,
            "concrete_pq_security_bits": null,
            "required_assumptions": ["test conditional assumption"]
        })
    }

    fn conditional_smallwood_authority_fixture() -> Value {
        json!({
            "kind": "conditional_lean",
            "production_authorized": false,
            "shipped_rust_verifier_refinement_proved": false,
            "qrom_failure_bound_composed": false,
            "deployed_hash_instantiation_loss_bounded": false,
            "concrete_pq_security_bits": null,
            "required_assumptions": CONDITIONAL_SMALLWOOD_ASSUMPTIONS
        })
    }

    fn governance_gate_evidence_fixture() -> Value {
        let report = json!({
            "passed": true,
            "test_filter": "governance_",
            "tests_failed": 0,
            "tests_passed": REQUIRED_GOVERNANCE_TEST_COUNT
        });
        let report_blake3 = executed_gate_report_blake3(&report).expect("hash test gate report");
        json!({
            "id": REQUIRED_GOVERNANCE_GATE_ID,
            "evidence_kind": "executed_command",
            "command": REQUIRED_GOVERNANCE_GATE_COMMAND,
            "status": "passed",
            "exit_code": 0,
            "executed_at": "2026-08-17T20:34:05Z",
            "policy_inputs_blake3": "0000000000000000000000000000000000000000000000000000000000000000",
            "report": report,
            "report_blake3": report_blake3
        })
    }

    fn claim_baseline_fixture(ids: &[&str]) -> Value {
        json!({
            "baseline_id": "test-formal-security-claims-v1",
            "baseline_claim_count": ids.len(),
            "baseline_claim_ids_blake3": claim_id_set_blake3(ids.iter().copied()),
            "tombstones": []
        })
    }

    fn active_goal_claims_fixture() -> Value {
        json!({
            "schema_version": CLAIMS_SCHEMA_VERSION,
            "generated_for_branch": "codex/superneo-formal-verification",
            "claim_baseline": claim_baseline_fixture(&[CONDITIONAL_SMALLWOOD_CLAIM_ID]),
            "governance_gate_evidence": [governance_gate_evidence_fixture()],
            "claims": [
                {
                    "id": CONDITIONAL_SMALLWOOD_CLAIM_ID,
                    "component": "test closure",
                    "claim_class": "lean_theorem",
                    "summary": "This conditional theorem does not establish production authority: the exact-map-to-canonical-semantic bridge is an explicit assumption, and no deployed 128-bit guarantee follows.",
                    "status": "research_only",
                    "proof_model": "conditional_lean_reduction_with_explicit_knowledge_soundness_semantic_refinement_and_poseidon_assumptions",
                    "production_eligible": false,
                    "authority": conditional_smallwood_authority_fixture(),
                    "lean_theorems": ["Hegemon.TestEvidence.test_closed_track"],
                    "assumptions": ["test assumption"],
                    "evidence_paths": ["formal/lean/TestEvidence.lean"],
                    "gates": ["test gate"],
                    "residual_risks": [{
                        "id": "test-residual",
                        "description": "test residual",
                        "status": "open",
                        "tracking": "formal/lean/TestEvidence.lean"
                    }]
                }
            ]
        })
    }

    fn active_goal_progress_fixture() -> Value {
        let required_properties: Vec<Value> = REQUIRED_HIGHEST_STANDARD_PROPERTIES
            .iter()
            .map(|(id, weight)| {
                json!({
                    "id": id,
                    "weight": weight,
                    "target_completion_percent": 100.0
                })
            })
            .collect();
        json!({
            "schema_version": ACTIVE_GOAL_SCHEMA_VERSION,
            "generated_for_branch": "codex/superneo-formal-verification",
            "goal_thread_id": "019e6319-afca-7233-988d-63f8830fbc7a",
            "goal_status_when_measured": "paused",
            "measurement_timestamp": "2026-06-19T08:09:02Z",
            "formal_source_tree_blake3": "0000000000000000000000000000000000000000000000000000000000000000",
            "objective": "On branch codex/superneo-formal-verification, execute all remaining highest-standard Lean formal verification work for Hegemon and maintain checked-in theorem matrix and living ExecPlans with completion percentage.",
            "objective_must_contain": [
                "codex/superneo-formal-verification",
                "highest-standard Lean formal verification",
                "completion percentage"
            ],
            "source_matrix_path": "config/highest-standard-formal-verification-matrix.json",
            "measurement_method": "Recompute the weighted average of highest-standard matrix property completion percentages and require exact property, weight, evidence, and explicit-assumption agreement.",
            "overall_completion_percent": 50.0,
            "weighted_completion_percent": 100.0,
            "total_property_count": REQUIRED_HIGHEST_STANDARD_PROPERTIES.len(),
            "completed_property_count": REQUIRED_HIGHEST_STANDARD_PROPERTIES.len(),
            "total_weight": 100,
            "external_assumption_boundary": "100% means complete under the matrix method with explicit named cryptographic and system-model assumptions, not assumption-free primitive security.",
            "claim_authority": {
                "claim_id": CONDITIONAL_SMALLWOOD_CLAIM_ID,
                "authority": conditional_smallwood_authority_fixture()
            },
            "acceptance_gates": [governance_gate_evidence_fixture()],
            "evidence_paths": [
                "config/highest-standard-formal-verification-matrix.json",
                ".agent/RESIDUAL_ASSUMPTION_CLOSURE_EXECPLAN.md",
                "scripts/check_formal_core.sh",
                "DESIGN.md",
                "METHODS.md"
            ],
            "required_properties": required_properties
        })
    }

    fn highest_standard_matrix_fixture() -> Value {
        let properties: Vec<Value> = REQUIRED_HIGHEST_STANDARD_PROPERTIES
            .iter()
            .map(|(id, weight)| {
                json!({
                    "id": id,
                    "weight": weight,
                    "completion_percent": 100.0,
                    "current_evidence": ["formal evidence"],
                    "missing_work": [],
                    "remaining_work": [],
                    "explicit_external_assumptions": ["named assumption"]
                })
            })
            .collect();
        json!({
            "schema_version": 1,
            "branch": "codex/superneo-formal-verification",
            "goal": "Highest-standard Lean formal verification for Hegemon.",
            "completion_method": "Weighted average of property completion percentages.",
            "overall_completion_percent": 50.0,
            "formal_surface_coverage_percent": 100.0,
            "mechanized_assumption_closure": {
                "measurement_method": "Count explicit mechanized tracks independently from formal surface coverage.",
                "total_tracks": 2,
                "closed_tracks": 1,
                "closure_percent": 50.0,
                "tracks": [
                    {
                        "id": "test.closed-track",
                        "status": "closed",
                        "evidence_paths": ["formal/lean/TestEvidence.lean"],
                        "lean_theorems": ["Hegemon.TestEvidence.test_closed_track"],
                        "remaining_work": []
                    },
                    {
                        "id": "test.open-track",
                        "status": "open",
                        "evidence_paths": ["formal/lean/TestEvidence.lean"],
                        "lean_theorems": [],
                        "remaining_work": ["discharge test assumption"]
                    }
                ]
            },
            "properties": properties
        })
    }

    fn system_model_gate_fixture() -> Value {
        let gates: Vec<Value> = REQUIRED_SYSTEM_MODEL_GATE_CATEGORIES
            .iter()
            .map(|category| {
                json!({
                    "id": format!("system.{category}"),
                    "category": category,
                    "assumption_class": "system_model",
                    "fail_closed": true,
                    "release_blocking": true,
                    "monitor": format!("{category} monitor"),
                    "enforcement_gate": "formal-core system-model gate",
                    "freshness_sla_hours": 24,
                    "alert_route": "release-owner",
                    "evidence_paths": [
                        format!("evidence/system-model-{category}.txt")
                    ]
                })
            })
            .collect();
        json!({
            "schema_version": 1,
            "generated_for_branch": "codex/superneo-formal-verification",
            "gates": gates
        })
    }

    fn claims_fixture() -> Value {
        json!({
            "schema_version": CLAIMS_SCHEMA_VERSION,
            "generated_for_branch": "codex/formal-blueprint-dag",
            "claim_baseline": claim_baseline_fixture(&["support.dep", "target.prod"]),
            "governance_gate_evidence": [governance_gate_evidence_fixture()],
            "claims": [
                {
                    "id": "support.dep",
                    "component": "support",
                    "claim_class": "dependency_gate",
                    "summary": "Support claim.",
                    "status": "enforced",
                    "proof_model": "ci_gate",
                    "production_eligible": true,
                    "assumptions": ["test assumption"],
                    "evidence_paths": ["evidence/support.txt"],
                    "gates": ["test support gate"],
                    "residual_risks": []
                },
                {
                    "id": "target.prod",
                    "component": "target",
                    "claim_class": "reference_vector",
                    "summary": "Target claim.",
                    "status": "enforced",
                    "proof_model": "reference_vectors",
                    "production_eligible": true,
                    "assumptions": ["test assumption"],
                    "evidence_paths": ["evidence/target.txt"],
                    "gates": ["test target gate"],
                    "residual_risks": []
                }
            ]
        })
    }

    fn lean_claims_fixture(evidence_paths: &[&str], lean_theorems: &[&str]) -> Value {
        json!({
            "schema_version": CLAIMS_SCHEMA_VERSION,
            "generated_for_branch": "codex/formal-blueprint-dag",
            "claim_baseline": claim_baseline_fixture(&["formal.test-claim"]),
            "governance_gate_evidence": [governance_gate_evidence_fixture()],
            "claims": [
                {
                    "id": "formal.test-claim",
                    "component": "test Lean claim",
                    "claim_class": "lean_theorem",
                    "summary": "Test claim.",
                    "status": "enforced",
                    "proof_model": "lean4_theorem_no_sorry_generated_rust_conformance_vectors",
                    "production_eligible": true,
                    "lean_theorems": lean_theorems,
                    "assumptions": ["test assumption"],
                    "evidence_paths": evidence_paths,
                    "gates": ["bash scripts/check_lean_formal.sh"],
                    "residual_risks": []
                }
            ]
        })
    }

    fn write_target_order_theorem(root: &Path) {
        write_repo_file(
            root,
            TARGET_ORDER_THEOREM_PATH,
            "namespace Hegemon.Native.ActionOrder\n\
             theorem order_gate_precedes_mutation : True := by\n\
               trivial\n\
             theorem order_gate_precedes_publication : True := by\n\
               trivial\n\
             end Hegemon.Native.ActionOrder\n",
        );
    }

    fn make_target_lean_theorem_claim(claims: &mut Value, lean_theorems: &[&str]) {
        let target = claims["claims"][1].as_object_mut().expect("target claim");
        target.insert("claim_class".to_owned(), json!("lean_theorem"));
        target.insert(
            "proof_model".to_owned(),
            json!("lean4_theorem_no_sorry_generated_rust_conformance_vectors"),
        );
        target.insert("lean_theorems".to_owned(), json!(lean_theorems));
        target.insert(
            "evidence_paths".to_owned(),
            json!(["evidence/target.txt", TARGET_ORDER_THEOREM_PATH]),
        );
    }

    fn blueprint_fixture(
        target_review_status: &str,
        support_deps: &[&str],
        target_deps: &[&str],
    ) -> Value {
        json!({
            "schema_version": BLUEPRINT_SCHEMA_VERSION,
            "generated_for_branch": "codex/formal-blueprint-dag",
            "governance_gate_evidence": [governance_gate_evidence_fixture()],
            "methodology": {
                "name": "test-blueprint",
                "summary": "Test blueprint.",
                "source_of_record": "claims.json",
                "gate": "test gate"
            },
            "nodes": [
                {
                    "id": "support.dep",
                    "claim_id": "support.dep",
                    "kind": "supporting_claim",
                    "formal_statement": "Support dependency holds.",
                    "informal_argument": "The support evidence exists.",
                    "depends_on": support_deps,
                    "implementation_paths": ["evidence/support.txt"],
                    "evidence_paths": ["evidence/support.txt"],
                    "target_review": {
                        "status": "needs_review",
                        "reviewer": "test",
                        "reviewed_at": "2026-06-06",
                        "notes": "reviewed"
                    },
                    "falsification_cases": [
                        {
                            "id": "support-negative",
                            "description": "support negative",
                            "gate": "test support gate"
                        }
                    ],
                    "scope_boundary": "test boundary"
                },
                {
                    "id": "target.prod",
                    "claim_id": "target.prod",
                    "kind": "target_claim",
                    "formal_statement": "Target production claim holds.",
                    "informal_argument": "The target evidence exists.",
                    "depends_on": target_deps,
                    "implementation_paths": ["evidence/target.txt"],
                    "evidence_paths": ["evidence/target.txt"],
                    "target_review": {
                        "status": target_review_status,
                        "reviewer": "test",
                        "reviewed_at": "2026-06-06",
                        "notes": "reviewed"
                    },
                    "falsification_cases": [
                        {
                            "id": "target-negative",
                            "description": "target negative",
                            "gate": "test target gate"
                        }
                    ],
                    "scope_boundary": "test boundary"
                }
            ]
        })
    }

    fn blueprint_fixture_with_binding(callee: &str, callers: &[&str]) -> Value {
        blueprint_fixture_with_binding_at("src/native.rs", callee, callers)
    }

    fn blueprint_fixture_with_binding_at(path: &str, callee: &str, callers: &[&str]) -> Value {
        let mut blueprint = blueprint_fixture("needs_review", &[], &["support.dep"]);
        let nodes = blueprint["nodes"].as_array_mut().expect("nodes array");
        let target = nodes[1].as_object_mut().expect("target object");
        target.insert(
            "implementation_paths".to_owned(),
            json!(["evidence/target.txt", path]),
        );
        target.insert(
            "implementation_bindings".to_owned(),
            json!([
                {
                    "path": path,
                    "callee": callee,
                    "required_callers": callers
                }
            ]),
        );
        blueprint
    }

    fn blueprint_fixture_with_theorem_ordered_binding(
        callee: &str,
        callers: &[&str],
        ordered_caller: &str,
        successors: &[&str],
        lean_theorems: &[&str],
    ) -> Value {
        let mut blueprint =
            blueprint_fixture_with_ordered_binding(callee, callers, ordered_caller, successors);
        enable_theorem_index_policy(&mut blueprint);
        let nodes = blueprint["nodes"].as_array_mut().expect("nodes array");
        let target = nodes[1].as_object_mut().expect("target object");
        target.insert(
            "evidence_paths".to_owned(),
            json!(["evidence/target.txt", TARGET_ORDER_THEOREM_PATH]),
        );
        let constraint = &mut target["implementation_bindings"][0]["call_order_constraints"][0];
        constraint["lean_theorems"] = json!(lean_theorems);
        blueprint
    }

    fn enable_theorem_index_policy(blueprint: &mut Value) {
        blueprint["policy"] = json!({
            "require_theorem_indexed_order_constraints": true
        });
    }

    fn blueprint_fixture_with_result_binding(
        callee: &str,
        callers: &[&str],
        result_obligation: &str,
    ) -> Value {
        let mut blueprint = blueprint_fixture_with_binding(callee, callers);
        let nodes = blueprint["nodes"].as_array_mut().expect("nodes array");
        let target = nodes[1].as_object_mut().expect("target object");
        target.insert(
            "implementation_bindings".to_owned(),
            json!([
                {
                    "path": "src/native.rs",
                    "callee": callee,
                    "required_callers": callers,
                    "result_obligation": result_obligation
                }
            ]),
        );
        blueprint
    }

    fn blueprint_fixture_with_ordered_binding(
        callee: &str,
        callers: &[&str],
        ordered_caller: &str,
        successors: &[&str],
    ) -> Value {
        let mut blueprint = blueprint_fixture_with_binding(callee, callers);
        let nodes = blueprint["nodes"].as_array_mut().expect("nodes array");
        let target = nodes[1].as_object_mut().expect("target object");
        target.insert(
            "implementation_bindings".to_owned(),
            json!([
                {
                    "path": "src/native.rs",
                    "callee": callee,
                    "required_callers": callers,
                    "call_order_constraints": [
                        {
                            "caller": ordered_caller,
                            "callee_must_precede": successors
                        }
                    ]
                }
            ]),
        );
        blueprint
    }

    fn blueprint_fixture_with_dominating_ordered_binding(
        callee: &str,
        callers: &[&str],
        ordered_caller: &str,
        successors: &[&str],
        result_obligation: Option<&str>,
    ) -> Value {
        let mut blueprint = blueprint_fixture_with_binding(callee, callers);
        let nodes = blueprint["nodes"].as_array_mut().expect("nodes array");
        let target = nodes[1].as_object_mut().expect("target object");
        let mut binding = json!({
            "path": "src/native.rs",
            "callee": callee,
            "required_callers": callers,
            "call_order_constraints": [
                {
                    "caller": ordered_caller,
                    "callee_must_precede": successors,
                    "must_dominate_successors": true
                }
            ]
        });
        if let Some(result_obligation) = result_obligation {
            binding["result_obligation"] = json!(result_obligation);
        }
        target.insert("implementation_bindings".to_owned(), json!([binding]));
        blueprint
    }
}
