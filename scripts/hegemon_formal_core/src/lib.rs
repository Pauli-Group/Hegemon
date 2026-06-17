use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

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
const TARGET_REVIEW_STATUSES: &[&str] = &["accepted", "needs_review", "blocked"];

#[derive(Debug, Serialize)]
pub struct ClaimsReport {
    pub claims: usize,
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
pub struct BlueprintReport {
    pub nodes: usize,
    pub edges: usize,
    pub production_nodes: usize,
    pub implementation_bindings: usize,
    pub implementation_result_obligations: usize,
    pub implementation_order_constraints: usize,
    pub implementation_order_edges: usize,
    pub implementation_dominance_constraints: usize,
    pub implementation_dominance_edges: usize,
    pub falsification_cases: usize,
    pub passed: bool,
}

#[derive(Debug, Clone)]
struct ClaimProjection {
    production_eligible: bool,
    evidence_paths: BTreeSet<String>,
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
    claims: Vec<SecurityClaim>,
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
    nodes: Vec<BlueprintNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlueprintMethodology {
    name: String,
    summary: String,
    source_of_record: String,
    gate: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlueprintNode {
    id: String,
    claim_id: String,
    kind: String,
    formal_statement: String,
    informal_argument: String,
    depends_on: Vec<String>,
    implementation_paths: Vec<String>,
    #[serde(default)]
    implementation_bindings: Vec<ImplementationBinding>,
    evidence_paths: Vec<String>,
    target_review: TargetReview,
    falsification_cases: Vec<FalsificationCase>,
    scope_boundary: String,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImplementationCallOrderConstraint {
    caller: String,
    callee_must_precede: Vec<String>,
    #[serde(default)]
    result_obligation: Option<String>,
    #[serde(default)]
    must_dominate_successors: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetReview {
    status: String,
    reviewer: String,
    reviewed_at: String,
    notes: String,
}

#[derive(Debug, Deserialize)]
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

pub fn check_claims_file(path: &Path) -> Result<ClaimsReport> {
    let root = repository_root_from(path);
    let ledger = read_claims_ledger(path)?;
    validate_claims_ledger(&root, &ledger)
}

pub fn check_blueprint_file(path: &Path, claims_path: &Path) -> Result<BlueprintReport> {
    let root = repository_root_from(path);
    let claim_index = validate_claims_for_blueprint(&root, claims_path)?;
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let blueprint: FormalBlueprint =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    validate_blueprint(&root, &blueprint, &claim_index)
}

fn read_claims_ledger(path: &Path) -> Result<ClaimsLedger> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn validate_claims_ledger(root: &Path, ledger: &ClaimsLedger) -> Result<ClaimsReport> {
    ensure!(
        ledger.schema_version == 1,
        "unsupported claims schema version"
    );
    ensure!(
        !ledger.generated_for_branch.trim().is_empty(),
        "generated_for_branch must be set"
    );
    ensure!(!ledger.claims.is_empty(), "claims ledger must not be empty");

    let mut ids = BTreeSet::new();
    let mut lean_theorem_claims = 0usize;
    let mut named_lean_theorems = BTreeSet::new();
    let mut residual_risks = 0usize;
    let mut production_eligible = 0usize;
    for claim in &ledger.claims {
        let theorem_names = validate_claim(&root, claim)?;
        ensure!(ids.insert(&claim.id), "duplicate claim id {}", claim.id);
        if claim.claim_class == "lean_theorem" {
            lean_theorem_claims += 1;
        }
        named_lean_theorems.extend(theorem_names);
        residual_risks += claim.residual_risks.len();
        if claim.production_eligible {
            production_eligible += 1;
        }
    }

    Ok(ClaimsReport {
        claims: ledger.claims.len(),
        lean_theorem_claims,
        named_lean_theorems: named_lean_theorems.len(),
        production_eligible,
        residual_risks,
        passed: true,
    })
}

fn validate_claims_for_blueprint(root: &Path, claims_path: &Path) -> Result<ClaimIndex> {
    let ledger = read_claims_ledger(claims_path)?;
    validate_claims_ledger(root, &ledger)?;
    let generated_for_branch = ledger.generated_for_branch.clone();
    let mut claims = BTreeMap::new();
    for claim in ledger.claims {
        claims.insert(
            claim.id,
            ClaimProjection {
                production_eligible: claim.production_eligible,
                evidence_paths: claim.evidence_paths.into_iter().collect(),
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
        "scripts/check_ci_release_gate_policy.py",
        "config/lean-axiom-waivers.json",
        "formal/lean/Hegemon/Privacy/Observer.lean",
        "formal/lean/Hegemon/Privacy/CiphertextPrivacy.lean",
        "formal/lean/Hegemon/Privacy/NativeObserverSurface.lean",
        "formal/lean/Hegemon/Privacy/NativeSidecarObserverSurface.lean",
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
        "formal/lean/Hegemon/Consensus/AggregationV5.lean",
        "formal/lean/Hegemon/Consensus/GenerateAggregationV5Vectors.lean",
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
        "formal/lean/Hegemon/Native/GenerateBlockActionValidationVectors.lean",
        "formal/lean/Hegemon/Native/BridgeActionPayloadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBridgeActionPayloadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/InboundBridgeReceiptAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateInboundBridgeReceiptAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/Risc0ReleaseVerifier.lean",
        "formal/lean/Hegemon/Native/GenerateRisc0ReleaseVerifierVectors.lean",
        "formal/lean/Hegemon/Native/NativeBackendReviewPolicy.lean",
        "formal/lean/Hegemon/Native/GenerateNativeBackendReviewPolicyVectors.lean",
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
        "formal/lean/Hegemon/Native/DaSidecarReplayBinding.lean",
        "formal/lean/Hegemon/Native/RawIngressSidecarReplayRecoverability.lean",
        "formal/lean/Hegemon/Native/CanonicalPublicationRefinement.lean",
        "formal/lean/Hegemon/Native/PendingActionScaleWire.lean",
        "formal/lean/Hegemon/Native/GeneratePendingActionScaleWireVectors.lean",
        "formal/lean/Hegemon/Native/PendingActionByteParserRefinement.lean",
        "formal/lean/Hegemon/Native/PendingActionBytePublicationRefinement.lean",
        "formal/lean/Hegemon/Native/PendingActionByteReplayRowCountBinding.lean",
        "formal/lean/Hegemon/Native/RawIngressPendingActionPublicationRefinement.lean",
        "formal/lean/Hegemon/Native/RawIngressActionHashTxLeafPublication.lean",
        "formal/lean/Hegemon/Native/RawIngressDaSidecarCanonicalPublication.lean",
        "formal/lean/Hegemon/Native/RawIngressFullBytePublicationSurface.lean",
        "formal/lean/Hegemon/Native/MaterializedSidecarDaBlobPublication.lean",
        "formal/lean/Hegemon/Native/MaterializedConsensusDaBlobRefinement.lean",
        "formal/lean/Hegemon/Native/MaterializedTransferNoTheftPublication.lean",
        "formal/lean/Hegemon/Native/NativePublicationRowEquivalence.lean",
        "formal/lean/Hegemon/Native/RawIngressBridgePendingActionPublication.lean",
        "formal/lean/Hegemon/Native/RawIngressTransferNoTheftPublication.lean",
        "formal/lean/Hegemon/Native/SidecarUploadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateSidecarUploadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/SyncAdmission.lean",
        "formal/lean/Hegemon/Native/SyncBlockReplayPublication.lean",
        "formal/lean/Hegemon/Native/GenerateSyncAdmissionVectors.lean",
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
        "formal/lean/Hegemon/Transaction/SmallWoodBalanceBoundary.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodSpendAuthorization.lean",
        "formal/lean/Hegemon/Transaction/SmallWoodTranscriptBinding.lean",
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
    Ok(theorem_names)
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
        let name = if first == "theorem" {
            tokens.get(1).copied()
        } else if first == "private" && tokens.get(1).copied() == Some("theorem") {
            tokens.get(2).copied()
        } else {
            None
        };
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
            stripped.push(current);
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
            stripped.push(current);
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
    blueprint: &FormalBlueprint,
    claim_index: &ClaimIndex,
) -> Result<BlueprintReport> {
    ensure!(
        blueprint.schema_version == 1,
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
    let mut implementation_dominance_constraints = 0usize;
    let mut implementation_dominance_edges = 0usize;
    let mut falsification_cases = 0usize;
    let mut dependents: BTreeMap<String, usize> =
        node_ids.iter().map(|id| (id.clone(), 0usize)).collect();

    for node in &blueprint.nodes {
        let claim = claim_index
            .claims
            .get(&node.claim_id)
            .expect("claim existence checked before node validation");
        validate_blueprint_node(root, node, claim)?;
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
                if constraint.result_obligation.is_some() {
                    implementation_result_obligations += 1;
                }
                if constraint.must_dominate_successors {
                    implementation_dominance_constraints += 1;
                    implementation_dominance_edges += constraint.callee_must_precede.len();
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

    Ok(BlueprintReport {
        nodes: blueprint.nodes.len(),
        edges,
        production_nodes,
        implementation_bindings,
        implementation_result_obligations,
        implementation_order_constraints,
        implementation_order_edges,
        implementation_dominance_constraints,
        implementation_dominance_edges,
        falsification_cases,
        passed: true,
    })
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
    validate_target_review(&node.id, &node.target_review)?;
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
    validate_implementation_bindings(root, node)?;
    validate_falsification_cases(node)?;
    if claim.production_eligible {
        ensure!(
            node.kind != "residual_risk",
            "{} production claim cannot be a residual_risk blueprint node",
            node.id
        );
        ensure!(
            node.target_review.status == "accepted",
            "{} production claim must have accepted target review",
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

fn validate_implementation_bindings(root: &Path, node: &BlueprintNode) -> Result<()> {
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
        }
        validate_rust_implementation_binding(root, &node.id, binding)?;
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

fn validate_rust_implementation_binding(
    root: &Path,
    claim_id: &str,
    binding: &ImplementationBinding,
) -> Result<()> {
    let path = root.join(&binding.path);
    let source = fs::read_to_string(&path)
        .with_context(|| format!("read {} implementation binding source", path.display()))?;
    let sanitized = sanitize_rust_source(&source);
    let test_module_spans = rust_cfg_test_module_spans(&sanitized);
    let functions = rust_function_spans(&sanitized)?;
    let result_obligation = parse_result_obligation(
        claim_id,
        &binding.callee,
        binding.result_obligation.as_deref(),
    )?;
    let non_test_callees = functions
        .iter()
        .filter(|function| {
            function.name == binding.callee
                && !function.is_test_only(&sanitized, &test_module_spans)
        })
        .collect::<Vec<_>>();
    ensure!(
        !non_test_callees.is_empty(),
        "{} implementation binding callee {} is missing from non-test Rust code in {}",
        claim_id,
        binding.callee,
        binding.path
    );
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
            ensure!(
                !rust_body_has_local_shadow_of_callee(body, &binding.callee),
                "{} implementation binding caller {} in {} locally shadows bound callee {}",
                claim_id,
                caller,
                binding.path,
                binding.callee
            );
            let call_sites = rust_bound_callee_call_sites(
                body,
                &binding.callee,
                function,
                &sanitized,
                &test_module_spans,
                &functions,
            );
            ensure!(
                !call_sites.is_empty()
                    && call_sites.iter().all(|call| {
                        call_satisfies_result_obligation(body, call, result_obligation)
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
        let callee_calls = rust_bound_callee_call_sites(
            body,
            &binding.callee,
            function,
            source,
            test_module_spans,
            functions,
        )
        .into_iter()
        .filter(|call| call_satisfies_result_obligation(body, call, constraint_result_obligation))
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
                            .any(|call| rust_call_dominates_successor(body, call, successor_call)),
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
    MustCheckResultFailClosed,
    MustCheckResultLoopSkipFailClosed,
    MustFilterOkResult,
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
        Some("must_check_result_fail_closed") => Ok(ResultObligation::MustCheckResultFailClosed),
        Some("must_check_result_loop_skip_fail_closed") => {
            Ok(ResultObligation::MustCheckResultLoopSkipFailClosed)
        }
        Some("must_filter_ok_result") => Ok(ResultObligation::MustFilterOkResult),
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
        ResultObligation::MustCheckResultFailClosed => " with fail-closed result handling",
        ResultObligation::MustCheckResultLoopSkipFailClosed => {
            " with loop-skip fail-closed result handling"
        }
        ResultObligation::MustFilterOkResult => " with filter Ok-result gating",
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
            body_start,
            body_end: body_end + 1,
        });
        cursor = body_end + 1;
    }
    Ok(functions)
}

fn rust_body_has_local_shadow_of_callee(source: &str, callee: &str) -> bool {
    rust_body_has_let_shadow(source, callee)
        || rust_body_has_for_shadow(source, callee)
        || rust_body_has_nested_fn_shadow(source, callee)
        || rust_body_has_use_shadow(source, callee)
        || rust_body_has_closure_parameter_shadow(source, callee)
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

fn enclosing_impl_type<'a>(
    impl_spans: &'a [RustImplSpan],
    fn_start: usize,
    fn_end: usize,
) -> Option<&'a str> {
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
        let Some((module_name, after_name)) = parse_rust_identifier_after(source, mod_start + 3)
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
        if module_name == "tests"
            && preceding_rust_attrs_contain_non_production_cfg(source, mod_start)
        {
            spans.push((mod_start, body_end + 1));
        }
        cursor = body_end + 1;
    }
    spans
}

fn sanitize_rust_source(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
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
                out.push('\n');
            } else {
                out.push(' ');
            }
            index += 1;
            continue;
        }

        if block_depth > 0 {
            if current == b'/' && next == Some(b'*') {
                block_depth += 1;
                out.push(' ');
                out.push(' ');
                index += 2;
                continue;
            }
            if current == b'*' && next == Some(b'/') {
                block_depth -= 1;
                out.push(' ');
                out.push(' ');
                index += 2;
                continue;
            }
            out.push(if current == b'\n' { '\n' } else { ' ' });
            index += 1;
            continue;
        }

        if in_string || in_char {
            let terminator = if in_string { b'"' } else { b'\'' };
            if current == b'\n' {
                out.push('\n');
                escaped = false;
            } else {
                out.push(' ');
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

        if current == b'/' && next == Some(b'/') {
            in_line_comment = true;
            out.push(' ');
            out.push(' ');
            index += 2;
            continue;
        }
        if current == b'/' && next == Some(b'*') {
            block_depth = 1;
            out.push(' ');
            out.push(' ');
            index += 2;
            continue;
        }
        if current == b'"' {
            in_string = true;
            out.push(' ');
            index += 1;
            continue;
        }
        if current == b'\'' && looks_like_rust_char_literal_start(bytes, index) {
            in_char = true;
            out.push(' ');
            index += 1;
            continue;
        }

        out.push(current as char);
        index += 1;
    }
    out
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
            .map_or(true, |byte| !is_rust_identifier_byte(byte));
    if is_rust_identifier_byte(prev) && !has_byte_literal_prefix {
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
        if !before.is_some_and(is_rust_identifier_byte)
            && !after.is_some_and(is_rust_identifier_byte)
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
        .is_some_and(|byte| is_rust_identifier_byte(*byte))
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
        if before.is_some_and(is_rust_identifier_byte) {
            return None;
        }
        cursor = segment_start;
    }
    let before = cursor
        .checked_sub(1)
        .and_then(|prev| source.as_bytes().get(prev).copied());
    if before.is_some_and(|byte| is_rust_identifier_byte(byte) || byte == b':' || byte == b'.') {
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
        if !before.is_some_and(is_rust_identifier_byte)
            && !after.is_some_and(is_rust_identifier_byte)
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
    call: &RustCallSite,
    obligation: ResultObligation,
) -> bool {
    match obligation {
        ResultObligation::None => true,
        ResultObligation::MustPropagateResult => call_result_is_propagated(source, call),
        ResultObligation::MustCheckResultFailClosed => {
            call_result_is_propagated(source, call) || call_result_is_fail_closed(source, call)
        }
        ResultObligation::MustCheckResultLoopSkipFailClosed => {
            call_result_is_loop_skip_fail_closed(source, call)
        }
        ResultObligation::MustFilterOkResult => call_result_is_filter_ok_predicate(source, call),
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
    let Some(is_ok_end) = call_result_direct_is_ok_end(source, call) else {
        return false;
    };
    let Some(filter_call) = enclosing_filter_call(source, call) else {
        return false;
    };
    let Some(body) = filter_closure_body(source, &filter_call) else {
        return false;
    };
    if call.start < body.start || is_ok_end > body.end {
        return false;
    }

    let expression_start = rust_call_expression_start(source, call.start);
    if expression_start < body.start {
        return false;
    }
    let statement_start = match body.kind {
        RustClosureBodyKind::Block => {
            top_level_statement_start_in_span(source, body.start, call.start)
        }
        RustClosureBodyKind::Expression => body.start,
    };
    if !source[statement_start..expression_start].trim().is_empty() {
        return false;
    }

    skip_ascii_whitespace(source, is_ok_end) == body.end
        && filter_call_result_is_used(source, &filter_call)
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
            filter_call.start < call.start && call.close_paren < filter_call.close_paren
        })
        .min_by_key(|filter_call| filter_call.close_paren - filter_call.start)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustClosureBodyKind {
    Block,
    Expression,
}

#[derive(Debug, Clone, Copy)]
struct RustClosureBody {
    start: usize,
    end: usize,
    kind: RustClosureBodyKind,
}

fn filter_closure_body(source: &str, filter_call: &RustCallSite) -> Option<RustClosureBody> {
    let open_paren = rust_call_open_paren(source, filter_call, "filter")?;
    let first_bar = find_top_level_byte(source, open_paren + 1, filter_call.close_paren, b'|')?;
    let second_bar = find_top_level_byte(source, first_bar + 1, filter_call.close_paren, b'|')?;
    let body_start = skip_ascii_whitespace(source, second_bar + 1);
    if source.as_bytes().get(body_start) == Some(&b'{') {
        let body_end = match_rust_brace(source, body_start).ok()?;
        if body_end > filter_call.close_paren {
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
        end: filter_call.close_paren,
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
            identifier_is_used_later_in_block(source, &binding, statement_end, block_end)
        } else {
            false
        }
    } else {
        true
    }
}

fn filter_chain_terminal_end(source: &str, filter_call: &RustCallSite) -> Option<usize> {
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
            return Some(cursor);
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
    let Some(rest) = prefix.strip_prefix("let ") else {
        return None;
    };
    let Some((lhs, _rhs_prefix)) = rest.split_once('=') else {
        return None;
    };
    let mut lhs = lhs.trim_start();
    if let Some(after_mut) = lhs.strip_prefix("mut ") {
        lhs = after_mut.trim_start();
    }
    let bytes = lhs.as_bytes();
    let Some(first) = bytes.first().copied() else {
        return None;
    };
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

fn identifier_is_used_later_in_block(source: &str, ident: &str, from: usize, to: usize) -> bool {
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
            .is_some_and(|byte| is_rust_identifier_byte(*byte));
        let after_is_ident = bytes
            .get(end)
            .is_some_and(|byte| is_rust_identifier_byte(*byte));
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

fn top_level_block_tail_expression<'a>(
    source: &'a str,
    body_start: usize,
    block_end: usize,
) -> Option<&'a str> {
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
    let prefix = source[prefix_start..block_start].trim_start();
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
    let tail_start = if has_semicolon {
        statement_end + 1
    } else {
        statement_end
    };
    source[tail_start..end].trim().is_empty()
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
    if before.is_some_and(is_rust_identifier_byte) || after.is_some_and(is_rust_identifier_byte) {
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

fn rust_call_dominates_successor(
    source: &str,
    callee: &RustCallSite,
    successor: &RustCallSite,
) -> bool {
    if callee.start >= successor.start {
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

fn validate_target_review(claim_id: &str, review: &TargetReview) -> Result<()> {
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
    ensure!(trimmed.len() % 2 == 0, "hex string has odd length");
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
            return current;
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
    fn blueprint_accepts_valid_claim_dag() {
        let root = test_root("valid-blueprint");
        write_repo_file(&root, "evidence/support.txt", "support");
        write_repo_file(&root, "evidence/target.txt", "target");
        let claims_path = root.join("claims.json");
        let blueprint_path = root.join("blueprint.json");
        write_json(&claims_path, claims_fixture());
        write_json(
            &blueprint_path,
            blueprint_fixture("accepted", &[], &["support.dep"]),
        );

        let report = check_blueprint_file(&blueprint_path, &claims_path).expect("valid blueprint");
        assert_eq!(report.nodes, 2);
        assert_eq!(report.edges, 1);
        assert_eq!(report.production_nodes, 2);
        assert_eq!(report.falsification_cases, 2);
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
            blueprint_fixture("accepted", &["target.prod"], &["support.dep"]),
        );

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn blueprint_requires_accepted_review_for_production_claims() {
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

        let err = check_blueprint_file(&blueprint_path, &claims_path).unwrap_err();
        assert!(err.to_string().contains("accepted target review"));
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
            blueprint_fixture("accepted", &[], &["support.dep"]),
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
        root
    }

    fn write_repo_file(root: &Path, rel: &str, contents: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("test path has parent"))
            .expect("create parent");
        std::fs::write(path, contents).expect("write test file");
    }

    fn write_json(path: &Path, value: Value) {
        std::fs::write(
            path,
            serde_json::to_string_pretty(&value).expect("serialize json"),
        )
        .expect("write json");
    }

    fn claims_fixture() -> Value {
        json!({
            "schema_version": 1,
            "generated_for_branch": "codex/formal-blueprint-dag",
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
            "schema_version": 1,
            "generated_for_branch": "codex/formal-blueprint-dag",
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

    fn blueprint_fixture(
        target_review_status: &str,
        support_deps: &[&str],
        target_deps: &[&str],
    ) -> Value {
        json!({
            "schema_version": 1,
            "generated_for_branch": "codex/formal-blueprint-dag",
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
                        "status": "accepted",
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
        let mut blueprint = blueprint_fixture("accepted", &[], &["support.dep"]);
        let nodes = blueprint["nodes"].as_array_mut().expect("nodes array");
        let target = nodes[1].as_object_mut().expect("target object");
        target.insert(
            "implementation_paths".to_owned(),
            json!(["evidence/target.txt", "src/native.rs"]),
        );
        target.insert(
            "implementation_bindings".to_owned(),
            json!([
                {
                    "path": "src/native.rs",
                    "callee": callee,
                    "required_callers": callers
                }
            ]),
        );
        blueprint
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
