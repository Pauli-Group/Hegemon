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
    evidence_paths: Vec<String>,
    target_review: TargetReview,
    falsification_cases: Vec<FalsificationCase>,
    scope_boundary: String,
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
        "config/lean-axiom-waivers.json",
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
        "formal/lean/Hegemon/Consensus/RecursivePublicReplay.lean",
        "formal/lean/Hegemon/Consensus/GenerateRecursivePublicReplayVectors.lean",
        "formal/lean/Hegemon/Consensus/RecursiveSemanticInputs.lean",
        "formal/lean/Hegemon/Consensus/GenerateRecursiveSemanticInputVectors.lean",
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
        "formal/lean/Hegemon/Native/ActionHashAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateActionHashAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ActionRootTranscript.lean",
        "formal/lean/Hegemon/Native/GenerateActionRootTranscriptVectors.lean",
        "formal/lean/Hegemon/Native/AnnouncedBlockAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateAnnouncedBlockAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ActionScopeAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateActionScopeAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/BridgeActionPayloadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBridgeActionPayloadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/Risc0ReleaseVerifier.lean",
        "formal/lean/Hegemon/Native/GenerateRisc0ReleaseVerifierVectors.lean",
        "formal/lean/Hegemon/Native/TransferActionPayloadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateTransferActionPayloadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/TransferStateAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateTransferStateAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/BlockArtifactBindingAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBlockArtifactBindingAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/BlockCommitmentAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateBlockCommitmentAdmissionVectors.lean",
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
        "formal/lean/Hegemon/Native/MineableActionAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateMineableActionAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/MinedWorkAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateMinedWorkAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/WorkTemplateAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateWorkTemplateAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/RecursiveArtifactContextAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateRecursiveArtifactContextAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/ResourceBudgetAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateResourceBudgetAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/RpcAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateRpcAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/SidecarUploadAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateSidecarUploadAdmissionVectors.lean",
        "formal/lean/Hegemon/Native/SyncAdmission.lean",
        "formal/lean/Hegemon/Native/GenerateSyncAdmissionVectors.lean",
        "formal/lean/Hegemon/Network/SecureChannel.lean",
        "formal/lean/Hegemon/Network/GenerateSecureChannelVectors.lean",
        "formal/lean/Hegemon/Network/PqNoise.lean",
        "formal/lean/Hegemon/Network/GeneratePqNoiseVectors.lean",
        "formal/lean/Hegemon/Release/DependencyAuditPolicy.lean",
        "formal/lean/Hegemon/Release/GenerateDependencyAuditPolicyVectors.lean",
        "formal/lean/Hegemon/Release/PqBinaryPolicy.lean",
        "formal/lean/Hegemon/Release/GeneratePqBinaryPolicyVectors.lean",
        "formal/lean/Hegemon/Native/TxLeafArtifact.lean",
        "formal/lean/Hegemon/Native/GenerateTxLeafArtifactVectors.lean",
        "formal/lean/Hegemon/Native/ReceiptRoot.lean",
        "formal/lean/Hegemon/Native/GenerateReceiptRootVectors.lean",
        "formal/lean/Hegemon/Shielded/Nullifier.lean",
        "formal/lean/Hegemon/Shielded/GenerateVectors.lean",
        "formal/lean/Hegemon/Transaction/Balance.lean",
        "formal/lean/Hegemon/Transaction/GenerateVectors.lean",
        "formal/lean/Hegemon/Transaction/MerklePath.lean",
        "formal/lean/Hegemon/Transaction/GenerateMerkleVectors.lean",
        "formal/lean/Hegemon/Transaction/PublicInputs.lean",
        "formal/lean/Hegemon/Transaction/GeneratePublicInputVectors.lean",
        "formal/lean/Hegemon/Transaction/PublicInputBinding.lean",
        "formal/lean/Hegemon/Transaction/GeneratePublicInputBindingVectors.lean",
        "formal/lean/Hegemon/Transaction/StatementHash.lean",
        "formal/lean/Hegemon/Transaction/GenerateStatementHashVectors.lean",
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
}
