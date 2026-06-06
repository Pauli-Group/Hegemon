use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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
];
const CONJECTURAL_MODELS: &[&str] = &["conjectural_research", "heuristic_only"];

#[derive(Debug, Serialize)]
pub struct ClaimsReport {
    pub claims: usize,
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

#[derive(Debug, Deserialize)]
struct ClaimsLedger {
    schema_version: u32,
    generated_for_branch: String,
    claims: Vec<SecurityClaim>,
}

#[derive(Debug, Deserialize)]
struct SecurityClaim {
    id: String,
    component: String,
    claim_class: String,
    summary: String,
    status: String,
    proof_model: String,
    production_eligible: bool,
    assumptions: Vec<String>,
    evidence_paths: Vec<String>,
    gates: Vec<String>,
    residual_risks: Vec<ResidualRisk>,
}

#[derive(Debug, Deserialize)]
struct ResidualRisk {
    id: String,
    description: String,
    status: String,
    tracking: String,
}

#[derive(Debug, Deserialize)]
struct BridgeVectorFile {
    schema_version: u32,
    cases: Vec<BridgeVectorCase>,
}

#[derive(Debug, Deserialize)]
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
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let ledger: ClaimsLedger =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
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
    let mut residual_risks = 0usize;
    let mut production_eligible = 0usize;
    for claim in &ledger.claims {
        validate_claim(&root, claim)?;
        ensure!(ids.insert(&claim.id), "duplicate claim id {}", claim.id);
        residual_risks += claim.residual_risks.len();
        if claim.production_eligible {
            production_eligible += 1;
        }
    }

    Ok(ClaimsReport {
        claims: ledger.claims.len(),
        production_eligible,
        residual_risks,
        passed: true,
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
        "config/formal-security-claims.json",
        "testdata/formal_core_vectors/bridge_messages.json",
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

fn validate_claim(root: &Path, claim: &SecurityClaim) -> Result<()> {
    ensure!(!claim.id.trim().is_empty(), "claim id must be set");
    ensure!(
        claim
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'),
        "claim id {} must use lowercase ascii, digits, '-' or '.'",
        claim.id
    );
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
        let path = root.join(evidence);
        ensure!(
            path.exists(),
            "{} evidence path does not exist: {}",
            claim.id,
            evidence
        );
    }
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
}
