use anyhow::{anyhow, ensure, Context, Result};
use blake3::Hasher;
use p3_goldilocks::Goldilocks;
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use superneo_backend_lattice::{
    CommitmentSecurityModel, LatticeBackend, LatticeCommitment, LeafDigestProof,
    NativeBackendParams, RingElem, RingProfile,
};
use superneo_ccs::{Assignment, Relation, RelationId, ShapeDigest, StatementDigest};
use superneo_core::{Backend, FoldedInstance, LeafArtifact};
use superneo_hegemon::{CanonicalTxValidityReceipt, TxLeafPublicRelation};
use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::bytes48_to_felts;
use transaction_circuit::proof::{
    transaction_public_inputs_digest_from_serialized, SerializedStarkInputs,
    TX_PROOF_DIGEST_DOMAIN, TX_STATEMENT_HASH_DOMAIN,
};
use transaction_circuit::{verify_transaction_proof_bytes_p3, TransactionPublicInputsP3};

const CANONICAL_RECEIPT_WIRE_BYTES: usize = 48 * 4;
const LEAF_ARTIFACT_WIRE_BYTES: usize = 2 + 32 + 32 + 48 + 48 + 48;
const TX_PUBLIC_WIRE_BYTES: usize =
    4 + (MAX_INPUTS * 48) + 4 + (MAX_OUTPUTS * 48) + 4 + (MAX_OUTPUTS * 48) + 48 + 2 + 2;
const MAX_NATIVE_TX_STARK_PROOF_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewVectorBundle {
    pub parameter_fingerprint: String,
    pub native_backend_params: ReviewBackendParams,
    pub native_security_claim: ReviewSecurityClaim,
    pub cases: Vec<ReviewVectorCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewBackendParams {
    pub family_label: String,
    pub spec_label: String,
    pub commitment_scheme_label: String,
    pub challenge_schedule_label: String,
    pub maturity_label: String,
    pub security_bits: u32,
    pub ring_profile: String,
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub challenge_bits: u32,
    pub fold_challenge_count: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_label: String,
    pub decomposition_bits: u32,
    pub opening_randomness_bits: u32,
    #[serde(default = "default_commitment_security_model")]
    pub commitment_security_model: String,
    #[serde(default = "default_commitment_bkmsis_target_bits")]
    pub commitment_bkmsis_target_bits: u32,
    #[serde(default = "default_max_commitment_message_ring_elems")]
    pub max_commitment_message_ring_elems: u32,
    #[serde(default = "default_max_claimed_receipt_root_leaves")]
    pub max_claimed_receipt_root_leaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSecurityClaim {
    pub claimed_security_bits: u32,
    pub transcript_soundness_bits: u32,
    pub opening_hiding_bits: u32,
    #[serde(default)]
    pub commitment_codomain_bits: u32,
    #[serde(default)]
    pub commitment_same_seed_search_bits: u32,
    #[serde(default)]
    pub commitment_random_matrix_bits: u32,
    #[serde(default)]
    pub commitment_problem_dimension: u32,
    #[serde(default)]
    pub commitment_problem_coeff_bound: u32,
    #[serde(default)]
    pub commitment_problem_l2_bound: u32,
    #[serde(default)]
    pub commitment_reduction_loss_bits: u32,
    pub commitment_binding_bits: u32,
    pub composition_loss_bits: u32,
    pub soundness_floor_bits: u32,
    pub assumption_ids: Vec<String>,
    pub review_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewVectorCase {
    pub name: String,
    pub kind: String,
    pub expected_valid: bool,
    pub expected_error_substring: Option<String>,
    pub artifact_hex: String,
    pub tx_context: Option<ReviewTxContext>,
    pub block_context: Option<ReviewBlockContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewReceipt {
    pub statement_hash_hex: String,
    pub proof_digest_hex: String,
    pub public_inputs_digest_hex: String,
    pub verifier_profile_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSerializedStarkInputs {
    pub input_flags: Vec<u8>,
    pub output_flags: Vec<u8>,
    pub fee: u64,
    pub value_balance_sign: u8,
    pub value_balance_magnitude: u64,
    pub merkle_root_hex: String,
    pub balance_slot_asset_ids: Vec<u64>,
    pub stablecoin_enabled: u8,
    pub stablecoin_asset_id: u64,
    pub stablecoin_policy_version: u32,
    pub stablecoin_issuance_sign: u8,
    pub stablecoin_issuance_magnitude: u64,
    pub stablecoin_policy_hash_hex: String,
    pub stablecoin_oracle_commitment_hex: String,
    pub stablecoin_attestation_commitment_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewTxPublicTx {
    pub nullifiers_hex: Vec<String>,
    pub commitments_hex: Vec<String>,
    pub ciphertext_hashes_hex: Vec<String>,
    pub balance_tag_hex: String,
    pub version_circuit: u16,
    pub version_crypto: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewTxContext {
    pub backend_params: ReviewBackendParams,
    pub expected_version: u16,
    pub params_fingerprint_hex: String,
    pub spec_digest_hex: String,
    pub relation_id_hex: String,
    pub shape_digest_hex: String,
    pub statement_digest_hex: String,
    pub receipt: ReviewReceipt,
    pub tx: ReviewTxPublicTx,
    pub stark_public_inputs: ReviewSerializedStarkInputs,
    pub commitment_rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewReceiptLeafContext {
    pub statement_digest_hex: String,
    pub witness_commitment_hex: String,
    pub proof_digest_hex: String,
    pub commitment_rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewBlockContext {
    pub backend_params: ReviewBackendParams,
    pub expected_version: u16,
    pub params_fingerprint_hex: String,
    pub spec_digest_hex: String,
    pub relation_id_hex: String,
    pub shape_digest_hex: String,
    pub root_statement_digest_hex: String,
    pub root_commitment_hex: String,
    pub leaves: Vec<ReviewReceiptLeafContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewVerificationSummary {
    pub bundle_path: String,
    pub case_count: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewCaseResult {
    pub name: String,
    pub expected_valid: bool,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefTxLeafPublicTx {
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    balance_tag: [u8; 48],
    version: VersionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefNativeTxLeafArtifact {
    version: u16,
    params_fingerprint: [u8; 48],
    spec_digest: [u8; 32],
    relation_id: [u8; 32],
    shape_digest: [u8; 32],
    statement_digest: [u8; 48],
    receipt: CanonicalTxValidityReceipt,
    stark_public_inputs: SerializedStarkInputs,
    tx: RefTxLeafPublicTx,
    stark_proof: Vec<u8>,
    commitment: LatticeCommitment,
    leaf: LeafArtifact<LeafDigestProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefReceiptRootLeaf {
    statement_digest: [u8; 48],
    witness_commitment: [u8; 48],
    proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefReceiptRootFoldStep {
    challenges: Vec<u64>,
    parent_statement_digest: [u8; 48],
    parent_commitment: [u8; 48],
    parent_rows: Vec<RingElem>,
    proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefReceiptRootArtifact {
    version: u16,
    params_fingerprint: [u8; 48],
    spec_digest: [u8; 32],
    relation_id: [u8; 32],
    shape_digest: [u8; 32],
    leaves: Vec<RefReceiptRootLeaf>,
    folds: Vec<RefReceiptRootFoldStep>,
    root_statement_digest: [u8; 48],
    root_commitment: [u8; 48],
}

pub fn load_bundle(bundle_path: &Path) -> Result<ReviewVectorBundle> {
    let bytes = fs::read(bundle_path).with_context(|| {
        format!(
            "failed to read review vector bundle {}",
            bundle_path.display()
        )
    })?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse review vector bundle {}",
            bundle_path.display()
        )
    })
}

pub fn verify_bundle_dir(
    bundle_dir: &Path,
) -> Result<(ReviewVerificationSummary, Vec<ReviewCaseResult>)> {
    let bundle_path = bundle_dir.join("bundle.json");
    let bundle = load_bundle(&bundle_path)?;
    let mut results = Vec::with_capacity(bundle.cases.len());
    let mut passed_cases = 0usize;
    for case in &bundle.cases {
        match verify_case(case) {
            Ok(()) if case.expected_valid => {
                passed_cases += 1;
                results.push(ReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: true,
                    passed: true,
                    detail: "accepted".to_owned(),
                });
            }
            Ok(()) => {
                results.push(ReviewCaseResult {
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
                results.push(ReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: false,
                    passed,
                    detail,
                });
            }
            Err(err) => {
                results.push(ReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: true,
                    passed: false,
                    detail: err.to_string(),
                });
            }
        }
    }
    let summary = ReviewVerificationSummary {
        bundle_path: bundle_path.display().to_string(),
        case_count: results.len(),
        passed_cases,
        failed_cases: results.len().saturating_sub(passed_cases),
    };
    Ok((summary, results))
}

pub fn verify_case(case: &ReviewVectorCase) -> Result<()> {
    let artifact_bytes =
        hex::decode(&case.artifact_hex).context("review case artifact_hex must be valid hex")?;
    match case.kind.as_str() {
        "native_tx_leaf" => verify_native_tx_leaf_case(case, &artifact_bytes),
        "receipt_root" => verify_receipt_root_case(case, &artifact_bytes),
        other => Err(anyhow!("unsupported review case kind {other}")),
    }
}

fn verify_native_tx_leaf_case(case: &ReviewVectorCase, artifact_bytes: &[u8]) -> Result<()> {
    let ctx = case
        .tx_context
        .as_ref()
        .ok_or_else(|| anyhow!("native_tx_leaf case {} is missing tx_context", case.name))?;
    let params = review_params_to_native(&ctx.backend_params)?;
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let security = params.security_params();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let artifact = parse_native_tx_leaf_artifact(&params, artifact_bytes)?;
    let tx = tx_from_review(ctx)?;
    let stark_public_inputs = stark_inputs_from_review(&ctx.stark_public_inputs)?;
    let receipt = receipt_from_review(&ctx.receipt)?;

    ensure!(
        artifact.version == ctx.expected_version,
        "native tx-leaf version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == decode_hex_array::<48>(&ctx.params_fingerprint_hex)?,
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.params_fingerprint == review_parameter_fingerprint(&params),
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "spec digest mismatch"
    );
    ensure!(
        artifact.spec_digest == review_spec_digest(&params),
        "spec digest mismatch"
    );
    ensure!(
        artifact.relation_id == decode_hex_array::<32>(&ctx.relation_id_hex)?,
        "relation id mismatch"
    );
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == decode_hex_array::<32>(&ctx.shape_digest_hex)?,
        "shape digest mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "shape digest mismatch"
    );
    ensure!(
        artifact.statement_digest == decode_hex_array::<48>(&ctx.statement_digest_hex)?,
        "statement digest mismatch"
    );
    ensure!(artifact.tx == tx, "public tx mismatch");
    ensure!(
        artifact.stark_public_inputs == stark_public_inputs,
        "serialized STARK inputs mismatch"
    );
    ensure!(artifact.receipt == receipt, "receipt mismatch");
    ensure!(
        artifact.leaf.version == artifact.version,
        "native tx-leaf inner proof version mismatch"
    );
    ensure!(
        artifact.leaf.relation_id == relation.relation_id(),
        "native tx-leaf inner relation id mismatch"
    );
    ensure!(
        artifact.leaf.shape_digest == pk.shape_digest,
        "native tx-leaf inner shape digest mismatch"
    );

    let expected_receipt = native_tx_leaf_receipt_from_parts(
        &artifact.tx,
        &artifact.stark_public_inputs,
        &artifact.stark_proof,
        &params,
        pk.shape_digest,
    )?;
    ensure!(
        artifact.receipt == expected_receipt,
        "canonical receipt mismatch"
    );

    let p3_public_inputs = transaction_public_inputs_p3_from_tx_leaf_public(
        &artifact.tx,
        &artifact.stark_public_inputs,
    )?;
    verify_transaction_proof_bytes_p3(&artifact.stark_proof, &p3_public_inputs)
        .map_err(|err| anyhow!("STARK proof verification failed: {err}"))?;

    validate_native_tx_leaf_public_witness_with_params(
        &params,
        &artifact.receipt,
        &artifact.tx,
        &artifact.stark_public_inputs,
        pk.shape_digest,
    )?;

    let encoding = relation.encode_statement(&artifact.receipt)?;
    ensure!(
        artifact.statement_digest == encoding.statement_digest.0,
        "statement digest mismatch"
    );
    ensure!(
        artifact.leaf.statement_digest == encoding.statement_digest,
        "inner statement digest mismatch"
    );

    let review_commitment = commitment_from_review_rows(&ctx.commitment_rows, "native tx-leaf")?;
    ensure!(
        artifact.commitment == review_commitment,
        "commitment rows mismatch"
    );

    let packed = pack_tx_leaf_public_witness(
        &artifact.tx,
        &artifact.stark_public_inputs,
        relation.shape(),
    )?;
    let expected_commitment = backend.commit_witness(&pk, &packed)?;
    ensure!(
        artifact.commitment == expected_commitment,
        "commitment mismatch"
    );
    ensure!(
        artifact.leaf.proof.witness_commitment_digest == artifact.commitment.digest,
        "witness commitment digest mismatch"
    );

    backend
        .verify_leaf(
            &vk,
            &relation.relation_id(),
            &encoding,
            &packed,
            &artifact.leaf.proof,
        )
        .map_err(|err| anyhow!("native tx-leaf verification failed: {err}"))?;
    Ok(())
}

fn verify_receipt_root_case(case: &ReviewVectorCase, artifact_bytes: &[u8]) -> Result<()> {
    let ctx = case
        .block_context
        .as_ref()
        .ok_or_else(|| anyhow!("receipt_root case {} is missing block_context", case.name))?;
    let params = review_params_to_native(&ctx.backend_params)?;
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let security = params.security_params();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let artifact = parse_receipt_root_artifact(&params, artifact_bytes)?;

    ensure!(
        artifact.version == ctx.expected_version,
        "receipt-root version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == decode_hex_array::<48>(&ctx.params_fingerprint_hex)?,
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.params_fingerprint == review_parameter_fingerprint(&params),
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "spec digest mismatch"
    );
    ensure!(
        artifact.spec_digest == review_spec_digest(&params),
        "spec digest mismatch"
    );
    ensure!(
        artifact.relation_id == decode_hex_array::<32>(&ctx.relation_id_hex)?,
        "relation id mismatch"
    );
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == decode_hex_array::<32>(&ctx.shape_digest_hex)?,
        "shape digest mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "shape digest mismatch"
    );
    ensure!(
        !artifact.leaves.is_empty(),
        "receipt-root must contain at least one leaf"
    );
    ensure!(
        artifact.leaves.len() <= params.max_claimed_receipt_root_leaves as usize,
        "receipt-root leaf count {} exceeds {}",
        artifact.leaves.len(),
        params.max_claimed_receipt_root_leaves
    );
    ensure!(
        artifact.leaves.len() == ctx.leaves.len(),
        "receipt-root leaf count mismatch"
    );

    let mut current = Vec::with_capacity(artifact.leaves.len());
    for (leaf, expected) in artifact.leaves.iter().zip(&ctx.leaves) {
        ensure!(
            leaf.statement_digest == decode_hex_array::<48>(&expected.statement_digest_hex)?,
            "leaf statement digest mismatch"
        );
        ensure!(
            leaf.witness_commitment == decode_hex_array::<48>(&expected.witness_commitment_hex)?,
            "leaf witness commitment mismatch"
        );
        ensure!(
            leaf.proof_digest == decode_hex_array::<48>(&expected.proof_digest_hex)?,
            "leaf proof digest mismatch"
        );
        let commitment =
            commitment_from_review_rows(&expected.commitment_rows, "receipt-root leaf")?;
        ensure!(
            commitment.digest == leaf.witness_commitment,
            "leaf commitment rows mismatch"
        );
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: StatementDigest(leaf.statement_digest),
            witness_commitment: commitment,
        });
    }

    let mut fold_index = 0usize;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let fold = artifact.folds.get(fold_index).ok_or_else(|| {
                    anyhow!("receipt-root artifact is missing fold step {fold_index}")
                })?;
                fold_index += 1;
                let (parent, expected_proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.challenges == expected_proof.challenges,
                    "parent challenge vector mismatch"
                );
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "parent commitment mismatch"
                );
                ensure!(
                    fold.parent_rows == expected_proof.parent_rows,
                    "parent rows mismatch"
                );
                ensure!(
                    fold.proof_digest == expected_proof.proof_digest,
                    "fold proof digest mismatch"
                );
                backend
                    .verify_fold(&vk, &parent, &left, &right, &expected_proof)
                    .map_err(|err| anyhow!("receipt-root fold verification failed: {err}"))?;
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }
    ensure!(
        fold_index == artifact.folds.len(),
        "receipt-root artifact has {} unused fold steps",
        artifact.folds.len().saturating_sub(fold_index)
    );

    let root = current
        .pop()
        .ok_or_else(|| anyhow!("receipt-root artifact did not yield a root"))?;
    ensure!(
        artifact.root_statement_digest == decode_hex_array::<48>(&ctx.root_statement_digest_hex)?,
        "root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == decode_hex_array::<48>(&ctx.root_commitment_hex)?,
        "root commitment mismatch"
    );
    ensure!(
        artifact.root_statement_digest == root.statement_digest.0,
        "root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == root.witness_commitment.digest,
        "root commitment mismatch"
    );
    Ok(())
}

pub fn review_params_to_native(review: &ReviewBackendParams) -> Result<NativeBackendParams> {
    let structural = NativeBackendParams::goldilocks_128b_structural_commitment();
    let mut params = match review.family_label.as_str() {
        "goldilocks_128b_structural_commitment" => structural,
        other => NativeBackendParams {
            manifest: superneo_backend_lattice::BackendManifest {
                family_label: Box::leak(other.to_owned().into_boxed_str()),
                spec_label: Box::leak(review.spec_label.clone().into_boxed_str()),
                commitment_scheme_label: Box::leak(
                    review.commitment_scheme_label.clone().into_boxed_str(),
                ),
                challenge_schedule_label: Box::leak(
                    review.challenge_schedule_label.clone().into_boxed_str(),
                ),
                maturity_label: Box::leak(review.maturity_label.clone().into_boxed_str()),
            },
            ..structural
        },
    };
    params.security_bits = review.security_bits;
    params.ring_profile = parse_review_ring_profile(&review.ring_profile)?;
    params.matrix_rows = review.matrix_rows;
    params.matrix_cols = review.matrix_cols;
    params.challenge_bits = review.challenge_bits;
    params.fold_challenge_count = review.fold_challenge_count;
    params.max_fold_arity = review.max_fold_arity;
    params.transcript_domain_label =
        Box::leak(review.transcript_domain_label.clone().into_boxed_str());
    params.decomposition_bits = review.decomposition_bits;
    params.opening_randomness_bits = review.opening_randomness_bits;
    params.commitment_security_model =
        parse_commitment_security_model(&review.commitment_security_model)?;
    params.commitment_bkmsis_target_bits = review.commitment_bkmsis_target_bits;
    params.max_commitment_message_ring_elems = review.max_commitment_message_ring_elems;
    params.max_claimed_receipt_root_leaves = review.max_claimed_receipt_root_leaves;
    validate_review_params(&params)?;
    Ok(params)
}

fn tx_from_review(ctx: &ReviewTxContext) -> Result<RefTxLeafPublicTx> {
    Ok(RefTxLeafPublicTx {
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
        version: VersionBinding::new(ctx.tx.version_circuit, ctx.tx.version_crypto),
    })
}

fn stark_inputs_from_review(review: &ReviewSerializedStarkInputs) -> Result<SerializedStarkInputs> {
    Ok(SerializedStarkInputs {
        input_flags: review.input_flags.clone(),
        output_flags: review.output_flags.clone(),
        fee: review.fee,
        value_balance_sign: review.value_balance_sign,
        value_balance_magnitude: review.value_balance_magnitude,
        merkle_root: decode_hex_array::<48>(&review.merkle_root_hex)?,
        balance_slot_asset_ids: review.balance_slot_asset_ids.clone(),
        stablecoin_enabled: review.stablecoin_enabled,
        stablecoin_asset_id: review.stablecoin_asset_id,
        stablecoin_policy_version: review.stablecoin_policy_version,
        stablecoin_issuance_sign: review.stablecoin_issuance_sign,
        stablecoin_issuance_magnitude: review.stablecoin_issuance_magnitude,
        stablecoin_policy_hash: decode_hex_array::<48>(&review.stablecoin_policy_hash_hex)?,
        stablecoin_oracle_commitment: decode_hex_array::<48>(
            &review.stablecoin_oracle_commitment_hex,
        )?,
        stablecoin_attestation_commitment: decode_hex_array::<48>(
            &review.stablecoin_attestation_commitment_hex,
        )?,
    })
}

fn receipt_from_review(review: &ReviewReceipt) -> Result<CanonicalTxValidityReceipt> {
    Ok(CanonicalTxValidityReceipt {
        statement_hash: decode_hex_array::<48>(&review.statement_hash_hex)?,
        proof_digest: decode_hex_array::<48>(&review.proof_digest_hex)?,
        public_inputs_digest: decode_hex_array::<48>(&review.public_inputs_digest_hex)?,
        verifier_profile: decode_hex_array::<48>(&review.verifier_profile_hex)?,
    })
}

fn commitment_from_review_rows(rows: &[Vec<u64>], label: &str) -> Result<LatticeCommitment> {
    ensure!(
        !rows.is_empty(),
        "{label} commitment rows must not be empty"
    );
    Ok(LatticeCommitment::from_rows(
        rows.iter().cloned().map(RingElem::from_coeffs).collect(),
    ))
}

fn native_tx_leaf_receipt_from_parts(
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    stark_proof: &[u8],
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
) -> Result<CanonicalTxValidityReceipt> {
    ensure!(
        !stark_proof.is_empty(),
        "native tx-leaf proof bytes must not be empty"
    );
    let relation = TxLeafPublicRelation::default();
    Ok(CanonicalTxValidityReceipt {
        statement_hash: tx_statement_hash_from_tx_leaf_public(tx, stark_public_inputs)?,
        proof_digest: digest48(TX_PROOF_DIGEST_DOMAIN, stark_proof),
        public_inputs_digest: transaction_public_inputs_digest_from_serialized(stark_public_inputs)
            .map_err(|err| anyhow!("failed to hash transaction public inputs: {err}"))?,
        verifier_profile: review_verifier_profile(
            params,
            &relation.relation_id(),
            &shape_digest,
            b"native-tx-leaf",
        ),
    })
}

fn validate_native_tx_leaf_public_witness_with_params(
    params: &NativeBackendParams,
    statement: &CanonicalTxValidityReceipt,
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    shape_digest: ShapeDigest,
) -> Result<()> {
    validate_tx_leaf_public_witness_with_expected_profile(
        statement,
        tx,
        stark_public_inputs,
        review_verifier_profile(
            params,
            &TxLeafPublicRelation::default().relation_id(),
            &shape_digest,
            b"native-tx-leaf",
        ),
    )
}

fn validate_tx_leaf_public_witness_with_expected_profile(
    statement: &CanonicalTxValidityReceipt,
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    expected_verifier_profile: [u8; 48],
) -> Result<()> {
    ensure!(
        tx.nullifiers.len() <= MAX_INPUTS,
        "tx-leaf nullifier length {} exceeds {}",
        tx.nullifiers.len(),
        MAX_INPUTS
    );
    ensure!(
        tx.commitments.len() <= MAX_OUTPUTS,
        "tx-leaf commitment length {} exceeds {}",
        tx.commitments.len(),
        MAX_OUTPUTS
    );
    ensure!(
        tx.ciphertext_hashes.len() <= MAX_OUTPUTS,
        "tx-leaf ciphertext-hash length {} exceeds {}",
        tx.ciphertext_hashes.len(),
        MAX_OUTPUTS
    );
    ensure!(
        stark_public_inputs.input_flags.len() <= MAX_INPUTS,
        "tx-leaf input flag length {} exceeds {}",
        stark_public_inputs.input_flags.len(),
        MAX_INPUTS
    );
    ensure!(
        stark_public_inputs.output_flags.len() <= MAX_OUTPUTS,
        "tx-leaf output flag length {} exceeds {}",
        stark_public_inputs.output_flags.len(),
        MAX_OUTPUTS
    );
    ensure!(
        stark_public_inputs.balance_slot_asset_ids.len() <= BALANCE_SLOTS,
        "tx-leaf balance slot asset length {} exceeds {}",
        stark_public_inputs.balance_slot_asset_ids.len(),
        BALANCE_SLOTS
    );
    ensure!(
        active_flag_count(&stark_public_inputs.input_flags)? == tx.nullifiers.len(),
        "tx-leaf nullifier list length does not match active input flags"
    );
    ensure!(
        active_flag_count(&stark_public_inputs.output_flags)? == tx.commitments.len(),
        "tx-leaf commitment list length does not match active output flags"
    );
    ensure!(
        active_flag_count(&stark_public_inputs.output_flags)? == tx.ciphertext_hashes.len(),
        "tx-leaf ciphertext-hash list length does not match active output flags"
    );
    let expected_statement_hash = tx_statement_hash_from_tx_leaf_public(tx, stark_public_inputs)?;
    ensure!(
        expected_statement_hash == statement.statement_hash,
        "statement hash mismatch"
    );
    let expected_public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(stark_public_inputs)
            .map_err(|err| anyhow!("failed to hash transaction public inputs: {err}"))?;
    ensure!(
        expected_public_inputs_digest == statement.public_inputs_digest,
        "public inputs digest mismatch"
    );
    ensure!(
        expected_verifier_profile == statement.verifier_profile,
        "verifier profile mismatch"
    );
    Ok(())
}

fn transaction_public_inputs_p3_from_tx_leaf_public(
    tx: &RefTxLeafPublicTx,
    stark_inputs: &SerializedStarkInputs,
) -> Result<TransactionPublicInputsP3> {
    ensure!(
        tx.nullifiers.len() <= MAX_INPUTS,
        "tx nullifier length {} exceeds {}",
        tx.nullifiers.len(),
        MAX_INPUTS
    );
    ensure!(
        tx.commitments.len() <= MAX_OUTPUTS,
        "tx commitment length {} exceeds {}",
        tx.commitments.len(),
        MAX_OUTPUTS
    );
    ensure!(
        tx.ciphertext_hashes.len() <= MAX_OUTPUTS,
        "tx ciphertext hash length {} exceeds {}",
        tx.ciphertext_hashes.len(),
        MAX_OUTPUTS
    );
    ensure!(
        stark_inputs.balance_slot_asset_ids.len() == BALANCE_SLOTS,
        "serialized STARK balance slot length {} does not match {}",
        stark_inputs.balance_slot_asset_ids.len(),
        BALANCE_SLOTS
    );
    ensure!(
        active_flag_count(&stark_inputs.input_flags)? == tx.nullifiers.len(),
        "tx nullifier list length does not match active input flags"
    );
    ensure!(
        active_flag_count(&stark_inputs.output_flags)? == tx.commitments.len(),
        "tx commitment list length does not match active output flags"
    );
    ensure!(
        active_flag_count(&stark_inputs.output_flags)? == tx.ciphertext_hashes.len(),
        "tx ciphertext-hash list length does not match active output flags"
    );

    let mut public = TransactionPublicInputsP3::default();
    public.input_flags = stark_inputs
        .input_flags
        .iter()
        .copied()
        .map(|flag| Goldilocks::new(u64::from(flag)))
        .collect();
    public.output_flags = stark_inputs
        .output_flags
        .iter()
        .copied()
        .map(|flag| Goldilocks::new(u64::from(flag)))
        .collect();
    public.nullifiers = tx
        .nullifiers
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            bytes48_to_felts(value).ok_or_else(|| anyhow!("tx nullifier {} is non-canonical", idx))
        })
        .collect::<Result<Vec<_>>>()?;
    public.commitments = tx
        .commitments
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            bytes48_to_felts(value).ok_or_else(|| anyhow!("tx commitment {} is non-canonical", idx))
        })
        .collect::<Result<Vec<_>>>()?;
    public.ciphertext_hashes = tx
        .ciphertext_hashes
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            bytes48_to_felts(value)
                .ok_or_else(|| anyhow!("tx ciphertext hash {} is non-canonical", idx))
        })
        .collect::<Result<Vec<_>>>()?;
    public.fee = Goldilocks::new(stark_inputs.fee);
    public.value_balance_sign = Goldilocks::new(u64::from(stark_inputs.value_balance_sign));
    public.value_balance_magnitude = Goldilocks::new(stark_inputs.value_balance_magnitude);
    public.merkle_root = bytes48_to_felts(&stark_inputs.merkle_root)
        .ok_or_else(|| anyhow!("merkle root is non-canonical"))?;
    for (slot, asset_id) in stark_inputs.balance_slot_asset_ids.iter().enumerate() {
        public.balance_slot_assets[slot] = Goldilocks::new(*asset_id);
    }
    public.stablecoin_enabled = Goldilocks::new(u64::from(stark_inputs.stablecoin_enabled));
    public.stablecoin_asset = Goldilocks::new(stark_inputs.stablecoin_asset_id);
    public.stablecoin_policy_version =
        Goldilocks::new(u64::from(stark_inputs.stablecoin_policy_version));
    public.stablecoin_issuance_sign =
        Goldilocks::new(u64::from(stark_inputs.stablecoin_issuance_sign));
    public.stablecoin_issuance_magnitude =
        Goldilocks::new(stark_inputs.stablecoin_issuance_magnitude);
    public.stablecoin_policy_hash = bytes48_to_felts(&stark_inputs.stablecoin_policy_hash)
        .ok_or_else(|| anyhow!("stablecoin policy hash is non-canonical"))?;
    public.stablecoin_oracle_commitment =
        bytes48_to_felts(&stark_inputs.stablecoin_oracle_commitment)
            .ok_or_else(|| anyhow!("stablecoin oracle commitment is non-canonical"))?;
    public.stablecoin_attestation_commitment =
        bytes48_to_felts(&stark_inputs.stablecoin_attestation_commitment)
            .ok_or_else(|| anyhow!("stablecoin attestation commitment is non-canonical"))?;
    Ok(public)
}

fn pack_tx_leaf_public_witness(
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    shape: &superneo_ccs::CcsShape<Goldilocks>,
) -> Result<superneo_ring::PackedWitness<u64>> {
    let mut values = Vec::with_capacity(shape.expected_witness_len());
    values.push(Goldilocks::new(stark_public_inputs.input_flags.len() as u64));
    values.push(Goldilocks::new(
        stark_public_inputs.output_flags.len() as u64
    ));
    push_padded_bits(
        &mut values,
        &stark_public_inputs.input_flags,
        MAX_INPUTS,
        "input flags",
    )?;
    push_padded_bits(
        &mut values,
        &stark_public_inputs.output_flags,
        MAX_OUTPUTS,
        "output flags",
    )?;
    values.push(Goldilocks::new(stark_public_inputs.fee));
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.value_balance_sign,
    )));
    values.push(Goldilocks::new(stark_public_inputs.value_balance_magnitude));
    push_bytes48_limbs(&mut values, &stark_public_inputs.merkle_root)?;
    values.push(Goldilocks::new(
        stark_public_inputs.balance_slot_asset_ids.len() as u64,
    ));
    push_padded_u64s(
        &mut values,
        &stark_public_inputs.balance_slot_asset_ids,
        BALANCE_SLOTS,
    );
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.stablecoin_enabled,
    )));
    values.push(Goldilocks::new(stark_public_inputs.stablecoin_asset_id));
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.stablecoin_policy_version,
    )));
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.stablecoin_issuance_sign,
    )));
    values.push(Goldilocks::new(
        stark_public_inputs.stablecoin_issuance_magnitude,
    ));
    push_bytes48_limbs(&mut values, &stark_public_inputs.stablecoin_policy_hash)?;
    push_bytes48_limbs(
        &mut values,
        &stark_public_inputs.stablecoin_oracle_commitment,
    )?;
    push_bytes48_limbs(
        &mut values,
        &stark_public_inputs.stablecoin_attestation_commitment,
    )?;
    values.push(Goldilocks::new(tx.nullifiers.len() as u64));
    push_padded_digest_vec(&mut values, &tx.nullifiers, MAX_INPUTS)?;
    values.push(Goldilocks::new(tx.commitments.len() as u64));
    push_padded_digest_vec(&mut values, &tx.commitments, MAX_OUTPUTS)?;
    values.push(Goldilocks::new(tx.ciphertext_hashes.len() as u64));
    push_padded_digest_vec(&mut values, &tx.ciphertext_hashes, MAX_OUTPUTS)?;
    push_bytes48_limbs(&mut values, &tx.balance_tag)?;
    values.push(Goldilocks::new(u64::from(tx.version.circuit)));
    values.push(Goldilocks::new(u64::from(tx.version.crypto)));
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    packer.pack(shape, &Assignment { witness: values })
}

fn tx_statement_hash_from_tx_leaf_public(
    tx: &RefTxLeafPublicTx,
    stark_inputs: &SerializedStarkInputs,
) -> Result<[u8; 48]> {
    let mut message = Vec::new();
    message.extend_from_slice(TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&stark_inputs.merkle_root);
    extend_padded_digests(&mut message, &tx.nullifiers, MAX_INPUTS)?;
    extend_padded_digests(&mut message, &tx.commitments, MAX_OUTPUTS)?;
    extend_padded_digests(&mut message, &tx.ciphertext_hashes, MAX_OUTPUTS)?;
    let value_balance = decode_signed_magnitude(
        stark_inputs.value_balance_sign,
        stark_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let stablecoin_issuance = decode_signed_magnitude(
        stark_inputs.stablecoin_issuance_sign,
        stark_inputs.stablecoin_issuance_magnitude,
        "stablecoin_issuance",
    )?;
    message.extend_from_slice(&stark_inputs.fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(&tx.balance_tag);
    message.extend_from_slice(&tx.version.circuit.to_le_bytes());
    message.extend_from_slice(&tx.version.crypto.to_le_bytes());
    message.push(stark_inputs.stablecoin_enabled);
    message.extend_from_slice(&stark_inputs.stablecoin_asset_id.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_hash);
    message.extend_from_slice(&stark_inputs.stablecoin_oracle_commitment);
    message.extend_from_slice(&stark_inputs.stablecoin_attestation_commitment);
    message.extend_from_slice(&stablecoin_issuance.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_version.to_le_bytes());
    Ok(blake3_384_bytes(&message))
}

fn active_flag_count(flags: &[u8]) -> Result<usize> {
    ensure!(flags.iter().all(|flag| *flag <= 1), "flags must be binary");
    Ok(flags.iter().filter(|flag| **flag == 1).count())
}

fn decode_signed_magnitude(sign: u8, magnitude: u64, label: &str) -> Result<i128> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        other => Err(anyhow!("{label} sign flag must be 0 or 1, got {other}")),
    }
}

fn push_padded_bits(
    values: &mut Vec<Goldilocks>,
    bits: &[u8],
    expected_len: usize,
    label: &str,
) -> Result<()> {
    ensure!(
        bits.len() <= expected_len,
        "{label} length {} exceeds {}",
        bits.len(),
        expected_len
    );
    ensure!(bits.iter().all(|bit| *bit <= 1), "{label} must be binary");
    for bit in bits {
        values.push(Goldilocks::new(u64::from(*bit)));
    }
    for _ in bits.len()..expected_len {
        values.push(Goldilocks::new(0));
    }
    Ok(())
}

fn push_padded_u64s(values: &mut Vec<Goldilocks>, ints: &[u64], expected_len: usize) {
    for value in ints {
        values.push(Goldilocks::new(*value));
    }
    for _ in ints.len()..expected_len {
        values.push(Goldilocks::new(0));
    }
}

fn push_bytes48_limbs(values: &mut Vec<Goldilocks>, bytes: &[u8; 48]) -> Result<()> {
    values.extend(
        bytes.chunks_exact(8).map(|chunk| {
            Goldilocks::new(u64::from_le_bytes(chunk.try_into().expect("8-byte limb")))
        }),
    );
    Ok(())
}

fn push_padded_digest_vec(
    values: &mut Vec<Goldilocks>,
    digests: &[[u8; 48]],
    expected_len: usize,
) -> Result<()> {
    ensure!(
        digests.len() <= expected_len,
        "digest vector length {} exceeds {}",
        digests.len(),
        expected_len
    );
    for digest in digests {
        push_bytes48_limbs(values, digest)?;
    }
    for _ in digests.len()..expected_len {
        for _ in 0..6 {
            values.push(Goldilocks::new(0));
        }
    }
    Ok(())
}

fn extend_padded_digests(
    out: &mut Vec<u8>,
    digests: &[[u8; 48]],
    expected_len: usize,
) -> Result<()> {
    ensure!(
        digests.len() <= expected_len,
        "digest vector length {} exceeds {}",
        digests.len(),
        expected_len
    );
    for digest in digests {
        out.extend_from_slice(digest);
    }
    for _ in digests.len()..expected_len {
        out.extend_from_slice(&[0u8; 48]);
    }
    Ok(())
}

fn parse_native_tx_leaf_artifact(
    params: &NativeBackendParams,
    bytes: &[u8],
) -> Result<RefNativeTxLeafArtifact> {
    ensure!(
        bytes.len() <= max_native_tx_leaf_artifact_bytes_with_params(params),
        "native tx-leaf artifact size {} exceeds {}",
        bytes.len(),
        max_native_tx_leaf_artifact_bytes_with_params(params)
    );
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let params_fingerprint = read_array::<48>(bytes, &mut cursor)?;
    let spec_digest = read_array::<32>(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let statement_digest = read_array::<48>(bytes, &mut cursor)?;
    let receipt = parse_canonical_receipt(bytes, &mut cursor)?;
    let stark_public_inputs = parse_serialized_stark_inputs(bytes, &mut cursor)?;
    let tx = parse_tx_leaf_public_tx(bytes, &mut cursor)?;
    let proof_len = read_u32_capped(
        bytes,
        &mut cursor,
        MAX_NATIVE_TX_STARK_PROOF_BYTES,
        "native tx-leaf proof bytes",
    )? as usize;
    let stark_proof = read_bytes(bytes, &mut cursor, proof_len)?;
    let commitment = parse_lattice_commitment(params, bytes, &mut cursor, "native tx-leaf")?;
    let leaf = parse_leaf_artifact(bytes, &mut cursor)?;
    ensure!(
        cursor == bytes.len(),
        "native tx-leaf artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(RefNativeTxLeafArtifact {
        version,
        params_fingerprint,
        spec_digest,
        relation_id,
        shape_digest,
        statement_digest,
        receipt,
        stark_public_inputs,
        tx,
        stark_proof,
        commitment,
        leaf,
    })
}

fn parse_receipt_root_artifact(
    params: &NativeBackendParams,
    bytes: &[u8],
) -> Result<RefReceiptRootArtifact> {
    ensure!(
        bytes.len()
            <= max_receipt_root_artifact_bytes_with_params(
                params.max_claimed_receipt_root_leaves as usize,
                params,
            ),
        "receipt-root artifact size {} exceeds {}",
        bytes.len(),
        max_receipt_root_artifact_bytes_with_params(
            params.max_claimed_receipt_root_leaves as usize,
            params,
        )
    );
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let params_fingerprint = read_array::<48>(bytes, &mut cursor)?;
    let spec_digest = read_array::<32>(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let leaf_count = read_u32_capped(
        bytes,
        &mut cursor,
        params.max_claimed_receipt_root_leaves as usize,
        "receipt-root leaves",
    )? as usize;
    let fold_count = read_u32_capped(
        bytes,
        &mut cursor,
        params.max_claimed_receipt_root_leaves.saturating_sub(1) as usize,
        "receipt-root folds",
    )? as usize;
    let mut leaves = Vec::with_capacity(leaf_count);
    for _ in 0..leaf_count {
        leaves.push(RefReceiptRootLeaf {
            statement_digest: read_array::<48>(bytes, &mut cursor)?,
            witness_commitment: read_array::<48>(bytes, &mut cursor)?,
            proof_digest: read_array::<48>(bytes, &mut cursor)?,
        });
    }
    let mut folds = Vec::with_capacity(fold_count);
    for _ in 0..fold_count {
        let challenge_count = read_u32_capped(
            bytes,
            &mut cursor,
            params.fold_challenge_count as usize,
            "receipt-root fold challenges",
        )? as usize;
        let mut challenges = Vec::with_capacity(challenge_count);
        for _ in 0..challenge_count {
            challenges.push(read_u64(bytes, &mut cursor)?);
        }
        let parent_statement_digest = read_array::<48>(bytes, &mut cursor)?;
        let parent_commitment = read_array::<48>(bytes, &mut cursor)?;
        let row_count = read_u32_capped(
            bytes,
            &mut cursor,
            params.matrix_rows,
            "receipt-root fold rows",
        )? as usize;
        let mut parent_rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            let coeff_count = read_u32_capped(
                bytes,
                &mut cursor,
                params.matrix_cols,
                "receipt-root fold row coefficients",
            )? as usize;
            let mut coeffs = Vec::with_capacity(coeff_count);
            for _ in 0..coeff_count {
                coeffs.push(read_u64(bytes, &mut cursor)?);
            }
            parent_rows.push(RingElem::from_coeffs(coeffs));
        }
        folds.push(RefReceiptRootFoldStep {
            challenges,
            parent_statement_digest,
            parent_commitment,
            parent_rows,
            proof_digest: read_array::<48>(bytes, &mut cursor)?,
        });
    }
    let root_statement_digest = read_array::<48>(bytes, &mut cursor)?;
    let root_commitment = read_array::<48>(bytes, &mut cursor)?;
    ensure!(
        cursor == bytes.len(),
        "receipt-root artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(RefReceiptRootArtifact {
        version,
        params_fingerprint,
        spec_digest,
        relation_id,
        shape_digest,
        leaves,
        folds,
        root_statement_digest,
        root_commitment,
    })
}

fn parse_canonical_receipt(bytes: &[u8], cursor: &mut usize) -> Result<CanonicalTxValidityReceipt> {
    Ok(CanonicalTxValidityReceipt {
        statement_hash: read_array::<48>(bytes, cursor)?,
        proof_digest: read_array::<48>(bytes, cursor)?,
        public_inputs_digest: read_array::<48>(bytes, cursor)?,
        verifier_profile: read_array::<48>(bytes, cursor)?,
    })
}

fn parse_serialized_stark_inputs(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<SerializedStarkInputs> {
    let input_flag_count =
        read_u32_capped(bytes, cursor, MAX_INPUTS, "serialized STARK input flags")? as usize;
    let input_flags = read_bytes(bytes, cursor, input_flag_count)?;
    let output_flag_count =
        read_u32_capped(bytes, cursor, MAX_OUTPUTS, "serialized STARK output flags")? as usize;
    let output_flags = read_bytes(bytes, cursor, output_flag_count)?;
    let fee = read_u64(bytes, cursor)?;
    let value_balance_sign = read_u8(bytes, cursor)?;
    let value_balance_magnitude = read_u64(bytes, cursor)?;
    let merkle_root = read_array::<48>(bytes, cursor)?;
    let balance_slot_count = read_u32_capped(
        bytes,
        cursor,
        BALANCE_SLOTS,
        "serialized STARK balance slots",
    )? as usize;
    let mut balance_slot_asset_ids = Vec::with_capacity(balance_slot_count);
    for _ in 0..balance_slot_count {
        balance_slot_asset_ids.push(read_u64(bytes, cursor)?);
    }
    Ok(SerializedStarkInputs {
        input_flags,
        output_flags,
        fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root,
        balance_slot_asset_ids,
        stablecoin_enabled: read_u8(bytes, cursor)?,
        stablecoin_asset_id: read_u64(bytes, cursor)?,
        stablecoin_policy_version: read_u32(bytes, cursor)?,
        stablecoin_issuance_sign: read_u8(bytes, cursor)?,
        stablecoin_issuance_magnitude: read_u64(bytes, cursor)?,
        stablecoin_policy_hash: read_array::<48>(bytes, cursor)?,
        stablecoin_oracle_commitment: read_array::<48>(bytes, cursor)?,
        stablecoin_attestation_commitment: read_array::<48>(bytes, cursor)?,
    })
}

fn parse_tx_leaf_public_tx(bytes: &[u8], cursor: &mut usize) -> Result<RefTxLeafPublicTx> {
    let nullifier_count =
        read_u32_capped(bytes, cursor, MAX_INPUTS, "native tx-leaf nullifiers")? as usize;
    let mut nullifiers = Vec::with_capacity(nullifier_count);
    for _ in 0..nullifier_count {
        nullifiers.push(read_array::<48>(bytes, cursor)?);
    }
    let commitment_count =
        read_u32_capped(bytes, cursor, MAX_OUTPUTS, "native tx-leaf commitments")? as usize;
    let mut commitments = Vec::with_capacity(commitment_count);
    for _ in 0..commitment_count {
        commitments.push(read_array::<48>(bytes, cursor)?);
    }
    let ciphertext_hash_count = read_u32_capped(
        bytes,
        cursor,
        MAX_OUTPUTS,
        "native tx-leaf ciphertext hashes",
    )? as usize;
    let mut ciphertext_hashes = Vec::with_capacity(ciphertext_hash_count);
    for _ in 0..ciphertext_hash_count {
        ciphertext_hashes.push(read_array::<48>(bytes, cursor)?);
    }
    Ok(RefTxLeafPublicTx {
        nullifiers,
        commitments,
        ciphertext_hashes,
        balance_tag: read_array::<48>(bytes, cursor)?,
        version: VersionBinding::new(read_u16(bytes, cursor)?, read_u16(bytes, cursor)?),
    })
}

fn parse_lattice_commitment(
    params: &NativeBackendParams,
    bytes: &[u8],
    cursor: &mut usize,
    label: &str,
) -> Result<LatticeCommitment> {
    let digest = read_array::<48>(bytes, cursor)?;
    let row_count = read_u32_capped(
        bytes,
        cursor,
        params.matrix_rows,
        &format!("{label} commitment rows"),
    )? as usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let coeff_count = read_u32_capped(
            bytes,
            cursor,
            params.matrix_cols,
            &format!("{label} commitment row coefficients"),
        )? as usize;
        let mut coeffs = Vec::with_capacity(coeff_count);
        for _ in 0..coeff_count {
            coeffs.push(read_u64(bytes, cursor)?);
        }
        rows.push(RingElem::from_coeffs(coeffs));
    }
    Ok(LatticeCommitment { digest, rows })
}

fn parse_leaf_artifact(bytes: &[u8], cursor: &mut usize) -> Result<LeafArtifact<LeafDigestProof>> {
    Ok(LeafArtifact {
        version: read_u16(bytes, cursor)?,
        relation_id: RelationId(read_array::<32>(bytes, cursor)?),
        shape_digest: ShapeDigest(read_array::<32>(bytes, cursor)?),
        statement_digest: StatementDigest(read_array::<48>(bytes, cursor)?),
        proof: LeafDigestProof {
            witness_commitment_digest: read_array::<48>(bytes, cursor)?,
            proof_digest: read_array::<48>(bytes, cursor)?,
        },
    })
}

fn max_native_tx_leaf_artifact_bytes_with_params(params: &NativeBackendParams) -> usize {
    let serialized_stark_inputs_bytes = 4
        + MAX_INPUTS
        + 4
        + MAX_OUTPUTS
        + 8
        + 1
        + 8
        + 48
        + 4
        + (BALANCE_SLOTS * 8)
        + 1
        + 8
        + 4
        + 1
        + 8
        + (48 * 3);
    let lattice_commitment_bytes = 48 + 4 + (params.matrix_rows * (4 + (params.matrix_cols * 8)));
    2 + 48
        + 32
        + 32
        + 32
        + 48
        + CANONICAL_RECEIPT_WIRE_BYTES
        + serialized_stark_inputs_bytes
        + TX_PUBLIC_WIRE_BYTES
        + 4
        + MAX_NATIVE_TX_STARK_PROOF_BYTES
        + lattice_commitment_bytes
        + LEAF_ARTIFACT_WIRE_BYTES
}

fn max_receipt_root_artifact_bytes_with_params(
    tx_count: usize,
    params: &NativeBackendParams,
) -> usize {
    let leaf_bytes = tx_count * (48 * 3);
    let fold_step_bytes = 4
        + ((params.fold_challenge_count as usize) * 8)
        + 48
        + 48
        + 4
        + (params.matrix_rows * (4 + (params.matrix_cols * 8)))
        + 48;
    let fold_bytes = tx_count.saturating_sub(1) * fold_step_bytes;
    2 + 48 + 32 + 32 + 32 + 4 + 4 + leaf_bytes + fold_bytes + 48 + 48
}

fn review_parameter_fingerprint(params: &NativeBackendParams) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.native-backend-params.v2");
    hasher.update(params.manifest.family_label.as_bytes());
    hasher.update(params.manifest.spec_label.as_bytes());
    hasher.update(params.manifest.commitment_scheme_label.as_bytes());
    hasher.update(params.manifest.challenge_schedule_label.as_bytes());
    hasher.update(params.manifest.maturity_label.as_bytes());
    hasher.update(&params.security_bits.to_le_bytes());
    hasher.update(review_ring_profile_label(params.ring_profile));
    hasher.update(&(params.matrix_rows as u64).to_le_bytes());
    hasher.update(&(params.matrix_cols as u64).to_le_bytes());
    hasher.update(&params.challenge_bits.to_le_bytes());
    hasher.update(&params.fold_challenge_count.to_le_bytes());
    hasher.update(&params.max_fold_arity.to_le_bytes());
    hasher.update(params.transcript_domain_label.as_bytes());
    hasher.update(&params.decomposition_bits.to_le_bytes());
    hasher.update(&params.opening_randomness_bits.to_le_bytes());
    hasher.update(&[match params.commitment_security_model {
        CommitmentSecurityModel::GeometryProxy => 0u8,
        CommitmentSecurityModel::BoundedKernelModuleSis => 1u8,
    }]);
    hasher.update(&params.commitment_bkmsis_target_bits.to_le_bytes());
    hasher.update(&params.max_commitment_message_ring_elems.to_le_bytes());
    hasher.update(&params.max_claimed_receipt_root_leaves.to_le_bytes());
    hash48(hasher)
}

fn review_spec_digest(params: &NativeBackendParams) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.native-backend-spec-digest.v1");
    hasher.update(params.manifest.family_label.as_bytes());
    hasher.update(params.manifest.spec_label.as_bytes());
    hasher.update(params.manifest.commitment_scheme_label.as_bytes());
    hasher.update(params.manifest.challenge_schedule_label.as_bytes());
    hasher.update(params.manifest.maturity_label.as_bytes());
    hasher.update(&params.security_bits.to_le_bytes());
    hasher.update(review_ring_profile_label(params.ring_profile));
    hasher.update(&(params.matrix_rows as u64).to_le_bytes());
    hasher.update(&(params.matrix_cols as u64).to_le_bytes());
    hasher.update(&params.challenge_bits.to_le_bytes());
    hasher.update(&params.fold_challenge_count.to_le_bytes());
    hasher.update(&params.max_fold_arity.to_le_bytes());
    hasher.update(params.transcript_domain_label.as_bytes());
    hasher.update(&params.decomposition_bits.to_le_bytes());
    hasher.update(&params.opening_randomness_bits.to_le_bytes());
    hasher.update(&[match params.commitment_security_model {
        CommitmentSecurityModel::GeometryProxy => 0u8,
        CommitmentSecurityModel::BoundedKernelModuleSis => 1u8,
    }]);
    hasher.update(&params.commitment_bkmsis_target_bits.to_le_bytes());
    hasher.update(&params.max_commitment_message_ring_elems.to_le_bytes());
    hasher.update(&params.max_claimed_receipt_root_leaves.to_le_bytes());
    hash32(hasher)
}

fn review_verifier_profile(
    params: &NativeBackendParams,
    relation_id: &RelationId,
    shape_digest: &ShapeDigest,
    profile_label: &[u8],
) -> [u8; 48] {
    digest48_with_parts(
        b"hegemon.superneo.explicit-verifier-profile.v1",
        &[
            profile_label,
            &review_parameter_fingerprint(params),
            &review_spec_digest(params),
            &relation_id.0,
            &shape_digest.0,
        ],
    )
}

fn review_ring_profile_label(profile: RingProfile) -> &'static [u8] {
    match profile {
        RingProfile::GoldilocksCyclotomic24 => b"goldilocks-cyclotomic24",
        RingProfile::GoldilocksFrog => b"goldilocks-frog",
    }
}

fn parse_review_ring_profile(value: &str) -> Result<RingProfile> {
    match value {
        "GoldilocksCyclotomic24" => Ok(RingProfile::GoldilocksCyclotomic24),
        "GoldilocksFrog" => Ok(RingProfile::GoldilocksFrog),
        other => Err(anyhow!("unsupported ring_profile {other}")),
    }
}

fn parse_commitment_security_model(value: &str) -> Result<CommitmentSecurityModel> {
    match value {
        "geometry_proxy" => Ok(CommitmentSecurityModel::GeometryProxy),
        "bounded_kernel_module_sis" => Ok(CommitmentSecurityModel::BoundedKernelModuleSis),
        other => Err(anyhow!("unsupported commitment_security_model {other}")),
    }
}

fn validate_review_params(params: &NativeBackendParams) -> Result<()> {
    ensure!(
        params.matrix_rows > 0,
        "matrix_rows must be strictly positive"
    );
    ensure!(
        params.matrix_cols > 0,
        "matrix_cols must be strictly positive"
    );
    ensure!(
        (1..=63).contains(&params.challenge_bits),
        "challenge_bits must be in 1..=63"
    );
    ensure!(
        (1..=8).contains(&params.fold_challenge_count),
        "fold_challenge_count must be in 1..=8"
    );
    ensure!(
        params.max_fold_arity == 2,
        "binary fold backend requires max_fold_arity == 2"
    );
    ensure!(
        (1..=16).contains(&params.decomposition_bits),
        "decomposition_bits must be in 1..=16"
    );
    ensure!(
        params.opening_randomness_bits > 0 && params.opening_randomness_bits <= 256,
        "opening_randomness_bits must be in 1..=256"
    );
    if matches!(
        params.commitment_security_model,
        CommitmentSecurityModel::BoundedKernelModuleSis
    ) {
        ensure!(
            params.commitment_bkmsis_target_bits > 0,
            "commitment_bkmsis_target_bits must be strictly positive under bounded_kernel_module_sis"
        );
    }
    ensure!(
        params.max_claimed_receipt_root_leaves > 0,
        "max_claimed_receipt_root_leaves must be strictly positive"
    );
    Ok(())
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes =
        hex::decode(value).with_context(|| format!("hex string has invalid encoding: {value}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow!("hex string has {} bytes, expected {}", len, N))
}

fn digest48(label: &[u8], payload: &[u8]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(payload);
    hash48(hasher)
}

fn digest48_with_parts(label: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    for part in parts {
        hasher.update(part);
    }
    hash48(hasher)
}

fn blake3_384_bytes(bytes: &[u8]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hash48(hasher)
}

fn hash48(hasher: Hasher) -> [u8; 48] {
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hash32(hasher: Hasher) -> [u8; 32] {
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn default_commitment_security_model() -> String {
    "bounded_kernel_module_sis".to_owned()
}

fn default_commitment_bkmsis_target_bits() -> u32 {
    128
}

fn default_max_commitment_message_ring_elems() -> u32 {
    513
}

fn default_max_claimed_receipt_root_leaves() -> u32 {
    128
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, cursor)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor)?))
}

fn read_u32_capped(bytes: &[u8], cursor: &mut usize, cap: usize, label: &str) -> Result<u32> {
    let value = read_u32(bytes, cursor)? as usize;
    ensure!(value <= cap, "{label} count {} exceeds {}", value, cap);
    Ok(value as u32)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    Ok(read_array::<1>(bytes, cursor)?[0])
}

fn read_bytes(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>> {
    ensure!(
        bytes.len().saturating_sub(*cursor) >= len,
        "artifact ended early while reading {} bytes",
        len
    );
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    ensure!(
        bytes.len().saturating_sub(*cursor) >= N,
        "artifact ended early while reading {} bytes",
        N
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode as hex_encode;
    use std::path::PathBuf;

    #[test]
    fn parses_and_verifies_bundle_from_testdata() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tools dir")
            .parent()
            .expect("repo root")
            .join("testdata/native_backend_vectors");
        if !root.exists() {
            return;
        }
        let (summary, results) = verify_bundle_dir(&root).expect("bundle verification");
        assert_eq!(
            summary.failed_cases, 0,
            "unexpected vector failures: {:?}",
            results
        );
    }

    #[test]
    fn review_bundle_params_round_trip_to_matching_fingerprint() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tools dir")
            .parent()
            .expect("repo root")
            .join("testdata/native_backend_vectors");
        if !root.exists() {
            return;
        }
        let bundle = load_bundle(&root.join("bundle.json")).expect("bundle load");
        let params = review_params_to_native(&bundle.native_backend_params).expect("params");
        let bundle_fingerprint =
            decode_hex_array::<48>(&bundle.parameter_fingerprint).expect("bundle fingerprint");
        let production_fingerprint = params.parameter_fingerprint();
        let reference_fingerprint = review_parameter_fingerprint(&params);
        assert_eq!(
            hex_encode(production_fingerprint),
            hex_encode(bundle_fingerprint),
            "production fingerprint mismatch: family={} spec={} scheme={} schedule={} maturity={} sec={} ring={:?} rows={} cols={} chall={} fold_count={} arity={} domain={} decomp={} opening={} commitment_model={:?} bkmsis_target={} max_msg={} max_leaves={}",
            params.manifest.family_label,
            params.manifest.spec_label,
            params.manifest.commitment_scheme_label,
            params.manifest.challenge_schedule_label,
            params.manifest.maturity_label,
            params.security_bits,
            params.ring_profile,
            params.matrix_rows,
            params.matrix_cols,
            params.challenge_bits,
            params.fold_challenge_count,
            params.max_fold_arity,
            params.transcript_domain_label,
            params.decomposition_bits,
            params.opening_randomness_bits,
            params.commitment_security_model,
            params.commitment_bkmsis_target_bits,
            params.max_commitment_message_ring_elems,
            params.max_claimed_receipt_root_leaves,
        );
        assert_eq!(
            hex_encode(reference_fingerprint),
            hex_encode(bundle_fingerprint),
            "reference fingerprint mismatch: family={} spec={} scheme={} schedule={} maturity={} sec={} ring={:?} rows={} cols={} chall={} fold_count={} arity={} domain={} decomp={} opening={} commitment_model={:?} bkmsis_target={} max_msg={} max_leaves={}",
            params.manifest.family_label,
            params.manifest.spec_label,
            params.manifest.commitment_scheme_label,
            params.manifest.challenge_schedule_label,
            params.manifest.maturity_label,
            params.security_bits,
            params.ring_profile,
            params.matrix_rows,
            params.matrix_cols,
            params.challenge_bits,
            params.fold_challenge_count,
            params.max_fold_arity,
            params.transcript_domain_label,
            params.decomposition_bits,
            params.opening_randomness_bits,
            params.commitment_security_model,
            params.commitment_bkmsis_target_bits,
            params.max_commitment_message_ring_elems,
            params.max_claimed_receipt_root_leaves,
        );
    }
}
