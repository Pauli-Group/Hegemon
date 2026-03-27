use anyhow::{anyhow, ensure, Context, Result};
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use superneo_backend_lattice::{
    canonical_opening_randomness_seed, commit_packed_witness_with_seed, review_fold_challenges,
    review_fold_proof_digest, review_fold_rows, review_fold_statement_digest, CommitmentOpening,
    LatticeBackend, LatticeCommitment, LeafDigestProof, NativeBackendParams, RingElem,
};
use superneo_ccs::{Relation, RelationId, ShapeDigest, StatementDigest};
use superneo_core::{Backend, FoldedInstance, LeafArtifact};
use superneo_hegemon::{
    experimental_native_tx_leaf_verifier_profile_for_params, native_leaf_proof_digest_for_review,
    native_tx_validity_statement_from_witness_with_params,
    serialized_stark_inputs_from_witness_for_review, CanonicalTxValidityReceipt,
    NativeTxLeafArtifact, NativeTxLeafOpening, NativeTxLeafRecord, NativeTxValidityRelation,
    ReceiptRootArtifact, ReceiptRootFoldStep, ReceiptRootLeaf,
};
use superneo_ring::{
    GoldilocksPackingConfig, GoldilocksPayPerBitPacker, PackedWidthSummary, WitnessPacker,
};
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::bytes48_to_felts;
use transaction_circuit::note::{
    InputNoteWitness, MerklePath, NoteData, OutputNoteWitness, MERKLE_TREE_DEPTH,
};
use transaction_circuit::proof::SerializedStarkInputs;
use transaction_circuit::{StablecoinPolicyBinding, TransactionWitness};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSecurityClaim {
    pub claimed_security_bits: u32,
    pub transcript_soundness_bits: u32,
    pub opening_hiding_bits: u32,
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
pub struct ReviewTxContext {
    pub backend_params: ReviewBackendParams,
    pub expected_version: u16,
    pub params_fingerprint_hex: String,
    pub spec_digest_hex: String,
    pub relation_id_hex: String,
    pub shape_digest_hex: String,
    pub statement_digest_hex: String,
    pub receipt: ReviewReceipt,
    pub stark_public_inputs: ReviewSerializedStarkInputs,
    pub ciphertext_hashes_hex: Vec<String>,
    pub witness_version_circuit: u16,
    pub witness_version_crypto: u16,
    pub opening_sk_spend_hex: String,
    pub opening_inputs: Vec<ReviewInputNoteWitness>,
    pub opening_outputs: Vec<ReviewOutputNoteWitness>,
    pub packed_witness: ReviewPackedWitness,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewReceiptLeafContext {
    pub statement_digest_hex: String,
    pub witness_commitment_hex: String,
    pub proof_digest_hex: String,
    pub commitment_rows: Vec<Vec<u64>>,
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
pub struct ReviewPackedWitness {
    pub coeffs: Vec<u64>,
    pub coeff_capacity_bits: u16,
    pub value_bit_widths: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewInputNoteWitness {
    pub note: ReviewNoteData,
    pub position: u64,
    pub rho_seed_hex: String,
    pub merkle_siblings_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewOutputNoteWitness {
    pub note: ReviewNoteData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewNoteData {
    pub value: u64,
    pub asset_id: u64,
    pub pk_recipient_hex: String,
    pub pk_auth_hex: String,
    pub rho_hex: String,
    pub r_hex: String,
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
    let artifact_bytes = hex::decode(&case.artifact_hex)
        .with_context(|| format!("case {} artifact_hex is not valid hex", case.name))?;
    match case.kind.as_str() {
        "native_tx_leaf" => verify_native_tx_leaf_case(case, &artifact_bytes),
        "receipt_root" => verify_receipt_root_case(case, &artifact_bytes),
        other => Err(anyhow!("unsupported review vector kind {other}")),
    }
}

fn verify_native_tx_leaf_case(case: &ReviewVectorCase, artifact_bytes: &[u8]) -> Result<()> {
    let ctx = case
        .tx_context
        .as_ref()
        .ok_or_else(|| anyhow!("native_tx_leaf case {} is missing tx_context", case.name))?;
    let params = review_params_to_native(&ctx.backend_params)?;
    let artifact = parse_native_tx_leaf_artifact(artifact_bytes)?;
    let relation = NativeTxValidityRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&params.security_params(), relation.shape())?;

    ensure!(
        artifact.version == ctx.expected_version,
        "native tx-leaf version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == decode_hex_array::<48>(&ctx.params_fingerprint_hex)?,
        "native tx-leaf parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "native tx-leaf spec digest mismatch"
    );
    ensure!(
        artifact.relation_id == decode_hex_array::<32>(&ctx.relation_id_hex)?,
        "native tx-leaf relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == decode_hex_array::<32>(&ctx.shape_digest_hex)?,
        "native tx-leaf shape digest mismatch"
    );
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "native tx-leaf relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "native tx-leaf shape digest mismatch"
    );
    ensure!(
        artifact.leaf.version == ctx.expected_version,
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

    let witness = review_tx_context_to_witness(ctx)?;
    let expected_stark_inputs = serialized_stark_inputs_from_witness_for_review(&witness)?;
    ensure!(
        expected_stark_inputs == artifact.stark_public_inputs,
        "native tx-leaf serialized STARK inputs mismatch"
    );
    ensure!(
        expected_stark_inputs == stark_inputs_from_review(&ctx.stark_public_inputs)?,
        "native tx-leaf review-context STARK inputs mismatch"
    );
    let expected_opening = opening_from_tx_context(ctx)?;
    ensure!(
        opening_matches(&artifact.opening, &expected_opening),
        "native tx-leaf opening mismatch"
    );

    let statement = native_tx_validity_statement_from_witness_with_params(&witness, &params)?;
    let encoding = relation.encode_statement(&statement)?;
    ensure!(
        artifact.statement_digest == decode_hex_array::<48>(&ctx.statement_digest_hex)?,
        "native tx-leaf statement digest mismatch"
    );
    ensure!(
        artifact.statement_digest == encoding.statement_digest.0,
        "native tx-leaf statement digest mismatch"
    );
    ensure!(
        artifact.leaf.statement_digest == encoding.statement_digest,
        "native tx-leaf inner statement digest mismatch"
    );

    let expected_receipt = CanonicalTxValidityReceipt {
        statement_hash: statement.statement_hash,
        proof_digest: decode_hex_array::<48>(&ctx.receipt.proof_digest_hex)?,
        public_inputs_digest: statement.public_inputs_digest,
        verifier_profile: experimental_native_tx_leaf_verifier_profile_for_params(&params),
    };
    ensure!(
        artifact.receipt.statement_hash == decode_hex_array::<48>(&ctx.receipt.statement_hash_hex)?,
        "native tx-leaf statement hash mismatch"
    );
    ensure!(
        artifact.receipt.public_inputs_digest
            == decode_hex_array::<48>(&ctx.receipt.public_inputs_digest_hex)?,
        "native tx-leaf public inputs digest mismatch"
    );
    ensure!(
        artifact.receipt.verifier_profile
            == decode_hex_array::<48>(&ctx.receipt.verifier_profile_hex)?,
        "native tx-leaf verifier profile mismatch"
    );
    ensure!(
        artifact.receipt.statement_hash == expected_receipt.statement_hash,
        "native tx-leaf statement hash mismatch"
    );
    ensure!(
        artifact.receipt.public_inputs_digest == expected_receipt.public_inputs_digest,
        "native tx-leaf public inputs digest mismatch"
    );
    ensure!(
        artifact.receipt.verifier_profile == expected_receipt.verifier_profile,
        "native tx-leaf verifier profile mismatch"
    );

    let assignment = relation.build_assignment(&statement, &witness)?;
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let packed = packer.pack(relation.shape(), &assignment)?;
    ensure!(
        packed == packed_witness_from_review(&ctx.packed_witness),
        "native tx-leaf packed witness mismatch"
    );
    ensure!(
        packed == artifact.commitment_opening.packed_witness,
        "native tx-leaf packed witness opening mismatch"
    );

    ensure!(
        artifact.commitment_opening.randomness_seed
            == canonical_opening_randomness_seed(
                &params,
                artifact.commitment_opening.randomness_seed,
            ),
        "randomness seed is not canonical"
    );
    let (expected_commitment, expected_opening) = commit_packed_witness_with_seed(
        &params,
        &packed,
        artifact.commitment_opening.randomness_seed,
    )?;
    ensure!(
        artifact.commitment == expected_commitment,
        "native tx-leaf commitment mismatch"
    );
    ensure!(
        artifact.commitment_opening == expected_opening,
        "native tx-leaf commitment opening mismatch"
    );
    ensure!(
        artifact.leaf.proof.witness_commitment_digest == artifact.commitment.digest,
        "native tx-leaf proof/commitment digest mismatch"
    );

    let expected_proof_digest = native_leaf_proof_digest_for_review(
        &params,
        &relation.relation_id(),
        &encoding.statement_digest,
        &artifact.commitment.digest,
        &artifact.commitment_opening.opening_digest,
    );
    ensure!(
        artifact.leaf.proof.proof_digest == expected_proof_digest,
        "native tx-leaf proof digest mismatch"
    );
    ensure!(
        artifact.receipt.proof_digest == expected_proof_digest,
        "native tx-leaf proof digest mismatch"
    );
    Ok(())
}

fn verify_receipt_root_case(case: &ReviewVectorCase, artifact_bytes: &[u8]) -> Result<()> {
    let ctx = case
        .block_context
        .as_ref()
        .ok_or_else(|| anyhow!("receipt_root case {} is missing block_context", case.name))?;
    let params = review_params_to_native(&ctx.backend_params)?;
    let relation = NativeTxValidityRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&params.security_params(), relation.shape())?;
    let artifact = parse_receipt_root_artifact(artifact_bytes)?;

    ensure!(
        artifact.version == ctx.expected_version,
        "receipt-root artifact version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == decode_hex_array::<48>(&ctx.params_fingerprint_hex)?,
        "native receipt-root parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "native receipt-root spec digest mismatch"
    );
    ensure!(
        artifact.relation_id == decode_hex_array::<32>(&ctx.relation_id_hex)?,
        "native receipt-root relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == decode_hex_array::<32>(&ctx.shape_digest_hex)?,
        "native receipt-root shape digest mismatch"
    );
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "native receipt-root relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "native receipt-root shape digest mismatch"
    );
    ensure!(
        artifact.leaves.len() == ctx.leaves.len(),
        "native receipt-root leaf count mismatch"
    );

    let mut current = Vec::with_capacity(artifact.leaves.len());
    for (leaf, expected) in artifact.leaves.iter().zip(&ctx.leaves) {
        ensure!(
            leaf.statement_digest == decode_hex_array::<48>(&expected.statement_digest_hex)?,
            "native receipt-root leaf statement digest mismatch"
        );
        ensure!(
            leaf.witness_commitment == decode_hex_array::<48>(&expected.witness_commitment_hex)?,
            "native receipt-root leaf witness commitment mismatch"
        );
        ensure!(
            leaf.proof_digest == decode_hex_array::<48>(&expected.proof_digest_hex)?,
            "native receipt-root leaf proof digest mismatch"
        );
        let commitment = LatticeCommitment::from_rows(
            expected
                .commitment_rows
                .iter()
                .cloned()
                .map(RingElem::from_coeffs)
                .collect(),
        );
        ensure!(
            commitment.digest == leaf.witness_commitment,
            "native receipt-root leaf commitment rows mismatch"
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
                let expected_challenges =
                    review_fold_challenges(&params, pk.shape_digest, &left, &right)?;
                ensure!(
                    fold.challenges == expected_challenges,
                    "fold challenge vector mismatch"
                );
                let expected_rows = review_fold_rows(
                    &left.witness_commitment,
                    &right.witness_commitment,
                    &expected_challenges,
                )?;
                ensure!(fold.parent_rows == expected_rows, "parent rows mismatch");
                let expected_commitment = LatticeCommitment::from_rows(expected_rows.clone());
                ensure!(
                    fold.parent_commitment == expected_commitment.digest,
                    "receipt-root parent commitment mismatch"
                );
                let expected_statement_digest = review_fold_statement_digest(
                    &left.statement_digest,
                    &right.statement_digest,
                    &expected_challenges,
                    &expected_commitment.digest,
                );
                ensure!(
                    fold.parent_statement_digest == expected_statement_digest.0,
                    "receipt-root parent statement digest mismatch"
                );
                let expected_proof_digest = review_fold_proof_digest(
                    &params,
                    pk.shape_digest,
                    &relation.relation_id(),
                    &left,
                    &right,
                    &expected_challenges,
                    &expected_statement_digest,
                    &expected_rows,
                )?;
                ensure!(
                    fold.proof_digest == expected_proof_digest,
                    "receipt-root fold proof digest mismatch"
                );
                next.push(FoldedInstance {
                    relation_id: relation.relation_id(),
                    shape_digest: pk.shape_digest,
                    statement_digest: expected_statement_digest,
                    witness_commitment: expected_commitment,
                });
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
        .ok_or_else(|| anyhow!("receipt-root artifact must retain one root"))?;
    ensure!(
        artifact.root_statement_digest == decode_hex_array::<48>(&ctx.root_statement_digest_hex)?,
        "receipt-root root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == decode_hex_array::<48>(&ctx.root_commitment_hex)?,
        "receipt-root root commitment mismatch"
    );
    ensure!(
        artifact.root_statement_digest == root.statement_digest.0,
        "receipt-root root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == root.witness_commitment.digest,
        "receipt-root root commitment mismatch"
    );
    Ok(())
}

pub fn review_params_to_native(review: &ReviewBackendParams) -> Result<NativeBackendParams> {
    let baseline = NativeBackendParams::heuristic_goldilocks_baseline();
    let rewrite = NativeBackendParams::goldilocks_128b_rewrite();
    let mut params = match review.family_label.as_str() {
        "heuristic_goldilocks_baseline" => baseline,
        "goldilocks_128b_rewrite" => rewrite,
        other => {
            let base = if review.security_bits >= 128 {
                rewrite
            } else {
                baseline
            };
            NativeBackendParams {
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
                ..base
            }
        }
    };
    params.security_bits = review.security_bits;
    params.matrix_rows = review.matrix_rows;
    params.matrix_cols = review.matrix_cols;
    params.challenge_bits = review.challenge_bits;
    params.fold_challenge_count = review.fold_challenge_count;
    params.max_fold_arity = review.max_fold_arity;
    params.transcript_domain_label =
        Box::leak(review.transcript_domain_label.clone().into_boxed_str());
    params.decomposition_bits = review.decomposition_bits;
    params.opening_randomness_bits = review.opening_randomness_bits;
    params.validate()?;
    Ok(params)
}

pub fn review_tx_context_to_witness(ctx: &ReviewTxContext) -> Result<TransactionWitness> {
    let stark = stark_inputs_from_review(&ctx.stark_public_inputs)?;
    let value_balance = signed_value(
        stark.value_balance_sign,
        stark.value_balance_magnitude,
        "value_balance_sign",
    )?;
    let issuance_delta = signed_value(
        stark.stablecoin_issuance_sign,
        stark.stablecoin_issuance_magnitude,
        "stablecoin_issuance_sign",
    )?;
    Ok(TransactionWitness {
        inputs: ctx
            .opening_inputs
            .iter()
            .map(input_note_from_review)
            .collect::<Result<Vec<_>>>()?,
        outputs: ctx
            .opening_outputs
            .iter()
            .map(output_note_from_review)
            .collect::<Result<Vec<_>>>()?,
        ciphertext_hashes: ctx
            .ciphertext_hashes_hex
            .iter()
            .map(|value| decode_hex_array::<48>(value))
            .collect::<Result<Vec<_>>>()?,
        sk_spend: decode_hex_array::<32>(&ctx.opening_sk_spend_hex)?,
        merkle_root: decode_hex_array::<48>(&ctx.stark_public_inputs.merkle_root_hex)?,
        fee: stark.fee,
        value_balance,
        stablecoin: StablecoinPolicyBinding {
            enabled: stark.stablecoin_enabled != 0,
            asset_id: stark.stablecoin_asset_id,
            policy_version: stark.stablecoin_policy_version,
            issuance_delta,
            policy_hash: decode_hex_array::<48>(
                &ctx.stark_public_inputs.stablecoin_policy_hash_hex,
            )?,
            oracle_commitment: decode_hex_array::<48>(
                &ctx.stark_public_inputs.stablecoin_oracle_commitment_hex,
            )?,
            attestation_commitment: decode_hex_array::<48>(
                &ctx.stark_public_inputs
                    .stablecoin_attestation_commitment_hex,
            )?,
        },
        version: VersionBinding::new(ctx.witness_version_circuit, ctx.witness_version_crypto),
    })
}

fn opening_from_tx_context(ctx: &ReviewTxContext) -> Result<NativeTxLeafOpening> {
    Ok(NativeTxLeafOpening {
        sk_spend: decode_hex_array::<32>(&ctx.opening_sk_spend_hex)?,
        inputs: ctx
            .opening_inputs
            .iter()
            .map(input_note_from_review)
            .collect::<Result<Vec<_>>>()?,
        outputs: ctx
            .opening_outputs
            .iter()
            .map(output_note_from_review)
            .collect::<Result<Vec<_>>>()?,
    })
}

pub fn review_block_context_to_records(
    ctx: &ReviewBlockContext,
) -> Result<Vec<NativeTxLeafRecord>> {
    let params_fingerprint = decode_hex_array::<48>(&ctx.params_fingerprint_hex)?;
    let spec_digest = decode_hex_array::<32>(&ctx.spec_digest_hex)?;
    let relation_id = decode_hex_array::<32>(&ctx.relation_id_hex)?;
    let shape_digest = decode_hex_array::<32>(&ctx.shape_digest_hex)?;
    ctx.leaves
        .iter()
        .map(|leaf| {
            Ok(NativeTxLeafRecord {
                params_fingerprint,
                spec_digest,
                relation_id,
                shape_digest,
                statement_digest: decode_hex_array::<48>(&leaf.statement_digest_hex)?,
                commitment: LatticeCommitment::from_rows(
                    leaf.commitment_rows
                        .iter()
                        .cloned()
                        .map(RingElem::from_coeffs)
                        .collect(),
                ),
                proof_digest: decode_hex_array::<48>(&leaf.proof_digest_hex)?,
            })
        })
        .collect()
}

fn opening_matches(left: &NativeTxLeafOpening, right: &NativeTxLeafOpening) -> bool {
    left.sk_spend == right.sk_spend
        && left.inputs.len() == right.inputs.len()
        && left
            .inputs
            .iter()
            .zip(&right.inputs)
            .all(|(left_input, right_input)| input_note_matches(left_input, right_input))
        && left.outputs.len() == right.outputs.len()
        && left
            .outputs
            .iter()
            .zip(&right.outputs)
            .all(|(left_output, right_output)| output_note_matches(left_output, right_output))
}

fn input_note_matches(left: &InputNoteWitness, right: &InputNoteWitness) -> bool {
    note_data_matches(&left.note, &right.note)
        && left.position == right.position
        && left.rho_seed == right.rho_seed
        && left.merkle_path.siblings == right.merkle_path.siblings
}

fn output_note_matches(left: &OutputNoteWitness, right: &OutputNoteWitness) -> bool {
    note_data_matches(&left.note, &right.note)
}

fn note_data_matches(left: &NoteData, right: &NoteData) -> bool {
    left.value == right.value
        && left.asset_id == right.asset_id
        && left.pk_recipient == right.pk_recipient
        && left.pk_auth == right.pk_auth
        && left.rho == right.rho
        && left.r == right.r
}

fn stark_inputs_from_review(review: &ReviewSerializedStarkInputs) -> Result<SerializedStarkInputs> {
    ensure!(
        review.input_flags.len() <= MAX_INPUTS,
        "serialized STARK input flag length {} exceeds {}",
        review.input_flags.len(),
        MAX_INPUTS
    );
    ensure!(
        review.output_flags.len() <= MAX_OUTPUTS,
        "serialized STARK output flag length {} exceeds {}",
        review.output_flags.len(),
        MAX_OUTPUTS
    );
    ensure!(
        review.balance_slot_asset_ids.len() <= BALANCE_SLOTS,
        "serialized STARK balance slot length {} exceeds {}",
        review.balance_slot_asset_ids.len(),
        BALANCE_SLOTS
    );
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

fn packed_witness_from_review(review: &ReviewPackedWitness) -> superneo_ring::PackedWitness<u64> {
    let used_bits = review
        .value_bit_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    let mut width_summary = PackedWidthSummary::default();
    for width in &review.value_bit_widths {
        width_summary.max_bit_width = width_summary.max_bit_width.max(*width);
        match *width {
            0 | 1 => width_summary.one_bit_values += 1,
            2..=8 => width_summary.byte_values += 1,
            9..=16 => width_summary.word16_values += 1,
            17..=32 => width_summary.word32_values += 1,
            _ => width_summary.wide_values += 1,
        }
    }
    superneo_ring::PackedWitness {
        coeffs: review.coeffs.clone(),
        original_len: review.value_bit_widths.len(),
        used_bits,
        coeff_capacity_bits: review.coeff_capacity_bits,
        value_bit_widths: review.value_bit_widths.clone(),
        width_summary,
    }
}

fn input_note_from_review(review: &ReviewInputNoteWitness) -> Result<InputNoteWitness> {
    let siblings = review
        .merkle_siblings_hex
        .iter()
        .map(|value| {
            let bytes = decode_hex_array::<48>(value)?;
            bytes48_to_felts(&bytes)
                .ok_or_else(|| anyhow!("native tx-leaf merkle sibling is non-canonical"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        siblings.len() == MERKLE_TREE_DEPTH,
        "native tx-leaf input merkle path length {} does not match {}",
        siblings.len(),
        MERKLE_TREE_DEPTH
    );
    Ok(InputNoteWitness {
        note: note_data_from_review(&review.note)?,
        position: review.position,
        rho_seed: decode_hex_array::<32>(&review.rho_seed_hex)?,
        merkle_path: MerklePath { siblings },
    })
}

fn output_note_from_review(review: &ReviewOutputNoteWitness) -> Result<OutputNoteWitness> {
    Ok(OutputNoteWitness {
        note: note_data_from_review(&review.note)?,
    })
}

fn note_data_from_review(review: &ReviewNoteData) -> Result<NoteData> {
    Ok(NoteData {
        value: review.value,
        asset_id: review.asset_id,
        pk_recipient: decode_hex_array::<32>(&review.pk_recipient_hex)?,
        pk_auth: decode_hex_array::<32>(&review.pk_auth_hex)?,
        rho: decode_hex_array::<32>(&review.rho_hex)?,
        r: decode_hex_array::<32>(&review.r_hex)?,
    })
}

fn signed_value(sign: u8, magnitude: u64, label: &str) -> Result<i128> {
    ensure!(sign <= 1, "{label} must be binary");
    Ok(if sign == 0 {
        i128::from(magnitude)
    } else {
        -i128::from(magnitude)
    })
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes =
        hex::decode(value).with_context(|| format!("hex string has invalid encoding: {value}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow!("hex string has {} bytes, expected {}", len, N))
}

fn parse_native_tx_leaf_artifact(bytes: &[u8]) -> Result<NativeTxLeafArtifact> {
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let params_fingerprint = read_array::<48>(bytes, &mut cursor)?;
    let spec_digest = read_array::<32>(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let statement_digest = read_array::<48>(bytes, &mut cursor)?;
    let receipt = parse_canonical_receipt(bytes, &mut cursor)?;
    let stark_public_inputs = parse_serialized_stark_inputs(bytes, &mut cursor)?;
    let opening = parse_native_tx_leaf_opening(bytes, &mut cursor)?;
    let commitment_opening = parse_commitment_opening(bytes, &mut cursor)?;
    let commitment = parse_lattice_commitment(bytes, &mut cursor)?;
    let leaf = parse_leaf_artifact(bytes, &mut cursor)?;
    ensure!(
        cursor == bytes.len(),
        "native tx-leaf artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(NativeTxLeafArtifact {
        version,
        params_fingerprint,
        spec_digest,
        relation_id,
        shape_digest,
        statement_digest,
        receipt,
        stark_public_inputs,
        opening,
        commitment_opening,
        commitment,
        leaf,
    })
}

fn parse_receipt_root_artifact(bytes: &[u8]) -> Result<ReceiptRootArtifact> {
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let params_fingerprint = read_array::<48>(bytes, &mut cursor)?;
    let spec_digest = read_array::<32>(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let leaf_count = read_u32(bytes, &mut cursor)? as usize;
    let fold_count = read_u32(bytes, &mut cursor)? as usize;
    let mut leaves = Vec::with_capacity(leaf_count);
    for _ in 0..leaf_count {
        leaves.push(ReceiptRootLeaf {
            statement_digest: read_array::<48>(bytes, &mut cursor)?,
            witness_commitment: read_array::<48>(bytes, &mut cursor)?,
            proof_digest: read_array::<48>(bytes, &mut cursor)?,
        });
    }
    let mut folds = Vec::with_capacity(fold_count);
    for _ in 0..fold_count {
        folds.push(parse_receipt_root_fold_step(bytes, &mut cursor)?);
    }
    let root_statement_digest = read_array::<48>(bytes, &mut cursor)?;
    let root_commitment = read_array::<48>(bytes, &mut cursor)?;
    ensure!(
        cursor == bytes.len(),
        "receipt-root artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(ReceiptRootArtifact {
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
    let input_flag_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        input_flag_count <= MAX_INPUTS,
        "serialized STARK input flag length {} exceeds {}",
        input_flag_count,
        MAX_INPUTS
    );
    let input_flags = read_bytes(bytes, cursor, input_flag_count)?;
    let output_flag_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        output_flag_count <= MAX_OUTPUTS,
        "serialized STARK output flag length {} exceeds {}",
        output_flag_count,
        MAX_OUTPUTS
    );
    let output_flags = read_bytes(bytes, cursor, output_flag_count)?;
    let fee = read_u64(bytes, cursor)?;
    let value_balance_sign = read_u8(bytes, cursor)?;
    let value_balance_magnitude = read_u64(bytes, cursor)?;
    let merkle_root = read_array::<48>(bytes, cursor)?;
    let balance_slot_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        balance_slot_count <= BALANCE_SLOTS,
        "serialized STARK balance slot length {} exceeds {}",
        balance_slot_count,
        BALANCE_SLOTS
    );
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

fn parse_native_tx_leaf_opening(bytes: &[u8], cursor: &mut usize) -> Result<NativeTxLeafOpening> {
    let sk_spend = read_array::<32>(bytes, cursor)?;
    let input_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        input_count <= MAX_INPUTS,
        "native tx-leaf opening input count {} exceeds {}",
        input_count,
        MAX_INPUTS
    );
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(parse_input_note_witness(bytes, cursor)?);
    }
    let output_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        output_count <= MAX_OUTPUTS,
        "native tx-leaf opening output count {} exceeds {}",
        output_count,
        MAX_OUTPUTS
    );
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(parse_output_note_witness(bytes, cursor)?);
    }
    Ok(NativeTxLeafOpening {
        sk_spend,
        inputs,
        outputs,
    })
}

fn parse_commitment_opening(bytes: &[u8], cursor: &mut usize) -> Result<CommitmentOpening> {
    Ok(CommitmentOpening {
        params_fingerprint: read_array::<48>(bytes, cursor)?,
        packed_witness: parse_packed_witness(bytes, cursor)?,
        randomness_seed: read_array::<32>(bytes, cursor)?,
        opening_digest: read_array::<48>(bytes, cursor)?,
    })
}

fn parse_packed_witness(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<superneo_ring::PackedWitness<u64>> {
    let coeff_count = read_u32(bytes, cursor)? as usize;
    let mut coeffs = Vec::with_capacity(coeff_count);
    for _ in 0..coeff_count {
        coeffs.push(read_u64(bytes, cursor)?);
    }
    let coeff_capacity_bits = u16::from_le_bytes(read_array::<2>(bytes, cursor)?);
    let width_count = read_u32(bytes, cursor)? as usize;
    let mut value_bit_widths = Vec::with_capacity(width_count);
    for _ in 0..width_count {
        value_bit_widths.push(u16::from_le_bytes(read_array::<2>(bytes, cursor)?));
    }
    let used_bits = value_bit_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    let mut width_summary = PackedWidthSummary::default();
    for width in &value_bit_widths {
        width_summary.max_bit_width = width_summary.max_bit_width.max(*width);
        match *width {
            0 | 1 => width_summary.one_bit_values += 1,
            2..=8 => width_summary.byte_values += 1,
            9..=16 => width_summary.word16_values += 1,
            17..=32 => width_summary.word32_values += 1,
            _ => width_summary.wide_values += 1,
        }
    }
    Ok(superneo_ring::PackedWitness {
        coeffs,
        original_len: value_bit_widths.len(),
        used_bits,
        coeff_capacity_bits,
        value_bit_widths,
        width_summary,
    })
}

fn parse_input_note_witness(bytes: &[u8], cursor: &mut usize) -> Result<InputNoteWitness> {
    let note = parse_note_data(bytes, cursor)?;
    let position = read_u64(bytes, cursor)?;
    let rho_seed = read_array::<32>(bytes, cursor)?;
    let sibling_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        sibling_count == MERKLE_TREE_DEPTH,
        "native tx-leaf input merkle path length {} does not match {}",
        sibling_count,
        MERKLE_TREE_DEPTH
    );
    let mut siblings = Vec::with_capacity(sibling_count);
    for _ in 0..sibling_count {
        let sibling_bytes = read_array::<48>(bytes, cursor)?;
        let sibling = bytes48_to_felts(&sibling_bytes)
            .ok_or_else(|| anyhow!("native tx-leaf merkle sibling is non-canonical"))?;
        siblings.push(sibling);
    }
    Ok(InputNoteWitness {
        note,
        position,
        rho_seed,
        merkle_path: MerklePath { siblings },
    })
}

fn parse_output_note_witness(bytes: &[u8], cursor: &mut usize) -> Result<OutputNoteWitness> {
    Ok(OutputNoteWitness {
        note: parse_note_data(bytes, cursor)?,
    })
}

fn parse_note_data(bytes: &[u8], cursor: &mut usize) -> Result<NoteData> {
    Ok(NoteData {
        value: read_u64(bytes, cursor)?,
        asset_id: read_u64(bytes, cursor)?,
        pk_recipient: read_array::<32>(bytes, cursor)?,
        pk_auth: read_array::<32>(bytes, cursor)?,
        rho: read_array::<32>(bytes, cursor)?,
        r: read_array::<32>(bytes, cursor)?,
    })
}

fn parse_lattice_commitment(bytes: &[u8], cursor: &mut usize) -> Result<LatticeCommitment> {
    let digest = read_array::<48>(bytes, cursor)?;
    let row_count = read_u32(bytes, cursor)? as usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let coeff_count = read_u32(bytes, cursor)? as usize;
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

fn parse_receipt_root_fold_step(bytes: &[u8], cursor: &mut usize) -> Result<ReceiptRootFoldStep> {
    let challenge_count = read_u32(bytes, cursor)? as usize;
    let mut challenges = Vec::with_capacity(challenge_count);
    for _ in 0..challenge_count {
        challenges.push(read_u64(bytes, cursor)?);
    }
    let parent_statement_digest = read_array::<48>(bytes, cursor)?;
    let parent_commitment = read_array::<48>(bytes, cursor)?;
    let row_count = read_u32(bytes, cursor)? as usize;
    let mut parent_rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let coeff_count = read_u32(bytes, cursor)? as usize;
        let mut coeffs = Vec::with_capacity(coeff_count);
        for _ in 0..coeff_count {
            coeffs.push(read_u64(bytes, cursor)?);
        }
        parent_rows.push(RingElem::from_coeffs(coeffs));
    }
    Ok(ReceiptRootFoldStep {
        challenges,
        parent_statement_digest,
        parent_commitment,
        parent_rows,
        proof_digest: read_array::<48>(bytes, cursor)?,
    })
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    Ok(read_array::<1>(bytes, cursor)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, cursor)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
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
}
