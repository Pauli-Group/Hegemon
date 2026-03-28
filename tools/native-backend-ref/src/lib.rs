use anyhow::{anyhow, ensure, Context, Result};
use blake3::Hasher;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use superneo_backend_lattice::{
    BackendKey, CommitmentOpening, LatticeCommitment, LeafDigestProof, NativeBackendParams,
    RingElem,
};
use superneo_ccs::{digest_shape, Relation, RelationId, ShapeDigest, StatementDigest};
use superneo_core::{FoldedInstance, LeafArtifact};
use superneo_hegemon::{
    CanonicalTxValidityReceipt, NativeTxLeafArtifact, NativeTxLeafOpening, NativeTxLeafRecord,
    NativeTxValidityRelation, NativeTxValidityStatement, ReceiptRootArtifact, ReceiptRootFoldStep,
    ReceiptRootLeaf,
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
    #[serde(default = "default_commitment_assumption_bits")]
    pub commitment_assumption_bits: u32,
    #[serde(default)]
    pub derive_commitment_binding_from_geometry: bool,
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
    let shape_digest = digest_shape(relation.shape());

    ensure!(
        artifact.version == ctx.expected_version,
        "native tx-leaf version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == decode_hex_array::<48>(&ctx.params_fingerprint_hex)?,
        "native tx-leaf parameter fingerprint mismatch"
    );
    ensure!(
        artifact.params_fingerprint == review_parameter_fingerprint(&params),
        "native tx-leaf parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "native tx-leaf spec digest mismatch"
    );
    ensure!(
        artifact.spec_digest == review_spec_digest(&params),
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
        artifact.shape_digest == shape_digest.0,
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
        artifact.leaf.shape_digest == shape_digest,
        "native tx-leaf inner shape digest mismatch"
    );

    let witness = review_tx_context_to_witness(ctx)?;
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| anyhow!("failed to derive native tx public inputs: {err}"))?;
    let expected_stark_inputs =
        review_serialized_stark_inputs_from_witness(&witness, &public_inputs)?;
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

    let statement = review_native_tx_validity_statement_from_witness(&witness, &params)?;
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
        verifier_profile: review_verifier_profile(
            &params,
            &relation.relation_id(),
            &shape_digest,
            b"native-tx-leaf",
        ),
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
            == review_canonical_opening_randomness_seed(
                &params,
                artifact.commitment_opening.randomness_seed,
            ),
        "randomness seed is not canonical"
    );
    let (expected_commitment, expected_opening) = review_commit_packed_witness_with_seed(
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

    let expected_proof_digest = review_native_leaf_proof_digest(
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
    let shape_digest = digest_shape(relation.shape());
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
        artifact.params_fingerprint == review_parameter_fingerprint(&params),
        "native receipt-root parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "native receipt-root spec digest mismatch"
    );
    ensure!(
        artifact.spec_digest == review_spec_digest(&params),
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
        artifact.shape_digest == shape_digest.0,
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
            shape_digest,
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
                    review_fold_challenges(&params, shape_digest, &left, &right)?;
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
                    shape_digest,
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
                    shape_digest,
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
    params.commitment_assumption_bits = review.commitment_assumption_bits;
    params.derive_commitment_binding_from_geometry = review.derive_commitment_binding_from_geometry;
    params.max_commitment_message_ring_elems = review.max_commitment_message_ring_elems;
    params.max_claimed_receipt_root_leaves = review.max_claimed_receipt_root_leaves;
    validate_review_params(&params)?;
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

fn default_commitment_assumption_bits() -> u32 {
    128
}

fn default_max_commitment_message_ring_elems() -> u32 {
    513
}

fn default_max_claimed_receipt_root_leaves() -> u32 {
    128
}

const GOLDILOCKS_MODULUS_I128: i128 = 18_446_744_069_414_584_321;
const COMMITMENT_WINDOW_COLUMNS: usize = 32;

#[derive(Clone, Debug)]
struct ReviewEmbeddedRingElem {
    ring: RingElem,
    source_width_bits: u16,
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
    hasher.update(&params.commitment_assumption_bits.to_le_bytes());
    hasher.update(&[params.derive_commitment_binding_from_geometry as u8]);
    hasher.update(&params.max_commitment_message_ring_elems.to_le_bytes());
    hasher.update(&params.max_claimed_receipt_root_leaves.to_le_bytes());
    review_hash48(hasher)
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
    hasher.update(&params.commitment_assumption_bits.to_le_bytes());
    hasher.update(&[params.derive_commitment_binding_from_geometry as u8]);
    hasher.update(&params.max_commitment_message_ring_elems.to_le_bytes());
    hasher.update(&params.max_claimed_receipt_root_leaves.to_le_bytes());
    review_hash32(hasher)
}

fn review_ring_profile_label(profile: superneo_backend_lattice::RingProfile) -> &'static [u8] {
    match profile {
        superneo_backend_lattice::RingProfile::GoldilocksCyclotomic24 => b"goldilocks-cyclotomic24",
        superneo_backend_lattice::RingProfile::GoldilocksFrog => b"goldilocks-frog",
    }
}

fn parse_review_ring_profile(value: &str) -> Result<superneo_backend_lattice::RingProfile> {
    match value {
        "GoldilocksCyclotomic24" => {
            Ok(superneo_backend_lattice::RingProfile::GoldilocksCyclotomic24)
        }
        "GoldilocksFrog" => Ok(superneo_backend_lattice::RingProfile::GoldilocksFrog),
        other => Err(anyhow!("unsupported ring_profile {other}")),
    }
}

fn review_digest32_with_label(label: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(payload);
    review_hash32(hasher)
}

fn review_digest48_with_parts(label: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    for part in parts {
        hasher.update(part);
    }
    review_hash48(hasher)
}

fn review_hash48(hasher: Hasher) -> [u8; 48] {
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn review_hash32(hasher: Hasher) -> [u8; 32] {
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn review_bla3_384_bytes(bytes: &[u8]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    review_hash48(hasher)
}

fn review_verifier_profile(
    params: &NativeBackendParams,
    relation_id: &RelationId,
    shape_digest: &ShapeDigest,
    profile_label: &[u8],
) -> [u8; 48] {
    review_digest48_with_parts(
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

fn review_serialized_stark_inputs_from_witness(
    witness: &TransactionWitness,
    public_inputs: &transaction_circuit::public_inputs::TransactionPublicInputs,
) -> Result<SerializedStarkInputs> {
    ensure!(
        public_inputs.balance_slots.len() == BALANCE_SLOTS,
        "native tx public inputs balance slot count {} does not match {}",
        public_inputs.balance_slots.len(),
        BALANCE_SLOTS
    );
    let value_balance_sign = u8::from(witness.value_balance < 0);
    let value_balance_magnitude = witness.value_balance.unsigned_abs() as u64;
    let stablecoin_issuance_sign = u8::from(witness.stablecoin.issuance_delta < 0);
    let stablecoin_issuance_magnitude = witness.stablecoin.issuance_delta.unsigned_abs() as u64;
    Ok(SerializedStarkInputs {
        input_flags: (0..MAX_INPUTS)
            .map(|idx| u8::from(idx < witness.inputs.len()))
            .collect(),
        output_flags: (0..MAX_OUTPUTS)
            .map(|idx| u8::from(idx < witness.outputs.len()))
            .collect(),
        fee: witness.fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root: witness.merkle_root,
        balance_slot_asset_ids: public_inputs
            .balance_slots
            .iter()
            .map(|slot| slot.asset_id)
            .collect(),
        stablecoin_enabled: u8::from(witness.stablecoin.enabled),
        stablecoin_asset_id: witness.stablecoin.asset_id,
        stablecoin_policy_version: witness.stablecoin.policy_version,
        stablecoin_issuance_sign,
        stablecoin_issuance_magnitude,
        stablecoin_policy_hash: witness.stablecoin.policy_hash,
        stablecoin_oracle_commitment: witness.stablecoin.oracle_commitment,
        stablecoin_attestation_commitment: witness.stablecoin.attestation_commitment,
    })
}

fn review_transaction_statement_hash_from_public_inputs(
    public_inputs: &transaction_circuit::public_inputs::TransactionPublicInputs,
) -> [u8; 48] {
    let mut message = Vec::new();
    message.extend_from_slice(transaction_circuit::proof::TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&public_inputs.merkle_root);
    for nf in &public_inputs.nullifiers {
        message.extend_from_slice(nf);
    }
    for cm in &public_inputs.commitments {
        message.extend_from_slice(cm);
    }
    for ct in &public_inputs.ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    message.extend_from_slice(&public_inputs.native_fee.to_le_bytes());
    message.extend_from_slice(&public_inputs.value_balance.to_le_bytes());
    message.extend_from_slice(&public_inputs.balance_tag);
    message.extend_from_slice(&public_inputs.circuit_version.to_le_bytes());
    message.extend_from_slice(&public_inputs.crypto_suite.to_le_bytes());
    message.push(public_inputs.stablecoin.enabled as u8);
    message.extend_from_slice(&public_inputs.stablecoin.asset_id.to_le_bytes());
    message.extend_from_slice(&public_inputs.stablecoin.policy_hash);
    message.extend_from_slice(&public_inputs.stablecoin.oracle_commitment);
    message.extend_from_slice(&public_inputs.stablecoin.attestation_commitment);
    message.extend_from_slice(&public_inputs.stablecoin.issuance_delta.to_le_bytes());
    message.extend_from_slice(&public_inputs.stablecoin.policy_version.to_le_bytes());
    review_bla3_384_bytes(&message)
}

fn review_native_tx_validity_statement_from_witness(
    witness: &TransactionWitness,
    params: &NativeBackendParams,
) -> Result<NativeTxValidityStatement> {
    witness
        .validate()
        .map_err(|err| anyhow!("native tx witness validation failed: {err}"))?;
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| anyhow!("failed to derive native tx public inputs: {err}"))?;
    let serialized = review_serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    Ok(NativeTxValidityStatement {
        statement_hash: review_transaction_statement_hash_from_public_inputs(&public_inputs),
        public_inputs_digest:
            transaction_circuit::proof::transaction_public_inputs_digest_from_serialized(
                &serialized,
            )
            .map_err(|err| anyhow!("failed to hash native tx public inputs: {err}"))?,
        verifier_profile: review_verifier_profile(
            params,
            &NativeTxValidityRelation::default().relation_id(),
            &digest_shape(NativeTxValidityRelation::default().shape()),
            b"native-tx",
        ),
    })
}

fn review_canonical_opening_randomness_seed(
    params: &NativeBackendParams,
    randomness_seed: [u8; 32],
) -> [u8; 32] {
    let allowed_bits = params.opening_randomness_bits.min(256) as usize;
    if allowed_bits >= 256 {
        return randomness_seed;
    }
    let mut canonical = [0u8; 32];
    let full_bytes = allowed_bits / 8;
    let partial_bits = allowed_bits % 8;
    if full_bytes > 0 {
        canonical[..full_bytes].copy_from_slice(&randomness_seed[..full_bytes]);
    }
    if partial_bits > 0 && full_bytes < canonical.len() {
        canonical[full_bytes] = randomness_seed[full_bytes] & ((1u8 << partial_bits) - 1);
    }
    canonical
}

fn review_commitment_opening_digest(
    params: &NativeBackendParams,
    packed: &superneo_ring::PackedWitness<u64>,
    randomness_seed: &[u8; 32],
) -> [u8; 48] {
    let randomness_seed = review_canonical_opening_randomness_seed(params, *randomness_seed);
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.commitment-opening.v1");
    hasher.update(&review_parameter_fingerprint(params));
    hasher.update(&(packed.original_len as u64).to_le_bytes());
    hasher.update(&(packed.used_bits as u64).to_le_bytes());
    hasher.update(&(packed.coeffs.len() as u64).to_le_bytes());
    for coeff in &packed.coeffs {
        hasher.update(&coeff.to_le_bytes());
    }
    hasher.update(&(packed.value_bit_widths.len() as u64).to_le_bytes());
    for width in &packed.value_bit_widths {
        hasher.update(&width.to_le_bytes());
    }
    hasher.update(&packed.coeff_capacity_bits.to_le_bytes());
    hasher.update(&randomness_seed);
    review_hash48(hasher)
}

fn review_reduce_goldilocks_signed(value: i128) -> u64 {
    let mut reduced = value % GOLDILOCKS_MODULUS_I128;
    if reduced < 0 {
        reduced += GOLDILOCKS_MODULUS_I128;
    }
    reduced as u64
}

fn review_reduce_goldilocks_u128(value: u128) -> u64 {
    (value % (GOLDILOCKS_MODULUS_I128 as u128)) as u64
}

fn review_goldilocks_from_signed(value: i128) -> Goldilocks {
    Goldilocks::new(review_reduce_goldilocks_signed(value))
}

fn review_operand_bit_width(value: u64) -> u16 {
    let width = u64::BITS - value.leading_zeros();
    width.max(1) as u16
}

fn review_expand_packed_bits(packed: &superneo_ring::PackedWitness<u64>) -> Result<Vec<u8>> {
    ensure!(
        (1..=64).contains(&packed.coeff_capacity_bits),
        "packed witness coeff capacity must be in 1..=64"
    );
    let coeff_capacity = packed.coeff_capacity_bits as usize;
    let mut bits = Vec::with_capacity(packed.used_bits);
    for bit_index in 0..packed.used_bits {
        let coeff_index = bit_index / coeff_capacity;
        let bit_offset = (bit_index % coeff_capacity) as u16;
        let coeff = *packed
            .coeffs
            .get(coeff_index)
            .ok_or_else(|| anyhow!("packed witness ended early while expanding bits"))?;
        bits.push(((coeff >> bit_offset) & 1) as u8);
    }
    Ok(bits)
}

fn review_expand_packed_bit_source_widths(
    packed: &superneo_ring::PackedWitness<u64>,
) -> Result<Vec<u16>> {
    let total_value_bits = packed
        .value_bit_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    ensure!(
        total_value_bits == packed.used_bits,
        "packed witness width metadata covers {} bits but used_bits is {}",
        total_value_bits,
        packed.used_bits
    );
    let mut bit_source_widths = Vec::with_capacity(packed.used_bits);
    for width in &packed.value_bit_widths {
        bit_source_widths.extend(std::iter::repeat_n(*width, usize::from(*width)));
    }
    Ok(bit_source_widths)
}

fn review_expand_packed_digits(
    packed: &superneo_ring::PackedWitness<u64>,
    digit_bits: u16,
) -> Result<(Vec<u64>, Vec<u16>)> {
    ensure!(
        (1..=16).contains(&digit_bits),
        "digit_bits must be in 1..=16"
    );
    let bits = review_expand_packed_bits(packed)?;
    let bit_source_widths = review_expand_packed_bit_source_widths(packed)?;
    let mut digits = Vec::with_capacity(bits.len().div_ceil(digit_bits as usize));
    let mut digit_source_widths = Vec::with_capacity(bits.len().div_ceil(digit_bits as usize));
    let mut cursor = 0usize;
    while cursor < bits.len() {
        let mut digit = 0u64;
        let mut source_width_bits = 1u16;
        for offset in 0..digit_bits as usize {
            let bit_index = cursor + offset;
            if bit_index >= bits.len() {
                break;
            }
            digit |= u64::from(bits[bit_index]) << offset;
            source_width_bits = source_width_bits.max(bit_source_widths[bit_index]);
        }
        digits.push(digit);
        digit_source_widths.push(source_width_bits);
        cursor += digit_bits as usize;
    }
    Ok((digits, digit_source_widths))
}

fn review_embed_packed_witness_with_layout(
    ring_degree: usize,
    digit_bits: u16,
    packed: &superneo_ring::PackedWitness<u64>,
) -> Result<Vec<ReviewEmbeddedRingElem>> {
    ensure!(
        packed.value_bit_widths.len() == packed.original_len,
        "packed witness width metadata length {} does not match original_len {}",
        packed.value_bit_widths.len(),
        packed.original_len
    );
    ensure!(ring_degree > 0, "ring degree must be strictly positive");
    let (digits, digit_source_widths) = review_expand_packed_digits(packed, digit_bits)?;
    let mut ring_elems = Vec::with_capacity(digits.len().div_ceil(ring_degree));
    for (chunk_index, chunk) in digits.chunks(ring_degree).enumerate() {
        let mut coeffs = vec![0u64; ring_degree];
        for (idx, digit) in chunk.iter().enumerate() {
            coeffs[idx] = *digit;
        }
        let source_width_bits = digit_source_widths
            .iter()
            .skip(chunk_index * ring_degree)
            .take(chunk.len())
            .copied()
            .max()
            .unwrap_or(1);
        ring_elems.push(ReviewEmbeddedRingElem {
            ring: RingElem::from_coeffs(coeffs),
            source_width_bits,
        });
    }
    Ok(ring_elems)
}

fn review_backend_key_for_shape(
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
    native_commitment_domain: bool,
) -> BackendKey {
    let label = if native_commitment_domain {
        b"hegemon.superneo.native-commitment-domain.v1".as_slice()
    } else {
        b"hegemon.superneo.transcript-domain.v1".as_slice()
    };
    BackendKey {
        params_fingerprint: review_parameter_fingerprint(params),
        shape_digest,
        security_bits: params.security_bits,
        challenge_bits: params.challenge_bits,
        fold_challenge_count: params.fold_challenge_count,
        max_fold_arity: params.max_fold_arity,
        transcript_domain_digest: review_digest32_with_label(
            label,
            params.transcript_domain_label.as_bytes(),
        ),
        ring_profile: params.ring_profile,
        commitment_rows: params.matrix_rows,
        ring_degree: params.matrix_cols,
        digit_bits: params.decomposition_bits as u16,
        opening_randomness_bits: params.opening_randomness_bits,
    }
}

fn review_matrix_entry(pk: &BackendKey, row_index: usize, col_index: usize) -> RingElem {
    let mut coeffs = Vec::with_capacity(pk.ring_degree);
    for coeff_index in 0..pk.ring_degree {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.ajtai-matrix.v1");
        hasher.update(&pk.params_fingerprint);
        hasher.update(review_ring_profile_label(pk.ring_profile));
        hasher.update(&pk.shape_digest.0);
        hasher.update(&pk.security_bits.to_le_bytes());
        hasher.update(&pk.challenge_bits.to_le_bytes());
        hasher.update(&pk.max_fold_arity.to_le_bytes());
        hasher.update(&pk.transcript_domain_digest);
        hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
        hasher.update(&(pk.ring_degree as u64).to_le_bytes());
        hasher.update(&pk.digit_bits.to_le_bytes());
        hasher.update(&pk.opening_randomness_bits.to_le_bytes());
        hasher.update(&(row_index as u64).to_le_bytes());
        hasher.update(&(col_index as u64).to_le_bytes());
        hasher.update(&(coeff_index as u64).to_le_bytes());
        let mut out = [0u8; 8];
        hasher.finalize_xof().fill(&mut out);
        coeffs.push(Goldilocks::new(u64::from_le_bytes(out)).as_canonical_u64());
    }
    RingElem::from_coeffs(coeffs)
}

fn review_accumulate_negacyclic_product(
    accumulator: &mut [i128],
    left: &RingElem,
    right: &RingElem,
) {
    let degree = left.coeffs.len();
    for (i, left_coeff) in left.coeffs.iter().enumerate() {
        for (j, right_coeff) in right.coeffs.iter().enumerate() {
            if *right_coeff == 0 {
                continue;
            }
            let target = i + j;
            let product = if review_operand_bit_width(*right_coeff) <= 16 {
                i128::from(*left_coeff) * i128::from((*right_coeff) as u16)
            } else {
                i128::from(*left_coeff) * i128::from(*right_coeff)
            };
            if target < degree {
                accumulator[target] += product;
            } else {
                accumulator[target - degree] -= product;
            }
        }
    }
}

fn review_commit_ring_message(
    pk: &BackendKey,
    message: &[ReviewEmbeddedRingElem],
) -> Vec<RingElem> {
    let window_size = message.len().clamp(1, COMMITMENT_WINDOW_COLUMNS);
    let mut accumulators = vec![vec![0i128; pk.ring_degree]; pk.commitment_rows];
    for (window_index, chunk) in message.chunks(window_size).enumerate() {
        let base_col = window_index * window_size;
        for (offset, message_elem) in chunk.iter().enumerate() {
            let col_index = base_col + offset;
            for (row_index, accumulator) in
                accumulators.iter_mut().enumerate().take(pk.commitment_rows)
            {
                let matrix_elem = review_matrix_entry(pk, row_index, col_index);
                let _ = message_elem.source_width_bits;
                review_accumulate_negacyclic_product(accumulator, &matrix_elem, &message_elem.ring);
            }
        }
    }
    accumulators
        .into_iter()
        .map(|coeffs| {
            RingElem::from_coeffs(
                coeffs
                    .into_iter()
                    .map(review_reduce_goldilocks_signed)
                    .collect(),
            )
        })
        .collect()
}

fn review_derive_randomizer_rows(
    params: &NativeBackendParams,
    randomness_seed: [u8; 32],
) -> Vec<RingElem> {
    let canonical_seed = review_canonical_opening_randomness_seed(params, randomness_seed);
    (0..params.matrix_rows)
        .map(|row_index| {
            let coeffs = (0..params.matrix_cols)
                .map(|coeff_index| {
                    let mut hasher = Hasher::new();
                    hasher.update(b"hegemon.superneo.commitment-randomizer.v1");
                    hasher.update(&review_parameter_fingerprint(params));
                    hasher.update(&canonical_seed);
                    hasher.update(&(row_index as u64).to_le_bytes());
                    hasher.update(&(coeff_index as u64).to_le_bytes());
                    let mut out = [0u8; 16];
                    hasher.finalize_xof().fill(&mut out);
                    review_reduce_goldilocks_u128(u128::from_le_bytes(out))
                })
                .collect();
            RingElem::from_coeffs(coeffs)
        })
        .collect()
}

fn review_add_ring_rows(left: &[RingElem], right: &[RingElem]) -> Result<Vec<RingElem>> {
    ensure!(
        left.len() == right.len(),
        "cannot add {} commitment rows to {} randomizer rows",
        left.len(),
        right.len()
    );
    let mut rows = Vec::with_capacity(left.len());
    for (left_row, right_row) in left.iter().zip(right) {
        ensure!(
            left_row.coeffs.len() == right_row.coeffs.len(),
            "cannot combine ring elements with different degrees"
        );
        let coeffs = left_row
            .coeffs
            .iter()
            .zip(&right_row.coeffs)
            .map(|(left_coeff, right_coeff)| {
                let value = i128::from(*left_coeff) + i128::from(*right_coeff);
                review_reduce_goldilocks_signed(value)
            })
            .collect();
        rows.push(RingElem::from_coeffs(coeffs));
    }
    Ok(rows)
}

fn review_digest_commitment_rows(rows: &[RingElem]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.commitment-digest.v2");
    hasher.update(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        hasher.update(&(row.coeffs.len() as u64).to_le_bytes());
        for coeff in &row.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    review_hash48(hasher)
}

fn review_commit_packed_witness_with_seed(
    params: &NativeBackendParams,
    witness: &superneo_ring::PackedWitness<u64>,
    randomness_seed: [u8; 32],
) -> Result<(LatticeCommitment, CommitmentOpening)> {
    let randomness_seed = review_canonical_opening_randomness_seed(params, randomness_seed);
    let key = review_backend_key_for_shape(params, ShapeDigest([0u8; 32]), true);
    let ring_message =
        review_embed_packed_witness_with_layout(key.ring_degree, key.digit_bits, witness)?;
    let deterministic_rows = review_commit_ring_message(&key, &ring_message);
    let randomizer_rows = review_derive_randomizer_rows(params, randomness_seed);
    let rows = review_add_ring_rows(&deterministic_rows, &randomizer_rows)?;
    let commitment = LatticeCommitment {
        digest: review_digest_commitment_rows(&rows),
        rows,
    };
    let opening = CommitmentOpening {
        params_fingerprint: review_parameter_fingerprint(params),
        packed_witness: witness.clone(),
        randomness_seed,
        opening_digest: review_commitment_opening_digest(params, witness, &randomness_seed),
    };
    Ok((commitment, opening))
}

fn review_reduce_fold_challenge(challenge_bits: u32, raw: u64) -> u64 {
    let mask_bits = challenge_bits.min(63);
    let modulus = 1u64 << mask_bits;
    let reduced = if modulus <= 1 {
        1
    } else {
        (raw % (modulus - 1)) + 1
    };
    Goldilocks::new(reduced).as_canonical_u64()
}

fn review_negacyclic_rotated_coeff(row: &RingElem, coeff_index: usize, rotation: usize) -> i128 {
    let degree = row.coeffs.len();
    let source_index = coeff_index + rotation;
    let wraps = source_index / degree;
    let index = source_index % degree;
    let coeff = i128::from(row.coeffs[index]);
    if wraps.is_multiple_of(2) {
        coeff
    } else {
        -coeff
    }
}

fn review_fold_challenges(
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
) -> Result<Vec<u64>> {
    superneo_core::validate_fold_pair(left, right)?;
    ensure!(
        left.shape_digest == shape_digest && right.shape_digest == shape_digest,
        "review fold challenge shape digest mismatch"
    );
    let pk = review_backend_key_for_shape(params, shape_digest, false);
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&pk.params_fingerprint);
    transcript.extend_from_slice(review_ring_profile_label(pk.ring_profile));
    transcript.extend_from_slice(&pk.shape_digest.0);
    transcript.extend_from_slice(&left.relation_id.0);
    transcript.extend_from_slice(&pk.security_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.fold_challenge_count.to_le_bytes());
    transcript.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    transcript.extend_from_slice(&pk.transcript_domain_digest);
    transcript.extend_from_slice(&(pk.commitment_rows as u64).to_le_bytes());
    transcript.extend_from_slice(&(pk.ring_degree as u64).to_le_bytes());
    transcript.extend_from_slice(&pk.digit_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.opening_randomness_bits.to_le_bytes());
    transcript.extend_from_slice(&left.statement_digest.0);
    transcript.extend_from_slice(&right.statement_digest.0);
    transcript.extend_from_slice(&left.witness_commitment.digest);
    transcript.extend_from_slice(&right.witness_commitment.digest);
    Ok((0..pk.fold_challenge_count as usize)
        .map(|challenge_index| {
            let mut hasher = Hasher::new();
            hasher.update(b"hegemon.superneo.fold-challenge.v3");
            hasher.update(&transcript);
            hasher.update(&(challenge_index as u64).to_le_bytes());
            let mut out = [0u8; 8];
            hasher.finalize_xof().fill(&mut out);
            review_reduce_fold_challenge(pk.challenge_bits, u64::from_le_bytes(out))
        })
        .collect())
}

fn review_fold_rows(
    left: &LatticeCommitment,
    right: &LatticeCommitment,
    challenges: &[u64],
) -> Result<Vec<RingElem>> {
    ensure!(
        !left.rows.is_empty() && !right.rows.is_empty(),
        "folded commitments require concrete row data"
    );
    ensure!(
        left.rows.len() == right.rows.len(),
        "folded commitments must have the same row length"
    );
    ensure!(
        !challenges.is_empty(),
        "folded commitments require at least one challenge"
    );
    let mut rows = Vec::with_capacity(left.rows.len());
    for (left_row, right_row) in left.rows.iter().zip(&right.rows) {
        ensure!(
            left_row.coeffs.len() == right_row.coeffs.len(),
            "cannot combine ring elements with different degrees"
        );
        let mut coeffs = Vec::with_capacity(left_row.coeffs.len());
        for (coeff_index, left_coeff) in left_row.coeffs.iter().enumerate() {
            let mut value = Goldilocks::new(*left_coeff);
            for (rotation, challenge) in challenges.iter().copied().enumerate() {
                let right_coeff = review_negacyclic_rotated_coeff(right_row, coeff_index, rotation);
                value += Goldilocks::new(challenge) * review_goldilocks_from_signed(right_coeff);
            }
            coeffs.push(value.as_canonical_u64());
        }
        rows.push(RingElem::from_coeffs(coeffs));
    }
    Ok(rows)
}

fn review_fold_statement_digest(
    left: &StatementDigest,
    right: &StatementDigest,
    challenges: &[u64],
    parent_commitment_digest: &[u8; 48],
) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-statement.v3");
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    for challenge in challenges {
        hasher.update(&challenge.to_le_bytes());
    }
    hasher.update(&left.0);
    hasher.update(&right.0);
    hasher.update(parent_commitment_digest);
    StatementDigest(review_hash48(hasher))
}

fn review_fold_proof_digest(
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
    relation_id: &RelationId,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
    challenges: &[u64],
    parent_statement_digest: &StatementDigest,
    parent_rows: &[RingElem],
) -> Result<[u8; 48]> {
    superneo_core::validate_fold_pair(left, right)?;
    ensure!(
        left.shape_digest == shape_digest && right.shape_digest == shape_digest,
        "review fold proof shape digest mismatch"
    );
    let pk = review_backend_key_for_shape(params, shape_digest, false);
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-proof.v3");
    hasher.update(&pk.params_fingerprint);
    hasher.update(review_ring_profile_label(pk.ring_profile));
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.fold_challenge_count.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&pk.opening_randomness_bits.to_le_bytes());
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    for challenge in challenges {
        hasher.update(&challenge.to_le_bytes());
    }
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    hasher.update(&parent_statement_digest.0);
    hasher.update(&review_digest_commitment_rows(parent_rows));
    hasher.update(&(parent_rows.len() as u64).to_le_bytes());
    for row in parent_rows {
        hasher.update(&(row.coeffs.len() as u64).to_le_bytes());
        for coeff in &row.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    Ok(review_hash48(hasher))
}

fn review_native_leaf_proof_digest(
    params: &NativeBackendParams,
    relation_id: &RelationId,
    statement_digest: &StatementDigest,
    commitment_digest: &[u8; 48],
    opening_digest: &[u8; 48],
) -> [u8; 48] {
    review_digest48_with_parts(
        b"hegemon.superneo.native-leaf-proof.v1",
        &[
            &review_parameter_fingerprint(params),
            &relation_id.0,
            &statement_digest.0,
            commitment_digest,
            opening_digest,
        ],
    )
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
    if !params.derive_commitment_binding_from_geometry {
        ensure!(
            params.commitment_assumption_bits > 0,
            "commitment_assumption_bits must be strictly positive when geometry binding is disabled"
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
            "production fingerprint mismatch: family={} spec={} scheme={} schedule={} maturity={} sec={} ring={:?} rows={} cols={} chall={} fold_count={} arity={} domain={} decomp={} opening={} assumption={} geom={} max_msg={} max_leaves={}",
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
            params.commitment_assumption_bits,
            params.derive_commitment_binding_from_geometry,
            params.max_commitment_message_ring_elems,
            params.max_claimed_receipt_root_leaves,
        );
        assert_eq!(
            hex_encode(reference_fingerprint),
            hex_encode(bundle_fingerprint),
            "reference fingerprint mismatch: family={} spec={} scheme={} schedule={} maturity={} sec={} ring={:?} rows={} cols={} chall={} fold_count={} arity={} domain={} decomp={} opening={} assumption={} geom={} max_msg={} max_leaves={}",
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
            params.commitment_assumption_bits,
            params.derive_commitment_binding_from_geometry,
            params.max_commitment_message_ring_elems,
            params.max_claimed_receipt_root_leaves,
        );
    }
}
