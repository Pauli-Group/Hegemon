use crate::{
    BlockRecursionError, Digest32, Digest48, fold_digest32, fold_digest48,
    public_replay::{BlockLeafRecordV1, RecursiveBlockPublicV1},
    statement::{RecursivePrefixStatementV1, recursive_prefix_statement_digest_v1},
};
use p3_goldilocks::Goldilocks;
use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;
use superneo_ccs::{
    Assignment, CcsShape, RelationId, ShapeDigest, SparseMatrix, WitnessField, WitnessSchema,
    digest_shape,
};
use superneo_core::RecursiveStatementEncoding;
use superneo_ring::{
    GoldilocksPackingConfig, GoldilocksPayPerBitPacker, PackedWitness, WitnessPacker,
};
use transaction_circuit::{
    RecursiveSmallwoodProfileV1, SmallwoodArithmetization, SmallwoodConstraintAdapter,
    SmallwoodNonlinearEvalView, SmallwoodRecursiveProfileTagV1, SmallwoodRecursiveRelationKindV1,
    SmallwoodPcsVerifierTraceV1, SmallwoodPiopVerifierTraceV1, SmallwoodProofTraceV1,
    SmallwoodRecursiveVerifierDescriptorV1,
    TransactionCircuitError,
    decode_smallwood_proof_trace_v1, smallwood_binding_words_v1,
    smallwood_poseidon2_eval_points_v1, smallwood_poseidon2_pcs_trace_v1,
    smallwood_poseidon2_piop_trace_v1,
    decode_smallwood_recursive_proof_envelope_v1, projected_smallwood_recursive_envelope_bytes_v1,
    projected_smallwood_recursive_proof_bytes_v1, recursive_binding_bytes_v1,
    recursive_descriptor_v1, recursive_profile_a_v1, recursive_profile_b_v1,
    verify_recursive_statement_direct_v1,
};

const RECURSIVE_BLOCK_RELATION_LABEL_V1: &str = "hegemon.superneo.block-recursive.v1";
const BLOCK_RECURSIVE_WITNESS_SLOTS: usize = 96;
const SMALLWOOD_BASE_A_ROW_COUNT_V1: usize = 1;
const SMALLWOOD_BASE_A_PACKING_FACTOR_V1: usize = 64;
const SMALLWOOD_STEP_ROW_COUNT_V1: usize = 1;
const SMALLWOOD_STEP_PACKING_FACTOR_V1: usize = 64;

pub const PREVIOUS_PROOF_WITNESS_ROW_WIDTH_LIMBS_V1: usize = SMALLWOOD_STEP_PACKING_FACTOR_V1;
pub const PREVIOUS_PROOF_WITNESS_LIMB_BYTES_V1: usize = 8;
pub const PREVIOUS_PROOF_TRANSCRIPT_LIMBS_V1: usize = 9;
pub const PREVIOUS_PROOF_PCS_LIMBS_V1: usize = 128;
pub const PREVIOUS_PROOF_DECS_LIMBS_V1: usize = 256;
pub const PREVIOUS_PROOF_MERKLE_LIMBS_V1: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreviousProofWitnessSectionV1 {
    pub limb_start: usize,
    pub limb_count: usize,
    pub row_start: usize,
    pub row_count: usize,
}

impl PreviousProofWitnessSectionV1 {
    fn new(limb_start: usize, limb_count: usize, row_start: usize) -> Self {
        let row_count = previous_proof_rows_for_limbs_v1(limb_count);
        Self {
            limb_start,
            limb_count,
            row_start,
            row_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreviousProofWitnessLayoutV1 {
    pub row_width: usize,
    pub descriptor: PreviousProofWitnessSectionV1,
    pub envelope: PreviousProofWitnessSectionV1,
    pub transcript: PreviousProofWitnessSectionV1,
    pub pcs: PreviousProofWitnessSectionV1,
    pub decs: PreviousProofWitnessSectionV1,
    pub merkle: PreviousProofWitnessSectionV1,
    total_limbs: usize,
    total_rows: usize,
}

impl PreviousProofWitnessLayoutV1 {
    pub fn total_limbs(&self) -> usize {
        self.total_limbs
    }

    pub fn total_rows(&self) -> usize {
        self.total_rows
    }
}

fn previous_proof_limbs_for_bytes_v1(bytes: usize) -> usize {
    bytes.div_ceil(PREVIOUS_PROOF_WITNESS_LIMB_BYTES_V1)
}

fn bytes_to_witness_limbs_v1(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks(PREVIOUS_PROOF_WITNESS_LIMB_BYTES_V1)
        .map(|chunk| {
            let mut limb = [0u8; PREVIOUS_PROOF_WITNESS_LIMB_BYTES_V1];
            limb[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(limb)
        })
        .collect()
}

pub fn previous_proof_rows_for_limbs_v1(limbs: usize) -> usize {
    limbs.div_ceil(PREVIOUS_PROOF_WITNESS_ROW_WIDTH_LIMBS_V1)
}

pub fn previous_proof_trace_limbs_v1(descriptor_bytes_len: usize, proof_bytes_len: usize) -> usize {
    previous_proof_limbs_for_bytes_v1(descriptor_bytes_len)
        + previous_proof_limbs_for_bytes_v1(proof_bytes_len)
        + PREVIOUS_PROOF_TRANSCRIPT_LIMBS_V1
        + PREVIOUS_PROOF_PCS_LIMBS_V1
        + PREVIOUS_PROOF_DECS_LIMBS_V1
        + PREVIOUS_PROOF_MERKLE_LIMBS_V1
}

fn previous_proof_witness_layout_from_sections_v1(
    descriptor_bytes_len: usize,
    proof_bytes_len: usize,
    transcript_limbs: usize,
    pcs_limbs: usize,
    decs_limbs: usize,
    merkle_limbs: usize,
) -> PreviousProofWitnessLayoutV1 {
    let descriptor_limbs = previous_proof_limbs_for_bytes_v1(descriptor_bytes_len);
    let envelope_limbs = previous_proof_limbs_for_bytes_v1(proof_bytes_len);

    let descriptor = PreviousProofWitnessSectionV1::new(0, descriptor_limbs, 0);
    let envelope = PreviousProofWitnessSectionV1::new(
        descriptor.limb_start + descriptor.limb_count,
        envelope_limbs,
        descriptor.row_start + descriptor.row_count,
    );
    let transcript = PreviousProofWitnessSectionV1::new(
        envelope.limb_start + envelope.limb_count,
        transcript_limbs,
        envelope.row_start + envelope.row_count,
    );
    let pcs = PreviousProofWitnessSectionV1::new(
        transcript.limb_start + transcript.limb_count,
        pcs_limbs,
        transcript.row_start + transcript.row_count,
    );
    let decs = PreviousProofWitnessSectionV1::new(
        pcs.limb_start + pcs.limb_count,
        decs_limbs,
        pcs.row_start + pcs.row_count,
    );
    let merkle = PreviousProofWitnessSectionV1::new(
        decs.limb_start + decs.limb_count,
        merkle_limbs,
        decs.row_start + decs.row_count,
    );

    let total_limbs = merkle.limb_start + merkle.limb_count;
    let total_rows = previous_proof_rows_for_limbs_v1(total_limbs);

    PreviousProofWitnessLayoutV1 {
        row_width: PREVIOUS_PROOF_WITNESS_ROW_WIDTH_LIMBS_V1,
        descriptor,
        envelope,
        transcript,
        pcs,
        decs,
        merkle,
        total_limbs,
        total_rows,
    }
}

pub fn previous_proof_witness_layout_from_sizes_v1(
    descriptor_bytes_len: usize,
    proof_bytes_len: usize,
) -> PreviousProofWitnessLayoutV1 {
    previous_proof_witness_layout_from_sections_v1(
        descriptor_bytes_len,
        proof_bytes_len,
        PREVIOUS_PROOF_TRANSCRIPT_LIMBS_V1,
        PREVIOUS_PROOF_PCS_LIMBS_V1,
        PREVIOUS_PROOF_DECS_LIMBS_V1,
        PREVIOUS_PROOF_MERKLE_LIMBS_V1,
    )
}

pub fn previous_proof_witness_layout_from_envelope_v1(
    envelope_bytes: &[u8],
) -> Result<PreviousProofWitnessLayoutV1, TransactionCircuitError> {
    let envelope = decode_smallwood_recursive_proof_envelope_v1(envelope_bytes)?;
    let descriptor_bytes_len = envelope.descriptor.serialized_v1().len();
    let proof_bytes_len = envelope.proof_bytes.len();
    Ok(previous_proof_witness_layout_from_sizes_v1(
        descriptor_bytes_len,
        proof_bytes_len,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseARelationV1 {
    pub statement: RecursivePrefixStatementV1,
    pub canonical_base_statement: RecursivePrefixStatementV1,
    linear_offsets: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostedRecursiveProofContextV1 {
    BaseA {
        statement: RecursivePrefixStatementV1,
        proof_envelope_bytes: Vec<u8>,
    },
    StepA {
        previous_recursive_proof: Box<HostedRecursiveProofContextV1>,
        previous_statement: RecursivePrefixStatementV1,
        leaf_record: BlockLeafRecordV1,
        target_statement: RecursivePrefixStatementV1,
        proof_envelope_bytes: Vec<u8>,
    },
    StepB {
        previous_recursive_proof: Box<HostedRecursiveProofContextV1>,
        previous_statement: RecursivePrefixStatementV1,
        leaf_record: BlockLeafRecordV1,
        target_statement: RecursivePrefixStatementV1,
        proof_envelope_bytes: Vec<u8>,
    },
}

impl HostedRecursiveProofContextV1 {
    pub fn proof_envelope_bytes(&self) -> &[u8] {
        match self {
            Self::BaseA {
                proof_envelope_bytes,
                ..
            }
            | Self::StepA {
                proof_envelope_bytes,
                ..
            }
            | Self::StepB {
                proof_envelope_bytes,
                ..
            } => proof_envelope_bytes,
        }
    }
}

fn hosted_recursive_profile_v1(
    profile: SmallwoodRecursiveProfileTagV1,
) -> RecursiveSmallwoodProfileV1 {
    match profile {
        SmallwoodRecursiveProfileTagV1::A => {
            recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING)
        }
        SmallwoodRecursiveProfileTagV1::B => {
            recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING)
        }
    }
}

pub fn hosted_recursive_descriptor_v1(
    profile: SmallwoodRecursiveProfileTagV1,
    relation_kind: SmallwoodRecursiveRelationKindV1,
) -> SmallwoodRecursiveVerifierDescriptorV1 {
    let profile_cfg = hosted_recursive_profile_v1(profile);
    let tag = match relation_kind {
        SmallwoodRecursiveRelationKindV1::BaseA => b"base-a",
        SmallwoodRecursiveRelationKindV1::StepA => b"step-a",
        SmallwoodRecursiveRelationKindV1::StepB => b"step-b",
    };
    let relation_id = fold_digest32(
        b"hegemon.block-recursion.hosted-recursive.relation-id.v1",
        &[tag],
    );
    let shape_digest = fold_digest32(
        b"hegemon.block-recursion.hosted-recursive.shape-digest.v1",
        &[tag],
    );
    let vk_digest = fold_digest32(
        b"hegemon.block-recursion.hosted-recursive.vk-digest.v1",
        &[tag],
    );
    recursive_descriptor_v1(
        &profile_cfg,
        relation_kind,
        relation_id,
        shape_digest,
        vk_digest,
    )
}

pub fn hosted_base_binding_bytes_v1(statement: &RecursivePrefixStatementV1) -> Vec<u8> {
    recursive_prefix_statement_digest_v1(statement).to_vec()
}

pub fn hosted_step_binding_bytes_v1(
    previous_recursive_proof: &HostedRecursiveProofContextV1,
    previous_statement: &RecursivePrefixStatementV1,
    leaf_record: &BlockLeafRecordV1,
    target_statement: &RecursivePrefixStatementV1,
) -> Vec<u8> {
    let previous_proof_digest = fold_digest48(
        b"hegemon.block-recursion.hosted-recursive.previous-proof.v1",
        &[previous_recursive_proof.proof_envelope_bytes()],
    );
    let previous_statement_digest = recursive_prefix_statement_digest_v1(previous_statement);
    let leaf_digest = fold_digest48(
        b"hegemon.block-recursion.hosted-recursive.step-leaf.v1",
        &[&crate::public_replay::canonical_verified_leaf_record_bytes_v1(leaf_record)],
    );
    let target_statement_digest = recursive_prefix_statement_digest_v1(target_statement);
    let mut out = Vec::with_capacity(48 * 4);
    out.extend_from_slice(&previous_proof_digest);
    out.extend_from_slice(&previous_statement_digest);
    out.extend_from_slice(&leaf_digest);
    out.extend_from_slice(&target_statement_digest);
    out
}

fn verify_recursive_proof_envelope_structure_v1(
    profile: &RecursiveSmallwoodProfileV1,
    expected_descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let envelope = decode_smallwood_recursive_proof_envelope_v1(envelope_bytes)?;
    if envelope.descriptor.version != expected_descriptor.version {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope version mismatch",
        ));
    }
    if envelope.descriptor.arithmetization != expected_descriptor.arithmetization {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope arithmetization mismatch",
        ));
    }
    if envelope.descriptor.profile != expected_descriptor.profile {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope profile mismatch",
        ));
    }
    if envelope.descriptor.relation_kind != expected_descriptor.relation_kind {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope relation kind mismatch",
        ));
    }
    if envelope.descriptor.relation_id != expected_descriptor.relation_id {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope relation id mismatch",
        ));
    }
    if envelope.descriptor.shape_digest != expected_descriptor.shape_digest {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope shape digest mismatch",
        ));
    }
    if envelope.descriptor.vk_digest != expected_descriptor.vk_digest {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope verifier key digest mismatch",
        ));
    }
    let expected_proof_bytes_len =
        projected_smallwood_recursive_proof_bytes_v1(profile, statement)?;
    if envelope.proof_bytes.len() != expected_proof_bytes_len {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope proof length mismatch",
        ));
    }
    let projected_envelope_len = projected_smallwood_recursive_envelope_bytes_v1(
        expected_descriptor,
        envelope.proof_bytes.len(),
    )?;
    if projected_envelope_len != envelope_bytes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope serialized length mismatch",
        ));
    }
    Ok(envelope.proof_bytes)
}

pub fn verify_recursive_proof_envelope_components_v1(
    profile: &RecursiveSmallwoodProfileV1,
    expected_descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    envelope_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let proof_bytes = verify_recursive_proof_envelope_structure_v1(
        profile,
        expected_descriptor,
        statement,
        envelope_bytes,
    )?;
    verify_recursive_statement_direct_v1(
        profile,
        expected_descriptor,
        statement,
        binded_data,
        &proof_bytes,
    )
}

pub fn verify_hosted_recursive_proof_context_descriptor_shape_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    match context {
        HostedRecursiveProofContextV1::BaseA {
            statement,
            proof_envelope_bytes,
        } => {
            let descriptor = hosted_recursive_descriptor_v1(
                SmallwoodRecursiveProfileTagV1::A,
                SmallwoodRecursiveRelationKindV1::BaseA,
            );
            let relation = BaseARelationV1::new(statement.clone(), statement.clone());
            let _ = verify_recursive_proof_envelope_structure_v1(
                &hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::A),
                &descriptor,
                &relation,
                proof_envelope_bytes,
            )?;
            Ok(())
        }
        HostedRecursiveProofContextV1::StepA {
            previous_recursive_proof,
            previous_statement,
            leaf_record,
            target_statement,
            proof_envelope_bytes,
        } => {
            verify_hosted_recursive_proof_context_descriptor_shape_v1(previous_recursive_proof)?;
            let descriptor = hosted_recursive_descriptor_v1(
                SmallwoodRecursiveProfileTagV1::A,
                SmallwoodRecursiveRelationKindV1::StepA,
            );
            let relation = StepARelationV1::new(
                (**previous_recursive_proof).clone(),
                previous_statement.clone(),
                leaf_record.clone(),
                target_statement.clone(),
            );
            let binding = hosted_step_binding_bytes_v1(
                previous_recursive_proof,
                previous_statement,
                leaf_record,
                target_statement,
            );
            let _ = verify_recursive_proof_envelope_structure_v1(
                &hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::A),
                &descriptor,
                &relation,
                proof_envelope_bytes,
            )?;
            let _ = binding;
            Ok(())
        }
        HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof,
            previous_statement,
            leaf_record,
            target_statement,
            proof_envelope_bytes,
        } => {
            verify_hosted_recursive_proof_context_descriptor_shape_v1(previous_recursive_proof)?;
            let descriptor = hosted_recursive_descriptor_v1(
                SmallwoodRecursiveProfileTagV1::B,
                SmallwoodRecursiveRelationKindV1::StepB,
            );
            let relation = StepBRelationV1::new(
                (**previous_recursive_proof).clone(),
                previous_statement.clone(),
                leaf_record.clone(),
                target_statement.clone(),
            );
            let binding = hosted_step_binding_bytes_v1(
                previous_recursive_proof,
                previous_statement,
                leaf_record,
                target_statement,
            );
            let _ = verify_recursive_proof_envelope_structure_v1(
                &hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::B),
                &descriptor,
                &relation,
                proof_envelope_bytes,
            )?;
            let _ = binding;
            Ok(())
        }
    }
}

const DIGEST_WORDS_V1: usize = 4;

fn digest_words_v1(digest: &Digest32) -> [u64; DIGEST_WORDS_V1] {
    let mut out = [0u64; DIGEST_WORDS_V1];
    for (idx, chunk) in digest.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        out[idx] = u64::from_le_bytes(word);
    }
    out
}

fn nonce_words_v1(nonce: &[u8; 4]) -> [u64; 1] {
    [u32::from_le_bytes(*nonce) as u64]
}

fn flatten_matrix_words_v1(matrix: &[Vec<u64>]) -> Vec<u64> {
    let mut out = Vec::new();
    for row in matrix {
        out.extend_from_slice(row);
    }
    out
}

fn flatten_u32_words_v1(values: &[u32]) -> Vec<u64> {
    values.iter().map(|&value| value as u64).collect()
}

fn flatten_auth_path_words_v1(paths: &[Vec<Digest32>]) -> Vec<u64> {
    let mut out = Vec::new();
    for path in paths {
        for node in path {
            out.extend_from_slice(&digest_words_v1(node));
        }
    }
    out
}

#[derive(Clone, Debug)]
struct HostedRecursiveProofSectionsV1 {
    descriptor: SmallwoodRecursiveVerifierDescriptorV1,
    binded_data: Vec<u8>,
    proof_bytes: Vec<u8>,
    proof_trace: SmallwoodProofTraceV1,
    eval_points: Vec<u64>,
    pcs_trace: SmallwoodPcsVerifierTraceV1,
    piop_trace: SmallwoodPiopVerifierTraceV1,
    descriptor_words: Vec<u64>,
    proof_words: Vec<u64>,
    transcript_words: Vec<u64>,
    pcs_words: Vec<u64>,
    decs_words: Vec<u64>,
    merkle_words: Vec<u64>,
}

impl HostedRecursiveProofSectionsV1 {
    fn validate_transcript_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let binding_words =
            smallwood_binding_words_v1(&recursive_binding_bytes_v1(&self.descriptor, &self.binded_data))?;
        if self.eval_points.len() != 3 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript opening-point count mismatch",
            ));
        }
        if self.eval_points.len() != self.proof_trace.opened_witness_row_scalars.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript row-scalar count mismatch",
            ));
        }
        if self.piop_trace.piop_gamma_prime.len() != 2 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript gamma-prime count mismatch",
            ));
        }
        if self.piop_trace.pcs_transcript_words != self.pcs_trace.decs_commitment_transcript {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript PCS/DECS transcript mismatch",
            ));
        }
        if self.piop_trace.piop_input_words.len() < binding_words.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop-input length mismatch",
            ));
        }
        if !self
            .piop_trace
            .piop_input_words
            .starts_with(&self.piop_trace.pcs_transcript_words)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop-input prefix mismatch",
            ));
        }
        if self.piop_trace.piop_input_words[self.piop_trace.pcs_transcript_words.len()..]
            != binding_words
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop-input binding suffix mismatch",
            ));
        }
        if self.piop_trace.piop_transcript_words.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop transcript words missing",
            ));
        }
        Ok(())
    }

    fn validate_pcs_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_combi_count = self.pcs_trace.coeffs.len();
        if self.proof_trace.opened_witness_row_scalars.len() != self.eval_points.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS opened-row/eval-point count mismatch",
            ));
        }
        if opened_combi_count == 0 || opened_combi_count != self.pcs_trace.combi_heads.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS coefficient/combi-head count mismatch",
            ));
        }
        if self.proof_trace.pcs_partial_evals_v1().len() != 3
            || self.proof_trace.pcs_rcombi_tails_v1().len() != opened_combi_count
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS section count mismatch",
            ));
        }
        if self.proof_trace.pcs_subset_evals_v1().len() != self.pcs_trace.decs_leaf_indexes.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS subset-eval count mismatch",
            ));
        }
        if self.piop_trace.pcs_transcript_words != self.pcs_trace.decs_commitment_transcript {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS transcript mismatch",
            ));
        }
        if self.pcs_trace.rows.is_empty()
            || self.pcs_trace.rows.len() != self.pcs_trace.decs_eval_points.len()
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS opened-row count mismatch",
            ));
        }
        if self.pcs_trace.decs_leaf_indexes.len() != self.pcs_trace.decs_eval_points.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS leaf-index/decs-point count mismatch",
            ));
        }
        if self
            .pcs_trace
            .decs_leaf_indexes
            .iter()
            .zip(self.pcs_trace.decs_eval_points.iter())
            .any(|(leaf, point)| u64::from(*leaf) != *point)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS leaf-index/decs-point value mismatch",
            ));
        }
        let expected_row_width = self.pcs_trace.coeffs.first().map(Vec::len).unwrap_or_default();
        if expected_row_width == 0
            || self
                .pcs_trace
                .rows
                .iter()
                .any(|row| row.len() != expected_row_width)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS opened-row width mismatch",
            ));
        }
        Ok(())
    }

    fn validate_decs_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_count = self.pcs_trace.decs_leaf_indexes.len();
        if opened_count == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier DECS opened-leaf set is empty",
            ));
        }
        if self.pcs_trace.decs_eval_points.len() != opened_count
            || self.proof_trace.decs_masking_evals_v1().len() != opened_count
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier DECS section count mismatch",
            ));
        }
        if self.proof_trace.decs_high_coeffs_v1().len() != 3 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier DECS high-coefficient count mismatch",
            ));
        }
        if self.piop_trace.pcs_transcript_words != self.pcs_trace.decs_commitment_transcript {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier DECS transcript mismatch",
            ));
        }
        for row in self.proof_trace.decs_masking_evals_v1() {
            if row.is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "recursive verifier DECS masking-eval row is empty",
                ));
            }
        }
        for poly in self.proof_trace.decs_high_coeffs_v1() {
            if poly.is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "recursive verifier DECS high-coefficient row is empty",
                ));
            }
        }
        Ok(())
    }

    fn validate_merkle_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_count = self.pcs_trace.decs_leaf_indexes.len();
        if self.pcs_trace.rows.len() != opened_count
            || self.proof_trace.decs_auth_paths_v1().len() != opened_count
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier Merkle section count mismatch",
            ));
        }
        let expected_path_len =
            self.proof_trace
                .decs_auth_paths_v1()
                .first()
                .map(Vec::len)
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "recursive verifier Merkle auth paths missing",
                ))?;
        if expected_path_len == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier Merkle auth path is empty",
            ));
        }
        if self.pcs_trace.root_digest == [0u8; 32] {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier Merkle root digest missing",
            ));
        }
        for idx in 0..opened_count {
            if self.pcs_trace.rows[idx].is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "recursive verifier Merkle row is empty",
                ));
            }
            if self.proof_trace.decs_auth_paths_v1()[idx].len() != expected_path_len {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "recursive verifier Merkle auth path length mismatch",
                ));
            }
        }
        Ok(())
    }
}

fn build_hosted_recursive_proof_sections_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<HostedRecursiveProofSectionsV1, TransactionCircuitError> {
    let (profile, descriptor, relation, binding, proof_bytes_len) =
        build_expected_recursive_inputs_v1(context)?;
    let proof_bytes = verify_recursive_proof_envelope_structure_v1(
        &profile,
        &descriptor,
        relation.as_ref(),
        context.proof_envelope_bytes(),
    )?;
    if proof_bytes.len() != proof_bytes_len {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope proof length mismatch",
        ));
    }
    let proof_trace = decode_smallwood_proof_trace_v1(&proof_bytes)?;
    let binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&descriptor, &binding))?;
    let eval_points = smallwood_poseidon2_eval_points_v1(relation.as_ref(), &proof_trace)?;
    let pcs_trace = smallwood_poseidon2_pcs_trace_v1(relation.as_ref(), &proof_trace, &eval_points)?;
    let piop_trace = smallwood_poseidon2_piop_trace_v1(
        relation.as_ref(),
        &binding_words,
        &proof_trace,
        &eval_points,
        &pcs_trace,
    )?;

    let mut transcript_words = Vec::new();
    transcript_words.extend_from_slice(&binding_words);
    transcript_words.extend_from_slice(&eval_points);
    transcript_words.extend_from_slice(&flatten_matrix_words_v1(&piop_trace.piop_gamma_prime));
    transcript_words.extend_from_slice(&piop_trace.pcs_transcript_words);
    transcript_words.extend_from_slice(&piop_trace.piop_input_words);
    transcript_words.extend_from_slice(&piop_trace.piop_transcript_words);
    transcript_words.extend_from_slice(&digest_words_v1(&proof_trace.h_piop));
    transcript_words.push(piop_trace.accept as u64);

    let mut pcs_words = Vec::new();
    pcs_words.extend_from_slice(&flatten_matrix_words_v1(
        &proof_trace.opened_witness_row_scalars,
    ));
    pcs_words.extend_from_slice(&flatten_matrix_words_v1(proof_trace.pcs_partial_evals_v1()));
    pcs_words.extend_from_slice(&flatten_matrix_words_v1(proof_trace.pcs_rcombi_tails_v1()));
    pcs_words.extend_from_slice(&flatten_matrix_words_v1(proof_trace.pcs_subset_evals_v1()));
    pcs_words.extend_from_slice(&flatten_matrix_words_v1(&pcs_trace.coeffs));
    pcs_words.extend_from_slice(&flatten_matrix_words_v1(&pcs_trace.combi_heads));
    pcs_words.extend_from_slice(&digest_words_v1(&pcs_trace.decs_trans_hash));
    pcs_words.extend_from_slice(&piop_trace.pcs_transcript_words);

    let mut decs_words = Vec::new();
    decs_words.extend_from_slice(&digest_words_v1(&pcs_trace.decs_trans_hash));
    decs_words.extend_from_slice(&flatten_u32_words_v1(&pcs_trace.decs_leaf_indexes));
    decs_words.extend_from_slice(&nonce_words_v1(&pcs_trace.decs_nonce));
    decs_words.extend_from_slice(&pcs_trace.decs_eval_points);
    decs_words.extend_from_slice(&flatten_matrix_words_v1(
        proof_trace.decs_masking_evals_v1(),
    ));
    decs_words.extend_from_slice(&flatten_matrix_words_v1(
        proof_trace.decs_high_coeffs_v1(),
    ));
    decs_words.extend_from_slice(&pcs_trace.decs_commitment_transcript);

    let mut merkle_words = Vec::new();
    merkle_words.extend_from_slice(&flatten_matrix_words_v1(&pcs_trace.rows));
    merkle_words.extend_from_slice(&flatten_auth_path_words_v1(
        proof_trace.decs_auth_paths_v1(),
    ));
    merkle_words.extend_from_slice(&digest_words_v1(&pcs_trace.root_digest));

    let sections = HostedRecursiveProofSectionsV1 {
        descriptor_words: bytes_to_witness_limbs_v1(&descriptor.serialized_v1()),
        proof_words: bytes_to_witness_limbs_v1(&proof_bytes),
        transcript_words,
        pcs_words,
        decs_words,
        merkle_words,
        descriptor,
        binded_data: binding,
        proof_bytes,
        proof_trace,
        eval_points,
        pcs_trace,
        piop_trace,
    };
    sections.validate_transcript_section_v1()?;
    sections.validate_pcs_section_v1()?;
    sections.validate_decs_section_v1()?;
    sections.validate_merkle_section_v1()?;
    Ok(sections)
}

pub fn verify_hosted_recursive_proof_context_binding_trace_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    match context {
        HostedRecursiveProofContextV1::BaseA { .. } => {}
        HostedRecursiveProofContextV1::StepA {
            previous_recursive_proof,
            ..
        }
        | HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof,
            ..
        } => verify_hosted_recursive_proof_context_binding_trace_v1(previous_recursive_proof)?,
    }

    let (_, descriptor, _, binding, _) = build_expected_recursive_inputs_v1(context)?;
    let sections = build_hosted_recursive_proof_sections_v1(context)?;
    let binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&descriptor, &binding))?;
    if sections.descriptor != descriptor {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace descriptor mismatch",
        ));
    }
    if sections.binded_data != binding {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace binding payload mismatch",
        ));
    }
    if !sections.transcript_words.starts_with(&binding_words) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace binding words mismatch",
        ));
    }
    if !sections.piop_trace.accept {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace accept bit mismatch",
        ));
    }
    Ok(())
}

pub fn hosted_recursive_proof_witness_layout_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<PreviousProofWitnessLayoutV1, TransactionCircuitError> {
    let sections = build_hosted_recursive_proof_sections_v1(context)?;
    Ok(previous_proof_witness_layout_from_sections_v1(
        sections.descriptor.serialized_v1().len(),
        sections.proof_bytes.len(),
        sections.transcript_words.len(),
        sections.pcs_words.len(),
        sections.decs_words.len(),
        sections.merkle_words.len(),
    ))
}

pub fn hosted_recursive_proof_witness_words_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let sections = build_hosted_recursive_proof_sections_v1(context)?;
    let layout = hosted_recursive_proof_witness_layout_v1(context)?;
    let witness_sections = [
        (
            "descriptor",
            layout.descriptor.limb_count,
            sections.descriptor_words.as_slice(),
        ),
        (
            "envelope",
            layout.envelope.limb_count,
            sections.proof_words.as_slice(),
        ),
        (
            "transcript",
            layout.transcript.limb_count,
            sections.transcript_words.as_slice(),
        ),
        ("pcs", layout.pcs.limb_count, sections.pcs_words.as_slice()),
        ("decs", layout.decs.limb_count, sections.decs_words.as_slice()),
        (
            "merkle",
            layout.merkle.limb_count,
            sections.merkle_words.as_slice(),
        ),
    ];
    let mut out = Vec::with_capacity(layout.total_rows() * layout.row_width);
    for (name, limit, words) in witness_sections {
        if words.len() > limit {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "recursive proof witness {name} section exceeds fixed limb budget: {} > {}",
                words.len(),
                limit
            )));
        }
        out.extend_from_slice(words);
        out.resize(out.len() + (limit - words.len()), 0);
    }
    out.resize(layout.total_rows() * layout.row_width, 0);
    Ok(out)
}

fn witness_section_words_v1<'a>(
    witness_words: &'a [u64],
    section: PreviousProofWitnessSectionV1,
) -> Result<&'a [u64], TransactionCircuitError> {
    witness_words
        .get(section.limb_start..section.limb_start + section.limb_count)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "recursive proof witness section out of bounds",
        ))
}

fn witness_words_to_bytes_v1(
    witness_words: &[u64],
    byte_len: usize,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if witness_words.len() * PREVIOUS_PROOF_WITNESS_LIMB_BYTES_V1 < byte_len {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof witness byte section truncated",
        ));
    }
    let mut out = Vec::with_capacity(witness_words.len() * PREVIOUS_PROOF_WITNESS_LIMB_BYTES_V1);
    for word in witness_words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(byte_len);
    Ok(out)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PreviousProofWitnessValidationV1 {
    witness_ready: bool,
    descriptor_shape_valid: bool,
    binding_trace_valid: bool,
    transcript_valid: bool,
    pcs_valid: bool,
    decs_merkle_valid: bool,
}

fn fixed_witness_linear_constraints_v1(
    witness_words: &[u64],
) -> (Vec<u32>, Vec<u32>, Vec<u64>, Vec<u64>) {
    let count = witness_words.len();
    (
        (0..=count as u32).collect(),
        (0..count as u32).collect(),
        vec![1u64; count],
        witness_words.to_vec(),
    )
}

fn build_expected_recursive_inputs_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<
    (
        RecursiveSmallwoodProfileV1,
        SmallwoodRecursiveVerifierDescriptorV1,
        Box<dyn SmallwoodConstraintAdapter + Sync>,
        Vec<u8>,
        usize,
    ),
    TransactionCircuitError,
> {
    match context {
        HostedRecursiveProofContextV1::BaseA {
            statement,
            proof_envelope_bytes,
        } => Ok((
            hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::A),
            hosted_recursive_descriptor_v1(
                SmallwoodRecursiveProfileTagV1::A,
                SmallwoodRecursiveRelationKindV1::BaseA,
            ),
            Box::new(BaseARelationV1::new(statement.clone(), statement.clone())),
            hosted_base_binding_bytes_v1(statement),
            decode_smallwood_recursive_proof_envelope_v1(proof_envelope_bytes)?
                .proof_bytes
                .len(),
        )),
        HostedRecursiveProofContextV1::StepA {
            previous_recursive_proof,
            previous_statement,
            leaf_record,
            target_statement,
            proof_envelope_bytes,
        } => Ok((
            hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::A),
            hosted_recursive_descriptor_v1(
                SmallwoodRecursiveProfileTagV1::A,
                SmallwoodRecursiveRelationKindV1::StepA,
            ),
            Box::new(StepARelationV1::new(
                (**previous_recursive_proof).clone(),
                previous_statement.clone(),
                leaf_record.clone(),
                target_statement.clone(),
            )),
            hosted_step_binding_bytes_v1(
                previous_recursive_proof,
                previous_statement,
                leaf_record,
                target_statement,
            ),
            decode_smallwood_recursive_proof_envelope_v1(proof_envelope_bytes)?
                .proof_bytes
                .len(),
        )),
        HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof,
            previous_statement,
            leaf_record,
            target_statement,
            proof_envelope_bytes,
        } => Ok((
            hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::B),
            hosted_recursive_descriptor_v1(
                SmallwoodRecursiveProfileTagV1::B,
                SmallwoodRecursiveRelationKindV1::StepB,
            ),
            Box::new(StepBRelationV1::new(
                (**previous_recursive_proof).clone(),
                previous_statement.clone(),
                leaf_record.clone(),
                target_statement.clone(),
            )),
            hosted_step_binding_bytes_v1(
                previous_recursive_proof,
                previous_statement,
                leaf_record,
                target_statement,
            ),
            decode_smallwood_recursive_proof_envelope_v1(proof_envelope_bytes)?
                .proof_bytes
                .len(),
        )),
    }
}

fn validate_previous_proof_witness_v1(
    context: &HostedRecursiveProofContextV1,
    layout: PreviousProofWitnessLayoutV1,
    witness_words: &[u64],
) -> PreviousProofWitnessValidationV1 {
    let mut validation = PreviousProofWitnessValidationV1::default();
    if witness_words.len() < layout.total_rows() * layout.row_width {
        return validation;
    }
    validation.witness_ready = true;

    let Ok((_, descriptor, _, binding, proof_bytes_len)) = build_expected_recursive_inputs_v1(context)
    else {
        return validation;
    };

    let expected_descriptor_words = bytes_to_witness_limbs_v1(&descriptor.serialized_v1());
    let Ok(descriptor_words) = witness_section_words_v1(witness_words, layout.descriptor) else {
        return validation;
    };
    validation.descriptor_shape_valid = descriptor_words == expected_descriptor_words.as_slice();
    if !validation.descriptor_shape_valid {
        return validation;
    }

    let Ok(proof_words) = witness_section_words_v1(witness_words, layout.envelope) else {
        return validation;
    };
    let Ok(proof_bytes) = witness_words_to_bytes_v1(proof_words, proof_bytes_len) else {
        return validation;
    };
    let Ok(envelope) = decode_smallwood_recursive_proof_envelope_v1(context.proof_envelope_bytes())
    else {
        return validation;
    };
    if envelope.proof_bytes != proof_bytes {
        return validation;
    }

    let Ok(sections) = build_hosted_recursive_proof_sections_v1(context) else {
        return validation;
    };

    let expected_binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&descriptor, &binding))
            .unwrap_or_default();
    validation.binding_trace_valid = sections.descriptor == descriptor
        && sections.binded_data == binding
        && sections.transcript_words.starts_with(&expected_binding_words)
        && sections.piop_trace.accept;

    validation.transcript_valid = sections.validate_transcript_section_v1().is_ok()
        && witness_section_words_v1(witness_words, layout.transcript)
            .map(|words| words == sections.transcript_words.as_slice())
            .unwrap_or(false);

    validation.pcs_valid = sections.validate_pcs_section_v1().is_ok()
        && witness_section_words_v1(witness_words, layout.pcs)
            .map(|words| words == sections.pcs_words.as_slice())
            .unwrap_or(false);

    validation.decs_merkle_valid = sections.validate_decs_section_v1().is_ok()
        && sections.validate_merkle_section_v1().is_ok()
        && witness_section_words_v1(witness_words, layout.decs)
            .map(|words| words == sections.decs_words.as_slice())
            .unwrap_or(false)
        && witness_section_words_v1(witness_words, layout.merkle)
            .map(|words| words == sections.merkle_words.as_slice())
            .unwrap_or(false);

    validation
}

pub fn verify_hosted_recursive_proof_context_transcript_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    match context {
        HostedRecursiveProofContextV1::BaseA { .. } => {}
        HostedRecursiveProofContextV1::StepA {
            previous_recursive_proof,
            ..
        }
        | HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof,
            ..
        } => verify_hosted_recursive_proof_context_transcript_v1(previous_recursive_proof)?,
    }

    let sections = build_hosted_recursive_proof_sections_v1(context)?;
    if sections.eval_points.len() != 3 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace opening-point count mismatch",
        ));
    }
    let binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&sections.descriptor, &sections.binded_data))?;
    if sections.piop_trace.piop_input_words.len() < binding_words.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace piop input too short",
        ));
    }
    let split = sections.piop_trace.piop_input_words.len() - binding_words.len();
    if sections.piop_trace.piop_input_words[..split] != sections.piop_trace.pcs_transcript_words {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace pcs transcript prefix mismatch",
        ));
    }
    if sections.piop_trace.piop_input_words[split..] != binding_words {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace binding suffix mismatch",
        ));
    }
    if sections.piop_trace.pcs_transcript_words != sections.pcs_trace.decs_commitment_transcript {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace decs transcript mismatch",
        ));
    }
    if sections.piop_trace.piop_gamma_prime.is_empty() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace missing gamma prime values",
        ));
    }
    Ok(())
}

fn verify_pcs_trace_v1(
    sections: &HostedRecursiveProofSectionsV1,
) -> Result<(), TransactionCircuitError> {
    sections.validate_pcs_section_v1()
}

fn verify_decs_merkle_trace_v1(
    sections: &HostedRecursiveProofSectionsV1,
) -> Result<(), TransactionCircuitError> {
    sections.validate_decs_section_v1()?;
    sections.validate_merkle_section_v1()
}

pub fn verify_hosted_recursive_proof_context_pcs_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    match context {
        HostedRecursiveProofContextV1::BaseA { .. } => verify_pcs_trace_v1(
            &build_hosted_recursive_proof_sections_v1(context).map_err(|err| {
                TransactionCircuitError::ConstraintViolationOwned(format!(
                    "recursive verifier PCS trace invalid: {err}"
                ))
            })?,
        ),
        HostedRecursiveProofContextV1::StepA {
            previous_recursive_proof,
            ..
        } => {
            verify_hosted_recursive_proof_context_pcs_v1(previous_recursive_proof)?;
            verify_pcs_trace_v1(
                &build_hosted_recursive_proof_sections_v1(context).map_err(|err| {
                    TransactionCircuitError::ConstraintViolationOwned(format!(
                        "recursive verifier PCS trace invalid: {err}"
                    ))
                })?,
            )
        }
        HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof,
            ..
        } => {
            verify_hosted_recursive_proof_context_pcs_v1(previous_recursive_proof)?;
            verify_pcs_trace_v1(
                &build_hosted_recursive_proof_sections_v1(context).map_err(|err| {
                    TransactionCircuitError::ConstraintViolationOwned(format!(
                        "recursive verifier PCS trace invalid: {err}"
                    ))
                })?,
            )
        }
    }
}

pub fn verify_hosted_recursive_proof_context_decs_merkle_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    match context {
        HostedRecursiveProofContextV1::BaseA { .. } => verify_decs_merkle_trace_v1(
            &build_hosted_recursive_proof_sections_v1(context).map_err(|err| {
                TransactionCircuitError::ConstraintViolationOwned(format!(
                    "recursive verifier DECS/Merkle trace invalid: {err}"
                ))
            })?,
        ),
        HostedRecursiveProofContextV1::StepA {
            previous_recursive_proof,
            ..
        } => {
            verify_hosted_recursive_proof_context_decs_merkle_v1(previous_recursive_proof)?;
            verify_decs_merkle_trace_v1(
                &build_hosted_recursive_proof_sections_v1(context).map_err(|err| {
                    TransactionCircuitError::ConstraintViolationOwned(format!(
                        "recursive verifier DECS/Merkle trace invalid: {err}"
                    ))
                })?,
            )
        }
        HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof,
            ..
        } => {
            verify_hosted_recursive_proof_context_decs_merkle_v1(previous_recursive_proof)?;
            verify_decs_merkle_trace_v1(
                &build_hosted_recursive_proof_sections_v1(context).map_err(|err| {
                    TransactionCircuitError::ConstraintViolationOwned(format!(
                        "recursive verifier DECS/Merkle trace invalid: {err}"
                    ))
                })?,
            )
        }
    }
}

pub fn verify_hosted_recursive_proof_context_components_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    verify_hosted_recursive_proof_context_descriptor_shape_v1(context)?;
    verify_hosted_recursive_proof_context_binding_trace_v1(context)?;
    verify_hosted_recursive_proof_context_transcript_v1(context)?;
    verify_hosted_recursive_proof_context_pcs_v1(context)?;
    verify_hosted_recursive_proof_context_decs_merkle_v1(context)
}

pub fn verify_hosted_recursive_proof_context_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    verify_hosted_recursive_proof_context_components_v1(context)
}

impl BaseARelationV1 {
    pub fn new(
        statement: RecursivePrefixStatementV1,
        canonical_base_statement: RecursivePrefixStatementV1,
    ) -> Self {
        Self {
            statement,
            canonical_base_statement,
            linear_offsets: vec![0],
        }
    }
}

impl SmallwoodConstraintAdapter for BaseARelationV1 {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        SMALLWOOD_BASE_A_ROW_COUNT_V1
    }

    fn packing_factor(&self) -> usize {
        SMALLWOOD_BASE_A_PACKING_FACTOR_V1
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn linear_constraint_count(&self) -> usize {
        0
    }

    fn constraint_count(&self) -> usize {
        1
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.linear_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &[]
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &[]
    }

    fn linear_targets(&self) -> &[u64] {
        &[]
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
        }
    }

    fn compute_constraints_u64(
        &self,
        _view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let mismatch = u64::from(self.statement != self.canonical_base_statement);
        out[0] = mismatch.saturating_mul(mismatch);
        Ok(())
    }
}

fn step_relation_mismatch(
    previous_statement: &RecursivePrefixStatementV1,
    leaf_record: &BlockLeafRecordV1,
    target_statement: &RecursivePrefixStatementV1,
) -> u64 {
    let expected_tx_count = previous_statement.tx_count.saturating_add(1);
    let tx_count_ok = target_statement.tx_count == expected_tx_count;
    let leaf_index_ok = leaf_record.tx_index == previous_statement.tx_count;
    let start_state_ok =
        target_statement.start_state_digest == previous_statement.start_state_digest;
    let tx_commitment_ok =
        target_statement.tx_statements_commitment == previous_statement.tx_statements_commitment;
    let start_tree_ok =
        target_statement.start_tree_commitment == previous_statement.start_tree_commitment;
    let nonzero_end_state = target_statement.end_state_digest != [0u8; 48];
    let nonzero_end_tree = target_statement.end_tree_commitment != [0u8; 48];
    let nonzero_leaf_commitment = target_statement.verified_leaf_commitment != [0u8; 48];
    let nonzero_receipt_commitment = target_statement.verified_receipt_commitment != [0u8; 48];
    u64::from(
        !(tx_count_ok
            && leaf_index_ok
            && start_state_ok
            && tx_commitment_ok
            && start_tree_ok
            && nonzero_end_state
            && nonzero_end_tree
            && nonzero_leaf_commitment
            && nonzero_receipt_commitment),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepARelationV1 {
    pub previous_recursive_proof: Box<HostedRecursiveProofContextV1>,
    pub previous_statement: RecursivePrefixStatementV1,
    pub leaf_record: BlockLeafRecordV1,
    pub target_statement: RecursivePrefixStatementV1,
    previous_proof_layout: Option<PreviousProofWitnessLayoutV1>,
    previous_proof_validation: PreviousProofWitnessValidationV1,
    witness_row_count: usize,
    linear_offsets: Vec<u32>,
    linear_indices: Vec<u32>,
    linear_coefficients: Vec<u64>,
    linear_targets: Vec<u64>,
}

impl StepARelationV1 {
    pub fn new(
        previous_recursive_proof: HostedRecursiveProofContextV1,
        previous_statement: RecursivePrefixStatementV1,
        leaf_record: BlockLeafRecordV1,
        target_statement: RecursivePrefixStatementV1,
    ) -> Self {
        let previous_proof_layout =
            hosted_recursive_proof_witness_layout_v1(&previous_recursive_proof).ok();
        let (
            witness_row_count,
            linear_offsets,
            linear_indices,
            linear_coefficients,
            linear_targets,
        ) = match hosted_recursive_proof_witness_words_v1(&previous_recursive_proof) {
            Ok(witness_words) => {
                let row_count = previous_proof_rows_for_limbs_v1(witness_words.len()).max(1);
                let (offsets, indices, coefficients, targets) =
                    fixed_witness_linear_constraints_v1(&witness_words);
                (row_count, offsets, indices, coefficients, targets)
            }
            Err(_) => (
                SMALLWOOD_STEP_ROW_COUNT_V1,
                vec![0],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        };
        let previous_proof_validation = previous_proof_layout
            .map(|layout| {
                validate_previous_proof_witness_v1(
                    &previous_recursive_proof,
                    layout,
                    &linear_targets,
                )
            })
            .unwrap_or_default();
        Self {
            previous_recursive_proof: Box::new(previous_recursive_proof),
            previous_statement,
            leaf_record,
            target_statement,
            previous_proof_layout,
            previous_proof_validation,
            witness_row_count,
            linear_offsets,
            linear_indices,
            linear_coefficients,
            linear_targets,
        }
    }
}

impl SmallwoodConstraintAdapter for StepARelationV1 {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        self.witness_row_count
    }

    fn packing_factor(&self) -> usize {
        SMALLWOOD_STEP_PACKING_FACTOR_V1
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn linear_constraint_count(&self) -> usize {
        self.linear_targets.len()
    }

    fn constraint_count(&self) -> usize {
        1
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.linear_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &self.linear_indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &self.linear_coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        &self.linear_targets
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
        }
    }

    fn compute_constraints_u64(
        &self,
        _view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let structural_mismatch = step_relation_mismatch(
            &self.previous_statement,
            &self.leaf_record,
            &self.target_statement,
        );
        let validation = self.previous_proof_validation;
        let trace_mismatch = u64::from(
            !validation.witness_ready
                || !validation.descriptor_shape_valid
                || !validation.binding_trace_valid
                || !validation.transcript_valid
                || !validation.pcs_valid
                || !validation.decs_merkle_valid,
        );
        let mismatch = structural_mismatch.saturating_add(trace_mismatch);
        out[0] = mismatch.saturating_mul(mismatch);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepBRelationV1 {
    pub previous_recursive_proof: Box<HostedRecursiveProofContextV1>,
    pub previous_statement: RecursivePrefixStatementV1,
    pub leaf_record: BlockLeafRecordV1,
    pub target_statement: RecursivePrefixStatementV1,
    previous_proof_layout: Option<PreviousProofWitnessLayoutV1>,
    previous_proof_validation: PreviousProofWitnessValidationV1,
    witness_row_count: usize,
    linear_offsets: Vec<u32>,
    linear_indices: Vec<u32>,
    linear_coefficients: Vec<u64>,
    linear_targets: Vec<u64>,
}

impl StepBRelationV1 {
    pub fn new(
        previous_recursive_proof: HostedRecursiveProofContextV1,
        previous_statement: RecursivePrefixStatementV1,
        leaf_record: BlockLeafRecordV1,
        target_statement: RecursivePrefixStatementV1,
    ) -> Self {
        let previous_proof_layout =
            hosted_recursive_proof_witness_layout_v1(&previous_recursive_proof).ok();
        let (
            witness_row_count,
            linear_offsets,
            linear_indices,
            linear_coefficients,
            linear_targets,
        ) = match hosted_recursive_proof_witness_words_v1(&previous_recursive_proof) {
            Ok(witness_words) => {
                let row_count = previous_proof_rows_for_limbs_v1(witness_words.len()).max(1);
                let (offsets, indices, coefficients, targets) =
                    fixed_witness_linear_constraints_v1(&witness_words);
                (row_count, offsets, indices, coefficients, targets)
            }
            Err(_) => (
                SMALLWOOD_STEP_ROW_COUNT_V1,
                vec![0],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        };
        let previous_proof_validation = previous_proof_layout
            .map(|layout| {
                validate_previous_proof_witness_v1(
                    &previous_recursive_proof,
                    layout,
                    &linear_targets,
                )
            })
            .unwrap_or_default();
        Self {
            previous_recursive_proof: Box::new(previous_recursive_proof),
            previous_statement,
            leaf_record,
            target_statement,
            previous_proof_layout,
            previous_proof_validation,
            witness_row_count,
            linear_offsets,
            linear_indices,
            linear_coefficients,
            linear_targets,
        }
    }
}

impl SmallwoodConstraintAdapter for StepBRelationV1 {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        self.witness_row_count
    }

    fn packing_factor(&self) -> usize {
        SMALLWOOD_STEP_PACKING_FACTOR_V1
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn linear_constraint_count(&self) -> usize {
        self.linear_targets.len()
    }

    fn constraint_count(&self) -> usize {
        1
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.linear_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &self.linear_indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &self.linear_coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        &self.linear_targets
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
        }
    }

    fn compute_constraints_u64(
        &self,
        _view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let structural_mismatch = step_relation_mismatch(
            &self.previous_statement,
            &self.leaf_record,
            &self.target_statement,
        );
        let validation = self.previous_proof_validation;
        let trace_mismatch = u64::from(
            !validation.witness_ready
                || !validation.descriptor_shape_valid
                || !validation.binding_trace_valid
                || !validation.transcript_valid
                || !validation.pcs_valid
                || !validation.decs_merkle_valid,
        );
        let mismatch = structural_mismatch.saturating_add(trace_mismatch);
        out[0] = mismatch.saturating_mul(mismatch);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatementKindV1 {
    EmptyPrefix = 0,
    Prefix = 1,
    Leaf = 2,
}

pub fn recursive_block_relation_id_v1() -> RelationId {
    RelationId::from_label(RECURSIVE_BLOCK_RELATION_LABEL_V1)
}

pub fn recursive_block_shape_v1() -> CcsShape<Goldilocks> {
    CcsShape {
        num_rows: 1,
        num_cols: BLOCK_RECURSIVE_WITNESS_SLOTS,
        matrices: vec![SparseMatrix {
            row_count: 1,
            col_count: BLOCK_RECURSIVE_WITNESS_SLOTS,
            entries: Vec::new(),
        }],
        selectors: vec![Goldilocks::new(1)],
        witness_schema: WitnessSchema {
            fields: vec![WitnessField {
                name: "block_recursive_slot",
                bit_width: 64,
                signed: false,
                count: BLOCK_RECURSIVE_WITNESS_SLOTS,
            }],
        },
    }
}

pub fn recursive_block_shape_digest_v1() -> ShapeDigest {
    digest_shape(&recursive_block_shape_v1())
}

fn bytes48_to_goldilocks(bytes: &Digest48) -> [Goldilocks; 6] {
    std::array::from_fn(|idx| {
        let start = idx * 8;
        Goldilocks::new(u64::from_le_bytes(
            bytes[start..start + 8].try_into().expect("fixed slice"),
        ))
    })
}

fn bytes32_to_goldilocks(bytes: &Digest32) -> [Goldilocks; 4] {
    std::array::from_fn(|idx| {
        let start = idx * 8;
        Goldilocks::new(u64::from_le_bytes(
            bytes[start..start + 8].try_into().expect("fixed slice"),
        ))
    })
}

pub fn block_public_inputs_v1(public: &RecursiveBlockPublicV1) -> Vec<Goldilocks> {
    let mut inputs = Vec::with_capacity(1 + (6 * 11));
    inputs.push(Goldilocks::new(public.tx_count as u64));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.tx_statements_commitment));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.verified_leaf_commitment));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.verified_receipt_commitment));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.start_shielded_root));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.end_shielded_root));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.start_kernel_root));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.end_kernel_root));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.nullifier_root));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.da_root));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.start_tree_commitment));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&public.end_tree_commitment));
    inputs
}

pub fn block_leaf_inputs_v1(record: &BlockLeafRecordV1) -> Vec<Goldilocks> {
    let mut inputs = Vec::with_capacity(1 + (6 * 8) + (4 * 3));
    inputs.push(Goldilocks::new(record.tx_index as u64));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.receipt_statement_hash));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.receipt_proof_digest));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.receipt_public_inputs_digest));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.receipt_verifier_profile));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.leaf_params_fingerprint));
    inputs.extend_from_slice(&bytes32_to_goldilocks(&record.leaf_spec_digest));
    inputs.extend_from_slice(&bytes32_to_goldilocks(&record.leaf_relation_id));
    inputs.extend_from_slice(&bytes32_to_goldilocks(&record.leaf_shape_digest));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.leaf_statement_digest));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.leaf_commitment_digest));
    inputs.extend_from_slice(&bytes48_to_goldilocks(&record.leaf_proof_digest));
    inputs
}

fn statement_from_inputs(
    inputs: Vec<Goldilocks>,
    external_statement_digest: Digest48,
) -> RecursiveStatementEncoding<Goldilocks> {
    RecursiveStatementEncoding {
        public_inputs: inputs,
        statement_commitment: bytes48_to_goldilocks(&external_statement_digest),
        external_statement_digest: Some(external_statement_digest),
    }
}

pub fn prefix_statement_v1(
    public: &RecursiveBlockPublicV1,
) -> RecursiveStatementEncoding<Goldilocks> {
    statement_from_inputs(
        block_public_inputs_v1(public),
        crate::recursive_block_public_statement_digest_v1(public),
    )
}

pub fn leaf_statement_v1(record: &BlockLeafRecordV1) -> RecursiveStatementEncoding<Goldilocks> {
    let digest = crate::fold_digest48(
        b"hegemon.block-recursion.leaf-statement.v1",
        &[&crate::public_replay::canonical_verified_leaf_record_bytes_v1(record)],
    );
    statement_from_inputs(block_leaf_inputs_v1(record), digest)
}

pub fn empty_prefix_public_v1(
    semantic_tx_statements_commitment: Digest48,
) -> RecursiveBlockPublicV1 {
    RecursiveBlockPublicV1 {
        tx_count: 0,
        tx_statements_commitment: semantic_tx_statements_commitment,
        verified_leaf_commitment: [0u8; 48],
        verified_receipt_commitment: [0u8; 48],
        start_shielded_root: [0u8; 48],
        end_shielded_root: [0u8; 48],
        start_kernel_root: [0u8; 48],
        end_kernel_root: [0u8; 48],
        nullifier_root: [0u8; 48],
        da_root: [0u8; 48],
        start_tree_commitment: [0u8; 48],
        end_tree_commitment: [0u8; 48],
    }
}

pub fn pack_statement_witness_v1(
    kind: BlockStatementKindV1,
    statement: &RecursiveStatementEncoding<Goldilocks>,
) -> Result<PackedWitness<u64>, BlockRecursionError> {
    let mut witness = Vec::with_capacity(BLOCK_RECURSIVE_WITNESS_SLOTS);
    witness.push(Goldilocks::new(kind as u64));
    witness.push(Goldilocks::new(statement.public_inputs.len() as u64));
    witness.extend(statement.public_inputs.iter().copied());
    witness.extend(statement.statement_commitment);
    witness.push(Goldilocks::new(u64::from(
        statement.external_statement_digest.is_some(),
    )));
    if let Some(digest) = statement.external_statement_digest {
        witness.extend(bytes48_to_goldilocks(&digest));
    } else {
        witness.extend(std::iter::repeat_n(Goldilocks::new(0), 6));
    }
    if witness.len() > BLOCK_RECURSIVE_WITNESS_SLOTS {
        return Err(BlockRecursionError::InvalidLength {
            what: "block-recursive witness slots",
            expected: BLOCK_RECURSIVE_WITNESS_SLOTS,
            actual: witness.len(),
        });
    }
    witness.resize(BLOCK_RECURSIVE_WITNESS_SLOTS, Goldilocks::new(0));
    let assignment = Assignment { witness };
    let shape = recursive_block_shape_v1();
    GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default())
        .pack(&shape, &assignment)
        .map_err(|err| {
            BlockRecursionError::InvalidField(Box::leak(
                format!("failed to pack recursive witness: {err}").into_boxed_str(),
            ))
        })
}

pub fn ensure_expected_shape_v1(shape_digest: ShapeDigest) -> Result<(), BlockRecursionError> {
    if shape_digest != recursive_block_shape_digest_v1() {
        return Err(BlockRecursionError::InvalidField("shape_digest"));
    }
    Ok(())
}

pub fn ensure_expected_relation_v1(relation_id: RelationId) -> Result<(), BlockRecursionError> {
    if relation_id != recursive_block_relation_id_v1() {
        return Err(BlockRecursionError::InvalidField("relation_id"));
    }
    Ok(())
}
