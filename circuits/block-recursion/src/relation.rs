use crate::{
    BlockRecursionError, Digest32, Digest48, fold_digest32,
    local_smallwood_poseidon2::{
        SmallwoodConfig, decs_commitment_transcript, decs_recompute_root, derive_gamma_prime,
        ensure_no_packing_collisions, ensure_row_polynomial_arithmetization,
        hash_challenge_opening_decs, hash_piop_transcript, lvcs_recompute_rows,
        pcs_build_coefficients, pcs_reconstruct_combi_heads, piop_recompute_transcript,
        validate_proof_shape, xof_decs_opening, xof_piop_opening_points,
    },
    public_replay::{
        BlockLeafRecordV1, RecursiveBlockPublicV1, canonical_verified_leaf_record_bytes_v1,
    },
    statement::{RecursivePrefixStatementV1, recursive_prefix_statement_bytes_v1},
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
    SmallwoodNonlinearEvalView, SmallwoodProofTraceV1, SmallwoodRecursiveProfileTagV1,
    SmallwoodRecursiveRelationKindV1, SmallwoodRecursiveVerifierDescriptorV1,
    SmallwoodTranscriptBackend, TransactionCircuitError, SMALLWOOD_DECS_NB_EVALS,
    SMALLWOOD_DECS_NB_OPENED_EVALS, SMALLWOOD_DECS_POW_BITS, decode_smallwood_proof_trace_v1,
    decode_smallwood_recursive_proof_envelope_v1, projected_smallwood_recursive_envelope_bytes_v1,
    projected_smallwood_recursive_proof_bytes_v1, recursive_binding_bytes_v1,
    recursive_descriptor_v1, recursive_profile_a_v1, recursive_profile_b_v1,
    smallwood_binding_words_v1, verify_recursive_statement_direct_v1,
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
const RECURSIVE_PREFIX_STATEMENT_BYTES_LEN_V1: usize = 4 + (48 * 7);
const VERIFIED_LEAF_RECORD_BYTES_LEN_V1: usize = 4 + (48 * 8) + (32 * 3);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepWitnessLayoutV1 {
    pub row_width: usize,
    pub previous_statement: PreviousProofWitnessSectionV1,
    pub leaf_record: PreviousProofWitnessSectionV1,
    pub descriptor: PreviousProofWitnessSectionV1,
    pub envelope: PreviousProofWitnessSectionV1,
    pub transcript: PreviousProofWitnessSectionV1,
    pub pcs: PreviousProofWitnessSectionV1,
    pub decs: PreviousProofWitnessSectionV1,
    pub merkle: PreviousProofWitnessSectionV1,
    total_limbs: usize,
    total_rows: usize,
}

impl StepWitnessLayoutV1 {
    pub fn total_limbs(&self) -> usize {
        self.total_limbs
    }

    pub fn total_rows(&self) -> usize {
        self.total_rows
    }

    fn previous_proof_layout_v1(&self) -> PreviousProofWitnessLayoutV1 {
        PreviousProofWitnessLayoutV1 {
            row_width: self.row_width,
            descriptor: PreviousProofWitnessSectionV1::new(0, self.descriptor.limb_count, 0),
            envelope: PreviousProofWitnessSectionV1::new(
                self.descriptor.limb_count,
                self.envelope.limb_count,
                previous_proof_rows_for_limbs_v1(self.descriptor.limb_count),
            ),
            transcript: PreviousProofWitnessSectionV1::new(
                self.descriptor.limb_count + self.envelope.limb_count,
                self.transcript.limb_count,
                previous_proof_rows_for_limbs_v1(
                    self.descriptor.limb_count + self.envelope.limb_count,
                ),
            ),
            pcs: PreviousProofWitnessSectionV1::new(
                self.descriptor.limb_count + self.envelope.limb_count + self.transcript.limb_count,
                self.pcs.limb_count,
                previous_proof_rows_for_limbs_v1(
                    self.descriptor.limb_count + self.envelope.limb_count + self.transcript.limb_count,
                ),
            ),
            decs: PreviousProofWitnessSectionV1::new(
                self.descriptor.limb_count
                    + self.envelope.limb_count
                    + self.transcript.limb_count
                    + self.pcs.limb_count,
                self.decs.limb_count,
                previous_proof_rows_for_limbs_v1(
                    self.descriptor.limb_count
                        + self.envelope.limb_count
                        + self.transcript.limb_count
                        + self.pcs.limb_count,
                ),
            ),
            merkle: PreviousProofWitnessSectionV1::new(
                self.descriptor.limb_count
                    + self.envelope.limb_count
                    + self.transcript.limb_count
                    + self.pcs.limb_count
                    + self.decs.limb_count,
                self.merkle.limb_count,
                previous_proof_rows_for_limbs_v1(
                    self.descriptor.limb_count
                        + self.envelope.limb_count
                        + self.transcript.limb_count
                        + self.pcs.limb_count
                        + self.decs.limb_count,
                ),
            ),
            total_limbs: self.descriptor.limb_count
                + self.envelope.limb_count
                + self.transcript.limb_count
                + self.pcs.limb_count
                + self.decs.limb_count
                + self.merkle.limb_count,
            total_rows: previous_proof_rows_for_limbs_v1(
                self.descriptor.limb_count
                    + self.envelope.limb_count
                    + self.transcript.limb_count
                    + self.pcs.limb_count
                    + self.decs.limb_count
                    + self.merkle.limb_count,
            ),
        }
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

fn step_witness_layout_from_previous_proof_v1(
    previous_proof_layout: PreviousProofWitnessLayoutV1,
) -> StepWitnessLayoutV1 {
    let previous_statement_limbs =
        previous_proof_limbs_for_bytes_v1(RECURSIVE_PREFIX_STATEMENT_BYTES_LEN_V1);
    let leaf_record_limbs =
        previous_proof_limbs_for_bytes_v1(VERIFIED_LEAF_RECORD_BYTES_LEN_V1);

    let previous_statement = PreviousProofWitnessSectionV1::new(0, previous_statement_limbs, 0);
    let leaf_record = PreviousProofWitnessSectionV1::new(
        previous_statement.limb_start + previous_statement.limb_count,
        leaf_record_limbs,
        previous_statement.row_start + previous_statement.row_count,
    );
    let descriptor = PreviousProofWitnessSectionV1::new(
        leaf_record.limb_start + leaf_record.limb_count,
        previous_proof_layout.descriptor.limb_count,
        leaf_record.row_start + leaf_record.row_count,
    );
    let envelope = PreviousProofWitnessSectionV1::new(
        descriptor.limb_start + descriptor.limb_count,
        previous_proof_layout.envelope.limb_count,
        descriptor.row_start + descriptor.row_count,
    );
    let transcript = PreviousProofWitnessSectionV1::new(
        envelope.limb_start + envelope.limb_count,
        previous_proof_layout.transcript.limb_count,
        envelope.row_start + envelope.row_count,
    );
    let pcs = PreviousProofWitnessSectionV1::new(
        transcript.limb_start + transcript.limb_count,
        previous_proof_layout.pcs.limb_count,
        transcript.row_start + transcript.row_count,
    );
    let decs = PreviousProofWitnessSectionV1::new(
        pcs.limb_start + pcs.limb_count,
        previous_proof_layout.decs.limb_count,
        pcs.row_start + pcs.row_count,
    );
    let merkle = PreviousProofWitnessSectionV1::new(
        decs.limb_start + decs.limb_count,
        previous_proof_layout.merkle.limb_count,
        decs.row_start + decs.row_count,
    );
    let total_limbs = merkle.limb_start + merkle.limb_count;
    let total_rows = previous_proof_rows_for_limbs_v1(total_limbs);
    StepWitnessLayoutV1 {
        row_width: PREVIOUS_PROOF_WITNESS_ROW_WIDTH_LIMBS_V1,
        previous_statement,
        leaf_record,
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

pub fn step_recursive_witness_layout_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<StepWitnessLayoutV1, TransactionCircuitError> {
    Ok(step_witness_layout_from_previous_proof_v1(
        hosted_recursive_proof_witness_layout_v1(context)?,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StepWitnessV1 {
    previous_statement: RecursivePrefixStatementV1,
    leaf_record: BlockLeafRecordV1,
    previous_proof_words: Vec<u64>,
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
    recursive_prefix_statement_bytes_v1(statement)
}

pub fn hosted_step_binding_bytes_v1(
    target_statement: &RecursivePrefixStatementV1,
) -> Vec<u8> {
    recursive_prefix_statement_bytes_v1(target_statement)
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
            let binding = hosted_step_binding_bytes_v1(target_statement);
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
            let binding = hosted_step_binding_bytes_v1(target_statement);
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
struct RecomputedPreviousProofComponentsV1 {
    descriptor: SmallwoodRecursiveVerifierDescriptorV1,
    binded_data: Vec<u8>,
    proof_bytes: Vec<u8>,
    proof_trace: SmallwoodProofTraceV1,
    eval_points: Vec<u64>,
    coeffs: Vec<Vec<u64>>,
    combi_heads: Vec<Vec<u64>>,
    decs_trans_hash: Digest32,
    decs_leaf_indexes: Vec<u32>,
    decs_nonce: [u8; 4],
    decs_eval_points: Vec<u64>,
    rows: Vec<Vec<u64>>,
    root_digest: Digest32,
    pcs_transcript_words: Vec<u64>,
    piop_input_words: Vec<u64>,
    piop_gamma_prime: Vec<Vec<u64>>,
    piop_transcript_words: Vec<u64>,
    accept: bool,
}

impl RecomputedPreviousProofComponentsV1 {
    fn descriptor_words_v1(&self) -> Vec<u64> {
        bytes_to_witness_limbs_v1(&self.descriptor.serialized_v1())
    }

    fn proof_words_v1(&self) -> Vec<u64> {
        bytes_to_witness_limbs_v1(&self.proof_bytes)
    }

    fn transcript_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(
            &smallwood_binding_words_v1(
                &recursive_binding_bytes_v1(&self.descriptor, &self.binded_data),
            )
            .unwrap_or_default(),
        );
        out.extend_from_slice(&self.eval_points);
        out.extend_from_slice(&flatten_matrix_words_v1(&self.piop_gamma_prime));
        out.extend_from_slice(&self.pcs_transcript_words);
        out.extend_from_slice(&self.piop_input_words);
        out.extend_from_slice(&self.piop_transcript_words);
        out.extend_from_slice(&digest_words_v1(&self.proof_trace.h_piop));
        out.push(self.accept as u64);
        out
    }

    fn pcs_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(&flatten_matrix_words_v1(
            &self.proof_trace.opened_witness_row_scalars,
        ));
        out.extend_from_slice(&flatten_matrix_words_v1(self.proof_trace.pcs_partial_evals_v1()));
        out.extend_from_slice(&flatten_matrix_words_v1(self.proof_trace.pcs_rcombi_tails_v1()));
        out.extend_from_slice(&flatten_matrix_words_v1(self.proof_trace.pcs_subset_evals_v1()));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.coeffs));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.combi_heads));
        out.extend_from_slice(&digest_words_v1(&self.decs_trans_hash));
        out.extend_from_slice(&self.pcs_transcript_words);
        out
    }

    fn decs_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(&digest_words_v1(&self.decs_trans_hash));
        out.extend_from_slice(&flatten_u32_words_v1(&self.decs_leaf_indexes));
        out.extend_from_slice(&nonce_words_v1(&self.decs_nonce));
        out.extend_from_slice(&self.decs_eval_points);
        out.extend_from_slice(&flatten_matrix_words_v1(
            self.proof_trace.decs_masking_evals_v1(),
        ));
        out.extend_from_slice(&flatten_matrix_words_v1(
            self.proof_trace.decs_high_coeffs_v1(),
        ));
        out.extend_from_slice(&self.pcs_transcript_words);
        out
    }

    fn merkle_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(&flatten_matrix_words_v1(&self.rows));
        out.extend_from_slice(&flatten_auth_path_words_v1(
            self.proof_trace.decs_auth_paths_v1(),
        ));
        out.extend_from_slice(&digest_words_v1(&self.root_digest));
        out
    }

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
        if self.piop_gamma_prime.len() != 2 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript gamma-prime count mismatch",
            ));
        }
        if self.pcs_transcript_words.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript PCS/DECS transcript mismatch",
            ));
        }
        if self.piop_input_words.len() < binding_words.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop-input length mismatch",
            ));
        }
        if !self.piop_input_words.starts_with(&self.pcs_transcript_words)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop-input prefix mismatch",
            ));
        }
        if self.piop_input_words[self.pcs_transcript_words.len()..] != binding_words
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop-input binding suffix mismatch",
            ));
        }
        if self.piop_transcript_words.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier transcript piop transcript words missing",
            ));
        }
        Ok(())
    }

    fn validate_pcs_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_combi_count = self.coeffs.len();
        if self.proof_trace.opened_witness_row_scalars.len() != self.eval_points.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS opened-row/eval-point count mismatch",
            ));
        }
        if opened_combi_count == 0 || opened_combi_count != self.combi_heads.len() {
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
        if self.proof_trace.pcs_subset_evals_v1().len() != self.decs_leaf_indexes.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS subset-eval count mismatch",
            ));
        }
        if self.pcs_transcript_words.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS transcript mismatch",
            ));
        }
        if self.rows.is_empty() || self.rows.len() != self.decs_eval_points.len()
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS opened-row count mismatch",
            ));
        }
        if self.decs_leaf_indexes.len() != self.decs_eval_points.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS leaf-index/decs-point count mismatch",
            ));
        }
        if self
            .decs_leaf_indexes
            .iter()
            .zip(self.decs_eval_points.iter())
            .any(|(leaf, point)| u64::from(*leaf) != *point)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS leaf-index/decs-point value mismatch",
            ));
        }
        let expected_row_width = self.coeffs.first().map(Vec::len).unwrap_or_default();
        if expected_row_width == 0 || self.rows.iter().any(|row| row.len() != expected_row_width)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier PCS opened-row width mismatch",
            ));
        }
        Ok(())
    }

    fn validate_decs_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_count = self.decs_leaf_indexes.len();
        if opened_count == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier DECS opened-leaf set is empty",
            ));
        }
        if self.decs_eval_points.len() != opened_count
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
        if self.pcs_transcript_words.is_empty() {
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
        let opened_count = self.decs_leaf_indexes.len();
        if self.rows.len() != opened_count || self.proof_trace.decs_auth_paths_v1().len() != opened_count
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
        if self.root_digest == [0u8; 32] {
            return Err(TransactionCircuitError::ConstraintViolation(
                "recursive verifier Merkle root digest missing",
            ));
        }
        for idx in 0..opened_count {
            if self.rows[idx].is_empty() {
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

fn recompute_previous_proof_components_from_proof_bytes_v1(
    descriptor: SmallwoodRecursiveVerifierDescriptorV1,
    relation: &(dyn SmallwoodConstraintAdapter + Sync),
    binding: Vec<u8>,
    proof_bytes: Vec<u8>,
    proof_bytes_len: usize,
) -> Result<RecomputedPreviousProofComponentsV1, TransactionCircuitError> {
    if proof_bytes.len() != proof_bytes_len {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope proof length mismatch",
        ));
    }
    let cfg = SmallwoodConfig::new(relation)?;
    ensure_row_polynomial_arithmetization(relation)?;
    let proof_trace = decode_smallwood_proof_trace_v1(&proof_bytes)?;
    validate_proof_shape(&cfg, &proof_trace)?;
    let binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&descriptor, &binding))?;
    let eval_points = xof_piop_opening_points(
        &proof_trace.nonce,
        &proof_trace.h_piop,
        SmallwoodTranscriptBackend::Poseidon2,
    );
    ensure_no_packing_collisions(cfg.packing_points_v1(), &eval_points)?;
    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows_v1()]; cfg.nb_lvcs_opened_combi_v1()];
    pcs_build_coefficients(&cfg, &eval_points, &mut coeffs);
    let combi_heads = pcs_reconstruct_combi_heads(
        &cfg,
        &eval_points,
        &proof_trace.opened_witness_row_scalars,
        proof_trace.pcs_partial_evals_v1(),
    )?;
    let decs_trans_hash = hash_challenge_opening_decs(
        &cfg,
        &combi_heads,
        &proof_trace.h_piop,
        proof_trace.pcs_rcombi_tails_v1(),
        SmallwoodTranscriptBackend::Poseidon2,
    );
    let (decs_leaf_indexes, decs_nonce) = xof_decs_opening(
        SMALLWOOD_DECS_NB_EVALS,
        SMALLWOOD_DECS_NB_OPENED_EVALS,
        SMALLWOOD_DECS_POW_BITS,
        &decs_trans_hash,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let decs_eval_points = decs_leaf_indexes
        .iter()
        .map(|&idx| idx as u64)
        .collect::<Vec<_>>();
    let rows = lvcs_recompute_rows(
        &cfg,
        &coeffs,
        &combi_heads,
        proof_trace.pcs_rcombi_tails_v1(),
        proof_trace.pcs_subset_evals_v1(),
        &decs_eval_points,
    )?;
    let root_digest = decs_recompute_root(
        &cfg,
        &proof_trace.salt,
        &rows,
        &decs_eval_points,
        &proof_trace,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let pcs_transcript_words = decs_commitment_transcript(
        &cfg,
        &proof_trace.salt,
        &rows,
        &root_digest,
        &decs_eval_points,
        &proof_trace,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let mut piop_input_words = pcs_transcript_words.clone();
    piop_input_words.extend_from_slice(&binding_words);
    let piop_transcript_words = piop_recompute_transcript(
        &cfg,
        relation,
        &piop_input_words,
        &eval_points,
        &proof_trace,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let hash_fpp = hash_piop_transcript(&piop_input_words, SmallwoodTranscriptBackend::Poseidon2);
    let piop_gamma_prime =
        derive_gamma_prime(&cfg, &hash_fpp, SmallwoodTranscriptBackend::Poseidon2);
    let accept = hash_piop_transcript(&piop_transcript_words, SmallwoodTranscriptBackend::Poseidon2)
        == proof_trace.h_piop;

    let components = RecomputedPreviousProofComponentsV1 {
        descriptor,
        binded_data: binding,
        proof_bytes,
        proof_trace,
        eval_points,
        coeffs,
        combi_heads,
        decs_trans_hash,
        decs_leaf_indexes,
        decs_nonce,
        decs_eval_points,
        rows,
        root_digest,
        pcs_transcript_words,
        piop_input_words,
        piop_gamma_prime,
        piop_transcript_words,
        accept,
    };
    components.validate_transcript_section_v1()?;
    components.validate_pcs_section_v1()?;
    components.validate_decs_section_v1()?;
    components.validate_merkle_section_v1()?;
    Ok(components)
}

fn recompute_previous_proof_components_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<RecomputedPreviousProofComponentsV1, TransactionCircuitError> {
    let (profile, descriptor, relation, binding, proof_bytes_len) =
        build_expected_recursive_inputs_v1(context)?;
    let proof_bytes = verify_recursive_proof_envelope_structure_v1(
        &profile,
        &descriptor,
        relation.as_ref(),
        context.proof_envelope_bytes(),
    )?;
    recompute_previous_proof_components_from_proof_bytes_v1(
        descriptor,
        relation.as_ref(),
        binding,
        proof_bytes,
        proof_bytes_len,
    )
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
    let components = recompute_previous_proof_components_v1(context)?;
    let binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&descriptor, &binding))?;
    if components.descriptor != descriptor {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace descriptor mismatch",
        ));
    }
    if components.binded_data != binding {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace binding payload mismatch",
        ));
    }
    if !components.transcript_words_v1().starts_with(&binding_words) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace binding words mismatch",
        ));
    }
    if !components.accept {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace accept bit mismatch",
        ));
    }
    Ok(())
}

pub fn hosted_recursive_proof_witness_layout_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<PreviousProofWitnessLayoutV1, TransactionCircuitError> {
    let components = recompute_previous_proof_components_v1(context)?;
    Ok(previous_proof_witness_layout_from_sections_v1(
        components.descriptor.serialized_v1().len(),
        components.proof_bytes.len(),
        components.transcript_words_v1().len(),
        components.pcs_words_v1().len(),
        components.decs_words_v1().len(),
        components.merkle_words_v1().len(),
    ))
}

pub fn hosted_recursive_proof_witness_words_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let components = recompute_previous_proof_components_v1(context)?;
    let layout = hosted_recursive_proof_witness_layout_v1(context)?;
    let descriptor_words = components.descriptor_words_v1();
    let proof_words = components.proof_words_v1();
    let transcript_words = components.transcript_words_v1();
    let pcs_words = components.pcs_words_v1();
    let decs_words = components.decs_words_v1();
    let merkle_words = components.merkle_words_v1();
    let witness_sections = [
        (
            "descriptor",
            layout.descriptor.limb_count,
            descriptor_words.as_slice(),
        ),
        (
            "envelope",
            layout.envelope.limb_count,
            proof_words.as_slice(),
        ),
        (
            "transcript",
            layout.transcript.limb_count,
            transcript_words.as_slice(),
        ),
        ("pcs", layout.pcs.limb_count, pcs_words.as_slice()),
        ("decs", layout.decs.limb_count, decs_words.as_slice()),
        (
            "merkle",
            layout.merkle.limb_count,
            merkle_words.as_slice(),
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

fn read_exact_fixed_v1<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], TransactionCircuitError> {
    let end = cursor.saturating_add(N);
    let slice = bytes
        .get(*cursor..end)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "recursive step witness byte section truncated",
        ))?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    *cursor = end;
    Ok(out)
}

fn read_exact_u32_v1(bytes: &[u8], cursor: &mut usize) -> Result<u32, TransactionCircuitError> {
    Ok(u32::from_le_bytes(read_exact_fixed_v1::<4>(bytes, cursor)?))
}

fn decode_recursive_prefix_statement_from_bytes_v1(
    bytes: &[u8],
) -> Result<RecursivePrefixStatementV1, TransactionCircuitError> {
    let mut cursor = 0usize;
    let statement = RecursivePrefixStatementV1 {
        tx_count: read_exact_u32_v1(bytes, &mut cursor)?,
        start_state_digest: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        end_state_digest: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        verified_leaf_commitment: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        tx_statements_commitment: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        verified_receipt_commitment: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        start_tree_commitment: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        end_tree_commitment: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
    };
    if cursor != bytes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive step statement bytes must exact-consume",
        ));
    }
    Ok(statement)
}

fn decode_block_leaf_record_from_bytes_v1(
    bytes: &[u8],
) -> Result<BlockLeafRecordV1, TransactionCircuitError> {
    let mut cursor = 0usize;
    let record = BlockLeafRecordV1 {
        tx_index: read_exact_u32_v1(bytes, &mut cursor)?,
        receipt_statement_hash: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        receipt_proof_digest: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        receipt_public_inputs_digest: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        receipt_verifier_profile: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        leaf_params_fingerprint: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        leaf_spec_digest: read_exact_fixed_v1::<32>(bytes, &mut cursor)?,
        leaf_relation_id: read_exact_fixed_v1::<32>(bytes, &mut cursor)?,
        leaf_shape_digest: read_exact_fixed_v1::<32>(bytes, &mut cursor)?,
        leaf_statement_digest: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        leaf_commitment_digest: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
        leaf_proof_digest: read_exact_fixed_v1::<48>(bytes, &mut cursor)?,
    };
    if cursor != bytes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive step leaf bytes must exact-consume",
        ));
    }
    Ok(record)
}

pub fn step_recursive_witness_words_v1(
    context: &HostedRecursiveProofContextV1,
    previous_statement: &RecursivePrefixStatementV1,
    leaf_record: &BlockLeafRecordV1,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let layout = step_recursive_witness_layout_v1(context)?;
    let previous_proof_words = hosted_recursive_proof_witness_words_v1(context)?;
    let previous_statement_words =
        bytes_to_witness_limbs_v1(&recursive_prefix_statement_bytes_v1(previous_statement));
    let leaf_record_words =
        bytes_to_witness_limbs_v1(&canonical_verified_leaf_record_bytes_v1(leaf_record));
    let previous_proof_layout = layout.previous_proof_layout_v1();
    let witness_sections = [
        (
            "previous_statement",
            layout.previous_statement.limb_count,
            previous_statement_words.as_slice(),
        ),
        ("leaf_record", layout.leaf_record.limb_count, leaf_record_words.as_slice()),
        (
            "previous_proof",
            previous_proof_layout.total_rows() * previous_proof_layout.row_width,
            previous_proof_words.as_slice(),
        ),
    ];
    let mut out = Vec::with_capacity(layout.total_rows() * layout.row_width);
    for (name, limit, words) in witness_sections {
        if words.len() > limit {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "recursive step witness {name} section exceeds fixed limb budget: {} > {}",
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

fn decode_step_witness_v1(
    layout: StepWitnessLayoutV1,
    witness_words: &[u64],
) -> Result<StepWitnessV1, TransactionCircuitError> {
    if witness_words.len() < layout.total_rows() * layout.row_width {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive step witness words truncated",
        ));
    }
    let previous_statement_bytes = witness_words_to_bytes_v1(
        witness_section_words_v1(witness_words, layout.previous_statement)?,
        RECURSIVE_PREFIX_STATEMENT_BYTES_LEN_V1,
    )?;
    let leaf_record_bytes = witness_words_to_bytes_v1(
        witness_section_words_v1(witness_words, layout.leaf_record)?,
        VERIFIED_LEAF_RECORD_BYTES_LEN_V1,
    )?;
    let previous_proof_layout = layout.previous_proof_layout_v1();
    let mut previous_proof_words =
        Vec::with_capacity(previous_proof_layout.total_rows() * previous_proof_layout.row_width);
    for section in [
        layout.descriptor,
        layout.envelope,
        layout.transcript,
        layout.pcs,
        layout.decs,
        layout.merkle,
    ] {
        previous_proof_words.extend_from_slice(witness_section_words_v1(witness_words, section)?);
    }
    previous_proof_words.resize(
        previous_proof_layout.total_rows() * previous_proof_layout.row_width,
        0,
    );
    Ok(StepWitnessV1 {
        previous_statement: decode_recursive_prefix_statement_from_bytes_v1(&previous_statement_bytes)?,
        leaf_record: decode_block_leaf_record_from_bytes_v1(&leaf_record_bytes)?,
        previous_proof_words,
    })
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
            hosted_step_binding_bytes_v1(target_statement),
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
            hosted_step_binding_bytes_v1(target_statement),
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

    let Ok((_, descriptor, relation, binding, proof_bytes_len)) =
        build_expected_recursive_inputs_v1(context)
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

    let Ok(components) = recompute_previous_proof_components_from_proof_bytes_v1(
        descriptor.clone(),
        relation.as_ref(),
        binding.clone(),
        proof_bytes,
        proof_bytes_len,
    ) else {
        return validation;
    };
    let transcript_words = components.transcript_words_v1();
    let pcs_words = components.pcs_words_v1();
    let decs_words = components.decs_words_v1();
    let merkle_words = components.merkle_words_v1();

    let expected_binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&descriptor, &binding))
            .unwrap_or_default();
    validation.binding_trace_valid = components.descriptor == descriptor
        && components.binded_data == binding
        && transcript_words.starts_with(&expected_binding_words)
        && components.accept;

    validation.transcript_valid = components.validate_transcript_section_v1().is_ok()
        && witness_section_words_v1(witness_words, layout.transcript)
            .map(|words| words == transcript_words.as_slice())
            .unwrap_or(false);

    validation.pcs_valid = components.validate_pcs_section_v1().is_ok()
        && witness_section_words_v1(witness_words, layout.pcs)
            .map(|words| words == pcs_words.as_slice())
            .unwrap_or(false);

    validation.decs_merkle_valid = components.validate_decs_section_v1().is_ok()
        && components.validate_merkle_section_v1().is_ok()
        && witness_section_words_v1(witness_words, layout.decs)
            .map(|words| words == decs_words.as_slice())
            .unwrap_or(false)
        && witness_section_words_v1(witness_words, layout.merkle)
            .map(|words| words == merkle_words.as_slice())
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

    let components = recompute_previous_proof_components_v1(context)?;
    if components.eval_points.len() != 3 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace opening-point count mismatch",
        ));
    }
    let binding_words =
        smallwood_binding_words_v1(&recursive_binding_bytes_v1(&components.descriptor, &components.binded_data))?;
    if components.piop_input_words.len() < binding_words.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace piop input too short",
        ));
    }
    let split = components.piop_input_words.len() - binding_words.len();
    if components.piop_input_words[..split] != components.pcs_transcript_words {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace pcs transcript prefix mismatch",
        ));
    }
    if components.piop_input_words[split..] != binding_words {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace binding suffix mismatch",
        ));
    }
    if components.pcs_transcript_words.is_empty() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace decs transcript mismatch",
        ));
    }
    if components.piop_gamma_prime.is_empty() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive verifier trace missing gamma prime values",
        ));
    }
    Ok(())
}

fn verify_pcs_trace_v1(
    components: &RecomputedPreviousProofComponentsV1,
) -> Result<(), TransactionCircuitError> {
    components.validate_pcs_section_v1()
}

fn verify_decs_merkle_trace_v1(
    components: &RecomputedPreviousProofComponentsV1,
) -> Result<(), TransactionCircuitError> {
    components.validate_decs_section_v1()?;
    components.validate_merkle_section_v1()
}

pub fn verify_hosted_recursive_proof_context_pcs_v1(
    context: &HostedRecursiveProofContextV1,
) -> Result<(), TransactionCircuitError> {
    match context {
        HostedRecursiveProofContextV1::BaseA { .. } => verify_pcs_trace_v1(
            &recompute_previous_proof_components_v1(context).map_err(|err| {
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
                &recompute_previous_proof_components_v1(context).map_err(|err| {
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
                &recompute_previous_proof_components_v1(context).map_err(|err| {
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
            &recompute_previous_proof_components_v1(context).map_err(|err| {
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
                &recompute_previous_proof_components_v1(context).map_err(|err| {
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
                &recompute_previous_proof_components_v1(context).map_err(|err| {
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
    pub target_statement: RecursivePrefixStatementV1,
    step_witness_layout: Option<StepWitnessLayoutV1>,
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
        let step_witness_layout = step_recursive_witness_layout_v1(&previous_recursive_proof).ok();
        let (
            witness_row_count,
            linear_offsets,
            linear_indices,
            linear_coefficients,
            linear_targets,
        ) = match step_recursive_witness_words_v1(
            &previous_recursive_proof,
            &previous_statement,
            &leaf_record,
        ) {
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
        Self {
            previous_recursive_proof: Box::new(previous_recursive_proof),
            target_statement,
            step_witness_layout,
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
        SmallwoodNonlinearEvalView::RowScalars { eval_point, rows: row_scalars }
    }

    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let _ = view;
        let witness = self
            .step_witness_layout
            .and_then(|layout| decode_step_witness_v1(layout, &self.linear_targets).ok());
        let structural_mismatch = witness
            .as_ref()
            .map(|witness| {
                step_relation_mismatch(
                    &witness.previous_statement,
                    &witness.leaf_record,
                    &self.target_statement,
                )
            })
            .unwrap_or(1);
        let validation = self
            .step_witness_layout
            .and_then(|layout| {
                witness.as_ref().map(|witness| {
                    validate_previous_proof_witness_v1(
                        &self.previous_recursive_proof,
                        layout.previous_proof_layout_v1(),
                        &witness.previous_proof_words,
                    )
                })
            })
            .unwrap_or_default();
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
    pub target_statement: RecursivePrefixStatementV1,
    step_witness_layout: Option<StepWitnessLayoutV1>,
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
        let step_witness_layout = step_recursive_witness_layout_v1(&previous_recursive_proof).ok();
        let (
            witness_row_count,
            linear_offsets,
            linear_indices,
            linear_coefficients,
            linear_targets,
        ) = match step_recursive_witness_words_v1(
            &previous_recursive_proof,
            &previous_statement,
            &leaf_record,
        ) {
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
        Self {
            previous_recursive_proof: Box::new(previous_recursive_proof),
            target_statement,
            step_witness_layout,
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
        SmallwoodNonlinearEvalView::RowScalars { eval_point, rows: row_scalars }
    }

    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let _ = view;
        let witness = self
            .step_witness_layout
            .and_then(|layout| decode_step_witness_v1(layout, &self.linear_targets).ok());
        let structural_mismatch = witness
            .as_ref()
            .map(|witness| {
                step_relation_mismatch(
                    &witness.previous_statement,
                    &witness.leaf_record,
                    &self.target_statement,
                )
            })
            .unwrap_or(1);
        let validation = self
            .step_witness_layout
            .and_then(|layout| {
                witness.as_ref().map(|witness| {
                    validate_previous_proof_witness_v1(
                        &self.previous_recursive_proof,
                        layout.previous_proof_layout_v1(),
                        &witness.previous_proof_words,
                    )
                })
            })
            .unwrap_or_default();
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
