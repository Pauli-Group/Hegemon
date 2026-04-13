use crate::{
    fold_digest32, fold_digest48,
    public_replay::{BlockLeafRecordV1, RecursiveBlockPublicV1},
    statement::{recursive_prefix_statement_digest_v1, RecursivePrefixStatementV1},
    BlockRecursionError, Digest32, Digest48,
};
use p3_goldilocks::Goldilocks;
use superneo_ccs::{
    digest_shape, Assignment, CcsShape, RelationId, ShapeDigest, SparseMatrix, WitnessField,
    WitnessSchema,
};
use superneo_core::RecursiveStatementEncoding;
use superneo_ring::{
    GoldilocksPackingConfig, GoldilocksPayPerBitPacker, PackedWitness, WitnessPacker,
};
use transaction_circuit::{
    decode_smallwood_recursive_proof_envelope_v1, projected_smallwood_recursive_envelope_bytes_v1,
    projected_smallwood_recursive_proof_bytes_v1, recursive_descriptor_v1,
    recursive_profile_a_v1, recursive_profile_b_v1,
    verify_recursive_statement_direct_v1, RecursiveSmallwoodProfileV1,
    SmallwoodArithmetization, SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView,
    SmallwoodRecursiveProfileTagV1, SmallwoodRecursiveRelationKindV1,
    SmallwoodRecursiveVerifierDescriptorV1, TransactionCircuitError,
};
use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;

const RECURSIVE_BLOCK_RELATION_LABEL_V1: &str = "hegemon.superneo.block-recursive.v1";
const BLOCK_RECURSIVE_WITNESS_SLOTS: usize = 96;
const SMALLWOOD_BASE_A_ROW_COUNT_V1: usize = 1;
const SMALLWOOD_BASE_A_PACKING_FACTOR_V1: usize = 8;
const SMALLWOOD_STEP_ROW_COUNT_V1: usize = 1;
const SMALLWOOD_STEP_PACKING_FACTOR_V1: usize = 8;

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
        SmallwoodRecursiveProfileTagV1::A => recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        SmallwoodRecursiveProfileTagV1::B => recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
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
    recursive_descriptor_v1(&profile_cfg, relation_kind, relation_id, shape_digest, vk_digest)
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

pub fn verify_recursive_proof_envelope_components_v1(
    profile: &RecursiveSmallwoodProfileV1,
    expected_descriptor: &SmallwoodRecursiveVerifierDescriptorV1,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    envelope_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let envelope = decode_smallwood_recursive_proof_envelope_v1(envelope_bytes)?;
    if envelope.descriptor != *expected_descriptor {
        return Err(TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope descriptor mismatch",
        ));
    }
    let expected_proof_bytes_len = projected_smallwood_recursive_proof_bytes_v1(profile, statement)?;
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
    verify_recursive_statement_direct_v1(
        profile,
        expected_descriptor,
        statement,
        binded_data,
        &envelope.proof_bytes,
    )
}

pub fn verify_hosted_recursive_proof_context_components_v1(
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
            let binding = hosted_base_binding_bytes_v1(statement);
            verify_recursive_proof_envelope_components_v1(
                &hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::A),
                &descriptor,
                &relation,
                &binding,
                proof_envelope_bytes,
            )
        }
        HostedRecursiveProofContextV1::StepA {
            previous_recursive_proof,
            previous_statement,
            leaf_record,
            target_statement,
            proof_envelope_bytes,
        } => {
            verify_hosted_recursive_proof_context_components_v1(previous_recursive_proof)?;
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
            verify_recursive_proof_envelope_components_v1(
                &hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::A),
                &descriptor,
                &relation,
                &binding,
                proof_envelope_bytes,
            )
        }
        HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof,
            previous_statement,
            leaf_record,
            target_statement,
            proof_envelope_bytes,
        } => {
            verify_hosted_recursive_proof_context_components_v1(previous_recursive_proof)?;
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
            verify_recursive_proof_envelope_components_v1(
                &hosted_recursive_profile_v1(SmallwoodRecursiveProfileTagV1::B),
                &descriptor,
                &relation,
                &binding,
                proof_envelope_bytes,
            )
        }
    }
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
    let start_state_ok = target_statement.start_state_digest == previous_statement.start_state_digest;
    let tx_commitment_ok =
        target_statement.tx_statements_commitment == previous_statement.tx_statements_commitment;
    let start_tree_ok = target_statement.start_tree_commitment == previous_statement.start_tree_commitment;
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
    linear_offsets: Vec<u32>,
}

impl StepARelationV1 {
    pub fn new(
        previous_recursive_proof: HostedRecursiveProofContextV1,
        previous_statement: RecursivePrefixStatementV1,
        leaf_record: BlockLeafRecordV1,
        target_statement: RecursivePrefixStatementV1,
    ) -> Self {
        Self {
            previous_recursive_proof: Box::new(previous_recursive_proof),
            previous_statement,
            leaf_record,
            target_statement,
            linear_offsets: vec![0],
        }
    }
}

impl SmallwoodConstraintAdapter for StepARelationV1 {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        SMALLWOOD_STEP_ROW_COUNT_V1
    }

    fn packing_factor(&self) -> usize {
        SMALLWOOD_STEP_PACKING_FACTOR_V1
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
        let structural_mismatch = step_relation_mismatch(
            &self.previous_statement,
            &self.leaf_record,
            &self.target_statement,
        );
        let recursive_mismatch = u64::from(
            verify_hosted_recursive_proof_context_components_v1(&self.previous_recursive_proof)
                .is_err(),
        );
        let mismatch = structural_mismatch.saturating_add(recursive_mismatch);
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
    linear_offsets: Vec<u32>,
}

impl StepBRelationV1 {
    pub fn new(
        previous_recursive_proof: HostedRecursiveProofContextV1,
        previous_statement: RecursivePrefixStatementV1,
        leaf_record: BlockLeafRecordV1,
        target_statement: RecursivePrefixStatementV1,
    ) -> Self {
        Self {
            previous_recursive_proof: Box::new(previous_recursive_proof),
            previous_statement,
            leaf_record,
            target_statement,
            linear_offsets: vec![0],
        }
    }
}

impl SmallwoodConstraintAdapter for StepBRelationV1 {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        SMALLWOOD_STEP_ROW_COUNT_V1
    }

    fn packing_factor(&self) -> usize {
        SMALLWOOD_STEP_PACKING_FACTOR_V1
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
        let structural_mismatch = step_relation_mismatch(
            &self.previous_statement,
            &self.leaf_record,
            &self.target_statement,
        );
        let recursive_mismatch = u64::from(
            verify_hosted_recursive_proof_context_components_v1(&self.previous_recursive_proof)
                .is_err(),
        );
        let mismatch = structural_mismatch.saturating_add(recursive_mismatch);
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
