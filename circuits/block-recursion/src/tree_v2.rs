use crate::{
    fold_digest32, fold_digest48,
    public_replay::{
        canonical_receipt_record_bytes_v1, canonical_verified_leaf_record_bytes_v1,
        prefix_statement_for_records_v1, BlockLeafRecordV1, BlockSemanticInputsV1,
    },
    statement::RecursivePrefixStatementV1,
    BlockRecursionError, Digest32, Digest48,
};
use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;
use rayon::prelude::*;
use std::sync::OnceLock;
use transaction_circuit::{
    decode_smallwood_proof_trace_prefix_v1, decode_smallwood_proof_trace_v1,
    encode_smallwood_proof_trace_v1, projected_smallwood_recursive_proof_bytes_v1,
    prove_recursive_statement_v1, recursive_descriptor_v1, recursive_profile_a_v1,
    recursive_profile_b_v1, verify_recursive_statement_direct_v1, SmallwoodArithmetization,
    SmallwoodConstraintAdapter, SmallwoodLinearConstraintForm, SmallwoodNonlinearEvalView,
    SmallwoodRecursiveProfileTagV1, SmallwoodRecursiveRelationKindV1,
    SmallwoodRecursiveVerifierDescriptorV1, TransactionCircuitError,
};

pub const RECURSIVE_BLOCK_ARTIFACT_VERSION_V2: u32 = 2;
pub const TREE_RECURSIVE_CHUNK_SIZE_V2: usize = 1000;
pub const TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2: usize = 1000;
const TREE_RECURSIVE_WITNESS_ROW_COUNT_V2: usize = 1;
const TREE_RECURSIVE_WITNESS_PACKING_FACTOR_V2: usize = 64;
const RECURSIVE_BLOCK_HEADER_BYTES_V2: usize = 112;
const RECURSIVE_BLOCK_PUBLIC_BYTES_V2: usize = 4 + (48 * 14);
const TREE_SEGMENT_STATEMENT_BYTES_V2: usize = (4 * 3) + (48 * 8);
const CHUNK_RECORD_BYTES_V2: usize = 4 + (48 * 8) + (32 * 3);
const CHUNK_RECORD_WITNESS_BYTES_V2: usize = CHUNK_RECORD_BYTES_V2 - 4;
const CHUNK_SLOT_BYTES_V2: usize = CHUNK_RECORD_WITNESS_BYTES_V2;
const TREE_CHILD_WITNESS_HEADER_BYTES_V2: usize = 8;
const TREE_MERGE_SUMMARY_BYTES_V2: usize = 4 + (48 * 8);
const EMPTY_LINEAR_OFFSETS_V2: [u32; 1] = [0];
static TREE_PROOF_CAP_REPORT_V2: OnceLock<TreeProofCapReportV2> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeProofCapReportV2 {
    pub max_supported_txs: usize,
    pub max_chunk_count: usize,
    pub max_tree_level: usize,
    pub p_chunk_a: usize,
    pub p_merge_a: usize,
    pub p_merge_b: usize,
    pub p_carry_a: usize,
    pub p_carry_b: usize,
    pub level_caps: Vec<usize>,
    pub root_proof_cap: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeWitnessGeometryReportV2 {
    pub chunk_slot_bytes: usize,
    pub full_chunk_witness_bytes: usize,
    pub merge_summary_bytes: usize,
    pub merge_child_header_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockPublicV2 {
    pub tx_count: u32,
    pub tx_statements_commitment: Digest48,
    pub statement_tree_digest_v2: Digest48,
    pub verified_leaf_tree_digest_v2: Digest48,
    pub verified_receipt_tree_digest_v2: Digest48,
    pub start_state_digest_rec_v2: Digest48,
    pub end_state_digest_rec_v2: Digest48,
    pub start_shielded_root: Digest48,
    pub end_shielded_root: Digest48,
    pub start_kernel_root: Digest48,
    pub end_kernel_root: Digest48,
    pub nullifier_root: Digest48,
    pub da_root: Digest48,
    pub start_tree_commitment: Digest48,
    pub end_tree_commitment: Digest48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveSegmentStatementV2 {
    pub start_index: u32,
    pub end_index: u32,
    pub segment_len: u32,
    pub tx_statements_commitment: Digest48,
    pub start_state_digest: Digest48,
    pub end_state_digest: Digest48,
    pub start_tree_commitment: Digest48,
    pub end_tree_commitment: Digest48,
    pub statement_tree_digest_v2: Digest48,
    pub verified_leaf_tree_digest_v2: Digest48,
    pub verified_receipt_tree_digest_v2: Digest48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRecTreeV2 {
    pub artifact_version_rec: u32,
    pub tx_line_digest_v2: Digest32,
    pub terminal_profile_tag_tau: u32,
    pub terminal_relation_kind_k: u32,
    pub proof_encoding_digest_rec: Digest32,
    pub proof_bytes_rec: u32,
    pub statement_digest_rec: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockInnerArtifactV2 {
    pub header: HeaderRecTreeV2,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockArtifactV2 {
    pub artifact: RecursiveBlockInnerArtifactV2,
    pub public: RecursiveBlockPublicV2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecursiveProverInputV2 {
    pub records: Vec<BlockLeafRecordV1>,
    pub semantic: BlockSemanticInputsV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TreeProofNodeV2 {
    level: usize,
    statement: RecursiveSegmentStatementV2,
    profile: SmallwoodRecursiveProfileTagV1,
    relation_kind: SmallwoodRecursiveRelationKindV1,
    proof_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeWitnessKindV2 {
    ChunkA = 1,
    MergeA = 2,
    MergeB = 3,
    CarryA = 4,
    CarryB = 5,
}

impl TreeWitnessKindV2 {
    fn from_relation_kind(
        relation_kind: SmallwoodRecursiveRelationKindV1,
    ) -> Result<Self, BlockRecursionError> {
        match relation_kind {
            SmallwoodRecursiveRelationKindV1::ChunkA => Ok(Self::ChunkA),
            SmallwoodRecursiveRelationKindV1::MergeA => Ok(Self::MergeA),
            SmallwoodRecursiveRelationKindV1::MergeB => Ok(Self::MergeB),
            SmallwoodRecursiveRelationKindV1::CarryA => Ok(Self::CarryA),
            SmallwoodRecursiveRelationKindV1::CarryB => Ok(Self::CarryB),
            _ => Err(BlockRecursionError::InvalidField("tree_v2 relation_kind")),
        }
    }

    fn relation_kind(self) -> SmallwoodRecursiveRelationKindV1 {
        match self {
            Self::ChunkA => SmallwoodRecursiveRelationKindV1::ChunkA,
            Self::MergeA => SmallwoodRecursiveRelationKindV1::MergeA,
            Self::MergeB => SmallwoodRecursiveRelationKindV1::MergeB,
            Self::CarryA => SmallwoodRecursiveRelationKindV1::CarryA,
            Self::CarryB => SmallwoodRecursiveRelationKindV1::CarryB,
        }
    }

    fn from_u32(value: u32) -> Result<Self, BlockRecursionError> {
        match value {
            1 => Ok(Self::ChunkA),
            2 => Ok(Self::MergeA),
            3 => Ok(Self::MergeB),
            4 => Ok(Self::CarryA),
            5 => Ok(Self::CarryB),
            _ => Err(BlockRecursionError::InvalidField("tree_v2 witness kind")),
        }
    }
}

#[derive(Debug)]
struct TreeRelationV2 {
    tree_level: usize,
    relation_kind: SmallwoodRecursiveRelationKindV1,
    target_statement: RecursiveSegmentStatementV2,
    auxiliary_witness_words: Vec<u64>,
    auxiliary_witness_limb_count: usize,
    cached_mismatch: OnceLock<Result<u64, BlockRecursionError>>,
}

struct ProjectionRelationV2 {
    auxiliary_witness_words: Vec<u64>,
}

impl TreeRelationV2 {
    fn new_chunk(
        target_statement: RecursiveSegmentStatementV2,
        records: &[BlockLeafRecordV1],
    ) -> Result<Self, BlockRecursionError> {
        if records.is_empty() || records.len() > TREE_RECURSIVE_CHUNK_SIZE_V2 {
            return Err(BlockRecursionError::InvalidLength {
                what: "tree_v2 chunk records",
                expected: TREE_RECURSIVE_CHUNK_SIZE_V2,
                actual: records.len(),
            });
        }
        let mut bytes = Vec::with_capacity(TREE_RECURSIVE_CHUNK_SIZE_V2 * CHUNK_SLOT_BYTES_V2);
        for record in records {
            bytes.extend_from_slice(&chunk_record_witness_bytes_v2(record));
        }
        for _ in records.len()..TREE_RECURSIVE_CHUNK_SIZE_V2 {
            bytes.extend_from_slice(&[0u8; CHUNK_SLOT_BYTES_V2]);
        }
        let auxiliary_witness_words = bytes_to_limbs_v2(&bytes);
        Ok(Self {
            tree_level: 0,
            relation_kind: SmallwoodRecursiveRelationKindV1::ChunkA,
            target_statement,
            auxiliary_witness_limb_count: auxiliary_witness_words.len(),
            auxiliary_witness_words,
            cached_mismatch: OnceLock::new(),
        })
    }

    fn new_merge(
        relation_kind: SmallwoodRecursiveRelationKindV1,
        target_statement: RecursiveSegmentStatementV2,
        left: &TreeProofNodeV2,
        right: &TreeProofNodeV2,
    ) -> Result<Self, BlockRecursionError> {
        if left.level != right.level {
            return Err(BlockRecursionError::ComposeCheckFailed(
                "tree_v2 merge children must have the same level",
            ));
        }
        let tree_level = left.level.saturating_add(1);
        let child_proof_cap = tree_recursive_child_proof_bytes_v2(tree_level);
        if left.proof_bytes.len() > child_proof_cap {
            return Err(BlockRecursionError::WidthMismatch {
                what: "tree_v2 live merge left child proof len",
                expected: child_proof_cap,
                actual: left.proof_bytes.len(),
            });
        }
        if right.proof_bytes.len() > child_proof_cap {
            return Err(BlockRecursionError::WidthMismatch {
                what: "tree_v2 live merge right child proof len",
                expected: child_proof_cap,
                actual: right.proof_bytes.len(),
            });
        }
        let left_kind = TreeWitnessKindV2::from_relation_kind(left.relation_kind)?;
        let right_kind = TreeWitnessKindV2::from_relation_kind(right.relation_kind)?;
        let merge_summary_bytes =
            merge_child_summary_bytes_v2(&target_statement, &left.statement, &right.statement)?;
        let mut bytes = Vec::with_capacity(
            (TREE_CHILD_WITNESS_HEADER_BYTES_V2 * 2)
                + merge_summary_bytes.len()
                + left.proof_bytes.len()
                + right.proof_bytes.len(),
        );
        put_u32_v2(&mut bytes, left_kind as u32);
        put_u32_v2(&mut bytes, left.proof_bytes.len() as u32);
        put_u32_v2(&mut bytes, right_kind as u32);
        put_u32_v2(&mut bytes, right.proof_bytes.len() as u32);
        bytes.extend_from_slice(&merge_summary_bytes);
        bytes.extend_from_slice(&left.proof_bytes);
        bytes.extend_from_slice(&right.proof_bytes);
        let auxiliary_witness_words = bytes_to_limbs_v2(&bytes);
        Ok(Self {
            tree_level,
            relation_kind,
            target_statement,
            auxiliary_witness_limb_count: auxiliary_witness_words.len(),
            auxiliary_witness_words,
            cached_mismatch: OnceLock::new(),
        })
    }

    fn new_merge_with_child_cap(
        relation_kind: SmallwoodRecursiveRelationKindV1,
        tree_level: usize,
        target_statement: RecursiveSegmentStatementV2,
        left: &TreeProofNodeV2,
        right: &TreeProofNodeV2,
        child_proof_cap: usize,
    ) -> Result<Self, BlockRecursionError> {
        let left_kind = TreeWitnessKindV2::from_relation_kind(left.relation_kind)?;
        let right_kind = TreeWitnessKindV2::from_relation_kind(right.relation_kind)?;
        let left_padded = pad_child_proof_bytes_with_cap_v2(&left.proof_bytes, child_proof_cap)?;
        let right_padded = pad_child_proof_bytes_with_cap_v2(&right.proof_bytes, child_proof_cap)?;
        let merge_summary_bytes =
            merge_child_summary_bytes_v2(&target_statement, &left.statement, &right.statement)?;
        let mut bytes = Vec::with_capacity(
            (TREE_CHILD_WITNESS_HEADER_BYTES_V2 * 2)
                + merge_summary_bytes.len()
                + (child_proof_cap * 2),
        );
        put_u32_v2(&mut bytes, left_kind as u32);
        put_u32_v2(&mut bytes, left.proof_bytes.len() as u32);
        put_u32_v2(&mut bytes, right_kind as u32);
        put_u32_v2(&mut bytes, right.proof_bytes.len() as u32);
        bytes.extend_from_slice(&merge_summary_bytes);
        bytes.extend_from_slice(&left_padded);
        bytes.extend_from_slice(&right_padded);
        let auxiliary_witness_words = bytes_to_limbs_v2(&bytes);
        Ok(Self {
            tree_level,
            relation_kind,
            target_statement,
            auxiliary_witness_limb_count: auxiliary_witness_words.len(),
            auxiliary_witness_words,
            cached_mismatch: OnceLock::new(),
        })
    }

    fn new_carry(
        relation_kind: SmallwoodRecursiveRelationKindV1,
        target_statement: RecursiveSegmentStatementV2,
        child: &TreeProofNodeV2,
    ) -> Result<Self, BlockRecursionError> {
        let tree_level = child.level.saturating_add(1);
        let child_proof_cap = tree_recursive_child_proof_bytes_v2(tree_level);
        if child.proof_bytes.len() > child_proof_cap {
            return Err(BlockRecursionError::WidthMismatch {
                what: "tree_v2 live carry child proof len",
                expected: child_proof_cap,
                actual: child.proof_bytes.len(),
            });
        }
        let child_kind = TreeWitnessKindV2::from_relation_kind(child.relation_kind)?;
        let mut bytes =
            Vec::with_capacity(TREE_CHILD_WITNESS_HEADER_BYTES_V2 + child.proof_bytes.len());
        put_u32_v2(&mut bytes, child_kind as u32);
        put_u32_v2(&mut bytes, child.proof_bytes.len() as u32);
        bytes.extend_from_slice(&child.proof_bytes);
        let auxiliary_witness_words = bytes_to_limbs_v2(&bytes);
        Ok(Self {
            tree_level,
            relation_kind,
            target_statement,
            auxiliary_witness_limb_count: auxiliary_witness_words.len(),
            auxiliary_witness_words,
            cached_mismatch: OnceLock::new(),
        })
    }

    fn new_carry_with_child_cap(
        relation_kind: SmallwoodRecursiveRelationKindV1,
        tree_level: usize,
        target_statement: RecursiveSegmentStatementV2,
        child: &TreeProofNodeV2,
        child_proof_cap: usize,
    ) -> Result<Self, BlockRecursionError> {
        let child_kind = TreeWitnessKindV2::from_relation_kind(child.relation_kind)?;
        let child_padded = pad_child_proof_bytes_with_cap_v2(&child.proof_bytes, child_proof_cap)?;
        let mut bytes = Vec::with_capacity(TREE_CHILD_WITNESS_HEADER_BYTES_V2 + child_proof_cap);
        put_u32_v2(&mut bytes, child_kind as u32);
        put_u32_v2(&mut bytes, child.proof_bytes.len() as u32);
        bytes.extend_from_slice(&child_padded);
        let auxiliary_witness_words = bytes_to_limbs_v2(&bytes);
        Ok(Self {
            tree_level,
            relation_kind,
            target_statement,
            auxiliary_witness_limb_count: auxiliary_witness_words.len(),
            auxiliary_witness_words,
            cached_mismatch: OnceLock::new(),
        })
    }

    fn from_witness_words_with_limb_count(
        tree_level: usize,
        relation_kind: SmallwoodRecursiveRelationKindV1,
        target_statement: RecursiveSegmentStatementV2,
        words: &[u64],
        limb_count: usize,
    ) -> Result<Self, BlockRecursionError> {
        if limb_count > words.len() {
            return Err(BlockRecursionError::InvalidLength {
                what: "tree_v2 auxiliary witness limbs",
                expected: words.len(),
                actual: limb_count,
            });
        }
        Ok(Self {
            tree_level,
            relation_kind,
            target_statement,
            auxiliary_witness_words: words[..limb_count].to_vec(),
            auxiliary_witness_limb_count: limb_count,
            cached_mismatch: OnceLock::new(),
        })
    }

    fn compute_mismatch_uncached(&self) -> Result<u64, BlockRecursionError> {
        match self.relation_kind {
            SmallwoodRecursiveRelationKindV1::ChunkA => {
                chunk_relation_mismatch_v2(&self.target_statement, &self.auxiliary_witness_words)
            }
            SmallwoodRecursiveRelationKindV1::MergeA | SmallwoodRecursiveRelationKindV1::MergeB => {
                merge_relation_mismatch_v2(
                    self.relation_kind,
                    self.tree_level,
                    &self.target_statement,
                    &self.auxiliary_witness_words,
                )
            }
            SmallwoodRecursiveRelationKindV1::CarryA | SmallwoodRecursiveRelationKindV1::CarryB => {
                carry_relation_mismatch_v2(
                    self.relation_kind,
                    self.tree_level,
                    &self.target_statement,
                    &self.auxiliary_witness_words,
                )
            }
            _ => Err(BlockRecursionError::InvalidField(
                "tree_v2 compute relation_kind",
            )),
        }
    }

    fn cached_mismatch(&self) -> Result<u64, BlockRecursionError> {
        self.cached_mismatch
            .get_or_init(|| self.compute_mismatch_uncached())
            .clone()
    }

    fn witness_values(&self) -> [u64; TREE_RECURSIVE_WITNESS_PACKING_FACTOR_V2] {
        [0u64; TREE_RECURSIVE_WITNESS_PACKING_FACTOR_V2]
    }
}

impl SmallwoodConstraintAdapter for TreeRelationV2 {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        TREE_RECURSIVE_WITNESS_ROW_COUNT_V2
    }

    fn packing_factor(&self) -> usize {
        TREE_RECURSIVE_WITNESS_PACKING_FACTOR_V2
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
        &EMPTY_LINEAR_OFFSETS_V2
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

    fn auxiliary_witness_words(&self) -> &[u64] {
        &self.auxiliary_witness_words
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(self.auxiliary_witness_limb_count)
    }

    fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
        SmallwoodLinearConstraintForm::Generic
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        rows: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows,
            auxiliary_words,
        }
    }

    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let SmallwoodNonlinearEvalView::RowScalars { .. } = view;
        let mismatch = self
            .cached_mismatch()
            .map_err(block_recursion_to_tx_error_v2)?;
        out[0] = mismatch.saturating_mul(mismatch);
        Ok(())
    }
}

impl SmallwoodConstraintAdapter for ProjectionRelationV2 {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        TREE_RECURSIVE_WITNESS_ROW_COUNT_V2
    }

    fn packing_factor(&self) -> usize {
        TREE_RECURSIVE_WITNESS_PACKING_FACTOR_V2
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
        &EMPTY_LINEAR_OFFSETS_V2
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

    fn auxiliary_witness_words(&self) -> &[u64] {
        &self.auxiliary_witness_words
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(self.auxiliary_witness_words.len())
    }

    fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
        SmallwoodLinearConstraintForm::Generic
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        rows: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows,
            auxiliary_words,
        }
    }

    fn compute_constraints_u64(
        &self,
        _view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        out[0] = 0;
        Ok(())
    }
}

fn block_recursion_to_tx_error_v2(err: BlockRecursionError) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolationOwned(err.to_string())
}

fn bytes_to_limbs_v2(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut limb = [0u8; 8];
            limb[..chunk.len()].copy_from_slice(chunk);
            u64::from_le_bytes(limb)
        })
        .collect()
}

fn limbs_to_exact_bytes_v2(
    words: &[u64],
    limb_count: usize,
) -> Result<Vec<u8>, BlockRecursionError> {
    if limb_count > words.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "tree_v2 witness limbs",
            expected: words.len(),
            actual: limb_count,
        });
    }
    let mut out = Vec::with_capacity(limb_count * 8);
    for word in &words[..limb_count] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    Ok(out)
}

fn put_u32_v2(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_fixed_v2<const N: usize>(out: &mut Vec<u8>, value: &[u8; N]) {
    out.extend_from_slice(value);
}

fn read_exact_fixed_v2<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], BlockRecursionError> {
    let end = cursor.saturating_add(N);
    let slice = bytes
        .get(*cursor..end)
        .ok_or(BlockRecursionError::InvalidLength {
            what: "tree_v2 fixed bytes",
            expected: N,
            actual: bytes.len().saturating_sub(*cursor),
        })?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    *cursor = end;
    Ok(out)
}

fn read_exact_u32_v2(bytes: &[u8], cursor: &mut usize) -> Result<u32, BlockRecursionError> {
    Ok(u32::from_le_bytes(read_exact_fixed_v2::<4>(bytes, cursor)?))
}

pub fn recursive_segment_statement_bytes_v2(statement: &RecursiveSegmentStatementV2) -> Vec<u8> {
    let mut out = Vec::with_capacity(TREE_SEGMENT_STATEMENT_BYTES_V2);
    put_u32_v2(&mut out, statement.start_index);
    put_u32_v2(&mut out, statement.end_index);
    put_u32_v2(&mut out, statement.segment_len);
    put_fixed_v2(&mut out, &statement.tx_statements_commitment);
    put_fixed_v2(&mut out, &statement.start_state_digest);
    put_fixed_v2(&mut out, &statement.end_state_digest);
    put_fixed_v2(&mut out, &statement.start_tree_commitment);
    put_fixed_v2(&mut out, &statement.end_tree_commitment);
    put_fixed_v2(&mut out, &statement.statement_tree_digest_v2);
    put_fixed_v2(&mut out, &statement.verified_leaf_tree_digest_v2);
    put_fixed_v2(&mut out, &statement.verified_receipt_tree_digest_v2);
    out
}

fn chunk_record_witness_bytes_v2(record: &BlockLeafRecordV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHUNK_RECORD_WITNESS_BYTES_V2);
    put_fixed_v2(&mut out, &record.receipt_statement_hash);
    put_fixed_v2(&mut out, &record.receipt_proof_digest);
    put_fixed_v2(&mut out, &record.receipt_public_inputs_digest);
    put_fixed_v2(&mut out, &record.receipt_verifier_profile);
    put_fixed_v2(&mut out, &record.leaf_params_fingerprint);
    put_fixed_v2(&mut out, &record.leaf_spec_digest);
    put_fixed_v2(&mut out, &record.leaf_relation_id);
    put_fixed_v2(&mut out, &record.leaf_shape_digest);
    put_fixed_v2(&mut out, &record.leaf_statement_digest);
    put_fixed_v2(&mut out, &record.leaf_commitment_digest);
    put_fixed_v2(&mut out, &record.leaf_proof_digest);
    out
}

fn merge_child_summary_bytes_v2(
    target_statement: &RecursiveSegmentStatementV2,
    left: &RecursiveSegmentStatementV2,
    right: &RecursiveSegmentStatementV2,
) -> Result<Vec<u8>, BlockRecursionError> {
    let expected = compose_recursive_segment_statements_v2(left, right)?;
    if &expected != target_statement {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "tree_v2 merge child summary requires adjacent child statements matching target",
        ));
    }
    let mut out = Vec::with_capacity(TREE_MERGE_SUMMARY_BYTES_V2);
    put_u32_v2(&mut out, left.segment_len);
    put_fixed_v2(&mut out, &left.end_state_digest);
    put_fixed_v2(&mut out, &left.end_tree_commitment);
    put_fixed_v2(&mut out, &left.statement_tree_digest_v2);
    put_fixed_v2(&mut out, &left.verified_leaf_tree_digest_v2);
    put_fixed_v2(&mut out, &left.verified_receipt_tree_digest_v2);
    put_fixed_v2(&mut out, &right.statement_tree_digest_v2);
    put_fixed_v2(&mut out, &right.verified_leaf_tree_digest_v2);
    put_fixed_v2(&mut out, &right.verified_receipt_tree_digest_v2);
    Ok(out)
}

pub fn recursive_segment_statement_digest32_v2(
    statement: &RecursiveSegmentStatementV2,
) -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.segment-statement.v2",
        &[&recursive_segment_statement_bytes_v2(statement)],
    )
}

pub fn recursive_segment_start_state_digest_v2(
    tx_statements_commitment: Digest48,
    start_tree_commitment: Digest48,
) -> Digest48 {
    fold_digest48(
        b"hegemon.block-recursion.segment-start-state.v2",
        &[&tx_statements_commitment, &start_tree_commitment],
    )
}

pub fn recursive_segment_end_state_digest_v2(
    end_index: u32,
    start_state_digest: Digest48,
    statement_tree_digest_v2: Digest48,
    verified_leaf_tree_digest_v2: Digest48,
    verified_receipt_tree_digest_v2: Digest48,
    start_tree_commitment: Digest48,
    end_tree_commitment: Digest48,
) -> Digest48 {
    fold_digest48(
        b"hegemon.block-recursion.segment-end-state.v2",
        &[
            &end_index.to_le_bytes(),
            &start_state_digest,
            &statement_tree_digest_v2,
            &verified_leaf_tree_digest_v2,
            &verified_receipt_tree_digest_v2,
            &start_tree_commitment,
            &end_tree_commitment,
        ],
    )
}

fn statement_digest_from_records_v2(records: &[BlockLeafRecordV1]) -> Digest48 {
    let chunks = records
        .iter()
        .map(|record| record.receipt_statement_hash.as_slice())
        .collect::<Vec<_>>();
    fold_digest48(
        b"hegemon.block-recursion.segment-statement-tree-leaf.v2",
        &chunks,
    )
}

fn leaf_digest_from_records_v2(records: &[BlockLeafRecordV1]) -> Digest48 {
    let chunks = records
        .iter()
        .map(canonical_verified_leaf_record_bytes_v1)
        .collect::<Vec<_>>();
    let refs = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    fold_digest48(b"hegemon.block-recursion.segment-leaf-tree-leaf.v2", &refs)
}

fn receipt_digest_from_records_v2(records: &[BlockLeafRecordV1]) -> Digest48 {
    let chunks = records
        .iter()
        .map(canonical_receipt_record_bytes_v1)
        .collect::<Vec<_>>();
    let refs = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    fold_digest48(
        b"hegemon.block-recursion.segment-receipt-tree-leaf.v2",
        &refs,
    )
}

fn combine_tree_digest_v2(
    domain: &[u8],
    left_len: u32,
    left: Digest48,
    right_len: u32,
    right: Digest48,
) -> Digest48 {
    fold_digest48(
        domain,
        &[
            &left_len.to_le_bytes(),
            &left,
            &right_len.to_le_bytes(),
            &right,
        ],
    )
}

fn reduce_nodes_v2(nodes: &[(u32, Digest48)], domain: &[u8]) -> Digest48 {
    if nodes.is_empty() {
        return fold_digest48(domain, &[]);
    }
    let mut current = nodes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut idx = 0usize;
        while idx < current.len() {
            if idx + 1 == current.len() {
                next.push(current[idx]);
                idx += 1;
                continue;
            }
            let (left_len, left_digest) = current[idx];
            let (right_len, right_digest) = current[idx + 1];
            next.push((
                left_len + right_len,
                combine_tree_digest_v2(domain, left_len, left_digest, right_len, right_digest),
            ));
            idx += 2;
        }
        current = next;
    }
    current[0].1
}

pub fn public_replay_v2(
    records: &[BlockLeafRecordV1],
    semantic: &BlockSemanticInputsV1,
) -> Result<RecursiveBlockPublicV2, BlockRecursionError> {
    let start_prefix = prefix_statement_for_records_v1(&[], semantic, false)?;
    let end_prefix = prefix_statement_for_records_v1(records, semantic, true)?;
    let chunk_nodes = records
        .chunks(TREE_RECURSIVE_CHUNK_SIZE_V2)
        .map(|chunk| {
            (
                chunk.len() as u32,
                statement_digest_from_records_v2(chunk),
                leaf_digest_from_records_v2(chunk),
                receipt_digest_from_records_v2(chunk),
            )
        })
        .collect::<Vec<_>>();
    let statement_nodes = chunk_nodes
        .iter()
        .map(|(len, digest, _, _)| (*len, *digest))
        .collect::<Vec<_>>();
    let leaf_nodes = chunk_nodes
        .iter()
        .map(|(len, _, digest, _)| (*len, *digest))
        .collect::<Vec<_>>();
    let receipt_nodes = chunk_nodes
        .iter()
        .map(|(len, _, _, digest)| (*len, *digest))
        .collect::<Vec<_>>();
    Ok(RecursiveBlockPublicV2 {
        tx_count: records.len() as u32,
        tx_statements_commitment: semantic.tx_statements_commitment,
        statement_tree_digest_v2: reduce_nodes_v2(
            &statement_nodes,
            b"hegemon.block-recursion.segment-statement-tree-node.v2",
        ),
        verified_leaf_tree_digest_v2: reduce_nodes_v2(
            &leaf_nodes,
            b"hegemon.block-recursion.segment-leaf-tree-node.v2",
        ),
        verified_receipt_tree_digest_v2: reduce_nodes_v2(
            &receipt_nodes,
            b"hegemon.block-recursion.segment-receipt-tree-node.v2",
        ),
        start_state_digest_rec_v2: start_prefix.end_state_digest,
        end_state_digest_rec_v2: end_prefix.end_state_digest,
        start_shielded_root: semantic.start_shielded_root,
        end_shielded_root: semantic.end_shielded_root,
        start_kernel_root: semantic.start_kernel_root,
        end_kernel_root: semantic.end_kernel_root,
        nullifier_root: semantic.nullifier_root,
        da_root: semantic.da_root,
        start_tree_commitment: semantic.start_tree_commitment,
        end_tree_commitment: semantic.end_tree_commitment,
    })
}

pub fn recursive_segment_statement_from_public_v2(
    public: &RecursiveBlockPublicV2,
) -> RecursiveSegmentStatementV2 {
    RecursiveSegmentStatementV2 {
        start_index: 0,
        end_index: public.tx_count,
        segment_len: public.tx_count,
        tx_statements_commitment: public.tx_statements_commitment,
        start_state_digest: public.start_state_digest_rec_v2,
        end_state_digest: public.end_state_digest_rec_v2,
        start_tree_commitment: public.start_tree_commitment,
        end_tree_commitment: public.end_tree_commitment,
        statement_tree_digest_v2: public.statement_tree_digest_v2,
        verified_leaf_tree_digest_v2: public.verified_leaf_tree_digest_v2,
        verified_receipt_tree_digest_v2: public.verified_receipt_tree_digest_v2,
    }
}

fn recursive_segment_statement_for_interval_v2(
    records: &[BlockLeafRecordV1],
    semantic: &BlockSemanticInputsV1,
    start: usize,
    end: usize,
) -> Result<RecursiveSegmentStatementV2, BlockRecursionError> {
    if start > end || end > records.len() {
        return Err(BlockRecursionError::InvalidField("tree_v2 interval bounds"));
    }
    let start_prefix = prefix_statement_for_records_v1(&records[..start], semantic, false)?;
    let end_prefix =
        prefix_statement_for_records_v1(&records[..end], semantic, end == records.len())?;
    recursive_segment_statement_from_interval_parts_v2(
        &start_prefix,
        &end_prefix,
        &records[start..end],
    )
}

fn recursive_segment_statement_from_interval_parts_v2(
    start_prefix: &RecursivePrefixStatementV1,
    end_prefix: &RecursivePrefixStatementV1,
    records: &[BlockLeafRecordV1],
) -> Result<RecursiveSegmentStatementV2, BlockRecursionError> {
    let segment_len = records.len() as u32;
    let statement_tree_digest_v2 = statement_digest_from_records_v2(records);
    let verified_leaf_tree_digest_v2 = leaf_digest_from_records_v2(records);
    let verified_receipt_tree_digest_v2 = receipt_digest_from_records_v2(records);
    Ok(RecursiveSegmentStatementV2 {
        start_index: start_prefix.tx_count,
        end_index: end_prefix.tx_count,
        segment_len,
        tx_statements_commitment: end_prefix.tx_statements_commitment,
        start_state_digest: start_prefix.end_state_digest,
        end_state_digest: end_prefix.end_state_digest,
        start_tree_commitment: start_prefix.end_tree_commitment,
        end_tree_commitment: end_prefix.end_tree_commitment,
        statement_tree_digest_v2,
        verified_leaf_tree_digest_v2,
        verified_receipt_tree_digest_v2,
    })
}

pub fn compose_recursive_segment_statements_v2(
    left: &RecursiveSegmentStatementV2,
    right: &RecursiveSegmentStatementV2,
) -> Result<RecursiveSegmentStatementV2, BlockRecursionError> {
    if left.end_index != right.start_index {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "tree_v2 segments must be adjacent",
        ));
    }
    if left.end_state_digest != right.start_state_digest {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "tree_v2 segment state join mismatch",
        ));
    }
    if left.end_tree_commitment != right.start_tree_commitment {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "tree_v2 segment tree join mismatch",
        ));
    }
    if left.tx_statements_commitment != right.tx_statements_commitment {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "tree_v2 segment tx_statements_commitment mismatch",
        ));
    }
    let segment_len = left.segment_len + right.segment_len;
    let statement_tree_digest_v2 = combine_tree_digest_v2(
        b"hegemon.block-recursion.segment-statement-tree-node.v2",
        left.segment_len,
        left.statement_tree_digest_v2,
        right.segment_len,
        right.statement_tree_digest_v2,
    );
    let verified_leaf_tree_digest_v2 = combine_tree_digest_v2(
        b"hegemon.block-recursion.segment-leaf-tree-node.v2",
        left.segment_len,
        left.verified_leaf_tree_digest_v2,
        right.segment_len,
        right.verified_leaf_tree_digest_v2,
    );
    let verified_receipt_tree_digest_v2 = combine_tree_digest_v2(
        b"hegemon.block-recursion.segment-receipt-tree-node.v2",
        left.segment_len,
        left.verified_receipt_tree_digest_v2,
        right.segment_len,
        right.verified_receipt_tree_digest_v2,
    );
    Ok(RecursiveSegmentStatementV2 {
        start_index: left.start_index,
        end_index: right.end_index,
        segment_len,
        tx_statements_commitment: left.tx_statements_commitment,
        start_state_digest: left.start_state_digest,
        end_state_digest: right.end_state_digest,
        start_tree_commitment: left.start_tree_commitment,
        end_tree_commitment: right.end_tree_commitment,
        statement_tree_digest_v2,
        verified_leaf_tree_digest_v2,
        verified_receipt_tree_digest_v2,
    })
}

fn decode_leaf_record_from_bytes_v2(
    bytes: &[u8],
    tx_index: u32,
) -> Result<BlockLeafRecordV1, BlockRecursionError> {
    let mut cursor = 0usize;
    let record = BlockLeafRecordV1 {
        tx_index,
        receipt_statement_hash: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        receipt_proof_digest: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        receipt_public_inputs_digest: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        receipt_verifier_profile: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        leaf_params_fingerprint: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        leaf_spec_digest: read_exact_fixed_v2::<32>(bytes, &mut cursor)?,
        leaf_relation_id: read_exact_fixed_v2::<32>(bytes, &mut cursor)?,
        leaf_shape_digest: read_exact_fixed_v2::<32>(bytes, &mut cursor)?,
        leaf_statement_digest: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        leaf_commitment_digest: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        leaf_proof_digest: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
    };
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(record)
}

fn decode_chunk_witness_v2(
    auxiliary_words: &[u64],
    start_index: u32,
    active_len: usize,
) -> Result<Vec<BlockLeafRecordV1>, BlockRecursionError> {
    let bytes = limbs_to_exact_bytes_v2(auxiliary_words, auxiliary_words.len())?;
    if active_len == 0 || active_len > TREE_RECURSIVE_CHUNK_SIZE_V2 {
        return Err(BlockRecursionError::InvalidField(
            "tree_v2 chunk active_len",
        ));
    }
    let mut cursor = 0usize;
    let mut records = Vec::with_capacity(active_len);
    for idx in 0..TREE_RECURSIVE_CHUNK_SIZE_V2 {
        let slot = bytes.get(cursor..cursor + CHUNK_SLOT_BYTES_V2).ok_or(
            BlockRecursionError::InvalidLength {
                what: "tree_v2 chunk slot",
                expected: CHUNK_SLOT_BYTES_V2,
                actual: bytes.len().saturating_sub(cursor),
            },
        )?;
        cursor += CHUNK_SLOT_BYTES_V2;
        if idx < active_len {
            records.push(decode_leaf_record_from_bytes_v2(
                slot,
                start_index + idx as u32,
            )?);
        } else if slot.iter().any(|byte| *byte != 0) {
            return Err(BlockRecursionError::InvalidField(
                "tree_v2 inactive chunk slot must be zero",
            ));
        }
    }
    if cursor != bytes.len() {
        let remaining = &bytes[cursor..];
        if remaining.iter().any(|byte| *byte != 0) {
            return Err(BlockRecursionError::TrailingBytes {
                remaining: bytes.len() - cursor,
            });
        }
    }
    Ok(records)
}

fn pad_child_proof_bytes_with_cap_v2(
    proof_bytes: &[u8],
    child_proof_cap: usize,
) -> Result<Vec<u8>, BlockRecursionError> {
    if proof_bytes.len() > child_proof_cap {
        return Err(BlockRecursionError::WidthMismatch {
            what: "tree_v2 child proof bytes",
            expected: child_proof_cap,
            actual: proof_bytes.len(),
        });
    }
    let mut out = Vec::with_capacity(child_proof_cap);
    out.extend_from_slice(proof_bytes);
    out.resize(child_proof_cap, 0u8);
    Ok(out)
}

fn decode_merge_child_v2(
    bytes: &[u8],
    cursor: &mut usize,
    proof_len: usize,
) -> Result<
    Vec<u8>,
    BlockRecursionError,
> {
    let proof_slice =
        bytes
            .get(*cursor..*cursor + proof_len)
            .ok_or(BlockRecursionError::InvalidLength {
                what: "tree_v2 child proof bytes",
                expected: proof_len,
                actual: bytes.len().saturating_sub(*cursor),
            })?;
    *cursor += proof_len;
    Ok(proof_slice.to_vec())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MergeChildSummaryV2 {
    left_segment_len: u32,
    left_end_state_digest: Digest48,
    left_end_tree_commitment: Digest48,
    left_statement_tree_digest_v2: Digest48,
    left_verified_leaf_tree_digest_v2: Digest48,
    left_verified_receipt_tree_digest_v2: Digest48,
    right_statement_tree_digest_v2: Digest48,
    right_verified_leaf_tree_digest_v2: Digest48,
    right_verified_receipt_tree_digest_v2: Digest48,
}

fn decode_merge_child_summary_v2(bytes: &[u8]) -> Result<MergeChildSummaryV2, BlockRecursionError> {
    let mut cursor = 0usize;
    let summary = MergeChildSummaryV2 {
        left_segment_len: read_exact_u32_v2(bytes, &mut cursor)?,
        left_end_state_digest: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        left_end_tree_commitment: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        left_statement_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        left_verified_leaf_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        left_verified_receipt_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        right_statement_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        right_verified_leaf_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
        right_verified_receipt_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, &mut cursor)?,
    };
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(summary)
}

fn reconstruct_merge_child_statements_v2(
    target_statement: &RecursiveSegmentStatementV2,
    summary: &MergeChildSummaryV2,
) -> Result<(RecursiveSegmentStatementV2, RecursiveSegmentStatementV2), BlockRecursionError> {
    if summary.left_segment_len == 0 || summary.left_segment_len >= target_statement.segment_len {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "tree_v2 left child segment_len must split the target segment",
        ));
    }
    let left_end_index = target_statement
        .start_index
        .checked_add(summary.left_segment_len)
        .ok_or(BlockRecursionError::InvalidField("tree_v2 left end_index overflow"))?;
    let right_segment_len = target_statement
        .segment_len
        .checked_sub(summary.left_segment_len)
        .ok_or(BlockRecursionError::InvalidField("tree_v2 right segment_len underflow"))?;
    let left = RecursiveSegmentStatementV2 {
        start_index: target_statement.start_index,
        end_index: left_end_index,
        segment_len: summary.left_segment_len,
        tx_statements_commitment: target_statement.tx_statements_commitment,
        start_state_digest: target_statement.start_state_digest,
        end_state_digest: summary.left_end_state_digest,
        start_tree_commitment: target_statement.start_tree_commitment,
        end_tree_commitment: summary.left_end_tree_commitment,
        statement_tree_digest_v2: summary.left_statement_tree_digest_v2,
        verified_leaf_tree_digest_v2: summary.left_verified_leaf_tree_digest_v2,
        verified_receipt_tree_digest_v2: summary.left_verified_receipt_tree_digest_v2,
    };
    let right = RecursiveSegmentStatementV2 {
        start_index: left_end_index,
        end_index: target_statement.end_index,
        segment_len: right_segment_len,
        tx_statements_commitment: target_statement.tx_statements_commitment,
        start_state_digest: summary.left_end_state_digest,
        end_state_digest: target_statement.end_state_digest,
        start_tree_commitment: summary.left_end_tree_commitment,
        end_tree_commitment: target_statement.end_tree_commitment,
        statement_tree_digest_v2: summary.right_statement_tree_digest_v2,
        verified_leaf_tree_digest_v2: summary.right_verified_leaf_tree_digest_v2,
        verified_receipt_tree_digest_v2: summary.right_verified_receipt_tree_digest_v2,
    };
    Ok((left, right))
}

fn chunk_relation_mismatch_v2(
    target_statement: &RecursiveSegmentStatementV2,
    auxiliary_words: &[u64],
) -> Result<u64, BlockRecursionError> {
    let active_len = target_statement.segment_len as usize;
    let records = decode_chunk_witness_v2(auxiliary_words, target_statement.start_index, active_len)?;
    let active_len = active_len as u32;
    let mut mismatch = 0u64;
    if active_len != target_statement.segment_len {
        mismatch += 1;
    }
    if target_statement.start_index.saturating_add(active_len) != target_statement.end_index {
        mismatch += 1;
    }
    if statement_digest_from_records_v2(&records) != target_statement.statement_tree_digest_v2 {
        mismatch += 1;
    }
    if leaf_digest_from_records_v2(&records) != target_statement.verified_leaf_tree_digest_v2 {
        mismatch += 1;
    }
    if receipt_digest_from_records_v2(&records) != target_statement.verified_receipt_tree_digest_v2
    {
        mismatch += 1;
    }
    for (offset, record) in records.iter().enumerate() {
        if record.tx_index != target_statement.start_index + offset as u32 {
            mismatch += 1;
        }
    }
    Ok(mismatch)
}

fn tree_binding_bytes_v2(statement: &RecursiveSegmentStatementV2) -> Vec<u8> {
    recursive_segment_statement_bytes_v2(statement)
}

fn tree_recursive_profile_v2(
    profile: SmallwoodRecursiveProfileTagV1,
) -> transaction_circuit::RecursiveSmallwoodProfileV1 {
    match profile {
        SmallwoodRecursiveProfileTagV1::A => {
            recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING)
        }
        SmallwoodRecursiveProfileTagV1::B => {
            recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING)
        }
    }
}

fn tree_recursive_descriptor_v2(
    profile: SmallwoodRecursiveProfileTagV1,
    relation_kind: SmallwoodRecursiveRelationKindV1,
    tree_level: usize,
) -> SmallwoodRecursiveVerifierDescriptorV1 {
    let profile_cfg = tree_recursive_profile_v2(profile);
    let child_proof_cap = if tree_level == 0 {
        0u32
    } else {
        tree_recursive_child_proof_bytes_v2(tree_level) as u32
    };
    let tag = match relation_kind {
        SmallwoodRecursiveRelationKindV1::ChunkA => b"chunk-a".as_slice(),
        SmallwoodRecursiveRelationKindV1::MergeA => b"merge-a".as_slice(),
        SmallwoodRecursiveRelationKindV1::MergeB => b"merge-b".as_slice(),
        SmallwoodRecursiveRelationKindV1::CarryA => b"carry-a".as_slice(),
        SmallwoodRecursiveRelationKindV1::CarryB => b"carry-b".as_slice(),
        _ => b"invalid".as_slice(),
    };
    let relation_id = fold_digest32(
        b"hegemon.block-recursion.tree-v2.relation-id",
        &[tag, &(tree_level as u32).to_le_bytes()],
    );
    let shape_digest = fold_digest32(
        b"hegemon.block-recursion.tree-v2.shape",
        &[
            tag,
            &(tree_level as u32).to_le_bytes(),
            &(TREE_RECURSIVE_CHUNK_SIZE_V2 as u32).to_le_bytes(),
            &child_proof_cap.to_le_bytes(),
        ],
    );
    let vk_digest = fold_digest32(b"hegemon.block-recursion.tree-v2.vk", &[tag, &shape_digest]);
    recursive_descriptor_v1(
        &profile_cfg,
        relation_kind,
        relation_id,
        shape_digest,
        vk_digest,
    )
}

fn rebuild_tree_relation_from_proof_v2(
    profile: SmallwoodRecursiveProfileTagV1,
    relation_kind: SmallwoodRecursiveRelationKindV1,
    tree_level: usize,
    statement: RecursiveSegmentStatementV2,
    proof_bytes: &[u8],
) -> Result<TreeRelationV2, BlockRecursionError> {
    let _ = profile;
    let proof_trace = decode_smallwood_proof_trace_v1(proof_bytes)
        .map_err(|_| BlockRecursionError::InvalidField("tree_v2 proof trace decode"))?;
    TreeRelationV2::from_witness_words_with_limb_count(
        tree_level,
        relation_kind,
        statement,
        &proof_trace.auxiliary_witness_words,
        proof_trace.auxiliary_witness_limb_count,
    )
}

fn decode_canonical_tree_proof_prefix_v2(
    padded_proof_bytes: &[u8],
) -> Result<(Vec<u8>, usize), BlockRecursionError> {
    let (proof_trace, consumed_len) = decode_smallwood_proof_trace_prefix_v1(padded_proof_bytes)
        .map_err(|_| BlockRecursionError::InvalidField("tree_v2 proof trace decode"))?;
    let canonical_proof_bytes = encode_smallwood_proof_trace_v1(&proof_trace)
        .map_err(|_| BlockRecursionError::InvalidField("tree_v2 proof trace encode"))?;
    if canonical_proof_bytes.len() != consumed_len
        || padded_proof_bytes[..consumed_len] != canonical_proof_bytes
    {
        return Err(BlockRecursionError::InvalidField(
            "tree_v2 proof canonical encoding",
        ));
    }
    if padded_proof_bytes[consumed_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(BlockRecursionError::InvalidField("tree_v2 proof padding"));
    }
    Ok((canonical_proof_bytes, consumed_len))
}

fn verify_tree_child_v2(
    profile: SmallwoodRecursiveProfileTagV1,
    relation_kind: SmallwoodRecursiveRelationKindV1,
    tree_level: usize,
    statement: &RecursiveSegmentStatementV2,
    proof_bytes: &[u8],
) -> Result<(), BlockRecursionError> {
    let relation = rebuild_tree_relation_from_proof_v2(
        profile,
        relation_kind,
        tree_level,
        statement.clone(),
        proof_bytes,
    )?;
    let profile_cfg = tree_recursive_profile_v2(profile);
    let descriptor = tree_recursive_descriptor_v2(profile, relation_kind, tree_level);
    verify_recursive_statement_direct_v1(
        &profile_cfg,
        &descriptor,
        &relation,
        &tree_binding_bytes_v2(statement),
        proof_bytes,
    )
    .map_err(|err| {
        BlockRecursionError::InvalidField(Box::leak(
            format!("tree_v2 child verify: {err}").into_boxed_str(),
        ))
    })
}

fn merge_relation_mismatch_v2(
    relation_kind: SmallwoodRecursiveRelationKindV1,
    tree_level: usize,
    target_statement: &RecursiveSegmentStatementV2,
    auxiliary_words: &[u64],
) -> Result<u64, BlockRecursionError> {
    if tree_level == 0 {
        return Err(BlockRecursionError::InvalidField(
            "tree_v2 merge level must be nonzero",
        ));
    }
    let bytes = limbs_to_exact_bytes_v2(auxiliary_words, auxiliary_words.len())?;
    let mut cursor = 0usize;
    let child_level = tree_level - 1;
    let child_proof_cap = tree_recursive_child_proof_bytes_v2(tree_level);
    let left_kind = TreeWitnessKindV2::from_u32(read_exact_u32_v2(&bytes, &mut cursor)?)?.relation_kind();
    let left_proof_len = read_exact_u32_v2(&bytes, &mut cursor)? as usize;
    if left_proof_len > child_proof_cap {
        return Err(BlockRecursionError::WidthMismatch {
            what: "tree_v2 left child proof len",
            expected: child_proof_cap,
            actual: left_proof_len,
        });
    }
    let right_kind = TreeWitnessKindV2::from_u32(read_exact_u32_v2(&bytes, &mut cursor)?)?.relation_kind();
    let right_proof_len = read_exact_u32_v2(&bytes, &mut cursor)? as usize;
    if right_proof_len > child_proof_cap {
        return Err(BlockRecursionError::WidthMismatch {
            what: "tree_v2 right child proof len",
            expected: child_proof_cap,
            actual: right_proof_len,
        });
    }
    let summary = decode_merge_child_summary_v2(
        bytes
            .get(*&cursor..cursor + TREE_MERGE_SUMMARY_BYTES_V2)
            .ok_or(BlockRecursionError::InvalidLength {
                what: "tree_v2 merge child summary bytes",
                expected: TREE_MERGE_SUMMARY_BYTES_V2,
                actual: bytes.len().saturating_sub(cursor),
            })?,
    )?;
    cursor += TREE_MERGE_SUMMARY_BYTES_V2;
    let (left_statement, right_statement) =
        reconstruct_merge_child_statements_v2(target_statement, &summary)?;
    let left_proof = decode_merge_child_v2(&bytes, &mut cursor, left_proof_len)?;
    let right_proof = decode_merge_child_v2(&bytes, &mut cursor, right_proof_len)?;
    if cursor != bytes.len() && bytes[cursor..].iter().any(|byte| *byte != 0) {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    let mut mismatch = 0u64;
    let expected_child_profile = expected_child_profile_for_parent_kind_v2(relation_kind)?;
    let left_profile = profile_for_relation_kind_v2(left_kind)?;
    let right_profile = profile_for_relation_kind_v2(right_kind)?;
    if left_profile != expected_child_profile {
        mismatch += 1;
    }
    if right_profile != expected_child_profile {
        mismatch += 1;
    }
    let composed = compose_recursive_segment_statements_v2(&left_statement, &right_statement)?;
    if &composed != target_statement {
        mismatch += 1;
    }
    if verify_tree_child_v2(
        left_profile,
        left_kind,
        child_level,
        &left_statement,
        &left_proof,
    )
    .is_err()
    {
        mismatch += 1;
    }
    if verify_tree_child_v2(
        right_profile,
        right_kind,
        child_level,
        &right_statement,
        &right_proof,
    )
    .is_err()
    {
        mismatch += 1;
    }
    Ok(mismatch)
}

fn carry_relation_mismatch_v2(
    relation_kind: SmallwoodRecursiveRelationKindV1,
    tree_level: usize,
    target_statement: &RecursiveSegmentStatementV2,
    auxiliary_words: &[u64],
) -> Result<u64, BlockRecursionError> {
    if tree_level == 0 {
        return Err(BlockRecursionError::InvalidField(
            "tree_v2 carry level must be nonzero",
        ));
    }
    let bytes = limbs_to_exact_bytes_v2(auxiliary_words, auxiliary_words.len())?;
    let child_proof_cap = tree_recursive_child_proof_bytes_v2(tree_level);
    let child_level = tree_level - 1;
    let mut cursor = 0usize;
    let child_kind =
        TreeWitnessKindV2::from_u32(read_exact_u32_v2(&bytes, &mut cursor)?)?.relation_kind();
    let proof_len = read_exact_u32_v2(&bytes, &mut cursor)? as usize;
    let proof_slice =
        bytes
            .get(cursor..cursor + proof_len)
            .ok_or(BlockRecursionError::InvalidLength {
                what: "tree_v2 carry child proof bytes",
                expected: proof_len,
                actual: bytes.len().saturating_sub(cursor),
            })?;
    if proof_len > child_proof_cap {
        return Err(BlockRecursionError::WidthMismatch {
            what: "tree_v2 carry child proof len",
            expected: child_proof_cap,
            actual: proof_len,
        });
    }
    cursor += proof_len;
    let mut mismatch = 0u64;
    let expected_child_profile = expected_child_profile_for_parent_kind_v2(relation_kind)?;
    let profile = profile_for_relation_kind_v2(child_kind)?;
    if expected_child_profile != profile {
        mismatch += 1;
    }
    if verify_tree_child_v2(
        profile,
        child_kind,
        child_level,
        target_statement,
        proof_slice,
    )
    .is_err()
    {
        mismatch += 1;
    }
    if cursor != bytes.len() && bytes[cursor..].iter().any(|byte| *byte != 0) {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(mismatch)
}

fn tree_profile_for_level_v2(level: usize) -> SmallwoodRecursiveProfileTagV1 {
    if level.is_multiple_of(2) {
        SmallwoodRecursiveProfileTagV1::A
    } else {
        SmallwoodRecursiveProfileTagV1::B
    }
}

fn tree_carry_kind_for_level_v2(level: usize) -> SmallwoodRecursiveRelationKindV1 {
    if level.is_multiple_of(2) {
        SmallwoodRecursiveRelationKindV1::CarryA
    } else {
        SmallwoodRecursiveRelationKindV1::CarryB
    }
}

fn tree_merge_kind_for_level_v2(level: usize) -> SmallwoodRecursiveRelationKindV1 {
    if level.is_multiple_of(2) {
        SmallwoodRecursiveRelationKindV1::MergeA
    } else {
        SmallwoodRecursiveRelationKindV1::MergeB
    }
}

fn ensure_supported_tree_tx_count_v2(tx_count: u32) -> Result<(), BlockRecursionError> {
    let actual = tx_count as usize;
    if actual == 0 || actual > TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 {
        return Err(BlockRecursionError::InvalidLength {
            what: "recursive_block_v2 tx_count",
            expected: TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2,
            actual,
        });
    }
    Ok(())
}

fn tree_chunk_count_for_tx_count_v2(tx_count: u32) -> Result<usize, BlockRecursionError> {
    ensure_supported_tree_tx_count_v2(tx_count)?;
    Ok((tx_count as usize).div_ceil(TREE_RECURSIVE_CHUNK_SIZE_V2))
}

fn tree_root_level_for_chunk_count_v2(mut chunk_count: usize) -> usize {
    let mut level = 0usize;
    while chunk_count > 1 {
        level += 1;
        chunk_count = chunk_count.div_ceil(2);
    }
    level
}

fn tree_root_level_for_tx_count_v2(tx_count: u32) -> Result<usize, BlockRecursionError> {
    Ok(tree_root_level_for_chunk_count_v2(
        tree_chunk_count_for_tx_count_v2(tx_count)?,
    ))
}

fn prove_tree_relation_v2(
    profile: SmallwoodRecursiveProfileTagV1,
    relation: &TreeRelationV2,
) -> Result<Vec<u8>, BlockRecursionError> {
    let profile_cfg = tree_recursive_profile_v2(profile);
    let descriptor =
        tree_recursive_descriptor_v2(profile, relation.relation_kind, relation.tree_level);
    prove_recursive_statement_v1(
        &profile_cfg,
        &descriptor,
        relation,
        &relation.witness_values(),
        &tree_binding_bytes_v2(&relation.target_statement),
    )
    .map_err(|err| {
        BlockRecursionError::InvalidField(Box::leak(
            format!("tree_v2 prove: {err}").into_boxed_str(),
        ))
    })
}

fn expected_child_profile_for_parent_kind_v2(
    relation_kind: SmallwoodRecursiveRelationKindV1,
) -> Result<SmallwoodRecursiveProfileTagV1, BlockRecursionError> {
    match relation_kind {
        SmallwoodRecursiveRelationKindV1::MergeA | SmallwoodRecursiveRelationKindV1::CarryA => {
            Ok(SmallwoodRecursiveProfileTagV1::B)
        }
        SmallwoodRecursiveRelationKindV1::MergeB | SmallwoodRecursiveRelationKindV1::CarryB => {
            Ok(SmallwoodRecursiveProfileTagV1::A)
        }
        _ => Err(BlockRecursionError::InvalidField(
            "tree_v2 parent relation kind",
        )),
    }
}

fn profile_for_relation_kind_v2(
    relation_kind: SmallwoodRecursiveRelationKindV1,
) -> Result<SmallwoodRecursiveProfileTagV1, BlockRecursionError> {
    match relation_kind {
        SmallwoodRecursiveRelationKindV1::ChunkA
        | SmallwoodRecursiveRelationKindV1::MergeA
        | SmallwoodRecursiveRelationKindV1::CarryA => Ok(SmallwoodRecursiveProfileTagV1::A),
        SmallwoodRecursiveRelationKindV1::MergeB | SmallwoodRecursiveRelationKindV1::CarryB => {
            Ok(SmallwoodRecursiveProfileTagV1::B)
        }
        _ => Err(BlockRecursionError::InvalidField(
            "tree_v2 relation kind profile mapping",
        )),
    }
}

fn dummy_digest32_v2(seed: u8) -> Digest32 {
    [seed; 32]
}

fn dummy_digest48_v2(seed: u8) -> Digest48 {
    [seed; 48]
}

fn dummy_segment_statement_v2(
    start_index: u32,
    end_index: u32,
    seed: u8,
) -> RecursiveSegmentStatementV2 {
    RecursiveSegmentStatementV2 {
        start_index,
        end_index,
        segment_len: end_index.saturating_sub(start_index),
        tx_statements_commitment: dummy_digest48_v2(seed),
        start_state_digest: dummy_digest48_v2(seed.wrapping_add(1)),
        end_state_digest: dummy_digest48_v2(seed.wrapping_add(2)),
        start_tree_commitment: dummy_digest48_v2(seed.wrapping_add(3)),
        end_tree_commitment: dummy_digest48_v2(seed.wrapping_add(4)),
        statement_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(5)),
        verified_leaf_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(6)),
        verified_receipt_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(7)),
    }
}

fn dummy_composed_segment_statements_v2(
    left_len: u32,
    right_len: u32,
    seed: u8,
) -> (
    RecursiveSegmentStatementV2,
    RecursiveSegmentStatementV2,
    RecursiveSegmentStatementV2,
) {
    let tx_statements_commitment = dummy_digest48_v2(seed);
    let start_state_digest = dummy_digest48_v2(seed.wrapping_add(1));
    let left_end_state_digest = dummy_digest48_v2(seed.wrapping_add(2));
    let end_state_digest = dummy_digest48_v2(seed.wrapping_add(3));
    let start_tree_commitment = dummy_digest48_v2(seed.wrapping_add(4));
    let left_end_tree_commitment = dummy_digest48_v2(seed.wrapping_add(5));
    let end_tree_commitment = dummy_digest48_v2(seed.wrapping_add(6));
    let left = RecursiveSegmentStatementV2 {
        start_index: 0,
        end_index: left_len,
        segment_len: left_len,
        tx_statements_commitment,
        start_state_digest,
        end_state_digest: left_end_state_digest,
        start_tree_commitment,
        end_tree_commitment: left_end_tree_commitment,
        statement_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(7)),
        verified_leaf_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(8)),
        verified_receipt_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(9)),
    };
    let right = RecursiveSegmentStatementV2 {
        start_index: left_len,
        end_index: left_len + right_len,
        segment_len: right_len,
        tx_statements_commitment,
        start_state_digest: left_end_state_digest,
        end_state_digest,
        start_tree_commitment: left_end_tree_commitment,
        end_tree_commitment,
        statement_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(10)),
        verified_leaf_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(11)),
        verified_receipt_tree_digest_v2: dummy_digest48_v2(seed.wrapping_add(12)),
    };
    let target = compose_recursive_segment_statements_v2(&left, &right)
        .expect("dummy composed segment statements must join");
    (left, right, target)
}

fn dummy_leaf_record_v2(tx_index: u32, seed: u8) -> BlockLeafRecordV1 {
    BlockLeafRecordV1 {
        tx_index,
        receipt_statement_hash: dummy_digest48_v2(seed),
        receipt_proof_digest: dummy_digest48_v2(seed.wrapping_add(1)),
        receipt_public_inputs_digest: dummy_digest48_v2(seed.wrapping_add(2)),
        receipt_verifier_profile: dummy_digest48_v2(seed.wrapping_add(3)),
        leaf_params_fingerprint: dummy_digest48_v2(seed.wrapping_add(4)),
        leaf_spec_digest: dummy_digest32_v2(seed.wrapping_add(5)),
        leaf_relation_id: dummy_digest32_v2(seed.wrapping_add(6)),
        leaf_shape_digest: dummy_digest32_v2(seed.wrapping_add(7)),
        leaf_statement_digest: dummy_digest48_v2(seed.wrapping_add(8)),
        leaf_commitment_digest: dummy_digest48_v2(seed.wrapping_add(9)),
        leaf_proof_digest: dummy_digest48_v2(seed.wrapping_add(10)),
    }
}

fn dummy_tree_node_v2(
    level: usize,
    relation_kind: SmallwoodRecursiveRelationKindV1,
    statement: RecursiveSegmentStatementV2,
) -> Result<TreeProofNodeV2, BlockRecursionError> {
    Ok(TreeProofNodeV2 {
        level,
        statement,
        profile: profile_for_relation_kind_v2(relation_kind)?,
        relation_kind,
        proof_bytes: Vec::new(),
    })
}

fn projected_tree_relation_proof_bytes_v2(
    relation_kind: SmallwoodRecursiveRelationKindV1,
    relation: &TreeRelationV2,
) -> Result<usize, BlockRecursionError> {
    let profile = profile_for_relation_kind_v2(relation_kind)?;
    projected_smallwood_recursive_proof_bytes_v1(&tree_recursive_profile_v2(profile), relation)
        .map_err(|err| {
            BlockRecursionError::InvalidField(Box::leak(
                format!("tree_v2 projected proof bytes: {err}").into_boxed_str(),
            ))
        })
}

fn projected_tree_relation_proof_bytes_for_aux_bytes_v2(
    profile: SmallwoodRecursiveProfileTagV1,
    auxiliary_witness_bytes: usize,
) -> Result<usize, BlockRecursionError> {
    let relation = ProjectionRelationV2 {
        auxiliary_witness_words: vec![0u64; auxiliary_witness_bytes.div_ceil(8)],
    };
    projected_smallwood_recursive_proof_bytes_v1(&tree_recursive_profile_v2(profile), &relation)
        .map_err(|err| {
            BlockRecursionError::InvalidField(Box::leak(
                format!("tree_v2 projected proof bytes from aux: {err}").into_boxed_str(),
            ))
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeProjectionSweepPointV2 {
    pub chunk_size: usize,
    pub max_supported_txs: usize,
    pub max_chunk_count: usize,
    pub max_tree_level: usize,
    pub p_chunk_a: usize,
    pub p_merge_a: usize,
    pub p_merge_b: usize,
    pub p_carry_a: usize,
    pub p_carry_b: usize,
    pub root_proof_cap: usize,
    pub artifact_bytes: usize,
}

pub fn derive_tree_projection_point_v2(
    chunk_size: usize,
    max_supported_txs: usize,
) -> Result<TreeProjectionSweepPointV2, BlockRecursionError> {
    if chunk_size == 0 || max_supported_txs == 0 {
        return Err(BlockRecursionError::InvalidField(
            "tree_v2 projection chunk_size/max_supported_txs",
        ));
    }
    let chunk_aux_bytes = chunk_size * CHUNK_SLOT_BYTES_V2;
    let p_chunk_a = projected_tree_relation_proof_bytes_for_aux_bytes_v2(
        SmallwoodRecursiveProfileTagV1::A,
        chunk_aux_bytes,
    )?;
    let max_chunk_count = max_supported_txs.div_ceil(chunk_size);
    let max_tree_level = tree_root_level_for_chunk_count_v2(max_chunk_count);
    let mut p_merge_a = 0usize;
    let mut p_merge_b = 0usize;
    let mut p_carry_a = 0usize;
    let mut p_carry_b = 0usize;
    let mut level_caps = vec![p_chunk_a];
    for tree_level in 1..=max_tree_level {
        let child_cap = level_caps[tree_level - 1];
        let merge_kind = tree_merge_kind_for_level_v2(tree_level);
        let carry_kind = tree_carry_kind_for_level_v2(tree_level);
        let merge_profile = profile_for_relation_kind_v2(merge_kind)?;
        let carry_profile = profile_for_relation_kind_v2(carry_kind)?;
        let merge_cap = projected_tree_relation_proof_bytes_for_aux_bytes_v2(
            merge_profile,
            (TREE_CHILD_WITNESS_HEADER_BYTES_V2 * 2) + TREE_MERGE_SUMMARY_BYTES_V2 + (child_cap * 2),
        )?;
        let carry_cap = projected_tree_relation_proof_bytes_for_aux_bytes_v2(
            carry_profile,
            TREE_CHILD_WITNESS_HEADER_BYTES_V2 + child_cap,
        )?;
        match merge_kind {
            SmallwoodRecursiveRelationKindV1::MergeA => p_merge_a = p_merge_a.max(merge_cap),
            SmallwoodRecursiveRelationKindV1::MergeB => p_merge_b = p_merge_b.max(merge_cap),
            _ => {}
        }
        match carry_kind {
            SmallwoodRecursiveRelationKindV1::CarryA => p_carry_a = p_carry_a.max(carry_cap),
            SmallwoodRecursiveRelationKindV1::CarryB => p_carry_b = p_carry_b.max(carry_cap),
            _ => {}
        }
        level_caps.push(merge_cap.max(carry_cap));
    }
    let root_proof_cap = *level_caps.last().ok_or(BlockRecursionError::InvalidField(
        "tree_v2 projection level_caps",
    ))?;
    Ok(TreeProjectionSweepPointV2 {
        chunk_size,
        max_supported_txs,
        max_chunk_count,
        max_tree_level,
        p_chunk_a,
        p_merge_a,
        p_merge_b,
        p_carry_a,
        p_carry_b,
        root_proof_cap,
        artifact_bytes: RECURSIVE_BLOCK_HEADER_BYTES_V2
            + RECURSIVE_BLOCK_PUBLIC_BYTES_V2
            + root_proof_cap,
    })
}

fn projected_chunk_proof_bytes_v2() -> Result<usize, BlockRecursionError> {
    let records = (0..TREE_RECURSIVE_CHUNK_SIZE_V2)
        .map(|idx| dummy_leaf_record_v2(idx as u32, 0x30u8.wrapping_add(idx as u8)))
        .collect::<Vec<_>>();
    let relation = TreeRelationV2::new_chunk(
        dummy_segment_statement_v2(0, TREE_RECURSIVE_CHUNK_SIZE_V2 as u32, 0x40),
        &records,
    )?;
    projected_tree_relation_proof_bytes_v2(SmallwoodRecursiveRelationKindV1::ChunkA, &relation)
}

fn projected_merge_proof_bytes_v2(
    relation_kind: SmallwoodRecursiveRelationKindV1,
    tree_level: usize,
    child_proof_cap: usize,
) -> Result<usize, BlockRecursionError> {
    let (left_statement, right_statement, target_statement) = dummy_composed_segment_statements_v2(
        TREE_RECURSIVE_CHUNK_SIZE_V2 as u32,
        TREE_RECURSIVE_CHUNK_SIZE_V2 as u32,
        0x50,
    );
    let left = dummy_tree_node_v2(
        tree_level.saturating_sub(1),
        SmallwoodRecursiveRelationKindV1::ChunkA,
        left_statement,
    )?;
    let right = dummy_tree_node_v2(
        tree_level.saturating_sub(1),
        SmallwoodRecursiveRelationKindV1::ChunkA,
        right_statement,
    )?;
    let relation = TreeRelationV2::new_merge_with_child_cap(
        relation_kind,
        tree_level,
        target_statement,
        &left,
        &right,
        child_proof_cap,
    )?;
    projected_tree_relation_proof_bytes_v2(relation_kind, &relation)
}

fn projected_carry_proof_bytes_v2(
    relation_kind: SmallwoodRecursiveRelationKindV1,
    tree_level: usize,
    child_proof_cap: usize,
) -> Result<usize, BlockRecursionError> {
    let child = dummy_tree_node_v2(
        tree_level.saturating_sub(1),
        SmallwoodRecursiveRelationKindV1::ChunkA,
        dummy_segment_statement_v2(0, TREE_RECURSIVE_CHUNK_SIZE_V2 as u32, 0x80),
    )?;
    let relation = TreeRelationV2::new_carry_with_child_cap(
        relation_kind,
        tree_level,
        child.statement.clone(),
        &child,
        child_proof_cap,
    )?;
    projected_tree_relation_proof_bytes_v2(relation_kind, &relation)
}

pub fn derive_tree_proof_cap_v2() -> Result<TreeProofCapReportV2, BlockRecursionError> {
    let p_chunk_a = projected_chunk_proof_bytes_v2()?;
    let max_chunk_count =
        TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2.div_ceil(TREE_RECURSIVE_CHUNK_SIZE_V2);
    let max_tree_level = tree_root_level_for_chunk_count_v2(max_chunk_count);
    let mut p_merge_a = 0usize;
    let mut p_merge_b = 0usize;
    let mut p_carry_a = 0usize;
    let mut p_carry_b = 0usize;
    let mut level_caps = vec![p_chunk_a];
    for tree_level in 1..=max_tree_level {
        let child_cap = level_caps[tree_level - 1];
        let merge_kind = tree_merge_kind_for_level_v2(tree_level);
        let carry_kind = tree_carry_kind_for_level_v2(tree_level);
        let merge_cap = projected_merge_proof_bytes_v2(merge_kind, tree_level, child_cap)?;
        let carry_cap = projected_carry_proof_bytes_v2(carry_kind, tree_level, child_cap)?;
        match merge_kind {
            SmallwoodRecursiveRelationKindV1::MergeA => p_merge_a = p_merge_a.max(merge_cap),
            SmallwoodRecursiveRelationKindV1::MergeB => p_merge_b = p_merge_b.max(merge_cap),
            _ => {}
        }
        match carry_kind {
            SmallwoodRecursiveRelationKindV1::CarryA => p_carry_a = p_carry_a.max(carry_cap),
            SmallwoodRecursiveRelationKindV1::CarryB => p_carry_b = p_carry_b.max(carry_cap),
            _ => {}
        }
        level_caps.push(merge_cap.max(carry_cap));
    }
    let root_proof_cap = *level_caps.last().ok_or(BlockRecursionError::InvalidField(
        "tree_v2 proof cap level_caps",
    ))?;
    Ok(TreeProofCapReportV2 {
        max_supported_txs: TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2,
        max_chunk_count,
        max_tree_level,
        p_chunk_a,
        p_merge_a,
        p_merge_b,
        p_carry_a,
        p_carry_b,
        level_caps,
        root_proof_cap,
    })
}

pub fn tree_proof_cap_report_v2() -> &'static TreeProofCapReportV2 {
    TREE_PROOF_CAP_REPORT_V2
        .get_or_init(|| derive_tree_proof_cap_v2().expect("tree_v2 proof cap must derive"))
}

pub fn tree_witness_geometry_report_v2() -> TreeWitnessGeometryReportV2 {
    TreeWitnessGeometryReportV2 {
        chunk_slot_bytes: CHUNK_SLOT_BYTES_V2,
        full_chunk_witness_bytes: TREE_RECURSIVE_CHUNK_SIZE_V2 * CHUNK_SLOT_BYTES_V2,
        merge_summary_bytes: TREE_MERGE_SUMMARY_BYTES_V2,
        merge_child_header_bytes: TREE_CHILD_WITNESS_HEADER_BYTES_V2 * 2,
    }
}

fn tree_recursive_child_proof_bytes_v2(tree_level: usize) -> usize {
    debug_assert!(tree_level > 0);
    tree_proof_cap_report_v2().level_caps[tree_level - 1]
}

pub fn project_tree_proof_bytes_v2() -> usize {
    tree_proof_cap_report_v2().root_proof_cap
}

pub fn recursive_block_artifact_bytes_v2() -> usize {
    RECURSIVE_BLOCK_HEADER_BYTES_V2
        + project_tree_proof_bytes_v2()
        + recursive_block_public_bytes_v2()
}

fn pad_terminal_proof_bytes_v2(proof_bytes: Vec<u8>) -> Result<Vec<u8>, BlockRecursionError> {
    let cap = project_tree_proof_bytes_v2();
    if proof_bytes.len() > cap {
        return Err(BlockRecursionError::WidthMismatch {
            what: "proof_bytes_rec_v2",
            expected: cap,
            actual: proof_bytes.len(),
        });
    }
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&proof_bytes);
    out.resize(cap, 0u8);
    Ok(out)
}

pub fn recursive_block_public_bytes_v2() -> usize {
    RECURSIVE_BLOCK_PUBLIC_BYTES_V2
}

pub fn serialize_recursive_block_public_v2(public: &RecursiveBlockPublicV2) -> Vec<u8> {
    let mut out = Vec::with_capacity(recursive_block_public_bytes_v2());
    put_u32_v2(&mut out, public.tx_count);
    put_fixed_v2(&mut out, &public.tx_statements_commitment);
    put_fixed_v2(&mut out, &public.statement_tree_digest_v2);
    put_fixed_v2(&mut out, &public.verified_leaf_tree_digest_v2);
    put_fixed_v2(&mut out, &public.verified_receipt_tree_digest_v2);
    put_fixed_v2(&mut out, &public.start_state_digest_rec_v2);
    put_fixed_v2(&mut out, &public.end_state_digest_rec_v2);
    put_fixed_v2(&mut out, &public.start_shielded_root);
    put_fixed_v2(&mut out, &public.end_shielded_root);
    put_fixed_v2(&mut out, &public.start_kernel_root);
    put_fixed_v2(&mut out, &public.end_kernel_root);
    put_fixed_v2(&mut out, &public.nullifier_root);
    put_fixed_v2(&mut out, &public.da_root);
    put_fixed_v2(&mut out, &public.start_tree_commitment);
    put_fixed_v2(&mut out, &public.end_tree_commitment);
    out
}

fn deserialize_recursive_block_public_v2(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<RecursiveBlockPublicV2, BlockRecursionError> {
    Ok(RecursiveBlockPublicV2 {
        tx_count: read_exact_u32_v2(bytes, cursor)?,
        tx_statements_commitment: read_exact_fixed_v2::<48>(bytes, cursor)?,
        statement_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, cursor)?,
        verified_leaf_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, cursor)?,
        verified_receipt_tree_digest_v2: read_exact_fixed_v2::<48>(bytes, cursor)?,
        start_state_digest_rec_v2: read_exact_fixed_v2::<48>(bytes, cursor)?,
        end_state_digest_rec_v2: read_exact_fixed_v2::<48>(bytes, cursor)?,
        start_shielded_root: read_exact_fixed_v2::<48>(bytes, cursor)?,
        end_shielded_root: read_exact_fixed_v2::<48>(bytes, cursor)?,
        start_kernel_root: read_exact_fixed_v2::<48>(bytes, cursor)?,
        end_kernel_root: read_exact_fixed_v2::<48>(bytes, cursor)?,
        nullifier_root: read_exact_fixed_v2::<48>(bytes, cursor)?,
        da_root: read_exact_fixed_v2::<48>(bytes, cursor)?,
        start_tree_commitment: read_exact_fixed_v2::<48>(bytes, cursor)?,
        end_tree_commitment: read_exact_fixed_v2::<48>(bytes, cursor)?,
    })
}

pub fn recursive_block_tx_line_digest_v2() -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.tx-line-digest.v2",
        &[b"smallwood_candidate", b"tx_leaf", b"recursive_block_v2"],
    )
}

pub fn recursive_block_proof_encoding_digest_v2() -> Digest32 {
    recursive_block_proof_encoding_digest_parts_v2(
        TREE_RECURSIVE_CHUNK_SIZE_V2 as u32,
        TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 as u32,
        project_tree_proof_bytes_v2() as u32,
    )
}

fn recursive_block_proof_encoding_digest_parts_v2(
    chunk_size: u32,
    max_supported_txs: u32,
    proof_bytes: u32,
) -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.proof-encoding-digest.v2",
        &[
            b"smallwood-recursive-proof-v1",
            &chunk_size.to_le_bytes(),
            &max_supported_txs.to_le_bytes(),
            &proof_bytes.to_le_bytes(),
        ],
    )
}

pub fn recursive_block_artifact_verifier_profile_v2() -> Digest48 {
    fold_digest48(
        b"hegemon.block-recursion.verifier-profile.v2",
        &[
            &RECURSIVE_BLOCK_ARTIFACT_VERSION_V2.to_le_bytes(),
            &recursive_block_tx_line_digest_v2(),
            &recursive_block_proof_encoding_digest_v2(),
            b"recursive_block_v2",
        ],
    )
}

fn serialize_header_rec_tree_v2(header: &HeaderRecTreeV2) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECURSIVE_BLOCK_HEADER_BYTES_V2);
    put_u32_v2(&mut out, header.artifact_version_rec);
    put_fixed_v2(&mut out, &header.tx_line_digest_v2);
    put_u32_v2(&mut out, header.terminal_profile_tag_tau);
    put_u32_v2(&mut out, header.terminal_relation_kind_k);
    put_fixed_v2(&mut out, &header.proof_encoding_digest_rec);
    put_u32_v2(&mut out, header.proof_bytes_rec);
    put_fixed_v2(&mut out, &header.statement_digest_rec);
    out
}

fn deserialize_header_rec_tree_v2(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<HeaderRecTreeV2, BlockRecursionError> {
    Ok(HeaderRecTreeV2 {
        artifact_version_rec: read_exact_u32_v2(bytes, cursor)?,
        tx_line_digest_v2: read_exact_fixed_v2::<32>(bytes, cursor)?,
        terminal_profile_tag_tau: read_exact_u32_v2(bytes, cursor)?,
        terminal_relation_kind_k: read_exact_u32_v2(bytes, cursor)?,
        proof_encoding_digest_rec: read_exact_fixed_v2::<32>(bytes, cursor)?,
        proof_bytes_rec: read_exact_u32_v2(bytes, cursor)?,
        statement_digest_rec: read_exact_fixed_v2::<32>(bytes, cursor)?,
    })
}

pub fn serialize_recursive_block_artifact_v2(
    artifact: &RecursiveBlockArtifactV2,
) -> Result<Vec<u8>, BlockRecursionError> {
    let cap = project_tree_proof_bytes_v2();
    if artifact.artifact.proof_bytes.len() != cap {
        return Err(BlockRecursionError::WidthMismatch {
            what: "recursive_block_v2 proof bytes",
            expected: cap,
            actual: artifact.artifact.proof_bytes.len(),
        });
    }
    let mut out = Vec::new();
    out.extend_from_slice(&serialize_header_rec_tree_v2(&artifact.artifact.header));
    out.extend_from_slice(&artifact.artifact.proof_bytes);
    out.extend_from_slice(&serialize_recursive_block_public_v2(&artifact.public));
    Ok(out)
}

pub fn deserialize_recursive_block_artifact_v2(
    bytes: &[u8],
) -> Result<RecursiveBlockArtifactV2, BlockRecursionError> {
    let mut cursor = 0usize;
    let header = deserialize_header_rec_tree_v2(bytes, &mut cursor)?;
    let cap = project_tree_proof_bytes_v2();
    let proof_bytes = bytes
        .get(cursor..cursor + cap)
        .ok_or(BlockRecursionError::InvalidLength {
            what: "recursive_block_v2 proof bytes",
            expected: cap,
            actual: bytes.len().saturating_sub(cursor),
        })?
        .to_vec();
    cursor += cap;
    let public = deserialize_recursive_block_public_v2(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(RecursiveBlockArtifactV2 {
        artifact: RecursiveBlockInnerArtifactV2 {
            header,
            proof_bytes,
        },
        public,
    })
}

fn build_header_rec_tree_v2(node: &TreeProofNodeV2) -> HeaderRecTreeV2 {
    HeaderRecTreeV2 {
        artifact_version_rec: RECURSIVE_BLOCK_ARTIFACT_VERSION_V2,
        tx_line_digest_v2: recursive_block_tx_line_digest_v2(),
        terminal_profile_tag_tau: node.profile.tag(),
        terminal_relation_kind_k: node.relation_kind.tag(),
        proof_encoding_digest_rec: recursive_block_proof_encoding_digest_v2(),
        proof_bytes_rec: project_tree_proof_bytes_v2() as u32,
        statement_digest_rec: recursive_segment_statement_digest32_v2(&node.statement),
    }
}

pub fn prove_block_recursive_v2(
    input: &BlockRecursiveProverInputV2,
) -> Result<RecursiveBlockArtifactV2, BlockRecursionError> {
    ensure_supported_tree_tx_count_v2(input.records.len() as u32)?;
    let public = public_replay_v2(&input.records, &input.semantic)?;
    let mut level = 0usize;
    let mut current = input
        .records
        .par_chunks(TREE_RECURSIVE_CHUNK_SIZE_V2)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            let start = chunk_idx * TREE_RECURSIVE_CHUNK_SIZE_V2;
            let end = start + chunk.len();
            let statement = recursive_segment_statement_for_interval_v2(
                &input.records,
                &input.semantic,
                start,
                end,
            )?;
            let relation = TreeRelationV2::new_chunk(statement.clone(), chunk)?;
            let proof_bytes = prove_tree_relation_v2(SmallwoodRecursiveProfileTagV1::A, &relation)?;
            Ok(TreeProofNodeV2 {
                level,
                statement,
                profile: SmallwoodRecursiveProfileTagV1::A,
                relation_kind: SmallwoodRecursiveRelationKindV1::ChunkA,
                proof_bytes,
            })
        })
        .collect::<Result<Vec<_>, BlockRecursionError>>()?;

    while current.len() > 1 {
        level += 1;
        let profile = tree_profile_for_level_v2(level);
        let merge_kind = tree_merge_kind_for_level_v2(level);
        let carry_kind = tree_carry_kind_for_level_v2(level);
        let pairs = (0..current.len()).step_by(2).collect::<Vec<_>>();
        current = pairs
            .into_par_iter()
            .map(|idx| {
                if idx + 1 >= current.len() {
                    let child = &current[idx];
                    let relation =
                        TreeRelationV2::new_carry(carry_kind, child.statement.clone(), child)?;
                    let proof_bytes = prove_tree_relation_v2(profile, &relation)?;
                    Ok(TreeProofNodeV2 {
                        level,
                        statement: child.statement.clone(),
                        profile,
                        relation_kind: carry_kind,
                        proof_bytes,
                    })
                } else {
                    let left = &current[idx];
                    let right = &current[idx + 1];
                    let statement =
                        compose_recursive_segment_statements_v2(&left.statement, &right.statement)?;
                    let relation =
                        TreeRelationV2::new_merge(merge_kind, statement.clone(), left, right)?;
                    let proof_bytes = prove_tree_relation_v2(profile, &relation)?;
                    Ok(TreeProofNodeV2 {
                        level,
                        statement,
                        profile,
                        relation_kind: merge_kind,
                        proof_bytes,
                    })
                }
            })
            .collect::<Result<Vec<_>, BlockRecursionError>>()?;
    }

    let root = current
        .into_iter()
        .next()
        .ok_or(BlockRecursionError::InvalidField("recursive_block_v2 root"))?;
    let expected_root_statement = recursive_segment_statement_from_public_v2(&public);
    if root.statement != expected_root_statement {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "recursive_block_v2 root statement mismatch",
        ));
    }
    let header = build_header_rec_tree_v2(&root);
    let proof_bytes = pad_terminal_proof_bytes_v2(root.proof_bytes)?;
    Ok(RecursiveBlockArtifactV2 {
        artifact: RecursiveBlockInnerArtifactV2 {
            header,
            proof_bytes,
        },
        public,
    })
}

fn expected_root_terminal_kind_v2(
    tx_count: u32,
) -> Result<SmallwoodRecursiveRelationKindV1, BlockRecursionError> {
    let mut node_count = tree_chunk_count_for_tx_count_v2(tx_count)?;
    if node_count == 1 {
        return Ok(SmallwoodRecursiveRelationKindV1::ChunkA);
    }
    let mut level = 0usize;
    let mut last_kind = SmallwoodRecursiveRelationKindV1::ChunkA;
    while node_count > 1 {
        level += 1;
        let odd = node_count % 2 == 1;
        node_count = node_count.div_ceil(2);
        last_kind = if odd && node_count == 1 {
            tree_carry_kind_for_level_v2(level)
        } else {
            tree_merge_kind_for_level_v2(level)
        };
    }
    Ok(last_kind)
}

fn expected_root_terminal_profile_v2(
    tx_count: u32,
) -> Result<SmallwoodRecursiveProfileTagV1, BlockRecursionError> {
    Ok(match expected_root_terminal_kind_v2(tx_count)? {
        SmallwoodRecursiveRelationKindV1::ChunkA => SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::MergeA | SmallwoodRecursiveRelationKindV1::CarryA => {
            SmallwoodRecursiveProfileTagV1::A
        }
        SmallwoodRecursiveRelationKindV1::MergeB | SmallwoodRecursiveRelationKindV1::CarryB => {
            SmallwoodRecursiveProfileTagV1::B
        }
        _ => SmallwoodRecursiveProfileTagV1::A,
    })
}

pub fn verify_block_recursive_v2(
    artifact: &RecursiveBlockArtifactV2,
    expected_public: &RecursiveBlockPublicV2,
) -> Result<RecursiveBlockPublicV2, BlockRecursionError> {
    if artifact.public != *expected_public {
        return Err(BlockRecursionError::InvalidField(
            "recursive_block_v2 public mismatch",
        ));
    }
    let cap = project_tree_proof_bytes_v2();
    if artifact.artifact.proof_bytes.len() != cap {
        return Err(BlockRecursionError::WidthMismatch {
            what: "recursive_block_v2 proof bytes",
            expected: cap,
            actual: artifact.artifact.proof_bytes.len(),
        });
    }
    let expected_kind = expected_root_terminal_kind_v2(expected_public.tx_count)?;
    let expected_profile = expected_root_terminal_profile_v2(expected_public.tx_count)?;
    let expected_level = tree_root_level_for_tx_count_v2(expected_public.tx_count)?;
    let expected_statement = recursive_segment_statement_from_public_v2(expected_public);
    let expected_header = HeaderRecTreeV2 {
        artifact_version_rec: RECURSIVE_BLOCK_ARTIFACT_VERSION_V2,
        tx_line_digest_v2: recursive_block_tx_line_digest_v2(),
        terminal_profile_tag_tau: expected_profile.tag(),
        terminal_relation_kind_k: expected_kind.tag(),
        proof_encoding_digest_rec: recursive_block_proof_encoding_digest_v2(),
        proof_bytes_rec: cap as u32,
        statement_digest_rec: recursive_segment_statement_digest32_v2(&expected_statement),
    };
    if artifact.artifact.header != expected_header {
        return Err(BlockRecursionError::InvalidField(
            "recursive_block_v2 header mismatch",
        ));
    }
    let (canonical_proof_bytes, canonical_len) =
        decode_canonical_tree_proof_prefix_v2(&artifact.artifact.proof_bytes)?;
    let projected_proof_bytes = projected_smallwood_recursive_proof_bytes_v1(
        &tree_recursive_profile_v2(expected_profile),
        &rebuild_tree_relation_from_proof_v2(
            expected_profile,
            expected_kind,
            expected_level,
            expected_statement.clone(),
            &canonical_proof_bytes,
        )?,
    )
    .map_err(|err| {
        BlockRecursionError::InvalidField(Box::leak(
            format!("tree_v2 project proof bytes: {err}").into_boxed_str(),
        ))
    })?;
    if canonical_len > projected_proof_bytes {
        return Err(BlockRecursionError::WidthMismatch {
            what: "recursive_block_v2 proof bytes",
            expected: projected_proof_bytes,
            actual: canonical_len,
        });
    }
    verify_tree_child_v2(
        expected_profile,
        expected_kind,
        expected_level,
        &expected_statement,
        &canonical_proof_bytes,
    )?;
    Ok(expected_public.clone())
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use transaction_circuit::{
        build_recursive_verifier_trace_v1, decode_smallwood_proof_trace_v1,
        projected_smallwood_recursive_envelope_bytes_v1,
    };

    fn digest32(tag: u8, idx: u32) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (offset, byte) in out.iter_mut().enumerate() {
            *byte = tag
                .wrapping_add(idx as u8)
                .wrapping_add((offset as u8).wrapping_mul(3));
        }
        out
    }

    fn digest48(tag: u8, idx: u32) -> [u8; 48] {
        let mut out = [0u8; 48];
        for (offset, byte) in out.iter_mut().enumerate() {
            *byte = tag
                .wrapping_add(idx as u8)
                .wrapping_add((offset as u8).wrapping_mul(5));
        }
        out
    }

    fn sample_input_v2(tx_count: u32) -> BlockRecursiveProverInputV2 {
        let records = (0..tx_count)
            .map(|tx_index| BlockLeafRecordV1 {
                tx_index,
                receipt_statement_hash: digest48(0x10, tx_index),
                receipt_proof_digest: digest48(0x20, tx_index),
                receipt_public_inputs_digest: digest48(0x30, tx_index),
                receipt_verifier_profile: digest48(0x40, tx_index),
                leaf_params_fingerprint: digest48(0x50, tx_index),
                leaf_spec_digest: digest32(0x60, tx_index),
                leaf_relation_id: digest32(0x70, tx_index),
                leaf_shape_digest: digest32(0x80, tx_index),
                leaf_statement_digest: digest48(0x90, tx_index),
                leaf_commitment_digest: digest48(0xa0, tx_index),
                leaf_proof_digest: digest48(0xb0, tx_index),
            })
            .collect();
        BlockRecursiveProverInputV2 {
            records,
            semantic: BlockSemanticInputsV1 {
                tx_statements_commitment: digest48(0xc0, tx_count),
                start_shielded_root: digest48(0xd0, 0),
                end_shielded_root: digest48(0xd1, tx_count),
                start_kernel_root: digest48(0xe0, 0),
                end_kernel_root: digest48(0xe1, tx_count),
                nullifier_root: digest48(0xf0, tx_count),
                da_root: digest48(0xf8, tx_count),
                start_tree_commitment: digest48(0xa8, 0),
                end_tree_commitment: digest48(0xa9, tx_count),
            },
        }
    }

    #[test]
    #[ignore = "diagnostic size-report for compact child object experiments"]
    fn tree_v2_child_object_candidate_size_report() {
        let tx_count = if TREE_RECURSIVE_CHUNK_SIZE_V2 >= TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 {
            TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 as u32
        } else {
            (TREE_RECURSIVE_CHUNK_SIZE_V2 + 1) as u32
        };
        let input = sample_input_v2(tx_count);
        let artifact = prove_block_recursive_v2(&input).unwrap();
        let expected_public = public_replay_v2(&input.records, &input.semantic).unwrap();
        let expected_kind = expected_root_terminal_kind_v2(expected_public.tx_count).unwrap();
        let expected_profile = expected_root_terminal_profile_v2(expected_public.tx_count).unwrap();
        let expected_level = tree_root_level_for_tx_count_v2(expected_public.tx_count).unwrap();
        let expected_statement = recursive_segment_statement_from_public_v2(&expected_public);
        let (canonical_proof_bytes, _consumed_len) =
            decode_canonical_tree_proof_prefix_v2(&artifact.artifact.proof_bytes).unwrap();
        let relation = rebuild_tree_relation_from_proof_v2(
            expected_profile,
            expected_kind,
            expected_level,
            expected_statement.clone(),
            &canonical_proof_bytes,
        )
        .unwrap();
        let actual_proof_bytes = canonical_proof_bytes.len();
        let proof_slice = canonical_proof_bytes.as_slice();
        let proof_trace = decode_smallwood_proof_trace_v1(proof_slice).unwrap();
        let descriptor =
            tree_recursive_descriptor_v2(expected_profile, expected_kind, expected_level);
        let binding = tree_binding_bytes_v2(&expected_statement);
        let verifier_trace = build_recursive_verifier_trace_v1(
            &tree_recursive_profile_v2(expected_profile),
            &descriptor,
            &relation,
            &binding,
            proof_slice,
        )
        .unwrap();
        let proof_trace_bytes = bincode::serialize(&proof_trace).unwrap();
        let verifier_trace_bytes = bincode::serialize(&verifier_trace).unwrap();
        let envelope_bytes =
            projected_smallwood_recursive_envelope_bytes_v1(&descriptor, actual_proof_bytes)
                .unwrap();
        eprintln!(
            "tree_v2 child object candidates: proof={} proof_trace={} verifier_trace={} envelope={} aux_words={}",
            actual_proof_bytes,
            proof_trace_bytes.len(),
            verifier_trace_bytes.len(),
            envelope_bytes,
            relation.auxiliary_witness_words.len()
        );
    }

    #[test]
    fn tree_v2_proof_encoding_digest_binds_chunk_geometry() {
        let current = recursive_block_proof_encoding_digest_v2();
        let same_width_old_chunk = recursive_block_proof_encoding_digest_parts_v2(
            256,
            TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 as u32,
            project_tree_proof_bytes_v2() as u32,
        );
        let same_chunk_old_width = recursive_block_proof_encoding_digest_parts_v2(
            TREE_RECURSIVE_CHUNK_SIZE_V2 as u32,
            TREE_RECURSIVE_MAX_SUPPORTED_TXS_V2 as u32,
            783_135u32,
        );
        assert_ne!(current, same_width_old_chunk);
        assert_ne!(current, same_chunk_old_width);
    }

    #[test]
    fn tree_v2_merge_relation_executes_under_synthetic_two_chunk_shape() {
        let input = sample_input_v2(2);
        let left_statement =
            recursive_segment_statement_for_interval_v2(&input.records, &input.semantic, 0, 1)
                .expect("left statement");
        let right_statement =
            recursive_segment_statement_for_interval_v2(&input.records, &input.semantic, 1, 2)
                .expect("right statement");

        let left_chunk = TreeRelationV2::new_chunk(left_statement.clone(), &input.records[..1])
            .expect("left chunk relation");
        let right_chunk = TreeRelationV2::new_chunk(right_statement.clone(), &input.records[1..2])
            .expect("right chunk relation");
        let left_proof =
            prove_tree_relation_v2(SmallwoodRecursiveProfileTagV1::A, &left_chunk)
                .expect("left chunk proof");
        let right_proof =
            prove_tree_relation_v2(SmallwoodRecursiveProfileTagV1::A, &right_chunk)
                .expect("right chunk proof");
        let left_node = TreeProofNodeV2 {
            level: 0,
            statement: left_statement,
            profile: SmallwoodRecursiveProfileTagV1::A,
            relation_kind: SmallwoodRecursiveRelationKindV1::ChunkA,
            proof_bytes: left_proof,
        };
        let right_node = TreeProofNodeV2 {
            level: 0,
            statement: right_statement,
            profile: SmallwoodRecursiveProfileTagV1::A,
            relation_kind: SmallwoodRecursiveRelationKindV1::ChunkA,
            proof_bytes: right_proof,
        };

        let merge_kind = tree_merge_kind_for_level_v2(1);
        let profile = tree_profile_for_level_v2(1);
        let target_statement =
            compose_recursive_segment_statements_v2(&left_node.statement, &right_node.statement)
                .expect("merge target");
        let merge_relation =
            TreeRelationV2::new_merge(merge_kind, target_statement.clone(), &left_node, &right_node)
                .expect("merge relation");
        let merge_proof =
            prove_tree_relation_v2(profile, &merge_relation).expect("merge proof");
        verify_tree_child_v2(profile, merge_kind, 1, &target_statement, &merge_proof)
            .expect("merge verify");
    }

    #[test]
    fn tree_v2_carry_relation_executes_under_synthetic_odd_chunk_shape() {
        let input = sample_input_v2(1);
        let statement =
            recursive_segment_statement_for_interval_v2(&input.records, &input.semantic, 0, 1)
                .expect("chunk statement");
        let chunk_relation =
            TreeRelationV2::new_chunk(statement.clone(), &input.records[..1]).expect("chunk relation");
        let chunk_proof =
            prove_tree_relation_v2(SmallwoodRecursiveProfileTagV1::A, &chunk_relation)
                .expect("chunk proof");
        let child_node = TreeProofNodeV2 {
            level: 0,
            statement: statement.clone(),
            profile: SmallwoodRecursiveProfileTagV1::A,
            relation_kind: SmallwoodRecursiveRelationKindV1::ChunkA,
            proof_bytes: chunk_proof,
        };

        let carry_kind = tree_carry_kind_for_level_v2(1);
        let profile = tree_profile_for_level_v2(1);
        let carry_relation =
            TreeRelationV2::new_carry(carry_kind, statement.clone(), &child_node)
                .expect("carry relation");
        let carry_proof =
            prove_tree_relation_v2(profile, &carry_relation).expect("carry proof");
        verify_tree_child_v2(profile, carry_kind, 1, &statement, &carry_proof)
            .expect("carry verify");
    }
}
