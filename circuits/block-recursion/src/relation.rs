use crate::{
    public_replay::{BlockLeafRecordV1, RecursiveBlockPublicV1},
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

const RECURSIVE_BLOCK_RELATION_LABEL_V1: &str = "hegemon.superneo.block-recursive.v1";
const BLOCK_RECURSIVE_WITNESS_SLOTS: usize = 96;

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

fn bytes32_to_goldilocks(bytes: &Digest32) -> [Goldilocks; 4] {
    std::array::from_fn(|idx| {
        let start = idx * 8;
        Goldilocks::new(u64::from_le_bytes(
            bytes[start..start + 8].try_into().expect("fixed slice"),
        ))
    })
}

fn bytes48_to_goldilocks(bytes: &Digest48) -> [Goldilocks; 6] {
    std::array::from_fn(|idx| {
        let start = idx * 8;
        Goldilocks::new(u64::from_le_bytes(
            bytes[start..start + 8].try_into().expect("fixed slice"),
        ))
    })
}

pub fn block_public_inputs_v1(public: &RecursiveBlockPublicV1) -> Vec<Goldilocks> {
    let mut inputs = Vec::with_capacity(1 + (6 * 9) + (4 * 2));
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
    inputs.extend_from_slice(&bytes32_to_goldilocks(&public.frontier_commitment));
    inputs.extend_from_slice(&bytes32_to_goldilocks(&public.history_commitment));
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
        frontier_commitment: [0u8; 32],
        history_commitment: [0u8; 32],
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
