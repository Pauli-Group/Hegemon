use crate::{
    fold_digest32, fold_digest48, public_replay::RecursiveBlockPublicV1, BlockRecursionError,
    Digest32, Digest48,
};
use transaction_circuit::{
    smallwood_recursive_proof_encoding_digest_v1, SmallwoodRecursiveProfileTagV1,
    SmallwoodRecursiveRelationKindV1,
};

pub const RECURSIVE_BLOCK_ARTIFACT_VERSION_V1: u32 = 1;
pub const RECURSIVE_BLOCK_HEADER_BYTES_V1: usize = 336;
pub const RECURSIVE_BLOCK_PUBLIC_BYTES_V1: usize = 532;
pub const RECURSIVE_BLOCK_STEP_A_PROOF_BYTES_V1: usize = 698_536;
pub const RECURSIVE_BLOCK_STEP_B_PROOF_BYTES_V1: usize = 200_952;
pub const RECURSIVE_BLOCK_PROOF_BYTES_V1: usize = RECURSIVE_BLOCK_STEP_A_PROOF_BYTES_V1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRecStepV1 {
    pub artifact_version_rec: u32,
    pub tx_line_digest_v1: Digest32,
    pub rec_profile_tag_tau: u32,
    pub terminal_relation_kind_k: u32,
    pub relation_id_base_a: Digest32,
    pub relation_id_step_a: Digest32,
    pub relation_id_step_b: Digest32,
    pub shape_digest_rec: Digest32,
    pub vk_digest_base_a: Digest32,
    pub vk_digest_step_a: Digest32,
    pub vk_digest_step_b: Digest32,
    pub proof_encoding_digest_rec: Digest32,
    pub proof_bytes_rec: u32,
    pub statement_digest_rec: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockInnerArtifactV1 {
    pub header: HeaderRecStepV1,
    pub proof_bytes: Vec<u8>,
}

pub type RecursiveBlockArtifactRecV1 = RecursiveBlockInnerArtifactV1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockArtifactV1 {
    pub artifact: RecursiveBlockInnerArtifactV1,
    pub public: RecursiveBlockPublicV1,
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_fixed<const N: usize>(out: &mut Vec<u8>, value: &[u8; N]) {
    out.extend_from_slice(value);
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, BlockRecursionError> {
    let end = cursor.saturating_add(4);
    if end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "u32",
            expected: 4,
            actual: bytes.len().saturating_sub(*cursor),
        });
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(u32::from_le_bytes(buf))
}

fn read_fixed<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], BlockRecursionError> {
    let end = cursor.saturating_add(N);
    if end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "fixed bytes",
            expected: N,
            actual: bytes.len().saturating_sub(*cursor),
        });
    }
    let mut buf = [0u8; N];
    buf.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(buf)
}

pub fn recursive_block_tx_line_digest_v1() -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.tx-line-digest.v1",
        &[b"smallwood_candidate", b"tx_leaf", b"recursive_block_v1"],
    )
}

pub fn recursive_block_proof_encoding_digest_v1() -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.proof-encoding-digest.v1",
        &[&smallwood_recursive_proof_encoding_digest_v1()],
    )
}

pub fn recursive_block_artifact_verifier_profile_v1() -> Digest48 {
    fold_digest48(
        b"hegemon.block-recursion.verifier-profile.v1",
        &[
            &RECURSIVE_BLOCK_ARTIFACT_VERSION_V1.to_le_bytes(),
            &recursive_block_tx_line_digest_v1(),
            &recursive_block_proof_encoding_digest_v1(),
            b"recursive_block_v1",
        ],
    )
}

pub fn serialize_recursive_block_public_v1(public: &RecursiveBlockPublicV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECURSIVE_BLOCK_PUBLIC_BYTES_V1);
    put_u32(&mut out, public.tx_count);
    put_fixed(&mut out, &public.tx_statements_commitment);
    put_fixed(&mut out, &public.verified_leaf_commitment);
    put_fixed(&mut out, &public.verified_receipt_commitment);
    put_fixed(&mut out, &public.start_shielded_root);
    put_fixed(&mut out, &public.end_shielded_root);
    put_fixed(&mut out, &public.start_kernel_root);
    put_fixed(&mut out, &public.end_kernel_root);
    put_fixed(&mut out, &public.nullifier_root);
    put_fixed(&mut out, &public.da_root);
    put_fixed(&mut out, &public.start_tree_commitment);
    put_fixed(&mut out, &public.end_tree_commitment);
    out
}

pub fn recursive_block_public_statement_digest_v1(public: &RecursiveBlockPublicV1) -> Digest48 {
    let bytes = serialize_recursive_block_public_v1(public);
    fold_digest48(b"hegemon.block-recursion.public-statement.v1", &[&bytes])
}

pub fn header_rec_step_profile_digest_v1(header: &HeaderRecStepV1) -> Digest32 {
    let bytes = serialize_header_rec_step_v1(header).expect("header serialization must succeed");
    fold_digest32(b"hegemon.block-recursion.header-profile.v1", &[&bytes])
}

fn deserialize_recursive_block_public_v1(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<RecursiveBlockPublicV1, BlockRecursionError> {
    let tx_count = read_u32(bytes, cursor)?;
    let tx_statements_commitment = read_fixed::<48>(bytes, cursor)?;
    let verified_leaf_commitment = read_fixed::<48>(bytes, cursor)?;
    let verified_receipt_commitment = read_fixed::<48>(bytes, cursor)?;
    let start_shielded_root = read_fixed::<48>(bytes, cursor)?;
    let end_shielded_root = read_fixed::<48>(bytes, cursor)?;
    let start_kernel_root = read_fixed::<48>(bytes, cursor)?;
    let end_kernel_root = read_fixed::<48>(bytes, cursor)?;
    let nullifier_root = read_fixed::<48>(bytes, cursor)?;
    let da_root = read_fixed::<48>(bytes, cursor)?;
    let start_tree_commitment = read_fixed::<48>(bytes, cursor)?;
    let end_tree_commitment = read_fixed::<48>(bytes, cursor)?;
    Ok(RecursiveBlockPublicV1 {
        tx_count,
        tx_statements_commitment,
        verified_leaf_commitment,
        verified_receipt_commitment,
        start_shielded_root,
        end_shielded_root,
        start_kernel_root,
        end_kernel_root,
        nullifier_root,
        da_root,
        start_tree_commitment,
        end_tree_commitment,
    })
}

pub fn serialize_header_rec_step_v1(
    header: &HeaderRecStepV1,
) -> Result<Vec<u8>, BlockRecursionError> {
    let mut out = Vec::with_capacity(RECURSIVE_BLOCK_HEADER_BYTES_V1);
    put_u32(&mut out, header.artifact_version_rec);
    put_fixed(&mut out, &header.tx_line_digest_v1);
    put_u32(&mut out, header.rec_profile_tag_tau);
    put_u32(&mut out, header.terminal_relation_kind_k);
    put_fixed(&mut out, &header.relation_id_base_a);
    put_fixed(&mut out, &header.relation_id_step_a);
    put_fixed(&mut out, &header.relation_id_step_b);
    put_fixed(&mut out, &header.shape_digest_rec);
    put_fixed(&mut out, &header.vk_digest_base_a);
    put_fixed(&mut out, &header.vk_digest_step_a);
    put_fixed(&mut out, &header.vk_digest_step_b);
    put_fixed(&mut out, &header.proof_encoding_digest_rec);
    put_u32(&mut out, header.proof_bytes_rec);
    put_fixed(&mut out, &header.statement_digest_rec);
    if out.len() != RECURSIVE_BLOCK_HEADER_BYTES_V1 {
        return Err(BlockRecursionError::WidthMismatch {
            what: "header_rec_step_bytes",
            expected: RECURSIVE_BLOCK_HEADER_BYTES_V1,
            actual: out.len(),
        });
    }
    Ok(out)
}

pub fn deserialize_header_rec_step_v1(
    bytes: &[u8],
) -> Result<HeaderRecStepV1, BlockRecursionError> {
    if bytes.len() != RECURSIVE_BLOCK_HEADER_BYTES_V1 {
        return Err(BlockRecursionError::InvalidLength {
            what: "header_rec_step_bytes",
            expected: RECURSIVE_BLOCK_HEADER_BYTES_V1,
            actual: bytes.len(),
        });
    }
    let mut cursor = 0usize;
    let header = HeaderRecStepV1 {
        artifact_version_rec: read_u32(bytes, &mut cursor)?,
        tx_line_digest_v1: read_fixed::<32>(bytes, &mut cursor)?,
        rec_profile_tag_tau: read_u32(bytes, &mut cursor)?,
        terminal_relation_kind_k: read_u32(bytes, &mut cursor)?,
        relation_id_base_a: read_fixed::<32>(bytes, &mut cursor)?,
        relation_id_step_a: read_fixed::<32>(bytes, &mut cursor)?,
        relation_id_step_b: read_fixed::<32>(bytes, &mut cursor)?,
        shape_digest_rec: read_fixed::<32>(bytes, &mut cursor)?,
        vk_digest_base_a: read_fixed::<32>(bytes, &mut cursor)?,
        vk_digest_step_a: read_fixed::<32>(bytes, &mut cursor)?,
        vk_digest_step_b: read_fixed::<32>(bytes, &mut cursor)?,
        proof_encoding_digest_rec: read_fixed::<32>(bytes, &mut cursor)?,
        proof_bytes_rec: read_u32(bytes, &mut cursor)?,
        statement_digest_rec: read_fixed::<32>(bytes, &mut cursor)?,
    };
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    if header.rec_profile_tag_tau != SmallwoodRecursiveProfileTagV1::A.tag()
        && header.rec_profile_tag_tau != SmallwoodRecursiveProfileTagV1::B.tag()
    {
        return Err(BlockRecursionError::InvalidField("rec_profile_tag_tau"));
    }
    match header.terminal_relation_kind_k {
        value if value == SmallwoodRecursiveRelationKindV1::BaseA.tag() => {}
        value if value == SmallwoodRecursiveRelationKindV1::StepA.tag() => {}
        value if value == SmallwoodRecursiveRelationKindV1::StepB.tag() => {}
        _ => {
            return Err(BlockRecursionError::InvalidField(
                "terminal_relation_kind_k",
            ))
        }
    }
    if header.proof_bytes_rec != RECURSIVE_BLOCK_PROOF_BYTES_V1 as u32 {
        return Err(BlockRecursionError::InvalidField("proof_bytes_rec"));
    }
    Ok(header)
}

pub fn serialize_recursive_block_inner_artifact_v1(
    artifact: &RecursiveBlockInnerArtifactV1,
) -> Result<Vec<u8>, BlockRecursionError> {
    if artifact.header.proof_bytes_rec as usize != artifact.proof_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "proof_bytes_rec",
            expected: artifact.header.proof_bytes_rec as usize,
            actual: artifact.proof_bytes.len(),
        });
    }
    let mut out = serialize_header_rec_step_v1(&artifact.header)?;
    out.extend_from_slice(&artifact.proof_bytes);
    Ok(out)
}

pub fn serialize_recursive_block_artifact_rec_v1(
    artifact: &RecursiveBlockArtifactRecV1,
) -> Result<Vec<u8>, BlockRecursionError> {
    serialize_recursive_block_inner_artifact_v1(artifact)
}

pub fn deserialize_recursive_block_inner_artifact_v1(
    bytes: &[u8],
) -> Result<RecursiveBlockInnerArtifactV1, BlockRecursionError> {
    if bytes.len() < RECURSIVE_BLOCK_HEADER_BYTES_V1 {
        return Err(BlockRecursionError::InvalidLength {
            what: "recursive_block_inner_artifact_bytes",
            expected: RECURSIVE_BLOCK_HEADER_BYTES_V1,
            actual: bytes.len(),
        });
    }
    let header = deserialize_header_rec_step_v1(&bytes[..RECURSIVE_BLOCK_HEADER_BYTES_V1])?;
    let proof_end = RECURSIVE_BLOCK_HEADER_BYTES_V1
        .checked_add(header.proof_bytes_rec as usize)
        .ok_or(BlockRecursionError::InvalidField(
            "proof_bytes_rec overflow",
        ))?;
    if proof_end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "recursive_block_inner_proof_bytes",
            expected: header.proof_bytes_rec as usize,
            actual: bytes.len().saturating_sub(RECURSIVE_BLOCK_HEADER_BYTES_V1),
        });
    }
    let proof_bytes = bytes[RECURSIVE_BLOCK_HEADER_BYTES_V1..proof_end].to_vec();
    if proof_end != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - proof_end,
        });
    }
    Ok(RecursiveBlockInnerArtifactV1 {
        header,
        proof_bytes,
    })
}

pub fn deserialize_recursive_block_artifact_rec_v1(
    bytes: &[u8],
) -> Result<RecursiveBlockArtifactRecV1, BlockRecursionError> {
    deserialize_recursive_block_inner_artifact_v1(bytes)
}

pub fn serialize_recursive_block_artifact_v1(
    artifact: &RecursiveBlockArtifactV1,
) -> Result<Vec<u8>, BlockRecursionError> {
    let mut out = serialize_recursive_block_inner_artifact_v1(&artifact.artifact)?;
    out.extend_from_slice(&serialize_recursive_block_public_v1(&artifact.public));
    Ok(out)
}

pub fn deserialize_recursive_block_artifact_v1(
    bytes: &[u8],
) -> Result<RecursiveBlockArtifactV1, BlockRecursionError> {
    let minimum_len = RECURSIVE_BLOCK_HEADER_BYTES_V1 + RECURSIVE_BLOCK_PUBLIC_BYTES_V1;
    if bytes.len() < minimum_len {
        return Err(BlockRecursionError::InvalidLength {
            what: "recursive_block_artifact_bytes",
            expected: minimum_len,
            actual: bytes.len(),
        });
    }
    let header = deserialize_header_rec_step_v1(&bytes[..RECURSIVE_BLOCK_HEADER_BYTES_V1])?;
    let proof_end = RECURSIVE_BLOCK_HEADER_BYTES_V1
        .checked_add(header.proof_bytes_rec as usize)
        .ok_or(BlockRecursionError::InvalidField(
            "proof_bytes_rec overflow",
        ))?;
    let public_end = proof_end
        .checked_add(RECURSIVE_BLOCK_PUBLIC_BYTES_V1)
        .ok_or(BlockRecursionError::InvalidField(
            "recursive artifact length overflow",
        ))?;
    if public_end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "recursive_block_artifact_bytes",
            expected: public_end,
            actual: bytes.len(),
        });
    }
    let proof_bytes = bytes[RECURSIVE_BLOCK_HEADER_BYTES_V1..proof_end].to_vec();
    let mut cursor = proof_end;
    let public = deserialize_recursive_block_public_v1(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(RecursiveBlockArtifactV1 {
        artifact: RecursiveBlockInnerArtifactV1 {
            header,
            proof_bytes,
        },
        public,
    })
}
