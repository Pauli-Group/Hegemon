use crate::{
    fold_digest32, fold_digest48, public_replay::RecursiveBlockPublicV1, BlockRecursionError,
    Digest32, Digest48,
};
use superneo_backend_lattice::RecursiveLatticeDeciderProof;

pub type CanonicalDeciderTranscript = Vec<u8>;

pub const RECURSIVE_BLOCK_ARTIFACT_VERSION_V1: u16 = 1;
pub const RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1: u16 = 1;
pub const BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderDecStepV1 {
    pub version: u16,
    pub proof_kind: u16,
    pub header_bytes: u32,
    pub artifact_bytes: u32,
    pub relation_id: Digest32,
    pub shape_digest: Digest32,
    pub statement_digest: Digest48,
    pub decider_profile_digest: Digest32,
    pub accumulator_serializer_digest: Digest32,
    pub decider_serializer_digest: Digest32,
    pub transcript_digest: Digest32,
    pub accumulator_bytes: u32,
    pub decider_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockAccumulationTranscriptV1 {
    pub version: u16,
    pub step_count: u32,
    pub transcript_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockArtifactV1 {
    pub header: HeaderDecStepV1,
    pub public: RecursiveBlockPublicV1,
    pub accumulator_bytes: Vec<u8>,
    pub decider_bytes: Vec<u8>,
}

const HEADER_MAGIC: [u8; 8] = *b"HBRC0001";
const ARTIFACT_MAGIC: [u8; 8] = *b"RBRC0001";
const TRANSCRIPT_MAGIC: [u8; 8] = *b"TBR1T001";

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_fixed<const N: usize>(out: &mut Vec<u8>, value: &[u8; N]) {
    out.extend_from_slice(value);
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, BlockRecursionError> {
    let end = cursor.saturating_add(2);
    if end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "u16",
            expected: 2,
            actual: bytes.len().saturating_sub(*cursor),
        });
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(u16::from_le_bytes(buf))
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

fn parse_header_dec_step_v1_prefix(
    bytes: &[u8],
) -> Result<(HeaderDecStepV1, usize), BlockRecursionError> {
    let mut cursor = 0usize;
    let magic = read_fixed::<8>(bytes, &mut cursor)?;
    if magic != HEADER_MAGIC {
        return Err(BlockRecursionError::InvalidField("header magic"));
    }
    let version = read_u16(bytes, &mut cursor)?;
    let proof_kind = read_u16(bytes, &mut cursor)?;
    let header_bytes = read_u32(bytes, &mut cursor)?;
    let artifact_bytes = read_u32(bytes, &mut cursor)?;
    let relation_id = read_fixed::<32>(bytes, &mut cursor)?;
    let shape_digest = read_fixed::<32>(bytes, &mut cursor)?;
    let statement_digest = read_fixed::<48>(bytes, &mut cursor)?;
    let decider_profile_digest = read_fixed::<32>(bytes, &mut cursor)?;
    let accumulator_serializer_digest = read_fixed::<32>(bytes, &mut cursor)?;
    let decider_serializer_digest = read_fixed::<32>(bytes, &mut cursor)?;
    let transcript_digest = read_fixed::<32>(bytes, &mut cursor)?;
    let accumulator_bytes = read_u32(bytes, &mut cursor)?;
    let decider_bytes = read_u32(bytes, &mut cursor)?;
    Ok((
        HeaderDecStepV1 {
            version,
            proof_kind,
            header_bytes,
            artifact_bytes,
            relation_id,
            shape_digest,
            statement_digest,
            decider_profile_digest,
            accumulator_serializer_digest,
            decider_serializer_digest,
            transcript_digest,
            accumulator_bytes,
            decider_bytes,
        },
        cursor,
    ))
}

pub fn serialize_header_dec_step_v1(
    header: &HeaderDecStepV1,
) -> Result<Vec<u8>, BlockRecursionError> {
    let mut out = Vec::with_capacity(8 + 2 + 2 + 4 + 4 + 32 + 32 + 48 + 32 + 32 + 32 + 32 + 4 + 4);
    out.extend_from_slice(&HEADER_MAGIC);
    put_u16(&mut out, header.version);
    put_u16(&mut out, header.proof_kind);
    put_u32(&mut out, header.header_bytes);
    put_u32(&mut out, header.artifact_bytes);
    put_fixed(&mut out, &header.relation_id);
    put_fixed(&mut out, &header.shape_digest);
    put_fixed(&mut out, &header.statement_digest);
    put_fixed(&mut out, &header.decider_profile_digest);
    put_fixed(&mut out, &header.accumulator_serializer_digest);
    put_fixed(&mut out, &header.decider_serializer_digest);
    put_fixed(&mut out, &header.transcript_digest);
    put_u32(&mut out, header.accumulator_bytes);
    put_u32(&mut out, header.decider_bytes);
    Ok(out)
}

pub fn deserialize_header_dec_step_v1(
    bytes: &[u8],
) -> Result<HeaderDecStepV1, BlockRecursionError> {
    let (header, cursor) = parse_header_dec_step_v1_prefix(bytes)?;
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(header)
}

pub fn serialize_block_accumulation_transcript_v1(
    transcript: &BlockAccumulationTranscriptV1,
) -> Result<CanonicalDeciderTranscript, BlockRecursionError> {
    let mut out = Vec::with_capacity(8 + 2 + 4 + 4 + transcript.transcript_bytes.len());
    out.extend_from_slice(&TRANSCRIPT_MAGIC);
    put_u16(&mut out, transcript.version);
    put_u32(&mut out, transcript.step_count);
    put_u32(&mut out, transcript.transcript_bytes.len() as u32);
    out.extend_from_slice(&transcript.transcript_bytes);
    Ok(out)
}

pub fn deserialize_block_accumulation_transcript_v1(
    bytes: &[u8],
) -> Result<BlockAccumulationTranscriptV1, BlockRecursionError> {
    let mut cursor = 0usize;
    let magic = read_fixed::<8>(bytes, &mut cursor)?;
    if magic != TRANSCRIPT_MAGIC {
        return Err(BlockRecursionError::InvalidField("transcript magic"));
    }
    let version = read_u16(bytes, &mut cursor)?;
    let step_count = read_u32(bytes, &mut cursor)?;
    let transcript_len = read_u32(bytes, &mut cursor)? as usize;
    let end = cursor.saturating_add(transcript_len);
    if end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "transcript_bytes",
            expected: transcript_len,
            actual: bytes.len().saturating_sub(cursor),
        });
    }
    let transcript_bytes = bytes[cursor..end].to_vec();
    cursor = end;
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(BlockAccumulationTranscriptV1 {
        version,
        step_count,
        transcript_bytes,
    })
}

pub fn block_accumulation_transcript_serializer_digest_v1() -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.accumulation-transcript-serializer.v1",
        &[
            &TRANSCRIPT_MAGIC,
            &BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1.to_le_bytes(),
            b"step_count:u32",
            b"transcript_bytes_len:u32",
            b"transcript_bytes:opaque",
        ],
    )
}

pub fn block_accumulation_transcript_digest_v1(
    transcript: &BlockAccumulationTranscriptV1,
) -> Result<Digest32, BlockRecursionError> {
    let bytes = serialize_block_accumulation_transcript_v1(transcript)?;
    Ok(fold_digest32(
        b"hegemon.block-recursion.accumulation-transcript-digest.v1",
        &[&bytes],
    ))
}

pub fn recursive_lcccs_serializer_digest_v1() -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.lcccs-serializer.v1",
        &[b"superneo_core::serialize_lcccs_instance"],
    )
}

pub fn recursive_decider_serializer_digest_v1() -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.decider-serializer.v1",
        &[
            b"superneo-backend-lattice::RecursiveLatticeDeciderProof",
            &(RecursiveLatticeDeciderProof::CANONICAL_BYTE_SIZE as u32).to_le_bytes(),
        ],
    )
}

pub fn decider_profile_digest_v1(profile_bytes: &[u8]) -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.decider-profile.v1",
        &[profile_bytes],
    )
}

pub fn compress_transcript_digest_v1(transcript_digest: &Digest48) -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.transcript-digest.v1",
        &[transcript_digest],
    )
}

fn serialize_recursive_block_public_v1(public: &RecursiveBlockPublicV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + (48 * 9) + (32 * 2));
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
    put_fixed(&mut out, &public.frontier_commitment);
    put_fixed(&mut out, &public.history_commitment);
    out
}

pub fn recursive_block_public_statement_digest_v1(public: &RecursiveBlockPublicV1) -> Digest48 {
    let bytes = serialize_recursive_block_public_v1(public);
    fold_digest48(b"hegemon.block-recursion.public-statement.v1", &[&bytes])
}

pub fn header_dec_step_profile_digest_v1(header: &HeaderDecStepV1) -> Digest32 {
    fold_digest32(
        b"hegemon.block-recursion.header-profile.v1",
        &[
            &header.version.to_le_bytes(),
            &header.proof_kind.to_le_bytes(),
            &header.header_bytes.to_le_bytes(),
            &header.artifact_bytes.to_le_bytes(),
            &header.relation_id,
            &header.shape_digest,
            &header.statement_digest,
            &header.accumulator_serializer_digest,
            &header.decider_serializer_digest,
            &header.transcript_digest,
            &header.accumulator_bytes.to_le_bytes(),
            &header.decider_bytes.to_le_bytes(),
        ],
    )
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
    let frontier_commitment = read_fixed::<32>(bytes, cursor)?;
    let history_commitment = read_fixed::<32>(bytes, cursor)?;
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
        frontier_commitment,
        history_commitment,
    })
}

pub fn serialize_recursive_block_artifact_v1(
    artifact: &RecursiveBlockArtifactV1,
) -> Result<Vec<u8>, BlockRecursionError> {
    let public_bytes = serialize_recursive_block_public_v1(&artifact.public);
    let header_bytes_preview = serialize_header_dec_step_v1(&HeaderDecStepV1 {
        header_bytes: 0,
        artifact_bytes: 0,
        ..artifact.header.clone()
    })?;
    let header_len = header_bytes_preview.len() as u32;
    let artifact_len = (ARTIFACT_MAGIC.len()
        + header_bytes_preview.len()
        + public_bytes.len()
        + 4
        + artifact.accumulator_bytes.len()
        + 4
        + artifact.decider_bytes.len()) as u32;
    let header = HeaderDecStepV1 {
        header_bytes: header_len,
        artifact_bytes: artifact_len,
        ..artifact.header.clone()
    };
    let header_bytes = serialize_header_dec_step_v1(&header)?;
    let mut out = Vec::with_capacity(artifact_len as usize);
    out.extend_from_slice(&ARTIFACT_MAGIC);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&public_bytes);
    put_u32(&mut out, artifact.accumulator_bytes.len() as u32);
    out.extend_from_slice(&artifact.accumulator_bytes);
    put_u32(&mut out, artifact.decider_bytes.len() as u32);
    out.extend_from_slice(&artifact.decider_bytes);
    Ok(out)
}

pub fn deserialize_recursive_block_artifact_v1(
    bytes: &[u8],
) -> Result<RecursiveBlockArtifactV1, BlockRecursionError> {
    let mut cursor = 0usize;
    let magic = read_fixed::<8>(bytes, &mut cursor)?;
    if magic != ARTIFACT_MAGIC {
        return Err(BlockRecursionError::InvalidField("artifact magic"));
    }
    let header_start = cursor;
    let (header, header_cursor) = parse_header_dec_step_v1_prefix(&bytes[cursor..])?;
    let header_len = header.header_bytes as usize;
    if header_len == 0 {
        return Err(BlockRecursionError::InvalidField("header_bytes"));
    }
    let header_end = header_start.saturating_add(header_len);
    if header_end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "header bytes",
            expected: header_len,
            actual: bytes.len().saturating_sub(header_start),
        });
    }
    if header_cursor != header_len {
        return Err(BlockRecursionError::WidthMismatch {
            what: "header_bytes",
            expected: header_len,
            actual: header_cursor,
        });
    }
    cursor = header_end;
    let public = deserialize_recursive_block_public_v1(bytes, &mut cursor)?;
    let accumulator_len = read_u32(bytes, &mut cursor)? as usize;
    let acc_end = cursor.saturating_add(accumulator_len);
    if acc_end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "accumulator_bytes",
            expected: accumulator_len,
            actual: bytes.len().saturating_sub(cursor),
        });
    }
    let accumulator_bytes = bytes[cursor..acc_end].to_vec();
    cursor = acc_end;
    let decider_len = read_u32(bytes, &mut cursor)? as usize;
    let dec_end = cursor.saturating_add(decider_len);
    if dec_end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "decider_bytes",
            expected: decider_len,
            actual: bytes.len().saturating_sub(cursor),
        });
    }
    let decider_bytes = bytes[cursor..dec_end].to_vec();
    cursor = dec_end;
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    if header.accumulator_bytes as usize != accumulator_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "accumulator_bytes",
            expected: header.accumulator_bytes as usize,
            actual: accumulator_bytes.len(),
        });
    }
    if header.decider_bytes as usize != decider_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "decider_bytes",
            expected: header.decider_bytes as usize,
            actual: decider_bytes.len(),
        });
    }
    if header.artifact_bytes as usize != bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "artifact_bytes",
            expected: header.artifact_bytes as usize,
            actual: bytes.len(),
        });
    }
    Ok(RecursiveBlockArtifactV1 {
        header,
        public,
        accumulator_bytes,
        decider_bytes,
    })
}
