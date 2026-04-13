use crate::BlockRecursionError;

pub type Digest32 = [u8; 32];
pub type Digest48 = [u8; 48];

const RECURSIVE_STATE_MAGIC: [u8; 8] = *b"BRST0001";
const RECURSIVE_STATE_VERSION_V1: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveStateV1 {
    pub step_index: u32,
    pub tx_count: u32,
    pub statement_commitment: Digest48,
    pub leaf_commitment: Digest48,
    pub receipt_commitment: Digest48,
    pub frontier_commitment: Digest32,
    pub history_commitment: Digest32,
    pub nullifier_root: Digest32,
    pub da_root: Digest32,
}

impl RecursiveStateV1 {
    pub fn genesis(tx_count: u32) -> Self {
        Self {
            step_index: 0,
            tx_count,
            statement_commitment: [0; 48],
            leaf_commitment: [0; 48],
            receipt_commitment: [0; 48],
            frontier_commitment: [0; 32],
            history_commitment: [0; 32],
            nullifier_root: [0; 32],
            da_root: [0; 32],
        }
    }

    pub fn commit(&self) -> Digest32 {
        fold_digest32(
            b"recursive_state_v1",
            &[
                &self.step_index.to_le_bytes(),
                &self.tx_count.to_le_bytes(),
                &self.statement_commitment,
                &self.leaf_commitment,
                &self.receipt_commitment,
                &self.frontier_commitment,
                &self.history_commitment,
                &self.nullifier_root,
                &self.da_root,
            ],
        )
    }
}

pub fn fold_digest32(tag: &[u8], chunks: &[&[u8]]) -> Digest32 {
    let mut out = [0u8; 32];
    for (i, byte) in tag.iter().enumerate() {
        out[i % 32] ^= byte.wrapping_add(i as u8);
    }
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        for (byte_index, byte) in chunk.iter().enumerate() {
            let slot = (chunk_index + byte_index) % 32;
            let rot = ((chunk_index + byte_index) % 7) as u32;
            out[slot] = out[slot].wrapping_add(byte.rotate_left(rot));
            out[slot] ^= (chunk_index as u8).wrapping_mul(17);
        }
    }
    out
}

pub fn fold_digest48(tag: &[u8], chunks: &[&[u8]]) -> Digest48 {
    let mut out = [0u8; 48];
    for (i, byte) in tag.iter().enumerate() {
        out[i % 48] ^= byte.wrapping_add((i as u8).wrapping_mul(3));
    }
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        for (byte_index, byte) in chunk.iter().enumerate() {
            let slot = (chunk_index * 7 + byte_index) % 48;
            let rot = ((chunk_index + byte_index) % 5) as u32;
            out[slot] = out[slot].wrapping_add(byte.rotate_left(rot));
            out[slot] ^= (byte_index as u8).wrapping_mul(11);
        }
    }
    out
}

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
            what: "recursive state u16",
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
            what: "recursive state u32",
            expected: 4,
            actual: bytes.len().saturating_sub(*cursor),
        });
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(u32::from_le_bytes(buf))
}

fn read_fixed<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], BlockRecursionError> {
    let end = cursor.saturating_add(N);
    if end > bytes.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "recursive state fixed bytes",
            expected: N,
            actual: bytes.len().saturating_sub(*cursor),
        });
    }
    let mut buf = [0u8; N];
    buf.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(buf)
}

pub fn recursive_state_serializer_digest_v1() -> Digest32 {
    fold_digest32(
        b"block_recursive_state_serializer_v1",
        &[
            &RECURSIVE_STATE_MAGIC,
            &RECURSIVE_STATE_VERSION_V1.to_le_bytes(),
            b"step_index:u32",
            b"tx_count:u32",
            b"statement_commitment:48",
            b"leaf_commitment:48",
            b"receipt_commitment:48",
            b"frontier_commitment:32",
            b"history_commitment:32",
            b"nullifier_root:32",
            b"da_root:32",
        ],
    )
}

pub fn serialize_recursive_state_v1(
    state: &RecursiveStateV1,
) -> Result<Vec<u8>, BlockRecursionError> {
    let mut out = Vec::with_capacity(8 + 2 + 4 + 4 + 48 * 3 + 32 * 4);
    out.extend_from_slice(&RECURSIVE_STATE_MAGIC);
    put_u16(&mut out, RECURSIVE_STATE_VERSION_V1);
    put_u32(&mut out, state.step_index);
    put_u32(&mut out, state.tx_count);
    put_fixed(&mut out, &state.statement_commitment);
    put_fixed(&mut out, &state.leaf_commitment);
    put_fixed(&mut out, &state.receipt_commitment);
    put_fixed(&mut out, &state.frontier_commitment);
    put_fixed(&mut out, &state.history_commitment);
    put_fixed(&mut out, &state.nullifier_root);
    put_fixed(&mut out, &state.da_root);
    Ok(out)
}

pub fn deserialize_recursive_state_v1(
    bytes: &[u8],
) -> Result<RecursiveStateV1, BlockRecursionError> {
    let mut cursor = 0usize;
    let magic = read_fixed::<8>(bytes, &mut cursor)?;
    if magic != RECURSIVE_STATE_MAGIC {
        return Err(BlockRecursionError::InvalidField(
            "recursive state magic",
        ));
    }
    let version = read_u16(bytes, &mut cursor)?;
    if version != RECURSIVE_STATE_VERSION_V1 {
        return Err(BlockRecursionError::InvalidVersion {
            what: "recursive state",
            version,
        });
    }
    let state = RecursiveStateV1 {
        step_index: read_u32(bytes, &mut cursor)?,
        tx_count: read_u32(bytes, &mut cursor)?,
        statement_commitment: read_fixed::<48>(bytes, &mut cursor)?,
        leaf_commitment: read_fixed::<48>(bytes, &mut cursor)?,
        receipt_commitment: read_fixed::<48>(bytes, &mut cursor)?,
        frontier_commitment: read_fixed::<32>(bytes, &mut cursor)?,
        history_commitment: read_fixed::<32>(bytes, &mut cursor)?,
        nullifier_root: read_fixed::<32>(bytes, &mut cursor)?,
        da_root: read_fixed::<32>(bytes, &mut cursor)?,
    };
    if cursor != bytes.len() {
        return Err(BlockRecursionError::TrailingBytes {
            remaining: bytes.len() - cursor,
        });
    }
    Ok(state)
}
