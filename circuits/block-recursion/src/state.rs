pub type Digest32 = [u8; 32];
pub type Digest48 = [u8; 48];

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
