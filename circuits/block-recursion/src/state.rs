pub type Digest32 = [u8; 32];
pub type Digest48 = [u8; 48];

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
