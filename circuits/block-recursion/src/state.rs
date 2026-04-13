pub type Digest32 = [u8; 32];
pub type Digest48 = [u8; 48];

pub fn fold_digest32(tag: &[u8], chunks: &[&[u8]]) -> Digest32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.block-recursion.digest32.v1");
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(chunks.len() as u64).to_le_bytes());
    for chunk in chunks {
        hasher.update(&(chunk.len() as u64).to_le_bytes());
        hasher.update(chunk);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

pub fn fold_digest48(tag: &[u8], chunks: &[&[u8]]) -> Digest48 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.block-recursion.digest48.v1");
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(chunks.len() as u64).to_le_bytes());
    for chunk in chunks {
        hasher.update(&(chunk.len() as u64).to_le_bytes());
        hasher.update(chunk);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(digest.as_bytes());
    out[32..].copy_from_slice(&blake3::derive_key(
        "hegemon.block-recursion.digest48.tail.v1",
        digest.as_bytes(),
    )[..16]);
    out
}
