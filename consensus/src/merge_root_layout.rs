use block_circuit::CommitmentBlockProver;
use crypto::hashes::blake3_384;

pub fn merge_root_leaf_fan_in_from_env() -> usize {
    std::env::var("HEGEMON_AGG_LEAF_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1)
}

pub fn merge_root_arity_from_env() -> u16 {
    std::env::var("HEGEMON_MERGE_ARITY")
        .ok()
        .or_else(|| std::env::var("HEGEMON_AGG_MERGE_FANIN").ok())
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(2)
        .max(2)
}

pub fn merge_root_tree_levels_for_tx_count(tx_count: usize) -> u16 {
    if tx_count <= 1 {
        return 1;
    }
    let mut levels = 1u16;
    let mut width = tx_count.div_ceil(merge_root_leaf_fan_in_from_env());
    while width > 1 {
        width = width.div_ceil(merge_root_arity_from_env() as usize);
        levels = levels.saturating_add(1);
    }
    levels
}

pub fn merge_root_leaf_manifest_commitment(
    statement_hashes: &[[u8; 48]],
) -> Result<[u8; 48], String> {
    let leaf_fan_in = merge_root_leaf_fan_in_from_env();
    let mut manifest_material = Vec::new();
    manifest_material.extend_from_slice(b"agg-leaf-manifest-v1");
    manifest_material.extend_from_slice(&(leaf_fan_in as u16).to_le_bytes());
    manifest_material.extend_from_slice(&(statement_hashes.len() as u32).to_le_bytes());
    for (leaf_index, chunk) in statement_hashes.chunks(leaf_fan_in).enumerate() {
        let leaf_commitment = CommitmentBlockProver::commitment_from_statement_hashes(chunk)
            .map_err(|err| format!("leaf manifest statement commitment failed: {err}"))?;
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(b"agg-leaf-v1");
        descriptor.extend_from_slice(&(leaf_index as u32).to_le_bytes());
        descriptor.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        descriptor.extend_from_slice(&leaf_commitment);
        manifest_material.extend_from_slice(&blake3_384(&descriptor));
    }
    Ok(blake3_384(&manifest_material))
}
