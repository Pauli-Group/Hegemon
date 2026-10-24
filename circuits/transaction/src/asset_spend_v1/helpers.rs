//! Deterministic fixture and wallet helpers. These do not authorize registry state.
use super::*;
use transaction_core::poseidon2_width16::{
    poseidon2_width16_compress14, poseidon2_width16_sponge, Felt,
};

pub(crate) fn hash(domain: u64, words: &[u64]) -> Result<Digest, crate::TransactionCircuitError> {
    if words
        .iter()
        .any(|word| *word >= hegemon_field::GOLDILOCKS_MODULUS)
    {
        return Err(error("asset noncanonical helper input"));
    }
    poseidon2_width16_sponge(
        domain,
        &words
            .iter()
            .copied()
            .map(Felt::from_u64)
            .collect::<Vec<_>>(),
    )
    .map(|digest| digest.map(|word| word.as_canonical_u64()))
    .map_err(|_| error("asset helper hash shape"))
}
pub fn credential_leaf(
    asset_id: u32,
    policy_version: u32,
    recipient_key: [u64; 4],
    authority: Digest,
    expires_at: u64,
) -> Result<Digest, crate::TransactionCircuitError> {
    if asset_id == 0 || expires_at >= 1 << 48 {
        return Err(error("asset credential scalar shape"));
    }
    let mut words = vec![u64::from(asset_id), u64::from(policy_version)];
    words.extend(recipient_key);
    words.extend(authority);
    words.push(expires_at);
    hash(CREDENTIAL_LEAF_DOMAIN, &words)
}
pub fn credential_root(
    leaf: Digest,
    index: u32,
    siblings: &[Digest],
) -> Result<Digest, crate::TransactionCircuitError> {
    if !matches!(siblings.len(), 4 | 8 | 16)
        || u64::from(index) >= 1u64 << siblings.len()
        || leaf
            .iter()
            .chain(siblings.iter().flatten())
            .any(|word| *word >= hegemon_field::GOLDILOCKS_MODULUS)
    {
        return Err(error("asset credential path shape"));
    }
    let mut root = leaf;
    for (level, sibling) in siblings.iter().copied().enumerate() {
        let (left, right) = if index >> level & 1 == 0 {
            (root, sibling)
        } else {
            (sibling, root)
        };
        root = poseidon2_width16_compress14(
            CREDENTIAL_NODE_DOMAIN + level as u64,
            &left.map(Felt::from_u64),
            &right.map(Felt::from_u64),
        )
        .map(|word| word.as_canonical_u64());
    }
    Ok(root)
}
pub fn credential_node(
    level: usize,
    left: Digest,
    right: Digest,
) -> Result<Digest, crate::TransactionCircuitError> {
    if level >= 16
        || left
            .iter()
            .chain(right.iter())
            .any(|word| *word >= hegemon_field::GOLDILOCKS_MODULUS)
    {
        return Err(error("asset credential node shape"));
    }
    Ok(poseidon2_width16_compress14(
        CREDENTIAL_NODE_DOMAIN + level as u64,
        &left.map(Felt::from_u64),
        &right.map(Felt::from_u64),
    )
    .map(|word| word.as_canonical_u64()))
}
/// Entry0 is the canonical absent credential leaf. Entry h is the empty subtree at height h.
pub fn credential_default_nodes(depth: u8) -> Result<Vec<Digest>, crate::TransactionCircuitError> {
    if !matches!(depth, 4 | 8 | 16) {
        return Err(error("asset credential default depth"));
    }
    let mut nodes = vec![[0; 7]];
    for level in 0..usize::from(depth) {
        nodes.push(credential_node(level, nodes[level], nodes[level])?);
    }
    Ok(nodes)
}
pub fn dummy_nullifier(
    chain_id: [u8; 32],
    secret: [u64; 5],
) -> Result<Digest, crate::TransactionCircuitError> {
    let mut words = Vec::new();
    types::append_bytes(&mut words, &chain_id);
    words.extend(secret);
    hash(DUMMY_NULLIFIER_DOMAIN, &words)
}
pub fn issuer_commitment(
    asset_id: u32,
    policy_version: u32,
    secret: Digest,
) -> Result<Digest, crate::TransactionCircuitError> {
    if asset_id == 0
        || secret == [0; 7]
        || secret
            .iter()
            .any(|word| *word >= hegemon_field::GOLDILOCKS_MODULUS)
    {
        return Err(error("asset issuer secret shape"));
    }
    Ok(
        transaction_core::stablecoin_poseidon2_v8::stablecoin_poseidon2_v8_issuer_commitment(
            asset_id,
            policy_version,
            &secret.map(Felt::from_u64),
        )
        .map(|word| word.as_canonical_u64()),
    )
}
