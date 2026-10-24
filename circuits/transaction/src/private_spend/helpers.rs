//! Deterministic wallet construction helpers. The circuit independently checks
//! all semantic relations; these helpers grant no authorization.
use super::*;
use crate::smallwood_poseidon2_v8_hash_schedule::{
    SMALLWOOD_POSEIDON2_V8_AUTH_MODE_BIND_DOMAIN as BIND,
    SMALLWOOD_POSEIDON2_V8_AUTH_VALUE_LOCK_DOMAIN as VALUE,
    SMALLWOOD_POSEIDON2_V8_NULLIFIER_DOMAIN as NF,
};
use transaction_core::poseidon2_width16::{
    poseidon2_width16_compress14, poseidon2_width16_sponge, Felt,
};

pub(crate) fn sponge(d: u64, w: &[u64]) -> Result<Digest, crate::TransactionCircuitError> {
    if w.iter().any(|x| *x >= hegemon_field::GOLDILOCKS_MODULUS) {
        return Err(super::error("private spend noncanonical helper input"));
    }
    poseidon2_width16_sponge(
        d,
        &w.iter().copied().map(Felt::from_u64).collect::<Vec<_>>(),
    )
    .map(|a| a.map(|f| f.as_canonical_u64()))
    .map_err(|_| super::error("private spend helper hash"))
}
fn compress(d: u64, a: Digest, b: Digest) -> Digest {
    poseidon2_width16_compress14(d, &a.map(Felt::from_u64), &b.map(Felt::from_u64))
        .map(|f| f.as_canonical_u64())
}
fn key7(k: Key) -> Digest {
    [k[0], k[1], k[2], k[3], k[4], 0, 0]
}
pub fn ordinary_owner(
    recipient_authority: Digest,
) -> Result<Digest, crate::TransactionCircuitError> {
    sponge(ORDINARY_OWNER_DOMAIN, &recipient_authority)
}
pub fn treasury_policy_root(tags: [Digest; 3]) -> Result<Digest, crate::TransactionCircuitError> {
    let mut w = vec![2, 3];
    w.extend(tags.into_iter().flatten());
    w.extend([0; 21]);
    sponge(
        crate::smallwood_poseidon2_v8_types::SMALLWOOD_POSEIDON2_V8_AUTH_POLICY_DOMAIN,
        &w,
    )
}
pub fn treasury_value_owner(t: &TreasuryOpening) -> Result<Digest, crate::TransactionCircuitError> {
    Ok(compress(
        BIND,
        key7(t.policy_key),
        compress(VALUE, treasury_policy_root(t.signer_tags)?, [0; 7]),
    ))
}
pub fn treasury_accumulator_owner(
    t: &TreasuryOpening,
    bits: [u64; 3],
) -> Result<Digest, crate::TransactionCircuitError> {
    if t.intent.len() != INTENT_WORDS {
        return Err(super::error("private spend intent length"));
    }
    let mut w = treasury_policy_root(t.signer_tags)?.to_vec();
    w.extend(sponge(INTENT_DOMAIN, &t.intent)?);
    w.extend([2, 3, bits.iter().sum()]);
    w.extend(bits);
    w.extend([0; 3]);
    Ok(compress(
        BIND,
        key7(t.policy_key),
        sponge(ACCUMULATOR_DOMAIN, &w)?,
    ))
}
pub fn htlc_owner(
    chain: [u8; 32],
    h: &PrivateHtlcOpening,
) -> Result<Digest, crate::TransactionCircuitError> {
    let mut w = vec![];
    types::append_bytes(&mut w, &chain);
    types::append_bytes(&mut w, &h.hashlock);
    w.extend(h.claim_authority);
    w.extend(h.refund_authority);
    w.extend(h.claim_recipient);
    w.extend(h.refund_recipient);
    w.push(h.timeout);
    Ok(compress(
        if h.release_secret == 0 {
            HTLC_OWNER_DOMAIN
        } else if h.release_secret == 1 {
            HTLC_RELEASE_OWNER_DOMAIN
        } else {
            return Err(super::error("HTLC release flag"));
        },
        key7(h.nullifier_key),
        sponge(HTLC_POLICY_DOMAIN, &w)?,
    ))
}
pub fn real_nullifier(
    key: Key,
    position: u32,
    note: Note,
) -> Result<Digest, crate::TransactionCircuitError> {
    let mut w = key7(key).to_vec();
    w.push(position as u64);
    w.extend(note.rho);
    sponge(NF, &w)
}
pub fn dummy_nullifier(
    chain: [u8; 32],
    secret: Key,
) -> Result<Digest, crate::TransactionCircuitError> {
    let mut w = vec![];
    types::append_bytes(&mut w, &chain);
    w.extend(secret);
    sponge(DUMMY_NULLIFIER_DOMAIN, &w)
}
pub fn note_commitment(note: Note) -> Result<Digest, crate::TransactionCircuitError> {
    sponge(
        transaction_core::constants::NOTE_DOMAIN_TAG,
        &types::note_words(note),
    )
}

/// Chain/asset/descriptor-bound policy owner; branches share its nullifier key.
pub fn policy_owner(
    chain: [u8; 32],
    asset_id: u64,
    policy: &BoundedPolicy,
) -> Result<Digest, crate::TransactionCircuitError> {
    policy
        .owner(chain, asset_id)
        .map_err(|_| super::error("invalid bounded policy"))
}
