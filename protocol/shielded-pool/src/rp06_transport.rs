//! Independent, bounded RP06 candidate carrier. Parsing is never release authority.
//!
//! Historical V8 carriers are not adapted. This grammar carries the exact
//! 1192-byte source preamble, canonical raw ciphertexts and one unchanged SMZB
//! proof. Every decoder borrows the caller's full self-contained bytes.

use alloc::vec::Vec;
use core::fmt;
use protocol_versioning::launch_candidate::{
    LAUNCH_SHIELDED_FAMILY_ID, RP06_ACTION_ID, RP06_DOMAIN_SET, RP06_PROFILE_ID,
    RP06_VERSION_BINDING,
};
use transaction_core::hashing_pq::ciphertext_hash_bytes;

pub const RP06_NATIVE_LEAF_MAGIC: [u8; 8] = *b"HGR6TX01";
pub const RP06_ENVELOPE_MAGIC: [u8; 8] = *b"HGR6LC01";
pub const RP06_PREAMBLE_MAGIC: [u8; 8] = *b"HGR6PB01";
pub const RP06_PROGRAM_MAGIC: [u8; 8] = *b"HGV8RP06";
pub const RP06_INNER_PROOF_MAGIC: [u8; 4] = *b"SMZB";
pub const RP06_PREAMBLE_BYTES: usize = 1192;
pub const RP06_PUBLIC_WORDS: usize = 128;
pub const RP06_INTENT_LIMBS: usize = 7;
pub const RP06_NATIVE_LEAF_HEADER_BYTES: usize = 20;
pub const RP06_ENVELOPE_HEADER_BYTES: usize = 32;
pub const RP06_CIPHERTEXT_BYTES: usize = crate::types::MAX_CIPHERTEXT_BYTES;
/// Literal strict SMZB q38 encoder/decoder ceiling; exact-source projection must match.
pub const RP06_CANDIDATE_MAX_PROOF_BYTES: usize = 164_113;
pub const RP06_CANDIDATE_MAX_NATIVE_LEAF_BYTES: usize = RP06_NATIVE_LEAF_HEADER_BYTES
    + RP06_PREAMBLE_BYTES
    + 2 * RP06_CIPHERTEXT_BYTES
    + RP06_CANDIDATE_MAX_PROOF_BYTES;
pub const RP06_CANDIDATE_MAX_ENVELOPE_BYTES: usize =
    RP06_ENVELOPE_HEADER_BYTES + RP06_CANDIDATE_MAX_NATIVE_LEAF_BYTES;
pub const RP06_CANDIDATE_MAX_INLINE_BYTES: usize = 4 + RP06_CANDIDATE_MAX_ENVELOPE_BYTES;
const FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;
const PUBLIC_OFFSET: usize = 112;
const INTENT_OFFSET: usize = 1136;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rp06ExpectedContext {
    chain_id: [u8; 32],
    relation_digest: [u8; 48],
}
impl Rp06ExpectedContext {
    pub fn new(chain_id: [u8; 32], relation_digest: [u8; 48]) -> Result<Self, Rp06TransportError> {
        if chain_id == [0; 32] || relation_digest == [0; 48] {
            return Err(Rp06TransportError::ZeroContext);
        }
        Ok(Self {
            chain_id,
            relation_digest,
        })
    }
    pub const fn chain_id(self) -> [u8; 32] {
        self.chain_id
    }
    pub const fn relation_digest(self) -> [u8; 48] {
        self.relation_digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedRp06NativeLeaf<'a> {
    raw: &'a [u8],
    preamble: &'a [u8; RP06_PREAMBLE_BYTES],
    ciphertexts: [Option<&'a [u8; RP06_CIPHERTEXT_BYTES]>; 2],
    proof: &'a [u8],
}
impl<'a> DecodedRp06NativeLeaf<'a> {
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub const fn preamble(self) -> &'a [u8; RP06_PREAMBLE_BYTES] {
        self.preamble
    }
    pub const fn proof(self) -> &'a [u8] {
        self.proof
    }
    pub fn chain_id(self) -> [u8; 32] {
        self.preamble[80..112].try_into().expect("fixed chain id")
    }
    pub fn relation_digest(self) -> [u8; 48] {
        self.preamble[32..80].try_into().expect("fixed digest")
    }
    pub fn public_word(self, index: usize) -> Option<u64> {
        (index < RP06_PUBLIC_WORDS).then(|| word(self.preamble, PUBLIC_OFFSET + index * 8))
    }
    pub fn intent_limb(self, index: usize) -> Option<u64> {
        (index < RP06_INTENT_LIMBS).then(|| word(self.preamble, INTENT_OFFSET + index * 8))
    }
    pub const fn ciphertext(self, slot: usize) -> Option<&'a [u8; RP06_CIPHERTEXT_BYTES]> {
        if slot < 2 {
            self.ciphertexts[slot]
        } else {
            None
        }
    }
    pub fn public_words(self) -> [u64; RP06_PUBLIC_WORDS] {
        core::array::from_fn(|i| self.public_word(i).expect("fixed statement"))
    }
    fn ensure_context(self, expected: Rp06ExpectedContext) -> Result<Self, Rp06TransportError> {
        if self.chain_id() != expected.chain_id
            || self.relation_digest() != expected.relation_digest
        {
            return Err(Rp06TransportError::ContextMismatch);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedRp06Envelope<'a> {
    raw: &'a [u8],
    leaf: DecodedRp06NativeLeaf<'a>,
}
impl<'a> DecodedRp06Envelope<'a> {
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub const fn native_leaf(self) -> DecodedRp06NativeLeaf<'a> {
        self.leaf
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedRp06InlineArgs<'a> {
    raw: &'a [u8],
    envelope: DecodedRp06Envelope<'a>,
}
impl<'a> DecodedRp06InlineArgs<'a> {
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }
    pub const fn envelope(self) -> DecodedRp06Envelope<'a> {
        self.envelope
    }
    pub const fn native_leaf(self) -> DecodedRp06NativeLeaf<'a> {
        self.envelope.leaf
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rp06TransportError {
    ZeroContext,
    ContextMismatch,
    InvalidIdentity,
    InvalidLength,
    ResourceLimit,
    NonCanonicalWord(usize),
    NonBooleanFlag(usize),
    NetworkEmbeddingMismatch,
    CiphertextPresence(usize),
    CiphertextFormat(usize),
    CiphertextHash(usize),
    NonCanonicalCompact,
    AllocationFailed,
}
impl fmt::Display for Rp06TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for Rp06TransportError {}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("checked header"),
    )
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked header"),
    )
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("checked words"))
}
fn validate_identity(bytes: &[u8], offset: usize) -> Result<(), Rp06TransportError> {
    if u16_at(bytes, offset) != 1
        || u16_at(bytes, offset + 2) != RP06_VERSION_BINDING.circuit
        || u16_at(bytes, offset + 4) != RP06_VERSION_BINDING.crypto
        || u16_at(bytes, offset + 6) != LAUNCH_SHIELDED_FAMILY_ID
        || u16_at(bytes, offset + 8) != RP06_ACTION_ID
        || u16_at(bytes, offset + 10) != RP06_DOMAIN_SET
        || bytes[offset + 12] != 2
        || bytes[offset + 13] != RP06_PROFILE_ID
        || bytes[offset + 14] != 1
        || bytes[offset + 15] != 0
    {
        return Err(Rp06TransportError::InvalidIdentity);
    }
    Ok(())
}
fn validate_preamble(bytes: &[u8; RP06_PREAMBLE_BYTES]) -> Result<[bool; 2], Rp06TransportError> {
    if bytes[..8] != RP06_PREAMBLE_MAGIC || bytes[8..16] != RP06_PROGRAM_MAGIC {
        return Err(Rp06TransportError::InvalidIdentity);
    }
    validate_identity(bytes, 16)?;
    if bytes[32..80] == [0; 48] || bytes[80..112] == [0; 32] {
        return Err(Rp06TransportError::ZeroContext);
    }
    for i in 0..(RP06_PUBLIC_WORDS + RP06_INTENT_LIMBS) {
        if word(bytes, PUBLIC_OFFSET + i * 8) >= FIELD_MODULUS {
            return Err(Rp06TransportError::NonCanonicalWord(i));
        }
    }
    for i in 0..8 {
        if word(bytes, PUBLIC_OFFSET + (120 + i) * 8) != u64::from(u32_at(bytes, 80 + i * 4)) {
            return Err(Rp06TransportError::NetworkEmbeddingMismatch);
        }
    }
    let mut active = [false; 2];
    for (i, flag) in active.iter_mut().enumerate() {
        *flag = match word(bytes, PUBLIC_OFFSET + (2 + i) * 8) {
            0 => false,
            1 => true,
            _ => return Err(Rp06TransportError::NonBooleanFlag(i)),
        };
    }
    Ok(active)
}

/// Canonical raw DA note format, including exact KEM width and zero padding.
fn validate_ciphertext(
    bytes: &[u8; RP06_CIPHERTEXT_BYTES],
    slot: usize,
) -> Result<(), Rp06TransportError> {
    let container = &bytes[..crate::types::ENCRYPTED_NOTE_SIZE];
    if container[0] != 5 || u16_at(container, 1) != RP06_VERSION_BINDING.crypto {
        return Err(Rp06TransportError::CiphertextFormat(slot));
    }
    let note_end = 11usize
        .checked_add(u32_at(container, 7) as usize)
        .filter(|end| end.checked_add(4).is_some_and(|n| n <= container.len()))
        .ok_or(Rp06TransportError::CiphertextFormat(slot))?;
    let memo_end = (note_end + 4)
        .checked_add(u32_at(container, note_end) as usize)
        .filter(|end| *end <= container.len())
        .ok_or(Rp06TransportError::CiphertextFormat(slot))?;
    if container[memo_end..].iter().any(|byte| *byte != 0) {
        return Err(Rp06TransportError::CiphertextFormat(slot));
    }
    Ok(())
}
fn validate_ciphertext_hash(
    preamble: &[u8; RP06_PREAMBLE_BYTES],
    slot: usize,
    bytes: Option<&[u8; RP06_CIPHERTEXT_BYTES]>,
) -> Result<(), Rp06TransportError> {
    let start = 32 + slot * 6;
    if let Some(bytes) = bytes {
        validate_ciphertext(bytes, slot)?;
        let digest = ciphertext_hash_bytes(bytes);
        for (i, limb) in digest.chunks_exact(8).enumerate() {
            if word(preamble, PUBLIC_OFFSET + (start + i) * 8)
                != u64::from_be_bytes(limb.try_into().expect("hash limb"))
            {
                return Err(Rp06TransportError::CiphertextHash(slot));
            }
        }
    } else if (0..6).any(|i| word(preamble, PUBLIC_OFFSET + (start + i) * 8) != 0) {
        return Err(Rp06TransportError::CiphertextHash(slot));
    }
    Ok(())
}

pub fn preflight_rp06_native_leaf_exact(
    raw: &[u8],
) -> Result<DecodedRp06NativeLeaf<'_>, Rp06TransportError> {
    if raw.len() < RP06_NATIVE_LEAF_HEADER_BYTES + RP06_PREAMBLE_BYTES
        || raw.len() > RP06_CANDIDATE_MAX_NATIVE_LEAF_BYTES
    {
        return Err(Rp06TransportError::ResourceLimit);
    }
    if raw[..8] != RP06_NATIVE_LEAF_MAGIC
        || u16_at(raw, 8) != 1
        || usize::from(u16_at(raw, 10)) != RP06_PREAMBLE_BYTES
    {
        return Err(Rp06TransportError::InvalidIdentity);
    }
    if u32_at(raw, 16) as usize != raw.len() {
        return Err(Rp06TransportError::InvalidLength);
    }
    let proof_len = u32_at(raw, 12) as usize;
    if proof_len <= 4 || proof_len > RP06_CANDIDATE_MAX_PROOF_BYTES {
        return Err(Rp06TransportError::ResourceLimit);
    }
    let preamble = (&raw[20..20 + RP06_PREAMBLE_BYTES])
        .try_into()
        .expect("fixed preamble");
    let active = validate_preamble(preamble)?;
    let proof_start = RP06_NATIVE_LEAF_HEADER_BYTES
        + RP06_PREAMBLE_BYTES
        + active.into_iter().filter(|flag| *flag).count() * RP06_CIPHERTEXT_BYTES;
    if proof_start.checked_add(proof_len) != Some(raw.len()) {
        return Err(Rp06TransportError::InvalidLength);
    }
    let proof = &raw[proof_start..];
    if proof[..4] != RP06_INNER_PROOF_MAGIC {
        return Err(Rp06TransportError::InvalidIdentity);
    }
    let mut ciphertexts = [None; 2];
    let mut cursor = 20 + RP06_PREAMBLE_BYTES;
    for slot in 0..2 {
        if active[slot] {
            ciphertexts[slot] = Some(
                (&raw[cursor..cursor + RP06_CIPHERTEXT_BYTES])
                    .try_into()
                    .expect("fixed ciphertext"),
            );
            cursor += RP06_CIPHERTEXT_BYTES;
        }
        validate_ciphertext_hash(preamble, slot, ciphertexts[slot])?;
    }
    Ok(DecodedRp06NativeLeaf {
        raw,
        preamble,
        ciphertexts,
        proof,
    })
}
pub fn decode_rp06_native_leaf_exact(
    expected: Rp06ExpectedContext,
    raw: &[u8],
) -> Result<DecodedRp06NativeLeaf<'_>, Rp06TransportError> {
    preflight_rp06_native_leaf_exact(raw)?.ensure_context(expected)
}

pub fn encode_rp06_candidate_native_leaf(
    expected: Rp06ExpectedContext,
    preamble: &[u8; RP06_PREAMBLE_BYTES],
    ciphertexts: [Option<&[u8; RP06_CIPHERTEXT_BYTES]>; 2],
    proof: &[u8],
) -> Result<Vec<u8>, Rp06TransportError> {
    let active = validate_preamble(preamble)?;
    if proof.len() <= 4 || proof.len() > RP06_CANDIDATE_MAX_PROOF_BYTES {
        return Err(Rp06TransportError::ResourceLimit);
    }
    let count = active.into_iter().filter(|flag| *flag).count();
    for slot in 0..2 {
        if active[slot] != ciphertexts[slot].is_some() {
            return Err(Rp06TransportError::CiphertextPresence(slot));
        }
        validate_ciphertext_hash(preamble, slot, ciphertexts[slot])?;
    }
    let len = 20 + RP06_PREAMBLE_BYTES + count * RP06_CIPHERTEXT_BYTES + proof.len();
    let mut raw = Vec::new();
    raw.try_reserve_exact(len)
        .map_err(|_| Rp06TransportError::AllocationFailed)?;
    raw.extend(RP06_NATIVE_LEAF_MAGIC);
    raw.extend(1u16.to_le_bytes());
    raw.extend((RP06_PREAMBLE_BYTES as u16).to_le_bytes());
    raw.extend((proof.len() as u32).to_le_bytes());
    raw.extend((len as u32).to_le_bytes());
    raw.extend(preamble);
    for bytes in ciphertexts.into_iter().flatten() {
        raw.extend(bytes);
    }
    raw.extend(proof);
    decode_rp06_native_leaf_exact(expected, &raw)?;
    Ok(raw)
}

pub fn preflight_rp06_envelope_exact(
    raw: &[u8],
) -> Result<DecodedRp06Envelope<'_>, Rp06TransportError> {
    if raw.len() < 32 || raw.len() > RP06_CANDIDATE_MAX_ENVELOPE_BYTES {
        return Err(Rp06TransportError::ResourceLimit);
    }
    if raw[..8] != RP06_ENVELOPE_MAGIC || u16_at(raw, 8) != 1 {
        return Err(Rp06TransportError::InvalidIdentity);
    }
    // Envelope uses the historical field order, but exact successor identity only.
    if u16_at(raw, 10) != RP06_VERSION_BINDING.circuit
        || u16_at(raw, 12) != RP06_VERSION_BINDING.crypto
        || u16_at(raw, 14) != LAUNCH_SHIELDED_FAMILY_ID
        || u16_at(raw, 16) != RP06_ACTION_ID
        || raw[18] != 2
        || raw[19] != RP06_PROFILE_ID
        || u16_at(raw, 20) != RP06_DOMAIN_SET
        || raw[22] != 1
        || raw[23] != 0
    {
        return Err(Rp06TransportError::InvalidIdentity);
    }
    let leaf = preflight_rp06_native_leaf_exact(&raw[32..])?;
    if u32_at(raw, 24) as usize != leaf.proof().len()
        || u32_at(raw, 28) as usize != leaf.raw().len()
    {
        return Err(Rp06TransportError::InvalidLength);
    }
    Ok(DecodedRp06Envelope { raw, leaf })
}
pub fn decode_rp06_envelope_exact(
    expected: Rp06ExpectedContext,
    raw: &[u8],
) -> Result<DecodedRp06Envelope<'_>, Rp06TransportError> {
    let decoded = preflight_rp06_envelope_exact(raw)?;
    decoded.leaf.ensure_context(expected)?;
    Ok(decoded)
}
pub fn encode_rp06_candidate_envelope(
    expected: Rp06ExpectedContext,
    leaf: &[u8],
) -> Result<Vec<u8>, Rp06TransportError> {
    let leaf = decode_rp06_native_leaf_exact(expected, leaf)?;
    let len = 32 + leaf.raw().len();
    let mut raw = Vec::new();
    raw.try_reserve_exact(len)
        .map_err(|_| Rp06TransportError::AllocationFailed)?;
    raw.extend(RP06_ENVELOPE_MAGIC);
    for word in [
        1,
        RP06_VERSION_BINDING.circuit,
        RP06_VERSION_BINDING.crypto,
        LAUNCH_SHIELDED_FAMILY_ID,
        RP06_ACTION_ID,
    ] {
        raw.extend(word.to_le_bytes());
    }
    raw.extend([2, RP06_PROFILE_ID]);
    raw.extend(RP06_DOMAIN_SET.to_le_bytes());
    raw.extend([1, 0]);
    raw.extend((leaf.proof().len() as u32).to_le_bytes());
    raw.extend((leaf.raw().len() as u32).to_le_bytes());
    raw.extend(leaf.raw());
    decode_rp06_envelope_exact(expected, &raw)?;
    Ok(raw)
}

fn compact_prefix(raw: &[u8]) -> Result<(usize, usize), Rp06TransportError> {
    let first = *raw.first().ok_or(Rp06TransportError::NonCanonicalCompact)?;
    match first & 3 {
        0 => Ok((usize::from(first >> 2), 1)),
        1 if raw.len() >= 2 => {
            let len = usize::from(u16_at(raw, 0) >> 2);
            if len < 64 {
                return Err(Rp06TransportError::NonCanonicalCompact);
            }
            Ok((len, 2))
        }
        2 if raw.len() >= 4 => {
            let len = (u32_at(raw, 0) >> 2) as usize;
            if len < 16384 {
                return Err(Rp06TransportError::NonCanonicalCompact);
            }
            Ok((len, 4))
        }
        _ => Err(Rp06TransportError::NonCanonicalCompact),
    }
}
pub fn preflight_rp06_inline_args_exact(
    raw: &[u8],
) -> Result<DecodedRp06InlineArgs<'_>, Rp06TransportError> {
    if raw.len() > RP06_CANDIDATE_MAX_INLINE_BYTES {
        return Err(Rp06TransportError::ResourceLimit);
    }
    let (len, offset) = compact_prefix(raw)?;
    if offset.checked_add(len) != Some(raw.len()) {
        return Err(Rp06TransportError::InvalidLength);
    }
    let envelope = preflight_rp06_envelope_exact(&raw[offset..])?;
    Ok(DecodedRp06InlineArgs { raw, envelope })
}
pub fn decode_rp06_inline_args_exact(
    expected: Rp06ExpectedContext,
    raw: &[u8],
) -> Result<DecodedRp06InlineArgs<'_>, Rp06TransportError> {
    let decoded = preflight_rp06_inline_args_exact(raw)?;
    decoded.native_leaf().ensure_context(expected)?;
    Ok(decoded)
}
pub fn encode_rp06_candidate_inline_args(
    expected: Rp06ExpectedContext,
    envelope: &[u8],
) -> Result<Vec<u8>, Rp06TransportError> {
    decode_rp06_envelope_exact(expected, envelope)?;
    let len = envelope.len() as u32;
    let mut raw = Vec::new();
    raw.try_reserve_exact(4 + envelope.len())
        .map_err(|_| Rp06TransportError::AllocationFailed)?;
    if len < 64 {
        raw.push((len as u8) << 2);
    } else if len < 16384 {
        raw.extend((((len as u16) << 2) | 1).to_le_bytes());
    } else {
        raw.extend(((len << 2) | 2).to_le_bytes());
    }
    raw.extend(envelope);
    decode_rp06_inline_args_exact(expected, &raw)?;
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(output: bool) -> (Rp06ExpectedContext, Vec<u8>) {
        let context = Rp06ExpectedContext::new([2; 32], [3; 48]).unwrap();
        let mut preamble = [0u8; RP06_PREAMBLE_BYTES];
        preamble[..8].copy_from_slice(&RP06_PREAMBLE_MAGIC);
        preamble[8..16].copy_from_slice(&RP06_PROGRAM_MAGIC);
        for (i, value) in [1u16, 9, 7, 1, 14, 6].into_iter().enumerate() {
            preamble[16 + i * 2..18 + i * 2].copy_from_slice(&value.to_le_bytes());
        }
        preamble[28..32].copy_from_slice(&[2, 10, 1, 0]);
        preamble[32..80].fill(3);
        preamble[80..112].fill(2);
        for i in 0..8 {
            preamble[PUBLIC_OFFSET + (120 + i) * 8..PUBLIC_OFFSET + (121 + i) * 8]
                .copy_from_slice(&u64::from(0x0202_0202u32).to_le_bytes());
        }
        let mut ciphertext = [0u8; RP06_CIPHERTEXT_BYTES];
        ciphertext[0] = 5;
        ciphertext[1..3].copy_from_slice(&7u16.to_le_bytes());
        if output {
            preamble[PUBLIC_OFFSET + 16..PUBLIC_OFFSET + 24].copy_from_slice(&1u64.to_le_bytes());
            for (i, bytes) in ciphertext_hash_bytes(&ciphertext)
                .chunks_exact(8)
                .enumerate()
            {
                let limb = u64::from_be_bytes(bytes.try_into().unwrap());
                preamble[PUBLIC_OFFSET + (32 + i) * 8..PUBLIC_OFFSET + (33 + i) * 8]
                    .copy_from_slice(&limb.to_le_bytes());
            }
        }
        // A shape fixture deliberately cannot establish cryptographic proof validity.
        let leaf = encode_rp06_candidate_native_leaf(
            context,
            &preamble,
            [output.then_some(&ciphertext), None],
            b"SMZB\0",
        )
        .unwrap();
        let envelope = encode_rp06_candidate_envelope(context, &leaf).unwrap();
        (
            context,
            encode_rp06_candidate_inline_args(context, &envelope).unwrap(),
        )
    }
    #[test]
    fn rp06_carrier_borrows_exact_proof_and_ciphertexts() {
        for active in [false, true] {
            let (context, args) = fixture(active);
            let decoded = decode_rp06_inline_args_exact(context, &args).unwrap();
            assert_eq!(decoded.native_leaf().proof(), b"SMZB\0");
            assert!(core::ptr::eq(
                decoded.native_leaf().proof().as_ptr(),
                args[args.len() - 5..].as_ptr()
            ));
            assert_eq!(decoded.native_leaf().ciphertext(0).is_some(), active);
            assert_eq!(decoded.native_leaf().public_words().len(), 128);
        }
    }
    #[test]
    fn rp06_carrier_rejects_network_reduction_lengths_and_old_identity() {
        let (context, args) = fixture(false);
        let decoded = decode_rp06_inline_args_exact(context, &args).unwrap();
        let original = decoded.native_leaf().raw();
        let mut leaf = original.to_vec();
        leaf[20 + PUBLIC_OFFSET + 120 * 8..20 + PUBLIC_OFFSET + 121 * 8]
            .copy_from_slice(&(u64::from(u32::MAX) + 1).to_le_bytes());
        assert_eq!(
            preflight_rp06_native_leaf_exact(&leaf).unwrap_err(),
            Rp06TransportError::NetworkEmbeddingMismatch
        );
        let wrong = Rp06ExpectedContext::new([9; 32], [3; 48]).unwrap();
        assert!(decode_rp06_inline_args_exact(wrong, &args).is_err());
        let mut leaf = original.to_vec();
        leaf[8] = 2;
        assert!(preflight_rp06_native_leaf_exact(&leaf).is_err());
        let mut leaf = original.to_vec();
        leaf.extend([0]);
        assert!(preflight_rp06_native_leaf_exact(&leaf).is_err());
        let mut args = args.clone();
        args.push(0);
        assert!(preflight_rp06_inline_args_exact(&args).is_err());
        assert!(compact_prefix(&[1, 0]).is_err());
        assert!(compact_prefix(&[2, 0, 0, 0]).is_err());
    }
    #[test]
    fn rp06_carrier_rejects_ciphertext_mutations_and_padding() {
        let (context, args) = fixture(true);
        let original = decode_rp06_inline_args_exact(context, &args)
            .unwrap()
            .native_leaf()
            .raw();
        let mut leaf = original.to_vec();
        leaf[20 + RP06_PREAMBLE_BYTES + 20] = 1;
        assert_eq!(
            preflight_rp06_native_leaf_exact(&leaf).unwrap_err(),
            Rp06TransportError::CiphertextFormat(0)
        );
        let mut leaf = original.to_vec();
        leaf[20 + RP06_PREAMBLE_BYTES + crate::types::ENCRYPTED_NOTE_SIZE] ^= 1;
        assert_eq!(
            preflight_rp06_native_leaf_exact(&leaf).unwrap_err(),
            Rp06TransportError::CiphertextHash(0)
        );
    }
}
