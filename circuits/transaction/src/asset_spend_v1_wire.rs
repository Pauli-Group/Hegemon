//! Exact controlled-asset candidate and separately identified native framing.
//!
//! `HGASLC02` is deliberately separate from every accepted native action and
//! the incompatible ordinary-only `HGASLC01` candidate.
//! Decoding authenticates framing and ciphertext commitments, not a proof or
//! chain context. Only a proof-aware caller may apply the decoded statement.
#![forbid(unsafe_code)]

use crate::asset_spend_v1::{
    relation_digest, AssetSpendPublic, CANDIDATE_PROOF_MAGIC, MAX_CANDIDATE_PROOF_BYTES,
    PUBLIC_WORDS, RELATION_ID,
};
use crate::private_spend::CIPHERTEXT_BYTES;
use transaction_core::hashing_pq::ciphertext_hash_bytes;

pub const ASSET_SPEND_V1_ACTION_MAGIC: [u8; 8] = *b"HGASLC02";
pub const ASSET_SPEND_V1_OUTPUTS: usize = 3;
/// magic, identity length/identity, relation source digest, schema counts,
/// reserved zero, ciphertext width, proof length, and complete action length.
pub const ASSET_SPEND_V1_HEADER_BYTES: usize = 74 + RELATION_ID.len();
pub const ASSET_SPEND_V1_PUBLIC_BYTES: usize = PUBLIC_WORDS * 8;
pub const ASSET_SPEND_V1_FIXED_BYTES: usize = ASSET_SPEND_V1_HEADER_BYTES
    + ASSET_SPEND_V1_PUBLIC_BYTES
    + ASSET_SPEND_V1_OUTPUTS * CIPHERTEXT_BYTES;
pub const ASSET_SPEND_V1_MAX_ACTION_BYTES: usize =
    ASSET_SPEND_V1_FIXED_BYTES + MAX_CANDIDATE_PROOF_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetSpendWireErrorV1 {
    ActionLength,
    Truncated,
    Magic,
    RelationIdentity,
    RelationSource,
    Schema,
    NonCanonicalPublic,
    PublicShape,
    CiphertextCommitment,
    ProofLength,
    ProofMagic,
    UnsupportedProfile,
    TrailingBytes,
}

impl core::fmt::Display for AssetSpendWireErrorV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "candidate asset action: {self:?}")
    }
}
impl std::error::Error for AssetSpendWireErrorV1 {}

/// Borrowed, structurally decoded action. This type grants no authorization.
#[derive(Debug)]
pub struct AssetSpendActionRefV1<'a> {
    pub public: AssetSpendPublic,
    pub ciphertexts: [&'a [u8; CIPHERTEXT_BYTES]; ASSET_SPEND_V1_OUTPUTS],
    pub proof: &'a [u8],
}

fn validate_public(public: &AssetSpendPublic) -> Result<(), AssetSpendWireErrorV1> {
    public
        .validate_structure()
        .map_err(|_| AssetSpendWireErrorV1::PublicShape)?;
    // Every slot is active in this candidate. No raw-zero padding is a note or
    // a usable nullifier. Roots and issuer are authenticated by ledger state.
    if public
        .nullifiers
        .iter()
        .chain(public.commitments.iter())
        .any(|digest| *digest == [0; 7])
        || (public.operation == crate::asset_spend_v1::TRANSFER && public.magnitude != 0)
        || (public.operation != crate::asset_spend_v1::TRANSFER && public.magnitude == 0)
    {
        return Err(AssetSpendWireErrorV1::PublicShape);
    }
    Ok(())
}

fn validate_proof_framing(proof: &[u8]) -> Result<(), AssetSpendWireErrorV1> {
    if proof.len() < CANDIDATE_PROOF_MAGIC.len() || proof.len() > MAX_CANDIDATE_PROOF_BYTES {
        return Err(AssetSpendWireErrorV1::ProofLength);
    }
    if proof.get(..4) != Some(CANDIDATE_PROOF_MAGIC.as_slice()) {
        return Err(AssetSpendWireErrorV1::ProofMagic);
    }
    Ok(())
}

fn validate_ciphertexts(
    public: &AssetSpendPublic,
    ciphertexts: [&[u8; CIPHERTEXT_BYTES]; ASSET_SPEND_V1_OUTPUTS],
) -> Result<(), AssetSpendWireErrorV1> {
    for (slot, ciphertext) in ciphertexts.into_iter().enumerate() {
        if ciphertext_hash_bytes(ciphertext) != public.ciphertext_commitments[slot] {
            return Err(AssetSpendWireErrorV1::CiphertextCommitment);
        }
    }
    Ok(())
}

/// Encode one exact candidate action. A correctly framed invalid proof can be
/// encoded; actual proof verification belongs to `AssetLedgerV1::apply_action`.
pub fn encode_asset_spend_action_v1(
    public: &AssetSpendPublic,
    ciphertexts: &[[u8; CIPHERTEXT_BYTES]; ASSET_SPEND_V1_OUTPUTS],
    proof: &[u8],
) -> Result<Vec<u8>, AssetSpendWireErrorV1> {
    encode_spend_with_profile(
        public,
        ciphertexts,
        proof,
        ASSET_SPEND_V1_ACTION_MAGIC,
        false,
    )
}

fn native_profile(public: &AssetSpendPublic) -> Result<usize, AssetSpendWireErrorV1> {
    crate::asset_spend_v1_admission::spend_profile_upper_bound_v1(
        public.policy_mode,
        public.credential_depth,
    )
    .map_err(|error| match error {
        crate::asset_spend_v1_admission::NativeAssetAdmissionErrorV1::SourceIdentity => {
            AssetSpendWireErrorV1::RelationSource
        }
        _ => AssetSpendWireErrorV1::UnsupportedProfile,
    })
}

fn encode_spend_with_profile(
    public: &AssetSpendPublic,
    ciphertexts: &[[u8; CIPHERTEXT_BYTES]; ASSET_SPEND_V1_OUTPUTS],
    proof: &[u8],
    magic: [u8; 8],
    native: bool,
) -> Result<Vec<u8>, AssetSpendWireErrorV1> {
    if native {
        let upper = native_profile(public)?;
        if proof.len() > NATIVE_ASSET_INNER_PROOF_CAP_V1 || proof.len() > upper {
            return Err(AssetSpendWireErrorV1::ProofLength);
        }
    }
    validate_public(public)?;
    validate_proof_framing(proof)?;
    validate_ciphertexts(public, [&ciphertexts[0], &ciphertexts[1], &ciphertexts[2]])?;
    let total = ASSET_SPEND_V1_FIXED_BYTES
        .checked_add(proof.len())
        .ok_or(AssetSpendWireErrorV1::ActionLength)?;
    let proof_len = u32::try_from(proof.len()).map_err(|_| AssetSpendWireErrorV1::ProofLength)?;
    let total_len = u32::try_from(total).map_err(|_| AssetSpendWireErrorV1::ActionLength)?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend(magic);
    bytes.extend((RELATION_ID.len() as u16).to_le_bytes());
    bytes.extend(RELATION_ID.as_bytes());
    bytes.extend(&relation_digest()[..48]);
    bytes.extend((PUBLIC_WORDS as u16).to_le_bytes());
    bytes.extend([ASSET_SPEND_V1_OUTPUTS as u8, 0]);
    bytes.extend((CIPHERTEXT_BYTES as u32).to_le_bytes());
    bytes.extend(proof_len.to_le_bytes());
    bytes.extend(total_len.to_le_bytes());
    for word in public.words() {
        bytes.extend(word.to_le_bytes());
    }
    for ciphertext in ciphertexts {
        bytes.extend(ciphertext);
    }
    bytes.extend(proof);
    debug_assert_eq!(bytes.len(), total);
    Ok(bytes)
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], AssetSpendWireErrorV1> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(AssetSpendWireErrorV1::Truncated)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AssetSpendWireErrorV1::Truncated)?;
        self.cursor = end;
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16, AssetSpendWireErrorV1> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, AssetSpendWireErrorV1> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
}

struct Words<'a> {
    words: &'a [u64; PUBLIC_WORDS],
    cursor: usize,
}
impl Words<'_> {
    fn word(&mut self) -> u64 {
        let word = self.words[self.cursor];
        self.cursor += 1;
        word
    }
    fn digest(&mut self) -> [u64; 7] {
        core::array::from_fn(|_| self.word())
    }
    fn u32(&mut self) -> Result<u32, AssetSpendWireErrorV1> {
        u32::try_from(self.word()).map_err(|_| AssetSpendWireErrorV1::NonCanonicalPublic)
    }
    fn u8(&mut self) -> Result<u8, AssetSpendWireErrorV1> {
        u8::try_from(self.word()).map_err(|_| AssetSpendWireErrorV1::NonCanonicalPublic)
    }
    fn boolean(&mut self) -> Result<bool, AssetSpendWireErrorV1> {
        match self.word() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AssetSpendWireErrorV1::NonCanonicalPublic),
        }
    }
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], AssetSpendWireErrorV1> {
        let mut bytes = [0; N];
        for chunk in bytes.chunks_exact_mut(4) {
            chunk.copy_from_slice(&self.u32()?.to_le_bytes());
        }
        Ok(bytes)
    }
}

fn decode_public(bytes: &[u8]) -> Result<AssetSpendPublic, AssetSpendWireErrorV1> {
    let mut words = [0u64; PUBLIC_WORDS];
    for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
        if *word >= hegemon_field::GOLDILOCKS_MODULUS {
            return Err(AssetSpendWireErrorV1::NonCanonicalPublic);
        }
    }
    let mut reader = Words {
        words: &words,
        cursor: 0,
    };
    let public = AssetSpendPublic {
        chain_id: reader.bytes()?,
        reference_parent_hash: reader.bytes()?,
        parent_height: reader.word(),
        note_root: reader.digest(),
        registry_root: reader.digest(),
        asset_id: reader.u32()?,
        policy_version: reader.u32()?,
        credential_root: reader.digest(),
        credential_depth: reader.u8()?,
        frozen: reader.boolean()?,
        mint_enabled: reader.boolean()?,
        issuer_commitment: reader.digest(),
        operation: reader.u8()?,
        magnitude: reader.word(),
        fee: reader.word(),
        nullifiers: [reader.digest(), reader.digest()],
        commitments: [reader.digest(), reader.digest(), reader.digest()],
        ciphertext_commitments: [reader.bytes()?, reader.bytes()?, reader.bytes()?],
        policy_mode: reader.u8()?,
        secret_release: u64::from(reader.boolean()?),
        released_secret: reader.bytes()?,
    };
    if reader.cursor != PUBLIC_WORDS || public.words() != words {
        return Err(AssetSpendWireErrorV1::NonCanonicalPublic);
    }
    validate_public(&public)?;
    Ok(public)
}

/// Validate exact schema, source binding, lengths, canonical public fields and
/// ciphertext hashes before returning borrowed proof bytes. No proof runs here.
pub fn decode_asset_spend_action_v1(
    bytes: &[u8],
) -> Result<AssetSpendActionRefV1<'_>, AssetSpendWireErrorV1> {
    decode_spend_with_profile(bytes, ASSET_SPEND_V1_ACTION_MAGIC, false)
}

fn decode_spend_with_profile(
    bytes: &[u8],
    magic: [u8; 8],
    native: bool,
) -> Result<AssetSpendActionRefV1<'_>, AssetSpendWireErrorV1> {
    let cap = if native {
        NATIVE_ASSET_INNER_PROOF_CAP_V1
    } else {
        MAX_CANDIDATE_PROOF_BYTES
    };
    if bytes.len() < ASSET_SPEND_V1_FIXED_BYTES + CANDIDATE_PROOF_MAGIC.len()
        || bytes.len() > ASSET_SPEND_V1_FIXED_BYTES + cap
    {
        return Err(AssetSpendWireErrorV1::ActionLength);
    }
    let mut reader = Reader { bytes, cursor: 0 };
    if reader.take(8)? != magic {
        return Err(AssetSpendWireErrorV1::Magic);
    }
    if usize::from(reader.u16()?) != RELATION_ID.len()
        || reader.take(RELATION_ID.len())? != RELATION_ID.as_bytes()
    {
        return Err(AssetSpendWireErrorV1::RelationIdentity);
    }
    if reader.take(48)? != &relation_digest()[..48] {
        return Err(AssetSpendWireErrorV1::RelationSource);
    }
    if usize::from(reader.u16()?) != PUBLIC_WORDS
        || reader.take(2)? != [ASSET_SPEND_V1_OUTPUTS as u8, 0]
        || reader.u32()? as usize != CIPHERTEXT_BYTES
    {
        return Err(AssetSpendWireErrorV1::Schema);
    }
    let proof_len = reader.u32()? as usize;
    if !(CANDIDATE_PROOF_MAGIC.len()..=cap).contains(&proof_len) {
        return Err(AssetSpendWireErrorV1::ProofLength);
    }
    let expected_len = ASSET_SPEND_V1_FIXED_BYTES
        .checked_add(proof_len)
        .ok_or(AssetSpendWireErrorV1::ActionLength)?;
    if reader.u32()? as usize != expected_len || bytes.len() != expected_len {
        return Err(AssetSpendWireErrorV1::ActionLength);
    }
    debug_assert_eq!(reader.cursor, ASSET_SPEND_V1_HEADER_BYTES);
    let public = decode_public(reader.take(ASSET_SPEND_V1_PUBLIC_BYTES)?)?;
    if native {
        if proof_len > native_profile(&public)? {
            return Err(AssetSpendWireErrorV1::ProofLength);
        }
    }
    let ciphertexts = [
        reader
            .take(CIPHERTEXT_BYTES)?
            .try_into()
            .expect("fixed ciphertext"),
        reader
            .take(CIPHERTEXT_BYTES)?
            .try_into()
            .expect("fixed ciphertext"),
        reader
            .take(CIPHERTEXT_BYTES)?
            .try_into()
            .expect("fixed ciphertext"),
    ];
    validate_ciphertexts(&public, ciphertexts)?;
    let proof = reader.take(proof_len)?;
    validate_proof_framing(proof)?;
    if reader.cursor != bytes.len() {
        return Err(AssetSpendWireErrorV1::TrailingBytes);
    }
    Ok(AssetSpendActionRefV1 {
        public,
        ciphertexts,
        proof,
    })
}

/// Native envelopes share the unchanged SMZE statement and proof identity.
/// Their recognition alone does not enable a production capability.
pub const NATIVE_ASSET_SPEND_ACTION_MAGIC_V1: [u8; 8] = *b"HGANSP01";
pub const NATIVE_ASSET_ADMIN_ACTION_MAGIC_V1: [u8; 8] = *b"HGANAD01";
pub const NATIVE_ASSET_INNER_PROOF_CAP_V1: usize =
    crate::asset_spend_v1_admission::NATIVE_INNER_PROOF_CAP_BYTES;
pub const NATIVE_ASSET_SPEND_MAX_ACTION_BYTES_V1: usize =
    ASSET_SPEND_V1_FIXED_BYTES + NATIVE_ASSET_INNER_PROOF_CAP_V1;
pub const NATIVE_ASSET_ADMIN_HEADER_BYTES_V1: usize =
    70 + crate::asset_policy_admin_v1::RELATION_ID.len();
pub const NATIVE_ASSET_ADMIN_FIXED_BYTES_V1: usize =
    NATIVE_ASSET_ADMIN_HEADER_BYTES_V1 + crate::asset_policy_admin_v1::PUBLIC_WORDS * 8;
pub const NATIVE_ASSET_ADMIN_MAX_ACTION_BYTES_V1: usize =
    NATIVE_ASSET_ADMIN_FIXED_BYTES_V1 + NATIVE_ASSET_INNER_PROOF_CAP_V1;

pub fn encode_native_asset_spend_action_v1(
    public: &AssetSpendPublic,
    ciphertexts: &[[u8; CIPHERTEXT_BYTES]; ASSET_SPEND_V1_OUTPUTS],
    proof: &[u8],
) -> Result<Vec<u8>, AssetSpendWireErrorV1> {
    encode_spend_with_profile(
        public,
        ciphertexts,
        proof,
        NATIVE_ASSET_SPEND_ACTION_MAGIC_V1,
        true,
    )
}
pub fn decode_native_asset_spend_action_v1(
    bytes: &[u8],
) -> Result<AssetSpendActionRefV1<'_>, AssetSpendWireErrorV1> {
    decode_spend_with_profile(bytes, NATIVE_ASSET_SPEND_ACTION_MAGIC_V1, true)
}

#[derive(Debug)]
pub struct AssetAdminActionRefV1<'a> {
    pub public: crate::asset_policy_admin_v1::PolicyAdminPublicV1,
    pub proof: &'a [u8],
}
fn decode_admin_public(
    bytes: &[u8],
) -> Result<crate::asset_policy_admin_v1::PolicyAdminPublicV1, AssetSpendWireErrorV1> {
    use crate::asset_policy_admin_v1::{self as admin, PolicyAdminPublicV1};
    use transaction_core::{asset_registry_v1::AssetControlsV1, poseidon2_width16::Felt};
    let mut words = [0u64; PUBLIC_WORDS];
    for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
        if *word >= hegemon_field::GOLDILOCKS_MODULUS {
            return Err(AssetSpendWireErrorV1::NonCanonicalPublic);
        }
    }
    let mut reader = Words {
        words: &words,
        cursor: 0,
    };
    if reader.word() != admin::CONTEXT_TAG {
        return Err(AssetSpendWireErrorV1::Schema);
    }
    let chain_id = reader.bytes()?;
    let reference_parent_hash = reader.bytes()?;
    let parent_height = reader.word();
    let registry_root = reader.digest();
    let after_registry_root = reader.digest();
    let asset_id = reader.u32()?;
    let old_policy_version = reader.u32()?;
    let new_policy_version = reader.u32()?;
    let policy_admin_commitment = reader.digest();
    let before_policy_leaf = reader.digest();
    let after_policy_leaf = reader.digest();
    let credential_root = reader.digest().map(Felt::from_u64);
    let credential_depth = reader.u8()?;
    let frozen = reader.boolean()?;
    let mint_enabled = reader.boolean()?;
    let expires_at = reader.word();
    let action_intent = reader.digest();
    let public = PolicyAdminPublicV1 {
        chain_id,
        reference_parent_hash,
        parent_height,
        registry_root,
        after_registry_root,
        asset_id,
        old_policy_version,
        new_policy_version,
        policy_admin_commitment,
        before_policy_leaf,
        after_policy_leaf,
        controls: AssetControlsV1 {
            credential_root,
            credential_depth,
            frozen,
            mint_enabled,
        },
        expires_at,
        action_intent,
    };
    // This reconstructs all134 words, including the full source digest and every
    // reserved zero, rather than trusting arbitrary serialized arguments.
    if public.words() != words {
        return Err(AssetSpendWireErrorV1::NonCanonicalPublic);
    }
    public
        .validate_structure()
        .map_err(|_| AssetSpendWireErrorV1::PublicShape)?;
    Ok(public)
}

pub fn encode_native_asset_admin_action_v1(
    public: &crate::asset_policy_admin_v1::PolicyAdminPublicV1,
    proof: &[u8],
) -> Result<Vec<u8>, AssetSpendWireErrorV1> {
    use crate::asset_policy_admin_v1 as admin;
    public
        .validate_structure()
        .map_err(|_| AssetSpendWireErrorV1::PublicShape)?;
    let upper = crate::asset_spend_v1_admission::admin_profile_upper_bound_v1()
        .map_err(|_| AssetSpendWireErrorV1::RelationSource)?;
    if proof.len() > NATIVE_ASSET_INNER_PROOF_CAP_V1 || proof.len() > upper {
        return Err(AssetSpendWireErrorV1::ProofLength);
    }
    validate_proof_framing(proof)?;
    let total = NATIVE_ASSET_ADMIN_FIXED_BYTES_V1 + proof.len();
    let mut bytes = Vec::with_capacity(total);
    bytes.extend(NATIVE_ASSET_ADMIN_ACTION_MAGIC_V1);
    bytes.extend((admin::RELATION_ID.len() as u16).to_le_bytes());
    bytes.extend(admin::RELATION_ID.as_bytes());
    bytes.extend(&admin::relation_digest()[..48]);
    bytes.extend((admin::PUBLIC_WORDS as u16).to_le_bytes());
    bytes.extend([0, 0]);
    bytes.extend((proof.len() as u32).to_le_bytes());
    bytes.extend((total as u32).to_le_bytes());
    bytes.extend(public.binding_bytes());
    bytes.extend(proof);
    debug_assert_eq!(bytes.len(), total);
    Ok(bytes)
}

pub fn decode_native_asset_admin_action_v1(
    bytes: &[u8],
) -> Result<AssetAdminActionRefV1<'_>, AssetSpendWireErrorV1> {
    use crate::asset_policy_admin_v1 as admin;
    if bytes.len() < NATIVE_ASSET_ADMIN_FIXED_BYTES_V1 + 4
        || bytes.len() > NATIVE_ASSET_ADMIN_MAX_ACTION_BYTES_V1
    {
        return Err(AssetSpendWireErrorV1::ActionLength);
    }
    let mut reader = Reader { bytes, cursor: 0 };
    if reader.take(8)? != NATIVE_ASSET_ADMIN_ACTION_MAGIC_V1 {
        return Err(AssetSpendWireErrorV1::Magic);
    }
    if usize::from(reader.u16()?) != admin::RELATION_ID.len()
        || reader.take(admin::RELATION_ID.len())? != admin::RELATION_ID.as_bytes()
    {
        return Err(AssetSpendWireErrorV1::RelationIdentity);
    }
    if reader.take(48)? != &admin::relation_digest()[..48] {
        return Err(AssetSpendWireErrorV1::RelationSource);
    }
    if usize::from(reader.u16()?) != admin::PUBLIC_WORDS || reader.take(2)? != [0, 0] {
        return Err(AssetSpendWireErrorV1::Schema);
    }
    let proof_len = reader.u32()? as usize;
    let upper = crate::asset_spend_v1_admission::admin_profile_upper_bound_v1()
        .map_err(|_| AssetSpendWireErrorV1::RelationSource)?;
    if !(4..=NATIVE_ASSET_INNER_PROOF_CAP_V1).contains(&proof_len) || proof_len > upper {
        return Err(AssetSpendWireErrorV1::ProofLength);
    }
    let total = NATIVE_ASSET_ADMIN_FIXED_BYTES_V1 + proof_len;
    if reader.u32()? as usize != total || bytes.len() != total {
        return Err(AssetSpendWireErrorV1::ActionLength);
    }
    debug_assert_eq!(reader.cursor, NATIVE_ASSET_ADMIN_HEADER_BYTES_V1);
    let public = decode_admin_public(reader.take(admin::PUBLIC_WORDS * 8)?)?;
    let proof = reader.take(proof_len)?;
    validate_proof_framing(proof)?;
    if reader.cursor != bytes.len() {
        return Err(AssetSpendWireErrorV1::TrailingBytes);
    }
    Ok(AssetAdminActionRefV1 { public, proof })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_spend_fixture_source_is_qualified(test: &str) -> bool {
        let qualified = hex::encode(relation_digest())
            == crate::asset_spend_v1_admission::QUALIFIED_SPEND_SOURCE_SHA512;
        eprintln!("inactive asset fixture {test}: spend_source_qualified={qualified}");
        qualified
    }

    fn native_admin_fixture_source_is_qualified(test: &str) -> bool {
        let qualified = hex::encode(crate::asset_policy_admin_v1::relation_digest())
            == crate::asset_spend_v1_admission::QUALIFIED_ADMIN_SOURCE_SHA512;
        eprintln!("inactive asset fixture {test}: admin_source_qualified={qualified}");
        qualified
    }

    fn fixture() -> (AssetSpendPublic, [[u8; CIPHERTEXT_BYTES]; 3], Vec<u8>) {
        let ciphertexts = [
            [1; CIPHERTEXT_BYTES],
            [2; CIPHERTEXT_BYTES],
            [3; CIPHERTEXT_BYTES],
        ];
        let public = AssetSpendPublic {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 100,
            note_root: [3; 7],
            registry_root: [4; 7],
            asset_id: 1,
            policy_version: 1,
            credential_root: [5; 7],
            credential_depth: 4,
            frozen: false,
            mint_enabled: true,
            issuer_commitment: [6; 7],
            operation: crate::asset_spend_v1::TRANSFER,
            magnitude: 0,
            fee: 1,
            nullifiers: [[7; 7], [8; 7]],
            commitments: [[9; 7], [10; 7], [11; 7]],
            ciphertext_commitments: ciphertexts
                .map(|ciphertext| ciphertext_hash_bytes(&ciphertext)),
            policy_mode: 0,
            secret_release: 0,
            released_secret: [0; 32],
        };
        // This is deliberately an invalid proof. Tests exercise framing only;
        // no parser result or fixture boolean substitutes for a real verifier.
        (public, ciphertexts, CANDIDATE_PROOF_MAGIC.to_vec())
    }

    #[test]
    fn exact_roundtrip_and_nonproof_overhead() {
        let (public, ciphertexts, proof) = fixture();
        let bytes = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        let parsed = decode_asset_spend_action_v1(&bytes).unwrap();
        assert_eq!(parsed.public, public);
        assert_eq!(parsed.proof, proof);
        assert_eq!(parsed.ciphertexts[2], &ciphertexts[2]);
        assert_eq!(bytes.len() - proof.len(), ASSET_SPEND_V1_FIXED_BYTES);
        assert_eq!(
            encode_asset_spend_action_v1(&parsed.public, &ciphertexts, parsed.proof).unwrap(),
            bytes
        );
    }

    #[test]
    fn malformed_headers_lengths_sources_and_inner_magic_reject() {
        let (public, ciphertexts, proof) = fixture();
        let bytes = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        for offset in [
            0,
            8,
            10,
            10 + RELATION_ID.len(),
            ASSET_SPEND_V1_HEADER_BYTES - 16,
            ASSET_SPEND_V1_HEADER_BYTES - 12,
            ASSET_SPEND_V1_HEADER_BYTES - 8,
            ASSET_SPEND_V1_HEADER_BYTES - 4,
            bytes.len() - 1,
        ] {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 0x80;
            assert!(
                decode_asset_spend_action_v1(&mutated).is_err(),
                "offset {offset}"
            );
        }
        for cut in [
            0,
            1,
            8,
            ASSET_SPEND_V1_HEADER_BYTES,
            ASSET_SPEND_V1_FIXED_BYTES,
            bytes.len() - 1,
        ] {
            assert!(decode_asset_spend_action_v1(&bytes[..cut]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_asset_spend_action_v1(&extra).is_err());
    }

    #[test]
    fn canonical_word_and_byte_limb_aliases_reject() {
        let (public, ciphertexts, proof) = fixture();
        let bytes = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        for (index, value) in [
            (17, hegemon_field::GOLDILOCKS_MODULUS),
            (0, 1u64 << 32),
            (31, 1u64 << 32),
            (41, 2),
            (42, 2),
            (50, 256),
            (124, 256),
            (125, 2),
            (126, 1u64 << 32),
        ] {
            let mut mutated = bytes.clone();
            let start = ASSET_SPEND_V1_HEADER_BYTES + index * 8;
            mutated[start..start + 8].copy_from_slice(&value.to_le_bytes());
            assert!(
                decode_asset_spend_action_v1(&mutated).is_err(),
                "word {index}"
            );
        }
    }

    #[test]
    fn ciphertext_rebinding_nullifiers_and_native_asset_reject() {
        let (mut public, ciphertexts, proof) = fixture();
        let mut bytes = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        bytes[ASSET_SPEND_V1_HEADER_BYTES + ASSET_SPEND_V1_PUBLIC_BYTES] ^= 1;
        assert!(matches!(
            decode_asset_spend_action_v1(&bytes),
            Err(AssetSpendWireErrorV1::CiphertextCommitment)
        ));
        public.nullifiers[1] = public.nullifiers[0];
        assert!(encode_asset_spend_action_v1(&public, &ciphertexts, &proof).is_err());
        public.nullifiers[1] = [8; 7];
        public.nullifiers[0] = [0; 7];
        assert!(encode_asset_spend_action_v1(&public, &ciphertexts, &proof).is_err());
        public.nullifiers[0] = [7; 7];
        public.asset_id = 0;
        assert!(encode_asset_spend_action_v1(&public, &ciphertexts, &proof).is_err());
    }

    #[test]
    fn successor_wire_binds_release_and_rejects_ordinary_only_identity() {
        let (mut public, ciphertexts, proof) = fixture();
        let ordinary = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        let mut historical = ordinary.clone();
        historical[..8].copy_from_slice(b"HGASLC01");
        assert!(matches!(
            decode_asset_spend_action_v1(&historical),
            Err(AssetSpendWireErrorV1::Magic)
        ));
        public.policy_mode = 1;
        public.secret_release = 1;
        public.released_secret = [37; 32];
        let release = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        let decoded = decode_asset_spend_action_v1(&release).unwrap();
        assert_eq!(decoded.public, public);
        assert_ne!(release, ordinary);
        let mut hidden_nonzero = ordinary.clone();
        let release_offset = ASSET_SPEND_V1_HEADER_BYTES + 126 * 8;
        hidden_nonzero[release_offset] = 1;
        assert!(decode_asset_spend_action_v1(&hidden_nonzero).is_err());
        public.secret_release = 0;
        assert!(encode_asset_spend_action_v1(&public, &ciphertexts, &proof).is_err());
        public.secret_release = 1;
        public.policy_mode = 0;
        assert!(encode_asset_spend_action_v1(&public, &ciphertexts, &proof).is_err());
    }

    #[test]
    fn native_spend_identity_profile_and_historical_candidate_are_distinct() {
        let (mut public, ciphertexts, proof) = fixture();
        if native_spend_fixture_source_is_qualified(
            "native_spend_identity_profile_and_historical_candidate_are_distinct",
        ) {
            let native =
                encode_native_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
            assert_eq!(&native[..8], b"HGANSP01");
            assert_eq!(
                decode_native_asset_spend_action_v1(&native).unwrap().public,
                public
            );
            assert!(matches!(
                decode_asset_spend_action_v1(&native),
                Err(AssetSpendWireErrorV1::Magic)
            ));
            let candidate = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
            assert!(matches!(
                decode_native_asset_spend_action_v1(&candidate),
                Err(AssetSpendWireErrorV1::Magic)
            ));
            assert_eq!(&candidate[8..], &native[8..]);
        } else {
            assert_eq!(
                encode_native_asset_spend_action_v1(&public, &ciphertexts, &proof),
                Err(AssetSpendWireErrorV1::RelationSource)
            );
            let mut candidate =
                encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
            assert!(matches!(
                decode_native_asset_spend_action_v1(&candidate),
                Err(AssetSpendWireErrorV1::Magic)
            ));
            candidate[..8].copy_from_slice(&NATIVE_ASSET_SPEND_ACTION_MAGIC_V1);
            assert!(matches!(
                decode_native_asset_spend_action_v1(&candidate),
                Err(AssetSpendWireErrorV1::RelationSource)
            ));
        }

        public.policy_mode = 1;
        public.credential_depth = 16;
        // Historical candidate framing remains unchanged. Native admission
        // rejects this graph before ciphertext hashing or structured proof work.
        let mut unsupported = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        unsupported[..8].copy_from_slice(&NATIVE_ASSET_SPEND_ACTION_MAGIC_V1);
        unsupported[ASSET_SPEND_V1_HEADER_BYTES + ASSET_SPEND_V1_PUBLIC_BYTES] ^= 1;
        assert!(matches!(
            decode_native_asset_spend_action_v1(&unsupported),
            Err(AssetSpendWireErrorV1::UnsupportedProfile)
        ));
        assert_eq!(
            encode_native_asset_spend_action_v1(&public, &ciphertexts, &proof),
            Err(AssetSpendWireErrorV1::UnsupportedProfile)
        );
    }

    #[test]
    fn native_size_limits_reject_before_proof_parse() {
        let (public, ciphertexts, proof) = fixture();
        // The outer action-length bound precedes historical source admission.
        let mut oversized = encode_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        oversized[..8].copy_from_slice(&NATIVE_ASSET_SPEND_ACTION_MAGIC_V1);
        oversized.resize(NATIVE_ASSET_SPEND_MAX_ACTION_BYTES_V1 + 1, 0);
        assert!(matches!(
            decode_native_asset_spend_action_v1(&oversized),
            Err(AssetSpendWireErrorV1::ActionLength)
        ));
        if !native_spend_fixture_source_is_qualified("native_size_limits_reject_before_proof_parse")
        {
            assert_eq!(
                native_profile(&public),
                Err(AssetSpendWireErrorV1::RelationSource)
            );
            assert_eq!(
                encode_native_asset_spend_action_v1(&public, &ciphertexts, &proof),
                Err(AssetSpendWireErrorV1::RelationSource)
            );
            return;
        }
        let upper = native_profile(&public).unwrap();
        let mut too_large = vec![0; upper + 1];
        too_large[..4].copy_from_slice(&CANDIDATE_PROOF_MAGIC);
        assert_eq!(
            encode_native_asset_spend_action_v1(&public, &ciphertexts, &too_large),
            Err(AssetSpendWireErrorV1::ProofLength)
        );
        let mut native =
            encode_native_asset_spend_action_v1(&public, &ciphertexts, &proof).unwrap();
        native.resize(NATIVE_ASSET_SPEND_MAX_ACTION_BYTES_V1 + 1, 0);
        assert!(matches!(
            decode_native_asset_spend_action_v1(&native),
            Err(AssetSpendWireErrorV1::ActionLength)
        ));
    }

    fn admin_fixture() -> crate::asset_policy_admin_v1::PolicyAdminPublicV1 {
        use transaction_core::{asset_registry_v1::AssetControlsV1, poseidon2_width16::Felt};
        crate::asset_policy_admin_v1::PolicyAdminPublicV1 {
            chain_id: [1; 32],
            reference_parent_hash: [2; 32],
            parent_height: 100,
            registry_root: [3; 7],
            after_registry_root: [4; 7],
            asset_id: 1,
            old_policy_version: 1,
            new_policy_version: 1,
            policy_admin_commitment: [5; 7],
            before_policy_leaf: [6; 7],
            after_policy_leaf: [7; 7],
            controls: AssetControlsV1 {
                credential_root: [Felt::from_u64(8); 7],
                credential_depth: 8,
                frozen: false,
                mint_enabled: true,
            },
            expires_at: 110,
            action_intent: [9; 7],
        }
    }

    #[test]
    fn native_admin_codec_binds_entire_canonical_statement() {
        let public = admin_fixture();
        let proof = b"SMZE";
        // Canonical public-word decoding is independent of native source admission.
        let canonical = public.binding_bytes();
        assert_eq!(decode_admin_public(&canonical).unwrap(), public);
        for (word, value) in [
            (0, 0u64),
            (1, 1 << 32),
            (32, 1 << 32),
            (63, 256),
            (64, 2),
            (65, 2),
            (74, 0),
            (90, 1),
            (133, 1),
        ] {
            let mut mutation = canonical.clone();
            let start = word * 8;
            if word == 74 {
                mutation[start] ^= 1;
            } else {
                mutation[start..start + 8].copy_from_slice(&value.to_le_bytes());
            }
            assert!(
                decode_admin_public(&mutation).is_err(),
                "public word {word}"
            );
        }
        if !native_admin_fixture_source_is_qualified(
            "native_admin_codec_binds_entire_canonical_statement",
        ) {
            assert_eq!(
                encode_native_asset_admin_action_v1(&public, proof),
                Err(AssetSpendWireErrorV1::RelationSource)
            );
            return;
        }
        let bytes = encode_native_asset_admin_action_v1(&public, proof).unwrap();
        let decoded = decode_native_asset_admin_action_v1(&bytes).unwrap();
        assert_eq!(decoded.public, public);
        assert_eq!(decoded.proof, proof);
        assert_eq!(bytes.len(), NATIVE_ASSET_ADMIN_FIXED_BYTES_V1 + proof.len());
        assert_eq!(
            encode_native_asset_admin_action_v1(&decoded.public, decoded.proof).unwrap(),
            bytes
        );
        for (word, value) in [
            (0, 0u64),
            (1, 1 << 32),
            (32, 1 << 32),
            (63, 256),
            (64, 2),
            (65, 2),
            (74, 0),
            (90, 1),
            (133, 1),
        ] {
            let mut mutation = bytes.clone();
            let start = NATIVE_ASSET_ADMIN_HEADER_BYTES_V1 + word * 8;
            // The source digest word mutation must differ even if its actual
            // value happened to be zero in another qualified source closure.
            if word == 74 {
                mutation[start] ^= 1;
            } else {
                mutation[start..start + 8].copy_from_slice(&value.to_le_bytes());
            }
            assert!(
                decode_native_asset_admin_action_v1(&mutation).is_err(),
                "word {word}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_native_asset_admin_action_v1(&trailing).is_err());
        let mut wrong_magic = bytes.clone();
        wrong_magic[..8].copy_from_slice(b"HGANSP01");
        assert!(decode_native_asset_admin_action_v1(&wrong_magic).is_err());
        assert!(decode_native_asset_spend_action_v1(&bytes).is_err());
        let too_large =
            vec![0; crate::asset_spend_v1_admission::ADMIN_PROFILE_UPPER_BOUND_BYTES + 1];
        assert_eq!(
            encode_native_asset_admin_action_v1(&public, &too_large),
            Err(AssetSpendWireErrorV1::ProofLength)
        );
    }

    #[test]
    fn native_admission_checks_current_context_and_actual_proof_parse() {
        use crate::asset_spend_v1_admission::{
            self as admission, NativeAssetAdmissionErrorV1 as E, NativeAssetContextV1,
        };
        let (mut public, _, proof) = fixture();
        let spend_source_is_qualified = native_spend_fixture_source_is_qualified(
            "native_admission_checks_current_context_and_actual_proof_parse",
        );
        let admin_source_is_qualified = native_admin_fixture_source_is_qualified(
            "native_admission_checks_current_context_and_actual_proof_parse",
        );
        // Exercise the actual parser even when the native source gate stops first.
        assert!(crate::asset_spend_v1::proof_wire_receipt(&proof).is_err());
        let current = NativeAssetContextV1 {
            chain_id: public.chain_id,
            reference_parent_hash: public.reference_parent_hash,
            parent_height: public.parent_height,
            note_root: public.note_root,
            registry_root: public.registry_root,
        };
        assert_eq!(
            admission::preflight_spend_v1(&public, &proof, current),
            if spend_source_is_qualified {
                Err(E::NonCanonicalProof)
            } else {
                Err(E::SourceIdentity)
            }
        );
        assert_eq!(
            admission::verify_spend_v1(&public, &proof, current),
            if spend_source_is_qualified {
                Err(E::NonCanonicalProof)
            } else {
                Err(E::SourceIdentity)
            }
        );
        for field in 0..5 {
            let mut stale = current;
            match field {
                0 => stale.chain_id[0] ^= 1,
                1 => stale.reference_parent_hash[0] ^= 1,
                2 => stale.parent_height += 1,
                3 => stale.note_root[0] ^= 1,
                _ => stale.registry_root[0] ^= 1,
            }
            assert_eq!(
                admission::preflight_spend_v1(&public, &proof, stale),
                if spend_source_is_qualified {
                    Err(E::CurrentContext)
                } else {
                    Err(E::SourceIdentity)
                }
            );
        }
        public.policy_mode = 1;
        public.credential_depth = 16;
        assert_eq!(
            admission::preflight_spend_v1(&public, &proof, current),
            Err(E::UnsupportedProfile)
        );
        let admin = admin_fixture();
        let admin_current = NativeAssetContextV1 {
            registry_root: admin.registry_root,
            ..current
        };
        assert_eq!(
            admission::preflight_admin_v1(&admin, &proof, admin_current),
            if admin_source_is_qualified {
                Err(E::NonCanonicalProof)
            } else {
                Err(E::SourceIdentity)
            }
        );
        let stale = NativeAssetContextV1 {
            parent_height: 101,
            ..admin_current
        };
        assert_eq!(
            admission::preflight_admin_v1(&admin, &proof, stale),
            if admin_source_is_qualified {
                Err(E::CurrentContext)
            } else {
                Err(E::SourceIdentity)
            }
        );
    }
}
