//! Fresh recovery envelope only. Structural decoding is NOT proof verification.
//! Ledger MUST verify spend+both capsules/admin and authenticate CURRENT rows.
#![forbid(unsafe_code)]
use crate::{
    asset_recovery_admin_v1 as admin, asset_recovery_capsule_v1 as capsule,
    asset_recovery_spend_v1 as spend, asset_spend_v1::AssetSpendPublic,
};
use transaction_core::asset_recovery_v1::{
    self as recovery, RecoveryContextV1, RecoveryControlsV1, RecoveryDescriptorV1,
    RecoveryPowersV1, RecoveryRowV1,
};
use transaction_core::hashing_pq::ciphertext_hash_bytes;

pub const MAGIC: [u8; 8] = *b"HGARCV02";
pub const VERSION: u16 = 2;
pub const SPEND: u8 = 1;
pub const ADMIN: u8 = 2;
pub const CIPHERTEXT_BYTES: usize = 2608;
pub const MAX_PROOF_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CAPSULE_BUNDLE_BYTES: usize = capsule::MAX_CAPSULE_BUNDLE_BYTES;
/// One spend plus two capsules, each containing two actual SMZR proofs.
pub const PROOF_UNITS: usize = 1 + 2 * capsule::SEGMENT_COUNT;
pub const SPEND_FIXED_BYTES: usize =
    16 + 128 + 12 + (spend::PUBLIC_WORDS + 2 * capsule::PUBLIC_WORDS) * 8 + 3 * CIPHERTEXT_BYTES;
pub const ADMIN_FIXED_BYTES: usize = 16 + 64 + 4 + 128 * 8;
pub const MAX_SPEND_ACTION_BYTES: usize =
    SPEND_FIXED_BYTES + MAX_PROOF_BYTES + 2 * MAX_CAPSULE_BUNDLE_BYTES;
pub const MAX_ADMIN_ACTION_BYTES: usize = ADMIN_FIXED_BYTES + MAX_PROOF_BYTES;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    Length,
    Truncated,
    Header,
    Source,
    Canonical,
    Public,
    Proof,
    Ciphertext,
    CapsuleBinding,
}
impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "recovery wire: {self:?}")
    }
}
impl std::error::Error for WireError {}
type Result<T> = core::result::Result<T, WireError>;
pub struct CapsuleRef<'a> {
    pub public: capsule::AssetRecoveryCapsulePublicV1,
    pub proof: &'a [u8],
}
pub struct SpendRef<'a> {
    pub public: spend::Public,
    pub ciphertexts: [&'a [u8; CIPHERTEXT_BYTES]; 3],
    pub proof: &'a [u8],
    pub capsules: [CapsuleRef<'a>; 2],
}
pub struct AdminRef<'a> {
    pub public: admin::Public,
    pub proof: &'a [u8],
}
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(WireError::Length)?;
        let x = self.b.get(self.at..end).ok_or(WireError::Truncated)?;
        self.at = end;
        Ok(x)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn words<const N: usize>(&mut self) -> Result<[u64; N]> {
        let b = self.take(N * 8)?;
        let mut w = [0; N];
        for (x, b) in w.iter_mut().zip(b.chunks_exact(8)) {
            *x = u64::from_le_bytes(b.try_into().unwrap());
            if *x >= hegemon_field::GOLDILOCKS_MODULUS {
                return Err(WireError::Canonical);
            }
        }
        Ok(w)
    }
}
struct Words<'a> {
    w: &'a [u64],
    at: usize,
}
impl<'a> Words<'a> {
    fn word(&mut self) -> Result<u64> {
        let x = *self.w.get(self.at).ok_or(WireError::Truncated)?;
        self.at += 1;
        if x >= hegemon_field::GOLDILOCKS_MODULUS {
            return Err(WireError::Canonical);
        }
        Ok(x)
    }
    fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.word()?).map_err(|_| WireError::Canonical)
    }
    fn u8(&mut self) -> Result<u8> {
        u8::try_from(self.word()?).map_err(|_| WireError::Canonical)
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.word()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::Canonical),
        }
    }
    fn digest(&mut self) -> Result<[u64; 7]> {
        let mut d = [0; 7];
        for x in &mut d {
            *x = self.word()?
        }
        Ok(d)
    }
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        if N % 4 != 0 {
            return Err(WireError::Length);
        }
        let mut b = [0; N];
        for x in b.chunks_exact_mut(4) {
            x.copy_from_slice(&self.u32()?.to_le_bytes())
        }
        Ok(b)
    }
    fn powers(&mut self) -> Result<RecoveryPowersV1> {
        let b = self.word()?;
        if b > 3 {
            return Err(WireError::Canonical);
        }
        Ok(RecoveryPowersV1 {
            transfer: b & 1 != 0,
            burn: b & 2 != 0,
        })
    }
    fn controls(&mut self) -> Result<RecoveryControlsV1> {
        Ok(RecoveryControlsV1 {
            epoch: self.word()?,
            delegate_action_commitment: self.digest()?,
            revoked: self.boolean()?,
            powers: self.powers()?,
            note_freeze_root: self.digest()?,
        })
    }
}
pub fn encode_recovery_row(chain: [u8; 32], row: &RecoveryRowV1) -> Result<[u64; 48]> {
    row.validate().map_err(|_| WireError::Public)?;
    let mut w =
        recovery::descriptor_words(&row.descriptor, chain).map_err(|_| WireError::Public)?;
    w.extend(recovery::controls_words(&row.controls).map_err(|_| WireError::Public)?);
    w.try_into().map_err(|_| WireError::Length)
}
pub fn decode_recovery_row(w: &[u64; 48]) -> Result<([u8; 32], RecoveryRowV1)> {
    let mut r = Words { w, at: 0 };
    let chain = r.bytes()?;
    let descriptor = RecoveryDescriptorV1 {
        asset_id: r.u32()?,
        stable_policy_id: r.digest()?,
        policy_admin_commitment: r.digest()?,
        archive_key_commitment: r.digest()?,
        maximum_powers: r.powers()?,
    };
    let row = RecoveryRowV1 {
        descriptor,
        controls: r.controls()?,
    };
    if encode_recovery_row(chain, &row)? != *w {
        return Err(WireError::Canonical);
    }
    Ok((chain, row))
}
// Copied field order from asset_spend_v1_wire::decode_public; old private API
// and old source are unchanged. Checked readers replace infallible word reads.
pub fn decode_base_public(w: &[u64; 134]) -> Result<AssetSpendPublic> {
    let mut r = Words { w, at: 0 };
    let p = AssetSpendPublic {
        chain_id: r.bytes()?,
        reference_parent_hash: r.bytes()?,
        parent_height: r.word()?,
        note_root: r.digest()?,
        registry_root: r.digest()?,
        asset_id: r.u32()?,
        policy_version: r.u32()?,
        credential_root: r.digest()?,
        credential_depth: r.u8()?,
        frozen: r.boolean()?,
        mint_enabled: r.boolean()?,
        issuer_commitment: r.digest()?,
        operation: r.u8()?,
        magnitude: r.word()?,
        fee: r.word()?,
        nullifiers: [r.digest()?, r.digest()?],
        commitments: [r.digest()?, r.digest()?, r.digest()?],
        ciphertext_commitments: [r.bytes()?, r.bytes()?, r.bytes()?],
        policy_mode: r.u8()?,
        secret_release: u64::from(r.boolean()?),
        released_secret: r.bytes()?,
    };
    p.validate_structure().map_err(|_| WireError::Public)?;
    if p.nullifiers
        .iter()
        .chain(p.commitments.iter())
        .any(|d| *d == [0; 7])
        || (p.operation == crate::asset_spend_v1::TRANSFER && p.magnitude != 0)
        || (p.operation != crate::asset_spend_v1::TRANSFER && p.magnitude == 0)
    {
        return Err(WireError::Public);
    }
    if p.words() != *w {
        return Err(WireError::Canonical);
    }
    Ok(p)
}
pub fn decode_spend_public(w: &[u64; 182]) -> Result<spend::Public> {
    let base = decode_base_public(w[..134].try_into().unwrap())?;
    let (chain, row) = decode_recovery_row(w[134..].try_into().unwrap())?;
    if chain != base.chain_id {
        return Err(WireError::Public);
    }
    let p = spend::Public { base, row };
    if p.words().map_err(|_| WireError::Public)?.as_slice() != w {
        return Err(WireError::Canonical);
    }
    Ok(p)
}
pub fn decode_capsule_public(
    w: &[u64; capsule::PUBLIC_WORDS],
) -> Result<capsule::AssetRecoveryCapsulePublicV1> {
    let mut r = Words { w, at: 0 };
    let mut p = capsule::AssetRecoveryCapsulePublicV1 {
        chain_id: r.bytes()?,
        asset_id: r.u32()?,
        stable_policy_id: r.digest()?,
        archive_key_commitment: r.digest()?,
        note_commitment: r.digest()?,
        ciphertext: [0; capsule::CIPHERTEXT_BYTES],
    };
    let _derived_context: [u8; 32] = r.bytes()?;
    p.ciphertext = r.bytes()?;
    if p.words().map_err(|_| WireError::Public)? != *w {
        return Err(WireError::Canonical);
    }
    Ok(p)
}
pub fn decode_admin_public(w: &[u64; 128]) -> Result<admin::Public> {
    let mut rowwords = [0; 48];
    rowwords[..31].copy_from_slice(&w[..31]);
    rowwords[31..].copy_from_slice(&w[40..57]);
    let (chain, before) = decode_recovery_row(&rowwords)?;
    let mut r = Words { w, at: 31 };
    let parent_hash = r.bytes()?;
    let parent_height = r.word()?;
    r.at = 57;
    let after = r.controls()?;
    let context = RecoveryContextV1 {
        chain_id: chain,
        parent_hash,
        parent_height,
        row_commitment: r.digest()?,
    };
    let expires_at = r.word()?;
    let action_intent = r.digest()?;
    let active = r.boolean()?;
    let position = r.u32()?;
    let note_commitment = r.digest()?;
    let before_frozen = r.boolean()?;
    let after_frozen = r.boolean()?;
    let freeze = if active {
        Some(admin::FreezeMutation {
            position,
            note_commitment,
            before_frozen,
            after_frozen,
        })
    } else {
        None
    };
    let p = admin::Public {
        context,
        before,
        after,
        expires_at,
        action_intent,
        freeze,
    };
    if p.words().map_err(|_| WireError::Public)? != *w {
        return Err(WireError::Canonical);
    }
    Ok(p)
}
fn proof(p: &[u8], route: u8, source: [u8; 64]) -> Result<()> {
    crate::asset_recovery_backend_v1::check_component_envelope(p, route, &source)
        .map_err(|_| WireError::Proof)
}
fn capsule_proof(p: &[u8]) -> Result<()> {
    capsule::bundle_components(p)
        .map(|_| ())
        .map_err(|_| WireError::Proof)
}
fn header(r: &mut Reader<'_>, kind: u8, fixed: usize, max: usize) -> Result<()> {
    if r.b.len() < fixed || r.b.len() > max {
        return Err(WireError::Length);
    }
    if r.take(8)? != MAGIC
        || r.take(2)? != VERSION.to_le_bytes()
        || r.take(2)? != [kind, 0]
        || r.u32()? as usize != r.b.len()
    {
        return Err(WireError::Header);
    }
    Ok(())
}
fn source(r: &mut Reader<'_>, expected: [u8; 64]) -> Result<()> {
    if r.take(64)? != expected {
        return Err(WireError::Source);
    }
    Ok(())
}
fn lengths(r: &mut Reader<'_>, caps: &[usize], fixed: usize) -> Result<[usize; 3]> {
    let mut lens = [0; 3];
    let mut total = fixed;
    for (l, cap) in lens.iter_mut().zip(caps) {
        *l = r.u32()? as usize;
        if !(84..=*cap).contains(l) {
            return Err(WireError::Proof);
        }
        total = total.checked_add(*l).ok_or(WireError::Length)?
    }
    if total != r.b.len() {
        return Err(WireError::Length);
    }
    Ok(lens)
}
fn capsule_binding(
    p: &spend::Public,
    c: &capsule::AssetRecoveryCapsulePublicV1,
    slot: usize,
) -> Result<()> {
    if c.chain_id != p.base.chain_id
        || c.asset_id != p.base.asset_id
        || c.stable_policy_id != p.row.descriptor.stable_policy_id
        || c.archive_key_commitment != p.row.descriptor.archive_key_commitment
        || c.note_commitment != p.base.commitments[slot]
    {
        return Err(WireError::CapsuleBinding);
    }
    Ok(())
}
pub fn decode_spend_ref(bytes: &[u8]) -> Result<SpendRef<'_>> {
    let mut r = Reader { b: bytes, at: 0 };
    header(&mut r, SPEND, SPEND_FIXED_BYTES, MAX_SPEND_ACTION_BYTES)?;
    source(&mut r, spend::relation_digest())?;
    source(&mut r, capsule::relation_digest())?;
    let lens = lengths(
        &mut r,
        &[
            MAX_PROOF_BYTES,
            MAX_CAPSULE_BUNDLE_BYTES,
            MAX_CAPSULE_BUNDLE_BYTES,
        ],
        SPEND_FIXED_BYTES,
    )?;
    let public = decode_spend_public(&r.words()?)?;
    let ciphertexts: [&[u8; CIPHERTEXT_BYTES]; 3] = [
        r.take(CIPHERTEXT_BYTES)?.try_into().unwrap(),
        r.take(CIPHERTEXT_BYTES)?.try_into().unwrap(),
        r.take(CIPHERTEXT_BYTES)?.try_into().unwrap(),
    ];
    for (i, c) in ciphertexts.iter().enumerate() {
        if ciphertext_hash_bytes(*c) != public.base.ciphertext_commitments[i] {
            return Err(WireError::Ciphertext);
        }
    }
    let a = decode_capsule_public(&r.words()?)?;
    let b = decode_capsule_public(&r.words()?)?;
    capsule_binding(&public, &a, 0)?;
    capsule_binding(&public, &b, 1)?;
    let p = r.take(lens[0])?;
    let ap = r.take(lens[1])?;
    let bp = r.take(lens[2])?;
    proof(p, 1, spend::relation_digest())?;
    capsule_proof(ap)?;
    capsule_proof(bp)?;
    if r.at != bytes.len() {
        return Err(WireError::Length);
    }
    Ok(SpendRef {
        public,
        ciphertexts,
        proof: p,
        capsules: [
            CapsuleRef {
                public: a,
                proof: ap,
            },
            CapsuleRef {
                public: b,
                proof: bp,
            },
        ],
    })
}
pub fn decode_admin_ref(bytes: &[u8]) -> Result<AdminRef<'_>> {
    let mut r = Reader { b: bytes, at: 0 };
    header(&mut r, ADMIN, ADMIN_FIXED_BYTES, MAX_ADMIN_ACTION_BYTES)?;
    source(&mut r, admin::relation_digest())?;
    let lens = lengths(&mut r, &[MAX_PROOF_BYTES], ADMIN_FIXED_BYTES)?;
    let public = decode_admin_public(&r.words()?)?;
    let p = r.take(lens[0])?;
    proof(p, 3, admin::relation_digest())?;
    if r.at != bytes.len() {
        return Err(WireError::Length);
    }
    Ok(AdminRef { public, proof: p })
}
fn push_header(b: &mut Vec<u8>, kind: u8, total: usize) {
    b.extend(MAGIC);
    b.extend(VERSION.to_le_bytes());
    b.extend([kind, 0]);
    b.extend((total as u32).to_le_bytes())
}
fn push_words(b: &mut Vec<u8>, w: &[u64]) {
    for x in w {
        b.extend(x.to_le_bytes())
    }
}
pub fn encode_spend(
    p: &spend::Public,
    ciphertexts: &[[u8; CIPHERTEXT_BYTES]; 3],
    p_proof: &[u8],
    capsules: [(&capsule::AssetRecoveryCapsulePublicV1, &[u8]); 2],
) -> Result<Vec<u8>> {
    proof(p_proof, 1, spend::relation_digest())?;
    capsule_proof(capsules[0].1)?;
    capsule_proof(capsules[1].1)?;
    let total = [p_proof.len(), capsules[0].1.len(), capsules[1].1.len()]
        .into_iter()
        .try_fold(SPEND_FIXED_BYTES, |n, len| n.checked_add(len))
        .ok_or(WireError::Length)?;
    if total > MAX_SPEND_ACTION_BYTES {
        return Err(WireError::Length);
    }
    let mut b = Vec::with_capacity(total);
    push_header(&mut b, SPEND, total);
    b.extend(spend::relation_digest());
    b.extend(capsule::relation_digest());
    for x in [p_proof, capsules[0].1, capsules[1].1] {
        b.extend((x.len() as u32).to_le_bytes())
    }
    push_words(&mut b, &p.words().map_err(|_| WireError::Public)?);
    for x in ciphertexts {
        b.extend(x)
    }
    for (c, _) in capsules {
        push_words(&mut b, &c.words().map_err(|_| WireError::Public)?)
    }
    b.extend(p_proof);
    for (_, proof) in capsules {
        b.extend(proof)
    }
    decode_spend_ref(&b)?;
    Ok(b)
}
pub fn encode_admin(p: &admin::Public, p_proof: &[u8]) -> Result<Vec<u8>> {
    proof(p_proof, 3, admin::relation_digest())?;
    let total = ADMIN_FIXED_BYTES + p_proof.len();
    let mut b = Vec::with_capacity(total);
    push_header(&mut b, ADMIN, total);
    b.extend(admin::relation_digest());
    b.extend((p_proof.len() as u32).to_le_bytes());
    push_words(&mut b, &p.words().map_err(|_| WireError::Public)?);
    b.extend(p_proof);
    decode_admin_ref(&b)?;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Syntactically exact envelopes only, NEVER valid cryptographic proofs.
    fn fake(route: u8, source: [u8; 64]) -> Vec<u8> {
        let mut p = b"SMZR".to_vec();
        p.extend(1u16.to_le_bytes());
        p.extend([route, 0]);
        p.extend(source);
        p.extend(4u32.to_le_bytes());
        p.extend([0; 4]);
        p.extend(b"SMZE");
        p
    }
    fn fake_capsule() -> Vec<u8> {
        let mut b = b"SMRC".to_vec();
        b.extend(1u16.to_le_bytes());
        b.extend([2, 0]);
        for _ in 0..2 {
            b.extend(84u32.to_le_bytes());
        }
        for i in 0..2 {
            b.extend(fake(
                2,
                capsule::segment_relation_digest(capsule::relation_digest(), i).unwrap(),
            ));
        }
        b
    }
    fn fixture() -> (
        spend::Public,
        [[u8; CIPHERTEXT_BYTES]; 3],
        [capsule::AssetRecoveryCapsulePublicV1; 2],
    ) {
        let (mut p, _) = spend::fixtures::fixture(crate::asset_spend_v1::TRANSFER, false).unwrap();
        let c = [
            [1; CIPHERTEXT_BYTES],
            [2; CIPHERTEXT_BYTES],
            [3; CIPHERTEXT_BYTES],
        ];
        p.base.ciphertext_commitments = c.each_ref().map(|x| ciphertext_hash_bytes(x));
        let caps = core::array::from_fn(|i| capsule::AssetRecoveryCapsulePublicV1 {
            chain_id: p.base.chain_id,
            asset_id: p.base.asset_id,
            stable_policy_id: p.row.descriptor.stable_policy_id,
            archive_key_commitment: p.row.descriptor.archive_key_commitment,
            note_commitment: p.base.commitments[i],
            ciphertext: [i as u8; capsule::CIPHERTEXT_BYTES],
        });
        (p, c, caps)
    }
    #[test]
    fn structural_spend_roundtrip_and_rejections_not_proof_verification() {
        let (p, c, caps) = fixture();
        let primary = fake(1, spend::relation_digest());
        let bundle = fake_capsule();
        let b = encode_spend(
            &p,
            &c,
            primary.as_slice(),
            [(&caps[0], bundle.as_slice()), (&caps[1], bundle.as_slice())],
        )
        .unwrap();
        assert_eq!(
            b.len(),
            SPEND_FIXED_BYTES + primary.len() + 2 * bundle.len()
        );
        assert_eq!(PROOF_UNITS, 5);
        let mut old_wire = b.clone();
        old_wire[..8].copy_from_slice(b"HGARCV01");
        old_wire[8..10].copy_from_slice(&1u16.to_le_bytes());
        assert!(decode_spend_ref(&old_wire).is_err());
        let r = decode_spend_ref(&b).unwrap();
        assert_eq!(r.public, p);
        assert_eq!(r.proof, primary.as_slice());
        assert!(r.capsules[0].public == caps[0]);
        for end in [0, 7, 15, 80, 144, 155, 156, 1000, b.len() - 1] {
            assert!(decode_spend_ref(&b[..end]).is_err())
        }
        for at in [
            0,
            8,
            10,
            11,
            16,
            80,
            144,
            148,
            152,
            SPEND_FIXED_BYTES,
            SPEND_FIXED_BYTES + 4,
            SPEND_FIXED_BYTES + 8,
        ] {
            let mut bad = b.clone();
            bad[at] ^= 0x80;
            assert!(decode_spend_ref(&bad).is_err(), "offset{at}")
        }
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(decode_spend_ref(&trailing).is_err());
        assert!(decode_admin_ref(&b).is_err());
        let mut wrong = caps[0].clone();
        wrong.asset_id += 1;
        assert!(encode_spend(
            &p,
            &c,
            primary.as_slice(),
            [(&wrong, bundle.as_slice()), (&caps[1], bundle.as_slice())]
        )
        .is_err());
        assert!(encode_spend(
            &p,
            &c,
            primary.as_slice(),
            [(&caps[1], bundle.as_slice()), (&caps[0], bundle.as_slice())]
        )
        .is_err());
        assert!(encode_spend(
            &p,
            &c,
            primary.as_slice(),
            [(&caps[0], b""), (&caps[1], bundle.as_slice())]
        )
        .is_err());
        let mut zero_len = b.clone();
        zero_len[148..152].copy_from_slice(&0u32.to_le_bytes());
        assert!(decode_spend_ref(&zero_len).is_err());
        // Rewrapping an old 98-word capsule body with current source/header
        // cannot bypass the exact 82-word fixed schema. Framing rejection only.
        let mut old_shape = b.clone();
        let capstart = 16 + 128 + 12 + spend::PUBLIC_WORDS * 8 + 3 * CIPHERTEXT_BYTES;
        old_shape.splice(
            capstart + capsule::PUBLIC_WORDS * 8..capstart + capsule::PUBLIC_WORDS * 8,
            [0u8; (98 - capsule::PUBLIC_WORDS) * 8],
        );
        let old_len = old_shape.len() as u32;
        old_shape[12..16].copy_from_slice(&old_len.to_le_bytes());
        assert!(matches!(
            decode_spend_ref(&old_shape),
            Err(WireError::Length)
        ));
        let mut wrong_context = b.clone();
        wrong_context[capstart + 30 * 8] ^= 1;
        assert!(decode_spend_ref(&wrong_context).is_err());
        let mut cipher = c;
        cipher[0][0] ^= 1;
        assert!(encode_spend(
            &p,
            &cipher,
            primary.as_slice(),
            [(&caps[0], bundle.as_slice()), (&caps[1], bundle.as_slice())]
        )
        .is_err());
    }
    #[test]
    fn shared_row_strict_roundtrip_and_aliases() {
        let (p, _, _) = fixture();
        let w = encode_recovery_row(p.base.chain_id, &p.row).unwrap();
        let (chain, row) = decode_recovery_row(&w).unwrap();
        assert_eq!(chain, p.base.chain_id);
        assert_eq!(row, p.row);
        for (at, value) in [
            (0, 1u64 << 32),
            (8, 1u64 << 32),
            (30, 4),
            (31, 1u64 << 48),
            (39, 2),
            (40, 4),
            (47, hegemon_field::GOLDILOCKS_MODULUS),
        ] {
            let mut bad = w;
            bad[at] = value;
            assert!(decode_recovery_row(&bad).is_err())
        }
    }
    #[test]
    fn capsule_derived_context_and_ct_u32_aliases() {
        let (_, _, caps) = fixture();
        let w = caps[0].words().unwrap();
        assert!(decode_capsule_public(&w).unwrap() == caps[0]);
        for (at, value) in [(30, w[30] ^ 1), (38, 1u64 << 32), (8, 1u64 << 32)] {
            let mut bad = w;
            bad[at] = value;
            assert!(decode_capsule_public(&bad).is_err())
        }
    }
    #[test]
    fn structural_admin_roundtrip_padding_and_crossroute() {
        let (p, _, _) = fixture();
        let mut after = p.row.controls;
        after.epoch += 1;
        let a = admin::Public {
            context: RecoveryContextV1 {
                chain_id: p.base.chain_id,
                parent_hash: [9; 32],
                parent_height: 40,
                row_commitment: p.row.commitment(p.base.chain_id).unwrap(),
            },
            before: p.row,
            after,
            expires_at: 41,
            action_intent: [1; 7],
            freeze: None,
        };
        let primary = fake(3, admin::relation_digest());
        let b = encode_admin(&a, &primary).unwrap();
        assert_eq!(decode_admin_ref(&b).unwrap().public, a);
        assert!(decode_spend_ref(&b).is_err());
        let mut w = a.words().unwrap();
        w[123] = 1;
        assert!(decode_admin_public(&w).is_err());
        let mut w = a.words().unwrap();
        w[90] = 1;
        assert!(decode_admin_public(&w).is_err());
        for end in [0, 15, 80, 84, b.len() - 1] {
            assert!(decode_admin_ref(&b[..end]).is_err())
        }
        let mut bad = b;
        bad[16] ^= 1;
        assert!(decode_admin_ref(&bad).is_err());
    }
}
