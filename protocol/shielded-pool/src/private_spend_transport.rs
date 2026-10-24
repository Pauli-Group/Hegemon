//! Exact common private-spend carrier. Decoding is not proof acceptance or
//! release authority. Secret release is an explicit public proof-statement
//! output; private policy and recipient metadata are not serialized here.
use alloc::vec::Vec;
use transaction_core::hashing_pq::ciphertext_hash_bytes;
pub const MAGIC: [u8; 8] = *b"HGPSLC02";
pub const INNER_PROOF_MAGIC: [u8; 4] = *b"SMZL";
pub const PREAMBLE_BYTES: usize = 568;
pub const CIPHERTEXT_BYTES: usize = 2608;
/// Matches the compact candidate engine cap; framing is not proof acceptance.
pub const MAX_PROOF_BYTES: usize = 171_848;
pub const FIXED_BYTES: usize = PREAMBLE_BYTES + 2 * CIPHERTEXT_BYTES;
pub const MAX_CARRIER_BYTES: usize = FIXED_BYTES + MAX_PROOF_BYTES;
pub const ACTION_ID: u16 = 15;
pub const CIRCUIT_VERSION: u16 = 12;
pub const CRYPTO_SUITE: u16 = 7;
pub const PROFILE_ID: u8 = 12;
pub const DOMAIN_SET: u16 = 8;
// format1,circuit12,cryptoETA7,family1,action15,domain8,backend2,profile12,class1,reserved0.
pub const IDENTITY: [u8; 16] = [1, 0, 12, 0, 7, 0, 1, 0, 15, 0, 8, 0, 2, 12, 1, 0];
const P: u64 = 0xffff_ffff_0000_0001;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Length,
    ResourceLimit,
    Identity,
    Context,
    Noncanonical,
    Range,
    CiphertextBinding,
    ProofMagic,
    Allocation,
}
impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "private spend carrier: {self:?}")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for TransportError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedContext {
    chain_id: [u8; 32],
    relation_digest: [u8; 48],
}
impl ExpectedContext {
    pub fn new(chain_id: [u8; 32], relation_digest: [u8; 48]) -> Result<Self, TransportError> {
        if chain_id == [0; 32] || relation_digest == [0; 48] {
            return Err(TransportError::Context);
        }
        Ok(Self {
            chain_id,
            relation_digest,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicStatement {
    pub relation_digest: [u8; 48],
    pub chain_id: [u8; 32],
    pub reference_parent_hash: [u8; 32],
    pub reference_parent_height: u64,
    pub merkle_root: [u64; 7],
    pub fee: u64,
    pub nullifiers: [[u64; 7]; 2],
    pub commitments: [[u64; 7]; 2],
    pub ciphertext_commitments: [[u8; 48]; 2],
    /// Fixed public proof-statement fields, present in every private mode.
    pub secret_release: u64,
    pub released_secret: [u8; 32],
}
/// All slices borrow the exact supplied carrier. No reconstruction is substituted.
pub struct DecodedPrivateSpend<'a> {
    pub public: PublicStatement,
    pub raw: &'a [u8],
    pub preamble: &'a [u8; PREAMBLE_BYTES],
    pub ciphertexts: [&'a [u8; CIPHERTEXT_BYTES]; 2],
    pub proof: &'a [u8],
}
fn words<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u64; N], TransportError> {
    let mut w = [0; N];
    for x in &mut w {
        let end = at.checked_add(8).ok_or(TransportError::Length)?;
        *x = u64::from_le_bytes(
            bytes
                .get(*at..end)
                .ok_or(TransportError::Length)?
                .try_into()
                .map_err(|_| TransportError::Length)?,
        );
        if *x >= P {
            return Err(TransportError::Noncanonical);
        }
        *at = end;
    }
    Ok(w)
}
impl PublicStatement {
    pub fn preamble(&self) -> Result<[u8; PREAMBLE_BYTES], TransportError> {
        if self.relation_digest == [0; 48] || self.chain_id == [0; 32] {
            return Err(TransportError::Context);
        }
        if self.reference_parent_height >= 1 << 48 || self.fee >= 1 << 56 {
            return Err(TransportError::Range);
        }
        if self.secret_release > 1 {
            return Err(TransportError::Range);
        }
        if self.secret_release == 0 && self.released_secret != [0; 32] {
            return Err(TransportError::Noncanonical);
        }
        let mut out = [0; PREAMBLE_BYTES];
        out[..8].copy_from_slice(&MAGIC);
        out[8..24].copy_from_slice(&IDENTITY);
        out[24..72].copy_from_slice(&self.relation_digest);
        out[72..104].copy_from_slice(&self.chain_id);
        out[104..136].copy_from_slice(&self.reference_parent_hash);
        out[136..144].copy_from_slice(&self.reference_parent_height.to_le_bytes());
        let mut at = 144;
        let mut put = |w: &[u64]| -> Result<(), TransportError> {
            for x in w {
                if *x >= P {
                    return Err(TransportError::Noncanonical);
                }
                out[at..at + 8].copy_from_slice(&x.to_le_bytes());
                at += 8;
            }
            Ok(())
        };
        put(&self.merkle_root)?;
        put(&[self.fee])?;
        for n in &self.nullifiers {
            put(n)?;
        }
        for c in &self.commitments {
            put(c)?;
        }
        for h in &self.ciphertext_commitments {
            out[at..at + 48].copy_from_slice(h);
            at += 48;
        }
        out[at..at + 8].copy_from_slice(&self.secret_release.to_le_bytes());
        at += 8;
        out[at..at + 32].copy_from_slice(&self.released_secret);
        at += 32;
        debug_assert_eq!(at, PREAMBLE_BYTES);
        Ok(out)
    }
}
/// Consumes the entire carrier tail as proof. The engine must separately apply
/// its exact SMZL proof decoder; this framing parser does not verify proof internals.
pub fn decode_exact(
    expected: ExpectedContext,
    bytes: &[u8],
) -> Result<DecodedPrivateSpend<'_>, TransportError> {
    if bytes.len() > MAX_CARRIER_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    if bytes.len() < FIXED_BYTES + 4 {
        return Err(TransportError::Length);
    }
    let preamble: &[u8; PREAMBLE_BYTES] = bytes[..PREAMBLE_BYTES]
        .try_into()
        .map_err(|_| TransportError::Length)?;
    if preamble[..8] != MAGIC || preamble[8..24] != IDENTITY {
        return Err(TransportError::Identity);
    }
    let mut at = 136;
    let height = words::<1>(preamble, &mut at)?[0];
    let root = words(preamble, &mut at)?;
    let fee = words::<1>(preamble, &mut at)?[0];
    let nullifiers = [words(preamble, &mut at)?, words(preamble, &mut at)?];
    let commitments = [words(preamble, &mut at)?, words(preamble, &mut at)?];
    let ciphertext_commitments = [
        preamble[at..at + 48]
            .try_into()
            .map_err(|_| TransportError::Length)?,
        preamble[at + 48..at + 96]
            .try_into()
            .map_err(|_| TransportError::Length)?,
    ];
    at += 96;
    let secret_release = words::<1>(preamble, &mut at)?[0];
    // Secret bytes are not field limbs: all 256-bit preimages remain valid
    // when release is enabled, including byte strings above the field modulus.
    let released_secret = preamble[at..at + 32]
        .try_into()
        .map_err(|_| TransportError::Length)?;
    at += 32;
    debug_assert_eq!(at, PREAMBLE_BYTES);
    let public = PublicStatement {
        relation_digest: preamble[24..72]
            .try_into()
            .map_err(|_| TransportError::Length)?,
        chain_id: preamble[72..104]
            .try_into()
            .map_err(|_| TransportError::Length)?,
        reference_parent_hash: preamble[104..136]
            .try_into()
            .map_err(|_| TransportError::Length)?,
        reference_parent_height: height,
        merkle_root: root,
        fee,
        nullifiers,
        commitments,
        ciphertext_commitments,
        secret_release,
        released_secret,
    };
    if public.chain_id != expected.chain_id || public.relation_digest != expected.relation_digest {
        return Err(TransportError::Context);
    }
    if public.preamble()?.as_slice() != preamble {
        return Err(TransportError::Noncanonical);
    }
    let ciphertexts: [&[u8; CIPHERTEXT_BYTES]; 2] = [
        bytes[PREAMBLE_BYTES..PREAMBLE_BYTES + CIPHERTEXT_BYTES]
            .try_into()
            .map_err(|_| TransportError::Length)?,
        bytes[PREAMBLE_BYTES + CIPHERTEXT_BYTES..FIXED_BYTES]
            .try_into()
            .map_err(|_| TransportError::Length)?,
    ];
    for (i, c) in ciphertexts.iter().enumerate() {
        if ciphertext_hash_bytes(c.as_slice()) != public.ciphertext_commitments[i] {
            return Err(TransportError::CiphertextBinding);
        }
    }
    let proof = &bytes[FIXED_BYTES..];
    if proof[..4] != INNER_PROOF_MAGIC {
        return Err(TransportError::ProofMagic);
    }
    Ok(DecodedPrivateSpend {
        public,
        raw: bytes,
        preamble,
        ciphertexts,
        proof,
    })
}
pub fn encode(
    public: &PublicStatement,
    ciphertexts: [&[u8; CIPHERTEXT_BYTES]; 2],
    proof: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    if proof.len() < 4 {
        return Err(TransportError::Length);
    }
    if proof[..4] != INNER_PROOF_MAGIC {
        return Err(TransportError::ProofMagic);
    }
    let preamble = public.preamble()?;
    for (i, c) in ciphertexts.iter().enumerate() {
        if ciphertext_hash_bytes(c.as_slice()) != public.ciphertext_commitments[i] {
            return Err(TransportError::CiphertextBinding);
        }
    }
    let length = FIXED_BYTES
        .checked_add(proof.len())
        .ok_or(TransportError::ResourceLimit)?;
    let mut out = Vec::new();
    out.try_reserve_exact(length)
        .map_err(|_| TransportError::Allocation)?;
    out.extend_from_slice(&preamble);
    for c in ciphertexts {
        out.extend_from_slice(c);
    }
    out.extend_from_slice(proof);
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PublicStatement, [[u8; CIPHERTEXT_BYTES]; 2]) {
        let c = [[19; CIPHERTEXT_BYTES], [20; CIPHERTEXT_BYTES]];
        let s = PublicStatement {
            relation_digest: [1; 48],
            chain_id: [2; 32],
            reference_parent_hash: [3; 32],
            reference_parent_height: 7,
            merkle_root: [4; 7],
            fee: 2,
            nullifiers: [[5; 7], [6; 7]],
            commitments: [[7; 7], [8; 7]],
            ciphertext_commitments: [ciphertext_hash_bytes(&c[0]), ciphertext_hash_bytes(&c[1])],
            secret_release: 0,
            released_secret: [0; 32],
        };
        (s, c)
    }
    #[test]
    fn private_spend_transport_roundtrip_exact_borrow() {
        let (s, c) = fixture();
        let b = encode(&s, [&c[0], &c[1]], b"SMZLproof").unwrap();
        let d = decode_exact(
            ExpectedContext::new(s.chain_id, s.relation_digest).unwrap(),
            &b,
        )
        .unwrap();
        assert_eq!(d.public, s);
        assert_eq!(d.raw, b);
        assert_eq!(d.proof, b"SMZLproof");
        assert!(core::ptr::eq(d.raw.as_ptr(), b.as_ptr()));
        assert_eq!(d.ciphertexts[0], &c[0]);
        assert_eq!(b.len(), PREAMBLE_BYTES + 2 * CIPHERTEXT_BYTES + 9);
        assert_eq!(&b[..8], b"HGPSLC02");
        assert_eq!(u16::from_le_bytes(b[10..12].try_into().unwrap()), 12);
    }
    #[test]
    fn private_spend_transport_rejects_identity_context_and_field() {
        let (s, c) = fixture();
        let b = encode(&s, [&c[0], &c[1]], b"SMZL").unwrap();
        let e = ExpectedContext::new(s.chain_id, s.relation_digest).unwrap();
        for i in 0..24 {
            let mut x = b.clone();
            x[i] ^= 1;
            assert!(matches!(decode_exact(e, &x), Err(TransportError::Identity)));
        }
        assert!(matches!(
            decode_exact(
                ExpectedContext::new([9; 32], s.relation_digest).unwrap(),
                &b
            ),
            Err(TransportError::Context)
        ));
        let mut x = b.clone();
        x[144..152].copy_from_slice(&P.to_le_bytes());
        assert!(matches!(
            decode_exact(e, &x),
            Err(TransportError::Noncanonical)
        ));
    }
    #[test]
    fn private_spend_transport_release_roundtrip_preserves_all_256_bits() {
        let (mut statement, ciphertexts) = fixture();
        let expected = ExpectedContext::new(statement.chain_id, statement.relation_digest).unwrap();
        statement.secret_release = 1;
        for secret in [[0; 32], [0xff; 32], core::array::from_fn(|i| i as u8)] {
            statement.released_secret = secret;
            let encoded =
                encode(&statement, [&ciphertexts[0], &ciphertexts[1]], b"SMZLproof").unwrap();
            let decoded = decode_exact(expected, &encoded).unwrap();
            assert_eq!(decoded.public, statement);
            assert_eq!(&decoded.preamble[528..536], &1u64.to_le_bytes());
            assert_eq!(&decoded.preamble[536..568], &secret);
            assert_eq!(decoded.proof, b"SMZLproof");
        }
    }

    #[test]
    fn private_spend_transport_rejects_noncanonical_release_and_historical_mode() {
        let (mut statement, ciphertexts) = fixture();
        let expected = ExpectedContext::new(statement.chain_id, statement.relation_digest).unwrap();
        let encoded = encode(&statement, [&ciphertexts[0], &ciphertexts[1]], b"SMZL").unwrap();
        statement.secret_release = 2;
        assert!(matches!(
            encode(&statement, [&ciphertexts[0], &ciphertexts[1]], b"SMZL"),
            Err(TransportError::Range)
        ));
        let mut invalid_flag = encoded.clone();
        invalid_flag[528..536].copy_from_slice(&2u64.to_le_bytes());
        assert!(matches!(
            decode_exact(expected, &invalid_flag),
            Err(TransportError::Range)
        ));
        statement.secret_release = 0;
        for i in 0..32 {
            statement.released_secret = [0; 32];
            statement.released_secret[i] = 1;
            assert!(matches!(
                encode(&statement, [&ciphertexts[0], &ciphertexts[1]], b"SMZL"),
                Err(TransportError::Noncanonical)
            ));
            let mut unused_secret = encoded.clone();
            unused_secret[536 + i] = 1;
            assert!(matches!(
                decode_exact(expected, &unused_secret),
                Err(TransportError::Noncanonical)
            ));
        }
        let mut historical = encoded.clone();
        historical[..8].copy_from_slice(b"HGPSLC01");
        assert!(matches!(
            decode_exact(expected, &historical),
            Err(TransportError::Identity)
        ));
        historical[..8].copy_from_slice(&MAGIC);
        historical[10..12].copy_from_slice(&11u16.to_le_bytes());
        assert!(matches!(
            decode_exact(expected, &historical),
            Err(TransportError::Identity)
        ));
    }

    #[test]
    fn private_spend_transport_release_bytes_are_part_of_exact_public_statement() {
        let (mut statement, ciphertexts) = fixture();
        statement.secret_release = 1;
        statement.released_secret = [0x5a; 32];
        let expected = ExpectedContext::new(statement.chain_id, statement.relation_digest).unwrap();
        let encoded = encode(&statement, [&ciphertexts[0], &ciphertexts[1]], b"SMZL").unwrap();
        for i in 0..32 {
            let mut changed = encoded.clone();
            changed[536 + i] ^= 1;
            // Framing accepts another canonical preimage. Proof verification
            // must use this changed statement; parsing never authenticates it.
            let decoded = decode_exact(expected, &changed).unwrap();
            assert_ne!(decoded.public, statement);
            assert_eq!(
                decoded.public.released_secret[i],
                statement.released_secret[i] ^ 1
            );
            assert_eq!(decoded.raw, changed);
        }
        for offset in [24, 72] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(matches!(
                decode_exact(expected, &changed),
                Err(TransportError::Context)
            ));
        }
        let mut trailing = encoded;
        trailing.push(0);
        let decoded = decode_exact(expected, &trailing).unwrap();
        assert_eq!(decoded.proof, b"SMZL\0");
        // The exact SMZL verifier, not the framing parser, rejects proof tails.
    }

    #[test]
    fn private_spend_transport_binds_both_complete_ciphertexts() {
        let (s, c) = fixture();
        let b = encode(&s, [&c[0], &c[1]], b"SMZL").unwrap();
        let e = ExpectedContext::new(s.chain_id, s.relation_digest).unwrap();
        for i in [
            PREAMBLE_BYTES,
            PREAMBLE_BYTES + CIPHERTEXT_BYTES - 1,
            PREAMBLE_BYTES + CIPHERTEXT_BYTES,
            FIXED_BYTES - 1,
        ] {
            let mut x = b.clone();
            x[i] ^= 1;
            assert!(matches!(
                decode_exact(e, &x),
                Err(TransportError::CiphertextBinding)
            ));
        }
        assert!(encode(&s, [&c[1], &c[0]], b"SMZL").is_err());
    }
    #[test]
    fn private_spend_transport_compact_magic_and_cap_do_not_alias_historical_proofs() {
        let (statement, ciphertexts) = fixture();
        let expected = ExpectedContext::new(statement.chain_id, statement.relation_digest).unwrap();
        let mut proof = alloc::vec![0; MAX_PROOF_BYTES];
        proof[..4].copy_from_slice(b"SMZL");
        let encoded = encode(&statement, [&ciphertexts[0], &ciphertexts[1]], &proof).unwrap();
        assert_eq!(encoded.len(), 177_632);
        assert_eq!(decode_exact(expected, &encoded).unwrap().proof, proof);
        for historical_magic in [b"SMZD", b"SMZC", b"SMZE"] {
            proof[..4].copy_from_slice(historical_magic);
            assert!(matches!(
                encode(&statement, [&ciphertexts[0], &ciphertexts[1]], &proof),
                Err(TransportError::ProofMagic)
            ));
            let mut wrong = encoded.clone();
            wrong[FIXED_BYTES..FIXED_BYTES + 4].copy_from_slice(historical_magic);
            assert!(matches!(decode_exact(expected, &wrong), Err(TransportError::ProofMagic)));
        }
        proof[..4].copy_from_slice(b"SMZL");
        proof.push(0);
        assert!(matches!(
            encode(&statement, [&ciphertexts[0], &ciphertexts[1]], &proof),
            Err(TransportError::ResourceLimit)
        ));
        let mut too_long = encoded;
        too_long.push(0);
        assert!(matches!(decode_exact(expected, &too_long), Err(TransportError::ResourceLimit)));
    }

    #[test]
    fn private_spend_transport_rejects_short_and_over_cap() {
        let (s, c) = fixture();
        let b = encode(&s, [&c[0], &c[1]], b"SMZL").unwrap();
        let e = ExpectedContext::new(s.chain_id, s.relation_digest).unwrap();
        for n in [
            0,
            527,
            528,
            PREAMBLE_BYTES - 1,
            PREAMBLE_BYTES,
            FIXED_BYTES,
            FIXED_BYTES + 3,
        ] {
            assert!(decode_exact(e, &b[..n]).is_err());
        }
        let x = alloc::vec![0;MAX_CARRIER_BYTES+1];
        assert!(matches!(
            decode_exact(e, &x),
            Err(TransportError::ResourceLimit)
        ));
    }
}
