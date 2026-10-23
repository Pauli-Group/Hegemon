//! Exact self-contained HTLC carriers with separate development/strict identities.
//! Encoding and parsing never grant runtime authority or replace proof verification.
#![forbid(unsafe_code)]

use crate::{
    hashing_pq::ciphertext_hash_bytes,
    smallwood_htlc::{self, HtlcAction, HtlcStatement},
    TransactionCircuitError,
};

pub const MAGIC: &[u8; 8] = b"HGHTLC01";
pub const MAX_CIPHERTEXT_BYTES: usize = 16 * 1024;
pub const HEADER_BYTES: usize = 414;
pub const MAX_CARRIER_BYTES: usize =
    HEADER_BYTES + MAX_CIPHERTEXT_BYTES + smallwood_htlc::MAX_DEVELOPMENT_PROOF_BYTES;
pub const CANDIDATE_MAGIC: &[u8; 8] = b"HGHTLC02";
pub const CANDIDATE_HEADER_BYTES: usize = HEADER_BYTES + 3;
pub const CANDIDATE_CIPHERTEXT_BYTES: usize =
    crate::smallwood_poseidon2_v8_types::SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES;
pub const MAX_CANDIDATE_CARRIER_BYTES: usize =
    CANDIDATE_HEADER_BYTES + CANDIDATE_CIPHERTEXT_BYTES + smallwood_htlc::MAX_CANDIDATE_PROOF_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtlcCarrierProfile {
    Development,
    CandidateSmzc,
}
impl HtlcCarrierProfile {
    fn header_bytes(self) -> usize {
        match self {
            Self::Development => HEADER_BYTES,
            Self::CandidateSmzc => CANDIDATE_HEADER_BYTES,
        }
    }
    fn max_bytes(self) -> usize {
        match self {
            Self::Development => MAX_CARRIER_BYTES,
            Self::CandidateSmzc => MAX_CANDIDATE_CARRIER_BYTES,
        }
    }
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Development => MAGIC,
            Self::CandidateSmzc => CANDIDATE_MAGIC,
        }
    }
    fn validate_lengths(
        self,
        ciphertext: usize,
        proof: usize,
    ) -> Result<(), TransactionCircuitError> {
        let valid = match self {
            Self::Development => {
                (1..=MAX_CIPHERTEXT_BYTES).contains(&ciphertext)
                    && (1..=smallwood_htlc::MAX_DEVELOPMENT_PROOF_BYTES).contains(&proof)
            }
            Self::CandidateSmzc => {
                ciphertext == CANDIDATE_CIPHERTEXT_BYTES
                    && (4..=smallwood_htlc::MAX_CANDIDATE_PROOF_BYTES).contains(&proof)
            }
        };
        if !valid {
            return Err(error("HTLC carrier component length"));
        }
        Ok(())
    }
}

/// Proof and ciphertext are borrowed unchanged from the canonical carrier.
pub struct HtlcCarrier<'a> {
    pub profile: HtlcCarrierProfile,
    pub statement: HtlcStatement,
    pub ciphertext: &'a [u8],
    pub proof: &'a [u8],
    pub exact_bytes: &'a [u8],
}

fn error(message: &'static str) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolation(message)
}

pub fn encode(
    statement: &HtlcStatement,
    ciphertext: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    encode_profile(
        statement,
        ciphertext,
        proof,
        HtlcCarrierProfile::Development,
    )
}

pub fn encode_candidate(
    statement: &HtlcStatement,
    ciphertext: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    encode_profile(
        statement,
        ciphertext,
        proof,
        HtlcCarrierProfile::CandidateSmzc,
    )
}

pub fn candidate_max_carrier_bytes(
    statement: &HtlcStatement,
) -> Result<usize, TransactionCircuitError> {
    let proof = smallwood_htlc::candidate_proof_size_hint(statement)?;
    if proof > smallwood_htlc::MAX_CANDIDATE_PROOF_BYTES {
        return Err(error(
            "HTLC strict source projection exceeds independent cap",
        ));
    }
    Ok(CANDIDATE_HEADER_BYTES + CANDIDATE_CIPHERTEXT_BYTES + proof)
}

fn encode_profile(
    statement: &HtlcStatement,
    ciphertext: &[u8],
    proof: &[u8],
    profile: HtlcCarrierProfile,
) -> Result<Vec<u8>, TransactionCircuitError> {
    statement.validate_structure()?;
    profile.validate_lengths(ciphertext.len(), proof.len())?;
    if profile == HtlcCarrierProfile::CandidateSmzc
        && proof.get(..4) != Some(smallwood_htlc::CANDIDATE_PROOF_MAGIC.as_slice())
    {
        return Err(error("HTLC strict carrier requires SMZC proof"));
    }
    if ciphertext_hash_bytes(ciphertext) != statement.ciphertext_commitment {
        return Err(error("HTLC ciphertext binding"));
    }
    let mut bytes = Vec::with_capacity(profile.header_bytes() + ciphertext.len() + proof.len());
    bytes.extend_from_slice(profile.magic());
    bytes.extend_from_slice(&statement.version.to_le_bytes());
    bytes.extend_from_slice(&smallwood_htlc::relation_digest());
    if profile == HtlcCarrierProfile::CandidateSmzc {
        bytes.push(protocol_versioning::launch_candidate::HTLC_PROFILE_ID);
        bytes.extend_from_slice(
            &protocol_versioning::launch_candidate::HTLC_DOMAIN_SET.to_le_bytes(),
        );
    }
    bytes.push(match statement.action {
        HtlcAction::Lock => 0,
        HtlcAction::Claim => 1,
        HtlcAction::Refund => 2,
    });
    bytes.push(u8::from(statement.revealed_secret.is_some()));
    bytes.extend_from_slice(&statement.network_id);
    bytes.extend_from_slice(&statement.parent_hash);
    bytes.extend_from_slice(&statement.parent_height.to_le_bytes());
    for word in statement
        .merkle_root
        .into_iter()
        .chain(statement.nullifier)
        .chain(statement.output_commitment)
    {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(&statement.ciphertext_commitment);
    bytes.extend_from_slice(&statement.fee.to_le_bytes());
    bytes.extend_from_slice(&statement.revealed_secret.unwrap_or([0; 32]));
    bytes.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    debug_assert_eq!(bytes.len(), profile.header_bytes());
    bytes.extend_from_slice(ciphertext);
    bytes.extend_from_slice(proof);
    Ok(bytes)
}

pub fn decode_exact(bytes: &[u8]) -> Result<HtlcCarrier<'_>, TransactionCircuitError> {
    decode_profile(bytes, HtlcCarrierProfile::Development)
}

pub fn decode_candidate_exact(bytes: &[u8]) -> Result<HtlcCarrier<'_>, TransactionCircuitError> {
    decode_profile(bytes, HtlcCarrierProfile::CandidateSmzc)
}

/// Wallet storage can retain either explicitly tagged profile; runtime callers
/// must use decode_candidate_exact and source-owned authorization.
pub fn decode_wallet_exact(bytes: &[u8]) -> Result<HtlcCarrier<'_>, TransactionCircuitError> {
    match bytes.get(..8) {
        Some(magic) if magic == MAGIC => decode_exact(bytes),
        Some(magic) if magic == CANDIDATE_MAGIC => decode_candidate_exact(bytes),
        _ => Err(error("HTLC carrier magic")),
    }
}

fn decode_profile(
    bytes: &[u8],
    profile: HtlcCarrierProfile,
) -> Result<HtlcCarrier<'_>, TransactionCircuitError> {
    if bytes.len() < profile.header_bytes() || bytes.len() > profile.max_bytes() {
        return Err(error("HTLC carrier length"));
    }
    let mut cursor = Cursor { bytes, offset: 0 };
    if &cursor.take::<8>()? != profile.magic() {
        return Err(error("HTLC carrier magic"));
    }
    let version = u32::from_le_bytes(cursor.take()?);
    if cursor.take::<64>()? != smallwood_htlc::relation_digest() {
        return Err(error("HTLC carrier relation identity"));
    }
    if profile == HtlcCarrierProfile::CandidateSmzc
        && (cursor.take::<1>()?[0] != protocol_versioning::launch_candidate::HTLC_PROFILE_ID
            || u16::from_le_bytes(cursor.take()?)
                != protocol_versioning::launch_candidate::HTLC_DOMAIN_SET)
    {
        return Err(error("HTLC strict carrier profile or domain mismatch"));
    }
    let action = match cursor.take::<1>()?[0] {
        0 => HtlcAction::Lock,
        1 => HtlcAction::Claim,
        2 => HtlcAction::Refund,
        _ => return Err(error("HTLC carrier action")),
    };
    let disclosed = match cursor.take::<1>()?[0] {
        0 => false,
        1 => true,
        _ => return Err(error("HTLC carrier disclosure flag")),
    };
    let network_id = cursor.take()?;
    let parent_hash = cursor.take()?;
    let parent_height = u64::from_le_bytes(cursor.take()?);
    let merkle_root = cursor.digest()?;
    let nullifier = cursor.digest()?;
    let output_commitment = cursor.digest()?;
    let ciphertext_commitment = cursor.take()?;
    let fee = u64::from_le_bytes(cursor.take()?);
    let secret = cursor.take::<32>()?;
    if !disclosed && secret != [0; 32] {
        return Err(error("HTLC carrier hidden secret padding"));
    }
    let ciphertext_len = u32::from_le_bytes(cursor.take()?) as usize;
    let proof_len = u32::from_le_bytes(cursor.take()?) as usize;
    profile.validate_lengths(ciphertext_len, proof_len)?;
    let proof_start = profile
        .header_bytes()
        .checked_add(ciphertext_len)
        .ok_or(error("HTLC carrier overflow"))?;
    if proof_start.checked_add(proof_len) != Some(bytes.len()) {
        return Err(error("HTLC carrier trailing or truncated bytes"));
    }
    let statement = HtlcStatement {
        version,
        action,
        network_id,
        parent_hash,
        parent_height,
        merkle_root,
        nullifier,
        output_commitment,
        ciphertext_commitment,
        fee,
        revealed_secret: disclosed.then_some(secret),
    };
    statement.validate_structure()?;
    let ciphertext = &bytes[profile.header_bytes()..proof_start];
    if ciphertext_hash_bytes(ciphertext) != statement.ciphertext_commitment {
        return Err(error("HTLC ciphertext binding"));
    }
    let proof = &bytes[proof_start..];
    if profile == HtlcCarrierProfile::CandidateSmzc
        && proof.get(..4) != Some(smallwood_htlc::CANDIDATE_PROOF_MAGIC.as_slice())
    {
        return Err(error("HTLC strict carrier requires SMZC proof"));
    }
    Ok(HtlcCarrier {
        profile,
        statement,
        ciphertext,
        proof,
        exact_bytes: bytes,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], TransactionCircuitError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(error("HTLC carrier overflow"))?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(error("HTLC carrier truncation"))?
            .try_into()
            .map_err(|_| error("HTLC carrier truncation"))?;
        self.offset = end;
        Ok(result)
    }
    fn digest(&mut self) -> Result<[u64; 7], TransactionCircuitError> {
        let mut result = [0; 7];
        for word in &mut result {
            *word = u64::from_le_bytes(self.take()?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn statement() -> HtlcStatement {
        HtlcStatement {
            version: 1,
            action: HtlcAction::Lock,
            network_id: [1; 32],
            parent_hash: [2; 32],
            parent_height: 8,
            merkle_root: [3; 7],
            nullifier: [4; 7],
            output_commitment: [5; 7],
            ciphertext_commitment: ciphertext_hash_bytes(b"ciphertext"),
            fee: 1,
            revealed_secret: None,
        }
    }
    #[test]
    fn development_carrier_preserves_proof_and_rejects_malleability() {
        // Framing-only fixture: these bytes are deliberately not a real proof.
        let raw = encode(&statement(), b"ciphertext", b"unverified-proof").unwrap();
        let decoded = decode_exact(&raw).unwrap();
        assert_eq!(decoded.proof, b"unverified-proof");
        assert_eq!(
            encode(&decoded.statement, decoded.ciphertext, decoded.proof).unwrap(),
            raw
        );
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(decode_exact(&trailing).is_err());
        for offset in [0, 12, 77, HEADER_BYTES - 9, HEADER_BYTES] {
            let mut bad = raw.clone();
            bad[offset] ^= 1;
            assert!(decode_exact(&bad).is_err(), "offset={offset}");
        }
        for n in [0, 7, HEADER_BYTES - 1, raw.len() - 1] {
            assert!(decode_exact(&raw[..n]).is_err());
        }
    }

    #[test]
    fn candidate_carrier_is_distinct_exact_and_uses_native_ciphertext_size() {
        // Framing-only SMZC marker. A runtime verifier must still reject this
        // fixture as an invalid proof; a parser never grants proof authority.
        let proof = b"SMZC-invalid-framing-fixture";
        let ciphertext = vec![42; CANDIDATE_CIPHERTEXT_BYTES];
        let mut statement = statement();
        statement.ciphertext_commitment = ciphertext_hash_bytes(&ciphertext);
        let raw = encode_candidate(&statement, &ciphertext, proof).unwrap();
        let decoded = decode_candidate_exact(&raw).unwrap();
        assert_eq!(decoded.profile, HtlcCarrierProfile::CandidateSmzc);
        assert_eq!(decoded.proof, proof);
        assert_eq!(decoded.exact_bytes.as_ptr(), raw.as_ptr());
        assert_eq!(
            decoded.proof.as_ptr(),
            raw[CANDIDATE_HEADER_BYTES + ciphertext.len()..].as_ptr()
        );
        assert_eq!(
            encode_candidate(&decoded.statement, decoded.ciphertext, decoded.proof).unwrap(),
            raw
        );
        assert!(decode_exact(&raw).is_err());
        assert!(smallwood_htlc::verify_candidate(&statement, decoded.proof).is_err());

        let development = encode(&statement, &ciphertext, b"SMZ1-invalid-fixture").unwrap();
        assert!(decode_candidate_exact(&development).is_err());
        assert!(encode_candidate(&statement, &ciphertext, b"SMZ1-invalid-fixture").is_err());
        let mut relabelled = development.clone();
        relabelled[..8].copy_from_slice(CANDIDATE_MAGIC);
        assert!(decode_candidate_exact(&relabelled).is_err());
        assert_eq!(
            decode_wallet_exact(&development).unwrap().profile,
            HtlcCarrierProfile::Development
        );
        assert_eq!(
            decode_wallet_exact(&raw).unwrap().profile,
            HtlcCarrierProfile::CandidateSmzc
        );

        for size in [
            0,
            CANDIDATE_CIPHERTEXT_BYTES - 1,
            CANDIDATE_CIPHERTEXT_BYTES + 1,
        ] {
            let wrong_ciphertext = vec![42; size];
            let mut wrong_statement = statement.clone();
            wrong_statement.ciphertext_commitment = ciphertext_hash_bytes(&wrong_ciphertext);
            assert!(encode_candidate(&wrong_statement, &wrong_ciphertext, proof).is_err());
        }
        for offset in [
            0,
            12,
            76,
            77,
            78,
            80,
            CANDIDATE_HEADER_BYTES - 9,
            CANDIDATE_HEADER_BYTES,
            CANDIDATE_HEADER_BYTES + ciphertext.len(),
        ] {
            let mut bad = raw.clone();
            bad[offset] ^= 1;
            assert!(decode_candidate_exact(&bad).is_err(), "offset={offset}");
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(decode_candidate_exact(&trailing).is_err());
        for size in [0, 7, CANDIDATE_HEADER_BYTES - 1, raw.len() - 1] {
            assert!(decode_candidate_exact(&raw[..size]).is_err());
        }
        for offset in [CANDIDATE_HEADER_BYTES - 8, CANDIDATE_HEADER_BYTES - 4] {
            let mut bad = raw.clone();
            bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(decode_candidate_exact(&bad).is_err());
        }
    }

    #[test]
    fn strict_source_projection_stays_inside_independent_carrier_cap() {
        for action in [HtlcAction::Lock, HtlcAction::Claim, HtlcAction::Refund] {
            let mut statement = statement();
            statement.action = action;
            let projected = candidate_max_carrier_bytes(&statement).unwrap();
            assert!(projected > CANDIDATE_HEADER_BYTES + CANDIDATE_CIPHERTEXT_BYTES);
            assert!(projected <= MAX_CANDIDATE_CARRIER_BYTES);
            // The native PendingAction wrapper has 225 fixed bytes. Preserve
            // the existing wallet bound instead of silently increasing it.
            assert!(projected + 225 < 2 * 1024 * 1024 + 16 * 1024);
        }
    }
}
