//! Exact transport boundary for the dormant SmallWood V5 envelope.
//!
//! The proof artifact is one self-contained `SWV5` byte string.  Wallet/RPC,
//! peer relay, mempool, mining, block, restart, sync, and reorg code must move
//! that string as bytes; none of those layers may decode and reconstruct a
//! different proof representation.  This module owns only the small SCALE
//! action wrapper used to carry those bytes.  It does not authorize V5.

use alloc::vec::Vec;
use core::fmt;

use codec::{Decode, Encode};

pub const SMALLWOOD_V5_TRANSPORT_MAGIC: [u8; 4] = *b"SWV5";
pub const SMALLWOOD_V5_TRANSPORT_ENVELOPE_VERSION: u16 = 1;
pub const SMALLWOOD_V5_TRANSPORT_CIRCUIT: u16 = 5;
pub const SMALLWOOD_V5_TRANSPORT_CRYPTO_SUITE: u16 = 4;
pub const SMALLWOOD_V5_TRANSPORT_BACKEND_ID: u8 = 2;
pub const SMALLWOOD_V5_TRANSPORT_PROFILE_ID: u8 = 1;
pub const SMALLWOOD_V5_TRANSPORT_INLINE_MODE: u8 = 1;
pub const SMALLWOOD_V5_TRANSPORT_FAMILY_ID: u16 = 1;
pub const SMALLWOOD_V5_TRANSPORT_ACTION_ID: u16 = 7;
pub const SMALLWOOD_V5_TRANSPORT_HEADER_BYTES: usize = 80;
pub const SMALLWOOD_V5_TRANSPORT_STATEMENT_BYTES: usize = 672;
pub const SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES: usize = 512 * 1024;
pub const SMALLWOOD_V5_TRANSPORT_MAX_PROOF_BYTES: usize = SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES
    - SMALLWOOD_V5_TRANSPORT_HEADER_BYTES
    - SMALLWOOD_V5_TRANSPORT_STATEMENT_BYTES;
pub const SMALLWOOD_V5_TRANSPORT_MAX_ACTION_BYTES: usize =
    SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES + 5;

const OFFSET_ENVELOPE_VERSION: usize = 4;
const OFFSET_CIRCUIT: usize = 6;
const OFFSET_CRYPTO_SUITE: usize = 8;
const OFFSET_BACKEND: usize = 10;
const OFFSET_PROFILE: usize = 11;
const OFFSET_MODE: usize = 12;
const OFFSET_RESERVED: usize = 13;
const OFFSET_FAMILY: usize = 20;
const OFFSET_ACTION: usize = 22;
const OFFSET_STATEMENT_LEN: usize = 24;
const OFFSET_PROOF_LEN: usize = 28;
const OFFSET_RELATION_BINDING: usize = 32;

/// The only route payload for the dormant V5 candidate.  The envelope itself
/// remains the proof authority; this wrapper exists only for SCALE transport.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct SmallwoodV5InlineArgs {
    pub envelope: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodV5TransportStage {
    Wallet,
    Rpc,
    Relay,
    Mempool,
    Mining,
    Block,
    Restart,
    Sync,
    Reorg,
    FreshVerify,
}

impl SmallwoodV5TransportStage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Rpc => "rpc",
            Self::Relay => "relay",
            Self::Mempool => "mempool",
            Self::Mining => "mining",
            Self::Block => "block",
            Self::Restart => "restart",
            Self::Sync => "sync",
            Self::Reorg => "reorg",
            Self::FreshVerify => "fresh_verify",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodV5TransportError {
    EmptyEnvelope,
    EnvelopeTooLarge {
        observed: usize,
        maximum: usize,
    },
    ActionBytesTooLarge {
        observed: usize,
        maximum: usize,
    },
    HeaderTooShort {
        observed: usize,
    },
    InvalidMagic([u8; 4]),
    UnsupportedEnvelopeVersion(u16),
    UnsupportedCircuit(u16),
    UnsupportedCryptoSuite(u16),
    UnsupportedBackend(u8),
    UnsupportedProfile(u8),
    UnsupportedMode(u8),
    NonZeroReserved([u8; 3]),
    UnsupportedFamily(u16),
    UnsupportedAction(u16),
    InvalidStatementLength(usize),
    EmptyProof,
    ProofTooLarge {
        observed: usize,
        maximum: usize,
    },
    ZeroRelationBinding,
    LengthOverflow,
    Truncated {
        declared: usize,
        observed: usize,
    },
    TrailingBytes {
        trailing: usize,
    },
    NonCanonicalCompactLength,
    CompactLengthTruncated,
    CompactLengthOverflow,
    StageMismatch {
        stage: SmallwoodV5TransportStage,
        expected: usize,
        observed: usize,
        first_difference: Option<usize>,
    },
}

impl fmt::Display for SmallwoodV5TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SmallwoodV5TransportError {}

/// Check only the fixed transport grammar, without allocating or copying the
/// proof.  The transaction crate's full parser additionally checks every
/// Goldilocks public word in the statement.
pub fn validate_smallwood_v5_envelope_shape(
    envelope: &[u8],
) -> Result<(), SmallwoodV5TransportError> {
    if envelope.is_empty() {
        return Err(SmallwoodV5TransportError::EmptyEnvelope);
    }
    if envelope.len() > SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES {
        return Err(SmallwoodV5TransportError::EnvelopeTooLarge {
            observed: envelope.len(),
            maximum: SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES,
        });
    }
    if envelope.len() < SMALLWOOD_V5_TRANSPORT_HEADER_BYTES {
        return Err(SmallwoodV5TransportError::HeaderTooShort {
            observed: envelope.len(),
        });
    }
    let magic = envelope[..4]
        .try_into()
        .expect("the fixed magic width is four bytes");
    if magic != SMALLWOOD_V5_TRANSPORT_MAGIC {
        return Err(SmallwoodV5TransportError::InvalidMagic(magic));
    }
    let envelope_version = read_u16_le(envelope, OFFSET_ENVELOPE_VERSION);
    if envelope_version != SMALLWOOD_V5_TRANSPORT_ENVELOPE_VERSION {
        return Err(SmallwoodV5TransportError::UnsupportedEnvelopeVersion(
            envelope_version,
        ));
    }
    let circuit = read_u16_le(envelope, OFFSET_CIRCUIT);
    if circuit != SMALLWOOD_V5_TRANSPORT_CIRCUIT {
        return Err(SmallwoodV5TransportError::UnsupportedCircuit(circuit));
    }
    let crypto_suite = read_u16_le(envelope, OFFSET_CRYPTO_SUITE);
    if crypto_suite != SMALLWOOD_V5_TRANSPORT_CRYPTO_SUITE {
        return Err(SmallwoodV5TransportError::UnsupportedCryptoSuite(
            crypto_suite,
        ));
    }
    if envelope[OFFSET_BACKEND] != SMALLWOOD_V5_TRANSPORT_BACKEND_ID {
        return Err(SmallwoodV5TransportError::UnsupportedBackend(
            envelope[OFFSET_BACKEND],
        ));
    }
    if envelope[OFFSET_PROFILE] != SMALLWOOD_V5_TRANSPORT_PROFILE_ID {
        return Err(SmallwoodV5TransportError::UnsupportedProfile(
            envelope[OFFSET_PROFILE],
        ));
    }
    if envelope[OFFSET_MODE] != SMALLWOOD_V5_TRANSPORT_INLINE_MODE {
        return Err(SmallwoodV5TransportError::UnsupportedMode(
            envelope[OFFSET_MODE],
        ));
    }
    let reserved = envelope[OFFSET_RESERVED..OFFSET_RESERVED + 3]
        .try_into()
        .expect("the reserved field is three bytes");
    if reserved != [0; 3] {
        return Err(SmallwoodV5TransportError::NonZeroReserved(reserved));
    }
    let family = read_u16_le(envelope, OFFSET_FAMILY);
    if family != SMALLWOOD_V5_TRANSPORT_FAMILY_ID {
        return Err(SmallwoodV5TransportError::UnsupportedFamily(family));
    }
    let action = read_u16_le(envelope, OFFSET_ACTION);
    if action != SMALLWOOD_V5_TRANSPORT_ACTION_ID {
        return Err(SmallwoodV5TransportError::UnsupportedAction(action));
    }
    let statement_len = read_u32_le(envelope, OFFSET_STATEMENT_LEN) as usize;
    if statement_len != SMALLWOOD_V5_TRANSPORT_STATEMENT_BYTES {
        return Err(SmallwoodV5TransportError::InvalidStatementLength(
            statement_len,
        ));
    }
    let proof_len = read_u32_le(envelope, OFFSET_PROOF_LEN) as usize;
    if proof_len == 0 {
        return Err(SmallwoodV5TransportError::EmptyProof);
    }
    if proof_len > SMALLWOOD_V5_TRANSPORT_MAX_PROOF_BYTES {
        return Err(SmallwoodV5TransportError::ProofTooLarge {
            observed: proof_len,
            maximum: SMALLWOOD_V5_TRANSPORT_MAX_PROOF_BYTES,
        });
    }
    if envelope[OFFSET_RELATION_BINDING..OFFSET_RELATION_BINDING + 48]
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(SmallwoodV5TransportError::ZeroRelationBinding);
    }
    let declared = SMALLWOOD_V5_TRANSPORT_HEADER_BYTES
        .checked_add(statement_len)
        .and_then(|length| length.checked_add(proof_len))
        .ok_or(SmallwoodV5TransportError::LengthOverflow)?;
    if envelope.len() < declared {
        return Err(SmallwoodV5TransportError::Truncated {
            declared,
            observed: envelope.len(),
        });
    }
    if envelope.len() > declared {
        return Err(SmallwoodV5TransportError::TrailingBytes {
            trailing: envelope.len() - declared,
        });
    }
    Ok(())
}

/// Encode the route wrapper with an exact, pre-sized allocation.  The caller's
/// envelope is never normalized or reconstructed.
pub fn encode_smallwood_v5_inline_args(
    envelope: &[u8],
) -> Result<Vec<u8>, SmallwoodV5TransportError> {
    validate_smallwood_v5_envelope_shape(envelope)?;
    let mut encoded = Vec::with_capacity(compact_u32_encoded_len(envelope.len()) + envelope.len());
    encode_compact_u32(envelope.len() as u32, &mut encoded);
    encoded.extend_from_slice(envelope);
    Ok(encoded)
}

/// Decode the route wrapper exactly.  The compact length is checked before
/// allocating the owned envelope, and every byte must be consumed.
pub fn decode_smallwood_v5_inline_args_exact(
    encoded: &[u8],
) -> Result<SmallwoodV5InlineArgs, SmallwoodV5TransportError> {
    if encoded.len() > SMALLWOOD_V5_TRANSPORT_MAX_ACTION_BYTES {
        return Err(SmallwoodV5TransportError::ActionBytesTooLarge {
            observed: encoded.len(),
            maximum: SMALLWOOD_V5_TRANSPORT_MAX_ACTION_BYTES,
        });
    }
    let (declared_len, payload_offset) = decode_compact_u32(encoded)?;
    let declared_len = usize::try_from(declared_len)
        .map_err(|_| SmallwoodV5TransportError::CompactLengthOverflow)?;
    if declared_len > SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES {
        return Err(SmallwoodV5TransportError::EnvelopeTooLarge {
            observed: declared_len,
            maximum: SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES,
        });
    }
    let payload_end = payload_offset
        .checked_add(declared_len)
        .ok_or(SmallwoodV5TransportError::LengthOverflow)?;
    if encoded.len() < payload_end {
        return Err(SmallwoodV5TransportError::Truncated {
            declared: payload_end,
            observed: encoded.len(),
        });
    }
    if encoded.len() > payload_end {
        return Err(SmallwoodV5TransportError::TrailingBytes {
            trailing: encoded.len() - payload_end,
        });
    }
    let envelope = &encoded[payload_offset..payload_end];
    validate_smallwood_v5_envelope_shape(envelope)?;
    Ok(SmallwoodV5InlineArgs {
        envelope: envelope.to_vec(),
    })
}

/// Validate one transport stage and prove that it carried exactly the same
/// envelope bytes as the wallet's canonical artifact.
pub fn ensure_smallwood_v5_stage_bytes(
    canonical_envelope: &[u8],
    observed_action_args: &[u8],
    stage: SmallwoodV5TransportStage,
) -> Result<(), SmallwoodV5TransportError> {
    validate_smallwood_v5_envelope_shape(canonical_envelope)?;
    let decoded = decode_smallwood_v5_inline_args_exact(observed_action_args)?;
    if decoded.envelope == canonical_envelope {
        return Ok(());
    }
    let first_difference = canonical_envelope
        .iter()
        .zip(&decoded.envelope)
        .position(|(expected, observed)| expected != observed)
        .or_else(|| {
            (canonical_envelope.len() != decoded.envelope.len())
                .then_some(canonical_envelope.len().min(decoded.envelope.len()))
        });
    Err(SmallwoodV5TransportError::StageMismatch {
        stage,
        expected: canonical_envelope.len(),
        observed: decoded.envelope.len(),
        first_difference,
    })
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed envelope header was checked"),
    )
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed envelope header was checked"),
    )
}

fn compact_u32_encoded_len(value: usize) -> usize {
    if value < 1 << 6 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        5
    }
}

fn encode_compact_u32(value: u32, output: &mut Vec<u8>) {
    match value {
        value if value < 1 << 6 => output.push((value as u8) << 2),
        value if value < 1 << 14 => {
            let encoded = ((value << 2) | 1) as u16;
            output.extend_from_slice(&encoded.to_le_bytes());
        }
        value if value < 1 << 30 => {
            let encoded = (value << 2) | 2;
            output.extend_from_slice(&encoded.to_le_bytes());
        }
        value => {
            // Compact<u32> uses the four-byte payload form for values above
            // 2^30 - 1: mode 0b11 followed by exactly four little-endian
            // bytes.  The V5 envelope cap never reaches this arm, but keep
            // the helper complete so malformed-length tests cannot exercise
            // an invalid SCALE prefix.
            output.push(0b11);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn decode_compact_u32(encoded: &[u8]) -> Result<(u32, usize), SmallwoodV5TransportError> {
    let first = *encoded
        .first()
        .ok_or(SmallwoodV5TransportError::CompactLengthTruncated)?;
    match first & 0b11 {
        0 => Ok(((first >> 2) as u32, 1)),
        1 => {
            if encoded.len() < 2 {
                return Err(SmallwoodV5TransportError::CompactLengthTruncated);
            }
            let value = u16::from_le_bytes([encoded[0], encoded[1]]) >> 2;
            if value < 1 << 6 {
                return Err(SmallwoodV5TransportError::NonCanonicalCompactLength);
            }
            Ok((u32::from(value), 2))
        }
        2 => {
            if encoded.len() < 4 {
                return Err(SmallwoodV5TransportError::CompactLengthTruncated);
            }
            let value = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) >> 2;
            if value < 1 << 14 {
                return Err(SmallwoodV5TransportError::NonCanonicalCompactLength);
            }
            Ok((value, 4))
        }
        3 => {
            let byte_count = usize::from(first >> 2) + 4;
            if byte_count > 4 || encoded.len() < byte_count + 1 {
                return Err(SmallwoodV5TransportError::CompactLengthOverflow);
            }
            let mut bytes = [0u8; 4];
            bytes[..byte_count].copy_from_slice(&encoded[1..byte_count + 1]);
            let value = u32::from_le_bytes(bytes);
            if value < 1 << 30 {
                return Err(SmallwoodV5TransportError::NonCanonicalCompactLength);
            }
            Ok((value, byte_count + 1))
        }
        _ => unreachable!("the compact mode is two bits"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(proof_len: usize) -> Vec<u8> {
        let mut bytes = vec![
            0u8;
            SMALLWOOD_V5_TRANSPORT_HEADER_BYTES
                + SMALLWOOD_V5_TRANSPORT_STATEMENT_BYTES
                + proof_len
        ];
        bytes[..4].copy_from_slice(&SMALLWOOD_V5_TRANSPORT_MAGIC);
        bytes[OFFSET_ENVELOPE_VERSION..OFFSET_ENVELOPE_VERSION + 2]
            .copy_from_slice(&SMALLWOOD_V5_TRANSPORT_ENVELOPE_VERSION.to_le_bytes());
        bytes[OFFSET_CIRCUIT..OFFSET_CIRCUIT + 2]
            .copy_from_slice(&SMALLWOOD_V5_TRANSPORT_CIRCUIT.to_le_bytes());
        bytes[OFFSET_CRYPTO_SUITE..OFFSET_CRYPTO_SUITE + 2]
            .copy_from_slice(&SMALLWOOD_V5_TRANSPORT_CRYPTO_SUITE.to_le_bytes());
        bytes[OFFSET_BACKEND] = SMALLWOOD_V5_TRANSPORT_BACKEND_ID;
        bytes[OFFSET_PROFILE] = SMALLWOOD_V5_TRANSPORT_PROFILE_ID;
        bytes[OFFSET_MODE] = SMALLWOOD_V5_TRANSPORT_INLINE_MODE;
        bytes[OFFSET_FAMILY..OFFSET_FAMILY + 2]
            .copy_from_slice(&SMALLWOOD_V5_TRANSPORT_FAMILY_ID.to_le_bytes());
        bytes[OFFSET_ACTION..OFFSET_ACTION + 2]
            .copy_from_slice(&SMALLWOOD_V5_TRANSPORT_ACTION_ID.to_le_bytes());
        bytes[OFFSET_STATEMENT_LEN..OFFSET_STATEMENT_LEN + 4]
            .copy_from_slice(&(SMALLWOOD_V5_TRANSPORT_STATEMENT_BYTES as u32).to_le_bytes());
        bytes[OFFSET_PROOF_LEN..OFFSET_PROOF_LEN + 4]
            .copy_from_slice(&(proof_len as u32).to_le_bytes());
        bytes[OFFSET_RELATION_BINDING..OFFSET_RELATION_BINDING + 48].fill(0x52);
        bytes
    }

    #[test]
    fn exact_scale_wrapper_roundtrips_without_trailing_bytes() {
        let canonical = envelope(19);
        let encoded = encode_smallwood_v5_inline_args(&canonical).unwrap();
        let decoded = decode_smallwood_v5_inline_args_exact(&encoded).unwrap();
        assert_eq!(decoded.envelope, canonical);
        assert_eq!(
            encoded.len(),
            compact_u32_encoded_len(canonical.len()) + canonical.len()
        );
        assert!(matches!(
            decode_smallwood_v5_inline_args_exact(&[encoded.as_slice(), &[0]].concat()),
            Err(SmallwoodV5TransportError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn compact_length_and_envelope_caps_precede_allocation() {
        let mut oversized = Vec::new();
        encode_compact_u32(
            (SMALLWOOD_V5_TRANSPORT_MAX_ENVELOPE_BYTES + 1) as u32,
            &mut oversized,
        );
        assert!(matches!(
            decode_smallwood_v5_inline_args_exact(&oversized),
            Err(SmallwoodV5TransportError::EnvelopeTooLarge { .. })
        ));
        assert!(matches!(
            decode_smallwood_v5_inline_args_exact(&[0b01]),
            Err(SmallwoodV5TransportError::CompactLengthTruncated)
        ));
        assert!(matches!(
            decode_smallwood_v5_inline_args_exact(&[4]),
            Err(SmallwoodV5TransportError::Truncated { .. })
        ));
    }

    #[test]
    fn noncanonical_and_overwide_compact_lengths_reject() {
        for encoded in [
            vec![0b01, 0],                        // zero encoded in the two-byte mode
            vec![0b10, 0, 0, 0],                  // zero encoded in the four-byte mode
            vec![0b11, 0, 0, 0, 0],               // zero encoded in the five-byte mode
            vec![0b11 | (1 << 2), 0, 0, 0, 0, 0], // six-byte mode is not u32
        ] {
            assert!(
                matches!(
                    decode_smallwood_v5_inline_args_exact(&encoded),
                    Err(SmallwoodV5TransportError::NonCanonicalCompactLength)
                        | Err(SmallwoodV5TransportError::CompactLengthOverflow)
                ),
                "noncanonical compact length unexpectedly decoded: {encoded:?}"
            );
        }
    }

    #[test]
    fn malformed_header_and_proof_declarations_reject() {
        let canonical = envelope(19);
        for offset in [
            0,
            OFFSET_ENVELOPE_VERSION,
            OFFSET_CIRCUIT,
            OFFSET_CRYPTO_SUITE,
            OFFSET_BACKEND,
            OFFSET_PROFILE,
            OFFSET_MODE,
            OFFSET_FAMILY,
            OFFSET_ACTION,
        ] {
            let mut changed = canonical.clone();
            changed[offset] ^= 1;
            assert!(
                validate_smallwood_v5_envelope_shape(&changed).is_err(),
                "offset {offset}"
            );
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(matches!(
            validate_smallwood_v5_envelope_shape(&trailing),
            Err(SmallwoodV5TransportError::TrailingBytes { .. })
        ));
        let mut empty = canonical.clone();
        empty[OFFSET_PROOF_LEN..OFFSET_PROOF_LEN + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            validate_smallwood_v5_envelope_shape(&empty),
            Err(SmallwoodV5TransportError::EmptyProof)
        ));
    }

    #[test]
    fn every_transport_stage_is_byte_exact_and_mutations_identify_the_stage() {
        let canonical = envelope(23);
        let args = encode_smallwood_v5_inline_args(&canonical).unwrap();
        for stage in [
            SmallwoodV5TransportStage::Wallet,
            SmallwoodV5TransportStage::Rpc,
            SmallwoodV5TransportStage::Relay,
            SmallwoodV5TransportStage::Mempool,
            SmallwoodV5TransportStage::Mining,
            SmallwoodV5TransportStage::Block,
            SmallwoodV5TransportStage::Restart,
            SmallwoodV5TransportStage::Sync,
            SmallwoodV5TransportStage::Reorg,
            SmallwoodV5TransportStage::FreshVerify,
        ] {
            ensure_smallwood_v5_stage_bytes(&canonical, &args, stage).unwrap();
        }
        let mut changed = canonical.clone();
        changed[SMALLWOOD_V5_TRANSPORT_HEADER_BYTES] ^= 1;
        let changed_args = encode_smallwood_v5_inline_args(&changed).unwrap();
        assert!(matches!(
            ensure_smallwood_v5_stage_bytes(
                &canonical,
                &changed_args,
                SmallwoodV5TransportStage::Restart,
            ),
            Err(SmallwoodV5TransportError::StageMismatch {
                stage: SmallwoodV5TransportStage::Restart,
                first_difference: Some(SMALLWOOD_V5_TRANSPORT_HEADER_BYTES),
                ..
            })
        ));
    }

    #[test]
    fn derived_scale_type_matches_canonical_transport_encoding() {
        let canonical = envelope(7);
        let encoded = encode_smallwood_v5_inline_args(&canonical).unwrap();
        assert_eq!(
            SmallwoodV5InlineArgs {
                envelope: canonical
            }
            .encode(),
            encoded
        );
    }
}
