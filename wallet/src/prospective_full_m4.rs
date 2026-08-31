//! Default-off wallet adapter for the prospective V5/Delta direct-proof route.
//!
//! This module supplies the concrete ciphertext certificate required by the
//! composed proof boundary. It deliberately reuses the active wallet-v3 DA
//! parser and canonical encoder; it does not duplicate that grammar and does
//! not activate the prospective proof route in the wallet or node.

use core::fmt;

use hegemon_standalone_full_shake256_relation_prototype::composed_envelope::{
    CanonicalCiphertextValidator, MAX_CANONICAL_CIPHERTEXT_BYTES,
    WALLET_V3_CIPHERTEXT_CONTAINER_BYTES, WALLET_V3_ML_KEM_1024_CIPHERTEXT_BYTES,
};

use crate::{NoteCiphertext, WalletError};

/// Exact active wallet-v3 Gamma DA wire length: the fixed 579-byte container
/// followed directly by the fixed 1,568-byte ML-KEM-1024 ciphertext. Unlike
/// the chain representation, the DA representation has no SCALE length field.
/// The proof route's `crypto_suite = 4` identifies its relation/hash suite; the
/// independently parsed note-encryption container remains wallet Gamma suite 3.
pub const WALLET_V3_GAMMA_DA_BYTES: usize =
    crate::notes::CHAIN_CIPHERTEXT_SIZE + synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN;

const _: () = assert!(WALLET_V3_GAMMA_DA_BYTES == MAX_CANONICAL_CIPHERTEXT_BYTES);
const _: () = assert!(crate::notes::CHAIN_CIPHERTEXT_SIZE == WALLET_V3_CIPHERTEXT_CONTAINER_BYTES);
const _: () = assert!(
    synthetic_crypto::ml_kem::ML_KEM_CIPHERTEXT_LEN == WALLET_V3_ML_KEM_1024_CIPHERTEXT_BYTES
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletV3DaCanonicalizationError {
    Length { expected: usize, actual: usize },
    Parse(String),
    Reencode(String),
    NonCanonical,
}

impl fmt::Display for WalletV3DaCanonicalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for WalletV3DaCanonicalizationError {}

/// Stateless exact parser/re-encoder for the active wallet-v3 Gamma DA wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalletV3DaCanonicalizer;

impl CanonicalCiphertextValidator for WalletV3DaCanonicalizer {
    type Error = WalletV3DaCanonicalizationError;

    fn canonicalize_exact(
        &self,
        _slot: usize,
        encoded: &[u8],
        canonical: &mut Vec<u8>,
    ) -> Result<(), Self::Error> {
        if encoded.len() != WALLET_V3_GAMMA_DA_BYTES {
            return Err(WalletV3DaCanonicalizationError::Length {
                expected: WALLET_V3_GAMMA_DA_BYTES,
                actual: encoded.len(),
            });
        }

        let parsed = NoteCiphertext::from_da_bytes(encoded).map_err(parse_error)?;
        let reencoded = parsed.to_da_bytes().map_err(reencode_error)?;
        if reencoded.as_slice() != encoded {
            return Err(WalletV3DaCanonicalizationError::NonCanonical);
        }
        canonical.extend_from_slice(&reencoded);
        Ok(())
    }
}

fn parse_error(error: WalletError) -> WalletV3DaCanonicalizationError {
    WalletV3DaCanonicalizationError::Parse(error.to_string())
}

fn reencode_error(error: WalletError) -> WalletV3DaCanonicalizationError {
    WalletV3DaCanonicalizationError::Reencode(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSION_OFFSET: usize = 0;
    const SUITE_OFFSET: usize = 1;
    const NOTE_LEN_OFFSET: usize = 7;
    const MEMO_LEN_OFFSET_EMPTY_NOTE: usize = NOTE_LEN_OFFSET + 4;
    const EMPTY_PAYLOAD_PADDING_OFFSET: usize = MEMO_LEN_OFFSET_EMPTY_NOTE + 4;

    fn canonical_empty_da() -> Vec<u8> {
        let encoded = NoteCiphertext::empty().to_da_bytes().unwrap();
        assert_eq!(encoded.len(), WALLET_V3_GAMMA_DA_BYTES);
        encoded
    }

    fn canonicalize(encoded: &[u8]) -> Result<Vec<u8>, WalletV3DaCanonicalizationError> {
        let mut canonical = Vec::new();
        WalletV3DaCanonicalizer.canonicalize_exact(0, encoded, &mut canonical)?;
        Ok(canonical)
    }

    #[test]
    fn exact_wallet_v3_gamma_da_roundtrip() {
        let encoded = canonical_empty_da();
        assert_eq!(canonicalize(&encoded).unwrap(), encoded);
    }

    #[test]
    fn wrong_version_and_suite_fail_closed() {
        let mut wrong_version = canonical_empty_da();
        wrong_version[VERSION_OFFSET] = wrong_version[VERSION_OFFSET].wrapping_add(1);
        assert!(matches!(
            canonicalize(&wrong_version),
            Err(WalletV3DaCanonicalizationError::Parse(_))
        ));

        let mut wrong_suite = canonical_empty_da();
        wrong_suite[SUITE_OFFSET..SUITE_OFFSET + 2].copy_from_slice(&4u16.to_le_bytes());
        assert!(matches!(
            canonicalize(&wrong_suite),
            Err(WalletV3DaCanonicalizationError::Parse(_))
        ));
    }

    #[test]
    fn truncated_and_trailing_kem_bytes_fail_before_parse() {
        let encoded = canonical_empty_da();
        assert!(matches!(
            canonicalize(&encoded[..encoded.len() - 1]),
            Err(WalletV3DaCanonicalizationError::Length { .. })
        ));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            canonicalize(&trailing),
            Err(WalletV3DaCanonicalizationError::Length { .. })
        ));
    }

    #[test]
    fn nonzero_container_padding_and_memo_overrun_fail_closed() {
        let mut nonzero_padding = canonical_empty_da();
        nonzero_padding[EMPTY_PAYLOAD_PADDING_OFFSET] = 1;
        assert!(matches!(
            canonicalize(&nonzero_padding),
            Err(WalletV3DaCanonicalizationError::Parse(_))
        ));

        let mut memo_overrun = canonical_empty_da();
        memo_overrun[MEMO_LEN_OFFSET_EMPTY_NOTE..MEMO_LEN_OFFSET_EMPTY_NOTE + 4]
            .copy_from_slice(&(WALLET_V3_CIPHERTEXT_CONTAINER_BYTES as u32).to_le_bytes());
        assert!(matches!(
            canonicalize(&memo_overrun),
            Err(WalletV3DaCanonicalizationError::Parse(_))
        ));
    }

    #[test]
    fn kem_and_memo_payload_bytes_are_structural_not_authentication_gates() {
        let mut changed_kem = canonical_empty_da();
        changed_kem[WALLET_V3_CIPHERTEXT_CONTAINER_BYTES] ^= 1;
        assert_eq!(canonicalize(&changed_kem).unwrap(), changed_kem);

        let mut with_memo = NoteCiphertext::empty();
        with_memo.memo_payload = vec![0x5a];
        let mut changed_memo = with_memo.to_da_bytes().unwrap();
        assert_eq!(canonicalize(&changed_memo).unwrap(), changed_memo);
        changed_memo[MEMO_LEN_OFFSET_EMPTY_NOTE + 4] ^= 1;
        assert_eq!(canonicalize(&changed_memo).unwrap(), changed_memo);
    }
}
