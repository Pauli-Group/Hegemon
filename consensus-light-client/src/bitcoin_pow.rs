//! Bitcoin SHA256d ASIC work envelope for the fresh native rules profile.
//!
//! A miner hashes an ordinary 80-byte Bitcoin-shaped header. Its Merkle root
//! is the double SHA256 of a one-transaction coinbase containing the complete
//! canonical Hegemon V2 header prehash and the 28-byte extranonce. An empty
//! Merkle branch therefore reproduces the exact consensus work on an ASIC.

use alloc::vec::Vec;

use crate::{compact_to_target, double_sha256, Hash32, LightClientError};

pub const BITCOIN80_COINBASE_DOMAIN: &[u8] = b"hegemon.bitcoin-asic.pow-v1\0";
pub const BITCOIN80_EXTRANONCE_LEN: usize = 28;
const BITCOIN80_SCRIPT_SIG_LEN: u8 =
    (2 + BITCOIN80_COINBASE_DOMAIN.len() + 32 + BITCOIN80_EXTRANONCE_LEN) as u8;
const BITCOIN80_PUSHDATA_LEN: u8 =
    (BITCOIN80_COINBASE_DOMAIN.len() + 32 + BITCOIN80_EXTRANONCE_LEN) as u8;
/// Stratum `coinbase2`: final input sequence, one zero-value OP_RETURN output,
/// and locktime zero. This is only an ASIC work transaction, not a Hegemon
/// monetary transaction or a valid Bitcoin-chain reward claim.
pub const BITCOIN80_COINBASE_SUFFIX: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, // input sequence
    0x01, // output count
    0, 0, 0, 0, 0, 0, 0, 0, // output value
    0x01, 0x6a, // one-byte OP_RETURN scriptPubKey
    0, 0, 0, 0, // locktime
];
pub const BITCOIN80_VERSION: u32 = 0x2000_0000;
/// The 24 bits reserved for mining under the scheduled combined profile.
pub const BITCOIN80_VERSION_ROLLING_MASK: u32 = 0x1fff_ffe0;
/// The otherwise-unused native V2 version commitment carries the exact mining
/// version under the combined rules profile. This tag cannot alias a legacy
/// proof-version commitment because its interpretation is profile-specific.
pub const BITCOIN80_MINING_VERSION_TAG: &[u8; 44] =
    b"hegemon.bitcoin80.mining-version-v1\0\0\0\0\0\0\0\0\0";

pub fn bitcoin80_validate_mining_version(
    version: u32,
    allow_rolling: bool,
) -> Result<(), LightClientError> {
    let mask = if allow_rolling {
        BITCOIN80_VERSION_ROLLING_MASK
    } else {
        0
    };
    if version & !mask != BITCOIN80_VERSION {
        return Err(LightClientError::InvalidMiningVersion);
    }
    Ok(())
}

pub fn bitcoin80_mining_version_payload(version: u32) -> crate::Digest48 {
    let mut payload = [0u8; 48];
    payload[..4].copy_from_slice(&version.to_le_bytes());
    payload[4..].copy_from_slice(BITCOIN80_MINING_VERSION_TAG);
    payload
}

pub fn bitcoin80_mining_version_from_payload(
    payload: &crate::Digest48,
) -> Result<u32, LightClientError> {
    if &payload[4..] != BITCOIN80_MINING_VERSION_TAG {
        return Err(LightClientError::InvalidMiningVersion);
    }
    let version = u32::from_le_bytes(payload[..4].try_into().expect("four-byte version"));
    bitcoin80_validate_mining_version(version, true)?;
    Ok(version)
}
pub const BITCOIN80_HEADER_LEN: usize = 80;
/// Largest admissible target in the new ASIC profile. The leading sign bit is
/// clear, and this is the largest target representable by the old 32-byte
/// unsigned compact decoder while also being positive in Bitcoin's format.
pub const BITCOIN80_POW_LIMIT_BITS: u32 = 0x207f_ffff;

pub(crate) fn bitcoin_compact_from_target(target: &Hash32) -> Result<u32, LightClientError> {
    let first = target
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(LightClientError::InvalidCompactTarget)?;
    let significant = &target[first..];
    let mut exponent = significant.len() as u32;
    let mut mantissa = 0u32;
    if significant.len() <= 3 {
        for byte in significant {
            mantissa = (mantissa << 8) | u32::from(*byte);
        }
        mantissa <<= 8 * (3 - significant.len());
    } else {
        for byte in &significant[..3] {
            mantissa = (mantissa << 8) | u32::from(*byte);
        }
    }
    // Bitcoin reserves bit 23 as the sign bit. Raising the exponent preserves
    // the highest bytes and rounds the target down when precision is lost.
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }
    if exponent > 32 {
        return Err(LightClientError::InvalidCompactTarget);
    }
    Ok((exponent << 24) | mantissa)
}

/// Translate an unsigned legacy schedule result into a positive Bitcoin
/// compact target. Targets above the explicit ASIC pow limit clamp to it;
/// targets below it round down to the nearest canonical compact value.
pub fn normalize_legacy_compact_for_bitcoin(bits: u32) -> Result<u32, LightClientError> {
    let exponent = bits >> 24;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 {
        return Err(LightClientError::InvalidCompactTarget);
    }
    // A 4x retarget of an admitted 32-byte target can exceed 256 bits. The
    // old encoder then emits exponent 33 with a nonzero leading mantissa byte.
    // Only that exact overflow shape is produced by the inherited schedule;
    // malformed oversized encodings are rejected rather than silently mapped
    // to an easier target.
    if exponent > 32 {
        return if exponent == 33 && mantissa >= 0x0001_0000 {
            Ok(BITCOIN80_POW_LIMIT_BITS)
        } else {
            Err(LightClientError::InvalidCompactTarget)
        };
    }
    let mut target = compact_to_target((exponent << 24) | mantissa)?;
    let pow_limit = compact_to_target(BITCOIN80_POW_LIMIT_BITS)?;
    if target > pow_limit {
        target = pow_limit;
    }
    bitcoin_compact_from_target(&target)
}

/// Strict new-profile nBits admission. Legacy unsigned compact encodings
/// remain available elsewhere, but ASIC work requires a positive, nonzero,
/// canonical Bitcoin encoding at or below the profile's pow limit.
pub fn bitcoin80_validate_compact(bits: u32) -> Result<Hash32, LightClientError> {
    if bits & 0x0080_0000 != 0 {
        return Err(LightClientError::InvalidCompactTarget);
    }
    let target = compact_to_target(bits)?;
    let pow_limit = compact_to_target(BITCOIN80_POW_LIMIT_BITS)?;
    if target > pow_limit || bitcoin_compact_from_target(&target)? != bits {
        return Err(LightClientError::InvalidCompactTarget);
    }
    Ok(target)
}

/// Stratum `coinbase1`. The miner appends 24-byte extranonce1 and 4-byte
/// extranonce2, then `BITCOIN80_COINBASE_SUFFIX`; the Merkle branch is empty.
/// This is a structurally serialized legacy Bitcoin transaction with one
/// coinbase input, which stock Stratum firmware can parse as mining work.
pub fn bitcoin80_coinbase_prefix(pre_hash: &Hash32) -> Vec<u8> {
    let mut coinbase1 =
        Vec::with_capacity(4 + 1 + 32 + 4 + 1 + 2 + BITCOIN80_COINBASE_DOMAIN.len() + 32);
    coinbase1.extend_from_slice(&1u32.to_le_bytes()); // transaction version
    coinbase1.push(1); // one input
    coinbase1.extend_from_slice(&[0u8; 32]); // coinbase prevout hash
    coinbase1.extend_from_slice(&u32::MAX.to_le_bytes()); // coinbase prevout index
    coinbase1.push(BITCOIN80_SCRIPT_SIG_LEN);
    coinbase1.push(0x4c); // OP_PUSHDATA1
    coinbase1.push(BITCOIN80_PUSHDATA_LEN);
    coinbase1.extend_from_slice(BITCOIN80_COINBASE_DOMAIN);
    coinbase1.extend_from_slice(pre_hash);
    coinbase1
}

/// Canonical 80-byte work header. `parent_hash` is the displayed big-endian
/// hash used throughout Hegemon, so Bitcoin's header stores it reversed.
/// The first four nonce bytes are the 32-bit ASIC nonce in little-endian form.
pub fn bitcoin80_header(
    pre_hash: &Hash32,
    parent_hash: &Hash32,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: Hash32,
) -> Result<[u8; BITCOIN80_HEADER_LEN], LightClientError> {
    bitcoin80_header_with_version(
        pre_hash,
        parent_hash,
        timestamp_ms,
        pow_bits,
        nonce,
        BITCOIN80_VERSION,
    )
}

/// Exact final header bytes including the independently rolled mining version.
/// The coinbase commitment is deliberately independent of the version bits.
pub fn bitcoin80_header_with_version(
    pre_hash: &Hash32,
    parent_hash: &Hash32,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: Hash32,
    mining_version: u32,
) -> Result<[u8; BITCOIN80_HEADER_LEN], LightClientError> {
    bitcoin80_validate_mining_version(mining_version, true)?;
    bitcoin80_validate_compact(pow_bits)?;
    let seconds =
        u32::try_from(timestamp_ms / 1_000).map_err(|_| LightClientError::TimestampOutOfRange)?;
    let mut header = [0u8; BITCOIN80_HEADER_LEN];
    header[..4].copy_from_slice(&mining_version.to_le_bytes());
    for (dst, src) in header[4..36].iter_mut().zip(parent_hash.iter().rev()) {
        *dst = *src;
    }

    let mut coinbase = bitcoin80_coinbase_prefix(pre_hash);
    coinbase.extend_from_slice(&nonce[4..]);
    coinbase.extend_from_slice(BITCOIN80_COINBASE_SUFFIX);
    header[36..68].copy_from_slice(&double_sha256(&coinbase));
    header[68..72].copy_from_slice(&seconds.to_le_bytes());
    header[72..76].copy_from_slice(&pow_bits.to_le_bytes());
    header[76..80].copy_from_slice(&nonce[..4]);
    Ok(header)
}

/// Display-order work hash: reverse the raw double-SHA256 digest so the
/// existing big-endian `hash <= target` comparison has Bitcoin semantics.
pub fn bitcoin80_hash_header(header: &[u8; BITCOIN80_HEADER_LEN]) -> Hash32 {
    let mut hash = double_sha256(header);
    hash.reverse();
    hash
}

pub fn bitcoin80_work_hash(
    pre_hash: &Hash32,
    parent_hash: &Hash32,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: Hash32,
) -> Result<Hash32, LightClientError> {
    Ok(bitcoin80_hash_header(&bitcoin80_header(
        pre_hash,
        parent_hash,
        timestamp_ms,
        pow_bits,
        nonce,
    )?))
}

/// Display-order hash of the exact negotiated version, nonce and extra nonce.
pub fn bitcoin80_work_hash_with_version(
    pre_hash: &Hash32,
    parent_hash: &Hash32,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: Hash32,
    mining_version: u32,
) -> Result<Hash32, LightClientError> {
    Ok(bitcoin80_hash_header(&bitcoin80_header_with_version(
        pre_hash,
        parent_hash,
        timestamp_ms,
        pow_bits,
        nonce,
        mining_version,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash_meets_target, pow_hash_from_pre_hash, verify_pow_header_v2, PowHeaderV2,
        TrustedCheckpointV2, HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_V2,
    };

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    #[test]
    fn bitcoin_genesis_header_has_bitcoin_display_hash() {
        let header = decode_hex::<80>(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49",
            "ffff001d",
            "1dac2b7c"
        ));
        assert_eq!(
            bitcoin80_hash_header(&header),
            decode_hex::<32>("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        );
        assert!(hash_meets_target(&bitcoin80_hash_header(&header), 0x1d00ffff).unwrap());
        assert!(!hash_meets_target(&double_sha256(&header), 0x1d00ffff).unwrap());
    }

    #[test]
    fn header_layout_and_nonce_splits_are_exact() {
        let pre_hash = [0x12; 32];
        let parent_hash = core::array::from_fn(|i| i as u8);
        let nonce = core::array::from_fn(|i| (i + 32) as u8);
        let header = bitcoin80_header(
            &pre_hash,
            &parent_hash,
            1_700_000_000_999,
            0x1d00ffff,
            nonce,
        )
        .unwrap();
        assert_eq!(
            header,
            decode_hex::<80>(concat!(
                "00000020",
                "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
                "0d79a279f66afe94dcbafd27be9561d5f52da748850de332925e39af528c81a8",
                "00f15365",
                "ffff001d",
                "20212223"
            ))
        );
        assert_eq!(
            bitcoin80_hash_header(&header),
            decode_hex::<32>("c24f807ba8341c6adad9b7411546d6dcf475b54aa489e51555202f45435b3b90")
        );
        assert_eq!(&header[..4], &BITCOIN80_VERSION.to_le_bytes());
        let mut parent_wire = parent_hash;
        parent_wire.reverse();
        assert_eq!(&header[4..36], &parent_wire);
        assert_eq!(&header[68..72], &1_700_000_000u32.to_le_bytes());
        assert_eq!(&header[72..76], &0x1d00ffffu32.to_le_bytes());
        assert_eq!(&header[76..80], &nonce[..4]);
        let mut coinbase = bitcoin80_coinbase_prefix(&pre_hash);
        assert_eq!(&coinbase[..4], &1u32.to_le_bytes());
        assert_eq!(coinbase[4], 1);
        assert_eq!(&coinbase[5..37], &[0u8; 32]);
        assert_eq!(&coinbase[37..41], &u32::MAX.to_le_bytes());
        assert_eq!(coinbase[41], BITCOIN80_SCRIPT_SIG_LEN);
        assert_eq!(coinbase[42], 0x4c);
        assert_eq!(coinbase[43], BITCOIN80_PUSHDATA_LEN);
        assert_eq!(
            &coinbase[44..44 + BITCOIN80_COINBASE_DOMAIN.len()],
            BITCOIN80_COINBASE_DOMAIN
        );
        assert_eq!(&coinbase[44 + BITCOIN80_COINBASE_DOMAIN.len()..], &pre_hash);
        coinbase.extend_from_slice(&nonce[4..28]);
        coinbase.extend_from_slice(&nonce[28..32]);
        coinbase.extend_from_slice(BITCOIN80_COINBASE_SUFFIX);
        assert_eq!(coinbase.len(), 151);
        assert_eq!(&header[36..68], &double_sha256(&coinbase));
    }

    #[test]
    fn overflowing_bitcoin_seconds_is_rejected() {
        let bad_timestamp = (u32::MAX as u64 + 1) * 1_000;
        assert_eq!(
            bitcoin80_header(&[0; 32], &[0; 32], bad_timestamp, 0x1d00ffff, [0; 32]),
            Err(LightClientError::TimestampOutOfRange)
        );
    }

    #[test]
    fn legacy_compact_normalizes_sign_boundary_and_clamps_retarget_overflow() {
        assert_eq!(
            normalize_legacy_compact_for_bitcoin(0x1e80_0000),
            Ok(0x1f00_8000)
        );
        assert_eq!(
            normalize_legacy_compact_for_bitcoin(0x1e80_ffff),
            Ok(0x1f00_80ff)
        );
        assert_eq!(
            normalize_legacy_compact_for_bitcoin(0x2080_0000),
            Ok(BITCOIN80_POW_LIMIT_BITS)
        );
        // A 4x retarget from the ASIC pow limit can produce an inherited
        // 33-byte unsigned compact target before the wrapper clamps it.
        assert_eq!(
            normalize_legacy_compact_for_bitcoin(0x2101_ffff),
            Ok(BITCOIN80_POW_LIMIT_BITS)
        );
        for bits in [0x0101_0000, 0x1d00_ffff, BITCOIN80_POW_LIMIT_BITS] {
            assert_eq!(normalize_legacy_compact_for_bitcoin(bits), Ok(bits));
        }
        for bits in [0, 0x2100_0001, 0x2201_0000] {
            assert_eq!(
                normalize_legacy_compact_for_bitcoin(bits),
                Err(LightClientError::InvalidCompactTarget)
            );
        }
    }

    #[test]
    fn bitcoin_compact_rejects_negative_zero_noncanonical_and_above_limit() {
        for bits in [0x0101_0000, 0x1d00_ffff, BITCOIN80_POW_LIMIT_BITS] {
            assert_eq!(bitcoin80_validate_compact(bits), compact_to_target(bits));
        }
        for bits in [
            0,
            0x1d80_ffff, // sign bit set
            0x2080_0000, // sign bit and above pow limit
            0x1d00_01ff, // leading-zero noncanonical mantissa
            0x2101_0000, // exponent overflow
        ] {
            assert_eq!(
                bitcoin80_validate_compact(bits),
                Err(LightClientError::InvalidCompactTarget)
            );
            assert_eq!(
                bitcoin80_header(&[0; 32], &[0; 32], 1_700_000_000_000, bits, [0; 32]),
                Err(LightClientError::InvalidCompactTarget)
            );
        }
    }

    fn sample_v2_header(rules_hash: Hash32) -> PowHeaderV2 {
        PowHeaderV2 {
            chain_id: [1; 32],
            rules_hash,
            height: 9,
            timestamp_ms: 1_700_000_000_123,
            parent_hash: [2; 32],
            state_root: [3; 48],
            kernel_root: [4; 48],
            nullifier_root: [5; 48],
            proof_commitment: [6; 48],
            da_root: [7; 48],
            action_root: [8; 32],
            tx_statements_commitment: [9; 48],
            version_commitment: [10; 48],
            fee_commitment: [11; 48],
            supply_digest: 12,
            tx_count: 13,
            message_root: [14; 48],
            message_count: 15,
            header_mmr_root: [16; 32],
            header_mmr_len: 9,
            pow_bits: 0x1d00ffff,
            nonce: [17; 32],
            cumulative_work: [18; 48],
        }
    }

    #[test]
    fn active_v2_commits_full_canonical_header_and_preserves_legacy_v2() {
        let header = sample_v2_header(HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC);
        assert_eq!(header.canonical_bytes().len(), 713);
        assert_eq!(
            header.pow_hash(),
            bitcoin80_work_hash(
                &header.pre_hash(),
                &header.parent_hash,
                header.timestamp_ms,
                header.pow_bits,
                header.nonce,
            )
            .unwrap()
        );
        let base_hash = header.pow_hash();
        let mut changed = header.clone();
        changed.state_root[0] ^= 1;
        assert_ne!(changed.pre_hash(), header.pre_hash());
        assert_ne!(changed.pow_hash(), base_hash);
        changed = header.clone();
        changed.cumulative_work[47] ^= 1;
        assert_ne!(changed.pre_hash(), header.pre_hash());
        assert_ne!(changed.pow_hash(), base_hash);
        changed = header.clone();
        changed.timestamp_ms += 1; // same Bitcoin nTime second; prehash still binds ms
        assert_ne!(changed.pre_hash(), header.pre_hash());
        assert_ne!(changed.pow_hash(), base_hash);

        let legacy = sample_v2_header(HEGEMON_LIGHT_CLIENT_RULES_HASH_V2);
        assert_eq!(
            legacy.pow_hash(),
            pow_hash_from_pre_hash(&legacy.pre_hash(), legacy.nonce)
        );
        assert_ne!(legacy.pow_hash(), header.pow_hash());
    }

    #[test]
    fn nonce_low_four_bytes_enter_header_and_high_28_enter_merkle_root() {
        let header = sample_v2_header(HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC);
        let original = bitcoin80_header(
            &header.pre_hash(),
            &header.parent_hash,
            header.timestamp_ms,
            header.pow_bits,
            header.nonce,
        )
        .unwrap();
        let mut asic_nonce = header.nonce;
        asic_nonce[0] ^= 1;
        let changed_asic = bitcoin80_header(
            &header.pre_hash(),
            &header.parent_hash,
            header.timestamp_ms,
            header.pow_bits,
            asic_nonce,
        )
        .unwrap();
        assert_eq!(&original[36..76], &changed_asic[36..76]);
        assert_ne!(&original[76..80], &changed_asic[76..80]);
        let mut extra_nonce = header.nonce;
        extra_nonce[4] ^= 1;
        let changed_extra = bitcoin80_header(
            &header.pre_hash(),
            &header.parent_hash,
            header.timestamp_ms,
            header.pow_bits,
            extra_nonce,
        )
        .unwrap();
        assert_ne!(&original[36..68], &changed_extra[36..68]);
        assert_eq!(&original[68..80], &changed_extra[68..80]);
        extra_nonce = header.nonce;
        extra_nonce[31] ^= 1;
        let changed_extra2 = bitcoin80_header(
            &header.pre_hash(),
            &header.parent_hash,
            header.timestamp_ms,
            header.pow_bits,
            extra_nonce,
        )
        .unwrap();
        assert_ne!(&original[36..68], &changed_extra2[36..68]);
        assert_eq!(&original[68..80], &changed_extra2[68..80]);
    }

    #[test]
    fn active_v2_verifier_rejects_unrepresentable_bitcoin_time() {
        let mut child = sample_v2_header(HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC);
        child.timestamp_ms = (u32::MAX as u64 + 1) * 1_000;
        let parent = TrustedCheckpointV2 {
            chain_id: child.chain_id,
            rules_hash: child.rules_hash,
            height: child.height - 1,
            header_hash: child.parent_hash,
            timestamp_ms: child.timestamp_ms - 1,
            pow_bits: child.pow_bits,
            cumulative_work: [0; 48],
            header_mmr_root: [0; 32],
            header_mmr_len: child.height - 1,
        };
        assert_eq!(child.pow_hash(), [0xff; 32]);
        assert_eq!(
            verify_pow_header_v2(&parent, &child),
            Err(LightClientError::TimestampOutOfRange)
        );
    }

    #[test]
    fn active_v2_verifier_rejects_negative_compact_work() {
        let mut child = sample_v2_header(HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC);
        child.pow_bits = 0x1d80_ffff;
        let parent = TrustedCheckpointV2 {
            chain_id: child.chain_id,
            rules_hash: child.rules_hash,
            height: child.height - 1,
            header_hash: child.parent_hash,
            timestamp_ms: child.timestamp_ms - 1,
            pow_bits: child.pow_bits,
            cumulative_work: [0; 48],
            header_mmr_root: [0; 32],
            header_mmr_len: child.height - 1,
        };
        assert_eq!(child.pow_hash(), [0xff; 32]);
        assert_eq!(
            verify_pow_header_v2(&parent, &child),
            Err(LightClientError::InvalidCompactTarget)
        );
    }
}

#[cfg(test)]
mod mining_version_tests {
    use super::*;
    use crate::{PowHeaderV2, HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED};
    use codec::{Decode, Encode};

    #[test]
    fn mining_version_changes_exact_four_header_bytes_only() {
        let fixed =
            bitcoin80_header(&[7; 32], &[9; 32], 1_700_000_000_123, 0x207fffff, [5; 32]).unwrap();
        for bit in 5..29 {
            let version = BITCOIN80_VERSION | (1 << bit);
            let rolled = bitcoin80_header_with_version(
                &[7; 32],
                &[9; 32],
                1_700_000_000_123,
                0x207fffff,
                [5; 32],
                version,
            )
            .unwrap();
            assert_eq!(&rolled[..4], &version.to_le_bytes());
            assert_eq!(&rolled[4..], &fixed[4..]);
            assert_ne!(
                bitcoin80_hash_header(&rolled),
                bitcoin80_hash_header(&fixed)
            );
        }
        assert!(bitcoin80_validate_mining_version(BITCOIN80_VERSION, false).is_ok());
        assert!(bitcoin80_validate_mining_version(BITCOIN80_VERSION | 32, false).is_err());
        for bit in [0, 4, 29, 30, 31] {
            assert!(bitcoin80_header_with_version(
                &[7; 32],
                &[9; 32],
                1_700_000_000_123,
                0x207fffff,
                [5; 32],
                BITCOIN80_VERSION ^ (1 << bit)
            )
            .is_err());
        }
    }

    fn combined_header(version: u32) -> PowHeaderV2 {
        PowHeaderV2 {
            chain_id: [1; 32],
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED,
            height: 120,
            timestamp_ms: 1_700_000_000_123,
            parent_hash: [2; 32],
            state_root: [3; 48],
            kernel_root: [4; 48],
            nullifier_root: [5; 48],
            proof_commitment: [6; 48],
            da_root: [7; 48],
            action_root: [8; 32],
            tx_statements_commitment: [9; 48],
            version_commitment: bitcoin80_mining_version_payload(version),
            fee_commitment: [11; 48],
            supply_digest: 12,
            tx_count: 13,
            message_root: [14; 48],
            message_count: 15,
            header_mmr_root: [16; 32],
            header_mmr_len: 120,
            pow_bits: 0x207fffff,
            nonce: [17; 32],
            cumulative_work: [18; 48],
        }
    }

    #[test]
    fn combined_payload_is_explicit_without_aliasing_coinbase_or_work() {
        let fixed = combined_header(BITCOIN80_VERSION);
        let rolled = combined_header(BITCOIN80_VERSION | BITCOIN80_VERSION_ROLLING_MASK);
        assert_eq!(fixed.canonical_bytes().len(), 713);
        assert_ne!(fixed.canonical_bytes(), rolled.canonical_bytes());
        assert_eq!(fixed.pre_hash(), rolled.pre_hash());
        assert_ne!(fixed.pow_hash(), rolled.pow_hash());
        let encoded = rolled.encode();
        let mut cursor = encoded.as_slice();
        assert_eq!(PowHeaderV2::decode(&mut cursor).unwrap(), rolled);
        assert!(cursor.is_empty());
        let mut malformed = rolled.clone();
        malformed.version_commitment[47] ^= 1;
        assert_eq!(
            malformed.mining_version(),
            Err(LightClientError::InvalidMiningVersion)
        );
        assert_ne!(malformed.pre_hash(), fixed.pre_hash());
        assert_eq!(malformed.pow_hash(), [0xff; 32]);
        let mut outside = rolled;
        outside.version_commitment[0] |= 1;
        assert_eq!(
            outside.mining_version(),
            Err(LightClientError::InvalidMiningVersion)
        );
        assert_eq!(outside.pow_hash(), [0xff; 32]);
        let mut historical = fixed;
        historical.rules_hash = crate::HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC;
        assert_eq!(
            historical.pre_hash(),
            crate::hash32(&historical.canonical_bytes())
        );
        assert_eq!(historical.mining_version(), Ok(BITCOIN80_VERSION));
    }

    #[test]
    fn combined_boundary_requires_explicit_version_and_preserves_fixed_miners() {
        let schedule = crate::PowRulesSchedule::combined_at(120).unwrap();
        for height in [119, 120, 121] {
            let parent = crate::TrustedCheckpointV2 {
                chain_id: [1; 32],
                rules_hash: schedule.rules_hash(height - 1),
                height: height - 1,
                header_hash: [2; 32],
                timestamp_ms: 1_700_000_000_000,
                pow_bits: 0x207fffff,
                cumulative_work: [0; 48],
                header_mmr_root: [0; 32],
                header_mmr_len: height - 1,
            };
            for version in [BITCOIN80_VERSION, BITCOIN80_VERSION | 32] {
                let mut header = combined_header(version);
                header.height = height;
                header.header_mmr_len = height;
                header.rules_hash = schedule.rules_hash(height);
                if height < 120 {
                    header.version_commitment = [0; 48];
                }
                header.cumulative_work =
                    crate::cumulative_work_after(&parent.cumulative_work, parent.pow_bits).unwrap();
                for nonce in 0u32..1000 {
                    header.nonce[..4].copy_from_slice(&nonce.to_le_bytes());
                    if crate::hash_meets_target(&header.pow_hash(), header.pow_bits).unwrap() {
                        break;
                    }
                }
                let verified = crate::verify_pow_header_v2_with_expected_bits_and_schedule(
                    &parent,
                    &header,
                    parent.pow_bits,
                    schedule,
                )
                .unwrap();
                assert_eq!(verified, header.pow_hash());
                assert_eq!(
                    header.mining_version().unwrap(),
                    if height < 120 {
                        BITCOIN80_VERSION
                    } else {
                        version
                    }
                );
                if height >= 120 {
                    let mut missing = header.clone();
                    missing.version_commitment = [0; 48];
                    assert_eq!(
                        crate::verify_pow_header_v2_with_expected_bits_and_schedule(
                            &parent,
                            &missing,
                            parent.pow_bits,
                            schedule
                        ),
                        Err(LightClientError::InvalidMiningVersion)
                    );
                    assert_eq!(
                        crate::verify_pow_header_v2(&parent, &header),
                        Err(LightClientError::UnsupportedDifficultySchedule)
                    );
                }
            }
        }
    }
}
