//! Inactive, versioned commitment to the complete stablecoin-policy state.
//!
//! This module deliberately does not feed [`crate::manifest::kernel_global_root`]
//! and does not authorize any transaction-proof profile. It defines the typed,
//! conventional-hash value that a future consensus-state equality graph can
//! bind without reusing the narrower per-policy identity hash.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use hegemon_hash384::Blake2b384DomainHasher;
use scale_info::TypeInfo;

use crate::manifest::{ProtocolManifest, StablecoinPolicyManifestEntry};

/// Canonical encoding and transcript version.
pub const STABLECOIN_MANIFEST_STATE_V1_VERSION: u32 = 1;
/// RFC 7693 BLAKE2b-384 output width used by this inactive kernel seam.
pub const STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES: usize = 48;
/// Direct little-endian `u64` word count for the M4 equality seam.
pub const STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS: usize =
    STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES / core::mem::size_of::<u64>();
/// Exact fixed width of one canonically encoded manifest entry.
pub const STABLECOIN_MANIFEST_STATE_V1_ENTRY_BYTES: usize = 183;
/// Domain passed to the repository's length-framed BLAKE2b-384 transcript.
pub const STABLECOIN_MANIFEST_STATE_V1_DOMAIN: &[u8] =
    b"hegemon.kernel.stablecoin-manifest-state.v1";

/// This candidate commitment is not part of the active consensus state root.
pub const STABLECOIN_MANIFEST_STATE_V1_KERNEL_GLOBAL_ROOT_INTEGRATED: bool = false;
/// No proof relation or release manifest may treat this source seam as authority.
pub const STABLECOIN_MANIFEST_STATE_V1_PRODUCTION_AUTHORIZED: bool = false;

pub const STABLECOIN_ENTRY_V1_ASSET_ID_OFFSET: usize = 0;
pub const STABLECOIN_ENTRY_V1_ORACLE_FEED_OFFSET: usize = 4;
pub const STABLECOIN_ENTRY_V1_ATTESTATION_ID_OFFSET: usize = 8;
pub const STABLECOIN_ENTRY_V1_MIN_COLLATERAL_RATIO_PPM_OFFSET: usize = 16;
pub const STABLECOIN_ENTRY_V1_MAX_MINT_PER_EPOCH_OFFSET: usize = 32;
pub const STABLECOIN_ENTRY_V1_ORACLE_MAX_AGE_OFFSET: usize = 48;
pub const STABLECOIN_ENTRY_V1_ORACLE_SUBMITTED_AT_OFFSET: usize = 56;
pub const STABLECOIN_ENTRY_V1_ENABLED_AT_OFFSET: usize = 64;
pub const STABLECOIN_ENTRY_V1_RETIRED_PRESENT_OFFSET: usize = 72;
pub const STABLECOIN_ENTRY_V1_RETIRED_AT_OFFSET: usize = 73;
pub const STABLECOIN_ENTRY_V1_POLICY_VERSION_OFFSET: usize = 81;
pub const STABLECOIN_ENTRY_V1_ACTIVE_OFFSET: usize = 85;
pub const STABLECOIN_ENTRY_V1_ORACLE_COMMITMENT_OFFSET: usize = 86;
pub const STABLECOIN_ENTRY_V1_ATTESTATION_COMMITMENT_OFFSET: usize = 134;
pub const STABLECOIN_ENTRY_V1_ATTESTATION_DISPUTED_OFFSET: usize = 182;

/// Typed 48-byte conventional commitment to the complete stablecoin policy set.
///
/// This type is intentionally distinct from `FamilyRoot`, `GlobalRoot`, and the
/// per-entry 48-byte policy/oracle/attestation values even though the widths
/// coincide.
#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    MaxEncodedLen,
    TypeInfo,
)]
pub struct StablecoinManifestStateCommitmentV1([u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES]);

impl StablecoinManifestStateCommitmentV1 {
    pub const ZERO: Self = Self([0u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES]);

    pub const fn new(bytes: [u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES] {
        self.0
    }

    pub fn from_le_words(words: [u64; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS]) -> Self {
        let mut bytes = [0u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES];
        for (index, word) in words.into_iter().enumerate() {
            let start = index * core::mem::size_of::<u64>();
            bytes[start..start + core::mem::size_of::<u64>()].copy_from_slice(&word.to_le_bytes());
        }
        Self(bytes)
    }

    pub fn to_le_words(self) -> [u64; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS] {
        let mut words = [0u64; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            let start = index * core::mem::size_of::<u64>();
            let mut encoded = [0u8; core::mem::size_of::<u64>()];
            encoded.copy_from_slice(&self.0[start..start + core::mem::size_of::<u64>()]);
            *word = u64::from_le_bytes(encoded);
        }
        words
    }
}

impl Default for StablecoinManifestStateCommitmentV1 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<[u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES]>
    for StablecoinManifestStateCommitmentV1
{
    fn from(bytes: [u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES]) -> Self {
        Self::new(bytes)
    }
}

impl From<StablecoinManifestStateCommitmentV1>
    for [u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES]
{
    fn from(commitment: StablecoinManifestStateCommitmentV1) -> Self {
        commitment.into_bytes()
    }
}

impl AsRef<[u8]> for StablecoinManifestStateCommitmentV1 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DecodeWithMemTracking for StablecoinManifestStateCommitmentV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StablecoinManifestStateCommitmentV1Error {
    TooManyEntries { actual: usize },
}

/// Encode every stablecoin policy field into a fixed-width canonical byte row.
///
/// Integers are little-endian. Booleans are exactly `0` or `1`. `retired_at`
/// is encoded as a presence byte plus a fixed eight-byte payload; the payload
/// is zero when the option is absent. This differs deliberately from variable-
/// width SCALE `Option<u64>` so every M4 source offset is invariant.
pub fn stablecoin_manifest_state_entry_v1_bytes(
    entry: &StablecoinPolicyManifestEntry,
) -> [u8; STABLECOIN_MANIFEST_STATE_V1_ENTRY_BYTES] {
    let mut encoded = [0u8; STABLECOIN_MANIFEST_STATE_V1_ENTRY_BYTES];
    encoded[STABLECOIN_ENTRY_V1_ASSET_ID_OFFSET..STABLECOIN_ENTRY_V1_ORACLE_FEED_OFFSET]
        .copy_from_slice(&entry.asset_id.to_le_bytes());
    encoded[STABLECOIN_ENTRY_V1_ORACLE_FEED_OFFSET..STABLECOIN_ENTRY_V1_ATTESTATION_ID_OFFSET]
        .copy_from_slice(&entry.oracle_feed.to_le_bytes());
    encoded[STABLECOIN_ENTRY_V1_ATTESTATION_ID_OFFSET
        ..STABLECOIN_ENTRY_V1_MIN_COLLATERAL_RATIO_PPM_OFFSET]
        .copy_from_slice(&entry.attestation_id.to_le_bytes());
    encoded[STABLECOIN_ENTRY_V1_MIN_COLLATERAL_RATIO_PPM_OFFSET
        ..STABLECOIN_ENTRY_V1_MAX_MINT_PER_EPOCH_OFFSET]
        .copy_from_slice(&entry.min_collateral_ratio_ppm.to_le_bytes());
    encoded
        [STABLECOIN_ENTRY_V1_MAX_MINT_PER_EPOCH_OFFSET..STABLECOIN_ENTRY_V1_ORACLE_MAX_AGE_OFFSET]
        .copy_from_slice(&entry.max_mint_per_epoch.to_le_bytes());
    encoded
        [STABLECOIN_ENTRY_V1_ORACLE_MAX_AGE_OFFSET..STABLECOIN_ENTRY_V1_ORACLE_SUBMITTED_AT_OFFSET]
        .copy_from_slice(&entry.oracle_max_age.to_le_bytes());
    encoded[STABLECOIN_ENTRY_V1_ORACLE_SUBMITTED_AT_OFFSET..STABLECOIN_ENTRY_V1_ENABLED_AT_OFFSET]
        .copy_from_slice(&entry.oracle_submitted_at.to_le_bytes());
    encoded[STABLECOIN_ENTRY_V1_ENABLED_AT_OFFSET..STABLECOIN_ENTRY_V1_RETIRED_PRESENT_OFFSET]
        .copy_from_slice(&entry.enabled_at.to_le_bytes());
    if let Some(retired_at) = entry.retired_at {
        encoded[STABLECOIN_ENTRY_V1_RETIRED_PRESENT_OFFSET] = 1;
        encoded[STABLECOIN_ENTRY_V1_RETIRED_AT_OFFSET..STABLECOIN_ENTRY_V1_POLICY_VERSION_OFFSET]
            .copy_from_slice(&retired_at.to_le_bytes());
    }
    encoded[STABLECOIN_ENTRY_V1_POLICY_VERSION_OFFSET..STABLECOIN_ENTRY_V1_ACTIVE_OFFSET]
        .copy_from_slice(&entry.policy_version.to_le_bytes());
    encoded[STABLECOIN_ENTRY_V1_ACTIVE_OFFSET] = u8::from(entry.active);
    encoded[STABLECOIN_ENTRY_V1_ORACLE_COMMITMENT_OFFSET
        ..STABLECOIN_ENTRY_V1_ATTESTATION_COMMITMENT_OFFSET]
        .copy_from_slice(&entry.oracle_commitment);
    encoded[STABLECOIN_ENTRY_V1_ATTESTATION_COMMITMENT_OFFSET
        ..STABLECOIN_ENTRY_V1_ATTESTATION_DISPUTED_OFFSET]
        .copy_from_slice(&entry.attestation_commitment);
    encoded[STABLECOIN_ENTRY_V1_ATTESTATION_DISPUTED_OFFSET] = u8::from(entry.attestation_disputed);
    encoded
}

/// Commit the canonical ordered list of all stablecoin policy entries.
///
/// The exact framed parts are `u32le(version)`, `u32le(entry_count)`, then one
/// 183-byte entry part for every entry in `ProtocolManifest::stablecoin_policies`
/// order. The vector order and duplicate multiplicity are both committed so the
/// digest authenticates the exact manifest state rather than only its current
/// existential-admission behavior.
pub fn stablecoin_manifest_state_commitment_v1(
    entries: &[StablecoinPolicyManifestEntry],
) -> Result<StablecoinManifestStateCommitmentV1, StablecoinManifestStateCommitmentV1Error> {
    let entry_count = u32::try_from(entries.len()).map_err(|_| {
        StablecoinManifestStateCommitmentV1Error::TooManyEntries {
            actual: entries.len(),
        }
    })?;
    let version_bytes = STABLECOIN_MANIFEST_STATE_V1_VERSION.to_le_bytes();
    let entry_count_bytes = entry_count.to_le_bytes();
    let mut hasher = Blake2b384DomainHasher::new(STABLECOIN_MANIFEST_STATE_V1_DOMAIN);
    hasher
        .update_part(&version_bytes)
        .update_part(&entry_count_bytes);
    for entry in entries {
        let encoded = stablecoin_manifest_state_entry_v1_bytes(entry);
        hasher.update_part(&encoded);
    }
    Ok(StablecoinManifestStateCommitmentV1::new(hasher.finalize()))
}

pub fn protocol_manifest_stablecoin_state_commitment_v1(
    manifest: &ProtocolManifest,
) -> Result<StablecoinManifestStateCommitmentV1, StablecoinManifestStateCommitmentV1Error> {
    stablecoin_manifest_state_commitment_v1(&manifest.stablecoin_policies)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KAT: [u8; STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES] = [
        0xc7, 0x10, 0x12, 0x39, 0x69, 0x2a, 0x87, 0x43, 0xb4, 0xf5, 0x50, 0x73, 0xf1, 0x6e, 0xdd,
        0xd3, 0xc5, 0x4f, 0x36, 0x18, 0xf7, 0x9d, 0x78, 0xed, 0xe2, 0xb4, 0xa2, 0x46, 0x9d, 0x0f,
        0xea, 0x6f, 0xa1, 0x65, 0x03, 0xbf, 0x6f, 0x74, 0xcc, 0x3a, 0xe5, 0x3d, 0x6f, 0x67, 0x4d,
        0x9b, 0x27, 0xa1,
    ];

    fn entry() -> StablecoinPolicyManifestEntry {
        StablecoinPolicyManifestEntry {
            asset_id: 1001,
            oracle_feed: 7,
            attestation_id: 0x0102_0304_0506_0708,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000_000,
            oracle_max_age: 120,
            oracle_submitted_at: 42,
            enabled_at: 10,
            retired_at: Some(1000),
            policy_version: 3,
            active: true,
            oracle_commitment: [0x11; 48],
            attestation_commitment: [0x22; 48],
            attestation_disputed: false,
        }
    }

    #[test]
    fn entry_layout_and_commitment_kat_are_exact() {
        let entry = entry();
        let encoded = stablecoin_manifest_state_entry_v1_bytes(&entry);
        assert_eq!(encoded.len(), STABLECOIN_MANIFEST_STATE_V1_ENTRY_BYTES);
        assert_eq!(encoded[STABLECOIN_ENTRY_V1_RETIRED_PRESENT_OFFSET], 1);
        assert_eq!(
            &encoded
                [STABLECOIN_ENTRY_V1_RETIRED_AT_OFFSET..STABLECOIN_ENTRY_V1_POLICY_VERSION_OFFSET],
            &1000u64.to_le_bytes()
        );
        assert_eq!(
            stablecoin_manifest_state_commitment_v1(&[entry])
                .unwrap()
                .into_bytes(),
            KAT
        );
        let typed = StablecoinManifestStateCommitmentV1::new(KAT);
        assert_eq!(
            StablecoinManifestStateCommitmentV1::from_le_words(typed.to_le_words()),
            typed
        );
    }

    #[test]
    fn absent_retirement_has_a_canonical_zero_payload() {
        let mut entry = entry();
        entry.retired_at = None;
        let encoded = stablecoin_manifest_state_entry_v1_bytes(&entry);
        assert_eq!(encoded[STABLECOIN_ENTRY_V1_RETIRED_PRESENT_OFFSET], 0);
        assert_eq!(
            &encoded
                [STABLECOIN_ENTRY_V1_RETIRED_AT_OFFSET..STABLECOIN_ENTRY_V1_POLICY_VERSION_OFFSET],
            &[0u8; 8]
        );
    }

    #[test]
    fn vector_order_and_multiplicity_are_bound() {
        let first = entry();
        let mut second = first.clone();
        second.asset_id += 1;
        let forward =
            stablecoin_manifest_state_commitment_v1(&[first.clone(), second.clone()]).unwrap();
        let reverse = stablecoin_manifest_state_commitment_v1(&[second, first.clone()]).unwrap();
        let duplicate = stablecoin_manifest_state_commitment_v1(&[first.clone(), first]).unwrap();
        assert_ne!(forward, reverse);
        assert_ne!(forward, duplicate);
    }

    #[test]
    fn every_policy_and_lifecycle_field_is_bound() {
        let canonical = entry();
        let expected = stablecoin_manifest_state_commitment_v1(&[canonical.clone()]).unwrap();
        let mutations: [fn(&mut StablecoinPolicyManifestEntry); 14] = [
            |entry| entry.asset_id ^= 1,
            |entry| entry.oracle_feed ^= 1,
            |entry| entry.attestation_id ^= 1,
            |entry| entry.min_collateral_ratio_ppm ^= 1,
            |entry| entry.max_mint_per_epoch ^= 1,
            |entry| entry.oracle_max_age ^= 1,
            |entry| entry.oracle_submitted_at ^= 1,
            |entry| entry.enabled_at ^= 1,
            |entry| entry.retired_at = None,
            |entry| entry.policy_version ^= 1,
            |entry| entry.active = !entry.active,
            |entry| entry.oracle_commitment[0] ^= 1,
            |entry| entry.attestation_commitment[0] ^= 1,
            |entry| entry.attestation_disputed = !entry.attestation_disputed,
        ];
        for mutate in mutations {
            let mut changed = canonical.clone();
            mutate(&mut changed);
            assert_ne!(
                stablecoin_manifest_state_commitment_v1(&[changed]).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn commitment_version_remains_explicitly_inactive() {
        assert!(!STABLECOIN_MANIFEST_STATE_V1_KERNEL_GLOBAL_ROOT_INTEGRATED);
        assert!(!STABLECOIN_MANIFEST_STATE_V1_PRODUCTION_AUTHORIZED);
    }
}
