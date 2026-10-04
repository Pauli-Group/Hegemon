//! Prospective all-W64 stablecoin-manifest authority.
//!
//! This module is deliberately inactive.  It does not feed
//! [`crate::manifest::kernel_global_root`], does not change genesis, and does
//! not authorize a transaction-proof route.  It is a source-exact port of the
//! minimum-width manifest architecture that survived the local composition
//! screen: sixteen strictly ordered 215-byte rows, RFC 7693 BLAKE2b-512 for
//! every identity and tree role, a depth-four membership proof, and a typed
//! verifier-owned parent root/height input.
//!
//! No legacy 48-byte or experimental 56-byte digest has a conversion into any
//! type in this module.  A future state transition must rerun the W64 policy,
//! oracle, and attestation constructors over their canonical sources.

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Fresh row/profile version.  This does not allocate a consensus version.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_VERSION: u32 = 2;
/// The manifest contains exactly sixteen committed slots.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_CAP: usize = 16;
/// A cap of sixteen fixes four Merkle sibling levels.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH: usize = 4;
/// Every identity, root, and snapshot is a native 64-byte BLAKE2b-512 value.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES: usize = 64;
/// One W64 value is eight directly encoded little-endian `u64` words.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_WORDS: usize = 8;
/// Exact byte width of one canonical all-W64 policy row.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES: usize = 215;
/// A tree slot is `present:u8 || row`.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES: usize = 216;
/// Exact selected witness: `index:u32le || row || sibling[0..4]`.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_WITNESS_BYTES: usize = 475;
/// Exact proof-public suffix: `root64 || parent_height:u64le`.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_PUBLIC_BYTES: usize = 72;
/// The policy constructor consumes the exact immutable 61-byte policy tuple.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_POLICY_TUPLE_BYTES: usize = 61;
/// Prospective oracle and attestation payloads are nonempty and bounded.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_SOURCE_PAYLOAD_MAX: usize = 4096;

/// This source seam is not an activated protocol surface.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_ACTIVE: bool = false;
/// The V2 root is absent from the live kernel global root.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_KERNEL_GLOBAL_ROOT_INTEGRATED: bool = false;
/// No live or replacement genesis installs this profile.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_GENESIS_INTEGRATED: bool = false;
/// No canonical state writer owns these rows or their constructors.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_STATE_WRITER_INTEGRATED: bool = false;
/// The current oracle subsystem does not own the prospective source grammar.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_ORACLE_CONSTRUCTOR_AUTHORIZED: bool = false;
/// The current attestation subsystem does not own the prospective source grammar.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_ATTESTATION_CONSTRUCTOR_AUTHORIZED: bool = false;
/// The transaction relation has not compiled this membership surface.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_RELATION_INTEGRATED: bool = false;
/// No mempool, mining, import, sync, restart, or reorg route accepts this profile.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_CONSENSUS_ROUTE_AUTHORIZED: bool = false;
/// BLAKE2b-512 has no reviewed concrete QROM-instantiation bridge here.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_QROM_AUTHORIZED: bool = false;
/// No complete whole-view zero-knowledge result is attached to this module.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_COMPLETE_ZK_AUTHORIZED: bool = false;
/// No Rust/formal/compiler refinement closes this source seam.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_FORMAL_REFINEMENT_COMPLETE: bool = false;
/// This candidate cannot authorize production in this revision.
pub const STABLECOIN_MANIFEST_AUTHORITY_V2_PRODUCTION_AUTHORIZED: bool = false;

const AUTHORITY_PROFILE_V2: u8 = 2;
const AUTHORITY_WIDTH_V2: u8 = 64;
const AUTHORITY_CAP_LOG2_V2: u8 = 4;
const ROLE_FULL: u8 = 1;
const ROLE_LEAF: u8 = 2;
const ROLE_NODE: u8 = 3;
const ROLE_SNAPSHOT: u8 = 4;
const IDENTITY_ROLE_POLICY: u8 = 1;
const IDENTITY_ROLE_ORACLE: u8 = 2;
const IDENTITY_ROLE_ATTESTATION: u8 = 3;

pub const STABLECOIN_ENTRY_V2_ASSET_ID_OFFSET: usize = 0;
pub const STABLECOIN_ENTRY_V2_ORACLE_FEED_OFFSET: usize = 4;
pub const STABLECOIN_ENTRY_V2_ATTESTATION_ID_OFFSET: usize = 8;
pub const STABLECOIN_ENTRY_V2_MIN_COLLATERAL_RATIO_PPM_OFFSET: usize = 16;
pub const STABLECOIN_ENTRY_V2_MAX_MINT_PER_EPOCH_OFFSET: usize = 32;
pub const STABLECOIN_ENTRY_V2_ORACLE_MAX_AGE_OFFSET: usize = 48;
pub const STABLECOIN_ENTRY_V2_ORACLE_SUBMITTED_AT_OFFSET: usize = 56;
pub const STABLECOIN_ENTRY_V2_ENABLED_AT_OFFSET: usize = 64;
pub const STABLECOIN_ENTRY_V2_RETIRED_PRESENT_OFFSET: usize = 72;
pub const STABLECOIN_ENTRY_V2_RETIRED_AT_OFFSET: usize = 73;
pub const STABLECOIN_ENTRY_V2_POLICY_VERSION_OFFSET: usize = 81;
pub const STABLECOIN_ENTRY_V2_ACTIVE_OFFSET: usize = 85;
pub const STABLECOIN_ENTRY_V2_ORACLE_COMMITMENT_OFFSET: usize = 86;
pub const STABLECOIN_ENTRY_V2_ATTESTATION_COMMITMENT_OFFSET: usize = 150;
pub const STABLECOIN_ENTRY_V2_ATTESTATION_DISPUTED_OFFSET: usize = 214;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StablecoinManifestAuthorityV2Error {
    WrongLength,
    NonCanonicalBoolean,
    NonCanonicalRetirement,
    PayloadLength,
    TooManyEntries,
    EntriesNotStrictlyOrdered,
    NonCanonicalSlot,
    PresentAfterEmptySlot,
    IndexOutOfRange,
    SelectedSlotAbsent,
    ParentSnapshotMismatch,
    ParentRootHeightMismatch,
    MembershipRootMismatch,
    ConstructorMetadataMismatch,
    ConstructorCommitmentMismatch,
    PolicyIdentityMismatch,
    BindingMismatch,
    InactivePolicy,
    PolicyNotEnabled,
    PolicyRetired,
    AttestationDisputed,
    OracleFromFuture,
    OracleStale,
    ZeroIssuance,
    IssuanceCapExceeded,
}

macro_rules! digest_type {
    ($name:ident) => {
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
        pub struct $name([u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES]);

        impl $name {
            pub const ZERO: Self = Self([0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES]);

            pub const fn new(bytes: [u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES] {
                self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::ZERO
            }
        }

        impl DecodeWithMemTracking for $name {}
    };
}

digest_type!(StablecoinPolicyIdentityV2);
digest_type!(StablecoinOracleAuthorityCommitmentV2);
digest_type!(StablecoinAttestationAuthorityCommitmentV2);
digest_type!(StablecoinManifestRootV2);
digest_type!(StablecoinManifestSnapshotV2);

/// Exact prospective canonical row.  This is intentionally a distinct type
/// from the live 183-byte `StablecoinPolicyManifestEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinPolicyManifestEntryV2 {
    pub asset_id: u32,
    pub oracle_feed: u32,
    pub attestation_id: u64,
    pub min_collateral_ratio_ppm: u128,
    pub max_mint_per_epoch: u128,
    pub oracle_max_age: u64,
    pub oracle_submitted_at: u64,
    pub enabled_at: u64,
    pub retired_at: Option<u64>,
    pub policy_version: u32,
    pub active: bool,
    pub oracle_commitment: StablecoinOracleAuthorityCommitmentV2,
    pub attestation_commitment: StablecoinAttestationAuthorityCommitmentV2,
    pub attestation_disputed: bool,
}

impl StablecoinPolicyManifestEntryV2 {
    pub const fn key(&self) -> (u32, u32) {
        (self.asset_id, self.policy_version)
    }

    pub fn encode_canonical(&self) -> [u8; STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES] {
        let mut encoded = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES];
        encoded[0..4].copy_from_slice(&self.asset_id.to_le_bytes());
        encoded[4..8].copy_from_slice(&self.oracle_feed.to_le_bytes());
        encoded[8..16].copy_from_slice(&self.attestation_id.to_le_bytes());
        encoded[16..32].copy_from_slice(&self.min_collateral_ratio_ppm.to_le_bytes());
        encoded[32..48].copy_from_slice(&self.max_mint_per_epoch.to_le_bytes());
        encoded[48..56].copy_from_slice(&self.oracle_max_age.to_le_bytes());
        encoded[56..64].copy_from_slice(&self.oracle_submitted_at.to_le_bytes());
        encoded[64..72].copy_from_slice(&self.enabled_at.to_le_bytes());
        if let Some(retired_at) = self.retired_at {
            encoded[STABLECOIN_ENTRY_V2_RETIRED_PRESENT_OFFSET] = 1;
            encoded[73..81].copy_from_slice(&retired_at.to_le_bytes());
        }
        encoded[81..85].copy_from_slice(&self.policy_version.to_le_bytes());
        encoded[STABLECOIN_ENTRY_V2_ACTIVE_OFFSET] = u8::from(self.active);
        encoded[86..150].copy_from_slice(self.oracle_commitment.as_bytes());
        encoded[150..214].copy_from_slice(self.attestation_commitment.as_bytes());
        encoded[STABLECOIN_ENTRY_V2_ATTESTATION_DISPUTED_OFFSET] =
            u8::from(self.attestation_disputed);
        encoded
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinManifestAuthorityV2Error> {
        let raw: &[u8; STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinManifestAuthorityV2Error::WrongLength)?;
        if raw[STABLECOIN_ENTRY_V2_RETIRED_PRESENT_OFFSET] > 1
            || raw[STABLECOIN_ENTRY_V2_ACTIVE_OFFSET] > 1
            || raw[STABLECOIN_ENTRY_V2_ATTESTATION_DISPUTED_OFFSET] > 1
        {
            return Err(StablecoinManifestAuthorityV2Error::NonCanonicalBoolean);
        }
        if raw[STABLECOIN_ENTRY_V2_RETIRED_PRESENT_OFFSET] == 0 && raw[73..81] != [0u8; 8] {
            return Err(StablecoinManifestAuthorityV2Error::NonCanonicalRetirement);
        }
        let mut oracle_commitment = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES];
        oracle_commitment.copy_from_slice(&raw[86..150]);
        let mut attestation_commitment = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES];
        attestation_commitment.copy_from_slice(&raw[150..214]);
        let decoded = Self {
            asset_id: u32::from_le_bytes(raw[0..4].try_into().expect("fixed slice")),
            oracle_feed: u32::from_le_bytes(raw[4..8].try_into().expect("fixed slice")),
            attestation_id: u64::from_le_bytes(raw[8..16].try_into().expect("fixed slice")),
            min_collateral_ratio_ppm: u128::from_le_bytes(
                raw[16..32].try_into().expect("fixed slice"),
            ),
            max_mint_per_epoch: u128::from_le_bytes(raw[32..48].try_into().expect("fixed slice")),
            oracle_max_age: u64::from_le_bytes(raw[48..56].try_into().expect("fixed slice")),
            oracle_submitted_at: u64::from_le_bytes(raw[56..64].try_into().expect("fixed slice")),
            enabled_at: u64::from_le_bytes(raw[64..72].try_into().expect("fixed slice")),
            retired_at: (raw[72] == 1)
                .then(|| u64::from_le_bytes(raw[73..81].try_into().expect("fixed slice"))),
            policy_version: u32::from_le_bytes(raw[81..85].try_into().expect("fixed slice")),
            active: raw[85] == 1,
            oracle_commitment: StablecoinOracleAuthorityCommitmentV2::new(oracle_commitment),
            attestation_commitment: StablecoinAttestationAuthorityCommitmentV2::new(
                attestation_commitment,
            ),
            attestation_disputed: raw[214] == 1,
        };
        if decoded.encode_canonical() != *raw {
            return Err(StablecoinManifestAuthorityV2Error::NonCanonicalBoolean);
        }
        Ok(decoded)
    }

    fn policy_tuple(&self) -> [u8; STABLECOIN_MANIFEST_AUTHORITY_V2_POLICY_TUPLE_BYTES] {
        let mut encoded = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_POLICY_TUPLE_BYTES];
        encoded[0..4].copy_from_slice(&self.asset_id.to_le_bytes());
        encoded[4..8].copy_from_slice(&self.oracle_feed.to_le_bytes());
        encoded[8..16].copy_from_slice(&self.attestation_id.to_le_bytes());
        encoded[16..32].copy_from_slice(&self.min_collateral_ratio_ppm.to_le_bytes());
        encoded[32..48].copy_from_slice(&self.max_mint_per_epoch.to_le_bytes());
        encoded[48..56].copy_from_slice(&self.oracle_max_age.to_le_bytes());
        encoded[56..60].copy_from_slice(&self.policy_version.to_le_bytes());
        encoded[60] = u8::from(self.active);
        encoded
    }
}

/// Canonical prospective oracle source.  The current oracle subsystem does
/// not yet own or refine this grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinOracleAuthoritySourceV2 {
    pub asset_id: u32,
    pub policy_version: u32,
    pub oracle_feed: u32,
    pub submitted_at: u64,
    pub source_id: [u8; 32],
    pub payload: Vec<u8>,
}

impl StablecoinOracleAuthoritySourceV2 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, StablecoinManifestAuthorityV2Error> {
        if !(1..=STABLECOIN_MANIFEST_AUTHORITY_V2_SOURCE_PAYLOAD_MAX).contains(&self.payload.len())
        {
            return Err(StablecoinManifestAuthorityV2Error::PayloadLength);
        }
        let mut encoded = Vec::with_capacity(54 + self.payload.len());
        encoded.extend_from_slice(&self.asset_id.to_le_bytes());
        encoded.extend_from_slice(&self.policy_version.to_le_bytes());
        encoded.extend_from_slice(&self.oracle_feed.to_le_bytes());
        encoded.extend_from_slice(&self.submitted_at.to_le_bytes());
        encoded.extend_from_slice(&self.source_id);
        encoded.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinManifestAuthorityV2Error> {
        if raw.len() < 55 {
            return Err(StablecoinManifestAuthorityV2Error::WrongLength);
        }
        let payload_len = u16::from_le_bytes(raw[52..54].try_into().expect("fixed slice")) as usize;
        if !(1..=STABLECOIN_MANIFEST_AUTHORITY_V2_SOURCE_PAYLOAD_MAX).contains(&payload_len)
            || raw.len() != 54 + payload_len
        {
            return Err(StablecoinManifestAuthorityV2Error::PayloadLength);
        }
        let value = Self {
            asset_id: u32::from_le_bytes(raw[0..4].try_into().expect("fixed slice")),
            policy_version: u32::from_le_bytes(raw[4..8].try_into().expect("fixed slice")),
            oracle_feed: u32::from_le_bytes(raw[8..12].try_into().expect("fixed slice")),
            submitted_at: u64::from_le_bytes(raw[12..20].try_into().expect("fixed slice")),
            source_id: raw[20..52].try_into().expect("fixed slice"),
            payload: raw[54..].to_vec(),
        };
        if value.encode_canonical()?.as_slice() != raw {
            return Err(StablecoinManifestAuthorityV2Error::WrongLength);
        }
        Ok(value)
    }
}

/// Canonical prospective attestation source.  Mutable dispute status remains
/// in the manifest row rather than this immutable constructor source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinAttestationAuthoritySourceV2 {
    pub asset_id: u32,
    pub policy_version: u32,
    pub attestation_id: u64,
    pub created_at: u64,
    pub issuer_id: [u8; 32],
    pub payload: Vec<u8>,
}

impl StablecoinAttestationAuthoritySourceV2 {
    pub fn encode_canonical(&self) -> Result<Vec<u8>, StablecoinManifestAuthorityV2Error> {
        if !(1..=STABLECOIN_MANIFEST_AUTHORITY_V2_SOURCE_PAYLOAD_MAX).contains(&self.payload.len())
        {
            return Err(StablecoinManifestAuthorityV2Error::PayloadLength);
        }
        let mut encoded = Vec::with_capacity(58 + self.payload.len());
        encoded.extend_from_slice(&self.asset_id.to_le_bytes());
        encoded.extend_from_slice(&self.policy_version.to_le_bytes());
        encoded.extend_from_slice(&self.attestation_id.to_le_bytes());
        encoded.extend_from_slice(&self.created_at.to_le_bytes());
        encoded.extend_from_slice(&self.issuer_id);
        encoded.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinManifestAuthorityV2Error> {
        if raw.len() < 59 {
            return Err(StablecoinManifestAuthorityV2Error::WrongLength);
        }
        let payload_len = u16::from_le_bytes(raw[56..58].try_into().expect("fixed slice")) as usize;
        if !(1..=STABLECOIN_MANIFEST_AUTHORITY_V2_SOURCE_PAYLOAD_MAX).contains(&payload_len)
            || raw.len() != 58 + payload_len
        {
            return Err(StablecoinManifestAuthorityV2Error::PayloadLength);
        }
        let value = Self {
            asset_id: u32::from_le_bytes(raw[0..4].try_into().expect("fixed slice")),
            policy_version: u32::from_le_bytes(raw[4..8].try_into().expect("fixed slice")),
            attestation_id: u64::from_le_bytes(raw[8..16].try_into().expect("fixed slice")),
            created_at: u64::from_le_bytes(raw[16..24].try_into().expect("fixed slice")),
            issuer_id: raw[24..56].try_into().expect("fixed slice"),
            payload: raw[58..].to_vec(),
        };
        if value.encode_canonical()?.as_slice() != raw {
            return Err(StablecoinManifestAuthorityV2Error::WrongLength);
        }
        Ok(value)
    }
}

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], count: u128, last: bool) {
    let mut message = [0u64; 16];
    for (word, chunk) in message.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().expect("fixed chunk"));
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= count as u64;
    v[13] ^= (count >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for schedule in BLAKE2B_SIGMA {
        blake2b_g(
            &mut v,
            0,
            4,
            8,
            12,
            message[schedule[0]],
            message[schedule[1]],
        );
        blake2b_g(
            &mut v,
            1,
            5,
            9,
            13,
            message[schedule[2]],
            message[schedule[3]],
        );
        blake2b_g(
            &mut v,
            2,
            6,
            10,
            14,
            message[schedule[4]],
            message[schedule[5]],
        );
        blake2b_g(
            &mut v,
            3,
            7,
            11,
            15,
            message[schedule[6]],
            message[schedule[7]],
        );
        blake2b_g(
            &mut v,
            0,
            5,
            10,
            15,
            message[schedule[8]],
            message[schedule[9]],
        );
        blake2b_g(
            &mut v,
            1,
            6,
            11,
            12,
            message[schedule[10]],
            message[schedule[11]],
        );
        blake2b_g(
            &mut v,
            2,
            7,
            8,
            13,
            message[schedule[12]],
            message[schedule[13]],
        );
        blake2b_g(
            &mut v,
            3,
            4,
            9,
            14,
            message[schedule[14]],
            message[schedule[15]],
        );
    }
    for index in 0..8 {
        h[index] ^= v[index] ^ v[index + 8];
    }
}

/// Exact unkeyed, personalized RFC 7693 BLAKE2b-512.
pub fn blake2b512_personalized_v2(message: &[u8], personalization: [u8; 16]) -> [u8; 64] {
    let mut parameter_block = [0u8; 64];
    parameter_block[0] = 64;
    parameter_block[2] = 1;
    parameter_block[3] = 1;
    parameter_block[48..64].copy_from_slice(&personalization);
    let mut state = BLAKE2B_IV;
    for (word, chunk) in state.iter_mut().zip(parameter_block.chunks_exact(8)) {
        *word ^= u64::from_le_bytes(chunk.try_into().expect("fixed chunk"));
    }

    let mut offset = 0usize;
    while message.len().saturating_sub(offset) > 128 {
        let block: &[u8; 128] = message[offset..offset + 128]
            .try_into()
            .expect("fixed BLAKE2b block");
        offset += 128;
        blake2b_compress(&mut state, block, offset as u128, false);
    }
    let remainder = &message[offset..];
    let mut final_block = [0u8; 128];
    final_block[..remainder.len()].copy_from_slice(remainder);
    blake2b_compress(&mut state, &final_block, message.len() as u128, true);

    let mut digest = [0u8; 64];
    for (chunk, word) in digest.chunks_exact_mut(8).zip(state) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn identity_personalization(role: u8) -> [u8; 16] {
    [
        b'H',
        b'G',
        b'M',
        b'A',
        b'I',
        b'D',
        b'V',
        b'2',
        role,
        AUTHORITY_PROFILE_V2,
        AUTHORITY_WIDTH_V2,
        0,
        0,
        0,
        0,
        0,
    ]
}

fn tree_personalization(role: u8, level: u8) -> [u8; 16] {
    [
        b'H',
        b'G',
        b'M',
        b'A',
        b'R',
        b'O',
        b'O',
        b'T',
        role,
        AUTHORITY_PROFILE_V2,
        AUTHORITY_WIDTH_V2,
        AUTHORITY_CAP_LOG2_V2,
        level,
        0,
        0,
        0,
    ]
}

/// Construct the exact W64 policy identity over the canonical 61-byte tuple.
pub fn stablecoin_policy_identity_v2(
    entry: &StablecoinPolicyManifestEntryV2,
) -> StablecoinPolicyIdentityV2 {
    StablecoinPolicyIdentityV2::new(blake2b512_personalized_v2(
        &entry.policy_tuple(),
        identity_personalization(IDENTITY_ROLE_POLICY),
    ))
}

/// Construct the exact W64 oracle authority from its raw canonical source.
pub fn stablecoin_oracle_authority_commitment_v2(
    source: &StablecoinOracleAuthoritySourceV2,
) -> Result<StablecoinOracleAuthorityCommitmentV2, StablecoinManifestAuthorityV2Error> {
    Ok(StablecoinOracleAuthorityCommitmentV2::new(
        blake2b512_personalized_v2(
            &source.encode_canonical()?,
            identity_personalization(IDENTITY_ROLE_ORACLE),
        ),
    ))
}

/// Construct the exact W64 attestation authority from its raw canonical source.
pub fn stablecoin_attestation_authority_commitment_v2(
    source: &StablecoinAttestationAuthoritySourceV2,
) -> Result<StablecoinAttestationAuthorityCommitmentV2, StablecoinManifestAuthorityV2Error> {
    Ok(StablecoinAttestationAuthorityCommitmentV2::new(
        blake2b512_personalized_v2(
            &source.encode_canonical()?,
            identity_personalization(IDENTITY_ROLE_ATTESTATION),
        ),
    ))
}

/// Recompute both prospective source constructors and require exact metadata
/// and commitment agreement with the row.  Passing this function does not
/// authorize either current subsystem to produce these sources.
pub fn validate_stablecoin_authority_sources_v2(
    entry: &StablecoinPolicyManifestEntryV2,
    oracle: &StablecoinOracleAuthoritySourceV2,
    attestation: &StablecoinAttestationAuthoritySourceV2,
) -> Result<(), StablecoinManifestAuthorityV2Error> {
    if oracle.asset_id != entry.asset_id
        || oracle.policy_version != entry.policy_version
        || oracle.oracle_feed != entry.oracle_feed
        || oracle.submitted_at != entry.oracle_submitted_at
        || attestation.asset_id != entry.asset_id
        || attestation.policy_version != entry.policy_version
        || attestation.attestation_id != entry.attestation_id
    {
        return Err(StablecoinManifestAuthorityV2Error::ConstructorMetadataMismatch);
    }
    if stablecoin_oracle_authority_commitment_v2(oracle)? != entry.oracle_commitment
        || stablecoin_attestation_authority_commitment_v2(attestation)?
            != entry.attestation_commitment
    {
        return Err(StablecoinManifestAuthorityV2Error::ConstructorCommitmentMismatch);
    }
    Ok(())
}

/// Reject any vector that is not already a strict numeric ordering by
/// `(asset_id, policy_version)`.  Sorting or deduplication is never performed.
pub fn validate_stablecoin_manifest_entries_v2(
    entries: &[StablecoinPolicyManifestEntryV2],
) -> Result<(), StablecoinManifestAuthorityV2Error> {
    if entries.len() > STABLECOIN_MANIFEST_AUTHORITY_V2_CAP {
        return Err(StablecoinManifestAuthorityV2Error::TooManyEntries);
    }
    if entries
        .windows(2)
        .any(|pair| pair[0].key() >= pair[1].key())
    {
        return Err(StablecoinManifestAuthorityV2Error::EntriesNotStrictlyOrdered);
    }
    Ok(())
}

/// Materialize the fixed sixteen-slot prefix-present grammar.
pub fn stablecoin_manifest_slots_v2(
    entries: &[StablecoinPolicyManifestEntryV2],
) -> Result<
    [[u8; STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES]; STABLECOIN_MANIFEST_AUTHORITY_V2_CAP],
    StablecoinManifestAuthorityV2Error,
> {
    validate_stablecoin_manifest_entries_v2(entries)?;
    let mut slots =
        [[0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES]; STABLECOIN_MANIFEST_AUTHORITY_V2_CAP];
    for (slot, entry) in slots.iter_mut().zip(entries) {
        slot[0] = 1;
        slot[1..].copy_from_slice(&entry.encode_canonical());
    }
    Ok(slots)
}

/// Decode a complete slot vector, enforcing canonical presence, zero empty
/// slots, a present prefix, and strict row ordering.
pub fn stablecoin_manifest_entries_from_slots_v2(
    slots: &[[u8; STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES];
         STABLECOIN_MANIFEST_AUTHORITY_V2_CAP],
) -> Result<Vec<StablecoinPolicyManifestEntryV2>, StablecoinManifestAuthorityV2Error> {
    let mut entries = Vec::new();
    let mut saw_empty = false;
    for slot in slots {
        match slot[0] {
            0 => {
                if slot[1..] != [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES] {
                    return Err(StablecoinManifestAuthorityV2Error::NonCanonicalSlot);
                }
                saw_empty = true;
            }
            1 => {
                if saw_empty {
                    return Err(StablecoinManifestAuthorityV2Error::PresentAfterEmptySlot);
                }
                entries.push(StablecoinPolicyManifestEntryV2::decode_canonical(
                    &slot[1..],
                )?);
            }
            _ => return Err(StablecoinManifestAuthorityV2Error::NonCanonicalSlot),
        }
    }
    validate_stablecoin_manifest_entries_v2(&entries)?;
    Ok(entries)
}

/// Hash one exact 216-byte leaf slot with the leaf-specific personalization.
pub fn stablecoin_manifest_leaf_v2(
    slot: &[u8],
) -> Result<StablecoinManifestRootV2, StablecoinManifestAuthorityV2Error> {
    let slot: &[u8; STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES] = slot
        .try_into()
        .map_err(|_| StablecoinManifestAuthorityV2Error::WrongLength)?;
    match slot[0] {
        0 if slot[1..] == [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES] => {}
        0 => return Err(StablecoinManifestAuthorityV2Error::NonCanonicalSlot),
        1 => {
            StablecoinPolicyManifestEntryV2::decode_canonical(&slot[1..])?;
        }
        _ => return Err(StablecoinManifestAuthorityV2Error::NonCanonicalSlot),
    }
    Ok(StablecoinManifestRootV2::new(blake2b512_personalized_v2(
        slot,
        tree_personalization(ROLE_LEAF, 0),
    )))
}

/// Hash one ordered pair at an exact Merkle level.  Level zero combines leaf
/// hashes; level three produces the cap-sixteen tree root.
pub fn stablecoin_manifest_node_v2(
    left: StablecoinManifestRootV2,
    right: StablecoinManifestRootV2,
    level: usize,
) -> Result<StablecoinManifestRootV2, StablecoinManifestAuthorityV2Error> {
    if level >= STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH {
        return Err(StablecoinManifestAuthorityV2Error::IndexOutOfRange);
    }
    let mut message = [0u8; 2 * STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES];
    message[..64].copy_from_slice(left.as_bytes());
    message[64..].copy_from_slice(right.as_bytes());
    Ok(StablecoinManifestRootV2::new(blake2b512_personalized_v2(
        &message,
        tree_personalization(ROLE_NODE, level as u8),
    )))
}

fn stablecoin_manifest_levels_v2(
    entries: &[StablecoinPolicyManifestEntryV2],
) -> Result<
    [[StablecoinManifestRootV2; STABLECOIN_MANIFEST_AUTHORITY_V2_CAP];
        STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH + 1],
    StablecoinManifestAuthorityV2Error,
> {
    let slots = stablecoin_manifest_slots_v2(entries)?;
    let mut levels = [[StablecoinManifestRootV2::ZERO; STABLECOIN_MANIFEST_AUTHORITY_V2_CAP];
        STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH + 1];
    for (leaf, slot) in levels[0].iter_mut().zip(&slots) {
        *leaf = stablecoin_manifest_leaf_v2(slot)?;
    }
    for level in 0..STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH {
        let parent_count = STABLECOIN_MANIFEST_AUTHORITY_V2_CAP >> (level + 1);
        for parent in 0..parent_count {
            let left = levels[level][2 * parent];
            let right = levels[level][2 * parent + 1];
            levels[level + 1][parent] = stablecoin_manifest_node_v2(left, right, level)?;
        }
    }
    Ok(levels)
}

/// Build the canonical depth-four Merkle authority root.
pub fn stablecoin_manifest_root_v2(
    entries: &[StablecoinPolicyManifestEntryV2],
) -> Result<StablecoinManifestRootV2, StablecoinManifestAuthorityV2Error> {
    Ok(stablecoin_manifest_levels_v2(entries)?[STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH][0])
}

/// Build the separately domain-separated full-vector root used only as an
/// architecture/reference KAT.  Membership verification uses the Merkle root.
pub fn stablecoin_manifest_full_vector_root_v2(
    entries: &[StablecoinPolicyManifestEntryV2],
) -> Result<StablecoinManifestRootV2, StablecoinManifestAuthorityV2Error> {
    let slots = stablecoin_manifest_slots_v2(entries)?;
    let mut message =
        [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_CAP * STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES];
    for (index, slot) in slots.iter().enumerate() {
        let start = index * STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES;
        message[start..start + STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES].copy_from_slice(slot);
    }
    Ok(StablecoinManifestRootV2::new(blake2b512_personalized_v2(
        &message,
        tree_personalization(ROLE_FULL, 0),
    )))
}

/// Exact private membership witness.  Siblings are ordered from leaf level to
/// root level and the index determines left/right orientation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinManifestMembershipProofV2 {
    pub index: u32,
    pub entry: StablecoinPolicyManifestEntryV2,
    pub siblings: [StablecoinManifestRootV2; STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH],
}

impl StablecoinManifestMembershipProofV2 {
    pub fn encode_canonical(
        &self,
    ) -> Result<
        [u8; STABLECOIN_MANIFEST_AUTHORITY_V2_WITNESS_BYTES],
        StablecoinManifestAuthorityV2Error,
    > {
        if self.index as usize >= STABLECOIN_MANIFEST_AUTHORITY_V2_CAP {
            return Err(StablecoinManifestAuthorityV2Error::IndexOutOfRange);
        }
        let mut encoded = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_WITNESS_BYTES];
        encoded[..4].copy_from_slice(&self.index.to_le_bytes());
        encoded[4..4 + STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES]
            .copy_from_slice(&self.entry.encode_canonical());
        let mut cursor = 4 + STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES;
        for sibling in self.siblings {
            encoded[cursor..cursor + STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES]
                .copy_from_slice(sibling.as_bytes());
            cursor += STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES;
        }
        Ok(encoded)
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinManifestAuthorityV2Error> {
        let raw: &[u8; STABLECOIN_MANIFEST_AUTHORITY_V2_WITNESS_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinManifestAuthorityV2Error::WrongLength)?;
        let index = u32::from_le_bytes(raw[..4].try_into().expect("fixed slice"));
        if index as usize >= STABLECOIN_MANIFEST_AUTHORITY_V2_CAP {
            return Err(StablecoinManifestAuthorityV2Error::IndexOutOfRange);
        }
        let entry = StablecoinPolicyManifestEntryV2::decode_canonical(
            &raw[4..4 + STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES],
        )?;
        let mut siblings = [StablecoinManifestRootV2::ZERO; STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH];
        let mut cursor = 4 + STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES;
        for sibling in &mut siblings {
            let mut bytes = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES];
            bytes.copy_from_slice(
                &raw[cursor..cursor + STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES],
            );
            *sibling = StablecoinManifestRootV2::new(bytes);
            cursor += STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES;
        }
        let decoded = Self {
            index,
            entry,
            siblings,
        };
        if decoded.encode_canonical()? != *raw {
            return Err(StablecoinManifestAuthorityV2Error::WrongLength);
        }
        Ok(decoded)
    }
}

/// Construct a membership witness only for a present canonical slot.
pub fn prove_stablecoin_manifest_membership_v2(
    entries: &[StablecoinPolicyManifestEntryV2],
    index: usize,
) -> Result<StablecoinManifestMembershipProofV2, StablecoinManifestAuthorityV2Error> {
    validate_stablecoin_manifest_entries_v2(entries)?;
    if index >= STABLECOIN_MANIFEST_AUTHORITY_V2_CAP {
        return Err(StablecoinManifestAuthorityV2Error::IndexOutOfRange);
    }
    if index >= entries.len() {
        return Err(StablecoinManifestAuthorityV2Error::SelectedSlotAbsent);
    }
    let levels = stablecoin_manifest_levels_v2(entries)?;
    let mut siblings = [StablecoinManifestRootV2::ZERO; STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH];
    let mut cursor = index;
    for level in 0..STABLECOIN_MANIFEST_AUTHORITY_V2_DEPTH {
        siblings[level] = levels[level][cursor ^ 1];
        cursor >>= 1;
    }
    Ok(StablecoinManifestMembershipProofV2 {
        index: index as u32,
        entry: entries[index].clone(),
        siblings,
    })
}

/// Recompute the Merkle root from one exact selected witness.
pub fn stablecoin_manifest_root_from_membership_v2(
    witness: &StablecoinManifestMembershipProofV2,
) -> Result<StablecoinManifestRootV2, StablecoinManifestAuthorityV2Error> {
    if witness.index as usize >= STABLECOIN_MANIFEST_AUTHORITY_V2_CAP {
        return Err(StablecoinManifestAuthorityV2Error::IndexOutOfRange);
    }
    let mut slot = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_SLOT_BYTES];
    slot[0] = 1;
    slot[1..].copy_from_slice(&witness.entry.encode_canonical());
    let mut current = stablecoin_manifest_leaf_v2(&slot)?;
    let mut cursor = witness.index as usize;
    for (level, sibling) in witness.siblings.iter().copied().enumerate() {
        current = if cursor & 1 == 0 {
            stablecoin_manifest_node_v2(current, sibling, level)?
        } else {
            stablecoin_manifest_node_v2(sibling, current, level)?
        };
        cursor >>= 1;
    }
    if cursor != 0 {
        return Err(StablecoinManifestAuthorityV2Error::IndexOutOfRange);
    }
    Ok(current)
}

/// Domain-separated state snapshot over `parent_height:u64le || root64`.
pub fn stablecoin_manifest_snapshot_v2(
    root: StablecoinManifestRootV2,
    parent_height: u64,
) -> StablecoinManifestSnapshotV2 {
    let mut message = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_PUBLIC_BYTES];
    message[..8].copy_from_slice(&parent_height.to_le_bytes());
    message[8..].copy_from_slice(root.as_bytes());
    StablecoinManifestSnapshotV2::new(blake2b512_personalized_v2(
        &message,
        tree_personalization(ROLE_SNAPSHOT, 0),
    ))
}

/// Proof-public suffix.  The profile, width, cap, and domains are fixed by the
/// prospective transaction identity and are never prover-selected fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinManifestPublicAuthorityV2 {
    pub root: StablecoinManifestRootV2,
    pub parent_height: u64,
}

impl StablecoinManifestPublicAuthorityV2 {
    pub fn encode_canonical(self) -> [u8; STABLECOIN_MANIFEST_AUTHORITY_V2_PUBLIC_BYTES] {
        let mut encoded = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_PUBLIC_BYTES];
        encoded[..64].copy_from_slice(self.root.as_bytes());
        encoded[64..].copy_from_slice(&self.parent_height.to_le_bytes());
        encoded
    }

    pub fn decode_canonical(raw: &[u8]) -> Result<Self, StablecoinManifestAuthorityV2Error> {
        let raw: &[u8; STABLECOIN_MANIFEST_AUTHORITY_V2_PUBLIC_BYTES] = raw
            .try_into()
            .map_err(|_| StablecoinManifestAuthorityV2Error::WrongLength)?;
        let mut root = [0u8; STABLECOIN_MANIFEST_AUTHORITY_V2_DIGEST_BYTES];
        root.copy_from_slice(&raw[..64]);
        Ok(Self {
            root: StablecoinManifestRootV2::new(root),
            parent_height: u64::from_le_bytes(raw[64..].try_into().expect("fixed slice")),
        })
    }
}

/// Verifier-owned canonical parent-state input.  The node must obtain this
/// typed value from authenticated parent state before invoking a proof
/// verifier; the prover cannot self-assert it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinManifestParentStateV2 {
    pub root: StablecoinManifestRootV2,
    pub parent_height: u64,
    pub snapshot: StablecoinManifestSnapshotV2,
}

impl StablecoinManifestParentStateV2 {
    pub fn from_canonical_parent(root: StablecoinManifestRootV2, parent_height: u64) -> Self {
        Self {
            root,
            parent_height,
            snapshot: stablecoin_manifest_snapshot_v2(root, parent_height),
        }
    }

    pub fn validate_snapshot(self) -> Result<(), StablecoinManifestAuthorityV2Error> {
        if self.snapshot != stablecoin_manifest_snapshot_v2(self.root, self.parent_height) {
            return Err(StablecoinManifestAuthorityV2Error::ParentSnapshotMismatch);
        }
        Ok(())
    }
}

/// Require exact equality between the proof-public suffix and the authenticated
/// verifier-owned parent state.  This is deliberately an outer verifier check,
/// not a Merkle relation predicate.
pub fn verify_stablecoin_manifest_parent_v2(
    public: StablecoinManifestPublicAuthorityV2,
    parent: StablecoinManifestParentStateV2,
) -> Result<(), StablecoinManifestAuthorityV2Error> {
    parent.validate_snapshot()?;
    if public.root != parent.root || public.parent_height != parent.parent_height {
        return Err(StablecoinManifestAuthorityV2Error::ParentRootHeightMismatch);
    }
    Ok(())
}

/// Stablecoin statement fields that must agree with the selected row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinManifestBindingV2 {
    pub asset_id: u64,
    pub policy_version: u32,
    pub issuance_magnitude: u64,
    pub policy_identity: StablecoinPolicyIdentityV2,
    pub oracle_commitment: StablecoinOracleAuthorityCommitmentV2,
    pub attestation_commitment: StablecoinAttestationAuthorityCommitmentV2,
}

pub fn stablecoin_manifest_binding_v2(
    entry: &StablecoinPolicyManifestEntryV2,
    issuance_magnitude: u64,
) -> StablecoinManifestBindingV2 {
    StablecoinManifestBindingV2 {
        asset_id: u64::from(entry.asset_id),
        policy_version: entry.policy_version,
        issuance_magnitude,
        policy_identity: stablecoin_policy_identity_v2(entry),
        oracle_commitment: entry.oracle_commitment,
        attestation_commitment: entry.attestation_commitment,
    }
}

/// Check exact policy identity, statement binding, lifecycle, freshness,
/// dispute, and issuance semantics at the canonical parent height.
pub fn verify_stablecoin_manifest_entry_v2(
    binding: StablecoinManifestBindingV2,
    entry: &StablecoinPolicyManifestEntryV2,
    parent_height: u64,
) -> Result<(), StablecoinManifestAuthorityV2Error> {
    if stablecoin_policy_identity_v2(entry) != binding.policy_identity {
        return Err(StablecoinManifestAuthorityV2Error::PolicyIdentityMismatch);
    }
    if u64::from(entry.asset_id) != binding.asset_id
        || entry.policy_version != binding.policy_version
        || entry.oracle_commitment != binding.oracle_commitment
        || entry.attestation_commitment != binding.attestation_commitment
    {
        return Err(StablecoinManifestAuthorityV2Error::BindingMismatch);
    }
    if !entry.active {
        return Err(StablecoinManifestAuthorityV2Error::InactivePolicy);
    }
    if parent_height < entry.enabled_at {
        return Err(StablecoinManifestAuthorityV2Error::PolicyNotEnabled);
    }
    if entry
        .retired_at
        .is_some_and(|retired_at| parent_height >= retired_at)
    {
        return Err(StablecoinManifestAuthorityV2Error::PolicyRetired);
    }
    if entry.attestation_disputed {
        return Err(StablecoinManifestAuthorityV2Error::AttestationDisputed);
    }
    if entry.oracle_submitted_at > parent_height {
        return Err(StablecoinManifestAuthorityV2Error::OracleFromFuture);
    }
    if parent_height - entry.oracle_submitted_at > entry.oracle_max_age {
        return Err(StablecoinManifestAuthorityV2Error::OracleStale);
    }
    if binding.issuance_magnitude == 0 {
        return Err(StablecoinManifestAuthorityV2Error::ZeroIssuance);
    }
    if u128::from(binding.issuance_magnitude) > entry.max_mint_per_epoch {
        return Err(StablecoinManifestAuthorityV2Error::IssuanceCapExceeded);
    }
    Ok(())
}

/// Complete prospective manifest-authority predicate.  This first authenticates
/// the verifier-owned parent root/height, then checks selected membership and
/// row semantics.  It remains unused by every active route.
pub fn verify_stablecoin_manifest_authority_v2(
    binding: StablecoinManifestBindingV2,
    public: StablecoinManifestPublicAuthorityV2,
    witness: &StablecoinManifestMembershipProofV2,
    parent: StablecoinManifestParentStateV2,
) -> Result<(), StablecoinManifestAuthorityV2Error> {
    verify_stablecoin_manifest_parent_v2(public, parent)?;
    if stablecoin_manifest_root_from_membership_v2(witness)? != public.root {
        return Err(StablecoinManifestAuthorityV2Error::MembershipRootMismatch);
    }
    verify_stablecoin_manifest_entry_v2(binding, &witness.entry, public.parent_height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const POLICY_KAT: [u8; 64] = [
        0x86, 0x6d, 0x20, 0x13, 0x43, 0x96, 0x85, 0x85, 0xd9, 0x0f, 0x58, 0xe6, 0x98, 0xc0, 0x64,
        0x8c, 0x34, 0xff, 0x55, 0x1d, 0xa1, 0x3c, 0x43, 0x7e, 0x68, 0x9d, 0xa6, 0xca, 0x29, 0xfe,
        0x15, 0x71, 0x9d, 0xe8, 0xac, 0x1f, 0xcb, 0xa7, 0xb5, 0xb0, 0xcd, 0xca, 0x0d, 0xb9, 0x5b,
        0x64, 0x1a, 0x63, 0xa1, 0x48, 0x3e, 0x94, 0xb9, 0xc5, 0x2a, 0xab, 0xda, 0x5e, 0xab, 0xa7,
        0x5c, 0x7e, 0xa3, 0x45,
    ];
    const ORACLE_KAT: [u8; 64] = [
        0x4f, 0x66, 0x00, 0xa3, 0x5d, 0xe0, 0x80, 0x28, 0xd7, 0xb4, 0xe9, 0x8c, 0xd6, 0x0d, 0x7d,
        0xca, 0xdd, 0x20, 0x86, 0xc6, 0x70, 0x45, 0xb4, 0xd6, 0x22, 0x72, 0xaf, 0x12, 0xcc, 0xed,
        0x76, 0x86, 0x37, 0xaa, 0xc5, 0x21, 0x5c, 0x00, 0xb7, 0x25, 0x7e, 0x1e, 0xff, 0x51, 0xf5,
        0x61, 0x38, 0xf5, 0xb9, 0x2e, 0x4b, 0x48, 0x6b, 0xb8, 0x70, 0xac, 0x6e, 0xf6, 0x4e, 0x14,
        0x2e, 0x2d, 0xf2, 0x5e,
    ];
    const ATTESTATION_KAT: [u8; 64] = [
        0x7b, 0x04, 0x34, 0xf9, 0x52, 0xf5, 0x72, 0xc2, 0xd7, 0x4a, 0xa4, 0x84, 0x61, 0x14, 0x28,
        0x42, 0xd3, 0xd5, 0x04, 0xd2, 0xff, 0xc0, 0x10, 0x62, 0xd4, 0xd3, 0xc5, 0x5a, 0xfb, 0xfe,
        0xdd, 0xd5, 0x49, 0xe0, 0x7f, 0xdb, 0xd7, 0x17, 0x09, 0x45, 0x0b, 0x1d, 0x45, 0xd1, 0x3e,
        0xb0, 0x18, 0x6d, 0xd7, 0xeb, 0x7b, 0x34, 0xb5, 0xaa, 0x83, 0xe5, 0x57, 0xa4, 0x0c, 0xda,
        0x8b, 0x25, 0x90, 0x5d,
    ];
    const MERKLE_ROOT_KAT: [u8; 64] = [
        0x0c, 0x6c, 0xbb, 0x84, 0x0c, 0x55, 0x23, 0xb5, 0x8c, 0x3a, 0xae, 0x93, 0xe0, 0x8f, 0xe1,
        0x7f, 0x95, 0x6c, 0x7b, 0x22, 0xf7, 0xc4, 0x3d, 0x05, 0xef, 0x7d, 0x10, 0xf6, 0xd1, 0xdc,
        0xdd, 0x1e, 0x7c, 0x45, 0x56, 0xae, 0x98, 0x3e, 0xd5, 0x06, 0xd5, 0x10, 0xbc, 0x8f, 0x60,
        0x7d, 0x7d, 0x3a, 0x71, 0x4d, 0xb4, 0x20, 0xc9, 0x94, 0x3a, 0xd4, 0xc7, 0xa6, 0xe7, 0x5d,
        0xd7, 0xea, 0x99, 0x39,
    ];
    const FULL_ROOT_KAT: [u8; 64] = [
        0xc6, 0xdc, 0x59, 0xc6, 0x61, 0x90, 0xe9, 0xd6, 0xa4, 0x99, 0x37, 0x4b, 0x51, 0x47, 0x28,
        0x8e, 0xae, 0x6b, 0xa6, 0x9a, 0x10, 0xb8, 0xa7, 0xd5, 0xf9, 0x9b, 0x73, 0x6a, 0x47, 0x45,
        0xfc, 0x01, 0x28, 0x7d, 0x03, 0x09, 0xa0, 0xc8, 0xaf, 0x9a, 0x7c, 0xff, 0xba, 0x77, 0xbf,
        0xa2, 0xde, 0x90, 0x86, 0x40, 0xee, 0x0f, 0x4c, 0xa9, 0x95, 0xb5, 0x7f, 0x91, 0xf5, 0x6d,
        0x81, 0xa5, 0xea, 0xf2,
    ];
    const SNAPSHOT_KAT: [u8; 64] = [
        0xf7, 0xa6, 0x0b, 0x50, 0xef, 0x6c, 0xd8, 0x48, 0x54, 0x6b, 0xe6, 0x53, 0xfe, 0x42, 0x79,
        0x06, 0xc0, 0x60, 0x62, 0xc1, 0x8d, 0xf3, 0xf3, 0x4f, 0x6a, 0x88, 0x72, 0x02, 0xcf, 0xf7,
        0xe5, 0x76, 0xbc, 0xf6, 0xc1, 0x34, 0x12, 0xd3, 0xda, 0x08, 0xf4, 0x39, 0x76, 0x07, 0xc5,
        0x08, 0x0c, 0x53, 0xfd, 0x94, 0xb7, 0xde, 0xcc, 0x90, 0xcf, 0xf8, 0x20, 0x01, 0x52, 0xd3,
        0xe3, 0x10, 0x04, 0xf2,
    ];

    fn sample_sources(
        asset_id: u32,
        policy_version: u32,
    ) -> (
        StablecoinOracleAuthoritySourceV2,
        StablecoinAttestationAuthoritySourceV2,
    ) {
        let delta = asset_id - 1001;
        (
            StablecoinOracleAuthoritySourceV2 {
                asset_id,
                policy_version,
                oracle_feed: 7 + delta,
                submitted_at: 42,
                source_id: [0x31 + (delta % 31) as u8; 32],
                payload: {
                    let mut payload = b"price:i128le=".to_vec();
                    payload.extend_from_slice(&u128::from(123_456 + delta).to_le_bytes());
                    payload
                },
            },
            StablecoinAttestationAuthoritySourceV2 {
                asset_id,
                policy_version,
                attestation_id: 0x0102_0304_0506_0708 + u64::from(delta),
                created_at: 9,
                issuer_id: [0x51 + (delta % 31) as u8; 32],
                payload: b"eligible:true".to_vec(),
            },
        )
    }

    fn sample_entry(asset_id: u32) -> StablecoinPolicyManifestEntryV2 {
        let (oracle, attestation) = sample_sources(asset_id, 3);
        StablecoinPolicyManifestEntryV2 {
            asset_id,
            oracle_feed: oracle.oracle_feed,
            attestation_id: attestation.attestation_id,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000_000,
            oracle_max_age: 120,
            oracle_submitted_at: oracle.submitted_at,
            enabled_at: 10,
            retired_at: Some(1000),
            policy_version: 3,
            active: true,
            oracle_commitment: stablecoin_oracle_authority_commitment_v2(&oracle).unwrap(),
            attestation_commitment: stablecoin_attestation_authority_commitment_v2(&attestation)
                .unwrap(),
            attestation_disputed: false,
        }
    }

    fn sample_entries() -> Vec<StablecoinPolicyManifestEntryV2> {
        (0..STABLECOIN_MANIFEST_AUTHORITY_V2_CAP)
            .map(|index| sample_entry(1001 + index as u32))
            .collect()
    }

    #[test]
    fn constructor_and_root_kats_match_the_independent_reference() {
        let entries = sample_entries();
        let entry = &entries[0];
        let (oracle, attestation) = sample_sources(1001, 3);
        assert_eq!(
            stablecoin_policy_identity_v2(entry).into_bytes(),
            POLICY_KAT
        );
        assert_eq!(
            stablecoin_oracle_authority_commitment_v2(&oracle)
                .unwrap()
                .into_bytes(),
            ORACLE_KAT
        );
        assert_eq!(
            stablecoin_attestation_authority_commitment_v2(&attestation)
                .unwrap()
                .into_bytes(),
            ATTESTATION_KAT
        );
        validate_stablecoin_authority_sources_v2(entry, &oracle, &attestation).unwrap();
        let root = stablecoin_manifest_root_v2(&entries).unwrap();
        assert_eq!(root.into_bytes(), MERKLE_ROOT_KAT);
        assert_eq!(
            stablecoin_manifest_full_vector_root_v2(&entries)
                .unwrap()
                .into_bytes(),
            FULL_ROOT_KAT
        );
        assert_eq!(
            stablecoin_manifest_snapshot_v2(root, 50).into_bytes(),
            SNAPSHOT_KAT
        );
    }

    #[test]
    fn all_sixteen_paths_and_exact_codecs_verify() {
        let entries = sample_entries();
        let root = stablecoin_manifest_root_v2(&entries).unwrap();
        let public = StablecoinManifestPublicAuthorityV2 {
            root,
            parent_height: 50,
        };
        assert_eq!(
            StablecoinManifestPublicAuthorityV2::decode_canonical(&public.encode_canonical())
                .unwrap(),
            public
        );
        let parent = StablecoinManifestParentStateV2::from_canonical_parent(root, 50);
        for (index, entry) in entries.iter().enumerate() {
            let witness = prove_stablecoin_manifest_membership_v2(&entries, index).unwrap();
            let encoded = witness.encode_canonical().unwrap();
            assert_eq!(
                encoded.len(),
                STABLECOIN_MANIFEST_AUTHORITY_V2_WITNESS_BYTES
            );
            let decoded = StablecoinManifestMembershipProofV2::decode_canonical(&encoded).unwrap();
            assert_eq!(decoded, witness);
            verify_stablecoin_manifest_authority_v2(
                stablecoin_manifest_binding_v2(entry, 1),
                public,
                &decoded,
                parent,
            )
            .unwrap();
        }
    }

    #[test]
    fn every_row_and_path_byte_mutation_rejects() {
        let entries = sample_entries();
        let root = stablecoin_manifest_root_v2(&entries).unwrap();
        let public = StablecoinManifestPublicAuthorityV2 {
            root,
            parent_height: 50,
        };
        let parent = StablecoinManifestParentStateV2::from_canonical_parent(root, 50);
        let binding = stablecoin_manifest_binding_v2(&entries[7], 1);
        let witness = prove_stablecoin_manifest_membership_v2(&entries, 7).unwrap();
        let canonical = witness.encode_canonical().unwrap();

        for offset in 4..4 + STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES {
            let mut changed = canonical;
            changed[offset] ^= 1;
            let rejected = StablecoinManifestMembershipProofV2::decode_canonical(&changed)
                .and_then(|candidate| {
                    verify_stablecoin_manifest_authority_v2(binding, public, &candidate, parent)
                });
            assert!(rejected.is_err(), "row byte {offset} was not bound");
        }
        let path_start = 4 + STABLECOIN_MANIFEST_AUTHORITY_V2_ENTRY_BYTES;
        for offset in path_start..STABLECOIN_MANIFEST_AUTHORITY_V2_WITNESS_BYTES {
            let mut changed = canonical;
            changed[offset] ^= 1;
            let candidate =
                StablecoinManifestMembershipProofV2::decode_canonical(&changed).unwrap();
            assert!(
                verify_stablecoin_manifest_authority_v2(binding, public, &candidate, parent,)
                    .is_err(),
                "path byte {offset} was not bound"
            );
        }
    }

    #[test]
    fn ordering_duplicates_prefix_and_parent_mutations_reject() {
        let entries = sample_entries();
        let mut reversed = entries.clone();
        reversed.reverse();
        assert_eq!(
            validate_stablecoin_manifest_entries_v2(&reversed),
            Err(StablecoinManifestAuthorityV2Error::EntriesNotStrictlyOrdered)
        );
        let duplicate = vec![entries[0].clone(), entries[0].clone()];
        assert_eq!(
            validate_stablecoin_manifest_entries_v2(&duplicate),
            Err(StablecoinManifestAuthorityV2Error::EntriesNotStrictlyOrdered)
        );
        let mut same_key = entries[0].clone();
        same_key.oracle_feed ^= 1;
        assert_eq!(
            validate_stablecoin_manifest_entries_v2(&[entries[0].clone(), same_key]),
            Err(StablecoinManifestAuthorityV2Error::EntriesNotStrictlyOrdered)
        );

        let mut slots = stablecoin_manifest_slots_v2(&entries[..1]).unwrap();
        slots[0].fill(0);
        slots[1][0] = 1;
        slots[1][1..].copy_from_slice(&entries[0].encode_canonical());
        assert_eq!(
            stablecoin_manifest_entries_from_slots_v2(&slots),
            Err(StablecoinManifestAuthorityV2Error::PresentAfterEmptySlot)
        );
        let mut bad_empty = stablecoin_manifest_slots_v2(&entries[..1]).unwrap();
        bad_empty[1][1] = 1;
        assert_eq!(
            stablecoin_manifest_entries_from_slots_v2(&bad_empty),
            Err(StablecoinManifestAuthorityV2Error::NonCanonicalSlot)
        );

        let root = stablecoin_manifest_root_v2(&entries).unwrap();
        let public = StablecoinManifestPublicAuthorityV2 {
            root,
            parent_height: 50,
        };
        let parent = StablecoinManifestParentStateV2::from_canonical_parent(root, 50);
        let mut wrong_root = root.into_bytes();
        wrong_root[0] ^= 1;
        assert!(verify_stablecoin_manifest_parent_v2(
            StablecoinManifestPublicAuthorityV2 {
                root: StablecoinManifestRootV2::new(wrong_root),
                parent_height: 50,
            },
            parent,
        )
        .is_err());
        assert!(verify_stablecoin_manifest_parent_v2(
            StablecoinManifestPublicAuthorityV2 {
                parent_height: 51,
                ..public
            },
            parent,
        )
        .is_err());
        let mut snapshot = parent.snapshot.into_bytes();
        snapshot[0] ^= 1;
        assert!(verify_stablecoin_manifest_parent_v2(
            public,
            StablecoinManifestParentStateV2 {
                snapshot: StablecoinManifestSnapshotV2::new(snapshot),
                ..parent
            },
        )
        .is_err());
    }

    #[test]
    fn exact_source_mutations_cannot_retain_constructor_identity() {
        let entry = sample_entry(1001);
        let (oracle, attestation) = sample_sources(1001, 3);
        let oracle_hash = stablecoin_oracle_authority_commitment_v2(&oracle).unwrap();
        let oracle_bytes = oracle.encode_canonical().unwrap();
        for offset in 0..oracle_bytes.len() {
            let mut changed = oracle_bytes.clone();
            changed[offset] ^= 1;
            let same = StablecoinOracleAuthoritySourceV2::decode_canonical(&changed)
                .and_then(|source| stablecoin_oracle_authority_commitment_v2(&source))
                .is_ok_and(|digest| digest == oracle_hash);
            assert!(!same, "oracle source byte {offset} was not bound");
        }
        let attestation_hash =
            stablecoin_attestation_authority_commitment_v2(&attestation).unwrap();
        let attestation_bytes = attestation.encode_canonical().unwrap();
        for offset in 0..attestation_bytes.len() {
            let mut changed = attestation_bytes.clone();
            changed[offset] ^= 1;
            let same = StablecoinAttestationAuthoritySourceV2::decode_canonical(&changed)
                .and_then(|source| stablecoin_attestation_authority_commitment_v2(&source))
                .is_ok_and(|digest| digest == attestation_hash);
            assert!(!same, "attestation source byte {offset} was not bound");
        }
        validate_stablecoin_authority_sources_v2(&entry, &oracle, &attestation).unwrap();
    }

    #[test]
    fn all_release_and_integration_authority_remains_false() {
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_ACTIVE);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_KERNEL_GLOBAL_ROOT_INTEGRATED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_GENESIS_INTEGRATED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_STATE_WRITER_INTEGRATED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_ORACLE_CONSTRUCTOR_AUTHORIZED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_ATTESTATION_CONSTRUCTOR_AUTHORIZED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_RELATION_INTEGRATED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_CONSENSUS_ROUTE_AUTHORIZED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_QROM_AUTHORIZED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_COMPLETE_ZK_AUTHORIZED);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_FORMAL_REFINEMENT_COMPLETE);
        assert!(!STABLECOIN_MANIFEST_AUTHORITY_V2_PRODUCTION_AUTHORIZED);
    }
}
