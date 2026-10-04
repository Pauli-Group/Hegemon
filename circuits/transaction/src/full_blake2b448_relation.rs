//! Diagnostic conventional-hash successor for the full 2x2 transaction relation.
//!
//! This module deliberately allocates no production statement, envelope, proof, or
//! consensus identity. Its `HX448C02` tags are test-only candidate domains and are
//! rejected by production dispatch. Grammar two carries the live stablecoin
//! authority widths directly: 48-byte policy, oracle, and attestation commitments;
//! it never pads, truncates, or reinterprets the rejected grammar-one 56-byte
//! diagnostics. The semantic compiler can evaluate the same
//! canonical frames with either of the two surviving conventional-hash profiles:
//!
//! * unkeyed RFC 7693 BLAKE2b-448 for hidden/preimage roles; or
//! * separately tagged FIPS 202 SHA3-512 calls, truncated to 56 bytes.
//!
//! Collision-only roles remain FIPS 202 SHAKE256-448 in both profiles.  There are
//! exactly 83 physical calls.  The BLAKE profile uses 15 BLAKE calls / 28
//! compressions and 68 SHAKE calls / 105 Keccak-f permutations.  The split-SHA3
//! profile uses 15 SHA3 calls / 46 permutations plus the same 105 SHAKE
//! permutations.  A fixed authorization program selects all message blocks and
//! metadata before four hash pipelines; it never hashes five arms and selects an
//! output afterward.
//!
//! This is a scalar semantic diagnostic with independently executable per-call
//! Boolean hash traces, not one aggregate proof relation or production
//! authorization. The retained object rechecks its canonical statement,
//! semantics, per-index call inventory, source frames, and local traces, but the
//! cross-call source/digest equality graph still belongs in a proof-backend
//! lowering. In particular, the 11,472-word raw-AND advantage for BLAKE excludes
//! its linear additions/rotations, mux metadata, DCE, and proof geometry. No
//! same-backend compiled artifact resolves the profiles, and neither has a
//! complete composed proof-system/QROM certificate or verifier refinement.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use hegemon_hash384::{blake2b_384_domain_hash, domains};
use protocol_kernel::manifest::{ProtocolManifest, StablecoinPolicyManifestEntry};
use protocol_kernel::stablecoin_manifest_commitment_v1::{
    StablecoinManifestStateCommitmentV1, STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES,
    STABLECOIN_MANIFEST_STATE_V1_VERSION,
};
use sha3::{Digest as Sha3Digest, Sha3_512};
use thiserror::Error;

use crate::full_shake448_relation::{
    AccumulatorOpening, FullShake448Witness, NoteKind, NoteOpening, PrivateAuthMode,
};
use crate::full_shake448_statement::{
    SignedMagnitude, V6ActivationBinding, V6_CANONICAL_CIPHERTEXT_BYTES, V6_MAX_NOTE_VALUE,
};
use crate::smallwood_blake2b384::{
    blake2b_relation, Blake2bConstraintTrace, Blake2bRelationError, BLAKE2B_448_OUTPUT_BYTES,
    BLAKE2B_BLOCK_BYTES,
};
use crate::smallwood_shake256_full_relation::{
    shake256_relation, Shake256ConstraintTrace, Shake256RelationError,
};

pub const MAX_INPUTS: usize = 2;
pub const MAX_OUTPUTS: usize = 2;
pub const BALANCE_SLOTS: usize = 4;
pub const MERKLE_DEPTH: usize = 32;
pub const MAX_SIGNERS: usize = 6;
pub const SPEND_KEY_BYTES: usize = 48;
pub const DIGEST_BYTES: usize = 56;
pub const LIVE_STABLECOIN_BINDING_BYTES: usize = 48;
pub const LIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES: usize = 61;
pub const LIVE_STABLECOIN_POLICY_DOMAIN: &[u8] = domains::KERNEL_STABLECOIN_POLICY_V2;
/// Version of the diagnostic consensus-state input seam. This is not a
/// transaction grammar, proof-profile, PCS, or production identity version.
pub const STABLECOIN_CONSENSUS_STATE_SEAM_VERSION: u32 = STABLECOIN_MANIFEST_STATE_V1_VERSION;
/// The kernel's inactive v1 manifest-state commitment uses conventional
/// BLAKE2b-384. Its 48-byte width is independent of the proof challenge field
/// and gives no strict-PQ composition credit to the C02 candidate.
pub const STABLECOIN_MANIFEST_STATE_COMMITMENT_V1_BYTES: usize =
    STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_BYTES;
pub const CANDIDATE_STATEMENT_BYTES: usize = 869;
pub const CANDIDATE_STATEMENT_LIMB_BYTES: usize = 7;
pub const CANDIDATE_STATEMENT_LIMBS: usize =
    CANDIDATE_STATEMENT_BYTES.div_ceil(CANDIDATE_STATEMENT_LIMB_BYTES);
pub const OFFSET_FLAGS: usize = 10;
pub const OFFSET_ANCHOR: usize = 14;
pub const OFFSET_NULLIFIERS: usize = 70;
pub const OFFSET_COMMITMENTS: usize = 182;
pub const OFFSET_CIPHERTEXT_HASHES: usize = 294;
pub const OFFSET_CIPHERTEXT_SIZES: usize = 406;
pub const OFFSET_ASSETS: usize = 414;
pub const OFFSET_FEE: usize = 446;
pub const OFFSET_VALUE_BALANCE_SIGN: usize = 454;
pub const OFFSET_VALUE_BALANCE_MAGNITUDE: usize = 455;
pub const OFFSET_STABLE_ENABLED: usize = 463;
pub const OFFSET_STABLE_ASSET: usize = 464;
pub const OFFSET_STABLE_VERSION: usize = 472;
pub const OFFSET_STABLE_ISSUANCE_SIGN: usize = 476;
pub const OFFSET_STABLE_ISSUANCE_MAGNITUDE: usize = 477;
pub const OFFSET_STABLE_POLICY: usize = 485;
pub const OFFSET_STABLE_ORACLE: usize = 533;
pub const OFFSET_STABLE_ATTESTATION: usize = 581;
pub const OFFSET_BALANCE_TAG: usize = 629;
pub const OFFSET_ACTIVATION: usize = 685;
pub const OFFSET_NETWORK: usize = 693;
pub const OFFSET_BACKEND: usize = 697;
pub const OFFSET_PROFILE: usize = 698;
pub const OFFSET_DOMAIN_SET: usize = 699;
pub const OFFSET_CHAIN_ID: usize = 701;
pub const OFFSET_GENESIS_ID: usize = 757;
pub const OFFSET_RULES_HASH: usize = 813;
pub const NATIVE_ASSET_ID: u64 = 0;
pub const PADDING_ASSET_ID: u64 = u64::MAX;
pub const RESERVED_REDUCED_PADDING_ASSET_ID: u64 = u32::MAX as u64 - 1;
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// Diagnostic-only.  This value is forbidden as a production statement magic.
pub const RETIRED_DIAGNOSTIC_STATEMENT_MAGIC: [u8; 8] = *b"HX448C01";
pub const CANDIDATE_STATEMENT_MAGIC: [u8; 8] = *b"HX448C02";
/// Grammar two replaces only the three 56-byte diagnostic stablecoin values
/// with their authoritative live 48-byte widths. Grammar one is not accepted.
pub const CANDIDATE_STATEMENT_GRAMMAR: u16 = 2;
/// Diagnostic-only common application frame tag.  It is not a proof identity.
pub const CANDIDATE_PROFILE_TAG: [u8; 8] = *b"HX448C02";

pub const ROLE_NOTE: [u8; 8] = *b"nt.b4481";
pub const ROLE_NULLIFIER: [u8; 8] = *b"nf.b4481";
pub const ROLE_MERKLE: [u8; 8] = *b"mk.s4481";
pub const ROLE_SPEND_A: [u8; 8] = *b"sk.b44a1";
pub const ROLE_SPEND_B: [u8; 8] = *b"sk.b44b1";
pub const ROLE_POLICY: [u8; 8] = *b"pl.b4481";
pub const ROLE_AUTH_A: [u8; 8] = *b"au.b44a1";
pub const ROLE_AUTH_B: [u8; 8] = *b"au.b44b1";
pub const ROLE_INTENT: [u8; 8] = *b"in.s4481";
pub const ROLE_BALANCE: [u8; 8] = *b"bl.s4481";
pub const ROLE_CIPHERTEXT: [u8; 8] = *b"ct.s4481";
pub const LANE_A_TAG: [u8; 8] = *b"lane.A01";
pub const LANE_B_TAG: [u8; 8] = *b"lane.B01";

pub const NOTE_CALL_START: usize = 0;
pub const NULLIFIER_CALL_START: usize = 4;
pub const MERKLE_CALL_START: usize = 6;
pub const SPEND_A_CALL_START: usize = 70;
pub const SPEND_B_CALL_START: usize = 72;
pub const POLICY_CALL: usize = 74;
pub const AUTH_A_CALL_START: usize = 75;
pub const AUTH_B_CALL_START: usize = 77;
pub const INTENT_CALL: usize = 79;
pub const BALANCE_CALL: usize = 80;
pub const CIPHERTEXT_CALL_START: usize = 81;

pub const PHYSICAL_HASH_CALLS: usize = 83;
pub const SECRET_HASH_CALLS: usize = 15;
pub const COLLISION_HASH_CALLS: usize = 68;
pub const BLAKE2B_COMPRESSIONS: usize = 28;
pub const SHAKE256_PERMUTATIONS: usize = 105;
pub const SPLIT_SHA3_PERMUTATIONS: usize = 46;
/// One native AND word for each of 576 additions per BLAKE2b compression.
pub const BLAKE_NATIVE_CORE_WORDS: usize = BLAKE2B_COMPRESSIONS * 576;
/// `rotr` lowers to one linear Shift constraint and no AND.
pub const BLAKE_ROTATION_LINEAR_WORDS: usize = BLAKE2B_COMPRESSIONS * 384;
/// Each `iadd` also emits one linear constraint in addition to its AND.
pub const BLAKE_ADDITION_LINEAR_WORDS: usize = BLAKE2B_COMPRESSIONS * 576;
pub const SHAKE_NATIVE_CORE_WORDS: usize = SHAKE256_PERMUTATIONS * 600;
pub const MIXED_BLAKE_NATIVE_CORE_WORDS: usize = BLAKE_NATIVE_CORE_WORDS + SHAKE_NATIVE_CORE_WORDS;
pub const SPLIT_SHA3_NATIVE_CORE_WORDS: usize =
    (SHAKE256_PERMUTATIONS + SPLIT_SHA3_PERMUTATIONS) * 600;
/// Exact Goldilocks scalar constraints across the four fixed authorization
/// calls. This is a relation diagnostic, not a native-Binius/DCE measurement.
pub const BLAKE_AUTH_MUX_SCALAR_CONSTRAINTS: usize = 2 * (204_542 + 202_270);
/// Exact Goldilocks scalar constraints across the same four authorization
/// calls for split SHA3-512/56. This is not a native-Binius/DCE measurement.
pub const SPLIT_SHA3_AUTH_MUX_SCALAR_CONSTRAINTS: usize = 2 * (375_514 + 373_242);

pub const FULL_BLAKE2B448_AGGREGATE_CONSTRAINT_RELATION_COMPILED: bool = false;
pub const FULL_BLAKE2B448_PRODUCTION_AUTHORIZED: bool = false;
/// Exact 48-byte compatibility binding is not a positive strict-PQ composition
/// margin for three opaque authorities. A final successor needs fresh wider
/// bindings derived from authoritative constructors/preimages while retaining
/// these 48-byte values as consensus compatibility checks.
pub const FULL_BLAKE2B448_STRICT_STABLECOIN_PQ_MARGIN: bool = false;
pub const FULL_BLAKE2B448_PRODUCTION_BLOCKERS: [&str; 8] = [
    "same-backend compiled/DCE profile tournament has no winner",
    "aggregate source/digest wire equality graph is absent from this scalar diagnostic",
    "stablecoin lifecycle equality has only an uncompiled typed state-input seam; the whole-manifest commitment and selected-entry membership graph are absent",
    "opaque 48-byte stablecoin authorities have no positive strict-PQ composition margin or wider constructor bridge",
    "complete-zero-knowledge proof and simulator are absent",
    "composed PCS/IOP/Fiat-Shamir/QROM certificate is absent",
    "Rust/proof-backend/verifier refinement is absent",
    "production statement/envelope/consensus identity is intentionally unallocated",
];

pub type Digest384 = [u8; LIVE_STABLECOIN_BINDING_BYTES];

/// Width-consistent public stablecoin surface for the diagnostic relation.
///
/// These byte arrays have the same widths and meanings as the live
/// `StablecoinPolicyBinding`. They are not conversions from a 56-byte value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinStatementBinding384 {
    pub enabled: bool,
    pub asset_id: u64,
    pub policy_version: u32,
    pub issuance_delta: SignedMagnitude,
    pub policy_hash: Digest384,
    pub oracle_commitment: Digest384,
    pub attestation_commitment: Digest384,
}

/// Fresh, diagnostic-only statement grammar. All PQ relation digests remain
/// 56 bytes; only the live stablecoin authority surface is 48 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullBlake2b448Statement {
    pub input_flags: [bool; MAX_INPUTS],
    pub output_flags: [bool; MAX_OUTPUTS],
    pub anchor: Digest448,
    pub nullifiers: [Digest448; MAX_INPUTS],
    pub commitments: [Digest448; MAX_OUTPUTS],
    pub ciphertext_hashes: [Digest448; MAX_OUTPUTS],
    pub ciphertext_sizes: [u32; MAX_OUTPUTS],
    pub balance_asset_ids: [u64; BALANCE_SLOTS],
    pub fee: u64,
    pub value_balance: SignedMagnitude,
    pub stablecoin: StablecoinStatementBinding384,
    pub balance_tag: Digest448,
    pub activation: V6ActivationBinding,
}

const KECCAK_RATE_SHA3_512: usize = 72;
const KECCAK_STATE_BITS: usize = 1_600;
const KECCAK_LANE_BITS: usize = 64;

const BLAKE2B_IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
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

const KECCAK_RHO_OFFSETS: [[usize; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

pub type Digest448 = [u8; DIGEST_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretHashProfile {
    UnkeyedBlake2b448,
    SplitSha3_512Truncated448,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateHashAlgorithm {
    Blake2b448,
    Sha3_512Truncated448,
    Shake256_448,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashPurpose {
    CollisionBinding,
    PreimageBinding,
    HiddenSeedDerivation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashRoleSpec {
    pub role: [u8; 8],
    pub purpose: HashPurpose,
    pub calls: usize,
    pub maximum_frame_bytes: usize,
    pub blake_compressions_per_call: usize,
    pub sha3_permutations_per_call: usize,
    pub shake_permutations_per_call: usize,
}

pub const MIXED_HASH_REGISTRY: [HashRoleSpec; 11] = [
    HashRoleSpec {
        role: ROLE_NOTE,
        purpose: HashPurpose::PreimageBinding,
        calls: 4,
        maximum_frame_bytes: 232,
        blake_compressions_per_call: 2,
        sha3_permutations_per_call: 4,
        shake_permutations_per_call: 0,
    },
    HashRoleSpec {
        role: ROLE_NULLIFIER,
        purpose: HashPurpose::HiddenSeedDerivation,
        calls: 2,
        maximum_frame_bytes: 135,
        blake_compressions_per_call: 2,
        sha3_permutations_per_call: 2,
        shake_permutations_per_call: 0,
    },
    HashRoleSpec {
        role: ROLE_MERKLE,
        purpose: HashPurpose::CollisionBinding,
        calls: 64,
        maximum_frame_bytes: 133,
        blake_compressions_per_call: 0,
        sha3_permutations_per_call: 0,
        shake_permutations_per_call: 1,
    },
    HashRoleSpec {
        role: ROLE_SPEND_A,
        purpose: HashPurpose::HiddenSeedDerivation,
        calls: 2,
        maximum_frame_bytes: 77,
        blake_compressions_per_call: 1,
        sha3_permutations_per_call: 2,
        shake_permutations_per_call: 0,
    },
    HashRoleSpec {
        role: ROLE_SPEND_B,
        purpose: HashPurpose::HiddenSeedDerivation,
        calls: 2,
        maximum_frame_bytes: 77,
        blake_compressions_per_call: 1,
        sha3_permutations_per_call: 2,
        shake_permutations_per_call: 0,
    },
    HashRoleSpec {
        role: ROLE_POLICY,
        purpose: HashPurpose::PreimageBinding,
        calls: 1,
        maximum_frame_bytes: 385,
        blake_compressions_per_call: 4,
        sha3_permutations_per_call: 6,
        shake_permutations_per_call: 0,
    },
    HashRoleSpec {
        role: ROLE_AUTH_A,
        purpose: HashPurpose::HiddenSeedDerivation,
        calls: 2,
        maximum_frame_bytes: 181,
        blake_compressions_per_call: 2,
        sha3_permutations_per_call: 3,
        shake_permutations_per_call: 0,
    },
    HashRoleSpec {
        role: ROLE_AUTH_B,
        purpose: HashPurpose::HiddenSeedDerivation,
        calls: 2,
        maximum_frame_bytes: 181,
        blake_compressions_per_call: 2,
        sha3_permutations_per_call: 3,
        shake_permutations_per_call: 0,
    },
    HashRoleSpec {
        role: ROLE_INTENT,
        purpose: HashPurpose::CollisionBinding,
        calls: 1,
        maximum_frame_bytes: 720,
        blake_compressions_per_call: 0,
        sha3_permutations_per_call: 0,
        shake_permutations_per_call: 6,
    },
    HashRoleSpec {
        role: ROLE_BALANCE,
        purpose: HashPurpose::CollisionBinding,
        calls: 1,
        maximum_frame_bytes: 100,
        blake_compressions_per_call: 0,
        sha3_permutations_per_call: 0,
        shake_permutations_per_call: 1,
    },
    HashRoleSpec {
        role: ROLE_CIPHERTEXT,
        purpose: HashPurpose::CollisionBinding,
        calls: 2,
        maximum_frame_bytes: 2_182,
        blake_compressions_per_call: 0,
        sha3_permutations_per_call: 0,
        shake_permutations_per_call: 17,
    },
];

pub const fn mixed_hash_registry() -> &'static [HashRoleSpec; 11] {
    &MIXED_HASH_REGISTRY
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileCostReport {
    pub profile: SecretHashProfile,
    pub physical_calls: usize,
    pub blake_compressions: usize,
    pub sha3_permutations: usize,
    pub shake_permutations: usize,
    pub raw_native_nonlinear_words: usize,
    /// BLAKE `rotr` Shift constraints only; excludes other linear constraints.
    pub blake_rotation_linear_words: usize,
    pub fixed_mux_scalar_constraints: Option<usize>,
    pub compiled_native_nonlinear_words: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileTournamentReport {
    pub blake: ProfileCostReport,
    pub split_sha3: ProfileCostReport,
    /// Always `None` until both profiles have same-backend compiled/DCE artifacts.
    pub winner: Option<SecretHashProfile>,
}

pub fn profile_tournament_report() -> ProfileTournamentReport {
    ProfileTournamentReport {
        blake: ProfileCostReport {
            profile: SecretHashProfile::UnkeyedBlake2b448,
            physical_calls: PHYSICAL_HASH_CALLS,
            blake_compressions: BLAKE2B_COMPRESSIONS,
            sha3_permutations: 0,
            shake_permutations: SHAKE256_PERMUTATIONS,
            raw_native_nonlinear_words: MIXED_BLAKE_NATIVE_CORE_WORDS,
            blake_rotation_linear_words: BLAKE_ROTATION_LINEAR_WORDS,
            fixed_mux_scalar_constraints: Some(BLAKE_AUTH_MUX_SCALAR_CONSTRAINTS),
            compiled_native_nonlinear_words: None,
        },
        split_sha3: ProfileCostReport {
            profile: SecretHashProfile::SplitSha3_512Truncated448,
            physical_calls: PHYSICAL_HASH_CALLS,
            blake_compressions: 0,
            sha3_permutations: SPLIT_SHA3_PERMUTATIONS,
            shake_permutations: SHAKE256_PERMUTATIONS,
            raw_native_nonlinear_words: SPLIT_SHA3_NATIVE_CORE_WORDS,
            blake_rotation_linear_words: 0,
            fixed_mux_scalar_constraints: Some(SPLIT_SHA3_AUTH_MUX_SCALAR_CONSTRAINTS),
            compiled_native_nonlinear_words: None,
        },
        winner: None,
    }
}

pub fn validate_mixed_hash_registry() -> Result<(), FullBlake2b448RelationError> {
    let roles = MIXED_HASH_REGISTRY
        .iter()
        .map(|entry| entry.role)
        .collect::<BTreeSet<_>>();
    let calls = MIXED_HASH_REGISTRY
        .iter()
        .map(|entry| entry.calls)
        .sum::<usize>();
    let secret_calls = MIXED_HASH_REGISTRY
        .iter()
        .filter(|entry| entry.shake_permutations_per_call == 0)
        .map(|entry| entry.calls)
        .sum::<usize>();
    let collision_calls = MIXED_HASH_REGISTRY
        .iter()
        .filter(|entry| entry.shake_permutations_per_call != 0)
        .map(|entry| entry.calls)
        .sum::<usize>();
    let blake = MIXED_HASH_REGISTRY
        .iter()
        .map(|entry| entry.calls * entry.blake_compressions_per_call)
        .sum::<usize>();
    let sha3 = MIXED_HASH_REGISTRY
        .iter()
        .map(|entry| entry.calls * entry.sha3_permutations_per_call)
        .sum::<usize>();
    let shake = MIXED_HASH_REGISTRY
        .iter()
        .map(|entry| entry.calls * entry.shake_permutations_per_call)
        .sum::<usize>();
    if roles.len() != MIXED_HASH_REGISTRY.len()
        || calls != PHYSICAL_HASH_CALLS
        || secret_calls != SECRET_HASH_CALLS
        || collision_calls != COLLISION_HASH_CALLS
        || blake != BLAKE2B_COMPRESSIONS
        || sha3 != SPLIT_SHA3_PERMUTATIONS
        || shake != SHAKE256_PERMUTATIONS
        || LANE_A_TAG == LANE_B_TAG
    {
        return Err(FullBlake2b448RelationError::Registry);
    }
    for forbidden in [
        *b"HGF6ST02",
        *b"HGF6HR02",
        *b"HGR6RM02",
        *b"HGV6PB02",
        RETIRED_DIAGNOSTIC_STATEMENT_MAGIC,
    ] {
        if CANDIDATE_STATEMENT_MAGIC == forbidden
            || CANDIDATE_PROFILE_TAG == forbidden
            || roles.contains(&forbidden)
        {
            return Err(FullBlake2b448RelationError::HistoricalIdentityReuse);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceKind {
    Constant,
    CandidateStatement,
    PrivateWitness,
    InternalDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceByte {
    pub kind: SourceKind,
    pub symbol: String,
    pub byte_index: usize,
    pub value: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourcedField {
    kind: SourceKind,
    symbol: String,
    bytes: Vec<u8>,
    byte_indices: Vec<usize>,
}

impl SourcedField {
    fn contiguous(kind: SourceKind, symbol: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            kind,
            symbol: symbol.into(),
            bytes: bytes.to_vec(),
            byte_indices: (0..bytes.len()).collect(),
        }
    }

    fn indexed(
        kind: SourceKind,
        symbol: impl Into<String>,
        bytes: Vec<u8>,
        byte_indices: Vec<usize>,
    ) -> Self {
        debug_assert_eq!(bytes.len(), byte_indices.len());
        Self {
            kind,
            symbol: symbol.into(),
            bytes,
            byte_indices,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourcedFrame {
    pub bytes: Vec<u8>,
    pub sources: Vec<SourceByte>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StablecoinAuthority {
    Disabled,
    Enabled {
        asset_id: u64,
        policy_version: u32,
        issuance_delta: SignedMagnitude,
        policy_hash: Digest384,
        oracle_commitment: Digest384,
        attestation_commitment: Digest384,
    },
}

/// Exact consensus-side rejection order for an enabled live stablecoin view.
/// The manifest and height remain external admission facts; the three compared
/// 48-byte values are public statement bytes, never hidden proof inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveStablecoinPolicyRejection {
    PolicyMissing,
    PolicyHashDerivationDrift,
    PolicyInactive,
    PolicyNotLive,
    AssetMismatch,
    PolicyHashMismatch,
    PolicyVersionMismatch,
    OracleCommitmentMismatch,
    AttestationCommitmentMismatch,
    AttestationDisputed,
    OracleStale,
    IssuanceZero,
    IssuanceOverLimit,
}

/// Exact external protocol-manifest snapshot retained by this scalar diagnostic
/// so `verify()` can repeat the native manifest-member search and every
/// consensus-side policy predicate.
///
/// This view is not itself authenticated against consensus state. That missing
/// equality graph remains an explicit production blocker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinProtocolManifestView {
    pub current_height: u64,
    pub manifest: ProtocolManifest,
}

/// Public, typed input seam between the diagnostic relation and a
/// verifier-selected consensus snapshot.
///
/// `expected_*` is the consensus value selected by the verifier;
/// `provided_*` accompanies the selected manifest entry. The M4 source lowers
/// exact equality between both pairs plus every native lifecycle predicate.
/// The two commitments do *not* by themselves prove that `entry` is a member
/// of the committed vector: the inactive kernel v1 commitment is flat, and a
/// whole-manifest hash graph or authenticated membership scheme has not been
/// compiled. This type makes that missing graph explicit instead of silently
/// trusting an ambient host `ProtocolManifest`.
///
/// The 48-byte commitment here is a conventional kernel-state digest. It is
/// unrelated to the candidate's proof challenge width and carries no
/// strict-PQ or production claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StablecoinConsensusStateSeam {
    pub seam_version: u32,
    pub expected_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1,
    pub provided_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1,
    pub expected_current_height: u64,
    pub provided_current_height: u64,
    pub entry_index: u32,
    pub entry: Option<StablecoinPolicyManifestEntry>,
}

impl StablecoinConsensusStateSeam {
    /// Unique representation when the transaction carries no stablecoin
    /// authority. This keeps unused public state lanes non-malleable.
    pub const fn disabled() -> Self {
        Self {
            seam_version: 0,
            expected_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1::ZERO,
            provided_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1::ZERO,
            expected_current_height: 0,
            provided_current_height: 0,
            entry_index: 0,
            entry: None,
        }
    }

    /// Construct the enabled typed seam. This constructor does not claim that
    /// `entry` is a member of either commitment; callers must obtain it from
    /// the verifier-selected manifest and the eventual relation must compile
    /// that membership/hash graph before production use.
    pub fn enabled(
        expected_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1,
        provided_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1,
        expected_current_height: u64,
        provided_current_height: u64,
        entry_index: u32,
        entry: StablecoinPolicyManifestEntry,
    ) -> Self {
        Self {
            seam_version: STABLECOIN_CONSENSUS_STATE_SEAM_VERSION,
            expected_manifest_state_commitment_v1,
            provided_manifest_state_commitment_v1,
            expected_current_height,
            provided_current_height,
            entry_index,
            entry: Some(entry),
        }
    }
}

impl Default for StablecoinConsensusStateSeam {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StablecoinConsensusStateSeamRejection {
    DisabledStateNotCanonical,
    SeamVersion,
    ManifestStateCommitmentZero,
    ManifestStateCommitmentMismatch,
    CurrentHeightMismatch,
    EntryMissing,
    EntryIndexOutOfRange,
    EntryRejected(LiveStablecoinPolicyRejection),
}

/// Exact 61-byte SCALE encoding of the policy-identity tuple used by
/// `StablecoinPolicyManifestEntry::policy_hash`.
///
/// Fixed-width SCALE integers are little-endian and SCALE `bool` is one byte.
/// Lifecycle heights, live oracle evidence, opaque commitments, and dispute
/// state are deliberately excluded from policy identity.
pub fn live_stablecoin_policy_tuple_scale_bytes(
    entry: &StablecoinPolicyManifestEntry,
) -> [u8; LIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES] {
    let mut encoded = [0u8; LIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES];
    encoded[0..4].copy_from_slice(&entry.asset_id.to_le_bytes());
    encoded[4..8].copy_from_slice(&entry.oracle_feed.to_le_bytes());
    encoded[8..16].copy_from_slice(&entry.attestation_id.to_le_bytes());
    encoded[16..32].copy_from_slice(&entry.min_collateral_ratio_ppm.to_le_bytes());
    encoded[32..48].copy_from_slice(&entry.max_mint_per_epoch.to_le_bytes());
    encoded[48..56].copy_from_slice(&entry.oracle_max_age.to_le_bytes());
    encoded[56..60].copy_from_slice(&entry.policy_version.to_le_bytes());
    encoded[60] = u8::from(entry.active);
    encoded
}

/// Independent RFC 7693 BLAKE2b-384 recomputation over the exact framed
/// 61-byte policy tuple. Validation differentially pins this to the kernel
/// manifest method so either implementation drifting fails closed.
pub fn live_stablecoin_policy_hash(entry: &StablecoinPolicyManifestEntry) -> Digest384 {
    let encoded = live_stablecoin_policy_tuple_scale_bytes(entry);
    blake2b_384_domain_hash(LIVE_STABLECOIN_POLICY_DOMAIN, [encoded.as_slice()])
}

fn validate_stablecoin_manifest_entry(
    authority: StablecoinAuthority,
    current_height: u64,
    entry: &StablecoinPolicyManifestEntry,
) -> Result<(), LiveStablecoinPolicyRejection> {
    let StablecoinAuthority::Enabled {
        asset_id,
        policy_version,
        issuance_delta,
        policy_hash,
        oracle_commitment,
        attestation_commitment,
    } = authority
    else {
        return Ok(());
    };
    let independently_recomputed = live_stablecoin_policy_hash(entry);
    if independently_recomputed != entry.policy_hash() {
        return Err(LiveStablecoinPolicyRejection::PolicyHashDerivationDrift);
    }
    if !entry.active {
        return Err(LiveStablecoinPolicyRejection::PolicyInactive);
    }
    let lifecycle_open = current_height >= entry.enabled_at
        && match entry.retired_at {
            Some(retired_at) => current_height < retired_at,
            None => true,
        };
    if !lifecycle_open {
        return Err(LiveStablecoinPolicyRejection::PolicyNotLive);
    }
    if u64::from(entry.asset_id) != asset_id {
        return Err(LiveStablecoinPolicyRejection::AssetMismatch);
    }
    if independently_recomputed != policy_hash {
        return Err(LiveStablecoinPolicyRejection::PolicyHashMismatch);
    }
    if entry.policy_version != policy_version {
        return Err(LiveStablecoinPolicyRejection::PolicyVersionMismatch);
    }
    if entry.oracle_commitment != oracle_commitment {
        return Err(LiveStablecoinPolicyRejection::OracleCommitmentMismatch);
    }
    if entry.attestation_commitment != attestation_commitment {
        return Err(LiveStablecoinPolicyRejection::AttestationCommitmentMismatch);
    }
    if entry.attestation_disputed {
        return Err(LiveStablecoinPolicyRejection::AttestationDisputed);
    }
    let oracle_fresh = entry.oracle_submitted_at <= current_height
        && current_height.saturating_sub(entry.oracle_submitted_at) <= entry.oracle_max_age;
    if !oracle_fresh {
        return Err(LiveStablecoinPolicyRejection::OracleStale);
    }
    if issuance_delta.magnitude == 0 {
        return Err(LiveStablecoinPolicyRejection::IssuanceZero);
    }
    if u128::from(issuance_delta.magnitude) > entry.max_mint_per_epoch {
        return Err(LiveStablecoinPolicyRejection::IssuanceOverLimit);
    }
    Ok(())
}

/// Mirror native admission's existential search over plausible members of the
/// supplied `ProtocolManifest`: an entry is plausible when either its asset id
/// or kernel-derived policy hash matches the public binding, and authorization
/// succeeds when any plausible member passes every ordered predicate.
///
/// The entire manifest view (not a detached entry) is retained and rechecked.
/// Authentication of this external view against consensus state is deliberately
/// outside the diagnostic relation and remains fail-closed for production.
pub fn validate_stablecoin_protocol_manifest_view(
    authority: StablecoinAuthority,
    manifest_view: Option<&StablecoinProtocolManifestView>,
) -> Result<(), LiveStablecoinPolicyRejection> {
    let StablecoinAuthority::Enabled {
        asset_id,
        policy_hash,
        ..
    } = authority
    else {
        return Ok(());
    };
    let view = manifest_view.ok_or(LiveStablecoinPolicyRejection::PolicyMissing)?;
    let mut first_rejection = None;
    for entry in &view.manifest.stablecoin_policies {
        let plausible = u64::from(entry.asset_id) == asset_id || entry.policy_hash() == policy_hash;
        if !plausible {
            continue;
        }
        match validate_stablecoin_manifest_entry(authority, view.current_height, entry) {
            Ok(()) => return Ok(()),
            Err(rejection) => {
                first_rejection.get_or_insert(rejection);
            }
        }
    }
    Err(first_rejection.unwrap_or(LiveStablecoinPolicyRejection::PolicyMissing))
}

/// Validate exactly the non-hash predicates exposed by the typed
/// consensus-state seam. This mirrors the selected-entry portion of native
/// admission and deliberately does not claim manifest-membership authority.
pub fn validate_stablecoin_consensus_state_seam(
    authority: StablecoinAuthority,
    state: &StablecoinConsensusStateSeam,
) -> Result<(), StablecoinConsensusStateSeamRejection> {
    let StablecoinAuthority::Enabled { .. } = authority else {
        return if state == &StablecoinConsensusStateSeam::disabled() {
            Ok(())
        } else {
            Err(StablecoinConsensusStateSeamRejection::DisabledStateNotCanonical)
        };
    };
    if state.seam_version != STABLECOIN_CONSENSUS_STATE_SEAM_VERSION {
        return Err(StablecoinConsensusStateSeamRejection::SeamVersion);
    }
    if state
        .expected_manifest_state_commitment_v1
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || state
            .provided_manifest_state_commitment_v1
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(StablecoinConsensusStateSeamRejection::ManifestStateCommitmentZero);
    }
    if state.expected_manifest_state_commitment_v1 != state.provided_manifest_state_commitment_v1 {
        return Err(StablecoinConsensusStateSeamRejection::ManifestStateCommitmentMismatch);
    }
    if state.expected_current_height != state.provided_current_height {
        return Err(StablecoinConsensusStateSeamRejection::CurrentHeightMismatch);
    }
    let entry = state
        .entry
        .as_ref()
        .ok_or(StablecoinConsensusStateSeamRejection::EntryMissing)?;
    validate_stablecoin_manifest_entry(authority, state.provided_current_height, entry)
        .map_err(StablecoinConsensusStateSeamRejection::EntryRejected)
}

/// Resolve the first native-valid plausible manifest member into the typed
/// seam. The caller supplies the verifier-expected and manifest-provided
/// commitments separately so equality is explicit. This adapter is source
/// plumbing for the inactive diagnostic candidate; it is not the missing
/// in-circuit whole-manifest commitment/membership graph.
pub fn stablecoin_consensus_state_seam_from_protocol_manifest(
    authority: StablecoinAuthority,
    manifest_view: Option<&StablecoinProtocolManifestView>,
    expected_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1,
    provided_manifest_state_commitment_v1: StablecoinManifestStateCommitmentV1,
) -> Result<StablecoinConsensusStateSeam, StablecoinConsensusStateSeamRejection> {
    let StablecoinAuthority::Enabled {
        asset_id,
        policy_hash,
        ..
    } = authority
    else {
        return Ok(StablecoinConsensusStateSeam::disabled());
    };
    if expected_manifest_state_commitment_v1
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || provided_manifest_state_commitment_v1
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(StablecoinConsensusStateSeamRejection::ManifestStateCommitmentZero);
    }
    if expected_manifest_state_commitment_v1 != provided_manifest_state_commitment_v1 {
        return Err(StablecoinConsensusStateSeamRejection::ManifestStateCommitmentMismatch);
    }
    let view = manifest_view.ok_or(StablecoinConsensusStateSeamRejection::EntryMissing)?;
    let mut first_rejection = None;
    for (entry_index, entry) in view.manifest.stablecoin_policies.iter().enumerate() {
        let plausible = u64::from(entry.asset_id) == asset_id || entry.policy_hash() == policy_hash;
        if !plausible {
            continue;
        }
        match validate_stablecoin_manifest_entry(authority, view.current_height, entry) {
            Ok(()) => {
                let entry_index = u32::try_from(entry_index)
                    .map_err(|_| StablecoinConsensusStateSeamRejection::EntryIndexOutOfRange)?;
                let state = StablecoinConsensusStateSeam::enabled(
                    expected_manifest_state_commitment_v1,
                    provided_manifest_state_commitment_v1,
                    view.current_height,
                    view.current_height,
                    entry_index,
                    entry.clone(),
                );
                validate_stablecoin_consensus_state_seam(authority, &state)?;
                return Ok(state);
            }
            Err(rejection) => {
                first_rejection.get_or_insert(rejection);
            }
        }
    }
    Err(StablecoinConsensusStateSeamRejection::EntryRejected(
        first_rejection.unwrap_or(LiveStablecoinPolicyRejection::PolicyMissing),
    ))
}

impl StablecoinAuthority {
    pub fn try_from_statement(
        statement: &FullBlake2b448Statement,
    ) -> Result<Self, FullBlake2b448RelationError> {
        let stable = statement.stablecoin;
        if !stable.enabled {
            if stable.asset_id != 0
                || stable.policy_version != 0
                || stable.issuance_delta != SignedMagnitude::default()
                || stable.policy_hash != [0; LIVE_STABLECOIN_BINDING_BYTES]
                || stable.oracle_commitment != [0; LIVE_STABLECOIN_BINDING_BYTES]
                || stable.attestation_commitment != [0; LIVE_STABLECOIN_BINDING_BYTES]
            {
                return Err(FullBlake2b448RelationError::Stablecoin(
                    "disabled binding must be uniquely zero",
                ));
            }
            return Ok(Self::Disabled);
        }
        signed_i128(stable.issuance_delta)?;
        if stable.asset_id == NATIVE_ASSET_ID
            || !is_canonical_asset(stable.asset_id)
            || !statement.balance_asset_ids.contains(&stable.asset_id)
        {
            return Err(FullBlake2b448RelationError::Stablecoin(
                "enabled authority must be typed, canonical, non-native, and slotted",
            ));
        }
        Ok(Self::Enabled {
            asset_id: stable.asset_id,
            policy_version: stable.policy_version,
            issuance_delta: stable.issuance_delta,
            policy_hash: stable.policy_hash,
            oracle_commitment: stable.oracle_commitment,
            attestation_commitment: stable.attestation_commitment,
        })
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FullBlake2b448RelationError {
    #[error(transparent)]
    Blake(#[from] Blake2bRelationError),
    #[error(transparent)]
    Shake(#[from] Shake256RelationError),
    #[error("mixed hash registry does not have the exact 83-call schedule")]
    Registry,
    #[error("retained semantic certificate does not match the statement and witness")]
    SemanticCertificate,
    #[error("hash call {0} does not match the exact per-index call specification")]
    CallSpec(usize),
    #[error("candidate relation reuses a rejected historical identity")]
    HistoricalIdentityReuse,
    #[error("candidate statement is not canonical: {0}")]
    Statement(&'static str),
    #[error("candidate activation does not equal verifier-selected activation")]
    Activation,
    #[error("candidate activation aliases the rejected V6 route")]
    HistoricalActivation,
    #[error("frame is not canonical: {0}")]
    Frame(&'static str),
    #[error("hash slot {0} has incorrect geometry")]
    Geometry(usize),
    #[error("hash trace or source/output binding failed at slot {0}")]
    HashBinding(usize),
    #[error("transaction shape is invalid: {0}")]
    Shape(&'static str),
    #[error("inactive {role} slot {index} is nonzero")]
    InactivePayload { index: usize, role: &'static str },
    #[error("public value mismatch: {0}")]
    PublicMismatch(&'static str),
    #[error("composed parser/admission precondition failed: {0}")]
    AdmissionPrecondition(&'static str),
    #[error("value is out of range: {0}")]
    ValueOutOfRange(&'static str),
    #[error("asset slots or selector are invalid")]
    Asset,
    #[error("balance fails for asset {0}")]
    Balance(u64),
    #[error("stablecoin authority is invalid: {0}")]
    Stablecoin(&'static str),
    #[error("live stablecoin policy authorization rejected: {0:?}")]
    LiveStablecoinPolicy(LiveStablecoinPolicyRejection),
    #[error("authorization relation is invalid: {0}")]
    Authorization(&'static str),
    #[error("input {0} Merkle membership fails")]
    Membership(usize),
    #[error("fixed five-arm authorization mux is invalid: {0}")]
    AuthorizationMux(&'static str),
    #[error("Boolean wire {0} is out of range")]
    BooleanWire(usize),
    #[error("Boolean constraint {0} failed")]
    BooleanConstraint(usize),
    #[error("the diagnostic mixed relation is not production-authorized")]
    ProductionAuthorizationUnavailable,
}

pub fn ensure_full_blake2b448_relation_production_authorized(
) -> Result<(), FullBlake2b448RelationError> {
    Err(FullBlake2b448RelationError::ProductionAuthorizationUnavailable)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoolWire(usize);

impl BoolWire {
    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateBoolConstraint {
    Constant {
        output: BoolWire,
        value: bool,
    },
    Boolean {
        wire: BoolWire,
    },
    Not {
        input: BoolWire,
        output: BoolWire,
    },
    Xor {
        left: BoolWire,
        right: BoolWire,
        output: BoolWire,
    },
    FullAdderSum {
        left: BoolWire,
        right: BoolWire,
        carry_in: BoolWire,
        sum: BoolWire,
    },
    FullAdderCarry {
        left: BoolWire,
        right: BoolWire,
        carry_in: BoolWire,
        carry_out: BoolWire,
    },
    OneHot5 {
        selectors: [BoolWire; 5],
    },
    OneHotMux5 {
        selectors: [BoolWire; 5],
        inputs: [BoolWire; 5],
        output: BoolWire,
    },
    Parity5 {
        inputs: [BoolWire; 5],
        output: BoolWire,
    },
    FusedChi {
        a: BoolWire,
        b: BoolWire,
        c: BoolWire,
        output: BoolWire,
    },
}

impl CandidateBoolConstraint {
    fn residual(self, witness: &[u64]) -> Result<u64, FullBlake2b448RelationError> {
        let value = |wire: BoolWire| {
            witness
                .get(wire.index())
                .copied()
                .ok_or(FullBlake2b448RelationError::BooleanWire(wire.index()))
        };
        match self {
            Self::Constant { output, value: bit } => Ok(field_sub(value(output)?, u64::from(bit))),
            Self::Boolean { wire } => {
                let bit = value(wire)?;
                Ok(field_mul(bit, field_sub(bit, 1)))
            }
            Self::Not { input, output } => {
                Ok(field_sub(field_add(value(input)?, value(output)?), 1))
            }
            Self::Xor {
                left,
                right,
                output,
            } => Ok(field_sub(
                value(output)?,
                field_xor(value(left)?, value(right)?),
            )),
            Self::FullAdderSum {
                left,
                right,
                carry_in,
                sum,
            } => {
                let a = value(left)?;
                let b = value(right)?;
                let c = value(carry_in)?;
                let ab = field_mul(a, b);
                let ac = field_mul(a, c);
                let bc = field_mul(b, c);
                let abc = field_mul(ab, c);
                let pair_sum = field_add(field_add(ab, ac), bc);
                let expected = field_add(
                    field_sub(field_add(field_add(a, b), c), field_mul_small(pair_sum, 2)),
                    field_mul_small(abc, 4),
                );
                Ok(field_sub(value(sum)?, expected))
            }
            Self::FullAdderCarry {
                left,
                right,
                carry_in,
                carry_out,
            } => {
                let a = value(left)?;
                let b = value(right)?;
                let c = value(carry_in)?;
                let pair_sum =
                    field_add(field_add(field_mul(a, b), field_mul(a, c)), field_mul(b, c));
                let expected =
                    field_sub(pair_sum, field_mul_small(field_mul(field_mul(a, b), c), 2));
                Ok(field_sub(value(carry_out)?, expected))
            }
            Self::OneHot5 { selectors } => {
                let sum = selectors
                    .into_iter()
                    .try_fold(0, |sum, wire| value(wire).map(|v| field_add(sum, v)))?;
                Ok(field_sub(sum, 1))
            }
            Self::OneHotMux5 {
                selectors,
                inputs,
                output,
            } => {
                let mut selected = 0;
                for (selector, input) in selectors.into_iter().zip(inputs) {
                    selected = field_add(selected, field_mul(value(selector)?, value(input)?));
                }
                Ok(field_sub(value(output)?, selected))
            }
            Self::Parity5 { inputs, output } => {
                let parity = inputs
                    .into_iter()
                    .try_fold(0, |parity, wire| value(wire).map(|v| field_xor(parity, v)))?;
                Ok(field_sub(value(output)?, parity))
            }
            Self::FusedChi { a, b, c, output } => {
                let a = value(a)?;
                let b = value(b)?;
                let c = value(c)?;
                let ac = field_mul(a, c);
                let expected = field_add(
                    field_sub(
                        field_sub(field_add(a, c), field_mul(b, c)),
                        field_mul_small(ac, 2),
                    ),
                    field_mul_small(field_mul(ac, b), 2),
                );
                Ok(field_sub(value(output)?, expected))
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Bit {
    wire: BoolWire,
    known: Option<bool>,
}

type Word = [Bit; 64];

#[derive(Clone)]
struct BoolBuilder {
    witness: Vec<u64>,
    constraints: Vec<CandidateBoolConstraint>,
    zero: Bit,
    one: Bit,
}

impl BoolBuilder {
    fn new() -> Self {
        let placeholder = Bit {
            wire: BoolWire(0),
            known: Some(false),
        };
        let mut builder = Self {
            witness: Vec::new(),
            constraints: Vec::new(),
            zero: placeholder,
            one: Bit {
                wire: BoolWire(0),
                known: Some(true),
            },
        };
        let zero = builder.allocate(false, Some(false));
        builder.constraints.push(CandidateBoolConstraint::Constant {
            output: zero.wire,
            value: false,
        });
        let one = builder.allocate(true, Some(true));
        builder.constraints.push(CandidateBoolConstraint::Constant {
            output: one.wire,
            value: true,
        });
        builder.zero = zero;
        builder.one = one;
        builder
    }

    fn allocate(&mut self, value: bool, known: Option<bool>) -> Bit {
        let bit = Bit {
            wire: BoolWire(self.witness.len()),
            known,
        };
        self.witness.push(u64::from(value));
        bit
    }

    const fn constant(&self, value: bool) -> Bit {
        if value {
            self.one
        } else {
            self.zero
        }
    }

    fn input(&mut self, value: bool) -> Bit {
        let bit = self.allocate(value, None);
        self.constraints
            .push(CandidateBoolConstraint::Boolean { wire: bit.wire });
        bit
    }

    fn value(&self, bit: Bit) -> bool {
        self.witness[bit.wire.index()] == 1
    }

    fn not(&mut self, input: Bit) -> Bit {
        if let Some(value) = input.known {
            return self.constant(!value);
        }
        let output = self.allocate(!self.value(input), None);
        self.constraints.push(CandidateBoolConstraint::Not {
            input: input.wire,
            output: output.wire,
        });
        output
    }

    fn xor(&mut self, left: Bit, right: Bit) -> Bit {
        if left.wire == right.wire {
            return self.zero;
        }
        match (left.known, right.known) {
            (Some(a), Some(b)) => self.constant(a ^ b),
            (Some(false), None) => right,
            (None, Some(false)) => left,
            (Some(true), None) => self.not(right),
            (None, Some(true)) => self.not(left),
            (None, None) => {
                let output = self.allocate(self.value(left) ^ self.value(right), None);
                self.constraints.push(CandidateBoolConstraint::Xor {
                    left: left.wire,
                    right: right.wire,
                    output: output.wire,
                });
                output
            }
        }
    }

    fn full_adder(&mut self, left: Bit, right: Bit, carry_in: Bit) -> (Bit, Bit) {
        if let (Some(a), Some(b), Some(c)) = (left.known, right.known, carry_in.known) {
            let total = u8::from(a) + u8::from(b) + u8::from(c);
            return (self.constant(total & 1 == 1), self.constant(total >= 2));
        }
        let total = u8::from(self.value(left))
            + u8::from(self.value(right))
            + u8::from(self.value(carry_in));
        let sum = self.allocate(total & 1 == 1, None);
        let carry_out = self.allocate(total >= 2, None);
        self.constraints
            .push(CandidateBoolConstraint::FullAdderSum {
                left: left.wire,
                right: right.wire,
                carry_in: carry_in.wire,
                sum: sum.wire,
            });
        self.constraints
            .push(CandidateBoolConstraint::FullAdderCarry {
                left: left.wire,
                right: right.wire,
                carry_in: carry_in.wire,
                carry_out: carry_out.wire,
            });
        (sum, carry_out)
    }

    fn add_word(&mut self, left: Word, right: Word) -> Word {
        let mut carry = self.zero;
        core::array::from_fn(|bit| {
            let (sum, next) = self.full_adder(left[bit], right[bit], carry);
            carry = next;
            sum
        })
    }

    fn constant_word(&self, value: u64) -> Word {
        core::array::from_fn(|bit| self.constant((value >> bit) & 1 == 1))
    }

    fn xor_word(&mut self, left: Word, right: Word) -> Word {
        core::array::from_fn(|bit| self.xor(left[bit], right[bit]))
    }

    fn one_hot(&mut self, selectors: [Bit; 5]) {
        self.constraints.push(CandidateBoolConstraint::OneHot5 {
            selectors: selectors.map(|bit| bit.wire),
        });
    }

    fn mux5(&mut self, selectors: [Bit; 5], inputs: [Bit; 5]) -> Bit {
        let selected = selectors
            .iter()
            .position(|bit| self.value(*bit))
            .map(|index| self.value(inputs[index]))
            .unwrap_or(false);
        let output = self.allocate(selected, None);
        self.constraints.push(CandidateBoolConstraint::OneHotMux5 {
            selectors: selectors.map(|bit| bit.wire),
            inputs: inputs.map(|bit| bit.wire),
            output: output.wire,
        });
        output
    }

    fn parity5(&mut self, inputs: [Bit; 5]) -> Bit {
        if inputs.iter().all(|bit| bit.known.is_some()) {
            let value = inputs
                .iter()
                .fold(false, |parity, bit| parity ^ bit.known.expect("checked"));
            return self.constant(value);
        }
        let value = inputs
            .iter()
            .fold(false, |parity, bit| parity ^ self.value(*bit));
        let output = self.allocate(value, None);
        self.constraints.push(CandidateBoolConstraint::Parity5 {
            inputs: inputs.map(|bit| bit.wire),
            output: output.wire,
        });
        output
    }

    fn fused_chi(&mut self, a: Bit, b: Bit, c: Bit) -> Bit {
        if let (Some(a), Some(b), Some(c)) = (a.known, b.known, c.known) {
            return self.constant(a ^ ((!b) & c));
        }
        let output = self.allocate(self.value(a) ^ ((!self.value(b)) & self.value(c)), None);
        self.constraints.push(CandidateBoolConstraint::FusedChi {
            a: a.wire,
            b: b.wire,
            c: c.wire,
            output: output.wire,
        });
        output
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateSourceBitBinding {
    pub source: SourceByte,
    pub bit_index: usize,
    pub wire: BoolWire,
}

#[derive(Clone)]
pub struct CandidateBooleanTrace {
    pub witness: Vec<u64>,
    pub constraints: Vec<CandidateBoolConstraint>,
    pub source_bindings: Vec<CandidateSourceBitBinding>,
    pub digest_bit_wires: Vec<BoolWire>,
    pub digest: Digest448,
    pub compression_count: usize,
    pub permutation_count: usize,
    pub fixed_mux: bool,
}

impl CandidateBooleanTrace {
    pub fn verify(&self) -> Result<(), FullBlake2b448RelationError> {
        for (index, value) in self.witness.iter().copied().enumerate() {
            if value >= GOLDILOCKS_MODULUS {
                return Err(FullBlake2b448RelationError::BooleanWire(index));
            }
        }
        for (index, constraint) in self.constraints.iter().copied().enumerate() {
            if constraint.residual(&self.witness)? != 0 {
                return Err(FullBlake2b448RelationError::BooleanConstraint(index));
            }
        }
        for binding in &self.source_bindings {
            let expected = u64::from((binding.source.value >> binding.bit_index) & 1);
            if self.witness.get(binding.wire.index()).copied() != Some(expected) {
                return Err(FullBlake2b448RelationError::HashBinding(usize::MAX));
            }
        }
        if self.digest_bit_wires.len() != DIGEST_BYTES * 8 {
            return Err(FullBlake2b448RelationError::HashBinding(usize::MAX));
        }
        let actual = wires_to_digest(&self.witness, &self.digest_bit_wires)?;
        if actual != self.digest {
            return Err(FullBlake2b448RelationError::HashBinding(usize::MAX));
        }
        Ok(())
    }
}

fn wires_to_digest(
    witness: &[u64],
    wires: &[BoolWire],
) -> Result<Digest448, FullBlake2b448RelationError> {
    if wires.len() != DIGEST_BYTES * 8 {
        return Err(FullBlake2b448RelationError::HashBinding(usize::MAX));
    }
    let mut output = [0u8; DIGEST_BYTES];
    for byte in 0..DIGEST_BYTES {
        for bit in 0..8 {
            let wire = wires[byte * 8 + bit];
            let value = witness
                .get(wire.index())
                .copied()
                .ok_or(FullBlake2b448RelationError::BooleanWire(wire.index()))?;
            if value > 1 {
                return Err(FullBlake2b448RelationError::BooleanWire(wire.index()));
            }
            output[byte] |= (value as u8) << bit;
        }
    }
    Ok(output)
}

fn field_add(left: u64, right: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(GOLDILOCKS_MODULUS)) as u64
}

fn field_sub(left: u64, right: u64) -> u64 {
    ((u128::from(left) + u128::from(GOLDILOCKS_MODULUS) - u128::from(right))
        % u128::from(GOLDILOCKS_MODULUS)) as u64
}

fn field_mul(left: u64, right: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(GOLDILOCKS_MODULUS)) as u64
}

fn field_mul_small(value: u64, scalar: u64) -> u64 {
    field_mul(value, scalar)
}

fn field_xor(left: u64, right: u64) -> u64 {
    field_sub(
        field_add(left, right),
        field_mul_small(field_mul(left, right), 2),
    )
}

fn rotate_right(word: Word, amount: usize) -> Word {
    core::array::from_fn(|bit| word[(bit + amount) % 64])
}

fn blake_mix(
    builder: &mut BoolBuilder,
    work: &mut [Word; 16],
    [a, b, c, d]: [usize; 4],
    message_x: Word,
    message_y: Word,
) {
    let a_plus_b = builder.add_word(work[a], work[b]);
    work[a] = builder.add_word(a_plus_b, message_x);
    work[d] = rotate_right(builder.xor_word(work[d], work[a]), 32);
    work[c] = builder.add_word(work[c], work[d]);
    work[b] = rotate_right(builder.xor_word(work[b], work[c]), 24);
    let a_plus_b = builder.add_word(work[a], work[b]);
    work[a] = builder.add_word(a_plus_b, message_y);
    work[d] = rotate_right(builder.xor_word(work[d], work[a]), 16);
    work[c] = builder.add_word(work[c], work[d]);
    work[b] = rotate_right(builder.xor_word(work[b], work[c]), 63);
}

fn blake_compress_selected(
    builder: &mut BoolBuilder,
    state: [Word; 8],
    message: [Word; 16],
    counter: [Bit; 128],
    final_flag: Bit,
) -> [Word; 8] {
    let zero_word = builder.constant_word(0);
    let mut work = [zero_word; 16];
    work[..8].copy_from_slice(&state);
    for (index, iv) in BLAKE2B_IV.iter().copied().enumerate() {
        work[index + 8] = builder.constant_word(iv);
    }
    work[12] = builder.xor_word(work[12], counter[..64].try_into().expect("64 counter bits"));
    work[13] = builder.xor_word(work[13], counter[64..].try_into().expect("64 counter bits"));
    work[14] = builder.xor_word(work[14], [final_flag; 64]);
    for schedule in BLAKE2B_SIGMA {
        blake_mix(
            builder,
            &mut work,
            [0, 4, 8, 12],
            message[schedule[0]],
            message[schedule[1]],
        );
        blake_mix(
            builder,
            &mut work,
            [1, 5, 9, 13],
            message[schedule[2]],
            message[schedule[3]],
        );
        blake_mix(
            builder,
            &mut work,
            [2, 6, 10, 14],
            message[schedule[4]],
            message[schedule[5]],
        );
        blake_mix(
            builder,
            &mut work,
            [3, 7, 11, 15],
            message[schedule[6]],
            message[schedule[7]],
        );
        blake_mix(
            builder,
            &mut work,
            [0, 5, 10, 15],
            message[schedule[8]],
            message[schedule[9]],
        );
        blake_mix(
            builder,
            &mut work,
            [1, 6, 11, 12],
            message[schedule[10]],
            message[schedule[11]],
        );
        blake_mix(
            builder,
            &mut work,
            [2, 7, 8, 13],
            message[schedule[12]],
            message[schedule[13]],
        );
        blake_mix(
            builder,
            &mut work,
            [3, 4, 9, 14],
            message[schedule[14]],
            message[schedule[15]],
        );
    }
    core::array::from_fn(|index| {
        let mixed = builder.xor_word(work[index], work[index + 8]);
        builder.xor_word(state[index], mixed)
    })
}

fn keccak_f1600(
    builder: &mut BoolBuilder,
    mut state: [Bit; KECCAK_STATE_BITS],
) -> [Bit; KECCAK_STATE_BITS] {
    for round_constant in KECCAK_ROUND_CONSTANTS {
        let mut parity = [[builder.zero; KECCAK_LANE_BITS]; 5];
        for x in 0..5 {
            for z in 0..KECCAK_LANE_BITS {
                parity[x][z] =
                    builder.parity5(core::array::from_fn(|y| state[keccak_index(x, y, z)]));
            }
        }
        let mut theta = [builder.zero; KECCAK_STATE_BITS];
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..KECCAK_LANE_BITS {
                    let rotated =
                        parity[(x + 1) % 5][(z + KECCAK_LANE_BITS - 1) % KECCAK_LANE_BITS];
                    let delta = builder.xor(parity[(x + 4) % 5][z], rotated);
                    theta[keccak_index(x, y, z)] = builder.xor(state[keccak_index(x, y, z)], delta);
                }
            }
        }
        let mut rho_pi = [builder.zero; KECCAK_STATE_BITS];
        for x in 0..5 {
            for y in 0..5 {
                let target_x = y;
                let target_y = (2 * x + 3 * y) % 5;
                let rotation = KECCAK_RHO_OFFSETS[x][y];
                for z in 0..KECCAK_LANE_BITS {
                    rho_pi[keccak_index(target_x, target_y, (z + rotation) % KECCAK_LANE_BITS)] =
                        theta[keccak_index(x, y, z)];
                }
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..KECCAK_LANE_BITS {
                    state[keccak_index(x, y, z)] = builder.fused_chi(
                        rho_pi[keccak_index(x, y, z)],
                        rho_pi[keccak_index((x + 1) % 5, y, z)],
                        rho_pi[keccak_index((x + 2) % 5, y, z)],
                    );
                }
            }
        }
        for z in 0..KECCAK_LANE_BITS {
            if (round_constant >> z) & 1 == 1 {
                let index = keccak_index(0, 0, z);
                state[index] = builder.not(state[index]);
            }
        }
    }
    state
}

const fn keccak_index(x: usize, y: usize, z: usize) -> usize {
    (x + 5 * y) * KECCAK_LANE_BITS + z
}

fn allocate_sourced_bytes(
    builder: &mut BoolBuilder,
    frame: &SourcedFrame,
    padded_bytes: usize,
    bindings: &mut Vec<CandidateSourceBitBinding>,
) -> Result<Vec<Bit>, FullBlake2b448RelationError> {
    if frame.bytes.len() != frame.sources.len()
        || frame
            .bytes
            .iter()
            .zip(&frame.sources)
            .any(|(byte, source)| *byte != source.value)
        || frame.bytes.len() > padded_bytes
    {
        return Err(FullBlake2b448RelationError::Frame("typed source coverage"));
    }
    let mut bits = Vec::with_capacity(padded_bytes * 8);
    for byte_index in 0..padded_bytes {
        let value = frame.bytes.get(byte_index).copied().unwrap_or(0);
        for bit_index in 0..8 {
            let value_bit = (value >> bit_index) & 1 == 1;
            let bit = if byte_index < frame.bytes.len() {
                let bit = match frame.sources[byte_index].kind {
                    SourceKind::Constant => builder.constant(value_bit),
                    _ => builder.input(value_bit),
                };
                bindings.push(CandidateSourceBitBinding {
                    source: frame.sources[byte_index].clone(),
                    bit_index,
                    wire: bit.wire,
                });
                bit
            } else {
                builder.constant(false)
            };
            bits.push(bit);
        }
    }
    Ok(bits)
}

fn constant_u128_bits(builder: &BoolBuilder, value: u128) -> [Bit; 128] {
    core::array::from_fn(|bit| builder.constant((value >> bit) & 1 == 1))
}

fn fixed_blake2b_authorization_trace(
    mode_selectors: [bool; 5],
    arms: &[SourcedFrame; 5],
) -> Result<CandidateBooleanTrace, FullBlake2b448RelationError> {
    if arms
        .iter()
        .any(|arm| !(129..=256).contains(&arm.bytes.len()))
    {
        return Err(FullBlake2b448RelationError::AuthorizationMux(
            "every BLAKE arm must use exactly two message blocks",
        ));
    }
    let mut builder = BoolBuilder::new();
    let selectors = mode_selectors.map(|selected| builder.input(selected));
    builder.one_hot(selectors);
    let mut bindings = Vec::new();
    let mut arm_bits = Vec::with_capacity(5);
    for arm in arms {
        arm_bits.push(allocate_sourced_bytes(
            &mut builder,
            arm,
            2 * BLAKE2B_BLOCK_BYTES,
            &mut bindings,
        )?);
    }
    let arm_bits: [Vec<Bit>; 5] = arm_bits
        .try_into()
        .map_err(|_| FullBlake2b448RelationError::AuthorizationMux("five arms"))?;
    let mut selected_blocks = Vec::with_capacity(2 * BLAKE2B_BLOCK_BYTES * 8);
    for bit in 0..2 * BLAKE2B_BLOCK_BYTES * 8 {
        selected_blocks
            .push(builder.mux5(selectors, core::array::from_fn(|arm| arm_bits[arm][bit])));
    }
    let counters: [[u128; 2]; 5] = core::array::from_fn(|arm| [128, arms[arm].bytes.len() as u128]);
    let finals = [[false, true]; 5];
    let mut selected_counters = Vec::with_capacity(2);
    let mut selected_finals = Vec::with_capacity(2);
    for block in 0..2 {
        let arm_counter_bits: [[Bit; 128]; 5] =
            core::array::from_fn(|arm| constant_u128_bits(&builder, counters[arm][block]));
        selected_counters.push(core::array::from_fn(|bit| {
            builder.mux5(
                selectors,
                core::array::from_fn(|arm| arm_counter_bits[arm][bit]),
            )
        }));
        selected_finals.push(builder.mux5(
            selectors,
            core::array::from_fn(|arm| builder.constant(finals[arm][block])),
        ));
    }
    let mut state = core::array::from_fn(|index| builder.constant_word(BLAKE2B_IV[index]));
    state[0] = builder.xor_word(
        state[0],
        builder.constant_word(0x0101_0000u64 ^ DIGEST_BYTES as u64),
    );
    for block in 0..2 {
        let words = core::array::from_fn(|word| {
            selected_blocks[block * BLAKE2B_BLOCK_BYTES * 8 + word * 64
                ..block * BLAKE2B_BLOCK_BYTES * 8 + (word + 1) * 64]
                .try_into()
                .expect("64-bit BLAKE word")
        });
        state = blake_compress_selected(
            &mut builder,
            state,
            words,
            selected_counters[block],
            selected_finals[block],
        );
    }
    let digest_bit_wires = (0..DIGEST_BYTES)
        .flat_map(|byte| {
            let word = byte / 8;
            let byte_in_word = byte % 8;
            (0..8).map(move |bit| state[word][byte_in_word * 8 + bit].wire)
        })
        .collect::<Vec<_>>();
    let selected_mode = mode_selectors.iter().position(|selected| *selected).ok_or(
        FullBlake2b448RelationError::AuthorizationMux("one-hot selector"),
    )?;
    let reference = blake2b_relation::<BLAKE2B_448_OUTPUT_BYTES>(&arms[selected_mode].bytes)?;
    let digest = reference.digest();
    let trace = CandidateBooleanTrace {
        witness: builder.witness,
        constraints: builder.constraints,
        source_bindings: bindings,
        digest_bit_wires,
        digest,
        compression_count: 2,
        permutation_count: 0,
        fixed_mux: true,
    };
    trace.verify()?;
    Ok(trace)
}

fn sha3_padded(message: &[u8]) -> Vec<u8> {
    let blocks = message.len() / KECCAK_RATE_SHA3_512 + 1;
    let mut padded = vec![0u8; blocks * KECCAK_RATE_SHA3_512];
    padded[..message.len()].copy_from_slice(message);
    padded[message.len()] ^= 0x06;
    let last = padded.len() - 1;
    padded[last] ^= 0x80;
    padded
}

fn sha3_reference(message: &[u8]) -> Digest448 {
    let output = Sha3_512::digest(message);
    output[..DIGEST_BYTES]
        .try_into()
        .expect("SHA3-512 has at least 56 bytes")
}

fn sha3_512_trace(
    frame: &SourcedFrame,
) -> Result<CandidateBooleanTrace, FullBlake2b448RelationError> {
    let padded = sha3_padded(&frame.bytes);
    let mut builder = BoolBuilder::new();
    let mut bindings = Vec::new();
    let message_bits =
        allocate_sourced_bytes(&mut builder, frame, frame.bytes.len(), &mut bindings)?;
    let mut state = [builder.zero; KECCAK_STATE_BITS];
    for block in 0..padded.len() / KECCAK_RATE_SHA3_512 {
        for byte in 0..KECCAK_RATE_SHA3_512 {
            let absolute = block * KECCAK_RATE_SHA3_512 + byte;
            for bit in 0..8 {
                let absorbed = if absolute < frame.bytes.len() {
                    message_bits[absolute * 8 + bit]
                } else {
                    builder.constant((padded[absolute] >> bit) & 1 == 1)
                };
                state[byte * 8 + bit] = builder.xor(state[byte * 8 + bit], absorbed);
            }
        }
        state = keccak_f1600(&mut builder, state);
    }
    let digest_bit_wires = state[..DIGEST_BYTES * 8]
        .iter()
        .map(|bit| bit.wire)
        .collect();
    let trace = CandidateBooleanTrace {
        witness: builder.witness,
        constraints: builder.constraints,
        source_bindings: bindings,
        digest_bit_wires,
        digest: sha3_reference(&frame.bytes),
        compression_count: 0,
        permutation_count: padded.len() / KECCAK_RATE_SHA3_512,
        fixed_mux: false,
    };
    trace.verify()?;
    Ok(trace)
}

fn fixed_sha3_authorization_trace(
    mode_selectors: [bool; 5],
    arms: &[SourcedFrame; 5],
) -> Result<CandidateBooleanTrace, FullBlake2b448RelationError> {
    let padded = arms.each_ref().map(|arm| sha3_padded(&arm.bytes));
    if padded
        .iter()
        .any(|bytes| bytes.len() > 3 * KECCAK_RATE_SHA3_512)
    {
        return Err(FullBlake2b448RelationError::AuthorizationMux(
            "SHA3 arm exceeds three permutations",
        ));
    }
    let mut builder = BoolBuilder::new();
    let selectors = mode_selectors.map(|selected| builder.input(selected));
    builder.one_hot(selectors);
    let mut bindings = Vec::new();
    let mut arms_bits = Vec::with_capacity(5);
    for (arm, arm_padded) in arms.iter().zip(padded.iter()) {
        let raw = allocate_sourced_bytes(&mut builder, arm, arm.bytes.len(), &mut bindings)?;
        let mut bits = Vec::with_capacity(3 * KECCAK_RATE_SHA3_512 * 8);
        for byte in 0..3 * KECCAK_RATE_SHA3_512 {
            for bit in 0..8 {
                bits.push(if byte < arm.bytes.len() {
                    raw[byte * 8 + bit]
                } else {
                    builder.constant((arm_padded.get(byte).copied().unwrap_or(0) >> bit) & 1 == 1)
                });
            }
        }
        arms_bits.push(bits);
    }
    let arms_bits: [Vec<Bit>; 5] = arms_bits
        .try_into()
        .map_err(|_| FullBlake2b448RelationError::AuthorizationMux("five arms"))?;
    let selected = (0..3 * KECCAK_RATE_SHA3_512 * 8)
        .map(|bit| builder.mux5(selectors, core::array::from_fn(|arm| arms_bits[arm][bit])))
        .collect::<Vec<_>>();
    let mut state = [builder.zero; KECCAK_STATE_BITS];
    let mut states = Vec::with_capacity(3);
    for block in 0..3 {
        for bit in 0..KECCAK_RATE_SHA3_512 * 8 {
            state[bit] = builder.xor(state[bit], selected[block * KECCAK_RATE_SHA3_512 * 8 + bit]);
        }
        state = keccak_f1600(&mut builder, state);
        states.push(state);
    }
    let terminal = padded
        .each_ref()
        .map(|bytes| bytes.len() / KECCAK_RATE_SHA3_512 - 1);
    let digest_bit_wires = (0..DIGEST_BYTES * 8)
        .map(|bit| {
            builder.mux5(
                selectors,
                core::array::from_fn(|arm| states[terminal[arm]][bit]),
            )
        })
        .map(|bit| bit.wire)
        .collect::<Vec<_>>();
    let selected_mode = mode_selectors.iter().position(|selected| *selected).ok_or(
        FullBlake2b448RelationError::AuthorizationMux("one-hot selector"),
    )?;
    let trace = CandidateBooleanTrace {
        witness: builder.witness,
        constraints: builder.constraints,
        source_bindings: bindings,
        digest_bit_wires,
        digest: sha3_reference(&arms[selected_mode].bytes),
        compression_count: 0,
        permutation_count: 3,
        fixed_mux: true,
    };
    trace.verify()?;
    Ok(trace)
}

pub fn candidate_statement_bytes(
    statement: &FullBlake2b448Statement,
    expected_activation: V6ActivationBinding,
) -> Result<[u8; CANDIDATE_STATEMENT_BYTES], FullBlake2b448RelationError> {
    if statement.activation != expected_activation {
        return Err(FullBlake2b448RelationError::Activation);
    }
    if statement.activation.has_v6_route() {
        return Err(FullBlake2b448RelationError::HistoricalActivation);
    }
    if statement.activation.circuit_version == 0
        || statement.activation.crypto_suite == 0
        || statement.activation.family_id == 0
        || statement.activation.action_id == 0
        || statement.activation.backend_id == 0
        || statement.activation.proof_profile == 0
        || statement.activation.domain_set == 0
        || statement.activation.chain_id == [0; DIGEST_BYTES]
        || statement.activation.genesis_id == [0; DIGEST_BYTES]
        || statement.activation.rules_hash == [0; DIGEST_BYTES]
    {
        return Err(FullBlake2b448RelationError::Statement(
            "activation must be explicit and nonzero",
        ));
    }
    signed_i128(statement.value_balance)?;
    signed_i128(statement.stablecoin.issuance_delta)?;
    let mut bytes = Vec::with_capacity(CANDIDATE_STATEMENT_BYTES);
    bytes.extend_from_slice(&CANDIDATE_STATEMENT_MAGIC);
    bytes.extend_from_slice(&CANDIDATE_STATEMENT_GRAMMAR.to_be_bytes());
    bytes.extend(statement.input_flags.map(u8::from));
    bytes.extend(statement.output_flags.map(u8::from));
    bytes.extend_from_slice(&statement.anchor);
    for value in statement.nullifiers {
        bytes.extend_from_slice(&value);
    }
    for value in statement.commitments {
        bytes.extend_from_slice(&value);
    }
    for value in statement.ciphertext_hashes {
        bytes.extend_from_slice(&value);
    }
    for value in statement.ciphertext_sizes {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    for value in statement.balance_asset_ids {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&statement.fee.to_be_bytes());
    push_signed(&mut bytes, statement.value_balance);
    bytes.push(u8::from(statement.stablecoin.enabled));
    bytes.extend_from_slice(&statement.stablecoin.asset_id.to_be_bytes());
    bytes.extend_from_slice(&statement.stablecoin.policy_version.to_be_bytes());
    push_signed(&mut bytes, statement.stablecoin.issuance_delta);
    bytes.extend_from_slice(&statement.stablecoin.policy_hash);
    bytes.extend_from_slice(&statement.stablecoin.oracle_commitment);
    bytes.extend_from_slice(&statement.stablecoin.attestation_commitment);
    bytes.extend_from_slice(&statement.balance_tag);
    bytes.extend_from_slice(&statement.activation.circuit_version.to_be_bytes());
    bytes.extend_from_slice(&statement.activation.crypto_suite.to_be_bytes());
    bytes.extend_from_slice(&statement.activation.family_id.to_be_bytes());
    bytes.extend_from_slice(&statement.activation.action_id.to_be_bytes());
    bytes.extend_from_slice(&statement.activation.network_id.to_be_bytes());
    bytes.push(statement.activation.backend_id);
    bytes.push(statement.activation.proof_profile);
    bytes.extend_from_slice(&statement.activation.domain_set.to_be_bytes());
    bytes.extend_from_slice(&statement.activation.chain_id);
    bytes.extend_from_slice(&statement.activation.genesis_id);
    bytes.extend_from_slice(&statement.activation.rules_hash);
    bytes
        .try_into()
        .map_err(|_| FullBlake2b448RelationError::Statement("exact 869-byte width"))
}

pub fn candidate_statement_limbs(
    statement_bytes: &[u8; CANDIDATE_STATEMENT_BYTES],
) -> [u64; CANDIDATE_STATEMENT_LIMBS] {
    core::array::from_fn(|index| {
        let offset = index * CANDIDATE_STATEMENT_LIMB_BYTES;
        let take = (CANDIDATE_STATEMENT_BYTES - offset).min(CANDIDATE_STATEMENT_LIMB_BYTES);
        let mut encoded = [0u8; 8];
        encoded[..take].copy_from_slice(&statement_bytes[offset..offset + take]);
        u64::from_le_bytes(encoded)
    })
}

fn push_signed(bytes: &mut Vec<u8>, value: SignedMagnitude) {
    bytes.push(u8::from(value.negative));
    bytes.extend_from_slice(&value.magnitude.to_be_bytes());
}

/// Decode only the fresh diagnostic candidate grammar.
///
/// In particular this never delegates to the rejected HGF6 decoder.  Every
/// historical magic is rejected before any field is interpreted, and a final
/// byte-for-byte re-encoding check makes this codec canonical.
pub fn decode_candidate_statement_bytes(
    bytes: &[u8],
    expected_activation: V6ActivationBinding,
) -> Result<FullBlake2b448Statement, FullBlake2b448RelationError> {
    if bytes.len() != CANDIDATE_STATEMENT_BYTES {
        return Err(FullBlake2b448RelationError::Statement(
            "exact 869-byte width",
        ));
    }
    let magic: [u8; 8] = bytes[..8].try_into().expect("length checked");
    if [
        *b"HGF6ST02",
        *b"HGF6HR02",
        *b"HGR6RM02",
        *b"HGV6PB02",
        RETIRED_DIAGNOSTIC_STATEMENT_MAGIC,
    ]
    .contains(&magic)
    {
        return Err(FullBlake2b448RelationError::HistoricalIdentityReuse);
    }
    if magic != CANDIDATE_STATEMENT_MAGIC {
        return Err(FullBlake2b448RelationError::Statement(
            "candidate statement magic",
        ));
    }
    let mut cursor = CandidateStatementCursor { bytes, offset: 8 };
    if cursor.u16() != CANDIDATE_STATEMENT_GRAMMAR {
        return Err(FullBlake2b448RelationError::Statement(
            "candidate statement grammar",
        ));
    }
    let input_flags = [cursor.boolean("input flag")?, cursor.boolean("input flag")?];
    let output_flags = [
        cursor.boolean("output flag")?,
        cursor.boolean("output flag")?,
    ];
    let statement = FullBlake2b448Statement {
        input_flags,
        output_flags,
        anchor: cursor.array(),
        nullifiers: core::array::from_fn(|_| cursor.array()),
        commitments: core::array::from_fn(|_| cursor.array()),
        ciphertext_hashes: core::array::from_fn(|_| cursor.array()),
        ciphertext_sizes: core::array::from_fn(|_| cursor.u32()),
        balance_asset_ids: core::array::from_fn(|_| cursor.u64()),
        fee: cursor.u64(),
        value_balance: cursor.signed("value balance")?,
        stablecoin: StablecoinStatementBinding384 {
            enabled: cursor.boolean("stablecoin enabled")?,
            asset_id: cursor.u64(),
            policy_version: cursor.u32(),
            issuance_delta: cursor.signed("stablecoin issuance")?,
            policy_hash: cursor.array(),
            oracle_commitment: cursor.array(),
            attestation_commitment: cursor.array(),
        },
        balance_tag: cursor.array(),
        activation: V6ActivationBinding {
            circuit_version: cursor.u16(),
            crypto_suite: cursor.u16(),
            family_id: cursor.u16(),
            action_id: cursor.u16(),
            network_id: cursor.u32(),
            backend_id: cursor.byte(),
            proof_profile: cursor.byte(),
            domain_set: cursor.u16(),
            chain_id: cursor.array(),
            genesis_id: cursor.array(),
            rules_hash: cursor.array(),
        },
    };
    debug_assert_eq!(cursor.offset, CANDIDATE_STATEMENT_BYTES);
    let canonical = candidate_statement_bytes(&statement, expected_activation)?;
    if canonical.as_slice() != bytes {
        return Err(FullBlake2b448RelationError::Statement(
            "non-canonical candidate statement",
        ));
    }
    Ok(statement)
}

struct CandidateStatementCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl CandidateStatementCursor<'_> {
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let output = self.bytes[self.offset..self.offset + N]
            .try_into()
            .expect("candidate statement width checked");
        self.offset += N;
        output
    }

    fn byte(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn boolean(&mut self, field: &'static str) -> Result<bool, FullBlake2b448RelationError> {
        match self.byte() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(FullBlake2b448RelationError::Statement(field)),
        }
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }

    fn signed(
        &mut self,
        field: &'static str,
    ) -> Result<SignedMagnitude, FullBlake2b448RelationError> {
        let value = SignedMagnitude {
            negative: self.boolean(field)?,
            magnitude: self.u64(),
        };
        signed_i128(value)?;
        Ok(value)
    }
}

fn constant_sources(symbol: &str, bytes: &[u8]) -> Vec<SourceByte> {
    bytes
        .iter()
        .copied()
        .enumerate()
        .map(|(byte_index, value)| SourceByte {
            kind: SourceKind::Constant,
            symbol: symbol.to_owned(),
            byte_index,
            value,
        })
        .collect()
}

fn encode_frame(
    role: [u8; 8],
    fields: Vec<SourcedField>,
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    if fields.len() > u8::MAX as usize
        || fields
            .iter()
            .any(|field| field.bytes.len() > u16::MAX as usize)
    {
        return Err(FullBlake2b448RelationError::Frame("field count or length"));
    }
    let mut bytes = Vec::new();
    let mut sources = Vec::new();
    bytes.extend_from_slice(&CANDIDATE_PROFILE_TAG);
    sources.extend(constant_sources(
        "candidate.profile",
        &CANDIDATE_PROFILE_TAG,
    ));
    bytes.extend_from_slice(&role);
    sources.extend(constant_sources(&format!("candidate.role.{role:?}"), &role));
    bytes.push(fields.len() as u8);
    sources.push(SourceByte {
        kind: SourceKind::Constant,
        symbol: format!("candidate.role.{role:?}.field_count"),
        byte_index: 0,
        value: fields.len() as u8,
    });
    for (field_index, field) in fields.into_iter().enumerate() {
        let length = (field.bytes.len() as u16).to_be_bytes();
        bytes.extend_from_slice(&length);
        sources.extend(constant_sources(
            &format!("candidate.role.{role:?}.field[{field_index}].length"),
            &length,
        ));
        for ((value, byte_index), _) in field
            .bytes
            .iter()
            .copied()
            .zip(field.byte_indices.iter().copied())
            .zip(0..)
        {
            bytes.push(value);
            sources.push(SourceByte {
                kind: field.kind,
                symbol: field.symbol.clone(),
                byte_index,
                value,
            });
        }
    }
    if bytes.len() != sources.len()
        || bytes
            .iter()
            .zip(&sources)
            .any(|(byte, source)| *byte != source.value)
    {
        return Err(FullBlake2b448RelationError::Frame("source map"));
    }
    Ok(SourcedFrame { bytes, sources })
}

fn note_kind_tag(kind: NoteKind) -> u8 {
    match kind {
        NoteKind::Ordinary => 0,
        NoteKind::Accumulator => 1,
        NoteKind::ValueLock => 2,
    }
}

fn note_frame(
    symbol: &str,
    note: &NoteOpening,
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    encode_frame(
        ROLE_NOTE,
        vec![
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.kind"),
                &[note_kind_tag(note.kind)],
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.value_u64be"),
                &note.value.to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.asset_u64be"),
                &note.asset_id.to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.pk_recipient"),
                &note.pk_recipient,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.rho"),
                &note.rho,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.randomness"),
                &note.randomness,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.pk_auth"),
                &note.pk_auth,
            ),
        ],
    )
}

fn spend_frame(
    index: usize,
    lane: usize,
    spend_key: &[u8; SPEND_KEY_BYTES],
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let (role, lane_tag) = if lane == 0 {
        (ROLE_SPEND_A, LANE_A_TAG)
    } else {
        (ROLE_SPEND_B, LANE_B_TAG)
    };
    encode_frame(
        role,
        vec![
            SourcedField::contiguous(
                SourceKind::Constant,
                format!("spend.lane[{lane}]"),
                &lane_tag,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("input[{index}].spend_key"),
                spend_key,
            ),
        ],
    )
}

fn nullifier_frame(
    index: usize,
    key: &Digest448,
    position: u64,
    rho: &[u8; 48],
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    encode_frame(
        ROLE_NULLIFIER,
        vec![
            SourcedField::contiguous(
                SourceKind::InternalDigest,
                format!("resolved_nullifier_key[{index}]"),
                key,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("input[{index}].position_u64be"),
                &position.to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("input[{index}].note.rho"),
                rho,
            ),
        ],
    )
}

fn merkle_frame(
    input: usize,
    level: usize,
    current: &Digest448,
    sibling: &Digest448,
    current_is_left: bool,
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let current = SourcedField::contiguous(
        SourceKind::InternalDigest,
        if level == 0 {
            format!("digest.note.input[{input}]")
        } else {
            format!("digest.merkle.input[{input}].level[{}]", level - 1)
        },
        current,
    );
    let sibling = SourcedField::contiguous(
        SourceKind::PrivateWitness,
        format!("input[{input}].siblings[{level}]"),
        sibling,
    );
    let fields = if current_is_left {
        vec![current, sibling]
    } else {
        vec![sibling, current]
    };
    encode_frame(ROLE_MERKLE, fields)
}

fn policy_frame(
    opening: &AccumulatorOpening,
    signer_tags: &[Digest448; MAX_SIGNERS],
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let mut fields = vec![
        SourcedField::contiguous(
            SourceKind::PrivateWitness,
            "authorization.selected_policy.threshold_u64be",
            &opening.threshold.to_be_bytes(),
        ),
        SourcedField::contiguous(
            SourceKind::PrivateWitness,
            "authorization.selected_policy.signer_count_u64be",
            &opening.signer_count.to_be_bytes(),
        ),
    ];
    fields.extend(signer_tags.iter().enumerate().map(|(index, tag)| {
        SourcedField::contiguous(
            SourceKind::PrivateWitness,
            format!("authorization.signer_tags[{index}]"),
            tag,
        )
    }));
    encode_frame(ROLE_POLICY, fields)
}

fn accumulator_frame(
    role: [u8; 8],
    lane: usize,
    symbol: &str,
    opening: &AccumulatorOpening,
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let approved = opening.approved_slots.map(u8::from);
    let lane_tag = if lane == 0 { LANE_A_TAG } else { LANE_B_TAG };
    encode_frame(
        role,
        vec![
            SourcedField::contiguous(
                SourceKind::Constant,
                format!("authorization.lane[{lane}]"),
                &lane_tag,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.policy_root"),
                &opening.policy_root,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.intent_digest"),
                &opening.intent_digest,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.threshold_u64be"),
                &opening.threshold.to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.signer_count_u64be"),
                &opening.signer_count.to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.approval_count_u64be"),
                &opening.approval_count.to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("{symbol}.approved_slots"),
                &approved,
            ),
        ],
    )
}

fn value_lock_frame(
    role: [u8; 8],
    lane: usize,
    policy_root: &Digest448,
    intent: &Digest448,
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let lane_tag = if lane == 0 { LANE_A_TAG } else { LANE_B_TAG };
    encode_frame(
        role,
        vec![
            SourcedField::contiguous(
                SourceKind::Constant,
                format!("authorization.lane[{lane}]"),
                &lane_tag,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                "authorization.current.policy_root",
                policy_root,
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                "authorization.current.intent_digest",
                intent,
            ),
        ],
    )
}

fn dummy_authorization_frame(
    role: [u8; 8],
    lane: usize,
    slot: usize,
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let mut payload = [0u8; 117];
    payload[0] = slot as u8;
    payload[1] = lane as u8;
    encode_frame(
        role,
        vec![SourcedField::contiguous(
            SourceKind::Constant,
            format!("authorization.dummy[{slot}].lane[{lane}]"),
            &payload,
        )],
    )
}

fn authorization_arms(
    witness: &FullShake448Witness,
    lane: usize,
    slot: usize,
) -> Result<[SourcedFrame; 5], FullBlake2b448RelationError> {
    let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
    if slot == 0 {
        Ok([
            dummy_authorization_frame(role, lane, slot)?,
            accumulator_frame(role, lane, "authorization.next", &witness.auth.next)?,
            accumulator_frame(role, lane, "authorization.current", &witness.auth.current)?,
            value_lock_frame(
                role,
                lane,
                &witness.auth.current.policy_root,
                &witness.auth.current.intent_digest,
            )?,
            accumulator_frame(role, lane, "authorization.current", &witness.auth.current)?,
        ])
    } else {
        Ok([
            dummy_authorization_frame(role, lane, slot)?,
            dummy_authorization_frame(role, lane, slot)?,
            accumulator_frame(role, lane, "authorization.next", &witness.auth.next)?,
            dummy_authorization_frame(role, lane, slot)?,
            value_lock_frame(
                role,
                lane,
                &witness.auth.current.policy_root,
                &witness.auth.current.intent_digest,
            )?,
        ])
    }
}

fn intent_frame(
    statement_bytes: &[u8; CANDIDATE_STATEMENT_BYTES],
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let mut payload = Vec::with_capacity(701);
    payload.extend_from_slice(&statement_bytes[..OFFSET_ANCHOR]);
    payload.extend_from_slice(&statement_bytes[OFFSET_COMMITMENTS..]);
    let mut indices = (0..OFFSET_ANCHOR).collect::<Vec<_>>();
    indices.extend(OFFSET_COMMITMENTS..CANDIDATE_STATEMENT_BYTES);
    encode_frame(
        ROLE_INTENT,
        vec![SourcedField::indexed(
            SourceKind::CandidateStatement,
            "candidate.statement.bytes",
            payload,
            indices,
        )],
    )
}

fn balance_frame(
    statement: &FullBlake2b448Statement,
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    let mut assets = [0u8; BALANCE_SLOTS * 8];
    for (index, asset) in statement.balance_asset_ids.iter().enumerate() {
        assets[index * 8..index * 8 + 8].copy_from_slice(&asset.to_be_bytes());
    }
    encode_frame(
        ROLE_BALANCE,
        vec![
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                statement.fee.to_be_bytes().to_vec(),
                (OFFSET_FEE..OFFSET_VALUE_BALANCE_SIGN).collect(),
            ),
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                vec![u8::from(statement.value_balance.negative)],
                vec![OFFSET_VALUE_BALANCE_SIGN],
            ),
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                statement.value_balance.magnitude.to_be_bytes().to_vec(),
                (OFFSET_VALUE_BALANCE_MAGNITUDE..OFFSET_STABLE_ENABLED).collect(),
            ),
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                assets.to_vec(),
                (OFFSET_ASSETS..OFFSET_FEE).collect(),
            ),
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                vec![u8::from(statement.stablecoin.enabled)],
                vec![OFFSET_STABLE_ENABLED],
            ),
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                statement.stablecoin.asset_id.to_be_bytes().to_vec(),
                (OFFSET_STABLE_ASSET..OFFSET_STABLE_VERSION).collect(),
            ),
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                vec![u8::from(statement.stablecoin.issuance_delta.negative)],
                vec![OFFSET_STABLE_ISSUANCE_SIGN],
            ),
            SourcedField::indexed(
                SourceKind::CandidateStatement,
                "candidate.statement.bytes",
                statement
                    .stablecoin
                    .issuance_delta
                    .magnitude
                    .to_be_bytes()
                    .to_vec(),
                (OFFSET_STABLE_ISSUANCE_MAGNITUDE..OFFSET_STABLE_POLICY).collect(),
            ),
        ],
    )
}

fn ciphertext_frame(
    statement: &FullBlake2b448Statement,
    index: usize,
    ciphertext: &[u8; V6_CANONICAL_CIPHERTEXT_BYTES],
) -> Result<SourcedFrame, FullBlake2b448RelationError> {
    encode_frame(
        ROLE_CIPHERTEXT,
        vec![
            SourcedField::contiguous(
                SourceKind::Constant,
                "ciphertext.profile",
                &[statement.activation.proof_profile],
            ),
            SourcedField::contiguous(
                SourceKind::Constant,
                "ciphertext.domain_set_u16be",
                &statement.activation.domain_set.to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::Constant,
                format!("ciphertext.output[{index}].slot"),
                &[index as u8],
            ),
            SourcedField::contiguous(
                SourceKind::Constant,
                "ciphertext.fixed_length_u32be",
                &(V6_CANONICAL_CIPHERTEXT_BYTES as u32).to_be_bytes(),
            ),
            SourcedField::contiguous(
                SourceKind::PrivateWitness,
                format!("output[{index}].canonical_ciphertext"),
                ciphertext,
            ),
        ],
    )
}

pub enum ExecutableHashTrace {
    Blake2b(Blake2bConstraintTrace<BLAKE2B_448_OUTPUT_BYTES>),
    CandidateBoolean(CandidateBooleanTrace),
    Shake256(Shake256ConstraintTrace),
}

impl ExecutableHashTrace {
    fn digest(&self) -> Digest448 {
        match self {
            Self::Blake2b(trace) => trace.digest(),
            Self::CandidateBoolean(trace) => trace.digest,
            Self::Shake256(trace) => trace
                .digest()
                .try_into()
                .expect("fixed 56-byte SHAKE output"),
        }
    }

    fn verify(&self, frame: &SourcedFrame) -> Result<(), FullBlake2b448RelationError> {
        if frame.bytes.len() != frame.sources.len()
            || frame
                .bytes
                .iter()
                .zip(&frame.sources)
                .any(|(byte, source)| *byte != source.value)
        {
            return Err(FullBlake2b448RelationError::Frame("trace source coverage"));
        }
        match self {
            Self::Blake2b(trace) => {
                trace.verify_constraints()?;
                trace.verify_input_bindings(&[], &frame.bytes)?;
            }
            Self::CandidateBoolean(trace) => trace.verify()?,
            Self::Shake256(trace) => {
                trace.verify_constraints()?;
                if trace.message_len() != frame.bytes.len()
                    || trace.message_bit_wires().len() != frame.bytes.len() * 8
                    || trace
                        .message_bit_wires()
                        .iter()
                        .enumerate()
                        .any(|(index, wire)| {
                            trace.witness_values()[wire.index()]
                                != u64::from((frame.bytes[index / 8] >> (index % 8)) & 1)
                        })
                {
                    return Err(FullBlake2b448RelationError::HashBinding(usize::MAX));
                }
            }
        }
        Ok(())
    }

    fn scalar_constraints(&self) -> usize {
        match self {
            Self::Blake2b(trace) => trace.constraints().len(),
            Self::CandidateBoolean(trace) => trace.constraints.len(),
            Self::Shake256(trace) => trace.constraints().len(),
        }
    }

    fn cores(&self) -> (usize, usize) {
        match self {
            Self::Blake2b(trace) => (trace.blocks().len(), 0),
            Self::CandidateBoolean(trace) => (trace.compression_count, trace.permutation_count),
            Self::Shake256(trace) => (0, trace.permutations().len()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputBinding {
    Internal,
    PublicWhenInputActive(usize),
    PublicWhenOutputActive(usize),
    PublicAlways,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSpec {
    pub index: usize,
    pub name: String,
    pub role: [u8; 8],
    pub algorithm: CandidateHashAlgorithm,
    pub output_symbol: String,
    pub binding: OutputBinding,
    pub expected_public_digest: Option<Digest448>,
    pub exact_frame_bytes: usize,
    pub blake_compressions: usize,
    pub keccak_permutations: usize,
    pub fixed_authorization_mux: bool,
}

fn secret_algorithm(profile: SecretHashProfile) -> CandidateHashAlgorithm {
    match profile {
        SecretHashProfile::UnkeyedBlake2b448 => CandidateHashAlgorithm::Blake2b448,
        SecretHashProfile::SplitSha3_512Truncated448 => {
            CandidateHashAlgorithm::Sha3_512Truncated448
        }
    }
}

fn call_spec_from_role(
    profile: SecretHashProfile,
    index: usize,
    name: String,
    role: [u8; 8],
    output_symbol: String,
    binding: OutputBinding,
    expected_public_digest: Option<Digest448>,
    exact_frame_bytes: usize,
    fixed_authorization_mux: bool,
) -> Result<CallSpec, FullBlake2b448RelationError> {
    let role_spec = role_spec(role)?;
    let collision = role_spec.shake_permutations_per_call != 0;
    let algorithm = if collision {
        CandidateHashAlgorithm::Shake256_448
    } else {
        secret_algorithm(profile)
    };
    let blake_compressions = if !collision && profile == SecretHashProfile::UnkeyedBlake2b448 {
        role_spec.blake_compressions_per_call
    } else {
        0
    };
    let keccak_permutations = if collision {
        role_spec.shake_permutations_per_call
    } else if profile == SecretHashProfile::SplitSha3_512Truncated448 {
        role_spec.sha3_permutations_per_call
    } else {
        0
    };
    Ok(CallSpec {
        index,
        name,
        role,
        algorithm,
        output_symbol,
        binding,
        expected_public_digest,
        exact_frame_bytes,
        blake_compressions,
        keccak_permutations,
        fixed_authorization_mux,
    })
}

pub fn exact_call_spec(
    profile: SecretHashProfile,
    index: usize,
    statement: &FullBlake2b448Statement,
    witness: &FullShake448Witness,
) -> Result<CallSpec, FullBlake2b448RelationError> {
    match index {
        NOTE_CALL_START..=3 => {
            if index < MAX_INPUTS {
                call_spec_from_role(
                    profile,
                    index,
                    format!("note.input[{index}]"),
                    ROLE_NOTE,
                    format!("digest.note.input[{index}]"),
                    OutputBinding::Internal,
                    None,
                    232,
                    false,
                )
            } else {
                let output = index - MAX_INPUTS;
                call_spec_from_role(
                    profile,
                    index,
                    format!("note.output[{output}]"),
                    ROLE_NOTE,
                    format!("digest.note.output[{output}]"),
                    OutputBinding::PublicWhenOutputActive(output),
                    witness.outputs[output]
                        .active
                        .then_some(statement.commitments[output]),
                    232,
                    false,
                )
            }
        }
        NULLIFIER_CALL_START..=5 => {
            let input = index - NULLIFIER_CALL_START;
            call_spec_from_role(
                profile,
                index,
                format!("nullifier.input[{input}]"),
                ROLE_NULLIFIER,
                format!("digest.nullifier[{input}]"),
                OutputBinding::PublicWhenInputActive(input),
                witness.inputs[input]
                    .active
                    .then_some(statement.nullifiers[input]),
                135,
                false,
            )
        }
        MERKLE_CALL_START..=69 => {
            let relative = index - MERKLE_CALL_START;
            let input = relative / MERKLE_DEPTH;
            let level = relative % MERKLE_DEPTH;
            call_spec_from_role(
                profile,
                index,
                format!("merkle.input[{input}].level[{level}]"),
                ROLE_MERKLE,
                format!("digest.merkle.input[{input}].level[{level}]"),
                OutputBinding::Internal,
                None,
                133,
                false,
            )
        }
        SPEND_A_CALL_START..=71 => {
            let input = index - SPEND_A_CALL_START;
            call_spec_from_role(
                profile,
                index,
                format!("spend.input[{input}].lane_a"),
                ROLE_SPEND_A,
                format!("digest.spend.input[{input}].lane_a"),
                OutputBinding::Internal,
                None,
                77,
                false,
            )
        }
        SPEND_B_CALL_START..=73 => {
            let input = index - SPEND_B_CALL_START;
            call_spec_from_role(
                profile,
                index,
                format!("spend.input[{input}].lane_b"),
                ROLE_SPEND_B,
                format!("digest.spend.input[{input}].lane_b"),
                OutputBinding::Internal,
                None,
                77,
                false,
            )
        }
        // Call 74 remains the private accumulator-authorization policy hash;
        // the public stablecoin manifest fields do not enter this frame.
        POLICY_CALL => call_spec_from_role(
            profile,
            index,
            "authorization.policy".to_owned(),
            ROLE_POLICY,
            "digest.authorization.policy".to_owned(),
            OutputBinding::Internal,
            None,
            385,
            false,
        ),
        AUTH_A_CALL_START..=76 | AUTH_B_CALL_START..=78 => {
            let (lane, slot, role) = if index < AUTH_B_CALL_START {
                (0, index - AUTH_A_CALL_START, ROLE_AUTH_A)
            } else {
                (1, index - AUTH_B_CALL_START, ROLE_AUTH_B)
            };
            let selected = witness
                .auth
                .mode
                .selectors()
                .iter()
                .position(|selected| *selected)
                .ok_or(FullBlake2b448RelationError::AuthorizationMux("not one hot"))?;
            let arm_lengths = if slot == 0 {
                [136, 181, 181, 143, 181]
            } else {
                [136, 136, 181, 136, 143]
            };
            call_spec_from_role(
                profile,
                index,
                format!("authorization.mux[{slot}].lane[{lane}]"),
                role,
                format!("digest.authorization.mux[{slot}].lane[{lane}]"),
                OutputBinding::Internal,
                None,
                arm_lengths[selected],
                true,
            )
        }
        INTENT_CALL => call_spec_from_role(
            profile,
            index,
            "intent.statement".to_owned(),
            ROLE_INTENT,
            "digest.intent".to_owned(),
            OutputBinding::Internal,
            None,
            720,
            false,
        ),
        BALANCE_CALL => call_spec_from_role(
            profile,
            index,
            "balance.tag".to_owned(),
            ROLE_BALANCE,
            "digest.balance_tag".to_owned(),
            OutputBinding::PublicAlways,
            Some(statement.balance_tag),
            100,
            false,
        ),
        CIPHERTEXT_CALL_START..=82 => {
            let output = index - CIPHERTEXT_CALL_START;
            call_spec_from_role(
                profile,
                index,
                format!("ciphertext.output[{output}]"),
                ROLE_CIPHERTEXT,
                format!("digest.ciphertext[{output}]"),
                OutputBinding::PublicWhenOutputActive(output),
                witness.outputs[output]
                    .active
                    .then_some(statement.ciphertext_hashes[output]),
                2_182,
                false,
            )
        }
        _ => Err(FullBlake2b448RelationError::CallSpec(index)),
    }
}

pub struct ExecutableHashCall {
    pub index: usize,
    pub name: String,
    pub role: [u8; 8],
    pub algorithm: CandidateHashAlgorithm,
    pub frame: SourcedFrame,
    pub output_symbol: String,
    pub digest: Digest448,
    pub binding: OutputBinding,
    pub expected_public_digest: Option<Digest448>,
    pub trace: ExecutableHashTrace,
    /// All five arms are retained for a fixed authorization call.
    pub authorization_arms: Option<[SourcedFrame; 5]>,
    pub mode_selectors: Option<[bool; 5]>,
}

impl ExecutableHashCall {
    pub fn verify(&self) -> Result<(), FullBlake2b448RelationError> {
        self.trace.verify(&self.frame)?;
        if self.digest != self.trace.digest() {
            return Err(FullBlake2b448RelationError::HashBinding(self.index));
        }
        if let Some(expected) = self.expected_public_digest {
            if expected != self.digest {
                return Err(FullBlake2b448RelationError::HashBinding(self.index));
            }
        }
        if let Some(arms) = &self.authorization_arms {
            let selectors =
                self.mode_selectors
                    .ok_or(FullBlake2b448RelationError::AuthorizationMux(
                        "missing selectors",
                    ))?;
            let selected = selectors
                .iter()
                .position(|selected| *selected)
                .ok_or(FullBlake2b448RelationError::AuthorizationMux("not one hot"))?;
            if selectors
                .iter()
                .enumerate()
                .any(|(index, value)| index != selected && *value)
                || self.frame != arms[selected]
            {
                return Err(FullBlake2b448RelationError::AuthorizationMux(
                    "selected arm mismatch",
                ));
            }
        }
        Ok(())
    }

    pub fn verify_against_spec(&self, spec: &CallSpec) -> Result<(), FullBlake2b448RelationError> {
        let trace_kind_matches = match (spec.algorithm, spec.fixed_authorization_mux, &self.trace) {
            (CandidateHashAlgorithm::Blake2b448, false, ExecutableHashTrace::Blake2b(_)) => true,
            (
                CandidateHashAlgorithm::Blake2b448,
                true,
                ExecutableHashTrace::CandidateBoolean(trace),
            ) => trace.fixed_mux && trace.compression_count == spec.blake_compressions,
            (
                CandidateHashAlgorithm::Sha3_512Truncated448,
                _,
                ExecutableHashTrace::CandidateBoolean(trace),
            ) => trace.fixed_mux == spec.fixed_authorization_mux && trace.compression_count == 0,
            (CandidateHashAlgorithm::Shake256_448, false, ExecutableHashTrace::Shake256(_)) => true,
            _ => false,
        };
        if self.index != spec.index
            || self.name != spec.name
            || self.role != spec.role
            || self.algorithm != spec.algorithm
            || self.output_symbol != spec.output_symbol
            || self.binding != spec.binding
            || self.expected_public_digest != spec.expected_public_digest
            || self.frame.bytes.len() != spec.exact_frame_bytes
            || self.trace.cores() != (spec.blake_compressions, spec.keccak_permutations)
            || self.authorization_arms.is_some() != spec.fixed_authorization_mux
            || self.mode_selectors.is_some() != spec.fixed_authorization_mux
            || !trace_kind_matches
        {
            return Err(FullBlake2b448RelationError::CallSpec(spec.index));
        }
        self.verify()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MixedRelationStats {
    pub active_inputs: usize,
    pub active_outputs: usize,
    pub physical_hash_calls: usize,
    pub secret_hash_calls: usize,
    pub collision_hash_calls: usize,
    pub blake_compressions: usize,
    pub sha3_permutations: usize,
    pub shake_permutations: usize,
    pub scalar_hash_constraints: usize,
    pub public_values: usize,
    pub production_authorized: bool,
}

pub struct FullBlake2b448Relation {
    profile: SecretHashProfile,
    statement: FullBlake2b448Statement,
    witness: FullShake448Witness,
    semantic_certificate: SemanticCertificate,
    statement_bytes: [u8; CANDIDATE_STATEMENT_BYTES],
    public_limbs: [u64; CANDIDATE_STATEMENT_LIMBS],
    stablecoin_authority: StablecoinAuthority,
    stablecoin_protocol_manifest_view: Option<StablecoinProtocolManifestView>,
    hash_calls: Vec<ExecutableHashCall>,
    stats: MixedRelationStats,
    production_blockers: Vec<&'static str>,
}

impl FullBlake2b448Relation {
    pub const fn profile(&self) -> SecretHashProfile {
        self.profile
    }

    pub const fn statement(&self) -> &FullBlake2b448Statement {
        &self.statement
    }

    pub fn witness(&self) -> &FullShake448Witness {
        &self.witness
    }

    pub const fn semantic_certificate(&self) -> &SemanticCertificate {
        &self.semantic_certificate
    }

    pub const fn statement_bytes(&self) -> &[u8; CANDIDATE_STATEMENT_BYTES] {
        &self.statement_bytes
    }

    pub const fn public_limbs(&self) -> &[u64; CANDIDATE_STATEMENT_LIMBS] {
        &self.public_limbs
    }

    pub const fn stablecoin_authority(&self) -> StablecoinAuthority {
        self.stablecoin_authority
    }

    pub fn stablecoin_protocol_manifest_view(&self) -> Option<&StablecoinProtocolManifestView> {
        self.stablecoin_protocol_manifest_view.as_ref()
    }

    pub fn hash_calls(&self) -> &[ExecutableHashCall] {
        &self.hash_calls
    }

    pub const fn stats(&self) -> MixedRelationStats {
        self.stats
    }

    pub fn production_blockers(&self) -> &[&'static str] {
        &self.production_blockers
    }

    pub fn verify(&self) -> Result<(), FullBlake2b448RelationError> {
        validate_mixed_hash_registry()?;
        let certificate = validate_full_blake2b448_pre_hash_semantics(
            &self.statement,
            &self.witness,
            self.semantic_certificate.expected_activation,
            self.stablecoin_protocol_manifest_view.as_ref(),
        )?;
        if certificate != self.semantic_certificate
            || self.statement_bytes != certificate.statement_bytes
            || self.public_limbs != certificate.public_limbs
            || self.stablecoin_authority != certificate.stablecoin_authority
        {
            return Err(FullBlake2b448RelationError::SemanticCertificate);
        }
        if self.hash_calls.len() != PHYSICAL_HASH_CALLS {
            return Err(FullBlake2b448RelationError::Registry);
        }
        for (index, call) in self.hash_calls.iter().enumerate() {
            let spec = exact_call_spec(self.profile, index, &self.statement, &self.witness)?;
            call.verify_against_spec(&spec)?;
        }
        validate_derived_semantics(
            &self.statement,
            &self.witness,
            &certificate,
            &self.hash_calls,
        )?;
        let blake = self
            .hash_calls
            .iter()
            .map(|call| call.trace.cores().0)
            .sum::<usize>();
        let permutations = self
            .hash_calls
            .iter()
            .map(|call| call.trace.cores().1)
            .sum::<usize>();
        let (expected_blake, expected_sha3, expected_shake) = match self.profile {
            SecretHashProfile::UnkeyedBlake2b448 => {
                if blake != BLAKE2B_COMPRESSIONS || permutations != SHAKE256_PERMUTATIONS {
                    return Err(FullBlake2b448RelationError::Registry);
                }
                (BLAKE2B_COMPRESSIONS, 0, SHAKE256_PERMUTATIONS)
            }
            SecretHashProfile::SplitSha3_512Truncated448 => {
                if blake != 0 || permutations != SHAKE256_PERMUTATIONS + SPLIT_SHA3_PERMUTATIONS {
                    return Err(FullBlake2b448RelationError::Registry);
                }
                (0, SPLIT_SHA3_PERMUTATIONS, SHAKE256_PERMUTATIONS)
            }
        };
        let expected_stats = MixedRelationStats {
            active_inputs: certificate.active_inputs,
            active_outputs: certificate.active_outputs,
            physical_hash_calls: PHYSICAL_HASH_CALLS,
            secret_hash_calls: SECRET_HASH_CALLS,
            collision_hash_calls: COLLISION_HASH_CALLS,
            blake_compressions: expected_blake,
            sha3_permutations: expected_sha3,
            shake_permutations: expected_shake,
            scalar_hash_constraints: self
                .hash_calls
                .iter()
                .map(|call| call.trace.scalar_constraints())
                .sum(),
            public_values: CANDIDATE_STATEMENT_LIMBS,
            production_authorized: FULL_BLAKE2B448_PRODUCTION_AUTHORIZED,
        };
        if self.stats != expected_stats
            || self.production_blockers.as_slice() != &FULL_BLAKE2B448_PRODUCTION_BLOCKERS[..]
        {
            return Err(FullBlake2b448RelationError::SemanticCertificate);
        }
        Ok(())
    }
}

fn role_spec(role: [u8; 8]) -> Result<HashRoleSpec, FullBlake2b448RelationError> {
    MIXED_HASH_REGISTRY
        .iter()
        .copied()
        .find(|entry| entry.role == role)
        .ok_or(FullBlake2b448RelationError::Registry)
}

fn compile_ordinary_call(
    profile: SecretHashProfile,
    index: usize,
    name: impl Into<String>,
    frame: SourcedFrame,
    output_symbol: impl Into<String>,
    binding: OutputBinding,
    expected_public_digest: Option<Digest448>,
) -> Result<ExecutableHashCall, FullBlake2b448RelationError> {
    let name = name.into();
    let role: [u8; 8] = frame.bytes[8..16]
        .try_into()
        .map_err(|_| FullBlake2b448RelationError::Geometry(index))?;
    let spec = role_spec(role)?;
    if frame.bytes.len() > spec.maximum_frame_bytes {
        return Err(FullBlake2b448RelationError::Geometry(index));
    }
    let (algorithm, trace) = if spec.shake_permutations_per_call != 0 {
        let trace = shake256_relation(&frame.bytes, DIGEST_BYTES)?;
        if trace.permutations().len() != spec.shake_permutations_per_call {
            return Err(FullBlake2b448RelationError::Geometry(index));
        }
        (
            CandidateHashAlgorithm::Shake256_448,
            ExecutableHashTrace::Shake256(trace),
        )
    } else {
        match profile {
            SecretHashProfile::UnkeyedBlake2b448 => {
                let trace = blake2b_relation::<BLAKE2B_448_OUTPUT_BYTES>(&frame.bytes)?;
                if trace.blocks().len() != spec.blake_compressions_per_call {
                    return Err(FullBlake2b448RelationError::Geometry(index));
                }
                (
                    CandidateHashAlgorithm::Blake2b448,
                    ExecutableHashTrace::Blake2b(trace),
                )
            }
            SecretHashProfile::SplitSha3_512Truncated448 => {
                let trace = sha3_512_trace(&frame)?;
                if trace.permutation_count != spec.sha3_permutations_per_call {
                    return Err(FullBlake2b448RelationError::Geometry(index));
                }
                (
                    CandidateHashAlgorithm::Sha3_512Truncated448,
                    ExecutableHashTrace::CandidateBoolean(trace),
                )
            }
        }
    };
    let digest = trace.digest();
    let call = ExecutableHashCall {
        index,
        name,
        role,
        algorithm,
        frame,
        output_symbol: output_symbol.into(),
        digest,
        binding,
        expected_public_digest,
        trace,
        authorization_arms: None,
        mode_selectors: None,
    };
    call.verify()?;
    Ok(call)
}

fn compile_authorization_call(
    profile: SecretHashProfile,
    index: usize,
    name: impl Into<String>,
    arms: [SourcedFrame; 5],
    mode_selectors: [bool; 5],
    output_symbol: impl Into<String>,
) -> Result<ExecutableHashCall, FullBlake2b448RelationError> {
    let selected = mode_selectors
        .iter()
        .position(|selected| *selected)
        .ok_or(FullBlake2b448RelationError::AuthorizationMux("not one hot"))?;
    if mode_selectors
        .iter()
        .enumerate()
        .any(|(index, value)| index != selected && *value)
    {
        return Err(FullBlake2b448RelationError::AuthorizationMux("not one hot"));
    }
    let role: [u8; 8] = arms[selected].bytes[8..16]
        .try_into()
        .map_err(|_| FullBlake2b448RelationError::Geometry(index))?;
    let spec = role_spec(role)?;
    if arms
        .iter()
        .any(|arm| arm.bytes.len() > spec.maximum_frame_bytes || arm.bytes[8..16] != role)
    {
        return Err(FullBlake2b448RelationError::Geometry(index));
    }
    let trace = match profile {
        SecretHashProfile::UnkeyedBlake2b448 => {
            fixed_blake2b_authorization_trace(mode_selectors, &arms)?
        }
        SecretHashProfile::SplitSha3_512Truncated448 => {
            fixed_sha3_authorization_trace(mode_selectors, &arms)?
        }
    };
    if trace.compression_count != spec.blake_compressions_per_call
        && profile == SecretHashProfile::UnkeyedBlake2b448
        || trace.permutation_count != spec.sha3_permutations_per_call
            && profile == SecretHashProfile::SplitSha3_512Truncated448
    {
        return Err(FullBlake2b448RelationError::Geometry(index));
    }
    let algorithm = match profile {
        SecretHashProfile::UnkeyedBlake2b448 => CandidateHashAlgorithm::Blake2b448,
        SecretHashProfile::SplitSha3_512Truncated448 => {
            CandidateHashAlgorithm::Sha3_512Truncated448
        }
    };
    let digest = trace.digest;
    let call = ExecutableHashCall {
        index,
        name: name.into(),
        role,
        algorithm,
        frame: arms[selected].clone(),
        output_symbol: output_symbol.into(),
        digest,
        binding: OutputBinding::Internal,
        expected_public_digest: None,
        trace: ExecutableHashTrace::CandidateBoolean(trace),
        authorization_arms: Some(arms),
        mode_selectors: Some(mode_selectors),
    };
    call.verify()?;
    Ok(call)
}

fn signed_i128(value: SignedMagnitude) -> Result<i128, FullBlake2b448RelationError> {
    if value.magnitude > V6_MAX_NOTE_VALUE || value.negative && value.magnitude == 0 {
        return Err(FullBlake2b448RelationError::ValueOutOfRange(
            "signed magnitude",
        ));
    }
    Ok(if value.negative {
        -i128::from(value.magnitude)
    } else {
        i128::from(value.magnitude)
    })
}

fn is_canonical_asset(asset: u64) -> bool {
    asset < GOLDILOCKS_MODULUS && asset != RESERVED_REDUCED_PADDING_ASSET_ID
}

fn validate_slots(slots: [u64; BALANCE_SLOTS]) -> Result<(), FullBlake2b448RelationError> {
    if slots[0] != NATIVE_ASSET_ID {
        return Err(FullBlake2b448RelationError::Asset);
    }
    let mut padding = false;
    let mut previous = NATIVE_ASSET_ID;
    for asset in slots.into_iter().skip(1) {
        if asset == PADDING_ASSET_ID {
            padding = true;
        } else if padding || !is_canonical_asset(asset) || asset == 0 || asset <= previous {
            return Err(FullBlake2b448RelationError::Asset);
        } else {
            previous = asset;
        }
    }
    Ok(())
}

fn validate_note(note: &NoteOpening) -> Result<(), FullBlake2b448RelationError> {
    if note.value > V6_MAX_NOTE_VALUE {
        return Err(FullBlake2b448RelationError::ValueOutOfRange("note value"));
    }
    if !is_canonical_asset(note.asset_id) {
        return Err(FullBlake2b448RelationError::Asset);
    }
    Ok(())
}

fn input_inactive_payload_is_zero(input: &crate::full_shake448_relation::InputWitness) -> bool {
    input.spend_key == [0; SPEND_KEY_BYTES]
        && input.note.is_zero()
        && input.position == 0
        && input.siblings == [[0; DIGEST_BYTES]; MERKLE_DEPTH]
        && input.balance_slot_selectors == [false; BALANCE_SLOTS]
}

fn output_inactive_payload_is_zero(output: &crate::full_shake448_relation::OutputWitness) -> bool {
    output.note.is_zero()
        && output.balance_slot_selectors == [false; BALANCE_SLOTS]
        && output.canonical_ciphertext == [0; V6_CANONICAL_CIPHERTEXT_BYTES]
}

fn selected_slot(
    selectors: [bool; BALANCE_SLOTS],
    slots: [u64; BALANCE_SLOTS],
    asset: u64,
) -> Result<usize, FullBlake2b448RelationError> {
    let selected = selectors
        .iter()
        .position(|selected| *selected)
        .ok_or(FullBlake2b448RelationError::Asset)?;
    if selectors
        .iter()
        .enumerate()
        .any(|(index, value)| index != selected && *value)
        || slots[selected] != asset
        || asset == PADDING_ASSET_ID
    {
        return Err(FullBlake2b448RelationError::Asset);
    }
    Ok(selected)
}

/// Parser/admission checks inherited from the live verifier-input boundary.
///
/// These are deliberately kept outside the algebraic transaction relation:
/// `circuits/transaction-core/src/verifier_inputs.rs` rejects a zero public
/// nullifier for an active input and a zero public note commitment for an active
/// output.  No analogous live predicate exists for input-note commitments,
/// ciphertext hashes, accumulator intents, or signer tags, so those values are
/// not strengthened here. Enabled stablecoin bindings additionally require the
/// exact consensus-side manifest/height view supplied to the live-policy
/// compiler. Its policy/oracle/attestation equalities target the statement's
/// native 48-byte fields directly. The scalar compiler still receives these as
/// an external manifest view; the M4 diagnostic has a typed selected-entry
/// lifecycle seam, while consensus-root authenticity and manifest membership
/// remain external until their aggregate graph is compiled.
pub fn validate_composed_admission_preconditions(
    statement: &FullBlake2b448Statement,
) -> Result<(), FullBlake2b448RelationError> {
    for (active, nullifier) in statement.input_flags.into_iter().zip(statement.nullifiers) {
        if active && nullifier == [0; DIGEST_BYTES] {
            return Err(FullBlake2b448RelationError::AdmissionPrecondition(
                "active public nullifier is zero",
            ));
        }
    }
    for (active, commitment) in statement
        .output_flags
        .into_iter()
        .zip(statement.commitments)
    {
        if active && commitment == [0; DIGEST_BYTES] {
            return Err(FullBlake2b448RelationError::AdmissionPrecondition(
                "active public output commitment is zero",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemanticCertificate {
    pub expected_activation: V6ActivationBinding,
    pub statement_bytes: [u8; CANDIDATE_STATEMENT_BYTES],
    pub public_limbs: [u64; CANDIDATE_STATEMENT_LIMBS],
    pub stablecoin_authority: StablecoinAuthority,
    pub active_inputs: usize,
    pub active_outputs: usize,
}

pub fn validate_full_blake2b448_pre_hash_semantics(
    statement: &FullBlake2b448Statement,
    witness: &FullShake448Witness,
    expected_activation: V6ActivationBinding,
    stablecoin_protocol_manifest_view: Option<&StablecoinProtocolManifestView>,
) -> Result<SemanticCertificate, FullBlake2b448RelationError> {
    validate_mixed_hash_registry()?;
    let statement_bytes = candidate_statement_bytes(statement, expected_activation)?;
    if decode_candidate_statement_bytes(&statement_bytes, expected_activation)? != *statement {
        return Err(FullBlake2b448RelationError::Statement(
            "candidate parser/statement round trip",
        ));
    }
    let public_limbs = candidate_statement_limbs(&statement_bytes);
    if public_limbs
        .iter()
        .any(|value| *value >= GOLDILOCKS_MODULUS)
    {
        return Err(FullBlake2b448RelationError::Statement(
            "non-canonical public limb",
        ));
    }
    let mut reconstructed = [0u8; CANDIDATE_STATEMENT_BYTES];
    for (index, limb) in public_limbs.iter().copied().enumerate() {
        let offset = index * CANDIDATE_STATEMENT_LIMB_BYTES;
        let take = (CANDIDATE_STATEMENT_BYTES - offset).min(CANDIDATE_STATEMENT_LIMB_BYTES);
        reconstructed[offset..offset + take].copy_from_slice(&limb.to_le_bytes()[..take]);
    }
    if reconstructed != statement_bytes {
        return Err(FullBlake2b448RelationError::Statement(
            "candidate statement limb reconstruction",
        ));
    }
    let stablecoin_authority = StablecoinAuthority::try_from_statement(statement)?;
    validate_stablecoin_protocol_manifest_view(
        stablecoin_authority,
        stablecoin_protocol_manifest_view,
    )
    .map_err(FullBlake2b448RelationError::LiveStablecoinPolicy)?;
    validate_composed_admission_preconditions(statement)?;
    if witness.inputs.each_ref().map(|input| input.active) != statement.input_flags
        || witness.outputs.each_ref().map(|output| output.active) != statement.output_flags
    {
        return Err(FullBlake2b448RelationError::PublicMismatch(
            "activity flags",
        ));
    }
    let active_inputs = statement
        .input_flags
        .into_iter()
        .filter(|active| *active)
        .count();
    let active_outputs = statement
        .output_flags
        .into_iter()
        .filter(|active| *active)
        .count();
    if active_inputs == 0 && active_outputs == 0 {
        return Err(FullBlake2b448RelationError::Shape(
            "all-empty activity mask",
        ));
    }
    if statement.fee > V6_MAX_NOTE_VALUE {
        return Err(FullBlake2b448RelationError::ValueOutOfRange("fee"));
    }
    validate_slots(statement.balance_asset_ids)?;
    if statement.input_flags == [true, true] && statement.nullifiers[0] == statement.nullifiers[1] {
        return Err(FullBlake2b448RelationError::PublicMismatch(
            "duplicate active nullifiers",
        ));
    }
    for (index, input) in witness.inputs.iter().enumerate() {
        if input.active {
            validate_note(&input.note)?;
            if input.position >> MERKLE_DEPTH != 0 {
                return Err(FullBlake2b448RelationError::Membership(index));
            }
        } else if !input_inactive_payload_is_zero(input)
            || statement.nullifiers[index] != [0; DIGEST_BYTES]
        {
            return Err(FullBlake2b448RelationError::InactivePayload {
                index,
                role: "input",
            });
        }
    }
    for (index, output) in witness.outputs.iter().enumerate() {
        if output.active {
            validate_note(&output.note)?;
            if statement.ciphertext_sizes[index] as usize != V6_CANONICAL_CIPHERTEXT_BYTES {
                return Err(FullBlake2b448RelationError::PublicMismatch(
                    "ciphertext size",
                ));
            }
        } else if !output_inactive_payload_is_zero(output)
            || statement.commitments[index] != [0; DIGEST_BYTES]
            || statement.ciphertext_hashes[index] != [0; DIGEST_BYTES]
            || statement.ciphertext_sizes[index] != 0
        {
            return Err(FullBlake2b448RelationError::InactivePayload {
                index,
                role: "output",
            });
        }
    }
    Ok(SemanticCertificate {
        expected_activation,
        statement_bytes,
        public_limbs,
        stablecoin_authority,
        active_inputs,
        active_outputs,
    })
}

fn validate_native_balance(
    inputs: u128,
    outputs: u128,
    fee: u64,
    value_balance: SignedMagnitude,
) -> Result<(), FullBlake2b448RelationError> {
    let inputs = i128::try_from(inputs)
        .map_err(|_| FullBlake2b448RelationError::ValueOutOfRange("native inputs"))?;
    let outputs = i128::try_from(outputs)
        .map_err(|_| FullBlake2b448RelationError::ValueOutOfRange("native outputs"))?;
    if inputs - outputs != i128::from(fee) - signed_i128(value_balance)? {
        return Err(FullBlake2b448RelationError::Balance(NATIVE_ASSET_ID));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ResolvedAuthorization {
    input_auth_keys: [Digest448; MAX_INPUTS],
    input_nullifier_keys: [Digest448; MAX_INPUTS],
    output0_auth_key: Option<Digest448>,
}

fn require_note_kind(
    note: &NoteOpening,
    kind: NoteKind,
    error: &'static str,
) -> Result<(), FullBlake2b448RelationError> {
    if note.kind != kind {
        return Err(FullBlake2b448RelationError::Authorization(error));
    }
    Ok(())
}

fn require_active_inputs_kind(
    witness: &FullShake448Witness,
    kind: NoteKind,
    error: &'static str,
) -> Result<(), FullBlake2b448RelationError> {
    if witness
        .inputs
        .iter()
        .any(|input| input.active && input.note.kind != kind)
    {
        return Err(FullBlake2b448RelationError::Authorization(error));
    }
    Ok(())
}

fn require_active_outputs_kind(
    witness: &FullShake448Witness,
    kind: NoteKind,
    error: &'static str,
) -> Result<(), FullBlake2b448RelationError> {
    if witness
        .outputs
        .iter()
        .any(|output| output.active && output.note.kind != kind)
    {
        return Err(FullBlake2b448RelationError::Authorization(error));
    }
    Ok(())
}

fn require_optional_ordinary_output1(
    witness: &FullShake448Witness,
) -> Result<(), FullBlake2b448RelationError> {
    if witness.outputs[1].active && witness.outputs[1].note.kind != NoteKind::Ordinary {
        return Err(FullBlake2b448RelationError::Authorization(
            "optional output one must be ordinary",
        ));
    }
    Ok(())
}

fn require_zero_native_accumulator_note(
    note: &NoteOpening,
    error: &'static str,
) -> Result<(), FullBlake2b448RelationError> {
    if note.value != 0 || note.asset_id != NATIVE_ASSET_ID {
        return Err(FullBlake2b448RelationError::Authorization(error));
    }
    Ok(())
}

fn validate_accumulator(
    opening: &AccumulatorOpening,
    signer_tags: &[Digest448; MAX_SIGNERS],
    expected_policy_root: Digest448,
    expected_intent: Option<Digest448>,
) -> Result<(), FullBlake2b448RelationError> {
    if !(1..=MAX_SIGNERS as u64).contains(&opening.signer_count)
        || !(1..=opening.signer_count).contains(&opening.threshold)
        || opening.approval_count > opening.signer_count
        || expected_intent.is_some_and(|intent| opening.intent_digest != intent)
        || opening
            .approved_slots
            .iter()
            .filter(|approved| **approved)
            .count() as u64
            != opening.approval_count
        || opening.policy_root != expected_policy_root
    {
        return Err(FullBlake2b448RelationError::Authorization(
            "invalid accumulator metadata",
        ));
    }
    for slot in 0..MAX_SIGNERS {
        if slot < opening.signer_count as usize {
            if signer_tags[..slot].contains(&signer_tags[slot]) {
                return Err(FullBlake2b448RelationError::Authorization(
                    "duplicate signer tag",
                ));
            }
        } else if signer_tags[slot] != [0; DIGEST_BYTES] || opening.approved_slots[slot] {
            return Err(FullBlake2b448RelationError::Authorization(
                "inactive signer slot is nonzero",
            ));
        }
    }
    Ok(())
}

fn validate_authorization_activity_shape(
    mode: PrivateAuthMode,
    input_flags: [bool; MAX_INPUTS],
    output_flags: [bool; MAX_OUTPUTS],
) -> Result<(), FullBlake2b448RelationError> {
    let nonempty = input_flags
        .into_iter()
        .chain(output_flags)
        .any(|active| active);
    let input_nonempty = input_flags.into_iter().any(|active| active);
    let both_inputs = input_flags.into_iter().all(|active| active);
    let valid = match mode {
        PrivateAuthMode::SingleKey => true,
        PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
            input_nonempty && output_flags[0]
        }
        PrivateAuthMode::ApprovalStep => both_inputs && output_flags[0],
        PrivateAuthMode::FinalThresholdSpend => both_inputs,
    };
    if !nonempty || !valid {
        return Err(FullBlake2b448RelationError::Authorization(
            "activity mask incompatible with mode",
        ));
    }
    Ok(())
}

fn resolve_authorization(
    witness: &FullShake448Witness,
    spend_material: [(Digest448, Digest448); MAX_INPUTS],
    policy_digest: Digest448,
    authorization_a: (Digest448, Digest448),
    authorization_b: (Digest448, Digest448),
    intent: Digest448,
) -> Result<ResolvedAuthorization, FullBlake2b448RelationError> {
    validate_authorization_activity_shape(
        witness.auth.mode,
        witness.inputs.each_ref().map(|input| input.active),
        witness.outputs.each_ref().map(|output| output.active),
    )?;
    match witness.auth.mode {
        PrivateAuthMode::SingleKey => {
            if !witness.auth.current.is_zero()
                || !witness.auth.next.is_zero()
                || witness.auth.signer_tags != [[0; DIGEST_BYTES]; MAX_SIGNERS]
            {
                return Err(FullBlake2b448RelationError::Authorization(
                    "single-key auxiliary witness must be zero",
                ));
            }
            require_active_inputs_kind(
                witness,
                NoteKind::Ordinary,
                "single-key inputs must be ordinary",
            )?;
            require_active_outputs_kind(
                witness,
                NoteKind::Ordinary,
                "single-key outputs must be ordinary",
            )?;
            Ok(ResolvedAuthorization {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: None,
            })
        }
        PrivateAuthMode::AccumulatorInit => {
            if !witness.auth.current.is_zero() {
                return Err(FullBlake2b448RelationError::Authorization(
                    "init current state must be zero",
                ));
            }
            require_active_inputs_kind(
                witness,
                NoteKind::Ordinary,
                "init inputs must be ordinary",
            )?;
            require_note_kind(
                &witness.outputs[0].note,
                NoteKind::Accumulator,
                "init output zero must be accumulator",
            )?;
            require_optional_ordinary_output1(witness)?;
            require_zero_native_accumulator_note(
                &witness.outputs[0].note,
                "init accumulator note must be zero native",
            )?;
            validate_accumulator(
                &witness.auth.next,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            if witness.auth.next.approval_count != 0
                || witness.auth.next.approved_slots != [false; MAX_SIGNERS]
            {
                return Err(FullBlake2b448RelationError::Authorization(
                    "init approvals must be zero",
                ));
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: Some(authorization_a.0),
            })
        }
        PrivateAuthMode::ApprovalStep => {
            require_note_kind(
                &witness.inputs[0].note,
                NoteKind::Accumulator,
                "approval input zero must be accumulator",
            )?;
            require_note_kind(
                &witness.inputs[1].note,
                NoteKind::Ordinary,
                "approval signer input must be ordinary",
            )?;
            require_note_kind(
                &witness.outputs[0].note,
                NoteKind::Accumulator,
                "approval output zero must be accumulator",
            )?;
            require_optional_ordinary_output1(witness)?;
            require_zero_native_accumulator_note(
                &witness.inputs[0].note,
                "current accumulator note must be zero native",
            )?;
            require_zero_native_accumulator_note(
                &witness.outputs[0].note,
                "next accumulator note must be zero native",
            )?;
            if witness.inputs[0].spend_key != [0; SPEND_KEY_BYTES] {
                return Err(FullBlake2b448RelationError::Authorization(
                    "approval accumulator spend key must be zero",
                ));
            }
            validate_accumulator(
                &witness.auth.current,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            validate_accumulator(
                &witness.auth.next,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            if witness.auth.current.policy_root != witness.auth.next.policy_root
                || witness.auth.current.intent_digest != witness.auth.next.intent_digest
                || witness.auth.current.threshold != witness.auth.next.threshold
                || witness.auth.current.signer_count != witness.auth.next.signer_count
                || witness.auth.next.approval_count
                    != witness.auth.current.approval_count.saturating_add(1)
            {
                return Err(FullBlake2b448RelationError::Authorization(
                    "approval transition metadata",
                ));
            }
            let signer = spend_material[1].0;
            let matches = (0..witness.auth.current.signer_count as usize)
                .filter(|slot| witness.auth.signer_tags[*slot] == signer)
                .collect::<Vec<_>>();
            if matches.len() != 1 || witness.auth.current.approved_slots[matches[0]] {
                return Err(FullBlake2b448RelationError::Authorization(
                    "approval signer membership",
                ));
            }
            for slot in 0..MAX_SIGNERS {
                if witness.auth.next.approved_slots[slot]
                    != (witness.auth.current.approved_slots[slot] || slot == matches[0])
                {
                    return Err(FullBlake2b448RelationError::Authorization(
                        "approval slot transition",
                    ));
                }
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [authorization_a.0, spend_material[1].0],
                input_nullifier_keys: [authorization_a.1, spend_material[1].1],
                output0_auth_key: Some(authorization_b.0),
            })
        }
        PrivateAuthMode::ValueLockCreation => {
            if !witness.auth.next.is_zero() {
                return Err(FullBlake2b448RelationError::Authorization(
                    "value-lock next state must be zero",
                ));
            }
            require_active_inputs_kind(
                witness,
                NoteKind::Ordinary,
                "value-lock inputs must be ordinary",
            )?;
            require_note_kind(
                &witness.outputs[0].note,
                NoteKind::ValueLock,
                "value-lock output zero kind",
            )?;
            require_optional_ordinary_output1(witness)?;
            validate_accumulator(
                &witness.auth.current,
                &witness.auth.signer_tags,
                policy_digest,
                None,
            )?;
            if witness.auth.current.approval_count != 0
                || witness.auth.current.approved_slots != [false; MAX_SIGNERS]
            {
                return Err(FullBlake2b448RelationError::Authorization(
                    "value-lock approvals must be zero",
                ));
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [spend_material[0].0, spend_material[1].0],
                input_nullifier_keys: [spend_material[0].1, spend_material[1].1],
                output0_auth_key: Some(authorization_a.0),
            })
        }
        PrivateAuthMode::FinalThresholdSpend => {
            if !witness.auth.next.is_zero() {
                return Err(FullBlake2b448RelationError::Authorization(
                    "final next state must be zero",
                ));
            }
            require_note_kind(
                &witness.inputs[0].note,
                NoteKind::ValueLock,
                "final input zero must be value-lock",
            )?;
            require_note_kind(
                &witness.inputs[1].note,
                NoteKind::Accumulator,
                "final input one must be accumulator",
            )?;
            require_active_outputs_kind(
                witness,
                NoteKind::Ordinary,
                "final outputs must be ordinary",
            )?;
            if witness
                .inputs
                .iter()
                .any(|input| input.spend_key != [0; SPEND_KEY_BYTES])
            {
                return Err(FullBlake2b448RelationError::Authorization(
                    "final spend keys must be zero",
                ));
            }
            require_zero_native_accumulator_note(
                &witness.inputs[1].note,
                "final accumulator must be zero native",
            )?;
            validate_accumulator(
                &witness.auth.current,
                &witness.auth.signer_tags,
                policy_digest,
                Some(intent),
            )?;
            if witness.auth.current.approval_count < witness.auth.current.threshold {
                return Err(FullBlake2b448RelationError::Authorization(
                    "threshold not reached",
                ));
            }
            Ok(ResolvedAuthorization {
                input_auth_keys: [authorization_b.0, authorization_a.0],
                input_nullifier_keys: [authorization_b.1, authorization_a.1],
                output0_auth_key: None,
            })
        }
    }
}

fn require_exact_frame(
    calls: &[ExecutableHashCall],
    index: usize,
    expected: SourcedFrame,
) -> Result<(), FullBlake2b448RelationError> {
    if match calls.get(index) {
        Some(call) => call.frame != expected,
        None => true,
    } {
        return Err(FullBlake2b448RelationError::CallSpec(index));
    }
    Ok(())
}

fn validate_derived_semantics(
    statement: &FullBlake2b448Statement,
    witness: &FullShake448Witness,
    certificate: &SemanticCertificate,
    calls: &[ExecutableHashCall],
) -> Result<(), FullBlake2b448RelationError> {
    if calls.len() != PHYSICAL_HASH_CALLS {
        return Err(FullBlake2b448RelationError::Registry);
    }

    for input in 0..MAX_INPUTS {
        require_exact_frame(
            calls,
            NOTE_CALL_START + input,
            note_frame(&format!("input[{input}].note"), &witness.inputs[input].note)?,
        )?;
        require_exact_frame(
            calls,
            SPEND_A_CALL_START + input,
            spend_frame(input, 0, &witness.inputs[input].spend_key)?,
        )?;
        require_exact_frame(
            calls,
            SPEND_B_CALL_START + input,
            spend_frame(input, 1, &witness.inputs[input].spend_key)?,
        )?;
    }
    for output in 0..MAX_OUTPUTS {
        require_exact_frame(
            calls,
            NOTE_CALL_START + MAX_INPUTS + output,
            note_frame(
                &format!("output[{output}].note"),
                &witness.outputs[output].note,
            )?,
        )?;
        require_exact_frame(
            calls,
            CIPHERTEXT_CALL_START + output,
            ciphertext_frame(
                statement,
                output,
                &witness.outputs[output].canonical_ciphertext,
            )?,
        )?;
    }

    let selected_policy = if witness.auth.mode == PrivateAuthMode::AccumulatorInit {
        &witness.auth.next
    } else {
        &witness.auth.current
    };
    require_exact_frame(
        calls,
        POLICY_CALL,
        policy_frame(selected_policy, &witness.auth.signer_tags)?,
    )?;
    let selectors = witness.auth.mode.selectors();
    for lane in 0..2 {
        for slot in 0..2 {
            let index = if lane == 0 {
                AUTH_A_CALL_START + slot
            } else {
                AUTH_B_CALL_START + slot
            };
            let expected_arms = authorization_arms(witness, lane, slot)?;
            if calls[index].authorization_arms.as_ref() != Some(&expected_arms)
                || calls[index].mode_selectors != Some(selectors)
            {
                return Err(FullBlake2b448RelationError::CallSpec(index));
            }
        }
    }
    require_exact_frame(
        calls,
        INTENT_CALL,
        intent_frame(&certificate.statement_bytes)?,
    )?;
    require_exact_frame(calls, BALANCE_CALL, balance_frame(statement)?)?;

    let spend_material = core::array::from_fn(|input| {
        (
            calls[SPEND_A_CALL_START + input].digest,
            calls[SPEND_B_CALL_START + input].digest,
        )
    });
    let authorization_a = (
        calls[AUTH_A_CALL_START].digest,
        calls[AUTH_B_CALL_START].digest,
    );
    let authorization_b = (
        calls[AUTH_A_CALL_START + 1].digest,
        calls[AUTH_B_CALL_START + 1].digest,
    );
    let resolved = resolve_authorization(
        witness,
        spend_material,
        calls[POLICY_CALL].digest,
        authorization_a,
        authorization_b,
        calls[INTENT_CALL].digest,
    )?;

    let mut input_values = [[0u128; BALANCE_SLOTS]; MAX_INPUTS];
    let mut output_values = [[0u128; BALANCE_SLOTS]; MAX_OUTPUTS];
    for input_index in 0..MAX_INPUTS {
        let input = &witness.inputs[input_index];
        if input.active {
            let slot = selected_slot(
                input.balance_slot_selectors,
                statement.balance_asset_ids,
                input.note.asset_id,
            )?;
            input_values[input_index][slot] = u128::from(input.note.value);
            if input.note.pk_auth != resolved.input_auth_keys[input_index] {
                return Err(FullBlake2b448RelationError::Authorization(
                    "input note authorization key",
                ));
            }
        }
        require_exact_frame(
            calls,
            NULLIFIER_CALL_START + input_index,
            nullifier_frame(
                input_index,
                &resolved.input_nullifier_keys[input_index],
                input.position,
                &input.note.rho,
            )?,
        )?;
        let mut current = calls[NOTE_CALL_START + input_index].digest;
        for level in 0..MERKLE_DEPTH {
            let index = MERKLE_CALL_START + input_index * MERKLE_DEPTH + level;
            require_exact_frame(
                calls,
                index,
                merkle_frame(
                    input_index,
                    level,
                    &current,
                    &input.siblings[level],
                    (input.position >> level) & 1 == 0,
                )?,
            )?;
            current = calls[index].digest;
        }
        if input.active && current != statement.anchor {
            return Err(FullBlake2b448RelationError::Membership(input_index));
        }
    }

    for output_index in 0..MAX_OUTPUTS {
        let output = &witness.outputs[output_index];
        if output.active {
            let slot = selected_slot(
                output.balance_slot_selectors,
                statement.balance_asset_ids,
                output.note.asset_id,
            )?;
            output_values[output_index][slot] = u128::from(output.note.value);
        }
    }
    if let Some(expected) = resolved.output0_auth_key {
        if !witness.outputs[0].active || witness.outputs[0].note.pk_auth != expected {
            return Err(FullBlake2b448RelationError::Authorization(
                "mode-specific output zero authorization",
            ));
        }
    }

    for slot in 0..BALANCE_SLOTS {
        let inputs = input_values.iter().map(|values| values[slot]).sum::<u128>();
        let outputs = output_values
            .iter()
            .map(|values| values[slot])
            .sum::<u128>();
        let asset = statement.balance_asset_ids[slot];
        if asset == PADDING_ASSET_ID {
            if inputs != 0 || outputs != 0 {
                return Err(FullBlake2b448RelationError::Balance(asset));
            }
        } else if asset == NATIVE_ASSET_ID {
            validate_native_balance(inputs, outputs, statement.fee, statement.value_balance)?;
        } else {
            let expected_delta = match certificate.stablecoin_authority {
                StablecoinAuthority::Enabled {
                    asset_id,
                    issuance_delta,
                    ..
                } if asset_id == asset => signed_i128(issuance_delta)?,
                _ => 0,
            };
            if i128::try_from(inputs).expect("bounded note sum")
                - i128::try_from(outputs).expect("bounded note sum")
                != expected_delta
            {
                return Err(FullBlake2b448RelationError::Balance(asset));
            }
        }
    }
    Ok(())
}

pub fn compile_full_blake2b448_candidate(
    profile: SecretHashProfile,
    statement: &FullBlake2b448Statement,
    witness: &FullShake448Witness,
    expected_activation: V6ActivationBinding,
) -> Result<FullBlake2b448Relation, FullBlake2b448RelationError> {
    compile_full_blake2b448_candidate_with_policy_view(
        profile,
        statement,
        witness,
        expected_activation,
        None,
    )
}

pub fn compile_full_blake2b448_candidate_with_stablecoin_protocol_manifest(
    profile: SecretHashProfile,
    statement: &FullBlake2b448Statement,
    witness: &FullShake448Witness,
    expected_activation: V6ActivationBinding,
    current_height: u64,
    manifest: &ProtocolManifest,
) -> Result<FullBlake2b448Relation, FullBlake2b448RelationError> {
    compile_full_blake2b448_candidate_with_policy_view(
        profile,
        statement,
        witness,
        expected_activation,
        Some(StablecoinProtocolManifestView {
            current_height,
            manifest: manifest.clone(),
        }),
    )
}

fn compile_full_blake2b448_candidate_with_policy_view(
    profile: SecretHashProfile,
    statement: &FullBlake2b448Statement,
    witness: &FullShake448Witness,
    expected_activation: V6ActivationBinding,
    stablecoin_protocol_manifest_view: Option<StablecoinProtocolManifestView>,
) -> Result<FullBlake2b448Relation, FullBlake2b448RelationError> {
    let semantic_certificate = validate_full_blake2b448_pre_hash_semantics(
        statement,
        witness,
        expected_activation,
        stablecoin_protocol_manifest_view.as_ref(),
    )?;
    let statement_bytes = semantic_certificate.statement_bytes;
    let public_limbs = semantic_certificate.public_limbs;
    let stablecoin_authority = semantic_certificate.stablecoin_authority;
    let active_inputs = semantic_certificate.active_inputs;
    let active_outputs = semantic_certificate.active_outputs;

    let mut calls: Vec<Option<ExecutableHashCall>> = std::iter::repeat_with(|| None)
        .take(PHYSICAL_HASH_CALLS)
        .collect();
    let mut note_commitments = [[0u8; DIGEST_BYTES]; MAX_INPUTS + MAX_OUTPUTS];
    for index in 0..MAX_INPUTS {
        let call = compile_ordinary_call(
            profile,
            NOTE_CALL_START + index,
            format!("note.input[{index}]"),
            note_frame(&format!("input[{index}].note"), &witness.inputs[index].note)?,
            format!("digest.note.input[{index}]"),
            OutputBinding::Internal,
            None,
        )?;
        note_commitments[index] = call.digest;
        let call_index = call.index;
        calls[call_index] = Some(call);
    }
    for index in 0..MAX_OUTPUTS {
        let call = compile_ordinary_call(
            profile,
            NOTE_CALL_START + MAX_INPUTS + index,
            format!("note.output[{index}]"),
            note_frame(
                &format!("output[{index}].note"),
                &witness.outputs[index].note,
            )?,
            format!("digest.note.output[{index}]"),
            OutputBinding::PublicWhenOutputActive(index),
            witness.outputs[index]
                .active
                .then_some(statement.commitments[index]),
        )?;
        note_commitments[MAX_INPUTS + index] = call.digest;
        let call_index = call.index;
        calls[call_index] = Some(call);
    }

    let mut spend_material = [([0u8; DIGEST_BYTES], [0u8; DIGEST_BYTES]); MAX_INPUTS];
    for index in 0..MAX_INPUTS {
        let call_a = compile_ordinary_call(
            profile,
            SPEND_A_CALL_START + index,
            format!("spend.input[{index}].lane_a"),
            spend_frame(index, 0, &witness.inputs[index].spend_key)?,
            format!("digest.spend.input[{index}].lane_a"),
            OutputBinding::Internal,
            None,
        )?;
        let call_b = compile_ordinary_call(
            profile,
            SPEND_B_CALL_START + index,
            format!("spend.input[{index}].lane_b"),
            spend_frame(index, 1, &witness.inputs[index].spend_key)?,
            format!("digest.spend.input[{index}].lane_b"),
            OutputBinding::Internal,
            None,
        )?;
        spend_material[index] = (call_a.digest, call_b.digest);
        let call_a_index = call_a.index;
        let call_b_index = call_b.index;
        calls[call_a_index] = Some(call_a);
        calls[call_b_index] = Some(call_b);
    }

    let selected_policy = if witness.auth.mode == PrivateAuthMode::AccumulatorInit {
        &witness.auth.next
    } else {
        &witness.auth.current
    };
    let policy_call = compile_ordinary_call(
        profile,
        POLICY_CALL,
        "authorization.policy",
        policy_frame(selected_policy, &witness.auth.signer_tags)?,
        "digest.authorization.policy",
        OutputBinding::Internal,
        None,
    )?;
    let policy_digest = policy_call.digest;
    calls[POLICY_CALL] = Some(policy_call);

    let selectors = witness.auth.mode.selectors();
    let mut authorization = [[0u8; DIGEST_BYTES]; 4];
    for lane in 0..2 {
        for slot in 0..2 {
            let index = if lane == 0 {
                AUTH_A_CALL_START + slot
            } else {
                AUTH_B_CALL_START + slot
            };
            let call = compile_authorization_call(
                profile,
                index,
                format!("authorization.mux[{slot}].lane[{lane}]"),
                authorization_arms(witness, lane, slot)?,
                selectors,
                format!("digest.authorization.mux[{slot}].lane[{lane}]"),
            )?;
            authorization[slot * 2 + lane] = call.digest;
            calls[index] = Some(call);
        }
    }
    let authorization_a = (authorization[0], authorization[1]);
    let authorization_b = (authorization[2], authorization[3]);

    let intent_call = compile_ordinary_call(
        profile,
        INTENT_CALL,
        "intent.statement",
        intent_frame(&statement_bytes)?,
        "digest.intent",
        OutputBinding::Internal,
        None,
    )?;
    let intent = intent_call.digest;
    calls[INTENT_CALL] = Some(intent_call);
    let resolved = resolve_authorization(
        witness,
        spend_material,
        policy_digest,
        authorization_a,
        authorization_b,
        intent,
    )?;

    let mut input_values = [[0u128; BALANCE_SLOTS]; MAX_INPUTS];
    let mut output_values = [[0u128; BALANCE_SLOTS]; MAX_OUTPUTS];
    for index in 0..MAX_INPUTS {
        let input = &witness.inputs[index];
        if input.active {
            let slot = selected_slot(
                input.balance_slot_selectors,
                statement.balance_asset_ids,
                input.note.asset_id,
            )?;
            input_values[index][slot] = u128::from(input.note.value);
            if input.note.pk_auth != resolved.input_auth_keys[index] {
                return Err(FullBlake2b448RelationError::Authorization(
                    "input note authorization key",
                ));
            }
        }
        let nullifier_call = compile_ordinary_call(
            profile,
            NULLIFIER_CALL_START + index,
            format!("nullifier.input[{index}]"),
            nullifier_frame(
                index,
                &resolved.input_nullifier_keys[index],
                input.position,
                &input.note.rho,
            )?,
            format!("digest.nullifier[{index}]"),
            OutputBinding::PublicWhenInputActive(index),
            input.active.then_some(statement.nullifiers[index]),
        )?;
        let nullifier_call_index = nullifier_call.index;
        calls[nullifier_call_index] = Some(nullifier_call);

        let mut current = note_commitments[index];
        for level in 0..MERKLE_DEPTH {
            let sibling = input.siblings[level];
            let current_is_left = (input.position >> level) & 1 == 0;
            let merkle_call = compile_ordinary_call(
                profile,
                MERKLE_CALL_START + index * MERKLE_DEPTH + level,
                format!("merkle.input[{index}].level[{level}]"),
                merkle_frame(index, level, &current, &sibling, current_is_left)?,
                format!("digest.merkle.input[{index}].level[{level}]"),
                OutputBinding::Internal,
                None,
            )?;
            current = merkle_call.digest;
            let merkle_call_index = merkle_call.index;
            calls[merkle_call_index] = Some(merkle_call);
        }
        if input.active && current != statement.anchor {
            return Err(FullBlake2b448RelationError::Membership(index));
        }
    }

    for index in 0..MAX_OUTPUTS {
        let output = &witness.outputs[index];
        if output.active {
            let slot = selected_slot(
                output.balance_slot_selectors,
                statement.balance_asset_ids,
                output.note.asset_id,
            )?;
            output_values[index][slot] = u128::from(output.note.value);
        }
        let ciphertext_call = compile_ordinary_call(
            profile,
            CIPHERTEXT_CALL_START + index,
            format!("ciphertext.output[{index}]"),
            ciphertext_frame(statement, index, &output.canonical_ciphertext)?,
            format!("digest.ciphertext[{index}]"),
            OutputBinding::PublicWhenOutputActive(index),
            output.active.then_some(statement.ciphertext_hashes[index]),
        )?;
        let ciphertext_call_index = ciphertext_call.index;
        calls[ciphertext_call_index] = Some(ciphertext_call);
    }
    if let Some(expected) = resolved.output0_auth_key {
        if !witness.outputs[0].active || witness.outputs[0].note.pk_auth != expected {
            return Err(FullBlake2b448RelationError::Authorization(
                "mode-specific output zero authorization",
            ));
        }
    }

    for slot in 0..BALANCE_SLOTS {
        let inputs = input_values.iter().map(|values| values[slot]).sum::<u128>();
        let outputs = output_values
            .iter()
            .map(|values| values[slot])
            .sum::<u128>();
        let asset = statement.balance_asset_ids[slot];
        if asset == PADDING_ASSET_ID {
            if inputs != 0 || outputs != 0 {
                return Err(FullBlake2b448RelationError::Balance(asset));
            }
        } else if asset == NATIVE_ASSET_ID {
            validate_native_balance(inputs, outputs, statement.fee, statement.value_balance)?;
        } else {
            let expected_delta = match stablecoin_authority {
                StablecoinAuthority::Enabled {
                    asset_id,
                    issuance_delta,
                    ..
                } if asset_id == asset => signed_i128(issuance_delta)?,
                _ => 0,
            };
            if i128::try_from(inputs).expect("bounded note sum")
                - i128::try_from(outputs).expect("bounded note sum")
                != expected_delta
            {
                return Err(FullBlake2b448RelationError::Balance(asset));
            }
        }
    }

    let balance_call = compile_ordinary_call(
        profile,
        BALANCE_CALL,
        "balance.tag",
        balance_frame(statement)?,
        "digest.balance_tag",
        OutputBinding::PublicAlways,
        Some(statement.balance_tag),
    )?;
    calls[BALANCE_CALL] = Some(balance_call);

    let hash_calls = calls
        .into_iter()
        .enumerate()
        .map(|(index, call)| call.ok_or(FullBlake2b448RelationError::Geometry(index)))
        .collect::<Result<Vec<_>, _>>()?;
    let blake_compressions = hash_calls.iter().map(|call| call.trace.cores().0).sum();
    let all_permutations = hash_calls
        .iter()
        .map(|call| call.trace.cores().1)
        .sum::<usize>();
    let sha3_permutations = if profile == SecretHashProfile::SplitSha3_512Truncated448 {
        SPLIT_SHA3_PERMUTATIONS
    } else {
        0
    };
    let shake_permutations = all_permutations - sha3_permutations;
    let scalar_hash_constraints = hash_calls
        .iter()
        .map(|call| call.trace.scalar_constraints())
        .sum();
    let relation = FullBlake2b448Relation {
        profile,
        statement: *statement,
        witness: witness.clone(),
        semantic_certificate,
        statement_bytes,
        public_limbs,
        stablecoin_authority,
        stablecoin_protocol_manifest_view,
        hash_calls,
        stats: MixedRelationStats {
            active_inputs,
            active_outputs,
            physical_hash_calls: PHYSICAL_HASH_CALLS,
            secret_hash_calls: SECRET_HASH_CALLS,
            collision_hash_calls: COLLISION_HASH_CALLS,
            blake_compressions,
            sha3_permutations,
            shake_permutations,
            scalar_hash_constraints,
            public_values: CANDIDATE_STATEMENT_LIMBS,
            production_authorized: FULL_BLAKE2B448_PRODUCTION_AUTHORIZED,
        },
        production_blockers: FULL_BLAKE2B448_PRODUCTION_BLOCKERS.to_vec(),
    };
    relation.verify()?;
    Ok(relation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::full_shake448_relation::{InputWitness, OutputWitness, PrivateAuthWitness};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;

    fn activation() -> V6ActivationBinding {
        V6ActivationBinding {
            circuit_version: 0x4481,
            crypto_suite: 0x4482,
            family_id: 0x4483,
            action_id: 0x4484,
            backend_id: 0x45,
            proof_profile: 0x46,
            domain_set: 0x4487,
            network_id: 7,
            chain_id: [0x11; DIGEST_BYTES],
            genesis_id: [0x22; DIGEST_BYTES],
            rules_hash: [0x33; DIGEST_BYTES],
        }
    }

    fn zero_stablecoin() -> StablecoinStatementBinding384 {
        StablecoinStatementBinding384 {
            enabled: false,
            asset_id: 0,
            policy_version: 0,
            issuance_delta: SignedMagnitude::default(),
            policy_hash: [0; LIVE_STABLECOIN_BINDING_BYTES],
            oracle_commitment: [0; LIVE_STABLECOIN_BINDING_BYTES],
            attestation_commitment: [0; LIVE_STABLECOIN_BINDING_BYTES],
        }
    }

    fn live_policy_entry(asset_id: u32) -> StablecoinPolicyManifestEntry {
        StablecoinPolicyManifestEntry {
            asset_id,
            oracle_feed: 9,
            attestation_id: 11,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: u128::from(V6_MAX_NOTE_VALUE),
            oracle_max_age: 64,
            oracle_submitted_at: 20,
            enabled_at: 10,
            retired_at: Some(100),
            policy_version: 3,
            active: true,
            oracle_commitment: [0xa1; LIVE_STABLECOIN_BINDING_BYTES],
            attestation_commitment: [0xb2; LIVE_STABLECOIN_BINDING_BYTES],
            attestation_disputed: false,
        }
    }

    fn protocol_manifest_with_policies(
        stablecoin_policies: Vec<StablecoinPolicyManifestEntry>,
    ) -> ProtocolManifest {
        let mut manifest = protocol_kernel::manifest::protocol_manifest();
        manifest.stablecoin_policies = stablecoin_policies;
        manifest
    }

    fn install_live_stablecoin_binding(
        statement: &mut FullBlake2b448Statement,
        issuance_delta: SignedMagnitude,
    ) -> StablecoinPolicyManifestEntry {
        let asset_id = u32::try_from(statement.balance_asset_ids[1]).expect("fixture asset");
        let entry = live_policy_entry(asset_id);
        statement.stablecoin = StablecoinStatementBinding384 {
            enabled: true,
            asset_id: u64::from(entry.asset_id),
            policy_version: entry.policy_version,
            issuance_delta,
            policy_hash: live_stablecoin_policy_hash(&entry),
            oracle_commitment: entry.oracle_commitment,
            attestation_commitment: entry.attestation_commitment,
        };
        entry
    }

    fn statement() -> FullBlake2b448Statement {
        FullBlake2b448Statement {
            input_flags: [true, false],
            output_flags: [true, false],
            anchor: [0x44; DIGEST_BYTES],
            nullifiers: [[0x55; DIGEST_BYTES], [0; DIGEST_BYTES]],
            commitments: [[0x66; DIGEST_BYTES], [0; DIGEST_BYTES]],
            ciphertext_hashes: [[0; DIGEST_BYTES], [0; DIGEST_BYTES]],
            ciphertext_sizes: [V6_CANONICAL_CIPHERTEXT_BYTES as u32, 0],
            balance_asset_ids: [NATIVE_ASSET_ID, 7, PADDING_ASSET_ID, PADDING_ASSET_ID],
            fee: 0,
            value_balance: SignedMagnitude::default(),
            stablecoin: zero_stablecoin(),
            balance_tag: [0; DIGEST_BYTES],
            activation: activation(),
        }
    }

    fn zero_witness(mode: PrivateAuthMode) -> FullShake448Witness {
        FullShake448Witness {
            inputs: core::array::from_fn(|_| InputWitness::zero()),
            outputs: core::array::from_fn(|_| OutputWitness::zero()),
            auth: PrivateAuthWitness {
                mode,
                ..PrivateAuthWitness::default()
            },
        }
    }

    fn raw_sourced_frame(bytes: Vec<u8>, symbol: &str) -> SourcedFrame {
        let sources = bytes
            .iter()
            .copied()
            .enumerate()
            .map(|(byte_index, value)| SourceByte {
                kind: SourceKind::PrivateWitness,
                symbol: symbol.to_owned(),
                byte_index,
                value,
            })
            .collect();
        SourcedFrame { bytes, sources }
    }

    fn digest(hex_value: &str) -> Digest448 {
        hex::decode(hex_value)
            .expect("hex KAT")
            .try_into()
            .expect("56-byte KAT")
    }

    fn corpus_secret_digest(profile: SecretHashProfile, frame: &SourcedFrame) -> Digest448 {
        match profile {
            SecretHashProfile::UnkeyedBlake2b448 => {
                blake2b_relation::<BLAKE2B_448_OUTPUT_BYTES>(&frame.bytes)
                    .expect("corpus BLAKE2b frame")
                    .digest()
            }
            SecretHashProfile::SplitSha3_512Truncated448 => sha3_reference(&frame.bytes),
        }
    }

    fn corpus_shake_digest(frame: &SourcedFrame) -> Digest448 {
        let mut state = Shake256::default();
        Update::update(&mut state, &frame.bytes);
        let mut reader = state.finalize_xof();
        let mut output = [0u8; DIGEST_BYTES];
        reader.read(&mut output);
        output
    }

    fn corpus_authorization_digest(
        profile: SecretHashProfile,
        witness: &FullShake448Witness,
        lane: usize,
        slot: usize,
    ) -> Digest448 {
        let selected = witness
            .auth
            .mode
            .selectors()
            .iter()
            .position(|selected| *selected)
            .expect("authorization mode is one hot");
        let arms = authorization_arms(witness, lane, slot).expect("canonical authorization arms");
        corpus_secret_digest(profile, &arms[selected])
    }

    fn corpus_resolved_keys(
        profile: SecretHashProfile,
        witness: &FullShake448Witness,
    ) -> ([Digest448; MAX_INPUTS], [Digest448; MAX_INPUTS]) {
        let spend: [(Digest448, Digest448); MAX_INPUTS] = core::array::from_fn(|input| {
            (
                corpus_secret_digest(
                    profile,
                    &spend_frame(input, 0, &witness.inputs[input].spend_key)
                        .expect("lane-A spend frame"),
                ),
                corpus_secret_digest(
                    profile,
                    &spend_frame(input, 1, &witness.inputs[input].spend_key)
                        .expect("lane-B spend frame"),
                ),
            )
        });
        let auth_a = (
            corpus_authorization_digest(profile, witness, 0, 0),
            corpus_authorization_digest(profile, witness, 1, 0),
        );
        let auth_b = (
            corpus_authorization_digest(profile, witness, 0, 1),
            corpus_authorization_digest(profile, witness, 1, 1),
        );
        match witness.auth.mode {
            PrivateAuthMode::SingleKey
            | PrivateAuthMode::AccumulatorInit
            | PrivateAuthMode::ValueLockCreation => {
                ([spend[0].0, spend[1].0], [spend[0].1, spend[1].1])
            }
            PrivateAuthMode::ApprovalStep => ([auth_a.0, spend[1].0], [auth_a.1, spend[1].1]),
            PrivateAuthMode::FinalThresholdSpend => ([auth_b.0, auth_a.0], [auth_b.1, auth_a.1]),
        }
    }

    fn set_corpus_mode_authorizations(
        profile: SecretHashProfile,
        witness: &mut FullShake448Witness,
    ) {
        let (input_auth, _) = corpus_resolved_keys(profile, witness);
        for (index, input) in witness.inputs.iter_mut().enumerate() {
            if input.active {
                input.note.pk_auth = input_auth[index];
            }
        }
        let output0_auth = match witness.auth.mode {
            PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
                Some(corpus_authorization_digest(profile, witness, 0, 0))
            }
            PrivateAuthMode::ApprovalStep => {
                Some(corpus_authorization_digest(profile, witness, 0, 1))
            }
            PrivateAuthMode::SingleKey | PrivateAuthMode::FinalThresholdSpend => None,
        };
        if let Some(pk_auth) = output0_auth {
            witness.outputs[0].note.pk_auth = pk_auth;
        }
    }

    fn refresh_corpus_public_bindings(
        profile: SecretHashProfile,
        statement: &mut FullBlake2b448Statement,
        witness: &mut FullShake448Witness,
    ) {
        statement.anchor = [0; DIGEST_BYTES];
        statement.nullifiers = [[0; DIGEST_BYTES]; MAX_INPUTS];
        statement.commitments = [[0; DIGEST_BYTES]; MAX_OUTPUTS];
        statement.ciphertext_hashes = [[0; DIGEST_BYTES]; MAX_OUTPUTS];
        for input in &mut witness.inputs {
            input.siblings = [[0; DIGEST_BYTES]; MERKLE_DEPTH];
        }

        for output in 0..MAX_OUTPUTS {
            if witness.outputs[output].active {
                statement.commitments[output] = corpus_secret_digest(
                    profile,
                    &note_frame(
                        &format!("output[{output}].note"),
                        &witness.outputs[output].note,
                    )
                    .expect("output note frame"),
                );
                statement.ciphertext_hashes[output] = corpus_shake_digest(
                    &ciphertext_frame(
                        statement,
                        output,
                        &witness.outputs[output].canonical_ciphertext,
                    )
                    .expect("ciphertext frame"),
                );
            }
        }
        statement.balance_tag =
            corpus_shake_digest(&balance_frame(statement).expect("balance frame"));
        let statement_bytes =
            candidate_statement_bytes(statement, statement.activation).expect("candidate bytes");
        let intent =
            corpus_shake_digest(&intent_frame(&statement_bytes).expect("candidate intent frame"));
        if witness.auth.mode == PrivateAuthMode::FinalThresholdSpend {
            witness.auth.current.intent_digest = intent;
            set_corpus_mode_authorizations(profile, witness);
        }

        let note_commitments: [Digest448; MAX_INPUTS] = core::array::from_fn(|input| {
            corpus_secret_digest(
                profile,
                &note_frame(&format!("input[{input}].note"), &witness.inputs[input].note)
                    .expect("input note frame"),
            )
        });
        if statement.input_flags == [true, true] {
            witness.inputs[0].siblings[0] = note_commitments[1];
            witness.inputs[1].siblings[0] = note_commitments[0];
        }
        let (_, nullifier_keys) = corpus_resolved_keys(profile, witness);
        for input in 0..MAX_INPUTS {
            if !witness.inputs[input].active {
                continue;
            }
            statement.nullifiers[input] = corpus_secret_digest(
                profile,
                &nullifier_frame(
                    input,
                    &nullifier_keys[input],
                    witness.inputs[input].position,
                    &witness.inputs[input].note.rho,
                )
                .expect("nullifier frame"),
            );
            let mut current = note_commitments[input];
            for level in 0..MERKLE_DEPTH {
                current = corpus_shake_digest(
                    &merkle_frame(
                        input,
                        level,
                        &current,
                        &witness.inputs[input].siblings[level],
                        (witness.inputs[input].position >> level) & 1 == 0,
                    )
                    .expect("Merkle frame"),
                );
            }
            if statement.anchor == [0; DIGEST_BYTES] {
                statement.anchor = current;
            } else {
                assert_eq!(statement.anchor, current, "two-input Merkle roots");
            }
        }
    }

    fn corpus_note(seed: u8, kind: NoteKind) -> NoteOpening {
        NoteOpening {
            kind,
            value: 0,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed; 32],
            rho: [seed.wrapping_add(1); 48],
            randomness: [seed.wrapping_add(2); 48],
            pk_auth: [0; DIGEST_BYTES],
        }
    }

    fn build_corpus_fixture(
        profile: SecretHashProfile,
        mode: PrivateAuthMode,
        mask: u8,
    ) -> (FullBlake2b448Statement, FullShake448Witness) {
        let input_flags = [mask & 1 != 0, mask & 2 != 0];
        let output_flags = [mask & 4 != 0, mask & 8 != 0];
        assert!(mask != 0);
        validate_authorization_activity_shape(mode, input_flags, output_flags)
            .expect("corpus activity shape");
        let mut witness = FullShake448Witness {
            inputs: core::array::from_fn(|input| {
                if !input_flags[input] {
                    return InputWitness::zero();
                }
                InputWitness {
                    active: true,
                    spend_key: [0x30 + input as u8; SPEND_KEY_BYTES],
                    note: corpus_note(0x40 + input as u8, NoteKind::Ordinary),
                    position: input as u64,
                    siblings: [[0; DIGEST_BYTES]; MERKLE_DEPTH],
                    balance_slot_selectors: [true, false, false, false],
                }
            }),
            outputs: core::array::from_fn(|output| {
                if !output_flags[output] {
                    return OutputWitness::zero();
                }
                OutputWitness {
                    active: true,
                    note: corpus_note(0x50 + output as u8, NoteKind::Ordinary),
                    balance_slot_selectors: [true, false, false, false],
                    canonical_ciphertext: [0x60 + output as u8; V6_CANONICAL_CIPHERTEXT_BYTES],
                }
            }),
            auth: PrivateAuthWitness {
                mode,
                ..PrivateAuthWitness::default()
            },
        };

        match mode {
            PrivateAuthMode::SingleKey => {}
            PrivateAuthMode::AccumulatorInit => {
                witness.outputs[0].note.kind = NoteKind::Accumulator;
                witness.auth.next = AccumulatorOpening {
                    policy_root: [0; DIGEST_BYTES],
                    intent_digest: [0; DIGEST_BYTES],
                    threshold: 1,
                    signer_count: 1,
                    approval_count: 0,
                    approved_slots: [false; MAX_SIGNERS],
                };
            }
            PrivateAuthMode::ApprovalStep => {
                witness.inputs[0].note.kind = NoteKind::Accumulator;
                witness.inputs[0].spend_key = [0; SPEND_KEY_BYTES];
                witness.outputs[0].note.kind = NoteKind::Accumulator;
                witness.auth.signer_tags[0] = corpus_secret_digest(
                    profile,
                    &spend_frame(1, 0, &witness.inputs[1].spend_key)
                        .expect("approval signer spend frame"),
                );
                witness.auth.current = AccumulatorOpening {
                    policy_root: [0; DIGEST_BYTES],
                    intent_digest: [0; DIGEST_BYTES],
                    threshold: 1,
                    signer_count: 1,
                    approval_count: 0,
                    approved_slots: [false; MAX_SIGNERS],
                };
                witness.auth.next = witness.auth.current.clone();
                witness.auth.next.approval_count = 1;
                witness.auth.next.approved_slots[0] = true;
            }
            PrivateAuthMode::ValueLockCreation => {
                witness.outputs[0].note.kind = NoteKind::ValueLock;
                witness.auth.current = AccumulatorOpening {
                    policy_root: [0; DIGEST_BYTES],
                    intent_digest: [0; DIGEST_BYTES],
                    threshold: 1,
                    signer_count: 1,
                    approval_count: 0,
                    approved_slots: [false; MAX_SIGNERS],
                };
            }
            PrivateAuthMode::FinalThresholdSpend => {
                witness.inputs[0].note.kind = NoteKind::ValueLock;
                witness.inputs[1].note.kind = NoteKind::Accumulator;
                witness.inputs[0].spend_key = [0; SPEND_KEY_BYTES];
                witness.inputs[1].spend_key = [0; SPEND_KEY_BYTES];
                witness.auth.current = AccumulatorOpening {
                    policy_root: [0; DIGEST_BYTES],
                    intent_digest: [0; DIGEST_BYTES],
                    threshold: 1,
                    signer_count: 1,
                    approval_count: 1,
                    approved_slots: [true, false, false, false, false, false],
                };
            }
        }

        if mode != PrivateAuthMode::SingleKey {
            let selected = if mode == PrivateAuthMode::AccumulatorInit {
                &witness.auth.next
            } else {
                &witness.auth.current
            };
            let policy_root = corpus_secret_digest(
                profile,
                &policy_frame(selected, &witness.auth.signer_tags).expect("policy frame"),
            );
            if mode == PrivateAuthMode::AccumulatorInit {
                witness.auth.next.policy_root = policy_root;
            } else {
                witness.auth.current.policy_root = policy_root;
                if mode == PrivateAuthMode::ApprovalStep {
                    witness.auth.next.policy_root = policy_root;
                }
            }
        }
        set_corpus_mode_authorizations(profile, &mut witness);

        let mut statement = FullBlake2b448Statement {
            input_flags,
            output_flags,
            anchor: [0; DIGEST_BYTES],
            nullifiers: [[0; DIGEST_BYTES]; MAX_INPUTS],
            commitments: [[0; DIGEST_BYTES]; MAX_OUTPUTS],
            ciphertext_hashes: [[0; DIGEST_BYTES]; MAX_OUTPUTS],
            ciphertext_sizes: output_flags.map(|active| {
                if active {
                    V6_CANONICAL_CIPHERTEXT_BYTES as u32
                } else {
                    0
                }
            }),
            balance_asset_ids: [
                NATIVE_ASSET_ID,
                PADDING_ASSET_ID,
                PADDING_ASSET_ID,
                PADDING_ASSET_ID,
            ],
            fee: 0,
            value_balance: SignedMagnitude::default(),
            stablecoin: zero_stablecoin(),
            balance_tag: [0; DIGEST_BYTES],
            activation: activation(),
        };
        refresh_corpus_public_bindings(profile, &mut statement, &mut witness);
        (statement, witness)
    }

    fn compile_corpus_fixture(
        profile: SecretHashProfile,
        statement: &FullBlake2b448Statement,
        witness: &FullShake448Witness,
    ) -> FullBlake2b448Relation {
        let relation = if statement.stablecoin.enabled {
            let entry = live_policy_entry(
                u32::try_from(statement.stablecoin.asset_id).expect("fixture asset"),
            );
            let manifest = protocol_manifest_with_policies(vec![entry]);
            compile_full_blake2b448_candidate_with_stablecoin_protocol_manifest(
                profile,
                statement,
                witness,
                statement.activation,
                20,
                &manifest,
            )
        } else {
            compile_full_blake2b448_candidate(profile, statement, witness, statement.activation)
        }
        .expect("honest scalar corpus fixture");
        relation.verify().expect("local hash-trace verifier");
        assert_eq!(relation.hash_calls.len(), PHYSICAL_HASH_CALLS);
        relation
    }

    #[test]
    fn registry_schedule_and_no_winner_are_exact() {
        validate_mixed_hash_registry().unwrap();
        let report = profile_tournament_report();
        assert_eq!(report.winner, None);
        assert_eq!(report.blake.physical_calls, 83);
        assert_eq!(report.blake.blake_compressions, 28);
        assert_eq!(report.blake.shake_permutations, 105);
        assert_eq!(report.blake.raw_native_nonlinear_words, 79_128);
        assert_eq!(report.blake.blake_rotation_linear_words, 10_752);
        assert_eq!(report.split_sha3.physical_calls, 83);
        assert_eq!(report.split_sha3.sha3_permutations, 46);
        assert_eq!(report.split_sha3.shake_permutations, 105);
        assert_eq!(report.split_sha3.raw_native_nonlinear_words, 90_600);
        assert_eq!(
            report.split_sha3.raw_native_nonlinear_words - report.blake.raw_native_nonlinear_words,
            11_472
        );
        assert_eq!(
            report.blake.fixed_mux_scalar_constraints,
            Some(BLAKE_AUTH_MUX_SCALAR_CONSTRAINTS)
        );
        assert_eq!(
            report.split_sha3.fixed_mux_scalar_constraints,
            Some(SPLIT_SHA3_AUTH_MUX_SCALAR_CONSTRAINTS)
        );
        assert_eq!(
            MIXED_HASH_REGISTRY
                .iter()
                .map(|role| role.calls)
                .sum::<usize>(),
            PHYSICAL_HASH_CALLS
        );
    }

    #[test]
    fn fresh_statement_codec_round_trips_and_rejects_every_historical_identity() {
        let statement = statement();
        let encoded = candidate_statement_bytes(&statement, activation()).unwrap();
        assert_eq!(&encoded[..8], &CANDIDATE_STATEMENT_MAGIC);
        assert_eq!(
            decode_candidate_statement_bytes(&encoded, activation()).unwrap(),
            statement
        );
        let limbs = candidate_statement_limbs(&encoded);
        let mut reconstructed = [0u8; CANDIDATE_STATEMENT_BYTES];
        for (index, limb) in limbs.into_iter().enumerate() {
            let offset = index * CANDIDATE_STATEMENT_LIMB_BYTES;
            let take = (CANDIDATE_STATEMENT_BYTES - offset).min(CANDIDATE_STATEMENT_LIMB_BYTES);
            reconstructed[offset..offset + take].copy_from_slice(&limb.to_le_bytes()[..take]);
        }
        assert_eq!(reconstructed, encoded);
        for historical in [
            *b"HGF6ST02",
            *b"HGF6HR02",
            *b"HGR6RM02",
            *b"HGV6PB02",
            RETIRED_DIAGNOSTIC_STATEMENT_MAGIC,
        ] {
            let mut rejected = encoded;
            rejected[..8].copy_from_slice(&historical);
            assert_eq!(
                decode_candidate_statement_bytes(&rejected, activation()),
                Err(FullBlake2b448RelationError::HistoricalIdentityReuse)
            );
        }
    }

    #[test]
    fn canonical_frames_freeze_lengths_roles_lanes_and_typed_sources() {
        let statement = statement();
        let encoded = candidate_statement_bytes(&statement, activation()).unwrap();
        let note = NoteOpening::zero();
        let note = note_frame("note", &note).unwrap();
        assert_eq!(note.bytes.len(), 232);
        assert_eq!(&note.bytes[..8], &CANDIDATE_PROFILE_TAG);
        assert_eq!(&note.bytes[8..16], &ROLE_NOTE);
        assert!(note
            .bytes
            .iter()
            .zip(&note.sources)
            .all(|(byte, source)| *byte == source.value));

        let spend_a = spend_frame(0, 0, &[0; SPEND_KEY_BYTES]).unwrap();
        let spend_b = spend_frame(0, 1, &[0; SPEND_KEY_BYTES]).unwrap();
        assert_eq!((spend_a.bytes.len(), spend_b.bytes.len()), (77, 77));
        assert_ne!(spend_a.bytes, spend_b.bytes);
        assert_eq!(&spend_a.bytes[8..16], &ROLE_SPEND_A);
        assert_eq!(&spend_b.bytes[8..16], &ROLE_SPEND_B);

        let nullifier = nullifier_frame(0, &[0; DIGEST_BYTES], 0, &[0; 48]).unwrap();
        assert_eq!(nullifier.bytes.len(), 135);
        let merkle_left = merkle_frame(0, 0, &[1; DIGEST_BYTES], &[2; DIGEST_BYTES], true).unwrap();
        let merkle_right =
            merkle_frame(0, 0, &[1; DIGEST_BYTES], &[2; DIGEST_BYTES], false).unwrap();
        assert_eq!(
            (merkle_left.bytes.len(), merkle_right.bytes.len()),
            (133, 133)
        );
        assert_ne!(merkle_left.bytes, merkle_right.bytes);
        assert!(merkle_left
            .sources
            .iter()
            .any(|source| source.kind == SourceKind::PrivateWitness
                && source.symbol == "input[0].siblings[0]"));
        assert!(merkle_left
            .sources
            .iter()
            .any(|source| source.kind == SourceKind::InternalDigest
                && source.symbol == "digest.note.input[0]"));

        let policy = policy_frame(
            &AccumulatorOpening::zero(),
            &[[0; DIGEST_BYTES]; MAX_SIGNERS],
        )
        .unwrap();
        assert_eq!(policy.bytes.len(), 385);
        let witness = zero_witness(PrivateAuthMode::SingleKey);
        for lane in 0..2 {
            for slot in 0..2 {
                let arms = authorization_arms(&witness, lane, slot).unwrap();
                let expected = if slot == 0 {
                    [136, 181, 181, 143, 181]
                } else {
                    [136, 136, 181, 136, 143]
                };
                assert_eq!(arms.each_ref().map(|arm| arm.bytes.len()), expected);
                let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
                assert!(arms.iter().all(|arm| arm.bytes[8..16] == role));
                let blake = fixed_blake2b_authorization_trace(
                    PrivateAuthMode::SingleKey.selectors(),
                    &arms,
                )
                .unwrap();
                let sha3 =
                    fixed_sha3_authorization_trace(PrivateAuthMode::SingleKey.selectors(), &arms)
                        .unwrap();
                eprintln!(
                    "canonical_auth_mux lane={lane} slot={slot} blake={} sha3={}",
                    blake.constraints.len(),
                    sha3.constraints.len()
                );
            }
        }
        assert_eq!(intent_frame(&encoded).unwrap().bytes.len(), 720);
        assert_eq!(balance_frame(&statement).unwrap().bytes.len(), 100);
        assert_eq!(
            ciphertext_frame(&statement, 0, &[0; V6_CANONICAL_CIPHERTEXT_BYTES])
                .unwrap()
                .bytes
                .len(),
            2_182
        );
    }

    #[test]
    fn rfc7693_blake2b448_kats_cover_block_boundaries() {
        for (message, expected) in [
            (
                Vec::new(),
                "e7d2cb731e704ab61a3fa0ddd3bb3a6bfe3c3bc03b2c80a7545a0c9cedb575dfaa6821be9879e9ecd24350297f14470ad3d1cd2d19f27fbf",
            ),
            (
                b"abc".to_vec(),
                "13ee23af59cf24b95795d6417d2592f96d772eb6c4866e51698ecf6d4848539251ae2ee731a28758ecbcd5cb5f3f005c202f509cc32975b1",
            ),
            (
                (0..127).map(|i| i as u8).collect(),
                "9f9715ce3ddf0dca587aca554c1c550f6285992131eb36cf7e413d09df7898a32b516b011ffb7f75b0bd86147d843c0837597f4f853f5acf",
            ),
            (
                (0..128).map(|i| i as u8).collect(),
                "e86ac9582179a9ac3f19f7d83fcf52c996a15b4007143efa2e2985a9fc800b1c12331a670d8a7335a687de08caae1a0112befc6f6090e975",
            ),
            (
                (0..129).map(|i| (i % 256) as u8).collect(),
                "c2be04a246b254a9c297675857e5ff8225965227b95583c7f691b8a61ef848f4694f9c68e803bb04763ed858d648b00ec703690dcec121fe",
            ),
        ] {
            let trace = blake2b_relation::<BLAKE2B_448_OUTPUT_BYTES>(&message).unwrap();
            trace.verify_constraints().unwrap();
            assert_eq!(trace.digest(), digest(expected));
        }
    }

    #[test]
    fn fips202_sha3_512_truncated448_kats_cover_block_boundaries() {
        for (message, expected) in [
            (
                Vec::new(),
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e3",
            ),
            (
                b"abc".to_vec(),
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5",
            ),
            (
                (0..127).map(|i| i as u8).collect(),
                "73bb20ba4987e427db00b5d42e431b3a37232f41ca4d29591758f26e73788a3b3468eacc9415f4bce5ba6aecda14750080ede3f0d1017727",
            ),
            (
                (0..128).map(|i| i as u8).collect(),
                "989c1995da9d2d341f993c2e2ca695f3477075061bfbd2cdf0be75cf7ba99fbe33d8d2c4dcc31fa89917786b883e6c9d5b02ed81b7483a4c",
            ),
            (
                (0..129).map(|i| (i % 256) as u8).collect(),
                "4d8f28ea5211c66a28b6a0f98b34b45e9c51ca6759193ff52d10ee579d64441d9b240a40c3660f39af600a9fd15f137c635ed13494fc26a5",
            ),
        ] {
            let trace = sha3_512_trace(&raw_sourced_frame(message, "kat.message")).unwrap();
            trace.verify().unwrap();
            assert_eq!(trace.digest, digest(expected));
        }
    }

    #[test]
    fn fixed_five_arm_muxes_bind_all_sources_and_detect_mutations() {
        let arms = core::array::from_fn(|arm| {
            let bytes = (0..129)
                .map(|index| ((index + arm) % 256) as u8)
                .collect::<Vec<_>>();
            raw_sourced_frame(bytes, &format!("arm[{arm}]"))
        });
        let selectors = [true, false, false, false, false];
        let blake = fixed_blake2b_authorization_trace(selectors, &arms).unwrap();
        assert_eq!((blake.compression_count, blake.permutation_count), (2, 0));
        assert_eq!(
            blake.digest,
            digest(
                "c2be04a246b254a9c297675857e5ff8225965227b95583c7f691b8a61ef848f4694f9c68e803bb04763ed858d648b00ec703690dcec121fe"
            )
        );
        assert_eq!(blake.source_bindings.len(), 5 * 129 * 8);
        let mut bad_source = blake.clone();
        let source_wire = bad_source.source_bindings[0].wire.index();
        bad_source.witness[source_wire] ^= 1;
        assert!(bad_source.verify().is_err());
        let mut bad_digest = blake.clone();
        bad_digest.digest[0] ^= 1;
        assert!(bad_digest.verify().is_err());

        let sha3 = fixed_sha3_authorization_trace(selectors, &arms).unwrap();
        assert_eq!((sha3.compression_count, sha3.permutation_count), (0, 3));
        assert_eq!(
            sha3.digest,
            digest(
                "4d8f28ea5211c66a28b6a0f98b34b45e9c51ca6759193ff52d10ee579d64441d9b240a40c3660f39af600a9fd15f137c635ed13494fc26a5"
            )
        );
        assert_eq!(sha3.source_bindings.len(), 5 * 129 * 8);
        let mut bad_mux = sha3.clone();
        let selector_wire = match bad_mux
            .constraints
            .iter()
            .find_map(|constraint| match constraint {
                CandidateBoolConstraint::OneHot5 { selectors } => Some(selectors[0]),
                _ => None,
            }) {
            Some(wire) => wire,
            None => panic!("fixed mux one-hot constraint"),
        };
        bad_mux.witness[selector_wire.index()] = 0;
        assert!(bad_mux.verify().is_err());
        eprintln!(
            "fixed_mux_scalar_constraints blake={} sha3={}",
            blake.constraints.len(),
            sha3.constraints.len()
        );
    }

    #[test]
    fn activity_shape_helper_enumerates_all_masks_and_modes() {
        let modes = [
            PrivateAuthMode::SingleKey,
            PrivateAuthMode::AccumulatorInit,
            PrivateAuthMode::ApprovalStep,
            PrivateAuthMode::ValueLockCreation,
            PrivateAuthMode::FinalThresholdSpend,
        ];
        let mut accepted = 0usize;
        for mask in 0u8..16 {
            let inputs = [mask & 1 != 0, mask & 2 != 0];
            let outputs = [mask & 4 != 0, mask & 8 != 0];
            for mode in modes {
                let expected_shape = mask != 0
                    && match mode {
                        PrivateAuthMode::SingleKey => true,
                        PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
                            inputs.into_iter().any(|active| active) && outputs[0]
                        }
                        PrivateAuthMode::ApprovalStep => inputs == [true, true] && outputs[0],
                        PrivateAuthMode::FinalThresholdSpend => inputs == [true, true],
                    };
                assert_eq!(
                    validate_authorization_activity_shape(mode, inputs, outputs).is_ok(),
                    expected_shape,
                    "mask={mask:04b} mode={mode:?}"
                );
                accepted += usize::from(expected_shape);
            }
        }
        assert_eq!(accepted, 33);
    }

    #[test]
    #[ignore = "requires the repository disk gate; materializes 66 mask/mode plus edge 83-call traces"]
    fn disk_gated_full_scalar_mask_mode_edge_and_mutation_corpus() {
        assert!(
            matches!(
                std::env::var("HEGEMON_RUN_FULL_BLAKE2B448_SCALAR_CORPUS").as_deref(),
                Ok("1")
            ),
            "set the explicit corpus gate only after the repository disk threshold passes"
        );
        let profiles = [
            SecretHashProfile::UnkeyedBlake2b448,
            SecretHashProfile::SplitSha3_512Truncated448,
        ];
        let modes = [
            PrivateAuthMode::SingleKey,
            PrivateAuthMode::AccumulatorInit,
            PrivateAuthMode::ApprovalStep,
            PrivateAuthMode::ValueLockCreation,
            PrivateAuthMode::FinalThresholdSpend,
        ];
        let mut valid_mask_mode_cases = 0usize;
        for profile in profiles {
            for mask in 1u8..16 {
                let input_flags = [mask & 1 != 0, mask & 2 != 0];
                let output_flags = [mask & 4 != 0, mask & 8 != 0];
                for mode in modes {
                    if validate_authorization_activity_shape(mode, input_flags, output_flags)
                        .is_err()
                    {
                        continue;
                    }
                    let (statement, witness) = build_corpus_fixture(profile, mode, mask);
                    compile_corpus_fixture(profile, &statement, &witness);
                    valid_mask_mode_cases += 1;
                }
            }
        }
        assert_eq!(valid_mask_mode_cases, 66);

        for profile in profiles {
            // Native zero, positive, and negative signed-value-balance equations.
            let (mut zero, mut zero_case_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            zero_case_witness.inputs[0].note.value = 3;
            zero_case_witness.outputs[0].note.value = 2;
            zero.fee = 1;
            refresh_corpus_public_bindings(profile, &mut zero, &mut zero_case_witness);
            compile_corpus_fixture(profile, &zero, &zero_case_witness);

            let (mut positive, mut positive_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            positive_witness.inputs[0].note.value = 1;
            positive_witness.outputs[0].note.value = 2;
            positive.fee = 1;
            positive.value_balance = SignedMagnitude {
                negative: false,
                magnitude: 2,
            };
            refresh_corpus_public_bindings(profile, &mut positive, &mut positive_witness);
            compile_corpus_fixture(profile, &positive, &positive_witness);

            let (mut negative, mut negative_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            negative_witness.inputs[0].note.value = 5;
            negative_witness.outputs[0].note.value = 2;
            negative.fee = 1;
            negative.value_balance = SignedMagnitude {
                negative: true,
                magnitude: 2,
            };
            refresh_corpus_public_bindings(profile, &mut negative, &mut negative_witness);
            compile_corpus_fixture(profile, &negative, &negative_witness);

            // Output-only native mint and input-only native burn are both live shapes.
            let (mut mint, mut mint_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0100);
            mint_witness.outputs[0].note.value = V6_MAX_NOTE_VALUE;
            mint.value_balance = SignedMagnitude {
                negative: false,
                magnitude: V6_MAX_NOTE_VALUE,
            };
            refresh_corpus_public_bindings(profile, &mut mint, &mut mint_witness);
            compile_corpus_fixture(profile, &mint, &mint_witness);

            let (mut burn, mut burn_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0001);
            burn_witness.inputs[0].note.value = V6_MAX_NOTE_VALUE;
            burn.value_balance = SignedMagnitude {
                negative: true,
                magnitude: V6_MAX_NOTE_VALUE,
            };
            refresh_corpus_public_bindings(profile, &mut burn, &mut burn_witness);
            compile_corpus_fixture(profile, &burn, &burn_witness);

            // Ordinary non-native transfer conserves the asset without invoking
            // the live mint/burn exception.
            let (mut stable_ordinary, mut stable_ordinary_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            stable_ordinary.balance_asset_ids =
                [NATIVE_ASSET_ID, 7, PADDING_ASSET_ID, PADDING_ASSET_ID];
            stable_ordinary_witness.inputs[0].note.asset_id = 7;
            stable_ordinary_witness.inputs[0].note.value = 9;
            stable_ordinary_witness.inputs[0].balance_slot_selectors = [false, true, false, false];
            stable_ordinary_witness.outputs[0].note.asset_id = 7;
            stable_ordinary_witness.outputs[0].note.value = 9;
            stable_ordinary_witness.outputs[0].balance_slot_selectors = [false, true, false, false];
            refresh_corpus_public_bindings(
                profile,
                &mut stable_ordinary,
                &mut stable_ordinary_witness,
            );
            compile_corpus_fixture(profile, &stable_ordinary, &stable_ordinary_witness);

            // Live authorization rejects zero issuance before any hash work.
            let (mut stable_zero, mut stable_zero_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            stable_zero.balance_asset_ids =
                [NATIVE_ASSET_ID, 7, PADDING_ASSET_ID, PADDING_ASSET_ID];
            let stable_zero_entry =
                install_live_stablecoin_binding(&mut stable_zero, SignedMagnitude::default());
            let stable_zero_manifest = protocol_manifest_with_policies(vec![stable_zero_entry]);
            refresh_corpus_public_bindings(profile, &mut stable_zero, &mut stable_zero_witness);
            assert!(matches!(
                compile_full_blake2b448_candidate_with_stablecoin_protocol_manifest(
                    profile,
                    &stable_zero,
                    &stable_zero_witness,
                    stable_zero.activation,
                    20,
                    &stable_zero_manifest,
                ),
                Err(FullBlake2b448RelationError::LiveStablecoinPolicy(
                    LiveStablecoinPolicyRejection::IssuanceZero
                ))
            ));

            // Stablecoin mint/burn use the exact signed issuance equation.
            let (mut stable_mint, mut stable_mint_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0100);
            stable_mint.balance_asset_ids =
                [NATIVE_ASSET_ID, 7, PADDING_ASSET_ID, PADDING_ASSET_ID];
            stable_mint_witness.outputs[0].note.asset_id = 7;
            stable_mint_witness.outputs[0].note.value = V6_MAX_NOTE_VALUE;
            stable_mint_witness.outputs[0].balance_slot_selectors = [false, true, false, false];
            install_live_stablecoin_binding(
                &mut stable_mint,
                SignedMagnitude {
                    negative: true,
                    magnitude: V6_MAX_NOTE_VALUE,
                },
            );
            refresh_corpus_public_bindings(profile, &mut stable_mint, &mut stable_mint_witness);
            compile_corpus_fixture(profile, &stable_mint, &stable_mint_witness);

            let (mut stable_burn, mut stable_burn_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0001);
            stable_burn.balance_asset_ids =
                [NATIVE_ASSET_ID, 7, PADDING_ASSET_ID, PADDING_ASSET_ID];
            stable_burn_witness.inputs[0].note.asset_id = 7;
            stable_burn_witness.inputs[0].note.value = V6_MAX_NOTE_VALUE;
            stable_burn_witness.inputs[0].balance_slot_selectors = [false, true, false, false];
            install_live_stablecoin_binding(
                &mut stable_burn,
                SignedMagnitude {
                    negative: false,
                    magnitude: V6_MAX_NOTE_VALUE,
                },
            );
            refresh_corpus_public_bindings(profile, &mut stable_burn, &mut stable_burn_witness);
            compile_corpus_fixture(profile, &stable_burn, &stable_burn_witness);

            // Negative-zero, range, conservation, disabled-binding, and padding mutations.
            let mut negative_zero = zero;
            negative_zero.value_balance = SignedMagnitude {
                negative: true,
                magnitude: 0,
            };
            assert!(compile_full_blake2b448_candidate(
                profile,
                &negative_zero,
                &zero_case_witness,
                negative_zero.activation,
            )
            .is_err());

            let mut overrange_witness = zero_case_witness.clone();
            overrange_witness.inputs[0].note.value = V6_MAX_NOTE_VALUE + 1;
            assert!(compile_full_blake2b448_candidate(
                profile,
                &zero,
                &overrange_witness,
                zero.activation,
            )
            .is_err());

            let mut imbalance = positive;
            imbalance.value_balance.magnitude -= 1;
            refresh_corpus_public_bindings(profile, &mut imbalance, &mut positive_witness);
            assert!(compile_full_blake2b448_candidate(
                profile,
                &imbalance,
                &positive_witness,
                imbalance.activation,
            )
            .is_err());

            let mut disabled_nonzero = zero;
            disabled_nonzero.stablecoin.policy_hash[0] = 1;
            assert!(compile_full_blake2b448_candidate(
                profile,
                &disabled_nonzero,
                &zero_case_witness,
                disabled_nonzero.activation,
            )
            .is_err());

            let mut inactive_nonzero = zero_case_witness.clone();
            inactive_nonzero.inputs[1].spend_key[0] = 1;
            assert!(compile_full_blake2b448_candidate(
                profile,
                &zero,
                &inactive_nonzero,
                zero.activation,
            )
            .is_err());

            let mut empty_statement = zero;
            empty_statement.input_flags = [false; MAX_INPUTS];
            empty_statement.output_flags = [false; MAX_OUTPUTS];
            empty_statement.nullifiers = [[0; DIGEST_BYTES]; MAX_INPUTS];
            empty_statement.commitments = [[0; DIGEST_BYTES]; MAX_OUTPUTS];
            empty_statement.ciphertext_hashes = [[0; DIGEST_BYTES]; MAX_OUTPUTS];
            empty_statement.ciphertext_sizes = [0; MAX_OUTPUTS];
            let empty_witness = zero_witness(PrivateAuthMode::SingleKey);
            assert!(matches!(
                compile_full_blake2b448_candidate(
                    profile,
                    &empty_statement,
                    &empty_witness,
                    empty_statement.activation,
                ),
                Err(FullBlake2b448RelationError::Shape(
                    "all-empty activity mask"
                ))
            ));

            let (retained_statement, retained_witness) =
                build_corpus_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            let mut retained =
                compile_corpus_fixture(profile, &retained_statement, &retained_witness);
            retained.statement_bytes[0] ^= 1;
            assert!(matches!(
                retained.verify(),
                Err(FullBlake2b448RelationError::SemanticCertificate)
            ));
            retained.statement_bytes[0] ^= 1;
            retained.hash_calls[0].name.push_str(".mutated");
            assert!(matches!(
                retained.verify(),
                Err(FullBlake2b448RelationError::CallSpec(0))
            ));
        }
    }

    #[test]
    fn composed_admission_and_protocol_manifest_view_fail_closed() {
        let mut statement = statement();
        assert!(validate_composed_admission_preconditions(&statement).is_ok());
        statement.nullifiers[0] = [0; DIGEST_BYTES];
        assert!(matches!(
            validate_composed_admission_preconditions(&statement),
            Err(FullBlake2b448RelationError::AdmissionPrecondition(_))
        ));
        statement.nullifiers[0] = [1; DIGEST_BYTES];
        statement.commitments[0] = [1; DIGEST_BYTES];
        statement.ciphertext_hashes[0] = [0; DIGEST_BYTES];
        assert!(validate_composed_admission_preconditions(&statement).is_ok());

        let entry = install_live_stablecoin_binding(
            &mut statement,
            SignedMagnitude {
                negative: true,
                magnitude: 1,
            },
        );
        let authority = StablecoinAuthority::try_from_statement(&statement).unwrap();
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, None),
            Err(LiveStablecoinPolicyRejection::PolicyMissing)
        );
        let view = StablecoinProtocolManifestView {
            current_height: 20,
            manifest: protocol_manifest_with_policies(vec![entry.clone()]),
        };
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&view)),
            Ok(())
        );
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(StablecoinAuthority::Disabled, Some(&view),),
            Ok(())
        );

        let StablecoinAuthority::Enabled {
            asset_id,
            policy_version,
            issuance_delta,
            policy_hash,
            oracle_commitment,
            attestation_commitment,
        } = authority
        else {
            panic!("fixture stablecoin authority must be enabled")
        };
        let enabled_authority =
            |asset_id,
             policy_version,
             policy_hash,
             oracle_commitment,
             attestation_commitment,
             issuance_delta| StablecoinAuthority::Enabled {
                asset_id,
                policy_version,
                issuance_delta,
                policy_hash,
                oracle_commitment,
                attestation_commitment,
            };
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(
                enabled_authority(
                    asset_id + 1,
                    policy_version,
                    policy_hash,
                    oracle_commitment,
                    attestation_commitment,
                    issuance_delta,
                ),
                Some(&view),
            ),
            Err(LiveStablecoinPolicyRejection::AssetMismatch)
        );
        let mut wrong_policy_hash = policy_hash;
        wrong_policy_hash[0] ^= 1;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(
                enabled_authority(
                    asset_id,
                    policy_version,
                    wrong_policy_hash,
                    oracle_commitment,
                    attestation_commitment,
                    issuance_delta,
                ),
                Some(&view),
            ),
            Err(LiveStablecoinPolicyRejection::PolicyHashMismatch)
        );
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(
                enabled_authority(
                    asset_id,
                    policy_version + 1,
                    policy_hash,
                    oracle_commitment,
                    attestation_commitment,
                    issuance_delta,
                ),
                Some(&view),
            ),
            Err(LiveStablecoinPolicyRejection::PolicyVersionMismatch)
        );
        let mut wrong_oracle = oracle_commitment;
        wrong_oracle[0] ^= 1;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(
                enabled_authority(
                    asset_id,
                    policy_version,
                    policy_hash,
                    wrong_oracle,
                    attestation_commitment,
                    issuance_delta,
                ),
                Some(&view),
            ),
            Err(LiveStablecoinPolicyRejection::OracleCommitmentMismatch)
        );
        let mut wrong_attestation = attestation_commitment;
        wrong_attestation[0] ^= 1;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(
                enabled_authority(
                    asset_id,
                    policy_version,
                    policy_hash,
                    oracle_commitment,
                    wrong_attestation,
                    issuance_delta,
                ),
                Some(&view),
            ),
            Err(LiveStablecoinPolicyRejection::AttestationCommitmentMismatch)
        );
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(
                enabled_authority(
                    asset_id,
                    policy_version,
                    policy_hash,
                    oracle_commitment,
                    attestation_commitment,
                    SignedMagnitude::default(),
                ),
                Some(&view),
            ),
            Err(LiveStablecoinPolicyRejection::IssuanceZero)
        );

        let no_plausible_view = StablecoinProtocolManifestView {
            current_height: 20,
            manifest: protocol_manifest_with_policies(vec![live_policy_entry(8)]),
        };
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&no_plausible_view)),
            Err(LiveStablecoinPolicyRejection::PolicyMissing)
        );
        let mut rejected_first = entry.clone();
        rejected_first.active = false;
        let existential_view = StablecoinProtocolManifestView {
            current_height: 20,
            manifest: protocol_manifest_with_policies(vec![rejected_first, entry.clone()]),
        };
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&existential_view)),
            Ok(()),
            "native admission accepts when any plausible manifest member passes"
        );

        let mut inactive = view.clone();
        inactive.manifest.stablecoin_policies[0].active = false;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&inactive)),
            Err(LiveStablecoinPolicyRejection::PolicyInactive)
        );
        let mut retired = view.clone();
        retired.current_height = 100;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&retired)),
            Err(LiveStablecoinPolicyRejection::PolicyNotLive)
        );
        let mut before_enabled = view.clone();
        before_enabled.current_height = 9;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&before_enabled)),
            Err(LiveStablecoinPolicyRejection::PolicyNotLive)
        );
        let mut future_oracle = view.clone();
        future_oracle.manifest.stablecoin_policies[0].oracle_submitted_at = 21;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&future_oracle)),
            Err(LiveStablecoinPolicyRejection::OracleStale)
        );
        let mut stale_oracle = view.clone();
        stale_oracle.current_height = 85;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&stale_oracle)),
            Err(LiveStablecoinPolicyRejection::OracleStale)
        );
        let mut disputed = view.clone();
        disputed.manifest.stablecoin_policies[0].attestation_disputed = true;
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(authority, Some(&disputed)),
            Err(LiveStablecoinPolicyRejection::AttestationDisputed)
        );
        let mut capped = view.clone();
        capped.manifest.stablecoin_policies[0].max_mint_per_epoch = 1;
        let capped_entry = &capped.manifest.stablecoin_policies[0];
        let capped_hash = live_stablecoin_policy_hash(capped_entry);
        let over_limit = StablecoinAuthority::Enabled {
            asset_id: u64::from(capped_entry.asset_id),
            policy_version: capped_entry.policy_version,
            issuance_delta: SignedMagnitude {
                negative: true,
                magnitude: V6_MAX_NOTE_VALUE,
            },
            policy_hash: capped_hash,
            oracle_commitment: capped_entry.oracle_commitment,
            attestation_commitment: capped_entry.attestation_commitment,
        };
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(over_limit, Some(&capped)),
            Err(LiveStablecoinPolicyRejection::IssuanceOverLimit)
        );

        let manifest_commitment = protocol_kernel::stablecoin_manifest_commitment_v1::
            protocol_manifest_stablecoin_state_commitment_v1(&view.manifest)
            .unwrap();
        let state = stablecoin_consensus_state_seam_from_protocol_manifest(
            authority,
            Some(&view),
            manifest_commitment,
            manifest_commitment,
        )
        .unwrap();
        assert_eq!(state.entry_index, 0);
        assert_eq!(
            validate_stablecoin_consensus_state_seam(authority, &state),
            Ok(())
        );
        let mut wrong_root = state.clone();
        let mut wrong_root_bytes = wrong_root
            .provided_manifest_state_commitment_v1
            .into_bytes();
        wrong_root_bytes[0] ^= 1;
        wrong_root.provided_manifest_state_commitment_v1 =
            StablecoinManifestStateCommitmentV1::new(wrong_root_bytes);
        assert_eq!(
            validate_stablecoin_consensus_state_seam(authority, &wrong_root),
            Err(StablecoinConsensusStateSeamRejection::ManifestStateCommitmentMismatch)
        );
        let mut wrong_height = state.clone();
        wrong_height.provided_current_height ^= 1;
        assert_eq!(
            validate_stablecoin_consensus_state_seam(authority, &wrong_height),
            Err(StablecoinConsensusStateSeamRejection::CurrentHeightMismatch)
        );
        assert_eq!(
            validate_stablecoin_consensus_state_seam(
                StablecoinAuthority::Disabled,
                &StablecoinConsensusStateSeam::disabled(),
            ),
            Ok(())
        );
        assert_eq!(
            validate_stablecoin_consensus_state_seam(StablecoinAuthority::Disabled, &state,),
            Err(StablecoinConsensusStateSeamRejection::DisabledStateNotCanonical)
        );
        assert!(validate_accumulator(
            &AccumulatorOpening {
                policy_root: [0; DIGEST_BYTES],
                intent_digest: [0; DIGEST_BYTES],
                threshold: 1,
                signer_count: 1,
                approval_count: 0,
                approved_slots: [false; MAX_SIGNERS],
            },
            &[[0; DIGEST_BYTES]; MAX_SIGNERS],
            [0; DIGEST_BYTES],
            None,
        )
        .is_ok());
    }

    #[test]
    fn live_policy_tuple_and_native_blake2b384_kat_are_exact() {
        let source_manifest = protocol_kernel::manifest::protocol_manifest();
        let entry = source_manifest
            .stablecoin_policies
            .first()
            .cloned()
            .expect("default stablecoin policy entry");
        assert_eq!(CANDIDATE_STATEMENT_BYTES, 869);
        assert_eq!(CANDIDATE_STATEMENT_LIMBS, 125);
        assert_eq!(OFFSET_STABLE_ORACLE - OFFSET_STABLE_POLICY, 48);
        assert_eq!(OFFSET_STABLE_ATTESTATION - OFFSET_STABLE_ORACLE, 48);
        assert_eq!(OFFSET_BALANCE_TAG - OFFSET_STABLE_ATTESTATION, 48);
        assert_eq!(
            hex::encode(live_stablecoin_policy_tuple_scale_bytes(&entry)),
            "e903000001000000010000000000000060e3160000000000000000000000000000ca9a3b000000000000000000000000ffffffffffffffff0100000000"
        );
        assert_eq!(
            hex::encode(live_stablecoin_policy_hash(&entry)),
            "4e36d2e5728b9b3a1eb473aac318800434bf3947817410a281d04e8ea6b68ed133bc48c3570db5c3935126aa76be2100"
        );
        assert_eq!(live_stablecoin_policy_hash(&entry), entry.policy_hash());
        assert!(!entry.active);
        assert_eq!(entry.retired_at, Some(0));
        let current_source_authority = StablecoinAuthority::Enabled {
            asset_id: u64::from(entry.asset_id),
            policy_version: entry.policy_version,
            issuance_delta: SignedMagnitude {
                negative: true,
                magnitude: 1,
            },
            policy_hash: live_stablecoin_policy_hash(&entry),
            oracle_commitment: entry.oracle_commitment,
            attestation_commitment: entry.attestation_commitment,
        };
        assert_eq!(
            validate_stablecoin_protocol_manifest_view(
                current_source_authority,
                Some(&StablecoinProtocolManifestView {
                    current_height: 0,
                    manifest: source_manifest,
                }),
            ),
            Err(LiveStablecoinPolicyRejection::PolicyInactive),
            "the current source manifest has no live stablecoin authorization"
        );
    }

    #[test]
    fn production_and_identity_allocation_remain_fail_closed() {
        assert_eq!(profile_tournament_report().winner, None);
        assert!(!FULL_BLAKE2B448_AGGREGATE_CONSTRAINT_RELATION_COMPILED);
        assert!(!FULL_BLAKE2B448_PRODUCTION_AUTHORIZED);
        assert!(!FULL_BLAKE2B448_STRICT_STABLECOIN_PQ_MARGIN);
        assert_eq!(
            ensure_full_blake2b448_relation_production_authorized(),
            Err(FullBlake2b448RelationError::ProductionAuthorizationUnavailable)
        );
        assert_ne!(CANDIDATE_STATEMENT_MAGIC, *b"HGF6ST02");
        assert_ne!(CANDIDATE_PROFILE_TAG, *b"HGF6HR02");
        assert_ne!(
            CANDIDATE_STATEMENT_MAGIC,
            RETIRED_DIAGNOSTIC_STATEMENT_MAGIC
        );
    }
}
