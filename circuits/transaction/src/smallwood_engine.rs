use std::cell::{Cell, RefCell};
use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use blake3::Hasher;
use getrandom::fill as getrandom_fill;
use hegemon_field::Goldilocks;
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha512};
use transaction_core::poseidon2::poseidon2_permutation;
use transaction_core::poseidon2::Felt;

use crate::{
    error::TransactionCircuitError,
    smallwood_hx512_transcript::{
        Hx512DeferredVerifierTranscript, Hx512Error, Hx512Transcript,
        HX512_PROFILE_LEAF_TAPE_BYTES, HX512_SALT_BYTES,
    },
    smallwood_semantics::{
        SmallwoodConstraintAdapter, SmallwoodLinearConstraintForm, SmallwoodNonlinearEvalView,
    },
    smallwood_v6_transcript::{
        Sha512V6, Sha512V6BindingPreamble, Sha512V6Error, Sha512V6Role,
        SHA512_V6_SMZ2_DECS_DOMAIN_SIZE, SHA512_V6_SMZ2_MAX_PIOP_NONCE_TRIALS,
        SHA512_V6_SMZ2_PACKING_FACTOR, SHA512_V6_SMZ2_PIOP_OPENING_COUNT,
    },
};

const FIELD_ORDER: u64 = 0xffff_ffff_0000_0001;
const NEG_ORDER: u64 = FIELD_ORDER.wrapping_neg();
const GOLDILOCKS_TWO_ADIC_ROOT: u64 = 0x1856_29dc_da58_878c;
const GOLDILOCKS_TWO_ADICITY: u32 = 32;
pub const DIGEST_BYTES: usize = 64;
pub const SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES: usize = 64;
pub const SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1: usize = 23;
pub const SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1: usize =
    SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1 * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES;
/// Fresh V8 Poseidon2 relation profile.  The count is part of the SMZ8 wire
/// grammar rather than a caller-selected proof dimension.
pub const SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT: usize = 19;
pub const SMALLWOOD_POSEIDON2_V8_DECS_OPENED_TAPE_BYTES: usize =
    SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES;
/// Exact maximum accepted compact Merkle surface for nineteen distinct leaves
/// in the depth-23 V8 tree.  The split-DP projector below recomputes and checks
/// this protocol constant rather than trusting independent full paths.
pub const SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES: usize = 355;
pub const SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTH_PATH_BYTES: usize = 2
    + SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT
    + SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES * DIGEST_BYTES;
/// Fresh successor proof profile.  SMZ9 is additive: the q=19/open=5 SMZ8
/// grammar above remains decodable only under its historical profile.
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT: usize = 20;
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_TAPE_BYTES: usize =
    SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES;
/// Exact split-DP maximum for twenty distinct leaves in a depth-23 tree.
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES: usize = 372;
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTH_PATH_BYTES: usize = 2
    + SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT
    + SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES * DIGEST_BYTES;
/// Inactive compact profile-7 commitment width. Every request computes a
/// complete SHA-512 digest; only the first seven 64-bit words are committed to
/// the proof wire and recursively absorbed by commitment roles.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES: usize = 56;
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_DECS_OPENED_LEAF_COUNT: usize = 19;
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_DECS_OPENED_TAPE_BYTES: usize =
    SMALLWOOD_POSEIDON2_V8_COMPACT448_DECS_OPENED_LEAF_COUNT
        * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES;
/// Exact split-DP maximum for nineteen distinct leaves in a depth-23 tree.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_COMPACT_AUTHENTICATION_NODES: usize = 355;
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_COMPACT_AUTH_PATH_BYTES: usize = 2
    + SMALLWOOD_POSEIDON2_V8_COMPACT448_DECS_OPENED_LEAF_COUNT
    + SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_COMPACT_AUTHENTICATION_NODES
        * SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES;
/// Exact maximum canonical inner encoding projected from HGV8RP03. The SMC7
/// parser checks this borrowed-input length before allocating payload fields.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES: usize = 117_702;
/// Inactive q=20/profile-8 sibling. It preserves the active SMZ9 sampling
/// tuple while observing seven words of every complete SHA-512 commitment.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_DECS_OPENED_LEAF_COUNT: usize = 20;
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_DECS_OPENED_TAPE_BYTES: usize =
    SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_DECS_OPENED_LEAF_COUNT
        * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES;
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_COMPACT_AUTHENTICATION_NODES: usize = 372;
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_COMPACT_AUTH_PATH_BYTES: usize = 2
    + SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_DECS_OPENED_LEAF_COUNT
    + SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_COMPACT_AUTHENTICATION_NODES
        * SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES;
/// Exact HGV8RP03 source ceiling for the inactive q=20/448-bit SMC8 wire.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES: usize = 119_879;
/// Consensus proof-leaf ceiling.  The SMZ8 decoder checks this borrowed input
/// length immediately after reading the four-byte identity, before allocating
/// any matrix, authentication path, tape, or opened-witness vector.
pub const SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES: usize = 131_072;
/// Maximum field-word request accepted by the historical SHA-512 transcript
/// sampler.  The active request surface is far smaller; this explicit ceiling
/// keeps the rejection-tail calculation finite and prevents attacker-selected
/// dimensions from turning one transcript request into unbounded work.
pub const SMALLWOOD_SHA512_FIELD_XOF_MAX_OUTPUT_WORDS_V1: usize = 1 << 24;
/// The capped sampler makes at least this many additional 64-bit candidates
/// available beyond the requested accepted words.  Digest blocks contain eight
/// candidates, so alignment can only increase the actual slack.
pub const SMALLWOOD_SHA512_FIELD_XOF_EXTRA_CANDIDATE_WORDS_V1: usize = 32;
const SMALLWOOD_SHA512_FIELD_XOF_WORDS_PER_DIGEST_V1: usize = DIGEST_BYTES / 8;
/// Wire width of a V3 commitment after computing the complete SHA-512 digest
/// and observing its first 48 bytes. This is not the SHA-512/384 algorithm.
pub const SMALLWOOD_FULL_SHA512_FIRST48_COMMITMENT_BYTES_V3: usize = 48;
const LEGACY_DIGEST_BYTES: usize = 32;
const LEGACY_DIGEST_WORDS: usize = LEGACY_DIGEST_BYTES / 8;
const DIGEST_WORDS: usize = DIGEST_BYTES / 8;
const SALT_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 4;

const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";
const SMALLWOOD_COMPRESS2_DOMAIN: &[u8] = b"hegemon.smallwood.f64-compress2.v1";
const SMALLWOOD_LEVEL5_FIXED_DECS_DOMAIN: &[u8] = b"hegemon.smallwood.level5.decs-fixed-sampling";
pub const SMALLWOOD_LEVEL5_FIXED_DECS_CANDIDATE_COUNT: usize = 50;
const SMALLWOOD_POSEIDON2_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.poseidon2-xof.v1";
const SMALLWOOD_POSEIDON2_COMPRESS2_DOMAIN: &[u8] = b"hegemon.smallwood.poseidon2-compress2.v1";
const SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN: &[u8] = b"hegemon.smallwood.level5.piop-input";
const SMALLWOOD_LEVEL5_PIOP_TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.smallwood.level5.piop-transcript";
const SMALLWOOD_LEVEL5_DECS_OPENING_DOMAIN: &[u8] = b"hegemon.smallwood.level5.decs-opening";
const SMALLWOOD_LEVEL5_MERKLE_LEAF_DOMAIN: &[u8] = b"hegemon.smallwood.level5.merkle-leaf";
const SMALLWOOD_STRICT_ZK_MERKLE_LEAF_DOMAIN_V1: &[u8] =
    b"hegemon.smallwood.strict-zk.merkle-leaf.v1";
/// Every conventional SHA-512 request in the V8 proof absorbs this profile
/// frame before its role-specific domain.  This keeps the role grammar while
/// preventing any V8 request from aliasing historical Level-5, V3, or V6
/// transcript bytes.
pub const SMALLWOOD_POSEIDON2_V8_SHA512_PROFILE_DOMAIN: &[u8] =
    b"hegemon.smallwood.poseidon2-v8.sha512.profile.v1";
/// Fresh SHA-512 profile frame for the q=20/open=6 SMZ9 successor.  Keeping a
/// distinct frame makes transcript separation independent of outer parsing.
pub const SMALLWOOD_POSEIDON2_V8_SMZ9_SHA512_PROFILE_DOMAIN: &[u8] =
    b"hegemon.smallwood.poseidon2-v8.smz9.sha512.profile.v1";
/// Inactive profile-7 domain for the q=19, six-opening, 448-bit observed
/// commitment candidate. It cannot alias either SMZ8 or SMZ9 requests.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_SHA512_PROFILE_DOMAIN: &[u8] =
    b"hegemon.smallwood.poseidon2-v8.smc7.sha512-448.profile.v1";
/// Inactive profile-8 domain for the q=20, six-opening, 448-bit observed
/// commitment candidate. It cannot alias SMZ9 or SMC7 requests.
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_SHA512_PROFILE_DOMAIN: &[u8] =
    b"hegemon.smallwood.poseidon2-v8.smc8.sha512-448.profile.v1";
const SMALLWOOD_LEVEL5_MERKLE_NODE_DOMAIN: &[u8] = b"hegemon.smallwood.level5.merkle-node";
const SMALLWOOD_LEVEL5_MERKLE_ROOT_DOMAIN: &[u8] = b"hegemon.smallwood.level5.merkle-root";
const SMALLWOOD_LEVEL5_DECS_COEFFICIENT_DOMAIN: &[u8] =
    b"hegemon.smallwood.level5.decs-coefficient";
const SMALLWOOD_LEVEL5_PIOP_COEFFICIENT_DOMAIN: &[u8] =
    b"hegemon.smallwood.level5.piop-coefficient";
const SMALLWOOD_LEVEL5_PIOP_OPENING_DOMAIN: &[u8] = b"hegemon.smallwood.level5.piop-opening";
const SMALLWOOD_LEVEL5_DECS_QUERY_DOMAIN: &[u8] = b"hegemon.smallwood.level5.decs-query";
/// Extra domain frame prepended to every SHA-512 request in the additive V3
/// prototype. Role domains below remain present, so transcript and Merkle
/// calls cannot alias one another or the active Level-5 profile.
pub const SMALLWOOD_FULL_SHA512_FIRST48_PROFILE_DOMAIN_V3: &[u8] =
    b"hegemon.smallwood.full-sha512-first48-commitment.v3";
pub const SMALLWOOD_LEVEL5_MAX_PIOP_NONCE_TRIALS: u32 = 16;
pub const SMALLWOOD_LEVEL5_MAX_DECS_NONCE_TRIALS: u32 = 1;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodNoGrindingProfileV1 {
    pub rho: usize,
    pub nb_opened_evals: usize,
    pub beta: usize,
    pub opening_pow_bits: u32,
    pub decs_nb_evals: usize,
    pub decs_nb_opened_evals: usize,
    pub decs_eta: usize,
    pub decs_pow_bits: u32,
}

pub const LEGACY_SMALLWOOD_NO_GRINDING_PROFILE_V1: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 2,
        nb_opened_evals: 3,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 32768,
        decs_nb_opened_evals: 25,
        decs_eta: 3,
        decs_pow_bits: 0,
    };

const HISTORICAL_SMALLWOOD_V3_NO_GRINDING_PROFILE_V1: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 3,
        nb_opened_evals: 3,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 32768,
        decs_nb_opened_evals: 24,
        decs_eta: 3,
        decs_pow_bits: 0,
    };

pub const ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 5,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 1_048_576,
        decs_nb_opened_evals: 23,
        decs_eta: 5,
        decs_pow_bits: 0,
    };

pub const LEVEL5_SMALLWOOD_NO_GRINDING_PROFILE: SmallwoodNoGrindingProfileV1 =
    ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1;

/// Repaired compact testnet profile.  Keep the measured Level-5 geometry and
/// eta=5 wire size while changing the leaking DECS domain and leaf commitment
/// under the distinct SMZ1 selector.  This profile is deliberately not the
/// production 260-bit/QROM attestation; that gate remains fail-closed.
pub const STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE: SmallwoodNoGrindingProfileV1 =
    ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1;

/// Fresh compact V8 security tuple.  This is not an authorization flag.  The
/// larger 2^23 DECS domain permits nineteen openings while retaining the
/// selected interactive/CMS margin and reducing the proof payload.
pub const POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 5,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 1 << 23,
        decs_nb_opened_evals: SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT,
        decs_eta: 5,
        decs_pow_bits: 0,
    };

/// Fresh compact V8 successor tuple.  It is carried only by SMZ9/profile 6;
/// no SMZ8 byte string is reinterpreted under these parameters.
pub const POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 6,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 1 << 23,
        decs_nb_opened_evals: SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT,
        decs_eta: 5,
        decs_pow_bits: 0,
    };

/// Inactive compact profile-7 tuple. This is a measurement candidate, not a
/// security claim or production selector. The complete composed theorem must
/// decide whether nineteen DECS queries retain the required margin.
pub const POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 6,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 1 << 23,
        decs_nb_opened_evals: SMALLWOOD_POSEIDON2_V8_COMPACT448_DECS_OPENED_LEAF_COUNT,
        decs_eta: 5,
        decs_pow_bits: 0,
    };

/// Inactive profile-8 tuple. It keeps the q=20/open=6 SMZ9 sampling geometry
/// and changes only the transcript/wire commitment observation to 56 bytes.
pub const POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 6,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 1 << 23,
        decs_nb_opened_evals: SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_DECS_OPENED_LEAF_COUNT,
        decs_eta: 5,
        decs_pow_bits: 0,
    };

/// Prospective, inactive HX512 profile.  The six PIOP openings are part of the
/// polynomial-hiding dimension and must not be reduced to the historical
/// five-opening Level-5 profile.  The 48 DECS queries remain provisional until
/// the composed QROM certificate and final adapter row count are frozen.
pub const HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 5,
        nb_opened_evals: 6,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 1_048_576,
        decs_nb_opened_evals: 48,
        decs_eta: 5,
        decs_pow_bits: 0,
    };
pub const HX512_SMALLWOOD_PACKING_FACTOR_V1: usize = 1_024;
pub const HX512_SMALLWOOD_MAX_CONSTRAINT_DEGREE_V1: usize = 6;
pub const HX512_SMALLWOOD_WITNESS_POLYNOMIAL_DEGREE_V1: usize = 1_029;
pub const HX512_SMALLWOOD_MPOL_POLYNOMIAL_DEGREE_V1: usize = 5_150;
pub const HX512_SMALLWOOD_LINEAR_POLYNOMIAL_DEGREE_V1: usize = 2_052;
pub const HX512_SMALLWOOD_FIELD_RNG_EXTRA_CANDIDATES_V1: usize = 256;
pub const HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodHx512RngBudgetV1 {
    pub accepted_field_words: usize,
    pub accepted_field_bytes: usize,
    pub field_candidate_limit: usize,
    pub maximum_field_candidate_bytes: usize,
    pub field_rejection_budget: usize,
    pub field_request_count: usize,
    pub minimum_field_rng_calls: usize,
    pub maximum_field_rng_calls: usize,
    pub decs_leaf_tape_count: usize,
    pub decs_leaf_tape_bytes_each: usize,
    pub decs_leaf_tape_bytes_total: usize,
    pub decs_leaf_tape_rng_calls: usize,
    pub global_salt_bytes: usize,
    pub global_salt_rng_calls: usize,
    pub minimum_total_getrandom_fill_calls: usize,
    pub maximum_total_getrandom_fill_calls: usize,
    pub minimum_total_getrandom_fill_bytes: usize,
    pub maximum_total_getrandom_fill_bytes: usize,
    pub internal_outer_retry_count: usize,
    pub salt_collision_entropy_bits: u16,
    pub salt_reuse_registry_authority: bool,
    pub getrandom_fill_failure_is_fatal: bool,
}

const HISTORICAL_SMALLWOOD_V2_NO_GRINDING_PROFILE_V1: SmallwoodNoGrindingProfileV1 =
    SmallwoodNoGrindingProfileV1 {
        rho: 2,
        nb_opened_evals: 3,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 32768,
        decs_nb_opened_evals: 23,
        decs_eta: 3,
        decs_pow_bits: 0,
    };

pub const SMALLWOOD_RHO: usize = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.rho;
pub const SMALLWOOD_NB_OPENED_EVALS: usize =
    ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.nb_opened_evals;
pub const SMALLWOOD_BETA: usize = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.beta;
pub const SMALLWOOD_DECS_NB_EVALS: usize = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals;
pub const SMALLWOOD_DECS_NB_OPENED_EVALS: usize =
    ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals;
pub const SMALLWOOD_DECS_POW_BITS: u32 = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_pow_bits;
// This is an allocation/parser ceiling, not an accepted-profile selector. The
// verifier still enforces the exact active or explicitly supplied profile shape.
// Keep enough bounded headroom for offline security-profile evaluation without
// changing the canonical u16 wire format.
const MAX_SMALLWOOD_COMPACT_COLLECTION_ROWS_V1: usize = 96;
const SMALLWOOD_POSEIDON2_RATE: usize = 6;
static CONSECUTIVE_LAGRANGE_BASIS_CACHE: OnceLock<Mutex<BTreeMap<usize, Arc<Vec<Vec<u64>>>>>> =
    OnceLock::new();
static CONSECUTIVE_BARYCENTRIC_WEIGHT_CACHE: OnceLock<Mutex<BTreeMap<usize, Arc<Vec<u64>>>>> =
    OnceLock::new();
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmallwoodArithmetization {
    Bridge64V1,
    DirectPacked64V1,
    DirectPacked64CompactBindingsV1,
    DirectPacked128CompactBindingsV1,
    DirectPacked16CompactBindingsV1,
    DirectPacked32CompactBindingsV1,
    DirectPacked64CompactBindingsSkipInitialMdsV1,
    DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
    DirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1,
    DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2,
    DirectPacked64CompressedLevel5,
    DirectPacked128CompressedLevel5,
    /// Non-active V3 prototype: full SHA-512 requests and field-XOF blocks,
    /// with commitment digests serialized as the first 48 output bytes.
    DirectPacked64CompressedLevel5FullSha512First48CommitmentV3,
    /// Inactive V6 selector. Its fresh-domain SHA-512 backend and `SMZ2` wire
    /// must never be routed through the historical Level-5 transcript.
    DirectPacked64CompressedV6Sha512Smz2,
    /// Fresh inactive HX512 profile. This selector has a distinct inner wire,
    /// 64-byte outer-owned salt, 72-byte tapes, and exact eight-stage
    /// transcript. It is never interpreted as SMZ1/SMZ2.
    DirectRadix4Packed1024Hx512Candidate,
    /// Surgical testnet repair of the compact Level-5 relation.  The relation,
    /// packing, profile, and SHA-512 transcript are unchanged; only the DECS
    /// evaluation domain and leaf commitment use the strict SMZ1 construction.
    /// Appending this variant preserves every historical bincode discriminant.
    DirectPacked64CompressedLevel5StrictZkSmz1,
    /// Fresh V8 compact Poseidon2 relation with a conventional, independently
    /// domain-separated SHA-512 transcript and the SMZ8 strict-ZK wire.  This
    /// appended selector never reinterprets historical arithmetization bytes.
    DirectPacked64Poseidon2V8Sha512Smz8,
    /// Additive q=20/open=6 successor for the same V8 relation.  Appending the
    /// selector preserves every historical bincode discriminant, including
    /// the q=19/open=5 SMZ8 candidate.
    DirectPacked64Poseidon2V8Sha512Smz9,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmallwoodDecsChallengeFormat {
    ScalarPowers,
    Uniform,
}

/// The theorem used for the first DECS soundness term.
///
/// This records which probability model was actually applied.  It is an
/// interactive-protocol calculation, not a production security rating: hash
/// instantiation, Fiat--Shamir, verifier refinement, relation refinement, and
/// zero knowledge are accounted for by separate fail-closed gates.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmallwoodDecsSoundnessModelV1 {
    /// Historical scalar-power coefficients retain the union over candidate
    /// bad supports.
    ScalarPowerSupportUnion,
    /// The committed rows determine one bad support before the verifier
    /// samples every coefficient of the independent uniform matrix.
    UniformMatrixCommittedSupport,
}

fn decs_challenge_format_for_arithmetization(
    arithmetization: SmallwoodArithmetization,
) -> SmallwoodDecsChallengeFormat {
    if matches!(
        arithmetization,
        SmallwoodArithmetization::DirectPacked64CompressedLevel5
            | SmallwoodArithmetization::DirectPacked128CompressedLevel5
            | SmallwoodArithmetization::DirectPacked64CompressedLevel5FullSha512First48CommitmentV3
            | SmallwoodArithmetization::DirectPacked64CompressedV6Sha512Smz2
            | SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1
            | SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz8
            | SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
            | SmallwoodArithmetization::DirectRadix4Packed1024Hx512Candidate
    ) {
        SmallwoodDecsChallengeFormat::Uniform
    } else {
        SmallwoodDecsChallengeFormat::ScalarPowers
    }
}

pub fn smallwood_no_grinding_profile_for_arithmetization(
    arithmetization: SmallwoodArithmetization,
) -> SmallwoodNoGrindingProfileV1 {
    match arithmetization {
        SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1 => {
            HISTORICAL_SMALLWOOD_V2_NO_GRINDING_PROFILE_V1
        }
        SmallwoodArithmetization::DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2 => {
            HISTORICAL_SMALLWOOD_V3_NO_GRINDING_PROFILE_V1
        }
        SmallwoodArithmetization::DirectPacked64CompressedLevel5
        | SmallwoodArithmetization::DirectPacked128CompressedLevel5
        | SmallwoodArithmetization::DirectPacked64CompressedLevel5FullSha512First48CommitmentV3
        | SmallwoodArithmetization::DirectPacked64CompressedV6Sha512Smz2 => {
            LEVEL5_SMALLWOOD_NO_GRINDING_PROFILE
        }
        SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1 => {
            STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE
        }
        SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz8 => {
            POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE
        }
        SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9 => {
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE
        }
        SmallwoodArithmetization::DirectRadix4Packed1024Hx512Candidate => {
            HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1
        }
        SmallwoodArithmetization::Bridge64V1
        | SmallwoodArithmetization::DirectPacked64V1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked128CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked16CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked32CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1
        | SmallwoodArithmetization::DirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1 => {
            LEGACY_SMALLWOOD_NO_GRINDING_PROFILE_V1
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodTranscriptBackend {
    Blake3,
    Poseidon2,
    Sha512Level5,
    /// Inactive fresh-domain V6 SHA-512 selector. Generic transcript dispatch
    /// rejects it until the dedicated backend is bound; it is not Level-5.
    Sha512V6,
    /// Complete SHA-512 is evaluated for every request. Only fixed digest
    /// commitments are observed/serialized as the first 48 bytes; field-XOF
    /// output continues to use complete SHA-512 counter blocks.
    FullSha512First48CommitmentV3,
    /// Fresh exact eight-stage HX512 transcript. Entry requires a scoped
    /// typestate session installed by `smallwood_hx512_engine`.
    Hx512Candidate,
    /// Conventional SHA-512 transcript for the V8 Poseidon2 relation.  Every
    /// request receives the fresh V8 profile frame in addition to its role
    /// domain; no historical Level-5 proof can be replayed under this backend.
    Sha512Poseidon2V8,
    /// Fresh SHA-512 transcript identity for the V8 SMZ9/profile-6 successor.
    /// Its appended discriminant and profile domain cannot alias SMZ8.
    Sha512Poseidon2V8Smz9,
    /// Inactive profile-7 transcript. Every hash invocation executes complete
    /// SHA-512, commitment roles observe 56 bytes, and field-XOF roles consume
    /// complete 64-byte blocks.
    Sha512Poseidon2V8Compact448Smc7,
    /// Inactive profile-8 sibling: complete SHA-512, 56 observed commitment
    /// bytes, and the unchanged q=20 SMZ9 sampling tuple.
    Sha512Poseidon2V8Compact448Q20Smc8,
}

impl SmallwoodTranscriptBackend {
    fn digest_bytes(self) -> usize {
        match self {
            Self::Blake3 | Self::Poseidon2 => LEGACY_DIGEST_BYTES,
            Self::Sha512Level5
            | Self::Sha512V6
            | Self::Hx512Candidate
            | Self::Sha512Poseidon2V8
            | Self::Sha512Poseidon2V8Smz9 => DIGEST_BYTES,
            Self::Sha512Poseidon2V8Compact448Smc7 | Self::Sha512Poseidon2V8Compact448Q20Smc8 => {
                SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES
            }
            Self::FullSha512First48CommitmentV3 => {
                SMALLWOOD_FULL_SHA512_FIRST48_COMMITMENT_BYTES_V3
            }
        }
    }

    fn digest_words(self) -> usize {
        self.digest_bytes() / std::mem::size_of::<u64>()
    }

    fn is_sha512_level5(self) -> bool {
        matches!(
            self,
            Self::Sha512Level5
                | Self::FullSha512First48CommitmentV3
                | Self::Sha512Poseidon2V8
                | Self::Sha512Poseidon2V8Smz9
                | Self::Sha512Poseidon2V8Compact448Smc7
                | Self::Sha512Poseidon2V8Compact448Q20Smc8
        )
    }

    fn observes_truncated_sha512_commitment(self) -> bool {
        matches!(
            self,
            Self::FullSha512First48CommitmentV3
                | Self::Sha512Poseidon2V8Compact448Smc7
                | Self::Sha512Poseidon2V8Compact448Q20Smc8
        )
    }

    fn sha512_profile_domain(self) -> Option<&'static [u8]> {
        match self {
            Self::FullSha512First48CommitmentV3 => {
                Some(SMALLWOOD_FULL_SHA512_FIRST48_PROFILE_DOMAIN_V3)
            }
            Self::Sha512Poseidon2V8 => Some(SMALLWOOD_POSEIDON2_V8_SHA512_PROFILE_DOMAIN),
            Self::Sha512Poseidon2V8Smz9 => Some(SMALLWOOD_POSEIDON2_V8_SMZ9_SHA512_PROFILE_DOMAIN),
            Self::Sha512Poseidon2V8Compact448Smc7 => {
                Some(SMALLWOOD_POSEIDON2_V8_COMPACT448_SHA512_PROFILE_DOMAIN)
            }
            Self::Sha512Poseidon2V8Compact448Q20Smc8 => {
                Some(SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_SHA512_PROFILE_DOMAIN)
            }
            _ => None,
        }
    }
}

// The V6 preamble is a statement-owned object, not a process-wide constant.
// Keep it scoped to the dedicated V6 prover/verifier entrypoint so the legacy
// generic APIs cannot silently manufacture a transcript without the exact
// `HGV6PB02` binding.  V6 Merkle requests run sequentially below because the
// worker threads used by the legacy fast path cannot inherit a statement
// binding context safely.
thread_local! {
    static SMALLWOOD_V6_TRANSCRIPT_CONTEXT_V1: RefCell<Option<Sha512V6>> = const { RefCell::new(None) };
}

struct SmallwoodV6TranscriptContextGuard {
    previous: Option<Sha512V6>,
}

impl Drop for SmallwoodV6TranscriptContextGuard {
    fn drop(&mut self) {
        SMALLWOOD_V6_TRANSCRIPT_CONTEXT_V1.with(|slot| {
            let _ = slot.replace(self.previous.take());
        });
    }
}

fn enter_smallwood_v6_transcript_context(
    preamble: Sha512V6BindingPreamble,
) -> Result<SmallwoodV6TranscriptContextGuard, TransactionCircuitError> {
    let backend = Sha512V6::new(preamble).map_err(smallwood_v6_error)?;
    let previous = SMALLWOOD_V6_TRANSCRIPT_CONTEXT_V1.with(|slot| slot.replace(Some(backend)));
    Ok(SmallwoodV6TranscriptContextGuard { previous })
}

fn with_smallwood_v6_transcript<R>(
    f: impl FnOnce(&Sha512V6) -> R,
) -> Result<R, TransactionCircuitError> {
    SMALLWOOD_V6_TRANSCRIPT_CONTEXT_V1.with(|slot| {
        let context = slot.borrow();
        context
            .as_ref()
            .map(f)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood Sha512V6 requires an exact binding-preamble context",
            ))
    })
}

fn smallwood_v6_error(error: Sha512V6Error) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolationOwned(format!(
        "smallwood Sha512V6 transcript contract: {error}"
    ))
}

fn v6_role_for_engine_domain(domain: &[u8]) -> Option<Sha512V6Role> {
    let candidates = [
        (SMALLWOOD_XOF_DOMAIN, Sha512V6Role::FieldXof),
        (SMALLWOOD_COMPRESS2_DOMAIN, Sha512V6Role::Compress2),
        (SMALLWOOD_LEVEL5_FIXED_DECS_DOMAIN, Sha512V6Role::DecsQuery),
        (SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN, Sha512V6Role::PiopInput),
        (
            SMALLWOOD_LEVEL5_PIOP_TRANSCRIPT_DOMAIN,
            Sha512V6Role::PiopTranscript,
        ),
        (
            SMALLWOOD_LEVEL5_DECS_OPENING_DOMAIN,
            Sha512V6Role::DecsOpening,
        ),
        (
            SMALLWOOD_LEVEL5_MERKLE_LEAF_DOMAIN,
            Sha512V6Role::MerkleLeaf,
        ),
        (
            SMALLWOOD_STRICT_ZK_MERKLE_LEAF_DOMAIN_V1,
            Sha512V6Role::MerkleLeaf,
        ),
        (
            SMALLWOOD_LEVEL5_MERKLE_NODE_DOMAIN,
            Sha512V6Role::MerkleNode,
        ),
        (
            SMALLWOOD_LEVEL5_MERKLE_ROOT_DOMAIN,
            Sha512V6Role::MerkleRoot,
        ),
        (
            SMALLWOOD_LEVEL5_DECS_COEFFICIENT_DOMAIN,
            Sha512V6Role::DecsCoefficient,
        ),
        (
            SMALLWOOD_LEVEL5_PIOP_COEFFICIENT_DOMAIN,
            Sha512V6Role::PiopCoefficient,
        ),
        (
            SMALLWOOD_LEVEL5_PIOP_OPENING_DOMAIN,
            Sha512V6Role::PiopOpening,
        ),
        (SMALLWOOD_LEVEL5_DECS_QUERY_DOMAIN, Sha512V6Role::DecsQuery),
    ];
    candidates
        .into_iter()
        .find_map(|(candidate, role)| (domain == candidate).then_some(role))
        .or_else(|| {
            Sha512V6Role::ALL
                .into_iter()
                .find(|role| domain == role.domain())
        })
}

fn v6_domain_for_engine_domain(domain: &'static [u8]) -> &'static [u8] {
    v6_role_for_engine_domain(domain)
        .map(Sha512V6Role::domain)
        .unwrap_or_else(|| panic!("unregistered Smallwood V6 transcript domain"))
}

fn transcript_domain(
    backend: SmallwoodTranscriptBackend,
    level5_domain: &'static [u8],
) -> &'static [u8] {
    match backend {
        SmallwoodTranscriptBackend::Sha512V6 => v6_domain_for_engine_domain(level5_domain),
        backend if backend.is_sha512_level5() => level5_domain,
        _ => SMALLWOOD_XOF_DOMAIN,
    }
}

fn ensure_transcript_backend_dispatch_available(
    backend: SmallwoodTranscriptBackend,
) -> Result<(), TransactionCircuitError> {
    if backend == SmallwoodTranscriptBackend::Sha512V6 {
        return with_smallwood_v6_transcript(|_| ()).map(|_| ());
    }
    if backend == SmallwoodTranscriptBackend::Hx512Candidate {
        return with_smallwood_hx512_transcript_driver(|_| ()).map(|_| ());
    }
    Ok(())
}

fn smallwood_hx512_error(error: Hx512Error) -> TransactionCircuitError {
    TransactionCircuitError::ConstraintViolationOwned(format!(
        "smallwood HX512 transcript contract: {error}"
    ))
}

struct SmallwoodHx512RngSessionV1 {
    expected_field_request_sizes: VecDeque<usize>,
    remaining_field_candidates: usize,
    expected_tape_batch_bytes: VecDeque<usize>,
    budget: SmallwoodHx512RngBudgetV1,
}

thread_local! {
    static SMALLWOOD_HX512_RNG_SESSION_V1: RefCell<Option<SmallwoodHx512RngSessionV1>> = const { RefCell::new(None) };
}

struct SmallwoodHx512RngSessionGuardV1 {
    active: bool,
}

impl SmallwoodHx512RngSessionGuardV1 {
    fn finish(mut self) -> Result<SmallwoodHx512RngBudgetV1, TransactionCircuitError> {
        let session = SMALLWOOD_HX512_RNG_SESSION_V1.with(|slot| slot.borrow_mut().take());
        self.active = false;
        let session = session.ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 prover RNG session is missing at terminal finish",
        ))?;
        if !session.expected_field_request_sizes.is_empty()
            || !session.expected_tape_batch_bytes.is_empty()
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 prover did not consume its exact field/tape RNG schedule",
            ));
        }
        Ok(session.budget)
    }
}

impl Drop for SmallwoodHx512RngSessionGuardV1 {
    fn drop(&mut self) {
        if self.active {
            SMALLWOOD_HX512_RNG_SESSION_V1.with(|slot| {
                let _ = slot.borrow_mut().take();
            });
        }
    }
}

fn enter_smallwood_hx512_rng_session_v1(
    expected_field_request_sizes: VecDeque<usize>,
    expected_tape_batch_bytes: VecDeque<usize>,
    budget: SmallwoodHx512RngBudgetV1,
) -> Result<SmallwoodHx512RngSessionGuardV1, TransactionCircuitError> {
    SMALLWOOD_HX512_RNG_SESSION_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "nested HX512 prover RNG sessions are forbidden",
            ));
        }
        *slot = Some(SmallwoodHx512RngSessionV1 {
            expected_field_request_sizes,
            remaining_field_candidates: budget.field_candidate_limit,
            expected_tape_batch_bytes,
            budget,
        });
        Ok(SmallwoodHx512RngSessionGuardV1 { active: true })
    })
}

fn smallwood_hx512_register_field_rng_request_v1(
    requested_values: usize,
) -> Result<bool, TransactionCircuitError> {
    SMALLWOOD_HX512_RNG_SESSION_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(session) = slot.as_mut() else {
            return Ok(false);
        };
        let expected = session.expected_field_request_sizes.pop_front().ok_or(
            TransactionCircuitError::ConstraintViolation(
                "HX512 prover exceeded its field RNG request schedule",
            ),
        )?;
        if requested_values != expected {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "HX512 prover field RNG request drift: requested={requested_values} expected={expected}"
            )));
        }
        Ok(true)
    })
}

fn smallwood_hx512_register_field_candidates_v1(
    candidates: usize,
) -> Result<(), TransactionCircuitError> {
    SMALLWOOD_HX512_RNG_SESSION_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        let session = slot
            .as_mut()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 field candidate draw is outside its prover RNG session",
            ))?;
        session.remaining_field_candidates = session
            .remaining_field_candidates
            .checked_sub(candidates)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 field RNG rejection budget exhausted",
            ))?;
        Ok(())
    })
}

fn smallwood_hx512_register_tape_rng_batch_v1(
    requested_bytes: usize,
) -> Result<bool, TransactionCircuitError> {
    SMALLWOOD_HX512_RNG_SESSION_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(session) = slot.as_mut() else {
            return Ok(false);
        };
        let expected = session.expected_tape_batch_bytes.pop_front().ok_or(
            TransactionCircuitError::ConstraintViolation(
                "HX512 prover exceeded its leaf-tape RNG schedule",
            ),
        )?;
        if requested_bytes != expected {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "HX512 prover leaf-tape RNG request drift: requested={requested_bytes} expected={expected}"
            )));
        }
        Ok(true)
    })
}

/// Closed engine-facing protocol surface.  There is deliberately no generic
/// append, digest, or sampler callback: the only challenge-bearing calls are
/// the eight events in the frozen HX512 schedule.  `Hx512Transcript` enforces
/// their order, single use, and poisoned-on-XOF-failure semantics.
trait SmallwoodHx512EightStageDriver {
    fn hash_leaf(
        &self,
        salt: &[u8],
        leaf_index: usize,
        tape: &[u8],
        committed_evaluations: &[u64],
        masking_evaluations: &[u64],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>;
    fn hash_node(
        &self,
        level: usize,
        node_index: usize,
        left: &[u8; DIGEST_BYTES],
        right: &[u8; DIGEST_BYTES],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>;
    fn bind_decs_root(
        &mut self,
        salt: &[u8],
        leaf_count: usize,
        root: &[u8; DIGEST_BYTES],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>;
    fn sample_decs_coefficients(
        &mut self,
        expected: usize,
    ) -> Result<Vec<u64>, TransactionCircuitError>;
    fn bind_piop_input(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>;
    fn sample_piop_coefficients(
        &mut self,
        expected: usize,
    ) -> Result<Vec<u64>, TransactionCircuitError>;
    fn bind_piop_transcript(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>;
    fn sample_piop_openings(
        &mut self,
        expected: usize,
    ) -> Result<Vec<u64>, TransactionCircuitError>;
    fn bind_decs_opening(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>;
    fn sample_decs_queries(
        &mut self,
        expected: usize,
        domain_size: usize,
        decs_opening_digest: &[u8; DIGEST_BYTES],
    ) -> Result<Vec<u32>, TransactionCircuitError>;
    fn finish(self) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>;
}

enum SmallwoodHx512TranscriptMode {
    Prover(Hx512Transcript),
    Verifier(Hx512DeferredVerifierTranscript),
}

struct SmallwoodHx512TranscriptDriver {
    transcript: SmallwoodHx512TranscriptMode,
    authoritative_salt: [u8; HX512_SALT_BYTES],
    decs_root: Option<[u8; DIGEST_BYTES]>,
    decs_root_digest: Option<[u8; DIGEST_BYTES]>,
    piop_input_digest: Option<[u8; DIGEST_BYTES]>,
    piop_transcript_digest: Option<[u8; DIGEST_BYTES]>,
    decs_opening_digest: Option<[u8; DIGEST_BYTES]>,
    cached_decs_coefficients: Option<Vec<u64>>,
    cached_piop_coefficients: Option<Vec<u64>>,
    cached_piop_openings: Option<Vec<u64>>,
    piop_openings_consumed: bool,
    failure: Option<String>,
}

impl SmallwoodHx512TranscriptDriver {
    fn record_failure<T>(&mut self, error: TransactionCircuitError, fallback: T) -> T {
        if self.failure.is_none() {
            self.failure = Some(error.to_string());
        }
        fallback
    }

    fn cached_decs_root_digest(&self) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        self.decs_root_digest
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 DECS root binding has not been consumed",
            ))
    }

    fn fresh_proof_prefix(
        &self,
    ) -> Result<([u8; DIGEST_BYTES], [u8; DIGEST_BYTES]), TransactionCircuitError> {
        Ok((
            self.decs_root
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "HX512 raw DECS root is missing from the prover transcript",
                ))?,
            self.piop_input_digest
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "HX512 PIOP input digest is missing from the prover transcript",
                ))?,
        ))
    }
}

impl SmallwoodHx512EightStageDriver for SmallwoodHx512TranscriptDriver {
    fn hash_leaf(
        &self,
        salt: &[u8],
        leaf_index: usize,
        tape: &[u8],
        committed_evaluations: &[u64],
        masking_evaluations: &[u64],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        if salt != self.authoritative_salt || tape.len() != HX512_PROFILE_LEAF_TAPE_BYTES {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 Merkle leaf requires the authoritative salt and exact 72-byte tape",
            ));
        }
        let leaf_index = u32::try_from(leaf_index).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "HX512 Merkle leaf index does not fit canonical u32",
            )
        })?;
        let tape: &[u8; HX512_PROFILE_LEAF_TAPE_BYTES] = tape.try_into().map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "HX512 Merkle leaf tape has the wrong width",
            )
        })?;
        match &self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => transcript
                .hash_leaf(
                    &self.authoritative_salt,
                    leaf_index,
                    tape,
                    committed_evaluations,
                    masking_evaluations,
                )
                .map_err(smallwood_hx512_error),
            SmallwoodHx512TranscriptMode::Verifier(transcript) => transcript
                .hash_leaf(
                    &self.authoritative_salt,
                    leaf_index,
                    tape,
                    committed_evaluations,
                    masking_evaluations,
                )
                .map_err(smallwood_hx512_error),
        }
    }

    fn hash_node(
        &self,
        level: usize,
        node_index: usize,
        left: &[u8; DIGEST_BYTES],
        right: &[u8; DIGEST_BYTES],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        let level = u8::try_from(level).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "HX512 Merkle level does not fit canonical u8",
            )
        })?;
        let node_index = u32::try_from(node_index).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "HX512 Merkle node index does not fit canonical u32",
            )
        })?;
        Ok(match &self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                transcript.hash_merkle_node(level, node_index, left, right)
            }
            SmallwoodHx512TranscriptMode::Verifier(transcript) => {
                transcript.hash_merkle_node(level, node_index, left, right)
            }
        })
    }

    fn bind_decs_root(
        &mut self,
        salt: &[u8],
        leaf_count: usize,
        root: &[u8; DIGEST_BYTES],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        if salt != self.authoritative_salt {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 root binding salt does not match the authoritative outer salt",
            ));
        }
        let leaf_count = u32::try_from(leaf_count).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "HX512 DECS leaf count does not fit canonical u32",
            )
        })?;
        match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                let digest = transcript
                    .hash_merkle_root(leaf_count, root)
                    .map_err(smallwood_hx512_error)?;
                self.decs_root = Some(*root);
                self.decs_root_digest = Some(digest);
                Ok(digest)
            }
            SmallwoodHx512TranscriptMode::Verifier(transcript) => {
                transcript
                    .verify_reconstructed_root(root)
                    .map_err(smallwood_hx512_error)?;
                self.decs_root = Some(*root);
                self.decs_root_digest
                    .ok_or(TransactionCircuitError::ConstraintViolation(
                        "HX512 verifier DECS-root digest is missing",
                    ))
            }
        }
    }

    fn sample_decs_coefficients(
        &mut self,
        expected: usize,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        let values = match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                transcript
                    .sample_decs_coefficients()
                    .map_err(smallwood_hx512_error)?
                    .values
            }
            SmallwoodHx512TranscriptMode::Verifier(_) => self
                .cached_decs_coefficients
                .take()
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "HX512 verifier DECS coefficients were absent or consumed twice",
                ))?,
        };
        if values.len() != expected {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 DECS coefficient count does not match engine geometry",
            ));
        }
        Ok(values)
    }

    fn bind_piop_input(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                let digest = transcript
                    .absorb_piop_input(message)
                    .map_err(smallwood_hx512_error)?;
                self.piop_input_digest = Some(digest);
                Ok(digest)
            }
            SmallwoodHx512TranscriptMode::Verifier(transcript) => {
                transcript
                    .verify_reconstructed_piop_input(message)
                    .map_err(smallwood_hx512_error)?;
                self.piop_input_digest
                    .ok_or(TransactionCircuitError::ConstraintViolation(
                        "HX512 verifier PIOP-input digest claim is missing",
                    ))
            }
        }
    }

    fn sample_piop_coefficients(
        &mut self,
        expected: usize,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        let values = match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                transcript
                    .sample_piop_coefficients()
                    .map_err(smallwood_hx512_error)?
                    .values
            }
            SmallwoodHx512TranscriptMode::Verifier(_) => self
                .cached_piop_coefficients
                .take()
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "HX512 verifier PIOP coefficients were absent or consumed twice",
                ))?,
        };
        if values.len() != expected {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 PIOP coefficient count does not match engine geometry",
            ));
        }
        Ok(values)
    }

    fn bind_piop_transcript(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                let digest = transcript
                    .absorb_piop_transcript(message)
                    .map_err(smallwood_hx512_error)?;
                self.piop_transcript_digest = Some(digest);
                Ok(digest)
            }
            SmallwoodHx512TranscriptMode::Verifier(transcript) => {
                transcript
                    .verify_reconstructed_piop_transcript(message)
                    .map_err(smallwood_hx512_error)?;
                self.piop_transcript_digest
                    .ok_or(TransactionCircuitError::ConstraintViolation(
                        "HX512 verifier PIOP-transcript digest claim is missing",
                    ))
            }
        }
    }

    fn sample_piop_openings(
        &mut self,
        expected: usize,
    ) -> Result<Vec<u64>, TransactionCircuitError> {
        if self.piop_openings_consumed {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 PIOP opening challenge was consumed more than once",
            ));
        }
        let values = match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                transcript
                    .sample_piop_openings()
                    .map_err(smallwood_hx512_error)?
                    .values
            }
            SmallwoodHx512TranscriptMode::Verifier(_) => self.cached_piop_openings.take().ok_or(
                TransactionCircuitError::ConstraintViolation(
                    "HX512 verifier PIOP openings are missing",
                ),
            )?,
        };
        if values.len() != expected {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 PIOP opening count does not match engine geometry",
            ));
        }
        self.piop_openings_consumed = true;
        Ok(values)
    }

    fn bind_decs_opening(
        &mut self,
        message: &[u8],
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        let digest = match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => transcript
                .absorb_decs_opening(message)
                .map_err(smallwood_hx512_error)?,
            SmallwoodHx512TranscriptMode::Verifier(transcript) => transcript
                .absorb_decs_opening(message)
                .map_err(smallwood_hx512_error)?,
        };
        self.decs_opening_digest = Some(digest);
        Ok(digest)
    }

    fn sample_decs_queries(
        &mut self,
        expected: usize,
        domain_size: usize,
        decs_opening_digest: &[u8; DIGEST_BYTES],
    ) -> Result<Vec<u32>, TransactionCircuitError> {
        if self.decs_opening_digest.as_ref() != Some(decs_opening_digest) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 DECS query input does not match the exact stage7 digest",
            ));
        }
        let samples = match &mut self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => transcript
                .sample_decs_queries()
                .map_err(smallwood_hx512_error)?,
            SmallwoodHx512TranscriptMode::Verifier(transcript) => transcript
                .sample_decs_queries()
                .map_err(smallwood_hx512_error)?,
        };
        if samples.indexes.len() != expected
            || samples
                .indexes
                .iter()
                .any(|index| *index as usize >= domain_size)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 DECS query shape does not match engine geometry",
            ));
        }
        Ok(samples.indexes)
    }

    fn finish(self) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        if let Some(failure) = self.failure {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "HX512 transcript driver failed closed: {failure}"
            )));
        }
        if self.cached_decs_coefficients.is_some()
            || self.cached_piop_coefficients.is_some()
            || self.cached_piop_openings.is_some()
            || !self.piop_openings_consumed
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 transcript driver did not consume the complete engine challenge schedule",
            ));
        }
        match self.transcript {
            SmallwoodHx512TranscriptMode::Prover(transcript) => {
                transcript.finish().map_err(smallwood_hx512_error)
            }
            SmallwoodHx512TranscriptMode::Verifier(transcript) => {
                transcript.finish().map_err(smallwood_hx512_error)
            }
        }
    }
}

thread_local! {
    static SMALLWOOD_HX512_TRANSCRIPT_DRIVER: RefCell<Option<SmallwoodHx512TranscriptDriver>> = const { RefCell::new(None) };
}

struct SmallwoodHx512TranscriptContextGuard {
    active: bool,
}

impl SmallwoodHx512TranscriptContextGuard {
    fn finish(mut self) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        let driver = SMALLWOOD_HX512_TRANSCRIPT_DRIVER.with(|slot| slot.borrow_mut().take());
        self.active = false;
        driver
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 transcript context is missing at terminal finish",
            ))?
            .finish()
    }
}

impl Drop for SmallwoodHx512TranscriptContextGuard {
    fn drop(&mut self) {
        if self.active {
            SMALLWOOD_HX512_TRANSCRIPT_DRIVER.with(|slot| {
                let _ = slot.borrow_mut().take();
            });
        }
    }
}

fn install_smallwood_hx512_transcript_driver(
    driver: SmallwoodHx512TranscriptDriver,
) -> Result<SmallwoodHx512TranscriptContextGuard, TransactionCircuitError> {
    SMALLWOOD_HX512_TRANSCRIPT_DRIVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "nested HX512 transcript contexts are forbidden",
            ));
        }
        *slot = Some(driver);
        Ok(SmallwoodHx512TranscriptContextGuard { active: true })
    })
}

fn enter_smallwood_hx512_prover_transcript_context(
    transcript: Hx512Transcript,
    authoritative_salt: [u8; HX512_SALT_BYTES],
) -> Result<SmallwoodHx512TranscriptContextGuard, TransactionCircuitError> {
    install_smallwood_hx512_transcript_driver(SmallwoodHx512TranscriptDriver {
        transcript: SmallwoodHx512TranscriptMode::Prover(transcript),
        authoritative_salt,
        decs_root: None,
        decs_root_digest: None,
        piop_input_digest: None,
        piop_transcript_digest: None,
        decs_opening_digest: None,
        cached_decs_coefficients: None,
        cached_piop_coefficients: None,
        cached_piop_openings: None,
        piop_openings_consumed: false,
        failure: None,
    })
}

/// Install the exact deferred verifier schedule. Events zero through five are
/// driven from the proof-carried raw root, h3, and h5 before the engine uses
/// any challenge. Events six and seven are consumed later from reconstructed
/// response data; the three claims are then checked in root/h3/h5 order.
fn enter_smallwood_hx512_verifier_transcript_context(
    mut transcript: Hx512DeferredVerifierTranscript,
    authoritative_salt: [u8; HX512_SALT_BYTES],
    claimed_decs_root: [u8; DIGEST_BYTES],
    claimed_piop_input_digest: [u8; DIGEST_BYTES],
    claimed_piop_transcript_digest: [u8; DIGEST_BYTES],
) -> Result<SmallwoodHx512TranscriptContextGuard, TransactionCircuitError> {
    let leaf_count =
        u32::try_from(HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "HX512 DECS leaf count does not fit canonical u32",
            )
        })?;
    let decs_root_digest = transcript
        .bind_claimed_decs_root(leaf_count, &claimed_decs_root)
        .map_err(smallwood_hx512_error)?;
    let decs_coefficients = transcript
        .sample_decs_coefficients()
        .map_err(smallwood_hx512_error)?
        .values;
    transcript
        .claim_piop_input_digest(claimed_piop_input_digest)
        .map_err(smallwood_hx512_error)?;
    let piop_coefficients = transcript
        .sample_piop_coefficients()
        .map_err(smallwood_hx512_error)?
        .values;
    transcript
        .claim_piop_transcript_digest(claimed_piop_transcript_digest)
        .map_err(smallwood_hx512_error)?;
    let piop_openings = transcript
        .sample_piop_openings()
        .map_err(smallwood_hx512_error)?
        .values;
    install_smallwood_hx512_transcript_driver(SmallwoodHx512TranscriptDriver {
        transcript: SmallwoodHx512TranscriptMode::Verifier(transcript),
        authoritative_salt,
        decs_root: Some(claimed_decs_root),
        decs_root_digest: Some(decs_root_digest),
        piop_input_digest: Some(claimed_piop_input_digest),
        piop_transcript_digest: Some(claimed_piop_transcript_digest),
        decs_opening_digest: None,
        cached_decs_coefficients: Some(decs_coefficients),
        cached_piop_coefficients: Some(piop_coefficients),
        cached_piop_openings: Some(piop_openings),
        piop_openings_consumed: false,
        failure: None,
    })
}

/// The sole executable HX512 prover seam. Keeping context installation and
/// terminal finish in this function prevents a crate-internal caller from
/// obtaining a proof after dropping a poisoned or incomplete driver.
pub(crate) fn prove_smallwood_hx512_core_atomic_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    salt: &[u8; HX512_SALT_BYTES],
    transcript: Hx512Transcript,
) -> Result<SmallwoodProof, TransactionCircuitError> {
    let (rng_budget, field_requests, tape_batches, expected_witness_values) =
        derive_smallwood_hx512_rng_schedule_v1(statement)?;
    if witness_values.len() != expected_witness_values {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "HX512 canonical witness length mismatch: actual={} expected={expected_witness_values}",
            witness_values.len()
        )));
    }
    let rng_guard = enter_smallwood_hx512_rng_session_v1(field_requests, tape_batches, rng_budget)?;
    let guard = enter_smallwood_hx512_prover_transcript_context(transcript, *salt)?;
    let proof = prove_statement_core_with_transcript_backend_profile_and_domain(
        statement,
        witness_values,
        &[],
        HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1,
        SmallwoodTranscriptBackend::Hx512Candidate,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        salt,
        HX512_PROFILE_LEAF_TAPE_BYTES,
        SmallwoodProofWireIdentityV1::FreshHx512Candidate,
    )?;
    guard.finish()?;
    rng_guard.finish()?;
    Ok(proof)
}

/// The sole executable HX512 verifier seam. `Ok` is unreachable until the
/// generic verifier has replayed the proof and terminal finish has checked the
/// raw root, h3, h5, every cached challenge, and the complete eight-event
/// deferred transcript state.
pub(crate) fn verify_smallwood_hx512_core_atomic_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof: &SmallwoodProof,
    salt: &[u8; HX512_SALT_BYTES],
    transcript: Hx512DeferredVerifierTranscript,
) -> Result<(), TransactionCircuitError> {
    let claimed_root =
        proof
            .hx512_decs_root
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 proof is missing its raw DECS root",
            ))?;
    let claimed_h3 =
        proof
            .hx512_piop_input_digest
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 proof is missing its h3 digest",
            ))?;
    let guard = enter_smallwood_hx512_verifier_transcript_context(
        transcript,
        *salt,
        claimed_root,
        claimed_h3,
        proof.h_piop,
    )?;
    verify_statement_core_with_transcript_backend_profile_and_domain(
        statement,
        &[],
        proof,
        HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1,
        SmallwoodTranscriptBackend::Hx512Candidate,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        Some(HX512_PROFILE_LEAF_TAPE_BYTES),
    )?;
    guard.finish()?;
    Ok(())
}

fn with_smallwood_hx512_transcript_driver<R>(
    f: impl FnOnce(&mut SmallwoodHx512TranscriptDriver) -> R,
) -> Result<R, TransactionCircuitError> {
    SMALLWOOD_HX512_TRANSCRIPT_DRIVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        let driver = slot
            .as_mut()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 transcript backend requires a dedicated active context",
            ))?;
        Ok(f(driver))
    })
}

fn encode_smallwood_hx512_field_message(words: &[u64]) -> Vec<u8> {
    let mut message = Vec::with_capacity(8 + words.len().saturating_mul(8));
    message.extend_from_slice(&(words.len() as u64).to_be_bytes());
    for word in words {
        message.extend_from_slice(&word.to_be_bytes());
    }
    message
}

fn sample_smallwood_hx512_piop_openings(
    packing_points: &[u64],
    expected: usize,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let openings =
        with_smallwood_hx512_transcript_driver(|driver| driver.sample_piop_openings(expected))??;
    ensure_no_packing_collisions(packing_points, &openings)?;
    Ok(openings)
}

fn hx512_capture_digest(
    request: impl FnOnce(
        &mut SmallwoodHx512TranscriptDriver,
    ) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError>,
) -> [u8; DIGEST_BYTES] {
    with_smallwood_hx512_transcript_driver(|driver| match request(driver) {
        Ok(digest) => digest,
        Err(error) => driver.record_failure(error, [0u8; DIGEST_BYTES]),
    })
    .unwrap_or([0u8; DIGEST_BYTES])
}

fn hx512_capture_field_samples(
    expected: usize,
    request: impl FnOnce(
        &mut SmallwoodHx512TranscriptDriver,
        usize,
    ) -> Result<Vec<u64>, TransactionCircuitError>,
) -> Vec<u64> {
    with_smallwood_hx512_transcript_driver(|driver| match request(driver, expected) {
        Ok(samples) => samples,
        Err(error) => driver.record_failure(error, vec![0u64; expected]),
    })
    .unwrap_or_else(|_| vec![0u64; expected])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodProofWireIdentityV1 {
    LegacySmw1,
    Sha512Level5Smw2,
    FullSha512First48CommitmentSmw3,
    StrictZkSha512Level5Smz1,
    StrictZkSha512V6Smz2,
    /// Fresh compact V8 identity.  It shares no magic, transcript profile, or
    /// query/tape count with SMZ1 or SMZ2.
    StrictZkSha512Poseidon2V8Smz8,
    /// Additive V8 successor with q=20, six PIOP openings, and a fresh
    /// transcript/profile identity.  SMZ8 bytes never decode as this variant.
    StrictZkSha512Poseidon2V8Smz9,
    /// Inactive profile-7 wire for the same HGV8RP03 relation. It uses six
    /// PIOP openings, nineteen DECS queries, and 56-byte observed commitments.
    StrictZkSha512Poseidon2V8Compact448Smc7,
    /// Inactive q=20/profile-8 sibling with 56-byte observed commitments.
    StrictZkSha512Poseidon2V8Compact448Q20Smc8,
    /// Internal marker for the additive HX512 core proof. It has no historical
    /// magic and is rejected by every SMW/SMZ encoder and decoder.
    FreshHx512Candidate,
}

impl SmallwoodProofWireIdentityV1 {
    pub const fn is_strict_zk(self) -> bool {
        matches!(
            self,
            Self::StrictZkSha512Level5Smz1
                | Self::StrictZkSha512V6Smz2
                | Self::StrictZkSha512Poseidon2V8Smz8
                | Self::StrictZkSha512Poseidon2V8Smz9
                | Self::StrictZkSha512Poseidon2V8Compact448Smc7
                | Self::StrictZkSha512Poseidon2V8Compact448Q20Smc8
                | Self::FreshHx512Candidate
        )
    }

    const fn opened_leaf_tape_profile(self) -> Option<(usize, usize)> {
        match self {
            Self::StrictZkSha512Level5Smz1 | Self::StrictZkSha512V6Smz2 => Some((
                SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1,
                SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            )),
            Self::StrictZkSha512Poseidon2V8Smz8 => Some((
                SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT,
                SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            )),
            Self::StrictZkSha512Poseidon2V8Smz9 => Some((
                SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT,
                SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            )),
            Self::StrictZkSha512Poseidon2V8Compact448Smc7 => Some((
                SMALLWOOD_POSEIDON2_V8_COMPACT448_DECS_OPENED_LEAF_COUNT,
                SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            )),
            Self::StrictZkSha512Poseidon2V8Compact448Q20Smc8 => Some((
                SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_DECS_OPENED_LEAF_COUNT,
                SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            )),
            Self::FreshHx512Candidate => Some((
                HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals,
                HX512_PROFILE_LEAF_TAPE_BYTES,
            )),
            _ => None,
        }
    }

    const fn maximum_auth_path_depth(self) -> Option<usize> {
        match self {
            Self::StrictZkSha512Level5Smz1 | Self::StrictZkSha512V6Smz2 => Some(20),
            Self::StrictZkSha512Poseidon2V8Smz8
            | Self::StrictZkSha512Poseidon2V8Smz9
            | Self::StrictZkSha512Poseidon2V8Compact448Smc7
            | Self::StrictZkSha512Poseidon2V8Compact448Q20Smc8 => Some(23),
            Self::FreshHx512Candidate => Some(20),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SmallwoodDecsEvaluationDomain {
    Consecutive,
    Radix2Subgroup,
    /// A deterministic multiplicative coset of the radix-2 subgroup whose
    /// points are disjoint from every interpolation coordinate `0..d` used
    /// by the LVCS row polynomials.  This is the only radix-2 domain shape
    /// suitable for a future complete-ZK profile: opening an interpolation
    /// coordinate reveals a committed LVCS row cell directly.
    Radix2DisjointCoset,
}

fn proof_wire_identity_for_backend_and_domain(
    backend: SmallwoodTranscriptBackend,
    domain: SmallwoodDecsEvaluationDomain,
) -> Result<SmallwoodProofWireIdentityV1, TransactionCircuitError> {
    if domain == SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
        return match backend {
            SmallwoodTranscriptBackend::Sha512Level5 => {
                Ok(SmallwoodProofWireIdentityV1::StrictZkSha512Level5Smz1)
            }
            SmallwoodTranscriptBackend::Sha512V6 => {
                Ok(SmallwoodProofWireIdentityV1::StrictZkSha512V6Smz2)
            }
            SmallwoodTranscriptBackend::Sha512Poseidon2V8 => {
                Ok(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8)
            }
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 => {
                Ok(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9)
            }
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 => {
                Ok(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7)
            }
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 => {
                Ok(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8)
            }
            _ => Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-ZK DECS domain requires an exact strict SHA-512 wire",
            )),
        };
    }
    match backend {
        SmallwoodTranscriptBackend::Blake3 | SmallwoodTranscriptBackend::Poseidon2 => {
            Ok(SmallwoodProofWireIdentityV1::LegacySmw1)
        }
        SmallwoodTranscriptBackend::Sha512Level5 => {
            Ok(SmallwoodProofWireIdentityV1::Sha512Level5Smw2)
        }
        SmallwoodTranscriptBackend::FullSha512First48CommitmentV3 => {
            Ok(SmallwoodProofWireIdentityV1::FullSha512First48CommitmentSmw3)
        }
        SmallwoodTranscriptBackend::Sha512V6 => Err(TransactionCircuitError::ConstraintViolation(
            "smallwood fresh V6 SHA-512 backend requires the SMZ2 disjoint-coset wire",
        )),
        SmallwoodTranscriptBackend::Sha512Poseidon2V8 => {
            Err(TransactionCircuitError::ConstraintViolation(
                "smallwood fresh V8 SHA-512 backend requires the SMZ8 disjoint-coset wire",
            ))
        }
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 => {
            Err(TransactionCircuitError::ConstraintViolation(
                "smallwood fresh V8 successor backend requires the SMZ9 disjoint-coset wire",
            ))
        }
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 => {
            Err(TransactionCircuitError::ConstraintViolation(
                "smallwood compact V8 profile-7 backend requires the SMC7 disjoint-coset wire",
            ))
        }
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 => {
            Err(TransactionCircuitError::ConstraintViolation(
                "smallwood compact V8 profile-8 backend requires the SMC8 disjoint-coset wire",
            ))
        }
        SmallwoodTranscriptBackend::Hx512Candidate => {
            Err(TransactionCircuitError::ConstraintViolation(
                "fresh HX512 backend requires its separate inner-wire entrypoint",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodVerifierOperationProfileV1 {
    pub field_additions: u64,
    pub field_subtractions: u64,
    pub field_multiplications: u64,
    pub field_negations: u64,
    pub field_inversions: u64,
    pub transcript_calls: u64,
    pub transcript_absorbed_words: u64,
    pub transcript_squeezed_words: u64,
    #[serde(default)]
    pub sha512_digest_calls: u64,
    pub poseidon2_permutations: u64,
    pub merkle_leaf_hashes: u64,
    pub merkle_internal_hashes: u64,
    pub merkle_root_hashes: u64,
    pub merkle_authentication_words: u64,
    pub piop_nonce_trials: u64,
    pub decs_nonce_trials: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodTranscriptCallTraceV1 {
    pub domain: Vec<u8>,
    pub input_words: Vec<u64>,
    pub output_words: Vec<u64>,
    #[serde(default)]
    pub raw_digest_calls: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodVerifierStageOperationProfileV1 {
    pub stage: String,
    pub operations: SmallwoodVerifierOperationProfileV1,
}

thread_local! {
    static SMALLWOOD_VERIFIER_OPERATION_PROFILE_V1:
        Cell<Option<SmallwoodVerifierOperationProfileV1>> = const { Cell::new(None) };
    static SMALLWOOD_TRANSCRIPT_CALL_TRACE_V1:
        RefCell<Option<Vec<SmallwoodTranscriptCallTraceV1>>> = const { RefCell::new(None) };
    static SMALLWOOD_VERIFIER_STAGE_PROFILE_V1:
        RefCell<Option<Vec<(String, SmallwoodVerifierOperationProfileV1)>>> =
            const { RefCell::new(None) };
}

#[inline(always)]
fn update_verifier_operation_profile_v1(
    update: impl FnOnce(&mut SmallwoodVerifierOperationProfileV1),
) {
    SMALLWOOD_VERIFIER_OPERATION_PROFILE_V1.with(|slot| {
        if let Some(mut profile) = slot.get() {
            update(&mut profile);
            slot.set(Some(profile));
        }
    });
}

fn begin_verifier_operation_profile_v1() -> Result<(), TransactionCircuitError> {
    SMALLWOOD_VERIFIER_OPERATION_PROFILE_V1.with(|slot| {
        if slot.get().is_some() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "SmallWood verifier operation profiling is already active",
            ));
        }
        slot.set(Some(SmallwoodVerifierOperationProfileV1::default()));
        Ok(())
    })
}

fn finish_verifier_operation_profile_v1() -> SmallwoodVerifierOperationProfileV1 {
    SMALLWOOD_VERIFIER_OPERATION_PROFILE_V1
        .with(|slot| slot.replace(None))
        .unwrap_or_default()
}

fn begin_verifier_stage_profile_v1() -> Result<(), TransactionCircuitError> {
    SMALLWOOD_VERIFIER_STAGE_PROFILE_V1.with(|slot| {
        let mut stages = slot.borrow_mut();
        if stages.is_some() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "SmallWood verifier stage profiling is already active",
            ));
        }
        *stages = Some(Vec::new());
        Ok(())
    })
}

fn record_verifier_stage_profile_v1(stage: &'static str) {
    let cumulative = SMALLWOOD_VERIFIER_OPERATION_PROFILE_V1
        .with(|slot| slot.get())
        .unwrap_or_default();
    SMALLWOOD_VERIFIER_STAGE_PROFILE_V1.with(|slot| {
        if let Some(stages) = slot.borrow_mut().as_mut() {
            stages.push((stage.to_owned(), cumulative));
        }
    });
}

fn subtract_operation_profile_v1(
    current: SmallwoodVerifierOperationProfileV1,
    previous: SmallwoodVerifierOperationProfileV1,
) -> SmallwoodVerifierOperationProfileV1 {
    SmallwoodVerifierOperationProfileV1 {
        field_additions: current
            .field_additions
            .saturating_sub(previous.field_additions),
        field_subtractions: current
            .field_subtractions
            .saturating_sub(previous.field_subtractions),
        field_multiplications: current
            .field_multiplications
            .saturating_sub(previous.field_multiplications),
        field_negations: current
            .field_negations
            .saturating_sub(previous.field_negations),
        field_inversions: current
            .field_inversions
            .saturating_sub(previous.field_inversions),
        transcript_calls: current
            .transcript_calls
            .saturating_sub(previous.transcript_calls),
        transcript_absorbed_words: current
            .transcript_absorbed_words
            .saturating_sub(previous.transcript_absorbed_words),
        transcript_squeezed_words: current
            .transcript_squeezed_words
            .saturating_sub(previous.transcript_squeezed_words),
        sha512_digest_calls: current
            .sha512_digest_calls
            .saturating_sub(previous.sha512_digest_calls),
        poseidon2_permutations: current
            .poseidon2_permutations
            .saturating_sub(previous.poseidon2_permutations),
        merkle_leaf_hashes: current
            .merkle_leaf_hashes
            .saturating_sub(previous.merkle_leaf_hashes),
        merkle_internal_hashes: current
            .merkle_internal_hashes
            .saturating_sub(previous.merkle_internal_hashes),
        merkle_root_hashes: current
            .merkle_root_hashes
            .saturating_sub(previous.merkle_root_hashes),
        merkle_authentication_words: current
            .merkle_authentication_words
            .saturating_sub(previous.merkle_authentication_words),
        piop_nonce_trials: current
            .piop_nonce_trials
            .saturating_sub(previous.piop_nonce_trials),
        decs_nonce_trials: current
            .decs_nonce_trials
            .saturating_sub(previous.decs_nonce_trials),
    }
}

fn finish_verifier_stage_profile_v1() -> Vec<SmallwoodVerifierStageOperationProfileV1> {
    let cumulative = SMALLWOOD_VERIFIER_STAGE_PROFILE_V1
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default();
    let mut previous = SmallwoodVerifierOperationProfileV1::default();
    cumulative
        .into_iter()
        .map(|(stage, current)| {
            let operations = subtract_operation_profile_v1(current, previous);
            previous = current;
            SmallwoodVerifierStageOperationProfileV1 { stage, operations }
        })
        .collect()
}

fn begin_transcript_call_trace_v1() -> Result<(), TransactionCircuitError> {
    SMALLWOOD_TRANSCRIPT_CALL_TRACE_V1.with(|slot| {
        let mut trace = slot.borrow_mut();
        if trace.is_some() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "SmallWood transcript call tracing is already active",
            ));
        }
        *trace = Some(Vec::new());
        Ok(())
    })
}

fn record_transcript_call_trace_v1(
    domain: &[u8],
    input_words: &[u64],
    output_words: &[u64],
    raw_digest_calls: u64,
) {
    SMALLWOOD_TRANSCRIPT_CALL_TRACE_V1.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.push(SmallwoodTranscriptCallTraceV1 {
                domain: domain.to_vec(),
                input_words: input_words.to_vec(),
                output_words: output_words.to_vec(),
                raw_digest_calls,
            });
        }
    });
}

fn finish_transcript_call_trace_v1() -> Vec<SmallwoodTranscriptCallTraceV1> {
    SMALLWOOD_TRANSCRIPT_CALL_TRACE_V1
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
pub struct SmallwoodProof {
    pub(crate) wire_identity: SmallwoodProofWireIdentityV1,
    pub(crate) digest_bytes: usize,
    pub(crate) strict_zk_decs_leaf_hiding: bool,
    /// Fresh-only prefix fields. Historical SMW/SMZ encoders require both to
    /// be absent. HX512 carries the raw DECS root and the deferred stage-3
    /// digest before the existing stage-5 `h_piop` digest.
    pub(crate) hx512_decs_root: Option<[u8; DIGEST_BYTES]>,
    pub(crate) hx512_piop_input_digest: Option<[u8; DIGEST_BYTES]>,
    pub(crate) salt: Vec<u8>,
    pub(crate) nonce: [u8; NONCE_BYTES],
    pub(crate) h_piop: [u8; DIGEST_BYTES],
    pub(crate) piop: PiopProof,
    pub(crate) pcs: PcsProof,
    pub(crate) opened_witness: SmallwoodOpenedWitnessBundle,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PiopProof {
    pub(crate) ppol_highs: Vec<Vec<u64>>,
    pub(crate) plin_highs: Vec<Vec<u64>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsProof {
    pub(crate) rcombi_tails: Vec<Vec<u64>>,
    pub(crate) subset_evals: Vec<Vec<u64>>,
    pub(crate) partial_evals: Vec<Vec<u64>>,
    pub(crate) decs: DecsProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecsProof {
    pub(crate) auth_paths: Vec<Vec<[u8; DIGEST_BYTES]>>,
    // Byte vectors keep the LPPC/DECS mechanics independent of a particular
    // hiding-tape profile. Historical SMZ1/SMZ2 encoders still require exactly
    // 64 bytes per tape; the fresh HX512 wire owns its separate 72-byte rule.
    pub(crate) leaf_tapes: Vec<Vec<u8>>,
    pub(crate) masking_evals: Vec<Vec<u64>>,
    pub(crate) high_coeffs: Vec<Vec<u64>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodProofTraceV1 {
    pub wire_identity: SmallwoodProofWireIdentityV1,
    pub salt: [u8; SALT_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub h_piop: [u8; DIGEST_BYTES],
    pub piop: PiopProof,
    pub pcs: PcsProof,
    pub opened_witness_row_scalars: Vec<Vec<u64>>,
    pub auxiliary_witness_words: Vec<u64>,
    pub auxiliary_witness_limb_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodProofSizeReportV1 {
    pub total_bytes: usize,
    pub transcript_bytes: usize,
    pub commitment_bytes: usize,
    pub opened_values_bytes: usize,
    pub opening_payload_bytes: usize,
    pub opened_witness_bytes: usize,
    pub other_bytes: usize,
    pub salt_bytes: usize,
    pub nonce_bytes: usize,
    pub h_piop_bytes: usize,
    pub piop_bytes: usize,
    pub pcs_rcombi_tails_bytes: usize,
    pub pcs_subset_evals_bytes: usize,
    pub pcs_partial_evals_bytes: usize,
    pub decs_auth_paths_bytes: usize,
    pub decs_leaf_tapes_bytes: usize,
    pub decs_masking_evals_bytes: usize,
    pub decs_high_coeffs_bytes: usize,
}

/// Exact rational union term for exhaustion of one capped SHA-512-to-field
/// request in the ideal uniform-block model.
///
/// If `C` candidate words are available and `n` accepted words are requested,
/// exhaustion needs at least `t = C - n + 1` rejected candidates.  A union over
/// all `t`-subsets gives the exact recorded bound
///
/// `binomial(C, t) * (2^32 - 1)^t / 2^(64 t)`.
///
/// This is an explicit abort term, not a concrete-SHA-512 or QROM theorem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodSha512FieldXofAbortBoundV1 {
    pub requested_output_words: usize,
    pub digest_call_cap: usize,
    pub candidate_word_cap: usize,
    pub minimum_rejections_for_exhaustion: usize,
    pub union_bound_numerator: BigUint,
    pub union_bound_denominator: BigUint,
}

impl SmallwoodSha512FieldXofAbortBoundV1 {
    pub fn is_strictly_below_power_of_two_v1(&self, bits: usize) -> bool {
        (&self.union_bound_numerator << bits) < self.union_bound_denominator
    }
}

fn smallwood_sha512_field_xof_digest_call_cap_v1(
    requested_output_words: usize,
) -> Result<usize, TransactionCircuitError> {
    if requested_output_words > SMALLWOOD_SHA512_FIELD_XOF_MAX_OUTPUT_WORDS_V1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SHA-512 field-XOF request exceeds the explicit output-word cap",
        ));
    }
    if requested_output_words == 0 {
        return Ok(0);
    }
    requested_output_words
        .checked_add(SMALLWOOD_SHA512_FIELD_XOF_EXTRA_CANDIDATE_WORDS_V1)
        .map(|candidate_words| {
            candidate_words.div_ceil(SMALLWOOD_SHA512_FIELD_XOF_WORDS_PER_DIGEST_V1)
        })
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SHA-512 field-XOF candidate budget overflow",
        ))
}

pub fn report_smallwood_sha512_field_xof_abort_bound_v1(
    requested_output_words: usize,
) -> Result<SmallwoodSha512FieldXofAbortBoundV1, TransactionCircuitError> {
    let digest_call_cap = smallwood_sha512_field_xof_digest_call_cap_v1(requested_output_words)?;
    if requested_output_words == 0 {
        return Ok(SmallwoodSha512FieldXofAbortBoundV1 {
            requested_output_words,
            digest_call_cap,
            candidate_word_cap: 0,
            minimum_rejections_for_exhaustion: 0,
            union_bound_numerator: BigUint::from(0u8),
            union_bound_denominator: BigUint::from(1u8),
        });
    }
    let candidate_word_cap = digest_call_cap
        .checked_mul(SMALLWOOD_SHA512_FIELD_XOF_WORDS_PER_DIGEST_V1)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SHA-512 field-XOF word budget overflow",
        ))?;
    let minimum_rejections_for_exhaustion = candidate_word_cap
        .checked_sub(requested_output_words)
        .and_then(|slack| slack.checked_add(1))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SHA-512 field-XOF exhaustion threshold underflow",
        ))?;
    let union_bound_numerator = binomial(
        candidate_word_cap as u128,
        minimum_rejections_for_exhaustion,
    )
    .ok_or(TransactionCircuitError::ConstraintViolation(
        "smallwood SHA-512 field-XOF abort binomial is undefined",
    ))? * BigUint::from(NEG_ORDER)
        .pow(minimum_rejections_for_exhaustion as u32);
    let union_bound_denominator =
        BigUint::from(1u8) << (64usize * minimum_rejections_for_exhaustion);
    Ok(SmallwoodSha512FieldXofAbortBoundV1 {
        requested_output_words,
        digest_call_cap,
        candidate_word_cap,
        minimum_rejections_for_exhaustion,
        union_bound_numerator,
        union_bound_denominator,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodBackendOpeningSurfaceReportV1 {
    pub total_inner_proof_bytes: usize,
    pub transcript_bytes: usize,
    pub commitment_bytes: usize,
    pub opened_values_bytes: usize,
    pub opening_payload_bytes: usize,
    pub opened_witness_bytes: usize,
    pub pcs_rcombi_tails_bytes: usize,
    pub pcs_subset_evals_bytes: usize,
    pub pcs_partial_evals_bytes: usize,
    pub decs_auth_paths_bytes: usize,
    pub decs_leaf_tapes_bytes: usize,
    pub decs_masking_evals_bytes: usize,
    pub decs_high_coeffs_bytes: usize,
    pub nb_polys: usize,
    pub nb_unstacked_cols: usize,
    pub nb_lvcs_rows: usize,
    pub nb_lvcs_cols: usize,
    pub nb_lvcs_opened_combi: usize,
    pub opened_row_count: usize,
    pub opened_row_width: usize,
    pub pcs_rcombi_tail_width: usize,
    pub pcs_subset_eval_width: usize,
    pub pcs_partial_eval_width: usize,
    pub opened_witness_invariant_column_count: usize,
    pub pcs_subset_invariant_column_count: usize,
    pub pcs_partial_invariant_column_count: usize,
    pub opened_witness_invariant_compaction_raw_bytes: usize,
    pub pcs_subset_invariant_compaction_raw_bytes: usize,
    pub pcs_partial_invariant_compaction_raw_bytes: usize,
    pub opened_witness_row_scalar_floor_raw_bytes: usize,
    pub opened_witness_partial_extra_slot_count: usize,
    pub opened_witness_partial_poly_count: usize,
    pub opened_witness_partial_raw_bytes: usize,
    pub subset_eval_shape_floor_raw_bytes: usize,
    pub subset_eval_shape_matches_beta_packing_identity: bool,
    pub decs_opened_leaf_count: usize,
    pub decs_distinct_leaf_count: usize,
    pub decs_duplicate_leaf_count: usize,
    pub decs_total_auth_nodes: usize,
    pub decs_unique_auth_nodes: usize,
    pub decs_duplicate_auth_nodes: usize,
    pub decs_min_auth_path_len: usize,
    pub decs_max_auth_path_len: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmallwoodLvcsPlannerGeometryKindV1 {
    CurrentTiledRowsV1,
    SharedPackingRowsProjectionV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodLvcsPlannerProjectionReportV1 {
    pub planner: SmallwoodLvcsPlannerGeometryKindV1,
    pub total_lvcs_cells: usize,
    pub nb_lvcs_rows: usize,
    pub nb_lvcs_cols: usize,
    pub nb_lvcs_opened_combi: usize,
    pub subset_eval_width: usize,
    pub projected_inner_proof_bytes: usize,
    pub soundness: SmallwoodNoGrindingSoundnessReportV1,
}

fn invariant_column_count_u64(matrix: &[Vec<u64>]) -> usize {
    let Some(first_row) = matrix.first() else {
        return 0;
    };
    let width = first_row.len();
    if matrix.iter().any(|row| row.len() != width) {
        return 0;
    }
    (0..width)
        .filter(|&col| {
            let first = first_row[col];
            matrix.iter().skip(1).all(|row| row[col] == first)
        })
        .count()
}

fn report_smallwood_no_grinding_soundness_from_cfg(
    cfg: &SmallwoodConfig,
    public_value_count: usize,
) -> SmallwoodNoGrindingSoundnessReportV1 {
    let profile = cfg.profile;
    let field_order = FIELD_ORDER as f64;
    let n_rows = cfg.nb_lvcs_rows;
    let n_cols = cfg.nb_lvcs_cols;
    let n_pcs = cfg.nb_polys;
    let d_q = cfg.mpol_poly_degree;
    let piop_consistency_degree = cfg
        .mpol_poly_degree
        .checked_add(cfg.packing_factor)
        .expect("validated SmallWood degree geometry");
    let piop_opening_domain_size = FIELD_ORDER
        .checked_sub(cfg.packing_factor as u64)
        .expect("packing domain is smaller than Goldilocks");
    let decs_degree = n_cols + profile.decs_nb_opened_evals - 1;
    let (epsilon1_floor_bits, epsilon1_model) = match cfg.decs_challenge_format {
        SmallwoodDecsChallengeFormat::ScalarPowers => (
            (profile.decs_eta as f64 * (field_order / n_rows as f64).log2()
                - log2_binomial(profile.decs_nb_evals as u128, decs_degree + 2))
            .max(0.0),
            SmallwoodDecsSoundnessModelV1::ScalarPowerSupportUnion,
        ),
        SmallwoodDecsChallengeFormat::Uniform => (
            profile.decs_eta as f64 * field_order.log2(),
            SmallwoodDecsSoundnessModelV1::UniformMatrixCommittedSupport,
        ),
    };
    // The active PIOP challenge is a full uniform rho-by-constraint matrix.
    let epsilon2 = field_order.powi(-(profile.rho as i32));
    let epsilon2_floor_bits = -epsilon2.log2();
    let epsilon3_floor_bits = log2_binom_ratio_large_over_small(
        piop_opening_domain_size as u128,
        piop_consistency_degree as u128,
        profile.nb_opened_evals,
    );
    let epsilon4_floor_bits = log2_binom_ratio_large_over_small(
        profile.decs_nb_evals as u128,
        (n_cols + profile.decs_nb_opened_evals - 1) as u128,
        profile.decs_nb_opened_evals,
    );
    let aggregate_error = (2.0f64.powf(-epsilon1_floor_bits)
        + epsilon2
        + 2.0f64.powf(-epsilon3_floor_bits)
        + 2.0f64.powf(-epsilon4_floor_bits))
    .min(1.0);
    let security_floor_bits = -aggregate_error.log2();
    let meets_128_bit_floor =
        smallwood_no_grinding_exact_aggregate_check_from_cfg(cfg, public_value_count, 128);
    let meets_256_bit_floor =
        smallwood_no_grinding_exact_aggregate_check_from_cfg(cfg, public_value_count, 256);
    let meets_260_bit_floor =
        smallwood_no_grinding_exact_aggregate_check_from_cfg(cfg, public_value_count, 260);
    SmallwoodNoGrindingSoundnessReportV1 {
        profile,
        n_pcs,
        d_q,
        n_rows,
        n_cols,
        epsilon1_model,
        epsilon1_floor_bits,
        epsilon2_floor_bits,
        epsilon3_floor_bits,
        epsilon4_floor_bits,
        security_floor_bits,
        meets_128_bit_floor,
        meets_256_bit_floor,
        meets_260_bit_floor,
    }
}

fn falling_product(n: u128, count: usize) -> Option<BigUint> {
    if n < count as u128 {
        return None;
    }
    Some((0..count).fold(BigUint::from(1u8), |product, index| {
        product * BigUint::from(n - index as u128)
    }))
}

fn binomial(n: u128, k: usize) -> Option<BigUint> {
    if n < k as u128 {
        return None;
    }
    let complement = n - k as u128;
    let reduced_k = if complement < k as u128 {
        usize::try_from(complement).ok()?
    } else {
        k
    };
    let mut value = BigUint::from(1u8);
    for index in 0..reduced_k {
        value *= BigUint::from(n - index as u128);
        value /= BigUint::from(index + 1);
    }
    Some(value)
}

fn smallwood_no_grinding_exact_terms_from_cfg(
    cfg: &SmallwoodConfig,
    _public_value_count: usize,
) -> Option<[(BigUint, BigUint); 4]> {
    let profile = cfg.profile;
    if profile.opening_pow_bits != 0
        || profile.decs_pow_bits != 0
        || cfg.constraint_degree == 0
        || profile.beta > u32::MAX as usize
        || profile.rho > u32::MAX as usize
        || profile.decs_eta > u32::MAX as usize
        || profile.rho == usize::MAX
        || profile.rho + 1 > u32::MAX as usize
    {
        return None;
    }

    let q = BigUint::from(FIELD_ORDER);
    let decs_degree = cfg
        .nb_lvcs_cols
        .checked_add(profile.decs_nb_opened_evals)?
        .checked_sub(1)?;
    let (decs_batching_numerator, decs_batching_denominator) = match cfg.decs_challenge_format {
        SmallwoodDecsChallengeFormat::ScalarPowers => (
            binomial(profile.decs_nb_evals as u128, decs_degree + 2)?
                * BigUint::from(cfg.nb_lvcs_rows).pow(profile.decs_eta as u32),
            q.pow(profile.decs_eta as u32),
        ),
        // `decs_commit` commits every row through `hash_mt` before
        // `derive_decs_challenge` samples the full independent matrix.  The
        // fixed-support theorem therefore bounds this event by one affine
        // fiber, `1 / |F|^eta`, with no support union.
        SmallwoodDecsChallengeFormat::Uniform => {
            (BigUint::from(1u8), q.pow(profile.decs_eta as u32))
        }
    };
    let epsilon1_numerator = decs_batching_numerator;
    let epsilon1_denominator = decs_batching_denominator;

    let epsilon2_numerator = BigUint::from(1u8);
    let epsilon2_denominator = q.pow(profile.rho as u32);
    // The verifier checks Q(e) = F(e) / Z(e) + M(e).  For a false claim,
    // Z * (Q - M) - F is a nonzero polynomial of degree at most
    // mpol_poly_degree + packing_factor.  Opening points are sampled without
    // replacement from the field outside the packing domain.
    let piop_consistency_degree = cfg.mpol_poly_degree.checked_add(cfg.packing_factor)?;
    let piop_opening_domain_size = (FIELD_ORDER as u128).checked_sub(cfg.packing_factor as u128)?;
    let epsilon3_numerator =
        falling_product(piop_consistency_degree as u128, profile.nb_opened_evals)?;
    let epsilon3_denominator = falling_product(piop_opening_domain_size, profile.nb_opened_evals)?;

    let decs_numerator_base = cfg
        .nb_lvcs_cols
        .checked_add(profile.decs_nb_opened_evals)
        .and_then(|value| value.checked_sub(1))?;
    let epsilon4_numerator =
        falling_product(decs_numerator_base as u128, profile.decs_nb_opened_evals)?;
    let epsilon4_denominator =
        falling_product(profile.decs_nb_evals as u128, profile.decs_nb_opened_evals)?;

    Some([
        (epsilon1_numerator, epsilon1_denominator),
        (epsilon2_numerator, epsilon2_denominator),
        (epsilon3_numerator, epsilon3_denominator),
        (epsilon4_numerator, epsilon4_denominator),
    ])
}

fn smallwood_no_grinding_exact_term_checks_from_cfg(
    cfg: &SmallwoodConfig,
    public_value_count: usize,
    security_bits: usize,
) -> [bool; 4] {
    let Some(terms) = smallwood_no_grinding_exact_terms_from_cfg(cfg, public_value_count) else {
        return [false; 4];
    };
    let scale = BigUint::from(1u8) << security_bits;
    std::array::from_fn(|index| &scale * &terms[index].0 <= terms[index].1)
}

fn smallwood_no_grinding_exact_aggregate_check_from_cfg(
    cfg: &SmallwoodConfig,
    public_value_count: usize,
    security_bits: usize,
) -> bool {
    let Some(terms) = smallwood_no_grinding_exact_terms_from_cfg(cfg, public_value_count) else {
        return false;
    };
    let common_denominator = terms
        .iter()
        .fold(BigUint::from(1u8), |product, (_, denominator)| {
            product * denominator
        });
    let aggregate_numerator = terms
        .iter()
        .fold(BigUint::from(0u8), |sum, (numerator, denominator)| {
            sum + numerator * (&common_denominator / denominator)
        });
    let scale = BigUint::from(1u8) << security_bits;
    scale * aggregate_numerator <= common_denominator
}

fn smallwood_no_grinding_exact_128_bit_aggregate_check_from_cfg(
    cfg: &SmallwoodConfig,
    public_value_count: usize,
) -> bool {
    smallwood_no_grinding_exact_aggregate_check_from_cfg(cfg, public_value_count, 128)
}

fn project_lvcs_planner_geometry_cfg(
    cfg: &SmallwoodConfig,
    planner: SmallwoodLvcsPlannerGeometryKindV1,
) -> Result<SmallwoodConfig, TransactionCircuitError> {
    let mut projected = cfg.clone();
    match planner {
        SmallwoodLvcsPlannerGeometryKindV1::CurrentTiledRowsV1 => {}
        SmallwoodLvcsPlannerGeometryKindV1::SharedPackingRowsProjectionV1 => {
            let total_lvcs_cells = cfg.nb_unstacked_rows.saturating_mul(cfg.nb_unstacked_cols);
            projected.nb_lvcs_rows = cfg
                .packing_factor
                .saturating_add(cfg.beta().saturating_mul(cfg.nb_opened_evals()));
            if projected.nb_lvcs_rows < projected.nb_lvcs_opened_combi {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood projected LVCS planner underflows opened combis",
                ));
            }
            projected.nb_lvcs_cols = total_lvcs_cells.div_ceil(projected.nb_lvcs_rows);
            projected.fullrank_cols = (0..projected.nb_lvcs_opened_combi).collect();
        }
    }
    Ok(projected)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodNoGrindingSoundnessReportV1 {
    pub profile: SmallwoodNoGrindingProfileV1,
    pub n_pcs: usize,
    pub d_q: usize,
    pub n_rows: usize,
    pub n_cols: usize,
    pub epsilon1_model: SmallwoodDecsSoundnessModelV1,
    pub epsilon1_floor_bits: f64,
    pub epsilon2_floor_bits: f64,
    pub epsilon3_floor_bits: f64,
    pub epsilon4_floor_bits: f64,
    pub security_floor_bits: f64,
    pub meets_128_bit_floor: bool,
    pub meets_256_bit_floor: bool,
    pub meets_260_bit_floor: bool,
}

const SMALLWOOD_PROOF_WIRE_MAGIC_V1: [u8; 4] = *b"SMW1";
const SMALLWOOD_PROOF_WIRE_MAGIC_LEVEL5: [u8; 4] = *b"SMW2";
pub const SMALLWOOD_PROOF_WIRE_MAGIC_FULL_SHA512_FIRST48_COMMITMENT_V3: [u8; 4] = *b"SMW3";
/// Inactive inner-wire research identity for the fixed 23-opening,
/// disjoint-coset, index-bound, independent-512-bit-leaf-tape construction. It
/// is not a V6 envelope or a production authorization and cannot be decoded as
/// the historical `SMW2`.
const SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V1: [u8; 4] = *b"SMZ1";
/// Inactive fresh-domain V6 inner-wire identity. It preserves the exact SMZ1
/// payload grammar but cannot be interpreted by the historical Level-5
/// transcript backend.
pub const SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V2: [u8; 4] = *b"SMZ2";
/// Fresh compact V8 inner proof.  The payload remains the compact SmallWood
/// grammar, but its query/tape count and transcript identity are SMZ8-only.
pub const SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8: [u8; 4] = *b"SMZ8";
/// Additive q=20/open=6 V8 successor.  The distinct magic is consensus-visible
/// and makes every historical SMZ8 proof fail before payload allocation.
pub const SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9: [u8; 4] = *b"SMZ9";
/// Inactive compact profile-7 inner proof. The selector is append-only and is
/// never accepted by the SMZ8 or SMZ9 decoders.
pub const SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7: [u8; 4] = *b"SMC7";
/// Inactive q=20/448-bit sibling. It is never accepted as SMZ9 or SMC7.
pub const SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8: [u8; 4] = *b"SMC8";
const SMALLWOOD_OPENED_WITNESS_MODE_NONE_V1: u8 = 0;
const SMALLWOOD_OPENED_WITNESS_MODE_ROW_SCALARS_V1: u8 = 1;

impl SmallwoodProofWireIdentityV1 {
    const fn digest_bytes(self) -> usize {
        match self {
            Self::LegacySmw1 => LEGACY_DIGEST_BYTES,
            Self::FullSha512First48CommitmentSmw3 => {
                SMALLWOOD_FULL_SHA512_FIRST48_COMMITMENT_BYTES_V3
            }
            Self::Sha512Level5Smw2
            | Self::StrictZkSha512Level5Smz1
            | Self::StrictZkSha512V6Smz2
            | Self::StrictZkSha512Poseidon2V8Smz8
            | Self::StrictZkSha512Poseidon2V8Smz9
            | Self::FreshHx512Candidate => DIGEST_BYTES,
            Self::StrictZkSha512Poseidon2V8Compact448Smc7
            | Self::StrictZkSha512Poseidon2V8Compact448Q20Smc8 => {
                SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES
            }
        }
    }

    const fn magic(self) -> &'static [u8; 4] {
        match self {
            Self::LegacySmw1 => &SMALLWOOD_PROOF_WIRE_MAGIC_V1,
            Self::Sha512Level5Smw2 => &SMALLWOOD_PROOF_WIRE_MAGIC_LEVEL5,
            Self::FullSha512First48CommitmentSmw3 => {
                &SMALLWOOD_PROOF_WIRE_MAGIC_FULL_SHA512_FIRST48_COMMITMENT_V3
            }
            Self::StrictZkSha512Level5Smz1 => &SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V1,
            Self::StrictZkSha512V6Smz2 => &SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V2,
            Self::StrictZkSha512Poseidon2V8Smz8 => &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8,
            Self::StrictZkSha512Poseidon2V8Smz9 => &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9,
            Self::StrictZkSha512Poseidon2V8Compact448Smc7 => {
                &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7
            }
            Self::StrictZkSha512Poseidon2V8Compact448Q20Smc8 => {
                &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8
            }
            Self::FreshHx512Candidate => {
                panic!("fresh HX512 core proofs have a separate inner-wire encoder")
            }
        }
    }
}

fn push_u8_v1(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn push_u16_v1(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_v1(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_v1(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_field_word_v1(out: &mut Vec<u8>, value: u64) -> Result<(), TransactionCircuitError> {
    if value >= FIELD_ORDER {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof field element is not canonically encoded",
        ));
    }
    push_u64_v1(out, value);
    Ok(())
}

fn read_exact_v1<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], TransactionCircuitError> {
    let end = cursor
        .checked_add(len)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood proof cursor overflow",
        ))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood proof underflow",
        ))?;
    *cursor = end;
    Ok(slice)
}

fn read_u8_v1(bytes: &[u8], cursor: &mut usize) -> Result<u8, TransactionCircuitError> {
    Ok(*read_exact_v1(bytes, cursor, 1)?.first().ok_or(
        TransactionCircuitError::ConstraintViolation("smallwood proof missing byte"),
    )?)
}

fn read_u16_v1(bytes: &[u8], cursor: &mut usize) -> Result<u16, TransactionCircuitError> {
    let mut word = [0u8; 2];
    word.copy_from_slice(read_exact_v1(bytes, cursor, 2)?);
    Ok(u16::from_le_bytes(word))
}

fn read_u32_v1(bytes: &[u8], cursor: &mut usize) -> Result<u32, TransactionCircuitError> {
    let mut word = [0u8; 4];
    word.copy_from_slice(read_exact_v1(bytes, cursor, 4)?);
    Ok(u32::from_le_bytes(word))
}

fn read_u64_v1(bytes: &[u8], cursor: &mut usize) -> Result<u64, TransactionCircuitError> {
    let mut word = [0u8; 8];
    word.copy_from_slice(read_exact_v1(bytes, cursor, 8)?);
    Ok(u64::from_le_bytes(word))
}

fn read_field_word_v1(bytes: &[u8], cursor: &mut usize) -> Result<u64, TransactionCircuitError> {
    let value = read_u64_v1(bytes, cursor)?;
    if value >= FIELD_ORDER {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof field element is not canonically encoded",
        ));
    }
    Ok(value)
}

fn shape_u16_v1(matrix: &[Vec<u64>]) -> Result<(u16, u16), TransactionCircuitError> {
    if matrix.len() > MAX_SMALLWOOD_COMPACT_COLLECTION_ROWS_V1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix row count exceeds supported profile maximum",
        ));
    }
    let rows = u16::try_from(matrix.len()).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix row count exceeds compact wire limit",
        )
    })?;
    let cols = matrix.first().map_or(0usize, |row| row.len());
    if matrix.iter().any(|row| row.len() != cols) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix row width mismatch",
        ));
    }
    let cols = u16::try_from(cols).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix column count exceeds compact wire limit",
        )
    })?;
    if (rows == 0) != (cols == 0) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix must have either two zero dimensions or two non-zero dimensions",
        ));
    }
    Ok((rows, cols))
}

fn encoded_matrix_u64_bytes_v1(matrix: &[Vec<u64>]) -> Result<usize, TransactionCircuitError> {
    let (rows, cols) = shape_u16_v1(matrix)?;
    Ok(4 + rows as usize * cols as usize * std::mem::size_of::<u64>())
}

fn encode_matrix_u64_v1(
    out: &mut Vec<u8>,
    matrix: &[Vec<u64>],
) -> Result<(), TransactionCircuitError> {
    let (rows, cols) = shape_u16_v1(matrix)?;
    push_u16_v1(out, rows);
    push_u16_v1(out, cols);
    for row in matrix {
        for &value in row {
            push_field_word_v1(out, value)?;
        }
    }
    Ok(())
}

fn decode_matrix_u64_v1(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let rows = read_u16_v1(bytes, cursor)? as usize;
    let cols = read_u16_v1(bytes, cursor)? as usize;
    if rows > MAX_SMALLWOOD_COMPACT_COLLECTION_ROWS_V1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix row count exceeds supported profile maximum",
        ));
    }
    if (rows == 0) != (cols == 0) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix must have either two zero dimensions or two non-zero dimensions",
        ));
    }
    let encoded_bytes = rows
        .checked_mul(cols)
        .and_then(|values| values.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix dimensions overflow encoded length",
        ))?;
    if encoded_bytes > bytes.len().saturating_sub(*cursor) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof matrix dimensions exceed remaining bytes",
        ));
    }
    let mut out = Vec::with_capacity(rows);
    for _ in 0..rows {
        let mut row = Vec::with_capacity(cols);
        for _ in 0..cols {
            row.push(read_field_word_v1(bytes, cursor)?);
        }
        out.push(row);
    }
    Ok(out)
}

fn encoded_auth_paths_bytes_v1(
    paths: &[Vec<[u8; DIGEST_BYTES]>],
    digest_bytes: usize,
) -> Result<usize, TransactionCircuitError> {
    if !matches!(
        digest_bytes,
        LEGACY_DIGEST_BYTES
            | SMALLWOOD_FULL_SHA512_FIRST48_COMMITMENT_BYTES_V3
            | SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES
            | DIGEST_BYTES
    ) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof digest width is unsupported",
        ));
    }
    if paths.len() > MAX_SMALLWOOD_COMPACT_COLLECTION_ROWS_V1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path count exceeds supported profile maximum",
        ));
    }
    let rows = u16::try_from(paths.len()).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path count exceeds compact wire limit",
        )
    })?;
    for path in paths {
        u8::try_from(path.len()).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "smallwood proof auth-path length exceeds compact wire limit",
            )
        })?;
    }
    let total_nodes = paths.iter().map(|path| path.len()).sum::<usize>();
    Ok(2 + rows as usize + total_nodes * digest_bytes)
}

fn encode_auth_paths_v1(
    out: &mut Vec<u8>,
    paths: &[Vec<[u8; DIGEST_BYTES]>],
    digest_bytes: usize,
) -> Result<(), TransactionCircuitError> {
    encoded_auth_paths_bytes_v1(paths, digest_bytes)?;
    let rows = u16::try_from(paths.len()).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path count exceeds compact wire limit",
        )
    })?;
    push_u16_v1(out, rows);
    for path in paths {
        push_u8_v1(
            out,
            u8::try_from(path.len()).map_err(|_| {
                TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auth-path length exceeds compact wire limit",
                )
            })?,
        );
    }
    for path in paths {
        for node in path {
            out.extend_from_slice(&node[..digest_bytes]);
        }
    }
    Ok(())
}

fn decode_auth_paths_v1(
    bytes: &[u8],
    cursor: &mut usize,
    digest_bytes: usize,
    expected_rows: Option<usize>,
    maximum_depth: Option<usize>,
) -> Result<Vec<Vec<[u8; DIGEST_BYTES]>>, TransactionCircuitError> {
    if !matches!(
        digest_bytes,
        LEGACY_DIGEST_BYTES
            | SMALLWOOD_FULL_SHA512_FIRST48_COMMITMENT_BYTES_V3
            | SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES
            | DIGEST_BYTES
    ) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof digest width is unsupported",
        ));
    }
    let rows = read_u16_v1(bytes, cursor)? as usize;
    if rows > MAX_SMALLWOOD_COMPACT_COLLECTION_ROWS_V1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path count exceeds supported profile maximum",
        ));
    }
    if expected_rows.is_some_and(|expected| rows != expected) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path count does not match its wire identity",
        ));
    }
    let mut lengths = Vec::with_capacity(rows);
    for _ in 0..rows {
        let length = read_u8_v1(bytes, cursor)? as usize;
        if maximum_depth.is_some_and(|maximum| length > maximum) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood proof auth-path length exceeds its wire profile depth",
            ));
        }
        lengths.push(length);
    }
    let encoded_bytes = lengths
        .iter()
        .try_fold(0usize, |total, length| total.checked_add(*length))
        .and_then(|nodes| nodes.checked_mul(digest_bytes))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path dimensions overflow encoded length",
        ))?;
    if encoded_bytes > bytes.len().saturating_sub(*cursor) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path dimensions exceed remaining bytes",
        ));
    }
    let mut out = Vec::with_capacity(rows);
    for len in lengths {
        let mut path = Vec::with_capacity(len);
        for _ in 0..len {
            let mut node = [0u8; DIGEST_BYTES];
            node[..digest_bytes].copy_from_slice(read_exact_v1(bytes, cursor, digest_bytes)?);
            path.push(node);
        }
        out.push(path);
    }
    Ok(out)
}

fn encoded_opened_witness_bytes_v1(
    opened_witness: &SmallwoodOpenedWitnessBundle,
) -> Result<usize, TransactionCircuitError> {
    Ok(match &opened_witness.mode {
        SmallwoodOpenedWitnessMode::None => 1,
        SmallwoodOpenedWitnessMode::RowScalars {
            row_scalars,
            auxiliary_words,
            ..
        } => {
            let count = u32::try_from(auxiliary_words.len()).map_err(|_| {
                TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auxiliary witness count exceeds compact wire limit",
                )
            })?;
            1 + encoded_matrix_u64_bytes_v1(row_scalars)? + 8 + count as usize * 8
        }
    })
}

fn encode_opened_witness_v1(
    out: &mut Vec<u8>,
    opened_witness: &SmallwoodOpenedWitnessBundle,
) -> Result<(), TransactionCircuitError> {
    match &opened_witness.mode {
        SmallwoodOpenedWitnessMode::None => {
            push_u8_v1(out, SMALLWOOD_OPENED_WITNESS_MODE_NONE_V1);
        }
        SmallwoodOpenedWitnessMode::RowScalars {
            row_scalars,
            auxiliary_words,
            auxiliary_limb_count,
        } => {
            let aux_count = u32::try_from(auxiliary_words.len()).map_err(|_| {
                TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auxiliary witness count exceeds compact wire limit",
                )
            })?;
            let aux_limb_count = u32::try_from(*auxiliary_limb_count).map_err(|_| {
                TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auxiliary limb count exceeds compact wire limit",
                )
            })?;
            if aux_limb_count > aux_count {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auxiliary limb count exceeds word count",
                ));
            }
            push_u8_v1(out, SMALLWOOD_OPENED_WITNESS_MODE_ROW_SCALARS_V1);
            encode_matrix_u64_v1(out, row_scalars)?;
            push_u32_v1(out, aux_count);
            push_u32_v1(out, aux_limb_count);
            for &word in auxiliary_words {
                push_field_word_v1(out, word)?;
            }
        }
    }
    Ok(())
}

fn decode_opened_witness_v1(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<SmallwoodOpenedWitnessBundle, TransactionCircuitError> {
    match read_u8_v1(bytes, cursor)? {
        SMALLWOOD_OPENED_WITNESS_MODE_NONE_V1 => Ok(SmallwoodOpenedWitnessBundle {
            mode: SmallwoodOpenedWitnessMode::None,
        }),
        SMALLWOOD_OPENED_WITNESS_MODE_ROW_SCALARS_V1 => {
            let row_scalars = decode_matrix_u64_v1(bytes, cursor)?;
            let auxiliary_word_count = read_u32_v1(bytes, cursor)? as usize;
            let auxiliary_limb_count = read_u32_v1(bytes, cursor)? as usize;
            if auxiliary_limb_count > auxiliary_word_count {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auxiliary limb count exceeds word count",
                ));
            }
            let encoded_bytes = auxiliary_word_count
                .checked_mul(std::mem::size_of::<u64>())
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auxiliary witness count overflows encoded length",
                ))?;
            if encoded_bytes > bytes.len().saturating_sub(*cursor) {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood proof auxiliary witness count exceeds remaining bytes",
                ));
            }
            let mut auxiliary_words = Vec::with_capacity(auxiliary_word_count);
            for _ in 0..auxiliary_word_count {
                auxiliary_words.push(read_field_word_v1(bytes, cursor)?);
            }
            Ok(SmallwoodOpenedWitnessBundle::row_scalars(
                row_scalars,
                auxiliary_words,
                auxiliary_limb_count,
            ))
        }
        _ => Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof opened-witness mode tag mismatch",
        )),
    }
}

fn encode_pcs_proof_v1(
    out: &mut Vec<u8>,
    proof: &PcsProof,
    digest_bytes: usize,
    wire_identity: SmallwoodProofWireIdentityV1,
) -> Result<(), TransactionCircuitError> {
    encode_matrix_u64_v1(out, &proof.rcombi_tails)?;
    encode_matrix_u64_v1(out, &proof.subset_evals)?;
    encode_matrix_u64_v1(out, &proof.partial_evals)?;
    if wire_identity
        .maximum_auth_path_depth()
        .is_some_and(|maximum| {
            proof
                .decs
                .auth_paths
                .iter()
                .any(|path| path.len() > maximum)
        })
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof auth-path length exceeds its wire profile depth",
        ));
    }
    encode_auth_paths_v1(out, &proof.decs.auth_paths, digest_bytes)?;
    if let Some((opened_leaf_count, tape_bytes)) = wire_identity.opened_leaf_tape_profile() {
        if proof.decs.auth_paths.len() != opened_leaf_count {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict wire has a non-canonical opened DECS leaf count",
            ));
        }
        if proof.decs.leaf_tapes.len() != opened_leaf_count {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict wire has a non-canonical DECS leaf-tape count",
            ));
        }
        for tape in &proof.decs.leaf_tapes {
            if tape.len() != tape_bytes {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood strict wire has a non-canonical DECS leaf-tape width",
                ));
            }
            out.extend_from_slice(tape);
        }
    } else if !proof.decs.leaf_tapes.is_empty() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood legacy proof cannot serialize DECS leaf tapes",
        ));
    }
    encode_matrix_u64_v1(out, &proof.decs.masking_evals)?;
    encode_matrix_u64_v1(out, &proof.decs.high_coeffs)?;
    Ok(())
}

fn decode_pcs_proof_v1(
    bytes: &[u8],
    cursor: &mut usize,
    digest_bytes: usize,
    wire_identity: SmallwoodProofWireIdentityV1,
) -> Result<PcsProof, TransactionCircuitError> {
    let rcombi_tails = decode_matrix_u64_v1(bytes, cursor)?;
    let subset_evals = decode_matrix_u64_v1(bytes, cursor)?;
    let partial_evals = decode_matrix_u64_v1(bytes, cursor)?;
    let tape_profile = wire_identity.opened_leaf_tape_profile();
    let auth_paths = decode_auth_paths_v1(
        bytes,
        cursor,
        digest_bytes,
        tape_profile.map(|profile| profile.0),
        wire_identity.maximum_auth_path_depth(),
    )?;
    let leaf_tapes = if let Some((opened_leaf_count, tape_bytes)) = tape_profile {
        let encoded_tape_bytes = opened_leaf_count.checked_mul(tape_bytes).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "smallwood strict leaf-tape payload length overflow",
            ),
        )?;
        if encoded_tape_bytes > bytes.len().saturating_sub(*cursor) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict leaf-tape payload exceeds remaining bytes",
            ));
        }
        let mut tapes = Vec::with_capacity(opened_leaf_count);
        for _ in 0..opened_leaf_count {
            tapes.push(read_exact_v1(bytes, cursor, tape_bytes)?.to_vec());
        }
        tapes
    } else {
        Vec::new()
    };
    Ok(PcsProof {
        rcombi_tails,
        subset_evals,
        partial_evals,
        decs: DecsProof {
            auth_paths,
            leaf_tapes,
            masking_evals: decode_matrix_u64_v1(bytes, cursor)?,
            high_coeffs: decode_matrix_u64_v1(bytes, cursor)?,
        },
    })
}

fn encode_smallwood_proof_bytes_v1(
    proof: &SmallwoodProof,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if proof.wire_identity == SmallwoodProofWireIdentityV1::FreshHx512Candidate {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 core proof cannot be encoded as an SMW/SMZ wire",
        ));
    }
    if proof.hx512_decs_root.is_some() || proof.hx512_piop_input_digest.is_some() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "historical SMW/SMZ wires forbid fresh HX512 prefix fields",
        ));
    }
    if proof.salt.len() != SALT_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "historical smallwood wire requires an exact 32-byte salt",
        ));
    }
    if !matches!(
        proof.digest_bytes,
        LEGACY_DIGEST_BYTES
            | SMALLWOOD_FULL_SHA512_FIRST48_COMMITMENT_BYTES_V3
            | SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES
            | DIGEST_BYTES
    ) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof digest width is unsupported",
        ));
    }
    if proof.strict_zk_decs_leaf_hiding
        && proof.digest_bytes != DIGEST_BYTES
        && !(proof.wire_identity
            == SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7
            && proof.digest_bytes == SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES)
        && !(proof.wire_identity
            == SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8
            && proof.digest_bytes == SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK proof requires full-width SHA-512 commitments",
        ));
    }
    if proof.digest_bytes != proof.wire_identity.digest_bytes()
        || proof.strict_zk_decs_leaf_hiding != proof.wire_identity.is_strict_zk()
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof payload does not match its exact wire identity",
        ));
    }
    if proof.h_piop[proof.digest_bytes..]
        .iter()
        .any(|byte| *byte != 0)
        || proof
            .pcs
            .decs
            .auth_paths
            .iter()
            .flatten()
            .any(|node| node[proof.digest_bytes..].iter().any(|byte| *byte != 0))
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof digest tail must be zero outside the serialized width",
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(proof.wire_identity.magic());
    out.extend_from_slice(&proof.salt);
    out.extend_from_slice(&proof.nonce);
    out.extend_from_slice(&proof.h_piop[..proof.digest_bytes]);
    encode_matrix_u64_v1(&mut out, &proof.piop.ppol_highs)?;
    encode_matrix_u64_v1(&mut out, &proof.piop.plin_highs)?;
    encode_pcs_proof_v1(
        &mut out,
        &proof.pcs,
        proof.digest_bytes,
        proof.wire_identity,
    )?;
    encode_opened_witness_v1(&mut out, &proof.opened_witness)?;
    if matches!(
        proof.wire_identity,
        SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8
            | SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9
    ) && out.len() > SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ8/SMZ9 inner proof exceeds the 131072-byte cap",
        ));
    }
    if proof.wire_identity == SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7
        && out.len() > SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC7 inner proof exceeds the exact 117702-byte cap",
        ));
    }
    if proof.wire_identity
        == SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8
        && out.len() > SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC8 inner proof exceeds the exact 119879-byte cap",
        ));
    }
    Ok(out)
}

fn decode_smallwood_proof_bytes_prefix_v1(
    proof_bytes: &[u8],
) -> Result<(SmallwoodProof, usize), TransactionCircuitError> {
    let mut cursor = 0usize;
    let magic = read_exact_v1(
        proof_bytes,
        &mut cursor,
        SMALLWOOD_PROOF_WIRE_MAGIC_V1.len(),
    )?;
    let wire_identity = if magic == SMALLWOOD_PROOF_WIRE_MAGIC_V1 {
        SmallwoodProofWireIdentityV1::LegacySmw1
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_LEVEL5 {
        SmallwoodProofWireIdentityV1::Sha512Level5Smw2
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_FULL_SHA512_FIRST48_COMMITMENT_V3 {
        SmallwoodProofWireIdentityV1::FullSha512First48CommitmentSmw3
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V1 {
        SmallwoodProofWireIdentityV1::StrictZkSha512Level5Smz1
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V2 {
        SmallwoodProofWireIdentityV1::StrictZkSha512V6Smz2
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8 {
        SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9 {
        SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7 {
        SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7
    } else if magic == SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8 {
        SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8
    } else {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof wire magic mismatch",
        ));
    };
    if matches!(
        wire_identity,
        SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8
            | SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9
    ) && proof_bytes.len() > SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ8/SMZ9 inner proof exceeds the 131072-byte cap",
        ));
    }
    if wire_identity == SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7
        && proof_bytes.len() > SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC7 inner proof exceeds the exact 117702-byte cap",
        ));
    }
    if wire_identity == SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8
        && proof_bytes.len() > SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC8 inner proof exceeds the exact 119879-byte cap",
        ));
    }
    let digest_bytes = wire_identity.digest_bytes();
    let strict_zk_decs_leaf_hiding = wire_identity.is_strict_zk();
    let salt = read_exact_v1(proof_bytes, &mut cursor, SALT_BYTES)?.to_vec();
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(read_exact_v1(proof_bytes, &mut cursor, NONCE_BYTES)?);
    let mut h_piop = [0u8; DIGEST_BYTES];
    h_piop[..digest_bytes].copy_from_slice(read_exact_v1(proof_bytes, &mut cursor, digest_bytes)?);
    let ppol_highs = decode_matrix_u64_v1(proof_bytes, &mut cursor)?;
    let plin_highs = decode_matrix_u64_v1(proof_bytes, &mut cursor)?;
    let pcs = decode_pcs_proof_v1(proof_bytes, &mut cursor, digest_bytes, wire_identity)?;
    let opened_witness = decode_opened_witness_v1(proof_bytes, &mut cursor)?;
    Ok((
        SmallwoodProof {
            wire_identity,
            digest_bytes,
            strict_zk_decs_leaf_hiding,
            hx512_decs_root: None,
            hx512_piop_input_digest: None,
            salt,
            nonce,
            h_piop,
            piop: PiopProof {
                ppol_highs,
                plin_highs,
            },
            pcs,
            opened_witness,
        },
        cursor,
    ))
}

fn decode_smallwood_proof_bytes_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProof, TransactionCircuitError> {
    let (proof, cursor) = decode_smallwood_proof_bytes_prefix_v1(proof_bytes)?;
    if cursor != proof_bytes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof trailing bytes",
        ));
    }
    Ok(proof)
}

pub fn decode_smallwood_smz2_proof_trace_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProofTraceV1, TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    if proof.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512V6Smz2 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood fresh V6 transcript requires exact SMZ2 inner-wire identity",
        ));
    }
    smallwood_proof_to_trace_v1(&proof)
}

fn push_u32_hx512(out: &mut Vec<u8>, value: usize) -> Result<(), TransactionCircuitError> {
    let value = u32::try_from(value).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "fresh HX512 dimension does not fit canonical u32",
        )
    })?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn read_u32_hx512(bytes: &[u8], cursor: &mut usize) -> Result<usize, TransactionCircuitError> {
    let mut word = [0u8; 4];
    word.copy_from_slice(read_exact_v1(bytes, cursor, 4)?);
    Ok(u32::from_be_bytes(word) as usize)
}

fn push_field_word_hx512(out: &mut Vec<u8>, value: u64) -> Result<(), TransactionCircuitError> {
    if value >= FIELD_ORDER {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 field element is not canonically encoded",
        ));
    }
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn read_field_word_hx512(bytes: &[u8], cursor: &mut usize) -> Result<u64, TransactionCircuitError> {
    let mut word = [0u8; 8];
    word.copy_from_slice(read_exact_v1(bytes, cursor, 8)?);
    let value = u64::from_be_bytes(word);
    if value >= FIELD_ORDER {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 field element is not canonically encoded",
        ));
    }
    Ok(value)
}

fn encode_matrix_u64_hx512(
    out: &mut Vec<u8>,
    matrix: &[Vec<u64>],
    expected_rows: usize,
    expected_cols: usize,
) -> Result<(), TransactionCircuitError> {
    if matrix.len() != expected_rows
        || matrix.iter().any(|row| row.len() != expected_cols)
        || expected_rows == 0
        || expected_cols == 0
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 matrix does not match the profile-bound dimensions",
        ));
    }
    push_u32_hx512(out, expected_rows)?;
    push_u32_hx512(out, expected_cols)?;
    for row in matrix {
        for &value in row {
            push_field_word_hx512(out, value)?;
        }
    }
    Ok(())
}

fn decode_matrix_u64_hx512(
    bytes: &[u8],
    cursor: &mut usize,
    expected_rows: usize,
    expected_cols: usize,
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let rows = read_u32_hx512(bytes, cursor)?;
    let cols = read_u32_hx512(bytes, cursor)?;
    if rows != expected_rows || cols != expected_cols || rows == 0 || cols == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 matrix header does not match the profile-bound dimensions",
        ));
    }
    let encoded_bytes = rows
        .checked_mul(cols)
        .and_then(|count| count.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 matrix dimensions overflow encoded length",
        ))?;
    if encoded_bytes > bytes.len().saturating_sub(*cursor) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 matrix dimensions exceed remaining bytes",
        ));
    }
    let mut matrix = Vec::with_capacity(rows);
    for _ in 0..rows {
        let mut row = Vec::with_capacity(cols);
        for _ in 0..cols {
            row.push(read_field_word_hx512(bytes, cursor)?);
        }
        matrix.push(row);
    }
    Ok(matrix)
}

fn encode_auth_paths_hx512(
    out: &mut Vec<u8>,
    paths: &[Vec<[u8; DIGEST_BYTES]>],
    expected_count: usize,
    maximum_depth: usize,
) -> Result<(), TransactionCircuitError> {
    if paths.len() != expected_count
        || paths
            .iter()
            .any(|path| path.is_empty() || path.len() > maximum_depth)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 authentication paths do not match the profile-bound shape",
        ));
    }
    push_u32_hx512(out, expected_count)?;
    for path in paths {
        push_u32_hx512(out, path.len())?;
    }
    for path in paths {
        for node in path {
            out.extend_from_slice(node);
        }
    }
    Ok(())
}

fn decode_auth_paths_hx512(
    bytes: &[u8],
    cursor: &mut usize,
    expected_count: usize,
    maximum_depth: usize,
) -> Result<Vec<Vec<[u8; DIGEST_BYTES]>>, TransactionCircuitError> {
    let count = read_u32_hx512(bytes, cursor)?;
    if count != expected_count || count == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 authentication-path count mismatch",
        ));
    }
    let mut lengths = Vec::with_capacity(count);
    for _ in 0..count {
        let length = read_u32_hx512(bytes, cursor)?;
        if length == 0 || length > maximum_depth {
            return Err(TransactionCircuitError::ConstraintViolation(
                "fresh HX512 authentication-path length exceeds the profile bound",
            ));
        }
        lengths.push(length);
    }
    let encoded_bytes = lengths
        .iter()
        .try_fold(0usize, |total, length| total.checked_add(*length))
        .and_then(|nodes| nodes.checked_mul(DIGEST_BYTES))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 authentication-path dimensions overflow encoded length",
        ))?;
    if encoded_bytes > bytes.len().saturating_sub(*cursor) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 authentication paths exceed remaining bytes",
        ));
    }
    let mut paths = Vec::with_capacity(count);
    for length in lengths {
        let mut path = Vec::with_capacity(length);
        for _ in 0..length {
            let mut node = [0u8; DIGEST_BYTES];
            node.copy_from_slice(read_exact_v1(bytes, cursor, DIGEST_BYTES)?);
            path.push(node);
        }
        paths.push(path);
    }
    Ok(paths)
}

/// Encode only the LPPC/PIOP/DECS response payload for the fresh HX512 inner
/// wire. The authoritative 64-byte salt is outer-wire owned and deliberately
/// not duplicated here. Historical SMW/SMZ codecs never call this function.
/// Every response matrix uses fresh-only u32-big-endian dimensions followed
/// by canonical Goldilocks u64-big-endian cells.
pub(crate) fn encode_smallwood_hx512_core_payload(
    proof: &SmallwoodProof,
    geometry: &SmallwoodCoreGeometryV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if proof.wire_identity != SmallwoodProofWireIdentityV1::FreshHx512Candidate
        || proof.digest_bytes != DIGEST_BYTES
        || !proof.strict_zk_decs_leaf_hiding
        || proof.salt.len() != crate::smallwood_hx512_transcript::HX512_SALT_BYTES
        || proof.nonce != [0u8; NONCE_BYTES]
        || proof.hx512_decs_root.is_none()
        || proof.hx512_piop_input_digest.is_none()
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 core proof metadata mismatch",
        ));
    }
    let opened_leaf_count = HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals;
    let leaf_tape_bytes = HX512_PROFILE_LEAF_TAPE_BYTES;
    if proof.pcs.decs.auth_paths.len() != opened_leaf_count
        || proof.pcs.decs.leaf_tapes.len() != opened_leaf_count
        || proof
            .pcs
            .decs
            .leaf_tapes
            .iter()
            .any(|tape| tape.len() != leaf_tape_bytes)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 core DECS opening/tape shape mismatch",
        ));
    }
    if !proof
        .opened_witness
        .auxiliary_words_ref()
        .unwrap_or(&[])
        .is_empty()
        || proof.opened_witness.auxiliary_limb_count() != 0
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 core forbids auxiliary witness words",
        ));
    }
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "fresh HX512 core requires row-scalar opened witness data",
        ),
    )?;
    let mut out = Vec::new();
    out.extend_from_slice(proof.hx512_decs_root.as_ref().expect("checked HX512 root"));
    out.extend_from_slice(
        proof
            .hx512_piop_input_digest
            .as_ref()
            .expect("checked HX512 PIOP-input digest"),
    );
    out.extend_from_slice(&proof.h_piop);
    encode_matrix_u64_hx512(
        &mut out,
        &proof.piop.ppol_highs,
        geometry.ppol_high_rows,
        geometry.ppol_high_cols,
    )?;
    encode_matrix_u64_hx512(
        &mut out,
        &proof.piop.plin_highs,
        geometry.plin_high_rows,
        geometry.plin_high_cols,
    )?;
    encode_matrix_u64_hx512(
        &mut out,
        &proof.pcs.rcombi_tails,
        geometry.rcombi_rows,
        geometry.rcombi_cols,
    )?;
    encode_matrix_u64_hx512(
        &mut out,
        &proof.pcs.subset_evals,
        geometry.subset_rows,
        geometry.subset_cols,
    )?;
    encode_matrix_u64_hx512(
        &mut out,
        &proof.pcs.partial_evals,
        geometry.partial_rows,
        geometry.partial_cols,
    )?;
    encode_auth_paths_hx512(
        &mut out,
        &proof.pcs.decs.auth_paths,
        opened_leaf_count,
        HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals.ilog2() as usize,
    )?;
    for tape in &proof.pcs.decs.leaf_tapes {
        out.extend_from_slice(tape);
    }
    encode_matrix_u64_hx512(
        &mut out,
        &proof.pcs.decs.masking_evals,
        geometry.masking_rows,
        geometry.masking_cols,
    )?;
    encode_matrix_u64_hx512(
        &mut out,
        &proof.pcs.decs.high_coeffs,
        geometry.high_rows,
        geometry.high_cols,
    )?;
    encode_matrix_u64_hx512(
        &mut out,
        row_scalars,
        geometry.opened_witness_rows,
        geometry.opened_witness_cols,
    )?;
    Ok(out)
}

/// Decode the fresh HX512 core only after the caller has checked the complete
/// inner-frame length against its profile cap. All matrix dimensions remain
/// self-describing for canonical parsing and are checked against the derived
/// engine configuration before verification.
pub(crate) fn decode_smallwood_hx512_core_payload(
    payload: &[u8],
    authoritative_salt: &[u8; crate::smallwood_hx512_transcript::HX512_SALT_BYTES],
    geometry: &SmallwoodCoreGeometryV1,
    maximum_payload_bytes: usize,
) -> Result<SmallwoodProof, TransactionCircuitError> {
    if payload.is_empty() || payload.len() > maximum_payload_bytes {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 core payload exceeds its allocation cap",
        ));
    }
    let opened_leaf_count = HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals;
    let leaf_tape_bytes = HX512_PROFILE_LEAF_TAPE_BYTES;
    let mut cursor = 0usize;
    let mut decs_root = [0u8; DIGEST_BYTES];
    decs_root.copy_from_slice(read_exact_v1(payload, &mut cursor, DIGEST_BYTES)?);
    let mut piop_input_digest = [0u8; DIGEST_BYTES];
    piop_input_digest.copy_from_slice(read_exact_v1(payload, &mut cursor, DIGEST_BYTES)?);
    let mut h_piop = [0u8; DIGEST_BYTES];
    h_piop.copy_from_slice(read_exact_v1(payload, &mut cursor, DIGEST_BYTES)?);
    let ppol_highs = decode_matrix_u64_hx512(
        payload,
        &mut cursor,
        geometry.ppol_high_rows,
        geometry.ppol_high_cols,
    )?;
    let plin_highs = decode_matrix_u64_hx512(
        payload,
        &mut cursor,
        geometry.plin_high_rows,
        geometry.plin_high_cols,
    )?;
    let rcombi_tails = decode_matrix_u64_hx512(
        payload,
        &mut cursor,
        geometry.rcombi_rows,
        geometry.rcombi_cols,
    )?;
    let subset_evals = decode_matrix_u64_hx512(
        payload,
        &mut cursor,
        geometry.subset_rows,
        geometry.subset_cols,
    )?;
    let partial_evals = decode_matrix_u64_hx512(
        payload,
        &mut cursor,
        geometry.partial_rows,
        geometry.partial_cols,
    )?;
    let auth_paths = decode_auth_paths_hx512(
        payload,
        &mut cursor,
        opened_leaf_count,
        HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals.ilog2() as usize,
    )?;
    let tape_payload_bytes = opened_leaf_count.checked_mul(leaf_tape_bytes).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "fresh HX512 opened tape payload length overflow",
        ),
    )?;
    if tape_payload_bytes > payload.len().saturating_sub(cursor) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 opened tape payload exceeds remaining bytes",
        ));
    }
    let mut leaf_tapes = Vec::with_capacity(opened_leaf_count);
    for _ in 0..opened_leaf_count {
        leaf_tapes.push(read_exact_v1(payload, &mut cursor, leaf_tape_bytes)?.to_vec());
    }
    let masking_evals = decode_matrix_u64_hx512(
        payload,
        &mut cursor,
        geometry.masking_rows,
        geometry.masking_cols,
    )?;
    let high_coeffs =
        decode_matrix_u64_hx512(payload, &mut cursor, geometry.high_rows, geometry.high_cols)?;
    let row_scalars = decode_matrix_u64_hx512(
        payload,
        &mut cursor,
        geometry.opened_witness_rows,
        geometry.opened_witness_cols,
    )?;
    if cursor != payload.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fresh HX512 core payload has trailing bytes",
        ));
    }
    Ok(SmallwoodProof {
        wire_identity: SmallwoodProofWireIdentityV1::FreshHx512Candidate,
        digest_bytes: DIGEST_BYTES,
        strict_zk_decs_leaf_hiding: true,
        hx512_decs_root: Some(decs_root),
        hx512_piop_input_digest: Some(piop_input_digest),
        salt: authoritative_salt.to_vec(),
        nonce: [0u8; NONCE_BYTES],
        h_piop,
        piop: PiopProof {
            ppol_highs,
            plin_highs,
        },
        pcs: PcsProof {
            rcombi_tails,
            subset_evals,
            partial_evals,
            decs: DecsProof {
                auth_paths,
                leaf_tapes,
                masking_evals,
                high_coeffs,
            },
        },
        opened_witness: SmallwoodOpenedWitnessBundle::row_scalars(row_scalars, Vec::new(), 0),
    })
}

impl SmallwoodProofTraceV1 {
    pub fn piop_ppol_highs_v1(&self) -> &[Vec<u64>] {
        &self.piop.ppol_highs
    }

    pub fn piop_plin_highs_v1(&self) -> &[Vec<u64>] {
        &self.piop.plin_highs
    }

    pub fn decs_proof_v1(&self) -> &DecsProof {
        &self.pcs.decs
    }

    pub fn pcs_partial_evals_v1(&self) -> &[Vec<u64>] {
        &self.pcs.partial_evals
    }

    pub fn pcs_rcombi_tails_v1(&self) -> &[Vec<u64>] {
        &self.pcs.rcombi_tails
    }

    pub fn pcs_subset_evals_v1(&self) -> &[Vec<u64>] {
        &self.pcs.subset_evals
    }

    pub fn decs_auth_paths_v1(&self) -> &[Vec<[u8; DIGEST_BYTES]>] {
        &self.pcs.decs.auth_paths
    }

    pub fn decs_masking_evals_v1(&self) -> &[Vec<u64>] {
        &self.pcs.decs.masking_evals
    }

    pub fn decs_leaf_tapes_v1(&self) -> &[Vec<u8>] {
        &self.pcs.decs.leaf_tapes
    }

    pub fn decs_high_coeffs_v1(&self) -> &[Vec<u64>] {
        &self.pcs.decs.high_coeffs
    }
}

impl PcsProof {
    pub fn partial_evals_mut_v1(&mut self) -> &mut Vec<Vec<u64>> {
        &mut self.partial_evals
    }

    pub fn decs_mut_v1(&mut self) -> &mut DecsProof {
        &mut self.decs
    }
}

impl DecsProof {
    pub fn masking_evals_mut_v1(&mut self) -> &mut Vec<Vec<u64>> {
        &mut self.masking_evals
    }

    pub fn leaf_tapes_mut_v1(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.leaf_tapes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPcsVerifierTraceV1 {
    pub coeffs: Vec<Vec<u64>>,
    pub combi_heads: Vec<Vec<u64>>,
    pub decs_trans_hash: [u8; DIGEST_BYTES],
    pub decs_leaf_indexes: Vec<u32>,
    pub decs_nonce: [u8; NONCE_BYTES],
    pub decs_eval_points: Vec<u64>,
    pub rows: Vec<Vec<u64>>,
    pub root_digest: [u8; DIGEST_BYTES],
    pub decs_gamma_all: Vec<Vec<u64>>,
    pub decs_commitment_transcript: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPiopVerifierTraceV1 {
    pub pcs_transcript_words: Vec<u64>,
    pub piop_input_words: Vec<u64>,
    pub piop_gamma_prime: Vec<Vec<u64>>,
    pub piop_transcript_words: Vec<u64>,
    pub accept: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodVerifierTraceV1 {
    pub profile: SmallwoodNoGrindingProfileV1,
    pub proof: SmallwoodProofTraceV1,
    pub binding_words: Vec<u64>,
    pub eval_points: Vec<u64>,
    pub piop_gamma_prime: Vec<Vec<u64>>,
    pub pcs_transcript_words: Vec<u64>,
    pub piop_input_words: Vec<u64>,
    pub piop_transcript_words: Vec<u64>,
    pub pcs_trace: SmallwoodPcsVerifierTraceV1,
    pub accept: bool,
}

fn digest_words_v1(digest: &[u8; DIGEST_BYTES]) -> [u64; DIGEST_WORDS] {
    let mut out = [0u64; DIGEST_WORDS];
    for (idx, chunk) in digest.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        out[idx] = u64::from_le_bytes(word);
    }
    out
}

fn nonce_words_v1(nonce: &[u8; NONCE_BYTES]) -> [u64; 1] {
    [u32::from_le_bytes(*nonce) as u64]
}

fn flatten_matrix_words_v1(matrix: &[Vec<u64>]) -> Vec<u64> {
    let mut out = Vec::new();
    for row in matrix {
        out.extend_from_slice(row);
    }
    out
}

fn flatten_u32_words_v1(values: &[u32]) -> Vec<u64> {
    values.iter().map(|&value| value as u64).collect()
}

fn flatten_auth_path_words_v1(paths: &[Vec<[u8; DIGEST_BYTES]>]) -> Vec<u64> {
    let mut out = Vec::new();
    for path in paths {
        for node in path {
            out.extend_from_slice(&digest_words_v1(node));
        }
    }
    out
}

impl SmallwoodVerifierTraceV1 {
    pub fn transcript_binding_words_v1(&self) -> &[u64] {
        &self.binding_words
    }

    pub fn transcript_eval_points_v1(&self) -> &[u64] {
        &self.eval_points
    }

    pub fn transcript_piop_gamma_prime_v1(&self) -> &[Vec<u64>] {
        &self.piop_gamma_prime
    }

    pub fn transcript_pcs_words_v1(&self) -> &[u64] {
        &self.pcs_transcript_words
    }

    pub fn transcript_piop_input_words_v1(&self) -> &[u64] {
        &self.piop_input_words
    }

    pub fn transcript_piop_words_v1(&self) -> &[u64] {
        &self.piop_transcript_words
    }

    pub fn transcript_hash_words_v1(&self) -> [u64; DIGEST_WORDS] {
        digest_words_v1(&self.proof.h_piop)
    }

    pub fn flatten_transcript_section_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.binding_words);
        out.extend_from_slice(&self.eval_points);
        out.extend_from_slice(&flatten_matrix_words_v1(&self.piop_gamma_prime));
        out.extend_from_slice(&self.pcs_transcript_words);
        out.extend_from_slice(&self.piop_input_words);
        out.extend_from_slice(&self.piop_transcript_words);
        out.extend_from_slice(&self.transcript_hash_words_v1());
        out.push(self.accept as u64);
        out
    }

    pub fn validate_transcript_section_v1(&self) -> Result<(), TransactionCircuitError> {
        if self.eval_points.len() != self.profile.nb_opened_evals {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace transcript eval-point count mismatch",
            ));
        }
        if self.eval_points.len() != self.proof.opened_witness_row_scalars.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace transcript row-scalar count mismatch",
            ));
        }
        if self.piop_gamma_prime.len() != self.profile.rho {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace gamma-prime count mismatch",
            ));
        }
        if self.piop_input_words.len() != self.pcs_transcript_words.len() + self.binding_words.len()
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace piop-input length mismatch",
            ));
        }
        if !self
            .piop_input_words
            .starts_with(&self.pcs_transcript_words)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace piop-input prefix mismatch",
            ));
        }
        if !self.piop_input_words[self.pcs_transcript_words.len()..].eq(&self.binding_words) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace piop-input binding suffix mismatch",
            ));
        }
        if self.piop_transcript_words.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace piop transcript words missing",
            ));
        }
        Ok(())
    }

    pub fn pcs_opened_witness_row_scalars_v1(&self) -> &[Vec<u64>] {
        &self.proof.opened_witness_row_scalars
    }

    pub fn pcs_partial_evals_v1(&self) -> &[Vec<u64>] {
        &self.proof.pcs.partial_evals
    }

    pub fn pcs_rcombi_tails_v1(&self) -> &[Vec<u64>] {
        &self.proof.pcs.rcombi_tails
    }

    pub fn pcs_subset_evals_v1(&self) -> &[Vec<u64>] {
        &self.proof.pcs.subset_evals
    }

    pub fn pcs_coeffs_v1(&self) -> &[Vec<u64>] {
        &self.pcs_trace.coeffs
    }

    pub fn pcs_combi_heads_v1(&self) -> &[Vec<u64>] {
        &self.pcs_trace.combi_heads
    }

    pub fn pcs_decs_transcript_hash_words_v1(&self) -> [u64; DIGEST_WORDS] {
        digest_words_v1(&self.pcs_trace.decs_trans_hash)
    }

    pub fn flatten_pcs_section_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(&flatten_matrix_words_v1(
            &self.proof.opened_witness_row_scalars,
        ));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.proof.pcs.partial_evals));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.proof.pcs.rcombi_tails));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.proof.pcs.subset_evals));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.pcs_trace.coeffs));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.pcs_trace.combi_heads));
        out.extend_from_slice(&self.pcs_decs_transcript_hash_words_v1());
        out.extend_from_slice(&self.pcs_transcript_words);
        out
    }

    pub fn validate_pcs_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_combi_count = self.pcs_trace.coeffs.len();
        if opened_combi_count == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace PCS coefficients missing",
            ));
        }
        if self.proof.pcs.partial_evals.len() != self.profile.nb_opened_evals
            || self.proof.pcs.rcombi_tails.len() != opened_combi_count
            || self.pcs_trace.combi_heads.len() != opened_combi_count
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace PCS section count mismatch",
            ));
        }
        if self.proof.pcs.subset_evals.len() != self.pcs_trace.decs_leaf_indexes.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace PCS subset-eval count mismatch",
            ));
        }
        if self.pcs_transcript_words != self.pcs_trace.decs_commitment_transcript {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace PCS transcript mismatch",
            ));
        }
        for row in &self.proof.opened_witness_row_scalars {
            if row.is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood verifier trace PCS opened row is empty",
                ));
            }
        }
        for idx in 0..opened_combi_count {
            if self.pcs_trace.coeffs[idx].is_empty()
                || self.pcs_trace.combi_heads[idx].is_empty()
                || self.proof.pcs.rcombi_tails[idx].is_empty()
            {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood verifier trace PCS subsection is empty",
                ));
            }
        }
        for row in &self.proof.pcs.partial_evals {
            if row.is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood verifier trace PCS partial-eval row is empty",
                ));
            }
        }
        for row in &self.proof.pcs.subset_evals {
            if row.is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood verifier trace PCS subset-eval row is empty",
                ));
            }
        }
        Ok(())
    }

    pub fn decs_leaf_indexes_v1(&self) -> &[u32] {
        &self.pcs_trace.decs_leaf_indexes
    }

    pub fn decs_nonce_words_v1(&self) -> [u64; 1] {
        nonce_words_v1(&self.pcs_trace.decs_nonce)
    }

    pub fn decs_eval_points_v1(&self) -> &[u64] {
        &self.pcs_trace.decs_eval_points
    }

    pub fn decs_masking_evals_v1(&self) -> &[Vec<u64>] {
        &self.proof.pcs.decs.masking_evals
    }

    pub fn decs_high_coeffs_v1(&self) -> &[Vec<u64>] {
        &self.proof.pcs.decs.high_coeffs
    }

    pub fn decs_gamma_all_v1(&self) -> &[Vec<u64>] {
        &self.pcs_trace.decs_gamma_all
    }

    pub fn flatten_decs_section_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.pcs_decs_transcript_hash_words_v1());
        out.extend_from_slice(&flatten_u32_words_v1(&self.pcs_trace.decs_leaf_indexes));
        out.extend_from_slice(&self.decs_nonce_words_v1());
        out.extend_from_slice(&self.pcs_trace.decs_eval_points);
        for tape in &self.proof.pcs.decs.leaf_tapes {
            out.extend(bytes_to_words_unchecked(tape));
        }
        out.extend_from_slice(&flatten_matrix_words_v1(&self.proof.pcs.decs.masking_evals));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.proof.pcs.decs.high_coeffs));
        out.extend_from_slice(&flatten_matrix_words_v1(&self.pcs_trace.decs_gamma_all));
        out.extend_from_slice(&self.pcs_trace.decs_commitment_transcript);
        out
    }

    pub fn validate_decs_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_count = self.pcs_trace.decs_leaf_indexes.len();
        if opened_count == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace DECS opened-leaf set is empty",
            ));
        }
        let coefficient_width = self
            .pcs_trace
            .coeffs
            .first()
            .map(Vec::len)
            .filter(|width| *width != 0)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace DECS coefficient table is empty",
            ))?;
        if self.pcs_trace.decs_eval_points.len() != opened_count
            || self.proof.pcs.decs.masking_evals.len() != opened_count
            || (!self.proof.pcs.decs.leaf_tapes.is_empty()
                && self.proof.pcs.decs.leaf_tapes.len() != opened_count)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace DECS section count mismatch",
            ));
        }
        if self.proof.pcs.decs.high_coeffs.len() != self.profile.decs_eta {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace DECS high-coefficient count mismatch",
            ));
        }
        if self.pcs_trace.decs_gamma_all.len() != self.profile.decs_eta
            || self
                .pcs_trace
                .decs_gamma_all
                .iter()
                .any(|row| row.len() != coefficient_width)
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace DECS challenge coefficient shape mismatch",
            ));
        }
        for row in &self.proof.pcs.decs.masking_evals {
            if row.is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood verifier trace DECS masking-eval row is empty",
                ));
            }
        }
        for poly in &self.proof.pcs.decs.high_coeffs {
            if poly.is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood verifier trace DECS high-coefficient row is empty",
                ));
            }
        }
        Ok(())
    }

    pub fn merkle_rows_v1(&self) -> &[Vec<u64>] {
        &self.pcs_trace.rows
    }

    pub fn merkle_auth_paths_v1(&self) -> &[Vec<[u8; DIGEST_BYTES]>] {
        &self.proof.pcs.decs.auth_paths
    }

    pub fn merkle_root_digest_words_v1(&self) -> [u64; DIGEST_WORDS] {
        digest_words_v1(&self.pcs_trace.root_digest)
    }

    pub fn flatten_merkle_section_words_v1(&self) -> Vec<u64> {
        let mut out = Vec::new();
        out.extend_from_slice(&flatten_matrix_words_v1(&self.pcs_trace.rows));
        out.extend_from_slice(&flatten_auth_path_words_v1(&self.proof.pcs.decs.auth_paths));
        out.extend_from_slice(&self.merkle_root_digest_words_v1());
        out
    }

    pub fn validate_merkle_section_v1(&self) -> Result<(), TransactionCircuitError> {
        let opened_count = self.pcs_trace.decs_leaf_indexes.len();
        if self.pcs_trace.rows.len() != opened_count
            || self.proof.pcs.decs.auth_paths.len() != opened_count
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood verifier trace Merkle section count mismatch",
            ));
        }
        for idx in 0..opened_count {
            if self.pcs_trace.rows[idx].is_empty() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood verifier trace Merkle row is empty",
                ));
            }
        }
        Ok(())
    }

    pub fn validate_sections_v1(&self) -> Result<(), TransactionCircuitError> {
        self.validate_transcript_section_v1()?;
        self.validate_pcs_section_v1()?;
        self.validate_decs_section_v1()?;
        self.validate_merkle_section_v1()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodOpenedWitnessBundle {
    mode: SmallwoodOpenedWitnessMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SmallwoodOpenedWitnessMode {
    None,
    RowScalars {
        row_scalars: Vec<Vec<u64>>,
        auxiliary_words: Vec<u64>,
        auxiliary_limb_count: usize,
    },
}

impl SmallwoodOpenedWitnessBundle {
    pub(crate) fn row_scalars(
        row_scalars: Vec<Vec<u64>>,
        auxiliary_words: Vec<u64>,
        auxiliary_limb_count: usize,
    ) -> Self {
        Self {
            mode: SmallwoodOpenedWitnessMode::RowScalars {
                row_scalars,
                auxiliary_words,
                auxiliary_limb_count,
            },
        }
    }

    pub(crate) fn row_scalars_ref(&self) -> Option<&[Vec<u64>]> {
        match &self.mode {
            SmallwoodOpenedWitnessMode::RowScalars { row_scalars, .. } => Some(row_scalars),
            _ => None,
        }
    }

    pub(crate) fn auxiliary_words_ref(&self) -> Option<&[u64]> {
        match &self.mode {
            SmallwoodOpenedWitnessMode::RowScalars {
                auxiliary_words, ..
            } => Some(auxiliary_words),
            _ => None,
        }
    }

    pub(crate) fn auxiliary_limb_count(&self) -> usize {
        match &self.mode {
            SmallwoodOpenedWitnessMode::RowScalars {
                auxiliary_limb_count,
                ..
            } => *auxiliary_limb_count,
            SmallwoodOpenedWitnessMode::None => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SmallwoodConfig {
    profile: SmallwoodNoGrindingProfileV1,
    decs_challenge_format: SmallwoodDecsChallengeFormat,
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    linear_constraint_count: usize,
    witness_size: usize,
    total_variable_count: usize,
    auxiliary_witness_word_count: usize,
    auxiliary_witness_limb_count: usize,
    constraint_count: usize,
    wit_poly_degree: usize,
    mpol_poly_degree: usize,
    mlin_poly_degree: usize,
    nb_polys: usize,
    degree: Vec<usize>,
    width: Vec<usize>,
    delta: Vec<usize>,
    nb_unstacked_rows: usize,
    nb_unstacked_cols: usize,
    nb_lvcs_rows: usize,
    nb_lvcs_cols: usize,
    nb_lvcs_opened_combi: usize,
    fullrank_cols: Vec<usize>,
    packing_points: Vec<u64>,
}

pub fn ensure_row_polynomial_arithmetization(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<(), TransactionCircuitError> {
    match statement.arithmetization() {
        SmallwoodArithmetization::Bridge64V1
        | SmallwoodArithmetization::DirectPacked64V1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked128CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked16CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked32CompactBindingsV1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsSkipInitialMdsV1
        | SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1
        | SmallwoodArithmetization::DirectPacked128CompactBindingsInlineMerkleSkipInitialMdsV1
        | SmallwoodArithmetization::DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2
        | SmallwoodArithmetization::DirectPacked64CompressedLevel5
        | SmallwoodArithmetization::DirectPacked128CompressedLevel5
        | SmallwoodArithmetization::DirectPacked64CompressedLevel5FullSha512First48CommitmentV3
        | SmallwoodArithmetization::DirectPacked64CompressedV6Sha512Smz2
        | SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1
        | SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz8
        | SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
        | SmallwoodArithmetization::DirectRadix4Packed1024Hx512Candidate => Ok(()),
    }
}

fn poseidon2_domain_words(domain: &[u8]) -> Vec<u64> {
    let mut words = Vec::with_capacity(1 + domain.len().div_ceil(8));
    words.push(domain.len() as u64);
    for chunk in domain.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        words.push(u64::from_le_bytes(word));
    }
    words
}

#[inline]
fn update_hasher_with_word_slice(hasher: &mut Hasher, words: &[u64]) {
    #[cfg(target_endian = "little")]
    unsafe {
        let bytes =
            std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), std::mem::size_of_val(words));
        hasher.update(bytes);
    }
    #[cfg(not(target_endian = "little"))]
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
}

#[inline]
fn read_blake3_xof_words(mut reader: blake3::OutputReader, out_words: usize) -> Vec<u64> {
    let mut out = vec![0u64; out_words];
    for slot in &mut out {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        *slot = (u128::from_le_bytes(buf) % FIELD_ORDER as u128) as u64;
    }
    out
}

#[inline]
fn read_blake3_xof_digest(reader: blake3::OutputReader) -> [u8; DIGEST_BYTES] {
    words_to_digest(&read_blake3_xof_words(reader, LEGACY_DIGEST_WORDS))
}

fn sha512_raw_domain_digest(
    backend: SmallwoodTranscriptBackend,
    domain: &[u8],
    words: &[u64],
    counter: u64,
) -> [u8; DIGEST_BYTES] {
    update_verifier_operation_profile_v1(|profile| {
        profile.sha512_digest_calls += 1;
    });
    let key = SmallwoodSha512OracleKeyV1::new(backend, domain, words, counter);
    if let Some(output) = query_smallwood_sha512_oracle_overlay_v1(&key) {
        return output;
    }
    concrete_smallwood_sha512_oracle_query_v1(&key)
}

fn concrete_smallwood_sha512_oracle_query_v1(
    key: &SmallwoodSha512OracleKeyV1,
) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    if let Some(profile_domain) = &key.profile_domain {
        hasher.update((profile_domain.len() as u64).to_le_bytes());
        hasher.update(profile_domain);
    }
    hasher.update((key.role_domain.len() as u64).to_le_bytes());
    hasher.update(&key.role_domain);
    hasher.update((key.words.len() as u64).to_le_bytes());
    for word in &key.words {
        hasher.update(word.to_le_bytes());
    }
    hasher.update(key.counter.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
fn sha512_domain_digest(domain: &[u8], words: &[u64], counter: u64) -> [u8; DIGEST_BYTES] {
    sha512_raw_domain_digest(
        SmallwoodTranscriptBackend::Sha512Level5,
        domain,
        words,
        counter,
    )
}

fn observe_sha512_commitment(
    backend: SmallwoodTranscriptBackend,
    mut raw_digest: [u8; DIGEST_BYTES],
) -> [u8; DIGEST_BYTES] {
    if backend.observes_truncated_sha512_commitment() {
        raw_digest[backend.digest_bytes()..].fill(0);
    }
    raw_digest
}

fn sha512_commitment_domain_digest(
    backend: SmallwoodTranscriptBackend,
    domain: &[u8],
    words: &[u64],
    counter: u64,
) -> [u8; DIGEST_BYTES] {
    observe_sha512_commitment(
        backend,
        sha512_raw_domain_digest(backend, domain, words, counter),
    )
}

fn read_sha512_xof_words_with_count(
    backend: SmallwoodTranscriptBackend,
    domain: &[u8],
    words: &[u64],
    out_words: usize,
) -> Result<(Vec<u64>, u64), TransactionCircuitError> {
    let digest_call_cap = smallwood_sha512_field_xof_digest_call_cap_v1(out_words)?;
    read_canonical_field_words_from_blocks_v1(out_words, digest_call_cap, |counter| {
        sha512_raw_domain_digest(backend, domain, words, counter)
    })
}

fn read_canonical_field_words_from_blocks_v1(
    out_words: usize,
    digest_call_cap: usize,
    mut next_block: impl FnMut(u64) -> [u8; DIGEST_BYTES],
) -> Result<(Vec<u64>, u64), TransactionCircuitError> {
    let mut output = Vec::with_capacity(out_words);
    let mut counter = 0u64;
    let mut digest_calls = 0u64;
    while output.len() < out_words {
        if digest_calls as usize >= digest_call_cap {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood SHA-512 field-XOF rejection budget exhausted",
            ));
        }
        // Field-XOF rejection sampling consumes all eight words of every full
        // SHA-512 block, including under the first-48 commitment profile.
        let block = next_block(counter);
        digest_calls += 1;
        for chunk in block.chunks_exact(8) {
            let mut candidate = [0u8; 8];
            candidate.copy_from_slice(chunk);
            let candidate = u64::from_le_bytes(candidate);
            if candidate < FIELD_ORDER {
                output.push(candidate);
                if output.len() == out_words {
                    break;
                }
            }
        }
        if output.len() < out_words {
            counter = counter
                .checked_add(1)
                .expect("SmallWood SHA-512 XOF counter exhausted");
        }
    }
    Ok((output, digest_calls))
}

thread_local! {
    static SMALLWOOD_SHA512_FIELD_XOF_FAILURE_V1: RefCell<Option<String>> = const { RefCell::new(None) };
    static SMALLWOOD_SHA512_FIELD_XOF_SCOPE_ACTIVE_V1: Cell<bool> = const { Cell::new(false) };
}

struct SmallwoodSha512FieldXofScopeV1 {
    active: bool,
}

impl SmallwoodSha512FieldXofScopeV1 {
    fn finish(mut self) -> Result<(), TransactionCircuitError> {
        let failure = SMALLWOOD_SHA512_FIELD_XOF_FAILURE_V1.with(|slot| slot.borrow_mut().take());
        SMALLWOOD_SHA512_FIELD_XOF_SCOPE_ACTIVE_V1.with(|active| active.set(false));
        self.active = false;
        match failure {
            Some(message) => Err(TransactionCircuitError::ConstraintViolationOwned(message)),
            None => Ok(()),
        }
    }
}

impl Drop for SmallwoodSha512FieldXofScopeV1 {
    fn drop(&mut self) {
        if self.active {
            SMALLWOOD_SHA512_FIELD_XOF_FAILURE_V1.with(|slot| {
                let _ = slot.borrow_mut().take();
            });
            SMALLWOOD_SHA512_FIELD_XOF_SCOPE_ACTIVE_V1.with(|active| active.set(false));
        }
    }
}

fn enter_smallwood_sha512_field_xof_scope_v1(
) -> Result<SmallwoodSha512FieldXofScopeV1, TransactionCircuitError> {
    let already_active =
        SMALLWOOD_SHA512_FIELD_XOF_SCOPE_ACTIVE_V1.with(|active| active.replace(true));
    if already_active {
        return Err(TransactionCircuitError::ConstraintViolation(
            "nested smallwood SHA-512 field-XOF failure scopes are forbidden",
        ));
    }
    SMALLWOOD_SHA512_FIELD_XOF_FAILURE_V1.with(|slot| {
        let _ = slot.borrow_mut().take();
    });
    Ok(SmallwoodSha512FieldXofScopeV1 { active: true })
}

fn record_smallwood_sha512_field_xof_failure_v1(
    error: TransactionCircuitError,
    out_words: usize,
) -> Vec<u64> {
    SMALLWOOD_SHA512_FIELD_XOF_FAILURE_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(error.to_string());
        }
    });
    // Keep every downstream shape exact so the enclosing prover or verifier
    // reaches its mandatory scope check and returns the recorded error.  These
    // deterministic poison values are never accepted as transcript output.
    (0..out_words)
        .map(|index| FIELD_ORDER - 1 - index as u64)
        .collect()
}

fn transcript_xof_words(
    backend: SmallwoodTranscriptBackend,
    domain: &[u8],
    words: &[u64],
    out_words: usize,
) -> Vec<u64> {
    match backend {
        SmallwoodTranscriptBackend::Blake3 => {
            update_verifier_operation_profile_v1(|profile| {
                profile.transcript_calls += 1;
                profile.transcript_absorbed_words += words.len() as u64;
                profile.transcript_squeezed_words += out_words as u64;
            });
            let output =
                if out_words == 4 && words.len() <= 8 && domain == SMALLWOOD_COMPRESS2_DOMAIN {
                    let mut padded = [0u64; 8];
                    for (idx, word) in words.iter().enumerate() {
                        padded[idx] = *word;
                    }
                    blake3_compress2_words(&padded).to_vec()
                } else {
                    let mut hasher = Hasher::new();
                    hasher.update(domain);
                    hasher.update(&(words.len() as u64).to_le_bytes());
                    update_hasher_with_word_slice(&mut hasher, words);
                    read_blake3_xof_words(hasher.finalize_xof(), out_words)
                };
            record_transcript_call_trace_v1(domain, words, &output, 0);
            output
        }
        SmallwoodTranscriptBackend::Poseidon2 => {
            let mut state = [Felt::ZERO; transaction_core::constants::POSEIDON2_WIDTH];
            let poseidon_domain = if domain == SMALLWOOD_COMPRESS2_DOMAIN {
                SMALLWOOD_POSEIDON2_COMPRESS2_DOMAIN
            } else {
                SMALLWOOD_POSEIDON2_XOF_DOMAIN
            };
            let mut absorb = poseidon2_domain_words(poseidon_domain);
            absorb.push(words.len() as u64);
            absorb.extend_from_slice(words);
            absorb.push(1);
            let absorb_permutations = absorb.len().div_ceil(SMALLWOOD_POSEIDON2_RATE);
            let squeeze_permutations = out_words
                .div_ceil(SMALLWOOD_POSEIDON2_RATE)
                .saturating_sub(1);
            update_verifier_operation_profile_v1(|profile| {
                profile.transcript_calls += 1;
                profile.transcript_absorbed_words += absorb.len() as u64;
                profile.transcript_squeezed_words += out_words as u64;
                profile.poseidon2_permutations +=
                    (absorb_permutations + squeeze_permutations) as u64;
            });
            for chunk in absorb.chunks(SMALLWOOD_POSEIDON2_RATE) {
                for (idx, word) in chunk.iter().enumerate() {
                    state[idx] += Felt::from_u64(canon(*word));
                }
                poseidon2_permutation(&mut state);
            }
            let mut out = Vec::with_capacity(out_words);
            while out.len() < out_words {
                for elem in state.iter().take(SMALLWOOD_POSEIDON2_RATE) {
                    if out.len() == out_words {
                        break;
                    }
                    out.push(elem.as_canonical_u64());
                }
                if out.len() < out_words {
                    poseidon2_permutation(&mut state);
                }
            }
            record_transcript_call_trace_v1(domain, words, &out, 0);
            out
        }
        SmallwoodTranscriptBackend::Sha512Level5
        | SmallwoodTranscriptBackend::FullSha512First48CommitmentV3
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 => {
            update_verifier_operation_profile_v1(|profile| {
                profile.transcript_calls += 1;
                profile.transcript_absorbed_words += words.len() as u64;
                profile.transcript_squeezed_words += out_words as u64;
            });
            let (output, raw_digest_calls) = read_sha512_xof_words_with_count(
                backend, domain, words, out_words,
            )
            .unwrap_or_else(|error| {
                return (
                    record_smallwood_sha512_field_xof_failure_v1(error, out_words),
                    0,
                );
            });
            record_transcript_call_trace_v1(domain, words, &output, raw_digest_calls);
            output
        }
        SmallwoodTranscriptBackend::Sha512V6 => {
            let role = v6_role_for_engine_domain(domain)
                .unwrap_or_else(|| panic!("unregistered Smallwood V6 transcript domain"));
            update_verifier_operation_profile_v1(|profile| {
                profile.transcript_calls += 1;
                profile.transcript_absorbed_words += words.len() as u64;
                profile.transcript_squeezed_words += out_words as u64;
            });
            let output = with_smallwood_v6_transcript(|v6| {
                v6.xof_role(role, words, out_words)
                    .map_err(smallwood_v6_error)
            })
            .unwrap_or_else(|error| panic!("Smallwood V6 transcript request failed: {error}"))
            .unwrap_or_else(|error| panic!("Smallwood V6 transcript request failed: {error}"));
            record_transcript_call_trace_v1(
                domain,
                words,
                &output.words,
                output.raw_digest_calls as u64,
            );
            output.words
        }
        SmallwoodTranscriptBackend::Hx512Candidate => {
            panic!("HX512 transcript requests require the dedicated eight-stage driver")
        }
    }
}

fn transcript_xof_digest(
    backend: SmallwoodTranscriptBackend,
    domain: &[u8],
    words: &[u64],
) -> [u8; DIGEST_BYTES] {
    match backend {
        SmallwoodTranscriptBackend::Sha512Level5
        | SmallwoodTranscriptBackend::FullSha512First48CommitmentV3
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7
        | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 => {
            sha512_commitment_domain_digest(backend, domain, words, 0)
        }
        SmallwoodTranscriptBackend::Blake3 | SmallwoodTranscriptBackend::Poseidon2 => {
            words_to_digest(&transcript_xof_words(
                backend,
                domain,
                words,
                LEGACY_DIGEST_WORDS,
            ))
        }
        SmallwoodTranscriptBackend::Sha512V6 => {
            let role = v6_role_for_engine_domain(domain)
                .unwrap_or_else(|| panic!("unregistered Smallwood V6 transcript domain"));
            with_smallwood_v6_transcript(|v6| v6.digest_role(role, words))
                .unwrap_or_else(|error| panic!("Smallwood V6 transcript request failed: {error}"))
        }
        SmallwoodTranscriptBackend::Hx512Candidate => {
            panic!("HX512 transcript requests require the dedicated eight-stage driver")
        }
    }
}

fn blake3_compress2_words(words: &[u64; 8]) -> [u64; 4] {
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_COMPRESS2_DOMAIN);
    hasher.update(&(words.len() as u64).to_le_bytes());
    update_hasher_with_word_slice(&mut hasher, words);
    let mut out = [0u64; 4];
    out.copy_from_slice(&read_blake3_xof_words(hasher.finalize_xof(), 4));
    out
}

#[derive(Clone, Debug)]
struct DecsKey {
    committed_domain_evals: Vec<Vec<u64>>,
    masking_domain_evals: Vec<Vec<u64>>,
    leaf_tapes: Vec<Vec<u8>>,
    dec_polys: Vec<Vec<u64>>,
    /// Commitment-time DECS coefficients retained only by the prover.  They
    /// let `decs_open` check that a table index and its algebraic evaluation
    /// point were not confused when a non-consecutive domain is used.
    gamma_all: Vec<Vec<u64>>,
    tree_levels: Vec<Vec<[u8; DIGEST_BYTES]>>,
}

#[derive(Clone, Debug)]
struct LvcsKey {
    extended_rows: Vec<Vec<u64>>,
    decs_key: DecsKey,
}

#[derive(Clone, Debug)]
struct PcsKey {
    lvcs_key: LvcsKey,
}

pub(crate) fn prove_candidate(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    prove_statement_with_transcript_backend_and_profile(
        statement,
        witness_values,
        binded_data,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
        SmallwoodTranscriptBackend::Blake3,
    )
}

pub(crate) fn prove_candidate_with_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    prove_statement_with_transcript_backend_and_profile(
        statement,
        witness_values,
        binded_data,
        profile,
        SmallwoodTranscriptBackend::Blake3,
    )
}

fn ensure_sha512_v6_smz2_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<(), TransactionCircuitError> {
    if statement.arithmetization() != SmallwoodArithmetization::DirectPacked64CompressedV6Sha512Smz2
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Sha512V6/SMZ2 requires the dedicated V6 arithmetization",
        ));
    }
    if statement.packing_factor() != SHA512_V6_SMZ2_PACKING_FACTOR {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Sha512V6/SMZ2 requires the exact 64-wide packing domain",
        ));
    }
    let expected = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1;
    if profile != expected {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Sha512V6/SMZ2 requires the exact fixed V6 security profile",
        ));
    }
    Ok(())
}

fn ensure_poseidon2_v8_smz8_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(), TransactionCircuitError> {
    if statement.arithmetization() != SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz8
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ8 requires the dedicated appended arithmetization",
        ));
    }
    if statement.packing_factor() != 64 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ8 requires the exact 64-wide packing domain",
        ));
    }
    if profile != POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ8 requires the exact rho5/open5/beta2/N2^23/q19/eta5 profile",
        ));
    }
    if decs_evaluation_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ8 requires the exact disjoint-coset DECS domain",
        ));
    }
    Ok(())
}

fn ensure_poseidon2_v8_smz9_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(), TransactionCircuitError> {
    if statement.arithmetization() != SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ9 requires the dedicated appended arithmetization",
        ));
    }
    if statement.packing_factor() != 64 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ9 requires the exact 64-wide packing domain",
        ));
    }
    if profile != POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ9 requires the exact rho5/open6/beta2/N2^23/q20/eta5 profile",
        ));
    }
    if decs_evaluation_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMZ9 requires the exact disjoint-coset DECS domain",
        ));
    }
    Ok(())
}

fn ensure_poseidon2_v8_compact448_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(), TransactionCircuitError> {
    // HGV8RP03 itself is deliberately unchanged and therefore retains its
    // appended SMZ9 arithmetization selector. SMC7 changes only the proof
    // profile, transcript domain, observed commitment width, and wire magic.
    if statement.arithmetization() != SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC7 requires the exact HGV8RP03 arithmetization",
        ));
    }
    if statement.packing_factor() != 64 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC7 requires the exact 64-wide packing domain",
        ));
    }
    if profile != POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC7 requires the exact rho5/open6/beta2/N2^23/q19/eta5 profile",
        ));
    }
    if decs_evaluation_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC7 requires the exact disjoint-coset DECS domain",
        ));
    }
    Ok(())
}

fn ensure_poseidon2_v8_compact448_q20_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(), TransactionCircuitError> {
    if statement.arithmetization() != SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC8 requires the exact HGV8RP03 arithmetization",
        ));
    }
    if statement.packing_factor() != 64 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC8 requires the exact 64-wide packing domain",
        ));
    }
    if profile != POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC8 requires the exact rho5/open6/beta2/N2^23/q20/eta5 profile",
        ));
    }
    if decs_evaluation_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Smallwood Poseidon2 V8/SMC8 requires the exact disjoint-coset DECS domain",
        ));
    }
    Ok(())
}

/// Build the exact public transcript binding for one engine/domain pair.
///
/// V6 does not accept a caller-authored coset descriptor.  Both prover and
/// verifier reconstruct the complete LVCS interpolation length, derive the
/// canonical disjoint coset, ask the fresh transcript backend to validate the
/// same geometry and shift, and absorb its digest alongside the public
/// statement words.  This makes a stale tail count, alternate shift, or
/// colliding domain change the commitment transcript before any challenge is
/// derived.
fn transcript_binding_words_for_domain(
    cfg: &SmallwoodConfig,
    binded_data: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<Vec<u64>, TransactionCircuitError> {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        if decs_evaluation_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 requires the exact derived disjoint-coset DECS domain",
            ));
        }
        if !binded_data.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 binds statement and context at transcript construction, not legacy binded_data",
            ));
        }
        return Ok(Vec::new());
    }
    let mut binding_words = bytes_to_words(binded_data)?;
    if transcript_backend != SmallwoodTranscriptBackend::Sha512V6 {
        return Ok(binding_words);
    }
    if decs_evaluation_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Sha512V6 transcript requires the exact disjoint-coset domain",
        ));
    }
    let interpolation_point_count = cfg
        .nb_lvcs_cols
        .checked_add(cfg.decs_nb_opened_evals())
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK interpolation geometry overflow",
        ))?;
    let descriptor =
        SmallwoodDisjointCosetDescriptorV1::derive(cfg.decs_nb_evals(), interpolation_point_count)?;
    let coset_digest = with_smallwood_v6_transcript(|backend| {
        backend.disjoint_coset_binding_digest(
            cfg.decs_nb_evals(),
            cfg.nb_lvcs_cols,
            interpolation_point_count,
            descriptor.shift,
        )
    })?
    .map_err(smallwood_v6_error)?;
    binding_words.extend(bytes_to_words_unchecked(&coset_digest));
    Ok(binding_words)
}

/// Prove the inactive V6 candidate with an already validated exact
/// `HGV6PB02` preamble.  The generic backend entrypoints intentionally remain
/// unavailable for V6 so a caller cannot omit the statement-owned preamble.
pub(crate) fn prove_statement_with_sha512_v6_smz2(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    preamble: Sha512V6BindingPreamble,
) -> Result<Vec<u8>, TransactionCircuitError> {
    ensure_sha512_v6_smz2_profile(statement, profile)?;
    let _context = enter_smallwood_v6_transcript_context(preamble)?;
    prove_statement_with_transcript_backend_profile_and_domain(
        statement,
        witness_values,
        binded_data,
        profile,
        SmallwoodTranscriptBackend::Sha512V6,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

pub(crate) fn prove_statement_with_transcript_backend(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u8>, TransactionCircuitError> {
    prove_statement_with_transcript_backend_and_profile(
        statement,
        witness_values,
        binded_data,
        smallwood_no_grinding_profile_for_arithmetization(statement.arithmetization()),
        transcript_backend,
    )
}

pub(crate) fn prove_statement_with_transcript_backend_and_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u8>, TransactionCircuitError> {
    prove_statement_with_transcript_backend_profile_and_domain(
        statement,
        witness_values,
        binded_data,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Consecutive,
    )
}

pub(crate) fn prove_statement_with_transcript_backend_profile_and_domain(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<Vec<u8>, TransactionCircuitError> {
    ensure_transcript_backend_dispatch_available(transcript_backend)?;
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8 {
        ensure_poseidon2_v8_smz8_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 {
        ensure_poseidon2_v8_smz9_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 {
        ensure_poseidon2_v8_compact448_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 {
        ensure_poseidon2_v8_compact448_q20_profile(statement, profile, decs_evaluation_domain)?;
    }
    if decs_evaluation_domain == SmallwoodDecsEvaluationDomain::Radix2DisjointCoset
        && !matches!(
            transcript_backend,
            SmallwoodTranscriptBackend::Sha512Level5
                | SmallwoodTranscriptBackend::Sha512V6
                | SmallwoodTranscriptBackend::Sha512Poseidon2V8
                | SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9
                | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7
                | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8
        )
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS mode requires an exact strict SHA-512 transcript backend",
        ));
    }
    let wire_identity =
        proof_wire_identity_for_backend_and_domain(transcript_backend, decs_evaluation_domain)?;
    if wire_identity
        .opened_leaf_tape_profile()
        .is_some_and(|tape_profile| profile.decs_nb_opened_evals != tape_profile.0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict wire opening count does not match its exact identity profile",
        ));
    }
    let salt = random_bytes::<SALT_BYTES>()?;
    let proof = prove_statement_core_with_transcript_backend_profile_and_domain(
        statement,
        witness_values,
        binded_data,
        profile,
        transcript_backend,
        decs_evaluation_domain,
        &salt,
        wire_identity
            .opened_leaf_tape_profile()
            .map_or(0, |tape_profile| tape_profile.1),
        wire_identity,
    )?;
    encode_smallwood_proof_bytes_v1(&proof)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_statement_core_with_transcript_backend_profile_and_domain(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_values: &[u64],
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
    salt: &[u8],
    decs_leaf_tape_bytes: usize,
    wire_identity: SmallwoodProofWireIdentityV1,
) -> Result<SmallwoodProof, TransactionCircuitError> {
    let sha512_field_xof_scope = enter_smallwood_sha512_field_xof_scope_v1()?;
    ensure_transcript_backend_dispatch_available(transcript_backend)?;
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8 {
        ensure_poseidon2_v8_smz8_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 {
        ensure_poseidon2_v8_smz9_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 {
        ensure_poseidon2_v8_compact448_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 {
        ensure_poseidon2_v8_compact448_q20_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        ensure_smallwood_hx512_core_contract_v1(
            statement,
            profile,
            decs_evaluation_domain,
            salt.len(),
            decs_leaf_tape_bytes,
            wire_identity,
        )?;
    }
    if salt.is_empty() || !salt.len().is_multiple_of(8) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood core salt must be non-empty and word aligned",
        ));
    }
    if decs_evaluation_domain == SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
        if decs_leaf_tape_bytes == 0 || !decs_leaf_tape_bytes.is_multiple_of(8) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood disjoint-coset core requires a non-empty word-aligned leaf tape",
            ));
        }
    } else if decs_leaf_tape_bytes != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood non-hiding core forbids DECS leaf tapes",
        ));
    }
    ensure_row_polynomial_arithmetization(statement)?;
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let stage_started = Instant::now();
    let mut last_stage = stage_started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(stage_started)
            );
            *last = now;
        }
    };
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    if trace_enabled {
        let projected_proof_bytes = serialized_proof_size_hint_with_profile(
            &cfg,
            profile,
            statement.auxiliary_witness_words().len(),
            transcript_backend,
            decs_evaluation_domain,
        )?;
        eprintln!(
            "[smallwood] cfg rows={} packing={} constraints={} linear_constraints={} nb_polys={} nb_lvcs_rows={} nb_lvcs_cols={} projected_proof_bytes={}",
            cfg.row_count,
            cfg.packing_factor,
            cfg.constraint_count,
            cfg.linear_constraint_count,
            cfg.nb_polys,
            cfg.nb_lvcs_rows,
            cfg.nb_lvcs_cols,
            projected_proof_bytes,
        );
    }
    log_stage("statement", &mut last_stage);
    let binded_words = transcript_binding_words_for_domain(
        &cfg,
        binded_data,
        transcript_backend,
        decs_evaluation_domain,
    )?;
    log_stage("binded_words", &mut last_stage);
    let witness_polys = if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        // The fresh RNG budget is thread-local and sequence-exact. Keeping this
        // phase sequential prevents Rayon workers from escaping that budget.
        witness_values
            .chunks_exact(cfg.packing_factor)
            .map(|row_values| {
                poly_interpolate_random(row_values, &cfg.packing_points, cfg.nb_opened_evals())
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        witness_values
            .par_chunks_exact(cfg.packing_factor)
            .map(|row_values| {
                poly_interpolate_random(row_values, &cfg.packing_points, cfg.nb_opened_evals())
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut mpol_ppoly = Vec::with_capacity(cfg.rho());
    let mut mpol_plin = Vec::with_capacity(cfg.rho());
    for _ in 0..cfg.rho() {
        mpol_ppoly.push(random_poly(cfg.mpol_poly_degree)?);
        mpol_plin.push(poly_random_sum_zero(
            &cfg.packing_points,
            cfg.mlin_poly_degree,
        )?);
    }
    log_stage("witness_polys", &mut last_stage);

    let (pcs_key, pcs_transcript_words) = pcs_commit(
        &cfg,
        &witness_polys,
        &mpol_ppoly,
        &mpol_plin,
        salt,
        transcript_backend,
        decs_evaluation_domain,
        &binded_words,
        decs_leaf_tape_bytes,
    )?;
    log_stage("pcs_commit", &mut last_stage);
    let mut piop_input = pcs_transcript_words;
    piop_input.extend_from_slice(&binded_words);
    let piop = piop_run(
        &cfg,
        statement,
        &witness_polys,
        &mpol_ppoly,
        &mpol_plin,
        &piop_input,
        transcript_backend,
    )?;
    log_stage("piop_run", &mut last_stage);
    let h_piop = hash_piop_transcript(&piop.transcript_words, transcript_backend);
    let (nonce, eval_points) = if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        (
            [0u8; NONCE_BYTES],
            sample_smallwood_hx512_piop_openings(&cfg.packing_points, cfg.nb_opened_evals())?,
        )
    } else {
        let nonce = choose_opening_nonce(&cfg, &h_piop, transcript_backend)?;
        let eval_points =
            xof_piop_opening_points_for_profile(&nonce, &h_piop, profile, transcript_backend);
        (nonce, eval_points)
    };
    log_stage("opening_nonce", &mut last_stage);
    let (pcs_proof, opened_witness) = pcs_open(
        &cfg,
        &pcs_key,
        &witness_polys,
        &mpol_ppoly,
        &mpol_plin,
        &eval_points,
        &h_piop,
        transcript_backend,
        decs_evaluation_domain,
    )?;
    log_stage("pcs_open", &mut last_stage);
    let auxiliary_witness_words = statement.auxiliary_witness_words().to_vec();
    let auxiliary_witness_limb_count = statement
        .auxiliary_witness_limb_count()
        .unwrap_or(auxiliary_witness_words.len());
    let hx512_prefix = if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        Some(with_smallwood_hx512_transcript_driver(|driver| {
            driver.fresh_proof_prefix()
        })??)
    } else {
        None
    };
    let proof = SmallwoodProof {
        wire_identity,
        digest_bytes: transcript_backend.digest_bytes(),
        strict_zk_decs_leaf_hiding: decs_evaluation_domain
            == SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        hx512_decs_root: hx512_prefix.map(|prefix| prefix.0),
        hx512_piop_input_digest: hx512_prefix.map(|prefix| prefix.1),
        salt: salt.to_vec(),
        nonce,
        h_piop,
        piop: piop.proof,
        pcs: pcs_proof,
        opened_witness: SmallwoodOpenedWitnessBundle::row_scalars(
            opened_witness
                .row_scalars_ref()
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "smallwood prover missing row-scalar opened witness data",
                ))?
                .to_vec(),
            auxiliary_witness_words,
            auxiliary_witness_limb_count,
        ),
    };
    if trace_enabled {
        eprintln!(
            "[smallwood] completed core proof total={:?}",
            stage_started.elapsed()
        );
    }
    sha512_field_xof_scope.finish()?;
    Ok(proof)
}

pub(crate) fn verify_candidate(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    verify_statement_with_transcript_backend_and_profile(
        statement,
        binded_data,
        proof_bytes,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
        SmallwoodTranscriptBackend::Blake3,
    )
}

pub(crate) fn verify_candidate_with_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<(), TransactionCircuitError> {
    verify_statement_with_transcript_backend_and_profile(
        statement,
        binded_data,
        proof_bytes,
        profile,
        SmallwoodTranscriptBackend::Blake3,
    )
}

/// Verify the inactive V6 candidate under the same exact preamble used by the
/// prover.  This is an engine refinement seam only; production authorization
/// remains false in `smallwood_v6_transcript`.
pub(crate) fn verify_statement_with_sha512_v6_smz2(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    preamble: Sha512V6BindingPreamble,
) -> Result<(), TransactionCircuitError> {
    ensure_sha512_v6_smz2_profile(statement, profile)?;
    let _context = enter_smallwood_v6_transcript_context(preamble)?;
    verify_statement_with_transcript_backend_profile_and_domain(
        statement,
        binded_data,
        proof_bytes,
        profile,
        SmallwoodTranscriptBackend::Sha512V6,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

pub(crate) fn verify_statement_with_transcript_backend(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<(), TransactionCircuitError> {
    verify_statement_with_transcript_backend_and_profile(
        statement,
        binded_data,
        proof_bytes,
        smallwood_no_grinding_profile_for_arithmetization(statement.arithmetization()),
        transcript_backend,
    )
}

pub(crate) fn verify_statement_with_transcript_backend_and_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<(), TransactionCircuitError> {
    verify_statement_with_transcript_backend_profile_and_domain(
        statement,
        binded_data,
        proof_bytes,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Consecutive,
    )
}

fn ensure_decs_domain_wire_binding(
    proof: &SmallwoodProof,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(), TransactionCircuitError> {
    let expected =
        proof_wire_identity_for_backend_and_domain(transcript_backend, decs_evaluation_domain)?;
    if proof.wire_identity != expected {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof wire, transcript backend, and DECS domain identity mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn verify_statement_with_transcript_backend_profile_and_domain(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(), TransactionCircuitError> {
    ensure_transcript_backend_dispatch_available(transcript_backend)?;
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8 {
        ensure_poseidon2_v8_smz8_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 {
        ensure_poseidon2_v8_smz9_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 {
        ensure_poseidon2_v8_compact448_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 {
        ensure_poseidon2_v8_compact448_q20_profile(statement, profile, decs_evaluation_domain)?;
    }
    // Validate the verifier-owned relation before touching attacker-controlled
    // proof bytes.  The core reconstructs this configuration again after
    // decoding; this early pass preserves fail-closed parser precedence.
    SmallwoodConfig::new_with_profile(statement, profile)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    if proof.digest_bytes != transcript_backend.digest_bytes() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof digest width does not match the transcript backend",
        ));
    }
    ensure_decs_domain_wire_binding(&proof, transcript_backend, decs_evaluation_domain)?;
    verify_statement_core_with_transcript_backend_profile_and_domain(
        statement,
        binded_data,
        &proof,
        profile,
        transcript_backend,
        decs_evaluation_domain,
        proof_wire_identity_for_backend_and_domain(transcript_backend, decs_evaluation_domain)?
            .opened_leaf_tape_profile()
            .map(|tape_profile| tape_profile.1),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_statement_core_with_transcript_backend_profile_and_domain(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof: &SmallwoodProof,
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
    hiding_tape_bytes: Option<usize>,
) -> Result<(), TransactionCircuitError> {
    let sha512_field_xof_scope = enter_smallwood_sha512_field_xof_scope_v1()?;
    ensure_transcript_backend_dispatch_available(transcript_backend)?;
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8 {
        ensure_poseidon2_v8_smz8_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 {
        ensure_poseidon2_v8_smz9_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 {
        ensure_poseidon2_v8_compact448_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 {
        ensure_poseidon2_v8_compact448_q20_profile(statement, profile, decs_evaluation_domain)?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        ensure_smallwood_hx512_core_contract_v1(
            statement,
            profile,
            decs_evaluation_domain,
            proof.salt.len(),
            hiding_tape_bytes.unwrap_or(0),
            proof.wire_identity,
        )?;
    }
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    ensure_row_polynomial_arithmetization(statement)?;
    if proof.digest_bytes != transcript_backend.digest_bytes() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood core proof digest width does not match the transcript backend",
        ));
    }
    if proof.strict_zk_decs_leaf_hiding != hiding_tape_bytes.is_some() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood core proof hiding mode does not match the selected profile",
        ));
    }
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof missing row-scalar opened witness data",
        ),
    )?;
    let auxiliary_words = proof.opened_witness.auxiliary_words_ref().unwrap_or(&[]);
    if row_scalars.len() != cfg.nb_opened_evals() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof opened evaluation count mismatch",
        ));
    }
    validate_proof_shape_with_hiding_profile(&cfg, proof, hiding_tape_bytes)?;
    let binded_words = transcript_binding_words_for_domain(
        &cfg,
        binded_data,
        transcript_backend,
        decs_evaluation_domain,
    )?;
    let eval_points = canonical_piop_opening_points(
        &cfg.packing_points,
        profile,
        &proof.nonce,
        &proof.h_piop,
        transcript_backend,
    )?;
    let pcs_transcript = pcs_recompute_transcript(
        &cfg,
        &proof.salt,
        &eval_points,
        row_scalars,
        &proof.pcs,
        &proof.h_piop,
        transcript_backend,
        decs_evaluation_domain,
        &binded_words,
    )?;
    let mut piop_input = pcs_transcript;
    piop_input.extend_from_slice(&binded_words);
    let piop_transcript = piop_recompute_transcript(
        &cfg,
        statement,
        &piop_input,
        &eval_points,
        row_scalars,
        auxiliary_words,
        &proof.piop,
        transcript_backend,
    )?;
    let recomputed = hash_piop_transcript(&piop_transcript, transcript_backend);
    sha512_field_xof_scope.finish()?;
    if recomputed != proof.h_piop {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood piop transcript hash mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn build_smallwood_verifier_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<SmallwoodVerifierTraceV1, TransactionCircuitError> {
    build_smallwood_verifier_trace_with_profile_v1(
        statement,
        binded_data,
        proof_bytes,
        smallwood_no_grinding_profile_for_arithmetization(statement.arithmetization()),
        transcript_backend,
    )
}

pub(crate) fn build_smallwood_verifier_trace_with_profile_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<SmallwoodVerifierTraceV1, TransactionCircuitError> {
    build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Consecutive,
    )
}

pub(crate) fn build_smallwood_verifier_trace_with_profile_and_domain_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<SmallwoodVerifierTraceV1, TransactionCircuitError> {
    let sha512_field_xof_scope = enter_smallwood_sha512_field_xof_scope_v1()?;
    ensure_transcript_backend_dispatch_available(transcript_backend)?;
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    if proof.digest_bytes != transcript_backend.digest_bytes() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof digest width does not match the transcript backend",
        ));
    }
    ensure_decs_domain_wire_binding(&proof, transcript_backend, decs_evaluation_domain)?;
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof missing row-scalar opened witness data",
        ),
    )?;
    let auxiliary_words = proof.opened_witness.auxiliary_words_ref().unwrap_or(&[]);
    if row_scalars.len() != cfg.nb_opened_evals() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof opened evaluation count mismatch",
        ));
    }
    validate_proof_shape(&cfg, &proof)?;

    let binding_words = transcript_binding_words_for_domain(
        &cfg,
        binded_data,
        transcript_backend,
        decs_evaluation_domain,
    )?;
    let eval_points = canonical_piop_opening_points(
        &cfg.packing_points,
        profile,
        &proof.nonce,
        &proof.h_piop,
        transcript_backend,
    )?;
    record_verifier_stage_profile_v1("opening_points");

    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(&cfg, &eval_points, &mut coeffs);
    record_verifier_stage_profile_v1("pcs_coefficients");
    let combi_heads =
        pcs_reconstruct_combi_heads(&cfg, &eval_points, row_scalars, &proof.pcs.partial_evals)?;
    record_verifier_stage_profile_v1("pcs_combi_heads");
    let decs_trans_hash = hash_challenge_opening_decs(
        &cfg,
        &combi_heads,
        &proof.h_piop,
        &proof.pcs.rcombi_tails,
        transcript_backend,
    );
    record_verifier_stage_profile_v1("decs_challenge_hash");
    let (decs_leaf_indexes, decs_nonce) = xof_decs_opening(
        profile.decs_nb_evals,
        profile.decs_nb_opened_evals,
        profile.decs_pow_bits,
        &decs_trans_hash,
        transcript_backend,
    )?;
    record_verifier_stage_profile_v1("decs_queries");
    let decs_eval_points = decs_field_evaluation_points(
        decs_evaluation_domain,
        cfg.decs_nb_evals(),
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals(),
        &decs_leaf_indexes,
    )?;
    let rows = lvcs_recompute_rows(
        &cfg,
        &coeffs,
        &combi_heads,
        &proof.pcs.rcombi_tails,
        &proof.pcs.subset_evals,
        &decs_eval_points,
    )?;
    record_verifier_stage_profile_v1("lvcs_rows");
    let root_digest = decs_recompute_root(
        &cfg,
        &proof.salt,
        &rows,
        &decs_leaf_indexes,
        &proof.pcs.decs,
        transcript_backend,
    )?;
    record_verifier_stage_profile_v1("merkle_root");
    let hash_mt = hash_merkle_root_with_binding(
        &proof.salt,
        &root_digest,
        transcript_backend,
        &binding_words,
    );
    let decs_gamma_all = derive_decs_challenge(
        cfg.nb_lvcs_rows,
        cfg.decs_eta(),
        cfg.decs_challenge_format,
        &hash_mt,
        transcript_backend,
    );
    let decs_commitment_transcript = decs_commitment_transcript_with_challenge(
        &cfg,
        &rows,
        &decs_eval_points,
        &proof.pcs.decs,
        &hash_mt,
        &decs_gamma_all,
        transcript_backend,
    )?;
    record_verifier_stage_profile_v1("pcs_commitment_transcript");

    let pcs_transcript_words = decs_commitment_transcript.clone();
    let mut piop_input_words = pcs_transcript_words.clone();
    piop_input_words.extend_from_slice(&binding_words);
    let piop_transcript_words = piop_recompute_transcript(
        &cfg,
        statement,
        &piop_input_words,
        &eval_points,
        row_scalars,
        auxiliary_words,
        &proof.piop,
        transcript_backend,
    )?;
    record_verifier_stage_profile_v1("piop_constraints");
    let recomputed = hash_piop_transcript(&piop_transcript_words, transcript_backend);
    let hash_fpp = hash_piop(&piop_input_words, transcript_backend);
    let piop_gamma_prime = derive_gamma_prime(&cfg, &hash_fpp, transcript_backend);
    record_verifier_stage_profile_v1("final_transcript");

    let trace_salt: [u8; SALT_BYTES] = proof.salt.as_slice().try_into().map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "historical smallwood verifier trace requires an exact 32-byte salt",
        )
    })?;
    let proof_trace = SmallwoodProofTraceV1 {
        wire_identity: proof.wire_identity,
        salt: trace_salt,
        nonce: proof.nonce,
        h_piop: proof.h_piop,
        piop: proof.piop,
        pcs: proof.pcs,
        opened_witness_row_scalars: row_scalars.to_vec(),
        auxiliary_witness_words: auxiliary_words.to_vec(),
        auxiliary_witness_limb_count: proof.opened_witness.auxiliary_limb_count(),
    };
    let pcs_trace = SmallwoodPcsVerifierTraceV1 {
        coeffs,
        combi_heads,
        decs_trans_hash,
        decs_leaf_indexes,
        decs_nonce,
        decs_eval_points,
        rows,
        root_digest,
        decs_gamma_all,
        decs_commitment_transcript,
    };
    sha512_field_xof_scope.finish()?;
    Ok(SmallwoodVerifierTraceV1 {
        profile,
        proof: proof_trace,
        binding_words,
        eval_points,
        piop_gamma_prime,
        pcs_transcript_words,
        piop_input_words,
        piop_transcript_words,
        pcs_trace,
        accept: recomputed == proof.h_piop,
    })
}

pub(crate) fn profile_smallwood_verifier_with_profile_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<
    (
        SmallwoodVerifierTraceV1,
        SmallwoodVerifierOperationProfileV1,
        Vec<SmallwoodVerifierStageOperationProfileV1>,
        Vec<SmallwoodTranscriptCallTraceV1>,
    ),
    TransactionCircuitError,
> {
    begin_verifier_operation_profile_v1()?;
    if let Err(error) = begin_verifier_stage_profile_v1() {
        finish_verifier_operation_profile_v1();
        return Err(error);
    }
    if let Err(error) = begin_transcript_call_trace_v1() {
        finish_verifier_stage_profile_v1();
        finish_verifier_operation_profile_v1();
        return Err(error);
    }
    let trace = build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        profile,
        transcript_backend,
        decs_evaluation_domain,
    );
    let operation_profile = finish_verifier_operation_profile_v1();
    let stage_operation_profiles = finish_verifier_stage_profile_v1();
    let transcript_calls = finish_transcript_call_trace_v1();
    trace.map(|trace| {
        (
            trace,
            operation_profile,
            stage_operation_profiles,
            transcript_calls,
        )
    })
}

pub fn build_smallwood_poseidon2_verifier_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<SmallwoodVerifierTraceV1, TransactionCircuitError> {
    build_smallwood_verifier_trace_v1(
        statement,
        binded_data,
        proof_bytes,
        SmallwoodTranscriptBackend::Poseidon2,
    )
}

/// Rebuild the exact SHA-512/SMZ9 verifier trace used by the V8 candidate.
///
/// This entry point exists so refinement and retained-artifact tooling can
/// inspect the same profile, disjoint-coset evaluation points, and proof bytes
/// as the verifier.  The returned `accept` field remains authoritative; this
/// function does not convert a rejecting trace into evidence.
pub fn build_smallwood_poseidon2_v8_smz9_verifier_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<SmallwoodVerifierTraceV1, TransactionCircuitError> {
    ensure_poseidon2_v8_smz9_profile(
        statement,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Rebuild the inactive profile-7 verifier trace for measurement and tests.
/// This does not select SMC7 for the frontend or grant production authority.
pub fn build_smallwood_poseidon2_v8_compact448_verifier_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<SmallwoodVerifierTraceV1, TransactionCircuitError> {
    ensure_poseidon2_v8_compact448_profile(
        statement,
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Rebuild the inactive q=20/profile-8 verifier trace for measurement/tests.
pub fn build_smallwood_poseidon2_v8_compact448_q20_verifier_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<SmallwoodVerifierTraceV1, TransactionCircuitError> {
    ensure_poseidon2_v8_compact448_q20_profile(
        statement,
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )
}

/// Replays the exact Poseidon2 verifier from a proposed outer-certificate
/// witness and requires equality with every verifier-derived trace field.
///
/// This guards witness generation. The outer proof must still constrain the
/// same recomputations algebraically.
pub fn validate_smallwood_poseidon2_verifier_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    trace: &SmallwoodVerifierTraceV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    trace.validate_sections_v1()?;
    if !trace.accept {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood outer witness contains a rejecting verifier trace",
        ));
    }
    let proof_bytes = encode_smallwood_proof_trace_v1(&trace.proof)?;
    let rebuilt = build_smallwood_verifier_trace_with_profile_v1(
        statement,
        binded_data,
        &proof_bytes,
        trace.profile,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    if !rebuilt.accept {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood outer witness canonical proof does not verify",
        ));
    }
    if rebuilt != *trace {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood outer witness trace does not match exact verifier replay",
        ));
    }
    Ok(proof_bytes)
}

pub fn smallwood_proof_from_trace_v1(trace: &SmallwoodProofTraceV1) -> SmallwoodProof {
    SmallwoodProof {
        wire_identity: trace.wire_identity,
        digest_bytes: trace.wire_identity.digest_bytes(),
        strict_zk_decs_leaf_hiding: trace.wire_identity.is_strict_zk(),
        hx512_decs_root: None,
        hx512_piop_input_digest: None,
        salt: trace.salt.to_vec(),
        nonce: trace.nonce,
        h_piop: trace.h_piop,
        piop: trace.piop.clone(),
        pcs: trace.pcs.clone(),
        opened_witness: SmallwoodOpenedWitnessBundle::row_scalars(
            trace.opened_witness_row_scalars.clone(),
            trace.auxiliary_witness_words.clone(),
            trace.auxiliary_witness_limb_count,
        ),
    }
}

pub fn encode_smallwood_proof_trace_v1(
    trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    encode_smallwood_proof_bytes_v1(&smallwood_proof_from_trace_v1(trace))
}

pub fn encode_smallwood_smz2_proof_trace_v1(
    trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if trace.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512V6Smz2 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood fresh V6 transcript encoder requires exact SMZ2 inner-wire identity",
        ));
    }
    encode_smallwood_proof_trace_v1(trace)
}

pub fn encode_smallwood_smz8_proof_trace_v1(
    trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if trace.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 encoder requires exact SMZ8 inner-wire identity",
        ));
    }
    encode_smallwood_proof_trace_v1(trace)
}

pub fn encode_smallwood_smz9_proof_trace_v1(
    trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if trace.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 successor encoder requires exact SMZ9 inner-wire identity",
        ));
    }
    encode_smallwood_proof_trace_v1(trace)
}

pub fn encode_smallwood_smc7_proof_trace_v1(
    trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if trace.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 compact encoder requires exact SMC7 inner-wire identity",
        ));
    }
    encode_smallwood_proof_trace_v1(trace)
}

pub fn encode_smallwood_smc8_proof_trace_v1(
    trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u8>, TransactionCircuitError> {
    if trace.wire_identity
        != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 q20 compact encoder requires exact SMC8 inner-wire identity",
        ));
    }
    encode_smallwood_proof_trace_v1(trace)
}

pub fn decode_smallwood_proof_trace_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProofTraceV1, TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    smallwood_proof_to_trace_v1(&proof)
}

pub fn decode_smallwood_smz8_proof_trace_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProofTraceV1, TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    if proof.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 decoder requires exact SMZ8 inner-wire identity",
        ));
    }
    smallwood_proof_to_trace_v1(&proof)
}

pub fn decode_smallwood_smz9_proof_trace_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProofTraceV1, TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    if proof.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 successor decoder requires exact SMZ9 inner-wire identity",
        ));
    }
    smallwood_proof_to_trace_v1(&proof)
}

pub fn decode_smallwood_smc7_proof_trace_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProofTraceV1, TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    if proof.wire_identity != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 compact decoder requires exact SMC7 inner-wire identity",
        ));
    }
    smallwood_proof_to_trace_v1(&proof)
}

pub fn decode_smallwood_smc8_proof_trace_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProofTraceV1, TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    if proof.wire_identity
        != SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood Poseidon2 V8 q20 compact decoder requires exact SMC8 inner-wire identity",
        ));
    }
    smallwood_proof_to_trace_v1(&proof)
}

pub fn decode_smallwood_proof_trace_prefix_v1(
    proof_bytes: &[u8],
) -> Result<(SmallwoodProofTraceV1, usize), TransactionCircuitError> {
    let (proof, consumed) = decode_smallwood_proof_bytes_prefix_v1(proof_bytes)?;
    Ok((smallwood_proof_to_trace_v1(&proof)?, consumed))
}

fn smallwood_proof_to_trace_v1(
    proof: &SmallwoodProof,
) -> Result<SmallwoodProofTraceV1, TransactionCircuitError> {
    let salt: [u8; SALT_BYTES] = proof.salt.as_slice().try_into().map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "historical smallwood proof trace requires an exact 32-byte salt",
        )
    })?;
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof missing row-scalar opened witness data",
        ),
    )?;
    Ok(SmallwoodProofTraceV1 {
        wire_identity: proof.wire_identity,
        salt,
        nonce: proof.nonce,
        h_piop: proof.h_piop,
        piop: proof.piop.clone(),
        pcs: proof.pcs.clone(),
        opened_witness_row_scalars: row_scalars.to_vec(),
        auxiliary_witness_words: proof
            .opened_witness
            .auxiliary_words_ref()
            .unwrap_or(&[])
            .to_vec(),
        auxiliary_witness_limb_count: proof.opened_witness.auxiliary_limb_count(),
    })
}

const SMALLWOOD_STRICT_WHOLE_VIEW_SIMULATOR_DOMAIN_V1: &[u8] =
    b"hegemon.smallwood.strict-whole-view-simulator.v1";
const SMALLWOOD_STRICT_WHOLE_VIEW_MERKLE_PROGRAM_INPUT_DOMAIN_V1: &[u8] =
    b"hegemon.smallwood.strict-whole-view-merkle-program-input.v1";

/// Canonical full SHA-512 random-oracle key before commitment truncation.  It
/// is exactly the byte grammar consumed by `sha512_raw_domain_digest`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SmallwoodSha512OracleKeyV1 {
    pub profile_domain: Option<Vec<u8>>,
    pub role_domain: Vec<u8>,
    pub words: Vec<u64>,
    pub counter: u64,
}

impl SmallwoodSha512OracleKeyV1 {
    fn new(
        backend: SmallwoodTranscriptBackend,
        role_domain: &[u8],
        words: &[u64],
        counter: u64,
    ) -> Self {
        Self {
            profile_domain: backend.sha512_profile_domain().map(<[u8]>::to_vec),
            role_domain: role_domain.to_vec(),
            words: words.to_vec(),
            counter,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SmallwoodSha512OracleProgramKindV1 {
    LazyMerkle,
    FinalPiop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SmallwoodSha512OracleProgramV1 {
    key: SmallwoodSha512OracleKeyV1,
    output: [u8; DIGEST_BYTES],
    kind: SmallwoodSha512OracleProgramKindV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodSha512OracleQueryV1 {
    pub key: SmallwoodSha512OracleKeyV1,
    pub output: [u8; DIGEST_BYTES],
    pub programmed_kind: Option<SmallwoodSha512OracleProgramKindV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkOracleReplayReceiptV1 {
    pub program_count: usize,
    pub query_count: usize,
    pub final_piop_program_hits: usize,
    pub lazy_merkle_program_hits: usize,
}

/// Exact typed inventory of the canonical program table materialized by one
/// strict whole-view simulation.  A salt-only program is classified by an
/// exact key whose complete raw word input is the four-word 32-byte proof
/// salt.  The current lazy route must contain none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkOracleProgramInventoryV1 {
    pub total_programs: usize,
    pub lazy_strict_leaf_programs: usize,
    pub lazy_internal_node_programs: usize,
    pub final_piop_programs: usize,
    pub salt_only_programs: usize,
    pub direct_256_bit_first_program_route_used: bool,
}

#[derive(Clone, Debug)]
struct SmallwoodSha512OracleOverlayStateV1 {
    programs: BTreeMap<
        SmallwoodSha512OracleKeyV1,
        ([u8; DIGEST_BYTES], SmallwoodSha512OracleProgramKindV1),
    >,
    queries: Vec<SmallwoodSha512OracleQueryV1>,
    hit_counts: BTreeMap<SmallwoodSha512OracleProgramKindV1, usize>,
}

thread_local! {
    static SMALLWOOD_SHA512_ORACLE_OVERLAY_V1:
        RefCell<Option<SmallwoodSha512OracleOverlayStateV1>> = const { RefCell::new(None) };
}

fn query_smallwood_sha512_oracle_overlay_v1(
    key: &SmallwoodSha512OracleKeyV1,
) -> Option<[u8; DIGEST_BYTES]> {
    let lookup = SMALLWOOD_SHA512_ORACLE_OVERLAY_V1.with(|slot| {
        let slot = slot.borrow();
        let state = slot.as_ref()?;
        Some(state.programs.get(key).copied())
    })?;
    let (output, programmed_kind) = match lookup {
        Some((output, kind)) => (output, Some(kind)),
        None => (concrete_smallwood_sha512_oracle_query_v1(key), None),
    };
    SMALLWOOD_SHA512_ORACLE_OVERLAY_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        let state = slot
            .as_mut()
            .expect("active SmallWood SHA-512 overlay disappeared during a query");
        if let Some(kind) = programmed_kind {
            *state.hit_counts.entry(kind).or_default() += 1;
        }
        state.queries.push(SmallwoodSha512OracleQueryV1 {
            key: key.clone(),
            output,
            programmed_kind,
        });
    });
    Some(output)
}

struct SmallwoodSha512OracleOverlayScopeV1 {
    active: bool,
}

impl SmallwoodSha512OracleOverlayScopeV1 {
    fn finish(mut self) -> Result<SmallwoodSha512OracleOverlayStateV1, TransactionCircuitError> {
        let state = SMALLWOOD_SHA512_ORACLE_OVERLAY_V1.with(|slot| slot.borrow_mut().take());
        self.active = false;
        state.ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SHA-512 oracle overlay state is missing",
        ))
    }
}

impl Drop for SmallwoodSha512OracleOverlayScopeV1 {
    fn drop(&mut self) {
        if self.active {
            SMALLWOOD_SHA512_ORACLE_OVERLAY_V1.with(|slot| {
                let _ = slot.borrow_mut().take();
            });
        }
    }
}

fn enter_smallwood_sha512_oracle_overlay_v1(
    programs: Vec<SmallwoodSha512OracleProgramV1>,
    prior_concrete_queries: &[SmallwoodSha512OracleKeyV1],
) -> Result<SmallwoodSha512OracleOverlayScopeV1, TransactionCircuitError> {
    let mut prior = BTreeSet::new();
    for key in prior_concrete_queries {
        if !prior.insert(key.clone()) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood SHA-512 oracle overlay repeats a prior query key",
            ));
        }
    }
    let mut table = BTreeMap::new();
    for program in programs {
        if prior.contains(&program.key) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood SHA-512 oracle program conflicts with a prior concrete query",
            ));
        }
        if table
            .insert(program.key, (program.output, program.kind))
            .is_some()
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood SHA-512 oracle overlay repeats a program key",
            ));
        }
    }
    let already_active = SMALLWOOD_SHA512_ORACLE_OVERLAY_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            true
        } else {
            *slot = Some(SmallwoodSha512OracleOverlayStateV1 {
                programs: table,
                queries: Vec::new(),
                hit_counts: BTreeMap::new(),
            });
            false
        }
    });
    if already_active {
        return Err(TransactionCircuitError::ConstraintViolation(
            "nested smallwood SHA-512 oracle overlays are forbidden",
        ));
    }
    Ok(SmallwoodSha512OracleOverlayScopeV1 { active: true })
}

/// One lazily programmed unopened Merkle subtree in the executable strict-view
/// simulator.  The `(level, node_index)` pair is the exact position consumed
/// by the compact authentication-path verifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SmallwoodStrictZkProgrammedMerkleInputV1 {
    /// A level-zero frontier digest is a strict-ZK leaf, not an internal node.
    /// Salt and leaf index are supplied by the enclosing proof and record
    /// position; these fields complete the exact role-framed SHA-512 input.
    StrictZkLeaf {
        tape: [u8; DIGEST_BYTES],
        committed_evaluations: Vec<u64>,
        masking_evaluations: Vec<u64>,
    },
    /// A frontier digest above level zero is programmed at the exact ordered
    /// two-child Merkle-node input.  The active SHA-512 grammar does not absorb
    /// the level or node index into this role input.
    MerkleNode {
        left: [u8; DIGEST_BYTES],
        right: [u8; DIGEST_BYTES],
    },
}

/// One explicit lazy-program coin.  No seed expansion occurs in the simulator:
/// every 512-bit output and every 512/1024-bit hidden input is supplied in its
/// own typed record and consumed exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkProgrammedMerkleCoinV1 {
    pub input: SmallwoodStrictZkProgrammedMerkleInputV1,
    pub output: [u8; DIGEST_BYTES],
}

/// Complete witness-free coin surface consumed by one strict whole-view run.
/// The deterministic fixture builder below is only a reproducible test-data
/// source; the simulation API itself accepts this explicit tape and never
/// treats a 64-byte seed as independent protocol coins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkWholeViewCoinsV1 {
    pub salt: [u8; SALT_BYTES],
    pub final_piop_output: [u8; DIGEST_BYTES],
    pub opened_witness_row_scalars: Vec<Vec<u64>>,
    pub pcs_partial_evaluations: Vec<Vec<u64>>,
    pub lvcs_random_tails: Vec<Vec<u64>>,
    pub decs_subset_evaluations: Vec<Vec<u64>>,
    pub decs_masking_evaluations: Vec<Vec<u64>>,
    pub decs_high_coefficients: Vec<Vec<u64>>,
    pub opened_leaf_tapes: Vec<[u8; DIGEST_BYTES]>,
    pub programmed_merkle_coins: Vec<SmallwoodStrictZkProgrammedMerkleCoinV1>,
    pub nonlinear_piop_high_coefficients: Vec<Vec<u64>>,
    pub linear_piop_high_coefficients: Vec<Vec<u64>>,
}

/// Exact draw accounting for the direct `CryptoRng` typed-coin sampler.  The
/// marker trait and this ledger establish which draws the executable consumes;
/// they do not turn a computational RNG into information-theoretically uniform
/// independent coins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkWholeViewSamplerDrawLedgerV1 {
    pub rng_bytes_consumed: usize,
    pub field_candidate_words: usize,
    pub field_rejections: usize,
    pub accepted_field_words: usize,
    pub salt_bytes: usize,
    pub opened_leaf_tape_draws_512: usize,
    pub programmed_leaf_input_draws_512: usize,
    pub programmed_internal_child_draws_512: usize,
    pub programmed_output_draws_512: usize,
    pub final_output_draws_512: usize,
    pub formal_coin_shape_bound: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkWholeViewSampleV1 {
    pub coins: SmallwoodStrictZkWholeViewCoinsV1,
    pub draw_ledger: SmallwoodStrictZkWholeViewSamplerDrawLedgerV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkWholeViewCoinConsumptionV1 {
    pub canonical_field_coins: usize,
    pub opened_leaf_tape_coins_512: usize,
    pub programmed_leaf_input_coins_512: usize,
    pub programmed_internal_input_coins_1024: usize,
    pub programmed_output_coins_512: usize,
    pub final_output_coins_512: usize,
    pub all_supplied_coins_consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkProgrammedMerkleNodeV1 {
    pub level: u32,
    pub node_index: u32,
    pub input: SmallwoodStrictZkProgrammedMerkleInputV1,
    pub digest: [u8; DIGEST_BYTES],
}

/// Exact joint level histogram for one canonical compact Merkle program.
/// Level zero is the strict-leaf role; every higher level is the ordered
/// two-child internal-node role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkProgrammedMerkleHistogramV1 {
    pub level_counts: Vec<usize>,
    pub strict_leaf_programs: usize,
    pub internal_node_programs: usize,
    pub total_programs: usize,
}

/// Source-derived joint envelope for every canonical SMZ9 compact path.  The
/// two inequalities are joint: `leaf <= 20` and `leaf + internal <= 372`.
/// Security accounting must not add the independent maxima `20 + 372`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkProgrammedMerkleJointCapV1 {
    pub tree_depth: usize,
    pub maximum_strict_leaf_programs: usize,
    pub maximum_total_programs: usize,
}

pub fn smallwood_strict_zk_programmed_merkle_histogram_v1(
    nodes: &[SmallwoodStrictZkProgrammedMerkleNodeV1],
    tree_depth: usize,
) -> Result<SmallwoodStrictZkProgrammedMerkleHistogramV1, TransactionCircuitError> {
    let mut level_counts = vec![0usize; tree_depth];
    let mut strict_leaf_programs = 0usize;
    let mut internal_node_programs = 0usize;
    for node in nodes {
        let level = node.level as usize;
        let count =
            level_counts
                .get_mut(level)
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "smallwood strict-view programmed Merkle level exceeds the tree depth",
                ))?;
        *count = count
            .checked_add(1)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view programmed Merkle histogram overflow",
            ))?;
        match (level, &node.input) {
            (0, SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf { .. }) => {
                strict_leaf_programs += 1;
            }
            (1.., SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode { .. }) => {
                internal_node_programs += 1;
            }
            _ => {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood strict-view programmed Merkle histogram role/level mismatch",
                ));
            }
        }
    }
    let total_programs = strict_leaf_programs
        .checked_add(internal_node_programs)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle histogram total overflow",
        ))?;
    if total_programs != nodes.len() || level_counts.iter().sum::<usize>() != total_programs {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle histogram total mismatch",
        ));
    }
    Ok(SmallwoodStrictZkProgrammedMerkleHistogramV1 {
        level_counts,
        strict_leaf_programs,
        internal_node_programs,
        total_programs,
    })
}

pub fn smallwood_smz9_programmed_merkle_joint_cap_v1(
) -> Result<SmallwoodStrictZkProgrammedMerkleJointCapV1, TransactionCircuitError> {
    let maximum_total_programs = maximum_smallwood_compact_authentication_nodes_v1(
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_evals,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_opened_evals,
    )?;
    if maximum_total_programs != SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ9 compact Merkle joint cap drift",
        ));
    }
    Ok(SmallwoodStrictZkProgrammedMerkleJointCapV1 {
        tree_depth: POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE
            .decs_nb_evals
            .ilog2() as usize,
        maximum_strict_leaf_programs: POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE
            .decs_nb_opened_evals,
        maximum_total_programs,
    })
}

/// Exact canonical proof view emitted by the executable ROM simulator harness.
///
/// The final PIOP hash entry is recorded as a programmed oracle entry.  The
/// concrete SHA-512 verifier is also replayed and recorded, but is not required
/// to accept that programmed view.  This is executable refinement evidence; it
/// is deliberately not a complete-ZK, QROM, or production-authorization claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodStrictZkWholeViewSimulationV1 {
    pub proof_bytes: Vec<u8>,
    /// Verifier trace obtained through the canonical programmed-oracle overlay.
    pub verifier_trace: SmallwoodVerifierTraceV1,
    /// The same proof replayed against unmodified concrete SHA-512.
    pub concrete_verifier_trace: SmallwoodVerifierTraceV1,
    pub programmed_merkle_nodes: Vec<SmallwoodStrictZkProgrammedMerkleNodeV1>,
    pub programmed_merkle_histogram: SmallwoodStrictZkProgrammedMerkleHistogramV1,
    pub programmed_final_piop_input_words: Vec<u64>,
    pub programmed_final_piop_output: [u8; DIGEST_BYTES],
    pub prior_sha512_queries: Vec<SmallwoodSha512OracleKeyV1>,
    pub oracle_query_trace: Vec<SmallwoodSha512OracleQueryV1>,
    pub oracle_replay_receipt: SmallwoodStrictZkOracleReplayReceiptV1,
    pub coin_consumption: SmallwoodStrictZkWholeViewCoinConsumptionV1,
    pub raw_witness_words_consumed: usize,
    pub concrete_sha512_accepts: bool,
}

/// Deterministic fixture-only expander.  It is never accepted by the simulator
/// as an entropy source; callers must first materialize the complete typed tape.
struct SmallwoodStrictWholeViewFixtureRngV1 {
    seed: [u8; DIGEST_BYTES],
    counter: u64,
    block: [u8; DIGEST_BYTES],
    offset: usize,
}

impl SmallwoodStrictWholeViewFixtureRngV1 {
    fn new(seed: [u8; DIGEST_BYTES]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0u8; DIGEST_BYTES],
            offset: DIGEST_BYTES,
        }
    }

    fn refill(&mut self) -> Result<(), TransactionCircuitError> {
        let mut hasher = Sha512::new();
        hasher.update((SMALLWOOD_STRICT_WHOLE_VIEW_SIMULATOR_DOMAIN_V1.len() as u64).to_le_bytes());
        hasher.update(SMALLWOOD_STRICT_WHOLE_VIEW_SIMULATOR_DOMAIN_V1);
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        self.block = hasher.finalize().into();
        self.counter =
            self.counter
                .checked_add(1)
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "smallwood strict-view simulator counter exhausted",
                ))?;
        self.offset = 0;
        Ok(())
    }

    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), TransactionCircuitError> {
        let mut written = 0usize;
        while written < output.len() {
            if self.offset == DIGEST_BYTES {
                self.refill()?;
            }
            let take = min(DIGEST_BYTES - self.offset, output.len() - written);
            output[written..written + take]
                .copy_from_slice(&self.block[self.offset..self.offset + take]);
            self.offset += take;
            written += take;
        }
        Ok(())
    }

    fn digest(&mut self) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        let mut output = [0u8; DIGEST_BYTES];
        self.fill_bytes(&mut output)?;
        Ok(output)
    }

    fn field_word(&mut self) -> Result<u64, TransactionCircuitError> {
        // The harness exposes its own bounded abort instead of conditioning or
        // resampling the whole view.  Sixty-four trials already make this tail
        // negligible relative to any profile in this engine.
        for _ in 0..64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes)?;
            let candidate = u64::from_le_bytes(bytes);
            if candidate < FIELD_ORDER {
                return Ok(candidate);
            }
        }
        Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator field rejection budget exhausted",
        ))
    }

    fn matrix(
        &mut self,
        rows: usize,
        columns: usize,
    ) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
        (0..rows)
            .map(|_| (0..columns).map(|_| self.field_word()).collect())
            .collect()
    }
}

fn smallwood_hidden_merkle_fixture_rng_v1(
    simulator_seed: [u8; DIGEST_BYTES],
) -> SmallwoodStrictWholeViewFixtureRngV1 {
    let mut hasher = Sha512::new();
    hasher.update(
        (SMALLWOOD_STRICT_WHOLE_VIEW_MERKLE_PROGRAM_INPUT_DOMAIN_V1.len() as u64).to_le_bytes(),
    );
    hasher.update(SMALLWOOD_STRICT_WHOLE_VIEW_MERKLE_PROGRAM_INPUT_DOMAIN_V1);
    hasher.update(simulator_seed);
    SmallwoodStrictWholeViewFixtureRngV1::new(hasher.finalize().into())
}

fn sample_smallwood_hidden_merkle_fixture_input_v1(
    cfg: &SmallwoodConfig,
    level: usize,
    rng: &mut SmallwoodStrictWholeViewFixtureRngV1,
) -> Result<SmallwoodStrictZkProgrammedMerkleInputV1, TransactionCircuitError> {
    if level == 0 {
        let tape = rng.digest()?;
        let committed_evaluations = (0..cfg.nb_lvcs_rows)
            .map(|_| rng.field_word())
            .collect::<Result<Vec<_>, _>>()?;
        let masking_evaluations = (0..cfg.decs_eta())
            .map(|_| rng.field_word())
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf {
            tape,
            committed_evaluations,
            masking_evaluations,
        });
    }
    Ok(SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode {
        left: rng.digest()?,
        right: rng.digest()?,
    })
}

fn canonical_smallwood_programmed_merkle_input_v1(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
    node: &SmallwoodStrictZkProgrammedMerkleNodeV1,
) -> Result<(Vec<u8>, Vec<u64>), TransactionCircuitError> {
    let level = node.level as usize;
    let node_index = node.node_index as usize;
    let depth = cfg.decs_nb_evals().ilog2() as usize;
    if level >= depth || node_index >= (cfg.decs_nb_evals() >> level) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle position is out of range",
        ));
    }
    match (&node.input, level) {
        (
            SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf {
                tape,
                committed_evaluations,
                masking_evaluations,
            },
            0,
        ) => {
            if committed_evaluations.len() != cfg.nb_lvcs_rows
                || masking_evaluations.len() != cfg.decs_eta()
                || committed_evaluations
                    .iter()
                    .chain(masking_evaluations)
                    .any(|&word| word >= FIELD_ORDER)
            {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood strict-view programmed leaf input is noncanonical",
                ));
            }
            let words = strict_zk_merkle_leaf_words(
                &bytes_to_words_unchecked(salt),
                node_index,
                tape,
                committed_evaluations,
                masking_evaluations,
            )?;
            Ok((SMALLWOOD_STRICT_ZK_MERKLE_LEAF_DOMAIN_V1.to_vec(), words))
        }
        (SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode { left, right }, 1..) => {
            let mut words = Vec::with_capacity(2 * transcript_backend.digest_words());
            words.extend(digest_to_words(left, transcript_backend));
            words.extend(digest_to_words(right, transcript_backend));
            Ok((
                transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_MERKLE_NODE_DOMAIN).to_vec(),
                words,
            ))
        }
        (SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf { .. }, _) => {
            Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view programmed leaf input appears above level zero",
            ))
        }
        (SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode { .. }, 0) => {
            Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view programmed node input appears at level zero",
            ))
        }
    }
}

fn smallwood_compact_merkle_program_positions_v1(
    cfg: &SmallwoodConfig,
    leaf_indexes: &[u32],
) -> Result<Vec<(usize, usize)>, TransactionCircuitError> {
    if leaf_indexes.len() != cfg.decs_nb_opened_evals()
        || leaf_indexes
            .iter()
            .any(|&index| index as usize >= cfg.decs_nb_evals())
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view fixture leaf-index shape is invalid",
        ));
    }
    let mut current_indices = leaf_indexes
        .iter()
        .map(|&index| index as usize)
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut positions = Vec::new();
    for level in 0..cfg.decs_nb_evals().ilog2() as usize {
        let level_opened = current_indices.iter().copied().collect::<BTreeSet<_>>();
        for &index in &current_indices {
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            if !level_opened.contains(&sibling) && seen.insert((level, sibling)) {
                positions.push((level, sibling));
            }
        }
        for index in &mut current_indices {
            *index /= 2;
        }
    }
    Ok(positions)
}

fn simulate_smallwood_compact_merkle_program_v1(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    rows: &[Vec<u64>],
    leaf_indexes: &[u32],
    masking_evals: &[Vec<u64>],
    leaf_tapes: &[Vec<u8>],
    transcript_backend: SmallwoodTranscriptBackend,
    program_coins: &mut VecDeque<SmallwoodStrictZkProgrammedMerkleCoinV1>,
) -> Result<
    (
        Vec<Vec<[u8; DIGEST_BYTES]>>,
        Vec<SmallwoodStrictZkProgrammedMerkleNodeV1>,
        [u8; DIGEST_BYTES],
    ),
    TransactionCircuitError,
> {
    if rows.len() != leaf_indexes.len()
        || masking_evals.len() != leaf_indexes.len()
        || leaf_tapes.len() != leaf_indexes.len()
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator Merkle opening count mismatch",
        ));
    }
    let mut current_indices = leaf_indexes
        .iter()
        .map(|&index| index as usize)
        .collect::<Vec<_>>();
    let mut current_hashes = Vec::with_capacity(rows.len());
    for opening in 0..rows.len() {
        let mut leaf_evals = rows[opening].clone();
        leaf_evals.extend_from_slice(&masking_evals[opening]);
        current_hashes.push(hash_strict_zk_merkle_leaf(
            cfg.nb_lvcs_rows,
            &leaf_evals,
            current_indices[opening],
            &leaf_tapes[opening],
            salt,
            transcript_backend,
        )?);
    }

    let mut paths = vec![Vec::new(); leaf_indexes.len()];
    let mut programmed = BTreeMap::<(usize, usize), SmallwoodStrictZkProgrammedMerkleNodeV1>::new();
    let depth = cfg.decs_nb_evals().ilog2() as usize;
    for level in 0..depth {
        let level_hashes = current_indices
            .iter()
            .copied()
            .zip(current_hashes.iter().copied())
            .collect::<BTreeMap<_, _>>();
        let level_opened = current_indices.iter().copied().collect::<BTreeSet<_>>();
        let mut next_hashes = Vec::with_capacity(current_hashes.len());
        for opening in 0..current_indices.len() {
            let index = current_indices[opening];
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            let sibling_hash = if level_opened.contains(&sibling) {
                *level_hashes
                    .get(&sibling)
                    .ok_or(TransactionCircuitError::ConstraintViolation(
                        "smallwood strict-view simulator opened sibling hash is missing",
                    ))?
            } else {
                let digest = if let Some(program) = programmed.get(&(level, sibling)) {
                    program.digest
                } else {
                    let coin = program_coins.pop_front().ok_or(
                        TransactionCircuitError::ConstraintViolation(
                            "smallwood strict-view programmed Merkle coin tape underflow",
                        ),
                    )?;
                    let digest = coin.output;
                    programmed.insert(
                        (level, sibling),
                        SmallwoodStrictZkProgrammedMerkleNodeV1 {
                            level: level as u32,
                            node_index: sibling as u32,
                            input: coin.input,
                            digest,
                        },
                    );
                    digest
                };
                paths[opening].push(digest);
                digest
            };
            next_hashes.push(hash_merkle_children_at(
                if index.is_multiple_of(2) {
                    &current_hashes[opening]
                } else {
                    &sibling_hash
                },
                if index.is_multiple_of(2) {
                    &sibling_hash
                } else {
                    &current_hashes[opening]
                },
                level,
                index / 2,
                transcript_backend,
            ));
        }
        for index in &mut current_indices {
            *index /= 2;
        }
        current_hashes = next_hashes;
    }
    let root =
        current_hashes
            .first()
            .copied()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view simulator Merkle root is missing",
            ))?;
    if current_hashes.iter().any(|candidate| *candidate != root) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator compact Merkle paths disagree on the root",
        ));
    }
    if !program_coins.is_empty() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle coin tape has unconsumed entries",
        ));
    }
    let programmed = programmed.into_values().collect();
    Ok((paths, programmed, root))
}

fn extract_smallwood_compact_merkle_program_v1(
    cfg: &SmallwoodConfig,
    leaf_indexes: &[u32],
    paths: &[Vec<[u8; DIGEST_BYTES]>],
) -> Result<BTreeMap<(usize, usize), [u8; DIGEST_BYTES]>, TransactionCircuitError> {
    if paths.len() != leaf_indexes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle path count mismatch",
        ));
    }
    let mut current_indices = leaf_indexes
        .iter()
        .map(|&index| index as usize)
        .collect::<Vec<_>>();
    let mut cursors = vec![0usize; paths.len()];
    let mut programmed = BTreeMap::<(usize, usize), [u8; DIGEST_BYTES]>::new();
    for level in 0..cfg.decs_nb_evals().ilog2() as usize {
        let level_opened = current_indices.iter().copied().collect::<BTreeSet<_>>();
        for opening in 0..current_indices.len() {
            let index = current_indices[opening];
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            if !level_opened.contains(&sibling) {
                let digest = paths[opening].get(cursors[opening]).copied().ok_or(
                    TransactionCircuitError::ConstraintViolation(
                        "smallwood strict-view programmed Merkle path underflow",
                    ),
                )?;
                cursors[opening] += 1;
                if programmed
                    .insert((level, sibling), digest)
                    .is_some_and(|existing| existing != digest)
                {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "smallwood strict-view programmed Merkle node is inconsistent",
                    ));
                }
            }
        }
        for index in &mut current_indices {
            *index /= 2;
        }
    }
    if cursors
        .iter()
        .zip(paths)
        .any(|(&cursor, path)| cursor != path.len())
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle path has trailing nodes",
        ));
    }
    Ok(programmed)
}

fn smallwood_strict_whole_view_oracle_programs_v1(
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
    programmed_merkle_nodes: &[SmallwoodStrictZkProgrammedMerkleNodeV1],
    programmed_final_piop_input_words: &[u64],
    programmed_final_piop_output: [u8; DIGEST_BYTES],
) -> Result<Vec<SmallwoodSha512OracleProgramV1>, TransactionCircuitError> {
    let mut programs = Vec::with_capacity(programmed_merkle_nodes.len() + 1);
    for node in programmed_merkle_nodes {
        let (domain, words) =
            canonical_smallwood_programmed_merkle_input_v1(cfg, salt, transcript_backend, node)?;
        programs.push(SmallwoodSha512OracleProgramV1 {
            key: SmallwoodSha512OracleKeyV1::new(transcript_backend, &domain, &words, 0),
            output: node.digest,
            kind: SmallwoodSha512OracleProgramKindV1::LazyMerkle,
        });
    }
    programs.push(SmallwoodSha512OracleProgramV1 {
        key: SmallwoodSha512OracleKeyV1::new(
            transcript_backend,
            transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_PIOP_TRANSCRIPT_DOMAIN),
            programmed_final_piop_input_words,
            0,
        ),
        output: programmed_final_piop_output,
        kind: SmallwoodSha512OracleProgramKindV1::FinalPiop,
    });
    Ok(programs)
}

/// Rebuild and classify every exact raw SHA-512 program key in the scoped
/// simulator overlay.  This is source inventory only: excluding a salt-only
/// route does not prove the fresh typed inputs have information-theoretic
/// conditional entropy or that adaptive QROM programming is applicable.
pub fn smallwood_strict_whole_view_oracle_program_inventory_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    simulation: &SmallwoodStrictZkWholeViewSimulationV1,
) -> Result<SmallwoodStrictZkOracleProgramInventoryV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    let decoded = decode_smallwood_proof_trace_v1(&simulation.proof_bytes)?;
    let programs = smallwood_strict_whole_view_oracle_programs_v1(
        &cfg,
        &decoded.salt,
        transcript_backend,
        &simulation.programmed_merkle_nodes,
        &simulation.programmed_final_piop_input_words,
        simulation.programmed_final_piop_output,
    )?;
    let salt_words = bytes_to_words_unchecked(&decoded.salt);
    let salt_only_programs = programs
        .iter()
        .filter(|program| program.key.words.as_slice() == salt_words.as_slice())
        .count();
    let final_piop_programs = programs
        .iter()
        .filter(|program| program.kind == SmallwoodSha512OracleProgramKindV1::FinalPiop)
        .count();
    let lazy_programs = programs
        .iter()
        .filter(|program| program.kind == SmallwoodSha512OracleProgramKindV1::LazyMerkle)
        .count();
    if programs.len() != simulation.programmed_merkle_nodes.len() + 1
        || lazy_programs != simulation.programmed_merkle_nodes.len()
        || final_piop_programs != 1
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view oracle program inventory count mismatch",
        ));
    }
    Ok(SmallwoodStrictZkOracleProgramInventoryV1 {
        total_programs: programs.len(),
        lazy_strict_leaf_programs: simulation.programmed_merkle_histogram.strict_leaf_programs,
        lazy_internal_node_programs: simulation
            .programmed_merkle_histogram
            .internal_node_programs,
        final_piop_programs,
        salt_only_programs,
        direct_256_bit_first_program_route_used: salt_only_programs != 0,
    })
}

const SMALLWOOD_STRICT_WHOLE_VIEW_ORACLE_PROGRAM_VECTOR_DOMAIN_V1: &[u8] =
    b"hegemon.smallwood.strict-whole-view-oracle-program-vector.v1";
const SMALLWOOD_STRICT_WHOLE_VIEW_ORACLE_QUERY_VECTOR_DOMAIN_V1: &[u8] =
    b"hegemon.smallwood.strict-whole-view-oracle-query-vector.v1";

fn hash_smallwood_sha512_oracle_key_v1(hasher: &mut Sha512, key: &SmallwoodSha512OracleKeyV1) {
    match &key.profile_domain {
        Some(domain) => {
            hasher.update([1u8]);
            hasher.update((domain.len() as u64).to_le_bytes());
            hasher.update(domain);
        }
        None => hasher.update([0u8]),
    }
    hasher.update((key.role_domain.len() as u64).to_le_bytes());
    hasher.update(&key.role_domain);
    hasher.update((key.words.len() as u64).to_le_bytes());
    for word in &key.words {
        hasher.update(word.to_le_bytes());
    }
    hasher.update(key.counter.to_le_bytes());
}

fn hash_smallwood_sha512_oracle_program_kind_v1(
    hasher: &mut Sha512,
    kind: SmallwoodSha512OracleProgramKindV1,
) {
    hasher.update([match kind {
        SmallwoodSha512OracleProgramKindV1::LazyMerkle => 0,
        SmallwoodSha512OracleProgramKindV1::FinalPiop => 1,
    }]);
}

/// Digest the exact sorted full-output program table consumed by the scoped
/// verifier overlay.  This is a deterministic cross-language vector anchor,
/// not an entropy, QROM, or production-authority receipt.
pub fn smallwood_strict_whole_view_oracle_program_table_sha512_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    simulation: &SmallwoodStrictZkWholeViewSimulationV1,
) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    let decoded = decode_smallwood_proof_trace_v1(&simulation.proof_bytes)?;
    let mut programs = smallwood_strict_whole_view_oracle_programs_v1(
        &cfg,
        &decoded.salt,
        transcript_backend,
        &simulation.programmed_merkle_nodes,
        &simulation.programmed_final_piop_input_words,
        simulation.programmed_final_piop_output,
    )?;
    programs.sort_by(|left, right| left.key.cmp(&right.key));
    let mut hasher = Sha512::new();
    hasher.update(
        (SMALLWOOD_STRICT_WHOLE_VIEW_ORACLE_PROGRAM_VECTOR_DOMAIN_V1.len() as u64).to_le_bytes(),
    );
    hasher.update(SMALLWOOD_STRICT_WHOLE_VIEW_ORACLE_PROGRAM_VECTOR_DOMAIN_V1);
    hasher.update((programs.len() as u64).to_le_bytes());
    for program in programs {
        hash_smallwood_sha512_oracle_key_v1(&mut hasher, &program.key);
        hash_smallwood_sha512_oracle_program_kind_v1(&mut hasher, program.kind);
        hasher.update(program.output);
    }
    Ok(hasher.finalize().into())
}

/// Digest the ordered canonical SHA-512 query trace observed during overlay
/// replay, including whether and how each query hit the program table.
pub fn smallwood_strict_whole_view_oracle_query_trace_sha512_v1(
    simulation: &SmallwoodStrictZkWholeViewSimulationV1,
) -> [u8; DIGEST_BYTES] {
    let mut hasher = Sha512::new();
    hasher.update(
        (SMALLWOOD_STRICT_WHOLE_VIEW_ORACLE_QUERY_VECTOR_DOMAIN_V1.len() as u64).to_le_bytes(),
    );
    hasher.update(SMALLWOOD_STRICT_WHOLE_VIEW_ORACLE_QUERY_VECTOR_DOMAIN_V1);
    hasher.update((simulation.oracle_query_trace.len() as u64).to_le_bytes());
    for query in &simulation.oracle_query_trace {
        hash_smallwood_sha512_oracle_key_v1(&mut hasher, &query.key);
        match query.programmed_kind {
            Some(kind) => {
                hasher.update([1u8]);
                hash_smallwood_sha512_oracle_program_kind_v1(&mut hasher, kind);
            }
            None => hasher.update([0u8]),
        }
        hasher.update(query.output);
    }
    hasher.finalize().into()
}

fn replay_smallwood_strict_whole_view_oracle_overlay_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    proof_bytes: &[u8],
    cfg: &SmallwoodConfig,
    salt: &[u8; SALT_BYTES],
    programmed_merkle_nodes: &[SmallwoodStrictZkProgrammedMerkleNodeV1],
    programmed_final_piop_input_words: &[u64],
    programmed_final_piop_output: [u8; DIGEST_BYTES],
    prior_sha512_queries: &[SmallwoodSha512OracleKeyV1],
) -> Result<
    (
        SmallwoodVerifierTraceV1,
        Vec<SmallwoodSha512OracleQueryV1>,
        SmallwoodStrictZkOracleReplayReceiptV1,
    ),
    TransactionCircuitError,
> {
    let programs = smallwood_strict_whole_view_oracle_programs_v1(
        cfg,
        salt,
        transcript_backend,
        programmed_merkle_nodes,
        programmed_final_piop_input_words,
        programmed_final_piop_output,
    )?;
    let overlay_scope = enter_smallwood_sha512_oracle_overlay_v1(programs, prior_sha512_queries)?;
    let trace = build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let overlay = overlay_scope.finish()?;
    trace.validate_sections_v1()?;
    let final_piop_program_hits = overlay
        .hit_counts
        .get(&SmallwoodSha512OracleProgramKindV1::FinalPiop)
        .copied()
        .unwrap_or(0);
    let lazy_merkle_program_hits = overlay
        .hit_counts
        .get(&SmallwoodSha512OracleProgramKindV1::LazyMerkle)
        .copied()
        .unwrap_or(0);
    if !trace.accept || final_piop_program_hits != 1 || lazy_merkle_program_hits != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed-oracle replay did not have the exact hit surface",
        ));
    }
    let receipt = SmallwoodStrictZkOracleReplayReceiptV1 {
        program_count: overlay.programs.len(),
        query_count: overlay.queries.len(),
        final_piop_program_hits,
        lazy_merkle_program_hits,
    };
    Ok((trace, overlay.queries, receipt))
}

/// Materialize a deterministic, fully typed test fixture.  The returned tape
/// is the simulator input; the seed is not.  Production or theorem-backed
/// freshness must supply an independently sampled value of this exact type.
pub fn build_smallwood_strict_whole_view_fixture_coins_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    fixture_seed: [u8; DIGEST_BYTES],
) -> Result<SmallwoodStrictZkWholeViewCoinsV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    if cfg.auxiliary_witness_word_count != 0 || cfg.auxiliary_witness_limb_count != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view fixture refuses auxiliary witness coins",
        ));
    }
    let wire_identity = proof_wire_identity_for_backend_and_domain(
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let (expected_openings, tape_bytes) = wire_identity.opened_leaf_tape_profile().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view fixture requires a strict tape wire",
        ),
    )?;
    if profile.decs_nb_opened_evals != expected_openings || tape_bytes != DIGEST_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view fixture profile has the wrong tape geometry",
        ));
    }

    let transcript_scope = enter_smallwood_sha512_field_xof_scope_v1()?;
    let mut rng = SmallwoodStrictWholeViewFixtureRngV1::new(fixture_seed);
    let mut hidden_input_rng = smallwood_hidden_merkle_fixture_rng_v1(fixture_seed);
    let mut salt = [0u8; SALT_BYTES];
    rng.fill_bytes(&mut salt)?;
    let final_piop_output = rng.digest()?;
    let nonce = choose_opening_nonce_for_profile(
        &cfg.packing_points,
        profile,
        &final_piop_output,
        transcript_backend,
    )?;
    let eval_points = canonical_piop_opening_points(
        &cfg.packing_points,
        profile,
        &nonce,
        &final_piop_output,
        transcript_backend,
    )?;
    let opened_witness_row_scalars = rng.matrix(cfg.nb_opened_evals(), cfg.nb_polys)?;
    let pcs_partial_evaluations =
        rng.matrix(cfg.nb_opened_evals(), cfg.nb_unstacked_cols - cfg.nb_polys)?;
    let combi_heads = pcs_reconstruct_combi_heads(
        &cfg,
        &eval_points,
        &opened_witness_row_scalars,
        &pcs_partial_evaluations,
    )?;
    let lvcs_random_tails = rng.matrix(cfg.nb_lvcs_opened_combi, cfg.decs_nb_opened_evals())?;
    let decs_trans_hash = hash_challenge_opening_decs(
        &cfg,
        &combi_heads,
        &final_piop_output,
        &lvcs_random_tails,
        transcript_backend,
    );
    let (decs_leaf_indexes, _) = xof_decs_opening(
        cfg.decs_nb_evals(),
        cfg.decs_nb_opened_evals(),
        cfg.decs_pow_bits(),
        &decs_trans_hash,
        transcript_backend,
    )?;
    let decs_subset_evaluations = rng.matrix(
        cfg.decs_nb_opened_evals(),
        cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi,
    )?;
    let decs_masking_evaluations = rng.matrix(cfg.decs_nb_opened_evals(), cfg.decs_eta())?;
    let decs_high_coefficients = rng.matrix(cfg.decs_eta(), cfg.nb_lvcs_cols)?;
    let opened_leaf_tapes = (0..cfg.decs_nb_opened_evals())
        .map(|_| rng.digest())
        .collect::<Result<Vec<_>, _>>()?;
    let programmed_merkle_coins =
        smallwood_compact_merkle_program_positions_v1(&cfg, &decs_leaf_indexes)?
            .into_iter()
            .map(|(level, _)| {
                Ok(SmallwoodStrictZkProgrammedMerkleCoinV1 {
                    output: rng.digest()?,
                    input: sample_smallwood_hidden_merkle_fixture_input_v1(
                        &cfg,
                        level,
                        &mut hidden_input_rng,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, TransactionCircuitError>>()?;
    let nonlinear_piop_high_coefficients =
        rng.matrix(cfg.rho(), cfg.mpol_poly_degree + 1 - cfg.nb_opened_evals())?;
    let linear_piop_high_coefficients = rng.matrix(
        cfg.rho(),
        cfg.mlin_poly_degree + 1 - (cfg.nb_opened_evals() + 1),
    )?;
    transcript_scope.finish()?;

    Ok(SmallwoodStrictZkWholeViewCoinsV1 {
        salt,
        final_piop_output,
        opened_witness_row_scalars,
        pcs_partial_evaluations,
        lvcs_random_tails,
        decs_subset_evaluations,
        decs_masking_evaluations,
        decs_high_coefficients,
        opened_leaf_tapes,
        programmed_merkle_coins,
        nonlinear_piop_high_coefficients,
        linear_piop_high_coefficients,
    })
}

struct SmallwoodStrictWholeViewCryptoSamplerV1<'a, R: CryptoRng + RngCore + ?Sized> {
    rng: &'a mut R,
    ledger: SmallwoodStrictZkWholeViewSamplerDrawLedgerV1,
}

impl<'a, R: CryptoRng + RngCore + ?Sized> SmallwoodStrictWholeViewCryptoSamplerV1<'a, R> {
    fn new(rng: &'a mut R) -> Self {
        Self {
            rng,
            ledger: SmallwoodStrictZkWholeViewSamplerDrawLedgerV1 {
                rng_bytes_consumed: 0,
                field_candidate_words: 0,
                field_rejections: 0,
                accepted_field_words: 0,
                salt_bytes: 0,
                opened_leaf_tape_draws_512: 0,
                programmed_leaf_input_draws_512: 0,
                programmed_internal_child_draws_512: 0,
                programmed_output_draws_512: 0,
                final_output_draws_512: 0,
                formal_coin_shape_bound: false,
            },
        }
    }

    fn bump(value: &mut usize, amount: usize) -> Result<(), TransactionCircuitError> {
        *value = value
            .checked_add(amount)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view CryptoRng draw ledger overflow",
            ))?;
        Ok(())
    }

    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), TransactionCircuitError> {
        self.rng.fill_bytes(output);
        Self::bump(&mut self.ledger.rng_bytes_consumed, output.len())
    }

    fn digest(&mut self) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
        let mut output = [0u8; DIGEST_BYTES];
        self.fill_bytes(&mut output)?;
        Ok(output)
    }

    fn field_word(&mut self) -> Result<u64, TransactionCircuitError> {
        loop {
            let candidate = self.rng.next_u64();
            Self::bump(&mut self.ledger.rng_bytes_consumed, 8)?;
            Self::bump(&mut self.ledger.field_candidate_words, 1)?;
            if candidate < FIELD_ORDER {
                Self::bump(&mut self.ledger.accepted_field_words, 1)?;
                return Ok(candidate);
            }
            Self::bump(&mut self.ledger.field_rejections, 1)?;
        }
    }

    fn matrix(
        &mut self,
        rows: usize,
        columns: usize,
    ) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
        (0..rows)
            .map(|_| (0..columns).map(|_| self.field_word()).collect())
            .collect()
    }

    fn field_vector(&mut self, len: usize) -> Result<Vec<u64>, TransactionCircuitError> {
        (0..len).map(|_| self.field_word()).collect()
    }
}

/// Sample the complete strict whole-view tape directly from a caller-supplied
/// cryptographic RNG.  Every field element uses exact rejection sampling; each
/// 512-bit leaf/final/output value and each ordered internal child is a distinct
/// RNG draw recorded in the returned ledger.  `CryptoRng` is a computational
/// interface marker, not a proof of the formal independent-uniform coin model.
pub fn sample_smallwood_strict_whole_view_coins_v1<R: CryptoRng + RngCore + ?Sized>(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    rng: &mut R,
) -> Result<SmallwoodStrictZkWholeViewSampleV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    if cfg.auxiliary_witness_word_count != 0 || cfg.auxiliary_witness_limb_count != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view CryptoRng sampler refuses auxiliary witness coins",
        ));
    }
    let wire_identity = proof_wire_identity_for_backend_and_domain(
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let (expected_openings, tape_bytes) = wire_identity.opened_leaf_tape_profile().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view CryptoRng sampler requires a strict tape wire",
        ),
    )?;
    if profile.decs_nb_opened_evals != expected_openings || tape_bytes != DIGEST_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view CryptoRng sampler profile has the wrong tape geometry",
        ));
    }

    let transcript_scope = enter_smallwood_sha512_field_xof_scope_v1()?;
    let mut sampler = SmallwoodStrictWholeViewCryptoSamplerV1::new(rng);
    let mut salt = [0u8; SALT_BYTES];
    sampler.fill_bytes(&mut salt)?;
    sampler.ledger.salt_bytes = SALT_BYTES;
    let final_piop_output = sampler.digest()?;
    sampler.ledger.final_output_draws_512 = 1;
    let nonce = choose_opening_nonce_for_profile(
        &cfg.packing_points,
        profile,
        &final_piop_output,
        transcript_backend,
    )?;
    let eval_points = canonical_piop_opening_points(
        &cfg.packing_points,
        profile,
        &nonce,
        &final_piop_output,
        transcript_backend,
    )?;
    let opened_witness_row_scalars = sampler.matrix(cfg.nb_opened_evals(), cfg.nb_polys)?;
    let pcs_partial_evaluations =
        sampler.matrix(cfg.nb_opened_evals(), cfg.nb_unstacked_cols - cfg.nb_polys)?;
    let combi_heads = pcs_reconstruct_combi_heads(
        &cfg,
        &eval_points,
        &opened_witness_row_scalars,
        &pcs_partial_evaluations,
    )?;
    let lvcs_random_tails = sampler.matrix(cfg.nb_lvcs_opened_combi, cfg.decs_nb_opened_evals())?;
    let decs_trans_hash = hash_challenge_opening_decs(
        &cfg,
        &combi_heads,
        &final_piop_output,
        &lvcs_random_tails,
        transcript_backend,
    );
    let (decs_leaf_indexes, _) = xof_decs_opening(
        cfg.decs_nb_evals(),
        cfg.decs_nb_opened_evals(),
        cfg.decs_pow_bits(),
        &decs_trans_hash,
        transcript_backend,
    )?;
    let decs_subset_evaluations = sampler.matrix(
        cfg.decs_nb_opened_evals(),
        cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi,
    )?;
    let decs_masking_evaluations = sampler.matrix(cfg.decs_nb_opened_evals(), cfg.decs_eta())?;
    let decs_high_coefficients = sampler.matrix(cfg.decs_eta(), cfg.nb_lvcs_cols)?;
    let mut opened_leaf_tapes = Vec::with_capacity(cfg.decs_nb_opened_evals());
    for _ in 0..cfg.decs_nb_opened_evals() {
        opened_leaf_tapes.push(sampler.digest()?);
        SmallwoodStrictWholeViewCryptoSamplerV1::<R>::bump(
            &mut sampler.ledger.opened_leaf_tape_draws_512,
            1,
        )?;
    }
    let positions = smallwood_compact_merkle_program_positions_v1(&cfg, &decs_leaf_indexes)?;
    let mut programmed_merkle_coins = Vec::with_capacity(positions.len());
    for (level, _) in positions {
        let output = sampler.digest()?;
        SmallwoodStrictWholeViewCryptoSamplerV1::<R>::bump(
            &mut sampler.ledger.programmed_output_draws_512,
            1,
        )?;
        let input = if level == 0 {
            let tape = sampler.digest()?;
            SmallwoodStrictWholeViewCryptoSamplerV1::<R>::bump(
                &mut sampler.ledger.programmed_leaf_input_draws_512,
                1,
            )?;
            SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf {
                tape,
                committed_evaluations: sampler.field_vector(cfg.nb_lvcs_rows)?,
                masking_evaluations: sampler.field_vector(cfg.decs_eta())?,
            }
        } else {
            let left = sampler.digest()?;
            let right = sampler.digest()?;
            SmallwoodStrictWholeViewCryptoSamplerV1::<R>::bump(
                &mut sampler.ledger.programmed_internal_child_draws_512,
                2,
            )?;
            SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode { left, right }
        };
        programmed_merkle_coins.push(SmallwoodStrictZkProgrammedMerkleCoinV1 { input, output });
    }
    let nonlinear_piop_high_coefficients =
        sampler.matrix(cfg.rho(), cfg.mpol_poly_degree + 1 - cfg.nb_opened_evals())?;
    let linear_piop_high_coefficients = sampler.matrix(
        cfg.rho(),
        cfg.mlin_poly_degree + 1 - (cfg.nb_opened_evals() + 1),
    )?;
    transcript_scope.finish()?;

    let coins = SmallwoodStrictZkWholeViewCoinsV1 {
        salt,
        final_piop_output,
        opened_witness_row_scalars,
        pcs_partial_evaluations,
        lvcs_random_tails,
        decs_subset_evaluations,
        decs_masking_evaluations,
        decs_high_coefficients,
        opened_leaf_tapes,
        programmed_merkle_coins,
        nonlinear_piop_high_coefficients,
        linear_piop_high_coefficients,
    };
    let consumption = validate_smallwood_strict_whole_view_coin_shapes_v1(&cfg, &coins)?;
    if sampler.ledger.accepted_field_words != consumption.canonical_field_coins
        || sampler.ledger.opened_leaf_tape_draws_512 != consumption.opened_leaf_tape_coins_512
        || sampler.ledger.programmed_leaf_input_draws_512
            != consumption.programmed_leaf_input_coins_512
        || sampler.ledger.programmed_internal_child_draws_512
            != 2 * consumption.programmed_internal_input_coins_1024
        || sampler.ledger.programmed_output_draws_512 != consumption.programmed_output_coins_512
        || sampler.ledger.final_output_draws_512 != consumption.final_output_coins_512
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view CryptoRng draw ledger does not bind the formal coin shape",
        ));
    }
    sampler.ledger.formal_coin_shape_bound = true;
    Ok(SmallwoodStrictZkWholeViewSampleV1 {
        coins,
        draw_ledger: sampler.ledger,
    })
}

fn validate_smallwood_strict_coin_matrix_v1(
    matrix: &[Vec<u64>],
    rows: usize,
    columns: usize,
) -> Result<(), TransactionCircuitError> {
    if matrix.len() != rows
        || matrix.iter().any(|row| row.len() != columns)
        || matrix.iter().flatten().any(|&word| word >= FIELD_ORDER)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view typed field-coin matrix is noncanonical",
        ));
    }
    Ok(())
}

fn validate_smallwood_strict_whole_view_coin_shapes_v1(
    cfg: &SmallwoodConfig,
    coins: &SmallwoodStrictZkWholeViewCoinsV1,
) -> Result<SmallwoodStrictZkWholeViewCoinConsumptionV1, TransactionCircuitError> {
    let shapes = [
        (
            &coins.opened_witness_row_scalars,
            cfg.nb_opened_evals(),
            cfg.nb_polys,
        ),
        (
            &coins.pcs_partial_evaluations,
            cfg.nb_opened_evals(),
            cfg.nb_unstacked_cols - cfg.nb_polys,
        ),
        (
            &coins.lvcs_random_tails,
            cfg.nb_lvcs_opened_combi,
            cfg.decs_nb_opened_evals(),
        ),
        (
            &coins.decs_subset_evaluations,
            cfg.decs_nb_opened_evals(),
            cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi,
        ),
        (
            &coins.decs_masking_evaluations,
            cfg.decs_nb_opened_evals(),
            cfg.decs_eta(),
        ),
        (
            &coins.decs_high_coefficients,
            cfg.decs_eta(),
            cfg.nb_lvcs_cols,
        ),
        (
            &coins.nonlinear_piop_high_coefficients,
            cfg.rho(),
            cfg.mpol_poly_degree + 1 - cfg.nb_opened_evals(),
        ),
        (
            &coins.linear_piop_high_coefficients,
            cfg.rho(),
            cfg.mlin_poly_degree + 1 - (cfg.nb_opened_evals() + 1),
        ),
    ];
    let typed_field_coins = shapes
        .iter()
        .map(|(_, rows, columns)| rows * columns)
        .sum::<usize>();
    for &(matrix, rows, columns) in &shapes {
        validate_smallwood_strict_coin_matrix_v1(matrix, rows, columns)?;
    }
    if coins.opened_leaf_tapes.len() != cfg.decs_nb_opened_evals() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view typed opened-leaf tape count mismatch",
        ));
    }

    let mut fresh_inputs = BTreeSet::new();
    for tape in &coins.opened_leaf_tapes {
        if !fresh_inputs.insert(*tape) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view typed tape reuses a 512-bit input coin",
            ));
        }
    }
    let mut leaf_programs = 0usize;
    let mut internal_programs = 0usize;
    let mut hidden_field_coins = 0usize;
    for coin in &coins.programmed_merkle_coins {
        match &coin.input {
            SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf {
                tape,
                committed_evaluations,
                masking_evaluations,
            } => {
                if committed_evaluations.len() != cfg.nb_lvcs_rows
                    || masking_evaluations.len() != cfg.decs_eta()
                    || committed_evaluations
                        .iter()
                        .chain(masking_evaluations)
                        .any(|&word| word >= FIELD_ORDER)
                    || !fresh_inputs.insert(*tape)
                {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "smallwood strict-view typed programmed-leaf coins are invalid or reused",
                    ));
                }
                leaf_programs += 1;
                hidden_field_coins += committed_evaluations.len() + masking_evaluations.len();
            }
            SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode { left, right } => {
                if left == right || !fresh_inputs.insert(*left) || !fresh_inputs.insert(*right) {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "smallwood strict-view typed internal-node coins are reused",
                    ));
                }
                internal_programs += 1;
            }
        }
    }
    let canonical_field_coins = typed_field_coins + hidden_field_coins;
    Ok(SmallwoodStrictZkWholeViewCoinConsumptionV1 {
        canonical_field_coins,
        opened_leaf_tape_coins_512: coins.opened_leaf_tapes.len(),
        programmed_leaf_input_coins_512: leaf_programs,
        programmed_internal_input_coins_1024: internal_programs,
        programmed_output_coins_512: coins.programmed_merkle_coins.len(),
        final_output_coins_512: 1,
        all_supplied_coins_consumed: true,
    })
}

/// Simulate the exact strict SmallWood serialized view without reading a raw
/// witness.  `Sha512Level5` emits SMZ1; the same geometry-generic path emits
/// SMZ8, SMZ9, or inactive SMC7/SMC8 when called with the corresponding V8 backend
/// and exact profile.
pub fn simulate_smallwood_strict_whole_view_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    coins: SmallwoodStrictZkWholeViewCoinsV1,
) -> Result<SmallwoodStrictZkWholeViewSimulationV1, TransactionCircuitError> {
    if !matches!(
        transcript_backend,
        SmallwoodTranscriptBackend::Sha512Level5
            | SmallwoodTranscriptBackend::Sha512Poseidon2V8
            | SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9
            | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7
            | SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8
    ) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator supports only SMZ1, SMZ8, SMZ9, SMC7, or SMC8 SHA-512 backends",
        ));
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8 {
        ensure_poseidon2_v8_smz8_profile(
            statement,
            profile,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 {
        ensure_poseidon2_v8_smz9_profile(
            statement,
            profile,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 {
        ensure_poseidon2_v8_compact448_profile(
            statement,
            profile,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )?;
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 {
        ensure_poseidon2_v8_compact448_q20_profile(
            statement,
            profile,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )?;
    }
    ensure_row_polynomial_arithmetization(statement)?;
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    if cfg.auxiliary_witness_word_count != 0 || cfg.auxiliary_witness_limb_count != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator refuses witness-dependent auxiliary proof words",
        ));
    }
    let wire_identity = proof_wire_identity_for_backend_and_domain(
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let (expected_openings, tape_bytes) = wire_identity.opened_leaf_tape_profile().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator requires a strict tape wire",
        ),
    )?;
    if profile.decs_nb_opened_evals != expected_openings || tape_bytes != DIGEST_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator profile does not match its wire opening count",
        ));
    }

    let coin_consumption = validate_smallwood_strict_whole_view_coin_shapes_v1(&cfg, &coins)?;
    let SmallwoodStrictZkWholeViewCoinsV1 {
        salt,
        final_piop_output: h_piop,
        opened_witness_row_scalars,
        pcs_partial_evaluations: partial_evals,
        lvcs_random_tails: rcombi_tails,
        decs_subset_evaluations: subset_evals,
        decs_masking_evaluations: masking_evals,
        decs_high_coefficients: high_coeffs,
        opened_leaf_tapes,
        programmed_merkle_coins,
        nonlinear_piop_high_coefficients: ppol_highs,
        linear_piop_high_coefficients: plin_highs,
    } = coins;
    let transcript_scope = enter_smallwood_sha512_field_xof_scope_v1()?;
    let nonce = choose_opening_nonce_for_profile(
        &cfg.packing_points,
        profile,
        &h_piop,
        transcript_backend,
    )?;
    let eval_points = canonical_piop_opening_points(
        &cfg.packing_points,
        profile,
        &nonce,
        &h_piop,
        transcript_backend,
    )?;
    let combi_heads = pcs_reconstruct_combi_heads(
        &cfg,
        &eval_points,
        &opened_witness_row_scalars,
        &partial_evals,
    )?;
    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(&cfg, &eval_points, &mut coeffs);
    let decs_trans_hash = hash_challenge_opening_decs(
        &cfg,
        &combi_heads,
        &h_piop,
        &rcombi_tails,
        transcript_backend,
    );
    let (decs_leaf_indexes, _) = xof_decs_opening(
        cfg.decs_nb_evals(),
        cfg.decs_nb_opened_evals(),
        cfg.decs_pow_bits(),
        &decs_trans_hash,
        transcript_backend,
    )?;
    let decs_eval_points = decs_field_evaluation_points(
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        cfg.decs_nb_evals(),
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals(),
        &decs_leaf_indexes,
    )?;
    let rows = lvcs_recompute_rows(
        &cfg,
        &coeffs,
        &combi_heads,
        &rcombi_tails,
        &subset_evals,
        &decs_eval_points,
    )?;
    let leaf_tapes = opened_leaf_tapes
        .into_iter()
        .map(|tape| tape.to_vec())
        .collect::<Vec<_>>();
    let mut programmed_merkle_coin_cursor = VecDeque::from(programmed_merkle_coins);
    let (auth_paths, programmed_merkle_nodes, root_digest) =
        simulate_smallwood_compact_merkle_program_v1(
            &cfg,
            &salt,
            &rows,
            &decs_leaf_indexes,
            &masking_evals,
            &leaf_tapes,
            transcript_backend,
            &mut programmed_merkle_coin_cursor,
        )?;
    transcript_scope.finish()?;

    let proof_trace = SmallwoodProofTraceV1 {
        wire_identity,
        salt,
        nonce,
        h_piop,
        piop: PiopProof {
            ppol_highs,
            plin_highs,
        },
        pcs: PcsProof {
            rcombi_tails,
            subset_evals,
            partial_evals,
            decs: DecsProof {
                auth_paths,
                leaf_tapes,
                masking_evals,
                high_coeffs,
            },
        },
        opened_witness_row_scalars,
        auxiliary_witness_words: Vec::new(),
        auxiliary_witness_limb_count: 0,
    };
    let proof = smallwood_proof_from_trace_v1(&proof_trace);
    validate_proof_shape_with_hiding_profile(&cfg, &proof, Some(tape_bytes))?;
    let rebuilt_root = decs_recompute_root(
        &cfg,
        &salt,
        &rows,
        &decs_leaf_indexes,
        &proof_trace.pcs.decs,
        transcript_backend,
    )?;
    if rebuilt_root != root_digest {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator Merkle root refinement mismatch",
        ));
    }
    let proof_bytes = encode_smallwood_proof_trace_v1(&proof_trace)?;
    if encode_smallwood_proof_trace_v1(&decode_smallwood_proof_trace_v1(&proof_bytes)?)?
        != proof_bytes
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator emitted a noncanonical proof wire",
        ));
    }
    let concrete_verifier_trace = build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        &proof_bytes,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    concrete_verifier_trace.validate_sections_v1()?;
    let programmed_final_piop_input_words = concrete_verifier_trace.piop_transcript_words.clone();
    let concrete_sha512_accepts = concrete_verifier_trace.accept;
    let prior_sha512_queries = Vec::new();
    let (verifier_trace, oracle_query_trace, oracle_replay_receipt) =
        replay_smallwood_strict_whole_view_oracle_overlay_v1(
            statement,
            binded_data,
            profile,
            transcript_backend,
            &proof_bytes,
            &cfg,
            &salt,
            &programmed_merkle_nodes,
            &programmed_final_piop_input_words,
            h_piop,
            &prior_sha512_queries,
        )?;
    if oracle_replay_receipt.program_count != programmed_merkle_nodes.len() + 1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed-oracle table count mismatch",
        ));
    }
    let programmed_merkle_histogram = smallwood_strict_zk_programmed_merkle_histogram_v1(
        &programmed_merkle_nodes,
        cfg.decs_nb_evals().ilog2() as usize,
    )?;
    if programmed_merkle_histogram.strict_leaf_programs
        != coin_consumption.programmed_leaf_input_coins_512
        || programmed_merkle_histogram.internal_node_programs
            != coin_consumption.programmed_internal_input_coins_1024
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle histogram/coin ledger mismatch",
        ));
    }
    Ok(SmallwoodStrictZkWholeViewSimulationV1 {
        proof_bytes,
        verifier_trace,
        concrete_verifier_trace,
        programmed_merkle_nodes,
        programmed_merkle_histogram,
        programmed_final_piop_input_words,
        programmed_final_piop_output: h_piop,
        prior_sha512_queries,
        oracle_query_trace,
        oracle_replay_receipt,
        coin_consumption,
        raw_witness_words_consumed: 0,
        concrete_sha512_accepts,
    })
}

pub fn simulate_smallwood_smz1_whole_view_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    coins: SmallwoodStrictZkWholeViewCoinsV1,
) -> Result<SmallwoodStrictZkWholeViewSimulationV1, TransactionCircuitError> {
    simulate_smallwood_strict_whole_view_v1(
        statement,
        binded_data,
        profile,
        SmallwoodTranscriptBackend::Sha512Level5,
        coins,
    )
}

/// Replay the concrete verifier-facing structure and every recorded oracle
/// program through the scoped SHA-512 overlay.  Concrete SHA-512 is also run
/// and recorded separately; a concrete rejection is never called refinement.
pub fn validate_smallwood_strict_whole_view_simulation_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    simulation: &SmallwoodStrictZkWholeViewSimulationV1,
) -> Result<(), TransactionCircuitError> {
    if simulation.raw_witness_words_consumed != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulator consumed raw witness words",
        ));
    }
    if !simulation.coin_consumption.all_supplied_coins_consumed
        || simulation.coin_consumption.final_output_coins_512 != 1
        || simulation.coin_consumption.programmed_output_coins_512
            != simulation.programmed_merkle_nodes.len()
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulation coin-consumption ledger mismatch",
        ));
    }
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    let rebuilt_histogram = smallwood_strict_zk_programmed_merkle_histogram_v1(
        &simulation.programmed_merkle_nodes,
        cfg.decs_nb_evals().ilog2() as usize,
    )?;
    let maximum_total_programs = maximum_smallwood_compact_authentication_nodes_v1(
        cfg.decs_nb_evals(),
        cfg.decs_nb_opened_evals(),
    )?;
    if rebuilt_histogram != simulation.programmed_merkle_histogram
        || rebuilt_histogram.strict_leaf_programs > cfg.decs_nb_opened_evals()
        || rebuilt_histogram.total_programs > maximum_total_programs
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed Merkle joint histogram mismatch",
        ));
    }
    let decoded = decode_smallwood_proof_trace_v1(&simulation.proof_bytes)?;
    if encode_smallwood_proof_trace_v1(&decoded)? != simulation.proof_bytes {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulation wire is not canonical",
        ));
    }
    let rebuilt = build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        &simulation.proof_bytes,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    rebuilt.validate_sections_v1()?;
    if rebuilt != simulation.concrete_verifier_trace {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulation concrete verifier trace mismatch",
        ));
    }
    if simulation.programmed_final_piop_input_words != rebuilt.piop_transcript_words
        || simulation.programmed_final_piop_output != rebuilt.proof.h_piop
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulation final PIOP oracle program mismatch",
        ));
    }
    if simulation.concrete_sha512_accepts != rebuilt.accept {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulation concrete verifier result mismatch",
        ));
    }
    let expected_program = extract_smallwood_compact_merkle_program_v1(
        &cfg,
        &rebuilt.pcs_trace.decs_leaf_indexes,
        &rebuilt.proof.pcs.decs.auth_paths,
    )?;
    if expected_program.len() != simulation.programmed_merkle_nodes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view simulation Merkle oracle program count mismatch",
        ));
    }
    let mut seen_positions = BTreeSet::new();
    let mut seen_inputs = BTreeSet::new();
    let mut previous_position = None;
    for node in &simulation.programmed_merkle_nodes {
        let position = (node.level as usize, node.node_index as usize);
        if previous_position.is_some_and(|previous| previous >= position) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view simulation Merkle programs are not canonically ordered",
            ));
        }
        previous_position = Some(position);
        if !seen_positions.insert(position) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view simulation repeats a Merkle program position",
            ));
        }
        if expected_program.get(&position) != Some(&node.digest) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view simulation Merkle program output/path mismatch",
            ));
        }
        let input = canonical_smallwood_programmed_merkle_input_v1(
            &cfg,
            &rebuilt.proof.salt,
            transcript_backend,
            node,
        )?;
        if !seen_inputs.insert(input) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-view simulation repeats a Merkle oracle input",
            ));
        }
    }
    // Deliberately do not require concrete SHA-512(input) == digest here: the
    // recorded pair is a lazy QRO program.  Instead, execute every pair through
    // the canonical overlay and require the exact one-hit final-PIOP surface.
    let (overlay_trace, oracle_query_trace, oracle_replay_receipt) =
        replay_smallwood_strict_whole_view_oracle_overlay_v1(
            statement,
            binded_data,
            profile,
            transcript_backend,
            &simulation.proof_bytes,
            &cfg,
            &rebuilt.proof.salt,
            &simulation.programmed_merkle_nodes,
            &simulation.programmed_final_piop_input_words,
            simulation.programmed_final_piop_output,
            &simulation.prior_sha512_queries,
        )?;
    if overlay_trace != simulation.verifier_trace
        || oracle_query_trace != simulation.oracle_query_trace
        || oracle_replay_receipt != simulation.oracle_replay_receipt
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-view programmed-oracle replay trace mismatch",
        ));
    }
    Ok(())
}

pub fn report_smallwood_proof_size_v1(
    proof_bytes: &[u8],
) -> Result<SmallwoodProofSizeReportV1, TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    let total_bytes = proof_bytes.len();
    let salt_bytes = SMALLWOOD_PROOF_WIRE_MAGIC_V1.len() + proof.salt.len();
    let nonce_bytes = proof.nonce.len();
    let h_piop_bytes = proof.digest_bytes;
    let piop_bytes = encoded_matrix_u64_bytes_v1(&proof.piop.ppol_highs)?
        + encoded_matrix_u64_bytes_v1(&proof.piop.plin_highs)?;
    let pcs_rcombi_tails_bytes = encoded_matrix_u64_bytes_v1(&proof.pcs.rcombi_tails)?;
    let pcs_subset_evals_bytes = encoded_matrix_u64_bytes_v1(&proof.pcs.subset_evals)?;
    let pcs_partial_evals_bytes = encoded_matrix_u64_bytes_v1(&proof.pcs.partial_evals)?;
    let decs_auth_paths_bytes =
        encoded_auth_paths_bytes_v1(&proof.pcs.decs.auth_paths, proof.digest_bytes)?;
    let decs_leaf_tapes_bytes = proof
        .pcs
        .decs
        .leaf_tapes
        .len()
        .checked_mul(SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS leaf-tape byte count overflow",
        ))?;
    let decs_masking_evals_bytes = encoded_matrix_u64_bytes_v1(&proof.pcs.decs.masking_evals)?;
    let decs_high_coeffs_bytes = encoded_matrix_u64_bytes_v1(&proof.pcs.decs.high_coeffs)?;
    let opened_witness_bytes = encoded_opened_witness_bytes_v1(&proof.opened_witness)?;
    let transcript_bytes = salt_bytes + nonce_bytes + h_piop_bytes + piop_bytes;
    let commitment_bytes = decs_auth_paths_bytes;
    let opened_values_bytes = pcs_subset_evals_bytes + pcs_partial_evals_bytes;
    let opening_payload_bytes = pcs_rcombi_tails_bytes
        + decs_leaf_tapes_bytes
        + decs_masking_evals_bytes
        + decs_high_coeffs_bytes
        + opened_witness_bytes;
    let accounted =
        transcript_bytes + commitment_bytes + opened_values_bytes + opening_payload_bytes;
    if accounted > total_bytes {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood proof size report over-accounted bytes: accounted={accounted} total={total_bytes}"
        )));
    }
    Ok(SmallwoodProofSizeReportV1 {
        total_bytes,
        transcript_bytes,
        commitment_bytes,
        opened_values_bytes,
        opening_payload_bytes,
        opened_witness_bytes,
        other_bytes: total_bytes - accounted,
        salt_bytes,
        nonce_bytes,
        h_piop_bytes,
        piop_bytes,
        pcs_rcombi_tails_bytes,
        pcs_subset_evals_bytes,
        pcs_partial_evals_bytes,
        decs_auth_paths_bytes,
        decs_leaf_tapes_bytes,
        decs_masking_evals_bytes,
        decs_high_coeffs_bytes,
    })
}

fn compact_decs_auth_path_node_budget(
    leaf_indexes: &[u32],
    decs_domain_size: usize,
) -> (usize, usize, usize, usize) {
    if leaf_indexes.is_empty() {
        return (0, 0, 0, 0);
    }
    let depth = decs_domain_size.ilog2() as usize;
    let mut current_indices = leaf_indexes
        .iter()
        .map(|&idx| idx as usize)
        .collect::<Vec<_>>();
    let mut total_nodes = 0usize;
    let mut unique_nodes = std::collections::BTreeSet::new();
    for level in 0..depth {
        let level_indices = current_indices
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut next_indices = Vec::with_capacity(current_indices.len());
        let mut has_next = false;
        for &index in &current_indices {
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            if !level_indices.contains(&sibling_index) {
                total_nodes += 1;
                unique_nodes.insert((level, sibling_index));
            }
            if level + 1 < depth {
                next_indices.push(index / 2);
                has_next = true;
            }
        }
        if !has_next {
            break;
        }
        current_indices = next_indices;
    }
    let distinct_leaf_count = leaf_indexes
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    (
        distinct_leaf_count,
        leaf_indexes.len().saturating_sub(distinct_leaf_count),
        total_nodes,
        unique_nodes.len(),
    )
}

pub fn report_smallwood_backend_opening_surface_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<SmallwoodBackendOpeningSurfaceReportV1, TransactionCircuitError> {
    report_smallwood_backend_opening_surface_with_profile_v1(
        statement,
        binded_data,
        proof_bytes,
        smallwood_no_grinding_profile_for_arithmetization(statement.arithmetization()),
        transcript_backend,
    )
}

pub fn report_smallwood_backend_opening_surface_with_profile_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<SmallwoodBackendOpeningSurfaceReportV1, TransactionCircuitError> {
    report_smallwood_backend_opening_surface_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Consecutive,
    )
}

pub(crate) fn report_smallwood_backend_opening_surface_with_profile_and_domain_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_data: &[u8],
    proof_bytes: &[u8],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<SmallwoodBackendOpeningSurfaceReportV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let trace = build_smallwood_verifier_trace_with_profile_and_domain_v1(
        statement,
        binded_data,
        proof_bytes,
        profile,
        transcript_backend,
        decs_evaluation_domain,
    )?;
    let size = report_smallwood_proof_size_v1(proof_bytes)?;
    let opened_row_count = trace.proof.opened_witness_row_scalars.len();
    let opened_row_width = trace
        .proof
        .opened_witness_row_scalars
        .first()
        .map_or(0usize, |row| row.len());
    let decs_opened_leaf_count = trace.pcs_trace.decs_leaf_indexes.len();
    let (
        decs_distinct_leaf_count,
        decs_duplicate_leaf_count,
        decs_total_auth_nodes,
        decs_unique_auth_nodes,
    ) = compact_decs_auth_path_node_budget(&trace.pcs_trace.decs_leaf_indexes, cfg.decs_nb_evals());
    let path_lengths = trace
        .proof
        .pcs
        .decs
        .auth_paths
        .iter()
        .map(|path| path.len())
        .collect::<Vec<_>>();
    let decs_min_auth_path_len = path_lengths.iter().copied().min().unwrap_or(0);
    let decs_max_auth_path_len = path_lengths.iter().copied().max().unwrap_or(0);
    let opened_witness_invariant_column_count =
        invariant_column_count_u64(&trace.proof.opened_witness_row_scalars);
    let pcs_subset_invariant_column_count =
        invariant_column_count_u64(&trace.proof.pcs.subset_evals);
    let pcs_partial_invariant_column_count =
        invariant_column_count_u64(&trace.proof.pcs.partial_evals);
    let opened_witness_invariant_compaction_raw_bytes = opened_witness_invariant_column_count
        .saturating_mul(opened_row_count.saturating_sub(1))
        .saturating_mul(std::mem::size_of::<u64>());
    let pcs_subset_invariant_compaction_raw_bytes = pcs_subset_invariant_column_count
        .saturating_mul(trace.proof.pcs.subset_evals.len().saturating_sub(1))
        .saturating_mul(std::mem::size_of::<u64>());
    let pcs_partial_invariant_compaction_raw_bytes = pcs_partial_invariant_column_count
        .saturating_mul(trace.proof.pcs.partial_evals.len().saturating_sub(1))
        .saturating_mul(std::mem::size_of::<u64>());
    let opened_witness_row_scalar_floor_raw_bytes = opened_row_count
        .saturating_mul(cfg.nb_polys)
        .saturating_mul(std::mem::size_of::<u64>());
    let opened_witness_partial_extra_slot_count =
        cfg.nb_unstacked_cols.saturating_sub(cfg.nb_polys);
    let opened_witness_partial_poly_count = cfg.width.iter().filter(|&&width| width > 1).count();
    let opened_witness_partial_raw_bytes = opened_row_count
        .saturating_mul(opened_witness_partial_extra_slot_count)
        .saturating_mul(std::mem::size_of::<u64>());
    let subset_eval_shape_floor_raw_bytes = trace
        .proof
        .pcs
        .subset_evals
        .len()
        .saturating_mul(cfg.nb_lvcs_rows.saturating_sub(cfg.nb_lvcs_opened_combi))
        .saturating_mul(std::mem::size_of::<u64>());
    let subset_eval_shape_matches_beta_packing_identity = trace
        .proof
        .pcs
        .subset_evals
        .first()
        .is_none_or(|row| row.len() == cfg.beta().saturating_mul(cfg.packing_factor));
    Ok(SmallwoodBackendOpeningSurfaceReportV1 {
        total_inner_proof_bytes: size.total_bytes,
        transcript_bytes: size.transcript_bytes,
        commitment_bytes: size.commitment_bytes,
        opened_values_bytes: size.opened_values_bytes,
        opening_payload_bytes: size.opening_payload_bytes,
        opened_witness_bytes: size.opened_witness_bytes,
        pcs_rcombi_tails_bytes: size.pcs_rcombi_tails_bytes,
        pcs_subset_evals_bytes: size.pcs_subset_evals_bytes,
        pcs_partial_evals_bytes: size.pcs_partial_evals_bytes,
        decs_auth_paths_bytes: size.decs_auth_paths_bytes,
        decs_leaf_tapes_bytes: size.decs_leaf_tapes_bytes,
        decs_masking_evals_bytes: size.decs_masking_evals_bytes,
        decs_high_coeffs_bytes: size.decs_high_coeffs_bytes,
        nb_polys: cfg.nb_polys,
        nb_unstacked_cols: cfg.nb_unstacked_cols,
        nb_lvcs_rows: cfg.nb_lvcs_rows,
        nb_lvcs_cols: cfg.nb_lvcs_cols,
        nb_lvcs_opened_combi: cfg.nb_lvcs_opened_combi,
        opened_row_count,
        opened_row_width,
        pcs_rcombi_tail_width: trace
            .proof
            .pcs
            .rcombi_tails
            .first()
            .map_or(0, |row| row.len()),
        pcs_subset_eval_width: trace
            .proof
            .pcs
            .subset_evals
            .first()
            .map_or(0, |row| row.len()),
        pcs_partial_eval_width: trace
            .proof
            .pcs
            .partial_evals
            .first()
            .map_or(0, |row| row.len()),
        opened_witness_invariant_column_count,
        pcs_subset_invariant_column_count,
        pcs_partial_invariant_column_count,
        opened_witness_invariant_compaction_raw_bytes,
        pcs_subset_invariant_compaction_raw_bytes,
        pcs_partial_invariant_compaction_raw_bytes,
        opened_witness_row_scalar_floor_raw_bytes,
        opened_witness_partial_extra_slot_count,
        opened_witness_partial_poly_count,
        opened_witness_partial_raw_bytes,
        subset_eval_shape_floor_raw_bytes,
        subset_eval_shape_matches_beta_packing_identity,
        decs_opened_leaf_count,
        decs_distinct_leaf_count,
        decs_duplicate_leaf_count,
        decs_total_auth_nodes,
        decs_unique_auth_nodes,
        decs_duplicate_auth_nodes: decs_total_auth_nodes.saturating_sub(decs_unique_auth_nodes),
        decs_min_auth_path_len,
        decs_max_auth_path_len,
    })
}

fn log2_binom_ratio_large_over_small(large_n: u128, small_n: u128, k: usize) -> f64 {
    (0..k)
        .map(|i| {
            let i = i as u128;
            ((large_n - i) as f64 / (small_n - i) as f64).log2()
        })
        .sum()
}

fn log2_binomial(n: u128, k: usize) -> f64 {
    if n < k as u128 {
        return f64::INFINITY;
    }
    let complement = n - k as u128;
    let reduced_k = if complement < k as u128 {
        complement as usize
    } else {
        k
    };
    (0..reduced_k)
        .map(|index| {
            let index = index as u128;
            ((n - index) as f64 / (index + 1) as f64).log2()
        })
        .sum()
}

pub fn report_smallwood_no_grinding_soundness_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    public_value_count: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodNoGrindingSoundnessReportV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    Ok(report_smallwood_no_grinding_soundness_from_cfg(
        &cfg,
        public_value_count,
    ))
}

pub fn smallwood_no_grinding_exact_128_bit_term_checks(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    public_value_count: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<[bool; 4], TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    Ok(smallwood_no_grinding_exact_term_checks_from_cfg(
        &cfg,
        public_value_count,
        128,
    ))
}

pub fn smallwood_no_grinding_exact_256_bit_term_checks(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    public_value_count: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<[bool; 4], TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    Ok(smallwood_no_grinding_exact_term_checks_from_cfg(
        &cfg,
        public_value_count,
        256,
    ))
}

pub fn smallwood_no_grinding_exact_128_bit_aggregate_check(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    public_value_count: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<bool, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    Ok(smallwood_no_grinding_exact_128_bit_aggregate_check_from_cfg(&cfg, public_value_count))
}

pub fn smallwood_no_grinding_exact_256_bit_aggregate_check(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    public_value_count: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<bool, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    Ok(smallwood_no_grinding_exact_aggregate_check_from_cfg(
        &cfg,
        public_value_count,
        256,
    ))
}

pub fn smallwood_no_grinding_exact_260_bit_aggregate_check(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    public_value_count: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<bool, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    Ok(smallwood_no_grinding_exact_aggregate_check_from_cfg(
        &cfg,
        public_value_count,
        260,
    ))
}

pub fn report_smallwood_lvcs_planner_projection_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    public_value_count: usize,
    auxiliary_words_len: usize,
    profile: SmallwoodNoGrindingProfileV1,
    planner: SmallwoodLvcsPlannerGeometryKindV1,
) -> Result<SmallwoodLvcsPlannerProjectionReportV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    let projected_cfg = project_lvcs_planner_geometry_cfg(&cfg, planner)?;
    let soundness =
        report_smallwood_no_grinding_soundness_from_cfg(&projected_cfg, public_value_count);
    let (transcript_backend, decs_evaluation_domain) = match statement.arithmetization() {
        SmallwoodArithmetization::DirectPacked64CompressedLevel5
        | SmallwoodArithmetization::DirectPacked128CompressedLevel5 => (
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodDecsEvaluationDomain::Radix2Subgroup,
        ),
        SmallwoodArithmetization::DirectPacked64CompressedV6Sha512Smz2 => (
            SmallwoodTranscriptBackend::Sha512V6,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        ),
        SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1 => (
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        ),
        SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz8 => (
            SmallwoodTranscriptBackend::Sha512Poseidon2V8,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        ),
        SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9 => (
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        ),
        SmallwoodArithmetization::DirectPacked64CompressedLevel5FullSha512First48CommitmentV3 => (
            SmallwoodTranscriptBackend::FullSha512First48CommitmentV3,
            SmallwoodDecsEvaluationDomain::Radix2Subgroup,
        ),
        SmallwoodArithmetization::DirectRadix4Packed1024Hx512Candidate => {
            return Err(TransactionCircuitError::ConstraintViolation(
                "fresh HX512 proof sizing requires the dedicated radix-4/K1024 entrypoint",
            ));
        }
        _ => (
            SmallwoodTranscriptBackend::Blake3,
            SmallwoodDecsEvaluationDomain::Consecutive,
        ),
    };
    Ok(SmallwoodLvcsPlannerProjectionReportV1 {
        planner,
        total_lvcs_cells: cfg.nb_unstacked_rows.saturating_mul(cfg.nb_unstacked_cols),
        nb_lvcs_rows: projected_cfg.nb_lvcs_rows,
        nb_lvcs_cols: projected_cfg.nb_lvcs_cols,
        nb_lvcs_opened_combi: projected_cfg.nb_lvcs_opened_combi,
        subset_eval_width: projected_cfg
            .nb_lvcs_rows
            .saturating_sub(projected_cfg.nb_lvcs_opened_combi),
        projected_inner_proof_bytes: serialized_proof_size_hint_with_profile(
            &projected_cfg,
            profile,
            auxiliary_words_len,
            transcript_backend,
            decs_evaluation_domain,
        )?,
        soundness,
    })
}

#[derive(Clone, Debug)]
struct StructuralIdentityWitnessStatement {
    arithmetization: SmallwoodArithmetization,
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    linear_offsets: Vec<u32>,
    linear_indices: Vec<u32>,
    linear_coefficients: Vec<u64>,
    linear_targets: Vec<u64>,
    auxiliary_words: Vec<u64>,
}

impl StructuralIdentityWitnessStatement {
    fn new(
        row_count: usize,
        packing_factor: usize,
        constraint_degree: usize,
        constraint_count: usize,
        auxiliary_words_len: usize,
    ) -> Result<Self, TransactionCircuitError> {
        Self::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
            row_count,
            packing_factor,
            constraint_degree,
            constraint_count,
            auxiliary_words_len,
        )
    }

    fn new_for_arithmetization(
        arithmetization: SmallwoodArithmetization,
        row_count: usize,
        packing_factor: usize,
        constraint_degree: usize,
        constraint_count: usize,
        auxiliary_words_len: usize,
    ) -> Result<Self, TransactionCircuitError> {
        if row_count == 0 || packing_factor == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood structural shape requires non-zero row_count and packing_factor",
            ));
        }
        let witness_size = row_count.checked_mul(packing_factor).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "smallwood structural witness size overflow",
            ),
        )?;
        let mut linear_offsets = Vec::with_capacity(witness_size + 1);
        let mut linear_indices = Vec::with_capacity(witness_size);
        let mut linear_coefficients = Vec::with_capacity(witness_size);
        let mut linear_targets = Vec::with_capacity(witness_size);
        linear_offsets.push(0);
        for idx in 0..witness_size {
            linear_indices.push(idx as u32);
            linear_coefficients.push(1);
            linear_targets.push(0);
            linear_offsets.push((idx + 1) as u32);
        }
        Ok(Self {
            arithmetization,
            row_count,
            packing_factor,
            constraint_degree,
            constraint_count,
            linear_offsets,
            linear_indices,
            linear_coefficients,
            linear_targets,
            auxiliary_words: vec![0u64; auxiliary_words_len],
        })
    }

    fn with_linear_targets(
        row_count: usize,
        packing_factor: usize,
        constraint_degree: usize,
        constraint_count: usize,
        linear_targets: &[u64],
        auxiliary_words: &[u64],
    ) -> Result<Self, TransactionCircuitError> {
        let mut statement = Self::new(
            row_count,
            packing_factor,
            constraint_degree,
            constraint_count,
            auxiliary_words.len(),
        )?;
        let witness_size = row_count.checked_mul(packing_factor).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "smallwood structural witness size overflow",
            ),
        )?;
        if linear_targets.len() != witness_size {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood structural identity target length {} does not match witness size {witness_size}",
                linear_targets.len()
            )));
        }
        statement.linear_targets.copy_from_slice(linear_targets);
        statement.auxiliary_words.copy_from_slice(auxiliary_words);
        Ok(statement)
    }
}

impl SmallwoodConstraintAdapter for StructuralIdentityWitnessStatement {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        self.arithmetization
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn packing_factor(&self) -> usize {
        self.packing_factor
    }

    fn constraint_degree(&self) -> usize {
        self.constraint_degree
    }

    fn linear_constraint_count(&self) -> usize {
        self.linear_targets.len()
    }

    fn constraint_count(&self) -> usize {
        self.constraint_count
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.linear_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &self.linear_indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &self.linear_coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        &self.linear_targets
    }

    fn auxiliary_witness_words(&self) -> &[u64] {
        &self.auxiliary_words
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(self.auxiliary_words.len())
    }

    fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
        SmallwoodLinearConstraintForm::IdentityWitness
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        rows: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows,
            auxiliary_words,
        }
    }

    fn compute_constraints_u64(
        &self,
        _view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        out.fill(0);
        Ok(())
    }
}

pub fn projected_smallwood_structural_proof_bytes_v1(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    auxiliary_words_len: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<usize, TransactionCircuitError> {
    let statement = StructuralIdentityWitnessStatement::new(
        row_count,
        packing_factor,
        constraint_degree,
        constraint_count,
        auxiliary_words_len,
    )?;
    projected_candidate_proof_bytes_with_profile(&statement, profile)
}

pub fn projected_smallwood_structural_proof_bytes_with_backend_v1(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    auxiliary_words_len: usize,
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<usize, TransactionCircuitError> {
    let statement = StructuralIdentityWitnessStatement::new(
        row_count,
        packing_factor,
        constraint_degree,
        constraint_count,
        auxiliary_words_len,
    )?;
    projected_candidate_proof_bytes_with_profile_and_backend(
        &statement,
        profile,
        transcript_backend,
    )
}

pub fn report_smallwood_structural_no_grinding_soundness_v1(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    public_value_count: usize,
    auxiliary_words_len: usize,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodNoGrindingSoundnessReportV1, TransactionCircuitError> {
    let statement = StructuralIdentityWitnessStatement::new(
        row_count,
        packing_factor,
        constraint_degree,
        constraint_count,
        auxiliary_words_len,
    )?;
    report_smallwood_no_grinding_soundness_v1(&statement, public_value_count, profile)
}

pub fn prove_smallwood_structural_identity_witness_v1(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    witness_values: &[u64],
    binded_data: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    prove_smallwood_structural_identity_witness_with_auxiliary_v1(
        row_count,
        packing_factor,
        constraint_degree,
        constraint_count,
        witness_values,
        &[],
        binded_data,
    )
}

pub fn prove_smallwood_structural_identity_witness_with_auxiliary_v1(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    witness_values: &[u64],
    auxiliary_words: &[u64],
    binded_data: &[u8],
) -> Result<Vec<u8>, TransactionCircuitError> {
    let statement = StructuralIdentityWitnessStatement::with_linear_targets(
        row_count,
        packing_factor,
        constraint_degree,
        constraint_count,
        witness_values,
        auxiliary_words,
    )?;
    prove_statement_with_transcript_backend(
        &statement,
        witness_values,
        binded_data,
        SmallwoodTranscriptBackend::Blake3,
    )
}

pub fn verify_smallwood_structural_identity_witness_v1(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    witness_values: &[u64],
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    verify_smallwood_structural_identity_witness_with_auxiliary_v1(
        row_count,
        packing_factor,
        constraint_degree,
        constraint_count,
        witness_values,
        &[],
        binded_data,
        proof_bytes,
    )
}

pub fn verify_smallwood_structural_identity_witness_with_auxiliary_v1(
    row_count: usize,
    packing_factor: usize,
    constraint_degree: usize,
    constraint_count: usize,
    witness_values: &[u64],
    auxiliary_words: &[u64],
    binded_data: &[u8],
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let statement = StructuralIdentityWitnessStatement::with_linear_targets(
        row_count,
        packing_factor,
        constraint_degree,
        constraint_count,
        witness_values,
        auxiliary_words,
    )?;
    verify_statement_with_transcript_backend(
        &statement,
        binded_data,
        proof_bytes,
        SmallwoodTranscriptBackend::Blake3,
    )
}

pub fn smallwood_binding_words_v1(binded_data: &[u8]) -> Result<Vec<u64>, TransactionCircuitError> {
    bytes_to_words(binded_data)
}

pub fn smallwood_poseidon2_eval_points_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    let eval_points = xof_piop_opening_points(
        &proof.nonce,
        &proof.h_piop,
        SmallwoodTranscriptBackend::Poseidon2,
    );
    ensure_no_packing_collisions(&cfg.packing_points, &eval_points)?;
    Ok(eval_points)
}

pub fn smallwood_poseidon2_opening_points_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
) -> Result<Vec<u64>, TransactionCircuitError> {
    smallwood_poseidon2_eval_points_v1(statement, proof_trace)
}

pub fn smallwood_poseidon2_coeffs_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    eval_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(&cfg, eval_points, &mut coeffs);
    Ok(coeffs)
}

pub fn smallwood_poseidon2_combi_heads_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
    eval_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof missing row-scalar opened witness data",
        ),
    )?;
    pcs_reconstruct_combi_heads(&cfg, eval_points, row_scalars, &proof.pcs.partial_evals)
}

pub fn smallwood_poseidon2_decs_trans_hash_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
    combi_heads: &[Vec<u64>],
) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    Ok(hash_challenge_opening_decs(
        &cfg,
        combi_heads,
        &proof.h_piop,
        &proof.pcs.rcombi_tails,
        SmallwoodTranscriptBackend::Poseidon2,
    ))
}

pub fn smallwood_poseidon2_decs_query_v1(
    decs_trans_hash: &[u8; DIGEST_BYTES],
) -> Result<(Vec<u32>, [u8; NONCE_BYTES], Vec<u64>), TransactionCircuitError> {
    let (decs_leaf_indexes, decs_nonce) = xof_decs_opening(
        SMALLWOOD_DECS_NB_EVALS,
        SMALLWOOD_DECS_NB_OPENED_EVALS,
        SMALLWOOD_DECS_POW_BITS,
        decs_trans_hash,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let decs_eval_points = decs_leaf_indexes
        .iter()
        .map(|&idx| idx as u64)
        .collect::<Vec<_>>();
    Ok((decs_leaf_indexes, decs_nonce, decs_eval_points))
}

pub fn smallwood_poseidon2_recompute_rows_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
    coeffs: &[Vec<u64>],
    combi_heads: &[Vec<u64>],
    decs_eval_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    lvcs_recompute_rows(
        &cfg,
        coeffs,
        combi_heads,
        &proof.pcs.rcombi_tails,
        &proof.pcs.subset_evals,
        decs_eval_points,
    )
}

pub fn smallwood_poseidon2_recompute_root_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
    rows: &[Vec<u64>],
    decs_leaf_indexes: &[u32],
) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    decs_recompute_root(
        &cfg,
        &proof.salt,
        rows,
        decs_leaf_indexes,
        &proof.pcs.decs,
        SmallwoodTranscriptBackend::Poseidon2,
    )
}

pub fn smallwood_poseidon2_decs_commitment_transcript_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
    rows: &[Vec<u64>],
    root_digest: &[u8; DIGEST_BYTES],
    decs_eval_points: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    decs_commitment_transcript(
        &cfg,
        &proof.salt,
        rows,
        root_digest,
        decs_eval_points,
        &proof.pcs.decs,
        SmallwoodTranscriptBackend::Poseidon2,
    )
}

pub fn smallwood_poseidon2_piop_input_words_v1(
    pcs_transcript_words: &[u64],
    binded_words: &[u64],
) -> Vec<u64> {
    let mut out = pcs_transcript_words.to_vec();
    out.extend_from_slice(binded_words);
    out
}

pub fn smallwood_poseidon2_piop_transcript_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
    piop_input_words: &[u64],
    eval_points: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof missing row-scalar opened witness data",
        ),
    )?;
    let auxiliary_words = proof.opened_witness.auxiliary_words_ref().unwrap_or(&[]);
    piop_recompute_transcript(
        &cfg,
        statement,
        piop_input_words,
        eval_points,
        row_scalars,
        auxiliary_words,
        &proof.piop,
        SmallwoodTranscriptBackend::Poseidon2,
    )
}

pub fn smallwood_poseidon2_gamma_prime_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    piop_input_words: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let hash_fpp = hash_piop(piop_input_words, SmallwoodTranscriptBackend::Poseidon2);
    Ok(derive_gamma_prime(
        &cfg,
        &hash_fpp,
        SmallwoodTranscriptBackend::Poseidon2,
    ))
}

pub fn smallwood_poseidon2_piop_accept_v1(
    proof_trace: &SmallwoodProofTraceV1,
    piop_transcript_words: &[u64],
) -> bool {
    hash_piop_transcript(piop_transcript_words, SmallwoodTranscriptBackend::Poseidon2)
        == proof_trace.h_piop
}

pub fn smallwood_poseidon2_pcs_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    proof_trace: &SmallwoodProofTraceV1,
    eval_points: &[u64],
) -> Result<SmallwoodPcsVerifierTraceV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof missing row-scalar opened witness data",
        ),
    )?;
    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(&cfg, eval_points, &mut coeffs);
    let combi_heads =
        pcs_reconstruct_combi_heads(&cfg, eval_points, row_scalars, &proof.pcs.partial_evals)?;
    let decs_trans_hash = hash_challenge_opening_decs(
        &cfg,
        &combi_heads,
        &proof.h_piop,
        &proof.pcs.rcombi_tails,
        SmallwoodTranscriptBackend::Poseidon2,
    );
    let (decs_leaf_indexes, decs_nonce) = xof_decs_opening(
        SMALLWOOD_DECS_NB_EVALS,
        SMALLWOOD_DECS_NB_OPENED_EVALS,
        SMALLWOOD_DECS_POW_BITS,
        &decs_trans_hash,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let decs_eval_points = decs_leaf_indexes
        .iter()
        .map(|&idx| idx as u64)
        .collect::<Vec<_>>();
    let rows = lvcs_recompute_rows(
        &cfg,
        &coeffs,
        &combi_heads,
        &proof.pcs.rcombi_tails,
        &proof.pcs.subset_evals,
        &decs_eval_points,
    )?;
    let root_digest = decs_recompute_root(
        &cfg,
        &proof.salt,
        &rows,
        &decs_leaf_indexes,
        &proof.pcs.decs,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let hash_mt = hash_merkle_root(
        &proof.salt,
        &root_digest,
        SmallwoodTranscriptBackend::Poseidon2,
    );
    let decs_gamma_all = derive_decs_challenge(
        cfg.nb_lvcs_rows,
        cfg.decs_eta(),
        cfg.decs_challenge_format,
        &hash_mt,
        SmallwoodTranscriptBackend::Poseidon2,
    );
    let decs_commitment_transcript = decs_commitment_transcript_with_challenge(
        &cfg,
        &rows,
        &decs_eval_points,
        &proof.pcs.decs,
        &hash_mt,
        &decs_gamma_all,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    Ok(SmallwoodPcsVerifierTraceV1 {
        coeffs,
        combi_heads,
        decs_trans_hash,
        decs_leaf_indexes,
        decs_nonce,
        decs_eval_points,
        rows,
        root_digest,
        decs_gamma_all,
        decs_commitment_transcript,
    })
}

pub fn smallwood_poseidon2_piop_trace_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    binded_words: &[u64],
    proof_trace: &SmallwoodProofTraceV1,
    eval_points: &[u64],
    pcs_trace: &SmallwoodPcsVerifierTraceV1,
) -> Result<SmallwoodPiopVerifierTraceV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    let proof = smallwood_proof_from_trace_v1(proof_trace);
    validate_proof_shape(&cfg, &proof)?;
    let row_scalars = proof.opened_witness.row_scalars_ref().ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood proof missing row-scalar opened witness data",
        ),
    )?;
    let auxiliary_words = proof.opened_witness.auxiliary_words_ref().unwrap_or(&[]);
    let pcs_transcript_words = pcs_trace.decs_commitment_transcript.clone();
    let mut piop_input_words = pcs_transcript_words.clone();
    piop_input_words.extend_from_slice(binded_words);
    let piop_transcript_words = piop_recompute_transcript(
        &cfg,
        statement,
        &piop_input_words,
        eval_points,
        row_scalars,
        auxiliary_words,
        &proof.piop,
        SmallwoodTranscriptBackend::Poseidon2,
    )?;
    let recomputed = hash_piop_transcript(
        &piop_transcript_words,
        SmallwoodTranscriptBackend::Poseidon2,
    );
    let hash_fpp = hash_piop(&piop_input_words, SmallwoodTranscriptBackend::Poseidon2);
    let piop_gamma_prime =
        derive_gamma_prime(&cfg, &hash_fpp, SmallwoodTranscriptBackend::Poseidon2);
    Ok(SmallwoodPiopVerifierTraceV1 {
        pcs_transcript_words,
        piop_input_words,
        piop_gamma_prime,
        piop_transcript_words,
        accept: recomputed == proof.h_piop,
    })
}

pub fn validate_proof_shape(
    cfg: &SmallwoodConfig,
    proof: &SmallwoodProof,
) -> Result<(), TransactionCircuitError> {
    let tape_profile = proof.wire_identity.opened_leaf_tape_profile();
    let hiding_tape_bytes = tape_profile.map(|profile| profile.1);
    if proof.strict_zk_decs_leaf_hiding != tape_profile.is_some()
        || tape_profile.is_some_and(|profile| cfg.decs_nb_opened_evals() != profile.0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict wire and configured DECS opening profile disagree",
        ));
    }
    validate_proof_shape_with_hiding_profile(cfg, proof, hiding_tape_bytes)
}

fn validate_proof_shape_with_hiding_profile(
    cfg: &SmallwoodConfig,
    proof: &SmallwoodProof,
    hiding_tape_bytes: Option<usize>,
) -> Result<(), TransactionCircuitError> {
    let is_fresh_hx512 = proof.wire_identity == SmallwoodProofWireIdentityV1::FreshHx512Candidate;
    if is_fresh_hx512
        != (proof.hx512_decs_root.is_some() && proof.hx512_piop_input_digest.is_some())
        || (!is_fresh_hx512
            && (proof.hx512_decs_root.is_some() || proof.hx512_piop_input_digest.is_some()))
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof prefix fields do not match the exact wire identity",
        ));
    }
    validate_pcs_opening_shape(cfg, &proof.pcs, &proof.opened_witness, hiding_tape_bytes)?;
    if proof.piop.ppol_highs.len() != cfg.rho()
        || proof
            .piop
            .ppol_highs
            .iter()
            .any(|poly| poly.len() != cfg.mpol_poly_degree + 1 - cfg.nb_opened_evals())
        || proof.piop.plin_highs.len() != cfg.rho()
        || proof
            .piop
            .plin_highs
            .iter()
            .any(|poly| poly.len() != cfg.mlin_poly_degree + 1 - (cfg.nb_opened_evals() + 1))
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood piop proof shape mismatch",
        ));
    }
    Ok(())
}

fn validate_pcs_opening_shape(
    cfg: &SmallwoodConfig,
    pcs: &PcsProof,
    opened_witness: &SmallwoodOpenedWitnessBundle,
    hiding_tape_bytes: Option<usize>,
) -> Result<(), TransactionCircuitError> {
    let row_scalars =
        opened_witness
            .row_scalars_ref()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood bridge proof opened witness mode mismatch",
            ))?;
    if row_scalars.len() != cfg.nb_opened_evals()
        || row_scalars.iter().any(|row| row.len() != cfg.nb_polys)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof opened evaluation shape mismatch",
        ));
    }
    let auxiliary_words = opened_witness.auxiliary_words_ref().unwrap_or(&[]);
    let auxiliary_limb_count = opened_witness.auxiliary_limb_count();
    if auxiliary_words.len() != cfg.auxiliary_witness_word_count
        || auxiliary_limb_count != cfg.auxiliary_witness_limb_count
    {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood proof auxiliary witness shape mismatch: words={} expected_words={} limbs={} expected_limbs={}",
            auxiliary_words.len(),
            cfg.auxiliary_witness_word_count,
            auxiliary_limb_count,
            cfg.auxiliary_witness_limb_count
        )));
    }
    if auxiliary_limb_count > auxiliary_words.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood auxiliary witness limb count exceeds opened witness words",
        ));
    }
    if auxiliary_words[auxiliary_limb_count..]
        .iter()
        .any(|&word| word != 0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood auxiliary witness padding must be zero",
        ));
    }
    if auxiliary_words.iter().any(|&word| word >= FIELD_ORDER) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof auxiliary witness contains a non-canonical Goldilocks element",
        ));
    }
    if pcs.rcombi_tails.len() != cfg.nb_lvcs_opened_combi
        || pcs
            .rcombi_tails
            .iter()
            .any(|tail| tail.len() != cfg.decs_nb_opened_evals())
        || pcs.subset_evals.len() != cfg.decs_nb_opened_evals()
        || pcs
            .subset_evals
            .iter()
            .any(|row| row.len() != cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi)
        || pcs.partial_evals.len() != cfg.nb_opened_evals()
        || pcs
            .partial_evals
            .iter()
            .any(|row| row.len() != cfg.nb_unstacked_cols - cfg.nb_polys)
        || pcs.decs.auth_paths.len() != cfg.decs_nb_opened_evals()
        || pcs
            .decs
            .auth_paths
            .iter()
            .any(|path| path.len() > cfg.decs_nb_evals().ilog2() as usize)
        || (hiding_tape_bytes.is_some() && pcs.decs.leaf_tapes.len() != cfg.decs_nb_opened_evals())
        || (hiding_tape_bytes.is_some()
            && pcs
                .decs
                .leaf_tapes
                .iter()
                .any(|tape| Some(tape.len()) != hiding_tape_bytes))
        || (hiding_tape_bytes.is_none() && !pcs.decs.leaf_tapes.is_empty())
        || pcs.decs.masking_evals.len() != cfg.decs_nb_opened_evals()
        || pcs
            .decs
            .masking_evals
            .iter()
            .any(|row| row.len() != cfg.decs_eta())
        || pcs.decs.high_coeffs.len() != cfg.decs_eta()
        || pcs
            .decs
            .high_coeffs
            .iter()
            .any(|poly| poly.len() != cfg.nb_lvcs_cols)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood PCS proof shape mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn projected_candidate_proof_bytes(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<usize, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new(statement)?;
    ensure_row_polynomial_arithmetization(statement)?;
    serialized_proof_size_hint_with_profile(
        &cfg,
        cfg.profile,
        statement
            .auxiliary_witness_limb_count()
            .unwrap_or(statement.auxiliary_witness_words().len()),
        SmallwoodTranscriptBackend::Blake3,
        SmallwoodDecsEvaluationDomain::Consecutive,
    )
}

pub(crate) fn projected_candidate_proof_bytes_with_profile(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<usize, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    ensure_row_polynomial_arithmetization(statement)?;
    serialized_proof_size_hint_with_profile(
        &cfg,
        profile,
        statement
            .auxiliary_witness_limb_count()
            .unwrap_or(statement.auxiliary_witness_words().len()),
        SmallwoodTranscriptBackend::Blake3,
        SmallwoodDecsEvaluationDomain::Consecutive,
    )
}

pub(crate) fn projected_candidate_proof_bytes_with_profile_and_backend(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<usize, TransactionCircuitError> {
    projected_candidate_proof_bytes_with_profile_backend_and_domain(
        statement,
        profile,
        transcript_backend,
        SmallwoodDecsEvaluationDomain::Consecutive,
    )
}

pub(crate) fn projected_candidate_proof_bytes_with_profile_backend_and_domain(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<usize, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    ensure_row_polynomial_arithmetization(statement)?;
    serialized_proof_size_hint_with_profile(
        &cfg,
        profile,
        statement
            .auxiliary_witness_limb_count()
            .unwrap_or(statement.auxiliary_witness_words().len()),
        transcript_backend,
        decs_evaluation_domain,
    )
}

pub(crate) fn ensure_canonical_smallwood_proof_bytes(
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let proof = decode_smallwood_proof_bytes_v1(proof_bytes)?;
    let roundtrip = encode_smallwood_proof_bytes_v1(&proof)?;
    if roundtrip != proof_bytes {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood proof bytes must use canonical serializer",
        ));
    }
    Ok(())
}

struct PiopRunOutput {
    transcript_words: Vec<u64>,
    proof: PiopProof,
}

fn validate_identity_witness_form(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_size: usize,
    linear_constraint_count: usize,
) -> Result<(), TransactionCircuitError> {
    if statement.linear_constraint_form() != SmallwoodLinearConstraintForm::IdentityWitness {
        return Ok(());
    }
    if linear_constraint_count != witness_size {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "identity witness linear constraints must cover the full witness: constraints={} witness_size={witness_size}",
            linear_constraint_count
        )));
    }
    if statement.linear_targets().len() != linear_constraint_count {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "identity witness linear target count mismatch: targets={} constraints={linear_constraint_count}",
            statement.linear_targets().len()
        )));
    }
    let offsets = statement.linear_constraint_offsets();
    let indices = statement.linear_constraint_indices();
    let coefficients = statement.linear_constraint_coefficients();
    if offsets.len() != linear_constraint_count + 1
        || indices.len() != linear_constraint_count
        || coefficients.len() != linear_constraint_count
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "identity witness linear metadata length mismatch",
        ));
    }
    for check in 0..linear_constraint_count {
        if offsets[check] as usize != check
            || offsets[check + 1] as usize != check + 1
            || indices[check] as usize != check
            || coefficients[check] != 1
        {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "identity witness linear metadata mismatch at constraint {check}"
            )));
        }
    }
    Ok(())
}

fn validate_auxiliary_witness_metadata(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_size: usize,
) -> Result<(usize, usize), TransactionCircuitError> {
    u32::try_from(witness_size).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood witness size does not fit the u32 linear-variable index space",
        )
    })?;
    let auxiliary_words = statement.auxiliary_witness_words();
    let total_variable_count = witness_size.checked_add(auxiliary_words.len()).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood total linear-variable count overflow",
        ),
    )?;
    u32::try_from(total_variable_count).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood total linear-variable count does not fit the u32 index space",
        )
    })?;
    let auxiliary_limb_count = statement
        .auxiliary_witness_limb_count()
        .unwrap_or(auxiliary_words.len());
    if auxiliary_limb_count > auxiliary_words.len() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood auxiliary witness limb count {auxiliary_limb_count} exceeds word count {}",
            auxiliary_words.len()
        )));
    }
    for (index, &word) in auxiliary_words.iter().enumerate() {
        if word >= FIELD_ORDER {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood auxiliary witness word {index} is not a canonical Goldilocks element"
            )));
        }
        if index >= auxiliary_limb_count && word != 0 {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood auxiliary witness padding word {index} must be zero"
            )));
        }
    }
    Ok((total_variable_count, auxiliary_limb_count))
}

fn validate_generic_linear_constraint_form(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    linear_constraint_count: usize,
    total_variable_count: usize,
) -> Result<(), TransactionCircuitError> {
    if statement.linear_constraint_form() != SmallwoodLinearConstraintForm::Generic {
        return Ok(());
    }

    u32::try_from(linear_constraint_count).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood generic linear-constraint count does not fit the u32 CSR index space",
        )
    })?;
    let expected_offset_count = linear_constraint_count.checked_add(1).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood generic linear-constraint offset count overflow",
        ),
    )?;
    let offsets = statement.linear_constraint_offsets();
    let indices = statement.linear_constraint_indices();
    let coefficients = statement.linear_constraint_coefficients();
    let targets = statement.linear_targets();
    if offsets.len() != expected_offset_count {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood generic CSR offset count mismatch: offsets={} expected={expected_offset_count}",
            offsets.len()
        )));
    }
    if indices.len() != coefficients.len() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood generic CSR term metadata length mismatch: indices={} coefficients={}",
            indices.len(),
            coefficients.len()
        )));
    }
    if targets.len() != linear_constraint_count {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood generic CSR target count mismatch: targets={} constraints={linear_constraint_count}",
            targets.len()
        )));
    }
    if offsets.first().copied() != Some(0) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood generic CSR offsets must start at zero",
        ));
    }
    for (constraint, pair) in offsets.windows(2).enumerate() {
        if pair[0] > pair[1] {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood generic CSR offsets must be strictly increasing: constraint={constraint} start={} end={}",
                pair[0], pair[1]
            )));
        }
        if pair[0] == pair[1]
            && !(statement.arithmetization()
                == SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1
                && targets[constraint] == 0)
        {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood generic CSR permits no empty constraint outside canonical zero-target SMZ1 padding: constraint={constraint} offset={}",
                pair[0]
            )));
        }
    }
    let term_count = u32::try_from(indices.len()).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood generic CSR term count does not fit the u32 offset space",
        )
    })?;
    if offsets.last().copied() != Some(term_count) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood generic CSR final offset mismatch: final={} terms={term_count}",
            offsets.last().copied().unwrap_or_default()
        )));
    }
    for (constraint, &target) in targets.iter().enumerate() {
        if target >= FIELD_ORDER {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood generic CSR target at constraint {constraint} is not a canonical Goldilocks element"
            )));
        }
        let start = offsets[constraint] as usize;
        let end = offsets[constraint + 1] as usize;
        let mut seen_indices = BTreeSet::new();
        for term in start..end {
            let coefficient = coefficients[term];
            if coefficient == 0 {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood generic CSR coefficient must be nonzero: constraint={constraint} term={term}"
                )));
            }
            if coefficient >= FIELD_ORDER {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood generic CSR coefficient is not a canonical Goldilocks element: constraint={constraint} term={term}"
                )));
            }
            let index = indices[term] as usize;
            if index >= total_variable_count {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood generic CSR variable index out of range: constraint={constraint} term={term} index={index} variables={total_variable_count}"
                )));
            }
            if !seen_indices.insert(indices[term]) {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood generic CSR contains a duplicate variable index: constraint={constraint} index={index}"
                )));
            }
        }
    }
    Ok(())
}

impl SmallwoodConfig {
    pub fn new(
        statement: &(dyn SmallwoodConstraintAdapter + Sync),
    ) -> Result<Self, TransactionCircuitError> {
        Self::new_with_profile(statement, ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1)
    }

    pub fn new_with_profile(
        statement: &(dyn SmallwoodConstraintAdapter + Sync),
        profile: SmallwoodNoGrindingProfileV1,
    ) -> Result<Self, TransactionCircuitError> {
        let row_count = statement.row_count();
        let packing_factor = statement.packing_factor();
        let constraint_degree = statement.constraint_degree();
        let linear_constraint_count = statement.linear_constraint_count();
        let constraint_count = statement.constraint_count();
        if row_count == 0 || packing_factor == 0 {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood row_count and packing_factor must be non-zero",
            ));
        }
        let witness_size = row_count.checked_mul(packing_factor).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "smallwood row_count times packing_factor overflows witness size",
            ),
        )?;
        let (total_variable_count, auxiliary_witness_limb_count) =
            validate_auxiliary_witness_metadata(statement, witness_size)?;
        validate_identity_witness_form(statement, witness_size, linear_constraint_count)?;
        validate_generic_linear_constraint_form(
            statement,
            linear_constraint_count,
            total_variable_count,
        )?;
        if profile.rho == 0
            || profile.nb_opened_evals == 0
            || profile.beta == 0
            || profile.decs_nb_evals == 0
            || !profile.decs_nb_evals.is_power_of_two()
            || profile.decs_nb_opened_evals == 0
            || profile.decs_eta == 0
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood profile parameters must be non-zero and use a power-of-two DECS domain",
            ));
        }
        let wit_poly_degree = packing_factor + profile.nb_opened_evals - 1;
        let mpol_poly_degree =
            constraint_degree * (packing_factor + profile.nb_opened_evals - 1) - packing_factor;
        let mlin_poly_degree =
            (packing_factor + profile.nb_opened_evals - 1) + (packing_factor - 1);
        let nb_polys = row_count + 2 * profile.rho;
        let mut degree = vec![wit_poly_degree; row_count];
        degree.extend(std::iter::repeat_n(mpol_poly_degree, profile.rho));
        degree.extend(std::iter::repeat_n(mlin_poly_degree, profile.rho));
        let mut width = Vec::with_capacity(nb_polys);
        let mut delta = Vec::with_capacity(nb_polys);
        let nb_unstacked_rows = packing_factor + profile.nb_opened_evals;
        let mut nb_unstacked_cols = 0usize;
        for &deg in &degree {
            let w = (deg + 1 - profile.nb_opened_evals).div_ceil(packing_factor);
            width.push(w);
            let d = (packing_factor * w + profile.nb_opened_evals) - (deg + 1);
            if w == 1 && d != 0 {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood invalid polynomial width/delta pair for degree {deg}"
                )));
            }
            delta.push(d);
            nb_unstacked_cols += w;
        }
        let nb_lvcs_rows = nb_unstacked_rows * profile.beta;
        let nb_lvcs_cols = nb_unstacked_cols.div_ceil(profile.beta);
        let nb_lvcs_opened_combi = profile.beta * profile.nb_opened_evals;
        let mut fullrank_cols = Vec::with_capacity(nb_lvcs_opened_combi);
        for i in 0..profile.beta {
            for j in 0..profile.nb_opened_evals {
                fullrank_cols.push(i * (packing_factor + profile.nb_opened_evals) + j);
            }
        }
        let packing_points = (0..packing_factor).map(|i| i as u64).collect();
        Ok(Self {
            profile,
            decs_challenge_format: decs_challenge_format_for_arithmetization(
                statement.arithmetization(),
            ),
            row_count,
            packing_factor,
            constraint_degree,
            linear_constraint_count,
            witness_size,
            total_variable_count,
            auxiliary_witness_word_count: statement.auxiliary_witness_words().len(),
            auxiliary_witness_limb_count,
            constraint_count,
            wit_poly_degree,
            mpol_poly_degree,
            mlin_poly_degree,
            nb_polys,
            degree,
            width,
            delta,
            nb_unstacked_rows,
            nb_unstacked_cols,
            nb_lvcs_rows,
            nb_lvcs_cols,
            nb_lvcs_opened_combi,
            fullrank_cols,
            packing_points,
        })
    }

    pub fn packing_points_v1(&self) -> &[u64] {
        &self.packing_points
    }

    pub fn nb_lvcs_rows_v1(&self) -> usize {
        self.nb_lvcs_rows
    }

    pub fn nb_lvcs_opened_combi_v1(&self) -> usize {
        self.nb_lvcs_opened_combi
    }

    #[inline]
    fn rho(&self) -> usize {
        self.profile.rho
    }

    #[inline]
    fn nb_opened_evals(&self) -> usize {
        self.profile.nb_opened_evals
    }

    #[inline]
    fn beta(&self) -> usize {
        self.profile.beta
    }

    #[inline]
    fn decs_nb_evals(&self) -> usize {
        self.profile.decs_nb_evals
    }

    #[inline]
    fn decs_nb_opened_evals(&self) -> usize {
        self.profile.decs_nb_opened_evals
    }

    #[inline]
    fn decs_eta(&self) -> usize {
        self.profile.decs_eta
    }

    #[inline]
    fn decs_pow_bits(&self) -> u32 {
        self.profile.decs_pow_bits
    }
}

/// Exact response dimensions derived by the generic LPPC/DECS engine. The
/// fresh HX512 header binds this complete shape; no parser-owned dimension is
/// allowed to select allocations or verifier arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SmallwoodCoreGeometryV1 {
    pub(crate) row_count: usize,
    pub(crate) packing_factor: usize,
    pub(crate) constraint_degree: usize,
    pub(crate) nonlinear_constraint_count: usize,
    pub(crate) linear_constraint_count: usize,
    pub(crate) witness_poly_degree: usize,
    pub(crate) mpol_poly_degree: usize,
    pub(crate) mlin_poly_degree: usize,
    pub(crate) nb_polys: usize,
    pub(crate) nb_unstacked_rows: usize,
    pub(crate) nb_unstacked_cols: usize,
    pub(crate) nb_lvcs_rows: usize,
    pub(crate) nb_lvcs_cols: usize,
    pub(crate) nb_lvcs_opened_combi: usize,
    pub(crate) interpolation_point_count: usize,
    pub(crate) coset_shift: u64,
    pub(crate) coset_generator: u64,
    pub(crate) ppol_high_rows: usize,
    pub(crate) ppol_high_cols: usize,
    pub(crate) plin_high_rows: usize,
    pub(crate) plin_high_cols: usize,
    pub(crate) rcombi_rows: usize,
    pub(crate) rcombi_cols: usize,
    pub(crate) subset_rows: usize,
    pub(crate) subset_cols: usize,
    pub(crate) partial_rows: usize,
    pub(crate) partial_cols: usize,
    pub(crate) masking_rows: usize,
    pub(crate) masking_cols: usize,
    pub(crate) high_rows: usize,
    pub(crate) high_cols: usize,
    pub(crate) opened_witness_rows: usize,
    pub(crate) opened_witness_cols: usize,
    pub(crate) auxiliary_word_count: usize,
}

pub(crate) fn derive_smallwood_core_geometry_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodCoreGeometryV1, TransactionCircuitError> {
    let cfg = SmallwoodConfig::new_with_profile(statement, profile)?;
    let interpolation_point_count = cfg
        .nb_lvcs_cols
        .checked_add(cfg.decs_nb_opened_evals())
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood core interpolation geometry overflow",
        ))?;
    let coset =
        SmallwoodDisjointCosetDescriptorV1::derive(cfg.decs_nb_evals(), interpolation_point_count)?;
    Ok(SmallwoodCoreGeometryV1 {
        row_count: cfg.row_count,
        packing_factor: cfg.packing_factor,
        constraint_degree: cfg.constraint_degree,
        nonlinear_constraint_count: cfg.constraint_count,
        linear_constraint_count: cfg.linear_constraint_count,
        witness_poly_degree: cfg.wit_poly_degree,
        mpol_poly_degree: cfg.mpol_poly_degree,
        mlin_poly_degree: cfg.mlin_poly_degree,
        nb_polys: cfg.nb_polys,
        nb_unstacked_rows: cfg.nb_unstacked_rows,
        nb_unstacked_cols: cfg.nb_unstacked_cols,
        nb_lvcs_rows: cfg.nb_lvcs_rows,
        nb_lvcs_cols: cfg.nb_lvcs_cols,
        nb_lvcs_opened_combi: cfg.nb_lvcs_opened_combi,
        interpolation_point_count,
        coset_shift: coset.shift,
        coset_generator: radix2_subgroup_generator(cfg.decs_nb_evals())?,
        ppol_high_rows: cfg.rho(),
        ppol_high_cols: cfg.mpol_poly_degree + 1 - cfg.nb_opened_evals(),
        plin_high_rows: cfg.rho(),
        plin_high_cols: cfg.mlin_poly_degree + 1 - (cfg.nb_opened_evals() + 1),
        rcombi_rows: cfg.nb_lvcs_opened_combi,
        rcombi_cols: cfg.decs_nb_opened_evals(),
        subset_rows: cfg.decs_nb_opened_evals(),
        subset_cols: cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi,
        partial_rows: cfg.nb_opened_evals(),
        partial_cols: cfg.nb_unstacked_cols - cfg.nb_polys,
        masking_rows: cfg.decs_nb_opened_evals(),
        masking_cols: cfg.decs_eta(),
        high_rows: cfg.decs_eta(),
        high_cols: cfg.nb_lvcs_cols,
        opened_witness_rows: cfg.nb_opened_evals(),
        opened_witness_cols: cfg.nb_polys,
        auxiliary_word_count: cfg.auxiliary_witness_word_count,
    })
}

/// Validate the exact prospective HX512 arithmetic profile and return only
/// engine-derived dimensions.  In particular, callers cannot substitute the
/// historical K=64 adapter or treat the radix-4 topology's base-row count as
/// the final relation row count.
pub(crate) fn preflight_smallwood_hx512_profile_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<SmallwoodCoreGeometryV1, TransactionCircuitError> {
    if statement.arithmetization() != SmallwoodArithmetization::DirectRadix4Packed1024Hx512Candidate
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 preflight requires the fresh radix-4/K1024 arithmetization selector",
        ));
    }
    if statement.packing_factor() != HX512_SMALLWOOD_PACKING_FACTOR_V1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 preflight requires exact K=1024 direct packing",
        ));
    }
    if statement.constraint_degree() != HX512_SMALLWOOD_MAX_CONSTRAINT_DEGREE_V1 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 preflight requires exact maximum constraint degree six",
        ));
    }
    if !statement.auxiliary_witness_words().is_empty()
        || statement.auxiliary_witness_limb_count().unwrap_or(0) != 0
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 preflight requires aux_count=0",
        ));
    }
    let geometry =
        derive_smallwood_core_geometry_v1(statement, HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1)?;
    if geometry.witness_poly_degree != HX512_SMALLWOOD_WITNESS_POLYNOMIAL_DEGREE_V1
        || geometry.mpol_poly_degree != HX512_SMALLWOOD_MPOL_POLYNOMIAL_DEGREE_V1
        || geometry.mlin_poly_degree != HX512_SMALLWOOD_LINEAR_POLYNOMIAL_DEGREE_V1
        || geometry.nb_unstacked_rows
            != HX512_SMALLWOOD_PACKING_FACTOR_V1
                + HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.nb_opened_evals
        || geometry.nb_lvcs_opened_combi
            != HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.beta
                * HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.nb_opened_evals
        || geometry.auxiliary_word_count != 0
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 derived engine geometry does not match the exact K1024/s6 profile",
        ));
    }
    Ok(geometry)
}

fn derive_smallwood_hx512_rng_schedule_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<
    (
        SmallwoodHx512RngBudgetV1,
        VecDeque<usize>,
        VecDeque<usize>,
        usize,
    ),
    TransactionCircuitError,
> {
    preflight_smallwood_hx512_profile_v1(statement)?;
    let cfg = SmallwoodConfig::new_with_profile(statement, HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1)?;
    let expected_witness_values = cfg.row_count.checked_mul(cfg.packing_factor).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "HX512 canonical witness length overflows addressable memory",
        ),
    )?;
    let mut field_requests = VecDeque::new();

    // One s-coefficient hiding polynomial for every packed witness row.
    field_requests.extend(std::iter::repeat_n(cfg.nb_opened_evals(), cfg.row_count));
    // MPOL and linear masking polynomials are generated in alternating order.
    for _ in 0..cfg.rho() {
        field_requests.push_back(cfg.mpol_poly_degree + 1);
        field_requests.push_back(cfg.mlin_poly_degree);
    }
    // Unstacking randomizers: one width-1 vector per opening and polynomial.
    for &width in &cfg.width {
        if width > 1 {
            field_requests.extend(std::iter::repeat_n(width - 1, cfg.nb_opened_evals()));
        }
    }
    // Random LVCS tail evaluations and eta DECS masking polynomials.
    field_requests.extend(std::iter::repeat_n(
        cfg.decs_nb_opened_evals(),
        cfg.nb_lvcs_rows,
    ));
    field_requests.extend(std::iter::repeat_n(
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals(),
        cfg.decs_eta(),
    ));

    let accepted_field_words = field_requests
        .iter()
        .try_fold(0usize, |total, request| total.checked_add(*request))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 field RNG schedule overflows its accepted-word count",
        ))?;
    let field_candidate_limit = accepted_field_words
        .checked_add(HX512_SMALLWOOD_FIELD_RNG_EXTRA_CANDIDATES_V1)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 field RNG schedule overflows its candidate limit",
        ))?;
    let accepted_field_bytes =
        accepted_field_words
            .checked_mul(8)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "HX512 accepted field RNG byte count overflows",
            ))?;
    let maximum_field_candidate_bytes = field_candidate_limit.checked_mul(8).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "HX512 maximum field RNG byte count overflows",
        ),
    )?;
    let field_request_count = field_requests.len();
    let maximum_field_rng_calls = field_request_count
        .checked_add(HX512_SMALLWOOD_FIELD_RNG_EXTRA_CANDIDATES_V1)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 field RNG call bound overflows",
        ))?;

    let tape_count = cfg.decs_nb_evals();
    let tape_bytes_total = tape_count
        .checked_mul(HX512_PROFILE_LEAF_TAPE_BYTES)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 leaf-tape RNG byte count overflows",
        ))?;
    let mut tape_batches = VecDeque::new();
    let mut remaining_tapes = tape_count;
    while remaining_tapes != 0 {
        let batch = remaining_tapes.min(HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1);
        tape_batches.push_back(batch.checked_mul(HX512_PROFILE_LEAF_TAPE_BYTES).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "HX512 leaf-tape RNG batch byte count overflows",
            ),
        )?);
        remaining_tapes -= batch;
    }
    let tape_rng_calls = tape_batches.len();
    let minimum_total_getrandom_fill_calls = 1usize
        .checked_add(field_request_count)
        .and_then(|calls| calls.checked_add(tape_rng_calls))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 minimum total getrandom-fill call count overflows",
        ))?;
    let maximum_total_getrandom_fill_calls = 1usize
        .checked_add(maximum_field_rng_calls)
        .and_then(|calls| calls.checked_add(tape_rng_calls))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 total getrandom-fill call bound overflows",
        ))?;
    let minimum_total_getrandom_fill_bytes = HX512_SALT_BYTES
        .checked_add(tape_bytes_total)
        .and_then(|bytes| bytes.checked_add(accepted_field_bytes))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 minimum total getrandom-fill byte count overflows",
        ))?;
    let maximum_total_getrandom_fill_bytes = HX512_SALT_BYTES
        .checked_add(tape_bytes_total)
        .and_then(|bytes| bytes.checked_add(maximum_field_candidate_bytes))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "HX512 maximum total getrandom-fill byte count overflows",
        ))?;
    let budget = SmallwoodHx512RngBudgetV1 {
        accepted_field_words,
        accepted_field_bytes,
        field_candidate_limit,
        maximum_field_candidate_bytes,
        field_rejection_budget: HX512_SMALLWOOD_FIELD_RNG_EXTRA_CANDIDATES_V1,
        field_request_count,
        minimum_field_rng_calls: field_request_count,
        maximum_field_rng_calls,
        decs_leaf_tape_count: tape_count,
        decs_leaf_tape_bytes_each: HX512_PROFILE_LEAF_TAPE_BYTES,
        decs_leaf_tape_bytes_total: tape_bytes_total,
        decs_leaf_tape_rng_calls: tape_rng_calls,
        global_salt_bytes: HX512_SALT_BYTES,
        global_salt_rng_calls: 1,
        minimum_total_getrandom_fill_calls,
        maximum_total_getrandom_fill_calls,
        minimum_total_getrandom_fill_bytes,
        maximum_total_getrandom_fill_bytes,
        internal_outer_retry_count: 0,
        salt_collision_entropy_bits: (8 * HX512_SALT_BYTES) as u16,
        salt_reuse_registry_authority: false,
        getrandom_fill_failure_is_fatal: true,
    };
    Ok((
        budget,
        field_requests,
        tape_batches,
        expected_witness_values,
    ))
}

pub(crate) fn smallwood_hx512_rng_budget_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<SmallwoodHx512RngBudgetV1, TransactionCircuitError> {
    derive_smallwood_hx512_rng_schedule_v1(statement).map(|schedule| schedule.0)
}

fn ensure_smallwood_hx512_core_contract_v1(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    profile: SmallwoodNoGrindingProfileV1,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
    salt_len: usize,
    tape_bytes: usize,
    wire_identity: SmallwoodProofWireIdentityV1,
) -> Result<(), TransactionCircuitError> {
    preflight_smallwood_hx512_profile_v1(statement)?;
    if profile != HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1
        || decs_evaluation_domain != SmallwoodDecsEvaluationDomain::Radix2DisjointCoset
        || salt_len != HX512_SALT_BYTES
        || tape_bytes != HX512_PROFILE_LEAF_TAPE_BYTES
        || wire_identity != SmallwoodProofWireIdentityV1::FreshHx512Candidate
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 core requires the exact s6/q48/K1024/disjoint-coset/salt64/tape72 fresh-wire profile",
        ));
    }
    Ok(())
}

fn piop_run(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_polys: &[Vec<u64>],
    mpol_ppoly: &[Vec<u64>],
    mpol_plin: &[Vec<u64>],
    binded_words: &[u64],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<PiopRunOutput, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/piop] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let hash_fpp = hash_piop(binded_words, transcript_backend);
    let gammas = derive_gamma_prime(cfg, &hash_fpp, transcript_backend);
    log_stage("derive_gamma_prime", &mut last);
    let in_ppol = get_constraint_polynomials(cfg, statement, witness_polys)?;
    log_stage("constraint_polynomials", &mut last);
    let lagrange_basis = cached_lagrange_basis(cfg.packing_factor, &cfg.packing_points)?;
    let in_plin = get_constraint_linear_polynomials_batched(
        cfg,
        statement,
        witness_polys,
        lagrange_basis.as_ref(),
        &gammas,
    )?;
    log_stage("constraint_linear_polynomials", &mut last);
    let mut transcript_words = Vec::new();
    transcript_words.extend(digest_to_words(&hash_fpp, transcript_backend));
    let mut ppol_highs = Vec::with_capacity(cfg.rho());
    let mut plin_highs = Vec::with_capacity(cfg.rho());
    for rep in 0..cfg.rho() {
        let mut out_ppol = vec![0u64; cfg.mpol_poly_degree + cfg.packing_factor + 1];
        for (poly, gamma) in in_ppol.iter().zip(gammas[rep].iter()) {
            poly_add_assign_scaled(&mut out_ppol, poly, *gamma);
        }
        for root in &cfg.packing_points {
            out_ppol = poly_remove_one_degree_factor(&out_ppol, *root);
        }
        poly_add_assign(&mut out_ppol, &mpol_ppoly[rep]);

        let mut out_plin = in_plin[rep].clone();
        poly_add_assign(&mut out_plin, &mpol_plin[rep]);

        transcript_words.extend_from_slice(&out_ppol);
        transcript_words.extend_from_slice(&out_plin[1..]);
        ppol_highs.push(out_ppol[cfg.nb_opened_evals()..].to_vec());
        plin_highs.push(out_plin[(cfg.nb_opened_evals() + 1)..].to_vec());
    }
    log_stage("transcript_assembly", &mut last);
    Ok(PiopRunOutput {
        transcript_words,
        proof: PiopProof {
            ppol_highs,
            plin_highs,
        },
    })
}

pub fn piop_recompute_transcript(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    in_transcript: &[u64],
    eval_points: &[u64],
    row_scalars: &[Vec<u64>],
    auxiliary_words: &[u64],
    proof: &PiopProof,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let hash_fpp = hash_piop(in_transcript, transcript_backend);
    let gammas = derive_gamma_prime(cfg, &hash_fpp, transcript_backend);
    let wit_evals = row_scalars
        .iter()
        .map(|row| row[..cfg.row_count].to_vec())
        .collect::<Vec<_>>();
    let meval_ppoly = row_scalars
        .iter()
        .map(|row| row[cfg.row_count..cfg.row_count + cfg.rho()].to_vec())
        .collect::<Vec<_>>();
    let meval_plin = row_scalars
        .iter()
        .map(|row| row[cfg.row_count + cfg.rho()..cfg.row_count + 2 * cfg.rho()].to_vec())
        .collect::<Vec<_>>();
    let in_epol =
        get_constraint_polynomial_evals(cfg, statement, eval_points, &wit_evals, auxiliary_words)?;
    let lagrange_basis = cached_lagrange_basis(cfg.packing_factor, &cfg.packing_points)?;
    let in_elin = get_constraint_linear_evals(
        cfg,
        statement,
        eval_points,
        &wit_evals,
        lagrange_basis.as_ref(),
    )?;
    let linear_targets = effective_linear_targets(cfg, statement, auxiliary_words)?;
    let mut transcript_words = Vec::new();
    transcript_words.extend(digest_to_words(&hash_fpp, transcript_backend));
    let eval_points_with_zero = {
        let mut v = eval_points.to_vec();
        v.push(0);
        v
    };
    let lag = poly_set_lagrange(&eval_points_with_zero, cfg.nb_opened_evals());
    let correction_factor = smallwood_piop_linear_correction_factor(
        &cfg.packing_points,
        eval_points,
    )
    .filter(|factor| *factor != 0)
    .ok_or(TransactionCircuitError::ConstraintViolation(
        "smallwood linear target correction factor is zero or the opening points are inadmissible",
    ))?;
    debug_assert_eq!(
        correction_factor,
        cfg.packing_points
            .iter()
            .fold(0u64, |sum, point| add_mod(sum, poly_eval(&lag, *point)))
    );
    for rep in 0..cfg.rho() {
        let mut out_epol = vec![0u64; cfg.nb_opened_evals()];
        for j in 0..cfg.nb_opened_evals() {
            let mut acc = 0u64;
            for num in 0..cfg.constraint_count {
                acc = add_mod(acc, mul_mod(in_epol[j][num], gammas[rep][num]));
            }
            let mut denom = 1u64;
            for root in &cfg.packing_points {
                denom = mul_mod(denom, sub_mod(eval_points[j], *root));
            }
            acc = div_mod(acc, denom);
            out_epol[j] = add_mod(acc, meval_ppoly[j][rep]);
        }
        let out_ppol = poly_restore(
            &proof.ppol_highs[rep],
            &out_epol,
            eval_points,
            cfg.mpol_poly_degree,
        )?;

        let mut out_elin = vec![0u64; cfg.nb_opened_evals() + 1];
        for j in 0..cfg.nb_opened_evals() {
            let mut acc = 0u64;
            for num in 0..cfg.linear_constraint_count {
                acc = add_mod(acc, mul_mod(in_elin[j][num], gammas[rep][num]));
            }
            out_elin[j] = add_mod(acc, meval_plin[j][rep]);
        }
        let mut out_plin = if cfg.mlin_poly_degree > cfg.nb_opened_evals() {
            poly_restore(
                &proof.plin_highs[rep],
                &out_elin,
                &eval_points_with_zero,
                cfg.mlin_poly_degree,
            )?
        } else {
            poly_interpolate_generic(&out_elin, &eval_points_with_zero)
        };
        let mut res = 0u64;
        for num in 0..cfg.linear_constraint_count {
            res = add_mod(res, mul_mod(linear_targets[num], gammas[rep][num]));
        }
        for root in &cfg.packing_points {
            res = sub_mod(res, poly_eval(&out_plin, *root));
        }
        res = div_mod(res, correction_factor);
        let scaled_lag = poly_mul_scalar(&lag, res);
        poly_add_assign(&mut out_plin, &scaled_lag);
        transcript_words.extend_from_slice(&out_ppol);
        transcript_words.extend_from_slice(&out_plin[1..]);
    }
    Ok(transcript_words)
}

fn pcs_commit(
    cfg: &SmallwoodConfig,
    witness_polys: &[Vec<u64>],
    mpol_ppoly: &[Vec<u64>],
    mpol_plin: &[Vec<u64>],
    salt: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
    statement_binding: &[u64],
    decs_leaf_tape_bytes: usize,
) -> Result<(PcsKey, Vec<u64>), TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/pcs_commit] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let mut polys = witness_polys.to_vec();
    polys.extend_from_slice(mpol_ppoly);
    polys.extend_from_slice(mpol_plin);

    let mut rows = vec![vec![0u64; cfg.nb_unstacked_cols]; cfg.nb_unstacked_rows];
    let mut offset = 0usize;
    for (j, poly) in polys.iter().enumerate() {
        let width = cfg.width[j];
        let degree = cfg.degree[j];
        let delta = cfg.delta[j];
        let mut ind = 0usize;
        for i in 0..(width - 1) {
            for row in rows.iter_mut().take(cfg.packing_factor) {
                row[offset + i] = poly[ind];
                ind += 1;
            }
        }
        for row in rows.iter_mut().take(cfg.nb_unstacked_rows).skip(delta) {
            row[offset + (width - 1)] = poly[ind];
            ind += 1;
        }
        if width > 1 {
            for open_idx in 0..cfg.nb_opened_evals() {
                let rnd = random_vec(width - 1)?;
                let target_row = cfg.packing_factor + open_idx;
                rows[target_row][offset..offset + width - 1].copy_from_slice(&rnd);
                for i in 0..(width - 2) {
                    rows[open_idx][offset + 1 + i] =
                        sub_mod(rows[open_idx][offset + 1 + i], rnd[i]);
                }
                let last_row = delta + open_idx;
                rows[last_row][offset + (width - 1)] =
                    sub_mod(rows[last_row][offset + (width - 1)], rnd[width - 2]);
            }
            for row in rows.iter_mut().take(delta) {
                row[offset + (width - 1)] = 0;
            }
        }
        let _ = degree;
        offset += width;
    }
    log_stage("unstack_rows", &mut last);

    let mut stacked_rows = vec![vec![0u64; cfg.nb_lvcs_cols]; cfg.nb_lvcs_rows];
    for (i, row) in stacked_rows.iter_mut().enumerate() {
        let num_unstacked_row = i % cfg.nb_unstacked_rows;
        let num_unstacked_offset = (i / cfg.nb_unstacked_rows) * cfg.nb_lvcs_cols;
        if num_unstacked_offset < cfg.nb_unstacked_cols {
            let copy = min(
                cfg.nb_lvcs_cols,
                cfg.nb_unstacked_cols - num_unstacked_offset,
            );
            row[..copy].copy_from_slice(
                &rows[num_unstacked_row][num_unstacked_offset..num_unstacked_offset + copy],
            );
        }
    }
    log_stage("stack_rows", &mut last);
    let lvcs_key = lvcs_commit(
        cfg,
        &stacked_rows,
        salt,
        transcript_backend,
        decs_evaluation_domain,
        statement_binding,
        decs_leaf_tape_bytes,
    )?;
    log_stage("lvcs_commit", &mut last);
    let pcs_key = PcsKey { lvcs_key };
    let transcript_words = pcs_commit_transcript_words(
        salt,
        &pcs_key.lvcs_key.decs_key,
        transcript_backend,
        statement_binding,
    );
    log_stage("pcs_transcript", &mut last);
    Ok((pcs_key, transcript_words))
}

fn pcs_open(
    cfg: &SmallwoodConfig,
    key: &PcsKey,
    _witness_polys: &[Vec<u64>],
    _mpol_ppoly: &[Vec<u64>],
    _mpol_plin: &[Vec<u64>],
    eval_points: &[u64],
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(PcsProof, SmallwoodOpenedWitnessBundle), TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/pcs_open] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(cfg, eval_points, &mut coeffs);
    log_stage("build_coefficients", &mut last);
    let (combi_heads, rcombi_tails, subset_evals, decs_proof) = lvcs_open(
        cfg,
        &key.lvcs_key,
        &coeffs,
        h_piop,
        transcript_backend,
        decs_evaluation_domain,
    )?;
    log_stage("lvcs_open", &mut last);
    let (opened_witness, partial_evals) =
        pcs_build_opened_evaluations(cfg, eval_points, &combi_heads)?;
    log_stage("opened_evals", &mut last);

    Ok((
        PcsProof {
            rcombi_tails,
            subset_evals,
            partial_evals,
            decs: decs_proof,
        },
        opened_witness,
    ))
}

fn pcs_recompute_transcript(
    cfg: &SmallwoodConfig,
    salt: &[u8],
    eval_points: &[u64],
    row_scalars: &[Vec<u64>],
    proof: &PcsProof,
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
    statement_binding: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
    pcs_build_coefficients(cfg, eval_points, &mut coeffs);
    let combi_heads =
        pcs_reconstruct_combi_heads(cfg, eval_points, row_scalars, &proof.partial_evals)?;
    let decs_trans_hash = hash_challenge_opening_decs(
        cfg,
        &combi_heads,
        h_piop,
        &proof.rcombi_tails,
        transcript_backend,
    );
    let (decs_leaf_indexes, _decs_nonce) = xof_decs_opening(
        cfg.decs_nb_evals(),
        cfg.decs_nb_opened_evals(),
        cfg.decs_pow_bits(),
        &decs_trans_hash,
        transcript_backend,
    )?;
    let decs_eval_points = decs_field_evaluation_points(
        decs_evaluation_domain,
        cfg.decs_nb_evals(),
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals(),
        &decs_leaf_indexes,
    )?;
    let rows = lvcs_recompute_rows(
        cfg,
        &coeffs,
        &combi_heads,
        &proof.rcombi_tails,
        &proof.subset_evals,
        &decs_eval_points,
    )?;
    let root_words = decs_recompute_root(
        cfg,
        salt,
        &rows,
        &decs_leaf_indexes,
        &proof.decs,
        transcript_backend,
    )?;
    decs_commitment_transcript_with_binding(
        cfg,
        salt,
        &rows,
        &root_words,
        &decs_eval_points,
        &proof.decs,
        transcript_backend,
        statement_binding,
    )
}

fn pcs_commit_transcript_words(
    salt: &[u8],
    decs_key: &DecsKey,
    transcript_backend: SmallwoodTranscriptBackend,
    statement_binding: &[u64],
) -> Vec<u64> {
    let root = decs_key
        .tree_levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .unwrap_or([0u8; DIGEST_BYTES]);
    let hash_mt = if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        with_smallwood_hx512_transcript_driver(|driver| match driver.cached_decs_root_digest() {
            Ok(digest) => digest,
            Err(error) => driver.record_failure(error, [0u8; DIGEST_BYTES]),
        })
        .unwrap_or([0u8; DIGEST_BYTES])
    } else {
        hash_merkle_root_with_binding(salt, &root, transcript_backend, statement_binding)
    };
    let mut transcript = digest_to_words(&hash_mt, transcript_backend);
    for poly in &decs_key.dec_polys {
        transcript.extend_from_slice(poly);
    }
    transcript
}

fn pcs_build_opened_evaluations(
    cfg: &SmallwoodConfig,
    eval_points: &[u64],
    combi_heads: &[Vec<u64>],
) -> Result<(SmallwoodOpenedWitnessBundle, Vec<Vec<u64>>), TransactionCircuitError> {
    let mut row_scalars = vec![vec![0u64; cfg.nb_polys]; eval_points.len()];
    let mut partial_evals =
        vec![vec![0u64; cfg.nb_unstacked_cols - cfg.nb_polys]; eval_points.len()];
    for (j, &eval_point) in eval_points.iter().enumerate() {
        let mut r_to_mu = eval_point;
        for _ in 1..cfg.packing_factor {
            r_to_mu = mul_mod(r_to_mu, eval_point);
        }
        let mut num_col = 0usize;
        let mut num_combi = cfg.beta() * j;
        let mut ind = 0usize;
        for (k, row_scalar) in row_scalars[j].iter_mut().enumerate().take(cfg.nb_polys) {
            let mut acc = 0u64;
            let mut pow = 1u64;
            for i in 0..cfg.width[k] {
                let value = combi_heads[num_combi][num_col];
                if i > 0 {
                    partial_evals[j][ind] = value;
                    ind += 1;
                }
                acc = add_mod(acc, mul_mod(value, pow));
                if cfg.width[k] > 1 {
                    if i < cfg.width[k] - 2 {
                        pow = mul_mod(pow, r_to_mu);
                    } else if i == cfg.width[k] - 2 {
                        for _ in 0..(cfg.packing_factor - cfg.delta[k]) {
                            pow = mul_mod(pow, eval_point);
                        }
                    }
                }
                num_col += 1;
                if num_col >= cfg.nb_lvcs_cols {
                    num_col = 0;
                    num_combi += 1;
                }
            }
            *row_scalar = acc;
        }
    }
    Ok((
        SmallwoodOpenedWitnessBundle::row_scalars(row_scalars, Vec::new(), 0),
        partial_evals,
    ))
}

pub fn pcs_reconstruct_combi_heads(
    cfg: &SmallwoodConfig,
    eval_points: &[u64],
    row_scalars: &[Vec<u64>],
    partial_evals: &[Vec<u64>],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut combi_heads = vec![vec![0u64; cfg.nb_lvcs_cols]; cfg.nb_lvcs_opened_combi];
    for (j, &eval_point) in eval_points.iter().enumerate() {
        let mut r_to_mu = eval_point;
        for _ in 1..cfg.packing_factor {
            r_to_mu = mul_mod(r_to_mu, eval_point);
        }
        let mut unstacked_vec = vec![0u64; cfg.nb_unstacked_cols];
        let mut poly_ind = 0usize;
        let mut partial_ind = 0usize;
        for (k, row_scalar) in row_scalars[j].iter().enumerate().take(cfg.nb_polys) {
            let mut sum = 0u64;
            let mut pow = 1u64;
            for i in 1..cfg.width[k] {
                let value = partial_evals[j][partial_ind];
                partial_ind += 1;
                unstacked_vec[poly_ind + i] = value;
                if i < cfg.width[k] - 1 {
                    pow = mul_mod(pow, r_to_mu);
                } else {
                    for _ in 0..(cfg.packing_factor - cfg.delta[k]) {
                        pow = mul_mod(pow, eval_point);
                    }
                }
                sum = add_mod(sum, mul_mod(value, pow));
            }
            unstacked_vec[poly_ind] = sub_mod(*row_scalar, sum);
            poly_ind += cfg.width[k];
        }
        debug_assert_eq!(partial_ind, cfg.nb_unstacked_cols - cfg.nb_polys);
        for i in 0..cfg.beta() {
            let num_combi = j * cfg.beta() + i;
            let offset = i * cfg.nb_lvcs_cols;
            combi_heads[num_combi].fill(0);
            if offset < cfg.nb_unstacked_cols {
                let copy = min(cfg.nb_lvcs_cols, cfg.nb_unstacked_cols - offset);
                combi_heads[num_combi][..copy]
                    .copy_from_slice(&unstacked_vec[offset..offset + copy]);
            }
        }
    }
    Ok(combi_heads)
}

fn get_constraint_polynomials(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_polys: &[Vec<u64>],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let degree = cfg.constraint_degree * cfg.wit_poly_degree;
    let nb_samples = degree + 1;
    let sample_points = (0..nb_samples).map(|i| i as u64).collect::<Vec<_>>();
    let wit_evals = sample_points
        .par_iter()
        .map(|&point| {
            witness_polys
                .iter()
                .map(|poly| poly_eval(poly, point))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let auxiliary_words = statement.auxiliary_witness_words();
    let evaluated_constraints = wit_evals
        .par_iter()
        .zip(sample_points.par_iter().copied())
        .map(|(row, sample_point)| {
            let mut row_constraints = vec![0u64; cfg.constraint_count];
            let view = statement.nonlinear_eval_view(sample_point, row, auxiliary_words);
            statement.compute_constraints_u64(view, &mut row_constraints)?;
            Ok::<_, TransactionCircuitError>(row_constraints)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut constraint_evals = vec![vec![0u64; nb_samples]; cfg.constraint_count];
    for (sample_idx, row_constraints) in evaluated_constraints.iter().enumerate() {
        for idx in 0..cfg.constraint_count {
            constraint_evals[idx][sample_idx] = row_constraints[idx];
        }
    }
    constraint_evals
        .par_iter()
        .map(|evals| interpolate_consecutive(evals))
        .collect::<Result<Vec<_>, _>>()
}

fn get_constraint_polynomial_evals(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    eval_points: &[u64],
    witness_evals: &[Vec<u64>],
    auxiliary_words: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut out = vec![vec![0u64; cfg.constraint_count]; eval_points.len()];
    for (row_idx, rows) in witness_evals.iter().enumerate() {
        let view = statement.nonlinear_eval_view(eval_points[row_idx], rows, auxiliary_words);
        statement.compute_constraints_u64(view, &mut out[row_idx])?;
    }
    Ok(out)
}

fn get_constraint_linear_polynomials_batched(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    witness_polys: &[Vec<u64>],
    lag: &[Vec<u64>],
    gammas: &[Vec<u64>],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let out_degree = cfg.wit_poly_degree + (cfg.packing_factor - 1);
    if statement.linear_constraint_form() == SmallwoodLinearConstraintForm::IdentityWitness {
        return (0..cfg.rho())
            .into_par_iter()
            .map(|rep| {
                let mut tmp_out = vec![0u64; out_degree + 1];
                let mut tmp = vec![0u64; out_degree + 1];
                let mut lag_combo = vec![0u64; cfg.packing_factor];
                for row in 0..cfg.row_count {
                    let weights =
                        &gammas[rep][row * cfg.packing_factor..(row + 1) * cfg.packing_factor];
                    if weights.iter().all(|weight| *weight == 0) {
                        continue;
                    }
                    lag_combo.fill(0);
                    for col in 0..cfg.packing_factor {
                        let weight = weights[col];
                        if weight != 0 {
                            poly_add_assign_scaled(&mut lag_combo, &lag[col], weight);
                        }
                    }
                    poly_mul_into(
                        &mut tmp,
                        &witness_polys[row],
                        &lag_combo,
                        cfg.wit_poly_degree,
                        cfg.packing_factor - 1,
                    );
                    poly_add_assign(&mut tmp_out, &tmp);
                }
                Ok::<_, TransactionCircuitError>(tmp_out)
            })
            .collect::<Result<Vec<_>, _>>();
    }
    (0..cfg.rho())
        .into_par_iter()
        .map(|rep| {
            let mut aggregated = vec![0u64; cfg.witness_size];
            for (check, &gamma) in gammas[rep]
                .iter()
                .enumerate()
                .take(cfg.linear_constraint_count)
            {
                if gamma == 0 {
                    continue;
                }
                let start = statement.linear_constraint_offsets()[check] as usize;
                let end = statement.linear_constraint_offsets()[check + 1] as usize;
                for term_idx in start..end {
                    let coeff = statement.linear_constraint_coefficients()[term_idx];
                    let idx = statement.linear_constraint_indices()[term_idx] as usize;
                    if coeff == 0 || coeff >= FIELD_ORDER || idx >= cfg.total_variable_count {
                        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                            "smallwood generic CSR metadata changed after config validation: constraint={check} term={term_idx}"
                        )));
                    }
                    if idx >= cfg.witness_size {
                        continue;
                    }
                    aggregated[idx] = add_mod(aggregated[idx], mul_mod(coeff, gamma));
                }
            }
            let mut tmp_out = vec![0u64; out_degree + 1];
            let mut tmp = vec![0u64; out_degree + 1];
            let mut lag_combo = vec![0u64; cfg.packing_factor];
            for row in 0..cfg.row_count {
                let weights = &aggregated[row * cfg.packing_factor..(row + 1) * cfg.packing_factor];
                if weights.iter().all(|weight| *weight == 0) {
                    continue;
                }
                lag_combo.fill(0);
                for col in 0..cfg.packing_factor {
                    let weight = weights[col];
                    if weight != 0 {
                        poly_add_assign_scaled(&mut lag_combo, &lag[col], weight);
                    }
                }
                poly_mul_into(
                    &mut tmp,
                    &witness_polys[row],
                    &lag_combo,
                    cfg.wit_poly_degree,
                    cfg.packing_factor - 1,
                );
                poly_add_assign(&mut tmp_out, &tmp);
            }
            Ok::<_, TransactionCircuitError>(tmp_out)
        })
        .collect::<Result<Vec<_>, _>>()
}

fn get_constraint_linear_evals(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    eval_points: &[u64],
    witness_evals: &[Vec<u64>],
    lag: &[Vec<u64>],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut lag_evals = vec![vec![0u64; cfg.packing_factor]; eval_points.len()];
    for (num, &eval_point) in eval_points.iter().enumerate() {
        for col in 0..cfg.packing_factor {
            lag_evals[num][col] = poly_eval(&lag[col], eval_point);
        }
    }
    if statement.linear_constraint_form() == SmallwoodLinearConstraintForm::IdentityWitness {
        let mut out = vec![vec![0u64; cfg.linear_constraint_count]; eval_points.len()];
        for num in 0..eval_points.len() {
            let mut out_idx = 0usize;
            for &witness in witness_evals[num].iter().take(cfg.row_count) {
                for &lag_eval in lag_evals[num].iter().take(cfg.packing_factor) {
                    out[num][out_idx] = mul_mod(witness, lag_eval);
                    out_idx += 1;
                }
            }
        }
        return Ok(out);
    }
    let mut out = vec![vec![0u64; cfg.linear_constraint_count]; eval_points.len()];
    for num in 0..eval_points.len() {
        for (check, out_eval) in out[num]
            .iter_mut()
            .enumerate()
            .take(cfg.linear_constraint_count)
        {
            let start = statement.linear_constraint_offsets()[check] as usize;
            let end = statement.linear_constraint_offsets()[check + 1] as usize;
            let mut acc = 0u64;
            for term_idx in start..end {
                let coeff = statement.linear_constraint_coefficients()[term_idx];
                let idx = statement.linear_constraint_indices()[term_idx] as usize;
                if coeff == 0 || coeff >= FIELD_ORDER || idx >= cfg.total_variable_count {
                    return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                        "smallwood generic CSR metadata changed after config validation: constraint={check} term={term_idx}"
                    )));
                }
                if idx >= cfg.witness_size {
                    continue;
                }
                let row = idx / cfg.packing_factor;
                let col = idx % cfg.packing_factor;
                if row >= cfg.row_count {
                    return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                        "smallwood generic CSR witness row out of range after config validation: constraint={check} term={term_idx} row={row}"
                    )));
                }
                let term = mul_mod(witness_evals[num][row], mul_mod(lag_evals[num][col], coeff));
                acc = add_mod(acc, term);
            }
            *out_eval = acc;
        }
    }
    Ok(out)
}

fn linear_targets_as_field(statement: &(dyn SmallwoodConstraintAdapter + Sync)) -> Vec<u64> {
    statement
        .linear_targets()
        .iter()
        .copied()
        .map(canon)
        .collect()
}

fn adjusted_linear_targets_with_auxiliary(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    auxiliary_words: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    if auxiliary_words.len() != cfg.auxiliary_witness_word_count {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood auxiliary witness word count changed after config validation: words={} expected={}",
            auxiliary_words.len(),
            cfg.auxiliary_witness_word_count
        )));
    }
    if auxiliary_words.iter().any(|&word| word >= FIELD_ORDER) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood auxiliary witness contains a non-canonical Goldilocks element",
        ));
    }
    let mut targets = linear_targets_as_field(statement);
    if auxiliary_words.is_empty() {
        return Ok(targets);
    }
    for (check, target) in targets
        .iter_mut()
        .enumerate()
        .take(cfg.linear_constraint_count)
    {
        let start = statement.linear_constraint_offsets()[check] as usize;
        let end = statement.linear_constraint_offsets()[check + 1] as usize;
        let mut adjustment = 0u64;
        for term_idx in start..end {
            let coeff = statement.linear_constraint_coefficients()[term_idx];
            let idx = statement.linear_constraint_indices()[term_idx] as usize;
            if coeff == 0 || coeff >= FIELD_ORDER || idx >= cfg.total_variable_count {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood generic CSR metadata changed after config validation: constraint={check} term={term_idx}"
                )));
            }
            if idx < cfg.witness_size {
                continue;
            }
            let aux_idx = idx - cfg.witness_size;
            if aux_idx >= auxiliary_words.len() {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "smallwood generic CSR auxiliary index out of range after config validation: constraint={check} term={term_idx} auxiliary_index={aux_idx}"
                )));
            }
            adjustment = add_mod(adjustment, mul_mod(coeff, auxiliary_words[aux_idx]));
        }
        *target = sub_mod(*target, adjustment);
    }
    Ok(targets)
}

fn effective_linear_targets(
    cfg: &SmallwoodConfig,
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
    auxiliary_words: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    adjusted_linear_targets_with_auxiliary(cfg, statement, auxiliary_words)
}

pub fn pcs_build_coefficients(cfg: &SmallwoodConfig, eval_points: &[u64], coeffs: &mut [Vec<u64>]) {
    let m = cfg.packing_factor + cfg.nb_opened_evals();
    for (j, &r) in eval_points.iter().enumerate() {
        let mut powers = vec![0u64; m];
        powers[0] = 1;
        for k in 1..m {
            powers[k] = mul_mod(powers[k - 1], r);
        }
        for k in 0..cfg.beta() {
            let row = &mut coeffs[j * cfg.beta() + k];
            row.fill(0);
            let start = m * k;
            row[start..start + m].copy_from_slice(&powers);
        }
    }
}

fn lvcs_commit(
    cfg: &SmallwoodConfig,
    rows: &[Vec<u64>],
    salt: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
    statement_binding: &[u64],
    decs_leaf_tape_bytes: usize,
) -> Result<LvcsKey, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/lvcs_commit] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let mut extended_rows =
        vec![vec![0u64; cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals()]; cfg.nb_lvcs_rows];
    for row in 0..cfg.nb_lvcs_rows {
        extended_rows[row][..cfg.nb_lvcs_cols].copy_from_slice(&rows[row]);
        let rnd = random_vec(cfg.decs_nb_opened_evals())?;
        extended_rows[row][cfg.nb_lvcs_cols..].copy_from_slice(&rnd);
    }
    log_stage("extend_rows", &mut last);
    let rotated_rows = extended_rows
        .par_iter()
        .map(|row| rotate_left_words(row, cfg.nb_lvcs_cols))
        .collect::<Vec<_>>();
    let decs_key = decs_commit(
        cfg.nb_lvcs_rows,
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals() - 1,
        cfg.decs_eta(),
        cfg.decs_challenge_format,
        cfg.decs_nb_evals(),
        &rotated_rows,
        salt,
        transcript_backend,
        decs_evaluation_domain,
        statement_binding,
        decs_leaf_tape_bytes,
    )?;
    log_stage("decs_commit", &mut last);
    Ok(LvcsKey {
        extended_rows,
        decs_key,
    })
}

fn lvcs_open(
    cfg: &SmallwoodConfig,
    key: &LvcsKey,
    coeffs: &[Vec<u64>],
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<(Vec<Vec<u64>>, Vec<Vec<u64>>, Vec<Vec<u64>>, DecsProof), TransactionCircuitError> {
    let mut extended_combis =
        vec![vec![0u64; cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals()]; cfg.nb_lvcs_opened_combi];
    mat_mul(
        &mut extended_combis,
        coeffs,
        &key.extended_rows,
        cfg.nb_lvcs_opened_combi,
        cfg.nb_lvcs_rows,
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals(),
    );
    let mut combi_heads = Vec::with_capacity(cfg.nb_lvcs_opened_combi);
    let mut rcombi_tails = Vec::with_capacity(cfg.nb_lvcs_opened_combi);
    for combi in &extended_combis {
        combi_heads.push(combi[..cfg.nb_lvcs_cols].to_vec());
        rcombi_tails.push(combi[cfg.nb_lvcs_cols..].to_vec());
    }
    let trans_hash =
        hash_challenge_opening_decs(cfg, &combi_heads, h_piop, &rcombi_tails, transcript_backend);
    let (leaf_indexes, nonce) = xof_decs_opening(
        cfg.decs_nb_evals(),
        cfg.decs_nb_opened_evals(),
        cfg.decs_pow_bits(),
        &trans_hash,
        transcript_backend,
    )?;
    let field_eval_points = decs_field_evaluation_points(
        decs_evaluation_domain,
        cfg.decs_nb_evals(),
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals(),
        &leaf_indexes,
    )?;
    let mut evals = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.decs_nb_opened_evals()];
    let decs_proof = decs_open(
        cfg.nb_lvcs_rows,
        cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals() - 1,
        cfg.decs_nb_opened_evals(),
        &key.decs_key,
        &leaf_indexes,
        &field_eval_points,
        &mut evals,
        nonce,
        transcript_backend,
    )?;
    let mut subset_evals =
        vec![vec![0u64; cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi]; cfg.decs_nb_opened_evals()];
    for j in 0..cfg.decs_nb_opened_evals() {
        let mut ind = 0usize;
        let mut pos = 0usize;
        for (k, eval) in evals[j].iter().enumerate().take(cfg.nb_lvcs_rows) {
            if ind < cfg.nb_lvcs_opened_combi && cfg.fullrank_cols[ind] == k {
                ind += 1;
            } else {
                subset_evals[j][pos] = *eval;
                pos += 1;
            }
        }
    }

    Ok((combi_heads, rcombi_tails, subset_evals, decs_proof))
}

pub fn lvcs_recompute_rows(
    cfg: &SmallwoodConfig,
    coeffs: &[Vec<u64>],
    combi_heads: &[Vec<u64>],
    rcombi_tails: &[Vec<u64>],
    subset_evals: &[Vec<u64>],
    eval_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut extended_combis =
        vec![vec![0u64; cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals()]; cfg.nb_lvcs_opened_combi];
    for k in 0..cfg.nb_lvcs_opened_combi {
        extended_combis[k][..cfg.nb_lvcs_cols].copy_from_slice(&combi_heads[k]);
        extended_combis[k][cfg.nb_lvcs_cols..].copy_from_slice(&rcombi_tails[k]);
    }
    let mut rotated_combis = Vec::with_capacity(cfg.nb_lvcs_opened_combi);
    for combi in &extended_combis {
        rotated_combis.push(rotate_left_words(combi, cfg.nb_lvcs_cols));
    }
    let mut coeffs_part1 = vec![vec![0u64; cfg.nb_lvcs_opened_combi]; cfg.nb_lvcs_opened_combi];
    let mut coeffs_part2 =
        vec![vec![0u64; cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi]; cfg.nb_lvcs_opened_combi];
    for j in 0..cfg.nb_lvcs_opened_combi {
        let mut ind = 0usize;
        for k in 0..cfg.nb_lvcs_rows {
            if ind < cfg.nb_lvcs_opened_combi && cfg.fullrank_cols[ind] == k {
                coeffs_part1[j][ind] = coeffs[j][k];
                ind += 1;
            } else {
                coeffs_part2[j][k - ind] = coeffs[j][k];
            }
        }
    }
    let coeffs_part1_inv = mat_inv(&coeffs_part1)?;
    let mut evals = vec![vec![0u64; cfg.nb_lvcs_rows]; subset_evals.len()];
    for j in 0..subset_evals.len() {
        let q = rotated_combis
            .iter()
            .map(|values| evaluate_consecutive_values(values, eval_points[j]))
            .collect::<Result<Vec<_>, _>>()?;
        let tmp = mat_vec_mul_owned(&coeffs_part2, &subset_evals[j]);
        let rhs = q
            .iter()
            .zip(tmp.iter())
            .map(|(&a, &b)| sub_mod(a, b))
            .collect::<Vec<_>>();
        let res = mat_vec_mul_owned(&coeffs_part1_inv, &rhs);
        let mut ind = 0usize;
        for k in 0..cfg.nb_lvcs_rows {
            if ind < cfg.nb_lvcs_opened_combi && cfg.fullrank_cols[ind] == k {
                evals[j][k] = res[ind];
                ind += 1;
            } else {
                evals[j][k] = subset_evals[j][k - ind];
            }
        }
    }
    Ok(evals)
}

fn decs_commit(
    nb_polys: usize,
    poly_degree: usize,
    decs_eta: usize,
    decs_challenge_format: SmallwoodDecsChallengeFormat,
    decs_nb_evals: usize,
    initial_domain_evals: &[Vec<u64>],
    salt: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
    statement_binding: &[u64],
    decs_leaf_tape_bytes: usize,
) -> Result<DecsKey, TransactionCircuitError> {
    let trace_enabled = std::env::var_os("HEGEMON_SMALLWOOD_TRACE").is_some();
    let started = Instant::now();
    let mut last = started;
    let log_stage = |label: &str, last: &mut Instant| {
        if trace_enabled {
            let now = Instant::now();
            eprintln!(
                "[smallwood/decs_commit] {label}: +{:?} total={:?}",
                now.duration_since(*last),
                now.duration_since(started)
            );
            *last = now;
        }
    };
    let masking_polys = (0..decs_eta)
        .map(|_| random_poly(poly_degree))
        .collect::<Result<Vec<_>, _>>()?;
    let initial_len = poly_degree + 1;
    let disjoint_coset_descriptor =
        if decs_evaluation_domain == SmallwoodDecsEvaluationDomain::Radix2DisjointCoset {
            Some(SmallwoodDisjointCosetDescriptorV1::derive(
                decs_nb_evals,
                initial_len,
            )?)
        } else {
            None
        };
    log_stage("masking_polys", &mut last);
    let committed_domain_evals = initial_domain_evals
        .par_iter()
        .map(|evals| {
            let mut out = vec![0u64; decs_nb_evals];
            match decs_evaluation_domain {
                SmallwoodDecsEvaluationDomain::Consecutive => {
                    extend_consecutive_evals_into(
                        evals,
                        &mut out,
                        &mut Vec::new(),
                        &mut Vec::new(),
                    );
                }
                SmallwoodDecsEvaluationDomain::Radix2Subgroup => {
                    evaluate_consecutive_values_on_radix2_subgroup_into(evals, &mut out)?;
                }
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset => {
                    evaluate_consecutive_values_on_radix2_coset_into(
                        evals,
                        &mut out,
                        disjoint_coset_descriptor
                            .expect("computed disjoint DECS coset descriptor")
                            .shift,
                    )?;
                }
            }
            Ok::<_, TransactionCircuitError>(out)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let masking_domain_evals = masking_polys
        .par_iter()
        .map(|poly| {
            let mut out = vec![0u64; decs_nb_evals];
            match decs_evaluation_domain {
                SmallwoodDecsEvaluationDomain::Consecutive => {
                    evaluate_poly_on_consecutive_domain_into(
                        poly,
                        &mut out,
                        &mut Vec::new(),
                        &mut Vec::new(),
                        &mut Vec::new(),
                    );
                }
                SmallwoodDecsEvaluationDomain::Radix2Subgroup => {
                    evaluate_poly_on_radix2_subgroup_into(poly, &mut out)?;
                }
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset => {
                    evaluate_poly_on_radix2_coset_into(
                        poly,
                        &mut out,
                        disjoint_coset_descriptor
                            .expect("computed disjoint DECS coset descriptor")
                            .shift,
                    )?;
                }
            }
            Ok::<_, TransactionCircuitError>(out)
        })
        .collect::<Result<Vec<_>, _>>()?;
    log_stage("domain_evals", &mut last);
    let leaf_tapes = if decs_evaluation_domain == SmallwoodDecsEvaluationDomain::Radix2DisjointCoset
    {
        random_decs_leaf_tapes(decs_nb_evals, decs_leaf_tape_bytes)?
    } else {
        Vec::new()
    };
    let salt_words = bytes_to_words_unchecked(salt);
    let mut tree_levels = vec![vec![[0u8; DIGEST_BYTES]; decs_nb_evals]];
    if matches!(
        transcript_backend,
        SmallwoodTranscriptBackend::Sha512V6 | SmallwoodTranscriptBackend::Hx512Candidate
    ) {
        // The exact V6 preamble lives in the dedicated engine session.  Do
        // not move these requests to Rayon workers: TLS context is not
        // inherited by worker threads and would otherwise permit an
        // unbound/failing transcript request.
        tree_levels[0] = (0..decs_nb_evals)
            .map(|leaf_idx| {
                if let Some(tape) = leaf_tapes.get(leaf_idx) {
                    hash_strict_zk_merkle_leaf_from_tables(
                        &salt_words,
                        &committed_domain_evals,
                        &masking_domain_evals,
                        leaf_idx,
                        tape,
                        transcript_backend,
                    )
                } else {
                    hash_merkle_leave_from_tables(
                        &salt_words,
                        &committed_domain_evals,
                        &masking_domain_evals,
                        leaf_idx,
                        transcript_backend,
                    )
                }
            })
            .collect();
    } else {
        tree_levels[0] = (0..decs_nb_evals)
            .into_par_iter()
            .map(|leaf_idx| {
                if let Some(tape) = leaf_tapes.get(leaf_idx) {
                    hash_strict_zk_merkle_leaf_from_tables(
                        &salt_words,
                        &committed_domain_evals,
                        &masking_domain_evals,
                        leaf_idx,
                        tape,
                        transcript_backend,
                    )
                } else {
                    hash_merkle_leave_from_tables(
                        &salt_words,
                        &committed_domain_evals,
                        &masking_domain_evals,
                        leaf_idx,
                        transcript_backend,
                    )
                }
            })
            .collect();
    }
    log_stage("leaf_hashes", &mut last);
    let root = merkle_build_levels(&mut tree_levels, transcript_backend);
    log_stage("merkle_tree", &mut last);
    let hash_mt = hash_merkle_root_with_binding(salt, &root, transcript_backend, statement_binding);
    let gamma_all = derive_decs_challenge(
        nb_polys,
        decs_eta,
        decs_challenge_format,
        &hash_mt,
        transcript_backend,
    );
    log_stage("challenge", &mut last);
    let mut combined_domain_evals = vec![vec![0u64; initial_len]; decs_eta];
    mat_mul(
        &mut combined_domain_evals,
        &gamma_all,
        initial_domain_evals,
        decs_eta,
        nb_polys,
        initial_len,
    );
    let dec_polys = combined_domain_evals
        .par_iter()
        .enumerate()
        .map(|(k, evals)| {
            let mut poly = interpolate_consecutive(evals)?;
            poly_add_assign(&mut poly, &masking_polys[k]);
            Ok::<_, TransactionCircuitError>(poly)
        })
        .collect::<Result<Vec<_>, _>>()?;
    log_stage("dec_polys", &mut last);
    Ok(DecsKey {
        committed_domain_evals,
        masking_domain_evals,
        leaf_tapes,
        dec_polys,
        gamma_all,
        tree_levels,
    })
}

fn decs_open(
    nb_polys: usize,
    poly_degree: usize,
    decs_nb_opened_evals: usize,
    key: &DecsKey,
    leaf_indexes: &[u32],
    field_eval_points: &[u64],
    evals_out: &mut [Vec<u64>],
    nonce: [u8; NONCE_BYTES],
    _transcript_backend: SmallwoodTranscriptBackend,
) -> Result<DecsProof, TransactionCircuitError> {
    if leaf_indexes.len() != decs_nb_opened_evals
        || field_eval_points.len() != decs_nb_opened_evals
        || evals_out.len() != decs_nb_opened_evals
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS opening index/evaluation-point shape mismatch",
        ));
    }
    let indices = leaf_indexes
        .iter()
        .map(|&index| index as usize)
        .collect::<Vec<_>>();
    if indices
        .iter()
        .any(|&index| index >= key.tree_levels[0].len())
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS opening index exceeds the committed table",
        ));
    }
    let auth_paths = compact_merkle_auth_paths(&key.tree_levels, &indices);
    let leaf_tapes = if key.leaf_tapes.is_empty() {
        Vec::new()
    } else {
        indices
            .iter()
            .map(|&index| key.leaf_tapes[index].clone())
            .collect()
    };
    let mut masking_evals = Vec::with_capacity(indices.len());
    for (j, &idx) in indices.iter().enumerate() {
        evals_out[j] = key
            .committed_domain_evals
            .iter()
            .map(|poly| poly[idx])
            .collect();
        masking_evals.push(
            key.masking_domain_evals
                .iter()
                .map(|poly| poly[idx])
                .collect::<Vec<_>>(),
        );
    }
    for (opening, &field_point) in field_eval_points.iter().enumerate() {
        for (combination, dec_poly) in key.dec_polys.iter().enumerate() {
            let mut table_value =
                proof_combination_at_opening(&key.gamma_all[combination], &evals_out[opening]);
            table_value = add_mod(table_value, masking_evals[opening][combination]);
            if table_value != poly_eval(dec_poly, field_point) {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood DECS table index does not match its algebraic evaluation point",
                ));
            }
        }
    }
    let high_coeffs = key
        .dec_polys
        .iter()
        .map(|poly| poly[decs_nb_opened_evals..].to_vec())
        .collect::<Vec<_>>();
    let _ = (nb_polys, poly_degree, nonce);
    Ok(DecsProof {
        auth_paths,
        leaf_tapes,
        masking_evals,
        high_coeffs,
    })
}

fn proof_combination_at_opening(coefficients: &[u64], opened_values: &[u64]) -> u64 {
    coefficients
        .iter()
        .zip(opened_values)
        .fold(0u64, |acc, (&coefficient, &value)| {
            add_mod(acc, mul_mod(coefficient, value))
        })
}

/// Recompute the DECS Merkle root from authenticated table positions.
///
/// `leaf_indexes` are exact sorted `u32` table indexes. They are deliberately
/// not algebraic evaluation points: callers using a radix-2 subgroup or coset
/// must pass those field points only to LVCS/polynomial reconstruction.
pub fn decs_recompute_root(
    cfg: &SmallwoodConfig,
    salt: &[u8],
    evals: &[Vec<u64>],
    leaf_indexes: &[u32],
    proof: &DecsProof,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
    if leaf_indexes.len() != evals.len()
        || leaf_indexes.len() != proof.auth_paths.len()
        || leaf_indexes
            .iter()
            .any(|&index| index as usize >= cfg.decs_nb_evals())
        || !leaf_indexes.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS Merkle leaf indexes must be in-range, distinct, and sorted",
        ));
    }
    let depth = cfg.decs_nb_evals().ilog2() as usize;
    let expected_lengths = expected_compact_merkle_auth_path_lengths(
        &leaf_indexes
            .iter()
            .map(|&index| index as usize)
            .collect::<Vec<_>>(),
        depth,
    );
    if proof.auth_paths.len() != expected_lengths.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood decs auth path count mismatch",
        ));
    }
    update_verifier_operation_profile_v1(|profile| {
        profile.merkle_authentication_words += proof
            .auth_paths
            .iter()
            .map(|path| path.len() * transcript_backend.digest_words())
            .sum::<usize>() as u64;
    });
    let mut current_hashes = Vec::with_capacity(leaf_indexes.len());
    let mut current_indices = Vec::with_capacity(leaf_indexes.len());
    let mut auth_path_cursors = vec![0usize; leaf_indexes.len()];
    if !proof.leaf_tapes.is_empty() && proof.leaf_tapes.len() != leaf_indexes.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS opened leaf-tape count mismatch",
        ));
    }
    for j in 0..leaf_indexes.len() {
        if proof.auth_paths[j].len() != expected_lengths[j] {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood decs compact auth path length mismatch",
            ));
        }
        let mut leaf_evals = evals[j].clone();
        leaf_evals.extend_from_slice(&proof.masking_evals[j]);
        current_hashes.push(if proof.leaf_tapes.is_empty() {
            hash_merkle_leave(cfg.nb_lvcs_rows, &leaf_evals, salt, transcript_backend)
        } else {
            hash_strict_zk_merkle_leaf(
                cfg.nb_lvcs_rows,
                &leaf_evals,
                leaf_indexes[j] as usize,
                &proof.leaf_tapes[j],
                salt,
                transcript_backend,
            )?
        });
        current_indices.push(leaf_indexes[j] as usize);
    }
    for level in 0..depth {
        let mut level_hashes = BTreeMap::new();
        for (&index, &hash) in current_indices.iter().zip(current_hashes.iter()) {
            match level_hashes.insert(index, hash) {
                Some(existing) if existing != hash => {
                    return Err(TransactionCircuitError::ConstraintViolation(
                        "smallwood decs duplicate subtree hash mismatch",
                    ));
                }
                _ => {}
            }
        }
        let mut next_hashes = Vec::with_capacity(current_hashes.len());
        let mut next_indices = Vec::with_capacity(current_indices.len());
        for j in 0..current_indices.len() {
            let index = current_indices[j];
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            let sibling_hash = if let Some(hash) = level_hashes.get(&sibling_index) {
                *hash
            } else {
                let cursor = auth_path_cursors[j];
                let hash = proof.auth_paths[j].get(cursor).copied().ok_or(
                    TransactionCircuitError::ConstraintViolation(
                        "smallwood decs compact auth path underflow",
                    ),
                )?;
                auth_path_cursors[j] += 1;
                hash
            };
            let parent = hash_merkle_children_at(
                if index.is_multiple_of(2) {
                    &current_hashes[j]
                } else {
                    &sibling_hash
                },
                if index.is_multiple_of(2) {
                    &sibling_hash
                } else {
                    &current_hashes[j]
                },
                level,
                index / 2,
                transcript_backend,
            );
            next_hashes.push(parent);
            next_indices.push(index / 2);
        }
        current_hashes = next_hashes;
        current_indices = next_indices;
    }
    for (cursor, path) in auth_path_cursors.iter().zip(proof.auth_paths.iter()) {
        if *cursor != path.len() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood decs compact auth path overflow",
            ));
        }
    }
    let root =
        current_hashes
            .first()
            .copied()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood decs root recomputation missing",
            ))?;
    if current_hashes.iter().any(|hash| *hash != root) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood decs root mismatch across opened leaves",
        ));
    }
    Ok(root)
}

pub fn decs_commitment_transcript(
    cfg: &SmallwoodConfig,
    salt: &[u8],
    evals: &[Vec<u64>],
    root_words: &[u8; DIGEST_BYTES],
    eval_points: &[u64],
    proof: &DecsProof,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u64>, TransactionCircuitError> {
    decs_commitment_transcript_with_binding(
        cfg,
        salt,
        evals,
        root_words,
        eval_points,
        proof,
        transcript_backend,
        &[],
    )
}

fn decs_commitment_transcript_with_binding(
    cfg: &SmallwoodConfig,
    salt: &[u8],
    evals: &[Vec<u64>],
    root_words: &[u8; DIGEST_BYTES],
    eval_points: &[u64],
    proof: &DecsProof,
    transcript_backend: SmallwoodTranscriptBackend,
    statement_binding: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    let hash_mt =
        hash_merkle_root_with_binding(salt, root_words, transcript_backend, statement_binding);
    let gamma_all = derive_decs_challenge(
        cfg.nb_lvcs_rows,
        cfg.decs_eta(),
        cfg.decs_challenge_format,
        &hash_mt,
        transcript_backend,
    );
    decs_commitment_transcript_with_challenge(
        cfg,
        evals,
        eval_points,
        proof,
        &hash_mt,
        &gamma_all,
        transcript_backend,
    )
}

fn decs_commitment_transcript_with_challenge(
    cfg: &SmallwoodConfig,
    evals: &[Vec<u64>],
    eval_points: &[u64],
    proof: &DecsProof,
    hash_mt: &[u8; DIGEST_BYTES],
    gamma_all: &[Vec<u64>],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u64>, TransactionCircuitError> {
    if gamma_all.len() != cfg.decs_eta()
        || gamma_all.iter().any(|row| row.len() != cfg.nb_lvcs_rows)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood decs challenge coefficient shape mismatch",
        ));
    }
    let mut transcript = Vec::new();
    transcript.extend(digest_to_words(hash_mt, transcript_backend));
    for (k, gamma_row) in gamma_all.iter().enumerate().take(cfg.decs_eta()) {
        let mut dec_evals = vec![0u64; cfg.decs_nb_opened_evals()];
        for i in 0..cfg.decs_nb_opened_evals() {
            let mut acc = 0u64;
            for j in 0..cfg.nb_lvcs_rows {
                acc = add_mod(acc, mul_mod(evals[i][j], gamma_row[j]));
            }
            acc = add_mod(acc, proof.masking_evals[i][k]);
            dec_evals[i] = acc;
        }
        let dec_poly = poly_restore(
            &proof.high_coeffs[k],
            &dec_evals,
            eval_points,
            cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals() - 1,
        )?;
        transcript.extend_from_slice(&dec_poly);
    }
    Ok(transcript)
}

fn hash_piop(words: &[u64], transcript_backend: SmallwoodTranscriptBackend) -> [u8; DIGEST_BYTES] {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        let message = encode_smallwood_hx512_field_message(words);
        return hx512_capture_digest(|driver| driver.bind_piop_input(&message));
    }
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN),
        words,
    )
}

pub fn hash_piop_transcript(
    words: &[u64],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        let message = encode_smallwood_hx512_field_message(words);
        return hx512_capture_digest(|driver| driver.bind_piop_transcript(&message));
    }
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_PIOP_TRANSCRIPT_DOMAIN),
        words,
    )
}

pub fn hash_challenge_opening_decs(
    cfg: &SmallwoodConfig,
    combi_heads: &[Vec<u64>],
    h_piop: &[u8; DIGEST_BYTES],
    rcombi_tails: &[Vec<u64>],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::new();
    input.extend_from_slice(&digest_to_words(h_piop, transcript_backend));
    for k in 0..cfg.nb_lvcs_opened_combi {
        input.extend_from_slice(&combi_heads[k]);
        input.extend_from_slice(&rcombi_tails[k]);
    }
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        let message = encode_smallwood_hx512_field_message(&input);
        return hx512_capture_digest(|driver| driver.bind_decs_opening(&message));
    }
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_DECS_OPENING_DOMAIN),
        &input,
    )
}

fn hash_merkle_leave(
    _nb_polys: usize,
    evals: &[u64],
    salt: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    update_verifier_operation_profile_v1(|profile| {
        profile.merkle_leaf_hashes += 1;
    });
    let mut input = Vec::with_capacity(salt.len().div_ceil(8) + evals.len());
    input.extend(bytes_to_words_unchecked(salt));
    input.extend_from_slice(evals);
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        return hx512_capture_digest(|driver| {
            Ok(driver.record_failure(
                TransactionCircuitError::ConstraintViolation(
                    "HX512 forbids unhiding Merkle leaves",
                ),
                [0u8; DIGEST_BYTES],
            ))
        });
    }
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_MERKLE_LEAF_DOMAIN),
        &input,
    )
}

fn strict_zk_merkle_leaf_words(
    salt_words: &[u64],
    leaf_index: usize,
    tape: &[u8],
    committed_evaluations: &[u64],
    masking_evaluations: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    if tape.is_empty() || !tape.len().is_multiple_of(8) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS leaf tape must be non-empty and word aligned",
        ));
    }
    let leaf_index = u64::try_from(leaf_index).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS leaf index does not fit the transcript wire",
        )
    })?;
    let tape_words = bytes_to_words_unchecked(tape);
    let mut input = Vec::with_capacity(
        salt_words.len()
            + 1
            + tape_words.len()
            + 1
            + committed_evaluations.len()
            + 1
            + masking_evaluations.len(),
    );
    input.extend_from_slice(salt_words);
    input.push(leaf_index);
    input.extend_from_slice(&tape_words);
    input.push(committed_evaluations.len() as u64);
    input.extend_from_slice(committed_evaluations);
    input.push(masking_evaluations.len() as u64);
    input.extend_from_slice(masking_evaluations);
    Ok(input)
}

fn hash_strict_zk_merkle_leaf(
    nb_polys: usize,
    evals: &[u64],
    leaf_index: usize,
    tape: &[u8],
    salt: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<[u8; DIGEST_BYTES], TransactionCircuitError> {
    if nb_polys > evals.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS leaf evaluation split is invalid",
        ));
    }
    update_verifier_operation_profile_v1(|profile| {
        profile.merkle_leaf_hashes += 1;
    });
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        return with_smallwood_hx512_transcript_driver(|driver| {
            driver.hash_leaf(
                salt,
                leaf_index,
                tape,
                &evals[..nb_polys],
                &evals[nb_polys..],
            )
        })?;
    }
    let input = strict_zk_merkle_leaf_words(
        &bytes_to_words_unchecked(salt),
        leaf_index,
        tape,
        &evals[..nb_polys],
        &evals[nb_polys..],
    )?;
    Ok(transcript_xof_digest(
        transcript_backend,
        SMALLWOOD_STRICT_ZK_MERKLE_LEAF_DOMAIN_V1,
        &input,
    ))
}

fn hash_strict_zk_merkle_leaf_from_tables(
    salt_words: &[u64],
    committed_domain_evals: &[Vec<u64>],
    masking_domain_evals: &[Vec<u64>],
    leaf_index: usize,
    tape: &[u8],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    if transcript_backend == SmallwoodTranscriptBackend::Sha512Level5 {
        update_verifier_operation_profile_v1(|profile| {
            profile.sha512_digest_calls += 1;
        });
        let tape_word_count = tape.len().div_ceil(8);
        let word_count = salt_words.len()
            + 1
            + tape_word_count
            + 1
            + committed_domain_evals.len()
            + 1
            + masking_domain_evals.len();
        let mut hasher = Sha512::new();
        hasher.update((SMALLWOOD_STRICT_ZK_MERKLE_LEAF_DOMAIN_V1.len() as u64).to_le_bytes());
        hasher.update(SMALLWOOD_STRICT_ZK_MERKLE_LEAF_DOMAIN_V1);
        hasher.update((word_count as u64).to_le_bytes());
        for word in salt_words {
            hasher.update(word.to_le_bytes());
        }
        hasher.update((leaf_index as u64).to_le_bytes());
        hasher.update(tape);
        hasher.update((committed_domain_evals.len() as u64).to_le_bytes());
        for poly in committed_domain_evals {
            hasher.update(poly[leaf_index].to_le_bytes());
        }
        hasher.update((masking_domain_evals.len() as u64).to_le_bytes());
        for poly in masking_domain_evals {
            hasher.update(poly[leaf_index].to_le_bytes());
        }
        hasher.update(0u64.to_le_bytes());
        return hasher.finalize().into();
    }
    let committed = committed_domain_evals
        .iter()
        .map(|poly| poly[leaf_index])
        .collect::<Vec<_>>();
    let masking = masking_domain_evals
        .iter()
        .map(|poly| poly[leaf_index])
        .collect::<Vec<_>>();
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        let salt = salt_words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        return hx512_capture_digest(|driver| {
            driver.hash_leaf(&salt, leaf_index, tape, &committed, &masking)
        });
    }
    let input = strict_zk_merkle_leaf_words(salt_words, leaf_index, tape, &committed, &masking)
        .expect("validated strict-ZK DECS leaf index");
    transcript_xof_digest(
        transcript_backend,
        SMALLWOOD_STRICT_ZK_MERKLE_LEAF_DOMAIN_V1,
        &input,
    )
}

fn hash_merkle_leave_from_tables(
    salt_words: &[u64],
    committed_domain_evals: &[Vec<u64>],
    masking_domain_evals: &[Vec<u64>],
    leaf_idx: usize,
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    if transcript_backend == SmallwoodTranscriptBackend::Blake3 {
        let mut hasher = Hasher::new();
        hasher.update(SMALLWOOD_XOF_DOMAIN);
        hasher.update(
            &((salt_words.len() + committed_domain_evals.len() + masking_domain_evals.len())
                as u64)
                .to_le_bytes(),
        );
        update_hasher_with_word_slice(&mut hasher, salt_words);
        for poly in committed_domain_evals {
            hasher.update(&poly[leaf_idx].to_le_bytes());
        }
        for poly in masking_domain_evals {
            hasher.update(&poly[leaf_idx].to_le_bytes());
        }
        return read_blake3_xof_digest(hasher.finalize_xof());
    }
    if transcript_backend.is_sha512_level5() {
        let domain = SMALLWOOD_LEVEL5_MERKLE_LEAF_DOMAIN;
        let word_count =
            salt_words.len() + committed_domain_evals.len() + masking_domain_evals.len();
        let mut hasher = Sha512::new();
        if let Some(profile_domain) = transcript_backend.sha512_profile_domain() {
            hasher.update((profile_domain.len() as u64).to_le_bytes());
            hasher.update(profile_domain);
        }
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        hasher.update((word_count as u64).to_le_bytes());
        for word in salt_words {
            hasher.update(word.to_le_bytes());
        }
        for poly in committed_domain_evals {
            hasher.update(poly[leaf_idx].to_le_bytes());
        }
        for poly in masking_domain_evals {
            hasher.update(poly[leaf_idx].to_le_bytes());
        }
        hasher.update(0u64.to_le_bytes());
        let raw_digest = hasher.finalize().into();
        return observe_sha512_commitment(transcript_backend, raw_digest);
    }
    let mut input = Vec::with_capacity(
        salt_words.len() + committed_domain_evals.len() + masking_domain_evals.len(),
    );
    input.extend_from_slice(salt_words);
    for poly in committed_domain_evals {
        input.push(poly[leaf_idx]);
    }
    for poly in masking_domain_evals {
        input.push(poly[leaf_idx]);
    }
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_MERKLE_LEAF_DOMAIN),
        &input,
    )
}

fn hash_merkle_root(
    salt: &[u8],
    root: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    hash_merkle_root_with_binding(salt, root, transcript_backend, &[])
}

fn hash_merkle_root_with_binding(
    salt: &[u8],
    root: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
    statement_binding: &[u64],
) -> [u8; DIGEST_BYTES] {
    update_verifier_operation_profile_v1(|profile| {
        profile.merkle_root_hashes += 1;
    });
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        if !statement_binding.is_empty() {
            return hx512_capture_digest(|driver| {
                Ok(driver.record_failure(
                    TransactionCircuitError::ConstraintViolation(
                        "HX512 forbids duplicate legacy statement-binding words",
                    ),
                    [0u8; DIGEST_BYTES],
                ))
            });
        }
        return hx512_capture_digest(|driver| {
            driver.bind_decs_root(
                salt,
                HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals,
                root,
            )
        });
    }
    if transcript_backend == SmallwoodTranscriptBackend::Blake3 {
        let mut hasher = Hasher::new();
        hasher.update(SMALLWOOD_XOF_DOMAIN);
        hasher.update(&((salt.len().div_ceil(8) + LEGACY_DIGEST_WORDS) as u64).to_le_bytes());
        hasher.update(salt);
        hasher.update(&root[..LEGACY_DIGEST_BYTES]);
        return read_blake3_xof_digest(hasher.finalize_xof());
    }
    let mut input = Vec::with_capacity(
        salt.len().div_ceil(8) + transcript_backend.digest_words() + statement_binding.len(),
    );
    input.extend(bytes_to_words_unchecked(salt));
    input.extend(digest_to_words(root, transcript_backend));
    if transcript_backend.is_sha512_level5()
        || transcript_backend == SmallwoodTranscriptBackend::Sha512V6
    {
        input.extend_from_slice(statement_binding);
    }
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_MERKLE_ROOT_DOMAIN),
        &input,
    )
}

fn derive_decs_challenge(
    nb_polys: usize,
    decs_eta: usize,
    challenge_format: SmallwoodDecsChallengeFormat,
    hash_mt: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<Vec<u64>> {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        if challenge_format != SmallwoodDecsChallengeFormat::Uniform {
            return vec![vec![0u64; nb_polys]; decs_eta];
        }
        let samples = hx512_capture_field_samples(decs_eta * nb_polys, |driver, expected| {
            driver.sample_decs_coefficients(expected)
        });
        return samples
            .chunks_exact(nb_polys)
            .map(<[u64]>::to_vec)
            .collect();
    }
    match challenge_format {
        SmallwoodDecsChallengeFormat::ScalarPowers => {
            let gamma_words = transcript_xof_words(
                transcript_backend,
                transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_DECS_COEFFICIENT_DOMAIN),
                &digest_to_words(hash_mt, transcript_backend),
                decs_eta,
            );
            let mut out = vec![vec![0u64; nb_polys]; decs_eta];
            for k in 0..decs_eta {
                out[k][0] = gamma_words[k];
                for j in 1..nb_polys {
                    out[k][j] = mul_mod(out[k][j - 1], gamma_words[k]);
                }
            }
            out
        }
        SmallwoodDecsChallengeFormat::Uniform => {
            let gamma_words = transcript_xof_words(
                transcript_backend,
                transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_DECS_COEFFICIENT_DOMAIN),
                &digest_to_words(hash_mt, transcript_backend),
                decs_eta * nb_polys,
            );
            gamma_words
                .chunks_exact(nb_polys)
                .map(<[u64]>::to_vec)
                .collect()
        }
    }
}

pub fn derive_gamma_prime(
    cfg: &SmallwoodConfig,
    hash_fpp: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<Vec<u64>> {
    let nb_max_constraints = cfg.constraint_count.max(cfg.linear_constraint_count);
    let rho = cfg.rho();
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        let gamma_words =
            hx512_capture_field_samples(rho * nb_max_constraints, |driver, expected| {
                driver.sample_piop_coefficients(expected)
            });
        return gamma_words
            .chunks_exact(nb_max_constraints)
            .map(<[u64]>::to_vec)
            .collect();
    }
    let gamma_words = transcript_xof_words(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_PIOP_COEFFICIENT_DOMAIN),
        &digest_to_words(hash_fpp, transcript_backend),
        rho * nb_max_constraints,
    );
    gamma_words
        .chunks_exact(nb_max_constraints)
        .map(<[u64]>::to_vec)
        .collect()
}

fn choose_opening_nonce(
    cfg: &SmallwoodConfig,
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<[u8; NONCE_BYTES], TransactionCircuitError> {
    choose_opening_nonce_for_profile(&cfg.packing_points, cfg.profile, h_piop, transcript_backend)
}

fn choose_opening_nonce_for_profile(
    packing_points: &[u64],
    profile: SmallwoodNoGrindingProfileV1,
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<[u8; NONCE_BYTES], TransactionCircuitError> {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        return Err(TransactionCircuitError::ConstraintViolation(
            "HX512 has no serialized or grindable PIOP nonce; stage6 samples openings directly",
        ));
    }
    let mut counter = 0u32;
    loop {
        let max_trials = if transcript_backend == SmallwoodTranscriptBackend::Sha512V6 {
            SHA512_V6_SMZ2_MAX_PIOP_NONCE_TRIALS
        } else if transcript_backend.is_sha512_level5() {
            SMALLWOOD_LEVEL5_MAX_PIOP_NONCE_TRIALS
        } else {
            u32::MAX
        };
        if counter >= max_trials {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood opening nonce trial limit exhausted",
            ));
        }
        update_verifier_operation_profile_v1(|operation_profile| {
            operation_profile.piop_nonce_trials += 1;
        });
        let nonce = counter.to_le_bytes();
        let eval_points =
            xof_piop_opening_points_for_profile(&nonce, h_piop, profile, transcript_backend);
        let valid = smallwood_piop_opening_points_are_valid_for_profile(
            packing_points,
            &eval_points,
            profile,
        );
        if valid {
            return Ok(nonce);
        }
        counter = counter
            .checked_add(1)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood opening nonce overflow",
            ))?;
    }
}

fn canonical_piop_opening_points(
    packing_points: &[u64],
    profile: SmallwoodNoGrindingProfileV1,
    provided_nonce: &[u8; NONCE_BYTES],
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<Vec<u64>, TransactionCircuitError> {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        if *provided_nonce != [0u8; NONCE_BYTES] {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 internal nonce sentinel must be canonical zero and is not serialized",
            ));
        }
        return sample_smallwood_hx512_piop_openings(packing_points, profile.nb_opened_evals);
    }
    let expected_nonce =
        choose_opening_nonce_for_profile(packing_points, profile, h_piop, transcript_backend)?;
    if *provided_nonce != expected_nonce {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood opening nonce is not canonical; grinding is forbidden",
        ));
    }
    let eval_points =
        xof_piop_opening_points_for_profile(provided_nonce, h_piop, profile, transcript_backend);
    ensure_no_packing_collisions_for_profile(packing_points, &eval_points, profile)?;
    Ok(eval_points)
}

fn serialized_proof_size_hint_with_profile(
    cfg: &SmallwoodConfig,
    profile: SmallwoodNoGrindingProfileV1,
    auxiliary_words_len: usize,
    transcript_backend: SmallwoodTranscriptBackend,
    decs_evaluation_domain: SmallwoodDecsEvaluationDomain,
) -> Result<usize, TransactionCircuitError> {
    let digest_bytes = transcript_backend.digest_bytes();
    if !matches!(
        digest_bytes,
        LEGACY_DIGEST_BYTES
            | SMALLWOOD_FULL_SHA512_FIRST48_COMMITMENT_BYTES_V3
            | SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES
            | DIGEST_BYTES
    ) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood projection digest width is unsupported",
        ));
    }
    let wire_identity =
        proof_wire_identity_for_backend_and_domain(transcript_backend, decs_evaluation_domain)?;
    let strict_zk_decs_leaf_hiding = wire_identity.is_strict_zk();
    let leaf_tapes =
        if let Some((opened_leaf_count, tape_bytes)) = wire_identity.opened_leaf_tape_profile() {
            if profile.decs_nb_opened_evals != opened_leaf_count {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood strict projection opening count does not match its wire identity",
                ));
            }
            vec![vec![0u8; tape_bytes]; opened_leaf_count]
        } else {
            Vec::new()
        };
    let auth_paths = if matches!(
        wire_identity,
        SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7
            | SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8
    ) {
        let opened_leaf_count = profile.decs_nb_opened_evals;
        let total_nodes = maximum_smallwood_compact_authentication_nodes_v1(
            profile.decs_nb_evals,
            opened_leaf_count,
        )?;
        let base_nodes = total_nodes / opened_leaf_count;
        let longer_paths = total_nodes % opened_leaf_count;
        (0..opened_leaf_count)
            .map(|index| vec![[0u8; DIGEST_BYTES]; base_nodes + usize::from(index < longer_paths)])
            .collect()
    } else {
        vec![
            vec![[0u8; DIGEST_BYTES]; profile.decs_nb_evals.ilog2() as usize];
            profile.decs_nb_opened_evals
        ]
    };
    let proof = SmallwoodProof {
        wire_identity,
        digest_bytes,
        strict_zk_decs_leaf_hiding,
        hx512_decs_root: None,
        hx512_piop_input_digest: None,
        salt: vec![0u8; SALT_BYTES],
        nonce: [0u8; NONCE_BYTES],
        h_piop: [0u8; DIGEST_BYTES],
        piop: PiopProof {
            ppol_highs: vec![
                vec![0u64; cfg.mpol_poly_degree + 1 - profile.nb_opened_evals];
                profile.rho
            ],
            plin_highs: vec![
                vec![0u64; cfg.mlin_poly_degree + 1 - (profile.nb_opened_evals + 1)];
                profile.rho
            ],
        },
        pcs: PcsProof {
            rcombi_tails: vec![vec![0u64; profile.decs_nb_opened_evals]; cfg.nb_lvcs_opened_combi],
            subset_evals: vec![
                vec![0u64; cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi];
                profile.decs_nb_opened_evals
            ],
            partial_evals: vec![
                vec![0u64; cfg.nb_unstacked_cols - cfg.nb_polys];
                profile.nb_opened_evals
            ],
            decs: DecsProof {
                auth_paths,
                leaf_tapes,
                masking_evals: vec![vec![0u64; profile.decs_eta]; profile.decs_nb_opened_evals],
                high_coeffs: vec![vec![0u64; cfg.nb_lvcs_cols]; profile.decs_eta],
            },
        },
        opened_witness: SmallwoodOpenedWitnessBundle::row_scalars(
            vec![vec![0u64; cfg.nb_polys]; profile.nb_opened_evals],
            vec![0u64; auxiliary_words_len],
            auxiliary_words_len,
        ),
    };
    encode_smallwood_proof_bytes_v1(&proof).map(|bytes| bytes.len())
}

/// Exact maximum number of serialized authentication nodes among canonical
/// compact Merkle openings of `opened_leaf_count` distinct leaves.
///
/// At an internal node, openings confined to one child pay one sibling node
/// per opened leaf; openings in both children pay no sibling node at that
/// level.  The dynamic program considers every feasible split at every tree
/// height, so it proves the maximum rather than assuming independent full
/// paths (which the verifier rejects as non-canonical).
pub fn maximum_smallwood_compact_authentication_nodes_v1(
    domain_size: usize,
    opened_leaf_count: usize,
) -> Result<usize, TransactionCircuitError> {
    if domain_size == 0 || !domain_size.is_power_of_two() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood compact-auth projection requires a power-of-two domain",
        ));
    }
    if opened_leaf_count == 0
        || opened_leaf_count > domain_size
        || opened_leaf_count > MAX_SMALLWOOD_COMPACT_COLLECTION_ROWS_V1
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood compact-auth projection opening count is outside the wire bounds",
        ));
    }

    let depth = domain_size.ilog2() as usize;
    let mut previous = vec![None; opened_leaf_count + 1];
    previous[0] = Some(0usize);
    previous[1] = Some(0usize);
    for height in 1..=depth {
        let subtree_capacity = 1usize << height;
        let child_capacity = subtree_capacity / 2;
        let mut current = vec![None; opened_leaf_count + 1];
        for total in 0..=opened_leaf_count.min(subtree_capacity) {
            let minimum_left = total.saturating_sub(child_capacity);
            let maximum_left = total.min(child_capacity);
            let mut best = None;
            for left in minimum_left..=maximum_left {
                let right = total - left;
                let (Some(left_nodes), Some(right_nodes)) = (previous[left], previous[right])
                else {
                    continue;
                };
                let boundary_nodes = if (left == 0) ^ (right == 0) { total } else { 0 };
                let nodes = left_nodes
                    .checked_add(right_nodes)
                    .and_then(|nodes| nodes.checked_add(boundary_nodes))
                    .ok_or(TransactionCircuitError::ConstraintViolation(
                        "smallwood compact-auth projection overflow",
                    ))?;
                best = Some(best.map_or(nodes, |prior: usize| prior.max(nodes)));
            }
            current[total] = best;
        }
        previous = current;
    }
    previous[opened_leaf_count].ok_or(TransactionCircuitError::ConstraintViolation(
        "smallwood compact-auth projection has no feasible leaf placement",
    ))
}

/// Project the exact maximum canonical SMZ8 inner-wire bytes from the
/// compiler-reported statement geometry and serialized auxiliary-witness
/// surface.  Public statement words are transcript-bound but are not repeated
/// in the proof; auxiliary witness words are charged by the serializer.
pub fn projected_poseidon2_v8_inner_proof_bytes(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_poseidon2_v8_smz8_profile(
        statement,
        POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let cfg =
        SmallwoodConfig::new_with_profile(statement, POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE)?;
    let full_path_projection = serialized_proof_size_hint_with_profile(
        &cfg,
        POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE,
        statement.auxiliary_witness_words().len(),
        SmallwoodTranscriptBackend::Sha512Poseidon2V8,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let depth = POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE
        .decs_nb_evals
        .ilog2() as usize;
    let opened_leaf_count = POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_opened_evals;
    let full_path_nodes = opened_leaf_count.checked_mul(depth).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ8 full-path projection overflow",
        ),
    )?;
    let compact_nodes = maximum_smallwood_compact_authentication_nodes_v1(
        POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_evals,
        opened_leaf_count,
    )?;
    if compact_nodes != SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ8 compact-auth protocol constant drift",
        ));
    }
    let noncanonical_path_bytes = full_path_nodes
        .checked_sub(compact_nodes)
        .and_then(|nodes| nodes.checked_mul(DIGEST_BYTES))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ8 compact-path projection overflow",
        ))?;
    full_path_projection
        .checked_sub(noncanonical_path_bytes)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ8 compact-path projection underflow",
        ))
}

/// Project the exact maximum canonical SMZ9 inner-wire bytes from the same V8
/// relation geometry.  The successor uses six PIOP openings and twenty
/// distinct DECS leaves; public words remain transcript-bound and absent from
/// the proof payload.
pub fn projected_poseidon2_v8_smz9_inner_proof_bytes(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_poseidon2_v8_smz9_profile(
        statement,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let cfg = SmallwoodConfig::new_with_profile(
        statement,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
    )?;
    let full_path_projection = serialized_proof_size_hint_with_profile(
        &cfg,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        statement.auxiliary_witness_words().len(),
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let depth = POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE
        .decs_nb_evals
        .ilog2() as usize;
    let opened_leaf_count = POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_opened_evals;
    let full_path_nodes = opened_leaf_count.checked_mul(depth).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ9 full-path projection overflow",
        ),
    )?;
    let compact_nodes = maximum_smallwood_compact_authentication_nodes_v1(
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_evals,
        opened_leaf_count,
    )?;
    if compact_nodes != SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ9 compact-auth protocol constant drift",
        ));
    }
    let noncanonical_path_bytes = full_path_nodes
        .checked_sub(compact_nodes)
        .and_then(|nodes| nodes.checked_mul(DIGEST_BYTES))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ9 compact-path projection overflow",
        ))?;
    full_path_projection
        .checked_sub(noncanonical_path_bytes)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMZ9 compact-path projection underflow",
        ))
}

/// Project the exact maximum canonical SMC7 inner-wire bytes. HGV8RP03 keeps
/// the SMZ9 relation adapter and six PIOP openings; SMC7 changes the DECS
/// query count to nineteen and serializes each complete-SHA-512 commitment as
/// its canonical first 56 bytes. Compact authentication is charged by the same
/// exact split dynamic program used by the encoder, not by nineteen full paths.
pub fn projected_poseidon2_v8_compact448_inner_proof_bytes(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_poseidon2_v8_compact448_profile(
        statement,
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let cfg = SmallwoodConfig::new_with_profile(
        statement,
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
    )?;
    let compact_path_projection = serialized_proof_size_hint_with_profile(
        &cfg,
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE,
        statement.auxiliary_witness_words().len(),
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let depth = POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE
        .decs_nb_evals
        .ilog2() as usize;
    let opened_leaf_count =
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_opened_evals;
    let full_path_nodes = opened_leaf_count.checked_mul(depth).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood SMC7 full-path projection overflow",
        ),
    )?;
    let compact_nodes = maximum_smallwood_compact_authentication_nodes_v1(
        POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_evals,
        opened_leaf_count,
    )?;
    if compact_nodes != SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_COMPACT_AUTHENTICATION_NODES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC7 compact-auth protocol constant drift",
        ));
    }
    let noncanonical_path_bytes = full_path_nodes
        .checked_sub(compact_nodes)
        .and_then(|nodes| nodes.checked_mul(SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC7 compact-path projection overflow",
        ))?;
    let full_path_projection = compact_path_projection
        .checked_add(noncanonical_path_bytes)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC7 full-path reconstruction overflow",
        ))?;
    full_path_projection
        .checked_sub(noncanonical_path_bytes)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC7 compact-path projection underflow",
        ))
}

/// Project the exact maximum canonical SMC8 inner-wire bytes. This keeps the
/// q=20/open=6 SMZ9 sampling tuple and changes only the complete-SHA-512
/// commitment observation and fresh transcript/wire identities.
pub fn projected_poseidon2_v8_compact448_q20_inner_proof_bytes(
    statement: &(dyn SmallwoodConstraintAdapter + Sync),
) -> Result<usize, TransactionCircuitError> {
    ensure_poseidon2_v8_compact448_q20_profile(
        statement,
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let cfg = SmallwoodConfig::new_with_profile(
        statement,
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
    )?;
    let compact_path_projection = serialized_proof_size_hint_with_profile(
        &cfg,
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE,
        statement.auxiliary_witness_words().len(),
        SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
    )?;
    let depth = POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE
        .decs_nb_evals
        .ilog2() as usize;
    let opened_leaf_count =
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_opened_evals;
    let full_path_nodes = opened_leaf_count.checked_mul(depth).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood SMC8 full-path projection overflow",
        ),
    )?;
    let compact_nodes = maximum_smallwood_compact_authentication_nodes_v1(
        POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_evals,
        opened_leaf_count,
    )?;
    if compact_nodes != SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_COMPACT_AUTHENTICATION_NODES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC8 compact-auth protocol constant drift",
        ));
    }
    let noncanonical_path_bytes = full_path_nodes
        .checked_sub(compact_nodes)
        .and_then(|nodes| nodes.checked_mul(SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC8 compact-path projection overflow",
        ))?;
    let full_path_projection = compact_path_projection
        .checked_add(noncanonical_path_bytes)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC8 full-path reconstruction overflow",
        ))?;
    full_path_projection
        .checked_sub(noncanonical_path_bytes)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood SMC8 compact-path projection underflow",
        ))
}

pub fn ensure_no_packing_collisions(
    packing_points: &[u64],
    eval_points: &[u64],
) -> Result<(), TransactionCircuitError> {
    if !smallwood_piop_opening_points_are_valid(packing_points, eval_points) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood opening points must be canonical, distinct, outside the packing domain, and have a nonzero linear correction factor",
        ));
    }
    Ok(())
}

fn ensure_no_packing_collisions_for_profile(
    packing_points: &[u64],
    eval_points: &[u64],
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<(), TransactionCircuitError> {
    if !smallwood_piop_opening_points_are_valid_for_profile(packing_points, eval_points, profile) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood opening points violate the packing, linear-correction, or PCS-unstack admissibility predicate",
        ));
    }
    Ok(())
}

pub(crate) fn smallwood_piop_opening_points_are_valid(
    packing_points: &[u64],
    eval_points: &[u64],
) -> bool {
    smallwood_piop_linear_correction_factor(packing_points, eval_points)
        .is_some_and(|factor| factor != 0)
}

fn smallwood_piop_opening_points_are_valid_for_profile(
    packing_points: &[u64],
    eval_points: &[u64],
    profile: SmallwoodNoGrindingProfileV1,
) -> bool {
    smallwood_piop_opening_points_are_valid(packing_points, eval_points)
        && (!matches!(
            profile,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE
                | POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE
        ) || smallwood_smz9_pcs_unstack_blocks_v1(eval_points).is_some_and(|blocks| {
            blocks
                .iter()
                .flat_map(|block| block.iter().flatten())
                .all(|&coefficient| coefficient != 0)
        }))
}

/// Return the exact forty 6-by-6 blocks which carry the 240 SMZ9 PCS
/// unstacking coins into the serialized partial-evaluation view.
///
/// For coin index `t`, `pcs_commit` places the coin at row `64+t`.
/// The first six coins of each width-eight nonlinear polynomial are subtracted
/// at row `t`, while its final coin is subtracted at row `29+t`.  Each
/// width-two linear polynomial's coin is subtracted at row `1+t`.  At opening
/// `j` with point `r_j`, evaluation by `pcs_build_coefficients` therefore gives
/// the exact block entries
///
/// * `M[j,t] = r_j^t (r_j^64 - 1)` for each intermediate nonlinear role;
/// * `M[j,t] = r_j^(29+t) (r_j^35 - 1)` for a nonlinear-final role; and
/// * `M[j,t] = r_j^(1+t) (r_j^63 - 1)` for a linear role.
///
/// Each block is a nonzero row-diagonal scaling of the same Vandermonde
/// matrix.  There are five nonlinear polynomials with seven roles apiece and
/// five linear polynomials with one role apiece, for forty blocks and total
/// dimension 240.  Returning every block makes the accepted-proof audit check
/// the exact cross-opening map instead of copying an unrelated rank.
pub(crate) fn smallwood_smz9_pcs_unstack_blocks_v1(
    eval_points: &[u64],
) -> Option<Vec<Vec<Vec<u64>>>> {
    const NONLINEAR_POLYNOMIALS: usize = 5;
    const NONLINEAR_INTERMEDIATE_COINS: usize = 6;
    const LINEAR_POLYNOMIALS: usize = 5;
    const BLOCK_COUNT: usize =
        NONLINEAR_POLYNOMIALS * (NONLINEAR_INTERMEDIATE_COINS + 1) + LINEAR_POLYNOMIALS;

    if eval_points.len() != POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE.nb_opened_evals
        || eval_points.iter().any(|&point| point >= FIELD_ORDER)
    {
        return None;
    }
    let block = |base_power: u64, gap: u64| {
        eval_points
            .iter()
            .map(|&point| {
                let row_factor = sub_mod(pow_mod(point, gap), 1);
                (0..eval_points.len())
                    .map(|coin_index| {
                        mul_mod(pow_mod(point, base_power + coin_index as u64), row_factor)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };
    let mut blocks = Vec::with_capacity(BLOCK_COUNT);
    for _ in 0..NONLINEAR_POLYNOMIALS {
        for _ in 0..NONLINEAR_INTERMEDIATE_COINS {
            blocks.push(block(0, 64));
        }
        blocks.push(block(29, 35));
    }
    for _ in 0..LINEAR_POLYNOMIALS {
        blocks.push(block(1, 63));
    }
    (blocks.len() == BLOCK_COUNT).then_some(blocks)
}

/// Compute the exact correction factor used by the linear PIOP verifier.
///
/// The verifier restores the linear mask at the opening points together with
/// an extra value at zero.  It then adjusts the coefficient of the Lagrange
/// basis polynomial belonging to zero so that the restored polynomial has the
/// required sum over the packing domain.  That adjustment is defined only
/// when
///
///     sum_{x in packing_points} prod_r (x - r) / prod_r (0 - r)
///
/// is nonzero.  The historical nonce selector checked only that the `r` were
/// distinct and outside the packing domain, so it could accept an honest
/// prover view which this verifier later rejected.  Keeping this calculation
/// in one helper makes prover nonce selection and verifier canonicalization
/// use the identical admissibility predicate.
pub(crate) fn smallwood_piop_linear_correction_factor(
    packing_points: &[u64],
    eval_points: &[u64],
) -> Option<u64> {
    if packing_points.is_empty()
        || eval_points.is_empty()
        || packing_points
            .iter()
            .enumerate()
            .any(|(index, point)| *point >= FIELD_ORDER || packing_points[..index].contains(point))
        || eval_points.iter().enumerate().any(|(index, point)| {
            *point == 0
                || *point >= FIELD_ORDER
                || packing_points.contains(point)
                || eval_points[..index].contains(point)
        })
    {
        return None;
    }

    let denominator = eval_points
        .iter()
        .fold(1u64, |product, point| mul_mod(product, neg_mod(*point)));
    let denominator_inverse = inv_mod(denominator).ok()?;
    let numerator_sum = packing_points.iter().fold(0u64, |sum, packing| {
        let numerator = eval_points.iter().fold(1u64, |product, opening| {
            mul_mod(product, sub_mod(*packing, *opening))
        });
        add_mod(sum, numerator)
    });
    Some(mul_mod(numerator_sum, denominator_inverse))
}

pub fn xof_piop_opening_points(
    nonce: &[u8; NONCE_BYTES],
    h_piop: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<u64> {
    xof_piop_opening_points_for_profile(
        nonce,
        h_piop,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
        transcript_backend,
    )
}

fn xof_piop_opening_points_for_profile(
    nonce: &[u8; NONCE_BYTES],
    h_piop: &[u8; DIGEST_BYTES],
    profile: SmallwoodNoGrindingProfileV1,
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<u64> {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        return with_smallwood_hx512_transcript_driver(|driver| {
            driver.record_failure(
                TransactionCircuitError::ConstraintViolation(
                    "HX512 opening points must be consumed directly by the exact stage-six driver",
                ),
                vec![0u64; profile.nb_opened_evals],
            )
        })
        .unwrap_or_else(|_| vec![0u64; profile.nb_opened_evals]);
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512V6 {
        if profile.nb_opened_evals != SHA512_V6_SMZ2_PIOP_OPENING_COUNT {
            panic!("Smallwood Sha512V6 requires exactly five PIOP opening points");
        }
        let nonce_value = u32::from_le_bytes(*nonce);
        return with_smallwood_v6_transcript(|v6| {
            v6.piop_opening_points_for_nonce(nonce_value, h_piop)
                .map(|points| points.to_vec())
                .map_err(smallwood_v6_error)
        })
        .unwrap_or_else(|error| panic!("Smallwood V6 opening-point request failed: {error}"))
        .unwrap_or_else(|error| panic!("Smallwood V6 opening-point request failed: {error}"));
    }
    let mut input = Vec::with_capacity(1 + DIGEST_WORDS);
    input.push(u32::from_le_bytes(*nonce) as u64);
    input.extend(digest_to_words(h_piop, transcript_backend));
    transcript_xof_words(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_PIOP_OPENING_DOMAIN),
        &input,
        profile.nb_opened_evals,
    )
}

pub fn xof_decs_opening(
    nb_evals: usize,
    nb_opened_evals: usize,
    pow_bits: u32,
    trans_hash: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<(Vec<u32>, [u8; NONCE_BYTES]), TransactionCircuitError> {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        if nb_evals != HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals
            || nb_opened_evals != HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals
            || pow_bits != 0
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "HX512 requires the exact 2^20/q48/no-grinding DECS profile",
            ));
        }
        let indexes = with_smallwood_hx512_transcript_driver(|driver| {
            driver.sample_decs_queries(nb_opened_evals, nb_evals, trans_hash)
        })??;
        return Ok((indexes, [0u8; NONCE_BYTES]));
    }
    if transcript_backend == SmallwoodTranscriptBackend::Sha512V6 {
        if nb_evals != SHA512_V6_SMZ2_DECS_DOMAIN_SIZE
            || nb_opened_evals != SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1
            || pow_bits != 0
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood Sha512V6 requires the exact 2^20/23/no-grinding DECS profile",
            ));
        }
        let challenge = with_smallwood_v6_transcript(|v6| {
            v6.derive_decs_opening_challenge(trans_hash)
                .map_err(smallwood_v6_error)
        })??;
        return Ok((challenge.leaf_indexes.to_vec(), challenge.nonce));
    }
    if transcript_backend.is_sha512_level5() {
        return xof_decs_opening_fixed_no_grinding(
            nb_evals,
            nb_opened_evals,
            pow_bits,
            trans_hash,
            transcript_backend,
        );
    }
    let log2_order = 63.999999f64;
    let log2_nb_evals = (nb_evals as f64).log2();
    let maxi = ((log2_order / log2_nb_evals) - 0.001).floor() as usize;
    let mut delta_opening_size = 0usize;
    loop {
        let opening_challenge_size = nb_opened_evals.div_ceil(maxi) + delta_opening_size;
        let min_queries = nb_opened_evals / opening_challenge_size;
        let max_queries = nb_opened_evals.div_ceil(opening_challenge_size);
        let nb_at_max = nb_opened_evals % opening_challenge_size;
        let mut nb_queries = vec![0usize; opening_challenge_size];
        let mut additional_bits = vec![0u32; opening_challenge_size];
        let mut current_w = 0f64;
        for i in 0..opening_challenge_size {
            nb_queries[i] = if i < nb_at_max {
                max_queries
            } else {
                min_queries
            };
            let exact = log2_order - (nb_queries[i] as f64) * log2_nb_evals;
            additional_bits[i] = exact.floor() as u32;
            current_w += exact - additional_bits[i] as f64;
        }
        let mut ind = 0usize;
        let mut can_continue = true;
        while current_w < pow_bits as f64 {
            let missing = (pow_bits as f64 - current_w).floor() as u32;
            let add_w = missing.min(additional_bits[ind]);
            current_w += add_w as f64;
            additional_bits[ind] -= add_w;
            ind += 1;
            if current_w < pow_bits as f64 && ind >= opening_challenge_size {
                can_continue = false;
                delta_opening_size += 1;
                break;
            }
        }
        if !can_continue {
            continue;
        }
        let mut max_keep = vec![0u64; opening_challenge_size];
        let mut acc = nb_evals as u64;
        for _ in 1..min_queries {
            acc = mul_mod(acc, nb_evals as u64);
        }
        for i in nb_at_max..opening_challenge_size {
            let mut value = acc;
            value = (value << additional_bits[i]) % FIELD_ORDER;
            max_keep[i] = if value == 0 {
                FIELD_ORDER - 1
            } else {
                value - 1
            };
        }
        if nb_at_max > 0 {
            acc = mul_mod(acc, nb_evals as u64);
            for i in 0..nb_at_max {
                let mut value = acc;
                value = (value << additional_bits[i]) % FIELD_ORDER;
                max_keep[i] = if value == 0 {
                    FIELD_ORDER - 1
                } else {
                    value - 1
                };
            }
        }
        let mut nonce_counter = 0u32;
        loop {
            if transcript_backend.is_sha512_level5()
                && nonce_counter >= SMALLWOOD_LEVEL5_MAX_DECS_NONCE_TRIALS
            {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "smallwood Level-5 DECS nonce trial limit exhausted",
                ));
            }
            update_verifier_operation_profile_v1(|operation_profile| {
                operation_profile.decs_nonce_trials += 1;
            });
            let nonce = nonce_counter.to_le_bytes();
            let mut input = Vec::with_capacity(1 + DIGEST_WORDS);
            input.push(u32::from_le_bytes(nonce) as u64);
            input.extend(digest_to_words(trans_hash, transcript_backend));
            let lhash_output = transcript_xof_words(
                transcript_backend,
                transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_DECS_QUERY_DOMAIN),
                &input,
                opening_challenge_size,
            );
            if lhash_output
                .iter()
                .zip(max_keep.iter())
                .all(|(&value, &limit)| value <= limit)
            {
                let mut leaves_indexes = vec![0u32; nb_opened_evals];
                let mut ind = 0usize;
                for i in 0..opening_challenge_size {
                    let mut value = lhash_output[i];
                    for _ in 0..nb_queries[i] {
                        leaves_indexes[ind] = (value % nb_evals as u64) as u32;
                        value /= nb_evals as u64;
                        ind += 1;
                    }
                }
                leaves_indexes.sort_unstable();
                if leaves_indexes.windows(2).all(|pair| pair[0] != pair[1]) {
                    return Ok((leaves_indexes, nonce));
                }
            }
            nonce_counter = nonce_counter.checked_add(1).ok_or(
                TransactionCircuitError::ConstraintViolation(
                    "smallwood decs opening nonce overflow",
                ),
            )?;
        }
    }
}

/// Fixed-work, no-grinding DECS sampling selected by the Level-5 transcript.
///
/// Goldilocks has residue one modulo every power of two through 2^32. Rejecting
/// the single top residue therefore makes reduction into the 2^k DECS domain
/// exact. Taking the first distinct values from an IID uniform stream yields an
/// ordered uniform sample without replacement. Forty candidates leave 20 spare
/// draws for the active 20-query profile and make sampler exhaustion less than
/// 2^-128 without allowing the prover to select a nonce.
pub fn xof_decs_opening_fixed_no_grinding(
    nb_evals: usize,
    nb_opened_evals: usize,
    pow_bits: u32,
    trans_hash: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Result<(Vec<u32>, [u8; NONCE_BYTES]), TransactionCircuitError> {
    if !nb_evals.is_power_of_two() || nb_evals > u32::MAX as usize {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fixed DECS domain must be a power of two fitting u32",
        ));
    }
    if nb_opened_evals == 0 || nb_opened_evals > SMALLWOOD_LEVEL5_FIXED_DECS_CANDIDATE_COUNT {
        return Err(TransactionCircuitError::ConstraintViolation(
            "DECS opening count exceeds the fixed sampler",
        ));
    }
    if pow_bits != 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fixed DECS sampling forbids grinding bits",
        ));
    }

    update_verifier_operation_profile_v1(|operation_profile| {
        operation_profile.decs_nonce_trials += 1;
    });
    let mut input = Vec::with_capacity(DIGEST_WORDS);
    input.extend(digest_to_words(trans_hash, transcript_backend));
    let candidates = transcript_xof_words(
        transcript_backend,
        SMALLWOOD_LEVEL5_FIXED_DECS_DOMAIN,
        &input,
        SMALLWOOD_LEVEL5_FIXED_DECS_CANDIDATE_COUNT,
    );

    let modulus_multiple = (FIELD_ORDER / nb_evals as u64) * nb_evals as u64;
    let mut seen = std::collections::BTreeSet::new();
    let mut leaves_indexes = Vec::with_capacity(nb_opened_evals);
    for candidate in candidates {
        if candidate >= modulus_multiple {
            continue;
        }
        let index = (candidate % nb_evals as u64) as u32;
        if seen.insert(index) {
            leaves_indexes.push(index);
            if leaves_indexes.len() == nb_opened_evals {
                break;
            }
        }
    }
    if leaves_indexes.len() != nb_opened_evals {
        return Err(TransactionCircuitError::ConstraintViolation(
            "fixed DECS sampler exhausted its candidate pool",
        ));
    }
    leaves_indexes.sort_unstable();
    Ok((leaves_indexes, [0u8; NONCE_BYTES]))
}

fn bytes_to_words(bytes: &[u8]) -> Result<Vec<u64>, TransactionCircuitError> {
    if !bytes.len().is_multiple_of(8) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood binded_data must be padded to 8-byte words",
        ));
    }
    Ok(bytes_to_words_unchecked(bytes))
}

fn bytes_to_words_unchecked(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            u64::from_le_bytes(buf)
        })
        .collect()
}

fn digest_to_words(
    bytes: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> Vec<u64> {
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        return bytes
            .chunks_exact(8)
            .map(|chunk| {
                let mut word = [0u8; 8];
                word.copy_from_slice(chunk);
                u64::from_be_bytes(word)
            })
            .collect();
    }
    bytes_to_words_unchecked(&bytes[..transcript_backend.digest_bytes()])
}

fn words_to_digest(words: &[u64]) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    for (idx, word) in words.iter().enumerate().take(DIGEST_WORDS) {
        out[idx * 8..(idx + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn merkle_build_levels(
    levels: &mut Vec<Vec<[u8; DIGEST_BYTES]>>,
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    let mut level_idx = 0usize;
    while levels[level_idx].len() > 1 {
        let current = &levels[level_idx];
        let parents = if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
            current
                .chunks_exact(2)
                .enumerate()
                .map(|(node_index, children)| {
                    hash_merkle_children_at(
                        &children[0],
                        &children[1],
                        level_idx,
                        node_index,
                        transcript_backend,
                    )
                })
                .collect()
        } else if transcript_backend == SmallwoodTranscriptBackend::Sha512V6 {
            current
                .chunks(2)
                .map(|children| hash_merkle_chunk(children, transcript_backend))
                .collect()
        } else {
            current
                .par_chunks(2)
                .map(|children| hash_merkle_chunk(children, transcript_backend))
                .collect()
        };
        levels.push(parents);
        level_idx += 1;
    }
    levels[level_idx][0]
}

fn hash_merkle_chunk(
    children: &[[u8; DIGEST_BYTES]],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    debug_assert!(!children.is_empty());
    debug_assert!(children.len() <= 2);
    if children.len() == 2 {
        return hash_merkle_children(&children[0], &children[1], transcript_backend);
    }
    if transcript_backend == SmallwoodTranscriptBackend::Blake3 {
        let mut hasher = Hasher::new();
        hasher.update(SMALLWOOD_XOF_DOMAIN);
        hasher.update(&(LEGACY_DIGEST_WORDS as u64).to_le_bytes());
        hasher.update(&children[0][..LEGACY_DIGEST_BYTES]);
        return read_blake3_xof_digest(hasher.finalize_xof());
    }
    let input = digest_to_words(&children[0], transcript_backend);
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_MERKLE_NODE_DOMAIN),
        &input,
    )
}

fn hash_merkle_children(
    left: &[u8; DIGEST_BYTES],
    right: &[u8; DIGEST_BYTES],
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    hash_merkle_children_at(left, right, 0, 0, transcript_backend)
}

fn hash_merkle_children_at(
    left: &[u8; DIGEST_BYTES],
    right: &[u8; DIGEST_BYTES],
    level: usize,
    node_index: usize,
    transcript_backend: SmallwoodTranscriptBackend,
) -> [u8; DIGEST_BYTES] {
    update_verifier_operation_profile_v1(|profile| {
        profile.merkle_internal_hashes += 1;
    });
    if transcript_backend == SmallwoodTranscriptBackend::Hx512Candidate {
        return hx512_capture_digest(|driver| driver.hash_node(level, node_index, left, right));
    }
    if transcript_backend == SmallwoodTranscriptBackend::Blake3 {
        let mut hasher = Hasher::new();
        hasher.update(SMALLWOOD_XOF_DOMAIN);
        hasher.update(&((2 * LEGACY_DIGEST_WORDS) as u64).to_le_bytes());
        hasher.update(&left[..LEGACY_DIGEST_BYTES]);
        hasher.update(&right[..LEGACY_DIGEST_BYTES]);
        return read_blake3_xof_digest(hasher.finalize_xof());
    }
    let mut input = Vec::with_capacity(2 * transcript_backend.digest_words());
    input.extend(digest_to_words(left, transcript_backend));
    input.extend(digest_to_words(right, transcript_backend));
    transcript_xof_digest(
        transcript_backend,
        transcript_domain(transcript_backend, SMALLWOOD_LEVEL5_MERKLE_NODE_DOMAIN),
        &input,
    )
}

fn compact_merkle_auth_paths(
    levels: &[Vec<[u8; DIGEST_BYTES]>],
    indices: &[usize],
) -> Vec<Vec<[u8; DIGEST_BYTES]>> {
    let mut paths = vec![Vec::new(); indices.len()];
    let mut current_indices = indices.to_vec();
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let level_opened = current_indices
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        for (path_idx, &index) in current_indices.iter().enumerate() {
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            if !level_opened.contains(&sibling) {
                paths[path_idx].push(level[sibling]);
            }
        }
        for index in &mut current_indices {
            *index /= 2;
        }
    }
    paths
}

fn expected_compact_merkle_auth_path_lengths(indices: &[usize], depth: usize) -> Vec<usize> {
    let mut lengths = vec![0usize; indices.len()];
    let mut current_indices = indices.to_vec();
    for _ in 0..depth {
        let level_opened = current_indices
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        for (path_idx, &index) in current_indices.iter().enumerate() {
            let sibling = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            if !level_opened.contains(&sibling) {
                lengths[path_idx] += 1;
            }
        }
        for index in &mut current_indices {
            *index /= 2;
        }
    }
    lengths
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::hashing_pq::{felts_to_bytes48, merkle_node, spend_auth_key_bytes, Felt};
    use crate::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use crate::proof::decode_transaction_proof_bytes_exact;
    use crate::public_inputs::StablecoinPolicyBinding;
    use crate::smallwood_frontend::{
        build_packed_smallwood_bridge_material_from_witness,
        build_packed_smallwood_frontend_material_from_witness,
        build_production_smallwood_frontend_material_from_witness,
        decode_smallwood_candidate_proof_for_version, encode_smallwood_candidate_proof,
        prove_smallwood_candidate_with_arithmetization,
        verify_smallwood_candidate_transaction_proof, PackedSmallwoodAuxFrontendMaterial,
        SmallwoodCandidateProof, SMALLWOOD_BRIDGE_PACKING_FACTOR,
        SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    };
    use crate::smallwood_semantics::{
        PackedStatement, SmallwoodLinearConstraintForm, SmallwoodNonlinearEvalView,
    };
    use crate::witness::TransactionWitness;
    use proptest::{collection::vec, prelude::*};
    use protocol_versioning::{TxProofBackend, SMALLWOOD_CANDIDATE_VERSION_BINDING};
    use std::sync::OnceLock;

    fn hx512_codec_test_geometry() -> SmallwoodCoreGeometryV1 {
        SmallwoodCoreGeometryV1 {
            row_count: 1,
            packing_factor: HX512_SMALLWOOD_PACKING_FACTOR_V1,
            constraint_degree: HX512_SMALLWOOD_MAX_CONSTRAINT_DEGREE_V1,
            nonlinear_constraint_count: 1,
            linear_constraint_count: 1,
            witness_poly_degree: HX512_SMALLWOOD_WITNESS_POLYNOMIAL_DEGREE_V1,
            mpol_poly_degree: HX512_SMALLWOOD_MPOL_POLYNOMIAL_DEGREE_V1,
            mlin_poly_degree: HX512_SMALLWOOD_LINEAR_POLYNOMIAL_DEGREE_V1,
            nb_polys: 1,
            nb_unstacked_rows: 1,
            nb_unstacked_cols: 1,
            nb_lvcs_rows: 1,
            nb_lvcs_cols: 1,
            nb_lvcs_opened_combi: 1,
            interpolation_point_count: 1,
            coset_shift: 2,
            coset_generator: 3,
            ppol_high_rows: 1,
            ppol_high_cols: 1,
            plin_high_rows: 1,
            plin_high_cols: 1,
            rcombi_rows: 1,
            rcombi_cols: 1,
            subset_rows: 1,
            subset_cols: 1,
            partial_rows: 1,
            partial_cols: 1,
            masking_rows: HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals,
            masking_cols: 1,
            high_rows: 1,
            high_cols: 1,
            opened_witness_rows: 1,
            opened_witness_cols: 1,
            auxiliary_word_count: 0,
        }
    }

    fn hx512_codec_test_proof() -> SmallwoodProof {
        let q = HX512_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals;
        SmallwoodProof {
            wire_identity: SmallwoodProofWireIdentityV1::FreshHx512Candidate,
            digest_bytes: DIGEST_BYTES,
            strict_zk_decs_leaf_hiding: true,
            hx512_decs_root: Some([0x11; DIGEST_BYTES]),
            hx512_piop_input_digest: Some([0x22; DIGEST_BYTES]),
            salt: vec![0x33; HX512_SALT_BYTES],
            nonce: [0; NONCE_BYTES],
            h_piop: [0x44; DIGEST_BYTES],
            piop: PiopProof {
                ppol_highs: vec![vec![1]],
                plin_highs: vec![vec![2]],
            },
            pcs: PcsProof {
                rcombi_tails: vec![vec![3]],
                subset_evals: vec![vec![4]],
                partial_evals: vec![vec![5]],
                decs: DecsProof {
                    auth_paths: vec![vec![[0x55; DIGEST_BYTES]]; q],
                    leaf_tapes: vec![vec![0x66; HX512_PROFILE_LEAF_TAPE_BYTES]; q],
                    masking_evals: vec![vec![6]; q],
                    high_coeffs: vec![vec![7]],
                },
            },
            opened_witness: SmallwoodOpenedWitnessBundle::row_scalars(vec![vec![8]], Vec::new(), 0),
        }
    }

    #[test]
    fn hx512_core_codec_is_fresh_big_endian_and_exact() {
        let geometry = hx512_codec_test_geometry();
        let proof = hx512_codec_test_proof();
        let encoded = encode_smallwood_hx512_core_payload(&proof, &geometry).unwrap();
        assert_eq!(&encoded[..64], &[0x11; 64]);
        assert_eq!(&encoded[64..128], &[0x22; 64]);
        assert_eq!(&encoded[128..192], &[0x44; 64]);
        assert_eq!(&encoded[192..196], &1u32.to_be_bytes());
        assert_eq!(&encoded[196..200], &1u32.to_be_bytes());
        assert_eq!(&encoded[200..208], &1u64.to_be_bytes());

        let salt = [0x33; HX512_SALT_BYTES];
        let decoded =
            decode_smallwood_hx512_core_payload(&encoded, &salt, &geometry, encoded.len()).unwrap();
        assert_eq!(
            encode_smallwood_hx512_core_payload(&decoded, &geometry).unwrap(),
            encoded
        );
        assert_eq!(decoded.nonce, [0; NONCE_BYTES]);
    }

    #[test]
    fn hx512_core_codec_caps_before_shapes_and_rejects_aliases() {
        let geometry = hx512_codec_test_geometry();
        let proof = hx512_codec_test_proof();
        let encoded = encode_smallwood_hx512_core_payload(&proof, &geometry).unwrap();
        let salt = [0x33; HX512_SALT_BYTES];

        assert!(
            decode_smallwood_hx512_core_payload(&encoded, &salt, &geometry, encoded.len() - 1,)
                .is_err()
        );

        let mut wrong_dimension = encoded.clone();
        wrong_dimension[195] = 2;
        assert!(decode_smallwood_hx512_core_payload(
            &wrong_dimension,
            &salt,
            &geometry,
            wrong_dimension.len(),
        )
        .is_err());

        let mut noncanonical_field = encoded.clone();
        noncanonical_field[200..208].copy_from_slice(&FIELD_ORDER.to_be_bytes());
        assert!(decode_smallwood_hx512_core_payload(
            &noncanonical_field,
            &salt,
            &geometry,
            noncanonical_field.len(),
        )
        .is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(
            decode_smallwood_hx512_core_payload(&trailing, &salt, &geometry, trailing.len(),)
                .is_err()
        );
    }

    #[test]
    fn hx512_field_message_preserves_digest_bytes_exactly() {
        let digest: [u8; DIGEST_BYTES] = core::array::from_fn(|index| index as u8);
        let words = digest_to_words(&digest, SmallwoodTranscriptBackend::Hx512Candidate);
        let message = encode_smallwood_hx512_field_message(&words);
        assert_eq!(&message[..8], &(DIGEST_WORDS as u64).to_be_bytes());
        assert_eq!(&message[8..], &digest);
    }

    fn transcript_xof_words_blake3_reference(
        domain: &[u8],
        words: &[u64],
        out_words: usize,
    ) -> Vec<u64> {
        if out_words == 4 && words.len() <= 8 && domain == SMALLWOOD_COMPRESS2_DOMAIN {
            let mut padded = [0u64; 8];
            for (idx, word) in words.iter().enumerate() {
                padded[idx] = *word;
            }
            let mut hasher = Hasher::new();
            hasher.update(SMALLWOOD_COMPRESS2_DOMAIN);
            hasher.update(&(padded.len() as u64).to_le_bytes());
            for word in &padded {
                hasher.update(&word.to_le_bytes());
            }
            let mut reader = hasher.finalize_xof();
            let mut out = vec![0u64; 4];
            for slot in &mut out {
                let mut buf = [0u8; 16];
                reader.fill(&mut buf);
                *slot = (u128::from_le_bytes(buf) % FIELD_ORDER as u128) as u64;
            }
            return out;
        }
        let mut hasher = Hasher::new();
        hasher.update(domain);
        hasher.update(&(words.len() as u64).to_le_bytes());
        for word in words {
            hasher.update(&word.to_le_bytes());
        }
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u64; out_words];
        for slot in &mut out {
            let mut buf = [0u8; 16];
            reader.fill(&mut buf);
            *slot = (u128::from_le_bytes(buf) % FIELD_ORDER as u128) as u64;
        }
        out
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct LegacySmallwoodCandidateProofForTest {
        #[serde(default = "default_bridge_smallwood_arithmetization_for_test")]
        arithmetization: SmallwoodArithmetization,
        ark_proof: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanSmallwoodProofWireVectors {
        schema_version: u32,
        cases: Vec<LeanSmallwoodProofWireCase>,
        active_artifact_cases: Vec<LeanSmallwoodActiveArtifactCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanSmallwoodProofWireCase {
        name: String,
        proof_hex: String,
        accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    struct LeanSmallwoodActiveArtifactCase {
        name: String,
        artifact_hex: String,
        accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    struct LeanSmallwoodSmz8ProofWireVectors {
        schema_version: u32,
        profile: LeanSmallwoodSmz8ProofWireProfile,
        cases: Vec<LeanSmallwoodProofWireCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanSmallwoodSmz8ProofWireProfile {
        magic_ascii: String,
        opened_leaf_count: usize,
        opened_leaf_tape_bytes: usize,
        opened_leaf_tapes_bytes: usize,
        maximum_auth_path_depth: usize,
        maximum_inner_proof_bytes: usize,
    }

    #[derive(Debug, Deserialize)]
    struct LeanSmallwoodSmz9ProofWireVectors {
        schema_version: u32,
        profile: LeanSmallwoodSmz9ProofWireProfile,
        cases: Vec<LeanSmallwoodProofWireCase>,
    }

    #[derive(Debug, Deserialize)]
    struct LeanSmallwoodSmz9ProofWireProfile {
        magic_ascii: String,
        opened_leaf_count: usize,
        opened_leaf_tape_bytes: usize,
        opened_leaf_tapes_bytes: usize,
        maximum_auth_path_depth: usize,
        maximum_compact_authentication_nodes: usize,
        opened_witness_mode: u8,
        auxiliary_word_count: usize,
        auxiliary_limb_count: usize,
        maximum_inner_proof_bytes: usize,
    }

    fn decode_wire_hex(value: &str) -> Vec<u8> {
        let hex = value
            .strip_prefix("0x")
            .unwrap_or_else(|| panic!("hex string missing 0x prefix: {value}"));
        assert_eq!(hex.len() % 2, 0, "hex string has an odd length");
        (0..hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&hex[index..index + 2], 16)
                    .unwrap_or_else(|err| panic!("invalid hex byte in {value}: {err}"))
            })
            .collect()
    }

    #[test]
    fn lean_generated_smallwood_proof_wire_vectors_match_production_parser() {
        let vectors: LeanSmallwoodProofWireVectors = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/formal_crypto_vectors/smallwood_proof_wire.json"
        )))
        .expect("parse Lean SmallWood proof-wire vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(!vectors.cases.is_empty(), "proof-wire vectors are empty");

        for case in vectors.cases {
            let bytes = decode_wire_hex(&case.proof_hex);
            let decoded = decode_smallwood_proof_bytes_v1(&bytes);
            assert_eq!(
                decoded.is_ok(),
                case.accepted,
                "{}: Rust parser disagreed with Lean",
                case.name
            );
            if let Ok(proof) = decoded {
                assert_eq!(
                    encode_smallwood_proof_bytes_v1(&proof)
                        .expect("re-encode accepted SmallWood proof"),
                    bytes,
                    "{}: accepted proof did not re-encode canonically",
                    case.name
                );
            }
        }

        assert!(
            !vectors.active_artifact_cases.is_empty(),
            "active proof-artifact parser vectors are empty"
        );
        for case in vectors.active_artifact_cases {
            let bytes = decode_wire_hex(&case.artifact_hex);
            assert_eq!(
                production_active_smallwood_artifact_parser_accepts(&bytes),
                case.accepted,
                "{}: Rust accepted-path parser disagreed with Lean",
                case.name
            );
        }
    }

    #[test]
    fn lean_generated_smz8_proof_wire_vectors_match_production_parser() {
        let vectors: LeanSmallwoodSmz8ProofWireVectors =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/formal_crypto_vectors/smallwood_smz8_proof_wire.json"
            )))
            .expect("parse Lean SmallWood SMZ8 proof-wire vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(vectors.profile.magic_ascii.as_bytes(), b"SMZ8");
        assert_eq!(
            vectors.profile.opened_leaf_count,
            SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT
        );
        assert_eq!(
            vectors.profile.opened_leaf_tape_bytes,
            SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES
        );
        assert_eq!(
            vectors.profile.opened_leaf_tapes_bytes,
            SMALLWOOD_POSEIDON2_V8_DECS_OPENED_TAPE_BYTES
        );
        assert_eq!(vectors.profile.maximum_auth_path_depth, 23);
        assert_eq!(
            vectors.profile.maximum_inner_proof_bytes,
            SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES
        );
        assert!(
            !vectors.cases.is_empty(),
            "SMZ8 proof-wire vectors are empty"
        );

        for case in vectors.cases {
            let bytes = decode_wire_hex(&case.proof_hex);
            let decoded = decode_smallwood_proof_bytes_v1(&bytes);
            assert_eq!(
                decoded.is_ok(),
                case.accepted,
                "{}: Rust SMZ8 parser disagreed with Lean",
                case.name
            );
            if let Ok(proof) = decoded {
                assert_eq!(
                    proof.wire_identity,
                    SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8,
                    "{}: accepted vector used a non-SMZ8 identity",
                    case.name
                );
                assert_eq!(
                    proof.pcs.decs.auth_paths.len(),
                    SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT
                );
                assert!(proof
                    .pcs
                    .decs
                    .auth_paths
                    .iter()
                    .all(|path| path.len() <= vectors.profile.maximum_auth_path_depth));
                assert_eq!(
                    proof.pcs.decs.leaf_tapes.len(),
                    SMALLWOOD_POSEIDON2_V8_DECS_OPENED_LEAF_COUNT
                );
                assert!(proof
                    .pcs
                    .decs
                    .leaf_tapes
                    .iter()
                    .all(|tape| tape.len() == SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES));
                assert_eq!(
                    encode_smallwood_proof_bytes_v1(&proof).expect("re-encode accepted SMZ8 proof"),
                    bytes,
                    "{}: accepted SMZ8 proof did not re-encode canonically",
                    case.name
                );
            }
        }
    }

    #[test]
    fn lean_generated_smz9_proof_wire_vectors_match_production_parser() {
        let vectors: LeanSmallwoodSmz9ProofWireVectors =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/formal_crypto_vectors/smallwood_smz9_proof_wire.json"
            )))
            .expect("parse Lean SmallWood SMZ9 proof-wire vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(vectors.profile.magic_ascii.as_bytes(), b"SMZ9");
        assert_eq!(
            vectors.profile.opened_leaf_count,
            SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT,
        );
        assert_eq!(
            vectors.profile.opened_leaf_tape_bytes,
            SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
        );
        assert_eq!(
            vectors.profile.opened_leaf_tapes_bytes,
            SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_TAPE_BYTES,
        );
        assert_eq!(vectors.profile.maximum_auth_path_depth, 23);
        assert_eq!(
            vectors.profile.maximum_compact_authentication_nodes,
            SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES,
        );
        assert_eq!(vectors.profile.opened_witness_mode, 1);
        assert_eq!(vectors.profile.auxiliary_word_count, 0);
        assert_eq!(vectors.profile.auxiliary_limb_count, 0);
        assert_eq!(
            vectors.profile.maximum_inner_proof_bytes,
            SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES,
        );
        assert!(
            !vectors.cases.is_empty(),
            "SMZ9 proof-wire vectors are empty"
        );

        for case in vectors.cases {
            let bytes = decode_wire_hex(&case.proof_hex);
            let decoded = decode_smallwood_proof_bytes_v1(&bytes);
            assert_eq!(
                decoded.is_ok(),
                case.accepted,
                "{}: Rust SMZ9 parser disagreed with Lean",
                case.name,
            );
            if let Ok(proof) = decoded {
                assert_eq!(
                    proof.wire_identity,
                    SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9,
                    "{}: accepted vector used a non-SMZ9 identity",
                    case.name,
                );
                assert_eq!(
                    proof.pcs.decs.auth_paths.len(),
                    SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT,
                );
                assert!(proof
                    .pcs
                    .decs
                    .auth_paths
                    .iter()
                    .all(|path| path.len() <= vectors.profile.maximum_auth_path_depth));
                assert_eq!(
                    proof.pcs.decs.leaf_tapes.len(),
                    SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_LEAF_COUNT,
                );
                assert!(proof
                    .pcs
                    .decs
                    .leaf_tapes
                    .iter()
                    .all(|tape| tape.len() == SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES));
                assert_eq!(
                    encode_smallwood_proof_bytes_v1(&proof).expect("re-encode accepted SMZ9 proof"),
                    bytes,
                    "{}: accepted SMZ9 proof did not re-encode canonically",
                    case.name,
                );
            }
        }
    }

    fn production_active_smallwood_artifact_parser_accepts(bytes: &[u8]) -> bool {
        let Ok(wrapper) = decode_transaction_proof_bytes_exact(bytes) else {
            return false;
        };
        if wrapper.version_binding() != SMALLWOOD_CANDIDATE_VERSION_BINDING
            || wrapper.backend != TxProofBackend::SmallwoodCandidate
            || wrapper.stark_public_inputs.is_none()
        {
            return false;
        }
        let Ok(candidate) = decode_smallwood_candidate_proof_for_version(
            &wrapper.stark_proof,
            wrapper.version_binding(),
        ) else {
            return false;
        };
        candidate.arithmetization == SmallwoodArithmetization::DirectPacked64CompressedLevel5
            && decode_smallwood_proof_bytes_v1(&candidate.ark_proof).is_ok()
    }

    #[test]
    fn proof_wire_encoder_rejects_noncanonical_structures() {
        let mut out = Vec::new();
        assert!(encode_matrix_u64_v1(&mut out, &[Vec::new()]).is_err());
        assert!(encode_matrix_u64_v1(
            &mut out,
            &vec![vec![0u64]; MAX_SMALLWOOD_COMPACT_COLLECTION_ROWS_V1 + 1],
        )
        .is_err());
        assert!(encode_matrix_u64_v1(&mut out, &[vec![FIELD_ORDER]]).is_err());
        assert!(encode_auth_paths_v1(&mut out, &[Vec::new()], LEGACY_DIGEST_BYTES).is_err());
        assert!(encode_opened_witness_v1(
            &mut out,
            &SmallwoodOpenedWitnessBundle::row_scalars(Vec::new(), Vec::new(), 1),
        )
        .is_err());
    }

    fn synthetic_hx512_rng_budget_v1() -> SmallwoodHx512RngBudgetV1 {
        SmallwoodHx512RngBudgetV1 {
            accepted_field_words: 3,
            accepted_field_bytes: 24,
            field_candidate_limit: 259,
            maximum_field_candidate_bytes: 2_072,
            field_rejection_budget: 256,
            field_request_count: 2,
            minimum_field_rng_calls: 2,
            maximum_field_rng_calls: 258,
            decs_leaf_tape_count: 1,
            decs_leaf_tape_bytes_each: 72,
            decs_leaf_tape_bytes_total: 72,
            decs_leaf_tape_rng_calls: 1,
            global_salt_bytes: 64,
            global_salt_rng_calls: 1,
            minimum_total_getrandom_fill_calls: 4,
            maximum_total_getrandom_fill_calls: 260,
            minimum_total_getrandom_fill_bytes: 160,
            maximum_total_getrandom_fill_bytes: 2_208,
            internal_outer_retry_count: 0,
            salt_collision_entropy_bits: 512,
            salt_reuse_registry_authority: false,
            getrandom_fill_failure_is_fatal: true,
        }
    }

    #[test]
    fn hx512_rng_session_enforces_exact_request_order_and_terminal_consumption() {
        let budget = synthetic_hx512_rng_budget_v1();
        let guard = enter_smallwood_hx512_rng_session_v1(
            VecDeque::from([2usize, 1]),
            VecDeque::from([72usize]),
            budget,
        )
        .expect("install synthetic HX512 RNG session");
        assert!(
            smallwood_hx512_register_field_rng_request_v1(2).expect("consume first field request")
        );
        smallwood_hx512_register_field_candidates_v1(2).expect("consume first field candidates");
        assert!(
            smallwood_hx512_register_field_rng_request_v1(1).expect("consume second field request")
        );
        smallwood_hx512_register_field_candidates_v1(1).expect("consume second field candidates");
        assert!(smallwood_hx512_register_tape_rng_batch_v1(72).expect("consume tape request"));
        assert_eq!(guard.finish().expect("finish exact RNG session"), budget);
    }

    #[test]
    fn hx512_rng_session_rejects_request_drift_and_drop_clears_state() {
        let budget = synthetic_hx512_rng_budget_v1();
        let guard =
            enter_smallwood_hx512_rng_session_v1(VecDeque::from([2usize]), VecDeque::new(), budget)
                .expect("install synthetic HX512 RNG session");
        let error = smallwood_hx512_register_field_rng_request_v1(1)
            .expect_err("request-size drift must fail closed");
        assert!(error
            .to_string()
            .contains("HX512 prover field RNG request drift"));
        drop(guard);

        let replacement =
            enter_smallwood_hx512_rng_session_v1(VecDeque::new(), VecDeque::new(), budget)
                .expect("dropped guard must clear the thread-local session");
        replacement
            .finish()
            .expect("empty replacement session must finish");
    }

    #[test]
    fn hx512_rng_session_rejects_candidate_budget_exhaustion() {
        let mut budget = synthetic_hx512_rng_budget_v1();
        budget.field_candidate_limit = 1;
        let guard =
            enter_smallwood_hx512_rng_session_v1(VecDeque::from([2usize]), VecDeque::new(), budget)
                .expect("install bounded synthetic HX512 RNG session");
        assert!(
            smallwood_hx512_register_field_rng_request_v1(2).expect("consume exact request shape")
        );
        let error = smallwood_hx512_register_field_candidates_v1(2)
            .expect_err("candidate cap exhaustion must fail closed");
        assert!(error
            .to_string()
            .contains("HX512 field RNG rejection budget exhausted"));
        drop(guard);
    }

    #[test]
    fn prover_field_randomness_rejects_noncanonical_machine_words() {
        assert_eq!(canonical_random_field_word(0), Some(0));
        assert_eq!(
            canonical_random_field_word(FIELD_ORDER - 1),
            Some(FIELD_ORDER - 1)
        );
        assert_eq!(canonical_random_field_word(FIELD_ORDER), None);
        assert_eq!(canonical_random_field_word(u64::MAX), None);

        let sampled = random_vec(1024).expect("sample canonical Goldilocks words");
        assert_eq!(sampled.len(), 1024);
        assert!(sampled.iter().all(|value| *value < FIELD_ORDER));
    }

    #[test]
    fn level5_sha512_raw_digest_and_field_xof_match_independent_known_answer() {
        let words = [0, 1, FIELD_ORDER - 1, FIELD_ORDER, u64::MAX];
        let raw = sha512_domain_digest(SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN, &words, 0);
        assert_eq!(
            hex::encode(raw),
            concat!(
                "f22b64e7f4ebf5d8475469e6937a16ee0cf4d7e9cbd577cb65cd3401ac18313a",
                "07658c063f197d35c200845d4a9795da313f54238ffc602fe98e24da1becab16"
            )
        );
        assert_eq!(
            read_sha512_xof_words_with_count(
                SmallwoodTranscriptBackend::Sha512Level5,
                SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
                &words,
                12,
            )
            .expect("sample bounded Level-5 field XOF")
            .0,
            vec![
                0xd8f5_ebf4_e764_2bf2,
                0xee16_7a93_e669_5447,
                0xcb77_d5cb_e9d7_f40c,
                0x3a31_18ac_0134_cd65,
                0x357d_193f_068c_6507,
                0xda95_974a_5d84_00c2,
                0x2f60_fc8f_2354_3f31,
                0x16ab_ec1b_da24_8ee9,
                0xb242_d98c_70fb_cf33,
                0x9329_6cb3_d637_aaf3,
                0x442e_12ba_57dd_91d4,
                0x9c38_543c_3187_d01b,
            ]
        );
    }

    #[test]
    fn sha512_field_xof_forced_exhaustion_returns_constraint_violation_without_unwind() {
        let outcome = std::panic::catch_unwind(|| {
            read_canonical_field_words_from_blocks_v1(1, 2, |_| [0xff; DIGEST_BYTES])
        });
        let error = outcome
            .expect("bounded rejection exhaustion must not unwind")
            .expect_err("all noncanonical candidates must exhaust the explicit cap");
        assert!(error
            .to_string()
            .contains("SHA-512 field-XOF rejection budget exhausted"));

        let (words, calls) =
            read_canonical_field_words_from_blocks_v1(9, 2, |_| [0u8; DIGEST_BYTES])
                .expect("canonical candidates fit the exact two-block budget");
        assert_eq!(words, vec![0u64; 9]);
        assert_eq!(calls, 2);
    }

    #[test]
    fn sha512_field_xof_abort_report_records_exact_finite_tail() {
        let report = report_smallwood_sha512_field_xof_abort_bound_v1(
            SMALLWOOD_SHA512_FIELD_XOF_MAX_OUTPUT_WORDS_V1,
        )
        .expect("report capped sampler abort tail");
        assert_eq!(
            report.candidate_word_cap,
            SMALLWOOD_SHA512_FIELD_XOF_MAX_OUTPUT_WORDS_V1
                + SMALLWOOD_SHA512_FIELD_XOF_EXTRA_CANDIDATE_WORDS_V1
        );
        assert_eq!(report.minimum_rejections_for_exhaustion, 33);
        assert!(report.is_strictly_below_power_of_two_v1(386));
        assert!(report.union_bound_numerator > BigUint::from(0u8));
        assert!(report.union_bound_denominator > report.union_bound_numerator);
        assert!(report_smallwood_sha512_field_xof_abort_bound_v1(
            SMALLWOOD_SHA512_FIELD_XOF_MAX_OUTPUT_WORDS_V1 + 1
        )
        .is_err());
    }

    #[test]
    fn v3_full_sha512_first48_commitment_and_field_xof_match_independent_known_answer() {
        let backend = SmallwoodTranscriptBackend::FullSha512First48CommitmentV3;
        let words = [0, 1, FIELD_ORDER - 1, FIELD_ORDER, u64::MAX];
        let raw = sha512_raw_domain_digest(backend, SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN, &words, 0);
        assert_eq!(
            hex::encode(raw),
            concat!(
                "9d128910d9178df05499ea882ef4239326ddcaa20d39c9aacd9d24c272e73abd",
                "26204db52019ea8bf163682e96fd57c702ba30f33f744b5aa74630d64d8745a7"
            )
        );

        let observed =
            sha512_commitment_domain_digest(backend, SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN, &words, 0);
        assert_eq!(&observed[..48], &raw[..48]);
        assert_eq!(&observed[48..], &[0u8; 16]);
        assert_ne!(
            raw,
            sha512_domain_digest(SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN, &words, 0),
            "the V3 profile frame must separate it from active Level-5"
        );
        assert_ne!(
            observed,
            sha512_commitment_domain_digest(
                backend,
                SMALLWOOD_LEVEL5_MERKLE_NODE_DOMAIN,
                &words,
                0,
            ),
            "role domains must not alias"
        );

        let (xof, digest_calls) = read_sha512_xof_words_with_count(
            backend,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            12,
        )
        .expect("sample bounded V3 field XOF");
        assert_eq!(digest_calls, 2);
        assert_eq!(
            xof,
            vec![
                0xf08d_17d9_1089_129d,
                0x9323_f42e_88ea_9954,
                0xaac9_390d_a2ca_dd26,
                0xbd3a_e772_c224_9dcd,
                0x8bea_1920_b54d_2026,
                0xc757_fd96_2e68_63f1,
                0x5a4b_743f_f330_ba02,
                0xa745_874d_d630_46a7,
                0x9332_a886_34ba_9e91,
                0x3a39_c8a0_e193_f47e,
                0x9e53_9b04_80b8_493a,
                0x8115_624d_59bc_9825,
            ]
        );
        assert_eq!(
            &xof[6..8],
            &[0x5a4b_743f_f330_ba02, 0xa745_874d_d630_46a7],
            "V3 field-XOF must consume words seven and eight of the full SHA-512 block"
        );
    }

    #[test]
    fn v3_wire_is_canonical_and_rejects_cross_profile_or_digest_mutations() {
        const SMOKE_PROFILE: SmallwoodNoGrindingProfileV1 = SmallwoodNoGrindingProfileV1 {
            rho: 2,
            nb_opened_evals: 2,
            beta: 2,
            opening_pow_bits: 0,
            decs_nb_evals: 256,
            decs_nb_opened_evals: 4,
            decs_eta: 2,
            decs_pow_bits: 0,
        };
        let backend = SmallwoodTranscriptBackend::FullSha512First48CommitmentV3;
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5FullSha512First48CommitmentV3,
            8,
            8,
            2,
            17,
            0,
        )
        .unwrap();
        let witness = vec![0u64; 64];
        let binding = [0x5au8; 16];
        let proof = prove_statement_with_transcript_backend_and_profile(
            &statement,
            &witness,
            &binding,
            SMOKE_PROFILE,
            backend,
        )
        .expect("produce V3 codec/refinement smoke proof");
        assert_eq!(
            &proof[..4],
            &SMALLWOOD_PROOF_WIRE_MAGIC_FULL_SHA512_FIRST48_COMMITMENT_V3
        );
        ensure_canonical_smallwood_proof_bytes(&proof).unwrap();
        verify_statement_with_transcript_backend_and_profile(
            &statement,
            &binding,
            &proof,
            SMOKE_PROFILE,
            backend,
        )
        .expect("verify V3 codec/refinement smoke proof");

        for cross_backend in [
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodTranscriptBackend::Blake3,
            SmallwoodTranscriptBackend::Poseidon2,
        ] {
            let err = verify_statement_with_transcript_backend_and_profile(
                &statement,
                &binding,
                &proof,
                SMOKE_PROFILE,
                cross_backend,
            )
            .expect_err("V3 wire must not verify under another transcript profile");
            assert!(err.to_string().contains("digest width"));
        }

        let h_piop_offset = 4 + SALT_BYTES + NONCE_BYTES;
        let mut digest_mutation = proof.clone();
        digest_mutation[h_piop_offset] ^= 1;
        assert!(verify_statement_with_transcript_backend_and_profile(
            &statement,
            &binding,
            &digest_mutation,
            SMOKE_PROFILE,
            backend,
        )
        .is_err());

        let mut decoded = decode_smallwood_proof_bytes_v1(&proof).unwrap();
        let first_node = decoded
            .pcs
            .decs
            .auth_paths
            .iter_mut()
            .find_map(|path| path.first_mut())
            .expect("smoke proof must contain an authentication node");
        first_node[0] ^= 1;
        let auth_mutation = encode_smallwood_proof_bytes_v1(&decoded).unwrap();
        assert!(verify_statement_with_transcript_backend_and_profile(
            &statement,
            &binding,
            &auth_mutation,
            SMOKE_PROFILE,
            backend,
        )
        .is_err());

        let mut hidden_tail = decode_smallwood_proof_bytes_v1(&proof).unwrap();
        hidden_tail.h_piop[48] = 1;
        assert!(encode_smallwood_proof_bytes_v1(&hidden_tail).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_mutations_of_a_canonical_wire_are_exact_or_rejected(
            offset in 0usize..110,
            replacement in any::<u8>(),
            suffix in vec(any::<u8>(), 0..8),
        ) {
            let vectors: LeanSmallwoodProofWireVectors = serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/formal_crypto_vectors/smallwood_proof_wire.json"
            )))
            .expect("parse Lean SmallWood proof-wire vectors");
            let mut bytes = decode_wire_hex(
                &vectors.cases.iter()
                    .find(|case| case.name == "canonical-minimal")
                    .expect("canonical minimal vector")
                    .proof_hex,
            );
            let selected = offset % bytes.len();
            bytes[selected] = replacement;
            bytes.extend_from_slice(&suffix);

            if let Ok(proof) = decode_smallwood_proof_bytes_v1(&bytes) {
                prop_assert_eq!(
                    encode_smallwood_proof_bytes_v1(&proof)
                        .expect("accepted proof must re-encode"),
                    bytes,
                );
            }
        }
    }

    #[test]
    fn verifier_rejects_noncanonical_opening_nonce_grinding() {
        let packing_points = [0u64, 1, 2, 3];
        let h_piop = [0x5au8; DIGEST_BYTES];
        let backend = SmallwoodTranscriptBackend::Blake3;
        let profile = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1;
        let canonical =
            choose_opening_nonce_for_profile(&packing_points, profile, &h_piop, backend)
                .expect("choose canonical opening nonce");
        canonical_piop_opening_points(&packing_points, profile, &canonical, &h_piop, backend)
            .expect("canonical nonce must be accepted");

        let mut counter = u32::from_le_bytes(canonical)
            .checked_add(1)
            .expect("test nonce has successor");
        let alternate = loop {
            let nonce = counter.to_le_bytes();
            let points = xof_piop_opening_points_for_profile(&nonce, &h_piop, profile, backend);
            if smallwood_piop_opening_points_are_valid_for_profile(
                &packing_points,
                &points,
                profile,
            ) {
                break nonce;
            }
            counter = counter.checked_add(1).expect("find alternate valid nonce");
        };
        assert_ne!(alternate, canonical);
        let err =
            canonical_piop_opening_points(&packing_points, profile, &alternate, &h_piop, backend)
                .expect_err("alternate valid nonce must not enable grinding");
        assert!(matches!(
            err,
            TransactionCircuitError::ConstraintViolation(
                "smallwood opening nonce is not canonical; grinding is forbidden"
            )
        ));
    }

    #[test]
    fn prover_and_verifier_reject_zero_linear_correction_openings() {
        let packing_points = (0..64u64).collect::<Vec<_>>();
        let zero_correction = [1_000, 1_001, 1_002, 1_003, 9_145_141_821_497_892_284];

        // This is the concrete completeness counterexample which passed the
        // historical distinct/nonpacking-only predicate.
        assert!(zero_correction.iter().enumerate().all(|(index, point)| {
            *point < FIELD_ORDER
                && !packing_points.contains(point)
                && !zero_correction[..index].contains(point)
        }));
        assert_eq!(
            smallwood_piop_linear_correction_factor(&packing_points, &zero_correction),
            Some(0)
        );
        assert!(!smallwood_piop_opening_points_are_valid(
            &packing_points,
            &zero_correction
        ));
        assert!(ensure_no_packing_collisions(&packing_points, &zero_correction).is_err());

        let mut repaired = zero_correction;
        repaired[4] ^= 1;
        assert_eq!(
            smallwood_piop_linear_correction_factor(&packing_points, &repaired),
            Some(4_569_085_921_222_085_778)
        );
        assert!(smallwood_piop_opening_points_are_valid(
            &packing_points,
            &repaired
        ));
        ensure_no_packing_collisions(&packing_points, &repaired)
            .expect("nonzero-correction opening set is admissible on both sides");
    }

    #[test]
    fn smz9_prover_and_verifier_reject_singular_pcs_unstack_openings() {
        let packing_points = (0..64u64).collect::<Vec<_>>();
        let singular = [549_755_813_888, 100, 101, 102, 103, 104];

        // 549755813888 is an order-64 Goldilocks root.  This opening set
        // satisfies the historical distinct/outside/correction predicate, but
        // r^64 - 1 vanishes at its first opening and zeroes the first row of
        // thirty exact PCS-unstack blocks.
        assert_eq!(pow_mod(singular[0], 64), 1);
        assert_eq!(pow_mod(singular[0], 32), FIELD_ORDER - 1);
        assert_eq!(
            smallwood_piop_linear_correction_factor(&packing_points, &singular),
            Some(8_728_840_291_490_827_106)
        );
        assert!(smallwood_piop_opening_points_are_valid(
            &packing_points,
            &singular
        ));
        let blocks = smallwood_smz9_pcs_unstack_blocks_v1(&singular)
            .expect("construct exact singular SMZ9 PCS-unstack blocks");
        assert_eq!(blocks.len(), 40);
        assert_eq!(
            blocks
                .iter()
                .filter(|block| block[0].iter().all(|&coefficient| coefficient == 0))
                .count(),
            30
        );
        assert!(!smallwood_piop_opening_points_are_valid_for_profile(
            &packing_points,
            &singular,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        ));
        assert!(ensure_no_packing_collisions_for_profile(
            &packing_points,
            &singular,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        )
        .is_err());

        let h_piop = [0xa5; DIGEST_BYTES];
        let nonce = choose_opening_nonce_for_profile(
            &packing_points,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            &h_piop,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect("honest SMZ9 selector finds an admissible nonce");
        let honest = xof_piop_opening_points_for_profile(
            &nonce,
            &h_piop,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        );
        assert!(smallwood_piop_opening_points_are_valid_for_profile(
            &packing_points,
            &honest,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
        ));
        let honest_blocks = smallwood_smz9_pcs_unstack_blocks_v1(&honest)
            .expect("construct exact honest SMZ9 PCS-unstack blocks");
        assert_eq!(honest_blocks.len(), 40);
        assert!(honest_blocks
            .iter()
            .flat_map(|block| block.iter().flatten())
            .all(|&coefficient| coefficient != 0));
        canonical_piop_opening_points(
            &packing_points,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            &nonce,
            &h_piop,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect("verifier canonicalization accepts the honest selected openings");
    }

    #[test]
    fn smz9_exact_witness_randomness_matrix_matches_poly_restore_differences() {
        let packing_points = (0..64u64).collect::<Vec<_>>();
        let packing_evaluations = packing_points
            .iter()
            .map(|&point| add_mod(pow_mod(point, 3), 17))
            .collect::<Vec<_>>();
        let opening_points = [101, 103, 107, 109, 113, 127];
        let exact = smallwood_smz9_witness_randomness_matrix_v1(&opening_points)
            .expect("construct exact SMZ9 witness-randomness matrix");
        let baseline_high = [11, 13, 17, 19, 23, 29];
        let baseline = poly_restore(&baseline_high, &packing_evaluations, &packing_points, 69)
            .expect("restore baseline witness polynomial");

        for coin_index in 0..6 {
            let mut changed_high = baseline_high;
            changed_high[coin_index] = add_mod(changed_high[coin_index], 1);
            let changed = poly_restore(&changed_high, &packing_evaluations, &packing_points, 69)
                .expect("restore basis-mutated witness polynomial");
            for (opening_index, &point) in opening_points.iter().enumerate() {
                assert_eq!(
                    sub_mod(poly_eval(&changed, point), poly_eval(&baseline, point)),
                    exact[opening_index][coin_index],
                    "opening={opening_index} coin={coin_index}"
                );
            }
        }

        assert_ne!(
            exact,
            opening_points
                .iter()
                .map(|&point| {
                    (0..6)
                        .map(|coin_index| pow_mod(point, (64 + coin_index) as u64))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
            "a bare degree-64 monomial basis is not the Rust poly_restore map"
        );
    }

    #[test]
    fn fixed_decs_sampler_is_unique_unbiased_and_bounded() {
        const DOMAIN_SIZE: usize = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals;
        const OPENING_COUNT: usize = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals;
        let transcript_hash = [0x5au8; DIGEST_BYTES];
        let (indexes, nonce) = xof_decs_opening_fixed_no_grinding(
            DOMAIN_SIZE,
            OPENING_COUNT,
            0,
            &transcript_hash,
            SmallwoodTranscriptBackend::Sha512Level5,
        )
        .expect("sample fixed DECS queries");
        assert_eq!(nonce, [0; NONCE_BYTES]);
        assert_eq!(indexes.len(), OPENING_COUNT);
        assert!(indexes.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(indexes.iter().all(|&index| index < DOMAIN_SIZE as u32));

        // If 50 draws contain fewer than 26 distinct values, all accepted draws
        // fit in some 25-element subset. The union bound below is conservative
        // integer evidence that fixed-pool exhaustion is below 2^-260.
        fn binomial(n: usize, k: usize) -> BigUint {
            let k = k.min(n - k);
            (0..k).fold(BigUint::from(1u8), |value, index| {
                value * BigUint::from(n - index) / BigUint::from(index + 1)
            })
        }
        let domain = BigUint::from(DOMAIN_SIZE);
        let subset_size = OPENING_COUNT - 1;
        let draws = SMALLWOOD_LEVEL5_FIXED_DECS_CANDIDATE_COUNT;
        let failure_numerator =
            binomial(DOMAIN_SIZE, subset_size) * BigUint::from(subset_size).pow(draws as u32);
        let failure_denominator = domain.pow(draws as u32);
        assert!(
            (failure_numerator << 260usize) < failure_denominator,
            "fixed DECS sampler exhaustion bound must be below 2^-260"
        );
        assert!(xof_decs_opening_fixed_no_grinding(
            DOMAIN_SIZE,
            OPENING_COUNT,
            1,
            &transcript_hash,
            SmallwoodTranscriptBackend::Sha512Level5,
        )
        .is_err());

        let (active_indexes, active_nonce) = xof_decs_opening(
            DOMAIN_SIZE,
            OPENING_COUNT,
            0,
            &transcript_hash,
            SmallwoodTranscriptBackend::Sha512Level5,
        )
        .expect("active Level-5 path selects fixed DECS sampling");
        assert_eq!(active_indexes, indexes);
        assert_eq!(active_nonce, [0; NONCE_BYTES]);
    }

    #[test]
    fn decs_challenge_is_exactly_scalar_power_batching() {
        const WIDTH: usize = 138;
        const REPETITIONS: usize = 5;
        let challenge = derive_decs_challenge(
            WIDTH,
            REPETITIONS,
            SmallwoodDecsChallengeFormat::ScalarPowers,
            &[0x5au8; DIGEST_BYTES],
            SmallwoodTranscriptBackend::Sha512Level5,
        );

        assert_eq!(challenge.len(), REPETITIONS);
        for coefficients in challenge {
            assert_eq!(coefficients.len(), WIDTH);
            let gamma = coefficients[0];
            let mut expected = gamma;
            for coefficient in coefficients {
                assert_eq!(coefficient, expected);
                expected = mul_mod(expected, gamma);
            }
        }
    }

    #[test]
    fn level5_decs_challenge_is_full_uniform_matrix() {
        const WIDTH: usize = 138;
        const REPETITIONS: usize = 5;
        let digest = [0x5au8; DIGEST_BYTES];
        let challenge = derive_decs_challenge(
            WIDTH,
            REPETITIONS,
            SmallwoodDecsChallengeFormat::Uniform,
            &digest,
            SmallwoodTranscriptBackend::Sha512Level5,
        );
        let expected = transcript_xof_words(
            SmallwoodTranscriptBackend::Sha512Level5,
            transcript_domain(
                SmallwoodTranscriptBackend::Sha512Level5,
                SMALLWOOD_LEVEL5_DECS_COEFFICIENT_DOMAIN,
            ),
            &digest_to_words(&digest, SmallwoodTranscriptBackend::Sha512Level5),
            WIDTH * REPETITIONS,
        );

        assert_eq!(challenge.len(), REPETITIONS);
        assert!(challenge.iter().all(|row| row.len() == WIDTH));
        assert_eq!(
            challenge.into_iter().flatten().collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn level5_piop_challenge_is_full_uniform_matrix() {
        let statement = StructuralIdentityWitnessStatement::new(8, 8, 2, 17, 0).unwrap();
        let cfg = SmallwoodConfig::new(&statement).unwrap();
        let digest = [0xa5u8; DIGEST_BYTES];
        let challenge = derive_gamma_prime(&cfg, &digest, SmallwoodTranscriptBackend::Sha512Level5);
        let width = cfg.constraint_count.max(cfg.linear_constraint_count);
        let expected = transcript_xof_words(
            SmallwoodTranscriptBackend::Sha512Level5,
            transcript_domain(
                SmallwoodTranscriptBackend::Sha512Level5,
                SMALLWOOD_LEVEL5_PIOP_COEFFICIENT_DOMAIN,
            ),
            &digest_to_words(&digest, SmallwoodTranscriptBackend::Sha512Level5),
            cfg.rho() * width,
        );

        assert_eq!(challenge.len(), cfg.rho());
        assert!(challenge.iter().all(|row| row.len() == width));
        assert_eq!(
            challenge.into_iter().flatten().collect::<Vec<_>>(),
            expected
        );
    }

    fn default_bridge_smallwood_arithmetization_for_test() -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn decode_smallwood_candidate_proof_for_test(bytes: &[u8]) -> SmallwoodCandidateProof {
        bincode::deserialize(bytes).unwrap_or_else(|_| {
            let legacy: LegacySmallwoodCandidateProofForTest =
                bincode::deserialize(bytes).expect("decode legacy smallwood candidate proof");
            SmallwoodCandidateProof {
                arithmetization: legacy.arithmetization,
                ark_proof: legacy.ark_proof,
                auxiliary_witness_words: Vec::new(),
            }
        })
    }

    fn merkle_build_levels_blake3_reference(
        levels: &mut Vec<Vec<[u8; DIGEST_BYTES]>>,
    ) -> [u8; DIGEST_BYTES] {
        let mut current = levels[0].clone();
        while current.len() > 1 {
            let mut parents = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                let mut input = Vec::with_capacity(pair.len() * LEGACY_DIGEST_WORDS);
                for child in pair {
                    input.extend(digest_to_words(child, SmallwoodTranscriptBackend::Blake3));
                }
                parents.push(words_to_digest(&transcript_xof_words_blake3_reference(
                    SMALLWOOD_XOF_DOMAIN,
                    &input,
                    LEGACY_DIGEST_WORDS,
                )));
            }
            levels.push(parents.clone());
            current = parents;
        }
        current[0]
    }

    fn sample_witness() -> TransactionWitness {
        let sk_spend = [42u8; 32];
        let pk_auth = spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: crate::constants::NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            pk_auth,
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [5u8; 32],
            pk_auth,
            rho: [6u8; 32],
            r: [7u8; 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..crate::note::MERKLE_TREE_DEPTH {
            let zero = [Felt::ZERO; 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }
        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [9u8; 32],
                    merkle_path: MerklePath {
                        siblings: siblings0,
                    },
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [8u8; 32],
                    merkle_path: MerklePath {
                        siblings: siblings1,
                    },
                },
            ],
            outputs: vec![
                OutputNoteWitness {
                    note: NoteData {
                        value: 3,
                        asset_id: crate::constants::NATIVE_ASSET_ID,
                        pk_recipient: [11u8; 32],
                        pk_auth: [111u8; 32],
                        rho: [12u8; 32],
                        r: [13u8; 32],
                    },
                },
                OutputNoteWitness {
                    note: NoteData {
                        value: 5,
                        asset_id: 1,
                        pk_recipient: [21u8; 32],
                        pk_auth: [121u8; 32],
                        rho: [22u8; 32],
                        r: [23u8; 32],
                    },
                },
            ],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&current),
            fee: 5,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: SMALLWOOD_CANDIDATE_VERSION_BINDING,
        }
    }

    fn production_statement(material: &PackedSmallwoodAuxFrontendMaterial) -> PackedStatement<'_> {
        PackedStatement::new_with_auxiliary(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
            &material.public_statement.public_values,
            material.public_statement.lppc_row_count as usize,
            material.public_statement.lppc_packing_factor as usize,
            material.public_statement.effective_constraint_degree as usize,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
            &material.auxiliary_witness_words,
            material.auxiliary_witness_words.len(),
        )
    }

    fn sample_production_candidate() -> &'static (PackedSmallwoodAuxFrontendMaterial, Vec<u8>) {
        static SAMPLE: OnceLock<(PackedSmallwoodAuxFrontendMaterial, Vec<u8>)> = OnceLock::new();
        SAMPLE.get_or_init(|| {
            let witness = sample_witness();
            let material =
                build_production_smallwood_frontend_material_from_witness(&witness).unwrap();
            let proof = {
                let statement = production_statement(&material);
                prove_candidate(
                    &statement,
                    &material.packed_expanded_witness,
                    &material.transcript_binding,
                )
                .unwrap()
            };
            (material, proof)
        })
    }

    struct FakeIdentityWitnessStatement {
        row_count: usize,
        packing_factor: usize,
        linear_offsets: Vec<u32>,
        linear_indices: Vec<u32>,
        linear_coefficients: Vec<u64>,
        linear_targets: Vec<u64>,
    }

    impl SmallwoodConstraintAdapter for FakeIdentityWitnessStatement {
        fn arithmetization(&self) -> SmallwoodArithmetization {
            SmallwoodArithmetization::Bridge64V1
        }

        fn row_count(&self) -> usize {
            self.row_count
        }

        fn packing_factor(&self) -> usize {
            self.packing_factor
        }

        fn constraint_degree(&self) -> usize {
            2
        }

        fn linear_constraint_count(&self) -> usize {
            self.linear_targets.len()
        }

        fn constraint_count(&self) -> usize {
            1
        }

        fn linear_constraint_offsets(&self) -> &[u32] {
            &self.linear_offsets
        }

        fn linear_constraint_indices(&self) -> &[u32] {
            &self.linear_indices
        }

        fn linear_constraint_coefficients(&self) -> &[u64] {
            &self.linear_coefficients
        }

        fn linear_targets(&self) -> &[u64] {
            &self.linear_targets
        }

        fn auxiliary_witness_words(&self) -> &[u64] {
            &[]
        }

        fn auxiliary_witness_limb_count(&self) -> Option<usize> {
            None
        }

        fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
            SmallwoodLinearConstraintForm::IdentityWitness
        }

        fn nonlinear_eval_view<'a>(
            &self,
            eval_point: u64,
            rows: &'a [u64],
            auxiliary_words: &'a [u64],
        ) -> SmallwoodNonlinearEvalView<'a> {
            SmallwoodNonlinearEvalView::RowScalars {
                eval_point,
                rows,
                auxiliary_words,
            }
        }

        fn compute_constraints_u64(
            &self,
            _view: SmallwoodNonlinearEvalView<'_>,
            out: &mut [u64],
        ) -> Result<(), TransactionCircuitError> {
            out[0] = 0;
            Ok(())
        }
    }

    const GENERIC_CSR_SMOKE_PROFILE: SmallwoodNoGrindingProfileV1 = SmallwoodNoGrindingProfileV1 {
        rho: 2,
        nb_opened_evals: 2,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 256,
        decs_nb_opened_evals: 4,
        decs_eta: 2,
        decs_pow_bits: 0,
    };

    #[derive(Clone, Debug)]
    struct GenericCsrTestStatement {
        row_count: usize,
        packing_factor: usize,
        linear_constraint_count: usize,
        linear_offsets: Vec<u32>,
        linear_indices: Vec<u32>,
        linear_coefficients: Vec<u64>,
        linear_targets: Vec<u64>,
        auxiliary_words: Vec<u64>,
        auxiliary_limb_count: Option<usize>,
    }

    impl GenericCsrTestStatement {
        fn valid() -> Self {
            Self {
                row_count: 2,
                packing_factor: 2,
                linear_constraint_count: 2,
                linear_offsets: vec![0, 2, 4],
                // The first constraint is deliberately descending. Semantic
                // term order is retained and must not be confused with a
                // canonicality requirement to sort variable indices.
                linear_indices: vec![1, 0, 4, 2],
                linear_coefficients: vec![1, 1, 1, 1],
                linear_targets: vec![3, 7],
                // Index four is the first addressable auxiliary variable.
                auxiliary_words: vec![2],
                auxiliary_limb_count: Some(1),
            }
        }
    }

    impl SmallwoodConstraintAdapter for GenericCsrTestStatement {
        fn arithmetization(&self) -> SmallwoodArithmetization {
            SmallwoodArithmetization::Bridge64V1
        }

        fn row_count(&self) -> usize {
            self.row_count
        }

        fn packing_factor(&self) -> usize {
            self.packing_factor
        }

        fn constraint_degree(&self) -> usize {
            2
        }

        fn linear_constraint_count(&self) -> usize {
            self.linear_constraint_count
        }

        fn constraint_count(&self) -> usize {
            1
        }

        fn linear_constraint_offsets(&self) -> &[u32] {
            &self.linear_offsets
        }

        fn linear_constraint_indices(&self) -> &[u32] {
            &self.linear_indices
        }

        fn linear_constraint_coefficients(&self) -> &[u64] {
            &self.linear_coefficients
        }

        fn linear_targets(&self) -> &[u64] {
            &self.linear_targets
        }

        fn auxiliary_witness_words(&self) -> &[u64] {
            &self.auxiliary_words
        }

        fn auxiliary_witness_limb_count(&self) -> Option<usize> {
            self.auxiliary_limb_count
        }

        fn nonlinear_eval_view<'a>(
            &self,
            eval_point: u64,
            rows: &'a [u64],
            auxiliary_words: &'a [u64],
        ) -> SmallwoodNonlinearEvalView<'a> {
            SmallwoodNonlinearEvalView::RowScalars {
                eval_point,
                rows,
                auxiliary_words,
            }
        }

        fn compute_constraints_u64(
            &self,
            _view: SmallwoodNonlinearEvalView<'_>,
            out: &mut [u64],
        ) -> Result<(), TransactionCircuitError> {
            out.fill(0);
            Ok(())
        }
    }

    fn expect_generic_csr_rejection(statement: &GenericCsrTestStatement, needle: &str) {
        let error = SmallwoodConfig::new_with_profile(statement, GENERIC_CSR_SMOKE_PROFILE)
            .expect_err("malformed generic CSR metadata unexpectedly constructed a config");
        assert!(
            error.to_string().contains(needle),
            "unexpected error for {needle:?}: {error:?}"
        );
    }

    #[test]
    fn generic_csr_config_accepts_descending_terms_and_first_auxiliary_index() {
        let statement = GenericCsrTestStatement::valid();
        let config = SmallwoodConfig::new_with_profile(&statement, GENERIC_CSR_SMOKE_PROFILE)
            .expect("canonical generic CSR config");
        assert_eq!(config.witness_size, 4);
        assert_eq!(config.total_variable_count, 5);
        assert_eq!(config.auxiliary_witness_word_count, 1);
        assert_eq!(config.auxiliary_witness_limb_count, 1);
    }

    #[test]
    fn generic_csr_config_rejects_geometry_and_length_invariants() {
        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_offsets.pop();
        expect_generic_csr_rejection(&statement, "offset count mismatch");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_coefficients.pop();
        expect_generic_csr_rejection(&statement, "term metadata length mismatch");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_targets.pop();
        expect_generic_csr_rejection(&statement, "target count mismatch");

        let mut statement = GenericCsrTestStatement::valid();
        statement.row_count = usize::MAX;
        statement.packing_factor = 2;
        expect_generic_csr_rejection(&statement, "overflows witness size");

        let mut statement = GenericCsrTestStatement::valid();
        statement.row_count = u32::MAX as usize + 1;
        statement.packing_factor = 1;
        expect_generic_csr_rejection(&statement, "witness size does not fit");

        let mut statement = GenericCsrTestStatement::valid();
        statement.row_count = u32::MAX as usize;
        statement.packing_factor = 1;
        expect_generic_csr_rejection(&statement, "total linear-variable count does not fit");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_constraint_count = u32::MAX as usize + 1;
        expect_generic_csr_rejection(&statement, "constraint count does not fit");
    }

    #[test]
    fn generic_csr_config_rejects_noncanonical_offsets() {
        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_offsets[0] = 1;
        expect_generic_csr_rejection(&statement, "start at zero");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_offsets = vec![0, 3, 2];
        expect_generic_csr_rejection(&statement, "strictly increasing");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_offsets = vec![0, 0, 4];
        expect_generic_csr_rejection(&statement, "no empty constraint");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_offsets = vec![0, 2, 3];
        expect_generic_csr_rejection(&statement, "final offset mismatch");
    }

    #[test]
    fn generic_csr_config_rejects_noncanonical_terms_and_targets() {
        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_coefficients[0] = 0;
        expect_generic_csr_rejection(&statement, "coefficient must be nonzero");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_coefficients[0] = FIELD_ORDER;
        expect_generic_csr_rejection(&statement, "coefficient is not a canonical");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_targets[0] = FIELD_ORDER;
        expect_generic_csr_rejection(&statement, "target at constraint");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_indices[1] = statement.linear_indices[0];
        expect_generic_csr_rejection(&statement, "duplicate variable index");

        let mut statement = GenericCsrTestStatement::valid();
        statement.linear_indices[2] = 5;
        expect_generic_csr_rejection(&statement, "variable index out of range");
    }

    #[test]
    fn generic_csr_config_rejects_noncanonical_auxiliary_metadata() {
        let mut statement = GenericCsrTestStatement::valid();
        statement.auxiliary_words[0] = FIELD_ORDER;
        expect_generic_csr_rejection(&statement, "auxiliary witness word");

        let mut statement = GenericCsrTestStatement::valid();
        statement.auxiliary_limb_count = Some(2);
        expect_generic_csr_rejection(&statement, "limb count");

        let mut statement = GenericCsrTestStatement::valid();
        statement.auxiliary_words.push(1);
        statement.auxiliary_limb_count = Some(1);
        expect_generic_csr_rejection(&statement, "padding word");
    }

    #[test]
    fn generic_csr_validation_has_prover_verifier_and_parser_parity() {
        let statement = GenericCsrTestStatement::valid();
        let witness = [1, 2, 5, 0];
        let binding = [0x42u8; 24];
        let proof = prove_statement_with_transcript_backend_and_profile(
            &statement,
            &witness,
            &binding,
            GENERIC_CSR_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect("prove canonical generic CSR statement");
        verify_statement_with_transcript_backend_and_profile(
            &statement,
            &binding,
            &proof,
            GENERIC_CSR_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect("verify canonical generic CSR statement");

        let mut missing_auxiliary = decode_smallwood_proof_bytes_v1(&proof)
            .expect("decode canonical generic CSR smoke proof");
        match &mut missing_auxiliary.opened_witness.mode {
            SmallwoodOpenedWitnessMode::RowScalars {
                auxiliary_words,
                auxiliary_limb_count,
                ..
            } => {
                auxiliary_words.clear();
                *auxiliary_limb_count = 0;
            }
            mode => panic!("unexpected generic CSR opened-witness mode: {mode:?}"),
        }
        let missing_auxiliary = encode_smallwood_proof_bytes_v1(&missing_auxiliary)
            .expect("encode shape-mismatched generic CSR proof");
        let auxiliary_shape_error = verify_statement_with_transcript_backend_and_profile(
            &statement,
            &binding,
            &missing_auxiliary,
            GENERIC_CSR_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect_err("verifier accepted a proof missing its statement-addressable auxiliary word");
        assert!(
            auxiliary_shape_error
                .to_string()
                .contains("auxiliary witness shape mismatch"),
            "unexpected auxiliary proof-shape error: {auxiliary_shape_error:?}"
        );

        let mut malformed = statement;
        malformed.linear_indices[2] = 5;
        let prover_error = prove_statement_with_transcript_backend_and_profile(
            &malformed,
            &witness,
            &binding,
            GENERIC_CSR_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect_err("prover accepted an out-of-range generic CSR index");
        let verifier_error = verify_statement_with_transcript_backend_and_profile(
            &malformed,
            &binding,
            &proof,
            GENERIC_CSR_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect_err("verifier accepted an out-of-range generic CSR index");
        let parser_precedence_error = verify_statement_with_transcript_backend_and_profile(
            &malformed,
            &binding,
            &[],
            GENERIC_CSR_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect_err("proof parser ran before generic CSR validation");
        let trace_parser_precedence_error = build_smallwood_verifier_trace_with_profile_v1(
            &malformed,
            &binding,
            &[],
            GENERIC_CSR_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Blake3,
        )
        .expect_err("verifier trace parser ran before generic CSR validation");
        for error in [
            prover_error,
            verifier_error,
            parser_precedence_error,
            trace_parser_precedence_error,
        ] {
            assert!(
                error.to_string().contains("variable index out of range"),
                "unexpected prover/verifier validation error: {error:?}"
            );
        }
    }

    #[test]
    fn compact_matrix_decoder_rejects_impossible_dimensions_before_allocation() {
        let bytes = [25, 0, 0xff, 0xff];
        let err = decode_matrix_u64_v1(&bytes, &mut 0usize)
            .expect_err("truncated supported-row matrix dimensions must reject");
        assert!(
            err.to_string()
                .contains("dimensions exceed remaining bytes"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn compact_matrix_decoder_rejects_zero_width_and_excessive_rows_before_allocation() {
        let zero_width = [0xff, 0xff, 0, 0];
        let err = decode_matrix_u64_v1(&zero_width, &mut 0usize)
            .expect_err("zero-width maximal-row matrix must reject");
        assert!(
            err.to_string()
                .contains("row count exceeds supported profile maximum"),
            "unexpected error: {err:?}"
        );

        let mixed_zero = [1, 0, 0, 0];
        let err = decode_matrix_u64_v1(&mixed_zero, &mut 0usize)
            .expect_err("mixed zero matrix dimensions must reject");
        assert!(
            err.to_string().contains("two zero dimensions"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn compact_auth_path_decoder_rejects_impossible_dimensions_before_allocation() {
        let bytes = [1, 0, 255];
        let err = decode_auth_paths_v1(&bytes, &mut 0usize, LEGACY_DIGEST_BYTES, None, None)
            .expect_err("truncated maximal auth path must reject");
        assert!(
            err.to_string()
                .contains("dimensions exceed remaining bytes"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn compact_auth_path_decoder_rejects_excessive_count_before_allocation() {
        let excessive_count = [0xff, 0xff];
        let err = decode_auth_paths_v1(
            &excessive_count,
            &mut 0usize,
            LEGACY_DIGEST_BYTES,
            None,
            None,
        )
        .expect_err("maximal auth-path count must reject");
        assert!(
            err.to_string()
                .contains("count exceeds supported profile maximum"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn compact_auxiliary_decoder_rejects_impossible_count_before_allocation() {
        let mut bytes = vec![SMALLWOOD_OPENED_WITNESS_MODE_ROW_SCALARS_V1];
        push_u16_v1(&mut bytes, 0);
        push_u16_v1(&mut bytes, 0);
        push_u32_v1(&mut bytes, u32::MAX);
        push_u32_v1(&mut bytes, 0);
        let err = decode_opened_witness_v1(&bytes, &mut 0usize)
            .expect_err("truncated maximal auxiliary count must reject");
        assert!(
            err.to_string().contains("count exceeds remaining bytes"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    #[ignore = "full production prove/decode/verify coverage runs in the release benchmark"]
    fn direct_packed_arithmetization_proves_and_verifies_succinctly() {
        let (material, proof) = sample_production_candidate();
        let statement = production_statement(material);
        assert!(
            proof.len() < 524_288,
            "direct packed proof bytes {} exceed native tx-leaf cap",
            proof.len()
        );
        let decoded = decode_smallwood_proof_bytes_v1(proof).unwrap();
        let cfg = SmallwoodConfig::new(&statement).unwrap();
        match decoded.opened_witness.mode {
            SmallwoodOpenedWitnessMode::RowScalars {
                row_scalars,
                auxiliary_words,
                auxiliary_limb_count,
            } => {
                assert_eq!(row_scalars.len(), SMALLWOOD_NB_OPENED_EVALS);
                assert!(row_scalars.iter().all(|row| row.len() == cfg.nb_polys));
                assert_eq!(auxiliary_words, material.auxiliary_witness_words);
                assert_eq!(auxiliary_limb_count, material.auxiliary_witness_words.len());
            }
            mode => panic!("unexpected opened witness mode for direct packed proof: {mode:?}"),
        }
        verify_candidate(&statement, &material.transcript_binding, proof).unwrap();
    }

    #[test]
    fn identity_witness_fast_path_rejects_malformed_linear_metadata() {
        let statement = FakeIdentityWitnessStatement {
            row_count: 1,
            packing_factor: 4,
            linear_offsets: vec![0, 1, 2, 3, 4],
            linear_indices: vec![0, 1, 2, 3],
            linear_coefficients: vec![1, 1, 7, 1],
            linear_targets: vec![10, 11, 12, 13],
        };
        let err = SmallwoodConfig::new(&statement)
            .expect_err("malformed identity-witness metadata unexpectedly accepted");
        assert!(err.to_string().contains("identity witness"));
    }

    #[test]
    fn direct_packed_projection_matches_bridge_baseline() {
        let witness = sample_witness();
        let direct_material =
            build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        let bridge_material =
            build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let direct_statement = PackedStatement::new(
            SmallwoodArithmetization::DirectPacked64V1,
            &direct_material.public_statement.public_values,
            direct_material.public_statement.lppc_row_count as usize,
            SMALLWOOD_BRIDGE_PACKING_FACTOR,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as usize,
            &direct_material.linear_constraints.term_offsets,
            &direct_material.linear_constraints.term_indices,
            &direct_material.linear_constraints.term_coefficients,
            &direct_material.linear_constraints.targets,
        );
        let bridge_statement = PackedStatement::new(
            SmallwoodArithmetization::Bridge64V1,
            &bridge_material.public_statement.public_values,
            bridge_material.public_statement.lppc_row_count as usize,
            SMALLWOOD_BRIDGE_PACKING_FACTOR,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as usize,
            &bridge_material.linear_constraints.term_offsets,
            &bridge_material.linear_constraints.term_indices,
            &bridge_material.linear_constraints.term_coefficients,
            &bridge_material.linear_constraints.targets,
        );
        let direct_bytes = projected_candidate_proof_bytes(&direct_statement).unwrap();
        let bridge_bytes = projected_candidate_proof_bytes(&bridge_statement).unwrap();
        assert!(
            direct_bytes <= bridge_bytes,
            "row-aligned direct mode must stay at or below the bridge baseline: direct={direct_bytes} bridge={bridge_bytes}",
        );
    }

    #[test]
    fn level5_lvcs_planner_projection_charges_sha512_digest_width() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
            699,
            64,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as usize,
            890,
            0,
        )
        .unwrap();
        let profile = ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1;
        let planner = report_smallwood_lvcs_planner_projection_v1(
            &statement,
            78,
            0,
            profile,
            SmallwoodLvcsPlannerGeometryKindV1::CurrentTiledRowsV1,
        )
        .unwrap();
        let level5 = projected_candidate_proof_bytes_with_profile_and_backend(
            &statement,
            profile,
            SmallwoodTranscriptBackend::Sha512Level5,
        )
        .unwrap();
        let legacy = projected_candidate_proof_bytes_with_profile_and_backend(
            &statement,
            profile,
            SmallwoodTranscriptBackend::Blake3,
        )
        .unwrap();

        assert_eq!(planner.projected_inner_proof_bytes, level5);
        assert_eq!(
            level5 - legacy,
            (1 + profile.decs_nb_opened_evals * profile.decs_nb_evals.ilog2() as usize)
                * (DIGEST_BYTES - LEGACY_DIGEST_BYTES)
        );
    }

    #[test]
    fn uniform_decs_soundness_report_uses_committed_support_theorem() {
        const COMPRESSED_ROW_COUNT: usize = 699;
        const COMPRESSED_CONSTRAINT_COUNT: usize = 890;
        const PRODUCTION_PUBLIC_VALUE_COUNT: usize = 78;

        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
            COMPRESSED_ROW_COUNT,
            64,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as usize,
            COMPRESSED_CONSTRAINT_COUNT,
            0,
        )
        .unwrap();
        let soundness = report_smallwood_no_grinding_soundness_v1(
            &statement,
            PRODUCTION_PUBLIC_VALUE_COUNT,
            LEVEL5_SMALLWOOD_NO_GRINDING_PROFILE,
        )
        .unwrap();
        assert_eq!(
            soundness.epsilon1_model,
            SmallwoodDecsSoundnessModelV1::UniformMatrixCommittedSupport
        );
        assert!(soundness.epsilon1_floor_bits > 319.0);
        assert!(soundness.epsilon1_floor_bits < 321.0);
        assert!(soundness.security_floor_bits > 262.37);
        assert!(soundness.security_floor_bits < 262.39);
        assert!(soundness.meets_128_bit_floor);
        assert!(soundness.meets_256_bit_floor);
        assert!(soundness.meets_260_bit_floor);
        assert!(
            smallwood_no_grinding_exact_128_bit_term_checks(
                &statement,
                PRODUCTION_PUBLIC_VALUE_COUNT,
                LEVEL5_SMALLWOOD_NO_GRINDING_PROFILE,
            )
            .unwrap()[0]
        );
    }

    #[test]
    fn scalar_power_decs_soundness_report_retains_support_union() {
        const ROW_COUNT: usize = 699;
        const CONSTRAINT_COUNT: usize = 890;
        const PUBLIC_VALUE_COUNT: usize = 78;

        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64V1,
            ROW_COUNT,
            64,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as usize,
            CONSTRAINT_COUNT,
            0,
        )
        .unwrap();
        let cfg =
            SmallwoodConfig::new_with_profile(&statement, LEVEL5_SMALLWOOD_NO_GRINDING_PROFILE)
                .unwrap();
        let soundness = report_smallwood_no_grinding_soundness_from_cfg(&cfg, PUBLIC_VALUE_COUNT);
        assert_eq!(
            soundness.epsilon1_model,
            SmallwoodDecsSoundnessModelV1::ScalarPowerSupportUnion
        );

        let terms = smallwood_no_grinding_exact_terms_from_cfg(&cfg, PUBLIC_VALUE_COUNT)
            .expect("historical scalar-power terms");
        let decs_degree = cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals() - 1;
        let expected_numerator = binomial(cfg.decs_nb_evals() as u128, decs_degree + 2).unwrap()
            * BigUint::from(cfg.nb_lvcs_rows).pow(cfg.decs_eta() as u32);
        assert_eq!(terms[0].0, expected_numerator);
    }

    #[test]
    #[ignore = "mutates a freshly generated production proof; covered by native artifact vectors"]
    fn direct_packed_arithmetization_rejects_opened_witness_mode_mismatch() {
        let (material, proof_bytes) = sample_production_candidate();
        let statement = production_statement(material);
        let mut proof = decode_smallwood_proof_bytes_v1(proof_bytes).unwrap();
        proof.opened_witness.mode = SmallwoodOpenedWitnessMode::None;
        let proof_bytes = encode_smallwood_proof_bytes_v1(&proof).unwrap();
        let err = verify_candidate(&statement, &material.transcript_binding, &proof_bytes)
            .expect_err("mode-mismatched direct proof unexpectedly verified");
        assert!(
            err.to_string().contains("row-scalar"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[ignore = "mutates a freshly generated production proof; covered by native artifact vectors"]
    fn direct_packed_arithmetization_rejects_auxiliary_witness_limb_count_overflow() {
        let (material, proof_bytes) = sample_production_candidate();
        let mut proof = decode_smallwood_proof_bytes_v1(proof_bytes).unwrap();
        match &mut proof.opened_witness.mode {
            SmallwoodOpenedWitnessMode::RowScalars {
                auxiliary_words,
                auxiliary_limb_count,
                ..
            } => {
                assert_eq!(
                    auxiliary_words.len(),
                    material.auxiliary_witness_words.len()
                );
                *auxiliary_limb_count = auxiliary_words.len() + 1;
            }
            mode => panic!("unexpected opened witness mode for direct packed proof: {mode:?}"),
        }
        let err = encode_smallwood_proof_bytes_v1(&proof)
            .expect_err("canonical encoder accepted an overflowing auxiliary limb count");
        assert!(err.to_string().contains("auxiliary"));
    }

    #[test]
    #[ignore = "mutates a freshly generated production proof; covered by native artifact vectors"]
    fn direct_packed_arithmetization_rejects_nonzero_auxiliary_padding() {
        let (material, proof_bytes) = sample_production_candidate();
        let statement = production_statement(material);
        let mut proof = decode_smallwood_proof_bytes_v1(proof_bytes).unwrap();
        match &mut proof.opened_witness.mode {
            SmallwoodOpenedWitnessMode::RowScalars {
                auxiliary_words,
                auxiliary_limb_count,
                ..
            } => {
                *auxiliary_limb_count = auxiliary_words.len();
                auxiliary_words.push(1);
            }
            mode => panic!("unexpected opened witness mode for direct packed proof: {mode:?}"),
        }
        let err = verify_candidate(
            &statement,
            &material.transcript_binding,
            &encode_smallwood_proof_bytes_v1(&proof).unwrap(),
        )
        .expect_err("direct proof with nonzero auxiliary padding unexpectedly verified");
        assert!(err.to_string().contains("padding"));
    }

    #[test]
    #[ignore = "full production PCS forgery campaign runs explicitly in release mode"]
    fn verifier_rejects_forged_self_consistent_pcs_layer() {
        let witness = sample_witness();
        let material = build_production_smallwood_frontend_material_from_witness(&witness).unwrap();
        let statement = production_statement(&material);
        let cfg = SmallwoodConfig::new(&statement).unwrap();
        let mut proof = prove_smallwood_candidate_with_arithmetization(
            &witness,
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
        )
        .unwrap();
        let mut outer = decode_smallwood_candidate_proof_for_test(&proof.stark_proof);
        let mut inner = decode_smallwood_proof_bytes_v1(&outer.ark_proof).unwrap();

        let transcript_backend = SmallwoodTranscriptBackend::Sha512Level5;
        let eval_points = canonical_piop_opening_points(
            &cfg.packing_points,
            cfg.profile,
            &inner.nonce,
            &inner.h_piop,
            transcript_backend,
        )
        .unwrap();
        let forged_partial_evals =
            vec![vec![0u64; cfg.nb_unstacked_cols - cfg.nb_polys]; cfg.nb_opened_evals()];
        let forged_combi_heads = pcs_reconstruct_combi_heads(
            &cfg,
            &eval_points,
            inner.opened_witness.row_scalars_ref().unwrap(),
            &forged_partial_evals,
        )
        .unwrap();
        let forged_rcombi_tails =
            vec![vec![0u64; cfg.decs_nb_opened_evals()]; cfg.nb_lvcs_opened_combi];
        let trans_hash = hash_challenge_opening_decs(
            &cfg,
            &forged_combi_heads,
            &inner.h_piop,
            &forged_rcombi_tails,
            transcript_backend,
        );
        let (leaves_indexes, _) = xof_decs_opening(
            cfg.decs_nb_evals(),
            cfg.decs_nb_opened_evals(),
            cfg.decs_pow_bits(),
            &trans_hash,
            transcript_backend,
        )
        .unwrap();
        let decs_eval_points = decs_field_evaluation_points(
            SmallwoodDecsEvaluationDomain::Radix2Subgroup,
            cfg.decs_nb_evals(),
            cfg.nb_lvcs_cols + cfg.decs_nb_opened_evals(),
            &leaves_indexes,
        )
        .unwrap();
        let zero_rows = vec![
            vec![0u64; cfg.nb_lvcs_rows - cfg.nb_lvcs_opened_combi];
            cfg.decs_nb_opened_evals()
        ];
        let zero_masking = vec![vec![0u64; cfg.decs_eta()]; cfg.decs_nb_opened_evals()];
        let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
        pcs_build_coefficients(&cfg, &eval_points, &mut coeffs);
        let forged_rows = lvcs_recompute_rows(
            &cfg,
            &coeffs,
            &forged_combi_heads,
            &forged_rcombi_tails,
            &zero_rows,
            &decs_eval_points,
        )
        .unwrap();
        let zero_leaf = hash_merkle_leave(
            cfg.nb_lvcs_rows,
            &vec![0u64; cfg.nb_lvcs_rows + cfg.decs_eta()],
            &inner.salt,
            transcript_backend,
        );
        let mut leaf_hashes = vec![zero_leaf; cfg.decs_nb_evals()];
        for (row, (&leaf, masking)) in forged_rows
            .iter()
            .zip(leaves_indexes.iter().zip(zero_masking.iter()))
        {
            let mut leaf_evals = row.clone();
            leaf_evals.extend_from_slice(masking);
            leaf_hashes[leaf as usize] = hash_merkle_leave(
                cfg.nb_lvcs_rows,
                &leaf_evals,
                &inner.salt,
                transcript_backend,
            );
        }
        let mut levels = vec![leaf_hashes];
        merkle_build_levels(&mut levels, transcript_backend);
        let auth_paths = compact_merkle_auth_paths(
            &levels,
            &leaves_indexes
                .iter()
                .map(|leaf| *leaf as usize)
                .collect::<Vec<_>>(),
        );

        inner.pcs = PcsProof {
            rcombi_tails: forged_rcombi_tails,
            subset_evals: zero_rows,
            partial_evals: forged_partial_evals,
            decs: DecsProof {
                auth_paths,
                leaf_tapes: Vec::new(),
                masking_evals: zero_masking,
                high_coeffs: vec![vec![0u64; cfg.nb_lvcs_cols]; cfg.decs_eta()],
            },
        };

        outer.ark_proof = encode_smallwood_proof_bytes_v1(&inner).unwrap();
        proof.stark_proof = encode_smallwood_candidate_proof(
            outer.arithmetization,
            outer.ark_proof,
            &outer.auxiliary_witness_words,
        )
        .unwrap();

        let err = verify_smallwood_candidate_transaction_proof(&proof)
            .expect_err("forged self-consistent PCS layer unexpectedly verified");
        assert_eq!(
            err.to_string(),
            "constraint system violated: smallwood piop transcript hash mismatch",
            "forged PCS layer rejected outside the PCS-to-PIOP equation binding: {err}"
        );
    }

    #[test]
    #[ignore = "debug probe for LVCS/DECS row reconstruction"]
    fn lvcs_reconstructed_rows_match_opened_rows() {
        let witness = sample_witness();
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let statement = PackedStatement::new(
            SmallwoodArithmetization::Bridge64V1,
            &material.public_statement.public_values,
            material.public_statement.lppc_row_count as usize,
            SMALLWOOD_BRIDGE_PACKING_FACTOR,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as usize,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        );
        let cfg = SmallwoodConfig::new(&statement).unwrap();
        let binded_words = bytes_to_words(&material.transcript_binding).unwrap();
        let witness_polys = material
            .packed_witness_rows
            .chunks_exact(SMALLWOOD_BRIDGE_PACKING_FACTOR)
            .map(|row_values| {
                poly_interpolate_random(row_values, &cfg.packing_points, SMALLWOOD_NB_OPENED_EVALS)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mpol_ppoly = (0..SMALLWOOD_RHO)
            .map(|_| random_poly(cfg.mpol_poly_degree).unwrap())
            .collect::<Vec<_>>();
        let mpol_plin = (0..SMALLWOOD_RHO)
            .map(|_| poly_random_sum_zero(&cfg.packing_points, cfg.mlin_poly_degree).unwrap())
            .collect::<Vec<_>>();
        let salt = random_bytes::<SALT_BYTES>().unwrap();
        let (pcs_key, pcs_transcript_words) = pcs_commit(
            &cfg,
            &witness_polys,
            &mpol_ppoly,
            &mpol_plin,
            &salt,
            SmallwoodTranscriptBackend::Blake3,
            SmallwoodDecsEvaluationDomain::Consecutive,
            &binded_words,
            0,
        )
        .unwrap();
        let mut piop_input = pcs_transcript_words;
        piop_input.extend_from_slice(&binded_words);
        let piop = piop_run(
            &cfg,
            &statement,
            &witness_polys,
            &mpol_ppoly,
            &mpol_plin,
            &piop_input,
            SmallwoodTranscriptBackend::Blake3,
        )
        .unwrap();
        let h_piop =
            hash_piop_transcript(&piop.transcript_words, SmallwoodTranscriptBackend::Blake3);
        let nonce =
            choose_opening_nonce(&cfg, &h_piop, SmallwoodTranscriptBackend::Blake3).unwrap();
        let eval_points =
            xof_piop_opening_points(&nonce, &h_piop, SmallwoodTranscriptBackend::Blake3);
        let mut coeffs = vec![vec![0u64; cfg.nb_lvcs_rows]; cfg.nb_lvcs_opened_combi];
        pcs_build_coefficients(&cfg, &eval_points, &mut coeffs);
        let (original_combi_heads, original_rcombi_tails, original_subset_evals, _original_decs) =
            lvcs_open(
                &cfg,
                &pcs_key.lvcs_key,
                &coeffs,
                &h_piop,
                SmallwoodTranscriptBackend::Blake3,
                SmallwoodDecsEvaluationDomain::Consecutive,
            )
            .unwrap();
        let (pcs_proof, opened_witness) = pcs_open(
            &cfg,
            &pcs_key,
            &witness_polys,
            &mpol_ppoly,
            &mpol_plin,
            &eval_points,
            &h_piop,
            SmallwoodTranscriptBackend::Blake3,
            SmallwoodDecsEvaluationDomain::Consecutive,
        )
        .unwrap();
        assert_eq!(pcs_proof.rcombi_tails, original_rcombi_tails);
        assert_eq!(pcs_proof.subset_evals, original_subset_evals);
        let combi_heads = pcs_reconstruct_combi_heads(
            &cfg,
            &eval_points,
            opened_witness.row_scalars_ref().unwrap(),
            &pcs_proof.partial_evals,
        )
        .unwrap();
        assert_eq!(combi_heads, original_combi_heads);
        let trans_hash = hash_challenge_opening_decs(
            &cfg,
            &combi_heads,
            &h_piop,
            &pcs_proof.rcombi_tails,
            SmallwoodTranscriptBackend::Blake3,
        );
        let (leaves_indexes, _) = xof_decs_opening(
            SMALLWOOD_DECS_NB_EVALS,
            SMALLWOOD_DECS_NB_OPENED_EVALS,
            SMALLWOOD_DECS_POW_BITS,
            &trans_hash,
            SmallwoodTranscriptBackend::Blake3,
        )
        .unwrap();
        let decs_eval_points = leaves_indexes
            .iter()
            .map(|&idx| idx as u64)
            .collect::<Vec<_>>();
        let rows = lvcs_recompute_rows(
            &cfg,
            &coeffs,
            &combi_heads,
            &pcs_proof.rcombi_tails,
            &pcs_proof.subset_evals,
            &decs_eval_points,
        )
        .unwrap();
        let opened_rows = decs_eval_points
            .iter()
            .map(|&idx| {
                pcs_key
                    .lvcs_key
                    .decs_key
                    .committed_domain_evals
                    .iter()
                    .map(|poly| poly[idx as usize])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut direct_q = vec![vec![0u64; cfg.nb_lvcs_opened_combi]; decs_eval_points.len()];
        for (j, opened_row) in opened_rows.iter().enumerate() {
            for k in 0..cfg.nb_lvcs_opened_combi {
                let mut acc = 0u64;
                for (coeff, value) in coeffs[k].iter().zip(opened_row.iter()) {
                    acc = add_mod(acc, mul_mod(*coeff, *value));
                }
                direct_q[j][k] = acc;
            }
        }
        let mut poly_q = vec![vec![0u64; cfg.nb_lvcs_opened_combi]; decs_eval_points.len()];
        let mut extended_combis = vec![
            vec![0u64; cfg.nb_lvcs_cols + SMALLWOOD_DECS_NB_OPENED_EVALS];
            cfg.nb_lvcs_opened_combi
        ];
        for k in 0..cfg.nb_lvcs_opened_combi {
            extended_combis[k][..cfg.nb_lvcs_cols].copy_from_slice(&combi_heads[k]);
            extended_combis[k][cfg.nb_lvcs_cols..].copy_from_slice(&pcs_proof.rcombi_tails[k]);
        }
        let combi_polys = extended_combis
            .iter()
            .map(|combi| {
                interpolate_consecutive(&rotate_left_words(combi, cfg.nb_lvcs_cols)).unwrap()
            })
            .collect::<Vec<_>>();
        for (j, &point) in decs_eval_points.iter().enumerate() {
            for (k, poly) in combi_polys.iter().enumerate() {
                poly_q[j][k] = poly_eval(poly, point);
            }
        }
        assert_eq!(poly_q, direct_q);
        assert_eq!(rows, opened_rows);
    }

    #[test]
    #[ignore = "diagnostic for deciding whether a full DECS multiproof is worth the churn"]
    fn compact_decs_auth_path_dedup_budget_report() {
        let witness = sample_witness();
        let material = build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        let statement = PackedStatement::new(
            SmallwoodArithmetization::DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1,
            &material.public_statement.public_values,
            material.public_statement.lppc_row_count as usize,
            material.public_statement.lppc_packing_factor as usize,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as usize,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        );
        let proof_bytes = prove_candidate(
            &statement,
            &material.packed_expanded_witness,
            &material.transcript_binding,
        )
        .unwrap();
        let trace = build_smallwood_verifier_trace_v1(
            &statement,
            &material.transcript_binding,
            &proof_bytes,
            SmallwoodTranscriptBackend::Blake3,
        )
        .unwrap();
        let mut current_indices = trace
            .pcs_trace
            .decs_leaf_indexes
            .iter()
            .map(|&idx| idx as usize)
            .collect::<Vec<_>>();
        let depth = SMALLWOOD_DECS_NB_EVALS.ilog2() as usize;
        let mut total_nodes = 0usize;
        let mut unique_nodes = std::collections::BTreeSet::new();
        for level in 0..depth {
            let level_indices = current_indices
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            for &index in &current_indices {
                let sibling_index = if index.is_multiple_of(2) {
                    index + 1
                } else {
                    index - 1
                };
                if !level_indices.contains(&sibling_index) {
                    total_nodes += 1;
                    unique_nodes.insert((level, sibling_index));
                }
            }
            current_indices = current_indices.iter().map(|index| index / 2).collect();
        }
        let duplicated_nodes = total_nodes - unique_nodes.len();
        eprintln!(
            "compact auth-path nodes total={} unique={} duplicated={} max_digest_savings_bytes={}",
            total_nodes,
            unique_nodes.len(),
            duplicated_nodes,
            duplicated_nodes * DIGEST_BYTES
        );
        assert_eq!(
            total_nodes,
            trace
                .proof
                .pcs
                .decs
                .auth_paths
                .iter()
                .map(|path| path.len())
                .sum::<usize>()
        );
    }

    #[test]
    fn interpolate_consecutive_roundtrips_small_examples() {
        let samples = [
            vec![5u64],
            vec![3u64, 7],
            vec![9u64, 2, 4],
            vec![1u64, 8, 6, 5],
            vec![11u64, 22, 33, 44, 55],
        ];
        for evals in samples {
            let poly = interpolate_consecutive(&evals).unwrap();
            let recovered = (0..evals.len())
                .map(|point| poly_eval(&poly, point as u64))
                .collect::<Vec<_>>();
            assert_eq!(recovered, evals);
        }
    }

    #[test]
    fn barycentric_consecutive_evaluation_matches_coefficient_form() {
        for size in [1usize, 2, 3, 8, 67, 141] {
            let values = (0..size)
                .map(|index| {
                    reduce128(
                        (index as u128 + 1) * (index as u128 + 17) * 0x9e37_79b9_7f4a_7c15u128,
                    )
                })
                .collect::<Vec<_>>();
            let polynomial = interpolate_consecutive(&values).unwrap();
            let points = [
                0u64,
                (size - 1) as u64,
                size as u64,
                size as u64 + 13,
                16_383,
                32_767,
            ];
            for point in points {
                assert_eq!(
                    evaluate_consecutive_values(&values, point).unwrap(),
                    poly_eval(&polynomial, point),
                    "size={size} point={point}"
                );
            }
        }
    }

    #[test]
    fn extend_consecutive_matches_interpolated_polynomial() {
        let initial = vec![9u64, 2, 4];
        let poly = interpolate_consecutive(&initial).unwrap();
        let extended = extend_consecutive_evals(&initial, 8);
        let expected = (0..8)
            .map(|point| poly_eval(&poly, point as u64))
            .collect::<Vec<_>>();
        assert_eq!(extended, expected);
    }

    #[test]
    fn radix2_subgroup_evaluation_matches_direct_polynomial_evaluation() {
        for size in [2usize, 4, 8, 32, 256] {
            let poly = (0..(size / 2))
                .map(|index| reduce128((index as u128 + 3) * 0x9e37_79b9_7f4a_7c15u128))
                .collect::<Vec<_>>();
            let root = radix2_subgroup_generator(size).unwrap();
            let mut actual = vec![0u64; size];
            evaluate_poly_on_radix2_subgroup_into(&poly, &mut actual).unwrap();
            let mut point = 1u64;
            let expected = (0..size)
                .map(|_| {
                    let value = poly_eval(&poly, point);
                    point = mul_mod(point, root);
                    value
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "size={size}");
        }
    }

    #[test]
    fn consecutive_samples_evaluate_on_radix2_subgroup() {
        let initial = vec![9u64, 2, 4, 17, 23];
        let poly = interpolate_consecutive(&initial).unwrap();
        let size = 32usize;
        let root = radix2_subgroup_generator(size).unwrap();
        let mut actual = vec![0u64; size];
        evaluate_consecutive_values_on_radix2_subgroup_into(&initial, &mut actual).unwrap();
        let mut point = 1u64;
        let expected = (0..size)
            .map(|_| {
                let value = poly_eval(&poly, point);
                point = mul_mod(point, root);
                value
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    #[ignore = "release-only DECS subgroup evaluator benchmark"]
    fn production_shape_radix2_subgroup_evaluator_benchmark() {
        let row_count = 134usize;
        let initial_len = 806usize;
        let initial_rows = (0..row_count)
            .map(|row| {
                (0..initial_len)
                    .map(|column| {
                        reduce128(
                            (row as u128 + 1) * (column as u128 + 3) * 0x9e37_79b9_7f4a_7c15u128,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        for domain_size in [32_768usize, 131_072, 262_144] {
            let started = Instant::now();
            let evaluations = initial_rows
                .par_iter()
                .map(|initial| {
                    let mut output = vec![0u64; domain_size];
                    evaluate_consecutive_values_on_radix2_subgroup_into(initial, &mut output)?;
                    Ok::<_, TransactionCircuitError>(output)
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let checksum = evaluations.iter().fold(0u64, |accumulator, row| {
                add_mod(
                    accumulator,
                    add_mod(row[domain_size / 3], row[domain_size - 1]),
                )
            });
            eprintln!(
                "smallwood DECS subgroup evaluator domain={} rows={} initial_len={} elapsed={:?} checksum={}",
                domain_size,
                row_count,
                initial_len,
                started.elapsed(),
                checksum
            );
            drop(evaluations);
        }
    }

    #[test]
    fn blake3_bulk_word_hashing_matches_reference() {
        let domains = [SMALLWOOD_XOF_DOMAIN, SMALLWOOD_COMPRESS2_DOMAIN];
        let samples = [
            Vec::new(),
            vec![7u64],
            vec![1u64, 2, 3, 4],
            (0..8u64).collect::<Vec<_>>(),
            (0..11u64).collect::<Vec<_>>(),
        ];
        for domain in domains {
            for words in &samples {
                for &out_words in &[1usize, 3, 4, 7] {
                    let actual = transcript_xof_words(
                        SmallwoodTranscriptBackend::Blake3,
                        domain,
                        words,
                        out_words,
                    );
                    let expected = transcript_xof_words_blake3_reference(domain, words, out_words);
                    assert_eq!(
                        actual,
                        expected,
                        "domain={domain:?} len={} out={out_words}",
                        words.len()
                    );
                }
            }
        }
    }

    #[test]
    fn blake3_merkle_fast_paths_match_reference() {
        let salt = [9u8; SALT_BYTES];
        let salt_words = bytes_to_words_unchecked(&salt);
        let committed = vec![
            vec![11u64, 12, 13, 14, 15],
            vec![21u64, 22, 23, 24, 25],
            vec![31u64, 32, 33, 34, 35],
        ];
        let masking = vec![vec![41u64, 42, 43, 44, 45], vec![51u64, 52, 53, 54, 55]];
        for leaf_idx in 0..5 {
            let actual = hash_merkle_leave_from_tables(
                &salt_words,
                &committed,
                &masking,
                leaf_idx,
                SmallwoodTranscriptBackend::Blake3,
            );
            let mut input = salt_words.to_vec();
            for poly in &committed {
                input.push(poly[leaf_idx]);
            }
            for poly in &masking {
                input.push(poly[leaf_idx]);
            }
            let expected = words_to_digest(&transcript_xof_words_blake3_reference(
                SMALLWOOD_XOF_DOMAIN,
                &input,
                LEGACY_DIGEST_WORDS,
            ));
            assert_eq!(actual, expected, "leaf_idx={leaf_idx}");
        }

        let mut levels = vec![vec![
            [1u8; DIGEST_BYTES],
            [2u8; DIGEST_BYTES],
            [3u8; DIGEST_BYTES],
            [4u8; DIGEST_BYTES],
            [5u8; DIGEST_BYTES],
        ]];
        let mut expected_levels = levels.clone();
        let actual_root = merkle_build_levels(&mut levels, SmallwoodTranscriptBackend::Blake3);
        let expected_root = merkle_build_levels_blake3_reference(&mut expected_levels);
        assert_eq!(actual_root, expected_root);
        assert_eq!(levels, expected_levels);

        let actual_root_hash =
            hash_merkle_root(&salt, &actual_root, SmallwoodTranscriptBackend::Blake3);
        let mut root_words = bytes_to_words_unchecked(&salt);
        root_words.extend(digest_to_words(
            &actual_root,
            SmallwoodTranscriptBackend::Blake3,
        ));
        let expected_root_hash = words_to_digest(&transcript_xof_words_blake3_reference(
            SMALLWOOD_XOF_DOMAIN,
            &root_words,
            LEGACY_DIGEST_WORDS,
        ));
        assert_eq!(actual_root_hash, expected_root_hash);
    }
}

fn rotate_left_words(values: &[u64], by: usize) -> Vec<u64> {
    let n = values.len();
    let by = by % n;
    values[by..]
        .iter()
        .chain(values[..by].iter())
        .copied()
        .collect()
}

fn poly_interpolate_random(
    evals: &[u64],
    eval_points: &[u64],
    nb_random: usize,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let rnd = random_vec(nb_random)?;
    poly_restore(&rnd, evals, eval_points, evals.len() + nb_random - 1)
}

fn poly_random_sum_zero(
    eval_points: &[u64],
    degree: usize,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut p = vec![0u64; degree + 1];
    let rnd = random_vec(degree)?;
    p[1..].copy_from_slice(&rnd);
    let mut acc = 0u64;
    let mut factor = 0u64;
    for &point in eval_points {
        acc = add_mod(acc, poly_eval(&p, point));
        factor = add_mod(factor, 1);
    }
    p[0] = div_mod(neg_mod(acc), factor);
    Ok(p)
}

fn poly_eval(poly: &[u64], point: u64) -> u64 {
    let mut acc = *poly.last().unwrap_or(&0);
    for coeff in poly.iter().rev().skip(1) {
        acc = add_mod(mul_mod(acc, point), *coeff);
    }
    acc
}

fn pow_mod(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exponent >>= 1;
    }
    canon(result)
}

fn radix2_subgroup_generator(size: usize) -> Result<u64, TransactionCircuitError> {
    if !size.is_power_of_two() || (size as u64) > (1u64 << GOLDILOCKS_TWO_ADICITY) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS subgroup size must be a power of two no larger than 2^32",
        ));
    }
    let size_u64 = u64::try_from(size).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood DECS subgroup size does not fit u64",
        )
    })?;
    let log_size = size_u64.ilog2();
    let root = pow_mod(
        GOLDILOCKS_TWO_ADIC_ROOT,
        1u64 << (GOLDILOCKS_TWO_ADICITY - log_size),
    );
    if pow_mod(root, size_u64) != 1 || (size > 1 && pow_mod(root, size_u64 / 2) == 1) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS subgroup generator has the wrong order",
        ));
    }
    Ok(root)
}

const SMALLWOOD_STRICT_ZK_COSET_SEARCH_LIMIT: usize = 1 << 12;

/// Return whether `shift * H` avoids every LVCS interpolation point
/// `0, ..., interpolation_point_count - 1`, where `H` is the radix-2
/// subgroup of `domain_size` elements.
///
/// SmallWood's LVCS hiding proof requires this disjointness.  Merely choosing
/// a large evaluation domain is not sufficient: the active `2^20` subgroup
/// contains the ordinary field element 64, which is an actual LVCS coordinate
/// for the 375-column/23-randomizer geometry.
fn radix2_coset_is_disjoint_from_interpolation_domain(
    domain_size: usize,
    interpolation_point_count: usize,
    shift: u64,
) -> Result<bool, TransactionCircuitError> {
    if shift == 0 || shift >= FIELD_ORDER {
        return Ok(false);
    }
    let domain_size = u64::try_from(domain_size).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood DECS coset domain size does not fit the field wire",
        )
    })?;
    let shift_inv = inv_mod(shift)?;
    for point in 1..interpolation_point_count {
        let point = u64::try_from(point).map_err(|_| {
            TransactionCircuitError::ConstraintViolation(
                "smallwood LVCS interpolation point does not fit the field wire",
            )
        })?;
        if pow_mod(mul_mod(point, shift_inv), domain_size) == 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Deterministically select the first small multiplicative coset that is
/// disjoint from the complete LVCS interpolation domain.  The value is
/// derived solely from proof geometry and therefore adds no proof bytes.
fn radix2_disjoint_coset_shift(
    domain_size: usize,
    interpolation_point_count: usize,
) -> Result<u64, TransactionCircuitError> {
    if interpolation_point_count == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood LVCS interpolation domain must not be empty",
        ));
    }
    let start = u64::try_from(interpolation_point_count).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "smallwood LVCS interpolation domain does not fit the field wire",
        )
    })?;
    for offset in 0..SMALLWOOD_STRICT_ZK_COSET_SEARCH_LIMIT {
        let candidate = start.checked_add(offset as u64).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "smallwood strict-ZK DECS coset search overflow",
            ),
        )?;
        if radix2_coset_is_disjoint_from_interpolation_domain(
            domain_size,
            interpolation_point_count,
            candidate,
        )? {
            return Ok(candidate);
        }
    }
    Err(TransactionCircuitError::ConstraintViolation(
        "smallwood strict-ZK DECS coset search exhausted",
    ))
}

/// Canonical, executable description of the strict DECS evaluation domain.
///
/// The shift is not caller-selected metadata.  It is deterministically
/// derived from the exact radix-2 domain size and the complete interpolation
/// length, including every LVCS random-tail coordinate.  Construction checks
/// the entire interpolation set `0..interpolation_point_count`; because the
/// packing coordinates are a prefix of that set, this also excludes every
/// packing-domain intersection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SmallwoodDisjointCosetDescriptorV1 {
    pub(crate) domain_size: usize,
    pub(crate) interpolation_point_count: usize,
    pub(crate) shift: u64,
}

impl SmallwoodDisjointCosetDescriptorV1 {
    pub(crate) fn derive(
        domain_size: usize,
        interpolation_point_count: usize,
    ) -> Result<Self, TransactionCircuitError> {
        if !domain_size.is_power_of_two()
            || interpolation_point_count == 0
            || interpolation_point_count > domain_size
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-ZK DECS coset geometry is invalid",
            ));
        }
        // This also rejects domains beyond the Goldilocks two-adicity.
        let _ = radix2_subgroup_generator(domain_size)?;
        let shift = radix2_disjoint_coset_shift(domain_size, interpolation_point_count)?;
        if !radix2_coset_is_disjoint_from_interpolation_domain(
            domain_size,
            interpolation_point_count,
            shift,
        )? {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood strict-ZK DECS coset intersects the interpolation domain",
            ));
        }
        Ok(Self {
            domain_size,
            interpolation_point_count,
            shift,
        })
    }

    pub(crate) fn point_for_leaf_index(
        self,
        leaf_index: usize,
    ) -> Result<u64, TransactionCircuitError> {
        if leaf_index >= self.domain_size {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood DECS leaf index exceeds the evaluation domain",
            ));
        }
        let root = radix2_subgroup_generator(self.domain_size)?;
        Ok(mul_mod(self.shift, pow_mod(root, leaf_index as u64)))
    }
}

fn decs_field_evaluation_points(
    domain: SmallwoodDecsEvaluationDomain,
    domain_size: usize,
    interpolation_point_count: usize,
    leaf_indexes: &[u32],
) -> Result<Vec<u64>, TransactionCircuitError> {
    match domain {
        SmallwoodDecsEvaluationDomain::Consecutive => {
            Ok(leaf_indexes.iter().map(|&index| u64::from(index)).collect())
        }
        SmallwoodDecsEvaluationDomain::Radix2Subgroup => {
            let root = radix2_subgroup_generator(domain_size)?;
            leaf_indexes
                .iter()
                .map(|&index| {
                    if index as usize >= domain_size {
                        return Err(TransactionCircuitError::ConstraintViolation(
                            "smallwood DECS leaf index exceeds the evaluation domain",
                        ));
                    }
                    Ok(pow_mod(root, u64::from(index)))
                })
                .collect()
        }
        SmallwoodDecsEvaluationDomain::Radix2DisjointCoset => {
            let descriptor =
                SmallwoodDisjointCosetDescriptorV1::derive(domain_size, interpolation_point_count)?;
            leaf_indexes
                .iter()
                .map(|&index| descriptor.point_for_leaf_index(index as usize))
                .collect()
        }
    }
}

fn radix2_fft_in_place(values: &mut [u64], root: u64) {
    let size = values.len();
    let mut reversed = 0usize;
    for index in 1..size {
        let mut bit = size >> 1;
        while reversed & bit != 0 {
            reversed ^= bit;
            bit >>= 1;
        }
        reversed ^= bit;
        if index < reversed {
            values.swap(index, reversed);
        }
    }

    let mut width = 2usize;
    while width <= size {
        let twiddle_step = pow_mod(root, (size / width) as u64);
        for block in values.chunks_exact_mut(width) {
            let mut twiddle = 1u64;
            let half = width / 2;
            for offset in 0..half {
                let even = block[offset];
                let odd = mul_mod(block[offset + half], twiddle);
                block[offset] = add_mod(even, odd);
                block[offset + half] = sub_mod(even, odd);
                twiddle = mul_mod(twiddle, twiddle_step);
            }
        }
        width <<= 1;
    }
}

fn evaluate_poly_on_radix2_subgroup_into(
    poly: &[u64],
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    if poly.len() > out.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS polynomial degree exceeds subgroup domain",
        ));
    }
    let root = radix2_subgroup_generator(out.len())?;
    out.fill(0);
    out[..poly.len()].copy_from_slice(poly);
    radix2_fft_in_place(out, root);
    Ok(())
}

/// Evaluate a coefficient-form polynomial on `shift * H`, where `H` is the
/// radix-2 subgroup represented by the FFT order.  Multiplying coefficient
/// `a_k` by `shift^k` turns `P(shift * X)` into an ordinary subgroup FFT.
fn evaluate_poly_on_radix2_coset_into(
    poly: &[u64],
    out: &mut [u64],
    shift: u64,
) -> Result<(), TransactionCircuitError> {
    if poly.len() > out.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS polynomial degree exceeds coset domain",
        ));
    }
    if shift == 0 || shift >= FIELD_ORDER {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood DECS coset shift is not a nonzero field element",
        ));
    }
    let root = radix2_subgroup_generator(out.len())?;
    out.fill(0);
    let mut shift_power = 1u64;
    for (slot, &coefficient) in out.iter_mut().zip(poly.iter()) {
        *slot = mul_mod(coefficient, shift_power);
        shift_power = mul_mod(shift_power, shift);
    }
    radix2_fft_in_place(out, root);
    Ok(())
}

fn evaluate_consecutive_values_on_radix2_subgroup_into(
    initial: &[u64],
    out: &mut [u64],
) -> Result<(), TransactionCircuitError> {
    let coefficients = interpolate_consecutive(initial)?;
    evaluate_poly_on_radix2_subgroup_into(&coefficients, out)
}

fn evaluate_consecutive_values_on_radix2_coset_into(
    initial: &[u64],
    out: &mut [u64],
    shift: u64,
) -> Result<(), TransactionCircuitError> {
    let coefficients = interpolate_consecutive(initial)?;
    evaluate_poly_on_radix2_coset_into(&coefficients, out, shift)
}

fn evaluate_poly_on_consecutive_domain_into(
    poly: &[u64],
    out: &mut [u64],
    initial: &mut Vec<u64>,
    work: &mut Vec<u64>,
    diffs: &mut Vec<u64>,
) {
    let initial_len = poly.len();
    initial.clear();
    initial.reserve(initial_len);
    for point in 0..initial_len {
        initial.push(poly_eval(poly, point as u64));
    }
    extend_consecutive_evals_into(initial, out, work, diffs);
}

#[cfg(test)]
fn extend_consecutive_evals(initial: &[u64], total_len: usize) -> Vec<u64> {
    let mut work = Vec::new();
    let mut diffs = Vec::new();
    let mut out = vec![0u64; total_len];
    extend_consecutive_evals_into(initial, &mut out, &mut work, &mut diffs);
    if total_len <= initial.len() {
        out.truncate(total_len);
    }
    out
}

fn extend_consecutive_evals_into(
    initial: &[u64],
    out: &mut [u64],
    work: &mut Vec<u64>,
    diffs: &mut Vec<u64>,
) {
    if initial.is_empty() || out.is_empty() {
        return;
    }
    let n = initial.len();
    let keep = out.len().min(n);
    out[..keep].copy_from_slice(&initial[..keep]);
    if out.len() <= n {
        return;
    }

    work.clear();
    work.extend_from_slice(initial);
    diffs.clear();
    diffs.reserve(n);
    diffs.push(work[n - 1]);
    for order in 1..n {
        for idx in 0..(n - order) {
            work[idx] = sub_mod(work[idx + 1], work[idx]);
        }
        diffs.push(work[n - order - 1]);
    }
    for slot in out.iter_mut().skip(n) {
        for idx in (0..(diffs.len() - 1)).rev() {
            diffs[idx] = add_mod(diffs[idx], diffs[idx + 1]);
        }
        *slot = diffs[0];
    }
}

fn poly_interpolate_generic(evals: &[u64], eval_points: &[u64]) -> Vec<u64> {
    let degree = evals.len() - 1;
    let mut p = vec![0u64; degree + 1];
    for i in 0..evals.len() {
        let mut lag = vec![0u64; degree + 1];
        lag[0] = 1;
        let mut acc = 1u64;
        for j in 0..evals.len() {
            if j == i {
                continue;
            }
            lag = poly_mul_linear_normalized(&lag, eval_points[j]);
            acc = mul_mod(acc, sub_mod(eval_points[i], eval_points[j]));
        }
        let scale = div_mod(evals[i], acc);
        poly_add_assign_scaled(&mut p, &lag, scale);
    }
    p
}

fn interpolate_consecutive(evals: &[u64]) -> Result<Vec<u64>, TransactionCircuitError> {
    let n = evals.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut dd = evals.to_vec();
    for order in 1..n {
        let inv = inv_mod(order as u64)?;
        for i in (order..n).rev() {
            dd[i] = mul_mod(sub_mod(dd[i], dd[i - 1]), inv);
        }
    }
    let mut poly = vec![0u64; n];
    let mut basis = vec![1u64];
    for (k, coeff) in dd.iter().enumerate() {
        poly_add_assign_scaled(&mut poly, &basis, *coeff);
        if k + 1 < n {
            basis = poly_mul_linear_normalized(&basis, k as u64);
        }
    }
    Ok(poly)
}

fn build_consecutive_barycentric_weights(size: usize) -> Result<Vec<u64>, TransactionCircuitError> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut factorials = vec![1u64; size];
    for index in 1..size {
        factorials[index] = mul_mod(factorials[index - 1], index as u64);
    }
    let mut inverse_factorials = vec![1u64; size];
    inverse_factorials[size - 1] = inv_mod(factorials[size - 1])?;
    for index in (1..size).rev() {
        inverse_factorials[index - 1] = mul_mod(inverse_factorials[index], index as u64);
    }
    Ok((0..size)
        .map(|index| {
            let magnitude = mul_mod(
                inverse_factorials[index],
                inverse_factorials[size - 1 - index],
            );
            if (size - 1 - index).is_multiple_of(2) {
                magnitude
            } else {
                neg_mod(magnitude)
            }
        })
        .collect())
}

fn cached_consecutive_barycentric_weights(
    size: usize,
) -> Result<Arc<Vec<u64>>, TransactionCircuitError> {
    let cache = CONSECUTIVE_BARYCENTRIC_WEIGHT_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(cached) = cache
        .lock()
        .expect("barycentric weight cache mutex")
        .get(&size)
    {
        return Ok(cached.clone());
    }
    let built = Arc::new(build_consecutive_barycentric_weights(size)?);
    let mut guard = cache.lock().expect("barycentric weight cache mutex");
    Ok(guard.entry(size).or_insert_with(|| built.clone()).clone())
}

/// Evaluates the unique polynomial represented by values at `0..values.len()`.
///
/// The direct Lagrange form uses prefix and suffix products. It is linear in
/// the number of values and is exactly equivalent to interpolating coefficient
/// form and applying Horner evaluation.
fn evaluate_consecutive_values(values: &[u64], point: u64) -> Result<u64, TransactionCircuitError> {
    if values.is_empty() {
        return Ok(0);
    }
    if point < values.len() as u64 {
        return Ok(values[point as usize]);
    }

    let weights = cached_consecutive_barycentric_weights(values.len())?;
    let mut prefix = vec![1u64; values.len() + 1];
    for index in 0..values.len() {
        prefix[index + 1] = mul_mod(prefix[index], sub_mod(point, index as u64));
    }
    let mut suffix = vec![1u64; values.len() + 1];
    for index in (0..values.len()).rev() {
        suffix[index] = mul_mod(suffix[index + 1], sub_mod(point, index as u64));
    }

    let mut result = 0u64;
    for index in 0..values.len() {
        let omitted_product = mul_mod(prefix[index], suffix[index + 1]);
        let basis = mul_mod(weights[index], omitted_product);
        result = add_mod(result, mul_mod(values[index], basis));
    }
    Ok(result)
}

pub fn interpolate_smallwood_consecutive_row_v1(
    evals: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    interpolate_consecutive(evals)
}

fn poly_set_lagrange(points: &[u64], ind: usize) -> Vec<u64> {
    let degree = points.len() - 1;
    let mut lag = vec![0u64; degree + 1];
    lag[0] = 1;
    let mut acc = 1u64;
    for (j, point) in points.iter().enumerate() {
        if j == ind {
            continue;
        }
        lag = poly_mul_linear_normalized(&lag, *point);
        acc = mul_mod(acc, sub_mod(points[ind], *point));
    }
    let scale = div_mod(1, acc);
    poly_mul_scalar(&lag, scale)
}

fn build_lagrange_basis(
    packing_factor: usize,
    packing_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let mut out = Vec::with_capacity(packing_factor);
    let consecutive = points_are_consecutive(packing_points);
    for j in 0..packing_factor {
        let evals = (0..packing_factor)
            .map(|idx| if idx == j { 1 } else { 0 })
            .collect::<Vec<_>>();
        out.push(if consecutive {
            interpolate_consecutive(&evals)?
        } else {
            poly_interpolate_generic(&evals, packing_points)
        });
    }
    Ok(out)
}

fn cached_lagrange_basis(
    packing_factor: usize,
    packing_points: &[u64],
) -> Result<Arc<Vec<Vec<u64>>>, TransactionCircuitError> {
    if !points_are_consecutive(packing_points) {
        return Ok(Arc::new(build_lagrange_basis(
            packing_factor,
            packing_points,
        )?));
    }
    let cache = CONSECUTIVE_LAGRANGE_BASIS_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(cached) = cache
        .lock()
        .expect("lagrange cache mutex")
        .get(&packing_factor)
    {
        return Ok(cached.clone());
    }
    let built = Arc::new(build_lagrange_basis(packing_factor, packing_points)?);
    let mut guard = cache.lock().expect("lagrange cache mutex");
    let cached = guard.entry(packing_factor).or_insert_with(|| built.clone());
    Ok(cached.clone())
}

fn poly_remove_one_degree_factor(poly: &[u64], root: u64) -> Vec<u64> {
    let in_degree = poly.len() - 1;
    let mut out = vec![0u64; in_degree];
    out[in_degree - 1] = poly[in_degree];
    for i in (0..(in_degree - 1)).rev() {
        out[i] = add_mod(poly[i + 1], mul_mod(root, out[i + 1]));
    }
    out
}

fn poly_restore(
    high: &[u64],
    evals: &[u64],
    eval_points: &[u64],
    degree: usize,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let nb_evals = evals.len();
    let mut shifted = vec![0u64; nb_evals];
    for i in 0..nb_evals {
        let mut pow_eval = eval_points[i];
        for _ in 0..(nb_evals - 1) {
            pow_eval = mul_mod(pow_eval, eval_points[i]);
        }
        let shift = mul_mod(poly_eval(high, eval_points[i]), pow_eval);
        shifted[i] = sub_mod(evals[i], shift);
    }
    let mut p = vec![0u64; degree + 1];
    let low = if points_are_consecutive(eval_points) {
        interpolate_consecutive(&shifted)?
    } else {
        poly_interpolate_generic(&shifted, eval_points)
    };
    p[..nb_evals].copy_from_slice(&low);
    p[nb_evals..].copy_from_slice(high);
    Ok(p)
}

/// Return the exact six-by-six affine-randomness map used by SMZ9 witness
/// interpolation.
///
/// `poly_interpolate_random` samples the coefficients in degrees 64 through
/// 69, then `poly_restore` changes the low 64 coefficients so the polynomial
/// keeps its prescribed values at packing points 0 through 63.  Consequently
/// a unit coin in position `t` contributes the polynomial
///
/// `B_t(X) = X^(64+t) - I_pack(x |-> x^(64+t))`,
///
/// not the bare monomial `X^(64+t)`.  This helper deliberately calls the same
/// `poly_restore` primitive as the prover, so the accepted-proof audit and the
/// honest prover cannot drift to different witness-map formulas.
pub(crate) fn smallwood_smz9_witness_randomness_matrix_v1(
    eval_points: &[u64],
) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    const PACKING_FACTOR: usize = 64;
    const RANDOM_COEFFICIENTS: usize = 6;
    const WITNESS_DEGREE: usize = PACKING_FACTOR + RANDOM_COEFFICIENTS - 1;

    if eval_points.len() != RANDOM_COEFFICIENTS
        || eval_points.iter().any(|&point| point >= FIELD_ORDER)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SMZ9 witness-randomness matrix requires six canonical opening points",
        ));
    }
    let packing_points = (0..PACKING_FACTOR as u64).collect::<Vec<_>>();
    let zero_packing_evaluations = vec![0u64; PACKING_FACTOR];
    let mut columns = Vec::with_capacity(RANDOM_COEFFICIENTS);
    for coin_index in 0..RANDOM_COEFFICIENTS {
        let mut unit_high = vec![0u64; RANDOM_COEFFICIENTS];
        unit_high[coin_index] = 1;
        columns.push(poly_restore(
            &unit_high,
            &zero_packing_evaluations,
            &packing_points,
            WITNESS_DEGREE,
        )?);
    }
    Ok(eval_points
        .iter()
        .map(|&point| {
            columns
                .iter()
                .map(|basis| poly_eval(basis, point))
                .collect::<Vec<_>>()
        })
        .collect())
}

fn points_are_consecutive(points: &[u64]) -> bool {
    points
        .iter()
        .enumerate()
        .all(|(idx, point)| *point == idx as u64)
}

fn poly_mul_linear_normalized(poly: &[u64], root: u64) -> Vec<u64> {
    let degree = poly.len() - 1;
    let mut out = vec![0u64; degree + 2];
    let neg_root = neg_mod(root);
    out[degree + 1] = poly[degree];
    for i in 0..degree {
        let idx = degree - i;
        out[idx] = add_mod(poly[idx - 1], mul_mod(neg_root, poly[idx]));
    }
    out[0] = mul_mod(neg_root, poly[0]);
    out
}

fn poly_mul_scalar(poly: &[u64], scalar: u64) -> Vec<u64> {
    poly.iter().map(|&c| mul_mod(c, scalar)).collect()
}

fn poly_mul_into(out: &mut [u64], a: &[u64], b: &[u64], degree_a: usize, degree_b: usize) {
    out.fill(0);
    let degree_c = degree_a + degree_b;
    for (num, out_coeff) in out.iter_mut().enumerate().take(degree_c + 1) {
        let mut acc = 0u64;
        for (i, &a_coeff) in a.iter().enumerate().take(min(num, degree_a) + 1) {
            let j = num - i;
            if j > degree_b {
                continue;
            }
            acc = add_mod(acc, mul_mod(a_coeff, b[j]));
        }
        *out_coeff = acc;
    }
}

fn poly_add_assign(dst: &mut [u64], src: &[u64]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = add_mod(*d, *s);
    }
}

fn poly_add_assign_scaled(dst: &mut [u64], src: &[u64], scalar: u64) {
    if scalar == 0 {
        return;
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = add_mod(*d, mul_mod(*s, scalar));
    }
}

fn mat_mul(c: &mut [Vec<u64>], a: &[Vec<u64>], b: &[Vec<u64>], m: usize, n: usize, p: usize) {
    for i in 0..m {
        for k in 0..p {
            let mut acc = 0u64;
            for j in 0..n {
                acc = add_mod(acc, mul_mod(a[i][j], b[j][k]));
            }
            c[i][k] = acc;
        }
    }
}

fn mat_vec_mul_owned(a: &[Vec<u64>], b: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; a.len()];
    for i in 0..a.len() {
        let mut acc = 0u64;
        for j in 0..b.len() {
            acc = add_mod(acc, mul_mod(a[i][j], b[j]));
        }
        out[i] = acc;
    }
    out
}

fn mat_inv(a: &[Vec<u64>]) -> Result<Vec<Vec<u64>>, TransactionCircuitError> {
    let n = a.len();
    let mut a_copy = a.to_vec();
    let mut inv = vec![vec![0u64; n]; n];
    for (i, row) in inv.iter_mut().enumerate().take(n) {
        row[i] = 1;
    }
    for i in 0..n {
        let mut pivot = i;
        while pivot < n && a_copy[pivot][i] == 0 {
            pivot += 1;
        }
        if pivot == n {
            return Err(TransactionCircuitError::ConstraintViolation(
                "smallwood matrix inversion failed",
            ));
        }
        if pivot != i {
            a_copy.swap(i, pivot);
            inv.swap(i, pivot);
        }
        let inv_pivot = inv_mod(a_copy[i][i])?;
        for j in 0..n {
            a_copy[i][j] = mul_mod(a_copy[i][j], inv_pivot);
            inv[i][j] = mul_mod(inv[i][j], inv_pivot);
        }
        for k in 0..n {
            if k == i {
                continue;
            }
            let factor = a_copy[k][i];
            if factor == 0 {
                continue;
            }
            for j in 0..n {
                a_copy[k][j] = sub_mod(a_copy[k][j], mul_mod(a_copy[i][j], factor));
                inv[k][j] = sub_mod(inv[k][j], mul_mod(inv[i][j], factor));
            }
        }
    }
    Ok(inv)
}

fn random_poly(degree: usize) -> Result<Vec<u64>, TransactionCircuitError> {
    random_vec(degree + 1)
}

#[inline]
fn canonical_random_field_word(candidate: u64) -> Option<u64> {
    (candidate < FIELD_ORDER).then_some(candidate)
}

fn random_vec(size: usize) -> Result<Vec<u64>, TransactionCircuitError> {
    let bounded_hx512 = smallwood_hx512_register_field_rng_request_v1(size)?;
    let mut values = Vec::with_capacity(size);
    while values.len() < size {
        let remaining = size - values.len();
        if bounded_hx512 {
            smallwood_hx512_register_field_candidates_v1(remaining)?;
        }
        let byte_len = remaining.checked_mul(8).ok_or({
            TransactionCircuitError::ConstraintViolation(
                "smallwood random field request exceeds addressable memory",
            )
        })?;
        let mut bytes = vec![0u8; byte_len];
        getrandom_fill(&mut bytes).map_err(|err| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood random generation failed: {err}"
            ))
        })?;
        for chunk in bytes.chunks_exact(8) {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            if let Some(value) = canonical_random_field_word(u64::from_le_bytes(buf)) {
                values.push(value);
            }
        }
    }
    Ok(values)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], TransactionCircuitError> {
    let mut out = [0u8; N];
    getrandom_fill(&mut out).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood random byte generation failed: {err}"
        ))
    })?;
    Ok(out)
}

fn random_decs_leaf_tapes(
    count: usize,
    tape_bytes: usize,
) -> Result<Vec<Vec<u8>>, TransactionCircuitError> {
    if tape_bytes == 0 || !tape_bytes.is_multiple_of(8) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood strict-ZK DECS tape width must be non-zero and word aligned",
        ));
    }
    let mut tapes = Vec::with_capacity(count);
    while tapes.len() < count {
        let batch_count = (count - tapes.len()).min(HX512_SMALLWOOD_DECS_TAPES_PER_RNG_CALL_V1);
        let byte_count = batch_count.checked_mul(tape_bytes).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "smallwood strict-ZK DECS leaf-tape request overflows addressable memory",
            ),
        )?;
        let _bounded_hx512 = smallwood_hx512_register_tape_rng_batch_v1(byte_count)?;
        let mut bytes = vec![0u8; byte_count];
        getrandom_fill(&mut bytes).map_err(|err| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "smallwood strict-ZK DECS leaf-tape generation failed: {err}"
            ))
        })?;
        for chunk in bytes.chunks_exact(tape_bytes) {
            tapes.push(chunk.to_vec());
        }
    }
    Ok(tapes)
}

#[inline]
fn canon(x: u64) -> u64 {
    let mut c = x;
    if c >= FIELD_ORDER {
        c -= FIELD_ORDER;
    }
    c
}

#[inline(always)]
fn add_mod(a: u64, b: u64) -> u64 {
    update_verifier_operation_profile_v1(|profile| {
        profile.field_additions += 1;
    });
    let (sum, over) = a.overflowing_add(b);
    let (mut sum, over) = sum.overflowing_add(u64::from(over) * NEG_ORDER);
    if over {
        sum = sum.wrapping_add(NEG_ORDER);
    }
    canon(sum)
}

#[inline(always)]
fn sub_mod(a: u64, b: u64) -> u64 {
    update_verifier_operation_profile_v1(|profile| {
        profile.field_subtractions += 1;
    });
    let (diff, under) = a.overflowing_sub(b);
    let (mut diff, under) = diff.overflowing_sub(u64::from(under) * NEG_ORDER);
    if under {
        diff = diff.wrapping_sub(NEG_ORDER);
    }
    canon(diff)
}

#[inline(always)]
fn mul_mod(a: u64, b: u64) -> u64 {
    update_verifier_operation_profile_v1(|profile| {
        profile.field_multiplications += 1;
    });
    reduce128((a as u128) * (b as u128))
}

#[inline]
fn neg_mod(a: u64) -> u64 {
    update_verifier_operation_profile_v1(|profile| {
        profile.field_negations += 1;
    });
    let canonical = canon(a);
    if canonical == 0 {
        0
    } else {
        FIELD_ORDER - canonical
    }
}

fn inv_mod(a: u64) -> Result<u64, TransactionCircuitError> {
    update_verifier_operation_profile_v1(|profile| {
        profile.field_inversions += 1;
    });
    Goldilocks::new(a)
        .try_inverse()
        .map(|value| value.as_canonical_u64())
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "smallwood inversion of zero",
        ))
}

#[inline]
fn div_mod(a: u64, b: u64) -> u64 {
    mul_mod(a, inv_mod(b).expect("non-zero divisor"))
}

#[inline(always)]
fn reduce128(x: u128) -> u64 {
    let x_lo = x as u64;
    let x_hi = (x >> 64) as u64;
    let x_hi_hi = x_hi >> 32;
    let x_hi_lo = x_hi & NEG_ORDER;

    let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
    if borrow {
        t0 = t0.wrapping_sub(NEG_ORDER);
    }
    let t1 = x_hi_lo.wrapping_mul(NEG_ORDER);
    add_no_canonicalize_trashing_input(t0, t1)
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    unsafe {
        let res_wrapped: u64;
        let adjustment: u64;
        core::arch::asm!(
            "add {0}, {1}",
            "sbb {1:e}, {1:e}",
            inlateout(reg) x => res_wrapped,
            inlateout(reg) y => adjustment,
            options(pure, nomem, nostack),
        );
        res_wrapped.wrapping_add(adjustment)
    }
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
    let (res_wrapped, carry) = x.overflowing_add(y);
    res_wrapped.wrapping_add(NEG_ORDER.wrapping_mul(u64::from(carry)))
}

#[cfg(test)]
mod complete_zk_domain_tests {
    use super::*;

    const ACTIVE_INTERPOLATION_POINTS: usize = 375 + 23;
    const COSET_SMOKE_PROFILE: SmallwoodNoGrindingProfileV1 = SmallwoodNoGrindingProfileV1 {
        rho: 2,
        nb_opened_evals: 2,
        beta: 2,
        opening_pow_bits: 0,
        decs_nb_evals: 256,
        decs_nb_opened_evals: SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1,
        decs_eta: 2,
        decs_pow_bits: 0,
    };

    /// Deterministic `CryptoRng` marker implementation used only to make the
    /// typed-sampler vector reproducible.  It is not production entropy and
    /// carries no information-theoretic freshness claim.
    struct SmallwoodStrictWholeViewDeterministicTestRngV1 {
        seed: [u8; DIGEST_BYTES],
        counter: u64,
        block: [u8; DIGEST_BYTES],
        offset: usize,
    }

    impl SmallwoodStrictWholeViewDeterministicTestRngV1 {
        fn new(seed: [u8; DIGEST_BYTES]) -> Self {
            Self {
                seed,
                counter: 0,
                block: [0u8; DIGEST_BYTES],
                offset: DIGEST_BYTES,
            }
        }

        fn refill(&mut self) {
            let mut hasher = Sha512::new();
            hasher.update(b"hegemon.smallwood.strict-whole-view-crypto-sampler-test-rng.v1");
            hasher.update(self.seed);
            hasher.update(self.counter.to_le_bytes());
            self.block = hasher.finalize().into();
            self.counter = self
                .counter
                .checked_add(1)
                .expect("deterministic strict-view test RNG counter exhausted");
            self.offset = 0;
        }
    }

    impl RngCore for SmallwoodStrictWholeViewDeterministicTestRngV1 {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, output: &mut [u8]) {
            let mut written = 0usize;
            while written < output.len() {
                if self.offset == DIGEST_BYTES {
                    self.refill();
                }
                let take = min(DIGEST_BYTES - self.offset, output.len() - written);
                output[written..written + take]
                    .copy_from_slice(&self.block[self.offset..self.offset + take]);
                self.offset += take;
                written += take;
            }
        }
    }

    impl CryptoRng for SmallwoodStrictWholeViewDeterministicTestRngV1 {}

    fn minimal_strict_trace(identity: SmallwoodProofWireIdentityV1) -> SmallwoodProofTraceV1 {
        let (opened_leaf_count, tape_bytes) = identity
            .opened_leaf_tape_profile()
            .expect("strict test identity carries a tape profile");
        let mut h_piop = [0x53; DIGEST_BYTES];
        h_piop[identity.digest_bytes()..].fill(0);
        SmallwoodProofTraceV1 {
            wire_identity: identity,
            salt: [0x31; SALT_BYTES],
            nonce: [0x42; NONCE_BYTES],
            h_piop,
            piop: PiopProof {
                ppol_highs: Vec::new(),
                plin_highs: Vec::new(),
            },
            pcs: PcsProof {
                rcombi_tails: Vec::new(),
                subset_evals: Vec::new(),
                partial_evals: Vec::new(),
                decs: DecsProof {
                    auth_paths: vec![Vec::new(); opened_leaf_count],
                    leaf_tapes: vec![vec![0x64; tape_bytes]; opened_leaf_count],
                    masking_evals: Vec::new(),
                    high_coeffs: Vec::new(),
                },
            },
            opened_witness_row_scalars: Vec::new(),
            auxiliary_witness_words: Vec::new(),
            auxiliary_witness_limb_count: 0,
        }
    }

    #[test]
    fn poseidon2_v8_profile_and_sha512_domains_are_fresh_and_exact() {
        let profile = smallwood_no_grinding_profile_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz8,
        );
        assert_eq!(profile, POSEIDON2_V8_SMALLWOOD_NO_GRINDING_PROFILE);
        assert_eq!(profile.rho, 5);
        assert_eq!(profile.nb_opened_evals, 5);
        assert_eq!(profile.beta, 2);
        assert_eq!(profile.decs_nb_evals, 1 << 23);
        assert_eq!(profile.decs_nb_opened_evals, 19);
        assert_eq!(profile.decs_eta, 5);
        assert_eq!(profile.opening_pow_bits, 0);
        assert_eq!(profile.decs_pow_bits, 0);
        assert_eq!(
            maximum_smallwood_compact_authentication_nodes_v1(
                profile.decs_nb_evals,
                profile.decs_nb_opened_evals,
            )
            .expect("derive exact canonical compact-path maximum"),
            SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES,
        );
        assert_eq!(profile.decs_nb_opened_evals * 23, 437);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTH_PATH_BYTES, 22_741,);
        // These variants were appended after every historical selector.  The
        // frontend separately pins the serialized arithmetization value to 16;
        // this ordinal protects the internal backend selector from reordering.
        assert_eq!(SmallwoodTranscriptBackend::Sha512Poseidon2V8 as u8, 6);

        let words = [1u64, 2, 3, 4];
        let historical = sha512_raw_domain_digest(
            SmallwoodTranscriptBackend::Sha512Level5,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        let v8 = sha512_raw_domain_digest(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        assert_ne!(v8, historical);
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8.sha512_profile_domain(),
            Some(SMALLWOOD_POSEIDON2_V8_SHA512_PROFILE_DOMAIN),
        );
        assert_eq!(
            proof_wire_identity_for_backend_and_domain(
                SmallwoodTranscriptBackend::Sha512Poseidon2V8,
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
            )
            .expect("bind V8 backend to its strict wire"),
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8,
        );
        assert!(proof_wire_identity_for_backend_and_domain(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8,
            SmallwoodDecsEvaluationDomain::Radix2Subgroup,
        )
        .is_err());
    }

    #[test]
    fn smz8_codec_is_canonical_profile_bound_and_allocation_capped() {
        let trace =
            minimal_strict_trace(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8);
        let encoded = encode_smallwood_smz8_proof_trace_v1(&trace)
            .expect("encode minimal canonical SMZ8 trace");
        assert_eq!(&encoded[..4], &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8);
        assert_eq!(encoded.len(), 1_382);
        assert_eq!(
            decode_smallwood_smz8_proof_trace_v1(&encoded).expect("decode exact SMZ8 trace"),
            trace,
        );
        let report =
            report_smallwood_proof_size_v1(&encoded).expect("account for exact SMZ8 wire fields");
        assert_eq!(
            report.decs_leaf_tapes_bytes,
            SMALLWOOD_POSEIDON2_V8_DECS_OPENED_TAPE_BYTES,
        );
        assert_eq!(SMALLWOOD_POSEIDON2_V8_DECS_OPENED_TAPE_BYTES, 19 * 64);

        let mut excessive_path = trace.clone();
        excessive_path.pcs.decs.auth_paths[0] = vec![[0x75; DIGEST_BYTES]; 24];
        let error = encode_smallwood_smz8_proof_trace_v1(&excessive_path)
            .expect_err("SMZ8 encoder must reject an over-depth path");
        assert!(error
            .to_string()
            .contains("auth-path length exceeds its wire profile depth"));

        // The three empty PCS matrices end at byte 124 in this deliberately
        // minimal fixture.  The next u16 is the authentication-path count;
        // SMZ8 rejects a forged count before allocating its lengths vector.
        let mut wrong_path_count = encoded.clone();
        wrong_path_count[124..126].copy_from_slice(&20u16.to_le_bytes());
        let error = decode_smallwood_smz8_proof_trace_v1(&wrong_path_count)
            .expect_err("SMZ8 must reject a non-19 path header");
        assert!(error
            .to_string()
            .contains("auth-path count does not match its wire identity"));

        let mut historical_magic = encoded.clone();
        historical_magic[..4].copy_from_slice(&SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V1);
        assert!(decode_smallwood_proof_trace_v1(&historical_magic).is_err());

        let historical =
            minimal_strict_trace(SmallwoodProofWireIdentityV1::StrictZkSha512Level5Smz1);
        let historical =
            encode_smallwood_proof_trace_v1(&historical).expect("encode historical SMZ1 fixture");
        assert!(decode_smallwood_smz8_proof_trace_v1(&historical).is_err());

        let mut over_cap = vec![0u8; SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES + 1];
        over_cap[..4].copy_from_slice(&SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8);
        let error = decode_smallwood_proof_trace_v1(&over_cap)
            .expect_err("SMZ8 must reject the borrowed input length before payload allocation");
        assert!(error.to_string().contains("exceeds the 131072-byte cap"));
    }

    #[test]
    fn smz9_profile_codec_projection_and_smz8_rejection_are_exact() {
        let profile = smallwood_no_grinding_profile_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9,
        );
        assert_eq!(profile, POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE);
        assert_eq!(profile.rho, 5);
        assert_eq!(profile.nb_opened_evals, 6);
        assert_eq!(profile.beta, 2);
        assert_eq!(profile.decs_nb_evals, 1 << 23);
        assert_eq!(profile.decs_nb_opened_evals, 20);
        assert_eq!(profile.decs_eta, 5);
        assert_eq!(profile.opening_pow_bits, 0);
        assert_eq!(profile.decs_pow_bits, 0);
        assert_eq!(
            maximum_smallwood_compact_authentication_nodes_v1(
                profile.decs_nb_evals,
                profile.decs_nb_opened_evals,
            )
            .expect("derive exact SMZ9 compact-path maximum"),
            SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTHENTICATION_NODES,
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_SMZ9_MAX_COMPACT_AUTH_PATH_BYTES,
            23_830
        );
        assert_eq!(SMALLWOOD_POSEIDON2_V8_SMZ9_DECS_OPENED_TAPE_BYTES, 20 * 64);
        assert_eq!(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9 as u8,
            17,
        );
        assert_eq!(SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9 as u8, 7);

        let words = [1u64, 2, 3, 4];
        let smz8_digest = sha512_raw_domain_digest(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        let smz9_digest = sha512_raw_domain_digest(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        assert_ne!(smz9_digest, smz8_digest);
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9.sha512_profile_domain(),
            Some(SMALLWOOD_POSEIDON2_V8_SMZ9_SHA512_PROFILE_DOMAIN),
        );
        assert_eq!(
            proof_wire_identity_for_backend_and_domain(
                SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
            )
            .expect("bind SMZ9 backend to its strict wire"),
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9,
        );

        let trace =
            minimal_strict_trace(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9);
        let encoded = encode_smallwood_smz9_proof_trace_v1(&trace)
            .expect("encode minimal canonical SMZ9 trace");
        assert_eq!(&encoded[..4], &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9);
        assert_eq!(encoded.len(), 1_447);
        assert_eq!(
            decode_smallwood_smz9_proof_trace_v1(&encoded).expect("decode exact SMZ9 trace"),
            trace,
        );
        assert!(decode_smallwood_smz8_proof_trace_v1(&encoded).is_err());

        let smz8 =
            minimal_strict_trace(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz8);
        let smz8 = encode_smallwood_smz8_proof_trace_v1(&smz8).expect("encode SMZ8 fixture");
        assert!(decode_smallwood_smz9_proof_trace_v1(&smz8).is_err());

        let mut wrong_path_count = encoded.clone();
        wrong_path_count[124..126].copy_from_slice(&19u16.to_le_bytes());
        assert!(decode_smallwood_smz9_proof_trace_v1(&wrong_path_count).is_err());

        let mut over_cap = vec![0u8; SMALLWOOD_POSEIDON2_V8_MAX_INNER_PROOF_BYTES + 1];
        over_cap[..4].copy_from_slice(&SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9);
        let error = decode_smallwood_proof_trace_v1(&over_cap)
            .expect_err("SMZ9 must reject the borrowed input length before payload allocation");
        assert!(error.to_string().contains("exceeds the 131072-byte cap"));

        let projection_statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9,
            686,
            64,
            8,
            830,
            0,
        )
        .expect("construct exact SMZ9 projection geometry");
        assert_eq!(
            projected_poseidon2_v8_smz9_inner_proof_bytes(&projection_statement)
                .expect("project exact maximum canonical SMZ9 proof"),
            122_863,
        );
    }

    #[test]
    fn smc7_profile_complete_sha512_codec_projection_and_caps_are_exact() {
        let profile = POSEIDON2_V8_COMPACT448_SMALLWOOD_NO_GRINDING_PROFILE;
        assert_eq!(profile.rho, 5);
        assert_eq!(profile.nb_opened_evals, 6);
        assert_eq!(profile.beta, 2);
        assert_eq!(profile.decs_nb_evals, 1 << 23);
        assert_eq!(profile.decs_nb_opened_evals, 19);
        assert_eq!(profile.decs_eta, 5);
        assert_eq!(profile.opening_pow_bits, 0);
        assert_eq!(profile.decs_pow_bits, 0);
        assert_eq!(
            maximum_smallwood_compact_authentication_nodes_v1(
                profile.decs_nb_evals,
                profile.decs_nb_opened_evals,
            )
            .expect("derive exact SMC7 compact-path maximum"),
            SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_COMPACT_AUTHENTICATION_NODES,
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_COMPACT_AUTH_PATH_BYTES,
            19_901,
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_COMPACT448_DECS_OPENED_TAPE_BYTES,
            19 * 64,
        );
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7 as u8,
            8,
        );
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7.digest_bytes(),
            56,
        );

        let words = [1u64, 2, 3, 4];
        let raw = sha512_raw_domain_digest(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        let observed = sha512_commitment_domain_digest(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        assert_eq!(
            &observed[..SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES],
            &raw[..SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES],
        );
        assert!(observed[SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES..]
            .iter()
            .all(|byte| *byte == 0));
        assert!(raw[SMALLWOOD_POSEIDON2_V8_COMPACT448_DIGEST_BYTES..]
            .iter()
            .any(|byte| *byte != 0));
        let raw_words = bytes_to_words_unchecked(&raw);
        assert!(raw_words.iter().all(|word| *word < FIELD_ORDER));
        let sampled = transcript_xof_words(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            DIGEST_WORDS,
        );
        assert_eq!(sampled, raw_words);
        assert_eq!(
            sampled[7],
            u64::from_le_bytes(raw[56..64].try_into().expect("last SHA-512 word")),
        );
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7.sha512_profile_domain(),
            Some(SMALLWOOD_POSEIDON2_V8_COMPACT448_SHA512_PROFILE_DOMAIN),
        );
        assert_eq!(
            proof_wire_identity_for_backend_and_domain(
                SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
            )
            .expect("bind compact backend to its strict wire"),
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7,
        );

        let trace = minimal_strict_trace(
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7,
        );
        let encoded =
            encode_smallwood_smc7_proof_trace_v1(&trace).expect("encode canonical SMC7 trace");
        assert_eq!(
            &encoded[..4],
            &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7,
        );
        assert_eq!(encoded.len(), 1_374);
        assert_eq!(
            decode_smallwood_smc7_proof_trace_v1(&encoded).expect("decode exact SMC7 trace"),
            trace,
        );
        assert!(decode_smallwood_smz9_proof_trace_v1(&encoded).is_err());

        let smz9 =
            minimal_strict_trace(SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9);
        let smz9 = encode_smallwood_smz9_proof_trace_v1(&smz9).expect("encode SMZ9 fixture");
        assert!(decode_smallwood_smc7_proof_trace_v1(&smz9).is_err());

        let mut nonzero_digest_tail = trace.clone();
        nonzero_digest_tail.h_piop[56] = 1;
        assert!(encode_smallwood_smc7_proof_trace_v1(&nonzero_digest_tail).is_err());

        let mut wrong_path_count = encoded.clone();
        wrong_path_count[116..118].copy_from_slice(&20u16.to_le_bytes());
        assert!(decode_smallwood_smc7_proof_trace_v1(&wrong_path_count).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_smallwood_smc7_proof_trace_v1(&trailing).is_err());

        let mut over_cap = vec![0u8; SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES + 1];
        over_cap[..4].copy_from_slice(&SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_SMC7);
        let error = decode_smallwood_proof_trace_v1(&over_cap)
            .expect_err("SMC7 rejects borrowed input length before payload allocation");
        assert!(error.to_string().contains("exact 117702-byte cap"));

        let mut oversized_encoding = trace.clone();
        oversized_encoding.piop.ppol_highs = vec![vec![0; 96]; 96];
        oversized_encoding.piop.plin_highs = vec![vec![0; 96]; 96];
        let error = encode_smallwood_smc7_proof_trace_v1(&oversized_encoding)
            .expect_err("SMC7 encoder enforces the exact candidate cap");
        assert!(error.to_string().contains("exact 117702-byte cap"));

        let projection_statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9,
            686,
            64,
            8,
            830,
            0,
        )
        .expect("construct exact SMC7 projection geometry");
        assert_eq!(
            projected_poseidon2_v8_compact448_inner_proof_bytes(&projection_statement)
                .expect("project exact maximum canonical SMC7 proof"),
            SMALLWOOD_POSEIDON2_V8_COMPACT448_MAX_INNER_PROOF_BYTES,
        );
    }

    #[test]
    fn smc8_q20_profile_codec_projection_and_caps_are_exact() {
        let profile = POSEIDON2_V8_COMPACT448_Q20_SMALLWOOD_NO_GRINDING_PROFILE;
        assert_eq!(profile.rho, 5);
        assert_eq!(profile.nb_opened_evals, 6);
        assert_eq!(profile.beta, 2);
        assert_eq!(profile.decs_nb_evals, 1 << 23);
        assert_eq!(profile.decs_nb_opened_evals, 20);
        assert_eq!(profile.decs_eta, 5);
        assert_eq!(
            maximum_smallwood_compact_authentication_nodes_v1(
                profile.decs_nb_evals,
                profile.decs_nb_opened_evals,
            )
            .expect("derive exact SMC8 compact-path maximum"),
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_COMPACT_AUTHENTICATION_NODES,
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_COMPACT_AUTH_PATH_BYTES,
            20_854,
        );
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_DECS_OPENED_TAPE_BYTES,
            20 * 64,
        );
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8 as u8,
            9,
        );
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8.digest_bytes(),
            56,
        );

        let words = [1u64, 2, 3, 4];
        let raw = sha512_raw_domain_digest(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        let observed = sha512_commitment_domain_digest(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
            SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
            &words,
            0,
        );
        assert_eq!(&observed[..56], &raw[..56]);
        assert!(observed[56..].iter().all(|byte| *byte == 0));
        assert_ne!(
            raw,
            sha512_raw_domain_digest(
                SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Smc7,
                SMALLWOOD_LEVEL5_PIOP_INPUT_DOMAIN,
                &words,
                0,
            ),
        );
        assert_eq!(
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8.sha512_profile_domain(),
            Some(SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_SHA512_PROFILE_DOMAIN),
        );
        assert_eq!(
            proof_wire_identity_for_backend_and_domain(
                SmallwoodTranscriptBackend::Sha512Poseidon2V8Compact448Q20Smc8,
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
            )
            .expect("bind q20 compact backend to its strict wire"),
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8,
        );

        let trace = minimal_strict_trace(
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Q20Smc8,
        );
        let encoded =
            encode_smallwood_smc8_proof_trace_v1(&trace).expect("encode canonical SMC8 trace");
        assert_eq!(
            &encoded[..4],
            &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8,
        );
        assert_eq!(encoded.len(), 1_439);
        assert_eq!(
            decode_smallwood_smc8_proof_trace_v1(&encoded).expect("decode exact SMC8 trace"),
            trace,
        );
        assert!(decode_smallwood_smz9_proof_trace_v1(&encoded).is_err());
        assert!(decode_smallwood_smc7_proof_trace_v1(&encoded).is_err());

        let smc7 = minimal_strict_trace(
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Compact448Smc7,
        );
        let smc7 = encode_smallwood_smc7_proof_trace_v1(&smc7).expect("encode SMC7 fixture");
        assert!(decode_smallwood_smc8_proof_trace_v1(&smc7).is_err());

        let mut nonzero_digest_tail = trace.clone();
        nonzero_digest_tail.h_piop[56] = 1;
        assert!(encode_smallwood_smc8_proof_trace_v1(&nonzero_digest_tail).is_err());

        let mut wrong_path_count = encoded.clone();
        wrong_path_count[116..118].copy_from_slice(&19u16.to_le_bytes());
        assert!(decode_smallwood_smc8_proof_trace_v1(&wrong_path_count).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_smallwood_smc8_proof_trace_v1(&trailing).is_err());

        let mut over_cap =
            vec![0u8; SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES + 1];
        over_cap[..4].copy_from_slice(&SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_COMPACT448_Q20_SMC8);
        let error = decode_smallwood_proof_trace_v1(&over_cap)
            .expect_err("SMC8 rejects borrowed input length before payload allocation");
        assert!(error.to_string().contains("exact 119879-byte cap"));

        let mut oversized_encoding = trace.clone();
        oversized_encoding.piop.ppol_highs = vec![vec![0; 96]; 96];
        oversized_encoding.piop.plin_highs = vec![vec![0; 96]; 96];
        let error = encode_smallwood_smc8_proof_trace_v1(&oversized_encoding)
            .expect_err("SMC8 encoder enforces the exact candidate cap");
        assert!(error.to_string().contains("exact 119879-byte cap"));

        let projection_statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9,
            686,
            64,
            8,
            830,
            0,
        )
        .expect("construct exact SMC8 projection geometry");
        assert_eq!(
            projected_poseidon2_v8_compact448_q20_inner_proof_bytes(&projection_statement)
                .expect("project exact maximum canonical SMC8 proof"),
            SMALLWOOD_POSEIDON2_V8_COMPACT448_Q20_MAX_INNER_PROOF_BYTES,
        );
    }

    #[test]
    fn compact_authentication_maximum_matches_exhaustive_small_trees() {
        for depth in 1..=4usize {
            let domain_size = 1usize << depth;
            let mut exhaustive_maximum = vec![0usize; domain_size + 1];
            for mask in 1usize..(1usize << domain_size) {
                let indices = (0..domain_size)
                    .filter(|index| mask & (1usize << index) != 0)
                    .collect::<Vec<_>>();
                let nodes = expected_compact_merkle_auth_path_lengths(&indices, depth)
                    .iter()
                    .sum::<usize>();
                exhaustive_maximum[indices.len()] = exhaustive_maximum[indices.len()].max(nodes);
            }
            for opened_leaf_count in 1..=domain_size {
                assert_eq!(
                    maximum_smallwood_compact_authentication_nodes_v1(
                        domain_size,
                        opened_leaf_count,
                    )
                    .expect("derive compact authentication maximum"),
                    exhaustive_maximum[opened_leaf_count],
                    "depth={depth} opened_leaf_count={opened_leaf_count}",
                );
            }
        }
    }

    #[test]
    fn retained_radix2_subgroup_hits_actual_lvcs_coordinate_64() {
        let point = decs_field_evaluation_points(
            SmallwoodDecsEvaluationDomain::Radix2Subgroup,
            1 << 20,
            ACTIVE_INTERPOLATION_POINTS,
            &[163_840],
        )
        .expect("derive retained DECS point");
        assert_eq!(point, vec![64]);
        assert!((23..ACTIVE_INTERPOLATION_POINTS).contains(&(point[0] as usize)));
    }

    #[test]
    fn strict_zk_coset_is_disjoint_from_complete_interpolation_domain() {
        let descriptor =
            SmallwoodDisjointCosetDescriptorV1::derive(1 << 20, ACTIVE_INTERPOLATION_POINTS)
                .expect("derive strict-ZK DECS coset");
        assert_eq!(descriptor.domain_size, 1 << 20);
        assert_eq!(
            descriptor.interpolation_point_count,
            ACTIVE_INTERPOLATION_POINTS
        );
        assert_eq!(descriptor.shift, 398);
        assert!(radix2_coset_is_disjoint_from_interpolation_domain(
            descriptor.domain_size,
            descriptor.interpolation_point_count,
            descriptor.shift,
        )
        .expect("check strict-ZK DECS coset"));
        let point = decs_field_evaluation_points(
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
            descriptor.domain_size,
            descriptor.interpolation_point_count,
            &[163_840],
        )
        .expect("derive strict-ZK DECS point");
        assert_eq!(
            point,
            vec![descriptor
                .point_for_leaf_index(163_840)
                .expect("derive the same point from the bound descriptor")]
        );
        assert!(!(0..ACTIVE_INTERPOLATION_POINTS).contains(&(point[0] as usize)));

        let stale_descriptor =
            SmallwoodDisjointCosetDescriptorV1::derive(1 << 20, ACTIVE_INTERPOLATION_POINTS - 23)
                .expect("derive deliberately stale geometry");
        assert_ne!(stale_descriptor.shift, descriptor.shift);
        assert!(descriptor.point_for_leaf_index(1 << 20).is_err());
    }

    #[test]
    fn smz1_size_projection_accounts_for_every_opened_leaf_tape() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1,
            699,
            64,
            8,
            890,
            0,
        )
        .expect("construct active SMZ1 structural statement");
        let cfg = SmallwoodConfig::new_with_profile(
            &statement,
            STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
        )
        .expect("derive active SMZ1 geometry");
        let historical_smw2_bytes = serialized_proof_size_hint_with_profile(
            &cfg,
            STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
            0,
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodDecsEvaluationDomain::Radix2Subgroup,
        )
        .expect("project historical SMW2 proof bytes");
        let strict_smz1_bytes = serialized_proof_size_hint_with_profile(
            &cfg,
            STRICT_ZK_SMZ1_SMALLWOOD_NO_GRINDING_PROFILE,
            0,
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .expect("project strict SMZ1 proof bytes");

        assert_eq!(strict_smz1_bytes, 126_434);
        assert_eq!(
            strict_smz1_bytes - historical_smw2_bytes,
            SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1
        );
        assert_eq!(SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1, 23 * 64);
    }

    #[test]
    fn coset_fft_matches_direct_polynomial_evaluation() {
        let initial = vec![3u64, 5, 8, 13, 21];
        let coefficients = interpolate_consecutive(&initial).expect("interpolate test polynomial");
        let shift =
            radix2_disjoint_coset_shift(16, initial.len()).expect("select test disjoint coset");
        let root = radix2_subgroup_generator(16).expect("derive test subgroup root");
        let mut actual = vec![0u64; 16];
        evaluate_consecutive_values_on_radix2_coset_into(&initial, &mut actual, shift)
            .expect("evaluate test polynomial over coset");
        let expected = (0..16)
            .map(|index| poly_eval(&coefficients, mul_mod(shift, pow_mod(root, index as u64))))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn compact_auth_path_zero_length_is_canonical_and_reconstructs_root() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
            8,
            8,
            2,
            17,
            0,
        )
        .expect("construct compact-auth-path statement");
        let cfg = SmallwoodConfig::new_with_profile(&statement, COSET_SMOKE_PROFILE)
            .expect("construct compact-auth-path configuration");
        let backend = SmallwoodTranscriptBackend::Sha512Level5;
        let salt = [0x5au8; SALT_BYTES];

        // For leaf zero, these exact 23 positions supply a sibling subtree at
        // every level of the 256-leaf tree.  Its individual compact path is
        // therefore empty even though the aggregate multiproof is complete.
        let opened_indices = vec![
            0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 64, 128,
        ];
        assert_eq!(
            opened_indices.len(),
            SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1
        );

        let committed_rows = (0..cfg.decs_nb_evals())
            .map(|leaf_index| {
                (0..cfg.nb_lvcs_rows)
                    .map(|column| (leaf_index * 1_000 + column) as u64)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let masking_rows = (0..cfg.decs_nb_evals())
            .map(|leaf_index| {
                (0..cfg.decs_eta())
                    .map(|column| (1_000_000 + leaf_index * 10 + column) as u64)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let leaf_tapes = (0..cfg.decs_nb_evals())
            .map(|leaf_index| vec![leaf_index as u8; SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES])
            .collect::<Vec<_>>();
        let leaf_hashes = (0..cfg.decs_nb_evals())
            .map(|leaf_index| {
                let mut evaluations = committed_rows[leaf_index].clone();
                evaluations.extend_from_slice(&masking_rows[leaf_index]);
                hash_strict_zk_merkle_leaf(
                    cfg.nb_lvcs_rows,
                    &evaluations,
                    leaf_index,
                    &leaf_tapes[leaf_index],
                    &salt,
                    backend,
                )
                .expect("hash deterministic strict-ZK leaf")
            })
            .collect::<Vec<_>>();
        let mut tree_levels = vec![leaf_hashes];
        let expected_root = merkle_build_levels(&mut tree_levels, backend);
        let auth_paths = compact_merkle_auth_paths(&tree_levels, &opened_indices);
        assert!(auth_paths[0].is_empty());

        let mut encoded_paths = Vec::new();
        encode_auth_paths_v1(&mut encoded_paths, &auth_paths, DIGEST_BYTES)
            .expect("encode compact multiproof containing an empty individual path");
        let mut cursor = 0usize;
        let decoded_paths = decode_auth_paths_v1(
            &encoded_paths,
            &mut cursor,
            DIGEST_BYTES,
            Some(SMALLWOOD_STRICT_ZK_DECS_OPENED_LEAF_COUNT_V1),
            Some(8),
        )
        .expect("decode compact multiproof containing an empty individual path");
        assert_eq!(decoded_paths, auth_paths);
        assert_eq!(cursor, encoded_paths.len());

        let leaf_indexes = opened_indices
            .iter()
            .map(|&index| index as u32)
            .collect::<Vec<_>>();
        let proof = DecsProof {
            auth_paths,
            leaf_tapes: opened_indices
                .iter()
                .map(|&index| leaf_tapes[index].clone())
                .collect(),
            masking_evals: opened_indices
                .iter()
                .map(|&index| masking_rows[index].clone())
                .collect(),
            high_coeffs: vec![vec![0u64; cfg.nb_lvcs_cols]; cfg.decs_eta()],
        };
        let opened_rows = opened_indices
            .iter()
            .map(|&index| committed_rows[index].clone())
            .collect::<Vec<_>>();
        let reconstructed =
            decs_recompute_root(&cfg, &salt, &opened_rows, &leaf_indexes, &proof, backend)
                .expect("reconstruct root from compact multiproof with an empty individual path");
        assert_eq!(reconstructed, expected_root);
    }

    #[test]
    fn disjoint_coset_proof_roundtrips_and_rejects_domain_or_payload_mutation() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
            8,
            8,
            2,
            17,
            0,
        )
        .expect("construct disjoint-coset smoke statement");
        let witness = vec![0u64; 64];
        let binding = [0x6au8; 16];
        let backend = SmallwoodTranscriptBackend::Sha512Level5;
        let proof = prove_statement_with_transcript_backend_profile_and_domain(
            &statement,
            &witness,
            &binding,
            COSET_SMOKE_PROFILE,
            backend,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .expect("prove over the disjoint DECS coset");
        assert_eq!(&proof[..4], &SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V1);
        let decoded = decode_smallwood_proof_bytes_v1(&proof)
            .expect("decode strict-ZK disjoint-coset smoke proof");
        assert_eq!(
            decoded.wire_identity,
            SmallwoodProofWireIdentityV1::StrictZkSha512Level5Smz1
        );
        assert!(decoded.strict_zk_decs_leaf_hiding);
        assert_eq!(
            decoded.pcs.decs.leaf_tapes.len(),
            COSET_SMOKE_PROFILE.decs_nb_opened_evals
        );
        assert_eq!(
            decoded.pcs.decs.leaf_tapes.len() * SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES,
            SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1
        );
        let size_report = report_smallwood_proof_size_v1(&proof)
            .expect("account for strict-ZK disjoint-coset smoke proof bytes");
        assert_eq!(
            size_report.decs_leaf_tapes_bytes,
            SMALLWOOD_STRICT_ZK_DECS_OPENED_TAPE_BYTES_V1
        );
        let smz1_trace =
            decode_smallwood_proof_trace_v1(&proof).expect("decode historical strict-ZK trace");
        assert_eq!(
            encode_smallwood_proof_trace_v1(&smz1_trace)
                .expect("re-encode historical strict-ZK trace"),
            proof
        );
        assert!(decode_smallwood_smz2_proof_trace_v1(&proof).is_err());
        assert!(encode_smallwood_smz2_proof_trace_v1(&smz1_trace).is_err());

        let mut smz2_trace = smz1_trace.clone();
        smz2_trace.wire_identity = SmallwoodProofWireIdentityV1::StrictZkSha512V6Smz2;
        let smz2 = encode_smallwood_smz2_proof_trace_v1(&smz2_trace)
            .expect("encode distinct fresh-domain SMZ2 wire");
        assert_eq!(&smz2[..4], &SMALLWOOD_PROOF_WIRE_MAGIC_STRICT_ZK_V2);
        let decoded_smz2 =
            decode_smallwood_proof_bytes_v1(&smz2).expect("decode distinct fresh-domain SMZ2 wire");
        assert_eq!(
            decoded_smz2.wire_identity,
            SmallwoodProofWireIdentityV1::StrictZkSha512V6Smz2
        );
        assert_eq!(
            decode_smallwood_smz2_proof_trace_v1(&smz2).expect("require exact SMZ2 identity"),
            smz2_trace
        );
        assert!(ensure_decs_domain_wire_binding(
            &decoded,
            SmallwoodTranscriptBackend::Sha512V6,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .is_err());
        assert!(ensure_decs_domain_wire_binding(
            &decoded_smz2,
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .is_err());
        ensure_decs_domain_wire_binding(
            &decoded_smz2,
            SmallwoodTranscriptBackend::Sha512V6,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .expect("SMZ2 identity pairs only with fresh V6 SHA-512 and the disjoint coset");

        let unavailable_verify = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_statement_with_transcript_backend_profile_and_domain(
                &statement,
                &binding,
                &smz2,
                COSET_SMOKE_PROFILE,
                SmallwoodTranscriptBackend::Sha512V6,
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
            )
        }));
        assert!(matches!(unavailable_verify, Ok(Err(_))));
        assert!(verify_statement_with_transcript_backend_profile_and_domain(
            &statement,
            &binding,
            &smz2,
            COSET_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .is_err());
        verify_statement_with_transcript_backend_profile_and_domain(
            &statement,
            &binding,
            &proof,
            COSET_SMOKE_PROFILE,
            backend,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .expect("verify over the identical disjoint DECS coset");

        let cfg = SmallwoodConfig::new_with_profile(&statement, COSET_SMOKE_PROFILE)
            .expect("construct strict-ZK smoke configuration");
        let trace = build_smallwood_verifier_trace_with_profile_and_domain_v1(
            &statement,
            &binding,
            &proof,
            COSET_SMOKE_PROFILE,
            backend,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .expect("build strict-ZK verifier trace");
        let coset_points_miscast_as_indexes = trace
            .pcs_trace
            .decs_eval_points
            .iter()
            .map(|&point| point as u32)
            .collect::<Vec<_>>();
        assert_ne!(
            coset_points_miscast_as_indexes,
            trace.pcs_trace.decs_leaf_indexes
        );
        assert!(decs_recompute_root(
            &cfg,
            &decoded.salt,
            &trace.pcs_trace.rows,
            &coset_points_miscast_as_indexes,
            &decoded.pcs.decs,
            backend,
        )
        .is_err());

        let mut noncanonical_count = decoded.clone();
        noncanonical_count.pcs.decs.auth_paths.pop();
        noncanonical_count.pcs.decs.leaf_tapes.pop();
        assert!(encode_smallwood_proof_bytes_v1(&noncanonical_count).is_err());

        assert!(verify_statement_with_transcript_backend_profile_and_domain(
            &statement,
            &binding,
            &proof,
            COSET_SMOKE_PROFILE,
            backend,
            SmallwoodDecsEvaluationDomain::Radix2Subgroup,
        )
        .is_err());

        let mut decoded = decode_smallwood_proof_bytes_v1(&proof)
            .expect("decode disjoint-coset smoke proof for mutation");
        decoded.pcs.subset_evals[0][0] = add_mod(decoded.pcs.subset_evals[0][0], 1);
        let mutated = encode_smallwood_proof_bytes_v1(&decoded)
            .expect("encode canonical disjoint-coset payload mutation");
        assert!(verify_statement_with_transcript_backend_profile_and_domain(
            &statement,
            &binding,
            &mutated,
            COSET_SMOKE_PROFILE,
            backend,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .is_err());

        let mut decoded = decode_smallwood_proof_bytes_v1(&proof)
            .expect("decode strict-ZK leaf tape for mutation");
        decoded.pcs.decs.leaf_tapes[0][0] ^= 1;
        let mutated = encode_smallwood_proof_bytes_v1(&decoded)
            .expect("encode canonical strict-ZK leaf-tape mutation");
        assert!(verify_statement_with_transcript_backend_profile_and_domain(
            &statement,
            &binding,
            &mutated,
            COSET_SMOKE_PROFILE,
            backend,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .is_err());

        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(decode_smallwood_proof_bytes_v1(&trailing).is_err());
    }

    #[test]
    fn strict_zk_wire_rejects_arbitrary_opening_counts_before_proving() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5,
            8,
            8,
            2,
            17,
            0,
        )
        .expect("construct strict-ZK identity-boundary statement");
        let arbitrary_opening_profile = SmallwoodNoGrindingProfileV1 {
            decs_nb_opened_evals: 4,
            ..COSET_SMOKE_PROFILE
        };
        assert!(prove_statement_with_transcript_backend_profile_and_domain(
            &statement,
            &[0u64; 64],
            &[0x6au8; 16],
            arbitrary_opening_profile,
            SmallwoodTranscriptBackend::Sha512Level5,
            SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
        )
        .is_err());
        let unavailable_prove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_statement_with_transcript_backend_profile_and_domain(
                &statement,
                &[0u64; 64],
                &[0x6au8; 16],
                COSET_SMOKE_PROFILE,
                SmallwoodTranscriptBackend::Sha512V6,
                SmallwoodDecsEvaluationDomain::Radix2DisjointCoset,
            )
        }));
        assert!(matches!(unavailable_prove, Ok(Err(_))));
    }

    #[test]
    fn strict_zk_leaf_hash_binds_index_tape_and_matches_table_fast_path() {
        let salt = [9u8; SALT_BYTES];
        let salt_words = bytes_to_words_unchecked(&salt);
        let committed = vec![vec![11u64, 12], vec![21u64, 22], vec![31u64, 32]];
        let masking = vec![vec![41u64, 42], vec![51u64, 52]];
        let tape = [7u8; SMALLWOOD_STRICT_ZK_DECS_LEAF_TAPE_BYTES];
        let mut evals = committed.iter().map(|poly| poly[1]).collect::<Vec<_>>();
        evals.extend(masking.iter().map(|poly| poly[1]));
        let reference = hash_strict_zk_merkle_leaf(
            committed.len(),
            &evals,
            1,
            &tape,
            &salt,
            SmallwoodTranscriptBackend::Sha512Level5,
        )
        .expect("hash strict-ZK DECS leaf reference");
        let fast = hash_strict_zk_merkle_leaf_from_tables(
            &salt_words,
            &committed,
            &masking,
            1,
            &tape,
            SmallwoodTranscriptBackend::Sha512Level5,
        );
        assert_eq!(fast, reference);

        let index_mutation = hash_strict_zk_merkle_leaf(
            committed.len(),
            &evals,
            0,
            &tape,
            &salt,
            SmallwoodTranscriptBackend::Sha512Level5,
        )
        .expect("hash strict-ZK DECS leaf index mutation");
        assert_ne!(reference, index_mutation);
        let mut changed_tape = tape;
        changed_tape[0] ^= 1;
        let tape_mutation = hash_strict_zk_merkle_leaf(
            committed.len(),
            &evals,
            1,
            &changed_tape,
            &salt,
            SmallwoodTranscriptBackend::Sha512Level5,
        )
        .expect("hash strict-ZK DECS leaf tape mutation");
        assert_ne!(reference, tape_mutation);
    }

    #[test]
    fn smz1_whole_view_simulator_is_witness_free_and_canonical() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1,
            8,
            8,
            2,
            17,
            0,
        )
        .expect("construct strict-view simulator statement");
        let binding = [0x42u8; 16];
        let seed = [0x91u8; DIGEST_BYTES];
        let coins = build_smallwood_strict_whole_view_fixture_coins_v1(
            &statement,
            COSET_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Sha512Level5,
            seed,
        )
        .expect("build typed SMZ1 fixture coins");
        let first = simulate_smallwood_smz1_whole_view_v1(
            &statement,
            &binding,
            COSET_SMOKE_PROFILE,
            coins.clone(),
        )
        .expect("simulate exact canonical SMZ1 view");
        let second =
            simulate_smallwood_smz1_whole_view_v1(&statement, &binding, COSET_SMOKE_PROFILE, coins)
                .expect("repeat deterministic exact SMZ1 simulation");
        assert_eq!(first, second);
        assert_eq!(first.raw_witness_words_consumed, 0);
        assert_eq!(
            first.programmed_final_piop_input_words,
            first.verifier_trace.piop_transcript_words
        );
        assert_eq!(
            first.programmed_final_piop_output,
            first.verifier_trace.proof.h_piop
        );
        assert_eq!(
            decode_smallwood_proof_trace_v1(&first.proof_bytes)
                .expect("decode simulated canonical SMZ1 view")
                .wire_identity,
            SmallwoodProofWireIdentityV1::StrictZkSha512Level5Smz1
        );
        validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            COSET_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Sha512Level5,
            &first,
        )
        .expect("refine the complete serialized SMZ1 view");

        let mut trailing = first.proof_bytes.clone();
        trailing.push(0);
        assert!(decode_smallwood_proof_trace_v1(&trailing).is_err());

        let mut mutated = first.clone();
        mutated.programmed_final_piop_input_words[0] ^= 1;
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            COSET_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Sha512Level5,
            &mutated,
        )
        .is_err());
        let mut mutated = first.clone();
        mutated.programmed_merkle_nodes[0].digest[0] ^= 1;
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            COSET_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Sha512Level5,
            &mutated,
        )
        .is_err());
    }

    #[test]
    fn strict_whole_view_simulator_is_relation_geometry_generic() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64CompressedLevel5StrictZkSmz1,
            9,
            16,
            3,
            19,
            0,
        )
        .expect("construct alternate strict-view relation geometry");
        let binding = [0x24u8; 16];
        let coins = build_smallwood_strict_whole_view_fixture_coins_v1(
            &statement,
            COSET_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Sha512Level5,
            [0x37u8; DIGEST_BYTES],
        )
        .expect("build typed alternate-relation fixture coins");
        let simulation =
            simulate_smallwood_smz1_whole_view_v1(&statement, &binding, COSET_SMOKE_PROFILE, coins)
                .expect("simulate alternate relation geometry without a witness");
        let cfg = SmallwoodConfig::new_with_profile(&statement, COSET_SMOKE_PROFILE)
            .expect("derive alternate simulator geometry");
        assert!(simulation
            .verifier_trace
            .proof
            .opened_witness_row_scalars
            .iter()
            .all(|row| row.len() == cfg.nb_polys));
        assert_eq!(simulation.raw_witness_words_consumed, 0);
        validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            COSET_SMOKE_PROFILE,
            SmallwoodTranscriptBackend::Sha512Level5,
            &simulation,
        )
        .expect("refine alternate relation geometry");
    }

    #[test]
    fn smz9_crypto_rng_typed_coin_sampler_has_exact_draw_ledger() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9,
            8,
            64,
            2,
            17,
            0,
        )
        .expect("construct SMZ9 CryptoRng sampler statement");
        let seed = [0xb7u8; DIGEST_BYTES];
        let mut first_rng = SmallwoodStrictWholeViewDeterministicTestRngV1::new(seed);
        let mut second_rng = SmallwoodStrictWholeViewDeterministicTestRngV1::new(seed);
        let first = sample_smallwood_strict_whole_view_coins_v1(
            &statement,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &mut first_rng,
        )
        .expect("sample direct typed SMZ9 coins");
        let second = sample_smallwood_strict_whole_view_coins_v1(
            &statement,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &mut second_rng,
        )
        .expect("repeat deterministic direct typed SMZ9 coins");
        assert_eq!(first, second);
        assert!(first.draw_ledger.formal_coin_shape_bound);
        assert_eq!(
            first.draw_ledger.field_candidate_words,
            first.draw_ledger.accepted_field_words + first.draw_ledger.field_rejections
        );
        assert_eq!(first.draw_ledger.salt_bytes, SALT_BYTES);
        assert_eq!(first.draw_ledger.final_output_draws_512, 1);
        assert_eq!(
            first.draw_ledger.opened_leaf_tape_draws_512,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE.decs_nb_opened_evals
        );
        assert_eq!(
            first.draw_ledger.programmed_output_draws_512,
            first.coins.programmed_merkle_coins.len()
        );

        let simulation = simulate_smallwood_strict_whole_view_v1(
            &statement,
            &[0x72u8; 16],
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            first.coins,
        )
        .expect("simulate the direct CryptoRng typed tape");
        assert!(simulation.verifier_trace.accept);
        assert_eq!(simulation.oracle_replay_receipt.final_piop_program_hits, 1);
        assert_eq!(simulation.oracle_replay_receipt.lazy_merkle_program_hits, 0);
    }

    #[test]
    fn smz9_whole_view_simulator_is_witness_free_canonical_and_mutation_bound() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9,
            8,
            64,
            2,
            17,
            0,
        )
        .expect("construct SMZ9 simulator statement");
        let binding = [0x62u8; 16];
        let seed = [0x93u8; DIGEST_BYTES];
        let coins = build_smallwood_strict_whole_view_fixture_coins_v1(
            &statement,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            seed,
        )
        .expect("build typed SMZ9 fixture coins");

        let mut reused_coin_tape = coins.clone();
        assert!(reused_coin_tape.opened_leaf_tapes.len() >= 2);
        reused_coin_tape.opened_leaf_tapes[1] = reused_coin_tape.opened_leaf_tapes[0];
        let reused_error = simulate_smallwood_strict_whole_view_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            reused_coin_tape,
        )
        .expect_err("reused 512-bit input coin must fail closed");
        assert_eq!(
            reused_error.to_string(),
            "constraint system violated: smallwood strict-view typed tape reuses a 512-bit input coin"
        );

        let mut unconsumed_coin_tape = coins.clone();
        let mut trailing_coin = unconsumed_coin_tape
            .programmed_merkle_coins
            .last()
            .expect("SMZ9 fixture has a lazy Merkle program")
            .clone();
        trailing_coin.output = [0xd3u8; DIGEST_BYTES];
        trailing_coin.input = SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode {
            left: [0xd1u8; DIGEST_BYTES],
            right: [0xd2u8; DIGEST_BYTES],
        };
        unconsumed_coin_tape
            .programmed_merkle_coins
            .push(trailing_coin);
        let unconsumed_error = simulate_smallwood_strict_whole_view_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            unconsumed_coin_tape,
        )
        .expect_err("unconsumed typed coin must fail closed");
        assert_eq!(
            unconsumed_error.to_string(),
            "constraint system violated: smallwood strict-view programmed Merkle coin tape has unconsumed entries"
        );

        let first = simulate_smallwood_strict_whole_view_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            coins.clone(),
        )
        .expect("simulate exact canonical SMZ9 view");
        let second = simulate_smallwood_strict_whole_view_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            coins,
        )
        .expect("repeat deterministic SMZ9 simulation");
        assert_eq!(first, second);
        assert_eq!(first.raw_witness_words_consumed, 0);
        assert_eq!(&first.proof_bytes[..4], b"SMZ9");
        assert_eq!(
            decode_smallwood_smz9_proof_trace_v1(&first.proof_bytes)
                .expect("decode simulated SMZ9 view")
                .wire_identity,
            SmallwoodProofWireIdentityV1::StrictZkSha512Poseidon2V8Smz9,
        );
        validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &first,
        )
        .expect("refine the complete serialized SMZ9 view");
        assert!(first.verifier_trace.accept);
        assert!(!first.concrete_sha512_accepts);
        assert!(first.coin_consumption.all_supplied_coins_consumed);
        assert_eq!(first.oracle_replay_receipt.final_piop_program_hits, 1);
        assert_eq!(first.oracle_replay_receipt.lazy_merkle_program_hits, 0);

        let mut prior_query_conflict = first.clone();
        let final_program_key = prior_query_conflict
            .oracle_query_trace
            .iter()
            .find(|query| {
                query.programmed_kind == Some(SmallwoodSha512OracleProgramKindV1::FinalPiop)
            })
            .expect("overlay trace contains the final-PIOP programmed query")
            .key
            .clone();
        prior_query_conflict
            .prior_sha512_queries
            .push(final_program_key);
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &prior_query_conflict,
        )
        .is_err());

        let mut wrong_program_output = first.clone();
        wrong_program_output.programmed_final_piop_output[0] ^= 1;
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &wrong_program_output,
        )
        .is_err());

        let decoded = decode_smallwood_smz9_proof_trace_v1(&first.proof_bytes)
            .expect("decode canonical SMZ9 proof before salt-only route mutation");
        let mut salt_only_first_program = first.clone();
        salt_only_first_program.programmed_final_piop_input_words =
            bytes_to_words_unchecked(&decoded.salt);
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &salt_only_first_program,
        )
        .is_err());

        let mut smz8_magic = first.proof_bytes.clone();
        smz8_magic[..4].copy_from_slice(b"SMZ8");
        assert!(decode_smallwood_smz9_proof_trace_v1(&smz8_magic).is_err());

        let mut mutated = first.clone();
        mutated.programmed_final_piop_input_words[0] ^= 1;
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &mutated,
        )
        .is_err());
        let mut mutated = first.clone();
        mutated.programmed_merkle_nodes[0].digest[0] ^= 1;
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &mutated,
        )
        .is_err());

        let mut reordered = first.clone();
        reordered.programmed_merkle_nodes.swap(0, 1);
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &reordered,
        )
        .is_err());

        let mut duplicate_position = first.clone();
        assert!(duplicate_position.programmed_merkle_nodes.len() >= 2);
        let repeated_level = duplicate_position.programmed_merkle_nodes[0].level;
        let repeated_node_index = duplicate_position.programmed_merkle_nodes[0].node_index;
        duplicate_position.programmed_merkle_nodes[1].level = repeated_level;
        duplicate_position.programmed_merkle_nodes[1].node_index = repeated_node_index;
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &duplicate_position,
        )
        .is_err());

        let mut role_mismatch = first.clone();
        let leaf_program = role_mismatch
            .programmed_merkle_nodes
            .iter_mut()
            .find(|node| node.level == 0)
            .expect("SMZ9 lazy program contains a level-zero frontier leaf");
        leaf_program.input = SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode {
            left: [0u8; DIGEST_BYTES],
            right: [1u8; DIGEST_BYTES],
        };
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &role_mismatch,
        )
        .is_err());

        let mut internal_role_mismatch = first.clone();
        let internal_program = internal_role_mismatch
            .programmed_merkle_nodes
            .iter_mut()
            .find(|node| node.level > 0)
            .expect("SMZ9 lazy program contains an internal frontier node");
        internal_program.input = SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf {
            tape: [0u8; DIGEST_BYTES],
            committed_evaluations: Vec::new(),
            masking_evaluations: Vec::new(),
        };
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &internal_role_mismatch,
        )
        .is_err());

        let mut noncanonical_leaf = first.clone();
        let leaf_program = noncanonical_leaf
            .programmed_merkle_nodes
            .iter_mut()
            .find(|node| node.level == 0)
            .expect("SMZ9 lazy program contains a level-zero frontier leaf");
        match &mut leaf_program.input {
            SmallwoodStrictZkProgrammedMerkleInputV1::StrictZkLeaf {
                committed_evaluations,
                ..
            } => committed_evaluations[0] = FIELD_ORDER,
            SmallwoodStrictZkProgrammedMerkleInputV1::MerkleNode { .. } => {
                panic!("level-zero lazy program used the internal-node role")
            }
        }
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &noncanonical_leaf,
        )
        .is_err());

        let mut duplicate_input = first;
        let internal_indices = duplicate_input
            .programmed_merkle_nodes
            .iter()
            .enumerate()
            .filter_map(|(index, node)| (node.level > 0).then_some(index))
            .take(2)
            .collect::<Vec<_>>();
        assert_eq!(internal_indices.len(), 2);
        let repeated_input = duplicate_input.programmed_merkle_nodes[internal_indices[0]]
            .input
            .clone();
        duplicate_input.programmed_merkle_nodes[internal_indices[1]].input = repeated_input;
        assert!(validate_smallwood_strict_whole_view_simulation_v1(
            &statement,
            &binding,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            &duplicate_input,
        )
        .is_err());
    }

    #[test]
    fn smz9_exact_geometry_honest_map_audit_is_full_rank_and_fail_closed() {
        let statement = StructuralIdentityWitnessStatement::new_for_arithmetization(
            SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9,
            686,
            64,
            8,
            830,
            0,
        )
        .expect("construct exact SMZ9 honest-map geometry");
        let coins = build_smallwood_strict_whole_view_fixture_coins_v1(
            &statement,
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            [0xa7u8; DIGEST_BYTES],
        )
        .expect("build typed exact-geometry SMZ9 fixture coins");
        let simulation = simulate_smallwood_strict_whole_view_v1(
            &statement,
            &[0x5au8; 16],
            POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE,
            SmallwoodTranscriptBackend::Sha512Poseidon2V8Smz9,
            coins,
        )
        .expect("simulate exact SMZ9 honest-map geometry");
        let report = crate::smallwood_poseidon2_v8_zk_refinement::audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(
            &simulation.verifier_trace,
        )
        .expect("audit exact SMZ9 honest maps");
        assert!(report.exact_square_full_rank_decomposition());
        assert_eq!(report.lvcs_tail_coin_count, 2_800);
        assert_eq!(report.lvcs_joint_view_count, 2_800);

        let mut duplicate_piop = simulation.verifier_trace.clone();
        duplicate_piop.eval_points[5] = duplicate_piop.eval_points[4];
        assert!(crate::smallwood_poseidon2_v8_zk_refinement::audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(
            &duplicate_piop,
        )
        .is_err());

        let mut singular_lvcs = simulation.verifier_trace.clone();
        singular_lvcs.pcs_trace.coeffs[0].fill(0);
        assert!(crate::smallwood_poseidon2_v8_zk_refinement::audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(
            &singular_lvcs,
        )
        .is_err());

        let mut duplicate_decs = simulation.verifier_trace;
        duplicate_decs.pcs_trace.decs_eval_points[19] =
            duplicate_decs.pcs_trace.decs_eval_points[18];
        assert!(crate::smallwood_poseidon2_v8_zk_refinement::audit_smallwood_poseidon2_v8_smz9_honest_maps_v1(
            &duplicate_decs,
        )
        .is_err());
    }
}
