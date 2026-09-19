//! Exact 869-byte mixed conventional-hash M4 candidate compiler.
//!
//! This module deliberately has no accepting proof verifier.  It builds one
//! chip-free M4 relation for either of two source-identical hash profiles and
//! exposes post-compiler geometry so a later disk-admitted run can select a
//! winner.  `WINNER` and `PRODUCTION_AUTHORIZED` remain false until that run,
//! complete ZK, an E384 PCS/channel, QROM composition, refinement, transport,
//! and retained proof artifacts all pass.

use std::array;

use binius_circuits::keccak::permutation::keccak_f1600;
use binius_core::constraint_system::m4::WitnessM4;
use binius_core::Word;
use binius_frontend::{CircuitBuilder, CircuitM4, PopulateM4Error, Wire};
pub use hegemon_strict_mixed_field_prototype::{B128, E384};
use sha2::{Digest as ShaDigest, Sha512};
use transaction_circuit::full_blake2b448_relation as scalar_candidate;
use transaction_circuit::full_blake2b448_relation::{
    FullBlake2b448Statement, StablecoinConsensusStateSeam,
};
use transaction_circuit::full_shake448_relation::{
    AccumulatorOpening, FullShake448Witness, NoteKind, NoteOpening, PrivateAuthMode,
};
use transaction_circuit::full_shake448_statement::{
    V6ActivationBinding, V6_CANONICAL_CIPHERTEXT_BYTES,
};

use super::{
    and_msb, assert_61_bit, assert_digest_eq_cond, assert_digest_nonzero_cond,
    assert_digest_unequal_cond, assert_digest_zero_cond, assert_implies, assert_low_bool,
    assert_words_zero_cond, constant_words, constrain_approval_membership, constrain_auth_non_hash,
    constrain_note_and_selectors, constrain_slots, decode_be, digest_or, low_bool_msb, map_private,
    or_msb, pack_bytes, select_accumulator, select_digest, AccumulatorWords, AuthWords,
    BalanceNote, DecodedPublic, FrameBuilder, FullM4Wires, InputWords, ModeSelectors, OutputWords,
    PackedFrame, PolicySelectors,
};

/// The exact Binius source revision used by both comparison circuits.
pub const PINNED_BINIUS_REVISION: &str = "3f96163049f680b2909f6545690bd929f1b48c44";
/// Canonical SHA-512 over the local Binius Cargo manifests, lock/toolchain
/// files, and complete `crates/` tree. Each sorted entry is framed as a
/// big-endian path length, UTF-8 relative path, big-endian byte length, and raw
/// bytes after `hegemon.binius64.local-tree.v1\0`. The dependency-free source
/// checker recomputes this value and fails closed on any drift.
pub const PINNED_BINIUS_TREE_SHA512: &str = "1aead2b02df1b30bc217ae4d0337ccf9ab7fa1e42dabcc8f0c0a91aef6059eb7fe55fef123583a9af2e2d769566618f2c5e734b2afce0b0d006c695de8cab052";
/// Exact scalar-candidate identity. It is diagnostic-only and is rejected by
/// production dispatch; this compiler never reinterprets a historical V6
/// magic or allocates a production route.
pub const DIAGNOSTIC_STATEMENT_MAGIC: [u8; 8] = scalar_candidate::CANDIDATE_STATEMENT_MAGIC;
pub const DIAGNOSTIC_STATEMENT_GRAMMAR: u16 = scalar_candidate::CANDIDATE_STATEMENT_GRAMMAR;
pub const CANDIDATE_FRAME_TAG: [u8; 8] = scalar_candidate::CANDIDATE_PROFILE_TAG;
pub const CANDIDATE_STATEMENT_BYTES: usize = scalar_candidate::CANDIDATE_STATEMENT_BYTES;
pub const CANDIDATE_STATEMENT_WORDS: usize = CANDIDATE_STATEMENT_BYTES.div_ceil(8);
/// Typed public consensus-state seam appended after the immutable 109-word
/// HX448C02 statement. These are relation inputs, not statement bytes.
pub const CANDIDATE_CONSENSUS_STATE_WORDS: usize = 50;
pub const CANDIDATE_PUBLIC_WORDS: usize =
    CANDIDATE_STATEMENT_WORDS + CANDIDATE_CONSENSUS_STATE_WORDS;
pub const CANDIDATE_BASE_PRIVATE_WORDS: usize = super::PRIVATE_WORDS;
pub const CIPHERTEXT_WORDS: usize = V6_CANONICAL_CIPHERTEXT_BYTES.div_ceil(8);
pub const CANDIDATE_PRIVATE_WORDS: usize = CANDIDATE_BASE_PRIVATE_WORDS + 2 * CIPHERTEXT_WORDS;
pub const CANDIDATE_PRIVATE_BYTES: usize = CANDIDATE_PRIVATE_WORDS * 8;
pub const DIGEST_BYTES: usize = 56;
pub const DIGEST_WORDS: usize = DIGEST_BYTES / 8;
pub const LIVE_STABLECOIN_BINDING_WORDS: usize =
    scalar_candidate::LIVE_STABLECOIN_BINDING_BYTES / 8;
pub const MANIFEST_STATE_COMMITMENT_V1_WORDS: usize =
    protocol_kernel::stablecoin_manifest_commitment_v1::
        STABLECOIN_MANIFEST_STATE_V1_COMMITMENT_WORDS;
pub const SHAKE256_RATE_BYTES: usize = 136;
pub const SHAKE256_RATE_WORDS: usize = SHAKE256_RATE_BYTES / 8;
pub const SHA3_512_RATE_BYTES: usize = 72;
pub const SHA3_512_RATE_WORDS: usize = SHA3_512_RATE_BYTES / 8;
pub const BLAKE2B_BLOCK_BYTES: usize = 128;
pub const BLAKE2B_BLOCK_WORDS: usize = 16;
pub const AUTHORIZATION_MODE_COUNT: usize = 5;
pub const ACTIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES: usize = 61;
/// SCALE widths for `(asset_id, oracle_feed, attestation_id,
/// min_collateral_ratio_ppm, max_mint_per_epoch, oracle_max_age,
/// policy_version, active)` in the live kernel manifest.
pub const ACTIVE_STABLECOIN_POLICY_TUPLE_COMPONENT_BYTES: [usize; 8] = [4, 4, 8, 16, 16, 8, 4, 1];
pub const ACTIVE_STABLECOIN_POLICY_HASH_BYTES: usize = 48;
/// Conventional kernel-state commitment width. This does not select or imply
/// a 48-byte proof challenge field.
pub const ACTIVE_STABLECOIN_MANIFEST_COMMITMENT_BYTES: usize =
    scalar_candidate::STABLECOIN_MANIFEST_STATE_COMMITMENT_V1_BYTES;
pub const ACTIVE_STABLECOIN_POLICY_DOMAIN: &[u8] = b"hegemon.kernel.stablecoin-policy.v2";
pub const ACTIVE_STABLECOIN_MANIFEST_STATE_DOMAIN: &[u8] =
    b"hegemon.kernel.stablecoin-manifest-state.v1";

pub const STATE_SEAM_VERSION_WORD: usize = 0;
pub const STATE_EXPECTED_HEIGHT_WORD: usize = 1;
pub const STATE_PROVIDED_HEIGHT_WORD: usize = 2;
pub const STATE_ENTRY_INDEX_WORD: usize = 3;
pub const STATE_ENTRY_PRESENT_WORD: usize = 4;
pub const STATE_ASSET_ID_WORD: usize = 5;
pub const STATE_ORACLE_FEED_WORD: usize = 6;
pub const STATE_ATTESTATION_ID_WORD: usize = 7;
pub const STATE_MIN_COLLATERAL_WORDS: std::ops::Range<usize> = 8..10;
pub const STATE_MAX_MINT_WORDS: std::ops::Range<usize> = 10..12;
pub const STATE_ORACLE_MAX_AGE_WORD: usize = 12;
pub const STATE_ORACLE_SUBMITTED_AT_WORD: usize = 13;
pub const STATE_ENABLED_AT_WORD: usize = 14;
pub const STATE_RETIRED_PRESENT_WORD: usize = 15;
pub const STATE_RETIRED_AT_WORD: usize = 16;
pub const STATE_POLICY_VERSION_WORD: usize = 17;
pub const STATE_ACTIVE_WORD: usize = 18;
pub const STATE_POLICY_HASH_WORDS: std::ops::Range<usize> = 19..25;
pub const STATE_ORACLE_COMMITMENT_WORDS: std::ops::Range<usize> = 25..31;
pub const STATE_ATTESTATION_COMMITMENT_WORDS: std::ops::Range<usize> = 31..37;
pub const STATE_ATTESTATION_DISPUTED_WORD: usize = 37;
pub const STATE_EXPECTED_MANIFEST_COMMITMENT_WORDS: std::ops::Range<usize> = 38..44;
pub const STATE_PROVIDED_MANIFEST_COMMITMENT_WORDS: std::ops::Range<usize> = 44..50;

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
pub const OFFSET_PROFILE: usize = 698;
pub const OFFSET_DOMAIN_SET: usize = 699;
pub const OFFSET_CHAIN_ID: usize = 701;
pub const OFFSET_GENESIS_ID: usize = 757;
pub const OFFSET_RULES_HASH: usize = 813;

const ROLE_NOTE: [u8; 8] = scalar_candidate::ROLE_NOTE;
const ROLE_NULLIFIER: [u8; 8] = scalar_candidate::ROLE_NULLIFIER;
const ROLE_MERKLE: [u8; 8] = scalar_candidate::ROLE_MERKLE;
const ROLE_SPEND_A: [u8; 8] = scalar_candidate::ROLE_SPEND_A;
const ROLE_SPEND_B: [u8; 8] = scalar_candidate::ROLE_SPEND_B;
const ROLE_POLICY: [u8; 8] = scalar_candidate::ROLE_POLICY;
const ROLE_AUTH_A: [u8; 8] = scalar_candidate::ROLE_AUTH_A;
const ROLE_AUTH_B: [u8; 8] = scalar_candidate::ROLE_AUTH_B;
const ROLE_INTENT: [u8; 8] = scalar_candidate::ROLE_INTENT;
const ROLE_BALANCE_TAG: [u8; 8] = scalar_candidate::ROLE_BALANCE;
const ROLE_CIPHERTEXT_HASH: [u8; 8] = scalar_candidate::ROLE_CIPHERTEXT;
pub const KEY_OUTPUT_LANE_A_TAG: [u8; 8] = scalar_candidate::LANE_A_TAG;
pub const KEY_OUTPUT_LANE_B_TAG: [u8; 8] = scalar_candidate::LANE_B_TAG;

const SHAKE_DOMAIN_SUFFIX: u64 = 0x1f;
const SHA3_DOMAIN_SUFFIX: u64 = 0x06;

/// Neither profile is selected by source fiat.  A disk-admitted compiled/DCE
/// comparison is required first.
pub const WINNER: Option<SecretHashProfile> = None;
pub const PRODUCTION_AUTHORIZED: bool = false;
pub const IDENTITY_FROZEN: bool = false;
pub const COMPLETE_ZERO_KNOWLEDGE_PROVED: bool = false;
pub const COMPOSED_QROM_PQ128_PROVED: bool = false;
pub const E384_PCS_CHANNEL_INTEGRATED: bool = false;
pub const M4_AGGREGATE_RELATION_ARTIFACT_VERIFIED: bool = false;
/// Grammar two binds the live 48-byte policy/oracle/attestation fields as six
/// public 64-bit words each. There is no 48-to-56 conversion.
pub const ACTIVE_STABLECOIN_MANIFEST_ADAPTER_INTEGRATED: bool = true;
/// The source now contains lifecycle/freshness/dispute/cap constraints, but no
/// aggregate circuit was compiled under the disk stop. Keep this evidence flag
/// false until an actual retained artifact exists.
pub const ACTIVE_STABLECOIN_LIFECYCLE_CONSTRAINTS_COMPILED: bool = false;
/// The inactive flat kernel commitment has no compiled recomputation or
/// selected-entry membership graph in this candidate.
pub const ACTIVE_STABLECOIN_MANIFEST_MEMBERSHIP_GRAPH_COMPILED: bool = false;
/// The three exact 48-byte compatibility authorities do not establish a
/// positive strict-PQ composition margin. Authoritative wider constructors or
/// preimages are required before any successor can be production-authorized.
pub const STRICT_STABLECOIN_PQ_MARGIN: bool = false;

/// Exact source-level semantic group inventory. These names describe emitted
/// M4 constraints; they are not post-DCE counts because no circuit build was
/// admitted under the disk stop.
pub const LOCAL_NON_HASH_CONSTRAINT_GROUPS: [&str; 20] = [
    "statement transport and canonical padding",
    "all sixteen activity masks with all-empty rejection",
    "signed-magnitude ranges and no negative zero",
    "four canonical ordered asset slots",
    "active note kind value and asset ranges",
    "active selector one-hot and selected-asset equality",
    "inactive input witness and public nullifier zero",
    "active input 32-bit Merkle position",
    "inactive output witness ciphertext and public bindings zero",
    "active ciphertext exact size and trailing padding",
    "duplicate active nullifier rejection",
    "five-mode range and one-hot selection",
    "mode-specific 2-in 2-out activity shapes",
    "mode-specific note typing and unused-lane zeroing",
    "accumulator threshold signer and approval metadata",
    "approval increment no-clear one-change and signer membership",
    "signed native balance including fee",
    "ordinary non-native conservation",
    "stablecoin mint and burn signed balance",
    "disabled unique-zero and enabled typed stablecoin surface",
];

pub const HASH_LINK_CONSTRAINT_GROUPS: [&str; 7] = [
    "note commitments and resolved authorization keys",
    "nullifier derivation and active public equality",
    "32-level Merkle direction selection and anchor equality",
    "policy and four authorization-lane digest links",
    "final-spend intent equality",
    "public balance-tag equality",
    "canonical ciphertext hash equality",
];

pub const CONSENSUS_STATE_SEAM_CONSTRAINT_GROUPS: [&str; 9] = [
    "disabled state unique-zero",
    "v1 typed widths booleans and entry presence",
    "nonzero expected/provided manifest commitment equality",
    "expected/provided current-height equality",
    "selected entry statement field equalities",
    "active and lifecycle-open predicates",
    "canonical optional retirement and strict retirement bound",
    "oracle nonfuture and saturating freshness bound",
    "undisputed nonzero issuance and u128 cap",
];

/// These predicates are intentionally not represented as M4 constraints yet.
pub const HOST_ORACLE_ONLY_GROUPS: [&str; 4] = [
    "61-byte policy-identity BLAKE2b-384 recomputation",
    "whole-manifest v1 BLAKE2b-384 recomputation",
    "selected-entry index membership in the committed vector",
    "consensus authentication of expected root and height",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterfeitDisposition {
    M4Reject,
    HostOracleOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterfeitMutationCase {
    pub name: &'static str,
    pub disposition: CounterfeitDisposition,
}

pub const COUNTERFEIT_MUTATION_MATRIX: [CounterfeitMutationCase; 20] = [
    CounterfeitMutationCase {
        name: "all_empty_activity",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "invalid_authorization_shape",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "signed_balance_drift",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "stable_mint_or_burn_drift",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "missing_consensus_state",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "wrong_state_seam_version",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "zero_manifest_commitment",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "manifest_commitment_equality_mismatch",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "current_height_equality_mismatch",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "missing_selected_entry",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "statement_entry_binding_mismatch",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "inactive_or_closed_lifecycle",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "future_or_stale_oracle",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "disputed_attestation",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "zero_or_over_cap_issuance",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "note_nullifier_merkle_or_ciphertext_link_drift",
        disposition: CounterfeitDisposition::M4Reject,
    },
    CounterfeitMutationCase {
        name: "forged_policy_hash_derivation",
        disposition: CounterfeitDisposition::HostOracleOnly,
    },
    CounterfeitMutationCase {
        name: "forged_whole_manifest_commitment",
        disposition: CounterfeitDisposition::HostOracleOnly,
    },
    CounterfeitMutationCase {
        name: "forged_selected_entry_membership",
        disposition: CounterfeitDisposition::HostOracleOnly,
    },
    CounterfeitMutationCase {
        name: "forged_consensus_expected_root_or_height",
        disposition: CounterfeitDisposition::HostOracleOnly,
    },
];

pub type DiagnosticActivationBinding = V6ActivationBinding;

fn assert_diagnostic_activation(activation: DiagnosticActivationBinding) {
    assert!(
        !activation.has_v6_route(),
        "the diagnostic candidate must not reuse the rejected V6 route"
    );
    assert_ne!(activation.circuit_version, 0);
    assert_ne!(activation.crypto_suite, 0);
    assert_ne!(activation.family_id, 0);
    assert_ne!(activation.action_id, 0);
    assert_ne!(activation.backend_id, 0);
    assert_ne!(activation.proof_profile, 0);
    assert_ne!(activation.domain_set, 0);
    assert_ne!(activation.chain_id, [0; DIGEST_BYTES]);
    assert_ne!(activation.genesis_id, [0; DIGEST_BYTES]);
    assert_ne!(activation.rules_hash, [0; DIGEST_BYTES]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SecretHashProfile {
    /// Unkeyed RFC 7693 BLAKE2b with `nn=56`, plus SHAKE256-448 for
    /// collision-only public bindings.
    Blake2b448Mixed = 1,
    /// Separately tagged FIPS 202 SHA3-512 calls, truncated to 56 bytes, plus
    /// the identical SHAKE256-448 collision-only layer.
    Sha3_512SplitControl = 2,
}

impl SecretHashProfile {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Blake2b448Mixed => "blake2b448-mixed",
            Self::Sha3_512SplitControl => "sha3-512-split-control",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HashAlgorithm {
    Blake2b448,
    Sha3_512Truncated448,
    Shake256_448,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HashPurpose {
    PreimageHidingAndBinding,
    HiddenSeedDerivation,
    CollisionOnlyBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashRoleSpec {
    pub role: &'static str,
    pub algorithm: HashAlgorithm,
    pub purpose: HashPurpose,
    pub calls: usize,
    pub maximum_frame_bytes: usize,
    pub output_bytes: usize,
    pub cores_per_call: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashInvocationKind {
    NoteInput(usize),
    NoteOutput(usize),
    Nullifier(usize),
    Merkle { input: usize, level: usize },
    Spend { input: usize, lane: usize },
    Policy,
    Authorization { slot: usize, lane: usize },
    Intent,
    Balance,
    Ciphertext(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateOutputBinding {
    Internal,
    PublicWhenInputActive(usize),
    PublicWhenOutputActive(usize),
    PublicAlways,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateFrameWidth {
    Exact(usize),
    AuthorizationMux {
        arm_bytes: [usize; AUTHORIZATION_MODE_COUNT],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashInvocationSpec {
    pub index: usize,
    pub kind: HashInvocationKind,
    pub role: [u8; 8],
    pub algorithm: HashAlgorithm,
    pub purpose: HashPurpose,
    pub maximum_frame_bytes: usize,
    pub frame_width: CandidateFrameWidth,
    pub output_bytes: usize,
    pub primitive_cores: usize,
    pub binding: CandidateOutputBinding,
    pub source_bound: bool,
    pub output_bound: bool,
}

/// Exact scalar-authority call order. Algorithm choice is explicit on every
/// invocation; no adapter may infer it from a role string or a call count.
pub fn hash_invocation_registry(profile: SecretHashProfile) -> Vec<HashInvocationSpec> {
    let secret_algorithm = match profile {
        SecretHashProfile::Blake2b448Mixed => HashAlgorithm::Blake2b448,
        SecretHashProfile::Sha3_512SplitControl => HashAlgorithm::Sha3_512Truncated448,
    };
    let secret_cores = |frame_bytes: usize| match profile {
        SecretHashProfile::Blake2b448Mixed => frame_bytes.div_ceil(BLAKE2B_BLOCK_BYTES),
        SecretHashProfile::Sha3_512SplitControl => frame_bytes / SHA3_512_RATE_BYTES + 1,
    };
    let mut calls = Vec::with_capacity(scalar_candidate::PHYSICAL_HASH_CALLS);
    let mut push =
        |index, kind, role, algorithm, purpose, frame_width, primitive_cores, binding| {
            let maximum_frame_bytes = match frame_width {
                CandidateFrameWidth::Exact(bytes) => bytes,
                CandidateFrameWidth::AuthorizationMux { arm_bytes } => {
                    *arm_bytes.iter().max().expect("five authorization arms")
                }
            };
            calls.push(HashInvocationSpec {
                index,
                kind,
                role,
                algorithm,
                purpose,
                maximum_frame_bytes,
                frame_width,
                output_bytes: DIGEST_BYTES,
                primitive_cores,
                binding,
                source_bound: true,
                output_bound: true,
            });
        };
    for input in 0..2 {
        push(
            scalar_candidate::NOTE_CALL_START + input,
            HashInvocationKind::NoteInput(input),
            ROLE_NOTE,
            secret_algorithm,
            HashPurpose::PreimageHidingAndBinding,
            CandidateFrameWidth::Exact(232),
            secret_cores(232),
            CandidateOutputBinding::Internal,
        );
    }
    for output in 0..2 {
        push(
            scalar_candidate::NOTE_CALL_START + 2 + output,
            HashInvocationKind::NoteOutput(output),
            ROLE_NOTE,
            secret_algorithm,
            HashPurpose::PreimageHidingAndBinding,
            CandidateFrameWidth::Exact(232),
            secret_cores(232),
            CandidateOutputBinding::PublicWhenOutputActive(output),
        );
    }
    for input in 0..2 {
        push(
            scalar_candidate::NULLIFIER_CALL_START + input,
            HashInvocationKind::Nullifier(input),
            ROLE_NULLIFIER,
            secret_algorithm,
            HashPurpose::HiddenSeedDerivation,
            CandidateFrameWidth::Exact(135),
            secret_cores(135),
            CandidateOutputBinding::PublicWhenInputActive(input),
        );
    }
    for input in 0..2 {
        for level in 0..32 {
            push(
                scalar_candidate::MERKLE_CALL_START + input * 32 + level,
                HashInvocationKind::Merkle { input, level },
                ROLE_MERKLE,
                HashAlgorithm::Shake256_448,
                HashPurpose::CollisionOnlyBinding,
                CandidateFrameWidth::Exact(133),
                1,
                CandidateOutputBinding::Internal,
            );
        }
    }
    for input in 0..2 {
        push(
            scalar_candidate::SPEND_A_CALL_START + input,
            HashInvocationKind::Spend { input, lane: 0 },
            ROLE_SPEND_A,
            secret_algorithm,
            HashPurpose::HiddenSeedDerivation,
            CandidateFrameWidth::Exact(77),
            secret_cores(77),
            CandidateOutputBinding::Internal,
        );
    }
    for input in 0..2 {
        push(
            scalar_candidate::SPEND_B_CALL_START + input,
            HashInvocationKind::Spend { input, lane: 1 },
            ROLE_SPEND_B,
            secret_algorithm,
            HashPurpose::HiddenSeedDerivation,
            CandidateFrameWidth::Exact(77),
            secret_cores(77),
            CandidateOutputBinding::Internal,
        );
    }
    // Call 74 remains the private accumulator-authorization policy hash;
    // stablecoin policy/oracle/attestation stay direct public statement words.
    push(
        scalar_candidate::POLICY_CALL,
        HashInvocationKind::Policy,
        ROLE_POLICY,
        secret_algorithm,
        HashPurpose::PreimageHidingAndBinding,
        CandidateFrameWidth::Exact(385),
        secret_cores(385),
        CandidateOutputBinding::Internal,
    );
    for lane in 0..2 {
        for slot in 0..2 {
            push(
                if lane == 0 {
                    scalar_candidate::AUTH_A_CALL_START + slot
                } else {
                    scalar_candidate::AUTH_B_CALL_START + slot
                },
                HashInvocationKind::Authorization { slot, lane },
                if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B },
                secret_algorithm,
                HashPurpose::HiddenSeedDerivation,
                CandidateFrameWidth::AuthorizationMux {
                    arm_bytes: authorization_arm_lengths(slot == 1),
                },
                secret_cores(181),
                CandidateOutputBinding::Internal,
            );
        }
    }
    push(
        scalar_candidate::INTENT_CALL,
        HashInvocationKind::Intent,
        ROLE_INTENT,
        HashAlgorithm::Shake256_448,
        HashPurpose::CollisionOnlyBinding,
        CandidateFrameWidth::Exact(720),
        6,
        CandidateOutputBinding::Internal,
    );
    push(
        scalar_candidate::BALANCE_CALL,
        HashInvocationKind::Balance,
        ROLE_BALANCE_TAG,
        HashAlgorithm::Shake256_448,
        HashPurpose::CollisionOnlyBinding,
        CandidateFrameWidth::Exact(100),
        1,
        CandidateOutputBinding::PublicAlways,
    );
    for output in 0..2 {
        push(
            scalar_candidate::CIPHERTEXT_CALL_START + output,
            HashInvocationKind::Ciphertext(output),
            ROLE_CIPHERTEXT_HASH,
            HashAlgorithm::Shake256_448,
            HashPurpose::CollisionOnlyBinding,
            CandidateFrameWidth::Exact(2_182),
            17,
            CandidateOutputBinding::PublicWhenOutputActive(output),
        );
    }
    calls.sort_by_key(|call| call.index);
    assert_eq!(calls.len(), scalar_candidate::PHYSICAL_HASH_CALLS);
    assert!(calls
        .iter()
        .enumerate()
        .all(|(index, call)| index == call.index));
    calls
}

/// Validate every typed call slot independently of the aggregate role counts.
/// This is source-stage metadata validation only; the deferred differential
/// harness must still prove that each compiled frame and digest uses the same
/// shared statement/witness wires as its semantic consumer.
pub fn hash_invocation_registry_is_exact(profile: SecretHashProfile) -> bool {
    let calls = hash_invocation_registry(profile);
    if calls.len() != 83
        || calls.iter().map(|call| call.primitive_cores).sum::<usize>() != primitive_cores(profile)
    {
        return false;
    }
    let secret_algorithm = match profile {
        SecretHashProfile::Blake2b448Mixed => HashAlgorithm::Blake2b448,
        SecretHashProfile::Sha3_512SplitControl => HashAlgorithm::Sha3_512Truncated448,
    };
    let secret_cores = |bytes: usize| match profile {
        SecretHashProfile::Blake2b448Mixed => bytes.div_ceil(BLAKE2B_BLOCK_BYTES),
        SecretHashProfile::Sha3_512SplitControl => bytes / SHA3_512_RATE_BYTES + 1,
    };
    for call in &calls {
        if call.index >= 83
            || call.output_bytes != DIGEST_BYTES
            || !call.source_bound
            || !call.output_bound
        {
            return false;
        }
        let expected = match call.index {
            0..=1 => (
                HashInvocationKind::NoteInput(call.index),
                ROLE_NOTE,
                secret_algorithm,
                HashPurpose::PreimageHidingAndBinding,
                CandidateFrameWidth::Exact(232),
                secret_cores(232),
                CandidateOutputBinding::Internal,
            ),
            2..=3 => (
                HashInvocationKind::NoteOutput(call.index - 2),
                ROLE_NOTE,
                secret_algorithm,
                HashPurpose::PreimageHidingAndBinding,
                CandidateFrameWidth::Exact(232),
                secret_cores(232),
                CandidateOutputBinding::PublicWhenOutputActive(call.index - 2),
            ),
            4..=5 => (
                HashInvocationKind::Nullifier(call.index - 4),
                ROLE_NULLIFIER,
                secret_algorithm,
                HashPurpose::HiddenSeedDerivation,
                CandidateFrameWidth::Exact(135),
                secret_cores(135),
                CandidateOutputBinding::PublicWhenInputActive(call.index - 4),
            ),
            6..=69 => {
                let relative = call.index - 6;
                (
                    HashInvocationKind::Merkle {
                        input: relative / 32,
                        level: relative % 32,
                    },
                    ROLE_MERKLE,
                    HashAlgorithm::Shake256_448,
                    HashPurpose::CollisionOnlyBinding,
                    CandidateFrameWidth::Exact(133),
                    1,
                    CandidateOutputBinding::Internal,
                )
            }
            70..=71 => (
                HashInvocationKind::Spend {
                    input: call.index - 70,
                    lane: 0,
                },
                ROLE_SPEND_A,
                secret_algorithm,
                HashPurpose::HiddenSeedDerivation,
                CandidateFrameWidth::Exact(77),
                secret_cores(77),
                CandidateOutputBinding::Internal,
            ),
            72..=73 => (
                HashInvocationKind::Spend {
                    input: call.index - 72,
                    lane: 1,
                },
                ROLE_SPEND_B,
                secret_algorithm,
                HashPurpose::HiddenSeedDerivation,
                CandidateFrameWidth::Exact(77),
                secret_cores(77),
                CandidateOutputBinding::Internal,
            ),
            74 => (
                HashInvocationKind::Policy,
                ROLE_POLICY,
                secret_algorithm,
                HashPurpose::PreimageHidingAndBinding,
                CandidateFrameWidth::Exact(385),
                secret_cores(385),
                CandidateOutputBinding::Internal,
            ),
            75..=78 => {
                let lane = usize::from(call.index >= 77);
                let slot = (call.index - 75) % 2;
                (
                    HashInvocationKind::Authorization { slot, lane },
                    if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B },
                    secret_algorithm,
                    HashPurpose::HiddenSeedDerivation,
                    CandidateFrameWidth::AuthorizationMux {
                        arm_bytes: authorization_arm_lengths(slot == 1),
                    },
                    secret_cores(181),
                    CandidateOutputBinding::Internal,
                )
            }
            79 => (
                HashInvocationKind::Intent,
                ROLE_INTENT,
                HashAlgorithm::Shake256_448,
                HashPurpose::CollisionOnlyBinding,
                CandidateFrameWidth::Exact(720),
                6,
                CandidateOutputBinding::Internal,
            ),
            80 => (
                HashInvocationKind::Balance,
                ROLE_BALANCE_TAG,
                HashAlgorithm::Shake256_448,
                HashPurpose::CollisionOnlyBinding,
                CandidateFrameWidth::Exact(100),
                1,
                CandidateOutputBinding::PublicAlways,
            ),
            81..=82 => (
                HashInvocationKind::Ciphertext(call.index - 81),
                ROLE_CIPHERTEXT_HASH,
                HashAlgorithm::Shake256_448,
                HashPurpose::CollisionOnlyBinding,
                CandidateFrameWidth::Exact(2_182),
                17,
                CandidateOutputBinding::PublicWhenOutputActive(call.index - 81),
            ),
            _ => return false,
        };
        if (
            call.kind,
            call.role,
            call.algorithm,
            call.purpose,
            call.frame_width,
            call.primitive_cores,
            call.binding,
        ) != expected
            || call.maximum_frame_bytes
                != match call.frame_width {
                    CandidateFrameWidth::Exact(bytes) => bytes,
                    CandidateFrameWidth::AuthorizationMux { arm_bytes } => {
                        *arm_bytes.iter().max().expect("five authorization arms")
                    }
                }
        {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashLoweringCoverage {
    pub profile: SecretHashProfile,
    pub lowered_calls: [bool; 83],
    pub exact_call_specs: bool,
}

impl HashLoweringCoverage {
    pub fn ensure_complete(&self) -> Result<(), &'static str> {
        if !self.exact_call_specs || !self.lowered_calls.into_iter().all(|lowered| lowered) {
            return Err("not every exact typed hash call was lowered exactly once");
        }
        Ok(())
    }
}

struct HashLoweringAudit {
    profile: SecretHashProfile,
    specs: [HashInvocationSpec; 83],
    lowered_calls: [bool; 83],
}

impl HashLoweringAudit {
    fn new(profile: SecretHashProfile) -> Self {
        assert!(hash_invocation_registry_is_exact(profile));
        Self {
            profile,
            specs: hash_invocation_registry(profile)
                .try_into()
                .expect("the exact registry has 83 entries"),
            lowered_calls: [false; 83],
        }
    }

    fn claim(
        &mut self,
        index: usize,
        kind: HashInvocationKind,
        role: [u8; 8],
        algorithm: HashAlgorithm,
        frame_width: CandidateFrameWidth,
        binding: CandidateOutputBinding,
        primitive_cores: usize,
    ) {
        let spec = self.specs[index];
        assert!(
            !self.lowered_calls[index],
            "hash call {index} lowered twice"
        );
        assert_eq!(spec.index, index);
        assert_eq!(spec.kind, kind);
        assert_eq!(spec.role, role);
        assert_eq!(spec.algorithm, algorithm);
        assert_eq!(spec.frame_width, frame_width);
        assert_eq!(spec.output_bytes, DIGEST_BYTES);
        assert_eq!(spec.binding, binding);
        assert_eq!(spec.primitive_cores, primitive_cores);
        assert!(spec.source_bound && spec.output_bound);
        self.lowered_calls[index] = true;
    }

    fn lower_ordinary(
        &mut self,
        builder: &CircuitBuilder,
        index: usize,
        kind: HashInvocationKind,
        role: [u8; 8],
        frame: &PackedFrame,
        binding: CandidateOutputBinding,
    ) -> [Wire; DIGEST_WORDS] {
        let algorithm = self.specs[index].algorithm;
        let primitive_cores = match algorithm {
            HashAlgorithm::Blake2b448 => frame.len_bytes.div_ceil(BLAKE2B_BLOCK_BYTES),
            HashAlgorithm::Sha3_512Truncated448 => frame.len_bytes / SHA3_512_RATE_BYTES + 1,
            HashAlgorithm::Shake256_448 => frame.len_bytes / SHAKE256_RATE_BYTES + 1,
        };
        self.claim(
            index,
            kind,
            role,
            algorithm,
            CandidateFrameWidth::Exact(frame.len_bytes),
            binding,
            primitive_cores,
        );
        match algorithm {
            HashAlgorithm::Blake2b448 => blake2b448_words(builder, frame),
            HashAlgorithm::Sha3_512Truncated448 => sha3_512_truncated448_words(builder, frame),
            HashAlgorithm::Shake256_448 => shake256_448_words(builder, frame),
        }
    }

    fn lower_authorization_mux(
        &mut self,
        builder: &CircuitBuilder,
        index: usize,
        kind: HashInvocationKind,
        role: [u8; 8],
        selectors: &[Wire; AUTHORIZATION_MODE_COUNT],
        arms: &[PackedFrame; AUTHORIZATION_MODE_COUNT],
    ) -> [Wire; DIGEST_WORDS] {
        let algorithm = self.specs[index].algorithm;
        let arm_bytes = arms.each_ref().map(|arm| arm.len_bytes);
        let primitive_cores = match algorithm {
            HashAlgorithm::Blake2b448 => 2,
            HashAlgorithm::Sha3_512Truncated448 => 3,
            HashAlgorithm::Shake256_448 => panic!("authorization secret role cannot use SHAKE256"),
        };
        self.claim(
            index,
            kind,
            role,
            algorithm,
            CandidateFrameWidth::AuthorizationMux { arm_bytes },
            CandidateOutputBinding::Internal,
            primitive_cores,
        );
        match algorithm {
            HashAlgorithm::Blake2b448 => mux_one_hot_blake2b448(builder, selectors, arms),
            HashAlgorithm::Sha3_512Truncated448 => {
                mux_one_hot_sha3_512_truncated448(builder, selectors, arms)
            }
            HashAlgorithm::Shake256_448 => unreachable!(),
        }
    }

    fn finish(self) -> HashLoweringCoverage {
        let coverage = HashLoweringCoverage {
            profile: self.profile,
            lowered_calls: self.lowered_calls,
            exact_call_specs: hash_invocation_registry_is_exact(self.profile),
        };
        coverage
            .ensure_complete()
            .expect("all 83 exact typed hash calls must be lowered exactly once");
        coverage
    }
}

pub const fn role_registry(profile: SecretHashProfile) -> [HashRoleSpec; 11] {
    let secret_algorithm = match profile {
        SecretHashProfile::Blake2b448Mixed => HashAlgorithm::Blake2b448,
        SecretHashProfile::Sha3_512SplitControl => HashAlgorithm::Sha3_512Truncated448,
    };
    let secret_cores = match profile {
        SecretHashProfile::Blake2b448Mixed => [2, 2, 1, 1, 4, 2, 2],
        SecretHashProfile::Sha3_512SplitControl => [4, 2, 2, 2, 6, 3, 3],
    };
    [
        HashRoleSpec {
            role: "nt.b4481",
            algorithm: secret_algorithm,
            purpose: HashPurpose::PreimageHidingAndBinding,
            calls: 4,
            maximum_frame_bytes: 232,
            output_bytes: 56,
            cores_per_call: secret_cores[0],
        },
        HashRoleSpec {
            role: "nf.b4481",
            algorithm: secret_algorithm,
            purpose: HashPurpose::HiddenSeedDerivation,
            calls: 2,
            maximum_frame_bytes: 135,
            output_bytes: 56,
            cores_per_call: secret_cores[1],
        },
        HashRoleSpec {
            role: "mk.s4481",
            algorithm: HashAlgorithm::Shake256_448,
            purpose: HashPurpose::CollisionOnlyBinding,
            calls: 64,
            maximum_frame_bytes: 133,
            output_bytes: 56,
            cores_per_call: 1,
        },
        HashRoleSpec {
            role: "sk.b44a1",
            algorithm: secret_algorithm,
            purpose: HashPurpose::HiddenSeedDerivation,
            calls: 2,
            maximum_frame_bytes: 77,
            output_bytes: 56,
            cores_per_call: secret_cores[2],
        },
        HashRoleSpec {
            role: "sk.b44b1",
            algorithm: secret_algorithm,
            purpose: HashPurpose::HiddenSeedDerivation,
            calls: 2,
            maximum_frame_bytes: 77,
            output_bytes: 56,
            cores_per_call: secret_cores[3],
        },
        HashRoleSpec {
            role: "pl.b4481",
            algorithm: secret_algorithm,
            purpose: HashPurpose::PreimageHidingAndBinding,
            calls: 1,
            maximum_frame_bytes: 385,
            output_bytes: 56,
            cores_per_call: secret_cores[4],
        },
        HashRoleSpec {
            role: "au.b44a1",
            algorithm: secret_algorithm,
            purpose: HashPurpose::HiddenSeedDerivation,
            calls: 2,
            maximum_frame_bytes: 181,
            output_bytes: 56,
            cores_per_call: secret_cores[5],
        },
        HashRoleSpec {
            role: "au.b44b1",
            algorithm: secret_algorithm,
            purpose: HashPurpose::HiddenSeedDerivation,
            calls: 2,
            maximum_frame_bytes: 181,
            output_bytes: 56,
            cores_per_call: secret_cores[6],
        },
        HashRoleSpec {
            role: "in.s4481",
            algorithm: HashAlgorithm::Shake256_448,
            purpose: HashPurpose::CollisionOnlyBinding,
            calls: 1,
            maximum_frame_bytes: 720,
            output_bytes: 56,
            cores_per_call: 6,
        },
        HashRoleSpec {
            role: "bl.s4481",
            algorithm: HashAlgorithm::Shake256_448,
            purpose: HashPurpose::CollisionOnlyBinding,
            calls: 1,
            maximum_frame_bytes: 100,
            output_bytes: 56,
            cores_per_call: 1,
        },
        HashRoleSpec {
            role: "ct.s4481",
            algorithm: HashAlgorithm::Shake256_448,
            purpose: HashPurpose::CollisionOnlyBinding,
            calls: 2,
            maximum_frame_bytes: 2_182,
            output_bytes: 56,
            cores_per_call: 17,
        },
    ]
}

pub const fn physical_hash_calls(profile: SecretHashProfile) -> usize {
    let registry = role_registry(profile);
    let mut total = 0;
    let mut index = 0;
    while index < registry.len() {
        total += registry[index].calls;
        index += 1;
    }
    total
}

pub const fn primitive_cores(profile: SecretHashProfile) -> usize {
    let registry = role_registry(profile);
    let mut total = 0;
    let mut index = 0;
    while index < registry.len() {
        total += registry[index].calls * registry[index].cores_per_call;
        index += 1;
    }
    total
}

/// Source-static native AND projection for the pinned builder. Keccak costs
/// 600 ANDs per permutation; BLAKE2b costs 576 ANDs per compression. The 384
/// rotations per BLAKE compression are linear Shift constraints and are
/// reported separately rather than mislabeled as nonlinear gates.
pub const fn raw_hash_and_words(profile: SecretHashProfile) -> usize {
    match profile {
        SecretHashProfile::Blake2b448Mixed => 105 * 600 + 28 * 576,
        SecretHashProfile::Sha3_512SplitControl => 151 * 600,
    }
}

pub const fn raw_hash_rotation_linear_words(profile: SecretHashProfile) -> usize {
    match profile {
        SecretHashProfile::Blake2b448Mixed => 28 * 384,
        SecretHashProfile::Sha3_512SplitControl => 0,
    }
}

pub const fn raw_blake_addition_linear_words(profile: SecretHashProfile) -> usize {
    match profile {
        SecretHashProfile::Blake2b448Mixed => 28 * 576,
        SecretHashProfile::Sha3_512SplitControl => 0,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStaticConstraintLedger {
    pub and_constraints: usize,
    pub linear_constraints: usize,
    pub bmul_constraints: usize,
    pub includes_hash_mux_and_metadata: bool,
    pub includes_non_hash_relation: bool,
    pub post_compiler_dce: bool,
}

/// Source-static hash-program ledger from the pinned opcode schedule, including
/// authorization mux/counter/final metadata but excluding non-hash transaction
/// semantics. These are not compiler/DCE counts and cannot select a winner or
/// predict proof bytes; `compiled_geometry()` remains the measurement authority.
pub const fn source_static_constraint_ledger(
    profile: SecretHashProfile,
) -> SourceStaticConstraintLedger {
    match profile {
        SecretHashProfile::Blake2b448Mixed => SourceStaticConstraintLedger {
            and_constraints: 79_128,
            linear_constraints: 265_963,
            bmul_constraints: 452,
            includes_hash_mux_and_metadata: true,
            includes_non_hash_relation: false,
            post_compiler_dce: false,
        },
        SecretHashProfile::Sha3_512SplitControl => SourceStaticConstraintLedger {
            and_constraints: 90_600,
            linear_constraints: 327_437,
            bmul_constraints: 444,
            includes_hash_mux_and_metadata: true,
            includes_non_hash_relation: false,
            post_compiler_dce: false,
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledGeometry {
    pub profile: SecretHashProfile,
    pub program_digest_sha512: [u8; 64],
    pub source_digest_sha512: [u8; 64],
    pub constants: usize,
    pub public_words: usize,
    pub private_words: usize,
    pub zero_constraints: usize,
    pub and_constraints: usize,
    pub imul_constraints: usize,
    pub bmul_constraints: usize,
    pub chip_count: usize,
    pub raw_hash_and_projection: usize,
    pub raw_blake_addition_linear_projection: usize,
    pub raw_blake_rotation_linear_projection: usize,
    pub includes_authorization_mux_and_metadata: bool,
}

struct CandidateWires {
    base: FullM4Wires,
    statement_words: [Wire; CANDIDATE_STATEMENT_WORDS],
    consensus_state: CandidateConsensusStateWires,
    ciphertext_sizes: [Wire; 2],
    ciphertexts: [[Wire; CIPHERTEXT_WORDS]; 2],
    all_private: [Wire; CANDIDATE_PRIVATE_WORDS],
}

#[derive(Clone)]
struct CandidateConsensusStateWires {
    all_words: [Wire; CANDIDATE_CONSENSUS_STATE_WORDS],
    seam_version: Wire,
    expected_current_height: Wire,
    provided_current_height: Wire,
    entry_index: Wire,
    entry_present: Wire,
    asset_id: Wire,
    oracle_feed: Wire,
    attestation_id: Wire,
    min_collateral_ratio_ppm: [Wire; 2],
    max_mint_per_epoch: [Wire; 2],
    oracle_max_age: Wire,
    oracle_submitted_at: Wire,
    enabled_at: Wire,
    retired_present: Wire,
    retired_at: Wire,
    policy_version: Wire,
    active: Wire,
    policy_hash: [Wire; LIVE_STABLECOIN_BINDING_WORDS],
    oracle_commitment: [Wire; LIVE_STABLECOIN_BINDING_WORDS],
    attestation_commitment: [Wire; LIVE_STABLECOIN_BINDING_WORDS],
    attestation_disputed: Wire,
    expected_manifest_state_commitment_v1: [Wire; MANIFEST_STATE_COMMITMENT_V1_WORDS],
    provided_manifest_state_commitment_v1: [Wire; MANIFEST_STATE_COMMITMENT_V1_WORDS],
}

pub struct CandidateCircuit {
    profile: SecretHashProfile,
    activation: DiagnosticActivationBinding,
    hash_lowering_coverage: HashLoweringCoverage,
    circuit: CircuitM4,
    wires: CandidateWires,
}

#[derive(Debug)]
pub enum CandidateWitnessError {
    StatementCodec,
    ActivityFlagsMismatch,
    ConsensusStateRequired,
    Population(PopulateM4Error),
}

impl From<PopulateM4Error> for CandidateWitnessError {
    fn from(error: PopulateM4Error) -> Self {
        Self::Population(error)
    }
}

impl CandidateCircuit {
    pub fn hash_lowering_coverage(&self) -> &HashLoweringCoverage {
        &self.hash_lowering_coverage
    }

    /// Return exact post-compiler/DCE counts.  Constructing this object is a
    /// circuit compile, not a proof run; it still remains disk-gated in this
    /// campaign because the checkout has less than 28 GiB free.
    pub fn compiled_geometry(&self) -> CompiledGeometry {
        let composite = self.circuit.to_constraint_system();
        let main = &composite.main.cs;
        CompiledGeometry {
            profile: self.profile,
            program_digest_sha512: program_digest(self.profile, self.activation),
            source_digest_sha512: source_digest(),
            constants: main.constants.len(),
            public_words: main.n_inout,
            private_words: main.n_private,
            zero_constraints: main.zero_constraints.len(),
            and_constraints: main.and_constraints.len(),
            imul_constraints: main.imul_constraints.len(),
            bmul_constraints: main.bmul_constraints.len(),
            chip_count: composite.chips.len(),
            raw_hash_and_projection: raw_hash_and_words(self.profile),
            raw_blake_addition_linear_projection: raw_blake_addition_linear_words(self.profile),
            raw_blake_rotation_linear_projection: raw_hash_rotation_linear_words(self.profile),
            includes_authorization_mux_and_metadata: true,
        }
    }

    pub fn generate_witness(
        &self,
        statement: &[u8; CANDIDATE_STATEMENT_BYTES],
        witness: &FullShake448Witness,
    ) -> Result<WitnessM4, CandidateWitnessError> {
        let decoded =
            scalar_candidate::decode_candidate_statement_bytes(statement, self.activation)
                .map_err(|_| CandidateWitnessError::StatementCodec)?;
        if decoded.stablecoin.enabled {
            return Err(CandidateWitnessError::ConsensusStateRequired);
        }
        self.generate_witness_with_consensus_state(
            statement,
            witness,
            &StablecoinConsensusStateSeam::disabled(),
        )
    }

    pub fn generate_witness_with_consensus_state(
        &self,
        statement: &[u8; CANDIDATE_STATEMENT_BYTES],
        witness: &FullShake448Witness,
        consensus_state: &StablecoinConsensusStateSeam,
    ) -> Result<WitnessM4, CandidateWitnessError> {
        let decoded =
            scalar_candidate::decode_candidate_statement_bytes(statement, self.activation)
                .map_err(|_| CandidateWitnessError::StatementCodec)?;
        if witness.inputs.each_ref().map(|input| input.active) != decoded.input_flags
            || witness.outputs.each_ref().map(|output| output.active) != decoded.output_flags
        {
            return Err(CandidateWitnessError::ActivityFlagsMismatch);
        }
        let statement_public = pack_statement_words(statement);
        let consensus_public = pack_consensus_state_words(consensus_state);
        let private = pack_candidate_private_words(witness);
        self.circuit
            .generate_witness(|filler| {
                for (&wire, value) in self.wires.all_private.iter().zip(private) {
                    filler[wire] = Word(value);
                }
                for (&wire, value) in self.wires.statement_words.iter().zip(statement_public) {
                    filler[wire] = Word(value);
                }
                for (&wire, value) in self
                    .wires
                    .consensus_state
                    .all_words
                    .iter()
                    .zip(consensus_public)
                {
                    filler[wire] = Word(value);
                }
            })
            .map_err(Into::into)
    }

    pub fn constraint_system(&self) -> binius_core::constraint_system::m4::ConstraintSystemM4 {
        self.circuit.to_constraint_system()
    }
}

fn map_candidate_consensus_state(
    words: &[Wire; CANDIDATE_CONSENSUS_STATE_WORDS],
) -> CandidateConsensusStateWires {
    CandidateConsensusStateWires {
        all_words: *words,
        seam_version: words[STATE_SEAM_VERSION_WORD],
        expected_current_height: words[STATE_EXPECTED_HEIGHT_WORD],
        provided_current_height: words[STATE_PROVIDED_HEIGHT_WORD],
        entry_index: words[STATE_ENTRY_INDEX_WORD],
        entry_present: words[STATE_ENTRY_PRESENT_WORD],
        asset_id: words[STATE_ASSET_ID_WORD],
        oracle_feed: words[STATE_ORACLE_FEED_WORD],
        attestation_id: words[STATE_ATTESTATION_ID_WORD],
        min_collateral_ratio_ppm: words[STATE_MIN_COLLATERAL_WORDS]
            .try_into()
            .expect("two-word u128"),
        max_mint_per_epoch: words[STATE_MAX_MINT_WORDS]
            .try_into()
            .expect("two-word u128"),
        oracle_max_age: words[STATE_ORACLE_MAX_AGE_WORD],
        oracle_submitted_at: words[STATE_ORACLE_SUBMITTED_AT_WORD],
        enabled_at: words[STATE_ENABLED_AT_WORD],
        retired_present: words[STATE_RETIRED_PRESENT_WORD],
        retired_at: words[STATE_RETIRED_AT_WORD],
        policy_version: words[STATE_POLICY_VERSION_WORD],
        active: words[STATE_ACTIVE_WORD],
        policy_hash: words[STATE_POLICY_HASH_WORDS]
            .try_into()
            .expect("six-word policy hash"),
        oracle_commitment: words[STATE_ORACLE_COMMITMENT_WORDS]
            .try_into()
            .expect("six-word oracle commitment"),
        attestation_commitment: words[STATE_ATTESTATION_COMMITMENT_WORDS]
            .try_into()
            .expect("six-word attestation commitment"),
        attestation_disputed: words[STATE_ATTESTATION_DISPUTED_WORD],
        expected_manifest_state_commitment_v1: words[STATE_EXPECTED_MANIFEST_COMMITMENT_WORDS]
            .try_into()
            .expect("six-word expected manifest-state commitment"),
        provided_manifest_state_commitment_v1: words[STATE_PROVIDED_MANIFEST_COMMITMENT_WORDS]
            .try_into()
            .expect("six-word provided manifest-state commitment"),
    }
}

pub fn build_candidate_m4(
    profile: SecretHashProfile,
    expected_activation: DiagnosticActivationBinding,
) -> CandidateCircuit {
    assert_diagnostic_activation(expected_activation);
    assert!(
        hash_invocation_registry_is_exact(profile),
        "all 83 typed call specifications must match the exact candidate schedule"
    );
    let builder = CircuitBuilder::new();
    let all_private = array::from_fn(|_| builder.add_witness());
    let statement_words = array::from_fn(|_| builder.add_inout());
    let consensus_state_words = array::from_fn(|_| builder.add_inout());
    let consensus_state = map_candidate_consensus_state(&consensus_state_words);
    let base_private: [Wire; super::PRIVATE_WORDS] = all_private[..super::PRIVATE_WORDS]
        .try_into()
        .expect("candidate base witness prefix");
    let zero = builder.add_constant_64(0);
    let base_public: [Wire; super::PUBLIC_WORDS] =
        array::from_fn(|index| statement_words.get(index).copied().unwrap_or(zero));
    let statement = decode_candidate_public(&builder, &statement_words);
    let derived_intent = [zero; super::DERIVED_INTENT_WORDS];
    let (inputs, outputs, auth) = map_private(&base_private);
    let base = FullM4Wires {
        private: base_private,
        public: base_public,
        derived_intent,
        statement,
        inputs,
        outputs,
        auth,
    };
    let ciphertexts = array::from_fn(|slot| {
        let start = CANDIDATE_BASE_PRIVATE_WORDS + slot * CIPHERTEXT_WORDS;
        all_private[start..start + CIPHERTEXT_WORDS]
            .try_into()
            .expect("fixed ciphertext word lane")
    });
    let ciphertext_sizes = array::from_fn(|slot| {
        candidate_public_be_u32(
            &builder,
            &statement_words,
            OFFSET_CIPHERTEXT_SIZES + slot * 4,
        )
    });
    let wires = CandidateWires {
        base,
        statement_words,
        consensus_state,
        ciphertext_sizes,
        ciphertexts,
        all_private,
    };
    constrain_candidate_transport(&builder, &wires, expected_activation);
    let (modes, policy) = constrain_candidate_non_hash(&builder, &wires);
    let hash_lowering_coverage =
        constrain_candidate_hashes(&builder, &wires, &modes, &policy, profile);
    let circuit = builder.build_m4();
    assert!(
        circuit.chips.is_empty(),
        "the candidate must remain one chip-free M4 main"
    );
    circuit
        .validate()
        .expect("the candidate circuit must pass structural validation");
    CandidateCircuit {
        profile,
        activation: expected_activation,
        hash_lowering_coverage,
        circuit,
        wires,
    }
}

fn decode_candidate_public(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
) -> DecodedPublic {
    let input_flags = [
        candidate_public_byte(builder, public, OFFSET_FLAGS),
        candidate_public_byte(builder, public, OFFSET_FLAGS + 1),
    ];
    let output_flags = [
        candidate_public_byte(builder, public, OFFSET_FLAGS + 2),
        candidate_public_byte(builder, public, OFFSET_FLAGS + 3),
    ];
    DecodedPublic {
        input_flags,
        output_flags,
        anchor: candidate_public_words_at(builder, public, OFFSET_ANCHOR),
        nullifiers: array::from_fn(|index| {
            candidate_public_words_at(builder, public, OFFSET_NULLIFIERS + index * DIGEST_BYTES)
        }),
        commitments: array::from_fn(|index| {
            candidate_public_words_at(builder, public, OFFSET_COMMITMENTS + index * DIGEST_BYTES)
        }),
        ciphertext_hashes: array::from_fn(|index| {
            candidate_public_words_at(
                builder,
                public,
                OFFSET_CIPHERTEXT_HASHES + index * DIGEST_BYTES,
            )
        }),
        assets: array::from_fn(|index| {
            candidate_public_be_u64(builder, public, OFFSET_ASSETS + index * 8)
        }),
        fee: candidate_public_be_u64(builder, public, OFFSET_FEE),
        value_balance_sign: candidate_public_byte(builder, public, OFFSET_VALUE_BALANCE_SIGN),
        value_balance_magnitude: candidate_public_be_u64(
            builder,
            public,
            OFFSET_VALUE_BALANCE_MAGNITUDE,
        ),
        stable_enabled: candidate_public_byte(builder, public, OFFSET_STABLE_ENABLED),
        stable_asset: candidate_public_be_u64(builder, public, OFFSET_STABLE_ASSET),
        stable_version: candidate_public_be_u32(builder, public, OFFSET_STABLE_VERSION),
        stable_issuance_sign: candidate_public_byte(builder, public, OFFSET_STABLE_ISSUANCE_SIGN),
        stable_issuance_magnitude: candidate_public_be_u64(
            builder,
            public,
            OFFSET_STABLE_ISSUANCE_MAGNITUDE,
        ),
        stable_policy: candidate_public_words_at::<LIVE_STABLECOIN_BINDING_WORDS>(
            builder,
            public,
            OFFSET_STABLE_POLICY,
        )
        .to_vec(),
        stable_oracle: candidate_public_words_at::<LIVE_STABLECOIN_BINDING_WORDS>(
            builder,
            public,
            OFFSET_STABLE_ORACLE,
        )
        .to_vec(),
        stable_attestation: candidate_public_words_at::<LIVE_STABLECOIN_BINDING_WORDS>(
            builder,
            public,
            OFFSET_STABLE_ATTESTATION,
        )
        .to_vec(),
        balance_tag: candidate_public_words_at(builder, public, OFFSET_BALANCE_TAG),
    }
}

fn constrain_candidate_transport(
    builder: &CircuitBuilder,
    wires: &CandidateWires,
    activation: DiagnosticActivationBinding,
) {
    builder.assert_zero(
        "statement.trailing_word_padding",
        builder.band(
            wires.statement_words[CANDIDATE_STATEMENT_WORDS - 1],
            builder.add_constant_64(0xffff_ff00_0000_0000),
        ),
    );
    assert_candidate_public_bytes_const(
        builder,
        "statement.magic",
        &wires.statement_words,
        0,
        &DIAGNOSTIC_STATEMENT_MAGIC,
    );
    assert_candidate_public_bytes_const(
        builder,
        "statement.grammar_version",
        &wires.statement_words,
        8,
        &DIAGNOSTIC_STATEMENT_GRAMMAR.to_be_bytes(),
    );
    assert_candidate_public_bytes_const(
        builder,
        "statement.activation",
        &wires.statement_words,
        OFFSET_ACTIVATION,
        &activation_bytes(activation),
    );
    for (name, flag) in [
        ("input_flags[0]", wires.base.statement.input_flags[0]),
        ("input_flags[1]", wires.base.statement.input_flags[1]),
        ("output_flags[0]", wires.base.statement.output_flags[0]),
        ("output_flags[1]", wires.base.statement.output_flags[1]),
        (
            "value_balance.sign",
            wires.base.statement.value_balance_sign,
        ),
        ("stable.enabled", wires.base.statement.stable_enabled),
        (
            "stable.issuance_sign",
            wires.base.statement.stable_issuance_sign,
        ),
    ] {
        assert_low_bool(builder, name, flag);
    }
    for (name, digest) in [
        ("activation.chain_id", &activation.chain_id),
        ("activation.genesis_id", &activation.genesis_id),
        ("activation.rules_hash", &activation.rules_hash),
    ] {
        assert!(
            digest.iter().any(|byte| *byte != 0),
            "{name} must be nonzero"
        );
    }
}

fn constrain_candidate_non_hash(
    builder: &CircuitBuilder,
    wires: &CandidateWires,
) -> (ModeSelectors, PolicySelectors) {
    let zero = builder.add_constant_64(0);
    let one = builder.add_constant_64(1);
    let statement = &wires.base.statement;
    let input_nonempty = builder.bor(statement.input_flags[0], statement.input_flags[1]);
    let output_nonempty = builder.bor(statement.output_flags[0], statement.output_flags[1]);
    builder.assert_non_zero(
        "shape.action_nonempty",
        builder.bor(input_nonempty, output_nonempty),
    );
    assert_61_bit(
        builder,
        "value_balance.magnitude",
        statement.value_balance_magnitude,
    );
    let value_balance_zero = builder.icmp_eq(statement.value_balance_magnitude, zero);
    builder.assert_eq_cond(
        "value_balance.no_negative_zero",
        statement.value_balance_sign,
        zero,
        value_balance_zero,
    );
    assert_61_bit(builder, "fee", statement.fee);
    assert_61_bit(
        builder,
        "stable.issuance_magnitude",
        statement.stable_issuance_magnitude,
    );
    let issuance_zero = builder.icmp_eq(statement.stable_issuance_magnitude, zero);
    builder.assert_eq_cond(
        "stable.issuance.no_negative_zero",
        statement.stable_issuance_sign,
        zero,
        issuance_zero,
    );
    constrain_slots(builder, statement);
    constrain_candidate_stablecoin(builder, wires);

    let balance_inputs: [BalanceNote; super::MAX_INPUTS] = array::from_fn(|index| {
        let inactive = builder.bnot(low_bool_msb(builder, statement.input_flags[index]));
        assert_words_zero_cond(
            builder,
            &format!("input[{index}].inactive"),
            &wires.base.private[index * super::INPUT_WORDS..(index + 1) * super::INPUT_WORDS],
            inactive,
        );
        let note = constrain_note_and_selectors(
            builder,
            &format!("input[{index}]"),
            &wires.base.inputs[index].note,
            &wires.base.inputs[index].selectors_be,
            statement.input_flags[index],
            &statement.assets,
        );
        let position =
            binius_circuits::bytes::swap_bytes(builder, wires.base.inputs[index].position_be);
        builder.assert_zero(
            format!("input[{index}].position.high32"),
            builder.shr(position, 32),
        );
        assert_digest_zero_cond(
            builder,
            &format!("nullifier[{index}].inactive"),
            &statement.nullifiers[index],
            inactive,
        );
        note
    });
    let balance_outputs: [BalanceNote; super::MAX_OUTPUTS] = array::from_fn(|index| {
        let inactive = builder.bnot(low_bool_msb(builder, statement.output_flags[index]));
        let start = 522 + index * super::OUTPUT_WORDS;
        assert_words_zero_cond(
            builder,
            &format!("output[{index}].inactive"),
            &wires.base.private[start..start + super::OUTPUT_WORDS],
            inactive,
        );
        assert_words_zero_cond(
            builder,
            &format!("output[{index}].inactive_ciphertext"),
            &wires.ciphertexts[index],
            inactive,
        );
        builder.assert_zero(
            format!("output[{index}].ciphertext.trailing_padding"),
            builder.band(
                wires.ciphertexts[index][CIPHERTEXT_WORDS - 1],
                builder.add_constant_64(0xffff_ffff_ff00_0000),
            ),
        );
        let active = low_bool_msb(builder, statement.output_flags[index]);
        builder.assert_eq_cond(
            format!("output[{index}].ciphertext_size.active"),
            wires.ciphertext_sizes[index],
            builder.add_constant_64(V6_CANONICAL_CIPHERTEXT_BYTES as u64),
            active,
        );
        builder.assert_eq_cond(
            format!("output[{index}].ciphertext_size.inactive"),
            wires.ciphertext_sizes[index],
            zero,
            inactive,
        );
        let note = constrain_note_and_selectors(
            builder,
            &format!("output[{index}]"),
            &wires.base.outputs[index].note,
            &wires.base.outputs[index].selectors_be,
            statement.output_flags[index],
            &statement.assets,
        );
        assert_digest_zero_cond(
            builder,
            &format!("commitment[{index}].inactive"),
            &statement.commitments[index],
            inactive,
        );
        assert_digest_zero_cond(
            builder,
            &format!("ciphertext[{index}].inactive"),
            &statement.ciphertext_hashes[index],
            inactive,
        );
        note
    });
    let both_inputs = and_msb(
        builder,
        low_bool_msb(builder, statement.input_flags[0]),
        low_bool_msb(builder, statement.input_flags[1]),
    );
    assert_digest_unequal_cond(
        builder,
        "nullifiers.distinct",
        &statement.nullifiers[0],
        &statement.nullifiers[1],
        both_inputs,
    );

    let mode = binius_circuits::bytes::swap_bytes(builder, wires.base.auth.mode_be);
    builder.assert_true(
        "auth.mode.range",
        builder.icmp_ule(mode, builder.add_constant_64(4)),
    );
    let modes = ModeSelectors {
        single: builder.icmp_eq(mode, zero),
        init: builder.icmp_eq(mode, one),
        approval: builder.icmp_eq(mode, builder.add_constant_64(2)),
        lock: builder.icmp_eq(mode, builder.add_constant_64(3)),
        final_spend: builder.icmp_eq(mode, builder.add_constant_64(4)),
    };
    assert_one_hot_modes(builder, &modes);
    let input_nonempty_msb = or_msb(
        builder,
        &statement
            .input_flags
            .map(|flag| low_bool_msb(builder, flag)),
    );
    let init_or_lock = or_msb(builder, &[modes.init, modes.lock]);
    assert_implies(
        builder,
        "auth.init_or_lock.input_nonempty",
        init_or_lock,
        input_nonempty_msb,
    );
    let policy_opening = select_accumulator(
        builder,
        modes.init,
        &wires.base.auth.next,
        &wires.base.auth.current,
    );
    let policy_threshold = binius_circuits::bytes::swap_bytes(builder, policy_opening.threshold_be);
    let policy_signer_count =
        binius_circuits::bytes::swap_bytes(builder, policy_opening.signer_count_be);
    let policy = PolicySelectors {
        opening: policy_opening,
        threshold: policy_threshold,
        signer_count: policy_signer_count,
        slot_active: array::from_fn(|slot| {
            builder.icmp_ult(builder.add_constant_64(slot as u64), policy_signer_count)
        }),
    };
    constrain_auth_non_hash(builder, &wires.base, &modes, &policy, false);
    constrain_candidate_balance(builder, wires, &balance_inputs, &balance_outputs);
    (modes, policy)
}

fn constrain_candidate_stablecoin(builder: &CircuitBuilder, wires: &CandidateWires) {
    let statement = &wires.base.statement;
    let zero = builder.add_constant_64(0);
    let enabled = low_bool_msb(builder, statement.stable_enabled);
    let disabled = builder.bnot(enabled);
    builder.assert_eq_cond(
        "stable.disabled.asset",
        statement.stable_asset,
        zero,
        disabled,
    );
    builder.assert_eq_cond(
        "stable.disabled.version",
        statement.stable_version,
        zero,
        disabled,
    );
    builder.assert_eq_cond(
        "stable.disabled.issuance_sign",
        statement.stable_issuance_sign,
        zero,
        disabled,
    );
    builder.assert_eq_cond(
        "stable.disabled.issuance_magnitude",
        statement.stable_issuance_magnitude,
        zero,
        disabled,
    );
    for (name, digest) in [
        ("policy", &statement.stable_policy),
        ("oracle", &statement.stable_oracle),
        ("attestation", &statement.stable_attestation),
    ] {
        assert_digest_zero_cond(
            builder,
            &format!("stable.disabled.{name}"),
            digest,
            disabled,
        );
    }
    assert_implies(
        builder,
        "stable.enabled.asset_nonzero",
        enabled,
        builder.icmp_ne(statement.stable_asset, zero),
    );
    assert_implies(
        builder,
        "stable.enabled.asset_range",
        enabled,
        builder.icmp_ult(
            statement.stable_asset,
            builder.add_constant_64(super::FIELD_MODULUS),
        ),
    );
    assert_implies(
        builder,
        "stable.enabled.asset_alias",
        enabled,
        builder.icmp_ne(
            statement.stable_asset,
            builder.add_constant_64(super::RESERVED_REDUCED_PADDING_ASSET_ID),
        ),
    );
    let matches_slot = or_msb(
        builder,
        &statement
            .assets
            .map(|asset| builder.icmp_eq(statement.stable_asset, asset)),
    );
    assert_implies(
        builder,
        "stable.enabled.slotted_asset",
        enabled,
        matches_slot,
    );
    constrain_candidate_stablecoin_consensus_state(builder, wires, enabled, disabled);
}

fn assert_state_words_equal_cond(
    builder: &CircuitBuilder,
    name: &str,
    left: &[Wire],
    right: &[Wire],
    condition: Wire,
) {
    assert_eq!(left.len(), right.len());
    for (word, (&left, &right)) in left.iter().zip(right).enumerate() {
        builder.assert_eq_cond(format!("{name}[{word}]"), left, right, condition);
    }
}

fn state_words_or(builder: &CircuitBuilder, words: &[Wire]) -> Wire {
    words
        .iter()
        .copied()
        .fold(builder.add_constant_64(0), |acc, word| {
            builder.bor(acc, word)
        })
}

fn constrain_candidate_stablecoin_consensus_state(
    builder: &CircuitBuilder,
    wires: &CandidateWires,
    enabled: Wire,
    disabled: Wire,
) {
    let zero = builder.add_constant_64(0);
    let one = builder.add_constant_64(1);
    let state = &wires.consensus_state;
    let statement = &wires.base.statement;

    // Disabled authority has exactly one representation across all additional
    // public lanes. Enabled authority must use the explicit inactive v1 seam.
    assert_words_zero_cond(builder, "stable.state.disabled", &state.all_words, disabled);
    for (name, value) in [
        ("seam_version", state.seam_version),
        ("entry_index", state.entry_index),
        ("asset_id", state.asset_id),
        ("oracle_feed", state.oracle_feed),
        ("policy_version", state.policy_version),
    ] {
        builder.assert_zero(
            format!("stable.state.{name}.high32"),
            builder.shr(value, 32),
        );
    }
    for (name, value) in [
        ("entry_present", state.entry_present),
        ("retired_present", state.retired_present),
        ("active", state.active),
        ("attestation_disputed", state.attestation_disputed),
    ] {
        assert_low_bool(builder, &format!("stable.state.{name}"), value);
    }
    builder.assert_eq_cond(
        "stable.state.version",
        state.seam_version,
        builder.add_constant_64(u64::from(
            scalar_candidate::STABLECOIN_CONSENSUS_STATE_SEAM_VERSION,
        )),
        enabled,
    );
    builder.assert_eq_cond(
        "stable.state.entry_present.enabled",
        state.entry_present,
        one,
        enabled,
    );
    builder.assert_eq_cond(
        "stable.state.height",
        state.provided_current_height,
        state.expected_current_height,
        enabled,
    );

    // This is the fail-closed equality seam to the verifier-selected state
    // commitment. Recomputing the flat commitment and proving selected-entry
    // membership remain explicitly absent aggregate hash work.
    assert_state_words_equal_cond(
        builder,
        "stable.state.manifest_commitment",
        &state.provided_manifest_state_commitment_v1,
        &state.expected_manifest_state_commitment_v1,
        enabled,
    );
    assert_implies(
        builder,
        "stable.state.expected_manifest_commitment_nonzero",
        enabled,
        builder.icmp_ne(
            state_words_or(builder, &state.expected_manifest_state_commitment_v1),
            zero,
        ),
    );
    assert_implies(
        builder,
        "stable.state.provided_manifest_commitment_nonzero",
        enabled,
        builder.icmp_ne(
            state_words_or(builder, &state.provided_manifest_state_commitment_v1),
            zero,
        ),
    );

    // Exact selected-entry equality to the C02 compatibility surface.
    builder.assert_eq_cond(
        "stable.state.asset",
        state.asset_id,
        statement.stable_asset,
        enabled,
    );
    builder.assert_eq_cond(
        "stable.state.policy_version",
        state.policy_version,
        statement.stable_version,
        enabled,
    );
    assert_state_words_equal_cond(
        builder,
        "stable.state.policy_hash",
        &state.policy_hash,
        &statement.stable_policy,
        enabled,
    );
    assert_state_words_equal_cond(
        builder,
        "stable.state.oracle_commitment",
        &state.oracle_commitment,
        &statement.stable_oracle,
        enabled,
    );
    assert_state_words_equal_cond(
        builder,
        "stable.state.attestation_commitment",
        &state.attestation_commitment,
        &statement.stable_attestation,
        enabled,
    );

    // Native lifecycle/order predicates over the verifier-visible selected
    // entry and exact consensus height.
    builder.assert_eq_cond("stable.state.active", state.active, one, enabled);
    builder.assert_eq_cond(
        "stable.state.attestation_not_disputed",
        state.attestation_disputed,
        zero,
        enabled,
    );
    builder.assert_eq_cond(
        "stable.state.retired_absent_zero",
        state.retired_at,
        zero,
        builder.bnot(low_bool_msb(builder, state.retired_present)),
    );
    assert_implies(
        builder,
        "stable.state.lifecycle_started",
        enabled,
        builder.icmp_uge(state.provided_current_height, state.enabled_at),
    );
    assert_implies(
        builder,
        "stable.state.lifecycle_not_retired",
        and_msb(
            builder,
            enabled,
            low_bool_msb(builder, state.retired_present),
        ),
        builder.icmp_ult(state.provided_current_height, state.retired_at),
    );
    assert_implies(
        builder,
        "stable.state.oracle_not_future",
        enabled,
        builder.icmp_ule(state.oracle_submitted_at, state.provided_current_height),
    );
    let (oracle_deadline, oracle_deadline_overflow) =
        builder.iadd(state.oracle_submitted_at, state.oracle_max_age);
    let oracle_before_deadline = builder.icmp_ule(state.provided_current_height, oracle_deadline);
    assert_implies(
        builder,
        "stable.state.oracle_fresh",
        enabled,
        builder.bor(oracle_deadline_overflow, oracle_before_deadline),
    );

    assert_implies(
        builder,
        "stable.state.issuance_nonzero",
        enabled,
        builder.icmp_ne(statement.stable_issuance_magnitude, zero),
    );
    let cap_high_nonzero = builder.icmp_ne(state.max_mint_per_epoch[1], zero);
    let within_low_cap = builder.icmp_ule(
        statement.stable_issuance_magnitude,
        state.max_mint_per_epoch[0],
    );
    assert_implies(
        builder,
        "stable.state.issuance_within_limit",
        enabled,
        builder.bor(cap_high_nonzero, within_low_cap),
    );
}

fn constrain_candidate_balance(
    builder: &CircuitBuilder,
    wires: &CandidateWires,
    balance_inputs: &[BalanceNote; super::MAX_INPUTS],
    balance_outputs: &[BalanceNote; super::MAX_OUTPUTS],
) {
    let statement = &wires.base.statement;
    let zero = builder.add_constant_64(0);
    let enabled = low_bool_msb(builder, statement.stable_enabled);
    let issuance_negative = low_bool_msb(builder, statement.stable_issuance_sign);
    let value_balance_negative = low_bool_msb(builder, statement.value_balance_sign);

    for slot in 0..super::BALANCE_SLOTS {
        let mut inputs = zero;
        let mut outputs = zero;
        for index in 0..super::MAX_INPUTS {
            let contribution = builder.select(
                low_bool_msb(builder, balance_inputs[index].selectors[slot]),
                balance_inputs[index].value,
                zero,
            );
            let (sum, carry) = builder.iadd(inputs, contribution);
            builder.assert_false(format!("balance[{slot}].input_overflow[{index}]"), carry);
            inputs = sum;
        }
        for index in 0..super::MAX_OUTPUTS {
            let contribution = builder.select(
                low_bool_msb(builder, balance_outputs[index].selectors[slot]),
                balance_outputs[index].value,
                zero,
            );
            let (sum, carry) = builder.iadd(outputs, contribution);
            builder.assert_false(format!("balance[{slot}].output_overflow[{index}]"), carry);
            outputs = sum;
        }

        if slot == 0 {
            let (outputs_and_fee, fee_carry) = builder.iadd(outputs, statement.fee);
            builder.assert_false("balance.native.fee_overflow", fee_carry);
            let (inputs_and_magnitude, positive_carry) =
                builder.iadd(inputs, statement.value_balance_magnitude);
            builder.assert_false("balance.native.positive_overflow", positive_carry);
            builder.assert_eq_cond(
                "balance.native.nonnegative_equation",
                inputs_and_magnitude,
                outputs_and_fee,
                builder.bnot(value_balance_negative),
            );
            let (outputs_fee_and_magnitude, negative_carry) =
                builder.iadd(outputs_and_fee, statement.value_balance_magnitude);
            builder.assert_false("balance.native.negative_overflow", negative_carry);
            builder.assert_eq_cond(
                "balance.native.negative_equation",
                inputs,
                outputs_fee_and_magnitude,
                value_balance_negative,
            );
            continue;
        }

        let asset = statement.assets[slot];
        let padding = builder.icmp_eq(asset, builder.add_constant_64(super::PADDING_ASSET_ID));
        builder.assert_eq_cond(
            format!("balance[{slot}].padding_inputs"),
            inputs,
            zero,
            padding,
        );
        builder.assert_eq_cond(
            format!("balance[{slot}].padding_outputs"),
            outputs,
            zero,
            padding,
        );
        let stable_slot = and_msb(
            builder,
            enabled,
            builder.icmp_eq(asset, statement.stable_asset),
        );
        let mint = and_msb(builder, stable_slot, issuance_negative);
        let burn = and_msb(builder, stable_slot, builder.bnot(issuance_negative));
        let (inputs_and_mint, mint_carry) =
            builder.iadd(inputs, statement.stable_issuance_magnitude);
        assert_implies(
            builder,
            &format!("balance[{slot}].mint_no_overflow"),
            mint,
            builder.bnot(mint_carry),
        );
        builder.assert_eq_cond(
            format!("balance[{slot}].mint"),
            outputs,
            inputs_and_mint,
            mint,
        );
        let (outputs_and_burn, burn_carry) =
            builder.iadd(outputs, statement.stable_issuance_magnitude);
        assert_implies(
            builder,
            &format!("balance[{slot}].burn_no_overflow"),
            burn,
            builder.bnot(burn_carry),
        );
        builder.assert_eq_cond(
            format!("balance[{slot}].burn"),
            inputs,
            outputs_and_burn,
            burn,
        );
        let ordinary = builder.bnot(stable_slot);
        builder.assert_eq_cond(
            format!("balance[{slot}].ordinary"),
            inputs,
            outputs,
            ordinary,
        );
    }
}

fn assert_one_hot_modes(builder: &CircuitBuilder, modes: &ModeSelectors) {
    let selectors = modes.all();
    builder.assert_non_zero("auth.mode.one_hot.some", or_msb(builder, &selectors));
    for left in 0..selectors.len() {
        for right in left + 1..selectors.len() {
            builder.assert_zero(
                format!("auth.mode.one_hot.disjoint[{left}][{right}]"),
                builder.band(selectors[left], selectors[right]),
            );
        }
    }
}

fn constrain_candidate_hashes(
    builder: &CircuitBuilder,
    wires: &CandidateWires,
    modes: &ModeSelectors,
    policy: &PolicySelectors,
    profile: SecretHashProfile,
) -> HashLoweringCoverage {
    let mut lowering = HashLoweringAudit::new(profile);
    let statement = &wires.base.statement;
    let in_active = statement
        .input_flags
        .map(|flag| low_bool_msb(builder, flag));
    let out_active = statement
        .output_flags
        .map(|flag| low_bool_msb(builder, flag));

    let spend_auth: [[Wire; DIGEST_WORDS]; super::MAX_INPUTS] = array::from_fn(|index| {
        let frame = spend_key_frame_lane(
            builder,
            &wires.base.inputs[index].spend_key,
            KEY_OUTPUT_LANE_A_TAG,
        );
        lowering.lower_ordinary(
            builder,
            scalar_candidate::SPEND_A_CALL_START + index,
            HashInvocationKind::Spend {
                input: index,
                lane: 0,
            },
            ROLE_SPEND_A,
            &frame,
            CandidateOutputBinding::Internal,
        )
    });
    let spend_nf: [[Wire; DIGEST_WORDS]; super::MAX_INPUTS] = array::from_fn(|index| {
        let frame = spend_key_frame_lane(
            builder,
            &wires.base.inputs[index].spend_key,
            KEY_OUTPUT_LANE_B_TAG,
        );
        lowering.lower_ordinary(
            builder,
            scalar_candidate::SPEND_B_CALL_START + index,
            HashInvocationKind::Spend {
                input: index,
                lane: 1,
            },
            ROLE_SPEND_B,
            &frame,
            CandidateOutputBinding::Internal,
        )
    });

    let policy_frame =
        candidate_policy_frame(builder, &policy.opening, &wires.base.auth.signer_tags);
    let policy_digest = lowering.lower_ordinary(
        builder,
        scalar_candidate::POLICY_CALL,
        HashInvocationKind::Policy,
        ROLE_POLICY,
        &policy_frame,
        CandidateOutputBinding::Internal,
    );
    assert_digest_eq_cond(
        builder,
        "auth.policy_root",
        &policy_digest,
        &policy.opening.policy_root,
        modes.non_single(builder),
    );

    let slot_a_auth = authorization_mux_hash(
        builder,
        profile,
        &mut lowering,
        modes,
        AuthorizationSlot::A,
        KEY_OUTPUT_LANE_A_TAG,
        &wires.base.auth,
    );
    let slot_a_nf = authorization_mux_hash(
        builder,
        profile,
        &mut lowering,
        modes,
        AuthorizationSlot::A,
        KEY_OUTPUT_LANE_B_TAG,
        &wires.base.auth,
    );
    let slot_b_auth = authorization_mux_hash(
        builder,
        profile,
        &mut lowering,
        modes,
        AuthorizationSlot::B,
        KEY_OUTPUT_LANE_A_TAG,
        &wires.base.auth,
    );
    let slot_b_nf = authorization_mux_hash(
        builder,
        profile,
        &mut lowering,
        modes,
        AuthorizationSlot::B,
        KEY_OUTPUT_LANE_B_TAG,
        &wires.base.auth,
    );

    let mut resolved_auth = spend_auth;
    let mut resolved_nf = spend_nf;
    resolved_auth[0] = select_digest(builder, modes.approval, &slot_a_auth, &resolved_auth[0]);
    resolved_nf[0] = select_digest(builder, modes.approval, &slot_a_nf, &resolved_nf[0]);
    resolved_auth[0] = select_digest(builder, modes.final_spend, &slot_b_auth, &resolved_auth[0]);
    resolved_nf[0] = select_digest(builder, modes.final_spend, &slot_b_nf, &resolved_nf[0]);
    resolved_auth[1] = select_digest(builder, modes.final_spend, &slot_a_auth, &resolved_auth[1]);
    resolved_nf[1] = select_digest(builder, modes.final_spend, &slot_a_nf, &resolved_nf[1]);

    let output0_init_or_lock = or_msb(builder, &[modes.init, modes.lock]);
    assert_digest_eq_cond(
        builder,
        "auth.output0.init_or_lock",
        &wires.base.outputs[0].note.auth,
        &slot_a_auth,
        output0_init_or_lock,
    );
    assert_digest_eq_cond(
        builder,
        "auth.output0.approval",
        &wires.base.outputs[0].note.auth,
        &slot_b_auth,
        modes.approval,
    );

    let note_commitments: [[Wire; DIGEST_WORDS]; super::MAX_INPUTS + super::MAX_OUTPUTS] =
        array::from_fn(|index| {
            let (note, kind, binding) = if index < super::MAX_INPUTS {
                (
                    &wires.base.inputs[index].note,
                    HashInvocationKind::NoteInput(index),
                    CandidateOutputBinding::Internal,
                )
            } else {
                let output = index - super::MAX_INPUTS;
                (
                    &wires.base.outputs[output].note,
                    HashInvocationKind::NoteOutput(output),
                    CandidateOutputBinding::PublicWhenOutputActive(output),
                )
            };
            let frame = candidate_note_frame(builder, note);
            lowering.lower_ordinary(
                builder,
                scalar_candidate::NOTE_CALL_START + index,
                kind,
                ROLE_NOTE,
                &frame,
                binding,
            )
        });
    for index in 0..super::MAX_INPUTS {
        assert_digest_eq_cond(
            builder,
            &format!("input[{index}].authorization"),
            &wires.base.inputs[index].note.auth,
            &resolved_auth[index],
            in_active[index],
        );
    }
    for index in 0..super::MAX_OUTPUTS {
        let commitment = &note_commitments[super::MAX_INPUTS + index];
        assert_digest_nonzero_cond(
            builder,
            &format!("output[{index}].commitment_nonzero"),
            commitment,
            out_active[index],
        );
        assert_digest_eq_cond(
            builder,
            &format!("output[{index}].commitment"),
            commitment,
            &statement.commitments[index],
            out_active[index],
        );
    }

    for index in 0..super::MAX_INPUTS {
        let frame = candidate_semantic_frame(
            builder,
            ROLE_NULLIFIER,
            &[
                (&resolved_nf[index], DIGEST_BYTES),
                (&[wires.base.inputs[index].position_be], 8),
                (&wires.base.inputs[index].note.rho, 48),
            ],
        );
        let nullifier = lowering.lower_ordinary(
            builder,
            scalar_candidate::NULLIFIER_CALL_START + index,
            HashInvocationKind::Nullifier(index),
            ROLE_NULLIFIER,
            &frame,
            CandidateOutputBinding::PublicWhenInputActive(index),
        );
        assert_digest_eq_cond(
            builder,
            &format!("input[{index}].nullifier"),
            &nullifier,
            &statement.nullifiers[index],
            in_active[index],
        );
        assert_digest_nonzero_cond(
            builder,
            &format!("input[{index}].nullifier_nonzero"),
            &nullifier,
            in_active[index],
        );
    }

    for index in 0..super::MAX_INPUTS {
        let position =
            binius_circuits::bytes::swap_bytes(builder, wires.base.inputs[index].position_be);
        let mut current = note_commitments[index];
        for (level, sibling) in wires.base.inputs[index].siblings.iter().enumerate() {
            let direction_msb = builder.shl(position, 63 - level as u32);
            let left: [Wire; DIGEST_WORDS] =
                array::from_fn(|word| builder.select(direction_msb, sibling[word], current[word]));
            let right: [Wire; DIGEST_WORDS] = array::from_fn(|word| {
                let pair_xor = builder.bxor(current[word], sibling[word]);
                builder.bxor(pair_xor, left[word])
            });
            let frame = candidate_semantic_frame(
                builder,
                ROLE_MERKLE,
                &[(&left, DIGEST_BYTES), (&right, DIGEST_BYTES)],
            );
            current = lowering.lower_ordinary(
                builder,
                scalar_candidate::MERKLE_CALL_START + index * super::MERKLE_DEPTH + level,
                HashInvocationKind::Merkle {
                    input: index,
                    level,
                },
                ROLE_MERKLE,
                &frame,
                CandidateOutputBinding::Internal,
            );
        }
        assert_digest_eq_cond(
            builder,
            &format!("input[{index}].anchor"),
            &current,
            &statement.anchor,
            in_active[index],
        );
    }

    let intent_frame = intent_frame(builder, &wires.statement_words);
    let intent = lowering.lower_ordinary(
        builder,
        scalar_candidate::INTENT_CALL,
        HashInvocationKind::Intent,
        ROLE_INTENT,
        &intent_frame,
        CandidateOutputBinding::Internal,
    );
    assert_digest_eq_cond(
        builder,
        "auth.final.intent",
        &wires.base.auth.current.intent,
        &intent,
        modes.final_spend,
    );
    let balance_frame = balance_tag_frame(builder, wires);
    let balance_tag = lowering.lower_ordinary(
        builder,
        scalar_candidate::BALANCE_CALL,
        HashInvocationKind::Balance,
        ROLE_BALANCE_TAG,
        &balance_frame,
        CandidateOutputBinding::PublicAlways,
    );
    assert_digest_eq_cond(
        builder,
        "balance_tag.public",
        &balance_tag,
        &statement.balance_tag,
        builder.add_constant_64(u64::MAX),
    );
    for index in 0..super::MAX_OUTPUTS {
        let frame = ciphertext_frame(builder, wires, index);
        let digest = lowering.lower_ordinary(
            builder,
            scalar_candidate::CIPHERTEXT_CALL_START + index,
            HashInvocationKind::Ciphertext(index),
            ROLE_CIPHERTEXT_HASH,
            &frame,
            CandidateOutputBinding::PublicWhenOutputActive(index),
        );
        assert_digest_eq_cond(
            builder,
            &format!("output[{index}].ciphertext_hash"),
            &digest,
            &statement.ciphertext_hashes[index],
            out_active[index],
        );
    }

    constrain_approval_membership(
        builder,
        &wires.base,
        modes.approval,
        &spend_auth[1],
        &policy.slot_active,
    );
    lowering.finish()
}

fn candidate_note_frame(builder: &CircuitBuilder, note: &super::NoteWords) -> PackedFrame {
    let kind = binius_circuits::bytes::swap_bytes(builder, note.kind_be);
    let frame = candidate_semantic_frame(
        builder,
        ROLE_NOTE,
        &[
            (&[kind], 1),
            (&[note.value_be], 8),
            (&[note.asset_be], 8),
            (&note.recipient, 32),
            (&note.rho, 48),
            (&note.randomness, 48),
            (&note.auth, DIGEST_BYTES),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 232);
    frame
}

fn spend_key_frame_lane(
    builder: &CircuitBuilder,
    spend_key: &[Wire; 6],
    lane_tag: [u8; 8],
) -> PackedFrame {
    let role = if lane_tag == KEY_OUTPUT_LANE_A_TAG {
        ROLE_SPEND_A
    } else {
        assert_eq!(lane_tag, KEY_OUTPUT_LANE_B_TAG);
        ROLE_SPEND_B
    };
    let lane = constant_words(builder, &lane_tag);
    let frame = candidate_semantic_frame(builder, role, &[(&lane, 8), (spend_key, 48)]);
    debug_assert_eq!(frame.len_bytes, 77);
    frame
}

fn candidate_policy_frame(
    builder: &CircuitBuilder,
    opening: &AccumulatorWords,
    tags: &[[Wire; DIGEST_WORDS]; super::MAX_SIGNERS],
) -> PackedFrame {
    let threshold = [opening.threshold_be];
    let signer_count = [opening.signer_count_be];
    let mut fields: Vec<(&[Wire], usize)> = vec![(&threshold, 8), (&signer_count, 8)];
    fields.extend(tags.iter().map(|tag| (&tag[..], DIGEST_BYTES)));
    let frame = candidate_semantic_frame(builder, ROLE_POLICY, &fields);
    debug_assert_eq!(frame.len_bytes, 385);
    frame
}

fn accumulator_frame_lane(
    builder: &CircuitBuilder,
    role: [u8; 8],
    opening: &AccumulatorWords,
    lane_tag: [u8; 8],
) -> PackedFrame {
    let approved_numeric = opening
        .approved_be
        .map(|wire| binius_circuits::bytes::swap_bytes(builder, wire));
    let approved = pack_bytes(builder, &approved_numeric);
    let lane = constant_words(builder, &lane_tag);
    let frame = candidate_semantic_frame(
        builder,
        role,
        &[
            (&lane, 8),
            (&opening.policy_root, DIGEST_BYTES),
            (&opening.intent, DIGEST_BYTES),
            (&[opening.threshold_be], 8),
            (&[opening.signer_count_be], 8),
            (&[opening.approval_count_be], 8),
            (&approved, super::MAX_SIGNERS),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 181);
    frame
}

fn value_lock_frame_lane(
    builder: &CircuitBuilder,
    role: [u8; 8],
    policy_root: &[Wire; DIGEST_WORDS],
    intent: &[Wire; DIGEST_WORDS],
    lane_tag: [u8; 8],
) -> PackedFrame {
    let lane = constant_words(builder, &lane_tag);
    let frame = candidate_semantic_frame(
        builder,
        role,
        &[
            (&lane, 8),
            (policy_root, DIGEST_BYTES),
            (intent, DIGEST_BYTES),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 143);
    frame
}

fn intent_frame(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
) -> PackedFrame {
    let mut bytes = Vec::with_capacity(701);
    for offset in 0..14 {
        bytes.push(candidate_public_byte(builder, public, offset));
    }
    for offset in 182..CANDIDATE_STATEMENT_BYTES {
        bytes.push(candidate_public_byte(builder, public, offset));
    }
    assert_eq!(bytes.len(), 701);
    let words = pack_bytes(builder, &bytes);
    let frame = candidate_semantic_frame(builder, ROLE_INTENT, &[(&words, bytes.len())]);
    debug_assert_eq!(frame.len_bytes, 720);
    frame
}

fn balance_tag_frame(builder: &CircuitBuilder, wires: &CandidateWires) -> PackedFrame {
    let fee = candidate_public_field_words(builder, &wires.statement_words, OFFSET_FEE, 8);
    let sign = candidate_public_field_words(
        builder,
        &wires.statement_words,
        OFFSET_VALUE_BALANCE_SIGN,
        1,
    );
    let magnitude = candidate_public_field_words(
        builder,
        &wires.statement_words,
        OFFSET_VALUE_BALANCE_MAGNITUDE,
        8,
    );
    let assets = candidate_public_field_words(builder, &wires.statement_words, OFFSET_ASSETS, 32);
    let stable_enabled =
        candidate_public_field_words(builder, &wires.statement_words, OFFSET_STABLE_ENABLED, 1);
    let stable_asset =
        candidate_public_field_words(builder, &wires.statement_words, OFFSET_STABLE_ASSET, 8);
    let issuance_sign = candidate_public_field_words(
        builder,
        &wires.statement_words,
        OFFSET_STABLE_ISSUANCE_SIGN,
        1,
    );
    let issuance_magnitude = candidate_public_field_words(
        builder,
        &wires.statement_words,
        OFFSET_STABLE_ISSUANCE_MAGNITUDE,
        8,
    );
    let frame = candidate_semantic_frame(
        builder,
        ROLE_BALANCE_TAG,
        &[
            (&fee, 8),
            (&sign, 1),
            (&magnitude, 8),
            (&assets, 32),
            (&stable_enabled, 1),
            (&stable_asset, 8),
            (&issuance_sign, 1),
            (&issuance_magnitude, 8),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 100);
    frame
}

fn ciphertext_frame(builder: &CircuitBuilder, wires: &CandidateWires, slot: usize) -> PackedFrame {
    let profile = candidate_public_field_words(builder, &wires.statement_words, OFFSET_PROFILE, 1);
    let domain =
        candidate_public_field_words(builder, &wires.statement_words, OFFSET_DOMAIN_SET, 2);
    let slot_words = constant_words(builder, &[slot as u8]);
    let length_words = constant_words(
        builder,
        &(V6_CANONICAL_CIPHERTEXT_BYTES as u32).to_be_bytes(),
    );
    let frame = candidate_semantic_frame(
        builder,
        ROLE_CIPHERTEXT_HASH,
        &[
            (&profile, 1),
            (&domain, 2),
            (&slot_words, 1),
            (&length_words, 4),
            (&wires.ciphertexts[slot], V6_CANONICAL_CIPHERTEXT_BYTES),
        ],
    );
    debug_assert_eq!(frame.len_bytes, 2_182);
    frame
}

fn candidate_semantic_frame(
    builder: &CircuitBuilder,
    role: [u8; 8],
    fields: &[(&[Wire], usize)],
) -> PackedFrame {
    let mut frame = FrameBuilder::new(builder);
    frame.push_const(&CANDIDATE_FRAME_TAG);
    frame.push_const(&role);
    frame.push_const(&[fields.len() as u8]);
    for &(words, len_bytes) in fields {
        frame.push_const(&(len_bytes as u16).to_be_bytes());
        frame.push_words(words, len_bytes);
    }
    frame.finish()
}

fn candidate_dummy_frame(
    builder: &CircuitBuilder,
    role: [u8; 8],
    slot: usize,
    lane: usize,
) -> PackedFrame {
    let mut payload = [0u8; 117];
    payload[0] = slot as u8;
    payload[1] = lane as u8;
    let payload = constant_words(builder, &payload);
    let frame = candidate_semantic_frame(builder, role, &[(&payload, 117)]);
    debug_assert_eq!(frame.len_bytes, 136);
    frame
}

#[derive(Clone, Copy)]
enum AuthorizationSlot {
    A,
    B,
}

fn authorization_mux_hash(
    builder: &CircuitBuilder,
    profile: SecretHashProfile,
    lowering: &mut HashLoweringAudit,
    modes: &ModeSelectors,
    slot: AuthorizationSlot,
    lane_tag: [u8; 8],
    auth: &AuthWords,
) -> [Wire; DIGEST_WORDS] {
    let lane = if lane_tag == KEY_OUTPUT_LANE_A_TAG {
        0
    } else {
        assert_eq!(lane_tag, KEY_OUTPUT_LANE_B_TAG);
        1
    };
    let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
    let slot_index = match slot {
        AuthorizationSlot::A => 0,
        AuthorizationSlot::B => 1,
    };
    let dummy = candidate_dummy_frame(builder, role, slot_index, lane);
    let current_accumulator = accumulator_frame_lane(builder, role, &auth.current, lane_tag);
    let next_accumulator = accumulator_frame_lane(builder, role, &auth.next, lane_tag);
    let value_lock = value_lock_frame_lane(
        builder,
        role,
        &auth.current.policy_root,
        &auth.current.intent,
        lane_tag,
    );
    let arms = match slot {
        AuthorizationSlot::A => [
            dummy.clone(),
            next_accumulator.clone(),
            current_accumulator.clone(),
            value_lock.clone(),
            current_accumulator,
        ],
        AuthorizationSlot::B => [
            dummy.clone(),
            dummy.clone(),
            next_accumulator,
            dummy,
            value_lock,
        ],
    };
    let selectors = modes.all();
    assert_eq!(profile, lowering.profile);
    let index = if lane == 0 {
        scalar_candidate::AUTH_A_CALL_START + slot_index
    } else {
        scalar_candidate::AUTH_B_CALL_START + slot_index
    };
    lowering.lower_authorization_mux(
        builder,
        index,
        HashInvocationKind::Authorization {
            slot: slot_index,
            lane,
        },
        role,
        &selectors,
        &arms,
    )
}

fn secret_hash56(
    builder: &CircuitBuilder,
    profile: SecretHashProfile,
    frame: &PackedFrame,
) -> [Wire; DIGEST_WORDS] {
    match profile {
        SecretHashProfile::Blake2b448Mixed => blake2b448_words(builder, frame),
        SecretHashProfile::Sha3_512SplitControl => sha3_512_truncated448_words(builder, frame),
    }
}

fn shake256_448_words(builder: &CircuitBuilder, frame: &PackedFrame) -> [Wire; DIGEST_WORDS] {
    assert_eq!(frame.words.len(), frame.len_bytes.div_ceil(8));
    let zero = builder.add_constant_64(0);
    let mut state = [zero; 25];
    let full_blocks = frame.len_bytes / SHAKE256_RATE_BYTES;
    for block in 0..full_blocks {
        for word in 0..SHAKE256_RATE_WORDS {
            state[word] =
                builder.bxor(state[word], frame.words[block * SHAKE256_RATE_WORDS + word]);
        }
        keccak_f1600(builder, &mut state);
    }
    let remainder = frame.len_bytes % SHAKE256_RATE_BYTES;
    let base = full_blocks * SHAKE256_RATE_WORDS;
    for word in 0..remainder.div_ceil(8) {
        state[word] = builder.bxor(state[word], frame.words[base + word]);
    }
    let suffix_word = remainder / 8;
    let suffix_shift = (remainder % 8) * 8;
    state[suffix_word] = builder.bxor(
        state[suffix_word],
        builder.add_constant_64(SHAKE_DOMAIN_SUFFIX << suffix_shift),
    );
    state[SHAKE256_RATE_WORDS - 1] = builder.bxor(
        state[SHAKE256_RATE_WORDS - 1],
        builder.add_constant_64(0x80u64 << 56),
    );
    keccak_f1600(builder, &mut state);
    state[..DIGEST_WORDS].try_into().unwrap()
}

fn sha3_512_truncated448_words(
    builder: &CircuitBuilder,
    frame: &PackedFrame,
) -> [Wire; DIGEST_WORDS] {
    let blocks = padded_sha3_blocks(builder, frame, None);
    let zero = builder.add_constant_64(0);
    let mut state = [zero; 25];
    for block in blocks.chunks_exact(SHA3_512_RATE_WORDS) {
        for word in 0..SHA3_512_RATE_WORDS {
            state[word] = builder.bxor(state[word], block[word]);
        }
        keccak_f1600(builder, &mut state);
    }
    state[..DIGEST_WORDS].try_into().unwrap()
}

fn mux_one_hot_sha3_512_truncated448(
    builder: &CircuitBuilder,
    selectors: &[Wire; AUTHORIZATION_MODE_COUNT],
    arms: &[PackedFrame; AUTHORIZATION_MODE_COUNT],
) -> [Wire; DIGEST_WORDS] {
    let padded: [Vec<Wire>; AUTHORIZATION_MODE_COUNT] =
        array::from_fn(|index| padded_sha3_blocks(builder, &arms[index], Some(3)));
    let uses_third: [Wire; AUTHORIZATION_MODE_COUNT] = array::from_fn(|index| {
        builder.add_constant_64(if arms[index].len_bytes / SHA3_512_RATE_BYTES + 1 == 3 {
            u64::MAX
        } else {
            0
        })
    });
    let zero = builder.add_constant_64(0);
    let mut state = [zero; 25];
    let mut state_after_two = [zero; 25];
    for block in 0..3 {
        for word in 0..SHA3_512_RATE_WORDS {
            let selected = select_one_hot_wire(
                builder,
                selectors,
                &array::from_fn(|arm| padded[arm][block * SHA3_512_RATE_WORDS + word]),
            );
            state[word] = builder.bxor(state[word], selected);
        }
        keccak_f1600(builder, &mut state);
        if block == 1 {
            state_after_two = state;
        }
    }
    let select_third = select_one_hot_wire(builder, selectors, &uses_third);
    array::from_fn(|word| builder.select(select_third, state[word], state_after_two[word]))
}

fn padded_sha3_blocks(
    builder: &CircuitBuilder,
    frame: &PackedFrame,
    fixed_blocks: Option<usize>,
) -> Vec<Wire> {
    let actual_blocks = frame.len_bytes / SHA3_512_RATE_BYTES + 1;
    let blocks = fixed_blocks.unwrap_or(actual_blocks);
    assert!(actual_blocks <= blocks);
    let zero = builder.add_constant_64(0);
    let mut words = vec![zero; blocks * SHA3_512_RATE_WORDS];
    for (index, word) in frame.words.iter().copied().enumerate() {
        words[index] = word;
    }
    let suffix_word = frame.len_bytes / 8;
    let suffix_shift = (frame.len_bytes % 8) * 8;
    words[suffix_word] = builder.bxor(
        words[suffix_word],
        builder.add_constant_64(SHA3_DOMAIN_SUFFIX << suffix_shift),
    );
    let final_word = actual_blocks * SHA3_512_RATE_WORDS - 1;
    words[final_word] = builder.bxor(words[final_word], builder.add_constant_64(0x80u64 << 56));
    words
}

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

#[derive(Clone)]
struct Blake2bFixedSchedule {
    blocks: [[Wire; BLAKE2B_BLOCK_WORDS]; 2],
    counter_lo: [Wire; 2],
    counter_hi: [Wire; 2],
    final_mask: [Wire; 2],
}

fn blake2b448_words(builder: &CircuitBuilder, frame: &PackedFrame) -> [Wire; DIGEST_WORDS] {
    assert!(frame.len_bytes > 0);
    let blocks = frame.len_bytes.div_ceil(BLAKE2B_BLOCK_BYTES);
    let zero = builder.add_constant_64(0);
    let mut h = blake2b_initial_state(builder);
    for block in 0..blocks {
        let message: [Wire; BLAKE2B_BLOCK_WORDS] = array::from_fn(|word| {
            frame
                .words
                .get(block * BLAKE2B_BLOCK_WORDS + word)
                .copied()
                .unwrap_or(zero)
        });
        let counter = ((block + 1) * BLAKE2B_BLOCK_BYTES).min(frame.len_bytes) as u64;
        let final_mask = if block + 1 == blocks { u64::MAX } else { 0 };
        h = blake2b_compress(
            builder,
            h,
            message,
            builder.add_constant_64(counter),
            zero,
            builder.add_constant_64(final_mask),
        );
    }
    h[..DIGEST_WORDS].try_into().unwrap()
}

fn mux_one_hot_blake2b448(
    builder: &CircuitBuilder,
    selectors: &[Wire; AUTHORIZATION_MODE_COUNT],
    arms: &[PackedFrame; AUTHORIZATION_MODE_COUNT],
) -> [Wire; DIGEST_WORDS] {
    let schedules: [Blake2bFixedSchedule; AUTHORIZATION_MODE_COUNT] =
        array::from_fn(|index| fixed_two_block_blake_schedule(builder, &arms[index]));
    let mut h = blake2b_initial_state(builder);
    for block in 0..2 {
        let message: [Wire; BLAKE2B_BLOCK_WORDS] = array::from_fn(|word| {
            select_one_hot_wire(
                builder,
                selectors,
                &array::from_fn(|arm| schedules[arm].blocks[block][word]),
            )
        });
        let counter_lo = select_one_hot_wire(
            builder,
            selectors,
            &array::from_fn(|arm| schedules[arm].counter_lo[block]),
        );
        let counter_hi = select_one_hot_wire(
            builder,
            selectors,
            &array::from_fn(|arm| schedules[arm].counter_hi[block]),
        );
        let final_mask = select_one_hot_wire(
            builder,
            selectors,
            &array::from_fn(|arm| schedules[arm].final_mask[block]),
        );
        h = blake2b_compress(builder, h, message, counter_lo, counter_hi, final_mask);
    }
    h[..DIGEST_WORDS].try_into().unwrap()
}

fn fixed_two_block_blake_schedule(
    builder: &CircuitBuilder,
    frame: &PackedFrame,
) -> Blake2bFixedSchedule {
    assert!((129..=256).contains(&frame.len_bytes));
    let zero = builder.add_constant_64(0);
    Blake2bFixedSchedule {
        blocks: array::from_fn(|block| {
            array::from_fn(|word| {
                frame
                    .words
                    .get(block * BLAKE2B_BLOCK_WORDS + word)
                    .copied()
                    .unwrap_or(zero)
            })
        }),
        counter_lo: [
            builder.add_constant_64(BLAKE2B_BLOCK_BYTES as u64),
            builder.add_constant_64(frame.len_bytes as u64),
        ],
        counter_hi: [zero, zero],
        final_mask: [zero, builder.add_constant_64(u64::MAX)],
    }
}

fn blake2b_initial_state(builder: &CircuitBuilder) -> [Wire; 8] {
    let mut h = BLAKE2B_IV.map(|word| builder.add_constant_64(word));
    // RFC 7693 parameter block: digest length 56, key length 0, fanout 1,
    // depth 1.  The primitive is unkeyed.
    h[0] = builder.bxor(h[0], builder.add_constant_64(0x0101_0038));
    h
}

fn blake2b_compress(
    builder: &CircuitBuilder,
    h: [Wire; 8],
    message: [Wire; 16],
    counter_lo: Wire,
    counter_hi: Wire,
    final_mask: Wire,
) -> [Wire; 8] {
    let mut v: [Wire; 16] = array::from_fn(|index| {
        if index < 8 {
            h[index]
        } else {
            builder.add_constant_64(BLAKE2B_IV[index - 8])
        }
    });
    v[12] = builder.bxor(v[12], counter_lo);
    v[13] = builder.bxor(v[13], counter_hi);
    v[14] = builder.bxor(v[14], final_mask);
    for sigma in &BLAKE2B_SIGMA {
        blake2b_g(
            builder,
            &mut v,
            0,
            4,
            8,
            12,
            message[sigma[0]],
            message[sigma[1]],
        );
        blake2b_g(
            builder,
            &mut v,
            1,
            5,
            9,
            13,
            message[sigma[2]],
            message[sigma[3]],
        );
        blake2b_g(
            builder,
            &mut v,
            2,
            6,
            10,
            14,
            message[sigma[4]],
            message[sigma[5]],
        );
        blake2b_g(
            builder,
            &mut v,
            3,
            7,
            11,
            15,
            message[sigma[6]],
            message[sigma[7]],
        );
        blake2b_g(
            builder,
            &mut v,
            0,
            5,
            10,
            15,
            message[sigma[8]],
            message[sigma[9]],
        );
        blake2b_g(
            builder,
            &mut v,
            1,
            6,
            11,
            12,
            message[sigma[10]],
            message[sigma[11]],
        );
        blake2b_g(
            builder,
            &mut v,
            2,
            7,
            8,
            13,
            message[sigma[12]],
            message[sigma[13]],
        );
        blake2b_g(
            builder,
            &mut v,
            3,
            4,
            9,
            14,
            message[sigma[14]],
            message[sigma[15]],
        );
    }
    array::from_fn(|index| builder.bxor(h[index], builder.bxor(v[index], v[index + 8])))
}

#[allow(clippy::too_many_arguments)]
fn blake2b_g(
    builder: &CircuitBuilder,
    v: &mut [Wire; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: Wire,
    y: Wire,
) {
    let (a_plus_b, _) = builder.iadd(v[a], v[b]);
    let (a_next, _) = builder.iadd(a_plus_b, x);
    let d_next = builder.rotr(builder.bxor(v[d], a_next), 32);
    let (c_next, _) = builder.iadd(v[c], d_next);
    let b_next = builder.rotr(builder.bxor(v[b], c_next), 24);
    let (a_plus_b, _) = builder.iadd(a_next, b_next);
    let (a_final, _) = builder.iadd(a_plus_b, y);
    let d_final = builder.rotr(builder.bxor(d_next, a_final), 16);
    let (c_final, _) = builder.iadd(c_next, d_final);
    let b_final = builder.rotr(builder.bxor(b_next, c_final), 63);
    v[a] = a_final;
    v[b] = b_final;
    v[c] = c_final;
    v[d] = d_final;
}

fn select_one_hot_wire<const N: usize>(
    builder: &CircuitBuilder,
    selectors: &[Wire; N],
    values: &[Wire; N],
) -> Wire {
    let zero = builder.add_constant_64(0);
    selectors
        .iter()
        .zip(values)
        .fold(zero, |selected, (&selector, &value)| {
            builder.bxor(selected, builder.select(selector, value, zero))
        })
}

fn candidate_public_le_word(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    assert!(byte_offset + 8 <= CANDIDATE_STATEMENT_BYTES);
    let word = byte_offset / 8;
    let shift = (byte_offset % 8) * 8;
    if shift == 0 {
        return public[word];
    }
    builder.bxor(
        builder.shr(public[word], shift as u32),
        builder.shl(public[word + 1], (64 - shift) as u32),
    )
}

fn candidate_public_words_at<const N: usize>(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
    byte_offset: usize,
) -> [Wire; N] {
    array::from_fn(|word| candidate_public_le_word(builder, public, byte_offset + word * 8))
}

fn candidate_public_byte(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    assert!(byte_offset < CANDIDATE_STATEMENT_BYTES);
    builder.extract_byte(public[byte_offset / 8], (byte_offset % 8) as u32)
}

fn candidate_public_be_u64(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    let bytes: [Wire; 8] =
        array::from_fn(|index| candidate_public_byte(builder, public, byte_offset + index));
    decode_be(builder, &bytes)
}

fn candidate_public_be_u32(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
    byte_offset: usize,
) -> Wire {
    let bytes: [Wire; 4] =
        array::from_fn(|index| candidate_public_byte(builder, public, byte_offset + index));
    decode_be(builder, &bytes)
}

fn candidate_public_field_words(
    builder: &CircuitBuilder,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
    byte_offset: usize,
    len_bytes: usize,
) -> Vec<Wire> {
    assert!(byte_offset + len_bytes <= CANDIDATE_STATEMENT_BYTES);
    let bytes: Vec<Wire> = (0..len_bytes)
        .map(|index| candidate_public_byte(builder, public, byte_offset + index))
        .collect();
    pack_bytes(builder, &bytes)
}

fn assert_candidate_public_bytes_const(
    builder: &CircuitBuilder,
    name: &str,
    public: &[Wire; CANDIDATE_STATEMENT_WORDS],
    byte_offset: usize,
    expected: &[u8],
) {
    assert!(byte_offset + expected.len() <= CANDIDATE_STATEMENT_BYTES);
    for (index, expected) in expected.iter().copied().enumerate() {
        builder.assert_eq(
            format!("{name}.byte[{index}]"),
            candidate_public_byte(builder, public, byte_offset + index),
            builder.add_constant_64(expected as u64),
        );
    }
}

fn activation_bytes(activation: DiagnosticActivationBinding) -> [u8; 184] {
    let mut bytes = Vec::with_capacity(184);
    bytes.extend_from_slice(&activation.circuit_version.to_be_bytes());
    bytes.extend_from_slice(&activation.crypto_suite.to_be_bytes());
    bytes.extend_from_slice(&activation.family_id.to_be_bytes());
    bytes.extend_from_slice(&activation.action_id.to_be_bytes());
    bytes.extend_from_slice(&activation.network_id.to_be_bytes());
    bytes.push(activation.backend_id);
    bytes.push(activation.proof_profile);
    bytes.extend_from_slice(&activation.domain_set.to_be_bytes());
    bytes.extend_from_slice(&activation.chain_id);
    bytes.extend_from_slice(&activation.genesis_id);
    bytes.extend_from_slice(&activation.rules_hash);
    bytes
        .try_into()
        .expect("diagnostic activation is 184 bytes")
}

/// Lossless encoder delegated to the scalar candidate codec. The typed
/// statement activation must equal the verifier-selected activation.
pub fn encode_diagnostic_statement(
    statement: &FullBlake2b448Statement,
    activation: DiagnosticActivationBinding,
) -> [u8; CANDIDATE_STATEMENT_BYTES] {
    assert_diagnostic_activation(activation);
    scalar_candidate::candidate_statement_bytes(statement, activation)
        .expect("typed statement must satisfy the exact scalar candidate codec")
}

pub fn decode_diagnostic_activation(
    statement: &[u8; CANDIDATE_STATEMENT_BYTES],
) -> Option<DiagnosticActivationBinding> {
    if statement[..8] != DIAGNOSTIC_STATEMENT_MAGIC
        || statement[8..10] != DIAGNOSTIC_STATEMENT_GRAMMAR.to_be_bytes()
    {
        return None;
    }
    let u16_at =
        |offset: usize| u16::from_be_bytes(statement[offset..offset + 2].try_into().unwrap());
    let u32_at =
        |offset: usize| u32::from_be_bytes(statement[offset..offset + 4].try_into().unwrap());
    let activation = DiagnosticActivationBinding {
        circuit_version: u16_at(OFFSET_ACTIVATION),
        crypto_suite: u16_at(OFFSET_ACTIVATION + 2),
        family_id: u16_at(OFFSET_ACTIVATION + 4),
        action_id: u16_at(OFFSET_ACTIVATION + 6),
        network_id: u32_at(OFFSET_ACTIVATION + 8),
        backend_id: statement[OFFSET_ACTIVATION + 12],
        proof_profile: statement[OFFSET_PROFILE],
        domain_set: u16_at(OFFSET_DOMAIN_SET),
        chain_id: statement[OFFSET_CHAIN_ID..OFFSET_GENESIS_ID]
            .try_into()
            .unwrap(),
        genesis_id: statement[OFFSET_GENESIS_ID..OFFSET_RULES_HASH]
            .try_into()
            .unwrap(),
        rules_hash: statement[OFFSET_RULES_HASH..CANDIDATE_STATEMENT_BYTES]
            .try_into()
            .unwrap(),
    };
    if activation.has_v6_route()
        || activation.circuit_version == 0
        || activation.crypto_suite == 0
        || activation.family_id == 0
        || activation.action_id == 0
        || activation.backend_id == 0
        || activation.proof_profile == 0
        || activation.domain_set == 0
        || activation.chain_id.iter().all(|byte| *byte == 0)
        || activation.genesis_id.iter().all(|byte| *byte == 0)
        || activation.rules_hash.iter().all(|byte| *byte == 0)
        || scalar_candidate::decode_candidate_statement_bytes(statement, activation).is_err()
    {
        return None;
    }
    Some(activation)
}

fn pack_statement_words(
    statement: &[u8; CANDIDATE_STATEMENT_BYTES],
) -> [u64; CANDIDATE_STATEMENT_WORDS] {
    assert_eq!(&statement[..8], &DIAGNOSTIC_STATEMENT_MAGIC);
    assert_eq!(
        &statement[8..10],
        &DIAGNOSTIC_STATEMENT_GRAMMAR.to_be_bytes()
    );
    array::from_fn(|word| {
        let start = word * 8;
        let mut bytes = [0u8; 8];
        let available = (CANDIDATE_STATEMENT_BYTES - start).min(8);
        bytes[..available].copy_from_slice(&statement[start..start + available]);
        u64::from_le_bytes(bytes)
    })
}

fn pack_bytes48_words(bytes: &[u8; LIVE_STABLECOIN_BINDING_WORDS * 8]) -> [u64; 6] {
    array::from_fn(|word| u64::from_le_bytes(bytes[word * 8..word * 8 + 8].try_into().unwrap()))
}

fn pack_u128_words(value: u128) -> [u64; 2] {
    [value as u64, (value >> 64) as u64]
}

fn pack_consensus_state_words(
    state: &StablecoinConsensusStateSeam,
) -> [u64; CANDIDATE_CONSENSUS_STATE_WORDS] {
    let mut words = [0u64; CANDIDATE_CONSENSUS_STATE_WORDS];
    words[STATE_SEAM_VERSION_WORD] = u64::from(state.seam_version);
    words[STATE_EXPECTED_HEIGHT_WORD] = state.expected_current_height;
    words[STATE_PROVIDED_HEIGHT_WORD] = state.provided_current_height;
    words[STATE_ENTRY_INDEX_WORD] = u64::from(state.entry_index);
    words[STATE_ENTRY_PRESENT_WORD] = u64::from(state.entry.is_some());
    words[STATE_EXPECTED_MANIFEST_COMMITMENT_WORDS]
        .copy_from_slice(&state.expected_manifest_state_commitment_v1.to_le_words());
    words[STATE_PROVIDED_MANIFEST_COMMITMENT_WORDS]
        .copy_from_slice(&state.provided_manifest_state_commitment_v1.to_le_words());
    if let Some(entry) = &state.entry {
        words[STATE_ASSET_ID_WORD] = u64::from(entry.asset_id);
        words[STATE_ORACLE_FEED_WORD] = u64::from(entry.oracle_feed);
        words[STATE_ATTESTATION_ID_WORD] = entry.attestation_id;
        words[STATE_MIN_COLLATERAL_WORDS]
            .copy_from_slice(&pack_u128_words(entry.min_collateral_ratio_ppm));
        words[STATE_MAX_MINT_WORDS].copy_from_slice(&pack_u128_words(entry.max_mint_per_epoch));
        words[STATE_ORACLE_MAX_AGE_WORD] = entry.oracle_max_age;
        words[STATE_ORACLE_SUBMITTED_AT_WORD] = entry.oracle_submitted_at;
        words[STATE_ENABLED_AT_WORD] = entry.enabled_at;
        words[STATE_RETIRED_PRESENT_WORD] = u64::from(entry.retired_at.is_some());
        words[STATE_RETIRED_AT_WORD] = entry.retired_at.unwrap_or(0);
        words[STATE_POLICY_VERSION_WORD] = u64::from(entry.policy_version);
        words[STATE_ACTIVE_WORD] = u64::from(entry.active);
        words[STATE_POLICY_HASH_WORDS].copy_from_slice(&pack_bytes48_words(
            &scalar_candidate::live_stablecoin_policy_hash(entry),
        ));
        words[STATE_ORACLE_COMMITMENT_WORDS]
            .copy_from_slice(&pack_bytes48_words(&entry.oracle_commitment));
        words[STATE_ATTESTATION_COMMITMENT_WORDS]
            .copy_from_slice(&pack_bytes48_words(&entry.attestation_commitment));
        words[STATE_ATTESTATION_DISPUTED_WORD] = u64::from(entry.attestation_disputed);
    }
    words
}

fn pack_candidate_private_words(witness: &FullShake448Witness) -> [u64; CANDIDATE_PRIVATE_WORDS] {
    let bytes = serialize_candidate_private(witness);
    array::from_fn(|word| u64::from_le_bytes(bytes[word * 8..word * 8 + 8].try_into().unwrap()))
}

fn serialize_candidate_private(witness: &FullShake448Witness) -> [u8; CANDIDATE_PRIVATE_BYTES] {
    let mut bytes = Vec::with_capacity(CANDIDATE_PRIVATE_BYTES);
    for input in &witness.inputs {
        bytes.extend_from_slice(&input.spend_key);
        push_candidate_note(&mut bytes, &input.note);
        bytes.extend_from_slice(&input.position.to_be_bytes());
        for sibling in &input.siblings {
            bytes.extend_from_slice(sibling);
        }
        push_candidate_bools(&mut bytes, &input.balance_slot_selectors);
    }
    for output in &witness.outputs {
        push_candidate_note(&mut bytes, &output.note);
        push_candidate_bools(&mut bytes, &output.balance_slot_selectors);
    }
    let mode = match witness.auth.mode {
        PrivateAuthMode::SingleKey => 0u64,
        PrivateAuthMode::AccumulatorInit => 1,
        PrivateAuthMode::ApprovalStep => 2,
        PrivateAuthMode::ValueLockCreation => 3,
        PrivateAuthMode::FinalThresholdSpend => 4,
    };
    bytes.extend_from_slice(&mode.to_be_bytes());
    push_candidate_accumulator(&mut bytes, &witness.auth.current);
    push_candidate_accumulator(&mut bytes, &witness.auth.next);
    for tag in &witness.auth.signer_tags {
        bytes.extend_from_slice(tag);
    }
    assert_eq!(bytes.len(), CANDIDATE_BASE_PRIVATE_WORDS * 8);
    for output in &witness.outputs {
        bytes.extend_from_slice(&output.canonical_ciphertext);
        bytes.resize(
            bytes.len() + (CIPHERTEXT_WORDS * 8 - V6_CANONICAL_CIPHERTEXT_BYTES),
            0,
        );
    }
    bytes
        .try_into()
        .expect("candidate private transport has one fixed width")
}

fn push_candidate_note(output: &mut Vec<u8>, note: &NoteOpening) {
    let kind = match note.kind {
        NoteKind::Ordinary => 0u64,
        NoteKind::Accumulator => 1,
        NoteKind::ValueLock => 2,
    };
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&note.value.to_be_bytes());
    output.extend_from_slice(&note.asset_id.to_be_bytes());
    output.extend_from_slice(&note.pk_recipient);
    output.extend_from_slice(&note.rho);
    output.extend_from_slice(&note.randomness);
    output.extend_from_slice(&note.pk_auth);
}

fn push_candidate_bools<const N: usize>(output: &mut Vec<u8>, values: &[bool; N]) {
    for value in values {
        output.extend_from_slice(&u64::from(*value).to_be_bytes());
    }
}

fn push_candidate_accumulator(output: &mut Vec<u8>, opening: &AccumulatorOpening) {
    output.extend_from_slice(&opening.policy_root);
    output.extend_from_slice(&opening.intent_digest);
    output.extend_from_slice(&opening.threshold.to_be_bytes());
    output.extend_from_slice(&opening.signer_count.to_be_bytes());
    output.extend_from_slice(&opening.approval_count.to_be_bytes());
    push_candidate_bools(output, &opening.approved_slots);
}

pub fn source_digest() -> [u8; 64] {
    let mut hasher = Sha512::new();
    ShaDigest::update(&mut hasher, b"hegemon.m4-mixed-candidate.source.v2\0");
    ShaDigest::update(&mut hasher, include_bytes!("mixed_candidate.rs"));
    ShaDigest::update(&mut hasher, include_bytes!("lib.rs"));
    ShaDigest::update(&mut hasher, include_bytes!("../Cargo.toml"));
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../strict-mixed-field/src/lib.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../../../circuits/transaction/src/full_blake2b448_relation.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../../../circuits/transaction/src/full_shake448_relation.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../../../circuits/transaction/src/full_shake448_statement.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../../../protocol/kernel/src/manifest.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../../../protocol/kernel/src/stablecoin_manifest_commitment_v1.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../../../crypto/hash384/src/lib.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../binius64/crates/frontend/src/builder/mod.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../binius64/crates/circuits/src/keccak/permutation.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../binius64/crates/core/src/constraint_system/m4.rs"),
    );
    ShaDigest::update(
        &mut hasher,
        include_bytes!("../../binius64/crates/core/src/constraint_system/shift.rs"),
    );
    ShaDigest::update(&mut hasher, PINNED_BINIUS_TREE_SHA512.as_bytes());
    hasher.finalize().into()
}

fn bind_invocation_kind(hasher: &mut Sha512, kind: HashInvocationKind) {
    match kind {
        HashInvocationKind::NoteInput(index) => {
            ShaDigest::update(hasher, [0, index as u8]);
        }
        HashInvocationKind::NoteOutput(index) => {
            ShaDigest::update(hasher, [1, index as u8]);
        }
        HashInvocationKind::Nullifier(index) => {
            ShaDigest::update(hasher, [2, index as u8]);
        }
        HashInvocationKind::Merkle { input, level } => {
            ShaDigest::update(hasher, [3, input as u8, level as u8]);
        }
        HashInvocationKind::Spend { input, lane } => {
            ShaDigest::update(hasher, [4, input as u8, lane as u8]);
        }
        HashInvocationKind::Policy => ShaDigest::update(hasher, [5]),
        HashInvocationKind::Authorization { slot, lane } => {
            ShaDigest::update(hasher, [6, slot as u8, lane as u8]);
        }
        HashInvocationKind::Intent => ShaDigest::update(hasher, [7]),
        HashInvocationKind::Balance => ShaDigest::update(hasher, [8]),
        HashInvocationKind::Ciphertext(index) => {
            ShaDigest::update(hasher, [9, index as u8]);
        }
    }
}

fn bind_output_binding(hasher: &mut Sha512, binding: CandidateOutputBinding) {
    match binding {
        CandidateOutputBinding::Internal => ShaDigest::update(hasher, [0]),
        CandidateOutputBinding::PublicWhenInputActive(index) => {
            ShaDigest::update(hasher, [1, index as u8]);
        }
        CandidateOutputBinding::PublicWhenOutputActive(index) => {
            ShaDigest::update(hasher, [2, index as u8]);
        }
        CandidateOutputBinding::PublicAlways => ShaDigest::update(hasher, [3]),
    }
}

fn bind_frame_width(hasher: &mut Sha512, width: CandidateFrameWidth) {
    match width {
        CandidateFrameWidth::Exact(bytes) => {
            ShaDigest::update(hasher, [0]);
            ShaDigest::update(hasher, (bytes as u32).to_be_bytes());
        }
        CandidateFrameWidth::AuthorizationMux { arm_bytes } => {
            ShaDigest::update(hasher, [1]);
            for bytes in arm_bytes {
                ShaDigest::update(hasher, (bytes as u32).to_be_bytes());
            }
        }
    }
}

pub fn program_digest(
    profile: SecretHashProfile,
    activation: DiagnosticActivationBinding,
) -> [u8; 64] {
    assert_diagnostic_activation(activation);
    let mut hasher = Sha512::new();
    ShaDigest::update(&mut hasher, b"hegemon.m4-mixed-candidate.program.v2\0");
    ShaDigest::update(&mut hasher, CANDIDATE_FRAME_TAG);
    ShaDigest::update(&mut hasher, DIAGNOSTIC_STATEMENT_MAGIC);
    ShaDigest::update(&mut hasher, DIAGNOSTIC_STATEMENT_GRAMMAR.to_be_bytes());
    ShaDigest::update(&mut hasher, [profile as u8]);
    ShaDigest::update(&mut hasher, PINNED_BINIUS_REVISION.as_bytes());
    ShaDigest::update(&mut hasher, PINNED_BINIUS_TREE_SHA512.as_bytes());
    ShaDigest::update(&mut hasher, activation_bytes(activation));
    ShaDigest::update(&mut hasher, ACTIVE_STABLECOIN_POLICY_DOMAIN);
    ShaDigest::update(&mut hasher, ACTIVE_STABLECOIN_MANIFEST_STATE_DOMAIN);
    ShaDigest::update(
        &mut hasher,
        (ACTIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES as u16).to_be_bytes(),
    );
    ShaDigest::update(
        &mut hasher,
        [
            ACTIVE_STABLECOIN_POLICY_HASH_BYTES as u8,
            ACTIVE_STABLECOIN_MANIFEST_COMMITMENT_BYTES as u8,
            ACTIVE_STABLECOIN_MANIFEST_ADAPTER_INTEGRATED as u8,
            ACTIVE_STABLECOIN_LIFECYCLE_CONSTRAINTS_COMPILED as u8,
            ACTIVE_STABLECOIN_MANIFEST_MEMBERSHIP_GRAPH_COMPILED as u8,
            STRICT_STABLECOIN_PQ_MARGIN as u8,
        ],
    );
    ShaDigest::update(
        &mut hasher,
        (CANDIDATE_STATEMENT_BYTES as u32).to_be_bytes(),
    );
    ShaDigest::update(
        &mut hasher,
        (CANDIDATE_CONSENSUS_STATE_WORDS as u32).to_be_bytes(),
    );
    ShaDigest::update(
        &mut hasher,
        scalar_candidate::STABLECOIN_CONSENSUS_STATE_SEAM_VERSION.to_be_bytes(),
    );
    ShaDigest::update(&mut hasher, (CANDIDATE_PRIVATE_WORDS as u32).to_be_bytes());
    for role in role_registry(profile) {
        ShaDigest::update(&mut hasher, role.role.as_bytes());
        ShaDigest::update(&mut hasher, [role.algorithm as u8, role.purpose as u8]);
        ShaDigest::update(&mut hasher, (role.calls as u16).to_be_bytes());
        ShaDigest::update(&mut hasher, (role.maximum_frame_bytes as u32).to_be_bytes());
        ShaDigest::update(&mut hasher, (role.output_bytes as u16).to_be_bytes());
        ShaDigest::update(&mut hasher, (role.cores_per_call as u16).to_be_bytes());
    }
    for call in hash_invocation_registry(profile) {
        ShaDigest::update(&mut hasher, (call.index as u16).to_be_bytes());
        ShaDigest::update(&mut hasher, call.role);
        ShaDigest::update(&mut hasher, [call.algorithm as u8, call.purpose as u8]);
        ShaDigest::update(&mut hasher, (call.maximum_frame_bytes as u32).to_be_bytes());
        bind_frame_width(&mut hasher, call.frame_width);
        ShaDigest::update(&mut hasher, (call.output_bytes as u16).to_be_bytes());
        ShaDigest::update(&mut hasher, (call.primitive_cores as u16).to_be_bytes());
        ShaDigest::update(
            &mut hasher,
            [call.source_bound as u8, call.output_bound as u8],
        );
        bind_invocation_kind(&mut hasher, call.kind);
        bind_output_binding(&mut hasher, call.binding);
    }
    ShaDigest::update(&mut hasher, source_digest());
    hasher.finalize().into()
}

pub const REJECTED_IDENTITY_MAGICS: [[u8; 8]; 5] = [
    *b"HGF6ST02",
    *b"HGF6HR02",
    *b"HGR6RM02",
    *b"HGV6PB02",
    scalar_candidate::RETIRED_DIAGNOSTIC_STATEMENT_MAGIC,
];

pub fn rejects_reserved_identity(bytes: &[u8]) -> bool {
    bytes.get(..8).is_some_and(|identity| {
        REJECTED_IDENTITY_MAGICS
            .iter()
            .any(|magic| identity == magic)
    })
}

pub const fn authorization_arm_lengths(slot_b: bool) -> [usize; 5] {
    if slot_b {
        [136, 136, 181, 136, 143]
    } else {
        [136, 181, 181, 143, 181]
    }
}

pub fn candidate_activity_shape_accepts(
    mode: PrivateAuthMode,
    inputs: [bool; 2],
    outputs: [bool; 2],
) -> bool {
    let nonempty = inputs.into_iter().chain(outputs).any(|active| active);
    let input_nonempty = inputs.into_iter().any(|active| active);
    let mode_shape = match mode {
        PrivateAuthMode::SingleKey => true,
        PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
            input_nonempty && outputs[0]
        }
        PrivateAuthMode::ApprovalStep => inputs == [true, true] && outputs[0],
        PrivateAuthMode::FinalThresholdSpend => inputs == [true, true],
    };
    nonempty && mode_shape
}

pub fn candidate_accumulator_metadata_accepts(
    opening: &AccumulatorOpening,
    signer_tags: &[[u8; DIGEST_BYTES]; 6],
    expected_policy_root: [u8; DIGEST_BYTES],
    expected_intent: Option<[u8; DIGEST_BYTES]>,
) -> bool {
    if !(1..=6).contains(&opening.signer_count)
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
        return false;
    }
    for slot in 0..6 {
        if slot < opening.signer_count as usize {
            if signer_tags[..slot].contains(&signer_tags[slot]) {
                return false;
            }
        } else if signer_tags[slot] != [0; DIGEST_BYTES] || opening.approved_slots[slot] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::digest::{Update as BlakeUpdate, VariableOutput};
    use blake2::Blake2bVar;
    use sha3::digest::{ExtendableOutput, Update as Sha3Update, XofReader};
    use sha3::{Sha3_512, Shake256};
    use transaction_circuit::full_blake2b448_relation::StablecoinStatementBinding384;
    use transaction_circuit::full_shake448_relation::{
        InputWitness, OutputWitness, PrivateAuthWitness,
    };
    use transaction_circuit::full_shake448_statement::{SignedMagnitude, V6ActivationBinding};

    fn diagnostic_activation() -> DiagnosticActivationBinding {
        DiagnosticActivationBinding {
            circuit_version: 0x4481,
            crypto_suite: 0x4482,
            family_id: 0x4483,
            action_id: 0x4484,
            network_id: 0x0102_0304,
            backend_id: 0x45,
            proof_profile: 0x46,
            domain_set: 0x4487,
            chain_id: [0x11; 56],
            genesis_id: [0x22; 56],
            rules_hash: [0x33; 56],
        }
    }

    fn live_policy_entry(
        asset_id: u32,
    ) -> protocol_kernel::manifest::StablecoinPolicyManifestEntry {
        protocol_kernel::manifest::StablecoinPolicyManifestEntry {
            asset_id,
            oracle_feed: 9,
            attestation_id: 11,
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: u128::from(
                transaction_circuit::full_shake448_statement::V6_MAX_NOTE_VALUE,
            ),
            oracle_max_age: 64,
            oracle_submitted_at: 20,
            enabled_at: 10,
            retired_at: Some(100),
            policy_version: 3,
            active: true,
            oracle_commitment: [0xa1; scalar_candidate::LIVE_STABLECOIN_BINDING_BYTES],
            attestation_commitment: [0xb2; scalar_candidate::LIVE_STABLECOIN_BINDING_BYTES],
            attestation_disputed: false,
        }
    }

    fn protocol_manifest_with_policies(
        stablecoin_policies: Vec<protocol_kernel::manifest::StablecoinPolicyManifestEntry>,
    ) -> protocol_kernel::manifest::ProtocolManifest {
        let mut manifest = protocol_kernel::manifest::protocol_manifest();
        manifest.stablecoin_policies = stablecoin_policies;
        manifest
    }

    fn consensus_state_for_manifest(
        statement: &FullBlake2b448Statement,
        manifest: &protocol_kernel::manifest::ProtocolManifest,
        current_height: u64,
    ) -> StablecoinConsensusStateSeam {
        let authority = scalar_candidate::StablecoinAuthority::try_from_statement(statement)
            .expect("typed stablecoin statement");
        let commitment = protocol_kernel::stablecoin_manifest_commitment_v1::
            protocol_manifest_stablecoin_state_commitment_v1(manifest)
            .expect("bounded diagnostic manifest");
        let view = scalar_candidate::StablecoinProtocolManifestView {
            current_height,
            manifest: manifest.clone(),
        };
        scalar_candidate::stablecoin_consensus_state_seam_from_protocol_manifest(
            authority,
            Some(&view),
            commitment,
            commitment,
        )
        .expect("live diagnostic manifest state")
    }

    fn install_live_stablecoin_binding(
        statement: &mut FullBlake2b448Statement,
        issuance_delta: SignedMagnitude,
    ) -> protocol_kernel::manifest::StablecoinPolicyManifestEntry {
        let entry = live_policy_entry(
            u32::try_from(statement.balance_asset_ids[1]).expect("fixture asset"),
        );
        statement.stablecoin = StablecoinStatementBinding384 {
            enabled: true,
            asset_id: u64::from(entry.asset_id),
            policy_version: entry.policy_version,
            issuance_delta,
            policy_hash: scalar_candidate::live_stablecoin_policy_hash(&entry),
            oracle_commitment: entry.oracle_commitment,
            attestation_commitment: entry.attestation_commitment,
        };
        entry
    }

    fn semantic_statement() -> FullBlake2b448Statement {
        FullBlake2b448Statement {
            input_flags: [true, false],
            output_flags: [false, true],
            anchor: [0x41; 56],
            nullifiers: [[0x42; 56], [0; 56]],
            commitments: [[0; 56], [0x43; 56]],
            ciphertext_hashes: [[0; 56], [0x44; 56]],
            ciphertext_sizes: [0, V6_CANONICAL_CIPHERTEXT_BYTES as u32],
            balance_asset_ids: [0, 7, u64::MAX, u64::MAX],
            fee: 3,
            value_balance: SignedMagnitude {
                negative: false,
                magnitude: 2,
            },
            stablecoin: StablecoinStatementBinding384 {
                enabled: true,
                asset_id: 7,
                policy_version: 0,
                issuance_delta: SignedMagnitude::default(),
                policy_hash: [0; 48],
                oracle_commitment: [0; 48],
                attestation_commitment: [0; 48],
            },
            balance_tag: [0x45; 56],
            activation: diagnostic_activation(),
        }
    }

    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), N * 2);
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    fn patterned(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn blake2b448(message: &[u8]) -> [u8; 56] {
        let mut state = Blake2bVar::new(56).unwrap();
        BlakeUpdate::update(&mut state, message);
        let mut output = [0u8; 56];
        state.finalize_variable(&mut output).unwrap();
        output
    }

    fn shake256_448(message: &[u8]) -> [u8; DIGEST_BYTES] {
        let mut state = Shake256::default();
        Sha3Update::update(&mut state, message);
        let mut reader = state.finalize_xof();
        let mut output = [0u8; DIGEST_BYTES];
        reader.read(&mut output);
        output
    }

    fn host_hash(profile: SecretHashProfile, secret: bool, message: &[u8]) -> [u8; DIGEST_BYTES] {
        if !secret {
            return shake256_448(message);
        }
        match profile {
            SecretHashProfile::Blake2b448Mixed => blake2b448(message),
            SecretHashProfile::Sha3_512SplitControl => Sha3_512::digest(message)[..DIGEST_BYTES]
                .try_into()
                .unwrap(),
        }
    }

    fn host_frame(role: [u8; 8], fields: &[&[u8]]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&CANDIDATE_FRAME_TAG);
        frame.extend_from_slice(&role);
        frame.push(fields.len().try_into().unwrap());
        for field in fields {
            frame.extend_from_slice(&(field.len() as u16).to_be_bytes());
            frame.extend_from_slice(field);
        }
        frame
    }

    fn host_note_frame(note: &NoteOpening) -> Vec<u8> {
        let kind = [match note.kind {
            NoteKind::Ordinary => 0,
            NoteKind::Accumulator => 1,
            NoteKind::ValueLock => 2,
        }];
        host_frame(
            ROLE_NOTE,
            &[
                &kind,
                &note.value.to_be_bytes(),
                &note.asset_id.to_be_bytes(),
                &note.pk_recipient,
                &note.rho,
                &note.randomness,
                &note.pk_auth,
            ],
        )
    }

    fn host_spend_frame(input: usize, lane: usize, spend_key: &[u8; 48]) -> Vec<u8> {
        let _ = input;
        let (role, lane_tag) = if lane == 0 {
            (ROLE_SPEND_A, KEY_OUTPUT_LANE_A_TAG)
        } else {
            (ROLE_SPEND_B, KEY_OUTPUT_LANE_B_TAG)
        };
        host_frame(role, &[&lane_tag, spend_key])
    }

    fn host_policy_frame(
        opening: &AccumulatorOpening,
        signer_tags: &[[u8; DIGEST_BYTES]; 6],
    ) -> Vec<u8> {
        let threshold = opening.threshold.to_be_bytes();
        let signer_count = opening.signer_count.to_be_bytes();
        let mut fields: Vec<&[u8]> = vec![&threshold, &signer_count];
        fields.extend(signer_tags.iter().map(|tag| &tag[..]));
        host_frame(ROLE_POLICY, &fields)
    }

    fn host_accumulator_frame(lane: usize, opening: &AccumulatorOpening) -> Vec<u8> {
        let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
        let lane_tag = if lane == 0 {
            KEY_OUTPUT_LANE_A_TAG
        } else {
            KEY_OUTPUT_LANE_B_TAG
        };
        let threshold = opening.threshold.to_be_bytes();
        let signer_count = opening.signer_count.to_be_bytes();
        let approval_count = opening.approval_count.to_be_bytes();
        let approved = opening.approved_slots.map(u8::from);
        host_frame(
            role,
            &[
                &lane_tag,
                &opening.policy_root,
                &opening.intent_digest,
                &threshold,
                &signer_count,
                &approval_count,
                &approved,
            ],
        )
    }

    fn host_value_lock_frame(lane: usize, opening: &AccumulatorOpening) -> Vec<u8> {
        let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
        let lane_tag = if lane == 0 {
            KEY_OUTPUT_LANE_A_TAG
        } else {
            KEY_OUTPUT_LANE_B_TAG
        };
        host_frame(
            role,
            &[&lane_tag, &opening.policy_root, &opening.intent_digest],
        )
    }

    fn host_dummy_frame(slot: usize, lane: usize) -> Vec<u8> {
        let role = if lane == 0 { ROLE_AUTH_A } else { ROLE_AUTH_B };
        let mut payload = [0u8; 117];
        payload[0] = slot as u8;
        payload[1] = lane as u8;
        host_frame(role, &[&payload])
    }

    fn host_authorization_arms(
        witness: &FullShake448Witness,
        slot: usize,
        lane: usize,
    ) -> [Vec<u8>; 5] {
        let dummy = host_dummy_frame(slot, lane);
        let current = host_accumulator_frame(lane, &witness.auth.current);
        let next = host_accumulator_frame(lane, &witness.auth.next);
        let value_lock = host_value_lock_frame(lane, &witness.auth.current);
        if slot == 0 {
            [dummy, next, current.clone(), value_lock, current]
        } else {
            [dummy.clone(), dummy.clone(), next, dummy, value_lock]
        }
    }

    fn host_authorization_digest(
        profile: SecretHashProfile,
        witness: &FullShake448Witness,
        slot: usize,
        lane: usize,
    ) -> [u8; DIGEST_BYTES] {
        let selected = witness
            .auth
            .mode
            .selectors()
            .into_iter()
            .position(|selected| selected)
            .unwrap();
        host_hash(
            profile,
            true,
            &host_authorization_arms(witness, slot, lane)[selected],
        )
    }

    fn host_merkle_frame(
        current: &[u8; DIGEST_BYTES],
        sibling: &[u8; DIGEST_BYTES],
        current_is_left: bool,
    ) -> Vec<u8> {
        if current_is_left {
            host_frame(ROLE_MERKLE, &[current, sibling])
        } else {
            host_frame(ROLE_MERKLE, &[sibling, current])
        }
    }

    fn host_nullifier_frame(key: &[u8; DIGEST_BYTES], position: u64, rho: &[u8; 48]) -> Vec<u8> {
        host_frame(ROLE_NULLIFIER, &[key, &position.to_be_bytes(), rho])
    }

    fn host_balance_frame(statement: &FullBlake2b448Statement) -> Vec<u8> {
        let mut assets = [0u8; 32];
        for (slot, asset) in statement.balance_asset_ids.iter().enumerate() {
            assets[slot * 8..slot * 8 + 8].copy_from_slice(&asset.to_be_bytes());
        }
        let sign = [u8::from(statement.value_balance.negative)];
        let stable = [u8::from(statement.stablecoin.enabled)];
        let issuance_sign = [u8::from(statement.stablecoin.issuance_delta.negative)];
        host_frame(
            ROLE_BALANCE_TAG,
            &[
                &statement.fee.to_be_bytes(),
                &sign,
                &statement.value_balance.magnitude.to_be_bytes(),
                &assets,
                &stable,
                &statement.stablecoin.asset_id.to_be_bytes(),
                &issuance_sign,
                &statement.stablecoin.issuance_delta.magnitude.to_be_bytes(),
            ],
        )
    }

    fn host_ciphertext_frame(
        statement: &FullBlake2b448Statement,
        slot: usize,
        ciphertext: &[u8; V6_CANONICAL_CIPHERTEXT_BYTES],
    ) -> Vec<u8> {
        let profile = [statement.activation.proof_profile];
        let slot_byte = [slot as u8];
        host_frame(
            ROLE_CIPHERTEXT_HASH,
            &[
                &profile,
                &statement.activation.domain_set.to_be_bytes(),
                &slot_byte,
                &(V6_CANONICAL_CIPHERTEXT_BYTES as u32).to_be_bytes(),
                ciphertext,
            ],
        )
    }

    fn host_intent_frame(statement: &FullBlake2b448Statement) -> Vec<u8> {
        let encoded = encode_diagnostic_statement(statement, statement.activation);
        let mut payload = Vec::with_capacity(701);
        payload.extend_from_slice(&encoded[..14]);
        payload.extend_from_slice(&encoded[182..]);
        assert_eq!(payload.len(), 701);
        host_frame(ROLE_INTENT, &[&payload])
    }

    fn host_resolved_keys(
        profile: SecretHashProfile,
        witness: &FullShake448Witness,
    ) -> ([[u8; DIGEST_BYTES]; 2], [[u8; DIGEST_BYTES]; 2]) {
        let spend_auth = array::from_fn(|input| {
            host_hash(
                profile,
                true,
                &host_spend_frame(input, 0, &witness.inputs[input].spend_key),
            )
        });
        let spend_nf = array::from_fn(|input| {
            host_hash(
                profile,
                true,
                &host_spend_frame(input, 1, &witness.inputs[input].spend_key),
            )
        });
        let slot_a_auth = host_authorization_digest(profile, witness, 0, 0);
        let slot_a_nf = host_authorization_digest(profile, witness, 0, 1);
        let slot_b_auth = host_authorization_digest(profile, witness, 1, 0);
        let slot_b_nf = host_authorization_digest(profile, witness, 1, 1);
        match witness.auth.mode {
            PrivateAuthMode::SingleKey
            | PrivateAuthMode::AccumulatorInit
            | PrivateAuthMode::ValueLockCreation => (spend_auth, spend_nf),
            PrivateAuthMode::ApprovalStep => {
                ([slot_a_auth, spend_auth[1]], [slot_a_nf, spend_nf[1]])
            }
            PrivateAuthMode::FinalThresholdSpend => {
                ([slot_b_auth, slot_a_auth], [slot_b_nf, slot_a_nf])
            }
        }
    }

    fn host_call_inventory(
        profile: SecretHashProfile,
        statement: &FullBlake2b448Statement,
        witness: &FullShake448Witness,
    ) -> (Vec<Vec<u8>>, Vec<[u8; DIGEST_BYTES]>) {
        let mut frames = vec![Vec::new(); scalar_candidate::PHYSICAL_HASH_CALLS];
        let mut note_digests = [[0u8; DIGEST_BYTES]; 4];
        for input in 0..2 {
            let frame = host_note_frame(&witness.inputs[input].note);
            note_digests[input] = host_hash(profile, true, &frame);
            frames[scalar_candidate::NOTE_CALL_START + input] = frame;
        }
        for output in 0..2 {
            let frame = host_note_frame(&witness.outputs[output].note);
            note_digests[2 + output] = host_hash(profile, true, &frame);
            frames[scalar_candidate::NOTE_CALL_START + 2 + output] = frame;
        }

        for input in 0..2 {
            frames[scalar_candidate::SPEND_A_CALL_START + input] =
                host_spend_frame(input, 0, &witness.inputs[input].spend_key);
            frames[scalar_candidate::SPEND_B_CALL_START + input] =
                host_spend_frame(input, 1, &witness.inputs[input].spend_key);
        }
        let selected_policy = if witness.auth.mode == PrivateAuthMode::AccumulatorInit {
            &witness.auth.next
        } else {
            &witness.auth.current
        };
        frames[scalar_candidate::POLICY_CALL] =
            host_policy_frame(selected_policy, &witness.auth.signer_tags);
        let selected_mode = witness
            .auth
            .mode
            .selectors()
            .into_iter()
            .position(|selected| selected)
            .unwrap();
        for lane in 0..2 {
            for slot in 0..2 {
                let index = if lane == 0 {
                    scalar_candidate::AUTH_A_CALL_START + slot
                } else {
                    scalar_candidate::AUTH_B_CALL_START + slot
                };
                frames[index] = host_authorization_arms(witness, slot, lane)[selected_mode].clone();
            }
        }
        frames[scalar_candidate::INTENT_CALL] = host_intent_frame(statement);
        frames[scalar_candidate::BALANCE_CALL] = host_balance_frame(statement);
        for output in 0..2 {
            frames[scalar_candidate::CIPHERTEXT_CALL_START + output] = host_ciphertext_frame(
                statement,
                output,
                &witness.outputs[output].canonical_ciphertext,
            );
        }

        let (_, resolved_nf) = host_resolved_keys(profile, witness);
        for input in 0..2 {
            frames[scalar_candidate::NULLIFIER_CALL_START + input] = host_nullifier_frame(
                &resolved_nf[input],
                witness.inputs[input].position,
                &witness.inputs[input].note.rho,
            );
            let mut current = note_digests[input];
            for level in 0..32 {
                let sibling = witness.inputs[input].siblings[level];
                let frame = host_merkle_frame(
                    &current,
                    &sibling,
                    (witness.inputs[input].position >> level) & 1 == 0,
                );
                current = host_hash(profile, false, &frame);
                frames[scalar_candidate::MERKLE_CALL_START + input * 32 + level] = frame;
            }
        }

        assert!(frames.iter().all(|frame| !frame.is_empty()));
        let registry = hash_invocation_registry(profile);
        let digests = registry
            .iter()
            .map(|call| {
                host_hash(
                    profile,
                    call.algorithm != HashAlgorithm::Shake256_448,
                    &frames[call.index],
                )
            })
            .collect();
        (frames, digests)
    }

    fn fixture_note(seed: u8, kind: NoteKind) -> NoteOpening {
        NoteOpening {
            kind,
            value: 0,
            asset_id: 0,
            pk_recipient: [seed; 32],
            rho: [seed.wrapping_add(1); 48],
            randomness: [seed.wrapping_add(2); 48],
            pk_auth: [0; DIGEST_BYTES],
        }
    }

    fn set_mode_authorizations(profile: SecretHashProfile, witness: &mut FullShake448Witness) {
        let (resolved_auth, _) = host_resolved_keys(profile, witness);
        for input in 0..2 {
            if witness.inputs[input].active {
                witness.inputs[input].note.pk_auth = resolved_auth[input];
            }
        }
        let output_key = match witness.auth.mode {
            PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
                Some(host_authorization_digest(profile, witness, 0, 0))
            }
            PrivateAuthMode::ApprovalStep => {
                Some(host_authorization_digest(profile, witness, 1, 0))
            }
            PrivateAuthMode::SingleKey | PrivateAuthMode::FinalThresholdSpend => None,
        };
        if let Some(key) = output_key.filter(|_| witness.outputs[0].active) {
            witness.outputs[0].note.pk_auth = key;
        }
    }

    fn refresh_fixture_public_bindings(
        profile: SecretHashProfile,
        statement: &mut FullBlake2b448Statement,
        witness: &mut FullShake448Witness,
    ) {
        statement.anchor = [0; DIGEST_BYTES];
        statement.nullifiers = [[0; DIGEST_BYTES]; 2];
        statement.commitments = [[0; DIGEST_BYTES]; 2];
        statement.ciphertext_hashes = [[0; DIGEST_BYTES]; 2];
        for input in &mut witness.inputs {
            input.siblings = [[0; DIGEST_BYTES]; 32];
        }
        for output in 0..2 {
            if statement.output_flags[output] {
                statement.commitments[output] = host_hash(
                    profile,
                    true,
                    &host_note_frame(&witness.outputs[output].note),
                );
                statement.ciphertext_hashes[output] = host_hash(
                    profile,
                    false,
                    &host_ciphertext_frame(
                        statement,
                        output,
                        &witness.outputs[output].canonical_ciphertext,
                    ),
                );
            }
        }
        statement.balance_tag = host_hash(profile, false, &host_balance_frame(statement));
        let intent = host_hash(profile, false, &host_intent_frame(statement));
        if witness.auth.mode == PrivateAuthMode::FinalThresholdSpend {
            witness.auth.current.intent_digest = intent;
            set_mode_authorizations(profile, witness);
        }
        let note_commitments: [[u8; DIGEST_BYTES]; 2] = array::from_fn(|input| {
            host_hash(profile, true, &host_note_frame(&witness.inputs[input].note))
        });
        if statement.input_flags == [true, true] {
            witness.inputs[0].siblings[0] = note_commitments[1];
            witness.inputs[1].siblings[0] = note_commitments[0];
        }
        let (_, nullifier_keys) = host_resolved_keys(profile, witness);
        for input in 0..2 {
            if statement.input_flags[input] {
                statement.nullifiers[input] = host_hash(
                    profile,
                    true,
                    &host_nullifier_frame(
                        &nullifier_keys[input],
                        witness.inputs[input].position,
                        &witness.inputs[input].note.rho,
                    ),
                );
                let mut current = note_commitments[input];
                for level in 0..32 {
                    current = host_hash(
                        profile,
                        false,
                        &host_merkle_frame(
                            &current,
                            &witness.inputs[input].siblings[level],
                            (witness.inputs[input].position >> level) & 1 == 0,
                        ),
                    );
                }
                if statement.anchor == [0; DIGEST_BYTES] {
                    statement.anchor = current;
                } else {
                    assert_eq!(statement.anchor, current);
                }
            }
        }
    }

    fn build_shape_fixture(
        profile: SecretHashProfile,
        mode: PrivateAuthMode,
        mask: u8,
    ) -> (FullBlake2b448Statement, FullShake448Witness) {
        let input_flags = [mask & 1 != 0, mask & 2 != 0];
        let output_flags = [mask & 4 != 0, mask & 8 != 0];
        let mut witness = FullShake448Witness {
            inputs: array::from_fn(|input| {
                if !input_flags[input] {
                    return InputWitness::zero();
                }
                InputWitness {
                    active: true,
                    spend_key: [0x30 + input as u8; 48],
                    note: fixture_note(0x40 + input as u8, NoteKind::Ordinary),
                    position: input as u64,
                    siblings: [[0; DIGEST_BYTES]; 32],
                    balance_slot_selectors: [true, false, false, false],
                }
            }),
            outputs: array::from_fn(|output| {
                if !output_flags[output] {
                    return OutputWitness::zero();
                }
                OutputWitness {
                    active: true,
                    note: fixture_note(0x50 + output as u8, NoteKind::Ordinary),
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
                if witness.outputs[0].active {
                    witness.outputs[0].note.kind = NoteKind::Accumulator;
                }
                witness.auth.next = AccumulatorOpening {
                    policy_root: [0; DIGEST_BYTES],
                    intent_digest: [0; DIGEST_BYTES],
                    threshold: 1,
                    signer_count: 1,
                    approval_count: 0,
                    approved_slots: [false; 6],
                };
            }
            PrivateAuthMode::ApprovalStep => {
                if witness.inputs[0].active {
                    witness.inputs[0].note.kind = NoteKind::Accumulator;
                    witness.inputs[0].spend_key = [0; 48];
                }
                if witness.outputs[0].active {
                    witness.outputs[0].note.kind = NoteKind::Accumulator;
                }
                let signer = host_hash(
                    profile,
                    true,
                    &host_spend_frame(1, 0, &witness.inputs[1].spend_key),
                );
                witness.auth.signer_tags[0] = signer;
                witness.auth.current = AccumulatorOpening {
                    policy_root: [0; DIGEST_BYTES],
                    intent_digest: [0; DIGEST_BYTES],
                    threshold: 1,
                    signer_count: 1,
                    approval_count: 0,
                    approved_slots: [false; 6],
                };
                witness.auth.next = witness.auth.current.clone();
                witness.auth.next.approval_count = 1;
                witness.auth.next.approved_slots[0] = true;
            }
            PrivateAuthMode::ValueLockCreation => {
                if witness.outputs[0].active {
                    witness.outputs[0].note.kind = NoteKind::ValueLock;
                }
                witness.auth.current = AccumulatorOpening {
                    policy_root: [0; DIGEST_BYTES],
                    intent_digest: [0; DIGEST_BYTES],
                    threshold: 1,
                    signer_count: 1,
                    approval_count: 0,
                    approved_slots: [false; 6],
                };
            }
            PrivateAuthMode::FinalThresholdSpend => {
                if witness.inputs[0].active {
                    witness.inputs[0].note.kind = NoteKind::ValueLock;
                    witness.inputs[0].spend_key = [0; 48];
                }
                if witness.inputs[1].active {
                    witness.inputs[1].note.kind = NoteKind::Accumulator;
                    witness.inputs[1].spend_key = [0; 48];
                }
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
            let policy_root = host_hash(
                profile,
                true,
                &host_policy_frame(selected, &witness.auth.signer_tags),
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
        set_mode_authorizations(profile, &mut witness);

        let mut statement = FullBlake2b448Statement {
            input_flags,
            output_flags,
            anchor: [0; DIGEST_BYTES],
            nullifiers: [[0; DIGEST_BYTES]; 2],
            commitments: [[0; DIGEST_BYTES]; 2],
            ciphertext_hashes: [[0; DIGEST_BYTES]; 2],
            ciphertext_sizes: output_flags.map(|active| {
                if active {
                    V6_CANONICAL_CIPHERTEXT_BYTES as u32
                } else {
                    0
                }
            }),
            balance_asset_ids: [0, u64::MAX, u64::MAX, u64::MAX],
            fee: 0,
            value_balance: SignedMagnitude::default(),
            stablecoin: StablecoinStatementBinding384 {
                enabled: false,
                asset_id: 0,
                policy_version: 0,
                issuance_delta: SignedMagnitude::default(),
                policy_hash: [0; scalar_candidate::LIVE_STABLECOIN_BINDING_BYTES],
                oracle_commitment: [0; scalar_candidate::LIVE_STABLECOIN_BINDING_BYTES],
                attestation_commitment: [0; scalar_candidate::LIVE_STABLECOIN_BINDING_BYTES],
            },
            balance_tag: [0; DIGEST_BYTES],
            activation: diagnostic_activation(),
        };

        refresh_fixture_public_bindings(profile, &mut statement, &mut witness);
        (statement, witness)
    }

    fn build_parity_fixture(
        profile: SecretHashProfile,
        mode: PrivateAuthMode,
        mask: u8,
    ) -> (FullBlake2b448Statement, FullShake448Witness) {
        let inputs = [mask & 1 != 0, mask & 2 != 0];
        let outputs = [mask & 4 != 0, mask & 8 != 0];
        assert!(candidate_activity_shape_accepts(mode, inputs, outputs));
        build_shape_fixture(profile, mode, mask)
    }

    #[test]
    fn exact_layout_and_fail_closed_flags() {
        assert_eq!(CANDIDATE_STATEMENT_BYTES, 869);
        assert_eq!(CANDIDATE_STATEMENT_WORDS, 109);
        assert_eq!(CIPHERTEXT_WORDS, 269);
        assert_eq!(CANDIDATE_PRIVATE_WORDS, 1_209);
        assert_eq!(CANDIDATE_PRIVATE_BYTES, 9_672);
        assert_ne!(DIAGNOSTIC_STATEMENT_MAGIC, *b"HGF6ST02");
        assert_ne!(CANDIDATE_FRAME_TAG, *b"HEG-F6V2");
        assert_eq!(WINNER, None);
        assert!(!PRODUCTION_AUTHORIZED);
        assert!(!IDENTITY_FROZEN);
        assert!(!COMPLETE_ZERO_KNOWLEDGE_PROVED);
        assert!(!COMPOSED_QROM_PQ128_PROVED);
        assert!(!E384_PCS_CHANNEL_INTEGRATED);
        assert!(!M4_AGGREGATE_RELATION_ARTIFACT_VERIFIED);
        assert!(ACTIVE_STABLECOIN_MANIFEST_ADAPTER_INTEGRATED);
        assert!(!ACTIVE_STABLECOIN_LIFECYCLE_CONSTRAINTS_COMPILED);
        assert!(!STRICT_STABLECOIN_PQ_MARGIN);
    }

    #[test]
    fn exact_dual_profile_call_and_core_schedules() {
        assert_eq!(physical_hash_calls(SecretHashProfile::Blake2b448Mixed), 83);
        assert_eq!(primitive_cores(SecretHashProfile::Blake2b448Mixed), 133);
        assert_eq!(
            physical_hash_calls(SecretHashProfile::Sha3_512SplitControl),
            83
        );
        assert_eq!(
            primitive_cores(SecretHashProfile::Sha3_512SplitControl),
            151
        );
        assert_eq!(
            raw_hash_and_words(SecretHashProfile::Blake2b448Mixed),
            79_128
        );
        assert_eq!(
            raw_hash_and_words(SecretHashProfile::Sha3_512SplitControl),
            90_600
        );
        assert_eq!(
            raw_hash_rotation_linear_words(SecretHashProfile::Blake2b448Mixed),
            10_752
        );
        assert_eq!(
            raw_hash_rotation_linear_words(SecretHashProfile::Sha3_512SplitControl),
            0
        );
        assert_eq!(
            raw_blake_addition_linear_words(SecretHashProfile::Blake2b448Mixed),
            16_128
        );
        assert_eq!(
            raw_blake_addition_linear_words(SecretHashProfile::Sha3_512SplitControl),
            0
        );
        let blake_static = source_static_constraint_ledger(SecretHashProfile::Blake2b448Mixed);
        let sha3_static = source_static_constraint_ledger(SecretHashProfile::Sha3_512SplitControl);
        assert_eq!(
            (
                blake_static.and_constraints,
                blake_static.linear_constraints,
                blake_static.bmul_constraints
            ),
            (79_128, 265_963, 452)
        );
        assert_eq!(
            (
                sha3_static.and_constraints,
                sha3_static.linear_constraints,
                sha3_static.bmul_constraints
            ),
            (90_600, 327_437, 444)
        );
        assert_eq!(
            sha3_static.and_constraints - blake_static.and_constraints,
            11_472
        );
        assert_eq!(
            sha3_static.linear_constraints - blake_static.linear_constraints,
            61_474
        );
        assert_eq!(
            blake_static.bmul_constraints - sha3_static.bmul_constraints,
            8
        );
        assert!(!blake_static.post_compiler_dce);
        assert!(!blake_static.includes_non_hash_relation);
        let mixed = role_registry(SecretHashProfile::Blake2b448Mixed);
        assert_eq!(mixed.iter().map(|role| role.calls).sum::<usize>(), 83);
        assert_eq!(
            mixed
                .iter()
                .filter(|role| role.algorithm == HashAlgorithm::Shake256_448)
                .map(|role| role.calls)
                .sum::<usize>(),
            68
        );
        assert_eq!(
            mixed
                .iter()
                .filter(|role| role.algorithm == HashAlgorithm::Blake2b448)
                .map(|role| role.calls * role.cores_per_call)
                .sum::<usize>(),
            28
        );
        for profile in [
            SecretHashProfile::Blake2b448Mixed,
            SecretHashProfile::Sha3_512SplitControl,
        ] {
            assert!(hash_invocation_registry_is_exact(profile));
            let invocations = hash_invocation_registry(profile);
            assert_eq!(invocations.len(), 83);
            assert!(invocations.iter().all(|call| call.source_bound));
            assert!(invocations.iter().all(|call| call.output_bound));
            assert_eq!(
                invocations
                    .iter()
                    .map(|call| call.primitive_cores)
                    .sum::<usize>(),
                primitive_cores(profile)
            );
            assert_eq!(invocations[0].role, ROLE_NOTE);
            assert_eq!(invocations[4].role, ROLE_NULLIFIER);
            assert_eq!(invocations[6].role, ROLE_MERKLE);
            assert_eq!(invocations[70].role, ROLE_SPEND_A);
            assert_eq!(invocations[72].role, ROLE_SPEND_B);
            assert_eq!(invocations[74].role, ROLE_POLICY);
            assert_eq!(invocations[75].role, ROLE_AUTH_A);
            assert_eq!(invocations[77].role, ROLE_AUTH_B);
            assert_eq!(invocations[79].role, ROLE_INTENT);
            assert_eq!(invocations[80].role, ROLE_BALANCE_TAG);
            assert_eq!(invocations[81].role, ROLE_CIPHERTEXT_HASH);
            assert_eq!(
                invocations[75].frame_width,
                CandidateFrameWidth::AuthorizationMux {
                    arm_bytes: [136, 181, 181, 143, 181]
                }
            );
            assert_eq!(
                invocations[76].frame_width,
                CandidateFrameWidth::AuthorizationMux {
                    arm_bytes: [136, 136, 181, 136, 143]
                }
            );
        }
    }

    #[test]
    fn stablecoin_compatibility_and_consensus_state_seam_widths_are_independent() {
        assert_eq!(
            ACTIVE_STABLECOIN_POLICY_TUPLE_COMPONENT_BYTES
                .into_iter()
                .sum::<usize>(),
            ACTIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES
        );
        assert_eq!(ACTIVE_STABLECOIN_POLICY_TUPLE_SCALE_BYTES, 61);
        assert_eq!(ACTIVE_STABLECOIN_POLICY_HASH_BYTES, 48);
        assert_eq!(ACTIVE_STABLECOIN_MANIFEST_COMMITMENT_BYTES, 48);
        assert_eq!(DIGEST_BYTES, 56);
        assert_eq!(LIVE_STABLECOIN_BINDING_WORDS, 6);
        assert_eq!(MANIFEST_STATE_COMMITMENT_V1_WORDS, 6);
        assert_eq!(CANDIDATE_STATEMENT_WORDS, 109);
        assert_eq!(CANDIDATE_CONSENSUS_STATE_WORDS, 50);
        assert_eq!(CANDIDATE_PUBLIC_WORDS, 159);
        assert_ne!(DIGEST_BYTES, ACTIVE_STABLECOIN_POLICY_HASH_BYTES);
        assert_eq!(
            ACTIVE_STABLECOIN_POLICY_DOMAIN,
            b"hegemon.kernel.stablecoin-policy.v2"
        );
        assert_eq!(
            ACTIVE_STABLECOIN_MANIFEST_STATE_DOMAIN,
            b"hegemon.kernel.stablecoin-manifest-state.v1"
        );
        assert_eq!(LOCAL_NON_HASH_CONSTRAINT_GROUPS.len(), 20);
        assert_eq!(HASH_LINK_CONSTRAINT_GROUPS.len(), 7);
        assert_eq!(CONSENSUS_STATE_SEAM_CONSTRAINT_GROUPS.len(), 9);
        assert_eq!(HOST_ORACLE_ONLY_GROUPS.len(), 4);
        assert_eq!(COUNTERFEIT_MUTATION_MATRIX.len(), 20);
        assert_eq!(
            COUNTERFEIT_MUTATION_MATRIX
                .iter()
                .filter(|case| case.disposition == CounterfeitDisposition::M4Reject)
                .count(),
            16
        );
        assert!(ACTIVE_STABLECOIN_MANIFEST_ADAPTER_INTEGRATED);
        assert!(!ACTIVE_STABLECOIN_LIFECYCLE_CONSTRAINTS_COMPILED);
        assert!(!ACTIVE_STABLECOIN_MANIFEST_MEMBERSHIP_GRAPH_COMPILED);
        assert!(!STRICT_STABLECOIN_PQ_MARGIN);
        assert!(!PRODUCTION_AUTHORIZED);
        assert!(!IDENTITY_FROZEN);
    }

    #[test]
    fn authorization_mux_is_fixed_five_arm_pre_hash_selection() {
        assert_eq!(authorization_arm_lengths(false), [136, 181, 181, 143, 181]);
        assert_eq!(authorization_arm_lengths(true), [136, 136, 181, 136, 143]);
        for lengths in [
            authorization_arm_lengths(false),
            authorization_arm_lengths(true),
        ] {
            assert!(lengths.into_iter().all(|len| len.div_ceil(128) == 2));
            assert!(lengths
                .into_iter()
                .all(|len| len / SHA3_512_RATE_BYTES + 1 <= 3));
        }
        assert_ne!(KEY_OUTPUT_LANE_A_TAG, KEY_OUTPUT_LANE_B_TAG);
    }

    #[test]
    fn all_sixteen_masks_times_five_modes_match_scalar_shape_oracle() {
        let scalar_source =
            include_str!("../../../../circuits/transaction/src/full_blake2b448_relation.rs");
        for required in [
            "input_nonempty && output_flags[0]",
            "PrivateAuthMode::ApprovalStep => both_inputs && output_flags[0]",
            "PrivateAuthMode::FinalThresholdSpend => both_inputs",
            "all-empty activity mask",
        ] {
            assert!(scalar_source.contains(required));
        }
        let modes = [
            PrivateAuthMode::SingleKey,
            PrivateAuthMode::AccumulatorInit,
            PrivateAuthMode::ApprovalStep,
            PrivateAuthMode::ValueLockCreation,
            PrivateAuthMode::FinalThresholdSpend,
        ];
        for mask in 0u8..16 {
            let inputs = [mask & 1 != 0, mask & 2 != 0];
            let outputs = [mask & 4 != 0, mask & 8 != 0];
            for mode in modes {
                let scalar_oracle = mask != 0
                    && match mode {
                        PrivateAuthMode::SingleKey => true,
                        PrivateAuthMode::AccumulatorInit | PrivateAuthMode::ValueLockCreation => {
                            inputs.into_iter().any(|active| active) && outputs[0]
                        }
                        PrivateAuthMode::ApprovalStep => inputs == [true, true] && outputs[0],
                        PrivateAuthMode::FinalThresholdSpend => inputs == [true, true],
                    };
                assert_eq!(
                    candidate_activity_shape_accepts(mode, inputs, outputs),
                    scalar_oracle,
                    "mask={mask:04b} mode={mode:?}"
                );
            }
        }
        assert!(!candidate_activity_shape_accepts(
            PrivateAuthMode::AccumulatorInit,
            [false, false],
            [true, false]
        ));
        assert!(!candidate_activity_shape_accepts(
            PrivateAuthMode::ValueLockCreation,
            [false, false],
            [true, false]
        ));
    }

    #[test]
    fn zero_intent_and_first_active_zero_signer_tag_match_scalar_edge() {
        let opening = AccumulatorOpening {
            policy_root: [0; DIGEST_BYTES],
            intent_digest: [0; DIGEST_BYTES],
            threshold: 1,
            signer_count: 1,
            approval_count: 0,
            approved_slots: [false; 6],
        };
        let tags = [[0; DIGEST_BYTES]; 6];
        assert!(candidate_accumulator_metadata_accepts(
            &opening,
            &tags,
            [0; DIGEST_BYTES],
            None
        ));
        let mut duplicate = opening.clone();
        duplicate.signer_count = 2;
        assert!(!candidate_accumulator_metadata_accepts(
            &duplicate,
            &tags,
            [0; DIGEST_BYTES],
            None
        ));
        let mut inactive_nonzero = tags;
        inactive_nonzero[1][0] = 1;
        assert!(!candidate_accumulator_metadata_accepts(
            &opening,
            &inactive_nonzero,
            [0; DIGEST_BYTES],
            None
        ));
    }

    #[test]
    fn rejected_v6_identities_cannot_be_diagnostic_authority() {
        for magic in REJECTED_IDENTITY_MAGICS {
            assert_ne!(magic, DIAGNOSTIC_STATEMENT_MAGIC);
            assert!(rejects_reserved_identity(&magic));
        }
        assert!(!rejects_reserved_identity(&DIAGNOSTIC_STATEMENT_MAGIC));
        let mut payload_occurrence = semantic_statement();
        payload_occurrence.balance_tag[..8].copy_from_slice(b"HGF6HR02");
        let encoded = encode_diagnostic_statement(&payload_occurrence, diagnostic_activation());
        assert_eq!(
            decode_diagnostic_activation(&encoded),
            Some(diagnostic_activation())
        );
        assert!(!rejects_reserved_identity(&encoded));
    }

    #[test]
    fn diagnostic_codec_roundtrips_exact_activation_offsets_and_mutations() {
        let activation = diagnostic_activation();
        let encoded = encode_diagnostic_statement(&semantic_statement(), activation);
        assert_eq!(&encoded[..8], &DIAGNOSTIC_STATEMENT_MAGIC);
        assert_eq!(&encoded[685..687], &0x4481u16.to_be_bytes());
        assert_eq!(&encoded[687..689], &0x4482u16.to_be_bytes());
        assert_eq!(&encoded[689..691], &0x4483u16.to_be_bytes());
        assert_eq!(&encoded[691..693], &0x4484u16.to_be_bytes());
        assert_eq!(&encoded[693..697], &0x0102_0304u32.to_be_bytes());
        assert_eq!(encoded[697], 0x45);
        assert_eq!(encoded[698], 0x46);
        assert_eq!(&encoded[699..701], &0x4487u16.to_be_bytes());
        assert_eq!(&encoded[701..757], &[0x11; 56]);
        assert_eq!(&encoded[757..813], &[0x22; 56]);
        assert_eq!(&encoded[813..869], &[0x33; 56]);
        assert_eq!(decode_diagnostic_activation(&encoded), Some(activation));

        for offset in OFFSET_ACTIVATION..CANDIDATE_STATEMENT_BYTES {
            let mut changed = encoded;
            changed[offset] ^= 1;
            assert_ne!(decode_diagnostic_activation(&changed), Some(activation));
        }
        let mut v6_magic = encoded;
        v6_magic[..8].copy_from_slice(b"HGF6ST02");
        assert_eq!(decode_diagnostic_activation(&v6_magic), None);

        let mut zero_network_statement = semantic_statement();
        zero_network_statement.activation.network_id = 0;
        let zero_network =
            encode_diagnostic_statement(&zero_network_statement, zero_network_statement.activation);
        assert_eq!(
            decode_diagnostic_activation(&zero_network),
            Some(zero_network_statement.activation)
        );
    }

    #[test]
    fn rfc7693_blake2b448_known_answers_cover_boundaries() {
        let vectors = [
            (
                0,
                "e7d2cb731e704ab61a3fa0ddd3bb3a6bfe3c3bc03b2c80a7545a0c9cedb575dfaa6821be9879e9ecd24350297f14470ad3d1cd2d19f27fbf",
            ),
            (
                127,
                "9f9715ce3ddf0dca587aca554c1c550f6285992131eb36cf7e413d09df7898a32b516b011ffb7f75b0bd86147d843c0837597f4f853f5acf",
            ),
            (
                128,
                "e86ac9582179a9ac3f19f7d83fcf52c996a15b4007143efa2e2985a9fc800b1c12331a670d8a7335a687de08caae1a0112befc6f6090e975",
            ),
            (
                129,
                "c2be04a246b254a9c297675857e5ff8225965227b95583c7f691b8a61ef848f4694f9c68e803bb04763ed858d648b00ec703690dcec121fe",
            ),
            (
                232,
                "f971a55a8bd5b3147333a155a69300930f47ab242d3b9690fe7a2bc76265a757b28ddb57f9ff31476c7079596cf7043375716e6fbce09977",
            ),
            (
                385,
                "2bf954a87eacb5a876231294263dc345b3fcc02d2e489e95be34a4dd631c9429779cda365d62363d70922d89bb124484c7ed8687bf1b60e3",
            ),
            (
                2_182,
                "6ce9f17639bcb6054ccac25aafc945016bbcce7df844a202f3839c7cd1ccac7d57c8a4a9bec6d77dcc84c8d5e94786c7c1fd12b0c9101779",
            ),
        ];
        for (len, expected) in vectors {
            assert_eq!(blake2b448(&patterned(len)), decode_hex::<56>(expected));
        }
        assert_eq!(
            blake2b448(b"abc"),
            decode_hex::<56>(
                "13ee23af59cf24b95795d6417d2592f96d772eb6c4866e51698ecf6d4848539251ae2ee731a28758ecbcd5cb5f3f005c202f509cc32975b1"
            )
        );
    }

    #[test]
    fn fips202_sha3_512_truncation_known_answers() {
        let empty = Sha3_512::digest(b"");
        let abc = Sha3_512::digest(b"abc");
        assert_eq!(
            &empty[..56],
            &decode_hex::<56>(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e3"
            )
        );
        assert_eq!(
            &abc[..56],
            &decode_hex::<56>(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5"
            )
        );
    }

    fn verify_small_m4_kat(profile: SecretHashProfile, message: &[u8], expected: [u8; 56]) -> bool {
        let builder = CircuitBuilder::new();
        let input: Vec<Wire> = (0..message.len().div_ceil(8))
            .map(|_| builder.add_witness())
            .collect();
        let frame = PackedFrame {
            words: input.clone(),
            len_bytes: message.len(),
        };
        let digest = secret_hash56(&builder, profile, &frame);
        for (index, expected_word) in expected.chunks_exact(8).enumerate() {
            builder.assert_eq(
                format!("kat.output[{index}]"),
                digest[index],
                builder.add_constant_64(u64::from_le_bytes(expected_word.try_into().unwrap())),
            );
        }
        let circuit = builder.build_m4();
        let witness = circuit
            .generate_witness(|filler| {
                for (index, &wire) in input.iter().enumerate() {
                    let mut word = [0u8; 8];
                    let start = index * 8;
                    let take = (message.len() - start).min(8);
                    word[..take].copy_from_slice(&message[start..start + take]);
                    filler[wire] = Word(u64::from_le_bytes(word));
                }
            })
            .unwrap();
        witness.verify(&circuit.to_constraint_system()).is_ok()
    }

    #[test]
    #[ignore = "requires the >=28 GiB circuit compile gate"]
    fn direct_m4_blake2b_and_sha3_known_answers_and_message_padding_mutations() {
        let blake_abc = decode_hex::<56>(
            "13ee23af59cf24b95795d6417d2592f96d772eb6c4866e51698ecf6d4848539251ae2ee731a28758ecbcd5cb5f3f005c202f509cc32975b1",
        );
        let sha3_abc = decode_hex::<56>(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a5",
        );
        assert!(verify_small_m4_kat(
            SecretHashProfile::Blake2b448Mixed,
            b"abc",
            blake_abc,
        ));
        assert!(verify_small_m4_kat(
            SecretHashProfile::Sha3_512SplitControl,
            b"abc",
            sha3_abc,
        ));
        assert!(!verify_small_m4_kat(
            SecretHashProfile::Blake2b448Mixed,
            b"abd",
            blake_abc,
        ));
        assert!(!verify_small_m4_kat(
            SecretHashProfile::Sha3_512SplitControl,
            b"ab",
            sha3_abc,
        ));
    }

    #[test]
    #[ignore = "requires the >=28 GiB full-circuit compile gate"]
    fn scalar_vs_m4_all_83_calls_all_modes_all_masks_and_mutations() {
        let profiles = [
            SecretHashProfile::Blake2b448Mixed,
            SecretHashProfile::Sha3_512SplitControl,
        ];
        let modes = [
            PrivateAuthMode::SingleKey,
            PrivateAuthMode::AccumulatorInit,
            PrivateAuthMode::ApprovalStep,
            PrivateAuthMode::ValueLockCreation,
            PrivateAuthMode::FinalThresholdSpend,
        ];
        for profile in profiles {
            let scalar_profile = match profile {
                SecretHashProfile::Blake2b448Mixed => {
                    scalar_candidate::SecretHashProfile::UnkeyedBlake2b448
                }
                SecretHashProfile::Sha3_512SplitControl => {
                    scalar_candidate::SecretHashProfile::SplitSha3_512Truncated448
                }
            };
            let candidate = build_candidate_m4(profile, diagnostic_activation());
            candidate
                .hash_lowering_coverage()
                .ensure_complete()
                .unwrap();
            let m4_specs = hash_invocation_registry(profile);
            let cs = candidate.constraint_system();
            let mut exercised = 0usize;
            for mask in 0u8..16 {
                let inputs = [mask & 1 != 0, mask & 2 != 0];
                let outputs = [mask & 4 != 0, mask & 8 != 0];
                for mode in modes {
                    if !candidate_activity_shape_accepts(mode, inputs, outputs) {
                        continue;
                    }
                    let (statement, witness) = build_parity_fixture(profile, mode, mask);
                    let encoded = encode_diagnostic_statement(&statement, statement.activation);
                    let scalar = scalar_candidate::compile_full_blake2b448_candidate(
                        scalar_profile,
                        &statement,
                        &witness,
                        statement.activation,
                    )
                    .unwrap();
                    let (host_frames, host_digests) =
                        host_call_inventory(profile, &statement, &witness);
                    assert_eq!(scalar.hash_calls().len(), 83);
                    assert_eq!(host_frames.len(), 83);
                    assert_eq!(host_digests.len(), 83);
                    for call in scalar.hash_calls() {
                        let scalar_spec = scalar_candidate::exact_call_spec(
                            scalar_profile,
                            call.index,
                            &statement,
                            &witness,
                        )
                        .unwrap();
                        call.verify_against_spec(&scalar_spec).unwrap();
                        let m4_spec = m4_specs[call.index];
                        let algorithm_matches = matches!(
                            (m4_spec.algorithm, scalar_spec.algorithm),
                            (
                                HashAlgorithm::Blake2b448,
                                scalar_candidate::CandidateHashAlgorithm::Blake2b448
                            ) | (
                                HashAlgorithm::Sha3_512Truncated448,
                                scalar_candidate::CandidateHashAlgorithm::Sha3_512Truncated448
                            ) | (
                                HashAlgorithm::Shake256_448,
                                scalar_candidate::CandidateHashAlgorithm::Shake256_448
                            )
                        );
                        let binding_matches = matches!(
                            (m4_spec.binding, scalar_spec.binding),
                            (
                                CandidateOutputBinding::Internal,
                                scalar_candidate::OutputBinding::Internal
                            ) | (
                                CandidateOutputBinding::PublicAlways,
                                scalar_candidate::OutputBinding::PublicAlways
                            ) | (
                                CandidateOutputBinding::PublicWhenInputActive(0),
                                scalar_candidate::OutputBinding::PublicWhenInputActive(0)
                            ) | (
                                CandidateOutputBinding::PublicWhenInputActive(1),
                                scalar_candidate::OutputBinding::PublicWhenInputActive(1)
                            ) | (
                                CandidateOutputBinding::PublicWhenOutputActive(0),
                                scalar_candidate::OutputBinding::PublicWhenOutputActive(0)
                            ) | (
                                CandidateOutputBinding::PublicWhenOutputActive(1),
                                scalar_candidate::OutputBinding::PublicWhenOutputActive(1)
                            )
                        );
                        let width_matches = match m4_spec.frame_width {
                            CandidateFrameWidth::Exact(bytes) => {
                                !scalar_spec.fixed_authorization_mux
                                    && bytes == scalar_spec.exact_frame_bytes
                            }
                            CandidateFrameWidth::AuthorizationMux { arm_bytes } => {
                                let selected = match mode {
                                    PrivateAuthMode::SingleKey => 0,
                                    PrivateAuthMode::AccumulatorInit => 1,
                                    PrivateAuthMode::ApprovalStep => 2,
                                    PrivateAuthMode::ValueLockCreation => 3,
                                    PrivateAuthMode::FinalThresholdSpend => 4,
                                };
                                scalar_spec.fixed_authorization_mux
                                    && arm_bytes[selected] == scalar_spec.exact_frame_bytes
                            }
                        };
                        assert!(algorithm_matches);
                        assert!(binding_matches);
                        assert!(width_matches);
                        assert_eq!(m4_spec.role, scalar_spec.role);
                        assert_eq!(m4_spec.index, scalar_spec.index);
                        assert_eq!(
                            m4_spec.primitive_cores,
                            scalar_spec.blake_compressions + scalar_spec.keccak_permutations
                        );
                        assert_eq!(
                            host_frames[call.index], call.frame.bytes,
                            "frame index={} mask={mask:04b} mode={mode:?} profile={profile:?}",
                            call.index
                        );
                        assert_eq!(
                            host_digests[call.index], call.digest,
                            "digest index={} mask={mask:04b} mode={mode:?} profile={profile:?}",
                            call.index
                        );
                        let mut mutated_frame = host_frames[call.index].clone();
                        let mutation = mutated_frame.len() - 1;
                        mutated_frame[mutation] ^= 1;
                        let secret = m4_spec.algorithm != HashAlgorithm::Shake256_448;
                        assert_ne!(
                            host_hash(profile, secret, &mutated_frame),
                            host_digests[call.index],
                            "one-byte frame mutation index={}",
                            call.index
                        );
                    }
                    for lane in 0..2 {
                        for slot in 0..2 {
                            let index = if lane == 0 {
                                scalar_candidate::AUTH_A_CALL_START + slot
                            } else {
                                scalar_candidate::AUTH_B_CALL_START + slot
                            };
                            let scalar_arms = scalar.hash_calls()[index]
                                .authorization_arms
                                .as_ref()
                                .unwrap();
                            let host_arms = host_authorization_arms(&witness, slot, lane);
                            for arm in 0..5 {
                                assert_eq!(host_arms[arm], scalar_arms[arm].bytes);
                            }
                        }
                    }
                    let m4_witness = candidate.generate_witness(&encoded, &witness).unwrap();
                    m4_witness.verify(&cs).unwrap();

                    let mut public_mutation = encoded;
                    public_mutation[OFFSET_BALANCE_TAG] ^= 1;
                    let bad_public = candidate
                        .generate_witness(&public_mutation, &witness)
                        .unwrap();
                    assert!(bad_public.verify(&cs).is_err());
                    let mut source_mutation = witness.clone();
                    if let Some(input) =
                        source_mutation.inputs.iter_mut().find(|input| input.active)
                    {
                        input.note.rho[0] ^= 1;
                        let bad_source = candidate
                            .generate_witness(&encoded, &source_mutation)
                            .unwrap();
                        assert!(bad_source.verify(&cs).is_err());
                    }
                    if matches!(
                        mode,
                        PrivateAuthMode::AccumulatorInit
                            | PrivateAuthMode::ApprovalStep
                            | PrivateAuthMode::ValueLockCreation
                    ) {
                        assert_eq!(witness.auth.current.intent_digest, [0; DIGEST_BYTES]);
                    }
                    if matches!(
                        mode,
                        PrivateAuthMode::AccumulatorInit
                            | PrivateAuthMode::ValueLockCreation
                            | PrivateAuthMode::FinalThresholdSpend
                    ) {
                        assert_eq!(witness.auth.signer_tags[0], [0; DIGEST_BYTES]);
                    }
                    exercised += 1;
                }
            }
            assert_eq!(exercised, 33);

            // Ordinary non-native conservation remains valid with the
            // stablecoin authority uniquely disabled.
            let (mut ordinary_statement, mut ordinary_witness) =
                build_parity_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            ordinary_statement.balance_asset_ids = [0, 7, u64::MAX, u64::MAX];
            ordinary_witness.inputs[0].note.asset_id = 7;
            ordinary_witness.inputs[0].note.value = 5;
            ordinary_witness.inputs[0].balance_slot_selectors = [false, true, false, false];
            ordinary_witness.outputs[0].note.asset_id = 7;
            ordinary_witness.outputs[0].note.value = 5;
            ordinary_witness.outputs[0].balance_slot_selectors = [false, true, false, false];
            refresh_fixture_public_bindings(
                profile,
                &mut ordinary_statement,
                &mut ordinary_witness,
            );
            scalar_candidate::compile_full_blake2b448_candidate(
                scalar_profile,
                &ordinary_statement,
                &ordinary_witness,
                ordinary_statement.activation,
            )
            .unwrap();
            let ordinary_encoded =
                encode_diagnostic_statement(&ordinary_statement, ordinary_statement.activation);
            candidate
                .generate_witness(&ordinary_encoded, &ordinary_witness)
                .unwrap()
                .verify(&cs)
                .unwrap();

            // Enabled burn: public input exceeds output by the exact positive
            // issuance delta and the scalar side consumes a current live view.
            let (mut burn_statement, mut burn_witness) =
                build_parity_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            burn_statement.balance_asset_ids = [0, 7, u64::MAX, u64::MAX];
            burn_witness.inputs[0].note.asset_id = 7;
            burn_witness.inputs[0].note.value = 5;
            burn_witness.inputs[0].balance_slot_selectors = [false, true, false, false];
            burn_witness.outputs[0].note.asset_id = 7;
            burn_witness.outputs[0].note.value = 2;
            burn_witness.outputs[0].balance_slot_selectors = [false, true, false, false];
            let burn_entry = install_live_stablecoin_binding(
                &mut burn_statement,
                SignedMagnitude {
                    negative: false,
                    magnitude: 3,
                },
            );
            let burn_manifest = protocol_manifest_with_policies(vec![burn_entry]);
            refresh_fixture_public_bindings(profile, &mut burn_statement, &mut burn_witness);
            scalar_candidate::compile_full_blake2b448_candidate_with_stablecoin_protocol_manifest(
                scalar_profile,
                &burn_statement,
                &burn_witness,
                burn_statement.activation,
                20,
                &burn_manifest,
            )
            .unwrap();
            let burn_encoded =
                encode_diagnostic_statement(&burn_statement, burn_statement.activation);
            let burn_state = consensus_state_for_manifest(&burn_statement, &burn_manifest, 20);
            candidate
                .generate_witness_with_consensus_state(&burn_encoded, &burn_witness, &burn_state)
                .unwrap()
                .verify(&cs)
                .unwrap();

            // Enabled mint: output-only value equals the magnitude of the
            // exact negative issuance delta under the same external view.
            let (mut mint_statement, mut mint_witness) =
                build_parity_fixture(profile, PrivateAuthMode::SingleKey, 0b0100);
            mint_statement.balance_asset_ids = [0, 7, u64::MAX, u64::MAX];
            mint_witness.outputs[0].note.asset_id = 7;
            mint_witness.outputs[0].note.value = 4;
            mint_witness.outputs[0].balance_slot_selectors = [false, true, false, false];
            let mint_entry = install_live_stablecoin_binding(
                &mut mint_statement,
                SignedMagnitude {
                    negative: true,
                    magnitude: 4,
                },
            );
            let mint_manifest = protocol_manifest_with_policies(vec![mint_entry]);
            refresh_fixture_public_bindings(profile, &mut mint_statement, &mut mint_witness);
            scalar_candidate::compile_full_blake2b448_candidate_with_stablecoin_protocol_manifest(
                scalar_profile,
                &mint_statement,
                &mint_witness,
                mint_statement.activation,
                20,
                &mint_manifest,
            )
            .unwrap();
            let mint_encoded =
                encode_diagnostic_statement(&mint_statement, mint_statement.activation);
            let mint_state = consensus_state_for_manifest(&mint_statement, &mint_manifest, 20);
            candidate
                .generate_witness_with_consensus_state(&mint_encoded, &mint_witness, &mint_state)
                .unwrap()
                .verify(&cs)
                .unwrap();

            let (mut signed_statement, mut signed_witness) =
                build_parity_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
            signed_witness.inputs[0].note.value = 5;
            signed_witness.outputs[0].note.value = 2;
            signed_statement.fee = 1;
            signed_statement.value_balance = SignedMagnitude {
                negative: true,
                magnitude: 2,
            };
            refresh_fixture_public_bindings(profile, &mut signed_statement, &mut signed_witness);
            scalar_candidate::compile_full_blake2b448_candidate(
                scalar_profile,
                &signed_statement,
                &signed_witness,
                signed_statement.activation,
            )
            .unwrap();
            let signed_encoded =
                encode_diagnostic_statement(&signed_statement, signed_statement.activation);
            candidate
                .generate_witness(&signed_encoded, &signed_witness)
                .unwrap()
                .verify(&cs)
                .unwrap();

            let mut bad_signed_statement = signed_statement.clone();
            bad_signed_statement.value_balance.magnitude ^= 1;
            refresh_fixture_public_bindings(
                profile,
                &mut bad_signed_statement,
                &mut signed_witness,
            );
            assert!(scalar_candidate::compile_full_blake2b448_candidate(
                scalar_profile,
                &bad_signed_statement,
                &signed_witness,
                bad_signed_statement.activation,
            )
            .is_err());
        }
    }

    #[test]
    #[ignore = "requires the >=28 GiB full-circuit compile gate"]
    fn scalar_and_m4_reject_all_47_invalid_mask_mode_pairs_per_profile() {
        let profiles = [
            SecretHashProfile::Blake2b448Mixed,
            SecretHashProfile::Sha3_512SplitControl,
        ];
        let modes = [
            PrivateAuthMode::SingleKey,
            PrivateAuthMode::AccumulatorInit,
            PrivateAuthMode::ApprovalStep,
            PrivateAuthMode::ValueLockCreation,
            PrivateAuthMode::FinalThresholdSpend,
        ];
        for profile in profiles {
            let scalar_profile = match profile {
                SecretHashProfile::Blake2b448Mixed => {
                    scalar_candidate::SecretHashProfile::UnkeyedBlake2b448
                }
                SecretHashProfile::Sha3_512SplitControl => {
                    scalar_candidate::SecretHashProfile::SplitSha3_512Truncated448
                }
            };
            let candidate = build_candidate_m4(profile, diagnostic_activation());
            let cs = candidate.constraint_system();
            let mut rejected = 0usize;
            for mask in 0u8..16 {
                let inputs = [mask & 1 != 0, mask & 2 != 0];
                let outputs = [mask & 4 != 0, mask & 8 != 0];
                for mode in modes {
                    if candidate_activity_shape_accepts(mode, inputs, outputs) {
                        continue;
                    }
                    let (statement, witness) = build_shape_fixture(profile, mode, mask);
                    assert_eq!(witness.inputs.each_ref().map(|input| input.active), inputs);
                    assert_eq!(
                        witness.outputs.each_ref().map(|output| output.active),
                        outputs
                    );
                    assert!(scalar_candidate::compile_full_blake2b448_candidate(
                        scalar_profile,
                        &statement,
                        &witness,
                        statement.activation,
                    )
                    .is_err());
                    let encoded = encode_diagnostic_statement(&statement, statement.activation);
                    let m4_witness = candidate.generate_witness(&encoded, &witness).unwrap();
                    assert!(m4_witness.verify(&cs).is_err());
                    rejected += 1;
                }
            }
            assert_eq!(rejected, 47);
        }
    }

    #[test]
    #[ignore = "requires the >=28 GiB full-circuit compile gate"]
    fn typed_transport_and_absent_live_predicate_edges_fail_or_accept_exactly() {
        let profile = SecretHashProfile::Blake2b448Mixed;
        let (statement, witness) =
            build_parity_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
        let encoded = encode_diagnostic_statement(&statement, statement.activation);
        let candidate = build_candidate_m4(profile, statement.activation);

        let mut mismatched = witness.clone();
        mismatched.inputs[0].active = false;
        assert!(matches!(
            candidate.generate_witness(&encoded, &mismatched),
            Err(CandidateWitnessError::ActivityFlagsMismatch)
        ));
        let mut wrong_magic = encoded;
        wrong_magic[..8].copy_from_slice(b"HGF6ST02");
        assert!(matches!(
            candidate.generate_witness(&wrong_magic, &witness),
            Err(CandidateWitnessError::StatementCodec)
        ));

        let mut zero_ciphertext_digest = statement.clone();
        zero_ciphertext_digest.ciphertext_hashes[0] = [0; DIGEST_BYTES];
        assert!(scalar_candidate::validate_composed_admission_preconditions(
            &zero_ciphertext_digest
        )
        .is_ok());
        let zero_encoded =
            encode_diagnostic_statement(&zero_ciphertext_digest, statement.activation);
        let zero_witness = candidate.generate_witness(&zero_encoded, &witness).unwrap();
        assert!(zero_witness.verify(&candidate.constraint_system()).is_err());
    }

    #[test]
    #[ignore = "requires the >=28 GiB full-circuit compile gate"]
    fn consensus_state_seam_counterfeit_matrix_is_fail_closed_at_its_exact_boundary() {
        let profile = SecretHashProfile::Blake2b448Mixed;
        let (mut statement, mut witness) =
            build_parity_fixture(profile, PrivateAuthMode::SingleKey, 0b0101);
        statement.balance_asset_ids = [0, 7, u64::MAX, u64::MAX];
        witness.inputs[0].note.asset_id = 7;
        witness.inputs[0].note.value = 5;
        witness.inputs[0].balance_slot_selectors = [false, true, false, false];
        witness.outputs[0].note.asset_id = 7;
        witness.outputs[0].note.value = 2;
        witness.outputs[0].balance_slot_selectors = [false, true, false, false];
        let entry = install_live_stablecoin_binding(
            &mut statement,
            SignedMagnitude {
                negative: false,
                magnitude: 3,
            },
        );
        let manifest = protocol_manifest_with_policies(vec![entry]);
        refresh_fixture_public_bindings(profile, &mut statement, &mut witness);
        let encoded = encode_diagnostic_statement(&statement, statement.activation);
        let state = consensus_state_for_manifest(&statement, &manifest, 20);
        let authority =
            scalar_candidate::StablecoinAuthority::try_from_statement(&statement).unwrap();
        scalar_candidate::validate_stablecoin_consensus_state_seam(authority, &state).unwrap();

        let candidate = build_candidate_m4(profile, statement.activation);
        let cs = candidate.constraint_system();
        assert!(matches!(
            candidate.generate_witness(&encoded, &witness),
            Err(CandidateWitnessError::ConsensusStateRequired)
        ));
        candidate
            .generate_witness_with_consensus_state(&encoded, &witness, &state)
            .unwrap()
            .verify(&cs)
            .unwrap();
        let rejects = |candidate_state: &StablecoinConsensusStateSeam| {
            candidate
                .generate_witness_with_consensus_state(&encoded, &witness, candidate_state)
                .unwrap()
                .verify(&cs)
                .is_err()
        };

        let mut wrong_version = state.clone();
        wrong_version.seam_version ^= 1;
        assert!(rejects(&wrong_version));
        let mut zero_commitment = state.clone();
        zero_commitment.expected_manifest_state_commitment_v1 =
            protocol_kernel::stablecoin_manifest_commitment_v1::
                StablecoinManifestStateCommitmentV1::ZERO;
        assert!(rejects(&zero_commitment));
        let mut root_mismatch = state.clone();
        let mut mismatched_root = root_mismatch
            .provided_manifest_state_commitment_v1
            .into_bytes();
        mismatched_root[0] ^= 1;
        root_mismatch.provided_manifest_state_commitment_v1 =
            protocol_kernel::stablecoin_manifest_commitment_v1::
                StablecoinManifestStateCommitmentV1::new(mismatched_root);
        assert!(rejects(&root_mismatch));
        let mut height_mismatch = state.clone();
        height_mismatch.provided_current_height ^= 1;
        assert!(rejects(&height_mismatch));
        let mut missing_entry = state.clone();
        missing_entry.entry = None;
        assert!(rejects(&missing_entry));
        let mut wrong_asset = state.clone();
        wrong_asset.entry.as_mut().unwrap().asset_id ^= 1;
        assert!(rejects(&wrong_asset));
        let mut inactive = state.clone();
        inactive.entry.as_mut().unwrap().active = false;
        assert!(rejects(&inactive));
        let mut before_enable = state.clone();
        before_enable.entry.as_mut().unwrap().enabled_at = 21;
        assert!(rejects(&before_enable));
        let mut retired = state.clone();
        retired.entry.as_mut().unwrap().retired_at = Some(20);
        assert!(rejects(&retired));
        let mut future_oracle = state.clone();
        future_oracle.entry.as_mut().unwrap().oracle_submitted_at = 21;
        assert!(rejects(&future_oracle));
        let mut stale_oracle = state.clone();
        stale_oracle.entry.as_mut().unwrap().oracle_submitted_at = 0;
        stale_oracle.entry.as_mut().unwrap().oracle_max_age = 19;
        assert!(rejects(&stale_oracle));
        let mut disputed = state.clone();
        disputed.entry.as_mut().unwrap().attestation_disputed = true;
        assert!(rejects(&disputed));
        let mut capped = state.clone();
        capped.entry.as_mut().unwrap().max_mint_per_epoch = 2;
        assert!(rejects(&capped));

        // Exact boundary evidence: equality alone cannot authenticate what the
        // verifier supplies as the expected consensus root/height, and the flat
        // root has no selected-index membership graph in this relation.
        let mut forged_equal_roots = state.clone();
        let mut forged_root = forged_equal_roots
            .expected_manifest_state_commitment_v1
            .into_bytes();
        forged_root[0] ^= 1;
        let forged_root = protocol_kernel::stablecoin_manifest_commitment_v1::
            StablecoinManifestStateCommitmentV1::new(forged_root);
        forged_equal_roots.expected_manifest_state_commitment_v1 = forged_root;
        forged_equal_roots.provided_manifest_state_commitment_v1 = forged_root;
        candidate
            .generate_witness_with_consensus_state(&encoded, &witness, &forged_equal_roots)
            .unwrap()
            .verify(&cs)
            .unwrap();
        let mut forged_equal_height = state.clone();
        forged_equal_height.expected_current_height = 21;
        forged_equal_height.provided_current_height = 21;
        candidate
            .generate_witness_with_consensus_state(&encoded, &witness, &forged_equal_height)
            .unwrap()
            .verify(&cs)
            .unwrap();
        let mut forged_entry_index = state;
        forged_entry_index.entry_index = 1;
        candidate
            .generate_witness_with_consensus_state(&encoded, &witness, &forged_entry_index)
            .unwrap()
            .verify(&cs)
            .unwrap();
    }

    #[test]
    fn program_and_source_digests_are_profile_bound() {
        let source = source_digest();
        assert_ne!(source, [0; 64]);
        let activation = diagnostic_activation();
        let blake = program_digest(SecretHashProfile::Blake2b448Mixed, activation);
        let sha3 = program_digest(SecretHashProfile::Sha3_512SplitControl, activation);
        assert_ne!(blake, sha3);
        let mut other_activation = activation;
        other_activation.network_id ^= 1;
        assert_ne!(
            blake,
            program_digest(SecretHashProfile::Blake2b448Mixed, other_activation)
        );
        assert_ne!(blake, [0; 64]);
        assert_eq!(core::mem::size_of::<B128>(), 16);
        assert_eq!(core::mem::size_of::<E384>(), 48);
    }
}
