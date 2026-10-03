//! Canonical public boundary for the mixed SHAKE512-448/SHAKE256-448
//! transaction relation.
//!
//! This module is the sole owner of the fresh V6/Epsilon statement grammar,
//! relation domains, route identifiers, and lossless byte-to-Goldilocks
//! projection.  The canonical 893 bytes are always the authority.  Projection
//! groups those bytes into 128 consecutive seven-byte little-endian limbs;
//! there is no modular reduction and no verifier-supplied intent suffix.
//! `intent.1`, `bal.tag1`, and both `ct.hash1` invocations are constrained
//! inside the qualifying 145-permutation relation.

#![forbid(unsafe_code)]

use hegemon_hash448::CiphertextHash56;
use sha2::{Digest as ShaDigest, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update as XofUpdate, XofReader},
    Shake256,
};
use thiserror::Error;

pub use protocol_versioning::{
    CIRCUIT_V6 as V6_CIRCUIT_VERSION, CRYPTO_SUITE_EPSILON as V6_CRYPTO_SUITE,
};

pub const V6_STATEMENT_MAGIC: [u8; 8] = *b"HGF6ST02";
pub const V6_STATEMENT_GRAMMAR_VERSION: u16 = 2;
pub const V6_FAMILY_ID: u16 = 1;
pub const V6_ACTION_ID: u16 = 8;
pub const V6_BACKEND_ID: u8 = 2;
pub const V6_PROOF_PROFILE: u8 = 3;
pub const V6_DOMAIN_SET: u16 = 2;

pub const V6_MAX_INPUTS: usize = 2;
pub const V6_MAX_OUTPUTS: usize = 2;
pub const V6_BALANCE_SLOTS: usize = 4;
pub const V6_DIGEST_BYTES: usize = 56;
pub const V6_STATEMENT_BYTES: usize = 893;
pub const V6_STATEMENT_LIMB_BYTES: usize = 7;
pub const V6_STATEMENT_LIMBS: usize = V6_STATEMENT_BYTES.div_ceil(V6_STATEMENT_LIMB_BYTES);
pub const V6_PUBLIC_VALUES: usize = V6_STATEMENT_LIMBS;
pub const V6_CANONICAL_CIPHERTEXT_BYTES: usize = 2_147;
pub const V6_MAX_NOTE_VALUE: u64 = (1u64 << 61) - 1;
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// The qualifying relation constrains all 75 private-dependent invocations,
/// `intent.1`, `bal.tag1`, and two fixed 2,182-byte `ct.hash1` frames: 79 SHAKE
/// invocations and 145 Keccak-f calls under the typed algorithm registry.
pub const V6_FULL_RELATION_SHAKE_INVOCATIONS: usize = 79;
pub const V6_FULL_RELATION_KECCAK_PERMUTATIONS: usize = 145;

pub const V6_PROFILE_TAG: [u8; 8] = *b"HEG-F6V2";
pub const ROLE_NOTE_COMMITMENT: [u8; 8] = *b"note.cm3";
pub const ROLE_NULLIFIER: [u8; 8] = *b"nullif.2";
pub const ROLE_MERKLE_NODE: [u8; 8] = *b"merk.nd2";
pub const ROLE_SPEND_KEYS: [u8; 8] = *b"sp.keys2";
pub const ROLE_POLICY: [u8; 8] = *b"policy.1";
pub const ROLE_ACCUMULATOR: [u8; 8] = *b"accum.01";
pub const ROLE_VALUE_LOCK: [u8; 8] = *b"val.lock";
pub const ROLE_INTENT: [u8; 8] = *b"intent.1";
pub const ROLE_BALANCE_TAG: [u8; 8] = *b"bal.tag1";
pub const ROLE_CIPHERTEXT_HASH: [u8; 8] = *b"ct.hash1";
pub const ROLE_AUTH_MUX: [u8; 8] = *b"auth.mux";
pub const KEY_OUTPUT_ORDER_TAG: [u8; 8] = *b"auth.nf1";

pub const V6_SEMANTIC_BINDING_TAGS: [[u8; 8]; 11] = [
    V6_PROFILE_TAG,
    ROLE_NOTE_COMMITMENT,
    ROLE_NULLIFIER,
    ROLE_MERKLE_NODE,
    ROLE_SPEND_KEYS,
    ROLE_POLICY,
    ROLE_ACCUMULATOR,
    ROLE_VALUE_LOCK,
    ROLE_INTENT,
    ROLE_BALANCE_TAG,
    ROLE_CIPHERTEXT_HASH,
];

/// Security purpose assigned to a relation hash role. The numeric tag is part
/// of `HGF6HR02` and must never be inferred from a function name.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V6HashPurpose {
    CollisionBinding = 1,
    PreimageBinding = 2,
    PrfKdf = 3,
}

/// Conventional hash/XOF selected for a relation role. Both variants emit the
/// same 56-byte public digest; their Keccak capacities and rates differ.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V6HashAlgorithm {
    Shake256Output448 = 1,
    Shake512Output448 = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V6HashRoleSpec {
    pub role: [u8; 8],
    pub purpose: V6HashPurpose,
    pub algorithm: V6HashAlgorithm,
    pub invocations: u16,
    pub max_frame_bytes: u32,
    pub output_bytes: u16,
    pub rate_bytes: u16,
    pub permutations_per_call: u16,
}

pub const V6_HASH_ROLE_REGISTRY_MAGIC: [u8; 8] = *b"HGF6HR02";
/// First serialization grammar under the successor `HGF6HR02` identity.
pub const V6_HASH_ROLE_REGISTRY_VERSION: u16 = 1;
pub const V6_HASH_ROLE_REGISTRY_BYTES: usize = 214;
pub const V6_HASH_ROLE_REGISTRY: [V6HashRoleSpec; 9] = [
    V6HashRoleSpec {
        role: ROLE_NOTE_COMMITMENT,
        purpose: V6HashPurpose::PreimageBinding,
        algorithm: V6HashAlgorithm::Shake512Output448,
        invocations: 4,
        max_frame_bytes: 232,
        output_bytes: 56,
        rate_bytes: 72,
        permutations_per_call: 4,
    },
    V6HashRoleSpec {
        role: ROLE_NULLIFIER,
        purpose: V6HashPurpose::PrfKdf,
        algorithm: V6HashAlgorithm::Shake512Output448,
        invocations: 2,
        max_frame_bytes: 135,
        output_bytes: 56,
        rate_bytes: 72,
        permutations_per_call: 2,
    },
    V6HashRoleSpec {
        role: ROLE_MERKLE_NODE,
        purpose: V6HashPurpose::CollisionBinding,
        algorithm: V6HashAlgorithm::Shake256Output448,
        invocations: 64,
        max_frame_bytes: 133,
        output_bytes: 56,
        rate_bytes: 136,
        permutations_per_call: 1,
    },
    V6HashRoleSpec {
        role: ROLE_SPEND_KEYS,
        purpose: V6HashPurpose::PrfKdf,
        algorithm: V6HashAlgorithm::Shake512Output448,
        invocations: 2,
        max_frame_bytes: 77,
        output_bytes: 112,
        rate_bytes: 72,
        permutations_per_call: 3,
    },
    V6HashRoleSpec {
        role: ROLE_POLICY,
        purpose: V6HashPurpose::PreimageBinding,
        algorithm: V6HashAlgorithm::Shake512Output448,
        invocations: 1,
        max_frame_bytes: 385,
        output_bytes: 56,
        rate_bytes: 72,
        permutations_per_call: 6,
    },
    V6HashRoleSpec {
        role: ROLE_AUTH_MUX,
        purpose: V6HashPurpose::PrfKdf,
        algorithm: V6HashAlgorithm::Shake512Output448,
        invocations: 2,
        max_frame_bytes: 181,
        output_bytes: 112,
        rate_bytes: 72,
        permutations_per_call: 4,
    },
    V6HashRoleSpec {
        role: ROLE_INTENT,
        purpose: V6HashPurpose::CollisionBinding,
        algorithm: V6HashAlgorithm::Shake256Output448,
        invocations: 1,
        max_frame_bytes: 744,
        output_bytes: 56,
        rate_bytes: 136,
        permutations_per_call: 6,
    },
    V6HashRoleSpec {
        role: ROLE_BALANCE_TAG,
        purpose: V6HashPurpose::CollisionBinding,
        algorithm: V6HashAlgorithm::Shake256Output448,
        invocations: 1,
        max_frame_bytes: 100,
        output_bytes: 56,
        rate_bytes: 136,
        permutations_per_call: 1,
    },
    V6HashRoleSpec {
        role: ROLE_CIPHERTEXT_HASH,
        purpose: V6HashPurpose::CollisionBinding,
        algorithm: V6HashAlgorithm::Shake256Output448,
        invocations: 2,
        max_frame_bytes: 2_182,
        output_bytes: 56,
        rate_bytes: 136,
        permutations_per_call: 17,
    },
];

/// Raw SHA-512 of the exact 214-byte `HGF6HR02` registry. The magic is the
/// registry's own typed domain; no hidden prefix, suffix, or NUL is absorbed.
pub const V6_HASH_ROLE_REGISTRY_DIGEST: [u8; 64] = [
    0x84, 0x0e, 0x44, 0x26, 0xab, 0x9b, 0x8b, 0x74, 0xe6, 0x40, 0x0f, 0x45, 0x73, 0x10, 0x9d, 0xb0,
    0xb2, 0x32, 0x4d, 0xf6, 0xb2, 0xfd, 0x81, 0xa8, 0x1f, 0x24, 0xc2, 0xcc, 0x80, 0x1d, 0xd0, 0x76,
    0x7b, 0x8c, 0xaa, 0xa2, 0xa5, 0x8e, 0x21, 0x9d, 0xb3, 0xf0, 0xe9, 0x04, 0x94, 0xd2, 0x31, 0x2e,
    0x39, 0xfc, 0x83, 0x64, 0x2d, 0x21, 0xb8, 0x1a, 0x6b, 0xec, 0xdf, 0x33, 0x73, 0xa1, 0x96, 0x31,
];

/// Fresh proof domains.  Profile 3 requires a DECS evaluation coset disjoint
/// from every LVCS coordinate; it must never alias the historical radix-2
/// subgroup domain.
pub const V6_PROOF_BINDING_DOMAIN: &[u8] = b"hegemon.smallwood.v6-epsilon.inline-proof.sha512.v2\0";
pub const V6_TRANSCRIPT_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.v6-epsilon.sha512.f64-xof.v2";
pub const V6_TRANSCRIPT_COMPRESS2_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.f64-compress2.v2";
pub const V6_TRANSCRIPT_PIOP_INPUT_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.piop-input.v2";
pub const V6_TRANSCRIPT_PIOP_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.piop-transcript.v2";
pub const V6_TRANSCRIPT_DECS_OPENING_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.decs-opening.v2";
pub const V6_TRANSCRIPT_MERKLE_LEAF_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.merkle-leaf.v2";
pub const V6_TRANSCRIPT_MERKLE_NODE_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.merkle-node.v2";
pub const V6_TRANSCRIPT_MERKLE_ROOT_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.merkle-root.v2";
pub const V6_TRANSCRIPT_DECS_COEFFICIENT_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.decs-coefficient.v2";
pub const V6_TRANSCRIPT_PIOP_COEFFICIENT_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.piop-coefficient.v2";
pub const V6_TRANSCRIPT_PIOP_OPENING_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.piop-opening.v2";
pub const V6_TRANSCRIPT_DECS_QUERY_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.sha512.decs-query.v2";
pub const V6_TRANSCRIPT_DECS_DISJOINT_COSET_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.decs-disjoint-coset.v2";
pub const V6_TRANSCRIPT_OPENED_LEAF_RANDOM_TAPE_DOMAIN: &[u8] =
    b"hegemon.smallwood.v6-epsilon.opened-leaf-random-tape.v2";
pub const V6_TRANSCRIPT_GRINDING_DOMAIN: &[u8] = b"hegemon.smallwood.v6-epsilon.sha512.grinding.v2";
/// Exact proof-system/security profile string absorbed before the first backend message.
/// It is owned and relation-manifest-bound here so envelope and transcript semantics cannot
/// drift under an unchanged `HGR6RM02` identity.
pub const V6_STRICT_SECURITY_PROFILE_ID: &str =
    "hegemon.smallwood.v6-epsilon.mixed-shake512-448-shake256-448.sha512.disjoint-decs.strict.v2";

/// Sole proof-transcript binding-preamble identity for V6/Epsilon.
///
/// The preamble is absorbed, byte for byte, before every SHA-512 V6 backend
/// request.  Its payload is:
///
/// `u16be(domain_len) || domain || u16be(profile_len) || profile ||`
/// `SWV6_header[74] || HGF6ST02_statement[893]`.
///
/// The outer prefix is `magic[8] || version_u16be || payload_len_u32be` and
/// the already aligned encoding occupies exactly 141 little-endian `u64`
/// words. The payload length excludes alignment bytes; version 2 has none.
pub const V6_BINDING_PREAMBLE_MAGIC: [u8; 8] = *b"HGV6PB02";
pub const V6_BINDING_PREAMBLE_VERSION: u16 = 2;
pub const V6_BINDING_PREAMBLE_ENVELOPE_HEADER_BYTES: usize = 74;
pub const V6_BINDING_PREAMBLE_PAYLOAD_BYTES: usize = 2
    + V6_PROOF_BINDING_DOMAIN.len()
    + 2
    + V6_STRICT_SECURITY_PROFILE_ID.len()
    + V6_BINDING_PREAMBLE_ENVELOPE_HEADER_BYTES
    + V6_STATEMENT_BYTES;
pub const V6_BINDING_PREAMBLE_UNPADDED_BYTES: usize =
    V6_BINDING_PREAMBLE_MAGIC.len() + 2 + 4 + V6_BINDING_PREAMBLE_PAYLOAD_BYTES;
pub const V6_BINDING_PREAMBLE_BYTES: usize = V6_BINDING_PREAMBLE_UNPADDED_BYTES.div_ceil(8) * 8;
pub const V6_BINDING_PREAMBLE_ZERO_PAD_BYTES: usize =
    V6_BINDING_PREAMBLE_BYTES - V6_BINDING_PREAMBLE_UNPADDED_BYTES;
pub const V6_BINDING_PREAMBLE_WORDS: usize = V6_BINDING_PREAMBLE_BYTES / 8;

const V6_BINDING_PREAMBLE_GRAMMAR_DESCRIPTOR: &[u8] = b"HGV6PB02;version=u16be-2;payload-length=u32be-excludes-alignment-pad;domain=u16be-length-plus-exact-bytes;profile=u16be-length-plus-exact-bytes;envelope-header=74-exact-bytes;statement=893-exact-bytes;alignment=unique-zero-pad-to-u64;word-view=u64le;absorb-before-every-backend-message";

pub const V6_PROOF_TRANSCRIPT_DOMAINS: [&[u8]; 16] = [
    V6_PROOF_BINDING_DOMAIN,
    V6_TRANSCRIPT_XOF_DOMAIN,
    V6_TRANSCRIPT_COMPRESS2_DOMAIN,
    V6_TRANSCRIPT_PIOP_INPUT_DOMAIN,
    V6_TRANSCRIPT_PIOP_DOMAIN,
    V6_TRANSCRIPT_DECS_OPENING_DOMAIN,
    V6_TRANSCRIPT_MERKLE_LEAF_DOMAIN,
    V6_TRANSCRIPT_MERKLE_NODE_DOMAIN,
    V6_TRANSCRIPT_MERKLE_ROOT_DOMAIN,
    V6_TRANSCRIPT_DECS_COEFFICIENT_DOMAIN,
    V6_TRANSCRIPT_PIOP_COEFFICIENT_DOMAIN,
    V6_TRANSCRIPT_PIOP_OPENING_DOMAIN,
    V6_TRANSCRIPT_DECS_QUERY_DOMAIN,
    V6_TRANSCRIPT_DECS_DISJOINT_COSET_DOMAIN,
    V6_TRANSCRIPT_OPENED_LEAF_RANDOM_TAPE_DOMAIN,
    V6_TRANSCRIPT_GRINDING_DOMAIN,
];

pub const V6_RELATION_MANIFEST_MAGIC: [u8; 8] = *b"HGR6RM02";
pub const V6_RELATION_MANIFEST_VERSION: u16 = 2;
pub const V6_RELATION_BINDING_DOMAIN: &[u8] = b"hegemon.swv6.relation-manifest.v2\0";
/// SHA-512 of the fixed `HGR6RM02` manifest under
/// [`V6_RELATION_BINDING_DOMAIN`]. Release tooling must independently
/// recompute this constant from [`v6_relation_manifest`].
pub const V6_DESCRIPTOR_RELATION_BINDING: [u8; 64] = [
    0x7b, 0xc4, 0x27, 0x0f, 0x9d, 0xc4, 0xb8, 0xc8, 0xe2, 0x3a, 0x8c, 0x04, 0xab, 0xfa, 0x19, 0x3d,
    0xc8, 0x20, 0xd4, 0xc9, 0x0a, 0x49, 0xab, 0xf7, 0x37, 0x0b, 0x8c, 0x86, 0x20, 0x52, 0xe1, 0x46,
    0xd6, 0x73, 0xe4, 0xb9, 0x43, 0xbb, 0x25, 0x1d, 0x6f, 0xc3, 0x16, 0x7d, 0xb9, 0x68, 0x92, 0xc3,
    0xc9, 0xc2, 0x59, 0x8c, 0x6d, 0xf8, 0x8b, 0x78, 0x55, 0x54, 0x19, 0x84, 0x25, 0x1a, 0x5f, 0xc5,
];

pub type Digest448 = [u8; V6_DIGEST_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementFieldSpec {
    pub name: &'static str,
    pub offset: usize,
    pub width: usize,
}

impl StatementFieldSpec {
    pub const fn end(self) -> usize {
        self.offset + self.width
    }
}

/// Exact V6 statement table.  Every integer in this table is big-endian.
pub const V6_STATEMENT_FIELDS: [StatementFieldSpec; 42] = [
    StatementFieldSpec {
        name: "magic",
        offset: 0,
        width: 8,
    },
    StatementFieldSpec {
        name: "grammar_version",
        offset: 8,
        width: 2,
    },
    StatementFieldSpec {
        name: "input_flags[0]",
        offset: 10,
        width: 1,
    },
    StatementFieldSpec {
        name: "input_flags[1]",
        offset: 11,
        width: 1,
    },
    StatementFieldSpec {
        name: "output_flags[0]",
        offset: 12,
        width: 1,
    },
    StatementFieldSpec {
        name: "output_flags[1]",
        offset: 13,
        width: 1,
    },
    StatementFieldSpec {
        name: "anchor",
        offset: 14,
        width: 56,
    },
    StatementFieldSpec {
        name: "nullifiers[0]",
        offset: 70,
        width: 56,
    },
    StatementFieldSpec {
        name: "nullifiers[1]",
        offset: 126,
        width: 56,
    },
    StatementFieldSpec {
        name: "commitments[0]",
        offset: 182,
        width: 56,
    },
    StatementFieldSpec {
        name: "commitments[1]",
        offset: 238,
        width: 56,
    },
    StatementFieldSpec {
        name: "ciphertext_hashes[0]",
        offset: 294,
        width: 56,
    },
    StatementFieldSpec {
        name: "ciphertext_hashes[1]",
        offset: 350,
        width: 56,
    },
    StatementFieldSpec {
        name: "ciphertext_sizes[0]",
        offset: 406,
        width: 4,
    },
    StatementFieldSpec {
        name: "ciphertext_sizes[1]",
        offset: 410,
        width: 4,
    },
    StatementFieldSpec {
        name: "balance_asset_ids[0]",
        offset: 414,
        width: 8,
    },
    StatementFieldSpec {
        name: "balance_asset_ids[1]",
        offset: 422,
        width: 8,
    },
    StatementFieldSpec {
        name: "balance_asset_ids[2]",
        offset: 430,
        width: 8,
    },
    StatementFieldSpec {
        name: "balance_asset_ids[3]",
        offset: 438,
        width: 8,
    },
    StatementFieldSpec {
        name: "fee",
        offset: 446,
        width: 8,
    },
    StatementFieldSpec {
        name: "value_balance.sign",
        offset: 454,
        width: 1,
    },
    StatementFieldSpec {
        name: "value_balance.magnitude",
        offset: 455,
        width: 8,
    },
    StatementFieldSpec {
        name: "stable.enabled",
        offset: 463,
        width: 1,
    },
    StatementFieldSpec {
        name: "stable.asset_id",
        offset: 464,
        width: 8,
    },
    StatementFieldSpec {
        name: "stable.policy_version",
        offset: 472,
        width: 4,
    },
    StatementFieldSpec {
        name: "stable.issuance.sign",
        offset: 476,
        width: 1,
    },
    StatementFieldSpec {
        name: "stable.issuance.magnitude",
        offset: 477,
        width: 8,
    },
    StatementFieldSpec {
        name: "stable.policy_hash",
        offset: 485,
        width: 56,
    },
    StatementFieldSpec {
        name: "stable.oracle_commitment",
        offset: 541,
        width: 56,
    },
    StatementFieldSpec {
        name: "stable.attestation_commitment",
        offset: 597,
        width: 56,
    },
    StatementFieldSpec {
        name: "balance_tag",
        offset: 653,
        width: 56,
    },
    StatementFieldSpec {
        name: "activation.circuit",
        offset: 709,
        width: 2,
    },
    StatementFieldSpec {
        name: "activation.crypto_suite",
        offset: 711,
        width: 2,
    },
    StatementFieldSpec {
        name: "activation.family",
        offset: 713,
        width: 2,
    },
    StatementFieldSpec {
        name: "activation.action",
        offset: 715,
        width: 2,
    },
    StatementFieldSpec {
        name: "activation.network",
        offset: 717,
        width: 4,
    },
    StatementFieldSpec {
        name: "activation.backend",
        offset: 721,
        width: 1,
    },
    StatementFieldSpec {
        name: "activation.profile",
        offset: 722,
        width: 1,
    },
    StatementFieldSpec {
        name: "activation.domain_set",
        offset: 723,
        width: 2,
    },
    StatementFieldSpec {
        name: "activation.chain_id",
        offset: 725,
        width: 56,
    },
    StatementFieldSpec {
        name: "activation.genesis_id",
        offset: 781,
        width: 56,
    },
    StatementFieldSpec {
        name: "activation.rules_hash",
        offset: 837,
        width: 56,
    },
];

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
pub const OFFSET_STABLE_ORACLE: usize = 541;
pub const OFFSET_STABLE_ATTESTATION: usize = 597;
pub const OFFSET_BALANCE_TAG: usize = 653;
pub const OFFSET_ACTIVATION: usize = 709;
pub const OFFSET_NETWORK: usize = 717;
pub const OFFSET_BACKEND: usize = 721;
pub const OFFSET_PROFILE: usize = 722;
pub const OFFSET_DOMAIN_SET: usize = 723;
pub const OFFSET_CHAIN_ID: usize = 725;
pub const OFFSET_GENESIS_ID: usize = 781;
pub const OFFSET_RULES_HASH: usize = 837;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignedMagnitude {
    pub negative: bool,
    pub magnitude: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StablecoinStatementBinding {
    pub enabled: bool,
    pub asset_id: u64,
    pub policy_version: u32,
    pub issuance_delta: SignedMagnitude,
    pub policy_hash: Digest448,
    pub oracle_commitment: Digest448,
    pub attestation_commitment: Digest448,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V6ActivationBinding {
    pub circuit_version: u16,
    pub crypto_suite: u16,
    pub family_id: u16,
    pub action_id: u16,
    pub backend_id: u8,
    pub proof_profile: u8,
    pub domain_set: u16,
    pub network_id: u32,
    pub chain_id: Digest448,
    pub genesis_id: Digest448,
    pub rules_hash: Digest448,
}

impl V6ActivationBinding {
    pub const fn has_v6_route(self) -> bool {
        self.circuit_version == V6_CIRCUIT_VERSION
            && self.crypto_suite == V6_CRYPTO_SUITE
            && self.family_id == V6_FAMILY_ID
            && self.action_id == V6_ACTION_ID
            && self.backend_id == V6_BACKEND_ID
            && self.proof_profile == V6_PROOF_PROFILE
            && self.domain_set == V6_DOMAIN_SET
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullShake448Statement {
    pub input_flags: [bool; V6_MAX_INPUTS],
    pub output_flags: [bool; V6_MAX_OUTPUTS],
    pub anchor: Digest448,
    pub nullifiers: [Digest448; V6_MAX_INPUTS],
    pub commitments: [Digest448; V6_MAX_OUTPUTS],
    pub ciphertext_hashes: [Digest448; V6_MAX_OUTPUTS],
    pub ciphertext_sizes: [u32; V6_MAX_OUTPUTS],
    pub balance_asset_ids: [u64; V6_BALANCE_SLOTS],
    pub fee: u64,
    pub value_balance: SignedMagnitude,
    pub stablecoin: StablecoinStatementBinding,
    pub balance_tag: Digest448,
    pub activation: V6ActivationBinding,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FullShake448StatementError {
    #[error("V6 statement must contain exactly {required} bytes, observed {observed}")]
    Length { required: usize, observed: usize },
    #[error("V6 statement magic is not HGF6ST02")]
    Magic,
    #[error("unsupported V6 statement grammar version {0}")]
    GrammarVersion(u16),
    #[error("statement field {0} is not Boolean")]
    NonBoolean(&'static str),
    #[error("signed field {0} encodes negative zero")]
    NegativeZero(&'static str),
    #[error("signed field {field} magnitude {magnitude} exceeds the 61-bit limit")]
    SignedMagnitudeOutOfRange { field: &'static str, magnitude: u64 },
    #[error("statement carries an unsupported V6 route/profile")]
    UnsupportedActivation,
    #[error("statement activation {0} must not be all zero")]
    ZeroActivationBinding(&'static str),
    #[error("semantic frame has {0} fields; at most 255 are encodable")]
    TooManyFrameFields(usize),
    #[error("semantic frame field {field} has {bytes} bytes; at most 65535 are encodable")]
    FrameFieldTooLong { field: usize, bytes: usize },
    #[error("semantic frame length overflow")]
    FrameLengthOverflow,
    #[error("ciphertext slot {0} is outside the fixed two-output relation")]
    CiphertextSlot(usize),
    #[error("V6 ciphertext length {observed} is not the canonical {required} bytes")]
    CiphertextLength { observed: usize, required: usize },
    #[error("statement limb {index} is not a canonical {bits}-bit encoding")]
    NonCanonicalStatementLimb { index: usize, bits: usize },
}

pub fn encode_v6_statement(
    statement: &FullShake448Statement,
) -> Result<[u8; V6_STATEMENT_BYTES], FullShake448StatementError> {
    validate_statement_values(statement)?;
    let mut bytes = Vec::with_capacity(V6_STATEMENT_BYTES);
    bytes.extend_from_slice(&V6_STATEMENT_MAGIC);
    bytes.extend_from_slice(&V6_STATEMENT_GRAMMAR_VERSION.to_be_bytes());
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
    push_activation(&mut bytes, statement.activation);
    debug_assert_eq!(bytes.len(), V6_STATEMENT_BYTES);
    Ok(bytes
        .try_into()
        .expect("the V6 statement table has a fixed compile-time width"))
}

pub fn decode_v6_statement(
    bytes: &[u8],
) -> Result<FullShake448Statement, FullShake448StatementError> {
    if bytes.len() != V6_STATEMENT_BYTES {
        return Err(FullShake448StatementError::Length {
            required: V6_STATEMENT_BYTES,
            observed: bytes.len(),
        });
    }
    let mut cursor = StatementCursor { bytes, offset: 0 };
    if cursor.array::<8>() != V6_STATEMENT_MAGIC {
        return Err(FullShake448StatementError::Magic);
    }
    let grammar_version = cursor.u16();
    if grammar_version != V6_STATEMENT_GRAMMAR_VERSION {
        return Err(FullShake448StatementError::GrammarVersion(grammar_version));
    }
    let input_flags = [
        cursor.boolean("input_flags[0]")?,
        cursor.boolean("input_flags[1]")?,
    ];
    let output_flags = [
        cursor.boolean("output_flags[0]")?,
        cursor.boolean("output_flags[1]")?,
    ];
    let anchor = cursor.array();
    let nullifiers = core::array::from_fn(|_| cursor.array());
    let commitments = core::array::from_fn(|_| cursor.array());
    let ciphertext_hashes = core::array::from_fn(|_| cursor.array());
    let ciphertext_sizes = core::array::from_fn(|_| cursor.u32());
    let balance_asset_ids = core::array::from_fn(|_| cursor.u64());
    let fee = cursor.u64();
    let value_balance = cursor.signed("value_balance")?;
    let stablecoin = StablecoinStatementBinding {
        enabled: cursor.boolean("stable.enabled")?,
        asset_id: cursor.u64(),
        policy_version: cursor.u32(),
        issuance_delta: cursor.signed("stable.issuance")?,
        policy_hash: cursor.array(),
        oracle_commitment: cursor.array(),
        attestation_commitment: cursor.array(),
    };
    let balance_tag = cursor.array();
    let activation = V6ActivationBinding {
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
    };
    debug_assert_eq!(cursor.offset, V6_STATEMENT_BYTES);
    let statement = FullShake448Statement {
        input_flags,
        output_flags,
        anchor,
        nullifiers,
        commitments,
        ciphertext_hashes,
        ciphertext_sizes,
        balance_asset_ids,
        fee,
        value_balance,
        stablecoin,
        balance_tag,
        activation,
    };
    validate_statement_values(&statement)?;
    Ok(statement)
}

fn validate_statement_values(
    statement: &FullShake448Statement,
) -> Result<(), FullShake448StatementError> {
    validate_signed(statement.value_balance, "value_balance")?;
    validate_signed(statement.stablecoin.issuance_delta, "stable.issuance")?;
    if !statement.activation.has_v6_route() {
        return Err(FullShake448StatementError::UnsupportedActivation);
    }
    if statement.activation.chain_id == [0; V6_DIGEST_BYTES] {
        return Err(FullShake448StatementError::ZeroActivationBinding(
            "chain_id",
        ));
    }
    if statement.activation.genesis_id == [0; V6_DIGEST_BYTES] {
        return Err(FullShake448StatementError::ZeroActivationBinding(
            "genesis_id",
        ));
    }
    if statement.activation.rules_hash == [0; V6_DIGEST_BYTES] {
        return Err(FullShake448StatementError::ZeroActivationBinding(
            "rules_hash",
        ));
    }
    Ok(())
}

fn validate_signed(
    value: SignedMagnitude,
    field: &'static str,
) -> Result<(), FullShake448StatementError> {
    if value.magnitude > V6_MAX_NOTE_VALUE {
        return Err(FullShake448StatementError::SignedMagnitudeOutOfRange {
            field,
            magnitude: value.magnitude,
        });
    }
    if value.negative && value.magnitude == 0 {
        return Err(FullShake448StatementError::NegativeZero(field));
    }
    Ok(())
}

fn push_signed(bytes: &mut Vec<u8>, value: SignedMagnitude) {
    bytes.push(u8::from(value.negative));
    bytes.extend_from_slice(&value.magnitude.to_be_bytes());
}

fn push_activation(bytes: &mut Vec<u8>, activation: V6ActivationBinding) {
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
}

struct StatementCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl StatementCursor<'_> {
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let output = self.bytes[self.offset..self.offset + N]
            .try_into()
            .expect("the exact V6 statement width was checked");
        self.offset += N;
        output
    }

    fn byte(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn boolean(&mut self, field: &'static str) -> Result<bool, FullShake448StatementError> {
        match self.byte() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(FullShake448StatementError::NonBoolean(field)),
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
    ) -> Result<SignedMagnitude, FullShake448StatementError> {
        let value = SignedMagnitude {
            negative: self.boolean(field)?,
            magnitude: self.u64(),
        };
        validate_signed(value, field)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V6StatementProjection {
    limbs: [u64; V6_STATEMENT_LIMBS],
}

impl V6StatementProjection {
    /// Construct the verifier's public-field view and prove it reconstructs one canonical
    /// `HGF6ST02` statement. Range-valid limbs alone are not a statement authority.
    pub fn from_limbs(
        limbs: [u64; V6_STATEMENT_LIMBS],
    ) -> Result<Self, FullShake448StatementError> {
        for (index, value) in limbs.iter().copied().enumerate() {
            let offset = index * V6_STATEMENT_LIMB_BYTES;
            let take = (V6_STATEMENT_BYTES - offset).min(V6_STATEMENT_LIMB_BYTES);
            let bits = take * 8;
            if value >= (1u64 << bits) {
                return Err(FullShake448StatementError::NonCanonicalStatementLimb { index, bits });
            }
            debug_assert!(value < GOLDILOCKS_MODULUS);
        }
        let projection = Self { limbs };
        decode_v6_statement(&projection.reconstruct())?;
        Ok(projection)
    }

    pub const fn limbs(&self) -> &[u64; V6_STATEMENT_LIMBS] {
        &self.limbs
    }

    pub fn reconstruct(&self) -> [u8; V6_STATEMENT_BYTES] {
        let mut bytes = [0u8; V6_STATEMENT_BYTES];
        for (index, value) in self.limbs.iter().copied().enumerate() {
            let offset = index * V6_STATEMENT_LIMB_BYTES;
            let take = (V6_STATEMENT_BYTES - offset).min(V6_STATEMENT_LIMB_BYTES);
            bytes[offset..offset + take].copy_from_slice(&value.to_le_bytes()[..take]);
        }
        bytes
    }
}

/// Parse and project the canonical statement without reduction.  The byte
/// grammar remains authoritative; the limbs are only its exact field view.
pub fn project_v6_statement(
    statement: &[u8],
) -> Result<V6StatementProjection, FullShake448StatementError> {
    decode_v6_statement(statement)?;
    let mut limbs = [0u64; V6_STATEMENT_LIMBS];
    for (index, chunk) in statement.chunks(V6_STATEMENT_LIMB_BYTES).enumerate() {
        let mut encoded = [0u8; 8];
        encoded[..chunk.len()].copy_from_slice(chunk);
        limbs[index] = u64::from_le_bytes(encoded);
        debug_assert!(limbs[index] < GOLDILOCKS_MODULUS);
    }
    V6StatementProjection::from_limbs(limbs)
}

/// Encode `HEG-F6V2 || role || count || (u16_be(len) || field)*`.
pub fn encode_v6_semantic_frame<'a>(
    role: [u8; 8],
    fields: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, FullShake448StatementError> {
    let fields = fields.into_iter().collect::<Vec<_>>();
    if fields.len() > u8::MAX as usize {
        return Err(FullShake448StatementError::TooManyFrameFields(fields.len()));
    }
    let field_bytes = fields
        .iter()
        .enumerate()
        .try_fold(0usize, |total, (index, field)| {
            if field.len() > u16::MAX as usize {
                return Err(FullShake448StatementError::FrameFieldTooLong {
                    field: index,
                    bytes: field.len(),
                });
            }
            total
                .checked_add(2)
                .and_then(|value| value.checked_add(field.len()))
                .ok_or(FullShake448StatementError::FrameLengthOverflow)
        })?;
    let capacity = 17usize
        .checked_add(field_bytes)
        .ok_or(FullShake448StatementError::FrameLengthOverflow)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&V6_PROFILE_TAG);
    frame.extend_from_slice(&role);
    frame.push(fields.len() as u8);
    for field in fields {
        frame.extend_from_slice(&(field.len() as u16).to_be_bytes());
        frame.extend_from_slice(field);
    }
    Ok(frame)
}

/// Exact `ct.hash1` preimage. It binds profile 3, domain set 2, the output
/// slot, a redundant big-endian u32 length, and the complete canonical bytes.
/// SHAKE256-448 evaluation belongs to the constrained relation/compiler.
pub fn encode_v6_ciphertext_hash_frame(
    slot: usize,
    canonical_ciphertext: &[u8],
) -> Result<Vec<u8>, FullShake448StatementError> {
    if slot >= V6_MAX_OUTPUTS {
        return Err(FullShake448StatementError::CiphertextSlot(slot));
    }
    if canonical_ciphertext.len() != V6_CANONICAL_CIPHERTEXT_BYTES {
        return Err(FullShake448StatementError::CiphertextLength {
            observed: canonical_ciphertext.len(),
            required: V6_CANONICAL_CIPHERTEXT_BYTES,
        });
    }
    let length = V6_CANONICAL_CIPHERTEXT_BYTES as u32;
    let profile = [V6_PROOF_PROFILE];
    let domain_set = V6_DOMAIN_SET.to_be_bytes();
    let slot = [slot as u8];
    let length = length.to_be_bytes();
    encode_v6_semantic_frame(
        ROLE_CIPHERTEXT_HASH,
        [
            profile.as_slice(),
            domain_set.as_slice(),
            slot.as_slice(),
            length.as_slice(),
            canonical_ciphertext,
        ],
    )
}

/// Host-reference SHAKE256-448 for one exact canonical ciphertext slot.
///
/// This function exists for parser/action mutation vectors and independent
/// relation conformance tests. It is never proof authority: production must
/// constrain both `ct.hash1` executions inside the 145-permutation relation.
pub fn reference_only_hash_v6_ciphertext(
    slot: usize,
    canonical_ciphertext: &[u8; V6_CANONICAL_CIPHERTEXT_BYTES],
) -> Result<CiphertextHash56, FullShake448StatementError> {
    let frame = encode_v6_ciphertext_hash_frame(slot, canonical_ciphertext)?;
    let mut state = Shake256::default();
    XofUpdate::update(&mut state, &frame);
    let mut reader = state.finalize_xof();
    let mut output = [0u8; V6_DIGEST_BYTES];
    XofReader::read(&mut reader, &mut output);
    Ok(CiphertextHash56::new(output))
}

const STATEMENT_CANONICALITY_DESCRIPTOR: &[u8] = b"HGF6ST02;grammar=2;all-integers=big-endian;flags=0-or-1;signed=no-negative-zero-and-magnitude-lt-2^61;route=6,5,1,8,2,3,2;chain-genesis-rules=nonzero-56-byte;exact-consume";
const PROJECTOR_DESCRIPTOR: &[u8] = b"statement-authority=893-raw-bytes;projection=consecutive-7-byte-little-endian;limbs=128;last-limb=4-bytes-lt-2^32;modular-reduction=forbidden;intent-public-suffix=forbidden";
const FULL_RELATION_QIR_DESCRIPTOR: &[u8] = b"registry=HGF6HR02;note.cm3:SHAKE512-448:4-calls/16-perms;nullif.2:SHAKE512-448:2/4;merk.nd2:SHAKE256-448:64/64;sp.keys2:SHAKE512-448:2/6;policy.1:SHAKE512-448:1/6;auth.mux:SHAKE512-448:2/8;intent.1:SHAKE256-448:1/6;bal.tag1:SHAKE256-448:1/1;ct.hash1:SHAKE256-448:2/34,frame-bytes=2182;total=79/145;host-digest-authority=forbidden";
const CIPHERTEXT_GRAMMAR_DESCRIPTOR: &[u8] = b"wallet-v3-gamma-da;active-action-canonical-bytes=2147;inactive-action-size=0;inactive-statement-hash=zero448;relation-slot-bytes=2147-always;inactive-relation-slot=2147-zero-bytes;ct.hash1-frame-bytes=2182;ct.hash1-fields=profile-u8,domain-set-u16be,slot-u8,byte-length-u32be,exact-canonical-bytes;relation-hashes-both-slots;public-hash=output-flag-times-computed-digest;digest=SHAKE256-448";
const SMALLWOOD_INNER_WIRE_DESCRIPTOR: &[u8] = b"SWV6-envelope-version=2;header=74;statement=893;proof=one-nonempty-exact-consumed;field=Goldilocks;relation-hash-registry=HGF6HR02;relation-digest-bytes=56;transcript=SHA-512;DECS=disjoint-coset;opened-leaf-random-tape-and-index-binding=required;sidecar,aggregate,receipt,cache,historical-substitution=forbidden";

/// Encode the sole typed relation hash registry. Every integer is big-endian;
/// no padding, terminator, or caller-provided field is permitted.
pub fn encode_v6_hash_role_registry() -> [u8; V6_HASH_ROLE_REGISTRY_BYTES] {
    let mut output = Vec::with_capacity(V6_HASH_ROLE_REGISTRY_BYTES);
    output.extend_from_slice(&V6_HASH_ROLE_REGISTRY_MAGIC);
    output.extend_from_slice(&V6_HASH_ROLE_REGISTRY_VERSION.to_be_bytes());
    output.extend_from_slice(&(V6_HASH_ROLE_REGISTRY.len() as u16).to_be_bytes());
    for spec in V6_HASH_ROLE_REGISTRY {
        output.extend_from_slice(&spec.role);
        output.push(spec.purpose as u8);
        output.push(spec.algorithm as u8);
        output.extend_from_slice(&spec.invocations.to_be_bytes());
        output.extend_from_slice(&spec.max_frame_bytes.to_be_bytes());
        output.extend_from_slice(&spec.output_bytes.to_be_bytes());
        output.extend_from_slice(&spec.rate_bytes.to_be_bytes());
        output.extend_from_slice(&spec.permutations_per_call.to_be_bytes());
    }
    output.extend_from_slice(&(V6_FULL_RELATION_SHAKE_INVOCATIONS as u16).to_be_bytes());
    output.extend_from_slice(&(V6_FULL_RELATION_KECCAK_PERMUTATIONS as u16).to_be_bytes());
    output
        .try_into()
        .expect("fixed HGF6HR02 registry must contain exactly 214 bytes")
}

pub fn recompute_v6_hash_role_registry_digest() -> [u8; 64] {
    let mut hasher = Sha512::new();
    ShaDigest::update(&mut hasher, encode_v6_hash_role_registry());
    let digest = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&digest);
    output
}

/// Fixed binary relation manifest. Its eight component digests bind the
/// statement/canonicality table, semantic roles, lossless projector, exact
/// 79-call/145-permutation QIR schedule, typed algorithm/purpose registry,
/// ciphertext grammar, SmallWood wire and verifier profile, and every
/// proof-transcript domain. Release receipts pin
/// this identity; receipt bytes never become part of it.
pub fn v6_relation_manifest() -> Vec<u8> {
    let statement_schema_digest = digest_statement_schema();
    let semantic_domain_digest = digest_semantic_domains();
    let projector_digest = sha512_descriptor(b"hegemon.swv6.projector.v2\0", PROJECTOR_DESCRIPTOR);
    let qir_digest = sha512_descriptor(b"hegemon.swv6.qir.v2\0", FULL_RELATION_QIR_DESCRIPTOR);
    let hash_role_registry_digest = recompute_v6_hash_role_registry_digest();
    let ciphertext_digest = sha512_descriptor(
        b"hegemon.swv6.ciphertext-grammar.v2\0",
        CIPHERTEXT_GRAMMAR_DESCRIPTOR,
    );
    let inner_wire_digest = sha512_descriptor(
        b"hegemon.swv6.smallwood-inner-wire.v2\0",
        SMALLWOOD_INNER_WIRE_DESCRIPTOR,
    );
    let transcript_digest = digest_proof_transcript_domains();

    let mut output = Vec::with_capacity(546);
    output.extend_from_slice(&V6_RELATION_MANIFEST_MAGIC);
    output.extend_from_slice(&V6_RELATION_MANIFEST_VERSION.to_be_bytes());
    output.extend_from_slice(&V6_CIRCUIT_VERSION.to_be_bytes());
    output.extend_from_slice(&V6_CRYPTO_SUITE.to_be_bytes());
    output.extend_from_slice(&V6_FAMILY_ID.to_be_bytes());
    output.extend_from_slice(&V6_ACTION_ID.to_be_bytes());
    output.push(V6_BACKEND_ID);
    output.push(V6_PROOF_PROFILE);
    output.extend_from_slice(&V6_DOMAIN_SET.to_be_bytes());
    output.extend_from_slice(&(V6_STATEMENT_BYTES as u16).to_be_bytes());
    output.extend_from_slice(&(V6_STATEMENT_LIMBS as u16).to_be_bytes());
    output.extend_from_slice(&(V6_FULL_RELATION_SHAKE_INVOCATIONS as u16).to_be_bytes());
    output.extend_from_slice(&(V6_FULL_RELATION_KECCAK_PERMUTATIONS as u16).to_be_bytes());
    output.extend_from_slice(&(V6_CANONICAL_CIPHERTEXT_BYTES as u32).to_be_bytes());
    for digest in [
        statement_schema_digest,
        semantic_domain_digest,
        projector_digest,
        qir_digest,
        hash_role_registry_digest,
        ciphertext_digest,
        inner_wire_digest,
        transcript_digest,
    ] {
        output.extend_from_slice(&digest);
    }
    debug_assert_eq!(output.len(), 546);
    output
}

fn digest_statement_schema() -> [u8; 64] {
    let mut descriptor = Vec::new();
    descriptor.extend_from_slice(STATEMENT_CANONICALITY_DESCRIPTOR);
    descriptor.extend_from_slice(&(V6_STATEMENT_FIELDS.len() as u16).to_be_bytes());
    for field in V6_STATEMENT_FIELDS {
        append_u16_item(&mut descriptor, field.name.as_bytes());
        descriptor.extend_from_slice(&(field.offset as u16).to_be_bytes());
        descriptor.extend_from_slice(&(field.width as u16).to_be_bytes());
    }
    sha512_descriptor(b"hegemon.swv6.statement-schema.v2\0", &descriptor)
}

fn digest_semantic_domains() -> [u8; 64] {
    let mut descriptor = Vec::new();
    descriptor.extend_from_slice(b"frame=HEG-F6V2||role8||count-u8||(length-u16be||field)*;");
    descriptor.extend_from_slice(&(V6_SEMANTIC_BINDING_TAGS.len() as u16).to_be_bytes());
    for tag in V6_SEMANTIC_BINDING_TAGS {
        append_u16_item(&mut descriptor, &tag);
    }
    append_u16_item(&mut descriptor, &KEY_OUTPUT_ORDER_TAG);
    sha512_descriptor(b"hegemon.swv6.semantic-domains.v2\0", &descriptor)
}

fn digest_proof_transcript_domains() -> [u8; 64] {
    let mut descriptor = Vec::new();
    append_u16_item(&mut descriptor, V6_STRICT_SECURITY_PROFILE_ID.as_bytes());
    append_u16_item(&mut descriptor, V6_BINDING_PREAMBLE_GRAMMAR_DESCRIPTOR);
    append_u16_item(&mut descriptor, &V6_BINDING_PREAMBLE_MAGIC);
    descriptor.extend_from_slice(&V6_BINDING_PREAMBLE_VERSION.to_be_bytes());
    descriptor.extend_from_slice(&(V6_BINDING_PREAMBLE_PAYLOAD_BYTES as u32).to_be_bytes());
    descriptor.extend_from_slice(&(V6_BINDING_PREAMBLE_UNPADDED_BYTES as u16).to_be_bytes());
    descriptor.extend_from_slice(&(V6_BINDING_PREAMBLE_BYTES as u16).to_be_bytes());
    descriptor.extend_from_slice(&(V6_BINDING_PREAMBLE_ZERO_PAD_BYTES as u16).to_be_bytes());
    descriptor.extend_from_slice(&(V6_BINDING_PREAMBLE_WORDS as u16).to_be_bytes());
    descriptor.extend_from_slice(&(V6_BINDING_PREAMBLE_ENVELOPE_HEADER_BYTES as u16).to_be_bytes());
    descriptor.extend_from_slice(&(V6_STATEMENT_BYTES as u16).to_be_bytes());
    descriptor.extend_from_slice(&(V6_PROOF_TRANSCRIPT_DOMAINS.len() as u16).to_be_bytes());
    for domain in V6_PROOF_TRANSCRIPT_DOMAINS {
        append_u16_item(&mut descriptor, domain);
    }
    sha512_descriptor(b"hegemon.swv6.proof-transcript-domains.v2\0", &descriptor)
}

fn append_u16_item(output: &mut Vec<u8>, value: &[u8]) {
    let length = u16::try_from(value.len()).expect("fixed manifest item fits u16");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn sha512_descriptor(domain: &[u8], descriptor: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    ShaDigest::update(&mut hasher, (domain.len() as u16).to_be_bytes());
    ShaDigest::update(&mut hasher, domain);
    ShaDigest::update(&mut hasher, (descriptor.len() as u64).to_be_bytes());
    ShaDigest::update(&mut hasher, descriptor);
    let digest = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&digest);
    output
}

pub fn recompute_v6_relation_binding() -> [u8; 64] {
    let manifest = v6_relation_manifest();
    sha512_descriptor(V6_RELATION_BINDING_DOMAIN, &manifest)
}

/// The fixed source-descriptor binding expected by the prospective V6 adapter.
/// It does not establish that the described relation was compiled or refined.
/// Callers do not supply or negotiate this value.
pub const fn descriptor_v6_relation_binding() -> [u8; 64] {
    V6_DESCRIPTOR_RELATION_BINDING
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> FullShake448Statement {
        FullShake448Statement {
            input_flags: [true, true],
            output_flags: [true, false],
            anchor: [0x11; 56],
            nullifiers: [[0x21; 56], [0x22; 56]],
            commitments: [[0x31; 56], [0; 56]],
            ciphertext_hashes: [[0x41; 56], [0; 56]],
            ciphertext_sizes: [2_147, 0],
            balance_asset_ids: [0, 7, 9, u64::MAX],
            fee: 13,
            value_balance: SignedMagnitude {
                negative: true,
                magnitude: 17,
            },
            stablecoin: StablecoinStatementBinding {
                enabled: true,
                asset_id: 7,
                policy_version: 23,
                issuance_delta: SignedMagnitude {
                    negative: false,
                    magnitude: 29,
                },
                policy_hash: [0x51; 56],
                oracle_commitment: [0x52; 56],
                attestation_commitment: [0x53; 56],
            },
            balance_tag: [0x61; 56],
            activation: V6ActivationBinding {
                circuit_version: V6_CIRCUIT_VERSION,
                crypto_suite: V6_CRYPTO_SUITE,
                family_id: V6_FAMILY_ID,
                action_id: V6_ACTION_ID,
                backend_id: V6_BACKEND_ID,
                proof_profile: V6_PROOF_PROFILE,
                domain_set: V6_DOMAIN_SET,
                network_id: 0x0102_0304,
                chain_id: [0x71; 56],
                genesis_id: [0x72; 56],
                rules_hash: [0x73; 56],
            },
        }
    }

    #[test]
    fn exact_table_is_contiguous_and_totals_893_bytes() {
        let mut offset = 0;
        for field in V6_STATEMENT_FIELDS {
            assert_eq!(field.offset, offset, "{}", field.name);
            offset = field.end();
        }
        assert_eq!(offset, V6_STATEMENT_BYTES);
        assert_eq!(V6_STATEMENT_LIMBS, 128);
        assert_eq!(V6_PUBLIC_VALUES, 128);
        assert_eq!(V6_FULL_RELATION_SHAKE_INVOCATIONS, 79);
        assert_eq!(V6_FULL_RELATION_KECCAK_PERMUTATIONS, 145);
    }

    #[test]
    fn statement_roundtrip_is_exact_and_big_endian() {
        let statement = fixture();
        let encoded = encode_v6_statement(&statement).unwrap();
        assert_eq!(&encoded[..8], b"HGF6ST02");
        assert_eq!(&encoded[8..10], &2u16.to_be_bytes());
        assert_eq!(
            &encoded[OFFSET_CIPHERTEXT_SIZES..OFFSET_CIPHERTEXT_SIZES + 4],
            &2_147u32.to_be_bytes()
        );
        assert_eq!(&encoded[OFFSET_FEE..OFFSET_FEE + 8], &13u64.to_be_bytes());
        assert_eq!(
            &encoded[OFFSET_NETWORK..OFFSET_NETWORK + 4],
            &0x0102_0304u32.to_be_bytes()
        );
        assert_eq!(decode_v6_statement(&encoded).unwrap(), statement);
    }

    #[test]
    fn rejected_profile2_statement_identity_cannot_decode_as_successor() {
        let encoded = encode_v6_statement(&fixture()).unwrap();

        let mut old_magic = encoded;
        old_magic[..8].copy_from_slice(b"HGF6ST01");
        assert!(matches!(
            decode_v6_statement(&old_magic),
            Err(FullShake448StatementError::Magic)
        ));

        let mut old_grammar = encoded;
        old_grammar[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            decode_v6_statement(&old_grammar),
            Err(FullShake448StatementError::GrammarVersion(1))
        ));

        let mut old_route = encoded;
        old_route[OFFSET_PROFILE] = 2;
        old_route[OFFSET_DOMAIN_SET..OFFSET_DOMAIN_SET + 2].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            decode_v6_statement(&old_route),
            Err(FullShake448StatementError::UnsupportedActivation)
        ));
    }

    #[test]
    fn parser_rejects_every_truncation_and_trailing_byte() {
        let encoded = encode_v6_statement(&fixture()).unwrap();
        for length in 0..V6_STATEMENT_BYTES {
            assert!(
                decode_v6_statement(&encoded[..length]).is_err(),
                "length {length}"
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_v6_statement(&trailing).is_err());
    }

    #[test]
    fn parser_rejects_all_identity_boolean_and_signed_noncanonical_mutations() {
        let encoded = encode_v6_statement(&fixture()).unwrap();
        for offset in [
            0, 8, 10, 11, 12, 13, 454, 463, 476, 709, 711, 713, 715, 721, 722, 723,
        ] {
            let mut changed = encoded;
            changed[offset] ^= if matches!(offset, 10 | 11 | 12 | 13 | 454 | 463 | 476) {
                3
            } else {
                1
            };
            assert!(decode_v6_statement(&changed).is_err(), "offset {offset}");
        }

        let mut negative_zero = encoded;
        negative_zero[OFFSET_VALUE_BALANCE_SIGN] = 1;
        negative_zero[OFFSET_VALUE_BALANCE_MAGNITUDE..OFFSET_VALUE_BALANCE_MAGNITUDE + 8].fill(0);
        assert!(matches!(
            decode_v6_statement(&negative_zero),
            Err(FullShake448StatementError::NegativeZero("value_balance"))
        ));
    }

    #[test]
    fn projection_is_128_lossless_little_endian_limbs() {
        let encoded = encode_v6_statement(&fixture()).unwrap();
        let projection = project_v6_statement(&encoded).unwrap();
        assert_eq!(projection.reconstruct(), encoded);
        assert_eq!(
            projection.limbs()[0],
            u64::from_le_bytes([b'H', b'G', b'F', b'6', b'S', b'T', b'0', 0])
        );
        assert!(projection
            .limbs()
            .iter()
            .all(|value| *value < GOLDILOCKS_MODULUS));

        let mut limbs = *projection.limbs();
        limbs[V6_STATEMENT_LIMBS - 1] = 1u64 << 32;
        assert!(matches!(
            V6StatementProjection::from_limbs(limbs),
            Err(FullShake448StatementError::NonCanonicalStatementLimb {
                index: 127,
                bits: 32
            })
        ));
        assert!(V6StatementProjection::from_limbs([0; V6_STATEMENT_LIMBS]).is_err());
    }

    #[test]
    fn ciphertext_frame_binds_profile_domain_slot_length_and_exact_bytes() {
        let bytes = vec![0x5a; V6_CANONICAL_CIPHERTEXT_BYTES];
        let frame = encode_v6_ciphertext_hash_frame(1, &bytes).unwrap();
        assert!(frame.starts_with(b"HEG-F6V2ct.hash1"));
        assert!(frame.windows(bytes.len()).any(|window| window == bytes));
        assert_ne!(frame, encode_v6_ciphertext_hash_frame(0, &bytes).unwrap());
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert_ne!(frame, encode_v6_ciphertext_hash_frame(1, &changed).unwrap());
        assert!(matches!(
            encode_v6_ciphertext_hash_frame(2, &bytes),
            Err(FullShake448StatementError::CiphertextSlot(2))
        ));
        assert!(matches!(
            encode_v6_ciphertext_hash_frame(0, &bytes[..bytes.len() - 1]),
            Err(FullShake448StatementError::CiphertextLength {
                observed: 2_146,
                required: 2_147
            })
        ));
        assert_eq!(frame.len(), 2_182);
        assert_eq!(frame.len() / 136 + 1, 17);
    }

    #[test]
    fn ciphertext_reference_hash_matches_independent_exact_frame_kat() {
        let bytes = [0x5a; V6_CANONICAL_CIPHERTEXT_BYTES];
        let digest = reference_only_hash_v6_ciphertext(1, &bytes).unwrap();
        let expected: [u8; V6_DIGEST_BYTES] = hex::decode(
            "6d484168504a2a801cf5e174dea968f024df02b3880ffd8e46c247ae44399522fad99c21f29c9d97e9d9d0682eb43024c59d485ce529475c",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert_eq!(digest.into_bytes(), expected);
        assert_ne!(
            reference_only_hash_v6_ciphertext(0, &bytes).unwrap(),
            digest
        );
        let mut changed = bytes;
        changed[V6_CANONICAL_CIPHERTEXT_BYTES - 1] ^= 1;
        assert_ne!(
            reference_only_hash_v6_ciphertext(1, &changed).unwrap(),
            digest
        );
    }

    #[test]
    fn ciphertext_manifest_distinguishes_inactive_action_from_fixed_relation_slot() {
        let descriptor = core::str::from_utf8(CIPHERTEXT_GRAMMAR_DESCRIPTOR).unwrap();
        assert!(descriptor.contains("inactive-action-size=0"));
        assert!(descriptor.contains("inactive-statement-hash=zero448"));
        assert!(descriptor.contains("relation-slot-bytes=2147-always"));
        assert!(descriptor.contains("inactive-relation-slot=2147-zero-bytes"));
        assert!(descriptor.contains("relation-hashes-both-slots"));
        assert!(descriptor.contains("public-hash=output-flag-times-computed-digest"));
    }

    #[test]
    fn fixed_relation_manifest_binds_every_component_digest() {
        let manifest = v6_relation_manifest();
        assert_eq!(&manifest[..8], b"HGR6RM02");
        assert_eq!(manifest.len(), 546);
        let component_digests = [
            digest_statement_schema(),
            digest_semantic_domains(),
            sha512_descriptor(b"hegemon.swv6.projector.v2\0", PROJECTOR_DESCRIPTOR),
            sha512_descriptor(b"hegemon.swv6.qir.v2\0", FULL_RELATION_QIR_DESCRIPTOR),
            recompute_v6_hash_role_registry_digest(),
            sha512_descriptor(
                b"hegemon.swv6.ciphertext-grammar.v2\0",
                CIPHERTEXT_GRAMMAR_DESCRIPTOR,
            ),
            sha512_descriptor(
                b"hegemon.swv6.smallwood-inner-wire.v2\0",
                SMALLWOOD_INNER_WIRE_DESCRIPTOR,
            ),
            digest_proof_transcript_domains(),
        ];
        for digest in component_digests {
            assert_ne!(digest, [0; 64]);
            assert!(manifest.windows(64).any(|window| window == digest));
        }
        let binding = descriptor_v6_relation_binding();
        assert_ne!(binding, [0; 64]);
        assert_eq!(binding, descriptor_v6_relation_binding());
        assert_eq!(binding, recompute_v6_relation_binding());
        assert_eq!(
            hex::encode(binding),
            "7bc4270f9dc4b8c8e23a8c04abfa193dc820d4c90a49abf7370b8c862052e146d673e4b943bb251d6fc3167db96892c3c9c2598c6df88b7855541984251a5fc5"
        );
    }

    #[test]
    fn mixed_hash_registry_and_preamble_geometry_are_exact() {
        let registry = encode_v6_hash_role_registry();
        assert_eq!(&registry[..8], b"HGF6HR02");
        assert_eq!(registry.len(), 214);
        assert_eq!(
            recompute_v6_hash_role_registry_digest(),
            V6_HASH_ROLE_REGISTRY_DIGEST
        );
        assert_eq!(V6_PROOF_BINDING_DOMAIN.len(), 52);
        assert_eq!(V6_STRICT_SECURITY_PROFILE_ID.len(), 91);
        assert_eq!(V6_BINDING_PREAMBLE_PAYLOAD_BYTES, 1_114);
        assert_eq!(V6_BINDING_PREAMBLE_UNPADDED_BYTES, 1_128);
        assert_eq!(V6_BINDING_PREAMBLE_BYTES, 1_128);
        assert_eq!(V6_BINDING_PREAMBLE_ZERO_PAD_BYTES, 0);
        assert_eq!(V6_BINDING_PREAMBLE_WORDS, 141);
    }
}
