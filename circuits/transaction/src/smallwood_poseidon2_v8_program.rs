//! Canonical, statement-independent executable program for the V8 Poseidon2 relation.
//!
//! This module commits to the compiler *program*, not to one statement's instantiated linear
//! targets.  Public-dependent coefficients and targets are represented by a small symbolic DSL;
//! hashing a concrete statement's numeric CSR targets here would give different transaction
//! statements different relation identities.  The resulting digest names the program, but it is
//! not a production-authorization bit and does not certify executable refinement, proof-system
//! security, or activation of any consensus route.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha512};

use crate::smallwood_poseidon2_v8_ir::SmallwoodPoseidon2V8Expr;
use crate::smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID;
use crate::smallwood_poseidon2_v8_semantics::{
    smallwood_poseidon2_v8_csr_expression_program,
    smallwood_poseidon2_v8_nonlinear_expression_program,
};

pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC: [u8; 8] = *b"HGV8RP03";
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_GRAMMAR: u16 = 3;
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_SECTION_COUNT: u16 = 9;
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES: usize = 853_429;
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512_BYTES: usize = 64;
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES: usize = 48;
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_IS_PRODUCTION_AUTHORITY: bool = false;

pub const SMALLWOOD_POSEIDON2_V8_CIRCUIT_VERSION: u16 = 8;
pub const SMALLWOOD_POSEIDON2_V8_CRYPTO_SUITE: u16 = 7;
pub const SMALLWOOD_POSEIDON2_V8_FAMILY_ID: u16 = 1;
pub const SMALLWOOD_POSEIDON2_V8_ACTION_ID: u16 = 10;
pub const SMALLWOOD_POSEIDON2_V8_BACKEND_ID: u8 = 2;
pub const SMALLWOOD_POSEIDON2_V8_PROFILE_ID: u8 = 6;
pub const SMALLWOOD_POSEIDON2_V8_DOMAIN_SET: u16 = 4;
pub const SMALLWOOD_POSEIDON2_V8_INNER_MAGIC: [u8; 4] = *b"SMZ9";

pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS: usize = 120;
pub const SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS: usize = 7;
pub const SMALLWOOD_POSEIDON2_V8_ROW_COUNT: usize = 686;
pub const SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_POSEIDON2_V8_PROOF_COLUMNS: usize = 368;
pub const SMALLWOOD_POSEIDON2_V8_PACKED_WITNESS_WORDS: usize =
    SMALLWOOD_POSEIDON2_V8_ROW_COUNT * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR;
pub const SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE: usize = 8;
pub const SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS: usize = 830;
/// Exact number of nodes in the relation-id-bound nonlinear expression DAG.
pub const SMALLWOOD_POSEIDON2_V8_NONLINEAR_EXPRESSION_NODES: usize = 8_271;
pub const SMALLWOOD_POSEIDON2_V8_HASH_LIVE_CALLS: usize = 125;
pub const SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALLS: usize = 128;
pub const SMALLWOOD_POSEIDON2_V8_HASH_ROWS: usize = 364;
pub const SMALLWOOD_POSEIDON2_V8_AUXILIARY_WORDS: usize = 0;

pub const SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT: usize = 86;
pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_VERSION_DOMAIN_DESCRIPTOR_COUNT: usize = 56;
pub const SMALLWOOD_POSEIDON2_V8_GLOBAL_BINDING_DESCRIPTOR_COUNT: usize = 8;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_LINEAR_CONSTRAINTS: usize = 19_935;
pub const SMALLWOOD_POSEIDON2_V8_MAXIMUM_LINEAR_CONSTRAINTS: usize = 20_509;
pub const SMALLWOOD_POSEIDON2_V8_MAXIMUM_SUMMED_IDENTITY_UNION: usize = 21_339;
/// Number of compiler-family instances before public-shape specialization and normalized empty
/// rows are removed.  This is a DSL inventory count, not an emitted relation count.
pub const SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES: usize = 20_605;
/// Exact number of nodes in the public-only CSR specialization expression DAG.
pub const SMALLWOOD_POSEIDON2_V8_CSR_EXPRESSION_NODES: usize = 565;

/// Reduced Goldilocks-field encoding of the external `u64::MAX` balance-slot padding marker.
/// Padding is excluded from every active-note/stable-asset membership product.
pub const SMALLWOOD_POSEIDON2_V8_BALANCE_SLOT_PADDING_FIELD_ID: u64 = 4_294_967_294;

pub const SMALLWOOD_POSEIDON2_V8_POSEIDON_PARAMETER_SET_ID: &str =
    "hegemon-p2w16-v1-114a4e7eb2684d29";
pub const SMALLWOOD_POSEIDON2_V8_POSEIDON_PARAMETER_SHA256: [u8; 32] = [
    0x11, 0x4a, 0x4e, 0x7e, 0xb2, 0x68, 0x4d, 0x29, 0x3d, 0x13, 0xd3, 0x06, 0xa7, 0x56, 0xb0, 0x3f,
    0xc7, 0x34, 0xf1, 0x9e, 0xdb, 0xfb, 0x80, 0xa0, 0x71, 0x26, 0xab, 0x1b, 0x2a, 0xd9, 0xe5, 0x29,
];

pub const SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN: u64 = 0x4854_5838_494e_5400;
pub const SMALLWOOD_POSEIDON2_V8_SPONGE_MODE_MARKER: u64 = 0x5350_4f4e_4745_5631;
pub const SMALLWOOD_POSEIDON2_V8_SUITE_MARKER: u64 = 0x4845_475f_5032_3136;

/// Exact 37-word geometry section shared with
/// `Hegemon.Transaction.Poseidon2V8RelationProgram.requiredGeometryWords`.
pub const SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS: [u64; 37] = [
    18_446_744_069_414_584_321,
    16,
    8,
    8,
    7,
    7,
    8,
    22,
    120,
    7,
    0,
    247,
    247,
    5,
    252,
    31,
    283,
    364,
    647,
    39,
    686,
    64,
    8,
    125,
    128,
    3,
    2,
    150,
    182,
    166,
    332,
    830,
    19_935,
    20_509,
    21_339,
    368,
    43_904,
];

/// Pinned SHA-512 KAT for the canonical HGV8RP03 executable program transcript.
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512: [u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512_BYTES] = [
    0x7e, 0x50, 0xeb, 0xa0, 0x7d, 0x84, 0x43, 0x3a, 0x53, 0xa6, 0xc8, 0x5e, 0xd2, 0xb3, 0xef, 0xec,
    0xbe, 0xff, 0x10, 0x3c, 0xa4, 0x02, 0xbb, 0x93, 0x18, 0x31, 0xe1, 0x59, 0x8e, 0x6c, 0x9a, 0xb8,
    0xfa, 0x13, 0x8c, 0x9b, 0x2f, 0x0c, 0xb9, 0xd2, 0x1b, 0xf2, 0xbf, 0x04, 0x4b, 0x50, 0xd4, 0xd0,
    0x57, 0xae, 0x0b, 0xb1, 0x2e, 0x4d, 0xef, 0x00, 0xec, 0x52, 0x76, 0x52, 0x45, 0xcf, 0x9e, 0x17,
];

/// First 48 bytes of [`SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512`].  This value names a compiler
/// program; it does not authorize that program for production.
pub const SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST: [u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES] = [
    0x7e, 0x50, 0xeb, 0xa0, 0x7d, 0x84, 0x43, 0x3a, 0x53, 0xa6, 0xc8, 0x5e, 0xd2, 0xb3, 0xef, 0xec,
    0xbe, 0xff, 0x10, 0x3c, 0xa4, 0x02, 0xbb, 0x93, 0x18, 0x31, 0xe1, 0x59, 0x8e, 0x6c, 0x9a, 0xb8,
    0xfa, 0x13, 0x8c, 0x9b, 0x2f, 0x0c, 0xb9, 0xd2, 0x1b, 0xf2, 0xbf, 0x04, 0x4b, 0x50, 0xd4, 0xd0,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8PublicRangeDescriptor {
    pub name: &'static str,
    pub start: u16,
    pub end: u16,
}

pub const SMALLWOOD_POSEIDON2_V8_PUBLIC_MAP: [SmallwoodPoseidon2V8PublicRangeDescriptor; 28] = [
    public_range("input_flags", 0, 2),
    public_range("output_flags", 2, 4),
    public_range("input_nullifiers", 4, 18),
    public_range("output_commitments", 18, 32),
    public_range("ciphertext_hashes", 32, 44),
    public_range("fee", 44, 45),
    public_range("value_balance_sign", 45, 46),
    public_range("value_balance_magnitude", 46, 47),
    public_range("merkle_root", 47, 54),
    public_range("balance_assets", 54, 58),
    public_range("compat_stable_enabled", 58, 59),
    public_range("compat_stable_asset", 59, 60),
    public_range("compat_stable_policy_version", 60, 61),
    public_range("compat_stable_issuance_sign", 61, 62),
    public_range("compat_stable_issuance_magnitude", 62, 63),
    public_range("reserved_legacy_stablecoin_commitments", 63, 81),
    public_range("circuit_version", 81, 82),
    public_range("crypto_suite", 82, 83),
    public_range("stable_direction", 83, 84),
    public_range("stable_asset", 84, 85),
    public_range("stable_policy_version", 85, 86),
    public_range("stable_magnitude", 86, 87),
    public_range("action_intent", 87, 94),
    public_range("parent_height", 94, 95),
    public_range("stable_before_root", 95, 102),
    public_range("stable_after_root", 102, 109),
    public_range("stable_after_counters", 109, 113),
    public_range("issuer_authorization", 113, 120),
];

pub const SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_RANGES: [SmallwoodPoseidon2V8PublicRangeDescriptor;
    4] = [
    public_range("input_nullifiers", 4, 18),
    public_range("merkle_root", 47, 54),
    public_range("action_intent", 87, 94),
    public_range("issuer_authorization", 113, 120),
];

const fn public_range(
    name: &'static str,
    start: u16,
    end: u16,
) -> SmallwoodPoseidon2V8PublicRangeDescriptor {
    SmallwoodPoseidon2V8PublicRangeDescriptor { name, start, end }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8DomainDescriptor {
    pub name: &'static str,
    pub value: u64,
}

pub const SMALLWOOD_POSEIDON2_V8_DOMAINS: [SmallwoodPoseidon2V8DomainDescriptor; 21] = [
    domain("note", 1),
    domain("nullifier_and_spend_prf", 2),
    domain("transaction_merkle_node", 4),
    domain("authorization_accumulator", 6),
    domain("authorization_policy", 7),
    domain("authorization_value_lock", 8),
    domain("action_intent", SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN),
    domain("stable_config_chunk_0", 0x4853_4338_4346_3000),
    domain("stable_config_chunk_1", 0x4853_4338_4346_3100),
    domain("stable_config_chunk_2", 0x4853_4338_4346_3200),
    domain("stable_config_chunk_3", 0x4853_4338_4346_3300),
    domain("stable_config_node_0", 0x4853_4338_434e_3000),
    domain("stable_config_node_1", 0x4853_4338_434e_3100),
    domain("stable_config_root", 0x4853_4338_4346_5200),
    domain("stable_state_leaf", 0x4853_4338_4c45_4146),
    domain("stable_state_node_0", 0x4853_4338_4e4f_4400),
    domain("stable_state_node_1", 0x4853_4338_4e4f_4401),
    domain("stable_state_node_2", 0x4853_4338_4e4f_4402),
    domain("stable_state_node_3", 0x4853_4338_4e4f_4403),
    domain("stable_issuer_commitment", 0x4853_4338_4953_434d),
    domain("stable_issuer_authorization", 0x4853_4338_4953_4155),
];

const fn domain(name: &'static str, value: u64) -> SmallwoodPoseidon2V8DomainDescriptor {
    SmallwoodPoseidon2V8DomainDescriptor { name, value }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8NonlinearFamilySpan {
    pub name: &'static str,
    pub count: u16,
}

const NONLINEAR_PREFIX_SPANS: &[SmallwoodPoseidon2V8NonlinearFamilySpan] = &[
    nonlinear_span("base.public_boolean", 7),
    nonlinear_span("base.stable_direction_domain", 1),
    nonlinear_span("base.stable_compatibility", 5),
    nonlinear_span("base.reserved_compatibility_zero", 18),
    nonlinear_span("base.input_direction_boolean", 32),
    nonlinear_span("base.input_asset_membership_excluding_padding", 1),
    nonlinear_span("base.input_direction_boolean", 32),
    nonlinear_span("base.input_asset_membership_excluding_padding", 1),
    nonlinear_span("base.output_asset_membership_excluding_padding", 1),
    nonlinear_span("base.output_inactive_ciphertext", 6),
    nonlinear_span("base.output_asset_membership_excluding_padding", 1),
    nonlinear_span("base.output_inactive_ciphertext", 6),
    nonlinear_span("base.stable_asset_membership_excluding_padding", 1),
    nonlinear_span("base.per_asset_balance", 4),
    nonlinear_span("base.dense_radix4_digit", 4),
    nonlinear_span("base.dense_top_boolean", 1),
    nonlinear_span("base.merkle_orientation", 7),
    nonlinear_span("base.policy_root_match", 1),
    nonlinear_span("auth.mode_boolean", 3),
    nonlinear_span("auth.mode_one_hot", 1),
    nonlinear_span("auth.single_mode_canonical_zero", 109),
    nonlinear_span("auth.effective_input_prf", 1),
    nonlinear_span("auth.effective_input_key", 4),
    nonlinear_span("auth.effective_input_prf", 1),
    nonlinear_span("auth.effective_input_key", 4),
    nonlinear_span("auth.approval_final_activity", 5),
    nonlinear_span("auth.approval_output_key", 4),
    nonlinear_span("auth.threshold_signer_encoding", 17),
    nonlinear_span("auth.count_transition", 20),
    nonlinear_span("auth.approval_bitmaps", 26),
    nonlinear_span("auth.membership_transition", 57),
    nonlinear_span("auth.inactive_policy_tags", 30),
    nonlinear_span("auth.signer_tag_distinctness", 30),
    nonlinear_span("auth.final_mode", 30),
];

const fn nonlinear_span(name: &'static str, count: u16) -> SmallwoodPoseidon2V8NonlinearFamilySpan {
    SmallwoodPoseidon2V8NonlinearFamilySpan { name, count }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8NonlinearDescriptor {
    pub global_index: u16,
    pub family: &'static str,
    pub local_index: u16,
    pub coordinate_0: u16,
    pub coordinate_1: u16,
}

/// Return all 830 identities in evaluator order.  Hash coordinates are `(group, round*16+lane)`
/// for full-round wires, `(group, round)` for partial-round wires, and `(group, lane)` for final
/// state bindings.  Non-hash families use zero coordinates and their explicit local index.
pub fn smallwood_poseidon2_v8_nonlinear_descriptors() -> Vec<SmallwoodPoseidon2V8NonlinearDescriptor>
{
    let mut out = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS);
    // The evaluator interleaves input/output families. A split span resumes its family's
    // local index rather than restarting at zero; hash groups below retain their coordinates.
    let mut next_local = std::collections::BTreeMap::<&'static str, u16>::new();
    for span in NONLINEAR_PREFIX_SPANS {
        let local_index = next_local.entry(span.name).or_default();
        for _ in 0..span.count {
            push_nonlinear(&mut out, span.name, *local_index, 0, 0);
            *local_index = local_index
                .checked_add(1)
                .expect("prefix family count fits u16");
        }
    }
    debug_assert_eq!(out.len(), 471);
    for group in 0..2u16 {
        for round in 0..4u16 {
            for lane in 0..16u16 {
                push_nonlinear(
                    &mut out,
                    "poseidon.external_initial_sbox_wire",
                    round * 16 + lane,
                    group,
                    round * 16 + lane,
                );
            }
        }
        for round in 0..22u16 {
            push_nonlinear(&mut out, "poseidon.internal_sbox_wire", round, group, round);
        }
        for round in 0..4u16 {
            for lane in 0..16u16 {
                push_nonlinear(
                    &mut out,
                    "poseidon.external_terminal_sbox_wire",
                    round * 16 + lane,
                    group,
                    round * 16 + lane,
                );
            }
        }
        for lane in 0..16u16 {
            push_nonlinear(&mut out, "poseidon.final_state", lane, group, lane);
        }
    }
    debug_assert_eq!(out.len(), 803);
    push_nonlinear(&mut out, "stable.role_selector_domain", 0, 0, 0);
    push_nonlinear(&mut out, "stable.selected_role_inverse", 0, 0, 0);
    push_nonlinear(&mut out, "stable.boolean_row", 0, 0, 0);
    push_nonlinear(&mut out, "stable.mul_row", 0, 0, 0);
    for row in 0..23u16 {
        push_nonlinear(&mut out, "stable.radix4_row", row, row, 0);
    }
    debug_assert_eq!(out.len(), SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS);
    out
}

fn push_nonlinear(
    out: &mut Vec<SmallwoodPoseidon2V8NonlinearDescriptor>,
    family: &'static str,
    local_index: u16,
    coordinate_0: u16,
    coordinate_1: u16,
) {
    out.push(SmallwoodPoseidon2V8NonlinearDescriptor {
        global_index: u16::try_from(out.len()).expect("830 V8 identities fit u16"),
        family,
        local_index,
        coordinate_0,
        coordinate_1,
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8CsrEmission {
    Always,
    NormalizeDropEmptyZero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8SymbolicCsrFamily {
    pub name: &'static str,
    pub instances: u32,
    pub index_program: &'static str,
    pub coefficient_program: &'static str,
    pub target_program: &'static str,
    pub emission: SmallwoodPoseidon2V8CsrEmission,
}

macro_rules! csr {
    ($name:literal, $instances:expr, $indices:literal, $coefficients:literal, $target:literal, $emission:ident) => {
        SmallwoodPoseidon2V8SymbolicCsrFamily {
            name: $name,
            instances: $instances,
            index_program: $indices,
            coefficient_program: $coefficients,
            target_program: $target,
            emission: SmallwoodPoseidon2V8CsrEmission::$emission,
        }
    };
}

/// Ordered compact DSL for every CSR-producing compiler loop.  `public[i]` denotes a symbolic
/// public word, never the word's value in one statement.  Index expressions are packed witness
/// coordinates under the fixed 686-by-64 geometry.  The union contains 20,605 row programs;
/// BTree index normalization, coefficient folding, zero-term deletion, and empty-zero deletion
/// are themselves committed in the descriptor header.
pub const SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES: [SmallwoodPoseidon2V8SymbolicCsrFamily;
    SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT] = [
    csr!(
        "base.raw_replicate",
        15_561,
        "w[row,lane],w[row,0]",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "base.input_inactive_raw",
        68,
        "w[input_row]",
        "1-public[input_flag]",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "base.output_inactive_raw",
        24,
        "w[output_row]",
        "1-public[output_flag]",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "base.output_ciphertext_bridge",
        12,
        "w[output_ciphertext_limb]",
        "1",
        "public[32+output*6+limb]",
        Always
    ),
    csr!(
        "base.dense_range_reconstruct",
        7,
        "value_source,dense_digits[30],dense_top",
        "1,-4^digit,-2^60",
        "symbolic_public_constant_negated",
        Always
    ),
    csr!(
        "base.transparent_value_balance_zero",
        2,
        "stable.source[120]",
        "1",
        "public[45_or_46]",
        Always
    ),
    csr!(
        "base.dense_range_padding",
        46,
        "w[dense_slot_210_255]",
        "1",
        "0",
        Always
    ),
    csr!(
        "base.dense_top_padding",
        57,
        "w[dense_top_lane_7_63]",
        "1",
        "0",
        Always
    ),
    csr!(
        "base.spend_key_inactive",
        8,
        "w[stable_source_112+input*4+limb]",
        "1-public[input]",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "base.spend_key_equal",
        4,
        "w[key0],w[key1]",
        "public[0]*public[1],-public[0]*public[1]",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "hash.transaction_prf_initial",
        16,
        "hash_initial[0,lane],spend_source",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "hash.transaction_prf_to_legacy",
        5,
        "raw.auth_legacy[limb],hash_final[0,limb]",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "hash.input_note_initial",
        72,
        "hash_initial[input_note_call+block,lane],semantic_or_prior",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "base.input_note_inactive_preimage",
        36,
        "absorbed_input[input,index]",
        "1-public[input]",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "hash.input_merkle_initial",
        1_024,
        "hash_initial[merkle_call,lane],inline_left_right",
        "compress14_v1",
        "domain_and_suite",
        Always
    ),
    csr!(
        "base.input_merkle_current_copy",
        448,
        "inline.current,prior_digest",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "base.input_merkle_direction_copy",
        448,
        "inline.direction,raw.direction",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "base.input_merkle_inactive_right",
        448,
        "inline.right",
        "1-public[input]",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "base.input_merkle_public_root",
        14,
        "hash_final[root_call,limb]",
        "public[input]",
        "public[input]*public[47+limb]",
        NormalizeDropEmptyZero
    ),
    csr!(
        "hash.input_nullifier_initial",
        32,
        "hash_initial[nullifier_call,lane],auth_prf_position_rho",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "base.input_nullifier_public",
        14,
        "hash_final[nullifier_call,limb]",
        "public[input]",
        "public[input]*public[4+input*7+limb]",
        NormalizeDropEmptyZero
    ),
    csr!(
        "hash.output_note_initial",
        72,
        "hash_initial[output_note_call+block,lane],semantic_or_prior",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "base.output_note_inactive_preimage",
        36,
        "absorbed_output[output,index]",
        "1-public[2+output]",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "base.output_commitment_public",
        14,
        "hash_final[output_note_final,limb]",
        "public[2+output]",
        "public[2+output]*public[18+output*7+limb]",
        NormalizeDropEmptyZero
    ),
    csr!(
        "hash.action_intent_initial",
        240,
        "hash_initial[79+block,lane],public_projection_or_prior",
        "sponge_v1",
        "projection(public;zero=[4,18),[47,54),[87,94),[113,120))",
        Always
    ),
    csr!(
        "auth.intent_digest_copy",
        7,
        "raw.auth_statement[limb],hash_final[93,limb]",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "hash.authorization_policy_initial",
        64,
        "hash_initial[94+block,lane],policy_source_or_prior",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "auth.policy_inline_bindings",
        21,
        "inline.policy_actual_expected_gate",
        "1,-1",
        "0_or_mode_sum",
        Always
    ),
    csr!(
        "auth.policy_inline_padding",
        171,
        "inline.policy_rows[lane_7_63]",
        "1",
        "0",
        Always
    ),
    csr!(
        "hash.authorization_current_initial",
        48,
        "hash_initial[98+block,lane],current_accumulator_or_prior",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "auth.current_digest_copy",
        7,
        "raw.auth_current[limb],hash_final[100,limb]",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "hash.authorization_next_initial",
        48,
        "hash_initial[101+block,lane],effective_next_accumulator_or_prior",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "auth.next_digest_copy",
        7,
        "raw.auth_next[limb],hash_final[103,limb]",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "hash.authorization_value_lock_initial",
        32,
        "hash_initial[104+block,lane],policy_intent_or_prior",
        "sponge_v1",
        "domain_len_mode_pad_suite",
        Always
    ),
    csr!(
        "auth.value_lock_digest_copy",
        7,
        "raw.auth_value_lock[limb],hash_final[105,limb]",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "hash.padding_initial_zero",
        48,
        "hash_initial[call_125_127,lane]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.disabled_private_source",
        94,
        "stable.source[0_93]",
        "1-enabled(public[83])",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.compatibility_source_copy",
        18,
        "stable.source[94_111]",
        "1",
        "public[63_80]",
        Always
    ),
    csr!(
        "stable.compatibility_source_zero",
        18,
        "stable.source[94_111]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.source_padding",
        8,
        "stable.source[120_127]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.issuer_secret_nonmint_zero",
        7,
        "stable.source[83_89]",
        "1-mint(public[83])",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.burn_authorization_zero",
        7,
        "stable.source[120]",
        "1",
        "burn(public[83])*public[113+limb]",
        Always
    ),
    csr!(
        "stable.public_scalar_bridge",
        2,
        "stable.source[0_1]",
        "1",
        "public[84_85]",
        Always
    ),
    csr!(
        "stable.direction_flags",
        3,
        "stable.bool[0_2]",
        "1",
        "enabled,mint,burn(public[83])",
        Always
    ),
    csr!(
        "stable.boolean_source_copy",
        4,
        "stable.bool[3_6],stable.source[2,4,21,22]",
        "1,-1",
        "0",
        Always
    ),
    csr!(
        "stable.asset_index_bits",
        4,
        "stable.bool[7_10]",
        "1",
        "bit(public[84]&15)",
        Always
    ),
    csr!(
        "stable.boolean_padding",
        11,
        "stable.bool[53_63]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.role_live_diff",
        210,
        "stable.role_diff[limb=0..6,condition=0..29];condition[0..20]=stable-role;condition21=nonzero-selected-spend-key;condition22=nonzero-policy;condition23=nonzero-intent;condition[24..29]=nonzero-signer-tag[0..5]",
        "bind(lhs,selected-expression(condition,limb));inactive-arm=unit-digest",
        "0",
        Always
    ),
    csr!(
        "stable.role_padding_unit",
        34,
        "stable.role_diff[0,condition=30..63]",
        "1",
        "1",
        Always
    ),
    csr!(
        "stable.role_padding_limbs",
        204,
        "stable.role_diff[limb=1..6,condition=30..63]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.role_padding_selector",
        34,
        "stable.role_selector[condition=30..63]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.role_padding_inverse",
        34,
        "stable.role_inverse[condition=30..63]",
        "1",
        "1",
        Always
    ),
    csr!(
        "hash.stable_config_chunk_initial",
        64,
        "hash_initial[106_109,lane],stable_config_chunk",
        "compress14_v1",
        "chunk_domain_and_suite",
        Always
    ),
    csr!(
        "hash.stable_config_tree_initial",
        48,
        "hash_initial[110_112,lane],prior_digest",
        "compress14_v1",
        "tree_domain_and_suite",
        Always
    ),
    csr!(
        "hash.stable_state_leaf_initial",
        32,
        "hash_initial[113_114,lane],config_digest_counters_index",
        "compress14_v1",
        "state_leaf_domain_and_suite",
        Always
    ),
    csr!(
        "hash.stable_path_initial",
        128,
        "hash_initial[115_122,lane],oriented_prior_and_sibling",
        "compress14_v1",
        "state_node_domain(level)_and_suite",
        Always
    ),
    csr!(
        "stable.public_roots",
        14,
        "hash_final[121_122,limb]",
        "enabled(public[83]);before-attempt disabled arm binds public[95+limb]-public[102+limb]",
        "enabled*public[95_108] or disabled root pass-through",
        NormalizeDropEmptyZero
    ),
    csr!(
        "hash.stable_issuer_initial",
        32,
        "hash_initial[123_124,lane],issuer_secret_and_public",
        "compress14_v1",
        "issuer_domain_and_suite",
        Always
    ),
    csr!(
        "stable.issuer_commitment",
        7,
        "hash_final[123,limb],stable.source[6+limb]",
        "mint,-mint",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.issuer_authorization",
        7,
        "hash_final[124,limb]",
        "mint",
        "mint*public[113+limb]",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.range_reconstruct",
        66,
        "range_source,stable.radix4_digits,optional_top_bool",
        "1,-4^digit,-2^(bits-1)",
        "symbolic_public_constant_negated",
        Always
    ),
    csr!(
        "stable.range_padding",
        38,
        "stable.range[1434_1471]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.high_limb_digit_padding",
        24,
        "stable.range[listed_start+12_15]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.asset_index_reconstruct",
        1,
        "public[84],numeric[0],bool[7_10]",
        "symbolic",
        "0",
        Always
    ),
    csr!(
        "stable.decimals_reconstruct",
        1,
        "source[46],bool[12_16]",
        "1,-2^bit",
        "0",
        Always
    ),
    csr!(
        "stable.decimal_slack",
        1,
        "source[46],bool[17_21]",
        "1,2^bit",
        "18*enabled",
        Always
    ),
    csr!(
        "stable.decimal_scale",
        1,
        "source[47],numeric[17]",
        "enabled,-enabled",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.epoch_counter_caps",
        7,
        "source,numeric,mul_c16,public[86,94,109_112]",
        "symbolic;parent_height_epoch_equation_enabled-gated",
        "symbolic_public",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.mint_config_canonical",
        4,
        "source[2,21,22,13],numeric[8]",
        "mint",
        "mint_literals",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.nonmint_numeric_zero",
        8,
        "numeric[1_8]",
        "1-mint",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.nonmint_collateral_zero",
        28,
        "numeric[18_45]",
        "1-mint",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.nonmint_borrow_zero",
        4,
        "bool[22_25]",
        "1-mint",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!("stable.final_borrow_zero", 1, "bool[25]", "1", "0", Always),
    csr!(
        "stable.decimal_power_mul_bindings",
        15,
        "mul_a_b_c[0_4] and numeric/bool",
        "symbolic",
        "0_or_1",
        Always
    ),
    csr!(
        "stable.epoch_zero_mux_bindings",
        7,
        "mul_a_b_c[15_17],numeric,bool,source",
        "symbolic",
        "0_or_1",
        Always
    ),
    csr!(
        "stable.time_additions",
        15,
        "range_halves,bool_carry",
        "mint symbolic low/high;1-mint carry",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.retirement_gate_bindings",
        8,
        "mul_a_c[25_28],source[4]",
        "symbolic",
        "0",
        Always
    ),
    csr!(
        "stable.retirement_residual_bindings",
        4,
        "mul_b[25_28],range_halves,bool_carry",
        "symbolic",
        "0",
        Always
    ),
    csr!(
        "stable.retired_present_gate",
        3,
        "mul_a_b_c[24],source[4,5]",
        "symbolic",
        "0_or_1",
        Always
    ),
    csr!(
        "stable.retirement_canonical_helpers",
        12,
        "mul_a_b_c[29_32],mul_a25,numeric,bool",
        "symbolic",
        "0_or_1",
        Always
    ),
    csr!(
        "stable.collateral_limb_reconstruct",
        2,
        "source[19],public[111],numeric[18,19,30,31]",
        "mint symbolic",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.collateral_product_bindings",
        30,
        "mul_a_b_c[5_14],numeric,source",
        "symbolic 2^32 and 10^6",
        "0",
        Always
    ),
    csr!(
        "stable.collateral_subtraction",
        4,
        "numeric[24_27,36_39,42_45],bool[22_25]",
        "mint symbolic 2^32",
        "0",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.max_carry_inverse",
        18,
        "mul_a_b_c[18_23],numeric[23,28,29,35,40,41]",
        "1,1-mint",
        "mint_or_(2^32-1-carry)",
        NormalizeDropEmptyZero
    ),
    csr!(
        "stable.mul_padding",
        93,
        "mul_a_b_c[33_63]",
        "1",
        "0",
        Always
    ),
    csr!(
        "stable.numeric_padding",
        18,
        "numeric[46_63]",
        "1",
        "0",
        Always
    ),
];

/// Source-derived compiler receipt for one statement specialization.  The executable builder
/// must name the canonical family for every attempted CSR row.  This keeps a source edit from
/// silently moving, adding, or deleting a compiler loop while the transcript KAT remains green.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8CsrFamilyReceipt {
    pub attempted_instances: [u32; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT],
    pub emitted_instances: [u32; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT],
    pub emitted_total: u32,
}

impl SmallwoodPoseidon2V8CsrFamilyReceipt {
    /// Normalized CSR row span for one family.  Families execute in transcript order, so emitted
    /// rows for each family are contiguous even when individual empty-zero attempts are dropped.
    pub fn emitted_span(&self, family_index: usize) -> Option<core::ops::Range<u32>> {
        let count = *self.emitted_instances.get(family_index)?;
        let start = self.emitted_instances[..family_index]
            .iter()
            .copied()
            .sum::<u32>();
        Some(start..start + count)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8CsrProgramDrift {
    FamilyOutOfOrder {
        attempt: u32,
        expected_family: u16,
        actual_family: u16,
    },
    AttemptAfterProgramEnd {
        attempt: u32,
        actual_family: u16,
    },
    AlwaysFamilyDropped {
        attempt: u32,
        family: u16,
    },
    ProgramIncomplete {
        attempted: u32,
        expected: u32,
        next_family: u16,
    },
    EmittedCountOutOfRange {
        emitted: u32,
        minimum: u32,
        maximum: u32,
    },
}

/// Fail-closed cursor used by the executable `CsrBuilder` refinement gate.  Call
/// [`Self::record_attempt`] before/after normalization for each source `push`, passing whether
/// normalization emitted a row, then call [`Self::finish`] exactly once.
#[derive(Clone, Debug)]
pub struct SmallwoodPoseidon2V8CsrProgramCursor {
    current_family: usize,
    attempted_total: u32,
    attempted_instances: [u32; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT],
    emitted_instances: [u32; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT],
}

impl Default for SmallwoodPoseidon2V8CsrProgramCursor {
    fn default() -> Self {
        Self {
            current_family: 0,
            attempted_total: 0,
            attempted_instances: [0; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT],
            emitted_instances: [0; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT],
        }
    }
}

impl SmallwoodPoseidon2V8CsrProgramCursor {
    pub fn new() -> Self {
        Self::default()
    }

    fn advance_completed_families(&mut self) {
        while let Some(family) =
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES.get(self.current_family)
        {
            if self.attempted_instances[self.current_family] != family.instances {
                break;
            }
            self.current_family += 1;
        }
    }

    pub fn record_attempt(
        &mut self,
        family_index: usize,
        emitted: bool,
    ) -> Result<(), SmallwoodPoseidon2V8CsrProgramDrift> {
        self.advance_completed_families();
        let Some(family) = SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES.get(self.current_family)
        else {
            return Err(
                SmallwoodPoseidon2V8CsrProgramDrift::AttemptAfterProgramEnd {
                    attempt: self.attempted_total,
                    actual_family: u16::try_from(family_index).unwrap_or(u16::MAX),
                },
            );
        };
        if family_index != self.current_family {
            return Err(SmallwoodPoseidon2V8CsrProgramDrift::FamilyOutOfOrder {
                attempt: self.attempted_total,
                expected_family: u16::try_from(self.current_family)
                    .expect("86 family indices fit u16"),
                actual_family: u16::try_from(family_index).unwrap_or(u16::MAX),
            });
        }
        if !emitted && family.emission == SmallwoodPoseidon2V8CsrEmission::Always {
            return Err(SmallwoodPoseidon2V8CsrProgramDrift::AlwaysFamilyDropped {
                attempt: self.attempted_total,
                family: u16::try_from(family_index).expect("86 family indices fit u16"),
            });
        }
        self.attempted_instances[family_index] += 1;
        if emitted {
            self.emitted_instances[family_index] += 1;
        }
        self.attempted_total += 1;
        Ok(())
    }

    pub fn finish(
        mut self,
    ) -> Result<SmallwoodPoseidon2V8CsrFamilyReceipt, SmallwoodPoseidon2V8CsrProgramDrift> {
        self.advance_completed_families();
        if self.current_family != SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT {
            return Err(SmallwoodPoseidon2V8CsrProgramDrift::ProgramIncomplete {
                attempted: self.attempted_total,
                expected: u32::try_from(SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES)
                    .expect("V8 family instances fit u32"),
                next_family: u16::try_from(self.current_family).expect("86 family indices fit u16"),
            });
        }
        let emitted_total = self.emitted_instances.iter().copied().sum::<u32>();
        let minimum = u32::try_from(SMALLWOOD_POSEIDON2_V8_MINIMUM_LINEAR_CONSTRAINTS)
            .expect("V8 minimum linear count fits u32");
        let maximum = u32::try_from(SMALLWOOD_POSEIDON2_V8_MAXIMUM_LINEAR_CONSTRAINTS)
            .expect("V8 maximum linear count fits u32");
        if !(minimum..=maximum).contains(&emitted_total) {
            return Err(
                SmallwoodPoseidon2V8CsrProgramDrift::EmittedCountOutOfRange {
                    emitted: emitted_total,
                    minimum,
                    maximum,
                },
            );
        }
        Ok(SmallwoodPoseidon2V8CsrFamilyReceipt {
            attempted_instances: self.attempted_instances,
            emitted_instances: self.emitted_instances,
            emitted_total,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashMode {
    SpongeV1,
    Compress14V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8HashCallDescriptor {
    pub index: u16,
    pub role: &'static str,
    pub role_arg_0: u16,
    pub role_arg_1: u16,
    pub mode: SmallwoodPoseidon2V8HashMode,
    pub domain: u64,
    pub input_words: u16,
    pub block: u8,
    pub blocks: u8,
    pub left_or_preimage_binding: &'static str,
    pub right_binding: &'static str,
    pub output_binding: &'static str,
}

/// Build the gap-free 125-call role and binding program.  For sponge calls, `block`, `blocks`,
/// `input_words`, and the named preimage determine every initial lane under `rate8-sponge-v1`:
/// later blocks add the prior final rate lanes, and the first/final capacity lanes bind domain,
/// length, mode, final marker, and suite.  For `compress14-v1`, the two named seven-limb operands
/// occupy lanes `[0,7)` and `[7,14)`, with domain and suite in lanes 14 and 15.
pub fn smallwood_poseidon2_v8_hash_call_descriptors() -> Vec<SmallwoodPoseidon2V8HashCallDescriptor>
{
    let mut out = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_HASH_LIVE_CALLS);
    push_sponge_calls(
        &mut out,
        "transaction_prf",
        0,
        0,
        2,
        4,
        "transaction_spend_key",
        "transaction_prf_digest",
    );
    for input in 0..2u16 {
        push_sponge_calls(
            &mut out,
            "input_note",
            input,
            0,
            1,
            18,
            "input_note_opening",
            "input_note_digest",
        );
        for level in 0..32u16 {
            push_compress_call(
                &mut out,
                "input_merkle",
                input,
                level,
                4,
                "oriented_input_current",
                "oriented_input_sibling",
                "input_merkle_node_digest",
            );
        }
        push_sponge_calls(
            &mut out,
            "input_nullifier",
            input,
            0,
            2,
            6,
            "input_auth_prf_position_rho",
            "input_nullifier_digest",
        );
    }
    for output in 0..2u16 {
        push_sponge_calls(
            &mut out,
            "output_note",
            output,
            0,
            1,
            18,
            "output_note_opening",
            "output_note_digest",
        );
    }
    push_sponge_calls(
        &mut out,
        "action_intent",
        0,
        0,
        SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN,
        120,
        "public_action_intent_projection",
        "action_intent_digest",
    );
    push_sponge_calls(
        &mut out,
        "authorization_policy",
        0,
        0,
        7,
        32,
        "authorization_policy_opening",
        "authorization_policy_digest",
    );
    push_sponge_calls(
        &mut out,
        "authorization_current",
        0,
        0,
        6,
        23,
        "authorization_current_opening",
        "authorization_current_digest",
    );
    push_sponge_calls(
        &mut out,
        "authorization_next",
        0,
        0,
        6,
        23,
        "authorization_effective_next_opening",
        "authorization_next_digest",
    );
    push_sponge_calls(
        &mut out,
        "authorization_value_lock",
        0,
        0,
        8,
        14,
        "authorization_policy_and_intent",
        "authorization_value_lock_digest",
    );
    let chunk_domains = [
        0x4853_4338_4346_3000,
        0x4853_4338_4346_3100,
        0x4853_4338_4346_3200,
        0x4853_4338_4346_3300,
    ];
    for (chunk, domain) in chunk_domains.into_iter().enumerate() {
        push_compress_call(
            &mut out,
            "stable_config_chunk",
            chunk as u16,
            0,
            domain,
            "stable_config_chunk_left",
            "stable_config_chunk_right_zero_padded",
            "stable_config_chunk_digest",
        );
    }
    push_compress_call(
        &mut out,
        "stable_config_node",
        0,
        0,
        0x4853_4338_434e_3000,
        "call_106_digest",
        "call_107_digest",
        "stable_config_node_digest",
    );
    push_compress_call(
        &mut out,
        "stable_config_node",
        1,
        0,
        0x4853_4338_434e_3100,
        "call_108_digest",
        "call_109_digest",
        "stable_config_node_digest",
    );
    push_compress_call(
        &mut out,
        "stable_config_root",
        0,
        0,
        0x4853_4338_4346_5200,
        "call_110_digest",
        "call_111_digest",
        "stable_config_root_digest",
    );
    push_compress_call(
        &mut out,
        "stable_state_leaf",
        0,
        0,
        0x4853_4338_4c45_4146,
        "call_112_digest",
        "stable_before_counters_and_index",
        "stable_before_leaf_digest",
    );
    push_compress_call(
        &mut out,
        "stable_state_leaf",
        1,
        0,
        0x4853_4338_4c45_4146,
        "call_112_digest",
        "stable_after_public_counters_and_index",
        "stable_after_leaf_digest",
    );
    for level in 0..4u16 {
        for after in 0..2u16 {
            push_compress_call(
                &mut out,
                "stable_path",
                after,
                level,
                0x4853_4338_4e4f_4400 + u64::from(level),
                "oriented_stable_path_current",
                "oriented_stable_path_sibling",
                "stable_path_node_digest",
            );
        }
    }
    push_compress_call(
        &mut out,
        "stable_issuer_commitment",
        0,
        0,
        0x4853_4338_4953_434d,
        "stable_issuer_secret",
        "stable_asset_policy_and_zero",
        "stable_issuer_commitment_digest",
    );
    push_compress_call(
        &mut out,
        "stable_issuer_authorization",
        0,
        0,
        0x4853_4338_4953_4155,
        "stable_issuer_secret",
        "public_action_intent",
        "stable_issuer_authorization_digest",
    );
    debug_assert_eq!(out.len(), SMALLWOOD_POSEIDON2_V8_HASH_LIVE_CALLS);
    out
}

#[allow(clippy::too_many_arguments)]
fn push_sponge_calls(
    out: &mut Vec<SmallwoodPoseidon2V8HashCallDescriptor>,
    role: &'static str,
    role_arg_0: u16,
    role_arg_1: u16,
    domain: u64,
    input_words: u16,
    preimage: &'static str,
    digest: &'static str,
) {
    let blocks = input_words.max(1).div_ceil(8) as u8;
    for block in 0..blocks {
        out.push(SmallwoodPoseidon2V8HashCallDescriptor {
            index: u16::try_from(out.len()).expect("125 calls fit u16"),
            role,
            role_arg_0,
            role_arg_1,
            mode: SmallwoodPoseidon2V8HashMode::SpongeV1,
            domain,
            input_words,
            block,
            blocks,
            left_or_preimage_binding: preimage,
            right_binding: if block == 0 {
                "sponge_first_block"
            } else {
                "sponge_add_prior_final"
            },
            output_binding: if block + 1 == blocks {
                digest
            } else {
                "next_sponge_call"
            },
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn push_compress_call(
    out: &mut Vec<SmallwoodPoseidon2V8HashCallDescriptor>,
    role: &'static str,
    role_arg_0: u16,
    role_arg_1: u16,
    domain: u64,
    left: &'static str,
    right: &'static str,
    digest: &'static str,
) {
    out.push(SmallwoodPoseidon2V8HashCallDescriptor {
        index: u16::try_from(out.len()).expect("125 calls fit u16"),
        role,
        role_arg_0,
        role_arg_1,
        mode: SmallwoodPoseidon2V8HashMode::Compress14V1,
        domain,
        input_words: 14,
        block: 0,
        blocks: 1,
        left_or_preimage_binding: left,
        right_binding: right,
        output_binding: digest,
    });
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8ProgramDescriptor {
    pub opcode: u16,
    pub words: Vec<u64>,
    pub label: String,
}

#[derive(Default)]
struct CanonicalEncoder {
    bytes: Vec<u8>,
}

impl CanonicalEncoder {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn blob(&mut self, value: &[u8]) {
        self.u32(u32::try_from(value.len()).expect("V8 transcript blob length fits u32"));
        self.bytes.extend_from_slice(value);
    }

    fn descriptor(&mut self, descriptor: &SmallwoodPoseidon2V8ProgramDescriptor) {
        debug_assert!(descriptor.label.is_ascii());
        self.u16(descriptor.opcode);
        self.u16(u16::try_from(descriptor.words.len()).expect("descriptor word count fits u16"));
        for word in &descriptor.words {
            self.u64(*word);
        }
        self.blob(descriptor.label.as_bytes());
    }

    fn descriptors(&mut self, descriptors: &[SmallwoodPoseidon2V8ProgramDescriptor]) {
        self.u32(u32::try_from(descriptors.len()).expect("descriptor count fits u32"));
        for descriptor in descriptors {
            self.descriptor(descriptor);
        }
    }

    fn section(&mut self, tag: u16, item_count: usize, payload: &[u8]) {
        self.u16(tag);
        self.u32(u32::try_from(item_count).expect("V8 section item count fits u32"));
        self.u64(u64::try_from(payload.len()).expect("V8 section payload length fits u64"));
        self.bytes.extend_from_slice(payload);
    }
}

fn expression_payload(expressions: &[SmallwoodPoseidon2V8Expr], roots: &[u32]) -> Vec<u8> {
    let mut out = CanonicalEncoder::default();
    out.u32(u32::try_from(expressions.len()).expect("V8 expression count fits u32"));
    for expression in expressions {
        match *expression {
            SmallwoodPoseidon2V8Expr::Constant(value) => {
                out.u8(0x01);
                out.u64(value);
            }
            SmallwoodPoseidon2V8Expr::Public(index) => {
                out.u8(0x02);
                out.u16(index);
            }
            SmallwoodPoseidon2V8Expr::WitnessRow(index) => {
                out.u8(0x03);
                out.u16(index);
            }
            SmallwoodPoseidon2V8Expr::Add { left, right } => {
                out.u8(0x10);
                out.u32(left);
                out.u32(right);
            }
            SmallwoodPoseidon2V8Expr::Sub { left, right } => {
                out.u8(0x11);
                out.u32(left);
                out.u32(right);
            }
            SmallwoodPoseidon2V8Expr::Mul { left, right } => {
                out.u8(0x12);
                out.u32(left);
                out.u32(right);
            }
            SmallwoodPoseidon2V8Expr::Neg { value } => {
                out.u8(0x13);
                out.u32(value);
            }
            SmallwoodPoseidon2V8Expr::Inverse { value } => {
                out.u8(0x14);
                out.u32(value);
            }
            SmallwoodPoseidon2V8Expr::SelectEqual {
                left,
                right,
                equal,
                not_equal,
            } => {
                out.u8(0x15);
                out.u32(left);
                out.u32(right);
                out.u32(equal);
                out.u32(not_equal);
            }
            SmallwoodPoseidon2V8Expr::Bit { value, bit } => {
                out.u8(0x16);
                out.u32(value);
                out.u8(bit);
            }
        }
    }
    out.u32(u32::try_from(roots.len()).expect("V8 expression root count fits u32"));
    for root in roots {
        out.u32(*root);
    }
    out.bytes
}

fn csr_executable_payload() -> (usize, Vec<u8>) {
    let program = smallwood_poseidon2_v8_csr_expression_program();
    let mut out = CanonicalEncoder::default();
    let expression_bytes = expression_payload(&program.expressions, &[]);
    out.blob(&expression_bytes);
    out.u32(u32::try_from(program.attempts.len()).expect("V8 CSR attempt count fits u32"));
    let mut local_by_family = [0u32; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT];
    for (global, attempt) in program.attempts.iter().enumerate() {
        let family = usize::from(attempt.family);
        let local = local_by_family[family];
        local_by_family[family] += 1;
        out.u32(u32::try_from(global).expect("V8 CSR global index fits u32"));
        out.u16(attempt.family);
        out.u32(local);
        out.u8(
            match SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES[family].emission {
                SmallwoodPoseidon2V8CsrEmission::Always => 0,
                SmallwoodPoseidon2V8CsrEmission::NormalizeDropEmptyZero => 1,
            },
        );
        out.u16(u16::try_from(attempt.terms.len()).expect("V8 CSR term count fits u16"));
        for (index, coefficient_root) in &attempt.terms {
            out.u32(*index);
            out.u32(*coefficient_root);
        }
        out.u32(attempt.target);
    }
    for (index, count) in local_by_family.into_iter().enumerate() {
        assert_eq!(
            count, SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES[index].instances,
            "executable CSR family instance count differs from its inventory"
        );
    }
    (program.attempts.len(), out.bytes)
}

fn public_map_version_domain_descriptors() -> Vec<SmallwoodPoseidon2V8ProgramDescriptor> {
    let mut out = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_PUBLIC_VERSION_DOMAIN_DESCRIPTOR_COUNT);
    out.push(SmallwoodPoseidon2V8ProgramDescriptor {
        opcode: 0x0201,
        words: vec![
            u64::from(SMALLWOOD_POSEIDON2_V8_CIRCUIT_VERSION),
            u64::from(SMALLWOOD_POSEIDON2_V8_CRYPTO_SUITE),
            u64::from(SMALLWOOD_POSEIDON2_V8_FAMILY_ID),
            u64::from(SMALLWOOD_POSEIDON2_V8_ACTION_ID),
            u64::from(SMALLWOOD_POSEIDON2_V8_BACKEND_ID),
            u64::from(SMALLWOOD_POSEIDON2_V8_PROFILE_ID),
            u64::from(SMALLWOOD_POSEIDON2_V8_DOMAIN_SET),
            u64::from_le_bytes([
                SMALLWOOD_POSEIDON2_V8_INNER_MAGIC[0],
                SMALLWOOD_POSEIDON2_V8_INNER_MAGIC[1],
                SMALLWOOD_POSEIDON2_V8_INNER_MAGIC[2],
                SMALLWOOD_POSEIDON2_V8_INNER_MAGIC[3],
                0,
                0,
                0,
                0,
            ]),
        ],
        label: "v8-eta-family1-action10-smallwood2-profile6-domain4-smz9".to_owned(),
    });
    for range in SMALLWOOD_POSEIDON2_V8_PUBLIC_MAP {
        out.push(SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0202,
            words: vec![u64::from(range.start), u64::from(range.end)],
            label: range.name.to_owned(),
        });
    }
    for range in SMALLWOOD_POSEIDON2_V8_INTENT_ZERO_RANGES {
        out.push(SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0203,
            words: vec![u64::from(range.start), u64::from(range.end)],
            label: range.name.to_owned(),
        });
    }
    for entry in SMALLWOOD_POSEIDON2_V8_DOMAINS {
        out.push(SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0204,
            words: vec![entry.value],
            label: entry.name.to_owned(),
        });
    }
    out.push(SmallwoodPoseidon2V8ProgramDescriptor {
        opcode: 0x0204,
        words: vec![
            SMALLWOOD_POSEIDON2_V8_SPONGE_MODE_MARKER,
            SMALLWOOD_POSEIDON2_V8_SUITE_MARKER,
        ],
        label: "rate8-sponge-v1-and-width16-suite-markers".to_owned(),
    });
    out.push(SmallwoodPoseidon2V8ProgramDescriptor {
        opcode: 0x0205,
        words: vec![
            SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN,
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT as u64,
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES as u64,
            SMALLWOOD_POSEIDON2_V8_BALANCE_SLOT_PADDING_FIELD_ID,
        ],
        label: "csr-btree-sort-field-fold-drop-zero-drop-empty-zero-v1\0copy-public120-zero-[4,18)-[47,54)-[87,94)-[113,120)\0asset-membership-excludes-padding-4294967294".to_owned(),
    });
    debug_assert_eq!(
        out.len(),
        SMALLWOOD_POSEIDON2_V8_PUBLIC_VERSION_DOMAIN_DESCRIPTOR_COUNT
    );
    out
}

fn nonlinear_program_descriptors() -> Vec<SmallwoodPoseidon2V8ProgramDescriptor> {
    smallwood_poseidon2_v8_nonlinear_descriptors()
        .into_iter()
        .map(|descriptor| SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0401,
            words: vec![
                u64::from(descriptor.global_index),
                u64::from(descriptor.local_index),
                u64::from(descriptor.coordinate_0),
                u64::from(descriptor.coordinate_1),
            ],
            label: descriptor.family.to_owned(),
        })
        .collect()
}

fn symbolic_csr_program_descriptors() -> Vec<SmallwoodPoseidon2V8ProgramDescriptor> {
    SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
        .iter()
        .enumerate()
        .map(|(index, family)| SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0501,
            words: vec![
                u64::try_from(index).expect("86 families fit u64"),
                u64::from(family.instances),
                match family.emission {
                    SmallwoodPoseidon2V8CsrEmission::Always => 0,
                    SmallwoodPoseidon2V8CsrEmission::NormalizeDropEmptyZero => 1,
                },
            ],
            label: format!(
                "{}\0{}\0{}\0{}",
                family.name,
                family.index_program,
                family.coefficient_program,
                family.target_program
            ),
        })
        .collect()
}

fn hash_role_program_descriptors() -> Vec<SmallwoodPoseidon2V8ProgramDescriptor> {
    smallwood_poseidon2_v8_hash_call_descriptors()
        .into_iter()
        .map(|call| SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: match call.mode {
                SmallwoodPoseidon2V8HashMode::SpongeV1 => 0x0601,
                SmallwoodPoseidon2V8HashMode::Compress14V1 => 0x0602,
            },
            words: vec![
                u64::from(call.index),
                u64::from(call.role_arg_0),
                u64::from(call.role_arg_1),
                call.domain,
                u64::from(call.input_words),
                u64::from(call.block),
                u64::from(call.blocks),
            ],
            label: format!(
                "{}\0{}\0{}\0{}",
                call.role, call.left_or_preimage_binding, call.right_binding, call.output_binding
            ),
        })
        .collect()
}

fn global_binding_program_descriptors() -> Vec<SmallwoodPoseidon2V8ProgramDescriptor> {
    let out = vec![
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0701,
            words: vec![8, 7, 1, 10, 2, 6, 4],
            label: format!("{SMALLWOOD_POSEIDON2_V8_RELATION_ID}\0SMZ9"),
        },
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0702,
            words: vec![120, 0xffff_ffff_0000_0001],
            label: "HGV8TX02.statement[0,120)->verifier.public[0,120);canonical-goldilocks"
                .to_owned(),
        },
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0703,
            words: vec![7, 87, 94],
            label: "relation.binding[0,7)=expected-action-intent=call[93].final[0,7)".to_owned(),
        },
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0704,
            words: vec![0, 247, 247, 5, 252, 31, 283, 364, 647, 39, 686],
            label: "rows=raw[0,247);dense[247,252);inline[252,283);hash[283,647);stable[647,686)"
                .to_owned(),
        },
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0705,
            words: vec![125, 128, 16, 48],
            label: "calls[125,128).initial[0,16)=0".to_owned(),
        },
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0706,
            words: vec![0],
            label: "auxiliary-witness-words=0".to_owned(),
        },
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0707,
            words: vec![64, 8, 830, 19_935, 20_509, 21_339, 5, 6, 2, 23, 20, 5],
            label: "DirectPacked64Poseidon2V8Sha512Smz9\0Sha512Poseidon2V8Smz9\0rho5-open6-beta2-N23-q20-eta5".to_owned(),
        },
        SmallwoodPoseidon2V8ProgramDescriptor {
            opcode: 0x0708,
            words: vec![64, 48],
            label: "SHA-512\0HGV8RP03-canonical-executable-program-prefix[0,48)".to_owned(),
        },
    ];
    debug_assert_eq!(
        out.len(),
        SMALLWOOD_POSEIDON2_V8_GLOBAL_BINDING_DESCRIPTOR_COUNT
    );
    out
}

fn descriptor_payload(descriptors: &[SmallwoodPoseidon2V8ProgramDescriptor]) -> Vec<u8> {
    let mut out = CanonicalEncoder::default();
    out.descriptors(descriptors);
    out.bytes
}

/// Encode the complete compiler-program descriptor.  No witness or public values are inputs.
/// Framing is byte-for-byte the nine-section transcript specified in
/// `Hegemon.Transaction.Poseidon2V8RelationProgram`.
pub fn encode_smallwood_poseidon2_v8_program() -> Vec<u8> {
    let mut out = CanonicalEncoder::default();
    out.bytes
        .extend_from_slice(&SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC);
    out.u16(SMALLWOOD_POSEIDON2_V8_PROGRAM_GRAMMAR);
    out.u16(SMALLWOOD_POSEIDON2_V8_PROGRAM_SECTION_COUNT);

    let mut geometry = CanonicalEncoder::default();
    for value in SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS {
        geometry.u64(value);
    }
    out.section(
        1,
        SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS.len(),
        &geometry.bytes,
    );

    let public = public_map_version_domain_descriptors();
    let public_payload = descriptor_payload(&public);
    out.section(2, public.len(), &public_payload);

    out.section(3, 1, &SMALLWOOD_POSEIDON2_V8_POSEIDON_PARAMETER_SHA256);

    let nonlinear = nonlinear_program_descriptors();
    let nonlinear_payload = descriptor_payload(&nonlinear);
    out.section(4, nonlinear.len(), &nonlinear_payload);

    let csr = symbolic_csr_program_descriptors();
    let csr_payload = descriptor_payload(&csr);
    out.section(5, csr.len(), &csr_payload);

    let roles = hash_role_program_descriptors();
    let role_payload = descriptor_payload(&roles);
    out.section(6, roles.len(), &role_payload);

    let bindings = global_binding_program_descriptors();
    let binding_payload = descriptor_payload(&bindings);
    out.section(7, bindings.len(), &binding_payload);

    let nonlinear_executable = smallwood_poseidon2_v8_nonlinear_expression_program();
    let nonlinear_executable_payload = expression_payload(
        &nonlinear_executable.expressions,
        &nonlinear_executable.roots,
    );
    out.section(
        8,
        nonlinear_executable.roots.len(),
        &nonlinear_executable_payload,
    );

    let (csr_attempts, csr_executable_payload) = csr_executable_payload();
    out.section(9, csr_attempts, &csr_executable_payload);

    out.bytes
}

pub fn smallwood_poseidon2_v8_program_sha512_from_bytes(
    bytes: &[u8],
) -> [u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512_BYTES] {
    let digest = Sha512::digest(bytes);
    let mut out = [0u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512_BYTES];
    out.copy_from_slice(&digest);
    out
}

pub fn smallwood_poseidon2_v8_program_digest_from_bytes(
    bytes: &[u8],
) -> [u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES] {
    let sha512 = smallwood_poseidon2_v8_program_sha512_from_bytes(bytes);
    let mut out = [0u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES];
    out.copy_from_slice(&sha512[..SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES]);
    out
}

pub fn recompute_smallwood_poseidon2_v8_program_sha512(
) -> [u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512_BYTES] {
    smallwood_poseidon2_v8_program_sha512_from_bytes(&encode_smallwood_poseidon2_v8_program())
}

pub fn recompute_smallwood_poseidon2_v8_program_digest(
) -> [u8; SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES] {
    smallwood_poseidon2_v8_program_digest_from_bytes(&encode_smallwood_poseidon2_v8_program())
}

pub fn smallwood_poseidon2_v8_program_digest_matches() -> bool {
    static MATCHES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *MATCHES.get_or_init(|| {
        let bytes = encode_smallwood_poseidon2_v8_program();
        smallwood_poseidon2_v8_program_sha512_from_bytes(&bytes)
            == SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512
            && smallwood_poseidon2_v8_program_digest_from_bytes(&bytes)
                == SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
    })
}

const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PACKED_WITNESS_WORDS == 43_904);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS == 830);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_LIVE_CALLS == 125);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512_BYTES == 64);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES == 48);

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u8(bytes: &[u8], cursor: &mut usize) -> u8 {
        let value = bytes[*cursor];
        *cursor += 1;
        value
    }

    fn read_u16(bytes: &[u8], cursor: &mut usize) -> u16 {
        let end = *cursor + 2;
        let value = u16::from_le_bytes(
            bytes[*cursor..end]
                .try_into()
                .expect("test transcript has a complete u16"),
        );
        *cursor = end;
        value
    }

    fn read_u32(bytes: &[u8], cursor: &mut usize) -> u32 {
        let end = *cursor + 4;
        let value = u32::from_le_bytes(
            bytes[*cursor..end]
                .try_into()
                .expect("test transcript has a complete u32"),
        );
        *cursor = end;
        value
    }

    fn read_u64(bytes: &[u8], cursor: &mut usize) -> u64 {
        let end = *cursor + 8;
        let value = u64::from_le_bytes(
            bytes[*cursor..end]
                .try_into()
                .expect("test transcript has a complete u64"),
        );
        *cursor = end;
        value
    }

    fn assert_descriptor_payload(payload: &[u8], count: u32, allowed_opcodes: &[u16]) {
        let mut cursor = 0;
        assert_eq!(read_u32(payload, &mut cursor), count);
        for _ in 0..count {
            let opcode = read_u16(payload, &mut cursor);
            assert!(
                allowed_opcodes.contains(&opcode),
                "unexpected opcode {opcode:#06x}"
            );
            let word_count = usize::from(read_u16(payload, &mut cursor));
            for _ in 0..word_count {
                let _ = read_u64(payload, &mut cursor);
            }
            let label_len = usize::try_from(read_u32(payload, &mut cursor))
                .expect("descriptor label length fits usize");
            let label_end = cursor + label_len;
            assert!(payload[cursor..label_end].is_ascii());
            cursor = label_end;
        }
        assert_eq!(
            cursor,
            payload.len(),
            "descriptor payload has trailing bytes"
        );
    }

    fn assert_expression_payload(
        payload: &[u8],
        expected_roots: u32,
        allow_witness_rows: bool,
    ) -> u32 {
        let mut cursor = 0;
        let expression_count = read_u32(payload, &mut cursor);
        for node in 0..expression_count {
            let opcode = read_u8(payload, &mut cursor);
            let prior = |operand: u32| {
                assert!(operand < node, "expression operand must precede its node");
            };
            match opcode {
                0x01 => assert!(read_u64(payload, &mut cursor) < hegemon_field::GOLDILOCKS_MODULUS),
                0x02 => assert!(
                    usize::from(read_u16(payload, &mut cursor))
                        < SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS
                ),
                0x03 => {
                    assert!(
                        allow_witness_rows,
                        "CSR expressions must not read witness rows"
                    );
                    assert!(
                        usize::from(read_u16(payload, &mut cursor))
                            < SMALLWOOD_POSEIDON2_V8_ROW_COUNT
                    );
                }
                0x10 | 0x11 | 0x12 => {
                    let left = read_u32(payload, &mut cursor);
                    let right = read_u32(payload, &mut cursor);
                    prior(left);
                    prior(right);
                }
                0x13 | 0x14 => prior(read_u32(payload, &mut cursor)),
                0x15 => {
                    let left = read_u32(payload, &mut cursor);
                    let right = read_u32(payload, &mut cursor);
                    let equal = read_u32(payload, &mut cursor);
                    let not_equal = read_u32(payload, &mut cursor);
                    prior(left);
                    prior(right);
                    prior(equal);
                    prior(not_equal);
                }
                0x16 => {
                    prior(read_u32(payload, &mut cursor));
                    assert!(read_u8(payload, &mut cursor) < 64);
                }
                _ => panic!("unknown HGV8RP03 expression opcode {opcode:#04x}"),
            }
        }
        let root_count = read_u32(payload, &mut cursor);
        assert_eq!(root_count, expected_roots);
        for _ in 0..root_count {
            assert!(read_u32(payload, &mut cursor) < expression_count);
        }
        assert_eq!(
            cursor,
            payload.len(),
            "expression payload has trailing bytes"
        );
        expression_count
    }

    fn expression_mutation_offsets(payload: &[u8]) -> (usize, usize, Option<usize>) {
        let mut cursor = 0;
        let expression_count = read_u32(payload, &mut cursor);
        let mut operator = None;
        let mut operand = None;
        for _ in 0..expression_count {
            let opcode_offset = cursor;
            let opcode = read_u8(payload, &mut cursor);
            match opcode {
                0x01 => cursor += 8,
                0x02 | 0x03 => cursor += 2,
                0x10 | 0x11 | 0x12 => {
                    operator.get_or_insert(opcode_offset);
                    operand.get_or_insert(cursor);
                    cursor += 8;
                }
                0x13 | 0x14 => {
                    operator.get_or_insert(opcode_offset);
                    operand.get_or_insert(cursor);
                    cursor += 4;
                }
                0x15 => {
                    operator.get_or_insert(opcode_offset);
                    operand.get_or_insert(cursor);
                    cursor += 16;
                }
                0x16 => {
                    operator.get_or_insert(opcode_offset);
                    operand.get_or_insert(cursor);
                    cursor += 5;
                }
                _ => panic!("unknown HGV8RP03 expression opcode {opcode:#04x}"),
            }
        }
        let root_count = read_u32(payload, &mut cursor);
        (
            operator.expect("expression program has an operator"),
            operand.expect("expression program has an operand"),
            (root_count != 0).then_some(cursor),
        )
    }

    struct CsrMutationOffsets {
        expression_operator: usize,
        expression_operand: usize,
        global: usize,
        family: usize,
        local: usize,
        emission: usize,
        witness_index: usize,
        coefficient_root: usize,
        target_root: usize,
    }

    fn csr_mutation_offsets(payload: &[u8]) -> CsrMutationOffsets {
        let mut cursor = 0;
        let expression_bytes = usize::try_from(read_u32(payload, &mut cursor)).unwrap();
        let expression_start = cursor;
        let expression_end = expression_start + expression_bytes;
        let (expression_operator, expression_operand, _) =
            expression_mutation_offsets(&payload[expression_start..expression_end]);
        cursor = expression_end;
        let attempts = read_u32(payload, &mut cursor);
        for _ in 0..attempts {
            let global = cursor;
            let _ = read_u32(payload, &mut cursor);
            let family = cursor;
            let _ = read_u16(payload, &mut cursor);
            let local = cursor;
            let _ = read_u32(payload, &mut cursor);
            let emission = cursor;
            let _ = read_u8(payload, &mut cursor);
            let term_count = usize::from(read_u16(payload, &mut cursor));
            let witness_index = cursor;
            if term_count != 0 {
                let coefficient_root = cursor + 4;
                cursor += term_count * 8;
                let target_root = cursor;
                return CsrMutationOffsets {
                    expression_operator: expression_start + expression_operator,
                    expression_operand: expression_start + expression_operand,
                    global,
                    family,
                    local,
                    emission,
                    witness_index,
                    coefficient_root,
                    target_root,
                };
            }
            cursor += term_count * 8 + 4;
        }
        panic!("HGV8RP03 CSR program has no nonempty attempted identity")
    }

    fn assert_csr_executable_payload(payload: &[u8], expected_attempts: u32) {
        let mut cursor = 0;
        let expression_bytes = usize::try_from(read_u32(payload, &mut cursor))
            .expect("CSR expression blob length fits usize");
        let expression_end = cursor + expression_bytes;
        let expression_count =
            assert_expression_payload(&payload[cursor..expression_end], 0, false);
        cursor = expression_end;
        assert_eq!(read_u32(payload, &mut cursor), expected_attempts);
        let mut local_by_family = [0u32; SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT];
        for global in 0..expected_attempts {
            assert_eq!(read_u32(payload, &mut cursor), global);
            let family = usize::from(read_u16(payload, &mut cursor));
            assert!(family < SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT);
            assert_eq!(read_u32(payload, &mut cursor), local_by_family[family]);
            local_by_family[family] += 1;
            let emission = read_u8(payload, &mut cursor);
            let expected_emission =
                match SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES[family].emission {
                    SmallwoodPoseidon2V8CsrEmission::Always => 0,
                    SmallwoodPoseidon2V8CsrEmission::NormalizeDropEmptyZero => 1,
                };
            assert_eq!(emission, expected_emission);
            let term_count = usize::from(read_u16(payload, &mut cursor));
            for _ in 0..term_count {
                assert!(
                    usize::try_from(read_u32(payload, &mut cursor)).unwrap()
                        < SMALLWOOD_POSEIDON2_V8_PACKED_WITNESS_WORDS
                );
                assert!(read_u32(payload, &mut cursor) < expression_count);
            }
            assert!(read_u32(payload, &mut cursor) < expression_count);
        }
        assert_eq!(
            cursor,
            payload.len(),
            "CSR executable payload has trailing bytes"
        );
        for (family, actual) in SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
            .iter()
            .zip(local_by_family)
        {
            assert_eq!(actual, family.instances);
        }
    }

    #[derive(Clone, Copy)]
    struct SectionBounds {
        header_start: usize,
        payload_start: usize,
        end: usize,
    }

    fn section_bounds(bytes: &[u8]) -> Vec<SectionBounds> {
        let mut cursor = 12;
        let mut sections =
            Vec::with_capacity(usize::from(SMALLWOOD_POSEIDON2_V8_PROGRAM_SECTION_COUNT));
        for _ in 0..SMALLWOOD_POSEIDON2_V8_PROGRAM_SECTION_COUNT {
            let header_start = cursor;
            let _ = read_u16(bytes, &mut cursor);
            let _ = read_u32(bytes, &mut cursor);
            let payload_len = usize::try_from(read_u64(bytes, &mut cursor))
                .expect("section payload length fits usize");
            let payload_start = cursor;
            let end = payload_start + payload_len;
            sections.push(SectionBounds {
                header_start,
                payload_start,
                end,
            });
            cursor = end;
        }
        assert_eq!(cursor, bytes.len());
        sections
    }

    fn mutate_declared_case(name: &str, bytes: &[u8]) -> Option<Vec<u8>> {
        if name == "statement_numeric_value" {
            return None;
        }
        let sections = section_bounds(bytes);
        if name == "section_order" {
            let first = sections[0];
            let second = sections[1];
            let mut mutated = Vec::with_capacity(bytes.len());
            mutated.extend_from_slice(&bytes[..first.header_start]);
            mutated.extend_from_slice(&bytes[second.header_start..second.end]);
            mutated.extend_from_slice(&bytes[first.header_start..first.end]);
            mutated.extend_from_slice(&bytes[second.end..]);
            return Some(mutated);
        }
        let nonlinear_payload = &bytes[sections[7].payload_start..sections[7].end];
        let (nonlinear_opcode, nonlinear_operand, nonlinear_root) =
            expression_mutation_offsets(nonlinear_payload);
        let nonlinear_root = nonlinear_root.expect("nonlinear executable program has roots");
        let csr_payload = &bytes[sections[8].payload_start..sections[8].end];
        let csr = csr_mutation_offsets(csr_payload);
        let offset = match name {
            "magic" => 0,
            "grammar" => 8,
            "section_tag" => sections[0].header_start,
            "section_item_count" => sections[0].header_start + 2,
            "section_payload_length" => sections[0].header_start + 6,
            "geometry" => sections[0].payload_start,
            "public_map_descriptor" => sections[1].payload_start + 4,
            "poseidon_parameter_manifest_digest" => sections[2].payload_start,
            "nonlinear_identity_descriptor" => sections[3].payload_start + 4,
            "nonlinear_identity_order" => sections[3].payload_start + 12,
            "linear_offset" => sections[4].payload_start + 4,
            "linear_index" => sections[4].payload_start + 12,
            "linear_coefficient" => sections[4].payload_start + 20,
            "symbolic_public_target" => sections[4].payload_start + 28,
            "linear_compiler_family" => sections[4].payload_start + 36,
            "linear_compiler_family_order" => sections[4].payload_start + 44,
            "hash_call_role" => sections[5].payload_start + 4,
            "binding_descriptor" => sections[6].payload_start + 4,
            "nonlinear_expression_opcode" => sections[7].payload_start + nonlinear_opcode,
            "nonlinear_expression_operand" => sections[7].payload_start + nonlinear_operand,
            "nonlinear_expression_root" => sections[7].payload_start + nonlinear_root,
            "csr_expression_opcode" => sections[8].payload_start + csr.expression_operator,
            "csr_expression_operand" => sections[8].payload_start + csr.expression_operand,
            "csr_attempt_global" => sections[8].payload_start + csr.global,
            "csr_attempt_family" => sections[8].payload_start + csr.family,
            "csr_attempt_local" => sections[8].payload_start + csr.local,
            "csr_attempt_emission" => sections[8].payload_start + csr.emission,
            "csr_witness_index" => sections[8].payload_start + csr.witness_index,
            "csr_coefficient_root" => sections[8].payload_start + csr.coefficient_root,
            "csr_target_root" => sections[8].payload_start + csr.target_root,
            other => panic!("unimplemented formal mutation case {other}"),
        };
        let mut mutated = bytes.to_vec();
        mutated[offset] ^= 1;
        Some(mutated)
    }

    fn lowercase_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn lean_generated_v8_relation_program_vectors_match_source() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/formal_core_vectors/poseidon2_v8_relation_program_transcript.json"
        )))
        .expect("parse Lean-generated HGV8RP03 relation-program vector");
        let bytes = encode_smallwood_poseidon2_v8_program();
        let sha512 = smallwood_poseidon2_v8_program_sha512_from_bytes(&bytes);
        let relation_id = smallwood_poseidon2_v8_program_digest_from_bytes(&bytes);

        assert_eq!(
            vectors["schema"],
            "hegemon.poseidon2-v8.relation-program-transcript-v2"
        );
        assert_eq!(vectors["artifact_available"], true);
        assert_eq!(vectors["statement_values_serialized"], false);
        assert_eq!(
            vectors["transcript_bytes"].as_u64(),
            Some(bytes.len() as u64)
        );
        assert_eq!(
            vectors["final_program_sha512"].as_str(),
            Some(lowercase_hex(&sha512).as_str())
        );
        assert_eq!(
            vectors["final_relation_id_48"].as_str(),
            Some(lowercase_hex(&relation_id).as_str())
        );
        assert_eq!(bytes.len(), SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES);
        assert_eq!(sha512, SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512);
        assert_eq!(relation_id, SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST);

        let magic = vectors["magic_bytes"]
            .as_array()
            .expect("magic_bytes is an array")
            .iter()
            .map(|value| value.as_u64().expect("magic byte is an integer") as u8)
            .collect::<Vec<_>>();
        assert_eq!(magic, SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC);
        assert_eq!(
            vectors["grammar"].as_u64(),
            Some(u64::from(SMALLWOOD_POSEIDON2_V8_PROGRAM_GRAMMAR))
        );
        assert_eq!(
            vectors["fixed_geometry"]["linear_compiler_families"].as_u64(),
            Some(86)
        );
        assert_eq!(
            vectors["fixed_geometry"]["linear_compiler_family_instances"].as_u64(),
            Some(20_605)
        );
        assert_eq!(
            vectors["fixed_geometry"]["minimum_linear_constraints"].as_u64(),
            Some(19_935)
        );
        assert_eq!(
            vectors["fixed_geometry"]["maximum_linear_constraints"].as_u64(),
            Some(20_509)
        );
        assert_eq!(
            vectors["fixed_geometry"]["maximum_summed_identity_union"].as_u64(),
            Some(21_339)
        );

        for case in vectors["mutation_cases"]
            .as_array()
            .expect("mutation_cases is an array")
        {
            let name = case["name"].as_str().expect("mutation case has a name");
            let expected_change = case["expected_relation_id_change"]
                .as_bool()
                .expect("mutation case has a Boolean expectation");
            match mutate_declared_case(name, &bytes) {
                Some(mutated) => {
                    assert!(
                        expected_change,
                        "{name} unexpectedly declares digest invariance"
                    );
                    assert_ne!(
                        smallwood_poseidon2_v8_program_digest_from_bytes(&mutated),
                        relation_id,
                        "{name} did not change the relation id"
                    );
                }
                None => {
                    assert!(
                        !expected_change,
                        "{name} unexpectedly declares digest mutation"
                    );
                    assert_eq!(
                        recompute_smallwood_poseidon2_v8_program_digest(),
                        relation_id,
                        "statement values must not enter HGV8RP03"
                    );
                }
            }
        }
    }

    #[test]
    fn source_program_bytes_match_checked_in_canonical_artifact() {
        let source_program = encode_smallwood_poseidon2_v8_program();
        let checked_in_program = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/formal_core_vectors/poseidon2_v8_relation_program.bin"
        ));

        assert_eq!(source_program.as_slice(), checked_in_program.as_slice());

        let mut mutated = checked_in_program.to_vec();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        assert_ne!(source_program, mutated);
        assert_ne!(
            smallwood_poseidon2_v8_program_sha512_from_bytes(&mutated),
            SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512
        );
    }

    #[test]
    fn program_descriptor_inventory_is_exact_and_gap_free() {
        let nonlinear = smallwood_poseidon2_v8_nonlinear_descriptors();
        assert_eq!(nonlinear.len(), 830);
        assert!(nonlinear
            .iter()
            .enumerate()
            .all(|(index, descriptor)| usize::from(descriptor.global_index) == index));
        assert_eq!(nonlinear[128].family, "base.policy_root_match");
        assert_eq!(nonlinear[129].family, "auth.mode_boolean");
        assert_eq!(nonlinear[470].family, "auth.final_mode");
        assert_eq!(nonlinear[471].family, "poseidon.external_initial_sbox_wire");
        assert_eq!(nonlinear[802].family, "poseidon.final_state");
        assert_eq!(nonlinear[803].family, "stable.role_selector_domain");

        let calls = smallwood_poseidon2_v8_hash_call_descriptors();
        assert_eq!(calls.len(), 125);
        assert!(calls
            .iter()
            .enumerate()
            .all(|(index, call)| usize::from(call.index) == index));
        assert_eq!(calls[0].role, "transaction_prf");
        assert_eq!(calls[4].role, "input_merkle");
        assert_eq!(calls[79].role, "action_intent");
        assert_eq!(calls[106].role, "stable_config_chunk");
        assert_eq!(calls[124].role, "stable_issuer_authorization");

        assert_eq!(SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES.len(), 86);
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
                .iter()
                .map(|family| family.instances as usize)
                .sum::<usize>(),
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES
        );
        assert_eq!(SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES, 20_605);
        assert_eq!(
            smallwood_poseidon2_v8_nonlinear_expression_program()
                .expressions
                .len(),
            SMALLWOOD_POSEIDON2_V8_NONLINEAR_EXPRESSION_NODES
        );
        assert_eq!(
            smallwood_poseidon2_v8_csr_expression_program()
                .expressions
                .len(),
            SMALLWOOD_POSEIDON2_V8_CSR_EXPRESSION_NODES
        );
        assert_eq!(SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS[32], 19_935);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS[33], 20_509);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS[34], 21_339);
    }

    #[test]
    fn executable_formula_fields_are_relation_id_bound() {
        let bytes = encode_smallwood_poseidon2_v8_program();
        let relation_id = smallwood_poseidon2_v8_program_digest_from_bytes(&bytes);
        let sections = section_bounds(&bytes);

        let nonlinear_payload = &bytes[sections[7].payload_start..sections[7].end];
        let (nonlinear_opcode, nonlinear_operand, nonlinear_root) =
            expression_mutation_offsets(nonlinear_payload);
        let nonlinear_root = nonlinear_root.expect("nonlinear program has roots");
        let csr_payload = &bytes[sections[8].payload_start..sections[8].end];
        let csr = csr_mutation_offsets(csr_payload);
        let mutation_offsets = [
            sections[7].payload_start + nonlinear_opcode,
            sections[7].payload_start + nonlinear_operand,
            sections[7].payload_start + nonlinear_root,
            sections[8].payload_start + csr.expression_operator,
            sections[8].payload_start + csr.expression_operand,
            sections[8].payload_start + csr.global,
            sections[8].payload_start + csr.family,
            sections[8].payload_start + csr.local,
            sections[8].payload_start + csr.emission,
            sections[8].payload_start + csr.witness_index,
            sections[8].payload_start + csr.coefficient_root,
            sections[8].payload_start + csr.target_root,
        ];
        for offset in mutation_offsets {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 1;
            assert_ne!(
                smallwood_poseidon2_v8_program_digest_from_bytes(&mutated),
                relation_id,
                "executable field at transcript offset {offset} was not relation-id bound"
            );
        }

        let csr_program = smallwood_poseidon2_v8_csr_expression_program();
        assert!(
            csr_program.expressions.iter().any(|expression| matches!(
                expression,
                SmallwoodPoseidon2V8Expr::SelectEqual {
                    equal,
                    not_equal,
                    ..
                } if equal != not_equal
            )),
            "public specialization must commit both SelectEqual arms"
        );
    }

    #[test]
    fn program_framing_is_exactly_nine_canonical_sections() {
        let bytes = encode_smallwood_poseidon2_v8_program();
        assert_eq!(&bytes[..8], &SMALLWOOD_POSEIDON2_V8_PROGRAM_MAGIC);
        let mut cursor = 8;
        assert_eq!(
            read_u16(&bytes, &mut cursor),
            SMALLWOOD_POSEIDON2_V8_PROGRAM_GRAMMAR
        );
        assert_eq!(
            read_u16(&bytes, &mut cursor),
            SMALLWOOD_POSEIDON2_V8_PROGRAM_SECTION_COUNT
        );

        let expected_counts = [
            37u32,
            56,
            1,
            830,
            86,
            125,
            8,
            SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS as u32,
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES as u32,
        ];
        let mut section_payload_offsets =
            Vec::with_capacity(usize::from(SMALLWOOD_POSEIDON2_V8_PROGRAM_SECTION_COUNT));
        for (section_index, expected_count) in expected_counts.into_iter().enumerate() {
            let tag = read_u16(&bytes, &mut cursor);
            let item_count = read_u32(&bytes, &mut cursor);
            let payload_len = usize::try_from(read_u64(&bytes, &mut cursor))
                .expect("section payload length fits usize");
            assert_eq!(tag, u16::try_from(section_index + 1).unwrap());
            assert_eq!(item_count, expected_count);
            let payload_start = cursor;
            let payload_end = payload_start + payload_len;
            let payload = &bytes[payload_start..payload_end];
            section_payload_offsets.push(payload_start);
            match tag {
                1 => {
                    assert_eq!(payload_len, 37 * 8);
                    let mut geometry_cursor = 0;
                    for expected in SMALLWOOD_POSEIDON2_V8_REQUIRED_GEOMETRY_WORDS {
                        assert_eq!(read_u64(payload, &mut geometry_cursor), expected);
                    }
                }
                2 => assert_descriptor_payload(
                    payload,
                    item_count,
                    &[0x0201, 0x0202, 0x0203, 0x0204, 0x0205],
                ),
                3 => assert_eq!(payload, SMALLWOOD_POSEIDON2_V8_POSEIDON_PARAMETER_SHA256),
                4 => assert_descriptor_payload(payload, item_count, &[0x0401]),
                5 => assert_descriptor_payload(payload, item_count, &[0x0501]),
                6 => assert_descriptor_payload(payload, item_count, &[0x0601, 0x0602]),
                7 => assert_descriptor_payload(
                    payload,
                    item_count,
                    &[
                        0x0701, 0x0702, 0x0703, 0x0704, 0x0705, 0x0706, 0x0707, 0x0708,
                    ],
                ),
                8 => {
                    assert_expression_payload(payload, item_count, true);
                }
                9 => assert_csr_executable_payload(payload, item_count),
                _ => unreachable!(),
            }
            cursor = payload_end;
        }
        assert_eq!(
            cursor,
            bytes.len(),
            "transcript has trailing bytes or extra sections"
        );

        let digest = smallwood_poseidon2_v8_program_digest_from_bytes(&bytes);
        for offset in section_payload_offsets {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 1;
            assert_ne!(
                smallwood_poseidon2_v8_program_digest_from_bytes(&mutated),
                digest
            );
        }
    }

    fn specialize_program_with_emitted_total(
        emitted_target: usize,
    ) -> SmallwoodPoseidon2V8CsrFamilyReceipt {
        let mut cursor = SmallwoodPoseidon2V8CsrProgramCursor::new();
        let mut drops_remaining = SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES
            .checked_sub(emitted_target)
            .expect("emitted target does not exceed attempted rows");
        for (family_index, family) in SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
            .iter()
            .enumerate()
        {
            for _ in 0..family.instances {
                let drop = family.emission
                    == SmallwoodPoseidon2V8CsrEmission::NormalizeDropEmptyZero
                    && drops_remaining != 0;
                cursor
                    .record_attempt(family_index, !drop)
                    .expect("canonical family attempts remain in order");
                drops_remaining -= usize::from(drop);
            }
        }
        assert_eq!(
            drops_remaining, 0,
            "not enough normalizable rows to reach target"
        );
        cursor
            .finish()
            .expect("target count is inside canonical range")
    }

    #[test]
    fn csr_family_cursor_detects_source_order_count_and_emission_drift() {
        for emitted_target in [
            SMALLWOOD_POSEIDON2_V8_MINIMUM_LINEAR_CONSTRAINTS,
            SMALLWOOD_POSEIDON2_V8_MAXIMUM_LINEAR_CONSTRAINTS,
        ] {
            let receipt = specialize_program_with_emitted_total(emitted_target);
            assert_eq!(receipt.emitted_total as usize, emitted_target);
            assert_eq!(
                receipt
                    .emitted_span(SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT - 1)
                    .expect("last family exists")
                    .end,
                receipt.emitted_total
            );
        }

        let mut out_of_order = SmallwoodPoseidon2V8CsrProgramCursor::new();
        assert!(matches!(
            out_of_order.record_attempt(1, true),
            Err(SmallwoodPoseidon2V8CsrProgramDrift::FamilyOutOfOrder { .. })
        ));

        let incomplete = SmallwoodPoseidon2V8CsrProgramCursor::new();
        assert!(matches!(
            incomplete.finish(),
            Err(SmallwoodPoseidon2V8CsrProgramDrift::ProgramIncomplete { .. })
        ));

        let always_family = SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
            .iter()
            .position(|family| family.emission == SmallwoodPoseidon2V8CsrEmission::Always)
            .expect("program has an always-emitted family");
        assert_eq!(always_family, 0);
        let mut dropped_always = SmallwoodPoseidon2V8CsrProgramCursor::new();
        assert!(matches!(
            dropped_always.record_attempt(always_family, false),
            Err(SmallwoodPoseidon2V8CsrProgramDrift::AlwaysFamilyDropped { .. })
        ));
    }

    #[test]
    fn program_digest_known_answer_and_descriptor_mutation() {
        let bytes = encode_smallwood_poseidon2_v8_program();
        let sha512 = smallwood_poseidon2_v8_program_sha512_from_bytes(&bytes);
        let relation_id = smallwood_poseidon2_v8_program_digest_from_bytes(&bytes);
        eprintln!(
            "HGV8RP03 bytes={} sha512={} relation_id={} nonlinear_exprs={} csr_exprs={}",
            bytes.len(),
            lowercase_hex(&sha512),
            lowercase_hex(&relation_id),
            smallwood_poseidon2_v8_nonlinear_expression_program()
                .expressions
                .len(),
            smallwood_poseidon2_v8_csr_expression_program()
                .expressions
                .len(),
        );
        assert_eq!(bytes.len(), SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES);
        assert_eq!(sha512, SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512);
        assert_eq!(relation_id, SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST);
        assert_eq!(
            &SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512[..SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST_BYTES],
            &SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
        );
        assert!(smallwood_poseidon2_v8_program_digest_matches());

        let mut mutated = bytes;
        let last = mutated
            .last_mut()
            .expect("the canonical program descriptor is nonempty");
        *last ^= 1;
        assert_ne!(
            smallwood_poseidon2_v8_program_digest_from_bytes(&mutated),
            SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
        );
        assert_ne!(
            smallwood_poseidon2_v8_program_sha512_from_bytes(&mutated),
            SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512
        );
    }
}
