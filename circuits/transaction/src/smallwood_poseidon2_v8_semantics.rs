//! Executable width-16 Poseidon2 relation for the fresh V8 SmallWood profile.
//!
//! This module is intentionally independent of the historical width-12 relation.  It owns the
//! fixed 686-row layout, the ordered 125-call hash schedule, verifier reconstruction from the
//! canonical 120-word statement, and the prover-only packed assignment.  Production authority is
//! deliberately outside this module.

#![forbid(unsafe_code)]

use thiserror::Error;

use transaction_core::constants::{
    BALANCE_SLOT_PADDING_FIELD_ID, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
};
use transaction_core::poseidon2_width16::{
    Felt, POSEIDON2_WIDTH16_RATE, POSEIDON2_WIDTH16_SPONGE_MODE_MARKER,
    POSEIDON2_WIDTH16_SUITE_MARKER, POSEIDON2_WIDTH16_WIDTH,
};
use transaction_core::stablecoin_poseidon2_v8::{
    StablecoinPoseidon2V8Context, StablecoinPoseidon2V8Direction, STABLECOIN_POSEIDON2_V8_DEPTH,
    STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0, STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1,
    STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2, STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3,
    STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0, STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1,
    STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT,
    STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION,
    STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT, STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF,
    STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0,
};

use crate::smallwood_engine::SmallwoodArithmetization;
use crate::smallwood_frontend::SmallwoodPrivateAuthMode;
use crate::smallwood_poseidon2_v8_frontend::{
    SmallwoodPoseidon2V8FrontendRelation, SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS,
    SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES,
};
use crate::smallwood_poseidon2_v8_hash_constraints::{
    evaluate_smallwood_poseidon2_v8_hash_constraints_ring,
    smallwood_poseidon2_v8_hash_call_final_witness_index,
    smallwood_poseidon2_v8_hash_call_initial_witness_index,
    smallwood_poseidon2_v8_hash_dummy_zero_witness_indices, SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT,
    SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT, SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT,
};
use crate::smallwood_poseidon2_v8_hash_schedule::{
    build_smallwood_poseidon2_v8_hash_schedule, SmallwoodPoseidon2V8HashScheduleError,
};
use crate::smallwood_poseidon2_v8_ir::{
    begin_smallwood_poseidon2_v8_expression_program,
    evaluate_smallwood_poseidon2_v8_expression_nodes,
    evaluate_smallwood_poseidon2_v8_expression_program,
    finish_smallwood_poseidon2_v8_expression_program,
    smallwood_poseidon2_v8_expression_program_is_active, smallwood_poseidon2_v8_symbolic_add,
    smallwood_poseidon2_v8_symbolic_bit, smallwood_poseidon2_v8_symbolic_inverse,
    smallwood_poseidon2_v8_symbolic_mul, smallwood_poseidon2_v8_symbolic_public_handle,
    smallwood_poseidon2_v8_symbolic_select_equal, smallwood_poseidon2_v8_symbolic_sub,
    smallwood_poseidon2_v8_symbolic_witness_row_handle, SmallwoodPoseidon2V8ExpressionProgram,
    SmallwoodPoseidon2V8SymbolicValue,
};
#[cfg(test)]
use crate::smallwood_poseidon2_v8_program::SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT;
use crate::smallwood_poseidon2_v8_program::{
    smallwood_poseidon2_v8_program_digest_matches, SmallwoodPoseidon2V8CsrProgramCursor,
    SMALLWOOD_POSEIDON2_V8_CSR_EXPRESSION_NODES, SMALLWOOD_POSEIDON2_V8_NONLINEAR_EXPRESSION_NODES,
    SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES,
    SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES,
};
pub use crate::smallwood_poseidon2_v8_program::{
    SmallwoodPoseidon2V8CsrFamilyReceipt,
    SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST as SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST,
};
use crate::smallwood_poseidon2_v8_relation::{
    build_smallwood_poseidon2_v8_relation_material,
    SmallwoodPoseidon2V8RelationError as SmallwoodPoseidon2V8TailMaterialError,
};
use crate::smallwood_poseidon2_v8_types::{
    SmallwoodPoseidon2V8PublicStatement, SmallwoodPoseidon2V8SurfaceError,
    SmallwoodPoseidon2V8Witness, SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN,
    SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
    SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS as SMALLWOOD_POSEIDON2_V8_TYPED_WITNESS_WORDS,
};
use crate::smallwood_semantics::{SmallwoodConstraintAdapter, SmallwoodNonlinearEvalView};
use crate::TransactionCircuitError;

pub const SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE: usize = 8;

pub const SMALLWOOD_POSEIDON2_V8_RAW_ROW_START: usize = 0;
pub const SMALLWOOD_POSEIDON2_V8_RAW_ROW_COUNT: usize = 247;
pub const SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START: usize = 247;
pub const SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_COUNT: usize = 5;
pub const SMALLWOOD_POSEIDON2_V8_INLINE_ROW_START: usize = 252;
pub const SMALLWOOD_POSEIDON2_V8_INLINE_ROW_COUNT: usize = 31;
pub const SMALLWOOD_POSEIDON2_V8_HASH_ROW_START: usize = 283;
pub const SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START: usize = 647;
pub const SMALLWOOD_POSEIDON2_V8_STABLE_ROW_COUNT: usize = 39;
pub const SMALLWOOD_POSEIDON2_V8_ROW_COUNT: usize = 686;
pub const SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS: usize =
    SMALLWOOD_POSEIDON2_V8_ROW_COUNT * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR;

const INPUTS: usize = 2;
const OUTPUTS: usize = 2;
const MERKLE_DEPTH: usize = 32;
const DIGEST: usize = 7;
const SIGNER_TAG_WORDS: usize = 5;
const SIGNERS: usize = 6;
const PAIRS: usize = 15;
const STABLE_ROLE_CONDITIONS: usize = 21;
const TOTAL_ROLE_CONDITIONS: usize = STABLE_ROLE_CONDITIONS + 1 + 2 + SIGNERS;
const INPUT_ROWS: usize = 34;
const OUTPUT_ROWS: usize = 12;
const AUTH_ROWS: usize = 155;
const INPUT_ROW_START: usize = 0;
const OUTPUT_ROW_START: usize = 68;
const AUTH_ROW_START: usize = 92;
const INLINE_MERKLE_GROUPS: usize = 7;
const INLINE_POLICY_ROW_START: usize = SMALLWOOD_POSEIDON2_V8_INLINE_ROW_START + 28;
const AUTH_INTENT_DOMAIN: u64 = SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN;
const AUTH_POLICY_DOMAIN: u64 = 7;
const AUTH_ACCUMULATOR_DOMAIN: u64 = 6;
const AUTH_VALUE_LOCK_DOMAIN: u64 = 8;
const MODULUS: u64 = hegemon_field::GOLDILOCKS_MODULUS;
const NEG_ONE: u64 = MODULUS - 1;

pub const SMALLWOOD_POSEIDON2_V8_TRANSACTION_CALLS: core::ops::Range<usize> = 0..79;
pub const SMALLWOOD_POSEIDON2_V8_INTENT_CALLS: core::ops::Range<usize> = 79..94;
pub const SMALLWOOD_POSEIDON2_V8_POLICY_CALLS: core::ops::Range<usize> = 94..98;
pub const SMALLWOOD_POSEIDON2_V8_CURRENT_ACCUMULATOR_CALLS: core::ops::Range<usize> = 98..101;
pub const SMALLWOOD_POSEIDON2_V8_NEXT_ACCUMULATOR_CALLS: core::ops::Range<usize> = 101..104;
pub const SMALLWOOD_POSEIDON2_V8_VALUE_LOCK_CALLS: core::ops::Range<usize> = 104..106;
pub const SMALLWOOD_POSEIDON2_V8_STABLE_CALLS: core::ops::Range<usize> = 106..125;

const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT == 125);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT == 364);
const _: () = assert!(
    SMALLWOOD_POSEIDON2_V8_HASH_ROW_START + SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT
        == SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START
);
const _: () = assert!(
    SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + SMALLWOOD_POSEIDON2_V8_STABLE_ROW_COUNT
        == SMALLWOOD_POSEIDON2_V8_ROW_COUNT
);
const _: () = assert!(79 + 15 + 4 + 3 + 3 + 2 + 19 == SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT);
const _: () = assert!(
    INPUTS * INPUT_ROWS + OUTPUTS * OUTPUT_ROWS + AUTH_ROWS == SMALLWOOD_POSEIDON2_V8_RAW_ROW_COUNT
);

#[inline]
fn fadd(left: u64, right: u64) -> u64 {
    if let Some(value) = smallwood_poseidon2_v8_symbolic_add(left, right) {
        return value;
    }
    ((u128::from(left) + u128::from(right)) % u128::from(MODULUS)) as u64
}

#[inline]
fn fsub(left: u64, right: u64) -> u64 {
    if let Some(value) = smallwood_poseidon2_v8_symbolic_sub(left, right) {
        return value;
    }
    if left >= right {
        left - right
    } else {
        MODULUS - (right - left)
    }
}

#[inline]
fn fmul(left: u64, right: u64) -> u64 {
    if let Some(value) = smallwood_poseidon2_v8_symbolic_mul(left, right) {
        return value;
    }
    ((u128::from(left) * u128::from(right)) % u128::from(MODULUS)) as u64
}

fn fpow(mut value: u64, mut exponent: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = fmul(result, value);
        }
        value = fmul(value, value);
        exponent >>= 1;
    }
    result
}

#[inline]
fn finv(value: u64) -> u64 {
    if let Some(value) = smallwood_poseidon2_v8_symbolic_inverse(value) {
        return value;
    }
    if value == 0 {
        0
    } else {
        fpow(value, MODULUS - 2)
    }
}

#[inline]
fn fselect_equal(left: u64, right: u64, equal: u64, not_equal: u64) -> u64 {
    smallwood_poseidon2_v8_symbolic_select_equal(left, right, equal, not_equal).unwrap_or_else(
        || {
            if left == right {
                equal
            } else {
                not_equal
            }
        },
    )
}

#[inline]
fn fbit(value: u64, bit: usize) -> u64 {
    smallwood_poseidon2_v8_symbolic_bit(value, bit).unwrap_or((value >> bit) & 1)
}

#[inline]
fn fbool(value: u64) -> u64 {
    fmul(value, fsub(value, 1))
}

#[inline]
const fn input_row(input: usize, offset: usize) -> usize {
    INPUT_ROW_START + input * INPUT_ROWS + offset
}

#[inline]
const fn input_value_row(input: usize) -> usize {
    input_row(input, 0)
}
#[inline]
const fn input_asset_row(input: usize) -> usize {
    input_row(input, 1)
}
#[inline]
const fn input_direction_row(input: usize, bit: usize) -> usize {
    input_row(input, 2 + bit)
}

#[inline]
const fn output_row(output: usize, offset: usize) -> usize {
    OUTPUT_ROW_START + output * OUTPUT_ROWS + offset
}
#[inline]
const fn output_value_row(output: usize) -> usize {
    output_row(output, 0)
}
#[inline]
const fn output_asset_row(output: usize) -> usize {
    output_row(output, 1)
}
#[inline]
const fn output_ciphertext_row(output: usize, limb: usize) -> usize {
    output_row(output, 2 + limb)
}
#[inline]
const fn output_auth_key_row(output: usize, limb: usize) -> usize {
    output_row(output, 8 + limb)
}

const AUTH_MODE: usize = 0;
const AUTH_INPUT_PRF: usize = AUTH_MODE + 3;
const AUTH_INPUT_KEY: usize = AUTH_INPUT_PRF + 2;
const AUTH_LEGACY: usize = AUTH_INPUT_KEY + 8;
const AUTH_CURRENT: usize = AUTH_LEGACY + 5;
const AUTH_NEXT: usize = AUTH_CURRENT + 7;
const AUTH_VALUE_LOCK: usize = AUTH_NEXT + 7;
const AUTH_STATEMENT: usize = AUTH_VALUE_LOCK + 7;
const AUTH_POLICY: usize = AUTH_STATEMENT + 7;
const AUTH_INTENT: usize = AUTH_POLICY + 7;
const AUTH_SCALAR: usize = AUTH_INTENT + 7;
const AUTH_THRESHOLD_FLAGS: usize = AUTH_SCALAR + 18;
const AUTH_SIGNER_FLAGS: usize = AUTH_THRESHOLD_FLAGS + 6;
const AUTH_COUNT_FLAGS: usize = AUTH_SIGNER_FLAGS + 6;
const AUTH_NEXT_COUNT_FLAGS: usize = AUTH_COUNT_FLAGS + 7;
const AUTH_POLICY_TAGS: usize = AUTH_NEXT_COUNT_FLAGS + 7;
const AUTH_MEMBERSHIP: usize = AUTH_POLICY_TAGS + 30;
const AUTH_DISTINCT_INV: usize = AUTH_MEMBERSHIP + 6;
const _: () = assert!(AUTH_DISTINCT_INV + 15 == AUTH_ROWS);

#[inline]
const fn auth_row(offset: usize) -> usize {
    AUTH_ROW_START + offset
}
#[inline]
const fn auth_mode_row(mode: usize) -> usize {
    auth_row(AUTH_MODE + mode)
}
#[inline]
const fn auth_input_prf_row(input: usize) -> usize {
    auth_row(AUTH_INPUT_PRF + input)
}
#[inline]
const fn auth_input_key_row(input: usize, limb: usize) -> usize {
    auth_row(AUTH_INPUT_KEY + input * 4 + limb)
}
#[inline]
const fn auth_legacy_row(limb: usize) -> usize {
    auth_row(AUTH_LEGACY + limb)
}
#[inline]
const fn auth_current_row(limb: usize) -> usize {
    auth_row(AUTH_CURRENT + limb)
}
#[inline]
const fn auth_next_row(limb: usize) -> usize {
    auth_row(AUTH_NEXT + limb)
}
#[inline]
const fn auth_value_lock_row(limb: usize) -> usize {
    auth_row(AUTH_VALUE_LOCK + limb)
}
#[inline]
const fn auth_statement_row(limb: usize) -> usize {
    auth_row(AUTH_STATEMENT + limb)
}
#[inline]
const fn auth_policy_row(limb: usize) -> usize {
    auth_row(AUTH_POLICY + limb)
}
#[inline]
const fn auth_intent_row(limb: usize) -> usize {
    auth_row(AUTH_INTENT + limb)
}
#[inline]
const fn auth_scalar_row(offset: usize) -> usize {
    auth_row(AUTH_SCALAR + offset)
}
#[inline]
const fn auth_threshold_row() -> usize {
    auth_scalar_row(0)
}
#[inline]
const fn auth_signer_count_row() -> usize {
    auth_scalar_row(1)
}
#[inline]
const fn auth_count_row() -> usize {
    auth_scalar_row(2)
}
#[inline]
const fn auth_approved_row(slot: usize) -> usize {
    auth_scalar_row(3 + slot)
}
#[inline]
const fn auth_next_count_row() -> usize {
    auth_scalar_row(9)
}
#[inline]
const fn auth_next_approved_row(slot: usize) -> usize {
    auth_scalar_row(10 + slot)
}
#[inline]
const fn auth_reserved_signer_row() -> usize {
    auth_scalar_row(16)
}
#[inline]
const fn auth_reserved_inverse_row() -> usize {
    auth_scalar_row(17)
}
#[inline]
const fn auth_threshold_flag_row(flag: usize) -> usize {
    auth_row(AUTH_THRESHOLD_FLAGS + flag)
}
#[inline]
const fn auth_signer_flag_row(flag: usize) -> usize {
    auth_row(AUTH_SIGNER_FLAGS + flag)
}
#[inline]
const fn auth_count_flag_row(flag: usize) -> usize {
    auth_row(AUTH_COUNT_FLAGS + flag)
}
#[inline]
const fn auth_next_count_flag_row(flag: usize) -> usize {
    auth_row(AUTH_NEXT_COUNT_FLAGS + flag)
}
#[inline]
const fn auth_policy_tag_row(slot: usize, limb: usize) -> usize {
    auth_row(AUTH_POLICY_TAGS + slot * SIGNER_TAG_WORDS + limb)
}
#[inline]
const fn auth_membership_row(slot: usize) -> usize {
    auth_row(AUTH_MEMBERSHIP + slot)
}
#[inline]
const fn auth_distinct_inverse_row(pair: usize) -> usize {
    auth_row(AUTH_DISTINCT_INV + pair)
}

#[inline]
const fn tail_source_index(slot: usize) -> usize {
    packed_index(
        SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + slot / 64,
        slot % 64,
    )
}

#[inline]
const fn hash_initial_index(call: usize, lane: usize) -> usize {
    SMALLWOOD_POSEIDON2_V8_HASH_ROW_START * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
        + smallwood_poseidon2_v8_hash_call_initial_witness_index(call, lane)
}

#[inline]
const fn hash_final_index(call: usize, lane: usize) -> usize {
    SMALLWOOD_POSEIDON2_V8_HASH_ROW_START * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
        + smallwood_poseidon2_v8_hash_call_final_witness_index(call, lane)
}

#[inline]
const fn raw_index(row: usize) -> usize {
    packed_index(row, 0)
}

fn field_product(values: impl IntoIterator<Item = u64>) -> u64 {
    values.into_iter().fold(1, fmul)
}

fn field_sum(values: impl IntoIterator<Item = u64>) -> u64 {
    values.into_iter().fold(0, fadd)
}

fn slot_membership_zero(public: &[u64; 120], asset: u64) -> u64 {
    // Padding marks absent balance slots and is never a valid note asset.  Omitting padding from
    // this product makes the active-note membership identity vanish only at an actual configured
    // asset, even when two or three trailing public slots repeat the padding sentinel.
    field_product((54..58).map(|slot| {
        let slot_asset = public[slot];
        fselect_equal(
            slot_asset,
            BALANCE_SLOT_PADDING_FIELD_ID,
            1,
            fsub(asset, slot_asset),
        )
    }))
}

fn slot_weights(public: &[u64; 120], asset: u64) -> [u64; 4] {
    core::array::from_fn(|slot| {
        let slot_asset = public[54 + slot];
        let denominator = field_product((0..4).filter(|other| *other != slot).map(|other| {
            let other_asset = public[54 + other];
            fselect_equal(
                other_asset,
                BALANCE_SLOT_PADDING_FIELD_ID,
                1,
                fsub(slot_asset, other_asset),
            )
        }));
        let numerator = field_product((0..4).filter(|other| *other != slot).map(|other| {
            let other_asset = public[54 + other];
            fselect_equal(
                other_asset,
                BALANCE_SLOT_PADDING_FIELD_ID,
                1,
                fsub(asset, other_asset),
            )
        }));
        fselect_equal(
            slot_asset,
            BALANCE_SLOT_PADDING_FIELD_ID,
            0,
            fmul(numerator, finv(denominator)),
        )
    })
}

#[inline]
fn signed_from_parts(sign: u64, magnitude: u64) -> u64 {
    fsub(magnitude, fmul(fadd(sign, sign), magnitude))
}

fn push_base_constraints(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    rows: &[u64],
    out: &mut Vec<u64>,
) {
    for index in [0usize, 1, 2, 3, 45, 58, 61] {
        out.push(fbool(public[index]));
    }
    let direction = public[83];
    out.push(field_product([
        direction,
        fsub(direction, 1),
        fsub(direction, 2),
    ]));
    let inv2 = finv(2);
    let enabled = fmul(fmul(direction, fsub(3, direction)), inv2);
    let mint = fmul(direction, fsub(2, direction));
    out.push(fsub(public[58], enabled));
    out.push(fsub(public[61], mint));
    out.push(fsub(public[59], public[84]));
    out.push(fsub(public[60], public[85]));
    out.push(fsub(public[62], public[86]));
    for value in &public[63..81] {
        out.push(*value);
    }

    for input in 0..INPUTS {
        let flag = public[input];
        for bit in 0..MERKLE_DEPTH {
            out.push(fbool(rows[input_direction_row(input, bit)]));
        }
        out.push(fmul(
            flag,
            slot_membership_zero(public, rows[input_asset_row(input)]),
        ));
    }
    for output in 0..OUTPUTS {
        let flag = public[2 + output];
        out.push(fmul(
            flag,
            slot_membership_zero(public, rows[output_asset_row(output)]),
        ));
        let inactive = fsub(1, flag);
        for limb in 0..6 {
            out.push(fmul(inactive, rows[output_ciphertext_row(output, limb)]));
        }
    }

    out.push(fmul(enabled, slot_membership_zero(public, public[59])));

    let signed_balance = signed_from_parts(public[45], public[46]);
    let signed_stable = signed_from_parts(public[61], public[62]);
    let native_expected = fsub(public[44], signed_balance);
    for slot in 0..4 {
        let mut delta = 0;
        for input in 0..INPUTS {
            let weight = slot_weights(public, rows[input_asset_row(input)])[slot];
            delta = fadd(
                delta,
                fmul(fmul(public[input], rows[input_value_row(input)]), weight),
            );
        }
        for output in 0..OUTPUTS {
            let weight = slot_weights(public, rows[output_asset_row(output)])[slot];
            delta = fsub(
                delta,
                fmul(
                    fmul(public[2 + output], rows[output_value_row(output)]),
                    weight,
                ),
            );
        }
        let expected = if slot == 0 {
            native_expected
        } else {
            fselect_equal(
                public[54 + slot],
                public[59],
                fmul(enabled, signed_stable),
                0,
            )
        };
        out.push(fsub(delta, expected));
    }

    for row in 0..4 {
        let value = rows[SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + row];
        out.push(field_product([
            value,
            fsub(value, 1),
            fsub(value, 2),
            fsub(value, 3),
        ]));
    }
    out.push(fbool(
        rows[SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + 4],
    ));

    for group in 0..INLINE_MERKLE_GROUPS {
        let base = SMALLWOOD_POSEIDON2_V8_INLINE_ROW_START + group * 4;
        let current = rows[base];
        let left = rows[base + 1];
        let right = rows[base + 2];
        let direction = rows[base + 3];
        out.push(fsub(
            current,
            fadd(left, fmul(direction, fsub(right, left))),
        ));
    }
    out.push(fmul(
        rows[INLINE_POLICY_ROW_START + 2],
        fsub(
            rows[INLINE_POLICY_ROW_START],
            rows[INLINE_POLICY_ROW_START + 1],
        ),
    ));

    push_auth_constraints(public, rows, out);
}

fn push_auth_constraints(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    rows: &[u64],
    out: &mut Vec<u64>,
) {
    let single = rows[auth_mode_row(0)];
    let approval = rows[auth_mode_row(1)];
    let final_mode = rows[auth_mode_row(2)];
    let non_single = fadd(approval, final_mode);
    for mode in [single, approval, final_mode] {
        out.push(fbool(mode));
    }
    out.push(fsub(fadd(fadd(single, approval), final_mode), 1));

    let threshold = rows[auth_threshold_row()];
    let signer_count = rows[auth_signer_count_row()];
    let count = rows[auth_count_row()];
    let next_count = rows[auth_next_count_row()];
    let reserved_signer = rows[auth_reserved_signer_row()];
    let reserved_inverse = rows[auth_reserved_inverse_row()];
    let approved: [u64; 6] = core::array::from_fn(|slot| rows[auth_approved_row(slot)]);
    let next_approved: [u64; 6] = core::array::from_fn(|slot| rows[auth_next_approved_row(slot)]);
    let threshold_flags: [u64; 6] =
        core::array::from_fn(|slot| rows[auth_threshold_flag_row(slot)]);
    let signer_flags: [u64; 6] = core::array::from_fn(|slot| rows[auth_signer_flag_row(slot)]);
    let count_flags: [u64; 7] = core::array::from_fn(|slot| rows[auth_count_flag_row(slot)]);
    let next_count_flags: [u64; 7] =
        core::array::from_fn(|slot| rows[auth_next_count_flag_row(slot)]);
    let memberships: [u64; 6] = core::array::from_fn(|slot| rows[auth_membership_row(slot)]);

    for limb in 0..DIGEST {
        out.push(fmul(single, rows[auth_policy_row(limb)]));
        out.push(fmul(single, rows[auth_intent_row(limb)]));
    }
    for value in [
        threshold,
        signer_count,
        count,
        next_count,
        reserved_signer,
        reserved_inverse,
    ] {
        out.push(fmul(single, value));
    }
    for value in approved
        .into_iter()
        .chain(next_approved)
        .chain(threshold_flags)
        .chain(signer_flags)
        .chain(count_flags)
        .chain(next_count_flags)
        .chain(memberships)
    {
        out.push(fmul(single, value));
    }
    for slot in 0..SIGNERS {
        for limb in 0..SIGNER_TAG_WORDS {
            out.push(fmul(single, rows[auth_policy_tag_row(slot, limb)]));
        }
    }
    for pair in 0..PAIRS {
        out.push(fmul(single, rows[auth_distinct_inverse_row(pair)]));
    }

    let current_prf = rows[auth_current_row(4)];
    let value_lock_prf = rows[auth_value_lock_row(4)];
    let legacy_prf = rows[auth_legacy_row(0)];
    for input in 0..INPUTS {
        let flag = public[input];
        let approval_prf = if input == 0 { current_prf } else { legacy_prf };
        let final_prf = if input == 0 {
            value_lock_prf
        } else {
            current_prf
        };
        let expected = fmul(
            flag,
            fadd(
                fmul(single, legacy_prf),
                fadd(fmul(approval, approval_prf), fmul(final_mode, final_prf)),
            ),
        );
        out.push(fsub(rows[auth_input_prf_row(input)], expected));
        for limb in 0..4 {
            let legacy = rows[auth_legacy_row(1 + limb)];
            let current = rows[auth_current_row(limb)];
            let value_lock = rows[auth_value_lock_row(limb)];
            let approval_key = if input == 0 { current } else { legacy };
            let final_key = if input == 0 { value_lock } else { current };
            let expected = fmul(
                flag,
                fadd(
                    fmul(single, legacy),
                    fadd(fmul(approval, approval_key), fmul(final_mode, final_key)),
                ),
            );
            out.push(fsub(rows[auth_input_key_row(input, limb)], expected));
        }
    }

    out.push(fmul(approval, fsub(public[0], 1)));
    out.push(fmul(approval, fsub(public[1], 1)));
    out.push(fmul(approval, fsub(public[2], 1)));
    out.push(fmul(final_mode, fsub(public[0], 1)));
    out.push(fmul(final_mode, fsub(public[1], 1)));
    for limb in 0..4 {
        out.push(fmul(
            approval,
            fsub(
                rows[output_auth_key_row(0, limb)],
                rows[auth_next_row(limb)],
            ),
        ));
    }

    for bit in threshold_flags {
        out.push(fmul(non_single, fbool(bit)));
    }
    out.push(fmul(non_single, fsub(field_sum(threshold_flags), 1)));
    out.push(fmul(
        non_single,
        fsub(
            threshold,
            field_sum(
                threshold_flags
                    .into_iter()
                    .enumerate()
                    .map(|(i, bit)| fmul(bit, (i + 1) as u64)),
            ),
        ),
    ));
    for bit in signer_flags {
        out.push(fmul(non_single, fbool(bit)));
    }
    out.push(fmul(non_single, fsub(field_sum(signer_flags), 1)));
    out.push(fmul(
        non_single,
        fsub(
            signer_count,
            field_sum(
                signer_flags
                    .into_iter()
                    .enumerate()
                    .map(|(i, bit)| fmul(bit, (i + 1) as u64)),
            ),
        ),
    ));
    let mut threshold_too_large = 0;
    for (index, bit) in threshold_flags.into_iter().enumerate() {
        threshold_too_large = fadd(
            threshold_too_large,
            fmul(bit, field_sum(signer_flags[..index].iter().copied())),
        );
    }
    out.push(fmul(non_single, threshold_too_large));

    for bit in count_flags {
        out.push(fmul(non_single, fbool(bit)));
    }
    out.push(fmul(non_single, fsub(field_sum(count_flags), 1)));
    out.push(fmul(
        non_single,
        fsub(
            count,
            field_sum(
                count_flags
                    .into_iter()
                    .enumerate()
                    .map(|(i, bit)| fmul(bit, i as u64)),
            ),
        ),
    ));
    for bit in next_count_flags {
        out.push(fmul(approval, fbool(bit)));
    }
    out.push(fmul(approval, fsub(field_sum(next_count_flags), 1)));
    out.push(fmul(
        approval,
        fsub(
            next_count,
            field_sum(
                next_count_flags
                    .into_iter()
                    .enumerate()
                    .map(|(i, bit)| fmul(bit, i as u64)),
            ),
        ),
    ));
    out.push(fmul(approval, fsub(fsub(next_count, count), 1)));
    out.push(fmul(approval, count_flags[6]));

    let slot_active = |slot: usize| field_sum(signer_flags[slot..].iter().copied());
    for slot in 0..SIGNERS {
        out.push(fmul(non_single, fbool(approved[slot])));
        out.push(fmul(
            fmul(non_single, approved[slot]),
            fsub(1, slot_active(slot)),
        ));
    }
    out.push(fmul(non_single, fsub(count, field_sum(approved))));
    for slot in 0..SIGNERS {
        out.push(fmul(approval, fbool(next_approved[slot])));
        out.push(fmul(
            fmul(approval, next_approved[slot]),
            fsub(1, slot_active(slot)),
        ));
    }
    out.push(fmul(approval, fsub(next_count, field_sum(next_approved))));
    for slot in 0..SIGNERS {
        out.push(fmul(fmul(approval, memberships[slot]), approved[slot]));
        out.push(fmul(
            approval,
            fsub(fsub(next_approved[slot], approved[slot]), memberships[slot]),
        ));
    }
    out.push(fmul(approval, reserved_signer));
    out.push(fmul(approval, reserved_inverse));
    for bit in memberships {
        out.push(fmul(approval, fbool(bit)));
    }
    out.push(fmul(approval, fsub(field_sum(memberships), 1)));
    for slot in 0..SIGNERS {
        out.push(fmul(
            fmul(approval, memberships[slot]),
            fsub(1, slot_active(slot)),
        ));
        for limb in 0..SIGNER_TAG_WORDS {
            out.push(fmul(
                fmul(approval, memberships[slot]),
                fsub(
                    rows[auth_legacy_row(limb)],
                    rows[auth_policy_tag_row(slot, limb)],
                ),
            ));
        }
    }
    for slot in 0..SIGNERS {
        let inactive = fsub(1, slot_active(slot));
        for limb in 0..SIGNER_TAG_WORDS {
            out.push(fmul(
                fmul(non_single, inactive),
                rows[auth_policy_tag_row(slot, limb)],
            ));
        }
    }
    let mut pair = 0;
    for left in 0..SIGNERS {
        for right in left + 1..SIGNERS {
            let active_pair = fmul(slot_active(left), slot_active(right));
            let diff = fsub(
                rows[auth_policy_tag_row(left, 0)],
                rows[auth_policy_tag_row(right, 0)],
            );
            let inverse = rows[auth_distinct_inverse_row(pair)];
            out.push(fmul(
                fmul(non_single, active_pair),
                fsub(fmul(diff, inverse), 1),
            ));
            out.push(fmul(fmul(non_single, fsub(1, active_pair)), inverse));
            pair += 1;
        }
    }

    let mut below = 0;
    for (threshold_index, threshold_flag) in threshold_flags.into_iter().enumerate() {
        below = fadd(
            below,
            fmul(
                threshold_flag,
                field_sum(count_flags[..=threshold_index].iter().copied()),
            ),
        );
    }
    out.push(fmul(final_mode, below));
    for limb in 0..DIGEST {
        out.push(fmul(
            final_mode,
            fsub(rows[auth_intent_row(limb)], rows[auth_statement_row(limb)]),
        ));
    }
    out.push(fmul(final_mode, next_count));
    for value in next_approved {
        out.push(fmul(final_mode, value));
    }
    out.push(fmul(final_mode, reserved_signer));
    out.push(fmul(final_mode, reserved_inverse));
    out.push(fmul(final_mode, fsub(next_count_flags[0], 1)));
    for value in &next_count_flags[1..] {
        out.push(fmul(final_mode, *value));
    }
    for value in memberships {
        out.push(fmul(final_mode, value));
    }
}

#[derive(Clone, Debug, Default)]
struct LinearExpression {
    terms: Vec<(usize, u64)>,
    constant: u64,
}

impl LinearExpression {
    fn witness(index: usize) -> Self {
        Self {
            terms: vec![(index, 1)],
            constant: 0,
        }
    }

    fn constant(value: u64) -> Self {
        Self {
            terms: Vec::new(),
            constant: value,
        }
    }

    fn add(mut self, other: Self) -> Self {
        self.terms.extend(other.terms);
        self.constant = fadd(self.constant, other.constant);
        self
    }

    fn sub(mut self, other: Self) -> Self {
        self.terms.extend(
            other
                .terms
                .into_iter()
                .map(|(index, coefficient)| (index, fsub(0, coefficient))),
        );
        self.constant = fsub(self.constant, other.constant);
        self
    }

    fn scale(mut self, coefficient: u64) -> Self {
        for (_, value) in &mut self.terms {
            *value = fmul(*value, coefficient);
        }
        self.constant = fmul(self.constant, coefficient);
        self
    }
}

#[derive(Clone, Debug)]
struct CsrBuilder {
    active_family: Option<usize>,
    rows_by_family: Vec<Vec<Option<CsrNormalizedRow>>>,
    program_error: Option<String>,
    symbolic_attempts: Vec<PendingSymbolicCsrAttempt>,
}

#[derive(Clone, Debug)]
// The numeric rows survive only as an independent test oracle. Production adapters are built
// directly from `ProgramSpecializedCsr`, so these fields are intentionally unread outside tests.
#[cfg_attr(not(test), allow(dead_code))]
struct CsrNormalizedRow {
    terms: Vec<(usize, u64)>,
    target: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SmallwoodPoseidon2V8SymbolicCsrAttempt {
    pub family: u16,
    pub terms: Vec<(u32, u32)>,
    pub target: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SmallwoodPoseidon2V8CsrExpressionProgram {
    pub expressions: Vec<crate::smallwood_poseidon2_v8_ir::SmallwoodPoseidon2V8Expr>,
    pub attempts: Vec<SmallwoodPoseidon2V8SymbolicCsrAttempt>,
}

#[derive(Clone, Debug)]
struct PendingSymbolicCsrAttempt {
    family: u16,
    terms: Vec<(u32, u64)>,
    target: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FinalizedCsr {
    offsets: Vec<u32>,
    indices: Vec<u32>,
    coefficients: Vec<u64>,
    targets: Vec<u64>,
    constraint_family_ids: Vec<u16>,
    family_receipt: SmallwoodPoseidon2V8CsrFamilyReceipt,
}

/// A CSR table that can only be constructed by specializing the relation-id-bound HGV8RP03
/// program.  Keeping this as a private newtype makes the adapter's source-level refinement a type
/// invariant: the verifier never stores a table emitted by an independent numeric compiler.
#[derive(Clone, Debug)]
struct ProgramSpecializedCsr(FinalizedCsr);

impl ProgramSpecializedCsr {
    fn for_public_words(
        public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    ) -> Result<Self, SmallwoodPoseidon2V8RelationError> {
        specialize_executable_csr_program(public).map(Self)
    }

    fn finalized(&self) -> &FinalizedCsr {
        &self.0
    }
}

impl CsrBuilder {
    fn new() -> Self {
        Self {
            active_family: None,
            rows_by_family: vec![Vec::new(); SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES.len()],
            program_error: None,
            symbolic_attempts: Vec::new(),
        }
    }

    fn set_family(&mut self, name: &'static str) {
        self.active_family = SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
            .iter()
            .position(|family| family.name == name);
        if self.active_family.is_none() && self.program_error.is_none() {
            self.program_error = Some(format!("unknown symbolic CSR family {name}"));
        }
    }

    fn push(&mut self, terms: impl IntoIterator<Item = (usize, u64)>, target: u64) {
        let family_index = self.active_family;
        if family_index.is_none() && self.program_error.is_none() {
            self.program_error = Some("CSR emission without an active symbolic family".to_owned());
        }
        let terms = terms.into_iter().collect::<Vec<_>>();
        if smallwood_poseidon2_v8_expression_program_is_active() {
            if let Some(family_index) = family_index {
                self.symbolic_attempts.push(PendingSymbolicCsrAttempt {
                    family: u16::try_from(family_index).expect("86 V8 CSR families fit u16"),
                    terms: terms
                        .iter()
                        .map(|(index, coefficient)| {
                            (
                                u32::try_from(*index).expect("V8 witness index fits u32"),
                                *coefficient,
                            )
                        })
                        .collect(),
                    target,
                });
            }
            return;
        }
        let mut normalized = std::collections::BTreeMap::<usize, u64>::new();
        for (index, coefficient) in terms {
            let coefficient = coefficient % MODULUS;
            if coefficient == 0 {
                continue;
            }
            let entry = normalized.entry(index).or_default();
            *entry = fadd(*entry, coefficient);
        }
        normalized.retain(|_, coefficient| *coefficient != 0);
        if normalized.is_empty() {
            if target == 0 {
                if let Some(family_index) = family_index {
                    self.rows_by_family[family_index].push(None);
                }
                return;
            }
            // V8 forbids empty CSR rows.  Route an impossible public-only equation through the
            // canonical zero source cell, which is independently constrained below.
            normalized.insert(tail_source_index(120), 1);
        }
        if let Some(family_index) = family_index {
            self.rows_by_family[family_index].push(Some(CsrNormalizedRow {
                terms: normalized.into_iter().collect(),
                target,
            }));
        }
    }

    fn bind(&mut self, witness_index: usize, expression: LinearExpression) {
        let mut terms = Vec::with_capacity(1 + expression.terms.len());
        terms.push((witness_index, 1));
        terms.extend(
            expression
                .terms
                .into_iter()
                .map(|(index, coefficient)| (index, fsub(0, coefficient))),
        );
        self.push(terms, expression.constant);
    }

    fn zero(&mut self, witness_index: usize) {
        self.push([(witness_index, 1)], 0);
    }

    fn equality(&mut self, left: usize, right: usize) {
        self.push([(left, 1), (right, NEG_ONE)], 0);
    }

    fn expression_zero(&mut self, expression: LinearExpression) {
        self.push(expression.terms, fsub(0, expression.constant));
    }

    // Independent numeric compiler used by differential mutation tests. It is not an adapter
    // construction path and therefore is intentionally unused by non-test builds.
    #[cfg_attr(not(test), allow(dead_code))]
    fn finish(self) -> Result<FinalizedCsr, SmallwoodPoseidon2V8RelationError> {
        if let Some(detail) = self.program_error {
            return Err(SmallwoodPoseidon2V8RelationError::CsrProgramMismatch { detail });
        }
        let mut cursor = SmallwoodPoseidon2V8CsrProgramCursor::new();
        let mut offsets = vec![0];
        let mut indices = Vec::new();
        let mut coefficients = Vec::new();
        let mut targets = Vec::new();
        let mut constraint_family_ids = Vec::new();
        for (family_index, attempts) in self.rows_by_family.into_iter().enumerate() {
            for row in attempts {
                cursor
                    .record_attempt(family_index, row.is_some())
                    .map_err(
                        |error| SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
                            detail: format!("{error:?}"),
                        },
                    )?;
                let Some(row) = row else {
                    continue;
                };
                for (index, coefficient) in row.terms {
                    indices.push(u32::try_from(index).expect("V8 witness index fits u32"));
                    coefficients.push(coefficient);
                }
                targets.push(row.target);
                constraint_family_ids
                    .push(u16::try_from(family_index).expect("86 symbolic CSR families fit u16"));
                offsets.push(u32::try_from(indices.len()).expect("V8 CSR terms fit u32"));
            }
        }
        let family_receipt = cursor.finish().map_err(|error| {
            SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
                detail: format!("{error:?}"),
            }
        })?;
        debug_assert_eq!(family_receipt.emitted_total as usize, targets.len());
        Ok(FinalizedCsr {
            offsets,
            indices,
            coefficients,
            targets,
            constraint_family_ids,
            family_receipt,
        })
    }

    fn finish_symbolic(self) -> SmallwoodPoseidon2V8CsrExpressionProgram {
        assert!(
            self.program_error.is_none(),
            "V8 symbolic CSR construction has a known family"
        );
        let mut symbolic_attempts = self.symbolic_attempts;
        symbolic_attempts.sort_by_key(|attempt| attempt.family);
        let mut handles = Vec::new();
        for attempt in &symbolic_attempts {
            handles.extend(attempt.terms.iter().map(|(_, coefficient)| *coefficient));
            handles.push(attempt.target);
        }
        let expression_program = finish_smallwood_poseidon2_v8_expression_program(handles);
        let mut roots = expression_program.roots.into_iter();
        let attempts = symbolic_attempts
            .into_iter()
            .map(|attempt| {
                let terms = attempt
                    .terms
                    .into_iter()
                    .map(|(index, _)| {
                        (
                            index,
                            roots.next().expect("symbolic CSR coefficient root exists"),
                        )
                    })
                    .collect();
                let target = roots.next().expect("symbolic CSR target root exists");
                SmallwoodPoseidon2V8SymbolicCsrAttempt {
                    family: attempt.family,
                    terms,
                    target,
                }
            })
            .collect();
        assert!(roots.next().is_none(), "symbolic CSR root stream is exact");
        SmallwoodPoseidon2V8CsrExpressionProgram {
            expressions: expression_program.expressions,
            attempts,
        }
    }
}

fn absorbed_expression(call: usize, input_index: usize) -> LinearExpression {
    let block = input_index / POSEIDON2_WIDTH16_RATE;
    let lane = input_index % POSEIDON2_WIDTH16_RATE;
    let current = LinearExpression::witness(hash_initial_index(call + block, lane));
    if block == 0 {
        current
    } else {
        current.sub(LinearExpression::witness(hash_final_index(
            call + block - 1,
            lane,
        )))
    }
}

fn bind_sponge(
    csr: &mut CsrBuilder,
    call_start: usize,
    domain: u64,
    inputs: &[Option<LinearExpression>],
) -> usize {
    let blocks = inputs.len().max(1).div_ceil(POSEIDON2_WIDTH16_RATE);
    for block in 0..blocks {
        let call = call_start + block;
        for lane in 0..POSEIDON2_WIDTH16_RATE {
            let input_index = block * POSEIDON2_WIDTH16_RATE + lane;
            match inputs.get(input_index).cloned() {
                Some(Some(source)) => {
                    let expected = if block == 0 {
                        source
                    } else {
                        LinearExpression::witness(hash_final_index(call - 1, lane)).add(source)
                    };
                    csr.bind(hash_initial_index(call, lane), expected);
                }
                Some(None) => {
                    // An explicit private source is represented by the
                    // initial-minus-previous-final difference, so no rate-lane equation is
                    // emitted. First-block private sources are the initial lane itself.
                }
                None => {
                    // A lane beyond the declared input is canonical sponge padding, not a
                    // private absorbed word. It is zero in the first block and preserves the
                    // previous final state in every later block.
                    let expected = if block == 0 {
                        LinearExpression::default()
                    } else {
                        LinearExpression::witness(hash_final_index(call - 1, lane))
                    };
                    csr.bind(hash_initial_index(call, lane), expected);
                }
            }
        }
        for lane in POSEIDON2_WIDTH16_RATE..POSEIDON2_WIDTH16_WIDTH {
            let expected = if block == 0 {
                let value = match lane {
                    8 => domain,
                    9 => inputs.len() as u64,
                    10 => POSEIDON2_WIDTH16_SPONGE_MODE_MARKER,
                    11 if blocks == 1 => 1,
                    15 => POSEIDON2_WIDTH16_SUITE_MARKER,
                    _ => 0,
                };
                LinearExpression::constant(value)
            } else {
                let mut value = LinearExpression::witness(hash_final_index(call - 1, lane));
                if lane == 11 && block + 1 == blocks {
                    value.constant = 1;
                }
                value
            };
            csr.bind(hash_initial_index(call, lane), expected);
        }
    }
    call_start + blocks - 1
}

fn bind_compress14(
    csr: &mut CsrBuilder,
    call: usize,
    domain: u64,
    left: [LinearExpression; DIGEST],
    right: [LinearExpression; DIGEST],
) {
    for (lane, expression) in left.into_iter().chain(right).enumerate() {
        csr.bind(hash_initial_index(call, lane), expression);
    }
    csr.bind(
        hash_initial_index(call, 14),
        LinearExpression::constant(domain),
    );
    csr.bind(
        hash_initial_index(call, 15),
        LinearExpression::constant(POSEIDON2_WIDTH16_SUITE_MARKER),
    );
}

fn input_note_call(input: usize) -> usize {
    if input == 0 {
        1
    } else {
        37
    }
}
fn input_merkle_call(input: usize, level: usize) -> usize {
    if input == 0 {
        4 + level
    } else {
        40 + level
    }
}
fn input_nullifier_call(input: usize) -> usize {
    if input == 0 {
        36
    } else {
        72
    }
}
fn output_note_call(output: usize) -> usize {
    73 + output * 3
}

fn inline_slot(input: usize, level: usize, limb: usize) -> (usize, usize) {
    let slot = (input * MERKLE_DEPTH + level) * DIGEST + limb;
    (slot / 64, slot % 64)
}

fn inline_index(input: usize, level: usize, limb: usize, component: usize) -> usize {
    let (group, lane) = inline_slot(input, level, limb);
    packed_index(
        SMALLWOOD_POSEIDON2_V8_INLINE_ROW_START + group * 4 + component,
        lane,
    )
}

fn build_base_linear_constraints(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    csr: &mut CsrBuilder,
) {
    // Raw semantic rows are scalar values replicated across all SIMD lanes.  This makes every
    // cross-row base predicate a genuine low-degree row-polynomial identity.
    csr.set_family("base.raw_replicate");
    for row in SMALLWOOD_POSEIDON2_V8_RAW_ROW_START
        ..SMALLWOOD_POSEIDON2_V8_RAW_ROW_START + SMALLWOOD_POSEIDON2_V8_RAW_ROW_COUNT
    {
        for lane in 1..SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR {
            csr.equality(packed_index(row, lane), packed_index(row, 0));
        }
    }

    // Canonical inactive raw padding and public ciphertext bridge.
    csr.set_family("base.input_inactive_raw");
    for input in 0..INPUTS {
        let inactive = fsub(1, public[input]);
        for row in input_value_row(input)..=input_direction_row(input, MERKLE_DEPTH - 1) {
            csr.push([(raw_index(row), inactive)], 0);
        }
    }
    for output in 0..OUTPUTS {
        let inactive = fsub(1, public[2 + output]);
        csr.set_family("base.output_inactive_raw");
        for row in output_value_row(output)..=output_auth_key_row(output, 3) {
            csr.push([(raw_index(row), inactive)], 0);
        }
        csr.set_family("base.output_ciphertext_bridge");
        for limb in 0..6 {
            csr.push(
                [(raw_index(output_ciphertext_row(output, limb)), 1)],
                public[32 + output * 6 + limb],
            );
        }
    }

    // Exact 61-bit ranges for the four note values and three public magnitudes.
    let ranged = [
        LinearExpression::witness(raw_index(input_value_row(0))),
        LinearExpression::witness(raw_index(input_value_row(1))),
        LinearExpression::witness(raw_index(output_value_row(0))),
        LinearExpression::witness(raw_index(output_value_row(1))),
        LinearExpression::constant(public[44]),
        LinearExpression::constant(public[46]),
        LinearExpression::constant(public[62]),
    ];
    csr.set_family("base.dense_range_reconstruct");
    for (value_index, value) in ranged.into_iter().enumerate() {
        let mut reconstruction = LinearExpression::default();
        let mut power = 1;
        for digit in 0..30 {
            let slot = value_index * 30 + digit;
            reconstruction.terms.push((
                packed_index(
                    SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + slot / 64,
                    slot % 64,
                ),
                power,
            ));
            power = fmul(power, 4);
        }
        reconstruction.terms.push((
            packed_index(
                SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + 4,
                value_index,
            ),
            1u64 << 60,
        ));
        let equation = value.sub(reconstruction);
        csr.push(equation.terms, fsub(0, equation.constant));
    }
    // Hegemon has no transparent pool.  Bind both retained value-balance
    // statement words to the independently constrained canonical zero source
    // cell so the executable relation, not only typed admission, rejects any
    // signed or unsigned transparent delta.
    csr.set_family("base.transparent_value_balance_zero");
    csr.push([(tail_source_index(120), 1)], public[45]);
    csr.push([(tail_source_index(120), 1)], public[46]);
    csr.set_family("base.dense_range_padding");
    for slot in 210..256 {
        csr.zero(packed_index(
            SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + slot / 64,
            slot % 64,
        ));
    }
    csr.set_family("base.dense_top_padding");
    for lane in 7..64 {
        csr.zero(packed_index(
            SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + 4,
            lane,
        ));
    }

    // The global spend secret is explicit in spare source slots.  Both active inputs must carry
    // the same key; an inactive slot is zero and cannot smuggle an unconstrained second secret.
    let both = fmul(public[0], public[1]);
    let mut chosen_spend_sources = Vec::with_capacity(4);
    for limb in 0..4 {
        let key0 = tail_source_index(112 + limb);
        let key1 = tail_source_index(116 + limb);
        csr.set_family("base.spend_key_inactive");
        csr.push([(key0, fsub(1, public[0]))], 0);
        csr.push([(key1, fsub(1, public[1]))], 0);
        csr.set_family("base.spend_key_equal");
        csr.push([(key0, both), (key1, fsub(0, both))], 0);
        let chosen = LinearExpression::witness(key0)
            .scale(public[0])
            .add(LinearExpression::witness(key1).scale(fmul(fsub(1, public[0]), public[1])));
        chosen_spend_sources.push(Some(chosen));
    }
    csr.set_family("hash.transaction_prf_initial");
    bind_sponge(csr, 0, NULLIFIER_DOMAIN_TAG, &chosen_spend_sources);
    csr.set_family("hash.transaction_prf_to_legacy");
    for limb in 0..5 {
        csr.equality(raw_index(auth_legacy_row(limb)), hash_final_index(0, limb));
    }

    for input in 0..INPUTS {
        let note_call = input_note_call(input);
        let mut note_sources = vec![None; 18];
        note_sources[0] = Some(LinearExpression::witness(raw_index(input_value_row(input))));
        note_sources[1] = Some(LinearExpression::witness(raw_index(input_asset_row(input))));
        for limb in 0..4 {
            note_sources[14 + limb] = Some(LinearExpression::witness(raw_index(
                auth_input_key_row(input, limb),
            )));
        }
        csr.set_family("hash.input_note_initial");
        bind_sponge(csr, note_call, NOTE_DOMAIN_TAG, &note_sources);
        let inactive = fsub(1, public[input]);
        csr.set_family("base.input_note_inactive_preimage");
        for index in 0..18 {
            let expression = absorbed_expression(note_call, index).scale(inactive);
            csr.push(expression.terms, fsub(0, expression.constant));
        }

        for level in 0..MERKLE_DEPTH {
            let call = input_merkle_call(input, level);
            let left = core::array::from_fn(|limb| {
                LinearExpression::witness(inline_index(input, level, limb, 1))
            });
            let right = core::array::from_fn(|limb| {
                LinearExpression::witness(inline_index(input, level, limb, 2))
            });
            csr.set_family("hash.input_merkle_initial");
            bind_compress14(csr, call, MERKLE_DOMAIN_TAG, left, right);
            for limb in 0..DIGEST {
                let current_source = if level == 0 {
                    LinearExpression::witness(hash_final_index(note_call + 2, limb))
                } else {
                    LinearExpression::witness(hash_final_index(call - 1, limb))
                };
                csr.set_family("base.input_merkle_current_copy");
                csr.bind(inline_index(input, level, limb, 0), current_source);
                csr.set_family("base.input_merkle_direction_copy");
                csr.bind(
                    inline_index(input, level, limb, 3),
                    LinearExpression::witness(raw_index(input_direction_row(input, level))),
                );
                csr.set_family("base.input_merkle_inactive_right");
                csr.push(
                    [(inline_index(input, level, limb, 2), fsub(1, public[input]))],
                    0,
                );
            }
        }
        let root_call = input_merkle_call(input, MERKLE_DEPTH - 1);
        csr.set_family("base.input_merkle_public_root");
        for limb in 0..DIGEST {
            csr.push(
                [(hash_final_index(root_call, limb), public[input])],
                fmul(public[input], public[47 + limb]),
            );
        }

        let mut nullifier_sources = vec![Some(LinearExpression::witness(raw_index(
            auth_input_prf_row(input),
        )))];
        let mut position = LinearExpression::default();
        for bit in 0..MERKLE_DEPTH {
            position
                .terms
                .push((raw_index(input_direction_row(input, bit)), 1u64 << bit));
        }
        nullifier_sources.push(Some(position));
        nullifier_sources.extend((0..4).map(|limb| Some(absorbed_expression(note_call, 6 + limb))));
        let nullifier_call = input_nullifier_call(input);
        csr.set_family("hash.input_nullifier_initial");
        bind_sponge(
            csr,
            nullifier_call,
            NULLIFIER_DOMAIN_TAG,
            &nullifier_sources,
        );
        csr.set_family("base.input_nullifier_public");
        for limb in 0..DIGEST {
            csr.push(
                [(hash_final_index(nullifier_call, limb), public[input])],
                fmul(public[input], public[4 + input * DIGEST + limb]),
            );
        }
    }

    for output in 0..OUTPUTS {
        let note_call = output_note_call(output);
        let mut note_sources = vec![None; 18];
        note_sources[0] = Some(LinearExpression::witness(raw_index(output_value_row(
            output,
        ))));
        note_sources[1] = Some(LinearExpression::witness(raw_index(output_asset_row(
            output,
        ))));
        for limb in 0..4 {
            note_sources[14 + limb] = Some(LinearExpression::witness(raw_index(
                output_auth_key_row(output, limb),
            )));
        }
        csr.set_family("hash.output_note_initial");
        bind_sponge(csr, note_call, NOTE_DOMAIN_TAG, &note_sources);
        let flag = public[2 + output];
        csr.set_family("base.output_note_inactive_preimage");
        for index in 0..18 {
            let expression = absorbed_expression(note_call, index).scale(fsub(1, flag));
            csr.push(expression.terms, fsub(0, expression.constant));
        }
        csr.set_family("base.output_commitment_public");
        for limb in 0..DIGEST {
            csr.push(
                [(hash_final_index(note_call + 2, limb), flag)],
                fmul(flag, public[18 + output * DIGEST + limb]),
            );
        }
    }

    let projection = {
        let mut words = *public;
        words[4..18].fill(0);
        words[47..54].fill(0);
        words[87..94].fill(0);
        words[113..120].fill(0);
        words
    };
    let intent_sources = projection
        .into_iter()
        .map(|value| Some(LinearExpression::constant(value)))
        .collect::<Vec<_>>();
    csr.set_family("hash.action_intent_initial");
    bind_sponge(csr, 79, AUTH_INTENT_DOMAIN, &intent_sources);
    csr.set_family("auth.intent_digest_copy");
    for limb in 0..DIGEST {
        csr.equality(
            raw_index(auth_statement_row(limb)),
            hash_final_index(93, limb),
        );
    }

    let mut policy_sources = vec![
        Some(LinearExpression::witness(raw_index(auth_threshold_row()))),
        Some(LinearExpression::witness(
            raw_index(auth_signer_count_row()),
        )),
    ];
    for slot in 0..SIGNERS {
        for limb in 0..SIGNER_TAG_WORDS {
            policy_sources.push(Some(LinearExpression::witness(raw_index(
                auth_policy_tag_row(slot, limb),
            ))));
        }
    }
    csr.set_family("hash.authorization_policy_initial");
    bind_sponge(csr, 94, AUTH_POLICY_DOMAIN, &policy_sources);
    csr.set_family("auth.policy_inline_bindings");
    for limb in 0..DIGEST {
        csr.bind(
            packed_index(INLINE_POLICY_ROW_START, limb),
            LinearExpression::witness(raw_index(auth_policy_row(limb))),
        );
        csr.bind(
            packed_index(INLINE_POLICY_ROW_START + 1, limb),
            LinearExpression::witness(hash_final_index(97, limb)),
        );
        csr.bind(
            packed_index(INLINE_POLICY_ROW_START + 2, limb),
            LinearExpression::witness(raw_index(auth_mode_row(1)))
                .add(LinearExpression::witness(raw_index(auth_mode_row(2)))),
        );
    }
    csr.set_family("auth.policy_inline_padding");
    for row in INLINE_POLICY_ROW_START..INLINE_POLICY_ROW_START + 3 {
        for lane in DIGEST..64 {
            csr.zero(packed_index(row, lane));
        }
    }

    bind_accumulator_sponge(
        csr,
        98,
        AUTH_CURRENT,
        AUTH_ACCUMULATOR_DOMAIN,
        "hash.authorization_current_initial",
        "auth.current_digest_copy",
    );
    bind_accumulator_sponge(
        csr,
        101,
        AUTH_NEXT,
        AUTH_ACCUMULATOR_DOMAIN,
        "hash.authorization_next_initial",
        "auth.next_digest_copy",
    );
    let mut value_lock_sources = Vec::with_capacity(14);
    for limb in 0..DIGEST {
        value_lock_sources.push(Some(LinearExpression::witness(raw_index(auth_policy_row(
            limb,
        )))));
    }
    for limb in 0..DIGEST {
        value_lock_sources.push(Some(LinearExpression::witness(raw_index(auth_intent_row(
            limb,
        )))));
    }
    csr.set_family("hash.authorization_value_lock_initial");
    bind_sponge(csr, 104, AUTH_VALUE_LOCK_DOMAIN, &value_lock_sources);
    csr.set_family("auth.value_lock_digest_copy");
    for limb in 0..DIGEST {
        csr.equality(
            raw_index(auth_value_lock_row(limb)),
            hash_final_index(105, limb),
        );
    }

    csr.set_family("hash.padding_initial_zero");
    for local_index in smallwood_poseidon2_v8_hash_dummy_zero_witness_indices() {
        csr.zero(
            SMALLWOOD_POSEIDON2_V8_HASH_ROW_START * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
                + local_index,
        );
    }
}

fn bind_accumulator_sponge(
    csr: &mut CsrBuilder,
    call: usize,
    digest_offset: usize,
    domain: u64,
    initial_family: &'static str,
    digest_family: &'static str,
) {
    let mut sources = Vec::with_capacity(23);
    for limb in 0..DIGEST {
        sources.push(Some(LinearExpression::witness(raw_index(auth_policy_row(
            limb,
        )))));
    }
    for limb in 0..DIGEST {
        sources.push(Some(LinearExpression::witness(raw_index(auth_intent_row(
            limb,
        )))));
    }
    let (count_row, approved_row): (usize, fn(usize) -> usize) = if digest_offset == AUTH_CURRENT {
        (auth_count_row(), auth_approved_row)
    } else {
        (auth_next_count_row(), auth_next_approved_row)
    };
    sources.push(Some(LinearExpression::witness(raw_index(
        auth_threshold_row(),
    ))));
    sources.push(Some(LinearExpression::witness(raw_index(
        auth_signer_count_row(),
    ))));
    sources.push(Some(LinearExpression::witness(raw_index(count_row))));
    for slot in 0..SIGNERS {
        sources.push(Some(LinearExpression::witness(raw_index(approved_row(
            slot,
        )))));
    }
    csr.set_family(initial_family);
    bind_sponge(csr, call, domain, &sources);
    csr.set_family(digest_family);
    for limb in 0..DIGEST {
        csr.equality(
            raw_index(auth_row(digest_offset + limb)),
            hash_final_index(call + 2, limb),
        );
    }
}

#[inline]
const fn stable_index(local_row: usize, lane: usize) -> usize {
    packed_index(SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + local_row, lane)
}
#[inline]
const fn stable_source(slot: usize) -> usize {
    stable_index(slot / 64, slot % 64)
}
#[inline]
const fn stable_role_diff(limb: usize, condition: usize) -> usize {
    stable_index(2 + limb, condition)
}
#[inline]
const fn stable_role_selector(condition: usize) -> usize {
    stable_index(9, condition)
}
#[inline]
const fn stable_role_inverse(condition: usize) -> usize {
    stable_index(10, condition)
}
#[inline]
const fn stable_bool(lane: usize) -> usize {
    stable_index(11, lane)
}
#[inline]
const fn stable_numeric(lane: usize) -> usize {
    stable_index(12, lane)
}
#[inline]
const fn stable_mul_a(lane: usize) -> usize {
    stable_index(13, lane)
}
#[inline]
const fn stable_mul_b(lane: usize) -> usize {
    stable_index(14, lane)
}
#[inline]
const fn stable_mul_c(lane: usize) -> usize {
    stable_index(15, lane)
}
#[inline]
const fn stable_range(slot: usize) -> usize {
    stable_index(16 + slot / 64, slot % 64)
}

fn push_stable_nonlinear_constraints(rows: &[u64], out: &mut Vec<u64>) {
    let selector = rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 9];
    out.push(field_product(
        (0..DIGEST).map(|choice| fsub(selector, choice as u64)),
    ));

    let inverse = rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 10];
    let mut selected = 0;
    for choice in 0..DIGEST {
        let mut basis = 1;
        let mut denominator = 1;
        for other in 0..DIGEST {
            if other == choice {
                continue;
            }
            basis = fmul(basis, fsub(selector, other as u64));
            denominator = fmul(denominator, fsub(choice as u64, other as u64));
        }
        selected = fadd(
            selected,
            fmul(
                rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 2 + choice],
                fmul(basis, finv(denominator)),
            ),
        );
    }
    out.push(fsub(fmul(inverse, selected), 1));
    out.push(fbool(rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 11]));
    out.push(fsub(
        fmul(
            rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 13],
            rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 14],
        ),
        rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 15],
    ));
    for row in 0..23 {
        let value = rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + 16 + row];
        out.push(field_product([
            value,
            fsub(value, 1),
            fsub(value, 2),
            fsub(value, 3),
        ]));
    }
}

/// Build all 830 nonlinear identities from the same constructors consumed by the verifier.
/// The u64 base/auth/stable constructors enter symbolic mode through the field helpers above;
/// the Poseidon2 kernel already exposes its source-owned generic ring evaluator.
pub(crate) fn smallwood_poseidon2_v8_nonlinear_expression_program(
) -> SmallwoodPoseidon2V8ExpressionProgram {
    begin_smallwood_poseidon2_v8_expression_program();
    let public = core::array::from_fn(smallwood_poseidon2_v8_symbolic_public_handle);
    let rows = (0..SMALLWOOD_POSEIDON2_V8_ROW_COUNT)
        .map(smallwood_poseidon2_v8_symbolic_witness_row_handle)
        .collect::<Vec<_>>();
    let mut roots = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT);
    push_base_constraints(&public, &rows, &mut roots);

    let symbolic_hash_rows = rows
        [SMALLWOOD_POSEIDON2_V8_HASH_ROW_START..SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START]
        .iter()
        .copied()
        .map(SmallwoodPoseidon2V8SymbolicValue::from_internal_handle)
        .collect::<Vec<_>>();
    let mut symbolic_hash_roots =
        vec![SmallwoodPoseidon2V8SymbolicValue::ZERO; SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT];
    evaluate_smallwood_poseidon2_v8_hash_constraints_ring(
        &symbolic_hash_rows,
        &mut symbolic_hash_roots,
    )
    .expect("fixed V8 symbolic hash geometry is valid");
    roots.extend(
        symbolic_hash_roots
            .into_iter()
            .map(SmallwoodPoseidon2V8SymbolicValue::into_internal_handle),
    );
    push_stable_nonlinear_constraints(&rows, &mut roots);
    debug_assert_eq!(
        roots.len(),
        SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT
    );
    finish_smallwood_poseidon2_v8_expression_program(roots)
}

fn executable_nonlinear_program() -> &'static SmallwoodPoseidon2V8ExpressionProgram {
    static PROGRAM: std::sync::OnceLock<SmallwoodPoseidon2V8ExpressionProgram> =
        std::sync::OnceLock::new();
    PROGRAM.get_or_init(smallwood_poseidon2_v8_nonlinear_expression_program)
}

fn evaluate_all_constraints(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    rows: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    if rows.len() != SMALLWOOD_POSEIDON2_V8_ROW_COUNT {
        return Err(TransactionCircuitError::ConstraintViolation(
            "Poseidon2 V8 SmallWood nonlinear row view has the wrong length",
        ));
    }
    evaluate_smallwood_poseidon2_v8_expression_program(executable_nonlinear_program(), public, rows)
        .map_err(TransactionCircuitError::ConstraintViolation)
}

#[derive(Clone, Debug)]
struct StableRangeBinding {
    source: LinearExpression,
    bits: usize,
    start: usize,
    top_boolean_lane: Option<usize>,
}

fn stable_range_reconstruction(binding: &StableRangeBinding) -> LinearExpression {
    let low_digits = binding.bits / 2;
    let mut out = LinearExpression::default();
    let mut power = 1u64;
    for digit in 0..low_digits {
        out.terms.push((stable_range(binding.start + digit), power));
        power = fmul(power, 4);
    }
    if let Some(lane) = binding.top_boolean_lane {
        out.terms
            .push((stable_bool(lane), 1u64 << (binding.bits - 1)));
    }
    out
}

fn stable_range_halves(binding: &StableRangeBinding) -> (LinearExpression, LinearExpression) {
    debug_assert!(binding.bits > 32);
    let low_digits = binding.bits / 2;
    let mut low = LinearExpression::default();
    let mut high = LinearExpression::default();
    let mut power = 1u64;
    for digit in 0..low_digits {
        if digit < 16 {
            low.terms.push((stable_range(binding.start + digit), power));
            power = fmul(power, 4);
        } else {
            let high_power = 1u64 << (2 * (digit - 16));
            high.terms
                .push((stable_range(binding.start + digit), high_power));
        }
    }
    if let Some(lane) = binding.top_boolean_lane {
        high.terms
            .push((stable_bool(lane), 1u64 << (binding.bits - 33)));
    }
    (low, high)
}

fn bind_stable_mul_lane(
    csr: &mut CsrBuilder,
    lane: usize,
    left: LinearExpression,
    right: LinearExpression,
    output: LinearExpression,
) {
    csr.bind(stable_mul_a(lane), left);
    csr.bind(stable_mul_b(lane), right);
    csr.bind(stable_mul_c(lane), output);
}

fn build_stable_arithmetic_constraints(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    csr: &mut CsrBuilder,
    mint: u64,
    burn: u64,
    enabled: u64,
) {
    let s = |slot| LinearExpression::witness(stable_source(slot));
    let n = |lane| LinearExpression::witness(stable_numeric(lane));
    let b = |lane| LinearExpression::witness(stable_bool(lane));
    let p = |index| LinearExpression::constant(public[index]);

    // Every scalar is reconstructed injectively from base-four digits and, for odd widths, one
    // explicit top bit.  The ordering is consensus-owned and shared with the materializer.
    let mut ranges = Vec::<StableRangeBinding>::with_capacity(66);
    let mut add_range = |source, bits, start, top_boolean_lane| {
        ranges.push(StableRangeBinding {
            source,
            bits,
            start,
            top_boolean_lane,
        });
    };
    for (source, start) in [
        (s(0), 0usize),
        (s(1), 16),
        (s(13), 32),
        (s(17), 48),
        (s(18), 64),
        (s(45), 80),
        (n(8), 96),
    ] {
        add_range(source, 32, start, None);
    }
    for (source, start, top) in [
        (s(3), 112usize, 33usize),
        (s(5), 143, 34),
        (s(15), 174, 35),
        (s(16), 205, 36),
        (s(20), 236, 37),
        (s(23), 267, 38),
        (s(47), 298, 39),
        (p(94), 329, 40),
        (s(93), 360, 41),
        (p(112), 391, 42),
        (n(1), 422, 43),
        (n(2), 453, 44),
        (n(3), 484, 45),
        (n(4), 515, 46),
        (n(5), 546, 47),
        (n(6), 577, 48),
        (n(7), 608, 49),
    ] {
        add_range(source, 63, start, Some(top));
    }
    for (source, start, top) in [
        (s(90), 639usize, 50usize),
        (p(109), 664, 51),
        (n(11), 689, 52),
    ] {
        add_range(source, 51, start, Some(top));
    }
    for (source, start) in [
        (s(14), 714usize),
        (s(19), 742),
        (p(86), 770),
        (s(91), 798),
        (s(92), 826),
        (p(110), 854),
        (p(111), 882),
        (n(9), 910),
        (n(10), 938),
    ] {
        add_range(source, 56, start, None);
    }
    add_range(n(12), 12, 966, None);
    add_range(n(0), 28, 972, None);
    for lane in 18..46 {
        add_range(n(lane), 32, 986 + 16 * (lane - 18), None);
    }
    debug_assert_eq!(ranges.len(), 66);
    csr.set_family("stable.range_reconstruct");
    for binding in &ranges {
        csr.expression_zero(
            binding
                .source
                .clone()
                .sub(stable_range_reconstruction(binding)),
        );
    }
    csr.set_family("stable.range_padding");
    for slot in 1_434..1_472 {
        csr.zero(stable_range(slot));
    }
    // Six high carry/output limbs are only 24 bits.  This eliminates the sole Goldilocks-wrap
    // aliases left by the 32-bit limb multiplication equations.
    csr.set_family("stable.high_limb_digit_padding");
    for start in [1_002usize, 1_050, 1_130, 1_194, 1_242, 1_322] {
        for digit in 12..16 {
            csr.zero(stable_range(start + digit));
        }
    }

    // Asset-index decomposition, decimal-scale construction, epoch/counter transition and caps.
    let mut asset = n(0).scale(16);
    for bit in 0..4 {
        asset = asset.add(b(7 + bit).scale(1u64 << bit));
    }
    csr.set_family("stable.asset_index_reconstruct");
    csr.expression_zero(p(84).sub(asset));
    let mut decimals = LinearExpression::default();
    let mut decimal_slack = LinearExpression::default();
    for bit in 0..5 {
        decimals = decimals.add(b(12 + bit).scale(1u64 << bit));
        decimal_slack = decimal_slack.add(b(17 + bit).scale(1u64 << bit));
    }
    csr.set_family("stable.decimals_reconstruct");
    csr.expression_zero(s(46).sub(decimals));
    csr.set_family("stable.decimal_slack");
    csr.expression_zero(
        s(46)
            .add(decimal_slack)
            .sub(LinearExpression::constant(fmul(18, enabled))),
    );
    csr.set_family("stable.decimal_scale");
    csr.expression_zero(s(47).sub(n(17)).scale(enabled));

    csr.set_family("stable.epoch_counter_caps");
    csr.expression_zero(s(90).add(n(11)).sub(p(109)));
    // Parent height is always statement- and range-bound.  Only an enabled
    // stablecoin transition interprets it as the epoch/counter clock.  Gating
    // this equation prevents Disabled mode from forcing the consensus height
    // to zero while keeping every inactive state/counter field canonical.
    csr.expression_zero(
        p(94)
            .sub(p(109).scale(1u64 << 12))
            .sub(n(12))
            .scale(enabled),
    );
    csr.expression_zero(s(91).add(n(9)).sub(s(14)));
    csr.expression_zero(p(110).add(n(10)).sub(s(14)));
    csr.expression_zero(
        p(110)
            .sub(LinearExpression::witness(stable_mul_c(16)))
            .sub(p(86).scale(mint)),
    );
    csr.expression_zero(p(111).sub(s(92)).sub(p(86).scale(fsub(mint, burn))));
    csr.expression_zero(p(112).sub(s(93)).sub(LinearExpression::constant(enabled)));

    csr.set_family("stable.mint_config_canonical");
    csr.expression_zero(s(2).sub(LinearExpression::constant(1)).scale(mint));
    csr.expression_zero(s(21).scale(mint));
    csr.expression_zero(s(22).sub(LinearExpression::constant(1)).scale(mint));
    csr.expression_zero(
        s(13)
            .sub(LinearExpression::constant(1_000_000))
            .sub(n(8))
            .scale(mint),
    );
    csr.set_family("stable.nonmint_numeric_zero");
    for lane in 1..=8 {
        csr.expression_zero(n(lane).scale(fsub(1, mint)));
    }
    csr.set_family("stable.nonmint_collateral_zero");
    for lane in 18..=45 {
        csr.expression_zero(n(lane).scale(fsub(1, mint)));
    }
    csr.set_family("stable.nonmint_borrow_zero");
    for lane in 22..=25 {
        csr.push([(stable_bool(lane), fsub(1, mint))], 0);
    }
    csr.set_family("stable.final_borrow_zero");
    csr.zero(stable_bool(25));

    // Decimal powers: accumulator[i] = accumulator[i-1] * (1 + (power-1)*bit).
    let powers = [10u64, 100, 10_000, 100_000_000, 10_000_000_000_000_000];
    csr.set_family("stable.decimal_power_mul_bindings");
    for (lane, power) in powers.into_iter().enumerate() {
        let left = if lane == 0 {
            LinearExpression::constant(1)
        } else {
            n(12 + lane)
        };
        let right = LinearExpression::constant(1).add(b(12 + lane).scale(power - 1));
        bind_stable_mul_lane(csr, lane, left, right, n(13 + lane));
    }

    // Epoch zero-test and same-epoch mint-base mux.
    csr.set_family("stable.epoch_zero_mux_bindings");
    csr.bind(stable_mul_a(15), n(11));
    csr.bind(stable_mul_c(15), LinearExpression::constant(1).sub(b(11)));
    csr.bind(stable_mul_a(16), b(11));
    csr.bind(stable_mul_b(16), s(91));
    csr.bind(stable_mul_a(17), b(11));
    csr.bind(stable_mul_b(17), n(11));
    csr.zero(stable_mul_c(17));

    // Exact low-32/high-31 additions prevent Goldilocks modular wrap from satisfying lifecycle
    // inequalities.  Retirement equations are privately gated by retired_present.
    let time_specs = [
        StableRangeBinding {
            source: s(3),
            bits: 63,
            start: 112,
            top_boolean_lane: Some(33),
        },
        StableRangeBinding {
            source: s(5),
            bits: 63,
            start: 143,
            top_boolean_lane: Some(34),
        },
        StableRangeBinding {
            source: s(15),
            bits: 63,
            start: 174,
            top_boolean_lane: Some(35),
        },
        StableRangeBinding {
            source: s(16),
            bits: 63,
            start: 205,
            top_boolean_lane: Some(36),
        },
        StableRangeBinding {
            source: s(20),
            bits: 63,
            start: 236,
            top_boolean_lane: Some(37),
        },
        StableRangeBinding {
            source: s(23),
            bits: 63,
            start: 267,
            top_boolean_lane: Some(38),
        },
        StableRangeBinding {
            source: p(94),
            bits: 63,
            start: 329,
            top_boolean_lane: Some(40),
        },
        StableRangeBinding {
            source: n(1),
            bits: 63,
            start: 422,
            top_boolean_lane: Some(43),
        },
        StableRangeBinding {
            source: n(2),
            bits: 63,
            start: 453,
            top_boolean_lane: Some(44),
        },
        StableRangeBinding {
            source: n(3),
            bits: 63,
            start: 484,
            top_boolean_lane: Some(45),
        },
        StableRangeBinding {
            source: n(4),
            bits: 63,
            start: 515,
            top_boolean_lane: Some(46),
        },
        StableRangeBinding {
            source: n(5),
            bits: 63,
            start: 546,
            top_boolean_lane: Some(47),
        },
        StableRangeBinding {
            source: n(6),
            bits: 63,
            start: 577,
            top_boolean_lane: Some(48),
        },
        StableRangeBinding {
            source: n(7),
            bits: 63,
            start: 608,
            top_boolean_lane: Some(49),
        },
    ];
    let halves = |index: usize| stable_range_halves(&time_specs[index]);
    let addition_residual = |x: usize, y: usize, z: usize, carry: usize, plus_one: u64| {
        let (x_lo, x_hi) = halves(x);
        let (y_lo, y_hi) = halves(y);
        let (z_lo, z_hi) = halves(z);
        let low = x_lo
            .add(y_lo)
            .add(LinearExpression::constant(plus_one))
            .sub(z_lo)
            .sub(b(carry).scale(1u64 << 32));
        let high = x_hi.add(y_hi).add(b(carry)).sub(z_hi);
        (low, high)
    };
    // enabled_at + enabled_age = parent; oracle/attestation age and freshness equations.
    csr.set_family("stable.time_additions");
    for (x, y, z, carry) in [
        (0usize, 7usize, 6usize, 26usize),
        (2, 10, 6, 29),
        (10, 11, 3, 30),
        (4, 12, 6, 31),
        (12, 13, 5, 32),
    ] {
        let (low, high) = addition_residual(x, y, z, carry, 0);
        csr.expression_zero(low.scale(mint));
        csr.expression_zero(high.scale(mint));
        csr.push([(stable_bool(carry), fsub(1, mint))], 0);
    }
    let retirement_gate = s(4).scale(mint);
    csr.set_family("stable.retirement_gate_bindings");
    for lane in 25..=28 {
        csr.bind(stable_mul_a(lane), retirement_gate.clone());
        csr.zero(stable_mul_c(lane));
    }
    let (retired_order_low, retired_order_high) = addition_residual(0, 8, 1, 27, 1);
    let (retired_height_low, retired_height_high) = addition_residual(6, 9, 1, 28, 1);
    for (lane, residual) in [
        (25usize, retired_order_low),
        (26, retired_order_high),
        (27, retired_height_low),
        (28, retired_height_high),
    ] {
        csr.set_family("stable.retirement_residual_bindings");
        csr.bind(stable_mul_b(lane), residual);
    }
    csr.set_family("stable.retired_present_gate");
    bind_stable_mul_lane(
        csr,
        24,
        LinearExpression::constant(1).sub(s(4)),
        s(5),
        LinearExpression::constant(0),
    );
    let no_retirement_gate =
        LinearExpression::constant(1).sub(LinearExpression::witness(stable_mul_a(25)));
    csr.set_family("stable.retirement_canonical_helpers");
    for (lane, helper) in [(29usize, n(2)), (30, n(3)), (31, b(27)), (32, b(28))] {
        bind_stable_mul_lane(
            csr,
            lane,
            no_retirement_gate.clone(),
            helper,
            LinearExpression::constant(0),
        );
    }

    // Two three-limb products and a four-limb subtraction prove collateral value >= debt ratio.
    csr.set_family("stable.collateral_limb_reconstruct");
    csr.expression_zero(s(19).sub(n(18)).sub(n(19).scale(1u64 << 32)).scale(mint));
    csr.expression_zero(p(111).sub(n(30)).sub(n(31).scale(1u64 << 32)).scale(mint));
    let bind_product = |csr: &mut CsrBuilder,
                        lane: usize,
                        base: usize,
                        multiplier: LinearExpression,
                        scale: LinearExpression| {
        bind_stable_mul_lane(
            csr,
            lane,
            n(base),
            multiplier.clone(),
            n(base + 2).add(n(base + 5).scale(1u64 << 32)),
        );
        bind_stable_mul_lane(
            csr,
            lane + 1,
            n(base + 1),
            multiplier,
            n(base + 3)
                .add(n(base + 4).scale(1u64 << 32))
                .sub(n(base + 5)),
        );
        bind_stable_mul_lane(
            csr,
            lane + 2,
            n(base + 2),
            scale.clone(),
            n(base + 6).add(n(base + 10).scale(1u64 << 32)),
        );
        bind_stable_mul_lane(
            csr,
            lane + 3,
            n(base + 3),
            scale.clone(),
            n(base + 7)
                .add(n(base + 11).scale(1u64 << 32))
                .sub(n(base + 10)),
        );
        bind_stable_mul_lane(
            csr,
            lane + 4,
            n(base + 4),
            scale,
            n(base + 8)
                .add(n(base + 9).scale(1u64 << 32))
                .sub(n(base + 11)),
        );
    };
    csr.set_family("stable.collateral_product_bindings");
    bind_product(csr, 5, 18, s(17), LinearExpression::constant(1_000_000));
    bind_product(csr, 10, 30, s(18), s(13));
    csr.set_family("stable.collateral_subtraction");
    for limb in 0..4 {
        let previous_borrow = if limb == 0 {
            LinearExpression::constant(0)
        } else {
            b(21 + limb)
        };
        let residual = n(24 + limb)
            .sub(n(36 + limb))
            .sub(previous_borrow)
            .add(b(22 + limb).scale(1u64 << 32))
            .sub(n(42 + limb));
        csr.expression_zero(residual.scale(mint));
    }

    // Each multiplication carry must be strictly below 2^32-1 while minting.  The inverse lanes
    // rule out the field-modulus alias without adding another row.
    csr.set_family("stable.max_carry_inverse");
    for (offset, carry_lane) in [23usize, 28, 29, 35, 40, 41].into_iter().enumerate() {
        csr.bind(
            stable_mul_a(18 + offset),
            LinearExpression::constant((1u64 << 32) - 1).sub(n(carry_lane)),
        );
        csr.push([(stable_mul_b(18 + offset), fsub(1, mint))], 0);
        csr.push([(stable_mul_c(18 + offset), 1)], mint);
    }

    csr.set_family("stable.mul_padding");
    for lane in 33..64 {
        csr.zero(stable_mul_a(lane));
        csr.zero(stable_mul_b(lane));
        csr.zero(stable_mul_c(lane));
    }
    csr.set_family("stable.numeric_padding");
    for lane in 46..64 {
        csr.zero(stable_numeric(lane));
    }
}

fn build_stable_linear_constraints(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    csr: &mut CsrBuilder,
) {
    let direction = public[83];
    let mint = fselect_equal(direction, 1, 1, 0);
    let burn = fselect_equal(direction, 2, 1, 0);
    let enabled = fadd(mint, burn);

    // Complete private source, reserved compatibility words, and global-spend-key padding.
    csr.set_family("stable.disabled_private_source");
    for slot in 0..94 {
        csr.push([(stable_source(slot), fsub(1, enabled))], 0);
    }
    for slot in 94..112 {
        csr.set_family("stable.compatibility_source_copy");
        csr.push([(stable_source(slot), 1)], public[63 + slot - 94]);
        csr.set_family("stable.compatibility_source_zero");
        csr.zero(stable_source(slot));
    }
    csr.set_family("stable.source_padding");
    for slot in 120..128 {
        csr.zero(stable_source(slot));
    }
    csr.set_family("stable.issuer_secret_nonmint_zero");
    for slot in 83..90 {
        csr.push([(stable_source(slot), fsub(1, mint))], 0);
    }
    // Burn authorization is canonically absent.  Keep this as an executable public equation as
    // well as a typed-statement admission rule; source slot 120 is independently fixed to zero.
    csr.set_family("stable.burn_authorization_zero");
    for limb in 0..DIGEST {
        csr.push([(stable_source(120), 1)], fmul(burn, public[113 + limb]));
    }

    // Public/private scalar bridge and Boolean/helper sources.
    csr.set_family("stable.public_scalar_bridge");
    csr.push([(stable_source(0), 1)], public[84]);
    csr.push([(stable_source(1), 1)], public[85]);
    csr.set_family("stable.direction_flags");
    for (lane, value) in [(0, enabled), (1, mint), (2, burn)] {
        csr.push([(stable_bool(lane), 1)], value);
    }
    csr.set_family("stable.boolean_source_copy");
    for (lane, source) in [(3, 2), (4, 4), (5, 21), (6, 22)] {
        csr.equality(stable_bool(lane), stable_source(source));
    }
    csr.set_family("stable.asset_index_bits");
    for bit in 0..4 {
        csr.push([(stable_bool(7 + bit), 1)], fbit(public[84], bit));
    }
    csr.set_family("stable.boolean_padding");
    for lane in 53..64 {
        csr.zero(stable_bool(lane));
    }

    // All 21 nonzero/role-separation checks use the same seven-row selector gadget.
    let commitments = [6usize, 24, 31, 38, 48];
    let unit = |limb: usize| if limb == 0 { 1 } else { 0 };
    csr.set_family("stable.role_live_diff");
    for condition in 0..STABLE_ROLE_CONDITIONS {
        for limb in 0..DIGEST {
            let expression = if condition < 5 {
                LinearExpression::witness(stable_source(commitments[condition] + limb))
                    .scale(enabled)
                    .add(LinearExpression::constant(fmul(
                        fsub(1, enabled),
                        unit(limb),
                    )))
            } else if condition < 15 {
                let mut pair = 0;
                let mut selected = (0, 1);
                'pairs: for left in 0..5 {
                    for right in left + 1..5 {
                        if pair == condition - 5 {
                            selected = (left, right);
                            break 'pairs;
                        }
                        pair += 1;
                    }
                }
                LinearExpression::witness(stable_source(commitments[selected.0] + limb))
                    .sub(LinearExpression::witness(stable_source(
                        commitments[selected.1] + limb,
                    )))
                    .scale(enabled)
                    .add(LinearExpression::constant(fmul(
                        fsub(1, enabled),
                        unit(limb),
                    )))
            } else if condition == 15 {
                LinearExpression::witness(stable_source(83 + limb))
                    .scale(mint)
                    .add(LinearExpression::constant(fmul(fsub(1, mint), unit(limb))))
            } else if condition == 16 {
                LinearExpression::constant(fadd(
                    fmul(enabled, if limb == 0 { public[86] } else { 0 }),
                    fmul(fsub(1, enabled), unit(limb)),
                ))
            } else if condition == 17 || condition == 18 {
                let source = if condition == 17 { 17 } else { 18 };
                LinearExpression::witness(stable_source(source))
                    .scale(fmul(mint, u64::from(limb == 0)))
                    .add(LinearExpression::constant(fmul(fsub(1, mint), unit(limb))))
            } else if condition == 19 {
                LinearExpression::witness(stable_source(0))
                    .scale(fmul(enabled, u64::from(limb == 0)))
                    .add(LinearExpression::constant(fmul(
                        fsub(1, enabled),
                        unit(limb),
                    )))
            } else {
                LinearExpression::constant(fadd(
                    fmul(enabled, public[87 + limb]),
                    fmul(fsub(1, enabled), unit(limb)),
                ))
            };
            csr.bind(stable_role_diff(limb, condition), expression);
        }
    }

    // Reuse nine otherwise spare lanes of the seven-limb nonzero selector gadget to make the
    // verifier relation match typed witness admission exactly.  The expressions add the unit
    // digest on inactive arms, so every lane remains satisfiable without weakening the active
    // nonzero requirement.
    let any_input = fsub(fadd(public[0], public[1]), fmul(public[0], public[1]));
    let chosen_spend_key = |limb: usize| {
        LinearExpression::witness(stable_source(112 + limb))
            .scale(public[0])
            .add(
                LinearExpression::witness(stable_source(116 + limb))
                    .scale(fmul(fsub(1, public[0]), public[1])),
            )
    };
    csr.set_family("stable.role_live_diff");
    for limb in 0..DIGEST {
        let expression = if limb < 4 {
            chosen_spend_key(limb).scale(any_input)
        } else {
            LinearExpression::constant(0)
        }
        .add(LinearExpression::constant(fmul(
            fsub(1, any_input),
            unit(limb),
        )));
        csr.bind(stable_role_diff(limb, STABLE_ROLE_CONDITIONS), expression);
    }

    let non_single = LinearExpression::witness(raw_index(auth_mode_row(1)))
        .add(LinearExpression::witness(raw_index(auth_mode_row(2))));
    csr.set_family("stable.role_live_diff");
    for (offset, row_fn) in [
        auth_policy_row as fn(usize) -> usize,
        auth_intent_row as fn(usize) -> usize,
    ]
    .into_iter()
    .enumerate()
    {
        let condition = STABLE_ROLE_CONDITIONS + 1 + offset;
        for limb in 0..DIGEST {
            let expression = LinearExpression::witness(raw_index(row_fn(limb)))
                .add(LinearExpression::constant(unit(limb)))
                .sub(non_single.clone().scale(unit(limb)));
            csr.bind(stable_role_diff(limb, condition), expression);
        }
    }

    csr.set_family("stable.role_live_diff");
    for slot in 0..SIGNERS {
        let condition = STABLE_ROLE_CONDITIONS + 3 + slot;
        let mut active = LinearExpression::default();
        for flag in slot..SIGNERS {
            active = active.add(LinearExpression::witness(raw_index(auth_signer_flag_row(
                flag,
            ))));
        }
        for limb in 0..DIGEST {
            let tag = if limb < SIGNER_TAG_WORDS {
                LinearExpression::witness(raw_index(auth_policy_tag_row(slot, limb)))
            } else {
                LinearExpression::constant(0)
            };
            let expression = tag
                .add(LinearExpression::constant(unit(limb)))
                .sub(active.clone().scale(unit(limb)));
            csr.bind(stable_role_diff(limb, condition), expression);
        }
    }

    for condition in TOTAL_ROLE_CONDITIONS..64 {
        csr.set_family("stable.role_padding_unit");
        csr.push([(stable_role_diff(0, condition), 1)], 1);
        csr.set_family("stable.role_padding_limbs");
        for limb in 1..DIGEST {
            csr.zero(stable_role_diff(limb, condition));
        }
        csr.set_family("stable.role_padding_selector");
        csr.zero(stable_role_selector(condition));
        csr.set_family("stable.role_padding_inverse");
        csr.push([(stable_role_inverse(condition), 1)], 1);
    }

    // Canonical stable compression calls: four config chunks, three config tree nodes, two
    // state leaves, two interleaved four-level paths, and two issuer relations.
    let chunk_domains = [
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_0,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_1,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_2,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_CHUNK_3,
    ];
    csr.set_family("hash.stable_config_chunk_initial");
    for chunk in 0..4 {
        let left = core::array::from_fn(|limb| {
            let field = chunk * 14 + limb;
            if field < 55 {
                LinearExpression::witness(stable_source(field))
            } else {
                LinearExpression::constant(0)
            }
        });
        let right = core::array::from_fn(|limb| {
            let field = chunk * 14 + 7 + limb;
            if field < 55 {
                LinearExpression::witness(stable_source(field))
            } else {
                LinearExpression::constant(0)
            }
        });
        bind_compress14(csr, 106 + chunk, chunk_domains[chunk], left, right);
    }
    csr.set_family("hash.stable_config_tree_initial");
    bind_compress14(
        csr,
        110,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_0,
        core::array::from_fn(|limb| LinearExpression::witness(hash_final_index(106, limb))),
        core::array::from_fn(|limb| LinearExpression::witness(hash_final_index(107, limb))),
    );
    bind_compress14(
        csr,
        111,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_NODE_1,
        core::array::from_fn(|limb| LinearExpression::witness(hash_final_index(108, limb))),
        core::array::from_fn(|limb| LinearExpression::witness(hash_final_index(109, limb))),
    );
    bind_compress14(
        csr,
        112,
        STABLECOIN_POSEIDON2_V8_DOMAIN_CONFIG_ROOT,
        core::array::from_fn(|limb| LinearExpression::witness(hash_final_index(110, limb))),
        core::array::from_fn(|limb| LinearExpression::witness(hash_final_index(111, limb))),
    );
    let index = (0..4).fold(0, |value, bit| {
        fadd(value, fmul(fbit(public[84], bit), 1u64 << bit))
    });
    let before_right = core::array::from_fn(|limb| match limb {
        0..=3 => LinearExpression::witness(stable_source(90 + limb)),
        4 => LinearExpression::constant(index),
        _ => LinearExpression::constant(0),
    });
    let after_right = core::array::from_fn(|limb| match limb {
        0..=3 => LinearExpression::constant(public[109 + limb]),
        4 => LinearExpression::constant(index),
        _ => LinearExpression::constant(0),
    });
    let config_digest =
        core::array::from_fn(|limb| LinearExpression::witness(hash_final_index(112, limb)));
    csr.set_family("hash.stable_state_leaf_initial");
    bind_compress14(
        csr,
        113,
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF,
        config_digest.clone(),
        before_right,
    );
    bind_compress14(
        csr,
        114,
        STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_LEAF,
        config_digest,
        after_right,
    );
    csr.set_family("hash.stable_path_initial");
    for level in 0..STABLECOIN_POSEIDON2_V8_DEPTH {
        let bit = fbit(public[84], level);
        for (path, leaf_call) in [(0usize, 113usize), (1, 114)] {
            let call = 115 + level * 2 + path;
            let previous = if level == 0 { leaf_call } else { call - 2 };
            let left = core::array::from_fn(|limb| {
                LinearExpression::witness(hash_final_index(previous, limb))
                    .scale(fsub(1, bit))
                    .add(LinearExpression::witness(stable_source(55 + level * 7 + limb)).scale(bit))
            });
            let right = core::array::from_fn(|limb| {
                LinearExpression::witness(stable_source(55 + level * 7 + limb))
                    .scale(fsub(1, bit))
                    .add(LinearExpression::witness(hash_final_index(previous, limb)).scale(bit))
            });
            bind_compress14(
                csr,
                call,
                STABLECOIN_POSEIDON2_V8_DOMAIN_STATE_NODE_0 + level as u64,
                left,
                right,
            );
        }
    }
    csr.set_family("stable.public_roots");
    for limb in 0..DIGEST {
        // Enabled transitions authenticate the before root through the state
        // path.  Disabled transitions carry no state witness, but this same
        // attempted identity becomes the public-only pass-through equation
        // before_root == after_root.  A nonzero public-only residual is routed
        // through the canonical zero source cell by CsrBuilder and is therefore
        // unsatisfiable.
        let disabled_passthrough = fmul(
            fsub(1, enabled),
            fsub(public[95 + limb], public[102 + limb]),
        );
        csr.push(
            [(hash_final_index(121, limb), enabled)],
            fadd(fmul(enabled, public[95 + limb]), disabled_passthrough),
        );
        csr.push(
            [(hash_final_index(122, limb), enabled)],
            fmul(enabled, public[102 + limb]),
        );
    }
    csr.set_family("hash.stable_issuer_initial");
    bind_compress14(
        csr,
        123,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_COMMITMENT,
        core::array::from_fn(|limb| LinearExpression::witness(stable_source(83 + limb))),
        core::array::from_fn(|limb| match limb {
            0 => LinearExpression::constant(public[84]),
            1 => LinearExpression::constant(public[85]),
            _ => LinearExpression::constant(0),
        }),
    );
    bind_compress14(
        csr,
        124,
        STABLECOIN_POSEIDON2_V8_DOMAIN_ISSUER_AUTHORIZATION,
        core::array::from_fn(|limb| LinearExpression::witness(stable_source(83 + limb))),
        core::array::from_fn(|limb| LinearExpression::constant(public[87 + limb])),
    );
    for limb in 0..DIGEST {
        csr.set_family("stable.issuer_commitment");
        csr.push(
            [
                (hash_final_index(123, limb), mint),
                (stable_source(6 + limb), fsub(0, mint)),
            ],
            0,
        );
        csr.set_family("stable.issuer_authorization");
        csr.push(
            [(hash_final_index(124, limb), mint)],
            fmul(mint, public[113 + limb]),
        );
    }

    build_stable_arithmetic_constraints(public, csr, mint, burn, enabled);
}

/// Generate every attempted CSR identity from the executable compiler itself.  Public words are
/// symbolic nodes, so activity specialization and zero-row deletion remain explicit in the
/// program rather than being frozen to one transaction statement.
pub(crate) fn smallwood_poseidon2_v8_csr_expression_program(
) -> SmallwoodPoseidon2V8CsrExpressionProgram {
    begin_smallwood_poseidon2_v8_expression_program();
    let public = core::array::from_fn(smallwood_poseidon2_v8_symbolic_public_handle);
    let mut csr = CsrBuilder::new();
    build_base_linear_constraints(&public, &mut csr);
    build_stable_linear_constraints(&public, &mut csr);
    csr.finish_symbolic()
}

fn executable_csr_program() -> &'static SmallwoodPoseidon2V8CsrExpressionProgram {
    static PROGRAM: std::sync::OnceLock<SmallwoodPoseidon2V8CsrExpressionProgram> =
        std::sync::OnceLock::new();
    PROGRAM.get_or_init(smallwood_poseidon2_v8_csr_expression_program)
}

/// Specialize the canonical statement-independent CSR expression program and apply the one
/// normalized-row rule used by the executable adapter. Every attempted identity is retained in
/// the program even when specialization drops an empty zero row.
fn specialize_executable_csr_program(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
) -> Result<FinalizedCsr, SmallwoodPoseidon2V8RelationError> {
    let program = executable_csr_program();
    let values =
        evaluate_smallwood_poseidon2_v8_expression_nodes(&program.expressions, public, &[])
            .map_err(
                |detail| SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
                    detail: detail.to_owned(),
                },
            )?;
    let mut cursor = SmallwoodPoseidon2V8CsrProgramCursor::new();
    let mut offsets = vec![0];
    let mut indices = Vec::new();
    let mut coefficients = Vec::new();
    let mut targets = Vec::new();
    let mut constraint_family_ids = Vec::new();
    for attempt in &program.attempts {
        let mut normalized = std::collections::BTreeMap::<usize, u64>::new();
        for (index, coefficient_root) in &attempt.terms {
            let coefficient = values
                .get(*coefficient_root as usize)
                .copied()
                .ok_or_else(|| SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
                    detail: "CSR coefficient root is out of range".to_owned(),
                })?
                % MODULUS;
            if coefficient == 0 {
                continue;
            }
            let entry = normalized.entry(*index as usize).or_default();
            *entry = fadd(*entry, coefficient);
        }
        normalized.retain(|_, coefficient| *coefficient != 0);
        let target = values
            .get(attempt.target as usize)
            .copied()
            .ok_or_else(|| SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
                detail: "CSR target root is out of range".to_owned(),
            })?;
        let emitted = !(normalized.is_empty() && target == 0);
        cursor
            .record_attempt(attempt.family as usize, emitted)
            .map_err(
                |error| SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
                    detail: format!("{error:?}"),
                },
            )?;
        if !emitted {
            continue;
        }
        if normalized.is_empty() {
            // V8 forbids empty CSR rows. Match `CsrBuilder::push` by routing a public-only
            // contradiction through the independently constrained canonical zero source cell.
            normalized.insert(tail_source_index(120), 1);
        }
        for (index, coefficient) in normalized {
            indices.push(u32::try_from(index).expect("V8 witness index fits u32"));
            coefficients.push(coefficient);
        }
        targets.push(target);
        constraint_family_ids.push(attempt.family);
        offsets.push(u32::try_from(indices.len()).expect("V8 CSR terms fit u32"));
    }
    let family_receipt =
        cursor.finish().map_err(
            |error| SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
                detail: format!("{error:?}"),
            },
        )?;
    Ok(FinalizedCsr {
        offsets,
        indices,
        coefficients,
        targets,
        constraint_family_ids,
        family_receipt,
    })
}

// Test oracle proving that the independent numeric emitter agrees with HGV8RP03 specialization
// and that term, target, ordering, and empty-row mutations are detected.
#[cfg_attr(not(test), allow(dead_code))]
fn ensure_csr_matches_executable_program(
    public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    actual: &FinalizedCsr,
) -> Result<(), SmallwoodPoseidon2V8RelationError> {
    let expected = specialize_executable_csr_program(public)?;
    if actual != &expected {
        return Err(SmallwoodPoseidon2V8RelationError::CsrProgramMismatch {
            detail: format!(
                "specialized CSR differs from HGV8RP03 (actual rows {}, terms {}; expected rows {}, terms {})",
                actual.targets.len(),
                actual.indices.len(),
                expected.targets.len(),
                expected.indices.len(),
            ),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8CallRoleRange {
    pub name: &'static str,
    pub start: usize,
    pub end: usize,
}

/// Exact ordered role table.  Half-open ranges cover every live call once and only once.
pub const SMALLWOOD_POSEIDON2_V8_CALL_ROLE_TABLE: [SmallwoodPoseidon2V8CallRoleRange; 20] = [
    SmallwoodPoseidon2V8CallRoleRange {
        name: "transaction_prf",
        start: 0,
        end: 1,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "input_0_note",
        start: 1,
        end: 4,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "input_0_merkle",
        start: 4,
        end: 36,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "input_0_nullifier",
        start: 36,
        end: 37,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "input_1_note",
        start: 37,
        end: 40,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "input_1_merkle",
        start: 40,
        end: 72,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "input_1_nullifier",
        start: 72,
        end: 73,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "output_0_note",
        start: 73,
        end: 76,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "output_1_note",
        start: 76,
        end: 79,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "action_intent",
        start: 79,
        end: 94,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "authorization_policy",
        start: 94,
        end: 98,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "authorization_current",
        start: 98,
        end: 101,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "authorization_next",
        start: 101,
        end: 104,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "authorization_value_lock",
        start: 104,
        end: 106,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "stable_config_chunks",
        start: 106,
        end: 110,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "stable_config_tree",
        start: 110,
        end: 113,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "stable_state_leaves",
        start: 113,
        end: 115,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "stable_authenticated_paths",
        start: 115,
        end: 123,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "stable_issuer_commitment",
        start: 123,
        end: 124,
    },
    SmallwoodPoseidon2V8CallRoleRange {
        name: "stable_issuer_authorization",
        start: 124,
        end: 125,
    },
];

pub const SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT: usize = 830;

fn set_replicated_row(rows: &mut [[u64; 64]], row: usize, value: u64) {
    rows[row].fill(value);
}

fn positive_flags(value: u64) -> [u64; SIGNERS] {
    core::array::from_fn(|index| u64::from(value == (index + 1) as u64))
}

fn count_flags_0_to_6(value: u64) -> [u64; SIGNERS + 1] {
    core::array::from_fn(|index| u64::from(value == index as u64))
}

fn slot_active(flags: &[u64; SIGNERS], slot: usize) -> u64 {
    flags[slot..].iter().copied().sum()
}

fn build_smallwood_poseidon2_v8_assignment(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<Vec<u64>, SmallwoodPoseidon2V8RelationError> {
    witness.validate_against_statement(statement)?;
    let public = statement.to_public_words();
    let schedule = Box::new(build_smallwood_poseidon2_v8_hash_schedule(
        statement, witness,
    )?);
    let mut rows = vec![[0u64; 64]; SMALLWOOD_POSEIDON2_V8_ROW_COUNT];

    for input in 0..INPUTS {
        set_replicated_row(
            &mut rows,
            input_value_row(input),
            witness.inputs[input].note.value,
        );
        set_replicated_row(
            &mut rows,
            input_asset_row(input),
            witness.inputs[input].note.asset_id,
        );
        for bit in 0..MERKLE_DEPTH {
            set_replicated_row(
                &mut rows,
                input_direction_row(input, bit),
                (witness.inputs[input].position >> bit) & 1,
            );
        }
    }
    for output in 0..OUTPUTS {
        set_replicated_row(
            &mut rows,
            output_value_row(output),
            witness.outputs[output].note.value,
        );
        set_replicated_row(
            &mut rows,
            output_asset_row(output),
            witness.outputs[output].note.asset_id,
        );
        for limb in 0..6 {
            set_replicated_row(
                &mut rows,
                output_ciphertext_row(output, limb),
                public[32 + output * 6 + limb],
            );
        }
        for limb in 0..4 {
            set_replicated_row(
                &mut rows,
                output_auth_key_row(output, limb),
                witness.outputs[output].note.authorization_key[limb],
            );
        }
    }

    let mode = match witness.auth.mode {
        SmallwoodPrivateAuthMode::SingleKey => [1, 0, 0],
        SmallwoodPrivateAuthMode::ApprovalStep => [0, 1, 0],
        SmallwoodPrivateAuthMode::FinalThresholdSpend => [0, 0, 1],
    };
    for (index, value) in mode.into_iter().enumerate() {
        set_replicated_row(&mut rows, auth_mode_row(index), value);
    }
    let legacy = schedule.calls[0].final_digest();
    let current = schedule.calls[100].final_digest();
    let next = schedule.calls[103].final_digest();
    let value_lock = schedule.calls[105].final_digest();
    let statement_digest = schedule.calls[93].final_digest();
    let computed_policy = schedule.calls[97].final_digest();
    let policy = if witness.auth.mode == SmallwoodPrivateAuthMode::SingleKey {
        [0; DIGEST]
    } else {
        computed_policy
    };
    for input in 0..INPUTS {
        let (prf, key) = if !statement.input_flags[input] {
            (0, [0; 4])
        } else {
            match witness.auth.mode {
                SmallwoodPrivateAuthMode::SingleKey => {
                    (legacy[0], legacy[1..5].try_into().unwrap())
                }
                SmallwoodPrivateAuthMode::ApprovalStep if input == 0 => {
                    (current[4], current[..4].try_into().unwrap())
                }
                SmallwoodPrivateAuthMode::ApprovalStep => {
                    (legacy[0], legacy[1..5].try_into().unwrap())
                }
                SmallwoodPrivateAuthMode::FinalThresholdSpend if input == 0 => {
                    (value_lock[4], value_lock[..4].try_into().unwrap())
                }
                SmallwoodPrivateAuthMode::FinalThresholdSpend => {
                    (current[4], current[..4].try_into().unwrap())
                }
            }
        };
        set_replicated_row(&mut rows, auth_input_prf_row(input), prf);
        for limb in 0..4 {
            set_replicated_row(&mut rows, auth_input_key_row(input, limb), key[limb]);
        }
    }
    for limb in 0..5 {
        set_replicated_row(&mut rows, auth_legacy_row(limb), legacy[limb]);
    }
    for (row_fn, digest) in [
        (auth_current_row as fn(usize) -> usize, current),
        (auth_next_row as fn(usize) -> usize, next),
        (auth_value_lock_row as fn(usize) -> usize, value_lock),
        (auth_statement_row as fn(usize) -> usize, statement_digest),
        (auth_policy_row as fn(usize) -> usize, policy),
    ] {
        for limb in 0..DIGEST {
            set_replicated_row(&mut rows, row_fn(limb), digest[limb]);
        }
    }
    for limb in 0..DIGEST {
        set_replicated_row(
            &mut rows,
            auth_intent_row(limb),
            witness.auth.current.intent_digest[limb],
        );
    }

    let current_opening = witness.auth.current;
    let next_opening = witness.auth.next;
    for (row, value) in [
        (auth_threshold_row(), current_opening.threshold),
        (auth_signer_count_row(), current_opening.signer_count),
        (auth_count_row(), current_opening.approval_count),
        (auth_next_count_row(), next_opening.approval_count),
        (auth_reserved_signer_row(), 0),
        (auth_reserved_inverse_row(), 0),
    ] {
        set_replicated_row(&mut rows, row, value);
    }
    for slot in 0..SIGNERS {
        set_replicated_row(
            &mut rows,
            auth_approved_row(slot),
            u64::from(current_opening.approved_slots[slot]),
        );
        set_replicated_row(
            &mut rows,
            auth_next_approved_row(slot),
            u64::from(next_opening.approved_slots[slot]),
        );
    }
    let non_single = witness.auth.mode != SmallwoodPrivateAuthMode::SingleKey;
    let threshold_flags = if non_single {
        positive_flags(current_opening.threshold)
    } else {
        [0; SIGNERS]
    };
    let signer_flags = if non_single {
        positive_flags(current_opening.signer_count)
    } else {
        [0; SIGNERS]
    };
    let current_count_flags = if non_single {
        count_flags_0_to_6(current_opening.approval_count)
    } else {
        [0; SIGNERS + 1]
    };
    let next_count_flags = match witness.auth.mode {
        SmallwoodPrivateAuthMode::SingleKey => [0; SIGNERS + 1],
        SmallwoodPrivateAuthMode::ApprovalStep => count_flags_0_to_6(next_opening.approval_count),
        SmallwoodPrivateAuthMode::FinalThresholdSpend => count_flags_0_to_6(0),
    };
    for slot in 0..SIGNERS {
        set_replicated_row(
            &mut rows,
            auth_threshold_flag_row(slot),
            threshold_flags[slot],
        );
        set_replicated_row(&mut rows, auth_signer_flag_row(slot), signer_flags[slot]);
        for limb in 0..SIGNER_TAG_WORDS {
            set_replicated_row(
                &mut rows,
                auth_policy_tag_row(slot, limb),
                witness.auth.policy_signer_tags[slot][limb],
            );
        }
    }
    for slot in 0..=SIGNERS {
        set_replicated_row(
            &mut rows,
            auth_count_flag_row(slot),
            current_count_flags[slot],
        );
        set_replicated_row(
            &mut rows,
            auth_next_count_flag_row(slot),
            next_count_flags[slot],
        );
    }
    for slot in 0..SIGNERS {
        let membership = u64::from(
            witness.auth.mode == SmallwoodPrivateAuthMode::ApprovalStep
                && slot_active(&signer_flags, slot) == 1
                && witness.auth.policy_signer_tags[slot] == legacy[..5],
        );
        set_replicated_row(&mut rows, auth_membership_row(slot), membership);
    }
    let mut pair = 0;
    for left in 0..SIGNERS {
        for right in left + 1..SIGNERS {
            let active = non_single
                && slot_active(&signer_flags, left) == 1
                && slot_active(&signer_flags, right) == 1;
            let inverse = if active {
                finv(fsub(
                    witness.auth.policy_signer_tags[left][0],
                    witness.auth.policy_signer_tags[right][0],
                ))
            } else {
                0
            };
            set_replicated_row(&mut rows, auth_distinct_inverse_row(pair), inverse);
            pair += 1;
        }
    }

    // Base-four 61-bit ranges for four private values and three verifier constants.
    for (value_index, value) in [
        witness.inputs[0].note.value,
        witness.inputs[1].note.value,
        witness.outputs[0].note.value,
        witness.outputs[1].note.value,
        public[44],
        public[46],
        public[62],
    ]
    .into_iter()
    .enumerate()
    {
        for digit in 0..30 {
            let slot = value_index * 30 + digit;
            rows[SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + slot / 64][slot % 64] =
                (value >> (2 * digit)) & 3;
        }
        rows[SMALLWOOD_POSEIDON2_V8_DENSE_RANGE_ROW_START + 4][value_index] = value >> 60;
    }

    // Explicit Merkle orientation rows and the policy-root equality row.
    for input in 0..INPUTS {
        let note_final = input_note_call(input) + 2;
        for level in 0..MERKLE_DEPTH {
            let previous = if level == 0 {
                schedule.calls[note_final].final_digest()
            } else {
                schedule.calls[input_merkle_call(input, level) - 1].final_digest()
            };
            let sibling = witness.inputs[input].siblings[level];
            let direction = (witness.inputs[input].position >> level) & 1;
            let (left, right) = if direction == 0 {
                (previous, sibling)
            } else {
                (sibling, previous)
            };
            for limb in 0..DIGEST {
                let (group, lane) = inline_slot(input, level, limb);
                let base = SMALLWOOD_POSEIDON2_V8_INLINE_ROW_START + group * 4;
                rows[base][lane] = previous[limb];
                rows[base + 1][lane] = left[limb];
                rows[base + 2][lane] = right[limb];
                rows[base + 3][lane] = direction;
            }
        }
    }
    for limb in 0..DIGEST {
        rows[INLINE_POLICY_ROW_START][limb] = policy[limb];
        rows[INLINE_POLICY_ROW_START + 1][limb] = computed_policy[limb];
        rows[INLINE_POLICY_ROW_START + 2][limb] = u64::from(non_single);
    }

    for (offset, hash_row) in schedule.packed_rows.as_rows().iter().copied().enumerate() {
        rows[SMALLWOOD_POSEIDON2_V8_HASH_ROW_START + offset] = hash_row;
    }

    let stable_context =
        if statement.stablecoin.direction == StablecoinPoseidon2V8Direction::Disabled {
            StablecoinPoseidon2V8Context {
                current_root: statement.stablecoin.before_root,
                parent_height: statement.stablecoin.parent_height,
                expected_action_intent: [Felt::ZERO; DIGEST],
            }
        } else {
            StablecoinPoseidon2V8Context {
                current_root: statement.stablecoin.before_root,
                parent_height: statement.stablecoin.parent_height,
                expected_action_intent: statement.stablecoin.action_intent,
            }
        };
    let stable_material = Box::new(build_smallwood_poseidon2_v8_relation_material(
        stable_context,
        statement.stablecoin,
        witness.stablecoin,
    )?);
    for (offset, stable_row) in stable_material.rows.iter().copied().enumerate() {
        rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + offset] = stable_row;
    }
    for slot in 94..112 {
        rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + slot / 64][slot % 64] =
            public[63 + slot - 94];
    }
    for limb in 0..4 {
        rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + (112 + limb) / 64][(112 + limb) % 64] =
            witness.inputs[0].spend_key[limb];
        rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + (116 + limb) / 64][(116 + limb) % 64] =
            witness.inputs[1].spend_key[limb];
    }

    let stable_row = |local: usize| SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START + local;
    let unit_digest = [1, 0, 0, 0, 0, 0, 0];
    let any_input = statement.input_flags[0] || statement.input_flags[1];
    let chosen_spend_key = if statement.input_flags[0] {
        witness.inputs[0].spend_key
    } else if statement.input_flags[1] {
        witness.inputs[1].spend_key
    } else {
        [0; 4]
    };
    let mut extra_role_differences = Vec::<[u64; DIGEST]>::with_capacity(9);
    extra_role_differences.push(core::array::from_fn(|limb| {
        if any_input {
            chosen_spend_key.get(limb).copied().unwrap_or(0)
        } else {
            unit_digest[limb]
        }
    }));
    extra_role_differences.push(if non_single { policy } else { unit_digest });
    extra_role_differences.push(if non_single {
        witness.auth.current.intent_digest
    } else {
        unit_digest
    });
    for slot in 0..SIGNERS {
        let active = slot_active(&signer_flags, slot) == 1;
        extra_role_differences.push(core::array::from_fn(|limb| {
            if active {
                witness.auth.policy_signer_tags[slot]
                    .get(limb)
                    .copied()
                    .unwrap_or(0)
            } else {
                unit_digest[limb]
            }
        }));
    }
    debug_assert_eq!(
        extra_role_differences.len(),
        TOTAL_ROLE_CONDITIONS - STABLE_ROLE_CONDITIONS
    );
    for (offset, difference) in extra_role_differences.into_iter().enumerate() {
        let condition = STABLE_ROLE_CONDITIONS + offset;
        let selected = difference
            .iter()
            .position(|value| *value != 0)
            .expect("typed V8 witness admission guarantees an active nonzero role");
        for limb in 0..DIGEST {
            rows[stable_row(2 + limb)][condition] = difference[limb];
        }
        rows[stable_row(9)][condition] = selected as u64;
        rows[stable_row(10)][condition] = finv(difference[selected]);
    }

    // Complete the exact multiplication helper assignment beyond the materializer's original
    // eighteen lanes.
    let numeric = rows[stable_row(12)];
    let booleans = rows[stable_row(11)];
    let source3 = rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START][3];
    let source4 = rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START][4];
    let source5 = rows[SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START][5];
    let mint = u64::from(statement.stablecoin.direction == StablecoinPoseidon2V8Direction::Mint);
    for (offset, carry_lane) in [23usize, 28, 29, 35, 40, 41].into_iter().enumerate() {
        let left = (1u64 << 32) - 1 - numeric[carry_lane];
        rows[stable_row(13)][18 + offset] = left;
        rows[stable_row(14)][18 + offset] = if mint == 1 { finv(left) } else { 0 };
        rows[stable_row(15)][18 + offset] = mint;
    }
    rows[stable_row(13)][24] = 1 - source4;
    rows[stable_row(14)][24] = source5;
    let gate = mint * source4;
    let limb_mask = (1u64 << 32) - 1;
    let low_residual = |x: u64, y: u64, z: u64, carry: u64| {
        fsub(
            fadd(fadd(x & limb_mask, y & limb_mask), 1),
            fadd(z & limb_mask, fmul(1u64 << 32, carry)),
        )
    };
    let high_residual =
        |x: u64, y: u64, z: u64, carry: u64| fsub(fadd(fadd(x >> 32, y >> 32), carry), z >> 32);
    let retirement = [
        low_residual(source3, numeric[2], source5, booleans[27]),
        high_residual(source3, numeric[2], source5, booleans[27]),
        low_residual(public[94], numeric[3], source5, booleans[28]),
        high_residual(public[94], numeric[3], source5, booleans[28]),
    ];
    for (offset, residual) in retirement.into_iter().enumerate() {
        rows[stable_row(13)][25 + offset] = gate;
        rows[stable_row(14)][25 + offset] = residual;
    }
    let no_gate = 1 - gate;
    for (lane, helper) in [
        (29usize, numeric[2]),
        (30, numeric[3]),
        (31, booleans[27]),
        (32, booleans[28]),
    ] {
        rows[stable_row(13)][lane] = no_gate;
        rows[stable_row(14)][lane] = helper;
    }

    Ok(rows.into_iter().flatten().collect())
}

#[inline]
fn packed_hash_initial(packed: &[u64], call: usize, lane: usize) -> u64 {
    packed[hash_initial_index(call, lane)]
}

#[inline]
fn packed_hash_final(packed: &[u64], call: usize, lane: usize) -> u64 {
    packed[hash_final_index(call, lane)]
}

/// Recover one semantic source word from a fixed V8 sponge call sequence.
///
/// The first block stores the source directly in the initial state.  Later blocks add the
/// source to the previous call's final state, so field subtraction recovers the unique source.
#[inline]
fn decode_sponge_source_word(packed: &[u64], first_call: usize, word: usize) -> u64 {
    let block = word / POSEIDON2_WIDTH16_RATE;
    let lane = word % POSEIDON2_WIDTH16_RATE;
    let call = first_call + block;
    let initial = packed_hash_initial(packed, call, lane);
    if block == 0 {
        initial
    } else {
        fsub(initial, packed_hash_final(packed, call - 1, lane))
    }
}

fn decoded_selector_words(
    active: bool,
    asset: u64,
    statement: &SmallwoodPoseidon2V8PublicStatement,
) -> [u64; 4] {
    let mut selectors = [0u64; 4];
    if active {
        if let Some(slot) = statement.balance_assets.iter().position(|candidate| {
            *candidate == asset && *candidate != BALANCE_SLOT_PADDING_FIELD_ID
        }) {
            selectors[slot] = 1;
        }
    }
    selectors
}

fn decode_accumulator_words(packed: &[u64], first_call: usize) -> [u64; 23] {
    core::array::from_fn(|word| decode_sponge_source_word(packed, first_call, word))
}

/// Semantic section owning one word in the canonical 721-word typed witness.
///
/// The numeric discriminants are part of the retained Rust/Lean refinement vector.  Changing one
/// therefore requires regenerating and reviewing that vector rather than silently reinterpreting
/// an existing receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SmallwoodPoseidon2V8DecoderFamily {
    Input0 = 0,
    Input1 = 1,
    Output0 = 2,
    Output1 = 3,
    Authorization = 4,
    Stablecoin = 5,
}

/// Exact operation used to recover one typed witness word from verifier-owned inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SmallwoodPoseidon2V8DecoderOperation {
    /// Copy one canonical public statement word.
    StatementWord = 0,
    /// Copy a sponge source word when the named public activity flag is one, otherwise zero.
    ActivitySelectedSpongeSource = 1,
    /// Recover a source word from a rate-eight sponge chain (initial, or initial minus prior final).
    SpongeSource = 2,
    /// Pack thirty-two consecutive boolean direction rows into one little-endian position word.
    PackDirectionBits = 3,
    /// Select the left or right digest operand using one private Merkle direction row.
    OrientedMerkleSibling = 4,
    /// Derive a one-hot selector from an activity flag, note asset, and public balance asset.
    DerivedBalanceSelector = 5,
    /// Decode the three authorization mode rows as the canonical one-hot mode word.
    AuthorizationModeOneHot = 6,
    /// Recover a sponge source only for approval-step mode, otherwise require zero.
    ApprovalSelectedSpongeSource = 7,
    /// Copy one replicated raw semantic row.
    RawWord = 8,
    /// Copy one Poseidon2 compression input lane.
    HashInitialWord = 9,
    /// Select a stable-tree sibling operand using one bit of the public stable asset id.
    OrientedStableSibling = 10,
}

/// One source-derived decoder correspondence entry.
///
/// `arguments` are packed-witness or public-word coordinates interpreted by `operation`.  The
/// all-ones sentinel means that the operation has no second packed coordinate (the first sponge
/// block, for example).  The compact seven-word encoding is mirrored exactly in Lean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8DecoderSource {
    pub typed_word: usize,
    pub family: SmallwoodPoseidon2V8DecoderFamily,
    pub operation: SmallwoodPoseidon2V8DecoderOperation,
    pub arguments: [u64; 4],
}

impl SmallwoodPoseidon2V8DecoderSource {
    pub fn to_receipt_words(self) -> [u64; 7] {
        [
            self.typed_word as u64,
            self.family as u8 as u64,
            self.operation as u8 as u64,
            self.arguments[0],
            self.arguments[1],
            self.arguments[2],
            self.arguments[3],
        ]
    }
}

const DECODER_NO_COORDINATE: u64 = u64::MAX;

fn decoder_sponge_arguments(first_call: usize, word: usize) -> [u64; 4] {
    let block = word / POSEIDON2_WIDTH16_RATE;
    let lane = word % POSEIDON2_WIDTH16_RATE;
    let call = first_call + block;
    [
        hash_initial_index(call, lane) as u64,
        if block == 0 {
            DECODER_NO_COORDINATE
        } else {
            hash_final_index(call - 1, lane) as u64
        },
        call as u64,
        lane as u64,
    ]
}

/// Exhaustive source-coordinate receipt for the arbitrary packed-assignment decoder.
///
/// There is exactly one entry for every canonical typed witness word.  Besides direct copies it
/// records all branch sources: four activity flags, two 32-bit Merkle positions, 448 oriented note
/// tree limbs, sixteen balance-selector decisions, the three-way authorization mode, the
/// approval-only next accumulator, and the public-index-directed stable path.
pub fn smallwood_poseidon2_v8_decoder_sources() -> Vec<SmallwoodPoseidon2V8DecoderSource> {
    let mut sources = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_TYPED_WITNESS_WORDS);
    let typed_word = core::cell::Cell::new(0usize);
    let mut push = |family, operation, arguments| {
        sources.push(SmallwoodPoseidon2V8DecoderSource {
            typed_word: typed_word.get(),
            family,
            operation,
            arguments,
        });
        typed_word.set(typed_word.get() + 1);
    };

    for input in 0..INPUTS {
        let family = if input == 0 {
            SmallwoodPoseidon2V8DecoderFamily::Input0
        } else {
            SmallwoodPoseidon2V8DecoderFamily::Input1
        };
        let activity_public_word = input as u64;
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::StatementWord,
            [activity_public_word, 0, 0, 0],
        );
        for limb in 0..4 {
            let mut arguments = decoder_sponge_arguments(0, limb);
            arguments[3] = activity_public_word;
            push(
                family,
                SmallwoodPoseidon2V8DecoderOperation::ActivitySelectedSpongeSource,
                arguments,
            );
        }
        let note_start = typed_word.get();
        for typed_word in 0..18 {
            let hash_word = match typed_word {
                0..=5 => typed_word,
                6..=9 => 14 + typed_word - 6,
                10..=13 => 6 + typed_word - 10,
                14..=17 => 10 + typed_word - 14,
                _ => unreachable!("the V8 note has exactly eighteen words"),
            };
            push(
                family,
                SmallwoodPoseidon2V8DecoderOperation::SpongeSource,
                decoder_sponge_arguments(input_note_call(input), hash_word),
            );
        }
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::PackDirectionBits,
            [
                raw_index(input_direction_row(input, 0)) as u64,
                SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR as u64,
                MERKLE_DEPTH as u64,
                input as u64,
            ],
        );
        for level in 0..MERKLE_DEPTH {
            let call = input_merkle_call(input, level);
            let direction = raw_index(input_direction_row(input, level)) as u64;
            for limb in 0..DIGEST {
                push(
                    family,
                    SmallwoodPoseidon2V8DecoderOperation::OrientedMerkleSibling,
                    [
                        hash_initial_index(call, limb) as u64,
                        hash_initial_index(call, DIGEST + limb) as u64,
                        direction,
                        level as u64,
                    ],
                );
            }
        }
        for balance_slot in 0..4 {
            push(
                family,
                SmallwoodPoseidon2V8DecoderOperation::DerivedBalanceSelector,
                [
                    activity_public_word,
                    (note_start + 1) as u64,
                    (54 + balance_slot) as u64,
                    balance_slot as u64,
                ],
            );
        }
    }

    for output in 0..OUTPUTS {
        let family = if output == 0 {
            SmallwoodPoseidon2V8DecoderFamily::Output0
        } else {
            SmallwoodPoseidon2V8DecoderFamily::Output1
        };
        let activity_public_word = (2 + output) as u64;
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::StatementWord,
            [activity_public_word, 0, 0, 0],
        );
        let note_start = typed_word.get();
        for typed_word in 0..18 {
            let hash_word = match typed_word {
                0..=5 => typed_word,
                6..=9 => 14 + typed_word - 6,
                10..=13 => 6 + typed_word - 10,
                14..=17 => 10 + typed_word - 14,
                _ => unreachable!("the V8 note has exactly eighteen words"),
            };
            push(
                family,
                SmallwoodPoseidon2V8DecoderOperation::SpongeSource,
                decoder_sponge_arguments(output_note_call(output), hash_word),
            );
        }
        for balance_slot in 0..4 {
            push(
                family,
                SmallwoodPoseidon2V8DecoderOperation::DerivedBalanceSelector,
                [
                    activity_public_word,
                    (note_start + 1) as u64,
                    (54 + balance_slot) as u64,
                    balance_slot as u64,
                ],
            );
        }
    }

    let family = SmallwoodPoseidon2V8DecoderFamily::Authorization;
    push(
        family,
        SmallwoodPoseidon2V8DecoderOperation::AuthorizationModeOneHot,
        [
            raw_index(auth_mode_row(0)) as u64,
            raw_index(auth_mode_row(1)) as u64,
            raw_index(auth_mode_row(2)) as u64,
            0,
        ],
    );
    for word in 0..23 {
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::SpongeSource,
            decoder_sponge_arguments(98, word),
        );
    }
    for word in 0..23 {
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::ApprovalSelectedSpongeSource,
            decoder_sponge_arguments(101, word),
        );
    }
    for slot in 0..SIGNERS {
        for limb in 0..SIGNER_TAG_WORDS {
            push(
                family,
                SmallwoodPoseidon2V8DecoderOperation::RawWord,
                [
                    raw_index(auth_policy_tag_row(slot, limb)) as u64,
                    slot as u64,
                    limb as u64,
                    0,
                ],
            );
        }
    }

    let family = SmallwoodPoseidon2V8DecoderFamily::Stablecoin;
    for word in 0..55 {
        let call = 106 + word / 14;
        let lane = word % 14;
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::HashInitialWord,
            [
                hash_initial_index(call, lane) as u64,
                call as u64,
                lane as u64,
                word as u64,
            ],
        );
    }
    for counter in 0..4 {
        let lane = DIGEST + counter;
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::HashInitialWord,
            [
                hash_initial_index(113, lane) as u64,
                113,
                lane as u64,
                counter as u64,
            ],
        );
    }
    for level in 0..STABLECOIN_POSEIDON2_V8_DEPTH {
        let call = 115 + 2 * level;
        for limb in 0..DIGEST {
            push(
                family,
                SmallwoodPoseidon2V8DecoderOperation::OrientedStableSibling,
                [
                    hash_initial_index(call, limb) as u64,
                    hash_initial_index(call, DIGEST + limb) as u64,
                    84,
                    level as u64,
                ],
            );
        }
    }
    for limb in 0..DIGEST {
        push(
            family,
            SmallwoodPoseidon2V8DecoderOperation::HashInitialWord,
            [
                hash_initial_index(123, limb) as u64,
                123,
                limb as u64,
                limb as u64,
            ],
        );
    }

    debug_assert_eq!(typed_word.get(), SMALLWOOD_POSEIDON2_V8_TYPED_WITNESS_WORDS);
    debug_assert_eq!(sources.len(), typed_word.get());
    sources
}

/// Convert the hash preimage order
/// `value,asset,recipient,rho,randomness,authorization` to the canonical typed-wire order
/// `value,asset,recipient,authorization,rho,randomness`.
fn decode_note_witness_words(packed: &[u64], first_call: usize) -> [u64; 18] {
    core::array::from_fn(|typed_word| {
        let hash_word = match typed_word {
            0..=5 => typed_word,
            6..=9 => 14 + typed_word - 6,
            10..=13 => 6 + typed_word - 10,
            14..=17 => 10 + typed_word - 14,
            _ => unreachable!("the V8 note has exactly eighteen words"),
        };
        decode_sponge_source_word(packed, first_call, hash_word)
    })
}

/// Decode the unique typed 721-word witness carried by an arbitrary canonical V8 packed
/// assignment.
///
/// This decoder does not trust prover-supplied side data.  It reads only coordinates already
/// consumed by `HGV8RP03`: sponge initial/final states, oriented Merkle operands, replicated raw
/// rows, and stablecoin compression inputs.  It then runs the canonical typed parser and semantic
/// surface validator.  The verifier additionally rebuilds the full packed assignment and demands
/// exact word-for-word equality, so unconstrained or alternate encodings cannot be accepted.
pub fn decode_smallwood_poseidon2_v8_packed_witness(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    packed: &[u64],
) -> Result<SmallwoodPoseidon2V8Witness, SmallwoodPoseidon2V8RelationError> {
    statement.validate_public_structure()?;
    if packed.len() != SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS {
        return Err(SmallwoodPoseidon2V8RelationError::WrongWitnessLength {
            expected: SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS,
            actual: packed.len(),
        });
    }
    for (index, value) in packed.iter().copied().enumerate() {
        if value >= MODULUS {
            return Err(SmallwoodPoseidon2V8RelationError::NonCanonicalWitness { index });
        }
    }

    let raw = |row: usize| packed[raw_index(row)];
    let mut words = Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_TYPED_WITNESS_WORDS);
    let global_spend_key: [u64; 4] =
        core::array::from_fn(|limb| decode_sponge_source_word(packed, 0, limb));

    for input in 0..INPUTS {
        let active = statement.input_flags[input];
        words.push(u64::from(active));
        words.extend(if active { global_spend_key } else { [0; 4] });
        let note = decode_note_witness_words(packed, input_note_call(input));
        words.extend(note);

        let mut position = 0u64;
        for bit in 0..MERKLE_DEPTH {
            let direction = raw(input_direction_row(input, bit));
            if direction > 1 {
                return Err(SmallwoodPoseidon2V8RelationError::PackedWitnessDecode {
                    detail: "input Merkle direction is not boolean",
                });
            }
            position |= direction << bit;
        }
        words.push(position);
        for level in 0..MERKLE_DEPTH {
            let call = input_merkle_call(input, level);
            let direction = raw(input_direction_row(input, level));
            let sibling_start = if direction == 0 { DIGEST } else { 0 };
            for limb in 0..DIGEST {
                words.push(packed_hash_initial(packed, call, sibling_start + limb));
            }
        }
        words.extend(decoded_selector_words(active, note[1], statement));
    }

    for output in 0..OUTPUTS {
        let active = statement.output_flags[output];
        words.push(u64::from(active));
        let note = decode_note_witness_words(packed, output_note_call(output));
        words.extend(note);
        words.extend(decoded_selector_words(active, note[1], statement));
    }

    let mode_rows = [
        raw(auth_mode_row(0)),
        raw(auth_mode_row(1)),
        raw(auth_mode_row(2)),
    ];
    let mode_word = match mode_rows {
        [1, 0, 0] => 0,
        [0, 1, 0] => 1,
        [0, 0, 1] => 2,
        _ => {
            return Err(SmallwoodPoseidon2V8RelationError::PackedWitnessDecode {
                detail: "authorization mode rows are not canonical one-hot",
            })
        }
    };
    words.push(mode_word);
    let current = decode_accumulator_words(packed, 98);
    words.extend(current);
    if mode_word == 1 {
        words.extend(decode_accumulator_words(packed, 101));
    } else {
        words.extend([0u64; 23]);
    }
    for slot in 0..SIGNERS {
        for limb in 0..SIGNER_TAG_WORDS {
            words.push(raw(auth_policy_tag_row(slot, limb)));
        }
    }

    // The 55 stable configuration words are the fourteen data lanes of calls 106..110, with
    // the final chunk using only thirteen live words.
    for word in 0..55 {
        let call = 106 + word / 14;
        let lane = word % 14;
        words.push(packed_hash_initial(packed, call, lane));
    }
    // Before counters occupy the right input of the before-state leaf compression.
    for lane in DIGEST..DIGEST + 4 {
        words.push(packed_hash_initial(packed, 113, lane));
    }
    let mut stable_index = u64::from(statement.stablecoin.asset_id & 15);
    for level in 0..STABLECOIN_POSEIDON2_V8_DEPTH {
        let call = 115 + 2 * level;
        let sibling_start = if stable_index & 1 == 0 { DIGEST } else { 0 };
        for limb in 0..DIGEST {
            words.push(packed_hash_initial(packed, call, sibling_start + limb));
        }
        stable_index >>= 1;
    }
    for limb in 0..DIGEST {
        words.push(packed_hash_initial(packed, 123, limb));
    }

    debug_assert_eq!(words.len(), SMALLWOOD_POSEIDON2_V8_TYPED_WITNESS_WORDS);
    let witness = SmallwoodPoseidon2V8Witness::try_from_witness_words(&words)?;
    witness.validate_against_statement(statement)?;
    Ok(witness)
}

fn verify_canonical_smallwood_poseidon2_v8_typed_lowering(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    packed: &[u64],
) -> Result<(), SmallwoodPoseidon2V8RelationError> {
    let decoded = decode_smallwood_poseidon2_v8_packed_witness(statement, packed)?;
    let canonical = build_smallwood_poseidon2_v8_assignment(statement, &decoded)?;
    if let Some(index) = packed
        .iter()
        .zip(canonical.iter())
        .position(|(actual, expected)| actual != expected)
    {
        return Err(SmallwoodPoseidon2V8RelationError::NonCanonicalTypedLowering { index });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8Geometry {
    pub public_words: usize,
    pub relation_balance_limbs: usize,
    pub witness_rows: usize,
    pub packing_factor: usize,
    pub packed_witness_words: usize,
    pub constraint_degree: usize,
    pub nonlinear_constraints: usize,
    pub linear_constraints: usize,
    pub auxiliary_words: usize,
    pub hash_calls: usize,
}

/// Source-level refinement facts for one accepted verifier adapter.
///
/// This receipt says that the stored linear table came from the HGV8RP03 symbolic program and
/// that nonlinear acceptance executes the relation-id-bound expression DAG for every packed
/// lane.  It is deliberately not a claim about a compiled machine binary, semantic-specification
/// adequacy, proof-system soundness, or production authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8SourceProgramRefinement {
    pub relation_digest: [u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES],
    pub packed_lanes: usize,
    pub nonlinear_expression_nodes: usize,
    pub nonlinear_roots: usize,
    pub csr_expression_nodes: usize,
    pub csr_attempts: usize,
    pub emitted_linear_constraints: usize,
    pub emitted_linear_terms: usize,
    pub csr_family_receipt: SmallwoodPoseidon2V8CsrFamilyReceipt,
}

#[derive(Clone, Debug)]
pub struct SmallwoodPoseidon2V8ConstraintAdapter {
    public_values: [u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
    relation_balance_binding: [u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS],
    program_csr: ProgramSpecializedCsr,
}

#[derive(Clone, Debug)]
pub struct SmallwoodPoseidon2V8LoweredRelation {
    pub adapter: SmallwoodPoseidon2V8ConstraintAdapter,
    pub witness_values: Vec<u64>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8RelationError {
    #[error("invalid V8 semantic surface: {0:?}")]
    Surface(SmallwoodPoseidon2V8SurfaceError),
    #[error("V8 hash schedule materialization failed: {0}")]
    HashSchedule(SmallwoodPoseidon2V8HashScheduleError),
    #[error("V8 stable tail materialization failed: {0:?}")]
    StableMaterial(SmallwoodPoseidon2V8TailMaterialError),
    #[error("the executable V8 relation compiler is not complete")]
    CompilerIncomplete,
    #[error("the executable HGV8RP03 relation program does not match its pinned digest")]
    ProgramDigestMismatch,
    #[error("packed witness length is {actual}, expected {expected}")]
    WrongWitnessLength { expected: usize, actual: usize },
    #[error("non-canonical packed witness word {index}")]
    NonCanonicalWitness { index: usize },
    #[error("linear constraint {constraint} failed")]
    LinearConstraintViolation { constraint: usize },
    #[error("nonlinear constraint {constraint} failed in lane {lane}")]
    NonlinearConstraintViolation { lane: usize, constraint: usize },
    #[error("the packed V8 witness could not be decoded: {detail}")]
    PackedWitnessDecode { detail: &'static str },
    #[error("packed witness word {index} is not the canonical typed V8 lowering")]
    NonCanonicalTypedLowering { index: usize },
    #[error("the executable CSR compiler does not match the canonical family program: {detail}")]
    CsrProgramMismatch { detail: String },
}

impl From<SmallwoodPoseidon2V8SurfaceError> for SmallwoodPoseidon2V8RelationError {
    fn from(value: SmallwoodPoseidon2V8SurfaceError) -> Self {
        Self::Surface(value)
    }
}

impl From<SmallwoodPoseidon2V8HashScheduleError> for SmallwoodPoseidon2V8RelationError {
    fn from(value: SmallwoodPoseidon2V8HashScheduleError) -> Self {
        Self::HashSchedule(value)
    }
}

impl From<SmallwoodPoseidon2V8TailMaterialError> for SmallwoodPoseidon2V8RelationError {
    fn from(value: SmallwoodPoseidon2V8TailMaterialError) -> Self {
        Self::StableMaterial(value)
    }
}

#[inline]
const fn packed_index(row: usize, lane: usize) -> usize {
    row * SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR + lane
}

impl SmallwoodPoseidon2V8ConstraintAdapter {
    /// Build the verifier-owned relation from public data only.
    pub fn from_public_statement(
        statement: &SmallwoodPoseidon2V8PublicStatement,
    ) -> Result<Self, SmallwoodPoseidon2V8RelationError> {
        if !smallwood_poseidon2_v8_program_digest_matches() {
            return Err(SmallwoodPoseidon2V8RelationError::ProgramDigestMismatch);
        }
        statement.validate_public_structure()?;
        let public_values = statement.to_public_words();
        let relation_balance_binding = statement.expected_action_intent()?;
        // Do not compile a second numeric relation and compare it after the fact.  The adapter
        // stores only a private `ProgramSpecializedCsr`, constructed directly by interpreting the
        // relation-id-bound HGV8RP03 CSR program on these canonical public words.
        let program_csr = ProgramSpecializedCsr::for_public_words(&public_values)?;
        Ok(Self {
            public_values,
            relation_balance_binding,
            program_csr,
        })
    }

    pub fn public_values(&self) -> &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS] {
        &self.public_values
    }

    pub fn relation_balance_binding(
        &self,
    ) -> &[u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS] {
        &self.relation_balance_binding
    }

    pub const fn relation_digest(&self) -> &[u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES] {
        &SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST
    }

    /// Readiness evidence only; production authority remains in protocol versioning.
    pub const fn compiler_complete(&self) -> bool {
        true
    }

    pub fn linear_constraint_family_ids(&self) -> &[u16] {
        &self.program_csr.finalized().constraint_family_ids
    }

    pub fn csr_family_receipt(&self) -> &SmallwoodPoseidon2V8CsrFamilyReceipt {
        &self.program_csr.finalized().family_receipt
    }

    pub fn source_program_refinement(&self) -> SmallwoodPoseidon2V8SourceProgramRefinement {
        let nonlinear = executable_nonlinear_program();
        let csr_program = executable_csr_program();
        let csr = self.program_csr.finalized();
        debug_assert_eq!(
            nonlinear.expressions.len(),
            SMALLWOOD_POSEIDON2_V8_NONLINEAR_EXPRESSION_NODES
        );
        debug_assert_eq!(
            csr_program.expressions.len(),
            SMALLWOOD_POSEIDON2_V8_CSR_EXPRESSION_NODES
        );
        debug_assert_eq!(
            csr_program.attempts.len(),
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES
        );
        SmallwoodPoseidon2V8SourceProgramRefinement {
            relation_digest: SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST,
            packed_lanes: SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR,
            nonlinear_expression_nodes: nonlinear.expressions.len(),
            nonlinear_roots: nonlinear.roots.len(),
            csr_expression_nodes: csr_program.expressions.len(),
            csr_attempts: csr_program.attempts.len(),
            emitted_linear_constraints: csr.targets.len(),
            emitted_linear_terms: csr.indices.len(),
            csr_family_receipt: csr.family_receipt.clone(),
        }
    }

    pub fn geometry(&self) -> SmallwoodPoseidon2V8Geometry {
        SmallwoodPoseidon2V8Geometry {
            public_words: SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
            relation_balance_limbs: SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS,
            witness_rows: SMALLWOOD_POSEIDON2_V8_ROW_COUNT,
            packing_factor: SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR,
            packed_witness_words: SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS,
            constraint_degree: SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE,
            nonlinear_constraints: SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT,
            linear_constraints: self.program_csr.finalized().targets.len(),
            auxiliary_words: 0,
            hash_calls: SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT,
        }
    }

    pub fn verify_packed_witness(
        &self,
        witness_values: &[u64],
    ) -> Result<(), SmallwoodPoseidon2V8RelationError> {
        if witness_values.len() != SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS {
            return Err(SmallwoodPoseidon2V8RelationError::WrongWitnessLength {
                expected: SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS,
                actual: witness_values.len(),
            });
        }
        for (index, value) in witness_values.iter().copied().enumerate() {
            if value >= hegemon_field::GOLDILOCKS_MODULUS {
                return Err(SmallwoodPoseidon2V8RelationError::NonCanonicalWitness { index });
            }
        }
        let modulus = u128::from(hegemon_field::GOLDILOCKS_MODULUS);
        let csr = self.program_csr.finalized();
        for constraint in 0..csr.targets.len() {
            let start = csr.offsets[constraint] as usize;
            let end = csr.offsets[constraint + 1] as usize;
            let mut value = 0u128;
            for term in start..end {
                value = (value
                    + u128::from(csr.coefficients[term])
                        * u128::from(witness_values[csr.indices[term] as usize]))
                    % modulus;
            }
            if value as u64 != csr.targets[constraint] {
                return Err(
                    SmallwoodPoseidon2V8RelationError::LinearConstraintViolation { constraint },
                );
            }
        }
        let mut lane_rows = vec![0u64; SMALLWOOD_POSEIDON2_V8_ROW_COUNT];
        for lane in 0..SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR {
            for (row, value) in lane_rows.iter_mut().enumerate() {
                *value = witness_values[packed_index(row, lane)];
            }
            let residuals =
                evaluate_all_constraints(&self.public_values, &lane_rows).map_err(|_| {
                    SmallwoodPoseidon2V8RelationError::NonlinearConstraintViolation {
                        lane,
                        constraint: 0,
                    }
                })?;
            debug_assert_eq!(
                residuals.len(),
                SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT
            );
            if let Some((constraint, _)) = residuals
                .iter()
                .copied()
                .enumerate()
                .find(|(_, residual)| *residual != 0)
            {
                return Err(
                    SmallwoodPoseidon2V8RelationError::NonlinearConstraintViolation {
                        lane,
                        constraint,
                    },
                );
            }
        }
        let statement =
            SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&self.public_values)?;
        verify_canonical_smallwood_poseidon2_v8_typed_lowering(&statement, witness_values)
    }
}

impl SmallwoodConstraintAdapter for SmallwoodPoseidon2V8ConstraintAdapter {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
    }

    fn row_count(&self) -> usize {
        SMALLWOOD_POSEIDON2_V8_ROW_COUNT
    }

    fn packing_factor(&self) -> usize {
        SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
    }

    fn constraint_degree(&self) -> usize {
        SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE
    }

    fn linear_constraint_count(&self) -> usize {
        self.program_csr.finalized().targets.len()
    }

    fn constraint_count(&self) -> usize {
        SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.program_csr.finalized().offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &self.program_csr.finalized().indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &self.program_csr.finalized().coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        &self.program_csr.finalized().targets
    }

    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        Some(0)
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        row_scalars: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows: row_scalars,
            auxiliary_words,
        }
    }

    fn compute_constraints_u64(
        &self,
        view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        let SmallwoodNonlinearEvalView::RowScalars {
            rows,
            auxiliary_words,
            ..
        } = view;
        if !auxiliary_words.is_empty() {
            return Err(TransactionCircuitError::ConstraintViolation(
                "Poseidon2 V8 SmallWood forbids auxiliary witness words",
            ));
        }
        if rows.len() != SMALLWOOD_POSEIDON2_V8_ROW_COUNT
            || out.len() != SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT
        {
            return Err(TransactionCircuitError::ConstraintViolation(
                "Poseidon2 V8 SmallWood nonlinear view has the wrong shape",
            ));
        }
        let residuals = evaluate_all_constraints(&self.public_values, rows)?;
        out.copy_from_slice(&residuals);
        Ok(())
    }
}

impl SmallwoodPoseidon2V8FrontendRelation for SmallwoodPoseidon2V8ConstraintAdapter {
    fn public_values(&self) -> &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS] {
        self.public_values()
    }

    fn relation_balance_binding(&self) -> &[u64; SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS] {
        self.relation_balance_binding()
    }

    fn relation_digest(&self) -> &[u8; SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST_BYTES] {
        self.relation_digest()
    }

    fn compiler_complete(&self) -> bool {
        self.compiler_complete()
    }
}

pub fn compile_smallwood_poseidon2_v8_relation(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<SmallwoodPoseidon2V8LoweredRelation, SmallwoodPoseidon2V8RelationError> {
    let adapter = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(statement)?;
    let witness_values = build_smallwood_poseidon2_v8_assignment(statement, witness)?;
    adapter.verify_packed_witness(&witness_values)?;
    Ok(SmallwoodPoseidon2V8LoweredRelation {
        adapter,
        witness_values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric_row_binding_witness<'a>(
        builder: &'a CsrBuilder,
        family: &'static str,
        witness_index: usize,
    ) -> Option<&'a CsrNormalizedRow> {
        let family_index = SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILIES
            .iter()
            .position(|candidate| candidate.name == family)
            .expect("test family exists");
        builder.rows_by_family[family_index]
            .iter()
            .filter_map(Option::as_ref)
            .find(|row| row.terms.iter().any(|(index, _)| *index == witness_index))
    }

    #[test]
    fn output_note_final_block_tail_lanes_preserve_previous_final_state() {
        let call = output_note_call(0);
        let mut inputs = vec![None; 18];
        inputs[0] = Some(LinearExpression::witness(raw_index(output_value_row(0))));
        inputs[1] = Some(LinearExpression::witness(raw_index(output_asset_row(0))));
        for limb in 0..4 {
            inputs[14 + limb] = Some(LinearExpression::witness(raw_index(output_auth_key_row(
                0, limb,
            ))));
        }

        let mut builder = CsrBuilder::new();
        builder.set_family("hash.output_note_initial");
        assert_eq!(
            bind_sponge(&mut builder, call, NOTE_DOMAIN_TAG, &inputs),
            call + 2
        );

        for lane in 2..POSEIDON2_WIDTH16_RATE {
            let initial = hash_initial_index(call + 2, lane);
            let previous_final = hash_final_index(call + 1, lane);
            let row = numeric_row_binding_witness(&builder, "hash.output_note_initial", initial)
                .expect("each out-of-range final-block lane is constrained");
            assert_eq!(row.target, 0, "lane {lane}");
            assert_eq!(row.terms.len(), 2, "lane {lane}");
            assert_eq!(
                row.terms.iter().find(|(index, _)| *index == initial),
                Some(&(initial, 1)),
                "lane {lane}"
            );
            assert_eq!(
                row.terms.iter().find(|(index, _)| *index == previous_final),
                Some(&(previous_final, NEG_ONE)),
                "lane {lane}"
            );
        }
    }

    #[test]
    fn in_range_private_sponge_hole_remains_unbound() {
        let call = output_note_call(0);
        let inputs = vec![None; 18];
        let mut builder = CsrBuilder::new();
        builder.set_family("hash.output_note_initial");
        bind_sponge(&mut builder, call, NOTE_DOMAIN_TAG, &inputs);

        let first_block_private_hole = hash_initial_index(call, 2);
        assert!(
            numeric_row_binding_witness(
                &builder,
                "hash.output_note_initial",
                first_block_private_hole,
            )
            .is_none(),
            "an explicit first-block None remains an intentional private absorbed word"
        );

        let private_hole = hash_initial_index(call + 1, 2);
        assert!(
            numeric_row_binding_witness(&builder, "hash.output_note_initial", private_hole,)
                .is_none(),
            "an explicit in-range None remains an intentional private absorbed word"
        );
        assert!(
            numeric_row_binding_witness(
                &builder,
                "hash.output_note_initial",
                hash_initial_index(call + 2, 2),
            )
            .is_some(),
            "the same lane becomes constrained once its input index is out of range"
        );

        let mut first_block_builder = CsrBuilder::new();
        first_block_builder.set_family("hash.output_note_initial");
        bind_sponge(
            &mut first_block_builder,
            call,
            NOTE_DOMAIN_TAG,
            &inputs[..2],
        );
        for lane in 2..POSEIDON2_WIDTH16_RATE {
            let initial = hash_initial_index(call, lane);
            let row = numeric_row_binding_witness(
                &first_block_builder,
                "hash.output_note_initial",
                initial,
            )
            .expect("out-of-range first-block lane is constrained");
            assert_eq!(row.terms, vec![(initial, 1)], "lane {lane}");
            assert_eq!(row.target, 0, "lane {lane}");
        }
    }

    fn default_numeric_csr() -> ([u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS], FinalizedCsr) {
        let public = SmallwoodPoseidon2V8PublicStatement::default().to_public_words();
        let mut builder = CsrBuilder::new();
        build_base_linear_constraints(&public, &mut builder);
        build_stable_linear_constraints(&public, &mut builder);
        (public, builder.finish().expect("default V8 CSR compiles"))
    }

    fn assert_program_rejects_numeric_csr(
        public: &[u64; SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS],
        csr: &FinalizedCsr,
    ) {
        assert!(matches!(
            ensure_csr_matches_executable_program(public, csr),
            Err(SmallwoodPoseidon2V8RelationError::CsrProgramMismatch { .. })
        ));
    }

    #[test]
    fn exact_row_partition_and_call_roles_are_gap_free() {
        assert_eq!(SMALLWOOD_POSEIDON2_V8_ROW_COUNT, 686);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_ROW_START, 283);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START, 647);
        let mut cursor = 0;
        for role in SMALLWOOD_POSEIDON2_V8_CALL_ROLE_TABLE {
            assert_eq!(role.start, cursor, "gap or overlap before {}", role.name);
            assert!(role.end > role.start);
            cursor = role.end;
        }
        assert_eq!(cursor, 125);
    }

    #[test]
    fn verifier_constructor_is_statement_only_and_authority_neutral() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        assert_eq!(adapter.geometry().witness_rows, 686);
        assert_eq!(adapter.geometry().hash_calls, 125);
        assert_eq!(adapter.geometry().auxiliary_words, 0);
        assert_eq!(adapter.geometry().nonlinear_constraints, 830);
        assert_eq!(adapter.geometry().linear_constraints, 20_509);
        assert!(adapter.compiler_complete());
        assert_ne!(adapter.relation_digest(), &[0; 48]);
        let refinement = adapter.source_program_refinement();
        assert_eq!(refinement.relation_digest, *adapter.relation_digest());
        assert_eq!(refinement.packed_lanes, 64);
        assert_eq!(refinement.nonlinear_expression_nodes, 8_271);
        assert_eq!(refinement.nonlinear_roots, 830);
        assert_eq!(refinement.csr_expression_nodes, 565);
        assert_eq!(refinement.csr_attempts, 20_605);
        assert_eq!(
            refinement.emitted_linear_constraints,
            adapter.geometry().linear_constraints
        );
        assert_eq!(
            refinement.csr_family_receipt.emitted_total as usize,
            refinement.emitted_linear_constraints
        );
    }

    #[test]
    fn executable_csr_program_is_numeric_authority_and_rejects_emission_drift() {
        let (public, csr) = default_numeric_csr();
        ensure_csr_matches_executable_program(&public, &csr)
            .expect("numeric CSR exactly specializes the executable program");
        assert_eq!(
            executable_csr_program().attempts.len(),
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES
        );
        assert!(
            executable_csr_program().attempts.len() > csr.targets.len(),
            "at least one attempted empty-zero identity must be retained in HGV8RP03"
        );

        let mut dropped_term = csr.clone();
        dropped_term.indices.remove(0);
        dropped_term.coefficients.remove(0);
        for offset in dropped_term.offsets.iter_mut().skip(1) {
            *offset -= 1;
        }
        assert_program_rejects_numeric_csr(&public, &dropped_term);

        let mut changed_target = csr.clone();
        changed_target.targets[0] = fadd(changed_target.targets[0], 1);
        assert_program_rejects_numeric_csr(&public, &changed_target);

        let mut reordered = csr.clone();
        let first_end = reordered.offsets[1] as usize;
        let second_end = reordered.offsets[2] as usize;
        let mut indices = reordered.indices[first_end..second_end].to_vec();
        indices.extend_from_slice(&reordered.indices[..first_end]);
        indices.extend_from_slice(&reordered.indices[second_end..]);
        reordered.indices = indices;
        let mut coefficients = reordered.coefficients[first_end..second_end].to_vec();
        coefficients.extend_from_slice(&reordered.coefficients[..first_end]);
        coefficients.extend_from_slice(&reordered.coefficients[second_end..]);
        reordered.coefficients = coefficients;
        reordered.offsets[1] = (second_end - first_end) as u32;
        reordered.targets.swap(0, 1);
        reordered.constraint_family_ids.swap(0, 1);
        assert_program_rejects_numeric_csr(&public, &reordered);

        let mut emitted_empty_zero = csr.clone();
        emitted_empty_zero
            .indices
            .push(u32::try_from(tail_source_index(120)).unwrap());
        emitted_empty_zero.coefficients.push(1);
        emitted_empty_zero
            .offsets
            .push(u32::try_from(emitted_empty_zero.indices.len()).unwrap());
        emitted_empty_zero.targets.push(0);
        let last_family = SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_COUNT - 1;
        emitted_empty_zero
            .constraint_family_ids
            .push(last_family as u16);
        emitted_empty_zero.family_receipt.emitted_instances[last_family] += 1;
        emitted_empty_zero.family_receipt.emitted_total += 1;
        assert_program_rejects_numeric_csr(&public, &emitted_empty_zero);
    }

    fn canonical_statement_for_mask_and_seed(
        mask: u8,
        seed: u64,
        fee: u64,
    ) -> SmallwoodPoseidon2V8PublicStatement {
        let mut statement = SmallwoodPoseidon2V8PublicStatement::default();
        statement.fee = fee;
        for input in 0..2 {
            statement.input_flags[input] = mask & (1 << input) != 0;
            if statement.input_flags[input] {
                for limb in 0..7 {
                    statement.nullifiers[input][limb] =
                        1 + seed.wrapping_add((input * 7 + limb) as u64) % (MODULUS - 1);
                }
            }
        }
        for output in 0..2 {
            statement.output_flags[output] = mask & (1 << (2 + output)) != 0;
            if statement.output_flags[output] {
                for limb in 0..7 {
                    statement.commitments[output][limb] = 1 + seed
                        .rotate_left(17)
                        .wrapping_add((output * 7 + limb) as u64)
                        % (MODULUS - 1);
                }
                for limb in 0..6 {
                    statement.ciphertext_commitments[output][limb] = 1 + seed
                        .rotate_left(31)
                        .wrapping_add((output * 6 + limb) as u64)
                        % (MODULUS - 1);
                }
            }
        }
        statement
    }

    #[test]
    fn all_sixteen_activity_masks_use_the_program_specialized_adapter() {
        for mask in 0u8..16 {
            let statement = canonical_statement_for_mask_and_seed(
                mask,
                0x9e37_79b9_7f4a_7c15u64.wrapping_mul(u64::from(mask) + 1),
                u64::from(mask),
            );
            statement.validate_public_structure().unwrap();
            let public = statement.to_public_words();
            let expected = specialize_executable_csr_program(&public).unwrap();
            let adapter =
                SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
            assert_eq!(
                adapter.program_csr.finalized(),
                &expected,
                "mask {mask:#06b}"
            );
            assert_eq!(
                adapter.source_program_refinement().relation_digest,
                SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST,
                "mask {mask:#06b}"
            );
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(32))]

        #[test]
        fn randomized_canonical_statements_build_the_adapter_from_the_same_pinned_program(
            mask in 0u8..16,
            seed in proptest::prelude::any::<u64>(),
            fee in 0u64..(1u64 << 61),
        ) {
            let statement = canonical_statement_for_mask_and_seed(mask, seed, fee);
            statement.validate_public_structure().unwrap();
            let public = statement.to_public_words();
            let expected = specialize_executable_csr_program(&public).unwrap();
            let adapter = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement)
                .unwrap();
            proptest::prop_assert_eq!(adapter.program_csr.finalized(), &expected);
            let refinement = adapter.source_program_refinement();
            proptest::prop_assert_eq!(refinement.relation_digest, SMALLWOOD_POSEIDON2_V8_RELATION_DIGEST);
            proptest::prop_assert_eq!(refinement.csr_attempts, SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES);
            proptest::prop_assert_eq!(refinement.packed_lanes, SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR);
        }
    }

    #[test]
    fn last_packed_lane_is_checked_by_the_bound_nonlinear_program() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let witness = SmallwoodPoseidon2V8Witness::default();
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        let mut witness_values =
            build_smallwood_poseidon2_v8_assignment(&statement, &witness).unwrap();
        adapter.verify_packed_witness(&witness_values).unwrap();

        let lane = SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR - 1;
        let linear_indices = adapter
            .program_csr
            .finalized()
            .indices
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let mut lane_rows = (0..SMALLWOOD_POSEIDON2_V8_ROW_COUNT)
            .map(|row| witness_values[packed_index(row, lane)])
            .collect::<Vec<_>>();
        let row = (0..SMALLWOOD_POSEIDON2_V8_ROW_COUNT)
            .find(|row| {
                let index = packed_index(*row, lane);
                if linear_indices.contains(&u32::try_from(index).unwrap()) {
                    return false;
                }
                let original = lane_rows[*row];
                lane_rows[*row] = if original + 1 == MODULUS {
                    0
                } else {
                    original + 1
                };
                let rejected = evaluate_all_constraints(adapter.public_values(), &lane_rows)
                    .expect("fixed V8 nonlinear geometry")
                    .into_iter()
                    .any(|residual| residual != 0);
                lane_rows[*row] = original;
                rejected
            })
            .expect("one last-lane nonlinear source is independent of the CSR table");
        let index = packed_index(row, lane);
        witness_values[index] = if witness_values[index] + 1 == MODULUS {
            0
        } else {
            witness_values[index] + 1
        };
        assert!(matches!(
            adapter.verify_packed_witness(&witness_values),
            Err(SmallwoodPoseidon2V8RelationError::NonlinearConstraintViolation {
                lane: rejected_lane,
                ..
            }) if rejected_lane == lane
        ));
    }

    #[test]
    fn canonical_all_inactive_single_key_assignment_satisfies_full_relation() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let witness = SmallwoodPoseidon2V8Witness::default();
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        let witness_values = build_smallwood_poseidon2_v8_assignment(&statement, &witness).unwrap();
        if let Err(SmallwoodPoseidon2V8RelationError::LinearConstraintViolation { constraint }) =
            adapter.verify_packed_witness(&witness_values)
        {
            let csr = adapter.program_csr.finalized();
            let start = csr.offsets[constraint] as usize;
            let end = csr.offsets[constraint + 1] as usize;
            panic!(
                "linear {constraint}: target={} terms={:?}",
                csr.targets[constraint],
                (start..end)
                    .map(|term| (
                        csr.indices[term],
                        csr.coefficients[term],
                        witness_values[csr.indices[term] as usize]
                    ))
                    .collect::<Vec<_>>()
            );
        }
        let lowered = compile_smallwood_poseidon2_v8_relation(&statement, &witness).unwrap();
        assert_eq!(
            lowered.witness_values.len(),
            SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS
        );
        assert_eq!(lowered.adapter.geometry().nonlinear_constraints, 830);
        lowered
            .adapter
            .verify_packed_witness(&lowered.witness_values)
            .unwrap();
    }
}
