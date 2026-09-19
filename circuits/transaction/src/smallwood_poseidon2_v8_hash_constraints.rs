//! Exact compressed width-16 Poseidon2 constraints for the fresh V8 SmallWood relation.
//!
//! The relation assigns one Poseidon2 call to each lane of two 64-lane groups.  A group stores
//! the sixteen initial state words, one wire for every S-box input, and the sixteen final state
//! words.  The nonlinear evaluator replays every round through the source-owned width-16 step
//! function, so this module does not carry a second copy of the permutation matrices or round
//! constants.
//!
//! This module constrains only the permutation traces.  The transaction adapter must add linear
//! bindings from every live call's initial/final state rows to the corresponding semantic wires.

#![forbid(unsafe_code)]

use hegemon_field::{PrimeCharacteristicRing, GOLDILOCKS_MODULUS};
use thiserror::Error;
use transaction_core::poseidon2_width16::{
    poseidon2_width16_step_ring, Felt, POSEIDON2_WIDTH16_EXTERNAL_ROUNDS,
    POSEIDON2_WIDTH16_INTERNAL_ROUNDS, POSEIDON2_WIDTH16_ROUND_CONSTANTS, POSEIDON2_WIDTH16_STEPS,
    POSEIDON2_WIDTH16_WIDTH,
};

pub const SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT: usize = 128;
pub const SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT: usize =
    SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT.div_ceil(SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR);
pub const SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT: usize =
    SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT * SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR;
pub const SMALLWOOD_POSEIDON2_V8_HASH_DUMMY_CALL_COUNT: usize =
    SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT - SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT;

pub const SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL: usize =
    POSEIDON2_WIDTH16_EXTERNAL_ROUNDS * 2 * POSEIDON2_WIDTH16_WIDTH
        + POSEIDON2_WIDTH16_INTERNAL_ROUNDS;
pub const SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP: usize = POSEIDON2_WIDTH16_WIDTH
    + SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL
    + POSEIDON2_WIDTH16_WIDTH;
pub const SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT: usize =
    SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT * SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP;
pub const SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINTS_PER_GROUP: usize =
    SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL + POSEIDON2_WIDTH16_WIDTH;
pub const SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT: usize =
    SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT * SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINTS_PER_GROUP;
pub const SMALLWOOD_POSEIDON2_V8_HASH_DUMMY_ZERO_LINEAR_CONSTRAINT_COUNT: usize =
    SMALLWOOD_POSEIDON2_V8_HASH_DUMMY_CALL_COUNT * POSEIDON2_WIDTH16_WIDTH;
pub const SMALLWOOD_POSEIDON2_V8_HASH_MAX_CONSTRAINT_DEGREE: usize = 7;

const _: () = assert!(POSEIDON2_WIDTH16_STEPS == 31);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT == 2);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_DUMMY_CALL_COUNT == 0);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL == 150);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP == 182);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT == 364);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINTS_PER_GROUP == 166);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT == 332);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8HashRows {
    pub rows: Vec<[u64; SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR]>,
}

impl SmallwoodPoseidon2V8HashRows {
    pub fn as_rows(&self) -> &[[u64; SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR]] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<[u64; SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR]> {
        self.rows
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8HashConstraintError {
    #[error("Poseidon2 V8 hash call count is {actual}, expected {expected}")]
    WrongCallCount { expected: usize, actual: usize },
    #[error("Poseidon2 V8 hash row count is {actual}, expected {expected}")]
    WrongRowCount { expected: usize, actual: usize },
    #[error("Poseidon2 V8 lane-row count is {actual}, expected {expected}")]
    WrongLaneRowCount { expected: usize, actual: usize },
    #[error("Poseidon2 V8 hash constraint count is {actual}, expected {expected}")]
    WrongConstraintCount { expected: usize, actual: usize },
    #[error("Poseidon2 V8 call {call} input lane {state_lane} is not canonical")]
    NonCanonicalInput { call: usize, state_lane: usize },
    #[error("Poseidon2 V8 packed row {row}, lane {lane} is not canonical")]
    NonCanonicalRow { row: usize, lane: usize },
    #[error("Poseidon2 V8 dummy call {call} input lane {state_lane} is not zero")]
    NonZeroDummyInput { call: usize, state_lane: usize },
    #[error(
        "Poseidon2 V8 packed constraint failed at lane {lane}, constraint {constraint}, residual {residual}"
    )]
    ConstraintViolation {
        lane: usize,
        constraint: usize,
        residual: u64,
    },
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_call_group(call: usize) -> usize {
    call / SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_call_lane(call: usize) -> usize {
    call % SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_group_row_start(group: usize) -> usize {
    group * SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_initial_row(group: usize, state_lane: usize) -> usize {
    smallwood_poseidon2_v8_hash_group_row_start(group) + state_lane
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_sbox_wire_row(group: usize, wire: usize) -> usize {
    smallwood_poseidon2_v8_hash_group_row_start(group) + POSEIDON2_WIDTH16_WIDTH + wire
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_final_row(group: usize, state_lane: usize) -> usize {
    smallwood_poseidon2_v8_hash_group_row_start(group)
        + POSEIDON2_WIDTH16_WIDTH
        + SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL
        + state_lane
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_call_initial_witness_index(
    call: usize,
    state_lane: usize,
) -> usize {
    smallwood_poseidon2_v8_hash_initial_row(
        smallwood_poseidon2_v8_hash_call_group(call),
        state_lane,
    ) * SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR
        + smallwood_poseidon2_v8_hash_call_lane(call)
}

#[inline]
pub const fn smallwood_poseidon2_v8_hash_call_final_witness_index(
    call: usize,
    state_lane: usize,
) -> usize {
    smallwood_poseidon2_v8_hash_final_row(smallwood_poseidon2_v8_hash_call_group(call), state_lane)
        * SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR
        + smallwood_poseidon2_v8_hash_call_lane(call)
}

/// Local packed-witness indices which the aggregate adapter must constrain to zero.
///
/// Add the adapter's hash-row base multiplied by the packing factor to every returned index
/// before inserting the corresponding one-term CSR equation.
pub fn smallwood_poseidon2_v8_hash_dummy_zero_witness_indices() -> Vec<usize> {
    let mut indices =
        Vec::with_capacity(SMALLWOOD_POSEIDON2_V8_HASH_DUMMY_ZERO_LINEAR_CONSTRAINT_COUNT);
    for call in
        SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT..SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT
    {
        for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
            indices.push(smallwood_poseidon2_v8_hash_call_initial_witness_index(
                call, state_lane,
            ));
        }
    }
    indices
}

fn write_call_rows(
    rows: &mut [[u64; SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR]],
    call: usize,
    initial_state: [u64; POSEIDON2_WIDTH16_WIDTH],
) {
    let group = smallwood_poseidon2_v8_hash_call_group(call);
    let lane = smallwood_poseidon2_v8_hash_call_lane(call);
    let mut state = initial_state.map(Felt::from_u64);
    for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
        rows[smallwood_poseidon2_v8_hash_initial_row(group, state_lane)][lane] =
            state[state_lane].as_canonical_u64();
    }

    poseidon2_width16_step_ring(&mut state, 0);
    let mut wire = 0;
    for (round, constants) in POSEIDON2_WIDTH16_ROUND_CONSTANTS
        .external_initial
        .iter()
        .enumerate()
    {
        for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
            rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, wire)][lane] =
                (state[state_lane] + Felt::from_u64(constants[state_lane])).as_canonical_u64();
            wire += 1;
        }
        poseidon2_width16_step_ring(&mut state, 1 + round);
    }
    for (round, constant) in POSEIDON2_WIDTH16_ROUND_CONSTANTS
        .internal
        .iter()
        .enumerate()
    {
        rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, wire)][lane] =
            (state[0] + Felt::from_u64(*constant)).as_canonical_u64();
        wire += 1;
        poseidon2_width16_step_ring(&mut state, 1 + POSEIDON2_WIDTH16_EXTERNAL_ROUNDS + round);
    }
    for (round, constants) in POSEIDON2_WIDTH16_ROUND_CONSTANTS
        .external_terminal
        .iter()
        .enumerate()
    {
        for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
            rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, wire)][lane] =
                (state[state_lane] + Felt::from_u64(constants[state_lane])).as_canonical_u64();
            wire += 1;
        }
        poseidon2_width16_step_ring(
            &mut state,
            1 + POSEIDON2_WIDTH16_EXTERNAL_ROUNDS + POSEIDON2_WIDTH16_INTERNAL_ROUNDS + round,
        );
    }
    debug_assert_eq!(wire, SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL);

    for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
        rows[smallwood_poseidon2_v8_hash_final_row(group, state_lane)][lane] =
            state[state_lane].as_canonical_u64();
    }
}

/// Materialize the exact compressed witness rows for 128 live width-16 Poseidon2 calls.
pub fn build_smallwood_poseidon2_v8_hash_rows(
    initial_states: &[[u64; POSEIDON2_WIDTH16_WIDTH]],
) -> Result<SmallwoodPoseidon2V8HashRows, SmallwoodPoseidon2V8HashConstraintError> {
    if initial_states.len() != SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT {
        return Err(SmallwoodPoseidon2V8HashConstraintError::WrongCallCount {
            expected: SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT,
            actual: initial_states.len(),
        });
    }
    for (call, state) in initial_states.iter().enumerate() {
        for (state_lane, value) in state.iter().enumerate() {
            if *value >= GOLDILOCKS_MODULUS {
                return Err(SmallwoodPoseidon2V8HashConstraintError::NonCanonicalInput {
                    call,
                    state_lane,
                });
            }
        }
    }

    let mut rows = vec![
        [0u64; SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR];
        SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT
    ];
    for (call, initial_state) in initial_states.iter().copied().enumerate() {
        write_call_rows(&mut rows, call, initial_state);
    }
    for call in
        SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT..SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT
    {
        write_call_rows(&mut rows, call, [0u64; POSEIDON2_WIDTH16_WIDTH]);
    }
    Ok(SmallwoodPoseidon2V8HashRows { rows })
}

/// Evaluate all three compressed permutation groups at one packed lane/evaluation point.
///
/// The input is one scalar per witness row, not the full row-major packed witness.  Each S-box
/// input wire is first bound to the current state plus its source-owned round constant.  The
/// state is then reconstructed from that wire before calling the canonical step function; this
/// keeps every emitted identity at degree seven instead of expanding degree across rounds.
pub fn evaluate_smallwood_poseidon2_v8_hash_constraints_ring<R: PrimeCharacteristicRing>(
    lane_rows: &[R],
    out: &mut [R],
) -> Result<(), SmallwoodPoseidon2V8HashConstraintError> {
    if lane_rows.len() != SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT {
        return Err(SmallwoodPoseidon2V8HashConstraintError::WrongLaneRowCount {
            expected: SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT,
            actual: lane_rows.len(),
        });
    }
    if out.len() != SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT {
        return Err(
            SmallwoodPoseidon2V8HashConstraintError::WrongConstraintCount {
                expected: SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT,
                actual: out.len(),
            },
        );
    }

    let mut constraint = 0;
    for group in 0..SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT {
        let mut state = core::array::from_fn(|state_lane| {
            lane_rows[smallwood_poseidon2_v8_hash_initial_row(group, state_lane)]
        });
        poseidon2_width16_step_ring(&mut state, 0);
        let mut wire = 0;

        for (round, constants) in POSEIDON2_WIDTH16_ROUND_CONSTANTS
            .external_initial
            .iter()
            .enumerate()
        {
            for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
                let round_constant = R::from_u64(constants[state_lane]);
                let actual = lane_rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, wire)];
                out[constraint] = actual - (state[state_lane] + round_constant);
                constraint += 1;
                state[state_lane] = actual - round_constant;
                wire += 1;
            }
            poseidon2_width16_step_ring(&mut state, 1 + round);
        }
        for (round, constant) in POSEIDON2_WIDTH16_ROUND_CONSTANTS
            .internal
            .iter()
            .enumerate()
        {
            let round_constant = R::from_u64(*constant);
            let actual = lane_rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, wire)];
            out[constraint] = actual - (state[0] + round_constant);
            constraint += 1;
            state[0] = actual - round_constant;
            wire += 1;
            poseidon2_width16_step_ring(&mut state, 1 + POSEIDON2_WIDTH16_EXTERNAL_ROUNDS + round);
        }
        for (round, constants) in POSEIDON2_WIDTH16_ROUND_CONSTANTS
            .external_terminal
            .iter()
            .enumerate()
        {
            for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
                let round_constant = R::from_u64(constants[state_lane]);
                let actual = lane_rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, wire)];
                out[constraint] = actual - (state[state_lane] + round_constant);
                constraint += 1;
                state[state_lane] = actual - round_constant;
                wire += 1;
            }
            poseidon2_width16_step_ring(
                &mut state,
                1 + POSEIDON2_WIDTH16_EXTERNAL_ROUNDS + POSEIDON2_WIDTH16_INTERNAL_ROUNDS + round,
            );
        }
        debug_assert_eq!(wire, SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL);

        for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
            let actual = lane_rows[smallwood_poseidon2_v8_hash_final_row(group, state_lane)];
            out[constraint] = actual - state[state_lane];
            constraint += 1;
        }
    }
    debug_assert_eq!(constraint, SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT);
    Ok(())
}

pub fn evaluate_smallwood_poseidon2_v8_hash_constraints_u64(
    lane_rows: &[u64],
    out: &mut [u64],
) -> Result<(), SmallwoodPoseidon2V8HashConstraintError> {
    if lane_rows.len() != SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT {
        return Err(SmallwoodPoseidon2V8HashConstraintError::WrongLaneRowCount {
            expected: SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT,
            actual: lane_rows.len(),
        });
    }
    if out.len() != SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT {
        return Err(
            SmallwoodPoseidon2V8HashConstraintError::WrongConstraintCount {
                expected: SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT,
                actual: out.len(),
            },
        );
    }
    for (row, value) in lane_rows.iter().enumerate() {
        if *value >= GOLDILOCKS_MODULUS {
            return Err(SmallwoodPoseidon2V8HashConstraintError::NonCanonicalRow { row, lane: 0 });
        }
    }

    let felt_rows = lane_rows
        .iter()
        .copied()
        .map(Felt::from_u64)
        .collect::<Vec<_>>();
    let mut felt_out = vec![Felt::ZERO; SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT];
    evaluate_smallwood_poseidon2_v8_hash_constraints_ring(&felt_rows, &mut felt_out)?;
    for (target, residual) in out.iter_mut().zip(felt_out) {
        *target = residual.as_canonical_u64();
    }
    Ok(())
}

/// Check the complete row-major packed witness, including mandatory zero bindings for padding.
pub fn verify_smallwood_poseidon2_v8_hash_rows(
    packed_rows: &[[u64; SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR]],
) -> Result<(), SmallwoodPoseidon2V8HashConstraintError> {
    if packed_rows.len() != SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT {
        return Err(SmallwoodPoseidon2V8HashConstraintError::WrongRowCount {
            expected: SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT,
            actual: packed_rows.len(),
        });
    }
    for (row, values) in packed_rows.iter().enumerate() {
        for (lane, value) in values.iter().enumerate() {
            if *value >= GOLDILOCKS_MODULUS {
                return Err(SmallwoodPoseidon2V8HashConstraintError::NonCanonicalRow { row, lane });
            }
        }
    }
    for call in
        SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT..SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT
    {
        let group = smallwood_poseidon2_v8_hash_call_group(call);
        let lane = smallwood_poseidon2_v8_hash_call_lane(call);
        for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
            if packed_rows[smallwood_poseidon2_v8_hash_initial_row(group, state_lane)][lane] != 0 {
                return Err(SmallwoodPoseidon2V8HashConstraintError::NonZeroDummyInput {
                    call,
                    state_lane,
                });
            }
        }
    }

    let mut lane_rows = vec![0u64; SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT];
    let mut residuals = vec![0u64; SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT];
    for lane in 0..SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR {
        for (row, value) in lane_rows.iter_mut().enumerate() {
            *value = packed_rows[row][lane];
        }
        evaluate_smallwood_poseidon2_v8_hash_constraints_u64(&lane_rows, &mut residuals)?;
        if let Some((constraint, residual)) = residuals
            .iter()
            .copied()
            .enumerate()
            .find(|(_, residual)| *residual != 0)
        {
            return Err(
                SmallwoodPoseidon2V8HashConstraintError::ConstraintViolation {
                    lane,
                    constraint,
                    residual,
                },
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use transaction_core::poseidon2_width16::{
        poseidon2_width16_permutation, POSEIDON2_WIDTH16_PARAMETER_SET_ID,
        POSEIDON2_WIDTH16_PARAMETER_SET_SHA256,
    };

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    struct LeanV8Geometry {
        width: usize,
        statement_words: usize,
        binding_limbs: usize,
        live_calls: usize,
        padded_calls: usize,
        groups: usize,
        sbox_wires_per_call: usize,
        rows_per_group: usize,
        constraints_per_group: usize,
        hash_rows: usize,
        hash_constraints: usize,
        dummy_zero_linear_constraints: usize,
        hash_row_start: usize,
        stable_row_start: usize,
        stable_rows: usize,
        relation_rows: usize,
        packing_factor: usize,
        relation_degree: usize,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    struct LeanV8CallRole {
        name: String,
        start: usize,
        end: usize,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    struct LeanV8RowIndexCase {
        call: usize,
        state_lane: usize,
        group: usize,
        lane: usize,
        initial_witness_index: usize,
        final_witness_index: usize,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    struct LeanV8MutationCase {
        name: String,
        candidate: LeanV8Geometry,
        expected_hash_kernel_geometry_valid: bool,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    struct LeanV8HashKernelVectors {
        schema: String,
        claim_scope: String,
        parameter_set_id: String,
        parameter_set_sha256: String,
        semantic_target_id: String,
        compiler_coverage: String,
        compiler_complete: bool,
        source_executable_program_refinement_available: bool,
        compiled_machine_refinement_available: bool,
        full_relation_receipt_available: bool,
        program_transcript_bytes: usize,
        program_sha512: String,
        relation_id_48: String,
        nonlinear_expression_nodes: usize,
        nonlinear_roots: usize,
        csr_expression_nodes: usize,
        csr_attempts: usize,
        packed_nonlinear_lanes: usize,
        geometry: LeanV8Geometry,
        call_roles: Vec<LeanV8CallRole>,
        row_index_cases: Vec<LeanV8RowIndexCase>,
        zero_permutation: Vec<u64>,
        sequential_permutation: Vec<u64>,
        mutation_cases: Vec<LeanV8MutationCase>,
    }

    fn lean_v8_geometry_matches_source(geometry: &LeanV8Geometry) -> bool {
        use crate::smallwood_poseidon2_v8_frontend::{
            SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS, SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS,
        };
        use crate::smallwood_poseidon2_v8_semantics::{
            SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE, SMALLWOOD_POSEIDON2_V8_HASH_ROW_START,
            SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR, SMALLWOOD_POSEIDON2_V8_ROW_COUNT,
            SMALLWOOD_POSEIDON2_V8_STABLE_ROW_COUNT, SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START,
        };

        geometry.width == POSEIDON2_WIDTH16_WIDTH
            && geometry.statement_words == SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS
            && geometry.binding_limbs == SMALLWOOD_POSEIDON2_V8_RELATION_BINDING_LIMBS
            && geometry.live_calls == SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT
            && geometry.padded_calls == SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT
            && geometry.groups == SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT
            && geometry.sbox_wires_per_call == SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL
            && geometry.rows_per_group == SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP
            && geometry.constraints_per_group == SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINTS_PER_GROUP
            && geometry.hash_rows == SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT
            && geometry.hash_constraints == SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT
            && geometry.dummy_zero_linear_constraints
                == SMALLWOOD_POSEIDON2_V8_HASH_DUMMY_ZERO_LINEAR_CONSTRAINT_COUNT
            && geometry.hash_row_start == SMALLWOOD_POSEIDON2_V8_HASH_ROW_START
            && geometry.stable_row_start == SMALLWOOD_POSEIDON2_V8_STABLE_ROW_START
            && geometry.stable_rows == SMALLWOOD_POSEIDON2_V8_STABLE_ROW_COUNT
            && geometry.relation_rows == SMALLWOOD_POSEIDON2_V8_ROW_COUNT
            && geometry.packing_factor == SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
            && geometry.relation_degree == SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE
    }

    fn initial_states() -> Vec<[u64; POSEIDON2_WIDTH16_WIDTH]> {
        (0..SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT)
            .map(|call| {
                core::array::from_fn(|lane| {
                    ((call as u128 * 0x1_0000_01b3 + lane as u128 * 0x9e37_79b9 + 17)
                        % u128::from(GOLDILOCKS_MODULUS)) as u64
                })
            })
            .collect()
    }

    #[test]
    fn exact_two_group_geometry_and_dummy_bindings() {
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT, 2);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT, 128);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_DUMMY_CALL_COUNT, 0);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL, 150);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_ROWS_PER_GROUP, 182);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT, 364);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINTS_PER_GROUP, 166);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT, 332);
        let bindings = smallwood_poseidon2_v8_hash_dummy_zero_witness_indices();
        assert!(bindings.is_empty());
    }

    #[test]
    fn materialized_rows_match_direct_width16_permutations() {
        let inputs = initial_states();
        let material = build_smallwood_poseidon2_v8_hash_rows(&inputs).unwrap();
        verify_smallwood_poseidon2_v8_hash_rows(material.as_rows()).unwrap();

        for (call, initial) in inputs.iter().copied().enumerate() {
            let mut expected = initial.map(Felt::from_u64);
            poseidon2_width16_permutation(&mut expected);
            let group = smallwood_poseidon2_v8_hash_call_group(call);
            let lane = smallwood_poseidon2_v8_hash_call_lane(call);
            for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
                assert_eq!(
                    material.rows[smallwood_poseidon2_v8_hash_final_row(group, state_lane)][lane],
                    expected[state_lane].as_canonical_u64(),
                    "call {call}, state lane {state_lane}",
                );
            }
        }
    }

    #[test]
    fn every_live_group_rejects_initial_sbox_and_final_wire_mutations() {
        let inputs = initial_states();
        let material = build_smallwood_poseidon2_v8_hash_rows(&inputs).unwrap();
        for group in 0..SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT {
            let lane = if group + 1 == SMALLWOOD_POSEIDON2_V8_HASH_GROUP_COUNT {
                (SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT - 1)
                    % SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR
            } else {
                7
            };
            for row in [
                smallwood_poseidon2_v8_hash_initial_row(group, 3),
                smallwood_poseidon2_v8_hash_sbox_wire_row(group, 0),
                smallwood_poseidon2_v8_hash_sbox_wire_row(
                    group,
                    POSEIDON2_WIDTH16_EXTERNAL_ROUNDS * POSEIDON2_WIDTH16_WIDTH + 5,
                ),
                smallwood_poseidon2_v8_hash_sbox_wire_row(
                    group,
                    SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL - 1,
                ),
                smallwood_poseidon2_v8_hash_final_row(group, 6),
            ] {
                let mut mutated = material.clone();
                mutated.rows[row][lane] = (mutated.rows[row][lane] + 1) % GOLDILOCKS_MODULUS;
                assert!(matches!(
                    verify_smallwood_poseidon2_v8_hash_rows(mutated.as_rows()),
                    Err(SmallwoodPoseidon2V8HashConstraintError::ConstraintViolation { .. })
                ));
            }
        }
    }

    #[test]
    fn every_call_lane_rejects_an_independent_trace_wire_mutation() {
        let material = build_smallwood_poseidon2_v8_hash_rows(&initial_states()).unwrap();
        let mut lane_rows = vec![0u64; SMALLWOOD_POSEIDON2_V8_HASH_ROW_COUNT];
        let mut residuals = vec![0u64; SMALLWOOD_POSEIDON2_V8_HASH_CONSTRAINT_COUNT];
        for call in 0..SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT {
            let group = smallwood_poseidon2_v8_hash_call_group(call);
            let lane = smallwood_poseidon2_v8_hash_call_lane(call);
            for (row, value) in lane_rows.iter_mut().enumerate() {
                *value = material.rows[row][lane];
            }
            let mutated_row = smallwood_poseidon2_v8_hash_sbox_wire_row(
                group,
                call % SMALLWOOD_POSEIDON2_V8_HASH_SBOX_WIRES_PER_CALL,
            );
            lane_rows[mutated_row] = (lane_rows[mutated_row] + 1) % GOLDILOCKS_MODULUS;
            evaluate_smallwood_poseidon2_v8_hash_constraints_u64(&lane_rows, &mut residuals)
                .unwrap();
            assert!(
                residuals.iter().any(|residual| *residual != 0),
                "call lane {call} accepted a mutated S-box wire",
            );
        }
    }

    #[test]
    fn reclaimed_last_lane_is_live_and_fully_constrained() {
        let material = build_smallwood_poseidon2_v8_hash_rows(&initial_states()).unwrap();
        for call in
            SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT..SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT
        {
            let group = smallwood_poseidon2_v8_hash_call_group(call);
            let lane = smallwood_poseidon2_v8_hash_call_lane(call);
            for state_lane in 0..POSEIDON2_WIDTH16_WIDTH {
                assert_eq!(
                    material.rows[smallwood_poseidon2_v8_hash_initial_row(group, state_lane)][lane],
                    0
                );
            }
        }

        let mut initial_mutation = material.clone();
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT,
            SMALLWOOD_POSEIDON2_V8_HASH_PADDED_CALL_COUNT
        );
        let call = SMALLWOOD_POSEIDON2_V8_HASH_CALL_COUNT - 1;
        let group = smallwood_poseidon2_v8_hash_call_group(call);
        let lane = smallwood_poseidon2_v8_hash_call_lane(call);
        let initial_row = smallwood_poseidon2_v8_hash_initial_row(group, 0);
        initial_mutation.rows[initial_row][lane] =
            (initial_mutation.rows[initial_row][lane] + 1) % GOLDILOCKS_MODULUS;
        assert!(matches!(
            verify_smallwood_poseidon2_v8_hash_rows(initial_mutation.as_rows()),
            Err(SmallwoodPoseidon2V8HashConstraintError::ConstraintViolation { .. })
        ));

        let mut trace_mutation = material;
        trace_mutation.rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, 17)][lane] =
            (trace_mutation.rows[smallwood_poseidon2_v8_hash_sbox_wire_row(group, 17)][lane] + 1)
                % GOLDILOCKS_MODULUS;
        assert!(matches!(
            verify_smallwood_poseidon2_v8_hash_rows(trace_mutation.as_rows()),
            Err(SmallwoodPoseidon2V8HashConstraintError::ConstraintViolation { .. })
        ));
    }

    #[test]
    fn shape_and_canonicality_fail_closed() {
        assert!(matches!(
            build_smallwood_poseidon2_v8_hash_rows(&initial_states()[..124]),
            Err(SmallwoodPoseidon2V8HashConstraintError::WrongCallCount { .. })
        ));
        let mut inputs = initial_states();
        inputs[17][4] = GOLDILOCKS_MODULUS;
        assert_eq!(
            build_smallwood_poseidon2_v8_hash_rows(&inputs),
            Err(SmallwoodPoseidon2V8HashConstraintError::NonCanonicalInput {
                call: 17,
                state_lane: 4,
            })
        );
    }

    #[test]
    fn lean_generated_v8_hash_kernel_refinement_vectors_match_source() {
        use crate::smallwood_poseidon2_v8_program::{
            SMALLWOOD_POSEIDON2_V8_CSR_EXPRESSION_NODES,
            SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS,
            SMALLWOOD_POSEIDON2_V8_NONLINEAR_EXPRESSION_NODES,
            SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST, SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512,
            SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES,
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES,
        };
        use crate::smallwood_poseidon2_v8_semantics::{
            SmallwoodPoseidon2V8ConstraintAdapter, SMALLWOOD_POSEIDON2_V8_CALL_ROLE_TABLE,
            SMALLWOOD_POSEIDON2_V8_HASH_ROW_START,
        };
        use crate::smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement;

        let vectors: LeanV8HashKernelVectors = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/formal_core_vectors/poseidon2_v8_rp04_hash_kernel_refinement.json"
        )))
        .unwrap();

        assert_eq!(
            vectors.schema,
            "hegemon.poseidon2-v8.source-executable-refinement-rp04-v1"
        );
        assert_eq!(
            vectors.claim_scope,
            "source_program_specialization_and_all_64_packed_lanes"
        );
        assert_eq!(vectors.parameter_set_id, POSEIDON2_WIDTH16_PARAMETER_SET_ID);
        assert_eq!(
            vectors.parameter_set_sha256,
            POSEIDON2_WIDTH16_PARAMETER_SET_SHA256
        );
        assert_eq!(
            vectors.semantic_target_id,
            "hegemon.smallwood.poseidon2-v8.stablecoin-relation.v3"
        );
        assert_eq!(vectors.compiler_coverage, "source_executable_program_bound");
        assert!(vectors.compiler_complete);
        assert!(vectors.source_executable_program_refinement_available);
        assert!(!vectors.compiled_machine_refinement_available);
        assert!(!vectors.full_relation_receipt_available);
        assert_eq!(
            vectors.program_transcript_bytes,
            SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES
        );
        assert_eq!(
            vectors.program_sha512,
            hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512)
        );
        assert_eq!(
            vectors.relation_id_48,
            hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST)
        );
        assert_eq!(
            vectors.nonlinear_expression_nodes,
            SMALLWOOD_POSEIDON2_V8_NONLINEAR_EXPRESSION_NODES
        );
        assert_eq!(
            vectors.nonlinear_roots,
            SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS
        );
        assert_eq!(
            vectors.csr_expression_nodes,
            SMALLWOOD_POSEIDON2_V8_CSR_EXPRESSION_NODES
        );
        assert_eq!(
            vectors.csr_attempts,
            SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES
        );
        assert_eq!(
            vectors.packed_nonlinear_lanes,
            SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR
        );
        assert!(lean_v8_geometry_matches_source(&vectors.geometry));

        assert_eq!(
            vectors.call_roles.len(),
            SMALLWOOD_POSEIDON2_V8_CALL_ROLE_TABLE.len()
        );
        for (lean, rust) in vectors
            .call_roles
            .iter()
            .zip(SMALLWOOD_POSEIDON2_V8_CALL_ROLE_TABLE)
        {
            assert_eq!(lean.name, rust.name);
            assert_eq!(lean.start, rust.start);
            assert_eq!(lean.end, rust.end);
        }

        let relation_hash_offset =
            SMALLWOOD_POSEIDON2_V8_HASH_ROW_START * SMALLWOOD_POSEIDON2_V8_HASH_PACKING_FACTOR;
        for case in vectors.row_index_cases {
            assert_eq!(
                case.group,
                smallwood_poseidon2_v8_hash_call_group(case.call)
            );
            assert_eq!(case.lane, smallwood_poseidon2_v8_hash_call_lane(case.call));
            assert_eq!(
                case.initial_witness_index,
                relation_hash_offset
                    + smallwood_poseidon2_v8_hash_call_initial_witness_index(
                        case.call,
                        case.state_lane,
                    )
            );
            assert_eq!(
                case.final_witness_index,
                relation_hash_offset
                    + smallwood_poseidon2_v8_hash_call_final_witness_index(
                        case.call,
                        case.state_lane,
                    )
            );
        }

        let mut zero = [Felt::ZERO; POSEIDON2_WIDTH16_WIDTH];
        poseidon2_width16_permutation(&mut zero);
        assert_eq!(
            vectors.zero_permutation,
            zero.map(|value| value.as_canonical_u64())
        );
        let mut sequential = core::array::from_fn(|index| Felt::from_u64(index as u64));
        poseidon2_width16_permutation(&mut sequential);
        assert_eq!(
            vectors.sequential_permutation,
            sequential.map(|value| value.as_canonical_u64())
        );

        assert_eq!(vectors.mutation_cases.len(), 18);
        for mutation in vectors.mutation_cases {
            assert!(
                !mutation.expected_hash_kernel_geometry_valid,
                "Lean unexpectedly accepted geometry mutation {}",
                mutation.name
            );
            assert!(
                !lean_v8_geometry_matches_source(&mutation.candidate),
                "Rust unexpectedly accepted geometry mutation {}",
                mutation.name
            );
        }

        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let adapter =
            SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(&statement).unwrap();
        assert!(adapter.compiler_complete());
    }
}
