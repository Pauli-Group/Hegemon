//! Real STARK AIR for transaction circuits using Poseidon hash.
//!
//! This AIR enforces:
//! - Poseidon hash transitions with explicit absorption/reset steps
//! - Note commitment correctness
//! - Merkle path verification
//! - Nullifier correctness
//! - MASP balance conservation with value balance

use alloc::vec;
use alloc::vec::Vec;
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{
    CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_OUTPUTS, MERKLE_DOMAIN_TAG, NATIVE_ASSET_ID,
    NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG, POSEIDON_ROUNDS, POSEIDON_WIDTH,
};
use crate::poseidon_constants;

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

/// Trace width (columns) for the transaction circuit.
pub const TRACE_WIDTH: usize = 65;

/// Poseidon state columns.
pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;

/// Absorbed input pair for the *next* cycle (written at cycle end).
pub const COL_IN0: usize = 3;
pub const COL_IN1: usize = 4;

/// Cycle control flags for the *next* cycle (written at cycle end).
pub const COL_RESET: usize = 5;
pub const COL_DOMAIN: usize = 6;
pub const COL_MERKLE_LEFT_23: usize = 7;

/// Active flags for inputs/outputs (set at note start rows).
pub const COL_IN_ACTIVE0: usize = 8;
pub const COL_IN_ACTIVE1: usize = 9;
pub const COL_OUT_ACTIVE0: usize = 10;
pub const COL_OUT_ACTIVE1: usize = 11;

/// Note values/asset ids (set at note start rows).
pub const COL_IN0_VALUE: usize = 12;
pub const COL_IN0_ASSET: usize = 13;
pub const COL_IN1_VALUE: usize = 14;
pub const COL_IN1_ASSET: usize = 15;
pub const COL_OUT0_VALUE: usize = 16;
pub const COL_OUT0_ASSET: usize = 17;
pub const COL_OUT1_VALUE: usize = 18;
pub const COL_OUT1_ASSET: usize = 19;

/// Balance slots (asset id + running sum in/out).
pub const COL_SLOT0_ASSET: usize = 20;
pub const COL_SLOT0_IN: usize = 21;
pub const COL_SLOT0_OUT: usize = 22;
pub const COL_SLOT1_ASSET: usize = 23;
pub const COL_SLOT1_IN: usize = 24;
pub const COL_SLOT1_OUT: usize = 25;
pub const COL_SLOT2_ASSET: usize = 26;
pub const COL_SLOT2_IN: usize = 27;
pub const COL_SLOT2_OUT: usize = 28;
pub const COL_SLOT3_ASSET: usize = 29;
pub const COL_SLOT3_IN: usize = 30;
pub const COL_SLOT3_OUT: usize = 31;

/// Selector flags: input note 0.
pub const COL_SEL_IN0_SLOT0: usize = 32;
pub const COL_SEL_IN0_SLOT1: usize = 33;
pub const COL_SEL_IN0_SLOT2: usize = 34;
pub const COL_SEL_IN0_SLOT3: usize = 35;

/// Selector flags: input note 1.
pub const COL_SEL_IN1_SLOT0: usize = 36;
pub const COL_SEL_IN1_SLOT1: usize = 37;
pub const COL_SEL_IN1_SLOT2: usize = 38;
pub const COL_SEL_IN1_SLOT3: usize = 39;

/// Selector flags: output note 0.
pub const COL_SEL_OUT0_SLOT0: usize = 40;
pub const COL_SEL_OUT0_SLOT1: usize = 41;
pub const COL_SEL_OUT0_SLOT2: usize = 42;
pub const COL_SEL_OUT0_SLOT3: usize = 43;

/// Selector flags: output note 1.
pub const COL_SEL_OUT1_SLOT0: usize = 44;
pub const COL_SEL_OUT1_SLOT1: usize = 45;
pub const COL_SEL_OUT1_SLOT2: usize = 46;
pub const COL_SEL_OUT1_SLOT3: usize = 47;

/// Fee and value balance (sign + magnitude).
pub const COL_FEE: usize = 48;
pub const COL_VALUE_BALANCE_SIGN: usize = 49;
pub const COL_VALUE_BALANCE_MAG: usize = 50;

/// Note start flags (mark commitment absorption for each note).
pub const COL_NOTE_START_IN0: usize = 51;
pub const COL_NOTE_START_IN1: usize = 52;
pub const COL_NOTE_START_OUT0: usize = 53;
pub const COL_NOTE_START_OUT1: usize = 54;

/// Captured hash limbs (first two limbs) carried across squeeze cycles.
pub const COL_OUT0: usize = 55;
pub const COL_OUT1: usize = 56;

/// Merkle pair flag for left limbs 0/1 (set on the second pair).
pub const COL_MERKLE_LEFT_01: usize = 57;

/// Capture flag to latch out0/out1 from the Poseidon state at cycle boundaries.
pub const COL_CAPTURE: usize = 58;

/// Merkle pair flag for right limbs 2/3 (third pair).
pub const COL_MERKLE_RIGHT_23: usize = 59;

/// Merkle pair flag for right limbs 0/1 (fourth pair).
pub const COL_MERKLE_RIGHT_01: usize = 60;

/// Capture flag to latch out2/out3 (squeeze output) at cycle boundaries.
pub const COL_CAPTURE2: usize = 61;

/// Captured hash limbs (second two limbs) carried across cycles.
pub const COL_OUT2: usize = 62;
pub const COL_OUT3: usize = 63;

/// Direction bit for Merkle path (0 = current is left, 1 = current is right).
pub const COL_DIR: usize = 64;

/// Cycle length: power of 2, must be > POSEIDON_ROUNDS.
pub const CYCLE_LENGTH: usize = 64;

/// Number of absorb cycles for a commitment hash (14 inputs / rate 2 = 7 cycles).
pub const COMMITMENT_ABSORB_CYCLES: usize = 7;

/// One squeeze cycle to output the final two limbs.
pub const COMMITMENT_SQUEEZE_CYCLES: usize = 1;

/// Total cycles for a commitment hash (absorb + squeeze).
pub const COMMITMENT_CYCLES: usize = COMMITMENT_ABSORB_CYCLES + COMMITMENT_SQUEEZE_CYCLES;

/// Number of absorb cycles for a nullifier hash (6 inputs / rate 2 = 3 cycles).
pub const NULLIFIER_ABSORB_CYCLES: usize = 3;

/// One squeeze cycle to output the final two limbs.
pub const NULLIFIER_SQUEEZE_CYCLES: usize = 1;

/// Total cycles for a nullifier hash (absorb + squeeze).
pub const NULLIFIER_CYCLES: usize = NULLIFIER_ABSORB_CYCLES + NULLIFIER_SQUEEZE_CYCLES;

/// Number of absorb cycles per Merkle level (8 inputs / rate 2 = 4 cycles).
pub const MERKLE_ABSORB_CYCLES: usize = 4;

/// One squeeze cycle to output the final two limbs.
pub const MERKLE_SQUEEZE_CYCLES: usize = 1;

/// Total cycles per Merkle level.
pub const MERKLE_CYCLES_PER_LEVEL: usize = MERKLE_ABSORB_CYCLES + MERKLE_SQUEEZE_CYCLES;

/// Number of cycles for Merkle path verification (hash per level).
pub const MERKLE_CYCLES: usize = CIRCUIT_MERKLE_DEPTH * MERKLE_CYCLES_PER_LEVEL;

/// Cycles per input note: commitment + merkle + nullifier.
pub const CYCLES_PER_INPUT: usize = COMMITMENT_CYCLES + MERKLE_CYCLES + NULLIFIER_CYCLES;

/// Dummy cycle at the start to seed the first absorption.
pub const DUMMY_CYCLES: usize = 1;

/// Total cycles used by the real computation (excluding padding cycles).
pub const TOTAL_USED_CYCLES: usize =
    DUMMY_CYCLES + (MAX_INPUTS * CYCLES_PER_INPUT) + (MAX_OUTPUTS * COMMITMENT_CYCLES);

/// Minimum trace length (power of 2).
/// For MAX_INPUTS=2, MAX_OUTPUTS=2, depth=32: 361 cycles * 64 = 23104 -> 32768.
pub const MIN_TRACE_LENGTH: usize = 32768;

/// Total cycles in the trace (including padding cycles).
pub const TOTAL_TRACE_CYCLES: usize = MIN_TRACE_LENGTH / CYCLE_LENGTH;

// ================================================================================================
// PERIODIC COLUMNS
// ================================================================================================

const fn make_hash_mask() -> [BaseElement; CYCLE_LENGTH] {
    let mut mask = [BaseElement::new(0); CYCLE_LENGTH];
    let mut i = 0;
    while i < POSEIDON_ROUNDS {
        mask[i] = BaseElement::new(1);
        i += 1;
    }
    mask
}

const fn make_absorb_mask() -> [BaseElement; CYCLE_LENGTH] {
    let mut mask = [BaseElement::new(0); CYCLE_LENGTH];
    mask[CYCLE_LENGTH - 1] = BaseElement::new(1);
    mask
}

const HASH_MASK: [BaseElement; CYCLE_LENGTH] = make_hash_mask();
const ABSORB_MASK: [BaseElement; CYCLE_LENGTH] = make_absorb_mask();

#[inline]
pub fn round_constant(round: usize, position: usize) -> BaseElement {
    BaseElement::new(poseidon_constants::ROUND_CONSTANTS[round][position])
}

fn get_periodic_columns(trace_len: usize) -> Vec<Vec<BaseElement>> {
    let mut result = vec![HASH_MASK.to_vec(), ABSORB_MASK.to_vec()];

    for pos in 0..POSEIDON_WIDTH {
        let mut column = Vec::with_capacity(CYCLE_LENGTH);
        for step in 0..CYCLE_LENGTH {
            if step < POSEIDON_ROUNDS {
                column.push(round_constant(step, pos));
            } else {
                column.push(BaseElement::ZERO);
            }
        }
        result.push(column);
    }

    let mut first_row = vec![BaseElement::ZERO; trace_len];
    if !first_row.is_empty() {
        first_row[0] = BaseElement::ONE;
    }
    let mut final_row = vec![BaseElement::ZERO; trace_len];
    if trace_len >= 2 {
        final_row[trace_len - 2] = BaseElement::ONE;
    }
    result.push(first_row);
    result.push(final_row);

    result
}

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct TransactionPublicInputsStark {
    pub input_flags: Vec<BaseElement>,
    pub output_flags: Vec<BaseElement>,
    pub nullifiers: Vec<[BaseElement; 4]>,
    pub commitments: Vec<[BaseElement; 4]>,
    pub fee: BaseElement,
    pub value_balance_sign: BaseElement,
    pub value_balance_magnitude: BaseElement,
    pub merkle_root: [BaseElement; 4],
}

impl Default for TransactionPublicInputsStark {
    fn default() -> Self {
        let zero = [BaseElement::ZERO; 4];
        Self {
            input_flags: vec![BaseElement::ZERO; MAX_INPUTS],
            output_flags: vec![BaseElement::ZERO; MAX_OUTPUTS],
            nullifiers: vec![zero; MAX_INPUTS],
            commitments: vec![zero; MAX_OUTPUTS],
            fee: BaseElement::ZERO,
            value_balance_sign: BaseElement::ZERO,
            value_balance_magnitude: BaseElement::ZERO,
            merkle_root: zero,
        }
    }
}

impl ToElements<BaseElement> for TransactionPublicInputsStark {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity((MAX_INPUTS + MAX_OUTPUTS) * 5 + 7);
        elements.extend(&self.input_flags);
        elements.extend(&self.output_flags);
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        for cm in &self.commitments {
            elements.extend_from_slice(cm);
        }
        elements.push(self.fee);
        elements.push(self.value_balance_sign);
        elements.push(self.value_balance_magnitude);
        elements.extend_from_slice(&self.merkle_root);
        elements
    }
}

// ================================================================================================
// CYCLE LAYOUT HELPERS
// ================================================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CycleKind {
    Dummy,
    InputCommitment { input: usize, chunk: usize },
    InputMerkle { input: usize, level: usize, chunk: usize },
    InputNullifier { input: usize, chunk: usize },
    OutputCommitment { output: usize, chunk: usize },
    Padding,
}

fn cycle_kind(cycle: usize) -> CycleKind {
    if cycle == 0 {
        return CycleKind::Dummy;
    }

    if cycle < DUMMY_CYCLES + MAX_INPUTS * CYCLES_PER_INPUT {
        let rel = cycle - DUMMY_CYCLES;
        let input = rel / CYCLES_PER_INPUT;
        let offset = rel % CYCLES_PER_INPUT;
        if offset < COMMITMENT_CYCLES {
            return CycleKind::InputCommitment {
                input,
                chunk: offset,
            };
        }
        let merkle_offset = offset - COMMITMENT_CYCLES;
        if merkle_offset < MERKLE_CYCLES {
            let level = merkle_offset / MERKLE_CYCLES_PER_LEVEL;
            let chunk = merkle_offset % MERKLE_CYCLES_PER_LEVEL;
            return CycleKind::InputMerkle { input, level, chunk };
        }
        return CycleKind::InputNullifier {
            input,
            chunk: merkle_offset - MERKLE_CYCLES,
        };
    }

    let output_start = DUMMY_CYCLES + MAX_INPUTS * CYCLES_PER_INPUT;
    let output_end = output_start + MAX_OUTPUTS * COMMITMENT_CYCLES;
    if cycle < output_end {
        let rel = cycle - output_start;
        let output = rel / COMMITMENT_CYCLES;
        let chunk = rel % COMMITMENT_CYCLES;
        return CycleKind::OutputCommitment { output, chunk };
    }

    CycleKind::Padding
}

pub fn cycle_reset_domain(cycle: usize) -> Option<u64> {
    match cycle_kind(cycle) {
        CycleKind::InputCommitment { chunk, .. } if chunk == 0 => Some(NOTE_DOMAIN_TAG),
        CycleKind::InputMerkle { chunk, .. } if chunk == 0 => Some(MERKLE_DOMAIN_TAG),
        CycleKind::InputNullifier { chunk, .. } if chunk == 0 => Some(NULLIFIER_DOMAIN_TAG),
        CycleKind::OutputCommitment { chunk, .. } if chunk == 0 => Some(NOTE_DOMAIN_TAG),
        _ => None,
    }
}

pub fn cycle_is_merkle_pair(cycle: usize, pair: usize) -> bool {
    matches!(cycle_kind(cycle), CycleKind::InputMerkle { chunk, .. } if chunk == pair)
}

pub fn cycle_is_merkle_left_23(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 0)
}

pub fn cycle_is_merkle_left_01(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 1)
}

pub fn cycle_is_merkle_right_23(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 2)
}

pub fn cycle_is_merkle_right_01(cycle: usize) -> bool {
    cycle_is_merkle_pair(cycle, 3)
}

pub fn cycle_is_squeeze(cycle: usize) -> bool {
    match cycle_kind(cycle) {
        CycleKind::InputCommitment { chunk, .. } => chunk >= COMMITMENT_ABSORB_CYCLES,
        CycleKind::InputNullifier { chunk, .. } => chunk >= NULLIFIER_ABSORB_CYCLES,
        CycleKind::OutputCommitment { chunk, .. } => chunk >= COMMITMENT_ABSORB_CYCLES,
        CycleKind::InputMerkle { chunk, .. } => chunk >= MERKLE_ABSORB_CYCLES,
        _ => false,
    }
}

pub fn input_commitment_start_cycle(input_index: usize) -> usize {
    DUMMY_CYCLES + input_index * CYCLES_PER_INPUT
}

pub fn input_merkle_start_cycle(input_index: usize) -> usize {
    input_commitment_start_cycle(input_index) + COMMITMENT_CYCLES
}

pub fn input_nullifier_start_cycle(input_index: usize) -> usize {
    input_merkle_start_cycle(input_index) + MERKLE_CYCLES
}

pub fn output_commitment_start_cycle(output_index: usize) -> usize {
    DUMMY_CYCLES + MAX_INPUTS * CYCLES_PER_INPUT + output_index * COMMITMENT_CYCLES
}

pub fn nullifier_output_row(input_index: usize) -> usize {
    (input_nullifier_start_cycle(input_index) + NULLIFIER_CYCLES) * CYCLE_LENGTH - 1
}

pub fn merkle_root_output_row(input_index: usize) -> usize {
    (input_merkle_start_cycle(input_index) + MERKLE_CYCLES) * CYCLE_LENGTH - 1
}

pub fn commitment_output_row(output_index: usize) -> usize {
    (output_commitment_start_cycle(output_index) + COMMITMENT_CYCLES) * CYCLE_LENGTH - 1
}

pub fn note_start_row_input(input_index: usize) -> usize {
    (input_commitment_start_cycle(input_index) - 1) * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

pub fn note_start_row_output(output_index: usize) -> usize {
    (output_commitment_start_cycle(output_index) - 1) * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

fn is_zero_hash(value: &[BaseElement; 4]) -> bool {
    value.iter().all(|elem| *elem == BaseElement::ZERO)
}

// ================================================================================================
// AIR IMPLEMENTATION
// ================================================================================================

pub struct TransactionAirStark {
    context: AirContext<BaseElement>,
    pub_inputs: TransactionPublicInputsStark,
}

const NUM_CONSTRAINTS: usize = 72;

impl Air for TransactionAirStark {
    type BaseField = BaseElement;
    type PublicInputs = TransactionPublicInputsStark;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let trace_len = trace_info.length();
        let mut degrees = Vec::with_capacity(NUM_CONSTRAINTS);
        // Poseidon transitions use periodic hash/absorb flags and round constants.
        for _ in 0..3 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                5,
                vec![CYCLE_LENGTH],
            ));
        }
        degrees.push(TransitionConstraintDegree::new(2)); // reset boolean
        degrees.push(TransitionConstraintDegree::new(2)); // value balance sign boolean

        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(2)); // active flag booleans
        }
        for _ in 0..16 {
            degrees.push(TransitionConstraintDegree::new(2)); // selector booleans
        }
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(2)); // selector sums
        }
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(3)); // asset matches
        }
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::with_cycles(3, vec![trace_len]));
            // slot accumulators
        }
        degrees.push(TransitionConstraintDegree::new(2)); // slot0 asset check
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![trace_len])); // balance equation
        for _ in 0..3 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![trace_len]));
            // slot1..3 balance
        }
        degrees.push(TransitionConstraintDegree::new(2)); // merkle direction boolean
        degrees.push(TransitionConstraintDegree::new(2)); // merkle direction carry
        for _ in 0..8 {
            degrees.push(TransitionConstraintDegree::new(3)); // merkle link constraints
        }
        degrees.push(TransitionConstraintDegree::new(2)); // capture0 boolean
        degrees.push(TransitionConstraintDegree::new(2)); // capture0 only on absorb row
        degrees.push(TransitionConstraintDegree::new(2)); // out0 carry/update
        degrees.push(TransitionConstraintDegree::new(2)); // out1 carry/update
        degrees.push(TransitionConstraintDegree::new(2)); // capture2 boolean
        degrees.push(TransitionConstraintDegree::new(2)); // capture2 only on absorb row
        degrees.push(TransitionConstraintDegree::new(2)); // out2 carry/update
        degrees.push(TransitionConstraintDegree::new(2)); // out3 carry/update
        for _ in 0..(MAX_INPUTS + MAX_OUTPUTS) {
            degrees.push(TransitionConstraintDegree::new(2)); // note start value binding
            degrees.push(TransitionConstraintDegree::new(2)); // note start asset binding
        }
        debug_assert_eq!(degrees.len(), NUM_CONSTRAINTS);

        let mut num_assertions = 0;

        for (i, nf) in pub_inputs.nullifiers.iter().enumerate() {
            if !is_zero_hash(nf) && pub_inputs.input_flags[i] != BaseElement::ZERO {
                let row = nullifier_output_row(i);
                if row < trace_len {
                    num_assertions += 4;
                }
                let merkle_row = merkle_root_output_row(i);
                if merkle_row < trace_len {
                    num_assertions += 4;
                }
            }
        }

        for (i, cm) in pub_inputs.commitments.iter().enumerate() {
            if !is_zero_hash(cm) && pub_inputs.output_flags[i] != BaseElement::ZERO {
                let row = commitment_output_row(i);
                if row < trace_len {
                    num_assertions += 4;
                }
            }
        }

        // Reset/domain/merkle-pair/capture assertions for each cycle end.
        let total_cycles = trace_info.length() / CYCLE_LENGTH;
        num_assertions += total_cycles * 8;

        // Note start assertions (one per note).
        num_assertions += MAX_INPUTS + MAX_OUTPUTS;

        // Active flag assertions (one per flag at note start).
        num_assertions += MAX_INPUTS + MAX_OUTPUTS;

        // Fee/value balance assertions at the final enforcement row.
        num_assertions += 3;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let hash_flag = periodic_values[0];
        let absorb_flag = periodic_values[1];
        let rc0 = periodic_values[2];
        let rc1 = periodic_values[3];
        let rc2 = periodic_values[4];
        let mask_offset = 2 + POSEIDON_WIDTH;
        let first_row_mask = periodic_values[mask_offset];
        let final_row_mask = periodic_values[mask_offset + 1];

        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        let two: E = E::from(BaseElement::new(2));
        let hash_s0 = s0 * two + s1 + s2;
        let hash_s1 = s0 + s1 * two + s2;
        let hash_s2 = s0 + s1 + s2 * two;

        let one = E::ONE;
        let not_first_row = one - first_row_mask;
        let copy_flag = one - hash_flag - absorb_flag;

        let reset = current[COL_RESET];
        let domain = current[COL_DOMAIN];
        let in0 = current[COL_IN0];
        let in1 = current[COL_IN1];

        let start_s0 = domain + in0;
        let start_s1 = in1;
        let start_s2 = one;

        let cont_s0 = current[COL_S0] + in0;
        let cont_s1 = current[COL_S1] + in1;
        let cont_s2 = current[COL_S2];

        let absorb_s0 = reset * start_s0 + (one - reset) * cont_s0;
        let absorb_s1 = reset * start_s1 + (one - reset) * cont_s1;
        let absorb_s2 = reset * start_s2 + (one - reset) * cont_s2;

        let expected_s0 =
            hash_flag * hash_s0 + copy_flag * current[COL_S0] + absorb_flag * absorb_s0;
        let expected_s1 =
            hash_flag * hash_s1 + copy_flag * current[COL_S1] + absorb_flag * absorb_s1;
        let expected_s2 =
            hash_flag * hash_s2 + copy_flag * current[COL_S2] + absorb_flag * absorb_s2;

        let mut idx = 0;
        result[idx] = next[COL_S0] - expected_s0;
        idx += 1;
        result[idx] = next[COL_S1] - expected_s1;
        idx += 1;
        result[idx] = next[COL_S2] - expected_s2;
        idx += 1;

        // reset flag is boolean
        result[idx] = reset * (reset - one);
        idx += 1;

        // value_balance sign is boolean
        let vb_sign = current[COL_VALUE_BALANCE_SIGN];
        result[idx] = vb_sign * (vb_sign - one);
        idx += 1;

        // active flags are boolean
        let active_cols = [
            COL_IN_ACTIVE0,
            COL_IN_ACTIVE1,
            COL_OUT_ACTIVE0,
            COL_OUT_ACTIVE1,
        ];
        for &col in active_cols.iter() {
            let flag = current[col];
            result[idx] = flag * (flag - one);
            idx += 1;
        }

        // selector booleans
        for &sel_col in SELECTOR_COLUMNS.iter() {
            let sel = current[sel_col];
            result[idx] = sel * (sel - one);
            idx += 1;
        }

        // selector sums equal active flags
        let input_active = [current[COL_IN_ACTIVE0], current[COL_IN_ACTIVE1]];
        let output_active = [current[COL_OUT_ACTIVE0], current[COL_OUT_ACTIVE1]];
        let note_start_in0 = current[COL_NOTE_START_IN0];
        let note_start_in1 = current[COL_NOTE_START_IN1];
        let note_start_out0 = current[COL_NOTE_START_OUT0];
        let note_start_out1 = current[COL_NOTE_START_OUT1];

        let in0_sel_sum = current[COL_SEL_IN0_SLOT0]
            + current[COL_SEL_IN0_SLOT1]
            + current[COL_SEL_IN0_SLOT2]
            + current[COL_SEL_IN0_SLOT3];
        result[idx] = note_start_in0 * (in0_sel_sum - input_active[0]);
        idx += 1;

        let in1_sel_sum = current[COL_SEL_IN1_SLOT0]
            + current[COL_SEL_IN1_SLOT1]
            + current[COL_SEL_IN1_SLOT2]
            + current[COL_SEL_IN1_SLOT3];
        result[idx] = note_start_in1 * (in1_sel_sum - input_active[1]);
        idx += 1;

        let out0_sel_sum = current[COL_SEL_OUT0_SLOT0]
            + current[COL_SEL_OUT0_SLOT1]
            + current[COL_SEL_OUT0_SLOT2]
            + current[COL_SEL_OUT0_SLOT3];
        result[idx] = note_start_out0 * (out0_sel_sum - output_active[0]);
        idx += 1;

        let out1_sel_sum = current[COL_SEL_OUT1_SLOT0]
            + current[COL_SEL_OUT1_SLOT1]
            + current[COL_SEL_OUT1_SLOT2]
            + current[COL_SEL_OUT1_SLOT3];
        result[idx] = note_start_out1 * (out1_sel_sum - output_active[1]);
        idx += 1;

        // asset id matches selected slot
        let slot_assets = [
            current[COL_SLOT0_ASSET],
            current[COL_SLOT1_ASSET],
            current[COL_SLOT2_ASSET],
            current[COL_SLOT3_ASSET],
        ];

        let in0_asset = current[COL_IN0_ASSET];
        let in0_selected = current[COL_SEL_IN0_SLOT0] * slot_assets[0]
            + current[COL_SEL_IN0_SLOT1] * slot_assets[1]
            + current[COL_SEL_IN0_SLOT2] * slot_assets[2]
            + current[COL_SEL_IN0_SLOT3] * slot_assets[3];
        result[idx] = note_start_in0 * (in0_asset * input_active[0] - in0_selected);
        idx += 1;

        let in1_asset = current[COL_IN1_ASSET];
        let in1_selected = current[COL_SEL_IN1_SLOT0] * slot_assets[0]
            + current[COL_SEL_IN1_SLOT1] * slot_assets[1]
            + current[COL_SEL_IN1_SLOT2] * slot_assets[2]
            + current[COL_SEL_IN1_SLOT3] * slot_assets[3];
        result[idx] = note_start_in1 * (in1_asset * input_active[1] - in1_selected);
        idx += 1;

        let out0_asset = current[COL_OUT0_ASSET];
        let out0_selected = current[COL_SEL_OUT0_SLOT0] * slot_assets[0]
            + current[COL_SEL_OUT0_SLOT1] * slot_assets[1]
            + current[COL_SEL_OUT0_SLOT2] * slot_assets[2]
            + current[COL_SEL_OUT0_SLOT3] * slot_assets[3];
        result[idx] = note_start_out0 * (out0_asset * output_active[0] - out0_selected);
        idx += 1;

        let out1_asset = current[COL_OUT1_ASSET];
        let out1_selected = current[COL_SEL_OUT1_SLOT0] * slot_assets[0]
            + current[COL_SEL_OUT1_SLOT1] * slot_assets[1]
            + current[COL_SEL_OUT1_SLOT2] * slot_assets[2]
            + current[COL_SEL_OUT1_SLOT3] * slot_assets[3];
        result[idx] = note_start_out1 * (out1_asset * output_active[1] - out1_selected);
        idx += 1;

        // slot accumulators (inputs/outputs)
        let in_values = [current[COL_IN0_VALUE], current[COL_IN1_VALUE]];
        let out_values = [current[COL_OUT0_VALUE], current[COL_OUT1_VALUE]];

        let slot_in_cols = [COL_SLOT0_IN, COL_SLOT1_IN, COL_SLOT2_IN, COL_SLOT3_IN];
        let slot_out_cols = [COL_SLOT0_OUT, COL_SLOT1_OUT, COL_SLOT2_OUT, COL_SLOT3_OUT];

        let sel_in = [
            [
                COL_SEL_IN0_SLOT0,
                COL_SEL_IN0_SLOT1,
                COL_SEL_IN0_SLOT2,
                COL_SEL_IN0_SLOT3,
            ],
            [
                COL_SEL_IN1_SLOT0,
                COL_SEL_IN1_SLOT1,
                COL_SEL_IN1_SLOT2,
                COL_SEL_IN1_SLOT3,
            ],
        ];
        let sel_out = [
            [
                COL_SEL_OUT0_SLOT0,
                COL_SEL_OUT0_SLOT1,
                COL_SEL_OUT0_SLOT2,
                COL_SEL_OUT0_SLOT3,
            ],
            [
                COL_SEL_OUT1_SLOT0,
                COL_SEL_OUT1_SLOT1,
                COL_SEL_OUT1_SLOT2,
                COL_SEL_OUT1_SLOT3,
            ],
        ];
        let note_in_flags = [note_start_in0, note_start_in1];
        let note_out_flags = [note_start_out0, note_start_out1];

        for slot in 0..4 {
            let mut add_in = E::ZERO;
            let mut add_out = E::ZERO;
            for note in 0..2 {
                add_in += note_in_flags[note] * current[sel_in[note][slot]] * in_values[note];
                add_out += note_out_flags[note] * current[sel_out[note][slot]] * out_values[note];
            }
            result[idx] =
                not_first_row * (next[slot_in_cols[slot]] - (current[slot_in_cols[slot]] + add_in));
            idx += 1;
            result[idx] = not_first_row
                * (next[slot_out_cols[slot]] - (current[slot_out_cols[slot]] + add_out));
            idx += 1;
        }

        // slot0 asset id must be native (checked at note start rows)
        let note_start_any = note_start_in0 + note_start_in1 + note_start_out0 + note_start_out1;
        result[idx] = note_start_any
            * (current[COL_SLOT0_ASSET] - E::from(BaseElement::new(NATIVE_ASSET_ID)));
        idx += 1;

        // balance equations (checked at final enforcement row)
        let fee = current[COL_FEE];
        let vb_mag = current[COL_VALUE_BALANCE_MAG];
        let vb_signed = vb_mag - (vb_sign * vb_mag * two);
        let slot0_in = current[COL_SLOT0_IN];
        let slot0_out = current[COL_SLOT0_OUT];
        result[idx] = final_row_mask * (slot0_in + vb_signed - slot0_out - fee);
        idx += 1;

        for slot in 1..4 {
            result[idx] =
                final_row_mask * (current[slot_in_cols[slot]] - current[slot_out_cols[slot]]);
            idx += 1;
        }

        // merkle direction must be boolean and stable between resets
        let dir = current[COL_DIR];
        result[idx] = dir * (dir - one);
        idx += 1;
        result[idx] = (one - reset) * (next[COL_DIR] - current[COL_DIR]);
        idx += 1;

        // merkle link constraints (applied at cycle boundaries)
        let left_23 = current[COL_MERKLE_LEFT_23];
        let left_01 = current[COL_MERKLE_LEFT_01];
        let right_23 = current[COL_MERKLE_RIGHT_23];
        let right_01 = current[COL_MERKLE_RIGHT_01];
        let not_dir = one - dir;

        result[idx] =
            absorb_flag * left_23 * not_dir * (current[COL_IN0] - current[COL_OUT2]);
        idx += 1;
        result[idx] =
            absorb_flag * left_23 * not_dir * (current[COL_IN1] - current[COL_OUT3]);
        idx += 1;
        result[idx] =
            absorb_flag * left_01 * not_dir * (current[COL_IN0] - current[COL_OUT0]);
        idx += 1;
        result[idx] =
            absorb_flag * left_01 * not_dir * (current[COL_IN1] - current[COL_OUT1]);
        idx += 1;
        result[idx] = absorb_flag * right_23 * dir * (current[COL_IN0] - current[COL_OUT2]);
        idx += 1;
        result[idx] = absorb_flag * right_23 * dir * (current[COL_IN1] - current[COL_OUT3]);
        idx += 1;
        result[idx] = absorb_flag * right_01 * dir * (current[COL_IN0] - current[COL_OUT0]);
        idx += 1;
        result[idx] = absorb_flag * right_01 * dir * (current[COL_IN1] - current[COL_OUT1]);
        idx += 1;

        // capture0 flag must be boolean
        let capture = current[COL_CAPTURE];
        result[idx] = capture * (capture - one);
        idx += 1;
        // capture0 only on absorb rows
        result[idx] = capture * (one - absorb_flag);
        idx += 1;
        // carry/update captured outputs
        result[idx] = next[COL_OUT0]
            - (capture * current[COL_S0] + (one - capture) * current[COL_OUT0]);
        idx += 1;
        result[idx] = next[COL_OUT1]
            - (capture * current[COL_S1] + (one - capture) * current[COL_OUT1]);
        idx += 1;

        // capture2 flag must be boolean
        let capture2 = current[COL_CAPTURE2];
        result[idx] = capture2 * (capture2 - one);
        idx += 1;
        // capture2 only on absorb rows
        result[idx] = capture2 * (one - absorb_flag);
        idx += 1;
        // carry/update captured outputs
        result[idx] = next[COL_OUT2]
            - (capture2 * current[COL_S0] + (one - capture2) * current[COL_OUT2]);
        idx += 1;
        result[idx] = next[COL_OUT3]
            - (capture2 * current[COL_S1] + (one - capture2) * current[COL_OUT3]);
        idx += 1;

        // note start flags: tie commitment inputs to note values/assets
        let note_flags = [
            (COL_NOTE_START_IN0, COL_IN0_VALUE, COL_IN0_ASSET),
            (COL_NOTE_START_IN1, COL_IN1_VALUE, COL_IN1_ASSET),
            (COL_NOTE_START_OUT0, COL_OUT0_VALUE, COL_OUT0_ASSET),
            (COL_NOTE_START_OUT1, COL_OUT1_VALUE, COL_OUT1_ASSET),
        ];

        for (flag_col, value_col, asset_col) in note_flags {
            let flag = current[flag_col];
            result[idx] = flag * (current[COL_IN0] - current[value_col]);
            idx += 1;
            result[idx] = flag * (current[COL_IN1] - current[asset_col]);
            idx += 1;
        }

        debug_assert_eq!(idx, NUM_CONSTRAINTS);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();
        let trace_len = self.context.trace_len();

        for (i, nf) in self.pub_inputs.nullifiers.iter().enumerate() {
            if !is_zero_hash(nf) && self.pub_inputs.input_flags[i] != BaseElement::ZERO {
                let row = nullifier_output_row(i);
                if row < trace_len {
                    assertions.push(Assertion::single(COL_OUT0, row, nf[0]));
                    assertions.push(Assertion::single(COL_OUT1, row, nf[1]));
                    assertions.push(Assertion::single(COL_S0, row, nf[2]));
                    assertions.push(Assertion::single(COL_S1, row, nf[3]));
                }

                let merkle_row = merkle_root_output_row(i);
                if merkle_row < trace_len {
                    assertions.push(Assertion::single(
                        COL_OUT0,
                        merkle_row,
                        self.pub_inputs.merkle_root[0],
                    ));
                    assertions.push(Assertion::single(
                        COL_OUT1,
                        merkle_row,
                        self.pub_inputs.merkle_root[1],
                    ));
                    assertions.push(Assertion::single(
                        COL_S0,
                        merkle_row,
                        self.pub_inputs.merkle_root[2],
                    ));
                    assertions.push(Assertion::single(
                        COL_S1,
                        merkle_row,
                        self.pub_inputs.merkle_root[3],
                    ));
                }
            }
        }

        for (i, cm) in self.pub_inputs.commitments.iter().enumerate() {
            if !is_zero_hash(cm) && self.pub_inputs.output_flags[i] != BaseElement::ZERO {
                let row = commitment_output_row(i);
                if row < trace_len {
                    assertions.push(Assertion::single(COL_OUT0, row, cm[0]));
                    assertions.push(Assertion::single(COL_OUT1, row, cm[1]));
                    assertions.push(Assertion::single(COL_S0, row, cm[2]));
                    assertions.push(Assertion::single(COL_S1, row, cm[3]));
                }
            }
        }

        let total_cycles = trace_len / CYCLE_LENGTH;
        for cycle in 0..total_cycles {
            let row = cycle * CYCLE_LENGTH + (CYCLE_LENGTH - 1);
            let next_cycle = cycle + 1;
            let (reset, domain, left_23, left_01, right_23, right_01) = if next_cycle < total_cycles
            {
                let reset_domain = cycle_reset_domain(next_cycle);
                let reset = if reset_domain.is_some() {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                let domain = reset_domain
                    .map(BaseElement::new)
                    .unwrap_or(BaseElement::ZERO);
                let left_23 = if cycle_is_merkle_left_23(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                let left_01 = if cycle_is_merkle_left_01(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                let right_23 = if cycle_is_merkle_right_23(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                let right_01 = if cycle_is_merkle_right_01(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                (reset, domain, left_23, left_01, right_23, right_01)
            } else {
                (
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                    BaseElement::ZERO,
                )
            };

            let capture = if cycle_is_squeeze(next_cycle) {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };
            let capture2 = if cycle_is_squeeze(cycle) {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };

            assertions.push(Assertion::single(COL_RESET, row, reset));
            assertions.push(Assertion::single(COL_DOMAIN, row, domain));
            assertions.push(Assertion::single(COL_MERKLE_LEFT_23, row, left_23));
            assertions.push(Assertion::single(COL_MERKLE_LEFT_01, row, left_01));
            assertions.push(Assertion::single(COL_MERKLE_RIGHT_23, row, right_23));
            assertions.push(Assertion::single(COL_MERKLE_RIGHT_01, row, right_01));
            assertions.push(Assertion::single(COL_CAPTURE, row, capture));
            assertions.push(Assertion::single(COL_CAPTURE2, row, capture2));
        }

        // Note start flags: one assertion per note.
        for input in 0..MAX_INPUTS {
            let row = note_start_row_input(input);
            if row < trace_len {
                let col = if input == 0 {
                    COL_NOTE_START_IN0
                } else {
                    COL_NOTE_START_IN1
                };
                assertions.push(Assertion::single(col, row, BaseElement::ONE));
            }
        }

        for output in 0..MAX_OUTPUTS {
            let row = note_start_row_output(output);
            if row < trace_len {
                let col = if output == 0 {
                    COL_NOTE_START_OUT0
                } else {
                    COL_NOTE_START_OUT1
                };
                assertions.push(Assertion::single(col, row, BaseElement::ONE));
            }
        }

        // Active flags bound at note start rows.
        let input_rows = [note_start_row_input(0), note_start_row_input(1)];
        let input_cols = [COL_IN_ACTIVE0, COL_IN_ACTIVE1];
        for (idx, &row) in input_rows.iter().enumerate() {
            if row < trace_len {
                assertions.push(Assertion::single(
                    input_cols[idx],
                    row,
                    self.pub_inputs.input_flags[idx],
                ));
            }
        }

        let output_rows = [note_start_row_output(0), note_start_row_output(1)];
        let output_cols = [COL_OUT_ACTIVE0, COL_OUT_ACTIVE1];
        for (idx, &row) in output_rows.iter().enumerate() {
            if row < trace_len {
                assertions.push(Assertion::single(
                    output_cols[idx],
                    row,
                    self.pub_inputs.output_flags[idx],
                ));
            }
        }

        // Fee/value balance bound at the final enforcement row.
        if trace_len >= 2 {
            let final_row = trace_len - 2;
            assertions.push(Assertion::single(COL_FEE, final_row, self.pub_inputs.fee));
            assertions.push(Assertion::single(
                COL_VALUE_BALANCE_SIGN,
                final_row,
                self.pub_inputs.value_balance_sign,
            ));
            assertions.push(Assertion::single(
                COL_VALUE_BALANCE_MAG,
                final_row,
                self.pub_inputs.value_balance_magnitude,
            ));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        get_periodic_columns(self.context.trace_len())
    }
}

const SELECTOR_COLUMNS: [usize; 16] = [
    COL_SEL_IN0_SLOT0,
    COL_SEL_IN0_SLOT1,
    COL_SEL_IN0_SLOT2,
    COL_SEL_IN0_SLOT3,
    COL_SEL_IN1_SLOT0,
    COL_SEL_IN1_SLOT1,
    COL_SEL_IN1_SLOT2,
    COL_SEL_IN1_SLOT3,
    COL_SEL_OUT0_SLOT0,
    COL_SEL_OUT0_SLOT1,
    COL_SEL_OUT0_SLOT2,
    COL_SEL_OUT0_SLOT3,
    COL_SEL_OUT1_SLOT0,
    COL_SEL_OUT1_SLOT1,
    COL_SEL_OUT1_SLOT2,
    COL_SEL_OUT1_SLOT3,
];

// ================================================================================================
// POSEIDON HELPERS
// ================================================================================================

#[inline]
pub fn sbox(x: BaseElement) -> BaseElement {
    x.exp(5u64)
}

pub fn mds_mix(state: &[BaseElement; 3]) -> [BaseElement; 3] {
    let mut out = [BaseElement::ZERO; 3];
    for (row_idx, out_slot) in out.iter_mut().enumerate() {
        let mut acc = BaseElement::ZERO;
        for (col_idx, value) in state.iter().enumerate() {
            let coeff = BaseElement::new(poseidon_constants::MDS_MATRIX[row_idx][col_idx]);
            acc += *value * coeff;
        }
        *out_slot = acc;
    }
    out
}

pub fn poseidon_round(state: &mut [BaseElement; 3], round: usize) {
    state[0] += round_constant(round, 0);
    state[1] += round_constant(round, 1);
    state[2] += round_constant(round, 2);
    state[0] = sbox(state[0]);
    state[1] = sbox(state[1]);
    state[2] = sbox(state[2]);
    *state = mds_mix(state);
}

pub fn poseidon_permutation(state: &mut [BaseElement; 3]) {
    for round in 0..POSEIDON_ROUNDS {
        poseidon_round(state, round);
    }
}

pub fn poseidon_hash(domain_tag: u64, inputs: &[BaseElement]) -> BaseElement {
    let mut state = [
        BaseElement::new(domain_tag),
        BaseElement::ZERO,
        BaseElement::ONE,
    ];
    let rate = POSEIDON_WIDTH - 1;
    let mut cursor = 0;
    while cursor < inputs.len() {
        let take = core::cmp::min(rate, inputs.len() - cursor);
        for i in 0..take {
            state[i] += inputs[cursor + i];
        }
        poseidon_permutation(&mut state);
        cursor += take;
    }
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::FieldExtension;

    #[test]
    fn test_periodic_columns() {
        let cols = get_periodic_columns(MIN_TRACE_LENGTH);
        assert_eq!(cols.len(), 4 + POSEIDON_WIDTH);
        assert_eq!(cols[0].len(), CYCLE_LENGTH);
        assert_eq!(cols[1].len(), CYCLE_LENGTH);
        assert_eq!(cols[0][0], BaseElement::ONE);
        assert_eq!(cols[0][POSEIDON_ROUNDS - 1], BaseElement::ONE);
        assert_eq!(cols[0][POSEIDON_ROUNDS], BaseElement::ZERO);
        assert_eq!(cols[1][CYCLE_LENGTH - 1], BaseElement::ONE);
        let mask_offset = 2 + POSEIDON_WIDTH;
        assert_eq!(cols[mask_offset].len(), MIN_TRACE_LENGTH);
        assert_eq!(cols[mask_offset][0], BaseElement::ONE);
        assert_eq!(cols[mask_offset][1], BaseElement::ZERO);
        assert_eq!(cols[mask_offset + 1].len(), MIN_TRACE_LENGTH);
        assert_eq!(
            cols[mask_offset + 1][MIN_TRACE_LENGTH - 2],
            BaseElement::ONE
        );
    }

    #[test]
    fn test_air_creation() {
        let trace_info = TraceInfo::new(TRACE_WIDTH, MIN_TRACE_LENGTH);
        let zero = [BaseElement::ZERO; 4];
        let pub_inputs = TransactionPublicInputsStark {
            input_flags: vec![BaseElement::ONE, BaseElement::ZERO],
            output_flags: vec![BaseElement::ONE, BaseElement::ZERO],
            nullifiers: vec![
                [BaseElement::new(123), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                zero,
            ],
            commitments: vec![
                [BaseElement::new(456), BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO],
                zero,
            ],
            fee: BaseElement::ZERO,
            value_balance_sign: BaseElement::ZERO,
            value_balance_magnitude: BaseElement::ZERO,
            merkle_root: zero,
        };
        let options = ProofOptions::new(
            32,
            8,
            0,
            FieldExtension::None,
            4,
            31,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );

        let air = TransactionAirStark::new(trace_info, pub_inputs, options);
        assert_eq!(air.context().trace_info().width(), TRACE_WIDTH);
    }
}
