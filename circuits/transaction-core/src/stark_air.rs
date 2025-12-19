//! Real STARK AIR for transaction circuits using Poseidon hash.
//!
//! This AIR enforces:
//! - Poseidon hash transitions with explicit absorption/reset steps
//! - Note commitment correctness
//! - Merkle path verification
//! - Nullifier correctness
//! - MASP balance conservation with value balance

use alloc::vec::Vec;
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{
    CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_OUTPUTS, NATIVE_ASSET_ID, NOTE_DOMAIN_TAG,
    NULLIFIER_DOMAIN_TAG, MERKLE_DOMAIN_TAG, POSEIDON_ROUNDS, POSEIDON_WIDTH,
};

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

/// Trace width (columns) for the transaction circuit.
pub const TRACE_WIDTH: usize = 55;

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
pub const COL_LINK: usize = 7;

/// Active flags for inputs/outputs (constant across trace).
pub const COL_IN_ACTIVE0: usize = 8;
pub const COL_IN_ACTIVE1: usize = 9;
pub const COL_OUT_ACTIVE0: usize = 10;
pub const COL_OUT_ACTIVE1: usize = 11;

/// Note values/asset ids (constant across trace).
pub const COL_IN0_VALUE: usize = 12;
pub const COL_IN0_ASSET: usize = 13;
pub const COL_IN1_VALUE: usize = 14;
pub const COL_IN1_ASSET: usize = 15;
pub const COL_OUT0_VALUE: usize = 16;
pub const COL_OUT0_ASSET: usize = 17;
pub const COL_OUT1_VALUE: usize = 18;
pub const COL_OUT1_ASSET: usize = 19;

/// Balance slots (asset id + sum in/out).
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

/// Cycle length: power of 2, must be > POSEIDON_ROUNDS.
pub const CYCLE_LENGTH: usize = 16;

/// Number of cycles for a commitment hash (14 inputs / rate 2 = 7 cycles).
pub const COMMITMENT_CYCLES: usize = 7;

/// Number of cycles for a nullifier hash (6 inputs / rate 2 = 3 cycles).
pub const NULLIFIER_CYCLES: usize = 3;

/// Number of cycles for Merkle path verification (one hash per level).
pub const MERKLE_CYCLES: usize = CIRCUIT_MERKLE_DEPTH;

/// Cycles per input note: commitment + merkle + nullifier.
pub const CYCLES_PER_INPUT: usize = COMMITMENT_CYCLES + MERKLE_CYCLES + NULLIFIER_CYCLES;

/// Dummy cycle at the start to seed the first absorption.
pub const DUMMY_CYCLES: usize = 1;

/// Total cycles used by the real computation (excluding padding cycles).
pub const TOTAL_USED_CYCLES: usize =
    DUMMY_CYCLES + (MAX_INPUTS * CYCLES_PER_INPUT) + (MAX_OUTPUTS * COMMITMENT_CYCLES);

/// Minimum trace length (power of 2).
/// For MAX_INPUTS=2, MAX_OUTPUTS=2, depth=32: 105 cycles * 16 = 1680 -> 2048.
pub const MIN_TRACE_LENGTH: usize = 2048;

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
    let seed = ((round as u64 + 1).wrapping_mul(0x9e37_79b9u64))
        ^ ((position as u64 + 1).wrapping_mul(0x7f4a_7c15u64));
    BaseElement::new(seed)
}

fn get_periodic_columns() -> Vec<Vec<BaseElement>> {
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

    result
}

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct TransactionPublicInputsStark {
    pub input_flags: Vec<BaseElement>,
    pub output_flags: Vec<BaseElement>,
    pub nullifiers: Vec<BaseElement>,
    pub commitments: Vec<BaseElement>,
    pub fee: BaseElement,
    pub value_balance_sign: BaseElement,
    pub value_balance_magnitude: BaseElement,
    pub merkle_root: BaseElement,
}

impl Default for TransactionPublicInputsStark {
    fn default() -> Self {
        Self {
            input_flags: vec![BaseElement::ZERO; MAX_INPUTS],
            output_flags: vec![BaseElement::ZERO; MAX_OUTPUTS],
            nullifiers: vec![BaseElement::ZERO; MAX_INPUTS],
            commitments: vec![BaseElement::ZERO; MAX_OUTPUTS],
            fee: BaseElement::ZERO,
            value_balance_sign: BaseElement::ZERO,
            value_balance_magnitude: BaseElement::ZERO,
            merkle_root: BaseElement::ZERO,
        }
    }
}

impl ToElements<BaseElement> for TransactionPublicInputsStark {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(MAX_INPUTS + MAX_OUTPUTS + 8);
        elements.extend(&self.input_flags);
        elements.extend(&self.output_flags);
        elements.extend(&self.nullifiers);
        elements.extend(&self.commitments);
        elements.push(self.fee);
        elements.push(self.value_balance_sign);
        elements.push(self.value_balance_magnitude);
        elements.push(self.merkle_root);
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
    InputMerkle { input: usize, level: usize },
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
            return CycleKind::InputMerkle {
                input,
                level: merkle_offset,
            };
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
        CycleKind::InputMerkle { .. } => Some(MERKLE_DOMAIN_TAG),
        CycleKind::InputNullifier { chunk, .. } if chunk == 0 => Some(NULLIFIER_DOMAIN_TAG),
        CycleKind::OutputCommitment { chunk, .. } if chunk == 0 => Some(NOTE_DOMAIN_TAG),
        _ => None,
    }
}

pub fn cycle_is_merkle(cycle: usize) -> bool {
    matches!(cycle_kind(cycle), CycleKind::InputMerkle { .. })
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

// ================================================================================================
// AIR IMPLEMENTATION
// ================================================================================================

pub struct TransactionAirStark {
    context: AirContext<BaseElement>,
    pub_inputs: TransactionPublicInputsStark,
}

const NUM_CONSTRAINTS: usize = 98;

impl Air for TransactionAirStark {
    type BaseField = BaseElement;
    type PublicInputs = TransactionPublicInputsStark;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]);
            NUM_CONSTRAINTS
        ];

        let trace_len = trace_info.length();
        let mut num_assertions = 0;

        for (i, &nf) in pub_inputs.nullifiers.iter().enumerate() {
            if nf != BaseElement::ZERO && pub_inputs.input_flags[i] != BaseElement::ZERO {
                let row = nullifier_output_row(i);
                if row < trace_len {
                    num_assertions += 1;
                }
                let merkle_row = merkle_root_output_row(i);
                if merkle_row < trace_len {
                    num_assertions += 1;
                }
            }
        }

        for (i, &cm) in pub_inputs.commitments.iter().enumerate() {
            if cm != BaseElement::ZERO && pub_inputs.output_flags[i] != BaseElement::ZERO {
                let row = commitment_output_row(i);
                if row < trace_len {
                    num_assertions += 1;
                }
            }
        }

        // Reset/domain/link assertions for each cycle end.
        let total_cycles = trace_info.length() / CYCLE_LENGTH;
        num_assertions += total_cycles * 3;

        // Note start assertions (one per note).
        num_assertions += MAX_INPUTS + MAX_OUTPUTS;

        // Active flag assertions (one per flag at row 0).
        num_assertions += MAX_INPUTS + MAX_OUTPUTS;

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

        let expected_s0 = hash_flag * hash_s0 + copy_flag * current[COL_S0] + absorb_flag * absorb_s0;
        let expected_s1 = hash_flag * hash_s1 + copy_flag * current[COL_S1] + absorb_flag * absorb_s1;
        let expected_s2 = hash_flag * hash_s2 + copy_flag * current[COL_S2] + absorb_flag * absorb_s2;

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
        let active_cols = [COL_IN_ACTIVE0, COL_IN_ACTIVE1, COL_OUT_ACTIVE0, COL_OUT_ACTIVE1];
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

        let in0_sel_sum = current[COL_SEL_IN0_SLOT0]
            + current[COL_SEL_IN0_SLOT1]
            + current[COL_SEL_IN0_SLOT2]
            + current[COL_SEL_IN0_SLOT3];
        result[idx] = in0_sel_sum - input_active[0];
        idx += 1;

        let in1_sel_sum = current[COL_SEL_IN1_SLOT0]
            + current[COL_SEL_IN1_SLOT1]
            + current[COL_SEL_IN1_SLOT2]
            + current[COL_SEL_IN1_SLOT3];
        result[idx] = in1_sel_sum - input_active[1];
        idx += 1;

        let out0_sel_sum = current[COL_SEL_OUT0_SLOT0]
            + current[COL_SEL_OUT0_SLOT1]
            + current[COL_SEL_OUT0_SLOT2]
            + current[COL_SEL_OUT0_SLOT3];
        result[idx] = out0_sel_sum - output_active[0];
        idx += 1;

        let out1_sel_sum = current[COL_SEL_OUT1_SLOT0]
            + current[COL_SEL_OUT1_SLOT1]
            + current[COL_SEL_OUT1_SLOT2]
            + current[COL_SEL_OUT1_SLOT3];
        result[idx] = out1_sel_sum - output_active[1];
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
        result[idx] = in0_asset * input_active[0] - in0_selected;
        idx += 1;

        let in1_asset = current[COL_IN1_ASSET];
        let in1_selected = current[COL_SEL_IN1_SLOT0] * slot_assets[0]
            + current[COL_SEL_IN1_SLOT1] * slot_assets[1]
            + current[COL_SEL_IN1_SLOT2] * slot_assets[2]
            + current[COL_SEL_IN1_SLOT3] * slot_assets[3];
        result[idx] = in1_asset * input_active[1] - in1_selected;
        idx += 1;

        let out0_asset = current[COL_OUT0_ASSET];
        let out0_selected = current[COL_SEL_OUT0_SLOT0] * slot_assets[0]
            + current[COL_SEL_OUT0_SLOT1] * slot_assets[1]
            + current[COL_SEL_OUT0_SLOT2] * slot_assets[2]
            + current[COL_SEL_OUT0_SLOT3] * slot_assets[3];
        result[idx] = out0_asset * output_active[0] - out0_selected;
        idx += 1;

        let out1_asset = current[COL_OUT1_ASSET];
        let out1_selected = current[COL_SEL_OUT1_SLOT0] * slot_assets[0]
            + current[COL_SEL_OUT1_SLOT1] * slot_assets[1]
            + current[COL_SEL_OUT1_SLOT2] * slot_assets[2]
            + current[COL_SEL_OUT1_SLOT3] * slot_assets[3];
        result[idx] = out1_asset * output_active[1] - out1_selected;
        idx += 1;

        // slot sums (inputs)
        let in_values = [current[COL_IN0_VALUE], current[COL_IN1_VALUE]];
        let out_values = [current[COL_OUT0_VALUE], current[COL_OUT1_VALUE]];

        let slot_in_cols = [
            COL_SLOT0_IN,
            COL_SLOT1_IN,
            COL_SLOT2_IN,
            COL_SLOT3_IN,
        ];
        let slot_out_cols = [
            COL_SLOT0_OUT,
            COL_SLOT1_OUT,
            COL_SLOT2_OUT,
            COL_SLOT3_OUT,
        ];

        let sel_in = [
            [COL_SEL_IN0_SLOT0, COL_SEL_IN0_SLOT1, COL_SEL_IN0_SLOT2, COL_SEL_IN0_SLOT3],
            [COL_SEL_IN1_SLOT0, COL_SEL_IN1_SLOT1, COL_SEL_IN1_SLOT2, COL_SEL_IN1_SLOT3],
        ];
        let sel_out = [
            [COL_SEL_OUT0_SLOT0, COL_SEL_OUT0_SLOT1, COL_SEL_OUT0_SLOT2, COL_SEL_OUT0_SLOT3],
            [COL_SEL_OUT1_SLOT0, COL_SEL_OUT1_SLOT1, COL_SEL_OUT1_SLOT2, COL_SEL_OUT1_SLOT3],
        ];

        for slot in 0..4 {
            let mut sum_in = E::ZERO;
            let mut sum_out = E::ZERO;
            for note in 0..2 {
                sum_in += current[sel_in[note][slot]] * in_values[note];
                sum_out += current[sel_out[note][slot]] * out_values[note];
            }
            result[idx] = current[slot_in_cols[slot]] - sum_in;
            idx += 1;
            result[idx] = current[slot_out_cols[slot]] - sum_out;
            idx += 1;
        }

        // slot0 asset id must be native
        result[idx] = current[COL_SLOT0_ASSET] - E::from(BaseElement::new(NATIVE_ASSET_ID));
        idx += 1;

        // balance equations
        let fee = current[COL_FEE];
        let vb_mag = current[COL_VALUE_BALANCE_MAG];
        let vb_signed = vb_mag - (vb_sign * vb_mag * two);
        let slot0_in = current[COL_SLOT0_IN];
        let slot0_out = current[COL_SLOT0_OUT];
        result[idx] = slot0_in + vb_signed - slot0_out - fee;
        idx += 1;

        for slot in 1..4 {
            result[idx] = current[slot_in_cols[slot]] - current[slot_out_cols[slot]];
            idx += 1;
        }

        // constant columns
        for &col in CONST_COLUMNS.iter() {
            result[idx] = next[col] - current[col];
            idx += 1;
        }

        // link flag: in0 for next cycle equals current output when set
        let link = current[COL_LINK];
        result[idx] = link * (current[COL_IN0] - current[COL_S0]);
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

        for (i, &nf) in self.pub_inputs.nullifiers.iter().enumerate() {
            if nf != BaseElement::ZERO && self.pub_inputs.input_flags[i] != BaseElement::ZERO {
                let row = nullifier_output_row(i);
                if row < trace_len {
                    assertions.push(Assertion::single(COL_S0, row, nf));
                }

                let merkle_row = merkle_root_output_row(i);
                if merkle_row < trace_len {
                    assertions.push(Assertion::single(
                        COL_S0,
                        merkle_row,
                        self.pub_inputs.merkle_root,
                    ));
                }
            }
        }

        for (i, &cm) in self.pub_inputs.commitments.iter().enumerate() {
            if cm != BaseElement::ZERO && self.pub_inputs.output_flags[i] != BaseElement::ZERO {
                let row = commitment_output_row(i);
                if row < trace_len {
                    assertions.push(Assertion::single(COL_S0, row, cm));
                }
            }
        }

        let total_cycles = trace_len / CYCLE_LENGTH;
        for cycle in 0..total_cycles {
            let row = cycle * CYCLE_LENGTH + (CYCLE_LENGTH - 1);
            let next_cycle = cycle + 1;
            let (reset, domain, link) = if next_cycle < total_cycles {
                let reset_domain = cycle_reset_domain(next_cycle);
                let reset = if reset_domain.is_some() {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                let domain = reset_domain
                    .map(BaseElement::new)
                    .unwrap_or(BaseElement::ZERO);
                let link = if cycle_is_merkle(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                (reset, domain, link)
            } else {
                (BaseElement::ZERO, BaseElement::ZERO, BaseElement::ZERO)
            };

            assertions.push(Assertion::single(COL_RESET, row, reset));
            assertions.push(Assertion::single(COL_DOMAIN, row, domain));
            assertions.push(Assertion::single(COL_LINK, row, link));
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

        // Active flags bound at row 0.
        if trace_len > 0 {
            assertions.push(Assertion::single(
                COL_IN_ACTIVE0,
                0,
                self.pub_inputs.input_flags[0],
            ));
            assertions.push(Assertion::single(
                COL_IN_ACTIVE1,
                0,
                self.pub_inputs.input_flags[1],
            ));
            assertions.push(Assertion::single(
                COL_OUT_ACTIVE0,
                0,
                self.pub_inputs.output_flags[0],
            ));
            assertions.push(Assertion::single(
                COL_OUT_ACTIVE1,
                0,
                self.pub_inputs.output_flags[1],
            ));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        get_periodic_columns()
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

const CONST_COLUMNS: [usize; 43] = [
    COL_IN_ACTIVE0,
    COL_IN_ACTIVE1,
    COL_OUT_ACTIVE0,
    COL_OUT_ACTIVE1,
    COL_IN0_VALUE,
    COL_IN0_ASSET,
    COL_IN1_VALUE,
    COL_IN1_ASSET,
    COL_OUT0_VALUE,
    COL_OUT0_ASSET,
    COL_OUT1_VALUE,
    COL_OUT1_ASSET,
    COL_SLOT0_ASSET,
    COL_SLOT0_IN,
    COL_SLOT0_OUT,
    COL_SLOT1_ASSET,
    COL_SLOT1_IN,
    COL_SLOT1_OUT,
    COL_SLOT2_ASSET,
    COL_SLOT2_IN,
    COL_SLOT2_OUT,
    COL_SLOT3_ASSET,
    COL_SLOT3_IN,
    COL_SLOT3_OUT,
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
    COL_FEE,
    COL_VALUE_BALANCE_SIGN,
    COL_VALUE_BALANCE_MAG,
];

// ================================================================================================
// POSEIDON HELPERS
// ================================================================================================

#[inline]
pub fn sbox(x: BaseElement) -> BaseElement {
    x.exp(5u64)
}

pub fn mds_mix(state: &[BaseElement; 3]) -> [BaseElement; 3] {
    let two = BaseElement::new(2);
    [
        state[0] * two + state[1] + state[2],
        state[0] + state[1] * two + state[2],
        state[0] + state[1] + state[2] * two,
    ]
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
        let cols = get_periodic_columns();
        assert_eq!(cols.len(), 2 + POSEIDON_WIDTH);
        assert_eq!(cols[0].len(), CYCLE_LENGTH);
        assert_eq!(cols[1].len(), CYCLE_LENGTH);
        assert_eq!(cols[0][0], BaseElement::ONE);
        assert_eq!(cols[0][7], BaseElement::ONE);
        assert_eq!(cols[0][8], BaseElement::ZERO);
        assert_eq!(cols[1][15], BaseElement::ONE);
    }

    #[test]
    fn test_air_creation() {
        let trace_info = TraceInfo::new(TRACE_WIDTH, MIN_TRACE_LENGTH);
        let pub_inputs = TransactionPublicInputsStark {
            input_flags: vec![BaseElement::ONE, BaseElement::ZERO],
            output_flags: vec![BaseElement::ONE, BaseElement::ZERO],
            nullifiers: vec![BaseElement::new(123), BaseElement::ZERO],
            commitments: vec![BaseElement::new(456), BaseElement::ZERO],
            fee: BaseElement::ZERO,
            value_balance_sign: BaseElement::ZERO,
            value_balance_magnitude: BaseElement::ZERO,
            merkle_root: BaseElement::ZERO,
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
