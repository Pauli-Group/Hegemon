//! Plonky3 AIR for settlement commitments.

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::constants::{
    ABSORB_CYCLES, INPUT_CYCLES_PER_TRACE, MAX_INSTRUCTIONS, MAX_NULLIFIERS, PADDED_INPUT_COUNT,
    SETTLEMENT_DOMAIN_TAG, TRACE_LENGTH,
};
use transaction_core::constants::{
    POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS, POSEIDON2_STEPS, POSEIDON2_WIDTH,
};
use transaction_core::poseidon2_constants;
use transaction_core::p3_air::CYCLE_LENGTH;

pub type Felt = Goldilocks;
pub type HashFelt = [Felt; 6];

pub const COL_S0: usize = transaction_core::p3_air::COL_S0;
pub const COL_S1: usize = transaction_core::p3_air::COL_S1;
pub const COL_S2: usize = transaction_core::p3_air::COL_S2;
pub const COL_S3: usize = transaction_core::p3_air::COL_S3;
pub const COL_S4: usize = transaction_core::p3_air::COL_S4;
pub const COL_S5: usize = transaction_core::p3_air::COL_S5;
pub const COL_S6: usize = transaction_core::p3_air::COL_S6;
pub const COL_S7: usize = transaction_core::p3_air::COL_S7;
pub const COL_S8: usize = transaction_core::p3_air::COL_S8;
pub const COL_S9: usize = transaction_core::p3_air::COL_S9;
pub const COL_S10: usize = transaction_core::p3_air::COL_S10;
pub const COL_S11: usize = transaction_core::p3_air::COL_S11;
pub const COL_IN0: usize = transaction_core::p3_air::COL_IN0;
pub const COL_IN1: usize = transaction_core::p3_air::COL_IN1;
pub const COL_IN2: usize = transaction_core::p3_air::COL_IN2;
pub const COL_IN3: usize = transaction_core::p3_air::COL_IN3;
pub const COL_IN4: usize = transaction_core::p3_air::COL_IN4;
pub const COL_IN5: usize = transaction_core::p3_air::COL_IN5;
pub const TRACE_WIDTH: usize = COL_IN5 + 1;

// ================================================================================================
// PREPROCESSED COLUMNS (fixed schedule)
// ================================================================================================

/// Poseidon hash flag for each row (1 during rounds).
pub const PREP_HASH_FLAG: usize = 0;
/// Poseidon2 absorb flag for each row (1 on the absorb step).
pub const PREP_ABSORB_FLAG: usize = PREP_HASH_FLAG + 1;
/// Poseidon2 round-kind selectors.
pub const PREP_INIT_ROUND: usize = PREP_ABSORB_FLAG + 1;
pub const PREP_EXTERNAL_ROUND: usize = PREP_INIT_ROUND + 1;
pub const PREP_INTERNAL_ROUND: usize = PREP_EXTERNAL_ROUND + 1;
/// Poseidon2 round constants (per row).
pub const PREP_RC0: usize = PREP_INTERNAL_ROUND + 1;
pub const PREP_RC1: usize = PREP_RC0 + 1;
pub const PREP_RC2: usize = PREP_RC1 + 1;
pub const PREP_RC3: usize = PREP_RC2 + 1;
pub const PREP_RC4: usize = PREP_RC3 + 1;
pub const PREP_RC5: usize = PREP_RC4 + 1;
pub const PREP_RC6: usize = PREP_RC5 + 1;
pub const PREP_RC7: usize = PREP_RC6 + 1;
pub const PREP_RC8: usize = PREP_RC7 + 1;
pub const PREP_RC9: usize = PREP_RC8 + 1;
pub const PREP_RC10: usize = PREP_RC9 + 1;
pub const PREP_RC11: usize = PREP_RC10 + 1;
/// One-hot selectors for cycle start rows.
pub const PREP_CYCLE_START_BASE: usize = PREP_RC11 + 1;
/// One-hot selector for commitment output row.
pub const PREP_COMMIT_ROW: usize = PREP_CYCLE_START_BASE + INPUT_CYCLES_PER_TRACE;
/// Preprocessed trace width.
pub const PREPROCESSED_WIDTH: usize = PREP_COMMIT_ROW + 1;

pub fn commitment_row() -> usize {
    (INPUT_CYCLES_PER_TRACE - 1) * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

#[derive(Clone, Debug)]
pub struct SettlementPublicInputsP3 {
    pub instruction_count: u32,
    pub nullifier_count: u32,
    pub instructions: Vec<Felt>,
    pub nullifiers: Vec<HashFelt>,
    pub commitment: HashFelt,
}

impl SettlementPublicInputsP3 {
    pub fn validate(&self) -> Result<(), String> {
        if self.instructions.len() != MAX_INSTRUCTIONS {
            return Err("instructions length mismatch".into());
        }
        if self.nullifiers.len() != MAX_NULLIFIERS {
            return Err("nullifiers length mismatch".into());
        }
        if self.instruction_count as usize > MAX_INSTRUCTIONS {
            return Err("instruction_count exceeds maximum".into());
        }
        if self.nullifier_count as usize > MAX_NULLIFIERS {
            return Err("nullifier_count exceeds maximum".into());
        }
        Ok(())
    }

    pub fn input_elements(&self) -> Vec<Felt> {
        let mut inputs = Vec::with_capacity(PADDED_INPUT_COUNT);
        inputs.push(Felt::from_u64(self.instruction_count as u64));
        inputs.push(Felt::from_u64(self.nullifier_count as u64));
        inputs.extend(self.instructions.iter().copied());
        for nf in &self.nullifiers {
            inputs.extend_from_slice(nf);
        }
        while inputs.len() < PADDED_INPUT_COUNT {
            inputs.push(Felt::ZERO);
        }
        inputs
    }

    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements =
            Vec::with_capacity(2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * 6) + 6);
        elements.push(Felt::from_u64(self.instruction_count as u64));
        elements.push(Felt::from_u64(self.nullifier_count as u64));
        elements.extend(self.instructions.iter().copied());
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        elements.extend_from_slice(&self.commitment);
        elements
    }

    pub fn try_from_slice(elements: &[Felt]) -> Result<Self, String> {
        let expected_len = 2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * 6) + 6;
        if elements.len() != expected_len {
            return Err(format!(
                "settlement public inputs length mismatch: expected {expected_len}, got {}",
                elements.len()
            ));
        }

        let mut idx = 0usize;
        let instruction_count = elements[idx].as_canonical_u64() as u32;
        idx += 1;
        let nullifier_count = elements[idx].as_canonical_u64() as u32;
        idx += 1;
        let instructions = elements[idx..idx + MAX_INSTRUCTIONS].to_vec();
        idx += MAX_INSTRUCTIONS;
        let mut nullifiers = Vec::with_capacity(MAX_NULLIFIERS);
        for _ in 0..MAX_NULLIFIERS {
            let slice = &elements[idx..idx + 6];
            idx += 6;
            nullifiers.push([slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]]);
        }
        let commitment = {
            let slice = &elements[idx..idx + 6];
            [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]]
        };

        Ok(Self {
            instruction_count,
            nullifier_count,
            instructions,
            nullifiers,
            commitment,
        })
    }
}

impl Default for SettlementPublicInputsP3 {
    fn default() -> Self {
        Self {
            instruction_count: 0,
            nullifier_count: 0,
            instructions: vec![Felt::ZERO; MAX_INSTRUCTIONS],
            nullifiers: vec![[Felt::ZERO; 6]; MAX_NULLIFIERS],
            commitment: [Felt::ZERO; 6],
        }
    }
}

fn prep_cycle_start_col(cycle: usize) -> usize {
    PREP_CYCLE_START_BASE + cycle
}

fn build_preprocessed_trace() -> RowMajorMatrix<Felt> {
    let mut values = vec![Felt::ZERO; TRACE_LENGTH * PREPROCESSED_WIDTH];

    for row in 0..TRACE_LENGTH {
        let step = row % CYCLE_LENGTH;
        let cycle = row / CYCLE_LENGTH;
        let row_slice =
            &mut values[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];

        row_slice[PREP_HASH_FLAG] = Felt::from_bool(step < POSEIDON2_STEPS);
        row_slice[PREP_ABSORB_FLAG] = Felt::from_bool(step == CYCLE_LENGTH - 1);
        if step < POSEIDON2_STEPS {
            if step == 0 {
                row_slice[PREP_INIT_ROUND] = Felt::ONE;
            } else if step <= POSEIDON2_EXTERNAL_ROUNDS {
                let idx = step - 1;
                row_slice[PREP_EXTERNAL_ROUND] = Felt::ONE;
                let rc = &poseidon2_constants::EXTERNAL_ROUND_CONSTANTS[0][idx];
                row_slice[PREP_RC0] = Felt::from_u64(rc[0]);
                row_slice[PREP_RC1] = Felt::from_u64(rc[1]);
                row_slice[PREP_RC2] = Felt::from_u64(rc[2]);
                row_slice[PREP_RC3] = Felt::from_u64(rc[3]);
                row_slice[PREP_RC4] = Felt::from_u64(rc[4]);
                row_slice[PREP_RC5] = Felt::from_u64(rc[5]);
                row_slice[PREP_RC6] = Felt::from_u64(rc[6]);
                row_slice[PREP_RC7] = Felt::from_u64(rc[7]);
                row_slice[PREP_RC8] = Felt::from_u64(rc[8]);
                row_slice[PREP_RC9] = Felt::from_u64(rc[9]);
                row_slice[PREP_RC10] = Felt::from_u64(rc[10]);
                row_slice[PREP_RC11] = Felt::from_u64(rc[11]);
            } else if step <= POSEIDON2_EXTERNAL_ROUNDS + POSEIDON2_INTERNAL_ROUNDS {
                let idx = step - 1 - POSEIDON2_EXTERNAL_ROUNDS;
                row_slice[PREP_INTERNAL_ROUND] = Felt::ONE;
                row_slice[PREP_RC0] =
                    Felt::from_u64(poseidon2_constants::INTERNAL_ROUND_CONSTANTS[idx]);
            } else {
                let idx = step - 1 - POSEIDON2_EXTERNAL_ROUNDS - POSEIDON2_INTERNAL_ROUNDS;
                row_slice[PREP_EXTERNAL_ROUND] = Felt::ONE;
                let rc = &poseidon2_constants::EXTERNAL_ROUND_CONSTANTS[1][idx];
                row_slice[PREP_RC0] = Felt::from_u64(rc[0]);
                row_slice[PREP_RC1] = Felt::from_u64(rc[1]);
                row_slice[PREP_RC2] = Felt::from_u64(rc[2]);
                row_slice[PREP_RC3] = Felt::from_u64(rc[3]);
                row_slice[PREP_RC4] = Felt::from_u64(rc[4]);
                row_slice[PREP_RC5] = Felt::from_u64(rc[5]);
                row_slice[PREP_RC6] = Felt::from_u64(rc[6]);
                row_slice[PREP_RC7] = Felt::from_u64(rc[7]);
                row_slice[PREP_RC8] = Felt::from_u64(rc[8]);
                row_slice[PREP_RC9] = Felt::from_u64(rc[9]);
                row_slice[PREP_RC10] = Felt::from_u64(rc[10]);
                row_slice[PREP_RC11] = Felt::from_u64(rc[11]);
            }
        }

        if step == 0 && cycle < INPUT_CYCLES_PER_TRACE {
            row_slice[prep_cycle_start_col(cycle)] = Felt::ONE;
        }

        if row == commitment_row() {
            row_slice[PREP_COMMIT_ROW] = Felt::ONE;
        }
    }

    RowMajorMatrix::new(values, PREPROCESSED_WIDTH)
}

pub struct SettlementAirP3;

impl BaseAir<Felt> for SettlementAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(build_preprocessed_trace())
    }
}

impl<AB> Air<AB> for SettlementAirP3
where
    AB: AirBuilderWithPublicValues<F = Felt> + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();
        let current = main.row_slice(0).expect("trace must have >= 1 row");
        let next = main.row_slice(1).expect("trace must have >= 2 rows");
        let prep_row = preprocessed
            .row_slice(0)
            .expect("preprocessed trace must have >= 1 row");

        let one = AB::Expr::ONE;

        let hash_flag: AB::Expr = prep_row[PREP_HASH_FLAG].clone().into();
        let absorb_flag: AB::Expr = prep_row[PREP_ABSORB_FLAG].clone().into();
        let init_round: AB::Expr = prep_row[PREP_INIT_ROUND].clone().into();
        let external_round: AB::Expr = prep_row[PREP_EXTERNAL_ROUND].clone().into();
        let internal_round: AB::Expr = prep_row[PREP_INTERNAL_ROUND].clone().into();
        let rc0: AB::Expr = prep_row[PREP_RC0].clone().into();
        let rc1: AB::Expr = prep_row[PREP_RC1].clone().into();
        let rc2: AB::Expr = prep_row[PREP_RC2].clone().into();
        let rc3: AB::Expr = prep_row[PREP_RC3].clone().into();
        let rc4: AB::Expr = prep_row[PREP_RC4].clone().into();
        let rc5: AB::Expr = prep_row[PREP_RC5].clone().into();
        let rc6: AB::Expr = prep_row[PREP_RC6].clone().into();
        let rc7: AB::Expr = prep_row[PREP_RC7].clone().into();
        let rc8: AB::Expr = prep_row[PREP_RC8].clone().into();
        let rc9: AB::Expr = prep_row[PREP_RC9].clone().into();
        let rc10: AB::Expr = prep_row[PREP_RC10].clone().into();
        let rc11: AB::Expr = prep_row[PREP_RC11].clone().into();

        let sbox = |value: AB::Expr| -> AB::Expr {
            let v2 = value.clone() * value.clone();
            let v4 = v2.clone() * v2.clone();
            let v6 = v4.clone() * v2;
            v6 * value
        };

        let current_state = [
            current[COL_S0].clone().into(),
            current[COL_S1].clone().into(),
            current[COL_S2].clone().into(),
            current[COL_S3].clone().into(),
            current[COL_S4].clone().into(),
            current[COL_S5].clone().into(),
            current[COL_S6].clone().into(),
            current[COL_S7].clone().into(),
            current[COL_S8].clone().into(),
            current[COL_S9].clone().into(),
            current[COL_S10].clone().into(),
            current[COL_S11].clone().into(),
        ];

        let mds_light = |state: &mut [AB::Expr; POSEIDON2_WIDTH]| {
            for chunk in state.chunks_exact_mut(4) {
                let x0 = chunk[0].clone();
                let x1 = chunk[1].clone();
                let x2 = chunk[2].clone();
                let x3 = chunk[3].clone();

                let t01 = x0.clone() + x1.clone();
                let t23 = x2.clone() + x3.clone();
                let t0123 = t01.clone() + t23.clone();
                let t01123 = t0123.clone() + x1.clone();
                let t01233 = t0123 + x3.clone();

                chunk[3] = t01233.clone() + x0.clone() + x0;
                chunk[1] = t01123.clone() + x2.clone() + x2;
                chunk[0] = t01123 + t01;
                chunk[2] = t01233 + t23;
            }

            let mut sums: [AB::Expr; 4] = core::array::from_fn(|_| AB::Expr::ZERO);
            for k in 0..4 {
                let mut acc = AB::Expr::ZERO;
                let mut idx = k;
                while idx < POSEIDON2_WIDTH {
                    acc += state[idx].clone();
                    idx += 4;
                }
                sums[k] = acc;
            }

            for (idx, elem) in state.iter_mut().enumerate() {
                *elem = elem.clone() + sums[idx % 4].clone();
            }
        };

        let matmul_internal = |state: &mut [AB::Expr; POSEIDON2_WIDTH]| {
            let mut sum = AB::Expr::ZERO;
            for elem in state.iter() {
                sum += elem.clone();
            }
            for (idx, elem) in state.iter_mut().enumerate() {
                let diag = AB::Expr::from_u64(poseidon2_constants::INTERNAL_MATRIX_DIAG[idx]);
                *elem = elem.clone() * diag + sum.clone();
            }
        };

        let mut init_state = current_state.clone();
        mds_light(&mut init_state);

        let mut external_state = core::array::from_fn(|idx| {
            let rc = match idx {
                0 => rc0.clone(),
                1 => rc1.clone(),
                2 => rc2.clone(),
                3 => rc3.clone(),
                4 => rc4.clone(),
                5 => rc5.clone(),
                6 => rc6.clone(),
                7 => rc7.clone(),
                8 => rc8.clone(),
                9 => rc9.clone(),
                10 => rc10.clone(),
                _ => rc11.clone(),
            };
            sbox(current_state[idx].clone() + rc)
        });
        mds_light(&mut external_state);

        let mut internal_state = current_state.clone();
        internal_state[0] = sbox(current_state[0].clone() + rc0.clone());
        matmul_internal(&mut internal_state);

        let round_sum = init_round.clone() + external_round.clone() + internal_round.clone();
        let mut hash_state: [AB::Expr; POSEIDON2_WIDTH] =
            core::array::from_fn(|_| AB::Expr::ZERO);
        for idx in 0..POSEIDON2_WIDTH {
            hash_state[idx] = init_round.clone() * init_state[idx].clone()
                + external_round.clone() * external_state[idx].clone()
                + internal_round.clone() * internal_state[idx].clone();
        }

        let copy_flag = one.clone() - hash_flag.clone() - absorb_flag.clone();

        let in0: AB::Expr = next[COL_IN0].clone().into();
        let in1: AB::Expr = next[COL_IN1].clone().into();
        let in2: AB::Expr = next[COL_IN2].clone().into();
        let in3: AB::Expr = next[COL_IN3].clone().into();
        let in4: AB::Expr = next[COL_IN4].clone().into();
        let in5: AB::Expr = next[COL_IN5].clone().into();

        let absorb_state: [AB::Expr; POSEIDON2_WIDTH] = [
            current_state[0].clone() + in0,
            current_state[1].clone() + in1,
            current_state[2].clone() + in2,
            current_state[3].clone() + in3,
            current_state[4].clone() + in4,
            current_state[5].clone() + in5,
            current_state[6].clone(),
            current_state[7].clone(),
            current_state[8].clone(),
            current_state[9].clone(),
            current_state[10].clone(),
            current_state[11].clone(),
        ];

        let public_values = builder.public_values();
        let expected_len = 2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * 6) + 6;
        debug_assert_eq!(public_values.len(), expected_len);
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let mut idx = 0usize;
        let instruction_count = pv(idx);
        idx += 1;
        let nullifier_count = pv(idx);
        idx += 1;
        let instructions: Vec<AB::Expr> = (0..MAX_INSTRUCTIONS).map(|i| pv(idx + i)).collect();
        idx += MAX_INSTRUCTIONS;
        let mut nullifiers = Vec::with_capacity(MAX_NULLIFIERS);
        for _ in 0..MAX_NULLIFIERS {
            let nf = [
                pv(idx),
                pv(idx + 1),
                pv(idx + 2),
                pv(idx + 3),
                pv(idx + 4),
                pv(idx + 5),
            ];
            idx += 6;
            nullifiers.push(nf);
        }
        let commitment = [
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];

        let mut inputs = Vec::with_capacity(PADDED_INPUT_COUNT);
        inputs.push(instruction_count);
        inputs.push(nullifier_count);
        inputs.extend(instructions.into_iter());
        for nf in nullifiers {
            inputs.extend_from_slice(&nf);
        }
        while inputs.len() < PADDED_INPUT_COUNT {
            inputs.push(AB::Expr::ZERO);
        }

        {
            let mut when = builder.when_transition();
            when.assert_zero(hash_flag.clone() - round_sum);
            let state_cols = [
                COL_S0, COL_S1, COL_S2, COL_S3, COL_S4, COL_S5, COL_S6, COL_S7, COL_S8, COL_S9,
                COL_S10, COL_S11,
            ];
            for idx in 0..POSEIDON2_WIDTH {
                let expected = hash_flag.clone() * hash_state[idx].clone()
                    + copy_flag.clone() * current_state[idx].clone()
                    + absorb_flag.clone() * absorb_state[idx].clone();
                when.assert_zero(next[state_cols[idx]].clone() - expected);
            }

            for cycle in 0..INPUT_CYCLES_PER_TRACE {
                let (in0, in1, in2, in3, in4, in5) = if cycle < ABSORB_CYCLES {
                    let base = cycle * 6;
                    (
                        inputs[base].clone(),
                        inputs[base + 1].clone(),
                        inputs[base + 2].clone(),
                        inputs[base + 3].clone(),
                        inputs[base + 4].clone(),
                        inputs[base + 5].clone(),
                    )
                } else {
                    (
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                        AB::Expr::ZERO,
                    )
                };
                let gate: AB::Expr = prep_row[prep_cycle_start_col(cycle)].clone().into();
                when.assert_zero(gate.clone() * (current[COL_IN0].clone() - in0));
                when.assert_zero(gate.clone() * (current[COL_IN1].clone() - in1));
                when.assert_zero(gate.clone() * (current[COL_IN2].clone() - in2));
                when.assert_zero(gate.clone() * (current[COL_IN3].clone() - in3));
                when.assert_zero(gate.clone() * (current[COL_IN4].clone() - in4));
                when.assert_zero(gate * (current[COL_IN5].clone() - in5));
            }

            let gate: AB::Expr = prep_row[PREP_COMMIT_ROW].clone().into();
            when.assert_zero(gate.clone() * (current[COL_S0].clone() - commitment[0].clone()));
            when.assert_zero(gate.clone() * (current[COL_S1].clone() - commitment[1].clone()));
            when.assert_zero(gate.clone() * (current[COL_S2].clone() - commitment[2].clone()));
            when.assert_zero(gate.clone() * (current[COL_S3].clone() - commitment[3].clone()));
            when.assert_zero(gate.clone() * (current[COL_S4].clone() - commitment[4].clone()));
            when.assert_zero(gate * (current[COL_S5].clone() - commitment[5].clone()));
        }

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(
                current[COL_S0].clone()
                    - (AB::Expr::from_u64(SETTLEMENT_DOMAIN_TAG) + inputs[0].clone()),
            );
            when_first.assert_zero(current[COL_S1].clone() - inputs[1].clone());
            when_first.assert_zero(current[COL_S2].clone() - inputs[2].clone());
            when_first.assert_zero(current[COL_S3].clone() - inputs[3].clone());
            when_first.assert_zero(current[COL_S4].clone() - inputs[4].clone());
            when_first.assert_zero(current[COL_S5].clone() - inputs[5].clone());
            when_first.assert_zero(current[COL_S6].clone());
            when_first.assert_zero(current[COL_S7].clone());
            when_first.assert_zero(current[COL_S8].clone());
            when_first.assert_zero(current[COL_S9].clone());
            when_first.assert_zero(current[COL_S10].clone());
            when_first.assert_zero(current[COL_S11].clone() - one);
        }
    }
}
