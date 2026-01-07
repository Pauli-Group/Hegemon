//! Plonky3 AIR for settlement commitments.

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::constants::{
    ABSORB_CYCLES, INPUT_PAIRS_PER_TRACE, MAX_INSTRUCTIONS, MAX_NULLIFIERS, PADDED_INPUT_COUNT,
    SETTLEMENT_DOMAIN_TAG, TRACE_LENGTH,
};
use transaction_core::constants::POSEIDON_ROUNDS;
use transaction_core::p3_air::CYCLE_LENGTH;

pub type Felt = Goldilocks;
pub type HashFelt = [Felt; 4];

pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;
pub const COL_IN0: usize = 3;
pub const COL_IN1: usize = 4;
pub const TRACE_WIDTH: usize = COL_IN1 + 1;

// ================================================================================================
// PREPROCESSED COLUMNS (fixed schedule)
// ================================================================================================

/// Poseidon hash flag for each row (1 during rounds).
pub const PREP_HASH_FLAG: usize = 0;
/// Poseidon absorb flag for each row (1 on the absorb step).
pub const PREP_ABSORB_FLAG: usize = PREP_HASH_FLAG + 1;
/// Poseidon round constants (per row).
pub const PREP_RC0: usize = PREP_ABSORB_FLAG + 1;
pub const PREP_RC1: usize = PREP_RC0 + 1;
pub const PREP_RC2: usize = PREP_RC1 + 1;
/// One-hot selectors for cycle start rows.
pub const PREP_CYCLE_START_BASE: usize = PREP_RC2 + 1;
/// One-hot selector for commitment output rows.
pub const PREP_COMMIT_ROW_01: usize = PREP_CYCLE_START_BASE + INPUT_PAIRS_PER_TRACE;
pub const PREP_COMMIT_ROW_23: usize = PREP_COMMIT_ROW_01 + 1;
/// Preprocessed trace width.
pub const PREPROCESSED_WIDTH: usize = PREP_COMMIT_ROW_23 + 1;

pub fn commitment_row_01() -> usize {
    (ABSORB_CYCLES - 1) * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

pub fn commitment_row_23() -> usize {
    ABSORB_CYCLES * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
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
            Vec::with_capacity(2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * 4) + 4);
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
        let expected_len = 2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * 4) + 4;
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
            let slice = &elements[idx..idx + 4];
            idx += 4;
            nullifiers.push([slice[0], slice[1], slice[2], slice[3]]);
        }
        let commitment = {
            let slice = &elements[idx..idx + 4];
            [slice[0], slice[1], slice[2], slice[3]]
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
            nullifiers: vec![[Felt::ZERO; 4]; MAX_NULLIFIERS],
            commitment: [Felt::ZERO; 4],
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

        row_slice[PREP_HASH_FLAG] = Felt::from_bool(step < POSEIDON_ROUNDS);
        row_slice[PREP_ABSORB_FLAG] = Felt::from_bool(step == CYCLE_LENGTH - 1);
        if step < POSEIDON_ROUNDS {
            row_slice[PREP_RC0] =
                Felt::from_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS[step][0]);
            row_slice[PREP_RC1] =
                Felt::from_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS[step][1]);
            row_slice[PREP_RC2] =
                Felt::from_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS[step][2]);
        }

        if step == 0 && cycle < INPUT_PAIRS_PER_TRACE {
            row_slice[prep_cycle_start_col(cycle)] = Felt::ONE;
        }

        if row == commitment_row_01() {
            row_slice[PREP_COMMIT_ROW_01] = Felt::ONE;
        }
        if row == commitment_row_23() {
            row_slice[PREP_COMMIT_ROW_23] = Felt::ONE;
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
        let rc0: AB::Expr = prep_row[PREP_RC0].clone().into();
        let rc1: AB::Expr = prep_row[PREP_RC1].clone().into();
        let rc2: AB::Expr = prep_row[PREP_RC2].clone().into();

        let t0 = current[COL_S0].clone() + rc0;
        let t1 = current[COL_S1].clone() + rc1;
        let t2 = current[COL_S2].clone() + rc2;
        let s0 = t0.exp_const_u64::<5>();
        let s1 = t1.exp_const_u64::<5>();
        let s2 = t2.exp_const_u64::<5>();

        let mds = transaction_core::poseidon_constants::MDS_MATRIX;
        let m00 = AB::Expr::from_u64(mds[0][0]);
        let m01 = AB::Expr::from_u64(mds[0][1]);
        let m02 = AB::Expr::from_u64(mds[0][2]);
        let m10 = AB::Expr::from_u64(mds[1][0]);
        let m11 = AB::Expr::from_u64(mds[1][1]);
        let m12 = AB::Expr::from_u64(mds[1][2]);
        let m20 = AB::Expr::from_u64(mds[2][0]);
        let m21 = AB::Expr::from_u64(mds[2][1]);
        let m22 = AB::Expr::from_u64(mds[2][2]);

        let hash_s0 = s0.clone() * m00 + s1.clone() * m01 + s2.clone() * m02;
        let hash_s1 = s0.clone() * m10 + s1.clone() * m11 + s2.clone() * m12;
        let hash_s2 = s0 * m20 + s1 * m21 + s2 * m22;

        let public_values = builder.public_values();
        let expected_len = 2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * 4) + 4;
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
            let nf = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
            idx += 4;
            nullifiers.push(nf);
        }
        let commitment = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];

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
            when.assert_zero(
                absorb_flag.clone() * (next[COL_S0].clone() - (current[COL_S0].clone() + next[COL_IN0].clone())),
            );
            when.assert_zero(
                absorb_flag.clone() * (next[COL_S1].clone() - (current[COL_S1].clone() + next[COL_IN1].clone())),
            );
            when.assert_zero(absorb_flag.clone() * (next[COL_S2].clone() - current[COL_S2].clone()));
            when.assert_zero(hash_flag.clone() * (next[COL_S0].clone() - hash_s0));
            when.assert_zero(hash_flag.clone() * (next[COL_S1].clone() - hash_s1));
            when.assert_zero(hash_flag * (next[COL_S2].clone() - hash_s2));

            for cycle in 0..INPUT_PAIRS_PER_TRACE {
                let pair_index = cycle + 1;
                let (in0, in1) = if pair_index < ABSORB_CYCLES {
                    (inputs[2 * pair_index].clone(), inputs[2 * pair_index + 1].clone())
                } else {
                    (AB::Expr::ZERO, AB::Expr::ZERO)
                };
                let gate: AB::Expr = prep_row[prep_cycle_start_col(cycle)].clone().into();
                when.assert_zero(gate.clone() * (current[COL_IN0].clone() - in0));
                when.assert_zero(gate * (current[COL_IN1].clone() - in1));
            }

            let gate_01: AB::Expr = prep_row[PREP_COMMIT_ROW_01].clone().into();
            let gate_23: AB::Expr = prep_row[PREP_COMMIT_ROW_23].clone().into();
            when.assert_zero(gate_01.clone() * (current[COL_S0].clone() - commitment[0].clone()));
            when.assert_zero(gate_01 * (current[COL_S1].clone() - commitment[1].clone()));
            when.assert_zero(gate_23.clone() * (current[COL_S0].clone() - commitment[2].clone()));
            when.assert_zero(gate_23 * (current[COL_S1].clone() - commitment[3].clone()));
        }

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(
                current[COL_S0].clone()
                    - (AB::Expr::from_u64(SETTLEMENT_DOMAIN_TAG) + inputs[0].clone()),
            );
            when_first.assert_zero(current[COL_S1].clone() - inputs[1].clone());
            when_first.assert_zero(current[COL_S2].clone() - one);
        }
    }
}
