//! Plonky3 AIR for batch transaction proofs.
//!
//! This AIR enforces Poseidon hash transitions and public output assertions
//! for each transaction slot in the batch trace.

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::constants::{MAX_BATCH_SIZE, MAX_INPUTS, MAX_OUTPUTS};
use transaction_core::dimensions::{
    commitment_output_row, merkle_root_output_row, nullifier_output_row,
};
use transaction_core::constants::{
    POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS, POSEIDON2_STEPS, POSEIDON2_WIDTH,
};
use transaction_core::poseidon2_constants;
use transaction_core::p3_air::{
    CYCLE_LENGTH, COL_DOMAIN, COL_IN0, COL_IN1, COL_IN2, COL_IN3, COL_IN4, COL_IN5, COL_RESET,
    COL_S0, COL_S1, COL_S10, COL_S11, COL_S2, COL_S3, COL_S4, COL_S5, COL_S6, COL_S7, COL_S8,
    COL_S9,
};

pub type Felt = Goldilocks;

/// Trace width (columns) for the batch circuit.
pub const TRACE_WIDTH: usize = transaction_core::p3_air::TRACE_WIDTH;

// ================================================================================================
// PREPROCESSED COLUMNS (fixed schedule)
// ================================================================================================

/// Poseidon2 hash flag for each row (1 during permutation steps).
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
/// One-hot selectors for nullifier output rows.
pub const PREP_NF_ROW_BASE: usize = PREP_RC11 + 1;
/// One-hot selectors for merkle root rows.
pub const PREP_MR_ROW_BASE: usize = PREP_NF_ROW_BASE + (MAX_BATCH_SIZE * MAX_INPUTS);
/// One-hot selectors for commitment output rows.
pub const PREP_CM_ROW_BASE: usize = PREP_MR_ROW_BASE + (MAX_BATCH_SIZE * MAX_INPUTS);
/// Preprocessed trace width (columns).
pub const PREPROCESSED_WIDTH: usize = PREP_CM_ROW_BASE + (MAX_BATCH_SIZE * MAX_OUTPUTS);

#[derive(Clone, Debug)]
pub struct BatchPublicInputsP3 {
    pub batch_size: u32,
    pub anchor: [Felt; 6],
    pub tx_active: Vec<Felt>,
    pub nullifiers: Vec<[Felt; 6]>,
    pub commitments: Vec<[Felt; 6]>,
    pub total_fee: Felt,
    pub circuit_version: u32,
}

impl BatchPublicInputsP3 {
    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(self.expected_len());
        elements.push(Felt::from_u64(self.batch_size as u64));
        elements.extend_from_slice(&self.anchor);
        elements.extend_from_slice(&self.tx_active);
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        for cm in &self.commitments {
            elements.extend_from_slice(cm);
        }
        elements.push(self.total_fee);
        elements.push(Felt::from_u64(self.circuit_version as u64));
        elements
    }

    pub fn try_from_slice(elements: &[Felt]) -> Result<Self, String> {
        let expected_len = Self::expected_len_static();
        if elements.len() != expected_len {
            return Err(format!(
                "batch public inputs length mismatch: expected {expected_len}, got {}",
                elements.len()
            ));
        }

        let mut idx = 0usize;
        let batch_size = elements[idx].as_canonical_u64() as u32;
        idx += 1;
        let anchor = {
            let slice = &elements[idx..idx + 6];
            idx += 6;
            [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]]
        };
        let tx_active = elements[idx..idx + MAX_BATCH_SIZE].to_vec();
        idx += MAX_BATCH_SIZE;

        let mut nullifiers = Vec::with_capacity(MAX_BATCH_SIZE * MAX_INPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_INPUTS {
            let slice = &elements[idx..idx + 6];
            idx += 6;
            nullifiers.push([slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]]);
        }

        let mut commitments = Vec::with_capacity(MAX_BATCH_SIZE * MAX_OUTPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_OUTPUTS {
            let slice = &elements[idx..idx + 6];
            idx += 6;
            commitments.push([slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]]);
        }

        let total_fee = elements[idx];
        idx += 1;
        let circuit_version = elements[idx].as_canonical_u64() as u32;

        Ok(Self {
            batch_size,
            anchor,
            tx_active,
            nullifiers,
            commitments,
            total_fee,
            circuit_version,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.batch_size == 0 {
            return Err("batch_size cannot be zero".into());
        }
        if !self.batch_size.is_power_of_two() {
            return Err("batch_size must be power of two".into());
        }
        if self.batch_size as usize > MAX_BATCH_SIZE {
            return Err("batch_size exceeds maximum".into());
        }
        if self.tx_active.len() != MAX_BATCH_SIZE {
            return Err("tx_active length mismatch".into());
        }
        if self.nullifiers.len() != MAX_BATCH_SIZE * MAX_INPUTS {
            return Err("nullifier length mismatch".into());
        }
        if self.commitments.len() != MAX_BATCH_SIZE * MAX_OUTPUTS {
            return Err("commitment length mismatch".into());
        }

        let mut sum_active = 0u32;
        for (idx, flag) in self.tx_active.iter().enumerate() {
            let value = flag.as_canonical_u64();
            if value > 1 {
                return Err(format!("tx_active[{idx}] is not boolean"));
            }
            sum_active += value as u32;
            if idx > 0 && value == 1 && self.tx_active[idx - 1].as_canonical_u64() == 0 {
                return Err("tx_active must be a prefix of ones".into());
            }
        }
        if sum_active != self.batch_size {
            return Err("tx_active sum does not match batch_size".into());
        }

        Ok(())
    }

    fn expected_len(&self) -> usize {
        Self::expected_len_static()
    }

    fn expected_len_static() -> usize {
        1 + 6 + MAX_BATCH_SIZE + (MAX_BATCH_SIZE * MAX_INPUTS * 6)
            + (MAX_BATCH_SIZE * MAX_OUTPUTS * 6)
            + 1
            + 1
    }
}

impl Default for BatchPublicInputsP3 {
    fn default() -> Self {
        let zero = [Felt::ZERO; 6];
        let mut tx_active = vec![Felt::ZERO; MAX_BATCH_SIZE];
        if let Some(first) = tx_active.first_mut() {
            *first = Felt::ONE;
        }
        Self {
            batch_size: 1,
            anchor: zero,
            tx_active,
            nullifiers: vec![zero; MAX_BATCH_SIZE * MAX_INPUTS],
            commitments: vec![zero; MAX_BATCH_SIZE * MAX_OUTPUTS],
            total_fee: Felt::ZERO,
            circuit_version: 1,
        }
    }
}

fn prep_nf_row_col(tx: usize, input: usize) -> usize {
    PREP_NF_ROW_BASE + tx * MAX_INPUTS + input
}

fn prep_mr_row_col(tx: usize, input: usize) -> usize {
    PREP_MR_ROW_BASE + tx * MAX_INPUTS + input
}

fn prep_cm_row_col(tx: usize, output: usize) -> usize {
    PREP_CM_ROW_BASE + tx * MAX_OUTPUTS + output
}

fn build_preprocessed_trace(trace_len: usize) -> RowMajorMatrix<Felt> {
    let mut values = vec![Felt::ZERO; trace_len * PREPROCESSED_WIDTH];

    for row in 0..trace_len {
        let step = row % CYCLE_LENGTH;
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
    }

    for tx in 0..MAX_BATCH_SIZE {
        for input in 0..MAX_INPUTS {
            let row = nullifier_output_row(tx, input);
            if row < trace_len {
                let col = prep_nf_row_col(tx, input);
                values[row * PREPROCESSED_WIDTH + col] = Felt::ONE;
            }
            let row = merkle_root_output_row(tx, input);
            if row < trace_len {
                let col = prep_mr_row_col(tx, input);
                values[row * PREPROCESSED_WIDTH + col] = Felt::ONE;
            }
        }
        for output in 0..MAX_OUTPUTS {
            let row = commitment_output_row(tx, output);
            if row < trace_len {
                let col = prep_cm_row_col(tx, output);
                values[row * PREPROCESSED_WIDTH + col] = Felt::ONE;
            }
        }
    }

    RowMajorMatrix::new(values, PREPROCESSED_WIDTH)
}

pub struct BatchTransactionAirP3 {
    trace_len: usize,
}

impl BatchTransactionAirP3 {
    pub fn new(trace_len: usize) -> Self {
        Self { trace_len }
    }
}

impl BaseAir<Felt> for BatchTransactionAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(build_preprocessed_trace(self.trace_len))
    }
}

impl<AB> Air<AB> for BatchTransactionAirP3
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

        let reset: AB::Expr = current[COL_RESET].clone().into();
        let domain: AB::Expr = current[COL_DOMAIN].clone().into();
        let in0: AB::Expr = current[COL_IN0].clone().into();
        let in1: AB::Expr = current[COL_IN1].clone().into();
        let in2: AB::Expr = current[COL_IN2].clone().into();
        let in3: AB::Expr = current[COL_IN3].clone().into();
        let in4: AB::Expr = current[COL_IN4].clone().into();
        let in5: AB::Expr = current[COL_IN5].clone().into();

        let start_state = [
            domain.clone() + in0.clone(),
            in1.clone(),
            in2.clone(),
            in3.clone(),
            in4.clone(),
            in5.clone(),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            one.clone(),
        ];

        let cont_state = [
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

        let absorb_state: [AB::Expr; POSEIDON2_WIDTH] = core::array::from_fn(|idx| {
            reset.clone() * start_state[idx].clone()
                + (one.clone() - reset.clone()) * cont_state[idx].clone()
        });

        let public_values = builder.public_values();
        let expected_len = BatchPublicInputsP3::expected_len_static();
        debug_assert_eq!(public_values.len(), expected_len);
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let mut idx = 0usize;
        let batch_size = pv(idx);
        idx += 1;
        let anchor = [
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let tx_active: Vec<AB::Expr> = (0..MAX_BATCH_SIZE).map(|i| pv(idx + i)).collect();
        idx += MAX_BATCH_SIZE;

        let mut nullifiers = Vec::with_capacity(MAX_BATCH_SIZE * MAX_INPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_INPUTS {
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

        let mut commitments = Vec::with_capacity(MAX_BATCH_SIZE * MAX_OUTPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_OUTPUTS {
            let cm = [
                pv(idx),
                pv(idx + 1),
                pv(idx + 2),
                pv(idx + 3),
                pv(idx + 4),
                pv(idx + 5),
            ];
            idx += 6;
            commitments.push(cm);
        }

        let total_fee = pv(idx);
        idx += 1;
        let circuit_version = pv(idx);

        let is_last = builder.is_last_row();
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
        for flag in &tx_active {
            when.assert_bool(flag.clone());
        }

        for tx in 0..MAX_BATCH_SIZE {
            let active = tx_active[tx].clone();
            let nf_base = tx * MAX_INPUTS;
            let cm_base = tx * MAX_OUTPUTS;
            for nf_idx in 0..MAX_INPUTS {
                let row_flag: AB::Expr = prep_row[prep_nf_row_col(tx, nf_idx)].clone().into();
                let gate = row_flag * active.clone();
                let nf = &nullifiers[nf_base + nf_idx];
                when.assert_zero(gate.clone() * (current[COL_S0].clone() - nf[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1].clone() - nf[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S2].clone() - nf[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S3].clone() - nf[3].clone()));
                when.assert_zero(gate.clone() * (current[COL_S4].clone() - nf[4].clone()));
                when.assert_zero(gate.clone() * (current[COL_S5].clone() - nf[5].clone()));

                let row_flag: AB::Expr = prep_row[prep_mr_row_col(tx, nf_idx)].clone().into();
                let gate = row_flag * active.clone();
                when.assert_zero(gate.clone() * (current[COL_S0].clone() - anchor[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1].clone() - anchor[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S2].clone() - anchor[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S3].clone() - anchor[3].clone()));
                when.assert_zero(gate.clone() * (current[COL_S4].clone() - anchor[4].clone()));
                when.assert_zero(gate.clone() * (current[COL_S5].clone() - anchor[5].clone()));
            }

            for cm_idx in 0..MAX_OUTPUTS {
                let row_flag: AB::Expr = prep_row[prep_cm_row_col(tx, cm_idx)].clone().into();
                let gate = row_flag * active.clone();
                let cm = &commitments[cm_base + cm_idx];
                when.assert_zero(gate.clone() * (current[COL_S0].clone() - cm[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1].clone() - cm[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S2].clone() - cm[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S3].clone() - cm[3].clone()));
                when.assert_zero(gate.clone() * (current[COL_S4].clone() - cm[4].clone()));
                when.assert_zero(gate.clone() * (current[COL_S5].clone() - cm[5].clone()));
            }
        }

        let mut sum_active = AB::Expr::ZERO;
        for flag in &tx_active {
            sum_active = sum_active + flag.clone();
        }
        when.assert_zero(is_last.clone() * (sum_active - batch_size));

        for idx in 1..MAX_BATCH_SIZE {
            let prev = tx_active[idx - 1].clone();
            let curr = tx_active[idx].clone();
            when.assert_zero(is_last.clone() * curr * (one.clone() - prev));
        }

        for tx in 0..MAX_BATCH_SIZE {
            let inactive = one.clone() - tx_active[tx].clone();
            let nf_base = tx * MAX_INPUTS;
            let cm_base = tx * MAX_OUTPUTS;
            for nf_idx in 0..MAX_INPUTS {
                let nf = &nullifiers[nf_base + nf_idx];
                for limb in nf.iter() {
                    when.assert_zero(is_last.clone() * inactive.clone() * limb.clone());
                }
            }
            for cm_idx in 0..MAX_OUTPUTS {
                let cm = &commitments[cm_base + cm_idx];
                for limb in cm.iter() {
                    when.assert_zero(is_last.clone() * inactive.clone() * limb.clone());
                }
            }
        }

        when.assert_zero(is_last.clone() * (current[transaction_core::p3_air::COL_FEE].clone() - total_fee));
        when.assert_zero(
            is_last * (circuit_version - AB::Expr::from_u64(1)),
        );
    }
}
