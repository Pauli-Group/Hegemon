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

use crate::public_inputs::{MAX_BATCH_SIZE, MAX_INPUTS, MAX_OUTPUTS};
use transaction_core::dimensions::{
    commitment_output_row, merkle_root_output_row, nullifier_output_row,
};
use transaction_core::constants::POSEIDON_ROUNDS;
use transaction_core::p3_air::{CYCLE_LENGTH, COL_OUT0, COL_OUT1, COL_S0, COL_S1, COL_S2};

pub type Felt = Goldilocks;

/// Trace width (columns) for the batch circuit.
pub const TRACE_WIDTH: usize = transaction_core::p3_air::TRACE_WIDTH;

// ================================================================================================
// PREPROCESSED COLUMNS (fixed schedule)
// ================================================================================================

/// Poseidon hash flag for each row (1 during rounds).
pub const PREP_HASH_FLAG: usize = 0;
/// Poseidon round constants (per row).
pub const PREP_RC0: usize = PREP_HASH_FLAG + 1;
pub const PREP_RC1: usize = PREP_RC0 + 1;
pub const PREP_RC2: usize = PREP_RC1 + 1;
/// One-hot selectors for nullifier output rows.
pub const PREP_NF_ROW_BASE: usize = PREP_RC2 + 1;
/// One-hot selectors for merkle root rows.
pub const PREP_MR_ROW_BASE: usize = PREP_NF_ROW_BASE + (MAX_BATCH_SIZE * MAX_INPUTS);
/// One-hot selectors for commitment output rows.
pub const PREP_CM_ROW_BASE: usize = PREP_MR_ROW_BASE + (MAX_BATCH_SIZE * MAX_INPUTS);
/// Preprocessed trace width (columns).
pub const PREPROCESSED_WIDTH: usize = PREP_CM_ROW_BASE + (MAX_BATCH_SIZE * MAX_OUTPUTS);

#[derive(Clone, Debug)]
pub struct BatchPublicInputsP3 {
    pub batch_size: u32,
    pub anchor: [Felt; 4],
    pub tx_active: Vec<Felt>,
    pub nullifiers: Vec<[Felt; 4]>,
    pub commitments: Vec<[Felt; 4]>,
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
            let slice = &elements[idx..idx + 4];
            idx += 4;
            [slice[0], slice[1], slice[2], slice[3]]
        };
        let tx_active = elements[idx..idx + MAX_BATCH_SIZE].to_vec();
        idx += MAX_BATCH_SIZE;

        let mut nullifiers = Vec::with_capacity(MAX_BATCH_SIZE * MAX_INPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_INPUTS {
            let slice = &elements[idx..idx + 4];
            idx += 4;
            nullifiers.push([slice[0], slice[1], slice[2], slice[3]]);
        }

        let mut commitments = Vec::with_capacity(MAX_BATCH_SIZE * MAX_OUTPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_OUTPUTS {
            let slice = &elements[idx..idx + 4];
            idx += 4;
            commitments.push([slice[0], slice[1], slice[2], slice[3]]);
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
        1 + 4 + MAX_BATCH_SIZE + (MAX_BATCH_SIZE * MAX_INPUTS * 4)
            + (MAX_BATCH_SIZE * MAX_OUTPUTS * 4)
            + 1
            + 1
    }
}

impl Default for BatchPublicInputsP3 {
    fn default() -> Self {
        let zero = [Felt::ZERO; 4];
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

        row_slice[PREP_HASH_FLAG] = Felt::from_bool(step < POSEIDON_ROUNDS);
        if step < POSEIDON_ROUNDS {
            row_slice[PREP_RC0] =
                Felt::from_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS[step][0]);
            row_slice[PREP_RC1] =
                Felt::from_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS[step][1]);
            row_slice[PREP_RC2] =
                Felt::from_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS[step][2]);
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
        let expected_len = BatchPublicInputsP3::expected_len_static();
        debug_assert_eq!(public_values.len(), expected_len);
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let mut idx = 0usize;
        let batch_size = pv(idx);
        idx += 1;
        let anchor = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let tx_active: Vec<AB::Expr> = (0..MAX_BATCH_SIZE).map(|i| pv(idx + i)).collect();
        idx += MAX_BATCH_SIZE;

        let mut nullifiers = Vec::with_capacity(MAX_BATCH_SIZE * MAX_INPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_INPUTS {
            let nf = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
            idx += 4;
            nullifiers.push(nf);
        }

        let mut commitments = Vec::with_capacity(MAX_BATCH_SIZE * MAX_OUTPUTS);
        for _ in 0..MAX_BATCH_SIZE * MAX_OUTPUTS {
            let cm = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
            idx += 4;
            commitments.push(cm);
        }

        let total_fee = pv(idx);
        idx += 1;
        let circuit_version = pv(idx);

        let is_last = builder.is_last_row();
        let mut when = builder.when_transition();
        when.assert_zero(hash_flag.clone() * (next[COL_S0].clone() - hash_s0));
        when.assert_zero(hash_flag.clone() * (next[COL_S1].clone() - hash_s1));
        when.assert_zero(hash_flag * (next[COL_S2].clone() - hash_s2));
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
                when.assert_zero(gate.clone() * (current[COL_OUT0].clone() - nf[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_OUT1].clone() - nf[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S0].clone() - nf[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1].clone() - nf[3].clone()));

                let row_flag: AB::Expr = prep_row[prep_mr_row_col(tx, nf_idx)].clone().into();
                let gate = row_flag * active.clone();
                when.assert_zero(gate.clone() * (current[COL_OUT0].clone() - anchor[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_OUT1].clone() - anchor[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S0].clone() - anchor[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1].clone() - anchor[3].clone()));
            }

            for cm_idx in 0..MAX_OUTPUTS {
                let row_flag: AB::Expr = prep_row[prep_cm_row_col(tx, cm_idx)].clone().into();
                let gate = row_flag * active.clone();
                let cm = &commitments[cm_base + cm_idx];
                when.assert_zero(gate.clone() * (current[COL_OUT0].clone() - cm[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_OUT1].clone() - cm[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S0].clone() - cm[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1].clone() - cm[3].clone()));
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
