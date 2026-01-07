//! Plonky3 AIR for batch transaction proofs.
//!
//! This AIR enforces Poseidon hash transitions and public output assertions
//! for each transaction slot in the batch trace.

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::public_inputs::{MAX_BATCH_SIZE, MAX_INPUTS, MAX_OUTPUTS};
use transaction_core::dimensions::{
    commitment_output_row, merkle_root_output_row, nullifier_output_row,
};
use transaction_core::p3_air::{
    CYCLE_LENGTH, COL_CYCLE_BIT0, COL_OUT0, COL_OUT1, COL_S0, COL_S1, COL_S2, COL_STEP_BIT0,
    POSEIDON_ROUNDS,
};

pub type Felt = Goldilocks;

/// Additional cycle bits required for batch traces (16 * 32768 rows).
pub const EXTRA_CYCLE_BITS: usize = 4;
pub const COL_BATCH_CYCLE_BIT9: usize = transaction_core::p3_air::TRACE_WIDTH;
pub const COL_BATCH_CYCLE_BIT10: usize = COL_BATCH_CYCLE_BIT9 + 1;
pub const COL_BATCH_CYCLE_BIT11: usize = COL_BATCH_CYCLE_BIT9 + 2;
pub const COL_BATCH_CYCLE_BIT12: usize = COL_BATCH_CYCLE_BIT9 + 3;
pub const TRACE_WIDTH: usize = transaction_core::p3_air::TRACE_WIDTH + EXTRA_CYCLE_BITS;

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
        elements.push(Felt::from_canonical_u64(self.batch_size as u64));
        elements.extend_from_slice(&self.anchor);
        elements.extend_from_slice(&self.tx_active);
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        for cm in &self.commitments {
            elements.extend_from_slice(cm);
        }
        elements.push(self.total_fee);
        elements.push(Felt::from_canonical_u64(self.circuit_version as u64));
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
        let zero = [Felt::zero(); 4];
        let mut tx_active = vec![Felt::zero(); MAX_BATCH_SIZE];
        if let Some(first) = tx_active.first_mut() {
            *first = Felt::one();
        }
        Self {
            batch_size: 1,
            anchor: zero,
            tx_active,
            nullifiers: vec![zero; MAX_BATCH_SIZE * MAX_INPUTS],
            commitments: vec![zero; MAX_BATCH_SIZE * MAX_OUTPUTS],
            total_fee: Felt::zero(),
            circuit_version: 1,
        }
    }
}

pub struct BatchTransactionAirP3;

impl BaseAir<Felt> for BatchTransactionAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB> Air<AB> for BatchTransactionAirP3
where
    AB: AirBuilderWithPublicValues<F = Felt>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.row_slice(0);
        let next = main.row_slice(1);

        let one = AB::Expr::one();
        let two = AB::Expr::from_canonical_u64(2);

        let step_bits = [
            current[COL_STEP_BIT0],
            current[COL_STEP_BIT0 + 1],
            current[COL_STEP_BIT0 + 2],
            current[COL_STEP_BIT0 + 3],
            current[COL_STEP_BIT0 + 4],
            current[COL_STEP_BIT0 + 5],
        ];
        let step_bits_next = [
            next[COL_STEP_BIT0],
            next[COL_STEP_BIT0 + 1],
            next[COL_STEP_BIT0 + 2],
            next[COL_STEP_BIT0 + 3],
            next[COL_STEP_BIT0 + 4],
            next[COL_STEP_BIT0 + 5],
        ];
        let cycle_bits = [
            current[COL_CYCLE_BIT0],
            current[COL_CYCLE_BIT0 + 1],
            current[COL_CYCLE_BIT0 + 2],
            current[COL_CYCLE_BIT0 + 3],
            current[COL_CYCLE_BIT0 + 4],
            current[COL_CYCLE_BIT0 + 5],
            current[COL_CYCLE_BIT0 + 6],
            current[COL_CYCLE_BIT0 + 7],
            current[COL_CYCLE_BIT0 + 8],
            current[COL_BATCH_CYCLE_BIT9],
            current[COL_BATCH_CYCLE_BIT10],
            current[COL_BATCH_CYCLE_BIT11],
            current[COL_BATCH_CYCLE_BIT12],
        ];
        let cycle_bits_next = [
            next[COL_CYCLE_BIT0],
            next[COL_CYCLE_BIT0 + 1],
            next[COL_CYCLE_BIT0 + 2],
            next[COL_CYCLE_BIT0 + 3],
            next[COL_CYCLE_BIT0 + 4],
            next[COL_CYCLE_BIT0 + 5],
            next[COL_CYCLE_BIT0 + 6],
            next[COL_CYCLE_BIT0 + 7],
            next[COL_CYCLE_BIT0 + 8],
            next[COL_BATCH_CYCLE_BIT9],
            next[COL_BATCH_CYCLE_BIT10],
            next[COL_BATCH_CYCLE_BIT11],
            next[COL_BATCH_CYCLE_BIT12],
        ];

        let bit_selector = |bits: &[AB::Var], value: usize| -> AB::Expr {
            let mut acc = one.clone();
            for (idx, bit) in bits.iter().enumerate() {
                let bit_expr: AB::Expr = (*bit).into();
                if ((value >> idx) & 1) == 1 {
                    acc = acc * bit_expr;
                } else {
                    acc = acc * (one.clone() - bit_expr);
                }
            }
            acc
        };

        let row_selector = |row: usize| -> AB::Expr {
            let cycle = row / CYCLE_LENGTH;
            let step = row % CYCLE_LENGTH;
            bit_selector(&cycle_bits, cycle) * bit_selector(&step_bits, step)
        };

        let mut hash_flag = AB::Expr::zero();
        let mut rc0 = AB::Expr::zero();
        let mut rc1 = AB::Expr::zero();
        let mut rc2 = AB::Expr::zero();
        for round in 0..POSEIDON_ROUNDS {
            let sel = bit_selector(&step_bits, round);
            hash_flag += sel.clone();
            rc0 += sel.clone()
                * AB::Expr::from_canonical_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS
                    [round][0]);
            rc1 += sel.clone()
                * AB::Expr::from_canonical_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS
                    [round][1]);
            rc2 += sel
                * AB::Expr::from_canonical_u64(transaction_core::poseidon_constants::ROUND_CONSTANTS
                    [round][2]);
        }

        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;
        let s0 = t0.exp_const_u64::<5>();
        let s1 = t1.exp_const_u64::<5>();
        let s2 = t2.exp_const_u64::<5>();

        let mds = transaction_core::poseidon_constants::MDS_MATRIX;
        let m00 = AB::Expr::from_canonical_u64(mds[0][0]);
        let m01 = AB::Expr::from_canonical_u64(mds[0][1]);
        let m02 = AB::Expr::from_canonical_u64(mds[0][2]);
        let m10 = AB::Expr::from_canonical_u64(mds[1][0]);
        let m11 = AB::Expr::from_canonical_u64(mds[1][1]);
        let m12 = AB::Expr::from_canonical_u64(mds[1][2]);
        let m20 = AB::Expr::from_canonical_u64(mds[2][0]);
        let m21 = AB::Expr::from_canonical_u64(mds[2][1]);
        let m22 = AB::Expr::from_canonical_u64(mds[2][2]);

        let hash_s0 = s0.clone() * m00 + s1.clone() * m01 + s2.clone() * m02;
        let hash_s1 = s0.clone() * m10 + s1.clone() * m11 + s2.clone() * m12;
        let hash_s2 = s0 * m20 + s1 * m21 + s2 * m22;

        {
            let mut when_first = builder.when_first_row();
            for bit in step_bits.iter().chain(cycle_bits.iter()) {
                when_first.assert_zero(*bit);
            }
        }

        let mut when = builder.when_transition();
        when.assert_zero(hash_flag.clone() * (next[COL_S0] - hash_s0));
        when.assert_zero(hash_flag.clone() * (next[COL_S1] - hash_s1));
        when.assert_zero(hash_flag * (next[COL_S2] - hash_s2));

        for bit in step_bits.iter() {
            when.assert_bool(*bit);
        }
        for bit in cycle_bits.iter() {
            when.assert_bool(*bit);
        }

        let mut carry = one.clone();
        for (idx, bit) in step_bits.iter().enumerate() {
            let bit_expr: AB::Expr = (*bit).into();
            let carry_next = carry.clone() * bit_expr.clone();
            let next_expr: AB::Expr = step_bits_next[idx].into();
            when.assert_zero(
                next_expr - (bit_expr + carry.clone() - two.clone() * carry_next.clone()),
            );
            carry = carry_next;
        }

        let cycle_end = bit_selector(&step_bits, CYCLE_LENGTH - 1);
        let mut carry = cycle_end.clone();
        for (idx, bit) in cycle_bits.iter().enumerate() {
            let bit_expr: AB::Expr = (*bit).into();
            let carry_next = carry.clone() * bit_expr.clone();
            let next_expr: AB::Expr = cycle_bits_next[idx].into();
            when.assert_zero(
                next_expr - (bit_expr + carry.clone() - two.clone() * carry_next.clone()),
            );
            carry = carry_next;
        }

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

        let mut when = builder.when_transition();
        for flag in &tx_active {
            when.assert_bool(flag.clone());
        }

        for tx in 0..MAX_BATCH_SIZE {
            let active = tx_active[tx].clone();
            let nf_base = tx * MAX_INPUTS;
            let cm_base = tx * MAX_OUTPUTS;
            for nf_idx in 0..MAX_INPUTS {
                let row = nullifier_output_row(tx, nf_idx);
                let gate = row_selector(row) * active.clone();
                let nf = &nullifiers[nf_base + nf_idx];
                when.assert_zero(gate.clone() * (current[COL_OUT0] - nf[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_OUT1] - nf[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S0] - nf[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1] - nf[3].clone()));

                let row = merkle_root_output_row(tx, nf_idx);
                let gate = row_selector(row) * active.clone();
                when.assert_zero(gate.clone() * (current[COL_OUT0] - anchor[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_OUT1] - anchor[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S0] - anchor[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1] - anchor[3].clone()));
            }

            for cm_idx in 0..MAX_OUTPUTS {
                let row = commitment_output_row(tx, cm_idx);
                let gate = row_selector(row) * active.clone();
                let cm = &commitments[cm_base + cm_idx];
                when.assert_zero(gate.clone() * (current[COL_OUT0] - cm[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_OUT1] - cm[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_S0] - cm[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_S1] - cm[3].clone()));
            }
        }

        let is_last = builder.is_last_row();
        let mut sum_active = AB::Expr::zero();
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

        when.assert_zero(is_last.clone() * (current[transaction_core::p3_air::COL_FEE] - total_fee));
        when.assert_zero(
            is_last * (circuit_version - AB::Expr::from_canonical_u64(1)),
        );

    }
}
