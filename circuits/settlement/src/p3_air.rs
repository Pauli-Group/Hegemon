//! Plonky3 AIR for settlement commitments.

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::constants::{
    ABSORB_CYCLES, INPUT_PAIRS_PER_TRACE, MAX_INSTRUCTIONS, MAX_NULLIFIERS, PADDED_INPUT_COUNT,
    SETTLEMENT_DOMAIN_TAG,
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
pub const COL_STEP_BIT0: usize = 5;
pub const COL_CYCLE_BIT0: usize = 11;
pub const TRACE_WIDTH: usize = 16;

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
        inputs.push(Felt::from_canonical_u64(self.instruction_count as u64));
        inputs.push(Felt::from_canonical_u64(self.nullifier_count as u64));
        inputs.extend(self.instructions.iter().copied());
        for nf in &self.nullifiers {
            inputs.extend_from_slice(nf);
        }
        while inputs.len() < PADDED_INPUT_COUNT {
            inputs.push(Felt::zero());
        }
        inputs
    }

    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements =
            Vec::with_capacity(2 + MAX_INSTRUCTIONS + (MAX_NULLIFIERS * 4) + 4);
        elements.push(Felt::from_canonical_u64(self.instruction_count as u64));
        elements.push(Felt::from_canonical_u64(self.nullifier_count as u64));
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
            instructions: vec![Felt::zero(); MAX_INSTRUCTIONS],
            nullifiers: vec![[Felt::zero(); 4]; MAX_NULLIFIERS],
            commitment: [Felt::zero(); 4],
        }
    }
}

pub struct SettlementAirP3;

impl BaseAir<Felt> for SettlementAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB> Air<AB> for SettlementAirP3
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
        ];
        let cycle_bits_next = [
            next[COL_CYCLE_BIT0],
            next[COL_CYCLE_BIT0 + 1],
            next[COL_CYCLE_BIT0 + 2],
            next[COL_CYCLE_BIT0 + 3],
            next[COL_CYCLE_BIT0 + 4],
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

        let absorb_flag = bit_selector(&step_bits, CYCLE_LENGTH - 1);
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
        when.assert_zero(absorb_flag.clone() * (next[COL_S0] - (current[COL_S0] + next[COL_IN0])));
        when.assert_zero(absorb_flag.clone() * (next[COL_S1] - (current[COL_S1] + next[COL_IN1])));
        when.assert_zero(absorb_flag.clone() * (next[COL_S2] - current[COL_S2]));
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

        let mut carry = absorb_flag.clone();
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
            inputs.push(AB::Expr::zero());
        }

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(
                current[COL_S0] - (AB::Expr::from_canonical_u64(SETTLEMENT_DOMAIN_TAG) + inputs[0].clone()),
            );
            when_first.assert_zero(current[COL_S1] - inputs[1].clone());
            when_first.assert_zero(current[COL_S2] - one.clone());
        }

        for cycle in 0..INPUT_PAIRS_PER_TRACE {
            let row = cycle * CYCLE_LENGTH;
            let pair_index = cycle + 1;
            let (in0, in1) = if pair_index < ABSORB_CYCLES {
                (inputs[2 * pair_index].clone(), inputs[2 * pair_index + 1].clone())
            } else {
                (AB::Expr::zero(), AB::Expr::zero())
            };
            let gate = row_selector(row);
            when.assert_zero(gate.clone() * (current[COL_IN0] - in0));
            when.assert_zero(gate * (current[COL_IN1] - in1));
        }

        let row_01 = commitment_row_01();
        let row_23 = commitment_row_23();
        let gate_01 = row_selector(row_01);
        let gate_23 = row_selector(row_23);
        when.assert_zero(gate_01.clone() * (current[COL_S0] - commitment[0].clone()));
        when.assert_zero(gate_01 * (current[COL_S1] - commitment[1].clone()));
        when.assert_zero(gate_23.clone() * (current[COL_S0] - commitment[2].clone()));
        when.assert_zero(gate_23 * (current[COL_S1] - commitment[3].clone()));
    }
}
