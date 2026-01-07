//! Plonky3 AIR for commitment block proofs.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{AbstractField, Field, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::Matrix;

use crate::commitment_air::{
    BLOCK_COMMITMENT_DOMAIN_TAG, COL_DA_ROOT0, COL_DA_ROOT1, COL_DA_ROOT2, COL_DA_ROOT3,
    COL_END_ROOT0, COL_END_ROOT1, COL_END_ROOT2, COL_END_ROOT3, COL_INPUT0, COL_INPUT1,
    COL_NF_DIFF_INV, COL_NF_DIFF_NZ, COL_NF_PERM, COL_NF_PERM_INV, COL_NF_S0, COL_NF_S1,
    COL_NF_S2, COL_NF_S3, COL_NF_SORTED_INV, COL_NF_SORTED_NZ, COL_NF_U0, COL_NF_U1, COL_NF_U2,
    COL_NF_U3, COL_NULLIFIER_ROOT0, COL_NULLIFIER_ROOT1, COL_NULLIFIER_ROOT2, COL_NULLIFIER_ROOT3,
    COL_S0, COL_S1, COL_S2, COL_START_ROOT0, COL_START_ROOT1, COL_START_ROOT2, COL_START_ROOT3,
    TRACE_WIDTH as BASE_TRACE_WIDTH,
};
use transaction_circuit::constants::MAX_INPUTS;
use transaction_circuit::poseidon_constants;
use transaction_core::constants::POSEIDON_ROUNDS;
use transaction_core::p3_air::CYCLE_LENGTH;

pub type Felt = Goldilocks;

pub const STEP_BITS: usize = 6;
pub const CYCLE_BITS: usize = 12;
pub const COL_STEP_BIT0: usize = BASE_TRACE_WIDTH;
pub const COL_CYCLE_BIT0: usize = COL_STEP_BIT0 + STEP_BITS;
pub const COL_PERM_MASK: usize = COL_CYCLE_BIT0 + CYCLE_BITS;
pub const COL_PERM_ACC: usize = COL_PERM_MASK + 1;
pub const COL_INPUT_CYCLE_MASK: usize = COL_PERM_ACC + 1;
pub const COL_INPUT_CYCLE_ACC: usize = COL_INPUT_CYCLE_MASK + 1;
pub const TRACE_WIDTH: usize = COL_INPUT_CYCLE_ACC + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBlockPublicInputsP3 {
    pub tx_proofs_commitment: [Felt; 4],
    pub starting_state_root: [Felt; 4],
    pub ending_state_root: [Felt; 4],
    pub nullifier_root: [Felt; 4],
    pub da_root: [Felt; 4],
    pub tx_count: u32,
    pub perm_alpha: Felt,
    pub perm_beta: Felt,
    pub nullifiers: Vec<[Felt; 4]>,
    pub sorted_nullifiers: Vec<[Felt; 4]>,
}

impl CommitmentBlockPublicInputsP3 {
    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(self.expected_len());
        elements.extend_from_slice(&self.tx_proofs_commitment);
        elements.extend_from_slice(&self.starting_state_root);
        elements.extend_from_slice(&self.ending_state_root);
        elements.extend_from_slice(&self.nullifier_root);
        elements.extend_from_slice(&self.da_root);
        elements.push(Felt::from_canonical_u64(self.tx_count as u64));
        elements.push(self.perm_alpha);
        elements.push(self.perm_beta);
        for nf in &self.nullifiers {
            elements.extend_from_slice(nf);
        }
        for nf in &self.sorted_nullifiers {
            elements.extend_from_slice(nf);
        }
        elements
    }

    pub fn try_from_slice(elements: &[Felt]) -> Result<Self, String> {
        let base_len = 23;
        if elements.len() < base_len || (elements.len() - base_len) % 8 != 0 {
            return Err("commitment public inputs length mismatch".into());
        }
        let nullifier_count = (elements.len() - base_len) / 8;
        let mut idx = 0usize;
        let tx_proofs_commitment = slice4(elements, &mut idx);
        let starting_state_root = slice4(elements, &mut idx);
        let ending_state_root = slice4(elements, &mut idx);
        let nullifier_root = slice4(elements, &mut idx);
        let da_root = slice4(elements, &mut idx);
        let tx_count = elements[idx].as_canonical_u64() as u32;
        idx += 1;
        let perm_alpha = elements[idx];
        idx += 1;
        let perm_beta = elements[idx];
        idx += 1;
        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            nullifiers.push(slice4(elements, &mut idx));
        }
        let mut sorted_nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            sorted_nullifiers.push(slice4(elements, &mut idx));
        }

        Ok(Self {
            tx_proofs_commitment,
            starting_state_root,
            ending_state_root,
            nullifier_root,
            da_root,
            tx_count,
            perm_alpha,
            perm_beta,
            nullifiers,
            sorted_nullifiers,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.tx_count == 0 {
            return Err("tx_count cannot be zero".into());
        }
        let expected = (self.tx_count as usize).saturating_mul(MAX_INPUTS);
        if self.nullifiers.len() != expected {
            return Err("nullifier length mismatch".into());
        }
        if self.sorted_nullifiers.len() != expected {
            return Err("sorted nullifier length mismatch".into());
        }
        if self
            .sorted_nullifiers
            .windows(2)
            .any(|pair| limbs_to_bytes(&pair[0]) > limbs_to_bytes(&pair[1]))
        {
            return Err("sorted nullifiers are not ordered".into());
        }
        if self
            .nullifiers
            .iter()
            .all(|nf| nf.iter().all(|limb| limb.is_zero()))
        {
            return Err("nullifier list must include at least one non-zero entry".into());
        }
        Ok(())
    }

    fn expected_len(&self) -> usize {
        23 + self.nullifiers.len() * 8
    }
}

pub struct CommitmentBlockAirP3;

impl BaseAir<Felt> for CommitmentBlockAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

impl<AB> Air<AB> for CommitmentBlockAirP3
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
        let mut cycle_bits = Vec::with_capacity(CYCLE_BITS);
        let mut cycle_bits_next = Vec::with_capacity(CYCLE_BITS);
        for bit in 0..CYCLE_BITS {
            cycle_bits.push(current[COL_CYCLE_BIT0 + bit]);
            cycle_bits_next.push(next[COL_CYCLE_BIT0 + bit]);
        }

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

        let cycle_end = bit_selector(&step_bits, CYCLE_LENGTH - 1);
        let mut hash_flag = AB::Expr::zero();
        let mut rc0 = AB::Expr::zero();
        let mut rc1 = AB::Expr::zero();
        let mut rc2 = AB::Expr::zero();
        for round in 0..POSEIDON_ROUNDS {
            let sel = bit_selector(&step_bits, round);
            hash_flag += sel.clone();
            rc0 += sel.clone()
                * AB::Expr::from_canonical_u64(poseidon_constants::ROUND_CONSTANTS[round][0]);
            rc1 += sel.clone()
                * AB::Expr::from_canonical_u64(poseidon_constants::ROUND_CONSTANTS[round][1]);
            rc2 += sel * AB::Expr::from_canonical_u64(poseidon_constants::ROUND_CONSTANTS[round][2]);
        }

        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;
        let s0 = t0.exp_const_u64::<5>();
        let s1 = t1.exp_const_u64::<5>();
        let s2 = t2.exp_const_u64::<5>();

        let mds = poseidon_constants::MDS_MATRIX;
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
            when_first.assert_zero(current[COL_PERM_MASK] - one.clone());
            when_first.assert_zero(current[COL_PERM_ACC]);
            when_first.assert_zero(current[COL_INPUT_CYCLE_MASK] - one.clone());
            when_first.assert_zero(current[COL_INPUT_CYCLE_ACC]);
            when_first.assert_zero(current[COL_NF_PERM] - one.clone());
            when_first.assert_zero(
                current[COL_S0]
                    - (AB::Expr::from_canonical_u64(BLOCK_COMMITMENT_DOMAIN_TAG)
                        + current[COL_INPUT0]),
            );
            when_first.assert_zero(current[COL_S1] - current[COL_INPUT1]);
            when_first.assert_zero(current[COL_S2] - one.clone());
        }

        let public_values = builder.public_values();
        let base_len = 23;
        debug_assert!(public_values.len() >= base_len);
        debug_assert!((public_values.len() - base_len) % 8 == 0);
        let nullifier_count = (public_values.len() - base_len) / 8;
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let mut idx = 0usize;
        let output = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let start_root = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let end_root = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let nullifier_root = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let da_root = [pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)];
        idx += 4;
        let tx_count = pv(idx);
        idx += 1;
        let perm_alpha = pv(idx);
        idx += 1;
        let perm_beta = pv(idx);
        idx += 1;

        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            nullifiers.push([pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)]);
            idx += 4;
        }
        let mut sorted_nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            sorted_nullifiers.push([pv(idx), pv(idx + 1), pv(idx + 2), pv(idx + 3)]);
            idx += 4;
        }

        let is_last = builder.is_last_row();

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(current[COL_START_ROOT0] - start_root[0].clone());
            when_first.assert_zero(current[COL_START_ROOT1] - start_root[1].clone());
            when_first.assert_zero(current[COL_START_ROOT2] - start_root[2].clone());
            when_first.assert_zero(current[COL_START_ROOT3] - start_root[3].clone());
            when_first.assert_zero(current[COL_END_ROOT0] - end_root[0].clone());
            when_first.assert_zero(current[COL_END_ROOT1] - end_root[1].clone());
            when_first.assert_zero(current[COL_END_ROOT2] - end_root[2].clone());
            when_first.assert_zero(current[COL_END_ROOT3] - end_root[3].clone());
            when_first.assert_zero(current[COL_NULLIFIER_ROOT0] - nullifier_root[0].clone());
            when_first.assert_zero(current[COL_NULLIFIER_ROOT1] - nullifier_root[1].clone());
            when_first.assert_zero(current[COL_NULLIFIER_ROOT2] - nullifier_root[2].clone());
            when_first.assert_zero(current[COL_NULLIFIER_ROOT3] - nullifier_root[3].clone());
            when_first.assert_zero(current[COL_DA_ROOT0] - da_root[0].clone());
            when_first.assert_zero(current[COL_DA_ROOT1] - da_root[1].clone());
            when_first.assert_zero(current[COL_DA_ROOT2] - da_root[2].clone());
            when_first.assert_zero(current[COL_DA_ROOT3] - da_root[3].clone());
        }

        {
            let mut when = builder.when_transition();
            when.assert_zero(
                cycle_end.clone() * (next[COL_S0] - (current[COL_S0] + next[COL_INPUT0])),
            );
            when.assert_zero(
                cycle_end.clone() * (next[COL_S1] - (current[COL_S1] + next[COL_INPUT1])),
            );
            when.assert_zero(cycle_end.clone() * (next[COL_S2] - current[COL_S2]));
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

            let perm_mask = current[COL_PERM_MASK];
            let perm_mask_next = next[COL_PERM_MASK];
            let perm_acc = current[COL_PERM_ACC];
            let perm_acc_next = next[COL_PERM_ACC];
            when.assert_bool(perm_mask);
            when.assert_zero(perm_mask_next * (one.clone() - perm_mask));
            when.assert_zero(perm_acc_next - (perm_acc + perm_mask));

            let input_cycle_mask = current[COL_INPUT_CYCLE_MASK];
            let input_cycle_mask_next = next[COL_INPUT_CYCLE_MASK];
            let input_cycle_acc = current[COL_INPUT_CYCLE_ACC];
            let input_cycle_acc_next = next[COL_INPUT_CYCLE_ACC];
            when.assert_bool(input_cycle_mask);
            let not_cycle_end = one.clone() - cycle_end.clone();
            when.assert_zero(not_cycle_end * (input_cycle_mask_next - input_cycle_mask));
            when.assert_zero(
                cycle_end.clone() * input_cycle_mask_next * (one.clone() - input_cycle_mask),
            );
            when.assert_zero(
                input_cycle_acc_next - (input_cycle_acc + cycle_end.clone() * input_cycle_mask),
            );

            for col in [
                COL_START_ROOT0,
                COL_START_ROOT1,
                COL_START_ROOT2,
                COL_START_ROOT3,
                COL_END_ROOT0,
                COL_END_ROOT1,
                COL_END_ROOT2,
                COL_END_ROOT3,
                COL_NULLIFIER_ROOT0,
                COL_NULLIFIER_ROOT1,
                COL_NULLIFIER_ROOT2,
                COL_NULLIFIER_ROOT3,
                COL_DA_ROOT0,
                COL_DA_ROOT1,
                COL_DA_ROOT2,
                COL_DA_ROOT3,
            ] {
                when.assert_zero(next[col] - current[col]);
            }

            let alpha = perm_alpha;
            let beta = perm_beta;
            let alpha2 = alpha.clone() * alpha.clone();
            let alpha3 = alpha2.clone() * alpha.clone();

            let u0 = current[COL_NF_U0];
            let u1 = current[COL_NF_U1];
            let u2 = current[COL_NF_U2];
            let u3 = current[COL_NF_U3];
            let s0 = current[COL_NF_S0];
            let s1 = current[COL_NF_S1];
            let s2 = current[COL_NF_S2];
            let s3 = current[COL_NF_S3];

            let u = u0 + u1 * alpha.clone() + u2 * alpha2.clone() + u3 * alpha3.clone();
            let v = s0 + s1 * alpha.clone() + s2 * alpha2 + s3 * alpha3;
            let perm = current[COL_NF_PERM];
            let perm_inv = current[COL_NF_PERM_INV];
            let v_inv = current[COL_NF_SORTED_INV];
            let v_nz = current[COL_NF_SORTED_NZ];

            when.assert_zero(
                perm_mask * (next[COL_NF_PERM] - perm * (u + beta.clone()) * perm_inv),
            );
            when.assert_zero(perm_mask * ((v.clone() + beta.clone()) * perm_inv - one.clone()));
            when.assert_zero(perm_mask * (v.clone() * v_inv - v_nz));
            when.assert_zero(perm_mask * (v.clone() * (one.clone() - v_nz)));
            when.assert_zero(perm_mask * (v_nz * (v_nz - one.clone())));

            let next_v = next[COL_NF_S0]
                + next[COL_NF_S1] * alpha.clone()
                + next[COL_NF_S2] * alpha.clone() * alpha.clone()
                + next[COL_NF_S3] * alpha.clone() * alpha.clone() * alpha.clone();
            let diff = next_v - v;
            let diff_inv = current[COL_NF_DIFF_INV];
            let diff_nz = current[COL_NF_DIFF_NZ];
            let adj_mask = perm_mask * perm_mask_next;
            when.assert_zero(adj_mask.clone() * (diff.clone() * diff_inv - diff_nz));
            when.assert_zero(adj_mask.clone() * (diff * (one.clone() - diff_nz)));
            when.assert_zero(adj_mask.clone() * (diff_nz * (diff_nz - one.clone())));
            when.assert_zero(adj_mask * v_nz * (one.clone() - diff_nz));

            let perm_end = perm_mask * (one.clone() - perm_mask_next);
            when.assert_zero(perm_end * (next[COL_NF_PERM] - one.clone()));

            for (row, nf) in nullifiers.iter().enumerate() {
                let gate = row_selector(row);
                when.assert_zero(gate.clone() * (current[COL_NF_U0] - nf[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_NF_U1] - nf[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_NF_U2] - nf[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_NF_U3] - nf[3].clone()));
            }
            for (row, nf) in sorted_nullifiers.iter().enumerate() {
                let gate = row_selector(row);
                when.assert_zero(gate.clone() * (current[COL_NF_S0] - nf[0].clone()));
                when.assert_zero(gate.clone() * (current[COL_NF_S1] - nf[1].clone()));
                when.assert_zero(gate.clone() * (current[COL_NF_S2] - nf[2].clone()));
                when.assert_zero(gate.clone() * (current[COL_NF_S3] - nf[3].clone()));
            }

            let output0_marker =
                cycle_end.clone() * input_cycle_mask.clone() * (one.clone() - input_cycle_mask_next);
            when.assert_zero(output0_marker.clone() * (current[COL_S0] - output[0].clone()));
            when.assert_zero(output0_marker * (current[COL_S1] - output[1].clone()));
            when.assert_zero(is_last.clone() * (current[COL_S0] - output[2].clone()));
            when.assert_zero(is_last.clone() * (current[COL_S1] - output[3].clone()));

            let input_cycles = tx_count.clone() * AB::Expr::from_canonical_u64(2);
            let nullifier_count_expr = tx_count * AB::Expr::from_canonical_u64(MAX_INPUTS as u64);
            when.assert_zero(
                is_last.clone() * (input_cycle_acc + input_cycle_mask - input_cycles),
            );
            when.assert_zero(is_last * (perm_acc + perm_mask - nullifier_count_expr));
        }
    }
}

fn slice4(values: &[Felt], idx: &mut usize) -> [Felt; 4] {
    let slice = &values[*idx..*idx + 4];
    *idx += 4;
    [slice[0], slice[1], slice[2], slice[3]]
}

fn limbs_to_bytes(limbs: &[Felt; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, limb) in limbs.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&limb.as_canonical_u64().to_be_bytes());
    }
    out
}
