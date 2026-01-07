//! Plonky3 AIR for commitment block proofs.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
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

pub const PREP_HASH_FLAG: usize = 0;
pub const PREP_RC0: usize = PREP_HASH_FLAG + 1;
pub const PREP_RC1: usize = PREP_RC0 + 1;
pub const PREP_RC2: usize = PREP_RC1 + 1;
pub const PREP_CYCLE_END: usize = PREP_RC2 + 1;
pub const PREP_STEP_BIT0: usize = PREP_CYCLE_END + 1;
pub const PREP_CYCLE_BIT0: usize = PREP_STEP_BIT0 + STEP_BITS;
pub const PREP_PERM_MASK: usize = PREP_CYCLE_BIT0 + CYCLE_BITS;
pub const PREP_PERM_ACC: usize = PREP_PERM_MASK + 1;
pub const PREP_INPUT_CYCLE_MASK: usize = PREP_PERM_ACC + 1;
pub const PREP_INPUT_CYCLE_ACC: usize = PREP_INPUT_CYCLE_MASK + 1;
pub const PREPROCESSED_WIDTH: usize = PREP_INPUT_CYCLE_ACC + 1;

pub const TRACE_WIDTH: usize = BASE_TRACE_WIDTH;

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
        elements.push(Felt::from_u64(self.tx_count as u64));
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
        let total_cycles = CommitmentBlockAirP3::trace_length(self.tx_count as usize) / CYCLE_LENGTH;
        if (total_cycles as u64) > (1u64 << CYCLE_BITS) {
            return Err("trace exceeds cycle counter capacity".into());
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

#[derive(Clone, Debug)]
pub struct CommitmentBlockAirP3 {
    trace_len: usize,
    nullifier_count: usize,
    input_cycles: usize,
}

impl CommitmentBlockAirP3 {
    pub fn new(tx_count: usize) -> Self {
        let input_cycles = input_cycles_for(tx_count);
        let trace_len = Self::trace_length(tx_count);
        let nullifier_count = tx_count.saturating_mul(MAX_INPUTS);
        Self {
            trace_len,
            nullifier_count,
            input_cycles,
        }
    }

    pub fn trace_length(tx_count: usize) -> usize {
        let input_cycles = input_cycles_for(tx_count);
        (input_cycles + 1).next_power_of_two() * CYCLE_LENGTH
    }
}

fn input_cycles_for(tx_count: usize) -> usize {
    let input_elements = tx_count.saturating_mul(4);
    ((input_elements + 1) / 2).max(1)
}

fn build_preprocessed_trace(
    trace_len: usize,
    nullifier_count: usize,
    input_cycles: usize,
) -> RowMajorMatrix<Felt> {
    let mut values = vec![Felt::ZERO; trace_len * PREPROCESSED_WIDTH];

    for row in 0..trace_len {
        let step = row % CYCLE_LENGTH;
        let cycle = row / CYCLE_LENGTH;
        let row_slice =
            &mut values[row * PREPROCESSED_WIDTH..(row + 1) * PREPROCESSED_WIDTH];

        row_slice[PREP_HASH_FLAG] = Felt::from_bool(step < POSEIDON_ROUNDS);
        if step < POSEIDON_ROUNDS {
            row_slice[PREP_RC0] = Felt::from_u64(poseidon_constants::ROUND_CONSTANTS[step][0]);
            row_slice[PREP_RC1] = Felt::from_u64(poseidon_constants::ROUND_CONSTANTS[step][1]);
            row_slice[PREP_RC2] = Felt::from_u64(poseidon_constants::ROUND_CONSTANTS[step][2]);
        }
        row_slice[PREP_CYCLE_END] = Felt::from_bool(step + 1 == CYCLE_LENGTH);

        for bit in 0..STEP_BITS {
            row_slice[PREP_STEP_BIT0 + bit] = Felt::from_bool(((step >> bit) & 1) == 1);
        }
        for bit in 0..CYCLE_BITS {
            row_slice[PREP_CYCLE_BIT0 + bit] = Felt::from_bool(((cycle >> bit) & 1) == 1);
        }

        let perm_mask = row < nullifier_count;
        row_slice[PREP_PERM_MASK] = Felt::from_bool(perm_mask);
        let perm_acc = if row < nullifier_count {
            row as u64
        } else {
            nullifier_count as u64
        };
        row_slice[PREP_PERM_ACC] = Felt::from_u64(perm_acc);

        let input_cycle_mask = cycle < input_cycles;
        row_slice[PREP_INPUT_CYCLE_MASK] = Felt::from_bool(input_cycle_mask);
        let input_cycle_acc = if cycle < input_cycles {
            cycle as u64
        } else {
            input_cycles as u64
        };
        row_slice[PREP_INPUT_CYCLE_ACC] = Felt::from_u64(input_cycle_acc);
    }

    RowMajorMatrix::new(values, PREPROCESSED_WIDTH)
}

impl BaseAir<Felt> for CommitmentBlockAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(build_preprocessed_trace(
            self.trace_len,
            self.nullifier_count,
            self.input_cycles,
        ))
    }
}

impl<AB> Air<AB> for CommitmentBlockAirP3
where
    AB: AirBuilderWithPublicValues<F = Felt> + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.row_slice(0).expect("trace must have >= 1 row");
        let next = main.row_slice(1).expect("trace must have >= 2 rows");
        let preprocessed = builder.preprocessed();
        let prep = preprocessed
            .row_slice(0)
            .expect("preprocessed trace must have >= 1 row");
        let prep_next = preprocessed
            .row_slice(1)
            .expect("preprocessed trace must have >= 2 rows");

        let one = AB::Expr::ONE;

        let hash_flag: AB::Expr = prep[PREP_HASH_FLAG].clone().into();
        let rc0: AB::Expr = prep[PREP_RC0].clone().into();
        let rc1: AB::Expr = prep[PREP_RC1].clone().into();
        let rc2: AB::Expr = prep[PREP_RC2].clone().into();
        let cycle_end: AB::Expr = prep[PREP_CYCLE_END].clone().into();

        let perm_mask: AB::Expr = prep[PREP_PERM_MASK].clone().into();
        let perm_mask_next: AB::Expr = prep_next[PREP_PERM_MASK].clone().into();
        let perm_acc: AB::Expr = prep[PREP_PERM_ACC].clone().into();

        let input_cycle_mask: AB::Expr = prep[PREP_INPUT_CYCLE_MASK].clone().into();
        let input_cycle_mask_next: AB::Expr = prep_next[PREP_INPUT_CYCLE_MASK].clone().into();
        let input_cycle_acc: AB::Expr = prep[PREP_INPUT_CYCLE_ACC].clone().into();

        let step_bits: Vec<AB::Expr> = (0..STEP_BITS)
            .map(|bit| prep[PREP_STEP_BIT0 + bit].clone().into())
            .collect();
        let cycle_bits: Vec<AB::Expr> = (0..CYCLE_BITS)
            .map(|bit| prep[PREP_CYCLE_BIT0 + bit].clone().into())
            .collect();

        let bit_selector = |bits: &[AB::Expr], value: usize| -> AB::Expr {
            let mut acc = one.clone();
            for (idx, bit) in bits.iter().enumerate() {
                if ((value >> idx) & 1) == 1 {
                    acc = acc * bit.clone();
                } else {
                    acc = acc * (one.clone() - bit.clone());
                }
            }
            acc
        };

        let row_selector = |row: usize| -> AB::Expr {
            let cycle = row / CYCLE_LENGTH;
            let step = row % CYCLE_LENGTH;
            bit_selector(&cycle_bits, cycle) * bit_selector(&step_bits, step)
        };

        let t0 = current[COL_S0].clone() + rc0;
        let t1 = current[COL_S1].clone() + rc1;
        let t2 = current[COL_S2].clone() + rc2;
        let s0 = t0.exp_const_u64::<5>();
        let s1 = t1.exp_const_u64::<5>();
        let s2 = t2.exp_const_u64::<5>();

        let mds = poseidon_constants::MDS_MATRIX;
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

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(current[COL_NF_PERM].clone() - one.clone());
            when_first.assert_zero(
                current[COL_S0].clone()
                    - (AB::Expr::from_u64(BLOCK_COMMITMENT_DOMAIN_TAG)
                        + current[COL_INPUT0].clone()),
            );
            when_first.assert_zero(current[COL_S1].clone() - current[COL_INPUT1].clone());
            when_first.assert_zero(current[COL_S2].clone() - one.clone());
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

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(current[COL_START_ROOT0].clone() - start_root[0].clone());
            when_first.assert_zero(current[COL_START_ROOT1].clone() - start_root[1].clone());
            when_first.assert_zero(current[COL_START_ROOT2].clone() - start_root[2].clone());
            when_first.assert_zero(current[COL_START_ROOT3].clone() - start_root[3].clone());
            when_first.assert_zero(current[COL_END_ROOT0].clone() - end_root[0].clone());
            when_first.assert_zero(current[COL_END_ROOT1].clone() - end_root[1].clone());
            when_first.assert_zero(current[COL_END_ROOT2].clone() - end_root[2].clone());
            when_first.assert_zero(current[COL_END_ROOT3].clone() - end_root[3].clone());
            when_first.assert_zero(
                current[COL_NULLIFIER_ROOT0].clone() - nullifier_root[0].clone(),
            );
            when_first.assert_zero(
                current[COL_NULLIFIER_ROOT1].clone() - nullifier_root[1].clone(),
            );
            when_first.assert_zero(
                current[COL_NULLIFIER_ROOT2].clone() - nullifier_root[2].clone(),
            );
            when_first.assert_zero(
                current[COL_NULLIFIER_ROOT3].clone() - nullifier_root[3].clone(),
            );
            when_first.assert_zero(current[COL_DA_ROOT0].clone() - da_root[0].clone());
            when_first.assert_zero(current[COL_DA_ROOT1].clone() - da_root[1].clone());
            when_first.assert_zero(current[COL_DA_ROOT2].clone() - da_root[2].clone());
            when_first.assert_zero(current[COL_DA_ROOT3].clone() - da_root[3].clone());
        }

        {
            let mut when = builder.when_transition();
            when.assert_zero(
                cycle_end.clone()
                    * (next[COL_S0].clone()
                        - (current[COL_S0].clone() + next[COL_INPUT0].clone())),
            );
            when.assert_zero(
                cycle_end.clone()
                    * (next[COL_S1].clone()
                        - (current[COL_S1].clone() + next[COL_INPUT1].clone())),
            );
            when.assert_zero(
                cycle_end.clone() * (next[COL_S2].clone() - current[COL_S2].clone()),
            );
            when.assert_zero(hash_flag.clone() * (next[COL_S0].clone() - hash_s0));
            when.assert_zero(hash_flag.clone() * (next[COL_S1].clone() - hash_s1));
            when.assert_zero(hash_flag * (next[COL_S2].clone() - hash_s2));

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
                when.assert_zero(next[col].clone() - current[col].clone());
            }

            let alpha = perm_alpha;
            let beta = perm_beta;
            let alpha2 = alpha.clone() * alpha.clone();
            let alpha3 = alpha2.clone() * alpha.clone();

            let u0 = current[COL_NF_U0].clone();
            let u1 = current[COL_NF_U1].clone();
            let u2 = current[COL_NF_U2].clone();
            let u3 = current[COL_NF_U3].clone();
            let s0 = current[COL_NF_S0].clone();
            let s1 = current[COL_NF_S1].clone();
            let s2 = current[COL_NF_S2].clone();
            let s3 = current[COL_NF_S3].clone();

            let u = u0 + u1 * alpha.clone() + u2 * alpha2.clone() + u3 * alpha3.clone();
            let v = s0 + s1 * alpha.clone() + s2 * alpha2 + s3 * alpha3;
            let perm = current[COL_NF_PERM].clone();
            let perm_inv = current[COL_NF_PERM_INV].clone();
            let v_inv = current[COL_NF_SORTED_INV].clone();
            let v_nz = current[COL_NF_SORTED_NZ].clone();

            when.assert_zero(
                perm_mask.clone()
                    * (next[COL_NF_PERM].clone()
                        - perm * (u + beta.clone()) * perm_inv.clone()),
            );
            when.assert_zero(
                perm_mask.clone() * ((v.clone() + beta.clone()) * perm_inv - one.clone()),
            );
            when.assert_zero(perm_mask.clone() * (v.clone() * v_inv - v_nz.clone()));
            when.assert_zero(perm_mask.clone() * (v.clone() * (one.clone() - v_nz.clone())));
            when.assert_zero(perm_mask.clone() * (v_nz.clone() * (v_nz.clone() - one.clone())));

            let next_v = next[COL_NF_S0].clone()
                + next[COL_NF_S1].clone() * alpha.clone()
                + next[COL_NF_S2].clone() * alpha.clone() * alpha.clone()
                + next[COL_NF_S3].clone() * alpha.clone() * alpha.clone() * alpha.clone();
            let diff = next_v - v;
            let diff_inv = current[COL_NF_DIFF_INV].clone();
            let diff_nz = current[COL_NF_DIFF_NZ].clone();
            let adj_mask = perm_mask.clone() * perm_mask_next.clone();
            when.assert_zero(adj_mask.clone() * (diff.clone() * diff_inv - diff_nz.clone()));
            when.assert_zero(adj_mask.clone() * (diff * (one.clone() - diff_nz.clone())));
            when.assert_zero(adj_mask.clone() * (diff_nz.clone() * (diff_nz.clone() - one.clone())));
            when.assert_zero(adj_mask * v_nz.clone() * (one.clone() - diff_nz));

            let perm_end = perm_mask.clone() * (one.clone() - perm_mask_next.clone());
            when.assert_zero(perm_end * (next[COL_NF_PERM].clone() - one.clone()));

            let output0_marker =
                cycle_end.clone()
                    * input_cycle_mask.clone()
                    * (one.clone() - input_cycle_mask_next.clone());
            when.assert_zero(
                output0_marker.clone() * (current[COL_S0].clone() - output[0].clone()),
            );
            when.assert_zero(output0_marker * (current[COL_S1].clone() - output[1].clone()));
        }

        for (row, nf) in nullifiers.iter().enumerate() {
            let gate = row_selector(row);
            builder.assert_zero(gate.clone() * (current[COL_NF_U0].clone() - nf[0].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U1].clone() - nf[1].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U2].clone() - nf[2].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U3].clone() - nf[3].clone()));
        }
        for (row, nf) in sorted_nullifiers.iter().enumerate() {
            let gate = row_selector(row);
            builder.assert_zero(gate.clone() * (current[COL_NF_S0].clone() - nf[0].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S1].clone() - nf[1].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S2].clone() - nf[2].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S3].clone() - nf[3].clone()));
        }

        {
            let mut when_last = builder.when_last_row();
            when_last.assert_zero(current[COL_S0].clone() - output[2].clone());
            when_last.assert_zero(current[COL_S1].clone() - output[3].clone());

            let input_cycles = tx_count.clone() * AB::Expr::from_u64(2);
            let nullifier_count_expr = tx_count * AB::Expr::from_u64(MAX_INPUTS as u64);
            when_last.assert_zero(input_cycle_acc + input_cycle_mask - input_cycles);
            when_last.assert_zero(perm_acc + perm_mask.clone() - nullifier_count_expr);
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
