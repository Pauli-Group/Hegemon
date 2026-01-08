//! Plonky3 AIR for commitment block proofs.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::commitment_constants::{
    BLOCK_COMMITMENT_DOMAIN_TAG, COL_DA_ROOT0, COL_DA_ROOT1, COL_DA_ROOT2, COL_DA_ROOT3,
    COL_DA_ROOT4, COL_DA_ROOT5, COL_END_ROOT0, COL_END_ROOT1, COL_END_ROOT2, COL_END_ROOT3,
    COL_END_ROOT4, COL_END_ROOT5, COL_INPUT0, COL_INPUT1, COL_INPUT2, COL_INPUT3, COL_INPUT4,
    COL_INPUT5, COL_NF_DIFF_INV, COL_NF_DIFF_NZ, COL_NF_PERM, COL_NF_PERM_INV, COL_NF_S0,
    COL_NF_S1, COL_NF_S2, COL_NF_S3, COL_NF_S4, COL_NF_S5, COL_NF_SORTED_INV,
    COL_NF_SORTED_NZ, COL_NF_U0, COL_NF_U1, COL_NF_U2, COL_NF_U3, COL_NF_U4, COL_NF_U5,
    COL_NULLIFIER_ROOT0, COL_NULLIFIER_ROOT1, COL_NULLIFIER_ROOT2, COL_NULLIFIER_ROOT3,
    COL_NULLIFIER_ROOT4, COL_NULLIFIER_ROOT5, COL_S0, COL_S1, COL_S10, COL_S11, COL_S2, COL_S3,
    COL_S4, COL_S5, COL_S6, COL_S7, COL_S8, COL_S9, COL_START_ROOT0, COL_START_ROOT1,
    COL_START_ROOT2, COL_START_ROOT3, COL_START_ROOT4, COL_START_ROOT5,
    TRACE_WIDTH as BASE_TRACE_WIDTH,
};
use transaction_circuit::constants::MAX_INPUTS;
use transaction_core::constants::{
    POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS, POSEIDON2_STEPS, POSEIDON2_WIDTH,
};
use transaction_core::poseidon2_constants;
use transaction_core::p3_air::CYCLE_LENGTH;

pub type Felt = Goldilocks;

pub const STEP_BITS: usize = 6;
pub const CYCLE_BITS: usize = 12;

pub const PREP_HASH_FLAG: usize = 0;
pub const PREP_INIT_ROUND: usize = PREP_HASH_FLAG + 1;
pub const PREP_EXTERNAL_ROUND: usize = PREP_INIT_ROUND + 1;
pub const PREP_INTERNAL_ROUND: usize = PREP_EXTERNAL_ROUND + 1;
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
pub const PREP_CYCLE_END: usize = PREP_RC11 + 1;
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
    pub tx_proofs_commitment: [Felt; 6],
    pub starting_state_root: [Felt; 6],
    pub ending_state_root: [Felt; 6],
    pub nullifier_root: [Felt; 6],
    pub da_root: [Felt; 6],
    pub tx_count: u32,
    pub perm_alpha: Felt,
    pub perm_beta: Felt,
    pub nullifiers: Vec<[Felt; 6]>,
    pub sorted_nullifiers: Vec<[Felt; 6]>,
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
        let base_len = 33;
        if elements.len() < base_len || (elements.len() - base_len) % 12 != 0 {
            return Err("commitment public inputs length mismatch".into());
        }
        let nullifier_count = (elements.len() - base_len) / 12;
        let mut idx = 0usize;
        let tx_proofs_commitment = slice6(elements, &mut idx);
        let starting_state_root = slice6(elements, &mut idx);
        let ending_state_root = slice6(elements, &mut idx);
        let nullifier_root = slice6(elements, &mut idx);
        let da_root = slice6(elements, &mut idx);
        let tx_count = elements[idx].as_canonical_u64() as u32;
        idx += 1;
        let perm_alpha = elements[idx];
        idx += 1;
        let perm_beta = elements[idx];
        idx += 1;
        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            nullifiers.push(slice6(elements, &mut idx));
        }
        let mut sorted_nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            sorted_nullifiers.push(slice6(elements, &mut idx));
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
        33 + self.nullifiers.len() * 12
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
    tx_count.max(1)
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

        row_slice[PREP_HASH_FLAG] = Felt::from_bool(step < POSEIDON2_STEPS);
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
        let init_round: AB::Expr = prep[PREP_INIT_ROUND].clone().into();
        let external_round: AB::Expr = prep[PREP_EXTERNAL_ROUND].clone().into();
        let internal_round: AB::Expr = prep[PREP_INTERNAL_ROUND].clone().into();
        let rc0: AB::Expr = prep[PREP_RC0].clone().into();
        let rc1: AB::Expr = prep[PREP_RC1].clone().into();
        let rc2: AB::Expr = prep[PREP_RC2].clone().into();
        let rc3: AB::Expr = prep[PREP_RC3].clone().into();
        let rc4: AB::Expr = prep[PREP_RC4].clone().into();
        let rc5: AB::Expr = prep[PREP_RC5].clone().into();
        let rc6: AB::Expr = prep[PREP_RC6].clone().into();
        let rc7: AB::Expr = prep[PREP_RC7].clone().into();
        let rc8: AB::Expr = prep[PREP_RC8].clone().into();
        let rc9: AB::Expr = prep[PREP_RC9].clone().into();
        let rc10: AB::Expr = prep[PREP_RC10].clone().into();
        let rc11: AB::Expr = prep[PREP_RC11].clone().into();
        let cycle_end: AB::Expr = prep[PREP_CYCLE_END].clone().into();

        let perm_mask: AB::Expr = prep[PREP_PERM_MASK].clone().into();
        let perm_mask_next: AB::Expr = prep_next[PREP_PERM_MASK].clone().into();
        let perm_acc: AB::Expr = prep[PREP_PERM_ACC].clone().into();

        let input_cycle_mask: AB::Expr = prep[PREP_INPUT_CYCLE_MASK].clone().into();
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

        let copy_flag = one.clone() - hash_flag.clone() - cycle_end.clone();

        let in0: AB::Expr = next[COL_INPUT0].clone().into();
        let in1: AB::Expr = next[COL_INPUT1].clone().into();
        let in2: AB::Expr = next[COL_INPUT2].clone().into();
        let in3: AB::Expr = next[COL_INPUT3].clone().into();
        let in4: AB::Expr = next[COL_INPUT4].clone().into();
        let in5: AB::Expr = next[COL_INPUT5].clone().into();

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

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(current[COL_NF_PERM].clone() - one.clone());
            when_first.assert_zero(
                current[COL_S0].clone()
                    - (AB::Expr::from_u64(BLOCK_COMMITMENT_DOMAIN_TAG)
                        + current[COL_INPUT0].clone()),
            );
            when_first.assert_zero(current[COL_S1].clone() - current[COL_INPUT1].clone());
            when_first.assert_zero(current[COL_S2].clone() - current[COL_INPUT2].clone());
            when_first.assert_zero(current[COL_S3].clone() - current[COL_INPUT3].clone());
            when_first.assert_zero(current[COL_S4].clone() - current[COL_INPUT4].clone());
            when_first.assert_zero(current[COL_S5].clone() - current[COL_INPUT5].clone());
            when_first.assert_zero(current[COL_S6].clone());
            when_first.assert_zero(current[COL_S7].clone());
            when_first.assert_zero(current[COL_S8].clone());
            when_first.assert_zero(current[COL_S9].clone());
            when_first.assert_zero(current[COL_S10].clone());
            when_first.assert_zero(current[COL_S11].clone() - one.clone());
        }

        let public_values = builder.public_values();
        let base_len = 33;
        debug_assert!(public_values.len() >= base_len);
        debug_assert!((public_values.len() - base_len) % 12 == 0);
        let nullifier_count = (public_values.len() - base_len) / 12;
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let mut idx = 0usize;
        let output = [
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let start_root = [
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let end_root = [
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let nullifier_root = [
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let da_root = [
            pv(idx),
            pv(idx + 1),
            pv(idx + 2),
            pv(idx + 3),
            pv(idx + 4),
            pv(idx + 5),
        ];
        idx += 6;
        let tx_count = pv(idx);
        idx += 1;
        let perm_alpha = pv(idx);
        idx += 1;
        let perm_beta = pv(idx);
        idx += 1;

        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            nullifiers.push([
                pv(idx),
                pv(idx + 1),
                pv(idx + 2),
                pv(idx + 3),
                pv(idx + 4),
                pv(idx + 5),
            ]);
            idx += 6;
        }
        let mut sorted_nullifiers = Vec::with_capacity(nullifier_count);
        for _ in 0..nullifier_count {
            sorted_nullifiers.push([
                pv(idx),
                pv(idx + 1),
                pv(idx + 2),
                pv(idx + 3),
                pv(idx + 4),
                pv(idx + 5),
            ]);
            idx += 6;
        }

        {
            let mut when_first = builder.when_first_row();
            when_first.assert_zero(current[COL_START_ROOT0].clone() - start_root[0].clone());
            when_first.assert_zero(current[COL_START_ROOT1].clone() - start_root[1].clone());
            when_first.assert_zero(current[COL_START_ROOT2].clone() - start_root[2].clone());
            when_first.assert_zero(current[COL_START_ROOT3].clone() - start_root[3].clone());
            when_first.assert_zero(current[COL_START_ROOT4].clone() - start_root[4].clone());
            when_first.assert_zero(current[COL_START_ROOT5].clone() - start_root[5].clone());
            when_first.assert_zero(current[COL_END_ROOT0].clone() - end_root[0].clone());
            when_first.assert_zero(current[COL_END_ROOT1].clone() - end_root[1].clone());
            when_first.assert_zero(current[COL_END_ROOT2].clone() - end_root[2].clone());
            when_first.assert_zero(current[COL_END_ROOT3].clone() - end_root[3].clone());
            when_first.assert_zero(current[COL_END_ROOT4].clone() - end_root[4].clone());
            when_first.assert_zero(current[COL_END_ROOT5].clone() - end_root[5].clone());
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
            when_first.assert_zero(
                current[COL_NULLIFIER_ROOT4].clone() - nullifier_root[4].clone(),
            );
            when_first.assert_zero(
                current[COL_NULLIFIER_ROOT5].clone() - nullifier_root[5].clone(),
            );
            when_first.assert_zero(current[COL_DA_ROOT0].clone() - da_root[0].clone());
            when_first.assert_zero(current[COL_DA_ROOT1].clone() - da_root[1].clone());
            when_first.assert_zero(current[COL_DA_ROOT2].clone() - da_root[2].clone());
            when_first.assert_zero(current[COL_DA_ROOT3].clone() - da_root[3].clone());
            when_first.assert_zero(current[COL_DA_ROOT4].clone() - da_root[4].clone());
            when_first.assert_zero(current[COL_DA_ROOT5].clone() - da_root[5].clone());
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
                    + cycle_end.clone() * absorb_state[idx].clone();
                when.assert_zero(next[state_cols[idx]].clone() - expected);
            }

            for col in [
                COL_START_ROOT0,
                COL_START_ROOT1,
                COL_START_ROOT2,
                COL_START_ROOT3,
                COL_START_ROOT4,
                COL_START_ROOT5,
                COL_END_ROOT0,
                COL_END_ROOT1,
                COL_END_ROOT2,
                COL_END_ROOT3,
                COL_END_ROOT4,
                COL_END_ROOT5,
                COL_NULLIFIER_ROOT0,
                COL_NULLIFIER_ROOT1,
                COL_NULLIFIER_ROOT2,
                COL_NULLIFIER_ROOT3,
                COL_NULLIFIER_ROOT4,
                COL_NULLIFIER_ROOT5,
                COL_DA_ROOT0,
                COL_DA_ROOT1,
                COL_DA_ROOT2,
                COL_DA_ROOT3,
                COL_DA_ROOT4,
                COL_DA_ROOT5,
            ] {
                when.assert_zero(next[col].clone() - current[col].clone());
            }

            let alpha = perm_alpha;
            let beta = perm_beta;
            let alpha2 = alpha.clone() * alpha.clone();
            let alpha3 = alpha2.clone() * alpha.clone();
            let alpha4 = alpha3.clone() * alpha.clone();
            let alpha5 = alpha4.clone() * alpha.clone();

            let u0 = current[COL_NF_U0].clone();
            let u1 = current[COL_NF_U1].clone();
            let u2 = current[COL_NF_U2].clone();
            let u3 = current[COL_NF_U3].clone();
            let u4 = current[COL_NF_U4].clone();
            let u5 = current[COL_NF_U5].clone();
            let s0 = current[COL_NF_S0].clone();
            let s1 = current[COL_NF_S1].clone();
            let s2 = current[COL_NF_S2].clone();
            let s3 = current[COL_NF_S3].clone();
            let s4 = current[COL_NF_S4].clone();
            let s5 = current[COL_NF_S5].clone();

            let u = u0
                + u1 * alpha.clone()
                + u2 * alpha2.clone()
                + u3 * alpha3.clone()
                + u4 * alpha4.clone()
                + u5 * alpha5.clone();
            let v = s0
                + s1 * alpha.clone()
                + s2 * alpha2.clone()
                + s3 * alpha3.clone()
                + s4 * alpha4.clone()
                + s5 * alpha5.clone();
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
                + next[COL_NF_S2].clone() * alpha2.clone()
                + next[COL_NF_S3].clone() * alpha3.clone()
                + next[COL_NF_S4].clone() * alpha4.clone()
                + next[COL_NF_S5].clone() * alpha5.clone();
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
        }

        for (row, nf) in nullifiers.iter().enumerate() {
            let gate = row_selector(row);
            builder.assert_zero(gate.clone() * (current[COL_NF_U0].clone() - nf[0].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U1].clone() - nf[1].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U2].clone() - nf[2].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U3].clone() - nf[3].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U4].clone() - nf[4].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_U5].clone() - nf[5].clone()));
        }
        for (row, nf) in sorted_nullifiers.iter().enumerate() {
            let gate = row_selector(row);
            builder.assert_zero(gate.clone() * (current[COL_NF_S0].clone() - nf[0].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S1].clone() - nf[1].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S2].clone() - nf[2].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S3].clone() - nf[3].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S4].clone() - nf[4].clone()));
            builder.assert_zero(gate.clone() * (current[COL_NF_S5].clone() - nf[5].clone()));
        }

        {
            let mut when_last = builder.when_last_row();
            when_last.assert_zero(current[COL_S0].clone() - output[0].clone());
            when_last.assert_zero(current[COL_S1].clone() - output[1].clone());
            when_last.assert_zero(current[COL_S2].clone() - output[2].clone());
            when_last.assert_zero(current[COL_S3].clone() - output[3].clone());
            when_last.assert_zero(current[COL_S4].clone() - output[4].clone());
            when_last.assert_zero(current[COL_S5].clone() - output[5].clone());

            let input_cycles = tx_count.clone();
            let nullifier_count_expr = tx_count * AB::Expr::from_u64(MAX_INPUTS as u64);
            when_last.assert_zero(input_cycle_acc + input_cycle_mask - input_cycles);
            when_last.assert_zero(perm_acc + perm_mask.clone() - nullifier_count_expr);
        }
    }
}

fn slice6(values: &[Felt], idx: &mut usize) -> [Felt; 6] {
    let slice = &values[*idx..*idx + 6];
    *idx += 6;
    [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5]]
}

fn limbs_to_bytes(limbs: &[Felt; 6]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (idx, limb) in limbs.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&limb.as_canonical_u64().to_be_bytes());
    }
    out
}
