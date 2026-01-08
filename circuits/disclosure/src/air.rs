//! Plonky3 AIR for disclosure circuit proofs.
//!
//! Proves knowledge of rho and r such that the note commitment matches
//! the public claim (value, asset_id, pk_recipient, commitment).

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::constants::{
    CYCLE_LENGTH, DUMMY_CYCLES, INPUT_CHUNKS, NOTE_DOMAIN_TAG, POSEIDON2_STEPS, POSEIDON2_WIDTH,
    TRACE_WIDTH,
};
use transaction_core::constants::{POSEIDON2_EXTERNAL_ROUNDS, POSEIDON2_INTERNAL_ROUNDS};
use transaction_core::poseidon2_constants;

pub type Felt = Goldilocks;

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;
pub const COL_S3: usize = 3;
pub const COL_S4: usize = 4;
pub const COL_S5: usize = 5;
pub const COL_S6: usize = 6;
pub const COL_S7: usize = 7;
pub const COL_S8: usize = 8;
pub const COL_S9: usize = 9;
pub const COL_S10: usize = 10;
pub const COL_S11: usize = 11;

pub const COL_IN0: usize = 12;
pub const COL_IN1: usize = 13;
pub const COL_IN2: usize = 14;
pub const COL_IN3: usize = 15;
pub const COL_IN4: usize = 16;
pub const COL_IN5: usize = 17;

pub const COL_RESET: usize = 18;
pub const COL_DOMAIN: usize = 19;

pub fn absorb_row(cycle: usize) -> usize {
    cycle * CYCLE_LENGTH + (CYCLE_LENGTH - 1)
}

pub fn commitment_row() -> usize {
    let last_cycle = DUMMY_CYCLES + INPUT_CHUNKS - 1;
    absorb_row(last_cycle)
}

// ================================================================================================
// PREPROCESSED COLUMNS (fixed schedule)
// ================================================================================================

pub const PREP_HASH_FLAG: usize = 0;
pub const PREP_ABSORB_FLAG: usize = PREP_HASH_FLAG + 1;
pub const PREP_INIT_ROUND: usize = PREP_ABSORB_FLAG + 1;
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
pub const PREP_RESET: usize = PREP_RC11 + 1;
pub const PREP_DOMAIN: usize = PREP_RESET + 1;
pub const PREP_INPUT_ROW: usize = PREP_DOMAIN + 1;
pub const PREP_COMMITMENT_ROW: usize = PREP_INPUT_ROW + 1;
pub const PREPROCESSED_WIDTH: usize = PREP_COMMITMENT_ROW + 1;

#[derive(Clone, Debug)]
pub struct DisclosurePublicInputsP3 {
    pub value: Felt,
    pub asset_id: Felt,
    pub pk_recipient: [Felt; 4],
    pub commitment: [Felt; 6],
}

impl DisclosurePublicInputsP3 {
    pub fn expected_len() -> usize {
        12
    }

    pub fn to_vec(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(Self::expected_len());
        elements.push(self.value);
        elements.push(self.asset_id);
        elements.extend_from_slice(&self.pk_recipient);
        elements.extend_from_slice(&self.commitment);
        elements
    }

    pub fn try_from_slice(elements: &[Felt]) -> Result<Self, String> {
        if elements.len() != Self::expected_len() {
            return Err(format!(
                "disclosure public inputs length mismatch: expected {}, got {}",
                Self::expected_len(),
                elements.len()
            ));
        }
        let value = elements[0];
        let asset_id = elements[1];
        let pk_recipient = [elements[2], elements[3], elements[4], elements[5]];
        let commitment = [
            elements[6],
            elements[7],
            elements[8],
            elements[9],
            elements[10],
            elements[11],
        ];
        Ok(Self {
            value,
            asset_id,
            pk_recipient,
            commitment,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

fn build_preprocessed_trace(trace_len: usize) -> RowMajorMatrix<Felt> {
    let mut values = vec![Felt::ZERO; trace_len * PREPROCESSED_WIDTH];
    let input_row = absorb_row(0);
    let commitment_row = commitment_row();

    for row in 0..trace_len {
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

        if step == CYCLE_LENGTH - 1 {
            if cycle < INPUT_CHUNKS {
                if cycle == 0 {
                    row_slice[PREP_RESET] = Felt::ONE;
                    row_slice[PREP_DOMAIN] = Felt::from_u64(NOTE_DOMAIN_TAG);
                }
            }
            if row == input_row {
                row_slice[PREP_INPUT_ROW] = Felt::ONE;
            }
            if row == commitment_row {
                row_slice[PREP_COMMITMENT_ROW] = Felt::ONE;
            }
        }
    }

    RowMajorMatrix::new(values, PREPROCESSED_WIDTH)
}

pub struct DisclosureAirP3 {
    trace_len: usize,
}

impl DisclosureAirP3 {
    pub fn new(trace_len: usize) -> Self {
        Self { trace_len }
    }
}

impl BaseAir<Felt> for DisclosureAirP3 {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        Some(build_preprocessed_trace(self.trace_len))
    }
}

impl<AB> Air<AB> for DisclosureAirP3
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
        let prep_reset: AB::Expr = prep_row[PREP_RESET].clone().into();
        let prep_domain: AB::Expr = prep_row[PREP_DOMAIN].clone().into();
        let prep_input_row: AB::Expr = prep_row[PREP_INPUT_ROW].clone().into();
        let prep_commitment_row: AB::Expr = prep_row[PREP_COMMITMENT_ROW].clone().into();

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

        let mut when = builder.when_transition();
        when.assert_zero(hash_flag.clone() - round_sum);
        for idx in 0..POSEIDON2_WIDTH {
            let expected = hash_flag.clone() * hash_state[idx].clone()
                + copy_flag.clone() * current_state[idx].clone()
                + absorb_flag.clone() * absorb_state[idx].clone();
            let next_col = match idx {
                0 => COL_S0,
                1 => COL_S1,
                2 => COL_S2,
                3 => COL_S3,
                4 => COL_S4,
                5 => COL_S5,
                6 => COL_S6,
                7 => COL_S7,
                8 => COL_S8,
                9 => COL_S9,
                10 => COL_S10,
                _ => COL_S11,
            };
            when.assert_zero(next[next_col].clone() - expected);
        }
        when.assert_zero(current[COL_RESET].clone() - prep_reset);
        when.assert_zero(current[COL_DOMAIN].clone() - prep_domain);

        let public_values = builder.public_values();
        let expected_len = DisclosurePublicInputsP3::expected_len();
        debug_assert_eq!(public_values.len(), expected_len);
        let pv = |index: usize| -> AB::Expr { public_values[index].into() };

        let value = pv(0);
        let asset_id = pv(1);
        let pk0 = pv(2);
        let pk1 = pv(3);
        let pk2 = pv(4);
        let pk3 = pv(5);
        let cm0 = pv(6);
        let cm1 = pv(7);
        let cm2 = pv(8);
        let cm3 = pv(9);
        let cm4 = pv(10);
        let cm5 = pv(11);

        builder
            .when(prep_input_row.clone())
            .assert_zero(current[COL_IN0].clone() - value);
        builder
            .when(prep_input_row.clone())
            .assert_zero(current[COL_IN1].clone() - asset_id);
        builder
            .when(prep_input_row.clone())
            .assert_zero(current[COL_IN2].clone() - pk0);
        builder
            .when(prep_input_row.clone())
            .assert_zero(current[COL_IN3].clone() - pk1);
        builder
            .when(prep_input_row.clone())
            .assert_zero(current[COL_IN4].clone() - pk2);
        builder
            .when(prep_input_row.clone())
            .assert_zero(current[COL_IN5].clone() - pk3);

        builder
            .when(prep_commitment_row.clone())
            .assert_zero(current[COL_S0].clone() - cm0);
        builder
            .when(prep_commitment_row.clone())
            .assert_zero(current[COL_S1].clone() - cm1);
        builder
            .when(prep_commitment_row.clone())
            .assert_zero(current[COL_S2].clone() - cm2);
        builder
            .when(prep_commitment_row.clone())
            .assert_zero(current[COL_S3].clone() - cm3);
        builder
            .when(prep_commitment_row.clone())
            .assert_zero(current[COL_S4].clone() - cm4);
        builder
            .when(prep_commitment_row.clone())
            .assert_zero(current[COL_S5].clone() - cm5);
    }
}
