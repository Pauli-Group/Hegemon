//! Plonky3 prover for the transaction circuit.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, prove};
use protocol_versioning::{TxFriProfile, VersionBinding};

use crate::constants::{
    CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_NOTE_VALUE, MAX_OUTPUTS, MERKLE_DOMAIN_TAG,
    NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
};
use crate::hashing_pq::{
    bytes48_to_felts, merkle_node, note_commitment, nullifier, prf_key, spend_auth_key, HashFelt,
};
use crate::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
use crate::p3_config::{
    build_tx_fri_profile_for_version, config_with_profile, default_build_tx_fri_profile,
    release_tx_fri_profile_for_version, TransactionProofP3,
};
use crate::witness::TransactionWitness;
use crate::TransactionCircuitError;
use transaction_core::constants::POSEIDON2_STEPS;
use transaction_core::p3_air::{
    build_schedule_trace, commitment_output_row, cycle_is_merkle_left, cycle_is_merkle_right,
    cycle_is_output, cycle_reset_domain, merkle_root_output_row, note_start_row_input,
    note_start_row_output, nullifier_output_row, TransactionAirP3, TransactionPublicInputsP3,
    COL_AUTH_DERIVED0, COL_AUTH_DERIVED1, COL_AUTH_DERIVED2, COL_AUTH_DERIVED3, COL_CT0_0,
    COL_CT0_1, COL_CT0_2, COL_CT0_3, COL_CT0_4, COL_CT0_5, COL_CT1_0, COL_CT1_1, COL_CT1_2,
    COL_CT1_3, COL_CT1_4, COL_CT1_5, COL_DIR, COL_DOMAIN, COL_FEE, COL_IN0, COL_IN0_ASSET,
    COL_IN0_SLOT_BIT0, COL_IN0_SLOT_BIT1, COL_IN0_VALUE, COL_IN1, COL_IN1_ASSET, COL_IN1_SLOT_BIT0,
    COL_IN1_SLOT_BIT1, COL_IN1_VALUE, COL_IN2, COL_IN3, COL_IN4, COL_IN5, COL_IN_ACTIVE0,
    COL_IN_ACTIVE1, COL_MERKLE_LEFT, COL_MERKLE_RIGHT, COL_OUT0, COL_OUT0_ASSET,
    COL_OUT0_SLOT_BIT0, COL_OUT0_SLOT_BIT1, COL_OUT0_VALUE, COL_OUT1, COL_OUT1_ASSET,
    COL_OUT1_SLOT_BIT0, COL_OUT1_SLOT_BIT1, COL_OUT1_VALUE, COL_OUT2, COL_OUT3, COL_OUT4, COL_OUT5,
    COL_OUT_ACTIVE0, COL_OUT_ACTIVE1, COL_PRF_DERIVED, COL_RANGE_LIMBS_START, COL_RESET, COL_RHO0,
    COL_RHO1, COL_RHO2, COL_RHO3, COL_S0, COL_S1, COL_S10, COL_S11, COL_S2, COL_S3, COL_S4, COL_S5,
    COL_S6, COL_S7, COL_S8, COL_S9, COL_SCHEDULE_START, COL_SLOT0_IN, COL_SLOT0_OUT, COL_SLOT1_IN,
    COL_SLOT1_OUT, COL_SLOT2_IN, COL_SLOT2_OUT, COL_SLOT3_IN, COL_SLOT3_OUT,
    COL_STABLECOIN_SLOT_BIT0, COL_STABLECOIN_SLOT_BIT1, COL_VALUE_BALANCE_MAG,
    COL_VALUE_BALANCE_SIGN, COMMITMENT_ABSORB_CYCLES, CYCLE_LENGTH, DUMMY_CYCLES,
    MERKLE_ABSORB_CYCLES, MIN_TRACE_LENGTH, NULLIFIER_ABSORB_CYCLES, PREPROCESSED_WIDTH,
    TOTAL_TRACE_CYCLES, TOTAL_USED_CYCLES, TRACE_WIDTH,
};
use transaction_core::poseidon2::poseidon2_step;
use transaction_core::range::{decompose_bounded_value, RANGE_LIMB_COUNT};

type Val = Goldilocks;

#[derive(Clone, Copy)]
struct CycleSpec {
    reset: bool,
    domain: u64,
    inputs: [Val; 6],
    dir: Val,
}

pub struct TransactionProverP3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionProofParams {
    pub log_blowup: usize,
    pub num_queries: usize,
}

impl TransactionProofParams {
    pub fn production() -> Self {
        let profile = default_build_tx_fri_profile();
        Self {
            log_blowup: profile.log_blowup_usize(),
            num_queries: profile.num_queries_usize(),
        }
    }

    pub fn production_for_version(version: VersionBinding) -> Self {
        let profile = build_tx_fri_profile_for_version(version);
        Self {
            log_blowup: profile.log_blowup_usize(),
            num_queries: profile.num_queries_usize(),
        }
    }

    pub fn release_for_version(version: VersionBinding) -> Self {
        let profile = release_tx_fri_profile_for_version(version);
        Self {
            log_blowup: profile.log_blowup_usize(),
            num_queries: profile.num_queries_usize(),
        }
    }

    pub fn recursion() -> Self {
        Self {
            log_blowup: std::env::var("HEGEMON_TX_RECURSION_LOG_BLOWUP")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
                .unwrap_or(3)
                .max(1),
            num_queries: std::env::var("HEGEMON_TX_RECURSION_NUM_QUERIES")
                .ok()
                .and_then(|raw| raw.parse::<usize>().ok())
                .unwrap_or(8)
                .max(1),
        }
    }
}

pub fn prewarm_transaction_prover_cache_p3(
    _params: TransactionProofParams,
) -> Result<(), TransactionCircuitError> {
    Ok(())
}

impl Default for TransactionProverP3 {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionProverP3 {
    pub fn new() -> Self {
        Self
    }

    pub fn build_trace(
        &self,
        witness: &TransactionWitness,
    ) -> Result<RowMajorMatrix<Val>, TransactionCircuitError> {
        let trace_len = MIN_TRACE_LENGTH;
        let mut trace = RowMajorMatrix::new(vec![Val::ZERO; trace_len * TRACE_WIDTH], TRACE_WIDTH);
        let schedule = build_schedule_trace();
        debug_assert_eq!(schedule.height(), trace_len);
        for row in 0..trace_len {
            let schedule_row = schedule.row_slice(row).expect("schedule row missing");
            let row_slice = trace.row_mut(row);
            row_slice[COL_SCHEDULE_START..COL_SCHEDULE_START + PREPROCESSED_WIDTH]
                .copy_from_slice(&*schedule_row);
        }

        let (input_notes, input_flags) = pad_inputs(&witness.inputs);
        let (output_notes, output_flags) = pad_outputs(&witness.outputs);

        let slots = witness.balance_slots()?;
        let slot_assets: Vec<u64> = slots.iter().map(|slot| slot.asset_id).collect();
        let selector_bits = build_selector_bits(
            &input_notes,
            &output_notes,
            &slot_assets,
            &input_flags,
            &output_flags,
        );

        let (vb_sign, vb_mag) = value_balance_parts(witness.value_balance)?;
        let fee = Val::from_u64(witness.fee);
        let stablecoin_inputs = stablecoin_binding_inputs(witness, &slot_assets)?;
        let sk_words = bytes32_to_vals(&witness.sk_spend);
        let derived_prf = prf_key(&witness.sk_spend);
        let derived_auth = spend_auth_key(&witness.sk_spend);
        let in0_rho_words = bytes32_to_vals(&input_notes[0].note.rho);
        let in1_rho_words = bytes32_to_vals(&input_notes[1].note.rho);
        let vb_mag_u64 = u64::try_from(witness.value_balance.unsigned_abs()).map_err(|_| {
            TransactionCircuitError::ValueBalanceOutOfRange(witness.value_balance.unsigned_abs())
        })?;
        let issuance_mag_u64 = u64::try_from(witness.stablecoin.issuance_delta.unsigned_abs())
            .map_err(|_| {
                TransactionCircuitError::ValueBalanceOutOfRange(
                    witness.stablecoin.issuance_delta.unsigned_abs(),
                )
            })?;
        let mut ciphertext_hashes: Vec<[Val; 6]> = witness
            .ciphertext_hashes
            .iter()
            .map(bytes48_to_vals)
            .collect::<Result<_, _>>()?;
        while ciphertext_hashes.len() < MAX_OUTPUTS {
            ciphertext_hashes.push([Val::ZERO; 6]);
        }

        let sentinel_row = 0;
        let slot_in_cols = [COL_SLOT0_IN, COL_SLOT1_IN, COL_SLOT2_IN, COL_SLOT3_IN];
        let slot_out_cols = [COL_SLOT0_OUT, COL_SLOT1_OUT, COL_SLOT2_OUT, COL_SLOT3_OUT];
        let selector_bit_cols = [
            [COL_IN0_SLOT_BIT0, COL_IN0_SLOT_BIT1],
            [COL_IN1_SLOT_BIT0, COL_IN1_SLOT_BIT1],
            [COL_OUT0_SLOT_BIT0, COL_OUT0_SLOT_BIT1],
            [COL_OUT1_SLOT_BIT0, COL_OUT1_SLOT_BIT1],
        ];
        let sentinel_cols = [
            COL_IN_ACTIVE0,
            COL_IN_ACTIVE1,
            COL_OUT_ACTIVE0,
            COL_OUT_ACTIVE1,
            COL_IN0_VALUE,
            COL_IN0_ASSET,
            COL_IN1_VALUE,
            COL_IN1_ASSET,
            COL_OUT0_VALUE,
            COL_OUT0_ASSET,
            COL_OUT1_VALUE,
            COL_OUT1_ASSET,
            COL_FEE,
            COL_VALUE_BALANCE_SIGN,
            COL_VALUE_BALANCE_MAG,
        ];

        {
            let row_slice = trace.row_mut(sentinel_row);
            for &col in sentinel_cols.iter() {
                row_slice[col] = Val::ONE;
            }
            for cols in selector_bit_cols.iter() {
                for &col in cols.iter() {
                    row_slice[col] = Val::ONE;
                }
            }
        }

        for row in 0..trace_len {
            let row_slice = trace.row_mut(row);
            row_slice[COL_PRF_DERIVED] = derived_prf;
            row_slice[COL_AUTH_DERIVED0] = derived_auth[0];
            row_slice[COL_AUTH_DERIVED1] = derived_auth[1];
            row_slice[COL_AUTH_DERIVED2] = derived_auth[2];
            row_slice[COL_AUTH_DERIVED3] = derived_auth[3];
        }

        let rho0_start = transaction_core::p3_air::commitment_rho_row(0);
        let rho1_start = transaction_core::p3_air::commitment_rho_row(1);
        for row in rho0_start..trace_len.min(rho1_start) {
            let row_slice = trace.row_mut(row);
            row_slice[COL_RHO0] = in0_rho_words[0];
            row_slice[COL_RHO1] = in0_rho_words[1];
            row_slice[COL_RHO2] = in0_rho_words[2];
            row_slice[COL_RHO3] = in0_rho_words[3];
        }
        for row in rho1_start..trace_len {
            let row_slice = trace.row_mut(row);
            row_slice[COL_RHO0] = in1_rho_words[0];
            row_slice[COL_RHO1] = in1_rho_words[1];
            row_slice[COL_RHO2] = in1_rho_words[2];
            row_slice[COL_RHO3] = in1_rho_words[3];
        }

        let set_range_limbs = |row_slice: &mut [Val],
                               limbs_start: usize,
                               value: u64|
         -> Result<(), TransactionCircuitError> {
            if u128::from(value) > MAX_NOTE_VALUE {
                return Err(TransactionCircuitError::ValueOutOfRange(u128::from(value)));
            }
            let limbs = decompose_bounded_value(value);
            for limb_idx in 0..RANGE_LIMB_COUNT {
                row_slice[limbs_start + limb_idx] = Val::from_u64(u64::from(limbs[limb_idx]));
            }
            Ok(())
        };

        let start_row_in0 = note_start_row_input(0);
        let start_row_in1 = note_start_row_input(1);
        let start_row_out0 = note_start_row_output(0);
        let start_row_out1 = note_start_row_output(1);
        if start_row_in0 < trace_len {
            let row_slice = trace.row_mut(start_row_in0);
            row_slice[COL_IN_ACTIVE0] = flag_to_felt(input_flags[0]);
            row_slice[COL_IN0_VALUE] = Val::from_u64(input_notes[0].note.value);
            row_slice[COL_IN0_ASSET] = Val::from_u64(input_notes[0].note.asset_id);
            set_range_limbs(row_slice, COL_RANGE_LIMBS_START, input_notes[0].note.value)?;
            row_slice[selector_bit_cols[0][0]] = selector_bits[0][0];
            row_slice[selector_bit_cols[0][1]] = selector_bits[0][1];
        }
        if start_row_in1 < trace_len {
            let row_slice = trace.row_mut(start_row_in1);
            row_slice[COL_IN_ACTIVE1] = flag_to_felt(input_flags[1]);
            row_slice[COL_IN1_VALUE] = Val::from_u64(input_notes[1].note.value);
            row_slice[COL_IN1_ASSET] = Val::from_u64(input_notes[1].note.asset_id);
            set_range_limbs(row_slice, COL_RANGE_LIMBS_START, input_notes[1].note.value)?;
            row_slice[selector_bit_cols[1][0]] = selector_bits[1][0];
            row_slice[selector_bit_cols[1][1]] = selector_bits[1][1];
        }
        if start_row_out0 < trace_len {
            let row_slice = trace.row_mut(start_row_out0);
            row_slice[COL_OUT_ACTIVE0] = flag_to_felt(output_flags[0]);
            row_slice[COL_OUT0_VALUE] = Val::from_u64(output_notes[0].note.value);
            row_slice[COL_OUT0_ASSET] = Val::from_u64(output_notes[0].note.asset_id);
            set_range_limbs(row_slice, COL_RANGE_LIMBS_START, output_notes[0].note.value)?;
            row_slice[selector_bit_cols[2][0]] = selector_bits[2][0];
            row_slice[selector_bit_cols[2][1]] = selector_bits[2][1];
        }
        if start_row_out1 < trace_len {
            let row_slice = trace.row_mut(start_row_out1);
            row_slice[COL_OUT_ACTIVE1] = flag_to_felt(output_flags[1]);
            row_slice[COL_OUT1_VALUE] = Val::from_u64(output_notes[1].note.value);
            row_slice[COL_OUT1_ASSET] = Val::from_u64(output_notes[1].note.asset_id);
            set_range_limbs(row_slice, COL_RANGE_LIMBS_START, output_notes[1].note.value)?;
            row_slice[selector_bit_cols[3][0]] = selector_bits[3][0];
            row_slice[selector_bit_cols[3][1]] = selector_bits[3][1];
        }

        let final_row = trace_len.saturating_sub(2);
        let value_balance_row = trace_len.saturating_sub(3);
        let issuance_row = trace_len.saturating_sub(4);
        if final_row < trace_len {
            let row_slice = trace.row_mut(final_row);
            row_slice[COL_FEE] = fee;
            row_slice[COL_VALUE_BALANCE_SIGN] = vb_sign;
            row_slice[COL_VALUE_BALANCE_MAG] = vb_mag;
            set_range_limbs(row_slice, COL_RANGE_LIMBS_START, witness.fee)?;
            row_slice[COL_CT0_0] = ciphertext_hashes[0][0];
            row_slice[COL_CT0_1] = ciphertext_hashes[0][1];
            row_slice[COL_CT0_2] = ciphertext_hashes[0][2];
            row_slice[COL_CT0_3] = ciphertext_hashes[0][3];
            row_slice[COL_CT0_4] = ciphertext_hashes[0][4];
            row_slice[COL_CT0_5] = ciphertext_hashes[0][5];
            row_slice[COL_CT1_0] = ciphertext_hashes[1][0];
            row_slice[COL_CT1_1] = ciphertext_hashes[1][1];
            row_slice[COL_CT1_2] = ciphertext_hashes[1][2];
            row_slice[COL_CT1_3] = ciphertext_hashes[1][3];
            row_slice[COL_CT1_4] = ciphertext_hashes[1][4];
            row_slice[COL_CT1_5] = ciphertext_hashes[1][5];
            row_slice[COL_STABLECOIN_SLOT_BIT0] = stablecoin_inputs.slot_selector_bits[0];
            row_slice[COL_STABLECOIN_SLOT_BIT1] = stablecoin_inputs.slot_selector_bits[1];
        }

        if value_balance_row < trace_len {
            let row_slice = trace.row_mut(value_balance_row);
            row_slice[COL_VALUE_BALANCE_MAG] = vb_mag;
            set_range_limbs(row_slice, COL_RANGE_LIMBS_START, vb_mag_u64)?;
        }

        if issuance_row < trace_len {
            let row_slice = trace.row_mut(issuance_row);
            set_range_limbs(row_slice, COL_RANGE_LIMBS_START, issuance_mag_u64)?;
        }

        let mut slot_in_acc = [0u64; 4];
        let mut slot_out_acc = [0u64; 4];
        for row in 1..trace_len {
            let row_slice = trace.row_mut(row);
            for slot in 0..4 {
                row_slice[slot_in_cols[slot]] = Val::from_u64(slot_in_acc[slot]);
                row_slice[slot_out_cols[slot]] = Val::from_u64(slot_out_acc[slot]);
            }

            if row == start_row_in0 && start_row_in0 < trace_len && input_flags[0] {
                let slot = selector_bits_to_index(selector_bits[0]);
                slot_in_acc[slot] = slot_in_acc[slot].saturating_add(input_notes[0].note.value);
            }
            if row == start_row_in1 && start_row_in1 < trace_len && input_flags[1] {
                let slot = selector_bits_to_index(selector_bits[1]);
                slot_in_acc[slot] = slot_in_acc[slot].saturating_add(input_notes[1].note.value);
            }
            if row == start_row_out0 && start_row_out0 < trace_len && output_flags[0] {
                let slot = selector_bits_to_index(selector_bits[2]);
                slot_out_acc[slot] = slot_out_acc[slot].saturating_add(output_notes[0].note.value);
            }
            if row == start_row_out1 && start_row_out1 < trace_len && output_flags[1] {
                let slot = selector_bits_to_index(selector_bits[3]);
                slot_out_acc[slot] = slot_out_acc[slot].saturating_add(output_notes[1].note.value);
            }
        }

        let cycle_specs = build_cycle_specs(&input_notes, &output_notes, witness, &input_flags)?;
        let mut prev_state = [Val::ZERO; 12];
        prev_state[0] = Val::from_u64(NULLIFIER_DOMAIN_TAG) + sk_words[0];
        prev_state[1] = sk_words[1];
        prev_state[2] = sk_words[2];
        prev_state[3] = sk_words[3];
        prev_state[11] = Val::ONE;
        let mut output = [Val::ZERO; 6];

        for cycle in 0..TOTAL_TRACE_CYCLES {
            let cycle_start = cycle * CYCLE_LENGTH;
            if cycle_start + CYCLE_LENGTH > trace_len {
                break;
            }

            let (state_start, dir) = if cycle == 0 {
                (prev_state, Val::ZERO)
            } else {
                let spec = cycle_specs.get(cycle - 1).cloned().unwrap_or(CycleSpec {
                    reset: false,
                    domain: 0,
                    inputs: [Val::ZERO; 6],
                    dir: Val::ZERO,
                });
                let state_start = if spec.reset {
                    [
                        Val::from_u64(spec.domain) + spec.inputs[0],
                        spec.inputs[1],
                        spec.inputs[2],
                        spec.inputs[3],
                        spec.inputs[4],
                        spec.inputs[5],
                        Val::ZERO,
                        Val::ZERO,
                        Val::ZERO,
                        Val::ZERO,
                        Val::ZERO,
                        Val::ONE,
                    ]
                } else {
                    [
                        prev_state[0] + spec.inputs[0],
                        prev_state[1] + spec.inputs[1],
                        prev_state[2] + spec.inputs[2],
                        prev_state[3] + spec.inputs[3],
                        prev_state[4] + spec.inputs[4],
                        prev_state[5] + spec.inputs[5],
                        prev_state[6],
                        prev_state[7],
                        prev_state[8],
                        prev_state[9],
                        prev_state[10],
                        prev_state[11],
                    ]
                };
                (state_start, spec.dir)
            };

            let mut state = state_start;
            for step in 0..CYCLE_LENGTH {
                let row = cycle_start + step;
                let row_slice = trace.row_mut(row);
                row_slice[COL_S0] = state[0];
                row_slice[COL_S1] = state[1];
                row_slice[COL_S2] = state[2];
                row_slice[COL_S3] = state[3];
                row_slice[COL_S4] = state[4];
                row_slice[COL_S5] = state[5];
                row_slice[COL_S6] = state[6];
                row_slice[COL_S7] = state[7];
                row_slice[COL_S8] = state[8];
                row_slice[COL_S9] = state[9];
                row_slice[COL_S10] = state[10];
                row_slice[COL_S11] = state[11];
                row_slice[COL_OUT0] = output[0];
                row_slice[COL_OUT1] = output[1];
                row_slice[COL_OUT2] = output[2];
                row_slice[COL_OUT3] = output[3];
                row_slice[COL_OUT4] = output[4];
                row_slice[COL_OUT5] = output[5];
                row_slice[COL_DIR] = dir;

                if step < POSEIDON2_STEPS {
                    poseidon2_step(&mut state, step);
                }
            }

            prev_state = state;

            let end_row = cycle_start + (CYCLE_LENGTH - 1);
            if end_row < trace_len {
                let next_cycle = cycle + 1;
                let next_spec = cycle_specs
                    .get(next_cycle - 1)
                    .cloned()
                    .unwrap_or(CycleSpec {
                        reset: false,
                        domain: 0,
                        inputs: [Val::ZERO; 6],
                        dir: Val::ZERO,
                    });
                let row_slice = trace.row_mut(end_row);
                row_slice[COL_IN0] = next_spec.inputs[0];
                row_slice[COL_IN1] = next_spec.inputs[1];
                row_slice[COL_IN2] = next_spec.inputs[2];
                row_slice[COL_IN3] = next_spec.inputs[3];
                row_slice[COL_IN4] = next_spec.inputs[4];
                row_slice[COL_IN5] = next_spec.inputs[5];

                if let Some(domain) = cycle_reset_domain(next_cycle) {
                    row_slice[COL_RESET] = Val::ONE;
                    row_slice[COL_DOMAIN] = Val::from_u64(domain);
                } else {
                    row_slice[COL_RESET] = Val::ZERO;
                    row_slice[COL_DOMAIN] = Val::ZERO;
                }

                row_slice[COL_MERKLE_LEFT] = flag_to_felt(cycle_is_merkle_left(next_cycle));
                row_slice[COL_MERKLE_RIGHT] = flag_to_felt(cycle_is_merkle_right(next_cycle));

                if cycle_is_output(cycle) {
                    output.copy_from_slice(&state[..6]);
                }
            }
        }

        Ok(trace)
    }

    pub fn public_inputs(
        &self,
        witness: &TransactionWitness,
    ) -> Result<TransactionPublicInputsP3, TransactionCircuitError> {
        let input_flags: Vec<Val> = (0..MAX_INPUTS)
            .map(|i| flag_to_felt(i < witness.inputs.len()))
            .collect();
        let output_flags: Vec<Val> = (0..MAX_OUTPUTS)
            .map(|i| flag_to_felt(i < witness.outputs.len()))
            .collect();

        let mut nullifiers = Vec::new();
        let prf = prf_key(&witness.sk_spend);
        for input in &witness.inputs {
            nullifiers.push(nullifier(prf, &input.note.rho, input.position));
        }
        while nullifiers.len() < MAX_INPUTS {
            nullifiers.push([Val::ZERO; 6]);
        }

        let mut commitments: Vec<HashFelt> = witness
            .outputs
            .iter()
            .map(|note| {
                note_commitment(
                    note.note.value,
                    note.note.asset_id,
                    &note.note.pk_recipient,
                    &note.note.pk_auth,
                    &note.note.rho,
                    &note.note.r,
                )
            })
            .collect();
        while commitments.len() < MAX_OUTPUTS {
            commitments.push([Val::ZERO; 6]);
        }

        let mut ciphertext_hashes: Vec<HashFelt> = witness
            .ciphertext_hashes
            .iter()
            .map(|ct| {
                bytes48_to_felts(ct).ok_or(TransactionCircuitError::ConstraintViolation(
                    "invalid ciphertext hash encoding",
                ))
            })
            .collect::<Result<_, _>>()?;
        while ciphertext_hashes.len() < MAX_OUTPUTS {
            ciphertext_hashes.push([Val::ZERO; 6]);
        }

        let merkle_root = bytes48_to_felts(&witness.merkle_root).ok_or(
            TransactionCircuitError::ConstraintViolation("invalid merkle root encoding"),
        )?;
        let slots = witness.balance_slots()?;
        let slot_assets: Vec<u64> = slots.iter().map(|slot| slot.asset_id).collect();
        let mut balance_slot_assets = [Val::from_u64(u64::MAX); 4];
        balance_slot_assets[0] = Val::ZERO;
        for (idx, asset_id) in slot_assets
            .iter()
            .take(balance_slot_assets.len())
            .enumerate()
        {
            balance_slot_assets[idx] = Val::from_u64(*asset_id);
        }
        let stablecoin_inputs = stablecoin_binding_inputs(witness, &slot_assets)?;
        let (vb_sign, vb_mag) = value_balance_parts(witness.value_balance)?;

        Ok(TransactionPublicInputsP3 {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            ciphertext_hashes,
            fee: Val::from_u64(witness.fee),
            value_balance_sign: vb_sign,
            value_balance_magnitude: vb_mag,
            merkle_root,
            balance_slot_assets,
            stablecoin_enabled: stablecoin_inputs.enabled,
            stablecoin_asset: stablecoin_inputs.asset,
            stablecoin_policy_version: stablecoin_inputs.policy_version,
            stablecoin_issuance_sign: stablecoin_inputs.issuance_sign,
            stablecoin_issuance_magnitude: stablecoin_inputs.issuance_mag,
            stablecoin_policy_hash: stablecoin_inputs.policy_hash,
            stablecoin_oracle_commitment: stablecoin_inputs.oracle_commitment,
            stablecoin_attestation_commitment: stablecoin_inputs.attestation_commitment,
        })
    }

    pub fn get_public_inputs_from_trace(trace: &RowMajorMatrix<Val>) -> TransactionPublicInputsP3 {
        let trace_len = trace.height();
        let input_rows = [note_start_row_input(0), note_start_row_input(1)];
        let input_cols = [COL_IN_ACTIVE0, COL_IN_ACTIVE1];
        let mut input_flags = Vec::with_capacity(MAX_INPUTS);
        for (idx, &row) in input_rows.iter().enumerate() {
            let flag = if row < trace_len {
                get_trace(trace, input_cols[idx], row)
            } else {
                Val::ZERO
            };
            input_flags.push(flag);
        }

        let output_rows = [note_start_row_output(0), note_start_row_output(1)];
        let output_cols = [COL_OUT_ACTIVE0, COL_OUT_ACTIVE1];
        let mut output_flags = Vec::with_capacity(MAX_OUTPUTS);
        for (idx, &row) in output_rows.iter().enumerate() {
            let flag = if row < trace_len {
                get_trace(trace, output_cols[idx], row)
            } else {
                Val::ZERO
            };
            output_flags.push(flag);
        }

        let read_hash = |row: usize| -> [Val; 6] {
            [
                get_trace(trace, COL_S0, row),
                get_trace(trace, COL_S1, row),
                get_trace(trace, COL_S2, row),
                get_trace(trace, COL_S3, row),
                get_trace(trace, COL_S4, row),
                get_trace(trace, COL_S5, row),
            ]
        };

        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for (i, flag) in input_flags.iter().enumerate() {
            let row = nullifier_output_row(i);
            let nf = if *flag == Val::ONE && row < trace_len {
                read_hash(row)
            } else {
                [Val::ZERO; 6]
            };
            nullifiers.push(nf);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for (i, flag) in output_flags.iter().enumerate() {
            let row = commitment_output_row(i);
            let cm = if *flag == Val::ONE && row < trace_len {
                read_hash(row)
            } else {
                [Val::ZERO; 6]
            };
            commitments.push(cm);
        }

        let merkle_root = if trace_len > 0 {
            let row = merkle_root_output_row(0);
            if row < trace_len {
                read_hash(row)
            } else {
                [Val::ZERO; 6]
            }
        } else {
            [Val::ZERO; 6]
        };

        let final_row = trace_len.saturating_sub(2);
        let balance_slot_assets =
            infer_balance_slot_assets_from_trace(trace, &input_flags, &output_flags);
        let ciphertext_hashes = if final_row < trace_len {
            vec![
                [
                    get_trace(trace, COL_CT0_0, final_row),
                    get_trace(trace, COL_CT0_1, final_row),
                    get_trace(trace, COL_CT0_2, final_row),
                    get_trace(trace, COL_CT0_3, final_row),
                    get_trace(trace, COL_CT0_4, final_row),
                    get_trace(trace, COL_CT0_5, final_row),
                ],
                [
                    get_trace(trace, COL_CT1_0, final_row),
                    get_trace(trace, COL_CT1_1, final_row),
                    get_trace(trace, COL_CT1_2, final_row),
                    get_trace(trace, COL_CT1_3, final_row),
                    get_trace(trace, COL_CT1_4, final_row),
                    get_trace(trace, COL_CT1_5, final_row),
                ],
            ]
        } else {
            vec![[Val::ZERO; 6]; MAX_OUTPUTS]
        };
        TransactionPublicInputsP3 {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            ciphertext_hashes,
            fee: get_trace(trace, COL_FEE, final_row),
            value_balance_sign: get_trace(trace, COL_VALUE_BALANCE_SIGN, final_row),
            value_balance_magnitude: get_trace(trace, COL_VALUE_BALANCE_MAG, final_row),
            merkle_root,
            balance_slot_assets,
            // Stablecoin binding payload now lives only in public inputs, not the witness trace.
            stablecoin_enabled: Val::ZERO,
            stablecoin_asset: Val::ZERO,
            stablecoin_policy_version: Val::ZERO,
            stablecoin_issuance_sign: Val::ZERO,
            stablecoin_issuance_magnitude: Val::ZERO,
            stablecoin_policy_hash: [Val::ZERO; 6],
            stablecoin_oracle_commitment: [Val::ZERO; 6],
            stablecoin_attestation_commitment: [Val::ZERO; 6],
        }
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &TransactionPublicInputsP3,
    ) -> TransactionProofP3 {
        self.prove_with_params(trace, pub_inputs, TransactionProofParams::production())
    }

    pub fn prove_with_params(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &TransactionPublicInputsP3,
        params: TransactionProofParams,
    ) -> TransactionProofP3 {
        let pub_inputs_vec = pub_inputs.to_vec();
        let log_chunks =
            get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, pub_inputs_vec.len(), 0);
        let log_blowup = params.log_blowup.max(log_chunks);
        let config = config_with_profile(TxFriProfile::new(
            log_blowup as u8,
            params.num_queries as u8,
            0,
        ));
        prove(&config.config, &TransactionAirP3, trace, &pub_inputs_vec)
    }

    pub fn prove_bytes(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &TransactionPublicInputsP3,
    ) -> Result<Vec<u8>, TransactionCircuitError> {
        self.prove_bytes_with_params(trace, pub_inputs, TransactionProofParams::production())
    }

    pub fn prove_bytes_with_params(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &TransactionPublicInputsP3,
        params: TransactionProofParams,
    ) -> Result<Vec<u8>, TransactionCircuitError> {
        let proof = self.prove_with_params(trace, pub_inputs, params);
        postcard::to_allocvec(&proof).map_err(|_| {
            TransactionCircuitError::ConstraintViolation("failed to serialize Plonky3 proof")
        })
    }

    pub fn prove_transaction(
        &self,
        witness: &TransactionWitness,
    ) -> Result<Vec<u8>, TransactionCircuitError> {
        witness.validate()?;
        let trace = self.build_trace(witness)?;
        let pub_inputs = self.public_inputs(witness)?;
        self.prove_bytes(trace, &pub_inputs)
    }
}

fn flag_to_felt(active: bool) -> Val {
    Val::from_bool(active)
}

fn get_trace(trace: &RowMajorMatrix<Val>, col: usize, row: usize) -> Val {
    trace.values[row * trace.width + col]
}

fn infer_balance_slot_assets_from_trace(
    trace: &RowMajorMatrix<Val>,
    input_flags: &[Val],
    output_flags: &[Val],
) -> [Val; 4] {
    let mut assets = vec![transaction_core::constants::NATIVE_ASSET_ID];
    for (idx, flag) in input_flags.iter().enumerate() {
        let row = note_start_row_input(idx);
        if *flag == Val::ONE && row < trace.height() {
            assets.push(
                get_trace(
                    trace,
                    if idx == 0 {
                        COL_IN0_ASSET
                    } else {
                        COL_IN1_ASSET
                    },
                    row,
                )
                .as_canonical_u64(),
            );
        }
    }
    for (idx, flag) in output_flags.iter().enumerate() {
        let row = note_start_row_output(idx);
        if *flag == Val::ONE && row < trace.height() {
            assets.push(
                get_trace(
                    trace,
                    if idx == 0 {
                        COL_OUT0_ASSET
                    } else {
                        COL_OUT1_ASSET
                    },
                    row,
                )
                .as_canonical_u64(),
            );
        }
    }
    assets.sort_unstable();
    assets.dedup();

    let mut slot_assets = [Val::from_u64(u64::MAX); 4];
    slot_assets[0] = Val::ZERO;
    for (idx, asset_id) in assets.into_iter().take(slot_assets.len()).enumerate() {
        slot_assets[idx] = Val::from_u64(asset_id);
    }
    slot_assets
}

fn bytes_to_vals(bytes: &[u8]) -> Vec<Val> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            Val::from_u64(u64::from_be_bytes(buf))
        })
        .collect()
}

fn bytes32_to_vals(bytes: &[u8; 32]) -> [Val; 4] {
    let vals = bytes_to_vals(bytes);
    debug_assert_eq!(vals.len(), 4);
    [vals[0], vals[1], vals[2], vals[3]]
}

fn bytes48_to_vals(bytes: &[u8; 48]) -> Result<[Val; 6], TransactionCircuitError> {
    bytes48_to_felts(bytes).ok_or(TransactionCircuitError::ConstraintViolation(
        "invalid 48-byte hash encoding",
    ))
}

fn commitment_inputs(note: &NoteData) -> Vec<Val> {
    let mut inputs = Vec::new();
    inputs.push(Val::from_u64(note.value));
    inputs.push(Val::from_u64(note.asset_id));
    inputs.extend(bytes_to_vals(&note.pk_recipient));
    inputs.extend(bytes_to_vals(&note.rho));
    inputs.extend(bytes_to_vals(&note.r));
    inputs.extend(bytes_to_vals(&note.pk_auth));
    inputs
}

fn nullifier_inputs(prf: Val, input: &InputNoteWitness) -> Vec<Val> {
    let mut inputs = Vec::new();
    inputs.push(prf);
    inputs.push(Val::from_u64(input.position));
    inputs.extend(bytes_to_vals(&input.note.rho));
    inputs
}

fn pad_inputs(inputs: &[InputNoteWitness]) -> (Vec<InputNoteWitness>, [bool; MAX_INPUTS]) {
    let mut padded = Vec::with_capacity(MAX_INPUTS);
    let mut flags = [false; MAX_INPUTS];
    for (idx, note) in inputs.iter().cloned().enumerate() {
        if idx < MAX_INPUTS {
            padded.push(note);
            flags[idx] = true;
        }
    }
    while padded.len() < MAX_INPUTS {
        padded.push(dummy_input());
    }
    (padded, flags)
}

fn pad_outputs(outputs: &[OutputNoteWitness]) -> (Vec<OutputNoteWitness>, [bool; MAX_OUTPUTS]) {
    let mut padded = Vec::with_capacity(MAX_OUTPUTS);
    let mut flags = [false; MAX_OUTPUTS];
    for (idx, note) in outputs.iter().cloned().enumerate() {
        if idx < MAX_OUTPUTS {
            padded.push(note);
            flags[idx] = true;
        }
    }
    while padded.len() < MAX_OUTPUTS {
        padded.push(dummy_output());
    }
    (padded, flags)
}

fn dummy_input() -> InputNoteWitness {
    InputNoteWitness {
        note: NoteData {
            value: 0,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            pk_auth: [0u8; 32],
            rho: [0u8; 32],
            r: [0u8; 32],
        },
        position: 0xA5A5_A5A5,
        rho_seed: [0u8; 32],
        merkle_path: crate::note::MerklePath::default(),
    }
}

fn dummy_output() -> OutputNoteWitness {
    OutputNoteWitness {
        note: NoteData {
            value: 0,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            pk_auth: [0u8; 32],
            rho: [0u8; 32],
            r: [0u8; 32],
        },
    }
}

fn selector_bits_for_slot(slot_idx: usize) -> [Val; 2] {
    [
        Val::from_bool((slot_idx & 1) != 0),
        Val::from_bool((slot_idx & 2) != 0),
    ]
}

fn selector_bits_to_index(bits: [Val; 2]) -> usize {
    usize::from(bits[0] == Val::ONE) + (usize::from(bits[1] == Val::ONE) << 1)
}

fn build_selector_bits(
    inputs: &[InputNoteWitness],
    outputs: &[OutputNoteWitness],
    slot_assets: &[u64],
    input_flags: &[bool; MAX_INPUTS],
    output_flags: &[bool; MAX_OUTPUTS],
) -> [[Val; 2]; 4] {
    let mut selectors = [[Val::ZERO; 2]; 4];

    for (idx, note) in inputs.iter().enumerate() {
        if input_flags[idx] {
            if let Some(slot_idx) = slot_assets.iter().position(|id| *id == note.note.asset_id) {
                selectors[idx] = selector_bits_for_slot(slot_idx);
            }
        }
    }

    for (idx, note) in outputs.iter().enumerate() {
        if output_flags[idx] {
            if let Some(slot_idx) = slot_assets.iter().position(|id| *id == note.note.asset_id) {
                selectors[2 + idx] = selector_bits_for_slot(slot_idx);
            }
        }
    }

    selectors
}

fn value_balance_parts(value_balance: i128) -> Result<(Val, Val), TransactionCircuitError> {
    let magnitude = value_balance.unsigned_abs();
    if magnitude > MAX_NOTE_VALUE {
        return Err(TransactionCircuitError::ValueBalanceOutOfRange(magnitude));
    }
    let mag_u64 = u64::try_from(magnitude)
        .map_err(|_| TransactionCircuitError::ValueBalanceOutOfRange(magnitude))?;
    let sign = if value_balance < 0 {
        Val::ONE
    } else {
        Val::ZERO
    };
    Ok((sign, Val::from_u64(mag_u64)))
}

struct StablecoinBindingInputs {
    enabled: Val,
    asset: Val,
    policy_version: Val,
    issuance_sign: Val,
    issuance_mag: Val,
    policy_hash: [Val; 6],
    oracle_commitment: [Val; 6],
    attestation_commitment: [Val; 6],
    slot_selector_bits: [Val; 2],
}

fn stablecoin_binding_inputs(
    witness: &TransactionWitness,
    slot_assets: &[u64],
) -> Result<StablecoinBindingInputs, TransactionCircuitError> {
    if !witness.stablecoin.enabled {
        return Ok(StablecoinBindingInputs {
            enabled: Val::ZERO,
            asset: Val::ZERO,
            policy_version: Val::ZERO,
            issuance_sign: Val::ZERO,
            issuance_mag: Val::ZERO,
            policy_hash: [Val::ZERO; 6],
            oracle_commitment: [Val::ZERO; 6],
            attestation_commitment: [Val::ZERO; 6],
            slot_selector_bits: [Val::ZERO; 2],
        });
    }

    let policy_hash = bytes48_to_vals(&witness.stablecoin.policy_hash)?;
    let oracle_commitment = bytes48_to_vals(&witness.stablecoin.oracle_commitment)?;
    let attestation_commitment = bytes48_to_vals(&witness.stablecoin.attestation_commitment)?;

    let (issuance_sign, issuance_mag) = value_balance_parts(witness.stablecoin.issuance_delta)?;
    let slot_index = slot_assets
        .iter()
        .position(|asset_id| *asset_id == witness.stablecoin.asset_id)
        .ok_or(TransactionCircuitError::BalanceMismatch(
            witness.stablecoin.asset_id,
        ))?;
    if slot_index == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "stablecoin binding cannot target native asset slot",
        ));
    }
    if slot_index >= 4 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "stablecoin slot index overflow",
        ));
    }

    Ok(StablecoinBindingInputs {
        enabled: Val::ONE,
        asset: Val::from_u64(witness.stablecoin.asset_id),
        policy_version: Val::from_u64(u64::from(witness.stablecoin.policy_version)),
        issuance_sign,
        issuance_mag,
        policy_hash,
        oracle_commitment,
        attestation_commitment,
        slot_selector_bits: selector_bits_for_slot(slot_index),
    })
}

fn build_cycle_specs(
    inputs: &[InputNoteWitness],
    outputs: &[OutputNoteWitness],
    witness: &TransactionWitness,
    input_flags: &[bool; MAX_INPUTS],
) -> Result<Vec<CycleSpec>, TransactionCircuitError> {
    let prf = prf_key(&witness.sk_spend);
    let mut cycles = Vec::with_capacity(TOTAL_USED_CYCLES - DUMMY_CYCLES);

    for (idx, input) in inputs.iter().enumerate() {
        let commitment_inputs = commitment_inputs(&input.note);
        for chunk_idx in 0..COMMITMENT_ABSORB_CYCLES {
            let reset = chunk_idx == 0;
            let domain = if reset { NOTE_DOMAIN_TAG } else { 0 };
            let mut chunk = [Val::ZERO; 6];
            let start = chunk_idx * 6;
            let take = commitment_inputs.len().saturating_sub(start).min(6);
            if take > 0 {
                chunk[..take].copy_from_slice(&commitment_inputs[start..start + take]);
            }
            cycles.push(CycleSpec {
                reset,
                domain,
                inputs: chunk,
                dir: Val::ZERO,
            });
        }

        let mut current = note_commitment(
            input.note.value,
            input.note.asset_id,
            &input.note.pk_recipient,
            &input.note.pk_auth,
            &input.note.rho,
            &input.note.r,
        );
        let mut pos = input.position;
        let fallback_path = MerklePath::default();
        let merkle_path = if input_flags[idx] {
            &input.merkle_path
        } else {
            &fallback_path
        };
        for level in 0..CIRCUIT_MERKLE_DEPTH {
            let dir = if pos & 1 == 0 { Val::ZERO } else { Val::ONE };
            let sibling = merkle_path
                .siblings
                .get(level)
                .copied()
                .unwrap_or([Val::ZERO; 6]);
            let (left, right) = if pos & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            for chunk_idx in 0..MERKLE_ABSORB_CYCLES {
                let reset = chunk_idx == 0;
                let domain = if reset { MERKLE_DOMAIN_TAG } else { 0 };
                let inputs = if chunk_idx == 0 { left } else { right };
                cycles.push(CycleSpec {
                    reset,
                    domain,
                    inputs,
                    dir,
                });
            }
            current = merkle_node(left, right);
            pos >>= 1;
        }

        let nullifier_inputs = nullifier_inputs(prf, input);
        for chunk_idx in 0..NULLIFIER_ABSORB_CYCLES {
            let reset = chunk_idx == 0;
            let domain = if reset { NULLIFIER_DOMAIN_TAG } else { 0 };
            let mut chunk = [Val::ZERO; 6];
            let start = chunk_idx * 6;
            let take = nullifier_inputs.len().saturating_sub(start).min(6);
            if take > 0 {
                chunk[..take].copy_from_slice(&nullifier_inputs[start..start + take]);
            }
            cycles.push(CycleSpec {
                reset,
                domain,
                inputs: chunk,
                dir: Val::ZERO,
            });
        }
    }

    for output in outputs.iter() {
        let commitment_inputs = commitment_inputs(&output.note);
        for chunk_idx in 0..COMMITMENT_ABSORB_CYCLES {
            let reset = chunk_idx == 0;
            let domain = if reset { NOTE_DOMAIN_TAG } else { 0 };
            let mut chunk = [Val::ZERO; 6];
            let start = chunk_idx * 6;
            let take = commitment_inputs.len().saturating_sub(start).min(6);
            if take > 0 {
                chunk[..take].copy_from_slice(&commitment_inputs[start..start + take]);
            }
            cycles.push(CycleSpec {
                reset,
                domain,
                inputs: chunk,
                dir: Val::ZERO,
            });
        }
    }

    debug_assert_eq!(cycles.len(), TOTAL_USED_CYCLES - DUMMY_CYCLES);

    Ok(cycles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing_pq::{felts_to_bytes48, merkle_node, note_commitment, HashFelt};
    use crate::note::{MerklePath, NoteData};
    use crate::p3_verifier::verify_transaction_proof_p3;
    use crate::StablecoinPolicyBinding;
    use std::panic::catch_unwind;

    fn compute_merkle_root_from_path(leaf: HashFelt, position: u64, path: &MerklePath) -> HashFelt {
        let mut current = leaf;
        let mut pos = position;
        for sibling in &path.siblings {
            current = if pos & 1 == 0 {
                merkle_node(current, *sibling)
            } else {
                merkle_node(*sibling, current)
            };
            pos >>= 1;
        }
        current
    }

    fn sample_witness() -> TransactionWitness {
        let sk_spend = [8u8; 32];
        let pk_auth = crate::hashing_pq::spend_auth_key_bytes(&sk_spend);
        let input_note = NoteData {
            value: 100,
            asset_id: 0,
            pk_recipient: [1u8; 32],
            pk_auth,
            rho: [2u8; 32],
            r: [3u8; 32],
        };
        let output_note = NoteData {
            value: 80,
            asset_id: 0,
            pk_recipient: [4u8; 32],
            pk_auth: [14u8; 32],
            rho: [5u8; 32],
            r: [6u8; 32],
        };
        let merkle_path = MerklePath::default();
        let leaf = note_commitment(
            input_note.value,
            input_note.asset_id,
            &input_note.pk_recipient,
            &input_note.pk_auth,
            &input_note.rho,
            &input_note.r,
        );
        let merkle_root = felts_to_bytes48(&compute_merkle_root_from_path(leaf, 0, &merkle_path));

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [7u8; 32],
                merkle_path,
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            ciphertext_hashes: vec![[9u8; 48]; 1],
            sk_spend,
            merkle_root,
            fee: 0,
            value_balance: -20,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    #[test]
    fn build_trace_roundtrip_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = TransactionProverP3::get_public_inputs_from_trace(&trace);
        pub_inputs.validate().expect("public inputs valid");
        assert_eq!(pub_inputs.nullifiers.len(), MAX_INPUTS);
        assert_eq!(pub_inputs.commitments.len(), MAX_OUTPUTS);
    }

    #[test]
    fn public_inputs_match_trace_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let trace = prover.build_trace(&witness).expect("trace build");
        let from_trace = TransactionProverP3::get_public_inputs_from_trace(&trace);
        let from_witness = prover.public_inputs(&witness).expect("public inputs");
        assert_eq!(from_trace.to_vec(), from_witness.to_vec());
    }

    #[test]
    #[cfg_attr(
        not(feature = "plonky3-e2e"),
        ignore = "slow: full Plonky3 prove/verify roundtrip"
    )]
    fn prove_verify_roundtrip_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = prover.public_inputs(&witness).expect("public inputs");
        let pub_inputs_vec = pub_inputs.to_vec();
        let log_chunks =
            get_log_num_quotient_chunks::<Val, _>(&TransactionAirP3, 0, pub_inputs_vec.len(), 0);
        let profile = transaction_core::p3_config::default_build_tx_fri_profile();
        let log_blowup = profile.log_blowup_usize().max(log_chunks);
        let num_queries = profile.num_queries_usize();
        let proof = prover.prove(trace, &pub_inputs);
        let proof_bytes = postcard::to_allocvec(&proof).expect("serialize proof");
        println!(
            "p3 tx proof: bytes={}, degree_bits={}, log_chunks={}, log_blowup={}, num_queries={}",
            proof_bytes.len(),
            proof.degree_bits,
            log_chunks,
            log_blowup,
            num_queries
        );
        verify_transaction_proof_p3(&proof, &pub_inputs).expect("verification should pass");
    }

    #[test]
    #[cfg_attr(
        not(feature = "plonky3-e2e"),
        ignore = "slow: full Plonky3 prove/verify roundtrip"
    )]
    fn prove_verify_roundtrip_p3_trace_inputs() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = TransactionProverP3::get_public_inputs_from_trace(&trace);
        let proof = prover.prove(trace, &pub_inputs);
        verify_transaction_proof_p3(&proof, &pub_inputs).expect("verification should pass");
    }

    #[test]
    fn schedule_mismatch_rejected_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let mut trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = prover.public_inputs(&witness).expect("public inputs");

        let row = 1;
        let col = COL_RESET;
        let idx = row * trace.width + col;
        trace.values[idx] = if trace.values[idx] == Val::ZERO {
            Val::ONE
        } else {
            Val::ZERO
        };

        let result = catch_unwind(|| prover.prove(trace, &pub_inputs));
        if let Ok(proof) = result {
            assert!(
                verify_transaction_proof_p3(&proof, &pub_inputs).is_err(),
                "verification should fail for tampered counters"
            );
        }
    }

    #[test]
    fn slot_asset_relabel_between_rows_rejected_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = prover.public_inputs(&witness).expect("public inputs");
        let proof = prover.prove(trace, &pub_inputs);

        let mut tampered = pub_inputs.clone();
        tampered.balance_slot_assets[1] += Val::ONE;
        assert!(
            verify_transaction_proof_p3(&proof, &tampered).is_err(),
            "verification should fail for slot asset relabeling across rows"
        );
    }

    #[test]
    fn ciphertext_hash_public_input_binding_rejected_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = prover.public_inputs(&witness).expect("public inputs");
        let proof = prover.prove(trace, &pub_inputs);

        let mut tampered = pub_inputs.clone();
        tampered.ciphertext_hashes[0][0] += Val::ONE;
        assert!(
            verify_transaction_proof_p3(&proof, &tampered).is_err(),
            "verification should fail when ciphertext hashes are modified"
        );
    }

    #[test]
    fn rho_binding_between_commitment_and_nullifier_rejected_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let mut trace = prover.build_trace(&witness).expect("trace build");

        let row = transaction_core::p3_air::nullifier_input_row(0);
        let idx = row * trace.width + COL_IN2;
        trace.values[idx] += Val::ONE;

        let pub_inputs = TransactionProverP3::get_public_inputs_from_trace(&trace);
        let result = catch_unwind(|| prover.prove(trace, &pub_inputs));
        if let Ok(proof) = result {
            assert!(
                verify_transaction_proof_p3(&proof, &pub_inputs).is_err(),
                "verification should fail for commitment/nullifier rho mismatch"
            );
        }
    }

    #[test]
    fn prf_derivation_binding_rejected_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let mut trace = prover.build_trace(&witness).expect("trace build");

        let row = transaction_core::p3_air::nullifier_input_row(0);
        let idx = row * trace.width + COL_IN0;
        trace.values[idx] += Val::ONE;

        let pub_inputs = TransactionProverP3::get_public_inputs_from_trace(&trace);
        let result = catch_unwind(|| prover.prove(trace, &pub_inputs));
        if let Ok(proof) = result {
            assert!(
                verify_transaction_proof_p3(&proof, &pub_inputs).is_err(),
                "verification should fail for unconstrained PRF tampering"
            );
        }
    }

    #[test]
    fn ownership_binding_rejected_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let mut trace = prover.build_trace(&witness).expect("trace build");

        let row = transaction_core::p3_air::commitment_auth_row(0);
        let idx = row * trace.width + COL_IN2;
        trace.values[idx] += Val::ONE;

        let pub_inputs = TransactionProverP3::get_public_inputs_from_trace(&trace);
        let result = catch_unwind(|| prover.prove(trace, &pub_inputs));
        if let Ok(proof) = result {
            assert!(
                verify_transaction_proof_p3(&proof, &pub_inputs).is_err(),
                "verification should fail for spend-key ownership tampering"
            );
        }
    }

    #[test]
    fn value_range_overflow_rejected_p3() {
        let mut witness = sample_witness();
        witness.inputs[0].note.value = 1u64 << 62;
        witness.outputs[0].note.value = (1u64 << 62) - 20;

        let prover = TransactionProverP3::new();
        let err = prover
            .build_trace(&witness)
            .expect_err("out-of-range note values should be rejected before proving");
        assert!(matches!(err, TransactionCircuitError::ValueOutOfRange(_)));
    }
}
