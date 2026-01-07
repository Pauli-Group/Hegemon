//! Plonky3 prover for the transaction circuit.

use p3_field::AbstractField;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::prove;
use winterfell::math::FieldElement;

use crate::constants::{
    CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_OUTPUTS, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG,
    NULLIFIER_DOMAIN_TAG, POSEIDON_ROUNDS,
};
use crate::hashing::{bytes32_to_felts, merkle_node, prf_key, Felt, HashFelt};
use crate::note::{InputNoteWitness, NoteData, OutputNoteWitness};
use crate::p3_config::{default_config, new_challenger, TransactionProofP3};
use crate::witness::TransactionWitness;
use crate::TransactionCircuitError;
use transaction_core::p3_air::{
    commitment_output_row, cycle_is_merkle_left_01, cycle_is_merkle_left_23, cycle_is_merkle_right_01,
    cycle_is_merkle_right_23, cycle_is_squeeze, cycle_reset_domain, merkle_root_output_row,
    note_start_row_input, note_start_row_output, nullifier_output_row, round_constant,
    TransactionAirP3, TransactionPublicInputsP3, COL_CAPTURE, COL_CAPTURE2, COL_CYCLE_BIT0,
    COL_DIR, COL_DOMAIN, COL_FEE, COL_IN0, COL_IN0_ASSET, COL_IN0_VALUE, COL_IN1, COL_IN1_ASSET,
    COL_IN1_VALUE, COL_IN_ACTIVE0, COL_IN_ACTIVE1, COL_MERKLE_LEFT_01, COL_MERKLE_LEFT_23,
    COL_MERKLE_RIGHT_01, COL_MERKLE_RIGHT_23, COL_NOTE_START_IN0, COL_NOTE_START_IN1,
    COL_NOTE_START_OUT0, COL_NOTE_START_OUT1, COL_OUT0, COL_OUT0_ASSET, COL_OUT0_VALUE, COL_OUT1,
    COL_OUT1_ASSET, COL_OUT1_VALUE, COL_OUT2, COL_OUT3, COL_OUT_ACTIVE0, COL_OUT_ACTIVE1, COL_RESET,
    COL_S0, COL_S1, COL_S2, COL_SEL_IN0_SLOT0, COL_SEL_IN0_SLOT1, COL_SEL_IN0_SLOT2,
    COL_SEL_IN0_SLOT3, COL_SEL_IN1_SLOT0, COL_SEL_IN1_SLOT1, COL_SEL_IN1_SLOT2, COL_SEL_IN1_SLOT3,
    COL_SEL_OUT0_SLOT0, COL_SEL_OUT0_SLOT1, COL_SEL_OUT0_SLOT2, COL_SEL_OUT0_SLOT3,
    COL_SEL_OUT1_SLOT0, COL_SEL_OUT1_SLOT1, COL_SEL_OUT1_SLOT2, COL_SEL_OUT1_SLOT3, COL_SLOT0_ASSET,
    COL_SLOT0_IN, COL_SLOT0_OUT, COL_SLOT1_ASSET, COL_SLOT1_IN, COL_SLOT1_OUT, COL_SLOT2_ASSET,
    COL_SLOT2_IN, COL_SLOT2_OUT, COL_SLOT3_ASSET, COL_SLOT3_IN, COL_SLOT3_OUT,
    COL_STABLECOIN_ASSET, COL_STABLECOIN_ATTEST0, COL_STABLECOIN_ATTEST1, COL_STABLECOIN_ATTEST2,
    COL_STABLECOIN_ATTEST3, COL_STABLECOIN_ENABLED, COL_STABLECOIN_ISSUANCE_MAG,
    COL_STABLECOIN_ISSUANCE_SIGN, COL_STABLECOIN_ORACLE0, COL_STABLECOIN_ORACLE1,
    COL_STABLECOIN_ORACLE2, COL_STABLECOIN_ORACLE3, COL_STABLECOIN_POLICY_HASH0,
    COL_STABLECOIN_POLICY_HASH1, COL_STABLECOIN_POLICY_HASH2, COL_STABLECOIN_POLICY_HASH3,
    COL_STABLECOIN_POLICY_VERSION, COL_STABLECOIN_SLOT_SEL0, COL_STABLECOIN_SLOT_SEL1,
    COL_STABLECOIN_SLOT_SEL2, COL_STABLECOIN_SLOT_SEL3, COL_STEP_BIT0,
    COL_VALUE_BALANCE_MAG, COL_VALUE_BALANCE_SIGN, COMMITMENT_ABSORB_CYCLES, CYCLE_LENGTH,
    DUMMY_CYCLES, MERKLE_ABSORB_CYCLES, MIN_TRACE_LENGTH, NULLIFIER_ABSORB_CYCLES,
    TOTAL_TRACE_CYCLES, TOTAL_USED_CYCLES, TRACE_WIDTH,
};

type Val = Goldilocks;

#[derive(Clone, Copy)]
struct CycleSpec {
    reset: bool,
    domain: u64,
    in0: Val,
    in1: Val,
    dir: Val,
}

pub struct TransactionProverP3;

impl TransactionProverP3 {
    pub fn new() -> Self {
        Self
    }

    pub fn build_trace(
        &self,
        witness: &TransactionWitness,
    ) -> Result<RowMajorMatrix<Val>, TransactionCircuitError> {
        let trace_len = MIN_TRACE_LENGTH;
        let mut trace = RowMajorMatrix::new(vec![Val::zero(); trace_len * TRACE_WIDTH], TRACE_WIDTH);

        for row in 0..trace_len {
            let step = row % CYCLE_LENGTH;
            let cycle = row / CYCLE_LENGTH;
            let row_slice = trace.row_mut(row);
            for bit in 0..6 {
                let is_one = ((step >> bit) & 1) == 1;
                row_slice[COL_STEP_BIT0 + bit] = Val::from_bool(is_one);
            }
            for bit in 0..9 {
                let is_one = ((cycle >> bit) & 1) == 1;
                row_slice[COL_CYCLE_BIT0 + bit] = Val::from_bool(is_one);
            }
        }

        let (input_notes, input_flags) = pad_inputs(&witness.inputs);
        let (output_notes, output_flags) = pad_outputs(&witness.outputs);

        let slots = witness.balance_slots()?;
        let slot_assets: Vec<u64> = slots.iter().map(|slot| slot.asset_id).collect();
        let selectors = build_selectors(
            &input_notes,
            &output_notes,
            &slot_assets,
            &input_flags,
            &output_flags,
        );

        let (vb_sign, vb_mag) = value_balance_parts(witness.value_balance)?;
        let fee = Val::from_canonical_u64(witness.fee);
        let stablecoin_inputs = stablecoin_binding_inputs(witness, &slot_assets)?;

        let sentinel_row = 0;
        let slot_asset_cols = [
            COL_SLOT0_ASSET,
            COL_SLOT1_ASSET,
            COL_SLOT2_ASSET,
            COL_SLOT3_ASSET,
        ];
        let slot_in_cols = [COL_SLOT0_IN, COL_SLOT1_IN, COL_SLOT2_IN, COL_SLOT3_IN];
        let slot_out_cols = [COL_SLOT0_OUT, COL_SLOT1_OUT, COL_SLOT2_OUT, COL_SLOT3_OUT];
        let selector_cols = [
            [
                COL_SEL_IN0_SLOT0,
                COL_SEL_IN0_SLOT1,
                COL_SEL_IN0_SLOT2,
                COL_SEL_IN0_SLOT3,
            ],
            [
                COL_SEL_IN1_SLOT0,
                COL_SEL_IN1_SLOT1,
                COL_SEL_IN1_SLOT2,
                COL_SEL_IN1_SLOT3,
            ],
            [
                COL_SEL_OUT0_SLOT0,
                COL_SEL_OUT0_SLOT1,
                COL_SEL_OUT0_SLOT2,
                COL_SEL_OUT0_SLOT3,
            ],
            [
                COL_SEL_OUT1_SLOT0,
                COL_SEL_OUT1_SLOT1,
                COL_SEL_OUT1_SLOT2,
                COL_SEL_OUT1_SLOT3,
            ],
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
                row_slice[col] = Val::one();
            }
            for cols in selector_cols.iter() {
                for &col in cols.iter() {
                    row_slice[col] = Val::one();
                }
            }
            for &col in slot_asset_cols.iter() {
                row_slice[col] = Val::one();
            }
            for &col in slot_in_cols.iter() {
                row_slice[col] = Val::one();
            }
            for &col in slot_out_cols.iter() {
                row_slice[col] = Val::from_canonical_u64(2);
            }
        }

        let start_row_in0 = note_start_row_input(0);
        let start_row_in1 = note_start_row_input(1);
        let start_row_out0 = note_start_row_output(0);
        let start_row_out1 = note_start_row_output(1);
        if start_row_in0 < trace_len {
            let row_slice = trace.row_mut(start_row_in0);
            row_slice[COL_NOTE_START_IN0] = Val::one();
            row_slice[COL_IN_ACTIVE0] = flag_to_felt(input_flags[0]);
            row_slice[COL_IN0_VALUE] = Val::from_canonical_u64(input_notes[0].note.value);
            row_slice[COL_IN0_ASSET] = Val::from_canonical_u64(input_notes[0].note.asset_id);
            for slot in 0..4 {
                row_slice[selector_cols[0][slot]] = selectors[0][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                row_slice[col] = Val::from_canonical_u64(slot_assets[idx]);
            }
        }
        if start_row_in1 < trace_len {
            let row_slice = trace.row_mut(start_row_in1);
            row_slice[COL_NOTE_START_IN1] = Val::one();
            row_slice[COL_IN_ACTIVE1] = flag_to_felt(input_flags[1]);
            row_slice[COL_IN1_VALUE] = Val::from_canonical_u64(input_notes[1].note.value);
            row_slice[COL_IN1_ASSET] = Val::from_canonical_u64(input_notes[1].note.asset_id);
            for slot in 0..4 {
                row_slice[selector_cols[1][slot]] = selectors[1][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                row_slice[col] = Val::from_canonical_u64(slot_assets[idx]);
            }
        }
        if start_row_out0 < trace_len {
            let row_slice = trace.row_mut(start_row_out0);
            row_slice[COL_NOTE_START_OUT0] = Val::one();
            row_slice[COL_OUT_ACTIVE0] = flag_to_felt(output_flags[0]);
            row_slice[COL_OUT0_VALUE] = Val::from_canonical_u64(output_notes[0].note.value);
            row_slice[COL_OUT0_ASSET] = Val::from_canonical_u64(output_notes[0].note.asset_id);
            for slot in 0..4 {
                row_slice[selector_cols[2][slot]] = selectors[2][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                row_slice[col] = Val::from_canonical_u64(slot_assets[idx]);
            }
        }
        if start_row_out1 < trace_len {
            let row_slice = trace.row_mut(start_row_out1);
            row_slice[COL_NOTE_START_OUT1] = Val::one();
            row_slice[COL_OUT_ACTIVE1] = flag_to_felt(output_flags[1]);
            row_slice[COL_OUT1_VALUE] = Val::from_canonical_u64(output_notes[1].note.value);
            row_slice[COL_OUT1_ASSET] = Val::from_canonical_u64(output_notes[1].note.asset_id);
            for slot in 0..4 {
                row_slice[selector_cols[3][slot]] = selectors[3][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                row_slice[col] = Val::from_canonical_u64(slot_assets[idx]);
            }
        }

        let final_row = trace_len.saturating_sub(2);
        if final_row < trace_len {
            let row_slice = trace.row_mut(final_row);
            row_slice[COL_FEE] = fee;
            row_slice[COL_VALUE_BALANCE_SIGN] = vb_sign;
            row_slice[COL_VALUE_BALANCE_MAG] = vb_mag;
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                row_slice[col] = Val::from_canonical_u64(slot_assets[idx]);
            }
            row_slice[COL_STABLECOIN_ENABLED] = stablecoin_inputs.enabled;
            row_slice[COL_STABLECOIN_ASSET] = stablecoin_inputs.asset;
            row_slice[COL_STABLECOIN_POLICY_VERSION] = stablecoin_inputs.policy_version;
            row_slice[COL_STABLECOIN_ISSUANCE_SIGN] = stablecoin_inputs.issuance_sign;
            row_slice[COL_STABLECOIN_ISSUANCE_MAG] = stablecoin_inputs.issuance_mag;
            row_slice[COL_STABLECOIN_POLICY_HASH0] = stablecoin_inputs.policy_hash[0];
            row_slice[COL_STABLECOIN_POLICY_HASH1] = stablecoin_inputs.policy_hash[1];
            row_slice[COL_STABLECOIN_POLICY_HASH2] = stablecoin_inputs.policy_hash[2];
            row_slice[COL_STABLECOIN_POLICY_HASH3] = stablecoin_inputs.policy_hash[3];
            row_slice[COL_STABLECOIN_ORACLE0] = stablecoin_inputs.oracle_commitment[0];
            row_slice[COL_STABLECOIN_ORACLE1] = stablecoin_inputs.oracle_commitment[1];
            row_slice[COL_STABLECOIN_ORACLE2] = stablecoin_inputs.oracle_commitment[2];
            row_slice[COL_STABLECOIN_ORACLE3] = stablecoin_inputs.oracle_commitment[3];
            row_slice[COL_STABLECOIN_ATTEST0] = stablecoin_inputs.attestation_commitment[0];
            row_slice[COL_STABLECOIN_ATTEST1] = stablecoin_inputs.attestation_commitment[1];
            row_slice[COL_STABLECOIN_ATTEST2] = stablecoin_inputs.attestation_commitment[2];
            row_slice[COL_STABLECOIN_ATTEST3] = stablecoin_inputs.attestation_commitment[3];
            row_slice[COL_STABLECOIN_SLOT_SEL0] = stablecoin_inputs.slot_selectors[0];
            row_slice[COL_STABLECOIN_SLOT_SEL1] = stablecoin_inputs.slot_selectors[1];
            row_slice[COL_STABLECOIN_SLOT_SEL2] = stablecoin_inputs.slot_selectors[2];
            row_slice[COL_STABLECOIN_SLOT_SEL3] = stablecoin_inputs.slot_selectors[3];
        }

        if final_row < trace_len {
            let one = Val::one();
            let stablecoin_sel_cols = [
                COL_STABLECOIN_SLOT_SEL0,
                COL_STABLECOIN_SLOT_SEL1,
                COL_STABLECOIN_SLOT_SEL2,
                COL_STABLECOIN_SLOT_SEL3,
            ];
            for row in 0..trace_len {
                let is_final = row == final_row;
                let enabled = bool_trace_value(stablecoin_inputs.enabled, is_final);
                let issuance_sign = bool_trace_value(stablecoin_inputs.issuance_sign, is_final);
                let row_slice = trace.row_mut(row);
                row_slice[COL_STABLECOIN_ENABLED] = enabled;
                row_slice[COL_STABLECOIN_ISSUANCE_SIGN] = issuance_sign;
                for (idx, &col) in stablecoin_sel_cols.iter().enumerate() {
                    row_slice[col] = bool_trace_value(stablecoin_inputs.slot_selectors[idx], is_final);
                }

                if !is_final {
                    row_slice[COL_STABLECOIN_ASSET] = stablecoin_inputs.asset + one;
                    row_slice[COL_STABLECOIN_POLICY_VERSION] =
                        stablecoin_inputs.policy_version + one;
                    row_slice[COL_STABLECOIN_ISSUANCE_MAG] = stablecoin_inputs.issuance_mag + one;
                    row_slice[COL_STABLECOIN_POLICY_HASH0] =
                        stablecoin_inputs.policy_hash[0] + one;
                    row_slice[COL_STABLECOIN_POLICY_HASH1] =
                        stablecoin_inputs.policy_hash[1] + one;
                    row_slice[COL_STABLECOIN_POLICY_HASH2] =
                        stablecoin_inputs.policy_hash[2] + one;
                    row_slice[COL_STABLECOIN_POLICY_HASH3] =
                        stablecoin_inputs.policy_hash[3] + one;
                    row_slice[COL_STABLECOIN_ORACLE0] =
                        stablecoin_inputs.oracle_commitment[0] + one;
                    row_slice[COL_STABLECOIN_ORACLE1] =
                        stablecoin_inputs.oracle_commitment[1] + one;
                    row_slice[COL_STABLECOIN_ORACLE2] =
                        stablecoin_inputs.oracle_commitment[2] + one;
                    row_slice[COL_STABLECOIN_ORACLE3] =
                        stablecoin_inputs.oracle_commitment[3] + one;
                    row_slice[COL_STABLECOIN_ATTEST0] =
                        stablecoin_inputs.attestation_commitment[0] + one;
                    row_slice[COL_STABLECOIN_ATTEST1] =
                        stablecoin_inputs.attestation_commitment[1] + one;
                    row_slice[COL_STABLECOIN_ATTEST2] =
                        stablecoin_inputs.attestation_commitment[2] + one;
                    row_slice[COL_STABLECOIN_ATTEST3] =
                        stablecoin_inputs.attestation_commitment[3] + one;
                }
            }
        }

        let mut slot_in_acc = [0u64; 4];
        let mut slot_out_acc = [0u64; 4];
        for row in 1..trace_len {
            let row_slice = trace.row_mut(row);
            for slot in 0..4 {
                row_slice[slot_in_cols[slot]] = Val::from_canonical_u64(slot_in_acc[slot]);
                row_slice[slot_out_cols[slot]] = Val::from_canonical_u64(slot_out_acc[slot]);
            }

            if row == start_row_in0 && start_row_in0 < trace_len {
                for slot in 0..4 {
                    if selectors[0][slot] == Val::one() {
                        slot_in_acc[slot] =
                            slot_in_acc[slot].saturating_add(input_notes[0].note.value);
                    }
                }
            }
            if row == start_row_in1 && start_row_in1 < trace_len {
                for slot in 0..4 {
                    if selectors[1][slot] == Val::one() {
                        slot_in_acc[slot] =
                            slot_in_acc[slot].saturating_add(input_notes[1].note.value);
                    }
                }
            }
            if row == start_row_out0 && start_row_out0 < trace_len {
                for slot in 0..4 {
                    if selectors[2][slot] == Val::one() {
                        slot_out_acc[slot] =
                            slot_out_acc[slot].saturating_add(output_notes[0].note.value);
                    }
                }
            }
            if row == start_row_out1 && start_row_out1 < trace_len {
                for slot in 0..4 {
                    if selectors[3][slot] == Val::one() {
                        slot_out_acc[slot] =
                            slot_out_acc[slot].saturating_add(output_notes[1].note.value);
                    }
                }
            }
        }

        let cycle_specs = build_cycle_specs(&input_notes, &output_notes, witness);
        let mut prev_state = [Val::zero(), Val::zero(), Val::one()];
        let mut out0 = Val::zero();
        let mut out1 = Val::zero();
        let mut out2 = Val::zero();
        let mut out3 = Val::zero();

        for cycle in 0..TOTAL_TRACE_CYCLES {
            let cycle_start = cycle * CYCLE_LENGTH;
            if cycle_start + CYCLE_LENGTH > trace_len {
                break;
            }

            let (state_start, dir) = if cycle == 0 {
                (prev_state, Val::zero())
            } else {
                let spec = cycle_specs.get(cycle - 1).cloned().unwrap_or(CycleSpec {
                    reset: false,
                    domain: 0,
                    in0: Val::zero(),
                    in1: Val::zero(),
                    dir: Val::zero(),
                });
                let state_start = if spec.reset {
                    [
                        Val::from_canonical_u64(spec.domain) + spec.in0,
                        spec.in1,
                        Val::one(),
                    ]
                } else {
                    [prev_state[0] + spec.in0, prev_state[1] + spec.in1, prev_state[2]]
                };
                (state_start, spec.dir)
            };

            let mut state = state_start;
            for round in 0..POSEIDON_ROUNDS {
                let row = cycle_start + round;
                let row_slice = trace.row_mut(row);
                row_slice[COL_S0] = state[0];
                row_slice[COL_S1] = state[1];
                row_slice[COL_S2] = state[2];
                row_slice[COL_OUT0] = out0;
                row_slice[COL_OUT1] = out1;
                row_slice[COL_OUT2] = out2;
                row_slice[COL_OUT3] = out3;
                row_slice[COL_DIR] = dir;
                poseidon_round(&mut state, round);
            }

            for step in POSEIDON_ROUNDS..CYCLE_LENGTH {
                let row = cycle_start + step;
                let row_slice = trace.row_mut(row);
                row_slice[COL_S0] = state[0];
                row_slice[COL_S1] = state[1];
                row_slice[COL_S2] = state[2];
                row_slice[COL_OUT0] = out0;
                row_slice[COL_OUT1] = out1;
                row_slice[COL_OUT2] = out2;
                row_slice[COL_OUT3] = out3;
                row_slice[COL_DIR] = dir;
            }

            prev_state = state;

            let end_row = cycle_start + (CYCLE_LENGTH - 1);
            if end_row < trace_len {
                let next_cycle = cycle + 1;
                let next_spec = cycle_specs.get(next_cycle - 1).cloned().unwrap_or(CycleSpec {
                    reset: false,
                    domain: 0,
                    in0: Val::zero(),
                    in1: Val::zero(),
                    dir: Val::zero(),
                });
                let row_slice = trace.row_mut(end_row);
                row_slice[COL_IN0] = next_spec.in0;
                row_slice[COL_IN1] = next_spec.in1;

                if let Some(domain) = cycle_reset_domain(next_cycle) {
                    row_slice[COL_RESET] = Val::one();
                    row_slice[COL_DOMAIN] = Val::from_canonical_u64(domain);
                } else {
                    row_slice[COL_RESET] = Val::zero();
                    row_slice[COL_DOMAIN] = Val::zero();
                }

                row_slice[COL_MERKLE_LEFT_23] = flag_to_felt(cycle_is_merkle_left_23(next_cycle));
                row_slice[COL_MERKLE_LEFT_01] = flag_to_felt(cycle_is_merkle_left_01(next_cycle));
                row_slice[COL_MERKLE_RIGHT_23] = flag_to_felt(cycle_is_merkle_right_23(next_cycle));
                row_slice[COL_MERKLE_RIGHT_01] = flag_to_felt(cycle_is_merkle_right_01(next_cycle));
                let capture = cycle_is_squeeze(next_cycle);
                row_slice[COL_CAPTURE] = flag_to_felt(capture);
                let capture2 = cycle_is_squeeze(cycle);
                row_slice[COL_CAPTURE2] = flag_to_felt(capture2);

                if capture {
                    out0 = state[0];
                    out1 = state[1];
                }
                if capture2 {
                    out2 = state[0];
                    out3 = state[1];
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
            nullifiers.push(crate::hashing::nullifier(
                prf,
                &input.note.rho,
                input.position,
            ));
        }
        while nullifiers.len() < MAX_INPUTS {
            nullifiers.push([Felt::ZERO; 4]);
        }

        let mut commitments: Vec<HashFelt> =
            witness.outputs.iter().map(|note| note.note.commitment()).collect();
        while commitments.len() < MAX_OUTPUTS {
            commitments.push([Felt::ZERO; 4]);
        }

        let merkle_root = bytes32_to_felts(&witness.merkle_root).ok_or(
            TransactionCircuitError::ConstraintViolation("invalid merkle root encoding"),
        )?;
        let slots = witness.balance_slots()?;
        let slot_assets: Vec<u64> = slots.iter().map(|slot| slot.asset_id).collect();
        let stablecoin_inputs = stablecoin_binding_inputs(witness, &slot_assets)?;
        let (vb_sign, vb_mag) = value_balance_parts(witness.value_balance)?;

        Ok(TransactionPublicInputsP3 {
            input_flags,
            output_flags,
            nullifiers: nullifiers.into_iter().map(hash_to_gl).collect(),
            commitments: commitments.into_iter().map(hash_to_gl).collect(),
            fee: Val::from_canonical_u64(witness.fee),
            value_balance_sign: vb_sign,
            value_balance_magnitude: vb_mag,
            merkle_root: hash_to_gl(merkle_root),
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
                Val::zero()
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
                Val::zero()
            };
            output_flags.push(flag);
        }

        let read_hash = |row: usize| -> [Val; 4] {
            [
                get_trace(trace, COL_OUT0, row),
                get_trace(trace, COL_OUT1, row),
                get_trace(trace, COL_S0, row),
                get_trace(trace, COL_S1, row),
            ]
        };

        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for (i, flag) in input_flags.iter().enumerate() {
            let row = nullifier_output_row(i);
            let nf = if *flag == Val::one() && row < trace_len {
                read_hash(row)
            } else {
                [Val::zero(); 4]
            };
            nullifiers.push(nf);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for (i, flag) in output_flags.iter().enumerate() {
            let row = commitment_output_row(i);
            let cm = if *flag == Val::one() && row < trace_len {
                read_hash(row)
            } else {
                [Val::zero(); 4]
            };
            commitments.push(cm);
        }

        let merkle_root = if trace_len > 0 {
            let row = merkle_root_output_row(0);
            if row < trace_len {
                read_hash(row)
            } else {
                [Val::zero(); 4]
            }
        } else {
            [Val::zero(); 4]
        };

        let final_row = trace_len.saturating_sub(2);
        TransactionPublicInputsP3 {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            fee: get_trace(trace, COL_FEE, final_row),
            value_balance_sign: get_trace(trace, COL_VALUE_BALANCE_SIGN, final_row),
            value_balance_magnitude: get_trace(trace, COL_VALUE_BALANCE_MAG, final_row),
            merkle_root,
            stablecoin_enabled: get_trace(trace, COL_STABLECOIN_ENABLED, final_row),
            stablecoin_asset: get_trace(trace, COL_STABLECOIN_ASSET, final_row),
            stablecoin_policy_version: get_trace(trace, COL_STABLECOIN_POLICY_VERSION, final_row),
            stablecoin_issuance_sign: get_trace(trace, COL_STABLECOIN_ISSUANCE_SIGN, final_row),
            stablecoin_issuance_magnitude: get_trace(trace, COL_STABLECOIN_ISSUANCE_MAG, final_row),
            stablecoin_policy_hash: [
                get_trace(trace, COL_STABLECOIN_POLICY_HASH0, final_row),
                get_trace(trace, COL_STABLECOIN_POLICY_HASH1, final_row),
                get_trace(trace, COL_STABLECOIN_POLICY_HASH2, final_row),
                get_trace(trace, COL_STABLECOIN_POLICY_HASH3, final_row),
            ],
            stablecoin_oracle_commitment: [
                get_trace(trace, COL_STABLECOIN_ORACLE0, final_row),
                get_trace(trace, COL_STABLECOIN_ORACLE1, final_row),
                get_trace(trace, COL_STABLECOIN_ORACLE2, final_row),
                get_trace(trace, COL_STABLECOIN_ORACLE3, final_row),
            ],
            stablecoin_attestation_commitment: [
                get_trace(trace, COL_STABLECOIN_ATTEST0, final_row),
                get_trace(trace, COL_STABLECOIN_ATTEST1, final_row),
                get_trace(trace, COL_STABLECOIN_ATTEST2, final_row),
                get_trace(trace, COL_STABLECOIN_ATTEST3, final_row),
            ],
        }
    }

    pub fn prove(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &TransactionPublicInputsP3,
    ) -> TransactionProofP3 {
        let config = default_config();
        let mut challenger = new_challenger(&config.perm);
        prove(
            &config.config,
            &TransactionAirP3,
            &mut challenger,
            trace,
            &pub_inputs.to_vec(),
        )
    }

    pub fn prove_bytes(
        &self,
        trace: RowMajorMatrix<Val>,
        pub_inputs: &TransactionPublicInputsP3,
    ) -> Result<Vec<u8>, TransactionCircuitError> {
        let proof = self.prove(trace, pub_inputs);
        bincode::serialize(&proof).map_err(|_| {
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

fn bool_trace_value(value: Val, is_final: bool) -> Val {
    if value == Val::one() {
        if is_final {
            Val::one()
        } else {
            Val::zero()
        }
    } else if is_final {
        Val::zero()
    } else {
        Val::one()
    }
}

fn get_trace(trace: &RowMajorMatrix<Val>, col: usize, row: usize) -> Val {
    trace.values[row * trace.width + col]
}

fn hash_to_gl(hash: HashFelt) -> [Val; 4] {
    [
        Val::from_canonical_u64(hash[0].as_int()),
        Val::from_canonical_u64(hash[1].as_int()),
        Val::from_canonical_u64(hash[2].as_int()),
        Val::from_canonical_u64(hash[3].as_int()),
    ]
}

fn bytes_to_felts(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            Felt::new(u64::from_be_bytes(buf))
        })
        .collect()
}

fn commitment_inputs(note: &NoteData) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(Felt::new(note.value));
    inputs.push(Felt::new(note.asset_id));
    inputs.extend(bytes_to_felts(&note.pk_recipient));
    inputs.extend(bytes_to_felts(&note.rho));
    inputs.extend(bytes_to_felts(&note.r));
    inputs
}

fn nullifier_inputs(prf: Felt, input: &InputNoteWitness) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(prf);
    inputs.push(Felt::new(input.position));
    inputs.extend(bytes_to_felts(&input.note.rho));
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
            rho: [0u8; 32],
            r: [0u8; 32],
        },
    }
}

fn build_selectors(
    inputs: &[InputNoteWitness],
    outputs: &[OutputNoteWitness],
    slot_assets: &[u64],
    input_flags: &[bool; MAX_INPUTS],
    output_flags: &[bool; MAX_OUTPUTS],
) -> [[Val; 4]; 4] {
    let mut selectors = [[Val::zero(); 4]; 4];

    for (idx, note) in inputs.iter().enumerate() {
        if input_flags[idx] {
            if let Some(slot_idx) = slot_assets.iter().position(|id| *id == note.note.asset_id) {
                selectors[idx][slot_idx] = Val::one();
            }
        }
    }

    for (idx, note) in outputs.iter().enumerate() {
        if output_flags[idx] {
            if let Some(slot_idx) = slot_assets.iter().position(|id| *id == note.note.asset_id) {
                selectors[2 + idx][slot_idx] = Val::one();
            }
        }
    }

    selectors
}

fn value_balance_parts(value_balance: i128) -> Result<(Val, Val), TransactionCircuitError> {
    let magnitude = value_balance.unsigned_abs();
    let mag_u64 = u64::try_from(magnitude)
        .map_err(|_| TransactionCircuitError::ValueBalanceOutOfRange(magnitude))?;
    let sign = if value_balance < 0 { Val::one() } else { Val::zero() };
    Ok((sign, Val::from_canonical_u64(mag_u64)))
}

struct StablecoinBindingInputs {
    enabled: Val,
    asset: Val,
    policy_version: Val,
    issuance_sign: Val,
    issuance_mag: Val,
    policy_hash: [Val; 4],
    oracle_commitment: [Val; 4],
    attestation_commitment: [Val; 4],
    slot_selectors: [Val; 4],
}

fn stablecoin_binding_inputs(
    witness: &TransactionWitness,
    slot_assets: &[u64],
) -> Result<StablecoinBindingInputs, TransactionCircuitError> {
    if !witness.stablecoin.enabled {
        return Ok(StablecoinBindingInputs {
            enabled: Val::zero(),
            asset: Val::zero(),
            policy_version: Val::zero(),
            issuance_sign: Val::zero(),
            issuance_mag: Val::zero(),
            policy_hash: [Val::zero(); 4],
            oracle_commitment: [Val::zero(); 4],
            attestation_commitment: [Val::zero(); 4],
            slot_selectors: [Val::zero(); 4],
        });
    }

    let policy_hash = bytes32_to_felts(&witness.stablecoin.policy_hash).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid stablecoin policy hash encoding"),
    )?;
    let oracle_commitment = bytes32_to_felts(&witness.stablecoin.oracle_commitment).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid stablecoin oracle commitment encoding"),
    )?;
    let attestation_commitment =
        bytes32_to_felts(&witness.stablecoin.attestation_commitment).ok_or(
            TransactionCircuitError::ConstraintViolation(
                "invalid stablecoin attestation commitment encoding",
            ),
        )?;

    let (issuance_sign, issuance_mag) = value_balance_parts(witness.stablecoin.issuance_delta)?;
    let mut slot_selectors = [Val::zero(); 4];
    let slot_index = slot_assets
        .iter()
        .position(|asset_id| *asset_id == witness.stablecoin.asset_id)
        .ok_or(TransactionCircuitError::BalanceMismatch(
            witness.stablecoin.asset_id,
        ))?;
    if slot_index >= slot_selectors.len() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "stablecoin slot index overflow",
        ));
    }
    slot_selectors[slot_index] = Val::one();

    Ok(StablecoinBindingInputs {
        enabled: Val::one(),
        asset: Val::from_canonical_u64(witness.stablecoin.asset_id),
        policy_version: Val::from_canonical_u64(u64::from(witness.stablecoin.policy_version)),
        issuance_sign,
        issuance_mag,
        policy_hash: hash_to_gl(policy_hash),
        oracle_commitment: hash_to_gl(oracle_commitment),
        attestation_commitment: hash_to_gl(attestation_commitment),
        slot_selectors,
    })
}

fn build_cycle_specs(
    inputs: &[InputNoteWitness],
    outputs: &[OutputNoteWitness],
    witness: &TransactionWitness,
) -> Vec<CycleSpec> {
    let prf = prf_key(&witness.sk_spend);
    let mut cycles = Vec::with_capacity(TOTAL_USED_CYCLES - DUMMY_CYCLES);

    for input in inputs.iter() {
        let commitment_inputs = commitment_inputs(&input.note);
        for chunk_idx in 0..COMMITMENT_ABSORB_CYCLES {
            let reset = chunk_idx == 0;
            let domain = if reset { NOTE_DOMAIN_TAG } else { 0 };
            let in0 = commitment_inputs[chunk_idx * 2];
            let in1 = commitment_inputs[chunk_idx * 2 + 1];
            cycles.push(CycleSpec {
                reset,
                domain,
                in0: Val::from_canonical_u64(in0.as_int()),
                in1: Val::from_canonical_u64(in1.as_int()),
                dir: Val::zero(),
            });
        }
        cycles.push(CycleSpec {
            reset: false,
            domain: 0,
            in0: Val::zero(),
            in1: Val::zero(),
            dir: Val::zero(),
        });

        let mut current = input.note.commitment();
        let mut pos = input.position;
        for level in 0..CIRCUIT_MERKLE_DEPTH {
            let dir = if pos & 1 == 0 { Val::zero() } else { Val::one() };
            let sibling = input
                .merkle_path
                .siblings
                .get(level)
                .copied()
                .unwrap_or([Felt::ZERO; 4]);
            let (left, right) = if pos & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            let left_ordered = [left[2], left[3], left[0], left[1]];
            let right_ordered = [right[2], right[3], right[0], right[1]];
            for pair_idx in 0..MERKLE_ABSORB_CYCLES {
                let reset = pair_idx == 0;
                let domain = if reset { MERKLE_DOMAIN_TAG } else { 0 };
                let (in0, in1) = if pair_idx < 2 {
                    let idx = pair_idx * 2;
                    (left_ordered[idx], left_ordered[idx + 1])
                } else {
                    let idx = (pair_idx - 2) * 2;
                    (right_ordered[idx], right_ordered[idx + 1])
                };
                cycles.push(CycleSpec {
                    reset,
                    domain,
                    in0: Val::from_canonical_u64(in0.as_int()),
                    in1: Val::from_canonical_u64(in1.as_int()),
                    dir,
                });
            }
            cycles.push(CycleSpec {
                reset: false,
                domain: 0,
                in0: Val::zero(),
                in1: Val::zero(),
                dir,
            });
            current = merkle_node(left, right);
            pos >>= 1;
        }

        let nullifier_inputs = nullifier_inputs(prf, input);
        for chunk_idx in 0..NULLIFIER_ABSORB_CYCLES {
            let reset = chunk_idx == 0;
            let domain = if reset { NULLIFIER_DOMAIN_TAG } else { 0 };
            let in0 = nullifier_inputs[chunk_idx * 2];
            let in1 = nullifier_inputs[chunk_idx * 2 + 1];
            cycles.push(CycleSpec {
                reset,
                domain,
                in0: Val::from_canonical_u64(in0.as_int()),
                in1: Val::from_canonical_u64(in1.as_int()),
                dir: Val::zero(),
            });
        }
        cycles.push(CycleSpec {
            reset: false,
            domain: 0,
            in0: Val::zero(),
            in1: Val::zero(),
            dir: Val::zero(),
        });
    }

    for output in outputs.iter() {
        let commitment_inputs = commitment_inputs(&output.note);
        for chunk_idx in 0..COMMITMENT_ABSORB_CYCLES {
            let reset = chunk_idx == 0;
            let domain = if reset { NOTE_DOMAIN_TAG } else { 0 };
            let in0 = commitment_inputs[chunk_idx * 2];
            let in1 = commitment_inputs[chunk_idx * 2 + 1];
            cycles.push(CycleSpec {
                reset,
                domain,
                in0: Val::from_canonical_u64(in0.as_int()),
                in1: Val::from_canonical_u64(in1.as_int()),
                dir: Val::zero(),
            });
        }
        cycles.push(CycleSpec {
            reset: false,
            domain: 0,
            in0: Val::zero(),
            in1: Val::zero(),
            dir: Val::zero(),
        });
    }

    cycles
}

fn poseidon_round(state: &mut [Val; 3], round: usize) {
    state[0] += round_constant(round, 0);
    state[1] += round_constant(round, 1);
    state[2] += round_constant(round, 2);
    state[0] = transaction_core::p3_air::sbox(state[0]);
    state[1] = transaction_core::p3_air::sbox(state[1]);
    state[2] = transaction_core::p3_air::sbox(state[2]);
    *state = transaction_core::p3_air::mds_mix(state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::{felts_to_bytes32, merkle_node, HashFelt};
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
        let input_note = NoteData {
            value: 100,
            asset_id: 0,
            pk_recipient: [1u8; 32],
            rho: [2u8; 32],
            r: [3u8; 32],
        };
        let output_note = NoteData {
            value: 80,
            asset_id: 0,
            pk_recipient: [4u8; 32],
            rho: [5u8; 32],
            r: [6u8; 32],
        };
        let merkle_path = MerklePath::default();
        let leaf = input_note.commitment();
        let merkle_root = felts_to_bytes32(&compute_merkle_root_from_path(leaf, 0, &merkle_path));

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [7u8; 32],
                merkle_path,
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            sk_spend: [8u8; 32],
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
    #[ignore = "slow: full Plonky3 prove/verify roundtrip"]
    fn prove_verify_roundtrip_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = prover.public_inputs(&witness).expect("public inputs");
        let proof = prover.prove(trace, &pub_inputs);
        verify_transaction_proof_p3(&proof, &pub_inputs).expect("verification should pass");
    }

    #[test]
    fn counter_mismatch_rejected_p3() {
        let witness = sample_witness();
        witness.validate().expect("witness valid");
        let prover = TransactionProverP3::new();
        let mut trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = prover.public_inputs(&witness).expect("public inputs");

        let row = 1;
        let col = COL_STEP_BIT0;
        let idx = row * trace.width + col;
        trace.values[idx] = if trace.values[idx] == Val::zero() {
            Val::one()
        } else {
            Val::zero()
        };

        let result = catch_unwind(|| prover.prove(trace, &pub_inputs));
        match result {
            Ok(proof) => assert!(
                verify_transaction_proof_p3(&proof, &pub_inputs).is_err(),
                "verification should fail for tampered counters"
            ),
            Err(_) => {}
        }
    }
}
