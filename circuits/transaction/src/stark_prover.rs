//! Real STARK prover for transaction circuits.
//!
//! Builds traces that satisfy the Poseidon AIR with explicit absorption/reset steps
//! and MASP balance constraints.

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable,
};

use crate::{
    constants::{
        CIRCUIT_MERKLE_DEPTH, MAX_INPUTS, MAX_OUTPUTS, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG,
        NULLIFIER_DOMAIN_TAG, POSEIDON_ROUNDS,
    },
    hashing::{bytes32_to_felts, merkle_node, prf_key, Felt},
    note::{InputNoteWitness, NoteData, OutputNoteWitness},
    stark_air::{
        commitment_output_row, cycle_is_merkle_left_01, cycle_is_merkle_left_23,
        cycle_is_merkle_right_01, cycle_is_merkle_right_23, cycle_is_squeeze, cycle_reset_domain,
        merkle_root_output_row, note_start_row_input, note_start_row_output, nullifier_output_row,
        poseidon_round, TransactionAirStark, TransactionPublicInputsStark, COL_CAPTURE,
        COL_CAPTURE2, COL_DIR, COL_DOMAIN, COL_FEE, COL_IN0, COL_IN0_ASSET, COL_IN0_VALUE, COL_IN1,
        COL_IN1_ASSET, COL_IN1_VALUE, COL_IN_ACTIVE0, COL_IN_ACTIVE1, COL_MERKLE_LEFT_01,
        COL_MERKLE_LEFT_23, COL_MERKLE_RIGHT_01, COL_MERKLE_RIGHT_23, COL_NOTE_START_IN0,
        COL_NOTE_START_IN1, COL_NOTE_START_OUT0, COL_NOTE_START_OUT1, COL_OUT0, COL_OUT0_ASSET,
        COL_OUT0_VALUE, COL_OUT1, COL_OUT1_ASSET, COL_OUT1_VALUE, COL_OUT2, COL_OUT3,
        COL_OUT_ACTIVE0, COL_OUT_ACTIVE1, COL_RESET, COL_S0, COL_S1, COL_S2, COL_SEL_IN0_SLOT0,
        COL_SEL_IN0_SLOT1, COL_SEL_IN0_SLOT2, COL_SEL_IN0_SLOT3, COL_SEL_IN1_SLOT0,
        COL_SEL_IN1_SLOT1, COL_SEL_IN1_SLOT2, COL_SEL_IN1_SLOT3, COL_SEL_OUT0_SLOT0,
        COL_SEL_OUT0_SLOT1, COL_SEL_OUT0_SLOT2, COL_SEL_OUT0_SLOT3, COL_SEL_OUT1_SLOT0,
        COL_SEL_OUT1_SLOT1, COL_SEL_OUT1_SLOT2, COL_SEL_OUT1_SLOT3, COL_SLOT0_ASSET, COL_SLOT0_IN,
        COL_SLOT0_OUT, COL_SLOT1_ASSET, COL_SLOT1_IN, COL_SLOT1_OUT, COL_SLOT2_ASSET, COL_SLOT2_IN,
        COL_SLOT2_OUT, COL_SLOT3_ASSET, COL_SLOT3_IN, COL_SLOT3_OUT, COL_STABLECOIN_ASSET,
        COL_STABLECOIN_ATTEST0, COL_STABLECOIN_ATTEST1, COL_STABLECOIN_ATTEST2,
        COL_STABLECOIN_ATTEST3, COL_STABLECOIN_ENABLED, COL_STABLECOIN_ISSUANCE_MAG,
        COL_STABLECOIN_ISSUANCE_SIGN, COL_STABLECOIN_ORACLE0, COL_STABLECOIN_ORACLE1,
        COL_STABLECOIN_ORACLE2, COL_STABLECOIN_ORACLE3, COL_STABLECOIN_POLICY_HASH0,
        COL_STABLECOIN_POLICY_HASH1, COL_STABLECOIN_POLICY_HASH2, COL_STABLECOIN_POLICY_HASH3,
        COL_STABLECOIN_POLICY_VERSION, COL_STABLECOIN_SLOT_SEL0, COL_STABLECOIN_SLOT_SEL1,
        COL_STABLECOIN_SLOT_SEL2, COL_STABLECOIN_SLOT_SEL3, COL_VALUE_BALANCE_MAG,
        COL_VALUE_BALANCE_SIGN, COMMITMENT_ABSORB_CYCLES, CYCLE_LENGTH, DUMMY_CYCLES,
        MERKLE_ABSORB_CYCLES, MIN_TRACE_LENGTH, NULLIFIER_ABSORB_CYCLES, TOTAL_TRACE_CYCLES,
        TOTAL_USED_CYCLES, TRACE_WIDTH,
    },
    witness::TransactionWitness,
    TransactionCircuitError,
};

type Blake3 = Blake3_256<BaseElement>;

#[derive(Clone, Copy)]
struct CycleSpec {
    reset: bool,
    domain: u64,
    in0: BaseElement,
    in1: BaseElement,
    dir: BaseElement,
}

// ================================================================================================
// PROVER
// ================================================================================================

pub struct TransactionProverStark {
    options: ProofOptions,
}

impl TransactionProverStark {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn with_default_options() -> Self {
        Self::new(default_proof_options())
    }

    pub fn build_trace(
        &self,
        witness: &TransactionWitness,
    ) -> Result<TraceTable<BaseElement>, TransactionCircuitError> {
        let trace_len = MIN_TRACE_LENGTH;
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];

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
        let fee = BaseElement::new(witness.fee);
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

        for &col in sentinel_cols.iter() {
            trace[col][sentinel_row] = BaseElement::ONE;
        }
        for cols in selector_cols.iter() {
            for &col in cols.iter() {
                trace[col][sentinel_row] = BaseElement::ONE;
            }
        }
        for &col in slot_asset_cols.iter() {
            trace[col][sentinel_row] = BaseElement::ONE;
        }
        for &col in slot_in_cols.iter() {
            trace[col][sentinel_row] = BaseElement::ONE;
        }
        for &col in slot_out_cols.iter() {
            trace[col][sentinel_row] = BaseElement::new(2);
        }

        // Note start flags and per-note data.
        let start_row_in0 = note_start_row_input(0);
        let start_row_in1 = note_start_row_input(1);
        let start_row_out0 = note_start_row_output(0);
        let start_row_out1 = note_start_row_output(1);
        if start_row_in0 < trace_len {
            trace[COL_NOTE_START_IN0][start_row_in0] = BaseElement::ONE;
            trace[COL_IN_ACTIVE0][start_row_in0] = flag_to_felt(input_flags[0]);
            trace[COL_IN0_VALUE][start_row_in0] = BaseElement::new(input_notes[0].note.value);
            trace[COL_IN0_ASSET][start_row_in0] = BaseElement::new(input_notes[0].note.asset_id);
            for slot in 0..4 {
                trace[selector_cols[0][slot]][start_row_in0] = selectors[0][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                trace[col][start_row_in0] = BaseElement::new(slot_assets[idx]);
            }
        }
        if start_row_in1 < trace_len {
            trace[COL_NOTE_START_IN1][start_row_in1] = BaseElement::ONE;
            trace[COL_IN_ACTIVE1][start_row_in1] = flag_to_felt(input_flags[1]);
            trace[COL_IN1_VALUE][start_row_in1] = BaseElement::new(input_notes[1].note.value);
            trace[COL_IN1_ASSET][start_row_in1] = BaseElement::new(input_notes[1].note.asset_id);
            for slot in 0..4 {
                trace[selector_cols[1][slot]][start_row_in1] = selectors[1][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                trace[col][start_row_in1] = BaseElement::new(slot_assets[idx]);
            }
        }
        if start_row_out0 < trace_len {
            trace[COL_NOTE_START_OUT0][start_row_out0] = BaseElement::ONE;
            trace[COL_OUT_ACTIVE0][start_row_out0] = flag_to_felt(output_flags[0]);
            trace[COL_OUT0_VALUE][start_row_out0] = BaseElement::new(output_notes[0].note.value);
            trace[COL_OUT0_ASSET][start_row_out0] = BaseElement::new(output_notes[0].note.asset_id);
            for slot in 0..4 {
                trace[selector_cols[2][slot]][start_row_out0] = selectors[2][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                trace[col][start_row_out0] = BaseElement::new(slot_assets[idx]);
            }
        }
        if start_row_out1 < trace_len {
            trace[COL_NOTE_START_OUT1][start_row_out1] = BaseElement::ONE;
            trace[COL_OUT_ACTIVE1][start_row_out1] = flag_to_felt(output_flags[1]);
            trace[COL_OUT1_VALUE][start_row_out1] = BaseElement::new(output_notes[1].note.value);
            trace[COL_OUT1_ASSET][start_row_out1] = BaseElement::new(output_notes[1].note.asset_id);
            for slot in 0..4 {
                trace[selector_cols[3][slot]][start_row_out1] = selectors[3][slot];
            }
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                trace[col][start_row_out1] = BaseElement::new(slot_assets[idx]);
            }
        }

        let final_row = trace_len.saturating_sub(2);
        if final_row < trace_len {
            trace[COL_FEE][final_row] = fee;
            trace[COL_VALUE_BALANCE_SIGN][final_row] = vb_sign;
            trace[COL_VALUE_BALANCE_MAG][final_row] = vb_mag;
            for (idx, &col) in slot_asset_cols.iter().enumerate() {
                trace[col][final_row] = BaseElement::new(slot_assets[idx]);
            }
            trace[COL_STABLECOIN_ENABLED][final_row] = stablecoin_inputs.enabled;
            trace[COL_STABLECOIN_ASSET][final_row] = stablecoin_inputs.asset;
            trace[COL_STABLECOIN_POLICY_VERSION][final_row] = stablecoin_inputs.policy_version;
            trace[COL_STABLECOIN_ISSUANCE_SIGN][final_row] = stablecoin_inputs.issuance_sign;
            trace[COL_STABLECOIN_ISSUANCE_MAG][final_row] = stablecoin_inputs.issuance_mag;
            trace[COL_STABLECOIN_POLICY_HASH0][final_row] = stablecoin_inputs.policy_hash[0];
            trace[COL_STABLECOIN_POLICY_HASH1][final_row] = stablecoin_inputs.policy_hash[1];
            trace[COL_STABLECOIN_POLICY_HASH2][final_row] = stablecoin_inputs.policy_hash[2];
            trace[COL_STABLECOIN_POLICY_HASH3][final_row] = stablecoin_inputs.policy_hash[3];
            trace[COL_STABLECOIN_ORACLE0][final_row] = stablecoin_inputs.oracle_commitment[0];
            trace[COL_STABLECOIN_ORACLE1][final_row] = stablecoin_inputs.oracle_commitment[1];
            trace[COL_STABLECOIN_ORACLE2][final_row] = stablecoin_inputs.oracle_commitment[2];
            trace[COL_STABLECOIN_ORACLE3][final_row] = stablecoin_inputs.oracle_commitment[3];
            trace[COL_STABLECOIN_ATTEST0][final_row] = stablecoin_inputs.attestation_commitment[0];
            trace[COL_STABLECOIN_ATTEST1][final_row] = stablecoin_inputs.attestation_commitment[1];
            trace[COL_STABLECOIN_ATTEST2][final_row] = stablecoin_inputs.attestation_commitment[2];
            trace[COL_STABLECOIN_ATTEST3][final_row] = stablecoin_inputs.attestation_commitment[3];
            trace[COL_STABLECOIN_SLOT_SEL0][final_row] = stablecoin_inputs.slot_selectors[0];
            trace[COL_STABLECOIN_SLOT_SEL1][final_row] = stablecoin_inputs.slot_selectors[1];
            trace[COL_STABLECOIN_SLOT_SEL2][final_row] = stablecoin_inputs.slot_selectors[2];
            trace[COL_STABLECOIN_SLOT_SEL3][final_row] = stablecoin_inputs.slot_selectors[3];
        }

        if final_row < trace_len {
            let one = BaseElement::ONE;
            let stablecoin_sel_cols = [
                COL_STABLECOIN_SLOT_SEL0,
                COL_STABLECOIN_SLOT_SEL1,
                COL_STABLECOIN_SLOT_SEL2,
                COL_STABLECOIN_SLOT_SEL3,
            ];
            #[allow(clippy::needless_range_loop)]
            for row in 0..trace_len {
                let is_final = row == final_row;
                let enabled = bool_trace_value(stablecoin_inputs.enabled, is_final);
                let issuance_sign = bool_trace_value(stablecoin_inputs.issuance_sign, is_final);
                trace[COL_STABLECOIN_ENABLED][row] = enabled;
                trace[COL_STABLECOIN_ISSUANCE_SIGN][row] = issuance_sign;
                for (idx, &col) in stablecoin_sel_cols.iter().enumerate() {
                    trace[col][row] =
                        bool_trace_value(stablecoin_inputs.slot_selectors[idx], is_final);
                }

                if !is_final {
                    trace[COL_STABLECOIN_ASSET][row] = stablecoin_inputs.asset + one;
                    trace[COL_STABLECOIN_POLICY_VERSION][row] =
                        stablecoin_inputs.policy_version + one;
                    trace[COL_STABLECOIN_ISSUANCE_MAG][row] = stablecoin_inputs.issuance_mag + one;
                    trace[COL_STABLECOIN_POLICY_HASH0][row] =
                        stablecoin_inputs.policy_hash[0] + one;
                    trace[COL_STABLECOIN_POLICY_HASH1][row] =
                        stablecoin_inputs.policy_hash[1] + one;
                    trace[COL_STABLECOIN_POLICY_HASH2][row] =
                        stablecoin_inputs.policy_hash[2] + one;
                    trace[COL_STABLECOIN_POLICY_HASH3][row] =
                        stablecoin_inputs.policy_hash[3] + one;
                    trace[COL_STABLECOIN_ORACLE0][row] =
                        stablecoin_inputs.oracle_commitment[0] + one;
                    trace[COL_STABLECOIN_ORACLE1][row] =
                        stablecoin_inputs.oracle_commitment[1] + one;
                    trace[COL_STABLECOIN_ORACLE2][row] =
                        stablecoin_inputs.oracle_commitment[2] + one;
                    trace[COL_STABLECOIN_ORACLE3][row] =
                        stablecoin_inputs.oracle_commitment[3] + one;
                    trace[COL_STABLECOIN_ATTEST0][row] =
                        stablecoin_inputs.attestation_commitment[0] + one;
                    trace[COL_STABLECOIN_ATTEST1][row] =
                        stablecoin_inputs.attestation_commitment[1] + one;
                    trace[COL_STABLECOIN_ATTEST2][row] =
                        stablecoin_inputs.attestation_commitment[2] + one;
                    trace[COL_STABLECOIN_ATTEST3][row] =
                        stablecoin_inputs.attestation_commitment[3] + one;
                }
            }
        }

        let mut slot_in_acc = [0u64; 4];
        let mut slot_out_acc = [0u64; 4];
        #[allow(clippy::needless_range_loop)]
        for row in 1..trace_len {
            for slot in 0..4 {
                trace[slot_in_cols[slot]][row] = BaseElement::new(slot_in_acc[slot]);
                trace[slot_out_cols[slot]][row] = BaseElement::new(slot_out_acc[slot]);
            }

            if row == start_row_in0 && start_row_in0 < trace_len {
                for slot in 0..4 {
                    if selectors[0][slot] == BaseElement::ONE {
                        slot_in_acc[slot] =
                            slot_in_acc[slot].saturating_add(input_notes[0].note.value);
                    }
                }
            }
            if row == start_row_in1 && start_row_in1 < trace_len {
                for slot in 0..4 {
                    if selectors[1][slot] == BaseElement::ONE {
                        slot_in_acc[slot] =
                            slot_in_acc[slot].saturating_add(input_notes[1].note.value);
                    }
                }
            }
            if row == start_row_out0 && start_row_out0 < trace_len {
                for slot in 0..4 {
                    if selectors[2][slot] == BaseElement::ONE {
                        slot_out_acc[slot] =
                            slot_out_acc[slot].saturating_add(output_notes[0].note.value);
                    }
                }
            }
            if row == start_row_out1 && start_row_out1 < trace_len {
                for slot in 0..4 {
                    if selectors[3][slot] == BaseElement::ONE {
                        slot_out_acc[slot] =
                            slot_out_acc[slot].saturating_add(output_notes[1].note.value);
                    }
                }
            }
        }

        let cycle_specs = build_cycle_specs(&input_notes, &output_notes, witness);
        let mut prev_state = [BaseElement::ZERO, BaseElement::ZERO, BaseElement::ONE];
        let mut out0 = BaseElement::ZERO;
        let mut out1 = BaseElement::ZERO;
        let mut out2 = BaseElement::ZERO;
        let mut out3 = BaseElement::ZERO;

        for cycle in 0..TOTAL_TRACE_CYCLES {
            let cycle_start = cycle * CYCLE_LENGTH;
            if cycle_start + CYCLE_LENGTH > trace_len {
                break;
            }

            let (state_start, dir) = if cycle == 0 {
                (prev_state, BaseElement::ZERO)
            } else {
                let spec = cycle_specs.get(cycle - 1).cloned().unwrap_or(CycleSpec {
                    reset: false,
                    domain: 0,
                    in0: BaseElement::ZERO,
                    in1: BaseElement::ZERO,
                    dir: BaseElement::ZERO,
                });
                let state_start = if spec.reset {
                    [
                        BaseElement::new(spec.domain) + spec.in0,
                        spec.in1,
                        BaseElement::ONE,
                    ]
                } else {
                    [
                        prev_state[0] + spec.in0,
                        prev_state[1] + spec.in1,
                        prev_state[2],
                    ]
                };
                (state_start, spec.dir)
            };

            let mut state = state_start;
            for round in 0..POSEIDON_ROUNDS {
                let row = cycle_start + round;
                trace[COL_S0][row] = state[0];
                trace[COL_S1][row] = state[1];
                trace[COL_S2][row] = state[2];
                trace[COL_OUT0][row] = out0;
                trace[COL_OUT1][row] = out1;
                trace[COL_OUT2][row] = out2;
                trace[COL_OUT3][row] = out3;
                trace[COL_DIR][row] = dir;
                poseidon_round(&mut state, round);
            }

            for step in POSEIDON_ROUNDS..CYCLE_LENGTH {
                let row = cycle_start + step;
                trace[COL_S0][row] = state[0];
                trace[COL_S1][row] = state[1];
                trace[COL_S2][row] = state[2];
                trace[COL_OUT0][row] = out0;
                trace[COL_OUT1][row] = out1;
                trace[COL_OUT2][row] = out2;
                trace[COL_OUT3][row] = out3;
                trace[COL_DIR][row] = dir;
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
                        in0: BaseElement::ZERO,
                        in1: BaseElement::ZERO,
                        dir: BaseElement::ZERO,
                    });
                trace[COL_IN0][end_row] = next_spec.in0;
                trace[COL_IN1][end_row] = next_spec.in1;

                if let Some(domain) = cycle_reset_domain(next_cycle) {
                    trace[COL_RESET][end_row] = BaseElement::ONE;
                    trace[COL_DOMAIN][end_row] = BaseElement::new(domain);
                } else {
                    trace[COL_RESET][end_row] = BaseElement::ZERO;
                    trace[COL_DOMAIN][end_row] = BaseElement::ZERO;
                }

                trace[COL_MERKLE_LEFT_23][end_row] = if cycle_is_merkle_left_23(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                trace[COL_MERKLE_LEFT_01][end_row] = if cycle_is_merkle_left_01(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                trace[COL_MERKLE_RIGHT_23][end_row] = if cycle_is_merkle_right_23(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                trace[COL_MERKLE_RIGHT_01][end_row] = if cycle_is_merkle_right_01(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                let capture = if cycle_is_squeeze(next_cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                trace[COL_CAPTURE][end_row] = capture;
                let capture2 = if cycle_is_squeeze(cycle) {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                };
                trace[COL_CAPTURE2][end_row] = capture2;

                if capture == BaseElement::ONE {
                    out0 = state[0];
                    out1 = state[1];
                }
                if capture2 == BaseElement::ONE {
                    out2 = state[0];
                    out3 = state[1];
                }
            }
        }

        Ok(TraceTable::init(trace))
    }

    pub fn get_public_inputs(
        &self,
        witness: &TransactionWitness,
    ) -> Result<TransactionPublicInputsStark, TransactionCircuitError> {
        let input_flags: Vec<BaseElement> = (0..MAX_INPUTS)
            .map(|i| flag_to_felt(i < witness.inputs.len()))
            .collect();
        let output_flags: Vec<BaseElement> = (0..MAX_OUTPUTS)
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
            nullifiers.push([BaseElement::ZERO; 4]);
        }

        let mut commitments = Vec::new();
        for output in &witness.outputs {
            commitments.push(output.note.commitment());
        }
        while commitments.len() < MAX_OUTPUTS {
            commitments.push([BaseElement::ZERO; 4]);
        }

        let (vb_sign, vb_mag) = value_balance_parts(witness.value_balance)?;
        let merkle_root = transaction_core::hashing::bytes32_to_felts(&witness.merkle_root).ok_or(
            TransactionCircuitError::ConstraintViolation("invalid merkle root"),
        )?;
        let slots = witness.balance_slots()?;
        let slot_assets: Vec<u64> = slots.iter().map(|slot| slot.asset_id).collect();
        let stablecoin_inputs = stablecoin_binding_inputs(witness, &slot_assets)?;

        Ok(TransactionPublicInputsStark {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            fee: BaseElement::new(witness.fee),
            value_balance_sign: vb_sign,
            value_balance_magnitude: vb_mag,
            merkle_root,
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

    pub fn prove_transaction(
        &self,
        witness: &TransactionWitness,
    ) -> Result<Proof, TransactionCircuitError> {
        witness.validate()?;
        let trace = self.build_trace(witness)?;
        self.prove(trace)
            .map_err(|_| TransactionCircuitError::ConstraintViolation("STARK proving failed"))
    }
}

impl Prover for TransactionProverStark {
    type BaseField = BaseElement;
    type Air = TransactionAirStark;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = MerkleTree<Blake3>;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> TransactionPublicInputsStark {
        let trace_len = trace.length();
        let input_rows = [note_start_row_input(0), note_start_row_input(1)];
        let input_cols = [COL_IN_ACTIVE0, COL_IN_ACTIVE1];
        let mut input_flags = Vec::with_capacity(MAX_INPUTS);
        for (idx, &row) in input_rows.iter().enumerate() {
            let flag = if row < trace_len {
                trace.get(input_cols[idx], row)
            } else {
                BaseElement::ZERO
            };
            input_flags.push(flag);
        }

        let output_rows = [note_start_row_output(0), note_start_row_output(1)];
        let output_cols = [COL_OUT_ACTIVE0, COL_OUT_ACTIVE1];
        let mut output_flags = Vec::with_capacity(MAX_OUTPUTS);
        for (idx, &row) in output_rows.iter().enumerate() {
            let flag = if row < trace_len {
                trace.get(output_cols[idx], row)
            } else {
                BaseElement::ZERO
            };
            output_flags.push(flag);
        }

        let read_hash = |row: usize| -> [BaseElement; 4] {
            [
                trace.get(COL_OUT0, row),
                trace.get(COL_OUT1, row),
                trace.get(COL_S0, row),
                trace.get(COL_S1, row),
            ]
        };

        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for (i, flag) in input_flags.iter().enumerate() {
            let row = nullifier_output_row(i);
            let nf = if *flag == BaseElement::ONE && row < trace.length() {
                read_hash(row)
            } else {
                [BaseElement::ZERO; 4]
            };
            nullifiers.push(nf);
        }

        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for (i, flag) in output_flags.iter().enumerate() {
            let row = commitment_output_row(i);
            let cm = if *flag == BaseElement::ONE && row < trace.length() {
                read_hash(row)
            } else {
                [BaseElement::ZERO; 4]
            };
            commitments.push(cm);
        }

        let merkle_root = if trace_len > 0 {
            let row = merkle_root_output_row(0);
            if row < trace_len {
                read_hash(row)
            } else {
                [BaseElement::ZERO; 4]
            }
        } else {
            [BaseElement::ZERO; 4]
        };

        let final_row = trace_len.saturating_sub(2);
        TransactionPublicInputsStark {
            input_flags,
            output_flags,
            nullifiers,
            commitments,
            fee: trace.get(COL_FEE, final_row),
            value_balance_sign: trace.get(COL_VALUE_BALANCE_SIGN, final_row),
            value_balance_magnitude: trace.get(COL_VALUE_BALANCE_MAG, final_row),
            merkle_root,
            stablecoin_enabled: trace.get(COL_STABLECOIN_ENABLED, final_row),
            stablecoin_asset: trace.get(COL_STABLECOIN_ASSET, final_row),
            stablecoin_policy_version: trace.get(COL_STABLECOIN_POLICY_VERSION, final_row),
            stablecoin_issuance_sign: trace.get(COL_STABLECOIN_ISSUANCE_SIGN, final_row),
            stablecoin_issuance_magnitude: trace.get(COL_STABLECOIN_ISSUANCE_MAG, final_row),
            stablecoin_policy_hash: [
                trace.get(COL_STABLECOIN_POLICY_HASH0, final_row),
                trace.get(COL_STABLECOIN_POLICY_HASH1, final_row),
                trace.get(COL_STABLECOIN_POLICY_HASH2, final_row),
                trace.get(COL_STABLECOIN_POLICY_HASH3, final_row),
            ],
            stablecoin_oracle_commitment: [
                trace.get(COL_STABLECOIN_ORACLE0, final_row),
                trace.get(COL_STABLECOIN_ORACLE1, final_row),
                trace.get(COL_STABLECOIN_ORACLE2, final_row),
                trace.get(COL_STABLECOIN_ORACLE3, final_row),
            ],
            stablecoin_attestation_commitment: [
                trace.get(COL_STABLECOIN_ATTEST0, final_row),
                trace.get(COL_STABLECOIN_ATTEST1, final_row),
                trace.get(COL_STABLECOIN_ATTEST2, final_row),
                trace.get(COL_STABLECOIN_ATTEST3, final_row),
            ],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_trace_poly_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_trace_poly_columns,
            domain,
            partition_options,
        )
    }
}

// ================================================================================================
// PROOF OPTIONS
// ================================================================================================

pub fn proof_options_from_config(
    num_queries: usize,
    blowup_factor: usize,
    grinding_factor: u32,
) -> ProofOptions {
    ProofOptions::new(
        num_queries,
        blowup_factor,
        grinding_factor,
        winterfell::FieldExtension::Quadratic,
        2,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        winterfell::FieldExtension::Quadratic,
        2,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(feature = "stark-fast")]
pub fn fast_proof_options() -> ProofOptions {
    ProofOptions::new(
        8,
        16,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

// ================================================================================================
// HELPERS
// ================================================================================================

fn flag_to_felt(active: bool) -> BaseElement {
    if active {
        BaseElement::ONE
    } else {
        BaseElement::ZERO
    }
}

fn bool_trace_value(value: BaseElement, is_final: bool) -> BaseElement {
    if value == BaseElement::ONE {
        if is_final {
            BaseElement::ONE
        } else {
            BaseElement::ZERO
        }
    } else if is_final {
        BaseElement::ZERO
    } else {
        BaseElement::ONE
    }
}

fn bytes_to_felts(bytes: &[u8]) -> Vec<BaseElement> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            BaseElement::new(u64::from_be_bytes(buf))
        })
        .collect()
}

fn commitment_inputs(note: &NoteData) -> Vec<BaseElement> {
    let mut inputs = Vec::new();
    inputs.push(BaseElement::new(note.value));
    inputs.push(BaseElement::new(note.asset_id));
    inputs.extend(bytes_to_felts(&note.pk_recipient));
    inputs.extend(bytes_to_felts(&note.rho));
    inputs.extend(bytes_to_felts(&note.r));
    inputs
}

fn nullifier_inputs(prf: BaseElement, input: &InputNoteWitness) -> Vec<BaseElement> {
    let mut inputs = Vec::new();
    inputs.push(prf);
    inputs.push(BaseElement::new(input.position));
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
) -> [[BaseElement; 4]; 4] {
    let mut selectors = [[BaseElement::ZERO; 4]; 4];

    for (idx, note) in inputs.iter().enumerate() {
        if input_flags[idx] {
            if let Some(slot_idx) = slot_assets.iter().position(|id| *id == note.note.asset_id) {
                selectors[idx][slot_idx] = BaseElement::ONE;
            }
        }
    }

    for (idx, note) in outputs.iter().enumerate() {
        if output_flags[idx] {
            if let Some(slot_idx) = slot_assets.iter().position(|id| *id == note.note.asset_id) {
                selectors[2 + idx][slot_idx] = BaseElement::ONE;
            }
        }
    }

    selectors
}

fn value_balance_parts(
    value_balance: i128,
) -> Result<(BaseElement, BaseElement), TransactionCircuitError> {
    let magnitude = value_balance.unsigned_abs();
    let mag_u64 = u64::try_from(magnitude)
        .map_err(|_| TransactionCircuitError::ValueBalanceOutOfRange(magnitude))?;
    let sign = if value_balance < 0 {
        BaseElement::ONE
    } else {
        BaseElement::ZERO
    };
    Ok((sign, BaseElement::new(mag_u64)))
}

struct StablecoinBindingInputs {
    enabled: BaseElement,
    asset: BaseElement,
    policy_version: BaseElement,
    issuance_sign: BaseElement,
    issuance_mag: BaseElement,
    policy_hash: [BaseElement; 4],
    oracle_commitment: [BaseElement; 4],
    attestation_commitment: [BaseElement; 4],
    slot_selectors: [BaseElement; 4],
}

fn stablecoin_binding_inputs(
    witness: &TransactionWitness,
    slot_assets: &[u64],
) -> Result<StablecoinBindingInputs, TransactionCircuitError> {
    if !witness.stablecoin.enabled {
        return Ok(StablecoinBindingInputs {
            enabled: BaseElement::ZERO,
            asset: BaseElement::ZERO,
            policy_version: BaseElement::ZERO,
            issuance_sign: BaseElement::ZERO,
            issuance_mag: BaseElement::ZERO,
            policy_hash: [BaseElement::ZERO; 4],
            oracle_commitment: [BaseElement::ZERO; 4],
            attestation_commitment: [BaseElement::ZERO; 4],
            slot_selectors: [BaseElement::ZERO; 4],
        });
    }

    let policy_hash = bytes32_to_felts(&witness.stablecoin.policy_hash).ok_or(
        TransactionCircuitError::ConstraintViolation("invalid stablecoin policy hash encoding"),
    )?;
    let oracle_commitment = bytes32_to_felts(&witness.stablecoin.oracle_commitment).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "invalid stablecoin oracle commitment encoding",
        ),
    )?;
    let attestation_commitment = bytes32_to_felts(&witness.stablecoin.attestation_commitment)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "invalid stablecoin attestation commitment encoding",
        ))?;

    let (issuance_sign, issuance_mag) = value_balance_parts(witness.stablecoin.issuance_delta)?;
    let mut slot_selectors = [BaseElement::ZERO; 4];
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
    slot_selectors[slot_index] = BaseElement::ONE;

    Ok(StablecoinBindingInputs {
        enabled: BaseElement::ONE,
        asset: BaseElement::new(witness.stablecoin.asset_id),
        policy_version: BaseElement::new(u64::from(witness.stablecoin.policy_version)),
        issuance_sign,
        issuance_mag,
        policy_hash,
        oracle_commitment,
        attestation_commitment,
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

    for (idx, input) in inputs.iter().enumerate() {
        let commitment_inputs = commitment_inputs(&input.note);
        for chunk_idx in 0..COMMITMENT_ABSORB_CYCLES {
            let reset = chunk_idx == 0;
            let domain = if reset { NOTE_DOMAIN_TAG } else { 0 };
            let in0 = commitment_inputs[chunk_idx * 2];
            let in1 = commitment_inputs[chunk_idx * 2 + 1];
            cycles.push(CycleSpec {
                reset,
                domain,
                in0,
                in1,
                dir: BaseElement::ZERO,
            });
        }
        cycles.push(CycleSpec {
            reset: false,
            domain: 0,
            in0: BaseElement::ZERO,
            in1: BaseElement::ZERO,
            dir: BaseElement::ZERO,
        });

        let mut current = input.note.commitment();
        let mut pos = input.position;
        for level in 0..CIRCUIT_MERKLE_DEPTH {
            let dir = if pos & 1 == 0 {
                BaseElement::ZERO
            } else {
                BaseElement::ONE
            };
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
                    in0,
                    in1,
                    dir,
                });
            }
            cycles.push(CycleSpec {
                reset: false,
                domain: 0,
                in0: BaseElement::ZERO,
                in1: BaseElement::ZERO,
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
                in0,
                in1,
                dir: BaseElement::ZERO,
            });
        }
        cycles.push(CycleSpec {
            reset: false,
            domain: 0,
            in0: BaseElement::ZERO,
            in1: BaseElement::ZERO,
            dir: BaseElement::ZERO,
        });

        let _ = idx;
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
                in0,
                in1,
                dir: BaseElement::ZERO,
            });
        }
        cycles.push(CycleSpec {
            reset: false,
            domain: 0,
            in0: BaseElement::ZERO,
            in1: BaseElement::ZERO,
            dir: BaseElement::ZERO,
        });
    }

    cycles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::{felts_to_bytes32, merkle_node, HashFelt};
    use crate::note::{MerklePath, NoteData};
    use crate::StablecoinPolicyBinding;

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

    #[test]
    fn build_trace_roundtrip() {
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

        let witness = TransactionWitness {
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
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        };

        let prover = TransactionProverStark::with_default_options();
        let trace = prover.build_trace(&witness).expect("trace build");
        let pub_inputs = prover.get_pub_inputs(&trace);
        assert_eq!(pub_inputs.nullifiers.len(), MAX_INPUTS);
        assert_eq!(pub_inputs.commitments.len(), MAX_OUTPUTS);
    }
}
