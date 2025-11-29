//! Real STARK prover for transaction circuits.
//!
//! Builds traces that satisfy the Poseidon AIR with periodic round constants.

use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator,
    DefaultTraceLde, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, Trace,
};
use winter_crypto::hashers::Blake3_256;

use crate::{
    constants::{MAX_INPUTS, MAX_OUTPUTS, POSEIDON_ROUNDS, POSEIDON_WIDTH, NULLIFIER_DOMAIN_TAG, NOTE_DOMAIN_TAG},
    hashing::prf_key,
    stark_air::{
        TransactionAirStark, TransactionPublicInputsStark,
        TRACE_WIDTH, MIN_TRACE_LENGTH, CYCLE_LENGTH,
        NULLIFIER_CYCLES, COMMITMENT_CYCLES,
        COL_S0, COL_S1, COL_S2,
        round_constant, sbox, mds_mix,
    },
    witness::TransactionWitness,
    TransactionCircuitError,
};

type Blake3 = Blake3_256<BaseElement>;

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

    /// Build execution trace.
    ///
    /// The trace uses 16-step cycles with 8 hash rounds followed by 8 copy steps.
    /// - Steps 0-7: Apply Poseidon rounds (state changes each step)
    /// - Steps 8-15: Copy state (state remains unchanged, hash output preserved)
    ///
    /// For a sponge that requires multiple absorptions, we use multiple cycles.
    /// The final hash output appears at the end of the last cycle for that hash.
    ///
    /// Trace layout (cycles):
    /// - Nullifier 0: cycles 0-2 (NULLIFIER_CYCLES=3), output at row 47
    /// - Nullifier 1: cycles 3-5, output at row 95
    /// - Commitment 0: cycles 6-12 (COMMITMENT_CYCLES=7), output at row 207
    /// - Commitment 1: cycles 13-19, output at row 319
    pub fn build_trace(
        &self,
        witness: &TransactionWitness,
    ) -> Result<TraceTable<BaseElement>, TransactionCircuitError> {
        let trace_len = MIN_TRACE_LENGTH;
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];

        let prf = prf_key(&witness.sk_spend);
        
        // Helper to compute a hash with sponge construction and record in trace
        let compute_hash_in_trace = |
            trace: &mut Vec<Vec<BaseElement>>,
            start_cycle: usize,
            domain_tag: u64,
            inputs: &[BaseElement],
        | -> BaseElement {
            let rate = POSEIDON_WIDTH - 1;
            let mut state = [
                BaseElement::new(domain_tag),
                BaseElement::ZERO,
                BaseElement::ONE,
            ];
            
            let mut cursor = 0;
            let mut cycle = start_cycle;
            
            while cursor < inputs.len() {
                let cycle_start = cycle * CYCLE_LENGTH;
                if cycle_start + CYCLE_LENGTH > trace_len {
                    break;
                }

                // Absorb up to 'rate' elements
                let take = core::cmp::min(rate, inputs.len() - cursor);
                for i in 0..take {
                    state[i] += inputs[cursor + i];
                }
                cursor += take;

                // Record 8 hash rounds (steps 0-7)
                for round in 0..POSEIDON_ROUNDS {
                    let row = cycle_start + round;
                    trace[COL_S0][row] = state[0];
                    trace[COL_S1][row] = state[1];
                    trace[COL_S2][row] = state[2];

                    // Apply round
                    let t0 = state[0] + round_constant(round, 0);
                    let t1 = state[1] + round_constant(round, 1);
                    let t2 = state[2] + round_constant(round, 2);
                    state = mds_mix(&[sbox(t0), sbox(t1), sbox(t2)]);
                }

                // Record copy steps (steps 8-15)
                for step in POSEIDON_ROUNDS..CYCLE_LENGTH {
                    let row = cycle_start + step;
                    trace[COL_S0][row] = state[0];
                    trace[COL_S1][row] = state[1];
                    trace[COL_S2][row] = state[2];
                }

                cycle += 1;
            }
            
            state[0]
        };
        
        // Helper to fill cycles with dummy hash for padding
        let fill_dummy_cycles = |
            trace: &mut Vec<Vec<BaseElement>>,
            start_cycle: usize,
            num_cycles: usize,
        | {
            let mut state = [BaseElement::ZERO, BaseElement::ZERO, BaseElement::ONE];
            
            for c in 0..num_cycles {
                let cycle_start = (start_cycle + c) * CYCLE_LENGTH;
                if cycle_start + CYCLE_LENGTH > trace_len {
                    break;
                }
                
                // Record 8 hash rounds
                for round in 0..POSEIDON_ROUNDS {
                    let row = cycle_start + round;
                    trace[COL_S0][row] = state[0];
                    trace[COL_S1][row] = state[1];
                    trace[COL_S2][row] = state[2];

                    let t0 = state[0] + round_constant(round, 0);
                    let t1 = state[1] + round_constant(round, 1);
                    let t2 = state[2] + round_constant(round, 2);
                    state = mds_mix(&[sbox(t0), sbox(t1), sbox(t2)]);
                }

                // Record copy steps
                for step in POSEIDON_ROUNDS..CYCLE_LENGTH {
                    let row = cycle_start + step;
                    trace[COL_S0][row] = state[0];
                    trace[COL_S1][row] = state[1];
                    trace[COL_S2][row] = state[2];
                }
            }
        };

        // Process nullifiers - each gets NULLIFIER_CYCLES (3) cycles
        for idx in 0..MAX_INPUTS {
            let start_cycle = idx * NULLIFIER_CYCLES;
            
            if idx < witness.inputs.len() {
                let input = &witness.inputs[idx];
                
                // Build hash inputs (same as hashing.rs nullifier function)
                let mut hash_inputs = Vec::new();
                hash_inputs.push(prf);
                hash_inputs.push(BaseElement::new(input.position));
                for chunk in input.note.rho.chunks(8) {
                    let mut buf = [0u8; 8];
                    let len = chunk.len().min(8);
                    buf[8 - len..].copy_from_slice(&chunk[..len]);
                    hash_inputs.push(BaseElement::new(u64::from_be_bytes(buf)));
                }

                compute_hash_in_trace(&mut trace, start_cycle, NULLIFIER_DOMAIN_TAG, &hash_inputs);
            } else {
                // Pad with dummy hash cycles
                fill_dummy_cycles(&mut trace, start_cycle, NULLIFIER_CYCLES);
            }
        }

        // Process commitments - each gets COMMITMENT_CYCLES (7) cycles
        let commitment_base_cycle = MAX_INPUTS * NULLIFIER_CYCLES;
        
        for idx in 0..MAX_OUTPUTS {
            let start_cycle = commitment_base_cycle + idx * COMMITMENT_CYCLES;
            
            if idx < witness.outputs.len() {
                let output = &witness.outputs[idx];
                
                // Build hash inputs (same as hashing.rs note_commitment function)
                let mut hash_inputs = Vec::new();
                hash_inputs.push(BaseElement::new(output.note.value));
                hash_inputs.push(BaseElement::new(output.note.asset_id));
                for bytes in [&output.note.pk_recipient[..], &output.note.rho[..], &output.note.r[..]] {
                    for chunk in bytes.chunks(8) {
                        let mut buf = [0u8; 8];
                        let len = chunk.len().min(8);
                        buf[8 - len..].copy_from_slice(&chunk[..len]);
                        hash_inputs.push(BaseElement::new(u64::from_be_bytes(buf)));
                    }
                }

                compute_hash_in_trace(&mut trace, start_cycle, NOTE_DOMAIN_TAG, &hash_inputs);
            } else {
                // Pad with dummy hash cycles
                fill_dummy_cycles(&mut trace, start_cycle, COMMITMENT_CYCLES);
            }
        }

        // Fill remaining rows with proper dummy hash cycles
        let total_used_cycles = MAX_INPUTS * NULLIFIER_CYCLES + MAX_OUTPUTS * COMMITMENT_CYCLES;
        let total_cycles = trace_len / CYCLE_LENGTH;
        
        if total_used_cycles < total_cycles {
            fill_dummy_cycles(&mut trace, total_used_cycles, total_cycles - total_used_cycles);
        }

        Ok(TraceTable::init(trace))
    }

    pub fn get_public_inputs(&self, witness: &TransactionWitness) -> TransactionPublicInputsStark {
        let prf = prf_key(&witness.sk_spend);

        let mut nullifiers = Vec::new();
        for input in &witness.inputs {
            nullifiers.push(crate::hashing::nullifier(prf, &input.note.rho, input.position));
        }
        while nullifiers.len() < MAX_INPUTS {
            nullifiers.push(BaseElement::ZERO);
        }

        let mut commitments = Vec::new();
        for output in &witness.outputs {
            commitments.push(output.note.commitment());
        }
        while commitments.len() < MAX_OUTPUTS {
            commitments.push(BaseElement::ZERO);
        }

        let total_input: u64 = witness.inputs.iter().map(|i| i.note.value).sum();
        let total_output: u64 = witness.outputs.iter().map(|o| o.note.value).sum();

        TransactionPublicInputsStark {
            nullifiers,
            commitments,
            total_input: BaseElement::new(total_input),
            total_output: BaseElement::new(total_output),
            fee: BaseElement::new(witness.fee),
            merkle_root: witness.merkle_root,
        }
    }

    pub fn prove_transaction(&self, witness: &TransactionWitness) -> Result<Proof, TransactionCircuitError> {
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
        // Read all nullifiers and commitments from their deterministic trace positions
        // Nullifier i ends at row: (i + 1) * NULLIFIER_CYCLES * CYCLE_LENGTH - 1
        // Commitment i ends at row: (MAX_INPUTS * NULLIFIER_CYCLES + (i + 1) * COMMITMENT_CYCLES) * CYCLE_LENGTH - 1
        
        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        for i in 0..MAX_INPUTS {
            let row = (i + 1) * NULLIFIER_CYCLES * CYCLE_LENGTH - 1;
            let nf = if row < trace.length() {
                trace.get(COL_S0, row)
            } else {
                BaseElement::ZERO
            };
            nullifiers.push(nf);
        }
        
        let commitment_base_cycles = MAX_INPUTS * NULLIFIER_CYCLES;
        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        for i in 0..MAX_OUTPUTS {
            let row = (commitment_base_cycles + (i + 1) * COMMITMENT_CYCLES) * CYCLE_LENGTH - 1;
            let cm = if row < trace.length() {
                trace.get(COL_S0, row)
            } else {
                BaseElement::ZERO
            };
            commitments.push(cm);
        }

        TransactionPublicInputsStark {
            nullifiers,
            commitments,
            total_input: BaseElement::ZERO,
            total_output: BaseElement::ZERO,
            fee: BaseElement::ZERO,
            merkle_root: BaseElement::ZERO,
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

pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32, 8, 0,
        winterfell::FieldExtension::None,
        4, 31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn fast_proof_options() -> ProofOptions {
    // Blowup factor must be at least 2 * constraint_degree = 2 * 5 = 10
    // Use 16 to be safe (power of 2)
    ProofOptions::new(
        8, 16, 0,
        winterfell::FieldExtension::None,
        2, 15,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
        use crate::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};    fn make_test_witness() -> TransactionWitness {
        let input_note = NoteData {
            value: 1000,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            rho: [1u8; 32],
            r: [2u8; 32],
        };

        let output_note = NoteData {
            value: 900,
            asset_id: 0,
            pk_recipient: [3u8; 32],
            rho: [4u8; 32],
            r: [5u8; 32],
        };

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [7u8; 32],
                merkle_path: MerklePath::default(),
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            sk_spend: [6u8; 32],
            merkle_root: BaseElement::new(12345),
            fee: 100,
            version: protocol_versioning::DEFAULT_VERSION_BINDING,
        }
    }

    #[test]
    fn test_build_trace() {
        let prover = TransactionProverStark::with_default_options();
        let witness = make_test_witness();

        let trace = prover.build_trace(&witness).unwrap();

        assert_eq!(trace.width(), TRACE_WIDTH);
        assert!(trace.length() >= MIN_TRACE_LENGTH);
    }

    #[test]
    fn test_trace_hash_matches_hashing_module() {
        let prover = TransactionProverStark::with_default_options();
        let witness = make_test_witness();
        let trace = prover.build_trace(&witness).unwrap();
        
        // Compute expected hashes using hashing module
        let prf = prf_key(&witness.sk_spend);
        let expected_nf = crate::hashing::nullifier(prf, &witness.inputs[0].note.rho, 0);
        let expected_cm = witness.outputs[0].note.commitment();
        
        // With multi-I/O layout:
        // - Nullifier 0 at cycles 0-2, output at row (0+1)*NULLIFIER_CYCLES*CYCLE_LENGTH - 1 = 47
        // - Nullifier 1 at cycles 3-5, output at row 95
        // - Commitment 0 at cycles 6-12, output at row (MAX_INPUTS*NULLIFIER_CYCLES + 1*COMMITMENT_CYCLES)*CYCLE_LENGTH - 1 = 207
        // - Commitment 1 at cycles 13-19, output at row 319
        let nf_row = NULLIFIER_CYCLES * CYCLE_LENGTH - 1;  // 47
        let trace_nf = trace.get(COL_S0, nf_row);
        
        // Commitment 0: base cycles = MAX_INPUTS * NULLIFIER_CYCLES = 6
        // Position = (6 + 7) * 16 - 1 = 207
        let commitment_base_cycles = MAX_INPUTS * NULLIFIER_CYCLES;
        let cm_row = (commitment_base_cycles + COMMITMENT_CYCLES) * CYCLE_LENGTH - 1;  // 207
        let trace_cm = trace.get(COL_S0, cm_row);
        
        println!("Expected nullifier: {:?}", expected_nf);
        println!("Trace nullifier at row {}: {:?}", nf_row, trace_nf);
        println!("Expected commitment: {:?}", expected_cm);
        println!("Trace commitment at row {}: {:?}", cm_row, trace_cm);
        
        assert_eq!(trace_nf, expected_nf, "Trace nullifier mismatch");
        assert_eq!(trace_cm, expected_cm, "Trace commitment mismatch");
        
        // Also verify that get_public_inputs and get_pub_inputs (Prover trait) return same values
        let pub_from_witness = prover.get_public_inputs(&witness);
        let pub_from_trace = <TransactionProverStark as Prover>::get_pub_inputs(&prover, &trace);
        
        println!("pub_from_witness.nullifiers[0]: {:?}", pub_from_witness.nullifiers[0]);
        println!("pub_from_trace.nullifiers[0]: {:?}", pub_from_trace.nullifiers[0]);
        println!("pub_from_witness.commitments[0]: {:?}", pub_from_witness.commitments[0]);
        println!("pub_from_trace.commitments[0]: {:?}", pub_from_trace.commitments[0]);
        
        assert_eq!(pub_from_witness.nullifiers[0], pub_from_trace.nullifiers[0], "Nullifier mismatch between functions");
        assert_eq!(pub_from_witness.commitments[0], pub_from_trace.commitments[0], "Commitment mismatch between functions");
    }

    #[test]
    fn test_public_inputs_match_witness() {
        let prover = TransactionProverStark::with_default_options();
        let witness = make_test_witness();

        let pub_inputs = prover.get_public_inputs(&witness);
        
        let prf = prf_key(&witness.sk_spend);
        let expected_nf = crate::hashing::nullifier(prf, &witness.inputs[0].note.rho, 0);
        assert_eq!(pub_inputs.nullifiers[0], expected_nf);

        let expected_cm = witness.outputs[0].note.commitment();
        assert_eq!(pub_inputs.commitments[0], expected_cm);
    }

    #[test]
    fn test_prove_and_verify() {
        let prover = TransactionProverStark::new(fast_proof_options());
        let witness = make_test_witness();

        let trace = prover.build_trace(&witness).unwrap();
        // Must use get_pub_inputs from Prover trait - this is what the prover uses internally
        let pub_inputs = <TransactionProverStark as Prover>::get_pub_inputs(&prover, &trace);

        let proof = prover.prove(trace).expect("proving should succeed");
        let proof_bytes = proof.to_bytes();
        assert!(proof_bytes.len() > 1000);

        let result = crate::stark_verifier::verify_transaction_proof(&proof, &pub_inputs);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }

    #[test]
    fn test_multi_input_output_trace() {
        // Test with 2 inputs and 2 outputs
        let input_note1 = NoteData {
            value: 1000,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            rho: [1u8; 32],
            r: [2u8; 32],
        };
        let input_note2 = NoteData {
            value: 500,
            asset_id: 0,
            pk_recipient: [10u8; 32],
            rho: [11u8; 32],
            r: [12u8; 32],
        };
        let output_note1 = NoteData {
            value: 800,
            asset_id: 0,
            pk_recipient: [3u8; 32],
            rho: [4u8; 32],
            r: [5u8; 32],
        };
        let output_note2 = NoteData {
            value: 600,
            asset_id: 0,
            pk_recipient: [13u8; 32],
            rho: [14u8; 32],
            r: [15u8; 32],
        };

        let witness = TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note1,
                    position: 0,
                    rho_seed: [7u8; 32],
                    merkle_path: MerklePath::default(),
                },
                InputNoteWitness {
                    note: input_note2,
                    position: 1,
                    rho_seed: [17u8; 32],
                    merkle_path: MerklePath::default(),
                },
            ],
            outputs: vec![
                OutputNoteWitness { note: output_note1 },
                OutputNoteWitness { note: output_note2 },
            ],
            sk_spend: [6u8; 32],
            merkle_root: BaseElement::new(12345),
            fee: 100,
            version: protocol_versioning::DEFAULT_VERSION_BINDING,
        };

        let prover = TransactionProverStark::new(fast_proof_options());
        let trace = prover.build_trace(&witness).unwrap();

        // Verify all hashes are at expected positions
        let prf = prf_key(&witness.sk_spend);

        // Nullifier 0 at row (0+1)*3*16 - 1 = 47
        let nf0_row = NULLIFIER_CYCLES * CYCLE_LENGTH - 1;
        let expected_nf0 = crate::hashing::nullifier(prf, &witness.inputs[0].note.rho, 0);
        assert_eq!(trace.get(COL_S0, nf0_row), expected_nf0, "Nullifier 0 mismatch");

        // Nullifier 1 at row (1+1)*3*16 - 1 = 95
        let nf1_row = 2 * NULLIFIER_CYCLES * CYCLE_LENGTH - 1;
        let expected_nf1 = crate::hashing::nullifier(prf, &witness.inputs[1].note.rho, 1);
        assert_eq!(trace.get(COL_S0, nf1_row), expected_nf1, "Nullifier 1 mismatch");

        // Commitment 0 at row (2*3 + 1*7)*16 - 1 = 207
        let commitment_base = MAX_INPUTS * NULLIFIER_CYCLES;
        let cm0_row = (commitment_base + COMMITMENT_CYCLES) * CYCLE_LENGTH - 1;
        let expected_cm0 = witness.outputs[0].note.commitment();
        assert_eq!(trace.get(COL_S0, cm0_row), expected_cm0, "Commitment 0 mismatch");

        // Commitment 1 at row (2*3 + 2*7)*16 - 1 = 319
        let cm1_row = (commitment_base + 2 * COMMITMENT_CYCLES) * CYCLE_LENGTH - 1;
        let expected_cm1 = witness.outputs[1].note.commitment();
        assert_eq!(trace.get(COL_S0, cm1_row), expected_cm1, "Commitment 1 mismatch");

        // Verify get_pub_inputs reads all values correctly
        let pub_inputs = <TransactionProverStark as Prover>::get_pub_inputs(&prover, &trace);
        assert_eq!(pub_inputs.nullifiers[0], expected_nf0, "pub_inputs nullifier 0 mismatch");
        assert_eq!(pub_inputs.nullifiers[1], expected_nf1, "pub_inputs nullifier 1 mismatch");
        assert_eq!(pub_inputs.commitments[0], expected_cm0, "pub_inputs commitment 0 mismatch");
        assert_eq!(pub_inputs.commitments[1], expected_cm1, "pub_inputs commitment 1 mismatch");

        // Prove and verify
        let proof = prover.prove(trace).expect("proving should succeed");
        let result = crate::stark_verifier::verify_transaction_proof(&proof, &pub_inputs);
        assert!(result.is_ok(), "Multi-I/O verification failed: {:?}", result);
    }
}
