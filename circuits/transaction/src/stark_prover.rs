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
    constants::{MAX_INPUTS, MAX_OUTPUTS, POSEIDON_ROUNDS, POSEIDON_WIDTH, NULLIFIER_DOMAIN_TAG, NOTE_DOMAIN_TAG, MERKLE_DOMAIN_TAG, CIRCUIT_MERKLE_DEPTH},
    hashing::prf_key,
    stark_air::{
        TransactionAirStark, TransactionPublicInputsStark,
        TRACE_WIDTH, MIN_TRACE_LENGTH, CYCLE_LENGTH,
        NULLIFIER_CYCLES, COMMITMENT_CYCLES, CYCLES_PER_INPUT, MERKLE_CYCLES,
        COL_S0, COL_S1, COL_S2, COL_MERKLE_SIBLING, COL_VALUE,
        round_constant, sbox, mds_mix,
        nullifier_output_row, commitment_output_row, merkle_root_output_row,
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
    /// ## Trace Layout (cycles per input):
    /// 
    /// For each input (MAX_INPUTS = 2):
    /// - Nullifier hash: NULLIFIER_CYCLES (3) cycles
    /// - Merkle path verification: MERKLE_CYCLES (8) cycles
    ///
    /// For each output (MAX_OUTPUTS = 2):
    /// - Commitment hash: COMMITMENT_CYCLES (7) cycles
    ///
    /// Total cycles = 2 * (3 + 8) + 2 * 7 = 36 cycles = 576 rows → 1024 (power of 2)
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
        
        // Helper to compute merkle_node hash (2 inputs → 1 output) in one cycle
        let compute_merkle_node_in_trace = |
            trace: &mut Vec<Vec<BaseElement>>,
            cycle: usize,
            left: BaseElement,
            right: BaseElement,
            sibling: BaseElement,
        | -> BaseElement {
            let cycle_start = cycle * CYCLE_LENGTH;
            if cycle_start + CYCLE_LENGTH > trace_len {
                return BaseElement::ZERO;
            }
            
            // merkle_node uses sponge with domain tag and 2 inputs
            let mut state = [
                BaseElement::new(MERKLE_DOMAIN_TAG),
                BaseElement::ZERO,
                BaseElement::ONE,
            ];
            
            // Absorb left and right
            state[0] += left;
            state[1] += right;
            
            // Record 8 hash rounds
            for round in 0..POSEIDON_ROUNDS {
                let row = cycle_start + round;
                trace[COL_S0][row] = state[0];
                trace[COL_S1][row] = state[1];
                trace[COL_S2][row] = state[2];
                trace[COL_MERKLE_SIBLING][row] = sibling;

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
                trace[COL_MERKLE_SIBLING][row] = sibling;
            }
            
            state[0]
        };
        
        // Helper to fill cycles with dummy hash for padding
        // This runs valid Poseidon rounds so the AIR constraints are satisfied
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

        // Process each input: nullifier hash + Merkle path verification
        for idx in 0..MAX_INPUTS {
            let input_base_cycle = idx * CYCLES_PER_INPUT;
            
            if idx < witness.inputs.len() {
                let input = &witness.inputs[idx];
                
                // Phase 1: Compute nullifier hash (3 cycles)
                let mut hash_inputs = Vec::new();
                hash_inputs.push(prf);
                hash_inputs.push(BaseElement::new(input.position));
                for chunk in input.note.rho.chunks(8) {
                    let mut buf = [0u8; 8];
                    let len = chunk.len().min(8);
                    buf[8 - len..].copy_from_slice(&chunk[..len]);
                    hash_inputs.push(BaseElement::new(u64::from_be_bytes(buf)));
                }
                compute_hash_in_trace(&mut trace, input_base_cycle, NULLIFIER_DOMAIN_TAG, &hash_inputs);
                
                // Phase 2: Merkle path verification (MERKLE_CYCLES cycles)
                // Compute note commitment as the leaf
                let leaf = input.note.commitment();
                let merkle_start_cycle = input_base_cycle + NULLIFIER_CYCLES;
                
                // Verify Merkle path from leaf to root
                let mut current = leaf;
                let mut pos = input.position;
                
                for level in 0..MERKLE_CYCLES {
                    let cycle = merkle_start_cycle + level;
                    
                    // Get sibling from merkle_path (or use zero if path is shorter)
                    let sibling = if level < input.merkle_path.siblings.len() {
                        input.merkle_path.siblings[level]
                    } else {
                        BaseElement::ZERO
                    };
                    
                    // Compute merkle_node based on position bit
                    let (left, right) = if pos & 1 == 0 {
                        (current, sibling)
                    } else {
                        (sibling, current)
                    };
                    
                    current = compute_merkle_node_in_trace(&mut trace, cycle, left, right, sibling);
                    pos >>= 1;
                }
                
                // Store marker in COL_VALUE at the nullifier output row
                // We use value + 1 so zero-value notes still have a non-zero marker
                let nf_row = (input_base_cycle + NULLIFIER_CYCLES) * CYCLE_LENGTH - 1;
                if nf_row < trace_len {
                    trace[COL_VALUE][nf_row] = BaseElement::new(input.note.value.wrapping_add(1));
                }
            } else {
                // Pad with dummy hash cycles (COL_VALUE stays zero for padding)
                fill_dummy_cycles(&mut trace, input_base_cycle, CYCLES_PER_INPUT);
            }
        }

        // Process commitments - each gets COMMITMENT_CYCLES (7) cycles
        let commitment_base_cycle = MAX_INPUTS * CYCLES_PER_INPUT;
        
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
                
                // Store marker in COL_VALUE at the commitment output row
                // We use value + 1 so zero-value notes still have a non-zero marker
                let cm_row = (start_cycle + COMMITMENT_CYCLES) * CYCLE_LENGTH - 1;
                if cm_row < trace_len {
                    trace[COL_VALUE][cm_row] = BaseElement::new(output.note.value.wrapping_add(1));
                }
            } else {
                // Pad with dummy hash cycles (COL_VALUE stays zero for padding)
                fill_dummy_cycles(&mut trace, start_cycle, COMMITMENT_CYCLES);
            }
        }

        // Fill remaining rows with proper dummy hash cycles
        let total_used_cycles = MAX_INPUTS * CYCLES_PER_INPUT + MAX_OUTPUTS * COMMITMENT_CYCLES;
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
        // Nullifier i ends at row: (i * CYCLES_PER_INPUT + NULLIFIER_CYCLES) * CYCLE_LENGTH - 1
        // Commitment i ends at row: (MAX_INPUTS * CYCLES_PER_INPUT + (i + 1) * COMMITMENT_CYCLES) * CYCLE_LENGTH - 1
        //
        // We use COL_VALUE to distinguish real inputs from padding:
        // - Real inputs have COL_VALUE set to note.value (can be 0 for zero-value notes)
        // - We mark real inputs with a 1 in position COL_VALUE at nullifier row
        // For now, use a simpler heuristic: real inputs have non-default hash outputs
        
        let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
        let mut total_input = BaseElement::ZERO;
        for i in 0..MAX_INPUTS {
            let row = nullifier_output_row(i);
            let (nf, value) = if row < trace.length() {
                let val = trace.get(COL_S0, row);
                // Check if this is a real input by looking at COL_VALUE
                // Real inputs have note values stored as (value + 1); padding has zero
                let marker = trace.get(COL_VALUE, row);
                if marker == BaseElement::ZERO {
                    // This is a padding slot, treat nullifier as zero
                    (BaseElement::ZERO, BaseElement::ZERO)
                } else {
                    // Recover original value by subtracting 1
                    let original_value = marker - BaseElement::ONE;
                    (val, original_value)
                }
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };
            nullifiers.push(nf);
            total_input = total_input + value;
        }
        
        let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
        let mut total_output = BaseElement::ZERO;
        for i in 0..MAX_OUTPUTS {
            let row = commitment_output_row(i);
            let (cm, value) = if row < trace.length() {
                let val = trace.get(COL_S0, row);
                // Check if this is a real output by looking at COL_VALUE
                let marker = trace.get(COL_VALUE, row);
                if marker == BaseElement::ZERO {
                    // This is a padding slot, treat commitment as zero
                    (BaseElement::ZERO, BaseElement::ZERO)
                } else {
                    // Recover original value by subtracting 1
                    let original_value = marker - BaseElement::ONE;
                    (val, original_value)
                }
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };
            commitments.push(cm);
            total_output = total_output + value;
        }
        
        // Read merkle root from the first input's Merkle output row
        let merkle_root = if trace.length() > 0 {
            let row = merkle_root_output_row(0);
            if row < trace.length() {
                trace.get(COL_S0, row)
            } else {
                BaseElement::ZERO
            }
        } else {
            BaseElement::ZERO
        };
        
        // Fee is total_input - total_output (balance equation)
        let fee = total_input - total_output;

        TransactionPublicInputsStark {
            nullifiers,
            commitments,
            total_input,
            total_output,
            fee,
            merkle_root,
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
    use crate::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness, MERKLE_TREE_DEPTH};
    use crate::hashing::merkle_node;
    
    /// Compute the Merkle root from a leaf and a path of siblings (all zeros for default path)
    fn compute_merkle_root_from_path(leaf: BaseElement, position: u64, path: &MerklePath) -> BaseElement {
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
    
    /// Build a Merkle tree with 2 leaves at positions 0 and 1, returning paths for both
    /// This is a minimal tree where leaves 0 and 1 are siblings at the bottom level.
    fn build_two_leaf_merkle_tree(leaf0: BaseElement, leaf1: BaseElement) -> (MerklePath, MerklePath, BaseElement) {
        // At level 0, leaves 0 and 1 are siblings
        // For leaf at position 0: sibling at level 0 is leaf1
        // For leaf at position 1: sibling at level 0 is leaf0
        
        let mut siblings0 = vec![leaf1];  // Path for position 0
        let mut siblings1 = vec![leaf0];  // Path for position 1
        
        // The parent of leaves 0,1 is merkle_node(leaf0, leaf1)
        let mut current = merkle_node(leaf0, leaf1);
        
        // For levels 1 through MERKLE_TREE_DEPTH-1, the sibling is zero (no other nodes in tree)
        for _ in 1..MERKLE_TREE_DEPTH {
            siblings0.push(BaseElement::ZERO);
            siblings1.push(BaseElement::ZERO);
            // Parent: merkle_node(current, 0) since we're always on left branch
            current = merkle_node(current, BaseElement::ZERO);
        }
        
        let path0 = MerklePath { siblings: siblings0 };
        let path1 = MerklePath { siblings: siblings1 };
        
        (path0, path1, current)
    }
    
    fn make_test_witness() -> TransactionWitness {
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

        let merkle_path = MerklePath::default();
        let leaf = input_note.commitment();
        let merkle_root = compute_merkle_root_from_path(leaf, 0, &merkle_path);

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: 0,
                rho_seed: [7u8; 32],
                merkle_path,
            }],
            outputs: vec![OutputNoteWitness { note: output_note }],
            sk_spend: [6u8; 32],
            merkle_root,
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
        
        // With merkle-path layout:
        // Input 0: nullifier cycles 0-2 (output at row 47), merkle cycles 3-10 (root at row 175)
        // Input 1: nullifier cycles 11-13 (output at row 223), merkle cycles 14-21 (root at row 351)
        // Commitment 0: cycles 22-28 (output at row 463)
        // Commitment 1: cycles 29-35 (output at row 575)
        let nf_row = nullifier_output_row(0);
        let trace_nf = trace.get(COL_S0, nf_row);
        
        let cm_row = commitment_output_row(0);
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

        // Build proper Merkle tree with both input notes
        let leaf0 = input_note1.commitment();
        let leaf1 = input_note2.commitment();
        let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

        let witness = TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note1,
                    position: 0,
                    rho_seed: [7u8; 32],
                    merkle_path: merkle_path0,
                },
                InputNoteWitness {
                    note: input_note2,
                    position: 1,
                    rho_seed: [17u8; 32],
                    merkle_path: merkle_path1,
                },
            ],
            outputs: vec![
                OutputNoteWitness { note: output_note1 },
                OutputNoteWitness { note: output_note2 },
            ],
            sk_spend: [6u8; 32],
            merkle_root,
            fee: 100,
            version: protocol_versioning::DEFAULT_VERSION_BINDING,
        };

        let prover = TransactionProverStark::new(fast_proof_options());
        let trace = prover.build_trace(&witness).unwrap();

        // Verify all hashes are at expected positions
        let prf = prf_key(&witness.sk_spend);

        // Nullifier 0 at nullifier_output_row(0)
        let nf0_row = nullifier_output_row(0);
        let expected_nf0 = crate::hashing::nullifier(prf, &witness.inputs[0].note.rho, 0);
        assert_eq!(trace.get(COL_S0, nf0_row), expected_nf0, "Nullifier 0 mismatch");

        // Nullifier 1 at nullifier_output_row(1)
        let nf1_row = nullifier_output_row(1);
        let expected_nf1 = crate::hashing::nullifier(prf, &witness.inputs[1].note.rho, 1);
        assert_eq!(trace.get(COL_S0, nf1_row), expected_nf1, "Nullifier 1 mismatch");

        // Commitment 0 at commitment_output_row(0)
        let cm0_row = commitment_output_row(0);
        let expected_cm0 = witness.outputs[0].note.commitment();
        assert_eq!(trace.get(COL_S0, cm0_row), expected_cm0, "Commitment 0 mismatch");

        // Commitment 1 at commitment_output_row(1)
        let cm1_row = commitment_output_row(1);
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
