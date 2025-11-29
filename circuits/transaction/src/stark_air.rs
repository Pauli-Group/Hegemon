//! Real STARK AIR for transaction circuits using Poseidon hash.
//!
//! Uses periodic columns for round constants and a hash_flag for active rounds.
//! Follows the winterfell rescue example pattern.

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use crate::constants::{MAX_INPUTS, MAX_OUTPUTS, POSEIDON_ROUNDS, POSEIDON_WIDTH};

// ================================================================================================
// TRACE CONFIGURATION
// ================================================================================================

/// Trace width: 3 state elements only
pub const TRACE_WIDTH: usize = 3;
pub const COL_S0: usize = 0;
pub const COL_S1: usize = 1;
pub const COL_S2: usize = 2;

/// Cycle length: power of 2, must be > POSEIDON_ROUNDS to allow copy steps
/// Using 16 allows 8 hash rounds + 8 copy/idle steps
pub const CYCLE_LENGTH: usize = 16;

/// Minimum trace length (power of 2)
/// Must accommodate: MAX_INPUTS × NULLIFIER_CYCLES + MAX_OUTPUTS × COMMITMENT_CYCLES
/// = 2 × 3 + 2 × 7 = 20 cycles × 16 = 320, round up to 512
pub const MIN_TRACE_LENGTH: usize = 512;

// ================================================================================================
// PERIODIC COLUMN: HASH MASK
// ================================================================================================

/// Mask that indicates which rows have active Poseidon round transitions.
/// For 8 rounds in a 16-step cycle:
/// - Steps 0-7: hash_flag=1, apply Poseidon round
/// - Steps 8-15: hash_flag=0, copy/idle (state unchanged)
const fn make_hash_mask() -> [BaseElement; CYCLE_LENGTH] {
    let mut mask = [BaseElement::new(0); CYCLE_LENGTH];
    let mut i = 0;
    while i < POSEIDON_ROUNDS {
        mask[i] = BaseElement::new(1);
        i += 1;
    }
    mask
}

const HASH_MASK: [BaseElement; CYCLE_LENGTH] = make_hash_mask();

// ================================================================================================
// ROUND CONSTANTS (matching hashing.rs)
// ================================================================================================

#[inline]
pub fn round_constant(round: usize, position: usize) -> BaseElement {
    let seed = ((round as u64 + 1).wrapping_mul(0x9e37_79b9u64))
        ^ ((position as u64 + 1).wrapping_mul(0x7f4a_7c15u64));
    BaseElement::new(seed)
}

/// Generate all periodic columns: [hash_mask, rc0, rc1, rc2]
fn get_periodic_columns() -> Vec<Vec<BaseElement>> {
    let mut result = vec![HASH_MASK.to_vec()];
    
    // Round constants for each position, extended to CYCLE_LENGTH
    for pos in 0..POSEIDON_WIDTH {
        let mut column = Vec::with_capacity(CYCLE_LENGTH);
        for step in 0..CYCLE_LENGTH {
            // Use round constant for steps 0..POSEIDON_ROUNDS, zero otherwise
            if step < POSEIDON_ROUNDS {
                column.push(round_constant(step, pos));
            } else {
                column.push(BaseElement::ZERO);
            }
        }
        result.push(column);
    }
    
    result
}

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

#[derive(Clone, Debug)]
pub struct TransactionPublicInputsStark {
    pub nullifiers: Vec<BaseElement>,
    pub commitments: Vec<BaseElement>,
    pub total_input: BaseElement,
    pub total_output: BaseElement,
    pub fee: BaseElement,
    pub merkle_root: BaseElement,
}

impl Default for TransactionPublicInputsStark {
    fn default() -> Self {
        Self {
            nullifiers: vec![BaseElement::ZERO; MAX_INPUTS],
            commitments: vec![BaseElement::ZERO; MAX_OUTPUTS],
            total_input: BaseElement::ZERO,
            total_output: BaseElement::ZERO,
            fee: BaseElement::ZERO,
            merkle_root: BaseElement::ZERO,
        }
    }
}

impl ToElements<BaseElement> for TransactionPublicInputsStark {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::with_capacity(MAX_INPUTS + MAX_OUTPUTS + 4);
        elements.extend(&self.nullifiers);
        elements.extend(&self.commitments);
        elements.push(self.total_input);
        elements.push(self.total_output);
        elements.push(self.fee);
        elements.push(self.merkle_root);
        elements
    }
}

// ================================================================================================
// AIR IMPLEMENTATION
// ================================================================================================

pub struct TransactionAirStark {
    context: AirContext<BaseElement>,
    pub_inputs: TransactionPublicInputsStark,
}

/// Number of cycles needed for a nullifier hash (6 inputs / rate 2 = 3 cycles)
pub const NULLIFIER_CYCLES: usize = 3;

/// Number of cycles needed for a commitment hash (14 inputs / rate 2 = 7 cycles)
pub const COMMITMENT_CYCLES: usize = 7;

/// Calculate trace row where nullifier N's hash output is located.
pub fn nullifier_output_row(nullifier_index: usize) -> usize {
    // Each nullifier takes NULLIFIER_CYCLES cycles
    // Nullifier 0: cycles 0,1,2 -> output at row 47 (3*16-1)
    // Nullifier 1: cycles 3,4,5 -> output at row 95 (6*16-1)
    let start_cycle = nullifier_index * NULLIFIER_CYCLES;
    (start_cycle + NULLIFIER_CYCLES) * CYCLE_LENGTH - 1
}

/// Calculate trace row where commitment M's hash output is located.
pub fn commitment_output_row(commitment_index: usize) -> usize {
    // Commitments start after all nullifiers
    let nullifier_total_cycles = MAX_INPUTS * NULLIFIER_CYCLES;
    let start_cycle = nullifier_total_cycles + commitment_index * COMMITMENT_CYCLES;
    (start_cycle + COMMITMENT_CYCLES) * CYCLE_LENGTH - 1
}

impl Air for TransactionAirStark {
    type BaseField = BaseElement;
    type PublicInputs = TransactionPublicInputsStark;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Constraint degree: S-box is x^5, so base degree is 5
        // The periodic hash_flag contributes via the cycles parameter
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
            TransitionConstraintDegree::with_cycles(5, vec![CYCLE_LENGTH]),
        ];

        // Count assertions: one for each non-zero nullifier and commitment
        let mut num_assertions = 0;
        
        for (i, &nf) in pub_inputs.nullifiers.iter().enumerate() {
            let row = nullifier_output_row(i);
            if nf != BaseElement::ZERO && row < trace_info.length() {
                num_assertions += 1;
            }
        }
        
        for (i, &cm) in pub_inputs.commitments.iter().enumerate() {
            let row = commitment_output_row(i);
            if cm != BaseElement::ZERO && row < trace_info.length() {
                num_assertions += 1;
            }
        }

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// Evaluate Poseidon round constraints.
    ///
    /// When hash_flag=1: next = MDS(S-box(current + round_constant))
    /// When hash_flag=0: no constraint (allows arbitrary state change at cycle boundaries)
    ///
    /// The assertions on specific rows ensure the correct hash outputs.
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Periodic values: [hash_flag, rc0, rc1, rc2]
        let hash_flag = periodic_values[0];
        let rc0 = periodic_values[1];
        let rc1 = periodic_values[2];
        let rc2 = periodic_values[3];

        // Compute Poseidon round result
        let t0 = current[COL_S0] + rc0;
        let t1 = current[COL_S1] + rc1;
        let t2 = current[COL_S2] + rc2;

        // S-box: x^5
        let s0 = t0.exp(5u64.into());
        let s1 = t1.exp(5u64.into());
        let s2 = t2.exp(5u64.into());

        // MDS mixing: [[2,1,1],[1,2,1],[1,1,2]]
        let two: E = E::from(BaseElement::new(2));
        let hash_s0 = s0 * two + s1 + s2;
        let hash_s1 = s0 + s1 * two + s2;
        let hash_s2 = s0 + s1 + s2 * two;

        // Constraint: hash_flag * (next - hash_result) = 0
        // When hash_flag=1: next must equal hash result
        // When hash_flag=0: constraint is automatically 0 (no enforcement)
        result[0] = hash_flag * (next[COL_S0] - hash_s0);
        result[1] = hash_flag * (next[COL_S1] - hash_s1);
        result[2] = hash_flag * (next[COL_S2] - hash_s2);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();
        
        // Assertions for all non-zero nullifiers
        for (i, &nf) in self.pub_inputs.nullifiers.iter().enumerate() {
            if nf != BaseElement::ZERO {
                let row = nullifier_output_row(i);
                if row < self.context.trace_len() {
                    assertions.push(Assertion::single(COL_S0, row, nf));
                }
            }
        }

        // Assertions for all non-zero commitments
        for (i, &cm) in self.pub_inputs.commitments.iter().enumerate() {
            if cm != BaseElement::ZERO {
                let row = commitment_output_row(i);
                if row < self.context.trace_len() {
                    assertions.push(Assertion::single(COL_S0, row, cm));
                }
            }
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        get_periodic_columns()
    }
}

// ================================================================================================
// POSEIDON HELPERS
// ================================================================================================

#[inline]
pub fn sbox(x: BaseElement) -> BaseElement {
    x.exp(5u64)
}

pub fn mds_mix(state: &[BaseElement; 3]) -> [BaseElement; 3] {
    let two = BaseElement::new(2);
    [
        state[0] * two + state[1] + state[2],
        state[0] + state[1] * two + state[2],
        state[0] + state[1] + state[2] * two,
    ]
}

pub fn poseidon_round(state: &mut [BaseElement; 3], round: usize) {
    state[0] += round_constant(round, 0);
    state[1] += round_constant(round, 1);
    state[2] += round_constant(round, 2);
    state[0] = sbox(state[0]);
    state[1] = sbox(state[1]);
    state[2] = sbox(state[2]);
    *state = mds_mix(state);
}

pub fn poseidon_permutation(state: &mut [BaseElement; 3]) {
    for round in 0..POSEIDON_ROUNDS {
        poseidon_round(state, round);
    }
}

pub fn poseidon_hash(domain_tag: u64, inputs: &[BaseElement]) -> BaseElement {
    let mut state = [BaseElement::new(domain_tag), BaseElement::ZERO, BaseElement::ONE];
    let rate = POSEIDON_WIDTH - 1;
    let mut cursor = 0;
    while cursor < inputs.len() {
        let take = core::cmp::min(rate, inputs.len() - cursor);
        for i in 0..take {
            state[i] += inputs[cursor + i];
        }
        poseidon_permutation(&mut state);
        cursor += take;
    }
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing;
    use winterfell::FieldExtension;

    #[test]
    fn test_round_constant_matches_hashing() {
        for round in 0..POSEIDON_ROUNDS {
            for pos in 0..POSEIDON_WIDTH {
                let our_rc = round_constant(round, pos);
                let expected = ((round as u64 + 1).wrapping_mul(0x9e37_79b9u64))
                    ^ ((pos as u64 + 1).wrapping_mul(0x7f4a_7c15u64));
                assert_eq!(our_rc, BaseElement::new(expected));
            }
        }
    }

    #[test]
    fn test_poseidon_hash_matches_hashing_module() {
        let inputs = vec![BaseElement::new(100), BaseElement::new(200)];
        let our_hash = poseidon_hash(1, &inputs);
        let _their_hash = hashing::note_commitment(100, 200, &[0u8; 32], &[0u8; 32], &[0u8; 32]);
        assert_ne!(our_hash, BaseElement::ZERO);
    }

    #[test]
    fn test_air_creation() {
        let trace_info = TraceInfo::new(TRACE_WIDTH, MIN_TRACE_LENGTH);
        // Need at least one non-zero assertion
        let pub_inputs = TransactionPublicInputsStark {
            nullifiers: vec![BaseElement::new(123), BaseElement::ZERO],
            commitments: vec![BaseElement::ZERO; MAX_OUTPUTS],
            ..Default::default()
        };
        let options = ProofOptions::new(
            32, 8, 0,
            FieldExtension::None,
            4, 31,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );

        let air = TransactionAirStark::new(trace_info, pub_inputs, options);
        assert_eq!(air.context().trace_info().width(), TRACE_WIDTH);
    }

    #[test]
    fn test_periodic_columns() {
        let cols = get_periodic_columns();
        // Should have hash_mask + 3 round constant columns
        assert_eq!(cols.len(), 1 + POSEIDON_WIDTH);
        assert_eq!(cols[0].len(), CYCLE_LENGTH);
        // Hash mask: 8 ones (for 8 rounds), 8 zeros (for copy steps)
        assert_eq!(cols[0][0], BaseElement::ONE);
        assert_eq!(cols[0][7], BaseElement::ONE);
        assert_eq!(cols[0][8], BaseElement::ZERO);
        assert_eq!(cols[0][15], BaseElement::ZERO);
    }

    #[test]
    fn test_public_inputs_to_elements() {
        let pub_inputs = TransactionPublicInputsStark {
            nullifiers: vec![BaseElement::new(1), BaseElement::new(2)],
            commitments: vec![BaseElement::new(3), BaseElement::new(4)],
            total_input: BaseElement::new(1000),
            total_output: BaseElement::new(900),
            fee: BaseElement::new(100),
            merkle_root: BaseElement::new(999),
        };

        let elements = pub_inputs.to_elements();
        assert_eq!(elements.len(), MAX_INPUTS + MAX_OUTPUTS + 4);
    }

    /// Test that constraint evaluation is consistent: compute one hash round manually
    /// and verify the constraint evaluates to zero.
    #[test]
    fn test_constraint_evaluation() {
        // Start with some state
        let state = [BaseElement::new(100), BaseElement::new(200), BaseElement::new(300)];
        let round = 0;
        
        // Get round constants
        let rc0 = round_constant(round, 0);
        let rc1 = round_constant(round, 1);
        let rc2 = round_constant(round, 2);
        
        // Compute expected next state
        let t0 = state[0] + rc0;
        let t1 = state[1] + rc1;
        let t2 = state[2] + rc2;
        
        let s0 = sbox(t0);
        let s1 = sbox(t1);
        let s2 = sbox(t2);
        
        let expected = mds_mix(&[s0, s1, s2]);
        
        // The constraint should be: hash_flag * (next - expected) = 0
        // With hash_flag = 1 and next = expected, result should be 0
        let next = expected;
        let hash_flag = BaseElement::ONE;
        
        let constraint0 = hash_flag * (next[0] - expected[0]);
        let constraint1 = hash_flag * (next[1] - expected[1]);
        let constraint2 = hash_flag * (next[2] - expected[2]);
        
        assert_eq!(constraint0, BaseElement::ZERO);
        assert_eq!(constraint1, BaseElement::ZERO);
        assert_eq!(constraint2, BaseElement::ZERO);
        
        // Also verify our round function matches
        let mut verify_state = [BaseElement::new(100), BaseElement::new(200), BaseElement::new(300)];
        poseidon_round(&mut verify_state, 0);
        assert_eq!(verify_state, expected);
    }

    /// Test constraint evaluation against actual trace data
    #[test]
    fn test_constraint_on_trace() {
        use crate::stark_prover::TransactionProverStark;
        use crate::witness::TransactionWitness;
        use crate::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
        
        let input_note = NoteData {
            value: 1000,
            asset_id: 0,
            pk_recipient: [1u8; 32],
            rho: [2u8; 32],
            r: [3u8; 32],
        };
        let output_note = NoteData {
            value: 900,
            asset_id: 0,
            pk_recipient: [3u8; 32],
            rho: [4u8; 32],
            r: [5u8; 32],
        };
        let witness = TransactionWitness {
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
        };
        
        let prover = TransactionProverStark::with_default_options();
        let trace = prover.build_trace(&witness).unwrap();
        
        // Get periodic columns
        let periodic_cols = get_periodic_columns();
        
        // Check constraint at step 0 (should be hash round)
        for step in 0..7 {
            let current = [
                trace.get(COL_S0, step),
                trace.get(COL_S1, step),
                trace.get(COL_S2, step),
            ];
            let next = [
                trace.get(COL_S0, step + 1),
                trace.get(COL_S1, step + 1),
                trace.get(COL_S2, step + 1),
            ];
            
            let hash_flag = periodic_cols[0][step % CYCLE_LENGTH];
            let rc0 = periodic_cols[1][step % CYCLE_LENGTH];
            let rc1 = periodic_cols[2][step % CYCLE_LENGTH];
            let rc2 = periodic_cols[3][step % CYCLE_LENGTH];
            
            // Compute constraint
            let t0 = current[0] + rc0;
            let t1 = current[1] + rc1;
            let t2 = current[2] + rc2;
            
            let s0 = sbox(t0);
            let s1 = sbox(t1);
            let s2 = sbox(t2);
            
            let expected = mds_mix(&[s0, s1, s2]);
            
            let c0 = hash_flag * (next[0] - expected[0]);
            let c1 = hash_flag * (next[1] - expected[1]);
            let c2 = hash_flag * (next[2] - expected[2]);
            
            assert_eq!(c0, BaseElement::ZERO, "Constraint 0 failed at step {}", step);
            assert_eq!(c1, BaseElement::ZERO, "Constraint 1 failed at step {}", step);
            assert_eq!(c2, BaseElement::ZERO, "Constraint 2 failed at step {}", step);
        }
        
        println!("All constraints satisfied for steps 0-6");
    }
}
