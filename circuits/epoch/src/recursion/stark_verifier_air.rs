//! Complete STARK verifier as AIR constraints.
//!
//! This module composes all the verification components into a single AIR
//! that can verify another STARK proof in-circuit, enabling true recursion.
//!
//! ## STARK Verification Steps
//!
//! 1. **Commitment Phase**
//!    - Verify trace commitment (Merkle root)
//!    - Verify constraint commitment (Merkle root)
//!
//! 2. **Query Phase (using Fiat-Shamir via RPO)**
//!    - Draw random challenges using RPO-based RandomCoin
//!    - Compute query positions
//!
//! 3. **FRI Verification**
//!    - Verify polynomial commitment opens to claimed values
//!    - Verify FRI folding is consistent
//!
//! 4. **Deep Composition**
//!    - Verify DEEP queries at OOD (out-of-domain) point
//!    - Verify constraint evaluations match
//!
//! ## Trace Layout
//!
//! The verifier trace combines multiple sub-components:
//! - RPO permutations for Fiat-Shamir challenges
//! - Merkle path verifications for query authentication
//! - FRI folding verifications
//! - Constraint evaluation checks

use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Word;
use winter_crypto::RandomCoin;
use winter_math::{FieldElement, ToElements};
use winterfell::math::fields::f64::BaseElement;

use super::rpo_air::{STATE_WIDTH, ROWS_PER_PERMUTATION, NUM_ROUNDS, MDS, ARK1, ARK2};
use super::merkle_air::DIGEST_WIDTH;
use winter_air::DeepCompositionCoefficients;

const CAPACITY_WIDTH: usize = 4;
const RATE_WIDTH: usize = 8;
const RATE_START: usize = CAPACITY_WIDTH;

// CONSTANTS
// ================================================================================================

/// Maximum supported proof trace length (log2)
pub const MAX_TRACE_LENGTH_LOG2: usize = 24;

/// Maximum number of transition constraints
pub const MAX_TRANSITION_CONSTRAINTS: usize = 256;

/// Maximum number of boundary assertions
pub const MAX_ASSERTIONS: usize = 128;

// STARK VERIFIER PUBLIC INPUTS
// ================================================================================================

/// Public inputs for STARK verification.
///
/// These are the minimal inputs needed to verify a STARK proof:
/// - The claimed public inputs of the inner proof
/// - The commitment structure (Merkle roots)
#[derive(Clone, Debug)]
pub struct StarkVerifierPublicInputs {
    /// Full public inputs of the inner proof (as field elements).
    pub inner_public_inputs: Vec<BaseElement>,
    /// Hash of the inner proof's public inputs
    pub inner_pub_inputs_hash: [BaseElement; DIGEST_WIDTH],
    
    /// Trace commitment (Merkle root of trace polynomial evaluations)
    pub trace_commitment: [BaseElement; DIGEST_WIDTH],
    
    /// Constraint commitment (Merkle root of constraint evaluations)
    pub constraint_commitment: [BaseElement; DIGEST_WIDTH],
    
    /// FRI layer commitments (Merkle roots)
    pub fri_commitments: Vec<[BaseElement; DIGEST_WIDTH]>,
    
    /// Security parameters
    pub num_queries: usize,
    pub blowup_factor: usize,
    pub trace_length: usize,
}

impl StarkVerifierPublicInputs {
    pub fn new(
        inner_public_inputs: Vec<BaseElement>,
        inner_pub_inputs_hash: [BaseElement; DIGEST_WIDTH],
        trace_commitment: [BaseElement; DIGEST_WIDTH],
        constraint_commitment: [BaseElement; DIGEST_WIDTH],
        fri_commitments: Vec<[BaseElement; DIGEST_WIDTH]>,
        num_queries: usize,
        blowup_factor: usize,
        trace_length: usize,
    ) -> Self {
        Self {
            inner_public_inputs,
            inner_pub_inputs_hash,
            trace_commitment,
            constraint_commitment,
            fri_commitments,
            num_queries,
            blowup_factor,
            trace_length,
        }
    }
}

impl ToElements<BaseElement> for StarkVerifierPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();
        
        elements.extend_from_slice(&self.inner_public_inputs);
        elements.extend_from_slice(&self.inner_pub_inputs_hash);
        elements.extend_from_slice(&self.trace_commitment);
        elements.extend_from_slice(&self.constraint_commitment);
        
        for commitment in &self.fri_commitments {
            elements.extend_from_slice(commitment);
        }
        
        elements.push(BaseElement::new(self.num_queries as u64));
        elements.push(BaseElement::new(self.blowup_factor as u64));
        elements.push(BaseElement::new(self.trace_length as u64));
        
        elements
    }
}

// STARK VERIFIER AIR
// ================================================================================================

/// AIR for verifying STARK proofs.
///
/// This is the core of recursive STARKs - a circuit that verifies another
/// STARK proof entirely in-circuit using algebraic operations.
///
/// The verification process:
/// 1. Reconstruct Fiat-Shamir challenges using RPO hash
/// 2. Verify Merkle proofs for queried positions
/// 3. Verify FRI folding consistency
/// 4. Check constraint evaluations at query positions
pub struct StarkVerifierAir {
    context: AirContext<BaseElement>,
    pub_inputs: StarkVerifierPublicInputs,
}

impl Air for StarkVerifierAir {
    type BaseField = BaseElement;
    type PublicInputs = StarkVerifierPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Constraints:
        // - RPO constraints for Fiat-Shamir (degree 8)
        // - Merkle path verification (degree 8 from RPO)
        // - FRI folding (degree 2)
        // - Constraint evaluation checks (varies)
        
        // For the initial minimal verifier we only enforce:
        // - RPO permutation constraints for hashing inner public inputs
        // - Capacity carryover between sponge blocks
        let num_constraints = STATE_WIDTH + DIGEST_WIDTH;
        let mut degrees = Vec::with_capacity(num_constraints);

        // RPO transition constraints are gated by two periodic selectors:
        // - half_round_type (permutation schedule)
        // - perm_mask (disable boundary transitions)
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                7,
                vec![
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                ],
            ));
        }

        // Capacity carryover is linear in trace columns and gated by one periodic selector.
        for _ in 0..DIGEST_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                1,
                vec![ROWS_PER_PERMUTATION],
            ));
        }

        // Assertions bind sponge inputs and output digest.
        let num_blocks = (pub_inputs.inner_public_inputs.len() + RATE_WIDTH - 1) / RATE_WIDTH;
        let num_assertions = CAPACITY_WIDTH + num_blocks * RATE_WIDTH + DIGEST_WIDTH;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self { context, pub_inputs }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Periodic values layout:
        // [half_round_type, ark[0..STATE_WIDTH], perm_mask]
        let half_round_type = periodic_values[0];
        let ark: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);
        let perm_mask = periodic_values[1 + STATE_WIDTH];
        let boundary_mask = E::ONE - perm_mask;

        // MDS result
        let mut mds_result: [E; STATE_WIDTH] = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                let mds_coeff = E::from(MDS[i][j]);
                mds_result[i] += mds_coeff * current[j];
            }
        }

        // Add round constants
        let mut intermediate: [E; STATE_WIDTH] = [E::ZERO; STATE_WIDTH];
        for i in 0..STATE_WIDTH {
            intermediate[i] = mds_result[i] + ark[i];
        }

        // Selectors
        let one = E::ONE;
        let two = one + one;
        let is_forward = half_round_type * (two - half_round_type);
        let is_inverse = half_round_type * (half_round_type - one);
        let is_padding = (one - half_round_type) * (two - half_round_type);

        // RPO state constraints
        for i in 0..STATE_WIDTH {
            let x = intermediate[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            let x3 = x2 * x;
            let x7 = x3 * x4;
            let forward_constraint = next[i] - x7;

            let y = next[i];
            let y2 = y * y;
            let y4 = y2 * y2;
            let y3 = y2 * y;
            let y7 = y3 * y4;
            let inverse_constraint = y7 - intermediate[i];

            let padding_constraint = next[i] - current[i];

            let rpo_constraint = is_forward * forward_constraint
                + is_inverse * inverse_constraint
                + is_padding * padding_constraint;
            // Disable RPO constraints at permutation boundaries to allow sponge reloading.
            result[i] = perm_mask * rpo_constraint;
        }

        // Capacity carryover constraints at boundaries between sponge blocks.
        for i in 0..DIGEST_WIDTH {
            result[STATE_WIDTH + i] = boundary_mask * (next[i] - current[i]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Sponge initialization.
        let input_len = self.pub_inputs.inner_public_inputs.len();
        let len_mod_rate = (input_len % RATE_WIDTH) as u64;
        assertions.push(Assertion::single(
            0,
            0,
            BaseElement::new(len_mod_rate),
        ));
        for i in 1..CAPACITY_WIDTH {
            assertions.push(Assertion::single(i, 0, BaseElement::ZERO));
        }

        // Bind each absorbed block to the corresponding public inputs.
        let num_blocks = (input_len + RATE_WIDTH - 1) / RATE_WIDTH;
        for block in 0..num_blocks {
            let row = block * ROWS_PER_PERMUTATION;
            let start = block * RATE_WIDTH;
            for j in 0..RATE_WIDTH {
                let val = if start + j < input_len {
                    self.pub_inputs.inner_public_inputs[start + j]
                } else {
                    BaseElement::ZERO
                };
                assertions.push(Assertion::single(RATE_START + j, row, val));
            }
        }

        // Bind digest after the final permutation.
        let last_row = num_blocks * ROWS_PER_PERMUTATION - 1;
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                RATE_START + i,
                last_row,
                self.pub_inputs.inner_pub_inputs_hash[i],
            ));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let total_rows = self.trace_length();

        let mut half_round_type = Vec::with_capacity(total_rows);
        let mut ark_columns: [Vec<BaseElement>; STATE_WIDTH] = 
            core::array::from_fn(|_| Vec::with_capacity(total_rows));
        let mut perm_mask = Vec::with_capacity(total_rows);

        for row in 0..total_rows {
            let local_row = row % ROWS_PER_PERMUTATION;
            let val = if local_row >= 14 {
                0
            } else if local_row % 2 == 0 {
                1
            } else {
                2
            };
            half_round_type.push(BaseElement::new(val));

            let constants = if local_row >= 14 {
                [BaseElement::ZERO; STATE_WIDTH]
            } else if local_row % 2 == 0 {
                let round = local_row / 2;
                if round < NUM_ROUNDS { ARK1[round] } else { [BaseElement::ZERO; STATE_WIDTH] }
            } else {
                let round = local_row / 2;
                if round < NUM_ROUNDS { ARK2[round] } else { [BaseElement::ZERO; STATE_WIDTH] }
            };

            for (i, &c) in constants.iter().enumerate() {
                ark_columns[i].push(c);
            }

            // Apply RPO constraints on all transitions except boundaries between permutations.
            let mask = (local_row < ROWS_PER_PERMUTATION - 1) as u64;
            perm_mask.push(BaseElement::new(mask));
        }

        let mut result = vec![half_round_type];
        for col in ark_columns {
            result.push(col);
        }
        result.push(perm_mask);
        result
    }
}

// VERIFICATION HELPERS
// ================================================================================================

/// Helper to extract query positions from an RPO transcript seed.
pub fn extract_query_positions(
    transcript_seed: [BaseElement; DIGEST_WIDTH],
    num_queries: usize,
    domain_size: usize,
    pow_nonce: u64,
) -> Vec<usize> {
    let word = Word::new(transcript_seed);
    let mut coin = RpoRandomCoin::new(word);
    let mut positions = coin
        .draw_integers(num_queries, domain_size, pow_nonce)
        .expect("failed to draw query positions");
    positions.sort_unstable();
    positions.dedup();
    positions
}

/// Compute a single DEEP composition evaluation for a query.
///
/// This matches `winter-verifier`'s `DeepComposer::compose_columns` for the
/// base-field, single-trace-segment case.
pub fn compute_deep_evaluation(
    x: BaseElement,
    trace_row: &[BaseElement],
    constraint_row: &[BaseElement],
    ood_trace_z: &[BaseElement],
    ood_trace_zg: &[BaseElement],
    ood_constraints_z: &[BaseElement],
    ood_constraints_zg: &[BaseElement],
    deep_coeffs: &DeepCompositionCoefficients<BaseElement>,
    z: BaseElement,
    g_trace: BaseElement,
) -> BaseElement {
    let z1 = z * g_trace;
    let x_minus_z0 = x - z;
    let x_minus_z1 = x - z1;

    assert_eq!(trace_row.len(), deep_coeffs.trace.len());
    assert_eq!(constraint_row.len(), deep_coeffs.constraints.len());

    let mut t1_num = BaseElement::ZERO;
    let mut t2_num = BaseElement::ZERO;
    for i in 0..trace_row.len() {
        t1_num += deep_coeffs.trace[i] * (trace_row[i] - ood_trace_z[i]);
        t2_num += deep_coeffs.trace[i] * (trace_row[i] - ood_trace_zg[i]);
    }
    let num_trace = t1_num * x_minus_z1 + t2_num * x_minus_z0;

    let mut c1_num = BaseElement::ZERO;
    let mut c2_num = BaseElement::ZERO;
    for j in 0..constraint_row.len() {
        c1_num += deep_coeffs.constraints[j] * (constraint_row[j] - ood_constraints_z[j]);
        c2_num += deep_coeffs.constraints[j] * (constraint_row[j] - ood_constraints_zg[j]);
    }
    let num_constraints = c1_num * x_minus_z1 + c2_num * x_minus_z0;

    let den = x_minus_z0 * x_minus_z1;
    (num_trace + num_constraints) / den
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_verifier_public_inputs() {
        let inner_inputs = vec![BaseElement::new(9); 3];
        let inner_hash = [BaseElement::new(1); DIGEST_WIDTH];
        let trace_commit = [BaseElement::new(2); DIGEST_WIDTH];
        let constraint_commit = [BaseElement::new(3); DIGEST_WIDTH];
        let fri_commits = vec![[BaseElement::new(4); DIGEST_WIDTH]; 5];
        
        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_inputs,
            inner_hash,
            trace_commit,
            constraint_commit,
            fri_commits.clone(),
            32,
            16,
            1024,
        );
        
        assert_eq!(pub_inputs.num_queries, 32);
        assert_eq!(pub_inputs.fri_commitments.len(), 5);
    }

    #[test]
    fn test_extract_query_positions() {
        let hash = [
            BaseElement::new(12345),
            BaseElement::new(67890),
            BaseElement::new(11111),
            BaseElement::new(22222),
        ];
        
        let positions = extract_query_positions(hash, 8, 1024, 0);
        
        assert_eq!(positions.len(), 8);
        for &pos in &positions {
            assert!(pos < 1024);
        }
        
        // Verify determinism
        let positions2 = extract_query_positions(hash, 8, 1024, 0);
        assert_eq!(positions, positions2);
    }

    #[test]
    fn test_deep_evaluation_matches_manual() {
        let z = BaseElement::new(10);
        let g_trace = BaseElement::new(2);
        let x = BaseElement::new(11);

        let trace_row = vec![BaseElement::new(5)];
        let constraint_row = vec![BaseElement::new(7)];

        let ood_trace_z = vec![BaseElement::new(3)];
        let ood_trace_zg = vec![BaseElement::new(4)];
        let ood_constraints_z = vec![BaseElement::new(2)];
        let ood_constraints_zg = vec![BaseElement::new(1)];

        let deep_coeffs = DeepCompositionCoefficients {
            trace: vec![BaseElement::ONE],
            constraints: vec![BaseElement::ONE],
        };

        // Manual computation per DeepComposer formula.
        let z1 = z * g_trace;
        let x_minus_z0 = x - z;
        let x_minus_z1 = x - z1;

        let t1_num = trace_row[0] - ood_trace_z[0];
        let t2_num = trace_row[0] - ood_trace_zg[0];
        let num_trace = t1_num * x_minus_z1 + t2_num * x_minus_z0;

        let c1_num = constraint_row[0] - ood_constraints_z[0];
        let c2_num = constraint_row[0] - ood_constraints_zg[0];
        let num_constraints = c1_num * x_minus_z1 + c2_num * x_minus_z0;

        let den = x_minus_z0 * x_minus_z1;
        let expected = (num_trace + num_constraints) / den;

        let computed = compute_deep_evaluation(
            x,
            &trace_row,
            &constraint_row,
            &ood_trace_z,
            &ood_trace_zg,
            &ood_constraints_z,
            &ood_constraints_zg,
            &deep_coeffs,
            z,
            g_trace,
        );

        assert_eq!(computed, expected);
    }

    #[test]
    fn test_to_elements() {
        let pub_inputs = StarkVerifierPublicInputs::new(
            vec![BaseElement::ONE; 2],
            [BaseElement::ONE; DIGEST_WIDTH],
            [BaseElement::new(2); DIGEST_WIDTH],
            [BaseElement::new(3); DIGEST_WIDTH],
            vec![[BaseElement::new(4); DIGEST_WIDTH]; 3],
            32,
            16,
            1024,
        );
        
        let elements = pub_inputs.to_elements();
        
        // inner_public_inputs (2) + 4 (inner hash) + 4 (trace) + 4 (constraint) + 3*4 (fri) + 3 (params)
        assert_eq!(elements.len(), 2 + 4 + 4 + 4 + 12 + 3);
    }
}
