//! Fibonacci AIR - Minimal Inner Proof for Verifier Spike
//!
//! This module implements the simplest possible AIR to serve as the inner
//! proof target for the verifier circuit spike. The Fibonacci sequence
//! constraint (fib(n) = fib(n-1) + fib(n-2)) requires only 2 columns.
//!
//! ## Trace Layout
//!
//! | Row | Column 0 (prev) | Column 1 (curr) |
//! |-----|-----------------|-----------------|
//! | 0   | fib(0) = 0      | fib(1) = 1      |
//! | 1   | fib(1) = 1      | fib(2) = 1      |
//! | 2   | fib(2) = 1      | fib(3) = 2      |
//! | 3   | fib(3) = 2      | fib(4) = 3      |
//! | ... | ...             | ...             |
//!
//! ## Constraints
//!
//! For each row i (except the last):
//! - next_prev = curr (column 0 of next row equals column 1 of current row)
//! - next_curr = prev + curr (column 1 of next row equals sum of current row)
//!
//! ## Public Inputs
//!
//! - fib(0): Initial value (always 0)
//! - fib(1): Initial value (always 1)
//! - fib(n): Final computed Fibonacci number

use winter_crypto::hashers::Blake3_256;
use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, ProofOptions, Prover, ProverError, StarkDomain, TraceInfo,
    TracePolyTable, TraceTable, TransitionConstraintDegree,
};

type Blake3 = Blake3_256<BaseElement>;

/// Number of columns in the Fibonacci trace.
const TRACE_WIDTH: usize = 2;

/// Default trace length (must be power of 2).
const DEFAULT_TRACE_LENGTH: usize = 64;

// ================================================================================================
// PUBLIC INPUTS
// ================================================================================================

/// Public inputs for Fibonacci proof verification.
#[derive(Clone, Debug, Default)]
pub struct FibonacciPublicInputs {
    /// Starting value fib(0) - always 0.
    pub fib_0: BaseElement,
    /// Starting value fib(1) - always 1.
    pub fib_1: BaseElement,
    /// Final computed value fib(n).
    pub result: BaseElement,
}

impl FibonacciPublicInputs {
    /// Create new public inputs for computing fib(n).
    pub fn new(result: BaseElement) -> Self {
        Self {
            fib_0: BaseElement::ZERO,
            fib_1: BaseElement::ONE,
            result,
        }
    }
}

impl ToElements<BaseElement> for FibonacciPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.fib_0, self.fib_1, self.result]
    }
}

// ================================================================================================
// FIBONACCI AIR
// ================================================================================================

/// AIR for Fibonacci sequence computation.
///
/// This is the simplest possible AIR, serving as the inner proof target
/// for the verifier circuit spike.
pub struct FibonacciAir {
    context: AirContext<BaseElement>,
    result: BaseElement,
}

impl FibonacciAir {
    /// Create a new Fibonacci AIR for the given trace length and result.
    pub fn new(trace_info: TraceInfo, pub_inputs: FibonacciPublicInputs, options: ProofOptions) -> Self {
        // Two transition constraints: one for each column
        let degrees = vec![
            TransitionConstraintDegree::new(1), // next_prev = curr
            TransitionConstraintDegree::new(1), // next_curr = prev + curr
        ];

        Self {
            context: AirContext::new(trace_info, degrees, 3, options),
            result: pub_inputs.result,
        }
    }
}

impl Air for FibonacciAir {
    type BaseField = BaseElement;
    type PublicInputs = FibonacciPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        FibonacciAir::new(trace_info, pub_inputs, options)
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Constraint 1: next[0] = current[1] (prev becomes curr)
        result[0] = next[0] - current[1];

        // Constraint 2: next[1] = current[0] + current[1] (new curr is sum)
        result[1] = next[1] - (current[0] + current[1]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_row = self.trace_length() - 1;

        vec![
            // Initial values: fib(0) = 0, fib(1) = 1
            Assertion::single(0, 0, BaseElement::ZERO), // column 0, row 0
            Assertion::single(1, 0, BaseElement::ONE),  // column 1, row 0
            // Final result
            Assertion::single(1, last_row, self.result), // column 1, last row
        ]
    }
}

// ================================================================================================
// FIBONACCI PROVER
// ================================================================================================

/// Prover for Fibonacci AIR.
pub struct FibonacciProver {
    options: ProofOptions,
}

impl FibonacciProver {
    /// Create a new Fibonacci prover with default options.
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(
                8,  // num_queries
                4,  // blowup_factor_log2
                0,  // grinding_factor
                FieldExtension::None,
                2,  // fri_folding_factor
                31, // fri_max_remainder_size
                BatchingMethod::Linear,
                BatchingMethod::Linear,
            ),
        }
    }

    /// Create a prover with custom options.
    pub fn with_options(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Build the Fibonacci trace for n iterations.
    pub fn build_trace(&self, n: usize) -> TraceTable<BaseElement> {
        // Trace length must be power of 2
        let trace_len = n.next_power_of_two().max(DEFAULT_TRACE_LENGTH);

        let mut trace = TraceTable::new(TRACE_WIDTH, trace_len);

        // Fill the trace with Fibonacci sequence
        trace.fill(
            |state| {
                // Initial state: fib(0) = 0, fib(1) = 1
                state[0] = BaseElement::ZERO;
                state[1] = BaseElement::ONE;
            },
            |_, state| {
                // Transition: prev = curr, curr = prev + curr
                let prev = state[0];
                let curr = state[1];
                state[0] = curr;
                state[1] = prev + curr;
            },
        );

        trace
    }

    /// Compute the n-th Fibonacci number.
    pub fn compute_fib(n: usize) -> BaseElement {
        if n == 0 {
            return BaseElement::ZERO;
        }
        if n == 1 {
            return BaseElement::ONE;
        }

        let mut prev = BaseElement::ZERO;
        let mut curr = BaseElement::ONE;

        for _ in 2..=n {
            let next = prev + curr;
            prev = curr;
            curr = next;
        }

        curr
    }

    /// Generate a proof for computing fib(n).
    pub fn prove(&self, n: usize) -> Result<(winterfell::Proof, FibonacciPublicInputs), ProverError> {
        let trace = self.build_trace(n);
        let trace_len = winterfell::Trace::length(&trace);

        // The result is fib(trace_len) due to how we fill the trace
        let result = Self::compute_fib(trace_len);
        let pub_inputs = FibonacciPublicInputs::new(result);

        let proof = Prover::prove(self, trace)?;
        Ok((proof, pub_inputs))
    }
}

impl Default for FibonacciProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover for FibonacciProver {
    type BaseField = BaseElement;
    type Air = FibonacciAir;
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

    fn get_pub_inputs(&self, trace: &Self::Trace) -> FibonacciPublicInputs {
        let last_row = winterfell::Trace::length(trace) - 1;
        // Read the result from column 1, last row
        let result = trace.get(1, last_row);
        FibonacciPublicInputs::new(result)
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
// VERIFICATION
// ================================================================================================

/// Verify a Fibonacci proof.
pub fn verify_fibonacci_proof(
    proof: &winterfell::Proof,
    pub_inputs: &FibonacciPublicInputs,
) -> Result<(), String> {
    let acceptable_options = AcceptableOptions::OptionSet(vec![ProofOptions::new(
        8,
        4,
        0,
        FieldExtension::None,
        2,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )]);

    winterfell::verify::<FibonacciAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
        proof.clone(),
        pub_inputs.clone(),
        &acceptable_options,
    )
    .map_err(|e| format!("Verification failed: {:?}", e))
}

// ================================================================================================
// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::Trace;

    #[test]
    fn test_compute_fib() {
        assert_eq!(FibonacciProver::compute_fib(0), BaseElement::ZERO);
        assert_eq!(FibonacciProver::compute_fib(1), BaseElement::ONE);
        assert_eq!(FibonacciProver::compute_fib(2), BaseElement::ONE);
        assert_eq!(FibonacciProver::compute_fib(3), BaseElement::new(2));
        assert_eq!(FibonacciProver::compute_fib(4), BaseElement::new(3));
        assert_eq!(FibonacciProver::compute_fib(5), BaseElement::new(5));
        assert_eq!(FibonacciProver::compute_fib(10), BaseElement::new(55));
    }

    #[test]
    fn test_build_trace() {
        let prover = FibonacciProver::new();
        let trace = prover.build_trace(10);

        // Trace should be at least 64 rows (power of 2)
        assert!(trace.length() >= 64);

        // Check initial values
        assert_eq!(trace.get(0, 0), BaseElement::ZERO);
        assert_eq!(trace.get(1, 0), BaseElement::ONE);

        // Check a few Fibonacci values
        assert_eq!(trace.get(1, 1), BaseElement::ONE);  // fib(2)
        assert_eq!(trace.get(1, 2), BaseElement::new(2));  // fib(3)
        assert_eq!(trace.get(1, 3), BaseElement::new(3));  // fib(4)
        assert_eq!(trace.get(1, 4), BaseElement::new(5));  // fib(5)
    }

    #[test]
    fn test_fibonacci_proof_generation() {
        let prover = FibonacciProver::new();
        let (proof, pub_inputs) = prover.prove(64).expect("Proof generation should succeed");

        // Verify the proof
        let result = verify_fibonacci_proof(&proof, &pub_inputs);
        assert!(result.is_ok(), "Verification failed: {:?}", result);

        // Check that result matches computed value
        let expected = FibonacciProver::compute_fib(64);
        assert_eq!(pub_inputs.result, expected);
    }

    #[test]
    fn test_proof_size() {
        let prover = FibonacciProver::new();
        let (proof, _) = prover.prove(64).expect("Proof generation should succeed");

        // Serialize and check size
        let proof_bytes = proof.to_bytes();
        println!("Fibonacci proof size: {} bytes", proof_bytes.len());

        // Proof should be reasonably small for this simple AIR
        assert!(proof_bytes.len() < 50_000, "Proof unexpectedly large: {} bytes", proof_bytes.len());
    }
}
