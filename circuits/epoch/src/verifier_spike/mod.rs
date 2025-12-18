//! Research Spike: Verifier Circuit Feasibility
//!
//! This module explores whether winterfell can practically support
//! verifying STARK proofs inside STARK proofs (recursive verification).
//!
//! ## Approach
//!
//! Rather than immediately attempting to verify complex transaction proofs,
//! we start with the simplest possible case:
//!
//! 1. **FibonacciAir**: A minimal 2-column AIR proving fib(n) = fib(n-1) + fib(n-2)
//! 2. **FibonacciVerifierAir**: An AIR that verifies Fibonacci proofs in-circuit
//!
//! ## Success Criteria
//!
//! - Outer proof size < 10× inner proof size
//! - Outer prover time < 100× inner prover time
//! - If criteria not met, document findings and evaluate alternatives
//!
//! ## Key Challenges
//!
//! 1. **FRI Verification**: The inner proof uses FRI protocol which requires
//!    polynomial evaluation at query points. Encoding this as AIR constraints
//!    requires representing polynomial arithmetic in the trace.
//!
//! 2. **Hash Function**: Winterfell uses Blake3 for Fiat-Shamir. Implementing
//!    Blake3 as AIR constraints is expensive (~100 columns). We use Poseidon
//!    for in-circuit hashing instead, which means the verifier circuit differs
//!    from native verification.
//!
//! 3. **Field Arithmetic**: The inner proof uses Goldilocks field (2^64 - 2^32 + 1).
//!    Field operations must be computed correctly in the outer proof's trace.
//!
//! ## Alternatives if Spike Fails
//!
//! - **Plonky2**: Native recursion support with efficient recursive circuits
//! - **Miden VM**: STARK-based VM with built-in recursion primitives
//! - **Contribute to winterfell**: Add recursion primitives upstream
//!
//! ## Usage
//!
//! ```ignore
//! use epoch_circuit::verifier_spike::{FibonacciAir, FibonacciVerifierAir};
//!
//! // Generate inner proof
//! let inner_proof = fibonacci_prover::prove(fib_sequence);
//!
//! // Generate outer proof that verifies inner proof
//! let outer_proof = fibonacci_verifier_prover::prove(&inner_proof);
//!
//! // Verify outer proof (constant time regardless of inner computation)
//! assert!(fibonacci_verifier::verify(&outer_proof));
//! ```

pub mod fibonacci_air;
pub mod fibonacci_verifier_air;

#[cfg(test)]
mod tests;

// Re-exports for convenience
pub use fibonacci_air::{FibonacciAir, FibonacciProver, FibonacciPublicInputs};
pub use fibonacci_verifier_air::{
    FibonacciVerifierAir, FibonacciVerifierProver, VerifierPublicInputs,
};

/// Benchmark results from the verifier spike.
#[derive(Debug, Clone)]
pub struct SpikeResults {
    /// Size of inner Fibonacci proof in bytes.
    pub inner_proof_size: usize,
    /// Size of outer verifier proof in bytes.
    pub outer_proof_size: usize,
    /// Time to generate inner proof in milliseconds.
    pub inner_prover_time_ms: u64,
    /// Time to generate outer proof in milliseconds.
    pub outer_prover_time_ms: u64,
    /// Time to verify inner proof in microseconds.
    pub inner_verify_time_us: u64,
    /// Time to verify outer proof in microseconds.
    pub outer_verify_time_us: u64,
    /// Whether the spike met success criteria.
    pub success: bool,
    /// Human-readable summary.
    pub summary: String,
}

impl SpikeResults {
    /// Compute size ratio (outer / inner).
    pub fn size_ratio(&self) -> f64 {
        self.outer_proof_size as f64 / self.inner_proof_size as f64
    }

    /// Compute prover time ratio (outer / inner).
    pub fn prover_time_ratio(&self) -> f64 {
        self.outer_prover_time_ms as f64 / self.inner_prover_time_ms.max(1) as f64
    }

    /// Check if spike met success criteria.
    pub fn meets_criteria(&self) -> bool {
        self.size_ratio() < 10.0 && self.prover_time_ratio() < 100.0
    }
}
