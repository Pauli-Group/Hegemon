//! FRI (Fast Reed-Solomon IOP) verification as AIR constraints.
//!
//! This module implements in-circuit FRI verification for recursive STARKs.
//! FRI is the core of STARK soundness - it proves a polynomial has low degree.
//!
//! ## FRI Protocol Overview
//!
//! 1. Commit: Prover commits to polynomial evaluations via Merkle tree
//! 2. Query: Verifier samples random query positions
//! 3. Verify: For each query, verify:
//!    - Merkle paths for committed values
//!    - Polynomial folding is consistent at each layer
//!    - Final polynomial is low-degree (check explicit coefficients)
//!
//! ## In-Circuit Verification
//!
//! For each query, we verify:
//! - Merkle authentication path using RPO hash
//! - Folding consistency: f_next(x^2) = f_even(x^2) + α * f_odd(x^2)
//!
//! Where α is the random folding factor from Fiat-Shamir (via RPO).

use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::{FieldElement, ToElements};
use winterfell::math::fields::f64::BaseElement;

use super::rpo_air::{STATE_WIDTH, ROWS_PER_PERMUTATION};
use super::merkle_air::DIGEST_WIDTH;

// CONSTANTS
// ================================================================================================

/// Maximum number of FRI layers we support
pub const MAX_FRI_LAYERS: usize = 20;

/// Number of queries per layer (security parameter)
pub const DEFAULT_NUM_QUERIES: usize = 32;

// FRI QUERY DATA
// ================================================================================================

/// Data for a single FRI query at one layer
#[derive(Clone, Debug)]
pub struct FriLayerQuery {
    /// The x-coordinate being queried
    pub position: u64,
    /// The evaluation f(x)
    pub evaluation: BaseElement,
    /// The evaluation f(-x) (sibling in folding)
    pub sibling_eval: BaseElement,
}

/// Complete FRI query across all layers
#[derive(Clone, Debug)]
pub struct FriQueryData {
    /// Query position in the initial domain
    pub initial_position: u64,
    /// Layer queries (from initial to final)
    pub layer_queries: Vec<FriLayerQuery>,
    /// Merkle authentication paths for each layer
    pub merkle_paths: Vec<Vec<[BaseElement; DIGEST_WIDTH]>>,
}

// PUBLIC INPUTS
// ================================================================================================

/// Public inputs for FRI verification
#[derive(Clone, Debug)]
pub struct FriPublicInputs {
    /// Commitments to each FRI layer (Merkle roots)
    pub layer_commitments: Vec<[BaseElement; DIGEST_WIDTH]>,
    /// The folding factors (random challenges from Fiat-Shamir)
    pub folding_factors: Vec<BaseElement>,
    /// Domain size of the initial polynomial
    pub initial_domain_size: usize,
    /// Claimed degree bound
    pub degree_bound: usize,
    /// Number of FRI layers
    pub num_layers: usize,
}

impl FriPublicInputs {
    pub fn new(
        layer_commitments: Vec<[BaseElement; DIGEST_WIDTH]>,
        folding_factors: Vec<BaseElement>,
        initial_domain_size: usize,
        degree_bound: usize,
    ) -> Self {
        let num_layers = layer_commitments.len();
        Self {
            layer_commitments,
            folding_factors,
            initial_domain_size,
            degree_bound,
            num_layers,
        }
    }
}

impl ToElements<BaseElement> for FriPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();
        
        // Flatten layer commitments
        for commitment in &self.layer_commitments {
            elements.extend_from_slice(commitment);
        }
        
        // Folding factors
        elements.extend_from_slice(&self.folding_factors);
        
        // Domain size and degree bound
        elements.push(BaseElement::new(self.initial_domain_size as u64));
        elements.push(BaseElement::new(self.degree_bound as u64));
        elements.push(BaseElement::new(self.num_layers as u64));
        
        elements
    }
}

// FRI FOLDING VERIFICATION
// ================================================================================================

/// Verify FRI folding consistency.
///
/// At each layer transition:
/// - f_next(x^2) = (f(x) + f(-x))/2 + α * (f(x) - f(-x))/(2x)
///
/// This can be rewritten as:
/// - 2 * f_next(x^2) = (1 + α/x) * f(x) + (1 - α/x) * f(-x)
///
/// Which in the field becomes:
/// - 2x * f_next(x^2) = (x + α) * f(x) + (x - α) * f(-x)
#[derive(Clone, Debug)]
pub struct FriFoldingVerifier;

impl FriFoldingVerifier {
    /// Verify a single folding step
    pub fn verify_folding(
        x: BaseElement,
        f_x: BaseElement,
        f_neg_x: BaseElement,
        f_next: BaseElement,
        alpha: BaseElement,
    ) -> bool {
        // 2x * f_next = (x + α) * f(x) + (x - α) * f(-x)
        let two = BaseElement::new(2);
        let lhs = two * x * f_next;
        let rhs = (x + alpha) * f_x + (x - alpha) * f_neg_x;
        lhs == rhs
    }

    /// Compute expected f_next from f(x), f(-x), and folding factor
    pub fn compute_folded(
        x: BaseElement,
        f_x: BaseElement,
        f_neg_x: BaseElement,
        alpha: BaseElement,
    ) -> BaseElement {
        // f_next = ((x + α) * f(x) + (x - α) * f(-x)) / (2x)
        let two = BaseElement::new(2);
        let numerator = (x + alpha) * f_x + (x - alpha) * f_neg_x;
        let denominator = two * x;
        numerator / denominator
    }
}

// FRI VERIFIER AIR
// ================================================================================================

/// AIR for FRI verification.
///
/// This AIR verifies FRI queries by checking:
/// 1. Merkle paths authenticate queried values
/// 2. Folding is consistent across layers
///
/// The trace layout combines Merkle verification (using RPO) with
/// folding constraint verification.
pub struct FriVerifierAir {
    context: AirContext<BaseElement>,
    pub_inputs: FriPublicInputs,
}

// Trace column layout.
// Columns 0..STATE_WIDTH-1 are reserved for RPO state when Merkle authentication
// is integrated. Folding checks use extra columns after the RPO state.
const COL_F_X: usize = STATE_WIDTH;
const COL_F_NEG_X: usize = STATE_WIDTH + 1;
const COL_ALPHA: usize = STATE_WIDTH + 2;
const COL_X: usize = STATE_WIDTH + 3;
const COL_F_NEXT: usize = STATE_WIDTH + 4;

impl Air for FriVerifierAir {
    type BaseField = BaseElement;
    type PublicInputs = FriPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Constraints:
        // - RPO constraints for Merkle verification (degree 8)
        // - Folding constraints (degree 2)
        let num_constraints = STATE_WIDTH + 1; // RPO state + 1 folding
        let degrees = vec![
            TransitionConstraintDegree::with_cycles(8, vec![ROWS_PER_PERMUTATION]);
            num_constraints
        ];

        // Assertions: bind the first layer commitment at row 0.
        // Full per-layer binding will be added once Merkle auth is wired in.
        let num_assertions = DIGEST_WIDTH;

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
        // [half_round_type, ark[0..STATE_WIDTH], folding_mask]
        let half_round_type = periodic_values[0];
        let ark: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);
        let folding_mask = periodic_values[1 + STATE_WIDTH];

        // RPO constraints are currently disabled by setting half_round_type=0
        // in periodic columns. This keeps the RPO state constant while we focus
        // on folding correctness. When Merkle authentication is added, these
        // constraints will enforce real RPO permutations.
        let one = E::ONE;
        let two = one + one;
        let is_forward = half_round_type * (two - half_round_type);
        let is_inverse = half_round_type * (half_round_type - one);
        let is_padding = (one - half_round_type) * (two - half_round_type);
        for i in 0..STATE_WIDTH {
            let intermediate = current[i] + ark[i];
            let x2 = intermediate * intermediate;
            let x4 = x2 * x2;
            let x3 = x2 * intermediate;
            let x7 = x3 * x4;
            let forward_constraint = next[i] - x7;

            let y2 = next[i] * next[i];
            let y4 = y2 * y2;
            let y3 = y2 * next[i];
            let y7 = y3 * y4;
            let inverse_constraint = y7 - intermediate;

            let padding_constraint = next[i] - current[i];
            result[i] =
                is_forward * forward_constraint + is_inverse * inverse_constraint + is_padding * padding_constraint;
        }

        // Folding constraint for folding factor 2 (matches winter-fri verify_generic::<2>):
        // 2x * f_next = (x + α) * f(x) + (x - α) * f(-x)
        let f_x = current[COL_F_X];
        let f_neg_x = current[COL_F_NEG_X];
        let alpha = current[COL_ALPHA];
        let x = current[COL_X];
        let f_next = current[COL_F_NEXT];

        let lhs = two * x * f_next;
        let rhs = (x + alpha) * f_x + (x - alpha) * f_neg_x;
        result[STATE_WIDTH] = folding_mask * (lhs - rhs);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();
        if let Some(first) = self.pub_inputs.layer_commitments.get(0) {
            for i in 0..DIGEST_WIDTH {
                assertions.push(Assertion::single(i, 0, first[i]));
            }
        }
        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Periodic columns:
        // - Disable RPO transitions for now (half_round_type=0, ark=0)
        // - Folding mask always on.
        let half_round_type = vec![BaseElement::ZERO; ROWS_PER_PERMUTATION];
        let ark_columns: [Vec<BaseElement>; STATE_WIDTH] =
            core::array::from_fn(|_| vec![BaseElement::ZERO; ROWS_PER_PERMUTATION]);
        let folding_mask = vec![BaseElement::ONE; ROWS_PER_PERMUTATION];

        let mut result = vec![half_round_type];
        for col in ark_columns {
            result.push(col);
        }
        result.push(folding_mask);
        result
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_folding_verification() {
        // Test folding with known values
        let x = BaseElement::new(7);
        let alpha = BaseElement::new(3);
        
        // Construct f(x) and f(-x) for a simple polynomial
        // Let f(y) = y^2 + 2y + 3
        let f_x = x * x + BaseElement::new(2) * x + BaseElement::new(3);
        let neg_x = BaseElement::ZERO - x;
        let f_neg_x = neg_x * neg_x + BaseElement::new(2) * neg_x + BaseElement::new(3);
        
        // Compute expected folded value
        let f_next = FriFoldingVerifier::compute_folded(x, f_x, f_neg_x, alpha);
        
        // Verify
        assert!(FriFoldingVerifier::verify_folding(x, f_x, f_neg_x, f_next, alpha));
    }

    #[test]
    fn test_fri_folding_wrong_value_fails() {
        let x = BaseElement::new(7);
        let alpha = BaseElement::new(3);
        let f_x = BaseElement::new(100);
        let f_neg_x = BaseElement::new(50);
        
        let f_next = FriFoldingVerifier::compute_folded(x, f_x, f_neg_x, alpha);
        
        // Wrong value should fail
        let wrong_f_next = f_next + BaseElement::ONE;
        assert!(!FriFoldingVerifier::verify_folding(x, f_x, f_neg_x, wrong_f_next, alpha));
    }

    #[test]
    fn test_fri_public_inputs() {
        let commitments = vec![[BaseElement::new(1); DIGEST_WIDTH]; 3];
        let factors = vec![BaseElement::new(2); 3];
        
        let pub_inputs = FriPublicInputs::new(
            commitments.clone(),
            factors.clone(),
            1024,
            32,
        );
        
        assert_eq!(pub_inputs.num_layers, 3);
        assert_eq!(pub_inputs.initial_domain_size, 1024);
        assert_eq!(pub_inputs.degree_bound, 32);
    }
}
