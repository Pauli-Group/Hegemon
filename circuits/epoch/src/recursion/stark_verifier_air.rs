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
//!
//! ### Column Map (High-Level)
//!
//! The trace is a single wide table where column ranges are allocated contiguously:
//!
//! ```text
//! 0 .. RPO_TRACE_WIDTH-1                       RPO sponge state (+ round counter)
//! RPO_TRACE_WIDTH .. BASE_VERIFIER_TRACE_WIDTH-1   carry/reseed masks + reseed word
//! BASE_VERIFIER_TRACE_WIDTH .. BASE_TRANSCRIPT_TRACE_WIDTH-1
//!     transcript staging (coeff/z/deep/fri/query draws)
//! BASE_TRANSCRIPT_TRACE_WIDTH .. BASE_RECURSION_TRACE_WIDTH-1
//!     query-position decomp + Merkle index + OOD/coeff snapshots
//! BASE_RECURSION_TRACE_WIDTH .. VERIFIER_TRACE_WIDTH-1
//!     DEEP accumulators + FRI remainder checks
//! ```
//!
//! For exact offsets, see the `COL_*` constants below.

use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Word;
use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_crypto::RandomCoin;
use winter_math::{FieldElement, StarkField, ToElements};
use winterfell::math::fields::f64::BaseElement;

use super::fri_air::MAX_FRI_LAYERS;
use super::merkle_air::DIGEST_WIDTH;
use super::rpo_air::{
    ARK1, ARK2, MDS, NUM_ROUNDS, ROWS_PER_PERMUTATION, STATE_WIDTH, TRACE_WIDTH as RPO_TRACE_WIDTH,
};
use winter_air::DeepCompositionCoefficients;

const CAPACITY_WIDTH: usize = 4;
pub(crate) const RATE_WIDTH: usize = 8;
const RATE_START: usize = CAPACITY_WIDTH;

// Trace layout for StarkVerifierAir.
// Columns 0..STATE_WIDTH-1 hold the RPO sponge state, and column STATE_WIDTH is an unused
// round counter (kept for compatibility with shared trace builders).
const ROUND_COL: usize = STATE_WIDTH;
pub(crate) const COL_CARRY_MASK: usize = RPO_TRACE_WIDTH;
pub(crate) const COL_FULL_CARRY_MASK: usize = RPO_TRACE_WIDTH + 1;
pub(crate) const COL_RESEED_MASK: usize = RPO_TRACE_WIDTH + 2;
pub(crate) const COL_COIN_INIT_MASK: usize = RPO_TRACE_WIDTH + 3;
pub(crate) const COL_RESEED_WORD_START: usize = RPO_TRACE_WIDTH + 4;
pub(crate) const BASE_VERIFIER_TRACE_WIDTH: usize = COL_RESEED_WORD_START + DIGEST_WIDTH;
pub(crate) const COL_COEFF_MASK: usize = BASE_VERIFIER_TRACE_WIDTH;
pub(crate) const COL_Z_MASK: usize = BASE_VERIFIER_TRACE_WIDTH + 1;
pub(crate) const COL_COEFF_START: usize = BASE_VERIFIER_TRACE_WIDTH + 2;
pub(crate) const COL_Z_VALUE: usize = COL_COEFF_START + RATE_WIDTH;
pub(crate) const COL_DEEP_MASK: usize = COL_Z_VALUE + 1;
pub(crate) const COL_DEEP_START: usize = COL_DEEP_MASK + 1;
pub(crate) const COL_FRI_MASK: usize = COL_DEEP_START + RATE_WIDTH;
pub(crate) const COL_FRI_ALPHA_VALUE: usize = COL_FRI_MASK + 1;
pub(crate) const COL_POS_MASK: usize = COL_FRI_ALPHA_VALUE + 1;
pub(crate) const COL_POS_START: usize = COL_POS_MASK + 1;
pub(crate) const BASE_TRANSCRIPT_TRACE_WIDTH: usize = COL_POS_START + RATE_WIDTH;
pub(crate) const COL_MERKLE_PATH_BIT: usize = BASE_TRANSCRIPT_TRACE_WIDTH;
// Query-position decomposition / permutation-check segment (true draw_integers modeling).
pub(crate) const COL_POS_DECOMP_MASK: usize = COL_MERKLE_PATH_BIT + 1;
pub(crate) const COL_POS_RAW: usize = COL_POS_DECOMP_MASK + 1;
pub(crate) const COL_POS_BIT0: usize = COL_POS_RAW + 1;
pub(crate) const COL_POS_BIT1: usize = COL_POS_BIT0 + 1;
pub(crate) const COL_POS_BIT2: usize = COL_POS_BIT1 + 1;
pub(crate) const COL_POS_BIT3: usize = COL_POS_BIT2 + 1;
pub(crate) const COL_POS_ACC: usize = COL_POS_BIT3 + 1;
pub(crate) const COL_POS_LO_ACC: usize = COL_POS_ACC + 1;
pub(crate) const COL_POS_MASKED_ACC: usize = COL_POS_LO_ACC + 1;
pub(crate) const COL_POS_HI_AND: usize = COL_POS_MASKED_ACC + 1;
pub(crate) const COL_POS_SORTED_VALUE: usize = COL_POS_HI_AND + 1;
pub(crate) const COL_POS_PERM_ACC: usize = COL_POS_SORTED_VALUE + 1;
pub(crate) const COL_MERKLE_INDEX: usize = COL_POS_PERM_ACC + 1;
// OOD digest and coin-state save/restore columns for true recursion.
pub(crate) const COL_OOD_DIGEST_START: usize = COL_MERKLE_INDEX + 1;
pub(crate) const COL_SAVED_COIN_START: usize = COL_OOD_DIGEST_START + DIGEST_WIDTH;
// Constraint composition coefficients (12 transition + 24 boundary for RpoAir).
pub(crate) const NUM_CONSTRAINT_COEFFS: usize = 36;
pub(crate) const COL_CONSTRAINT_COEFFS_START: usize = COL_SAVED_COIN_START + STATE_WIDTH;
// DEEP coefficients (trace width + constraint composition columns).
pub(crate) const NUM_DEEP_COEFFS: usize = RPO_TRACE_WIDTH + 8;
pub(crate) const COL_DEEP_COEFFS_START: usize = COL_CONSTRAINT_COEFFS_START + NUM_CONSTRAINT_COEFFS;
// FRI folding alphas (max supported; unused slots must be zeroed by the prover).
pub(crate) const COL_FRI_ALPHA_START: usize = COL_DEEP_COEFFS_START + NUM_DEEP_COEFFS;
// OOD evaluation vector hashed into the OOD digest (trace + quotient at z and z*g).
pub(crate) const OOD_EVAL_LEN: usize = 2 * (RPO_TRACE_WIDTH + 8);
pub(crate) const COL_OOD_EVALS_START: usize = COL_FRI_ALPHA_START + MAX_FRI_LAYERS;
pub(crate) const BASE_RECURSION_TRACE_WIDTH: usize = COL_OOD_EVALS_START + OOD_EVAL_LEN;

// --------------------------------------------------------------------
// DEEP + FRI recursion state columns
// --------------------------------------------------------------------
pub(crate) const COL_DEEP_T1_ACC: usize = BASE_RECURSION_TRACE_WIDTH;
pub(crate) const COL_DEEP_T2_ACC: usize = COL_DEEP_T1_ACC + 1;
pub(crate) const COL_DEEP_C1_ACC: usize = COL_DEEP_T2_ACC + 1;
pub(crate) const COL_DEEP_C2_ACC: usize = COL_DEEP_C1_ACC + 1;

pub(crate) const COL_FRI_EVAL: usize = COL_DEEP_C2_ACC + 1;
pub(crate) const COL_FRI_X: usize = COL_FRI_EVAL + 1;
pub(crate) const COL_FRI_POW: usize = COL_FRI_X + 1;

pub(crate) const COL_FRI_MSB_BITS_START: usize = COL_FRI_POW + 1;
pub(crate) const NUM_FRI_MSB_BITS: usize = MAX_FRI_LAYERS;

pub(crate) const COL_REMAINDER_COEFFS_START: usize = COL_FRI_MSB_BITS_START + NUM_FRI_MSB_BITS;
pub(crate) const NUM_REMAINDER_COEFFS: usize = RATE_WIDTH;

pub(crate) const VERIFIER_TRACE_WIDTH: usize = COL_REMAINDER_COEFFS_START + NUM_REMAINDER_COEFFS;

// Fixed context prefix for inner RPO-friendly proofs.
// This currently matches RpoAir proofs with RpoProofOptions::fast().
const CONTEXT_PREFIX_LEN: usize = 8;

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
    /// Number of query draws in the inner proof options (before dedup).
    pub num_draws: usize,
    /// Partition size used for main-trace Merkle leaves.
    pub trace_partition_size: usize,
    /// Partition size used for constraint-evaluation Merkle leaves.
    pub constraint_partition_size: usize,
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
        num_draws: usize,
        trace_partition_size: usize,
        constraint_partition_size: usize,
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
            num_draws,
            trace_partition_size,
            constraint_partition_size,
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
        elements.push(BaseElement::new(self.num_draws as u64));
        elements.push(BaseElement::new(self.trace_partition_size as u64));
        elements.push(BaseElement::new(self.constraint_partition_size as u64));
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
    expected_z: BaseElement,
    g_trace: BaseElement,
    g_lde: BaseElement,
    domain_offset: BaseElement,
    inv_domain_offset: BaseElement,
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

        // Constraints:
        // - RPO permutation constraints for sponge permutations (STATE_WIDTH)
        // - Boundary relations between stacked permutations:
        //   * capacity carryover (4)
        //   * reseed additions / coin-init resets (8)
        //   * mask validity + exclusivity (10)
        //   * constraint coefficient equality checks (8)
        //   * z equality check (1)
        //   * deep composition coefficient equality checks (8)
        //   * FRI alpha equality check (1)
        //   * query draw equality checks (8)
        // - Merkle authentication segment:
        //   * leaf sponge init (capacity width)
        //   * Merkle merge init (capacity width)
        //   * intra-leaf capacity chaining (1)
        //   * Merkle level chaining (digest width)
        //   * path-bit binary (1)
        //   * root checks for trace/constraint/FRI layers (digest width each)
        let num_fri_commitments = pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        assert!(
            num_fri_layers <= MAX_FRI_LAYERS,
            "inner proof requires {num_fri_layers} FRI layers, but verifier supports at most {MAX_FRI_LAYERS}"
        );

        // StarkVerifierAir currently assumes RpoAir-sized leaves and no partitioned (multi-digest)
        // Merkle leaves for trace and constraint openings.
        assert!(
            pub_inputs.trace_partition_size >= RPO_TRACE_WIDTH,
            "trace_partition_size must be >= {RPO_TRACE_WIDTH} (got {})",
            pub_inputs.trace_partition_size
        );
        assert!(
            pub_inputs.constraint_partition_size >= 8,
            "constraint_partition_size must be >= 8 (got {})",
            pub_inputs.constraint_partition_size
        );

        let lde_domain_size = pub_inputs.trace_length * pub_inputs.blowup_factor;
        assert!(
            lde_domain_size.is_power_of_two(),
            "lde_domain_size must be a power of two (trace_length={}, blowup_factor={})",
            pub_inputs.trace_length,
            pub_inputs.blowup_factor
        );
        let depth_trace = lde_domain_size.trailing_zeros() as usize;
        assert!(
            num_fri_layers <= depth_trace,
            "inner proof requires {num_fri_layers} FRI layers but LDE domain has only {depth_trace} bits"
        );

        let g_trace = BaseElement::get_root_of_unity(pub_inputs.trace_length.ilog2());
        let g_lde = BaseElement::get_root_of_unity(lde_domain_size.ilog2());
        let domain_offset = BaseElement::GENERATOR;
        let inv_domain_offset = domain_offset.inv();

        let base_boundary_constraints = 3 * DIGEST_WIDTH + 10 + 3 * RATE_WIDTH + 2;
        let num_root_masks = 2 + num_fri_layers; // trace, constraint, and each committed FRI layer
        let merkle_constraints = 1 // intra-leaf chaining
            + 1 // path-bit binary
            + DIGEST_WIDTH // digest carryover into next permutation
            + 1 // index shift relation (idx_cur = 2*idx_next + bit)
            + num_root_masks // index must be 0 at each root boundary
            + num_root_masks * DIGEST_WIDTH; // root digest checks
                                             // Query-position draw_integers + binding-check constraints.
        const POS_DECOMP_CONSTRAINTS: usize = 32;
        // OOD digest + coin-state save/restore constraints.
        const OOD_STATE_CONSTRAINTS: usize = DIGEST_WIDTH // ood digest constant columns
            + STATE_WIDTH // saved coin-state constant columns
            + OOD_EVAL_LEN // stored OOD evaluation elements
            + OOD_EVAL_LEN // capture OOD evaluation elements at OOD-hash input rows
            + DIGEST_WIDTH // capture digest at end of OOD hash segment
            + STATE_WIDTH // capture coin state at z boundary
            + STATE_WIDTH; // restore coin state (+digest) at deep-start row
                           // Store transcript-drawn coefficients (for later DEEP/FRI checks).
        let transcript_store_constraints = NUM_CONSTRAINT_COEFFS // stored constraint coeffs
            + NUM_DEEP_COEFFS // stored deep coeffs
            + MAX_FRI_LAYERS // stored alphas (max slots)
            + NUM_CONSTRAINT_COEFFS // capture constraint coeffs at draw boundaries
            + NUM_DEEP_COEFFS // capture deep coeffs at draw boundaries
            + num_fri_layers; // capture alphas at draw boundaries

        // DEEP + FRI recursion checks.
        let deep_fri_constraints = NUM_REMAINDER_COEFFS // remainder coefficients are constant
            + NUM_REMAINDER_COEFFS // bind remainder coeff columns to remainder commitment hash
            + 4 // DEEP trace/constraint numerator accumulators
            + 2 // x/pow state machine
            + 1 // eval freeze between FRI leaves
            + num_fri_layers // msb-bit capture state for selection
            + num_fri_layers // per-layer eval selection checks
            + 1 // DEEP composition check (layer 0)
            + num_fri_layers // FRI folding checks
            + (num_fri_layers > 0) as usize; // remainder evaluation check

        let num_constraints = STATE_WIDTH
            + base_boundary_constraints
            + merkle_constraints
            + POS_DECOMP_CONSTRAINTS
            + OOD_STATE_CONSTRAINTS
            + transcript_store_constraints
            + deep_fri_constraints;
        let mut degrees = Vec::with_capacity(num_constraints);

        // RPO transition constraints are gated by two periodic selectors:
        // - half_round_type (permutation schedule)
        // - perm_mask (disable boundary transitions)
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                8,
                vec![
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                ],
            ));
        }

        // Boundary relation constraints are quadratic in trace columns (mask * linear diff)
        // and gated by the periodic boundary mask.
        for _ in 0..base_boundary_constraints {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                vec![ROWS_PER_PERMUTATION],
            ));
        }

        // Merkle authentication constraints.
        //
        // The sparse Merkle selectors often behave like boundary‑gated relations, but the first
        // few constraints (leaf chaining, path‑bit binary, and the first three digest‑carry
        // relations) empirically pick up an extra full‑cycle contribution in Winterfell’s debug
        // degree calculation. We mirror that here to keep debug builds stable.
        let full_cycle = trace_info.length();
        let boundary_and_full = vec![ROWS_PER_PERMUTATION, full_cycle];
        let boundary_only = vec![ROWS_PER_PERMUTATION];

        // Intra‑leaf carry_mask=1 constraint.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_only.clone(),
        ));

        // Path‑bit binary constraint.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_and_full.clone(),
        ));

        // Merkle digest carry‑over constraints (DIGEST_WIDTH).
        for _ in 0..DIGEST_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                boundary_and_full.clone(),
            ));
        }

        // Index shift relation across Merkle merges (linear in trace columns).
        degrees.push(TransitionConstraintDegree::with_cycles(
            1,
            boundary_and_full.clone(),
        ));

        // Root index (must be zero at each root boundary).
        for _ in 0..num_root_masks {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                boundary_only.clone(),
            ));
        }

        // Root digests for trace, constraint, and each committed FRI layer.
        let root_check_constraints = num_root_masks * DIGEST_WIDTH;
        for _ in 0..root_check_constraints {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                boundary_only.clone(),
            ));
        }

        // --- Query position decomposition degrees -------------------------------------------
        // 1) Enforce decomp mask pattern (on/off).
        degrees.push(TransitionConstraintDegree::new(2));
        degrees.push(TransitionConstraintDegree::new(2));

        // 2) Bind gamma used in multiset equality (z challenge).
        degrees.push(TransitionConstraintDegree::new(2));

        // 3) Carry rate buffer into decomp perms (8 cols).
        for _ in 0..RATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                3,
                boundary_only.clone(),
            ));
        }
        // 4) Select raw value from buffer on decomp first row.
        degrees.push(TransitionConstraintDegree::with_cycles(
            3,
            boundary_only.clone(),
        ));

        // 5) Bit boolean constraints (4 bits per row).
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(3));
        }

        // 6) Accumulator init + update + boundary equality.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_only.clone(),
        )); // acc init
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION],
        )); // acc update (perm_mask * weight)
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION],
        )); // acc = raw

        // 7) Low-limb init + update + freeze.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_only.clone(),
        )); // lo init
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![
                ROWS_PER_PERMUTATION,
                ROWS_PER_PERMUTATION,
                ROWS_PER_PERMUTATION,
            ],
        )); // lo update (lo_mask * perm_mask * weight)
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION],
        )); // lo freeze

        // 8) Masked accumulator init + update.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_only.clone(),
        )); // masked init
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION],
        )); // masked update (perm_mask * wmask)

        // 8b) Bind the draw value used by the multiset accumulator to the transcript-derived
        // masked position (low depth bits of the raw draw).
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION],
        ));

        // 9) High-limb AND init + update.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_only.clone(),
        )); // hi init (row8)
        degrees.push(TransitionConstraintDegree::with_cycles(
            6,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION],
        )); // hi update

        // 10) Canonical check hi_max => lo=0.
        degrees.push(TransitionConstraintDegree::with_cycles(
            7,
            boundary_only.clone(),
        ));

        // 11) Binding accumulator init + freeze + updates.
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![full_cycle])); // acc init (pos_first_decomp_mask has full-cycle support)
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_and_full.clone(),
        )); // acc freeze (perm_mask + non-update boundaries)
        degrees.push(TransitionConstraintDegree::with_cycles(
            3,
            boundary_only.clone(),
        )); // acc multiply at decomp boundaries
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            boundary_and_full.clone(),
        )); // acc divide at trace-leaf end boundaries

        // --- OOD digest + coin save/restore degrees ----------------------------------------
        // (a) OOD digest columns are constant across the trace.
        for _ in 0..DIGEST_WIDTH {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (b) Saved coin-state columns are constant across the trace.
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (c) Stored OOD evaluation elements are constant across the trace.
        for _ in 0..OOD_EVAL_LEN {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (d) Capture OOD evaluation elements at the start rows of the OOD-hash segment.
        for _ in 0..OOD_EVAL_LEN {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (e) Capture OOD digest at the end of the OOD-hash segment.
        for _ in 0..DIGEST_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (f) Capture coin state at the z boundary (boundary-gated).
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                boundary_only.clone(),
            ));
        }
        // (g) Restore coin state (+OOD digest) at the first deep-coefficient row.
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }

        // --- Transcript store degrees -------------------------------------------------------
        // (a) Stored constraint composition coefficients are constant across the trace.
        for _ in 0..NUM_CONSTRAINT_COEFFS {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (b) Stored DEEP coefficients are constant across the trace.
        for _ in 0..NUM_DEEP_COEFFS {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (c) Stored FRI alphas are constant across the trace.
        for _ in 0..MAX_FRI_LAYERS {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (d) Capture constraint coefficients at their draw boundaries.
        for _ in 0..NUM_CONSTRAINT_COEFFS {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (e) Capture DEEP coefficients at their draw boundaries.
        for _ in 0..NUM_DEEP_COEFFS {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (f) Capture FRI alphas at their draw boundaries.
        for _ in 0..num_fri_layers {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }

        // --- DEEP + FRI recursion degrees -------------------------------------------------
        // (a) Remainder coefficients are constant across the trace.
        for _ in 0..NUM_REMAINDER_COEFFS {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // (b) Bind remainder coefficients to the remainder commitment hash input rows.
        for _ in 0..NUM_REMAINDER_COEFFS {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }

        // (c) DEEP trace/constraint numerator accumulators.
        // These constraints multiply trace values by stored (constant) coefficients and are gated
        // by sparse periodic row markers. In terms of polynomial degree, the constant columns do
        // not contribute, so the dominant term is linear-in-trace times one periodic mask.
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }

        // (d) x and pow state-machine updates (query reset + trace-index exponentiation + FRI x).
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![full_cycle]));
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![full_cycle]));

        // (e) Evaluation freeze between FRI leaves (disabled on query resets and leaf starts).
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));

        // (f) Capture MSB selection bits from the trace-index Merkle path.
        for _ in 0..num_fri_layers {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }

        // (g) Per-layer evaluation selection checks.
        for _ in 0..num_fri_layers {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![full_cycle]));
        }

        // (h) DEEP composition check (layer 0).
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![full_cycle]));

        // (i) Per-layer FRI folding checks.
        for _ in 0..num_fri_layers {
            degrees.push(TransitionConstraintDegree::with_cycles(3, vec![full_cycle]));
        }

        // (j) Remainder evaluation check.
        if num_fri_layers > 0 {
            // The remainder polynomial has degree <= 7 (8 coefficients), and the check is gated
            // by a sparse root-boundary selector.
            degrees.push(TransitionConstraintDegree::with_cycles(7, vec![full_cycle]));
        }

        debug_assert_eq!(
            degrees.len(),
            num_constraints,
            "degree descriptor count mismatch"
        );

        // Assertions bind:
        // - public-input hash sponge inputs + digest
        // - transcript seed sponge inputs (context prefix + public inputs)
        // - boundary masks and reseed words for the transcript skeleton
        let input_len = pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(RATE_WIDTH).max(1);

        let seed_len = CONTEXT_PREFIX_LEN + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);

        let mut num_assertions = 0usize;
        // public-input hash sponge
        num_assertions += CAPACITY_WIDTH;
        num_assertions += num_pi_blocks * RATE_WIDTH;
        num_assertions += DIGEST_WIDTH;

        // seed sponge
        num_assertions += CAPACITY_WIDTH;
        num_assertions += num_seed_blocks * RATE_WIDTH;

        // boundary masks for pi blocks (between blocks + reset boundary)
        if num_pi_blocks > 1 {
            num_assertions += (num_pi_blocks - 1) * 4;
        }
        num_assertions += 4; // reset boundary between pi-hash and seed-hash

        // boundary masks for seed blocks (between blocks + coin-init boundary)
        if num_seed_blocks > 1 {
            num_assertions += (num_seed_blocks - 1) * 4;
        }
        num_assertions += 4; // coin-init boundary

        // reseed(trace_commitment) boundary masks + reseed word
        num_assertions += 4 + DIGEST_WIDTH;

        // full-carry boundaries between coefficient draw permutations
        let num_coeff_perms = 36usize.div_ceil(RATE_WIDTH);
        if num_coeff_perms > 1 {
            num_assertions += (num_coeff_perms - 1) * 4;
        }

        // reseed(constraint_commitment) boundary masks + reseed word
        num_assertions += 4 + DIGEST_WIDTH;

        // z-draw boundary masks after constraint reseed permutation
        num_assertions += 4;

        // OOD evaluation digest sponge (Rpo256::hash_elements over merged OOD evaluations).
        //
        // For RpoAir (main trace width = RPO_TRACE_WIDTH, composition columns = 8), the merged
        // OOD evaluation vector has fixed length:
        //   len = (trace_z + quot_z + trace_zg + quot_zg) = 2 * (RPO_TRACE_WIDTH + 8)
        let ood_eval_len = 2 * (RPO_TRACE_WIDTH + 8);
        let num_ood_perms = ood_eval_len.div_ceil(RATE_WIDTH);
        num_assertions += CAPACITY_WIDTH; // sponge init at start of OOD hash segment
        if num_ood_perms > 0 {
            num_assertions += num_ood_perms * 4; // carry/reset masks for each OOD hash perm
        }

        // Deep coefficient draw boundaries after OOD reseed.
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8; // trace_width + num_constraint_comp_cols (8)
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);
        num_assertions += num_deep_perms * 4;

        // FRI alpha boundaries and remainder boundary.
        let num_fri_commitments = pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let num_fri_alpha_perms = num_fri_layers;
        let num_remainder_perms = (num_fri_commitments > 0) as usize;
        // Reseed with the first FRI commitment after the last DEEP permutation.
        if num_fri_commitments > 0 {
            num_assertions += DIGEST_WIDTH;
        }
        num_assertions += num_fri_alpha_perms * (4 + DIGEST_WIDTH);
        num_assertions += num_remainder_perms * 4;

        // Query position draw boundaries after FRI remainder.
        // `draw_integers` skips the first rate element after nonce absorption,
        // so the number of permutations is ceil((q + 1) / RATE_WIDTH).
        let num_pos_perms = if pub_inputs.num_draws == 0 {
            0
        } else {
            (pub_inputs.num_draws + 1).div_ceil(RATE_WIDTH)
        };
        if num_pos_perms > 0 {
            num_assertions += num_pos_perms * 4;
        }

        // Stage mask assertions (coeff_mask, z_mask, deep_mask, fri_mask, pos_mask) on every boundary we fix.
        // Boundaries:
        // - pi hash blocks: num_pi_blocks
        // - seed hash blocks: num_seed_blocks
        // - trace reseed boundary: 1
        // - coefficient boundaries: num_coeff_perms
        // - z-draw + OOD-reseed boundary: 1
        // - deep coefficient boundaries: num_deep_perms
        // - FRI alpha boundaries: num_fri_alpha_perms
        // - remainder boundary: num_remainder_perms
        // - query draw boundaries: num_pos_perms
        let stage_boundaries = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_remainder_perms
            + num_pos_perms
            + 2;
        num_assertions += stage_boundaries * 5;

        // Merkle init assertions (leaf/merge capacity) when the Merkle segment is present.
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_alpha_perms
            + num_remainder_perms
            + num_pos_perms
            + 2;
        let num_pos_decomp_perms = pub_inputs.num_draws;
        let pre_merkle_perms = transcript_perms + num_pos_decomp_perms;
        let total_perms = trace_info.length() / ROWS_PER_PERMUTATION;

        let lde_domain_size = pub_inputs.trace_length * pub_inputs.blowup_factor;
        let depth_trace = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };

        let trace_leaf_blocks = RPO_TRACE_WIDTH.div_ceil(RATE_WIDTH).max(1);
        let constraint_leaf_blocks = 8usize.div_ceil(RATE_WIDTH).max(1);
        let fri_leaf_blocks = 2usize.div_ceil(RATE_WIDTH).max(1);
        let mut merkle_perms_per_query =
            trace_leaf_blocks + depth_trace + constraint_leaf_blocks + depth_trace;
        for layer_idx in 0..num_fri_layers {
            merkle_perms_per_query += fri_leaf_blocks + depth_trace.saturating_sub(layer_idx + 1);
        }
        let expected_active_perms =
            pre_merkle_perms + pub_inputs.num_queries * merkle_perms_per_query;

        if expected_active_perms <= total_perms {
            let leaf_starts_per_query = 2 + num_fri_layers;
            num_assertions += pub_inputs.num_queries * leaf_starts_per_query * CAPACITY_WIDTH;

            let mut merges_per_query = 2 * depth_trace;
            for layer_idx in 0..num_fri_layers {
                merges_per_query += depth_trace.saturating_sub(layer_idx + 1);
            }
            num_assertions += pub_inputs.num_queries * merges_per_query * CAPACITY_WIDTH;
        }

        // Remainder polynomial commitment hash (hash remainder coeffs -> remainder commitment).
        // For RpoAir inner proofs with `fri_remainder_max_degree=7`, the remainder polynomial has
        // 8 coefficients and is hashed in a single RPO permutation.
        let remainder_hash_perms = (pub_inputs.fri_commitments.len() > 0) as usize;
        if remainder_hash_perms > 0 && expected_active_perms + remainder_hash_perms <= total_perms {
            num_assertions += CAPACITY_WIDTH; // sponge init
            num_assertions += DIGEST_WIDTH; // digest == remainder commitment
        }

        // Binding accumulator must end at 1.
        num_assertions += 1;

        let expected_z = compute_expected_z(&pub_inputs);
        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self {
            context,
            pub_inputs,
            expected_z,
            g_trace,
            g_lde,
            domain_offset,
            inv_domain_offset,
        }
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
        // [half_round_type, ark[0..STATE_WIDTH], perm_mask,
        //  pos_w_full[0..4], pos_w_masked[0..4], pos_lo_mask, pos_hi_mask, pos_hi_first_mask,
        //  pos_first_row_mask, pos_decomp_row_mask, pos_first_decomp_mask, pos_last_decomp_mask,
        //  pos_rate_sel[0..RATE_WIDTH],
        //  leaf_chain_mask, merkle_chain_mask, trace_leaf_end_mask,
        //  trace_root_mask, constraint_root_mask, fri_root_masks...,
        //  ood_digest_capture_mask, ood_eval_row_masks..., deep_start_row_mask,
        //  coeff_end_masks..., deep_end_masks..., fri_alpha_end_masks...,
        //  query_reset_mask, trace_leaf0_row_mask, trace_leaf1_row_mask, constraint_leaf_row_mask,
        //  trace_merkle_bit_mask, msb_capture_masks..., fri_leaf_row_masks..., remainder_hash_row0]
        let half_round_type = periodic_values[0];
        let ark: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[1 + i]);

        let base_offset = 1 + STATE_WIDTH;
        let perm_mask = periodic_values[base_offset];
        let boundary_mask = E::ONE - perm_mask;

        let mut p = base_offset + 1;

        let pos_w_full: [E; 4] = core::array::from_fn(|i| periodic_values[p + i]);
        p += 4;
        let pos_w_masked: [E; 4] = core::array::from_fn(|i| periodic_values[p + i]);
        p += 4;
        let pos_lo_mask = periodic_values[p];
        p += 1;
        let pos_hi_mask = periodic_values[p];
        p += 1;
        let pos_hi_first_mask = periodic_values[p];
        p += 1;
        let pos_first_row_mask = periodic_values[p];
        p += 1;
        let pos_decomp_row_mask = periodic_values[p];
        p += 1;
        let pos_first_decomp_mask = periodic_values[p];
        p += 1;
        let _pos_last_decomp_mask = periodic_values[p];
        p += 1;
        let pos_rate_sel = &periodic_values[p..p + RATE_WIDTH];
        p += RATE_WIDTH;

        let leaf_chain_mask = periodic_values[p];
        p += 1;
        let merkle_chain_mask = periodic_values[p];
        p += 1;
        let trace_leaf_end_mask = periodic_values[p];
        p += 1;
        let trace_root_mask = periodic_values[p];
        p += 1;
        let constraint_root_mask = periodic_values[p];
        p += 1;
        let num_fri_layers = self.pub_inputs.fri_commitments.len().saturating_sub(1);
        let fri_root_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let ood_digest_capture_mask = periodic_values[p];
        p += 1;
        let num_ood_perms = OOD_EVAL_LEN.div_ceil(RATE_WIDTH);
        let ood_eval_row_masks = &periodic_values[p..p + num_ood_perms];
        p += num_ood_perms;
        let deep_start_row_mask = periodic_values[p];
        p += 1;
        let num_coeff_perms = NUM_CONSTRAINT_COEFFS.div_ceil(RATE_WIDTH);
        let coeff_end_masks = &periodic_values[p..p + num_coeff_perms];
        p += num_coeff_perms;
        let num_deep_perms = NUM_DEEP_COEFFS.div_ceil(RATE_WIDTH);
        let deep_end_masks = &periodic_values[p..p + num_deep_perms];
        p += num_deep_perms;
        let fri_alpha_end_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;

        // --- DEEP + FRI periodic selectors ------------------------------------------------
        let query_reset_mask = periodic_values[p];
        p += 1;
        let trace_leaf0_row_mask = periodic_values[p];
        p += 1;
        let trace_leaf1_row_mask = periodic_values[p];
        p += 1;
        let constraint_leaf_row_mask = periodic_values[p];
        p += 1;
        let trace_merkle_bit_mask = periodic_values[p];
        p += 1;
        let msb_capture_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let fri_leaf_row_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let fri_leaf_any_row_mask = periodic_values[p];
        p += 1;
        let remainder_hash_row0_mask = periodic_values[p];
        p += 1;

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
        let decomp_mask_rpo = current[COL_POS_DECOMP_MASK];
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

            // During query-position decomposition perms we freeze the RPO state so that
            // transcript continuity is preserved across the inserted rows.
            let freeze_constraint = next[i] - current[i];

            // Disable RPO constraints at permutation boundaries; switch to freeze constraints
            // when decomp_mask_rpo = 1.
            result[i] = perm_mask
                * ((one - decomp_mask_rpo) * rpo_constraint + decomp_mask_rpo * freeze_constraint);
        }

        // Boundary relations between stacked permutations.
        let carry_mask = current[COL_CARRY_MASK];
        let full_carry_mask = current[COL_FULL_CARRY_MASK];
        let reseed_mask = current[COL_RESEED_MASK];
        let coin_init_mask = current[COL_COIN_INIT_MASK];
        let reseed_word: [E; DIGEST_WIDTH] =
            core::array::from_fn(|i| current[COL_RESEED_WORD_START + i]);

        let mut idx = STATE_WIDTH;
        for i in 0..DIGEST_WIDTH {
            // Capacity carryover for carry/full-carry/reseed; zero for coin-init.
            let carry_sum = carry_mask + full_carry_mask + reseed_mask;
            let cap_rel = carry_sum * (next[i] - current[i]) + coin_init_mask * next[i];
            result[idx + i] = boundary_mask * cap_rel;
        }
        idx += DIGEST_WIDTH;

        for i in 0..DIGEST_WIDTH {
            // First half of rate:
            // - full-carry copies full state
            // - reseed adds a word
            // - coin-init copies digest range
            // - carry/free boundaries impose no constraint
            let cur_rate = current[RATE_START + i];
            let next_rate = next[RATE_START + i];
            let rate_rel = (full_carry_mask + coin_init_mask) * (next_rate - cur_rate)
                + reseed_mask * (next_rate - (cur_rate + reseed_word[i]));
            result[idx + i] = boundary_mask * rate_rel;
        }
        idx += DIGEST_WIDTH;

        for i in 0..DIGEST_WIDTH {
            // Second half of rate:
            // - full-carry/reseed copy
            // - coin-init zeros
            // - carry/free boundaries impose no constraint
            let cur_rate = current[RATE_START + DIGEST_WIDTH + i];
            let next_rate = next[RATE_START + DIGEST_WIDTH + i];
            let rate_rel = (full_carry_mask + reseed_mask) * (next_rate - cur_rate)
                + coin_init_mask * next_rate;
            result[idx + i] = boundary_mask * rate_rel;
        }
        idx += DIGEST_WIDTH;

        // Mask validity (binary on boundaries).
        result[idx] = boundary_mask * carry_mask * (carry_mask - one);
        result[idx + 1] = boundary_mask * full_carry_mask * (full_carry_mask - one);
        result[idx + 2] = boundary_mask * reseed_mask * (reseed_mask - one);
        result[idx + 3] = boundary_mask * coin_init_mask * (coin_init_mask - one);
        idx += 4;

        // Exclusivity of masks on boundaries.
        result[idx] = boundary_mask * carry_mask * full_carry_mask;
        result[idx + 1] = boundary_mask * carry_mask * reseed_mask;
        result[idx + 2] = boundary_mask * carry_mask * coin_init_mask;
        result[idx + 3] = boundary_mask * full_carry_mask * reseed_mask;
        result[idx + 4] = boundary_mask * full_carry_mask * coin_init_mask;
        result[idx + 5] = boundary_mask * reseed_mask * coin_init_mask;

        idx += 6;

        // Transcript-derived value checks.
        let coeff_mask = current[COL_COEFF_MASK];
        let z_mask = current[COL_Z_MASK];

        for i in 0..RATE_WIDTH {
            let expected = current[COL_COEFF_START + i];
            result[idx + i] = boundary_mask * coeff_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        let expected_z = current[COL_Z_VALUE];
        result[idx] = boundary_mask * z_mask * (current[RATE_START] - expected_z);
        idx += 1;

        let deep_mask = current[COL_DEEP_MASK];
        for i in 0..RATE_WIDTH {
            let expected = current[COL_DEEP_START + i];
            result[idx + i] = boundary_mask * deep_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        let fri_mask = current[COL_FRI_MASK];
        let expected_alpha = current[COL_FRI_ALPHA_VALUE];
        result[idx] = boundary_mask * fri_mask * (current[RATE_START] - expected_alpha);
        idx += 1;

        let pos_mask = current[COL_POS_MASK];
        for i in 0..RATE_WIDTH {
            let expected = current[COL_POS_START + i];
            result[idx + i] = boundary_mask * pos_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        // --------------------------------------------------------------------
        // Merkle authentication segment
        // --------------------------------------------------------------------

        // Intra-leaf chaining: enforce carry_mask=1 on boundaries between sponge blocks.
        result[idx] = boundary_mask * leaf_chain_mask * (carry_mask - one);
        idx += 1;

        // Merkle level chaining uses a per-permutation path bit.
        let path_bit = current[COL_MERKLE_PATH_BIT];
        result[idx] = boundary_mask * merkle_chain_mask * path_bit * (path_bit - one);
        idx += 1;

        for i in 0..DIGEST_WIDTH {
            // Previous digest is in the first half of the rate (columns 4..7).
            let prev_digest = current[CAPACITY_WIDTH + i];
            let next_left = next[CAPACITY_WIDTH + i];
            let next_right = next[CAPACITY_WIDTH + DIGEST_WIDTH + i];

            let left_constraint = next_left - prev_digest;
            let right_constraint = next_right - prev_digest;

            result[idx + i] = boundary_mask
                * merkle_chain_mask
                * ((one - path_bit) * left_constraint + path_bit * right_constraint);
        }
        idx += DIGEST_WIDTH;

        // Bind the Merkle path-bit stream to the leaf index via the shift relation:
        // idx_cur = 2*idx_next + bit (bit is the least-significant bit of idx_cur).
        let merkle_idx = current[COL_MERKLE_INDEX];
        let merkle_idx_next = next[COL_MERKLE_INDEX];
        result[idx] =
            boundary_mask * merkle_chain_mask * (merkle_idx - (merkle_idx_next * two + path_bit));
        idx += 1;

        // The index must be fully shifted out (== 0) at each root boundary.
        result[idx] = boundary_mask * trace_root_mask * merkle_idx;
        idx += 1;
        result[idx] = boundary_mask * constraint_root_mask * merkle_idx;
        idx += 1;
        for (layer_idx, root_mask) in fri_root_masks.iter().enumerate() {
            if layer_idx >= self.pub_inputs.fri_commitments.len().saturating_sub(1) {
                break;
            }
            result[idx] = boundary_mask * (*root_mask) * merkle_idx;
            idx += 1;
        }

        // Root checks at the end of each authenticated path.
        for i in 0..DIGEST_WIDTH {
            let digest = current[CAPACITY_WIDTH + i];
            let trace_root = E::from(self.pub_inputs.trace_commitment[i]);
            result[idx + i] = boundary_mask * trace_root_mask * (digest - trace_root);
        }
        idx += DIGEST_WIDTH;

        for i in 0..DIGEST_WIDTH {
            let digest = current[CAPACITY_WIDTH + i];
            let constraint_root = E::from(self.pub_inputs.constraint_commitment[i]);
            result[idx + i] = boundary_mask * constraint_root_mask * (digest - constraint_root);
        }
        idx += DIGEST_WIDTH;

        for (layer_idx, root_mask) in fri_root_masks.iter().enumerate() {
            if layer_idx >= self.pub_inputs.fri_commitments.len().saturating_sub(1) {
                break;
            }
            let expected_root = self.pub_inputs.fri_commitments[layer_idx];
            for i in 0..DIGEST_WIDTH {
                let digest = current[CAPACITY_WIDTH + i];
                let root = E::from(expected_root[i]);
                result[idx + i] = boundary_mask * (*root_mask) * (digest - root);
            }
            idx += DIGEST_WIDTH;
        }

        // --------------------------------------------------------------------
        // Query position decomposition / permutation check
        // --------------------------------------------------------------------

        let decomp_mask = current[COL_POS_DECOMP_MASK];
        let decomp_mask_next = next[COL_POS_DECOMP_MASK];

        // (0) Enforce the periodic decomp mask schedule.
        result[idx] = pos_decomp_row_mask * (decomp_mask - one);
        idx += 1;
        result[idx] = (one - pos_decomp_row_mask) * decomp_mask;
        idx += 1;

        // Bind gamma used in multiset equality to the z challenge derived from transcript.
        let expected_gamma = E::from(self.expected_z);
        result[idx] = decomp_mask * (current[COL_Z_VALUE] - expected_gamma);
        idx += 1;

        // (1) Carry the rate buffer (COL_POS_START) from the latest pos-draw into all decomp perms.
        let carry_src = pos_mask + decomp_mask;
        for j in 0..RATE_WIDTH {
            result[idx + j] = boundary_mask
                * decomp_mask_next
                * carry_src
                * (next[COL_POS_START + j] - current[COL_POS_START + j]);
        }
        idx += RATE_WIDTH;

        // Select raw value for this decomp perm from the carried buffer.
        let mut expected_raw = E::ZERO;
        for j in 0..RATE_WIDTH {
            expected_raw += pos_rate_sel[j] * current[COL_POS_START + j];
        }
        let raw = current[COL_POS_RAW];
        result[idx] = decomp_mask * pos_first_row_mask * (raw - expected_raw);
        idx += 1;

        // Bits for nibble decomposition (4 bits per row).
        let b0 = current[COL_POS_BIT0];
        let b1 = current[COL_POS_BIT1];
        let b2 = current[COL_POS_BIT2];
        let b3 = current[COL_POS_BIT3];

        // (2) Booleanity of bits.
        result[idx] = decomp_mask * b0 * (b0 - one);
        result[idx + 1] = decomp_mask * b1 * (b1 - one);
        result[idx + 2] = decomp_mask * b2 * (b2 - one);
        result[idx + 3] = decomp_mask * b3 * (b3 - one);
        idx += 4;

        // (3) Full 64-bit accumulator init/update/boundary.
        let acc = current[COL_POS_ACC];
        let acc_next = next[COL_POS_ACC];
        result[idx] = decomp_mask * pos_first_row_mask * acc;
        idx += 1;

        let acc_update = acc_next
            - (acc
                + b0 * pos_w_full[0]
                + b1 * pos_w_full[1]
                + b2 * pos_w_full[2]
                + b3 * pos_w_full[3]);
        result[idx] = decomp_mask * perm_mask * acc_update;
        idx += 1;

        // At the boundary row, `acc` has not yet absorbed the last nibble (row 15),
        // so compare `acc_final` against `raw`.
        let acc_final =
            acc + b0 * pos_w_full[0] + b1 * pos_w_full[1] + b2 * pos_w_full[2] + b3 * pos_w_full[3];
        result[idx] = decomp_mask * boundary_mask * (acc_final - raw);
        idx += 1;

        // (4) Low-limb (32-bit) accumulator.
        let lo = current[COL_POS_LO_ACC];
        let lo_next = next[COL_POS_LO_ACC];
        result[idx] = decomp_mask * pos_first_row_mask * lo;
        idx += 1;

        let lo_update = lo_next
            - (lo
                + b0 * pos_w_full[0]
                + b1 * pos_w_full[1]
                + b2 * pos_w_full[2]
                + b3 * pos_w_full[3]);
        result[idx] = decomp_mask * pos_lo_mask * perm_mask * lo_update;
        idx += 1;
        result[idx] = decomp_mask * (one - pos_lo_mask) * perm_mask * (lo_next - lo);
        idx += 1;

        // (5) Masked accumulator (low `depth_trace` bits).
        let masked = current[COL_POS_MASKED_ACC];
        let masked_next = next[COL_POS_MASKED_ACC];
        result[idx] = decomp_mask * pos_first_row_mask * masked;
        idx += 1;

        let masked_update = masked_next
            - (masked
                + b0 * pos_w_masked[0]
                + b1 * pos_w_masked[1]
                + b2 * pos_w_masked[2]
                + b3 * pos_w_masked[3]);
        result[idx] = decomp_mask * perm_mask * masked_update;
        idx += 1;

        // (5b) Bind the multiset-draw value to the masked raw draw at the decomp boundary.
        // This prevents the prover from choosing `COL_POS_SORTED_VALUE` independently from the
        // transcript-derived query draw.
        let draw_val = current[COL_POS_SORTED_VALUE];
        let masked_final = masked
            + b0 * pos_w_masked[0]
            + b1 * pos_w_masked[1]
            + b2 * pos_w_masked[2]
            + b3 * pos_w_masked[3];
        result[idx] = decomp_mask * boundary_mask * (draw_val - masked_final);
        idx += 1;

        // (6) High-limb AND (hi == 2^32-1).
        let hi_and = current[COL_POS_HI_AND];
        let hi_and_next = next[COL_POS_HI_AND];
        result[idx] = decomp_mask * pos_hi_first_mask * (hi_and - one);
        idx += 1;

        let nibble_prod = b0 * b1 * b2 * b3;
        let hi_update = hi_and_next - hi_and * nibble_prod;
        result[idx] = decomp_mask * pos_hi_mask * perm_mask * hi_update;
        idx += 1;

        // (7) Canonical Goldilocks encoding: if hi all-ones then lo must be zero.
        // hi_and has absorbed nibbles 8..14; include nibble_prod of row 15 here.
        result[idx] = decomp_mask * boundary_mask * hi_and * nibble_prod * lo;
        idx += 1;

        // (8) Bind transcript-derived query draws to Merkle indexes used for trace-leaf
        // authentication by maintaining a grand-product accumulator:
        //
        //   acc <- acc * (draw + gamma)             at each decomp boundary
        //   acc <- acc / (trace_index + gamma)      at each trace-leaf hashing end boundary
        //
        // and asserting `acc == 1` at the end of the trace.
        let perm_acc = current[COL_POS_PERM_ACC];
        let perm_acc_next = next[COL_POS_PERM_ACC];
        let gamma = expected_gamma;
        let trace_idx = current[COL_MERKLE_INDEX];

        // Initialize accumulator at the first decomp row.
        result[idx] = decomp_mask * pos_first_decomp_mask * (perm_acc - one);
        idx += 1;

        // Freeze accumulator everywhere except update boundaries.
        let freeze_sel =
            perm_mask + boundary_mask * (one - decomp_mask) * (one - trace_leaf_end_mask);
        result[idx] = freeze_sel * (perm_acc_next - perm_acc);
        idx += 1;

        // Multiply by the transcript-derived draw at each decomp boundary.
        let decomp_update = perm_acc_next - perm_acc * (draw_val + gamma);
        result[idx] = boundary_mask * decomp_mask * decomp_update;
        idx += 1;

        // Divide by the Merkle index at the end of each trace-leaf hashing segment.
        let leaf_update = (trace_idx + gamma) * perm_acc_next - perm_acc;
        result[idx] = boundary_mask * trace_leaf_end_mask * leaf_update;
        idx += 1;

        // --------------------------------------------------------------------
        // OOD digest + coin-state save/restore
        // --------------------------------------------------------------------

        // OOD digest columns are constant across the trace.
        for i in 0..DIGEST_WIDTH {
            result[idx + i] = next[COL_OOD_DIGEST_START + i] - current[COL_OOD_DIGEST_START + i];
        }
        idx += DIGEST_WIDTH;

        // Saved coin-state columns are constant across the trace.
        for i in 0..STATE_WIDTH {
            result[idx + i] = next[COL_SAVED_COIN_START + i] - current[COL_SAVED_COIN_START + i];
        }
        idx += STATE_WIDTH;

        // OOD evaluation columns are constant across the trace.
        for i in 0..OOD_EVAL_LEN {
            result[idx + i] = next[COL_OOD_EVALS_START + i] - current[COL_OOD_EVALS_START + i];
        }
        idx += OOD_EVAL_LEN;

        // Capture OOD evaluation values at the start of each OOD-hash permutation.
        for i in 0..OOD_EVAL_LEN {
            let block = i / RATE_WIDTH;
            let offset = i % RATE_WIDTH;
            let mask = ood_eval_row_masks[block];
            let stored = current[COL_OOD_EVALS_START + i];
            let input_val = current[RATE_START + offset];
            result[idx + i] = mask * (stored - input_val);
        }
        idx += OOD_EVAL_LEN;

        // Capture the OOD digest at the end of the OOD-hash segment (digest is in the first
        // half of the rate: state[4..7]).
        for i in 0..DIGEST_WIDTH {
            let digest_col = current[COL_OOD_DIGEST_START + i];
            let digest_out = current[RATE_START + i];
            result[idx + i] = ood_digest_capture_mask * (digest_col - digest_out);
        }
        idx += DIGEST_WIDTH;

        // Capture coin state at the z boundary row so it can be restored after hashing OOD
        // evaluations. This is enforced only at the permutation boundary where `z_mask = 1`.
        for i in 0..STATE_WIDTH {
            let saved = current[COL_SAVED_COIN_START + i];
            result[idx + i] = boundary_mask * z_mask * (saved - current[i]);
        }
        idx += STATE_WIDTH;

        // Restore the coin state (and apply the OOD reseed) at the first row of the deep
        // coefficient segment.
        //
        // For a reseed, the first half of the rate (state[4..7]) is incremented by the digest,
        // while the rest of the state is preserved.
        for i in 0..CAPACITY_WIDTH {
            let saved = current[COL_SAVED_COIN_START + i];
            result[idx + i] = deep_start_row_mask * (current[i] - saved);
        }
        for i in 0..DIGEST_WIDTH {
            let saved = current[COL_SAVED_COIN_START + RATE_START + i];
            let digest = current[COL_OOD_DIGEST_START + i];
            let expected = saved + digest;
            result[idx + CAPACITY_WIDTH + i] =
                deep_start_row_mask * (current[RATE_START + i] - expected);
        }
        for i in 0..DIGEST_WIDTH {
            let saved = current[COL_SAVED_COIN_START + RATE_START + DIGEST_WIDTH + i];
            result[idx + CAPACITY_WIDTH + DIGEST_WIDTH + i] =
                deep_start_row_mask * (current[RATE_START + DIGEST_WIDTH + i] - saved);
        }
        idx += STATE_WIDTH;

        // --------------------------------------------------------------------
        // Transcript store: persist coeffs / deep coeffs / alphas
        // --------------------------------------------------------------------

        // Stored constraint composition coefficients are constant across the trace.
        for i in 0..NUM_CONSTRAINT_COEFFS {
            result[idx + i] =
                next[COL_CONSTRAINT_COEFFS_START + i] - current[COL_CONSTRAINT_COEFFS_START + i];
        }
        idx += NUM_CONSTRAINT_COEFFS;

        // Stored DEEP coefficients are constant across the trace.
        for i in 0..NUM_DEEP_COEFFS {
            result[idx + i] = next[COL_DEEP_COEFFS_START + i] - current[COL_DEEP_COEFFS_START + i];
        }
        idx += NUM_DEEP_COEFFS;

        // Stored FRI alphas are constant across the trace (unused slots are ignored).
        for i in 0..MAX_FRI_LAYERS {
            result[idx + i] = next[COL_FRI_ALPHA_START + i] - current[COL_FRI_ALPHA_START + i];
        }
        idx += MAX_FRI_LAYERS;

        // Capture constraint composition coefficients at their draw boundaries.
        for coeff_idx in 0..NUM_CONSTRAINT_COEFFS {
            let block = coeff_idx / RATE_WIDTH;
            let offset = coeff_idx % RATE_WIDTH;
            let mask = coeff_end_masks[block];
            let stored = current[COL_CONSTRAINT_COEFFS_START + coeff_idx];
            let drawn = current[RATE_START + offset];
            result[idx + coeff_idx] = mask * (stored - drawn);
        }
        idx += NUM_CONSTRAINT_COEFFS;

        // Capture DEEP coefficients at their draw boundaries.
        for deep_idx in 0..NUM_DEEP_COEFFS {
            let block = deep_idx / RATE_WIDTH;
            let offset = deep_idx % RATE_WIDTH;
            let mask = deep_end_masks[block];
            let stored = current[COL_DEEP_COEFFS_START + deep_idx];
            let drawn = current[RATE_START + offset];
            result[idx + deep_idx] = mask * (stored - drawn);
        }
        idx += NUM_DEEP_COEFFS;

        // Capture FRI alphas at their draw boundaries.
        for layer_idx in 0..num_fri_layers {
            let mask = fri_alpha_end_masks[layer_idx];
            let stored = current[COL_FRI_ALPHA_START + layer_idx];
            let drawn = current[RATE_START];
            result[idx + layer_idx] = mask * (stored - drawn);
        }
        idx += num_fri_layers;

        // --------------------------------------------------------------------
        // DEEP + FRI recursion state-machine
        // --------------------------------------------------------------------

        // Remainder coefficients are constant across the trace.
        for i in 0..NUM_REMAINDER_COEFFS {
            result[idx + i] =
                next[COL_REMAINDER_COEFFS_START + i] - current[COL_REMAINDER_COEFFS_START + i];
        }
        idx += NUM_REMAINDER_COEFFS;

        // Bind remainder coefficients to the remainder commitment hash input rows.
        for i in 0..NUM_REMAINDER_COEFFS {
            let coeff = current[COL_REMAINDER_COEFFS_START + i];
            result[idx + i] = remainder_hash_row0_mask * (current[RATE_START + i] - coeff);
        }
        idx += NUM_REMAINDER_COEFFS;

        // --- DEEP numerator accumulators -------------------------------------------------
        let t1 = current[COL_DEEP_T1_ACC];
        let t2 = current[COL_DEEP_T2_ACC];
        let c1 = current[COL_DEEP_C1_ACC];
        let c2 = current[COL_DEEP_C2_ACC];

        let t1_next = next[COL_DEEP_T1_ACC];
        let t2_next = next[COL_DEEP_T2_ACC];
        let c1_next = next[COL_DEEP_C1_ACC];
        let c2_next = next[COL_DEEP_C2_ACC];

        let mut t1_delta0 = E::ZERO;
        let mut t2_delta0 = E::ZERO;
        for j in 0..RATE_WIDTH {
            let coeff = current[COL_DEEP_COEFFS_START + j];
            let trace_val = current[RATE_START + j];
            let ood_z = current[COL_OOD_EVALS_START + j];
            let ood_zg = current[COL_OOD_EVALS_START + (RPO_TRACE_WIDTH + 8) + j];
            t1_delta0 += coeff * (trace_val - ood_z);
            t2_delta0 += coeff * (trace_val - ood_zg);
        }

        let mut t1_delta1 = E::ZERO;
        let mut t2_delta1 = E::ZERO;
        for j in 0..(RPO_TRACE_WIDTH - RATE_WIDTH) {
            let coeff = current[COL_DEEP_COEFFS_START + RATE_WIDTH + j];
            let trace_val = current[RATE_START + j];
            let ood_z = current[COL_OOD_EVALS_START + RATE_WIDTH + j];
            let ood_zg = current[COL_OOD_EVALS_START + (RPO_TRACE_WIDTH + 8) + RATE_WIDTH + j];
            t1_delta1 += coeff * (trace_val - ood_z);
            t2_delta1 += coeff * (trace_val - ood_zg);
        }

        let mut c1_delta = E::ZERO;
        let mut c2_delta = E::ZERO;
        for j in 0..8usize {
            let coeff = current[COL_DEEP_COEFFS_START + RPO_TRACE_WIDTH + j];
            let val = current[RATE_START + j];
            let ood_z = current[COL_OOD_EVALS_START + RPO_TRACE_WIDTH + j];
            let ood_zg = current[COL_OOD_EVALS_START + (RPO_TRACE_WIDTH + 8) + RPO_TRACE_WIDTH + j];
            c1_delta += coeff * (val - ood_z);
            c2_delta += coeff * (val - ood_zg);
        }

        let reset_term_t1 = query_reset_mask * (E::ZERO - t1);
        let reset_term_t2 = query_reset_mask * (E::ZERO - t2);
        let reset_term_c1 = query_reset_mask * (E::ZERO - c1);
        let reset_term_c2 = query_reset_mask * (E::ZERO - c2);

        result[idx] = t1_next
            - t1
            - reset_term_t1
            - trace_leaf0_row_mask * t1_delta0
            - trace_leaf1_row_mask * t1_delta1;
        result[idx + 1] = t2_next
            - t2
            - reset_term_t2
            - trace_leaf0_row_mask * t2_delta0
            - trace_leaf1_row_mask * t2_delta1;
        result[idx + 2] = c1_next - c1 - reset_term_c1 - constraint_leaf_row_mask * c1_delta;
        result[idx + 3] = c2_next - c2 - reset_term_c2 - constraint_leaf_row_mask * c2_delta;
        idx += 4;

        // --- x / pow state machine ---------------------------------------------------------
        let x = current[COL_FRI_X];
        let x_next = next[COL_FRI_X];
        let pow = current[COL_FRI_POW];
        let pow_next = next[COL_FRI_POW];
        let path_bit = current[COL_MERKLE_PATH_BIT];

        let reset_x = query_reset_mask * (E::from(self.domain_offset) - x);
        let reset_pow = query_reset_mask * (E::from(self.g_lde) - pow);

        let x_mul = x * path_bit * (pow - one);
        let x_trace_update = trace_merkle_bit_mask * x_mul;

        let x_fri_update = fri_leaf_any_row_mask * (x * x * E::from(self.inv_domain_offset) - x);

        result[idx] = x_next - x - reset_x - x_trace_update - x_fri_update;

        let pow_trace_update = trace_merkle_bit_mask * (pow * pow - pow);
        result[idx + 1] = pow_next - pow - reset_pow - pow_trace_update;
        idx += 2;

        // --- evaluation freeze between leaf updates ---------------------------------------
        let eval = current[COL_FRI_EVAL];
        let eval_next = next[COL_FRI_EVAL];
        result[idx] = (one - fri_leaf_any_row_mask - query_reset_mask) * (eval_next - eval);
        idx += 1;

        // --- MSB capture bits --------------------------------------------------------------
        for layer_idx in 0..num_fri_layers {
            let bit_col = COL_FRI_MSB_BITS_START + layer_idx;
            let cur_b = current[bit_col];
            let next_b = next[bit_col];
            let capture = msb_capture_masks[layer_idx];
            result[idx + layer_idx] = next_b
                - cur_b
                - query_reset_mask * (E::ZERO - cur_b)
                - capture * (path_bit - cur_b);
        }
        idx += num_fri_layers;

        // --- per-layer eval selection checks ----------------------------------------------
        for layer_idx in 0..num_fri_layers {
            let mask = fri_leaf_row_masks[layer_idx];
            let b = current[COL_FRI_MSB_BITS_START + layer_idx];
            let v0 = current[RATE_START];
            let v1 = current[RATE_START + 1];
            let selected = v0 + b * (v1 - v0);
            result[idx + layer_idx] = mask * (eval - selected);
        }
        idx += num_fri_layers;

        // --- DEEP composition check (layer 0) ---------------------------------------------
        if num_fri_layers > 0 {
            let mask = fri_leaf_row_masks[0];
            let z = E::from(self.expected_z);
            let z1 = z * E::from(self.g_trace);
            let x_minus_z0 = x - z;
            let x_minus_z1 = x - z1;
            let denom = x_minus_z0 * x_minus_z1;
            let num = (t1 + c1) * x_minus_z1 + (t2 + c2) * x_minus_z0;
            result[idx] = mask * (eval * denom - num);
        } else {
            result[idx] = E::ZERO;
        }
        idx += 1;

        // --- FRI folding checks -----------------------------------------------------------
        for layer_idx in 0..num_fri_layers {
            let mask = fri_leaf_row_masks[layer_idx];
            let b = current[COL_FRI_MSB_BITS_START + layer_idx];
            let alpha = current[COL_FRI_ALPHA_START + layer_idx];
            let v0 = current[RATE_START];
            let v1 = current[RATE_START + 1];

            let sign = one - two * b;
            let x_base = x * sign;

            // 2x * next_eval = (x + α) * f(x) + (x - α) * f(-x)
            let lhs = two * x_base * eval_next;
            let rhs = (x_base + alpha) * v0 + (x_base - alpha) * v1;
            result[idx + layer_idx] = mask * (lhs - rhs);
        }
        idx += num_fri_layers;

        // --- Remainder evaluation check ---------------------------------------------------
        if num_fri_layers > 0 {
            let remainder_mask = *fri_root_masks.last().unwrap_or(&E::ZERO);
            let mut acc = E::ZERO;
            for i in 0..NUM_REMAINDER_COEFFS {
                acc = acc * x + current[COL_REMAINDER_COEFFS_START + i];
            }
            result[idx] = remainder_mask * (eval - acc);
        } else {
            result[idx] = E::ZERO;
        }
        idx += 1;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // --- Segment A: Hash inner public inputs ---------------------------------------------
        let input_len = self.pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(RATE_WIDTH).max(1);

        // Sponge initialization (public input hash).
        let len_mod_rate = (input_len % RATE_WIDTH) as u64;
        assertions.push(Assertion::single(0, 0, BaseElement::new(len_mod_rate)));
        for i in 1..CAPACITY_WIDTH {
            assertions.push(Assertion::single(i, 0, BaseElement::ZERO));
        }

        // Bind absorbed public-input blocks.
        for block in 0..num_pi_blocks {
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

        // Bind digest after final public-input hash permutation.
        let pi_last_row = num_pi_blocks * ROWS_PER_PERMUTATION - 1;
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                RATE_START + i,
                pi_last_row,
                self.pub_inputs.inner_pub_inputs_hash[i],
            ));
        }

        // Boundary masks between public-input hash blocks.
        for block in 0..num_pi_blocks {
            let boundary_row = (block + 1) * ROWS_PER_PERMUTATION - 1;
            if block + 1 < num_pi_blocks {
                assertions.push(Assertion::single(
                    COL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ONE,
                ));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_RESEED_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COIN_INIT_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
            } else {
                // Reset to a new sponge for transcript seeding.
                assertions.push(Assertion::single(
                    COL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_RESEED_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COIN_INIT_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
            }
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
        }

        // --- Segment B: Hash transcript seed (context prefix + public inputs) ----------------
        let seed_prefix = build_context_prefix(&self.pub_inputs);
        let seed_len = seed_prefix.len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);
        let seed_start = num_pi_blocks * ROWS_PER_PERMUTATION;

        // Sponge initialization (transcript seed).
        let seed_mod_rate = (seed_len % RATE_WIDTH) as u64;
        assertions.push(Assertion::single(
            0,
            seed_start,
            BaseElement::new(seed_mod_rate),
        ));
        for i in 1..CAPACITY_WIDTH {
            assertions.push(Assertion::single(i, seed_start, BaseElement::ZERO));
        }

        // Bind absorbed seed blocks.
        for block in 0..num_seed_blocks {
            let row = seed_start + block * ROWS_PER_PERMUTATION;
            let start = block * RATE_WIDTH;
            for j in 0..RATE_WIDTH {
                let idx = start + j;
                let val = if idx < seed_prefix.len() {
                    seed_prefix[idx]
                } else {
                    let pi_idx = idx - seed_prefix.len();
                    if pi_idx < input_len {
                        self.pub_inputs.inner_public_inputs[pi_idx]
                    } else {
                        BaseElement::ZERO
                    }
                };
                assertions.push(Assertion::single(RATE_START + j, row, val));
            }
        }

        // Boundary masks between seed blocks and into coin-init.
        for block in 0..num_seed_blocks {
            let boundary_row = seed_start + (block + 1) * ROWS_PER_PERMUTATION - 1;
            if block + 1 < num_seed_blocks {
                assertions.push(Assertion::single(
                    COL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ONE,
                ));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_RESEED_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COIN_INIT_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
            } else {
                assertions.push(Assertion::single(
                    COL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_RESEED_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COIN_INIT_MASK,
                    boundary_row,
                    BaseElement::ONE,
                ));
            }
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
        }

        // --- Segment C: coin-init boundary into reseed(trace_commitment) ----------------------
        let coin_start = seed_start + num_seed_blocks * ROWS_PER_PERMUTATION;
        let coin_boundary_row = coin_start + ROWS_PER_PERMUTATION - 1;
        assertions.push(Assertion::single(
            COL_CARRY_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FULL_CARRY_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_RESEED_MASK,
            coin_boundary_row,
            BaseElement::ONE,
        ));
        assertions.push(Assertion::single(
            COL_COIN_INIT_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_COEFF_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_Z_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_DEEP_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FRI_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_POS_MASK,
            coin_boundary_row,
            BaseElement::ZERO,
        ));
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                COL_RESEED_WORD_START + i,
                coin_boundary_row,
                self.pub_inputs.trace_commitment[i],
            ));
        }

        // --- Coefficient draw full-carry boundaries and reseed(constraint_commitment) ---------
        let num_coeff_perms = 36usize.div_ceil(RATE_WIDTH);
        let trace_reseed_perm_idx = num_pi_blocks + num_seed_blocks + 1;
        let coeff_start_perm_idx = trace_reseed_perm_idx;

        // Boundaries between coefficient permutations use full-carry.
        for k in 0..(num_coeff_perms - 1) {
            let perm_idx = coeff_start_perm_idx + k;
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            assertions.push(Assertion::single(
                COL_CARRY_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(
                COL_RESEED_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COIN_INIT_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
        }

        // Boundary into constraint commitment reseed after last coefficient permutation.
        let last_coeff_perm_idx = coeff_start_perm_idx + num_coeff_perms - 1;
        let constraint_boundary_row = (last_coeff_perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
        assertions.push(Assertion::single(
            COL_CARRY_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FULL_CARRY_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_RESEED_MASK,
            constraint_boundary_row,
            BaseElement::ONE,
        ));
        assertions.push(Assertion::single(
            COL_COIN_INIT_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_COEFF_MASK,
            constraint_boundary_row,
            BaseElement::ONE,
        ));
        assertions.push(Assertion::single(
            COL_Z_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_DEEP_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FRI_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_POS_MASK,
            constraint_boundary_row,
            BaseElement::ZERO,
        ));
        for i in 0..DIGEST_WIDTH {
            assertions.push(Assertion::single(
                COL_RESEED_WORD_START + i,
                constraint_boundary_row,
                self.pub_inputs.constraint_commitment[i],
            ));
        }

        // Boundary after constraint reseed permutation: draw z (OOD digest is hashed next).
        let constraint_reseed_perm_idx = last_coeff_perm_idx + 1;
        let z_boundary_row = (constraint_reseed_perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
        assertions.push(Assertion::single(
            COL_CARRY_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FULL_CARRY_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_RESEED_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_COIN_INIT_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_COEFF_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_Z_MASK,
            z_boundary_row,
            BaseElement::ONE,
        ));
        assertions.push(Assertion::single(
            COL_DEEP_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_FRI_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));
        assertions.push(Assertion::single(
            COL_POS_MASK,
            z_boundary_row,
            BaseElement::ZERO,
        ));

        // --- Segment E: Hash merged OOD evaluations (trace+quotient) --------------------------
        //
        // Winterfell reseeds the public coin with `hash_elements(merge_ood_evaluations(..))`
        // after passing the OOD consistency check. We compute the same digest in-circuit and use
        // it to restore the coin state for deep-coefficient draws.
        let ood_eval_len = 2 * (RPO_TRACE_WIDTH + 8);
        let num_ood_perms = ood_eval_len.div_ceil(RATE_WIDTH);
        let ood_start_perm_idx = constraint_reseed_perm_idx + 1;
        let ood_start_row = ood_start_perm_idx * ROWS_PER_PERMUTATION;

        let ood_len_mod_rate = (ood_eval_len % RATE_WIDTH) as u64;
        assertions.push(Assertion::single(
            0,
            ood_start_row,
            BaseElement::new(ood_len_mod_rate),
        ));
        for i in 1..CAPACITY_WIDTH {
            assertions.push(Assertion::single(i, ood_start_row, BaseElement::ZERO));
        }

        for k in 0..num_ood_perms {
            let perm_idx = ood_start_perm_idx + k;
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            let is_last = k + 1 == num_ood_perms;

            assertions.push(Assertion::single(
                COL_CARRY_MASK,
                boundary_row,
                if is_last {
                    BaseElement::ZERO
                } else {
                    BaseElement::ONE
                },
            ));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_RESEED_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COIN_INIT_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
        }

        // --- Deep coefficient draw boundaries (permute-only, full-carry) ----------------------
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8; // trace_width + num_constraint_comp_cols
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);
        let deep_start_perm_idx = ood_start_perm_idx + num_ood_perms;
        let num_fri_commitments = self.pub_inputs.fri_commitments.len();
        let has_fri_commitments = num_fri_commitments > 0;
        for k in 0..num_deep_perms {
            let perm_idx = deep_start_perm_idx + k;
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            let is_last = k + 1 == num_deep_perms;

            assertions.push(Assertion::single(
                COL_CARRY_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                boundary_row,
                if is_last {
                    BaseElement::ZERO
                } else {
                    BaseElement::ONE
                },
            ));
            let reseed_here = is_last && has_fri_commitments;
            assertions.push(Assertion::single(
                COL_RESEED_MASK,
                boundary_row,
                if reseed_here {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                },
            ));
            assertions.push(Assertion::single(
                COL_COIN_INIT_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));

            if reseed_here {
                let first_commitment = self.pub_inputs.fri_commitments[0];
                for i in 0..DIGEST_WIDTH {
                    assertions.push(Assertion::single(
                        COL_RESEED_WORD_START + i,
                        boundary_row,
                        first_commitment[i],
                    ));
                }
            }
        }

        // --- FRI alpha draw boundaries --------------------------------------------------------
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let has_remainder = num_fri_commitments > 0;
        let fri_start_perm_idx = deep_start_perm_idx + num_deep_perms;

        for k in 0..num_fri_layers {
            let perm_idx = fri_start_perm_idx + k;
            let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;

            assertions.push(Assertion::single(
                COL_CARRY_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_RESEED_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(
                COL_COIN_INIT_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                boundary_row,
                BaseElement::ONE,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                boundary_row,
                BaseElement::ZERO,
            ));

            // Reseed word binds the next FRI commitment (or remainder after last alpha).
            let next_commitment = if k + 1 < num_fri_layers {
                self.pub_inputs.fri_commitments[k + 1]
            } else {
                self.pub_inputs.fri_commitments[num_fri_layers]
            };
            for i in 0..DIGEST_WIDTH {
                assertions.push(Assertion::single(
                    COL_RESEED_WORD_START + i,
                    boundary_row,
                    next_commitment[i],
                ));
            }
        }

        // Remainder permutation boundary (no alpha draw).
        if has_remainder {
            let remainder_perm_idx = fri_start_perm_idx + num_fri_layers;
            let remainder_boundary_row = (remainder_perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
            assertions.push(Assertion::single(
                COL_CARRY_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FULL_CARRY_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_RESEED_MASK,
                remainder_boundary_row,
                if self.pub_inputs.num_draws > 0 {
                    BaseElement::ONE
                } else {
                    BaseElement::ZERO
                },
            ));
            assertions.push(Assertion::single(
                COL_COIN_INIT_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_COEFF_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_Z_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_DEEP_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_FRI_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
            assertions.push(Assertion::single(
                COL_POS_MASK,
                remainder_boundary_row,
                BaseElement::ZERO,
            ));
        }

        // --- Query position draw boundaries --------------------------------------------------
        let num_pos_perms = if self.pub_inputs.num_draws == 0 {
            0
        } else {
            (self.pub_inputs.num_draws + 1).div_ceil(RATE_WIDTH)
        };

        if num_pos_perms > 0 {
            let pos_start_perm_idx = fri_start_perm_idx + num_fri_layers + has_remainder as usize;

            for k in 0..num_pos_perms {
                let perm_idx = pos_start_perm_idx + k;
                let boundary_row = (perm_idx + 1) * ROWS_PER_PERMUTATION - 1;
                let is_last = k + 1 == num_pos_perms;

                assertions.push(Assertion::single(
                    COL_CARRY_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_FULL_CARRY_MASK,
                    boundary_row,
                    if is_last {
                        BaseElement::ZERO
                    } else {
                        BaseElement::ONE
                    },
                ));
                assertions.push(Assertion::single(
                    COL_RESEED_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COIN_INIT_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_COEFF_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_Z_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_DEEP_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_FRI_MASK,
                    boundary_row,
                    BaseElement::ZERO,
                ));
                assertions.push(Assertion::single(
                    COL_POS_MASK,
                    boundary_row,
                    BaseElement::ONE,
                ));
            }
        }

        // --- Merkle init assertions ----------------------------------------------------------
        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_layers
            + has_remainder as usize
            + num_pos_perms
            + 2;
        let num_pos_decomp_perms = self.pub_inputs.num_draws;
        let pre_merkle_perms = transcript_perms + num_pos_decomp_perms;
        let total_perms = self.trace_length() / ROWS_PER_PERMUTATION;

        let lde_domain_size = self.pub_inputs.trace_length * self.pub_inputs.blowup_factor;
        let depth_trace = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };

        let trace_leaf_len = RPO_TRACE_WIDTH;
        let constraint_leaf_len = 8usize;
        let fri_leaf_len = 2usize;

        let compute_leaf_perms = |len: usize, partition_size: usize| -> usize {
            if partition_size >= len {
                len.div_ceil(RATE_WIDTH).max(1)
            } else {
                let mut perms = 0usize;
                let mut remaining = len;
                while remaining > 0 {
                    let part_len = remaining.min(partition_size);
                    perms += part_len.div_ceil(RATE_WIDTH).max(1);
                    remaining -= part_len;
                }
                let num_partitions = len.div_ceil(partition_size);
                let merged_len = num_partitions * DIGEST_WIDTH;
                perms + merged_len.div_ceil(RATE_WIDTH).max(1)
            }
        };

        let trace_leaf_perms =
            compute_leaf_perms(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_leaf_perms = compute_leaf_perms(
            constraint_leaf_len,
            self.pub_inputs.constraint_partition_size,
        );
        let fri_leaf_perms = fri_leaf_len.div_ceil(RATE_WIDTH).max(1);

        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        for layer_idx in 0..num_fri_layers {
            merkle_perms_per_query += fri_leaf_perms + depth_trace.saturating_sub(layer_idx + 1);
        }
        let expected_active_perms =
            pre_merkle_perms + self.pub_inputs.num_queries * merkle_perms_per_query;

        if expected_active_perms <= total_perms {
            let fri_len_mod = (fri_leaf_len % RATE_WIDTH) as u64;

            let add_leaf_assertions = |assertions: &mut Vec<Assertion<BaseElement>>,
                                       mut perm_idx: usize,
                                       len: usize,
                                       partition_size: usize|
             -> usize {
                if partition_size >= len {
                    let len_mod = (len % RATE_WIDTH) as u64;
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    assertions.push(Assertion::single(0, row0, BaseElement::new(len_mod)));
                    for i in 1..CAPACITY_WIDTH {
                        assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
                    }
                    perm_idx += len.div_ceil(RATE_WIDTH).max(1);
                    return perm_idx;
                }

                let mut remaining = len;
                while remaining > 0 {
                    let part_len = remaining.min(partition_size);
                    let len_mod = (part_len % RATE_WIDTH) as u64;
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    assertions.push(Assertion::single(0, row0, BaseElement::new(len_mod)));
                    for i in 1..CAPACITY_WIDTH {
                        assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
                    }
                    perm_idx += part_len.div_ceil(RATE_WIDTH).max(1);
                    remaining -= part_len;
                }

                let num_partitions = len.div_ceil(partition_size);
                let merged_len = num_partitions * DIGEST_WIDTH;
                let merged_mod = (merged_len % RATE_WIDTH) as u64;
                let row0 = perm_idx * ROWS_PER_PERMUTATION;
                assertions.push(Assertion::single(0, row0, BaseElement::new(merged_mod)));
                for i in 1..CAPACITY_WIDTH {
                    assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
                }
                perm_idx += merged_len.div_ceil(RATE_WIDTH).max(1);

                perm_idx
            };

            let mut perm_idx = pre_merkle_perms;
            for _q in 0..self.pub_inputs.num_queries {
                perm_idx = add_leaf_assertions(
                    &mut assertions,
                    perm_idx,
                    trace_leaf_len,
                    self.pub_inputs.trace_partition_size,
                );

                // Trace merge starts.
                for _ in 0..depth_trace {
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    for i in 0..CAPACITY_WIDTH {
                        assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
                    }
                    perm_idx += 1;
                }

                perm_idx = add_leaf_assertions(
                    &mut assertions,
                    perm_idx,
                    constraint_leaf_len,
                    self.pub_inputs.constraint_partition_size,
                );

                // Constraint merge starts.
                for _ in 0..depth_trace {
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    for i in 0..CAPACITY_WIDTH {
                        assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
                    }
                    perm_idx += 1;
                }

                // FRI layers.
                for layer_idx in 0..num_fri_layers {
                    // FRI leaf start.
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    assertions.push(Assertion::single(0, row0, BaseElement::new(fri_len_mod)));
                    for i in 1..CAPACITY_WIDTH {
                        assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
                    }
                    perm_idx += fri_leaf_perms;

                    // FRI merge starts for this layer.
                    let layer_depth = depth_trace.saturating_sub(layer_idx + 1);
                    for _ in 0..layer_depth {
                        let row0 = perm_idx * ROWS_PER_PERMUTATION;
                        for i in 0..CAPACITY_WIDTH {
                            assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
                        }
                        perm_idx += 1;
                    }
                }
            }
        }

        // --- Remainder polynomial commitment hash -----------------------------------------
        let remainder_hash_perms = (self.pub_inputs.fri_commitments.len() > 0) as usize;
        if remainder_hash_perms > 0 && expected_active_perms + remainder_hash_perms <= total_perms {
            let rem_start_perm_idx = expected_active_perms;
            let row0 = rem_start_perm_idx * ROWS_PER_PERMUTATION;

            // Rpo256::hash_elements() domain-prefix: capacity[0] = len_mod_rate, rest zero.
            // For the inner proof options we support, the remainder has 8 coefficients, so
            // len_mod_rate == 0.
            assertions.push(Assertion::single(0, row0, BaseElement::ZERO));
            for i in 1..CAPACITY_WIDTH {
                assertions.push(Assertion::single(i, row0, BaseElement::ZERO));
            }

            let boundary_row =
                (rem_start_perm_idx + remainder_hash_perms) * ROWS_PER_PERMUTATION - 1;
            let commitment = self
                .pub_inputs
                .fri_commitments
                .last()
                .copied()
                .unwrap_or([BaseElement::ZERO; DIGEST_WIDTH]);
            for i in 0..DIGEST_WIDTH {
                assertions.push(Assertion::single(
                    CAPACITY_WIDTH + i,
                    boundary_row,
                    commitment[i],
                ));
            }
        }

        // Binding accumulator must end at 1.
        assertions.push(Assertion::single(
            COL_POS_PERM_ACC,
            self.trace_length() - 1,
            BaseElement::ONE,
        ));

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let total_rows = self.trace_length();
        let total_perms = total_rows / ROWS_PER_PERMUTATION;

        // --- Transcript permutation counts (must match prover) -----------------------------
        let input_len = self.pub_inputs.inner_public_inputs.len();
        let num_pi_blocks = input_len.div_ceil(RATE_WIDTH).max(1);

        let seed_len = CONTEXT_PREFIX_LEN + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);

        let num_coeff_perms = 36usize.div_ceil(RATE_WIDTH);
        let num_deep_coeffs = RPO_TRACE_WIDTH + 8;
        let num_deep_perms = num_deep_coeffs.div_ceil(RATE_WIDTH);
        let ood_eval_len = 2 * (RPO_TRACE_WIDTH + 8);
        let num_ood_perms = ood_eval_len.div_ceil(RATE_WIDTH);

        let num_fri_commitments = self.pub_inputs.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let num_remainder_perms = (num_fri_commitments > 0) as usize;

        let num_pos_perms = if self.pub_inputs.num_draws == 0 {
            0
        } else {
            (self.pub_inputs.num_draws + 1).div_ceil(RATE_WIDTH)
        };

        let transcript_perms = num_pi_blocks
            + num_seed_blocks
            + num_coeff_perms
            + num_ood_perms
            + num_deep_perms
            + num_fri_layers
            + num_remainder_perms
            + num_pos_perms
            + 2;
        let num_pos_decomp_perms = self.pub_inputs.num_draws;
        let pre_merkle_perms = transcript_perms + num_pos_decomp_perms;

        // --- Merkle periodic selectors -----------------------------------------------------
        let mut leaf_chain_mask = vec![BaseElement::ZERO; total_rows];
        let mut merkle_chain_mask = vec![BaseElement::ZERO; total_rows];
        let mut trace_leaf_end_mask = vec![BaseElement::ZERO; total_rows];
        let mut trace_root_mask = vec![BaseElement::ZERO; total_rows];
        let mut constraint_root_mask = vec![BaseElement::ZERO; total_rows];
        let mut fri_root_masks = vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers];

        // DEEP + FRI masks (all sparse, full-length).
        let mut query_reset_mask = vec![BaseElement::ZERO; total_rows];
        let mut trace_leaf0_row_mask = vec![BaseElement::ZERO; total_rows];
        let mut trace_leaf1_row_mask = vec![BaseElement::ZERO; total_rows];
        let mut constraint_leaf_row_mask = vec![BaseElement::ZERO; total_rows];
        let mut trace_merkle_bit_mask = vec![BaseElement::ZERO; total_rows];
        let mut msb_capture_masks = vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers];
        let mut fri_leaf_row_masks = vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers];
        let mut fri_leaf_any_row_mask = vec![BaseElement::ZERO; total_rows];
        let mut remainder_hash_row0_mask = vec![BaseElement::ZERO; total_rows];

        // Fixed leaf shapes for RpoAir inner proofs.
        let trace_leaf_len = RPO_TRACE_WIDTH;
        let constraint_leaf_len = 8usize;
        let fri_leaf_len = 2usize;

        let compute_leaf_layout = |len: usize, partition_size: usize| -> (usize, Vec<bool>) {
            let hash_perms = |input_len: usize| input_len.div_ceil(RATE_WIDTH).max(1);

            if partition_size >= len {
                let perms = hash_perms(len);
                let mut chain = vec![false; perms];
                for i in 0..perms.saturating_sub(1) {
                    chain[i] = true;
                }
                return (perms, chain);
            }

            // Partitioned leaves: hash each partition independently, then hash the concatenated
            // partition digests (Rpo256::merge_many == hash_elements over digest elements).
            let mut chain = Vec::new();
            let mut remaining = len;
            while remaining > 0 {
                let part_len = remaining.min(partition_size);
                let perms = hash_perms(part_len);
                chain.extend((0..perms).map(|i| i + 1 < perms));
                remaining -= part_len;
            }

            let num_partitions = len.div_ceil(partition_size);
            let merged_len = num_partitions * DIGEST_WIDTH;
            let merged_perms = hash_perms(merged_len);
            chain.extend((0..merged_perms).map(|i| i + 1 < merged_perms));

            (chain.len(), chain)
        };

        let (trace_leaf_perms, trace_leaf_chain) =
            compute_leaf_layout(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let (constraint_leaf_perms, constraint_leaf_chain) = compute_leaf_layout(
            constraint_leaf_len,
            self.pub_inputs.constraint_partition_size,
        );
        let fri_leaf_perms = fri_leaf_len.div_ceil(RATE_WIDTH).max(1);

        let lde_domain_size = self.pub_inputs.trace_length * self.pub_inputs.blowup_factor;
        let depth_trace = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };

        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        for layer_idx in 0..num_fri_layers {
            merkle_perms_per_query += fri_leaf_perms + depth_trace.saturating_sub(layer_idx + 1);
        }
        let expected_active_perms =
            pre_merkle_perms + self.pub_inputs.num_queries * merkle_perms_per_query;

        // If the trace is too short to include the Merkle segment (e.g. minimal transcript-only
        // proofs), leave all Merkle periodic selectors at zero.
        if expected_active_perms <= total_perms {
            let mut perm_idx = pre_merkle_perms;
            for _q in 0..self.pub_inputs.num_queries {
                // Query reset happens on the boundary row immediately preceding the first trace
                // leaf permutation for this query.
                let query_row0 = perm_idx * ROWS_PER_PERMUTATION;
                if query_row0 > 0 && query_row0 - 1 < total_rows {
                    query_reset_mask[query_row0 - 1] = BaseElement::ONE;
                }

                // --- Trace leaf hashing -----------------------------------------------------
                for rel_perm in 0..trace_leaf_perms {
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                    if rel_perm == 0 && row0 < total_rows {
                        trace_leaf0_row_mask[row0] = BaseElement::ONE;
                    }
                    if rel_perm == 1 && row0 < total_rows {
                        trace_leaf1_row_mask[row0] = BaseElement::ONE;
                    }
                    if trace_leaf_chain.get(rel_perm).copied().unwrap_or(false) {
                        leaf_chain_mask[boundary] = BaseElement::ONE;
                    }
                    if rel_perm + 1 == trace_leaf_perms {
                        trace_leaf_end_mask[boundary] = BaseElement::ONE;
                    }
                    // Wire the final leaf-hash digest into the first Merkle merge permutation.
                    if depth_trace > 0 && rel_perm + 1 == trace_leaf_perms {
                        merkle_chain_mask[boundary] = BaseElement::ONE;
                        trace_merkle_bit_mask[boundary] = BaseElement::ONE;
                        // bit index 0; MSB capture happens only if a requested bit maps here.
                        if depth_trace > 0 {
                            let bit_idx = 0usize;
                            let capture_layer = depth_trace.saturating_sub(1 + bit_idx);
                            if capture_layer < num_fri_layers {
                                msb_capture_masks[capture_layer][boundary] = BaseElement::ONE;
                            }
                        }
                    }
                    perm_idx += 1;
                }

                // --- Trace Merkle path ------------------------------------------------------
                for level in 0..depth_trace {
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                    if level + 1 < depth_trace {
                        merkle_chain_mask[boundary] = BaseElement::ONE;
                        trace_merkle_bit_mask[boundary] = BaseElement::ONE;
                        let bit_idx = level + 1;
                        let capture_layer = depth_trace.saturating_sub(1 + bit_idx);
                        if capture_layer < num_fri_layers {
                            msb_capture_masks[capture_layer][boundary] = BaseElement::ONE;
                        }
                    } else {
                        trace_root_mask[boundary] = BaseElement::ONE;
                    }
                    perm_idx += 1;
                }

                // --- Constraint leaf hashing ------------------------------------------------
                for rel_perm in 0..constraint_leaf_perms {
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                    if rel_perm == 0 && row0 < total_rows {
                        constraint_leaf_row_mask[row0] = BaseElement::ONE;
                    }
                    if constraint_leaf_chain
                        .get(rel_perm)
                        .copied()
                        .unwrap_or(false)
                    {
                        leaf_chain_mask[boundary] = BaseElement::ONE;
                    }
                    // Wire the final leaf-hash digest into the first Merkle merge permutation.
                    if depth_trace > 0 && rel_perm + 1 == constraint_leaf_perms {
                        merkle_chain_mask[boundary] = BaseElement::ONE;
                    }
                    perm_idx += 1;
                }

                // --- Constraint Merkle path -------------------------------------------------
                for level in 0..depth_trace {
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                    if level + 1 < depth_trace {
                        merkle_chain_mask[boundary] = BaseElement::ONE;
                    } else {
                        constraint_root_mask[boundary] = BaseElement::ONE;
                    }
                    perm_idx += 1;
                }

                // --- FRI layers -------------------------------------------------------------
                for layer_idx in 0..num_fri_layers {
                    // FRI leaf hashing.
                    let layer_depth = depth_trace.saturating_sub(layer_idx + 1);
                    for rel_perm in 0..fri_leaf_perms {
                        let row0 = perm_idx * ROWS_PER_PERMUTATION;
                        let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                        if rel_perm == 0 && row0 < total_rows {
                            fri_leaf_row_masks[layer_idx][row0] = BaseElement::ONE;
                            fri_leaf_any_row_mask[row0] = BaseElement::ONE;
                        }
                        if layer_depth > 0 && rel_perm + 1 == fri_leaf_perms {
                            merkle_chain_mask[boundary] = BaseElement::ONE;
                        }
                        perm_idx += 1;
                    }

                    // Merkle path for this layer. Depth decreases by 1 per layer.
                    for level in 0..layer_depth {
                        let row0 = perm_idx * ROWS_PER_PERMUTATION;
                        let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                        if level + 1 < layer_depth {
                            merkle_chain_mask[boundary] = BaseElement::ONE;
                        } else {
                            fri_root_masks[layer_idx][boundary] = BaseElement::ONE;
                        }
                        perm_idx += 1;
                    }
                }
            }

            // Remainder commitment hash begins after all per-query Merkle permutations.
            if num_remainder_perms > 0 && expected_active_perms < total_perms {
                let row0 = expected_active_perms * ROWS_PER_PERMUTATION;
                if row0 < total_rows {
                    remainder_hash_row0_mask[row0] = BaseElement::ONE;
                }
            }
        }

        // --- Query-position periodic columns ----------------------------------------------
        let mut pos_w_full_cols: [Vec<BaseElement>; 4] =
            core::array::from_fn(|_| Vec::with_capacity(total_rows));
        let mut pos_w_masked_cols: [Vec<BaseElement>; 4] =
            core::array::from_fn(|_| Vec::with_capacity(total_rows));
        let mut pos_lo_mask_col = Vec::with_capacity(total_rows);
        let mut pos_hi_mask_col = Vec::with_capacity(total_rows);
        let mut pos_hi_first_mask_col = Vec::with_capacity(total_rows);
        let mut pos_first_row_mask_col = Vec::with_capacity(total_rows);

        for row in 0..total_rows {
            let local_row = row % ROWS_PER_PERMUTATION;
            for j in 0..4 {
                let exp = 4 * local_row + j;
                let w = BaseElement::new(1u64 << exp);
                pos_w_full_cols[j].push(w);
                let mw = if exp < depth_trace {
                    w
                } else {
                    BaseElement::ZERO
                };
                pos_w_masked_cols[j].push(mw);
            }
            pos_lo_mask_col.push(BaseElement::new((local_row < 8) as u64));
            pos_hi_mask_col.push(BaseElement::new(
                (local_row >= 8 && local_row < ROWS_PER_PERMUTATION - 1) as u64,
            ));
            pos_hi_first_mask_col.push(BaseElement::new((local_row == 8) as u64));
            pos_first_row_mask_col.push(BaseElement::new((local_row == 0) as u64));
        }

        // Full-length selectors for mapping coin outputs -> decomp perms.
        let mut pos_decomp_row_mask = vec![BaseElement::ZERO; total_rows];
        let mut pos_first_decomp_mask = vec![BaseElement::ZERO; total_rows];
        let mut pos_last_decomp_mask = vec![BaseElement::ZERO; total_rows];
        let mut pos_rate_sel = vec![vec![BaseElement::ZERO; total_rows]; RATE_WIDTH];

        let num_draws = self.pub_inputs.num_draws;
        if num_draws > 0 && num_pos_perms > 0 {
            let pos_start_perm_idx = num_pi_blocks
                + num_seed_blocks
                + num_coeff_perms
                + num_ood_perms
                + num_deep_perms
                + num_fri_layers
                + num_remainder_perms
                + 2;

            let mut remaining = num_draws;
            let mut perm_idx = pos_start_perm_idx;
            let mut first_row0: Option<usize> = None;
            let mut last_boundary: Option<usize> = None;

            for pos_perm in 0..num_pos_perms {
                let draws_here = if pos_perm == 0 {
                    remaining.min(RATE_WIDTH.saturating_sub(1))
                } else {
                    remaining.min(RATE_WIDTH)
                };
                let start_rate = if pos_perm == 0 { 1 } else { 0 };

                perm_idx += 1; // consume the pos-draw permutation

                for d in 0..draws_here {
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    for r in 0..ROWS_PER_PERMUTATION {
                        pos_decomp_row_mask[row0 + r] = BaseElement::ONE;
                    }
                    pos_rate_sel[start_rate + d][row0] = BaseElement::ONE;
                    if first_row0.is_none() {
                        first_row0 = Some(row0);
                    }
                    last_boundary = Some(row0 + ROWS_PER_PERMUTATION - 1);
                    perm_idx += 1;
                    remaining -= 1;
                    if remaining == 0 {
                        break;
                    }
                }
                if remaining == 0 {
                    break;
                }
            }

            if let Some(r0) = first_row0 {
                pos_first_decomp_mask[r0] = BaseElement::ONE;
            }
            if let Some(b) = last_boundary {
                pos_last_decomp_mask[b] = BaseElement::ONE;
            }
        }

        // --- Base RPO periodic columns -----------------------------------------------------
        // Sparse, full-length masks for capturing OOD digest and OOD evaluation inputs.
        let mut ood_digest_capture_mask = vec![BaseElement::ZERO; total_rows];
        let mut ood_eval_row_masks = vec![vec![BaseElement::ZERO; total_rows]; num_ood_perms];
        let mut deep_start_row_mask = vec![BaseElement::ZERO; total_rows];
        let deep_start_perm_idx =
            num_pi_blocks + num_seed_blocks + num_coeff_perms + num_ood_perms + 2;
        let ood_start_perm_idx = deep_start_perm_idx - num_ood_perms;
        let deep_start_row = deep_start_perm_idx * ROWS_PER_PERMUTATION;
        if deep_start_row > 0 && deep_start_row < total_rows {
            deep_start_row_mask[deep_start_row] = BaseElement::ONE;
            ood_digest_capture_mask[deep_start_row - 1] = BaseElement::ONE;
        }
        for k in 0..num_ood_perms {
            let row0 = (ood_start_perm_idx + k) * ROWS_PER_PERMUTATION;
            if row0 < total_rows {
                ood_eval_row_masks[k][row0] = BaseElement::ONE;
            }
        }

        // Sparse, full-length masks for capturing transcript-derived coefficients.
        let coeff_start_perm_idx = num_pi_blocks + num_seed_blocks + 1;
        let mut coeff_end_masks = vec![vec![BaseElement::ZERO; total_rows]; num_coeff_perms];
        for k in 0..num_coeff_perms {
            let perm_idx = coeff_start_perm_idx + k;
            let boundary = perm_idx * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
            if boundary < total_rows {
                coeff_end_masks[k][boundary] = BaseElement::ONE;
            }
        }

        let mut deep_end_masks = vec![vec![BaseElement::ZERO; total_rows]; num_deep_perms];
        for k in 0..num_deep_perms {
            let perm_idx = deep_start_perm_idx + k;
            let boundary = perm_idx * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
            if boundary < total_rows {
                deep_end_masks[k][boundary] = BaseElement::ONE;
            }
        }

        let fri_start_perm_idx = deep_start_perm_idx + num_deep_perms;
        let mut fri_alpha_end_masks = vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers];
        for layer_idx in 0..num_fri_layers {
            let perm_idx = fri_start_perm_idx + layer_idx;
            let boundary = perm_idx * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
            if boundary < total_rows {
                fri_alpha_end_masks[layer_idx][boundary] = BaseElement::ONE;
            }
        }

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
                if round < NUM_ROUNDS {
                    ARK1[round]
                } else {
                    [BaseElement::ZERO; STATE_WIDTH]
                }
            } else {
                let round = local_row / 2;
                if round < NUM_ROUNDS {
                    ARK2[round]
                } else {
                    [BaseElement::ZERO; STATE_WIDTH]
                }
            };

            for (i, &c) in constants.iter().enumerate() {
                ark_columns[i].push(c);
            }

            let mask = (local_row < ROWS_PER_PERMUTATION - 1) as u64;
            perm_mask.push(BaseElement::new(mask));
        }

        let mut result = vec![half_round_type];
        for col in ark_columns {
            result.push(col);
        }
        result.push(perm_mask);

        for col in pos_w_full_cols {
            result.push(col);
        }
        for col in pos_w_masked_cols {
            result.push(col);
        }
        result.push(pos_lo_mask_col);
        result.push(pos_hi_mask_col);
        result.push(pos_hi_first_mask_col);
        result.push(pos_first_row_mask_col);
        result.push(pos_decomp_row_mask);
        result.push(pos_first_decomp_mask);
        result.push(pos_last_decomp_mask);
        for col in pos_rate_sel {
            result.push(col);
        }

        result.push(leaf_chain_mask);
        result.push(merkle_chain_mask);
        result.push(trace_leaf_end_mask);
        result.push(trace_root_mask);
        result.push(constraint_root_mask);
        for col in fri_root_masks {
            result.push(col);
        }
        result.push(ood_digest_capture_mask);
        for col in ood_eval_row_masks {
            result.push(col);
        }
        result.push(deep_start_row_mask);
        for col in coeff_end_masks {
            result.push(col);
        }
        for col in deep_end_masks {
            result.push(col);
        }
        for col in fri_alpha_end_masks {
            result.push(col);
        }

        // --- DEEP + FRI periodic columns (appended) ---------------------------------------
        result.push(query_reset_mask);
        result.push(trace_leaf0_row_mask);
        result.push(trace_leaf1_row_mask);
        result.push(constraint_leaf_row_mask);
        result.push(trace_merkle_bit_mask);
        for col in msb_capture_masks {
            result.push(col);
        }
        for col in fri_leaf_row_masks {
            result.push(col);
        }
        result.push(fri_leaf_any_row_mask);
        result.push(remainder_hash_row0_mask);
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

// CONTEXT PREFIX
// ================================================================================================

pub(crate) fn build_context_prefix(pub_inputs: &StarkVerifierPublicInputs) -> Vec<BaseElement> {
    // TraceInfo element 0 encodes: main_width << 8 | num_aux_segments (0).
    let trace_info0 = BaseElement::new(((RPO_TRACE_WIDTH as u32) << 8) as u64);
    let trace_info1 = BaseElement::new(pub_inputs.trace_length as u64);

    // Goldilocks modulus bytes split into 2 elements:
    // low half = 1, high half = 2^32 - 1.
    let modulus0 = BaseElement::ONE;
    let modulus1 = BaseElement::new(u64::from(u32::MAX));

    // Inner proof constraints count (transition + boundary) for RpoAir.
    let num_constraints = BaseElement::new(36);

    // ProofOptions packed element (see `winter_air::ProofOptions::to_elements`):
    // [field_extension, fri_folding_factor, fri_remainder_max_degree, blowup_factor]
    //
    // NOTE: `FieldExtension` is 1-based in Winterfell (`None = 1`).
    let options0 = BaseElement::new(
        pub_inputs.blowup_factor as u64
            + (7u64 << 8)
            + (2u64 << 16)
            + ((winter_air::FieldExtension::None as u64) << 24),
    );

    let grinding_factor = BaseElement::ZERO;
    // Context prefix must use the original query draw count from proof options.
    let num_queries = BaseElement::new(pub_inputs.num_draws as u64);

    vec![
        trace_info0,
        trace_info1,
        modulus0,
        modulus1,
        num_constraints,
        options0,
        grinding_factor,
        num_queries,
    ]
}

/// Recompute the z challenge from public inputs using the same RPO Fiat–Shamir
/// transcript as the verifier trace.
pub(crate) fn compute_expected_z(pub_inputs: &StarkVerifierPublicInputs) -> BaseElement {
    // Transcript seed = hash(context_prefix || inner_public_inputs).
    //
    // This must match Winterfell's `ProverChannel` seeding:
    // `RandomCoin::new(&[context.to_elements(), pub_inputs])`.
    let mut seed_elems = build_context_prefix(pub_inputs);
    seed_elems.extend_from_slice(&pub_inputs.inner_public_inputs);
    let mut coin = <RpoRandomCoin as RandomCoin>::new(&seed_elems);
    coin.reseed(Word::new(pub_inputs.trace_commitment));

    // Draw 36 constraint composition coefficients.
    for _ in 0..36 {
        let _: BaseElement = coin.draw().expect("failed to draw coeff");
    }

    // Reseed with constraint commitment and draw z.
    coin.reseed(Word::new(pub_inputs.constraint_commitment));
    coin.draw().expect("failed to draw z")
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
            32,
            RPO_TRACE_WIDTH,
            8,
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
            32,
            RPO_TRACE_WIDTH,
            8,
            16,
            1024,
        );

        let elements = pub_inputs.to_elements();

        // inner_public_inputs (2) + 4 (inner hash) + 4 (trace) + 4 (constraint) + 3*4 (fri) + 6 (params)
        assert_eq!(elements.len(), 2 + 4 + 4 + 4 + 12 + 6);
    }
}
