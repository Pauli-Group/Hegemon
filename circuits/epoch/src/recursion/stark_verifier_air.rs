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

use miden_crypto::hash::rpo::Rpo256;
use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Word;
use winter_air::{
    Air, AirContext, Assertion, BatchingMethod, EvaluationFrame, FieldExtension, ProofOptions,
    TraceInfo, TransitionConstraintDegree,
};
use winter_crypto::RandomCoin;
use winter_math::{fft, polynom, FieldElement, StarkField, ToElements};
use winterfell::math::fields::f64::BaseElement;

use super::fri_air::MAX_FRI_LAYERS;
use super::merkle_air::DIGEST_WIDTH;
use super::rpo_air::{
    ARK1, ARK2, MDS, NUM_ROUNDS, ROWS_PER_PERMUTATION, STATE_WIDTH, TRACE_WIDTH as RPO_TRACE_WIDTH,
};
use winter_air::{ConstraintCompositionCoefficients, DeepCompositionCoefficients};
use transaction_circuit::{TransactionAirStark, TransactionPublicInputsStark};

const CAPACITY_WIDTH: usize = 4;
pub(crate) const RATE_WIDTH: usize = 8;
const RATE_START: usize = CAPACITY_WIDTH;

// Trace layout for StarkVerifierAir.
// Columns 0..STATE_WIDTH-1 hold the RPO sponge state, and column STATE_WIDTH is an unused
// round counter (kept for compatibility with shared trace builders).
#[allow(dead_code)] // Used in OOD consistency check for inner proofs
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
pub(crate) const COL_COIN_SAVE_MASK: usize = COL_POS_MASK + 1;
pub(crate) const COL_COIN_RESTORE_MASK: usize = COL_COIN_SAVE_MASK + 1;
pub(crate) const COL_POS_START: usize = COL_COIN_RESTORE_MASK + 1;
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
pub(crate) const COL_TAPE_MASK: usize = COL_MERKLE_INDEX + 1;
pub(crate) const COL_TAPE_KIND: usize = COL_TAPE_MASK + 1;
pub(crate) const COL_TAPE_INDEX: usize = COL_TAPE_KIND + 1;
pub(crate) const COL_TAPE_VALUES_START: usize = COL_TAPE_INDEX + 1;
pub(crate) const TAPE_WIDTH: usize = RATE_WIDTH;
// OOD digest and coin-state save/restore columns for true recursion.
pub(crate) const COL_OOD_DIGEST_START: usize = COL_TAPE_VALUES_START + TAPE_WIDTH;
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

    /// Out-of-domain trace evaluations at z (current row).
    pub ood_trace_current: Vec<BaseElement>,
    /// Out-of-domain quotient evaluations at z (current row).
    pub ood_quotient_current: Vec<BaseElement>,
    /// Out-of-domain trace evaluations at z*g (next row).
    pub ood_trace_next: Vec<BaseElement>,
    /// Out-of-domain quotient evaluations at z*g (next row).
    pub ood_quotient_next: Vec<BaseElement>,

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
    /// FRI folding factor used by the inner proof options.
    pub fri_folding_factor: usize,
    /// FRI remainder max degree used by the inner proof options.
    pub fri_remainder_max_degree: usize,
    /// Query seed grinding factor used by the inner proof options.
    pub grinding_factor: usize,
    pub trace_length: usize,

    /// Main trace width of the inner proof (i.e. number of trace columns).
    pub trace_width: usize,
    /// Constraint composition frame width of the inner proof (i.e. number of quotient columns).
    pub constraint_frame_width: usize,
    /// Number of transition constraints in the inner AIR.
    pub num_transition_constraints: usize,
    /// Number of boundary assertions in the inner AIR.
    pub num_assertions: usize,
    /// Field extension used by the inner proof.
    pub field_extension: FieldExtension,
}

impl StarkVerifierPublicInputs {
    pub fn new(
        inner_public_inputs: Vec<BaseElement>,
        inner_pub_inputs_hash: [BaseElement; DIGEST_WIDTH],
        trace_commitment: [BaseElement; DIGEST_WIDTH],
        constraint_commitment: [BaseElement; DIGEST_WIDTH],
        ood_trace_current: Vec<BaseElement>,
        ood_quotient_current: Vec<BaseElement>,
        ood_trace_next: Vec<BaseElement>,
        ood_quotient_next: Vec<BaseElement>,
        fri_commitments: Vec<[BaseElement; DIGEST_WIDTH]>,
        num_queries: usize,
        num_draws: usize,
        trace_partition_size: usize,
        constraint_partition_size: usize,
        blowup_factor: usize,
        fri_folding_factor: usize,
        fri_remainder_max_degree: usize,
        grinding_factor: usize,
        trace_length: usize,
        trace_width: usize,
        constraint_frame_width: usize,
        num_transition_constraints: usize,
        num_assertions: usize,
        field_extension: FieldExtension,
    ) -> Self {
        let extension_degree =
            field_extension_degree(field_extension).expect("unsupported field extension");
        let trace_ood_len = trace_width * extension_degree;
        let constraint_ood_len = constraint_frame_width * extension_degree;
        assert_eq!(
            ood_trace_current.len(),
            trace_ood_len,
            "OOD trace current length mismatch: expected {trace_ood_len}, got {}",
            ood_trace_current.len()
        );
        assert_eq!(
            ood_trace_next.len(),
            trace_ood_len,
            "OOD trace next length mismatch: expected {trace_ood_len}, got {}",
            ood_trace_next.len()
        );
        assert_eq!(
            ood_quotient_current.len(),
            constraint_ood_len,
            "OOD quotient current length mismatch: expected {constraint_ood_len}, got {}",
            ood_quotient_current.len()
        );
        assert_eq!(
            ood_quotient_next.len(),
            constraint_ood_len,
            "OOD quotient next length mismatch: expected {constraint_ood_len}, got {}",
            ood_quotient_next.len()
        );

        Self {
            inner_public_inputs,
            inner_pub_inputs_hash,
            trace_commitment,
            constraint_commitment,
            ood_trace_current,
            ood_quotient_current,
            ood_trace_next,
            ood_quotient_next,
            fri_commitments,
            num_queries,
            num_draws,
            trace_partition_size,
            constraint_partition_size,
            blowup_factor,
            fri_folding_factor,
            fri_remainder_max_degree,
            grinding_factor,
            trace_length,
            trace_width,
            constraint_frame_width,
            num_transition_constraints,
            num_assertions,
            field_extension,
        }
    }

    /// Parse a `StarkVerifierPublicInputs` struct from `to_elements()` output.
    ///
    /// This is used for recursion depth 2+, where the inner proof is itself a `StarkVerifierAir`
    /// proof and its public inputs arrive as an opaque element vector.
    #[allow(dead_code)]
    pub fn try_from_elements(
        elements: &[BaseElement],
        inner_public_inputs_len: usize,
    ) -> Result<Self, String> {
        // Layout:
        // [inner_public_inputs..., inner_pub_inputs_hash(4), trace_root(4), constraint_root(4),
        //  ood_trace_current, ood_quotient_current, ood_trace_next, ood_quotient_next,
        //  fri_commitments(4*k),
        //  num_queries, num_draws, trace_partition_size, constraint_partition_size, blowup_factor,
        //  fri_folding_factor?, fri_remainder_max_degree?, grinding_factor?,
        //  trace_length, trace_width?, constraint_frame_width?, num_transition_constraints?,
        //  num_assertions?, field_extension?]
        const DIGESTS_FIXED: usize = 3 * DIGEST_WIDTH; // pub_inputs_hash + trace + constraint
        const NUM_PARAMS_V1: usize = 6;
        const NUM_PARAMS_V2: usize = 10;
        const NUM_PARAMS_V3: usize = 11;
        const NUM_PARAMS_V4: usize = 14;

        let min_len_v1 = inner_public_inputs_len + DIGESTS_FIXED + NUM_PARAMS_V1;
        if elements.len() < min_len_v1 {
            return Err(format!(
                "StarkVerifierPublicInputs elements too short: got {}, need at least {}",
                elements.len(),
                min_len_v1
            ));
        }

        let mut idx = 0usize;
        let inner_public_inputs = elements[idx..idx + inner_public_inputs_len].to_vec();
        idx += inner_public_inputs_len;

        let slice_to_digest =
            |s: &[BaseElement]| -> [BaseElement; DIGEST_WIDTH] { [s[0], s[1], s[2], s[3]] };

        let inner_pub_inputs_hash = slice_to_digest(&elements[idx..idx + DIGEST_WIDTH]);
        idx += DIGEST_WIDTH;
        let trace_commitment = slice_to_digest(&elements[idx..idx + DIGEST_WIDTH]);
        idx += DIGEST_WIDTH;
        let constraint_commitment = slice_to_digest(&elements[idx..idx + DIGEST_WIDTH]);
        idx += DIGEST_WIDTH;

        let params_start_v4 = elements.len().saturating_sub(NUM_PARAMS_V4);
        let params_start_v3 = elements.len().saturating_sub(NUM_PARAMS_V3);
        let params_start_v2 = elements.len().saturating_sub(NUM_PARAMS_V2);
        let params_start_v1 = elements.len().saturating_sub(NUM_PARAMS_V1);

        let (params_start, num_params) = if elements.len()
            >= min_len_v1 + (NUM_PARAMS_V4 - NUM_PARAMS_V1)
            && params_start_v4 >= idx
        {
            (params_start_v4, NUM_PARAMS_V4)
        } else if elements.len()
            >= min_len_v1 + (NUM_PARAMS_V3 - NUM_PARAMS_V1)
            && params_start_v3 >= idx
            && elements[idx..params_start_v3]
                .len()
                .is_multiple_of(DIGEST_WIDTH)
        {
            (params_start_v3, NUM_PARAMS_V3)
        } else if elements.len()
            >= min_len_v1 + (NUM_PARAMS_V2 - NUM_PARAMS_V1)
            && params_start_v2 >= idx
            && elements[idx..params_start_v2]
                .len()
                .is_multiple_of(DIGEST_WIDTH)
        {
            (params_start_v2, NUM_PARAMS_V2)
        } else {
            (params_start_v1, NUM_PARAMS_V1)
        };

        let num_queries = elements[params_start].as_int() as usize;
        let num_draws = elements[params_start + 1].as_int() as usize;
        let trace_partition_size = elements[params_start + 2].as_int() as usize;
        let constraint_partition_size = elements[params_start + 3].as_int() as usize;
        let blowup_factor = elements[params_start + 4].as_int() as usize;

        let (fri_folding_factor, fri_remainder_max_degree, grinding_factor, trace_length) =
            if num_params == NUM_PARAMS_V4 {
                (
                    elements[params_start + 5].as_int() as usize,
                    elements[params_start + 6].as_int() as usize,
                    elements[params_start + 7].as_int() as usize,
                    elements[params_start + 8].as_int() as usize,
                )
            } else {
                (2usize, 7usize, 0usize, elements[params_start + 5].as_int() as usize)
            };

        let (
            trace_width,
            constraint_frame_width,
            num_transition_constraints,
            num_assertions,
            field_extension,
        ) = if num_params == NUM_PARAMS_V4 {
            let raw_extension = elements[params_start + 13].as_int() as u64;
            let field_extension = match raw_extension {
                1 => FieldExtension::None,
                2 => FieldExtension::Quadratic,
                3 => FieldExtension::Cubic,
                _ => {
                    return Err(format!("unknown field extension id: {raw_extension}"));
                }
            };
            (
                elements[params_start + 9].as_int() as usize,
                elements[params_start + 10].as_int() as usize,
                elements[params_start + 11].as_int() as usize,
                elements[params_start + 12].as_int() as usize,
                field_extension,
            )
        } else if num_params == NUM_PARAMS_V3 {
            let raw_extension = elements[params_start + 10].as_int() as u64;
            let field_extension = match raw_extension {
                1 => FieldExtension::None,
                2 => FieldExtension::Quadratic,
                3 => FieldExtension::Cubic,
                _ => {
                    return Err(format!("unknown field extension id: {raw_extension}"));
                }
            };
            (
                elements[params_start + 6].as_int() as usize,
                elements[params_start + 7].as_int() as usize,
                elements[params_start + 8].as_int() as usize,
                elements[params_start + 9].as_int() as usize,
                field_extension,
            )
        } else if num_params == NUM_PARAMS_V2 {
            (
                elements[params_start + 6].as_int() as usize,
                elements[params_start + 7].as_int() as usize,
                elements[params_start + 8].as_int() as usize,
                elements[params_start + 9].as_int() as usize,
                FieldExtension::None,
            )
        } else if inner_public_inputs.len() == 2 * STATE_WIDTH {
            (
                RPO_TRACE_WIDTH,
                8usize,
                STATE_WIDTH,
                2 * STATE_WIDTH,
                FieldExtension::None,
            )
        } else {
            // Best-effort fallback for legacy serialized verifier public inputs.
            // Depth-2 decoding prefers v2-encoded public inputs.
            (VERIFIER_TRACE_WIDTH, 0usize, 0usize, 0usize, FieldExtension::None)
        };

        let extension_degree = field_extension_degree(field_extension)?;
        let trace_ood_len = trace_width * extension_degree;
        let constraint_ood_len = constraint_frame_width * extension_degree;
        let ood_len = 2 * (trace_ood_len + constraint_ood_len);

        let (ood_trace_current, ood_quotient_current, ood_trace_next, ood_quotient_next) =
            if num_params == NUM_PARAMS_V4 {
                let ood_start = idx;
                let ood_end = ood_start + ood_len;
                if ood_end > params_start {
                    return Err(format!(
                        "missing OOD frame elements: expected {ood_len}, have {}",
                        params_start.saturating_sub(ood_start)
                    ));
                }
                let ood_slice = &elements[ood_start..ood_end];
                let mut ood_idx = 0usize;
                let take = |slice: &[BaseElement], idx: &mut usize, len: usize| -> Vec<BaseElement> {
                    let start = *idx;
                    let end = start + len;
                    *idx = end;
                    slice[start..end].to_vec()
                };

                (
                    take(ood_slice, &mut ood_idx, trace_ood_len),
                    take(ood_slice, &mut ood_idx, constraint_ood_len),
                    take(ood_slice, &mut ood_idx, trace_ood_len),
                    take(ood_slice, &mut ood_idx, constraint_ood_len),
                )
            } else {
                (Vec::new(), Vec::new(), Vec::new(), Vec::new())
            };

        let ood_end = if num_params == NUM_PARAMS_V4 {
            idx + ood_len
        } else {
            idx
        };

        let fri_elems = &elements[ood_end..params_start];
        if !fri_elems.len().is_multiple_of(DIGEST_WIDTH) {
            return Err(format!(
                "invalid FRI commitments length: {} is not a multiple of {}",
                fri_elems.len(),
                DIGEST_WIDTH
            ));
        }
        let fri_commitments = fri_elems
            .chunks_exact(DIGEST_WIDTH)
            .map(|chunk| slice_to_digest(chunk))
            .collect::<Vec<_>>();

        Ok(Self::new(
            inner_public_inputs,
            inner_pub_inputs_hash,
            trace_commitment,
            constraint_commitment,
            ood_trace_current,
            ood_quotient_current,
            ood_trace_next,
            ood_quotient_next,
            fri_commitments,
            num_queries,
            num_draws,
            trace_partition_size,
            constraint_partition_size,
            blowup_factor,
            fri_folding_factor,
            fri_remainder_max_degree,
            grinding_factor,
            trace_length,
            trace_width,
            constraint_frame_width,
            num_transition_constraints,
            num_assertions,
            field_extension,
        ))
    }
}

impl ToElements<BaseElement> for StarkVerifierPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();

        elements.extend_from_slice(&self.inner_public_inputs);
        elements.extend_from_slice(&self.inner_pub_inputs_hash);
        elements.extend_from_slice(&self.trace_commitment);
        elements.extend_from_slice(&self.constraint_commitment);
        elements.extend_from_slice(&self.ood_trace_current);
        elements.extend_from_slice(&self.ood_quotient_current);
        elements.extend_from_slice(&self.ood_trace_next);
        elements.extend_from_slice(&self.ood_quotient_next);

        for commitment in &self.fri_commitments {
            elements.extend_from_slice(commitment);
        }

        elements.push(BaseElement::new(self.num_queries as u64));
        elements.push(BaseElement::new(self.num_draws as u64));
        elements.push(BaseElement::new(self.trace_partition_size as u64));
        elements.push(BaseElement::new(self.constraint_partition_size as u64));
        elements.push(BaseElement::new(self.blowup_factor as u64));
        elements.push(BaseElement::new(self.fri_folding_factor as u64));
        elements.push(BaseElement::new(self.fri_remainder_max_degree as u64));
        elements.push(BaseElement::new(self.grinding_factor as u64));
        elements.push(BaseElement::new(self.trace_length as u64));
        elements.push(BaseElement::new(self.trace_width as u64));
        elements.push(BaseElement::new(self.constraint_frame_width as u64));
        elements.push(BaseElement::new(self.num_transition_constraints as u64));
        elements.push(BaseElement::new(self.num_assertions as u64));
        elements.push(BaseElement::new(self.field_extension as u64));

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
    inner_constraint_coeffs: ConstraintCompositionCoefficients<BaseElement>,
    inner_deep_coeffs: DeepCompositionCoefficients<BaseElement>,
    inner_fri_alphas: Vec<BaseElement>,
    inner_ood_constraint_eval_1: BaseElement,
    inner_ood_constraint_eval_2: BaseElement,
    trace_width_ext: usize,
    constraint_width_ext: usize,
    num_constraint_coeffs: usize,
    num_deep_coeffs: usize,
    ood_eval_len: usize,
    trace_data_block_starts: Vec<usize>,
    constraint_data_block_starts: Vec<usize>,
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
        //   * capacity carryover (DIGEST_WIDTH)
        //   * rate carryover / resets (2 * DIGEST_WIDTH)
        //   * mask validity + exclusivity (13)
        //   * transcript draws (coeff/z/deep/fri/pos/tape)
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
        assert_eq!(
            pub_inputs.fri_folding_factor,
            2,
            "StarkVerifierAir assumes FRI folding factor 2"
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

        let extension_degree = field_extension_degree(pub_inputs.field_extension)
            .expect("unsupported field extension");
        let trace_width_ext = pub_inputs.trace_width * extension_degree;
        let constraint_width_ext = pub_inputs.constraint_frame_width * extension_degree;
        let num_constraint_coeffs =
            (pub_inputs.num_transition_constraints + pub_inputs.num_assertions) * extension_degree;
        let num_deep_coeffs = trace_width_ext + constraint_width_ext;
        let ood_eval_len = 2 * num_deep_coeffs;

        assert_eq!(
            pub_inputs.ood_trace_current.len(),
            trace_width_ext,
            "OOD trace current length mismatch: expected {trace_width_ext}, got {}",
            pub_inputs.ood_trace_current.len()
        );
        assert_eq!(
            pub_inputs.ood_trace_next.len(),
            trace_width_ext,
            "OOD trace next length mismatch: expected {trace_width_ext}, got {}",
            pub_inputs.ood_trace_next.len()
        );
        assert_eq!(
            pub_inputs.ood_quotient_current.len(),
            constraint_width_ext,
            "OOD quotient current length mismatch: expected {constraint_width_ext}, got {}",
            pub_inputs.ood_quotient_current.len()
        );
        assert_eq!(
            pub_inputs.ood_quotient_next.len(),
            constraint_width_ext,
            "OOD quotient next length mismatch: expected {constraint_width_ext}, got {}",
            pub_inputs.ood_quotient_next.len()
        );

        let constraint_partition_size_base = pub_inputs.constraint_partition_size * extension_degree;
        let trace_layout =
            compute_leaf_layout(trace_width_ext, pub_inputs.trace_partition_size);
        let constraint_layout =
            compute_leaf_layout(constraint_width_ext, constraint_partition_size_base);
        let trace_data_block_starts = trace_layout.data_perm_starts.clone();
        let constraint_data_block_starts = constraint_layout.data_perm_starts.clone();

        let base_boundary_constraints = 3 * DIGEST_WIDTH + 13 + 4 * RATE_WIDTH + 2;
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
        let ood_state_constraints = DIGEST_WIDTH // ood digest constant columns
            + STATE_WIDTH // saved coin-state constant columns
            + ood_eval_len // bind OOD eval inputs to hash segment
            + DIGEST_WIDTH // capture digest at end of OOD hash segment
            + STATE_WIDTH // capture coin state at z boundary
            + STATE_WIDTH // restore coin state (+digest) at deep-start row
            + 1; // OOD constraint consistency check (winter-verifier step 3)

        let transcript_store_constraints = num_constraint_coeffs // capture constraint coeffs
            + num_deep_coeffs // capture deep coeffs
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
            + ood_state_constraints
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
        // (c) Bind OOD evaluation inputs at the start rows of the OOD-hash segment.
        for _ in 0..ood_eval_len {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (d) Capture OOD digest at the end of the OOD-hash segment.
        for _ in 0..DIGEST_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (e) Capture coin state at the z boundary (boundary-gated).
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                boundary_only.clone(),
            ));
        }
        // (f) Restore coin state (+OOD digest) at the first deep-coefficient row.
        for _ in 0..STATE_WIDTH {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (g) OOD constraint consistency check (evaluate inner constraints at z).
        //
        // This constraint is expressed entirely in terms of constant columns (OOD frame + drawn
        // coefficients), so its quotient polynomial is constant (degree 0) once other
        // constant-column constraints hold.
        degrees.push(TransitionConstraintDegree::new(1));

        // --- Transcript draw binding degrees -----------------------------------------------
        // (a) Capture constraint coefficients at their draw boundaries.
        for _ in 0..num_constraint_coeffs {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (b) Capture DEEP coefficients at their draw boundaries.
        for _ in 0..num_deep_coeffs {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![full_cycle]));
        }
        // (c) Capture FRI alphas at their draw boundaries.
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

        let seed_prefix_len = build_context_prefix(&pub_inputs).len();
        let seed_len = seed_prefix_len + input_len;
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

        // Full-carry boundaries between coefficient draw permutations. The coin draws one
        // coefficient per constraint (transition + boundary assertions).
        let num_coeff_perms = num_constraint_coeffs.div_ceil(RATE_WIDTH).max(1);
        if num_coeff_perms > 1 {
            num_assertions += (num_coeff_perms - 1) * 4;
        }

        // reseed(constraint_commitment) boundary masks + reseed word
        num_assertions += 4 + DIGEST_WIDTH;

        // z-draw boundary masks after constraint reseed permutation
        num_assertions += 4;

        // OOD evaluation digest sponge (Rpo256::hash_elements over merged OOD evaluations).
        let num_ood_perms = ood_eval_len.div_ceil(RATE_WIDTH);
        num_assertions += CAPACITY_WIDTH; // sponge init at start of OOD hash segment
        if num_ood_perms > 0 {
            num_assertions += num_ood_perms * 4; // carry/reset masks for each OOD hash perm
        }

        // Deep coefficient draw boundaries after OOD reseed.
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
        let trace_leaf_blocks =
            compute_leaf_perms(trace_width_ext, pub_inputs.trace_partition_size);
        let constraint_leaf_blocks =
            compute_leaf_perms(constraint_width_ext, constraint_partition_size_base);
        let leaf_chain_count = |leaf_len: usize, partition_size: usize| {
            if leaf_len == 0 {
                return 0usize;
            }
            if partition_size >= leaf_len {
                return 1usize;
            }
            let num_partitions = leaf_len.div_ceil(partition_size);
            num_partitions + 1
        };
        let fri_leaf_blocks = 2usize.div_ceil(RATE_WIDTH).max(1);
        let mut merkle_perms_per_query =
            trace_leaf_blocks + depth_trace + constraint_leaf_blocks + depth_trace;
        let replay_draws_per_query =
            leaf_chain_count(trace_width_ext, pub_inputs.trace_partition_size)
                + leaf_chain_count(constraint_width_ext, constraint_partition_size_base);
        merkle_perms_per_query += replay_draws_per_query;
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
        let remainder_hash_perms = (!pub_inputs.fri_commitments.is_empty()) as usize;
        if remainder_hash_perms > 0 && expected_active_perms + remainder_hash_perms <= total_perms {
            num_assertions += CAPACITY_WIDTH; // sponge init
            num_assertions += DIGEST_WIDTH; // digest == remainder commitment
        }

        // Binding accumulator must end at 1.
        num_assertions += 1;

        let ood_digest = compute_ood_digest(&pub_inputs);
        let (inner_constraint_coeffs, expected_z, inner_deep_coeffs, inner_fri_alphas) =
            compute_expected_transcript_draws(&pub_inputs, ood_digest)
                .expect("failed to reconstruct inner transcript");

        let (inner_ood_constraint_eval_1, inner_ood_constraint_eval_2) =
            match inner_proof_kind(&pub_inputs) {
                InnerProofKind::RpoAir => compute_rpo_ood_consistency(
                    &pub_inputs,
                    &inner_constraint_coeffs,
                    expected_z,
                    g_trace,
                )
                .expect("failed to evaluate RPO constraints at z"),
                InnerProofKind::TransactionAir => compute_transaction_ood_consistency(
                    &pub_inputs,
                    &inner_constraint_coeffs,
                    expected_z,
                )
                .expect("failed to evaluate transaction constraints at z"),
                InnerProofKind::StarkVerifierAir => {
                    panic!("non-RPO recursion for verifier proofs is not supported yet")
                }
            };
        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self {
            context,
            pub_inputs,
            expected_z,
            inner_constraint_coeffs,
            inner_deep_coeffs,
            inner_fri_alphas,
            inner_ood_constraint_eval_1,
            inner_ood_constraint_eval_2,
            trace_width_ext,
            constraint_width_ext,
            num_constraint_coeffs,
            num_deep_coeffs,
            ood_eval_len,
            trace_data_block_starts,
            constraint_data_block_starts,
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
        //  query_reset_mask, trace_leaf_row_masks..., constraint_leaf_row_masks...,
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
        let num_ood_perms = self.ood_eval_len.div_ceil(RATE_WIDTH);
        let ood_eval_row_masks = &periodic_values[p..p + num_ood_perms];
        p += num_ood_perms;
        let _deep_start_row_mask = periodic_values[p];
        p += 1;
        let num_coeff_perms = self.num_constraint_coeffs.div_ceil(RATE_WIDTH);
        let coeff_end_masks = &periodic_values[p..p + num_coeff_perms];
        p += num_coeff_perms;
        let num_deep_perms = self.num_deep_coeffs.div_ceil(RATE_WIDTH);
        let deep_end_masks = &periodic_values[p..p + num_deep_perms];
        p += num_deep_perms;
        let fri_alpha_end_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;

        // --- DEEP + FRI periodic selectors ------------------------------------------------
        let query_reset_mask = periodic_values[p];
        p += 1;
        let trace_data_blocks = self.trace_data_block_starts.len();
        let trace_leaf_row_masks = &periodic_values[p..p + trace_data_blocks];
        p += trace_data_blocks;
        let constraint_data_blocks = self.constraint_data_block_starts.len();
        let constraint_leaf_row_masks = &periodic_values[p..p + constraint_data_blocks];
        p += constraint_data_blocks;
        let trace_merkle_bit_mask = periodic_values[p];
        p += 1;
        let msb_capture_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let fri_leaf_row_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let fri_leaf_any_row_mask = periodic_values[p];
        p += 1;
        let remainder_hash_row0_mask = periodic_values[p];
        // Note: final p += 1 omitted since p is not used after this point

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
        result[idx + 4] =
            boundary_mask * current[COL_COIN_SAVE_MASK] * (current[COL_COIN_SAVE_MASK] - one);
        result[idx + 5] = boundary_mask
            * current[COL_COIN_RESTORE_MASK]
            * (current[COL_COIN_RESTORE_MASK] - one);
        result[idx + 6] =
            boundary_mask * current[COL_TAPE_MASK] * (current[COL_TAPE_MASK] - one);
        idx += 7;

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
        let coin_save_mask = current[COL_COIN_SAVE_MASK];
        let coin_restore_mask = current[COL_COIN_RESTORE_MASK];

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

        // Tape capture: when enabled, the tape values must match the permutation's rate output.
        let tape_mask = current[COL_TAPE_MASK];
        for i in 0..TAPE_WIDTH {
            let expected = current[COL_TAPE_VALUES_START + i];
            result[idx + i] = boundary_mask * tape_mask * (current[RATE_START + i] - expected);
        }
        idx += TAPE_WIDTH;

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

        // Bind OOD evaluation inputs at the start rows of the OOD-hash segment.
        for i in 0..self.ood_eval_len {
            let block = i / RATE_WIDTH;
            let offset = i % RATE_WIDTH;
            let mask = ood_eval_row_masks[block];
            let expected = if i < self.trace_width_ext {
                self.pub_inputs.ood_trace_current[i]
            } else if i < self.trace_width_ext + self.constraint_width_ext {
                self.pub_inputs.ood_quotient_current[i - self.trace_width_ext]
            } else if i < 2 * self.trace_width_ext + self.constraint_width_ext {
                self.pub_inputs.ood_trace_next[i - self.trace_width_ext - self.constraint_width_ext]
            } else {
                self.pub_inputs.ood_quotient_next[i
                    - (2 * self.trace_width_ext + self.constraint_width_ext)]
            };
            result[idx + i] = mask * (current[RATE_START + offset] - E::from(expected));
        }
        idx += self.ood_eval_len;

        // Capture the OOD digest at the end of the OOD-hash segment (digest is in the first
        // half of the rate: state[4..7]).
        for i in 0..DIGEST_WIDTH {
            let digest_col = current[COL_OOD_DIGEST_START + i];
            let digest_out = current[RATE_START + i];
            result[idx + i] = ood_digest_capture_mask * (digest_col - digest_out);
        }
        idx += DIGEST_WIDTH;

        // Capture coin state at the z boundary row so it can be restored after hashing OOD
        // evaluations. This is enforced only at the permutation boundary where
        // `coin_save_mask = 1`.
        for i in 0..STATE_WIDTH {
            let saved = current[COL_SAVED_COIN_START + i];
            result[idx + i] = boundary_mask * coin_save_mask * (saved - current[i]);
        }
        idx += STATE_WIDTH;

        // Restore the coin state (and apply the OOD reseed) at the first row of the deep
        // coefficient segment.
        //
        // For a reseed, the first half of the rate (state[4..7]) is incremented by the digest,
        // while the rest of the state is preserved.
        for i in 0..CAPACITY_WIDTH {
            let saved = current[COL_SAVED_COIN_START + i];
            result[idx + i] = coin_restore_mask * (current[i] - saved);
        }
        for i in 0..DIGEST_WIDTH {
            let saved = current[COL_SAVED_COIN_START + RATE_START + i];
            let digest = current[COL_OOD_DIGEST_START + i];
            let expected = saved + digest;
            result[idx + CAPACITY_WIDTH + i] =
                coin_restore_mask * (current[RATE_START + i] - expected);
        }
        for i in 0..DIGEST_WIDTH {
            let saved = current[COL_SAVED_COIN_START + RATE_START + DIGEST_WIDTH + i];
            result[idx + CAPACITY_WIDTH + DIGEST_WIDTH + i] =
                coin_restore_mask * (current[RATE_START + DIGEST_WIDTH + i] - saved);
        }
        idx += STATE_WIDTH;

        // --------------------------------------------------------------------
        // OOD consistency check (winter-verifier step 3)
        // --------------------------------------------------------------------
        //
        // Enforce that the inner proof's OOD constraint frame at z (quotient composition columns)
        // is consistent with evaluating the inner AIR constraints at z using transcript-drawn
        // constraint composition coefficients.
        //
        // This is required for soundness; without it, a prover could commit to an arbitrary low
        // degree constraint-composition polynomial unrelated to the trace.
        result[idx] = E::from(self.inner_ood_constraint_eval_1)
            - E::from(self.inner_ood_constraint_eval_2);
        idx += 1;

        // --------------------------------------------------------------------
        // Transcript draw binding
        // --------------------------------------------------------------------

        // Capture constraint composition coefficients at their draw boundaries.
        for coeff_idx in 0..self.num_constraint_coeffs {
            let block = coeff_idx / RATE_WIDTH;
            let offset = coeff_idx % RATE_WIDTH;
            let mask = coeff_end_masks[block];
            let expected = if coeff_idx < self.inner_constraint_coeffs.transition.len() {
                self.inner_constraint_coeffs.transition[coeff_idx]
            } else {
                let idx = coeff_idx - self.inner_constraint_coeffs.transition.len();
                self.inner_constraint_coeffs.boundary[idx]
            };
            let drawn = current[RATE_START + offset];
            result[idx + coeff_idx] = mask * (drawn - E::from(expected));
        }
        idx += self.num_constraint_coeffs;

        // Capture DEEP coefficients at their draw boundaries.
        for deep_idx in 0..self.num_deep_coeffs {
            let block = deep_idx / RATE_WIDTH;
            let offset = deep_idx % RATE_WIDTH;
            let mask = deep_end_masks[block];
            let expected = if deep_idx < self.inner_deep_coeffs.trace.len() {
                self.inner_deep_coeffs.trace[deep_idx]
            } else {
                let idx = deep_idx - self.inner_deep_coeffs.trace.len();
                self.inner_deep_coeffs.constraints[idx]
            };
            let drawn = current[RATE_START + offset];
            result[idx + deep_idx] = mask * (drawn - E::from(expected));
        }
        idx += self.num_deep_coeffs;

        // Capture FRI alphas at their draw boundaries.
        for layer_idx in 0..num_fri_layers {
            let mask = fri_alpha_end_masks[layer_idx];
            let expected = self.inner_fri_alphas[layer_idx];
            let drawn = current[RATE_START];
            result[idx + layer_idx] = mask * (drawn - E::from(expected));
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

        let mut t1_delta = E::ZERO;
        let mut t2_delta = E::ZERO;
        for (block_idx, start_idx) in self.trace_data_block_starts.iter().enumerate() {
            let mask = trace_leaf_row_masks[block_idx];
            let remaining = self.trace_width_ext.saturating_sub(*start_idx);
            let block_len = remaining.min(RATE_WIDTH);
            let mut block_t1 = E::ZERO;
            let mut block_t2 = E::ZERO;
            for j in 0..block_len {
                let idx = start_idx + j;
                let coeff = E::from(self.inner_deep_coeffs.trace[idx]);
                let trace_val = current[RATE_START + j];
                let ood_z = E::from(self.pub_inputs.ood_trace_current[idx]);
                let ood_zg = E::from(self.pub_inputs.ood_trace_next[idx]);
                block_t1 += coeff * (trace_val - ood_z);
                block_t2 += coeff * (trace_val - ood_zg);
            }
            t1_delta += mask * block_t1;
            t2_delta += mask * block_t2;
        }

        let mut c1_delta = E::ZERO;
        let mut c2_delta = E::ZERO;
        for (block_idx, start_idx) in self.constraint_data_block_starts.iter().enumerate() {
            let mask = constraint_leaf_row_masks[block_idx];
            let remaining = self.constraint_width_ext.saturating_sub(*start_idx);
            let block_len = remaining.min(RATE_WIDTH);
            let mut block_c1 = E::ZERO;
            let mut block_c2 = E::ZERO;
            for j in 0..block_len {
                let idx = start_idx + j;
                let coeff = E::from(self.inner_deep_coeffs.constraints[idx]);
                let val = current[RATE_START + j];
                let ood_z = E::from(self.pub_inputs.ood_quotient_current[idx]);
                let ood_zg = E::from(self.pub_inputs.ood_quotient_next[idx]);
                block_c1 += coeff * (val - ood_z);
                block_c2 += coeff * (val - ood_zg);
            }
            c1_delta += mask * block_c1;
            c2_delta += mask * block_c2;
        }

        let reset_term_t1 = query_reset_mask * (E::ZERO - t1);
        let reset_term_t2 = query_reset_mask * (E::ZERO - t2);
        let reset_term_c1 = query_reset_mask * (E::ZERO - c1);
        let reset_term_c2 = query_reset_mask * (E::ZERO - c2);

        result[idx] = t1_next - t1 - reset_term_t1 - t1_delta;
        result[idx + 1] = t2_next - t2 - reset_term_t2 - t2_delta;
        result[idx + 2] = c1_next - c1 - reset_term_c1 - c1_delta;
        result[idx + 3] = c2_next - c2 - reset_term_c2 - c2_delta;
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
            let alpha = E::from(self.inner_fri_alphas[layer_idx]);
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
        // idx is intentionally not incremented here: this is the final constraint slot.
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
        let num_coeff_perms = self.num_constraint_coeffs.div_ceil(RATE_WIDTH).max(1);
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
        let num_deep_coeffs = self.num_deep_coeffs;
        let ood_eval_len = self.ood_eval_len;
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
                for (i, value) in first_commitment.iter().copied().enumerate() {
                    assertions.push(Assertion::single(
                        COL_RESEED_WORD_START + i,
                        boundary_row,
                        value,
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
            for (i, value) in next_commitment.iter().copied().enumerate() {
                assertions.push(Assertion::single(
                    COL_RESEED_WORD_START + i,
                    boundary_row,
                    value,
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

            let mut perm_idx = pos_start_perm_idx;
            let mut remaining_draws = self.pub_inputs.num_draws;
            for k in 0..num_pos_perms {
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

                perm_idx += 1;
                let draws_here = if k == 0 {
                    remaining_draws.min(RATE_WIDTH - 1)
                } else {
                    remaining_draws.min(RATE_WIDTH)
                };
                remaining_draws = remaining_draws.saturating_sub(draws_here);
                perm_idx += draws_here;
                if remaining_draws == 0 {
                    break;
                }
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

        let extension_degree = field_extension_degree(self.pub_inputs.field_extension)
            .expect("unsupported field extension");
        let trace_leaf_len = self.trace_width_ext;
        let constraint_leaf_len = self.constraint_width_ext;
        let constraint_partition_size_base =
            self.pub_inputs.constraint_partition_size * extension_degree;
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
        let leaf_chain_count = |len: usize, partition_size: usize| -> usize {
            if len == 0 {
                return 0;
            }
            if partition_size >= len {
                return 1;
            }
            let num_partitions = len.div_ceil(partition_size);
            num_partitions + 1
        };

        let trace_leaf_perms =
            compute_leaf_perms(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_leaf_perms =
            compute_leaf_perms(constraint_leaf_len, constraint_partition_size_base);
        let fri_leaf_perms = fri_leaf_len.div_ceil(RATE_WIDTH).max(1);

        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        let replay_draws_per_query =
            leaf_chain_count(trace_leaf_len, self.pub_inputs.trace_partition_size)
                + leaf_chain_count(constraint_leaf_len, constraint_partition_size_base);
        merkle_perms_per_query += replay_draws_per_query;
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
                    perm_idx += 1; // replay draw perm before this leaf-hash chain
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
                    perm_idx += 1; // replay draw perm before this partition hash
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
                perm_idx += 1; // replay draw perm before merged digest hash
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
                    constraint_partition_size_base,
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
        let remainder_hash_perms = (!self.pub_inputs.fri_commitments.is_empty()) as usize;
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
            for (i, value) in commitment.iter().copied().enumerate() {
                assertions.push(Assertion::single(CAPACITY_WIDTH + i, boundary_row, value));
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

        let seed_len = build_context_prefix(&self.pub_inputs).len() + input_len;
        let num_seed_blocks = seed_len.div_ceil(RATE_WIDTH).max(1);

        let num_coeff_perms = self.num_constraint_coeffs.div_ceil(RATE_WIDTH).max(1);
        let num_deep_perms = self.num_deep_coeffs.div_ceil(RATE_WIDTH);
        let num_ood_perms = self.ood_eval_len.div_ceil(RATE_WIDTH);

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
        let mut deep_end_masks = vec![vec![BaseElement::ZERO; total_rows]; num_deep_perms];

        // DEEP + FRI masks (all sparse, full-length).
        let mut query_reset_mask = vec![BaseElement::ZERO; total_rows];
        let mut trace_merkle_bit_mask = vec![BaseElement::ZERO; total_rows];
        let mut msb_capture_masks = vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers];
        let mut fri_leaf_row_masks = vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers];
        let mut fri_leaf_any_row_mask = vec![BaseElement::ZERO; total_rows];
        let mut remainder_hash_row0_mask = vec![BaseElement::ZERO; total_rows];

        let extension_degree = field_extension_degree(self.pub_inputs.field_extension)
            .expect("unsupported field extension");
        let trace_leaf_len = self.trace_width_ext;
        let constraint_leaf_len = self.constraint_width_ext;
        let constraint_partition_size_base =
            self.pub_inputs.constraint_partition_size * extension_degree;
        let fri_leaf_len = 2usize;

        let trace_layout =
            compute_leaf_layout(trace_leaf_len, self.pub_inputs.trace_partition_size);
        let constraint_layout =
            compute_leaf_layout(constraint_leaf_len, constraint_partition_size_base);
        let trace_leaf_perms = trace_layout.total_perms;
        let constraint_leaf_perms = constraint_layout.total_perms;
        let trace_leaf_chain = &trace_layout.chain_flags;
        let constraint_leaf_chain = &constraint_layout.chain_flags;
        let trace_data_perm_map = &trace_layout.data_perm_map;
        let constraint_data_perm_map = &constraint_layout.data_perm_map;
        let mut trace_leaf_row_masks = vec![
            vec![BaseElement::ZERO; total_rows];
            trace_layout.data_perm_starts.len()
        ];
        let mut constraint_leaf_row_masks = vec![
            vec![BaseElement::ZERO; total_rows];
            constraint_layout.data_perm_starts.len()
        ];
        let fri_leaf_perms = fri_leaf_len.div_ceil(RATE_WIDTH).max(1);
        let trace_leaf_chains = trace_leaf_chain.iter().filter(|v| !**v).count();
        let constraint_leaf_chains = constraint_leaf_chain.iter().filter(|v| !**v).count();

        let lde_domain_size = self.pub_inputs.trace_length * self.pub_inputs.blowup_factor;
        let depth_trace = if lde_domain_size == 0 {
            0
        } else {
            lde_domain_size.trailing_zeros() as usize
        };

        let mut merkle_perms_per_query =
            trace_leaf_perms + depth_trace + constraint_leaf_perms + depth_trace;
        let replay_draws_per_query = trace_leaf_chains + constraint_leaf_chains;
        merkle_perms_per_query += replay_draws_per_query;
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
                let trace_chain_start =
                    |rel_perm: usize| rel_perm == 0 || !trace_leaf_chain[rel_perm - 1];
                let constraint_chain_start =
                    |rel_perm: usize| rel_perm == 0 || !constraint_leaf_chain[rel_perm - 1];
                let mut deep_draw_idx = 0usize;

                // --- Trace leaf hashing -----------------------------------------------------
                let mut rel_perm = 0usize;
                while rel_perm < trace_leaf_perms {
                    if trace_chain_start(rel_perm) {
                        let draw_row0 = perm_idx * ROWS_PER_PERMUTATION;
                        let draw_boundary = draw_row0 + ROWS_PER_PERMUTATION - 1;
                        if deep_draw_idx < num_deep_perms {
                            deep_end_masks[deep_draw_idx][draw_boundary] = BaseElement::ONE;
                        }
                        perm_idx += 1;
                        deep_draw_idx += 1;
                    }
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                    if row0 < total_rows {
                        if let Some(data_idx) = trace_data_perm_map[rel_perm] {
                            trace_leaf_row_masks[data_idx][row0] = BaseElement::ONE;
                        }
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
                    rel_perm += 1;
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
                let mut rel_perm = 0usize;
                while rel_perm < constraint_leaf_perms {
                    if constraint_chain_start(rel_perm) {
                        let draw_row0 = perm_idx * ROWS_PER_PERMUTATION;
                        let draw_boundary = draw_row0 + ROWS_PER_PERMUTATION - 1;
                        if deep_draw_idx < num_deep_perms {
                            deep_end_masks[deep_draw_idx][draw_boundary] = BaseElement::ONE;
                        }
                        perm_idx += 1;
                        deep_draw_idx += 1;
                    }
                    let row0 = perm_idx * ROWS_PER_PERMUTATION;
                    let boundary = row0 + ROWS_PER_PERMUTATION - 1;
                    if row0 < total_rows {
                        if let Some(data_idx) = constraint_data_perm_map[rel_perm] {
                            constraint_leaf_row_masks[data_idx][row0] = BaseElement::ONE;
                        }
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
                    rel_perm += 1;
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
                (8..ROWS_PER_PERMUTATION - 1).contains(&local_row) as u64,
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
        for (k, mask) in ood_eval_row_masks.iter_mut().enumerate() {
            let row0 = (ood_start_perm_idx + k) * ROWS_PER_PERMUTATION;
            if row0 < total_rows {
                mask[row0] = BaseElement::ONE;
            }
        }

        // Sparse, full-length masks for capturing transcript-derived coefficients.
        let coeff_start_perm_idx = num_pi_blocks + num_seed_blocks + 1;
        let mut coeff_end_masks = vec![vec![BaseElement::ZERO; total_rows]; num_coeff_perms];
        for (k, mask) in coeff_end_masks.iter_mut().enumerate() {
            let perm_idx = coeff_start_perm_idx + k;
            let boundary = perm_idx * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
            if boundary < total_rows {
                mask[boundary] = BaseElement::ONE;
            }
        }

        for (k, mask) in deep_end_masks.iter_mut().enumerate() {
            let perm_idx = deep_start_perm_idx + k;
            let boundary = perm_idx * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
            if boundary < total_rows {
                mask[boundary] = BaseElement::ONE;
            }
        }

        let fri_start_perm_idx = deep_start_perm_idx + num_deep_perms;
        let mut fri_alpha_end_masks = vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers];
        for (layer_idx, mask) in fri_alpha_end_masks.iter_mut().enumerate() {
            let perm_idx = fri_start_perm_idx + layer_idx;
            let boundary = perm_idx * ROWS_PER_PERMUTATION + (ROWS_PER_PERMUTATION - 1);
            if boundary < total_rows {
                mask[boundary] = BaseElement::ONE;
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
            } else if local_row.is_multiple_of(2) {
                1
            } else {
                2
            };
            half_round_type.push(BaseElement::new(val));

            let constants = if local_row >= 14 {
                [BaseElement::ZERO; STATE_WIDTH]
            } else if local_row.is_multiple_of(2) {
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
        for col in trace_leaf_row_masks {
            result.push(col);
        }
        for col in constraint_leaf_row_masks {
            result.push(col);
        }
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

#[derive(Clone, Debug)]
pub(crate) struct LeafLayout {
    total_perms: usize,
    chain_flags: Vec<bool>,
    pub(crate) data_perm_starts: Vec<usize>,
    data_perm_map: Vec<Option<usize>>,
}

pub(crate) fn compute_leaf_layout(len: usize, partition_size: usize) -> LeafLayout {
    let hash_perms = |input_len: usize| input_len.div_ceil(RATE_WIDTH).max(1);
    if len == 0 {
        return LeafLayout {
            total_perms: 0,
            chain_flags: Vec::new(),
            data_perm_starts: Vec::new(),
            data_perm_map: Vec::new(),
        };
    }

    if partition_size >= len {
        let perms = hash_perms(len);
        let mut chain_flags = vec![false; perms];
        for value in chain_flags.iter_mut().take(perms.saturating_sub(1)) {
            *value = true;
        }
        let data_perm_starts = (0..perms).map(|i| i * RATE_WIDTH).collect::<Vec<_>>();
        let data_perm_map = (0..perms).map(Some).collect::<Vec<_>>();
        return LeafLayout {
            total_perms: perms,
            chain_flags,
            data_perm_starts,
            data_perm_map,
        };
    }

    let mut chain_flags = Vec::new();
    let mut data_perm_starts = Vec::new();
    let mut data_perm_map = Vec::new();
    let mut remaining = len;
    let mut offset = 0usize;
    let mut data_idx = 0usize;

    while remaining > 0 {
        let part_len = remaining.min(partition_size);
        let perms = hash_perms(part_len);
        for perm in 0..perms {
            let start = offset + perm * RATE_WIDTH;
            data_perm_starts.push(start);
            data_perm_map.push(Some(data_idx));
            data_idx += 1;
            chain_flags.push(perm + 1 < perms);
        }
        remaining -= part_len;
        offset += part_len;
    }

    let num_partitions = len.div_ceil(partition_size);
    let merged_len = num_partitions * DIGEST_WIDTH;
    let merged_perms = hash_perms(merged_len);
    for perm in 0..merged_perms {
        data_perm_map.push(None);
        chain_flags.push(perm + 1 < merged_perms);
    }

    LeafLayout {
        total_perms: chain_flags.len(),
        chain_flags,
        data_perm_starts,
        data_perm_map,
    }
}

pub(crate) fn compute_inner_ood_constants(
    pub_inputs: &StarkVerifierPublicInputs,
    expected_z: BaseElement,
    g_trace: BaseElement,
) -> (
    [BaseElement; 1 + STATE_WIDTH],
    BaseElement,
    [BaseElement; 2],
    [BaseElement; 8],
) {
    assert_eq!(
        pub_inputs.trace_length, ROWS_PER_PERMUTATION,
        "StarkVerifierAir currently assumes RpoAir trace length {} (got {})",
        ROWS_PER_PERMUTATION, pub_inputs.trace_length
    );
    assert_eq!(
        pub_inputs.inner_public_inputs.len(),
        2 * STATE_WIDTH,
        "StarkVerifierAir currently assumes RpoAir public inputs length {} (got {})",
        2 * STATE_WIDTH,
        pub_inputs.inner_public_inputs.len()
    );

    let z = expected_z;
    let n = pub_inputs.trace_length;
    let g_last = g_trace.exp(((n - 1) as u64).into());

    let z_to_n = z.exp((n as u64).into());
    let transition_divisor = (z_to_n - BaseElement::ONE) / (z - g_last);
    let transition_divisor_inv_at_z = transition_divisor.inv();

    let boundary_inv_at_z = [(z - BaseElement::ONE).inv(), (z - g_last).inv()];

    let mut ood_constraint_weights = [BaseElement::ZERO; 8];
    ood_constraint_weights[0] = BaseElement::ONE;
    for i in 1..ood_constraint_weights.len() {
        ood_constraint_weights[i] = ood_constraint_weights[i - 1] * z_to_n;
    }

    let rpo_periodic_at_z = compute_rpo_periodic_at_point(z);

    (
        rpo_periodic_at_z,
        transition_divisor_inv_at_z,
        boundary_inv_at_z,
        ood_constraint_weights,
    )
}

pub(crate) fn field_extension_degree(field_extension: FieldExtension) -> Result<usize, String> {
    match field_extension {
        FieldExtension::None => Ok(1),
        FieldExtension::Quadratic => Ok(2),
        FieldExtension::Cubic => Ok(3),
    }
}

fn compute_rpo_periodic_at_point(x: BaseElement) -> [BaseElement; 1 + STATE_WIDTH] {
    let cycle_len = ROWS_PER_PERMUTATION;
    let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(cycle_len);
    let eval_column = |values: Vec<BaseElement>| -> BaseElement {
        let mut poly = values;
        fft::interpolate_poly(&mut poly, &inv_twiddles);
        polynom::eval(&poly, x)
    };

    let mut half_round_type_values = Vec::with_capacity(cycle_len);
    for row in 0..cycle_len {
        let val = if row >= 14 {
            0
        } else if row % 2 == 0 {
            1
        } else {
            2
        };
        half_round_type_values.push(BaseElement::new(val));
    }

    let mut result = [BaseElement::ZERO; 1 + STATE_WIDTH];
    result[0] = eval_column(half_round_type_values);

    for elem_idx in 0..STATE_WIDTH {
        let mut values = Vec::with_capacity(cycle_len);
        for row in 0..cycle_len {
            let val = if row >= cycle_len - 1 {
                BaseElement::ZERO
            } else if row % 2 == 0 {
                let round = row / 2;
                if round < NUM_ROUNDS {
                    ARK1[round][elem_idx]
                } else {
                    BaseElement::ZERO
                }
            } else {
                let round = row / 2;
                if round < NUM_ROUNDS {
                    ARK2[round][elem_idx]
                } else {
                    BaseElement::ZERO
                }
            };
            values.push(val);
        }

        result[1 + elem_idx] = eval_column(values);
    }

    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InnerProofKind {
    RpoAir,
    TransactionAir,
    StarkVerifierAir,
}

fn inner_proof_kind(pub_inputs: &StarkVerifierPublicInputs) -> InnerProofKind {
    if pub_inputs.inner_public_inputs.len() == 2 * STATE_WIDTH {
        InnerProofKind::RpoAir
    } else if pub_inputs.inner_public_inputs.len() == transaction_public_inputs_len() {
        InnerProofKind::TransactionAir
    } else {
        InnerProofKind::StarkVerifierAir
    }
}

fn transaction_public_inputs_len() -> usize {
    (transaction_circuit::constants::MAX_INPUTS + transaction_circuit::constants::MAX_OUTPUTS) * 5
        + 24
}

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
    let trace_width = pub_inputs.trace_width;
    let num_constraints = pub_inputs.num_transition_constraints + pub_inputs.num_assertions;

    // TraceInfo element 0 encodes: main_width << 8 | num_aux_segments (0).
    let trace_info0 = BaseElement::new(((trace_width as u32) << 8) as u64);
    let trace_info1 = BaseElement::new(pub_inputs.trace_length as u64);

    // Goldilocks modulus bytes split into 2 elements:
    // low half = 1, high half = 2^32 - 1.
    let modulus0 = BaseElement::ONE;
    let modulus1 = BaseElement::new(u64::from(u32::MAX));

    // Inner proof constraints count (transition + boundary).
    let num_constraints = BaseElement::new(num_constraints as u64);

    // ProofOptions packed element (see `winter_air::ProofOptions::to_elements`):
    // [field_extension, fri_folding_factor, fri_remainder_max_degree, blowup_factor]
    //
    // NOTE: `FieldExtension` is 1-based in Winterfell (`None = 1`).
    let options0 = BaseElement::new(
        pub_inputs.blowup_factor as u64
            + ((pub_inputs.fri_remainder_max_degree as u64) << 8)
            + ((pub_inputs.fri_folding_factor as u64) << 16)
            + ((pub_inputs.field_extension as u64) << 24),
    );

    let grinding_factor = BaseElement::new(pub_inputs.grinding_factor as u64);
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
    compute_expected_constraint_coeffs_and_z(pub_inputs).1
}

fn compute_expected_constraint_coeffs_and_z(
    pub_inputs: &StarkVerifierPublicInputs,
) -> (ConstraintCompositionCoefficients<BaseElement>, BaseElement) {
    let (coeffs, z, _, _) = compute_expected_transcript_draws(pub_inputs, compute_ood_digest(pub_inputs))
        .expect("failed to reconstruct transcript");
    (coeffs, z)
}

pub(crate) fn compute_ood_digest(
    pub_inputs: &StarkVerifierPublicInputs,
) -> [BaseElement; DIGEST_WIDTH] {
    let mut ood_evals = Vec::with_capacity(
        pub_inputs.ood_trace_current.len()
            + pub_inputs.ood_quotient_current.len()
            + pub_inputs.ood_trace_next.len()
            + pub_inputs.ood_quotient_next.len(),
    );
    ood_evals.extend_from_slice(&pub_inputs.ood_trace_current);
    ood_evals.extend_from_slice(&pub_inputs.ood_quotient_current);
    ood_evals.extend_from_slice(&pub_inputs.ood_trace_next);
    ood_evals.extend_from_slice(&pub_inputs.ood_quotient_next);

    let digest = Rpo256::hash_elements(&ood_evals);
    [digest[0], digest[1], digest[2], digest[3]]
}

pub(crate) fn compute_expected_transcript_draws(
    pub_inputs: &StarkVerifierPublicInputs,
    ood_digest: [BaseElement; DIGEST_WIDTH],
) -> Result<
    (
        ConstraintCompositionCoefficients<BaseElement>,
        BaseElement,
        DeepCompositionCoefficients<BaseElement>,
        Vec<BaseElement>,
    ),
    String,
> {
    if pub_inputs.field_extension != FieldExtension::None {
        return Err("recursive verifier only supports base-field transcript draws".to_string());
    }

    // Transcript seed = hash(context_prefix || inner_public_inputs).
    let mut seed_elems = build_context_prefix(pub_inputs);
    seed_elems.extend_from_slice(&pub_inputs.inner_public_inputs);
    let mut coin = <RpoRandomCoin as RandomCoin>::new(&seed_elems);
    coin.reseed(Word::new(pub_inputs.trace_commitment));

    let constraint_coeffs = ConstraintCompositionCoefficients::draw_linear(
        &mut coin,
        pub_inputs.num_transition_constraints,
        pub_inputs.num_assertions,
    )
    .map_err(|e| format!("failed to draw constraint coeffs: {e}"))?;

    // Reseed with constraint commitment and draw z.
    coin.reseed(Word::new(pub_inputs.constraint_commitment));
    let z = coin
        .draw()
        .map_err(|e| format!("failed to draw z: {e}"))?;

    // Reseed with OOD digest and draw DEEP coefficients.
    coin.reseed(Word::new(ood_digest));
    let deep_coeffs = DeepCompositionCoefficients::draw_linear(
        &mut coin,
        pub_inputs.trace_width,
        pub_inputs.constraint_frame_width,
    )
    .map_err(|e| format!("failed to draw deep coeffs: {e}"))?;

    // FRI commit phase: reseed with each layer commitment and draw alpha.
    let num_fri_layers = pub_inputs.fri_commitments.len().saturating_sub(1);
    let mut fri_alphas = Vec::with_capacity(num_fri_layers);
    for commitment in pub_inputs.fri_commitments.iter().take(num_fri_layers) {
        coin.reseed(Word::new(*commitment));
        let alpha: BaseElement = coin
            .draw()
            .map_err(|e| format!("failed to draw FRI alpha: {e}"))?;
        fri_alphas.push(alpha);
    }

    Ok((constraint_coeffs, z, deep_coeffs, fri_alphas))
}

fn compute_ood_constraint_eval_2(
    ood_quotient_current: &[BaseElement],
    z: BaseElement,
    trace_length: usize,
) -> BaseElement {
    if ood_quotient_current.is_empty() {
        return BaseElement::ZERO;
    }

    let z_to_n = z.exp((trace_length as u64).into());
    let mut weight = BaseElement::ONE;
    let mut acc = BaseElement::ZERO;
    for value in ood_quotient_current {
        acc += weight * *value;
        weight *= z_to_n;
    }
    acc
}

pub(crate) fn compute_rpo_ood_consistency(
    pub_inputs: &StarkVerifierPublicInputs,
    constraint_coeffs: &ConstraintCompositionCoefficients<BaseElement>,
    expected_z: BaseElement,
    g_trace: BaseElement,
) -> Result<(BaseElement, BaseElement), String> {
    if constraint_coeffs.transition.len() != STATE_WIDTH {
        return Err(format!(
            "RPO transition coeff length mismatch: expected {}, got {}",
            STATE_WIDTH,
            constraint_coeffs.transition.len()
        ));
    }
    if constraint_coeffs.boundary.len() != 2 * STATE_WIDTH {
        return Err(format!(
            "RPO boundary coeff length mismatch: expected {}, got {}",
            2 * STATE_WIDTH,
            constraint_coeffs.boundary.len()
        ));
    }

    let (rpo_periodic_at_z, transition_div_inv, boundary_div_inv, _ood_weights) =
        compute_inner_ood_constants(pub_inputs, expected_z, g_trace);
    let half_round_type = rpo_periodic_at_z[0];
    let ark: [BaseElement; STATE_WIDTH] =
        core::array::from_fn(|i| rpo_periodic_at_z[1 + i]);

    let ood_trace_z = &pub_inputs.ood_trace_current;
    let ood_trace_zg = &pub_inputs.ood_trace_next;
    if ood_trace_z.len() < STATE_WIDTH || ood_trace_zg.len() < STATE_WIDTH {
        return Err("RPO OOD trace frame is shorter than state width".to_string());
    }

    let one = BaseElement::ONE;
    let two = one + one;
    let is_forward = half_round_type * (two - half_round_type);
    let is_inverse = half_round_type * (half_round_type - one);
    let is_padding = (one - half_round_type) * (two - half_round_type);

    let mut t_combined = BaseElement::ZERO;
    for i in 0..STATE_WIDTH {
        let mut mds_res = BaseElement::ZERO;
        for j in 0..STATE_WIDTH {
            mds_res += BaseElement::from(MDS[i][j]) * ood_trace_z[j];
        }
        let intermediate = mds_res + ark[i];

        let x2 = intermediate * intermediate;
        let x4 = x2 * x2;
        let x3 = x2 * intermediate;
        let x7 = x3 * x4;
        let forward_constraint = ood_trace_zg[i] - x7;

        let y = ood_trace_zg[i];
        let y2 = y * y;
        let y4 = y2 * y2;
        let y3 = y2 * y;
        let y7 = y3 * y4;
        let inverse_constraint = y7 - intermediate;

        let padding_constraint = ood_trace_zg[i] - ood_trace_z[i];
        let t_eval = is_forward * forward_constraint
            + is_inverse * inverse_constraint
            + is_padding * padding_constraint;

        let coeff = constraint_coeffs.transition[i];
        t_combined += coeff * t_eval;
    }

    let transition_eval = t_combined * transition_div_inv;

    let mut boundary_row0 = BaseElement::ZERO;
    let mut boundary_row_last = BaseElement::ZERO;
    let (boundary_row0_coeffs, boundary_row_last_coeffs) =
        constraint_coeffs.boundary.split_at(STATE_WIDTH);
    let (input_states, output_states) = pub_inputs.inner_public_inputs.split_at(STATE_WIDTH);
    for (i, (coeff_row0, coeff_last)) in boundary_row0_coeffs
        .iter()
        .zip(boundary_row_last_coeffs.iter())
        .enumerate()
    {
        let input = input_states[i];
        let output = output_states[i];
        boundary_row0 += *coeff_row0 * (ood_trace_z[i] - input);
        boundary_row_last += *coeff_last * (ood_trace_z[i] - output);
    }
    let boundary_eval = boundary_row0 * boundary_div_inv[0] + boundary_row_last * boundary_div_inv[1];

    let eval1 = transition_eval + boundary_eval;
    let eval2 = compute_ood_constraint_eval_2(
        &pub_inputs.ood_quotient_current,
        expected_z,
        pub_inputs.trace_length,
    );
    Ok((eval1, eval2))
}

pub(crate) fn compute_transaction_ood_consistency(
    pub_inputs: &StarkVerifierPublicInputs,
    constraint_coeffs: &ConstraintCompositionCoefficients<BaseElement>,
    expected_z: BaseElement,
) -> Result<(BaseElement, BaseElement), String> {
    if pub_inputs.field_extension != FieldExtension::None {
        return Err("transaction recursion only supports base-field proofs".to_string());
    }

    let tx_inputs = TransactionPublicInputsStark::try_from_elements(&pub_inputs.inner_public_inputs)?;
    let trace_info = TraceInfo::new(pub_inputs.trace_width, pub_inputs.trace_length);
    let options = ProofOptions::new(
        pub_inputs.num_draws,
        pub_inputs.blowup_factor,
        pub_inputs.grinding_factor as u32,
        pub_inputs.field_extension,
        pub_inputs.fri_folding_factor,
        pub_inputs.fri_remainder_max_degree,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let air = TransactionAirStark::new(trace_info, tx_inputs, options);
    let frame = EvaluationFrame::from_rows(
        pub_inputs.ood_trace_current.clone(),
        pub_inputs.ood_trace_next.clone(),
    );
    let eval1 = evaluate_constraints_at(&air, constraint_coeffs.clone(), &frame, expected_z);
    let eval2 = compute_ood_constraint_eval_2(
        &pub_inputs.ood_quotient_current,
        expected_z,
        pub_inputs.trace_length,
    );
    Ok((eval1, eval2))
}

fn evaluate_constraints_at<A: Air<BaseField = BaseElement>>(
    air: &A,
    composition_coefficients: ConstraintCompositionCoefficients<BaseElement>,
    main_trace_frame: &EvaluationFrame<BaseElement>,
    x: BaseElement,
) -> BaseElement {
    let t_constraints = air.get_transition_constraints(&composition_coefficients.transition);

    let periodic_values = air
        .get_periodic_column_polys()
        .iter()
        .map(|poly| {
            let num_cycles = air.trace_length() / poly.len();
            let x = x.exp_vartime((num_cycles as u32).into());
            polynom::eval(poly, x)
        })
        .collect::<Vec<_>>();

    let mut t_evaluations = vec![BaseElement::ZERO; t_constraints.num_main_constraints()];
    air.evaluate_transition(main_trace_frame, &periodic_values, &mut t_evaluations);

    let mut result = t_constraints.combine_evaluations::<BaseElement>(&t_evaluations, &[], x);
    let b_constraints = air.get_boundary_constraints(None, &composition_coefficients.boundary);
    for group in b_constraints.main_constraints().iter() {
        result += group.evaluate_at(main_trace_frame.current(), x);
    }
    result
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recursion::InnerProofData;
    use transaction_circuit::constants::NATIVE_ASSET_ID;
    use transaction_circuit::hashing::{felts_to_bytes32, merkle_node, HashFelt};
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::public_inputs::StablecoinPolicyBinding;
    use transaction_circuit::rpo_prover::TransactionProverStarkRpo;
    use transaction_circuit::witness::TransactionWitness;
    use winterfell::Prover;

    #[test]
    fn test_stark_verifier_public_inputs() {
        let inner_inputs = vec![BaseElement::new(9); 3];
        let inner_hash = [BaseElement::new(1); DIGEST_WIDTH];
        let trace_commit = [BaseElement::new(2); DIGEST_WIDTH];
        let constraint_commit = [BaseElement::new(3); DIGEST_WIDTH];
        let fri_commits = vec![[BaseElement::new(4); DIGEST_WIDTH]; 5];
        let ood_trace = vec![BaseElement::new(5); RPO_TRACE_WIDTH];
        let ood_quotient = vec![BaseElement::new(6); 8];

        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_inputs,
            inner_hash,
            trace_commit,
            constraint_commit,
            ood_trace.clone(),
            ood_quotient.clone(),
            ood_trace,
            ood_quotient,
            fri_commits.clone(),
            32,
            32,
            RPO_TRACE_WIDTH,
            8,
            16,
            2,
            7,
            0,
            1024,
            RPO_TRACE_WIDTH,
            8,
            STATE_WIDTH,
            2 * STATE_WIDTH,
            FieldExtension::None,
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
            vec![BaseElement::new(4); RPO_TRACE_WIDTH],
            vec![BaseElement::new(5); 8],
            vec![BaseElement::new(6); RPO_TRACE_WIDTH],
            vec![BaseElement::new(7); 8],
            vec![[BaseElement::new(4); DIGEST_WIDTH]; 3],
            32,
            32,
            RPO_TRACE_WIDTH,
            8,
            16,
            2,
            7,
            0,
            1024,
            RPO_TRACE_WIDTH,
            8,
            STATE_WIDTH,
            2 * STATE_WIDTH,
            FieldExtension::None,
        );

        let elements = pub_inputs.to_elements();

        let ood_len = 2 * (RPO_TRACE_WIDTH + 8);
        // inner_public_inputs (2) + 4 (inner hash) + 4 (trace) + 4 (constraint) + ood + 3*4 (fri) + 14 (params)
        assert_eq!(elements.len(), 2 + 4 + 4 + 4 + ood_len + 12 + 14);
    }

    #[test]
    fn test_try_from_elements_roundtrip() {
        let inner_inputs: Vec<BaseElement> = (0..(2 * STATE_WIDTH))
            .map(|i| BaseElement::new(i as u64 + 1))
            .collect();
        let inner_hash = [BaseElement::new(10); DIGEST_WIDTH];
        let trace_commit = [BaseElement::new(11); DIGEST_WIDTH];
        let constraint_commit = [BaseElement::new(12); DIGEST_WIDTH];
        let fri_commits = vec![
            [BaseElement::new(13); DIGEST_WIDTH],
            [BaseElement::new(14); DIGEST_WIDTH],
        ];
        let ood_trace = vec![BaseElement::new(15); RPO_TRACE_WIDTH];
        let ood_quotient = vec![BaseElement::new(16); 8];

        let pub_inputs = StarkVerifierPublicInputs::new(
            inner_inputs.clone(),
            inner_hash,
            trace_commit,
            constraint_commit,
            ood_trace.clone(),
            ood_quotient.clone(),
            ood_trace,
            ood_quotient,
            fri_commits.clone(),
            4,
            4,
            RPO_TRACE_WIDTH,
            8,
            32,
            2,
            7,
            0,
            ROWS_PER_PERMUTATION,
            RPO_TRACE_WIDTH,
            8,
            STATE_WIDTH,
            2 * STATE_WIDTH,
            FieldExtension::None,
        );

        let elements = pub_inputs.to_elements();
        let decoded =
            StarkVerifierPublicInputs::try_from_elements(&elements, inner_inputs.len()).unwrap();

        assert_eq!(decoded.inner_public_inputs, inner_inputs);
        assert_eq!(decoded.inner_pub_inputs_hash, inner_hash);
        assert_eq!(decoded.trace_commitment, trace_commit);
        assert_eq!(decoded.constraint_commitment, constraint_commit);
        assert_eq!(decoded.ood_trace_current, vec![BaseElement::new(15); RPO_TRACE_WIDTH]);
        assert_eq!(decoded.ood_quotient_current, vec![BaseElement::new(16); 8]);
        assert_eq!(decoded.ood_trace_next, vec![BaseElement::new(15); RPO_TRACE_WIDTH]);
        assert_eq!(decoded.ood_quotient_next, vec![BaseElement::new(16); 8]);
        assert_eq!(decoded.fri_commitments, fri_commits);
        assert_eq!(decoded.num_queries, 4);
        assert_eq!(decoded.num_draws, 4);
        assert_eq!(decoded.trace_partition_size, RPO_TRACE_WIDTH);
        assert_eq!(decoded.constraint_partition_size, 8);
        assert_eq!(decoded.blowup_factor, 32);
        assert_eq!(decoded.fri_folding_factor, 2);
        assert_eq!(decoded.fri_remainder_max_degree, 7);
        assert_eq!(decoded.grinding_factor, 0);
        assert_eq!(decoded.trace_length, ROWS_PER_PERMUTATION);
        assert_eq!(decoded.field_extension, FieldExtension::None);
        assert_eq!(decoded.trace_width, RPO_TRACE_WIDTH);
        assert_eq!(decoded.constraint_frame_width, 8);
        assert_eq!(decoded.num_transition_constraints, STATE_WIDTH);
        assert_eq!(decoded.num_assertions, 2 * STATE_WIDTH);
    }

    fn compute_merkle_root_from_path(
        leaf: HashFelt,
        position: u64,
        path: &MerklePath,
    ) -> HashFelt {
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
            value: 5,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let output_note = OutputNoteWitness {
            note: NoteData {
                value: 4,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [9u8; 32],
                rho: [10u8; 32],
                r: [11u8; 32],
            },
        };

        let merkle_path = MerklePath::default();
        let position = 0u64;
        let merkle_root = felts_to_bytes32(&compute_merkle_root_from_path(
            input_note.commitment(),
            position,
            &merkle_path,
        ));

        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position,
                rho_seed: [7u8; 32],
                merkle_path,
            }],
            outputs: vec![output_note],
            sk_spend: [8u8; 32],
            merkle_root,
            fee: 1,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    #[test]
    #[ignore = "heavy: transaction OOD consistency check"]
    fn test_transaction_ood_consistency_matches() {
        let witness = sample_witness();
        let options = ProofOptions::new(
            8,
            8,
            0,
            FieldExtension::None,
            2,
            7,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let prover = TransactionProverStarkRpo::new(options);
        let trace = prover.build_trace(&witness).expect("trace");
        let pub_inputs = prover.get_pub_inputs(&trace);
        let proof = prover.prove(trace).expect("rpo proof");

        let inner_data = InnerProofData::from_proof::<TransactionAirStark>(
            &proof.to_bytes(),
            pub_inputs,
        )
        .expect("inner proof parsing");
        let verifier_inputs = inner_data.to_stark_verifier_inputs();

        let ood_digest = compute_ood_digest(&verifier_inputs);
        let (constraint_coeffs, expected_z, _, _) =
            compute_expected_transcript_draws(&verifier_inputs, ood_digest)
                .expect("transcript reconstruction");
        let (eval1, eval2) = compute_transaction_ood_consistency(
            &verifier_inputs,
            &constraint_coeffs,
            expected_z,
        )
        .expect("ood consistency computation");

        assert_eq!(eval1, eval2, "transaction OOD consistency check failed");
    }
}
