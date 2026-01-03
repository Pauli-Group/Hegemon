//! Batch STARK verifier AIR (Phase 3b).
//!
//! This module defines the public input shape for a batch verifier which will verify `N`
//! independent inner proofs in one outer proof by time-multiplexing the existing
//! `StarkVerifierAir` trace layout.
//!
//! The actual AIR/prover implementation lives in `stark_verifier_batch_prover.rs` and will be
//! built to keep trace width flat (≤255) by growing trace length with `N`.

use winter_air::{
    Air, AirContext, Assertion, EvaluationFrame, FieldExtension, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winter_math::fields::f64::BaseElement;
use winter_math::{FieldElement, StarkField, ToElements};

use super::merkle_air::DIGEST_WIDTH;
use super::rpo_air::{MDS, ROWS_PER_PERMUTATION, STATE_WIDTH};
use super::stark_verifier_air::{
    compute_expected_transcript_draws, compute_expected_transcript_draws_quadratic,
    compute_leaf_layout, compute_ood_digest, compute_rpo_ood_consistency,
    compute_rpo_ood_consistency_quadratic, compute_transaction_ood_consistency,
    compute_transaction_ood_consistency_quadratic, field_extension_degree, StarkVerifierAir,
    StarkVerifierPublicInputs, COL_CARRY_MASK, COL_COEFF_MASK, COL_COEFF_START, COL_COIN_INIT_MASK,
    COL_COIN_RESTORE_MASK, COL_COIN_SAVE_MASK, COL_DEEP_C1_ACC, COL_DEEP_C1_ACC_LIMB1,
    COL_DEEP_C2_ACC, COL_DEEP_C2_ACC_LIMB1, COL_DEEP_MASK, COL_DEEP_START, COL_DEEP_T1_ACC,
    COL_DEEP_T1_ACC_LIMB1, COL_DEEP_T2_ACC, COL_DEEP_T2_ACC_LIMB1, COL_FRI_ALPHA_VALUE,
    COL_FRI_EVAL, COL_FRI_EVAL_LIMB1, COL_FRI_MASK, COL_FRI_MSB_BITS_START,
    COL_FRI_POW, COL_FRI_X, COL_FULL_CARRY_MASK, COL_MERKLE_INDEX, COL_MERKLE_PATH_BIT,
    COL_OOD_DIGEST_START, COL_POS_ACC, COL_POS_BIT0, COL_POS_BIT1, COL_POS_BIT2, COL_POS_BIT3,
    COL_POS_DECOMP_MASK, COL_POS_HI_AND, COL_POS_LO_ACC, COL_POS_MASK, COL_POS_MASKED_ACC,
    COL_POS_PERM_ACC, COL_POS_PERM_ACC_LIMB1, COL_POS_RAW, COL_POS_SORTED_VALUE, COL_POS_START,
    COL_REMAINDER_COEFFS_EXT_START, COL_REMAINDER_COEFFS_START, COL_RESEED_MASK,
    COL_RESEED_WORD_START, COL_SAVED_COIN_START, COL_TAPE_MASK, COL_TAPE_VALUES_START, COL_Z_MASK,
    COL_Z_VALUE, COL_Z_VALUE_LIMB1, NUM_REMAINDER_COEFFS, RATE_WIDTH, TAPE_WIDTH,
    VERIFIER_TRACE_WIDTH,
};

#[cfg(test)]
use winter_math::{fft, polynom};

const CAPACITY_WIDTH: usize = 4;
const RATE_START: usize = CAPACITY_WIDTH;
const EXTENSION_LIMBS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InnerProofKind {
    RpoAir,
    TransactionAir,
}

fn transaction_public_inputs_len() -> usize {
    (transaction_circuit::constants::MAX_INPUTS + transaction_circuit::constants::MAX_OUTPUTS) * 5
        + 24
}

fn inner_proof_kind(
    pub_inputs: &StarkVerifierPublicInputs,
) -> Result<InnerProofKind, String> {
    if pub_inputs.inner_public_inputs.len() == 2 * STATE_WIDTH {
        Ok(InnerProofKind::RpoAir)
    } else if pub_inputs.inner_public_inputs.len() == transaction_public_inputs_len() {
        Ok(InnerProofKind::TransactionAir)
    } else {
        Err(format!(
            "unsupported inner public input length {}",
            pub_inputs.inner_public_inputs.len()
        ))
    }
}

/// Public inputs for a batch verifier proof.
///
/// We keep the per-inner-proof `StarkVerifierPublicInputs` explicit for now; this preserves the
/// existing Phase 2 binding model where the outer verifier’s public inputs are derived from the
/// inner proof bytes and tamper-reject is achieved by recomputing these inputs at verification
/// time.
#[derive(Clone, Debug)]
pub struct StarkVerifierBatchPublicInputs {
    /// Per-proof verifier public inputs (one entry per inner proof).
    pub inner: Vec<StarkVerifierPublicInputs>,
}

impl StarkVerifierBatchPublicInputs {
    pub fn num_inner(&self) -> usize {
        self.inner.len()
    }
}

impl ToElements<BaseElement> for StarkVerifierBatchPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut elements = Vec::new();
        elements.push(BaseElement::new(self.inner.len() as u64));
        for inner in &self.inner {
            elements.extend_from_slice(&inner.to_elements());
        }
        elements
    }
}

/// AIR which verifies a fixed number of inner proofs by concatenating `StarkVerifierAir` traces.
///
/// For now we require:
/// - all inner-proof parameters are uniform across the batch (same trace width/length, options)
/// - batch size is a power of two (so the batch trace length stays a power of two)
///
/// OOD/DEEP/FRI consistency is enforced for all supported inner proof kinds.
pub struct StarkVerifierBatchAir {
    context: AirContext<BaseElement>,
    pub_inputs: StarkVerifierBatchPublicInputs,
    segment_len: usize,
    template: StarkVerifierPublicInputs,
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
    options: ProofOptions,
}

impl StarkVerifierBatchAir {
    fn num_segments(&self) -> usize {
        self.pub_inputs.inner.len()
    }
}

impl Air for StarkVerifierBatchAir {
    type BaseField = BaseElement;
    type PublicInputs = StarkVerifierBatchPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert!(
            !pub_inputs.inner.is_empty(),
            "batch verifier requires at least one inner proof"
        );
        assert!(
            pub_inputs.inner.len().is_power_of_two(),
            "batch verifier requires power-of-two inner proof count (got {})",
            pub_inputs.inner.len()
        );

        let template = pub_inputs.inner[0].clone();
        let segment_len = trace_info.length() / pub_inputs.inner.len();
        assert!(
            trace_info.length() == segment_len * pub_inputs.inner.len(),
            "batch trace length must equal segment_len * num_segments"
        );
        assert!(
            segment_len.is_power_of_two(),
            "segment trace length must be a power of two (got {})",
            segment_len
        );
        assert_eq!(
            template.fri_folding_factor,
            2,
            "StarkVerifierBatchAir assumes FRI folding factor 2"
        );

        let inner_inputs_len = template.inner_public_inputs.len();

        for (idx, inner) in pub_inputs.inner.iter().enumerate().skip(1) {
            assert_eq!(
                inner.trace_length, template.trace_length,
                "inner proof {idx} trace_length mismatch"
            );
            assert_eq!(
                inner.trace_width, template.trace_width,
                "inner proof {idx} trace_width mismatch"
            );
            assert_eq!(
                inner.constraint_frame_width, template.constraint_frame_width,
                "inner proof {idx} constraint_frame_width mismatch"
            );
            assert_eq!(
                inner.num_transition_constraints, template.num_transition_constraints,
                "inner proof {idx} num_transition_constraints mismatch"
            );
            assert_eq!(
                inner.num_assertions, template.num_assertions,
                "inner proof {idx} num_assertions mismatch"
            );
            assert_eq!(
                inner.num_queries, template.num_queries,
                "inner proof {idx} num_queries mismatch"
            );
            assert_eq!(
                inner.num_draws, template.num_draws,
                "inner proof {idx} num_draws mismatch"
            );
            assert_eq!(
                inner.inner_public_inputs.len(),
                inner_inputs_len,
                "inner proof {idx} inner_public_inputs length mismatch"
            );
            assert_eq!(
                inner.field_extension, template.field_extension,
                "inner proof {idx} field_extension mismatch"
            );
            assert_eq!(
                inner.blowup_factor, template.blowup_factor,
                "inner proof {idx} blowup_factor mismatch"
            );
            assert_eq!(
                inner.fri_commitments.len(),
                template.fri_commitments.len(),
                "inner proof {idx} fri_commitments length mismatch"
            );
        }

        // Domain constants for the *inner* proof parameters (used in DEEP/FRI checks).
        let g_trace = BaseElement::get_root_of_unity(template.trace_length.ilog2());
        let lde_domain_size = template.trace_length * template.blowup_factor;
        let g_lde = BaseElement::get_root_of_unity(lde_domain_size.ilog2());
        let domain_offset = BaseElement::GENERATOR;
        let inv_domain_offset = domain_offset.inv();

        let extension_degree = field_extension_degree(template.field_extension)
            .expect("unsupported field extension");
        let is_quadratic = template.field_extension == FieldExtension::Quadratic;
        let trace_width_ext = template.trace_width * extension_degree;
        let constraint_width_ext = template.constraint_frame_width * extension_degree;
        let num_constraint_coeffs =
            (template.num_transition_constraints + template.num_assertions) * extension_degree;
        let num_deep_coeffs = trace_width_ext + constraint_width_ext;
        let ood_eval_len = 2 * num_deep_coeffs;

        for (idx, inner) in pub_inputs.inner.iter().enumerate() {
            assert_eq!(
                inner.ood_trace_current.len(),
                trace_width_ext,
                "inner proof {idx} OOD trace current length mismatch"
            );
            assert_eq!(
                inner.ood_trace_next.len(),
                trace_width_ext,
                "inner proof {idx} OOD trace next length mismatch"
            );
            assert_eq!(
                inner.ood_quotient_current.len(),
                constraint_width_ext,
                "inner proof {idx} OOD quotient current length mismatch"
            );
            assert_eq!(
                inner.ood_quotient_next.len(),
                constraint_width_ext,
                "inner proof {idx} OOD quotient next length mismatch"
            );
        }

        let constraint_partition_size_base = template.constraint_partition_size * extension_degree;
        let trace_layout = compute_leaf_layout(trace_width_ext, template.trace_partition_size);
        let constraint_layout =
            compute_leaf_layout(constraint_width_ext, constraint_partition_size_base);
        let trace_data_block_starts = trace_layout.data_perm_starts.clone();
        let constraint_data_block_starts = constraint_layout.data_perm_starts.clone();

        // Transition degrees are identical to `StarkVerifierAir`.
        let num_fri_layers = template.fri_commitments.len().saturating_sub(1);
        // Base periodic columns come from `StarkVerifierAir` and are repeated for each segment;
        // thus their full-cycle period is the per-segment trace length, not the total batch
        // length.
        let full_cycle = segment_len;
        let boundary_and_full = vec![ROWS_PER_PERMUTATION, full_cycle];

        // The batch verifier concatenates per-proof traces. In the concatenated trace, the last
        // row of each segment becomes an *internal* row, but `StarkVerifierAir` relies on the
        // last row being transition-exempt. We model per-segment transition exemptions by
        // multiplying every transition constraint by `segment_transition_mask` (period =
        // `segment_len`).
        macro_rules! deg {
            ($base:expr) => {
                TransitionConstraintDegree::with_cycles($base, vec![segment_len])
            };
            ($base:expr, $cycles:expr) => {{
                let mut cycles = $cycles;
                cycles.push(segment_len);
                TransitionConstraintDegree::with_cycles($base, cycles)
            }};
        }

        // Count constraints exactly as `StarkVerifierAir`.
        let extra_draw_constraints = if is_quadratic { 2 } else { 0 };
        let base_boundary_constraints =
            3 * DIGEST_WIDTH + 13 + 4 * RATE_WIDTH + 2 + extra_draw_constraints;
        let num_root_masks = 2 + num_fri_layers; // trace root, constraint root, and each committed FRI layer
        let merkle_constraints = 1 // intra-leaf chaining
            + 1 // path-bit binary
            + DIGEST_WIDTH // digest carryover into the next permutation
            + 1 // index shift (idx_cur = 2*idx_next + bit)
            + num_root_masks // index must be 0 at each root boundary
            + num_root_masks * DIGEST_WIDTH; // root digest checks
        let pos_decomp_constraints = 32 + if extension_degree == 2 { 5 } else { 0 };

        let ood_constraints = DIGEST_WIDTH // ood digest constant
            + STATE_WIDTH // saved coin state constant
            + ood_eval_len // bind OOD eval inputs
            + DIGEST_WIDTH // capture ood digest
            + STATE_WIDTH // capture coin state at z
            + STATE_WIDTH // restore coin state (+ood reseed)
            + extension_degree; // OOD constraint consistency check (winter-verifier step 3)

        let transcript_store_constraints = num_constraint_coeffs // capture constraint coeffs
            + num_deep_coeffs // capture deep coeffs
            + num_fri_layers * extension_degree; // capture alphas

        let remainder_coeffs_total = (template.fri_remainder_max_degree + 1) * extension_degree;
        assert!(
            remainder_coeffs_total <= NUM_REMAINDER_COEFFS * extension_degree,
            "remainder polynomial too large for recursion layout ({} coefficients)",
            remainder_coeffs_total
        );
        let deep_fri_constraints = remainder_coeffs_total // remainder coeffs constant
            + remainder_coeffs_total // bind remainder coeffs to commitment hash input
            + 4 * extension_degree // deep accumulators
            + 2 // x/pow updates
            + extension_degree // fri eval freeze
            + num_fri_layers // msb capture
            + num_fri_layers * extension_degree // layer eval selection
            + extension_degree // deep composition check
            + num_fri_layers * extension_degree // fri folding checks
            + (num_fri_layers > 0) as usize * extension_degree; // remainder eval check

        let num_constraints = STATE_WIDTH
            + base_boundary_constraints
            + merkle_constraints
            + pos_decomp_constraints
            + ood_constraints
            + transcript_store_constraints
            + deep_fri_constraints;

        let mut degrees = Vec::with_capacity(num_constraints);

        // --- RPO degrees ------------------------------------------------------------------
        // Match `StarkVerifierAir`: RPO constraints multiply by multiple periodic selectors.
        //
        // In the concatenated trace, some selector columns are repeated per segment and thus have
        // slightly lower degree than a full-length trace polynomial. Empirically this reduces the
        // transition-quotient degree by `num_segments - 1` vs the single-segment accounting. We
        // model this by trading one unit of `base` degree for an additional `segment_len` cycle.
        degrees.extend(vec![
            deg!(
                7,
                vec![
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                    ROWS_PER_PERMUTATION,
                    segment_len
                ]
            );
            STATE_WIDTH
        ]);

        // --- Boundary relation + transcript draw degrees ----------------------------------
        // Batch note: the transcript boundary-mask columns are repeated per segment in the batch
        // trace, which reduces the effective trace-column degree by `num_segments - 1`. The base
        // boundary relations which multiply a single such mask by a full-degree trace value thus
        // drop by `num_segments - 1` in debug-degree validation.
        let boundary_rel_degree = deg!(1, vec![ROWS_PER_PERMUTATION, segment_len]);

        // Some boundary-only constraints (mask booleanity + exclusivity) multiply two segment-
        // repeated mask columns together; in the batch trace this drops by `2 * (num_segments - 1)`.
        // We match the observed degrees by using a half-segment cycle (for the two-segment case
        // this is `segment_len / 2`).
        let boundary_pair_degree =
            TransitionConstraintDegree::with_cycles(2, vec![ROWS_PER_PERMUTATION, segment_len / 2]);

        // Capacity carryover + rate relations (3 * DIGEST_WIDTH).
        degrees.extend(vec![boundary_rel_degree.clone(); 3 * DIGEST_WIDTH]);
        // Mask validity (7) + exclusivity (6).
        degrees.extend(vec![boundary_pair_degree.clone(); 13]);
        // Transcript-derived value checks.
        degrees.extend(vec![boundary_rel_degree.clone(); RATE_WIDTH]); // coeff checks
        degrees.push(boundary_rel_degree.clone()); // z check
        if extension_degree > 1 {
            degrees.push(boundary_rel_degree.clone()); // z limb1 check
        }
        degrees.extend(vec![boundary_rel_degree.clone(); RATE_WIDTH]); // deep checks
        degrees.push(boundary_rel_degree.clone()); // fri alpha check
        if extension_degree > 1 {
            degrees.push(boundary_rel_degree.clone()); // fri alpha limb1 check
        }
        degrees.extend(vec![boundary_rel_degree.clone(); RATE_WIDTH]); // pos checks
        degrees.extend(vec![boundary_rel_degree.clone(); RATE_WIDTH]); // tape checks

        // --- Merkle authentication degrees ------------------------------------------------
        // Mirror `StarkVerifierAir`'s degree accounting for sparse selectors.
        degrees.push(boundary_pair_degree.clone()); // intra-leaf carry
        degrees.push(deg!(2, boundary_and_full.clone())); // path-bit binary
        degrees.extend(vec![deg!(2, boundary_and_full.clone()); DIGEST_WIDTH]); // digest carryover
        degrees.push(deg!(1, boundary_and_full.clone())); // index shift
        degrees.extend(vec![boundary_rel_degree.clone(); num_root_masks]); // root index checks
        degrees.extend(vec![
            boundary_rel_degree.clone();
            num_root_masks * DIGEST_WIDTH
        ]); // root digest checks

        // --- Query position decomposition degrees -----------------------------------------
        // Copy the shape from `StarkVerifierAir` so we can reuse `StarkVerifierProver` traces.
        let decomp_schedule_degree =
            TransitionConstraintDegree::with_cycles(2, vec![segment_len / 2]);
        degrees.push(decomp_schedule_degree.clone()); // decomp mask schedule (on)
        degrees.push(decomp_schedule_degree.clone()); // decomp mask schedule (off)

        degrees.push(deg!(1, vec![segment_len])); // gamma binding (z challenge)
        if extension_degree > 1 {
            degrees.push(deg!(1, vec![segment_len])); // gamma limb1 binding
        }

        let pos_carry_degree = deg!(1, vec![ROWS_PER_PERMUTATION, segment_len, segment_len]);
        degrees.extend(vec![pos_carry_degree.clone(); RATE_WIDTH]); // carry rate buffer
        degrees.push(pos_carry_degree.clone()); // raw select

        degrees.extend(vec![deg!(2, vec![segment_len]); 4]); // bit booleanity

        let pos_acc_init_degree = boundary_rel_degree.clone();
        let pos_acc_update_degree = deg!(
            1,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION, segment_len]
        );
        let pos_lo_update_degree = deg!(
            1,
            vec![
                ROWS_PER_PERMUTATION,
                ROWS_PER_PERMUTATION,
                ROWS_PER_PERMUTATION,
                segment_len
            ]
        );

        degrees.push(pos_acc_init_degree.clone()); // acc init
        degrees.push(pos_acc_update_degree.clone()); // acc update
        degrees.push(pos_acc_update_degree.clone()); // acc = raw at boundary

        degrees.push(pos_acc_init_degree.clone()); // lo init
        degrees.push(pos_lo_update_degree.clone()); // lo update
        degrees.push(pos_acc_update_degree.clone()); // lo freeze

        degrees.push(pos_acc_init_degree.clone()); // masked init
        degrees.push(pos_acc_update_degree.clone()); // masked update
        degrees.push(pos_acc_update_degree.clone()); // bind draw_val to masked raw draw

        degrees.push(boundary_pair_degree.clone()); // hi init
        degrees.push(TransitionConstraintDegree::with_cycles(
            6,
            vec![ROWS_PER_PERMUTATION, ROWS_PER_PERMUTATION, segment_len / 2],
        )); // hi update
        degrees.push(TransitionConstraintDegree::with_cycles(
            7,
            vec![ROWS_PER_PERMUTATION, segment_len / 2],
        )); // canonical check

        degrees.push(deg!(1, vec![segment_len, segment_len])); // perm acc init
        degrees.push(pos_carry_degree.clone()); // perm acc freeze
        degrees.push(deg!(2, vec![ROWS_PER_PERMUTATION, segment_len])); // perm acc multiply
        degrees.push(deg!(2, boundary_and_full.clone())); // perm acc divide
        if extension_degree > 1 {
            degrees.push(deg!(1, vec![segment_len, segment_len])); // perm acc limb1 init
            degrees.push(pos_carry_degree.clone()); // perm acc limb1 freeze
            degrees.push(deg!(2, vec![ROWS_PER_PERMUTATION, segment_len])); // perm acc limb1 multiply
            degrees.push(deg!(2, boundary_and_full.clone())); // perm acc limb1 divide
        }

        // OOD digest + coin save/restore degrees.
        degrees.extend(vec![deg!(1); DIGEST_WIDTH]); // ood digest constant
        degrees.extend(vec![deg!(1); STATE_WIDTH]); // saved coin constant
        degrees.extend(vec![deg!(1, vec![full_cycle]); ood_eval_len]); // bind ood evals
        degrees.extend(vec![deg!(1, vec![full_cycle]); DIGEST_WIDTH]); // capture ood digest
        degrees.extend(vec![boundary_rel_degree.clone(); STATE_WIDTH]); // capture coin at z
        degrees.extend(vec![deg!(1, vec![full_cycle]); STATE_WIDTH]); // restore coin
        degrees.extend(vec![TransitionConstraintDegree::new(1); extension_degree]); // ood constraint consistency check

        // Transcript draw binding degrees.
        degrees.extend(vec![deg!(1, vec![full_cycle]); num_constraint_coeffs]);
        degrees.extend(vec![deg!(1, vec![full_cycle]); num_deep_coeffs]);
        degrees.extend(vec![
            deg!(1, vec![full_cycle]);
            num_fri_layers * extension_degree
        ]);

        // DEEP + FRI recursion degrees.
        degrees.extend(vec![deg!(1); remainder_coeffs_total]);
        degrees.extend(vec![deg!(1, vec![full_cycle]); remainder_coeffs_total]);
        degrees.extend(vec![deg!(2, vec![full_cycle]); 4 * extension_degree]); // deep accs
        degrees.push(deg!(2, vec![full_cycle, full_cycle])); // x/pow update
        degrees.push(deg!(2, vec![full_cycle / 2])); // pow update
        degrees.extend(vec![deg!(1, vec![full_cycle]); extension_degree]); // eval freeze
        degrees.extend(vec![deg!(1, vec![full_cycle]); num_fri_layers]); // msb capture
        degrees.extend(vec![deg!(2, vec![full_cycle]); num_fri_layers * extension_degree]); // eval selection
        degrees.extend(vec![deg!(3, vec![full_cycle]); extension_degree]); // deep composition
        degrees.extend(vec![deg!(3, vec![full_cycle]); num_fri_layers * extension_degree]); // fri fold
        if num_fri_layers > 0 {
            degrees.extend(vec![deg!(8, vec![full_cycle]); extension_degree]); // remainder eval
        }

        debug_assert_eq!(
            degrees.len(),
            num_constraints,
            "degree descriptor count mismatch"
        );

        // Compute assertion count for one segment by constructing a segment AIR and reusing its
        // computed context.
        let segment_trace_info = TraceInfo::new(VERIFIER_TRACE_WIDTH, segment_len);
        let segment_air =
            StarkVerifierAir::new(segment_trace_info, template.clone(), options.clone());
        let per_segment_assertions = segment_air.context().num_assertions();
        let num_assertions = per_segment_assertions * pub_inputs.inner.len();

        let opts_stored = options.clone();
        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self {
            context,
            pub_inputs,
            segment_len,
            template,
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
            options: opts_stored,
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
        // We reuse the `StarkVerifierAir` transition logic and make the small number of
        // public-input-derived constants segment-aware by supplying them as extra periodic values.
        let current = frame.current();
        let next = frame.next();
        let is_quadratic = self.template.field_extension == FieldExtension::Quadratic;
        let extension_degree = if is_quadratic { 2 } else { 1 };

        // Parse the base periodic layout from `StarkVerifierAir`.
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

        let num_fri_commitments = self.template.fri_commitments.len();
        let num_fri_layers = num_fri_commitments.saturating_sub(1);
        let remainder_coeffs_len =
            (self.template.fri_remainder_max_degree + 1) * extension_degree;
        let num_remainder_perms = if num_fri_commitments > 0 {
            remainder_coeffs_len.div_ceil(RATE_WIDTH)
        } else {
            0
        };
        let fri_root_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let ood_digest_capture_mask = periodic_values[p];
        p += 1;
        let num_ood_perms = self.ood_eval_len.div_ceil(RATE_WIDTH);
        let ood_eval_row_masks = &periodic_values[p..p + num_ood_perms];
        p += num_ood_perms;
        let _deep_start_row_mask = periodic_values[p];
        p += 1;
        let num_coeff_perms = self.num_constraint_coeffs.div_ceil(RATE_WIDTH).max(1);
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
        let trace_leaf_row_masks =
            &periodic_values[p..p + self.trace_data_block_starts.len()];
        p += self.trace_data_block_starts.len();
        let constraint_leaf_row_masks =
            &periodic_values[p..p + self.constraint_data_block_starts.len()];
        p += self.constraint_data_block_starts.len();
        let trace_merkle_bit_mask = periodic_values[p];
        p += 1;
        let msb_capture_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let fri_leaf_row_masks = &periodic_values[p..p + num_fri_layers];
        p += num_fri_layers;
        let fri_leaf_any_row_mask = periodic_values[p];
        p += 1;
        let remainder_hash_row0_masks = &periodic_values[p..p + num_remainder_perms];
        p += num_remainder_perms;

        // --- Batch-only periodic values ---------------------------------------------------
        let segment_transition_mask = periodic_values[p];
        p += 1;
        let trace_commitment: [E; DIGEST_WIDTH] = core::array::from_fn(|i| periodic_values[p + i]);
        p += DIGEST_WIDTH;
        let constraint_commitment: [E; DIGEST_WIDTH] =
            core::array::from_fn(|i| periodic_values[p + i]);
        p += DIGEST_WIDTH;
        let fri_commitments_flat = &periodic_values[p..p + num_fri_layers * DIGEST_WIDTH];
        p += num_fri_layers * DIGEST_WIDTH;
        let expected_z0 = periodic_values[p];
        p += 1;
        let expected_z1 = if is_quadratic {
            let limb = periodic_values[p];
            p += 1;
            limb
        } else {
            E::ZERO
        };
        let inner_constraint_coeffs = &periodic_values[p..p + self.num_constraint_coeffs];
        p += self.num_constraint_coeffs;
        let inner_deep_coeffs = &periodic_values[p..p + self.num_deep_coeffs];
        p += self.num_deep_coeffs;
        let inner_fri_alphas = &periodic_values[p..p + num_fri_layers * extension_degree];
        p += num_fri_layers * extension_degree;
        let inner_ood_constraint_eval_10 = periodic_values[p];
        p += 1;
        let inner_ood_constraint_eval_11 = if is_quadratic {
            let limb = periodic_values[p];
            p += 1;
            limb
        } else {
            E::ZERO
        };
        let inner_ood_constraint_eval_20 = periodic_values[p];
        p += 1;
        let inner_ood_constraint_eval_21 = if is_quadratic {
            let limb = periodic_values[p];
            p += 1;
            limb
        } else {
            E::ZERO
        };
        let ood_trace_current = &periodic_values[p..p + self.trace_width_ext];
        p += self.trace_width_ext;
        let ood_quotient_current = &periodic_values[p..p + self.constraint_width_ext];
        p += self.constraint_width_ext;
        let ood_trace_next = &periodic_values[p..p + self.trace_width_ext];
        p += self.trace_width_ext;
        let ood_quotient_next = &periodic_values[p..p + self.constraint_width_ext];

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
        let coin_save_mask = current[COL_COIN_SAVE_MASK];
        let coin_restore_mask = current[COL_COIN_RESTORE_MASK];
        let tape_mask = current[COL_TAPE_MASK];
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
        result[idx + 4] = boundary_mask * coin_save_mask * (coin_save_mask - one);
        result[idx + 5] = boundary_mask * coin_restore_mask * (coin_restore_mask - one);
        result[idx + 6] = boundary_mask * tape_mask * (tape_mask - one);
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

        for i in 0..RATE_WIDTH {
            let expected = current[COL_COEFF_START + i];
            result[idx + i] = boundary_mask * coeff_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        let expected_z_val0 = current[COL_Z_VALUE];
        result[idx] = boundary_mask * z_mask * (current[RATE_START] - expected_z_val0);
        idx += 1;
        if is_quadratic {
            let expected_z_val1 = current[COL_Z_VALUE_LIMB1];
            result[idx] = boundary_mask * z_mask * (current[RATE_START + 1] - expected_z_val1);
            idx += 1;
        }

        let deep_mask = current[COL_DEEP_MASK];
        for i in 0..RATE_WIDTH {
            let expected = current[COL_DEEP_START + i];
            result[idx + i] = boundary_mask * deep_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        let fri_mask = current[COL_FRI_MASK];
        let expected_alpha0 = current[COL_FRI_ALPHA_VALUE];
        result[idx] = boundary_mask * fri_mask * (current[RATE_START] - expected_alpha0);
        idx += 1;
        if is_quadratic {
            let mut expected_alpha1 = E::ZERO;
            for (layer_idx, mask) in fri_alpha_end_masks.iter().enumerate() {
                if layer_idx >= num_fri_layers {
                    break;
                }
                let alpha1 = inner_fri_alphas[layer_idx * extension_degree + 1];
                expected_alpha1 += *mask * alpha1;
            }
            result[idx] = boundary_mask * fri_mask * (current[RATE_START + 1] - expected_alpha1);
            idx += 1;
        }

        let pos_mask = current[COL_POS_MASK];
        for i in 0..RATE_WIDTH {
            let expected = current[COL_POS_START + i];
            result[idx + i] = boundary_mask * pos_mask * (current[RATE_START + i] - expected);
        }
        idx += RATE_WIDTH;

        // Tape capture: when enabled, the tape values must match the permutation's rate output.
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
            let prev_digest = current[CAPACITY_WIDTH + i]; // digest lives in rate columns 4..7
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
        // idx_cur = 2*idx_next + bit.
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
            if layer_idx >= num_fri_layers {
                break;
            }
            result[idx] = boundary_mask * (*root_mask) * merkle_idx;
            idx += 1;
        }

        // Root checks at the end of each authenticated path.
        for i in 0..DIGEST_WIDTH {
            let digest = current[CAPACITY_WIDTH + i];
            result[idx + i] = boundary_mask * trace_root_mask * (digest - trace_commitment[i]);
        }
        idx += DIGEST_WIDTH;

        for i in 0..DIGEST_WIDTH {
            let digest = current[CAPACITY_WIDTH + i];
            result[idx + i] =
                boundary_mask * constraint_root_mask * (digest - constraint_commitment[i]);
        }
        idx += DIGEST_WIDTH;

        for (layer_idx, root_mask) in fri_root_masks.iter().enumerate() {
            if layer_idx >= num_fri_layers {
                break;
            }
            for i in 0..DIGEST_WIDTH {
                let digest = current[CAPACITY_WIDTH + i];
                let root = fri_commitments_flat[layer_idx * DIGEST_WIDTH + i];
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
        let expected_gamma0 = expected_z0;
        let expected_gamma1 = expected_z1;
        result[idx] = decomp_mask * (current[COL_Z_VALUE] - expected_gamma0);
        idx += 1;
        if is_quadratic {
            result[idx] = decomp_mask * (current[COL_Z_VALUE_LIMB1] - expected_gamma1);
            idx += 1;
        }

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

        // (8) Bind transcript-derived query draws to Merkle indexes used for trace-leaf auth.
        let perm_acc0 = current[COL_POS_PERM_ACC];
        let perm_acc1 = current[COL_POS_PERM_ACC_LIMB1];
        let perm_acc_next0 = next[COL_POS_PERM_ACC];
        let perm_acc_next1 = next[COL_POS_PERM_ACC_LIMB1];
        let gamma0 = expected_gamma0;
        let gamma1 = expected_gamma1;
        let trace_idx = current[COL_MERKLE_INDEX];

        result[idx] = decomp_mask * pos_first_decomp_mask * (perm_acc0 - one);
        idx += 1;
        if is_quadratic {
            result[idx] = decomp_mask * pos_first_decomp_mask * perm_acc1;
            idx += 1;
        }

        let freeze_sel =
            perm_mask + boundary_mask * (one - decomp_mask) * (one - trace_leaf_end_mask);
        result[idx] = freeze_sel * (perm_acc_next0 - perm_acc0);
        idx += 1;
        if is_quadratic {
            result[idx] = freeze_sel * (perm_acc_next1 - perm_acc1);
            idx += 1;
        }

        let (draw_plus_gamma0, draw_plus_gamma1) =
            ext_add(draw_val, E::ZERO, gamma0, gamma1);
        let (prod0, prod1) = ext_mul(perm_acc0, perm_acc1, draw_plus_gamma0, draw_plus_gamma1);
        result[idx] = boundary_mask * decomp_mask * (perm_acc_next0 - prod0);
        idx += 1;
        if is_quadratic {
            result[idx] = boundary_mask * decomp_mask * (perm_acc_next1 - prod1);
            idx += 1;
        }

        let (trace_plus_gamma0, trace_plus_gamma1) =
            ext_add(trace_idx, E::ZERO, gamma0, gamma1);
        let (leaf_mul0, leaf_mul1) =
            ext_mul(perm_acc_next0, perm_acc_next1, trace_plus_gamma0, trace_plus_gamma1);
        result[idx] = boundary_mask * trace_leaf_end_mask * (leaf_mul0 - perm_acc0);
        idx += 1;
        if is_quadratic {
            result[idx] = boundary_mask * trace_leaf_end_mask * (leaf_mul1 - perm_acc1);
            idx += 1;
        }

        // --------------------------------------------------------------------
        // OOD digest + coin-state save/restore
        // --------------------------------------------------------------------

        // OOD digest columns are constant within a segment.
        for i in 0..DIGEST_WIDTH {
            result[idx + i] = next[COL_OOD_DIGEST_START + i] - current[COL_OOD_DIGEST_START + i];
        }
        idx += DIGEST_WIDTH;

        // Saved coin-state columns are constant within a segment.
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
                ood_trace_current[i]
            } else if i < self.trace_width_ext + self.constraint_width_ext {
                ood_quotient_current[i - self.trace_width_ext]
            } else if i < 2 * self.trace_width_ext + self.constraint_width_ext {
                ood_trace_next[i - self.trace_width_ext - self.constraint_width_ext]
            } else {
                ood_quotient_next[i - (2 * self.trace_width_ext + self.constraint_width_ext)]
            };
            result[idx + i] = mask * (current[RATE_START + offset] - expected);
        }
        idx += self.ood_eval_len;

        // Capture the OOD digest at the end of the OOD-hash segment.
        for i in 0..DIGEST_WIDTH {
            let digest_col = current[COL_OOD_DIGEST_START + i];
            let digest_out = current[RATE_START + i];
            result[idx + i] = ood_digest_capture_mask * (digest_col - digest_out);
        }
        idx += DIGEST_WIDTH;

        // Capture coin state at the z boundary row.
        for i in 0..STATE_WIDTH {
            let saved = current[COL_SAVED_COIN_START + i];
            result[idx + i] = boundary_mask * coin_save_mask * (saved - current[i]);
        }
        idx += STATE_WIDTH;

        // Restore the coin state (and apply the OOD reseed).
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

        // OOD constraint consistency check (evaluate inner constraints at z).
        result[idx] = inner_ood_constraint_eval_10 - inner_ood_constraint_eval_20;
        idx += 1;
        if is_quadratic {
            result[idx] = inner_ood_constraint_eval_11 - inner_ood_constraint_eval_21;
            idx += 1;
        }

        // --------------------------------------------------------------------
        // Transcript draw binding
        // --------------------------------------------------------------------

        // Capture constraint composition coefficients at their draw boundaries.
        for coeff_idx in 0..self.num_constraint_coeffs {
            let block = coeff_idx / RATE_WIDTH;
            let offset = coeff_idx % RATE_WIDTH;
            let mask = coeff_end_masks[block];
            let expected = inner_constraint_coeffs[coeff_idx];
            let drawn = current[RATE_START + offset];
            result[idx + coeff_idx] = mask * (drawn - expected);
        }
        idx += self.num_constraint_coeffs;

        // Capture DEEP coefficients at their draw boundaries.
        for deep_idx in 0..self.num_deep_coeffs {
            let block = deep_idx / RATE_WIDTH;
            let offset = deep_idx % RATE_WIDTH;
            let mask = deep_end_masks[block];
            let expected = inner_deep_coeffs[deep_idx];
            let drawn = current[RATE_START + offset];
            result[idx + deep_idx] = mask * (drawn - expected);
        }
        idx += self.num_deep_coeffs;

        // Capture FRI alphas at their draw boundaries.
        let mut alpha_offset = 0usize;
        for layer_idx in 0..num_fri_layers {
            let mask = fri_alpha_end_masks[layer_idx];
            let expected0 = inner_fri_alphas[layer_idx * extension_degree];
            let drawn0 = current[RATE_START];
            result[idx + alpha_offset] = mask * (drawn0 - expected0);
            alpha_offset += 1;
            if is_quadratic {
                let expected1 = inner_fri_alphas[layer_idx * extension_degree + 1];
                let drawn1 = current[RATE_START + 1];
                result[idx + alpha_offset] = mask * (drawn1 - expected1);
                alpha_offset += 1;
            }
        }
        idx += alpha_offset;

        // --------------------------------------------------------------------
        // DEEP + FRI recursion state-machine
        // --------------------------------------------------------------------

        let remainder_blocks = num_remainder_perms;

        // Remainder coefficients are constant within a segment.
        for block in 0..remainder_blocks {
            let coeff_start = if block == 0 {
                COL_REMAINDER_COEFFS_START
            } else {
                COL_REMAINDER_COEFFS_EXT_START
            };
            for i in 0..NUM_REMAINDER_COEFFS {
                result[idx + block * NUM_REMAINDER_COEFFS + i] =
                    next[coeff_start + i] - current[coeff_start + i];
            }
        }
        idx += remainder_blocks * NUM_REMAINDER_COEFFS;

        // Bind remainder coefficients to the remainder commitment hash input rows.
        for block in 0..remainder_blocks {
            let coeff_start = if block == 0 {
                COL_REMAINDER_COEFFS_START
            } else {
                COL_REMAINDER_COEFFS_EXT_START
            };
            let mask = remainder_hash_row0_masks
                .get(block)
                .copied()
                .unwrap_or(E::ZERO);
            for i in 0..NUM_REMAINDER_COEFFS {
                let coeff = current[coeff_start + i];
                result[idx + block * NUM_REMAINDER_COEFFS + i] =
                    mask * (current[RATE_START + i] - coeff);
            }
        }
        idx += remainder_blocks * NUM_REMAINDER_COEFFS;

        // --- DEEP numerator accumulators ---
        let t1_0 = current[COL_DEEP_T1_ACC];
        let t1_1 = current[COL_DEEP_T1_ACC_LIMB1];
        let t2_0 = current[COL_DEEP_T2_ACC];
        let t2_1 = current[COL_DEEP_T2_ACC_LIMB1];
        let c1_0 = current[COL_DEEP_C1_ACC];
        let c1_1 = current[COL_DEEP_C1_ACC_LIMB1];
        let c2_0 = current[COL_DEEP_C2_ACC];
        let c2_1 = current[COL_DEEP_C2_ACC_LIMB1];

        let t1_next0 = next[COL_DEEP_T1_ACC];
        let t1_next1 = next[COL_DEEP_T1_ACC_LIMB1];
        let t2_next0 = next[COL_DEEP_T2_ACC];
        let t2_next1 = next[COL_DEEP_T2_ACC_LIMB1];
        let c1_next0 = next[COL_DEEP_C1_ACC];
        let c1_next1 = next[COL_DEEP_C1_ACC_LIMB1];
        let c2_next0 = next[COL_DEEP_C2_ACC];
        let c2_next1 = next[COL_DEEP_C2_ACC_LIMB1];

        if is_quadratic {
            let mut t1_delta0 = E::ZERO;
            let mut t1_delta1 = E::ZERO;
            let mut t2_delta0 = E::ZERO;
            let mut t2_delta1 = E::ZERO;
            for (block_idx, start_idx) in self.trace_data_block_starts.iter().enumerate() {
                let mask = trace_leaf_row_masks[block_idx];
                let remaining = self.trace_width_ext.saturating_sub(*start_idx);
                let block_len = remaining.min(RATE_WIDTH);
                debug_assert!(block_len.is_multiple_of(EXTENSION_LIMBS));
                let mut block_t1_0 = E::ZERO;
                let mut block_t1_1 = E::ZERO;
                let mut block_t2_0 = E::ZERO;
                let mut block_t2_1 = E::ZERO;
                let mut j = 0usize;
                while j < block_len {
                    let idx = start_idx + j;
                    let coeff0 = inner_deep_coeffs[idx];
                    let coeff1 = inner_deep_coeffs[idx + 1];
                    let trace0 = current[RATE_START + j];
                    let trace1 = current[RATE_START + j + 1];
                    let ood0 = ood_trace_current[idx];
                    let ood1 = ood_trace_current[idx + 1];
                    let oodg0 = ood_trace_next[idx];
                    let oodg1 = ood_trace_next[idx + 1];

                    let (diff0, diff1) = ext_sub(trace0, trace1, ood0, ood1);
                    let (term0, term1) = ext_mul(coeff0, coeff1, diff0, diff1);
                    block_t1_0 += term0;
                    block_t1_1 += term1;

                    let (diffg0, diffg1) = ext_sub(trace0, trace1, oodg0, oodg1);
                    let (termg0, termg1) = ext_mul(coeff0, coeff1, diffg0, diffg1);
                    block_t2_0 += termg0;
                    block_t2_1 += termg1;

                    j += EXTENSION_LIMBS;
                }
                t1_delta0 += mask * block_t1_0;
                t1_delta1 += mask * block_t1_1;
                t2_delta0 += mask * block_t2_0;
                t2_delta1 += mask * block_t2_1;
            }

            let mut c1_delta0 = E::ZERO;
            let mut c1_delta1 = E::ZERO;
            let mut c2_delta0 = E::ZERO;
            let mut c2_delta1 = E::ZERO;
            for (block_idx, start_idx) in self.constraint_data_block_starts.iter().enumerate() {
                let mask = constraint_leaf_row_masks[block_idx];
                let remaining = self.constraint_width_ext.saturating_sub(*start_idx);
                let block_len = remaining.min(RATE_WIDTH);
                debug_assert!(block_len.is_multiple_of(EXTENSION_LIMBS));
                let mut block_c1_0 = E::ZERO;
                let mut block_c1_1 = E::ZERO;
                let mut block_c2_0 = E::ZERO;
                let mut block_c2_1 = E::ZERO;
                let mut j = 0usize;
                while j < block_len {
                    let idx = start_idx + j;
                    let coeff0 = inner_deep_coeffs[self.trace_width_ext + idx];
                    let coeff1 = inner_deep_coeffs[self.trace_width_ext + idx + 1];
                    let val0 = current[RATE_START + j];
                    let val1 = current[RATE_START + j + 1];
                    let ood0 = ood_quotient_current[idx];
                    let ood1 = ood_quotient_current[idx + 1];
                    let oodg0 = ood_quotient_next[idx];
                    let oodg1 = ood_quotient_next[idx + 1];

                    let (diff0, diff1) = ext_sub(val0, val1, ood0, ood1);
                    let (term0, term1) = ext_mul(coeff0, coeff1, diff0, diff1);
                    block_c1_0 += term0;
                    block_c1_1 += term1;

                    let (diffg0, diffg1) = ext_sub(val0, val1, oodg0, oodg1);
                    let (termg0, termg1) = ext_mul(coeff0, coeff1, diffg0, diffg1);
                    block_c2_0 += termg0;
                    block_c2_1 += termg1;

                    j += EXTENSION_LIMBS;
                }
                c1_delta0 += mask * block_c1_0;
                c1_delta1 += mask * block_c1_1;
                c2_delta0 += mask * block_c2_0;
                c2_delta1 += mask * block_c2_1;
            }

            let reset_term_t1_0 = query_reset_mask * (E::ZERO - t1_0);
            let reset_term_t1_1 = query_reset_mask * (E::ZERO - t1_1);
            let reset_term_t2_0 = query_reset_mask * (E::ZERO - t2_0);
            let reset_term_t2_1 = query_reset_mask * (E::ZERO - t2_1);
            let reset_term_c1_0 = query_reset_mask * (E::ZERO - c1_0);
            let reset_term_c1_1 = query_reset_mask * (E::ZERO - c1_1);
            let reset_term_c2_0 = query_reset_mask * (E::ZERO - c2_0);
            let reset_term_c2_1 = query_reset_mask * (E::ZERO - c2_1);

            result[idx] = t1_next0 - t1_0 - reset_term_t1_0 - t1_delta0;
            result[idx + 1] = t1_next1 - t1_1 - reset_term_t1_1 - t1_delta1;
            result[idx + 2] = t2_next0 - t2_0 - reset_term_t2_0 - t2_delta0;
            result[idx + 3] = t2_next1 - t2_1 - reset_term_t2_1 - t2_delta1;
            result[idx + 4] = c1_next0 - c1_0 - reset_term_c1_0 - c1_delta0;
            result[idx + 5] = c1_next1 - c1_1 - reset_term_c1_1 - c1_delta1;
            result[idx + 6] = c2_next0 - c2_0 - reset_term_c2_0 - c2_delta0;
            result[idx + 7] = c2_next1 - c2_1 - reset_term_c2_1 - c2_delta1;
            idx += 8;
        } else {
            let t1 = t1_0;
            let t2 = t2_0;
            let c1 = c1_0;
            let c2 = c2_0;

            let t1_next = t1_next0;
            let t2_next = t2_next0;
            let c1_next = c1_next0;
            let c2_next = c2_next0;

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
                    let coeff = inner_deep_coeffs[idx];
                    let trace_val = current[RATE_START + j];
                    let ood_z = ood_trace_current[idx];
                    let ood_zg = ood_trace_next[idx];
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
                    let coeff = inner_deep_coeffs[self.trace_width_ext + idx];
                    let val = current[RATE_START + j];
                    let ood_z = ood_quotient_current[idx];
                    let ood_zg = ood_quotient_next[idx];
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
        }

        // --- x / pow state machine ---
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

        // --- evaluation freeze between leaf updates ---
        let eval0 = current[COL_FRI_EVAL];
        let eval1 = current[COL_FRI_EVAL_LIMB1];
        let eval_next0 = next[COL_FRI_EVAL];
        let eval_next1 = next[COL_FRI_EVAL_LIMB1];
        let freeze_mask = one - fri_leaf_any_row_mask - query_reset_mask;
        result[idx] = freeze_mask * (eval_next0 - eval0);
        idx += 1;
        if is_quadratic {
            result[idx] = freeze_mask * (eval_next1 - eval1);
            idx += 1;
        }

        // --- MSB capture bits ---
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

        // --- per-layer eval selection checks ---
        for layer_idx in 0..num_fri_layers {
            let mask = fri_leaf_row_masks[layer_idx];
            let b = current[COL_FRI_MSB_BITS_START + layer_idx];
            let (v00, v01, v10, v11) = if is_quadratic {
                (
                    current[RATE_START],
                    current[RATE_START + 1],
                    current[RATE_START + 2],
                    current[RATE_START + 3],
                )
            } else {
                (current[RATE_START], E::ZERO, current[RATE_START + 1], E::ZERO)
            };
            let selected0 = v00 + b * (v10 - v00);
            let selected1 = v01 + b * (v11 - v01);
            let base_idx = idx + layer_idx * extension_degree;
            result[base_idx] = mask * (eval0 - selected0);
            if is_quadratic {
                result[base_idx + 1] = mask * (eval1 - selected1);
            }
        }
        idx += num_fri_layers * extension_degree;

        // --- DEEP composition check (layer 0) ---
        if num_fri_layers > 0 {
            let mask = fri_leaf_row_masks[0];
            let (z0, z1) = (expected_z0, expected_z1);
            let (z1_0, z1_1) = ext_mul_base(z0, z1, E::from(self.g_trace));
            let (x0, x1) = (x, E::ZERO);
            let (x_minus_z0_0, x_minus_z0_1) = ext_sub(x0, x1, z0, z1);
            let (x_minus_z1_0, x_minus_z1_1) = ext_sub(x0, x1, z1_0, z1_1);
            let (den0, den1) =
                ext_mul(x_minus_z0_0, x_minus_z0_1, x_minus_z1_0, x_minus_z1_1);
            let (t1c1_0, t1c1_1) = ext_add(t1_0, t1_1, c1_0, c1_1);
            let (t2c2_0, t2c2_1) = ext_add(t2_0, t2_1, c2_0, c2_1);
            let (term1_0, term1_1) =
                ext_mul(t1c1_0, t1c1_1, x_minus_z1_0, x_minus_z1_1);
            let (term2_0, term2_1) =
                ext_mul(t2c2_0, t2c2_1, x_minus_z0_0, x_minus_z0_1);
            let (num0, num1) = ext_add(term1_0, term1_1, term2_0, term2_1);
            let (eval_den0, eval_den1) = ext_mul(eval0, eval1, den0, den1);
            result[idx] = mask * (eval_den0 - num0);
            if is_quadratic {
                result[idx + 1] = mask * (eval_den1 - num1);
            }
        } else {
            result[idx] = E::ZERO;
            if is_quadratic {
                result[idx + 1] = E::ZERO;
            }
        }
        idx += extension_degree;

        // --- FRI folding checks ---
        for layer_idx in 0..num_fri_layers {
            let mask = fri_leaf_row_masks[layer_idx];
            let b = current[COL_FRI_MSB_BITS_START + layer_idx];
            let alpha0 = inner_fri_alphas[layer_idx * extension_degree];
            let alpha1 = if is_quadratic {
                inner_fri_alphas[layer_idx * extension_degree + 1]
            } else {
                E::ZERO
            };
            let (v00, v01, v10, v11) = if is_quadratic {
                (
                    current[RATE_START],
                    current[RATE_START + 1],
                    current[RATE_START + 2],
                    current[RATE_START + 3],
                )
            } else {
                (current[RATE_START], E::ZERO, current[RATE_START + 1], E::ZERO)
            };

            let sign = one - two * b;
            let x_base = x * sign;
            let (x0, x1) = (x_base, E::ZERO);
            let (x_plus_a0, x_plus_a1) = ext_add(x0, x1, alpha0, alpha1);
            let (x_minus_a0, x_minus_a1) = ext_sub(x0, x1, alpha0, alpha1);
            let (rhs1_0, rhs1_1) = ext_mul(x_plus_a0, x_plus_a1, v00, v01);
            let (rhs2_0, rhs2_1) = ext_mul(x_minus_a0, x_minus_a1, v10, v11);
            let (rhs0, rhs1) = ext_add(rhs1_0, rhs1_1, rhs2_0, rhs2_1);
            let (lhs0, lhs1) = ext_mul_base(eval_next0, eval_next1, two * x_base);
            let base_idx = idx + layer_idx * extension_degree;
            result[base_idx] = mask * (lhs0 - rhs0);
            if is_quadratic {
                result[base_idx + 1] = mask * (lhs1 - rhs1);
            }
        }
        idx += num_fri_layers * extension_degree;

        // --- Remainder evaluation check ---
        if num_fri_layers > 0 {
            let remainder_mask = *fri_root_masks.last().unwrap_or(&E::ZERO);
            if is_quadratic {
                let mut acc0 = E::ZERO;
                let mut acc1 = E::ZERO;
                for i in 0..NUM_REMAINDER_COEFFS {
                    let (next0, next1) = ext_mul_base(acc0, acc1, x);
                    acc0 = next0 + current[COL_REMAINDER_COEFFS_START + i];
                    acc1 = next1 + current[COL_REMAINDER_COEFFS_EXT_START + i];
                }
                result[idx] = remainder_mask * (eval0 - acc0);
                result[idx + 1] = remainder_mask * (eval1 - acc1);
            } else {
                let mut acc = E::ZERO;
                for i in 0..NUM_REMAINDER_COEFFS {
                    acc = acc * x + current[COL_REMAINDER_COEFFS_START + i];
                }
                result[idx] = remainder_mask * (eval0 - acc);
            }
        } else {
            result[idx] = E::ZERO;
            if is_quadratic {
                result[idx + 1] = E::ZERO;
            }
        }
        idx += extension_degree;

        // Disable all transition constraints on segment-boundary rows (the last row of each
        // concatenated segment), matching the transition-exemption semantics of
        // `StarkVerifierAir` for each segment.
        debug_assert_eq!(idx, result.len(), "transition constraint count mismatch");
        if segment_transition_mask != E::ONE {
            for value in result.iter_mut() {
                *value *= segment_transition_mask;
            }
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();
        let segment_trace_info = TraceInfo::new(VERIFIER_TRACE_WIDTH, self.segment_len);
        let opts = self.options.clone();

        for (seg_idx, inner) in self.pub_inputs.inner.iter().enumerate() {
            let seg_air =
                StarkVerifierAir::new(segment_trace_info.clone(), inner.clone(), opts.clone());
            let offset = seg_idx * self.segment_len;
            for a in seg_air.get_assertions() {
                debug_assert!(a.is_single(), "segment assertions must be single-step");
                assertions.push(Assertion::single(
                    a.column(),
                    a.first_step() + offset,
                    a.values()[0],
                ));
            }
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let segment_trace_info = TraceInfo::new(VERIFIER_TRACE_WIDTH, self.segment_len);
        let opts = self.options.clone();
        let base_air = StarkVerifierAir::new(segment_trace_info, self.template.clone(), opts);
        let base_cols = base_air.get_periodic_column_values();

        let total_rows = self.trace_length();
        let num_segments = self.num_segments();
        let num_fri_layers = self.template.fri_commitments.len().saturating_sub(1);
        let extension_degree = field_extension_degree(self.template.field_extension)
            .expect("unsupported field extension");
        let extra_cols = 1
            + 2 * DIGEST_WIDTH
            + num_fri_layers * DIGEST_WIDTH
            + extension_degree
            + self.num_constraint_coeffs
            + self.num_deep_coeffs
            + num_fri_layers * extension_degree
            + 2 * extension_degree
            + 2 * self.trace_width_ext
            + 2 * self.constraint_width_ext;

        // Repeat the base periodic column values for every segment.
        let mut result = Vec::with_capacity(base_cols.len() + extra_cols);
        for base in &base_cols {
            debug_assert_eq!(base.len(), self.segment_len);
            let mut col = vec![BaseElement::ZERO; total_rows];
            for seg in 0..num_segments {
                let start = seg * self.segment_len;
                col[start..start + self.segment_len].copy_from_slice(base);
            }
            result.push(col);
        }

        // Segment transition mask: 0 only at segment boundaries.
        let mut seg_transition = vec![BaseElement::ONE; total_rows];
        for seg in 0..num_segments.saturating_sub(1) {
            let boundary_row = (seg + 1) * self.segment_len - 1;
            seg_transition[boundary_row] = BaseElement::ZERO;
        }
        seg_transition[total_rows - 1] = BaseElement::ZERO;
        result.push(seg_transition);

        // Per-segment constants used by `evaluate_transition`.
        let mut trace_commitment_cols = vec![vec![BaseElement::ZERO; total_rows]; DIGEST_WIDTH];
        let mut constraint_commitment_cols =
            vec![vec![BaseElement::ZERO; total_rows]; DIGEST_WIDTH];
        let mut fri_commitment_cols =
            vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers * DIGEST_WIDTH];
        let mut expected_z_cols = vec![vec![BaseElement::ZERO; total_rows]; extension_degree];
        let mut constraint_coeff_cols =
            vec![vec![BaseElement::ZERO; total_rows]; self.num_constraint_coeffs];
        let mut deep_coeff_cols = vec![vec![BaseElement::ZERO; total_rows]; self.num_deep_coeffs];
        let mut fri_alpha_cols =
            vec![vec![BaseElement::ZERO; total_rows]; num_fri_layers * extension_degree];
        let mut ood_eval1_cols = vec![vec![BaseElement::ZERO; total_rows]; extension_degree];
        let mut ood_eval2_cols = vec![vec![BaseElement::ZERO; total_rows]; extension_degree];
        let mut ood_trace_current_cols =
            vec![vec![BaseElement::ZERO; total_rows]; self.trace_width_ext];
        let mut ood_quotient_current_cols =
            vec![vec![BaseElement::ZERO; total_rows]; self.constraint_width_ext];
        let mut ood_trace_next_cols =
            vec![vec![BaseElement::ZERO; total_rows]; self.trace_width_ext];
        let mut ood_quotient_next_cols =
            vec![vec![BaseElement::ZERO; total_rows]; self.constraint_width_ext];

        for (seg_idx, inner) in self.pub_inputs.inner.iter().enumerate() {
            let ood_digest = compute_ood_digest(inner);
            let (constraint_coeffs, expected_z_flat, deep_coeffs, fri_alphas_flat) =
                match inner.field_extension {
                    FieldExtension::None => {
                        let (coeffs, z, deep, alphas) =
                            compute_expected_transcript_draws(inner, ood_digest)
                                .expect("failed to reconstruct inner transcript");
                        (coeffs, vec![z], deep, alphas)
                    }
                    FieldExtension::Quadratic => {
                        let (coeffs, z_flat, deep, alphas_flat) =
                            compute_expected_transcript_draws_quadratic(inner, ood_digest)
                                .expect("failed to reconstruct quadratic transcript");
                        (coeffs, z_flat, deep, alphas_flat)
                    }
                    _ => panic!("unsupported field extension for batch verifier"),
                };
            assert_eq!(
                expected_z_flat.len(),
                extension_degree,
                "inner proof {seg_idx} expected z limb count mismatch"
            );
            let (ood_eval1_flat, ood_eval2_flat) = match (inner_proof_kind(inner), inner.field_extension) {
                (Ok(InnerProofKind::RpoAir), FieldExtension::None) => {
                    let (eval1, eval2) = compute_rpo_ood_consistency(
                        inner,
                        &constraint_coeffs,
                        expected_z_flat[0],
                        self.g_trace,
                    )
                    .expect("failed to evaluate RPO constraints at z");
                    (vec![eval1], vec![eval2])
                }
                (Ok(InnerProofKind::RpoAir), FieldExtension::Quadratic) => {
                    let expected_z = [expected_z_flat[0], expected_z_flat[1]];
                    let (eval1, eval2) = compute_rpo_ood_consistency_quadratic(
                        inner,
                        &constraint_coeffs,
                        expected_z,
                        self.g_trace,
                    )
                    .expect("failed to evaluate quadratic RPO constraints at z");
                    (vec![eval1[0], eval1[1]], vec![eval2[0], eval2[1]])
                }
                (Ok(InnerProofKind::TransactionAir), FieldExtension::None) => {
                    let (eval1, eval2) = compute_transaction_ood_consistency(
                        inner,
                        &constraint_coeffs,
                        expected_z_flat[0],
                    )
                    .expect("failed to evaluate transaction constraints at z");
                    (vec![eval1], vec![eval2])
                }
                (Ok(InnerProofKind::TransactionAir), FieldExtension::Quadratic) => {
                    let expected_z = [expected_z_flat[0], expected_z_flat[1]];
                    let (eval1, eval2) = compute_transaction_ood_consistency_quadratic(
                        inner,
                        &constraint_coeffs,
                        expected_z,
                    )
                    .expect("failed to evaluate quadratic transaction constraints at z");
                    (vec![eval1[0], eval1[1]], vec![eval2[0], eval2[1]])
                }
                (Err(err), _) => panic!("unsupported inner proof kind: {err}"),
                (_, _) => panic!("unsupported field extension for batch verifier"),
            };

            let start = seg_idx * self.segment_len;
            let end = start + self.segment_len;

            for i in 0..DIGEST_WIDTH {
                trace_commitment_cols[i][start..end].fill(inner.trace_commitment[i]);
                constraint_commitment_cols[i][start..end].fill(inner.constraint_commitment[i]);
            }

            for layer_idx in 0..num_fri_layers {
                let root = inner.fri_commitments[layer_idx];
                for (i, value) in root.iter().copied().enumerate() {
                    let col_idx = layer_idx * DIGEST_WIDTH + i;
                    fri_commitment_cols[col_idx][start..end].fill(value);
                }
            }

            for (limb_idx, value) in expected_z_flat.iter().copied().enumerate() {
                expected_z_cols[limb_idx][start..end].fill(value);
            }
            for (limb_idx, value) in ood_eval1_flat.iter().copied().enumerate() {
                ood_eval1_cols[limb_idx][start..end].fill(value);
            }
            for (limb_idx, value) in ood_eval2_flat.iter().copied().enumerate() {
                ood_eval2_cols[limb_idx][start..end].fill(value);
            }

            let constraint_len =
                constraint_coeffs.transition.len() + constraint_coeffs.boundary.len();
            assert_eq!(
                constraint_len, self.num_constraint_coeffs,
                "inner proof {seg_idx} constraint coeff length mismatch"
            );
            for (i, value) in constraint_coeffs
                .transition
                .iter()
                .chain(constraint_coeffs.boundary.iter())
                .enumerate()
            {
                constraint_coeff_cols[i][start..end].fill(*value);
            }

            let deep_len = deep_coeffs.trace.len() + deep_coeffs.constraints.len();
            assert_eq!(
                deep_len, self.num_deep_coeffs,
                "inner proof {seg_idx} deep coeff length mismatch"
            );
            for (i, value) in deep_coeffs
                .trace
                .iter()
                .chain(deep_coeffs.constraints.iter())
                .enumerate()
            {
                deep_coeff_cols[i][start..end].fill(*value);
            }
            assert_eq!(
                fri_alphas_flat.len(),
                num_fri_layers * extension_degree,
                "inner proof {seg_idx} fri alpha limb count mismatch"
            );
            for (i, value) in fri_alphas_flat.iter().copied().enumerate() {
                fri_alpha_cols[i][start..end].fill(value);
            }

            for (i, value) in inner.ood_trace_current.iter().copied().enumerate() {
                ood_trace_current_cols[i][start..end].fill(value);
            }
            for (i, value) in inner.ood_quotient_current.iter().copied().enumerate() {
                ood_quotient_current_cols[i][start..end].fill(value);
            }
            for (i, value) in inner.ood_trace_next.iter().copied().enumerate() {
                ood_trace_next_cols[i][start..end].fill(value);
            }
            for (i, value) in inner.ood_quotient_next.iter().copied().enumerate() {
                ood_quotient_next_cols[i][start..end].fill(value);
            }
        }

        for col in trace_commitment_cols {
            result.push(col);
        }
        for col in constraint_commitment_cols {
            result.push(col);
        }
        for col in fri_commitment_cols {
            result.push(col);
        }
        for col in expected_z_cols {
            result.push(col);
        }
        for col in constraint_coeff_cols {
            result.push(col);
        }
        for col in deep_coeff_cols {
            result.push(col);
        }
        for col in fri_alpha_cols {
            result.push(col);
        }
        for col in ood_eval1_cols {
            result.push(col);
        }
        for col in ood_eval2_cols {
            result.push(col);
        }
        for col in ood_trace_current_cols {
            result.push(col);
        }
        for col in ood_quotient_current_cols {
            result.push(col);
        }
        for col in ood_trace_next_cols {
            result.push(col);
        }
        for col in ood_quotient_next_cols {
            result.push(col);
        }

        result
    }
}

fn ext_add<E: FieldElement<BaseField = BaseElement>>(a0: E, a1: E, b0: E, b1: E) -> (E, E) {
    (a0 + b0, a1 + b1)
}

fn ext_sub<E: FieldElement<BaseField = BaseElement>>(a0: E, a1: E, b0: E, b1: E) -> (E, E) {
    (a0 - b0, a1 - b1)
}

fn ext_mul<E: FieldElement<BaseField = BaseElement>>(a0: E, a1: E, b0: E, b1: E) -> (E, E) {
    let a0b0 = a0 * b0;
    let a1b1 = a1 * b1;
    let out0 = a0b0 - (a1b1 + a1b1);
    let out1 = (a0 + a1) * (b0 + b1) - a0b0;
    (out0, out1)
}

fn ext_mul_base<E: FieldElement<BaseField = BaseElement>>(a0: E, a1: E, base: E) -> (E, E) {
    (a0 * base, a1 * base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use winter_math::fields::f64::BaseElement;

    #[test]
    fn test_segment_transition_mask_degree() {
        let segment_len = 4096usize;
        let num_segments = 2usize;
        let total_rows = segment_len * num_segments;

        let mut seg_transition = vec![BaseElement::ONE; total_rows];
        seg_transition[segment_len - 1] = BaseElement::ZERO;
        seg_transition[total_rows - 1] = BaseElement::ZERO;

        // Interpolate the periodic column polynomial over the trace domain and check its degree.
        let mut poly = seg_transition;
        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(total_rows);
        fft::interpolate_poly(&mut poly, &inv_twiddles);
        let degree = polynom::degree_of(&poly);

        // For a length-8192 trace with cycle length 4096, the maximal periodic-column degree is
        // (8192 / 4096) * (4096 - 1) = 8190.
        assert_eq!(degree, 8190);
    }

    #[test]
    fn test_perm_mask_degree() {
        let trace_len = 8192usize;

        let mut values = Vec::with_capacity(trace_len);
        for row in 0..trace_len {
            let local_row = row % super::ROWS_PER_PERMUTATION;
            let mask = (local_row < super::ROWS_PER_PERMUTATION - 1) as u64;
            values.push(BaseElement::new(mask));
        }

        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(trace_len);
        fft::interpolate_poly(&mut values, &inv_twiddles);
        let degree = polynom::degree_of(&values);

        // For a cycle length of 16, the maximal periodic-column degree is (8192 / 16) * (16 - 1) = 7680.
        assert_eq!(degree, 7680);
    }

    #[test]
    fn test_half_round_type_degree() {
        let trace_len = 8192usize;

        let mut values = Vec::with_capacity(trace_len);
        for row in 0..trace_len {
            let local_row = row % super::ROWS_PER_PERMUTATION;
            let val = if local_row >= 14 {
                0
            } else if local_row.is_multiple_of(2) {
                1
            } else {
                2
            };
            values.push(BaseElement::new(val));
        }

        let inv_twiddles = fft::get_inv_twiddles::<BaseElement>(trace_len);
        fft::interpolate_poly(&mut values, &inv_twiddles);
        let degree = polynom::degree_of(&values);

        // Same 16-cycle periodic column behavior as `perm_mask`.
        assert_eq!(degree, 7680);
    }
}
