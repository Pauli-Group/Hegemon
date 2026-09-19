//! Source-derived security accounting for the exact compact V8/SMZ9 program.
//!
//! This module is deliberately not production authority.  It reconstructs the
//! verifier adapter from the source compiler, checks the pinned relation
//! program and profile, evaluates the exact rational loss terms, and refuses a
//! deployed >=128-bit result unless every external refinement, complete-ZK,
//! concrete-hash, composition, and review receipt is present.

#![forbid(unsafe_code)]

use num_bigint::BigUint;
use protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK;
use serde::{Deserialize, Serialize};

use transaction_core::constants::FIELD_MODULUS_U64;
use transaction_core::poseidon2_width16::{
    POSEIDON2_WIDTH16_PARAMETER_SET_ID, POSEIDON2_WIDTH16_PARAMETER_SET_SHA256,
};

use crate::{
    error::TransactionCircuitError,
    smallwood_engine::{
        projected_poseidon2_v8_smz9_inner_proof_bytes, report_smallwood_no_grinding_soundness_v1,
        report_smallwood_sha512_field_xof_abort_bound_v1, SmallwoodArithmetization,
        POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE, SMALLWOOD_LEVEL5_MAX_PIOP_NONCE_TRIALS,
        SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9,
    },
    smallwood_poseidon2_v8_hash_schedule::{
        SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS, SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS,
    },
    smallwood_poseidon2_v8_program::{
        smallwood_poseidon2_v8_program_digest_matches, SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE,
        SMALLWOOD_POSEIDON2_V8_MAXIMUM_LINEAR_CONSTRAINTS,
        SMALLWOOD_POSEIDON2_V8_MAXIMUM_SUMMED_IDENTITY_UNION,
        SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS, SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR,
        SMALLWOOD_POSEIDON2_V8_PROFILE_ID, SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512, SMALLWOOD_POSEIDON2_V8_PROOF_COLUMNS,
        SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS, SMALLWOOD_POSEIDON2_V8_ROW_COUNT,
    },
    smallwood_poseidon2_v8_semantics::SmallwoodPoseidon2V8ConstraintAdapter,
    smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8PublicStatement,
    smallwood_poseidon2_v8_zk_refinement::SMALLWOOD_POSEIDON2_V8_SMZ9_GLOBAL_QROM_LIFETIME_RECEIPT_ID,
    smallwood_semantics::SmallwoodConstraintAdapter,
};

pub const SMALLWOOD_POSEIDON2_V8_SECURITY_REPORT_SCHEMA: &str =
    "hegemon.smallwood.poseidon2-v8.smz9.source-security-report.v3";
pub const SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS: u32 = 128;
pub const SMALLWOOD_POSEIDON2_V8_QROM_QUERY_LOG2: u32 = 64;
pub const SMALLWOOD_POSEIDON2_V8_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2: u32 = 142;
pub const SMALLWOOD_POSEIDON2_V8_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2: u32 = 143;
pub const SMALLWOOD_POSEIDON2_V8_Q19_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2: u32 = 134;
pub const SMALLWOOD_POSEIDON2_V8_Q19_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2: u32 = 135;
pub const SMALLWOOD_POSEIDON2_V8_SHA512_OUTPUT_BITS: usize = 512;
pub const SMALLWOOD_POSEIDON2_V8_POSEIDON_DIGEST_LIMBS: u32 = 7;
pub const SMALLWOOD_POSEIDON2_V8_POSEIDON_LIVE_CALLS_PER_PROOF: u64 =
    SMALLWOOD_POSEIDON2_V8_SCHEDULE_LIVE_CALLS as u64;
pub const SMALLWOOD_POSEIDON2_V8_POSEIDON_EVALUATIONS_PER_PROOF: u64 =
    SMALLWOOD_POSEIDON2_V8_SCHEDULE_PADDED_CALLS as u64;
pub const SMALLWOOD_POSEIDON2_V8_FIXED_DECS_CANDIDATES: usize = 50;
pub const SMALLWOOD_POSEIDON2_V8_MAX_FIELD_XOF_REQUESTS_PER_PROOF: u64 = 1 << 25;
/// The PCS unstack map has three row factors, `r^64 - 1`, `r^35 - 1`,
/// and `r^63 - 1`.  Their Goldilocks root sets have 70 elements in union;
/// exactly `1` and `8` are already excluded by the packing domain `0..64`.
pub const SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ROOT_UNION_SIZE: usize = 70;
pub const SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ROOTS_IN_PACKING_DOMAIN: usize = 2;
pub const SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ADDITIONAL_FORBIDDEN_VALUES: usize =
    SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ROOT_UNION_SIZE
        - SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ROOTS_IN_PACKING_DOMAIN;
pub const SMALLWOOD_POSEIDON2_V8_UNBOUNDED_HISTORY_THEOREM_REQUIRED: &str =
    SMALLWOOD_POSEIDON2_V8_SMZ9_GLOBAL_QROM_LIFETIME_RECEIPT_ID;
pub const SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BITS: u32 = 256;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_EVEN_FIRST_PROGRAM_ENTROPY_BITS: u32 = 366;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_BYTE_FIRST_PROGRAM_ENTROPY_BITS: u32 = 368;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_BYTE_FIRST_PROGRAM_ENTROPY_BYTES: u32 = 46;
pub const SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BYTES: u32 = 32;
pub const SMALLWOOD_POSEIDON2_V8_SALT_WORD_ALIGNMENT_BYTES: u32 = 8;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_WIRE_FIRST_PROGRAM_ENTROPY_BITS: u32 = 384;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_WIRE_FIRST_PROGRAM_ENTROPY_BYTES: u32 = 48;
pub const SMALLWOOD_POSEIDON2_V8_ADDITIONAL_WIRE_FIRST_PROGRAM_ENTROPY_BYTES: u32 = 16;
pub const SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS: u32 = 512;
pub const SMALLWOOD_POSEIDON2_V8_FULL_TREE_PROGRAMS_PER_PROOF: u64 = 2 * (1 << 23) - 1;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_EVEN_FULL_TREE_ENTROPY_BITS: u32 = 414;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_BYTE_FULL_TREE_ENTROPY_BITS: u32 = 416;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_BYTE_FULL_TREE_ENTROPY_BYTES: u32 = 52;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_WIRE_FULL_TREE_ENTROPY_BITS: u32 = 448;
pub const SMALLWOOD_POSEIDON2_V8_MINIMUM_WIRE_FULL_TREE_ENTROPY_BYTES: u32 = 56;
pub const SMALLWOOD_POSEIDON2_V8_ADDITIONAL_WIRE_FULL_TREE_ENTROPY_BYTES: u32 = 24;
pub const SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES: u64 = 372;
pub const SMALLWOOD_POSEIDON2_V8_MAX_LAZY_PROGRAMS_PER_PROOF: u64 =
    SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES + 1;
pub const SMALLWOOD_POSEIDON2_V8_FIXTURE_LAZY_PROGRAMS_PER_PROOF: u64 = 354;
pub const SMALLWOOD_POSEIDON2_V8_MAX_LAZY_LEAF_PROGRAMS_PER_PROOF: u64 = 20;
pub const SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_PROGRAM_CAP_WHEN_LEAF_PROGRAMS_EQUAL_20: u64 =
    SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES
        - SMALLWOOD_POSEIDON2_V8_MAX_LAZY_LEAF_PROGRAMS_PER_PROOF;
pub const SMALLWOOD_POSEIDON2_V8_LAZY_WEIGHTED_CORNER_LEAF_AND_FINAL_PROGRAMS: u64 =
    SMALLWOOD_POSEIDON2_V8_MAX_LAZY_LEAF_PROGRAMS_PER_PROOF + 1;
pub const SMALLWOOD_POSEIDON2_V8_LAZY_MAX_OBSERVED_PROOF_VIEWS_128: u128 =
    18_889_465_930_379_069_227_007;
pub const SMALLWOOD_POSEIDON2_V8_LAZY_LEAF_AND_FINAL_ENTROPY_BITS: u32 = 512;
pub const SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_NODE_ENTROPY_BITS: u32 = 1024;
pub const SMALLWOOD_POSEIDON2_V8_SHA512_PRIMITIVE_PROFILE_ID: &str =
    "sha512-fips180-4-full-64-byte-output-role-framed-smz9";
pub const SMALLWOOD_POSEIDON2_V8_SHA512_ADVANTAGE_FUNCTION_ID: &str =
    "cms-collision=48*T^3/2^512;preimage=T^2/2^512;T=Q+H";
pub const SMALLWOOD_POSEIDON2_V8_POSEIDON2_ADVANTAGE_FUNCTION_ID: &str =
    "collision=T^3/p^7;preimage=T^2/p^7;T=Q+128*V;p=2^64-2^32+1";
pub const SMALLWOOD_POSEIDON2_V8_PRIMITIVE_REVIEW_QUERY_LOG2_SCREENS: [u32; 4] =
    [64, 128, 142, 143];

/// The canonical public-argument carrier is 128,297 bytes, while its full
/// `PendingAction` SCALE record is 128,522 bytes.  The 64 MiB byte quotient is
/// 522 complete maximum-size records, but that is not an upper bound on proof
/// interactions because smaller valid carriers exist.  Security accounting is
/// instead bound to the source-owned shared consensus count cap of 512.
/// The 4096-block scope matches the authenticated stablecoin state epoch, but
/// it is not a cryptographic reset: a reviewed release must either bind a real
/// profile lifetime to a finite proof budget or prove the shared global-query,
/// multi-statement reduction named below.  The corresponding receipt is
/// intentionally absent today.
pub const SMALLWOOD_POSEIDON2_V8_MAX_ACTION_BYTES: u64 = 128_297;
pub const SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES: u64 = 128_522;
pub const SMALLWOOD_POSEIDON2_V8_PROJECTED_INNER_PROOF_BYTES: usize = 122_863;
pub const SMALLWOOD_POSEIDON2_V8_BLOCK_ACTION_BYTE_CAP: u64 = 64 * 1024 * 1024;
pub const SMALLWOOD_POSEIDON2_V8_PROJECTED_RECORD_BYTE_QUOTIENT_DIAGNOSTIC: u64 =
    SMALLWOOD_POSEIDON2_V8_BLOCK_ACTION_BYTE_CAP / SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES;
pub const SMALLWOOD_POSEIDON2_V8_MAX_PROOFS_PER_BLOCK: u64 =
    SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK as u64;
pub const SMALLWOOD_POSEIDON2_V8_SECURITY_EPOCH_BLOCKS: u64 = 1 << 12;
pub const SMALLWOOD_POSEIDON2_V8_SECURITY_EPOCH_MAX_PROOFS: u64 =
    SMALLWOOD_POSEIDON2_V8_MAX_PROOFS_PER_BLOCK * SMALLWOOD_POSEIDON2_V8_SECURITY_EPOCH_BLOCKS;
pub const SMALLWOOD_POSEIDON2_V8_EAGER_PROGRAMS_PER_PROOF: u64 = 1 << 24;
pub const SMALLWOOD_POSEIDON2_V8_ACTIVE_EAGER_MAX_OBSERVED_PROOF_VIEWS_128: u64 =
    1_537_228_672_809_129_301;
pub const SMALLWOOD_POSEIDON2_V8_COMPACT448_EAGER_MAX_OBSERVED_PROOF_VIEWS_128: u64 =
    366_503_897_770;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8CompositionBudgetV1 {
    pub quantum_hash_query_log2: u32,
    pub max_proofs_per_block: u64,
    pub security_epoch_blocks: u64,
    pub security_epoch_max_proofs: u64,
    pub capability_activation_height: Option<u64>,
    pub capability_deactivation_height_exclusive: Option<u64>,
}

impl SmallwoodPoseidon2V8CompositionBudgetV1 {
    pub const fn current_source_budget() -> Self {
        Self {
            quantum_hash_query_log2: SMALLWOOD_POSEIDON2_V8_QROM_QUERY_LOG2,
            max_proofs_per_block: SMALLWOOD_POSEIDON2_V8_MAX_PROOFS_PER_BLOCK,
            security_epoch_blocks: SMALLWOOD_POSEIDON2_V8_SECURITY_EPOCH_BLOCKS,
            security_epoch_max_proofs: SMALLWOOD_POSEIDON2_V8_SECURITY_EPOCH_MAX_PROOFS,
            capability_activation_height: None,
            capability_deactivation_height_exclusive: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8ByteQuotientDiagnosticV2 {
    pub block_action_byte_cap: u64,
    pub projected_pending_action_bytes: u64,
    pub complete_projected_records_per_block: u64,
    pub is_upper_bound_on_proof_interactions: bool,
    pub used_in_security_loss_terms: bool,
}

/// External loss bounds use the conservative exact form `2^-bits`.
/// `None` means no reviewed bound exists and makes the deployed gate fail.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8WholeViewLossBitsV1 {
    /// Quantitative loss for simulating the exact statement-indexed product oracle with the
    /// concrete role-framed SHA-512 interface, including exact domain/step allocation.
    pub sha512_to_indexed_product_oracle: Option<u32>,
    /// Quantitative loss for the adaptive Merkle view.  A separate typed
    /// program-inventory receipt must establish that the executable simulator
    /// has no salt-only first-program point; the direct route remains a no-go.
    pub adaptive_merkle_programming: Option<u32>,
    pub adaptive_final_piop_programming: Option<u32>,
    pub concrete_sha512_instantiation: Option<u32>,
    pub residual_whole_view: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8PrimitiveWorkScreenReceiptV2 {
    pub quantum_query_log2: u32,
    pub collision_advantage_upper_bound: SmallwoodPoseidon2V8ExactLossTermV1,
    pub preimage_advantage_upper_bound: SmallwoodPoseidon2V8ExactLossTermV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2 {
    pub schema: String,
    pub receipt_id: String,
    pub primitive_id: String,
    pub exact_primitive_profile_identity: String,
    pub source_inventory_sha512_hex: String,
    pub theorem_or_reduction_id: String,
    pub theorem_source_sha512_hex: String,
    pub advantage_function: String,
    pub advantage_scope: String,
    pub adversarial_query_log2_max: u32,
    pub honest_programmed_oracle_exposures_decimal: String,
    pub bound_uses_queries_plus_honest_exposures: bool,
    pub max_proof_actions_per_block: u64,
    pub max_proof_interactions: u64,
    pub validity_activation_height: u64,
    pub validity_deactivation_height_exclusive: u64,
    pub work_screens: Vec<SmallwoodPoseidon2V8PrimitiveWorkScreenReceiptV2>,
    pub review_artifact_sha512_hex: String,
    pub independently_reviewed: bool,
}

/// These booleans summarize separately retained receipts.  They are diagnostic
/// inputs only: the release checker must byte-pin the actual distinct files.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8SecurityReceiptsV1 {
    pub exact_compiled_relation_refinement: bool,
    pub exact_smz9_transcript_refinement: bool,
    pub exact_smz9_indexed_logical_oracle_instantiation: bool,
    pub sha512_to_indexed_product_oracle_reduction: bool,
    pub piop_correction_aware_sampling_refinement: bool,
    pub sha512_primitive_security_bound:
        Option<SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2>,
    pub poseidon2_primitive_security_bound:
        Option<SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2>,
    pub adaptive_final_piop_programming_refinement: bool,
    pub executable_program_inventory_excludes_salt_only_first_program: bool,
    pub executable_rng_to_ideal_lazy_inputs_refinement: bool,
    pub adaptive_lazy_merkle_completion_qrom_reduction: bool,
    pub all_adaptive_program_points_conditioned: bool,
    pub adaptive_whole_view_complete_zero_knowledge: bool,
    /// Reviewed upper bound on all honest proof views observed or generated in the
    /// privacy experiment, including off-chain, rejected, orphan, and side-fork views.
    /// This is deliberately independent of the canonical accepted-proof counter.
    pub observed_honest_proof_views: Option<u64>,
    pub observed_honest_proof_views_model_reviewed: bool,
    pub global_history_composition: bool,
    pub consensus_budget_binding: bool,
    pub public_attack_inventory_complete: bool,
    pub independent_review: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8ProofExposureAccountingV2 {
    pub canonical_accepted_proofs: u64,
    pub observed_honest_proof_views: Option<u64>,
    pub observed_honest_proof_views_model_receipt_present: bool,
    pub consensus_counter_bounds_observed_honest_proof_views: bool,
    pub analyzed_proof_views: u64,
    pub analyzed_proof_views_are_canonical_count_diagnostic_only: bool,
    pub eager_programs_per_proof: u64,
    pub active_eager_per_proof_programming_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub active_eager_per_proof_security_bits_floor: u32,
    pub active_eager_max_observed_proof_views_for_strict_128_decimal: String,
    pub active_eager_successor_fails_strict_128: bool,
    pub compact448_eager_per_proof_programming_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub compact448_eager_per_proof_security_bits_floor: u32,
    pub compact448_eager_max_observed_proof_views_for_strict_128_decimal: String,
    pub compact448_eager_successor_fails_strict_128: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8ExactLossTermV1 {
    pub id: String,
    pub numerator_decimal: String,
    pub denominator_decimal: String,
    pub security_bits_floor: u32,
    pub approximate_security_bits: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8AssumptionStatusV1 {
    pub id: String,
    pub satisfied: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8ClaimLedgerV2 {
    pub proved_arithmetic: Vec<String>,
    pub source_checked_bindings: Vec<String>,
    pub stated_primitive_assumptions: Vec<String>,
    pub absent_reductions: Vec<String>,
    pub strongest_quantified_attack_id: String,
    pub public_attack_inventory_complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8KnownAttackV2 {
    pub id: String,
    pub primitive: String,
    pub model: String,
    pub approximate_work_factor_bits: Option<f64>,
    pub end_to_end_forgery_reduction_available: bool,
    pub independently_reviewed: bool,
    pub disposition: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8NoGrindingStatusV2 {
    pub piop_pow_bits: u32,
    pub decs_pow_bits: u32,
    pub canonical_first_valid_nonce: bool,
    pub nonce_trials_are_abort_handling_not_grinding: bool,
    pub exact_grinding_loss_numerator_decimal: String,
    pub exact_grinding_loss_denominator_decimal: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8GlobalQueryWorkScreenV2 {
    pub id: String,
    pub quantum_hash_query_log2: u32,
    pub accepted_proof_interactions: u64,
    pub query_dependent_terms_charged_once: bool,
    pub sha512_collision_uses_queries_plus_honest_programmed_exposures: bool,
    pub cms_instability_uses_queries_plus_honest_programmed_exposures: bool,
    pub honest_programmed_oracle_exposures_decimal: String,
    pub total_oracle_exposures_decimal: String,
    pub abort_terms_excluded_from_soundness_and_reduction_failure: bool,
    pub final_piop_and_full_tree_adaptive_programming_terms_included: bool,
    pub adaptive_programming_uses_conditional_512_bit_entropy: bool,
    pub adaptive_programming_uses_total_step_log2_ceiling: bool,
    pub adaptive_programming_query_log2_ceiling: u32,
    pub exact_smz9_logical_oracle_and_primitive_hypotheses_instantiated: bool,
    pub conditional_soundness_only: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_composed_reduction_failure: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_total_failure_diagnostic: SmallwoodPoseidon2V8ExactLossTermV1,
    pub certified_reduction_upper_bound_strictly_below_half: bool,
    pub is_known_attack: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8CandidateParameterScreenV2 {
    pub id: String,
    pub active_wire: bool,
    pub requires_new_backend_wire_and_layout_theorem: bool,
    pub piop_openings: usize,
    pub decs_openings: usize,
    pub decs_polynomial_degree: usize,
    pub merkle_conditional_entropy_bits: u32,
    pub quantum_hash_query_log2: u32,
    pub accepted_proof_interactions: u64,
    pub fixed_query_conditional_soundness_only: SmallwoodPoseidon2V8ExactLossTermV1,
    pub fixed_query_conditional_composed_reduction_failure: SmallwoodPoseidon2V8ExactLossTermV1,
    pub strongest_certified_reduction_query_log2: u32,
    pub first_failing_certified_reduction_query_log2: u32,
    pub strongest_screen: SmallwoodPoseidon2V8ExactLossTermV1,
    pub strongest_screen_strictly_below_half: bool,
    pub first_failing_screen: SmallwoodPoseidon2V8ExactLossTermV1,
    pub first_failing_screen_strictly_below_half: bool,
    pub completeness_aborts_excluded: bool,
    pub theorem_hypotheses_instantiated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8LifetimeBindingV2 {
    pub analysis_window_blocks: u64,
    pub analysis_max_proof_interactions: u64,
    pub analysis_window_is_cryptographic_reset: bool,
    pub capability_activation_height: Option<u64>,
    pub capability_deactivation_height_exclusive: Option<u64>,
    pub capability_window_blocks: Option<u64>,
    pub capability_max_proof_interactions: Option<u64>,
    pub capability_window_within_analysis_budget: bool,
    pub consensus_budget_binding_receipt_present: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8AdaptiveFirstProgramNoGoV2 {
    pub route_id: String,
    pub salt_only_oracle_program_count: u64,
    pub exact_lazy_program_keys_exclude_salt_only_point: bool,
    pub direct_256_bit_first_program_route_used: bool,
    pub paper_hypotheses_instantiated_for_exact_smz9_program_point: bool,
    pub quantum_hash_query_log2: u32,
    pub accepted_proof_interactions: u64,
    pub current_entropy_bits: u32,
    pub current_entropy_bytes: u32,
    pub current_single_proof_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub current_finite_history_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub current_single_proof_supports_strict_128_bits: bool,
    pub current_finite_history_supports_strict_128_bits: bool,
    pub minimum_even_entropy_bits_for_finite_history: u32,
    pub minimum_even_entropy_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub previous_even_entropy_bits: u32,
    pub previous_even_entropy_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub minimum_byte_entropy_bits: u32,
    pub minimum_byte_entropy_bytes: u32,
    pub salt_word_alignment_bytes: u32,
    pub minimum_wire_entropy_bits: u32,
    pub minimum_wire_entropy_bytes: u32,
    pub additional_wire_entropy_bytes: u32,
    pub wire_change_required_only_if_this_route_applies: bool,
    pub alternative_reduction_may_avoid_wire_change: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8ConditionalAdaptiveProgrammingScreenV2 {
    pub route_id: String,
    pub program_point_scope: String,
    pub paper_and_executable_hypotheses_instantiated: bool,
    pub entropy_bits: u32,
    pub quantum_hash_query_log2: u32,
    pub accepted_proof_interactions: u64,
    pub conditional_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub supports_strict_128_bits: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8AdaptiveFullTreeProgrammingScreenV2 {
    pub route_id: String,
    pub program_point_scope: String,
    pub paper_and_all_points_hypotheses_instantiated: bool,
    pub programs_per_proof: u64,
    pub accepted_proof_interactions: u64,
    pub total_programming_events_decimal: String,
    pub conditional_entropy_bits_per_program: u32,
    pub conditional_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub supports_strict_128_bits: bool,
    pub minimum_even_entropy_bits_for_strict_128: u32,
    pub minimum_even_entropy_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub previous_even_entropy_bits: u32,
    pub previous_even_entropy_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub previous_even_entropy_supports_strict_128_bits: bool,
    pub minimum_whole_byte_entropy_bits: u32,
    pub minimum_whole_byte_entropy_bytes: u32,
    pub salt_word_alignment_bytes: u32,
    pub minimum_wire_entropy_bits: u32,
    pub minimum_wire_entropy_bytes: u32,
    pub additional_wire_entropy_bytes: u32,
    pub minimum_wire_entropy_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub current_leaf_tape_entropy_bits: u32,
    pub leaf_input_fiber_refinement_instantiated: bool,
    pub hidden_child_internal_node_propagation_instantiated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8LazyMerkleProgrammingScreenV3 {
    pub route_id: String,
    pub source_records_exact_input_output_pairs_for_each_lazy_program: bool,
    pub maximum_compact_authentication_nodes: u64,
    pub maximum_abstract_programs_per_proof_including_final_piop: u64,
    pub fixture_abstract_programs_per_proof_including_final_piop: u64,
    pub accepted_proof_interactions: u64,
    pub maximum_abstract_programming_events_decimal: String,
    pub maximum_leaf_programs_per_proof: u64,
    pub maximum_internal_node_programs_per_proof: u64,
    pub internal_node_program_cap_when_leaf_programs_equal_20: u64,
    pub joint_leaf_plus_internal_program_cap: u64,
    pub weighted_upper_bound_leaf_and_final_program_cap: u64,
    pub weighted_upper_bound_internal_node_program_cap: u64,
    pub leaf_and_final_conditional_entropy_bits: u32,
    pub internal_node_conditional_entropy_bits: u32,
    pub conditional_leaf_and_final_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_internal_node_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_combined_loss: SmallwoodPoseidon2V8ExactLossTermV1,
    pub supports_strict_128_bits: bool,
    pub maximum_observed_honest_proof_views_for_strict_128_decimal: String,
    pub first_failing_observed_honest_proof_views_decimal: String,
    pub maximum_observed_honest_proof_views_supports_strict_128: bool,
    pub first_failing_observed_honest_proof_views_supports_strict_128: bool,
    pub source_role_framed_io_recording_refinement_instantiated: bool,
    pub source_duplicate_program_input_rejection_instantiated: bool,
    pub executable_rng_to_ideal_fresh_inputs_refinement_instantiated: bool,
    pub adaptive_lazy_completion_qrom_reduction_instantiated: bool,
    pub concrete_sha512_qro_instantiated: bool,
    pub global_prior_query_schedule_instantiated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodPoseidon2V8SecurityReportV1 {
    pub schema: String,
    pub proof_wire_magic_ascii: String,
    pub profile_wire_id: u8,
    pub program_digest_hex: String,
    pub program_sha512_hex: String,
    pub row_count: usize,
    pub proof_columns: usize,
    pub constraint_degree: usize,
    pub packing_factor: usize,
    pub nonlinear_identity_count: usize,
    pub maximum_linear_identity_count: usize,
    pub maximum_summed_identity_union: usize,
    pub rho: usize,
    pub piop_openings: usize,
    pub beta: usize,
    pub decs_domain_size: usize,
    pub decs_openings: usize,
    pub decs_eta: usize,
    pub piop_linear_correction_degree: usize,
    pub piop_pcs_unstack_additional_forbidden_values: usize,
    pub piop_admissibility_bad_tuple_coefficient: usize,
    pub piop_nonce_bad_per_trial: usize,
    pub projected_inner_proof_bytes: usize,
    pub projected_two_output_action_bytes: usize,
    pub projected_pending_action_bytes: usize,
    pub security_epoch_is_cryptographic_reset: bool,
    pub unbounded_history_theorem_required: String,
    pub budget: SmallwoodPoseidon2V8CompositionBudgetV1,
    pub byte_quotient_diagnostic: SmallwoodPoseidon2V8ByteQuotientDiagnosticV2,
    pub lifetime_binding: SmallwoodPoseidon2V8LifetimeBindingV2,
    pub proof_exposure_accounting: SmallwoodPoseidon2V8ProofExposureAccountingV2,
    pub interactive_terms: Vec<SmallwoodPoseidon2V8ExactLossTermV1>,
    pub interactive_aggregate: SmallwoodPoseidon2V8ExactLossTermV1,
    pub field_xof_requested_words: usize,
    pub field_xof_candidate_words: usize,
    pub field_xof_minimum_rejections: usize,
    pub field_xof_request_union: u64,
    pub field_xof_abort_union: SmallwoodPoseidon2V8ExactLossTermV1,
    pub canonical_piop_opening_abort: SmallwoodPoseidon2V8ExactLossTermV1,
    pub fixed_decs_sampler_abort: SmallwoodPoseidon2V8ExactLossTermV1,
    pub sha512_collision: SmallwoodPoseidon2V8ExactLossTermV1,
    pub sha512_preimage: SmallwoodPoseidon2V8ExactLossTermV1,
    pub tape_database_bridge: SmallwoodPoseidon2V8ExactLossTermV1,
    pub poseidon2_collision: SmallwoodPoseidon2V8ExactLossTermV1,
    pub poseidon2_preimage: SmallwoodPoseidon2V8ExactLossTermV1,
    pub poseidon_honest_evaluations_decimal: String,
    pub ideal_cms_qrom: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_fixed_query_baseline_without_honest_program_exposures:
        SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_completeness_abort_per_proof: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_completeness_abort_finite_history: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_global_query_soundness_only: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_global_query_composed_reduction_failure: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_total_failure_finite_history_diagnostic: SmallwoodPoseidon2V8ExactLossTermV1,
    pub conditional_global_query_work_screens: Vec<SmallwoodPoseidon2V8GlobalQueryWorkScreenV2>,
    pub strongest_conditional_global_query_work_factor_log2: u32,
    pub first_failing_conditional_global_query_work_factor_log2: u32,
    pub no_grinding: SmallwoodPoseidon2V8NoGrindingStatusV2,
    pub adaptive_first_program_no_go: SmallwoodPoseidon2V8AdaptiveFirstProgramNoGoV2,
    pub adaptive_final_piop_programming_screen:
        SmallwoodPoseidon2V8ConditionalAdaptiveProgrammingScreenV2,
    pub adaptive_full_tree_programming_screen:
        SmallwoodPoseidon2V8AdaptiveFullTreeProgrammingScreenV2,
    pub adaptive_lazy_merkle_programming_screen: SmallwoodPoseidon2V8LazyMerkleProgrammingScreenV3,
    pub candidate_parameter_screens: Vec<SmallwoodPoseidon2V8CandidateParameterScreenV2>,
    pub claim_ledger: SmallwoodPoseidon2V8ClaimLedgerV2,
    pub known_attacks: Vec<SmallwoodPoseidon2V8KnownAttackV2>,
    pub sha512_primitive_security_bound:
        Option<SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2>,
    pub poseidon2_primitive_security_bound:
        Option<SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2>,
    pub sha512_to_indexed_product_oracle_reduction_bound:
        Option<SmallwoodPoseidon2V8ExactLossTermV1>,
    pub external_whole_view_terms: Vec<Option<SmallwoodPoseidon2V8ExactLossTermV1>>,
    pub assumptions: Vec<SmallwoodPoseidon2V8AssumptionStatusV1>,
    pub deployed_finite_history_composed: Option<SmallwoodPoseidon2V8ExactLossTermV1>,
    pub deployed_composed_security_bits_floor: Option<u32>,
    pub meets_128_bit_deployed_floor: bool,
    pub production_eligible: bool,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug)]
struct ExactRatio {
    numerator: BigUint,
    denominator: BigUint,
}

impl ExactRatio {
    fn new(numerator: BigUint, denominator: BigUint) -> Result<Self, TransactionCircuitError> {
        if denominator == BigUint::from(0u8) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "V8 security ratio has zero denominator",
            ));
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    fn power_of_two(bits: u32) -> Self {
        Self {
            numerator: BigUint::from(1u8),
            denominator: BigUint::from(1u8) << bits as usize,
        }
    }

    fn add(&self, other: &Self) -> Self {
        Self {
            numerator: &self.numerator * &other.denominator + &other.numerator * &self.denominator,
            denominator: &self.denominator * &other.denominator,
        }
    }

    fn scale(&self, factor: u64) -> Self {
        Self {
            numerator: &self.numerator * BigUint::from(factor),
            denominator: self.denominator.clone(),
        }
    }

    fn bits_floor(&self) -> u32 {
        if self.numerator == BigUint::from(0u8) {
            return u32::MAX;
        }
        let mut bits = self
            .denominator
            .bits()
            .saturating_sub(self.numerator.bits()) as usize;
        while bits > 0 && (&self.numerator << bits) > self.denominator {
            bits -= 1;
        }
        while bits < u32::MAX as usize && (&self.numerator << (bits + 1)) <= self.denominator {
            bits += 1;
        }
        u32::try_from(bits).unwrap_or(u32::MAX)
    }

    fn approximate_bits(&self) -> f64 {
        biguint_log2(&self.denominator) - biguint_log2(&self.numerator)
    }

    fn strictly_below_power_of_two(&self, bits: u32) -> bool {
        (&self.numerator << bits as usize) < self.denominator
    }

    fn below_half(&self) -> bool {
        (&self.numerator << 1usize) < self.denominator
    }

    fn report(&self, id: &str) -> SmallwoodPoseidon2V8ExactLossTermV1 {
        SmallwoodPoseidon2V8ExactLossTermV1 {
            id: id.to_owned(),
            numerator_decimal: self.numerator.to_str_radix(10),
            denominator_decimal: self.denominator.to_str_radix(10),
            security_bits_floor: self.bits_floor(),
            approximate_security_bits: self.approximate_bits(),
        }
    }

    fn maximum_union_count_supporting_bits(
        &self,
        bits: u32,
    ) -> Result<BigUint, TransactionCircuitError> {
        if self.numerator == BigUint::from(0u8) {
            return Err(TransactionCircuitError::ConstraintViolation(
                "V8 security maximum union count is unbounded for a zero loss term",
            ));
        }
        Ok(&self.denominator / (&self.numerator << bits as usize))
    }
}

fn biguint_log2(value: &BigUint) -> f64 {
    if *value == BigUint::from(0u8) {
        return f64::NEG_INFINITY;
    }
    let bits = value.bits();
    let retained = bits.min(53);
    let shifted = if bits > retained {
        value >> usize::try_from(bits - retained).unwrap_or(usize::MAX)
    } else {
        value.clone()
    };
    let top = shifted.to_u64_digits().first().copied().unwrap_or(0);
    (top as f64).log2() + (bits - retained) as f64
}

fn falling_product(value: u128, count: usize) -> Result<BigUint, TransactionCircuitError> {
    if value < count as u128 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security falling product underflows",
        ));
    }
    Ok((0..count).fold(BigUint::from(1u8), |product, index| {
        product * BigUint::from(value - index as u128)
    }))
}

const fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn pow_mod_field(mut base: u64, mut exponent: u64) -> u64 {
    let modulus = FIELD_MODULUS_U64 as u128;
    let mut result = 1u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus) as u64;
        }
        base = ((base as u128 * base as u128) % modulus) as u64;
        exponent >>= 1;
    }
    result
}

/// Count the additional field values rejected by the exact PCS-unstack map.
///
/// The nonzero Goldilocks elements form a cyclic group of order `p - 1`, so
/// `x^n = 1` has `gcd(n, p - 1)` roots.  Inclusion-exclusion over exponents
/// 64, 35, and 63 gives 70 roots in total.  We then enumerate the 64 public
/// packing points to avoid charging the two roots (`1` and `8`) which the
/// base outside-domain predicate already rejects.
fn pcs_unstack_additional_forbidden_values() -> Result<usize, TransactionCircuitError> {
    let group_order = FIELD_MODULUS_U64 - 1;
    let root_count = |exponent: u64| gcd_u64(exponent, group_order) as usize;
    let pair_64_35 = gcd_u64(64, 35);
    let pair_64_63 = gcd_u64(64, 63);
    let pair_35_63 = gcd_u64(35, 63);
    let triple = gcd_u64(pair_64_35, 63);
    let union_size = root_count(64)
        .checked_add(root_count(35))
        .and_then(|value| value.checked_add(root_count(63)))
        .and_then(|value| value.checked_sub(root_count(pair_64_35)))
        .and_then(|value| value.checked_sub(root_count(pair_64_63)))
        .and_then(|value| value.checked_sub(root_count(pair_35_63)))
        .and_then(|value| value.checked_add(root_count(triple)))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security PCS-unstack root-union arithmetic overflow",
        ))?;
    let roots_in_packing_domain = (0..SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR as u64)
        .filter(|&point| {
            [64u64, 35, 63]
                .into_iter()
                .any(|exponent| pow_mod_field(point, exponent) == 1)
        })
        .count();
    if union_size != SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ROOT_UNION_SIZE
        || roots_in_packing_domain != SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ROOTS_IN_PACKING_DOMAIN
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security PCS-unstack forbidden-value inventory drift",
        ));
    }
    union_size
        .checked_sub(roots_in_packing_domain)
        .filter(|&count| count == SMALLWOOD_POSEIDON2_V8_PCS_UNSTACK_ADDITIONAL_FORBIDDEN_VALUES)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security PCS-unstack additional-forbidden count drift",
        ))
}

fn sum_ratios(terms: &[ExactRatio]) -> ExactRatio {
    terms.iter().fold(
        ExactRatio {
            numerator: BigUint::from(0u8),
            denominator: BigUint::from(1u8),
        },
        |sum, term| sum.add(term),
    )
}

fn ghhm_direct_adaptive_programming_ratio(
    entropy_bits: u32,
    quantum_query_log2: u32,
    proof_interactions: impl Into<BigUint>,
) -> Result<ExactRatio, TransactionCircuitError> {
    let entropy_gap = entropy_bits.checked_sub(quantum_query_log2).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "V8 GHHM arithmetic requires entropy at least the query exponent",
        ),
    )?;
    // Even gaps are exact dyadic specializations.  For odd gaps, flooring the
    // half-gap makes the denominator smaller and is therefore a conservative
    // rational upper bound on the square-root expression.
    ExactRatio::new(
        BigUint::from(3u8) * proof_interactions.into(),
        BigUint::from(1u8) << (1 + entropy_gap / 2) as usize,
    )
}

fn total_oracle_exposure_log2_ceiling(
    query_log2: u32,
    proof_views: u64,
) -> Result<u32, TransactionCircuitError> {
    total_oracle_exposure_log2_ceiling_biguint(query_log2, &BigUint::from(proof_views))
}

fn total_oracle_exposure_log2_ceiling_biguint(
    query_log2: u32,
    proof_views: &BigUint,
) -> Result<u32, TransactionCircuitError> {
    let total = (BigUint::from(1u8) << query_log2 as usize)
        + BigUint::from(SMALLWOOD_POSEIDON2_V8_EAGER_PROGRAMS_PER_PROOF) * proof_views;
    oracle_exposure_log2_ceiling(&total)
}

fn oracle_exposure_log2_ceiling(total: &BigUint) -> Result<u32, TransactionCircuitError> {
    u32::try_from(total.bits()).map_err(|_| {
        TransactionCircuitError::ConstraintViolation(
            "V8 total oracle-exposure exponent exceeds u32",
        )
    })
}

fn minimum_even_entropy_bits_for_strict_target(
    exposure_log2_ceiling: u32,
    programming_events: &BigUint,
    target_bits: u32,
) -> Result<u32, TransactionCircuitError> {
    let mut entropy_bits = exposure_log2_ceiling
        .checked_add(exposure_log2_ceiling & 1)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 adaptive entropy search overflow",
        ))?;
    loop {
        if ghhm_direct_adaptive_programming_ratio(
            entropy_bits,
            exposure_log2_ceiling,
            programming_events.clone(),
        )?
        .strictly_below_power_of_two(target_bits)
        {
            return Ok(entropy_bits);
        }
        entropy_bits = entropy_bits
            .checked_add(2)
            .filter(|value| *value <= 4096)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "V8 adaptive entropy search exceeded the audited range",
            ))?;
    }
}

fn round_up_to_multiple(value: u32, multiple: u32) -> Result<u32, TransactionCircuitError> {
    let remainder = value % multiple;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(multiple - remainder)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "V8 adaptive entropy alignment overflow",
            ))
    }
}

fn generic_eager_adaptive_programming_ratio(
    entropy_bits: u32,
    query_log2: u32,
    proof_views: u64,
) -> Result<ExactRatio, TransactionCircuitError> {
    let exposure_log2_ceiling = total_oracle_exposure_log2_ceiling(query_log2, proof_views)?;
    ghhm_direct_adaptive_programming_ratio(
        entropy_bits,
        exposure_log2_ceiling,
        BigUint::from(SMALLWOOD_POSEIDON2_V8_EAGER_PROGRAMS_PER_PROOF) * BigUint::from(proof_views),
    )
}

fn generic_compact448_eager_adaptive_programming_ratio(
    query_log2: u32,
    proof_views: u64,
) -> Result<ExactRatio, TransactionCircuitError> {
    let exposure_log2_ceiling = total_oracle_exposure_log2_ceiling(query_log2, proof_views)?;
    let tree = ghhm_direct_adaptive_programming_ratio(
        448,
        exposure_log2_ceiling,
        BigUint::from(SMALLWOOD_POSEIDON2_V8_FULL_TREE_PROGRAMS_PER_PROOF)
            * BigUint::from(proof_views),
    )?;
    let final_piop =
        ghhm_direct_adaptive_programming_ratio(512, exposure_log2_ceiling, proof_views)?;
    Ok(tree.add(&final_piop))
}

fn generic_lazy_joint_adaptive_programming_ratio(
    query_log2: u32,
    proof_views: impl Into<BigUint>,
) -> Result<ExactRatio, TransactionCircuitError> {
    let proof_views = proof_views.into();
    let exposure_log2_ceiling =
        total_oracle_exposure_log2_ceiling_biguint(query_log2, &proof_views)?;
    let leaf_and_final = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_LAZY_LEAF_AND_FINAL_ENTROPY_BITS,
        exposure_log2_ceiling,
        BigUint::from(SMALLWOOD_POSEIDON2_V8_LAZY_WEIGHTED_CORNER_LEAF_AND_FINAL_PROGRAMS)
            * &proof_views,
    )?;
    let internal = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_NODE_ENTROPY_BITS,
        exposure_log2_ceiling,
        BigUint::from(SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_PROGRAM_CAP_WHEN_LEAF_PROGRAMS_EQUAL_20)
            * proof_views,
    )?;
    Ok(leaf_and_final.add(&internal))
}

fn maximum_lazy_joint_observed_proof_views_for_strict_target(
    query_log2: u32,
    target_bits: u32,
) -> Result<u128, TransactionCircuitError> {
    let supports_target = |proof_views: u128| -> Result<bool, TransactionCircuitError> {
        Ok(
            generic_lazy_joint_adaptive_programming_ratio(query_log2, proof_views)?
                .strictly_below_power_of_two(target_bits),
        )
    };
    let mut lower = 0u128;
    let mut upper = 1u128;
    while supports_target(upper)? {
        lower = upper;
        upper = upper
            .checked_mul(2)
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "V8 lazy observed-proof-view ceiling search overflow",
            ))?;
    }
    while lower + 1 < upper {
        let midpoint = lower + (upper - lower) / 2;
        if supports_target(midpoint)? {
            lower = midpoint;
        } else {
            upper = midpoint;
        }
    }
    Ok(lower)
}

fn assumption(id: &str, satisfied: bool) -> SmallwoodPoseidon2V8AssumptionStatusV1 {
    SmallwoodPoseidon2V8AssumptionStatusV1 {
        id: id.to_owned(),
        satisfied,
    }
}

fn is_nonzero_sha512_hex(value: &str) -> bool {
    value.len() == 128
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn expected_primitive_work_screens(
    sha512_mode: bool,
    honest_programmed_oracle_exposures: &BigUint,
) -> Result<Vec<SmallwoodPoseidon2V8PrimitiveWorkScreenReceiptV2>, TransactionCircuitError> {
    let sha_space = BigUint::from(1u8) << SMALLWOOD_POSEIDON2_V8_SHA512_OUTPUT_BITS;
    let poseidon_space =
        BigUint::from(FIELD_MODULUS_U64).pow(SMALLWOOD_POSEIDON2_V8_POSEIDON_DIGEST_LIMBS);
    SMALLWOOD_POSEIDON2_V8_PRIMITIVE_REVIEW_QUERY_LOG2_SCREENS
        .into_iter()
        .map(|query_log2| {
            let queries = BigUint::from(1u8) << query_log2 as usize;
            let total = queries + honest_programmed_oracle_exposures;
            let (prefix, collision, preimage) = if sha512_mode {
                (
                    "sha512",
                    ExactRatio::new(total.pow(3) * BigUint::from(48u8), sha_space.clone())?,
                    ExactRatio::new(total.pow(2), sha_space.clone())?,
                )
            } else {
                (
                    "poseidon2_width16",
                    ExactRatio::new(total.pow(3), poseidon_space.clone())?,
                    ExactRatio::new(total.pow(2), poseidon_space.clone())?,
                )
            };
            Ok(SmallwoodPoseidon2V8PrimitiveWorkScreenReceiptV2 {
                quantum_query_log2: query_log2,
                collision_advantage_upper_bound: collision
                    .report(&format!("{prefix}_collision_at_2pow{query_log2}")),
                preimage_advantage_upper_bound: preimage
                    .report(&format!("{prefix}_preimage_at_2pow{query_log2}")),
            })
        })
        .collect()
}

fn validate_primitive_security_bound_receipt(
    receipt: &SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2,
    budget: SmallwoodPoseidon2V8CompositionBudgetV1,
    honest_programmed_oracle_exposures: &BigUint,
    analyzed_proof_views: u64,
    sha512_mode: bool,
) -> Result<(), TransactionCircuitError> {
    let (expected_receipt_id, expected_primitive_id, expected_profile, expected_function) =
        if sha512_mode {
            (
                "sha512-smz9-qrom-primitive-bound",
                "SHA-512",
                SMALLWOOD_POSEIDON2_V8_SHA512_PRIMITIVE_PROFILE_ID.to_owned(),
                SMALLWOOD_POSEIDON2_V8_SHA512_ADVANTAGE_FUNCTION_ID,
            )
        } else {
            (
                "poseidon2-width16-smz9-primitive-bound",
                POSEIDON2_WIDTH16_PARAMETER_SET_ID,
                format!(
                    "{POSEIDON2_WIDTH16_PARAMETER_SET_ID};sha256={POSEIDON2_WIDTH16_PARAMETER_SET_SHA256}"
                ),
                SMALLWOOD_POSEIDON2_V8_POSEIDON2_ADVANTAGE_FUNCTION_ID,
            )
        };
    let expected_honest_exposures = honest_programmed_oracle_exposures.clone();
    let valid_window = budget
        .capability_activation_height
        .zip(budget.capability_deactivation_height_exclusive)
        .is_some_and(|(activation, deactivation)| {
            receipt.validity_activation_height == activation
                && receipt.validity_deactivation_height_exclusive == deactivation
        });
    let expected_screens =
        expected_primitive_work_screens(sha512_mode, honest_programmed_oracle_exposures)?;
    if receipt.schema != "hegemon.smallwood.poseidon2-v8.primitive-security-bound.v2"
        || receipt.receipt_id != expected_receipt_id
        || receipt.primitive_id != expected_primitive_id
        || receipt.exact_primitive_profile_identity != expected_profile
        || !is_nonzero_sha512_hex(&receipt.source_inventory_sha512_hex)
        || receipt.theorem_or_reduction_id.is_empty()
        || !is_nonzero_sha512_hex(&receipt.theorem_source_sha512_hex)
        || receipt.advantage_function != expected_function
        || receipt.advantage_scope != "global-once"
        || receipt.adversarial_query_log2_max
            != SMALLWOOD_POSEIDON2_V8_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2
        || receipt.honest_programmed_oracle_exposures_decimal
            != expected_honest_exposures.to_string()
        || !receipt.bound_uses_queries_plus_honest_exposures
        || receipt.max_proof_actions_per_block != budget.max_proofs_per_block
        || receipt.max_proof_interactions != analyzed_proof_views
        || !valid_window
        || receipt.work_screens != expected_screens
        || !is_nonzero_sha512_hex(&receipt.review_artifact_sha512_hex)
        || !receipt.independently_reviewed
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 quantitative primitive security-bound receipt mismatch",
        ));
    }
    Ok(())
}

fn ensure_exact_source_relation(
    relation: &SmallwoodPoseidon2V8ConstraintAdapter,
) -> Result<(), TransactionCircuitError> {
    if !smallwood_poseidon2_v8_program_digest_matches()
        || relation.relation_digest() != &SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
        || !relation.compiler_complete()
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security report rejects an unpinned or incomplete relation program",
        ));
    }
    if relation.arithmetization() != SmallwoodArithmetization::DirectPacked64Poseidon2V8Sha512Smz9
        || relation.row_count() != SMALLWOOD_POSEIDON2_V8_ROW_COUNT
        || relation.packing_factor() != SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
        || relation.constraint_degree() != SMALLWOOD_POSEIDON2_V8_CONSTRAINT_DEGREE
        || relation.constraint_count() != SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINTS
        || relation.linear_constraint_count() != SMALLWOOD_POSEIDON2_V8_MAXIMUM_LINEAR_CONSTRAINTS
        || !relation.auxiliary_witness_words().is_empty()
        || relation.auxiliary_witness_limb_count() != Some(0)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security report relation geometry does not match the pinned maximum program",
        ));
    }
    Ok(())
}

pub fn report_smallwood_poseidon2_v8_source_security_v1(
    budget: SmallwoodPoseidon2V8CompositionBudgetV1,
    receipts: SmallwoodPoseidon2V8SecurityReceiptsV1,
    whole_view_losses: SmallwoodPoseidon2V8WholeViewLossBitsV1,
) -> Result<SmallwoodPoseidon2V8SecurityReportV1, TransactionCircuitError> {
    let expected_history_proofs = budget
        .max_proofs_per_block
        .checked_mul(budget.security_epoch_blocks);
    if budget.quantum_hash_query_log2 > 255
        || budget.max_proofs_per_block == 0
        || budget.security_epoch_blocks == 0
        || expected_history_proofs != Some(budget.security_epoch_max_proofs)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security composition budget is malformed",
        ));
    }
    let (capability_window_blocks, capability_max_proof_interactions) = match (
        budget.capability_activation_height,
        budget.capability_deactivation_height_exclusive,
    ) {
        (None, None) => (None, None),
        (Some(activation), Some(deactivation))
            if activation < deactivation && deactivation < u64::MAX =>
        {
            let blocks = deactivation - activation;
            let proofs = blocks.checked_mul(budget.max_proofs_per_block).ok_or(
                TransactionCircuitError::ConstraintViolation(
                    "V8 capability lifetime proof budget overflows",
                ),
            )?;
            (Some(blocks), Some(proofs))
        }
        _ => {
            return Err(TransactionCircuitError::ConstraintViolation(
                "V8 capability lifetime must be absent or a valid half-open activation window",
            ));
        }
    };
    let capability_window_within_analysis_budget = capability_window_blocks
        .zip(capability_max_proof_interactions)
        .is_some_and(|(blocks, proofs)| {
            blocks <= budget.security_epoch_blocks && proofs <= budget.security_epoch_max_proofs
        });
    if capability_window_blocks.is_some() && !capability_window_within_analysis_budget {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 capability lifetime exceeds the analyzed proof-interaction budget",
        ));
    }
    let lifetime_binding = SmallwoodPoseidon2V8LifetimeBindingV2 {
        analysis_window_blocks: budget.security_epoch_blocks,
        analysis_max_proof_interactions: budget.security_epoch_max_proofs,
        analysis_window_is_cryptographic_reset: false,
        capability_activation_height: budget.capability_activation_height,
        capability_deactivation_height_exclusive: budget.capability_deactivation_height_exclusive,
        capability_window_blocks,
        capability_max_proof_interactions,
        capability_window_within_analysis_budget,
        consensus_budget_binding_receipt_present: receipts.consensus_budget_binding,
    };
    let observed_honest_proof_views_model_receipt_present =
        receipts.observed_honest_proof_views.is_some()
            && receipts.observed_honest_proof_views_model_reviewed;
    let analyzed_proof_views = receipts
        .observed_honest_proof_views
        .unwrap_or(budget.security_epoch_max_proofs);
    let active_per_proof =
        generic_eager_adaptive_programming_ratio(512, budget.quantum_hash_query_log2, 1u64)?;
    let active_max = generic_eager_adaptive_programming_ratio(
        512,
        budget.quantum_hash_query_log2,
        SMALLWOOD_POSEIDON2_V8_ACTIVE_EAGER_MAX_OBSERVED_PROOF_VIEWS_128,
    )?;
    let active_first_fail = generic_eager_adaptive_programming_ratio(
        512,
        budget.quantum_hash_query_log2,
        SMALLWOOD_POSEIDON2_V8_ACTIVE_EAGER_MAX_OBSERVED_PROOF_VIEWS_128 + 1,
    )?;
    let compact448_per_proof =
        generic_compact448_eager_adaptive_programming_ratio(budget.quantum_hash_query_log2, 1)?;
    let compact448_max = generic_compact448_eager_adaptive_programming_ratio(
        budget.quantum_hash_query_log2,
        SMALLWOOD_POSEIDON2_V8_COMPACT448_EAGER_MAX_OBSERVED_PROOF_VIEWS_128,
    )?;
    let compact448_first_fail = generic_compact448_eager_adaptive_programming_ratio(
        budget.quantum_hash_query_log2,
        SMALLWOOD_POSEIDON2_V8_COMPACT448_EAGER_MAX_OBSERVED_PROOF_VIEWS_128 + 1,
    )?;
    if active_per_proof.bits_floor() != 198
        || compact448_per_proof.bits_floor() != 166
        || !active_max.strictly_below_power_of_two(128)
        || active_first_fail.strictly_below_power_of_two(128)
        || !compact448_max.strictly_below_power_of_two(128)
        || compact448_first_fail.strictly_below_power_of_two(128)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 generic observed-proof-view programming ceiling drift",
        ));
    }
    let proof_exposure_accounting = SmallwoodPoseidon2V8ProofExposureAccountingV2 {
        canonical_accepted_proofs: budget.security_epoch_max_proofs,
        observed_honest_proof_views: receipts.observed_honest_proof_views,
        observed_honest_proof_views_model_receipt_present,
        consensus_counter_bounds_observed_honest_proof_views: false,
        analyzed_proof_views,
        analyzed_proof_views_are_canonical_count_diagnostic_only: receipts
            .observed_honest_proof_views
            .is_none(),
        eager_programs_per_proof: SMALLWOOD_POSEIDON2_V8_EAGER_PROGRAMS_PER_PROOF,
        active_eager_per_proof_programming_loss: active_per_proof
            .report("active_eager_programming_one_observed_proof_view"),
        active_eager_per_proof_security_bits_floor: 198,
        active_eager_max_observed_proof_views_for_strict_128_decimal:
            SMALLWOOD_POSEIDON2_V8_ACTIVE_EAGER_MAX_OBSERVED_PROOF_VIEWS_128.to_string(),
        active_eager_successor_fails_strict_128: true,
        compact448_eager_per_proof_programming_loss: compact448_per_proof
            .report("compact448_eager_programming_one_observed_proof_view"),
        compact448_eager_per_proof_security_bits_floor: 166,
        compact448_eager_max_observed_proof_views_for_strict_128_decimal:
            SMALLWOOD_POSEIDON2_V8_COMPACT448_EAGER_MAX_OBSERVED_PROOF_VIEWS_128.to_string(),
        compact448_eager_successor_fails_strict_128: true,
    };

    let relation = SmallwoodPoseidon2V8ConstraintAdapter::from_public_statement(
        &SmallwoodPoseidon2V8PublicStatement::default(),
    )
    .map_err(|error| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "V8 security source relation reconstruction failed: {error}"
        ))
    })?;
    ensure_exact_source_relation(&relation)?;

    let profile = POSEIDON2_V8_SMZ9_SMALLWOOD_NO_GRINDING_PROFILE;
    let engine_geometry = report_smallwood_no_grinding_soundness_v1(
        &relation,
        SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
        profile,
    )?;
    if engine_geometry.n_cols != SMALLWOOD_POSEIDON2_V8_PROOF_COLUMNS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security report proof-column geometry drift",
        ));
    }
    let projected_inner_proof_bytes = projected_poseidon2_v8_smz9_inner_proof_bytes(&relation)?;
    if projected_inner_proof_bytes != SMALLWOOD_POSEIDON2_V8_PROJECTED_INNER_PROOF_BYTES {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security report SMZ9 proof-size projection drift",
        ));
    }

    let field = BigUint::from(FIELD_MODULUS_U64);
    let piop_consistency_degree = engine_geometry
        .d_q
        .checked_add(SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security PIOP degree overflow",
        ))?;
    let decs_polynomial_degree = engine_geometry
        .n_cols
        .checked_add(profile.decs_nb_opened_evals)
        .and_then(|value| value.checked_sub(1))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security DECS degree overflow",
        ))?;

    // The executable nonce selector conditions on distinct openings outside
    // the 64-point packing domain, a nonzero linear-correction numerator, and
    // full-rank PCS-unstack blocks.  The latter excludes the roots of
    // r^64=1, r^35=1, or r^63=1.  Their exact Goldilocks union has 70 values,
    // of which 1 and 8 are already in the packing domain, leaving 68 new
    // forbidden values.  If B is the ordered distinct/outside set,
    // |B|=(p-64)_q.  The correction numerator removes at most q*p^(q-1)
    // tuples and the PCS condition removes at most q*68*p^(q-1), so the
    // accepted set has at least |B|-q*(1+68)*p^(q-1) tuples.  Dividing the
    // usual discrepancy-root count by that lower bound is conservative; the
    // deployed sampling-refinement receipt remains deliberately false.
    let distinct_outside_opening_tuples = falling_product(
        (FIELD_MODULUS_U64 - SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR as u64) as u128,
        profile.nb_opened_evals,
    )?;
    let piop_pcs_unstack_additional_forbidden_values = pcs_unstack_additional_forbidden_values()?;
    let piop_admissibility_bad_tuple_coefficient = profile
        .nb_opened_evals
        .checked_mul(
            1usize
                .checked_add(piop_pcs_unstack_additional_forbidden_values)
                .ok_or(TransactionCircuitError::ConstraintViolation(
                    "V8 security opening-admissibility coefficient overflow",
                ))?,
        )
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security opening-admissibility coefficient overflow",
        ))?;
    let admissibility_rejected_tuple_bound =
        BigUint::from(piop_admissibility_bad_tuple_coefficient)
            * field.pow((profile.nb_opened_evals - 1) as u32);
    if admissibility_rejected_tuple_bound >= distinct_outside_opening_tuples {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 security full-admissibility opening denominator is not positive",
        ));
    }
    let admissibility_aware_opening_tuples =
        &distinct_outside_opening_tuples - &admissibility_rejected_tuple_bound;

    let interactive = vec![
        ExactRatio::new(BigUint::from(1u8), field.pow(profile.decs_eta as u32))?,
        ExactRatio::new(BigUint::from(1u8), field.pow(profile.rho as u32))?,
        ExactRatio::new(
            falling_product(piop_consistency_degree as u128, profile.nb_opened_evals)?,
            admissibility_aware_opening_tuples,
        )?,
        ExactRatio::new(
            falling_product(decs_polynomial_degree as u128, profile.decs_nb_opened_evals)?,
            falling_product(profile.decs_nb_evals as u128, profile.decs_nb_opened_evals)?,
        )?,
    ];
    let interactive_aggregate = sum_ratios(&interactive);
    if interactive_aggregate.bits_floor() != 288
        || !(288.79..288.80).contains(&interactive_aggregate.approximate_bits())
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8/SMZ9 admissibility-aware security accounting misses the required 288-bit floor",
        ));
    }

    let q = BigUint::from(1u8) << budget.quantum_hash_query_log2 as usize;
    let hash_space = BigUint::from(1u8) << SMALLWOOD_POSEIDON2_V8_SHA512_OUTPUT_BITS;
    let sha512_collision = ExactRatio::new(q.pow(3), hash_space.clone())?;
    let sha512_preimage = ExactRatio::new(q.pow(2), hash_space.clone())?;
    let tape_database_bridge = ExactRatio::new(
        BigUint::from(2u8) * BigUint::from(profile.decs_nb_evals).pow(2),
        hash_space.clone(),
    )?;
    let ideal_cms_qrom = interactive_aggregate
        .scale(12)
        .scale_biguint(&q.pow(2))
        .add(&sha512_collision.scale(48))
        .add(&tape_database_bridge);
    if budget.quantum_hash_query_log2 == SMALLWOOD_POSEIDON2_V8_QROM_QUERY_LOG2
        && ideal_cms_qrom.bits_floor() != 157
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8/SMZ9 admissibility-aware CMS/QROM accounting misses the required 157-bit floor",
        ));
    }

    let maximum_identity_count = relation
        .constraint_count()
        .max(relation.linear_constraint_count());
    let maximum_field_words = profile
        .rho
        .max(profile.decs_eta)
        .checked_mul(maximum_identity_count)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security field-XOF request overflow",
        ))?;
    let xof = report_smallwood_sha512_field_xof_abort_bound_v1(maximum_field_words)?;
    let field_xof_abort_union = ExactRatio::new(
        xof.union_bound_numerator
            * BigUint::from(SMALLWOOD_POSEIDON2_V8_MAX_FIELD_XOF_REQUESTS_PER_PROOF),
        xof.union_bound_denominator,
    )?;

    // Besides packing-domain hits and pairwise collisions, the canonical
    // opening selector rejects a zero linear-correction numerator
    //
    //   sum_{x in packing} product_j (x - r_j).
    //
    // This is a nonzero polynomial of total degree `q`: the coefficient of
    // `product_j r_j` is `(-1)^q * packing_factor`, nonzero in Goldilocks.
    // Schwartz-Zippel therefore contributes at most `q / p` per trial.  The
    // exact PCS-unstack root inventory adds `q * 68 / p`.  The separate
    // receipt below keeps both algebraic steps explicit rather than silently
    // folding them into the collision count.
    let piop_linear_correction_degree = profile.nb_opened_evals;
    let piop_nonce_bad_per_trial = profile
        .nb_opened_evals
        .checked_mul(SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR)
        .and_then(|value| {
            value.checked_add(profile.nb_opened_evals * (profile.nb_opened_evals - 1) / 2)
        })
        .and_then(|value| value.checked_add(piop_linear_correction_degree))
        .and_then(|value| {
            value
                .checked_add(profile.nb_opened_evals * piop_pcs_unstack_additional_forbidden_values)
        })
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security opening-abort bound overflow",
        ))?;
    let canonical_piop_opening_abort = ExactRatio::new(
        BigUint::from(piop_nonce_bad_per_trial).pow(SMALLWOOD_LEVEL5_MAX_PIOP_NONCE_TRIALS),
        field.pow(SMALLWOOD_LEVEL5_MAX_PIOP_NONCE_TRIALS),
    )?;

    let decs_bad_draws = SMALLWOOD_POSEIDON2_V8_FIXED_DECS_CANDIDATES
        .checked_sub(profile.decs_nb_opened_evals - 1)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 security DECS sampler slack underflow",
        ))?;
    let fixed_decs_sampler_abort = ExactRatio::new(
        (BigUint::from(1u8) << SMALLWOOD_POSEIDON2_V8_FIXED_DECS_CANDIDATES)
            * BigUint::from(SMALLWOOD_POSEIDON2_V8_FIXED_DECS_CANDIDATES)
                .pow(decs_bad_draws as u32),
        BigUint::from(profile.decs_nb_evals).pow(decs_bad_draws as u32),
    )?;

    let poseidon_space = field.pow(SMALLWOOD_POSEIDON2_V8_POSEIDON_DIGEST_LIMBS);
    let poseidon_honest_evaluations =
        BigUint::from(SMALLWOOD_POSEIDON2_V8_POSEIDON_EVALUATIONS_PER_PROOF)
            * BigUint::from(analyzed_proof_views);
    let total_poseidon_exposures = &q + &poseidon_honest_evaluations;
    let poseidon2_collision =
        ExactRatio::new(total_poseidon_exposures.pow(3), poseidon_space.clone())?;
    let poseidon2_preimage =
        ExactRatio::new(total_poseidon_exposures.pow(2), poseidon_space.clone())?;

    // SHA-512 collision and the tape/database term are already included in the
    // CMS expression.  This fixed-Q soundness screen adds only the independent
    // preimage and Poseidon2 terms.  Honest-prover rejection exhaustion is a
    // fail-closed completeness event and is recorded separately below.
    let conditional_fixed_query_soundness = sum_ratios(&[
        ideal_cms_qrom.clone(),
        sha512_preimage.clone(),
        poseidon2_collision.clone(),
        poseidon2_preimage.clone(),
    ]);
    let conditional_completeness_abort_per_proof = sum_ratios(&[
        field_xof_abort_union.clone(),
        canonical_piop_opening_abort.clone(),
        fixed_decs_sampler_abort.clone(),
    ]);
    let conditional_completeness_abort_finite_history =
        conditional_completeness_abort_per_proof.scale(analyzed_proof_views);
    let byte_quotient_diagnostic = SmallwoodPoseidon2V8ByteQuotientDiagnosticV2 {
        block_action_byte_cap: SMALLWOOD_POSEIDON2_V8_BLOCK_ACTION_BYTE_CAP,
        projected_pending_action_bytes: SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES,
        complete_projected_records_per_block:
            SMALLWOOD_POSEIDON2_V8_PROJECTED_RECORD_BYTE_QUOTIENT_DIAGNOSTIC,
        is_upper_bound_on_proof_interactions: false,
        used_in_security_loss_terms: false,
    };
    let full_tree_programming_events =
        BigUint::from(SMALLWOOD_POSEIDON2_V8_FULL_TREE_PROGRAMS_PER_PROOF)
            * BigUint::from(analyzed_proof_views);
    let all_honest_programmed_oracle_exposures =
        BigUint::from(SMALLWOOD_POSEIDON2_V8_EAGER_PROGRAMS_PER_PROOF)
            * BigUint::from(analyzed_proof_views);
    let active_exposure_log2_ceiling =
        total_oracle_exposure_log2_ceiling(budget.quantum_hash_query_log2, analyzed_proof_views)?;
    if observed_honest_proof_views_model_receipt_present
        && !generic_eager_adaptive_programming_ratio(
            SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
            budget.quantum_hash_query_log2,
            analyzed_proof_views,
        )?
        .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 reviewed observed-proof-view bound exceeds the active strict-128 ceiling",
        ));
    }
    if let Some(receipt) = receipts.sha512_primitive_security_bound.as_ref() {
        validate_primitive_security_bound_receipt(
            receipt,
            budget,
            &all_honest_programmed_oracle_exposures,
            analyzed_proof_views,
            true,
        )?;
    }
    if let Some(receipt) = receipts.poseidon2_primitive_security_bound.as_ref() {
        validate_primitive_security_bound_receipt(
            receipt,
            budget,
            &poseidon_honest_evaluations,
            analyzed_proof_views,
            false,
        )?;
    }

    // This is the strongest finite-history arithmetic available from the
    // statement-indexed global-query route.  Query-dependent CMS/SHA/Poseidon
    // terms are charged once at the total global query count.  The SHA-512
    // collision exposure includes both those queries and all honest programmed
    // outputs in the conservative eager schedule.  Separate conditional
    // GHHM-shaped terms charge one final-PIOP program plus every eager DECS-tree
    // program under ideal 512-bit conditional entropy.  Completeness aborts are
    // excluded from both soundness and reduction-failure bounds.
    let conditional_global_query_ratio = |query_log2: u32| -> Result<
        (ExactRatio, ExactRatio, ExactRatio, BigUint),
        TransactionCircuitError,
    > {
        let global_queries = BigUint::from(1u8) << query_log2 as usize;
        let total_oracle_exposures = &global_queries + &all_honest_programmed_oracle_exposures;
        let sha_collision_at_queries =
            ExactRatio::new(total_oracle_exposures.pow(3), hash_space.clone())?;
        let sha_preimage_at_queries =
            ExactRatio::new(total_oracle_exposures.pow(2), hash_space.clone())?;
        let ideal_cms_at_queries = interactive_aggregate
            .scale(12)
            .scale_biguint(&total_oracle_exposures.pow(2))
            .add(&sha_collision_at_queries.scale(48))
            .add(&tape_database_bridge);
        let total_poseidon_exposures = &global_queries + &poseidon_honest_evaluations;
        let poseidon_collision_at_queries =
            ExactRatio::new(total_poseidon_exposures.pow(3), poseidon_space.clone())?;
        let poseidon_preimage_at_queries =
            ExactRatio::new(total_poseidon_exposures.pow(2), poseidon_space.clone())?;
        let adaptive_query_log2_ceiling = oracle_exposure_log2_ceiling(&total_oracle_exposures)?;
        let final_piop_programming_at_queries = ghhm_direct_adaptive_programming_ratio(
            SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
            adaptive_query_log2_ceiling,
            analyzed_proof_views,
        )?;
        let full_tree_programming_at_queries = ghhm_direct_adaptive_programming_ratio(
            SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
            adaptive_query_log2_ceiling,
            full_tree_programming_events.clone(),
        )?;
        let soundness_only = sum_ratios(&[
            ideal_cms_at_queries,
            sha_preimage_at_queries,
            poseidon_collision_at_queries,
            poseidon_preimage_at_queries,
        ]);
        let composed_reduction_failure = sum_ratios(&[
            soundness_only.clone(),
            final_piop_programming_at_queries,
            full_tree_programming_at_queries,
        ]);
        let total_failure_diagnostic =
            composed_reduction_failure.add(&conditional_completeness_abort_finite_history);
        Ok((
            soundness_only,
            composed_reduction_failure,
            total_failure_diagnostic,
            total_oracle_exposures,
        ))
    };
    let (
        conditional_global_query_soundness_only,
        conditional_global_query_composed_reduction_failure,
        conditional_total_failure_finite_history_diagnostic,
        _,
    ) = conditional_global_query_ratio(budget.quantum_hash_query_log2)?;
    let global_query_hypotheses_instantiated = receipts.exact_compiled_relation_refinement
        && receipts.exact_smz9_transcript_refinement
        && receipts.exact_smz9_indexed_logical_oracle_instantiation
        && receipts.sha512_to_indexed_product_oracle_reduction
        && whole_view_losses.sha512_to_indexed_product_oracle.is_some()
        && receipts.piop_correction_aware_sampling_refinement
        && receipts.sha512_primitive_security_bound.is_some()
        && receipts.poseidon2_primitive_security_bound.is_some()
        && receipts.adaptive_final_piop_programming_refinement
        && receipts.executable_program_inventory_excludes_salt_only_first_program
        && receipts.executable_rng_to_ideal_lazy_inputs_refinement
        && receipts.adaptive_lazy_merkle_completion_qrom_reduction
        && receipts.all_adaptive_program_points_conditioned
        && receipts.adaptive_whole_view_complete_zero_knowledge
        && observed_honest_proof_views_model_receipt_present
        && receipts.global_history_composition
        && receipts.consensus_budget_binding
        && capability_window_within_analysis_budget;
    let conditional_global_query_work_screens = [
        SMALLWOOD_POSEIDON2_V8_QROM_QUERY_LOG2,
        SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS,
        SMALLWOOD_POSEIDON2_V8_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2,
        SMALLWOOD_POSEIDON2_V8_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2,
    ]
    .into_iter()
    .map(|query_log2| {
        let (soundness, reduction_failure, total_failure, total_exposures) =
            conditional_global_query_ratio(query_log2)?;
        Ok(SmallwoodPoseidon2V8GlobalQueryWorkScreenV2 {
            id: format!("conditional_global_query_work_at_2pow{query_log2}"),
            quantum_hash_query_log2: query_log2,
            accepted_proof_interactions: analyzed_proof_views,
            query_dependent_terms_charged_once: true,
            sha512_collision_uses_queries_plus_honest_programmed_exposures: true,
            cms_instability_uses_queries_plus_honest_programmed_exposures: true,
            honest_programmed_oracle_exposures_decimal: all_honest_programmed_oracle_exposures
                .to_string(),
            total_oracle_exposures_decimal: total_exposures.to_str_radix(10),
            abort_terms_excluded_from_soundness_and_reduction_failure: true,
            final_piop_and_full_tree_adaptive_programming_terms_included: true,
            adaptive_programming_uses_conditional_512_bit_entropy: true,
            adaptive_programming_uses_total_step_log2_ceiling: true,
            adaptive_programming_query_log2_ceiling: oracle_exposure_log2_ceiling(
                &total_exposures,
            )?,
            exact_smz9_logical_oracle_and_primitive_hypotheses_instantiated:
                global_query_hypotheses_instantiated,
            conditional_soundness_only: soundness.report(&format!(
                "conditional_global_query_soundness_only_at_2pow{query_log2}"
            )),
            conditional_composed_reduction_failure: reduction_failure.report(&format!(
                "conditional_global_query_composed_reduction_failure_at_2pow{query_log2}"
            )),
            conditional_total_failure_diagnostic: total_failure.report(&format!(
                "conditional_total_failure_diagnostic_at_2pow{query_log2}"
            )),
            certified_reduction_upper_bound_strictly_below_half: reduction_failure.below_half(),
            is_known_attack: false,
        })
    })
    .collect::<Result<Vec<_>, TransactionCircuitError>>()?;
    if !conditional_global_query_work_screens[2].certified_reduction_upper_bound_strictly_below_half
        || conditional_global_query_work_screens[3]
            .certified_reduction_upper_bound_strictly_below_half
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 conditional global-query work-factor boundary drift",
        ));
    }

    // Prospective q=19 screens are arithmetic comparisons only.  They do not
    // alter the active q=20 SMZ9 profile, proof size, transcript backend, or
    // authorization state.  The 448-bit variant additionally models a new
    // commitment/Merkle wire while leaving the field XOF and final-PIOP fresh
    // input at 512 bits.
    let q19_decs_openings = 19usize;
    let q19_decs_polynomial_degree = engine_geometry
        .n_cols
        .checked_add(q19_decs_openings)
        .and_then(|value| value.checked_sub(1))
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 q19 candidate DECS degree overflow",
        ))?;
    let q19_interactive = sum_ratios(&[
        interactive[0].clone(),
        interactive[1].clone(),
        interactive[2].clone(),
        ExactRatio::new(
            falling_product(q19_decs_polynomial_degree as u128, q19_decs_openings)?,
            falling_product(profile.decs_nb_evals as u128, q19_decs_openings)?,
        )?,
    ]);
    let candidate_ratio = |candidate_interactive: &ExactRatio,
                           query_log2: u32,
                           commitment_bits: u32,
                           merkle_entropy_bits: u32|
     -> Result<(ExactRatio, ExactRatio), TransactionCircuitError> {
        let global_queries = BigUint::from(1u8) << query_log2 as usize;
        let total_exposures = &global_queries + &all_honest_programmed_oracle_exposures;
        let adaptive_query_log2_ceiling = oracle_exposure_log2_ceiling(&total_exposures)?;
        let commitment_space = BigUint::from(1u8) << commitment_bits as usize;
        let (sha_collision, sha_preimage) = if commitment_bits == 512 {
            (
                ExactRatio::new(total_exposures.pow(3), commitment_space.clone())?,
                ExactRatio::new(total_exposures.pow(2), commitment_space.clone())?,
            )
        } else {
            // The compact candidate truncates only commitment/Merkle outputs.
            // Keep the exact final-PIOP SHA-512 domain separate instead of
            // charging that program through the 448-bit tree domain.
            let tree_exposures = &global_queries + &full_tree_programming_events;
            let final_piop_exposures = &global_queries + BigUint::from(analyzed_proof_views);
            let full_sha512_space = BigUint::from(1u8) << 512usize;
            (
                ExactRatio::new(tree_exposures.pow(3), commitment_space.clone())?.add(
                    &ExactRatio::new(final_piop_exposures.pow(3), full_sha512_space.clone())?,
                ),
                ExactRatio::new(tree_exposures.pow(2), commitment_space.clone())?.add(
                    &ExactRatio::new(final_piop_exposures.pow(2), full_sha512_space)?,
                ),
            )
        };
        let tape_bridge = ExactRatio::new(
            BigUint::from(2u8) * BigUint::from(profile.decs_nb_evals).pow(2),
            commitment_space,
        )?;
        let cms = candidate_interactive
            .scale(12)
            .scale_biguint(&total_exposures.pow(2))
            .add(&sha_collision.scale(48))
            .add(&tape_bridge);
        let soundness = sum_ratios(&[
            cms,
            sha_preimage,
            ExactRatio::new(
                (&global_queries + &poseidon_honest_evaluations).pow(3),
                poseidon_space.clone(),
            )?,
            ExactRatio::new(
                (&global_queries + &poseidon_honest_evaluations).pow(2),
                poseidon_space.clone(),
            )?,
        ]);
        let composed = sum_ratios(&[
            soundness.clone(),
            ghhm_direct_adaptive_programming_ratio(
                SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
                adaptive_query_log2_ceiling,
                analyzed_proof_views,
            )?,
            ghhm_direct_adaptive_programming_ratio(
                merkle_entropy_bits,
                adaptive_query_log2_ceiling,
                full_tree_programming_events.clone(),
            )?,
        ]);
        Ok((soundness, composed))
    };
    let mut candidate_parameter_screens = [("q19-sha512", 512u32), ("q19-compact448", 448u32)]
        .into_iter()
        .map(|(id, commitment_bits)| {
            let (fixed_soundness, fixed_composed) = candidate_ratio(
                &q19_interactive,
                budget.quantum_hash_query_log2,
                commitment_bits,
                commitment_bits,
            )?;
            let (_, strongest) = candidate_ratio(
                &q19_interactive,
                SMALLWOOD_POSEIDON2_V8_Q19_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2,
                commitment_bits,
                commitment_bits,
            )?;
            let (_, first_failing) = candidate_ratio(
                &q19_interactive,
                SMALLWOOD_POSEIDON2_V8_Q19_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2,
                commitment_bits,
                commitment_bits,
            )?;
            if !strongest.below_half() || first_failing.below_half() {
                return Err(TransactionCircuitError::ConstraintViolation(
                    "V8 q19 candidate certified-query frontier drift",
                ));
            }
            Ok(SmallwoodPoseidon2V8CandidateParameterScreenV2 {
                id: id.to_owned(),
                active_wire: false,
                requires_new_backend_wire_and_layout_theorem: true,
                piop_openings: profile.nb_opened_evals,
                decs_openings: q19_decs_openings,
                decs_polynomial_degree: q19_decs_polynomial_degree,
                merkle_conditional_entropy_bits: commitment_bits,
                quantum_hash_query_log2: budget.quantum_hash_query_log2,
                accepted_proof_interactions: analyzed_proof_views,
                fixed_query_conditional_soundness_only: fixed_soundness
                    .report(&format!("{id}_fixed_query_soundness_only")),
                fixed_query_conditional_composed_reduction_failure: fixed_composed
                    .report(&format!("{id}_fixed_query_composed_reduction_failure")),
                strongest_certified_reduction_query_log2:
                    SMALLWOOD_POSEIDON2_V8_Q19_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2,
                first_failing_certified_reduction_query_log2:
                    SMALLWOOD_POSEIDON2_V8_Q19_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2,
                strongest_screen: strongest.report(&format!(
                    "{id}_composed_reduction_failure_at_2pow{}",
                    SMALLWOOD_POSEIDON2_V8_Q19_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2
                )),
                strongest_screen_strictly_below_half: true,
                first_failing_screen: first_failing.report(&format!(
                    "{id}_composed_reduction_failure_at_2pow{}",
                    SMALLWOOD_POSEIDON2_V8_Q19_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2
                )),
                first_failing_screen_strictly_below_half: false,
                completeness_aborts_excluded: true,
                theorem_hypotheses_instantiated: false,
            })
        })
        .collect::<Result<Vec<_>, TransactionCircuitError>>()?;
    let (q20_compact_fixed_soundness, q20_compact_fixed_composed) = candidate_ratio(
        &interactive_aggregate,
        budget.quantum_hash_query_log2,
        448,
        448,
    )?;
    let (_, q20_compact_strongest) = candidate_ratio(
        &interactive_aggregate,
        SMALLWOOD_POSEIDON2_V8_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2,
        448,
        448,
    )?;
    let (_, q20_compact_first_failing) = candidate_ratio(
        &interactive_aggregate,
        SMALLWOOD_POSEIDON2_V8_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2,
        448,
        448,
    )?;
    if !q20_compact_strongest.below_half() || q20_compact_first_failing.below_half() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 q20 compact448 candidate certified-query frontier drift",
        ));
    }
    candidate_parameter_screens.push(SmallwoodPoseidon2V8CandidateParameterScreenV2 {
        id: "q20-compact448".to_owned(),
        active_wire: false,
        requires_new_backend_wire_and_layout_theorem: true,
        piop_openings: profile.nb_opened_evals,
        decs_openings: profile.decs_nb_opened_evals,
        decs_polynomial_degree,
        merkle_conditional_entropy_bits: 448,
        quantum_hash_query_log2: budget.quantum_hash_query_log2,
        accepted_proof_interactions: analyzed_proof_views,
        fixed_query_conditional_soundness_only: q20_compact_fixed_soundness
            .report("q20-compact448_fixed_query_soundness_only"),
        fixed_query_conditional_composed_reduction_failure: q20_compact_fixed_composed
            .report("q20-compact448_fixed_query_composed_reduction_failure"),
        strongest_certified_reduction_query_log2:
            SMALLWOOD_POSEIDON2_V8_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2,
        first_failing_certified_reduction_query_log2:
            SMALLWOOD_POSEIDON2_V8_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2,
        strongest_screen: q20_compact_strongest
            .report("q20-compact448_composed_reduction_failure_at_2pow142"),
        strongest_screen_strictly_below_half: true,
        first_failing_screen: q20_compact_first_failing
            .report("q20-compact448_composed_reduction_failure_at_2pow143"),
        first_failing_screen_strictly_below_half: false,
        completeness_aborts_excluded: true,
        theorem_hypotheses_instantiated: false,
    });

    let single_view_exposure_log2_ceiling =
        total_oracle_exposure_log2_ceiling(budget.quantum_hash_query_log2, 1)?;
    let current_first_program_single = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BITS,
        single_view_exposure_log2_ceiling,
        1u64,
    )?;
    let current_first_program_history = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BITS,
        active_exposure_log2_ceiling,
        analyzed_proof_views,
    )?;
    let first_program_events = BigUint::from(analyzed_proof_views);
    let minimum_even_first_program_entropy_bits = minimum_even_entropy_bits_for_strict_target(
        active_exposure_log2_ceiling,
        &first_program_events,
        SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS,
    )?;
    let minimum_even_first_program_history = ghhm_direct_adaptive_programming_ratio(
        minimum_even_first_program_entropy_bits,
        active_exposure_log2_ceiling,
        analyzed_proof_views,
    )?;
    let previous_even_first_program_history = ghhm_direct_adaptive_programming_ratio(
        minimum_even_first_program_entropy_bits - 2,
        active_exposure_log2_ceiling,
        analyzed_proof_views,
    )?;
    let minimum_byte_first_program_entropy_bits =
        round_up_to_multiple(minimum_even_first_program_entropy_bits, 8)?;
    let minimum_wire_first_program_entropy_bits =
        round_up_to_multiple(minimum_byte_first_program_entropy_bits, 64)?;
    let wire_first_program_history = ghhm_direct_adaptive_programming_ratio(
        minimum_wire_first_program_entropy_bits,
        active_exposure_log2_ceiling,
        analyzed_proof_views,
    )?;
    if current_first_program_single
        .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || current_first_program_history
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || !minimum_even_first_program_history
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || previous_even_first_program_history
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || !wire_first_program_history
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 conditional GHHM first-program no-go boundary drift",
        ));
    }
    let adaptive_first_program_no_go = SmallwoodPoseidon2V8AdaptiveFirstProgramNoGoV2 {
        route_id: "ghhm-2020-proposition-2-direct-dyadic-first-program".to_owned(),
        salt_only_oracle_program_count: 0,
        exact_lazy_program_keys_exclude_salt_only_point: receipts
            .executable_program_inventory_excludes_salt_only_first_program,
        direct_256_bit_first_program_route_used: false,
        paper_hypotheses_instantiated_for_exact_smz9_program_point: false,
        quantum_hash_query_log2: budget.quantum_hash_query_log2,
        accepted_proof_interactions: analyzed_proof_views,
        current_entropy_bits: SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BITS,
        current_entropy_bytes: SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BYTES,
        current_single_proof_loss: current_first_program_single
            .report("ghhm_current_256_bit_first_program_one_proof"),
        current_finite_history_loss: current_first_program_history
            .report("ghhm_current_256_bit_first_program_finite_history"),
        current_single_proof_supports_strict_128_bits: false,
        current_finite_history_supports_strict_128_bits: false,
        minimum_even_entropy_bits_for_finite_history: minimum_even_first_program_entropy_bits,
        minimum_even_entropy_loss: minimum_even_first_program_history
            .report("ghhm_minimum_even_first_program_finite_history"),
        previous_even_entropy_bits: minimum_even_first_program_entropy_bits - 2,
        previous_even_entropy_loss: previous_even_first_program_history
            .report("ghhm_previous_even_first_program_finite_history"),
        minimum_byte_entropy_bits: minimum_byte_first_program_entropy_bits,
        minimum_byte_entropy_bytes: minimum_byte_first_program_entropy_bits / 8,
        salt_word_alignment_bytes: SMALLWOOD_POSEIDON2_V8_SALT_WORD_ALIGNMENT_BYTES,
        minimum_wire_entropy_bits: minimum_wire_first_program_entropy_bits,
        minimum_wire_entropy_bytes: minimum_wire_first_program_entropy_bits / 8,
        additional_wire_entropy_bytes: minimum_wire_first_program_entropy_bits / 8
            - SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BYTES,
        wire_change_required_only_if_this_route_applies: true,
        alternative_reduction_may_avoid_wire_change: true,
    };

    let adaptive_final_piop_loss = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
        active_exposure_log2_ceiling,
        analyzed_proof_views,
    )?;
    let adaptive_final_piop_programming_screen =
        SmallwoodPoseidon2V8ConditionalAdaptiveProgrammingScreenV2 {
            route_id: "ghhm-shaped-final-piop-uniform-fiber-min-entropy".to_owned(),
            program_point_scope: "exact_final_piop_only_not_merkle_root_leaf_or_first_program"
                .to_owned(),
            paper_and_executable_hypotheses_instantiated: receipts
                .adaptive_final_piop_programming_refinement
                && receipts.sha512_primitive_security_bound.is_some(),
            entropy_bits: SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
            quantum_hash_query_log2: budget.quantum_hash_query_log2,
            accepted_proof_interactions: analyzed_proof_views,
            conditional_loss: adaptive_final_piop_loss
                .report("conditional_final_piop_programming_finite_history"),
            supports_strict_128_bits: adaptive_final_piop_loss
                .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS),
        };

    let adaptive_full_tree_loss = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
        active_exposure_log2_ceiling,
        full_tree_programming_events.clone(),
    )?;
    let minimum_even_full_tree_entropy_bits = minimum_even_entropy_bits_for_strict_target(
        active_exposure_log2_ceiling,
        &full_tree_programming_events,
        SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS,
    )?;
    let adaptive_full_tree_minimum_even_loss = ghhm_direct_adaptive_programming_ratio(
        minimum_even_full_tree_entropy_bits,
        active_exposure_log2_ceiling,
        full_tree_programming_events.clone(),
    )?;
    let adaptive_full_tree_previous_even_loss = ghhm_direct_adaptive_programming_ratio(
        minimum_even_full_tree_entropy_bits - 2,
        active_exposure_log2_ceiling,
        full_tree_programming_events.clone(),
    )?;
    let minimum_byte_full_tree_entropy_bits =
        round_up_to_multiple(minimum_even_full_tree_entropy_bits, 8)?;
    let minimum_wire_full_tree_entropy_bits =
        round_up_to_multiple(minimum_byte_full_tree_entropy_bits, 64)?;
    let adaptive_full_tree_minimum_wire_loss = ghhm_direct_adaptive_programming_ratio(
        minimum_wire_full_tree_entropy_bits,
        active_exposure_log2_ceiling,
        full_tree_programming_events.clone(),
    )?;
    if !adaptive_full_tree_loss
        .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || !adaptive_full_tree_minimum_even_loss
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || adaptive_full_tree_previous_even_loss
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || !adaptive_full_tree_minimum_wire_loss
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 conditional GHHM full-tree programming boundary drift",
        ));
    }
    let adaptive_full_tree_programming_screen =
        SmallwoodPoseidon2V8AdaptiveFullTreeProgrammingScreenV2 {
            route_id: "ghhm-shaped-hypothetical-eager-full-decs-tree-program-schedule".to_owned(),
            program_point_scope:
                "conservative-hypothetical-all-2N-minus-1-tree-programs-not-active-simulator"
                    .to_owned(),
            paper_and_all_points_hypotheses_instantiated: receipts
                .all_adaptive_program_points_conditioned
                && receipts.sha512_primitive_security_bound.is_some(),
            programs_per_proof: SMALLWOOD_POSEIDON2_V8_FULL_TREE_PROGRAMS_PER_PROOF,
            accepted_proof_interactions: analyzed_proof_views,
            total_programming_events_decimal: full_tree_programming_events.to_string(),
            conditional_entropy_bits_per_program:
                SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
            conditional_loss: adaptive_full_tree_loss
                .report("conditional_full_tree_programming_finite_history"),
            supports_strict_128_bits: adaptive_full_tree_loss
                .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS),
            minimum_even_entropy_bits_for_strict_128: minimum_even_full_tree_entropy_bits,
            minimum_even_entropy_loss: adaptive_full_tree_minimum_even_loss
                .report("conditional_full_tree_minimum_even_entropy"),
            previous_even_entropy_bits: minimum_even_full_tree_entropy_bits - 2,
            previous_even_entropy_loss: adaptive_full_tree_previous_even_loss
                .report("conditional_full_tree_previous_even_entropy"),
            previous_even_entropy_supports_strict_128_bits: false,
            minimum_whole_byte_entropy_bits: minimum_byte_full_tree_entropy_bits,
            minimum_whole_byte_entropy_bytes: minimum_byte_full_tree_entropy_bits / 8,
            salt_word_alignment_bytes: SMALLWOOD_POSEIDON2_V8_SALT_WORD_ALIGNMENT_BYTES,
            minimum_wire_entropy_bits: minimum_wire_full_tree_entropy_bits,
            minimum_wire_entropy_bytes: minimum_wire_full_tree_entropy_bits / 8,
            additional_wire_entropy_bytes: minimum_wire_full_tree_entropy_bits / 8
                - SMALLWOOD_POSEIDON2_V8_CURRENT_FIRST_PROGRAM_ENTROPY_BYTES,
            minimum_wire_entropy_loss: adaptive_full_tree_minimum_wire_loss
                .report("conditional_full_tree_minimum_wire_entropy"),
            current_leaf_tape_entropy_bits: 512,
            leaf_input_fiber_refinement_instantiated: receipts
                .all_adaptive_program_points_conditioned,
            hidden_child_internal_node_propagation_instantiated: receipts
                .all_adaptive_program_points_conditioned,
        };

    let lazy_merkle_programming_events =
        BigUint::from(SMALLWOOD_POSEIDON2_V8_MAX_LAZY_PROGRAMS_PER_PROOF)
            * BigUint::from(analyzed_proof_views);
    let lazy_leaf_and_final_programming_events =
        BigUint::from(SMALLWOOD_POSEIDON2_V8_LAZY_WEIGHTED_CORNER_LEAF_AND_FINAL_PROGRAMS)
            * BigUint::from(analyzed_proof_views);
    // The source envelope is joint: at most 20 level-zero leaves and at most
    // 372 total compact authentication nodes.  At the loss-maximizing leaf
    // loss-maximizing envelope, only 352 internal nodes remain. This is a
    // sound cap, not an attainability witness. Never add the independent
    // maxima 20 + 372.
    let lazy_internal_node_programming_events =
        BigUint::from(SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_PROGRAM_CAP_WHEN_LEAF_PROGRAMS_EQUAL_20)
            * BigUint::from(analyzed_proof_views);
    let adaptive_lazy_leaf_and_final_loss = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_LAZY_LEAF_AND_FINAL_ENTROPY_BITS,
        active_exposure_log2_ceiling,
        lazy_leaf_and_final_programming_events,
    )?;
    let adaptive_lazy_internal_node_loss = ghhm_direct_adaptive_programming_ratio(
        SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_NODE_ENTROPY_BITS,
        active_exposure_log2_ceiling,
        lazy_internal_node_programming_events,
    )?;
    let adaptive_lazy_combined_loss =
        adaptive_lazy_leaf_and_final_loss.add(&adaptive_lazy_internal_node_loss);
    let maximum_lazy_observed_proof_views =
        maximum_lazy_joint_observed_proof_views_for_strict_target(
            budget.quantum_hash_query_log2,
            SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS,
        )?;
    let first_failing_lazy_observed_proof_views = maximum_lazy_observed_proof_views
        .checked_add(1)
        .ok_or(TransactionCircuitError::ConstraintViolation(
            "V8 lazy observed-proof-view ceiling successor overflow",
        ))?;
    let maximum_lazy_observed_loss = generic_lazy_joint_adaptive_programming_ratio(
        budget.quantum_hash_query_log2,
        maximum_lazy_observed_proof_views,
    )?;
    let first_failing_lazy_observed_loss = generic_lazy_joint_adaptive_programming_ratio(
        budget.quantum_hash_query_log2,
        first_failing_lazy_observed_proof_views,
    )?;
    if maximum_lazy_observed_proof_views != SMALLWOOD_POSEIDON2_V8_LAZY_MAX_OBSERVED_PROOF_VIEWS_128
        || !maximum_lazy_observed_loss
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
        || first_failing_lazy_observed_loss
            .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS)
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "V8 lazy joint observed-proof-view ceiling drift",
        ));
    }
    let adaptive_lazy_merkle_programming_screen =
        SmallwoodPoseidon2V8LazyMerkleProgrammingScreenV3 {
            route_id: "ghhm-shaped-profile-wide-lazy-merkle-program-abstraction".to_owned(),
            source_records_exact_input_output_pairs_for_each_lazy_program: true,
            maximum_compact_authentication_nodes:
                SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES,
            maximum_abstract_programs_per_proof_including_final_piop:
                SMALLWOOD_POSEIDON2_V8_MAX_LAZY_PROGRAMS_PER_PROOF,
            fixture_abstract_programs_per_proof_including_final_piop:
                SMALLWOOD_POSEIDON2_V8_FIXTURE_LAZY_PROGRAMS_PER_PROOF,
            accepted_proof_interactions: analyzed_proof_views,
            maximum_abstract_programming_events_decimal: lazy_merkle_programming_events.to_string(),
            maximum_leaf_programs_per_proof:
                SMALLWOOD_POSEIDON2_V8_MAX_LAZY_LEAF_PROGRAMS_PER_PROOF,
            maximum_internal_node_programs_per_proof:
                SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES,
            internal_node_program_cap_when_leaf_programs_equal_20:
                SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_PROGRAM_CAP_WHEN_LEAF_PROGRAMS_EQUAL_20,
            joint_leaf_plus_internal_program_cap:
                SMALLWOOD_POSEIDON2_V8_MAX_COMPACT_AUTHENTICATION_NODES,
            weighted_upper_bound_leaf_and_final_program_cap:
                SMALLWOOD_POSEIDON2_V8_LAZY_WEIGHTED_CORNER_LEAF_AND_FINAL_PROGRAMS,
            weighted_upper_bound_internal_node_program_cap:
                SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_PROGRAM_CAP_WHEN_LEAF_PROGRAMS_EQUAL_20,
            leaf_and_final_conditional_entropy_bits:
                SMALLWOOD_POSEIDON2_V8_LAZY_LEAF_AND_FINAL_ENTROPY_BITS,
            internal_node_conditional_entropy_bits:
                SMALLWOOD_POSEIDON2_V8_LAZY_INTERNAL_NODE_ENTROPY_BITS,
            conditional_leaf_and_final_loss: adaptive_lazy_leaf_and_final_loss
                .report("conditional_lazy_leaf_and_final_programming_finite_history"),
            conditional_internal_node_loss: adaptive_lazy_internal_node_loss
                .report("conditional_lazy_internal_node_programming_finite_history"),
            conditional_combined_loss: adaptive_lazy_combined_loss
                .report("conditional_lazy_combined_programming_finite_history"),
            supports_strict_128_bits: adaptive_lazy_combined_loss
                .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS),
            maximum_observed_honest_proof_views_for_strict_128_decimal:
                maximum_lazy_observed_proof_views.to_string(),
            first_failing_observed_honest_proof_views_decimal:
                first_failing_lazy_observed_proof_views.to_string(),
            maximum_observed_honest_proof_views_supports_strict_128: maximum_lazy_observed_loss
                .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS),
            first_failing_observed_honest_proof_views_supports_strict_128:
                first_failing_lazy_observed_loss
                    .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS),
            source_role_framed_io_recording_refinement_instantiated: true,
            source_duplicate_program_input_rejection_instantiated: true,
            executable_rng_to_ideal_fresh_inputs_refinement_instantiated: receipts
                .executable_rng_to_ideal_lazy_inputs_refinement,
            adaptive_lazy_completion_qrom_reduction_instantiated: receipts
                .adaptive_lazy_merkle_completion_qrom_reduction,
            concrete_sha512_qro_instantiated: receipts.sha512_primitive_security_bound.is_some(),
            global_prior_query_schedule_instantiated: receipts
                .all_adaptive_program_points_conditioned,
        };

    let no_grinding = SmallwoodPoseidon2V8NoGrindingStatusV2 {
        piop_pow_bits: profile.opening_pow_bits,
        decs_pow_bits: profile.decs_pow_bits,
        canonical_first_valid_nonce: true,
        nonce_trials_are_abort_handling_not_grinding: true,
        exact_grinding_loss_numerator_decimal: "0".to_owned(),
        exact_grinding_loss_denominator_decimal: "1".to_owned(),
    };

    let poseidon_output_bits = biguint_log2(&poseidon_space);
    let known_attacks = vec![
        SmallwoodPoseidon2V8KnownAttackV2 {
            id: "generic-quantum-poseidon2-seven-limb-collision".to_owned(),
            primitive: "hegemon-p2w16-v1-114a4e7eb2684d29-seven-limb-digest".to_owned(),
            model: "generic-q-cubed-over-p-to-7-collision".to_owned(),
            approximate_work_factor_bits: Some(poseidon_output_bits / 3.0),
            end_to_end_forgery_reduction_available: false,
            independently_reviewed: receipts.public_attack_inventory_complete,
            disposition: "strongest_quantified_modeled_attack_not_a_lower_bound".to_owned(),
        },
        SmallwoodPoseidon2V8KnownAttackV2 {
            id: "generic-quantum-sha512-collision".to_owned(),
            primitive: "SHA-512".to_owned(),
            model: "generic-q-cubed-over-2-to-512-collision".to_owned(),
            approximate_work_factor_bits: Some(512.0 / 3.0),
            end_to_end_forgery_reduction_available: false,
            independently_reviewed: receipts.public_attack_inventory_complete,
            disposition: "generic_model_only".to_owned(),
        },
        SmallwoodPoseidon2V8KnownAttackV2 {
            id: "generic-quantum-poseidon2-seven-limb-preimage".to_owned(),
            primitive: "hegemon-p2w16-v1-114a4e7eb2684d29-seven-limb-digest".to_owned(),
            model: "generic-q-squared-over-p-to-7-preimage".to_owned(),
            approximate_work_factor_bits: Some(poseidon_output_bits / 2.0),
            end_to_end_forgery_reduction_available: false,
            independently_reviewed: receipts.public_attack_inventory_complete,
            disposition: "generic_model_only".to_owned(),
        },
        SmallwoodPoseidon2V8KnownAttackV2 {
            id: "generic-quantum-sha512-preimage".to_owned(),
            primitive: "SHA-512".to_owned(),
            model: "generic-q-squared-over-2-to-512-preimage".to_owned(),
            approximate_work_factor_bits: Some(256.0),
            end_to_end_forgery_reduction_available: false,
            independently_reviewed: receipts.public_attack_inventory_complete,
            disposition: "generic_model_only".to_owned(),
        },
        SmallwoodPoseidon2V8KnownAttackV2 {
            id: "eprint-2026-306-skipping-class-local-screen".to_owned(),
            primitive: "hegemon-p2w16-v1-114a4e7eb2684d29".to_owned(),
            model: "local-parameter-screen".to_owned(),
            approximate_work_factor_bits: None,
            end_to_end_forgery_reduction_available: false,
            independently_reviewed: receipts.public_attack_inventory_complete,
            disposition: "mitigated-by-M4-kron-P4-pending-external-review".to_owned(),
        },
        SmallwoodPoseidon2V8KnownAttackV2 {
            id: "eprint-2026-1254-degree-annihilation-local-screen".to_owned(),
            primitive: "hegemon-p2w16-v1-114a4e7eb2684d29".to_owned(),
            model: "local-reduced-round-screen".to_owned(),
            approximate_work_factor_bits: None,
            end_to_end_forgery_reduction_available: false,
            independently_reviewed: receipts.public_attack_inventory_complete,
            disposition: "no-practical-full-round-transfer-found-pending-external-review"
                .to_owned(),
        },
        SmallwoodPoseidon2V8KnownAttackV2 {
            id: "eprint-2026-1760-midpoint-reset-local-screen".to_owned(),
            primitive: "hegemon-p2w16-v1-114a4e7eb2684d29".to_owned(),
            model: "local-direct-prerequisite-screen".to_owned(),
            approximate_work_factor_bits: None,
            end_to_end_forgery_reduction_available: false,
            independently_reviewed: receipts.public_attack_inventory_complete,
            disposition: "direct-prerequisites-absent-pending-external-review".to_owned(),
        },
    ];

    let absent_reductions = [
        (
            "exact-compiled-relation-refinement",
            receipts.exact_compiled_relation_refinement,
        ),
        (
            "exact-smz9-indexed-logical-oracle-instantiation",
            receipts.exact_smz9_indexed_logical_oracle_instantiation,
        ),
        (
            "sha512-to-indexed-product-oracle-reduction",
            receipts.sha512_to_indexed_product_oracle_reduction
                && whole_view_losses.sha512_to_indexed_product_oracle.is_some(),
        ),
        (
            "correction-aware-opening-sampling-refinement",
            receipts.piop_correction_aware_sampling_refinement,
        ),
        (
            "quantitative-sha512-primitive-security-bound",
            receipts.sha512_primitive_security_bound.is_some(),
        ),
        (
            "quantitative-poseidon2-exact-parameter-security-bound",
            receipts.poseidon2_primitive_security_bound.is_some(),
        ),
        (
            "final-piop-programming-executable-refinement",
            receipts.adaptive_final_piop_programming_refinement,
        ),
        (
            "executable-program-inventory-excludes-salt-only-first-program",
            receipts.executable_program_inventory_excludes_salt_only_first_program,
        ),
        (
            "executable-rng-to-ideal-lazy-inputs-refinement",
            receipts.executable_rng_to_ideal_lazy_inputs_refinement,
        ),
        (
            "adaptive-lazy-merkle-completion-qrom-reduction",
            receipts.adaptive_lazy_merkle_completion_qrom_reduction,
        ),
        (
            "all-adaptive-program-points-conditioned",
            receipts.all_adaptive_program_points_conditioned,
        ),
        (
            "adaptive-whole-view-complete-zero-knowledge",
            receipts.adaptive_whole_view_complete_zero_knowledge,
        ),
        (
            "global-history-composition",
            receipts.global_history_composition,
        ),
        (
            "consensus-budget-binding",
            receipts.consensus_budget_binding,
        ),
        (
            "complete-public-attack-inventory",
            receipts.public_attack_inventory_complete,
        ),
        ("independent-composed-review", receipts.independent_review),
    ]
    .into_iter()
    .filter_map(|(id, satisfied)| (!satisfied).then(|| id.to_owned()))
    .collect::<Vec<_>>();

    let claim_ledger = SmallwoodPoseidon2V8ClaimLedgerV2 {
        proved_arithmetic: vec![
            "exact-smz9-profile-6-20-140-geometry".to_owned(),
            "correction-aware-opening-denominator-arithmetic".to_owned(),
            "conditional-global-query-work-2pow142-pass-2pow143-fail".to_owned(),
            "conditional-ghhm-first-program-256-bit-no-go".to_owned(),
            "conditional-ghhm-minimum-even-entropy-366-bits".to_owned(),
            "conditional-final-piop-512-bit-entropy-loss-screen".to_owned(),
            "conditional-full-tree-512-bit-entropy-loss-and-414-bit-minimum-screen".to_owned(),
            "conditional-lazy-leaf-final-512-and-internal-node-1024-bit-entropy-screen".to_owned(),
            "q19-134-pass-135-fail-prospective-arithmetic-screen".to_owned(),
            "canonical-completeness-abort-and-zero-grinding-arithmetic".to_owned(),
            "finite-4096-block-screen-is-not-a-cryptographic-reset".to_owned(),
        ],
        source_checked_bindings: vec![
            "SMZ9-profile-wire-id-6".to_owned(),
            "HGV8RP03-program-digest-and-geometry".to_owned(),
            "canonical-first-valid-piop-nonce".to_owned(),
            "exact-source-transcript-decode-reencode".to_owned(),
            "lazy-merkle-role-framed-input-output-recording-and-duplicate-rejection".to_owned(),
        ],
        stated_primitive_assumptions: vec![
            "ideal-cms-12Q2epsilon-plus-48Q3-over-2pow512-plus-2N2-over-2pow512".to_owned(),
            "sha512-generic-Q3-collision-and-Q2-preimage".to_owned(),
            "poseidon2-seven-limb-generic-Q3-collision-and-Q2-preimage-charging-125-live-plus-3-padding-evaluations-per-view".to_owned(),
            "ghhm-direct-dyadic-adaptive-reprogramming-expression".to_owned(),
        ],
        absent_reductions,
        strongest_quantified_attack_id: "generic-quantum-poseidon2-seven-limb-collision".to_owned(),
        public_attack_inventory_complete: receipts.public_attack_inventory_complete,
    };

    let sha512_to_product_ratio = whole_view_losses
        .sha512_to_indexed_product_oracle
        .map(ExactRatio::power_of_two);
    let named_external = [
        (
            "adaptive_merkle_programming",
            whole_view_losses.adaptive_merkle_programming,
        ),
        (
            "adaptive_final_piop_programming",
            whole_view_losses.adaptive_final_piop_programming,
        ),
        (
            "concrete_sha512_instantiation",
            whole_view_losses.concrete_sha512_instantiation,
        ),
        ("residual_whole_view", whole_view_losses.residual_whole_view),
    ];
    let external_ratios: Vec<Option<ExactRatio>> = named_external
        .iter()
        .map(|(_, bits)| bits.map(ExactRatio::power_of_two))
        .collect();
    let external_whole_view_terms = named_external
        .iter()
        .zip(&external_ratios)
        .map(|((id, _), ratio)| ratio.as_ref().map(|ratio| ratio.report(id)))
        .collect::<Vec<_>>();

    let assumptions = vec![
        assumption(
            "exact_compiled_relation_refinement",
            receipts.exact_compiled_relation_refinement,
        ),
        assumption(
            "exact_smz9_transcript_refinement",
            receipts.exact_smz9_transcript_refinement,
        ),
        assumption(
            "exact_smz9_indexed_logical_oracle_instantiation",
            receipts.exact_smz9_indexed_logical_oracle_instantiation,
        ),
        assumption(
            "sha512_to_indexed_product_oracle_reduction",
            receipts.sha512_to_indexed_product_oracle_reduction
                && sha512_to_product_ratio.is_some(),
        ),
        assumption(
            "piop_correction_aware_sampling_refinement",
            receipts.piop_correction_aware_sampling_refinement,
        ),
        assumption(
            "sha512_primitive_security_bound",
            receipts.sha512_primitive_security_bound.is_some(),
        ),
        assumption(
            "poseidon2_primitive_security_bound",
            receipts.poseidon2_primitive_security_bound.is_some(),
        ),
        assumption(
            "adaptive_final_piop_programming_refinement",
            receipts.adaptive_final_piop_programming_refinement,
        ),
        assumption(
            "executable_program_inventory_excludes_salt_only_first_program",
            receipts.executable_program_inventory_excludes_salt_only_first_program,
        ),
        assumption(
            "executable_rng_to_ideal_lazy_inputs_refinement",
            receipts.executable_rng_to_ideal_lazy_inputs_refinement,
        ),
        assumption(
            "adaptive_lazy_merkle_completion_qrom_reduction",
            receipts.adaptive_lazy_merkle_completion_qrom_reduction,
        ),
        assumption(
            "all_adaptive_program_points_conditioned",
            receipts.all_adaptive_program_points_conditioned,
        ),
        assumption(
            "adaptive_whole_view_complete_zero_knowledge",
            receipts.adaptive_whole_view_complete_zero_knowledge,
        ),
        assumption(
            "observed_honest_proof_views_model",
            observed_honest_proof_views_model_receipt_present,
        ),
        assumption(
            "global_history_composition",
            receipts.global_history_composition,
        ),
        assumption(
            "consensus_budget_binding",
            receipts.consensus_budget_binding,
        ),
        assumption(
            "public_attack_inventory_complete",
            receipts.public_attack_inventory_complete,
        ),
        assumption("independent_review", receipts.independent_review),
    ];

    let mut blockers = assumptions
        .iter()
        .filter(|item| !item.satisfied)
        .map(|item| format!("missing receipt: {}", item.id))
        .collect::<Vec<_>>();
    for ((id, _), ratio) in named_external.iter().zip(&external_ratios) {
        if ratio.is_none() {
            blockers.push(format!("missing whole-view loss bound: {id}"));
        }
    }
    if sha512_to_product_ratio.is_none() {
        blockers.push(
            "missing global-once SHA-512 to indexed-product-oracle reduction loss bound".to_owned(),
        );
    }
    if !capability_window_within_analysis_budget {
        blockers.push(
            "missing exact capability activation/deactivation lifetime within analyzed proof budget"
                .to_owned(),
        );
    }

    let all_external_present =
        external_ratios.iter().all(Option::is_some) && sha512_to_product_ratio.is_some();
    let all_receipts_present = assumptions.iter().all(|item| item.satisfied);
    let deployed_epoch =
        if all_external_present && all_receipts_present && capability_window_within_analysis_budget
        {
            let mut composed = conditional_global_query_composed_reduction_failure.clone();
            composed = composed.add(
                sha512_to_product_ratio
                    .as_ref()
                    .expect("presence checked before deployed composition"),
            );
            for ratio in external_ratios.iter().flatten() {
                composed = composed.add(&ratio.scale(analyzed_proof_views));
            }
            Some(composed)
        } else {
            None
        };
    let deployed_bits = deployed_epoch.as_ref().map(ExactRatio::bits_floor);
    let meets_target =
        deployed_bits.is_some_and(|bits| bits >= SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS);
    if let Some(bits) = deployed_bits {
        if bits < SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS {
            blockers.push(format!(
                "composed finite-lifetime security floor is {bits} bits, below {}",
                SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS
            ));
        }
    }

    Ok(SmallwoodPoseidon2V8SecurityReportV1 {
        schema: SMALLWOOD_POSEIDON2_V8_SECURITY_REPORT_SCHEMA.to_owned(),
        proof_wire_magic_ascii: String::from_utf8_lossy(
            &SMALLWOOD_PROOF_WIRE_MAGIC_POSEIDON2_V8_SMZ9,
        )
        .into_owned(),
        profile_wire_id: SMALLWOOD_POSEIDON2_V8_PROFILE_ID,
        program_digest_hex: hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST),
        program_sha512_hex: hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512),
        row_count: relation.row_count(),
        proof_columns: engine_geometry.n_cols,
        constraint_degree: relation.constraint_degree(),
        packing_factor: relation.packing_factor(),
        nonlinear_identity_count: relation.constraint_count(),
        maximum_linear_identity_count: relation.linear_constraint_count(),
        maximum_summed_identity_union: SMALLWOOD_POSEIDON2_V8_MAXIMUM_SUMMED_IDENTITY_UNION,
        rho: profile.rho,
        piop_openings: profile.nb_opened_evals,
        beta: profile.beta,
        decs_domain_size: profile.decs_nb_evals,
        decs_openings: profile.decs_nb_opened_evals,
        decs_eta: profile.decs_eta,
        piop_linear_correction_degree,
        piop_pcs_unstack_additional_forbidden_values,
        piop_admissibility_bad_tuple_coefficient,
        piop_nonce_bad_per_trial,
        projected_inner_proof_bytes,
        projected_two_output_action_bytes: SMALLWOOD_POSEIDON2_V8_MAX_ACTION_BYTES as usize,
        projected_pending_action_bytes: SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES as usize,
        security_epoch_is_cryptographic_reset: false,
        unbounded_history_theorem_required:
            SMALLWOOD_POSEIDON2_V8_UNBOUNDED_HISTORY_THEOREM_REQUIRED.to_owned(),
        budget,
        byte_quotient_diagnostic,
        lifetime_binding,
        proof_exposure_accounting,
        interactive_terms: [
            "pcs_decs_uniform_batching",
            "iop_constraint_batching",
            "iop_opening_consistency_conditioned_on_full_admissibility",
            "pcs_decs_low_degree_opening",
        ]
        .into_iter()
        .zip(&interactive)
        .map(|(id, ratio)| ratio.report(id))
        .collect(),
        interactive_aggregate: interactive_aggregate.report("interactive_aggregate"),
        field_xof_requested_words: xof.requested_output_words,
        field_xof_candidate_words: xof.candidate_word_cap,
        field_xof_minimum_rejections: xof.minimum_rejections_for_exhaustion,
        field_xof_request_union: SMALLWOOD_POSEIDON2_V8_MAX_FIELD_XOF_REQUESTS_PER_PROOF,
        field_xof_abort_union: field_xof_abort_union.report("field_xof_abort_union"),
        canonical_piop_opening_abort: canonical_piop_opening_abort
            .report("canonical_piop_opening_abort"),
        fixed_decs_sampler_abort: fixed_decs_sampler_abort.report("fixed_decs_sampler_abort"),
        sha512_collision: sha512_collision.report("sha512_collision"),
        sha512_preimage: sha512_preimage.report("sha512_preimage"),
        tape_database_bridge: tape_database_bridge.report("tape_database_bridge"),
        poseidon2_collision: poseidon2_collision.report("poseidon2_collision"),
        poseidon2_preimage: poseidon2_preimage.report("poseidon2_preimage"),
        poseidon_honest_evaluations_decimal: poseidon_honest_evaluations.to_string(),
        ideal_cms_qrom: ideal_cms_qrom.report("ideal_cms_qrom"),
        conditional_fixed_query_baseline_without_honest_program_exposures:
            conditional_fixed_query_soundness
                .report("conditional_fixed_query_baseline_without_honest_program_exposures"),
        conditional_completeness_abort_per_proof: conditional_completeness_abort_per_proof
            .report("conditional_completeness_abort_per_proof"),
        conditional_completeness_abort_finite_history:
            conditional_completeness_abort_finite_history
                .report("conditional_completeness_abort_finite_history"),
        conditional_global_query_soundness_only: conditional_global_query_soundness_only
            .report("conditional_global_query_soundness_only"),
        conditional_global_query_composed_reduction_failure:
            conditional_global_query_composed_reduction_failure
                .report("conditional_global_query_composed_reduction_failure"),
        conditional_total_failure_finite_history_diagnostic:
            conditional_total_failure_finite_history_diagnostic
                .report("conditional_total_failure_finite_history_diagnostic"),
        conditional_global_query_work_screens,
        strongest_conditional_global_query_work_factor_log2:
            SMALLWOOD_POSEIDON2_V8_STRONGEST_CONDITIONAL_WORK_QUERY_LOG2,
        first_failing_conditional_global_query_work_factor_log2:
            SMALLWOOD_POSEIDON2_V8_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2,
        no_grinding,
        adaptive_first_program_no_go,
        adaptive_final_piop_programming_screen,
        adaptive_full_tree_programming_screen,
        adaptive_lazy_merkle_programming_screen,
        candidate_parameter_screens,
        claim_ledger,
        known_attacks,
        sha512_primitive_security_bound: receipts.sha512_primitive_security_bound.clone(),
        poseidon2_primitive_security_bound: receipts.poseidon2_primitive_security_bound.clone(),
        sha512_to_indexed_product_oracle_reduction_bound: sha512_to_product_ratio
            .as_ref()
            .map(|ratio| ratio.report("sha512_to_indexed_product_oracle_reduction")),
        external_whole_view_terms,
        assumptions,
        deployed_finite_history_composed: deployed_epoch
            .as_ref()
            .map(|ratio| ratio.report("deployed_finite_history_composed")),
        deployed_composed_security_bits_floor: deployed_bits,
        meets_128_bit_deployed_floor: meets_target,
        production_eligible: meets_target && blockers.is_empty(),
        blockers,
    })
}

/// Reconstruct the report from the evidence that is actually checked in.
///
/// The source verifier now owns the exact SMZ9 decode/re-encode, production
/// verifier replay, and honest-map audit gate, and the matching Lean model
/// proves canonical-byte binding for every accepted input.  That discharges
/// only the source-internal transcript-refinement item.  Complete adaptive ZK,
/// concrete-QROM, global-history, compiler refinement, correction-aware
/// sampling refinement, and independent review remain absent.
pub fn report_smallwood_poseidon2_v8_current_source_security_v1(
) -> Result<SmallwoodPoseidon2V8SecurityReportV1, TransactionCircuitError> {
    report_smallwood_poseidon2_v8_source_security_v1(
        SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget(),
        SmallwoodPoseidon2V8SecurityReceiptsV1 {
            exact_smz9_transcript_refinement: true,
            executable_program_inventory_excludes_salt_only_first_program: true,
            ..SmallwoodPoseidon2V8SecurityReceiptsV1::default()
        },
        SmallwoodPoseidon2V8WholeViewLossBitsV1::default(),
    )
}

pub fn ensure_smallwood_poseidon2_v8_deployed_security_v1(
    report: &SmallwoodPoseidon2V8SecurityReportV1,
) -> Result<(), TransactionCircuitError> {
    let current_source = report_smallwood_poseidon2_v8_current_source_security_v1()?;
    if report != &current_source
        || report.schema != SMALLWOOD_POSEIDON2_V8_SECURITY_REPORT_SCHEMA
        || report.proof_wire_magic_ascii != "SMZ9"
        || report.profile_wire_id != SMALLWOOD_POSEIDON2_V8_PROFILE_ID
        || report.budget != SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget()
        || report.program_digest_hex != hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST)
        || report.program_sha512_hex != hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512)
        || report.projected_inner_proof_bytes != SMALLWOOD_POSEIDON2_V8_PROJECTED_INNER_PROOF_BYTES
        || report.projected_two_output_action_bytes
            != SMALLWOOD_POSEIDON2_V8_MAX_ACTION_BYTES as usize
        || report.projected_pending_action_bytes
            != SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES as usize
        || report.byte_quotient_diagnostic
            != (SmallwoodPoseidon2V8ByteQuotientDiagnosticV2 {
                block_action_byte_cap: SMALLWOOD_POSEIDON2_V8_BLOCK_ACTION_BYTE_CAP,
                projected_pending_action_bytes: SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES,
                complete_projected_records_per_block:
                    SMALLWOOD_POSEIDON2_V8_PROJECTED_RECORD_BYTE_QUOTIENT_DIAGNOSTIC,
                is_upper_bound_on_proof_interactions: false,
                used_in_security_loss_terms: false,
            })
        || report.security_epoch_is_cryptographic_reset
        || report.unbounded_history_theorem_required
            != SMALLWOOD_POSEIDON2_V8_UNBOUNDED_HISTORY_THEOREM_REQUIRED
        || !report.production_eligible
        || !report.meets_128_bit_deployed_floor
        || !report.blockers.is_empty()
    {
        return Err(TransactionCircuitError::ConstraintViolation(
            "SmallWood Poseidon2 V8 deployed security gate is fail-closed",
        ));
    }
    Ok(())
}

trait ExactRatioScaleBigUint {
    fn scale_biguint(&self, factor: &BigUint) -> Self;
}

impl ExactRatioScaleBigUint for ExactRatio {
    fn scale_biguint(&self, factor: &BigUint) -> Self {
        Self {
            numerator: &self.numerator * factor,
            denominator: self.denominator.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed_primitive_receipt(
        sha512_mode: bool,
        budget: SmallwoodPoseidon2V8CompositionBudgetV1,
    ) -> Option<SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2> {
        let (activation, deactivation) = budget
            .capability_activation_height
            .zip(budget.capability_deactivation_height_exclusive)?;
        let observed_honest_proof_views = budget.security_epoch_max_proofs;
        let honest_exposures = BigUint::from(if sha512_mode {
            SMALLWOOD_POSEIDON2_V8_EAGER_PROGRAMS_PER_PROOF
        } else {
            SMALLWOOD_POSEIDON2_V8_POSEIDON_EVALUATIONS_PER_PROOF
        }) * BigUint::from(observed_honest_proof_views);
        Some(SmallwoodPoseidon2V8PrimitiveSecurityBoundReceiptV2 {
            schema: "hegemon.smallwood.poseidon2-v8.primitive-security-bound.v2".to_owned(),
            receipt_id: if sha512_mode {
                "sha512-smz9-qrom-primitive-bound"
            } else {
                "poseidon2-width16-smz9-primitive-bound"
            }
            .to_owned(),
            primitive_id: if sha512_mode {
                "SHA-512".to_owned()
            } else {
                POSEIDON2_WIDTH16_PARAMETER_SET_ID.to_owned()
            },
            exact_primitive_profile_identity: if sha512_mode {
                SMALLWOOD_POSEIDON2_V8_SHA512_PRIMITIVE_PROFILE_ID.to_owned()
            } else {
                format!(
                    "{POSEIDON2_WIDTH16_PARAMETER_SET_ID};sha256={POSEIDON2_WIDTH16_PARAMETER_SET_SHA256}"
                )
            },
            source_inventory_sha512_hex: "11".repeat(64),
            theorem_or_reduction_id: "test-only-exact-primitive-bound".to_owned(),
            theorem_source_sha512_hex: "22".repeat(64),
            advantage_function: if sha512_mode {
                SMALLWOOD_POSEIDON2_V8_SHA512_ADVANTAGE_FUNCTION_ID
            } else {
                SMALLWOOD_POSEIDON2_V8_POSEIDON2_ADVANTAGE_FUNCTION_ID
            }
            .to_owned(),
            advantage_scope: "global-once".to_owned(),
            adversarial_query_log2_max:
                SMALLWOOD_POSEIDON2_V8_FIRST_FAILING_CONDITIONAL_WORK_QUERY_LOG2,
            honest_programmed_oracle_exposures_decimal: honest_exposures.clone().to_string(),
            bound_uses_queries_plus_honest_exposures: true,
            max_proof_actions_per_block: budget.max_proofs_per_block,
            max_proof_interactions: observed_honest_proof_views,
            validity_activation_height: activation,
            validity_deactivation_height_exclusive: deactivation,
            work_screens: expected_primitive_work_screens(sha512_mode, &honest_exposures).ok()?,
            review_artifact_sha512_hex: "33".repeat(64),
            independently_reviewed: true,
        })
    }

    fn complete_receipts(
        budget: SmallwoodPoseidon2V8CompositionBudgetV1,
    ) -> SmallwoodPoseidon2V8SecurityReceiptsV1 {
        SmallwoodPoseidon2V8SecurityReceiptsV1 {
            exact_compiled_relation_refinement: true,
            exact_smz9_transcript_refinement: true,
            exact_smz9_indexed_logical_oracle_instantiation: true,
            sha512_to_indexed_product_oracle_reduction: true,
            piop_correction_aware_sampling_refinement: true,
            sha512_primitive_security_bound: reviewed_primitive_receipt(true, budget),
            poseidon2_primitive_security_bound: reviewed_primitive_receipt(false, budget),
            adaptive_final_piop_programming_refinement: true,
            executable_program_inventory_excludes_salt_only_first_program: true,
            executable_rng_to_ideal_lazy_inputs_refinement: true,
            adaptive_lazy_merkle_completion_qrom_reduction: true,
            all_adaptive_program_points_conditioned: true,
            adaptive_whole_view_complete_zero_knowledge: true,
            observed_honest_proof_views: Some(budget.security_epoch_max_proofs),
            observed_honest_proof_views_model_reviewed: true,
            global_history_composition: true,
            consensus_budget_binding: true,
            public_attack_inventory_complete: true,
            independent_review: true,
        }
    }

    fn equal_external_losses(bits: u32) -> SmallwoodPoseidon2V8WholeViewLossBitsV1 {
        SmallwoodPoseidon2V8WholeViewLossBitsV1 {
            sha512_to_indexed_product_oracle: Some(bits),
            adaptive_merkle_programming: Some(bits),
            adaptive_final_piop_programming: Some(bits),
            concrete_sha512_instantiation: Some(bits),
            residual_whole_view: Some(bits),
        }
    }

    #[test]
    fn source_report_matches_required_floors_and_exact_program_id() {
        let report = report_smallwood_poseidon2_v8_current_source_security_v1().unwrap();
        assert_eq!(report.row_count, 686);
        assert_eq!(report.proof_columns, 368);
        assert_eq!(report.nonlinear_identity_count, 773);
        assert_eq!(report.maximum_linear_identity_count, 20_510);
        assert_eq!(report.maximum_summed_identity_union, 21_283);
        assert_eq!(report.proof_wire_magic_ascii, "SMZ9");
        assert_eq!(report.profile_wire_id, 6);
        assert_eq!(report.piop_openings, 6);
        assert_eq!(report.piop_linear_correction_degree, 6);
        assert_eq!(report.piop_pcs_unstack_additional_forbidden_values, 68);
        assert_eq!(report.piop_admissibility_bad_tuple_coefficient, 414);
        assert_eq!(report.piop_nonce_bad_per_trial, 813);
        assert_eq!(report.decs_openings, 20);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_POSEIDON_LIVE_CALLS_PER_PROOF, 125);
        assert_eq!(SMALLWOOD_POSEIDON2_V8_POSEIDON_EVALUATIONS_PER_PROOF, 128);
        assert_eq!(report.poseidon_honest_evaluations_decimal, "268435456");
        assert_eq!(report.projected_inner_proof_bytes, 122_863);
        assert_eq!(report.projected_two_output_action_bytes, 128_297);
        assert_eq!(report.projected_pending_action_bytes, 128_522);
        assert_eq!(
            SMALLWOOD_POSEIDON2_V8_BLOCK_ACTION_BYTE_CAP
                % SMALLWOOD_POSEIDON2_V8_MAX_PENDING_ACTION_BYTES,
            20_380
        );
        assert!(!report.security_epoch_is_cryptographic_reset);
        assert_eq!(
            report.unbounded_history_theorem_required,
            SMALLWOOD_POSEIDON2_V8_SMZ9_GLOBAL_QROM_LIFETIME_RECEIPT_ID
        );
        assert_eq!(report.budget.max_proofs_per_block, 512);
        assert_eq!(report.budget.security_epoch_max_proofs, 2_097_152);
        assert_eq!(
            report
                .byte_quotient_diagnostic
                .complete_projected_records_per_block,
            522
        );
        assert!(
            !report
                .byte_quotient_diagnostic
                .is_upper_bound_on_proof_interactions
        );
        assert!(!report.byte_quotient_diagnostic.used_in_security_loss_terms);
        assert_eq!(report.interactive_aggregate.security_bits_floor, 288);
        assert!((288.79..288.80).contains(&report.interactive_aggregate.approximate_security_bits));
        assert_eq!(report.ideal_cms_qrom.security_bits_floor, 157);
        assert!((157.21..157.22).contains(&report.ideal_cms_qrom.approximate_security_bits));
        assert_eq!(report.field_xof_requested_words, 102_545);
        assert_eq!(report.field_xof_candidate_words, 102_584);
        assert_eq!(report.field_xof_minimum_rejections, 40);
        assert_eq!(report.field_xof_request_union, 1 << 25);
        assert_eq!(
            report.canonical_piop_opening_abort.numerator_decimal,
            BigUint::from(813u16)
                .pow(SMALLWOOD_LEVEL5_MAX_PIOP_NONCE_TRIALS)
                .to_str_radix(10)
        );
        assert_eq!(report.field_xof_abort_union.security_bits_floor, 748);
        assert_eq!(report.canonical_piop_opening_abort.security_bits_floor, 869);
        assert_eq!(report.fixed_decs_sampler_abort.security_bits_floor, 488);
        assert_eq!(
            report
                .conditional_completeness_abort_finite_history
                .security_bits_floor,
            467
        );
        assert_eq!(
            report
                .conditional_global_query_composed_reduction_failure
                .security_bits_floor,
            157
        );
        assert!(
            !report
                .lifetime_binding
                .analysis_window_is_cryptographic_reset
        );
        assert_eq!(report.lifetime_binding.capability_activation_height, None);
        assert_eq!(
            report
                .lifetime_binding
                .capability_deactivation_height_exclusive,
            None
        );
        assert!(
            !report
                .lifetime_binding
                .capability_window_within_analysis_budget
        );
        assert_eq!(
            report.program_digest_hex,
            hex::encode(SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST)
        );
        assert!(report.assumptions.iter().any(|assumption| {
            assumption.id == "exact_smz9_transcript_refinement" && assumption.satisfied
        }));
        assert!(!report.assumptions.iter().any(|assumption| {
            !matches!(
                assumption.id.as_str(),
                "exact_smz9_transcript_refinement"
                    | "executable_program_inventory_excludes_salt_only_first_program"
            ) && assumption.satisfied
        }));
        assert!(!report.production_eligible);
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("adaptive_whole_view_complete_zero_knowledge")));
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("piop_correction_aware_sampling_refinement")));
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("independent_review")));
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("capability activation/deactivation lifetime")));
        assert!(ensure_smallwood_poseidon2_v8_deployed_security_v1(&report).is_err());
    }

    #[test]
    fn global_query_work_factor_is_distinct_from_fixed_query_advantage() {
        let report = report_smallwood_poseidon2_v8_current_source_security_v1().unwrap();
        assert_eq!(
            report.schema,
            "hegemon.smallwood.poseidon2-v8.smz9.source-security-report.v3"
        );
        assert_eq!(
            report
                .conditional_global_query_composed_reduction_failure
                .security_bits_floor,
            157
        );
        assert!((157.21..157.22).contains(
            &report
                .conditional_global_query_composed_reduction_failure
                .approximate_security_bits
        ));
        assert_eq!(
            report.strongest_conditional_global_query_work_factor_log2,
            142
        );
        assert_eq!(
            report.first_failing_conditional_global_query_work_factor_log2,
            143
        );
        assert_eq!(
            report
                .conditional_global_query_work_screens
                .iter()
                .map(|screen| screen.quantum_hash_query_log2)
                .collect::<Vec<_>>(),
            vec![64, 128, 142, 143]
        );
        assert!(
            report.conditional_global_query_work_screens[1]
                .certified_reduction_upper_bound_strictly_below_half
        );
        assert!(
            report.conditional_global_query_work_screens[2]
                .certified_reduction_upper_bound_strictly_below_half
        );
        assert!(
            !report.conditional_global_query_work_screens[3]
                .certified_reduction_upper_bound_strictly_below_half
        );
        assert_eq!(
            report.conditional_global_query_work_screens[1]
                .conditional_composed_reduction_failure
                .security_bits_floor,
            29
        );
        assert_eq!(
            report.conditional_global_query_work_screens[2]
                .conditional_composed_reduction_failure
                .security_bits_floor,
            1
        );
        assert_eq!(
            report.conditional_global_query_work_screens[0]
                .honest_programmed_oracle_exposures_decimal,
            "35184372088832"
        );
        assert_eq!(
            report.conditional_global_query_work_screens[0].total_oracle_exposures_decimal,
            "18446779258081640448"
        );
        assert!(report
            .conditional_global_query_work_screens
            .iter()
            .all(|screen| {
                screen.query_dependent_terms_charged_once
                    && screen.sha512_collision_uses_queries_plus_honest_programmed_exposures
                    && screen.abort_terms_excluded_from_soundness_and_reduction_failure
                    && screen.final_piop_and_full_tree_adaptive_programming_terms_included
                    && screen.adaptive_programming_uses_conditional_512_bit_entropy
                    && !screen.exact_smz9_logical_oracle_and_primitive_hypotheses_instantiated
                    && !screen.is_known_attack
            }));
        assert!(!report.production_eligible);
    }

    #[test]
    fn adaptive_programming_uses_exact_total_exposure_ceiling_at_u64_max() {
        assert_eq!(
            total_oracle_exposure_log2_ceiling(SMALLWOOD_POSEIDON2_V8_QROM_QUERY_LOG2, u64::MAX,)
                .unwrap(),
            89
        );
        assert!(!generic_eager_adaptive_programming_ratio(
            SMALLWOOD_POSEIDON2_V8_FINAL_PIOP_IDEAL_ENTROPY_BITS,
            SMALLWOOD_POSEIDON2_V8_QROM_QUERY_LOG2,
            u64::MAX,
        )
        .unwrap()
        .strictly_below_power_of_two(SMALLWOOD_POSEIDON2_V8_SECURITY_TARGET_BITS));
    }

    #[test]
    fn adaptive_programming_no_go_and_full_tree_screens_remain_conditional() {
        let report = report_smallwood_poseidon2_v8_current_source_security_v1().unwrap();
        let first = &report.adaptive_first_program_no_go;
        assert!(!first.paper_hypotheses_instantiated_for_exact_smz9_program_point);
        assert_eq!(first.current_entropy_bits, 256);
        assert_eq!(first.current_single_proof_loss.numerator_decimal, "3");
        assert_eq!(
            first.current_single_proof_loss.denominator_decimal,
            (BigUint::from(1u8) << 96usize).to_str_radix(10)
        );
        assert_eq!(first.current_single_proof_loss.security_bits_floor, 94);
        assert_eq!(first.current_finite_history_loss.security_bits_floor, 73);
        assert_eq!(first.minimum_even_entropy_bits_for_finite_history, 366);
        assert_eq!(first.minimum_even_entropy_loss.security_bits_floor, 128);
        assert_eq!(first.previous_even_entropy_bits, 364);
        assert_eq!(first.previous_even_entropy_loss.security_bits_floor, 127);
        assert_eq!(first.minimum_byte_entropy_bytes, 46);
        assert_eq!(first.salt_word_alignment_bytes, 8);
        assert_eq!(first.minimum_wire_entropy_bytes, 48);
        assert_eq!(first.additional_wire_entropy_bytes, 16);

        let final_piop = &report.adaptive_final_piop_programming_screen;
        assert_eq!(
            final_piop.program_point_scope,
            "exact_final_piop_only_not_merkle_root_leaf_or_first_program"
        );
        assert!(!final_piop.paper_and_executable_hypotheses_instantiated);
        assert_eq!(final_piop.conditional_loss.security_bits_floor, 201);
        assert!(final_piop.supports_strict_128_bits);

        let tree = &report.adaptive_full_tree_programming_screen;
        assert_eq!(tree.programs_per_proof, 16_777_215);
        assert_eq!(tree.total_programming_events_decimal, "35184369991680");
        assert_eq!(tree.conditional_loss.security_bits_floor, 177);
        assert!(tree.supports_strict_128_bits);
        assert_eq!(tree.minimum_even_entropy_bits_for_strict_128, 414);
        assert_eq!(tree.minimum_even_entropy_loss.security_bits_floor, 128);
        assert_eq!(tree.previous_even_entropy_bits, 412);
        assert_eq!(tree.previous_even_entropy_loss.security_bits_floor, 127);
        assert_eq!(tree.minimum_whole_byte_entropy_bytes, 52);
        assert_eq!(tree.minimum_wire_entropy_bytes, 56);
        assert_eq!(tree.additional_wire_entropy_bytes, 24);
        assert!(!tree.paper_and_all_points_hypotheses_instantiated);
        assert!(!tree.leaf_input_fiber_refinement_instantiated);
        assert!(!tree.hidden_child_internal_node_propagation_instantiated);

        let lazy = &report.adaptive_lazy_merkle_programming_screen;
        assert!(lazy.source_records_exact_input_output_pairs_for_each_lazy_program);
        assert!(lazy.source_role_framed_io_recording_refinement_instantiated);
        assert!(lazy.source_duplicate_program_input_rejection_instantiated);
        assert_eq!(lazy.leaf_and_final_conditional_entropy_bits, 512);
        assert_eq!(lazy.internal_node_conditional_entropy_bits, 1024);
        assert_eq!(lazy.maximum_leaf_programs_per_proof, 20);
        assert_eq!(lazy.maximum_internal_node_programs_per_proof, 372);
        assert_eq!(
            lazy.internal_node_program_cap_when_leaf_programs_equal_20,
            352
        );
        assert_eq!(lazy.joint_leaf_plus_internal_program_cap, 372);
        assert_eq!(lazy.weighted_upper_bound_leaf_and_final_program_cap, 21);
        assert_eq!(lazy.weighted_upper_bound_internal_node_program_cap, 352);
        assert_eq!(
            lazy.conditional_leaf_and_final_loss.security_bits_floor,
            197
        );
        assert_eq!(lazy.conditional_internal_node_loss.security_bits_floor, 448);
        assert_eq!(
            lazy.conditional_internal_node_loss.numerator_decimal,
            "2214592512"
        );
        assert_eq!(lazy.conditional_combined_loss.security_bits_floor, 197);
        assert_eq!(
            lazy.maximum_observed_honest_proof_views_for_strict_128_decimal,
            "18889465930379069227007"
        );
        assert_eq!(
            lazy.first_failing_observed_honest_proof_views_decimal,
            "18889465930379069227008"
        );
        assert!(lazy.maximum_observed_honest_proof_views_supports_strict_128);
        assert!(!lazy.first_failing_observed_honest_proof_views_supports_strict_128);
        assert!(!lazy.executable_rng_to_ideal_fresh_inputs_refinement_instantiated);
        assert!(!lazy.adaptive_lazy_completion_qrom_reduction_instantiated);
        assert!(!lazy.concrete_sha512_qro_instantiated);
        assert!(!lazy.global_prior_query_schedule_instantiated);

        assert_eq!(
            report
                .candidate_parameter_screens
                .iter()
                .map(|screen| screen.id.as_str())
                .collect::<Vec<_>>(),
            vec!["q19-sha512", "q19-compact448", "q20-compact448"]
        );
        let q19_sha512 = &report.candidate_parameter_screens[0];
        assert_eq!(q19_sha512.decs_openings, 19);
        assert_eq!(q19_sha512.decs_polynomial_degree, 386);
        assert_eq!(q19_sha512.strongest_certified_reduction_query_log2, 134);
        assert_eq!(q19_sha512.first_failing_certified_reduction_query_log2, 135);
        assert!((142.807..142.809).contains(
            &q19_sha512
                .fixed_query_conditional_composed_reduction_failure
                .approximate_security_bits
        ));
        let q19_compact = &report.candidate_parameter_screens[1];
        assert!((142.588..142.590).contains(
            &q19_compact
                .fixed_query_conditional_composed_reduction_failure
                .approximate_security_bits
        ));
        let q20_compact = &report.candidate_parameter_screens[2];
        assert_eq!(q20_compact.strongest_certified_reduction_query_log2, 142);
        assert_eq!(
            q20_compact.first_failing_certified_reduction_query_log2,
            143
        );
        assert!((145.414..145.416).contains(
            &q20_compact
                .fixed_query_conditional_composed_reduction_failure
                .approximate_security_bits
        ));
        assert!(report.candidate_parameter_screens.iter().all(|screen| {
            !screen.active_wire
                && screen.requires_new_backend_wire_and_layout_theorem
                && screen.completeness_aborts_excluded
                && !screen.theorem_hypotheses_instantiated
        }));

        assert_eq!(report.no_grinding.piop_pow_bits, 0);
        assert_eq!(report.no_grinding.decs_pow_bits, 0);
        assert!(report.no_grinding.canonical_first_valid_nonce);
        assert_eq!(
            report.no_grinding.exact_grinding_loss_numerator_decimal,
            "0"
        );
        assert_eq!(
            report.claim_ledger.strongest_quantified_attack_id,
            "generic-quantum-poseidon2-seven-limb-collision"
        );
        let strongest_attack = report
            .known_attacks
            .iter()
            .find(|attack| attack.id == report.claim_ledger.strongest_quantified_attack_id)
            .unwrap();
        assert!((149.33..149.34).contains(&strongest_attack.approximate_work_factor_bits.unwrap()));
        assert!(!strongest_attack.end_to_end_forgery_reduction_available);
        assert!(!report.claim_ledger.public_attack_inventory_complete);
    }

    #[test]
    fn exact_lifetime_window_and_history_union_require_152_bit_equal_external_terms() {
        let current_unbound = report_smallwood_poseidon2_v8_source_security_v1(
            SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget(),
            complete_receipts(SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget()),
            equal_external_losses(152),
        )
        .unwrap();
        assert_eq!(current_unbound.deployed_composed_security_bits_floor, None);
        assert!(!current_unbound.production_eligible);
        assert!(current_unbound
            .blockers
            .iter()
            .any(|blocker| blocker.contains("capability activation/deactivation lifetime")));

        let mut bounded_budget = SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget();
        bounded_budget.capability_activation_height = Some(100);
        bounded_budget.capability_deactivation_height_exclusive = Some(4_196);
        let below = report_smallwood_poseidon2_v8_source_security_v1(
            bounded_budget,
            complete_receipts(bounded_budget),
            equal_external_losses(151),
        )
        .unwrap();
        assert_eq!(below.deployed_composed_security_bits_floor, Some(127));
        assert_eq!(
            below
                .deployed_finite_history_composed
                .as_ref()
                .map(|term| term.security_bits_floor),
            Some(127)
        );
        assert!(!below.production_eligible);
        assert!(below
            .blockers
            .iter()
            .any(|blocker| blocker.contains("below 128")));
        let passing = report_smallwood_poseidon2_v8_source_security_v1(
            bounded_budget,
            complete_receipts(bounded_budget),
            equal_external_losses(152),
        )
        .unwrap();
        assert_eq!(passing.deployed_composed_security_bits_floor, Some(128));
        assert_eq!(
            passing
                .deployed_finite_history_composed
                .as_ref()
                .map(|term| term.security_bits_floor),
            Some(128)
        );
        assert_eq!(
            passing.lifetime_binding.capability_window_blocks,
            Some(4_096)
        );
        assert_eq!(
            passing.lifetime_binding.capability_max_proof_interactions,
            Some(2_097_152)
        );
        assert!(
            passing
                .lifetime_binding
                .capability_window_within_analysis_budget
        );
        assert!(passing.production_eligible);
        assert!(ensure_smallwood_poseidon2_v8_deployed_security_v1(&passing).is_err());
        let mut wrong_budget = passing.clone();
        wrong_budget.budget.max_proofs_per_block = 1;
        assert!(ensure_smallwood_poseidon2_v8_deployed_security_v1(&wrong_budget).is_err());
        assert!(!protocol_versioning::smallwood_poseidon2_production_authorized());

        let mut too_long = bounded_budget;
        too_long.capability_deactivation_height_exclusive = Some(4_197);
        assert!(report_smallwood_poseidon2_v8_source_security_v1(
            too_long,
            complete_receipts(too_long),
            equal_external_losses(152),
        )
        .is_err());
    }

    #[test]
    fn malformed_history_budget_is_rejected_before_accounting() {
        let mut budget = SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget();
        budget.security_epoch_max_proofs -= 1;
        assert!(report_smallwood_poseidon2_v8_source_security_v1(
            budget,
            SmallwoodPoseidon2V8SecurityReceiptsV1::default(),
            SmallwoodPoseidon2V8WholeViewLossBitsV1::default(),
        )
        .is_err());
    }

    #[test]
    fn quantitative_primitive_receipts_reject_one_field_substitutions() {
        let mut budget = SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget();
        budget.capability_activation_height = Some(100);
        budget.capability_deactivation_height_exclusive = Some(4_196);

        let mut profile_substitution = complete_receipts(budget);
        profile_substitution
            .sha512_primitive_security_bound
            .as_mut()
            .unwrap()
            .exact_primitive_profile_identity = "SHA-512".to_owned();
        assert!(report_smallwood_poseidon2_v8_source_security_v1(
            budget,
            profile_substitution,
            equal_external_losses(152),
        )
        .is_err());

        let mut screen_substitution = complete_receipts(budget);
        screen_substitution
            .poseidon2_primitive_security_bound
            .as_mut()
            .unwrap()
            .work_screens[0]
            .collision_advantage_upper_bound
            .numerator_decimal = "1".to_owned();
        assert!(report_smallwood_poseidon2_v8_source_security_v1(
            budget,
            screen_substitution,
            equal_external_losses(152),
        )
        .is_err());

        let mut lifetime_substitution = complete_receipts(budget);
        lifetime_substitution
            .sha512_primitive_security_bound
            .as_mut()
            .unwrap()
            .validity_deactivation_height_exclusive += 1;
        assert!(report_smallwood_poseidon2_v8_source_security_v1(
            budget,
            lifetime_substitution,
            equal_external_losses(152),
        )
        .is_err());

        let mut review_substitution = complete_receipts(budget);
        review_substitution
            .poseidon2_primitive_security_bound
            .as_mut()
            .unwrap()
            .independently_reviewed = false;
        assert!(report_smallwood_poseidon2_v8_source_security_v1(
            budget,
            review_substitution,
            equal_external_losses(152),
        )
        .is_err());

        let mut zero_digest = complete_receipts(budget);
        zero_digest
            .sha512_primitive_security_bound
            .as_mut()
            .unwrap()
            .theorem_source_sha512_hex = "00".repeat(64);
        assert!(report_smallwood_poseidon2_v8_source_security_v1(
            budget,
            zero_digest,
            equal_external_losses(152),
        )
        .is_err());
    }

    #[test]
    fn sha512_to_indexed_product_loss_is_composed_once_at_global_scope() {
        let mut budget = SmallwoodPoseidon2V8CompositionBudgetV1::current_source_budget();
        budget.capability_activation_height = Some(100);
        budget.capability_deactivation_height_exclusive = Some(4_196);
        let report = report_smallwood_poseidon2_v8_source_security_v1(
            budget,
            complete_receipts(budget),
            equal_external_losses(152),
        )
        .unwrap();
        let base = ExactRatio::new(
            BigUint::parse_bytes(
                report
                    .conditional_global_query_composed_reduction_failure
                    .numerator_decimal
                    .as_bytes(),
                10,
            )
            .unwrap(),
            BigUint::parse_bytes(
                report
                    .conditional_global_query_composed_reduction_failure
                    .denominator_decimal
                    .as_bytes(),
                10,
            )
            .unwrap(),
        )
        .unwrap();
        let global_once = ExactRatio::power_of_two(152);
        let history_scaled = ExactRatio::power_of_two(152).scale(budget.security_epoch_max_proofs);
        let mut expected = base.add(&global_once);
        for _ in 0..4 {
            expected = expected.add(&history_scaled);
        }
        let deployed = report.deployed_finite_history_composed.unwrap();
        assert_eq!(
            deployed.numerator_decimal,
            expected.numerator.to_str_radix(10)
        );
        assert_eq!(
            deployed.denominator_decimal,
            expected.denominator.to_str_radix(10)
        );
        assert_eq!(deployed.security_bits_floor, expected.bits_floor());
    }

    #[test]
    fn six_opening_full_admissibility_events_are_real_and_accounted_for() {
        let packing_points = (0..64u64).collect::<Vec<_>>();
        let openings = [
            1_000,
            1_001,
            1_002,
            1_003,
            1_004,
            17_012_888_329_801_212_958,
        ];
        assert!(openings.iter().enumerate().all(|(index, point)| {
            *point < FIELD_MODULUS_U64
                && !packing_points.contains(point)
                && !openings[..index].contains(point)
        }));
        assert_eq!(
            crate::smallwood_engine::smallwood_piop_linear_correction_factor(
                &packing_points,
                &openings,
            ),
            Some(0)
        );

        let report = report_smallwood_poseidon2_v8_current_source_security_v1().unwrap();
        assert_eq!(report.piop_linear_correction_degree, openings.len());
        assert_eq!(pcs_unstack_additional_forbidden_values().unwrap(), 68);
        assert_eq!(report.piop_admissibility_bad_tuple_coefficient, 414);
        assert_eq!(report.piop_nonce_bad_per_trial, 813);
        assert_eq!(
            report.canonical_piop_opening_abort.numerator_decimal,
            BigUint::from(813u16)
                .pow(SMALLWOOD_LEVEL5_MAX_PIOP_NONCE_TRIALS)
                .to_str_radix(10)
        );
    }

    #[test]
    fn pcs_unstack_r35_and_r63_singular_row_vectors_are_exact() {
        let packing_points = (0..64u64).collect::<Vec<_>>();
        let cases = [
            (
                1_041_288_259_238_279_555u64,
                35u64,
                11_822_583_459_820_424_585u64,
            ),
            (4_294_967_295u64, 63u64, 9_289_659_990_596_558_251u64),
        ];

        for (root, exponent, expected_correction) in cases {
            let openings = [root, 100, 101, 102, 103, 104];
            assert_eq!(pow_mod_field(root, exponent), 1);
            for other_exponent in [64u64, 35, 63] {
                if other_exponent != exponent {
                    assert_ne!(pow_mod_field(root, other_exponent), 1);
                }
            }
            assert!(openings.iter().enumerate().all(|(index, point)| {
                *point < FIELD_MODULUS_U64
                    && !packing_points.contains(point)
                    && !openings[..index].contains(point)
            }));
            assert_eq!(
                crate::smallwood_engine::smallwood_piop_linear_correction_factor(
                    &packing_points,
                    &openings,
                ),
                Some(expected_correction)
            );
            assert!(
                crate::smallwood_engine::smallwood_piop_opening_points_are_valid(
                    &packing_points,
                    &openings,
                ),
                "the legacy distinct/outside/nonzero-correction predicate must accept the vector"
            );

            let blocks = crate::smallwood_engine::smallwood_smz9_pcs_unstack_blocks_v1(&openings)
                .expect("construct exact singular SMZ9 PCS-unstack blocks");
            assert_eq!(blocks.len(), 40);
            assert_eq!(
                blocks
                    .iter()
                    .filter(|block| block[0].iter().all(|&coefficient| coefficient == 0))
                    .count(),
                5
            );
        }
    }
}
