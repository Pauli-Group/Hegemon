//! Exact source-level semantic-refinement receipt for the SmallWood Poseidon2 V8 relation.
//!
//! This module records what the executable source proves today without turning test coverage into
//! a universal theorem.  The typed 120-word statement and 721-word witness are parsed
//! canonically, validated, lowered to the 43,904-word `HGV8RP03` assignment, and replayed through
//! the verifier-owned adapter.  The remaining universal obligation is stronger: every arbitrary
//! packed assignment accepted by that adapter must decode to the fixed higher-level transaction
//! semantics.  That proof remains false here and in the corresponding Lean status value.

#[cfg(test)]
use hegemon_hash384::{
    blake2b_384_domain_hash, domains::TRANSACTION_CIPHERTEXT_HASH_V2, BLAKE2B_384_FRAME_V1,
};
use thiserror::Error;
#[cfg(test)]
use transaction_core::poseidon2_width16::{poseidon2_width16_compress14, poseidon2_width16_sponge};
#[cfg(test)]
use transaction_core::{
    hashing_pq::ciphertext_hash_bytes,
    stablecoin_poseidon2_v8::{
        stablecoin_poseidon2_v8_config_digest, stablecoin_poseidon2_v8_issuer_authorization,
        stablecoin_poseidon2_v8_issuer_commitment, stablecoin_poseidon2_v8_root,
        verify_stablecoin_transition_v8, StablecoinPoseidon2V8Config,
        StablecoinPoseidon2V8Counters, StablecoinPoseidon2V8Public, StablecoinPoseidon2V8Witness,
    },
};
use transaction_core::{
    poseidon2_width16::Felt,
    stablecoin_poseidon2_v8::{StablecoinPoseidon2V8Context, StablecoinPoseidon2V8Direction},
};

use crate::{
    smallwood_frontend::SmallwoodPrivateAuthMode,
    smallwood_poseidon2_v8_program::{
        SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST, SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512,
        SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES,
        SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES,
    },
    smallwood_poseidon2_v8_relation::SMALLWOOD_POSEIDON2_V8_RELATION_ID,
    smallwood_poseidon2_v8_semantics::{
        compile_smallwood_poseidon2_v8_relation, smallwood_poseidon2_v8_decoder_sources,
        SmallwoodPoseidon2V8RelationError, SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT,
        SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR, SMALLWOOD_POSEIDON2_V8_ROW_COUNT,
        SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS,
    },
    smallwood_poseidon2_v8_types::{
        SmallwoodPoseidon2V8InlineCiphertexts, SmallwoodPoseidon2V8PublicStatement,
        SmallwoodPoseidon2V8SemanticSurface, SmallwoodPoseidon2V8SurfaceError,
        SmallwoodPoseidon2V8Witness, SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES,
        SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
    },
};

pub const SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_SCHEMA: &str =
    "hegemon.poseidon2-v8.semantic-adequacy-refinement-v1";
pub const SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_TARGET: &str =
    "hegemon.smallwood.poseidon2-v8.exact-transaction-semantics.v1";
pub const SMALLWOOD_POSEIDON2_V8_POSEIDON_PRIMITIVE_SPECIFICATION: &str =
    "hegemon-p2w16-v1-114a4e7eb2684d29";
pub const SMALLWOOD_POSEIDON2_V8_STABLECOIN_PRIMITIVE_SPECIFICATION: &str =
    "hegemon.stablecoin.poseidon2-v8.transition.v1";
pub const SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_PRIMITIVE_SPECIFICATION: &str =
    "hegemon.rfc7693.blake2b-384.inline-ciphertext.v1";

/// Honest typed lowering is executable for every typed value accepted by the Rust validator.
pub const SMALLWOOD_POSEIDON2_V8_TYPED_LOWERING_REPLAY_AVAILABLE: bool = true;
/// The source verifier decodes every accepted packed assignment without prover side data.
pub const SMALLWOOD_POSEIDON2_V8_ARBITRARY_PACKED_DECODER_AVAILABLE: bool = true;
/// Source verification rebuilds the decoded typed witness and requires all 43,904 words equal.
pub const SMALLWOOD_POSEIDON2_V8_CANONICAL_TYPED_RELOWERING_ENFORCED: bool = true;
/// Lean now executes the exact width-16 V8 sponge/compress frames and cross-checks source KATs.
pub const SMALLWOOD_POSEIDON2_V8_EXACT_POSEIDON2_INTERPRETATION_REFINED: bool = true;
/// Lean executes the complete typed stablecoin transition and cross-checks source KATs.
pub const SMALLWOOD_POSEIDON2_V8_EXACT_STABLECOIN_TRANSITION_INTERPRETATION_REFINED: bool = true;
/// Lean executes the exact ciphertext frame and canonical six-word digest projection.
pub const SMALLWOOD_POSEIDON2_V8_EXACT_CIPHERTEXT_FRAMING_AND_PROJECTION_REFINED: bool = true;
/// The source verifier enforces all five semantic families through decode, validation, and exact
/// relowering.  This is distinct from a completed Lean theorem about the concrete Rust function.
pub const SMALLWOOD_POSEIDON2_V8_SOURCE_SEMANTIC_GATE_ENFORCED: bool = true;
/// No verified extraction or Rust-semantics proof connects the concrete Rust verifier to Lean.
pub const SMALLWOOD_POSEIDON2_V8_VERIFIED_RUST_SEMANTICS_EXTRACTION_AVAILABLE: bool = false;
/// Lean does not yet contain an implementation of RFC 7693 BLAKE2b-384 compression.
pub const SMALLWOOD_POSEIDON2_V8_IN_LEAN_RFC7693_BLAKE2B384_IMPLEMENTATION_AVAILABLE: bool = false;
/// No checked-in Lean proof yet connects the concrete Rust verifier to the universal theorem.
pub const SMALLWOOD_POSEIDON2_V8_UNIVERSAL_ACCEPTED_WITNESS_SOUNDNESS_PROVED: bool = false;
/// RFC 7693 BLAKE2b and verified Rust-semantics extraction remain before every primitive and
/// compiler-refinement obligation is closed.
pub const SMALLWOOD_POSEIDON2_V8_EXACT_PRIMITIVE_INTERPRETATION_REFINEMENT_PROVED: bool = false;
/// A refinement receipt is evidence only and never production authority.
pub const SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_PRODUCTION_AUTHORITY: bool = false;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8SemanticFamily {
    pub name: &'static str,
    pub external_to_private_relation: bool,
}

pub const SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_FAMILIES: [SmallwoodPoseidon2V8SemanticFamily; 10] = [
    SmallwoodPoseidon2V8SemanticFamily {
        name: "canonical_public_statement",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "two_input_two_output_all_activity_masks",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "note_commitments",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "nullifiers_and_depth32_merkle",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "all_authorization_modes",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "action_intent",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "per_asset_balance",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "stablecoin_transition",
        external_to_private_relation: false,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "inline_blake2b384_ciphertexts",
        external_to_private_relation: true,
    },
    SmallwoodPoseidon2V8SemanticFamily {
        name: "consensus_stablecoin_context",
        external_to_private_relation: true,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8SemanticObligationStatus {
    pub name: &'static str,
    pub source_verifier_enforced: bool,
    pub lean_universal_theorem_proved: bool,
}

/// Separately tracked status for the five conjuncts of the fixed semantic target.
pub const SMALLWOOD_POSEIDON2_V8_SEMANTIC_OBLIGATION_STATUS:
    [SmallwoodPoseidon2V8SemanticObligationStatus; 5] = [
    SmallwoodPoseidon2V8SemanticObligationStatus {
        name: "canonical_public_statement",
        source_verifier_enforced: true,
        lean_universal_theorem_proved: false,
    },
    SmallwoodPoseidon2V8SemanticObligationStatus {
        name: "canonical_witness_shape",
        source_verifier_enforced: true,
        lean_universal_theorem_proved: false,
    },
    SmallwoodPoseidon2V8SemanticObligationStatus {
        name: "cryptographic_links",
        source_verifier_enforced: true,
        lean_universal_theorem_proved: false,
    },
    SmallwoodPoseidon2V8SemanticObligationStatus {
        name: "per_asset_balance",
        source_verifier_enforced: true,
        lean_universal_theorem_proved: false,
    },
    SmallwoodPoseidon2V8SemanticObligationStatus {
        name: "stablecoin_transition",
        source_verifier_enforced: true,
        lean_universal_theorem_proved: false,
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmallwoodPoseidon2V8TypedSemanticRefinementReceipt {
    pub schema: &'static str,
    pub semantic_target: &'static str,
    pub relation_id: &'static str,
    pub relation_digest: [u8; 48],
    pub program_sha512: [u8; 64],
    pub program_transcript_bytes: usize,
    pub public_words: usize,
    pub typed_witness_words: usize,
    pub packed_witness_words: usize,
    pub relation_rows: usize,
    pub packing_factor: usize,
    pub nonlinear_identities: usize,
    pub csr_attempts: usize,
    pub emitted_linear_identities: usize,
    pub activity_mask: u8,
    pub authorization_mode: &'static str,
    pub stablecoin_direction: &'static str,
    pub public_roundtrip_exact: bool,
    pub typed_witness_roundtrip_exact: bool,
    pub derived_relation_context_valid: bool,
    pub typed_semantic_surface_valid: bool,
    pub packed_program_accepts_typed_lowering: bool,
    pub arbitrary_packed_decoder_available: bool,
    pub canonical_typed_relowering_enforced: bool,
    pub exact_poseidon2_interpretation_refined: bool,
    pub source_semantic_gate_enforced: bool,
    pub inline_ciphertexts_bound: bool,
    pub exact_primitive_interpretation_refinement_proved: bool,
    pub universal_accepted_witness_soundness_proved: bool,
    pub production_authority: bool,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SmallwoodPoseidon2V8SemanticRefinementError {
    #[error("invalid typed V8 semantic surface: {0:?}")]
    Surface(SmallwoodPoseidon2V8SurfaceError),
    #[error("V8 relation lowering or replay failed: {0}")]
    Relation(#[from] SmallwoodPoseidon2V8RelationError),
    #[error("the V8 public statement did not round-trip through its canonical 120-word parser")]
    PublicRoundtripMismatch,
    #[error("the V8 witness did not round-trip through its canonical 721-word parser")]
    WitnessRoundtripMismatch,
    #[error("the supplied stablecoin context is not the statement-derived relation context")]
    RelationContextMismatch,
    #[error("the source-program refinement receipt has inconsistent geometry")]
    SourceProgramReceiptMismatch,
}

impl From<SmallwoodPoseidon2V8SurfaceError> for SmallwoodPoseidon2V8SemanticRefinementError {
    fn from(value: SmallwoodPoseidon2V8SurfaceError) -> Self {
        Self::Surface(value)
    }
}

pub fn derived_smallwood_poseidon2_v8_relation_context(
    statement: &SmallwoodPoseidon2V8PublicStatement,
) -> StablecoinPoseidon2V8Context {
    StablecoinPoseidon2V8Context {
        current_root: statement.stablecoin.before_root,
        parent_height: statement.stablecoin.parent_height,
        expected_action_intent: if statement.stablecoin.direction
            == StablecoinPoseidon2V8Direction::Disabled
        {
            [Felt::ZERO; 7]
        } else {
            statement.stablecoin.action_intent
        },
    }
}

fn authorization_mode_name(mode: SmallwoodPrivateAuthMode) -> &'static str {
    match mode {
        SmallwoodPrivateAuthMode::SingleKey => "single_key",
        SmallwoodPrivateAuthMode::ApprovalStep => "approval_step",
        SmallwoodPrivateAuthMode::FinalThresholdSpend => "final_threshold_spend",
    }
}

fn stablecoin_direction_name(direction: StablecoinPoseidon2V8Direction) -> &'static str {
    match direction {
        StablecoinPoseidon2V8Direction::Disabled => "disabled",
        StablecoinPoseidon2V8Direction::Mint => "mint",
        StablecoinPoseidon2V8Direction::Burn => "burn",
    }
}

fn audit_smallwood_poseidon2_v8_typed_lowering_in_context(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
    stablecoin_context: StablecoinPoseidon2V8Context,
    inline_ciphertexts: Option<&SmallwoodPoseidon2V8InlineCiphertexts>,
) -> Result<
    SmallwoodPoseidon2V8TypedSemanticRefinementReceipt,
    SmallwoodPoseidon2V8SemanticRefinementError,
> {
    if stablecoin_context != derived_smallwood_poseidon2_v8_relation_context(statement) {
        return Err(SmallwoodPoseidon2V8SemanticRefinementError::RelationContextMismatch);
    }
    let surface = SmallwoodPoseidon2V8SemanticSurface {
        statement: *statement,
        witness: *witness,
        stablecoin_context,
    };
    surface.validate()?;
    if let Some(ciphertexts) = inline_ciphertexts {
        surface.validate_with_inline_ciphertexts(ciphertexts)?;
    }

    let public_words = statement.to_public_words();
    if SmallwoodPoseidon2V8PublicStatement::try_from_public_words(&public_words)? != *statement {
        return Err(SmallwoodPoseidon2V8SemanticRefinementError::PublicRoundtripMismatch);
    }
    let typed_witness_words = witness.to_witness_words();
    if SmallwoodPoseidon2V8Witness::try_from_witness_words(&typed_witness_words)? != *witness {
        return Err(SmallwoodPoseidon2V8SemanticRefinementError::WitnessRoundtripMismatch);
    }

    let lowered = compile_smallwood_poseidon2_v8_relation(statement, witness)?;
    lowered
        .adapter
        .verify_packed_witness(&lowered.witness_values)?;
    let source = lowered.adapter.source_program_refinement();
    if source.relation_digest != SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST
        || source.packed_lanes != SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR
        || source.nonlinear_roots != SMALLWOOD_POSEIDON2_V8_NONLINEAR_CONSTRAINT_COUNT
        || source.csr_attempts != SMALLWOOD_POSEIDON2_V8_SYMBOLIC_CSR_FAMILY_INSTANCES
        || source.emitted_linear_constraints != lowered.adapter.geometry().linear_constraints
    {
        return Err(SmallwoodPoseidon2V8SemanticRefinementError::SourceProgramReceiptMismatch);
    }

    Ok(SmallwoodPoseidon2V8TypedSemanticRefinementReceipt {
        schema: SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_SCHEMA,
        semantic_target: SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_TARGET,
        relation_id: SMALLWOOD_POSEIDON2_V8_RELATION_ID,
        relation_digest: SMALLWOOD_POSEIDON2_V8_PROGRAM_DIGEST,
        program_sha512: SMALLWOOD_POSEIDON2_V8_PROGRAM_SHA512,
        program_transcript_bytes: SMALLWOOD_POSEIDON2_V8_PROGRAM_TRANSCRIPT_BYTES,
        public_words: SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS,
        typed_witness_words: typed_witness_words.len(),
        packed_witness_words: lowered.witness_values.len(),
        relation_rows: SMALLWOOD_POSEIDON2_V8_ROW_COUNT,
        packing_factor: SMALLWOOD_POSEIDON2_V8_PACKING_FACTOR,
        nonlinear_identities: source.nonlinear_roots,
        csr_attempts: source.csr_attempts,
        emitted_linear_identities: source.emitted_linear_constraints,
        activity_mask: statement.activity_mask(),
        authorization_mode: authorization_mode_name(witness.auth.mode),
        stablecoin_direction: stablecoin_direction_name(statement.stablecoin.direction),
        public_roundtrip_exact: true,
        typed_witness_roundtrip_exact: true,
        derived_relation_context_valid: true,
        typed_semantic_surface_valid: true,
        packed_program_accepts_typed_lowering: true,
        arbitrary_packed_decoder_available:
            SMALLWOOD_POSEIDON2_V8_ARBITRARY_PACKED_DECODER_AVAILABLE,
        canonical_typed_relowering_enforced:
            SMALLWOOD_POSEIDON2_V8_CANONICAL_TYPED_RELOWERING_ENFORCED,
        exact_poseidon2_interpretation_refined:
            SMALLWOOD_POSEIDON2_V8_EXACT_POSEIDON2_INTERPRETATION_REFINED,
        source_semantic_gate_enforced: SMALLWOOD_POSEIDON2_V8_SOURCE_SEMANTIC_GATE_ENFORCED,
        inline_ciphertexts_bound: inline_ciphertexts.is_some(),
        exact_primitive_interpretation_refinement_proved:
            SMALLWOOD_POSEIDON2_V8_EXACT_PRIMITIVE_INTERPRETATION_REFINEMENT_PROVED,
        universal_accepted_witness_soundness_proved:
            SMALLWOOD_POSEIDON2_V8_UNIVERSAL_ACCEPTED_WITNESS_SOUNDNESS_PROVED,
        production_authority: SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_PRODUCTION_AUTHORITY,
    })
}

/// Audit the exact canonical typed relation surface and its statement-derived stablecoin context.
pub fn audit_smallwood_poseidon2_v8_typed_lowering(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
) -> Result<
    SmallwoodPoseidon2V8TypedSemanticRefinementReceipt,
    SmallwoodPoseidon2V8SemanticRefinementError,
> {
    audit_smallwood_poseidon2_v8_typed_lowering_in_context(
        statement,
        witness,
        derived_smallwood_poseidon2_v8_relation_context(statement),
        None,
    )
}

/// Audit the exact relation surface while requiring an independently supplied context to match.
pub fn audit_smallwood_poseidon2_v8_typed_lowering_with_context(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
    stablecoin_context: StablecoinPoseidon2V8Context,
) -> Result<
    SmallwoodPoseidon2V8TypedSemanticRefinementReceipt,
    SmallwoodPoseidon2V8SemanticRefinementError,
> {
    audit_smallwood_poseidon2_v8_typed_lowering_in_context(
        statement,
        witness,
        stablecoin_context,
        None,
    )
}

/// Audit relation lowering and the exact inline BLAKE2b-384 ciphertext commitments together.
pub fn audit_smallwood_poseidon2_v8_typed_lowering_with_inline_ciphertexts(
    statement: &SmallwoodPoseidon2V8PublicStatement,
    witness: &SmallwoodPoseidon2V8Witness,
    inline_ciphertexts: &SmallwoodPoseidon2V8InlineCiphertexts,
) -> Result<
    SmallwoodPoseidon2V8TypedSemanticRefinementReceipt,
    SmallwoodPoseidon2V8SemanticRefinementError,
> {
    audit_smallwood_poseidon2_v8_typed_lowering_in_context(
        statement,
        witness,
        derived_smallwood_poseidon2_v8_relation_context(statement),
        Some(inline_ciphertexts),
    )
}

const _: () = assert!(SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS == 120);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS == 686 * 64);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_BYTES == 2_147);
const _: () = assert!(SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_FAMILIES.len() == 10);

#[cfg(test)]
mod tests {
    use super::*;

    fn json_u64_array(value: &serde_json::Value) -> Vec<u64> {
        value
            .as_array()
            .expect("Lean KAT is a JSON array")
            .iter()
            .map(|word| word.as_u64().expect("Lean KAT word fits u64"))
            .collect()
    }

    fn json_u64_matrix(value: &serde_json::Value) -> Vec<Vec<u64>> {
        value
            .as_array()
            .expect("Lean refinement vector is a JSON matrix")
            .iter()
            .map(json_u64_array)
            .collect()
    }

    fn tagged_digest(base: u64) -> [Felt; 7] {
        core::array::from_fn(|limb| Felt::from_u64(base + limb as u64))
    }

    fn canonical_digest_words(digest: [Felt; 7]) -> Vec<u64> {
        digest
            .into_iter()
            .map(|word| word.as_canonical_u64())
            .collect()
    }

    #[test]
    fn default_typed_surface_replays_but_universal_status_stays_false() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let witness = SmallwoodPoseidon2V8Witness::default();
        let receipt = audit_smallwood_poseidon2_v8_typed_lowering(&statement, &witness).unwrap();
        assert_eq!(receipt.public_words, 120);
        assert_eq!(receipt.typed_witness_words, 728);
        assert_eq!(receipt.packed_witness_words, 43_904);
        assert!(receipt.packed_program_accepts_typed_lowering);
        assert!(receipt.arbitrary_packed_decoder_available);
        assert!(receipt.canonical_typed_relowering_enforced);
        assert!(receipt.exact_poseidon2_interpretation_refined);
        assert!(receipt.source_semantic_gate_enforced);
        assert!(!receipt.exact_primitive_interpretation_refinement_proved);
        assert!(!receipt.universal_accepted_witness_soundness_proved);
        assert!(!receipt.production_authority);
    }

    #[test]
    fn caller_supplied_relation_context_must_match_the_statement() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let witness = SmallwoodPoseidon2V8Witness::default();
        let mut context = derived_smallwood_poseidon2_v8_relation_context(&statement);
        context.parent_height += 1;
        assert_eq!(
            audit_smallwood_poseidon2_v8_typed_lowering_with_context(&statement, &witness, context,),
            Err(SmallwoodPoseidon2V8SemanticRefinementError::RelationContextMismatch)
        );
    }

    #[test]
    fn inactive_ciphertexts_are_bound_separately_from_private_relation_words() {
        let statement = SmallwoodPoseidon2V8PublicStatement::default();
        let witness = SmallwoodPoseidon2V8Witness::default();
        let receipt = audit_smallwood_poseidon2_v8_typed_lowering_with_inline_ciphertexts(
            &statement,
            &witness,
            &SmallwoodPoseidon2V8InlineCiphertexts::default(),
        )
        .unwrap();
        assert!(receipt.inline_ciphertexts_bound);
        assert!(!receipt.universal_accepted_witness_soundness_proved);
    }

    #[test]
    fn lean_generated_semantic_adequacy_receipt_matches_rust_status() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/formal_core_vectors/poseidon2_v8_semantic_adequacy.json"
        )))
        .unwrap();
        assert_eq!(
            vector["schema"],
            SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_SCHEMA
        );
        assert_eq!(
            vector["semantic_target"],
            SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_TARGET
        );
        assert_eq!(vector["relation_program"], "HGV8RP03");
        assert_eq!(
            vector["checked_in_coverage"],
            "source_verifier_canonical_relowering"
        );
        assert_eq!(vector["typed_lowering_replay_available"], true);
        assert_eq!(
            vector["arbitrary_packed_assignment_decoder_available"],
            SMALLWOOD_POSEIDON2_V8_ARBITRARY_PACKED_DECODER_AVAILABLE
        );
        assert_eq!(
            vector["canonical_typed_relowering_source_verifier_enforced"],
            SMALLWOOD_POSEIDON2_V8_CANONICAL_TYPED_RELOWERING_ENFORCED
        );
        assert_eq!(
            vector["source_semantic_gate_enforced"],
            SMALLWOOD_POSEIDON2_V8_SOURCE_SEMANTIC_GATE_ENFORCED
        );
        let rust_decoder_sources: Vec<Vec<u64>> = smallwood_poseidon2_v8_decoder_sources()
            .into_iter()
            .map(|source| source.to_receipt_words().to_vec())
            .collect();
        assert_eq!(
            json_u64_matrix(&vector["decoder_source_vector"]),
            rust_decoder_sources
        );
        assert_eq!(
            json_u64_array(&vector["decoder_family_counts"]),
            [252, 252, 23, 23, 77, 94]
        );
        assert_eq!(
            json_u64_array(&vector["decoder_operation_counts"]),
            [4, 8, 95, 2, 448, 16, 1, 23, 30, 66, 28]
        );
        assert_eq!(
            json_u64_array(&vector["decoder_activity_mask_branches"]),
            (0..16).collect::<Vec<_>>()
        );
        assert_eq!(
            json_u64_array(&vector["decoder_authorization_mode_branches"]),
            [0, 1, 2]
        );
        assert_eq!(
            json_u64_array(&vector["decoder_stablecoin_direction_branches"]),
            [0, 1, 2]
        );
        assert_eq!(
            json_u64_array(&vector["decoder_stable_tree_index_branches"]),
            (0..16).collect::<Vec<_>>()
        );
        assert_eq!(
            json_u64_array(&vector["decoder_note_hash_word_order"]),
            [0, 1, 2, 3, 4, 5, 14, 15, 16, 17, 6, 7, 8, 9, 10, 11, 12, 13]
        );
        assert_eq!(vector["relowering_compared_packed_words"], 43_904);
        assert_eq!(
            vector["concrete_rust_to_lean_universal_refinement_proved"],
            SMALLWOOD_POSEIDON2_V8_UNIVERSAL_ACCEPTED_WITNESS_SOUNDNESS_PROVED
        );
        assert_eq!(
            vector["poseidon2_primitive_specification"],
            SMALLWOOD_POSEIDON2_V8_POSEIDON_PRIMITIVE_SPECIFICATION
        );
        assert_eq!(
            vector["exact_poseidon2_primitive_interpretation_available"],
            true
        );
        let sponge = poseidon2_width16_sponge(2, &[1, 2, 3, 4].map(Felt::from_u64))
            .unwrap()
            .map(|word| word.as_canonical_u64());
        assert_eq!(
            json_u64_array(&vector["poseidon2_sponge_kat_domain2_1_2_3_4"]),
            sponge
        );
        let left = core::array::from_fn(|word| Felt::from_u64(word as u64));
        let right = core::array::from_fn(|word| Felt::from_u64((word + 7) as u64));
        let compressed =
            poseidon2_width16_compress14(4, &left, &right).map(|word| word.as_canonical_u64());
        assert_eq!(
            json_u64_array(&vector["poseidon2_compress14_kat_ranges"]),
            compressed
        );
        let nullifier = poseidon2_width16_sponge(2, &[1, 2, 3, 4, 5, 6].map(Felt::from_u64))
            .unwrap()
            .map(|word| word.as_canonical_u64());
        assert_eq!(
            json_u64_array(&vector["poseidon2_nullifier_kat"]),
            nullifier
        );
        assert_eq!(
            vector["stablecoin_primitive_specification"],
            SMALLWOOD_POSEIDON2_V8_STABLECOIN_PRIMITIVE_SPECIFICATION
        );
        assert_eq!(
            vector["exact_stablecoin_transition_interpretation_available"],
            SMALLWOOD_POSEIDON2_V8_EXACT_STABLECOIN_TRANSITION_INTERPRETATION_REFINED
        );
        let issuer_secret = tagged_digest(1);
        let action_intent = tagged_digest(11);
        let config = StablecoinPoseidon2V8Config {
            asset_id: 1_001,
            policy_version: 7,
            active: true,
            enabled_at: 1,
            retired_at: Some(20_000),
            issuer_commitment: stablecoin_poseidon2_v8_issuer_commitment(1_001, 7, &issuer_secret),
            min_collateral_ratio_ppm: 1_500_000,
            max_mint_per_epoch: 1_000_000,
            oracle_submitted_at: 8_900,
            oracle_max_age: 500,
            oracle_price_numerator: 2,
            oracle_price_denominator: 1,
            collateral_amount: 10_000,
            attestation_created_at: 8_800,
            attestation_disputed: false,
            attestation_present: true,
            attestation_max_age: 500,
            policy_admin_commitment: tagged_digest(101),
            oracle_authority_commitment: tagged_digest(201),
            attestation_authority_commitment: tagged_digest(301),
            collateral_asset_id: 0,
            collateral_decimals: 6,
            collateral_scale: 1_000_000,
            locked_collateral_commitment: tagged_digest(401),
        };
        let before = StablecoinPoseidon2V8Counters {
            epoch_id: 2,
            minted_in_epoch: 100,
            total_debt: 1_000,
            sequence: 9,
        };
        let siblings = [
            tagged_digest(601),
            tagged_digest(701),
            tagged_digest(801),
            tagged_digest(901),
        ];
        let config_digest = stablecoin_poseidon2_v8_config_digest(config);
        let before_root = stablecoin_poseidon2_v8_root(1_001, config_digest, before, &siblings)
            .expect("KAT stablecoin path is well formed");
        let mint_after = StablecoinPoseidon2V8Counters {
            epoch_id: 2,
            minted_in_epoch: 125,
            total_debt: 1_025,
            sequence: 10,
        };
        let burn_after = StablecoinPoseidon2V8Counters {
            epoch_id: 2,
            minted_in_epoch: 100,
            total_debt: 975,
            sequence: 10,
        };
        let mint_after_root =
            stablecoin_poseidon2_v8_root(1_001, config_digest, mint_after, &siblings)
                .expect("KAT mint path is well formed");
        let burn_after_root =
            stablecoin_poseidon2_v8_root(1_001, config_digest, burn_after, &siblings)
                .expect("KAT burn path is well formed");
        let issuer_authorization =
            stablecoin_poseidon2_v8_issuer_authorization(&action_intent, &issuer_secret);
        assert_eq!(
            json_u64_array(&vector["stablecoin_config_digest_kat"]),
            canonical_digest_words(config_digest)
        );
        assert_eq!(
            json_u64_array(&vector["stablecoin_before_root_kat"]),
            canonical_digest_words(before_root)
        );
        assert_eq!(
            json_u64_array(&vector["stablecoin_mint_after_root_kat"]),
            canonical_digest_words(mint_after_root)
        );
        assert_eq!(
            json_u64_array(&vector["stablecoin_burn_after_root_kat"]),
            canonical_digest_words(burn_after_root)
        );
        assert_eq!(
            json_u64_array(&vector["stablecoin_issuer_commitment_kat"]),
            canonical_digest_words(config.issuer_commitment)
        );
        assert_eq!(
            json_u64_array(&vector["stablecoin_issuer_authorization_kat"]),
            canonical_digest_words(issuer_authorization)
        );
        let context = StablecoinPoseidon2V8Context {
            current_root: before_root,
            parent_height: 9_000,
            expected_action_intent: action_intent,
        };
        let mint_public = StablecoinPoseidon2V8Public {
            direction: StablecoinPoseidon2V8Direction::Mint,
            asset_id: 1_001,
            policy_version: 7,
            magnitude: 25,
            action_intent,
            parent_height: 9_000,
            before_root,
            after_root: mint_after_root,
            after: mint_after,
            issuer_authorization,
        };
        let burn_public = StablecoinPoseidon2V8Public {
            direction: StablecoinPoseidon2V8Direction::Burn,
            asset_id: 1_001,
            policy_version: 7,
            magnitude: 25,
            action_intent,
            parent_height: 9_000,
            before_root,
            after_root: burn_after_root,
            after: burn_after,
            issuer_authorization: [Felt::ZERO; 7],
        };
        let mint_witness = StablecoinPoseidon2V8Witness {
            config,
            before,
            siblings,
            issuer_secret,
        };
        let burn_witness = StablecoinPoseidon2V8Witness {
            issuer_secret: [Felt::ZERO; 7],
            ..mint_witness
        };
        assert_eq!(
            vector["stablecoin_mint_kat_accepts"],
            verify_stablecoin_transition_v8(context, mint_public, mint_witness).is_ok()
        );
        assert_eq!(
            vector["stablecoin_burn_kat_accepts"],
            verify_stablecoin_transition_v8(context, burn_public, burn_witness).is_ok()
        );
        assert_eq!(
            vector["ciphertext_primitive_specification"],
            SMALLWOOD_POSEIDON2_V8_CIPHERTEXT_PRIMITIVE_SPECIFICATION
        );
        assert_eq!(
            vector["exact_ciphertext_framing_and_projection_available"],
            SMALLWOOD_POSEIDON2_V8_EXACT_CIPHERTEXT_FRAMING_AND_PROJECTION_REFINED
        );
        let ciphertext_kat = b"hegemon ciphertext hash v2 KAT";
        assert_eq!(
            json_u64_array(&vector["ciphertext_blake2b_kat_input"]),
            ciphertext_kat
                .iter()
                .copied()
                .map(u64::from)
                .collect::<Vec<_>>()
        );
        let mut frame = Vec::new();
        frame.extend_from_slice(BLAKE2B_384_FRAME_V1);
        frame.extend_from_slice(&(TRANSACTION_CIPHERTEXT_HASH_V2.len() as u64).to_le_bytes());
        frame.extend_from_slice(TRANSACTION_CIPHERTEXT_HASH_V2);
        frame.extend_from_slice(&(ciphertext_kat.len() as u64).to_le_bytes());
        frame.extend_from_slice(ciphertext_kat);
        assert_eq!(
            json_u64_array(&vector["ciphertext_blake2b_kat_frame"]),
            frame.iter().copied().map(u64::from).collect::<Vec<_>>()
        );
        let raw_digest =
            blake2b_384_domain_hash(TRANSACTION_CIPHERTEXT_HASH_V2, [ciphertext_kat.as_slice()]);
        assert_eq!(
            json_u64_array(&vector["ciphertext_blake2b_kat_digest"]),
            raw_digest
                .iter()
                .copied()
                .map(u64::from)
                .collect::<Vec<_>>()
        );
        let canonical_commitment = ciphertext_hash_bytes(ciphertext_kat);
        let commitment_words = canonical_commitment
            .chunks_exact(8)
            .map(|chunk| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(chunk);
                u64::from_be_bytes(bytes)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            json_u64_array(&vector["ciphertext_blake2b_kat_commitment_words"]),
            commitment_words
        );
        assert_eq!(
            vector["exact_primitive_interpretation_refinement_proved"],
            SMALLWOOD_POSEIDON2_V8_EXACT_PRIMITIVE_INTERPRETATION_REFINEMENT_PROVED
        );
        assert_eq!(
            vector["verified_rust_semantics_extraction_absent"],
            !SMALLWOOD_POSEIDON2_V8_VERIFIED_RUST_SEMANTICS_EXTRACTION_AVAILABLE
        );
        assert_eq!(
            vector["in_lean_rfc7693_blake2b384_implementation_absent"],
            !SMALLWOOD_POSEIDON2_V8_IN_LEAN_RFC7693_BLAKE2B384_IMPLEMENTATION_AVAILABLE
        );
        assert_eq!(
            vector["universal_accepted_witness_soundness_proved"],
            SMALLWOOD_POSEIDON2_V8_UNIVERSAL_ACCEPTED_WITNESS_SOUNDNESS_PROVED
        );
        assert_eq!(
            vector["production_authority"],
            SMALLWOOD_POSEIDON2_V8_SEMANTIC_REFINEMENT_PRODUCTION_AUTHORITY
        );
        assert_eq!(vector["public_words"], SMALLWOOD_POSEIDON2_V8_PUBLIC_WORDS);
        assert_eq!(vector["typed_witness_words"], 721);
        assert_eq!(
            vector["packed_witness_words"],
            SMALLWOOD_POSEIDON2_V8_WITNESS_WORDS
        );
        assert_eq!(vector["value_bound_exclusive"], 1u64 << 61);
        assert_eq!(vector["stablecoin_value_bound_exclusive"], 1u64 << 56);
        assert_eq!(vector["stablecoin_scalar_bound_exclusive"], 1u64 << 63);
        assert_eq!(
            vector["semantic_families"].as_array().unwrap().len(),
            SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_FAMILIES.len()
        );
        for (actual, expected) in vector["semantic_families"]
            .as_array()
            .unwrap()
            .iter()
            .zip(SMALLWOOD_POSEIDON2_V8_EXACT_SEMANTIC_FAMILIES)
        {
            assert_eq!(actual["name"], expected.name);
            assert_eq!(
                actual["external_to_private_relation"],
                expected.external_to_private_relation
            );
        }
    }
}
