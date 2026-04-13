#![forbid(unsafe_code)]

mod artifacts;
mod prover;
mod public_replay;
mod relation;
mod state;
mod statement;
#[cfg(test)]
mod tests;
mod verifier;

pub use artifacts::{
    block_accumulation_transcript_digest_v1, block_accumulation_transcript_serializer_digest_v1,
    compress_transcript_digest_v1, decider_profile_digest_v1,
    deserialize_block_accumulation_transcript_v1, deserialize_header_dec_step_v1,
    deserialize_recursive_block_artifact_v1, deserialize_recursive_block_inner_artifact_v1,
    header_dec_step_profile_digest_v1, recursive_block_public_statement_digest_v1,
    recursive_decider_serializer_digest_v1, recursive_lcccs_serializer_digest_v1,
    serialize_block_accumulation_transcript_v1, serialize_header_dec_step_v1,
    serialize_recursive_block_artifact_v1, serialize_recursive_block_inner_artifact_v1,
    serialize_recursive_block_public_v1, BlockAccumulationTranscriptV1, CanonicalDeciderTranscript,
    HeaderDecStepV1, RecursiveBlockArtifactV1, RecursiveBlockInnerArtifactV1,
    BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1, RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
    RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1,
};
pub use prover::{prove_block_recursive_v1, BlockRecursiveProverInputV1};
pub use public_replay::{
    canonical_receipt_record_bytes_v1, canonical_verified_leaf_record_bytes_v1, public_replay_v1,
    BlockLeafRecordV1, BlockSemanticInputsV1, RecursiveBlockPublicV1,
};
pub use relation::{
    block_leaf_inputs_v1, block_public_inputs_v1, empty_prefix_public_v1,
    ensure_expected_relation_v1, ensure_expected_shape_v1, hosted_base_binding_bytes_v1,
    hosted_recursive_descriptor_v1, hosted_recursive_proof_witness_layout_v1,
    hosted_recursive_proof_witness_words_v1, hosted_step_binding_bytes_v1, leaf_statement_v1,
    pack_statement_witness_v1, prefix_statement_v1, previous_proof_rows_for_limbs_v1,
    previous_proof_trace_limbs_v1, previous_proof_witness_layout_from_envelope_v1,
    previous_proof_witness_layout_from_sizes_v1, recursive_block_relation_id_v1,
    recursive_block_shape_digest_v1, recursive_block_shape_v1,
    verify_hosted_recursive_proof_context_binding_trace_v1,
    verify_hosted_recursive_proof_context_components_v1,
    verify_hosted_recursive_proof_context_decs_merkle_v1,
    verify_hosted_recursive_proof_context_descriptor_shape_v1,
    verify_hosted_recursive_proof_context_pcs_v1,
    verify_hosted_recursive_proof_context_transcript_v1, verify_hosted_recursive_proof_context_v1,
    verify_recursive_proof_envelope_components_v1, BaseARelationV1, BlockStatementKindV1,
    HostedRecursiveProofContextV1, PreviousProofWitnessLayoutV1, PreviousProofWitnessSectionV1,
    StepARelationV1, StepBRelationV1, PREVIOUS_PROOF_DECS_LIMBS_V1, PREVIOUS_PROOF_MERKLE_LIMBS_V1,
    PREVIOUS_PROOF_PCS_LIMBS_V1, PREVIOUS_PROOF_TRANSCRIPT_LIMBS_V1,
    PREVIOUS_PROOF_WITNESS_LIMB_BYTES_V1, PREVIOUS_PROOF_WITNESS_ROW_WIDTH_LIMBS_V1,
};
pub use state::{fold_digest32, fold_digest48, Digest32, Digest48};
pub use statement::{
    recursive_prefix_statement_digest_v1, statement_digest_v1, BlockPrefixStatementV1,
    BlockStepStatementV1, ComposeCheckV1, RecursivePrefixStatementV1,
};
pub use verifier::verify_block_recursive_v1;

use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockRecursionError {
    NotImplemented(&'static str),
    InvalidLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidField(&'static str),
    InvalidVersion {
        what: &'static str,
        version: u16,
    },
    TrailingBytes {
        remaining: usize,
    },
    WidthMismatch {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
    ComposeCheckFailed(&'static str),
}

impl fmt::Display for BlockRecursionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
            Self::InvalidLength {
                what,
                expected,
                actual,
            } => write!(
                f,
                "invalid length for {what}: expected {expected}, got {actual}"
            ),
            Self::InvalidField(what) => write!(f, "invalid field: {what}"),
            Self::InvalidVersion { what, version } => {
                write!(f, "invalid version for {what}: {version}")
            }
            Self::TrailingBytes { remaining } => {
                write!(f, "trailing bytes remain after exact parse: {remaining}")
            }
            Self::WidthMismatch {
                what,
                expected,
                actual,
            } => write!(
                f,
                "width mismatch for {what}: expected {expected}, got {actual}"
            ),
            Self::ComposeCheckFailed(what) => write!(f, "compose check failed: {what}"),
        }
    }
}

impl std::error::Error for BlockRecursionError {}
