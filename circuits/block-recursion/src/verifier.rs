use crate::{
    artifacts::{
        recursive_block_proof_encoding_digest_v1, recursive_block_tx_line_digest_v1,
        HeaderRecStepV1, RecursiveBlockArtifactV1, RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
        RECURSIVE_BLOCK_PROOF_BYTES_V1,
    },
    public_replay::RecursiveBlockPublicV1,
    relation::{
        hosted_base_binding_bytes_v1, hosted_recursive_descriptor_v1, hosted_step_binding_bytes_v1,
        recursive_block_shape_digest_v1, BaseARelationV1, StepARelationV1, StepBRelationV1,
    },
    statement::{
        recursive_prefix_statement_digest32_v1, recursive_prefix_statement_from_public_v1,
    },
    BlockRecursionError,
};
use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;
use transaction_circuit::{
    decode_smallwood_proof_trace_prefix_v1, decode_smallwood_proof_trace_v1,
    encode_smallwood_proof_trace_v1, projected_smallwood_recursive_proof_bytes_v1,
    recursive_profile_a_v1, recursive_profile_b_v1, verify_recursive_statement_v1,
    SmallwoodConstraintAdapter, SmallwoodRecursiveProfileTagV1, SmallwoodRecursiveRelationKindV1,
};

fn static_error(prefix: &'static str, err: impl core::fmt::Display) -> BlockRecursionError {
    BlockRecursionError::InvalidField(Box::leak(format!("{prefix}: {err}").into_boxed_str()))
}

fn expected_terminal_profile_tag_v1(tx_count: u32) -> SmallwoodRecursiveProfileTagV1 {
    if tx_count.is_multiple_of(2) {
        SmallwoodRecursiveProfileTagV1::A
    } else {
        SmallwoodRecursiveProfileTagV1::B
    }
}

fn expected_terminal_relation_kind_v1(tx_count: u32) -> SmallwoodRecursiveRelationKindV1 {
    if tx_count.is_multiple_of(2) {
        SmallwoodRecursiveRelationKindV1::StepA
    } else {
        SmallwoodRecursiveRelationKindV1::StepB
    }
}

fn expected_header_v1(
    public: &RecursiveBlockPublicV1,
) -> Result<HeaderRecStepV1, BlockRecursionError> {
    let statement = recursive_prefix_statement_from_public_v1(public);
    let base_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let step_a_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::StepA,
    );
    let step_b_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    Ok(HeaderRecStepV1 {
        artifact_version_rec: RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
        tx_line_digest_v1: recursive_block_tx_line_digest_v1(),
        rec_profile_tag_tau: expected_terminal_profile_tag_v1(public.tx_count).tag(),
        terminal_relation_kind_k: expected_terminal_relation_kind_v1(public.tx_count).tag(),
        relation_id_base_a: base_descriptor.relation_id,
        relation_id_step_a: step_a_descriptor.relation_id,
        relation_id_step_b: step_b_descriptor.relation_id,
        shape_digest_rec: recursive_block_shape_digest_v1().0,
        vk_digest_base_a: base_descriptor.vk_digest,
        vk_digest_step_a: step_a_descriptor.vk_digest,
        vk_digest_step_b: step_b_descriptor.vk_digest,
        proof_encoding_digest_rec: recursive_block_proof_encoding_digest_v1(),
        proof_bytes_rec: RECURSIVE_BLOCK_PROOF_BYTES_V1 as u32,
        statement_digest_rec: recursive_prefix_statement_digest32_v1(&statement),
    })
}

fn build_terminal_relation_v1(
    relation_kind: SmallwoodRecursiveRelationKindV1,
    profile_tag: SmallwoodRecursiveProfileTagV1,
    public: &RecursiveBlockPublicV1,
    proof_bytes: &[u8],
) -> Result<
    (
        transaction_circuit::RecursiveSmallwoodProfileV1,
        transaction_circuit::SmallwoodRecursiveVerifierDescriptorV1,
        Box<dyn SmallwoodConstraintAdapter + Sync>,
        Vec<u8>,
    ),
    BlockRecursionError,
> {
    let statement = recursive_prefix_statement_from_public_v1(public);
    let proof_trace = decode_smallwood_proof_trace_v1(proof_bytes)
        .map_err(|err| static_error("decode recursive proof trace failed", err))?;
    let descriptor = hosted_recursive_descriptor_v1(profile_tag, relation_kind);
    let profile = match profile_tag {
        SmallwoodRecursiveProfileTagV1::A => {
            recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING)
        }
        SmallwoodRecursiveProfileTagV1::B => {
            recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING)
        }
    };
    let relation: Box<dyn SmallwoodConstraintAdapter + Sync> = match relation_kind {
        SmallwoodRecursiveRelationKindV1::BaseA => {
            Box::new(BaseARelationV1::new(statement.clone(), statement.clone()))
        }
        SmallwoodRecursiveRelationKindV1::StepA => Box::new(
            StepARelationV1::from_witness_words_with_limb_count(
                statement.clone(),
                &proof_trace.auxiliary_witness_words,
                proof_trace.auxiliary_witness_limb_count,
            )
            .map_err(|err| static_error("rebuild StepA relation from proof witness failed", err))?,
        ),
        SmallwoodRecursiveRelationKindV1::StepB => Box::new(
            StepBRelationV1::from_witness_words_with_limb_count(
                statement.clone(),
                &proof_trace.auxiliary_witness_words,
                proof_trace.auxiliary_witness_limb_count,
            )
            .map_err(|err| static_error("rebuild StepB relation from proof witness failed", err))?,
        ),
        SmallwoodRecursiveRelationKindV1::ChunkA
        | SmallwoodRecursiveRelationKindV1::MergeA
        | SmallwoodRecursiveRelationKindV1::MergeB
        | SmallwoodRecursiveRelationKindV1::CarryA
        | SmallwoodRecursiveRelationKindV1::CarryB => {
            return Err(BlockRecursionError::InvalidField(
                "terminal_relation_kind_k",
            ))
        }
    };
    let binding = match relation_kind {
        SmallwoodRecursiveRelationKindV1::BaseA => hosted_base_binding_bytes_v1(&statement),
        SmallwoodRecursiveRelationKindV1::StepA | SmallwoodRecursiveRelationKindV1::StepB => {
            hosted_step_binding_bytes_v1(&statement)
        }
        SmallwoodRecursiveRelationKindV1::ChunkA
        | SmallwoodRecursiveRelationKindV1::MergeA
        | SmallwoodRecursiveRelationKindV1::MergeB
        | SmallwoodRecursiveRelationKindV1::CarryA
        | SmallwoodRecursiveRelationKindV1::CarryB => {
            return Err(BlockRecursionError::InvalidField(
                "terminal_relation_kind_k",
            ))
        }
    };
    Ok((profile, descriptor, relation, binding))
}

pub fn verify_block_recursive_v1(
    artifact: &RecursiveBlockArtifactV1,
    expected_public: &RecursiveBlockPublicV1,
) -> Result<RecursiveBlockPublicV1, BlockRecursionError> {
    if artifact.public != *expected_public {
        return Err(BlockRecursionError::InvalidField(
            "recursive public tuple mismatch",
        ));
    }
    let inner = &artifact.artifact;
    let expected_header = expected_header_v1(expected_public)?;
    if inner.header != expected_header {
        return Err(BlockRecursionError::InvalidField(
            "header_rec_step mismatch",
        ));
    }
    if inner.proof_bytes.len() != RECURSIVE_BLOCK_PROOF_BYTES_V1 {
        return Err(BlockRecursionError::WidthMismatch {
            what: "proof_bytes_rec",
            expected: RECURSIVE_BLOCK_PROOF_BYTES_V1,
            actual: inner.proof_bytes.len(),
        });
    }

    let relation_kind = expected_terminal_relation_kind_v1(expected_public.tx_count);
    let profile_tag = expected_terminal_profile_tag_v1(expected_public.tx_count);
    let (proof_trace, consumed_len) = decode_smallwood_proof_trace_prefix_v1(&inner.proof_bytes)
        .map_err(|err| static_error("decode recursive proof trace failed", err))?;
    let canonical_proof_bytes = encode_smallwood_proof_trace_v1(&proof_trace)
        .map_err(|err| static_error("re-encode recursive proof trace failed", err))?;
    if canonical_proof_bytes.len() != consumed_len
        || inner.proof_bytes[..consumed_len] != canonical_proof_bytes
    {
        return Err(BlockRecursionError::InvalidField(
            "proof_bytes_rec canonical encoding",
        ));
    }
    if inner.proof_bytes[consumed_len..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(BlockRecursionError::InvalidField("proof_bytes_rec padding"));
    }
    let actual_proof_bytes = canonical_proof_bytes.len();

    let (profile, descriptor, relation, binding) = build_terminal_relation_v1(
        relation_kind,
        profile_tag,
        expected_public,
        &canonical_proof_bytes,
    )?;
    let projected_proof_bytes =
        projected_smallwood_recursive_proof_bytes_v1(&profile, relation.as_ref())
            .map_err(|err| static_error("project recursive proof bytes failed", err))?;
    if actual_proof_bytes > projected_proof_bytes {
        return Err(BlockRecursionError::WidthMismatch {
            what: "proof_bytes_rec",
            expected: projected_proof_bytes,
            actual: actual_proof_bytes,
        });
    }

    verify_recursive_statement_v1(
        &profile,
        &descriptor,
        relation.as_ref(),
        &binding,
        &canonical_proof_bytes,
    )
    .map_err(|err| static_error("verify terminal recursive proof failed", err))?;
    Ok(expected_public.clone())
}
