use crate::{
    artifacts::{
        compress_transcript_digest_v1, decider_profile_digest_v1,
        recursive_decider_serializer_digest_v1, recursive_lcccs_serializer_digest_v1,
        serialize_block_accumulation_transcript_v1, serialize_recursive_block_inner_artifact_v1,
        BlockAccumulationTranscriptV1, HeaderDecStepV1, RecursiveBlockArtifactV1,
        RecursiveBlockInnerArtifactV1, BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1,
        RECURSIVE_BLOCK_ARTIFACT_VERSION_V1, RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1,
    },
    public_replay::{public_replay_v1, BlockLeafRecordV1, BlockSemanticInputsV1},
    relation::{
        ensure_expected_relation_v1, ensure_expected_shape_v1, leaf_statement_v1,
        pack_statement_witness_v1, prefix_statement_v1, recursive_block_relation_id_v1,
        recursive_block_shape_v1, BlockStatementKindV1,
    },
    BlockRecursionError,
};
use superneo_backend_lattice::{
    canonical_recursive_decider_transcript, recursive_backend_v2, LatticeBackend,
    NativeCommitmentScheme,
};
use superneo_core::{serialize_decider_profile, serialize_lcccs_instance, RecursiveBackend};
use superneo_hegemon::native_backend_params;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecursiveProverInputV1 {
    pub records: Vec<BlockLeafRecordV1>,
    pub semantic: BlockSemanticInputsV1,
}

fn static_error(prefix: &'static str, err: impl core::fmt::Display) -> BlockRecursionError {
    BlockRecursionError::InvalidField(Box::leak(format!("{prefix}: {err}").into_boxed_str()))
}

fn build_transcript_bytes_v1(
    step_count: u32,
    digests: &[Vec<u8>],
) -> Result<Vec<u8>, BlockRecursionError> {
    let mut transcript_bytes = Vec::new();
    transcript_bytes.extend_from_slice(b"hegemon.block-recursion.private-transcript.v1");
    transcript_bytes.extend_from_slice(&step_count.to_le_bytes());
    transcript_bytes.extend_from_slice(&(digests.len() as u32).to_le_bytes());
    for digest in digests {
        transcript_bytes.extend_from_slice(&(digest.len() as u32).to_le_bytes());
        transcript_bytes.extend_from_slice(digest);
    }
    serialize_block_accumulation_transcript_v1(&BlockAccumulationTranscriptV1 {
        version: BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1,
        step_count,
        transcript_bytes,
    })
}

pub fn prove_block_recursive_v1(
    input: &BlockRecursiveProverInputV1,
) -> Result<RecursiveBlockArtifactV1, BlockRecursionError> {
    if input.records.is_empty() {
        return Err(BlockRecursionError::InvalidField(
            "recursive block requires at least one verified leaf record",
        ));
    }

    let public = public_replay_v1(&input.records, &input.semantic)?;
    let params = native_backend_params();
    let backend = recursive_backend_v2(params.clone());
    let shape = recursive_block_shape_v1();
    let security = params.security_params();
    let (pk, _vk) = backend
        .setup_recursive(&security, &shape)
        .map_err(|err| static_error("recursive setup failed", err))?;
    ensure_expected_relation_v1(recursive_block_relation_id_v1())?;
    ensure_expected_shape_v1(pk.shape_digest)?;
    let relation_id = recursive_block_relation_id_v1();
    let decider_profile = backend
        .recursive_decider_profile(&security, &shape)
        .map_err(|err| static_error("recursive decider profile failed", err))?;
    let decider_profile_bytes = serialize_decider_profile(&decider_profile)
        .map_err(|err| static_error("serialize decider profile failed", err))?;

    let first_prefix_public = public_replay_v1(&input.records[..1], &input.semantic)?;
    let first_prefix_statement = prefix_statement_v1(&first_prefix_public);
    let first_prefix_packed =
        pack_statement_witness_v1(BlockStatementKindV1::Prefix, &first_prefix_statement)?;
    let native_backend = LatticeBackend::new(params.clone());
    let (_, first_prefix_opening) = native_backend
        .commit(&params, &first_prefix_packed)
        .map_err(|err| static_error("commit first prefix failed", err))?;
    let (first_prefix_claim, _) = backend
        .prove_cccs(
            &pk,
            &relation_id,
            &first_prefix_statement,
            &first_prefix_packed,
            &first_prefix_opening,
        )
        .map_err(|err| static_error("prove first prefix CCCS failed", err))?;
    let (mut current_accumulator, first_linearization) = backend
        .reduce_cccs(
            &pk,
            &first_prefix_claim,
            &first_prefix_packed,
            &first_prefix_opening,
        )
        .map_err(|err| static_error("linearize first prefix failed", err))?;
    let mut current_statement = first_prefix_statement;
    let mut current_packed = first_prefix_packed;
    let mut current_opening = first_prefix_opening;
    let mut transcript_digests = vec![first_linearization.proof_digest.to_vec()];

    for step_index in 1..input.records.len() {
        let record = &input.records[step_index];
        let step_statement = leaf_statement_v1(record);
        let step_packed = pack_statement_witness_v1(BlockStatementKindV1::Leaf, &step_statement)?;
        let (_, step_opening) = native_backend
            .commit(&params, &step_packed)
            .map_err(|err| static_error("commit step witness failed", err))?;
        let (step_claim, _) = backend
            .prove_cccs(
                &pk,
                &relation_id,
                &step_statement,
                &step_packed,
                &step_opening,
            )
            .map_err(|err| static_error("prove step CCCS failed", err))?;
        let (linearized_step, linearization_proof) = backend
            .reduce_cccs(&pk, &step_claim, &step_packed, &step_opening)
            .map_err(|err| static_error("linearize step failed", err))?;

        let target_prefix_public =
            public_replay_v1(&input.records[..=step_index], &input.semantic)?;
        let target_prefix_statement = prefix_statement_v1(&target_prefix_public);
        let (high_norm, high_norm_packed, high_norm_opening, fold_proof) = backend
            .fold_lcccs(
                &pk,
                &current_statement,
                &current_accumulator,
                &step_statement,
                &linearized_step,
                &linearization_proof,
                &target_prefix_statement,
                &current_packed,
                &current_opening,
                &step_packed,
                &step_opening,
            )
            .map_err(|err| static_error("fold recursive accumulator failed", err))?;
        let (normalized, normalized_packed, normalized_opening, normalization_proof) = backend
            .normalize_lcccs(
                &pk,
                &target_prefix_statement,
                &high_norm,
                &high_norm_packed,
                &high_norm_opening,
            )
            .map_err(|err| static_error("normalize recursive accumulator failed", err))?;

        transcript_digests.push(linearization_proof.proof_digest.to_vec());
        transcript_digests.push(fold_proof.proof_digest.to_vec());
        transcript_digests.push(normalization_proof.proof_digest.to_vec());

        current_statement = target_prefix_statement;
        current_accumulator = normalized;
        current_packed = normalized_packed;
        current_opening = normalized_opening;
    }

    let transcript_bytes = build_transcript_bytes_v1(public.tx_count, &transcript_digests)?;
    let transcript = canonical_recursive_decider_transcript(transcript_bytes);
    let decider_proof = backend
        .prove_decider(
            &pk,
            &decider_profile,
            &current_statement,
            &current_accumulator,
            &transcript,
        )
        .map_err(|err| static_error("prove recursive decider failed", err))?;
    let accumulator_bytes = serialize_lcccs_instance(&current_accumulator)
        .map_err(|err| static_error("serialize terminal accumulator failed", err))?;
    let decider_bytes = decider_proof
        .to_canonical_bytes()
        .map_err(|err| static_error("serialize decider proof failed", err))?;

    let mut header = HeaderDecStepV1 {
        version: RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
        proof_kind: RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1,
        header_bytes: 0,
        artifact_bytes: 0,
        relation_id: relation_id.0,
        shape_digest: pk.shape_digest.0,
        statement_digest: crate::recursive_block_public_statement_digest_v1(&public),
        decider_profile_digest: decider_profile_digest_v1(&decider_profile_bytes),
        accumulator_serializer_digest: recursive_lcccs_serializer_digest_v1(),
        decider_serializer_digest: recursive_decider_serializer_digest_v1(),
        transcript_digest: compress_transcript_digest_v1(&transcript.transcript_digest),
        accumulator_bytes: accumulator_bytes.len() as u32,
        decider_bytes: decider_bytes.len() as u32,
    };
    header.header_bytes = crate::serialize_header_dec_step_v1(&header)
        .map_err(|err| static_error("serialize recursive header failed", err))?
        .len() as u32;
    let mut inner_artifact = RecursiveBlockInnerArtifactV1 {
        header,
        accumulator_bytes,
        decider_bytes,
    };
    inner_artifact.header.artifact_bytes =
        serialize_recursive_block_inner_artifact_v1(&inner_artifact)
            .map_err(|err| static_error("serialize recursive artifact failed", err))?
            .len() as u32;
    Ok(RecursiveBlockArtifactV1 {
        artifact: inner_artifact,
        public,
    })
}
