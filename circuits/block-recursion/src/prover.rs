use crate::{
    artifacts::{
        recursive_block_proof_encoding_digest_v1, recursive_block_tx_line_digest_v1,
        HeaderRecStepV1, RecursiveBlockArtifactV1, RecursiveBlockInnerArtifactV1,
        RECURSIVE_BLOCK_ARTIFACT_VERSION_V1, RECURSIVE_BLOCK_PROOF_BYTES_V1,
    },
    public_replay::{
        canonical_receipt_record_bytes_v1, canonical_verified_leaf_record_bytes_v1,
        fold_verified_record_commitments_v1, public_replay_v1, BlockLeafRecordV1,
        BlockSemanticInputsV1,
    },
    relation::{
        hosted_base_binding_bytes_v1, hosted_recursive_descriptor_v1,
        hosted_step_binding_bytes_v1, BaseARelationV1, HostedRecursiveProofContextV1,
        StepARelationV1, StepBRelationV1, recursive_block_shape_digest_v1,
    },
    statement::{
        recursive_prefix_base_statement_v1, recursive_prefix_progress_tree_commitment_v1,
        recursive_prefix_statement_digest32_v1, recursive_prefix_statement_from_parts_v1,
        recursive_prefix_statement_from_public_v1, RecursivePrefixStatementV1,
    },
    BlockRecursionError,
};
use transaction_circuit::{
    encode_smallwood_recursive_proof_envelope_v1, prove_recursive_statement_v1,
    recursive_profile_a_v1, recursive_profile_b_v1, SmallwoodRecursiveProfileTagV1,
    SmallwoodRecursiveProofEnvelopeV1, SmallwoodRecursiveRelationKindV1,
};
use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecursiveProverInputV1 {
    pub records: Vec<BlockLeafRecordV1>,
    pub semantic: BlockSemanticInputsV1,
}

fn static_error(prefix: &'static str, err: impl core::fmt::Display) -> BlockRecursionError {
    BlockRecursionError::InvalidField(Box::leak(format!("{prefix}: {err}").into_boxed_str()))
}

fn prefix_record_commitments_v1(records: &[BlockLeafRecordV1]) -> ([u8; 48], [u8; 48]) {
    if records.is_empty() {
        return ([0u8; 48], [0u8; 48]);
    }
    let leaf_chunks = records
        .iter()
        .map(canonical_verified_leaf_record_bytes_v1)
        .collect::<Vec<_>>();
    let receipt_chunks = records
        .iter()
        .map(canonical_receipt_record_bytes_v1)
        .collect::<Vec<_>>();
    let leaf_refs = leaf_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let receipt_refs = receipt_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    fold_verified_record_commitments_v1(&leaf_refs, &receipt_refs)
}

fn prefix_statement_for_records_v1(
    records: &[BlockLeafRecordV1],
    semantic: &BlockSemanticInputsV1,
    terminal: bool,
) -> RecursivePrefixStatementV1 {
    if records.is_empty() {
        return recursive_prefix_base_statement_v1(semantic);
    }
    let (verified_leaf_commitment, verified_receipt_commitment) =
        prefix_record_commitments_v1(records);
    let tx_count = records.len() as u32;
    let end_tree_commitment = if terminal {
        semantic.end_tree_commitment
    } else {
        recursive_prefix_progress_tree_commitment_v1(
            tx_count,
            semantic.start_tree_commitment,
            verified_leaf_commitment,
            verified_receipt_commitment,
        )
    };
    recursive_prefix_statement_from_parts_v1(
        tx_count,
        semantic.tx_statements_commitment,
        verified_leaf_commitment,
        verified_receipt_commitment,
        semantic.start_tree_commitment,
        end_tree_commitment,
    )
}

fn prove_base_context_v1(
    statement: &RecursivePrefixStatementV1,
) -> Result<HostedRecursiveProofContextV1, BlockRecursionError> {
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .map_err(|err| static_error("prove base recursive statement failed", err))?;
    let proof_envelope_bytes = encode_smallwood_recursive_proof_envelope_v1(
        &SmallwoodRecursiveProofEnvelopeV1 {
            descriptor,
            proof_bytes: proof,
        },
    )
    .map_err(|err| static_error("encode base recursive proof envelope failed", err))?;
    Ok(HostedRecursiveProofContextV1::BaseA {
        statement: statement.clone(),
        proof_envelope_bytes,
    })
}

fn prove_step_context_v1(
    previous_recursive_proof: HostedRecursiveProofContextV1,
    previous_statement: &RecursivePrefixStatementV1,
    leaf_record: &BlockLeafRecordV1,
    target_statement: &RecursivePrefixStatementV1,
    step_index: usize,
) -> Result<(HostedRecursiveProofContextV1, Vec<u8>), BlockRecursionError> {
    if step_index == 0 {
        return Err(BlockRecursionError::InvalidField(
            "recursive step index must be nonzero",
        ));
    }
    if step_index % 2 == 1 {
        let relation = StepBRelationV1::new(
            previous_recursive_proof.clone(),
            previous_statement.clone(),
            leaf_record.clone(),
            target_statement.clone(),
        )
        .map_err(|err| static_error("construct StepB relation failed", err))?;
        let descriptor = hosted_recursive_descriptor_v1(
            SmallwoodRecursiveProfileTagV1::B,
            SmallwoodRecursiveRelationKindV1::StepB,
        );
        let binding = hosted_step_binding_bytes_v1(target_statement);
        let proof = prove_recursive_statement_v1(
            &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
            &descriptor,
            &relation,
            relation.fixed_witness_words(),
            &binding,
        )
        .map_err(|err| static_error("prove StepB recursive statement failed", err))?;
        let proof_envelope_bytes = encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof.clone(),
            },
        )
        .map_err(|err| static_error("encode StepB recursive proof envelope failed", err))?;
        Ok((
            HostedRecursiveProofContextV1::StepB {
                previous_recursive_proof: Box::new(previous_recursive_proof),
                previous_statement: previous_statement.clone(),
                leaf_record: leaf_record.clone(),
                target_statement: target_statement.clone(),
                proof_envelope_bytes,
            },
            proof,
        ))
    } else {
        let relation = StepARelationV1::new(
            previous_recursive_proof.clone(),
            previous_statement.clone(),
            leaf_record.clone(),
            target_statement.clone(),
        )
        .map_err(|err| static_error("construct StepA relation failed", err))?;
        let descriptor = hosted_recursive_descriptor_v1(
            SmallwoodRecursiveProfileTagV1::A,
            SmallwoodRecursiveRelationKindV1::StepA,
        );
        let binding = hosted_step_binding_bytes_v1(target_statement);
        let proof = prove_recursive_statement_v1(
            &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
            &descriptor,
            &relation,
            relation.fixed_witness_words(),
            &binding,
        )
        .map_err(|err| static_error("prove StepA recursive statement failed", err))?;
        let proof_envelope_bytes = encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof.clone(),
            },
        )
        .map_err(|err| static_error("encode StepA recursive proof envelope failed", err))?;
        Ok((
            HostedRecursiveProofContextV1::StepA {
                previous_recursive_proof: Box::new(previous_recursive_proof),
                previous_statement: previous_statement.clone(),
                leaf_record: leaf_record.clone(),
                target_statement: target_statement.clone(),
                proof_envelope_bytes,
            },
            proof,
        ))
    }
}

fn terminal_profile_tag_v1(tx_count: u32) -> SmallwoodRecursiveProfileTagV1 {
    if tx_count % 2 == 0 {
        SmallwoodRecursiveProfileTagV1::A
    } else {
        SmallwoodRecursiveProfileTagV1::B
    }
}

fn terminal_relation_kind_v1(tx_count: u32) -> SmallwoodRecursiveRelationKindV1 {
    if tx_count % 2 == 0 {
        SmallwoodRecursiveRelationKindV1::StepA
    } else {
        SmallwoodRecursiveRelationKindV1::StepB
    }
}

fn build_header_rec_step_v1(
    terminal_statement: &RecursivePrefixStatementV1,
    tx_count: u32,
) -> HeaderRecStepV1 {
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
    HeaderRecStepV1 {
        artifact_version_rec: RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
        tx_line_digest_v1: recursive_block_tx_line_digest_v1(),
        rec_profile_tag_tau: terminal_profile_tag_v1(tx_count).tag(),
        terminal_relation_kind_k: terminal_relation_kind_v1(tx_count).tag(),
        relation_id_base_a: base_descriptor.relation_id,
        relation_id_step_a: step_a_descriptor.relation_id,
        relation_id_step_b: step_b_descriptor.relation_id,
        shape_digest_rec: recursive_block_shape_digest_v1().0,
        vk_digest_base_a: base_descriptor.vk_digest,
        vk_digest_step_a: step_a_descriptor.vk_digest,
        vk_digest_step_b: step_b_descriptor.vk_digest,
        proof_encoding_digest_rec: recursive_block_proof_encoding_digest_v1(),
        proof_bytes_rec: RECURSIVE_BLOCK_PROOF_BYTES_V1 as u32,
        statement_digest_rec: recursive_prefix_statement_digest32_v1(terminal_statement),
    }
}

fn pad_terminal_proof_bytes_v1(proof_bytes: Vec<u8>) -> Result<Vec<u8>, BlockRecursionError> {
    if proof_bytes.len() > RECURSIVE_BLOCK_PROOF_BYTES_V1 {
        return Err(BlockRecursionError::WidthMismatch {
            what: "proof_bytes_rec",
            expected: RECURSIVE_BLOCK_PROOF_BYTES_V1,
            actual: proof_bytes.len(),
        });
    }
    if proof_bytes.len() == RECURSIVE_BLOCK_PROOF_BYTES_V1 {
        return Ok(proof_bytes);
    }
    let mut padded = Vec::with_capacity(RECURSIVE_BLOCK_PROOF_BYTES_V1);
    padded.extend_from_slice(&proof_bytes);
    padded.resize(RECURSIVE_BLOCK_PROOF_BYTES_V1, 0u8);
    Ok(padded)
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
    let terminal_statement = recursive_prefix_statement_from_public_v1(&public);
    let base_statement = recursive_prefix_base_statement_v1(&input.semantic);
    let mut current_context = prove_base_context_v1(&base_statement)?;
    let mut current_statement = base_statement.clone();
    let mut terminal_proof_bytes = None;

    for (index, record) in input.records.iter().enumerate() {
        let prefix_records = &input.records[..=index];
        let target_statement = if index + 1 == input.records.len() {
            terminal_statement.clone()
        } else {
            prefix_statement_for_records_v1(prefix_records, &input.semantic, false)
        };
        let (next_context, proof_bytes) = prove_step_context_v1(
            current_context,
            &current_statement,
            record,
            &target_statement,
            index + 1,
        )?;
        current_context = next_context;
        current_statement = target_statement;
        terminal_proof_bytes = Some(proof_bytes);
    }

    if current_statement != terminal_statement {
        return Err(BlockRecursionError::InvalidField(
            "terminal recursive statement mismatch",
        ));
    }

    let proof_bytes = terminal_proof_bytes.ok_or(BlockRecursionError::InvalidField(
        "missing terminal recursive proof bytes",
    ))?;
    let proof_bytes = pad_terminal_proof_bytes_v1(proof_bytes)?;
    let artifact = RecursiveBlockInnerArtifactV1 {
        header: build_header_rec_step_v1(&terminal_statement, public.tx_count),
        proof_bytes,
    };
    Ok(RecursiveBlockArtifactV1 { artifact, public })
}
