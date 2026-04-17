use std::sync::OnceLock;

use crate::local_smallwood_poseidon2::SmallwoodConfig as LocalSmallwoodConfig;
use crate::relation::{
    debug_step_witness_validation_from_words_with_limb_count_v1,
    debug_step_witness_validation_reason_from_words_with_limb_count_v1,
    debug_step_witness_validation_v1,
};

use super::{
    compose_recursive_segment_statements_v1, deserialize_recursive_block_artifact_v1,
    deserialize_recursive_block_artifact_v2, hosted_base_binding_bytes_v1,
    hosted_recursive_descriptor_v1, hosted_recursive_proof_witness_layout_v1,
    hosted_recursive_proof_witness_words_v1, hosted_step_binding_bytes_v1,
    prefix_statement_for_records_v1, previous_proof_rows_for_limbs_v1, prove_block_recursive_v1,
    prove_block_recursive_v2, public_replay_v1, public_replay_v2,
    recursive_block_artifact_bytes_v2, recursive_block_artifact_verifier_profile_v2,
    segment_statement_for_interval_v1, serialize_recursive_block_artifact_v1,
    serialize_recursive_block_artifact_v2, serialize_recursive_block_public_v1,
    step_recursive_witness_layout_v1, step_recursive_witness_words_v1, tree_proof_cap_report_v2,
    tree_witness_geometry_report_v2,
    verify_block_recursive_v1, verify_block_recursive_v2,
    verify_hosted_recursive_proof_context_binding_trace_v1,
    verify_hosted_recursive_proof_context_components_v1,
    verify_hosted_recursive_proof_context_decs_merkle_v1,
    verify_hosted_recursive_proof_context_descriptor_shape_v1,
    verify_hosted_recursive_proof_context_pcs_v1, verify_recursive_proof_envelope_components_v1,
    BaseARelationV1, BlockLeafRecordV1, BlockRecursionError, BlockRecursiveProverInputV1,
    BlockRecursiveProverInputV2, BlockSemanticInputsV1, HostedRecursiveProofContextV1,
    RecursiveBlockArtifactV1, RecursiveBlockArtifactV2, RecursiveBlockPublicV1,
    RecursiveBlockPublicV2, RecursivePrefixStatementV1, RecursiveSegmentStatementV1,
    StepARelationV1, StepBRelationV1, RECURSIVE_BLOCK_HEADER_BYTES_V1,
    RECURSIVE_BLOCK_PROOF_BYTES_V1, RECURSIVE_BLOCK_PUBLIC_BYTES_V1,
    TREE_RECURSIVE_CHUNK_SIZE_V2,
};
use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;
use transaction_circuit::{
    decode_smallwood_proof_trace_v1, decode_smallwood_recursive_proof_envelope_v1,
    encode_smallwood_recursive_proof_envelope_v1, projected_smallwood_recursive_proof_bytes_v1,
    prove_recursive_statement_v1, recursive_profile_a_v1, recursive_profile_b_v1,
    verify_recursive_statement_v1, SmallwoodArithmetization, SmallwoodConstraintAdapter,
    SmallwoodLinearConstraintForm, SmallwoodNonlinearEvalView, SmallwoodRecursiveProfileTagV1,
    SmallwoodRecursiveProofEnvelopeV1, SmallwoodRecursiveRelationKindV1, TransactionCircuitError,
};

fn digest32(tag: u8, idx: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (offset, byte) in out.iter_mut().enumerate() {
        *byte = tag
            .wrapping_add(idx as u8)
            .wrapping_add((offset as u8).wrapping_mul(3));
    }
    out
}

fn digest48(tag: u8, idx: u32) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (offset, byte) in out.iter_mut().enumerate() {
        *byte = tag
            .wrapping_add(idx as u8)
            .wrapping_add((offset as u8).wrapping_mul(5));
    }
    out
}

struct FakeIdentityWitnessStatement {
    row_count: usize,
    packing_factor: usize,
    linear_offsets: Vec<u32>,
    linear_indices: Vec<u32>,
    linear_coefficients: Vec<u64>,
    linear_targets: Vec<u64>,
}

impl SmallwoodConstraintAdapter for FakeIdentityWitnessStatement {
    fn arithmetization(&self) -> SmallwoodArithmetization {
        SmallwoodArithmetization::Bridge64V1
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn packing_factor(&self) -> usize {
        self.packing_factor
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn linear_constraint_count(&self) -> usize {
        self.linear_targets.len()
    }

    fn constraint_count(&self) -> usize {
        1
    }

    fn linear_constraint_offsets(&self) -> &[u32] {
        &self.linear_offsets
    }

    fn linear_constraint_indices(&self) -> &[u32] {
        &self.linear_indices
    }

    fn linear_constraint_coefficients(&self) -> &[u64] {
        &self.linear_coefficients
    }

    fn linear_targets(&self) -> &[u64] {
        &self.linear_targets
    }

    fn auxiliary_witness_words(&self) -> &[u64] {
        &[]
    }

    fn auxiliary_witness_limb_count(&self) -> Option<usize> {
        None
    }

    fn linear_constraint_form(&self) -> SmallwoodLinearConstraintForm {
        SmallwoodLinearConstraintForm::IdentityWitness
    }

    fn nonlinear_eval_view<'a>(
        &self,
        eval_point: u64,
        rows: &'a [u64],
        auxiliary_words: &'a [u64],
    ) -> SmallwoodNonlinearEvalView<'a> {
        SmallwoodNonlinearEvalView::RowScalars {
            eval_point,
            rows,
            auxiliary_words,
        }
    }

    fn compute_constraints_u64(
        &self,
        _view: SmallwoodNonlinearEvalView<'_>,
        out: &mut [u64],
    ) -> Result<(), TransactionCircuitError> {
        out[0] = 0;
        Ok(())
    }
}

fn sample_input(tx_count: u32) -> BlockRecursiveProverInputV1 {
    let records = (0..tx_count)
        .map(|tx_index| BlockLeafRecordV1 {
            tx_index,
            receipt_statement_hash: digest48(0x10, tx_index),
            receipt_proof_digest: digest48(0x20, tx_index),
            receipt_public_inputs_digest: digest48(0x30, tx_index),
            receipt_verifier_profile: digest48(0x40, tx_index),
            leaf_params_fingerprint: digest48(0x50, tx_index),
            leaf_spec_digest: digest32(0x60, tx_index),
            leaf_relation_id: digest32(0x70, tx_index),
            leaf_shape_digest: digest32(0x80, tx_index),
            leaf_statement_digest: digest48(0x90, tx_index),
            leaf_commitment_digest: digest48(0xa0, tx_index),
            leaf_proof_digest: digest48(0xb0, tx_index),
        })
        .collect();
    BlockRecursiveProverInputV1 {
        records,
        semantic: BlockSemanticInputsV1 {
            tx_statements_commitment: digest48(0xc0, tx_count),
            start_shielded_root: digest48(0xd0, 0),
            end_shielded_root: digest48(0xd1, tx_count),
            start_kernel_root: digest48(0xe0, 0),
            end_kernel_root: digest48(0xe1, tx_count),
            nullifier_root: digest48(0xf0, tx_count),
            da_root: digest48(0xf8, tx_count),
            start_tree_commitment: digest48(0xa8, 0),
            end_tree_commitment: digest48(0xa9, tx_count),
        },
    }
}

fn prove_artifact_uncached(tx_count: u32) -> (RecursiveBlockArtifactV1, RecursiveBlockPublicV1) {
    let input = sample_input(tx_count);
    let public = public_replay_v1(&input.records, &input.semantic).unwrap();
    let artifact = prove_block_recursive_v1(&input).unwrap();
    assert_eq!(artifact.public, public);
    (artifact, public)
}

fn prove_artifact(tx_count: u32) -> (RecursiveBlockArtifactV1, RecursiveBlockPublicV1) {
    static ONE_TX: OnceLock<(RecursiveBlockArtifactV1, RecursiveBlockPublicV1)> = OnceLock::new();
    static TWO_TX: OnceLock<(RecursiveBlockArtifactV1, RecursiveBlockPublicV1)> = OnceLock::new();
    static FIVE_TX: OnceLock<(RecursiveBlockArtifactV1, RecursiveBlockPublicV1)> = OnceLock::new();

    match tx_count {
        1 => ONE_TX.get_or_init(|| prove_artifact_uncached(1)).clone(),
        2 => TWO_TX.get_or_init(|| prove_artifact_uncached(2)).clone(),
        5 => FIVE_TX.get_or_init(|| prove_artifact_uncached(5)).clone(),
        _ => prove_artifact_uncached(tx_count),
    }
}

fn cached_two_tx_artifact() -> (RecursiveBlockArtifactV1, RecursiveBlockPublicV1) {
    prove_artifact(2)
}

fn prove_artifact_v2_uncached(tx_count: u32) -> (RecursiveBlockArtifactV2, RecursiveBlockPublicV2) {
    let input = sample_input(tx_count);
    let public = public_replay_v2(&input.records, &input.semantic).unwrap();
    let artifact = prove_block_recursive_v2(&BlockRecursiveProverInputV2 {
        records: input.records.clone(),
        semantic: input.semantic.clone(),
    })
    .unwrap();
    assert_eq!(artifact.public, public);
    (artifact, public)
}

fn prove_artifact_v2(tx_count: u32) -> (RecursiveBlockArtifactV2, RecursiveBlockPublicV2) {
    static ONE_TX: OnceLock<(RecursiveBlockArtifactV2, RecursiveBlockPublicV2)> = OnceLock::new();
    static FIVE_TX: OnceLock<(RecursiveBlockArtifactV2, RecursiveBlockPublicV2)> = OnceLock::new();
    static THIRTY_TWO_TX: OnceLock<(RecursiveBlockArtifactV2, RecursiveBlockPublicV2)> =
        OnceLock::new();
    static THIRTY_THREE_TX: OnceLock<(RecursiveBlockArtifactV2, RecursiveBlockPublicV2)> =
        OnceLock::new();

    match tx_count {
        1 => ONE_TX.get_or_init(|| prove_artifact_v2_uncached(1)).clone(),
        5 => FIVE_TX
            .get_or_init(|| prove_artifact_v2_uncached(5))
            .clone(),
        32 => THIRTY_TWO_TX
            .get_or_init(|| prove_artifact_v2_uncached(32))
            .clone(),
        33 => THIRTY_THREE_TX
            .get_or_init(|| prove_artifact_v2_uncached(33))
            .clone(),
        _ => prove_artifact_v2_uncached(tx_count),
    }
}

fn base_prefix_statement() -> RecursivePrefixStatementV1 {
    RecursivePrefixStatementV1 {
        tx_count: 0,
        start_state_digest: digest48(0x01, 0),
        end_state_digest: digest48(0x01, 0),
        verified_leaf_commitment: [0u8; 48],
        tx_statements_commitment: digest48(0x02, 0),
        verified_receipt_commitment: [0u8; 48],
        start_tree_commitment: digest48(0x03, 0),
        end_tree_commitment: digest48(0x03, 0),
    }
}

fn sample_leaf_record(tx_index: u32) -> BlockLeafRecordV1 {
    BlockLeafRecordV1 {
        tx_index,
        receipt_statement_hash: digest48(0x10, tx_index),
        receipt_proof_digest: digest48(0x20, tx_index),
        receipt_public_inputs_digest: digest48(0x30, tx_index),
        receipt_verifier_profile: digest48(0x40, tx_index),
        leaf_params_fingerprint: digest48(0x50, tx_index),
        leaf_spec_digest: digest32(0x60, tx_index),
        leaf_relation_id: digest32(0x70, tx_index),
        leaf_shape_digest: digest32(0x80, tx_index),
        leaf_statement_digest: digest48(0x90, tx_index),
        leaf_commitment_digest: digest48(0xa0, tx_index),
        leaf_proof_digest: digest48(0xb0, tx_index),
    }
}

fn step_statement_pair() -> (
    RecursivePrefixStatementV1,
    BlockLeafRecordV1,
    RecursivePrefixStatementV1,
) {
    let previous = base_prefix_statement();
    let leaf = sample_leaf_record(previous.tx_count);
    let target = RecursivePrefixStatementV1 {
        tx_count: previous.tx_count + 1,
        start_state_digest: previous.start_state_digest,
        end_state_digest: digest48(0x11, 1),
        verified_leaf_commitment: digest48(0x12, 1),
        tx_statements_commitment: previous.tx_statements_commitment,
        verified_receipt_commitment: digest48(0x13, 1),
        start_tree_commitment: previous.start_tree_commitment,
        end_tree_commitment: digest48(0x14, 1),
    };
    (previous, leaf, target)
}

fn compose_segment_chain_v1(
    segments: &[RecursiveSegmentStatementV1],
) -> Result<RecursiveSegmentStatementV1, BlockRecursionError> {
    let mut iter = segments.iter();
    let mut acc = iter
        .next()
        .cloned()
        .ok_or(BlockRecursionError::ComposeCheckFailed(
            "empty segment chain",
        ))?;
    for segment in iter {
        acc = compose_recursive_segment_statements_v1(&acc, segment)?;
    }
    Ok(acc)
}

fn base_a_context_v1() -> HostedRecursiveProofContextV1 {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .unwrap();
    HostedRecursiveProofContextV1::BaseA {
        statement,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof,
            },
        )
        .unwrap(),
    }
}

fn step_b_context_from_base_context_v1(
    base_context: HostedRecursiveProofContextV1,
) -> (
    HostedRecursiveProofContextV1,
    RecursivePrefixStatementV1,
    BlockLeafRecordV1,
    RecursivePrefixStatementV1,
) {
    let (previous, leaf, target) = step_statement_pair();
    let relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let binding = hosted_step_binding_bytes_v1(&target);
    let witness = step_recursive_witness_words_v1(&base_context, &previous, &leaf).unwrap();
    let proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &witness,
        &binding,
    )
    .unwrap();
    (
        HostedRecursiveProofContextV1::StepB {
            previous_recursive_proof: Box::new(base_context),
            previous_statement: previous.clone(),
            leaf_record: leaf.clone(),
            target_statement: target.clone(),
            proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
                &SmallwoodRecursiveProofEnvelopeV1 {
                    descriptor,
                    proof_bytes: proof,
                },
            )
            .unwrap(),
        },
        previous,
        leaf,
        target,
    )
}

fn advanced_step_target(
    previous: &RecursivePrefixStatementV1,
    tag_base: u8,
) -> RecursivePrefixStatementV1 {
    RecursivePrefixStatementV1 {
        tx_count: previous.tx_count + 1,
        start_state_digest: previous.start_state_digest,
        end_state_digest: digest48(tag_base, previous.tx_count + 1),
        verified_leaf_commitment: digest48(tag_base.wrapping_add(1), previous.tx_count + 1),
        tx_statements_commitment: previous.tx_statements_commitment,
        verified_receipt_commitment: digest48(tag_base.wrapping_add(2), previous.tx_count + 1),
        start_tree_commitment: previous.start_tree_commitment,
        end_tree_commitment: digest48(tag_base.wrapping_add(3), previous.tx_count + 1),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecursiveBlockV1ProofCapReport {
    base_a_exact_proof_bytes: usize,
    base_a_projected_proof_bytes: usize,
    base_a_envelope_bytes: usize,
    step_b_first_exact_proof_bytes: usize,
    step_b_first_projected_proof_bytes: usize,
    step_b_first_envelope_bytes: usize,
    step_a_exact_proof_bytes: usize,
    step_a_projected_proof_bytes: usize,
    step_a_envelope_bytes: usize,
    step_b_steady_exact_proof_bytes: usize,
    step_b_steady_projected_proof_bytes: usize,
    step_b_steady_envelope_bytes: usize,
    root_projected_proof_cap: usize,
    derived_artifact_bytes: usize,
}

fn recursive_block_v1_proof_cap_report() -> RecursiveBlockV1ProofCapReport {
    let base_statement = base_prefix_statement();
    let base_relation = BaseARelationV1::new(base_statement.clone(), base_statement.clone());
    let base_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let base_binding = hosted_base_binding_bytes_v1(&base_statement);
    let base_projected = projected_smallwood_recursive_proof_bytes_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &base_relation,
    )
    .unwrap();
    let base_proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &base_descriptor,
        &base_relation,
        &[0u64; 64],
        &base_binding,
    )
    .unwrap();
    let base_context = HostedRecursiveProofContextV1::BaseA {
        statement: base_statement.clone(),
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: base_descriptor,
                proof_bytes: base_proof.clone(),
            },
        )
        .unwrap(),
    };

    let (previous, leaf, target) = step_statement_pair();
    let step_b_first_relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let step_b_first_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let step_b_first_binding = hosted_step_binding_bytes_v1(&target);
    let step_b_first_witness =
        step_recursive_witness_words_v1(&base_context, &previous, &leaf).unwrap();
    let step_b_first_projected = projected_smallwood_recursive_proof_bytes_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_b_first_relation,
    )
    .unwrap();
    let step_b_first_proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_b_first_descriptor,
        &step_b_first_relation,
        &step_b_first_witness,
        &step_b_first_binding,
    )
    .unwrap();
    let step_b_first_context = HostedRecursiveProofContextV1::StepB {
        previous_recursive_proof: Box::new(base_context.clone()),
        previous_statement: previous.clone(),
        leaf_record: leaf.clone(),
        target_statement: target.clone(),
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: step_b_first_descriptor,
                proof_bytes: step_b_first_proof.clone(),
            },
        )
        .unwrap(),
    };

    let next_leaf = sample_leaf_record(target.tx_count);
    let next_target = advanced_step_target(&target, 0x21);
    let step_a_relation = StepARelationV1::new(
        step_b_first_context.clone(),
        target.clone(),
        next_leaf.clone(),
        next_target.clone(),
    )
    .unwrap();
    let step_a_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::StepA,
    );
    let step_a_binding = hosted_step_binding_bytes_v1(&next_target);
    let step_a_witness =
        step_recursive_witness_words_v1(&step_b_first_context, &target, &next_leaf).unwrap();
    let step_a_projected = projected_smallwood_recursive_proof_bytes_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_a_relation,
    )
    .unwrap();
    let step_a_proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_a_descriptor,
        &step_a_relation,
        &step_a_witness,
        &step_a_binding,
    )
    .unwrap();
    let step_a_context = HostedRecursiveProofContextV1::StepA {
        previous_recursive_proof: Box::new(step_b_first_context.clone()),
        previous_statement: target.clone(),
        leaf_record: next_leaf.clone(),
        target_statement: next_target.clone(),
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: step_a_descriptor,
                proof_bytes: step_a_proof.clone(),
            },
        )
        .unwrap(),
    };

    let third_leaf = sample_leaf_record(next_target.tx_count);
    let third_target = advanced_step_target(&next_target, 0x31);
    let step_b_steady_relation = StepBRelationV1::new(
        step_a_context.clone(),
        next_target.clone(),
        third_leaf.clone(),
        third_target.clone(),
    )
    .unwrap();
    let step_b_steady_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let step_b_steady_binding = hosted_step_binding_bytes_v1(&third_target);
    let step_b_steady_witness =
        step_recursive_witness_words_v1(&step_a_context, &next_target, &third_leaf).unwrap();
    let step_b_steady_projected = projected_smallwood_recursive_proof_bytes_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_b_steady_relation,
    )
    .unwrap();
    let step_b_steady_proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_b_steady_descriptor,
        &step_b_steady_relation,
        &step_b_steady_witness,
        &step_b_steady_binding,
    )
    .unwrap();
    let step_b_steady_context = HostedRecursiveProofContextV1::StepB {
        previous_recursive_proof: Box::new(step_a_context.clone()),
        previous_statement: next_target,
        leaf_record: third_leaf,
        target_statement: third_target,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: step_b_steady_descriptor,
                proof_bytes: step_b_steady_proof.clone(),
            },
        )
        .unwrap(),
    };

    let step_b_max = step_b_first_projected.max(step_b_steady_projected);
    let root_projected_proof_cap = step_a_projected.max(step_b_max);

    RecursiveBlockV1ProofCapReport {
        base_a_exact_proof_bytes: base_proof.len(),
        base_a_projected_proof_bytes: base_projected,
        base_a_envelope_bytes: base_context.proof_envelope_bytes().len(),
        step_b_first_exact_proof_bytes: step_b_first_proof.len(),
        step_b_first_projected_proof_bytes: step_b_first_projected,
        step_b_first_envelope_bytes: step_b_first_context.proof_envelope_bytes().len(),
        step_a_exact_proof_bytes: step_a_proof.len(),
        step_a_projected_proof_bytes: step_a_projected,
        step_a_envelope_bytes: step_a_context.proof_envelope_bytes().len(),
        step_b_steady_exact_proof_bytes: step_b_steady_proof.len(),
        step_b_steady_projected_proof_bytes: step_b_steady_projected,
        step_b_steady_envelope_bytes: step_b_steady_context.proof_envelope_bytes().len(),
        root_projected_proof_cap,
        derived_artifact_bytes: RECURSIVE_BLOCK_HEADER_BYTES_V1
            + RECURSIVE_BLOCK_PUBLIC_BYTES_V1
            + root_projected_proof_cap,
    }
}

fn tamper_base_context_proof_bytes_in_range_v1<F>(
    context: &HostedRecursiveProofContextV1,
    start_numer: usize,
    end_numer: usize,
    denom: usize,
    verifier: F,
) -> HostedRecursiveProofContextV1
where
    F: Fn(&HostedRecursiveProofContextV1) -> Result<(), TransactionCircuitError>,
{
    let HostedRecursiveProofContextV1::BaseA {
        statement,
        proof_envelope_bytes,
    } = context
    else {
        panic!("expected BaseA context");
    };
    let envelope = decode_smallwood_recursive_proof_envelope_v1(proof_envelope_bytes).unwrap();
    let proof_len = envelope.proof_bytes.len();
    let start = proof_len.saturating_mul(start_numer) / denom;
    let end = proof_len.saturating_mul(end_numer) / denom;
    let start = start.min(proof_len.saturating_sub(1));
    let end = end.max(start + 1).min(proof_len);
    for idx in start..end {
        for bit in [1u8, 2, 4, 8, 16, 32, 64, 128] {
            let mut tampered = envelope.clone();
            tampered.proof_bytes[idx] ^= bit;
            let candidate = HostedRecursiveProofContextV1::BaseA {
                statement: statement.clone(),
                proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(&tampered)
                    .unwrap(),
            };
            if verifier(&candidate).is_err() {
                return candidate;
            }
        }
    }
    panic!("failed to find a tampered proof byte in the requested region");
}

fn tamper_step_b_context_proof_bytes_in_range_v1<F>(
    context: &HostedRecursiveProofContextV1,
    start_numer: usize,
    end_numer: usize,
    denom: usize,
    verifier: F,
) -> HostedRecursiveProofContextV1
where
    F: Fn(&HostedRecursiveProofContextV1) -> Result<(), TransactionCircuitError>,
{
    let HostedRecursiveProofContextV1::StepB {
        previous_recursive_proof,
        previous_statement,
        leaf_record,
        target_statement,
        proof_envelope_bytes,
    } = context
    else {
        panic!("expected StepB context");
    };
    let envelope = decode_smallwood_recursive_proof_envelope_v1(proof_envelope_bytes).unwrap();
    let proof_len = envelope.proof_bytes.len();
    let start = proof_len.saturating_mul(start_numer) / denom;
    let end = proof_len.saturating_mul(end_numer) / denom;
    let start = start.min(proof_len.saturating_sub(1));
    let end = end.max(start + 1).min(proof_len);
    for idx in start..end {
        for bit in [1u8, 2, 4, 8, 16, 32, 64, 128] {
            let mut tampered = envelope.clone();
            tampered.proof_bytes[idx] ^= bit;
            let candidate = HostedRecursiveProofContextV1::StepB {
                previous_recursive_proof: previous_recursive_proof.clone(),
                previous_statement: previous_statement.clone(),
                leaf_record: leaf_record.clone(),
                target_statement: target_statement.clone(),
                proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(&tampered)
                    .unwrap(),
            };
            if verifier(&candidate).is_err() {
                return candidate;
            }
        }
    }
    panic!("failed to find a tampered StepB proof byte in the requested region");
}

#[test]
fn public_replay_matches_semantic_tuple() {
    let input = sample_input(3);
    let public = public_replay_v1(&input.records, &input.semantic).unwrap();
    assert_eq!(public.tx_count, 3);
    assert_eq!(
        public.tx_statements_commitment,
        input.semantic.tx_statements_commitment
    );
    assert_eq!(
        public.start_shielded_root,
        input.semantic.start_shielded_root
    );
    assert_eq!(public.end_shielded_root, input.semantic.end_shielded_root);
    assert_eq!(public.start_kernel_root, input.semantic.start_kernel_root);
    assert_eq!(public.end_kernel_root, input.semantic.end_kernel_root);
    assert_eq!(public.nullifier_root, input.semantic.nullifier_root);
    assert_eq!(public.da_root, input.semantic.da_root);
    assert_eq!(
        public.start_tree_commitment,
        input.semantic.start_tree_commitment
    );
    assert_eq!(
        public.end_tree_commitment,
        input.semantic.end_tree_commitment
    );
    assert_eq!(serialize_recursive_block_public_v1(&public).len(), 532);
}

#[test]
fn segment_statement_matches_direct_full_interval_replay() {
    let input = sample_input(5);
    let left = segment_statement_for_interval_v1(&input.records, &input.semantic, 0, 2).unwrap();
    let right = segment_statement_for_interval_v1(&input.records, &input.semantic, 2, 5).unwrap();
    let composed = compose_recursive_segment_statements_v1(&left, &right).unwrap();
    let direct = segment_statement_for_interval_v1(&input.records, &input.semantic, 0, 5).unwrap();
    assert_eq!(composed, direct);
    assert_eq!(direct.segment_len, 5);
    assert_eq!(direct.start_index, 0);
    assert_eq!(direct.end_index, 5);
}

#[test]
fn segment_statement_multi_partition_composition_matches_direct_replay() {
    let input = sample_input(5);
    let segments = vec![
        segment_statement_for_interval_v1(&input.records, &input.semantic, 0, 1).unwrap(),
        segment_statement_for_interval_v1(&input.records, &input.semantic, 1, 3).unwrap(),
        segment_statement_for_interval_v1(&input.records, &input.semantic, 3, 5).unwrap(),
    ];
    let composed = compose_segment_chain_v1(&segments).unwrap();
    let direct = segment_statement_for_interval_v1(&input.records, &input.semantic, 0, 5).unwrap();
    assert_eq!(composed, direct);
}

#[test]
fn segment_statement_rejects_gap() {
    let input = sample_input(5);
    let left = segment_statement_for_interval_v1(&input.records, &input.semantic, 0, 2).unwrap();
    let right = segment_statement_for_interval_v1(&input.records, &input.semantic, 3, 5).unwrap();
    let err = compose_recursive_segment_statements_v1(&left, &right).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::ComposeCheckFailed("segment statements must be adjacent")
    ));
}

#[test]
fn segment_statement_rejects_overlap() {
    let input = sample_input(5);
    let left = segment_statement_for_interval_v1(&input.records, &input.semantic, 0, 3).unwrap();
    let right = segment_statement_for_interval_v1(&input.records, &input.semantic, 2, 5).unwrap();
    let err = compose_recursive_segment_statements_v1(&left, &right).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::ComposeCheckFailed("segment statements must be adjacent")
    ));
}

#[test]
fn segment_statement_rejects_reordered_children() {
    let input = sample_input(5);
    let left = segment_statement_for_interval_v1(&input.records, &input.semantic, 0, 2).unwrap();
    let right = segment_statement_for_interval_v1(&input.records, &input.semantic, 2, 5).unwrap();
    let err = compose_recursive_segment_statements_v1(&right, &left).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::ComposeCheckFailed("segment statements must be adjacent")
    ));
}

#[test]
fn segment_statement_prefix_builder_matches_interval_start_boundary() {
    let input = sample_input(5);
    let prefix =
        prefix_statement_for_records_v1(&input.records[..2], &input.semantic, false).unwrap();
    let segment = segment_statement_for_interval_v1(&input.records, &input.semantic, 2, 5).unwrap();
    assert_eq!(segment.start_index, 2);
    assert_eq!(segment.start_state_digest, prefix.end_state_digest);
    assert_eq!(
        segment.start_verified_leaf_commitment,
        prefix.verified_leaf_commitment
    );
    assert_eq!(
        segment.start_verified_receipt_commitment,
        prefix.verified_receipt_commitment
    );
    assert_eq!(segment.start_tree_commitment, prefix.end_tree_commitment);
}

#[test]
fn prove_and_verify_recursive_artifact_succeeds() {
    let (artifact, public) = cached_two_tx_artifact();
    let verified = verify_block_recursive_v1(&artifact, &public).unwrap();
    assert_eq!(verified, public);
}

#[test]
#[ignore = "diagnostic report: v1 steady-state recursion is not a constant-size shipped path"]
fn recursive_block_v1_proof_cap_report_reveals_steady_state_growth() {
    let report = recursive_block_v1_proof_cap_report();
    eprintln!(
        "recursive_block_v1 cap report: base_a exact/projected={}/{}, step_b_first={}/{}, step_a={}/{}, step_b_steady={}/{}, root_cap={}, artifact_bytes={}",
        report.base_a_exact_proof_bytes,
        report.base_a_projected_proof_bytes,
        report.step_b_first_exact_proof_bytes,
        report.step_b_first_projected_proof_bytes,
        report.step_a_exact_proof_bytes,
        report.step_a_projected_proof_bytes,
        report.step_b_steady_exact_proof_bytes,
        report.step_b_steady_projected_proof_bytes,
        report.root_projected_proof_cap,
        report.derived_artifact_bytes,
    );
    assert!(report.base_a_exact_proof_bytes <= report.base_a_projected_proof_bytes);
    assert!(report.step_b_first_exact_proof_bytes <= report.step_b_first_projected_proof_bytes);
    assert!(report.step_a_exact_proof_bytes <= report.step_a_projected_proof_bytes);
    assert!(report.step_b_steady_exact_proof_bytes <= report.step_b_steady_projected_proof_bytes);
    assert!(
        report.step_a_projected_proof_bytes < RECURSIVE_BLOCK_PROOF_BYTES_V1,
        "first StepA should still fit within the historical v1 container width"
    );
    assert!(
        report.step_b_first_projected_proof_bytes < RECURSIVE_BLOCK_PROOF_BYTES_V1,
        "first StepB should still fit within the historical v1 container width"
    );
    assert!(
        report.step_b_steady_projected_proof_bytes > RECURSIVE_BLOCK_PROOF_BYTES_V1,
        "steady-state StepB should exceed the stale shipped v1 cap if the diagnostic is still relevant"
    );
    assert!(
        report.root_projected_proof_cap > RECURSIVE_BLOCK_PROOF_BYTES_V1,
        "steady-state recursive root cap should exceed the stale shipped v1 artifact width"
    );
    assert_eq!(
        serialize_recursive_block_artifact_v1(&cached_two_tx_artifact().0)
            .unwrap()
            .len(),
        RECURSIVE_BLOCK_HEADER_BYTES_V1
            + RECURSIVE_BLOCK_PUBLIC_BYTES_V1
            + RECURSIVE_BLOCK_PROOF_BYTES_V1
    );
}

#[test]
fn tree_v2_proof_cap_report_is_self_consistent() {
    let report = tree_proof_cap_report_v2();
    let geometry = tree_witness_geometry_report_v2();
    println!(
        "tree_v2 chunk_size={} max_supported_txs={} max_chunk_count={} max_tree_level={} \
         chunk_slot_bytes={} full_chunk_witness_bytes={} merge_summary_bytes={} merge_child_header_bytes={} \
         p_chunk_a={} p_merge_a={} p_merge_b={} p_carry_a={} p_carry_b={} root_proof_cap={} artifact_bytes={}",
        TREE_RECURSIVE_CHUNK_SIZE_V2,
        report.max_supported_txs,
        report.max_chunk_count,
        report.max_tree_level,
        geometry.chunk_slot_bytes,
        geometry.full_chunk_witness_bytes,
        geometry.merge_summary_bytes,
        geometry.merge_child_header_bytes,
        report.p_chunk_a,
        report.p_merge_a,
        report.p_merge_b,
        report.p_carry_a,
        report.p_carry_b,
        report.root_proof_cap,
        recursive_block_artifact_bytes_v2(),
    );
    let expected_max_chunk_count = report
        .max_supported_txs
        .div_ceil(TREE_RECURSIVE_CHUNK_SIZE_V2);
    let mut expected_max_tree_level = 0usize;
    let mut chunk_count = expected_max_chunk_count;
    while chunk_count > 1 {
        expected_max_tree_level += 1;
        chunk_count = chunk_count.div_ceil(2);
    }
    assert_eq!(report.max_supported_txs, 1000);
    assert_eq!(report.max_chunk_count, expected_max_chunk_count);
    assert_eq!(report.max_tree_level, expected_max_tree_level);
    assert_eq!(report.max_tree_level + 1, report.level_caps.len());
    assert!(report.p_chunk_a <= report.root_proof_cap);
    assert!(report.p_merge_a <= report.root_proof_cap);
    assert!(report.p_merge_b <= report.root_proof_cap);
    assert!(report.p_carry_a <= report.root_proof_cap);
    assert!(report.p_carry_b <= report.root_proof_cap);
    assert!(report.root_proof_cap > 0);
    assert!(recursive_block_artifact_bytes_v2() > report.root_proof_cap);
    assert_eq!(
        report.root_proof_cap,
        *report.level_caps.last().expect("tree_v2 root cap"),
    );
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn prove_and_verify_recursive_artifact_v2_succeeds() {
    let (artifact, public) = prove_artifact_v2(5);
    let verified = verify_block_recursive_v2(&artifact, &public).unwrap();
    assert_eq!(verified, public);
    assert_eq!(
        recursive_block_artifact_verifier_profile_v2(),
        recursive_block_artifact_verifier_profile_v2()
    );
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn recursive_artifact_v2_constant_size_across_tx_counts() {
    let short = serialize_recursive_block_artifact_v2(&prove_artifact_v2(1).0)
        .unwrap()
        .len();
    let long = serialize_recursive_block_artifact_v2(&prove_artifact_v2(5).0)
        .unwrap()
        .len();
    assert_eq!(short, long);
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn prove_and_verify_recursive_artifact_v2_at_first_merge_boundary_succeeds() {
    for tx_count in [
        TREE_RECURSIVE_CHUNK_SIZE_V2 as u32,
        (TREE_RECURSIVE_CHUNK_SIZE_V2 + 1) as u32,
    ] {
        let (artifact, public) = prove_artifact_v2(tx_count);
        let verified = verify_block_recursive_v2(&artifact, &public).unwrap();
        assert_eq!(verified, public);
    }
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn recursive_artifact_v2_constant_size_across_first_merge_boundary() {
    let chunk_aligned = serialize_recursive_block_artifact_v2(
        &prove_artifact_v2(TREE_RECURSIVE_CHUNK_SIZE_V2 as u32).0,
    )
    .unwrap()
    .len();
    let first_merged = serialize_recursive_block_artifact_v2(
        &prove_artifact_v2((TREE_RECURSIVE_CHUNK_SIZE_V2 + 1) as u32).0,
    )
    .unwrap()
    .len();
    assert_eq!(chunk_aligned, first_merged);
    assert_eq!(chunk_aligned, recursive_block_artifact_bytes_v2());
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn prove_and_verify_recursive_artifact_v2_across_first_carry_boundary_succeeds() {
    for tx_count in [
        (TREE_RECURSIVE_CHUNK_SIZE_V2 * 2) as u32,
        ((TREE_RECURSIVE_CHUNK_SIZE_V2 * 2) + 1) as u32,
    ] {
        let (artifact, public) = prove_artifact_v2(tx_count);
        let verified = verify_block_recursive_v2(&artifact, &public).unwrap();
        assert_eq!(verified, public);
    }
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn recursive_artifact_v2_constant_size_across_first_carry_boundary() {
    let merge_aligned = serialize_recursive_block_artifact_v2(
        &prove_artifact_v2((TREE_RECURSIVE_CHUNK_SIZE_V2 * 2) as u32).0,
    )
    .unwrap()
    .len();
    let first_carried = serialize_recursive_block_artifact_v2(
        &prove_artifact_v2(((TREE_RECURSIVE_CHUNK_SIZE_V2 * 2) + 1) as u32).0,
    )
    .unwrap()
    .len();
    assert_eq!(merge_aligned, first_carried);
    assert_eq!(merge_aligned, recursive_block_artifact_bytes_v2());
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn prove_and_verify_recursive_artifact_v2_at_deepest_supported_level_succeeds() {
    let report = tree_proof_cap_report_v2();
    let deepest_level_boundary = if report.max_tree_level == 0 {
        1u32
    } else {
        (((1usize << (report.max_tree_level - 1)) * TREE_RECURSIVE_CHUNK_SIZE_V2) + 1) as u32
    };
    assert!(deepest_level_boundary as usize <= report.max_supported_txs);
    let (artifact, public) = prove_artifact_v2(deepest_level_boundary);
    let verified = verify_block_recursive_v2(&artifact, &public).unwrap();
    assert_eq!(verified, public);
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn recursive_artifact_v2_constant_size_at_deepest_supported_level() {
    let report = tree_proof_cap_report_v2();
    let deepest_level_boundary = if report.max_tree_level == 0 {
        1u32
    } else {
        (((1usize << (report.max_tree_level - 1)) * TREE_RECURSIVE_CHUNK_SIZE_V2) + 1) as u32
    };
    assert!(deepest_level_boundary as usize <= report.max_supported_txs);
    let deep_width =
        serialize_recursive_block_artifact_v2(&prove_artifact_v2(deepest_level_boundary).0)
            .unwrap()
            .len();
    let max_width = serialize_recursive_block_artifact_v2(
        &prove_artifact_v2(report.max_supported_txs as u32).0,
    )
    .unwrap()
    .len();
    assert_eq!(deep_width, max_width);
    assert_eq!(deep_width, recursive_block_artifact_bytes_v2());
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn recursive_artifact_v2_matches_derived_constant_width() {
    let width = serialize_recursive_block_artifact_v2(&prove_artifact_v2(1).0)
        .unwrap()
        .len();
    assert_eq!(width, recursive_block_artifact_bytes_v2());
}

#[test]
#[ignore = "tree_v2 is experimental and not on the shipped product lane"]
fn recursive_artifact_v1_and_v2_fail_closed_cross_version() {
    let (artifact_v1, _public_v1) = cached_two_tx_artifact();
    let bytes_v1 = serialize_recursive_block_artifact_v1(&artifact_v1).unwrap();
    let parsed_v2 = deserialize_recursive_block_artifact_v2(&bytes_v1);
    assert!(parsed_v2.is_err());

    let (artifact_v2, _public_v2) = prove_artifact_v2(1);
    let bytes_v2 = serialize_recursive_block_artifact_v2(&artifact_v2).unwrap();
    let parsed_v1 = deserialize_recursive_block_artifact_v1(&bytes_v2);
    assert!(parsed_v1.is_err());
}

#[test]
fn recursive_artifact_roundtrips_and_exact_consumes() {
    let (artifact, _) = cached_two_tx_artifact();
    let bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    let parsed = deserialize_recursive_block_artifact_v1(&bytes).unwrap();
    assert_eq!(parsed, artifact);
    let public_len = serialize_recursive_block_public_v1(&parsed.public).len();
    assert_eq!(
        parsed.artifact.header.proof_bytes_rec as usize + 336,
        bytes.len() - public_len
    );
}

#[test]
fn recursive_artifact_rejects_trailing_bytes() {
    let (artifact, _) = cached_two_tx_artifact();
    let mut bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    bytes.extend_from_slice(&[0xde, 0xad]);
    let err = deserialize_recursive_block_artifact_v1(&bytes).unwrap_err();
    assert!(matches!(err, BlockRecursionError::TrailingBytes { .. }));
}

#[test]
fn recursive_artifact_rejects_width_mismatch() {
    let (mut artifact, _) = cached_two_tx_artifact();
    artifact.artifact.header.proof_bytes_rec =
        artifact.artifact.header.proof_bytes_rec.saturating_add(1);
    let err = serialize_recursive_block_artifact_v1(&artifact).unwrap_err();
    assert!(matches!(err, BlockRecursionError::WidthMismatch { .. }));
}

#[test]
fn recursive_artifact_rejects_tampered_statement_digest() {
    let (mut artifact, public) = cached_two_tx_artifact();
    artifact.artifact.header.statement_digest_rec[0] ^= 1;
    let err = verify_block_recursive_v1(&artifact, &public).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::InvalidField("header_rec_step mismatch")
    ));
}

#[test]
fn recursive_artifact_rejects_nonzero_proof_padding() {
    let (mut artifact, public) = prove_artifact(1);
    let padding_index = artifact.artifact.header.proof_bytes_rec as usize - 1;
    artifact.artifact.proof_bytes[padding_index] ^= 1;
    let err = verify_block_recursive_v1(&artifact, &public).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::InvalidField("proof_bytes_rec padding")
    ));
}

#[test]
fn recursive_artifact_rejects_wrong_expected_public() {
    let (artifact, mut public) = cached_two_tx_artifact();
    public.tx_count += 1;
    let err = verify_block_recursive_v1(&artifact, &public).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::InvalidField("recursive public tuple mismatch")
    ));
}

#[test]
fn recursive_artifact_rejects_alternate_serializer_under_same_profile() {
    let (mut artifact, public) = cached_two_tx_artifact();
    artifact.artifact.proof_bytes[0] ^= 1;
    let err = verify_block_recursive_v1(&artifact, &public).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn proof_bytes_constant_across_tx_counts() {
    let short = serialize_recursive_block_artifact_v1(&prove_artifact(1).0)
        .unwrap()
        .len();
    let long = serialize_recursive_block_artifact_v1(&prove_artifact(2).0)
        .unwrap()
        .len();
    assert_eq!(short, long);
}

#[test]
fn local_smallwood_config_rejects_malformed_identity_witness_metadata() {
    let statement = FakeIdentityWitnessStatement {
        row_count: 1,
        packing_factor: 4,
        linear_offsets: vec![0, 1, 2, 3, 4],
        linear_indices: vec![0, 1, 2, 3],
        linear_coefficients: vec![1, 9, 1, 1],
        linear_targets: vec![10, 11, 12, 13],
    };
    let err = LocalSmallwoodConfig::new(&statement)
        .expect_err("malformed identity-witness metadata unexpectedly accepted");
    assert!(err.to_string().contains("identity witness"));
}

#[test]
fn base_a_relation_proves_and_verifies_on_recursive_smallwood_profile() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .unwrap();
    verify_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &binding,
        &proof,
    )
    .unwrap();
}

#[test]
fn recursive_proof_envelope_component_checks_reject_tampered_envelope() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .unwrap();
    let mut envelope_bytes =
        encode_smallwood_recursive_proof_envelope_v1(&SmallwoodRecursiveProofEnvelopeV1 {
            descriptor,
            proof_bytes: proof,
        })
        .unwrap();
    envelope_bytes[0] ^= 1;
    let err = verify_recursive_proof_envelope_components_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &hosted_recursive_descriptor_v1(
            SmallwoodRecursiveProfileTagV1::A,
            SmallwoodRecursiveRelationKindV1::BaseA,
        ),
        &relation,
        &binding,
        &envelope_bytes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TransactionCircuitError::ConstraintViolation(_)
            | TransactionCircuitError::ConstraintViolationOwned(_)
    ));
}

#[test]
fn recursive_proof_envelope_component_checks_reject_wrong_relation_kind() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .unwrap();
    let mut envelope = SmallwoodRecursiveProofEnvelopeV1 {
        descriptor,
        proof_bytes: proof,
    };
    envelope.descriptor.relation_kind = SmallwoodRecursiveRelationKindV1::StepA;
    let envelope_bytes = encode_smallwood_recursive_proof_envelope_v1(&envelope).unwrap();
    let err = verify_recursive_proof_envelope_components_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &hosted_recursive_descriptor_v1(
            SmallwoodRecursiveProfileTagV1::A,
            SmallwoodRecursiveRelationKindV1::BaseA,
        ),
        &relation,
        &binding,
        &envelope_bytes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope relation kind mismatch"
        )
    ));
}

#[test]
fn previous_proof_layout_matches_trace_len_for_base_envelope() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .unwrap();
    let envelope_bytes =
        encode_smallwood_recursive_proof_envelope_v1(&SmallwoodRecursiveProofEnvelopeV1 {
            descriptor,
            proof_bytes: proof,
        })
        .unwrap();
    let context = HostedRecursiveProofContextV1::BaseA {
        statement,
        proof_envelope_bytes: envelope_bytes,
    };
    let witness_words = hosted_recursive_proof_witness_words_v1(&context).unwrap();
    let expected_limbs = witness_words.len();
    let layout = hosted_recursive_proof_witness_layout_v1(&context).unwrap();
    assert_eq!(layout.total_rows() * layout.row_width, expected_limbs);
    assert_eq!(
        layout.total_rows(),
        previous_proof_rows_for_limbs_v1(layout.total_limbs())
    );
    assert_eq!(
        layout.envelope.limb_start,
        layout.descriptor.limb_start + layout.descriptor.limb_count
    );
    assert_eq!(
        layout.transcript.limb_start,
        layout.envelope.limb_start + layout.envelope.limb_count
    );
    assert_eq!(
        layout.pcs.limb_start,
        layout.transcript.limb_start + layout.transcript.limb_count
    );
    assert_eq!(
        layout.decs.limb_start,
        layout.pcs.limb_start + layout.pcs.limb_count
    );
    assert_eq!(
        layout.merkle.limb_start,
        layout.decs.limb_start + layout.decs.limb_count
    );
}

#[test]
fn step_witness_layout_matches_trace_len_for_base_context() {
    let context = base_a_context_v1();
    let (previous, leaf, _) = step_statement_pair();
    let witness_words = step_recursive_witness_words_v1(&context, &previous, &leaf).unwrap();
    let layout = step_recursive_witness_layout_v1(&context).unwrap();
    assert_eq!(layout.total_rows() * layout.row_width, witness_words.len());
    assert_eq!(
        layout.leaf_record.limb_start,
        layout.previous_statement.limb_start + layout.previous_statement.limb_count
    );
    assert_eq!(
        layout.layout_header.limb_start,
        layout.leaf_record.limb_start + layout.leaf_record.limb_count
    );
    assert_eq!(
        layout.descriptor.limb_start,
        layout.layout_header.limb_start + layout.layout_header.limb_count
    );
    assert_eq!(
        layout.envelope.limb_start,
        layout.descriptor.limb_start + layout.descriptor.limb_count
    );
    assert_eq!(
        layout.merkle.limb_start,
        layout.decs.limb_start + layout.decs.limb_count
    );
}

#[test]
fn hosted_recursive_context_descriptor_shape_checks_reject_wrong_descriptor() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .unwrap();
    let mut envelope = SmallwoodRecursiveProofEnvelopeV1 {
        descriptor,
        proof_bytes: proof,
    };
    envelope.descriptor.shape_digest[0] ^= 1;
    let context = HostedRecursiveProofContextV1::BaseA {
        statement,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(&envelope).unwrap(),
    };
    let err = verify_hosted_recursive_proof_context_descriptor_shape_v1(&context).unwrap_err();
    assert!(matches!(
        err,
        TransactionCircuitError::ConstraintViolation(
            "recursive proof envelope shape digest mismatch"
        )
    ));
}

#[test]
fn hosted_recursive_context_binding_trace_checks_reject_wrong_binding_payload() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 64],
        &binding,
    )
    .unwrap();
    let mut wrong_statement = statement.clone();
    wrong_statement.end_state_digest[0] ^= 1;
    let context = HostedRecursiveProofContextV1::BaseA {
        statement: wrong_statement,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof,
            },
        )
        .unwrap(),
    };
    let err = verify_hosted_recursive_proof_context_binding_trace_v1(&context).unwrap_err();
    assert!(matches!(
        err,
        TransactionCircuitError::ConstraintViolation(_)
            | TransactionCircuitError::ConstraintViolationOwned(_)
    ));
}

#[test]
fn hosted_recursive_context_pcs_checks_reject_tampered_proof_bytes() {
    let context = base_a_context_v1();
    let tampered = tamper_base_context_proof_bytes_in_range_v1(
        &context,
        1,
        2,
        3,
        verify_hosted_recursive_proof_context_pcs_v1,
    );
    let err = verify_hosted_recursive_proof_context_pcs_v1(&tampered).unwrap_err();
    assert!(
        err.to_string().contains("PCS"),
        "unexpected PCS error: {err}"
    );
}

#[test]
fn hosted_recursive_context_decs_merkle_checks_reject_tampered_proof_bytes() {
    let context = base_a_context_v1();
    let tampered = tamper_base_context_proof_bytes_in_range_v1(
        &context,
        2,
        3,
        3,
        verify_hosted_recursive_proof_context_decs_merkle_v1,
    );
    let err = verify_hosted_recursive_proof_context_decs_merkle_v1(&tampered).unwrap_err();
    assert!(
        err.to_string().contains("DECS/Merkle"),
        "unexpected DECS/Merkle error: {err}"
    );
}

#[test]
fn step_b_relation_proves_and_verifies_on_recursive_smallwood_profile() {
    let base_statement = base_prefix_statement();
    let base_relation = BaseARelationV1::new(base_statement.clone(), base_statement.clone());
    let base_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let base_binding = hosted_base_binding_bytes_v1(&base_statement);
    let base_proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &base_descriptor,
        &base_relation,
        &[0u64; 64],
        &base_binding,
    )
    .unwrap();
    let base_envelope_bytes =
        encode_smallwood_recursive_proof_envelope_v1(&SmallwoodRecursiveProofEnvelopeV1 {
            descriptor: base_descriptor.clone(),
            proof_bytes: base_proof,
        })
        .unwrap();
    let base_context = HostedRecursiveProofContextV1::BaseA {
        statement: base_statement.clone(),
        proof_envelope_bytes: base_envelope_bytes,
    };

    let (previous, leaf, target) = step_statement_pair();
    let relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let binding = hosted_step_binding_bytes_v1(&target);
    let witness = step_recursive_witness_words_v1(&base_context, &previous, &leaf).unwrap();
    let proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &witness,
        &binding,
    )
    .unwrap();
    verify_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &binding,
        &proof,
    )
    .unwrap();
    let step_context = HostedRecursiveProofContextV1::StepB {
        previous_recursive_proof: Box::new(base_context),
        previous_statement: previous,
        leaf_record: leaf,
        target_statement: target,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof,
            },
        )
        .unwrap(),
    };
    verify_hosted_recursive_proof_context_components_v1(&step_context).unwrap();
}

#[test]
fn step_a_relation_proves_and_verifies_on_recursive_smallwood_profile() {
    let base_statement = base_prefix_statement();
    let base_relation = BaseARelationV1::new(base_statement.clone(), base_statement.clone());
    let base_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let base_binding = hosted_base_binding_bytes_v1(&base_statement);
    let base_proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &base_descriptor,
        &base_relation,
        &[0u64; 64],
        &base_binding,
    )
    .unwrap();
    let base_context = HostedRecursiveProofContextV1::BaseA {
        statement: base_statement.clone(),
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: base_descriptor.clone(),
                proof_bytes: base_proof,
            },
        )
        .unwrap(),
    };
    let (previous, leaf, target) = step_statement_pair();
    let step_b_relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let step_b_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let step_b_binding = hosted_step_binding_bytes_v1(&target);
    let step_b_witness = step_recursive_witness_words_v1(&base_context, &previous, &leaf).unwrap();
    let step_b_proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_b_descriptor,
        &step_b_relation,
        &step_b_witness,
        &step_b_binding,
    )
    .unwrap();
    let step_b_context = HostedRecursiveProofContextV1::StepB {
        previous_recursive_proof: Box::new(base_context),
        previous_statement: previous.clone(),
        leaf_record: leaf.clone(),
        target_statement: target.clone(),
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: step_b_descriptor,
                proof_bytes: step_b_proof,
            },
        )
        .unwrap(),
    };

    let next_leaf = sample_leaf_record(target.tx_count);
    let next_target = RecursivePrefixStatementV1 {
        tx_count: target.tx_count + 1,
        start_state_digest: target.start_state_digest,
        end_state_digest: digest48(0x21, 2),
        verified_leaf_commitment: digest48(0x22, 2),
        tx_statements_commitment: target.tx_statements_commitment,
        verified_receipt_commitment: digest48(0x23, 2),
        start_tree_commitment: target.start_tree_commitment,
        end_tree_commitment: digest48(0x24, 2),
    };
    let relation = StepARelationV1::new(
        step_b_context.clone(),
        target.clone(),
        next_leaf.clone(),
        next_target.clone(),
    )
    .unwrap();
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::StepA,
    );
    let binding = hosted_step_binding_bytes_v1(&next_target);
    let witness = step_recursive_witness_words_v1(&step_b_context, &target, &next_leaf).unwrap();
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &witness,
        &binding,
    )
    .unwrap();
    let step_a_context = HostedRecursiveProofContextV1::StepA {
        previous_recursive_proof: Box::new(step_b_context),
        previous_statement: target,
        leaf_record: next_leaf,
        target_statement: next_target,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof,
            },
        )
        .unwrap(),
    };
    verify_hosted_recursive_proof_context_components_v1(&step_a_context).unwrap();
}

#[test]
fn step_b_relation_rejects_wrong_previous_proof_witness() {
    let base_statement = base_prefix_statement();
    let base_relation = BaseARelationV1::new(base_statement.clone(), base_statement.clone());
    let base_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let base_binding = hosted_base_binding_bytes_v1(&base_statement);
    let base_proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &base_descriptor,
        &base_relation,
        &[0u64; 64],
        &base_binding,
    )
    .unwrap();
    let base_context = HostedRecursiveProofContextV1::BaseA {
        statement: base_statement,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: base_descriptor,
                proof_bytes: base_proof,
            },
        )
        .unwrap(),
    };
    let (previous, leaf, target) = step_statement_pair();
    let relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let binding = hosted_step_binding_bytes_v1(&target);
    let wrong_witness = vec![
        0u64;
        step_recursive_witness_words_v1(&base_context, &previous, &leaf)
            .unwrap()
            .len()
    ];
    let proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &wrong_witness,
        &binding,
    )
    .unwrap();
    let err = verify_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &binding,
        &proof,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("linear constraint")
            || err.to_string().contains("transcript hash mismatch"),
        "unexpected wrong-witness verification error: {err}"
    );
}

#[test]
fn step_b_relation_constraints_vanish_on_canonical_step_witness() {
    let base_context = base_a_context_v1();
    let (previous, leaf, target) = step_statement_pair();
    let relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let witness = step_recursive_witness_words_v1(&base_context, &previous, &leaf).unwrap();
    let layout = step_recursive_witness_layout_v1(&base_context).unwrap();
    let (structural_mismatch, validation) =
        debug_step_witness_validation_v1(layout, &target, &witness).unwrap();
    assert_eq!(structural_mismatch, 0);
    assert_eq!(validation, [true, true, true, true, true, true]);
    let view = relation.nonlinear_eval_view(0, &[0u64], &witness);
    let mut out = [1u64; 1];
    relation.compute_constraints_u64(view, &mut out).unwrap();
    assert_eq!(out, [0u64]);
}

#[test]
fn step_b_relation_reconstructed_from_proof_witness_is_self_consistent() {
    let base_context = base_a_context_v1();
    let (previous, leaf, target) = step_statement_pair();
    let relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let binding = hosted_step_binding_bytes_v1(&target);
    let witness = step_recursive_witness_words_v1(&base_context, &previous, &leaf).unwrap();
    let proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &witness,
        &binding,
    )
    .unwrap();
    let proof_trace = decode_smallwood_proof_trace_v1(&proof).unwrap();
    let (structural_mismatch, validation) =
        debug_step_witness_validation_from_words_with_limb_count_v1(
            &target,
            &proof_trace.auxiliary_witness_words,
            proof_trace.auxiliary_witness_limb_count,
        )
        .unwrap();
    let reason = debug_step_witness_validation_reason_from_words_with_limb_count_v1(
        &target,
        &proof_trace.auxiliary_witness_words,
        proof_trace.auxiliary_witness_limb_count,
    )
    .unwrap();
    assert_eq!(structural_mismatch, 0);
    assert_eq!(reason, "ok");
    assert_eq!(validation, [true, true, true, true, true, true]);
    let rebuilt = StepBRelationV1::from_witness_words_with_limb_count(
        target.clone(),
        &proof_trace.auxiliary_witness_words,
        proof_trace.auxiliary_witness_limb_count,
    )
    .unwrap();
    let view = rebuilt.nonlinear_eval_view(0, &[0u64], &proof_trace.auxiliary_witness_words);
    let mut out = [1u64; 1];
    rebuilt.compute_constraints_u64(view, &mut out).unwrap();
    assert_eq!(out, [0u64]);
}

#[test]
fn step_b_relation_verification_is_independent_of_external_previous_context() {
    let base_context = base_a_context_v1();
    let alternative_base_context = base_a_context_v1();
    assert_ne!(
        base_context.proof_envelope_bytes(),
        alternative_base_context.proof_envelope_bytes(),
        "expected two valid base proofs with the same public statement to serialize differently"
    );

    let (previous, leaf, target) = step_statement_pair();
    let relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let binding = hosted_step_binding_bytes_v1(&target);
    let witness = step_recursive_witness_words_v1(&base_context, &previous, &leaf).unwrap();
    let proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &witness,
        &binding,
    )
    .unwrap();

    let alternative_relation = StepBRelationV1::new(
        alternative_base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    )
    .unwrap();
    let alternative_binding = hosted_step_binding_bytes_v1(&target);
    verify_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &alternative_relation,
        &alternative_binding,
        &proof,
    )
    .unwrap();
}

#[test]
fn step_b_relation_constructor_rejects_malformed_previous_context() {
    let base_context = tamper_base_context_proof_bytes_in_range_v1(
        &base_a_context_v1(),
        0,
        1,
        1,
        verify_hosted_recursive_proof_context_components_v1,
    );
    let (previous, leaf, target) = step_statement_pair();
    let _ = StepBRelationV1::new(base_context, previous, leaf, target).unwrap_err();
}

#[test]
fn step_a_relation_verification_is_independent_of_external_previous_context() {
    let (step_b_context, _, _, target) = step_b_context_from_base_context_v1(base_a_context_v1());
    let (alternative_step_b_context, _, _, alternative_target) =
        step_b_context_from_base_context_v1(base_a_context_v1());
    assert_eq!(target, alternative_target);
    assert_ne!(
        step_b_context.proof_envelope_bytes(),
        alternative_step_b_context.proof_envelope_bytes(),
        "expected two valid Step_B proofs with the same public statement to serialize differently"
    );

    let next_leaf = sample_leaf_record(target.tx_count);
    let next_target = RecursivePrefixStatementV1 {
        tx_count: target.tx_count + 1,
        start_state_digest: target.start_state_digest,
        end_state_digest: digest48(0x21, 2),
        verified_leaf_commitment: digest48(0x22, 2),
        tx_statements_commitment: target.tx_statements_commitment,
        verified_receipt_commitment: digest48(0x23, 2),
        start_tree_commitment: target.start_tree_commitment,
        end_tree_commitment: digest48(0x24, 2),
    };
    let relation = StepARelationV1::new(
        step_b_context.clone(),
        target.clone(),
        next_leaf.clone(),
        next_target.clone(),
    )
    .unwrap();
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::StepA,
    );
    let binding = hosted_step_binding_bytes_v1(&next_target);
    let witness = step_recursive_witness_words_v1(&step_b_context, &target, &next_leaf).unwrap();
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &witness,
        &binding,
    )
    .unwrap();

    let alternative_relation = StepARelationV1::new(
        alternative_step_b_context,
        target,
        next_leaf,
        next_target.clone(),
    )
    .unwrap();
    verify_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &alternative_relation,
        &hosted_step_binding_bytes_v1(&next_target),
        &proof,
    )
    .unwrap();
}

#[test]
fn step_a_relation_constructor_rejects_malformed_previous_context() {
    let (step_b_context, _previous, _leaf, target) =
        step_b_context_from_base_context_v1(base_a_context_v1());
    let tampered_step_b_context = tamper_step_b_context_proof_bytes_in_range_v1(
        &step_b_context,
        0,
        1,
        1,
        verify_hosted_recursive_proof_context_components_v1,
    );
    let next_leaf = sample_leaf_record(target.tx_count);
    let next_target = RecursivePrefixStatementV1 {
        tx_count: target.tx_count + 1,
        start_state_digest: target.start_state_digest,
        end_state_digest: digest48(0x21, 2),
        verified_leaf_commitment: digest48(0x22, 2),
        tx_statements_commitment: target.tx_statements_commitment,
        verified_receipt_commitment: digest48(0x23, 2),
        start_tree_commitment: target.start_tree_commitment,
        end_tree_commitment: digest48(0x24, 2),
    };
    let _ =
        StepARelationV1::new(tampered_step_b_context, target, next_leaf, next_target).unwrap_err();
}

#[test]
fn step_binding_bytes_depend_only_on_target_statement() {
    let (_, _, target) = step_statement_pair();
    let next_target = RecursivePrefixStatementV1 {
        tx_count: target.tx_count + 1,
        ..target.clone()
    };

    let binding = hosted_step_binding_bytes_v1(&target);
    assert_eq!(binding, super::recursive_prefix_statement_bytes_v1(&target));
    assert_ne!(binding, hosted_step_binding_bytes_v1(&next_target));
}
