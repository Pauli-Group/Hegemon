mod common;

use block_circuit::CommitmentBlockProver;
use common::{
    PowBlockParams, assemble_pow_block, dummy_coinbase, dummy_transaction, make_validators,
};
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::proof::{ParallelProofVerifier, commitment_nullifier_lists};
use consensus::proof_interface::{BlockBackendInputs, ProofVerifier};
use consensus::types::{
    ConsensusBlock, ProofArtifactKind, ProofVerificationMode, ProvenBatch, ProvenBatchMode,
    Transaction, TxStatementBinding, TxValidityArtifact, TxValidityClaim, TxValidityReceipt,
    kernel_root_from_shielded_root,
};
use consensus::{CommitmentTreeState, NullifierSet, ProofError};
use crypto::hashes::blake3_384;

fn fallback_statement_hash(tx: &Transaction) -> [u8; 48] {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(b"tx-statement-fallback-v1");
    data.extend_from_slice(&tx.hash());
    blake3_384(&data)
}

fn build_block_with_commitment_proof(
    mode: ProofVerificationMode,
) -> (ConsensusBlock, CommitmentTreeState) {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let base_nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let transactions = vec![dummy_transaction(9)];

    let params = PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions,
        miner: &miner,
        base_nullifiers: &base_nullifiers,
        base_commitment_tree: &base_tree,
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce: [0u8; 32],
        parent_supply: 0,
        coinbase: dummy_coinbase(1),
    };

    let (mut block, updated_nullifiers, updated_tree) =
        assemble_pow_block(params).expect("assemble block");

    let lists = commitment_nullifier_lists(&block.transactions).expect("nullifier lists");
    let statement_hashes = block
        .transactions
        .iter()
        .map(fallback_statement_hash)
        .collect::<Vec<_>>();
    let statement_bindings = statement_hashes
        .iter()
        .copied()
        .map(|statement_hash| TxStatementBinding {
            statement_hash,
            anchor: base_tree.root(),
            fee: 0,
            circuit_version: 1,
        })
        .collect::<Vec<_>>();

    let commitment_proof = CommitmentBlockProver::new()
        .prove_from_statement_hashes_with_inputs(
            &statement_hashes,
            base_tree.root(),
            updated_tree.root(),
            kernel_root_from_shielded_root(&base_tree.root()),
            kernel_root_from_shielded_root(&updated_tree.root()),
            updated_nullifiers.commitment(),
            block.header.da_root,
            lists.nullifiers,
            lists.sorted_nullifiers,
        )
        .expect("commitment proof");

    let tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
            .expect("tx statements commitment");
    block.proven_batch = Some(ProvenBatch {
        version: 2,
        tx_count: block.transactions.len() as u32,
        tx_statements_commitment,
        da_root: block.header.da_root,
        da_chunk_count: 1,
        commitment_proof,
        mode: ProvenBatchMode::ReceiptRoot,
        proof_kind: consensus::proof_artifact_kind_from_mode(ProvenBatchMode::ReceiptRoot),
        verifier_profile: consensus::legacy_block_artifact_verifier_profile(
            consensus::proof_artifact_kind_from_mode(ProvenBatchMode::ReceiptRoot),
        ),
        receipt_root: None,
    });
    block.tx_validity_claims = Some(
        statement_bindings
            .into_iter()
            .map(|binding| {
                consensus::TxValidityClaim::new(
                    consensus::TxValidityReceipt::new(
                        binding.statement_hash,
                        [0x11; 48],
                        [0x22; 48],
                        [0x33; 48],
                    ),
                    binding,
                )
            })
            .collect(),
    );
    block.tx_statements_commitment = Some(tx_statements_commitment);
    block.proof_verification_mode = mode;

    (block, base_tree)
}

fn dummy_tx_validity_artifact(statement_hash: [u8; 48]) -> TxValidityArtifact {
    TxValidityArtifact {
        receipt: TxValidityReceipt::new(statement_hash, [0x11; 48], [0x22; 48], [0x33; 48]),
        proof: Some(consensus::ProofEnvelope {
            kind: ProofArtifactKind::TxLeaf,
            verifier_profile:
                consensus::proof_interface::experimental_native_tx_leaf_verifier_profile(),
            artifact_bytes: vec![1, 2, 3],
        }),
    }
}

#[test]
#[ignore = "commitment proof fixture no longer matches current prover constraints; replace with regenerated fixture"]
fn self_contained_mode_rejects_missing_aggregation_proof() {
    let (block, base_tree) =
        build_block_with_commitment_proof(ProofVerificationMode::SelfContainedAggregation);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, None, &base_tree)
        .expect_err("missing aggregation proof must be rejected");

    assert!(matches!(
        err,
        ProofError::MissingAggregationProofForSelfContainedMode
    ));
}

#[test]
fn self_contained_mode_rejects_missing_tx_validity_artifacts_before_proven_batch() {
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let base_nullifiers = NullifierSet::new();
    let base_tree = CommitmentTreeState::default();
    let transactions = vec![dummy_transaction(11)];
    let params = PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions,
        miner: &miner,
        base_nullifiers: &base_nullifiers,
        base_commitment_tree: &base_tree,
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce: [0u8; 32],
        parent_supply: 0,
        coinbase: dummy_coinbase(1),
    };
    let (mut block, _, _) = assemble_pow_block(params).expect("assemble block");
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;
    block.proven_batch = None;

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, None, &base_tree)
        .expect_err("missing tx validity artifacts must be rejected first");
    assert!(matches!(err, ProofError::MissingTransactionProofs));
}

#[test]
#[ignore = "commitment proof fixture no longer matches current prover constraints; replace with regenerated fixture"]
fn self_contained_mode_rejects_missing_tx_validity_claims_before_proven_batch() {
    let (mut block, base_tree) =
        build_block_with_commitment_proof(ProofVerificationMode::SelfContainedAggregation);
    let statement_hash = fallback_statement_hash(&block.transactions[0]);
    block.tx_validity_claims = None;
    let backend_inputs =
        BlockBackendInputs::from_tx_validity_artifacts(vec![dummy_tx_validity_artifact(
            statement_hash,
        )]);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, Some(&backend_inputs), &base_tree)
        .expect_err("missing tx validity claims must be rejected before aggregation");
    assert!(matches!(err, ProofError::MissingTransactionValidityClaims));
}

#[test]
#[ignore = "commitment proof fixture no longer matches current prover constraints; replace with regenerated fixture"]
fn self_contained_mode_rejects_claim_statement_hash_tampering() {
    let (mut block, base_tree) =
        build_block_with_commitment_proof(ProofVerificationMode::SelfContainedAggregation);
    let statement_hash = fallback_statement_hash(&block.transactions[0]);
    block.tx_validity_claims = Some(vec![TxValidityClaim::new(
        TxValidityReceipt::new([0xA5; 48], [0x11; 48], [0x22; 48], [0x33; 48]),
        TxStatementBinding {
            statement_hash,
            anchor: base_tree.root(),
            fee: 0,
            circuit_version: 1,
        },
    )]);
    let backend_inputs =
        BlockBackendInputs::from_tx_validity_artifacts(vec![dummy_tx_validity_artifact(
            statement_hash,
        )]);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, Some(&backend_inputs), &base_tree)
        .expect_err("tampered tx validity claim must be rejected");
    assert!(matches!(err, ProofError::AggregationProofInputsMismatch(_)));
}

#[test]
#[ignore = "commitment proof fixture no longer matches current prover constraints; replace with regenerated fixture"]
fn inline_required_mode_rejects_missing_transaction_proofs() {
    let (block, base_tree) =
        build_block_with_commitment_proof(ProofVerificationMode::InlineRequired);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, None, &base_tree)
        .expect_err("missing tx proofs must be rejected in inline mode");

    assert!(matches!(err, ProofError::MissingTransactionProofs));
}
