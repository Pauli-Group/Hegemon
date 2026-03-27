mod common;

use block_circuit::CommitmentBlockProver;
use common::{PowBlockParams, assemble_pow_block, dummy_coinbase, make_validators};
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::types::{
    ConsensusBlock, ProofArtifactKind, ProofEnvelope, ProofVerificationMode, ProvenBatch,
    ProvenBatchMode, ReceiptRootMetadata, ReceiptRootProofPayload, Transaction, TxStatementBinding,
    TxValidityArtifact, kernel_root_from_shielded_root,
};
use consensus::{
    CommitmentTreeState, NullifierSet, ParallelProofVerifier, ProofError, ProofVerifier,
    build_experimental_native_receipt_accumulation_artifact,
    build_experimental_native_receipt_root_artifact, build_experimental_receipt_arc_whir_artifact,
    clear_verified_native_tx_leaf_store, commitment_nullifier_lists,
    experimental_native_receipt_root_verifier_profile,
    experimental_receipt_accumulation_artifact_kind,
    experimental_receipt_accumulation_verifier_profile,
    experimental_receipt_arc_whir_artifact_kind, experimental_receipt_arc_whir_verifier_profile,
    prewarm_verified_native_tx_leaf_store, receipt_statement_commitment,
    tx_validity_artifact_from_native_tx_leaf_bytes, tx_validity_artifact_from_receipt,
    verify_experimental_receipt_arc_whir_artifact_detailed,
};
use crypto::hashes::blake3_384;
use std::sync::OnceLock;
use superneo_hegemon::build_native_tx_leaf_artifact_bytes;
use transaction_circuit::constants::CIRCUIT_MERKLE_DEPTH;
use transaction_circuit::hashing_pq::{
    Felt, HashFelt, felts_to_bytes48, merkle_node, spend_auth_key_bytes,
};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{MerklePath, NoteData};
use transaction_circuit::proof::prove;
use transaction_circuit::{
    InputNoteWitness, OutputNoteWitness, StablecoinPolicyBinding, TransactionProof,
    TransactionWitness,
};

#[derive(Clone)]
struct RawActiveFixture {
    base_tree: CommitmentTreeState,
    block: ConsensusBlock,
    updated_root: [u8; 48],
    witnesses: Vec<TransactionWitness>,
}

fn compute_merkle_root(leaf: HashFelt, position: u64, path: &[HashFelt]) -> HashFelt {
    let mut current = leaf;
    let mut pos = position;
    for sibling in path.iter().take(CIRCUIT_MERKLE_DEPTH) {
        current = if pos & 1 == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
        pos >>= 1;
    }
    current
}

fn default_subtrees() -> Vec<HashFelt> {
    let mut defaults = Vec::with_capacity(CIRCUIT_MERKLE_DEPTH + 1);
    defaults.push([Felt::new(0); 6]);
    for level in 0..CIRCUIT_MERKLE_DEPTH {
        let prev = defaults[level];
        defaults.push(merkle_node(prev, prev));
    }
    defaults
}

fn build_four_leaf_merkle_tree(leaves: [HashFelt; 4]) -> ([MerklePath; 4], HashFelt) {
    let defaults = default_subtrees();
    let level_one_left = merkle_node(leaves[0], leaves[1]);
    let level_one_right = merkle_node(leaves[2], leaves[3]);
    let mut root = merkle_node(level_one_left, level_one_right);
    for default in defaults.iter().take(CIRCUIT_MERKLE_DEPTH).skip(2) {
        root = merkle_node(root, *default);
    }

    let mut path0 = vec![leaves[1], level_one_right];
    let mut path1 = vec![leaves[0], level_one_right];
    let mut path2 = vec![leaves[3], level_one_left];
    let mut path3 = vec![leaves[2], level_one_left];
    for default in defaults.iter().take(CIRCUIT_MERKLE_DEPTH).skip(2) {
        path0.push(*default);
        path1.push(*default);
        path2.push(*default);
        path3.push(*default);
    }

    (
        [
            MerklePath { siblings: path0 },
            MerklePath { siblings: path1 },
            MerklePath { siblings: path2 },
            MerklePath { siblings: path3 },
        ],
        root,
    )
}

fn make_input_note(seed: u8, value: u64, asset_id: u64, pk_auth: [u8; 32]) -> NoteData {
    NoteData {
        value,
        asset_id,
        pk_recipient: [seed.wrapping_add(1); 32],
        pk_auth,
        rho: [seed.wrapping_add(2); 32],
        r: [seed.wrapping_add(3); 32],
    }
}

fn make_output(seed: u8, value: u64, asset_id: u64) -> OutputNoteWitness {
    OutputNoteWitness {
        note: NoteData {
            value,
            asset_id,
            pk_recipient: [seed.wrapping_add(4); 32],
            pk_auth: [seed.wrapping_add(5); 32],
            rho: [seed.wrapping_add(6); 32],
            r: [seed.wrapping_add(7); 32],
        },
    }
}

fn transaction_from_proof(proof: &TransactionProof) -> Transaction {
    let nullifiers: Vec<[u8; 48]> = proof
        .nullifiers
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 48])
        .collect();
    let commitments: Vec<[u8; 48]> = proof
        .commitments
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 48])
        .collect();
    Transaction::new_with_hashes(
        nullifiers,
        commitments,
        proof.public_inputs.balance_tag,
        proof.version_binding(),
        proof.public_inputs.ciphertext_hashes.clone(),
    )
}

fn statement_hash_from_proof(proof: &TransactionProof) -> [u8; 48] {
    let public = &proof.public_inputs;
    let mut message = Vec::new();
    message.extend_from_slice(b"tx-statement-v1");
    message.extend_from_slice(&public.merkle_root);
    for nf in &public.nullifiers {
        message.extend_from_slice(nf);
    }
    for cm in &public.commitments {
        message.extend_from_slice(cm);
    }
    for ct in &public.ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    message.extend_from_slice(&public.native_fee.to_le_bytes());
    message.extend_from_slice(&public.value_balance.to_le_bytes());
    message.extend_from_slice(&public.balance_tag);
    message.extend_from_slice(&public.circuit_version.to_le_bytes());
    message.extend_from_slice(&public.crypto_suite.to_le_bytes());
    message.push(public.stablecoin.enabled as u8);
    message.extend_from_slice(&public.stablecoin.asset_id.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_hash);
    message.extend_from_slice(&public.stablecoin.oracle_commitment);
    message.extend_from_slice(&public.stablecoin.attestation_commitment);
    message.extend_from_slice(&public.stablecoin.issuance_delta.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_version.to_le_bytes());
    blake3_384(&message)
}

fn statement_binding_from_proof(proof: &TransactionProof) -> TxStatementBinding {
    TxStatementBinding {
        statement_hash: statement_hash_from_proof(proof),
        anchor: proof.public_inputs.merkle_root,
        fee: proof.public_inputs.native_fee,
        circuit_version: u32::from(proof.public_inputs.circuit_version),
    }
}

fn build_raw_active_fixture() -> RawActiveFixture {
    let sk_spend_a = [42u8; 32];
    let sk_spend_b = [77u8; 32];
    let pk_auth_a = spend_auth_key_bytes(&sk_spend_a);
    let pk_auth_b = spend_auth_key_bytes(&sk_spend_b);

    let input_a0 = make_input_note(
        10,
        8,
        transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_auth_a,
    );
    let input_a1 = make_input_note(20, 5, 1, pk_auth_a);
    let input_b0 = make_input_note(
        30,
        7,
        transaction_circuit::constants::NATIVE_ASSET_ID,
        pk_auth_b,
    );
    let input_b1 = make_input_note(40, 4, 1, pk_auth_b);

    let leaves = [
        input_a0.commitment(),
        input_a1.commitment(),
        input_b0.commitment(),
        input_b1.commitment(),
    ];
    let (paths, merkle_root) = build_four_leaf_merkle_tree(leaves);
    for (position, leaf) in leaves.into_iter().enumerate() {
        assert_eq!(
            compute_merkle_root(leaf, position as u64, &paths[position].siblings),
            merkle_root
        );
    }
    let merkle_root_bytes = felts_to_bytes48(&merkle_root);

    let witness_a = TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_a0,
                position: 0,
                rho_seed: [11u8; 32],
                merkle_path: paths[0].clone(),
            },
            InputNoteWitness {
                note: input_a1,
                position: 1,
                rho_seed: [12u8; 32],
                merkle_path: paths[1].clone(),
            },
        ],
        outputs: vec![
            make_output(50, 3, transaction_circuit::constants::NATIVE_ASSET_ID),
            make_output(60, 5, 1),
        ],
        ciphertext_hashes: vec![[1u8; 48]; 2],
        sk_spend: sk_spend_a,
        merkle_root: merkle_root_bytes,
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };
    let witness_b = TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_b0,
                position: 2,
                rho_seed: [21u8; 32],
                merkle_path: paths[2].clone(),
            },
            InputNoteWitness {
                note: input_b1,
                position: 3,
                rho_seed: [22u8; 32],
                merkle_path: paths[3].clone(),
            },
        ],
        outputs: vec![
            make_output(70, 3, transaction_circuit::constants::NATIVE_ASSET_ID),
            make_output(80, 4, 1),
        ],
        ciphertext_hashes: vec![[2u8; 48]; 2],
        sk_spend: sk_spend_b,
        merkle_root: merkle_root_bytes,
        fee: 4,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };

    let (proving_key, _) = generate_keys();
    let proof_a = prove(&witness_a, &proving_key).expect("first tx proof");
    let proof_b = prove(&witness_b, &proving_key).expect("second tx proof");
    let proofs = [proof_a.clone(), proof_b.clone()];
    let transactions = proofs
        .iter()
        .map(transaction_from_proof)
        .collect::<Vec<_>>();

    let mut base_tree = CommitmentTreeState::default();
    for input in witness_a.inputs.iter().chain(witness_b.inputs.iter()) {
        base_tree
            .append(felts_to_bytes48(&input.note.commitment()))
            .expect("append input commitment");
    }
    assert_eq!(base_tree.root(), merkle_root_bytes);

    let base_nullifiers = NullifierSet::new();
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
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
        assemble_pow_block(params).expect("assemble raw-active block");

    let statement_bindings = proofs
        .iter()
        .map(statement_binding_from_proof)
        .collect::<Vec<_>>();
    let statement_hashes = statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let lists = commitment_nullifier_lists(&block.transactions).expect("nullifier lists");
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
        mode: ProvenBatchMode::InlineTx,
        proof_kind: consensus::proof_artifact_kind_from_mode(ProvenBatchMode::InlineTx),
        verifier_profile: consensus::legacy_block_artifact_verifier_profile(
            consensus::proof_artifact_kind_from_mode(ProvenBatchMode::InlineTx),
        ),
        flat_batches: Vec::new(),
        merge_root: None,
        receipt_root: None,
    });
    block.tx_statement_bindings = Some(statement_bindings);
    block.tx_statements_commitment = Some(tx_statements_commitment);
    block.tx_validity_artifacts = Some(
        proofs
            .iter()
            .map(|proof| {
                consensus::proof::tx_validity_artifact_from_proof(proof)
                    .expect("tx validity artifact")
            })
            .collect(),
    );
    block.proof_verification_mode = ProofVerificationMode::InlineRequired;

    RawActiveFixture {
        base_tree,
        block,
        updated_root: updated_tree.root(),
        witnesses: vec![witness_a, witness_b],
    }
}

fn raw_active_fixture() -> &'static RawActiveFixture {
    static FIXTURE: OnceLock<RawActiveFixture> = OnceLock::new();
    FIXTURE.get_or_init(build_raw_active_fixture)
}

fn build_receipt_root_block_artifacts(
    witnesses: &[TransactionWitness],
) -> (
    Vec<TxValidityArtifact>,
    ReceiptRootProofPayload,
    ProofEnvelope,
) {
    let tx_validity_artifacts = witnesses
        .iter()
        .map(|witness| {
            let built = build_native_tx_leaf_artifact_bytes(witness).expect("native tx leaf bytes");
            tx_validity_artifact_from_native_tx_leaf_bytes(built.artifact_bytes)
                .expect("native tx leaf artifact")
        })
        .collect::<Vec<_>>();
    let receipts = tx_validity_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();
    let built = build_experimental_native_receipt_root_artifact(&tx_validity_artifacts)
        .expect("native receipt-root bytes");
    let verifier_profile = experimental_native_receipt_root_verifier_profile();
    let payload = ReceiptRootProofPayload {
        root_proof: built.artifact_bytes.clone(),
        metadata: ReceiptRootMetadata {
            params_fingerprint: built.metadata.params_fingerprint,
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
        receipts: receipts.to_vec(),
    };
    let envelope = ProofEnvelope {
        kind: ProofArtifactKind::ReceiptRoot,
        verifier_profile,
        artifact_bytes: built.artifact_bytes,
    };
    (tx_validity_artifacts, payload, envelope)
}

fn build_receipt_accumulation_block_artifacts(
    witnesses: &[TransactionWitness],
) -> (
    Vec<TxValidityArtifact>,
    Vec<TxValidityArtifact>,
    ReceiptRootProofPayload,
    ProofEnvelope,
) {
    let tx_validity_artifacts = witnesses
        .iter()
        .map(|witness| {
            let built = build_native_tx_leaf_artifact_bytes(witness).expect("native tx leaf bytes");
            tx_validity_artifact_from_native_tx_leaf_bytes(built.artifact_bytes)
                .expect("native tx leaf artifact")
        })
        .collect::<Vec<_>>();
    let receipt_only_artifacts = tx_validity_artifacts
        .iter()
        .map(|artifact| tx_validity_artifact_from_receipt(artifact.receipt.clone()))
        .collect::<Vec<_>>();
    let receipts = tx_validity_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();
    let built = build_experimental_native_receipt_accumulation_artifact(&tx_validity_artifacts)
        .expect("native receipt accumulation bytes");
    let verifier_profile = experimental_receipt_accumulation_verifier_profile();
    let payload = ReceiptRootProofPayload {
        root_proof: built.artifact_bytes.clone(),
        metadata: ReceiptRootMetadata {
            params_fingerprint: built.metadata.params_fingerprint,
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
        receipts: receipts.to_vec(),
    };
    let envelope = ProofEnvelope {
        kind: experimental_receipt_accumulation_artifact_kind(),
        verifier_profile,
        artifact_bytes: built.artifact_bytes,
    };
    (
        tx_validity_artifacts,
        receipt_only_artifacts,
        payload,
        envelope,
    )
}

fn build_receipt_arc_whir_block_artifacts(
    witnesses: &[TransactionWitness],
) -> (
    Vec<TxValidityArtifact>,
    Vec<TxValidityArtifact>,
    ReceiptRootProofPayload,
    ProofEnvelope,
) {
    let tx_validity_artifacts = witnesses
        .iter()
        .map(|witness| {
            let built = build_native_tx_leaf_artifact_bytes(witness).expect("native tx leaf bytes");
            tx_validity_artifact_from_native_tx_leaf_bytes(built.artifact_bytes)
                .expect("native tx leaf artifact")
        })
        .collect::<Vec<_>>();
    let receipt_only_artifacts = tx_validity_artifacts
        .iter()
        .map(|artifact| tx_validity_artifact_from_receipt(artifact.receipt.clone()))
        .collect::<Vec<_>>();
    let receipts = tx_validity_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();
    let built =
        build_experimental_receipt_arc_whir_artifact(&receipts).expect("receipt_arc_whir bytes");
    let verifier_profile = experimental_receipt_arc_whir_verifier_profile();
    let payload = ReceiptRootProofPayload {
        root_proof: built.artifact_bytes.clone(),
        metadata: ReceiptRootMetadata {
            params_fingerprint: built.metadata.params_fingerprint,
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
        receipts: receipts.to_vec(),
    };
    let envelope = ProofEnvelope {
        kind: experimental_receipt_arc_whir_artifact_kind(),
        verifier_profile,
        artifact_bytes: built.artifact_bytes,
    };
    (
        tx_validity_artifacts,
        receipt_only_artifacts,
        payload,
        envelope,
    )
}

#[test]
fn raw_active_rejects_bad_tx_proof() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    let artifact = block
        .tx_validity_artifacts
        .as_mut()
        .expect("tx artifacts present")
        .first_mut()
        .expect("first tx artifact");
    let envelope = artifact.proof.as_mut().expect("inline tx proof envelope");
    let mut proof: TransactionProof =
        bincode::deserialize(&envelope.artifact_bytes).expect("decode tx proof");
    let stark_inputs = proof
        .stark_public_inputs
        .as_mut()
        .expect("serialized stark inputs present");
    stark_inputs.fee = stark_inputs.fee.saturating_add(1);
    envelope.artifact_bytes = bincode::serialize(&proof).expect("encode tx proof");

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect_err("tampered tx proof must be rejected");
    assert!(matches!(
        err,
        ProofError::TransactionProofInputsMismatch { .. }
            | ProofError::TransactionProofVerification { .. }
    ));
}

#[test]
fn raw_active_rejects_bad_ordering() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    block.transactions.swap(0, 1);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect_err("swapped tx ordering must be rejected");
    assert!(matches!(
        err,
        ProofError::CommitmentProofInputsMismatch(_)
            | ProofError::TransactionProofInputsMismatch { .. }
    ));
}

#[test]
fn raw_active_rejects_commitment_mismatch() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    block.tx_statements_commitment = Some([9u8; 48]);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect_err("statement commitment mismatch must be rejected");
    assert!(matches!(err, ProofError::CommitmentProofInputsMismatch(_)));
}

#[test]
fn receipt_root_block_is_accepted() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    let (tx_validity_artifacts, receipt_root, envelope) =
        build_receipt_root_block_artifacts(&fixture.witnesses);
    let proven_batch = block.proven_batch.as_mut().expect("proven batch");
    proven_batch.mode = ProvenBatchMode::ReceiptRoot;
    proven_batch.proof_kind = ProofArtifactKind::ReceiptRoot;
    proven_batch.verifier_profile = experimental_native_receipt_root_verifier_profile();
    proven_batch.receipt_root = Some(receipt_root);
    block.tx_validity_artifacts = Some(tx_validity_artifacts);
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;

    let verifier = ParallelProofVerifier::new();
    let updated = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect("valid receipt-root block should verify");
    assert_eq!(updated.root(), fixture.updated_root);
}

#[test]
fn receipt_accumulation_block_is_accepted_with_prewarmed_store() {
    let fixture = raw_active_fixture();
    clear_verified_native_tx_leaf_store();
    let mut block = fixture.block.clone();
    let (native_artifacts, receipt_only_artifacts, receipt_root, envelope) =
        build_receipt_accumulation_block_artifacts(&fixture.witnesses);
    prewarm_verified_native_tx_leaf_store(&block.transactions, &native_artifacts)
        .expect("prewarm verified native tx leaf store");
    let proven_batch = block.proven_batch.as_mut().expect("proven batch");
    proven_batch.mode = ProvenBatchMode::ReceiptRoot;
    proven_batch.proof_kind = experimental_receipt_accumulation_artifact_kind();
    proven_batch.verifier_profile = experimental_receipt_accumulation_verifier_profile();
    proven_batch.receipt_root = Some(receipt_root);
    block.tx_validity_artifacts = Some(receipt_only_artifacts);
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;

    let verifier = ParallelProofVerifier::new();
    let updated = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect("valid receipt accumulation block should verify");
    assert_eq!(updated.root(), fixture.updated_root);
    clear_verified_native_tx_leaf_store();
}

#[test]
fn receipt_accumulation_rejects_store_miss() {
    let fixture = raw_active_fixture();
    clear_verified_native_tx_leaf_store();
    let mut block = fixture.block.clone();
    let (_native_artifacts, receipt_only_artifacts, receipt_root, envelope) =
        build_receipt_accumulation_block_artifacts(&fixture.witnesses);
    let proven_batch = block.proven_batch.as_mut().expect("proven batch");
    proven_batch.mode = ProvenBatchMode::ReceiptRoot;
    proven_batch.proof_kind = experimental_receipt_accumulation_artifact_kind();
    proven_batch.verifier_profile = experimental_receipt_accumulation_verifier_profile();
    proven_batch.receipt_root = Some(receipt_root);
    block.tx_validity_artifacts = Some(receipt_only_artifacts);
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect_err("receipt accumulation must reject an unprepared store miss");
    assert!(matches!(
        err,
        ProofError::VerifiedTxArtifactUnavailable { .. }
    ));
    clear_verified_native_tx_leaf_store();
}

#[test]
fn receipt_arc_whir_block_is_accepted_from_native_tx_leaf_artifacts() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    let (native_artifacts, _receipt_only_artifacts, receipt_root, envelope) =
        build_receipt_arc_whir_block_artifacts(&fixture.witnesses);
    let proven_batch = block.proven_batch.as_mut().expect("proven batch");
    proven_batch.mode = ProvenBatchMode::ReceiptRoot;
    proven_batch.proof_kind = experimental_receipt_arc_whir_artifact_kind();
    proven_batch.verifier_profile = experimental_receipt_arc_whir_verifier_profile();
    proven_batch.receipt_root = Some(receipt_root);
    block.tx_validity_artifacts = Some(native_artifacts);
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;

    let verifier = ParallelProofVerifier::new();
    let updated = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect("valid receipt_arc_whir block should verify");
    assert_eq!(updated.root(), fixture.updated_root);
}

#[test]
fn receipt_arc_whir_rejects_receipt_only_tx_artifacts() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    let (_native_artifacts, receipt_only_artifacts, receipt_root, envelope) =
        build_receipt_arc_whir_block_artifacts(&fixture.witnesses);
    let proven_batch = block.proven_batch.as_mut().expect("proven batch");
    proven_batch.mode = ProvenBatchMode::ReceiptRoot;
    proven_batch.proof_kind = experimental_receipt_arc_whir_artifact_kind();
    proven_batch.verifier_profile = experimental_receipt_arc_whir_verifier_profile();
    proven_batch.receipt_root = Some(receipt_root);
    block.tx_validity_artifacts = Some(receipt_only_artifacts);
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect_err("receipt_arc_whir must reject proofless receipt-only tx artifacts");
    assert!(matches!(err, ProofError::MissingTransactionProofs));
}

#[test]
fn receipt_arc_whir_measures_native_leaf_replay_without_old_backend() {
    let fixture = raw_active_fixture();
    let (native_artifacts, _receipt_only_artifacts, _receipt_root, envelope) =
        build_receipt_arc_whir_block_artifacts(&fixture.witnesses);
    let receipts = native_artifacts
        .iter()
        .map(|artifact| artifact.receipt.clone())
        .collect::<Vec<_>>();
    let expected_commitment =
        receipt_statement_commitment(&receipts).expect("receipt statement commitment");
    clear_verified_native_tx_leaf_store();
    let details = verify_experimental_receipt_arc_whir_artifact_detailed(
        fixture.block.transactions.as_slice(),
        native_artifacts.as_slice(),
        &expected_commitment,
        &envelope,
    )
    .expect("receipt_arc_whir verification details");
    assert_eq!(
        details.residual_report.replayed_leaf_verifications,
        fixture.witnesses.len()
    );
    assert!(!details.residual_report.used_old_aggregation_backend);
    clear_verified_native_tx_leaf_store();
}

#[test]
fn receipt_root_rejects_receipts_for_the_wrong_statement_set() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    let (mut tx_validity_artifacts, receipt_root, envelope) =
        build_receipt_root_block_artifacts(&fixture.witnesses);
    tx_validity_artifacts[0].receipt.statement_hash = [0xA5; 48];
    let proven_batch = block.proven_batch.as_mut().expect("proven batch");
    proven_batch.mode = ProvenBatchMode::ReceiptRoot;
    proven_batch.proof_kind = ProofArtifactKind::ReceiptRoot;
    proven_batch.verifier_profile = experimental_native_receipt_root_verifier_profile();
    proven_batch.receipt_root = Some(receipt_root);
    block.tx_validity_artifacts = Some(tx_validity_artifacts);
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect_err("receipt-root must reject mismatched statement receipts");
    assert!(matches!(
        err,
        ProofError::ProvenBatchBindingMismatch(_)
            | ProofError::AggregationProofInputsMismatch(_)
            | ProofError::TransactionProofInputsMismatch { .. }
    ));
}

#[test]
fn raw_active_block_is_accepted() {
    let fixture = raw_active_fixture();
    let verifier = ParallelProofVerifier::new();
    let updated = verifier
        .verify_block(&fixture.block, &fixture.base_tree)
        .expect("valid raw-active block should verify");
    assert_eq!(updated.root(), fixture.updated_root);
}

#[test]
fn raw_active_rejects_duplicate_nullifier_conflict() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    block.transactions[1] = block.transactions[0].clone();
    if let Some(artifacts) = block.tx_validity_artifacts.as_mut() {
        artifacts[1] = artifacts[0].clone();
    }
    if let Some(bindings) = block.tx_statement_bindings.as_mut() {
        bindings[1] = bindings[0].clone();
    }

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block(&block, &fixture.base_tree)
        .expect_err("duplicate-nullifier block must be rejected");
    assert!(matches!(err, ProofError::CommitmentProofInputsMismatch(_)));
}
