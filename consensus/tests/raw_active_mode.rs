mod common;

use block_circuit::CommitmentBlockProver;
use common::{PowBlockParams, assemble_pow_block, dummy_coinbase, make_validators};
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::proof::{
    ParallelProofVerifier, commitment_nullifier_lists,
    tx_validity_artifact_from_native_tx_leaf_bytes,
};
use consensus::proof_interface::{
    BlockBackendInputs, ProofVerifier, build_experimental_native_receipt_root_artifact,
    experimental_native_receipt_root_verifier_profile,
};
use consensus::types::{
    ConsensusBlock, ProofArtifactKind, ProofEnvelope, ProofVerificationMode, ProvenBatch,
    ProvenBatchMode, ReceiptRootMetadata, ReceiptRootProofPayload, Transaction, TxStatementBinding,
    TxValidityArtifact, kernel_root_from_shielded_root,
};
use consensus::{CommitmentTreeState, NullifierSet, ProofError};
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
    backend_inputs: BlockBackendInputs,
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

fn build_power_of_two_merkle_tree(leaves: &[HashFelt]) -> (Vec<MerklePath>, HashFelt) {
    assert!(
        !leaves.is_empty() && leaves.len().is_power_of_two(),
        "leaf count must be a non-zero power of two"
    );
    assert!(
        leaves.len() <= (1usize << CIRCUIT_MERKLE_DEPTH),
        "leaf count exceeds circuit tree capacity"
    );

    let defaults = default_subtrees();
    let mut levels = vec![leaves.to_vec()];
    while levels.last().expect("at least one level").len() > 1 {
        let current = levels.last().expect("current level");
        let mut next = Vec::with_capacity(current.len() / 2);
        for chunk in current.chunks_exact(2) {
            next.push(merkle_node(chunk[0], chunk[1]));
        }
        levels.push(next);
    }

    let mut root = levels.last().expect("root level")[0];
    let occupied_levels = levels.len() - 1;
    for default in defaults
        .iter()
        .take(CIRCUIT_MERKLE_DEPTH)
        .skip(occupied_levels)
    {
        root = merkle_node(root, *default);
    }

    let mut paths = Vec::with_capacity(leaves.len());
    for leaf_index in 0..leaves.len() {
        let mut siblings = Vec::with_capacity(CIRCUIT_MERKLE_DEPTH);
        let mut index = leaf_index;
        for level in levels.iter().take(occupied_levels) {
            let sibling_index = index ^ 1;
            siblings.push(level[sibling_index]);
            index >>= 1;
        }
        for default in defaults
            .iter()
            .take(CIRCUIT_MERKLE_DEPTH)
            .skip(occupied_levels)
        {
            siblings.push(*default);
        }
        paths.push(MerklePath { siblings });
    }

    (paths, root)
}

fn nullifier_root_for_transactions(transactions: &[Transaction]) -> [u8; 48] {
    let mut set = NullifierSet::new();
    for tx in transactions {
        for nullifier in &tx.nullifiers {
            set.insert(*nullifier).expect("test nullifier insertion");
        }
    }
    set.commitment()
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

    let (tx_validity_artifacts, receipt_root, envelope) =
        build_receipt_root_block_artifacts(&[witness_a.clone(), witness_b.clone()]);
    block.proven_batch = Some(ProvenBatch {
        version: 2,
        tx_count: block.transactions.len() as u32,
        tx_statements_commitment,
        da_root: block.header.da_root,
        da_chunk_count: 1,
        commitment_proof,
        mode: ProvenBatchMode::ReceiptRoot,
        proof_kind: ProofArtifactKind::ReceiptRoot,
        verifier_profile: experimental_native_receipt_root_verifier_profile(),
        receipt_root: Some(receipt_root),
    });
    block.tx_validity_claims = Some(
        consensus::proof::tx_validity_claims_from_tx_artifacts(
            &block.transactions,
            &tx_validity_artifacts,
        )
        .expect("tx validity claims"),
    );
    block.tx_statements_commitment = Some(tx_statements_commitment);
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;
    let backend_inputs = BlockBackendInputs::from_tx_validity_artifacts(tx_validity_artifacts);

    RawActiveFixture {
        base_tree,
        block,
        backend_inputs,
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

fn build_upgrade_transition_blocks() -> (
    CommitmentTreeState,
    ConsensusBlock,
    BlockBackendInputs,
    CommitmentTreeState,
    ConsensusBlock,
    BlockBackendInputs,
    [u8; 48],
) {
    let sk_spend_a = [42u8; 32];
    let sk_spend_b = [77u8; 32];
    let sk_spend_c = [123u8; 32];
    let pk_auth_a = spend_auth_key_bytes(&sk_spend_a);
    let pk_auth_b = spend_auth_key_bytes(&sk_spend_b);
    let pk_auth_c = spend_auth_key_bytes(&sk_spend_c);

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

    let first_leaves = [
        input_a0.commitment(),
        input_a1.commitment(),
        input_b0.commitment(),
        input_b1.commitment(),
    ];
    let (first_paths, first_root) = build_four_leaf_merkle_tree(first_leaves);
    let first_root_bytes = felts_to_bytes48(&first_root);

    let witness_a = TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_a0.clone(),
                position: 0,
                rho_seed: [11u8; 32],
                merkle_path: first_paths[0].clone(),
            },
            InputNoteWitness {
                note: input_a1.clone(),
                position: 1,
                rho_seed: [12u8; 32],
                merkle_path: first_paths[1].clone(),
            },
        ],
        outputs: vec![
            OutputNoteWitness {
                note: NoteData {
                    value: 3,
                    asset_id: transaction_circuit::constants::NATIVE_ASSET_ID,
                    pk_recipient: [50u8; 32],
                    pk_auth: pk_auth_c,
                    rho: [51u8; 32],
                    r: [52u8; 32],
                },
            },
            OutputNoteWitness {
                note: NoteData {
                    value: 5,
                    asset_id: 1,
                    pk_recipient: [60u8; 32],
                    pk_auth: pk_auth_c,
                    rho: [61u8; 32],
                    r: [62u8; 32],
                },
            },
        ],
        ciphertext_hashes: vec![[1u8; 48]; 2],
        sk_spend: sk_spend_a,
        merkle_root: first_root_bytes,
        fee: 5,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };
    let witness_b = TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: input_b0.clone(),
                position: 2,
                rho_seed: [21u8; 32],
                merkle_path: first_paths[2].clone(),
            },
            InputNoteWitness {
                note: input_b1.clone(),
                position: 3,
                rho_seed: [22u8; 32],
                merkle_path: first_paths[3].clone(),
            },
        ],
        outputs: vec![
            make_output(70, 3, transaction_circuit::constants::NATIVE_ASSET_ID),
            make_output(80, 4, 1),
        ],
        ciphertext_hashes: vec![[2u8; 48]; 2],
        sk_spend: sk_spend_b,
        merkle_root: first_root_bytes,
        fee: 4,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };

    let (proving_key, _) = generate_keys();
    let proof_a = prove(&witness_a, &proving_key).expect("first tx proof");
    let proof_b = prove(&witness_b, &proving_key).expect("second tx proof");
    let first_transactions = [proof_a.clone(), proof_b.clone()]
        .iter()
        .map(transaction_from_proof)
        .collect::<Vec<_>>();

    let mut first_base_tree = CommitmentTreeState::default();
    for input in witness_a.inputs.iter().chain(witness_b.inputs.iter()) {
        first_base_tree
            .append(felts_to_bytes48(&input.note.commitment()))
            .expect("append first-phase input commitment");
    }

    let first_base_nullifiers = NullifierSet::new();
    let mut miners = make_validators(1, 0);
    let miner = miners.remove(0);
    let first_params = PowBlockParams {
        height: 1,
        parent_hash: [0u8; 32],
        timestamp_ms: 1_000,
        transactions: first_transactions,
        miner: &miner,
        base_nullifiers: &first_base_nullifiers,
        base_commitment_tree: &first_base_tree,
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce: [0u8; 32],
        parent_supply: 0,
        coinbase: dummy_coinbase(1),
    };
    let (mut first_block, first_updated_nullifiers, first_updated_tree) =
        assemble_pow_block(first_params).expect("assemble first inline block");

    let first_statement_bindings = [proof_a.clone(), proof_b.clone()]
        .iter()
        .map(statement_binding_from_proof)
        .collect::<Vec<_>>();
    let first_statement_hashes = first_statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let first_lists =
        commitment_nullifier_lists(&first_block.transactions).expect("first nullifier lists");
    let first_commitment_proof = CommitmentBlockProver::new()
        .prove_from_statement_hashes_with_inputs(
            &first_statement_hashes,
            first_base_tree.root(),
            first_updated_tree.root(),
            kernel_root_from_shielded_root(&first_base_tree.root()),
            kernel_root_from_shielded_root(&first_updated_tree.root()),
            first_updated_nullifiers.commitment(),
            first_block.header.da_root,
            first_lists.nullifiers,
            first_lists.sorted_nullifiers,
        )
        .expect("first commitment proof");
    let first_tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&first_statement_hashes)
            .expect("first tx statements commitment");

    let (first_tx_validity_artifacts, first_receipt_root, first_envelope) =
        build_receipt_root_block_artifacts(&[witness_a.clone(), witness_b.clone()]);
    first_block.proven_batch = Some(ProvenBatch {
        version: 2,
        tx_count: first_block.transactions.len() as u32,
        tx_statements_commitment: first_tx_statements_commitment,
        da_root: first_block.header.da_root,
        da_chunk_count: 1,
        commitment_proof: first_commitment_proof,
        mode: ProvenBatchMode::ReceiptRoot,
        proof_kind: ProofArtifactKind::ReceiptRoot,
        verifier_profile: experimental_native_receipt_root_verifier_profile(),
        receipt_root: Some(first_receipt_root),
    });
    first_block.tx_validity_claims = Some(
        consensus::proof::tx_validity_claims_from_tx_artifacts(
            &first_block.transactions,
            &first_tx_validity_artifacts,
        )
        .expect("first tx validity claims"),
    );
    first_block.tx_statements_commitment = Some(first_tx_statements_commitment);
    first_block.block_artifact = Some(first_envelope);
    first_block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;
    let first_backend_inputs =
        BlockBackendInputs::from_tx_validity_artifacts(first_tx_validity_artifacts);

    let upgrade_leaves = vec![
        input_a0.commitment(),
        input_a1.commitment(),
        input_b0.commitment(),
        input_b1.commitment(),
        witness_a.outputs[0].note.commitment(),
        witness_a.outputs[1].note.commitment(),
        witness_b.outputs[0].note.commitment(),
        witness_b.outputs[1].note.commitment(),
    ];
    let (upgrade_paths, upgrade_root) = build_power_of_two_merkle_tree(&upgrade_leaves);
    let upgrade_root_bytes = felts_to_bytes48(&upgrade_root);
    assert_eq!(upgrade_root_bytes, first_updated_tree.root());

    let witness_c = TransactionWitness {
        inputs: vec![
            InputNoteWitness {
                note: witness_a.outputs[0].note.clone(),
                position: 4,
                rho_seed: [31u8; 32],
                merkle_path: upgrade_paths[4].clone(),
            },
            InputNoteWitness {
                note: witness_a.outputs[1].note.clone(),
                position: 5,
                rho_seed: [32u8; 32],
                merkle_path: upgrade_paths[5].clone(),
            },
        ],
        outputs: vec![
            make_output(90, 2, transaction_circuit::constants::NATIVE_ASSET_ID),
            make_output(100, 5, 1),
        ],
        ciphertext_hashes: vec![[3u8; 48]; 2],
        sk_spend: sk_spend_c,
        merkle_root: upgrade_root_bytes,
        fee: 1,
        value_balance: 0,
        stablecoin: StablecoinPolicyBinding::default(),
        version: TransactionWitness::default_version_binding(),
    };
    let proof_c = prove(&witness_c, &proving_key).expect("upgrade tx proof");
    let second_transactions = vec![transaction_from_proof(&proof_c)];
    let second_params = PowBlockParams {
        height: 2,
        parent_hash: [1u8; 32],
        timestamp_ms: 2_000,
        transactions: second_transactions,
        miner: &miner,
        base_nullifiers: &first_updated_nullifiers,
        base_commitment_tree: &first_updated_tree,
        pow_bits: DEFAULT_GENESIS_POW_BITS,
        nonce: [1u8; 32],
        parent_supply: 1,
        coinbase: dummy_coinbase(2),
    };
    let (mut second_block, _second_updated_nullifiers, second_updated_tree) =
        assemble_pow_block(second_params).expect("assemble second native block");
    let second_statement_bindings = vec![statement_binding_from_proof(&proof_c)];
    let second_statement_hashes = second_statement_bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    let second_lists =
        commitment_nullifier_lists(&second_block.transactions).expect("second nullifier lists");
    let second_commitment_proof = CommitmentBlockProver::new()
        .prove_from_statement_hashes_with_inputs(
            &second_statement_hashes,
            first_updated_tree.root(),
            second_updated_tree.root(),
            kernel_root_from_shielded_root(&first_updated_tree.root()),
            kernel_root_from_shielded_root(&second_updated_tree.root()),
            nullifier_root_for_transactions(&second_block.transactions),
            second_block.header.da_root,
            second_lists.nullifiers,
            second_lists.sorted_nullifiers,
        )
        .expect("second commitment proof");
    let second_tx_statements_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&second_statement_hashes)
            .expect("second tx statements commitment");
    let (tx_validity_artifacts, receipt_root, envelope) =
        build_receipt_root_block_artifacts(&[witness_c]);
    second_block.proven_batch = Some(ProvenBatch {
        version: 2,
        tx_count: second_block.transactions.len() as u32,
        tx_statements_commitment: second_tx_statements_commitment,
        da_root: second_block.header.da_root,
        da_chunk_count: 1,
        commitment_proof: second_commitment_proof,
        mode: ProvenBatchMode::ReceiptRoot,
        proof_kind: ProofArtifactKind::ReceiptRoot,
        verifier_profile: experimental_native_receipt_root_verifier_profile(),
        receipt_root: Some(receipt_root),
    });
    second_block.tx_validity_claims = Some(
        consensus::proof::tx_validity_claims_from_tx_artifacts(
            &second_block.transactions,
            &tx_validity_artifacts,
        )
        .expect("second tx validity claims"),
    );
    second_block.tx_statements_commitment = Some(second_tx_statements_commitment);
    second_block.block_artifact = Some(envelope);
    second_block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;
    let second_backend_inputs =
        BlockBackendInputs::from_tx_validity_artifacts(tx_validity_artifacts);

    (
        first_base_tree,
        first_block,
        first_backend_inputs,
        first_updated_tree,
        second_block,
        second_backend_inputs,
        second_updated_tree.root(),
    )
}

#[test]
#[ignore = "heavy integration: raw-active native path is covered in native-path CI"]
fn raw_active_rejects_bad_tx_proof() {
    let fixture = raw_active_fixture();
    let block = fixture.block.clone();
    let mut backend_inputs = fixture.backend_inputs.clone();
    let artifact = backend_inputs
        .tx_validity_artifacts
        .as_mut()
        .expect("tx artifacts present")
        .first_mut()
        .expect("first tx artifact");
    let envelope = artifact.proof.as_mut().expect("native tx proof envelope");
    let first_byte = *envelope
        .artifact_bytes
        .first()
        .expect("non-empty native tx artifact bytes");
    envelope.artifact_bytes[0] = first_byte.wrapping_add(1);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, Some(&backend_inputs), &fixture.base_tree)
        .expect_err("tampered tx proof must be rejected");
    assert!(matches!(
        err,
        ProofError::TransactionProofInputsMismatch { .. }
            | ProofError::TransactionProofVerification { .. }
            | ProofError::UnsupportedProofArtifact(_)
    ));
}

#[test]
#[ignore = "heavy integration: raw-active native path is covered in native-path CI"]
fn raw_active_rejects_bad_ordering() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    block.transactions.swap(0, 1);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, Some(&fixture.backend_inputs), &fixture.base_tree)
        .expect_err("swapped tx ordering must be rejected");
    assert!(matches!(
        err,
        ProofError::CommitmentProofInputsMismatch(_)
            | ProofError::TransactionProofInputsMismatch { .. }
    ));
}

#[test]
#[ignore = "heavy integration: raw-active native path is covered in native-path CI"]
fn raw_active_rejects_commitment_mismatch() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    block.tx_statements_commitment = Some([9u8; 48]);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, Some(&fixture.backend_inputs), &fixture.base_tree)
        .expect_err("statement commitment mismatch must be rejected");
    assert!(matches!(err, ProofError::CommitmentProofInputsMismatch(_)));
}

#[test]
#[ignore = "heavy integration: raw-active native path is covered in native-path CI"]
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
    block.tx_validity_claims = Some(
        consensus::proof::tx_validity_claims_from_tx_artifacts(
            &block.transactions,
            &tx_validity_artifacts,
        )
        .expect("tx validity claims"),
    );
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;
    let backend_inputs = BlockBackendInputs::from_tx_validity_artifacts(tx_validity_artifacts);

    let verifier = ParallelProofVerifier::new();
    let updated = verifier
        .verify_block_with_backend(&block, Some(&backend_inputs), &fixture.base_tree)
        .expect("valid receipt-root block should verify");
    assert_eq!(updated.root(), fixture.updated_root);
}

#[test]
#[ignore = "heavy integration: native history transition builds multiple receipt-root proofs; cover product path in native-path CI"]
fn native_history_can_transition_to_native_receipt_root() {
    let (
        first_base_tree,
        first_block,
        first_backend_inputs,
        second_base_tree,
        second_block,
        second_backend_inputs,
        final_root,
    ) = build_upgrade_transition_blocks();
    let verifier = ParallelProofVerifier::new();

    let first_updated = verifier
        .verify_block_with_backend(&first_block, Some(&first_backend_inputs), &first_base_tree)
        .expect("historical native receipt_root block should verify");
    assert_eq!(first_updated.root(), second_base_tree.root());

    let second_updated = verifier
        .verify_block_with_backend(
            &second_block,
            Some(&second_backend_inputs),
            &second_base_tree,
        )
        .expect("native receipt_root block should verify after native history");
    assert_eq!(second_updated.root(), final_root);
}

#[test]
#[ignore = "heavy integration: raw-active native path is covered in native-path CI"]
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
    block.block_artifact = Some(envelope);
    block.proof_verification_mode = ProofVerificationMode::SelfContainedAggregation;
    let backend_inputs = BlockBackendInputs::from_tx_validity_artifacts(tx_validity_artifacts);

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, Some(&backend_inputs), &fixture.base_tree)
        .expect_err("receipt-root must reject mismatched statement receipts");
    assert!(matches!(
        err,
        ProofError::ProvenBatchBindingMismatch(_)
            | ProofError::AggregationProofInputsMismatch(_)
            | ProofError::TransactionProofInputsMismatch { .. }
    ));
}

#[test]
#[ignore = "heavy integration: raw-active native path is covered in native-path CI"]
fn raw_active_block_is_accepted() {
    let fixture = raw_active_fixture();
    let verifier = ParallelProofVerifier::new();
    let updated = verifier
        .verify_block_with_backend(
            &fixture.block,
            Some(&fixture.backend_inputs),
            &fixture.base_tree,
        )
        .expect("valid raw-active block should verify");
    assert_eq!(updated.root(), fixture.updated_root);
}

#[test]
#[ignore = "heavy integration: raw-active native path is covered in native-path CI"]
fn raw_active_rejects_duplicate_nullifier_conflict() {
    let fixture = raw_active_fixture();
    let mut block = fixture.block.clone();
    let mut backend_inputs = fixture.backend_inputs.clone();
    block.transactions[1] = block.transactions[0].clone();
    if let Some(artifacts) = backend_inputs.tx_validity_artifacts.as_mut() {
        artifacts[1] = artifacts[0].clone();
    }
    if let Some(claims) = block.tx_validity_claims.as_mut() {
        claims[1] = claims[0].clone();
    }

    let verifier = ParallelProofVerifier::new();
    let err = verifier
        .verify_block_with_backend(&block, Some(&backend_inputs), &fixture.base_tree)
        .expect_err("duplicate-nullifier block must be rejected");
    assert!(matches!(err, ProofError::CommitmentProofInputsMismatch(_)));
}
