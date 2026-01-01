use consensus::{encode_da_blob, verify_da_chunk, DaParams, DaRoot, Transaction, DEFAULT_VERSION_BINDING};
use std::collections::HashMap;

fn build_transaction(tag_seed: u8, ciphertexts: Vec<Vec<u8>>) -> Transaction {
    let nullifier = [tag_seed; 32];
    let commitment = [tag_seed.wrapping_add(1); 32];
    let balance_tag = [tag_seed.wrapping_add(2); 32];
    Transaction::new(
        vec![nullifier],
        vec![commitment],
        balance_tag,
        DEFAULT_VERSION_BINDING,
        ciphertexts,
    )
}

fn verify_sampled_chunks(
    root: DaRoot,
    indices: &[u32],
    proofs: Vec<consensus::DaChunkProof>,
) -> Result<(), String> {
    let mut proof_map = HashMap::new();
    for proof in proofs {
        proof_map.insert(proof.chunk.index, proof);
    }

    for index in indices {
        let proof = proof_map
            .get(index)
            .ok_or_else(|| format!("missing sampled chunk index {}", index))?;
        verify_da_chunk(root, proof).map_err(|err| format!("invalid DA chunk proof: {err}"))?;
    }

    Ok(())
}

#[test]
fn da_sampling_rejects_missing_chunk() {
    let tx_one = build_transaction(1, vec![vec![1u8; 24], vec![2u8; 17]]);
    let tx_two = build_transaction(9, vec![vec![3u8; 19]]);
    let transactions = vec![tx_one, tx_two];
    let params = DaParams {
        chunk_size: 8,
        sample_count: 3,
    };

    let encoding = encode_da_blob(&transactions, params).expect("da encoding");
    let root = encoding.root();
    let chunk_count = encoding.chunks().len();
    assert!(chunk_count >= 3, "need at least 3 chunks for sampling");
    let indices: Vec<u32> = (0..params.sample_count).collect();

    let mut proofs = indices
        .iter()
        .map(|index| encoding.proof(*index).expect("proof"))
        .collect::<Vec<_>>();

    proofs.pop();

    let err = verify_sampled_chunks(root, &indices, proofs).unwrap_err();
    assert!(err.contains("missing sampled chunk index"));
}

#[test]
fn da_sampling_accepts_all_chunks() {
    let tx_one = build_transaction(2, vec![vec![4u8; 21], vec![5u8; 20]]);
    let tx_two = build_transaction(7, vec![vec![6u8; 17], vec![7u8; 18]]);
    let transactions = vec![tx_one, tx_two];
    let params = DaParams {
        chunk_size: 8,
        sample_count: 3,
    };

    let encoding = encode_da_blob(&transactions, params).expect("da encoding");
    let root = encoding.root();
    let chunk_count = encoding.chunks().len();
    assert!(chunk_count >= 3, "need at least 3 chunks for sampling");
    let indices: Vec<u32> = (0..params.sample_count).collect();

    let proofs = indices
        .iter()
        .map(|index| encoding.proof(*index).expect("proof"))
        .collect::<Vec<_>>();

    verify_sampled_chunks(root, &indices, proofs).expect("sampled chunks verify");
}
