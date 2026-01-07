//! Plonky3 prover for commitment block proofs.

use blake3::Hasher as Blake3Hasher;
use p3_goldilocks::Goldilocks;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed};
use state_merkle::CommitmentTree;
use transaction_circuit::constants::{MAX_INPUTS, POSEIDON_ROUNDS};
use transaction_circuit::hashing::is_canonical_bytes32;
use transaction_circuit::TransactionProof;
use transaction_core::p3_air::{poseidon_round, CYCLE_LENGTH};

use crate::error::BlockError;
use crate::commitment_air::{
    BLOCK_COMMITMENT_DOMAIN_TAG, COL_DA_ROOT0, COL_DA_ROOT1, COL_DA_ROOT2, COL_DA_ROOT3,
    COL_END_ROOT0, COL_END_ROOT1, COL_END_ROOT2, COL_END_ROOT3, COL_INPUT0, COL_INPUT1,
    COL_NF_DIFF_INV, COL_NF_DIFF_NZ, COL_NF_PERM, COL_NF_PERM_INV, COL_NF_S0, COL_NF_S1,
    COL_NF_S2, COL_NF_S3, COL_NF_SORTED_INV, COL_NF_SORTED_NZ, COL_NF_U0, COL_NF_U1, COL_NF_U2,
    COL_NF_U3, COL_NULLIFIER_ROOT0, COL_NULLIFIER_ROOT1, COL_NULLIFIER_ROOT2, COL_NULLIFIER_ROOT3,
    COL_S0, COL_S1, COL_S2, COL_START_ROOT0, COL_START_ROOT1, COL_START_ROOT2, COL_START_ROOT3,
};
use crate::p3_commitment_air::{
    CommitmentBlockAirP3, CommitmentBlockPublicInputsP3, CYCLE_BITS, TRACE_WIDTH,
};
use transaction_circuit::p3_config::default_config;

type Val = Goldilocks;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBlockProofP3 {
    pub proof_bytes: Vec<u8>,
    pub proof_hash: [u8; 32],
    pub public_inputs: CommitmentBlockPublicInputsP3,
}

pub struct CommitmentBlockProverP3;

impl CommitmentBlockProverP3 {
    pub fn new() -> Self {
        Self
    }

    pub fn prove_block_commitment(
        &self,
        transactions: &[TransactionProof],
    ) -> Result<CommitmentBlockProofP3, BlockError> {
        let proof_hashes = proof_hashes_from_transactions(transactions)?;
        let nullifiers = nullifiers_from_transactions(transactions)?;
        let sorted_nullifiers = sorted_nullifiers(&nullifiers);
        self.prove_from_hashes_with_inputs(
            &proof_hashes,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            nullifiers,
            sorted_nullifiers,
        )
    }

    pub fn prove_block_commitment_with_tree(
        &self,
        tree: &mut CommitmentTree,
        transactions: &[TransactionProof],
        da_root: [u8; 32],
    ) -> Result<CommitmentBlockProofP3, BlockError> {
        if transactions.is_empty() {
            return Err(BlockError::CommitmentProofEmptyBlock);
        }

        let starting_root = tree.root();
        let nullifier_root = nullifier_root_from_transactions(transactions)?;
        let nullifiers = nullifiers_from_transactions(transactions)?;
        let sorted_nullifiers = sorted_nullifiers(&nullifiers);

        for (index, proof) in transactions.iter().enumerate() {
            let anchor = proof.public_inputs.merkle_root;
            if !tree.root_history().contains(&anchor) {
                return Err(BlockError::UnexpectedMerkleRoot {
                    index,
                    expected: tree.root(),
                    reported: anchor,
                });
            }
            for &commitment in proof.commitments.iter().filter(|c| **c != [0u8; 32]) {
                tree.append(commitment)?;
            }
        }

        let ending_root = tree.root();
        let proof_hashes = proof_hashes_from_transactions(transactions)?;
        self.prove_from_hashes_with_inputs(
            &proof_hashes,
            starting_root,
            ending_root,
            nullifier_root,
            da_root,
            nullifiers,
            sorted_nullifiers,
        )
    }

    pub fn prove_from_hashes(
        &self,
        proof_hashes: &[[u8; 32]],
    ) -> Result<CommitmentBlockProofP3, BlockError> {
        let nullifier_count = proof_hashes.len().saturating_mul(MAX_INPUTS);
        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for idx in 0..nullifier_count {
            let mut nf = [0u8; 32];
            nf[..8].copy_from_slice(&(idx as u64 + 1).to_be_bytes());
            nullifiers.push(nf);
        }
        let sorted_nullifiers = sorted_nullifiers(&nullifiers);
        self.prove_from_hashes_with_inputs(
            proof_hashes,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            nullifiers,
            sorted_nullifiers,
        )
    }

    pub fn prove_from_hashes_with_inputs(
        &self,
        proof_hashes: &[[u8; 32]],
        starting_state_root: [u8; 32],
        ending_state_root: [u8; 32],
        nullifier_root: [u8; 32],
        da_root: [u8; 32],
        nullifiers: Vec<[u8; 32]>,
        sorted_nullifiers: Vec<[u8; 32]>,
    ) -> Result<CommitmentBlockProofP3, BlockError> {
        if proof_hashes.is_empty() {
            return Err(BlockError::CommitmentProofEmptyBlock);
        }
        validate_commitment_bytes("starting_state_root", &starting_state_root)?;
        validate_commitment_bytes("ending_state_root", &ending_state_root)?;

        let expected_nullifiers = proof_hashes.len().saturating_mul(MAX_INPUTS);
        if nullifiers.len() != expected_nullifiers {
            return Err(BlockError::CommitmentProofInvalidInputs(format!(
                "nullifier length mismatch (expected {}, got {})",
                expected_nullifiers,
                nullifiers.len()
            )));
        }
        if sorted_nullifiers.len() != expected_nullifiers {
            return Err(BlockError::CommitmentProofInvalidInputs(format!(
                "sorted nullifier length mismatch (expected {}, got {})",
                expected_nullifiers,
                sorted_nullifiers.len()
            )));
        }
        if !sorted_nullifiers.windows(2).all(|pair| pair[0] <= pair[1]) {
            return Err(BlockError::CommitmentProofInvalidInputs(
                "sorted nullifiers are not ordered".to_string(),
            ));
        }
        if nullifiers.iter().all(|nf| *nf == [0u8; 32]) {
            return Err(BlockError::CommitmentProofInvalidInputs(
                "nullifier list must include at least one non-zero entry".to_string(),
            ));
        }
        for (idx, nf) in nullifiers.iter().enumerate() {
            validate_commitment_bytes(&format!("nullifiers[{idx}]"), nf)?;
        }
        for (idx, nf) in sorted_nullifiers.iter().enumerate() {
            validate_commitment_bytes(&format!("sorted_nullifiers[{idx}]"), nf)?;
        }

        let start_root_vals = bytes32_to_vals("starting_state_root", &starting_state_root)?;
        let end_root_vals = bytes32_to_vals("ending_state_root", &ending_state_root)?;
        let nullifier_root_vals = hash_bytes_to_vals(&nullifier_root);
        let da_root_vals = hash_bytes_to_vals(&da_root);
        let (perm_alpha, perm_beta) = derive_nullifier_challenges(
            &starting_state_root,
            &ending_state_root,
            &nullifier_root,
            &da_root,
            proof_hashes.len() as u32,
            &nullifiers,
            &sorted_nullifiers,
        );

        let (trace, commitment_vals) = self.build_trace(
            proof_hashes,
            &start_root_vals,
            &end_root_vals,
            &nullifier_root_vals,
            &da_root_vals,
            &nullifiers,
            &sorted_nullifiers,
            perm_alpha,
            perm_beta,
        )?;

        let pub_inputs = CommitmentBlockPublicInputsP3 {
            tx_proofs_commitment: commitment_vals,
            starting_state_root: start_root_vals,
            ending_state_root: end_root_vals,
            nullifier_root: nullifier_root_vals,
            da_root: da_root_vals,
            tx_count: proof_hashes.len() as u32,
            perm_alpha,
            perm_beta,
            nullifiers: decode_nullifier_list("nullifiers", &nullifiers)?,
            sorted_nullifiers: decode_nullifier_list("sorted_nullifiers", &sorted_nullifiers)?,
        };

        let config = default_config();
        let air = CommitmentBlockAirP3::new(pub_inputs.tx_count as usize);
        let degree_bits = trace.height().ilog2() as usize;
        let (prep_prover, _) = setup_preprocessed(&config.config, &air, degree_bits)
            .expect("CommitmentBlockAirP3 preprocessed trace missing");
        let proof = prove_with_preprocessed(
            &config.config,
            &air,
            trace,
            &pub_inputs.to_vec(),
            Some(&prep_prover),
        );
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|_| BlockError::CommitmentProofGeneration("serialize failed".into()))?;
        let proof_hash = blake3_256(&proof_bytes);

        Ok(CommitmentBlockProofP3 {
            proof_bytes,
            proof_hash,
            public_inputs: pub_inputs,
        })
    }

    fn build_trace(
        &self,
        proof_hashes: &[[u8; 32]],
        starting_state_root: &[Val; 4],
        ending_state_root: &[Val; 4],
        nullifier_root: &[Val; 4],
        da_root: &[Val; 4],
        nullifiers: &[[u8; 32]],
        sorted_nullifiers: &[[u8; 32]],
        perm_alpha: Val,
        perm_beta: Val,
    ) -> Result<(RowMajorMatrix<Val>, [Val; 4]), BlockError> {
        let mut inputs = hashes_to_vals(proof_hashes);
        let tx_count = proof_hashes.len();
        let input_cycles = tx_count.saturating_mul(2);
        let target_len = input_cycles * 2;
        if inputs.len() < target_len {
            inputs.resize(target_len, Val::ZERO);
        }

        let trace_len = CommitmentBlockAirP3::trace_length(tx_count);
        let total_cycles = trace_len / CYCLE_LENGTH;
        if (total_cycles as u64) > (1u64 << CYCLE_BITS) {
            return Err(BlockError::CommitmentProofInvalidInputs(
                "trace exceeds cycle counter capacity".into(),
            ));
        }

        let mut trace = RowMajorMatrix::new(vec![Val::ZERO; trace_len * TRACE_WIDTH], TRACE_WIDTH);

        let init0 = inputs.first().copied().unwrap_or(Val::ZERO);
        let init1 = inputs.get(1).copied().unwrap_or(Val::ZERO);
        let mut state = [
            Val::from_u64(BLOCK_COMMITMENT_DOMAIN_TAG) + init0,
            init1,
            Val::ONE,
        ];

        let mut output0 = Val::ZERO;
        let mut output1 = Val::ZERO;
        let mut output2 = Val::ZERO;
        let mut output3 = Val::ZERO;

        for cycle in 0..total_cycles {
            let pair_index = cycle;
            let (input0, input1) = if pair_index < input_cycles {
                let idx = pair_index * 2;
                (inputs[idx], inputs[idx + 1])
            } else {
                (Val::ZERO, Val::ZERO)
            };
            let (next_input0, next_input1) = if pair_index + 1 < input_cycles {
                let next_idx = (pair_index + 1) * 2;
                (inputs[next_idx], inputs[next_idx + 1])
            } else {
                (Val::ZERO, Val::ZERO)
            };

            let cycle_start = cycle * CYCLE_LENGTH;
            for step in 0..CYCLE_LENGTH {
                let row = cycle_start + step;
                let row_slice = trace.row_mut(row);
                row_slice[COL_S0] = state[0];
                row_slice[COL_S1] = state[1];
                row_slice[COL_S2] = state[2];
                row_slice[COL_INPUT0] = input0;
                row_slice[COL_INPUT1] = input1;

                if row + 1 < trace_len {
                    if step < POSEIDON_ROUNDS {
                        poseidon_round(&mut state, step);
                    } else {
                        state[0] += next_input0;
                        state[1] += next_input1;
                    }
                }

                if step + 1 == CYCLE_LENGTH {
                    if cycle + 1 == input_cycles {
                        output0 = row_slice[COL_S0];
                        output1 = row_slice[COL_S1];
                    }
                    if cycle + 1 == total_cycles {
                        output2 = row_slice[COL_S0];
                        output3 = row_slice[COL_S1];
                    }
                }
            }
        }

        let nullifier_felts = decode_nullifier_list("nullifiers", nullifiers)?;
        let sorted_nullifier_felts = decode_nullifier_list("sorted_nullifiers", sorted_nullifiers)?;
        let nullifier_count = nullifier_felts.len();
        if nullifier_count + 1 > trace_len {
            return Err(BlockError::CommitmentProofInvalidInputs(
                "nullifier rows exceed trace length".into(),
            ));
        }

        let alpha2 = perm_alpha * perm_alpha;
        let alpha3 = alpha2 * perm_alpha;
        let sorted_compressed: Vec<Val> = sorted_nullifier_felts
            .iter()
            .map(|limbs| compress_nullifier(limbs, perm_alpha, alpha2, alpha3))
            .collect();
        let mut perm = Val::ONE;
        for (row, u_limbs) in nullifier_felts.iter().enumerate() {
            let u = compress_nullifier(u_limbs, perm_alpha, alpha2, alpha3);
            let v = sorted_compressed[row];
            let denom = v + perm_beta;
            if denom.is_zero() {
                return Err(BlockError::CommitmentProofInvalidInputs(
                    "nullifier permutation denominator is zero".to_string(),
                ));
            }
            let (v_inv, v_nz) = invert_with_flag(v);
            let inv = denom.inverse();
            let row_slice = trace.row_mut(row);
            row_slice[COL_NF_PERM] = perm;
            row_slice[COL_NF_PERM_INV] = inv;
            row_slice[COL_NF_SORTED_INV] = v_inv;
            row_slice[COL_NF_SORTED_NZ] = v_nz;
            row_slice[COL_NF_U0] = u_limbs[0];
            row_slice[COL_NF_U1] = u_limbs[1];
            row_slice[COL_NF_U2] = u_limbs[2];
            row_slice[COL_NF_U3] = u_limbs[3];
            let s_limbs = sorted_nullifier_felts[row];
            row_slice[COL_NF_S0] = s_limbs[0];
            row_slice[COL_NF_S1] = s_limbs[1];
            row_slice[COL_NF_S2] = s_limbs[2];
            row_slice[COL_NF_S3] = s_limbs[3];
            perm = perm * (u + perm_beta) * inv;
        }
        trace.row_mut(nullifier_count)[COL_NF_PERM] = perm;

        for row in 0..nullifier_count.saturating_sub(1) {
            let next_row = row + 1;
            let (inv, nz) = invert_with_flag(sorted_compressed[next_row] - sorted_compressed[row]);
            let row_slice = trace.row_mut(row);
            row_slice[COL_NF_DIFF_INV] = inv;
            row_slice[COL_NF_DIFF_NZ] = nz;
        }

        for row in 0..trace_len {
            let row_slice = trace.row_mut(row);
            row_slice[COL_START_ROOT0] = starting_state_root[0];
            row_slice[COL_START_ROOT1] = starting_state_root[1];
            row_slice[COL_START_ROOT2] = starting_state_root[2];
            row_slice[COL_START_ROOT3] = starting_state_root[3];
            row_slice[COL_END_ROOT0] = ending_state_root[0];
            row_slice[COL_END_ROOT1] = ending_state_root[1];
            row_slice[COL_END_ROOT2] = ending_state_root[2];
            row_slice[COL_END_ROOT3] = ending_state_root[3];
            row_slice[COL_NULLIFIER_ROOT0] = nullifier_root[0];
            row_slice[COL_NULLIFIER_ROOT1] = nullifier_root[1];
            row_slice[COL_NULLIFIER_ROOT2] = nullifier_root[2];
            row_slice[COL_NULLIFIER_ROOT3] = nullifier_root[3];
            row_slice[COL_DA_ROOT0] = da_root[0];
            row_slice[COL_DA_ROOT1] = da_root[1];
            row_slice[COL_DA_ROOT2] = da_root[2];
            row_slice[COL_DA_ROOT3] = da_root[3];
        }

        Ok((trace, [output0, output1, output2, output3]))
    }
}

fn proof_hashes_from_transactions(
    transactions: &[TransactionProof],
) -> Result<Vec<[u8; 32]>, BlockError> {
    let mut hashes = Vec::with_capacity(transactions.len());
    for (index, tx) in transactions.iter().enumerate() {
        if tx.stark_proof.is_empty() {
            return Err(BlockError::MissingStarkProof { index });
        }
        hashes.push(blake3_256(&tx.stark_proof));
    }
    Ok(hashes)
}

fn nullifiers_from_transactions(
    transactions: &[TransactionProof],
) -> Result<Vec<[u8; 32]>, BlockError> {
    let mut nullifiers = Vec::with_capacity(transactions.len().saturating_mul(MAX_INPUTS));
    for (index, tx) in transactions.iter().enumerate() {
        if tx.nullifiers.len() != MAX_INPUTS {
            return Err(BlockError::CommitmentProofInvalidInputs(format!(
                "transaction {index} nullifier length mismatch"
            )));
        }
        nullifiers.extend_from_slice(&tx.nullifiers);
    }
    Ok(nullifiers)
}

fn sorted_nullifiers(nullifiers: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut sorted = nullifiers.to_vec();
    sorted.sort_unstable();
    sorted
}

fn blake3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn hashes_to_vals(hashes: &[[u8; 32]]) -> Vec<Val> {
    let mut elements = Vec::with_capacity(hashes.len() * 4);
    for hash in hashes {
        elements.extend_from_slice(&hash_bytes_to_vals(hash));
    }
    elements
}

fn hash_bytes_to_vals(bytes: &[u8; 32]) -> [Val; 4] {
    let mut felts = [Val::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        felts[idx] = Val::from_u64(limb);
    }
    felts
}

fn bytes32_to_vals(label: &str, value: &[u8; 32]) -> Result<[Val; 4], BlockError> {
    if !is_canonical_bytes32(value) {
        return Err(BlockError::CommitmentProofInvalidInputs(format!(
            "{label} encoding is non-canonical"
        )));
    }
    Ok(hash_bytes_to_vals(value))
}

fn decode_nullifier_list(
    label: &str,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<[Val; 4]>, BlockError> {
    let mut felts = Vec::with_capacity(nullifiers.len());
    for (idx, nf) in nullifiers.iter().enumerate() {
        if !is_canonical_bytes32(nf) {
            return Err(BlockError::CommitmentProofInvalidInputs(format!(
                "{label}[{idx}] encoding is non-canonical"
            )));
        }
        felts.push(hash_bytes_to_vals(nf));
    }
    Ok(felts)
}

fn compress_nullifier(
    limbs: &[Val; 4],
    alpha: Val,
    alpha2: Val,
    alpha3: Val,
) -> Val {
    limbs[0] + limbs[1] * alpha + limbs[2] * alpha2 + limbs[3] * alpha3
}

fn invert_with_flag(value: Val) -> (Val, Val) {
    if value.is_zero() {
        (Val::ZERO, Val::ZERO)
    } else {
        (value.inverse(), Val::ONE)
    }
}

fn validate_commitment_bytes(label: &str, value: &[u8; 32]) -> Result<(), BlockError> {
    if !is_canonical_bytes32(value) {
        return Err(BlockError::CommitmentProofInvalidInputs(format!(
            "{label} encoding is non-canonical"
        )));
    }
    Ok(())
}

fn derive_nullifier_challenges(
    starting_state_root: &[u8; 32],
    ending_state_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    da_root: &[u8; 32],
    tx_count: u32,
    nullifiers: &[[u8; 32]],
    sorted_nullifiers: &[[u8; 32]],
) -> (Val, Val) {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"blk-nullifier-perm-v1");
    hasher.update(starting_state_root);
    hasher.update(ending_state_root);
    hasher.update(nullifier_root);
    hasher.update(da_root);
    hasher.update(&tx_count.to_le_bytes());
    hasher.update(&(nullifiers.len() as u64).to_le_bytes());
    hasher.update(&(sorted_nullifiers.len() as u64).to_le_bytes());
    for nullifier in nullifiers {
        hasher.update(nullifier);
    }
    for nullifier in sorted_nullifiers {
        hasher.update(nullifier);
    }
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    let mut alpha = Val::from_u64(u64::from_le_bytes(
        bytes[0..8].try_into().expect("8-byte alpha"),
    ));
    let mut beta = Val::from_u64(u64::from_le_bytes(
        bytes[8..16].try_into().expect("8-byte beta"),
    ));
    if alpha.is_zero() {
        alpha = Val::ONE;
    }
    if beta.is_zero() {
        beta = Val::from_u64(2);
    }
    (alpha, beta)
}

fn nullifier_root_from_transactions(
    transactions: &[TransactionProof],
) -> Result<[u8; 32], BlockError> {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    let mut entries = BTreeSet::new();
    for proof in transactions {
        for &nullifier in &proof.nullifiers {
            if nullifier == [0u8; 32] {
                continue;
            }
            if !entries.insert(nullifier) {
                return Err(BlockError::DuplicateNullifier(nullifier));
            }
        }
    }
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry);
    }
    let digest = hasher.finalize();
    Ok(digest.into())
}
