//! Plonky3 prover for commitment block proofs.

use blake3::Hasher as Blake3Hasher;
use p3_goldilocks::Goldilocks;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{get_log_num_quotient_chunks, prove_with_preprocessed, setup_preprocessed};
use state_merkle::CommitmentTree;
use transaction_circuit::constants::MAX_INPUTS;
use transaction_circuit::TransactionProof;
use transaction_core::constants::{POSEIDON2_RATE, POSEIDON2_STEPS, POSEIDON2_WIDTH};
use transaction_core::hashing_pq::{felts_to_bytes48, is_canonical_bytes48, Commitment};
use transaction_core::p3_air::CYCLE_LENGTH;
use transaction_core::poseidon2::poseidon2_step;

use crate::error::BlockError;
use crate::commitment_constants::{
    BLOCK_COMMITMENT_DOMAIN_TAG, COL_DA_ROOT0, COL_DA_ROOT1, COL_DA_ROOT2, COL_DA_ROOT3,
    COL_DA_ROOT4, COL_DA_ROOT5, COL_END_ROOT0, COL_END_ROOT1, COL_END_ROOT2, COL_END_ROOT3,
    COL_END_ROOT4, COL_END_ROOT5, COL_INPUT0, COL_INPUT1, COL_INPUT2, COL_INPUT3, COL_INPUT4,
    COL_INPUT5, COL_NF_DIFF_INV, COL_NF_DIFF_NZ, COL_NF_PERM, COL_NF_PERM_INV, COL_NF_S0,
    COL_NF_S1, COL_NF_S2, COL_NF_S3, COL_NF_S4, COL_NF_S5, COL_NF_SORTED_INV,
    COL_NF_SORTED_NZ, COL_NF_U0, COL_NF_U1, COL_NF_U2, COL_NF_U3, COL_NF_U4, COL_NF_U5,
    COL_NULLIFIER_ROOT0, COL_NULLIFIER_ROOT1, COL_NULLIFIER_ROOT2, COL_NULLIFIER_ROOT3,
    COL_NULLIFIER_ROOT4, COL_NULLIFIER_ROOT5, COL_S0, COL_S1, COL_S10, COL_S11, COL_S2, COL_S3,
    COL_S4, COL_S5, COL_S6, COL_S7, COL_S8, COL_S9, COL_START_ROOT0, COL_START_ROOT1,
    COL_START_ROOT2, COL_START_ROOT3, COL_START_ROOT4, COL_START_ROOT5,
};
use crate::p3_commitment_air::{
    CommitmentBlockAirP3, CommitmentBlockPublicInputsP3, CYCLE_BITS, PREPROCESSED_WIDTH,
    TRACE_WIDTH,
};
use transaction_circuit::p3_config::{config_with_fri, FRI_LOG_BLOWUP, FRI_NUM_QUERIES};

type Val = Goldilocks;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBlockProofP3 {
    pub proof_bytes: Vec<u8>,
    pub proof_hash: Commitment,
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
            [0u8; 48],
            [0u8; 48],
            [0u8; 48],
            [0u8; 48],
            nullifiers,
            sorted_nullifiers,
        )
    }

    pub fn prove_block_commitment_with_tree(
        &self,
        tree: &mut CommitmentTree,
        transactions: &[TransactionProof],
        da_root: Commitment,
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
            for &commitment in proof.commitments.iter().filter(|c| **c != [0u8; 48]) {
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
        proof_hashes: &[Commitment],
    ) -> Result<CommitmentBlockProofP3, BlockError> {
        let nullifier_count = proof_hashes.len().saturating_mul(MAX_INPUTS);
        let mut nullifiers = Vec::with_capacity(nullifier_count);
        for idx in 0..nullifier_count {
            let mut nf = [0u8; 48];
            nf[..8].copy_from_slice(&(idx as u64 + 1).to_be_bytes());
            nullifiers.push(nf);
        }
        let sorted_nullifiers = sorted_nullifiers(&nullifiers);
        self.prove_from_hashes_with_inputs(
            proof_hashes,
            [0u8; 48],
            [0u8; 48],
            [0u8; 48],
            [0u8; 48],
            nullifiers,
            sorted_nullifiers,
        )
    }

    pub fn commitment_from_proof_hashes(
        proof_hashes: &[Commitment],
    ) -> Result<Commitment, BlockError> {
        if proof_hashes.is_empty() {
            return Err(BlockError::CommitmentProofEmptyBlock);
        }

        let mut inputs = hashes_to_vals(proof_hashes);
        let input_cycles = proof_hashes.len().max(1);
        let target_len = input_cycles * POSEIDON2_RATE;
        if inputs.len() < target_len {
            inputs.resize(target_len, Val::ZERO);
        }

        let trace_len = CommitmentBlockAirP3::trace_length(proof_hashes.len());
        let total_cycles = trace_len / CYCLE_LENGTH;

        let mut state = [Val::ZERO; POSEIDON2_WIDTH];
        state[0] = Val::from_u64(BLOCK_COMMITMENT_DOMAIN_TAG) + inputs[0];
        state[1] = inputs.get(1).copied().unwrap_or(Val::ZERO);
        state[2] = inputs.get(2).copied().unwrap_or(Val::ZERO);
        state[3] = inputs.get(3).copied().unwrap_or(Val::ZERO);
        state[4] = inputs.get(4).copied().unwrap_or(Val::ZERO);
        state[5] = inputs.get(5).copied().unwrap_or(Val::ZERO);
        state[POSEIDON2_WIDTH - 1] = Val::ONE;

        let mut output = [Val::ZERO; 6];
        for cycle in 0..total_cycles {
            let chunk_index = cycle;
            let (next_input0, next_input1, next_input2, next_input3, next_input4, next_input5) =
                if chunk_index + 1 < input_cycles {
                    let next_idx = (chunk_index + 1) * POSEIDON2_RATE;
                    (
                        inputs[next_idx],
                        inputs[next_idx + 1],
                        inputs[next_idx + 2],
                        inputs[next_idx + 3],
                        inputs[next_idx + 4],
                        inputs[next_idx + 5],
                    )
                } else {
                    (Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO)
                };

            for step in 0..CYCLE_LENGTH {
                if step + 1 == CYCLE_LENGTH && cycle + 1 == total_cycles {
                    output = [state[0], state[1], state[2], state[3], state[4], state[5]];
                }

                if step < POSEIDON2_STEPS {
                    poseidon2_step(&mut state, step);
                } else if step + 1 == CYCLE_LENGTH {
                    state[0] += next_input0;
                    state[1] += next_input1;
                    state[2] += next_input2;
                    state[3] += next_input3;
                    state[4] += next_input4;
                    state[5] += next_input5;
                }
            }
        }

        Ok(felts_to_bytes48(&output))
    }

    pub fn prove_from_hashes_with_inputs(
        &self,
        proof_hashes: &[Commitment],
        starting_state_root: Commitment,
        ending_state_root: Commitment,
        nullifier_root: Commitment,
        da_root: Commitment,
        nullifiers: Vec<Commitment>,
        sorted_nullifiers: Vec<Commitment>,
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
        if nullifiers.iter().all(|nf| *nf == [0u8; 48]) {
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

        let start_root_vals = bytes48_to_vals("starting_state_root", &starting_state_root)?;
        let end_root_vals = bytes48_to_vals("ending_state_root", &ending_state_root)?;
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

        let air = CommitmentBlockAirP3::new(pub_inputs.tx_count as usize);
        let pub_inputs_vec = pub_inputs.to_vec();
        let num_public_values = pub_inputs_vec.len();
        let log_chunks = get_log_num_quotient_chunks::<Val, _>(
            &air,
            PREPROCESSED_WIDTH,
            num_public_values,
            0,
        );
        let log_blowup = FRI_LOG_BLOWUP.max(log_chunks);
        let config = config_with_fri(log_blowup, FRI_NUM_QUERIES);
        let degree_bits = trace.height().ilog2() as usize;
        let (prep_prover, _) = setup_preprocessed(&config.config, &air, degree_bits)
            .expect("CommitmentBlockAirP3 preprocessed trace missing");
        let proof = prove_with_preprocessed(
            &config.config,
            &air,
            trace,
            &pub_inputs_vec,
            Some(&prep_prover),
        );
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|_| BlockError::CommitmentProofGeneration("serialize failed".into()))?;
        let proof_hash = blake3_384(&proof_bytes);

        Ok(CommitmentBlockProofP3 {
            proof_bytes,
            proof_hash,
            public_inputs: pub_inputs,
        })
    }

    fn build_trace(
        &self,
        proof_hashes: &[Commitment],
        starting_state_root: &[Val; 6],
        ending_state_root: &[Val; 6],
        nullifier_root: &[Val; 6],
        da_root: &[Val; 6],
        nullifiers: &[Commitment],
        sorted_nullifiers: &[Commitment],
        perm_alpha: Val,
        perm_beta: Val,
    ) -> Result<(RowMajorMatrix<Val>, [Val; 6]), BlockError> {
        let mut inputs = hashes_to_vals(proof_hashes);
        let tx_count = proof_hashes.len();
        let input_cycles = tx_count.max(1);
        let target_len = input_cycles * POSEIDON2_RATE;
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

        let mut state = [Val::ZERO; POSEIDON2_WIDTH];
        state[0] = Val::from_u64(BLOCK_COMMITMENT_DOMAIN_TAG) + inputs[0];
        state[1] = inputs.get(1).copied().unwrap_or(Val::ZERO);
        state[2] = inputs.get(2).copied().unwrap_or(Val::ZERO);
        state[3] = inputs.get(3).copied().unwrap_or(Val::ZERO);
        state[4] = inputs.get(4).copied().unwrap_or(Val::ZERO);
        state[5] = inputs.get(5).copied().unwrap_or(Val::ZERO);
        state[POSEIDON2_WIDTH - 1] = Val::ONE;

        let mut output = [Val::ZERO; 6];

        for cycle in 0..total_cycles {
            let chunk_index = cycle;
            let (input0, input1, input2, input3, input4, input5) = if chunk_index < input_cycles {
                let idx = chunk_index * POSEIDON2_RATE;
                (
                    inputs[idx],
                    inputs[idx + 1],
                    inputs[idx + 2],
                    inputs[idx + 3],
                    inputs[idx + 4],
                    inputs[idx + 5],
                )
            } else {
                (Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO)
            };
            let (next_input0, next_input1, next_input2, next_input3, next_input4, next_input5) =
                if chunk_index + 1 < input_cycles {
                    let next_idx = (chunk_index + 1) * POSEIDON2_RATE;
                    (
                        inputs[next_idx],
                        inputs[next_idx + 1],
                        inputs[next_idx + 2],
                        inputs[next_idx + 3],
                        inputs[next_idx + 4],
                        inputs[next_idx + 5],
                    )
                } else {
                    (Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO)
                };

            let cycle_start = cycle * CYCLE_LENGTH;
            for step in 0..CYCLE_LENGTH {
                let row = cycle_start + step;
                let row_slice = trace.row_mut(row);
                row_slice[COL_S0] = state[0];
                row_slice[COL_S1] = state[1];
                row_slice[COL_S2] = state[2];
                row_slice[COL_S3] = state[3];
                row_slice[COL_S4] = state[4];
                row_slice[COL_S5] = state[5];
                row_slice[COL_S6] = state[6];
                row_slice[COL_S7] = state[7];
                row_slice[COL_S8] = state[8];
                row_slice[COL_S9] = state[9];
                row_slice[COL_S10] = state[10];
                row_slice[COL_S11] = state[11];
                row_slice[COL_INPUT0] = input0;
                row_slice[COL_INPUT1] = input1;
                row_slice[COL_INPUT2] = input2;
                row_slice[COL_INPUT3] = input3;
                row_slice[COL_INPUT4] = input4;
                row_slice[COL_INPUT5] = input5;

                if row + 1 < trace_len {
                    if step < POSEIDON2_STEPS {
                        poseidon2_step(&mut state, step);
                    } else if step + 1 == CYCLE_LENGTH {
                        state[0] += next_input0;
                        state[1] += next_input1;
                        state[2] += next_input2;
                        state[3] += next_input3;
                        state[4] += next_input4;
                        state[5] += next_input5;
                    }
                }

                if step + 1 == CYCLE_LENGTH {
                    if cycle + 1 == total_cycles {
                        output = [
                            row_slice[COL_S0],
                            row_slice[COL_S1],
                            row_slice[COL_S2],
                            row_slice[COL_S3],
                            row_slice[COL_S4],
                            row_slice[COL_S5],
                        ];
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
        let alpha4 = alpha3 * perm_alpha;
        let alpha5 = alpha4 * perm_alpha;
        let sorted_compressed: Vec<Val> = sorted_nullifier_felts
            .iter()
            .map(|limbs| compress_nullifier(limbs, perm_alpha, alpha2, alpha3, alpha4, alpha5))
            .collect();
        let mut perm = Val::ONE;
        for (row, u_limbs) in nullifier_felts.iter().enumerate() {
            let u = compress_nullifier(u_limbs, perm_alpha, alpha2, alpha3, alpha4, alpha5);
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
            row_slice[COL_NF_U4] = u_limbs[4];
            row_slice[COL_NF_U5] = u_limbs[5];
            let s_limbs = sorted_nullifier_felts[row];
            row_slice[COL_NF_S0] = s_limbs[0];
            row_slice[COL_NF_S1] = s_limbs[1];
            row_slice[COL_NF_S2] = s_limbs[2];
            row_slice[COL_NF_S3] = s_limbs[3];
            row_slice[COL_NF_S4] = s_limbs[4];
            row_slice[COL_NF_S5] = s_limbs[5];
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
            row_slice[COL_START_ROOT4] = starting_state_root[4];
            row_slice[COL_START_ROOT5] = starting_state_root[5];
            row_slice[COL_END_ROOT0] = ending_state_root[0];
            row_slice[COL_END_ROOT1] = ending_state_root[1];
            row_slice[COL_END_ROOT2] = ending_state_root[2];
            row_slice[COL_END_ROOT3] = ending_state_root[3];
            row_slice[COL_END_ROOT4] = ending_state_root[4];
            row_slice[COL_END_ROOT5] = ending_state_root[5];
            row_slice[COL_NULLIFIER_ROOT0] = nullifier_root[0];
            row_slice[COL_NULLIFIER_ROOT1] = nullifier_root[1];
            row_slice[COL_NULLIFIER_ROOT2] = nullifier_root[2];
            row_slice[COL_NULLIFIER_ROOT3] = nullifier_root[3];
            row_slice[COL_NULLIFIER_ROOT4] = nullifier_root[4];
            row_slice[COL_NULLIFIER_ROOT5] = nullifier_root[5];
            row_slice[COL_DA_ROOT0] = da_root[0];
            row_slice[COL_DA_ROOT1] = da_root[1];
            row_slice[COL_DA_ROOT2] = da_root[2];
            row_slice[COL_DA_ROOT3] = da_root[3];
            row_slice[COL_DA_ROOT4] = da_root[4];
            row_slice[COL_DA_ROOT5] = da_root[5];
        }

        Ok((trace, output))
    }
}

fn proof_hashes_from_transactions(
    transactions: &[TransactionProof],
) -> Result<Vec<Commitment>, BlockError> {
    let mut hashes = Vec::with_capacity(transactions.len());
    for (index, tx) in transactions.iter().enumerate() {
        if tx.stark_proof.is_empty() {
            return Err(BlockError::MissingStarkProof { index });
        }
        hashes.push(blake3_384(&tx.stark_proof));
    }
    Ok(hashes)
}

fn nullifiers_from_transactions(
    transactions: &[TransactionProof],
) -> Result<Vec<Commitment>, BlockError> {
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

fn sorted_nullifiers(nullifiers: &[Commitment]) -> Vec<Commitment> {
    let mut sorted = nullifiers.to_vec();
    sorted.sort_unstable();
    sorted
}

fn blake3_384(data: &[u8]) -> Commitment {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hashes_to_vals(hashes: &[Commitment]) -> Vec<Val> {
    let mut elements = Vec::with_capacity(hashes.len() * 6);
    for hash in hashes {
        elements.extend_from_slice(&hash_bytes_to_vals(hash));
    }
    elements
}

fn hash_bytes_to_vals(bytes: &Commitment) -> [Val; 6] {
    let mut felts = [Val::ZERO; 6];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        felts[idx] = Val::from_u64(limb);
    }
    felts
}

fn bytes48_to_vals(label: &str, value: &Commitment) -> Result<[Val; 6], BlockError> {
    if !is_canonical_bytes48(value) {
        return Err(BlockError::CommitmentProofInvalidInputs(format!(
            "{label} encoding is non-canonical"
        )));
    }
    Ok(hash_bytes_to_vals(value))
}

fn decode_nullifier_list(
    label: &str,
    nullifiers: &[Commitment],
) -> Result<Vec<[Val; 6]>, BlockError> {
    let mut felts = Vec::with_capacity(nullifiers.len());
    for (idx, nf) in nullifiers.iter().enumerate() {
        if !is_canonical_bytes48(nf) {
            return Err(BlockError::CommitmentProofInvalidInputs(format!(
                "{label}[{idx}] encoding is non-canonical"
            )));
        }
        felts.push(hash_bytes_to_vals(nf));
    }
    Ok(felts)
}

fn compress_nullifier(
    limbs: &[Val; 6],
    alpha: Val,
    alpha2: Val,
    alpha3: Val,
    alpha4: Val,
    alpha5: Val,
) -> Val {
    limbs[0]
        + limbs[1] * alpha
        + limbs[2] * alpha2
        + limbs[3] * alpha3
        + limbs[4] * alpha4
        + limbs[5] * alpha5
}

fn invert_with_flag(value: Val) -> (Val, Val) {
    if value.is_zero() {
        (Val::ZERO, Val::ZERO)
    } else {
        (value.inverse(), Val::ONE)
    }
}

fn validate_commitment_bytes(label: &str, value: &Commitment) -> Result<(), BlockError> {
    if !is_canonical_bytes48(value) {
        return Err(BlockError::CommitmentProofInvalidInputs(format!(
            "{label} encoding is non-canonical"
        )));
    }
    Ok(())
}

fn derive_nullifier_challenges(
    starting_state_root: &Commitment,
    ending_state_root: &Commitment,
    nullifier_root: &Commitment,
    da_root: &Commitment,
    tx_count: u32,
    nullifiers: &[Commitment],
    sorted_nullifiers: &[Commitment],
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
) -> Result<Commitment, BlockError> {
    use std::collections::BTreeSet;

    let mut entries = BTreeSet::new();
    for proof in transactions {
        for &nullifier in &proof.nullifiers {
            if nullifier == [0u8; 48] {
                continue;
            }
            if !entries.insert(nullifier) {
                return Err(BlockError::DuplicateNullifier(nullifier));
            }
        }
    }
    let mut data = Vec::with_capacity(entries.len() * 48);
    for entry in entries {
        data.extend_from_slice(&entry);
    }
    Ok(blake3_384(&data))
}
