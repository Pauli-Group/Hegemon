use blake3::Hasher as Blake3Hasher;
use state_merkle::CommitmentTree;
use transaction_circuit::constants::{MAX_INPUTS, POSEIDON_ROUNDS};
use transaction_circuit::hashing::{bytes32_to_felts, felts_to_bytes32, is_canonical_bytes32};
use transaction_circuit::stark_air::{mds_mix, round_constant, sbox, CYCLE_LENGTH};
use transaction_circuit::TransactionProof;
use winter_crypto::hashers::Blake3_256;
use winter_crypto::MerkleTree;
use winterfell::{
    crypto::DefaultRandomCoin,
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    verify, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Proof, ProofOptions, Prover,
    StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::commitment_air::{
    derive_nullifier_challenges, CommitmentBlockAir, CommitmentBlockPublicInputs,
    BLOCK_COMMITMENT_DOMAIN_TAG, COL_DA_ROOT0, COL_DA_ROOT1, COL_DA_ROOT2, COL_DA_ROOT3,
    COL_END_ROOT0, COL_END_ROOT1, COL_END_ROOT2, COL_END_ROOT3, COL_INPUT0, COL_INPUT1,
    COL_NF_DIFF_INV, COL_NF_DIFF_NZ, COL_NF_PERM, COL_NF_PERM_INV, COL_NF_S0, COL_NF_S1,
    COL_NF_S2, COL_NF_S3, COL_NF_SORTED_INV, COL_NF_SORTED_NZ, COL_NF_U0, COL_NF_U1, COL_NF_U2,
    COL_NF_U3, COL_NULLIFIER_ROOT0, COL_NULLIFIER_ROOT1, COL_NULLIFIER_ROOT2, COL_NULLIFIER_ROOT3,
    COL_S0, COL_S1, COL_S2, COL_START_ROOT0, COL_START_ROOT1, COL_START_ROOT2, COL_START_ROOT3,
    TRACE_WIDTH,
};
use crate::error::BlockError;

type Blake3 = Blake3_256<BaseElement>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentBlockProof {
    pub proof_bytes: Vec<u8>,
    pub proof_hash: [u8; 32],
    pub public_inputs: CommitmentBlockPublicInputs,
}

#[derive(Clone, Debug)]
pub struct CommitmentBlockProver {
    options: ProofOptions,
    pub_inputs: Option<CommitmentBlockPublicInputs>,
}

impl CommitmentBlockProver {
    pub fn new() -> Self {
        Self {
            options: default_commitment_options(),
            pub_inputs: None,
        }
    }

    pub fn with_fast_options() -> Self {
        Self {
            options: fast_commitment_options(),
            pub_inputs: None,
        }
    }

    pub fn prove_block_commitment(
        &self,
        transactions: &[TransactionProof],
    ) -> Result<CommitmentBlockProof, BlockError> {
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
    ) -> Result<CommitmentBlockProof, BlockError> {
        if transactions.is_empty() {
            return Err(BlockError::CommitmentProofEmptyBlock);
        }

        let starting_root = tree.root();
        let nullifier_root = nullifier_root_from_transactions(transactions)?;
        let nullifiers = nullifiers_from_transactions(transactions)?;
        let sorted_nullifiers = sorted_nullifiers(&nullifiers);

        for (index, proof) in transactions.iter().enumerate() {
            let anchor = proof.public_inputs.merkle_root;
            if !tree.root_history().iter().any(|root| *root == anchor) {
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
    ) -> Result<CommitmentBlockProof, BlockError> {
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
    ) -> Result<CommitmentBlockProof, BlockError> {
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

        let start_root_felts = decode_commitment("starting_state_root", &starting_state_root)?;
        let end_root_felts = decode_commitment("ending_state_root", &ending_state_root)?;
        let nullifier_root_felts = hash_bytes_to_felts(&nullifier_root);
        let da_root_felts = hash_bytes_to_felts(&da_root);
        let (perm_alpha, perm_beta) = derive_nullifier_challenges(
            &starting_state_root,
            &ending_state_root,
            &nullifier_root,
            &da_root,
            proof_hashes.len() as u32,
            &nullifiers,
            &sorted_nullifiers,
        );

        let (trace, commitment_felts) = self.build_trace(
            proof_hashes,
            &start_root_felts,
            &end_root_felts,
            &nullifier_root_felts,
            &da_root_felts,
            &nullifiers,
            &sorted_nullifiers,
            perm_alpha,
            perm_beta,
        )?;
        let commitment = felts_to_bytes32(&commitment_felts);
        let pub_inputs = CommitmentBlockPublicInputs {
            tx_proofs_commitment: commitment,
            starting_state_root,
            ending_state_root,
            nullifier_root,
            da_root,
            tx_count: proof_hashes.len() as u32,
            nullifiers,
            sorted_nullifiers,
        };

        let prover = CommitmentBlockProver {
            options: self.options.clone(),
            pub_inputs: Some(pub_inputs.clone()),
        };
        let proof = prover
            .prove(trace)
            .map_err(|err| BlockError::CommitmentProofGeneration(format!("{:?}", err)))?;
        let proof_bytes = proof.to_bytes();
        let proof_hash = blake3_256(&proof_bytes);

        Ok(CommitmentBlockProof {
            proof_bytes,
            proof_hash,
            public_inputs: pub_inputs,
        })
    }

    pub fn commitment_from_proof_hashes(
        proof_hashes: &[[u8; 32]],
    ) -> Result<[u8; 32], BlockError> {
        if proof_hashes.is_empty() {
            return Err(BlockError::CommitmentProofEmptyBlock);
        }

        let mut inputs = hashes_to_elements(proof_hashes);
        let tx_count = proof_hashes.len();
        let total_cycles = CommitmentBlockAir::trace_length(tx_count) / CYCLE_LENGTH;
        let input_cycles = tx_count.saturating_mul(2).max(1);
        let target_len = input_cycles * 2;
        if inputs.len() < target_len {
            inputs.resize(target_len, BaseElement::ZERO);
        }

        let init0 = inputs.first().copied().unwrap_or(BaseElement::ZERO);
        let init1 = inputs.get(1).copied().unwrap_or(BaseElement::ZERO);
        let mut state = [
            BaseElement::new(BLOCK_COMMITMENT_DOMAIN_TAG) + init0,
            init1,
            BaseElement::ONE,
        ];

        let mut output0 = BaseElement::ZERO;
        let mut output1 = BaseElement::ZERO;
        let mut output2 = BaseElement::ZERO;
        let mut output3 = BaseElement::ZERO;
        let trace_len = total_cycles * CYCLE_LENGTH;

        for cycle in 0..total_cycles {
            let pair_index = cycle;
            let (_input0, _input1) = if pair_index < input_cycles {
                let idx = pair_index * 2;
                (inputs[idx], inputs[idx + 1])
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };
            let (next_input0, next_input1) = if pair_index + 1 < input_cycles {
                let next_idx = (pair_index + 1) * 2;
                (inputs[next_idx], inputs[next_idx + 1])
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };

            let cycle_start = cycle * CYCLE_LENGTH;
            for step in 0..CYCLE_LENGTH {
                let row = cycle_start + step;
                let current = state;

                if step + 1 == CYCLE_LENGTH {
                    if cycle + 1 == input_cycles {
                        output0 = current[0];
                        output1 = current[1];
                    }
                    if cycle + 1 == total_cycles {
                        output2 = current[0];
                        output3 = current[1];
                    }
                }

                if row + 1 < trace_len {
                    if step < POSEIDON_ROUNDS {
                        let t0 = state[0] + round_constant(step, 0);
                        let t1 = state[1] + round_constant(step, 1);
                        let t2 = state[2] + round_constant(step, 2);
                        state = mds_mix(&[sbox(t0), sbox(t1), sbox(t2)]);
                    } else {
                        state[0] += next_input0;
                        state[1] += next_input1;
                    }
                }
            }
        }

        Ok(felts_to_bytes32(&[output0, output1, output2, output3]))
    }

    pub fn verify_block_commitment(
        &self,
        proof: &CommitmentBlockProof,
    ) -> Result<(), BlockError> {
        validate_commitment_inputs(&proof.public_inputs)?;
        let stark_proof = Proof::from_bytes(&proof.proof_bytes)
            .map_err(|err| BlockError::CommitmentProofVerification(format!("{:?}", err)))?;
        let acceptable = acceptable_commitment_options();
        verify::<CommitmentBlockAir, Blake3, DefaultRandomCoin<Blake3>, MerkleTree<Blake3>>(
            stark_proof,
            proof.public_inputs.clone(),
            &acceptable,
        )
        .map_err(|err| BlockError::CommitmentProofVerification(format!("{:?}", err)))?;
        Ok(())
    }

    fn build_trace(
        &self,
        proof_hashes: &[[u8; 32]],
        starting_state_root: &[BaseElement; 4],
        ending_state_root: &[BaseElement; 4],
        nullifier_root: &[BaseElement; 4],
        da_root: &[BaseElement; 4],
        nullifiers: &[[u8; 32]],
        sorted_nullifiers: &[[u8; 32]],
        perm_alpha: BaseElement,
        perm_beta: BaseElement,
    ) -> Result<(TraceTable<BaseElement>, [BaseElement; 4]), BlockError> {
        let mut inputs = hashes_to_elements(proof_hashes);

        let tx_count = proof_hashes.len();
        let total_cycles = CommitmentBlockAir::trace_length(tx_count) / CYCLE_LENGTH;
        let input_cycles = tx_count.saturating_mul(2);
        let target_len = input_cycles * 2;
        if inputs.len() < target_len {
            inputs.resize(target_len, BaseElement::ZERO);
        }

        let trace_len = total_cycles * CYCLE_LENGTH;
        let mut trace = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];

        let init0 = inputs.first().copied().unwrap_or(BaseElement::ZERO);
        let init1 = inputs.get(1).copied().unwrap_or(BaseElement::ZERO);
        let mut state = [
            BaseElement::new(BLOCK_COMMITMENT_DOMAIN_TAG) + init0,
            init1,
            BaseElement::ONE,
        ];

        let mut output0 = BaseElement::ZERO;
        let mut output1 = BaseElement::ZERO;
        let mut output2 = BaseElement::ZERO;
        let mut output3 = BaseElement::ZERO;

        for cycle in 0..total_cycles {
            let pair_index = cycle;
            let (input0, input1) = if pair_index < input_cycles {
                let idx = pair_index * 2;
                (inputs[idx], inputs[idx + 1])
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };
            let (next_input0, next_input1) = if pair_index + 1 < input_cycles {
                let next_idx = (pair_index + 1) * 2;
                (inputs[next_idx], inputs[next_idx + 1])
            } else {
                (BaseElement::ZERO, BaseElement::ZERO)
            };

            let cycle_start = cycle * CYCLE_LENGTH;
            for step in 0..CYCLE_LENGTH {
                let row = cycle_start + step;
                trace[COL_S0][row] = state[0];
                trace[COL_S1][row] = state[1];
                trace[COL_S2][row] = state[2];
                trace[COL_INPUT0][row] = input0;
                trace[COL_INPUT1][row] = input1;

                if row + 1 < trace_len {
                    if step < POSEIDON_ROUNDS {
                        let t0 = state[0] + round_constant(step, 0);
                        let t1 = state[1] + round_constant(step, 1);
                        let t2 = state[2] + round_constant(step, 2);
                        state = mds_mix(&[sbox(t0), sbox(t1), sbox(t2)]);
                    } else {
                        state[0] += next_input0;
                        state[1] += next_input1;
                    }
                }

                if step + 1 == CYCLE_LENGTH {
                    if cycle + 1 == input_cycles {
                        output0 = trace[COL_S0][row];
                        output1 = trace[COL_S1][row];
                    }
                    if cycle + 1 == total_cycles {
                        output2 = trace[COL_S0][row];
                        output3 = trace[COL_S1][row];
                    }
                }
            }
        }

        fill_column(&mut trace, COL_START_ROOT0, starting_state_root[0]);
        fill_column(&mut trace, COL_START_ROOT1, starting_state_root[1]);
        fill_column(&mut trace, COL_START_ROOT2, starting_state_root[2]);
        fill_column(&mut trace, COL_START_ROOT3, starting_state_root[3]);
        fill_column(&mut trace, COL_END_ROOT0, ending_state_root[0]);
        fill_column(&mut trace, COL_END_ROOT1, ending_state_root[1]);
        fill_column(&mut trace, COL_END_ROOT2, ending_state_root[2]);
        fill_column(&mut trace, COL_END_ROOT3, ending_state_root[3]);
        fill_column(&mut trace, COL_NULLIFIER_ROOT0, nullifier_root[0]);
        fill_column(&mut trace, COL_NULLIFIER_ROOT1, nullifier_root[1]);
        fill_column(&mut trace, COL_NULLIFIER_ROOT2, nullifier_root[2]);
        fill_column(&mut trace, COL_NULLIFIER_ROOT3, nullifier_root[3]);
        fill_column(&mut trace, COL_DA_ROOT0, da_root[0]);
        fill_column(&mut trace, COL_DA_ROOT1, da_root[1]);
        fill_column(&mut trace, COL_DA_ROOT2, da_root[2]);
        fill_column(&mut trace, COL_DA_ROOT3, da_root[3]);

        let nullifier_felts = decode_nullifier_list("nullifiers", nullifiers)?;
        let sorted_nullifier_felts =
            decode_nullifier_list("sorted_nullifiers", sorted_nullifiers)?;
        let nullifier_count = nullifier_felts.len();
        if nullifier_count + 1 > trace_len {
            return Err(BlockError::CommitmentProofInvalidInputs(format!(
                "nullifier rows exceed trace length ({})",
                trace_len
            )));
        }

        for (row, limbs) in nullifier_felts.iter().enumerate() {
            trace[COL_NF_U0][row] = limbs[0];
            trace[COL_NF_U1][row] = limbs[1];
            trace[COL_NF_U2][row] = limbs[2];
            trace[COL_NF_U3][row] = limbs[3];
        }
        for (row, limbs) in sorted_nullifier_felts.iter().enumerate() {
            trace[COL_NF_S0][row] = limbs[0];
            trace[COL_NF_S1][row] = limbs[1];
            trace[COL_NF_S2][row] = limbs[2];
            trace[COL_NF_S3][row] = limbs[3];
        }

        let alpha2 = perm_alpha * perm_alpha;
        let alpha3 = alpha2 * perm_alpha;
        let mut perm = BaseElement::ONE;
        let sorted_compressed: Vec<BaseElement> = sorted_nullifier_felts
            .iter()
            .map(|limbs| compress_nullifier(limbs, perm_alpha, alpha2, alpha3))
            .collect();
        for (row, u_limbs) in nullifier_felts.iter().enumerate() {
            let u = compress_nullifier(u_limbs, perm_alpha, alpha2, alpha3);
            let v = sorted_compressed[row];
            let denom = v + perm_beta;
            if denom == BaseElement::ZERO {
                return Err(BlockError::CommitmentProofInvalidInputs(
                    "nullifier permutation denominator is zero".to_string(),
                ));
            }
            let (v_inv, v_nz) = invert_with_flag(v);
            let inv = denom.inv();
            trace[COL_NF_PERM][row] = perm;
            trace[COL_NF_PERM_INV][row] = inv;
            trace[COL_NF_SORTED_INV][row] = v_inv;
            trace[COL_NF_SORTED_NZ][row] = v_nz;
            perm = perm * (u + perm_beta) * inv;
        }
        trace[COL_NF_PERM][nullifier_count] = perm;

        for row in 0..nullifier_count.saturating_sub(1) {
            let next = row + 1;
            let (inv, nz) = invert_with_flag(sorted_compressed[next] - sorted_compressed[row]);
            trace[COL_NF_DIFF_INV][row] = inv;
            trace[COL_NF_DIFF_NZ][row] = nz;
        }

        Ok((TraceTable::init(trace), [output0, output1, output2, output3]))
    }
}

impl Default for CommitmentBlockProver {
    fn default() -> Self {
        Self::new()
    }
}

pub fn default_commitment_options() -> ProofOptions {
    ProofOptions::new(
        8,
        16,
        4,
        winterfell::FieldExtension::None,
        2,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn fast_commitment_options() -> ProofOptions {
    ProofOptions::new(
        4,
        8,
        0,
        winterfell::FieldExtension::None,
        2,
        15,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn acceptable_commitment_options() -> winterfell::AcceptableOptions {
    #[cfg(feature = "stark-fast")]
    {
        winterfell::AcceptableOptions::OptionSet(vec![
            default_commitment_options(),
            fast_commitment_options(),
        ])
    }
    #[cfg(not(feature = "stark-fast"))]
    {
        winterfell::AcceptableOptions::OptionSet(vec![default_commitment_options()])
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

fn hashes_to_elements(hashes: &[[u8; 32]]) -> Vec<BaseElement> {
    let mut elements = Vec::with_capacity(hashes.len() * 4);
    for hash in hashes {
        elements.extend_from_slice(&hash_bytes_to_felts(hash));
    }
    elements
}

fn hash_bytes_to_felts(bytes: &[u8; 32]) -> [BaseElement; 4] {
    let mut felts = [BaseElement::ZERO; 4];
    for (idx, chunk) in bytes.chunks(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("8-byte chunk"));
        felts[idx] = BaseElement::new(limb);
    }
    felts
}

fn fill_column(trace: &mut [Vec<BaseElement>], col: usize, value: BaseElement) {
    for row in trace[col].iter_mut() {
        *row = value;
    }
}

fn decode_commitment(label: &str, value: &[u8; 32]) -> Result<[BaseElement; 4], BlockError> {
    bytes32_to_felts(value).ok_or_else(|| {
        BlockError::CommitmentProofInvalidInputs(format!("{label} encoding is non-canonical"))
    })
}

fn decode_nullifier_list(
    label: &str,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<[BaseElement; 4]>, BlockError> {
    let mut felts = Vec::with_capacity(nullifiers.len());
    for (idx, nf) in nullifiers.iter().enumerate() {
        let limbs = bytes32_to_felts(nf).ok_or_else(|| {
            BlockError::CommitmentProofInvalidInputs(format!(
                "{label}[{idx}] encoding is non-canonical"
            ))
        })?;
        felts.push(limbs);
    }
    Ok(felts)
}

fn compress_nullifier(
    limbs: &[BaseElement; 4],
    alpha: BaseElement,
    alpha2: BaseElement,
    alpha3: BaseElement,
) -> BaseElement {
    limbs[0] + limbs[1] * alpha + limbs[2] * alpha2 + limbs[3] * alpha3
}

fn invert_with_flag(value: BaseElement) -> (BaseElement, BaseElement) {
    if value == BaseElement::ZERO {
        (BaseElement::ZERO, BaseElement::ZERO)
    } else {
        (value.inv(), BaseElement::ONE)
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

fn validate_commitment_inputs(inputs: &CommitmentBlockPublicInputs) -> Result<(), BlockError> {
    if inputs.tx_count == 0 {
        return Err(BlockError::CommitmentProofEmptyBlock);
    }
    validate_commitment_bytes("tx_proofs_commitment", &inputs.tx_proofs_commitment)?;
    validate_commitment_bytes("starting_state_root", &inputs.starting_state_root)?;
    validate_commitment_bytes("ending_state_root", &inputs.ending_state_root)?;
    let expected_nullifiers = (inputs.tx_count as usize).saturating_mul(MAX_INPUTS);
    if inputs.nullifiers.len() != expected_nullifiers {
        return Err(BlockError::CommitmentProofInvalidInputs(format!(
            "nullifier length mismatch (expected {}, got {})",
            expected_nullifiers,
            inputs.nullifiers.len()
        )));
    }
    if inputs.sorted_nullifiers.len() != expected_nullifiers {
        return Err(BlockError::CommitmentProofInvalidInputs(format!(
            "sorted nullifier length mismatch (expected {}, got {})",
            expected_nullifiers,
            inputs.sorted_nullifiers.len()
        )));
    }
    if !inputs
        .sorted_nullifiers
        .windows(2)
        .all(|pair| pair[0] <= pair[1])
    {
        return Err(BlockError::CommitmentProofInvalidInputs(
            "sorted nullifiers are not ordered".to_string(),
        ));
    }
    if inputs.nullifiers.iter().all(|nf| *nf == [0u8; 32]) {
        return Err(BlockError::CommitmentProofInvalidInputs(
            "nullifier list must include at least one non-zero entry".to_string(),
        ));
    }
    for (idx, nf) in inputs.nullifiers.iter().enumerate() {
        validate_commitment_bytes(&format!("nullifiers[{idx}]"), nf)?;
    }
    for (idx, nf) in inputs.sorted_nullifiers.iter().enumerate() {
        validate_commitment_bytes(&format!("sorted_nullifiers[{idx}]"), nf)?;
    }
    Ok(())
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

    let mut data = Vec::with_capacity(entries.len() * 32);
    for nf in entries {
        data.extend_from_slice(&nf);
    }
    let digest = Sha256::digest(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

impl Prover for CommitmentBlockProver {
    type BaseField = BaseElement;
    type Air = CommitmentBlockAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type VC = MerkleTree<Blake3>;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> CommitmentBlockPublicInputs {
        self.pub_inputs.clone().unwrap_or_default()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_trace_poly_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_trace_poly_columns,
            domain,
            partition_options,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimate_merkle_update_rows(tree_depth: usize, leaf_count: usize) -> (usize, usize) {
        // Poseidon sponge over 8 inputs uses 4 absorb cycles + 1 extra cycle for output limbs.
        let cycles_per_node = 5usize;
        let cycles = tree_depth.saturating_mul(leaf_count).saturating_mul(cycles_per_node);
        let rows = cycles.saturating_mul(CYCLE_LENGTH);
        (cycles, rows)
    }

    fn dummy_hashes(count: usize) -> Vec<[u8; 32]> {
        (0..count)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
                hash
            })
            .collect()
    }

    #[test]
    fn commitment_proof_roundtrip_100() {
        let hashes = dummy_hashes(100);
        let prover = CommitmentBlockProver::new();
        let proof = prover.prove_from_hashes(&hashes).expect("proof");
        prover
            .verify_block_commitment(&proof)
            .expect("verify");
    }

    #[test]
    fn commitment_proof_rejects_nullifier_mismatch() {
        let hashes = dummy_hashes(8);
        let prover = CommitmentBlockProver::with_fast_options();
        let proof = prover.prove_from_hashes(&hashes).expect("proof");
        let mut tampered = proof.clone();
        tampered.public_inputs.nullifiers[0] = [1u8; 32];
        assert!(prover.verify_block_commitment(&tampered).is_err());
    }

    #[test]
    fn commitment_merkle_budget() {
        let depth = transaction_circuit::note::MERKLE_TREE_DEPTH;
        let (cycles_one, rows_one) = estimate_merkle_update_rows(depth, 1);
        println!(
            "merkle update budget: depth={} leaves=1 cycles={} rows={}",
            depth, cycles_one, rows_one
        );

        let tx_count = 100usize;
        let commitments_per_tx = transaction_circuit::constants::MAX_OUTPUTS as usize;
        let leaves = tx_count.saturating_mul(commitments_per_tx);
        let (cycles, rows) = estimate_merkle_update_rows(depth, leaves);
        println!(
            "merkle update budget: depth={} leaves={} cycles={} rows={}",
            depth, leaves, cycles, rows
        );
    }
}
