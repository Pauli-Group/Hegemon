use std::collections::{HashMap, HashSet};

use epoch_circuit::recursion::recursive_prover::{fast_recursive_proof_options, recursive_proof_options};
use epoch_circuit::recursion::{prove_batch, verify_batch, InnerProofData, StarkVerifierPublicInputs};
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};
use state_merkle::CommitmentTree;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing::{bytes32_to_felts, felts_to_bytes32, Commitment, Felt};
use transaction_circuit::{TransactionAirStark, TransactionProof, TransactionPublicInputsStark, VerifyingKey};
use winterfell::{AcceptableOptions, Proof};
use winterfell::math::ToElements;

use crate::error::BlockError;

const RECURSIVE_BLOCK_DOMAIN: &[u8] = b"hegemon-recursive-block-proof-v1";

fn anchor_in_history(tree: &CommitmentTree, anchor: Commitment) -> bool {
    tree.root_history().contains(&anchor)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedVerifierInputs {
    pub inner_len: u32,
    pub elements: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveBlockProof {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_bytes: Vec<u8>,
    #[serde(with = "serde_bytes32")]
    pub recursive_proof_hash: Commitment,
    #[serde(with = "serde_bytes32")]
    pub starting_root: Commitment,
    #[serde(with = "serde_bytes32")]
    pub ending_root: Commitment,
    pub tx_count: u32,
    pub verifier_inputs: Vec<SerializedVerifierInputs>,
}

pub fn prove_block_recursive(
    tree: &mut CommitmentTree,
    transactions: &[TransactionProof],
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<RecursiveBlockProof, BlockError> {
    if transactions.is_empty() {
        return Err(BlockError::RecursiveProofCountMismatch);
    }

    let starting_root = tree.root();
    let mut seen_nullifiers: HashSet<Commitment> = HashSet::new();
    let mut inner_datas = Vec::with_capacity(transactions.len());
    let mut inner_pub_inputs = Vec::with_capacity(transactions.len());
    let mut serialized_inputs = Vec::with_capacity(transactions.len());

    for (index, proof) in transactions.iter().enumerate() {
        let binding = proof.version_binding();
        if !verifying_keys.contains_key(&binding) {
            return Err(BlockError::UnsupportedVersion { index, version: binding });
        }
        if proof.stark_proof.is_empty() {
            return Err(BlockError::MissingStarkProof { index });
        }
        let stark_inputs = stark_inputs_from_proof(proof, index)?;
        let merkle_root = felts_to_bytes32(&stark_inputs.merkle_root);
        if !anchor_in_history(tree, merkle_root) {
            return Err(BlockError::UnexpectedMerkleRoot {
                index,
                expected: tree.root(),
                reported: merkle_root,
            });
        }

        for &nullifier in &proof.nullifiers {
            if nullifier == [0u8; 32] {
                continue;
            }
            if !seen_nullifiers.insert(nullifier) {
                return Err(BlockError::DuplicateNullifier(nullifier));
            }
        }
        for &commitment in proof.commitments.iter().filter(|c| **c != [0u8; 32]) {
            tree.append(commitment)?;
        }

        let inner_data = InnerProofData::from_proof::<TransactionAirStark>(
            &proof.stark_proof,
            stark_inputs.clone(),
        )
        .map_err(|e| BlockError::RecursiveProofInput {
            index,
            reason: e.to_string(),
        })?;
        let verifier_inputs = inner_data.to_stark_verifier_inputs();
        serialized_inputs.push(serialize_verifier_inputs(&verifier_inputs));
        inner_datas.push(inner_data);
        inner_pub_inputs.push(verifier_inputs);
    }

    pad_to_power_of_two(&mut inner_datas, &mut inner_pub_inputs, &mut serialized_inputs)?;

    let options = recursive_proof_options();
    let proof = prove_batch(&inner_datas, inner_pub_inputs.clone(), options)
        .map_err(BlockError::RecursiveProofGeneration)?;
    let proof_bytes = proof.to_bytes();
    let recursive_proof_hash = hash_recursive_proof(&proof_bytes);

    Ok(RecursiveBlockProof {
        proof_bytes,
        recursive_proof_hash,
        starting_root,
        ending_root: tree.root(),
        tx_count: transactions.len() as u32,
        verifier_inputs: serialized_inputs,
    })
}

/// Build a recursive block proof with faster, lower-soundness options.
/// Intended for development and test workflows.
pub fn prove_block_recursive_fast(
    tree: &mut CommitmentTree,
    transactions: &[TransactionProof],
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<RecursiveBlockProof, BlockError> {
    if transactions.is_empty() {
        return Err(BlockError::RecursiveProofCountMismatch);
    }

    let starting_root = tree.root();
    let mut seen_nullifiers: HashSet<Commitment> = HashSet::new();
    let mut inner_datas = Vec::with_capacity(transactions.len());
    let mut inner_pub_inputs = Vec::with_capacity(transactions.len());
    let mut serialized_inputs = Vec::with_capacity(transactions.len());

    for (index, proof) in transactions.iter().enumerate() {
        let binding = proof.version_binding();
        if !verifying_keys.contains_key(&binding) {
            return Err(BlockError::UnsupportedVersion { index, version: binding });
        }
        if proof.stark_proof.is_empty() {
            return Err(BlockError::MissingStarkProof { index });
        }
        let stark_inputs = stark_inputs_from_proof(proof, index)?;
        let merkle_root = felts_to_bytes32(&stark_inputs.merkle_root);
        if !anchor_in_history(tree, merkle_root) {
            return Err(BlockError::UnexpectedMerkleRoot {
                index,
                expected: tree.root(),
                reported: merkle_root,
            });
        }

        for &nullifier in &proof.nullifiers {
            if nullifier == [0u8; 32] {
                continue;
            }
            if !seen_nullifiers.insert(nullifier) {
                return Err(BlockError::DuplicateNullifier(nullifier));
            }
        }
        for &commitment in proof.commitments.iter().filter(|c| **c != [0u8; 32]) {
            tree.append(commitment)?;
        }

        let inner_data = InnerProofData::from_proof::<TransactionAirStark>(
            &proof.stark_proof,
            stark_inputs.clone(),
        )
        .map_err(|e| BlockError::RecursiveProofInput {
            index,
            reason: e.to_string(),
        })?;
        let verifier_inputs = inner_data.to_stark_verifier_inputs();
        serialized_inputs.push(serialize_verifier_inputs(&verifier_inputs));
        inner_datas.push(inner_data);
        inner_pub_inputs.push(verifier_inputs);
    }

    pad_to_power_of_two(&mut inner_datas, &mut inner_pub_inputs, &mut serialized_inputs)?;

    let options = fast_recursive_proof_options();
    let proof = prove_batch(&inner_datas, inner_pub_inputs.clone(), options)
        .map_err(BlockError::RecursiveProofGeneration)?;
    let proof_bytes = proof.to_bytes();
    let recursive_proof_hash = hash_recursive_proof(&proof_bytes);

    Ok(RecursiveBlockProof {
        proof_bytes,
        recursive_proof_hash,
        starting_root,
        ending_root: tree.root(),
        tx_count: transactions.len() as u32,
        verifier_inputs: serialized_inputs,
    })
}

pub fn verify_block_recursive(
    tree: &mut CommitmentTree,
    proof: &RecursiveBlockProof,
    transactions: &[TransactionProof],
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<(), BlockError> {
    if proof.tx_count as usize != transactions.len() {
        return Err(BlockError::RecursiveProofCountMismatch);
    }
    if proof.recursive_proof_hash != hash_recursive_proof(&proof.proof_bytes) {
        return Err(BlockError::RecursiveProofHashMismatch);
    }

    let verifier_inputs = verify_recursive_proof(proof)?;
    if verifier_inputs.len() < transactions.len() {
        return Err(BlockError::RecursiveProofCountMismatch);
    }
    if !verifier_inputs.len().is_power_of_two() {
        return Err(BlockError::RecursiveProofCountMismatch);
    }
    if !padding_matches(&verifier_inputs, transactions.len()) {
        return Err(BlockError::RecursiveProofPaddingMismatch);
    }

    let mut seen_nullifiers: HashSet<Commitment> = HashSet::new();
    if tree.root() != proof.starting_root {
        return Err(BlockError::StartingRootMismatch {
            expected: proof.starting_root,
            observed: tree.root(),
        });
    }

    for (index, tx) in transactions.iter().enumerate() {
        let binding = tx.version_binding();
        if !verifying_keys.contains_key(&binding) {
            return Err(BlockError::UnsupportedVersion { index, version: binding });
        }

        let expected_inputs = stark_inputs_from_proof(tx, index)?;
        let verifier_inputs = &verifier_inputs[index];
        let recursive_inputs = transaction_inputs_from_inner(
            verifier_inputs.inner_public_inputs.as_slice(),
            Some(index),
        )?;

        if expected_inputs.to_elements() != recursive_inputs.to_elements() {
            return Err(BlockError::RecursiveProofInputsMismatch(index));
        }

        let merkle_root = felts_to_bytes32(&recursive_inputs.merkle_root);
        if !anchor_in_history(tree, merkle_root) {
            return Err(BlockError::UnexpectedMerkleRoot {
                index,
                expected: tree.root(),
                reported: merkle_root,
            });
        }

        for &nullifier in &tx.nullifiers {
            if nullifier == [0u8; 32] {
                continue;
            }
            if !seen_nullifiers.insert(nullifier) {
                return Err(BlockError::DuplicateNullifier(nullifier));
            }
        }
        for &commitment in tx.commitments.iter().filter(|c| **c != [0u8; 32]) {
            tree.append(commitment)?;
        }
    }

    if tree.root() != proof.ending_root {
        return Err(BlockError::EndingRootMismatch {
            expected: proof.ending_root,
            observed: tree.root(),
        });
    }

    Ok(())
}

pub fn verify_recursive_proof(
    proof: &RecursiveBlockProof,
) -> Result<Vec<StarkVerifierPublicInputs>, BlockError> {
    if proof.recursive_proof_hash != hash_recursive_proof(&proof.proof_bytes) {
        return Err(BlockError::RecursiveProofHashMismatch);
    }
    let verifier_inputs = decode_verifier_inputs(proof)?;
    let batch_proof = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|err| BlockError::RecursiveProofVerification(err.to_string()))?;
    #[cfg(feature = "fast-proofs")]
    let option_set = {
        let mut option_set = vec![recursive_proof_options()];
        option_set.push(fast_recursive_proof_options());
        option_set
    };
    #[cfg(not(feature = "fast-proofs"))]
    let option_set = vec![recursive_proof_options()];
    let acceptable = AcceptableOptions::OptionSet(option_set);
    verify_batch(&batch_proof, verifier_inputs.clone(), acceptable)
        .map_err(BlockError::RecursiveProofVerification)?;
    Ok(verifier_inputs)
}

pub fn decode_verifier_inputs(
    proof: &RecursiveBlockProof,
) -> Result<Vec<StarkVerifierPublicInputs>, BlockError> {
    proof
        .verifier_inputs
        .iter()
        .map(deserialize_verifier_inputs)
        .collect()
}

pub fn transaction_inputs_from_verifier_inputs(
    inputs: &StarkVerifierPublicInputs,
) -> Result<TransactionPublicInputsStark, BlockError> {
    transaction_inputs_from_inner(inputs.inner_public_inputs.as_slice(), None)
}

fn transaction_inputs_from_inner(
    elements: &[Felt],
    index: Option<usize>,
) -> Result<TransactionPublicInputsStark, BlockError> {
    let error_index = index.unwrap_or(0);
    let mut idx = 0usize;
    let min_len = MAX_INPUTS
        + MAX_OUTPUTS
        + MAX_INPUTS * 4
        + MAX_OUTPUTS * 4
        + 1
        + 1
        + 1
        + 4
        + 1
        + 1
        + 1
        + 1
        + 1
        + 4
        + 4
        + 4;
    if elements.len() < min_len {
        return Err(BlockError::RecursiveProofInput {
            index: error_index,
            reason: format!(
                "inner public input length too short: got {}, need at least {}",
                elements.len(),
                min_len
            ),
        });
    }

    let input_flags = elements[idx..idx + MAX_INPUTS].to_vec();
    idx += MAX_INPUTS;
    let output_flags = elements[idx..idx + MAX_OUTPUTS].to_vec();
    idx += MAX_OUTPUTS;

    let mut nullifiers = Vec::with_capacity(MAX_INPUTS);
    for _ in 0..MAX_INPUTS {
        let chunk = [
            elements[idx],
            elements[idx + 1],
            elements[idx + 2],
            elements[idx + 3],
        ];
        idx += 4;
        nullifiers.push(chunk);
    }

    let mut commitments = Vec::with_capacity(MAX_OUTPUTS);
    for _ in 0..MAX_OUTPUTS {
        let chunk = [
            elements[idx],
            elements[idx + 1],
            elements[idx + 2],
            elements[idx + 3],
        ];
        idx += 4;
        commitments.push(chunk);
    }

    let fee = elements[idx];
    idx += 1;
    let value_balance_sign = elements[idx];
    idx += 1;
    let value_balance_magnitude = elements[idx];
    idx += 1;

    let merkle_root = [
        elements[idx],
        elements[idx + 1],
        elements[idx + 2],
        elements[idx + 3],
    ];
    idx += 4;

    let stablecoin_enabled = elements[idx];
    idx += 1;
    let stablecoin_asset = elements[idx];
    idx += 1;
    let stablecoin_policy_version = elements[idx];
    idx += 1;
    let stablecoin_issuance_sign = elements[idx];
    idx += 1;
    let stablecoin_issuance_magnitude = elements[idx];
    idx += 1;

    let stablecoin_policy_hash = [
        elements[idx],
        elements[idx + 1],
        elements[idx + 2],
        elements[idx + 3],
    ];
    idx += 4;
    let stablecoin_oracle_commitment = [
        elements[idx],
        elements[idx + 1],
        elements[idx + 2],
        elements[idx + 3],
    ];
    idx += 4;
    let stablecoin_attestation_commitment = [
        elements[idx],
        elements[idx + 1],
        elements[idx + 2],
        elements[idx + 3],
    ];

    Ok(TransactionPublicInputsStark {
        input_flags,
        output_flags,
        nullifiers,
        commitments,
        fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root,
        stablecoin_enabled,
        stablecoin_asset,
        stablecoin_policy_version,
        stablecoin_issuance_sign,
        stablecoin_issuance_magnitude,
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
    })
}

fn serialize_verifier_inputs(inputs: &StarkVerifierPublicInputs) -> SerializedVerifierInputs {
    let elements: Vec<u64> = inputs.to_elements().iter().map(|e| e.as_int()).collect();
    SerializedVerifierInputs {
        inner_len: inputs.inner_public_inputs.len() as u32,
        elements,
    }
}

fn deserialize_verifier_inputs(
    inputs: &SerializedVerifierInputs,
) -> Result<StarkVerifierPublicInputs, BlockError> {
    let elements: Vec<Felt> = inputs.elements.iter().map(|v| Felt::new(*v)).collect();
    StarkVerifierPublicInputs::try_from_elements(&elements, inputs.inner_len as usize).map_err(
        |err| BlockError::RecursiveProofVerification(err),
    )
}

fn stark_inputs_from_proof(
    proof: &TransactionProof,
    index: usize,
) -> Result<TransactionPublicInputsStark, BlockError> {
    let stark_inputs = proof
        .stark_public_inputs
        .as_ref()
        .ok_or(BlockError::MissingStarkInputs { index })?;

    let input_flags = stark_inputs
        .input_flags
        .iter()
        .map(|flag| Felt::new(*flag as u64))
        .collect();
    let output_flags = stark_inputs
        .output_flags
        .iter()
        .map(|flag| Felt::new(*flag as u64))
        .collect();

    let nullifiers = proof
        .nullifiers
        .iter()
        .map(|nf| {
            bytes32_to_felts(nf).ok_or_else(|| BlockError::InvalidStarkInputs {
                index,
                reason: "invalid nullifier encoding".to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let commitments = proof
        .commitments
        .iter()
        .map(|cm| {
            bytes32_to_felts(cm).ok_or_else(|| BlockError::InvalidStarkInputs {
                index,
                reason: "invalid commitment encoding".to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_root = bytes32_to_felts(&stark_inputs.merkle_root).ok_or_else(|| {
        BlockError::InvalidStarkInputs {
            index,
            reason: "invalid merkle root encoding".to_string(),
        }
    })?;
    let stablecoin_policy_hash =
        bytes32_to_felts(&stark_inputs.stablecoin_policy_hash).ok_or_else(|| {
            BlockError::InvalidStarkInputs {
                index,
                reason: "invalid stablecoin policy hash encoding".to_string(),
            }
        })?;
    let stablecoin_oracle_commitment =
        bytes32_to_felts(&stark_inputs.stablecoin_oracle_commitment).ok_or_else(|| {
            BlockError::InvalidStarkInputs {
                index,
                reason: "invalid stablecoin oracle commitment encoding".to_string(),
            }
        })?;
    let stablecoin_attestation_commitment =
        bytes32_to_felts(&stark_inputs.stablecoin_attestation_commitment).ok_or_else(|| {
            BlockError::InvalidStarkInputs {
                index,
                reason: "invalid stablecoin attestation commitment encoding".to_string(),
            }
        })?;

    Ok(TransactionPublicInputsStark {
        input_flags,
        output_flags,
        nullifiers,
        commitments,
        fee: Felt::new(stark_inputs.fee),
        value_balance_sign: Felt::new(stark_inputs.value_balance_sign as u64),
        value_balance_magnitude: Felt::new(stark_inputs.value_balance_magnitude),
        merkle_root,
        stablecoin_enabled: Felt::new(stark_inputs.stablecoin_enabled as u64),
        stablecoin_asset: Felt::new(stark_inputs.stablecoin_asset_id),
        stablecoin_policy_version: Felt::new(stark_inputs.stablecoin_policy_version as u64),
        stablecoin_issuance_sign: Felt::new(stark_inputs.stablecoin_issuance_sign as u64),
        stablecoin_issuance_magnitude: Felt::new(stark_inputs.stablecoin_issuance_magnitude),
        stablecoin_policy_hash,
        stablecoin_oracle_commitment,
        stablecoin_attestation_commitment,
    })
}

fn pad_to_power_of_two(
    inner_datas: &mut Vec<InnerProofData>,
    inner_inputs: &mut Vec<StarkVerifierPublicInputs>,
    serialized_inputs: &mut Vec<SerializedVerifierInputs>,
) -> Result<(), BlockError> {
    if inner_datas.is_empty() {
        return Err(BlockError::RecursiveProofCountMismatch);
    }
    let target = inner_datas.len().next_power_of_two();
    while inner_datas.len() < target {
        let last_data = inner_datas
            .last()
            .cloned()
            .ok_or(BlockError::RecursiveProofCountMismatch)?;
        let last_inputs = inner_inputs
            .last()
            .cloned()
            .ok_or(BlockError::RecursiveProofCountMismatch)?;
        let last_serialized = serialized_inputs
            .last()
            .cloned()
            .ok_or(BlockError::RecursiveProofCountMismatch)?;
        inner_datas.push(last_data);
        inner_inputs.push(last_inputs);
        serialized_inputs.push(last_serialized);
    }
    Ok(())
}

fn padding_matches(
    inputs: &[StarkVerifierPublicInputs],
    tx_count: usize,
) -> bool {
    if inputs.len() == tx_count {
        return true;
    }
    if tx_count == 0 || inputs.is_empty() {
        return false;
    }
    let last = &inputs[tx_count - 1];
    inputs[tx_count..].iter().all(|entry| {
        entry.inner_public_inputs == last.inner_public_inputs
            && entry.inner_pub_inputs_hash == last.inner_pub_inputs_hash
            && entry.trace_commitment == last.trace_commitment
            && entry.constraint_commitment == last.constraint_commitment
            && entry.fri_commitments == last.fri_commitments
            && entry.num_queries == last.num_queries
            && entry.num_draws == last.num_draws
            && entry.trace_partition_size == last.trace_partition_size
            && entry.constraint_partition_size == last.constraint_partition_size
            && entry.blowup_factor == last.blowup_factor
            && entry.trace_length == last.trace_length
            && entry.trace_width == last.trace_width
            && entry.constraint_frame_width == last.constraint_frame_width
            && entry.num_transition_constraints == last.num_transition_constraints
            && entry.num_assertions == last.num_assertions
            && entry.field_extension == last.field_extension
    })
}

fn hash_recursive_proof(proof_bytes: &[u8]) -> Commitment {
    let mut buf = Vec::with_capacity(RECURSIVE_BLOCK_DOMAIN.len() + 4 + proof_bytes.len());
    buf.extend_from_slice(RECURSIVE_BLOCK_DOMAIN);
    buf.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(proof_bytes);
    let mut out = [0u8; 32];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&buf);
    hasher.finalize_xof().fill(&mut out);
    out
}

mod serde_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transaction_circuit::keys::generate_keys;
    use transaction_circuit::note::{
        InputNoteWitness, OutputNoteWitness, NoteData, MerklePath, MERKLE_TREE_DEPTH,
    };
    use transaction_circuit::proof::prove;
    use transaction_circuit::rpo_prover::TransactionProverStarkRpo;
    use transaction_circuit::witness::TransactionWitness;
    use transaction_circuit::hashing::{bytes32_to_felts, felts_to_bytes32};
    use transaction_circuit::constants::NATIVE_ASSET_ID;
    use transaction_circuit::public_inputs::StablecoinPolicyBinding;
    use transaction_circuit::proof::SerializedStarkInputs;
    use winterfell::{BatchingMethod, ProofOptions, Prover};

    fn sample_witness() -> (TransactionWitness, CommitmentTree) {
        let input_note = NoteData {
            value: 5,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let output_note = OutputNoteWitness {
            note: NoteData {
                value: 4,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [9u8; 32],
                rho: [10u8; 32],
                r: [11u8; 32],
            },
        };
        let mut tree = CommitmentTree::new(MERKLE_TREE_DEPTH).expect("tree");
        let commitment = felts_to_bytes32(&input_note.commitment());
        let (index, _root) = tree.append(commitment).expect("append");
        let merkle_root = tree.root();
        let siblings = tree
            .authentication_path(index)
            .expect("path")
            .into_iter()
            .map(|bytes| bytes32_to_felts(&bytes).expect("path felts"))
            .collect();
        let merkle_path = MerklePath { siblings };

        let witness = TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note,
                position: index as u64,
                rho_seed: [7u8; 32],
                merkle_path,
            }],
            outputs: vec![output_note],
            sk_spend: [8u8; 32],
            merkle_root,
            fee: 1,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        };

        (witness, tree)
    }

    fn build_rpo_proof(witness: &TransactionWitness) -> TransactionProof {
        let (proving_key, _verifying_key) = generate_keys();
        let mut proof = prove(witness, &proving_key).expect("base proof");
        let options = ProofOptions::new(
            8,
            8,
            0,
            winterfell::FieldExtension::None,
            2,
            7,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let prover = TransactionProverStarkRpo::new(options);
        let trace = prover.build_trace(witness).expect("trace");
        let stark_pub_inputs = prover.get_pub_inputs(&trace);
        let proof_bytes = prover.prove(trace).expect("rpo proof").to_bytes();

        let input_flags = stark_pub_inputs
            .input_flags
            .iter()
            .map(|f| f.as_int() as u8)
            .collect();
        let output_flags = stark_pub_inputs
            .output_flags
            .iter()
            .map(|f| f.as_int() as u8)
            .collect();

        proof.stark_proof = proof_bytes;
        proof.stark_public_inputs = Some(SerializedStarkInputs {
            input_flags,
            output_flags,
            fee: stark_pub_inputs.fee.as_int(),
            value_balance_sign: stark_pub_inputs.value_balance_sign.as_int() as u8,
            value_balance_magnitude: stark_pub_inputs.value_balance_magnitude.as_int(),
            merkle_root: felts_to_bytes32(&stark_pub_inputs.merkle_root),
            stablecoin_enabled: stark_pub_inputs.stablecoin_enabled.as_int() as u8,
            stablecoin_asset_id: stark_pub_inputs.stablecoin_asset.as_int(),
            stablecoin_policy_version: stark_pub_inputs.stablecoin_policy_version.as_int() as u32,
            stablecoin_issuance_sign: stark_pub_inputs.stablecoin_issuance_sign.as_int() as u8,
            stablecoin_issuance_magnitude: stark_pub_inputs.stablecoin_issuance_magnitude.as_int(),
            stablecoin_policy_hash: felts_to_bytes32(&stark_pub_inputs.stablecoin_policy_hash),
            stablecoin_oracle_commitment: felts_to_bytes32(
                &stark_pub_inputs.stablecoin_oracle_commitment,
            ),
            stablecoin_attestation_commitment: felts_to_bytes32(
                &stark_pub_inputs.stablecoin_attestation_commitment,
            ),
        });
        proof
    }

    #[test]
    #[ignore = "heavy: recursive proof generation"]
    fn recursive_block_proof_tamper_rejects() {
        let (witness, mut tree) = sample_witness();
        let proof = build_rpo_proof(&witness);
        let mut keys = HashMap::new();
        let (_proving_key, verifying_key) = generate_keys();
        keys.insert(proof.version_binding(), verifying_key);

        let mut verify_tree = tree.clone();
        let mut tamper_tree = tree.clone();
        let mut recursive =
            prove_block_recursive_fast(&mut tree, &[proof.clone()], &keys).expect("recursive");
        verify_block_recursive(&mut verify_tree, &recursive, &[proof.clone()], &keys)
            .expect("verify ok");

        recursive.proof_bytes[0] ^= 0x01;
        let err = verify_block_recursive(&mut tamper_tree, &recursive, &[proof], &keys)
            .expect_err("tamper should fail");
        assert!(matches!(err, BlockError::RecursiveProofHashMismatch));
    }
}
