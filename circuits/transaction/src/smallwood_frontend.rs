use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_versioning::{tx_proof_backend_for_version, TxProofBackend, VersionBinding};
use serde::{Deserialize, Serialize};
use transaction_core::{
    constants::{
        BALANCE_DOMAIN_TAG, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
        POSEIDON2_RATE, POSEIDON2_STEPS, POSEIDON2_WIDTH,
    },
    poseidon2::poseidon2_step,
};

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{bytes48_to_felts, felts_to_bytes48, Felt, HashFelt},
    note::{InputNoteWitness, MerklePath, OutputNoteWitness, MERKLE_TREE_DEPTH},
    proof::{
        transaction_public_inputs_p3_from_parts, SerializedStarkInputs, TransactionProof,
        VerificationReport,
    },
    public_inputs::{BalanceSlot, TransactionPublicInputs},
    smallwood_native::{
        prove_candidate as prove_smallwood_backend, verify_candidate as verify_smallwood_backend,
    },
    witness::TransactionWitness,
};

const SMALLWOOD_PUBLIC_STATEMENT_DOMAIN: &[u8] = b"hegemon.tx.smallwood-public-statement.v1";
const SMALLWOOD_BINDING_TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.tx.smallwood-binding-transcript.v1";

pub const SMALLWOOD_LPPC_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE: u16 = 8;
pub const SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION: usize = POSEIDON2_STEPS + 1;
pub const SMALLWOOD_RHO: u32 = 2;
pub const SMALLWOOD_NB_OPENED_EVALS: u32 = 3;
pub const SMALLWOOD_BETA: u32 = 3;
pub const SMALLWOOD_OPENING_POW_BITS: u32 = 0;
pub const SMALLWOOD_DECS_NB_EVALS: u32 = 4096;
pub const SMALLWOOD_DECS_NB_OPENED_EVALS: u32 = 37;
pub const SMALLWOOD_DECS_ETA: u32 = 10;
pub const SMALLWOOD_DECS_POW_BITS: u32 = 0;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodPublicStatement {
    pub public_values: Vec<u64>,
    pub public_value_count: u32,
    pub raw_witness_len: u32,
    pub lppc_row_count: u32,
    pub poseidon_permutation_count: u32,
    pub poseidon_state_row_count: u32,
    pub expanded_witness_len: u32,
    pub lppc_packing_factor: u16,
    pub effective_constraint_degree: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodCandidateProof {
    pub ark_proof: Vec<u8>,
}

struct SmallwoodFrontendMaterial {
    public_inputs: TransactionPublicInputs,
    serialized_public_inputs: SerializedStarkInputs,
    public_statement: SmallwoodPublicStatement,
    padded_expanded_witness: Vec<u64>,
    public_selector_indices: Vec<u32>,
    public_selector_targets: Vec<u64>,
    transcript_binding: Vec<u8>,
}

pub fn prove_smallwood_candidate(
    witness: &TransactionWitness,
) -> Result<TransactionProof, TransactionCircuitError> {
    if tx_proof_backend_for_version(witness.version) != Some(TxProofBackend::SmallwoodCandidate) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "version {:?} is not bound to the smallwood_candidate backend",
            witness.version
        )));
    }
    let material = build_smallwood_frontend_material(witness)?;
    let ark_proof = prove_smallwood_backend(
        &material.padded_expanded_witness,
        material.public_statement.lppc_row_count as usize,
        SMALLWOOD_LPPC_PACKING_FACTOR,
        SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
        &material.public_selector_indices,
        &material.public_selector_targets,
        &material.transcript_binding,
    )?;
    let proof_bytes =
        bincode::serialize(&SmallwoodCandidateProof { ark_proof }).map_err(|err| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "failed to serialize smallwood candidate proof: {err}"
            ))
        })?;
    Ok(TransactionProof {
        nullifiers: material.public_inputs.nullifiers.clone(),
        commitments: material.public_inputs.commitments.clone(),
        balance_slots: material.public_inputs.balance_slots.clone(),
        public_inputs: material.public_inputs,
        backend: TxProofBackend::SmallwoodCandidate,
        stark_proof: proof_bytes,
        stark_public_inputs: Some(material.serialized_public_inputs),
    })
}

pub fn verify_smallwood_candidate_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &transaction_core::p3_air::TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<(), TransactionCircuitError> {
    let candidate = decode_smallwood_candidate_proof(proof_bytes)?;
    if candidate.ark_proof.is_empty() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood candidate PCS/ARK proof bytes must not be empty",
        ));
    }
    ensure_smallwood_version(version, version)?;
    let public_statement = build_smallwood_public_statement(pub_inputs, version)?;
    let public_selector_indices =
        build_smallwood_public_selector_indices(public_statement.public_value_count as usize);
    verify_smallwood_backend(
        public_statement.lppc_row_count as usize,
        SMALLWOOD_LPPC_PACKING_FACTOR,
        SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
        &public_selector_indices,
        &public_statement.public_values,
        &smallwood_transcript_binding(&public_statement, version)?,
        &candidate.ark_proof,
    )?;
    Ok(())
}

pub fn verify_smallwood_candidate_transaction_proof(
    proof: &TransactionProof,
) -> Result<VerificationReport, TransactionCircuitError> {
    if !matches!(proof.backend, TxProofBackend::SmallwoodCandidate) {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood candidate verifier requires smallwood_candidate backend",
        ));
    }
    if proof.stark_proof.is_empty() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood candidate proof bytes must not be empty",
        ));
    }
    ensure_smallwood_version(proof.version_binding(), proof.version_binding())?;
    if proof.nullifiers != proof.public_inputs.nullifiers {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood candidate nullifier vector mismatch",
        ));
    }
    if proof.commitments != proof.public_inputs.commitments {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood candidate commitment vector mismatch",
        ));
    }
    if proof.balance_slots != proof.public_inputs.balance_slots {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood candidate balance slots mismatch",
        ));
    }
    crate::proof::verify_balance_slots(proof).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood candidate public input validation failed: {err}"
        ))
    })?;
    let serialized_public_inputs =
        proof
            .stark_public_inputs
            .as_ref()
            .ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood candidate serialized public inputs missing",
            ))?;
    let p3_inputs =
        transaction_public_inputs_p3_from_parts(&proof.public_inputs, serialized_public_inputs)?;
    verify_smallwood_candidate_proof_bytes(
        &proof.stark_proof,
        &p3_inputs,
        proof.version_binding(),
    )?;
    Ok(VerificationReport { verified: true })
}

pub fn smallwood_candidate_verifier_profile_material(version: VersionBinding) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(SMALLWOOD_PUBLIC_STATEMENT_DOMAIN);
    material.extend_from_slice(b"candidate-smallwood-pcs-ark");
    material.extend_from_slice(b"hegemon.blake3-field-xof.v1");
    material.extend_from_slice(&version.circuit.to_le_bytes());
    material.extend_from_slice(&version.crypto.to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_LPPC_PACKING_FACTOR as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_RHO as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_NB_OPENED_EVALS as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_BETA as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_OPENING_POW_BITS as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_DECS_NB_EVALS as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_DECS_NB_OPENED_EVALS as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_DECS_ETA as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_DECS_POW_BITS as u64).to_le_bytes());
    material.extend_from_slice(&(POSEIDON2_WIDTH as u64).to_le_bytes());
    material.extend_from_slice(&(POSEIDON2_RATE as u64).to_le_bytes());
    material.extend_from_slice(&(POSEIDON2_STEPS as u64).to_le_bytes());
    material
        .extend_from_slice(&(SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION as u64).to_le_bytes());
    material
}

pub fn build_smallwood_public_statement_from_witness(
    witness: &TransactionWitness,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    Ok(build_smallwood_frontend_material(witness)?.public_statement)
}

fn decode_smallwood_candidate_proof(
    proof_bytes: &[u8],
) -> Result<SmallwoodCandidateProof, TransactionCircuitError> {
    bincode::deserialize(proof_bytes).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to decode smallwood candidate proof: {err}"
        ))
    })
}

fn build_smallwood_frontend_material(
    witness: &TransactionWitness,
) -> Result<SmallwoodFrontendMaterial, TransactionCircuitError> {
    witness.validate()?;
    validate_native_merkle_membership(witness)?;
    let public_inputs = witness.public_inputs()?;
    let serialized_public_inputs = serialized_public_inputs_from_witness(witness, &public_inputs)?;
    let public_inputs_p3 =
        transaction_public_inputs_p3_from_parts(&public_inputs, &serialized_public_inputs)?;
    let raw_witness = raw_native_tx_validity_witness_words(witness)?;
    let poseidon_rows = poseidon_subtrace_rows(witness)?;
    let public_statement = build_smallwood_public_statement(&public_inputs_p3, witness.version)?;
    let expanded_witness = expanded_witness_words(
        &public_statement.public_values,
        &raw_witness,
        &poseidon_rows,
    );
    let lppc_rows = pack_lppc_rows(&expanded_witness);
    let padded_expanded_witness = flatten_lppc_rows(&lppc_rows);
    let public_selector_indices =
        build_smallwood_public_selector_indices(public_statement.public_values.len());
    let transcript_binding = smallwood_transcript_binding(&public_statement, witness.version)?;
    Ok(SmallwoodFrontendMaterial {
        public_inputs,
        serialized_public_inputs,
        public_selector_targets: public_statement.public_values.clone(),
        padded_expanded_witness,
        public_selector_indices,
        public_statement,
        transcript_binding,
    })
}

fn build_smallwood_public_statement(
    public_inputs: &transaction_core::p3_air::TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    let mut public_values = Vec::with_capacity(public_inputs.to_vec().len() + 2);
    public_values.extend(
        public_inputs
            .to_vec()
            .into_iter()
            .map(|felt| felt.as_canonical_u64()),
    );
    public_values.push(u64::from(version.circuit));
    public_values.push(u64::from(version.crypto));

    let raw_witness_len = raw_native_tx_validity_witness_word_count();
    let poseidon_permutation_count = smallwood_poseidon_permutation_count();
    let poseidon_state_row_count =
        poseidon_permutation_count * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION;
    let expanded_witness_len =
        public_values.len() + raw_witness_len + (poseidon_state_row_count * POSEIDON2_WIDTH);
    let lppc_row_count = expanded_witness_len.div_ceil(SMALLWOOD_LPPC_PACKING_FACTOR);

    Ok(SmallwoodPublicStatement {
        public_value_count: public_values.len() as u32,
        public_values,
        raw_witness_len: raw_witness_len as u32,
        lppc_row_count: lppc_row_count as u32,
        poseidon_permutation_count: poseidon_permutation_count as u32,
        poseidon_state_row_count: poseidon_state_row_count as u32,
        expanded_witness_len: expanded_witness_len as u32,
        lppc_packing_factor: SMALLWOOD_LPPC_PACKING_FACTOR as u16,
        effective_constraint_degree: SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    })
}

fn build_smallwood_public_selector_indices(public_value_count: usize) -> Vec<u32> {
    (0..public_value_count as u32).collect()
}

fn ensure_smallwood_version(
    expected: VersionBinding,
    actual: VersionBinding,
) -> Result<(), TransactionCircuitError> {
    if tx_proof_backend_for_version(expected) != Some(TxProofBackend::SmallwoodCandidate) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "version {:?} is not bound to the smallwood_candidate backend",
            expected
        )));
    }
    if expected == actual {
        Ok(())
    } else {
        Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood candidate version mismatch: expected {:?}, got {:?}",
            expected, actual
        )))
    }
}

fn validate_native_merkle_membership(
    witness: &TransactionWitness,
) -> Result<(), TransactionCircuitError> {
    let root = bytes48_to_felts(&witness.merkle_root).ok_or(
        TransactionCircuitError::ConstraintViolation("native tx merkle root is non-canonical"),
    )?;
    for (index, input) in witness.inputs.iter().enumerate() {
        if input.merkle_path.siblings.len() != MERKLE_TREE_DEPTH {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "native tx input {index} merkle path has length {}, expected {}",
                input.merkle_path.siblings.len(),
                MERKLE_TREE_DEPTH
            )));
        }
        if !input
            .merkle_path
            .verify(input.note.commitment(), input.position, root)
        {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "native tx input {index} merkle path does not match root"
            )));
        }
    }
    Ok(())
}

fn serialized_public_inputs_from_witness(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputs,
) -> Result<SerializedStarkInputs, TransactionCircuitError> {
    if public_inputs.balance_slots.len() != BALANCE_SLOTS {
        return Err(TransactionCircuitError::ConstraintViolation(
            "native tx public inputs balance slot count does not match BALANCE_SLOTS",
        ));
    }
    let (value_balance_sign, value_balance_magnitude) =
        signed_magnitude_u64(witness.value_balance, "value_balance")?;
    let (stablecoin_issuance_sign, stablecoin_issuance_magnitude) =
        signed_magnitude_u64(witness.stablecoin.issuance_delta, "stablecoin_issuance")?;
    Ok(SerializedStarkInputs {
        input_flags: (0..MAX_INPUTS)
            .map(|idx| u8::from(idx < witness.inputs.len()))
            .collect(),
        output_flags: (0..MAX_OUTPUTS)
            .map(|idx| u8::from(idx < witness.outputs.len()))
            .collect(),
        fee: witness.fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root: witness.merkle_root,
        balance_slot_asset_ids: public_inputs
            .balance_slots
            .iter()
            .map(|slot| slot.asset_id)
            .collect(),
        stablecoin_enabled: u8::from(witness.stablecoin.enabled),
        stablecoin_asset_id: witness.stablecoin.asset_id,
        stablecoin_policy_version: witness.stablecoin.policy_version,
        stablecoin_issuance_sign,
        stablecoin_issuance_magnitude,
        stablecoin_policy_hash: witness.stablecoin.policy_hash,
        stablecoin_oracle_commitment: witness.stablecoin.oracle_commitment,
        stablecoin_attestation_commitment: witness.stablecoin.attestation_commitment,
    })
}

fn signed_magnitude_u64(value: i128, label: &str) -> Result<(u8, u64), TransactionCircuitError> {
    let sign = u8::from(value < 0);
    let magnitude = value.unsigned_abs();
    if magnitude > u128::from(u64::MAX) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "{label} magnitude {magnitude} exceeds u64::MAX"
        )));
    }
    Ok((sign, magnitude as u64))
}

fn raw_native_tx_validity_witness_words(
    witness: &TransactionWitness,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut values = Vec::new();
    let (value_balance_sign, value_balance_magnitude) =
        signed_magnitude_u64(witness.value_balance, "value_balance")?;
    let (stablecoin_issuance_sign, stablecoin_issuance_magnitude) =
        signed_magnitude_u64(witness.stablecoin.issuance_delta, "stablecoin_issuance")?;

    values.push(witness.inputs.len() as u64);
    values.push(witness.outputs.len() as u64);
    values.push(witness.ciphertext_hashes.len() as u64);
    push_bytes32_words(&mut values, &witness.sk_spend);
    push_bytes48_words(&mut values, &witness.merkle_root);
    values.push(witness.fee);
    values.push(u64::from(value_balance_sign));
    values.push(value_balance_magnitude);
    values.push(u64::from(witness.stablecoin.enabled));
    values.push(witness.stablecoin.asset_id);
    push_bytes48_words(&mut values, &witness.stablecoin.policy_hash);
    push_bytes48_words(&mut values, &witness.stablecoin.oracle_commitment);
    push_bytes48_words(&mut values, &witness.stablecoin.attestation_commitment);
    values.push(u64::from(stablecoin_issuance_sign));
    values.push(stablecoin_issuance_magnitude);
    values.push(u64::from(witness.stablecoin.policy_version));
    values.push(u64::from(witness.version.circuit));
    values.push(u64::from(witness.version.crypto));

    push_padded_input_note_fields(&mut values, &witness.inputs)?;
    push_padded_output_note_fields(&mut values, &witness.outputs)?;
    push_padded_ciphertext_hashes(&mut values, &witness.ciphertext_hashes)?;
    Ok(values)
}

fn raw_native_tx_validity_witness_word_count() -> usize {
    237 + (MAX_INPUTS * (1 + 1 + 32 + 32 + 32 + 32 + 1 + 32 + (MERKLE_TREE_DEPTH * 48)))
        + (MAX_OUTPUTS * (1 + 1 + 32 + 32 + 32 + 32))
        + (MAX_OUTPUTS * 48)
}

fn smallwood_poseidon_permutation_count() -> usize {
    1 + (MAX_INPUTS * 3) + (MAX_INPUTS * MERKLE_TREE_DEPTH * 2) + MAX_INPUTS + (MAX_OUTPUTS * 3) + 2
}

fn poseidon_subtrace_rows(
    witness: &TransactionWitness,
) -> Result<
    Vec<[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]>,
    TransactionCircuitError,
> {
    let (inputs, _input_flags) = padded_inputs(&witness.inputs);
    let (outputs, _output_flags) = padded_outputs(&witness.outputs);
    let mut traces = Vec::new();

    let (prf_hash, prf_traces) =
        trace_sponge_hash(NULLIFIER_DOMAIN_TAG, &bytes_to_felts(&witness.sk_spend));
    let prf = prf_hash[0];
    traces.extend(prf_traces);

    for input in &inputs {
        let (commitment, commitment_traces) =
            trace_sponge_hash(NOTE_DOMAIN_TAG, &commitment_inputs(&input.note));
        traces.extend(commitment_traces);

        let mut current = commitment;
        let mut pos = input.position;
        for level in 0..MERKLE_TREE_DEPTH {
            let sibling = input
                .merkle_path
                .siblings
                .get(level)
                .copied()
                .unwrap_or([Felt::ZERO; 6]);
            let (left, right) = if pos & 1 == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            let (next, merkle_traces) = trace_merkle_node(left, right);
            traces.extend(merkle_traces);
            current = next;
            pos >>= 1;
        }

        let (_, nullifier_traces) =
            trace_sponge_hash(NULLIFIER_DOMAIN_TAG, &nullifier_inputs(prf, input));
        traces.extend(nullifier_traces);
    }

    for output in &outputs {
        let (_, commitment_traces) =
            trace_sponge_hash(NOTE_DOMAIN_TAG, &commitment_inputs(&output.note));
        traces.extend(commitment_traces);
    }

    let balance_slots = witness.balance_slots()?;
    let native_delta = balance_slots
        .iter()
        .find(|slot| slot.asset_id == crate::constants::NATIVE_ASSET_ID)
        .map(|slot| slot.delta)
        .unwrap_or(0);
    let (_, balance_traces) = trace_sponge_hash(
        BALANCE_DOMAIN_TAG,
        &balance_commitment_inputs(native_delta, &balance_slots)?,
    );
    traces.extend(balance_traces);
    Ok(traces)
}

fn expanded_witness_words(
    public_values: &[u64],
    raw_witness: &[u64],
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]],
) -> Vec<u64> {
    let mut expanded = Vec::with_capacity(
        public_values.len()
            + raw_witness.len()
            + poseidon_rows.len() * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION * POSEIDON2_WIDTH,
    );
    expanded.extend_from_slice(public_values);
    expanded.extend_from_slice(raw_witness);
    for permutation in poseidon_rows {
        for row in permutation {
            expanded.extend_from_slice(row);
        }
    }
    expanded
}

fn smallwood_transcript_binding(
    statement: &SmallwoodPublicStatement,
    version: VersionBinding,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut bytes = Vec::from(SMALLWOOD_BINDING_TRANSCRIPT_DOMAIN);
    bytes.extend_from_slice(&smallwood_candidate_verifier_profile_material(version));
    let encoded = bincode::serialize(statement).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize smallwood public statement transcript binding: {err}"
        ))
    })?;
    bytes.extend_from_slice(&encoded);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    Ok(bytes)
}

fn push_bytes32_words(out: &mut Vec<u64>, bytes: &[u8; 32]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}

fn push_bytes48_words(out: &mut Vec<u64>, bytes: &[u8; 48]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}
fn pack_lppc_rows(words: &[u64]) -> Vec<[u64; SMALLWOOD_LPPC_PACKING_FACTOR]> {
    let mut rows = Vec::with_capacity(words.len().div_ceil(SMALLWOOD_LPPC_PACKING_FACTOR));
    for chunk in words.chunks(SMALLWOOD_LPPC_PACKING_FACTOR) {
        let mut row = [0u64; SMALLWOOD_LPPC_PACKING_FACTOR];
        row[..chunk.len()].copy_from_slice(chunk);
        rows.push(row);
    }
    rows
}

fn flatten_lppc_rows(rows: &[[u64; SMALLWOOD_LPPC_PACKING_FACTOR]]) -> Vec<u64> {
    let mut values = Vec::with_capacity(rows.len() * SMALLWOOD_LPPC_PACKING_FACTOR);
    for row in rows {
        values.extend_from_slice(row);
    }
    values
}

fn push_padded_input_note_fields(
    out: &mut Vec<u64>,
    inputs: &[InputNoteWitness],
) -> Result<(), TransactionCircuitError> {
    if inputs.len() > MAX_INPUTS {
        return Err(TransactionCircuitError::TooManyInputs(inputs.len()));
    }
    for idx in 0..MAX_INPUTS {
        out.push(inputs.get(idx).map(|input| input.note.value).unwrap_or(0));
    }
    for idx in 0..MAX_INPUTS {
        out.push(
            inputs
                .get(idx)
                .map(|input| input.note.asset_id)
                .unwrap_or(0),
        );
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_words(out, &input.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_words(out, &input.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_words(out, &input.note.rho);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_words(out, &input.note.r);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        out.push(inputs.get(idx).map(|input| input.position).unwrap_or(0));
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_words(out, &input.rho_seed);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            if input.merkle_path.siblings.len() != MERKLE_TREE_DEPTH {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "native tx input {idx} merkle path has length {}, expected {}",
                    input.merkle_path.siblings.len(),
                    MERKLE_TREE_DEPTH
                )));
            }
            for sibling in &input.merkle_path.siblings {
                push_bytes48_words(out, &felts_to_bytes48(sibling));
            }
        } else {
            out.extend(std::iter::repeat_n(0u64, MERKLE_TREE_DEPTH * 48));
        }
    }
    Ok(())
}

fn push_padded_output_note_fields(
    out: &mut Vec<u64>,
    outputs: &[OutputNoteWitness],
) -> Result<(), TransactionCircuitError> {
    if outputs.len() > MAX_OUTPUTS {
        return Err(TransactionCircuitError::TooManyOutputs(outputs.len()));
    }
    for idx in 0..MAX_OUTPUTS {
        out.push(
            outputs
                .get(idx)
                .map(|output| output.note.value)
                .unwrap_or(0),
        );
    }
    for idx in 0..MAX_OUTPUTS {
        out.push(
            outputs
                .get(idx)
                .map(|output| output.note.asset_id)
                .unwrap_or(0),
        );
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_words(out, &output.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_words(out, &output.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_words(out, &output.note.rho);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_words(out, &output.note.r);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    Ok(())
}

fn push_padded_ciphertext_hashes(
    out: &mut Vec<u64>,
    ciphertext_hashes: &[[u8; 48]],
) -> Result<(), TransactionCircuitError> {
    if ciphertext_hashes.len() > MAX_OUTPUTS {
        return Err(TransactionCircuitError::CiphertextHashMismatch(
            ciphertext_hashes.len(),
        ));
    }
    for idx in 0..MAX_OUTPUTS {
        push_bytes48_words(
            out,
            &ciphertext_hashes.get(idx).copied().unwrap_or([0u8; 48]),
        );
    }
    Ok(())
}

fn bytes_to_felts(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(8)
        .map(|chunk| {
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            Felt::from_u64(u64::from_be_bytes(buf))
        })
        .collect()
}

fn commitment_inputs(note: &crate::note::NoteData) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(Felt::from_u64(note.value));
    inputs.push(Felt::from_u64(note.asset_id));
    inputs.extend(bytes_to_felts(&note.pk_recipient));
    inputs.extend(bytes_to_felts(&note.rho));
    inputs.extend(bytes_to_felts(&note.r));
    inputs.extend(bytes_to_felts(&note.pk_auth));
    inputs
}

fn nullifier_inputs(prf: Felt, input: &InputNoteWitness) -> Vec<Felt> {
    let mut inputs = Vec::new();
    inputs.push(prf);
    inputs.push(Felt::from_u64(input.position));
    inputs.extend(bytes_to_felts(&input.note.rho));
    inputs
}

fn balance_commitment_inputs(
    native_delta: i128,
    slots: &[BalanceSlot],
) -> Result<Vec<Felt>, TransactionCircuitError> {
    let mut inputs = Vec::with_capacity(1 + slots.len() * 2);
    let native_mag = native_delta.unsigned_abs();
    if native_mag > u128::from(u64::MAX) {
        return Err(TransactionCircuitError::BalanceDeltaOutOfRange(
            0, native_mag,
        ));
    }
    inputs.push(Felt::from_u64(native_mag as u64));
    for slot in slots {
        let magnitude = slot.delta.unsigned_abs();
        if magnitude > u128::from(u64::MAX) {
            return Err(TransactionCircuitError::BalanceDeltaOutOfRange(
                slot.asset_id,
                magnitude,
            ));
        }
        inputs.push(Felt::from_u64(slot.asset_id));
        inputs.push(Felt::from_u64(magnitude as u64));
    }
    Ok(inputs)
}

fn trace_merkle_node(
    left: HashFelt,
    right: HashFelt,
) -> (
    HashFelt,
    Vec<[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]>,
) {
    let mut inputs = Vec::with_capacity(12);
    inputs.extend_from_slice(&left);
    inputs.extend_from_slice(&right);
    trace_sponge_hash(MERKLE_DOMAIN_TAG, &inputs)
}

fn trace_sponge_hash(
    domain_tag: u64,
    inputs: &[Felt],
) -> (
    HashFelt,
    Vec<[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]>,
) {
    let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
    state[0] = Felt::from_u64(domain_tag);
    state[POSEIDON2_WIDTH - 1] = Felt::ONE;
    let mut cursor = 0usize;
    let mut permutations = Vec::new();
    while cursor < inputs.len() {
        let take = core::cmp::min(POSEIDON2_RATE, inputs.len() - cursor);
        for idx in 0..take {
            state[idx] += inputs[cursor + idx];
        }
        let mut rows = [[0u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION];
        rows[0] = snapshot_state(&state);
        for step in 0..POSEIDON2_STEPS {
            poseidon2_step(&mut state, step);
            rows[step + 1] = snapshot_state(&state);
        }
        permutations.push(rows);
        cursor += take;
    }
    let mut output = [Felt::ZERO; POSEIDON2_RATE];
    output.copy_from_slice(&state[..POSEIDON2_RATE]);
    (output, permutations)
}

fn snapshot_state(state: &[Felt; POSEIDON2_WIDTH]) -> [u64; POSEIDON2_WIDTH] {
    let mut row = [0u64; POSEIDON2_WIDTH];
    for (idx, value) in state.iter().enumerate() {
        row[idx] = value.as_canonical_u64();
    }
    row
}

fn padded_inputs(inputs: &[InputNoteWitness]) -> (Vec<InputNoteWitness>, [bool; MAX_INPUTS]) {
    let mut padded = Vec::with_capacity(MAX_INPUTS);
    let mut flags = [false; MAX_INPUTS];
    for (idx, note) in inputs.iter().cloned().enumerate() {
        if idx < MAX_INPUTS {
            padded.push(note);
            flags[idx] = true;
        }
    }
    while padded.len() < MAX_INPUTS {
        padded.push(dummy_input());
    }
    (padded, flags)
}

fn padded_outputs(outputs: &[OutputNoteWitness]) -> (Vec<OutputNoteWitness>, [bool; MAX_OUTPUTS]) {
    let mut padded = Vec::with_capacity(MAX_OUTPUTS);
    let mut flags = [false; MAX_OUTPUTS];
    for (idx, note) in outputs.iter().cloned().enumerate() {
        if idx < MAX_OUTPUTS {
            padded.push(note);
            flags[idx] = true;
        }
    }
    while padded.len() < MAX_OUTPUTS {
        padded.push(dummy_output());
    }
    (padded, flags)
}

fn dummy_input() -> InputNoteWitness {
    InputNoteWitness {
        note: crate::note::NoteData {
            value: 0,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            pk_auth: [0u8; 32],
            rho: [0u8; 32],
            r: [0u8; 32],
        },
        position: 0xA5A5_A5A5,
        rho_seed: [0u8; 32],
        merkle_path: MerklePath::default(),
    }
}

fn dummy_output() -> OutputNoteWitness {
    OutputNoteWitness {
        note: crate::note::NoteData {
            value: 0,
            asset_id: 0,
            pk_recipient: [0u8; 32],
            pk_auth: [0u8; 32],
            rho: [0u8; 32],
            r: [0u8; 32],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing_pq::{felts_to_bytes48, merkle_node, spend_auth_key_bytes};
    use crate::note::NoteData;
    use crate::public_inputs::StablecoinPolicyBinding;
    use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;

    fn sample_witness() -> TransactionWitness {
        let sk_spend = [42u8; 32];
        let pk_auth = spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: crate::constants::NATIVE_ASSET_ID,
            pk_recipient: [2u8; 32],
            pk_auth,
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: 1,
            pk_recipient: [5u8; 32],
            pk_auth,
            rho: [6u8; 32],
            r: [7u8; 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..MERKLE_TREE_DEPTH {
            let zero = [Felt::ZERO; 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }
        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [9u8; 32],
                    merkle_path: MerklePath {
                        siblings: siblings0,
                    },
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [8u8; 32],
                    merkle_path: MerklePath {
                        siblings: siblings1,
                    },
                },
            ],
            outputs: vec![
                OutputNoteWitness {
                    note: NoteData {
                        value: 3,
                        asset_id: crate::constants::NATIVE_ASSET_ID,
                        pk_recipient: [11u8; 32],
                        pk_auth: [111u8; 32],
                        rho: [12u8; 32],
                        r: [13u8; 32],
                    },
                },
                OutputNoteWitness {
                    note: NoteData {
                        value: 5,
                        asset_id: 1,
                        pk_recipient: [21u8; 32],
                        pk_auth: [121u8; 32],
                        rho: [22u8; 32],
                        r: [23u8; 32],
                    },
                },
            ],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&current),
            fee: 5,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    #[test]
    fn smallwood_frontend_matches_expected_shape() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let statement = build_smallwood_public_statement_from_witness(&witness).unwrap();
        assert_eq!(statement.public_value_count, 78);
        assert_eq!(statement.raw_witness_len, 3_991);
        assert_eq!(statement.poseidon_permutation_count, 145);
        assert_eq!(statement.poseidon_state_row_count, 4_640);
        assert_eq!(statement.expanded_witness_len, 59_749);
        assert_eq!(statement.lppc_row_count, 934);
        assert_eq!(statement.lppc_packing_factor, 64);
        assert_eq!(statement.effective_constraint_degree, 8);
    }

    #[test]
    fn smallwood_candidate_roundtrip_verifies() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let proof = prove_smallwood_candidate(&witness).unwrap();
        let report = verify_smallwood_candidate_transaction_proof(&proof).unwrap();
        assert!(report.verified);
    }
}
