use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_versioning::{tx_proof_backend_for_version, TxProofBackend, VersionBinding};
use serde::{Deserialize, Serialize};
use transaction_core::{
    constants::{
        BALANCE_DOMAIN_TAG, MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG,
        POSEIDON2_RATE, POSEIDON2_STEPS, POSEIDON2_WIDTH,
    },
    p3_air::TransactionPublicInputsP3,
    poseidon2::poseidon2_step,
};

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{bytes48_to_felts, merkle_node, Felt, HashFelt},
    note::{InputNoteWitness, MerklePath, OutputNoteWitness, MERKLE_TREE_DEPTH},
    proof::{
        transaction_public_inputs_p3_from_parts, SerializedStarkInputs, TransactionProof,
        VerificationReport,
    },
    public_inputs::TransactionPublicInputs,
    smallwood_native::{
        projected_candidate_proof_bytes as projected_smallwood_backend_proof_bytes,
        prove_candidate as prove_smallwood_backend, test_candidate_witness,
        verify_candidate as verify_smallwood_backend,
    },
    witness::TransactionWitness,
};

const SMALLWOOD_PUBLIC_STATEMENT_DOMAIN: &[u8] = b"hegemon.tx.smallwood-public-statement.v1";
const SMALLWOOD_BINDING_TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.tx.smallwood-binding-transcript.v1";

pub const SMALLWOOD_LPPC_PACKING_FACTOR: usize = 1;
pub const SMALLWOOD_PACKED_LPPC_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_BRIDGE_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE: u16 = 8;
pub const SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION: usize = POSEIDON2_STEPS + 1;
pub const SMALLWOOD_RHO: u32 = 2;
pub const SMALLWOOD_NB_OPENED_EVALS: u32 = 3;
pub const SMALLWOOD_BETA: u32 = 3;
pub const SMALLWOOD_OPENING_POW_BITS: u32 = 0;
pub const SMALLWOOD_DECS_NB_EVALS: u32 = 4096;
pub const SMALLWOOD_DECS_NB_OPENED_EVALS: u32 = 65;
pub const SMALLWOOD_DECS_ETA: u32 = 10;
pub const SMALLWOOD_DECS_POW_BITS: u32 = 0;
#[allow(dead_code)]
const SMALLWOOD_BASE_PUBLIC_VALUE_COUNT: usize = 78;
const SMALLWOOD_LANE_SELECTOR_ROWS: usize = SMALLWOOD_BRIDGE_PACKING_FACTOR;
const SMALLWOOD_WORDS_PER_32_BYTES: usize = 4;
const SMALLWOOD_WORDS_PER_48_BYTES: usize = 6;
const SMALLWOOD_PUBLIC_ROWS: usize = 78;
const SMALLWOOD_INPUT_SECRET_ROWS: usize = 1
    + 1
    + (SMALLWOOD_WORDS_PER_32_BYTES * 4)
    + 1
    + 2
    + MERKLE_TREE_DEPTH
    + (MERKLE_TREE_DEPTH * SMALLWOOD_WORDS_PER_48_BYTES * 4);
const SMALLWOOD_OUTPUT_SECRET_ROWS: usize = 1 + 1 + (SMALLWOOD_WORDS_PER_32_BYTES * 4) + 2;
const SMALLWOOD_SECRET_WITNESS_ROWS: usize = SMALLWOOD_WORDS_PER_32_BYTES
    + (MAX_INPUTS * SMALLWOOD_INPUT_SECRET_ROWS)
    + (MAX_OUTPUTS * SMALLWOOD_OUTPUT_SECRET_ROWS)
    + 2;
const SMALLWOOD_INPUT_SIBLING_OFFSET: usize = 53;
const SMALLWOOD_INPUT_AUX_HASH_OFFSET: usize =
    SMALLWOOD_INPUT_SIBLING_OFFSET + (MERKLE_TREE_DEPTH * SMALLWOOD_WORDS_PER_48_BYTES);

#[inline]
fn bridge_input_base(input: usize) -> usize {
    SMALLWOOD_PUBLIC_ROWS + SMALLWOOD_WORDS_PER_32_BYTES + input * SMALLWOOD_INPUT_SECRET_ROWS
}

#[inline]
fn bridge_output_base(output: usize) -> usize {
    SMALLWOOD_PUBLIC_ROWS
        + SMALLWOOD_WORDS_PER_32_BYTES
        + MAX_INPUTS * SMALLWOOD_INPUT_SECRET_ROWS
        + output * SMALLWOOD_OUTPUT_SECRET_ROWS
}

#[inline]
fn bridge_row_sk_chunk(chunk: usize) -> usize {
    SMALLWOOD_PUBLIC_ROWS + chunk
}

#[inline]
fn bridge_row_input_value(input: usize) -> usize {
    bridge_input_base(input)
}

#[inline]
fn bridge_row_input_asset(input: usize) -> usize {
    bridge_input_base(input) + 1
}

#[inline]
fn bridge_row_input_pk_auth(input: usize, limb: usize) -> usize {
    bridge_input_base(input) + 6 + limb
}

#[inline]
fn bridge_row_input_pk_recipient(input: usize, limb: usize) -> usize {
    bridge_input_base(input) + 2 + limb
}

#[inline]
fn bridge_row_input_rho(input: usize, limb: usize) -> usize {
    bridge_input_base(input) + 10 + limb
}

#[inline]
fn bridge_row_input_r(input: usize, limb: usize) -> usize {
    bridge_input_base(input) + 14 + limb
}

#[inline]
fn bridge_row_input_position(input: usize) -> usize {
    bridge_input_base(input) + 18
}

#[inline]
fn bridge_row_input_selector(input: usize, bit: usize) -> usize {
    bridge_input_base(input) + 19 + bit
}

#[inline]
fn bridge_row_input_direction(input: usize, bit: usize) -> usize {
    bridge_input_base(input) + 21 + bit
}

#[inline]
fn bridge_row_input_sibling(input: usize, level: usize, limb: usize) -> usize {
    bridge_input_base(input)
        + SMALLWOOD_INPUT_SIBLING_OFFSET
        + level * SMALLWOOD_WORDS_PER_48_BYTES
        + limb
}

#[inline]
fn bridge_row_input_current_hash(input: usize, level: usize, limb: usize) -> usize {
    bridge_input_base(input)
        + SMALLWOOD_INPUT_AUX_HASH_OFFSET
        + level * (SMALLWOOD_WORDS_PER_48_BYTES * 3)
        + limb
}

#[inline]
fn bridge_row_input_merkle_left(input: usize, level: usize, limb: usize) -> usize {
    bridge_input_base(input)
        + SMALLWOOD_INPUT_AUX_HASH_OFFSET
        + level * (SMALLWOOD_WORDS_PER_48_BYTES * 3)
        + SMALLWOOD_WORDS_PER_48_BYTES
        + limb
}

#[inline]
fn bridge_row_input_merkle_right(input: usize, level: usize, limb: usize) -> usize {
    bridge_input_base(input)
        + SMALLWOOD_INPUT_AUX_HASH_OFFSET
        + level * (SMALLWOOD_WORDS_PER_48_BYTES * 3)
        + (SMALLWOOD_WORDS_PER_48_BYTES * 2)
        + limb
}

#[inline]
fn bridge_row_output_value(output: usize) -> usize {
    bridge_output_base(output)
}

#[inline]
fn bridge_row_output_asset(output: usize) -> usize {
    bridge_output_base(output) + 1
}

#[inline]
fn bridge_row_output_selector(output: usize, bit: usize) -> usize {
    bridge_output_base(output) + 18 + bit
}

#[inline]
fn bridge_row_output_pk_recipient(output: usize, limb: usize) -> usize {
    bridge_output_base(output) + 2 + limb
}

#[inline]
fn bridge_row_output_pk_auth(output: usize, limb: usize) -> usize {
    bridge_output_base(output) + 6 + limb
}

#[inline]
fn bridge_row_output_rho(output: usize, limb: usize) -> usize {
    bridge_output_base(output) + 10 + limb
}

#[inline]
fn bridge_row_output_r(output: usize, limb: usize) -> usize {
    bridge_output_base(output) + 14 + limb
}

#[inline]
fn bridge_row_stable_selector(bit: usize) -> usize {
    SMALLWOOD_PUBLIC_ROWS + SMALLWOOD_SECRET_WITNESS_ROWS - 2 + bit
}

#[inline]
fn bridge_selector_row(selector: usize) -> usize {
    SMALLWOOD_PUBLIC_ROWS + SMALLWOOD_SECRET_WITNESS_ROWS + selector
}

#[inline]
fn bridge_poseidon_rows_start() -> usize {
    SMALLWOOD_PUBLIC_ROWS + SMALLWOOD_SECRET_WITNESS_ROWS + SMALLWOOD_LANE_SELECTOR_ROWS
}

#[inline]
fn bridge_poseidon_row(permutation: usize, step_row: usize, limb: usize) -> usize {
    let group = permutation / SMALLWOOD_BRIDGE_PACKING_FACTOR;
    bridge_poseidon_rows_start()
        + (group * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION + step_row) * POSEIDON2_WIDTH
        + limb
}

#[inline]
fn packed_bridge_index(row: usize, lane: usize) -> u32 {
    (row * SMALLWOOD_BRIDGE_PACKING_FACTOR + lane) as u32
}

#[inline]
fn packed_bridge_permutation_lane(permutation: usize) -> usize {
    permutation % SMALLWOOD_BRIDGE_PACKING_FACTOR
}

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
pub struct SmallwoodLinearConstraints {
    pub term_offsets: Vec<u32>,
    pub term_indices: Vec<u32>,
    pub term_coefficients: Vec<u64>,
    pub targets: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodCandidateProof {
    pub ark_proof: Vec<u8>,
}

#[allow(dead_code)]
struct SmallwoodFrontendMaterial {
    public_inputs: TransactionPublicInputs,
    serialized_public_inputs: SerializedStarkInputs,
    public_statement: SmallwoodPublicStatement,
    padded_expanded_witness: Vec<u64>,
    linear_constraints: SmallwoodLinearConstraints,
    transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackedSmallwoodFrontendMaterial {
    pub public_statement: SmallwoodPublicStatement,
    pub packed_expanded_witness: Vec<u64>,
    pub linear_constraints: SmallwoodLinearConstraints,
    pub transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackedBridgeSmallwoodFrontendMaterial {
    pub public_inputs: TransactionPublicInputs,
    pub serialized_public_inputs: SerializedStarkInputs,
    pub public_statement: SmallwoodPublicStatement,
    pub packed_witness_rows: Vec<u64>,
    pub linear_constraints: SmallwoodLinearConstraints,
    pub transcript_binding: Vec<u8>,
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
    let material = build_packed_smallwood_bridge_material(witness)?;
    test_candidate_witness(
        &material.packed_witness_rows,
        material.public_statement.lppc_row_count as usize,
        SMALLWOOD_BRIDGE_PACKING_FACTOR,
        SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
        &material.linear_constraints.term_offsets,
        &material.linear_constraints.term_indices,
        &material.linear_constraints.term_coefficients,
        &material.linear_constraints.targets,
    )?;
    let ark_proof = prove_smallwood_backend(
        &material.packed_witness_rows,
        material.public_statement.lppc_row_count as usize,
        SMALLWOOD_BRIDGE_PACKING_FACTOR,
        SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
        &material.linear_constraints.term_offsets,
        &material.linear_constraints.term_indices,
        &material.linear_constraints.term_coefficients,
        &material.linear_constraints.targets,
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

pub fn projected_smallwood_candidate_proof_bytes(
    witness: &TransactionWitness,
) -> Result<usize, TransactionCircuitError> {
    let material = build_packed_smallwood_bridge_material_from_witness(witness)?;
    projected_smallwood_backend_proof_bytes(
        material.public_statement.lppc_row_count as usize,
        material.public_statement.lppc_packing_factor as usize,
        material.public_statement.effective_constraint_degree,
        material.linear_constraints.targets.len(),
    )
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
    let public_statement = build_packed_smallwood_bridge_public_statement(pub_inputs, version)?;
    let linear_constraints = build_packed_bridge_linear_constraints(&public_statement);
    verify_smallwood_backend(
        public_statement.lppc_row_count as usize,
        SMALLWOOD_BRIDGE_PACKING_FACTOR,
        SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
        &linear_constraints.term_offsets,
        &linear_constraints.term_indices,
        &linear_constraints.term_coefficients,
        &linear_constraints.targets,
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
    material.extend_from_slice(&(SMALLWOOD_BRIDGE_PACKING_FACTOR as u64).to_le_bytes());
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

pub fn build_packed_smallwood_public_statement_from_witness(
    witness: &TransactionWitness,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    Ok(build_packed_smallwood_frontend_material(witness)?.public_statement)
}

pub fn build_packed_smallwood_frontend_material_from_witness(
    witness: &TransactionWitness,
) -> Result<PackedSmallwoodFrontendMaterial, TransactionCircuitError> {
    build_packed_smallwood_frontend_material(witness)
}

pub fn build_packed_smallwood_bridge_material_from_witness(
    witness: &TransactionWitness,
) -> Result<PackedBridgeSmallwoodFrontendMaterial, TransactionCircuitError> {
    build_packed_smallwood_bridge_material(witness)
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
    let secret_witness = semantic_secret_witness_rows(witness, &public_inputs_p3)?;
    let poseidon_rows = poseidon_subtrace_rows(witness)?;
    let public_statement = build_smallwood_public_statement(&public_inputs_p3, witness.version)?;
    let semantic_rows = expanded_witness_words(
        &public_statement.public_values,
        &secret_witness,
        &poseidon_rows,
    );
    let padded_expanded_witness = semantic_rows;
    let linear_constraints = build_coordinate_linear_constraints((
        build_smallwood_public_selector_indices(public_statement.public_values.len()),
        public_statement.public_values.clone(),
    ));
    let transcript_binding = smallwood_transcript_binding(&public_statement, witness.version)?;
    Ok(SmallwoodFrontendMaterial {
        public_inputs,
        serialized_public_inputs,
        padded_expanded_witness,
        linear_constraints,
        public_statement,
        transcript_binding,
    })
}

fn build_packed_smallwood_frontend_material(
    witness: &TransactionWitness,
) -> Result<PackedSmallwoodFrontendMaterial, TransactionCircuitError> {
    witness.validate()?;
    validate_native_merkle_membership(witness)?;
    let public_inputs = witness.public_inputs()?;
    let serialized_public_inputs = serialized_public_inputs_from_witness(witness, &public_inputs)?;
    let public_inputs_p3 =
        transaction_public_inputs_p3_from_parts(&public_inputs, &serialized_public_inputs)?;
    let raw_witness = native_relation_raw_witness_rows(witness)?;
    let poseidon_rows = packed_poseidon_subtrace_rows(witness, &public_inputs)?;
    let public_statement = build_packed_smallwood_public_statement(
        &public_inputs_p3,
        witness.version,
        &raw_witness,
        &poseidon_rows,
    )?;
    let expanded_witness = expanded_witness_words(
        &public_statement.public_values,
        &raw_witness,
        &poseidon_rows,
    );
    let packed_expanded_witness =
        pad_for_lppc_rows(expanded_witness, SMALLWOOD_PACKED_LPPC_PACKING_FACTOR);
    let linear_constraints = build_coordinate_linear_constraints((
        build_smallwood_public_selector_indices(public_statement.public_values.len()),
        public_inputs_p3
            .to_vec()
            .into_iter()
            .map(|felt| felt.as_canonical_u64())
            .chain([
                u64::from(witness.version.circuit),
                u64::from(witness.version.crypto),
            ])
            .collect(),
    ));
    let transcript_binding = smallwood_transcript_binding(&public_statement, witness.version)?;
    Ok(PackedSmallwoodFrontendMaterial {
        public_statement,
        packed_expanded_witness,
        linear_constraints,
        transcript_binding,
    })
}

fn build_packed_smallwood_bridge_material(
    witness: &TransactionWitness,
) -> Result<PackedBridgeSmallwoodFrontendMaterial, TransactionCircuitError> {
    witness.validate()?;
    validate_native_merkle_membership(witness)?;
    let public_inputs = witness.public_inputs()?;
    let serialized_public_inputs = serialized_public_inputs_from_witness(witness, &public_inputs)?;
    let public_inputs_p3 =
        transaction_public_inputs_p3_from_parts(&public_inputs, &serialized_public_inputs)?;
    let public_values: Vec<u64> = public_inputs_p3
        .to_vec()
        .into_iter()
        .map(|felt| felt.as_canonical_u64())
        .chain([
            u64::from(witness.version.circuit),
            u64::from(witness.version.crypto),
        ])
        .collect();
    let secret_rows = semantic_secret_witness_rows(witness, &public_inputs_p3)?;
    let poseidon_rows = poseidon_subtrace_rows(witness)?;
    let packed_witness_rows = packed_bridge_witness_rows(
        &public_values,
        &secret_rows,
        &poseidon_rows,
        SMALLWOOD_BRIDGE_PACKING_FACTOR,
    );
    let row_count = packed_witness_rows.len() / SMALLWOOD_BRIDGE_PACKING_FACTOR;
    let public_statement = SmallwoodPublicStatement {
        public_values: public_values.clone(),
        public_value_count: public_values.len() as u32,
        raw_witness_len: secret_rows.len() as u32,
        lppc_row_count: row_count as u32,
        poseidon_permutation_count: poseidon_rows.len() as u32,
        poseidon_state_row_count: (poseidon_rows.len()
            * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            as u32,
        expanded_witness_len: packed_witness_rows.len() as u32,
        lppc_packing_factor: SMALLWOOD_BRIDGE_PACKING_FACTOR as u16,
        effective_constraint_degree: SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    };
    let linear_constraints = build_packed_bridge_linear_constraints(&public_statement);
    let transcript_binding = smallwood_transcript_binding(&public_statement, witness.version)?;
    Ok(PackedBridgeSmallwoodFrontendMaterial {
        public_inputs,
        serialized_public_inputs,
        public_statement,
        packed_witness_rows,
        linear_constraints,
        transcript_binding,
    })
}

#[allow(dead_code)]
fn build_packed_smallwood_bridge_public_statement(
    public_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    let public_values: Vec<u64> = public_inputs
        .to_vec()
        .into_iter()
        .map(|felt| felt.as_canonical_u64())
        .chain([u64::from(version.circuit), u64::from(version.crypto)])
        .collect();
    if public_values.len() != SMALLWOOD_BASE_PUBLIC_VALUE_COUNT {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "unexpected smallwood bridge public value count {}, expected {}",
            public_values.len(),
            SMALLWOOD_BASE_PUBLIC_VALUE_COUNT
        )));
    }
    let poseidon_permutation_count = smallwood_poseidon_permutation_count();
    let poseidon_group_count = smallwood_bridge_poseidon_group_count(
        poseidon_permutation_count,
        SMALLWOOD_BRIDGE_PACKING_FACTOR,
    );
    let lppc_row_count = SMALLWOOD_BASE_PUBLIC_VALUE_COUNT
        + SMALLWOOD_SECRET_WITNESS_ROWS
        + SMALLWOOD_LANE_SELECTOR_ROWS
        + (poseidon_group_count * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION * POSEIDON2_WIDTH);
    Ok(SmallwoodPublicStatement {
        public_values,
        public_value_count: SMALLWOOD_BASE_PUBLIC_VALUE_COUNT as u32,
        raw_witness_len: SMALLWOOD_SECRET_WITNESS_ROWS as u32,
        lppc_row_count: lppc_row_count as u32,
        poseidon_permutation_count: poseidon_permutation_count as u32,
        poseidon_state_row_count: (poseidon_permutation_count
            * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            as u32,
        expanded_witness_len: (lppc_row_count * SMALLWOOD_BRIDGE_PACKING_FACTOR) as u32,
        lppc_packing_factor: SMALLWOOD_BRIDGE_PACKING_FACTOR as u16,
        effective_constraint_degree: SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    })
}

fn build_smallwood_public_statement(
    public_inputs: &TransactionPublicInputsP3,
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

    let raw_witness_len = SMALLWOOD_SECRET_WITNESS_ROWS;
    let poseidon_permutation_count = smallwood_poseidon_permutation_count();
    let poseidon_state_row_count =
        poseidon_permutation_count * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION;
    let semantic_row_count =
        public_values.len() + raw_witness_len + (poseidon_state_row_count * POSEIDON2_WIDTH);
    let expanded_witness_len = semantic_row_count * SMALLWOOD_LPPC_PACKING_FACTOR;
    let lppc_row_count = semantic_row_count;

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

fn build_packed_smallwood_public_statement(
    public_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
    raw_witness: &[u64],
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]],
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

    let raw_witness_len = raw_witness.len();
    let poseidon_permutation_count = poseidon_rows.len();
    let poseidon_state_row_count =
        poseidon_permutation_count * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION;
    let expanded_witness_len =
        public_values.len() + raw_witness_len + (poseidon_state_row_count * POSEIDON2_WIDTH);
    let lppc_row_count = expanded_witness_len.div_ceil(SMALLWOOD_PACKED_LPPC_PACKING_FACTOR);

    Ok(SmallwoodPublicStatement {
        public_value_count: public_values.len() as u32,
        public_values,
        raw_witness_len: raw_witness_len as u32,
        lppc_row_count: lppc_row_count as u32,
        poseidon_permutation_count: poseidon_permutation_count as u32,
        poseidon_state_row_count: poseidon_state_row_count as u32,
        expanded_witness_len: expanded_witness_len as u32,
        lppc_packing_factor: SMALLWOOD_PACKED_LPPC_PACKING_FACTOR as u16,
        effective_constraint_degree: SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    })
}

fn build_smallwood_public_selector_indices(public_value_count: usize) -> Vec<u32> {
    (0..public_value_count as u32).collect()
}

fn build_coordinate_linear_constraints(
    selectors: (Vec<u32>, Vec<u64>),
) -> SmallwoodLinearConstraints {
    let (indices, targets) = selectors;
    let term_offsets = (0..=indices.len() as u32).collect();
    let term_coefficients = vec![1u64; indices.len()];
    SmallwoodLinearConstraints {
        term_offsets,
        term_indices: indices,
        term_coefficients,
        targets,
    }
}

fn push_linear_constraint(
    constraints: &mut SmallwoodLinearConstraints,
    terms: &[(u32, u64)],
    target: u64,
) {
    for (index, coefficient) in terms {
        constraints.term_indices.push(*index);
        constraints.term_coefficients.push(*coefficient);
    }
    constraints
        .term_offsets
        .push(constraints.term_indices.len() as u32);
    constraints.targets.push(target);
}

fn push_bridge_constraint(
    constraints: &mut SmallwoodLinearConstraints,
    terms: &[(usize, usize, u64)],
    target: u64,
) {
    let mapped = terms
        .iter()
        .map(|(row, lane, coeff)| (packed_bridge_index(*row, *lane), *coeff))
        .collect::<Vec<_>>();
    push_linear_constraint(constraints, &mapped, target);
}

fn push_bridge_cell_equals(
    constraints: &mut SmallwoodLinearConstraints,
    lhs_row: usize,
    lhs_lane: usize,
    rhs_row: usize,
    rhs_lane: usize,
    neg_one: u64,
) {
    push_bridge_constraint(
        constraints,
        &[(lhs_row, lhs_lane, 1), (rhs_row, rhs_lane, neg_one)],
        0,
    );
}

fn build_packed_bridge_linear_constraints(
    statement: &SmallwoodPublicStatement,
) -> SmallwoodLinearConstraints {
    let packing_factor = statement.lppc_packing_factor as usize;
    let public_row_count = statement.public_value_count as usize;
    let secret_row_start = public_row_count;
    let secret_row_count = statement.raw_witness_len as usize;
    let selector_row_start = secret_row_start + secret_row_count;
    let neg_one = (transaction_core::constants::FIELD_MODULUS as u64).wrapping_sub(1);

    let mut constraints = SmallwoodLinearConstraints {
        term_offsets: vec![0],
        term_indices: Vec::new(),
        term_coefficients: Vec::new(),
        targets: Vec::new(),
    };

    for (row, value) in statement.public_values.iter().enumerate() {
        let base = (row * packing_factor) as u32;
        push_linear_constraint(&mut constraints, &[(base, 1)], *value);
    }

    for row in 0..public_row_count {
        let base = (row * packing_factor) as u32;
        for lane in 1..packing_factor {
            push_linear_constraint(
                &mut constraints,
                &[(base + lane as u32, 1), (base, neg_one)],
                0,
            );
        }
    }

    for row in 0..secret_row_count {
        let row_base = ((secret_row_start + row) * packing_factor) as u32;
        for lane in 1..packing_factor {
            push_linear_constraint(
                &mut constraints,
                &[(row_base + lane as u32, 1), (row_base, neg_one)],
                0,
            );
        }
    }

    for selector in 0..SMALLWOOD_LANE_SELECTOR_ROWS {
        let row_base = ((selector_row_start + selector) * packing_factor) as u32;
        for lane in 0..packing_factor {
            push_linear_constraint(
                &mut constraints,
                &[(row_base + lane as u32, 1)],
                u64::from(lane == selector),
            );
        }
    }

    let public_flag = |row: usize| statement.public_values[row] != 0;
    let push_fresh_poseidon_init =
        |constraints: &mut SmallwoodLinearConstraints,
         permutation: usize,
         domain_tag: u64,
         absorb_rows: &[(usize, usize)]| {
            let lane = packed_bridge_permutation_lane(permutation);
            for limb in 0..POSEIDON2_WIDTH {
                let row = bridge_poseidon_row(permutation, 0, limb);
                let mut terms = vec![(row, lane, 1)];
                let mut target = 0u64;
                if limb == 0 {
                    target = domain_tag;
                }
                if limb == POSEIDON2_WIDTH - 1 {
                    target = target.wrapping_add(1);
                }
                if limb < absorb_rows.len() {
                    terms.push((absorb_rows[limb].0, absorb_rows[limb].1, neg_one));
                }
                push_bridge_constraint(constraints, &terms, target);
            }
        };
    let push_continued_poseidon_init =
        |constraints: &mut SmallwoodLinearConstraints,
         permutation: usize,
         previous_permutation: usize,
         absorb_rows: &[usize]| {
            let lane = packed_bridge_permutation_lane(permutation);
            let previous_lane = packed_bridge_permutation_lane(previous_permutation);
            for limb in 0..POSEIDON2_WIDTH {
                let row = bridge_poseidon_row(permutation, 0, limb);
                let previous = bridge_poseidon_row(
                    previous_permutation,
                    SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                    limb,
                );
                let mut terms = vec![(row, lane, 1), (previous, previous_lane, neg_one)];
                if limb < absorb_rows.len() {
                    terms.push((absorb_rows[limb], lane, neg_one));
                }
                push_bridge_constraint(constraints, &terms, 0);
            }
        };

    push_fresh_poseidon_init(
        &mut constraints,
        bridge_prf_permutation(),
        NULLIFIER_DOMAIN_TAG,
        &[
            (bridge_row_sk_chunk(0), 0),
            (bridge_row_sk_chunk(1), 0),
            (bridge_row_sk_chunk(2), 0),
            (bridge_row_sk_chunk(3), 0),
        ],
    );

    for input in 0..MAX_INPUTS {
        push_fresh_poseidon_init(
            &mut constraints,
            bridge_input_commitment_permutation(input, 0),
            NOTE_DOMAIN_TAG,
            &[
                (bridge_row_input_value(input), 0),
                (bridge_row_input_asset(input), 0),
                (bridge_row_input_pk_recipient(input, 0), 0),
                (bridge_row_input_pk_recipient(input, 1), 0),
                (bridge_row_input_pk_recipient(input, 2), 0),
                (bridge_row_input_pk_recipient(input, 3), 0),
            ],
        );
        push_continued_poseidon_init(
            &mut constraints,
            bridge_input_commitment_permutation(input, 1),
            bridge_input_commitment_permutation(input, 0),
            &[
                bridge_row_input_rho(input, 0),
                bridge_row_input_rho(input, 1),
                bridge_row_input_rho(input, 2),
                bridge_row_input_rho(input, 3),
                bridge_row_input_r(input, 0),
                bridge_row_input_r(input, 1),
            ],
        );
        push_continued_poseidon_init(
            &mut constraints,
            bridge_input_commitment_permutation(input, 2),
            bridge_input_commitment_permutation(input, 1),
            &[
                bridge_row_input_r(input, 2),
                bridge_row_input_r(input, 3),
                bridge_row_input_pk_auth(input, 0),
                bridge_row_input_pk_auth(input, 1),
                bridge_row_input_pk_auth(input, 2),
                bridge_row_input_pk_auth(input, 3),
            ],
        );
        for level in 0..MERKLE_TREE_DEPTH {
            push_fresh_poseidon_init(
                &mut constraints,
                bridge_input_merkle_permutation(input, level, 0),
                MERKLE_DOMAIN_TAG,
                &[
                    (bridge_row_input_merkle_left(input, level, 0), 0),
                    (bridge_row_input_merkle_left(input, level, 1), 0),
                    (bridge_row_input_merkle_left(input, level, 2), 0),
                    (bridge_row_input_merkle_left(input, level, 3), 0),
                    (bridge_row_input_merkle_left(input, level, 4), 0),
                    (bridge_row_input_merkle_left(input, level, 5), 0),
                ],
            );
            push_continued_poseidon_init(
                &mut constraints,
                bridge_input_merkle_permutation(input, level, 1),
                bridge_input_merkle_permutation(input, level, 0),
                &[
                    bridge_row_input_merkle_right(input, level, 0),
                    bridge_row_input_merkle_right(input, level, 1),
                    bridge_row_input_merkle_right(input, level, 2),
                    bridge_row_input_merkle_right(input, level, 3),
                    bridge_row_input_merkle_right(input, level, 4),
                    bridge_row_input_merkle_right(input, level, 5),
                ],
            );
        }
        let prf_lane = packed_bridge_permutation_lane(bridge_prf_permutation());
        let prf_final_row = |limb: usize| {
            bridge_poseidon_row(
                bridge_prf_permutation(),
                SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                limb,
            )
        };
        push_fresh_poseidon_init(
            &mut constraints,
            bridge_input_nullifier_permutation(input),
            NULLIFIER_DOMAIN_TAG,
            &[
                (prf_final_row(0), prf_lane),
                (bridge_row_input_position(input), 0),
                (bridge_row_input_rho(input, 0), 0),
                (bridge_row_input_rho(input, 1), 0),
                (bridge_row_input_rho(input, 2), 0),
                (bridge_row_input_rho(input, 3), 0),
            ],
        );
    }

    for output in 0..MAX_OUTPUTS {
        push_fresh_poseidon_init(
            &mut constraints,
            bridge_output_commitment_permutation(output, 0),
            NOTE_DOMAIN_TAG,
            &[
                (bridge_row_output_value(output), 0),
                (bridge_row_output_asset(output), 0),
                (bridge_row_output_pk_recipient(output, 0), 0),
                (bridge_row_output_pk_recipient(output, 1), 0),
                (bridge_row_output_pk_recipient(output, 2), 0),
                (bridge_row_output_pk_recipient(output, 3), 0),
            ],
        );
        push_continued_poseidon_init(
            &mut constraints,
            bridge_output_commitment_permutation(output, 1),
            bridge_output_commitment_permutation(output, 0),
            &[
                bridge_row_output_rho(output, 0),
                bridge_row_output_rho(output, 1),
                bridge_row_output_rho(output, 2),
                bridge_row_output_rho(output, 3),
                bridge_row_output_r(output, 0),
                bridge_row_output_r(output, 1),
            ],
        );
        push_continued_poseidon_init(
            &mut constraints,
            bridge_output_commitment_permutation(output, 2),
            bridge_output_commitment_permutation(output, 1),
            &[
                bridge_row_output_r(output, 2),
                bridge_row_output_r(output, 3),
                bridge_row_output_pk_auth(output, 0),
                bridge_row_output_pk_auth(output, 1),
                bridge_row_output_pk_auth(output, 2),
                bridge_row_output_pk_auth(output, 3),
            ],
        );
    }

    for permutation in statement.poseidon_permutation_count as usize
        ..smallwood_bridge_poseidon_group_count(
            statement.poseidon_permutation_count as usize,
            SMALLWOOD_BRIDGE_PACKING_FACTOR,
        ) * SMALLWOOD_BRIDGE_PACKING_FACTOR
    {
        push_fresh_poseidon_init(&mut constraints, permutation, 0, &[]);
    }

    for input in 0..MAX_INPUTS {
        for level in 0..MERKLE_TREE_DEPTH {
            let source_permutation = if level == 0 {
                bridge_input_commitment_permutation(input, 2)
            } else {
                bridge_input_merkle_permutation(input, level - 1, 1)
            };
            let source_lane = packed_bridge_permutation_lane(source_permutation);
            for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
                let source_row = bridge_poseidon_row(
                    source_permutation,
                    SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                    limb,
                );
                push_bridge_cell_equals(
                    &mut constraints,
                    bridge_row_input_current_hash(input, level, limb),
                    0,
                    source_row,
                    source_lane,
                    neg_one,
                );
            }
        }
    }

    let prf_lane = packed_bridge_permutation_lane(bridge_prf_permutation());
    for input in 0..MAX_INPUTS {
        if public_flag(0 + input) {
            for limb in 0..SMALLWOOD_WORDS_PER_32_BYTES {
                push_bridge_cell_equals(
                    &mut constraints,
                    bridge_row_input_pk_auth(input, limb),
                    0,
                    bridge_poseidon_row(
                        bridge_prf_permutation(),
                        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                        limb + 1,
                    ),
                    prf_lane,
                    neg_one,
                );
            }
            let nullifier_lane =
                packed_bridge_permutation_lane(bridge_input_nullifier_permutation(input));
            for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
                push_bridge_cell_equals(
                    &mut constraints,
                    limb + 4 + input * SMALLWOOD_WORDS_PER_48_BYTES,
                    nullifier_lane,
                    bridge_poseidon_row(
                        bridge_input_nullifier_permutation(input),
                        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                        limb,
                    ),
                    nullifier_lane,
                    neg_one,
                );
                push_bridge_cell_equals(
                    &mut constraints,
                    43 + limb,
                    0,
                    bridge_poseidon_row(
                        bridge_input_merkle_permutation(input, MERKLE_TREE_DEPTH - 1, 1),
                        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                        limb,
                    ),
                    packed_bridge_permutation_lane(bridge_input_merkle_permutation(
                        input,
                        MERKLE_TREE_DEPTH - 1,
                        1,
                    )),
                    neg_one,
                );
            }
        }
    }

    for output in 0..MAX_OUTPUTS {
        if public_flag(2 + output) {
            let commitment_lane =
                packed_bridge_permutation_lane(bridge_output_commitment_permutation(output, 2));
            for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
                push_bridge_cell_equals(
                    &mut constraints,
                    16 + output * SMALLWOOD_WORDS_PER_48_BYTES + limb,
                    commitment_lane,
                    bridge_poseidon_row(
                        bridge_output_commitment_permutation(output, 2),
                        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                        limb,
                    ),
                    commitment_lane,
                    neg_one,
                );
            }
        }
    }

    constraints
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

fn semantic_secret_witness_rows(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputsP3,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let slot_assets = public_inputs
        .balance_slot_assets
        .iter()
        .map(|felt| felt.as_canonical_u64())
        .collect::<Vec<_>>();
    let (inputs, input_flags) = padded_inputs(&witness.inputs);
    let (outputs, output_flags) = padded_outputs(&witness.outputs);

    let mut values = Vec::with_capacity(SMALLWOOD_SECRET_WITNESS_ROWS);
    values.extend(bytes32_chunks_to_words(&witness.sk_spend));

    for (idx, input) in inputs.iter().enumerate() {
        push_note_fields(&mut values, &input.note);
        values.push(input.position);
        let selector_bits = if input_flags[idx] {
            selector_bits_for_asset(input.note.asset_id, &slot_assets)?
        } else {
            [0u64, 0u64]
        };
        values.extend(selector_bits);
        values.extend((0..MERKLE_TREE_DEPTH).map(|bit| ((input.position >> bit) & 1) as u64));
        if input.merkle_path.siblings.len() != MERKLE_TREE_DEPTH {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "native tx input merkle path has length {}, expected {}",
                input.merkle_path.siblings.len(),
                MERKLE_TREE_DEPTH
            )));
        }
        let mut current = input.note.commitment();
        for sibling in &input.merkle_path.siblings {
            values.extend(hash_felt_to_words(sibling));
        }
        for level in 0..MERKLE_TREE_DEPTH {
            let sibling = input.merkle_path.siblings[level];
            values.extend(hash_felt_to_words(&current));
            let (left, right) = if ((input.position >> level) & 1) == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            values.extend(hash_felt_to_words(&left));
            values.extend(hash_felt_to_words(&right));
            current = merkle_node(left, right);
        }
    }

    for (idx, output) in outputs.iter().enumerate() {
        push_note_fields(&mut values, &output.note);
        let selector_bits = if output_flags[idx] {
            selector_bits_for_asset(output.note.asset_id, &slot_assets)?
        } else {
            [0u64, 0u64]
        };
        values.extend(selector_bits);
    }

    let stablecoin_selector_bits = if witness.stablecoin.enabled {
        selector_bits_for_asset(witness.stablecoin.asset_id, &slot_assets)?
    } else {
        [0u64, 0u64]
    };
    values.extend(stablecoin_selector_bits);

    debug_assert_eq!(values.len(), SMALLWOOD_SECRET_WITNESS_ROWS);
    Ok(values)
}

fn native_relation_raw_witness_rows(
    witness: &TransactionWitness,
) -> Result<Vec<u64>, TransactionCircuitError> {
    witness.validate()?;
    validate_native_merkle_membership(witness)?;
    let mut values = Vec::with_capacity(3_991);
    let (value_balance_sign, value_balance_magnitude) =
        signed_magnitude_u64(witness.value_balance, "value_balance")?;
    let (stablecoin_issuance_sign, stablecoin_issuance_magnitude) =
        signed_magnitude_u64(witness.stablecoin.issuance_delta, "stablecoin_issuance")?;

    values.push(witness.inputs.len() as u64);
    values.push(witness.outputs.len() as u64);
    values.push(witness.ciphertext_hashes.len() as u64);
    push_bytes32_values(&mut values, &witness.sk_spend);
    push_bytes48_values(&mut values, &witness.merkle_root);
    values.push(witness.fee);
    values.push(u64::from(value_balance_sign));
    values.push(value_balance_magnitude);
    values.push(u64::from(witness.stablecoin.enabled));
    values.push(witness.stablecoin.asset_id);
    push_bytes48_values(&mut values, &witness.stablecoin.policy_hash);
    push_bytes48_values(&mut values, &witness.stablecoin.oracle_commitment);
    push_bytes48_values(&mut values, &witness.stablecoin.attestation_commitment);
    values.push(u64::from(stablecoin_issuance_sign));
    values.push(stablecoin_issuance_magnitude);
    values.push(u64::from(witness.stablecoin.policy_version));
    values.push(u64::from(witness.version.circuit));
    values.push(u64::from(witness.version.crypto));
    push_native_relation_inputs(&mut values, &witness.inputs)?;
    push_native_relation_outputs(&mut values, &witness.outputs)?;
    push_native_relation_ciphertext_hashes(&mut values, &witness.ciphertext_hashes)?;
    debug_assert_eq!(values.len(), 3_991);
    Ok(values)
}

fn smallwood_poseidon_permutation_count() -> usize {
    1 + (MAX_INPUTS * 3) + (MAX_INPUTS * MERKLE_TREE_DEPTH * 2) + MAX_INPUTS + (MAX_OUTPUTS * 3)
}

#[inline]
fn bridge_prf_permutation() -> usize {
    0
}

#[inline]
fn bridge_input_commitment_permutation(input: usize, chunk: usize) -> usize {
    1 + input * (3 + MERKLE_TREE_DEPTH * 2 + 1) + chunk
}

#[inline]
fn bridge_input_merkle_permutation(input: usize, level: usize, chunk: usize) -> usize {
    1 + input * (3 + MERKLE_TREE_DEPTH * 2 + 1) + 3 + level * 2 + chunk
}

#[inline]
fn bridge_input_nullifier_permutation(input: usize) -> usize {
    1 + input * (3 + MERKLE_TREE_DEPTH * 2 + 1) + (3 + MERKLE_TREE_DEPTH * 2 + 1) - 1
}

#[inline]
fn bridge_output_commitment_permutation(output: usize, chunk: usize) -> usize {
    1 + MAX_INPUTS * (3 + MERKLE_TREE_DEPTH * 2 + 1) + output * 3 + chunk
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

    Ok(traces)
}

fn packed_poseidon_subtrace_rows(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputs,
) -> Result<
    Vec<[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]>,
    TransactionCircuitError,
> {
    let mut traces = poseidon_subtrace_rows(witness)?;
    let native_delta = public_inputs
        .balance_slots
        .iter()
        .find(|slot| slot.asset_id == crate::constants::NATIVE_ASSET_ID)
        .map(|slot| slot.delta)
        .unwrap_or(0);
    let (_, balance_tag_traces) = trace_sponge_hash(
        BALANCE_DOMAIN_TAG,
        &balance_commitment_inputs(native_delta, &public_inputs.balance_slots)?,
    );
    traces.extend(balance_tag_traces);
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

fn pad_for_lppc_rows(mut flat: Vec<u64>, packing_factor: usize) -> Vec<u64> {
    let padded_len = flat.len().div_ceil(packing_factor) * packing_factor;
    flat.resize(padded_len, 0);
    flat
}

fn packed_bridge_witness_rows(
    public_values: &[u64],
    secret_rows: &[u64],
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]],
    packing_factor: usize,
) -> Vec<u64> {
    debug_assert_eq!(packing_factor, SMALLWOOD_BRIDGE_PACKING_FACTOR);
    let dummy_rows = dummy_poseidon_rows();
    let poseidon_group_count =
        smallwood_bridge_poseidon_group_count(poseidon_rows.len(), packing_factor);
    let mut rows = Vec::with_capacity(
        (public_values.len()
            + secret_rows.len()
            + SMALLWOOD_LANE_SELECTOR_ROWS
            + (poseidon_group_count
                * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION
                * POSEIDON2_WIDTH))
            * packing_factor,
    );

    for value in public_values {
        rows.extend(std::iter::repeat_n(*value, packing_factor));
    }
    for value in secret_rows {
        rows.extend(std::iter::repeat_n(*value, packing_factor));
    }
    for selector in 0..SMALLWOOD_LANE_SELECTOR_ROWS {
        for col in 0..packing_factor {
            rows.push(u64::from(col == selector));
        }
    }
    for group in 0..poseidon_group_count {
        for step in 0..SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION {
            for limb in 0..POSEIDON2_WIDTH {
                for lane in 0..packing_factor {
                    let value = poseidon_rows
                        .get(group * packing_factor + lane)
                        .map(|permutation| permutation[step][limb])
                        .unwrap_or(dummy_rows[step][limb]);
                    rows.push(value);
                }
            }
        }
    }

    rows
}

fn smallwood_bridge_poseidon_group_count(permutation_count: usize, packing_factor: usize) -> usize {
    permutation_count.div_ceil(packing_factor)
}

fn dummy_poseidon_rows() -> [[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]
{
    let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
    state[POSEIDON2_WIDTH - 1] = Felt::ONE;
    let mut rows = [[0u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION];
    rows[0] = snapshot_state(&state);
    for step in 0..POSEIDON2_STEPS {
        poseidon2_step(&mut state, step);
        rows[step + 1] = snapshot_state(&state);
    }
    rows
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

fn bytes32_chunks_to_words(bytes: &[u8; 32]) -> [u64; SMALLWOOD_WORDS_PER_32_BYTES] {
    let mut words = [0u64; SMALLWOOD_WORDS_PER_32_BYTES];
    for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        words[idx] = u64::from_be_bytes(buf) % transaction_core::constants::FIELD_MODULUS as u64;
    }
    words
}

fn push_bytes32_values(out: &mut Vec<u64>, bytes: &[u8; 32]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}

fn push_bytes48_values(out: &mut Vec<u64>, bytes: &[u8; 48]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}

fn hash_felt_to_words(hash: &HashFelt) -> [u64; SMALLWOOD_WORDS_PER_48_BYTES] {
    let mut words = [0u64; SMALLWOOD_WORDS_PER_48_BYTES];
    for (idx, felt) in hash.iter().enumerate() {
        words[idx] = felt.as_canonical_u64();
    }
    words
}

fn push_note_fields(out: &mut Vec<u64>, note: &crate::note::NoteData) {
    out.push(note.value);
    out.push(note.asset_id);
    out.extend(bytes32_chunks_to_words(&note.pk_recipient));
    out.extend(bytes32_chunks_to_words(&note.pk_auth));
    out.extend(bytes32_chunks_to_words(&note.rho));
    out.extend(bytes32_chunks_to_words(&note.r));
}

fn selector_bits_for_asset(
    asset_id: u64,
    slot_assets: &[u64],
) -> Result<[u64; 2], TransactionCircuitError> {
    let slot = slot_assets
        .iter()
        .position(|candidate| *candidate == asset_id)
        .ok_or(TransactionCircuitError::BalanceMismatch(asset_id))?;
    if slot >= BALANCE_SLOTS {
        return Err(TransactionCircuitError::BalanceMismatch(asset_id));
    }
    Ok([(slot & 1) as u64, ((slot >> 1) & 1) as u64])
}

fn push_native_relation_inputs(
    out: &mut Vec<u64>,
    inputs: &[InputNoteWitness],
) -> Result<(), TransactionCircuitError> {
    if inputs.len() > MAX_INPUTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "native tx input count {} exceeds {}",
            inputs.len(),
            MAX_INPUTS
        )));
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
            push_bytes32_values(out, &input.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_values(out, &input.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_values(out, &input.note.rho);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_values(out, &input.note.r);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        out.push(inputs.get(idx).map(|input| input.position).unwrap_or(0));
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_values(out, &input.rho_seed);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            if input.merkle_path.siblings.len() != MERKLE_TREE_DEPTH {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "native tx input {} merkle path has length {}, expected {}",
                    idx,
                    input.merkle_path.siblings.len(),
                    MERKLE_TREE_DEPTH
                )));
            }
            for sibling in &input.merkle_path.siblings {
                push_bytes48_values(out, &crate::hashing_pq::felts_to_bytes48(sibling));
            }
        } else {
            out.extend(std::iter::repeat_n(0u64, MERKLE_TREE_DEPTH * 48));
        }
    }
    Ok(())
}

fn push_native_relation_outputs(
    out: &mut Vec<u64>,
    outputs: &[OutputNoteWitness],
) -> Result<(), TransactionCircuitError> {
    if outputs.len() > MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "native tx output count {} exceeds {}",
            outputs.len(),
            MAX_OUTPUTS
        )));
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
            push_bytes32_values(out, &output.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_values(out, &output.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_values(out, &output.note.rho);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_values(out, &output.note.r);
        } else {
            out.extend(std::iter::repeat_n(0u64, 32));
        }
    }
    Ok(())
}

fn push_native_relation_ciphertext_hashes(
    out: &mut Vec<u64>,
    ciphertext_hashes: &[[u8; 48]],
) -> Result<(), TransactionCircuitError> {
    if ciphertext_hashes.len() > MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "native tx ciphertext hash count {} exceeds {}",
            ciphertext_hashes.len(),
            MAX_OUTPUTS
        )));
    }
    for idx in 0..MAX_OUTPUTS {
        push_bytes48_values(
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

fn balance_commitment_inputs(
    native_delta: i128,
    slots: &[crate::public_inputs::BalanceSlot],
) -> Result<Vec<Felt>, TransactionCircuitError> {
    let native_magnitude = native_delta.unsigned_abs();
    let native_magnitude = u64::try_from(native_magnitude).map_err(|_| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "native balance magnitude {native_magnitude} exceeds u64::MAX"
        ))
    })?;
    let mut inputs = Vec::with_capacity(1 + slots.len() * 2);
    inputs.push(Felt::from_u64(native_magnitude));
    for slot in slots {
        let magnitude = slot.delta.unsigned_abs();
        let magnitude = u64::try_from(magnitude).map_err(|_| {
            TransactionCircuitError::ConstraintViolationOwned(format!(
                "balance slot {} magnitude {} exceeds u64::MAX",
                slot.asset_id, magnitude
            ))
        })?;
        inputs.push(Felt::from_u64(slot.asset_id));
        inputs.push(Felt::from_u64(magnitude));
    }
    Ok(inputs)
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
        position: 0,
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
        assert_eq!(statement.raw_witness_len, 1_688);
        assert_eq!(statement.poseidon_permutation_count, 143);
        assert_eq!(statement.poseidon_state_row_count, 4_576);
        assert_eq!(statement.expanded_witness_len, 56_678);
        assert_eq!(statement.lppc_row_count, 56_678);
        assert_eq!(statement.lppc_packing_factor, 1);
        assert_eq!(statement.effective_constraint_degree, 8);
    }

    #[test]
    fn packed_smallwood_frontend_matches_expected_shape() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        let statement = &material.public_statement;
        assert_eq!(statement.public_value_count, 78);
        assert_eq!(statement.raw_witness_len, 3_991);
        assert_eq!(statement.poseidon_permutation_count, 145);
        assert_eq!(statement.poseidon_state_row_count, 4_640);
        assert_eq!(statement.expanded_witness_len, 59_749);
        assert_eq!(statement.lppc_row_count, 934);
        assert_eq!(statement.lppc_packing_factor, 64);
        assert_eq!(statement.effective_constraint_degree, 8);
        assert_eq!(material.linear_constraints.targets.len(), 78);
        assert_eq!(material.linear_constraints.term_offsets.len(), 79);
        assert_eq!(
            material.packed_expanded_witness.len(),
            statement.lppc_row_count as usize * statement.lppc_packing_factor as usize
        );
        assert_eq!(
            &material.packed_expanded_witness[..statement.public_value_count as usize],
            statement.public_values.as_slice()
        );
        assert!(
            material.packed_expanded_witness[statement.expanded_witness_len as usize..]
                .iter()
                .all(|value| *value == 0)
        );
    }

    #[test]
    fn packed_smallwood_bridge_material_matches_expected_shape() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let statement = &material.public_statement;
        assert_eq!(statement.public_value_count, 78);
        assert_eq!(statement.raw_witness_len, 1_688);
        assert_eq!(statement.poseidon_permutation_count, 143);
        assert_eq!(statement.poseidon_state_row_count, 4_576);
        assert_eq!(statement.lppc_packing_factor, 64);
        assert_eq!(statement.lppc_row_count, 2_982);
        assert_eq!(
            material.packed_witness_rows.len(),
            statement.lppc_row_count as usize * statement.lppc_packing_factor as usize
        );
        assert_eq!(material.linear_constraints.term_indices[0], 0);
        assert_eq!(material.linear_constraints.term_indices[1], 64);
        assert_eq!(
            &material.linear_constraints.targets[..statement.public_value_count as usize],
            statement.public_values.as_slice()
        );
        let selector_rows_start =
            statement.public_value_count as usize + statement.raw_witness_len as usize;
        let first_selector = &material.packed_witness_rows[selector_rows_start
            * SMALLWOOD_BRIDGE_PACKING_FACTOR
            ..(selector_rows_start + 1) * SMALLWOOD_BRIDGE_PACKING_FACTOR];
        assert_eq!(first_selector[0], 1);
        assert!(first_selector[1..].iter().all(|value| *value == 0));
    }

    #[test]
    fn packed_smallwood_bridge_witness_satisfies_constraints() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        test_candidate_witness(
            &material.packed_witness_rows,
            material.public_statement.lppc_row_count as usize,
            SMALLWOOD_BRIDGE_PACKING_FACTOR,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        )
        .unwrap();
    }

    #[test]
    fn packed_smallwood_bridge_groups_poseidon_rows_correctly() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let poseidon_rows = poseidon_subtrace_rows(&witness).unwrap();
        let group_rows_start = material.public_statement.public_value_count as usize
            + material.public_statement.raw_witness_len as usize
            + SMALLWOOD_LANE_SELECTOR_ROWS;
        for permutation in 0..poseidon_rows.len() {
            let group = permutation / SMALLWOOD_BRIDGE_PACKING_FACTOR;
            let lane = permutation % SMALLWOOD_BRIDGE_PACKING_FACTOR;
            for step in 0..SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION {
                for limb in 0..POSEIDON2_WIDTH {
                    let row = group_rows_start
                        + (group * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION + step)
                            * POSEIDON2_WIDTH
                        + limb;
                    assert_eq!(
                        material.packed_witness_rows[row * SMALLWOOD_BRIDGE_PACKING_FACTOR + lane],
                        poseidon_rows[permutation][step][limb]
                    );
                }
            }
        }
    }

    #[test]
    fn packed_smallwood_bridge_first_group_transition_matches_source_trace() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let poseidon_rows = poseidon_subtrace_rows(&witness).unwrap();
        let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
        for (limb, slot) in state.iter_mut().enumerate() {
            *slot = Felt::from_u64(poseidon_rows[0][29][limb]);
        }
        poseidon2_step(&mut state, 29);
        for limb in 0..POSEIDON2_WIDTH {
            assert_eq!(state[limb].as_canonical_u64(), poseidon_rows[0][30][limb]);
        }
    }

    #[test]
    fn packed_smallwood_bridge_first_group_transition_matches_packed_rows() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let group_rows_start = material.public_statement.public_value_count as usize
            + material.public_statement.raw_witness_len as usize
            + SMALLWOOD_LANE_SELECTOR_ROWS;
        let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
        for limb in 0..POSEIDON2_WIDTH {
            let row = group_rows_start + 29 * POSEIDON2_WIDTH + limb;
            state[limb] =
                Felt::from_u64(material.packed_witness_rows[row * SMALLWOOD_BRIDGE_PACKING_FACTOR]);
        }
        poseidon2_step(&mut state, 29);
        for limb in 0..POSEIDON2_WIDTH {
            let row = group_rows_start + 30 * POSEIDON2_WIDTH + limb;
            assert_eq!(
                state[limb].as_canonical_u64(),
                material.packed_witness_rows[row * SMALLWOOD_BRIDGE_PACKING_FACTOR]
            );
        }
    }

    #[test]
    fn packed_smallwood_bridge_first_merkle_left_rows_match_source() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let sibling = witness.inputs[0].merkle_path.siblings[0];
        let current = witness.inputs[0].note.commitment();
        for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
            let current_row =
                bridge_row_input_current_hash(0, 0, limb) * SMALLWOOD_BRIDGE_PACKING_FACTOR;
            let left_row =
                bridge_row_input_merkle_left(0, 0, limb) * SMALLWOOD_BRIDGE_PACKING_FACTOR;
            let right_row =
                bridge_row_input_merkle_right(0, 0, limb) * SMALLWOOD_BRIDGE_PACKING_FACTOR;
            assert_eq!(
                material.packed_witness_rows[current_row],
                current[limb].as_canonical_u64()
            );
            assert_eq!(
                material.packed_witness_rows[left_row],
                current[limb].as_canonical_u64()
            );
            assert_eq!(
                material.packed_witness_rows[right_row],
                sibling[limb].as_canonical_u64()
            );
        }
    }

    #[test]
    #[ignore = "experimental SmallWood packed candidate release proving is still too slow for the default test profile"]
    fn smallwood_candidate_roundtrip_verifies() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let proof = prove_smallwood_candidate(&witness).unwrap();
        eprintln!(
            "smallwood candidate proof bytes: {}",
            proof.stark_proof.len()
        );
        let report = verify_smallwood_candidate_transaction_proof(&proof).unwrap();
        assert!(report.verified);
    }

    #[test]
    #[ignore = "scalar SmallWood frontend is diagnostic only; the live candidate uses the packed 64-lane bridge"]
    fn smallwood_candidate_witness_satisfies_constraints() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_smallwood_frontend_material(&witness).unwrap();
        test_candidate_witness(
            &material.padded_expanded_witness,
            material.public_statement.lppc_row_count as usize,
            SMALLWOOD_LPPC_PACKING_FACTOR,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        )
        .unwrap();
    }

    #[test]
    #[ignore = "scalar SmallWood frontend is diagnostic only; the live candidate uses the packed 64-lane bridge"]
    fn smallwood_candidate_witness_rejects_mutation() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let mut material = build_smallwood_frontend_material(&witness).unwrap();
        material.padded_expanded_witness[0] ^= 1;
        let err = test_candidate_witness(
            &material.padded_expanded_witness,
            material.public_statement.lppc_row_count as usize,
            SMALLWOOD_LPPC_PACKING_FACTOR,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        )
        .expect_err("mutated smallwood witness must fail");
        assert!(err.to_string().contains("witness test failed"));
    }
}
