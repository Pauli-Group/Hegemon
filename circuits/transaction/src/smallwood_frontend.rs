use blake3::Hasher;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_versioning::{tx_proof_backend_for_version, TxProofBackend, VersionBinding};
use serde::{Deserialize, Serialize};
use transaction_core::{
    constants::{
        MERKLE_DOMAIN_TAG, NOTE_DOMAIN_TAG, NULLIFIER_DOMAIN_TAG, POSEIDON2_RATE, POSEIDON2_STEPS,
        POSEIDON2_WIDTH,
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
    smallwood_engine::{
        report_smallwood_proof_size_v1, SmallwoodArithmetization, SmallwoodProofSizeReportV1,
    },
    smallwood_native::{
        projected_candidate_proof_bytes as projected_smallwood_backend_proof_bytes,
        prove_candidate as prove_smallwood_backend, test_candidate_witness,
        verify_candidate as verify_smallwood_backend,
    },
    witness::TransactionWitness,
};

const SMALLWOOD_PUBLIC_STATEMENT_DOMAIN: &[u8] = b"hegemon.tx.smallwood-public-statement.v1";
const SMALLWOOD_BINDING_TRANSCRIPT_DOMAIN: &[u8] = b"hegemon.tx.smallwood-binding-transcript.v1";
const SMALLWOOD_XOF_DOMAIN: &[u8] = b"hegemon.smallwood.f64-xof.v1";

pub const SMALLWOOD_LPPC_PACKING_FACTOR: usize = 1;
pub const SMALLWOOD_PACKED_LPPC_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_BRIDGE_PACKING_FACTOR: usize = 64;
pub const SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE: u16 = 8;
pub const SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION: usize = POSEIDON2_STEPS + 1;
pub const SMALLWOOD_RHO: u32 = 2;
pub const SMALLWOOD_NB_OPENED_EVALS: u32 = 3;
pub const SMALLWOOD_BETA: u32 = 2;
pub const SMALLWOOD_OPENING_POW_BITS: u32 = 0;
pub const SMALLWOOD_DECS_NB_EVALS: u32 = 16384;
pub const SMALLWOOD_DECS_NB_OPENED_EVALS: u32 = 29;
pub const SMALLWOOD_DECS_ETA: u32 = 3;
pub const SMALLWOOD_DECS_POW_BITS: u32 = 0;
#[allow(dead_code)]
const SMALLWOOD_BASE_PUBLIC_VALUE_COUNT: usize = 78;
const SMALLWOOD_LANE_SELECTOR_ROWS: usize = 0;
const SMALLWOOD_WORDS_PER_48_BYTES: usize = 6;
const SMALLWOOD_PUBLIC_ROWS: usize = 0;
const SMALLWOOD_INPUT_SECRET_ROWS: usize = 1 + 1 + MERKLE_TREE_DEPTH;
const SMALLWOOD_TOTAL_INPUT_ROWS: usize = SMALLWOOD_INPUT_SECRET_ROWS + (MERKLE_TREE_DEPTH * 3);
const SMALLWOOD_INPUT_DIRECTION_OFFSET: usize = 2;
const PUB_INPUT_FLAG0: usize = 0;
const PUB_OUTPUT_FLAG0: usize = 2;
const PUB_NULLIFIERS: usize = 4;
const PUB_COMMITMENTS: usize = 16;
const PUB_CIPHERTEXT_HASHES: usize = 28;
const PUB_MERKLE_ROOT: usize = 43;
const PUB_STABLE_POLICY_VERSION: usize = 55;
const PUB_STABLE_POLICY_HASH: usize = 58;
const PUB_STABLE_ORACLE: usize = 64;
const PUB_STABLE_ATTESTATION: usize = 70;

fn smallwood_witness_self_check_enabled() -> bool {
    std::env::var("HEGEMON_SMALLWOOD_WITNESS_SELF_CHECK")
        .map(|value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(cfg!(debug_assertions))
}

#[inline]
fn bridge_input_base(input: usize) -> usize {
    SMALLWOOD_PUBLIC_ROWS + input * SMALLWOOD_TOTAL_INPUT_ROWS
}

#[inline]
fn bridge_output_base(layout: SmallwoodBridgeRowLayout, output: usize) -> usize {
    SMALLWOOD_PUBLIC_ROWS
        + MAX_INPUTS * SMALLWOOD_TOTAL_INPUT_ROWS
        + output * layout.output_secret_rows
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
fn bridge_row_input_direction(input: usize, bit: usize) -> usize {
    bridge_input_base(input) + SMALLWOOD_INPUT_DIRECTION_OFFSET + bit
}

#[inline]
fn bridge_row_input_current_agg(input: usize, level: usize) -> usize {
    bridge_input_base(input) + SMALLWOOD_INPUT_DIRECTION_OFFSET + MERKLE_TREE_DEPTH + level
}

#[inline]
fn bridge_row_input_left_agg(input: usize, level: usize) -> usize {
    bridge_input_base(input)
        + SMALLWOOD_INPUT_DIRECTION_OFFSET
        + MERKLE_TREE_DEPTH
        + MERKLE_TREE_DEPTH
        + level
}

#[inline]
fn bridge_row_input_right_agg(input: usize, level: usize) -> usize {
    bridge_input_base(input)
        + SMALLWOOD_INPUT_DIRECTION_OFFSET
        + MERKLE_TREE_DEPTH
        + MERKLE_TREE_DEPTH
        + MERKLE_TREE_DEPTH
        + level
}

#[inline]
fn bridge_stable_base(layout: SmallwoodBridgeRowLayout) -> usize {
    SMALLWOOD_PUBLIC_ROWS
        + MAX_INPUTS * SMALLWOOD_TOTAL_INPUT_ROWS
        + MAX_OUTPUTS * layout.output_secret_rows
}

#[inline]
fn bridge_poseidon_rows_start(layout: SmallwoodBridgeRowLayout) -> usize {
    SMALLWOOD_PUBLIC_ROWS + layout.secret_witness_rows() + SMALLWOOD_LANE_SELECTOR_ROWS
}

#[inline]
fn bridge_poseidon_row(
    layout: SmallwoodBridgeRowLayout,
    permutation: usize,
    step_row: usize,
    limb: usize,
) -> usize {
    let group = permutation / SMALLWOOD_BRIDGE_PACKING_FACTOR;
    bridge_poseidon_rows_start(layout)
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
    #[serde(default = "default_smallwood_candidate_arithmetization")]
    pub arithmetization: SmallwoodArithmetization,
    pub ark_proof: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmallwoodPublicBindingMode {
    RowAlignedSecretBindingsV1,
    CompactPublicBindingsV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SmallwoodPoseidonLayout {
    GroupedRowsV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodFrontendShape {
    pub lppc_packing_factor: usize,
    pub public_binding_mode: SmallwoodPublicBindingMode,
    pub poseidon_layout: SmallwoodPoseidonLayout,
}

impl SmallwoodFrontendShape {
    pub const fn bridge64_v1() -> Self {
        Self {
            lppc_packing_factor: SMALLWOOD_BRIDGE_PACKING_FACTOR,
            public_binding_mode: SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1,
            poseidon_layout: SmallwoodPoseidonLayout::GroupedRowsV1,
        }
    }

    pub const fn direct_packed64_compact_bindings_v1() -> Self {
        Self {
            lppc_packing_factor: SMALLWOOD_BRIDGE_PACKING_FACTOR,
            public_binding_mode: SmallwoodPublicBindingMode::CompactPublicBindingsV1,
            poseidon_layout: SmallwoodPoseidonLayout::GroupedRowsV1,
        }
    }
}

#[derive(Clone, Copy)]
struct SmallwoodBridgeRowLayout {
    output_secret_rows: usize,
    stable_binding_rows: usize,
}

impl SmallwoodBridgeRowLayout {
    const fn for_binding_mode(mode: SmallwoodPublicBindingMode) -> Self {
        match mode {
            SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1 => Self {
                output_secret_rows: 1 + 1 + SMALLWOOD_WORDS_PER_48_BYTES,
                stable_binding_rows: 1 + (SMALLWOOD_WORDS_PER_48_BYTES * 3),
            },
            SmallwoodPublicBindingMode::CompactPublicBindingsV1 => Self {
                output_secret_rows: 1 + 1,
                stable_binding_rows: 0,
            },
        }
    }

    const fn secret_witness_rows(self) -> usize {
        (MAX_INPUTS * SMALLWOOD_INPUT_SECRET_ROWS)
            + (MAX_OUTPUTS * self.output_secret_rows)
            + (MAX_INPUTS * (MERKLE_TREE_DEPTH * 3))
            + self.stable_binding_rows
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodCandidateProofSizeReport {
    pub total_bytes: usize,
    pub wrapper_bytes: usize,
    pub ark_proof_bytes: usize,
    pub transcript_bytes: usize,
    pub commitment_bytes: usize,
    pub opened_values_bytes: usize,
    pub opening_payload_bytes: usize,
    pub other_bytes: usize,
    pub arithmetization: SmallwoodArithmetization,
    pub inner: SmallwoodProofSizeReportV1,
}

fn default_smallwood_candidate_arithmetization() -> SmallwoodArithmetization {
    SmallwoodArithmetization::Bridge64V1
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

struct SmallwoodWitnessContext {
    witness: TransactionWitness,
    public_inputs: TransactionPublicInputs,
    serialized_public_inputs: SerializedStarkInputs,
    public_inputs_p3: TransactionPublicInputsP3,
    public_values: Vec<u64>,
    bridge_poseidon_rows:
        Vec<[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]>,
}

pub fn prove_smallwood_candidate(
    witness: &TransactionWitness,
) -> Result<TransactionProof, TransactionCircuitError> {
    prove_smallwood_candidate_with_arithmetization(witness, SmallwoodArithmetization::Bridge64V1)
}

pub fn prove_smallwood_candidate_with_arithmetization(
    witness: &TransactionWitness,
    arithmetization: SmallwoodArithmetization,
) -> Result<TransactionProof, TransactionCircuitError> {
    if tx_proof_backend_for_version(witness.version) != Some(TxProofBackend::SmallwoodCandidate) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "version {:?} is not bound to the smallwood_candidate backend",
            witness.version
        )));
    }
    let context = build_smallwood_witness_context(witness)?;
    match arithmetization {
        SmallwoodArithmetization::Bridge64V1 => {
            let material = build_packed_smallwood_bridge_material_from_context(&context, witness)?;
            if smallwood_witness_self_check_enabled() {
                test_candidate_witness(
                    SmallwoodArithmetization::Bridge64V1,
                    &material.public_statement.public_values,
                    &material.packed_witness_rows,
                    material.public_statement.lppc_row_count as usize,
                    SMALLWOOD_BRIDGE_PACKING_FACTOR,
                    SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
                    &material.linear_constraints.term_offsets,
                    &material.linear_constraints.term_indices,
                    &material.linear_constraints.term_coefficients,
                    &material.linear_constraints.targets,
                )?;
            }
            let ark_proof = prove_smallwood_backend(
                SmallwoodArithmetization::Bridge64V1,
                &material.public_statement.public_values,
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
            let proof_bytes = encode_smallwood_candidate_proof(arithmetization, ark_proof)?;
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
        SmallwoodArithmetization::DirectPacked64V1 => {
            let direct_material =
                build_packed_smallwood_frontend_material_from_context(&context, witness)?;
            if smallwood_witness_self_check_enabled() {
                test_candidate_witness(
                    SmallwoodArithmetization::DirectPacked64V1,
                    &direct_material.public_statement.public_values,
                    &direct_material.packed_expanded_witness,
                    direct_material.public_statement.lppc_row_count as usize,
                    direct_material.public_statement.lppc_packing_factor as usize,
                    SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
                    &direct_material.linear_constraints.term_offsets,
                    &direct_material.linear_constraints.term_indices,
                    &direct_material.linear_constraints.term_coefficients,
                    &direct_material.linear_constraints.targets,
                )?;
            }
            let ark_proof = prove_smallwood_backend(
                SmallwoodArithmetization::DirectPacked64V1,
                &direct_material.public_statement.public_values,
                &direct_material.packed_expanded_witness,
                direct_material.public_statement.lppc_row_count as usize,
                direct_material.public_statement.lppc_packing_factor as usize,
                SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
                &direct_material.linear_constraints.term_offsets,
                &direct_material.linear_constraints.term_indices,
                &direct_material.linear_constraints.term_coefficients,
                &direct_material.linear_constraints.targets,
                &direct_material.transcript_binding,
            )?;
            let proof_bytes = encode_smallwood_candidate_proof(arithmetization, ark_proof)?;
            Ok(TransactionProof {
                nullifiers: context.public_inputs.nullifiers.clone(),
                commitments: context.public_inputs.commitments.clone(),
                balance_slots: context.public_inputs.balance_slots.clone(),
                public_inputs: context.public_inputs.clone(),
                backend: TxProofBackend::SmallwoodCandidate,
                stark_proof: proof_bytes,
                stark_public_inputs: Some(context.serialized_public_inputs.clone()),
            })
        }
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1 => {
            let direct_material = build_packed_smallwood_frontend_material_from_context_with_shape(
                &context,
                witness,
                SmallwoodFrontendShape::direct_packed64_compact_bindings_v1(),
                SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
            )?;
            if smallwood_witness_self_check_enabled() {
                test_candidate_witness(
                    SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
                    &direct_material.public_statement.public_values,
                    &direct_material.packed_expanded_witness,
                    direct_material.public_statement.lppc_row_count as usize,
                    direct_material.public_statement.lppc_packing_factor as usize,
                    SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
                    &direct_material.linear_constraints.term_offsets,
                    &direct_material.linear_constraints.term_indices,
                    &direct_material.linear_constraints.term_coefficients,
                    &direct_material.linear_constraints.targets,
                )?;
            }
            let ark_proof = prove_smallwood_backend(
                SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
                &direct_material.public_statement.public_values,
                &direct_material.packed_expanded_witness,
                direct_material.public_statement.lppc_row_count as usize,
                direct_material.public_statement.lppc_packing_factor as usize,
                SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
                &direct_material.linear_constraints.term_offsets,
                &direct_material.linear_constraints.term_indices,
                &direct_material.linear_constraints.term_coefficients,
                &direct_material.linear_constraints.targets,
                &direct_material.transcript_binding,
            )?;
            let proof_bytes = encode_smallwood_candidate_proof(arithmetization, ark_proof)?;
            Ok(TransactionProof {
                nullifiers: context.public_inputs.nullifiers.clone(),
                commitments: context.public_inputs.commitments.clone(),
                balance_slots: context.public_inputs.balance_slots.clone(),
                public_inputs: context.public_inputs.clone(),
                backend: TxProofBackend::SmallwoodCandidate,
                stark_proof: proof_bytes,
                stark_public_inputs: Some(context.serialized_public_inputs.clone()),
            })
        }
    }
}

pub fn projected_smallwood_candidate_proof_bytes(
    witness: &TransactionWitness,
) -> Result<usize, TransactionCircuitError> {
    projected_smallwood_candidate_proof_bytes_for_arithmetization(
        witness,
        SmallwoodArithmetization::Bridge64V1,
    )
}

pub fn projected_smallwood_candidate_proof_bytes_for_arithmetization(
    witness: &TransactionWitness,
    arithmetization: SmallwoodArithmetization,
) -> Result<usize, TransactionCircuitError> {
    let context = build_smallwood_witness_context(witness)?;
    match arithmetization {
        SmallwoodArithmetization::Bridge64V1 => {
            let material = build_packed_smallwood_bridge_material_from_context(&context, witness)?;
            let ark_proof_bytes = projected_smallwood_backend_proof_bytes(
                SmallwoodArithmetization::Bridge64V1,
                &material.public_statement.public_values,
                material.public_statement.lppc_row_count as usize,
                material.public_statement.lppc_packing_factor as usize,
                material.public_statement.effective_constraint_degree,
                material.linear_constraints.targets.len(),
            )?;
            projected_wrapped_smallwood_candidate_proof_bytes(arithmetization, ark_proof_bytes)
        }
        SmallwoodArithmetization::DirectPacked64V1 => {
            let material =
                build_packed_smallwood_frontend_material_from_context(&context, witness)?;
            let ark_proof_bytes = projected_smallwood_backend_proof_bytes(
                SmallwoodArithmetization::DirectPacked64V1,
                &material.public_statement.public_values,
                material.public_statement.lppc_row_count as usize,
                material.public_statement.lppc_packing_factor as usize,
                material.public_statement.effective_constraint_degree,
                material.linear_constraints.targets.len(),
            )?;
            projected_wrapped_smallwood_candidate_proof_bytes(arithmetization, ark_proof_bytes)
        }
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1 => {
            let material = build_packed_smallwood_frontend_material_from_context_with_shape(
                &context,
                witness,
                SmallwoodFrontendShape::direct_packed64_compact_bindings_v1(),
                SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
            )?;
            let ark_proof_bytes = projected_smallwood_backend_proof_bytes(
                SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
                &material.public_statement.public_values,
                material.public_statement.lppc_row_count as usize,
                material.public_statement.lppc_packing_factor as usize,
                material.public_statement.effective_constraint_degree,
                material.linear_constraints.targets.len(),
            )?;
            projected_wrapped_smallwood_candidate_proof_bytes(arithmetization, ark_proof_bytes)
        }
    }
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
    let (public_statement, linear_constraints) = match candidate.arithmetization {
        SmallwoodArithmetization::Bridge64V1 => {
            let statement = build_packed_smallwood_bridge_public_statement(pub_inputs, version)?;
            let constraints = build_packed_bridge_linear_constraints(
                &statement,
                SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1,
            );
            (statement, constraints)
        }
        SmallwoodArithmetization::DirectPacked64V1 => {
            let statement = build_direct_packed_smallwood_public_statement(pub_inputs, version)?;
            let constraints = build_packed_bridge_linear_constraints(
                &statement,
                SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1,
            );
            (statement, constraints)
        }
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1 => {
            let statement = build_packed_smallwood_bridge_public_statement_with_shape(
                pub_inputs,
                version,
                SmallwoodFrontendShape::direct_packed64_compact_bindings_v1(),
            )?;
            let constraints = build_packed_bridge_linear_constraints(
                &statement,
                SmallwoodPublicBindingMode::CompactPublicBindingsV1,
            );
            (statement, constraints)
        }
    };
    verify_smallwood_backend(
        candidate.arithmetization,
        &public_statement.public_values,
        public_statement.lppc_row_count as usize,
        public_statement.lppc_packing_factor as usize,
        SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
        &linear_constraints.term_offsets,
        &linear_constraints.term_indices,
        &linear_constraints.term_coefficients,
        &linear_constraints.targets,
        &smallwood_transcript_binding(&public_statement, version, candidate.arithmetization)?,
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

pub fn smallwood_candidate_verifier_profile_material(
    version: VersionBinding,
    arithmetization: SmallwoodArithmetization,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(SMALLWOOD_PUBLIC_STATEMENT_DOMAIN);
    material.extend_from_slice(match arithmetization {
        SmallwoodArithmetization::Bridge64V1 => b"candidate-smallwood-bridge-pcs-ark".as_slice(),
        SmallwoodArithmetization::DirectPacked64V1 => {
            b"candidate-smallwood-direct-packed-payload".as_slice()
        },
        SmallwoodArithmetization::DirectPacked64CompactBindingsV1 => {
            b"candidate-smallwood-direct-packed-compact-bindings".as_slice()
        }
    });
    material.extend_from_slice(b"hegemon.blake3-field-xof.v1");
    material.extend_from_slice(&version.circuit.to_le_bytes());
    material.extend_from_slice(&version.crypto.to_le_bytes());
    material.extend_from_slice(&(arithmetization as u64).to_le_bytes());
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

pub fn build_packed_smallwood_frontend_material_with_shape_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodFrontendShape,
) -> Result<PackedSmallwoodFrontendMaterial, TransactionCircuitError> {
    let context = build_smallwood_witness_context(witness)?;
    build_packed_smallwood_frontend_material_from_context_with_shape(
        &context,
        witness,
        shape,
        direct_packed_arithmetization_for_shape(shape),
    )
}

pub fn build_packed_smallwood_bridge_material_from_witness(
    witness: &TransactionWitness,
) -> Result<PackedBridgeSmallwoodFrontendMaterial, TransactionCircuitError> {
    build_packed_smallwood_bridge_material(witness)
}

fn ensure_supported_smallwood_frontend_shape(
    shape: &SmallwoodFrontendShape,
) -> Result<(), TransactionCircuitError> {
    if shape.lppc_packing_factor != SMALLWOOD_BRIDGE_PACKING_FACTOR {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "unsupported SmallWood frontend packing factor {}, expected {} for the current engine",
            shape.lppc_packing_factor, SMALLWOOD_BRIDGE_PACKING_FACTOR
        )));
    }
    match shape.public_binding_mode {
        SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1
        | SmallwoodPublicBindingMode::CompactPublicBindingsV1 => {}
    }
    match shape.poseidon_layout {
        SmallwoodPoseidonLayout::GroupedRowsV1 => {}
    }
    Ok(())
}

fn direct_packed_arithmetization_for_shape(
    shape: SmallwoodFrontendShape,
) -> SmallwoodArithmetization {
    match shape.public_binding_mode {
        SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1 => {
            SmallwoodArithmetization::DirectPacked64V1
        }
        SmallwoodPublicBindingMode::CompactPublicBindingsV1 => {
            SmallwoodArithmetization::DirectPacked64CompactBindingsV1
        }
    }
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

pub fn report_smallwood_candidate_proof_size(
    proof_bytes: &[u8],
) -> Result<SmallwoodCandidateProofSizeReport, TransactionCircuitError> {
    let candidate = decode_smallwood_candidate_proof(proof_bytes)?;
    let inner = report_smallwood_proof_size_v1(&candidate.ark_proof)?;
    let wrapper_bytes = proof_bytes.len().checked_sub(candidate.ark_proof.len()).ok_or(
        TransactionCircuitError::ConstraintViolation(
            "smallwood candidate proof wrapper length underflow",
        ),
    )?;
    let accounted = wrapper_bytes
        + inner.transcript_bytes
        + inner.commitment_bytes
        + inner.opened_values_bytes
        + inner.opening_payload_bytes
        + inner.other_bytes;
    if accounted != proof_bytes.len() {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood candidate proof size report mismatch: accounted={accounted} total={}",
            proof_bytes.len()
        )));
    }
    Ok(SmallwoodCandidateProofSizeReport {
        total_bytes: proof_bytes.len(),
        wrapper_bytes,
        ark_proof_bytes: candidate.ark_proof.len(),
        transcript_bytes: inner.transcript_bytes,
        commitment_bytes: inner.commitment_bytes,
        opened_values_bytes: inner.opened_values_bytes,
        opening_payload_bytes: inner.opening_payload_bytes,
        other_bytes: inner.other_bytes,
        arithmetization: candidate.arithmetization,
        inner,
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
    let transcript_binding = smallwood_transcript_binding(
        &public_statement,
        witness.version,
        SmallwoodArithmetization::DirectPacked64V1,
    )?;
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
    let context = build_smallwood_witness_context(witness)?;
    build_packed_smallwood_frontend_material_from_context(&context, witness)
}

fn build_packed_smallwood_frontend_material_from_context(
    context: &SmallwoodWitnessContext,
    witness: &TransactionWitness,
) -> Result<PackedSmallwoodFrontendMaterial, TransactionCircuitError> {
    build_packed_smallwood_frontend_material_from_context_with_shape(
        context,
        witness,
        SmallwoodFrontendShape::bridge64_v1(),
        SmallwoodArithmetization::DirectPacked64V1,
    )
}

fn build_packed_smallwood_frontend_material_from_context_with_shape(
    context: &SmallwoodWitnessContext,
    witness: &TransactionWitness,
    shape: SmallwoodFrontendShape,
    arithmetization: SmallwoodArithmetization,
) -> Result<PackedSmallwoodFrontendMaterial, TransactionCircuitError> {
    ensure_supported_smallwood_frontend_shape(&shape)?;
    let layout = SmallwoodBridgeRowLayout::for_binding_mode(shape.public_binding_mode);
    let semantic_secret_rows = semantic_secret_witness_rows_with_mode(
        &context.witness,
        &context.public_inputs_p3,
        shape.public_binding_mode,
    )?;
    let packed_expanded_witness = packed_bridge_witness_rows(
        &semantic_secret_rows,
        &context.bridge_poseidon_rows,
        shape.lppc_packing_factor,
    );
    let row_count = packed_expanded_witness.len() / shape.lppc_packing_factor;
    let public_statement = SmallwoodPublicStatement {
        public_values: context.public_values.clone(),
        public_value_count: context.public_values.len() as u32,
        raw_witness_len: layout.secret_witness_rows() as u32,
        lppc_row_count: row_count as u32,
        poseidon_permutation_count: context.bridge_poseidon_rows.len() as u32,
        poseidon_state_row_count: (context.bridge_poseidon_rows.len()
            * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            as u32,
        expanded_witness_len: packed_expanded_witness.len() as u32,
        lppc_packing_factor: shape.lppc_packing_factor as u16,
        effective_constraint_degree: SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    };
    let linear_constraints =
        build_packed_bridge_linear_constraints(&public_statement, shape.public_binding_mode);
    let transcript_binding = smallwood_transcript_binding(
        &public_statement,
        witness.version,
        arithmetization,
    )?;
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
    let context = build_smallwood_witness_context(witness)?;
    build_packed_smallwood_bridge_material_from_context(&context, witness)
}

fn build_packed_smallwood_bridge_material_from_context(
    context: &SmallwoodWitnessContext,
    witness: &TransactionWitness,
) -> Result<PackedBridgeSmallwoodFrontendMaterial, TransactionCircuitError> {
    let shape = SmallwoodFrontendShape::bridge64_v1();
    ensure_supported_smallwood_frontend_shape(&shape)?;
    let layout = SmallwoodBridgeRowLayout::for_binding_mode(shape.public_binding_mode);
    let packed_witness_rows = packed_bridge_witness_rows(
        &semantic_secret_witness_rows_with_mode(
            &context.witness,
            &context.public_inputs_p3,
            shape.public_binding_mode,
        )?,
        &context.bridge_poseidon_rows,
        shape.lppc_packing_factor,
    );
    let row_count = packed_witness_rows.len() / shape.lppc_packing_factor;
    let public_statement = SmallwoodPublicStatement {
        public_values: context.public_values.clone(),
        public_value_count: context.public_values.len() as u32,
        raw_witness_len: layout.secret_witness_rows() as u32,
        lppc_row_count: row_count as u32,
        poseidon_permutation_count: context.bridge_poseidon_rows.len() as u32,
        poseidon_state_row_count: (context.bridge_poseidon_rows.len()
            * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            as u32,
        expanded_witness_len: packed_witness_rows.len() as u32,
        lppc_packing_factor: shape.lppc_packing_factor as u16,
        effective_constraint_degree: SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    };
    let linear_constraints =
        build_packed_bridge_linear_constraints(&public_statement, shape.public_binding_mode);
    let transcript_binding = smallwood_transcript_binding(
        &public_statement,
        witness.version,
        SmallwoodArithmetization::Bridge64V1,
    )?;
    Ok(PackedBridgeSmallwoodFrontendMaterial {
        public_inputs: context.public_inputs.clone(),
        serialized_public_inputs: context.serialized_public_inputs.clone(),
        public_statement,
        packed_witness_rows,
        linear_constraints,
        transcript_binding,
    })
}

fn build_smallwood_witness_context(
    witness: &TransactionWitness,
) -> Result<SmallwoodWitnessContext, TransactionCircuitError> {
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
    let bridge_poseidon_rows = poseidon_subtrace_rows(witness)?;
    Ok(SmallwoodWitnessContext {
        witness: witness.clone(),
        public_inputs,
        serialized_public_inputs,
        public_inputs_p3,
        public_values,
        bridge_poseidon_rows,
    })
}

#[allow(dead_code)]
fn build_packed_smallwood_bridge_public_statement(
    public_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    build_packed_smallwood_bridge_public_statement_with_shape(
        public_inputs,
        version,
        SmallwoodFrontendShape::bridge64_v1(),
    )
}

#[allow(dead_code)]
fn build_packed_smallwood_bridge_public_statement_with_shape(
    public_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
    shape: SmallwoodFrontendShape,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    ensure_supported_smallwood_frontend_shape(&shape)?;
    let layout = SmallwoodBridgeRowLayout::for_binding_mode(shape.public_binding_mode);
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
        shape.lppc_packing_factor,
    );
    let lppc_row_count = SMALLWOOD_PUBLIC_ROWS
        + layout.secret_witness_rows()
        + SMALLWOOD_LANE_SELECTOR_ROWS
        + (poseidon_group_count * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION * POSEIDON2_WIDTH);
    Ok(SmallwoodPublicStatement {
        public_values,
        public_value_count: SMALLWOOD_BASE_PUBLIC_VALUE_COUNT as u32,
        raw_witness_len: layout.secret_witness_rows() as u32,
        lppc_row_count: lppc_row_count as u32,
        poseidon_permutation_count: poseidon_permutation_count as u32,
        poseidon_state_row_count: (poseidon_permutation_count
            * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            as u32,
        expanded_witness_len: (lppc_row_count * shape.lppc_packing_factor) as u32,
        lppc_packing_factor: shape.lppc_packing_factor as u16,
        effective_constraint_degree: SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
    })
}

fn build_smallwood_public_statement(
    public_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    let layout = SmallwoodBridgeRowLayout::for_binding_mode(
        SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1,
    );
    let mut public_values = Vec::with_capacity(public_inputs.to_vec().len() + 2);
    public_values.extend(
        public_inputs
            .to_vec()
            .into_iter()
            .map(|felt| felt.as_canonical_u64()),
    );
    public_values.push(u64::from(version.circuit));
    public_values.push(u64::from(version.crypto));

    let raw_witness_len = layout.secret_witness_rows();
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

fn build_direct_packed_smallwood_public_statement(
    public_inputs: &TransactionPublicInputsP3,
    version: VersionBinding,
) -> Result<SmallwoodPublicStatement, TransactionCircuitError> {
    build_packed_smallwood_bridge_public_statement(public_inputs, version)
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

fn build_packed_bridge_linear_constraints(
    statement: &SmallwoodPublicStatement,
    public_binding_mode: SmallwoodPublicBindingMode,
) -> SmallwoodLinearConstraints {
    let layout = SmallwoodBridgeRowLayout::for_binding_mode(public_binding_mode);
    let packing_factor = statement.lppc_packing_factor as usize;
    let secret_row_start = SMALLWOOD_PUBLIC_ROWS;
    let secret_row_count = statement.raw_witness_len as usize;
    let neg_one = (transaction_core::constants::FIELD_MODULUS as u64).wrapping_sub(1);
    let neg_coeff = |value: u64| {
        if value == 0 {
            0
        } else {
            (transaction_core::constants::FIELD_MODULUS as u64).wrapping_sub(value)
        }
    };

    let mut constraints = SmallwoodLinearConstraints {
        term_offsets: vec![0],
        term_indices: Vec::new(),
        term_coefficients: Vec::new(),
        targets: Vec::new(),
    };

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

    let push_bridge_constant =
        |constraints: &mut SmallwoodLinearConstraints, row: usize, lane: usize, target: u64| {
            push_bridge_constraint(constraints, &[(row, lane, 1)], target);
        };
    let push_poseidon_fresh_frame =
        |constraints: &mut SmallwoodLinearConstraints, permutation: usize| {
            let lane = packed_bridge_permutation_lane(permutation);
            for limb in 6..(POSEIDON2_WIDTH - 1) {
                push_bridge_constant(
                    constraints,
                    bridge_poseidon_row(layout, permutation, 0, limb),
                    lane,
                    0,
                );
            }
            push_bridge_constant(
                constraints,
                bridge_poseidon_row(layout, permutation, 0, POSEIDON2_WIDTH - 1),
                lane,
                1,
            );
        };
    let push_poseidon_continuation = |constraints: &mut SmallwoodLinearConstraints,
                                      prev_permutation: usize,
                                      permutation: usize| {
        let prev_lane = packed_bridge_permutation_lane(prev_permutation);
        let lane = packed_bridge_permutation_lane(permutation);
        for limb in 6..POSEIDON2_WIDTH {
            push_bridge_constraint(
                constraints,
                &[
                    (bridge_poseidon_row(layout, permutation, 0, limb), lane, 1),
                    (
                        bridge_poseidon_row(
                            layout,
                            prev_permutation,
                            SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                            limb,
                        ),
                        prev_lane,
                        neg_one,
                    ),
                ],
                0,
            );
        }
    };
    let merkle_challenge_terms = |challenge: u64,
                                  permutation: usize,
                                  subtract_prev: Option<usize>|
     -> Vec<(usize, usize, u64)> {
        let lane = packed_bridge_permutation_lane(permutation);
        let mut power = 1u64;
        let mut terms = Vec::with_capacity(SMALLWOOD_WORDS_PER_48_BYTES * 2);
        for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
            terms.push((
                bridge_poseidon_row(layout, permutation, 0, limb),
                lane,
                neg_coeff(power),
            ));
            if let Some(prev) = subtract_prev {
                let prev_lane = packed_bridge_permutation_lane(prev);
                terms.push((
                    bridge_poseidon_row(
                        layout,
                        prev,
                        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                        limb,
                    ),
                    prev_lane,
                    power,
                ));
            }
            power = mul_mod_u64(power, challenge);
        }
        terms
    };

    let prf_permutation = bridge_prf_permutation();
    let prf_lane = packed_bridge_permutation_lane(prf_permutation);
    push_bridge_constant(
        &mut constraints,
        bridge_poseidon_row(layout, prf_permutation, 0, 4),
        prf_lane,
        0,
    );
    push_bridge_constant(
        &mut constraints,
        bridge_poseidon_row(layout, prf_permutation, 0, 5),
        prf_lane,
        0,
    );
    for limb in 6..(POSEIDON2_WIDTH - 1) {
        push_bridge_constant(
            &mut constraints,
            bridge_poseidon_row(layout, prf_permutation, 0, limb),
            prf_lane,
            0,
        );
    }
    push_bridge_constant(
        &mut constraints,
        bridge_poseidon_row(layout, prf_permutation, 0, POSEIDON2_WIDTH - 1),
        prf_lane,
        1,
    );

    for input in 0..MAX_INPUTS {
        if statement.public_values[PUB_INPUT_FLAG0 + input] == 0 {
            continue;
        }
        let commitment0 = bridge_input_commitment_permutation(input, 0);
        let commitment1 = bridge_input_commitment_permutation(input, 1);
        let commitment2 = bridge_input_commitment_permutation(input, 2);
        let lane0 = packed_bridge_permutation_lane(commitment0);

        push_bridge_constraint(
            &mut constraints,
            &[
                (bridge_poseidon_row(layout, commitment0, 0, 0), lane0, 1),
                (bridge_row_input_value(input), lane0, neg_one),
            ],
            NOTE_DOMAIN_TAG,
        );
        push_bridge_constraint(
            &mut constraints,
            &[
                (bridge_poseidon_row(layout, commitment0, 0, 1), lane0, 1),
                (bridge_row_input_asset(input), lane0, neg_one),
            ],
            0,
        );
        push_poseidon_fresh_frame(&mut constraints, commitment0);
        push_poseidon_continuation(&mut constraints, commitment0, commitment1);
        push_poseidon_continuation(&mut constraints, commitment1, commitment2);

        for level in 0..MERKLE_TREE_DEPTH {
            let challenge =
                smallwood_bridge_merkle_challenge(&statement.public_values, input, level);
            let merkle0 = bridge_input_merkle_permutation(input, level, 0);
            let merkle1 = bridge_input_merkle_permutation(input, level, 1);
            let lane = packed_bridge_permutation_lane(merkle0);
            let current_row = bridge_row_input_current_agg(input, level);
            let left_row = bridge_row_input_left_agg(input, level);
            let right_row = bridge_row_input_right_agg(input, level);

            let current_source = if level == 0 {
                commitment2
            } else {
                bridge_input_merkle_permutation(input, level - 1, 1)
            };
            let current_lane = packed_bridge_permutation_lane(current_source);
            let mut power = 1u64;
            let mut current_terms = vec![(current_row, lane, 1)];
            for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
                current_terms.push((
                    bridge_poseidon_row(
                        layout,
                        current_source,
                        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                        limb,
                    ),
                    current_lane,
                    neg_coeff(power),
                ));
                power = mul_mod_u64(power, challenge);
            }
            push_bridge_constraint(&mut constraints, &current_terms, 0);

            let mut left_terms = vec![(left_row, lane, 1)];
            left_terms.extend(merkle_challenge_terms(challenge, merkle0, None));
            push_bridge_constraint(&mut constraints, &left_terms, neg_coeff(MERKLE_DOMAIN_TAG));

            let mut right_terms = vec![(right_row, lane, 1)];
            right_terms.extend(merkle_challenge_terms(challenge, merkle1, Some(merkle0)));
            push_bridge_constraint(&mut constraints, &right_terms, 0);

            push_poseidon_fresh_frame(&mut constraints, merkle0);
            push_poseidon_continuation(&mut constraints, merkle0, merkle1);
        }

        let nullifier = bridge_input_nullifier_permutation(input);
        let nullifier_lane = packed_bridge_permutation_lane(nullifier);
        push_bridge_constraint(
            &mut constraints,
            &[
                (bridge_poseidon_row(layout, nullifier, 0, 0), nullifier_lane, 1),
                (
                    bridge_poseidon_row(
                        layout,
                        prf_permutation,
                        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                        0,
                    ),
                    prf_lane,
                    neg_one,
                ),
            ],
            NULLIFIER_DOMAIN_TAG,
        );
        let mut position_terms = Vec::with_capacity(MERKLE_TREE_DEPTH + 1);
        position_terms.push((bridge_poseidon_row(layout, nullifier, 0, 1), nullifier_lane, 1));
        for bit in 0..MERKLE_TREE_DEPTH {
            position_terms.push((
                bridge_row_input_direction(input, bit),
                nullifier_lane,
                neg_coeff(1u64 << bit),
            ));
        }
        push_bridge_constraint(&mut constraints, &position_terms, 0);
        for limb in 6..(POSEIDON2_WIDTH - 1) {
            push_bridge_constant(
                &mut constraints,
                bridge_poseidon_row(layout, nullifier, 0, limb),
                nullifier_lane,
                0,
            );
        }
        push_bridge_constant(
            &mut constraints,
            bridge_poseidon_row(layout, nullifier, 0, POSEIDON2_WIDTH - 1),
            nullifier_lane,
            1,
        );
        for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
            push_bridge_constant(
                &mut constraints,
                bridge_poseidon_row(
                    layout,
                    nullifier,
                    SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                    limb,
                ),
                nullifier_lane,
                statement.public_values
                    [PUB_NULLIFIERS + input * SMALLWOOD_WORDS_PER_48_BYTES + limb],
            );
        }
        let root_source = bridge_input_merkle_permutation(input, MERKLE_TREE_DEPTH - 1, 1);
        let root_lane = packed_bridge_permutation_lane(root_source);
        for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
            push_bridge_constant(
                &mut constraints,
                bridge_poseidon_row(
                    layout,
                    root_source,
                    SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                    limb,
                ),
                root_lane,
                statement.public_values[PUB_MERKLE_ROOT + limb],
            );
        }
    }

    for output in 0..MAX_OUTPUTS {
        if statement.public_values[PUB_OUTPUT_FLAG0 + output] == 0 {
            if matches!(
                public_binding_mode,
                SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1
            ) {
                for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
                    push_bridge_constant(
                        &mut constraints,
                        bridge_output_base(layout, output) + 2 + limb,
                        0,
                        statement.public_values
                            [PUB_CIPHERTEXT_HASHES + output * SMALLWOOD_WORDS_PER_48_BYTES + limb],
                    );
                }
            }
            continue;
        }
        let commitment0 = bridge_output_commitment_permutation(output, 0);
        let commitment1 = bridge_output_commitment_permutation(output, 1);
        let commitment2 = bridge_output_commitment_permutation(output, 2);
        let lane0 = packed_bridge_permutation_lane(commitment0);
        let output_base = bridge_output_base(layout, output);

        push_bridge_constraint(
            &mut constraints,
            &[
                (bridge_poseidon_row(layout, commitment0, 0, 0), lane0, 1),
                (output_base, lane0, neg_one),
            ],
            NOTE_DOMAIN_TAG,
        );
        push_bridge_constraint(
            &mut constraints,
            &[
                (bridge_poseidon_row(layout, commitment0, 0, 1), lane0, 1),
                (output_base + 1, lane0, neg_one),
            ],
            0,
        );
        push_poseidon_fresh_frame(&mut constraints, commitment0);
        push_poseidon_continuation(&mut constraints, commitment0, commitment1);
        push_poseidon_continuation(&mut constraints, commitment1, commitment2);
        let out_lane = packed_bridge_permutation_lane(commitment2);
        for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
            push_bridge_constant(
                &mut constraints,
                bridge_poseidon_row(
                    layout,
                    commitment2,
                    SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION - 1,
                    limb,
                ),
                out_lane,
                statement.public_values
                    [PUB_COMMITMENTS + output * SMALLWOOD_WORDS_PER_48_BYTES + limb],
            );
        }
        if matches!(
            public_binding_mode,
            SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1
        ) {
            for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
                push_bridge_constant(
                    &mut constraints,
                    output_base + 2 + limb,
                    lane0,
                    statement.public_values
                        [PUB_CIPHERTEXT_HASHES + output * SMALLWOOD_WORDS_PER_48_BYTES + limb],
                );
            }
        }
    }

    if matches!(
        public_binding_mode,
        SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1
    ) {
        let stable_base = bridge_stable_base(layout);
        push_bridge_constant(
            &mut constraints,
            stable_base,
            0,
            statement.public_values[PUB_STABLE_POLICY_VERSION],
        );
        for limb in 0..SMALLWOOD_WORDS_PER_48_BYTES {
            push_bridge_constant(
                &mut constraints,
                stable_base + 1 + limb,
                0,
                statement.public_values[PUB_STABLE_POLICY_HASH + limb],
            );
            push_bridge_constant(
                &mut constraints,
                stable_base + 1 + SMALLWOOD_WORDS_PER_48_BYTES + limb,
                0,
                statement.public_values[PUB_STABLE_ORACLE + limb],
            );
            push_bridge_constant(
                &mut constraints,
                stable_base + 1 + (SMALLWOOD_WORDS_PER_48_BYTES * 2) + limb,
                0,
                statement.public_values[PUB_STABLE_ATTESTATION + limb],
            );
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
    let canonicalize_balance_slot_asset_id =
        |asset_id: u64| Felt::from_u64(asset_id).as_canonical_u64();
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
            .map(|slot| canonicalize_balance_slot_asset_id(slot.asset_id))
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

fn smallwood_xof_words(input_words: &[u64], output_words: &mut [u64]) {
    let mut hasher = Hasher::new();
    hasher.update(SMALLWOOD_XOF_DOMAIN);
    hasher.update(&(input_words.len() as u64).to_le_bytes());
    for word in input_words {
        hasher.update(&word.to_le_bytes());
    }
    let mut reader = hasher.finalize_xof();
    for output in output_words {
        let mut buf = [0u8; 16];
        reader.fill(&mut buf);
        *output = (u128::from_le_bytes(buf) % transaction_core::constants::FIELD_MODULUS) as u64;
    }
}

fn smallwood_bridge_merkle_challenge(public_values: &[u64], input: usize, level: usize) -> u64 {
    let mut words = Vec::with_capacity(SMALLWOOD_BASE_PUBLIC_VALUE_COUNT + 4);
    words.push(0x736d_616c_6c77_6f6f);
    words.push(9);
    words.push(input as u64);
    words.push(level as u64);
    words.extend_from_slice(public_values);
    let mut out = [0u64; 1];
    smallwood_xof_words(&words, &mut out);
    if out[0] <= 1 {
        out[0] += 2;
    }
    out[0]
}

fn add_mod_u64(a: u64, b: u64) -> u64 {
    let modulus = transaction_core::constants::FIELD_MODULUS;
    let sum = a as u128 + b as u128;
    if sum >= modulus {
        (sum - modulus) as u64
    } else {
        sum as u64
    }
}

fn mul_mod_u64(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % transaction_core::constants::FIELD_MODULUS) as u64
}

fn aggregate_hash_words(words: &[u64; SMALLWOOD_WORDS_PER_48_BYTES], challenge: u64) -> u64 {
    let mut acc = 0u64;
    let mut power = 1u64;
    for &word in words {
        acc = add_mod_u64(acc, mul_mod_u64(power, word));
        power = mul_mod_u64(power, challenge);
    }
    acc
}

fn hash_felt_to_words(hash: &HashFelt) -> [u64; SMALLWOOD_WORDS_PER_48_BYTES] {
    let mut words = [0u64; SMALLWOOD_WORDS_PER_48_BYTES];
    for (idx, felt) in hash.iter().enumerate() {
        words[idx] = felt.as_canonical_u64();
    }
    words
}

fn aggregate_hash(hash: &HashFelt, challenge: u64) -> u64 {
    aggregate_hash_words(&hash_felt_to_words(hash), challenge)
}

fn semantic_secret_witness_rows(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputsP3,
) -> Result<Vec<u64>, TransactionCircuitError> {
    semantic_secret_witness_rows_with_mode(
        witness,
        public_inputs,
        SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1,
    )
}

fn semantic_secret_witness_rows_with_mode(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputsP3,
    public_binding_mode: SmallwoodPublicBindingMode,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let layout = SmallwoodBridgeRowLayout::for_binding_mode(public_binding_mode);
    let (inputs, _input_flags) = padded_inputs(&witness.inputs);
    let (outputs, _output_flags) = padded_outputs(&witness.outputs);
    let public_values: Vec<u64> = public_inputs
        .to_vec()
        .into_iter()
        .map(|felt| felt.as_canonical_u64())
        .chain([
            u64::from(witness.version.circuit),
            u64::from(witness.version.crypto),
        ])
        .collect();
    let mut values = Vec::with_capacity(layout.secret_witness_rows());

    for (idx, input) in inputs.iter().enumerate() {
        values.push(input.note.value);
        values.push(input.note.asset_id);
        values.extend((0..MERKLE_TREE_DEPTH).map(|bit| (input.position >> bit) & 1));
        if input.merkle_path.siblings.len() != MERKLE_TREE_DEPTH {
            return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                "native tx input merkle path has length {}, expected {}",
                input.merkle_path.siblings.len(),
                MERKLE_TREE_DEPTH
            )));
        }
        let mut current = input.note.commitment();
        let mut current_aggs = Vec::with_capacity(MERKLE_TREE_DEPTH);
        let mut left_aggs = Vec::with_capacity(MERKLE_TREE_DEPTH);
        let mut right_aggs = Vec::with_capacity(MERKLE_TREE_DEPTH);
        for level in 0..MERKLE_TREE_DEPTH {
            let sibling = input.merkle_path.siblings[level];
            let challenge = smallwood_bridge_merkle_challenge(&public_values, idx, level);
            current_aggs.push(aggregate_hash(&current, challenge));
            let (left, right) = if ((input.position >> level) & 1) == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            left_aggs.push(aggregate_hash(&left, challenge));
            right_aggs.push(aggregate_hash(&right, challenge));
            current = merkle_node(left, right);
        }
        values.extend(current_aggs);
        values.extend(left_aggs);
        values.extend(right_aggs);
    }

    for (idx, output) in outputs.iter().enumerate() {
        values.push(output.note.value);
        values.push(output.note.asset_id);
        if matches!(
            public_binding_mode,
            SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1
        ) {
            let ciphertext_hash = witness.ciphertext_hashes.get(idx).copied();
            let ciphertext_hash = ciphertext_hash.unwrap_or([0u8; 48]);
            let ciphertext_hash_words = bytes48_to_felts(&ciphertext_hash).ok_or(
                TransactionCircuitError::ConstraintViolation("invalid ciphertext hash encoding"),
            )?;
            values.extend(
                ciphertext_hash_words
                    .iter()
                    .map(|felt| felt.as_canonical_u64()),
            );
        }
    }

    if matches!(
        public_binding_mode,
        SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1
    ) {
        values.push(u64::from(witness.stablecoin.policy_version));
        for digest in [
            witness.stablecoin.policy_hash,
            witness.stablecoin.oracle_commitment,
            witness.stablecoin.attestation_commitment,
        ] {
            let words = bytes48_to_felts(&digest).ok_or(
                TransactionCircuitError::ConstraintViolation("invalid stablecoin binding encoding"),
            )?;
            values.extend(words.iter().map(|felt| felt.as_canonical_u64()));
        }
    }

    debug_assert_eq!(values.len(), layout.secret_witness_rows());
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

fn packed_bridge_witness_rows(
    secret_rows: &[u64],
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]],
    packing_factor: usize,
) -> Vec<u64> {
    debug_assert_eq!(packing_factor, SMALLWOOD_BRIDGE_PACKING_FACTOR);
    let dummy_rows = dummy_poseidon_rows();
    let poseidon_group_count =
        smallwood_bridge_poseidon_group_count(poseidon_rows.len(), packing_factor);
    let mut rows = Vec::with_capacity(
        (secret_rows.len()
            + (poseidon_group_count
                * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION
                * POSEIDON2_WIDTH))
            * packing_factor,
    );

    for value in secret_rows {
        rows.extend(std::iter::repeat_n(*value, packing_factor));
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
    arithmetization: SmallwoodArithmetization,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut bytes = Vec::from(SMALLWOOD_BINDING_TRANSCRIPT_DOMAIN);
    bytes.extend_from_slice(&smallwood_candidate_verifier_profile_material(
        version,
        arithmetization,
    ));
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

fn encode_smallwood_candidate_proof(
    arithmetization: SmallwoodArithmetization,
    ark_proof: Vec<u8>,
) -> Result<Vec<u8>, TransactionCircuitError> {
    bincode::serialize(&SmallwoodCandidateProof {
        arithmetization,
        ark_proof,
    })
    .map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize smallwood candidate proof: {err}"
        ))
    })
}

fn projected_wrapped_smallwood_candidate_proof_bytes(
    arithmetization: SmallwoodArithmetization,
    ark_proof_bytes: usize,
) -> Result<usize, TransactionCircuitError> {
    Ok(encode_smallwood_candidate_proof(arithmetization, vec![0u8; ark_proof_bytes])?.len())
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

    fn stablecoin_witness() -> TransactionWitness {
        let sk_spend = [8u8; 32];
        let pk_auth = spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 5,
            asset_id: crate::constants::NATIVE_ASSET_ID,
            pk_recipient: [1u8; 32],
            pk_auth,
            rho: [2u8; 32],
            r: [3u8; 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = [Felt::ZERO; 6];
        let mut siblings0 = vec![leaf1];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..MERKLE_TREE_DEPTH {
            let zero = [Felt::ZERO; 6];
            siblings0.push(zero);
            current = merkle_node(current, zero);
        }
        let output_stablecoin = OutputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: 4242,
                pk_recipient: [4u8; 32],
                pk_auth: [104u8; 32],
                rho: [5u8; 32],
                r: [6u8; 32],
            },
        };
        TransactionWitness {
            inputs: vec![InputNoteWitness {
                note: input_note_native,
                position: 0,
                rho_seed: [7u8; 32],
                merkle_path: MerklePath {
                    siblings: siblings0,
                },
            }],
            outputs: vec![output_stablecoin],
            ciphertext_hashes: vec![[9u8; 48]; 1],
            sk_spend,
            merkle_root: felts_to_bytes48(&current),
            fee: 5,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding {
                enabled: true,
                asset_id: 4242,
                policy_hash: [10u8; 48],
                oracle_commitment: [11u8; 48],
                attestation_commitment: [12u8; 48],
                issuance_delta: -5,
                policy_version: 1,
            },
            version: TransactionWitness::default_version_binding(),
        }
    }

    #[test]
    fn smallwood_frontend_matches_expected_shape() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let statement = build_smallwood_public_statement_from_witness(&witness).unwrap();
        assert_eq!(statement.public_value_count, 78);
        assert_eq!(statement.raw_witness_len, 295);
        assert_eq!(statement.poseidon_permutation_count, 143);
        assert_eq!(statement.poseidon_state_row_count, 4_576);
        assert_eq!(statement.expanded_witness_len, 55_285);
        assert_eq!(statement.lppc_row_count, 55_285);
        assert_eq!(statement.lppc_packing_factor, 1);
        assert_eq!(statement.effective_constraint_degree, 8);
    }

    #[test]
    fn packed_smallwood_frontend_matches_expected_shape() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        let bridge = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let statement = &material.public_statement;
        assert_eq!(statement.public_value_count, 78);
        assert_eq!(statement.raw_witness_len, 295);
        assert_eq!(statement.poseidon_permutation_count, 143);
        assert_eq!(statement.poseidon_state_row_count, 4_576);
        assert_eq!(statement.expanded_witness_len, 92_608);
        assert_eq!(statement.lppc_row_count, 1_447);
        assert_eq!(statement.lppc_packing_factor, 64);
        assert_eq!(statement.effective_constraint_degree, 8);
        assert_eq!(
            material.packed_expanded_witness.len(),
            statement.lppc_row_count as usize * statement.lppc_packing_factor as usize
        );
        assert_eq!(material.public_statement, bridge.public_statement);
        assert_eq!(material.packed_expanded_witness, bridge.packed_witness_rows);
        assert_eq!(
            material.linear_constraints.targets,
            bridge.linear_constraints.targets
        );
    }

    #[test]
    fn packed_smallwood_frontend_compact_bindings_matches_expected_shape() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_frontend_material_with_shape_from_witness(
            &witness,
            SmallwoodFrontendShape::direct_packed64_compact_bindings_v1(),
        )
        .unwrap();
        let statement = &material.public_statement;
        assert_eq!(statement.public_value_count, 78);
        assert_eq!(statement.raw_witness_len, 264);
        assert_eq!(statement.poseidon_permutation_count, 143);
        assert_eq!(statement.poseidon_state_row_count, 4_576);
        assert_eq!(statement.expanded_witness_len, 90_624);
        assert_eq!(statement.lppc_row_count, 1_416);
        assert_eq!(statement.lppc_packing_factor, 64);
        assert_eq!(statement.effective_constraint_degree, 8);
        assert_eq!(
            material.packed_expanded_witness.len(),
            statement.lppc_row_count as usize * statement.lppc_packing_factor as usize
        );
    }

    #[test]
    fn packed_smallwood_frontend_witness_satisfies_constraints() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        test_candidate_witness(
            SmallwoodArithmetization::DirectPacked64V1,
            &material.public_statement.public_values,
            &material.packed_expanded_witness,
            material.public_statement.lppc_row_count as usize,
            material.public_statement.lppc_packing_factor as usize,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        )
        .unwrap();
    }

    #[test]
    fn packed_smallwood_frontend_compact_bindings_witness_satisfies_constraints() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_frontend_material_with_shape_from_witness(
            &witness,
            SmallwoodFrontendShape::direct_packed64_compact_bindings_v1(),
        )
        .unwrap();
        test_candidate_witness(
            SmallwoodArithmetization::DirectPacked64CompactBindingsV1,
            &material.public_statement.public_values,
            &material.packed_expanded_witness,
            material.public_statement.lppc_row_count as usize,
            material.public_statement.lppc_packing_factor as usize,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        )
        .unwrap();
    }

    #[test]
    fn packed_smallwood_frontend_witness_rejects_mutation() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let mut material = build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        material.packed_expanded_witness[SMALLWOOD_BASE_PUBLIC_VALUE_COUNT + 17] ^= 1;
        let err = test_candidate_witness(
            SmallwoodArithmetization::DirectPacked64V1,
            &material.public_statement.public_values,
            &material.packed_expanded_witness,
            material.public_statement.lppc_row_count as usize,
            material.public_statement.lppc_packing_factor as usize,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &material.linear_constraints.term_offsets,
            &material.linear_constraints.term_indices,
            &material.linear_constraints.term_coefficients,
            &material.linear_constraints.targets,
        )
        .expect_err("mutated packed smallwood frontend must fail");
        assert!(err.to_string().contains("smallwood"));
    }

    #[test]
    fn packed_smallwood_frontend_rejects_public_binding_mutation() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        for public_index in [
            PUB_CIPHERTEXT_HASHES,
            PUB_NULLIFIERS,
            PUB_COMMITMENTS,
            PUB_MERKLE_ROOT,
            PUB_STABLE_POLICY_HASH,
        ] {
            let mut statement = material.public_statement.clone();
            statement.public_values[public_index] ^= 1;
            let linear_constraints = build_packed_bridge_linear_constraints(
                &statement,
                SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1,
            );
            let err = test_candidate_witness(
                SmallwoodArithmetization::DirectPacked64V1,
                &statement.public_values,
                &material.packed_expanded_witness,
                statement.lppc_row_count as usize,
                statement.lppc_packing_factor as usize,
                SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
                &linear_constraints.term_offsets,
                &linear_constraints.term_indices,
                &linear_constraints.term_coefficients,
                &linear_constraints.targets,
            )
            .expect_err("mutated public binding must fail");
            assert!(err.to_string().contains("smallwood"));
        }
    }

    #[test]
    fn packed_smallwood_frontend_rejects_enabled_stablecoin_binding_mutation() {
        let mut witness = stablecoin_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_frontend_material_from_witness(&witness).unwrap();
        for public_index in [
            PUB_STABLE_POLICY_VERSION,
            PUB_STABLE_POLICY_HASH,
            PUB_STABLE_ORACLE,
            PUB_STABLE_ATTESTATION,
        ] {
            let mut statement = material.public_statement.clone();
            statement.public_values[public_index] ^= 1;
            let linear_constraints = build_packed_bridge_linear_constraints(
                &statement,
                SmallwoodPublicBindingMode::RowAlignedSecretBindingsV1,
            );
            let err = test_candidate_witness(
                SmallwoodArithmetization::DirectPacked64V1,
                &statement.public_values,
                &material.packed_expanded_witness,
                statement.lppc_row_count as usize,
                statement.lppc_packing_factor as usize,
                SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
                &linear_constraints.term_offsets,
                &linear_constraints.term_indices,
                &linear_constraints.term_coefficients,
                &linear_constraints.targets,
            )
            .expect_err("mutated stablecoin-enabled public binding must fail");
            assert!(err.to_string().contains("smallwood"));
        }
    }

    #[test]
    fn packed_smallwood_frontend_and_bridge_share_witness_context() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let context = build_smallwood_witness_context(&witness).unwrap();
        let direct =
            build_packed_smallwood_frontend_material_from_context(&context, &witness).unwrap();
        let bridge =
            build_packed_smallwood_bridge_material_from_context(&context, &witness).unwrap();

        assert_eq!(
            direct.public_statement.public_values,
            bridge.public_statement.public_values
        );
        assert_eq!(direct.public_statement, bridge.public_statement);
        assert_eq!(bridge.public_inputs, context.public_inputs);
        assert_eq!(
            bridge.serialized_public_inputs,
            context.serialized_public_inputs
        );
        assert_eq!(direct.packed_expanded_witness, bridge.packed_witness_rows);
        assert_eq!(
            direct.linear_constraints.targets,
            bridge.linear_constraints.targets
        );

        test_candidate_witness(
            SmallwoodArithmetization::DirectPacked64V1,
            &direct.public_statement.public_values,
            &direct.packed_expanded_witness,
            direct.public_statement.lppc_row_count as usize,
            direct.public_statement.lppc_packing_factor as usize,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &direct.linear_constraints.term_offsets,
            &direct.linear_constraints.term_indices,
            &direct.linear_constraints.term_coefficients,
            &direct.linear_constraints.targets,
        )
        .unwrap();
        test_candidate_witness(
            SmallwoodArithmetization::Bridge64V1,
            &bridge.public_statement.public_values,
            &bridge.packed_witness_rows,
            bridge.public_statement.lppc_row_count as usize,
            SMALLWOOD_BRIDGE_PACKING_FACTOR,
            SMALLWOOD_EFFECTIVE_CONSTRAINT_DEGREE,
            &bridge.linear_constraints.term_offsets,
            &bridge.linear_constraints.term_indices,
            &bridge.linear_constraints.term_coefficients,
            &bridge.linear_constraints.targets,
        )
        .unwrap();
    }

    #[test]
    fn serialized_public_inputs_canonicalize_padding_asset_ids() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let context = build_smallwood_witness_context(&witness).unwrap();

        assert_eq!(
            context.serialized_public_inputs.balance_slot_asset_ids,
            vec![0, 1, 4_294_967_294, 4_294_967_294]
        );
    }

    #[test]
    fn packed_smallwood_bridge_material_matches_expected_shape() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        let statement = &material.public_statement;
        assert_eq!(statement.public_value_count, 78);
        assert_eq!(statement.raw_witness_len, 295);
        assert_eq!(statement.poseidon_permutation_count, 143);
        assert_eq!(statement.poseidon_state_row_count, 4_576);
        assert_eq!(statement.expanded_witness_len, 92_608);
        assert_eq!(statement.lppc_packing_factor, 64);
        assert_eq!(statement.lppc_row_count, 1_447);
        assert_eq!(
            material.packed_witness_rows.len(),
            statement.lppc_row_count as usize * statement.lppc_packing_factor as usize
        );
        assert_eq!(material.linear_constraints.term_indices[0], 1);
        assert_eq!(material.linear_constraints.term_indices[1], 0);
        assert_eq!(material.linear_constraints.targets[0], 0);
    }

    #[test]
    #[ignore = "bridge witness proving is diagnostic only; default boundary is pinned by projection/tag tests"]
    fn packed_smallwood_bridge_witness_satisfies_constraints() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_packed_smallwood_bridge_material_from_witness(&witness).unwrap();
        test_candidate_witness(
            SmallwoodArithmetization::Bridge64V1,
            &material.public_statement.public_values,
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
        let group_rows_start =
            SMALLWOOD_PUBLIC_ROWS + material.public_statement.raw_witness_len as usize;
        for (permutation, permutation_rows) in poseidon_rows.iter().enumerate() {
            let group = permutation / SMALLWOOD_BRIDGE_PACKING_FACTOR;
            let lane = permutation % SMALLWOOD_BRIDGE_PACKING_FACTOR;
            for (step, step_rows) in permutation_rows
                .iter()
                .enumerate()
                .take(SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            {
                for (limb, &value) in step_rows.iter().enumerate().take(POSEIDON2_WIDTH) {
                    let row = group_rows_start
                        + (group * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION + step)
                            * POSEIDON2_WIDTH
                        + limb;
                    assert_eq!(
                        material.packed_witness_rows[row * SMALLWOOD_BRIDGE_PACKING_FACTOR + lane],
                        value
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
        let group_rows_start =
            SMALLWOOD_PUBLIC_ROWS + material.public_statement.raw_witness_len as usize;
        let mut state = [Felt::ZERO; POSEIDON2_WIDTH];
        for (limb, slot) in state.iter_mut().enumerate().take(POSEIDON2_WIDTH) {
            let row = group_rows_start + 29 * POSEIDON2_WIDTH + limb;
            *slot =
                Felt::from_u64(material.packed_witness_rows[row * SMALLWOOD_BRIDGE_PACKING_FACTOR]);
        }
        poseidon2_step(&mut state, 29);
        for (limb, &value) in state.iter().enumerate().take(POSEIDON2_WIDTH) {
            let row = group_rows_start + 30 * POSEIDON2_WIDTH + limb;
            assert_eq!(
                value.as_canonical_u64(),
                material.packed_witness_rows[row * SMALLWOOD_BRIDGE_PACKING_FACTOR]
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
    fn smallwood_candidate_direct_packed_roundtrip_verifies() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let proof = prove_smallwood_candidate_with_arithmetization(
            &witness,
            SmallwoodArithmetization::DirectPacked64V1,
        )
        .unwrap();
        let report = verify_smallwood_candidate_transaction_proof(&proof).unwrap();
        assert!(report.verified);
        assert!(
            proof.stark_proof.len() < 524_288,
            "direct packed candidate proof bytes {} exceed native tx-leaf cap",
            proof.stark_proof.len()
        );
    }

    #[test]
    #[ignore = "scalar SmallWood frontend is diagnostic only; the live candidate uses the packed 64-lane bridge"]
    fn smallwood_candidate_witness_satisfies_constraints() {
        let mut witness = sample_witness();
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let material = build_smallwood_frontend_material(&witness).unwrap();
        test_candidate_witness(
            SmallwoodArithmetization::Bridge64V1,
            &material.public_statement.public_values,
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
            SmallwoodArithmetization::Bridge64V1,
            &material.public_statement.public_values,
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
