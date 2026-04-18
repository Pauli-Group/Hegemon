use p3_field::{PrimeCharacteristicRing, PrimeField64};
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};
use synthetic_crypto::hashes::blake3_384;
use transaction_core::{
    constants::{POSEIDON2_STEPS, POSEIDON2_WIDTH},
    poseidon2::poseidon2_step,
};

use crate::{
    constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS},
    error::TransactionCircuitError,
    hashing_pq::{bytes48_to_felts, felts_to_bytes48, merkle_node, Commitment, Felt, HashFelt},
    note::{InputNoteWitness, OutputNoteWitness},
    proof::{
        transaction_public_inputs_digest_from_serialized, transaction_public_inputs_p3_from_parts,
        transaction_statement_hash_from_public_inputs, SerializedStarkInputs,
    },
    public_inputs::TransactionPublicInputs,
    smallwood_engine::{
        projected_smallwood_structural_proof_bytes_v1,
        prove_smallwood_structural_identity_witness_v1,
        prove_smallwood_structural_identity_witness_with_auxiliary_v1,
        report_smallwood_structural_no_grinding_soundness_v1,
        verify_smallwood_structural_identity_witness_v1,
        verify_smallwood_structural_identity_witness_with_auxiliary_v1,
        SmallwoodNoGrindingProfileV1, SmallwoodNoGrindingSoundnessReportV1,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    },
    smallwood_frontend::{
        smallwood_bridge_poseidon_subtrace_rows_v1, smallwood_compact_bridge_helper_rows_v1,
        smallwood_compact_bridge_helper_rows_with_shape_v1, SmallwoodFrontendShape,
    },
    smallwood_semantics::packed_constraint_count_for_packing_factor,
    witness::TransactionWitness,
};

const SMALLWOOD_SEMANTIC_LPPC_PROFILE_DOMAIN: &[u8] = b"hegemon.tx.smallwood-semantic-lppc.v1";
const NATIVE_TX_VALIDITY_DIGEST_WORDS: usize = 6;
const NATIVE_TX_VALIDITY_PUBLIC_VALUE_COUNT: usize = NATIVE_TX_VALIDITY_DIGEST_WORDS * 3;
const NATIVE_TX_VALIDITY_RAW_WITNESS_ELEMENTS: usize = 3991;
const NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS: usize = 4096;
const SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE: usize = 8;
const SMALLWOOD_SEMANTIC_BRIDGE_MERKLE_AGGREGATE_ROWS: usize =
    MAX_INPUTS * crate::note::MERKLE_TREE_DEPTH * 3;
const SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION: usize = POSEIDON2_STEPS + 1;
const SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_PERMUTATIONS: usize =
    1 + MAX_INPUTS * (3 + crate::note::MERKLE_TREE_DEPTH * 2 + 1) + MAX_OUTPUTS * 3;
const SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_ROWS_PER_PERMUTATION: usize = 32;
const SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_WORDS: usize =
    SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_PERMUTATIONS
        * SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_ROWS_PER_PERMUTATION
        * transaction_core::constants::POSEIDON2_WIDTH;
const CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES: usize = 87_086;
const SMALLWOOD_SEMANTIC_HELPER_FLOOR_PROFILE_DOMAIN: &[u8] =
    b"hegemon.tx.smallwood-semantic-helper-floor.v1";
const SMALLWOOD_SEMANTIC_HELPER_AUX_FLOOR_PROFILE_DOMAIN: &[u8] =
    b"hegemon.tx.smallwood-semantic-helper-aux-floor.v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticLppcShape {
    pub witness_rows: usize,
    pub packing_factor: usize,
}

impl SmallwoodSemanticLppcShape {
    pub const fn packed_1024x4_v1() -> Self {
        Self {
            witness_rows: 1024,
            packing_factor: 4,
        }
    }

    pub const fn packed_512x8_v1() -> Self {
        Self {
            witness_rows: 512,
            packing_factor: 8,
        }
    }

    pub const fn packed_256x16_v1() -> Self {
        Self {
            witness_rows: 256,
            packing_factor: 16,
        }
    }

    pub const fn recommended_v1() -> Self {
        Self::packed_512x8_v1()
    }

    pub const fn padded_witness_elements(self) -> usize {
        self.witness_rows * self.packing_factor
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticLppcStatement {
    pub public_values: Vec<u64>,
    pub public_value_count: u32,
    pub raw_witness_elements: u32,
    pub padded_witness_elements: u32,
    pub witness_rows: u32,
    pub packing_factor: u16,
    pub constraint_degree: u16,
    pub constraint_count_estimate: u32,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub statement_hash: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub public_inputs_digest: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub verifier_profile_digest: Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodSemanticLppcFrontendMaterial {
    pub statement: SmallwoodSemanticLppcStatement,
    pub packed_witness_matrix: Vec<u64>,
    pub transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SmallwoodSemanticLppcProfileAnalysisReport {
    pub shape: SmallwoodSemanticLppcShape,
    pub statement: SmallwoodSemanticLppcStatement,
    pub projected_total_bytes: usize,
    pub soundness: SmallwoodNoGrindingSoundnessReportV1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticLppcIdentitySpikeReport {
    pub shape: SmallwoodSemanticLppcShape,
    pub statement: SmallwoodSemanticLppcStatement,
    pub exact_total_bytes: usize,
    pub projected_total_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticLppcAuxiliaryPoseidonSpikeReport {
    pub shape: SmallwoodSemanticLppcShape,
    pub statement: SmallwoodSemanticLppcStatement,
    pub auxiliary_poseidon_words: usize,
    pub projected_total_bytes: usize,
    pub shipped_smallwood_candidate_bytes: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticBridgeLowerBoundShape {
    pub packing_factor: usize,
}

impl SmallwoodSemanticBridgeLowerBoundShape {
    pub const fn packed_32x_v1() -> Self {
        Self { packing_factor: 32 }
    }

    pub const fn packed_64x_v1() -> Self {
        Self { packing_factor: 64 }
    }

    pub const fn packed_128x_v1() -> Self {
        Self {
            packing_factor: 128,
        }
    }

    pub const fn recommended_v1() -> Self {
        Self::packed_64x_v1()
    }

    pub const fn semantic_witness_rows(self) -> usize {
        NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS / self.packing_factor
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticBridgeLowerBoundStatement {
    pub public_values: Vec<u64>,
    pub public_value_count: u32,
    pub semantic_witness_rows: u32,
    pub merkle_aggregate_rows: u32,
    pub total_secret_rows: u32,
    pub poseidon_permutation_count: u32,
    pub poseidon_state_row_count: u32,
    pub witness_rows: u32,
    pub packing_factor: u16,
    pub constraint_degree: u16,
    pub constraint_count_estimate: u32,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub statement_hash: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub public_inputs_digest: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub verifier_profile_digest: Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodSemanticBridgeLowerBoundMaterial {
    pub statement: SmallwoodSemanticBridgeLowerBoundStatement,
    pub packed_witness_matrix: Vec<u64>,
    pub transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticBridgeLowerBoundReport {
    pub shape: SmallwoodSemanticBridgeLowerBoundShape,
    pub statement: SmallwoodSemanticBridgeLowerBoundStatement,
    pub exact_total_bytes: usize,
    pub projected_total_bytes: usize,
    pub shipped_smallwood_candidate_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticBridgeLowerBoundAnalysisReport {
    pub shape: SmallwoodSemanticBridgeLowerBoundShape,
    pub statement: SmallwoodSemanticBridgeLowerBoundStatement,
    pub projected_total_bytes: usize,
    pub shipped_smallwood_candidate_bytes: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperFloorShape {
    pub packing_factor: usize,
}

impl SmallwoodSemanticHelperFloorShape {
    pub const fn packed_32x_v1() -> Self {
        Self { packing_factor: 32 }
    }

    pub const fn packed_64x_v1() -> Self {
        Self { packing_factor: 64 }
    }

    pub const fn packed_128x_v1() -> Self {
        Self {
            packing_factor: 128,
        }
    }

    pub const fn recommended_v1() -> Self {
        Self::packed_64x_v1()
    }

    pub const fn semantic_witness_rows(self) -> usize {
        NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS / self.packing_factor
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperFloorStatement {
    pub public_values: Vec<u64>,
    pub public_value_count: u32,
    pub nonlinear_helper_rows: u32,
    pub semantic_witness_rows: u32,
    pub total_secret_rows: u32,
    pub poseidon_permutation_count: u32,
    pub poseidon_state_row_count: u32,
    pub witness_rows: u32,
    pub packing_factor: u16,
    pub constraint_degree: u16,
    pub constraint_count_estimate: u32,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub statement_hash: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub public_inputs_digest: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub verifier_profile_digest: Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodSemanticHelperFloorMaterial {
    pub statement: SmallwoodSemanticHelperFloorStatement,
    pub packed_witness_matrix: Vec<u64>,
    pub transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperFloorAnalysisReport {
    pub shape: SmallwoodSemanticHelperFloorShape,
    pub statement: SmallwoodSemanticHelperFloorStatement,
    pub projected_total_bytes: usize,
    pub shipped_smallwood_candidate_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperFloorReport {
    pub shape: SmallwoodSemanticHelperFloorShape,
    pub statement: SmallwoodSemanticHelperFloorStatement,
    pub exact_total_bytes: usize,
    pub projected_total_bytes: usize,
    pub shipped_smallwood_candidate_bytes: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperAuxShape {
    pub packing_factor: usize,
    pub inline_merkle_aggregates: bool,
    pub skip_initial_mds_poseidon: bool,
    pub derive_lane_local_helpers_from_semantic: bool,
}

impl SmallwoodSemanticHelperAuxShape {
    pub const fn packed_32x_v1() -> Self {
        Self {
            packing_factor: 32,
            inline_merkle_aggregates: false,
            skip_initial_mds_poseidon: false,
            derive_lane_local_helpers_from_semantic: false,
        }
    }

    pub const fn packed_64x_v1() -> Self {
        Self {
            packing_factor: 64,
            inline_merkle_aggregates: false,
            skip_initial_mds_poseidon: false,
            derive_lane_local_helpers_from_semantic: false,
        }
    }

    pub const fn packed_128x_v1() -> Self {
        Self {
            packing_factor: 128,
            inline_merkle_aggregates: false,
            skip_initial_mds_poseidon: false,
            derive_lane_local_helpers_from_semantic: false,
        }
    }

    pub const fn packed_32x_inline_merkle_skip_initial_mds_v1() -> Self {
        Self {
            packing_factor: 32,
            inline_merkle_aggregates: true,
            skip_initial_mds_poseidon: true,
            derive_lane_local_helpers_from_semantic: false,
        }
    }

    pub const fn packed_64x_inline_merkle_skip_initial_mds_v1() -> Self {
        Self {
            packing_factor: 64,
            inline_merkle_aggregates: true,
            skip_initial_mds_poseidon: true,
            derive_lane_local_helpers_from_semantic: false,
        }
    }

    pub const fn packed_128x_inline_merkle_skip_initial_mds_v1() -> Self {
        Self {
            packing_factor: 128,
            inline_merkle_aggregates: true,
            skip_initial_mds_poseidon: true,
            derive_lane_local_helpers_from_semantic: false,
        }
    }

    pub const fn packed_32x_semantic_adapter_floor_v1() -> Self {
        Self {
            packing_factor: 32,
            inline_merkle_aggregates: true,
            skip_initial_mds_poseidon: true,
            derive_lane_local_helpers_from_semantic: true,
        }
    }

    pub const fn packed_64x_semantic_adapter_floor_v1() -> Self {
        Self {
            packing_factor: 64,
            inline_merkle_aggregates: true,
            skip_initial_mds_poseidon: true,
            derive_lane_local_helpers_from_semantic: true,
        }
    }

    pub const fn packed_128x_semantic_adapter_floor_v1() -> Self {
        Self {
            packing_factor: 128,
            inline_merkle_aggregates: true,
            skip_initial_mds_poseidon: true,
            derive_lane_local_helpers_from_semantic: true,
        }
    }

    pub const fn recommended_v1() -> Self {
        Self::packed_64x_semantic_adapter_floor_v1()
    }

    pub const fn semantic_witness_rows(self) -> usize {
        NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS / self.packing_factor
    }

    pub const fn frontend_shape(self) -> SmallwoodFrontendShape {
        if self.inline_merkle_aggregates && self.skip_initial_mds_poseidon {
            SmallwoodFrontendShape::direct_packed_compact_bindings_inline_merkle_skip_initial_mds_v1(
                self.packing_factor,
            )
        } else {
            SmallwoodFrontendShape::direct_packed_compact_bindings_v1(self.packing_factor)
        }
    }

    pub const fn poseidon_rows_per_permutation(self) -> usize {
        if self.skip_initial_mds_poseidon {
            POSEIDON2_STEPS
        } else {
            SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperAuxStatement {
    pub public_values: Vec<u64>,
    pub public_value_count: u32,
    pub auxiliary_helper_words: u32,
    pub semantic_witness_rows: u32,
    pub total_secret_rows: u32,
    pub poseidon_permutation_count: u32,
    pub poseidon_state_row_count: u32,
    pub witness_rows: u32,
    pub packing_factor: u16,
    pub constraint_degree: u16,
    pub constraint_count_estimate: u32,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub statement_hash: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub public_inputs_digest: Commitment,
    #[serde(with = "crate::public_inputs::serde_bytes48")]
    pub verifier_profile_digest: Commitment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmallwoodSemanticHelperAuxMaterial {
    pub statement: SmallwoodSemanticHelperAuxStatement,
    pub packed_witness_matrix: Vec<u64>,
    pub auxiliary_helper_words: Vec<u64>,
    pub transcript_binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperAuxAnalysisReport {
    pub shape: SmallwoodSemanticHelperAuxShape,
    pub statement: SmallwoodSemanticHelperAuxStatement,
    pub projected_total_bytes: usize,
    pub shipped_smallwood_candidate_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmallwoodSemanticHelperAuxReport {
    pub shape: SmallwoodSemanticHelperAuxShape,
    pub statement: SmallwoodSemanticHelperAuxStatement,
    pub exact_total_bytes: usize,
    pub projected_total_bytes: usize,
    pub shipped_smallwood_candidate_bytes: usize,
}

pub fn smallwood_semantic_lppc_verifier_profile_material(
    version: VersionBinding,
    shape: SmallwoodSemanticLppcShape,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(SMALLWOOD_SEMANTIC_LPPC_PROFILE_DOMAIN);
    material.extend_from_slice(b"candidate-smallwood-semantic-lppc-structural");
    material.extend_from_slice(&version.circuit.to_le_bytes());
    material.extend_from_slice(&version.crypto.to_le_bytes());
    material.extend_from_slice(&(shape.witness_rows as u64).to_le_bytes());
    material.extend_from_slice(&(shape.packing_factor as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u64).to_le_bytes());
    material.extend_from_slice(&(ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.rho as u64).to_le_bytes());
    material.extend_from_slice(
        &(ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.nb_opened_evals as u64).to_le_bytes(),
    );
    material
        .extend_from_slice(&(ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.beta as u64).to_le_bytes());
    material.extend_from_slice(
        &(ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_evals as u64).to_le_bytes(),
    );
    material.extend_from_slice(
        &(ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_nb_opened_evals as u64).to_le_bytes(),
    );
    material.extend_from_slice(
        &(ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1.decs_eta as u64).to_le_bytes(),
    );
    material
}

pub fn build_smallwood_semantic_lppc_material_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticLppcShape,
) -> Result<SmallwoodSemanticLppcFrontendMaterial, TransactionCircuitError> {
    ensure_smallwood_semantic_lppc_shape(shape)?;
    witness.validate()?;
    let public_inputs = witness.public_inputs()?;
    let stark_public_inputs = serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    let statement_hash = transaction_statement_hash_from_public_inputs(&public_inputs);
    let public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(&stark_public_inputs)?;
    let verifier_profile_digest = blake3_384(&smallwood_semantic_lppc_verifier_profile_material(
        witness.version,
        shape,
    ));
    let public_values = semantic_lppc_public_values(
        statement_hash,
        public_inputs_digest,
        verifier_profile_digest,
    )?;
    let mut packed_witness_matrix = native_tx_validity_witness_elements(witness)?;
    packed_witness_matrix.resize(shape.padded_witness_elements(), 0);
    let statement = SmallwoodSemanticLppcStatement {
        public_value_count: public_values.len() as u32,
        public_values,
        raw_witness_elements: NATIVE_TX_VALIDITY_RAW_WITNESS_ELEMENTS as u32,
        padded_witness_elements: shape.padded_witness_elements() as u32,
        witness_rows: shape.witness_rows as u32,
        packing_factor: shape.packing_factor as u16,
        constraint_degree: SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u16,
        constraint_count_estimate: packed_constraint_count_for_packing_factor(shape.packing_factor)
            as u32,
        statement_hash,
        public_inputs_digest,
        verifier_profile_digest,
    };
    let transcript_binding = semantic_lppc_transcript_binding(&statement)?;
    Ok(SmallwoodSemanticLppcFrontendMaterial {
        statement,
        packed_witness_matrix,
        transcript_binding,
    })
}

pub fn analyze_smallwood_semantic_lppc_shape_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticLppcShape,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodSemanticLppcProfileAnalysisReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_lppc_material_from_witness(witness, shape)?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        0,
        profile,
    )?;
    let soundness = report_smallwood_structural_no_grinding_soundness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        material.statement.public_value_count as usize,
        0,
        profile,
    )?;
    Ok(SmallwoodSemanticLppcProfileAnalysisReport {
        shape,
        statement: material.statement,
        projected_total_bytes,
        soundness,
    })
}

pub fn analyze_smallwood_semantic_lppc_frontier_from_witness(
    witness: &TransactionWitness,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<Vec<SmallwoodSemanticLppcProfileAnalysisReport>, TransactionCircuitError> {
    [
        SmallwoodSemanticLppcShape::packed_1024x4_v1(),
        SmallwoodSemanticLppcShape::packed_512x8_v1(),
        SmallwoodSemanticLppcShape::packed_256x16_v1(),
    ]
    .into_iter()
    .map(|shape| analyze_smallwood_semantic_lppc_shape_from_witness(witness, shape, profile))
    .collect()
}

pub fn prove_smallwood_semantic_lppc_identity_spike_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticLppcShape,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let material = build_smallwood_semantic_lppc_material_from_witness(witness, shape)?;
    prove_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
    )
}

pub fn verify_smallwood_semantic_lppc_identity_spike_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticLppcShape,
    proof_bytes: &[u8],
) -> Result<(), TransactionCircuitError> {
    let material = build_smallwood_semantic_lppc_material_from_witness(witness, shape)?;
    verify_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
        proof_bytes,
    )
}

pub fn exact_smallwood_semantic_lppc_identity_spike_report_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticLppcShape,
) -> Result<SmallwoodSemanticLppcIdentitySpikeReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_lppc_material_from_witness(witness, shape)?;
    let proof = prove_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
    )?;
    verify_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
        &proof,
    )?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        0,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )?;
    Ok(SmallwoodSemanticLppcIdentitySpikeReport {
        shape,
        statement: material.statement,
        exact_total_bytes: proof.len(),
        projected_total_bytes,
    })
}

pub fn analyze_smallwood_semantic_lppc_auxiliary_poseidon_spike_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticLppcShape,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodSemanticLppcAuxiliaryPoseidonSpikeReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_lppc_material_from_witness(witness, shape)?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_WORDS,
        profile,
    )?;
    Ok(SmallwoodSemanticLppcAuxiliaryPoseidonSpikeReport {
        shape,
        statement: material.statement,
        auxiliary_poseidon_words: SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_WORDS,
        projected_total_bytes,
        shipped_smallwood_candidate_bytes: CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES,
    })
}

pub fn exact_smallwood_semantic_lppc_auxiliary_poseidon_spike_report_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticLppcShape,
) -> Result<SmallwoodSemanticLppcIdentitySpikeReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_lppc_material_from_witness(witness, shape)?;
    let auxiliary_words = vec![0u64; SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_WORDS];
    let proof = prove_smallwood_structural_identity_witness_with_auxiliary_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &auxiliary_words,
        &material.transcript_binding,
    )?;
    verify_smallwood_structural_identity_witness_with_auxiliary_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &auxiliary_words,
        &material.transcript_binding,
        &proof,
    )?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        SMALLWOOD_SEMANTIC_LPPC_AUXILIARY_POSEIDON_WORDS,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )?;
    Ok(SmallwoodSemanticLppcIdentitySpikeReport {
        shape,
        statement: material.statement,
        exact_total_bytes: proof.len(),
        projected_total_bytes,
    })
}

pub fn build_smallwood_semantic_bridge_lower_bound_material_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticBridgeLowerBoundShape,
) -> Result<SmallwoodSemanticBridgeLowerBoundMaterial, TransactionCircuitError> {
    ensure_smallwood_semantic_bridge_lower_bound_shape(shape)?;
    witness.validate()?;
    let public_inputs = witness.public_inputs()?;
    let stark_public_inputs = serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    let public_inputs_p3 =
        transaction_public_inputs_p3_from_parts(&public_inputs, &stark_public_inputs)?;
    let public_values: Vec<u64> = public_inputs_p3
        .to_vec()
        .into_iter()
        .map(|felt| felt.as_canonical_u64())
        .chain([
            u64::from(witness.version.circuit),
            u64::from(witness.version.crypto),
        ])
        .collect();
    let statement_hash = transaction_statement_hash_from_public_inputs(&public_inputs);
    let public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(&stark_public_inputs)?;
    let verifier_profile_digest = blake3_384(
        &smallwood_semantic_bridge_lower_bound_profile_material(witness.version, shape),
    );
    let poseidon_rows = smallwood_bridge_poseidon_subtrace_rows_v1(witness)?;
    let mut packed_witness_matrix =
        build_semantic_bridge_lower_bound_secret_rows(witness, &public_values, shape)?;
    let total_secret_rows = packed_witness_matrix.len() / shape.packing_factor;
    let poseidon_group_rows =
        smallwood_bridge_poseidon_group_rows(poseidon_rows.len(), shape.packing_factor);
    let statement = SmallwoodSemanticBridgeLowerBoundStatement {
        public_value_count: public_values.len() as u32,
        public_values,
        semantic_witness_rows: shape.semantic_witness_rows() as u32,
        merkle_aggregate_rows: SMALLWOOD_SEMANTIC_BRIDGE_MERKLE_AGGREGATE_ROWS as u32,
        total_secret_rows: total_secret_rows as u32,
        poseidon_permutation_count: poseidon_rows.len() as u32,
        poseidon_state_row_count: (poseidon_rows.len()
            * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            as u32,
        witness_rows: (total_secret_rows + poseidon_group_rows) as u32,
        packing_factor: shape.packing_factor as u16,
        constraint_degree: SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u16,
        constraint_count_estimate: packed_constraint_count_for_packing_factor(shape.packing_factor)
            as u32,
        statement_hash,
        public_inputs_digest,
        verifier_profile_digest,
    };
    append_grouped_poseidon_rows(
        &mut packed_witness_matrix,
        &poseidon_rows,
        shape.packing_factor,
    );
    let transcript_binding = semantic_bridge_lower_bound_transcript_binding(&statement)?;
    Ok(SmallwoodSemanticBridgeLowerBoundMaterial {
        statement,
        packed_witness_matrix,
        transcript_binding,
    })
}

pub fn analyze_smallwood_semantic_bridge_lower_bound_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticBridgeLowerBoundShape,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodSemanticBridgeLowerBoundAnalysisReport, TransactionCircuitError> {
    let material =
        build_smallwood_semantic_bridge_lower_bound_material_from_witness(witness, shape)?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        0,
        profile,
    )?;
    Ok(SmallwoodSemanticBridgeLowerBoundAnalysisReport {
        shape,
        statement: material.statement,
        projected_total_bytes,
        shipped_smallwood_candidate_bytes: CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES,
    })
}

pub fn analyze_smallwood_semantic_bridge_lower_bound_frontier_from_witness(
    witness: &TransactionWitness,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<Vec<SmallwoodSemanticBridgeLowerBoundAnalysisReport>, TransactionCircuitError> {
    [
        SmallwoodSemanticBridgeLowerBoundShape::packed_32x_v1(),
        SmallwoodSemanticBridgeLowerBoundShape::packed_64x_v1(),
        SmallwoodSemanticBridgeLowerBoundShape::packed_128x_v1(),
    ]
    .into_iter()
    .map(|shape| {
        analyze_smallwood_semantic_bridge_lower_bound_from_witness(witness, shape, profile)
    })
    .collect()
}

pub fn exact_smallwood_semantic_bridge_lower_bound_report_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticBridgeLowerBoundShape,
) -> Result<SmallwoodSemanticBridgeLowerBoundReport, TransactionCircuitError> {
    let material =
        build_smallwood_semantic_bridge_lower_bound_material_from_witness(witness, shape)?;
    let proof = prove_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
    )?;
    verify_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
        &proof,
    )?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        0,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )?;
    Ok(SmallwoodSemanticBridgeLowerBoundReport {
        shape,
        statement: material.statement,
        exact_total_bytes: proof.len(),
        projected_total_bytes,
        shipped_smallwood_candidate_bytes: CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES,
    })
}

pub fn build_smallwood_semantic_helper_floor_material_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticHelperFloorShape,
) -> Result<SmallwoodSemanticHelperFloorMaterial, TransactionCircuitError> {
    ensure_smallwood_semantic_helper_floor_shape(shape)?;
    witness.validate()?;
    let public_inputs = witness.public_inputs()?;
    let stark_public_inputs = serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    let public_inputs_p3 =
        transaction_public_inputs_p3_from_parts(&public_inputs, &stark_public_inputs)?;
    let public_values: Vec<u64> = public_inputs_p3
        .to_vec()
        .into_iter()
        .map(|felt| felt.as_canonical_u64())
        .chain([
            u64::from(witness.version.circuit),
            u64::from(witness.version.crypto),
        ])
        .collect();
    let statement_hash = transaction_statement_hash_from_public_inputs(&public_inputs);
    let public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(&stark_public_inputs)?;
    let verifier_profile_digest = blake3_384(&smallwood_semantic_helper_floor_profile_material(
        witness.version,
        shape,
    ));
    let helper_rows = smallwood_compact_bridge_helper_rows_v1(witness, shape.packing_factor)?;
    let mut semantic_rows = native_tx_validity_witness_elements(witness)?;
    semantic_rows.resize(NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS, 0);
    let poseidon_rows = smallwood_bridge_poseidon_subtrace_rows_v1(witness)?;
    let poseidon_group_rows =
        smallwood_bridge_poseidon_group_rows(poseidon_rows.len(), shape.packing_factor);

    let mut packed_witness_matrix = Vec::with_capacity(
        (helper_rows.len() + shape.semantic_witness_rows() + poseidon_group_rows)
            * shape.packing_factor,
    );
    for value in helper_rows.iter().copied() {
        packed_witness_matrix.extend(std::iter::repeat_n(value, shape.packing_factor));
    }
    for chunk in semantic_rows.chunks_exact(shape.packing_factor) {
        packed_witness_matrix.extend_from_slice(chunk);
    }
    append_grouped_poseidon_rows(
        &mut packed_witness_matrix,
        &poseidon_rows,
        shape.packing_factor,
    );

    let total_secret_rows = helper_rows.len() + shape.semantic_witness_rows();
    let statement = SmallwoodSemanticHelperFloorStatement {
        public_value_count: public_values.len() as u32,
        public_values,
        nonlinear_helper_rows: helper_rows.len() as u32,
        semantic_witness_rows: shape.semantic_witness_rows() as u32,
        total_secret_rows: total_secret_rows as u32,
        poseidon_permutation_count: poseidon_rows.len() as u32,
        poseidon_state_row_count: (poseidon_rows.len()
            * SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION)
            as u32,
        witness_rows: (total_secret_rows + poseidon_group_rows) as u32,
        packing_factor: shape.packing_factor as u16,
        constraint_degree: SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u16,
        constraint_count_estimate: packed_constraint_count_for_packing_factor(shape.packing_factor)
            as u32,
        statement_hash,
        public_inputs_digest,
        verifier_profile_digest,
    };
    let transcript_binding = semantic_helper_floor_transcript_binding(&statement)?;
    Ok(SmallwoodSemanticHelperFloorMaterial {
        statement,
        packed_witness_matrix,
        transcript_binding,
    })
}

pub fn analyze_smallwood_semantic_helper_floor_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticHelperFloorShape,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodSemanticHelperFloorAnalysisReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_helper_floor_material_from_witness(witness, shape)?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        0,
        profile,
    )?;
    Ok(SmallwoodSemanticHelperFloorAnalysisReport {
        shape,
        statement: material.statement,
        projected_total_bytes,
        shipped_smallwood_candidate_bytes: CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES,
    })
}

pub fn analyze_smallwood_semantic_helper_floor_frontier_from_witness(
    witness: &TransactionWitness,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<Vec<SmallwoodSemanticHelperFloorAnalysisReport>, TransactionCircuitError> {
    [
        SmallwoodSemanticHelperFloorShape::packed_32x_v1(),
        SmallwoodSemanticHelperFloorShape::packed_64x_v1(),
        SmallwoodSemanticHelperFloorShape::packed_128x_v1(),
    ]
    .into_iter()
    .map(|shape| analyze_smallwood_semantic_helper_floor_from_witness(witness, shape, profile))
    .collect()
}

pub fn exact_smallwood_semantic_helper_floor_report_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticHelperFloorShape,
) -> Result<SmallwoodSemanticHelperFloorReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_helper_floor_material_from_witness(witness, shape)?;
    let proof = prove_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
    )?;
    verify_smallwood_structural_identity_witness_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.transcript_binding,
        &proof,
    )?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        0,
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )?;
    Ok(SmallwoodSemanticHelperFloorReport {
        shape,
        statement: material.statement,
        exact_total_bytes: proof.len(),
        projected_total_bytes,
        shipped_smallwood_candidate_bytes: CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES,
    })
}

pub fn build_smallwood_semantic_helper_aux_material_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticHelperAuxShape,
) -> Result<SmallwoodSemanticHelperAuxMaterial, TransactionCircuitError> {
    ensure_smallwood_semantic_helper_aux_shape(shape)?;
    witness.validate()?;
    let public_inputs = witness.public_inputs()?;
    let stark_public_inputs = serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    let public_inputs_p3 =
        transaction_public_inputs_p3_from_parts(&public_inputs, &stark_public_inputs)?;
    let public_values: Vec<u64> = public_inputs_p3
        .to_vec()
        .into_iter()
        .map(|felt| felt.as_canonical_u64())
        .chain([
            u64::from(witness.version.circuit),
            u64::from(witness.version.crypto),
        ])
        .collect();
    let statement_hash = transaction_statement_hash_from_public_inputs(&public_inputs);
    let public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(&stark_public_inputs)?;
    let verifier_profile_digest = blake3_384(&smallwood_semantic_helper_aux_profile_material(
        witness.version,
        shape,
    ));
    let auxiliary_helper_words = if shape.derive_lane_local_helpers_from_semantic {
        Vec::new()
    } else {
        smallwood_compact_bridge_helper_rows_with_shape_v1(witness, shape.frontend_shape())?
    };
    let mut semantic_rows = native_tx_validity_witness_elements(witness)?;
    semantic_rows.resize(NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS, 0);
    let poseidon_rows = smallwood_bridge_poseidon_subtrace_rows_v1(witness)?;
    let poseidon_group_rows =
        smallwood_bridge_poseidon_group_rows_for_shape(shape, poseidon_rows.len());

    let mut packed_witness_matrix = Vec::with_capacity(
        (shape.semantic_witness_rows() + poseidon_group_rows) * shape.packing_factor,
    );
    for chunk in semantic_rows.chunks_exact(shape.packing_factor) {
        packed_witness_matrix.extend_from_slice(chunk);
    }
    append_grouped_poseidon_rows_for_shape(&mut packed_witness_matrix, &poseidon_rows, shape);

    let total_secret_rows = shape.semantic_witness_rows();
    let statement = SmallwoodSemanticHelperAuxStatement {
        public_value_count: public_values.len() as u32,
        public_values,
        auxiliary_helper_words: auxiliary_helper_words.len() as u32,
        semantic_witness_rows: shape.semantic_witness_rows() as u32,
        total_secret_rows: total_secret_rows as u32,
        poseidon_permutation_count: poseidon_rows.len() as u32,
        poseidon_state_row_count: (poseidon_rows.len() * shape.poseidon_rows_per_permutation())
            as u32,
        witness_rows: (total_secret_rows + poseidon_group_rows) as u32,
        packing_factor: shape.packing_factor as u16,
        constraint_degree: SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u16,
        constraint_count_estimate: packed_constraint_count_for_packing_factor(shape.packing_factor)
            as u32,
        statement_hash,
        public_inputs_digest,
        verifier_profile_digest,
    };
    let transcript_binding = semantic_helper_aux_transcript_binding(&statement)?;
    Ok(SmallwoodSemanticHelperAuxMaterial {
        statement,
        packed_witness_matrix,
        auxiliary_helper_words,
        transcript_binding,
    })
}

pub fn analyze_smallwood_semantic_helper_aux_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticHelperAuxShape,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<SmallwoodSemanticHelperAuxAnalysisReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_helper_aux_material_from_witness(witness, shape)?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        material.auxiliary_helper_words.len(),
        profile,
    )?;
    Ok(SmallwoodSemanticHelperAuxAnalysisReport {
        shape,
        statement: material.statement,
        projected_total_bytes,
        shipped_smallwood_candidate_bytes: CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES,
    })
}

pub fn analyze_smallwood_semantic_helper_aux_frontier_from_witness(
    witness: &TransactionWitness,
    profile: SmallwoodNoGrindingProfileV1,
) -> Result<Vec<SmallwoodSemanticHelperAuxAnalysisReport>, TransactionCircuitError> {
    [
        SmallwoodSemanticHelperAuxShape::packed_32x_v1(),
        SmallwoodSemanticHelperAuxShape::packed_64x_v1(),
        SmallwoodSemanticHelperAuxShape::packed_128x_v1(),
        SmallwoodSemanticHelperAuxShape::packed_32x_inline_merkle_skip_initial_mds_v1(),
        SmallwoodSemanticHelperAuxShape::packed_64x_inline_merkle_skip_initial_mds_v1(),
        SmallwoodSemanticHelperAuxShape::packed_128x_inline_merkle_skip_initial_mds_v1(),
        SmallwoodSemanticHelperAuxShape::packed_32x_semantic_adapter_floor_v1(),
        SmallwoodSemanticHelperAuxShape::packed_64x_semantic_adapter_floor_v1(),
        SmallwoodSemanticHelperAuxShape::packed_128x_semantic_adapter_floor_v1(),
    ]
    .into_iter()
    .map(|shape| analyze_smallwood_semantic_helper_aux_from_witness(witness, shape, profile))
    .collect()
}

pub fn exact_smallwood_semantic_helper_aux_report_from_witness(
    witness: &TransactionWitness,
    shape: SmallwoodSemanticHelperAuxShape,
) -> Result<SmallwoodSemanticHelperAuxReport, TransactionCircuitError> {
    let material = build_smallwood_semantic_helper_aux_material_from_witness(witness, shape)?;
    let proof = prove_smallwood_structural_identity_witness_with_auxiliary_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.auxiliary_helper_words,
        &material.transcript_binding,
    )?;
    verify_smallwood_structural_identity_witness_with_auxiliary_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        &material.packed_witness_matrix,
        &material.auxiliary_helper_words,
        &material.transcript_binding,
        &proof,
    )?;
    let projected_total_bytes = projected_smallwood_structural_proof_bytes_v1(
        material.statement.witness_rows as usize,
        material.statement.packing_factor as usize,
        material.statement.constraint_degree as usize,
        material.statement.constraint_count_estimate as usize,
        material.auxiliary_helper_words.len(),
        ACTIVE_SMALLWOOD_NO_GRINDING_PROFILE_V1,
    )?;
    Ok(SmallwoodSemanticHelperAuxReport {
        shape,
        statement: material.statement,
        exact_total_bytes: proof.len(),
        projected_total_bytes,
        shipped_smallwood_candidate_bytes: CURRENT_SMALLWOOD_SHIPPED_PROOF_BYTES,
    })
}

fn ensure_smallwood_semantic_lppc_shape(
    shape: SmallwoodSemanticLppcShape,
) -> Result<(), TransactionCircuitError> {
    if shape.witness_rows == 0 || shape.packing_factor == 0 {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood semantic LPPC shape requires non-zero rows and packing factor",
        ));
    }
    if !shape.witness_rows.is_power_of_two() || !shape.packing_factor.is_power_of_two() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood semantic LPPC shape must use power-of-two rows and packing factor",
        ));
    }
    if shape.padded_witness_elements() < NATIVE_TX_VALIDITY_RAW_WITNESS_ELEMENTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood semantic LPPC shape capacity {} is smaller than raw witness {}",
            shape.padded_witness_elements(),
            NATIVE_TX_VALIDITY_RAW_WITNESS_ELEMENTS
        )));
    }
    if shape.padded_witness_elements() != NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood semantic LPPC v1 expects a fixed padded witness window of {}, got {}",
            NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS,
            shape.padded_witness_elements()
        )));
    }
    Ok(())
}

fn ensure_smallwood_semantic_bridge_lower_bound_shape(
    shape: SmallwoodSemanticBridgeLowerBoundShape,
) -> Result<(), TransactionCircuitError> {
    if shape.packing_factor == 0 || !shape.packing_factor.is_power_of_two() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood semantic bridge lower-bound shape requires a power-of-two packing factor",
        ));
    }
    if !NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS.is_multiple_of(shape.packing_factor) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "semantic lower-bound packing {} does not divide the fixed semantic witness window {}",
            shape.packing_factor, NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS
        )));
    }
    Ok(())
}

fn ensure_smallwood_semantic_helper_floor_shape(
    shape: SmallwoodSemanticHelperFloorShape,
) -> Result<(), TransactionCircuitError> {
    if shape.packing_factor == 0 || !shape.packing_factor.is_power_of_two() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood semantic helper floor shape requires a power-of-two packing factor",
        ));
    }
    if !NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS.is_multiple_of(shape.packing_factor) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "semantic helper floor packing {} does not divide the fixed semantic witness window {}",
            shape.packing_factor, NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS
        )));
    }
    Ok(())
}

fn ensure_smallwood_semantic_helper_aux_shape(
    shape: SmallwoodSemanticHelperAuxShape,
) -> Result<(), TransactionCircuitError> {
    if shape.packing_factor == 0 || !shape.packing_factor.is_power_of_two() {
        return Err(TransactionCircuitError::ConstraintViolation(
            "smallwood semantic helper-aux shape requires a power-of-two packing factor",
        ));
    }
    if !NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS.is_multiple_of(shape.packing_factor) {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "semantic helper-aux packing {} does not divide the fixed semantic witness window {}",
            shape.packing_factor, NATIVE_TX_VALIDITY_PADDED_WITNESS_ELEMENTS
        )));
    }
    Ok(())
}

fn semantic_lppc_public_values(
    statement_hash: Commitment,
    public_inputs_digest: Commitment,
    verifier_profile_digest: Commitment,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut public_values = Vec::with_capacity(NATIVE_TX_VALIDITY_PUBLIC_VALUE_COUNT);
    for digest in [
        statement_hash,
        public_inputs_digest,
        verifier_profile_digest,
    ] {
        let limbs =
            bytes48_to_felts(&digest).ok_or(TransactionCircuitError::ConstraintViolation(
                "smallwood semantic LPPC digest encoding is non-canonical",
            ))?;
        public_values.extend(limbs.iter().map(|felt| felt.as_canonical_u64()));
    }
    Ok(public_values)
}

fn semantic_lppc_transcript_binding(
    statement: &SmallwoodSemanticLppcStatement,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut bytes = Vec::from(SMALLWOOD_SEMANTIC_LPPC_PROFILE_DOMAIN);
    let encoded = bincode::serialize(statement).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize semantic LPPC statement binding: {err}"
        ))
    })?;
    bytes.extend_from_slice(&encoded);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    Ok(bytes)
}

fn serialized_stark_inputs_from_witness(
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

fn native_tx_validity_witness_elements(
    witness: &TransactionWitness,
) -> Result<Vec<u64>, TransactionCircuitError> {
    witness.validate()?;
    let mut values = Vec::with_capacity(NATIVE_TX_VALIDITY_RAW_WITNESS_ELEMENTS);
    let (value_balance_sign, value_balance_magnitude) =
        signed_magnitude_u64(witness.value_balance, "value_balance")?;
    let (stablecoin_issuance_sign, stablecoin_issuance_magnitude) =
        signed_magnitude_u64(witness.stablecoin.issuance_delta, "stablecoin_issuance")?;

    values.push(witness.inputs.len() as u64);
    values.push(witness.outputs.len() as u64);
    values.push(witness.ciphertext_hashes.len() as u64);
    push_bytes32_u64(&mut values, &witness.sk_spend);
    push_bytes48_u64(&mut values, &witness.merkle_root);
    values.push(witness.fee);
    values.push(u64::from(value_balance_sign));
    values.push(value_balance_magnitude);
    values.push(u64::from(witness.stablecoin.enabled));
    values.push(witness.stablecoin.asset_id);
    push_bytes48_u64(&mut values, &witness.stablecoin.policy_hash);
    push_bytes48_u64(&mut values, &witness.stablecoin.oracle_commitment);
    push_bytes48_u64(&mut values, &witness.stablecoin.attestation_commitment);
    values.push(u64::from(stablecoin_issuance_sign));
    values.push(stablecoin_issuance_magnitude);
    values.push(u64::from(witness.stablecoin.policy_version));
    values.push(u64::from(witness.version.circuit));
    values.push(u64::from(witness.version.crypto));

    push_padded_input_note_fields(&mut values, &witness.inputs)?;
    push_padded_output_note_fields(&mut values, &witness.outputs)?;
    push_padded_ciphertext_hashes(&mut values, &witness.ciphertext_hashes)?;

    if values.len() != NATIVE_TX_VALIDITY_RAW_WITNESS_ELEMENTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "smallwood semantic LPPC witness length {} does not match expected {}",
            values.len(),
            NATIVE_TX_VALIDITY_RAW_WITNESS_ELEMENTS
        )));
    }
    Ok(values)
}

fn smallwood_semantic_bridge_lower_bound_profile_material(
    version: VersionBinding,
    shape: SmallwoodSemanticBridgeLowerBoundShape,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(b"hegemon.tx.smallwood-semantic-bridge-lower-bound.v1");
    material.extend_from_slice(&version.circuit.to_le_bytes());
    material.extend_from_slice(&version.crypto.to_le_bytes());
    material.extend_from_slice(&(shape.packing_factor as u64).to_le_bytes());
    material
        .extend_from_slice(&(SMALLWOOD_SEMANTIC_BRIDGE_MERKLE_AGGREGATE_ROWS as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u64).to_le_bytes());
    material
}

fn semantic_bridge_lower_bound_transcript_binding(
    statement: &SmallwoodSemanticBridgeLowerBoundStatement,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut bytes = Vec::from(b"hegemon.tx.smallwood-semantic-bridge-binding.v1".as_slice());
    let encoded = bincode::serialize(statement).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize semantic bridge lower-bound statement binding: {err}"
        ))
    })?;
    bytes.extend_from_slice(&encoded);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    Ok(bytes)
}

fn smallwood_semantic_helper_floor_profile_material(
    version: VersionBinding,
    shape: SmallwoodSemanticHelperFloorShape,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(SMALLWOOD_SEMANTIC_HELPER_FLOOR_PROFILE_DOMAIN);
    material.extend_from_slice(&version.circuit.to_le_bytes());
    material.extend_from_slice(&version.crypto.to_le_bytes());
    material.extend_from_slice(&(shape.packing_factor as u64).to_le_bytes());
    material.extend_from_slice(&(SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u64).to_le_bytes());
    material
}

fn semantic_helper_floor_transcript_binding(
    statement: &SmallwoodSemanticHelperFloorStatement,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut bytes = Vec::from(b"hegemon.tx.smallwood-semantic-helper-floor-binding.v1".as_slice());
    let encoded = bincode::serialize(statement).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize semantic helper floor statement binding: {err}"
        ))
    })?;
    bytes.extend_from_slice(&encoded);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    Ok(bytes)
}

fn smallwood_semantic_helper_aux_profile_material(
    version: VersionBinding,
    shape: SmallwoodSemanticHelperAuxShape,
) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(SMALLWOOD_SEMANTIC_HELPER_AUX_FLOOR_PROFILE_DOMAIN);
    material.extend_from_slice(&version.circuit.to_le_bytes());
    material.extend_from_slice(&version.crypto.to_le_bytes());
    material.extend_from_slice(&(shape.packing_factor as u64).to_le_bytes());
    material.push(u8::from(shape.inline_merkle_aggregates));
    material.push(u8::from(shape.skip_initial_mds_poseidon));
    material.push(u8::from(shape.derive_lane_local_helpers_from_semantic));
    material.extend_from_slice(&(SMALLWOOD_SEMANTIC_LPPC_CONSTRAINT_DEGREE as u64).to_le_bytes());
    material
}

fn semantic_helper_aux_transcript_binding(
    statement: &SmallwoodSemanticHelperAuxStatement,
) -> Result<Vec<u8>, TransactionCircuitError> {
    let mut bytes = Vec::from(b"hegemon.tx.smallwood-semantic-helper-aux-binding.v1".as_slice());
    let encoded = bincode::serialize(statement).map_err(|err| {
        TransactionCircuitError::ConstraintViolationOwned(format!(
            "failed to serialize semantic helper-aux statement binding: {err}"
        ))
    })?;
    bytes.extend_from_slice(&encoded);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    Ok(bytes)
}

fn build_semantic_bridge_lower_bound_secret_rows(
    witness: &TransactionWitness,
    public_values: &[u64],
    shape: SmallwoodSemanticBridgeLowerBoundShape,
) -> Result<Vec<u64>, TransactionCircuitError> {
    let semantic = native_tx_validity_witness_elements(witness)?;
    let mut rows = Vec::with_capacity(
        (shape.semantic_witness_rows() + SMALLWOOD_SEMANTIC_BRIDGE_MERKLE_AGGREGATE_ROWS)
            * shape.packing_factor,
    );
    for chunk in semantic.chunks_exact(shape.packing_factor) {
        rows.extend_from_slice(chunk);
    }
    let aggregate_rows = semantic_bridge_merkle_aggregate_rows(witness, public_values)?;
    for value in aggregate_rows {
        rows.extend(std::iter::repeat_n(value, shape.packing_factor));
    }
    Ok(rows)
}

fn semantic_bridge_merkle_aggregate_rows(
    witness: &TransactionWitness,
    public_values: &[u64],
) -> Result<Vec<u64>, TransactionCircuitError> {
    let mut values = Vec::with_capacity(SMALLWOOD_SEMANTIC_BRIDGE_MERKLE_AGGREGATE_ROWS);
    for input in 0..MAX_INPUTS {
        if let Some(note_input) = witness.inputs.get(input) {
            if note_input.merkle_path.siblings.len() != crate::note::MERKLE_TREE_DEPTH {
                return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
                    "semantic bridge lower-bound input merkle path has length {}, expected {}",
                    note_input.merkle_path.siblings.len(),
                    crate::note::MERKLE_TREE_DEPTH
                )));
            }
            let mut current = note_input.note.commitment();
            for level in 0..crate::note::MERKLE_TREE_DEPTH {
                let challenge = semantic_bridge_merkle_challenge(public_values, input, level);
                let sibling = note_input.merkle_path.siblings[level];
                values.push(aggregate_hash(current, challenge));
                let (left, right) = if ((note_input.position >> level) & 1) == 0 {
                    (current, sibling)
                } else {
                    (sibling, current)
                };
                values.push(aggregate_hash(left, challenge));
                values.push(aggregate_hash(right, challenge));
                current = merkle_node(left, right);
            }
        } else {
            values.extend(std::iter::repeat_n(0, crate::note::MERKLE_TREE_DEPTH * 3));
        }
    }
    Ok(values)
}

fn semantic_bridge_merkle_challenge(public_values: &[u64], input: usize, level: usize) -> u64 {
    let mut words = Vec::with_capacity(public_values.len() + 4);
    words.push(0x736d_616c_6c77_6f6f);
    words.push(9);
    words.push(input as u64);
    words.push(level as u64);
    words.extend_from_slice(public_values);
    let mut out = [0u64; 1];
    semantic_bridge_xof_words(&words, &mut out);
    if out[0] <= 1 {
        out[0] += 2;
    }
    out[0]
}

fn aggregate_hash_words(words: &[u64; NATIVE_TX_VALIDITY_DIGEST_WORDS], challenge: u64) -> u64 {
    let mut acc = 0u64;
    let mut power = 1u64;
    for &word in words {
        acc = add_mod_u64(acc, mul_mod_u64(power, word));
        power = mul_mod_u64(power, challenge);
    }
    acc
}

fn hash_felt_to_words(hash: HashFelt) -> [u64; NATIVE_TX_VALIDITY_DIGEST_WORDS] {
    let mut words = [0u64; NATIVE_TX_VALIDITY_DIGEST_WORDS];
    for (idx, felt) in hash.iter().enumerate() {
        words[idx] = felt.as_canonical_u64();
    }
    words
}

fn aggregate_hash(hash: HashFelt, challenge: u64) -> u64 {
    aggregate_hash_words(&hash_felt_to_words(hash), challenge)
}

fn semantic_bridge_xof_words(input_words: &[u64], output_words: &mut [u64]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hegemon.smallwood.f64-xof.v1");
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

fn smallwood_bridge_poseidon_group_rows(permutation_count: usize, packing_factor: usize) -> usize {
    smallwood_bridge_poseidon_group_rows_for_steps(
        permutation_count,
        packing_factor,
        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION,
    )
}

fn append_grouped_poseidon_rows(
    out: &mut Vec<u64>,
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]],
    packing_factor: usize,
) {
    append_grouped_poseidon_rows_for_steps(
        out,
        poseidon_rows,
        packing_factor,
        0,
        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION,
    );
}

fn smallwood_bridge_poseidon_group_rows_for_shape(
    shape: SmallwoodSemanticHelperAuxShape,
    permutation_count: usize,
) -> usize {
    smallwood_bridge_poseidon_group_rows_for_steps(
        permutation_count,
        shape.packing_factor,
        shape.poseidon_rows_per_permutation(),
    )
}

fn smallwood_bridge_poseidon_group_rows_for_steps(
    permutation_count: usize,
    packing_factor: usize,
    rows_per_permutation: usize,
) -> usize {
    permutation_count.div_ceil(packing_factor) * rows_per_permutation * POSEIDON2_WIDTH
}

fn append_grouped_poseidon_rows_for_shape(
    out: &mut Vec<u64>,
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]],
    shape: SmallwoodSemanticHelperAuxShape,
) {
    let step_start = usize::from(shape.skip_initial_mds_poseidon);
    append_grouped_poseidon_rows_for_steps(
        out,
        poseidon_rows,
        shape.packing_factor,
        step_start,
        SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION,
    );
}

fn append_grouped_poseidon_rows_for_steps(
    out: &mut Vec<u64>,
    poseidon_rows: &[[[u64; POSEIDON2_WIDTH]; SMALLWOOD_POSEIDON_STATE_ROWS_PER_PERMUTATION]],
    packing_factor: usize,
    step_start: usize,
    step_end: usize,
) {
    let dummy_rows = dummy_poseidon_rows();
    let poseidon_group_count = poseidon_rows.len().div_ceil(packing_factor);
    for group in 0..poseidon_group_count {
        for step in step_start..step_end {
            for limb in 0..POSEIDON2_WIDTH {
                for lane in 0..packing_factor {
                    let value = poseidon_rows
                        .get(group * packing_factor + lane)
                        .map(|permutation| permutation[step][limb])
                        .unwrap_or(dummy_rows[step][limb]);
                    out.push(value);
                }
            }
        }
    }
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

fn snapshot_state(state: &[Felt; POSEIDON2_WIDTH]) -> [u64; POSEIDON2_WIDTH] {
    let mut row = [0u64; POSEIDON2_WIDTH];
    for (idx, value) in state.iter().enumerate() {
        row[idx] = value.as_canonical_u64();
    }
    row
}

fn push_bytes32_u64(out: &mut Vec<u64>, bytes: &[u8; 32]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}

fn push_bytes48_u64(out: &mut Vec<u64>, bytes: &[u8; 48]) {
    out.extend(bytes.iter().map(|byte| u64::from(*byte)));
}

fn push_padded_input_note_fields(
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
            push_bytes32_u64(out, &input.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_u64(out, &input.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_u64(out, &input.note.rho);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_u64(out, &input.note.r);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        out.push(inputs.get(idx).map(|input| input.position).unwrap_or(0));
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32_u64(out, &input.rho_seed);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            for sibling in &input.merkle_path.siblings {
                let bytes = felts_to_bytes48(sibling);
                push_bytes48_u64(out, &bytes);
            }
        } else {
            out.extend(std::iter::repeat_n(0, crate::note::MERKLE_TREE_DEPTH * 48));
        }
    }
    Ok(())
}

fn push_padded_output_note_fields(
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
            push_bytes32_u64(out, &output.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_u64(out, &output.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_u64(out, &output.note.rho);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32_u64(out, &output.note.r);
        } else {
            out.extend(std::iter::repeat_n(0, 32));
        }
    }
    Ok(())
}

fn push_padded_ciphertext_hashes(
    out: &mut Vec<u64>,
    ciphertext_hashes: &[Commitment],
) -> Result<(), TransactionCircuitError> {
    if ciphertext_hashes.len() > MAX_OUTPUTS {
        return Err(TransactionCircuitError::ConstraintViolationOwned(format!(
            "native tx ciphertext hash count {} exceeds {}",
            ciphertext_hashes.len(),
            MAX_OUTPUTS
        )));
    }
    for idx in 0..MAX_OUTPUTS {
        let bytes = ciphertext_hashes.get(idx).copied().unwrap_or([0u8; 48]);
        push_bytes48_u64(out, &bytes);
    }
    Ok(())
}
