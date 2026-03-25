use std::sync::OnceLock;

use anyhow::{ensure, Result};
use blake3::Hasher;
use p3_goldilocks::Goldilocks;
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use superneo_backend_lattice::{LatticeBackend, LatticeCommitment, LeafDigestProof, RingElem};
use superneo_ccs::{
    digest_statement, Assignment, CcsShape, Relation, RelationId, SparseEntry, SparseMatrix,
    StatementEncoding, WitnessField, WitnessSchema,
};
use superneo_core::{Backend, FoldedInstance, LeafArtifact, SecurityParams};
use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{bytes48_to_felts, felts_to_bytes48};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{InputNoteWitness, OutputNoteWitness, MERKLE_TREE_DEPTH};
use transaction_circuit::proof::{
    transaction_proof_digest, transaction_public_inputs_digest,
    transaction_public_inputs_digest_from_serialized, transaction_statement_hash,
    transaction_verifier_profile_digest, transaction_verifier_profile_digest_for_version,
    verify as verify_transaction_proof, SerializedStarkInputs, TransactionProof,
};
use transaction_circuit::public_inputs::TransactionPublicInputs;
use transaction_circuit::TransactionWitness;

pub const MAX_RECEIPT_BYTES: usize = 96;
pub const MAX_TRACE_BITS: usize = 256;
pub const RECEIPT_ROOT_ARTIFACT_VERSION: u16 = 1;
pub const TX_LEAF_ARTIFACT_VERSION: u16 = 1;
pub const NATIVE_TX_LEAF_ARTIFACT_VERSION: u16 = 1;
pub const RECEIPT_ROOT_DIGEST_WIDTH: usize = 4;
pub const RECEIPT_ROOT_LIMBS_PER_DIGEST: usize = 6;
pub const RECEIPT_ROOT_WITNESS_LIMBS: usize =
    RECEIPT_ROOT_DIGEST_WIDTH * RECEIPT_ROOT_LIMBS_PER_DIGEST;
pub const DIGEST_LIMBS: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToyBalanceStatement {
    pub total_inputs: u64,
    pub total_outputs: u64,
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToyBalanceWitness {
    pub inputs: [u64; 2],
    pub outputs: [u64; 2],
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToyBalanceRelation {
    shape: CcsShape<Goldilocks>,
}

impl Default for ToyBalanceRelation {
    fn default() -> Self {
        let witness_schema = WitnessSchema {
            fields: vec![
                WitnessField {
                    name: "input_value",
                    bit_width: 20,
                    signed: false,
                    count: 2,
                },
                WitnessField {
                    name: "output_value",
                    bit_width: 20,
                    signed: false,
                    count: 2,
                },
                WitnessField {
                    name: "fee",
                    bit_width: 20,
                    signed: false,
                    count: 1,
                },
            ],
        };
        let shape = CcsShape {
            num_rows: 8,
            num_cols: witness_schema.total_witness_elements(),
            matrices: vec![SparseMatrix {
                row_count: 8,
                col_count: witness_schema.total_witness_elements(),
                entries: vec![
                    SparseEntry {
                        row: 0,
                        col: 0,
                        value: Goldilocks::new(1),
                    },
                    SparseEntry {
                        row: 1,
                        col: 4,
                        value: Goldilocks::new(1),
                    },
                ],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema,
        };
        Self { shape }
    }
}

impl Relation<Goldilocks> for ToyBalanceRelation {
    type Statement = ToyBalanceStatement;
    type Witness = ToyBalanceWitness;

    fn relation_id(&self) -> RelationId {
        RelationId::from_label("hegemon.superneo.toy-balance")
    }

    fn shape(&self) -> &CcsShape<Goldilocks> {
        &self.shape
    }

    fn encode_statement(
        &self,
        statement: &Self::Statement,
    ) -> Result<StatementEncoding<Goldilocks>> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&statement.total_inputs.to_le_bytes());
        bytes.extend_from_slice(&statement.total_outputs.to_le_bytes());
        bytes.extend_from_slice(&statement.fee.to_le_bytes());
        Ok(StatementEncoding {
            public_inputs: vec![
                Goldilocks::new(statement.total_inputs),
                Goldilocks::new(statement.total_outputs),
                Goldilocks::new(statement.fee),
            ],
            statement_digest: digest_statement(&bytes),
        })
    }

    fn build_assignment(
        &self,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Assignment<Goldilocks>> {
        let total_inputs: u64 = witness.inputs.iter().sum();
        let total_outputs: u64 = witness.outputs.iter().sum();
        ensure!(
            total_inputs == statement.total_inputs,
            "toy relation input sum {} does not match statement {}",
            total_inputs,
            statement.total_inputs
        );
        ensure!(
            total_outputs == statement.total_outputs,
            "toy relation output sum {} does not match statement {}",
            total_outputs,
            statement.total_outputs
        );
        ensure!(
            total_inputs == total_outputs + witness.fee,
            "toy relation does not conserve value"
        );
        ensure!(witness.fee == statement.fee, "toy fee mismatch");
        Ok(Assignment {
            witness: witness
                .inputs
                .iter()
                .chain(witness.outputs.iter())
                .copied()
                .map(Goldilocks::new)
                .chain(std::iter::once(Goldilocks::new(witness.fee)))
                .collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxProofReceipt {
    pub tx_statement_digest: [u8; 48],
    pub proof_digest: [u8; 48],
    pub verifier_profile_digest: [u8; 48],
    pub public_inputs_digest: [u8; 48],
    pub verification_trace_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxProofReceiptWitness {
    pub receipt_bytes: Vec<u8>,
    pub verification_trace_bits: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxProofReceiptRelation {
    shape: CcsShape<Goldilocks>,
}

impl Default for TxProofReceiptRelation {
    fn default() -> Self {
        let witness_schema = WitnessSchema {
            fields: vec![
                WitnessField {
                    name: "receipt_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "trace_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "receipt_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_RECEIPT_BYTES,
                },
                WitnessField {
                    name: "trace_bit",
                    bit_width: 1,
                    signed: false,
                    count: MAX_TRACE_BITS,
                },
            ],
        };
        let witness_cols = witness_schema.total_witness_elements();
        let shape = CcsShape {
            num_rows: 128,
            num_cols: witness_cols,
            matrices: vec![SparseMatrix {
                row_count: 128,
                col_count: witness_cols,
                entries: vec![
                    SparseEntry {
                        row: 0,
                        col: 0,
                        value: Goldilocks::new(1),
                    },
                    SparseEntry {
                        row: 1,
                        col: 1,
                        value: Goldilocks::new(1),
                    },
                    SparseEntry {
                        row: 2,
                        col: 2,
                        value: Goldilocks::new(1),
                    },
                ],
            }],
            selectors: vec![Goldilocks::new(1), Goldilocks::new(2)],
            witness_schema,
        };
        Self { shape }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalTxValidityReceipt {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub statement_hash: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub proof_digest: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub public_inputs_digest: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub verifier_profile: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTxValidityStatement {
    pub statement_hash: [u8; 48],
    pub public_inputs_digest: [u8; 48],
    pub verifier_profile: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTxValidityReceiptRelation {
    shape: CcsShape<Goldilocks>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxLeafPublicTx {
    pub nullifiers: Vec<[u8; 48]>,
    pub commitments: Vec<[u8; 48]>,
    pub ciphertext_hashes: Vec<[u8; 48]>,
    pub balance_tag: [u8; 48],
    pub version: VersionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxLeafPublicWitness {
    pub tx: TxLeafPublicTx,
    pub stark_public_inputs: SerializedStarkInputs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxLeafPublicRelation {
    shape: CcsShape<Goldilocks>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTxValidityRelation {
    shape: CcsShape<Goldilocks>,
}

impl Default for CanonicalTxValidityReceiptRelation {
    fn default() -> Self {
        let witness_schema = WitnessSchema {
            fields: vec![WitnessField {
                name: "receipt_limb",
                bit_width: 64,
                signed: false,
                count: RECEIPT_ROOT_WITNESS_LIMBS,
            }],
        };
        let shape = CcsShape {
            num_rows: 32,
            num_cols: witness_schema.total_witness_elements(),
            matrices: vec![SparseMatrix {
                row_count: 32,
                col_count: witness_schema.total_witness_elements(),
                entries: vec![SparseEntry {
                    row: 0,
                    col: 0,
                    value: Goldilocks::new(1),
                }],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema,
        };
        Self { shape }
    }
}

impl Default for TxLeafPublicRelation {
    fn default() -> Self {
        let witness_schema = WitnessSchema {
            fields: vec![
                WitnessField {
                    name: "input_flag_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "output_flag_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "input_flag",
                    bit_width: 1,
                    signed: false,
                    count: MAX_INPUTS,
                },
                WitnessField {
                    name: "output_flag",
                    bit_width: 1,
                    signed: false,
                    count: MAX_OUTPUTS,
                },
                WitnessField {
                    name: "fee",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "value_balance_sign",
                    bit_width: 1,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "value_balance_magnitude",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "merkle_root_limb",
                    bit_width: 64,
                    signed: false,
                    count: DIGEST_LIMBS,
                },
                WitnessField {
                    name: "balance_slot_asset_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "balance_slot_asset_id",
                    bit_width: 64,
                    signed: false,
                    count: BALANCE_SLOTS,
                },
                WitnessField {
                    name: "stablecoin_enabled",
                    bit_width: 1,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_asset_id",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_policy_version",
                    bit_width: 32,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_issuance_sign",
                    bit_width: 1,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_issuance_magnitude",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_policy_hash_limb",
                    bit_width: 64,
                    signed: false,
                    count: DIGEST_LIMBS,
                },
                WitnessField {
                    name: "stablecoin_oracle_commitment_limb",
                    bit_width: 64,
                    signed: false,
                    count: DIGEST_LIMBS,
                },
                WitnessField {
                    name: "stablecoin_attestation_commitment_limb",
                    bit_width: 64,
                    signed: false,
                    count: DIGEST_LIMBS,
                },
                WitnessField {
                    name: "nullifier_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "nullifier_limb",
                    bit_width: 64,
                    signed: false,
                    count: MAX_INPUTS * DIGEST_LIMBS,
                },
                WitnessField {
                    name: "commitment_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "commitment_limb",
                    bit_width: 64,
                    signed: false,
                    count: MAX_OUTPUTS * DIGEST_LIMBS,
                },
                WitnessField {
                    name: "ciphertext_hash_len",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "ciphertext_hash_limb",
                    bit_width: 64,
                    signed: false,
                    count: MAX_OUTPUTS * DIGEST_LIMBS,
                },
                WitnessField {
                    name: "balance_tag_limb",
                    bit_width: 64,
                    signed: false,
                    count: DIGEST_LIMBS,
                },
                WitnessField {
                    name: "circuit_version",
                    bit_width: 32,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "crypto_suite",
                    bit_width: 32,
                    signed: false,
                    count: 1,
                },
            ],
        };
        let shape = CcsShape {
            num_rows: 256,
            num_cols: witness_schema.total_witness_elements(),
            matrices: vec![SparseMatrix {
                row_count: 256,
                col_count: witness_schema.total_witness_elements(),
                entries: vec![
                    SparseEntry {
                        row: 0,
                        col: 0,
                        value: Goldilocks::new(1),
                    },
                    SparseEntry {
                        row: 1,
                        col: 1,
                        value: Goldilocks::new(1),
                    },
                    SparseEntry {
                        row: 2,
                        col: 2,
                        value: Goldilocks::new(1),
                    },
                ],
            }],
            selectors: vec![Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(3)],
            witness_schema,
        };
        Self { shape }
    }
}

impl Default for NativeTxValidityRelation {
    fn default() -> Self {
        let witness_schema = WitnessSchema {
            fields: vec![
                WitnessField {
                    name: "input_count",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "output_count",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "ciphertext_hash_count",
                    bit_width: 16,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "sk_spend_byte",
                    bit_width: 8,
                    signed: false,
                    count: 32,
                },
                WitnessField {
                    name: "merkle_root_byte",
                    bit_width: 8,
                    signed: false,
                    count: 48,
                },
                WitnessField {
                    name: "fee",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "value_balance_sign",
                    bit_width: 1,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "value_balance_magnitude",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_enabled",
                    bit_width: 1,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_asset_id",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_policy_hash_byte",
                    bit_width: 8,
                    signed: false,
                    count: 48,
                },
                WitnessField {
                    name: "stablecoin_oracle_commitment_byte",
                    bit_width: 8,
                    signed: false,
                    count: 48,
                },
                WitnessField {
                    name: "stablecoin_attestation_commitment_byte",
                    bit_width: 8,
                    signed: false,
                    count: 48,
                },
                WitnessField {
                    name: "stablecoin_issuance_sign",
                    bit_width: 1,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_issuance_magnitude",
                    bit_width: 64,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "stablecoin_policy_version",
                    bit_width: 32,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "version_circuit",
                    bit_width: 32,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "version_crypto",
                    bit_width: 32,
                    signed: false,
                    count: 1,
                },
                WitnessField {
                    name: "input_value",
                    bit_width: 64,
                    signed: false,
                    count: MAX_INPUTS,
                },
                WitnessField {
                    name: "input_asset_id",
                    bit_width: 64,
                    signed: false,
                    count: MAX_INPUTS,
                },
                WitnessField {
                    name: "input_pk_recipient_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_INPUTS * 32,
                },
                WitnessField {
                    name: "input_pk_auth_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_INPUTS * 32,
                },
                WitnessField {
                    name: "input_rho_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_INPUTS * 32,
                },
                WitnessField {
                    name: "input_r_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_INPUTS * 32,
                },
                WitnessField {
                    name: "input_position",
                    bit_width: 64,
                    signed: false,
                    count: MAX_INPUTS,
                },
                WitnessField {
                    name: "input_rho_seed_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_INPUTS * 32,
                },
                WitnessField {
                    name: "input_merkle_sibling_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_INPUTS * MERKLE_TREE_DEPTH * 48,
                },
                WitnessField {
                    name: "output_value",
                    bit_width: 64,
                    signed: false,
                    count: MAX_OUTPUTS,
                },
                WitnessField {
                    name: "output_asset_id",
                    bit_width: 64,
                    signed: false,
                    count: MAX_OUTPUTS,
                },
                WitnessField {
                    name: "output_pk_recipient_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_OUTPUTS * 32,
                },
                WitnessField {
                    name: "output_pk_auth_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_OUTPUTS * 32,
                },
                WitnessField {
                    name: "output_rho_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_OUTPUTS * 32,
                },
                WitnessField {
                    name: "output_r_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_OUTPUTS * 32,
                },
                WitnessField {
                    name: "ciphertext_hash_byte",
                    bit_width: 8,
                    signed: false,
                    count: MAX_OUTPUTS * 48,
                },
            ],
        };
        let shape = CcsShape {
            num_rows: 512,
            num_cols: witness_schema.total_witness_elements(),
            matrices: vec![SparseMatrix {
                row_count: 512,
                col_count: witness_schema.total_witness_elements(),
                entries: vec![
                    SparseEntry {
                        row: 0,
                        col: 0,
                        value: Goldilocks::new(1),
                    },
                    SparseEntry {
                        row: 1,
                        col: 1,
                        value: Goldilocks::new(1),
                    },
                    SparseEntry {
                        row: 2,
                        col: 2,
                        value: Goldilocks::new(1),
                    },
                ],
            }],
            selectors: vec![Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(3)],
            witness_schema,
        };
        Self { shape }
    }
}

impl Relation<Goldilocks> for CanonicalTxValidityReceiptRelation {
    type Statement = CanonicalTxValidityReceipt;
    type Witness = ();

    fn relation_id(&self) -> RelationId {
        RelationId::from_label("hegemon.superneo.canonical-tx-validity-receipt")
    }

    fn shape(&self) -> &CcsShape<Goldilocks> {
        &self.shape
    }

    fn encode_statement(
        &self,
        statement: &Self::Statement,
    ) -> Result<StatementEncoding<Goldilocks>> {
        let bytes = canonical_tx_validity_receipt_bytes(statement);
        let mut public_inputs = Vec::with_capacity(RECEIPT_ROOT_WITNESS_LIMBS);
        public_inputs.extend(bytes48_to_goldilocks(&statement.statement_hash));
        public_inputs.extend(bytes48_to_goldilocks(&statement.proof_digest));
        public_inputs.extend(bytes48_to_goldilocks(&statement.public_inputs_digest));
        public_inputs.extend(bytes48_to_goldilocks(&statement.verifier_profile));
        Ok(StatementEncoding {
            public_inputs,
            statement_digest: digest_statement(&bytes),
        })
    }

    fn build_assignment(
        &self,
        statement: &Self::Statement,
        _witness: &Self::Witness,
    ) -> Result<Assignment<Goldilocks>> {
        let mut witness = Vec::with_capacity(RECEIPT_ROOT_WITNESS_LIMBS);
        witness.extend(bytes48_to_goldilocks(&statement.statement_hash));
        witness.extend(bytes48_to_goldilocks(&statement.proof_digest));
        witness.extend(bytes48_to_goldilocks(&statement.public_inputs_digest));
        witness.extend(bytes48_to_goldilocks(&statement.verifier_profile));
        Ok(Assignment { witness })
    }
}

impl Relation<Goldilocks> for TxLeafPublicRelation {
    type Statement = CanonicalTxValidityReceipt;
    type Witness = TxLeafPublicWitness;

    fn relation_id(&self) -> RelationId {
        RelationId::from_label("hegemon.superneo.tx-leaf-public")
    }

    fn shape(&self) -> &CcsShape<Goldilocks> {
        &self.shape
    }

    fn encode_statement(
        &self,
        statement: &Self::Statement,
    ) -> Result<StatementEncoding<Goldilocks>> {
        CanonicalTxValidityReceiptRelation::default().encode_statement(statement)
    }

    fn build_assignment(
        &self,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Assignment<Goldilocks>> {
        validate_tx_leaf_public_witness(statement, witness)?;
        tx_leaf_public_witness_assignment(witness)
    }
}

impl Relation<Goldilocks> for NativeTxValidityRelation {
    type Statement = NativeTxValidityStatement;
    type Witness = TransactionWitness;

    fn relation_id(&self) -> RelationId {
        RelationId::from_label("hegemon.superneo.native-tx-validity")
    }

    fn shape(&self) -> &CcsShape<Goldilocks> {
        &self.shape
    }

    fn encode_statement(
        &self,
        statement: &Self::Statement,
    ) -> Result<StatementEncoding<Goldilocks>> {
        let mut bytes = Vec::with_capacity(48 * 3);
        bytes.extend_from_slice(&statement.statement_hash);
        bytes.extend_from_slice(&statement.public_inputs_digest);
        bytes.extend_from_slice(&statement.verifier_profile);
        let mut public_inputs = Vec::with_capacity(18);
        public_inputs.extend(bytes48_to_goldilocks(&statement.statement_hash));
        public_inputs.extend(bytes48_to_goldilocks(&statement.public_inputs_digest));
        public_inputs.extend(bytes48_to_goldilocks(&statement.verifier_profile));
        Ok(StatementEncoding {
            public_inputs,
            statement_digest: digest_statement(&bytes),
        })
    }

    fn build_assignment(
        &self,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Assignment<Goldilocks>> {
        validate_native_tx_witness(statement, witness)?;
        native_tx_witness_assignment(witness)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootLeaf {
    pub statement_digest: [u8; 48],
    pub witness_commitment: [u8; 48],
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootFoldStep {
    pub parent_statement_digest: [u8; 48],
    pub parent_commitment: [u8; 48],
    pub left_statement_digest: [u8; 48],
    pub left_commitment: [u8; 48],
    pub right_statement_digest: [u8; 48],
    pub right_commitment: [u8; 48],
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootArtifact {
    pub version: u16,
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub leaves: Vec<ReceiptRootLeaf>,
    pub folds: Vec<ReceiptRootFoldStep>,
    pub root_statement_digest: [u8; 48],
    pub root_commitment: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootMetadata {
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub leaf_count: u32,
    pub fold_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltReceiptRootArtifact {
    pub artifact_bytes: Vec<u8>,
    pub metadata: ReceiptRootMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxLeafArtifact {
    pub version: u16,
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub statement_digest: [u8; 48],
    pub stark_public_inputs: SerializedStarkInputs,
    pub leaf: LeafArtifact<LeafDigestProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeTxLeafOpening {
    #[serde(
        serialize_with = "serialize_fixed_bytes_32",
        deserialize_with = "deserialize_fixed_bytes_32"
    )]
    pub sk_spend: [u8; 32],
    pub inputs: Vec<InputNoteWitness>,
    pub outputs: Vec<OutputNoteWitness>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeTxLeafArtifact {
    pub version: u16,
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub statement_digest: [u8; 48],
    pub receipt: CanonicalTxValidityReceipt,
    pub stark_public_inputs: SerializedStarkInputs,
    pub opening: NativeTxLeafOpening,
    pub commitment: LatticeCommitment,
    pub leaf: LeafArtifact<LeafDigestProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltTxLeafArtifact {
    pub artifact_bytes: Vec<u8>,
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub statement_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltNativeTxLeafArtifact {
    pub artifact_bytes: Vec<u8>,
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub statement_digest: [u8; 48],
    pub receipt: CanonicalTxValidityReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxLeafMetadata {
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub statement_digest: [u8; 48],
    pub stark_public_inputs: SerializedStarkInputs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTxLeafMetadata {
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub statement_digest: [u8; 48],
    pub stark_public_inputs: SerializedStarkInputs,
    pub commitment: LatticeCommitment,
}

impl Relation<Goldilocks> for TxProofReceiptRelation {
    type Statement = TxProofReceipt;
    type Witness = TxProofReceiptWitness;

    fn relation_id(&self) -> RelationId {
        RelationId::from_label("hegemon.superneo.tx-proof-receipt")
    }

    fn shape(&self) -> &CcsShape<Goldilocks> {
        &self.shape
    }

    fn encode_statement(
        &self,
        statement: &Self::Statement,
    ) -> Result<StatementEncoding<Goldilocks>> {
        let mut bytes = Vec::with_capacity(48 * 5);
        bytes.extend_from_slice(&statement.tx_statement_digest);
        bytes.extend_from_slice(&statement.proof_digest);
        bytes.extend_from_slice(&statement.verifier_profile_digest);
        bytes.extend_from_slice(&statement.public_inputs_digest);
        bytes.extend_from_slice(&statement.verification_trace_digest);

        let mut public_inputs = Vec::with_capacity(30);
        public_inputs.extend(bytes48_to_goldilocks(&statement.tx_statement_digest));
        public_inputs.extend(bytes48_to_goldilocks(&statement.proof_digest));
        public_inputs.extend(bytes48_to_goldilocks(&statement.verifier_profile_digest));
        public_inputs.extend(bytes48_to_goldilocks(&statement.public_inputs_digest));
        public_inputs.extend(bytes48_to_goldilocks(&statement.verification_trace_digest));
        Ok(StatementEncoding {
            public_inputs,
            statement_digest: digest_statement(&bytes),
        })
    }

    fn build_assignment(
        &self,
        statement: &Self::Statement,
        witness: &Self::Witness,
    ) -> Result<Assignment<Goldilocks>> {
        ensure!(
            witness.receipt_bytes.len() <= MAX_RECEIPT_BYTES,
            "receipt length {} exceeds {}",
            witness.receipt_bytes.len(),
            MAX_RECEIPT_BYTES
        );
        ensure!(
            witness.verification_trace_bits.len() <= MAX_TRACE_BITS,
            "trace length {} exceeds {}",
            witness.verification_trace_bits.len(),
            MAX_TRACE_BITS
        );
        ensure!(
            digest48(b"hegemon.superneo.proof-bytes.v1", &witness.receipt_bytes)
                == statement.proof_digest,
            "receipt witness does not match proof digest"
        );
        ensure!(
            digest48(
                b"hegemon.superneo.verification-trace.v1",
                &witness.verification_trace_bits,
            ) == statement.verification_trace_digest,
            "verification trace witness does not match trace digest"
        );
        ensure!(
            witness
                .verification_trace_bits
                .iter()
                .all(|bit| *bit == 0 || *bit == 1),
            "trace bits must be binary"
        );

        let mut values = Vec::with_capacity(self.shape.expected_witness_len());
        values.push(Goldilocks::new(witness.receipt_bytes.len() as u64));
        values.push(Goldilocks::new(witness.verification_trace_bits.len() as u64));

        for idx in 0..MAX_RECEIPT_BYTES {
            let value = *witness.receipt_bytes.get(idx).unwrap_or(&0);
            values.push(Goldilocks::new(u64::from(value)));
        }

        for idx in 0..MAX_TRACE_BITS {
            let value = *witness.verification_trace_bits.get(idx).unwrap_or(&0);
            values.push(Goldilocks::new(u64::from(value)));
        }

        Ok(Assignment { witness: values })
    }
}

pub fn build_tx_proof_receipt(
    proof_bytes: &[u8],
    public_inputs: &[u8],
    verifier_profile: &[u8],
    verification_trace_bits: &[u8],
) -> Result<TxProofReceipt> {
    ensure!(
        !proof_bytes.is_empty(),
        "proof bytes must not be empty for receipt construction"
    );
    ensure!(
        !verifier_profile.is_empty(),
        "verifier profile must not be empty"
    );
    let tx_statement_digest = digest48_with_parts(
        b"hegemon.superneo.tx-statement.v1",
        &[public_inputs, verifier_profile],
    );
    let proof_digest = digest48(b"hegemon.superneo.proof-bytes.v1", proof_bytes);
    let verifier_profile_digest =
        digest48(b"hegemon.superneo.verifier-profile.v1", verifier_profile);
    let public_inputs_digest = digest48(b"hegemon.superneo.public-inputs.v1", public_inputs);
    let verification_trace_digest = digest48(
        b"hegemon.superneo.verification-trace.v1",
        verification_trace_bits,
    );

    Ok(TxProofReceipt {
        tx_statement_digest,
        proof_digest,
        verifier_profile_digest,
        public_inputs_digest,
        verification_trace_digest,
    })
}

fn transaction_verifying_key() -> &'static transaction_circuit::keys::VerifyingKey {
    static VERIFYING_KEY: OnceLock<transaction_circuit::keys::VerifyingKey> = OnceLock::new();
    VERIFYING_KEY.get_or_init(|| generate_keys().1)
}

fn serialize_fixed_bytes_48<S>(
    bytes: &[u8; 48],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

fn serialize_fixed_bytes_32<S>(
    bytes: &[u8; 32],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

fn deserialize_fixed_bytes_32<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::invalid_length(len, &"32 bytes"))
}

fn deserialize_fixed_bytes_48<'de, D>(deserializer: D) -> std::result::Result<[u8; 48], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::invalid_length(len, &"48 bytes"))
}

pub fn canonical_tx_validity_receipt_from_transaction_proof(
    proof: &TransactionProof,
) -> Result<CanonicalTxValidityReceipt> {
    Ok(CanonicalTxValidityReceipt {
        statement_hash: transaction_statement_hash(proof),
        proof_digest: transaction_proof_digest(proof),
        public_inputs_digest: transaction_public_inputs_digest(proof)
            .map_err(|err| anyhow::anyhow!("failed to derive tx public inputs digest: {err}"))?,
        verifier_profile: transaction_verifier_profile_digest(proof),
    })
}

pub fn native_tx_validity_statement_from_witness(
    witness: &TransactionWitness,
) -> Result<NativeTxValidityStatement> {
    witness
        .validate()
        .map_err(|err| anyhow::anyhow!("native tx witness validation failed: {err}"))?;
    validate_native_merkle_membership(witness)?;
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| anyhow::anyhow!("failed to derive native tx public inputs: {err}"))?;
    let serialized = serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    Ok(NativeTxValidityStatement {
        statement_hash: transaction_statement_hash_from_public_inputs(&public_inputs),
        public_inputs_digest: transaction_public_inputs_digest_from_serialized(&serialized)
            .map_err(|err| anyhow::anyhow!("failed to hash native tx public inputs: {err}"))?,
        verifier_profile: experimental_native_tx_verifier_profile(),
    })
}

pub fn tx_leaf_public_tx_from_transaction_proof(
    proof: &TransactionProof,
) -> Result<TxLeafPublicTx> {
    let stark_inputs = proof
        .stark_public_inputs
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("transaction proof is missing serialized STARK inputs"))?;
    let input_count = active_flag_count(&stark_inputs.input_flags)?;
    let output_count = active_flag_count(&stark_inputs.output_flags)?;
    ensure!(
        input_count <= proof.nullifiers.len(),
        "transaction proof input flags exceed nullifier vector"
    );
    ensure!(
        output_count <= proof.commitments.len()
            && output_count <= proof.public_inputs.ciphertext_hashes.len(),
        "transaction proof output flags exceed commitment/ciphertext vectors"
    );
    Ok(TxLeafPublicTx {
        nullifiers: proof.nullifiers[..input_count].to_vec(),
        commitments: proof.commitments[..output_count].to_vec(),
        ciphertext_hashes: proof.public_inputs.ciphertext_hashes[..output_count].to_vec(),
        balance_tag: proof.public_inputs.balance_tag,
        version: proof.version_binding(),
    })
}

pub fn tx_leaf_public_tx_from_witness(witness: &TransactionWitness) -> Result<TxLeafPublicTx> {
    witness
        .validate()
        .map_err(|err| anyhow::anyhow!("native tx witness validation failed: {err}"))?;
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| anyhow::anyhow!("failed to derive native tx public inputs: {err}"))?;
    Ok(TxLeafPublicTx {
        nullifiers: public_inputs.nullifiers[..witness.inputs.len()].to_vec(),
        commitments: public_inputs.commitments[..witness.outputs.len()].to_vec(),
        ciphertext_hashes: public_inputs.ciphertext_hashes[..witness.outputs.len()].to_vec(),
        balance_tag: public_inputs.balance_tag,
        version: witness.version,
    })
}

pub fn tx_leaf_public_witness_from_transaction_proof(
    proof: &TransactionProof,
) -> Result<TxLeafPublicWitness> {
    Ok(TxLeafPublicWitness {
        tx: tx_leaf_public_tx_from_transaction_proof(proof)?,
        stark_public_inputs: proof.stark_public_inputs.clone().ok_or_else(|| {
            anyhow::anyhow!("transaction proof is missing serialized STARK inputs")
        })?,
    })
}

pub fn tx_leaf_public_witness_from_parts(
    tx: &TxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
) -> TxLeafPublicWitness {
    TxLeafPublicWitness {
        tx: tx.clone(),
        stark_public_inputs: stark_public_inputs.clone(),
    }
}

fn stablecoin_binding_from_serialized(
    stark_public_inputs: &SerializedStarkInputs,
) -> Result<transaction_circuit::StablecoinPolicyBinding> {
    if stark_public_inputs.stablecoin_enabled == 0 {
        Ok(transaction_circuit::StablecoinPolicyBinding::default())
    } else {
        Ok(transaction_circuit::StablecoinPolicyBinding {
            enabled: true,
            asset_id: stark_public_inputs.stablecoin_asset_id,
            policy_hash: stark_public_inputs.stablecoin_policy_hash,
            oracle_commitment: stark_public_inputs.stablecoin_oracle_commitment,
            attestation_commitment: stark_public_inputs.stablecoin_attestation_commitment,
            issuance_delta: decode_signed_magnitude(
                stark_public_inputs.stablecoin_issuance_sign,
                stark_public_inputs.stablecoin_issuance_magnitude,
                "stablecoin_issuance",
            )?,
            policy_version: stark_public_inputs.stablecoin_policy_version,
        })
    }
}

fn native_witness_from_opening(
    tx: &TxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    opening: &NativeTxLeafOpening,
) -> Result<TransactionWitness> {
    ensure!(
        active_flag_count(&stark_public_inputs.input_flags)? == opening.inputs.len(),
        "native tx-leaf input opening length does not match active input flags"
    );
    ensure!(
        active_flag_count(&stark_public_inputs.output_flags)? == opening.outputs.len(),
        "native tx-leaf output opening length does not match active output flags"
    );
    ensure!(
        tx.commitments.len() == opening.outputs.len(),
        "native tx-leaf opening output length does not match tx commitments"
    );
    ensure!(
        tx.ciphertext_hashes.len() == opening.outputs.len(),
        "native tx-leaf opening output length does not match tx ciphertext hashes"
    );
    Ok(TransactionWitness {
        inputs: opening.inputs.clone(),
        outputs: opening.outputs.clone(),
        ciphertext_hashes: tx.ciphertext_hashes.clone(),
        sk_spend: opening.sk_spend,
        merkle_root: stark_public_inputs.merkle_root,
        fee: stark_public_inputs.fee,
        value_balance: decode_signed_magnitude(
            stark_public_inputs.value_balance_sign,
            stark_public_inputs.value_balance_magnitude,
            "value_balance",
        )?,
        stablecoin: stablecoin_binding_from_serialized(stark_public_inputs)?,
        version: tx.version,
    })
}

fn validate_native_merkle_membership(witness: &TransactionWitness) -> Result<()> {
    let root = bytes48_to_felts(&witness.merkle_root)
        .ok_or_else(|| anyhow::anyhow!("native tx merkle root is non-canonical"))?;
    for (index, input) in witness.inputs.iter().enumerate() {
        ensure!(
            input.merkle_path.siblings.len() == MERKLE_TREE_DEPTH,
            "native tx input {} merkle path has length {}, expected {}",
            index,
            input.merkle_path.siblings.len(),
            MERKLE_TREE_DEPTH
        );
        ensure!(
            input
                .merkle_path
                .verify(input.note.commitment(), input.position, root),
            "native tx input {} merkle path does not match root",
            index
        );
    }
    Ok(())
}

fn serialized_stark_inputs_from_witness(
    witness: &TransactionWitness,
    public_inputs: &TransactionPublicInputs,
) -> Result<SerializedStarkInputs> {
    ensure!(
        public_inputs.balance_slots.len() == BALANCE_SLOTS,
        "native tx public inputs balance slot count {} does not match {}",
        public_inputs.balance_slots.len(),
        BALANCE_SLOTS
    );
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

fn transaction_statement_hash_from_public_inputs(
    public_inputs: &TransactionPublicInputs,
) -> [u8; 48] {
    let mut message = Vec::new();
    message.extend_from_slice(transaction_circuit::proof::TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&public_inputs.merkle_root);
    for nf in &public_inputs.nullifiers {
        message.extend_from_slice(nf);
    }
    for cm in &public_inputs.commitments {
        message.extend_from_slice(cm);
    }
    for ct in &public_inputs.ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    message.extend_from_slice(&public_inputs.native_fee.to_le_bytes());
    message.extend_from_slice(&public_inputs.value_balance.to_le_bytes());
    message.extend_from_slice(&public_inputs.balance_tag);
    message.extend_from_slice(&public_inputs.circuit_version.to_le_bytes());
    message.extend_from_slice(&public_inputs.crypto_suite.to_le_bytes());
    message.push(public_inputs.stablecoin.enabled as u8);
    message.extend_from_slice(&public_inputs.stablecoin.asset_id.to_le_bytes());
    message.extend_from_slice(&public_inputs.stablecoin.policy_hash);
    message.extend_from_slice(&public_inputs.stablecoin.oracle_commitment);
    message.extend_from_slice(&public_inputs.stablecoin.attestation_commitment);
    message.extend_from_slice(&public_inputs.stablecoin.issuance_delta.to_le_bytes());
    message.extend_from_slice(&public_inputs.stablecoin.policy_version.to_le_bytes());
    blake3_384_bytes(&message)
}

fn validate_native_tx_witness(
    statement: &NativeTxValidityStatement,
    witness: &TransactionWitness,
) -> Result<()> {
    let expected = native_tx_validity_statement_from_witness(witness)?;
    ensure!(
        expected == *statement,
        "native tx validity statement mismatch"
    );
    Ok(())
}

fn native_tx_witness_assignment(witness: &TransactionWitness) -> Result<Assignment<Goldilocks>> {
    witness
        .validate()
        .map_err(|err| anyhow::anyhow!("native tx witness validation failed: {err}"))?;
    validate_native_merkle_membership(witness)?;
    let mut values = Vec::with_capacity(
        NativeTxValidityRelation::default()
            .shape
            .expected_witness_len(),
    );
    let (value_balance_sign, value_balance_magnitude) =
        signed_magnitude_u64(witness.value_balance, "value_balance")?;
    let (stablecoin_issuance_sign, stablecoin_issuance_magnitude) =
        signed_magnitude_u64(witness.stablecoin.issuance_delta, "stablecoin_issuance")?;

    values.push(Goldilocks::new(witness.inputs.len() as u64));
    values.push(Goldilocks::new(witness.outputs.len() as u64));
    values.push(Goldilocks::new(witness.ciphertext_hashes.len() as u64));
    push_bytes32(&mut values, &witness.sk_spend);
    push_bytes48_bytes(&mut values, &witness.merkle_root);
    values.push(Goldilocks::new(witness.fee));
    values.push(Goldilocks::new(u64::from(value_balance_sign)));
    values.push(Goldilocks::new(value_balance_magnitude));
    values.push(Goldilocks::new(u64::from(witness.stablecoin.enabled)));
    values.push(Goldilocks::new(witness.stablecoin.asset_id));
    push_bytes48_bytes(&mut values, &witness.stablecoin.policy_hash);
    push_bytes48_bytes(&mut values, &witness.stablecoin.oracle_commitment);
    push_bytes48_bytes(&mut values, &witness.stablecoin.attestation_commitment);
    values.push(Goldilocks::new(u64::from(stablecoin_issuance_sign)));
    values.push(Goldilocks::new(stablecoin_issuance_magnitude));
    values.push(Goldilocks::new(u64::from(
        witness.stablecoin.policy_version,
    )));
    values.push(Goldilocks::new(u64::from(witness.version.circuit)));
    values.push(Goldilocks::new(u64::from(witness.version.crypto)));

    push_padded_input_note_fields(&mut values, &witness.inputs)?;
    push_padded_output_note_fields(&mut values, &witness.outputs)?;
    push_padded_ciphertext_hashes(&mut values, &witness.ciphertext_hashes)?;

    Ok(Assignment { witness: values })
}

fn validate_tx_leaf_public_witness(
    statement: &CanonicalTxValidityReceipt,
    witness: &TxLeafPublicWitness,
) -> Result<()> {
    ensure!(
        witness.tx.nullifiers.len() <= MAX_INPUTS,
        "tx-leaf witness nullifier length {} exceeds {}",
        witness.tx.nullifiers.len(),
        MAX_INPUTS
    );
    ensure!(
        witness.tx.commitments.len() <= MAX_OUTPUTS,
        "tx-leaf witness commitment length {} exceeds {}",
        witness.tx.commitments.len(),
        MAX_OUTPUTS
    );
    ensure!(
        witness.tx.ciphertext_hashes.len() <= MAX_OUTPUTS,
        "tx-leaf witness ciphertext-hash length {} exceeds {}",
        witness.tx.ciphertext_hashes.len(),
        MAX_OUTPUTS
    );
    ensure!(
        witness.stark_public_inputs.input_flags.len() <= MAX_INPUTS,
        "tx-leaf witness input flag length {} exceeds {}",
        witness.stark_public_inputs.input_flags.len(),
        MAX_INPUTS
    );
    ensure!(
        witness.stark_public_inputs.output_flags.len() <= MAX_OUTPUTS,
        "tx-leaf witness output flag length {} exceeds {}",
        witness.stark_public_inputs.output_flags.len(),
        MAX_OUTPUTS
    );
    ensure!(
        witness.stark_public_inputs.balance_slot_asset_ids.len() <= BALANCE_SLOTS,
        "tx-leaf witness balance slot asset length {} exceeds {}",
        witness.stark_public_inputs.balance_slot_asset_ids.len(),
        BALANCE_SLOTS
    );
    ensure!(
        witness
            .stark_public_inputs
            .input_flags
            .iter()
            .all(|flag| *flag <= 1),
        "tx-leaf input flags must be binary"
    );
    ensure!(
        witness
            .stark_public_inputs
            .output_flags
            .iter()
            .all(|flag| *flag <= 1),
        "tx-leaf output flags must be binary"
    );
    ensure!(
        witness.stark_public_inputs.value_balance_sign <= 1,
        "tx-leaf value_balance_sign must be binary"
    );
    ensure!(
        witness.stark_public_inputs.stablecoin_enabled <= 1,
        "tx-leaf stablecoin_enabled must be binary"
    );
    ensure!(
        witness.stark_public_inputs.stablecoin_issuance_sign <= 1,
        "tx-leaf stablecoin_issuance_sign must be binary"
    );
    ensure!(
        active_flag_count(&witness.stark_public_inputs.input_flags)? == witness.tx.nullifiers.len(),
        "tx-leaf nullifier list length does not match active input flags"
    );
    ensure!(
        active_flag_count(&witness.stark_public_inputs.output_flags)?
            == witness.tx.commitments.len()
            && active_flag_count(&witness.stark_public_inputs.output_flags)?
                == witness.tx.ciphertext_hashes.len(),
        "tx-leaf output lists do not match active output flags"
    );

    let expected_statement_hash =
        tx_statement_hash_from_tx_leaf_public(&witness.tx, &witness.stark_public_inputs)?;
    ensure!(
        expected_statement_hash == statement.statement_hash,
        "tx-leaf statement hash mismatch"
    );
    let expected_public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(&witness.stark_public_inputs)
            .map_err(|err| anyhow::anyhow!("failed to hash tx-leaf public inputs: {err}"))?;
    ensure!(
        expected_public_inputs_digest == statement.public_inputs_digest,
        "tx-leaf public inputs digest mismatch"
    );
    let expected_verifier_profile =
        transaction_verifier_profile_digest_for_version(witness.tx.version);
    ensure!(
        expected_verifier_profile == statement.verifier_profile,
        "tx-leaf verifier profile mismatch"
    );
    Ok(())
}

fn tx_leaf_public_witness_assignment(
    witness: &TxLeafPublicWitness,
) -> Result<Assignment<Goldilocks>> {
    let mut values =
        Vec::with_capacity(TxLeafPublicRelation::default().shape.expected_witness_len());
    values.push(Goldilocks::new(
        witness.stark_public_inputs.input_flags.len() as u64,
    ));
    values.push(Goldilocks::new(
        witness.stark_public_inputs.output_flags.len() as u64,
    ));
    push_padded_bits(
        &mut values,
        &witness.stark_public_inputs.input_flags,
        MAX_INPUTS,
        "input flags",
    )?;
    push_padded_bits(
        &mut values,
        &witness.stark_public_inputs.output_flags,
        MAX_OUTPUTS,
        "output flags",
    )?;
    values.push(Goldilocks::new(witness.stark_public_inputs.fee));
    values.push(Goldilocks::new(u64::from(
        witness.stark_public_inputs.value_balance_sign,
    )));
    values.push(Goldilocks::new(
        witness.stark_public_inputs.value_balance_magnitude,
    ));
    push_bytes48_limbs(&mut values, &witness.stark_public_inputs.merkle_root);
    values.push(Goldilocks::new(
        witness.stark_public_inputs.balance_slot_asset_ids.len() as u64,
    ));
    push_padded_u64s(
        &mut values,
        &witness.stark_public_inputs.balance_slot_asset_ids,
        BALANCE_SLOTS,
    );
    values.push(Goldilocks::new(u64::from(
        witness.stark_public_inputs.stablecoin_enabled,
    )));
    values.push(Goldilocks::new(
        witness.stark_public_inputs.stablecoin_asset_id,
    ));
    values.push(Goldilocks::new(u64::from(
        witness.stark_public_inputs.stablecoin_policy_version,
    )));
    values.push(Goldilocks::new(u64::from(
        witness.stark_public_inputs.stablecoin_issuance_sign,
    )));
    values.push(Goldilocks::new(
        witness.stark_public_inputs.stablecoin_issuance_magnitude,
    ));
    push_bytes48_limbs(
        &mut values,
        &witness.stark_public_inputs.stablecoin_policy_hash,
    );
    push_bytes48_limbs(
        &mut values,
        &witness.stark_public_inputs.stablecoin_oracle_commitment,
    );
    push_bytes48_limbs(
        &mut values,
        &witness
            .stark_public_inputs
            .stablecoin_attestation_commitment,
    );
    values.push(Goldilocks::new(witness.tx.nullifiers.len() as u64));
    push_padded_digest_vec(&mut values, &witness.tx.nullifiers, MAX_INPUTS);
    values.push(Goldilocks::new(witness.tx.commitments.len() as u64));
    push_padded_digest_vec(&mut values, &witness.tx.commitments, MAX_OUTPUTS);
    values.push(Goldilocks::new(witness.tx.ciphertext_hashes.len() as u64));
    push_padded_digest_vec(&mut values, &witness.tx.ciphertext_hashes, MAX_OUTPUTS);
    push_bytes48_limbs(&mut values, &witness.tx.balance_tag);
    values.push(Goldilocks::new(u64::from(witness.tx.version.circuit)));
    values.push(Goldilocks::new(u64::from(witness.tx.version.crypto)));
    Ok(Assignment { witness: values })
}

fn decode_signed_magnitude(sign: u8, magnitude: u64, label: &str) -> Result<i128> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        other => Err(anyhow::anyhow!(
            "{label} sign flag must be 0 or 1, got {other}"
        )),
    }
}

fn tx_statement_hash_from_tx_leaf_public(
    tx: &TxLeafPublicTx,
    stark_inputs: &SerializedStarkInputs,
) -> Result<[u8; 48]> {
    let mut message = Vec::new();
    message.extend_from_slice(transaction_circuit::proof::TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&stark_inputs.merkle_root);
    extend_padded_digests(&mut message, &tx.nullifiers, MAX_INPUTS)?;
    extend_padded_digests(&mut message, &tx.commitments, MAX_OUTPUTS)?;
    extend_padded_digests(&mut message, &tx.ciphertext_hashes, MAX_OUTPUTS)?;
    let value_balance = decode_signed_magnitude(
        stark_inputs.value_balance_sign,
        stark_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let stablecoin_issuance = decode_signed_magnitude(
        stark_inputs.stablecoin_issuance_sign,
        stark_inputs.stablecoin_issuance_magnitude,
        "stablecoin_issuance",
    )?;
    message.extend_from_slice(&stark_inputs.fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(&tx.balance_tag);
    message.extend_from_slice(&tx.version.circuit.to_le_bytes());
    message.extend_from_slice(&tx.version.crypto.to_le_bytes());
    message.push(stark_inputs.stablecoin_enabled);
    message.extend_from_slice(&stark_inputs.stablecoin_asset_id.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_hash);
    message.extend_from_slice(&stark_inputs.stablecoin_oracle_commitment);
    message.extend_from_slice(&stark_inputs.stablecoin_attestation_commitment);
    message.extend_from_slice(&stablecoin_issuance.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_version.to_le_bytes());
    Ok(blake3_384_bytes(&message))
}

fn active_flag_count(flags: &[u8]) -> Result<usize> {
    ensure!(flags.iter().all(|flag| *flag <= 1), "flags must be binary");
    Ok(flags.iter().filter(|flag| **flag == 1).count())
}

fn push_padded_bits(
    out: &mut Vec<Goldilocks>,
    values: &[u8],
    target: usize,
    label: &str,
) -> Result<()> {
    ensure!(
        values.len() <= target,
        "{label} length {} exceeds {target}",
        values.len()
    );
    ensure!(
        values.iter().all(|value| *value <= 1),
        "{label} must be binary"
    );
    for idx in 0..target {
        out.push(Goldilocks::new(u64::from(*values.get(idx).unwrap_or(&0))));
    }
    Ok(())
}

fn push_padded_u64s(out: &mut Vec<Goldilocks>, values: &[u64], target: usize) {
    for idx in 0..target {
        out.push(Goldilocks::new(*values.get(idx).unwrap_or(&0)));
    }
}

fn push_bytes48_limbs(out: &mut Vec<Goldilocks>, bytes: &[u8; 48]) {
    out.extend(bytes48_to_goldilocks(bytes));
}

fn push_padded_digest_vec(out: &mut Vec<Goldilocks>, values: &[[u8; 48]], target: usize) {
    for idx in 0..target {
        let digest = values.get(idx).copied().unwrap_or([0u8; 48]);
        push_bytes48_limbs(out, &digest);
    }
}

fn extend_padded_digests(bytes: &mut Vec<u8>, values: &[[u8; 48]], target: usize) -> Result<()> {
    ensure!(
        values.len() <= target,
        "digest vector length {} exceeds {}",
        values.len(),
        target
    );
    for value in values {
        bytes.extend_from_slice(value);
    }
    for _ in values.len()..target {
        bytes.extend_from_slice(&[0u8; 48]);
    }
    Ok(())
}

fn signed_magnitude_u64(value: i128, label: &str) -> Result<(u8, u64)> {
    let sign = u8::from(value < 0);
    let magnitude = value.unsigned_abs();
    ensure!(
        magnitude <= u128::from(u64::MAX),
        "{label} magnitude {} exceeds u64::MAX",
        magnitude
    );
    Ok((sign, magnitude as u64))
}

fn push_bytes32(out: &mut Vec<Goldilocks>, bytes: &[u8; 32]) {
    out.extend(bytes.iter().map(|byte| Goldilocks::new(u64::from(*byte))));
}

fn push_bytes48_bytes(out: &mut Vec<Goldilocks>, bytes: &[u8; 48]) {
    out.extend(bytes.iter().map(|byte| Goldilocks::new(u64::from(*byte))));
}

fn push_note_bytes(out: &mut Vec<Goldilocks>, note: &transaction_circuit::note::NoteData) {
    out.push(Goldilocks::new(note.value));
    out.push(Goldilocks::new(note.asset_id));
    push_bytes32(out, &note.pk_recipient);
    push_bytes32(out, &note.pk_auth);
    push_bytes32(out, &note.rho);
    push_bytes32(out, &note.r);
}

fn push_zero_note_bytes(out: &mut Vec<Goldilocks>) {
    out.push(Goldilocks::new(0));
    out.push(Goldilocks::new(0));
    out.extend(std::iter::repeat_n(Goldilocks::new(0), 32 * 4));
}

fn push_padded_input_note_fields(
    out: &mut Vec<Goldilocks>,
    inputs: &[InputNoteWitness],
) -> Result<()> {
    ensure!(
        inputs.len() <= MAX_INPUTS,
        "native tx input count {} exceeds {}",
        inputs.len(),
        MAX_INPUTS
    );
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_note_bytes(out, &input.note);
        } else {
            push_zero_note_bytes(out);
        }
    }
    for idx in 0..MAX_INPUTS {
        out.push(Goldilocks::new(
            inputs.get(idx).map(|input| input.position).unwrap_or(0),
        ));
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32(out, &input.rho_seed);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            ensure!(
                input.merkle_path.siblings.len() == MERKLE_TREE_DEPTH,
                "native tx input {} merkle path has length {}, expected {}",
                idx,
                input.merkle_path.siblings.len(),
                MERKLE_TREE_DEPTH
            );
            for sibling in &input.merkle_path.siblings {
                let bytes = felts_to_bytes48(sibling);
                push_bytes48_bytes(out, &bytes);
            }
        } else {
            out.extend(std::iter::repeat_n(
                Goldilocks::new(0),
                MERKLE_TREE_DEPTH * 48,
            ));
        }
    }
    Ok(())
}

fn push_padded_output_note_fields(
    out: &mut Vec<Goldilocks>,
    outputs: &[OutputNoteWitness],
) -> Result<()> {
    ensure!(
        outputs.len() <= MAX_OUTPUTS,
        "native tx output count {} exceeds {}",
        outputs.len(),
        MAX_OUTPUTS
    );
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_note_bytes(out, &output.note);
        } else {
            push_zero_note_bytes(out);
        }
    }
    Ok(())
}

fn push_padded_ciphertext_hashes(
    out: &mut Vec<Goldilocks>,
    ciphertext_hashes: &[[u8; 48]],
) -> Result<()> {
    ensure!(
        ciphertext_hashes.len() <= MAX_OUTPUTS,
        "native tx ciphertext hash count {} exceeds {}",
        ciphertext_hashes.len(),
        MAX_OUTPUTS
    );
    for idx in 0..MAX_OUTPUTS {
        let bytes = ciphertext_hashes.get(idx).copied().unwrap_or([0u8; 48]);
        push_bytes48_bytes(out, &bytes);
    }
    Ok(())
}

pub fn experimental_receipt_root_verifier_profile() -> [u8; 48] {
    let relation = CanonicalTxValidityReceiptRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental receipt-root setup must succeed");
    let mut material = Vec::with_capacity(32 + 32 + 32 + 32);
    material.extend_from_slice(b"hegemon.superneo.receipt-root-profile.v1");
    material.extend_from_slice(&relation.relation_id().0);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    digest48(
        b"hegemon.superneo.receipt-root-profile.digest.v1",
        &material,
    )
}

pub fn experimental_tx_leaf_verifier_profile() -> [u8; 48] {
    let relation = TxLeafPublicRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental tx-leaf setup must succeed");
    let mut material = Vec::with_capacity(32 + 32 + 32 + 32);
    material.extend_from_slice(b"hegemon.superneo.tx-leaf-profile.v1");
    material.extend_from_slice(&relation.relation_id().0);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    digest48(b"hegemon.superneo.tx-leaf-profile.digest.v1", &material)
}

pub fn experimental_native_tx_leaf_verifier_profile() -> [u8; 48] {
    let relation = NativeTxValidityRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental native tx-leaf setup must succeed");
    let mut material = Vec::with_capacity(32 + 32 + 32 + 32);
    material.extend_from_slice(b"hegemon.superneo.native-tx-leaf-profile.v1");
    material.extend_from_slice(&relation.relation_id().0);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    digest48(
        b"hegemon.superneo.native-tx-leaf-profile.digest.v1",
        &material,
    )
}

pub fn experimental_native_tx_verifier_profile() -> [u8; 48] {
    let relation = NativeTxValidityRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental native tx setup must succeed");
    let mut material = Vec::with_capacity(32 + 32 + 32 + 32);
    material.extend_from_slice(b"hegemon.superneo.native-tx-profile.v1");
    material.extend_from_slice(&relation.relation_id().0);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    digest48(b"hegemon.superneo.native-tx-profile.digest.v1", &material)
}

pub fn experimental_native_receipt_root_verifier_profile() -> [u8; 48] {
    let relation = NativeTxValidityRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental native receipt-root setup must succeed");
    let mut material = Vec::with_capacity(32 + 32 + 32 + 32);
    material.extend_from_slice(b"hegemon.superneo.native-receipt-root-profile.v1");
    material.extend_from_slice(&relation.relation_id().0);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    digest48(
        b"hegemon.superneo.native-receipt-root-profile.digest.v1",
        &material,
    )
}

pub fn build_tx_leaf_artifact_bytes(proof: &TransactionProof) -> Result<BuiltTxLeafArtifact> {
    let relation = TxLeafPublicRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, _) = backend.setup(&security, relation.shape())?;

    verify_transaction_proof(proof, transaction_verifying_key())
        .map_err(|err| anyhow::anyhow!("transaction proof verification failed: {err}"))?;
    let receipt = canonical_tx_validity_receipt_from_transaction_proof(proof)?;
    let witness = tx_leaf_public_witness_from_transaction_proof(proof)?;
    let encoding = relation.encode_statement(&receipt)?;
    let assignment = relation.build_assignment(&receipt, &witness)?;
    let packed = packer.pack(relation.shape(), &assignment)?;
    let commitment = backend.commit_witness(&pk, &packed)?;
    let leaf_proof = backend.prove_leaf(
        &pk,
        &relation.relation_id(),
        &encoding,
        &packed,
        &commitment,
    )?;
    let artifact = TxLeafArtifact {
        version: TX_LEAF_ARTIFACT_VERSION,
        relation_id: relation.relation_id().0,
        shape_digest: pk.shape_digest.0,
        statement_digest: encoding.statement_digest.0,
        stark_public_inputs: witness.stark_public_inputs,
        leaf: LeafArtifact {
            version: TX_LEAF_ARTIFACT_VERSION,
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: leaf_proof,
        },
    };
    Ok(BuiltTxLeafArtifact {
        artifact_bytes: bincode::serialize(&artifact)
            .map_err(|err| anyhow::anyhow!("failed to encode tx-leaf artifact: {err}"))?,
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        statement_digest: artifact.statement_digest,
    })
}

pub fn build_native_tx_leaf_artifact_bytes(
    witness: &TransactionWitness,
) -> Result<BuiltNativeTxLeafArtifact> {
    let relation = NativeTxValidityRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, _) = backend.setup(&security, relation.shape())?;

    let statement = native_tx_validity_statement_from_witness(witness)?;
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| anyhow::anyhow!("failed to derive native tx public inputs: {err}"))?;
    let stark_public_inputs = serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    let encoding = relation.encode_statement(&statement)?;
    let assignment = relation.build_assignment(&statement, witness)?;
    let packed = packer.pack(relation.shape(), &assignment)?;
    let commitment = backend.commit_witness(&pk, &packed)?;
    let leaf_proof = backend.prove_leaf(
        &pk,
        &relation.relation_id(),
        &encoding,
        &packed,
        &commitment,
    )?;
    let receipt = CanonicalTxValidityReceipt {
        statement_hash: statement.statement_hash,
        proof_digest: leaf_proof.proof_digest,
        public_inputs_digest: statement.public_inputs_digest,
        verifier_profile: experimental_native_tx_leaf_verifier_profile(),
    };
    let artifact = NativeTxLeafArtifact {
        version: NATIVE_TX_LEAF_ARTIFACT_VERSION,
        relation_id: relation.relation_id().0,
        shape_digest: pk.shape_digest.0,
        statement_digest: encoding.statement_digest.0,
        receipt: receipt.clone(),
        stark_public_inputs,
        opening: NativeTxLeafOpening {
            sk_spend: witness.sk_spend,
            inputs: witness.inputs.clone(),
            outputs: witness.outputs.clone(),
        },
        commitment: commitment.clone(),
        leaf: LeafArtifact {
            version: NATIVE_TX_LEAF_ARTIFACT_VERSION,
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            proof: leaf_proof,
        },
    };
    Ok(BuiltNativeTxLeafArtifact {
        artifact_bytes: encode_native_tx_leaf_artifact(&artifact)?,
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        statement_digest: artifact.statement_digest,
        receipt,
    })
}

pub fn decode_tx_leaf_artifact_bytes(artifact_bytes: &[u8]) -> Result<TxLeafArtifact> {
    bincode::deserialize(artifact_bytes)
        .map_err(|err| anyhow::anyhow!("failed to decode tx-leaf artifact: {err}"))
}

pub fn decode_native_tx_leaf_artifact_bytes(artifact_bytes: &[u8]) -> Result<NativeTxLeafArtifact> {
    decode_native_tx_leaf_artifact(artifact_bytes)
}

pub fn verify_tx_leaf_artifact_bytes(
    tx: &TxLeafPublicTx,
    receipt: &CanonicalTxValidityReceipt,
    artifact_bytes: &[u8],
) -> Result<TxLeafMetadata> {
    let artifact = decode_tx_leaf_artifact_bytes(artifact_bytes)?;
    ensure!(
        artifact.version == TX_LEAF_ARTIFACT_VERSION,
        "unsupported tx-leaf artifact version {}",
        artifact.version
    );

    let relation = TxLeafPublicRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "tx-leaf relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "tx-leaf shape digest mismatch"
    );
    ensure!(
        artifact.leaf.version == TX_LEAF_ARTIFACT_VERSION,
        "tx-leaf inner proof version mismatch"
    );
    ensure!(
        artifact.leaf.relation_id == relation.relation_id(),
        "tx-leaf inner relation id mismatch"
    );
    ensure!(
        artifact.leaf.shape_digest == pk.shape_digest,
        "tx-leaf inner shape digest mismatch"
    );
    let witness = tx_leaf_public_witness_from_parts(tx, &artifact.stark_public_inputs);
    let encoding = relation.encode_statement(receipt)?;
    let assignment = relation.build_assignment(receipt, &witness)?;
    let packed = packer.pack(relation.shape(), &assignment)?;
    ensure!(
        artifact.statement_digest == encoding.statement_digest.0,
        "tx-leaf statement digest mismatch"
    );
    ensure!(
        artifact.leaf.statement_digest == encoding.statement_digest,
        "tx-leaf inner statement digest mismatch"
    );
    backend.verify_leaf(
        &vk,
        &relation.relation_id(),
        &encoding,
        &packed,
        &artifact.leaf.proof,
    )?;
    Ok(TxLeafMetadata {
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        statement_digest: artifact.statement_digest,
        stark_public_inputs: artifact.stark_public_inputs,
    })
}

pub fn verify_native_tx_leaf_artifact_bytes(
    tx: &TxLeafPublicTx,
    receipt: &CanonicalTxValidityReceipt,
    artifact_bytes: &[u8],
) -> Result<NativeTxLeafMetadata> {
    let artifact = decode_native_tx_leaf_artifact_bytes(artifact_bytes)?;
    ensure!(
        artifact.version == NATIVE_TX_LEAF_ARTIFACT_VERSION,
        "unsupported native tx-leaf artifact version {}",
        artifact.version
    );

    let relation = NativeTxValidityRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "native tx-leaf relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "native tx-leaf shape digest mismatch"
    );
    ensure!(
        artifact.leaf.version == NATIVE_TX_LEAF_ARTIFACT_VERSION,
        "native tx-leaf inner proof version mismatch"
    );
    ensure!(
        artifact.leaf.relation_id == relation.relation_id(),
        "native tx-leaf inner relation id mismatch"
    );
    ensure!(
        artifact.leaf.shape_digest == pk.shape_digest,
        "native tx-leaf inner shape digest mismatch"
    );
    ensure!(
        artifact.receipt == *receipt,
        "native tx-leaf canonical receipt mismatch"
    );
    ensure!(
        receipt.verifier_profile == experimental_native_tx_leaf_verifier_profile(),
        "native tx-leaf receipt verifier profile mismatch"
    );

    let witness =
        native_witness_from_opening(tx, &artifact.stark_public_inputs, &artifact.opening)?;
    let statement = native_tx_validity_statement_from_witness(&witness)?;
    ensure!(
        statement.statement_hash == receipt.statement_hash,
        "native tx-leaf statement hash mismatch"
    );
    ensure!(
        statement.public_inputs_digest == receipt.public_inputs_digest,
        "native tx-leaf public inputs digest mismatch"
    );
    let encoding = relation.encode_statement(&statement)?;
    let assignment = relation.build_assignment(&statement, &witness)?;
    let packed = packer.pack(relation.shape(), &assignment)?;
    let expected_commitment = backend.commit_witness(&pk, &packed)?;
    ensure!(
        artifact.commitment.digest == expected_commitment.digest,
        "native tx-leaf commitment digest mismatch"
    );
    ensure!(
        artifact.commitment.rows == expected_commitment.rows,
        "native tx-leaf commitment rows mismatch"
    );
    ensure!(
        artifact.statement_digest == encoding.statement_digest.0,
        "native tx-leaf statement digest mismatch"
    );
    ensure!(
        artifact.leaf.statement_digest == encoding.statement_digest,
        "native tx-leaf inner statement digest mismatch"
    );
    backend.verify_leaf(
        &vk,
        &relation.relation_id(),
        &encoding,
        &packed,
        &artifact.leaf.proof,
    )?;
    ensure!(
        artifact.leaf.proof.witness_commitment_digest == artifact.commitment.digest,
        "native tx-leaf proof/commitment digest mismatch"
    );
    ensure!(
        artifact.leaf.proof.proof_digest == receipt.proof_digest,
        "native tx-leaf proof digest mismatch"
    );
    Ok(NativeTxLeafMetadata {
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        statement_digest: artifact.statement_digest,
        stark_public_inputs: artifact.stark_public_inputs,
        commitment: artifact.commitment,
    })
}

pub fn build_native_tx_leaf_receipt_root_artifact_bytes(
    artifacts: &[NativeTxLeafArtifact],
) -> Result<BuiltReceiptRootArtifact> {
    ensure!(
        !artifacts.is_empty(),
        "native receipt-root artifact requires at least one tx-leaf artifact"
    );

    let relation = NativeTxValidityRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let (pk, _) = backend.setup(&security, relation.shape())?;

    let mut leaves = Vec::with_capacity(artifacts.len());
    let mut current = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        ensure!(
            artifact.version == NATIVE_TX_LEAF_ARTIFACT_VERSION,
            "native tx-leaf artifact version mismatch"
        );
        ensure!(
            artifact.relation_id == relation.relation_id().0,
            "native tx-leaf relation id mismatch"
        );
        ensure!(
            artifact.shape_digest == pk.shape_digest.0,
            "native tx-leaf shape digest mismatch"
        );
        ensure!(
            artifact.leaf.relation_id == relation.relation_id(),
            "native tx-leaf inner relation id mismatch"
        );
        ensure!(
            artifact.leaf.shape_digest == pk.shape_digest,
            "native tx-leaf inner shape digest mismatch"
        );
        ensure!(
            artifact.leaf.proof.witness_commitment_digest == artifact.commitment.digest,
            "native tx-leaf proof/commitment mismatch"
        );
        leaves.push(ReceiptRootLeaf {
            statement_digest: artifact.statement_digest,
            witness_commitment: artifact.commitment.digest,
            proof_digest: artifact.leaf.proof.proof_digest,
        });
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: artifact.leaf.statement_digest,
            witness_commitment: artifact.commitment.clone(),
        });
    }

    let mut folds = Vec::new();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                folds.push(ReceiptRootFoldStep {
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    left_statement_digest: left.statement_digest.0,
                    left_commitment: left.witness_commitment.digest,
                    right_statement_digest: right.statement_digest.0,
                    right_commitment: right.witness_commitment.digest,
                    proof_digest: proof.proof_digest,
                });
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    let root = current
        .pop()
        .expect("non-empty native receipt-root leaf set");
    let artifact = ReceiptRootArtifact {
        version: RECEIPT_ROOT_ARTIFACT_VERSION,
        relation_id: relation.relation_id().0,
        shape_digest: pk.shape_digest.0,
        leaves,
        folds: folds.clone(),
        root_statement_digest: root.statement_digest.0,
        root_commitment: root.witness_commitment.digest,
    };
    Ok(BuiltReceiptRootArtifact {
        artifact_bytes: encode_receipt_root_artifact(&artifact),
        metadata: ReceiptRootMetadata {
            relation_id: artifact.relation_id,
            shape_digest: artifact.shape_digest,
            leaf_count: artifact.leaves.len() as u32,
            fold_count: folds.len() as u32,
        },
    })
}

pub fn verify_native_tx_leaf_receipt_root_artifact_bytes(
    artifacts: &[NativeTxLeafArtifact],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata> {
    ensure!(
        !artifacts.is_empty(),
        "native receipt-root artifact requires at least one tx-leaf artifact"
    );
    let artifact = decode_receipt_root_artifact(artifact_bytes)?;
    ensure!(
        artifact.version == RECEIPT_ROOT_ARTIFACT_VERSION,
        "unsupported receipt-root artifact version {}",
        artifact.version
    );

    let relation = NativeTxValidityRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "native receipt-root relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "native receipt-root shape digest mismatch"
    );
    ensure!(
        artifact.leaves.len() == artifacts.len(),
        "native receipt-root leaf count {} does not match tx-leaf artifacts {}",
        artifact.leaves.len(),
        artifacts.len()
    );

    let mut current = Vec::with_capacity(artifacts.len());
    for (native_artifact, leaf) in artifacts.iter().zip(&artifact.leaves) {
        ensure!(
            native_artifact.version == NATIVE_TX_LEAF_ARTIFACT_VERSION,
            "native tx-leaf artifact version mismatch"
        );
        ensure!(
            leaf.statement_digest == native_artifact.statement_digest,
            "native receipt-root leaf statement digest mismatch"
        );
        ensure!(
            leaf.witness_commitment == native_artifact.commitment.digest,
            "native receipt-root leaf commitment mismatch"
        );
        ensure!(
            leaf.proof_digest == native_artifact.leaf.proof.proof_digest,
            "native receipt-root leaf proof digest mismatch"
        );
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: native_artifact.leaf.statement_digest,
            witness_commitment: native_artifact.commitment.clone(),
        });
    }

    let mut fold_index = 0usize;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let fold = artifact
                    .folds
                    .get(fold_index)
                    .ok_or_else(|| anyhow::anyhow!("native receipt-root fold list ended early"))?;
                fold_index += 1;
                ensure!(
                    fold.left_statement_digest == left.statement_digest.0
                        && fold.left_commitment == left.witness_commitment.digest,
                    "native receipt-root fold left child mismatch"
                );
                ensure!(
                    fold.right_statement_digest == right.statement_digest.0
                        && fold.right_commitment == right.witness_commitment.digest,
                    "native receipt-root fold right child mismatch"
                );
                let (parent, expected_proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "native receipt-root fold parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "native receipt-root fold parent commitment mismatch"
                );
                ensure!(
                    fold.proof_digest == expected_proof.proof_digest,
                    "native receipt-root fold proof digest mismatch"
                );
                backend.verify_fold(&vk, &parent, &left, &right, &expected_proof)?;
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    ensure!(
        fold_index == artifact.folds.len(),
        "native receipt-root artifact has {} unused fold steps",
        artifact.folds.len().saturating_sub(fold_index)
    );
    let root = current
        .pop()
        .expect("native receipt-root verifier must retain one root");
    ensure!(
        artifact.root_statement_digest == root.statement_digest.0,
        "native receipt-root root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == root.witness_commitment.digest,
        "native receipt-root root commitment mismatch"
    );

    Ok(ReceiptRootMetadata {
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        leaf_count: artifact.leaves.len() as u32,
        fold_count: artifact.folds.len() as u32,
    })
}

pub fn build_verified_tx_proof_receipt_root_artifact_bytes(
    proofs: &[TransactionProof],
) -> Result<BuiltReceiptRootArtifact> {
    ensure!(
        !proofs.is_empty(),
        "receipt-root artifact requires at least one transaction proof"
    );

    let relation = TxLeafPublicRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, _) = backend.setup(&security, relation.shape())?;

    let mut leaves = Vec::with_capacity(proofs.len());
    let mut current = Vec::with_capacity(proofs.len());
    for proof in proofs {
        verify_transaction_proof(proof, transaction_verifying_key())
            .map_err(|err| anyhow::anyhow!("transaction proof verification failed: {err}"))?;
        let statement = canonical_tx_validity_receipt_from_transaction_proof(proof)?;
        let witness = tx_leaf_public_witness_from_transaction_proof(proof)?;
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, &witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        let commitment = backend.commit_witness(&pk, &packed)?;
        let leaf_proof = backend.prove_leaf(
            &pk,
            &relation.relation_id(),
            &encoding,
            &packed,
            &commitment,
        )?;
        leaves.push(ReceiptRootLeaf {
            statement_digest: encoding.statement_digest.0,
            witness_commitment: commitment.digest,
            proof_digest: leaf_proof.proof_digest,
        });
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: commitment,
        });
    }

    let mut folds = Vec::new();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                folds.push(ReceiptRootFoldStep {
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    left_statement_digest: left.statement_digest.0,
                    left_commitment: left.witness_commitment.digest,
                    right_statement_digest: right.statement_digest.0,
                    right_commitment: right.witness_commitment.digest,
                    proof_digest: proof.proof_digest,
                });
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    let root = current
        .pop()
        .expect("non-empty verified receipt-root leaf set");
    let artifact = ReceiptRootArtifact {
        version: RECEIPT_ROOT_ARTIFACT_VERSION,
        relation_id: relation.relation_id().0,
        shape_digest: pk.shape_digest.0,
        leaves,
        folds: folds.clone(),
        root_statement_digest: root.statement_digest.0,
        root_commitment: root.witness_commitment.digest,
    };
    Ok(BuiltReceiptRootArtifact {
        artifact_bytes: encode_receipt_root_artifact(&artifact),
        metadata: ReceiptRootMetadata {
            relation_id: artifact.relation_id,
            shape_digest: artifact.shape_digest,
            leaf_count: artifact.leaves.len() as u32,
            fold_count: folds.len() as u32,
        },
    })
}

pub fn build_receipt_root_artifact_bytes(
    receipts: &[CanonicalTxValidityReceipt],
) -> Result<BuiltReceiptRootArtifact> {
    ensure!(
        !receipts.is_empty(),
        "receipt-root artifact requires at least one receipt"
    );

    let relation = CanonicalTxValidityReceiptRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, _) = backend.setup(&security, relation.shape())?;

    let mut leaves = Vec::with_capacity(receipts.len());
    let mut current = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let encoding = relation.encode_statement(receipt)?;
        let assignment = relation.build_assignment(receipt, &())?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        let commitment = backend.commit_witness(&pk, &packed)?;
        let proof = backend.prove_leaf(
            &pk,
            &relation.relation_id(),
            &encoding,
            &packed,
            &commitment,
        )?;
        leaves.push(ReceiptRootLeaf {
            statement_digest: encoding.statement_digest.0,
            witness_commitment: commitment.digest,
            proof_digest: proof.proof_digest,
        });
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: commitment,
        });
    }

    let mut folds = Vec::new();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                folds.push(ReceiptRootFoldStep {
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    left_statement_digest: left.statement_digest.0,
                    left_commitment: left.witness_commitment.digest,
                    right_statement_digest: right.statement_digest.0,
                    right_commitment: right.witness_commitment.digest,
                    proof_digest: proof.proof_digest,
                });
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    let root = current.pop().expect("non-empty receipt-root leaf set");
    let artifact = ReceiptRootArtifact {
        version: RECEIPT_ROOT_ARTIFACT_VERSION,
        relation_id: relation.relation_id().0,
        shape_digest: pk.shape_digest.0,
        leaves,
        folds: folds.clone(),
        root_statement_digest: root.statement_digest.0,
        root_commitment: root.witness_commitment.digest,
    };
    Ok(BuiltReceiptRootArtifact {
        artifact_bytes: encode_receipt_root_artifact(&artifact),
        metadata: ReceiptRootMetadata {
            relation_id: artifact.relation_id,
            shape_digest: artifact.shape_digest,
            leaf_count: artifact.leaves.len() as u32,
            fold_count: folds.len() as u32,
        },
    })
}

pub fn verify_verified_tx_proof_receipt_root_artifact_bytes(
    proofs: &[TransactionProof],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata> {
    ensure!(
        !proofs.is_empty(),
        "receipt-root artifact requires at least one transaction proof"
    );
    let artifact = decode_receipt_root_artifact(artifact_bytes)?;
    ensure!(
        artifact.version == RECEIPT_ROOT_ARTIFACT_VERSION,
        "unsupported receipt-root artifact version {}",
        artifact.version
    );

    let relation = TxLeafPublicRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "receipt-root relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "receipt-root shape digest mismatch"
    );
    ensure!(
        artifact.leaves.len() == proofs.len(),
        "receipt-root leaf count {} does not match tx proofs {}",
        artifact.leaves.len(),
        proofs.len()
    );

    let mut current = Vec::with_capacity(proofs.len());
    for (proof, leaf) in proofs.iter().zip(&artifact.leaves) {
        verify_transaction_proof(proof, transaction_verifying_key())
            .map_err(|err| anyhow::anyhow!("transaction proof verification failed: {err}"))?;
        let statement = canonical_tx_validity_receipt_from_transaction_proof(proof)?;
        let witness = tx_leaf_public_witness_from_transaction_proof(proof)?;
        let encoding = relation.encode_statement(&statement)?;
        let assignment = relation.build_assignment(&statement, &witness)?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        ensure!(
            leaf.statement_digest == encoding.statement_digest.0,
            "receipt-root leaf statement digest mismatch"
        );
        let proof = LeafDigestProof {
            witness_commitment_digest: leaf.witness_commitment,
            proof_digest: leaf.proof_digest,
        };
        backend.verify_leaf(&vk, &relation.relation_id(), &encoding, &packed, &proof)?;
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: backend.commit_witness(&pk, &packed)?,
        });
    }

    let mut fold_index = 0usize;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let fold = artifact
                    .folds
                    .get(fold_index)
                    .ok_or_else(|| anyhow::anyhow!("receipt-root fold list ended early"))?;
                fold_index += 1;
                ensure!(
                    fold.left_statement_digest == left.statement_digest.0
                        && fold.left_commitment == left.witness_commitment.digest,
                    "receipt-root fold left child mismatch"
                );
                ensure!(
                    fold.right_statement_digest == right.statement_digest.0
                        && fold.right_commitment == right.witness_commitment.digest,
                    "receipt-root fold right child mismatch"
                );
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "receipt-root fold parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "receipt-root fold parent commitment mismatch"
                );
                ensure!(
                    fold.proof_digest == proof.proof_digest,
                    "receipt-root fold proof digest mismatch"
                );
                backend.verify_fold(&vk, &parent, &left, &right, &proof)?;
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    ensure!(
        fold_index == artifact.folds.len(),
        "receipt-root artifact has {} unused fold steps",
        artifact.folds.len().saturating_sub(fold_index)
    );
    let root = current
        .pop()
        .expect("receipt-root verifier must retain one root");
    ensure!(
        artifact.root_statement_digest == root.statement_digest.0,
        "receipt-root root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == root.witness_commitment.digest,
        "receipt-root root commitment mismatch"
    );

    Ok(ReceiptRootMetadata {
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        leaf_count: artifact.leaves.len() as u32,
        fold_count: artifact.folds.len() as u32,
    })
}

pub fn verify_receipt_root_artifact_bytes(
    receipts: &[CanonicalTxValidityReceipt],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata> {
    ensure!(
        !receipts.is_empty(),
        "receipt-root artifact requires at least one receipt"
    );
    let artifact = decode_receipt_root_artifact(artifact_bytes)?;
    ensure!(
        artifact.version == RECEIPT_ROOT_ARTIFACT_VERSION,
        "unsupported receipt-root artifact version {}",
        artifact.version
    );

    let relation = CanonicalTxValidityReceiptRelation::default();
    let security = SecurityParams::experimental_default();
    let backend = LatticeBackend::default();
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "receipt-root relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "receipt-root shape digest mismatch"
    );
    ensure!(
        artifact.leaves.len() == receipts.len(),
        "receipt-root leaf count {} does not match receipts {}",
        artifact.leaves.len(),
        receipts.len()
    );

    let mut current = Vec::with_capacity(receipts.len());
    for (receipt, leaf) in receipts.iter().zip(&artifact.leaves) {
        let encoding = relation.encode_statement(receipt)?;
        let assignment = relation.build_assignment(receipt, &())?;
        let packed = packer.pack(relation.shape(), &assignment)?;
        ensure!(
            leaf.statement_digest == encoding.statement_digest.0,
            "receipt-root leaf statement digest mismatch"
        );
        let proof = LeafDigestProof {
            witness_commitment_digest: leaf.witness_commitment,
            proof_digest: leaf.proof_digest,
        };
        backend.verify_leaf(&vk, &relation.relation_id(), &encoding, &packed, &proof)?;
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: backend.commit_witness(&pk, &packed)?,
        });
    }

    let mut fold_index = 0usize;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let fold = artifact
                    .folds
                    .get(fold_index)
                    .ok_or_else(|| anyhow::anyhow!("receipt-root fold list ended early"))?;
                fold_index += 1;
                ensure!(
                    fold.left_statement_digest == left.statement_digest.0
                        && fold.left_commitment == left.witness_commitment.digest,
                    "receipt-root fold left child mismatch"
                );
                ensure!(
                    fold.right_statement_digest == right.statement_digest.0
                        && fold.right_commitment == right.witness_commitment.digest,
                    "receipt-root fold right child mismatch"
                );
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "receipt-root fold parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "receipt-root fold parent commitment mismatch"
                );
                ensure!(
                    fold.proof_digest == proof.proof_digest,
                    "receipt-root fold proof digest mismatch"
                );
                backend.verify_fold(&vk, &parent, &left, &right, &proof)?;
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        current = next;
    }

    ensure!(
        fold_index == artifact.folds.len(),
        "receipt-root artifact has {} unused fold steps",
        artifact.folds.len().saturating_sub(fold_index)
    );
    let root = current
        .pop()
        .expect("receipt-root verifier must retain one root");
    ensure!(
        artifact.root_statement_digest == root.statement_digest.0,
        "receipt-root root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == root.witness_commitment.digest,
        "receipt-root root commitment mismatch"
    );

    Ok(ReceiptRootMetadata {
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        leaf_count: artifact.leaves.len() as u32,
        fold_count: artifact.folds.len() as u32,
    })
}

fn encode_receipt_root_artifact(artifact: &ReceiptRootArtifact) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        2 + 32
            + 32
            + 4
            + 4
            + artifact.leaves.len() * (48 * 3)
            + artifact.folds.len() * (48 * 7)
            + 48
            + 48,
    );
    bytes.extend_from_slice(&artifact.version.to_le_bytes());
    bytes.extend_from_slice(&artifact.relation_id);
    bytes.extend_from_slice(&artifact.shape_digest);
    bytes.extend_from_slice(&(artifact.leaves.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(artifact.folds.len() as u32).to_le_bytes());
    for leaf in &artifact.leaves {
        bytes.extend_from_slice(&leaf.statement_digest);
        bytes.extend_from_slice(&leaf.witness_commitment);
        bytes.extend_from_slice(&leaf.proof_digest);
    }
    for fold in &artifact.folds {
        bytes.extend_from_slice(&fold.parent_statement_digest);
        bytes.extend_from_slice(&fold.parent_commitment);
        bytes.extend_from_slice(&fold.left_statement_digest);
        bytes.extend_from_slice(&fold.left_commitment);
        bytes.extend_from_slice(&fold.right_statement_digest);
        bytes.extend_from_slice(&fold.right_commitment);
        bytes.extend_from_slice(&fold.proof_digest);
    }
    bytes.extend_from_slice(&artifact.root_statement_digest);
    bytes.extend_from_slice(&artifact.root_commitment);
    bytes
}

fn encode_native_tx_leaf_artifact(artifact: &NativeTxLeafArtifact) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&artifact.version.to_le_bytes());
    bytes.extend_from_slice(&artifact.relation_id);
    bytes.extend_from_slice(&artifact.shape_digest);
    bytes.extend_from_slice(&artifact.statement_digest);
    encode_canonical_receipt(&mut bytes, &artifact.receipt);
    encode_serialized_stark_inputs(&mut bytes, &artifact.stark_public_inputs)?;
    encode_native_tx_leaf_opening(&mut bytes, &artifact.opening)?;
    encode_lattice_commitment(&mut bytes, &artifact.commitment)?;
    encode_leaf_artifact(&mut bytes, &artifact.leaf);
    Ok(bytes)
}

fn decode_native_tx_leaf_artifact(bytes: &[u8]) -> Result<NativeTxLeafArtifact> {
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let statement_digest = read_array::<48>(bytes, &mut cursor)?;
    let receipt = decode_canonical_receipt(bytes, &mut cursor)?;
    let stark_public_inputs = decode_serialized_stark_inputs(bytes, &mut cursor)?;
    let opening = decode_native_tx_leaf_opening(bytes, &mut cursor)?;
    let commitment = decode_lattice_commitment(bytes, &mut cursor)?;
    let leaf = decode_leaf_artifact(bytes, &mut cursor)?;
    ensure!(
        cursor == bytes.len(),
        "native tx-leaf artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(NativeTxLeafArtifact {
        version,
        relation_id,
        shape_digest,
        statement_digest,
        receipt,
        stark_public_inputs,
        opening,
        commitment,
        leaf,
    })
}

fn encode_canonical_receipt(bytes: &mut Vec<u8>, receipt: &CanonicalTxValidityReceipt) {
    bytes.extend_from_slice(&receipt.statement_hash);
    bytes.extend_from_slice(&receipt.proof_digest);
    bytes.extend_from_slice(&receipt.public_inputs_digest);
    bytes.extend_from_slice(&receipt.verifier_profile);
}

fn decode_canonical_receipt(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<CanonicalTxValidityReceipt> {
    Ok(CanonicalTxValidityReceipt {
        statement_hash: read_array::<48>(bytes, cursor)?,
        proof_digest: read_array::<48>(bytes, cursor)?,
        public_inputs_digest: read_array::<48>(bytes, cursor)?,
        verifier_profile: read_array::<48>(bytes, cursor)?,
    })
}

fn encode_serialized_stark_inputs(
    bytes: &mut Vec<u8>,
    stark: &SerializedStarkInputs,
) -> Result<()> {
    ensure!(
        stark.input_flags.len() <= MAX_INPUTS,
        "serialized STARK input flag length {} exceeds {}",
        stark.input_flags.len(),
        MAX_INPUTS
    );
    ensure!(
        stark.output_flags.len() <= MAX_OUTPUTS,
        "serialized STARK output flag length {} exceeds {}",
        stark.output_flags.len(),
        MAX_OUTPUTS
    );
    ensure!(
        stark.balance_slot_asset_ids.len() <= BALANCE_SLOTS,
        "serialized STARK balance slot length {} exceeds {}",
        stark.balance_slot_asset_ids.len(),
        BALANCE_SLOTS
    );
    bytes.extend_from_slice(&(stark.input_flags.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&stark.input_flags);
    bytes.extend_from_slice(&(stark.output_flags.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&stark.output_flags);
    bytes.extend_from_slice(&stark.fee.to_le_bytes());
    bytes.push(stark.value_balance_sign);
    bytes.extend_from_slice(&stark.value_balance_magnitude.to_le_bytes());
    bytes.extend_from_slice(&stark.merkle_root);
    bytes.extend_from_slice(&(stark.balance_slot_asset_ids.len() as u32).to_le_bytes());
    for asset_id in &stark.balance_slot_asset_ids {
        bytes.extend_from_slice(&asset_id.to_le_bytes());
    }
    bytes.push(stark.stablecoin_enabled);
    bytes.extend_from_slice(&stark.stablecoin_asset_id.to_le_bytes());
    bytes.extend_from_slice(&stark.stablecoin_policy_version.to_le_bytes());
    bytes.push(stark.stablecoin_issuance_sign);
    bytes.extend_from_slice(&stark.stablecoin_issuance_magnitude.to_le_bytes());
    bytes.extend_from_slice(&stark.stablecoin_policy_hash);
    bytes.extend_from_slice(&stark.stablecoin_oracle_commitment);
    bytes.extend_from_slice(&stark.stablecoin_attestation_commitment);
    Ok(())
}

fn decode_serialized_stark_inputs(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<SerializedStarkInputs> {
    let input_flag_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        input_flag_count <= MAX_INPUTS,
        "serialized STARK input flag length {} exceeds {}",
        input_flag_count,
        MAX_INPUTS
    );
    let input_flags = read_bytes(bytes, cursor, input_flag_count)?;
    let output_flag_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        output_flag_count <= MAX_OUTPUTS,
        "serialized STARK output flag length {} exceeds {}",
        output_flag_count,
        MAX_OUTPUTS
    );
    let output_flags = read_bytes(bytes, cursor, output_flag_count)?;
    let fee = read_u64(bytes, cursor)?;
    let value_balance_sign = read_u8(bytes, cursor)?;
    let value_balance_magnitude = read_u64(bytes, cursor)?;
    let merkle_root = read_array::<48>(bytes, cursor)?;
    let balance_slot_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        balance_slot_count <= BALANCE_SLOTS,
        "serialized STARK balance slot length {} exceeds {}",
        balance_slot_count,
        BALANCE_SLOTS
    );
    let mut balance_slot_asset_ids = Vec::with_capacity(balance_slot_count);
    for _ in 0..balance_slot_count {
        balance_slot_asset_ids.push(read_u64(bytes, cursor)?);
    }
    Ok(SerializedStarkInputs {
        input_flags,
        output_flags,
        fee,
        value_balance_sign,
        value_balance_magnitude,
        merkle_root,
        balance_slot_asset_ids,
        stablecoin_enabled: read_u8(bytes, cursor)?,
        stablecoin_asset_id: read_u64(bytes, cursor)?,
        stablecoin_policy_version: read_u32(bytes, cursor)?,
        stablecoin_issuance_sign: read_u8(bytes, cursor)?,
        stablecoin_issuance_magnitude: read_u64(bytes, cursor)?,
        stablecoin_policy_hash: read_array::<48>(bytes, cursor)?,
        stablecoin_oracle_commitment: read_array::<48>(bytes, cursor)?,
        stablecoin_attestation_commitment: read_array::<48>(bytes, cursor)?,
    })
}

fn encode_native_tx_leaf_opening(bytes: &mut Vec<u8>, opening: &NativeTxLeafOpening) -> Result<()> {
    ensure!(
        opening.inputs.len() <= MAX_INPUTS,
        "native tx-leaf opening input count {} exceeds {}",
        opening.inputs.len(),
        MAX_INPUTS
    );
    ensure!(
        opening.outputs.len() <= MAX_OUTPUTS,
        "native tx-leaf opening output count {} exceeds {}",
        opening.outputs.len(),
        MAX_OUTPUTS
    );
    bytes.extend_from_slice(&opening.sk_spend);
    bytes.extend_from_slice(&(opening.inputs.len() as u32).to_le_bytes());
    for input in &opening.inputs {
        encode_input_note_witness(bytes, input)?;
    }
    bytes.extend_from_slice(&(opening.outputs.len() as u32).to_le_bytes());
    for output in &opening.outputs {
        encode_output_note_witness(bytes, output);
    }
    Ok(())
}

fn decode_native_tx_leaf_opening(bytes: &[u8], cursor: &mut usize) -> Result<NativeTxLeafOpening> {
    let sk_spend = read_array::<32>(bytes, cursor)?;
    let input_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        input_count <= MAX_INPUTS,
        "native tx-leaf opening input count {} exceeds {}",
        input_count,
        MAX_INPUTS
    );
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        inputs.push(decode_input_note_witness(bytes, cursor)?);
    }
    let output_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        output_count <= MAX_OUTPUTS,
        "native tx-leaf opening output count {} exceeds {}",
        output_count,
        MAX_OUTPUTS
    );
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(decode_output_note_witness(bytes, cursor)?);
    }
    Ok(NativeTxLeafOpening {
        sk_spend,
        inputs,
        outputs,
    })
}

fn encode_note_data(bytes: &mut Vec<u8>, note: &transaction_circuit::note::NoteData) {
    bytes.extend_from_slice(&note.value.to_le_bytes());
    bytes.extend_from_slice(&note.asset_id.to_le_bytes());
    bytes.extend_from_slice(&note.pk_recipient);
    bytes.extend_from_slice(&note.pk_auth);
    bytes.extend_from_slice(&note.rho);
    bytes.extend_from_slice(&note.r);
}

fn decode_note_data(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<transaction_circuit::note::NoteData> {
    Ok(transaction_circuit::note::NoteData {
        value: read_u64(bytes, cursor)?,
        asset_id: read_u64(bytes, cursor)?,
        pk_recipient: read_array::<32>(bytes, cursor)?,
        pk_auth: read_array::<32>(bytes, cursor)?,
        rho: read_array::<32>(bytes, cursor)?,
        r: read_array::<32>(bytes, cursor)?,
    })
}

fn encode_input_note_witness(bytes: &mut Vec<u8>, input: &InputNoteWitness) -> Result<()> {
    ensure!(
        input.merkle_path.siblings.len() == MERKLE_TREE_DEPTH,
        "native tx-leaf input merkle path has length {}, expected {}",
        input.merkle_path.siblings.len(),
        MERKLE_TREE_DEPTH
    );
    encode_note_data(bytes, &input.note);
    bytes.extend_from_slice(&input.position.to_le_bytes());
    bytes.extend_from_slice(&input.rho_seed);
    bytes.extend_from_slice(&(input.merkle_path.siblings.len() as u32).to_le_bytes());
    for sibling in &input.merkle_path.siblings {
        bytes.extend_from_slice(&felts_to_bytes48(sibling));
    }
    Ok(())
}

fn decode_input_note_witness(bytes: &[u8], cursor: &mut usize) -> Result<InputNoteWitness> {
    let note = decode_note_data(bytes, cursor)?;
    let position = read_u64(bytes, cursor)?;
    let rho_seed = read_array::<32>(bytes, cursor)?;
    let sibling_count = read_u32(bytes, cursor)? as usize;
    ensure!(
        sibling_count == MERKLE_TREE_DEPTH,
        "native tx-leaf input merkle path length {} does not match {}",
        sibling_count,
        MERKLE_TREE_DEPTH
    );
    let mut siblings = Vec::with_capacity(sibling_count);
    for _ in 0..sibling_count {
        let sibling_bytes = read_array::<48>(bytes, cursor)?;
        let sibling = bytes48_to_felts(&sibling_bytes)
            .ok_or_else(|| anyhow::anyhow!("native tx-leaf merkle sibling is non-canonical"))?;
        siblings.push(sibling);
    }
    Ok(InputNoteWitness {
        note,
        position,
        rho_seed,
        merkle_path: transaction_circuit::note::MerklePath { siblings },
    })
}

fn encode_output_note_witness(bytes: &mut Vec<u8>, output: &OutputNoteWitness) {
    encode_note_data(bytes, &output.note);
}

fn decode_output_note_witness(bytes: &[u8], cursor: &mut usize) -> Result<OutputNoteWitness> {
    Ok(OutputNoteWitness {
        note: decode_note_data(bytes, cursor)?,
    })
}

fn encode_lattice_commitment(bytes: &mut Vec<u8>, commitment: &LatticeCommitment) -> Result<()> {
    bytes.extend_from_slice(&commitment.digest);
    bytes.extend_from_slice(&(commitment.rows.len() as u32).to_le_bytes());
    for row in &commitment.rows {
        bytes.extend_from_slice(&(row.coeffs.len() as u32).to_le_bytes());
        for coeff in &row.coeffs {
            bytes.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    Ok(())
}

fn decode_lattice_commitment(bytes: &[u8], cursor: &mut usize) -> Result<LatticeCommitment> {
    let digest = read_array::<48>(bytes, cursor)?;
    let row_count = read_u32(bytes, cursor)? as usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let coeff_count = read_u32(bytes, cursor)? as usize;
        let mut coeffs = Vec::with_capacity(coeff_count);
        for _ in 0..coeff_count {
            coeffs.push(read_u64(bytes, cursor)?);
        }
        rows.push(RingElem::from_coeffs(coeffs));
    }
    Ok(LatticeCommitment { digest, rows })
}

fn encode_leaf_artifact(bytes: &mut Vec<u8>, leaf: &LeafArtifact<LeafDigestProof>) {
    bytes.extend_from_slice(&leaf.version.to_le_bytes());
    bytes.extend_from_slice(&leaf.relation_id.0);
    bytes.extend_from_slice(&leaf.shape_digest.0);
    bytes.extend_from_slice(&leaf.statement_digest.0);
    bytes.extend_from_slice(&leaf.proof.witness_commitment_digest);
    bytes.extend_from_slice(&leaf.proof.proof_digest);
}

fn decode_leaf_artifact(bytes: &[u8], cursor: &mut usize) -> Result<LeafArtifact<LeafDigestProof>> {
    Ok(LeafArtifact {
        version: read_u16(bytes, cursor)?,
        relation_id: RelationId(read_array::<32>(bytes, cursor)?),
        shape_digest: superneo_ccs::ShapeDigest(read_array::<32>(bytes, cursor)?),
        statement_digest: superneo_ccs::StatementDigest(read_array::<48>(bytes, cursor)?),
        proof: LeafDigestProof {
            witness_commitment_digest: read_array::<48>(bytes, cursor)?,
            proof_digest: read_array::<48>(bytes, cursor)?,
        },
    })
}

fn decode_receipt_root_artifact(bytes: &[u8]) -> Result<ReceiptRootArtifact> {
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let leaf_count = read_u32(bytes, &mut cursor)? as usize;
    let fold_count = read_u32(bytes, &mut cursor)? as usize;
    let mut leaves = Vec::with_capacity(leaf_count);
    for _ in 0..leaf_count {
        leaves.push(ReceiptRootLeaf {
            statement_digest: read_array::<48>(bytes, &mut cursor)?,
            witness_commitment: read_array::<48>(bytes, &mut cursor)?,
            proof_digest: read_array::<48>(bytes, &mut cursor)?,
        });
    }
    let mut folds = Vec::with_capacity(fold_count);
    for _ in 0..fold_count {
        folds.push(ReceiptRootFoldStep {
            parent_statement_digest: read_array::<48>(bytes, &mut cursor)?,
            parent_commitment: read_array::<48>(bytes, &mut cursor)?,
            left_statement_digest: read_array::<48>(bytes, &mut cursor)?,
            left_commitment: read_array::<48>(bytes, &mut cursor)?,
            right_statement_digest: read_array::<48>(bytes, &mut cursor)?,
            right_commitment: read_array::<48>(bytes, &mut cursor)?,
            proof_digest: read_array::<48>(bytes, &mut cursor)?,
        });
    }
    let root_statement_digest = read_array::<48>(bytes, &mut cursor)?;
    let root_commitment = read_array::<48>(bytes, &mut cursor)?;
    ensure!(
        cursor == bytes.len(),
        "receipt-root artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(ReceiptRootArtifact {
        version,
        relation_id,
        shape_digest,
        leaves,
        folds,
        root_statement_digest,
        root_commitment,
    })
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, cursor)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    Ok(read_array::<1>(bytes, cursor)?[0])
}

fn read_bytes(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>> {
    ensure!(
        bytes.len().saturating_sub(*cursor) >= len,
        "artifact ended early while reading {} bytes",
        len
    );
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    ensure!(
        bytes.len().saturating_sub(*cursor) >= N,
        "receipt-root artifact ended early"
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn canonical_tx_validity_receipt_bytes(receipt: &CanonicalTxValidityReceipt) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(48 * RECEIPT_ROOT_DIGEST_WIDTH);
    bytes.extend_from_slice(&receipt.statement_hash);
    bytes.extend_from_slice(&receipt.proof_digest);
    bytes.extend_from_slice(&receipt.public_inputs_digest);
    bytes.extend_from_slice(&receipt.verifier_profile);
    bytes
}

fn bytes48_to_goldilocks(bytes: &[u8; 48]) -> Vec<Goldilocks> {
    bytes
        .chunks_exact(8)
        .map(|chunk| Goldilocks::new(u64::from_le_bytes(chunk.try_into().unwrap())))
        .collect()
}

fn digest48(label: &[u8], bytes: &[u8]) -> [u8; 48] {
    digest48_with_parts(label, &[bytes])
}

fn digest48_with_parts(label: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn blake3_384_bytes(bytes: &[u8]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
    use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
    use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
    use transaction_circuit::keys::generate_keys;
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::proof::prove;
    use transaction_circuit::{StablecoinPolicyBinding, TransactionWitness};

    use super::*;

    #[test]
    fn toy_balance_roundtrip() {
        let relation = ToyBalanceRelation::default();
        let statement = ToyBalanceStatement {
            total_inputs: 10,
            total_outputs: 9,
            fee: 1,
        };
        let witness = ToyBalanceWitness {
            inputs: [4, 6],
            outputs: [3, 6],
            fee: 1,
        };
        let assignment = relation.build_assignment(&statement, &witness).unwrap();
        let encoding = relation.encode_statement(&statement).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let packed = packer.pack(relation.shape(), &assignment).unwrap();
        let unpacked = packer.unpack(relation.shape(), &packed).unwrap();
        assert_eq!(assignment, unpacked);
        assert_eq!(encoding.public_inputs.len(), 3);
    }

    #[test]
    fn tx_receipt_roundtrip() {
        let relation = TxProofReceiptRelation::default();
        let proof_bytes = vec![7u8; 48];
        let public_inputs = vec![3u8; 24];
        let verifier_profile = b"inline-tx-v1";
        let witness = TxProofReceiptWitness {
            receipt_bytes: proof_bytes.clone(),
            verification_trace_bits: proof_bytes
                .iter()
                .flat_map(|byte| (0..8).map(move |shift| (byte >> shift) & 1))
                .take(64)
                .collect(),
        };
        let statement = build_tx_proof_receipt(
            &proof_bytes,
            &public_inputs,
            verifier_profile,
            &witness.verification_trace_bits,
        )
        .unwrap();
        let assignment = relation.build_assignment(&statement, &witness).unwrap();
        let encoding = relation.encode_statement(&statement).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let packed = packer.pack(relation.shape(), &assignment).unwrap();
        let unpacked = packer.unpack(relation.shape(), &packed).unwrap();
        assert_eq!(assignment, unpacked);
        assert_eq!(encoding.public_inputs.len(), 30);
    }

    #[test]
    fn tx_receipt_rejects_trace_digest_mismatch() {
        let relation = TxProofReceiptRelation::default();
        let proof_bytes = vec![7u8; 48];
        let public_inputs = vec![3u8; 24];
        let verifier_profile = b"inline-tx-v1";
        let witness = TxProofReceiptWitness {
            receipt_bytes: proof_bytes.clone(),
            verification_trace_bits: vec![1, 0, 1, 0],
        };
        let mut wrong_trace = witness.verification_trace_bits.clone();
        wrong_trace.push(1);
        let statement =
            build_tx_proof_receipt(&proof_bytes, &public_inputs, verifier_profile, &wrong_trace)
                .unwrap();
        assert!(relation.build_assignment(&statement, &witness).is_err());
    }

    #[test]
    fn canonical_receipt_root_round_trip() {
        let receipts = vec![
            CanonicalTxValidityReceipt {
                statement_hash: [1u8; 48],
                proof_digest: [2u8; 48],
                public_inputs_digest: [3u8; 48],
                verifier_profile: [4u8; 48],
            },
            CanonicalTxValidityReceipt {
                statement_hash: [5u8; 48],
                proof_digest: [6u8; 48],
                public_inputs_digest: [7u8; 48],
                verifier_profile: [8u8; 48],
            },
            CanonicalTxValidityReceipt {
                statement_hash: [9u8; 48],
                proof_digest: [10u8; 48],
                public_inputs_digest: [11u8; 48],
                verifier_profile: [12u8; 48],
            },
        ];
        let built = build_receipt_root_artifact_bytes(&receipts).unwrap();
        let metadata =
            verify_receipt_root_artifact_bytes(&receipts, &built.artifact_bytes).unwrap();
        assert_eq!(metadata.leaf_count, receipts.len() as u32);
        assert!(metadata.fold_count >= 2);
        assert_ne!(experimental_receipt_root_verifier_profile(), [0u8; 48]);
    }

    #[test]
    fn canonical_receipt_root_rejects_receipt_mismatch() {
        let receipts = vec![
            CanonicalTxValidityReceipt {
                statement_hash: [1u8; 48],
                proof_digest: [2u8; 48],
                public_inputs_digest: [3u8; 48],
                verifier_profile: [4u8; 48],
            },
            CanonicalTxValidityReceipt {
                statement_hash: [5u8; 48],
                proof_digest: [6u8; 48],
                public_inputs_digest: [7u8; 48],
                verifier_profile: [8u8; 48],
            },
        ];
        let built = build_receipt_root_artifact_bytes(&receipts).unwrap();
        let mut wrong = receipts.clone();
        wrong[1].proof_digest = [99u8; 48];
        assert!(verify_receipt_root_artifact_bytes(&wrong, &built.artifact_bytes).is_err());
    }

    #[test]
    fn tx_leaf_artifact_round_trip() {
        let proof = sample_transaction_proof(7);
        let receipt = canonical_tx_validity_receipt_from_transaction_proof(&proof).unwrap();
        let tx = tx_leaf_public_tx_from_transaction_proof(&proof).unwrap();
        let built = build_tx_leaf_artifact_bytes(&proof).unwrap();
        let metadata = verify_tx_leaf_artifact_bytes(&tx, &receipt, &built.artifact_bytes).unwrap();
        assert_eq!(
            metadata.relation_id,
            TxLeafPublicRelation::default().relation_id().0
        );
    }

    #[test]
    fn tx_leaf_artifact_rejects_wrong_tx_view() {
        let proof = sample_transaction_proof(8);
        let receipt = canonical_tx_validity_receipt_from_transaction_proof(&proof).unwrap();
        let mut tx = tx_leaf_public_tx_from_transaction_proof(&proof).unwrap();
        tx.balance_tag[0] ^= 0x5a;
        let built = build_tx_leaf_artifact_bytes(&proof).unwrap();
        assert!(verify_tx_leaf_artifact_bytes(&tx, &receipt, &built.artifact_bytes).is_err());
    }

    #[test]
    fn native_tx_validity_roundtrip() {
        let relation = NativeTxValidityRelation::default();
        let witness = sample_witness(9);
        let statement = native_tx_validity_statement_from_witness(&witness).unwrap();
        let assignment = relation.build_assignment(&statement, &witness).unwrap();
        let encoding = relation.encode_statement(&statement).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let packed = packer.pack(relation.shape(), &assignment).unwrap();
        let unpacked = packer.unpack(relation.shape(), &packed).unwrap();
        assert_eq!(assignment, unpacked);
        assert_eq!(encoding.public_inputs.len(), 18);
    }

    #[test]
    fn native_tx_validity_rejects_bad_merkle_path() {
        let relation = NativeTxValidityRelation::default();
        let mut witness = sample_witness(10);
        let statement = native_tx_validity_statement_from_witness(&witness).unwrap();
        witness.inputs[0].merkle_path.siblings[0] = [Goldilocks::new(9); 6];
        assert!(relation.build_assignment(&statement, &witness).is_err());
    }

    #[test]
    fn verified_tx_proof_receipt_root_round_trip() {
        let proofs = vec![sample_transaction_proof(1), sample_transaction_proof(2)];
        let built = build_verified_tx_proof_receipt_root_artifact_bytes(&proofs).unwrap();
        let metadata =
            verify_verified_tx_proof_receipt_root_artifact_bytes(&proofs, &built.artifact_bytes)
                .unwrap();
        assert_eq!(metadata.leaf_count, proofs.len() as u32);
        assert_eq!(
            metadata.relation_id,
            TxLeafPublicRelation::default().relation_id().0
        );
    }

    fn sample_transaction_proof(seed: u64) -> TransactionProof {
        let witness = sample_witness(seed);
        let (proving_key, _) = generate_keys();
        prove(&witness, &proving_key).expect("sample tx proof")
    }

    fn sample_witness(seed: u64) -> TransactionWitness {
        let sk_spend = [seed as u8 + 42; 32];
        let pk_auth = transaction_circuit::hashing_pq::spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed as u8 + 2; 32],
            pk_auth,
            rho: [seed as u8 + 3; 32],
            r: [seed as u8 + 4; 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: seed + 100,
            pk_recipient: [seed as u8 + 5; 32],
            pk_auth,
            rho: [seed as u8 + 6; 32],
            r: [seed as u8 + 7; 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

        let output_native = OutputNoteWitness {
            note: NoteData {
                value: 3,
                asset_id: NATIVE_ASSET_ID,
                pk_recipient: [seed as u8 + 11; 32],
                pk_auth: [seed as u8 + 12; 32],
                rho: [seed as u8 + 13; 32],
                r: [seed as u8 + 14; 32],
            },
        };
        let output_asset = OutputNoteWitness {
            note: NoteData {
                value: 5,
                asset_id: seed + 100,
                pk_recipient: [seed as u8 + 21; 32],
                pk_auth: [seed as u8 + 22; 32],
                rho: [seed as u8 + 23; 32],
                r: [seed as u8 + 24; 32],
            },
        };

        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [seed as u8 + 9; 32],
                    merkle_path: merkle_path0,
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [seed as u8 + 10; 32],
                    merkle_path: merkle_path1,
                },
            ],
            outputs: vec![output_native, output_asset],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&merkle_root),
            fee: 5,
            value_balance: 0,
            stablecoin: StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    fn build_two_leaf_merkle_tree(
        leaf0: HashFelt,
        leaf1: HashFelt,
    ) -> (MerklePath, MerklePath, HashFelt) {
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..CIRCUIT_MERKLE_DEPTH {
            let zero = [Goldilocks::new(0); 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }
        (
            MerklePath {
                siblings: siblings0,
            },
            MerklePath {
                siblings: siblings1,
            },
            current,
        )
    }
}
