use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};

use anyhow::{ensure, Result};
use blake3::Hasher;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use protocol_versioning::{
    tx_proof_backend_for_version, TxProofBackend, VersionBinding, DEFAULT_TX_PROOF_BACKEND,
};
use rayon::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use superneo_backend_lattice::{
    LatticeBackend, LatticeCommitment, LeafDigestProof, NativeBackendParams, RingElem,
};
use superneo_ccs::{
    digest_statement, Assignment, CcsShape, Relation, RelationId, SparseEntry, SparseMatrix,
    StatementEncoding, WitnessField, WitnessSchema,
};
use superneo_core::{Backend, FoldedInstance, LeafArtifact};
use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
use transaction_circuit::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{bytes48_to_felts, felts_to_bytes48};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::note::{InputNoteWitness, OutputNoteWitness, MERKLE_TREE_DEPTH};
use transaction_circuit::p3_prover::TransactionProofParams;
use transaction_circuit::proof::{
    prove_with_params as prove_transaction_with_params,
    smallwood_arithmetization_from_backend_and_proof_bytes, transaction_proof_digest,
    transaction_proof_digest_from_parts, transaction_public_inputs_digest,
    transaction_public_inputs_digest_from_serialized, transaction_statement_hash,
    transaction_verifier_profile_digest, verify as verify_transaction_proof,
    verify_transaction_proof_bytes_for_backend, SerializedStarkInputs, TransactionProof,
};
use transaction_circuit::public_inputs::TransactionPublicInputs;
use transaction_circuit::SmallwoodArithmetization;
use transaction_circuit::TransactionPublicInputsP3;
use transaction_circuit::TransactionWitness;

pub const MAX_RECEIPT_BYTES: usize = 96;
pub const MAX_TRACE_BITS: usize = 256;
pub const TX_LEAF_ARTIFACT_VERSION: u16 = 1;
pub const RECEIPT_ROOT_DIGEST_WIDTH: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeReceiptRootBuildCacheStats {
    pub leaf_cache_hits: u64,
    pub leaf_cache_misses: u64,
    pub chunk_cache_hits: u64,
    pub chunk_cache_misses: u64,
}
pub const RECEIPT_ROOT_LIMBS_PER_DIGEST: usize = 6;
pub const RECEIPT_ROOT_WITNESS_LIMBS: usize =
    RECEIPT_ROOT_DIGEST_WIDTH * RECEIPT_ROOT_LIMBS_PER_DIGEST;
pub const DIGEST_LIMBS: usize = 6;

const CANONICAL_RECEIPT_WIRE_BYTES: usize = 48 * 4;
const LEAF_ARTIFACT_WIRE_BYTES: usize = 2 + 32 + 32 + 48 + 48 + 48;
const TX_PUBLIC_WIRE_BYTES: usize =
    4 + (MAX_INPUTS * 48) + 4 + (MAX_OUTPUTS * 48) + 4 + (MAX_OUTPUTS * 48) + 48 + 2 + 2;
const MAX_NATIVE_TX_STARK_PROOF_BYTES: usize = 512 * 1024;
const NATIVE_TX_LEAF_PROOF_BACKEND_WIRE_BYTES: usize = 1;
const NATIVE_RECEIPT_ROOT_MINI_ROOT_SIZE: usize = 8;
const DEFAULT_RECEIPT_ROOT_BUILD_CACHE_CAPACITY: usize = 256;

fn native_tx_leaf_self_verify_enabled() -> bool {
    std::env::var("HEGEMON_NATIVE_TX_SELF_VERIFY")
        .map(|value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "" | "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(cfg!(debug_assertions))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeTxLeafCommitmentStats {
    pub witness_bits: usize,
    pub digit_bits: u16,
    pub packed_digits: usize,
    pub ring_degree: usize,
    pub live_message_ring_elems: usize,
    pub live_coefficient_dimension: usize,
    pub live_problem_coeff_bound: u32,
    pub live_problem_l2_bound: u32,
}

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
    pub proof_backend: TxProofBackend,
    pub smallwood_arithmetization: Option<SmallwoodArithmetization>,
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
    pub challenges: Vec<u64>,
    pub parent_statement_digest: [u8; 48],
    pub parent_commitment: [u8; 48],
    pub parent_rows: Vec<RingElem>,
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootArtifact {
    pub version: u16,
    pub params_fingerprint: [u8; 48],
    pub spec_digest: [u8; 32],
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub leaves: Vec<ReceiptRootLeaf>,
    pub folds: Vec<ReceiptRootFoldStep>,
    pub root_statement_digest: [u8; 48],
    pub root_commitment: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootMetadata {
    pub params_fingerprint: [u8; 48],
    pub spec_digest: [u8; 32],
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeReceiptRootHierarchyNode {
    pub leaf_start: u32,
    pub leaf_count: u32,
    pub statement_digest: [u8; 48],
    pub commitment_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeReceiptRootHierarchyLayer {
    pub level_index: u32,
    pub nodes: Vec<NativeReceiptRootHierarchyNode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeReceiptRootHierarchy {
    pub params_fingerprint: [u8; 48],
    pub spec_digest: [u8; 32],
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub mini_root_size: u32,
    pub leaf_count: u32,
    pub mini_roots: Vec<NativeReceiptRootHierarchyNode>,
    pub layers: Vec<NativeReceiptRootHierarchyLayer>,
    pub fold_count: u32,
    pub root_statement_digest: [u8; 48],
    pub root_commitment: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeReceiptRootChunkRoot {
    pub leaf_start: u32,
    pub leaf_count: u32,
    pub root: FoldedInstance<LatticeCommitment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeReceiptRootHierarchyBuild {
    pub metadata: ReceiptRootMetadata,
    pub hierarchy: NativeReceiptRootHierarchy,
    pub mini_root_instances: Vec<NativeReceiptRootChunkRoot>,
    pub root: FoldedInstance<LatticeCommitment>,
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

#[derive(Clone, Debug)]
pub struct NativeTxLeafArtifact {
    pub version: u16,
    pub params_fingerprint: [u8; 48],
    pub spec_digest: [u8; 32],
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub statement_digest: [u8; 48],
    pub receipt: CanonicalTxValidityReceipt,
    pub stark_public_inputs: SerializedStarkInputs,
    pub tx: TxLeafPublicTx,
    pub proof_backend: TxProofBackend,
    pub stark_proof: Vec<u8>,
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
    pub params_fingerprint: [u8; 48],
    pub spec_digest: [u8; 32],
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub statement_digest: [u8; 48],
    pub proof_backend: TxProofBackend,
    pub stark_public_inputs: SerializedStarkInputs,
    pub commitment: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeTxLeafRecord {
    pub params_fingerprint: [u8; 48],
    pub spec_digest: [u8; 32],
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub statement_digest: [u8; 48],
    pub commitment: LatticeCommitment,
    pub proof_digest: [u8; 48],
}

type NativeReceiptRootInstance = FoldedInstance<LatticeCommitment>;
type NativeReceiptRootProverKey = <LatticeBackend as Backend<Goldilocks>>::ProverKey;

#[derive(Clone, Debug)]
struct VerifiedNativeReceiptRootLeaf {
    leaf: ReceiptRootLeaf,
    instance: NativeReceiptRootInstance,
}

#[derive(Clone, Debug)]
struct CachedNativeReceiptRootLeaf {
    artifact_hash: [u8; 48],
    verified: VerifiedNativeReceiptRootLeaf,
}

#[derive(Clone, Debug)]
struct ReceiptRootChunkBuild {
    root: NativeReceiptRootInstance,
    level_folds: Vec<Vec<ReceiptRootFoldStep>>,
}

struct ReceiptRootLeafBuildCache {
    capacity: usize,
    order: VecDeque<[u8; 48]>,
    entries: HashMap<[u8; 48], VerifiedNativeReceiptRootLeaf>,
}

impl ReceiptRootLeafBuildCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, key: [u8; 48]) -> Option<VerifiedNativeReceiptRootLeaf> {
        let entry = self.entries.get(&key).cloned();
        if entry.is_some() {
            self.order.retain(|existing| *existing != key);
            self.order.push_back(key);
        }
        entry
    }

    fn insert(&mut self, key: [u8; 48], value: VerifiedNativeReceiptRootLeaf) {
        if self.capacity == 0 {
            return;
        }
        if let Some(existing) = self.entries.get_mut(&key) {
            *existing = value;
            self.order.retain(|entry| *entry != key);
            self.order.push_back(key);
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            } else {
                break;
            }
        }
        self.entries.insert(key, value);
        self.order.push_back(key);
    }

    fn clear(&mut self) {
        self.order.clear();
        self.entries.clear();
    }
}

struct ReceiptRootChunkBuildCache {
    capacity: usize,
    order: VecDeque<[u8; 48]>,
    entries: HashMap<[u8; 48], ReceiptRootChunkBuild>,
}

impl ReceiptRootChunkBuildCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, key: [u8; 48]) -> Option<ReceiptRootChunkBuild> {
        let entry = self.entries.get(&key).cloned();
        if entry.is_some() {
            self.order.retain(|existing| *existing != key);
            self.order.push_back(key);
        }
        entry
    }

    fn insert(&mut self, key: [u8; 48], value: ReceiptRootChunkBuild) {
        if self.capacity == 0 {
            return;
        }
        if let Some(existing) = self.entries.get_mut(&key) {
            *existing = value;
            self.order.retain(|entry| *entry != key);
            self.order.push_back(key);
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            } else {
                break;
            }
        }
        self.entries.insert(key, value);
        self.order.push_back(key);
    }

    fn clear(&mut self) {
        self.order.clear();
        self.entries.clear();
    }
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

fn transaction_proving_key() -> &'static transaction_circuit::keys::ProvingKey {
    static PROVING_KEY: OnceLock<transaction_circuit::keys::ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(|| generate_keys().0)
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
        verifier_profile: transaction_verifier_profile_digest(proof)
            .map_err(|err| anyhow::anyhow!("failed to derive tx verifier profile digest: {err}"))?,
    })
}

pub fn native_tx_validity_statement_from_witness(
    witness: &TransactionWitness,
) -> Result<NativeTxValidityStatement> {
    native_tx_validity_statement_from_witness_with_params(witness, &native_backend_params())
}

pub fn native_tx_validity_statement_from_witness_with_params(
    witness: &TransactionWitness,
    params: &NativeBackendParams,
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
        verifier_profile: experimental_native_tx_verifier_profile_for_params(params),
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
        proof_backend: proof.proof_backend(),
        smallwood_arithmetization: smallwood_arithmetization_from_backend_and_proof_bytes(
            proof.proof_backend(),
            proof.proof_bytes(),
        )
        .map_err(|err| anyhow::anyhow!("failed to decode tx proof arithmetization: {err}"))?,
    })
}

pub fn tx_leaf_public_witness_from_parts(
    tx: &TxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    proof_backend: TxProofBackend,
    smallwood_arithmetization: Option<SmallwoodArithmetization>,
) -> TxLeafPublicWitness {
    TxLeafPublicWitness {
        tx: tx.clone(),
        stark_public_inputs: stark_public_inputs.clone(),
        proof_backend,
        smallwood_arithmetization,
    }
}

fn native_tx_leaf_receipt_from_transaction_proof(
    proof: &TransactionProof,
    params: &NativeBackendParams,
) -> Result<CanonicalTxValidityReceipt> {
    Ok(CanonicalTxValidityReceipt {
        statement_hash: transaction_statement_hash(proof),
        proof_digest: transaction_proof_digest(proof),
        public_inputs_digest: transaction_public_inputs_digest(proof).map_err(|err| {
            anyhow::anyhow!("failed to derive native tx public inputs digest: {err}")
        })?,
        verifier_profile: experimental_native_tx_leaf_verifier_profile_for_params(params),
    })
}

fn native_tx_leaf_receipt_from_parts(
    tx: &TxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    stark_proof: &[u8],
    proof_backend: TxProofBackend,
    params: &NativeBackendParams,
) -> Result<CanonicalTxValidityReceipt> {
    ensure!(
        !stark_proof.is_empty(),
        "native tx-leaf proof bytes must not be empty"
    );
    Ok(CanonicalTxValidityReceipt {
        statement_hash: tx_statement_hash_from_tx_leaf_public(tx, stark_public_inputs)?,
        proof_digest: transaction_proof_digest_from_parts(proof_backend, stark_proof),
        public_inputs_digest: transaction_public_inputs_digest_from_serialized(stark_public_inputs)
            .map_err(|err| anyhow::anyhow!("failed to hash native tx public inputs: {err}"))?,
        verifier_profile: experimental_native_tx_leaf_verifier_profile_for_params(params),
    })
}

fn transaction_public_inputs_p3_from_tx_leaf_public(
    tx: &TxLeafPublicTx,
    stark_inputs: &SerializedStarkInputs,
) -> Result<TransactionPublicInputsP3> {
    ensure!(
        tx.nullifiers.len() <= MAX_INPUTS,
        "tx nullifier length {} exceeds {}",
        tx.nullifiers.len(),
        MAX_INPUTS
    );
    ensure!(
        tx.commitments.len() <= MAX_OUTPUTS,
        "tx commitment length {} exceeds {}",
        tx.commitments.len(),
        MAX_OUTPUTS
    );
    ensure!(
        tx.ciphertext_hashes.len() <= MAX_OUTPUTS,
        "tx ciphertext hash length {} exceeds {}",
        tx.ciphertext_hashes.len(),
        MAX_OUTPUTS
    );
    ensure!(
        stark_inputs.balance_slot_asset_ids.len() == BALANCE_SLOTS,
        "serialized STARK balance slot length {} does not match {}",
        stark_inputs.balance_slot_asset_ids.len(),
        BALANCE_SLOTS
    );
    ensure!(
        active_flag_count(&stark_inputs.input_flags)? == tx.nullifiers.len(),
        "tx-leaf nullifier list length does not match active input flags"
    );
    ensure!(
        active_flag_count(&stark_inputs.output_flags)? == tx.commitments.len(),
        "tx-leaf commitment list length does not match active output flags"
    );
    ensure!(
        active_flag_count(&stark_inputs.output_flags)? == tx.ciphertext_hashes.len(),
        "tx-leaf ciphertext-hash list length does not match active output flags"
    );

    let mut public = TransactionPublicInputsP3::default();
    public.input_flags = stark_inputs
        .input_flags
        .iter()
        .copied()
        .map(|flag| Goldilocks::from_u64(u64::from(flag)))
        .collect();
    public.output_flags = stark_inputs
        .output_flags
        .iter()
        .copied()
        .map(|flag| Goldilocks::from_u64(u64::from(flag)))
        .collect();
    for (slot, value) in tx.nullifiers.iter().enumerate() {
        public.nullifiers[slot] = bytes48_to_felts(value)
            .ok_or_else(|| anyhow::anyhow!("tx nullifier {} is non-canonical", slot))?;
    }
    for (slot, value) in tx.commitments.iter().enumerate() {
        public.commitments[slot] = bytes48_to_felts(value)
            .ok_or_else(|| anyhow::anyhow!("tx commitment {} is non-canonical", slot))?;
    }
    for (slot, value) in tx.ciphertext_hashes.iter().enumerate() {
        public.ciphertext_hashes[slot] = bytes48_to_felts(value)
            .ok_or_else(|| anyhow::anyhow!("tx ciphertext hash {} is non-canonical", slot))?;
    }
    public.fee = Goldilocks::from_u64(stark_inputs.fee);
    public.value_balance_sign = Goldilocks::from_u64(u64::from(stark_inputs.value_balance_sign));
    public.value_balance_magnitude = Goldilocks::from_u64(stark_inputs.value_balance_magnitude);
    public.merkle_root = bytes48_to_felts(&stark_inputs.merkle_root)
        .ok_or_else(|| anyhow::anyhow!("native tx-leaf merkle root is non-canonical"))?;
    for (slot, asset_id) in stark_inputs.balance_slot_asset_ids.iter().enumerate() {
        public.balance_slot_assets[slot] = Goldilocks::from_u64(*asset_id);
    }
    public.stablecoin_enabled = Goldilocks::from_u64(u64::from(stark_inputs.stablecoin_enabled));
    public.stablecoin_asset = Goldilocks::from_u64(stark_inputs.stablecoin_asset_id);
    public.stablecoin_policy_version =
        Goldilocks::from_u64(u64::from(stark_inputs.stablecoin_policy_version));
    public.stablecoin_issuance_sign =
        Goldilocks::from_u64(u64::from(stark_inputs.stablecoin_issuance_sign));
    public.stablecoin_issuance_magnitude =
        Goldilocks::from_u64(stark_inputs.stablecoin_issuance_magnitude);
    public.stablecoin_policy_hash = bytes48_to_felts(&stark_inputs.stablecoin_policy_hash)
        .ok_or_else(|| anyhow::anyhow!("native tx-leaf stablecoin policy hash is non-canonical"))?;
    public.stablecoin_oracle_commitment =
        bytes48_to_felts(&stark_inputs.stablecoin_oracle_commitment).ok_or_else(|| {
            anyhow::anyhow!("native tx-leaf stablecoin oracle commitment is non-canonical")
        })?;
    public.stablecoin_attestation_commitment =
        bytes48_to_felts(&stark_inputs.stablecoin_attestation_commitment).ok_or_else(|| {
            anyhow::anyhow!("native tx-leaf stablecoin attestation commitment is non-canonical")
        })?;
    Ok(public)
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
    let canonicalize_balance_slot_asset_id =
        |asset_id: u64| Goldilocks::from_u64(asset_id).as_canonical_u64();
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
    witness
        .validate()
        .map_err(|err| anyhow::anyhow!("native tx witness validation failed: {err}"))?;
    validate_native_merkle_membership(witness)?;
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| anyhow::anyhow!("failed to derive native tx public inputs: {err}"))?;
    let serialized = serialized_stark_inputs_from_witness(witness, &public_inputs)?;
    ensure!(
        transaction_statement_hash_from_public_inputs(&public_inputs) == statement.statement_hash,
        "native tx statement hash mismatch"
    );
    ensure!(
        transaction_public_inputs_digest_from_serialized(&serialized)
            .map_err(|err| anyhow::anyhow!("failed to hash native tx public inputs: {err}"))?
            == statement.public_inputs_digest,
        "native tx public inputs digest mismatch"
    );
    ensure!(
        statement.verifier_profile != [0u8; 48],
        "native tx verifier profile must not be empty"
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
        statement.verifier_profile != [0u8; 48],
        "tx-leaf verifier profile must not be empty"
    );
    validate_tx_leaf_public_witness_with_expected_profile(
        statement,
        witness,
        statement.verifier_profile,
    )
}

fn validate_tx_leaf_public_witness_with_expected_profile(
    statement: &CanonicalTxValidityReceipt,
    witness: &TxLeafPublicWitness,
    expected_verifier_profile: [u8; 48],
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
    ensure!(
        expected_verifier_profile == statement.verifier_profile,
        "tx-leaf verifier profile mismatch"
    );
    Ok(())
}

fn validate_native_tx_leaf_public_witness_with_params(
    params: &NativeBackendParams,
    statement: &CanonicalTxValidityReceipt,
    witness: &TxLeafPublicWitness,
) -> Result<()> {
    validate_tx_leaf_public_witness_with_expected_profile(
        statement,
        witness,
        experimental_native_tx_leaf_verifier_profile_for_params(params),
    )
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
        out.push(Goldilocks::new(
            inputs.get(idx).map(|input| input.note.value).unwrap_or(0),
        ));
    }
    for idx in 0..MAX_INPUTS {
        out.push(Goldilocks::new(
            inputs
                .get(idx)
                .map(|input| input.note.asset_id)
                .unwrap_or(0),
        ));
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32(out, &input.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32(out, &input.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32(out, &input.note.rho);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
        }
    }
    for idx in 0..MAX_INPUTS {
        if let Some(input) = inputs.get(idx) {
            push_bytes32(out, &input.note.r);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
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
        out.push(Goldilocks::new(
            outputs
                .get(idx)
                .map(|output| output.note.value)
                .unwrap_or(0),
        ));
    }
    for idx in 0..MAX_OUTPUTS {
        out.push(Goldilocks::new(
            outputs
                .get(idx)
                .map(|output| output.note.asset_id)
                .unwrap_or(0),
        ));
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32(out, &output.note.pk_recipient);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32(out, &output.note.pk_auth);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32(out, &output.note.rho);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
        }
    }
    for idx in 0..MAX_OUTPUTS {
        if let Some(output) = outputs.get(idx) {
            push_bytes32(out, &output.note.r);
        } else {
            out.extend(std::iter::repeat_n(Goldilocks::new(0), 32));
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

pub fn native_backend_params() -> NativeBackendParams {
    NativeBackendParams::default()
}

fn ceil_sqrt_u64(value: u64) -> u64 {
    if value <= 1 {
        return value;
    }
    let floor = (value as f64).sqrt().floor() as u64;
    if floor.saturating_mul(floor) == value {
        floor
    } else {
        floor.saturating_add(1)
    }
}

pub fn native_tx_leaf_commitment_stats() -> NativeTxLeafCommitmentStats {
    native_tx_leaf_commitment_stats_with_params(&native_backend_params())
}

pub fn native_tx_leaf_commitment_stats_with_params(
    params: &NativeBackendParams,
) -> NativeTxLeafCommitmentStats {
    let relation = TxLeafPublicRelation::default();
    let witness_bits = relation.shape().witness_schema.total_witness_bits();
    let digit_bits = params.digit_bits();
    let packed_digits = witness_bits.div_ceil(digit_bits as usize);
    let ring_degree = params.ring_degree();
    let live_message_ring_elems = packed_digits.div_ceil(ring_degree);
    let live_coefficient_dimension = live_message_ring_elems * ring_degree;
    let live_problem_coeff_bound = ((1u32 << digit_bits) - 1).max(1);
    let live_problem_l2_bound = ceil_sqrt_u64((live_coefficient_dimension as u64).saturating_mul(
        u64::from(live_problem_coeff_bound).saturating_mul(u64::from(live_problem_coeff_bound)),
    )) as u32;
    NativeTxLeafCommitmentStats {
        witness_bits,
        digit_bits,
        packed_digits,
        ring_degree,
        live_message_ring_elems,
        live_coefficient_dimension,
        live_problem_coeff_bound,
        live_problem_l2_bound,
    }
}

fn receipt_root_artifact_version(params: &NativeBackendParams) -> u16 {
    params.artifact_version(b"receipt-root-v2")
}

fn native_tx_leaf_artifact_version(params: &NativeBackendParams) -> u16 {
    params.artifact_version(b"native-tx-leaf-v2")
}

fn derive_verifier_profile(
    params: &NativeBackendParams,
    relation_id: &RelationId,
    shape_digest: &superneo_ccs::ShapeDigest,
    profile_label: &[u8],
) -> [u8; 48] {
    digest48_with_parts(
        b"hegemon.superneo.explicit-verifier-profile.v1",
        &[
            profile_label,
            &params.parameter_fingerprint(),
            &params.spec_digest(),
            &relation_id.0,
            &shape_digest.0,
        ],
    )
}

pub fn experimental_receipt_root_verifier_profile() -> [u8; 48] {
    let relation = CanonicalTxValidityReceiptRelation::default();
    let backend = LatticeBackend::default();
    let params = backend.native_params().clone();
    let security = backend.security_params();
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental receipt-root setup must succeed");
    let mut material = Vec::with_capacity(32 + 32 + 32 + 32);
    material.extend_from_slice(b"hegemon.superneo.receipt-root-profile.v1");
    material.extend_from_slice(&params.spec_digest());
    material.extend_from_slice(&relation.relation_id().0);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.fold_challenge_count.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    material.extend_from_slice(&pk.opening_randomness_bits.to_le_bytes());
    digest48(
        b"hegemon.superneo.receipt-root-profile.digest.v1",
        &material,
    )
}

pub fn experimental_tx_leaf_verifier_profile() -> [u8; 48] {
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::default();
    let params = backend.native_params().clone();
    let security = backend.security_params();
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental tx-leaf setup must succeed");
    let mut material = Vec::with_capacity(32 + 32 + 32 + 32);
    material.extend_from_slice(b"hegemon.superneo.tx-leaf-profile.v1");
    material.extend_from_slice(&params.spec_digest());
    material.extend_from_slice(&relation.relation_id().0);
    material.extend_from_slice(&pk.shape_digest.0);
    material.extend_from_slice(&pk.security_bits.to_le_bytes());
    material.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    material.extend_from_slice(&pk.fold_challenge_count.to_le_bytes());
    material.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    material.extend_from_slice(&pk.transcript_domain_digest);
    material.extend_from_slice(&pk.opening_randomness_bits.to_le_bytes());
    digest48(b"hegemon.superneo.tx-leaf-profile.digest.v1", &material)
}

pub fn experimental_native_tx_leaf_verifier_profile_for_params(
    params: &NativeBackendParams,
) -> [u8; 48] {
    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental native tx-leaf setup must succeed");
    derive_verifier_profile(
        params,
        &relation.relation_id(),
        &pk.shape_digest,
        b"native-tx-leaf",
    )
}

pub fn experimental_native_tx_leaf_verifier_profile() -> [u8; 48] {
    experimental_native_tx_leaf_verifier_profile_for_params(&native_backend_params())
}

pub fn experimental_native_tx_verifier_profile_for_params(
    params: &NativeBackendParams,
) -> [u8; 48] {
    let relation = NativeTxValidityRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental native tx setup must succeed");
    derive_verifier_profile(
        params,
        &relation.relation_id(),
        &pk.shape_digest,
        b"native-tx",
    )
}

pub fn experimental_native_tx_verifier_profile() -> [u8; 48] {
    experimental_native_tx_verifier_profile_for_params(&native_backend_params())
}

pub fn experimental_native_receipt_root_verifier_profile_for_params(
    params: &NativeBackendParams,
) -> [u8; 48] {
    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend
        .setup(&security, relation.shape())
        .expect("experimental native receipt-root setup must succeed");
    derive_verifier_profile(
        params,
        &relation.relation_id(),
        &pk.shape_digest,
        b"native-receipt-root",
    )
}

pub fn experimental_native_receipt_root_verifier_profile() -> [u8; 48] {
    experimental_native_receipt_root_verifier_profile_for_params(&native_backend_params())
}

pub fn max_native_tx_leaf_artifact_bytes() -> usize {
    max_native_tx_leaf_artifact_bytes_with_params(&native_backend_params())
}

pub fn max_native_tx_leaf_artifact_bytes_with_params(params: &NativeBackendParams) -> usize {
    let serialized_stark_inputs_bytes = 4
        + MAX_INPUTS
        + 4
        + MAX_OUTPUTS
        + 8
        + 1
        + 8
        + 48
        + 4
        + (BALANCE_SLOTS * 8)
        + 1
        + 8
        + 4
        + 1
        + 8
        + (48 * 3);
    let lattice_commitment_bytes = 48 + 4 + (params.matrix_rows * (4 + (params.matrix_cols * 8)));
    2 + 48
        + 32
        + 32
        + 32
        + 48
        + CANONICAL_RECEIPT_WIRE_BYTES
        + serialized_stark_inputs_bytes
        + TX_PUBLIC_WIRE_BYTES
        + 4
        + MAX_NATIVE_TX_STARK_PROOF_BYTES
        + NATIVE_TX_LEAF_PROOF_BACKEND_WIRE_BYTES
        + lattice_commitment_bytes
        + LEAF_ARTIFACT_WIRE_BYTES
}

pub fn max_native_receipt_root_artifact_bytes(tx_count: usize) -> usize {
    max_native_receipt_root_artifact_bytes_with_params(tx_count, &native_backend_params())
}

pub fn native_receipt_root_mini_root_size() -> usize {
    NATIVE_RECEIPT_ROOT_MINI_ROOT_SIZE
}

fn load_receipt_root_build_cache_capacity() -> usize {
    std::env::var("HEGEMON_RECEIPT_ROOT_CACHE_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_RECEIPT_ROOT_BUILD_CACHE_CAPACITY)
}

static NATIVE_RECEIPT_ROOT_LEAF_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static NATIVE_RECEIPT_ROOT_LEAF_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
static NATIVE_RECEIPT_ROOT_CHUNK_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static NATIVE_RECEIPT_ROOT_CHUNK_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

static NATIVE_RECEIPT_ROOT_LEAF_BUILD_CACHE: LazyLock<Mutex<ReceiptRootLeafBuildCache>> =
    LazyLock::new(|| {
        Mutex::new(ReceiptRootLeafBuildCache::new(
            load_receipt_root_build_cache_capacity(),
        ))
    });

static NATIVE_RECEIPT_ROOT_CHUNK_BUILD_CACHE: LazyLock<Mutex<ReceiptRootChunkBuildCache>> =
    LazyLock::new(|| {
        Mutex::new(ReceiptRootChunkBuildCache::new(
            load_receipt_root_build_cache_capacity(),
        ))
    });

pub fn native_receipt_root_build_cache_stats() -> NativeReceiptRootBuildCacheStats {
    NativeReceiptRootBuildCacheStats {
        leaf_cache_hits: NATIVE_RECEIPT_ROOT_LEAF_CACHE_HITS.load(Ordering::Relaxed),
        leaf_cache_misses: NATIVE_RECEIPT_ROOT_LEAF_CACHE_MISSES.load(Ordering::Relaxed),
        chunk_cache_hits: NATIVE_RECEIPT_ROOT_CHUNK_CACHE_HITS.load(Ordering::Relaxed),
        chunk_cache_misses: NATIVE_RECEIPT_ROOT_CHUNK_CACHE_MISSES.load(Ordering::Relaxed),
    }
}

pub fn clear_native_receipt_root_build_cache_stats() {
    NATIVE_RECEIPT_ROOT_LEAF_CACHE_HITS.store(0, Ordering::Relaxed);
    NATIVE_RECEIPT_ROOT_LEAF_CACHE_MISSES.store(0, Ordering::Relaxed);
    NATIVE_RECEIPT_ROOT_CHUNK_CACHE_HITS.store(0, Ordering::Relaxed);
    NATIVE_RECEIPT_ROOT_CHUNK_CACHE_MISSES.store(0, Ordering::Relaxed);
}

pub fn clear_native_receipt_root_build_caches() {
    if let Ok(mut guard) = NATIVE_RECEIPT_ROOT_LEAF_BUILD_CACHE.lock() {
        guard.clear();
    }
    if let Ok(mut guard) = NATIVE_RECEIPT_ROOT_CHUNK_BUILD_CACHE.lock() {
        guard.clear();
    }
}

pub fn max_native_receipt_root_artifact_bytes_with_params(
    tx_count: usize,
    params: &NativeBackendParams,
) -> usize {
    let leaf_bytes = tx_count * (48 * 3);
    let fold_step_bytes = 4
        + ((params.fold_challenge_count as usize) * 8)
        + 48
        + 48
        + 4
        + (params.matrix_rows * (4 + (params.matrix_cols * 8)))
        + 48;
    let fold_bytes = tx_count.saturating_sub(1) * fold_step_bytes;
    2 + 48 + 32 + 32 + 32 + 4 + 4 + leaf_bytes + fold_bytes + 48 + 48
}

fn native_leaf_proof_digest(
    params: &NativeBackendParams,
    relation_id: &RelationId,
    statement_digest: &superneo_ccs::StatementDigest,
    commitment_digest: &[u8; 48],
    opening_digest: &[u8; 48],
) -> [u8; 48] {
    digest48_with_parts(
        b"hegemon.superneo.native-leaf-proof.v1",
        &[
            &params.parameter_fingerprint(),
            &relation_id.0,
            &statement_digest.0,
            commitment_digest,
            opening_digest,
        ],
    )
}

pub fn native_leaf_proof_digest_for_review(
    params: &NativeBackendParams,
    relation_id: &RelationId,
    statement_digest: &superneo_ccs::StatementDigest,
    commitment_digest: &[u8; 48],
    opening_digest: &[u8; 48],
) -> [u8; 48] {
    native_leaf_proof_digest(
        params,
        relation_id,
        statement_digest,
        commitment_digest,
        opening_digest,
    )
}

pub fn build_tx_leaf_artifact_bytes(proof: &TransactionProof) -> Result<BuiltTxLeafArtifact> {
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::default();
    let security = backend.security_params();
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
    build_native_tx_leaf_artifact_bytes_with_params(&native_backend_params(), witness)
}

pub fn build_native_tx_leaf_artifact_bytes_with_params(
    params: &NativeBackendParams,
    witness: &TransactionWitness,
) -> Result<BuiltNativeTxLeafArtifact> {
    let proof = prove_transaction_with_params(
        witness,
        transaction_proving_key(),
        TransactionProofParams::release_for_version(witness.version),
    )
    .map_err(|err| anyhow::anyhow!("native tx proof generation failed: {err}"))?;
    build_native_tx_leaf_artifact_from_transaction_proof_with_params(params, &proof)
}

fn build_native_tx_leaf_artifact_from_transaction_proof_with_params(
    params: &NativeBackendParams,
    proof: &TransactionProof,
) -> Result<BuiltNativeTxLeafArtifact> {
    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    let (pk, _) = backend.setup(&security, relation.shape())?;

    if native_tx_leaf_self_verify_enabled() {
        verify_transaction_proof(proof, transaction_verifying_key())
            .map_err(|err| anyhow::anyhow!("transaction proof verification failed: {err}"))?;
    }
    let tx = tx_leaf_public_tx_from_transaction_proof(proof)?;
    let witness = tx_leaf_public_witness_from_transaction_proof(proof)?;
    let receipt = native_tx_leaf_receipt_from_transaction_proof(proof, params)?;
    let encoding = relation.encode_statement(&receipt)?;
    validate_native_tx_leaf_public_witness_with_params(params, &receipt, &witness)?;
    let assignment = tx_leaf_public_witness_assignment(&witness)?;
    let packed = packer.pack(relation.shape(), &assignment)?;
    let commitment = backend.commit_witness(&pk, &packed)?;
    let leaf_proof = backend.prove_leaf(
        &pk,
        &relation.relation_id(),
        &encoding,
        &packed,
        &commitment,
    )?;
    let artifact = NativeTxLeafArtifact {
        version: native_tx_leaf_artifact_version(params),
        params_fingerprint: params.parameter_fingerprint(),
        spec_digest: params.spec_digest(),
        relation_id: relation.relation_id().0,
        shape_digest: pk.shape_digest.0,
        statement_digest: encoding.statement_digest.0,
        receipt: receipt.clone(),
        stark_public_inputs: witness.stark_public_inputs,
        tx,
        proof_backend: proof.proof_backend(),
        stark_proof: proof.stark_proof.clone(),
        commitment: commitment.clone(),
        leaf: LeafArtifact {
            version: native_tx_leaf_artifact_version(params),
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

pub fn serialized_stark_inputs_from_witness_for_review(
    witness: &TransactionWitness,
) -> Result<SerializedStarkInputs> {
    let public_inputs = witness
        .public_inputs()
        .map_err(|err| anyhow::anyhow!("failed to derive native tx public inputs: {err}"))?;
    serialized_stark_inputs_from_witness(witness, &public_inputs)
}

pub fn decode_tx_leaf_artifact_bytes(artifact_bytes: &[u8]) -> Result<TxLeafArtifact> {
    bincode::deserialize(artifact_bytes)
        .map_err(|err| anyhow::anyhow!("failed to decode tx-leaf artifact: {err}"))
}

pub fn decode_native_tx_leaf_artifact_bytes(artifact_bytes: &[u8]) -> Result<NativeTxLeafArtifact> {
    decode_native_tx_leaf_artifact_with_params(&native_backend_params(), artifact_bytes)
}

pub fn encode_native_tx_leaf_artifact_bytes(artifact: &NativeTxLeafArtifact) -> Result<Vec<u8>> {
    encode_native_tx_leaf_artifact(artifact)
}

pub fn native_tx_leaf_record_from_artifact(artifact: &NativeTxLeafArtifact) -> NativeTxLeafRecord {
    NativeTxLeafRecord {
        params_fingerprint: artifact.params_fingerprint,
        spec_digest: artifact.spec_digest,
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        statement_digest: artifact.statement_digest,
        commitment: artifact.commitment.clone(),
        proof_digest: artifact.leaf.proof.proof_digest,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptRootWorkNode {
    leaf_start: usize,
    leaf_count: usize,
    instance: FoldedInstance<LatticeCommitment>,
}

impl ReceiptRootWorkNode {
    fn to_hierarchy_node(&self) -> NativeReceiptRootHierarchyNode {
        NativeReceiptRootHierarchyNode {
            leaf_start: self.leaf_start as u32,
            leaf_count: self.leaf_count as u32,
            statement_digest: self.instance.statement_digest.0,
            commitment_digest: self.instance.witness_commitment.digest,
        }
    }
}

fn native_receipt_root_leaf_nodes_from_records_with_params(
    params: &NativeBackendParams,
    records: &[NativeTxLeafRecord],
) -> Result<(
    [u8; 32],
    [u8; 32],
    Vec<ReceiptRootLeaf>,
    Vec<ReceiptRootWorkNode>,
)> {
    ensure!(
        !records.is_empty(),
        "native receipt-root hierarchy requires at least one tx-leaf record"
    );
    ensure!(
        records.len() <= params.max_claimed_receipt_root_leaves as usize,
        "native receipt-root hierarchy leaf count {} exceeds claimed maximum {}",
        records.len(),
        params.max_claimed_receipt_root_leaves
    );

    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&security, relation.shape())?;

    let mut leaves = Vec::with_capacity(records.len());
    let mut nodes = Vec::with_capacity(records.len());
    for (leaf_index, record) in records.iter().enumerate() {
        ensure!(
            record.params_fingerprint == params.parameter_fingerprint(),
            "native tx-leaf record parameter fingerprint mismatch"
        );
        ensure!(
            record.spec_digest == params.spec_digest(),
            "native tx-leaf record spec digest mismatch"
        );
        ensure!(
            record.relation_id == relation.relation_id().0,
            "native tx-leaf record relation id mismatch"
        );
        ensure!(
            record.shape_digest == pk.shape_digest.0,
            "native tx-leaf record shape digest mismatch"
        );

        leaves.push(ReceiptRootLeaf {
            statement_digest: record.statement_digest,
            witness_commitment: record.commitment.digest,
            proof_digest: record.proof_digest,
        });
        nodes.push(ReceiptRootWorkNode {
            leaf_start: leaf_index,
            leaf_count: 1,
            instance: FoldedInstance {
                relation_id: relation.relation_id(),
                shape_digest: pk.shape_digest,
                statement_digest: superneo_ccs::StatementDigest(record.statement_digest),
                witness_commitment: record.commitment.clone(),
            },
        });
    }

    Ok((relation.relation_id().0, pk.shape_digest.0, leaves, nodes))
}

fn build_receipt_root_layers_from_nodes_with_params(
    params: &NativeBackendParams,
    mut current: Vec<ReceiptRootWorkNode>,
) -> Result<(
    Vec<ReceiptRootFoldStep>,
    Vec<Vec<ReceiptRootWorkNode>>,
    FoldedInstance<LatticeCommitment>,
)> {
    ensure!(
        !current.is_empty(),
        "native receipt-root hierarchy requires at least one work node"
    );

    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&security, relation.shape())?;

    let mut folds = Vec::new();
    let mut layers = vec![current.clone()];
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(&pk, &left.instance, &right.instance)?;
                folds.push(ReceiptRootFoldStep {
                    challenges: proof.challenges.clone(),
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    parent_rows: proof.parent_rows.clone(),
                    proof_digest: proof.proof_digest,
                });
                next.push(ReceiptRootWorkNode {
                    leaf_start: left.leaf_start,
                    leaf_count: left.leaf_count + right.leaf_count,
                    instance: parent,
                });
            } else {
                next.push(left);
            }
        }
        layers.push(next.clone());
        current = next;
    }

    let root = current
        .pop()
        .expect("non-empty native receipt-root hierarchy must retain one root");
    Ok((folds, layers, root.instance))
}

fn build_receipt_root_subtree_from_nodes_with_params(
    params: &NativeBackendParams,
    nodes: &[ReceiptRootWorkNode],
) -> Result<ReceiptRootWorkNode> {
    let (_, _, root) = build_receipt_root_layers_from_nodes_with_params(params, nodes.to_vec())?;
    Ok(ReceiptRootWorkNode {
        leaf_start: nodes
            .first()
            .expect("receipt-root subtree requires at least one node")
            .leaf_start,
        leaf_count: nodes.iter().map(|node| node.leaf_count).sum(),
        instance: root,
    })
}

pub fn native_receipt_root_leaf_instance_from_record(
    record: &NativeTxLeafRecord,
) -> Result<FoldedInstance<LatticeCommitment>> {
    native_receipt_root_leaf_instance_from_record_with_params(&native_backend_params(), record)
}

pub fn native_receipt_root_leaf_instance_from_record_with_params(
    params: &NativeBackendParams,
    record: &NativeTxLeafRecord,
) -> Result<FoldedInstance<LatticeCommitment>> {
    let (_, _, _, nodes) = native_receipt_root_leaf_nodes_from_records_with_params(
        params,
        std::slice::from_ref(record),
    )?;
    Ok(nodes
        .into_iter()
        .next()
        .expect("one record should yield one work node")
        .instance)
}

pub fn fold_native_receipt_root_instances(
    instances: &[FoldedInstance<LatticeCommitment>],
) -> Result<FoldedInstance<LatticeCommitment>> {
    fold_native_receipt_root_instances_with_params(&native_backend_params(), instances)
}

pub fn fold_native_receipt_root_instances_with_params(
    params: &NativeBackendParams,
    instances: &[FoldedInstance<LatticeCommitment>],
) -> Result<FoldedInstance<LatticeCommitment>> {
    ensure!(
        !instances.is_empty(),
        "native receipt-root folding requires at least one instance"
    );
    let mut nodes = instances
        .iter()
        .cloned()
        .enumerate()
        .map(|(leaf_start, instance)| ReceiptRootWorkNode {
            leaf_start,
            leaf_count: 1,
            instance,
        })
        .collect::<Vec<_>>();

    if let Some(first) = nodes.first() {
        for node in &nodes[1..] {
            ensure!(
                node.instance.relation_id == first.instance.relation_id,
                "native receipt-root instance relation id mismatch"
            );
            ensure!(
                node.instance.shape_digest == first.instance.shape_digest,
                "native receipt-root instance shape digest mismatch"
            );
        }
    }

    let (_, _, root) =
        build_receipt_root_layers_from_nodes_with_params(params, std::mem::take(&mut nodes))?;
    Ok(root)
}

pub fn build_native_receipt_root_hierarchy_from_records(
    records: &[NativeTxLeafRecord],
    mini_root_size: usize,
) -> Result<NativeReceiptRootHierarchyBuild> {
    build_native_receipt_root_hierarchy_from_records_with_params(
        &native_backend_params(),
        records,
        mini_root_size,
    )
}

pub fn build_native_receipt_root_hierarchy_from_records_with_params(
    params: &NativeBackendParams,
    records: &[NativeTxLeafRecord],
    mini_root_size: usize,
) -> Result<NativeReceiptRootHierarchyBuild> {
    ensure!(
        mini_root_size > 0,
        "native receipt-root hierarchy mini-root size must be strictly positive"
    );
    ensure!(
        mini_root_size.is_power_of_two(),
        "native receipt-root hierarchy mini-root size {} must be a power of two",
        mini_root_size
    );

    let (relation_id, shape_digest, _leaves, leaf_nodes) =
        native_receipt_root_leaf_nodes_from_records_with_params(params, records)?;
    let (folds, layers, root) =
        build_receipt_root_layers_from_nodes_with_params(params, leaf_nodes.clone())?;
    let mini_root_instances = leaf_nodes
        .chunks(mini_root_size)
        .map(|chunk| build_receipt_root_subtree_from_nodes_with_params(params, chunk))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|node| NativeReceiptRootChunkRoot {
            leaf_start: node.leaf_start as u32,
            leaf_count: node.leaf_count as u32,
            root: node.instance,
        })
        .collect::<Vec<_>>();

    let hierarchy = NativeReceiptRootHierarchy {
        params_fingerprint: params.parameter_fingerprint(),
        spec_digest: params.spec_digest(),
        relation_id,
        shape_digest,
        mini_root_size: mini_root_size as u32,
        leaf_count: records.len() as u32,
        mini_roots: mini_root_instances
            .iter()
            .map(|mini_root| NativeReceiptRootHierarchyNode {
                leaf_start: mini_root.leaf_start,
                leaf_count: mini_root.leaf_count,
                statement_digest: mini_root.root.statement_digest.0,
                commitment_digest: mini_root.root.witness_commitment.digest,
            })
            .collect(),
        layers: layers
            .iter()
            .enumerate()
            .map(
                |(level_index, level_nodes)| NativeReceiptRootHierarchyLayer {
                    level_index: level_index as u32,
                    nodes: level_nodes
                        .iter()
                        .map(ReceiptRootWorkNode::to_hierarchy_node)
                        .collect(),
                },
            )
            .collect(),
        fold_count: folds.len() as u32,
        root_statement_digest: root.statement_digest.0,
        root_commitment: root.witness_commitment.digest,
    };
    let metadata = ReceiptRootMetadata {
        params_fingerprint: params.parameter_fingerprint(),
        spec_digest: params.spec_digest(),
        relation_id,
        shape_digest,
        leaf_count: records.len() as u32,
        fold_count: folds.len() as u32,
    };
    Ok(NativeReceiptRootHierarchyBuild {
        metadata,
        hierarchy,
        mini_root_instances,
        root,
    })
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
    let backend = LatticeBackend::default();
    let security = backend.security_params();
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
    let witness = tx_leaf_public_witness_from_parts(
        tx,
        &artifact.stark_public_inputs,
        DEFAULT_TX_PROOF_BACKEND,
        None,
    );
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
    verify_native_tx_leaf_artifact_bytes_with_params(
        &native_backend_params(),
        tx,
        receipt,
        artifact_bytes,
    )
}

pub fn verify_native_tx_leaf_artifact_bytes_with_params(
    params: &NativeBackendParams,
    tx: &TxLeafPublicTx,
    receipt: &CanonicalTxValidityReceipt,
    artifact_bytes: &[u8],
) -> Result<NativeTxLeafMetadata> {
    let artifact = decode_native_tx_leaf_artifact_with_params(params, artifact_bytes)?;
    ensure!(
        artifact.version == native_tx_leaf_artifact_version(params),
        "unsupported native tx-leaf artifact version {}",
        artifact.version
    );
    ensure!(
        artifact.params_fingerprint == params.parameter_fingerprint(),
        "native tx-leaf parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == params.spec_digest(),
        "native tx-leaf spec digest mismatch"
    );

    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
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
        artifact.leaf.version == native_tx_leaf_artifact_version(params),
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
    ensure!(artifact.tx == *tx, "native tx-leaf public tx mismatch");
    ensure!(
        artifact.receipt == *receipt,
        "native tx-leaf canonical receipt mismatch"
    );
    ensure!(
        receipt.verifier_profile == experimental_native_tx_leaf_verifier_profile_for_params(params),
        "native tx-leaf receipt verifier profile mismatch"
    );
    let expected_backend =
        tx_proof_backend_for_version(tx.version).unwrap_or(DEFAULT_TX_PROOF_BACKEND);
    ensure!(
        artifact.proof_backend == expected_backend,
        "native tx-leaf proof backend mismatch"
    );
    ensure!(
        !artifact.stark_proof.is_empty(),
        "native tx-leaf proof bytes must not be empty"
    );

    let expected_receipt = native_tx_leaf_receipt_from_parts(
        tx,
        &artifact.stark_public_inputs,
        &artifact.stark_proof,
        artifact.proof_backend,
        params,
    )?;
    ensure!(
        artifact.receipt == expected_receipt,
        "native tx-leaf canonical receipt mismatch"
    );
    let p3_public_inputs =
        transaction_public_inputs_p3_from_tx_leaf_public(tx, &artifact.stark_public_inputs)?;
    verify_transaction_proof_bytes_for_backend(
        artifact.proof_backend,
        &artifact.stark_proof,
        &p3_public_inputs,
        tx.version,
    )
    .map_err(|err| anyhow::anyhow!("native tx-leaf proof verification failed: {err}"))?;

    let witness = tx_leaf_public_witness_from_parts(
        tx,
        &artifact.stark_public_inputs,
        artifact.proof_backend,
        smallwood_arithmetization_from_backend_and_proof_bytes(
            artifact.proof_backend,
            &artifact.stark_proof,
        )
        .map_err(|err| {
            anyhow::anyhow!("failed to decode native tx-leaf proof arithmetization: {err}")
        })?,
    );
    validate_native_tx_leaf_public_witness_with_params(params, receipt, &witness)?;
    let encoding = relation.encode_statement(receipt)?;
    let assignment = tx_leaf_public_witness_assignment(&witness)?;
    let packed = packer.pack(relation.shape(), &assignment)?;
    let expected_commitment = backend.commit_witness(&pk, &packed)?;
    ensure!(
        artifact.statement_digest == encoding.statement_digest.0,
        "native tx-leaf statement digest mismatch"
    );
    ensure!(
        artifact.leaf.statement_digest == encoding.statement_digest,
        "native tx-leaf inner statement digest mismatch"
    );
    ensure!(
        artifact.commitment == expected_commitment,
        "native tx-leaf commitment mismatch"
    );
    ensure!(
        artifact.leaf.proof.witness_commitment_digest == expected_commitment.digest,
        "native tx-leaf proof/commitment digest mismatch"
    );
    backend.verify_leaf(
        &vk,
        &relation.relation_id(),
        &encoding,
        &packed,
        &artifact.leaf.proof,
    )?;
    Ok(NativeTxLeafMetadata {
        params_fingerprint: artifact.params_fingerprint,
        spec_digest: artifact.spec_digest,
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        statement_digest: artifact.statement_digest,
        proof_backend: artifact.proof_backend,
        stark_public_inputs: artifact.stark_public_inputs,
        commitment: expected_commitment,
    })
}

fn verified_native_receipt_root_leaf_from_artifact_bytes_with_params(
    params: &NativeBackendParams,
    artifact: &NativeTxLeafArtifact,
    artifact_bytes: &[u8],
) -> Result<VerifiedNativeReceiptRootLeaf> {
    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&security, relation.shape())?;
    let tx = artifact.tx.clone();
    let receipt = artifact.receipt.clone();
    let metadata =
        verify_native_tx_leaf_artifact_bytes_with_params(params, &tx, &receipt, artifact_bytes)
            .map_err(|err| anyhow::anyhow!("native tx-leaf artifact verification failed: {err}"))?;
    ensure!(
        artifact.version == native_tx_leaf_artifact_version(params),
        "native tx-leaf artifact version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == params.parameter_fingerprint(),
        "native tx-leaf parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == params.spec_digest(),
        "native tx-leaf spec digest mismatch"
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
    Ok(VerifiedNativeReceiptRootLeaf {
        leaf: ReceiptRootLeaf {
            statement_digest: artifact.statement_digest,
            witness_commitment: metadata.commitment.digest,
            proof_digest: artifact.leaf.proof.proof_digest,
        },
        instance: FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: artifact.leaf.statement_digest,
            witness_commitment: metadata.commitment,
        },
    })
}

#[cfg(test)]
fn verified_native_receipt_root_leaf_from_artifact_with_params(
    params: &NativeBackendParams,
    artifact: &NativeTxLeafArtifact,
) -> Result<VerifiedNativeReceiptRootLeaf> {
    let artifact_bytes = encode_native_tx_leaf_artifact(artifact)?;
    verified_native_receipt_root_leaf_from_artifact_bytes_with_params(
        params,
        artifact,
        &artifact_bytes,
    )
}

fn cached_native_receipt_root_leaf_from_artifact_with_params(
    params: &NativeBackendParams,
    artifact: &NativeTxLeafArtifact,
) -> Result<CachedNativeReceiptRootLeaf> {
    let artifact_bytes = encode_native_tx_leaf_artifact(artifact)?;
    let artifact_hash = blake3_384_bytes(&artifact_bytes);
    if let Ok(mut guard) = NATIVE_RECEIPT_ROOT_LEAF_BUILD_CACHE.lock() {
        if let Some(verified) = guard.get(artifact_hash) {
            NATIVE_RECEIPT_ROOT_LEAF_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            return Ok(CachedNativeReceiptRootLeaf {
                artifact_hash,
                verified,
            });
        }
    }
    NATIVE_RECEIPT_ROOT_LEAF_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    let verified = verified_native_receipt_root_leaf_from_artifact_bytes_with_params(
        params,
        artifact,
        &artifact_bytes,
    )?;
    if let Ok(mut guard) = NATIVE_RECEIPT_ROOT_LEAF_BUILD_CACHE.lock() {
        guard.insert(artifact_hash, verified.clone());
    }
    Ok(CachedNativeReceiptRootLeaf {
        artifact_hash,
        verified,
    })
}

fn native_receipt_root_chunk_cache_key(
    params: &NativeBackendParams,
    child_hashes: &[[u8; 48]],
) -> [u8; 48] {
    let mut material = Vec::with_capacity(64 + (child_hashes.len() * 48));
    material.extend_from_slice(b"hegemon.native-receipt-root.chunk.v1");
    material.extend_from_slice(&params.parameter_fingerprint());
    material.extend_from_slice(&(child_hashes.len() as u32).to_le_bytes());
    for child_hash in child_hashes {
        material.extend_from_slice(child_hash);
    }
    blake3_384_bytes(&material)
}

fn build_receipt_root_chunk_levels(
    backend: &LatticeBackend,
    pk: &NativeReceiptRootProverKey,
    leaves: &[NativeReceiptRootInstance],
) -> Result<ReceiptRootChunkBuild> {
    ensure!(
        !leaves.is_empty(),
        "native receipt-root mini-root requires at least one leaf"
    );
    let mut current = leaves.to_vec();
    let mut level_folds = Vec::new();

    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut level = Vec::with_capacity(current.len() / 2);
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(pk, &left, &right)?;
                level.push(ReceiptRootFoldStep {
                    challenges: proof.challenges.clone(),
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    parent_rows: proof.parent_rows.clone(),
                    proof_digest: proof.proof_digest,
                });
                next.push(parent);
            } else {
                next.push(left);
            }
        }
        level_folds.push(level);
        current = next;
    }

    Ok(ReceiptRootChunkBuild {
        root: current
            .pop()
            .expect("chunk builder retains one root for non-empty leaves"),
        level_folds,
    })
}

fn build_native_receipt_root_artifact_from_verified_leaves_with_params(
    params: &NativeBackendParams,
    pk: &NativeReceiptRootProverKey,
    relation: &TxLeafPublicRelation,
    backend: &LatticeBackend,
    verified_leaves: &[CachedNativeReceiptRootLeaf],
) -> Result<BuiltReceiptRootArtifact> {
    let leaves = verified_leaves
        .iter()
        .map(|verified| verified.verified.leaf.clone())
        .collect::<Vec<_>>();
    let jobs = verified_leaves
        .chunks(native_receipt_root_mini_root_size())
        .map(|chunk| {
            let child_hashes = chunk
                .iter()
                .map(|verified| verified.artifact_hash)
                .collect::<Vec<_>>();
            let leaves = chunk
                .iter()
                .map(|verified| verified.verified.instance.clone())
                .collect::<Vec<_>>();
            (child_hashes, leaves)
        })
        .collect::<Vec<_>>();

    let chunk_builds = jobs
        .par_iter()
        .map(|(child_hashes, leaves)| {
            let cache_key = native_receipt_root_chunk_cache_key(params, child_hashes);
            if let Ok(mut guard) = NATIVE_RECEIPT_ROOT_CHUNK_BUILD_CACHE.lock() {
                if let Some(cached) = guard.get(cache_key) {
                    NATIVE_RECEIPT_ROOT_CHUNK_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
                    return Ok(cached);
                }
            }
            NATIVE_RECEIPT_ROOT_CHUNK_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
            let built = build_receipt_root_chunk_levels(backend, pk, leaves)?;
            if let Ok(mut guard) = NATIVE_RECEIPT_ROOT_CHUNK_BUILD_CACHE.lock() {
                guard.insert(cache_key, built.clone());
            }
            Ok(built)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>>>()?;

    let mut folds = Vec::with_capacity(verified_leaves.len().saturating_sub(1));
    let max_internal_levels = chunk_builds
        .iter()
        .map(|chunk| chunk.level_folds.len())
        .max()
        .unwrap_or(0);
    for level_index in 0..max_internal_levels {
        for chunk in &chunk_builds {
            if let Some(level) = chunk.level_folds.get(level_index) {
                folds.extend(level.iter().cloned());
            }
        }
    }

    let mut current = chunk_builds
        .iter()
        .map(|chunk| chunk.root.clone())
        .collect::<Vec<_>>();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(pk, &left, &right)?;
                folds.push(ReceiptRootFoldStep {
                    challenges: proof.challenges.clone(),
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    parent_rows: proof.parent_rows.clone(),
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
        .expect("non-empty native receipt-root leaf set retains one root");
    let artifact = ReceiptRootArtifact {
        version: receipt_root_artifact_version(params),
        params_fingerprint: params.parameter_fingerprint(),
        spec_digest: params.spec_digest(),
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
            params_fingerprint: artifact.params_fingerprint,
            spec_digest: artifact.spec_digest,
            relation_id: artifact.relation_id,
            shape_digest: artifact.shape_digest,
            leaf_count: artifact.leaves.len() as u32,
            fold_count: folds.len() as u32,
        },
    })
}

pub fn build_native_tx_leaf_receipt_root_artifact_bytes(
    artifacts: &[NativeTxLeafArtifact],
) -> Result<BuiltReceiptRootArtifact> {
    build_native_tx_leaf_receipt_root_artifact_bytes_with_params(
        &native_backend_params(),
        artifacts,
    )
}

pub fn build_native_tx_leaf_receipt_root_artifact_bytes_with_params(
    params: &NativeBackendParams,
    artifacts: &[NativeTxLeafArtifact],
) -> Result<BuiltReceiptRootArtifact> {
    ensure!(
        !artifacts.is_empty(),
        "native receipt-root artifact requires at least one tx-leaf artifact"
    );
    ensure!(
        artifacts.len() <= params.max_claimed_receipt_root_leaves as usize,
        "native receipt-root leaf count {} exceeds claimed maximum {}",
        artifacts.len(),
        params.max_claimed_receipt_root_leaves
    );

    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&security, relation.shape())?;
    let verified_leaves = artifacts
        .par_iter()
        .map(|artifact| cached_native_receipt_root_leaf_from_artifact_with_params(params, artifact))
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    build_native_receipt_root_artifact_from_verified_leaves_with_params(
        params,
        &pk,
        &relation,
        &backend,
        &verified_leaves,
    )
}

pub fn verify_native_tx_leaf_receipt_root_artifact_bytes(
    artifacts: &[NativeTxLeafArtifact],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata> {
    verify_native_tx_leaf_receipt_root_artifact_bytes_with_params(
        &native_backend_params(),
        artifacts,
        artifact_bytes,
    )
}

pub fn verify_native_tx_leaf_receipt_root_artifact_bytes_with_params(
    params: &NativeBackendParams,
    artifacts: &[NativeTxLeafArtifact],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata> {
    ensure!(
        !artifacts.is_empty(),
        "native receipt-root artifact requires at least one tx-leaf artifact"
    );
    ensure!(
        artifacts.len() <= params.max_claimed_receipt_root_leaves as usize,
        "native receipt-root leaf count {} exceeds claimed maximum {}",
        artifacts.len(),
        params.max_claimed_receipt_root_leaves
    );
    let artifact = decode_receipt_root_artifact_with_params(params, artifact_bytes)?;
    ensure!(
        artifact.version == receipt_root_artifact_version(params),
        "unsupported receipt-root artifact version {}",
        artifact.version
    );
    ensure!(
        artifact.params_fingerprint == params.parameter_fingerprint(),
        "native receipt-root parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == params.spec_digest(),
        "native receipt-root spec digest mismatch"
    );

    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
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
    ensure!(
        artifact.leaves.len() <= params.max_claimed_receipt_root_leaves as usize,
        "native receipt-root leaf count {} exceeds claimed maximum {}",
        artifact.leaves.len(),
        params.max_claimed_receipt_root_leaves
    );

    let mut current = Vec::with_capacity(artifacts.len());
    for (native_artifact, leaf) in artifacts.iter().zip(&artifact.leaves) {
        let tx = native_artifact.tx.clone();
        let receipt = native_artifact.receipt.clone();
        let metadata = verify_native_tx_leaf_artifact_bytes_with_params(
            params,
            &tx,
            &receipt,
            &encode_native_tx_leaf_artifact(native_artifact)?,
        )?;
        ensure!(
            native_artifact.version == native_tx_leaf_artifact_version(params),
            "native tx-leaf artifact version mismatch"
        );
        ensure!(
            native_artifact.params_fingerprint == params.parameter_fingerprint(),
            "native tx-leaf parameter fingerprint mismatch"
        );
        ensure!(
            native_artifact.spec_digest == params.spec_digest(),
            "native tx-leaf spec digest mismatch"
        );
        ensure!(
            leaf.statement_digest == native_artifact.statement_digest,
            "native receipt-root leaf statement digest mismatch"
        );
        ensure!(
            leaf.witness_commitment == metadata.commitment.digest,
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
            witness_commitment: metadata.commitment,
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
                let (parent, expected_proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.challenges == expected_proof.challenges,
                    "native receipt-root fold challenge vector mismatch"
                );
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "native receipt-root fold parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "native receipt-root fold parent commitment mismatch"
                );
                ensure!(
                    fold.parent_rows == expected_proof.parent_rows,
                    "native receipt-root fold parent rows mismatch"
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
        params_fingerprint: artifact.params_fingerprint,
        spec_digest: artifact.spec_digest,
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        leaf_count: artifact.leaves.len() as u32,
        fold_count: artifact.folds.len() as u32,
    })
}

pub fn decode_receipt_root_artifact_bytes(artifact_bytes: &[u8]) -> Result<ReceiptRootArtifact> {
    decode_receipt_root_artifact_with_params(&native_backend_params(), artifact_bytes)
}

pub fn encode_receipt_root_artifact_bytes(artifact: &ReceiptRootArtifact) -> Vec<u8> {
    encode_receipt_root_artifact(artifact)
}

pub fn verify_native_tx_leaf_receipt_root_artifact_from_records(
    records: &[NativeTxLeafRecord],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata> {
    verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(
        &native_backend_params(),
        records,
        artifact_bytes,
    )
}

pub fn verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(
    params: &NativeBackendParams,
    records: &[NativeTxLeafRecord],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata> {
    ensure!(
        !records.is_empty(),
        "native receipt-root artifact requires at least one tx-leaf record"
    );
    ensure!(
        records.len() <= params.max_claimed_receipt_root_leaves as usize,
        "native receipt-root leaf count {} exceeds claimed maximum {}",
        records.len(),
        params.max_claimed_receipt_root_leaves
    );
    let artifact = decode_receipt_root_artifact_with_params(params, artifact_bytes)?;
    ensure!(
        artifact.version == receipt_root_artifact_version(params),
        "unsupported receipt-root artifact version {}",
        artifact.version
    );
    ensure!(
        artifact.params_fingerprint == params.parameter_fingerprint(),
        "native receipt-root parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == params.spec_digest(),
        "native receipt-root spec digest mismatch"
    );

    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
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
        artifact.leaves.len() == records.len(),
        "native receipt-root leaf count {} does not match tx-leaf records {}",
        artifact.leaves.len(),
        records.len()
    );
    ensure!(
        artifact.leaves.len() <= params.max_claimed_receipt_root_leaves as usize,
        "native receipt-root leaf count {} exceeds claimed maximum {}",
        artifact.leaves.len(),
        params.max_claimed_receipt_root_leaves
    );

    let mut current = Vec::with_capacity(records.len());
    for (record, leaf) in records.iter().zip(&artifact.leaves) {
        ensure!(
            record.params_fingerprint == params.parameter_fingerprint(),
            "native tx-leaf record parameter fingerprint mismatch"
        );
        ensure!(
            record.spec_digest == params.spec_digest(),
            "native tx-leaf record spec digest mismatch"
        );
        ensure!(
            record.relation_id == relation.relation_id().0,
            "native tx-leaf record relation id mismatch"
        );
        ensure!(
            record.shape_digest == pk.shape_digest.0,
            "native tx-leaf record shape digest mismatch"
        );
        ensure!(
            leaf.statement_digest == record.statement_digest,
            "native receipt-root leaf statement digest mismatch"
        );
        ensure!(
            leaf.witness_commitment == record.commitment.digest,
            "native receipt-root leaf commitment mismatch"
        );
        ensure!(
            leaf.proof_digest == record.proof_digest,
            "native receipt-root leaf proof digest mismatch"
        );
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: superneo_ccs::StatementDigest(record.statement_digest),
            witness_commitment: record.commitment.clone(),
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
                let (parent, expected_proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.challenges == expected_proof.challenges,
                    "native receipt-root fold challenge vector mismatch"
                );
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "native receipt-root fold parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "native receipt-root fold parent commitment mismatch"
                );
                ensure!(
                    fold.parent_rows == expected_proof.parent_rows,
                    "native receipt-root fold parent rows mismatch"
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
        params_fingerprint: artifact.params_fingerprint,
        spec_digest: artifact.spec_digest,
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
    let backend = LatticeBackend::default();
    let security = backend.security_params();
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

    let params = native_backend_params();
    let mut folds = Vec::new();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                folds.push(ReceiptRootFoldStep {
                    challenges: proof.challenges.clone(),
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    parent_rows: proof.parent_rows.clone(),
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
        version: receipt_root_artifact_version(&params),
        params_fingerprint: params.parameter_fingerprint(),
        spec_digest: params.spec_digest(),
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
            params_fingerprint: artifact.params_fingerprint,
            spec_digest: artifact.spec_digest,
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
    let backend = LatticeBackend::default();
    let security = backend.security_params();
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

    let params = native_backend_params();
    let mut folds = Vec::new();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                folds.push(ReceiptRootFoldStep {
                    challenges: proof.challenges.clone(),
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    parent_rows: proof.parent_rows.clone(),
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
        version: receipt_root_artifact_version(&params),
        params_fingerprint: params.parameter_fingerprint(),
        spec_digest: params.spec_digest(),
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
            params_fingerprint: artifact.params_fingerprint,
            spec_digest: artifact.spec_digest,
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
    let params = native_backend_params();
    ensure!(
        artifact.version == receipt_root_artifact_version(&params),
        "unsupported receipt-root artifact version {}",
        artifact.version
    );
    ensure!(
        artifact.params_fingerprint == params.parameter_fingerprint(),
        "receipt-root parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == params.spec_digest(),
        "receipt-root spec digest mismatch"
    );

    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::default();
    let security = backend.security_params();
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
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.challenges == proof.challenges,
                    "receipt-root fold challenge vector mismatch"
                );
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "receipt-root fold parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "receipt-root fold parent commitment mismatch"
                );
                ensure!(
                    fold.parent_rows == proof.parent_rows,
                    "receipt-root fold parent rows mismatch"
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
        params_fingerprint: artifact.params_fingerprint,
        spec_digest: artifact.spec_digest,
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
    let params = native_backend_params();
    ensure!(
        artifact.version == receipt_root_artifact_version(&params),
        "unsupported receipt-root artifact version {}",
        artifact.version
    );
    ensure!(
        artifact.params_fingerprint == params.parameter_fingerprint(),
        "receipt-root parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == params.spec_digest(),
        "receipt-root spec digest mismatch"
    );

    let relation = CanonicalTxValidityReceiptRelation::default();
    let backend = LatticeBackend::default();
    let security = backend.security_params();
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
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.challenges == proof.challenges,
                    "receipt-root fold challenge vector mismatch"
                );
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "receipt-root fold parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "receipt-root fold parent commitment mismatch"
                );
                ensure!(
                    fold.parent_rows == proof.parent_rows,
                    "receipt-root fold parent rows mismatch"
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
        params_fingerprint: artifact.params_fingerprint,
        spec_digest: artifact.spec_digest,
        relation_id: artifact.relation_id,
        shape_digest: artifact.shape_digest,
        leaf_count: artifact.leaves.len() as u32,
        fold_count: artifact.folds.len() as u32,
    })
}

fn encode_receipt_root_artifact(artifact: &ReceiptRootArtifact) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&artifact.version.to_le_bytes());
    bytes.extend_from_slice(&artifact.params_fingerprint);
    bytes.extend_from_slice(&artifact.spec_digest);
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
        bytes.extend_from_slice(&(fold.challenges.len() as u32).to_le_bytes());
        for challenge in &fold.challenges {
            bytes.extend_from_slice(&challenge.to_le_bytes());
        }
        bytes.extend_from_slice(&fold.parent_statement_digest);
        bytes.extend_from_slice(&fold.parent_commitment);
        bytes.extend_from_slice(&(fold.parent_rows.len() as u32).to_le_bytes());
        for row in &fold.parent_rows {
            bytes.extend_from_slice(&(row.coeffs.len() as u32).to_le_bytes());
            for coeff in &row.coeffs {
                bytes.extend_from_slice(&coeff.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&fold.proof_digest);
    }
    bytes.extend_from_slice(&artifact.root_statement_digest);
    bytes.extend_from_slice(&artifact.root_commitment);
    bytes
}

fn encode_native_tx_leaf_artifact(artifact: &NativeTxLeafArtifact) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&artifact.version.to_le_bytes());
    bytes.extend_from_slice(&artifact.params_fingerprint);
    bytes.extend_from_slice(&artifact.spec_digest);
    bytes.extend_from_slice(&artifact.relation_id);
    bytes.extend_from_slice(&artifact.shape_digest);
    bytes.extend_from_slice(&artifact.statement_digest);
    encode_canonical_receipt(&mut bytes, &artifact.receipt);
    encode_serialized_stark_inputs(&mut bytes, &artifact.stark_public_inputs)?;
    encode_tx_leaf_public_tx(&mut bytes, &artifact.tx)?;
    ensure!(
        artifact.stark_proof.len() <= MAX_NATIVE_TX_STARK_PROOF_BYTES,
        "native tx-leaf proof bytes {} exceed {}",
        artifact.stark_proof.len(),
        MAX_NATIVE_TX_STARK_PROOF_BYTES
    );
    bytes.extend_from_slice(&(artifact.stark_proof.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&artifact.stark_proof);
    encode_lattice_commitment(&mut bytes, &artifact.commitment)?;
    encode_leaf_artifact(&mut bytes, &artifact.leaf);
    bytes.push(artifact.proof_backend.wire_id());
    Ok(bytes)
}

fn decode_native_tx_leaf_artifact_with_params(
    params: &NativeBackendParams,
    bytes: &[u8],
) -> Result<NativeTxLeafArtifact> {
    ensure!(
        bytes.len() <= max_native_tx_leaf_artifact_bytes_with_params(params),
        "native tx-leaf artifact size {} exceeds {}",
        bytes.len(),
        max_native_tx_leaf_artifact_bytes_with_params(params)
    );
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let params_fingerprint = read_array::<48>(bytes, &mut cursor)?;
    let spec_digest = read_array::<32>(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let statement_digest = read_array::<48>(bytes, &mut cursor)?;
    let receipt = decode_canonical_receipt(bytes, &mut cursor)?;
    let stark_public_inputs = decode_serialized_stark_inputs(bytes, &mut cursor)?;
    let tx = decode_tx_leaf_public_tx(bytes, &mut cursor)?;
    let proof_len = read_u32_capped(
        bytes,
        &mut cursor,
        MAX_NATIVE_TX_STARK_PROOF_BYTES,
        "native tx-leaf proof bytes",
    )? as usize;
    let stark_proof = read_bytes(bytes, &mut cursor, proof_len)?;
    let commitment = decode_lattice_commitment_with_params(params, bytes, &mut cursor)?;
    let leaf = decode_leaf_artifact(bytes, &mut cursor)?;
    let proof_backend = if cursor < bytes.len() {
        let wire = read_u8(bytes, &mut cursor)?;
        TxProofBackend::try_from(wire)
            .map_err(|_| anyhow::anyhow!("unsupported native tx-leaf proof backend {wire}"))?
    } else {
        tx_proof_backend_for_version(tx.version).unwrap_or(DEFAULT_TX_PROOF_BACKEND)
    };
    ensure!(
        cursor == bytes.len(),
        "native tx-leaf artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(NativeTxLeafArtifact {
        version,
        params_fingerprint,
        spec_digest,
        relation_id,
        shape_digest,
        statement_digest,
        receipt,
        stark_public_inputs,
        tx,
        proof_backend,
        stark_proof,
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
    let input_flag_count =
        read_u32_capped(bytes, cursor, MAX_INPUTS, "serialized STARK input flags")? as usize;
    let input_flags = read_bytes(bytes, cursor, input_flag_count)?;
    let output_flag_count =
        read_u32_capped(bytes, cursor, MAX_OUTPUTS, "serialized STARK output flags")? as usize;
    let output_flags = read_bytes(bytes, cursor, output_flag_count)?;
    let fee = read_u64(bytes, cursor)?;
    let value_balance_sign = read_u8(bytes, cursor)?;
    let value_balance_magnitude = read_u64(bytes, cursor)?;
    let merkle_root = read_array::<48>(bytes, cursor)?;
    let balance_slot_count = read_u32_capped(
        bytes,
        cursor,
        BALANCE_SLOTS,
        "serialized STARK balance slots",
    )? as usize;
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

fn encode_tx_leaf_public_tx(bytes: &mut Vec<u8>, tx: &TxLeafPublicTx) -> Result<()> {
    ensure!(
        tx.nullifiers.len() <= MAX_INPUTS,
        "native tx-leaf nullifier count {} exceeds {}",
        tx.nullifiers.len(),
        MAX_INPUTS
    );
    ensure!(
        tx.commitments.len() <= MAX_OUTPUTS,
        "native tx-leaf commitment count {} exceeds {}",
        tx.commitments.len(),
        MAX_OUTPUTS
    );
    ensure!(
        tx.ciphertext_hashes.len() <= MAX_OUTPUTS,
        "native tx-leaf ciphertext hash count {} exceeds {}",
        tx.ciphertext_hashes.len(),
        MAX_OUTPUTS
    );
    bytes.extend_from_slice(&(tx.nullifiers.len() as u32).to_le_bytes());
    for value in &tx.nullifiers {
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&(tx.commitments.len() as u32).to_le_bytes());
    for value in &tx.commitments {
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&(tx.ciphertext_hashes.len() as u32).to_le_bytes());
    for value in &tx.ciphertext_hashes {
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&tx.balance_tag);
    bytes.extend_from_slice(&tx.version.circuit.to_le_bytes());
    bytes.extend_from_slice(&tx.version.crypto.to_le_bytes());
    Ok(())
}

fn decode_tx_leaf_public_tx(bytes: &[u8], cursor: &mut usize) -> Result<TxLeafPublicTx> {
    let nullifier_count =
        read_u32_capped(bytes, cursor, MAX_INPUTS, "native tx-leaf nullifiers")? as usize;
    let mut nullifiers = Vec::with_capacity(nullifier_count);
    for _ in 0..nullifier_count {
        nullifiers.push(read_array::<48>(bytes, cursor)?);
    }
    let commitment_count =
        read_u32_capped(bytes, cursor, MAX_OUTPUTS, "native tx-leaf commitments")? as usize;
    let mut commitments = Vec::with_capacity(commitment_count);
    for _ in 0..commitment_count {
        commitments.push(read_array::<48>(bytes, cursor)?);
    }
    let ciphertext_hash_count = read_u32_capped(
        bytes,
        cursor,
        MAX_OUTPUTS,
        "native tx-leaf ciphertext hashes",
    )? as usize;
    let mut ciphertext_hashes = Vec::with_capacity(ciphertext_hash_count);
    for _ in 0..ciphertext_hash_count {
        ciphertext_hashes.push(read_array::<48>(bytes, cursor)?);
    }
    Ok(TxLeafPublicTx {
        nullifiers,
        commitments,
        ciphertext_hashes,
        balance_tag: read_array::<48>(bytes, cursor)?,
        version: VersionBinding {
            circuit: read_u16(bytes, cursor)?,
            crypto: read_u16(bytes, cursor)?,
        },
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

fn decode_lattice_commitment_with_params(
    params: &NativeBackendParams,
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<LatticeCommitment> {
    let digest = read_array::<48>(bytes, cursor)?;
    let row_count = read_u32_capped(
        bytes,
        cursor,
        params.matrix_rows,
        "native tx-leaf commitment rows",
    )? as usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let coeff_count = read_u32_capped(
            bytes,
            cursor,
            params.matrix_cols,
            "native tx-leaf commitment row coefficients",
        )? as usize;
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
    decode_receipt_root_artifact_with_params(&native_backend_params(), bytes)
}

fn decode_receipt_root_artifact_with_params(
    params: &NativeBackendParams,
    bytes: &[u8],
) -> Result<ReceiptRootArtifact> {
    ensure!(
        bytes.len()
            <= max_native_receipt_root_artifact_bytes_with_params(
                params.max_claimed_receipt_root_leaves as usize,
                params,
            ),
        "receipt-root artifact size {} exceeds {}",
        bytes.len(),
        max_native_receipt_root_artifact_bytes_with_params(
            params.max_claimed_receipt_root_leaves as usize,
            params,
        )
    );
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor)?;
    let params_fingerprint = read_array::<48>(bytes, &mut cursor)?;
    let spec_digest = read_array::<32>(bytes, &mut cursor)?;
    let relation_id = read_array::<32>(bytes, &mut cursor)?;
    let shape_digest = read_array::<32>(bytes, &mut cursor)?;
    let leaf_count = read_u32_capped(
        bytes,
        &mut cursor,
        params.max_claimed_receipt_root_leaves as usize,
        "receipt-root leaves",
    )? as usize;
    let fold_count = read_u32_capped(
        bytes,
        &mut cursor,
        params.max_claimed_receipt_root_leaves.saturating_sub(1) as usize,
        "receipt-root folds",
    )? as usize;
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
        let challenge_count = read_u32_capped(
            bytes,
            &mut cursor,
            params.fold_challenge_count as usize,
            "receipt-root fold challenges",
        )? as usize;
        let mut challenges = Vec::with_capacity(challenge_count);
        for _ in 0..challenge_count {
            challenges.push(read_u64(bytes, &mut cursor)?);
        }
        let parent_statement_digest = read_array::<48>(bytes, &mut cursor)?;
        let parent_commitment = read_array::<48>(bytes, &mut cursor)?;
        let row_count = read_u32_capped(
            bytes,
            &mut cursor,
            params.matrix_rows,
            "receipt-root fold rows",
        )? as usize;
        let mut parent_rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            let coeff_count = read_u32_capped(
                bytes,
                &mut cursor,
                params.matrix_cols,
                "receipt-root fold row coefficients",
            )? as usize;
            let mut coeffs = Vec::with_capacity(coeff_count);
            for _ in 0..coeff_count {
                coeffs.push(read_u64(bytes, &mut cursor)?);
            }
            parent_rows.push(RingElem::from_coeffs(coeffs));
        }
        folds.push(ReceiptRootFoldStep {
            challenges,
            parent_statement_digest,
            parent_commitment,
            parent_rows,
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
        params_fingerprint,
        spec_digest,
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

fn read_u32_capped(bytes: &[u8], cursor: &mut usize, cap: usize, label: &str) -> Result<u32> {
    let value = read_u32(bytes, cursor)? as usize;
    ensure!(value <= cap, "{label} count {} exceeds {}", value, cap);
    Ok(value as u32)
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

#[cfg(test)]
fn build_native_tx_leaf_receipt_root_artifact_bytes_with_params_serial(
    params: &NativeBackendParams,
    artifacts: &[NativeTxLeafArtifact],
) -> Result<BuiltReceiptRootArtifact> {
    ensure!(
        !artifacts.is_empty(),
        "native receipt-root artifact requires at least one tx-leaf artifact"
    );
    ensure!(
        artifacts.len() <= params.max_claimed_receipt_root_leaves as usize,
        "native receipt-root leaf count {} exceeds claimed maximum {}",
        artifacts.len(),
        params.max_claimed_receipt_root_leaves
    );

    let relation = TxLeafPublicRelation::default();
    let security = params.security_params();
    let backend = LatticeBackend::new(params.clone());
    let (pk, _) = backend.setup(&security, relation.shape())?;
    let verified_leaves = artifacts
        .iter()
        .map(|artifact| {
            verified_native_receipt_root_leaf_from_artifact_with_params(params, artifact)
        })
        .collect::<Result<Vec<_>>>()?;
    let leaves = verified_leaves
        .iter()
        .map(|verified| verified.leaf.clone())
        .collect::<Vec<_>>();
    let mut current = verified_leaves
        .into_iter()
        .map(|verified| verified.instance)
        .collect::<Vec<_>>();
    let mut folds = Vec::with_capacity(current.len().saturating_sub(1));
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let (parent, proof) = backend.fold_pair(&pk, &left, &right)?;
                folds.push(ReceiptRootFoldStep {
                    challenges: proof.challenges.clone(),
                    parent_statement_digest: parent.statement_digest.0,
                    parent_commitment: parent.witness_commitment.digest,
                    parent_rows: proof.parent_rows.clone(),
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
        .expect("non-empty native receipt-root leaf set retains one root");
    let artifact = ReceiptRootArtifact {
        version: receipt_root_artifact_version(params),
        params_fingerprint: params.parameter_fingerprint(),
        spec_digest: params.spec_digest(),
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
            params_fingerprint: artifact.params_fingerprint,
            spec_digest: artifact.spec_digest,
            relation_id: artifact.relation_id,
            shape_digest: artifact.shape_digest,
            leaf_count: artifact.leaves.len() as u32,
            fold_count: folds.len() as u32,
        },
    })
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
    use std::{fs, path::PathBuf};

    use protocol_versioning::{
        LEGACY_PLONKY3_FRI_VERSION_BINDING, SMALLWOOD_CANDIDATE_VERSION_BINDING,
    };
    use superneo_backend_lattice::BackendManifest;
    use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};
    use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
    use transaction_circuit::hashing_pq::{felts_to_bytes48, merkle_node, HashFelt};
    use transaction_circuit::keys::generate_keys;
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::{
        prove_smallwood_candidate, StablecoinPolicyBinding, TransactionWitness,
    };

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
    fn tx_leaf_public_witness_accepts_smallwood_direct_profile_digest() {
        let mut proof = sample_transaction_proof(70);
        proof.backend = TxProofBackend::SmallwoodCandidate;
        proof.stark_proof = bincode::serialize(
            &transaction_circuit::smallwood_frontend::SmallwoodCandidateProof {
                arithmetization: SmallwoodArithmetization::DirectPacked64V1,
                ark_proof: vec![1, 2, 3, 4],
            },
        )
        .unwrap();
        let receipt = canonical_tx_validity_receipt_from_transaction_proof(&proof).unwrap();
        let witness = tx_leaf_public_witness_from_transaction_proof(&proof).unwrap();
        validate_tx_leaf_public_witness(&receipt, &witness).unwrap();
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
    fn native_tx_leaf_artifact_round_trip() {
        let witness = sample_witness(18);
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let built = sample_native_tx_leaf_artifact(18);
        let metadata =
            verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &built.artifact_bytes)
                .unwrap();
        assert_eq!(
            metadata.params_fingerprint,
            native_backend_params().parameter_fingerprint()
        );
        assert_eq!(metadata.spec_digest, native_backend_params().spec_digest());
        assert_eq!(metadata.proof_backend, TxProofBackend::Plonky3Fri);
    }

    #[test]
    fn native_tx_leaf_artifact_defaults_missing_backend_byte_to_plonky3() {
        let witness = sample_witness(19);
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let built = sample_native_tx_leaf_artifact(19);
        let mut legacy_bytes = built.artifact_bytes.clone();
        legacy_bytes.pop().expect("proof backend byte");
        let metadata =
            verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &legacy_bytes).unwrap();
        assert_eq!(metadata.proof_backend, TxProofBackend::Plonky3Fri);
    }

    #[test]
    #[ignore = "experimental SmallWood release proving is still too slow for the default test lane"]
    fn native_tx_leaf_artifact_accepts_smallwood_candidate_backend() {
        let mut witness = sample_witness(20);
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let proof = prove_smallwood_candidate(&witness).unwrap();
        let built = build_native_tx_leaf_artifact_from_transaction_proof_with_params(
            &native_backend_params(),
            &proof,
        )
        .unwrap();
        let metadata =
            verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &built.artifact_bytes)
                .unwrap();
        assert_eq!(metadata.proof_backend, TxProofBackend::SmallwoodCandidate);
    }

    #[test]
    #[ignore = "experimental SmallWood release proving is still too slow for the default test lane"]
    fn native_tx_leaf_artifact_rejects_tampered_smallwood_candidate_backend() {
        let mut witness = sample_witness(44);
        witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let proof = prove_smallwood_candidate(&witness).unwrap();
        let built = build_native_tx_leaf_artifact_from_transaction_proof_with_params(
            &native_backend_params(),
            &proof,
        )
        .unwrap();
        let mut artifact = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).unwrap();
        artifact.stark_proof[0] ^= 0x5a;
        let tampered = encode_native_tx_leaf_artifact(&artifact).unwrap();
        let err = verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &tampered)
            .expect_err("tampered smallwood candidate must fail");
        assert!(
            err.to_string().contains("smallwood") || err.to_string().contains("mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[ignore = "experimental SmallWood release proving is still too slow for the default test lane"]
    fn native_receipt_root_accepts_smallwood_candidate_leaf_record() {
        let mut smallwood_witness = sample_witness(45);
        smallwood_witness.version = SMALLWOOD_CANDIDATE_VERSION_BINDING;
        let smallwood_proof = prove_smallwood_candidate(&smallwood_witness).unwrap();
        let smallwood_leaf = build_native_tx_leaf_artifact_from_transaction_proof_with_params(
            &native_backend_params(),
            &smallwood_proof,
        )
        .unwrap();
        let plonky3_leaf = sample_native_tx_leaf_artifact(46);
        let artifacts = vec![
            decode_native_tx_leaf_artifact_bytes(&smallwood_leaf.artifact_bytes).unwrap(),
            decode_native_tx_leaf_artifact_bytes(&plonky3_leaf.artifact_bytes).unwrap(),
        ];
        let built = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        let metadata =
            verify_native_tx_leaf_receipt_root_artifact_bytes(&artifacts, &built.artifact_bytes)
                .unwrap();
        assert_eq!(metadata.leaf_count, 2);
    }

    #[test]
    fn native_tx_leaf_commitment_stats_match_current_relation() {
        let stats = native_tx_leaf_commitment_stats();
        assert_eq!(stats.witness_bits, 4_935);
        assert_eq!(stats.digit_bits, 8);
        assert_eq!(stats.packed_digits, 617);
        assert_eq!(stats.ring_degree, 54);
        assert_eq!(stats.live_message_ring_elems, 12);
        assert_eq!(stats.live_coefficient_dimension, 648);
        assert_eq!(stats.live_problem_coeff_bound, 255);
        assert_eq!(stats.live_problem_l2_bound, 6_492);
    }

    #[test]
    fn native_tx_leaf_rejects_tampered_stark_proof() {
        let witness = sample_witness(19);
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let built = sample_native_tx_leaf_artifact(19);
        let mut artifact = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).unwrap();
        artifact.stark_proof[0] ^= 0x5a;
        let tampered = encode_native_tx_leaf_artifact(&artifact).unwrap();
        assert!(verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &tampered).is_err());
    }

    #[test]
    fn native_tx_leaf_rejects_oversized_stark_proof_bytes() {
        let built = sample_native_tx_leaf_artifact(39);
        let mut artifact = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).unwrap();
        artifact.stark_proof = vec![0u8; MAX_NATIVE_TX_STARK_PROOF_BYTES + 1];
        let err = encode_native_tx_leaf_artifact(&artifact).unwrap_err();
        assert!(
            err.to_string().contains("proof bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn native_tx_leaf_rejects_malformed_commitment() {
        let witness = sample_witness(20);
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let built = sample_native_tx_leaf_artifact(20);
        let mut artifact = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).unwrap();
        artifact.commitment.rows[0].coeffs[0] ^= 1;
        let tampered = encode_native_tx_leaf_artifact(&artifact).unwrap();
        assert!(verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &tampered).is_err());
    }

    #[test]
    fn native_tx_leaf_rejects_mixed_parameter_set() {
        let witness = sample_witness(21);
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let params = alternate_native_backend_params();
        let built = build_native_tx_leaf_artifact_from_transaction_proof_with_params(
            &params,
            &sample_transaction_proof(21),
        )
        .unwrap();
        assert!(
            verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &built.artifact_bytes)
                .is_err()
        );
    }

    #[test]
    fn native_tx_leaf_rejects_spec_digest_mismatch() {
        let witness = sample_witness(22);
        let tx = tx_leaf_public_tx_from_witness(&witness).unwrap();
        let built = sample_native_tx_leaf_artifact(22);
        let mut artifact = decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).unwrap();
        artifact.spec_digest[0] ^= 0x5a;
        let tampered = encode_native_tx_leaf_artifact(&artifact).unwrap();
        assert!(verify_native_tx_leaf_artifact_bytes(&tx, &built.receipt, &tampered).is_err());
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

    #[test]
    fn native_receipt_root_hierarchy_matches_flat_root() {
        let artifacts = (0..16)
            .map(|seed| Ok(receipt_root_fixture_artifact(seed)))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let records = artifacts
            .iter()
            .map(native_tx_leaf_record_from_artifact)
            .collect::<Vec<_>>();

        let hierarchy = build_native_receipt_root_hierarchy_from_records(
            &records,
            native_receipt_root_mini_root_size(),
        )
        .unwrap();
        let built_flat = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        let decoded = decode_receipt_root_artifact(&built_flat.artifact_bytes).unwrap();

        assert_eq!(hierarchy.metadata.leaf_count, 16);
        assert_eq!(hierarchy.metadata.fold_count, decoded.folds.len() as u32);
        assert_eq!(
            hierarchy.hierarchy.root_statement_digest,
            decoded.root_statement_digest
        );
        assert_eq!(hierarchy.hierarchy.root_commitment, decoded.root_commitment);
    }

    #[test]
    fn native_receipt_root_hierarchy_reports_expected_layers() {
        let artifacts = (0..16)
            .map(|seed| Ok(receipt_root_fixture_artifact(seed + 100)))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let records = artifacts
            .iter()
            .map(native_tx_leaf_record_from_artifact)
            .collect::<Vec<_>>();

        let hierarchy = build_native_receipt_root_hierarchy_from_records(
            &records,
            native_receipt_root_mini_root_size(),
        )
        .unwrap();
        let layer_widths = hierarchy
            .hierarchy
            .layers
            .iter()
            .map(|layer| layer.nodes.len())
            .collect::<Vec<_>>();

        assert_eq!(layer_widths, vec![16, 8, 4, 2, 1]);
        assert_eq!(hierarchy.hierarchy.mini_roots.len(), 2);
        assert!(hierarchy
            .hierarchy
            .mini_roots
            .iter()
            .all(|node| node.leaf_count == 8));
    }

    #[test]
    fn native_receipt_root_hierarchy_rejects_zero_mini_root_size() {
        let artifact = receipt_root_fixture_artifact(120);
        let record = native_tx_leaf_record_from_artifact(&artifact);
        let err = build_native_receipt_root_hierarchy_from_records(&[record], 0).unwrap_err();
        assert!(
            err.to_string().contains("mini-root size"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn native_receipt_root_rejects_tampered_fold_rows() {
        let artifacts = [30u64, 31]
            .into_iter()
            .map(|seed| Ok(receipt_root_fixture_artifact(seed)))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let built = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        let mut decoded = decode_receipt_root_artifact(&built.artifact_bytes).unwrap();
        decoded.folds[0].parent_rows[0].coeffs[0] ^= 1;
        let tampered = encode_receipt_root_artifact(&decoded);
        assert!(verify_native_tx_leaf_receipt_root_artifact_bytes(&artifacts, &tampered).is_err());
    }

    #[test]
    fn native_receipt_root_rejects_spec_digest_mismatch() {
        let artifacts = [34u64, 35]
            .into_iter()
            .map(|seed| Ok(receipt_root_fixture_artifact(seed)))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let built = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        let mut decoded = decode_receipt_root_artifact(&built.artifact_bytes).unwrap();
        decoded.spec_digest[0] ^= 0x5a;
        let tampered = encode_receipt_root_artifact(&decoded);
        assert!(verify_native_tx_leaf_receipt_root_artifact_bytes(&artifacts, &tampered).is_err());
    }

    #[test]
    fn native_receipt_root_rejects_mixed_child_commitments() {
        let mut artifacts = receipt_root_distinct_artifacts();
        let built = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        artifacts.swap(0, 1);
        assert!(verify_native_tx_leaf_receipt_root_artifact_bytes(
            &artifacts,
            &built.artifact_bytes
        )
        .is_err());
    }

    #[test]
    fn native_receipt_root_rejects_tampered_leaf_proof_digest() {
        let artifacts = [40u64, 41]
            .into_iter()
            .map(|seed| Ok(receipt_root_fixture_artifact(seed)))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let built = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        let mut decoded = decode_receipt_root_artifact(&built.artifact_bytes).unwrap();
        decoded.leaves[0].proof_digest[0] ^= 0x5a;
        let tampered = encode_receipt_root_artifact(&decoded);
        assert!(verify_native_tx_leaf_receipt_root_artifact_bytes(&artifacts, &tampered).is_err());
    }

    #[test]
    fn native_receipt_root_rejects_tampered_leaf_statement_digest() {
        let artifacts = [42u64, 43]
            .into_iter()
            .map(|seed| Ok(receipt_root_fixture_artifact(seed)))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let built = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        let mut decoded = decode_receipt_root_artifact(&built.artifact_bytes).unwrap();
        decoded.leaves[0].statement_digest[0] ^= 0x5a;
        let tampered = encode_receipt_root_artifact(&decoded);
        assert!(verify_native_tx_leaf_receipt_root_artifact_bytes(&artifacts, &tampered).is_err());
    }

    #[test]
    fn native_receipt_root_builder_rejects_too_many_leaves() {
        let artifact = receipt_root_fixture_artifact(36);
        let artifacts =
            vec![artifact; native_backend_params().max_claimed_receipt_root_leaves as usize + 1];
        let err = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap_err();
        assert!(
            err.to_string().contains("leaf count"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn native_receipt_root_verifier_rejects_too_many_leaves() {
        let artifacts = [37u64, 38]
            .into_iter()
            .map(|seed| Ok(receipt_root_fixture_artifact(seed)))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let built = build_native_tx_leaf_receipt_root_artifact_bytes(&artifacts).unwrap();
        let oversized = vec![
            artifacts[0].clone();
            native_backend_params().max_claimed_receipt_root_leaves as usize + 1
        ];
        let err =
            verify_native_tx_leaf_receipt_root_artifact_bytes(&oversized, &built.artifact_bytes)
                .unwrap_err();
        assert!(
            err.to_string().contains("leaf count"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn native_receipt_root_chunked_builder_matches_serial_builder() {
        let params = native_backend_params();
        for leaf_count in [1usize, 2, 8, 9] {
            let artifacts = (0..leaf_count)
                .map(|seed| Ok(receipt_root_fixture_artifact(seed as u64 + 200)))
                .collect::<Result<Vec<_>>>()
                .unwrap();
            let chunked =
                build_native_tx_leaf_receipt_root_artifact_bytes_with_params(&params, &artifacts)
                    .unwrap();
            let serial = build_native_tx_leaf_receipt_root_artifact_bytes_with_params_serial(
                &params, &artifacts,
            )
            .unwrap();
            assert_eq!(
                chunked.metadata, serial.metadata,
                "metadata mismatch for leaf_count={leaf_count}"
            );
            assert_eq!(
                chunked.artifact_bytes, serial.artifact_bytes,
                "artifact bytes mismatch for leaf_count={leaf_count}"
            );
        }
    }

    fn sample_transaction_proof(seed: u64) -> TransactionProof {
        let witness = sample_witness(seed);
        let (proving_key, _) = generate_keys();
        prove_transaction_with_params(
            &witness,
            &proving_key,
            TransactionProofParams::release_for_version(witness.version),
        )
        .expect("sample tx proof")
    }

    fn sample_native_tx_leaf_artifact(seed: u64) -> BuiltNativeTxLeafArtifact {
        static CACHE: std::sync::OnceLock<
            std::sync::Mutex<std::collections::BTreeMap<u64, BuiltNativeTxLeafArtifact>>,
        > = std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()));
        if let Some(built) = cache.lock().expect("sample artifact cache lock").get(&seed) {
            return built.clone();
        }
        let built = build_native_tx_leaf_artifact_from_transaction_proof_with_params(
            &native_backend_params(),
            &sample_transaction_proof(seed),
        )
        .expect("sample native tx-leaf artifact");
        cache
            .lock()
            .expect("sample artifact cache lock")
            .insert(seed, built.clone());
        built
    }

    fn sample_decoded_native_tx_leaf_artifact(seed: u64) -> NativeTxLeafArtifact {
        decode_native_tx_leaf_artifact_bytes(&sample_native_tx_leaf_artifact(seed).artifact_bytes)
            .expect("decode sample native tx-leaf artifact")
    }

    fn receipt_root_fixture_artifact(seed: u64) -> NativeTxLeafArtifact {
        let _ = seed;
        review_bundle_valid_native_tx_leaf_artifact()
    }

    fn receipt_root_distinct_artifacts() -> Vec<NativeTxLeafArtifact> {
        static DISTINCT: std::sync::OnceLock<Vec<NativeTxLeafArtifact>> =
            std::sync::OnceLock::new();
        DISTINCT
            .get_or_init(|| {
                vec![
                    review_bundle_valid_native_tx_leaf_artifact(),
                    sample_decoded_native_tx_leaf_artifact(71),
                ]
            })
            .clone()
    }

    fn review_bundle_valid_native_tx_leaf_artifact() -> NativeTxLeafArtifact {
        static VALID_LEAF: std::sync::OnceLock<NativeTxLeafArtifact> = std::sync::OnceLock::new();
        VALID_LEAF
            .get_or_init(|| {
                let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../testdata/native_backend_vectors/bundle.json");
                let bundle_bytes = fs::read(&bundle_path)
                    .unwrap_or_else(|err| panic!("read {}: {err}", bundle_path.display()));
                let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
                    .unwrap_or_else(|err| {
                        panic!("parse review bundle {}: {err}", bundle_path.display())
                    });
                let artifact_hex = bundle["cases"]
                    .as_array()
                    .and_then(|cases| {
                        cases
                            .iter()
                            .find(|case| case["name"].as_str() == Some("native_tx_leaf_valid"))
                    })
                    .and_then(|case| case["artifact_hex"].as_str())
                    .expect("review bundle must contain native_tx_leaf_valid artifact_hex");
                let artifact_bytes =
                    hex::decode(artifact_hex).expect("review bundle artifact_hex must decode");
                decode_native_tx_leaf_artifact_bytes(&artifact_bytes)
                    .expect("review bundle native tx-leaf artifact must decode")
            })
            .clone()
    }

    fn alternate_native_backend_params() -> NativeBackendParams {
        NativeBackendParams {
            manifest: BackendManifest {
                family_label: "goldilocks_128b_structural_commitment_alt",
                ..native_backend_params().manifest
            },
            ..native_backend_params()
        }
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
            // Keep the default crate test lane on the historical Plonky3 binding so
            // generic regression tests do not accidentally become release-grade
            // SmallWood proving runs. Dedicated SmallWood tests opt in explicitly.
            version: LEGACY_PLONKY3_FRI_VERSION_BINDING,
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
