use anyhow::{anyhow, ensure, Context, Result};
use blake3::Hasher;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_uni_stark::verify as verify_uni_stark;
use protocol_versioning::VersionBinding;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use superneo_ccs::{
    digest_shape, digest_statement, Assignment, CcsShape, Relation, RelationId, ShapeDigest,
    SparseEntry, SparseMatrix, StatementDigest, StatementEncoding, WitnessField, WitnessSchema,
};
use superneo_core::{validate_fold_pair, FoldedInstance, LeafArtifact, SecurityParams};
use transaction_core::constants::{BALANCE_SLOTS, MAX_INPUTS, MAX_OUTPUTS};
use transaction_core::hashing_pq::bytes48_to_felts;
use transaction_core::p3_air::TransactionAirP3;
use transaction_core::p3_config::{config_with_fri, TransactionProofP3};
use transaction_core::TransactionPublicInputsP3;

const CANONICAL_RECEIPT_WIRE_BYTES: usize = 48 * 4;
const LEAF_ARTIFACT_WIRE_BYTES: usize = 2 + 32 + 32 + 48 + 48 + 48;
const TX_PUBLIC_WIRE_BYTES: usize =
    4 + (MAX_INPUTS * 48) + 4 + (MAX_OUTPUTS * 48) + 4 + (MAX_OUTPUTS * 48) + 48 + 2 + 2;
const MAX_NATIVE_TX_STARK_PROOF_BYTES: usize = 512 * 1024;
const TX_STATEMENT_HASH_DOMAIN: &[u8] = b"tx-statement-v1";
const TX_PROOF_DIGEST_DOMAIN: &[u8] = b"tx-proof-digest-v1";
const TX_PUBLIC_INPUTS_DIGEST_DOMAIN: &[u8] = b"tx-public-inputs-digest-v1";
const GOLDILOCKS_MODULUS_I128: i128 = 18_446_744_069_414_584_321;
const COEFF_CAPACITY_BITS: u16 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendManifest {
    pub family_label: &'static str,
    pub spec_label: &'static str,
    pub commitment_scheme_label: &'static str,
    pub challenge_schedule_label: &'static str,
    pub maturity_label: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingProfile {
    GoldilocksCyclotomic24,
    GoldilocksFrog,
}

impl RingProfile {
    fn label(self) -> &'static [u8] {
        match self {
            Self::GoldilocksCyclotomic24 => b"goldilocks-cyclotomic24",
            Self::GoldilocksFrog => b"goldilocks-frog",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentSecurityModel {
    GeometryProxy,
    BoundedKernelModuleSis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentEstimatorModel {
    SisLatticeEuclideanAdps16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBackendParams {
    pub manifest: BackendManifest,
    pub security_bits: u32,
    pub ring_profile: RingProfile,
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub challenge_bits: u32,
    pub fold_challenge_count: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_label: &'static str,
    pub decomposition_bits: u32,
    pub opening_randomness_bits: u32,
    pub commitment_security_model: CommitmentSecurityModel,
    pub commitment_estimator_model: CommitmentEstimatorModel,
    pub max_commitment_message_ring_elems: u32,
    pub max_claimed_receipt_root_leaves: u32,
}

impl NativeBackendParams {
    pub fn goldilocks_128b_structural_commitment() -> Self {
        Self {
            manifest: BackendManifest {
                family_label: "goldilocks_128b_structural_commitment",
                spec_label:
                    "hegemon.superneo.native-backend-spec.goldilocks-128b-structural-commitment.v7",
                commitment_scheme_label: "bounded_message_random_matrix_commitment",
                challenge_schedule_label: "quint_goldilocks_fs_challenge_negacyclic_mix",
                maturity_label: "structural_candidate",
            },
            security_bits: 128,
            ring_profile: RingProfile::GoldilocksCyclotomic24,
            matrix_rows: 74,
            matrix_cols: 8,
            challenge_bits: 63,
            fold_challenge_count: 5,
            max_fold_arity: 2,
            transcript_domain_label: "hegemon.superneo.fold.v3",
            decomposition_bits: 8,
            opening_randomness_bits: 256,
            commitment_security_model: CommitmentSecurityModel::BoundedKernelModuleSis,
            commitment_estimator_model: CommitmentEstimatorModel::SisLatticeEuclideanAdps16,
            max_commitment_message_ring_elems: 513,
            max_claimed_receipt_root_leaves: 128,
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.matrix_rows > 0,
            "matrix_rows must be strictly positive"
        );
        ensure!(
            self.matrix_cols > 0,
            "matrix_cols must be strictly positive"
        );
        ensure!(
            (1..=63).contains(&self.challenge_bits),
            "challenge_bits must be in 1..=63"
        );
        ensure!(
            (1..=8).contains(&self.fold_challenge_count),
            "fold_challenge_count must be in 1..=8"
        );
        ensure!(
            self.max_fold_arity == 2,
            "binary fold backend requires max_fold_arity == 2"
        );
        ensure!(
            (1..=16).contains(&self.decomposition_bits),
            "decomposition_bits must be in 1..=16"
        );
        ensure!(
            self.opening_randomness_bits > 0 && self.opening_randomness_bits <= 256,
            "opening_randomness_bits must be in 1..=256"
        );
        ensure!(
            self.max_commitment_message_ring_elems > 0,
            "max_commitment_message_ring_elems must be strictly positive"
        );
        ensure!(
            self.max_claimed_receipt_root_leaves > 0,
            "max_claimed_receipt_root_leaves must be strictly positive"
        );
        let _ = self.commitment_estimator_model;
        Ok(())
    }

    fn security_params(&self) -> SecurityParams {
        SecurityParams {
            target_security_bits: self.security_bits,
            max_fold_arity: self.max_fold_arity,
            transcript_domain: self.transcript_domain_label.as_bytes(),
        }
    }

    fn parameter_fingerprint(&self) -> [u8; 48] {
        review_parameter_fingerprint(self)
    }

    fn ring_degree(&self) -> usize {
        self.matrix_cols
    }

    fn digit_bits(&self) -> u16 {
        self.decomposition_bits as u16
    }
}

impl Default for NativeBackendParams {
    fn default() -> Self {
        Self::goldilocks_128b_structural_commitment()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendKey {
    pub params_fingerprint: [u8; 48],
    pub shape_digest: ShapeDigest,
    pub security_bits: u32,
    pub challenge_bits: u32,
    pub fold_challenge_count: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_digest: [u8; 32],
    pub ring_profile: RingProfile,
    pub commitment_rows: usize,
    pub ring_degree: usize,
    pub digit_bits: u16,
    pub opening_randomness_bits: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingElem {
    pub coeffs: Vec<u64>,
}

impl RingElem {
    pub fn from_coeffs(coeffs: Vec<u64>) -> Self {
        Self { coeffs }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeCommitment {
    pub digest: [u8; 48],
    pub rows: Vec<RingElem>,
}

impl LatticeCommitment {
    pub fn from_rows(rows: Vec<RingElem>) -> Self {
        let digest = digest_commitment_rows(&rows);
        Self { digest, rows }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafDigestProof {
    pub witness_commitment_digest: [u8; 48],
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldDigestProof {
    pub params_fingerprint: [u8; 48],
    pub challenges: Vec<u64>,
    pub parent_statement_digest: StatementDigest,
    pub parent_commitment_digest: [u8; 48],
    pub parent_rows: Vec<RingElem>,
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedWitness<R> {
    pub coeffs: Vec<R>,
    pub original_len: usize,
    pub used_bits: usize,
    pub coeff_capacity_bits: u16,
    pub value_bit_widths: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GoldilocksPackingConfig {
    pub limb_bits: u16,
    pub coeff_capacity_bits: u16,
    pub reject_out_of_range: bool,
}

impl Default for GoldilocksPackingConfig {
    fn default() -> Self {
        Self {
            limb_bits: 8,
            coeff_capacity_bits: COEFF_CAPACITY_BITS,
            reject_out_of_range: true,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GoldilocksPayPerBitPacker {
    pub config: GoldilocksPackingConfig,
}

impl GoldilocksPayPerBitPacker {
    pub fn new(config: GoldilocksPackingConfig) -> Self {
        Self { config }
    }

    pub fn pack(
        &self,
        shape: &CcsShape<Goldilocks>,
        assignment: &Assignment<Goldilocks>,
    ) -> Result<PackedWitness<u64>> {
        ensure!(
            assignment.witness.len() == shape.expected_witness_len(),
            "assignment length {} does not match expected witness length {}",
            assignment.witness.len(),
            shape.expected_witness_len()
        );
        let mut coeffs = Vec::new();
        let mut current = 0u64;
        let mut bits_used = 0u16;
        let mut value_bit_widths = Vec::with_capacity(assignment.witness.len());
        let mut used_bits = 0usize;
        let mut witness_idx = 0usize;

        for field in &shape.witness_schema.fields {
            ensure!(
                !field.signed,
                "signed witness fields are not yet supported by GoldilocksPayPerBitPacker"
            );
            for _ in 0..field.count {
                let raw = assignment.witness[witness_idx].as_canonical_u64();
                witness_idx += 1;
                value_bit_widths.push(field.bit_width);
                if self.config.reject_out_of_range && field.bit_width < 64 {
                    let max = 1u128 << field.bit_width;
                    ensure!(
                        u128::from(raw) < max,
                        "witness field {} value {} exceeds {} bits",
                        field.name,
                        raw,
                        field.bit_width
                    );
                }

                let mut remaining = field.bit_width;
                let mut source_offset = 0u16;
                while remaining > 0 {
                    if bits_used == self.config.coeff_capacity_bits {
                        coeffs.push(current);
                        current = 0;
                        bits_used = 0;
                    }
                    let available = self.config.coeff_capacity_bits - bits_used;
                    let take = remaining.min(available);
                    let chunk = extract_bits(raw, source_offset, take);
                    current |= chunk << bits_used;
                    bits_used += take;
                    source_offset += take;
                    remaining -= take;
                    used_bits += usize::from(take);
                    if bits_used == self.config.coeff_capacity_bits {
                        coeffs.push(current);
                        current = 0;
                        bits_used = 0;
                    }
                }
            }
        }

        if bits_used > 0 {
            coeffs.push(current);
        }

        Ok(PackedWitness {
            coeffs,
            original_len: assignment.witness.len(),
            used_bits,
            coeff_capacity_bits: self.config.coeff_capacity_bits,
            value_bit_widths,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTxValidityReceipt {
    pub statement_hash: [u8; 48],
    pub proof_digest: [u8; 48],
    pub public_inputs_digest: [u8; 48],
    pub verifier_profile: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTxValidityReceiptRelation {
    shape: CcsShape<Goldilocks>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxLeafPublicRelation {
    shape: CcsShape<Goldilocks>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializedStarkInputs {
    pub input_flags: Vec<u8>,
    pub output_flags: Vec<u8>,
    pub fee: u64,
    pub value_balance_sign: u8,
    pub value_balance_magnitude: u64,
    pub merkle_root: [u8; 48],
    pub balance_slot_asset_ids: Vec<u64>,
    pub stablecoin_enabled: u8,
    pub stablecoin_asset_id: u64,
    pub stablecoin_policy_version: u32,
    pub stablecoin_issuance_sign: u8,
    pub stablecoin_issuance_magnitude: u64,
    pub stablecoin_policy_hash: [u8; 48],
    pub stablecoin_oracle_commitment: [u8; 48],
    pub stablecoin_attestation_commitment: [u8; 48],
}

impl Default for CanonicalTxValidityReceiptRelation {
    fn default() -> Self {
        let witness_schema = WitnessSchema {
            fields: vec![WitnessField {
                name: "receipt_limb",
                bit_width: 64,
                signed: false,
                count: 24,
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
                    count: 6,
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
                    count: 6,
                },
                WitnessField {
                    name: "stablecoin_oracle_commitment_limb",
                    bit_width: 64,
                    signed: false,
                    count: 6,
                },
                WitnessField {
                    name: "stablecoin_attestation_commitment_limb",
                    bit_width: 64,
                    signed: false,
                    count: 6,
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
                    count: MAX_INPUTS * 6,
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
                    count: MAX_OUTPUTS * 6,
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
                    count: MAX_OUTPUTS * 6,
                },
                WitnessField {
                    name: "balance_tag_limb",
                    bit_width: 64,
                    signed: false,
                    count: 6,
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
        let mut public_inputs = Vec::with_capacity(24);
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
        let mut witness = Vec::with_capacity(24);
        witness.extend(bytes48_to_goldilocks(&statement.statement_hash));
        witness.extend(bytes48_to_goldilocks(&statement.proof_digest));
        witness.extend(bytes48_to_goldilocks(&statement.public_inputs_digest));
        witness.extend(bytes48_to_goldilocks(&statement.verifier_profile));
        Ok(Assignment { witness })
    }
}

impl Relation<Goldilocks> for TxLeafPublicRelation {
    type Statement = CanonicalTxValidityReceipt;
    type Witness = ();

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
        _statement: &Self::Statement,
        _witness: &Self::Witness,
    ) -> Result<Assignment<Goldilocks>> {
        Ok(Assignment {
            witness: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeBackend {
    params: NativeBackendParams,
}

impl LatticeBackend {
    pub fn new(params: NativeBackendParams) -> Self {
        Self { params }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewVectorBundle {
    pub parameter_fingerprint: String,
    pub native_backend_params: ReviewBackendParams,
    pub native_security_claim: ReviewSecurityClaim,
    pub cases: Vec<ReviewVectorCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewBackendParams {
    pub family_label: String,
    pub spec_label: String,
    pub commitment_scheme_label: String,
    pub challenge_schedule_label: String,
    pub maturity_label: String,
    pub security_bits: u32,
    pub ring_profile: String,
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub challenge_bits: u32,
    pub fold_challenge_count: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_label: String,
    pub decomposition_bits: u32,
    pub opening_randomness_bits: u32,
    #[serde(default = "default_commitment_security_model")]
    pub commitment_security_model: String,
    #[serde(default = "default_commitment_estimator_model")]
    pub commitment_estimator_model: String,
    #[serde(default = "default_max_commitment_message_ring_elems")]
    pub max_commitment_message_ring_elems: u32,
    #[serde(default = "default_max_claimed_receipt_root_leaves")]
    pub max_claimed_receipt_root_leaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSecurityClaim {
    pub claimed_security_bits: u32,
    pub transcript_soundness_bits: u32,
    pub opening_hiding_bits: u32,
    #[serde(default)]
    pub commitment_codomain_bits: u32,
    #[serde(default)]
    pub commitment_same_seed_search_bits: u32,
    #[serde(default)]
    pub commitment_random_matrix_bits: u32,
    #[serde(default)]
    pub commitment_problem_equations: u32,
    #[serde(default)]
    pub commitment_problem_dimension: u32,
    #[serde(default)]
    pub commitment_problem_coeff_bound: u32,
    #[serde(default)]
    pub commitment_problem_l2_bound: u32,
    #[serde(default)]
    pub commitment_estimator_dimension: u32,
    #[serde(default)]
    pub commitment_estimator_block_size: u32,
    #[serde(default)]
    pub commitment_estimator_classical_bits: u32,
    #[serde(default)]
    pub commitment_estimator_quantum_bits: u32,
    #[serde(default)]
    pub commitment_estimator_paranoid_bits: u32,
    #[serde(default)]
    pub commitment_reduction_loss_bits: u32,
    pub commitment_binding_bits: u32,
    pub composition_loss_bits: u32,
    pub soundness_floor_bits: u32,
    pub assumption_ids: Vec<String>,
    pub review_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewVectorCase {
    pub name: String,
    pub kind: String,
    pub expected_valid: bool,
    pub expected_error_substring: Option<String>,
    pub artifact_hex: String,
    pub tx_context: Option<ReviewTxContext>,
    pub block_context: Option<ReviewBlockContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewReceipt {
    pub statement_hash_hex: String,
    pub proof_digest_hex: String,
    pub public_inputs_digest_hex: String,
    pub verifier_profile_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSerializedStarkInputs {
    pub input_flags: Vec<u8>,
    pub output_flags: Vec<u8>,
    pub fee: u64,
    pub value_balance_sign: u8,
    pub value_balance_magnitude: u64,
    pub merkle_root_hex: String,
    pub balance_slot_asset_ids: Vec<u64>,
    pub stablecoin_enabled: u8,
    pub stablecoin_asset_id: u64,
    pub stablecoin_policy_version: u32,
    pub stablecoin_issuance_sign: u8,
    pub stablecoin_issuance_magnitude: u64,
    pub stablecoin_policy_hash_hex: String,
    pub stablecoin_oracle_commitment_hex: String,
    pub stablecoin_attestation_commitment_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewTxPublicTx {
    pub nullifiers_hex: Vec<String>,
    pub commitments_hex: Vec<String>,
    pub ciphertext_hashes_hex: Vec<String>,
    pub balance_tag_hex: String,
    pub version_circuit: u16,
    pub version_crypto: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewTxContext {
    pub backend_params: ReviewBackendParams,
    pub expected_version: u16,
    pub params_fingerprint_hex: String,
    pub spec_digest_hex: String,
    pub relation_id_hex: String,
    pub shape_digest_hex: String,
    pub statement_digest_hex: String,
    pub receipt: ReviewReceipt,
    pub tx: ReviewTxPublicTx,
    pub stark_public_inputs: ReviewSerializedStarkInputs,
    pub commitment_rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewReceiptLeafContext {
    pub statement_digest_hex: String,
    pub witness_commitment_hex: String,
    pub proof_digest_hex: String,
    pub commitment_rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewBlockContext {
    pub backend_params: ReviewBackendParams,
    pub expected_version: u16,
    pub params_fingerprint_hex: String,
    pub spec_digest_hex: String,
    pub relation_id_hex: String,
    pub shape_digest_hex: String,
    pub root_statement_digest_hex: String,
    pub root_commitment_hex: String,
    pub leaves: Vec<ReviewReceiptLeafContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewVerificationSummary {
    pub bundle_path: String,
    pub case_count: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewCaseResult {
    pub name: String,
    pub expected_valid: bool,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefTxLeafPublicTx {
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    balance_tag: [u8; 48],
    version: VersionBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefNativeTxLeafArtifact {
    version: u16,
    params_fingerprint: [u8; 48],
    spec_digest: [u8; 32],
    relation_id: [u8; 32],
    shape_digest: [u8; 32],
    statement_digest: [u8; 48],
    receipt: CanonicalTxValidityReceipt,
    stark_public_inputs: SerializedStarkInputs,
    tx: RefTxLeafPublicTx,
    stark_proof: Vec<u8>,
    commitment: LatticeCommitment,
    leaf: LeafArtifact<LeafDigestProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefReceiptRootLeaf {
    statement_digest: [u8; 48],
    witness_commitment: [u8; 48],
    proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefReceiptRootFoldStep {
    challenges: Vec<u64>,
    parent_statement_digest: [u8; 48],
    parent_commitment: [u8; 48],
    parent_rows: Vec<RingElem>,
    proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RefReceiptRootArtifact {
    version: u16,
    params_fingerprint: [u8; 48],
    spec_digest: [u8; 32],
    relation_id: [u8; 32],
    shape_digest: [u8; 32],
    leaves: Vec<RefReceiptRootLeaf>,
    folds: Vec<RefReceiptRootFoldStep>,
    root_statement_digest: [u8; 48],
    root_commitment: [u8; 48],
}

impl LatticeBackend {
    pub fn setup(
        &self,
        security: &SecurityParams,
        shape: &CcsShape<Goldilocks>,
    ) -> Result<(BackendKey, BackendKey)> {
        shape.validate()?;
        self.params.validate()?;
        ensure!(
            security.target_security_bits == self.params.security_bits,
            "security target {} does not match native backend params {}",
            security.target_security_bits,
            self.params.security_bits
        );
        ensure!(
            security.max_fold_arity == self.params.max_fold_arity,
            "max_fold_arity {} does not match native backend params {}",
            security.max_fold_arity,
            self.params.max_fold_arity
        );
        ensure!(
            security.transcript_domain == self.params.transcript_domain_label.as_bytes(),
            "transcript_domain does not match native backend params {}",
            self.params.transcript_domain_label
        );
        let key = BackendKey {
            params_fingerprint: self.params.parameter_fingerprint(),
            shape_digest: digest_shape(shape),
            security_bits: self.params.security_bits,
            challenge_bits: self.params.challenge_bits,
            fold_challenge_count: self.params.fold_challenge_count,
            max_fold_arity: self.params.max_fold_arity,
            transcript_domain_digest: digest32_with_label(
                b"hegemon.superneo.transcript-domain.v1",
                self.params.transcript_domain_label.as_bytes(),
            ),
            ring_profile: self.params.ring_profile,
            commitment_rows: self.params.matrix_rows,
            ring_degree: self.params.ring_degree(),
            digit_bits: self.params.digit_bits(),
            opening_randomness_bits: self.params.opening_randomness_bits,
        };
        Ok((key.clone(), key))
    }

    pub fn commit_witness(
        &self,
        pk: &BackendKey,
        packed: &PackedWitness<u64>,
    ) -> Result<LatticeCommitment> {
        let ring_message = embed_packed_witness(pk, packed)?;
        let rows = commit_ring_message(pk, &ring_message);
        Ok(LatticeCommitment::from_rows(rows))
    }

    pub fn verify_leaf(
        &self,
        vk: &BackendKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        expected_packed: &PackedWitness<u64>,
        proof: &LeafDigestProof,
    ) -> Result<()> {
        let expected_commitment = self.commit_witness(vk, expected_packed)?;
        ensure!(
            proof.witness_commitment_digest == expected_commitment.digest,
            "leaf witness commitment digest mismatch"
        );
        let expected_proof_digest = leaf_proof_digest(
            vk,
            relation_id,
            &statement.statement_digest,
            expected_packed,
            &expected_commitment.digest,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "leaf proof digest mismatch"
        );
        Ok(())
    }

    pub fn fold_pair(
        &self,
        pk: &BackendKey,
        left: &FoldedInstance<LatticeCommitment>,
        right: &FoldedInstance<LatticeCommitment>,
    ) -> Result<(FoldedInstance<LatticeCommitment>, FoldDigestProof)> {
        validate_fold_pair(left, right)?;
        let challenges = derive_fold_challenges(pk, left, right);
        let parent_rows = fold_commitment_rows(
            &left.witness_commitment,
            &right.witness_commitment,
            &challenges,
        )?;
        let parent_commitment = LatticeCommitment::from_rows(parent_rows.clone());
        let parent_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            &challenges,
            &parent_commitment.digest,
        );
        let proof_digest = fold_proof_digest(
            pk,
            &left.relation_id,
            left,
            right,
            &challenges,
            &parent_statement_digest,
            &parent_rows,
        );
        let proof = FoldDigestProof {
            params_fingerprint: pk.params_fingerprint,
            challenges: challenges.clone(),
            parent_statement_digest,
            parent_commitment_digest: parent_commitment.digest,
            parent_rows: parent_rows.clone(),
            proof_digest,
        };
        let parent = FoldedInstance {
            relation_id: left.relation_id,
            shape_digest: left.shape_digest,
            statement_digest: parent_statement_digest,
            witness_commitment: parent_commitment,
        };
        Ok((parent, proof))
    }

    pub fn verify_fold(
        &self,
        vk: &BackendKey,
        parent: &FoldedInstance<LatticeCommitment>,
        left: &FoldedInstance<LatticeCommitment>,
        right: &FoldedInstance<LatticeCommitment>,
        proof: &FoldDigestProof,
    ) -> Result<()> {
        validate_fold_pair(left, right)?;
        ensure!(
            parent.relation_id == left.relation_id && left.relation_id == right.relation_id,
            "parent relation id does not match folded children"
        );
        ensure!(
            parent.shape_digest == left.shape_digest && left.shape_digest == right.shape_digest,
            "parent shape digest does not match folded children"
        );
        ensure!(
            proof.params_fingerprint == vk.params_fingerprint,
            "fold proof parameter fingerprint mismatch"
        );
        let expected_challenges = derive_fold_challenges(vk, left, right);
        ensure!(
            proof.challenges == expected_challenges,
            "fold challenge vector mismatch"
        );
        let expected_rows = fold_commitment_rows(
            &left.witness_commitment,
            &right.witness_commitment,
            &expected_challenges,
        )?;
        ensure!(
            proof.parent_rows == expected_rows,
            "fold proof parent rows mismatch"
        );
        let expected_commitment = LatticeCommitment::from_rows(expected_rows.clone());
        ensure!(
            parent.witness_commitment.digest == expected_commitment.digest,
            "folded witness commitment digest mismatch"
        );
        ensure!(
            proof.parent_commitment_digest == expected_commitment.digest,
            "fold proof parent commitment digest mismatch"
        );
        let expected_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            &expected_challenges,
            &expected_commitment.digest,
        );
        ensure!(
            parent.statement_digest == expected_statement_digest,
            "folded statement digest mismatch"
        );
        ensure!(
            proof.parent_statement_digest == expected_statement_digest,
            "fold proof parent statement digest mismatch"
        );
        let expected_proof_digest = fold_proof_digest(
            vk,
            &left.relation_id,
            left,
            right,
            &expected_challenges,
            &expected_statement_digest,
            &expected_rows,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "fold proof digest mismatch"
        );
        Ok(())
    }
}

pub fn load_bundle(bundle_path: &Path) -> Result<ReviewVectorBundle> {
    let bytes = fs::read(bundle_path).with_context(|| {
        format!(
            "failed to read review vector bundle {}",
            bundle_path.display()
        )
    })?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "failed to parse review vector bundle {}",
            bundle_path.display()
        )
    })
}

pub fn verify_bundle_dir(
    bundle_dir: &Path,
) -> Result<(ReviewVerificationSummary, Vec<ReviewCaseResult>)> {
    let bundle_path = bundle_dir.join("bundle.json");
    let bundle = load_bundle(&bundle_path)?;
    let mut results = Vec::with_capacity(bundle.cases.len());
    let mut passed_cases = 0usize;
    for case in &bundle.cases {
        match verify_case(case) {
            Ok(()) if case.expected_valid => {
                passed_cases += 1;
                results.push(ReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: true,
                    passed: true,
                    detail: "accepted".to_owned(),
                });
            }
            Ok(()) => {
                results.push(ReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: false,
                    passed: false,
                    detail: "unexpected acceptance".to_owned(),
                });
            }
            Err(err) if !case.expected_valid => {
                let detail = err.to_string();
                let passed = case
                    .expected_error_substring
                    .as_deref()
                    .map(|expected| detail.contains(expected))
                    .unwrap_or(true);
                if passed {
                    passed_cases += 1;
                }
                results.push(ReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: false,
                    passed,
                    detail,
                });
            }
            Err(err) => {
                results.push(ReviewCaseResult {
                    name: case.name.clone(),
                    expected_valid: true,
                    passed: false,
                    detail: err.to_string(),
                });
            }
        }
    }
    let summary = ReviewVerificationSummary {
        bundle_path: bundle_path.display().to_string(),
        case_count: results.len(),
        passed_cases,
        failed_cases: results.len().saturating_sub(passed_cases),
    };
    Ok((summary, results))
}

pub fn verify_case(case: &ReviewVectorCase) -> Result<()> {
    let artifact_bytes =
        hex::decode(&case.artifact_hex).context("review case artifact_hex must be valid hex")?;
    match case.kind.as_str() {
        "native_tx_leaf" => verify_native_tx_leaf_case(case, &artifact_bytes),
        "receipt_root" => verify_receipt_root_case(case, &artifact_bytes),
        other => Err(anyhow!("unsupported review case kind {other}")),
    }
}

fn verify_native_tx_leaf_case(case: &ReviewVectorCase, artifact_bytes: &[u8]) -> Result<()> {
    let ctx = case
        .tx_context
        .as_ref()
        .ok_or_else(|| anyhow!("native_tx_leaf case {} is missing tx_context", case.name))?;
    let params = review_params_to_native(&ctx.backend_params)?;
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let security = params.security_params();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let artifact = parse_native_tx_leaf_artifact(&params, artifact_bytes)?;
    let tx = tx_from_review(ctx)?;
    let stark_public_inputs = stark_inputs_from_review(&ctx.stark_public_inputs)?;
    let receipt = receipt_from_review(&ctx.receipt)?;

    ensure!(
        artifact.version == ctx.expected_version,
        "native tx-leaf version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == decode_hex_array::<48>(&ctx.params_fingerprint_hex)?,
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.params_fingerprint == review_parameter_fingerprint(&params),
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "spec digest mismatch"
    );
    ensure!(
        artifact.spec_digest == review_spec_digest(&params),
        "spec digest mismatch"
    );
    ensure!(
        artifact.relation_id == decode_hex_array::<32>(&ctx.relation_id_hex)?,
        "relation id mismatch"
    );
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == decode_hex_array::<32>(&ctx.shape_digest_hex)?,
        "shape digest mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "shape digest mismatch"
    );
    ensure!(
        artifact.statement_digest == decode_hex_array::<48>(&ctx.statement_digest_hex)?,
        "statement digest mismatch"
    );
    ensure!(artifact.tx == tx, "public tx mismatch");
    ensure!(
        artifact.stark_public_inputs == stark_public_inputs,
        "serialized STARK inputs mismatch"
    );
    ensure!(artifact.receipt == receipt, "receipt mismatch");
    ensure!(
        artifact.leaf.version == artifact.version,
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

    let expected_receipt = native_tx_leaf_receipt_from_parts(
        &artifact.tx,
        &artifact.stark_public_inputs,
        &artifact.stark_proof,
        &params,
        pk.shape_digest,
    )?;
    ensure!(
        artifact.receipt == expected_receipt,
        "canonical receipt mismatch"
    );

    let p3_public_inputs = transaction_public_inputs_p3_from_tx_leaf_public(
        &artifact.tx,
        &artifact.stark_public_inputs,
    )?;
    verify_transaction_proof_bytes_p3(&artifact.stark_proof, &p3_public_inputs)
        .map_err(|err| anyhow!("STARK proof verification failed: {err}"))?;

    validate_native_tx_leaf_public_witness_with_params(
        &params,
        &artifact.receipt,
        &artifact.tx,
        &artifact.stark_public_inputs,
        pk.shape_digest,
    )?;

    let encoding = relation.encode_statement(&artifact.receipt)?;
    ensure!(
        artifact.statement_digest == encoding.statement_digest.0,
        "statement digest mismatch"
    );
    ensure!(
        artifact.leaf.statement_digest == encoding.statement_digest,
        "inner statement digest mismatch"
    );

    let review_commitment = commitment_from_review_rows(&ctx.commitment_rows, "native tx-leaf")?;
    ensure!(
        artifact.commitment == review_commitment,
        "commitment rows mismatch"
    );

    let packed = pack_tx_leaf_public_witness(
        &artifact.tx,
        &artifact.stark_public_inputs,
        relation.shape(),
    )?;
    let expected_commitment = backend.commit_witness(&pk, &packed)?;
    ensure!(
        artifact.commitment == expected_commitment,
        "commitment mismatch"
    );
    ensure!(
        artifact.leaf.proof.witness_commitment_digest == artifact.commitment.digest,
        "witness commitment digest mismatch"
    );

    backend
        .verify_leaf(
            &vk,
            &relation.relation_id(),
            &encoding,
            &packed,
            &artifact.leaf.proof,
        )
        .map_err(|err| anyhow!("native tx-leaf verification failed: {err}"))?;
    Ok(())
}

fn verify_receipt_root_case(case: &ReviewVectorCase, artifact_bytes: &[u8]) -> Result<()> {
    let ctx = case
        .block_context
        .as_ref()
        .ok_or_else(|| anyhow!("receipt_root case {} is missing block_context", case.name))?;
    let params = review_params_to_native(&ctx.backend_params)?;
    let relation = TxLeafPublicRelation::default();
    let backend = LatticeBackend::new(params.clone());
    let security = params.security_params();
    let (pk, vk) = backend.setup(&security, relation.shape())?;
    let artifact = parse_receipt_root_artifact(&params, artifact_bytes)?;

    ensure!(
        artifact.version == ctx.expected_version,
        "receipt-root version mismatch"
    );
    ensure!(
        artifact.params_fingerprint == decode_hex_array::<48>(&ctx.params_fingerprint_hex)?,
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.params_fingerprint == review_parameter_fingerprint(&params),
        "parameter fingerprint mismatch"
    );
    ensure!(
        artifact.spec_digest == decode_hex_array::<32>(&ctx.spec_digest_hex)?,
        "spec digest mismatch"
    );
    ensure!(
        artifact.spec_digest == review_spec_digest(&params),
        "spec digest mismatch"
    );
    ensure!(
        artifact.relation_id == decode_hex_array::<32>(&ctx.relation_id_hex)?,
        "relation id mismatch"
    );
    ensure!(
        artifact.relation_id == relation.relation_id().0,
        "relation id mismatch"
    );
    ensure!(
        artifact.shape_digest == decode_hex_array::<32>(&ctx.shape_digest_hex)?,
        "shape digest mismatch"
    );
    ensure!(
        artifact.shape_digest == pk.shape_digest.0,
        "shape digest mismatch"
    );
    ensure!(
        !artifact.leaves.is_empty(),
        "receipt-root must contain at least one leaf"
    );
    ensure!(
        artifact.leaves.len() <= params.max_claimed_receipt_root_leaves as usize,
        "receipt-root leaf count {} exceeds {}",
        artifact.leaves.len(),
        params.max_claimed_receipt_root_leaves
    );
    ensure!(
        artifact.leaves.len() == ctx.leaves.len(),
        "receipt-root leaf count mismatch"
    );

    let mut current = Vec::with_capacity(artifact.leaves.len());
    for (leaf, expected) in artifact.leaves.iter().zip(&ctx.leaves) {
        ensure!(
            leaf.statement_digest == decode_hex_array::<48>(&expected.statement_digest_hex)?,
            "leaf statement digest mismatch"
        );
        ensure!(
            leaf.witness_commitment == decode_hex_array::<48>(&expected.witness_commitment_hex)?,
            "leaf witness commitment mismatch"
        );
        ensure!(
            leaf.proof_digest == decode_hex_array::<48>(&expected.proof_digest_hex)?,
            "leaf proof digest mismatch"
        );
        let commitment =
            commitment_from_review_rows(&expected.commitment_rows, "receipt-root leaf")?;
        ensure!(
            commitment.digest == leaf.witness_commitment,
            "leaf commitment rows mismatch"
        );
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: StatementDigest(leaf.statement_digest),
            witness_commitment: commitment,
        });
    }

    let mut fold_index = 0usize;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut iter = current.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                let fold = artifact.folds.get(fold_index).ok_or_else(|| {
                    anyhow!("receipt-root artifact is missing fold step {fold_index}")
                })?;
                fold_index += 1;
                let (parent, expected_proof) = backend.fold_pair(&pk, &left, &right)?;
                ensure!(
                    fold.challenges == expected_proof.challenges,
                    "parent challenge vector mismatch"
                );
                ensure!(
                    fold.parent_statement_digest == parent.statement_digest.0,
                    "parent statement digest mismatch"
                );
                ensure!(
                    fold.parent_commitment == parent.witness_commitment.digest,
                    "parent commitment mismatch"
                );
                ensure!(
                    fold.parent_rows == expected_proof.parent_rows,
                    "parent rows mismatch"
                );
                ensure!(
                    fold.proof_digest == expected_proof.proof_digest,
                    "fold proof digest mismatch"
                );
                backend
                    .verify_fold(&vk, &parent, &left, &right, &expected_proof)
                    .map_err(|err| anyhow!("receipt-root fold verification failed: {err}"))?;
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
        .ok_or_else(|| anyhow!("receipt-root artifact did not yield a root"))?;
    ensure!(
        artifact.root_statement_digest == decode_hex_array::<48>(&ctx.root_statement_digest_hex)?,
        "root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == decode_hex_array::<48>(&ctx.root_commitment_hex)?,
        "root commitment mismatch"
    );
    ensure!(
        artifact.root_statement_digest == root.statement_digest.0,
        "root statement digest mismatch"
    );
    ensure!(
        artifact.root_commitment == root.witness_commitment.digest,
        "root commitment mismatch"
    );
    Ok(())
}

pub fn review_params_to_native(review: &ReviewBackendParams) -> Result<NativeBackendParams> {
    let structural = NativeBackendParams::goldilocks_128b_structural_commitment();
    let mut params = match review.family_label.as_str() {
        "goldilocks_128b_structural_commitment" => structural,
        other => NativeBackendParams {
            manifest: BackendManifest {
                family_label: Box::leak(other.to_owned().into_boxed_str()),
                spec_label: Box::leak(review.spec_label.clone().into_boxed_str()),
                commitment_scheme_label: Box::leak(
                    review.commitment_scheme_label.clone().into_boxed_str(),
                ),
                challenge_schedule_label: Box::leak(
                    review.challenge_schedule_label.clone().into_boxed_str(),
                ),
                maturity_label: Box::leak(review.maturity_label.clone().into_boxed_str()),
            },
            ..structural
        },
    };
    params.security_bits = review.security_bits;
    params.ring_profile = parse_review_ring_profile(&review.ring_profile)?;
    params.matrix_rows = review.matrix_rows;
    params.matrix_cols = review.matrix_cols;
    params.challenge_bits = review.challenge_bits;
    params.fold_challenge_count = review.fold_challenge_count;
    params.max_fold_arity = review.max_fold_arity;
    params.transcript_domain_label =
        Box::leak(review.transcript_domain_label.clone().into_boxed_str());
    params.decomposition_bits = review.decomposition_bits;
    params.opening_randomness_bits = review.opening_randomness_bits;
    params.commitment_security_model =
        parse_commitment_security_model(&review.commitment_security_model)?;
    params.commitment_estimator_model =
        parse_commitment_estimator_model(&review.commitment_estimator_model)?;
    params.max_commitment_message_ring_elems = review.max_commitment_message_ring_elems;
    params.max_claimed_receipt_root_leaves = review.max_claimed_receipt_root_leaves;
    validate_review_params(&params)?;
    Ok(params)
}

fn tx_from_review(ctx: &ReviewTxContext) -> Result<RefTxLeafPublicTx> {
    Ok(RefTxLeafPublicTx {
        nullifiers: ctx
            .tx
            .nullifiers_hex
            .iter()
            .map(|value| decode_hex_array::<48>(value))
            .collect::<Result<Vec<_>>>()?,
        commitments: ctx
            .tx
            .commitments_hex
            .iter()
            .map(|value| decode_hex_array::<48>(value))
            .collect::<Result<Vec<_>>>()?,
        ciphertext_hashes: ctx
            .tx
            .ciphertext_hashes_hex
            .iter()
            .map(|value| decode_hex_array::<48>(value))
            .collect::<Result<Vec<_>>>()?,
        balance_tag: decode_hex_array::<48>(&ctx.tx.balance_tag_hex)?,
        version: VersionBinding::new(ctx.tx.version_circuit, ctx.tx.version_crypto),
    })
}

fn stark_inputs_from_review(review: &ReviewSerializedStarkInputs) -> Result<SerializedStarkInputs> {
    Ok(SerializedStarkInputs {
        input_flags: review.input_flags.clone(),
        output_flags: review.output_flags.clone(),
        fee: review.fee,
        value_balance_sign: review.value_balance_sign,
        value_balance_magnitude: review.value_balance_magnitude,
        merkle_root: decode_hex_array::<48>(&review.merkle_root_hex)?,
        balance_slot_asset_ids: review.balance_slot_asset_ids.clone(),
        stablecoin_enabled: review.stablecoin_enabled,
        stablecoin_asset_id: review.stablecoin_asset_id,
        stablecoin_policy_version: review.stablecoin_policy_version,
        stablecoin_issuance_sign: review.stablecoin_issuance_sign,
        stablecoin_issuance_magnitude: review.stablecoin_issuance_magnitude,
        stablecoin_policy_hash: decode_hex_array::<48>(&review.stablecoin_policy_hash_hex)?,
        stablecoin_oracle_commitment: decode_hex_array::<48>(
            &review.stablecoin_oracle_commitment_hex,
        )?,
        stablecoin_attestation_commitment: decode_hex_array::<48>(
            &review.stablecoin_attestation_commitment_hex,
        )?,
    })
}

fn receipt_from_review(review: &ReviewReceipt) -> Result<CanonicalTxValidityReceipt> {
    Ok(CanonicalTxValidityReceipt {
        statement_hash: decode_hex_array::<48>(&review.statement_hash_hex)?,
        proof_digest: decode_hex_array::<48>(&review.proof_digest_hex)?,
        public_inputs_digest: decode_hex_array::<48>(&review.public_inputs_digest_hex)?,
        verifier_profile: decode_hex_array::<48>(&review.verifier_profile_hex)?,
    })
}

fn commitment_from_review_rows(rows: &[Vec<u64>], label: &str) -> Result<LatticeCommitment> {
    ensure!(
        !rows.is_empty(),
        "{label} commitment rows must not be empty"
    );
    Ok(LatticeCommitment::from_rows(
        rows.iter().cloned().map(RingElem::from_coeffs).collect(),
    ))
}

fn native_tx_leaf_receipt_from_parts(
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    stark_proof: &[u8],
    params: &NativeBackendParams,
    shape_digest: ShapeDigest,
) -> Result<CanonicalTxValidityReceipt> {
    ensure!(
        !stark_proof.is_empty(),
        "native tx-leaf proof bytes must not be empty"
    );
    let relation = TxLeafPublicRelation::default();
    Ok(CanonicalTxValidityReceipt {
        statement_hash: tx_statement_hash_from_tx_leaf_public(tx, stark_public_inputs)?,
        proof_digest: digest48(TX_PROOF_DIGEST_DOMAIN, stark_proof),
        public_inputs_digest: transaction_public_inputs_digest_from_serialized(stark_public_inputs)
            .map_err(|err| anyhow!("failed to hash transaction public inputs: {err}"))?,
        verifier_profile: review_verifier_profile(
            params,
            &relation.relation_id(),
            &shape_digest,
            b"native-tx-leaf",
        ),
    })
}

fn validate_native_tx_leaf_public_witness_with_params(
    params: &NativeBackendParams,
    statement: &CanonicalTxValidityReceipt,
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    shape_digest: ShapeDigest,
) -> Result<()> {
    validate_tx_leaf_public_witness_with_expected_profile(
        statement,
        tx,
        stark_public_inputs,
        review_verifier_profile(
            params,
            &TxLeafPublicRelation::default().relation_id(),
            &shape_digest,
            b"native-tx-leaf",
        ),
    )
}

fn validate_tx_leaf_public_witness_with_expected_profile(
    statement: &CanonicalTxValidityReceipt,
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    expected_verifier_profile: [u8; 48],
) -> Result<()> {
    ensure!(
        tx.nullifiers.len() <= MAX_INPUTS,
        "tx-leaf nullifier length {} exceeds {}",
        tx.nullifiers.len(),
        MAX_INPUTS
    );
    ensure!(
        tx.commitments.len() <= MAX_OUTPUTS,
        "tx-leaf commitment length {} exceeds {}",
        tx.commitments.len(),
        MAX_OUTPUTS
    );
    ensure!(
        tx.ciphertext_hashes.len() <= MAX_OUTPUTS,
        "tx-leaf ciphertext-hash length {} exceeds {}",
        tx.ciphertext_hashes.len(),
        MAX_OUTPUTS
    );
    ensure!(
        stark_public_inputs.input_flags.len() <= MAX_INPUTS,
        "tx-leaf input flag length {} exceeds {}",
        stark_public_inputs.input_flags.len(),
        MAX_INPUTS
    );
    ensure!(
        stark_public_inputs.output_flags.len() <= MAX_OUTPUTS,
        "tx-leaf output flag length {} exceeds {}",
        stark_public_inputs.output_flags.len(),
        MAX_OUTPUTS
    );
    ensure!(
        stark_public_inputs.balance_slot_asset_ids.len() <= BALANCE_SLOTS,
        "tx-leaf balance slot asset length {} exceeds {}",
        stark_public_inputs.balance_slot_asset_ids.len(),
        BALANCE_SLOTS
    );
    ensure!(
        active_flag_count(&stark_public_inputs.input_flags)? == tx.nullifiers.len(),
        "tx-leaf nullifier list length does not match active input flags"
    );
    ensure!(
        active_flag_count(&stark_public_inputs.output_flags)? == tx.commitments.len(),
        "tx-leaf commitment list length does not match active output flags"
    );
    ensure!(
        active_flag_count(&stark_public_inputs.output_flags)? == tx.ciphertext_hashes.len(),
        "tx-leaf ciphertext-hash list length does not match active output flags"
    );
    let expected_statement_hash = tx_statement_hash_from_tx_leaf_public(tx, stark_public_inputs)?;
    ensure!(
        expected_statement_hash == statement.statement_hash,
        "statement hash mismatch"
    );
    let expected_public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(stark_public_inputs)
            .map_err(|err| anyhow!("failed to hash transaction public inputs: {err}"))?;
    ensure!(
        expected_public_inputs_digest == statement.public_inputs_digest,
        "public inputs digest mismatch"
    );
    ensure!(
        expected_verifier_profile == statement.verifier_profile,
        "verifier profile mismatch"
    );
    Ok(())
}

fn transaction_public_inputs_p3_from_tx_leaf_public(
    tx: &RefTxLeafPublicTx,
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
        "tx nullifier list length does not match active input flags"
    );
    ensure!(
        active_flag_count(&stark_inputs.output_flags)? == tx.commitments.len(),
        "tx commitment list length does not match active output flags"
    );
    ensure!(
        active_flag_count(&stark_inputs.output_flags)? == tx.ciphertext_hashes.len(),
        "tx ciphertext-hash list length does not match active output flags"
    );

    let mut public = TransactionPublicInputsP3::default();
    public.input_flags = stark_inputs
        .input_flags
        .iter()
        .copied()
        .map(|flag| Goldilocks::new(u64::from(flag)))
        .collect();
    public.output_flags = stark_inputs
        .output_flags
        .iter()
        .copied()
        .map(|flag| Goldilocks::new(u64::from(flag)))
        .collect();
    public.nullifiers = tx
        .nullifiers
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            bytes48_to_felts(value).ok_or_else(|| anyhow!("tx nullifier {} is non-canonical", idx))
        })
        .collect::<Result<Vec<_>>>()?;
    public.commitments = tx
        .commitments
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            bytes48_to_felts(value).ok_or_else(|| anyhow!("tx commitment {} is non-canonical", idx))
        })
        .collect::<Result<Vec<_>>>()?;
    public.ciphertext_hashes = tx
        .ciphertext_hashes
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            bytes48_to_felts(value)
                .ok_or_else(|| anyhow!("tx ciphertext hash {} is non-canonical", idx))
        })
        .collect::<Result<Vec<_>>>()?;
    public.fee = Goldilocks::new(stark_inputs.fee);
    public.value_balance_sign = Goldilocks::new(u64::from(stark_inputs.value_balance_sign));
    public.value_balance_magnitude = Goldilocks::new(stark_inputs.value_balance_magnitude);
    public.merkle_root = bytes48_to_felts(&stark_inputs.merkle_root)
        .ok_or_else(|| anyhow!("merkle root is non-canonical"))?;
    for (slot, asset_id) in stark_inputs.balance_slot_asset_ids.iter().enumerate() {
        public.balance_slot_assets[slot] = Goldilocks::new(*asset_id);
    }
    public.stablecoin_enabled = Goldilocks::new(u64::from(stark_inputs.stablecoin_enabled));
    public.stablecoin_asset = Goldilocks::new(stark_inputs.stablecoin_asset_id);
    public.stablecoin_policy_version =
        Goldilocks::new(u64::from(stark_inputs.stablecoin_policy_version));
    public.stablecoin_issuance_sign =
        Goldilocks::new(u64::from(stark_inputs.stablecoin_issuance_sign));
    public.stablecoin_issuance_magnitude =
        Goldilocks::new(stark_inputs.stablecoin_issuance_magnitude);
    public.stablecoin_policy_hash = bytes48_to_felts(&stark_inputs.stablecoin_policy_hash)
        .ok_or_else(|| anyhow!("stablecoin policy hash is non-canonical"))?;
    public.stablecoin_oracle_commitment =
        bytes48_to_felts(&stark_inputs.stablecoin_oracle_commitment)
            .ok_or_else(|| anyhow!("stablecoin oracle commitment is non-canonical"))?;
    public.stablecoin_attestation_commitment =
        bytes48_to_felts(&stark_inputs.stablecoin_attestation_commitment)
            .ok_or_else(|| anyhow!("stablecoin attestation commitment is non-canonical"))?;
    Ok(public)
}

fn pack_tx_leaf_public_witness(
    tx: &RefTxLeafPublicTx,
    stark_public_inputs: &SerializedStarkInputs,
    shape: &CcsShape<Goldilocks>,
) -> Result<PackedWitness<u64>> {
    let mut values = Vec::with_capacity(shape.expected_witness_len());
    values.push(Goldilocks::new(stark_public_inputs.input_flags.len() as u64));
    values.push(Goldilocks::new(
        stark_public_inputs.output_flags.len() as u64
    ));
    push_padded_bits(
        &mut values,
        &stark_public_inputs.input_flags,
        MAX_INPUTS,
        "input flags",
    )?;
    push_padded_bits(
        &mut values,
        &stark_public_inputs.output_flags,
        MAX_OUTPUTS,
        "output flags",
    )?;
    values.push(Goldilocks::new(stark_public_inputs.fee));
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.value_balance_sign,
    )));
    values.push(Goldilocks::new(stark_public_inputs.value_balance_magnitude));
    push_bytes48_limbs(&mut values, &stark_public_inputs.merkle_root)?;
    values.push(Goldilocks::new(
        stark_public_inputs.balance_slot_asset_ids.len() as u64,
    ));
    push_padded_u64s(
        &mut values,
        &stark_public_inputs.balance_slot_asset_ids,
        BALANCE_SLOTS,
    );
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.stablecoin_enabled,
    )));
    values.push(Goldilocks::new(stark_public_inputs.stablecoin_asset_id));
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.stablecoin_policy_version,
    )));
    values.push(Goldilocks::new(u64::from(
        stark_public_inputs.stablecoin_issuance_sign,
    )));
    values.push(Goldilocks::new(
        stark_public_inputs.stablecoin_issuance_magnitude,
    ));
    push_bytes48_limbs(&mut values, &stark_public_inputs.stablecoin_policy_hash)?;
    push_bytes48_limbs(
        &mut values,
        &stark_public_inputs.stablecoin_oracle_commitment,
    )?;
    push_bytes48_limbs(
        &mut values,
        &stark_public_inputs.stablecoin_attestation_commitment,
    )?;
    values.push(Goldilocks::new(tx.nullifiers.len() as u64));
    push_padded_digest_vec(&mut values, &tx.nullifiers, MAX_INPUTS)?;
    values.push(Goldilocks::new(tx.commitments.len() as u64));
    push_padded_digest_vec(&mut values, &tx.commitments, MAX_OUTPUTS)?;
    values.push(Goldilocks::new(tx.ciphertext_hashes.len() as u64));
    push_padded_digest_vec(&mut values, &tx.ciphertext_hashes, MAX_OUTPUTS)?;
    push_bytes48_limbs(&mut values, &tx.balance_tag)?;
    values.push(Goldilocks::new(u64::from(tx.version.circuit)));
    values.push(Goldilocks::new(u64::from(tx.version.crypto)));
    let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
    packer.pack(shape, &Assignment { witness: values })
}

fn tx_statement_hash_from_tx_leaf_public(
    tx: &RefTxLeafPublicTx,
    stark_inputs: &SerializedStarkInputs,
) -> Result<[u8; 48]> {
    let mut message = Vec::new();
    message.extend_from_slice(TX_STATEMENT_HASH_DOMAIN);
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

fn decode_signed_magnitude(sign: u8, magnitude: u64, label: &str) -> Result<i128> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        other => Err(anyhow!("{label} sign flag must be 0 or 1, got {other}")),
    }
}

fn push_padded_bits(
    values: &mut Vec<Goldilocks>,
    bits: &[u8],
    expected_len: usize,
    label: &str,
) -> Result<()> {
    ensure!(
        bits.len() <= expected_len,
        "{label} length {} exceeds {}",
        bits.len(),
        expected_len
    );
    ensure!(bits.iter().all(|bit| *bit <= 1), "{label} must be binary");
    for bit in bits {
        values.push(Goldilocks::new(u64::from(*bit)));
    }
    for _ in bits.len()..expected_len {
        values.push(Goldilocks::new(0));
    }
    Ok(())
}

fn push_padded_u64s(values: &mut Vec<Goldilocks>, ints: &[u64], expected_len: usize) {
    for value in ints {
        values.push(Goldilocks::new(*value));
    }
    for _ in ints.len()..expected_len {
        values.push(Goldilocks::new(0));
    }
}

fn push_bytes48_limbs(values: &mut Vec<Goldilocks>, bytes: &[u8; 48]) -> Result<()> {
    values.extend(
        bytes.chunks_exact(8).map(|chunk| {
            Goldilocks::new(u64::from_le_bytes(chunk.try_into().expect("8-byte limb")))
        }),
    );
    Ok(())
}

fn push_padded_digest_vec(
    values: &mut Vec<Goldilocks>,
    digests: &[[u8; 48]],
    expected_len: usize,
) -> Result<()> {
    ensure!(
        digests.len() <= expected_len,
        "digest vector length {} exceeds {}",
        digests.len(),
        expected_len
    );
    for digest in digests {
        push_bytes48_limbs(values, digest)?;
    }
    for _ in digests.len()..expected_len {
        for _ in 0..6 {
            values.push(Goldilocks::new(0));
        }
    }
    Ok(())
}

fn extend_padded_digests(
    out: &mut Vec<u8>,
    digests: &[[u8; 48]],
    expected_len: usize,
) -> Result<()> {
    ensure!(
        digests.len() <= expected_len,
        "digest vector length {} exceeds {}",
        digests.len(),
        expected_len
    );
    for digest in digests {
        out.extend_from_slice(digest);
    }
    for _ in digests.len()..expected_len {
        out.extend_from_slice(&[0u8; 48]);
    }
    Ok(())
}

fn parse_native_tx_leaf_artifact(
    params: &NativeBackendParams,
    bytes: &[u8],
) -> Result<RefNativeTxLeafArtifact> {
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
    let receipt = parse_canonical_receipt(bytes, &mut cursor)?;
    let stark_public_inputs = parse_serialized_stark_inputs(bytes, &mut cursor)?;
    let tx = parse_tx_leaf_public_tx(bytes, &mut cursor)?;
    let proof_len = read_u32_capped(
        bytes,
        &mut cursor,
        MAX_NATIVE_TX_STARK_PROOF_BYTES,
        "native tx-leaf proof bytes",
    )? as usize;
    let stark_proof = read_bytes(bytes, &mut cursor, proof_len)?;
    let commitment = parse_lattice_commitment(params, bytes, &mut cursor, "native tx-leaf")?;
    let leaf = parse_leaf_artifact(bytes, &mut cursor)?;
    ensure!(
        cursor == bytes.len(),
        "native tx-leaf artifact has {} trailing bytes",
        bytes.len().saturating_sub(cursor)
    );
    Ok(RefNativeTxLeafArtifact {
        version,
        params_fingerprint,
        spec_digest,
        relation_id,
        shape_digest,
        statement_digest,
        receipt,
        stark_public_inputs,
        tx,
        stark_proof,
        commitment,
        leaf,
    })
}

fn parse_receipt_root_artifact(
    params: &NativeBackendParams,
    bytes: &[u8],
) -> Result<RefReceiptRootArtifact> {
    ensure!(
        bytes.len()
            <= max_receipt_root_artifact_bytes_with_params(
                params.max_claimed_receipt_root_leaves as usize,
                params,
            ),
        "receipt-root artifact size {} exceeds {}",
        bytes.len(),
        max_receipt_root_artifact_bytes_with_params(
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
        leaves.push(RefReceiptRootLeaf {
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
        folds.push(RefReceiptRootFoldStep {
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
    Ok(RefReceiptRootArtifact {
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

fn parse_canonical_receipt(bytes: &[u8], cursor: &mut usize) -> Result<CanonicalTxValidityReceipt> {
    Ok(CanonicalTxValidityReceipt {
        statement_hash: read_array::<48>(bytes, cursor)?,
        proof_digest: read_array::<48>(bytes, cursor)?,
        public_inputs_digest: read_array::<48>(bytes, cursor)?,
        verifier_profile: read_array::<48>(bytes, cursor)?,
    })
}

fn parse_serialized_stark_inputs(
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

fn parse_tx_leaf_public_tx(bytes: &[u8], cursor: &mut usize) -> Result<RefTxLeafPublicTx> {
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
    Ok(RefTxLeafPublicTx {
        nullifiers,
        commitments,
        ciphertext_hashes,
        balance_tag: read_array::<48>(bytes, cursor)?,
        version: VersionBinding::new(read_u16(bytes, cursor)?, read_u16(bytes, cursor)?),
    })
}

fn parse_lattice_commitment(
    params: &NativeBackendParams,
    bytes: &[u8],
    cursor: &mut usize,
    label: &str,
) -> Result<LatticeCommitment> {
    let digest = read_array::<48>(bytes, cursor)?;
    let row_count = read_u32_capped(
        bytes,
        cursor,
        params.matrix_rows,
        &format!("{label} commitment rows"),
    )? as usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let coeff_count = read_u32_capped(
            bytes,
            cursor,
            params.matrix_cols,
            &format!("{label} commitment row coefficients"),
        )? as usize;
        let mut coeffs = Vec::with_capacity(coeff_count);
        for _ in 0..coeff_count {
            coeffs.push(read_u64(bytes, cursor)?);
        }
        rows.push(RingElem::from_coeffs(coeffs));
    }
    Ok(LatticeCommitment { digest, rows })
}

fn parse_leaf_artifact(bytes: &[u8], cursor: &mut usize) -> Result<LeafArtifact<LeafDigestProof>> {
    Ok(LeafArtifact {
        version: read_u16(bytes, cursor)?,
        relation_id: RelationId(read_array::<32>(bytes, cursor)?),
        shape_digest: ShapeDigest(read_array::<32>(bytes, cursor)?),
        statement_digest: StatementDigest(read_array::<48>(bytes, cursor)?),
        proof: LeafDigestProof {
            witness_commitment_digest: read_array::<48>(bytes, cursor)?,
            proof_digest: read_array::<48>(bytes, cursor)?,
        },
    })
}

fn max_native_tx_leaf_artifact_bytes_with_params(params: &NativeBackendParams) -> usize {
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
        + lattice_commitment_bytes
        + LEAF_ARTIFACT_WIRE_BYTES
}

fn max_receipt_root_artifact_bytes_with_params(
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

fn canonical_tx_validity_receipt_bytes(receipt: &CanonicalTxValidityReceipt) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CANONICAL_RECEIPT_WIRE_BYTES);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InferredFriProfileP3 {
    log_blowup: usize,
    num_queries: usize,
}

#[derive(Debug, Clone)]
enum TransactionVerifyErrorP3 {
    InvalidProofFormat,
    InvalidPublicInputs(String),
    VerificationFailed(String),
}

impl core::fmt::Display for TransactionVerifyErrorP3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidProofFormat => write!(f, "Invalid proof format"),
            Self::InvalidPublicInputs(err) => write!(f, "Invalid public inputs: {err}"),
            Self::VerificationFailed(err) => write!(f, "Verification failed: {err}"),
        }
    }
}

fn infer_fri_profile_from_proof_p3(
    proof: &TransactionProofP3,
) -> Result<InferredFriProfileP3, TransactionVerifyErrorP3> {
    let num_queries = proof.opening_proof.query_proofs.len();
    if num_queries == 0 {
        return Err(TransactionVerifyErrorP3::VerificationFailed(
            "proof has zero FRI queries".to_owned(),
        ));
    }
    let final_poly_len = proof.opening_proof.final_poly.len();
    if final_poly_len == 0 || !final_poly_len.is_power_of_two() {
        return Err(TransactionVerifyErrorP3::VerificationFailed(
            "proof final polynomial length is invalid".to_owned(),
        ));
    }
    let log_final_poly_len = final_poly_len.ilog2() as usize;
    let baseline = proof.opening_proof.commit_phase_commits.len() + log_final_poly_len;
    let mut observed_log_max_height: Option<usize> = None;
    for (query_index, query_proof) in proof.opening_proof.query_proofs.iter().enumerate() {
        let query_max = query_proof
            .input_proof
            .iter()
            .map(|batch| batch.opening_proof.len())
            .max()
            .ok_or_else(|| {
                TransactionVerifyErrorP3::VerificationFailed(format!(
                    "query {query_index} has no input opening proofs"
                ))
            })?;
        if query_max < baseline {
            return Err(TransactionVerifyErrorP3::VerificationFailed(format!(
                "query {query_index} opening depth {query_max} smaller than required baseline {baseline}"
            )));
        }
        match observed_log_max_height {
            Some(expected) if expected != query_max => {
                return Err(TransactionVerifyErrorP3::VerificationFailed(format!(
                    "query opening depth mismatch: expected {expected}, got {query_max} at query {query_index}"
                )));
            }
            Some(_) => {}
            None => observed_log_max_height = Some(query_max),
        }
    }
    let observed_log_max_height = observed_log_max_height.ok_or_else(|| {
        TransactionVerifyErrorP3::VerificationFailed("proof has no query opening paths".to_owned())
    })?;
    let log_blowup = observed_log_max_height
        .checked_sub(baseline)
        .ok_or_else(|| {
            TransactionVerifyErrorP3::VerificationFailed(
                "failed to infer FRI blowup from proof shape".to_owned(),
            )
        })?;
    Ok(InferredFriProfileP3 {
        log_blowup,
        num_queries,
    })
}

fn verify_transaction_proof_bytes_p3(
    proof_bytes: &[u8],
    pub_inputs: &TransactionPublicInputsP3,
) -> Result<(), TransactionVerifyErrorP3> {
    pub_inputs
        .validate()
        .map_err(TransactionVerifyErrorP3::InvalidPublicInputs)?;
    let proof: TransactionProofP3 = postcard::from_bytes(proof_bytes)
        .map_err(|_| TransactionVerifyErrorP3::InvalidProofFormat)?;
    let fri_profile = infer_fri_profile_from_proof_p3(&proof)?;
    let config = config_with_fri(fri_profile.log_blowup, fri_profile.num_queries);
    verify_uni_stark(
        &config.config,
        &TransactionAirP3,
        &proof,
        &pub_inputs.to_vec(),
    )
    .map_err(|err| TransactionVerifyErrorP3::VerificationFailed(format!("{err:?}")))
}

fn transaction_public_inputs_digest_from_serialized(
    stark_inputs: &SerializedStarkInputs,
) -> Result<[u8; 48]> {
    #[derive(Serialize)]
    struct DigestSerializedStarkInputs<'a> {
        input_flags: &'a [u8],
        output_flags: &'a [u8],
        fee: u64,
        value_balance_sign: u8,
        value_balance_magnitude: u64,
        #[serde(serialize_with = "serialize_bytes_48_ref")]
        merkle_root: &'a [u8; 48],
        balance_slot_asset_ids: &'a [u64],
        stablecoin_enabled: u8,
        stablecoin_asset_id: u64,
        stablecoin_policy_version: u32,
        stablecoin_issuance_sign: u8,
        stablecoin_issuance_magnitude: u64,
        #[serde(serialize_with = "serialize_bytes_48_ref")]
        stablecoin_policy_hash: &'a [u8; 48],
        #[serde(serialize_with = "serialize_bytes_48_ref")]
        stablecoin_oracle_commitment: &'a [u8; 48],
        #[serde(serialize_with = "serialize_bytes_48_ref")]
        stablecoin_attestation_commitment: &'a [u8; 48],
    }

    let encoded = postcard::to_allocvec(&DigestSerializedStarkInputs {
        input_flags: &stark_inputs.input_flags,
        output_flags: &stark_inputs.output_flags,
        fee: stark_inputs.fee,
        value_balance_sign: stark_inputs.value_balance_sign,
        value_balance_magnitude: stark_inputs.value_balance_magnitude,
        merkle_root: &stark_inputs.merkle_root,
        balance_slot_asset_ids: &stark_inputs.balance_slot_asset_ids,
        stablecoin_enabled: stark_inputs.stablecoin_enabled,
        stablecoin_asset_id: stark_inputs.stablecoin_asset_id,
        stablecoin_policy_version: stark_inputs.stablecoin_policy_version,
        stablecoin_issuance_sign: stark_inputs.stablecoin_issuance_sign,
        stablecoin_issuance_magnitude: stark_inputs.stablecoin_issuance_magnitude,
        stablecoin_policy_hash: &stark_inputs.stablecoin_policy_hash,
        stablecoin_oracle_commitment: &stark_inputs.stablecoin_oracle_commitment,
        stablecoin_attestation_commitment: &stark_inputs.stablecoin_attestation_commitment,
    })
    .map_err(|err| anyhow!("failed to serialize STARK public inputs: {err}"))?;
    Ok(digest48_with_parts(
        TX_PUBLIC_INPUTS_DIGEST_DOMAIN,
        &[&encoded],
    ))
}

fn digest_commitment_rows(rows: &[RingElem]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.commitment-digest.v2");
    hasher.update(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        hasher.update(&(row.coeffs.len() as u64).to_le_bytes());
        for coeff in &row.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    hash48(hasher)
}

fn digest32_with_label(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(bytes);
    hash32(hasher)
}

fn embed_packed_witness(pk: &BackendKey, packed: &PackedWitness<u64>) -> Result<Vec<RingElem>> {
    let digits = expand_packed_digits(packed, pk.digit_bits)?;
    let mut ring_elems = Vec::with_capacity(digits.len().div_ceil(pk.ring_degree));
    for chunk in digits.chunks(pk.ring_degree) {
        let mut coeffs = vec![0u64; pk.ring_degree];
        for (idx, digit) in chunk.iter().enumerate() {
            coeffs[idx] = *digit;
        }
        ring_elems.push(RingElem::from_coeffs(coeffs));
    }
    Ok(ring_elems)
}

fn expand_packed_digits(packed: &PackedWitness<u64>, digit_bits: u16) -> Result<Vec<u64>> {
    ensure!(
        (1..=64).contains(&packed.coeff_capacity_bits),
        "packed witness coeff capacity must be in 1..=64"
    );
    ensure!(
        (1..=16).contains(&digit_bits),
        "digit_bits must be in 1..=16"
    );
    let total_value_bits = packed
        .value_bit_widths
        .iter()
        .map(|width| usize::from(*width))
        .sum::<usize>();
    ensure!(
        total_value_bits == packed.used_bits,
        "packed witness width metadata covers {} bits but used_bits is {}",
        total_value_bits,
        packed.used_bits
    );
    let bits = expand_packed_bits(packed)?;
    let mut digits = Vec::with_capacity(bits.len().div_ceil(digit_bits as usize));
    let mut cursor = 0usize;
    while cursor < bits.len() {
        let mut digit = 0u64;
        for offset in 0..digit_bits as usize {
            let bit_index = cursor + offset;
            if bit_index >= bits.len() {
                break;
            }
            digit |= u64::from(bits[bit_index]) << offset;
        }
        digits.push(digit);
        cursor += digit_bits as usize;
    }
    Ok(digits)
}

fn expand_packed_bits(packed: &PackedWitness<u64>) -> Result<Vec<u8>> {
    let coeff_capacity = packed.coeff_capacity_bits as usize;
    let mut bits = Vec::with_capacity(packed.used_bits);
    for bit_index in 0..packed.used_bits {
        let coeff_index = bit_index / coeff_capacity;
        let bit_offset = (bit_index % coeff_capacity) as u16;
        let coeff = *packed
            .coeffs
            .get(coeff_index)
            .ok_or_else(|| anyhow!("packed witness ended early while expanding bits"))?;
        bits.push(((coeff >> bit_offset) & 1) as u8);
    }
    Ok(bits)
}

fn commit_ring_message(pk: &BackendKey, message: &[RingElem]) -> Vec<RingElem> {
    let mut accumulators = vec![vec![0i128; pk.ring_degree]; pk.commitment_rows];
    for (col_index, message_elem) in message.iter().enumerate() {
        for (row_index, accumulator) in accumulators.iter_mut().enumerate() {
            accumulate_negacyclic_product(
                accumulator,
                &matrix_entry(pk, row_index, col_index),
                message_elem,
            );
        }
    }
    accumulators
        .into_iter()
        .map(|coeffs| {
            RingElem::from_coeffs(coeffs.into_iter().map(reduce_goldilocks_signed).collect())
        })
        .collect()
}

fn matrix_entry(pk: &BackendKey, row_index: usize, col_index: usize) -> RingElem {
    let mut coeffs = Vec::with_capacity(pk.ring_degree);
    for coeff_index in 0..pk.ring_degree {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.ajtai-matrix.v1");
        hasher.update(&pk.params_fingerprint);
        hasher.update(pk.ring_profile.label());
        hasher.update(&pk.shape_digest.0);
        hasher.update(&pk.security_bits.to_le_bytes());
        hasher.update(&pk.challenge_bits.to_le_bytes());
        hasher.update(&pk.max_fold_arity.to_le_bytes());
        hasher.update(&pk.transcript_domain_digest);
        hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
        hasher.update(&(pk.ring_degree as u64).to_le_bytes());
        hasher.update(&pk.digit_bits.to_le_bytes());
        hasher.update(&pk.opening_randomness_bits.to_le_bytes());
        hasher.update(&(row_index as u64).to_le_bytes());
        hasher.update(&(col_index as u64).to_le_bytes());
        hasher.update(&(coeff_index as u64).to_le_bytes());
        let mut out = [0u8; 8];
        hasher.finalize_xof().fill(&mut out);
        coeffs.push(Goldilocks::new(u64::from_le_bytes(out)).as_canonical_u64());
    }
    RingElem::from_coeffs(coeffs)
}

fn accumulate_negacyclic_product(accumulator: &mut [i128], left: &RingElem, right: &RingElem) {
    let degree = left.coeffs.len();
    for (i, left_coeff) in left.coeffs.iter().enumerate() {
        for (j, right_coeff) in right.coeffs.iter().enumerate() {
            if *right_coeff == 0 {
                continue;
            }
            let target = i + j;
            let product = i128::from(*left_coeff) * i128::from(*right_coeff);
            if target < degree {
                accumulator[target] += product;
            } else {
                accumulator[target - degree] -= product;
            }
        }
    }
}

fn derive_fold_challenges(
    pk: &BackendKey,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
) -> Vec<u64> {
    let mut transcript = Vec::with_capacity(48 + 32 + 32 + 48 + 48 + 64);
    transcript.extend_from_slice(&pk.params_fingerprint);
    transcript.extend_from_slice(pk.ring_profile.label());
    transcript.extend_from_slice(&pk.shape_digest.0);
    transcript.extend_from_slice(&left.relation_id.0);
    transcript.extend_from_slice(&pk.security_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.challenge_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.fold_challenge_count.to_le_bytes());
    transcript.extend_from_slice(&pk.max_fold_arity.to_le_bytes());
    transcript.extend_from_slice(&pk.transcript_domain_digest);
    transcript.extend_from_slice(&(pk.commitment_rows as u64).to_le_bytes());
    transcript.extend_from_slice(&(pk.ring_degree as u64).to_le_bytes());
    transcript.extend_from_slice(&pk.digit_bits.to_le_bytes());
    transcript.extend_from_slice(&pk.opening_randomness_bits.to_le_bytes());
    transcript.extend_from_slice(&left.statement_digest.0);
    transcript.extend_from_slice(&right.statement_digest.0);
    transcript.extend_from_slice(&left.witness_commitment.digest);
    transcript.extend_from_slice(&right.witness_commitment.digest);

    (0..pk.fold_challenge_count as usize)
        .map(|challenge_index| {
            let mut hasher = Hasher::new();
            hasher.update(b"hegemon.superneo.fold-challenge.v3");
            hasher.update(&transcript);
            hasher.update(&(challenge_index as u64).to_le_bytes());
            let mut out = [0u8; 8];
            hasher.finalize_xof().fill(&mut out);
            reduce_fold_challenge(pk.challenge_bits, u64::from_le_bytes(out))
        })
        .collect()
}

fn fold_commitment_rows(
    left: &LatticeCommitment,
    right: &LatticeCommitment,
    challenges: &[u64],
) -> Result<Vec<RingElem>> {
    ensure!(
        !left.rows.is_empty() && !right.rows.is_empty(),
        "folded commitments require concrete row data"
    );
    ensure!(
        left.rows.len() == right.rows.len(),
        "folded commitments must have the same row length"
    );
    ensure!(
        !challenges.is_empty(),
        "folded commitments require at least one challenge"
    );
    left.rows
        .iter()
        .zip(&right.rows)
        .map(|(left_row, right_row)| {
            delayed_linear_combine_with_schedule(left_row, right_row, challenges)
        })
        .collect()
}

fn delayed_linear_combine_with_schedule(
    left: &RingElem,
    right: &RingElem,
    challenges: &[u64],
) -> Result<RingElem> {
    ensure!(
        left.coeffs.len() == right.coeffs.len(),
        "cannot combine ring elements with different degrees"
    );
    let mut coeffs = Vec::with_capacity(left.coeffs.len());
    for (coeff_index, left_coeff) in left.coeffs.iter().enumerate() {
        let mut value = Goldilocks::new(*left_coeff);
        for (rotation, challenge) in challenges.iter().copied().enumerate() {
            let right_coeff = negacyclic_rotated_coeff(right, coeff_index, rotation);
            value += Goldilocks::new(challenge) * goldilocks_from_signed(right_coeff);
        }
        coeffs.push(value.as_canonical_u64());
    }
    Ok(RingElem::from_coeffs(coeffs))
}

fn negacyclic_rotated_coeff(row: &RingElem, coeff_index: usize, rotation: usize) -> i128 {
    let degree = row.coeffs.len();
    let source_index = coeff_index + rotation;
    let wraps = source_index / degree;
    let index = source_index % degree;
    let coeff = i128::from(row.coeffs[index]);
    if wraps.is_multiple_of(2) {
        coeff
    } else {
        -coeff
    }
}

fn reduce_fold_challenge(challenge_bits: u32, raw: u64) -> u64 {
    let mask_bits = challenge_bits.min(63);
    let modulus = 1u64 << mask_bits;
    let reduced = if modulus <= 1 {
        1
    } else {
        (raw % (modulus - 1)) + 1
    };
    Goldilocks::new(reduced).as_canonical_u64()
}

fn goldilocks_from_signed(value: i128) -> Goldilocks {
    Goldilocks::new(reduce_goldilocks_signed(value))
}

fn reduce_goldilocks_signed(value: i128) -> u64 {
    let mut reduced = value % GOLDILOCKS_MODULUS_I128;
    if reduced < 0 {
        reduced += GOLDILOCKS_MODULUS_I128;
    }
    reduced as u64
}

fn leaf_proof_digest(
    pk: &BackendKey,
    relation_id: &RelationId,
    statement_digest: &StatementDigest,
    packed: &PackedWitness<u64>,
    commitment_digest: &[u8; 48],
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.leaf-proof.v2");
    hasher.update(&pk.params_fingerprint);
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&pk.opening_randomness_bits.to_le_bytes());
    hasher.update(&statement_digest.0);
    hasher.update(commitment_digest);
    hasher.update(&(packed.original_len as u64).to_le_bytes());
    hasher.update(&(packed.used_bits as u64).to_le_bytes());
    hasher.update(&packed.coeff_capacity_bits.to_le_bytes());
    hasher.update(&(packed.coeffs.len() as u64).to_le_bytes());
    for coeff in &packed.coeffs {
        hasher.update(&coeff.to_le_bytes());
    }
    hash48(hasher)
}

fn fold_statement_digest(
    left: &StatementDigest,
    right: &StatementDigest,
    challenges: &[u64],
    parent_commitment_digest: &[u8; 48],
) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-statement.v3");
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    for challenge in challenges {
        hasher.update(&challenge.to_le_bytes());
    }
    hasher.update(&left.0);
    hasher.update(&right.0);
    hasher.update(parent_commitment_digest);
    StatementDigest(hash48(hasher))
}

fn fold_proof_digest(
    pk: &BackendKey,
    relation_id: &RelationId,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
    challenges: &[u64],
    parent_statement_digest: &StatementDigest,
    parent_rows: &[RingElem],
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-proof.v3");
    hasher.update(&pk.params_fingerprint);
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.fold_challenge_count.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&pk.opening_randomness_bits.to_le_bytes());
    hasher.update(&(challenges.len() as u32).to_le_bytes());
    for challenge in challenges {
        hasher.update(&challenge.to_le_bytes());
    }
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    hasher.update(&parent_statement_digest.0);
    hasher.update(&digest_commitment_rows(parent_rows));
    hasher.update(&(parent_rows.len() as u64).to_le_bytes());
    for row in parent_rows {
        hasher.update(&(row.coeffs.len() as u64).to_le_bytes());
        for coeff in &row.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    hash48(hasher)
}

fn review_parameter_fingerprint(params: &NativeBackendParams) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.native-backend-params.v2");
    hasher.update(params.manifest.family_label.as_bytes());
    hasher.update(params.manifest.spec_label.as_bytes());
    hasher.update(params.manifest.commitment_scheme_label.as_bytes());
    hasher.update(params.manifest.challenge_schedule_label.as_bytes());
    hasher.update(params.manifest.maturity_label.as_bytes());
    hasher.update(&params.security_bits.to_le_bytes());
    hasher.update(review_ring_profile_label(params.ring_profile));
    hasher.update(&(params.matrix_rows as u64).to_le_bytes());
    hasher.update(&(params.matrix_cols as u64).to_le_bytes());
    hasher.update(&params.challenge_bits.to_le_bytes());
    hasher.update(&params.fold_challenge_count.to_le_bytes());
    hasher.update(&params.max_fold_arity.to_le_bytes());
    hasher.update(params.transcript_domain_label.as_bytes());
    hasher.update(&params.decomposition_bits.to_le_bytes());
    hasher.update(&params.opening_randomness_bits.to_le_bytes());
    hasher.update(&[match params.commitment_security_model {
        CommitmentSecurityModel::GeometryProxy => 0u8,
        CommitmentSecurityModel::BoundedKernelModuleSis => 1u8,
    }]);
    hasher.update(commitment_estimator_model_label(params.commitment_estimator_model).as_bytes());
    hasher.update(&params.max_commitment_message_ring_elems.to_le_bytes());
    hasher.update(&params.max_claimed_receipt_root_leaves.to_le_bytes());
    hash48(hasher)
}

fn review_spec_digest(params: &NativeBackendParams) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.native-backend-spec-digest.v1");
    hasher.update(params.manifest.family_label.as_bytes());
    hasher.update(params.manifest.spec_label.as_bytes());
    hasher.update(params.manifest.commitment_scheme_label.as_bytes());
    hasher.update(params.manifest.challenge_schedule_label.as_bytes());
    hasher.update(params.manifest.maturity_label.as_bytes());
    hasher.update(&params.security_bits.to_le_bytes());
    hasher.update(review_ring_profile_label(params.ring_profile));
    hasher.update(&(params.matrix_rows as u64).to_le_bytes());
    hasher.update(&(params.matrix_cols as u64).to_le_bytes());
    hasher.update(&params.challenge_bits.to_le_bytes());
    hasher.update(&params.fold_challenge_count.to_le_bytes());
    hasher.update(&params.max_fold_arity.to_le_bytes());
    hasher.update(params.transcript_domain_label.as_bytes());
    hasher.update(&params.decomposition_bits.to_le_bytes());
    hasher.update(&params.opening_randomness_bits.to_le_bytes());
    hasher.update(&[match params.commitment_security_model {
        CommitmentSecurityModel::GeometryProxy => 0u8,
        CommitmentSecurityModel::BoundedKernelModuleSis => 1u8,
    }]);
    hasher.update(commitment_estimator_model_label(params.commitment_estimator_model).as_bytes());
    hasher.update(&params.max_commitment_message_ring_elems.to_le_bytes());
    hasher.update(&params.max_claimed_receipt_root_leaves.to_le_bytes());
    hash32(hasher)
}

fn review_verifier_profile(
    params: &NativeBackendParams,
    relation_id: &RelationId,
    shape_digest: &ShapeDigest,
    profile_label: &[u8],
) -> [u8; 48] {
    digest48_with_parts(
        b"hegemon.superneo.explicit-verifier-profile.v1",
        &[
            profile_label,
            &review_parameter_fingerprint(params),
            &review_spec_digest(params),
            &relation_id.0,
            &shape_digest.0,
        ],
    )
}

fn review_ring_profile_label(profile: RingProfile) -> &'static [u8] {
    match profile {
        RingProfile::GoldilocksCyclotomic24 => b"goldilocks-cyclotomic24",
        RingProfile::GoldilocksFrog => b"goldilocks-frog",
    }
}

fn parse_review_ring_profile(value: &str) -> Result<RingProfile> {
    match value {
        "GoldilocksCyclotomic24" => Ok(RingProfile::GoldilocksCyclotomic24),
        "GoldilocksFrog" => Ok(RingProfile::GoldilocksFrog),
        other => Err(anyhow!("unsupported ring_profile {other}")),
    }
}

fn parse_commitment_security_model(value: &str) -> Result<CommitmentSecurityModel> {
    match value {
        "geometry_proxy" => Ok(CommitmentSecurityModel::GeometryProxy),
        "bounded_kernel_module_sis" => Ok(CommitmentSecurityModel::BoundedKernelModuleSis),
        other => Err(anyhow!("unsupported commitment_security_model {other}")),
    }
}

fn commitment_estimator_model_label(model: CommitmentEstimatorModel) -> &'static str {
    match model {
        CommitmentEstimatorModel::SisLatticeEuclideanAdps16 => "sis_lattice_euclidean_adps16",
    }
}

fn parse_commitment_estimator_model(value: &str) -> Result<CommitmentEstimatorModel> {
    match value {
        "sis_lattice_euclidean_adps16" => Ok(CommitmentEstimatorModel::SisLatticeEuclideanAdps16),
        other => Err(anyhow!("unsupported commitment_estimator_model {other}")),
    }
}

fn validate_review_params(params: &NativeBackendParams) -> Result<()> {
    ensure!(
        params.matrix_rows > 0,
        "matrix_rows must be strictly positive"
    );
    ensure!(
        params.matrix_cols > 0,
        "matrix_cols must be strictly positive"
    );
    ensure!(
        (1..=63).contains(&params.challenge_bits),
        "challenge_bits must be in 1..=63"
    );
    ensure!(
        (1..=8).contains(&params.fold_challenge_count),
        "fold_challenge_count must be in 1..=8"
    );
    ensure!(
        params.max_fold_arity == 2,
        "binary fold backend requires max_fold_arity == 2"
    );
    ensure!(
        (1..=16).contains(&params.decomposition_bits),
        "decomposition_bits must be in 1..=16"
    );
    ensure!(
        params.opening_randomness_bits > 0 && params.opening_randomness_bits <= 256,
        "opening_randomness_bits must be in 1..=256"
    );
    let _ = params.commitment_estimator_model;
    ensure!(
        params.max_claimed_receipt_root_leaves > 0,
        "max_claimed_receipt_root_leaves must be strictly positive"
    );
    Ok(())
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes =
        hex::decode(value).with_context(|| format!("hex string has invalid encoding: {value}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow!("hex string has {} bytes, expected {}", len, N))
}

fn digest48(label: &[u8], payload: &[u8]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(payload);
    hash48(hasher)
}

fn digest48_with_parts(label: &[u8], parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    for part in parts {
        hasher.update(part);
    }
    hash48(hasher)
}

fn blake3_384_bytes(bytes: &[u8]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hash48(hasher)
}

fn hash48(hasher: Hasher) -> [u8; 48] {
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hash32(hasher: Hasher) -> [u8; 32] {
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn serialize_bytes_48_ref<S>(
    value: &&[u8; 48],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(*value)
}

fn default_commitment_security_model() -> String {
    "bounded_kernel_module_sis".to_owned()
}

fn default_commitment_estimator_model() -> String {
    "sis_lattice_euclidean_adps16".to_owned()
}

fn default_max_commitment_message_ring_elems() -> u32 {
    513
}

fn default_max_claimed_receipt_root_leaves() -> u32 {
    128
}

fn extract_bits(value: u64, offset: u16, width: u16) -> u64 {
    let shifted = value >> offset;
    if width == 64 {
        shifted
    } else {
        shifted & ((1u64 << width) - 1)
    }
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
        "artifact ended early while reading {} bytes",
        N
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode as hex_encode;
    use std::path::PathBuf;

    #[test]
    fn parses_and_verifies_bundle_from_testdata() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tools dir")
            .parent()
            .expect("repo root")
            .join("testdata/native_backend_vectors");
        if !root.exists() {
            return;
        }
        let (summary, results) = verify_bundle_dir(&root).expect("bundle verification");
        assert_eq!(
            summary.failed_cases, 0,
            "unexpected vector failures: {:?}",
            results
        );
    }

    #[test]
    fn review_bundle_params_round_trip_to_matching_fingerprint() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("tools dir")
            .parent()
            .expect("repo root")
            .join("testdata/native_backend_vectors");
        if !root.exists() {
            return;
        }
        let bundle = load_bundle(&root.join("bundle.json")).expect("bundle load");
        let params = review_params_to_native(&bundle.native_backend_params).expect("params");
        let bundle_fingerprint =
            decode_hex_array::<48>(&bundle.parameter_fingerprint).expect("bundle fingerprint");
        let production_fingerprint = params.parameter_fingerprint();
        let reference_fingerprint = review_parameter_fingerprint(&params);
        assert_eq!(
            hex_encode(production_fingerprint),
            hex_encode(bundle_fingerprint),
            "production fingerprint mismatch: family={} spec={} scheme={} schedule={} maturity={} sec={} ring={:?} rows={} cols={} chall={} fold_count={} arity={} domain={} decomp={} opening={} commitment_model={:?} estimator_model={:?} max_msg={} max_leaves={}",
            params.manifest.family_label,
            params.manifest.spec_label,
            params.manifest.commitment_scheme_label,
            params.manifest.challenge_schedule_label,
            params.manifest.maturity_label,
            params.security_bits,
            params.ring_profile,
            params.matrix_rows,
            params.matrix_cols,
            params.challenge_bits,
            params.fold_challenge_count,
            params.max_fold_arity,
            params.transcript_domain_label,
            params.decomposition_bits,
            params.opening_randomness_bits,
            params.commitment_security_model,
            params.commitment_estimator_model,
            params.max_commitment_message_ring_elems,
            params.max_claimed_receipt_root_leaves,
        );
        assert_eq!(
            hex_encode(reference_fingerprint),
            hex_encode(bundle_fingerprint),
            "reference fingerprint mismatch: family={} spec={} scheme={} schedule={} maturity={} sec={} ring={:?} rows={} cols={} chall={} fold_count={} arity={} domain={} decomp={} opening={} commitment_model={:?} estimator_model={:?} max_msg={} max_leaves={}",
            params.manifest.family_label,
            params.manifest.spec_label,
            params.manifest.commitment_scheme_label,
            params.manifest.challenge_schedule_label,
            params.manifest.maturity_label,
            params.security_bits,
            params.ring_profile,
            params.matrix_rows,
            params.matrix_cols,
            params.challenge_bits,
            params.fold_challenge_count,
            params.max_fold_arity,
            params.transcript_domain_label,
            params.decomposition_bits,
            params.opening_randomness_bits,
            params.commitment_security_model,
            params.commitment_estimator_model,
            params.max_commitment_message_ring_elems,
            params.max_claimed_receipt_root_leaves,
        );
    }
}
