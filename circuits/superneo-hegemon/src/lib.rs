use anyhow::{ensure, Result};
use blake3::Hasher;
use p3_goldilocks::Goldilocks;
use superneo_backend_lattice::{LatticeBackend, LatticeCommitment, LeafDigestProof};
use superneo_ccs::{
    digest_statement, Assignment, CcsShape, Relation, RelationId, SparseEntry, SparseMatrix,
    StatementEncoding, WitnessField, WitnessSchema,
};
use superneo_core::{Backend, FoldedInstance, SecurityParams};
use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};

pub const MAX_RECEIPT_BYTES: usize = 96;
pub const MAX_TRACE_BITS: usize = 256;
pub const RECEIPT_ROOT_ARTIFACT_VERSION: u16 = 1;
pub const RECEIPT_ROOT_DIGEST_WIDTH: usize = 4;
pub const RECEIPT_ROOT_LIMBS_PER_DIGEST: usize = 6;
pub const RECEIPT_ROOT_WITNESS_LIMBS: usize =
    RECEIPT_ROOT_DIGEST_WIDTH * RECEIPT_ROOT_LIMBS_PER_DIGEST;

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
        let proof = backend.prove_leaf(&pk, &relation.relation_id(), &encoding, &packed)?;
        leaves.push(ReceiptRootLeaf {
            statement_digest: encoding.statement_digest.0,
            witness_commitment: proof.witness_commitment.digest,
            proof_digest: proof.proof_digest,
        });
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: proof.witness_commitment,
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
            witness_commitment: LatticeCommitment::digest_only(leaf.witness_commitment),
            packed_witness: packed,
            proof_digest: leaf.proof_digest,
        };
        backend.verify_leaf(&vk, &relation.relation_id(), &encoding, &proof)?;
        current.push(FoldedInstance {
            relation_id: relation.relation_id(),
            shape_digest: pk.shape_digest,
            statement_digest: encoding.statement_digest,
            witness_commitment: backend.commit_witness(&pk, &proof.packed_witness)?,
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

#[cfg(test)]
mod tests {
    use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};

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
}
