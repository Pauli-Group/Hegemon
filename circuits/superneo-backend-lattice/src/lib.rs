use anyhow::{ensure, Result};
use blake3::Hasher;
use p3_goldilocks::Goldilocks;
use serde::{Serialize, Serializer};
use superneo_ccs::{
    digest_shape, CcsShape, RelationId, ShapeDigest, StatementDigest, StatementEncoding,
};
use superneo_core::{validate_fold_pair, Backend, FoldedInstance, SecurityParams};
use superneo_ring::PackedWitness;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LatticeBackendConfig {
    pub ring_profile: RingProfile,
    pub security_bits: u32,
    pub challenge_bits: u32,
}

impl Default for LatticeBackendConfig {
    fn default() -> Self {
        Self {
            ring_profile: RingProfile::GoldilocksCyclotomic24,
            security_bits: 128,
            challenge_bits: 128,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LatticeBackend {
    pub config: LatticeBackendConfig,
}

impl Default for LatticeBackend {
    fn default() -> Self {
        Self {
            config: LatticeBackendConfig::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackendKey {
    pub shape_digest: ShapeDigest,
    pub security_bits: u32,
    pub challenge_bits: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_digest: [u8; 32],
    pub ring_profile: RingProfile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeCommitment(pub [u8; 48]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LeafDigestProof {
    pub witness_commitment: LatticeCommitment,
    pub proof_digest: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FoldDigestProof {
    pub parent_statement_digest: StatementDigest,
    pub parent_commitment: LatticeCommitment,
    pub proof_digest: LatticeCommitment,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackendShape {
    pub shape_digest: ShapeDigest,
    pub num_rows: usize,
    pub num_cols: usize,
    pub matrix_count: usize,
    pub selector_count: usize,
    pub witness_bits: usize,
}

impl LatticeCommitment {
    pub const BYTES: usize = 48;

    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.0.len() * 2);
        for byte in self.0 {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }
}

impl LeafDigestProof {
    pub const BYTES: usize = LatticeCommitment::BYTES * 2;
}

impl FoldDigestProof {
    pub const BYTES: usize = StatementDigest::BYTES + (LatticeCommitment::BYTES * 2);
}

impl Serialize for LatticeCommitment {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl LatticeBackend {
    pub fn new(config: LatticeBackendConfig) -> Self {
        Self { config }
    }
}

impl Backend<Goldilocks> for LatticeBackend {
    type ProverKey = BackendKey;
    type VerifierKey = BackendKey;
    type PackedWitness = PackedWitness<u64>;
    type Commitment = LatticeCommitment;
    type LeafProof = LeafDigestProof;
    type FoldProof = FoldDigestProof;

    fn setup(
        &self,
        security: &SecurityParams,
        shape: &CcsShape<Goldilocks>,
    ) -> Result<(Self::ProverKey, Self::VerifierKey)> {
        shape.validate()?;
        let key = BackendKey {
            shape_digest: digest_shape(shape),
            security_bits: security.target_security_bits,
            challenge_bits: self.config.challenge_bits,
            max_fold_arity: security.max_fold_arity,
            transcript_domain_digest: digest32_with_label(
                b"hegemon.superneo.mock.transcript-domain.v1",
                security.transcript_domain,
            ),
            ring_profile: self.config.ring_profile,
        };
        Ok((key.clone(), key))
    }

    fn commit_witness(
        &self,
        pk: &Self::ProverKey,
        packed: &Self::PackedWitness,
    ) -> Result<Self::Commitment> {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.mock.commitment.v1");
        hasher.update(pk.ring_profile.label());
        hasher.update(&pk.shape_digest.0);
        hasher.update(&pk.security_bits.to_le_bytes());
        hasher.update(&pk.challenge_bits.to_le_bytes());
        hasher.update(&pk.max_fold_arity.to_le_bytes());
        hasher.update(&pk.transcript_domain_digest);
        hasher.update(&(packed.original_len as u64).to_le_bytes());
        hasher.update(&(packed.used_bits as u64).to_le_bytes());
        for coeff in &packed.coeffs {
            hasher.update(&coeff.to_le_bytes());
        }
        Ok(LatticeCommitment(hash48(hasher)))
    }

    fn prove_leaf(
        &self,
        pk: &Self::ProverKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        packed: &Self::PackedWitness,
    ) -> Result<Self::LeafProof> {
        let witness_commitment = self.commit_witness(pk, packed)?;
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.mock.leaf.v1");
        hasher.update(pk.ring_profile.label());
        hasher.update(&pk.shape_digest.0);
        hasher.update(&relation_id.0);
        hasher.update(&pk.security_bits.to_le_bytes());
        hasher.update(&pk.challenge_bits.to_le_bytes());
        hasher.update(&pk.max_fold_arity.to_le_bytes());
        hasher.update(&pk.transcript_domain_digest);
        hasher.update(&statement.statement_digest.0);
        hasher.update(&witness_commitment.0);
        Ok(LeafDigestProof {
            witness_commitment,
            proof_digest: LatticeCommitment(hash48(hasher)),
        })
    }

    fn verify_leaf(
        &self,
        vk: &Self::VerifierKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        proof: &Self::LeafProof,
    ) -> Result<()> {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.mock.leaf.v1");
        hasher.update(vk.ring_profile.label());
        hasher.update(&vk.shape_digest.0);
        hasher.update(&relation_id.0);
        hasher.update(&vk.security_bits.to_le_bytes());
        hasher.update(&vk.challenge_bits.to_le_bytes());
        hasher.update(&vk.max_fold_arity.to_le_bytes());
        hasher.update(&vk.transcript_domain_digest);
        hasher.update(&statement.statement_digest.0);
        hasher.update(&proof.witness_commitment.0);
        ensure!(
            proof.proof_digest == LatticeCommitment(hash48(hasher)),
            "leaf digest proof mismatch"
        );
        Ok(())
    }

    fn fold_pair(
        &self,
        pk: &Self::ProverKey,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
    ) -> Result<(FoldedInstance<Self::Commitment>, Self::FoldProof)> {
        validate_fold_pair(left, right)?;
        let parent_statement_digest =
            fold_statement_digest(&left.statement_digest, &right.statement_digest);
        let parent_commitment =
            fold_commitment(&left.witness_commitment, &right.witness_commitment);
        let mut proof_hasher = Hasher::new();
        proof_hasher.update(b"hegemon.superneo.mock.fold.v1");
        proof_hasher.update(pk.ring_profile.label());
        proof_hasher.update(&pk.shape_digest.0);
        proof_hasher.update(&left.relation_id.0);
        proof_hasher.update(&pk.security_bits.to_le_bytes());
        proof_hasher.update(&pk.challenge_bits.to_le_bytes());
        proof_hasher.update(&pk.max_fold_arity.to_le_bytes());
        proof_hasher.update(&pk.transcript_domain_digest);
        proof_hasher.update(&left.statement_digest.0);
        proof_hasher.update(&right.statement_digest.0);
        proof_hasher.update(&parent_statement_digest.0);
        proof_hasher.update(&parent_commitment.0);
        let proof = FoldDigestProof {
            parent_statement_digest,
            parent_commitment: parent_commitment.clone(),
            proof_digest: LatticeCommitment(hash48(proof_hasher)),
        };
        let parent = FoldedInstance {
            relation_id: left.relation_id,
            shape_digest: left.shape_digest,
            statement_digest: parent_statement_digest,
            witness_commitment: parent_commitment,
        };
        Ok((parent, proof))
    }

    fn verify_fold(
        &self,
        vk: &Self::VerifierKey,
        parent: &FoldedInstance<Self::Commitment>,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
        proof: &Self::FoldProof,
    ) -> Result<()> {
        validate_fold_pair(left, right)?;
        ensure!(
            left.shape_digest == vk.shape_digest,
            "left folded instance shape digest does not match verifier key"
        );
        ensure!(
            right.shape_digest == vk.shape_digest,
            "right folded instance shape digest does not match verifier key"
        );
        ensure!(
            parent.shape_digest == vk.shape_digest,
            "parent folded instance shape digest does not match verifier key"
        );
        ensure!(
            parent.relation_id == left.relation_id && left.relation_id == right.relation_id,
            "parent relation id does not match folded children"
        );
        ensure!(
            parent.shape_digest == left.shape_digest && left.shape_digest == right.shape_digest,
            "parent shape digest does not match folded children"
        );
        ensure!(
            parent.statement_digest == proof.parent_statement_digest,
            "parent statement digest mismatch"
        );
        ensure!(
            parent.witness_commitment == proof.parent_commitment,
            "parent witness commitment mismatch"
        );
        let expected_statement =
            fold_statement_digest(&left.statement_digest, &right.statement_digest);
        ensure!(
            expected_statement == parent.statement_digest,
            "folded statement digest mismatch"
        );
        let expected_commitment =
            fold_commitment(&left.witness_commitment, &right.witness_commitment);
        ensure!(
            expected_commitment == parent.witness_commitment,
            "folded witness commitment mismatch"
        );

        let mut proof_hasher = Hasher::new();
        proof_hasher.update(b"hegemon.superneo.mock.fold.v1");
        proof_hasher.update(vk.ring_profile.label());
        proof_hasher.update(&vk.shape_digest.0);
        proof_hasher.update(&left.relation_id.0);
        proof_hasher.update(&vk.security_bits.to_le_bytes());
        proof_hasher.update(&vk.challenge_bits.to_le_bytes());
        proof_hasher.update(&vk.max_fold_arity.to_le_bytes());
        proof_hasher.update(&vk.transcript_domain_digest);
        proof_hasher.update(&left.statement_digest.0);
        proof_hasher.update(&right.statement_digest.0);
        proof_hasher.update(&parent.statement_digest.0);
        proof_hasher.update(&parent.witness_commitment.0);
        ensure!(
            proof.proof_digest == LatticeCommitment(hash48(proof_hasher)),
            "fold digest proof mismatch"
        );
        Ok(())
    }
}

pub fn to_backend_ccs(shape: &CcsShape<Goldilocks>) -> Result<BackendShape> {
    shape.validate()?;
    Ok(BackendShape {
        shape_digest: digest_shape(shape),
        num_rows: shape.num_rows,
        num_cols: shape.num_cols,
        matrix_count: shape.matrices.len(),
        selector_count: shape.selectors.len(),
        witness_bits: shape.witness_schema.total_witness_bits(),
    })
}

fn fold_statement_digest(left: &StatementDigest, right: &StatementDigest) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.mock.fold.statement.v1");
    hasher.update(&left.0);
    hasher.update(&right.0);
    StatementDigest(hash48(hasher))
}

fn fold_commitment(left: &LatticeCommitment, right: &LatticeCommitment) -> LatticeCommitment {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.mock.fold.commitment.v1");
    hasher.update(&left.0);
    hasher.update(&right.0);
    LatticeCommitment(hash48(hasher))
}

fn hash48(hasher: Hasher) -> [u8; 48] {
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn digest32_with_label(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(label);
    hasher.update(bytes);
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

fn hex_nibble(value: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[value as usize] as char
}

#[cfg(test)]
mod tests {
    use superneo_ccs::{
        digest_statement, Assignment, CcsShape, SparseEntry, SparseMatrix, StatementEncoding,
        WitnessField, WitnessSchema,
    };
    use superneo_core::{Backend, FoldedInstance, SecurityParams};
    use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};

    use super::{LatticeBackend, LatticeBackendConfig, LatticeCommitment};
    use p3_goldilocks::Goldilocks;

    fn shape() -> CcsShape<Goldilocks> {
        CcsShape {
            num_rows: 2,
            num_cols: 4,
            matrices: vec![SparseMatrix {
                row_count: 2,
                col_count: 4,
                entries: vec![SparseEntry {
                    row: 0,
                    col: 0,
                    value: Goldilocks::new(1),
                }],
            }],
            selectors: vec![Goldilocks::new(1)],
            witness_schema: WitnessSchema {
                fields: vec![
                    WitnessField {
                        name: "a",
                        bit_width: 8,
                        signed: false,
                        count: 2,
                    },
                    WitnessField {
                        name: "b",
                        bit_width: 4,
                        signed: false,
                        count: 1,
                    },
                ],
            },
        }
    }

    #[test]
    fn leaf_and_fold_roundtrip() {
        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();

        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let left_assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let right_assignment = Assignment {
            witness: vec![Goldilocks::new(11), Goldilocks::new(21), Goldilocks::new(4)],
        };
        let left_packed = packer.pack(&shape(), &left_assignment).unwrap();
        let right_packed = packer.pack(&shape(), &right_assignment).unwrap();
        let left_statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(1)],
            statement_digest: digest_statement(b"left"),
        };
        let right_statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(2)],
            statement_digest: digest_statement(b"right"),
        };

        let left_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_packed,
            )
            .unwrap();
        let right_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_packed,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_proof,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_proof,
            )
            .unwrap();

        let left_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: left_statement.statement_digest,
            witness_commitment: left_proof.witness_commitment.clone(),
        };
        let right_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: right_statement.statement_digest,
            witness_commitment: right_proof.witness_commitment.clone(),
        };
        let (parent, proof) = backend
            .fold_pair(&pk, &left_instance, &right_instance)
            .unwrap();
        backend
            .verify_fold(&vk, &parent, &left_instance, &right_instance, &proof)
            .unwrap();
    }

    #[test]
    fn verify_fold_rejects_parent_metadata_mismatch() {
        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();

        let left = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"left"),
            witness_commitment: LatticeCommitment([1u8; 48]),
        };
        let right = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"right"),
            witness_commitment: LatticeCommitment([2u8; 48]),
        };
        let (mut parent, proof) = backend.fold_pair(&pk, &left, &right).unwrap();
        parent.relation_id = superneo_ccs::RelationId::from_label("wrong");
        assert!(backend
            .verify_fold(&vk, &parent, &left, &right, &proof)
            .is_err());
    }
}
