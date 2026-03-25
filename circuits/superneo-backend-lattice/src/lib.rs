use anyhow::{ensure, Result};
use blake3::Hasher;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use serde::Serialize;
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
    pub projection_rows: usize,
}

impl Default for LatticeBackendConfig {
    fn default() -> Self {
        Self {
            ring_profile: RingProfile::GoldilocksCyclotomic24,
            security_bits: 128,
            challenge_bits: 128,
            projection_rows: 12,
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
    pub projection_rows: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatticeCommitment {
    pub digest: [u8; 48],
    pub rows: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafDigestProof {
    pub witness_commitment: LatticeCommitment,
    pub packed_witness: PackedWitness<u64>,
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldDigestProof {
    pub challenge: u64,
    pub parent_statement_digest: StatementDigest,
    pub parent_commitment_digest: [u8; 48],
    pub proof_digest: [u8; 48],
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
    pub const DIGEST_BYTES: usize = 48;

    pub fn from_rows(rows: Vec<u64>) -> Self {
        Self {
            digest: digest_commitment_rows(&rows),
            rows,
        }
    }

    pub fn digest_only(digest: [u8; 48]) -> Self {
        Self {
            digest,
            rows: Vec::new(),
        }
    }

    pub fn byte_size(&self) -> usize {
        Self::DIGEST_BYTES + 4 + (self.rows.len() * 8)
    }

    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(self.digest.len() * 2);
        for byte in self.digest {
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
        out
    }
}

impl LeafDigestProof {
    pub fn byte_size(&self) -> usize {
        self.witness_commitment.byte_size()
            + 8
            + 8
            + 2
            + 4
            + (self.packed_witness.coeffs.len() * 8)
            + 48
    }
}

impl FoldDigestProof {
    pub const BYTES: usize = 8 + StatementDigest::BYTES + LatticeCommitment::DIGEST_BYTES + 48;

    pub fn byte_size(&self) -> usize {
        Self::BYTES
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
        ensure!(
            self.config.projection_rows > 0,
            "projection_rows must be strictly positive"
        );
        let key = BackendKey {
            shape_digest: digest_shape(shape),
            security_bits: security.target_security_bits,
            challenge_bits: self.config.challenge_bits,
            max_fold_arity: security.max_fold_arity,
            transcript_domain_digest: digest32_with_label(
                b"hegemon.superneo.transcript-domain.v1",
                security.transcript_domain,
            ),
            ring_profile: self.config.ring_profile,
            projection_rows: self.config.projection_rows,
        };
        Ok((key.clone(), key))
    }

    fn commit_witness(
        &self,
        pk: &Self::ProverKey,
        packed: &Self::PackedWitness,
    ) -> Result<Self::Commitment> {
        let bits = expand_packed_bits(packed)?;
        let rows = project_bits(pk, &bits);
        Ok(LatticeCommitment::from_rows(rows))
    }

    fn prove_leaf(
        &self,
        pk: &Self::ProverKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        packed: &Self::PackedWitness,
    ) -> Result<Self::LeafProof> {
        let witness_commitment = self.commit_witness(pk, packed)?;
        let proof_digest = leaf_proof_digest(
            pk,
            relation_id,
            &statement.statement_digest,
            packed,
            &witness_commitment,
        );
        Ok(LeafDigestProof {
            witness_commitment,
            packed_witness: packed.clone(),
            proof_digest,
        })
    }

    fn verify_leaf(
        &self,
        vk: &Self::VerifierKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        proof: &Self::LeafProof,
    ) -> Result<()> {
        let expected_commitment = self.commit_witness(vk, &proof.packed_witness)?;
        ensure!(
            proof.witness_commitment.digest == expected_commitment.digest,
            "leaf witness commitment digest mismatch"
        );
        if !proof.witness_commitment.rows.is_empty() {
            ensure!(
                proof.witness_commitment.rows == expected_commitment.rows,
                "leaf witness commitment rows mismatch"
            );
        }
        let expected_proof_digest = leaf_proof_digest(
            vk,
            relation_id,
            &statement.statement_digest,
            &proof.packed_witness,
            &expected_commitment,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "leaf proof digest mismatch"
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
        let challenge = derive_fold_challenge(pk, left, right);
        let parent_commitment = LatticeCommitment::from_rows(fold_commitment_rows(
            &left.witness_commitment,
            &right.witness_commitment,
            challenge,
        )?);
        let parent_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            challenge,
            &parent_commitment.digest,
        );
        let proof_digest = fold_proof_digest(
            pk,
            &left.relation_id,
            left,
            right,
            challenge,
            &parent_statement_digest,
            &parent_commitment.digest,
        );
        let proof = FoldDigestProof {
            challenge,
            parent_statement_digest,
            parent_commitment_digest: parent_commitment.digest,
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

        let expected_challenge = derive_fold_challenge(vk, left, right);
        ensure!(
            proof.challenge == expected_challenge,
            "fold challenge mismatch"
        );

        let expected_commitment = LatticeCommitment::from_rows(fold_commitment_rows(
            &left.witness_commitment,
            &right.witness_commitment,
            expected_challenge,
        )?);
        ensure!(
            parent.witness_commitment.digest == expected_commitment.digest,
            "folded witness commitment digest mismatch"
        );
        if !parent.witness_commitment.rows.is_empty() {
            ensure!(
                parent.witness_commitment.rows == expected_commitment.rows,
                "folded witness commitment rows mismatch"
            );
        }
        ensure!(
            proof.parent_commitment_digest == expected_commitment.digest,
            "fold proof parent commitment digest mismatch"
        );

        let expected_statement_digest = fold_statement_digest(
            &left.statement_digest,
            &right.statement_digest,
            expected_challenge,
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
            expected_challenge,
            &expected_statement_digest,
            &expected_commitment.digest,
        );
        ensure!(
            proof.proof_digest == expected_proof_digest,
            "fold proof digest mismatch"
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

fn expand_packed_bits(packed: &PackedWitness<u64>) -> Result<Vec<u8>> {
    ensure!(
        (1..=64).contains(&packed.coeff_capacity_bits),
        "packed witness coeff capacity must be in 1..=64"
    );
    let coeff_capacity = packed.coeff_capacity_bits as usize;
    let mut bits = Vec::with_capacity(packed.used_bits);
    for bit_index in 0..packed.used_bits {
        let coeff_index = bit_index / coeff_capacity;
        let bit_offset = (bit_index % coeff_capacity) as u16;
        let coeff = *packed
            .coeffs
            .get(coeff_index)
            .ok_or_else(|| anyhow::anyhow!("packed witness ended early while expanding bits"))?;
        bits.push(((coeff >> bit_offset) & 1) as u8);
    }
    Ok(bits)
}

fn project_bits(pk: &BackendKey, bits: &[u8]) -> Vec<u64> {
    let mut rows = vec![Goldilocks::new(0); pk.projection_rows];
    for (bit_index, bit) in bits.iter().enumerate() {
        if *bit == 0 {
            continue;
        }
        for (row_index, row) in rows.iter_mut().enumerate() {
            *row = *row + matrix_entry(pk, row_index, bit_index);
        }
    }
    rows.into_iter().map(|row| row.as_canonical_u64()).collect()
}

fn matrix_entry(pk: &BackendKey, row_index: usize, bit_index: usize) -> Goldilocks {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.matrix-commitment.v1");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.projection_rows as u64).to_le_bytes());
    hasher.update(&(row_index as u64).to_le_bytes());
    hasher.update(&(bit_index as u64).to_le_bytes());
    let mut out = [0u8; 8];
    hasher.finalize_xof().fill(&mut out);
    Goldilocks::new(u64::from_le_bytes(out))
}

fn digest_commitment_rows(rows: &[u64]) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.commitment-digest.v1");
    hasher.update(&(rows.len() as u64).to_le_bytes());
    for row in rows {
        hasher.update(&row.to_le_bytes());
    }
    hash48(hasher)
}

fn derive_fold_challenge(
    pk: &BackendKey,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-challenge.v1");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&left.relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    let mut out = [0u8; 8];
    hasher.finalize_xof().fill(&mut out);
    let challenge = Goldilocks::new(u64::from_le_bytes(out)).as_canonical_u64();
    if challenge == 0 {
        1
    } else {
        challenge
    }
}

fn fold_commitment_rows(
    left: &LatticeCommitment,
    right: &LatticeCommitment,
    challenge: u64,
) -> Result<Vec<u64>> {
    ensure!(
        !left.rows.is_empty() && !right.rows.is_empty(),
        "folded commitments require concrete row data"
    );
    ensure!(
        left.rows.len() == right.rows.len(),
        "folded commitments must have the same row length"
    );
    let scalar = Goldilocks::new(challenge);
    Ok(left
        .rows
        .iter()
        .zip(&right.rows)
        .map(|(left_row, right_row)| {
            (Goldilocks::new(*left_row) + scalar * Goldilocks::new(*right_row)).as_canonical_u64()
        })
        .collect())
}

fn leaf_proof_digest(
    pk: &BackendKey,
    relation_id: &RelationId,
    statement_digest: &StatementDigest,
    packed: &PackedWitness<u64>,
    commitment: &LatticeCommitment,
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.leaf-proof.v1");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.projection_rows as u64).to_le_bytes());
    hasher.update(&statement_digest.0);
    hasher.update(&commitment.digest);
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
    challenge: u64,
    parent_commitment_digest: &[u8; 48],
) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-statement.v1");
    hasher.update(&challenge.to_le_bytes());
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
    challenge: u64,
    parent_statement_digest: &StatementDigest,
    parent_commitment_digest: &[u8; 48],
) -> [u8; 48] {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-proof.v1");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.projection_rows as u64).to_le_bytes());
    hasher.update(&challenge.to_le_bytes());
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    hasher.update(&parent_statement_digest.0);
    hasher.update(parent_commitment_digest);
    hash48(hasher)
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
    use p3_goldilocks::Goldilocks;
    use superneo_ccs::{
        digest_statement, Assignment, CcsShape, SparseEntry, SparseMatrix, StatementEncoding,
        WitnessField, WitnessSchema,
    };
    use superneo_core::{Backend, FoldedInstance, SecurityParams};
    use superneo_ring::{GoldilocksPackingConfig, GoldilocksPayPerBitPacker, WitnessPacker};

    use super::{LatticeBackend, LatticeBackendConfig, LatticeCommitment};

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
    fn verify_leaf_rejects_tampered_packed_witness() {
        let backend = LatticeBackend::new(LatticeBackendConfig::default());
        let security = SecurityParams::experimental_default();
        let (pk, vk) = backend.setup(&security, &shape()).unwrap();
        let packer = GoldilocksPayPerBitPacker::new(GoldilocksPackingConfig::default());
        let assignment = Assignment {
            witness: vec![Goldilocks::new(10), Goldilocks::new(20), Goldilocks::new(3)],
        };
        let packed = packer.pack(&shape(), &assignment).unwrap();
        let statement = StatementEncoding {
            public_inputs: vec![Goldilocks::new(1)],
            statement_digest: digest_statement(b"left"),
        };
        let mut proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &packed,
            )
            .unwrap();
        proof.packed_witness.coeffs[0] ^= 1;
        assert!(backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &proof,
            )
            .is_err());
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
            witness_commitment: LatticeCommitment::from_rows(vec![1u64; pk.projection_rows]),
        };
        let right = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"right"),
            witness_commitment: LatticeCommitment::from_rows(vec![2u64; pk.projection_rows]),
        };
        let (mut parent, proof) = backend.fold_pair(&pk, &left, &right).unwrap();
        parent.relation_id = superneo_ccs::RelationId::from_label("wrong");
        assert!(backend
            .verify_fold(&vk, &parent, &left, &right, &proof)
            .is_err());
    }
}
