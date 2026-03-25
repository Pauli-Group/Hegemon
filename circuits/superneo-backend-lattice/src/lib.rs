use anyhow::{anyhow, ensure, Result};
use blake3::Hasher;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use superneo_ccs::{
    digest_shape, CcsShape, RelationId, ShapeDigest, StatementDigest, StatementEncoding,
};
use superneo_core::{validate_fold_pair, Backend, FoldedInstance, SecurityParams};
use superneo_ring::PackedWitness;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeBackendConfig {
    pub ring_profile: RingProfile,
    pub security_bits: u32,
    pub challenge_bits: u32,
    pub commitment_rows: usize,
    pub ring_degree: usize,
    pub digit_bits: u16,
}

impl Default for LatticeBackendConfig {
    fn default() -> Self {
        Self {
            ring_profile: RingProfile::GoldilocksCyclotomic24,
            security_bits: 128,
            challenge_bits: 16,
            commitment_rows: 8,
            ring_degree: 8,
            digit_bits: 8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendKey {
    pub shape_digest: ShapeDigest,
    pub security_bits: u32,
    pub challenge_bits: u32,
    pub max_fold_arity: u32,
    pub transcript_domain_digest: [u8; 32],
    pub ring_profile: RingProfile,
    pub commitment_rows: usize,
    pub ring_degree: usize,
    pub digit_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingElem {
    pub coeffs: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatticeCommitment {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub digest: [u8; 48],
    pub rows: Vec<RingElem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafDigestProof {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub witness_commitment_digest: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldDigestProof {
    pub challenge: u64,
    pub parent_statement_digest: StatementDigest,
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub parent_commitment_digest: [u8; 48],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub proof_digest: [u8; 48],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendShape {
    pub shape_digest: ShapeDigest,
    pub num_rows: usize,
    pub num_cols: usize,
    pub matrix_count: usize,
    pub selector_count: usize,
    pub witness_bits: usize,
}

impl RingElem {
    fn zero(ring_degree: usize) -> Self {
        Self {
            coeffs: vec![0; ring_degree],
        }
    }

    pub fn from_coeffs(coeffs: Vec<u64>) -> Self {
        Self { coeffs }
    }

    fn add_assign(&mut self, other: &Self) {
        for (lhs, rhs) in self.coeffs.iter_mut().zip(&other.coeffs) {
            *lhs = goldilocks_add(*lhs, *rhs);
        }
    }

    fn scale(&self, scalar: u64) -> Self {
        Self {
            coeffs: self
                .coeffs
                .iter()
                .map(|coeff| goldilocks_mul(*coeff, scalar))
                .collect(),
        }
    }

    fn mul_negacyclic(&self, other: &Self) -> Self {
        let degree = self.coeffs.len();
        let mut out = vec![Goldilocks::new(0); degree];
        for (i, left) in self.coeffs.iter().enumerate() {
            for (j, right) in other.coeffs.iter().enumerate() {
                let target = i + j;
                let product = Goldilocks::new(*left) * Goldilocks::new(*right);
                if target < degree {
                    out[target] = out[target] + product;
                } else {
                    out[target - degree] = out[target - degree] - product;
                }
            }
        }
        Self {
            coeffs: out
                .into_iter()
                .map(|value| value.as_canonical_u64())
                .collect(),
        }
    }

    fn byte_size(&self) -> usize {
        4 + (self.coeffs.len() * 8)
    }
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

impl LatticeCommitment {
    pub const DIGEST_BYTES: usize = 48;

    pub fn from_rows(rows: Vec<RingElem>) -> Self {
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
        Self::DIGEST_BYTES + 4 + self.rows.iter().map(RingElem::byte_size).sum::<usize>()
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
        48 + 48
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
            self.config.commitment_rows > 0,
            "commitment_rows must be strictly positive"
        );
        ensure!(
            self.config.ring_degree > 0,
            "ring_degree must be strictly positive"
        );
        ensure!(
            (1..=16).contains(&self.config.digit_bits),
            "digit_bits must be in 1..=16"
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
            commitment_rows: self.config.commitment_rows,
            ring_degree: self.config.ring_degree,
            digit_bits: self.config.digit_bits,
        };
        Ok((key.clone(), key))
    }

    fn commit_witness(
        &self,
        pk: &Self::ProverKey,
        packed: &Self::PackedWitness,
    ) -> Result<Self::Commitment> {
        let ring_message = embed_packed_witness(pk, packed)?;
        let rows = commit_ring_message(pk, &ring_message);
        Ok(LatticeCommitment::from_rows(rows))
    }

    fn prove_leaf(
        &self,
        pk: &Self::ProverKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        packed: &Self::PackedWitness,
        commitment: &Self::Commitment,
    ) -> Result<Self::LeafProof> {
        let proof_digest = leaf_proof_digest(
            pk,
            relation_id,
            &statement.statement_digest,
            packed,
            &commitment.digest,
        );
        Ok(LeafDigestProof {
            witness_commitment_digest: commitment.digest,
            proof_digest,
        })
    }

    fn verify_leaf(
        &self,
        vk: &Self::VerifierKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<Goldilocks>,
        expected_packed: &Self::PackedWitness,
        proof: &Self::LeafProof,
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
            .ok_or_else(|| anyhow!("packed witness ended early while expanding bits"))?;
        bits.push(((coeff >> bit_offset) & 1) as u8);
    }
    Ok(bits)
}

fn commit_ring_message(pk: &BackendKey, message: &[RingElem]) -> Vec<RingElem> {
    let mut rows = Vec::with_capacity(pk.commitment_rows);
    for row_index in 0..pk.commitment_rows {
        let mut acc = RingElem::zero(pk.ring_degree);
        for (col_index, message_elem) in message.iter().enumerate() {
            let matrix = matrix_entry(pk, row_index, col_index);
            acc.add_assign(&matrix.mul_negacyclic(message_elem));
        }
        rows.push(acc);
    }
    rows
}

fn matrix_entry(pk: &BackendKey, row_index: usize, col_index: usize) -> RingElem {
    let mut coeffs = Vec::with_capacity(pk.ring_degree);
    for coeff_index in 0..pk.ring_degree {
        let mut hasher = Hasher::new();
        hasher.update(b"hegemon.superneo.ajtai-matrix.v1");
        hasher.update(pk.ring_profile.label());
        hasher.update(&pk.shape_digest.0);
        hasher.update(&pk.security_bits.to_le_bytes());
        hasher.update(&pk.challenge_bits.to_le_bytes());
        hasher.update(&pk.max_fold_arity.to_le_bytes());
        hasher.update(&pk.transcript_domain_digest);
        hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
        hasher.update(&(pk.ring_degree as u64).to_le_bytes());
        hasher.update(&pk.digit_bits.to_le_bytes());
        hasher.update(&(row_index as u64).to_le_bytes());
        hasher.update(&(col_index as u64).to_le_bytes());
        hasher.update(&(coeff_index as u64).to_le_bytes());
        let mut out = [0u8; 8];
        hasher.finalize_xof().fill(&mut out);
        coeffs.push(Goldilocks::new(u64::from_le_bytes(out)).as_canonical_u64());
    }
    RingElem::from_coeffs(coeffs)
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

fn derive_fold_challenge(
    pk: &BackendKey,
    left: &FoldedInstance<LatticeCommitment>,
    right: &FoldedInstance<LatticeCommitment>,
) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-challenge.v2");
    hasher.update(pk.ring_profile.label());
    hasher.update(&pk.shape_digest.0);
    hasher.update(&left.relation_id.0);
    hasher.update(&pk.security_bits.to_le_bytes());
    hasher.update(&pk.challenge_bits.to_le_bytes());
    hasher.update(&pk.max_fold_arity.to_le_bytes());
    hasher.update(&pk.transcript_domain_digest);
    hasher.update(&(pk.commitment_rows as u64).to_le_bytes());
    hasher.update(&(pk.ring_degree as u64).to_le_bytes());
    hasher.update(&pk.digit_bits.to_le_bytes());
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    let mut out = [0u8; 8];
    hasher.finalize_xof().fill(&mut out);
    let raw = u64::from_le_bytes(out);
    let mask_bits = pk.challenge_bits.min(16);
    let modulus = 1u64 << mask_bits;
    let reduced = if modulus <= 1 {
        1
    } else {
        (raw % (modulus - 1)) + 1
    };
    Goldilocks::new(reduced).as_canonical_u64()
}

fn fold_commitment_rows(
    left: &LatticeCommitment,
    right: &LatticeCommitment,
    challenge: u64,
) -> Result<Vec<RingElem>> {
    ensure!(
        !left.rows.is_empty() && !right.rows.is_empty(),
        "folded commitments require concrete row data"
    );
    ensure!(
        left.rows.len() == right.rows.len(),
        "folded commitments must have the same row length"
    );
    Ok(left
        .rows
        .iter()
        .zip(&right.rows)
        .map(|(left_row, right_row)| {
            let mut acc = left_row.clone();
            acc.add_assign(&right_row.scale(challenge));
            acc
        })
        .collect())
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
    challenge: u64,
    parent_commitment_digest: &[u8; 48],
) -> StatementDigest {
    let mut hasher = Hasher::new();
    hasher.update(b"hegemon.superneo.fold-statement.v2");
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
    hasher.update(b"hegemon.superneo.fold-proof.v2");
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
    hasher.update(&challenge.to_le_bytes());
    hasher.update(&left.statement_digest.0);
    hasher.update(&right.statement_digest.0);
    hasher.update(&left.witness_commitment.digest);
    hasher.update(&right.witness_commitment.digest);
    hasher.update(&parent_statement_digest.0);
    hasher.update(parent_commitment_digest);
    hash48(hasher)
}

fn goldilocks_add(left: u64, right: u64) -> u64 {
    (Goldilocks::new(left) + Goldilocks::new(right)).as_canonical_u64()
}

fn goldilocks_mul(left: u64, right: u64) -> u64 {
    (Goldilocks::new(left) * Goldilocks::new(right)).as_canonical_u64()
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

    use super::{LatticeBackend, LatticeBackendConfig, LatticeCommitment, RingElem};

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
        let left_commitment = backend.commit_witness(&pk, &left_packed).unwrap();
        let right_commitment = backend.commit_witness(&pk, &right_packed).unwrap();

        let left_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_packed,
                &left_commitment,
            )
            .unwrap();
        let right_proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_packed,
                &right_commitment,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &left_statement,
                &left_packed,
                &left_proof,
            )
            .unwrap();
        backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &right_statement,
                &right_packed,
                &right_proof,
            )
            .unwrap();

        let left_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: left_statement.statement_digest,
            witness_commitment: left_commitment,
        };
        let right_instance = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: right_statement.statement_digest,
            witness_commitment: right_commitment,
        };
        let (parent, proof) = backend
            .fold_pair(&pk, &left_instance, &right_instance)
            .unwrap();
        backend
            .verify_fold(&vk, &parent, &left_instance, &right_instance, &proof)
            .unwrap();
    }

    #[test]
    fn verify_leaf_rejects_tampered_expected_witness() {
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
        let commitment = backend.commit_witness(&pk, &packed).unwrap();
        let proof = backend
            .prove_leaf(
                &pk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &packed,
                &commitment,
            )
            .unwrap();
        let mut tampered = packed.clone();
        tampered.coeffs[0] ^= 1;
        assert!(backend
            .verify_leaf(
                &vk,
                &superneo_ccs::RelationId::from_label("test"),
                &statement,
                &tampered,
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
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![1u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let right = FoldedInstance {
            relation_id: superneo_ccs::RelationId::from_label("test"),
            shape_digest: pk.shape_digest,
            statement_digest: digest_statement(b"right"),
            witness_commitment: LatticeCommitment::from_rows(vec![
                RingElem::from_coeffs(
                    vec![2u64; pk.ring_degree]
                );
                pk.commitment_rows
            ]),
        };
        let (mut parent, proof) = backend.fold_pair(&pk, &left, &right).unwrap();
        parent.relation_id = superneo_ccs::RelationId::from_label("wrong");
        assert!(backend
            .verify_fold(&vk, &parent, &left, &right, &proof)
            .is_err());
    }
}
