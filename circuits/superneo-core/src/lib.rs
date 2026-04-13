use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::Cursor;
use superneo_ccs::{CcsShape, RelationId, ShapeDigest, StatementDigest, StatementEncoding};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityParams {
    pub target_security_bits: u32,
    pub max_fold_arity: u32,
    pub transcript_domain: &'static [u8],
}

impl SecurityParams {
    pub fn experimental_default() -> Self {
        Self {
            target_security_bits: 128,
            max_fold_arity: 2,
            transcript_domain: b"hegemon.superneo.fold.v1",
        }
    }
}

pub trait Transcript {
    fn absorb_label(&mut self, label: &'static [u8]);
    fn absorb_bytes(&mut self, bytes: &[u8]);
    fn squeeze_bytes(&mut self, n: usize) -> Vec<u8>;
}

pub trait Backend<F> {
    type ProverKey;
    type VerifierKey;
    type PackedWitness;
    type Commitment: Clone;
    type LeafProof: Clone;
    type FoldProof: Clone;

    fn setup(
        &self,
        security: &SecurityParams,
        shape: &CcsShape<F>,
    ) -> Result<(Self::ProverKey, Self::VerifierKey)>;

    fn commit_witness(
        &self,
        pk: &Self::ProverKey,
        packed: &Self::PackedWitness,
    ) -> Result<Self::Commitment>;

    fn prove_leaf(
        &self,
        pk: &Self::ProverKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<F>,
        packed: &Self::PackedWitness,
        commitment: &Self::Commitment,
    ) -> Result<Self::LeafProof>;

    fn verify_leaf(
        &self,
        vk: &Self::VerifierKey,
        relation_id: &RelationId,
        statement: &StatementEncoding<F>,
        expected_packed: &Self::PackedWitness,
        proof: &Self::LeafProof,
    ) -> Result<()>;

    fn fold_pair(
        &self,
        pk: &Self::ProverKey,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
    ) -> Result<(FoldedInstance<Self::Commitment>, Self::FoldProof)>;

    fn verify_fold(
        &self,
        vk: &Self::VerifierKey,
        parent: &FoldedInstance<Self::Commitment>,
        left: &FoldedInstance<Self::Commitment>,
        right: &FoldedInstance<Self::Commitment>,
        proof: &Self::FoldProof,
    ) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveStatementEncoding<F> {
    pub public_inputs: Vec<F>,
    pub statement_commitment: [F; 6],
    #[serde(
        serialize_with = "serialize_fixed_bytes_48_option",
        deserialize_with = "deserialize_fixed_bytes_48_option"
    )]
    pub external_statement_digest: Option<[u8; 48]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CccsClaim<C, F> {
    pub relation_id: RelationId,
    pub shape_digest: ShapeDigest,
    pub statement: RecursiveStatementEncoding<F>,
    pub witness_commitment: C,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LcccsInstance<C, F> {
    pub relation_id: RelationId,
    pub shape_digest: ShapeDigest,
    pub statement: RecursiveStatementEncoding<F>,
    pub witness_commitment: C,
    pub relaxation_scalar: F,
    pub challenge_point: Vec<F>,
    pub evaluations: Vec<F>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveDeciderProfile {
    pub decider_id: [u8; 32],
    pub decider_vk_digest: [u8; 32],
    pub decider_transcript_digest: [u8; 32],
    pub init_acc_digest: [u8; 32],
    pub acc_encoding_digest: [u8; 32],
    pub dec_encoding_digest: [u8; 32],
    pub acc_bytes: u32,
    pub dec_bytes: u32,
    pub artifact_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalDeciderTranscript {
    #[serde(
        serialize_with = "serialize_fixed_bytes_48",
        deserialize_with = "deserialize_fixed_bytes_48"
    )]
    pub transcript_digest: [u8; 48],
    pub transcript_bytes: Vec<u8>,
}

pub trait RecursiveBackend<F> {
    type ProverKey;
    type VerifierKey;
    type PackedWitness;
    type Commitment: Clone;
    type CommitmentOpening: Clone;
    type CccsProof: Clone;
    type LinearizationProof: Clone;
    type FoldProof: Clone;
    type NormalizationProof: Clone;
    type DeciderProof: Clone;

    fn setup_recursive(
        &self,
        security: &SecurityParams,
        shape: &CcsShape<F>,
    ) -> Result<(Self::ProverKey, Self::VerifierKey)>;

    fn prove_cccs(
        &self,
        pk: &Self::ProverKey,
        relation_id: &RelationId,
        statement: &RecursiveStatementEncoding<F>,
        packed: &Self::PackedWitness,
        opening: &Self::CommitmentOpening,
    ) -> Result<(CccsClaim<Self::Commitment, F>, Self::CccsProof)>;

    fn verify_cccs(
        &self,
        vk: &Self::VerifierKey,
        claim: &CccsClaim<Self::Commitment, F>,
        proof: &Self::CccsProof,
    ) -> Result<()>;

    fn reduce_cccs(
        &self,
        pk: &Self::ProverKey,
        claim: &CccsClaim<Self::Commitment, F>,
        packed: &Self::PackedWitness,
        opening: &Self::CommitmentOpening,
    ) -> Result<(LcccsInstance<Self::Commitment, F>, Self::LinearizationProof)>;

    fn verify_linearized(
        &self,
        vk: &Self::VerifierKey,
        claim: &CccsClaim<Self::Commitment, F>,
        linearized: &LcccsInstance<Self::Commitment, F>,
        proof: &Self::LinearizationProof,
    ) -> Result<()>;

    fn fold_lcccs(
        &self,
        pk: &Self::ProverKey,
        previous_prefix: &RecursiveStatementEncoding<F>,
        left: &LcccsInstance<Self::Commitment, F>,
        step_statement: &RecursiveStatementEncoding<F>,
        right: &LcccsInstance<Self::Commitment, F>,
        linearization_proof: &Self::LinearizationProof,
        target_prefix: &RecursiveStatementEncoding<F>,
        left_packed: &Self::PackedWitness,
        left_opening: &Self::CommitmentOpening,
        right_packed: &Self::PackedWitness,
        right_opening: &Self::CommitmentOpening,
    ) -> Result<(
        LcccsInstance<Self::Commitment, F>,
        Self::PackedWitness,
        Self::CommitmentOpening,
        Self::FoldProof,
    )>;

    fn verify_fold_lcccs(
        &self,
        vk: &Self::VerifierKey,
        previous_prefix: &RecursiveStatementEncoding<F>,
        left: &LcccsInstance<Self::Commitment, F>,
        step_statement: &RecursiveStatementEncoding<F>,
        right: &LcccsInstance<Self::Commitment, F>,
        linearization_proof: &Self::LinearizationProof,
        parent: &LcccsInstance<Self::Commitment, F>,
        target_prefix: &RecursiveStatementEncoding<F>,
        proof: &Self::FoldProof,
    ) -> Result<()>;

    fn normalize_lcccs(
        &self,
        pk: &Self::ProverKey,
        statement: &RecursiveStatementEncoding<F>,
        high_norm: &LcccsInstance<Self::Commitment, F>,
        high_norm_packed: &Self::PackedWitness,
        high_norm_opening: &Self::CommitmentOpening,
    ) -> Result<(
        LcccsInstance<Self::Commitment, F>,
        Self::PackedWitness,
        Self::CommitmentOpening,
        Self::NormalizationProof,
    )>;

    fn verify_normalized(
        &self,
        vk: &Self::VerifierKey,
        statement: &RecursiveStatementEncoding<F>,
        high_norm: &LcccsInstance<Self::Commitment, F>,
        normalized: &LcccsInstance<Self::Commitment, F>,
        proof: &Self::NormalizationProof,
    ) -> Result<()>;

    fn prove_decider(
        &self,
        pk: &Self::ProverKey,
        decider_profile: &RecursiveDeciderProfile,
        statement: &RecursiveStatementEncoding<F>,
        terminal: &LcccsInstance<Self::Commitment, F>,
        transcript: &CanonicalDeciderTranscript,
    ) -> Result<Self::DeciderProof>;

    fn verify_decider(
        &self,
        vk: &Self::VerifierKey,
        decider_profile: &RecursiveDeciderProfile,
        statement: &RecursiveStatementEncoding<F>,
        terminal: &LcccsInstance<Self::Commitment, F>,
        proof: &Self::DeciderProof,
    ) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldedInstance<C> {
    pub relation_id: RelationId,
    pub shape_digest: ShapeDigest,
    pub statement_digest: StatementDigest,
    pub witness_commitment: C,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafArtifact<P> {
    pub version: u16,
    pub relation_id: RelationId,
    pub shape_digest: ShapeDigest,
    pub statement_digest: StatementDigest,
    pub proof: P,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldArtifact<P> {
    pub version: u16,
    pub parent_statement_digest: StatementDigest,
    pub left_statement_digest: StatementDigest,
    pub right_statement_digest: StatementDigest,
    pub proof: P,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldStep<C, P> {
    pub parent: FoldedInstance<C>,
    pub left: FoldedInstance<C>,
    pub right: FoldedInstance<C>,
    pub proof: P,
}

pub fn validate_fold_pair<C>(left: &FoldedInstance<C>, right: &FoldedInstance<C>) -> Result<()> {
    ensure!(
        left.relation_id == right.relation_id,
        "cannot fold different relations"
    );
    ensure!(
        left.shape_digest == right.shape_digest,
        "cannot fold different CCS shapes"
    );
    Ok(())
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

fn serialize_fixed_bytes_48_option<S>(
    bytes: &Option<[u8; 48]>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(bytes) => serializer.serialize_some(bytes.as_slice()),
        None => serializer.serialize_none(),
    }
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

fn deserialize_fixed_bytes_48_option<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<[u8; 48]>, D::Error>
where
    D: Deserializer<'de>,
{
    let maybe_bytes: Option<Vec<u8>> = Option::deserialize(deserializer)?;
    maybe_bytes
        .map(|bytes| {
            let len = bytes.len();
            bytes
                .try_into()
                .map_err(|_| serde::de::Error::invalid_length(len, &"48 bytes"))
        })
        .transpose()
}

pub fn serialize_lcccs_instance<C, F>(instance: &LcccsInstance<C, F>) -> Result<Vec<u8>>
where
    C: Serialize,
    F: Serialize,
{
    bincode::serialize(instance).context("failed to serialize LCCCS instance")
}

pub fn deserialize_lcccs_instance<C, F>(bytes: &[u8]) -> Result<LcccsInstance<C, F>>
where
    C: for<'de> Deserialize<'de>,
    F: for<'de> Deserialize<'de>,
{
    let mut cursor = Cursor::new(bytes);
    let instance =
        bincode::deserialize_from(&mut cursor).context("failed to deserialize LCCCS instance")?;
    ensure!(
        cursor.position() == bytes.len() as u64,
        "trailing bytes after LCCCS instance"
    );
    Ok(instance)
}

pub fn serialize_decider_profile(profile: &RecursiveDeciderProfile) -> Result<Vec<u8>> {
    bincode::serialize(profile).context("failed to serialize decider profile")
}

pub fn deserialize_decider_profile(bytes: &[u8]) -> Result<RecursiveDeciderProfile> {
    let mut cursor = Cursor::new(bytes);
    let profile =
        bincode::deserialize_from(&mut cursor).context("failed to deserialize decider profile")?;
    ensure!(
        cursor.position() == bytes.len() as u64,
        "trailing bytes after decider profile"
    );
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use superneo_ccs::{RelationId, ShapeDigest, StatementDigest};

    #[test]
    fn validate_fold_pair_rejects_shape_mismatch() {
        let left = FoldedInstance {
            relation_id: RelationId([1; 32]),
            shape_digest: ShapeDigest([2; 32]),
            statement_digest: StatementDigest([3; 48]),
            witness_commitment: [4u8; 48],
        };
        let right = FoldedInstance {
            relation_id: RelationId([1; 32]),
            shape_digest: ShapeDigest([9; 32]),
            statement_digest: StatementDigest([5; 48]),
            witness_commitment: [6u8; 48],
        };
        assert!(validate_fold_pair(&left, &right).is_err());
    }

    #[test]
    fn lcccs_roundtrips_without_trailing_bytes() {
        let instance = LcccsInstance {
            relation_id: RelationId([1; 32]),
            shape_digest: ShapeDigest([2; 32]),
            statement: RecursiveStatementEncoding {
                public_inputs: vec![7u64],
                statement_commitment: std::array::from_fn(|idx| idx as u64 + 1),
                external_statement_digest: Some([9; 48]),
            },
            witness_commitment: vec![3u8; 48],
            relaxation_scalar: 11u64,
            challenge_point: vec![13u64],
            evaluations: vec![17u64],
        };
        let bytes = serialize_lcccs_instance(&instance).unwrap();
        assert_eq!(
            deserialize_lcccs_instance::<Vec<u8>, u64>(&bytes).unwrap(),
            instance
        );

        let mut trailing = bytes;
        trailing.extend_from_slice(&[0u8; 4]);
        assert!(deserialize_lcccs_instance::<Vec<u8>, u64>(&trailing).is_err());
    }

    #[test]
    fn decider_profile_roundtrips_without_trailing_bytes() {
        let profile = RecursiveDeciderProfile {
            decider_id: [1; 32],
            decider_vk_digest: [2; 32],
            decider_transcript_digest: [3; 32],
            init_acc_digest: [4; 32],
            acc_encoding_digest: [5; 32],
            dec_encoding_digest: [6; 32],
            acc_bytes: 128,
            dec_bytes: 256,
            artifact_bytes: 512,
        };
        let bytes = serialize_decider_profile(&profile).unwrap();
        assert_eq!(deserialize_decider_profile(&bytes).unwrap(), profile);

        let mut trailing = bytes;
        trailing.push(0);
        assert!(deserialize_decider_profile(&trailing).is_err());
    }
}
