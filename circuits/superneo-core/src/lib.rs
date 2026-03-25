use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
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
}
