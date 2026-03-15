use codec::Encode;
use consensus::ArtifactAnnouncement;
use sp_core::hashing::blake2_256;

pub fn candidate_artifact_hash(
    artifact: &pallet_shielded_pool::types::CandidateArtifact,
) -> [u8; 32] {
    blake2_256(&artifact.encode())
}

pub fn artifact_announcement(
    artifact: &pallet_shielded_pool::types::CandidateArtifact,
) -> ArtifactAnnouncement {
    ArtifactAnnouncement {
        artifact_hash: candidate_artifact_hash(artifact),
        tx_statements_commitment: artifact.tx_statements_commitment,
        tx_count: artifact.tx_count,
        proof_mode: match artifact.proof_mode {
            pallet_shielded_pool::types::BlockProofMode::InlineTx => {
                consensus::ProvenBatchMode::InlineTx
            }
            pallet_shielded_pool::types::BlockProofMode::FlatBatches => {
                consensus::ProvenBatchMode::FlatBatches
            }
            pallet_shielded_pool::types::BlockProofMode::MergeRoot => {
                consensus::ProvenBatchMode::MergeRoot
            }
        },
        claimed_payout_amount: artifact
            .artifact_claim
            .as_ref()
            .map(|claim| claim.prover_amount)
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> pallet_shielded_pool::types::CandidateArtifact {
        pallet_shielded_pool::types::CandidateArtifact {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 2,
            tx_statements_commitment: [7u8; 48],
            da_root: [8u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![1, 2, 3]),
            proof_mode: pallet_shielded_pool::types::BlockProofMode::FlatBatches,
            flat_batches: vec![],
            merge_root: None,
            artifact_claim: None,
        }
    }

    #[test]
    fn artifact_hash_is_deterministic() {
        let artifact = artifact();
        assert_eq!(
            candidate_artifact_hash(&artifact),
            candidate_artifact_hash(&artifact)
        );
    }

    #[test]
    fn announcement_reflects_payload_shape() {
        let artifact = artifact();
        let announcement = artifact_announcement(&artifact);
        assert_eq!(announcement.tx_count, 2);
        assert_eq!(announcement.tx_statements_commitment, [7u8; 48]);
    }
}
