use codec::Encode;
use consensus::ArtifactAnnouncement;
use sp_core::hashing::blake2_256;

pub fn consensus_proven_batch_mode_from_pallet(
    mode: pallet_shielded_pool::types::BlockProofMode,
) -> consensus::ProvenBatchMode {
    match mode {
        pallet_shielded_pool::types::BlockProofMode::InlineTx => {
            consensus::ProvenBatchMode::InlineTx
        }
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot => {
            consensus::ProvenBatchMode::ReceiptRoot
        }
        pallet_shielded_pool::types::BlockProofMode::RecursiveBlock => {
            consensus::ProvenBatchMode::RecursiveBlock
        }
    }
}

pub fn consensus_proof_artifact_kind_from_pallet(
    kind: pallet_shielded_pool::types::ProofArtifactKind,
) -> consensus::ProofArtifactKind {
    match kind {
        pallet_shielded_pool::types::ProofArtifactKind::InlineTx => {
            consensus::ProofArtifactKind::InlineTx
        }
        pallet_shielded_pool::types::ProofArtifactKind::TxLeaf => {
            consensus::ProofArtifactKind::TxLeaf
        }
        pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot => {
            consensus::ProofArtifactKind::ReceiptRoot
        }
        pallet_shielded_pool::types::ProofArtifactKind::RecursiveBlockV1 => {
            consensus::ProofArtifactKind::RecursiveBlockV1
        }
        pallet_shielded_pool::types::ProofArtifactKind::Custom(bytes) => {
            consensus::ProofArtifactKind::Custom(bytes)
        }
    }
}

pub fn legacy_pallet_artifact_identity(
    mode: pallet_shielded_pool::types::BlockProofMode,
) -> (
    pallet_shielded_pool::types::ProofArtifactKind,
    pallet_shielded_pool::types::VerifierProfileDigest,
) {
    let kind = pallet_shielded_pool::types::proof_artifact_kind_from_mode(mode);
    let verifier_profile = match mode {
        pallet_shielded_pool::types::BlockProofMode::ReceiptRoot => {
            consensus::experimental_native_receipt_root_verifier_profile()
        }
        pallet_shielded_pool::types::BlockProofMode::RecursiveBlock => {
            consensus::recursive_block_artifact_verifier_profile()
        }
        pallet_shielded_pool::types::BlockProofMode::InlineTx => {
            consensus::legacy_block_artifact_verifier_profile(
                consensus_proof_artifact_kind_from_pallet(kind),
            )
        }
    };
    (kind, verifier_profile)
}

pub fn candidate_artifact_hash(
    artifact: &pallet_shielded_pool::types::CandidateArtifact,
) -> [u8; 32] {
    blake2_256(&artifact.encode())
}

pub fn artifact_announcement(
    artifact: &pallet_shielded_pool::types::CandidateArtifact,
) -> ArtifactAnnouncement {
    let proof_mode = consensus_proven_batch_mode_from_pallet(artifact.proof_mode);
    ArtifactAnnouncement {
        artifact_hash: candidate_artifact_hash(artifact),
        tx_statements_commitment: artifact.tx_statements_commitment,
        tx_count: artifact.tx_count,
        proof_mode,
        proof_kind: consensus_proof_artifact_kind_from_pallet(artifact.proof_kind),
        verifier_profile: artifact.verifier_profile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> pallet_shielded_pool::types::CandidateArtifact {
        let (proof_kind, verifier_profile) = legacy_pallet_artifact_identity(
            pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
        );
        pallet_shielded_pool::types::CandidateArtifact {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count: 2,
            tx_statements_commitment: [7u8; 48],
            da_root: [8u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![1, 2, 3]),
            proof_mode: pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
            proof_kind,
            verifier_profile,
            receipt_root: None,
            recursive_block: None,
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
        assert_eq!(
            announcement.proof_kind,
            consensus::ProofArtifactKind::ReceiptRoot
        );
        assert_eq!(
            announcement.verifier_profile,
            consensus::experimental_native_receipt_root_verifier_profile()
        );
    }

    #[test]
    fn receipt_root_uses_experimental_verifier_profile() {
        let (kind, verifier_profile) = legacy_pallet_artifact_identity(
            pallet_shielded_pool::types::BlockProofMode::ReceiptRoot,
        );
        assert_eq!(
            kind,
            pallet_shielded_pool::types::ProofArtifactKind::ReceiptRoot
        );
        assert_eq!(
            verifier_profile,
            consensus::experimental_native_receipt_root_verifier_profile()
        );
    }

    #[test]
    fn recursive_block_mode_maps_to_recursive_block_v1() {
        assert_eq!(
            consensus_proven_batch_mode_from_pallet(
                pallet_shielded_pool::types::BlockProofMode::RecursiveBlock
            ),
            consensus::ProvenBatchMode::RecursiveBlock
        );
        assert_eq!(
            consensus_proof_artifact_kind_from_pallet(
                pallet_shielded_pool::types::ProofArtifactKind::RecursiveBlockV1
            ),
            consensus::ProofArtifactKind::RecursiveBlockV1
        );
        let (kind, verifier_profile) = legacy_pallet_artifact_identity(
            pallet_shielded_pool::types::BlockProofMode::RecursiveBlock,
        );
        assert_eq!(
            kind,
            pallet_shielded_pool::types::ProofArtifactKind::RecursiveBlockV1
        );
        assert_eq!(
            verifier_profile,
            consensus::recursive_block_artifact_verifier_profile()
        );
    }
}
