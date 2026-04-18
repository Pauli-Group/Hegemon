//! Prover artifact RPC endpoints.

use crate::substrate::prover_coordinator::ProverCoordinator;
use codec::Encode;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactAnnouncementResponse {
    pub artifact_hash: String,
    pub tx_statements_commitment: String,
    pub tx_count: u32,
    pub proof_mode: String,
    pub proof_kind: String,
    pub verifier_profile: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateArtifactResponse {
    pub artifact_hash: String,
    pub tx_statements_commitment: String,
    pub tx_count: u32,
    pub proof_kind: String,
    pub verifier_profile: String,
    pub candidate_txs: Vec<String>,
    pub payload: String,
}

#[rpc(server, client, namespace = "prover")]
pub trait ProverApi {
    #[method(name = "listArtifactAnnouncements")]
    async fn list_artifact_announcements(&self) -> RpcResult<Vec<ArtifactAnnouncementResponse>>;

    #[method(name = "getCandidateArtifact")]
    async fn get_candidate_artifact(
        &self,
        artifact_hash: String,
    ) -> RpcResult<Option<CandidateArtifactResponse>>;
}

pub struct ProverRpc {
    coordinator: Arc<ProverCoordinator>,
}

impl ProverRpc {
    pub fn new(coordinator: Arc<ProverCoordinator>) -> Self {
        Self { coordinator }
    }

    fn map_artifact_announcement(
        announcement: consensus::ArtifactAnnouncement,
    ) -> ArtifactAnnouncementResponse {
        let route = announcement.route();
        ArtifactAnnouncementResponse {
            artifact_hash: format!("0x{}", hex::encode(announcement.artifact_hash)),
            tx_statements_commitment: format!(
                "0x{}",
                hex::encode(announcement.tx_statements_commitment)
            ),
            tx_count: announcement.tx_count,
            proof_mode: match route.mode {
                consensus::ProvenBatchMode::InlineTx => "inline_tx".to_string(),
                consensus::ProvenBatchMode::ReceiptRoot => "receipt_root".to_string(),
                consensus::ProvenBatchMode::RecursiveBlock => "recursive_block".to_string(),
            },
            proof_kind: route.kind.label().to_string(),
            verifier_profile: format!("0x{}", hex::encode(announcement.verifier_profile)),
        }
    }
}

#[async_trait::async_trait]
impl ProverApiServer for ProverRpc {
    async fn list_artifact_announcements(&self) -> RpcResult<Vec<ArtifactAnnouncementResponse>> {
        Ok(self
            .coordinator
            .list_artifact_announcements()
            .into_iter()
            .map(Self::map_artifact_announcement)
            .collect())
    }

    async fn get_candidate_artifact(
        &self,
        artifact_hash: String,
    ) -> RpcResult<Option<CandidateArtifactResponse>> {
        let artifact_hash = parse_bytes(&artifact_hash)?;
        if artifact_hash.len() != 32 {
            return Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                format!(
                    "expected 32-byte artifact_hash, got {}",
                    artifact_hash.len()
                ),
                None::<()>,
            ));
        }
        let mut artifact_hash_bytes = [0u8; 32];
        artifact_hash_bytes.copy_from_slice(&artifact_hash);

        let artifact = self
            .coordinator
            .lookup_prepared_bundle_by_hash(artifact_hash_bytes);
        Ok(artifact.map(|bundle| CandidateArtifactResponse {
            artifact_hash: format!(
                "0x{}",
                hex::encode(crate::substrate::artifact_market::candidate_artifact_hash(
                    &bundle.payload,
                ))
            ),
            tx_statements_commitment: format!(
                "0x{}",
                hex::encode(bundle.payload.tx_statements_commitment)
            ),
            tx_count: bundle.payload.tx_count,
            proof_kind:
                crate::substrate::artifact_market::consensus_proof_artifact_kind_from_pallet(
                    bundle.payload.proof_kind,
                )
                .label()
                .to_string(),
            verifier_profile: format!("0x{}", hex::encode(bundle.payload.verifier_profile)),
            candidate_txs: bundle
                .candidate_txs
                .iter()
                .map(|tx| format!("0x{}", hex::encode(tx)))
                .collect(),
            payload: format!("0x{}", hex::encode(bundle.payload.encode())),
        }))
    }
}

fn parse_bytes(value: &str) -> Result<Vec<u8>, ErrorObjectOwned> {
    if let Some(value) = value.strip_prefix("0x") {
        return hex::decode(value).map_err(|err| {
            ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                format!("invalid hex: {err}"),
                None::<()>,
            )
        });
    }
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).map_err(|err| {
        ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("invalid base64: {err}"),
            None::<()>,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_artifact_announcement_supports_recursive_block() {
        let announcement = consensus::ArtifactAnnouncement {
            artifact_hash: [1u8; 32],
            tx_statements_commitment: [2u8; 48],
            tx_count: 7,
            proof_mode: consensus::ProvenBatchMode::RecursiveBlock,
            proof_kind: consensus::ProofArtifactKind::RecursiveBlockV1,
            verifier_profile: [3u8; 48],
        };

        let mapped = ProverRpc::map_artifact_announcement(announcement);
        assert_eq!(mapped.proof_mode, "recursive_block");
        assert_eq!(mapped.proof_kind, "recursive_block_v1");
        assert_eq!(mapped.tx_count, 7);
    }
}
