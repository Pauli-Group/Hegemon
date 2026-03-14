//! Prover market RPC endpoints.

use crate::substrate::prover_coordinator::{
    LeafBatchWorkData, MergeNodeWorkData, ProverCoordinator, TxProofManifestWorkData, WorkStatus,
};
use base64::Engine;
use codec::{Decode, Encode};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkPackageResponse {
    pub package_id: String,
    pub parent_hash: String,
    pub block_number: u64,
    pub candidate_set_id: String,
    pub chunk_start_tx_index: u32,
    pub chunk_tx_count: u16,
    pub expected_chunks: u16,
    pub stage_type: String,
    pub level: u16,
    pub arity: u16,
    pub shape_id: String,
    pub dependencies: Vec<String>,
    pub tx_count: u32,
    pub candidate_txs: Vec<String>,
    pub tx_proof_manifest_payload: Option<TxProofManifestPayloadResponse>,
    pub leaf_batch_payload: Option<LeafBatchPayloadResponse>,
    pub merge_node_payload: Option<MergeNodePayloadResponse>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxProofManifestPayloadResponse {
    pub statement_hashes: Vec<String>,
    pub tx_proofs_bincode: String,
    pub tx_statements_commitment: String,
    pub da_root: String,
    pub da_chunk_count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeafBatchPayloadResponse {
    pub statement_hashes: Vec<String>,
    pub tx_proofs_bincode: String,
    pub tx_statements_commitment: String,
    pub tree_levels: u16,
    pub root_level: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergeNodePayloadResponse {
    pub child_proof_payloads_bincode: String,
    pub tx_statements_commitment: String,
    pub tree_levels: u16,
    pub root_level: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitWorkResultRequest {
    pub source: String,
    pub package_id: String,
    /// SCALE-encoded `CandidateArtifact` bytes (0x-prefixed hex or base64).
    pub payload: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitWorkResultResponse {
    pub accepted: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkStatusResponse {
    pub package_id: String,
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketParamsResponse {
    pub package_ttl_ms: u64,
    pub max_submissions_per_package: u32,
    pub max_submissions_per_source: u32,
    pub max_payload_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactAnnouncementResponse {
    pub artifact_hash: String,
    pub tx_statements_commitment: String,
    pub tx_count: u32,
    pub proof_mode: String,
    pub claimed_payout_amount: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateArtifactResponse {
    pub artifact_hash: String,
    pub tx_statements_commitment: String,
    pub tx_count: u32,
    pub candidate_txs: Vec<String>,
    pub payload: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StageQueueStatusResponse {
    pub stage_type: String,
    pub level: u16,
    pub queued_jobs: usize,
    pub inflight_jobs: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StagePlanStatusResponse {
    pub generation: u64,
    pub current_parent: Option<String>,
    pub queued_jobs: usize,
    pub inflight_jobs: usize,
    pub prepared_bundles: usize,
    pub latest_work_package: Option<String>,
    pub stage_queue: Vec<StageQueueStatusResponse>,
}

#[rpc(server, client, namespace = "prover")]
pub trait ProverApi {
    #[method(name = "getWorkPackage")]
    async fn get_work_package(&self) -> RpcResult<Option<WorkPackageResponse>>;

    #[method(name = "getStageWorkPackage")]
    async fn get_stage_work_package(&self) -> RpcResult<Option<WorkPackageResponse>>;

    #[method(name = "submitWorkResult")]
    async fn submit_work_result(
        &self,
        request: SubmitWorkResultRequest,
    ) -> RpcResult<SubmitWorkResultResponse>;

    #[method(name = "submitStageWorkResult")]
    async fn submit_stage_work_result(
        &self,
        request: SubmitWorkResultRequest,
    ) -> RpcResult<SubmitWorkResultResponse>;

    #[method(name = "getWorkStatus")]
    async fn get_work_status(&self, package_id: String) -> RpcResult<Option<WorkStatusResponse>>;

    #[method(name = "getMarketParams")]
    async fn get_market_params(&self) -> RpcResult<MarketParamsResponse>;

    #[method(name = "getStagePlanStatus")]
    async fn get_stage_plan_status(&self) -> RpcResult<StagePlanStatusResponse>;

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

    fn map_leaf_batch_payload(payload: LeafBatchWorkData) -> RpcResult<LeafBatchPayloadResponse> {
        let tx_proofs_bincode = bincode::serialize(&payload.tx_proofs).map_err(|err| {
            ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                format!("failed to serialize leaf tx proofs: {err}"),
                None::<()>,
            )
        })?;
        Ok(LeafBatchPayloadResponse {
            statement_hashes: payload
                .statement_hashes
                .into_iter()
                .map(|value| format!("0x{}", hex::encode(value)))
                .collect(),
            tx_proofs_bincode: base64::engine::general_purpose::STANDARD.encode(tx_proofs_bincode),
            tx_statements_commitment: format!(
                "0x{}",
                hex::encode(payload.tx_statements_commitment)
            ),
            tree_levels: payload.tree_levels,
            root_level: payload.root_level,
        })
    }

    fn map_tx_proof_manifest_payload(
        payload: TxProofManifestWorkData,
    ) -> RpcResult<TxProofManifestPayloadResponse> {
        let tx_proofs_bincode = bincode::serialize(&payload.tx_proofs).map_err(|err| {
            ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                format!("failed to serialize tx-proof-manifest tx proofs: {err}"),
                None::<()>,
            )
        })?;
        Ok(TxProofManifestPayloadResponse {
            statement_hashes: payload
                .statement_hashes
                .into_iter()
                .map(|value| format!("0x{}", hex::encode(value)))
                .collect(),
            tx_proofs_bincode: base64::engine::general_purpose::STANDARD.encode(tx_proofs_bincode),
            tx_statements_commitment: format!(
                "0x{}",
                hex::encode(payload.tx_statements_commitment)
            ),
            da_root: format!("0x{}", hex::encode(payload.da_root)),
            da_chunk_count: payload.da_chunk_count,
        })
    }

    fn map_merge_node_payload(payload: MergeNodeWorkData) -> RpcResult<MergeNodePayloadResponse> {
        let child_proof_payloads_bincode = bincode::serialize(&payload.child_proof_payloads)
            .map_err(|err| {
                ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    format!("failed to serialize child proof payloads: {err}"),
                    None::<()>,
                )
            })?;
        Ok(MergeNodePayloadResponse {
            child_proof_payloads_bincode: base64::engine::general_purpose::STANDARD
                .encode(child_proof_payloads_bincode),
            tx_statements_commitment: format!(
                "0x{}",
                hex::encode(payload.tx_statements_commitment)
            ),
            tree_levels: payload.tree_levels,
            root_level: payload.root_level,
        })
    }

    fn map_work_package(
        package: crate::substrate::prover_coordinator::WorkPackage,
    ) -> RpcResult<WorkPackageResponse> {
        Ok(WorkPackageResponse {
            package_id: package.package_id,
            parent_hash: format!("0x{}", hex::encode(package.parent_hash)),
            block_number: package.block_number,
            candidate_set_id: package.candidate_set_id,
            chunk_start_tx_index: package.chunk_start_tx_index,
            chunk_tx_count: package.chunk_tx_count,
            expected_chunks: package.expected_chunks,
            stage_type: package.stage_type.as_str().to_string(),
            level: package.level,
            arity: package.arity,
            shape_id: format!("0x{}", hex::encode(package.shape_id)),
            dependencies: package.dependencies,
            tx_count: package.tx_count,
            candidate_txs: package
                .candidate_txs
                .into_iter()
                .map(|tx| format!("0x{}", hex::encode(tx)))
                .collect(),
            tx_proof_manifest_payload: package
                .tx_proof_manifest_payload
                .map(Self::map_tx_proof_manifest_payload)
                .transpose()?,
            leaf_batch_payload: package
                .leaf_batch_payload
                .map(Self::map_leaf_batch_payload)
                .transpose()?,
            merge_node_payload: package
                .merge_node_payload
                .map(Self::map_merge_node_payload)
                .transpose()?,
            created_at_ms: package.created_at_ms,
            expires_at_ms: package.expires_at_ms,
        })
    }

    fn submit_work_result_impl(
        &self,
        request: SubmitWorkResultRequest,
    ) -> RpcResult<SubmitWorkResultResponse> {
        let payload_bytes = parse_bytes(&request.payload)?;
        let payload =
            pallet_shielded_pool::types::CandidateArtifact::decode(&mut payload_bytes.as_slice())
                .map_err(|err| {
                ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    format!("failed to decode payload: {err}"),
                    None::<()>,
                )
            })?;

        match self.coordinator.submit_external_work_result(
            &request.source,
            &request.package_id,
            payload,
        ) {
            Ok(()) => Ok(SubmitWorkResultResponse {
                accepted: true,
                error: None,
            }),
            Err(err) => Ok(SubmitWorkResultResponse {
                accepted: false,
                error: Some(err),
            }),
        }
    }

    fn map_artifact_announcement(
        announcement: consensus::ArtifactAnnouncement,
    ) -> ArtifactAnnouncementResponse {
        ArtifactAnnouncementResponse {
            artifact_hash: format!("0x{}", hex::encode(announcement.artifact_hash)),
            tx_statements_commitment: format!(
                "0x{}",
                hex::encode(announcement.tx_statements_commitment)
            ),
            tx_count: announcement.tx_count,
            proof_mode: match announcement.proof_mode {
                consensus::ProvenBatchMode::FlatBatches => "flat_batches".to_string(),
                consensus::ProvenBatchMode::MergeRoot => "merge_root".to_string(),
            },
            claimed_payout_amount: announcement.claimed_payout_amount,
        }
    }
}

#[async_trait::async_trait]
impl ProverApiServer for ProverRpc {
    async fn get_work_package(&self) -> RpcResult<Option<WorkPackageResponse>> {
        match self.coordinator.get_work_package() {
            Some(package) => Ok(Some(Self::map_work_package(package)?)),
            None => Ok(None),
        }
    }

    async fn get_stage_work_package(&self) -> RpcResult<Option<WorkPackageResponse>> {
        match self.coordinator.get_stage_work_package() {
            Some(package) => Ok(Some(Self::map_work_package(package)?)),
            None => Ok(None),
        }
    }

    async fn submit_work_result(
        &self,
        request: SubmitWorkResultRequest,
    ) -> RpcResult<SubmitWorkResultResponse> {
        self.submit_work_result_impl(request)
    }

    async fn submit_stage_work_result(
        &self,
        request: SubmitWorkResultRequest,
    ) -> RpcResult<SubmitWorkResultResponse> {
        let payload_bytes = parse_bytes(&request.payload)?;
        match self.coordinator.submit_external_stage_result(
            &request.source,
            &request.package_id,
            payload_bytes,
        ) {
            Ok(()) => Ok(SubmitWorkResultResponse {
                accepted: true,
                error: None,
            }),
            Err(err) => Ok(SubmitWorkResultResponse {
                accepted: false,
                error: Some(err),
            }),
        }
    }

    async fn get_work_status(&self, package_id: String) -> RpcResult<Option<WorkStatusResponse>> {
        Ok(self
            .coordinator
            .get_work_status(&package_id)
            .map(|status| match status {
                WorkStatus::Pending => WorkStatusResponse {
                    package_id,
                    status: "pending".to_string(),
                    reason: None,
                },
                WorkStatus::Accepted => WorkStatusResponse {
                    package_id,
                    status: "accepted".to_string(),
                    reason: None,
                },
                WorkStatus::Rejected(reason) => WorkStatusResponse {
                    package_id,
                    status: "rejected".to_string(),
                    reason: Some(reason),
                },
                WorkStatus::Expired => WorkStatusResponse {
                    package_id,
                    status: "expired".to_string(),
                    reason: None,
                },
            }))
    }

    async fn get_market_params(&self) -> RpcResult<MarketParamsResponse> {
        let params = self.coordinator.market_params();
        Ok(MarketParamsResponse {
            package_ttl_ms: params.package_ttl_ms,
            max_submissions_per_package: params.max_submissions_per_package,
            max_submissions_per_source: params.max_submissions_per_source,
            max_payload_bytes: params.max_payload_bytes,
        })
    }

    async fn get_stage_plan_status(&self) -> RpcResult<StagePlanStatusResponse> {
        let status = self.coordinator.stage_plan_status();
        Ok(StagePlanStatusResponse {
            generation: status.generation,
            current_parent: status
                .current_parent
                .map(|hash| format!("0x{}", hex::encode(hash))),
            queued_jobs: status.queued_jobs,
            inflight_jobs: status.inflight_jobs,
            prepared_bundles: status.prepared_bundles,
            latest_work_package: status.latest_work_package,
                stage_queue: status
                    .stage_queue
                    .into_iter()
                    .map(|stage| StageQueueStatusResponse {
                    stage_type: stage.stage_type.to_string(),
                        level: stage.level,
                        queued_jobs: stage.queued_jobs,
                        inflight_jobs: stage.inflight_jobs,
                })
                .collect(),
        })
    }

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
    use crate::substrate::prover_coordinator::{
        ProverCoordinator, ProverCoordinatorConfig,
    };
    use codec::Encode;
    use sp_core::H256;
    use std::sync::Arc;
    use std::time::Duration;
    use transaction_circuit::{proof::TransactionProof, public_inputs::TransactionPublicInputs};

    fn payload(tx_count: u32) -> pallet_shielded_pool::types::CandidateArtifact {
        pallet_shielded_pool::types::CandidateArtifact {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count,
            tx_statements_commitment: [5u8; 48],
            da_root: [6u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![1, 2]),
            proof_mode: pallet_shielded_pool::types::BlockProofMode::FlatBatches,
            flat_batches: vec![pallet_shielded_pool::types::BatchProofItem {
                start_tx_index: 0,
                tx_count: tx_count.min(u16::MAX as u32) as u16,
                proof_format: pallet_shielded_pool::types::BLOCK_PROOF_FORMAT_ID_V5,
                proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![3, 4]),
            }],
            merge_root: None,
            artifact_claim: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prover_rpc_workflow_methods_operate_end_to_end() {
        let parent_hash = H256::repeat_byte(91);
        let config = ProverCoordinatorConfig {
            workers: 1,
            target_txs: 1,
            queue_capacity: 1,
            max_inflight_per_level: 1,
            liveness_lane: true,
            adaptive_liveness_timeout: Duration::from_millis(0),
            incremental_upsizing: false,
            poll_interval: Duration::from_millis(10),
            job_timeout: Duration::from_secs(1),
            work_package_ttl: Duration::from_secs(2),
            max_submissions_per_package: 4,
            max_submissions_per_source: 4,
            max_payload_bytes: 1024,
        };
        let best = Arc::new(move || (parent_hash, 2u64));
        let pending = Arc::new(move |_max_txs: usize| vec![vec![1u8]]);
        let build = Arc::new(
            move |_parent: H256, _number: u64, _candidate_txs: Vec<Vec<u8>>| {
                Err("disabled local builder for rpc test".to_string())
            },
        );
        let root_aggregation = Arc::new(move |_candidate_txs: Vec<Vec<u8>>| {
            Ok(Some(crate::substrate::prover_coordinator::RootAggregationWorkData {
                    statement_hashes: vec![[7u8; 48]],
                    tx_proofs: vec![TransactionProof {
                        public_inputs: TransactionPublicInputs::default(),
                        nullifiers: Vec::new(),
                        commitments: Vec::new(),
                        balance_slots: Vec::new(),
                        stark_proof: Vec::new(),
                        stark_public_inputs: None,
                    }],
                    tx_statements_commitment: [5u8; 48],
                    tree_levels: 1,
                    root_level: 0,
                }))
        });
        let finalize = Arc::new(
            move |parent_hash: H256,
                  _number: u64,
                  candidate_txs: Vec<Vec<u8>>,
                  _root_proof_bytes: Vec<u8>| {
                let payload = payload(candidate_txs.len() as u32);
                Ok(crate::substrate::prover_coordinator::PreparedBundle {
                    key: crate::substrate::prover_coordinator::BundleMatchKey {
                        parent_hash,
                        tx_statements_commitment: payload.tx_statements_commitment,
                        tx_count: payload.tx_count,
                        proof_mode: payload.proof_mode,
                        artifact_hash: crate::substrate::artifact_market::candidate_artifact_hash(
                            &payload,
                        ),
                    },
                    payload,
                    candidate_txs,
                    build_ms: 1,
                })
            },
        );
        let coordinator = ProverCoordinator::new_with_recursive_builders(
            config,
            best,
            pending,
            build,
            finalize,
            Some(root_aggregation),
        );
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let rpc = ProverRpc::new(coordinator.clone());
        let stage_package = rpc
            .get_stage_work_package()
            .await
            .expect("stage package call should succeed")
            .expect("stage package should exist");
        assert_eq!(stage_package.stage_type, "leaf_batch_prove");
        assert!(stage_package.leaf_batch_payload.is_some());
        assert!(stage_package.merge_node_payload.is_none());

        let encoded = payload(stage_package.tx_count).encode();
        let submit = rpc
            .submit_work_result(SubmitWorkResultRequest {
                source: "rpc-test".to_string(),
                package_id: stage_package.package_id.clone(),
                payload: format!("0x{}", hex::encode(encoded)),
            })
            .await
            .expect("submit should return rpc result");
        assert!(!submit.accepted);
        assert!(submit.error.is_some());

        let stage_submit = rpc
            .submit_stage_work_result(SubmitWorkResultRequest {
                source: "rpc-test-stage".to_string(),
                package_id: stage_package.package_id.clone(),
                payload: "0x00".to_string(),
            })
            .await
            .expect("stage submit should return rpc result");
        assert!(!stage_submit.accepted);
        assert!(stage_submit.error.is_some());

        let status = rpc
            .get_work_status(stage_package.package_id.clone())
            .await
            .expect("status call should succeed")
            .expect("status should exist");
        assert!(
            status.status == "pending"
                || status.status == "rejected"
                || status.status == "accepted",
            "status should reflect the latest submission outcome"
        );

        let params = rpc
            .get_market_params()
            .await
            .expect("market params call should succeed");
        assert_eq!(params.package_ttl_ms, 2_000);
        assert_eq!(params.max_submissions_per_package, 4);
        assert_eq!(params.max_submissions_per_source, 4);
        assert_eq!(params.max_payload_bytes, 1024);

        let announcements = rpc
            .list_artifact_announcements()
            .await
            .expect("announcement call should succeed");
        let _ = announcements;

        let stage_status = rpc
            .get_stage_plan_status()
            .await
            .expect("stage status call should succeed");
        assert!(stage_status.generation > 0);
        assert!(
            stage_status.latest_work_package.is_some(),
            "latest stage package should be tracked"
        );
    }
}
