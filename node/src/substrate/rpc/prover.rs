//! Prover market RPC endpoints.

use crate::substrate::prover_coordinator::{ProverCoordinator, WorkStatus};
use codec::Decode;
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
    pub tx_count: u32,
    pub candidate_txs: Vec<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitWorkResultRequest {
    pub source: String,
    pub package_id: String,
    /// SCALE-encoded `BlockProofBundle` bytes (0x-prefixed hex or base64).
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

#[rpc(server, client, namespace = "prover")]
pub trait ProverApi {
    #[method(name = "getWorkPackage")]
    async fn get_work_package(&self) -> RpcResult<Option<WorkPackageResponse>>;

    #[method(name = "submitWorkResult")]
    async fn submit_work_result(
        &self,
        request: SubmitWorkResultRequest,
    ) -> RpcResult<SubmitWorkResultResponse>;

    #[method(name = "getWorkStatus")]
    async fn get_work_status(&self, package_id: String) -> RpcResult<Option<WorkStatusResponse>>;

    #[method(name = "getMarketParams")]
    async fn get_market_params(&self) -> RpcResult<MarketParamsResponse>;
}

pub struct ProverRpc {
    coordinator: Arc<ProverCoordinator>,
}

impl ProverRpc {
    pub fn new(coordinator: Arc<ProverCoordinator>) -> Self {
        Self { coordinator }
    }
}

#[async_trait::async_trait]
impl ProverApiServer for ProverRpc {
    async fn get_work_package(&self) -> RpcResult<Option<WorkPackageResponse>> {
        Ok(self
            .coordinator
            .get_work_package()
            .map(|package| WorkPackageResponse {
                package_id: package.package_id,
                parent_hash: format!("0x{}", hex::encode(package.parent_hash)),
                block_number: package.block_number,
                tx_count: package.tx_count,
                candidate_txs: package
                    .candidate_txs
                    .into_iter()
                    .map(|tx| format!("0x{}", hex::encode(tx)))
                    .collect(),
                created_at_ms: package.created_at_ms,
                expires_at_ms: package.expires_at_ms,
            }))
    }

    async fn submit_work_result(
        &self,
        request: SubmitWorkResultRequest,
    ) -> RpcResult<SubmitWorkResultResponse> {
        let payload_bytes = parse_bytes(&request.payload)?;
        let payload =
            pallet_shielded_pool::types::BlockProofBundle::decode(&mut payload_bytes.as_slice())
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
    use crate::substrate::prover_coordinator::{ProverCoordinator, ProverCoordinatorConfig};
    use codec::Encode;
    use sp_core::H256;
    use std::sync::Arc;
    use std::time::Duration;

    fn payload(tx_count: u32) -> pallet_shielded_pool::types::BlockProofBundle {
        pallet_shielded_pool::types::BlockProofBundle {
            version: pallet_shielded_pool::types::BLOCK_PROOF_BUNDLE_SCHEMA,
            tx_count,
            tx_statements_commitment: [5u8; 48],
            da_root: [6u8; 48],
            da_chunk_count: 1,
            commitment_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![1, 2]),
            aggregation_proof: pallet_shielded_pool::types::StarkProof::from_bytes(vec![3, 4]),
            prover_claim: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prover_rpc_workflow_methods_operate_end_to_end() {
        let parent_hash = H256::repeat_byte(91);
        let config = ProverCoordinatorConfig {
            workers: 1,
            target_txs: 1,
            queue_capacity: 1,
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
        let coordinator = ProverCoordinator::new(config, best, pending, build);
        coordinator.start();
        tokio::time::sleep(Duration::from_millis(60)).await;

        let rpc = ProverRpc::new(coordinator.clone());
        let package = rpc
            .get_work_package()
            .await
            .expect("rpc call should succeed")
            .expect("package should exist");

        let encoded = payload(package.tx_count).encode();
        let submit = rpc
            .submit_work_result(SubmitWorkResultRequest {
                source: "rpc-test".to_string(),
                package_id: package.package_id.clone(),
                payload: format!("0x{}", hex::encode(encoded)),
            })
            .await
            .expect("submit should return rpc result");
        assert!(submit.accepted);
        assert!(submit.error.is_none());

        let status = rpc
            .get_work_status(package.package_id.clone())
            .await
            .expect("status call should succeed")
            .expect("status should exist");
        assert_eq!(status.status, "accepted");

        let params = rpc
            .get_market_params()
            .await
            .expect("market params call should succeed");
        assert_eq!(params.package_ttl_ms, 2_000);
        assert_eq!(params.max_submissions_per_package, 4);
        assert_eq!(params.max_submissions_per_source, 4);
        assert_eq!(params.max_payload_bytes, 1024);
    }
}
