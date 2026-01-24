//! Data-availability RPC endpoints.

use crate::substrate::service::{DaChunkStore, PendingCiphertextStore};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use state_da::{DaChunkProof, DaParams, DaRoot};
use std::sync::Arc;
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaParamsRpc {
    pub chunk_size: u32,
    pub sample_count: u32,
}

impl From<DaParams> for DaParamsRpc {
    fn from(params: DaParams) -> Self {
        Self {
            chunk_size: params.chunk_size,
            sample_count: params.sample_count,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaChunkRpc {
    pub index: u32,
    pub data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaChunkProofRpc {
    pub chunk: DaChunkRpc,
    pub merkle_path: Vec<String>,
}

impl From<DaChunkProof> for DaChunkProofRpc {
    fn from(proof: DaChunkProof) -> Self {
        let chunk = DaChunkRpc {
            index: proof.chunk.index,
            data: format!("0x{}", hex::encode(proof.chunk.data)),
        };
        let merkle_path = proof
            .merkle_path
            .into_iter()
            .map(|node| format!("0x{}", hex::encode(node)))
            .collect();
        Self { chunk, merkle_path }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitCiphertextsRequest {
    /// Ciphertext bytes (base64, or 0x-prefixed hex).
    pub ciphertexts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitCiphertextsEntry {
    pub hash: String,
    pub size: u32,
}

#[rpc(server, client, namespace = "da")]
pub trait DaApi {
    /// Get a DA chunk proof by root and chunk index.
    #[method(name = "getChunk")]
    async fn get_chunk(&self, root: String, index: u32) -> RpcResult<Option<DaChunkProofRpc>>;

    /// Get DA parameters for the current chain.
    #[method(name = "getParams")]
    async fn get_params(&self) -> RpcResult<DaParamsRpc>;

    /// Stage ciphertext bytes in the node's pending sidecar pool.
    ///
    /// This is used by sidecar-based shielded transfer submission paths
    /// (`*_sidecar` extrinsics) so the block author can assemble the DA blob
    /// without requiring ciphertext bytes to live in the block body.
    #[method(name = "submitCiphertexts")]
    async fn submit_ciphertexts(
        &self,
        request: SubmitCiphertextsRequest,
    ) -> RpcResult<Vec<SubmitCiphertextsEntry>>;
}

pub struct DaRpc {
    store: Arc<Mutex<DaChunkStore>>,
    pending_ciphertexts: Arc<Mutex<PendingCiphertextStore>>,
    params: DaParams,
}

impl DaRpc {
    pub fn new(
        store: Arc<Mutex<DaChunkStore>>,
        pending_ciphertexts: Arc<Mutex<PendingCiphertextStore>>,
        params: DaParams,
    ) -> Self {
        Self {
            store,
            pending_ciphertexts,
            params,
        }
    }
}

#[async_trait::async_trait]
impl DaApiServer for DaRpc {
    async fn get_chunk(&self, root: String, index: u32) -> RpcResult<Option<DaChunkProofRpc>> {
        let root = parse_da_root(&root)?;
        let proof = {
            let mut store = self.store.lock();
            store.get(&root).map(|encoding| encoding.proof(index))
        };

        match proof {
            None => Ok(None),
            Some(Ok(proof)) => Ok(Some(DaChunkProofRpc::from(proof))),
            Some(Err(_)) => Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                "chunk index out of range",
                None::<()>,
            )),
        }
    }

    async fn get_params(&self) -> RpcResult<DaParamsRpc> {
        Ok(self.params.into())
    }

    async fn submit_ciphertexts(
        &self,
        request: SubmitCiphertextsRequest,
    ) -> RpcResult<Vec<SubmitCiphertextsEntry>> {
        const MAX_CIPHERTEXTS_PER_REQUEST: usize = 256;
        const MAX_TOTAL_BYTES_PER_REQUEST: usize = 2 * 1024 * 1024;

        if request.ciphertexts.len() > MAX_CIPHERTEXTS_PER_REQUEST {
            return Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                format!(
                    "too many ciphertexts (max {})",
                    MAX_CIPHERTEXTS_PER_REQUEST
                ),
                None::<()>,
            ));
        }

        let mut total_bytes = 0usize;
        let mut entries = Vec::with_capacity(request.ciphertexts.len());
        let mut pending = self.pending_ciphertexts.lock();
        for encoded in request.ciphertexts {
            let bytes = parse_bytes(&encoded)?;
            if bytes.is_empty() {
                return Err(ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    "ciphertext bytes empty",
                    None::<()>,
                ));
            }
            if bytes.len() > pallet_shielded_pool::types::MAX_CIPHERTEXT_BYTES {
                return Err(ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    "ciphertext exceeds MAX_CIPHERTEXT_BYTES",
                    None::<()>,
                ));
            }
            total_bytes = total_bytes.saturating_add(bytes.len());
            if total_bytes > MAX_TOTAL_BYTES_PER_REQUEST {
                return Err(ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    format!(
                        "request too large (max {} bytes)",
                        MAX_TOTAL_BYTES_PER_REQUEST
                    ),
                    None::<()>,
                ));
            }

            let size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            let hash = ciphertext_hash_bytes(&bytes);
            pending.insert(hash, bytes);
            entries.push(SubmitCiphertextsEntry {
                hash: format!("0x{}", hex::encode(hash)),
                size,
            });
        }

        Ok(entries)
    }
}

fn parse_da_root(value: &str) -> Result<DaRoot, ErrorObjectOwned> {
    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| {
        ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("invalid hex: {err}"),
            None::<()>,
        )
    })?;
    if bytes.len() != 48 {
        return Err(ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("expected 48-byte root, got {}", bytes.len()),
            None::<()>,
        ));
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
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
