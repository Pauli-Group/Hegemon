//! Data-availability RPC endpoints.

use crate::substrate::service::DaChunkStore;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use state_da::{DaChunkProof, DaParams, DaRoot};
use std::sync::Arc;

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

#[rpc(server, client, namespace = "da")]
pub trait DaApi {
    /// Get a DA chunk proof by root and chunk index.
    #[method(name = "getChunk")]
    async fn get_chunk(&self, root: String, index: u32) -> RpcResult<Option<DaChunkProofRpc>>;

    /// Get DA parameters for the current chain.
    #[method(name = "getParams")]
    async fn get_params(&self) -> RpcResult<DaParamsRpc>;
}

pub struct DaRpc {
    store: Arc<Mutex<DaChunkStore>>,
    params: DaParams,
}

impl DaRpc {
    pub fn new(store: Arc<Mutex<DaChunkStore>>, params: DaParams) -> Self {
        Self { store, params }
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
