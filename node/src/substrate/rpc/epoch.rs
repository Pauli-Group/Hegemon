//! Recursive epoch proof RPC endpoints.
//!
//! Provides read access to locally persisted recursive epoch proofs and a helper to request
//! missing proofs from peers over the PQ network.

use crate::substrate::epoch_proofs::RecursiveEpochProofStore;
use crate::substrate::network_bridge::{
    RecursiveEpochProofMessage, RecursiveEpochProofProtocolMessage,
    RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2,
};
use codec::Encode;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use network::PqNetworkHandle;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveEpochProofRpc {
    pub epoch_number: u64,
    pub start_block: u64,
    pub end_block: u64,
    pub proof_root: String,
    pub state_root: String,
    pub nullifier_set_root: String,
    pub commitment_tree_root: String,
    pub epoch_commitment: String,
    pub num_proofs: u32,
    pub proof_accumulator: String,
    pub proof_bytes: String,
    pub inner_proof_bytes: String,
    pub is_recursive: bool,
}

impl From<RecursiveEpochProofMessage> for RecursiveEpochProofRpc {
    fn from(msg: RecursiveEpochProofMessage) -> Self {
        Self {
            epoch_number: msg.epoch_number,
            start_block: msg.start_block,
            end_block: msg.end_block,
            proof_root: format!("0x{}", hex::encode(msg.proof_root)),
            state_root: format!("0x{}", hex::encode(msg.state_root)),
            nullifier_set_root: format!("0x{}", hex::encode(msg.nullifier_set_root)),
            commitment_tree_root: format!("0x{}", hex::encode(msg.commitment_tree_root)),
            epoch_commitment: format!("0x{}", hex::encode(msg.epoch_commitment)),
            num_proofs: msg.num_proofs,
            proof_accumulator: format!("0x{}", hex::encode(msg.proof_accumulator)),
            proof_bytes: format!("0x{}", hex::encode(msg.proof_bytes)),
            inner_proof_bytes: format!("0x{}", hex::encode(msg.inner_proof_bytes)),
            is_recursive: msg.is_recursive,
        }
    }
}

#[rpc(server, client, namespace = "epoch")]
pub trait EpochApi {
    /// Get a locally stored recursive epoch proof by epoch number.
    #[method(name = "getRecursiveProof")]
    async fn get_recursive_proof(
        &self,
        epoch_number: u64,
    ) -> RpcResult<Option<RecursiveEpochProofRpc>>;

    /// List epoch numbers for which we have stored recursive epoch proofs.
    #[method(name = "listRecursiveProofs")]
    async fn list_recursive_proofs(&self) -> RpcResult<Vec<u64>>;

    /// Request a recursive epoch proof from all connected peers.
    #[method(name = "requestRecursiveProof")]
    async fn request_recursive_proof(&self, epoch_number: u64) -> RpcResult<u32>;
}

pub struct EpochRpc {
    store: Arc<Mutex<RecursiveEpochProofStore>>,
    network: Option<PqNetworkHandle>,
}

impl EpochRpc {
    pub fn new(
        store: Arc<Mutex<RecursiveEpochProofStore>>,
        network: Option<PqNetworkHandle>,
    ) -> Self {
        Self { store, network }
    }
}

#[async_trait::async_trait]
impl EpochApiServer for EpochRpc {
    async fn get_recursive_proof(
        &self,
        epoch_number: u64,
    ) -> RpcResult<Option<RecursiveEpochProofRpc>> {
        let msg = self.store.lock().await.get(epoch_number).cloned();
        Ok(msg.map(Into::into))
    }

    async fn list_recursive_proofs(&self) -> RpcResult<Vec<u64>> {
        Ok(self.store.lock().await.epochs())
    }

    async fn request_recursive_proof(&self, epoch_number: u64) -> RpcResult<u32> {
        let Some(handle) = self.network.clone() else {
            return Err(ErrorObjectOwned::owned(
                -32000,
                "PQ network not available",
                None::<()>,
            ));
        };

        let peers = handle.connected_peers().await;
        let request = RecursiveEpochProofProtocolMessage::Request { epoch_number }.encode();

        let mut sent = 0u32;
        for peer_id in peers {
            if handle
                .send_message(
                    peer_id,
                    RECURSIVE_EPOCH_PROOFS_PROTOCOL_V2.to_string(),
                    request.clone(),
                )
                .await
                .is_ok()
            {
                sent += 1;
            }
        }

        Ok(sent)
    }
}
