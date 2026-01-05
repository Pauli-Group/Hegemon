//! Block-level RPC endpoints for recursive and commitment proofs.

use crate::substrate::service::{CommitmentBlockProofStore, RecursiveBlockProofStore};
use block_circuit::{
    CommitmentBlockProof, CommitmentBlockPublicInputs, RecursiveBlockProof,
    SerializedVerifierInputs,
};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sp_core::H256;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedVerifierInputsRpc {
    pub inner_len: u32,
    pub elements: Vec<u64>,
}

impl From<&SerializedVerifierInputs> for SerializedVerifierInputsRpc {
    fn from(value: &SerializedVerifierInputs) -> Self {
        Self {
            inner_len: value.inner_len,
            elements: value.elements.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveBlockProofRpc {
    pub block_hash: String,
    pub proof_bytes: String,
    pub recursive_proof_hash: String,
    pub starting_root: String,
    pub ending_root: String,
    pub tx_count: u32,
    pub verifier_inputs: Vec<SerializedVerifierInputsRpc>,
}

impl RecursiveBlockProofRpc {
    fn from_proof(block_hash: H256, proof: &RecursiveBlockProof) -> Self {
        Self {
            block_hash: format!("0x{}", hex::encode(block_hash.as_bytes())),
            proof_bytes: format!("0x{}", hex::encode(&proof.proof_bytes)),
            recursive_proof_hash: format!("0x{}", hex::encode(proof.recursive_proof_hash)),
            starting_root: format!("0x{}", hex::encode(proof.starting_root)),
            ending_root: format!("0x{}", hex::encode(proof.ending_root)),
            tx_count: proof.tx_count,
            verifier_inputs: proof
                .verifier_inputs
                .iter()
                .map(SerializedVerifierInputsRpc::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentBlockPublicInputsRpc {
    pub tx_proofs_commitment: String,
    pub starting_state_root: String,
    pub ending_state_root: String,
    pub nullifier_root: String,
    pub da_root: String,
    pub tx_count: u32,
}

impl From<&CommitmentBlockPublicInputs> for CommitmentBlockPublicInputsRpc {
    fn from(value: &CommitmentBlockPublicInputs) -> Self {
        Self {
            tx_proofs_commitment: format!("0x{}", hex::encode(value.tx_proofs_commitment)),
            starting_state_root: format!("0x{}", hex::encode(value.starting_state_root)),
            ending_state_root: format!("0x{}", hex::encode(value.ending_state_root)),
            nullifier_root: format!("0x{}", hex::encode(value.nullifier_root)),
            da_root: format!("0x{}", hex::encode(value.da_root)),
            tx_count: value.tx_count,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentBlockProofRpc {
    pub block_hash: String,
    pub proof_bytes: String,
    pub proof_hash: String,
    pub public_inputs: CommitmentBlockPublicInputsRpc,
}

impl CommitmentBlockProofRpc {
    fn from_proof(block_hash: H256, proof: &CommitmentBlockProof) -> Self {
        Self {
            block_hash: format!("0x{}", hex::encode(block_hash.as_bytes())),
            proof_bytes: format!("0x{}", hex::encode(&proof.proof_bytes)),
            proof_hash: format!("0x{}", hex::encode(proof.proof_hash)),
            public_inputs: CommitmentBlockPublicInputsRpc::from(&proof.public_inputs),
        }
    }
}

#[rpc(server, client, namespace = "block")]
pub trait BlockApi {
    /// Get a locally stored recursive block proof by block hash.
    #[method(name = "getRecursiveProof")]
    async fn get_recursive_proof(
        &self,
        block_hash: String,
    ) -> RpcResult<Option<RecursiveBlockProofRpc>>;

    /// Get a locally stored commitment block proof by block hash.
    #[method(name = "getCommitmentProof")]
    async fn get_commitment_proof(
        &self,
        block_hash: String,
    ) -> RpcResult<Option<CommitmentBlockProofRpc>>;
}

pub struct BlockRpc {
    recursive_store: Arc<Mutex<RecursiveBlockProofStore>>,
    commitment_store: Arc<Mutex<CommitmentBlockProofStore>>,
}

impl BlockRpc {
    pub fn new(
        recursive_store: Arc<Mutex<RecursiveBlockProofStore>>,
        commitment_store: Arc<Mutex<CommitmentBlockProofStore>>,
    ) -> Self {
        Self {
            recursive_store,
            commitment_store,
        }
    }
}

#[async_trait::async_trait]
impl BlockApiServer for BlockRpc {
    async fn get_recursive_proof(
        &self,
        block_hash: String,
    ) -> RpcResult<Option<RecursiveBlockProofRpc>> {
        let hash = parse_h256(&block_hash)?;
        let proof = self.recursive_store.lock().get(&hash).cloned();
        Ok(proof.map(|proof| RecursiveBlockProofRpc::from_proof(hash, &proof)))
    }

    async fn get_commitment_proof(
        &self,
        block_hash: String,
    ) -> RpcResult<Option<CommitmentBlockProofRpc>> {
        let hash = parse_h256(&block_hash)?;
        let proof = self.commitment_store.lock().get(&hash).cloned();
        Ok(proof.map(|proof| CommitmentBlockProofRpc::from_proof(hash, &proof)))
    }
}

fn parse_h256(value: &str) -> Result<H256, ErrorObjectOwned> {
    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| {
        ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("invalid hex: {err}"),
            None::<()>,
        )
    })?;
    if bytes.len() != 32 {
        return Err(ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("expected 32-byte hash, got {}", bytes.len()),
            None::<()>,
        ));
    }
    Ok(H256::from_slice(&bytes))
}
