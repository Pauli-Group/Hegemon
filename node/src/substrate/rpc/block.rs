//! Block-level RPC endpoints for commitment proofs.

use crate::substrate::service::CommitmentBlockProofStore;
use block_circuit::{CommitmentBlockProof, CommitmentBlockPublicInputs};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sp_core::H256;
use std::sync::Arc;
use transaction_circuit::hashing_pq::felts_to_bytes48;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentBlockPublicInputsRpc {
    pub tx_proofs_commitment: String,
    pub starting_state_root: String,
    pub ending_state_root: String,
    pub nullifier_root: String,
    pub da_root: String,
    pub tx_count: u32,
    pub nullifiers: Vec<String>,
    pub sorted_nullifiers: Vec<String>,
}

impl From<&CommitmentBlockPublicInputs> for CommitmentBlockPublicInputsRpc {
    fn from(value: &CommitmentBlockPublicInputs) -> Self {
        Self {
            tx_proofs_commitment: format!(
                "0x{}",
                hex::encode(felts_to_bytes48(&value.tx_proofs_commitment))
            ),
            starting_state_root: format!(
                "0x{}",
                hex::encode(felts_to_bytes48(&value.starting_state_root))
            ),
            ending_state_root: format!(
                "0x{}",
                hex::encode(felts_to_bytes48(&value.ending_state_root))
            ),
            nullifier_root: format!("0x{}", hex::encode(felts_to_bytes48(&value.nullifier_root))),
            da_root: format!("0x{}", hex::encode(felts_to_bytes48(&value.da_root))),
            tx_count: value.tx_count,
            nullifiers: value
                .nullifiers
                .iter()
                .map(|nf| format!("0x{}", hex::encode(felts_to_bytes48(nf))))
                .collect(),
            sorted_nullifiers: value
                .sorted_nullifiers
                .iter()
                .map(|nf| format!("0x{}", hex::encode(felts_to_bytes48(nf))))
                .collect(),
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
    /// Get a locally stored commitment block proof by block hash.
    #[method(name = "getCommitmentProof")]
    async fn get_commitment_proof(
        &self,
        block_hash: String,
    ) -> RpcResult<Option<CommitmentBlockProofRpc>>;
}

pub struct BlockRpc {
    commitment_store: Arc<Mutex<CommitmentBlockProofStore>>,
}

impl BlockRpc {
    pub fn new(commitment_store: Arc<Mutex<CommitmentBlockProofStore>>) -> Self {
        Self { commitment_store }
    }
}

#[async_trait::async_trait]
impl BlockApiServer for BlockRpc {
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
