//! Data-availability RPC endpoints.

use crate::substrate::service::{DaChunkStore, PendingCiphertextStore, PendingProofStore};
use consensus::backend_interface::{
    decode_native_tx_leaf_artifact_bytes, verify_native_tx_leaf_artifact_bytes,
    NativeTxLeafArtifact,
};
use crypto::hashes::blake3_384;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use pallet_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use state_da::{DaChunkProof, DaParams, DaRoot};
use std::sync::Arc;
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;

const NATIVE_TX_CANONICAL_PADDING_ASSET_ID: u64 = 4_294_967_294;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitProofsRequest {
    pub proofs: Vec<SubmitProofsItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitProofsItem {
    /// Binding hash bytes (0x-prefixed hex).
    pub binding_hash: String,
    /// Proof bytes (base64, or 0x-prefixed hex).
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitProofsEntry {
    pub binding_hash: String,
    pub proof_hash: String,
    pub size: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitWitnessesRequest {
    pub witnesses: Vec<SubmitWitnessesItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitWitnessesItem {
    /// Binding hash bytes (0x-prefixed hex).
    pub binding_hash: String,
    /// Witness bytes (base64, or 0x-prefixed hex).
    pub witness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitWitnessesEntry {
    pub binding_hash: String,
    pub witness_hash: String,
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

    /// Stage transaction proof bytes in the node's pending sidecar pool.
    ///
    /// In rollup/aggregation mode, shielded transfer extrinsics may omit the per-tx proof bytes
    /// from the block body; the block author assembles an aggregation proof using these staged
    /// proofs.
    ///
    /// Phase C note: this is an off-chain proposer/mempool staging API, not a consensus
    /// proof-availability requirement.
    #[method(name = "submitProofs")]
    async fn submit_proofs(
        &self,
        request: SubmitProofsRequest,
    ) -> RpcResult<Vec<SubmitProofsEntry>>;

    /// Witness sidecar upload is disabled.
    ///
    /// CRIT-1 hardening: spend witnesses may contain secret material and must not be uploaded
    /// to third-party nodes over RPC.
    #[method(name = "submitWitnesses")]
    async fn submit_witnesses(
        &self,
        request: SubmitWitnessesRequest,
    ) -> RpcResult<Vec<SubmitWitnessesEntry>>;
}

pub struct DaRpc {
    store: Arc<Mutex<DaChunkStore>>,
    pending_ciphertexts: Arc<Mutex<PendingCiphertextStore>>,
    pending_proofs: Arc<Mutex<PendingProofStore>>,
    params: DaParams,
    deny_unsafe: sc_rpc::DenyUnsafe,
}

impl DaRpc {
    pub fn new(
        store: Arc<Mutex<DaChunkStore>>,
        pending_ciphertexts: Arc<Mutex<PendingCiphertextStore>>,
        pending_proofs: Arc<Mutex<PendingProofStore>>,
        params: DaParams,
        deny_unsafe: sc_rpc::DenyUnsafe,
    ) -> Self {
        Self {
            store,
            pending_ciphertexts,
            pending_proofs,
            params,
            deny_unsafe,
        }
    }

    fn ensure_staging_allowed(&self) -> RpcResult<()> {
        if matches!(self.deny_unsafe, sc_rpc::DenyUnsafe::Yes) {
            return Err(invalid_params(
                "DA staging RPC is unsafe; run node with --rpc-methods=unsafe to enable",
            ));
        }
        Ok(())
    }
}

fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, message.into(), None::<()>)
}

fn signed_magnitude_to_i128(sign: u8, magnitude: u64) -> Result<i128, ErrorObjectOwned> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        _ => Err(invalid_params(
            "native tx-leaf staged proof has invalid signed-magnitude flag",
        )),
    }
}

fn decanonicalize_balance_slot_asset_id(asset_id: u64) -> u64 {
    if asset_id == NATIVE_TX_CANONICAL_PADDING_ASSET_ID {
        u64::MAX
    } else {
        asset_id
    }
}

fn stablecoin_binding_from_artifact(
    artifact: &NativeTxLeafArtifact,
) -> Result<Option<pallet_shielded_pool::types::StablecoinPolicyBinding>, ErrorObjectOwned> {
    if artifact.stark_public_inputs.stablecoin_enabled == 0 {
        return Ok(None);
    }

    Ok(Some(pallet_shielded_pool::types::StablecoinPolicyBinding {
        asset_id: artifact.stark_public_inputs.stablecoin_asset_id,
        policy_hash: artifact.stark_public_inputs.stablecoin_policy_hash,
        oracle_commitment: artifact.stark_public_inputs.stablecoin_oracle_commitment,
        attestation_commitment: artifact
            .stark_public_inputs
            .stablecoin_attestation_commitment,
        issuance_delta: signed_magnitude_to_i128(
            artifact.stark_public_inputs.stablecoin_issuance_sign,
            artifact.stark_public_inputs.stablecoin_issuance_magnitude,
        )?,
        policy_version: artifact.stark_public_inputs.stablecoin_policy_version,
    }))
}

fn try_binding_hash_from_native_tx_leaf_artifact(
    artifact: &NativeTxLeafArtifact,
    balance_slot_asset_ids: [u64; transaction_circuit::constants::BALANCE_SLOTS],
) -> Result<[u8; 64], ErrorObjectOwned> {
    Ok(
        StarkVerifier::compute_binding_hash(&ShieldedTransferInputs {
            anchor: artifact.stark_public_inputs.merkle_root,
            nullifiers: artifact.tx.nullifiers.clone(),
            commitments: artifact.tx.commitments.clone(),
            ciphertext_hashes: artifact.tx.ciphertext_hashes.clone(),
            balance_slot_asset_ids,
            fee: artifact.stark_public_inputs.fee,
            value_balance: signed_magnitude_to_i128(
                artifact.stark_public_inputs.value_balance_sign,
                artifact.stark_public_inputs.value_balance_magnitude,
            )?,
            stablecoin: stablecoin_binding_from_artifact(artifact)?,
        })
        .data,
    )
}

fn binding_hash_candidates_from_native_tx_leaf_artifact(
    artifact: &NativeTxLeafArtifact,
) -> Result<[[u8; 64]; 2], ErrorObjectOwned> {
    let direct_asset_ids: [u64; transaction_circuit::constants::BALANCE_SLOTS] = artifact
        .stark_public_inputs
        .balance_slot_asset_ids
        .clone()
        .try_into()
        .map_err(|_| {
            invalid_params("native tx-leaf staged proof has invalid balance-slot shape")
        })?;
    let legacy_asset_ids = direct_asset_ids.map(decanonicalize_balance_slot_asset_id);

    Ok([
        try_binding_hash_from_native_tx_leaf_artifact(artifact, legacy_asset_ids)?,
        try_binding_hash_from_native_tx_leaf_artifact(artifact, direct_asset_ids)?,
    ])
}

fn prevalidate_staged_native_tx_leaf_artifact(
    binding_hash: &[u8; 64],
    bytes: &[u8],
) -> Result<(), ErrorObjectOwned> {
    if bytes.len() > pallet_shielded_pool::types::NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE {
        return Err(invalid_params(
            "proof exceeds NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE",
        ));
    }

    let artifact = decode_native_tx_leaf_artifact_bytes(bytes).map_err(|err| {
        invalid_params(format!(
            "staged proof must be a canonical native tx-leaf artifact: {err}"
        ))
    })?;
    verify_native_tx_leaf_artifact_bytes(&artifact.tx, &artifact.receipt, bytes).map_err(
        |err| {
            invalid_params(format!(
                "staged native tx-leaf artifact failed self-verification: {err}"
            ))
        },
    )?;

    let derived_binding_hashes = binding_hash_candidates_from_native_tx_leaf_artifact(&artifact)?;
    if !derived_binding_hashes
        .iter()
        .any(|candidate| candidate == binding_hash)
    {
        return Err(invalid_params(
            "staged native tx-leaf artifact binding hash does not match request binding hash",
        ));
    }

    Ok(())
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

        self.ensure_staging_allowed()?;

        if request.ciphertexts.len() > MAX_CIPHERTEXTS_PER_REQUEST {
            return Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                format!("too many ciphertexts (max {})", MAX_CIPHERTEXTS_PER_REQUEST),
                None::<()>,
            ));
        }

        let mut total_bytes = 0usize;
        let mut entries = Vec::with_capacity(request.ciphertexts.len());
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
            self.pending_ciphertexts
                .lock()
                .insert(hash, bytes)
                .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;
            entries.push(SubmitCiphertextsEntry {
                hash: format!("0x{}", hex::encode(hash)),
                size,
            });
        }

        Ok(entries)
    }

    async fn submit_proofs(
        &self,
        request: SubmitProofsRequest,
    ) -> RpcResult<Vec<SubmitProofsEntry>> {
        const MAX_PROOFS_PER_REQUEST: usize = 64;
        const MAX_TOTAL_BYTES_PER_REQUEST: usize = 16 * 1024 * 1024;

        self.ensure_staging_allowed()?;

        if request.proofs.len() > MAX_PROOFS_PER_REQUEST {
            return Err(ErrorObjectOwned::owned(
                INVALID_PARAMS_CODE,
                format!("too many proofs (max {})", MAX_PROOFS_PER_REQUEST),
                None::<()>,
            ));
        }

        let mut total_bytes = 0usize;
        let mut entries = Vec::with_capacity(request.proofs.len());

        for item in request.proofs {
            let binding_hash = parse_binding_hash(&item.binding_hash)?;
            let bytes = parse_bytes(&item.proof)?;

            if bytes.is_empty() {
                return Err(ErrorObjectOwned::owned(
                    INVALID_PARAMS_CODE,
                    "proof bytes empty",
                    None::<()>,
                ));
            }

            prevalidate_staged_native_tx_leaf_artifact(&binding_hash, &bytes)?;

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
            let proof_hash = blake3_384(&bytes);
            let mut pending = self.pending_proofs.lock();
            if let Some(existing) = pending.get(&binding_hash) {
                if existing.as_slice() != bytes.as_slice() {
                    return Err(invalid_params(
                        "binding hash already staged with different proof bytes",
                    ));
                }
            }
            pending
                .insert(binding_hash, bytes)
                .map_err(|err| ErrorObjectOwned::owned(INVALID_PARAMS_CODE, err, None::<()>))?;
            tracing::debug!(
                binding_hash = %hex::encode(binding_hash),
                proof_size = size,
                pending_proof_entries = pending.len(),
                "Staged proof bytes in pending proof store"
            );
            entries.push(SubmitProofsEntry {
                binding_hash: format!("0x{}", hex::encode(binding_hash)),
                proof_hash: format!("0x{}", hex::encode(proof_hash)),
                size,
            });
        }

        let pending_proof_entries = self.pending_proofs.lock().len();
        tracing::debug!(
            proofs_staged = entries.len(),
            total_bytes,
            pending_proof_entries,
            "Completed da_submitProofs request"
        );

        Ok(entries)
    }

    async fn submit_witnesses(
        &self,
        request: SubmitWitnessesRequest,
    ) -> RpcResult<Vec<SubmitWitnessesEntry>> {
        let _ = request;
        Err(ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            "da_submitWitnesses is disabled; upload tx proof bytes via da_submitProofs instead",
            None::<()>,
        ))
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

fn parse_binding_hash(value: &str) -> Result<[u8; 64], ErrorObjectOwned> {
    let trimmed = value.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|err| {
        ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!("invalid hex: {err}"),
            None::<()>,
        )
    })?;
    if bytes.len() != pallet_shielded_pool::types::BINDING_HASH_SIZE {
        return Err(ErrorObjectOwned::owned(
            INVALID_PARAMS_CODE,
            format!(
                "expected {}-byte binding hash, got {}",
                pallet_shielded_pool::types::BINDING_HASH_SIZE,
                bytes.len()
            ),
            None::<()>,
        ));
    }
    let mut out = [0u8; pallet_shielded_pool::types::BINDING_HASH_SIZE];
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

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::backend_interface::{
        build_native_tx_leaf_artifact_bytes, decode_native_tx_leaf_artifact_bytes,
    };
    use tempfile::TempDir;
    use transaction_circuit::constants::{CIRCUIT_MERKLE_DEPTH, NATIVE_ASSET_ID};
    use transaction_circuit::hashing_pq::{
        felts_to_bytes48, merkle_node, spend_auth_key_bytes, Felt, HashFelt,
    };
    use transaction_circuit::note::{InputNoteWitness, MerklePath, NoteData, OutputNoteWitness};
    use transaction_circuit::witness::TransactionWitness;

    fn sample_witness(seed: u8) -> TransactionWitness {
        let sk_spend = [seed.wrapping_add(42); 32];
        let pk_auth = spend_auth_key_bytes(&sk_spend);
        let input_note_native = NoteData {
            value: 8,
            asset_id: NATIVE_ASSET_ID,
            pk_recipient: [seed.wrapping_add(2); 32],
            pk_auth,
            rho: [seed.wrapping_add(3); 32],
            r: [seed.wrapping_add(4); 32],
        };
        let input_note_asset = NoteData {
            value: 5,
            asset_id: u64::from(seed) + 100,
            pk_recipient: [seed.wrapping_add(5); 32],
            pk_auth,
            rho: [seed.wrapping_add(6); 32],
            r: [seed.wrapping_add(7); 32],
        };
        let leaf0 = input_note_native.commitment();
        let leaf1 = input_note_asset.commitment();
        let (merkle_path0, merkle_path1, merkle_root) = build_two_leaf_merkle_tree(leaf0, leaf1);

        TransactionWitness {
            inputs: vec![
                InputNoteWitness {
                    note: input_note_native,
                    position: 0,
                    rho_seed: [seed.wrapping_add(9); 32],
                    merkle_path: merkle_path0,
                },
                InputNoteWitness {
                    note: input_note_asset,
                    position: 1,
                    rho_seed: [seed.wrapping_add(10); 32],
                    merkle_path: merkle_path1,
                },
            ],
            outputs: vec![
                OutputNoteWitness {
                    note: NoteData {
                        value: 3,
                        asset_id: NATIVE_ASSET_ID,
                        pk_recipient: [seed.wrapping_add(11); 32],
                        pk_auth: [seed.wrapping_add(12); 32],
                        rho: [seed.wrapping_add(13); 32],
                        r: [seed.wrapping_add(14); 32],
                    },
                },
                OutputNoteWitness {
                    note: NoteData {
                        value: 5,
                        asset_id: u64::from(seed) + 100,
                        pk_recipient: [seed.wrapping_add(21); 32],
                        pk_auth: [seed.wrapping_add(22); 32],
                        rho: [seed.wrapping_add(23); 32],
                        r: [seed.wrapping_add(24); 32],
                    },
                },
            ],
            ciphertext_hashes: vec![[0u8; 48]; 2],
            sk_spend,
            merkle_root: felts_to_bytes48(&merkle_root),
            fee: 5,
            value_balance: 0,
            stablecoin: transaction_circuit::StablecoinPolicyBinding::default(),
            version: TransactionWitness::default_version_binding(),
        }
    }

    fn build_two_leaf_merkle_tree(
        leaf0: HashFelt,
        leaf1: HashFelt,
    ) -> (MerklePath, MerklePath, HashFelt) {
        let mut siblings0 = vec![leaf1];
        let mut siblings1 = vec![leaf0];
        let mut current = merkle_node(leaf0, leaf1);
        for _ in 1..CIRCUIT_MERKLE_DEPTH {
            let zero = [Felt::new(0); 6];
            siblings0.push(zero);
            siblings1.push(zero);
            current = merkle_node(current, zero);
        }
        (
            MerklePath {
                siblings: siblings0,
            },
            MerklePath {
                siblings: siblings1,
            },
            current,
        )
    }

    fn valid_native_tx_leaf_proof_and_binding(seed: u8) -> (Vec<u8>, [u8; 64]) {
        let built = build_native_tx_leaf_artifact_bytes(&sample_witness(seed))
            .expect("native tx leaf bytes");
        let artifact =
            decode_native_tx_leaf_artifact_bytes(&built.artifact_bytes).expect("decode tx leaf");
        let binding_hash = binding_hash_candidates_from_native_tx_leaf_artifact(&artifact)
            .expect("derive binding hash")[0];
        (built.artifact_bytes, binding_hash)
    }

    fn test_rpc(deny_unsafe: sc_rpc::DenyUnsafe) -> (DaRpc, TempDir) {
        let tmpdir = TempDir::new().expect("temp dir");
        let store = DaChunkStore::open(tmpdir.path(), 8, 16, 16).expect("chunk store");
        (
            DaRpc::new(
                Arc::new(Mutex::new(store)),
                Arc::new(Mutex::new(PendingCiphertextStore::new(8, 4096))),
                Arc::new(Mutex::new(PendingProofStore::new(8, 1024 * 1024))),
                DaParams {
                    chunk_size: 1024,
                    sample_count: 4,
                },
                deny_unsafe,
            ),
            tmpdir,
        )
    }

    #[tokio::test]
    async fn submit_ciphertexts_rejects_safe_rpc_mode() {
        let (rpc, _tmpdir) = test_rpc(sc_rpc::DenyUnsafe::Yes);
        let err = rpc
            .submit_ciphertexts(SubmitCiphertextsRequest {
                ciphertexts: vec![format!("0x{}", hex::encode([7u8; 32]))],
            })
            .await
            .expect_err("safe rpc mode must reject DA ciphertext staging");
        assert!(
            err.message().contains("unsafe"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_proofs_rejects_non_native_tx_leaf_artifact() {
        let (rpc, _tmpdir) = test_rpc(sc_rpc::DenyUnsafe::No);
        let err = rpc
            .submit_proofs(SubmitProofsRequest {
                proofs: vec![SubmitProofsItem {
                    binding_hash: format!("0x{}", hex::encode([3u8; 64])),
                    proof: format!("0x{}", hex::encode([9u8; 48])),
                }],
            })
            .await
            .expect_err("non-native tx-leaf bytes must be rejected");
        assert!(
            err.message().contains("canonical native tx-leaf artifact"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_proofs_rejects_binding_hash_mismatch_for_native_tx_leaf() {
        let (rpc, _tmpdir) = test_rpc(sc_rpc::DenyUnsafe::No);
        let (proof_bytes, _binding_hash) = valid_native_tx_leaf_proof_and_binding(41);
        let err = rpc
            .submit_proofs(SubmitProofsRequest {
                proofs: vec![SubmitProofsItem {
                    binding_hash: format!("0x{}", hex::encode([9u8; 64])),
                    proof: format!("0x{}", hex::encode(proof_bytes)),
                }],
            })
            .await
            .expect_err("mismatched binding hash must be rejected");
        assert!(
            err.message().contains("binding hash"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_proofs_rejects_conflicting_existing_entry() {
        let pending_proofs = Arc::new(Mutex::new(PendingProofStore::new(8, 1024 * 1024)));
        let tmpdir = TempDir::new().expect("temp dir");
        let rpc = DaRpc::new(
            Arc::new(Mutex::new(
                DaChunkStore::open(tmpdir.path(), 8, 16, 16).expect("chunk store"),
            )),
            Arc::new(Mutex::new(PendingCiphertextStore::new(8, 4096))),
            Arc::clone(&pending_proofs),
            DaParams {
                chunk_size: 1024,
                sample_count: 4,
            },
            sc_rpc::DenyUnsafe::No,
        );
        let (proof_bytes, binding_hash) = valid_native_tx_leaf_proof_and_binding(42);
        pending_proofs
            .lock()
            .insert(binding_hash, vec![7u8; 32])
            .expect("insert conflicting pending proof");

        let err = rpc
            .submit_proofs(SubmitProofsRequest {
                proofs: vec![SubmitProofsItem {
                    binding_hash: format!("0x{}", hex::encode(binding_hash)),
                    proof: format!("0x{}", hex::encode(proof_bytes)),
                }],
            })
            .await
            .expect_err("conflicting staged proof bytes must be rejected");
        assert!(
            err.message().contains("different proof bytes"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_proofs_rejects_safe_rpc_mode() {
        let (rpc, _tmpdir) = test_rpc(sc_rpc::DenyUnsafe::Yes);
        let (proof_bytes, binding_hash) = valid_native_tx_leaf_proof_and_binding(43);
        let err = rpc
            .submit_proofs(SubmitProofsRequest {
                proofs: vec![SubmitProofsItem {
                    binding_hash: format!("0x{}", hex::encode(binding_hash)),
                    proof: format!("0x{}", hex::encode(proof_bytes)),
                }],
            })
            .await
            .expect_err("safe rpc mode must reject DA proof staging");
        assert!(
            err.message().contains("unsafe"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_ciphertexts_rejects_store_byte_budget_exhaustion() {
        let tmpdir = TempDir::new().expect("temp dir");
        let rpc = DaRpc::new(
            Arc::new(Mutex::new(
                DaChunkStore::open(tmpdir.path(), 8, 16, 16).expect("chunk store"),
            )),
            Arc::new(Mutex::new(PendingCiphertextStore::new(8, 8))),
            Arc::new(Mutex::new(PendingProofStore::new(8, 1024 * 1024))),
            DaParams {
                chunk_size: 1024,
                sample_count: 4,
            },
            sc_rpc::DenyUnsafe::No,
        );

        let err = rpc
            .submit_ciphertexts(SubmitCiphertextsRequest {
                ciphertexts: vec![format!("0x{}", hex::encode([7u8; 16]))],
            })
            .await
            .expect_err("ciphertext staging must reject store byte budget exhaustion");
        assert!(
            err.message().contains("byte budget"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn submit_proofs_rejects_store_byte_budget_exhaustion() {
        let (proof_bytes, binding_hash) = valid_native_tx_leaf_proof_and_binding(44);
        let tmpdir = TempDir::new().expect("temp dir");
        let rpc = DaRpc::new(
            Arc::new(Mutex::new(
                DaChunkStore::open(tmpdir.path(), 8, 16, 16).expect("chunk store"),
            )),
            Arc::new(Mutex::new(PendingCiphertextStore::new(8, 4096))),
            Arc::new(Mutex::new(PendingProofStore::new(
                8,
                proof_bytes.len().saturating_sub(1),
            ))),
            DaParams {
                chunk_size: 1024,
                sample_count: 4,
            },
            sc_rpc::DenyUnsafe::No,
        );

        let err = rpc
            .submit_proofs(SubmitProofsRequest {
                proofs: vec![SubmitProofsItem {
                    binding_hash: format!("0x{}", hex::encode(binding_hash)),
                    proof: format!("0x{}", hex::encode(proof_bytes)),
                }],
            })
            .await
            .expect_err("proof staging must reject store byte budget exhaustion");
        assert!(
            err.message().contains("byte budget"),
            "unexpected error: {err:?}"
        );
    }
}
