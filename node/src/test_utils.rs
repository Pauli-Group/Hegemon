use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use consensus::header::{BlockHeader, PowSeal};
use consensus::reward::INITIAL_SUBSIDY;
use consensus::types::{da_root, ConsensusBlock, DaParams};
use crypto::hashes::{blake3_384, sha256};
use crypto::traits::{SigningKey, VerifyKey};
use parking_lot::Mutex;
use wallet::rpc::TransactionBundle;

use crate::config::NodeConfig;
use crate::error::NodeResult;
use crate::storage::{self, StorageMeta, StorageState};

const DEFAULT_DA_CHUNK_SIZE: u32 = 65536;
const DEFAULT_DA_SAMPLE_COUNT: u32 = 80;

#[derive(Clone, Copy, Debug)]
pub enum MinerAction {
    Start,
    Stop,
}

#[derive(Clone, Debug, Default)]
pub struct MinerStatus {
    pub is_running: bool,
    pub thread_count: u32,
    pub target_hash_rate: u64,
}

#[derive(Clone, Debug)]
pub struct ConsensusStatus {
    pub height: u64,
    pub best_hash: [u8; 32],
    pub pow_bits: u32,
    pub version_commitment: [u8; 48],
    pub proof_commitment: Vec<u8>,
}

#[derive(Clone)]
pub struct LegacyNode {
    state: Arc<Mutex<LegacyNodeState>>,
}

#[derive(Clone)]
struct LegacyNodeState {
    config: NodeConfig,
    blocks: Vec<ConsensusBlock>,
    mempool: Vec<[u8; 32]>,
    mining_status: MinerStatus,
    height: u64,
    best_hash: [u8; 32],
    version_commitment: [u8; 48],
    proof_commitment: [u8; 48],
    supply_digest: u128,
    merkle_root: [u8; 48],
}

pub struct NodeService {
    pub service: LegacyNode,
}

pub type NodeHandle = NodeService;

impl NodeService {
    pub fn start(config: NodeConfig, _router: network::GossipRouter) -> NodeResult<Self> {
        Ok(Self {
            service: LegacyNode::new(config),
        })
    }

    pub async fn shutdown(&self) -> NodeResult<()> {
        Ok(())
    }
}

impl LegacyNode {
    pub fn new(config: NodeConfig) -> Self {
        let stored = storage::load_state(&config.db_path);
        let (height, best_hash) = stored
            .meta
            .as_ref()
            .map(|meta| (meta.height, meta.best_hash))
            .unwrap_or((0, [0u8; 32]));
        let supply_digest = stored
            .meta
            .as_ref()
            .map(|meta| meta.supply_digest)
            .unwrap_or(0);
        let (version_commitment, proof_commitment) = stored
            .blocks
            .last()
            .map(|block| {
                (
                    block.header.version_commitment,
                    block.header.proof_commitment,
                )
            })
            .unwrap_or(([0u8; 48], [0u8; 48]));

        Self {
            state: Arc::new(Mutex::new(LegacyNodeState {
                config,
                blocks: stored.blocks,
                mempool: Vec::new(),
                mining_status: MinerStatus::default(),
                height,
                best_hash,
                version_commitment,
                proof_commitment,
                supply_digest,
                merkle_root: [0u8; 48],
            })),
        }
    }

    pub fn consensus_status(&self) -> ConsensusStatus {
        let state = self.state.lock();
        ConsensusStatus {
            height: state.height,
            best_hash: state.best_hash,
            pow_bits: state.config.pow_bits,
            version_commitment: state.version_commitment,
            proof_commitment: state.proof_commitment.to_vec(),
        }
    }

    pub fn api_addr(&self) -> std::net::SocketAddr {
        self.state.lock().config.api_addr
    }

    pub fn merkle_root(&self) -> [u8; 48] {
        self.state.lock().merkle_root
    }

    pub fn miner_status(&self) -> MinerStatus {
        self.state.lock().mining_status.clone()
    }

    pub async fn seal_pending_block(&self) -> NodeResult<Option<ConsensusBlock>> {
        let mut state = self.state.lock();
        let height = state.height + 1;
        state.supply_digest = state.supply_digest.saturating_add(INITIAL_SUBSIDY as u128);
        let supply_digest = state.supply_digest;
        let da_params = DaParams {
            chunk_size: DEFAULT_DA_CHUNK_SIZE,
            sample_count: DEFAULT_DA_SAMPLE_COUNT,
        };
        let da_root = da_root(&[], da_params).expect("da root");
        let header = BlockHeader {
            version: 1,
            height,
            view: 0,
            timestamp_ms: current_time_ms(),
            parent_hash: state.best_hash,
            state_root: [0u8; 48],
            nullifier_root: [0u8; 48],
            proof_commitment: state.proof_commitment,
            da_root,
            da_params,
            version_commitment: state.version_commitment,
            tx_count: 0,
            fee_commitment: [0u8; 48],
            supply_digest,
            validator_set_commitment: miner_id(&state.config),
            signature_aggregate: Vec::new(),
            signature_bitmap: None,
            pow: Some(PowSeal {
                nonce: [0u8; 32],
                pow_bits: state.config.pow_bits,
            }),
        };
        let block = ConsensusBlock {
            header,
            transactions: Vec::new(),
            coinbase: None,
            commitment_proof: None,
            aggregation_proof: None,
            transaction_proofs: None,
        };
        let best_hash = block.header.hash()?;
        state.height = height;
        state.best_hash = best_hash;
        state.blocks.push(block.clone());
        Ok(Some(block))
    }

    pub fn miner_ids(&self) -> Vec<[u8; 48]> {
        let state = self.state.lock();
        vec![miner_id(&state.config)]
    }

    pub async fn apply_block_for_test(&self, block: ConsensusBlock) -> NodeResult<()> {
        let mut state = self.state.lock();
        let best_hash = block.header.hash()?;
        state.height = block.header.height;
        state.best_hash = best_hash;
        state.version_commitment = block.header.version_commitment;
        state.proof_commitment = block.header.proof_commitment;
        state.supply_digest = block.header.supply_digest;
        state.blocks.push(block);
        Ok(())
    }

    pub fn latest_meta(&self) -> StorageMeta {
        let state = self.state.lock();
        StorageMeta {
            height: state.height,
            best_hash: state.best_hash,
            supply_digest: state.supply_digest,
        }
    }

    pub fn storage_meta(&self) -> NodeResult<StorageMeta> {
        Ok(self.latest_meta())
    }

    pub fn block_count(&self) -> NodeResult<usize> {
        Ok(self.state.lock().blocks.len())
    }

    pub fn flush_storage(&self) -> NodeResult<()> {
        let state = self.state.lock();
        let snapshot = StorageState {
            blocks: state.blocks.clone(),
            meta: Some(StorageMeta {
                height: state.height,
                best_hash: state.best_hash,
                supply_digest: state.supply_digest,
            }),
        };
        storage::store_state(&state.config.db_path, snapshot);
        Ok(())
    }

    pub fn config(&self) -> NodeConfig {
        self.state.lock().config.clone()
    }

    pub fn control_miner(
        &self,
        action: MinerAction,
        target_hash_rate: Option<u64>,
        threads: Option<u32>,
    ) -> NodeResult<MinerStatus> {
        let mut state = self.state.lock();
        match action {
            MinerAction::Start => {
                state.mining_status.is_running = true;
                state.mining_status.thread_count = threads.unwrap_or(1);
                state.mining_status.target_hash_rate = target_hash_rate.unwrap_or(0);
            }
            MinerAction::Stop => {
                state.mining_status.is_running = false;
                state.mining_status.thread_count = 0;
                state.mining_status.target_hash_rate = 0;
            }
        }
        Ok(state.mining_status.clone())
    }

    pub async fn submit_transaction(&self, bundle: TransactionBundle) -> NodeResult<[u8; 32]> {
        let mut data = Vec::new();
        data.extend_from_slice(&bundle.anchor);
        for nf in &bundle.nullifiers {
            data.extend_from_slice(nf);
        }
        for cm in &bundle.commitments {
            data.extend_from_slice(cm);
        }
        data.extend_from_slice(&bundle.fee.to_le_bytes());
        data.extend_from_slice(&bundle.value_balance.to_le_bytes());
        let tx_id = sha256(&data);
        self.state.lock().mempool.push(tx_id);
        Ok(tx_id)
    }

    pub fn mempool_len(&self) -> usize {
        self.state.lock().mempool.len()
    }

    pub fn mempool_ids(&self) -> Vec<[u8; 32]> {
        self.state.lock().mempool.clone()
    }
}

fn miner_id(config: &NodeConfig) -> [u8; 48] {
    blake3_384(&config.miner_secret().verify_key().to_bytes())
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
