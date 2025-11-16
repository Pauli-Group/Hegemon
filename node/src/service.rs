use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use consensus::PowConsensus;
use consensus::proof::HashVerifier;
use consensus::types::{
    CoinbaseData, CoinbaseSource, ConsensusBlock, Transaction, compute_fee_commitment,
    compute_version_commitment,
};
use crypto::hashes::sha256;
use crypto::ml_dsa::MlDsaSecretKey;
use crypto::traits::{SigningKey, VerifyKey};
use network::{GossipHandle, GossipMessage, GossipRouter};
use parking_lot::Mutex;
use protocol_versioning::{DEFAULT_VERSION_BINDING, VersionBinding};
use tokio::sync::{broadcast, mpsc, watch};
use transaction_circuit::hashing::Felt;
use transaction_circuit::keys::{VerifyingKey, generate_keys};
use transaction_circuit::proof::{TransactionProof, verify};

use crate::codec::{deserialize_block, serialize_block};
use crate::config::NodeConfig;
use crate::error::{NodeError, NodeResult};
use crate::mempool::Mempool;
use crate::miner::{self, BlockTemplate};
use crate::storage::{ChainMeta, Storage};
use crate::telemetry::{Telemetry, TelemetrySnapshot};
use crate::transaction::{ValidatedTransaction, felt_to_bytes, proof_to_transaction};

const EVENT_CHANNEL_SIZE: usize = 256;
const BLOCK_BROADCAST_CAPACITY: usize = 8;

pub struct NodeHandle {
    pub service: Arc<NodeService>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl NodeHandle {
    pub async fn shutdown(self) {
        for handle in self.tasks {
            handle.abort();
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeEvent {
    Transaction { tx_id: [u8; 32] },
    Block { height: u64, hash: [u8; 32] },
    Telemetry(TelemetrySnapshot),
}

pub struct NodeService {
    config: NodeConfig,
    storage: Storage,
    consensus: Mutex<PowConsensus<HashVerifier>>,
    ledger: Mutex<LedgerState>,
    mempool: Mempool,
    verifying_keys: HashMap<VersionBinding, VerifyingKey>,
    miner_secret: MlDsaSecretKey,
    miner_id: [u8; 32],
    gossip: GossipHandle,
    telemetry: Telemetry,
    event_tx: broadcast::Sender<NodeEvent>,
    template_tx: watch::Sender<Option<BlockTemplate>>,
}

struct LedgerState {
    tree: state_merkle::CommitmentTree,
    nullifiers: consensus::nullifier::NullifierSet,
    state_root: [u8; 32],
    nullifier_root: [u8; 32],
    supply_digest: u128,
    best_hash: [u8; 32],
    height: u64,
    pow_bits: u32,
}

impl NodeService {
    pub fn start(config: NodeConfig, router: GossipRouter) -> NodeResult<NodeHandle> {
        let storage = Storage::open(&config.db_path)?;
        let gossip = router.handle();
        let miner_secret = config.miner_secret();
        let miner_id = sha256(&miner_secret.verify_key().to_bytes());
        let verifying_keys = build_verifying_keys(&config.supported_versions);
        let mut tree = state_merkle::CommitmentTree::new(config.note_tree_depth)
            .map_err(|_| NodeError::Invalid("invalid tree depth"))?;
        let commitments = storage.load_commitments()?;
        for value in commitments {
            let _ = tree.append(value);
        }
        let mut nullifiers = consensus::nullifier::NullifierSet::new();
        for nf in storage.load_nullifiers()? {
            let _ = nullifiers.insert(nf);
        }
        let meta = storage.load_meta()?.unwrap_or_else(|| ChainMeta {
            best_hash: [0u8; 32],
            height: 0,
            state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            supply_digest: 0,
            pow_bits: config.pow_bits,
        });
        let ledger = LedgerState {
            tree,
            nullifiers,
            state_root: meta.state_root,
            nullifier_root: meta.nullifier_root,
            supply_digest: meta.supply_digest,
            best_hash: meta.best_hash,
            height: meta.height,
            pow_bits: meta.pow_bits,
        };
        let miner_pubkeys = vec![miner_secret.verify_key()];
        let mut consensus =
            PowConsensus::new(miner_pubkeys, meta.state_root, HashVerifier::default());
        let mut persisted_blocks = storage.load_blocks()?;
        persisted_blocks.sort_by_key(|block| block.header.height);
        for block in persisted_blocks {
            let _ = consensus.apply_block(block);
        }
        let mempool = Mempool::new(config.mempool_max_txs);
        let telemetry = Telemetry::new();
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_SIZE);
        let (template_tx, template_rx) = watch::channel(None);
        let (solution_tx, mut solution_rx) = mpsc::channel(BLOCK_BROADCAST_CAPACITY);
        let service = Arc::new(NodeService {
            config: config.clone(),
            storage,
            consensus: Mutex::new(consensus),
            ledger: Mutex::new(ledger),
            mempool,
            verifying_keys,
            miner_secret,
            miner_id,
            gossip,
            telemetry: telemetry.clone(),
            event_tx,
            template_tx,
        });
        let miner_tasks = miner::spawn_miners(
            config.miner_workers,
            template_rx,
            solution_tx,
            telemetry.clone(),
        );
        let gossip_service = service.clone();
        let gossip_router = router.handle();
        let gossip_task = tokio::spawn(async move {
            gossip_service.run_gossip(gossip_router).await;
        });
        let miner_service = service.clone();
        let miner_task = tokio::spawn(async move {
            while let Some(block) = solution_rx.recv().await {
                let _ = miner_service.accept_block(block, true).await;
            }
        });
        let telemetry_service = service.clone();
        let telemetry_task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let snapshot = telemetry_service.telemetry.snapshot();
                let _ = telemetry_service
                    .event_tx
                    .send(NodeEvent::Telemetry(snapshot));
            }
        });
        service.publish_template().ok();
        let mut tasks = Vec::new();
        tasks.extend(miner_tasks);
        tasks.push(gossip_task);
        tasks.push(miner_task);
        tasks.push(telemetry_task);
        Ok(NodeHandle { service, tasks })
    }

    async fn run_gossip(&self, router: GossipHandle) {
        let mut rx = router.subscribe();
        while let Ok(message) = rx.recv().await {
            match message {
                GossipMessage::Transaction(data) => {
                    if let Ok(proof) = bincode::deserialize::<TransactionProof>(&data) {
                        let _ = self.validate_and_add_transaction(proof, false).await;
                    }
                }
                GossipMessage::Block(data) => {
                    if let Ok(block) = deserialize_block(&data) {
                        let _ = self.accept_block(block, false).await;
                    }
                }
                GossipMessage::Evidence(_) => {}
            }
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    pub fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        self.telemetry.snapshot()
    }

    pub fn note_status(&self) -> NoteStatus {
        let ledger = self.ledger.lock();
        NoteStatus {
            leaf_count: ledger.tree.len() as u64,
            depth: ledger.tree.depth() as u64,
            root: ledger.tree.root().as_int(),
        }
    }

    pub fn merkle_root(&self) -> Felt {
        self.ledger.lock().tree.root()
    }

    pub fn latest_meta(&self) -> ChainMeta {
        let ledger = self.ledger.lock();
        ChainMeta {
            best_hash: ledger.best_hash,
            height: ledger.height,
            state_root: ledger.state_root,
            nullifier_root: ledger.nullifier_root,
            supply_digest: ledger.supply_digest,
            pow_bits: ledger.pow_bits,
        }
    }

    pub async fn submit_transaction(&self, proof: TransactionProof) -> NodeResult<[u8; 32]> {
        let tx_id = self.validate_and_add_transaction(proof, true).await?;
        Ok(tx_id)
    }

    pub fn api_addr(&self) -> SocketAddr {
        self.config.api_addr
    }

    pub fn api_token(&self) -> &str {
        &self.config.api_token
    }

    async fn validate_and_add_transaction(
        &self,
        proof: TransactionProof,
        broadcast: bool,
    ) -> NodeResult<[u8; 32]> {
        let version = proof.version_binding();
        let verifying_key = self
            .verifying_keys
            .get(&version)
            .ok_or(NodeError::Invalid("unsupported transaction version"))?;
        verify(&proof, verifying_key)?;
        let ledger = self.ledger.lock();
        if !ledger
            .tree
            .root_history()
            .iter()
            .any(|root| *root == proof.public_inputs.merkle_root)
        {
            return Err(NodeError::Invalid("unknown merkle root"));
        }
        for felt in &proof.public_inputs.nullifiers {
            if felt.as_int() != 0 {
                let nf = felt_to_bytes(*felt);
                if ledger.nullifiers.contains(&nf) {
                    return Err(NodeError::Invalid("nullifier already spent"));
                }
            }
        }
        drop(ledger);
        let tx = proof_to_transaction(&proof, version);
        let nullifiers = tx.nullifiers.clone();
        let commitments = proof
            .public_inputs
            .commitments
            .iter()
            .copied()
            .filter(|value| value.as_int() != 0)
            .collect();
        let validated = ValidatedTransaction {
            id: tx.hash(),
            proof: proof.clone(),
            transaction: tx,
            fee: proof.public_inputs.native_fee,
            timestamp: Instant::now(),
            commitments,
            nullifiers,
        };
        self.mempool.insert(validated.clone())?;
        self.telemetry.set_mempool_depth(self.mempool.len());
        self.publish_template()?;
        let _ = self.event_tx.send(NodeEvent::Transaction {
            tx_id: validated.id,
        });
        if broadcast {
            let payload = bincode::serialize(&validated.proof)?;
            let _ = self.gossip.broadcast_transaction(payload);
        }
        Ok(validated.id)
    }

    fn publish_template(&self) -> NodeResult<()> {
        let entries = self
            .mempool
            .collect(self.config.template_tx_limit)
            .into_iter()
            .collect::<Vec<_>>();
        if entries.is_empty() {
            let _ = self.template_tx.send(None);
            self.telemetry.set_difficulty(0);
            return Ok(());
        }
        let ledger = self.ledger.lock();
        let parent_hash = ledger.best_hash;
        let parent_height = ledger.height;
        let base_state_root = ledger.state_root;
        let base_supply = ledger.supply_digest;
        let mut nullifier_set = ledger.nullifiers.clone();
        let pow_bits = ledger.pow_bits;
        drop(ledger);

        let mut transactions = Vec::new();
        let mut total_fees = 0u64;
        for entry in &entries {
            for nf in &entry.transaction.nullifiers {
                nullifier_set.insert(*nf)?;
            }
            transactions.push(entry.transaction.clone());
            total_fees = total_fees.saturating_add(entry.fee);
        }
        let coinbase = CoinbaseData {
            minted: consensus::reward::block_subsidy(parent_height + 1),
            fees: total_fees as i64,
            burns: 0,
            source: CoinbaseSource::TransactionIndex(0),
        };
        let supply =
            consensus::reward::update_supply_digest(base_supply, coinbase.net_native_delta())
                .ok_or(NodeError::Invalid("supply overflow"))?;
        let state_root = accumulate_state(base_state_root, &transactions);
        let nullifier_root = nullifier_set.commitment();
        let header = build_header(
            parent_hash,
            parent_height,
            state_root,
            nullifier_root,
            &transactions,
            supply,
            pow_bits,
            &self.miner_secret,
            self.miner_id,
        )?;
        self.telemetry
            .set_difficulty(header.pow.as_ref().map(|s| s.pow_bits).unwrap_or(0));
        let block = ConsensusBlock {
            header,
            transactions,
            coinbase: Some(coinbase),
        };
        let _ = self.template_tx.send(Some(BlockTemplate { block }));
        Ok(())
    }

    async fn accept_block(&self, block: ConsensusBlock, propagate: bool) -> NodeResult<()> {
        let hash = block.header.hash()?;
        let mut consensus = self.consensus.lock();
        consensus.apply_block(block.clone())?;
        drop(consensus);
        let mut ledger = self.ledger.lock();
        ledger.best_hash = hash;
        ledger.height = block.header.height;
        ledger.state_root = block.header.state_root;
        ledger.nullifier_root = block.header.nullifier_root;
        ledger.supply_digest = block.header.supply_digest;
        ledger.pow_bits = block
            .header
            .pow
            .as_ref()
            .map(|seal| seal.pow_bits)
            .unwrap_or(ledger.pow_bits);
        let mut commitment_index = ledger.tree.len() as u64;
        for tx in &block.transactions {
            for cm in &tx.commitments {
                if let Some(value) = commitment_to_felt(cm) {
                    let _ = ledger.tree.append(value);
                    self.storage.append_commitment(commitment_index, value)?;
                    commitment_index += 1;
                }
            }
            for nf in &tx.nullifiers {
                ledger.nullifiers.insert(*nf)?;
            }
        }
        drop(ledger);
        let recorded_nullifiers: Vec<[u8; 32]> = block
            .transactions
            .iter()
            .flat_map(|tx| tx.nullifiers.clone())
            .collect();
        self.storage.insert_block(hash, &block)?;
        self.storage.store_meta(&self.latest_meta())?;
        self.storage.record_nullifiers(&recorded_nullifiers)?;
        let pruned: Vec<[u8; 32]> = block.transactions.iter().map(|tx| tx.hash()).collect();
        self.mempool.prune(&pruned);
        self.telemetry.set_height(block.header.height);
        self.telemetry.set_mempool_depth(self.mempool.len());
        self.publish_template()?;
        let _ = self.event_tx.send(NodeEvent::Block {
            height: block.header.height,
            hash,
        });
        if propagate {
            let payload = serialize_block(&block)?;
            let _ = self.gossip.broadcast_block(payload);
        }
        Ok(())
    }
}

fn build_verifying_keys(versions: &[VersionBinding]) -> HashMap<VersionBinding, VerifyingKey> {
    let mut keys = HashMap::new();
    for version in versions {
        let key = VerifyingKey {
            max_inputs: transaction_circuit::constants::MAX_INPUTS,
            max_outputs: transaction_circuit::constants::MAX_OUTPUTS,
            balance_slots: transaction_circuit::constants::BALANCE_SLOTS,
        };
        keys.insert(*version, key);
    }
    if keys.is_empty() {
        let (_, vk) = generate_keys();
        keys.insert(DEFAULT_VERSION_BINDING, vk);
    }
    keys
}

fn build_header(
    parent_hash: [u8; 32],
    parent_height: u64,
    state_root: [u8; 32],
    nullifier_root: [u8; 32],
    transactions: &[Transaction],
    supply_digest: u128,
    pow_bits: u32,
    secret: &MlDsaSecretKey,
    miner_id: [u8; 32],
) -> NodeResult<consensus::header::BlockHeader> {
    use consensus::header::{BlockHeader, PowSeal};
    let proof_commitment = consensus::types::compute_proof_commitment(transactions);
    let version_commitment = compute_version_commitment(transactions);
    let fee_commitment = compute_fee_commitment(transactions);
    let tx_count = transactions.len() as u32;
    let timestamp_ms = current_time_ms();
    let mut header = BlockHeader {
        version: 1,
        height: parent_height + 1,
        view: 0,
        timestamp_ms,
        parent_hash,
        state_root,
        nullifier_root,
        proof_commitment,
        version_commitment,
        tx_count,
        fee_commitment,
        supply_digest,
        validator_set_commitment: miner_id,
        signature_aggregate: Vec::new(),
        signature_bitmap: None,
        pow: Some(PowSeal {
            nonce: [0u8; 32],
            pow_bits,
        }),
    };
    let signing_hash = header.signing_hash()?;
    let signature = secret.sign(&signing_hash);
    header.signature_aggregate = signature.to_bytes().to_vec();
    Ok(header)
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn accumulate_state(mut root: [u8; 32], transactions: &[Transaction]) -> [u8; 32] {
    for tx in transactions {
        if tx.commitments.is_empty() {
            continue;
        }
        let mut data = Vec::with_capacity(32 + tx.commitments.len() * 32);
        data.extend_from_slice(&root);
        for cm in &tx.commitments {
            data.extend_from_slice(cm);
        }
        root = sha256(&data);
    }
    root
}

fn commitment_to_felt(bytes: &[u8; 32]) -> Option<Felt> {
    if bytes.iter().all(|b| *b == 0) {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[24..]);
    Some(Felt::new(u64::from_be_bytes(buf)))
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct NoteStatus {
    pub leaf_count: u64,
    pub depth: u64,
    pub root: u64,
}
