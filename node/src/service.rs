use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::proof::HashVerifier;
use consensus::types::{
    BalanceTag, CoinbaseData, CoinbaseSource, ConsensusBlock, Transaction, compute_fee_commitment,
    compute_proof_commitment, compute_version_commitment,
};
use consensus::{BlockOrigin, PowConsensus, import_pow_block};
use crypto::hashes::sha256;
use crypto::ml_dsa::MlDsaSecretKey;
use crypto::traits::{SigningKey, VerifyKey};
use network::{GossipHandle, GossipMessage, GossipRouter, PeerStore, PeerStoreConfig};
use parking_lot::Mutex;
use protocol_versioning::{DEFAULT_VERSION_BINDING, VersionBinding};
use rand::rngs::OsRng;
use tokio::sync::{broadcast, mpsc, watch};
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing::Felt;
use transaction_circuit::keys::{VerifyingKey, generate_keys};
use transaction_circuit::proof::verify;

use crate::bootstrap::PeerBundle;
use crate::codec::{deserialize_block, serialize_block};
use crate::config::NodeConfig;
use crate::error::{NodeError, NodeResult};
use crate::mempool::Mempool;
use crate::miner::{self, BlockTemplate};
use crate::storage::{ChainMeta, Storage};
use crate::sync::SyncService;
use crate::telemetry::{Telemetry, TelemetryPosture, TelemetrySnapshot};
use crate::transaction::{ValidatedTransaction, felt_to_bytes, proof_to_transaction};
use serde_bytes::ByteBuf;
use wallet::TransactionBundle;
use wallet::address::ShieldedAddress;
use wallet::notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};

const EVENT_CHANNEL_SIZE: usize = 256;
const BLOCK_BROADCAST_CAPACITY: usize = 8;

pub struct NodeHandle {
    pub service: Arc<NodeService>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl NodeHandle {
    pub async fn shutdown(self) -> NodeResult<()> {
        for handle in &self.tasks {
            handle.abort();
        }

        for handle in self.tasks {
            if let Err(err) = handle.await {
                if err.is_cancelled() {
                    tracing::info!("node task cancelled during shutdown");
                } else {
                    tracing::warn!(?err, "node task did not shut down cleanly");
                }
            }
        }

        let service = Arc::try_unwrap(self.service).map_err(|service| {
            let strong_count = Arc::strong_count(&service);
            tracing::warn!(
                strong_count = strong_count,
                "node service still referenced during shutdown"
            );
            NodeError::Invalid("node service still referenced during shutdown")
        })?;

        match service.into_storage().close() {
            Ok(()) => {
                tracing::info!("node storage closed successfully");
                Ok(())
            }
            Err(err) => {
                tracing::warn!(?err, "failed to close node storage");
                Err(err)
            }
        }
    }

    pub fn spawn_sync(&self, protocol: network::ProtocolHandle) -> tokio::task::JoinHandle<()> {
        SyncService::new(self.service.clone(), protocol).spawn()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeEvent {
    Transaction { tx_id: [u8; 32] },
    Block { height: u64, hash: [u8; 32] },
    Telemetry(TelemetrySnapshot),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinerAction {
    Start,
    Stop,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MinerStatus {
    pub metrics: TelemetrySnapshot,
    pub is_running: bool,
    pub target_hash_rate: u64,
    pub thread_count: usize,
    pub last_updated: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ConsensusStatus {
    pub height: u64,
    pub best_hash: [u8; 32],
    pub pow_bits: u32,
    pub version_commitment: [u8; 32],
    pub proof_commitment: Vec<u8>,
    pub telemetry: TelemetrySnapshot,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct StorageFootprint {
    pub height: u64,
    pub blocks: u64,
    pub notes: u64,
    pub nullifiers: u64,
    pub ciphertexts: u64,
    pub db_bytes: u64,
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
    miner_payout_address: ShieldedAddress,
    miner_running: Arc<AtomicBool>,
    target_hash_rate: Arc<AtomicU64>,
    thread_count: Arc<AtomicUsize>,
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
    version_commitment: [u8; 32],
    proof_commitment: [u8; 48],
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
        let miner_payout_address = config.miner_payout_address.clone();
        let verifying_keys = build_verifying_keys(&config.supported_versions);

        // Load persisted state and detect corruption/mismatch.
        let mut tree = state_merkle::CommitmentTree::new(config.note_tree_depth)
            .map_err(|_| NodeError::Invalid("invalid tree depth"))?;
        let mut nullifiers = consensus::nullifier::NullifierSet::new();

        let mut persisted_blocks = storage.load_blocks()?;
        persisted_blocks.sort_by_key(|block| block.header.height);
        let genesis_pow_bits = persisted_blocks
            .first()
            .and_then(|block| block.header.pow.as_ref().map(|seal| seal.pow_bits))
            .unwrap_or(config.pow_bits);
        let mut meta = storage.load_meta()?.unwrap_or(ChainMeta {
            best_hash: [0u8; 32],
            height: 0,
            state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            supply_digest: 0,
            pow_bits: genesis_pow_bits,
        });
        let persisted_height = persisted_blocks
            .last()
            .map(|b| b.header.height)
            .unwrap_or(0);
        let recorded_height = persisted_blocks
            .iter()
            .find_map(|block| match block.header.hash() {
                Ok(hash) if hash == meta.best_hash => Some(block.header.height),
                _ => None,
            });
        let expected_height = recorded_height.unwrap_or(persisted_height);
        if meta.height != expected_height {
            tracing::warn!(
                meta_height = meta.height,
                persisted_height,
                recorded_height,
                "ledger metadata height mismatch; resetting chain state to genesis"
            );
            storage.reset()?;
            meta.height = 0;
            meta.best_hash = [0u8; 32];
            meta.state_root = [0u8; 32];
            meta.nullifier_root = [0u8; 32];
            meta.supply_digest = 0;
            meta.pow_bits = genesis_pow_bits;
            persisted_blocks.clear();
        }

        let commitments = storage.load_commitments()?;
        for value in commitments {
            let _ = tree.append(value);
        }
        for nf in storage.load_nullifiers()? {
            let _ = nullifiers.insert(nf);
        }

        let mut last_version_commitment = [0u8; 32];
        let mut last_proof_commitment = [0u8; 48];
        let pow_bits = if meta.height == 0 {
            genesis_pow_bits
        } else {
            meta.pow_bits
        };
        let ledger = LedgerState {
            tree,
            nullifiers,
            state_root: meta.state_root,
            nullifier_root: meta.nullifier_root,
            supply_digest: meta.supply_digest,
            version_commitment: last_version_commitment,
            proof_commitment: last_proof_commitment,
            best_hash: meta.best_hash,
            height: meta.height,
            pow_bits,
        };

        let miner_pubkeys = vec![miner_secret.verify_key()];
        let mut consensus = PowConsensus::with_genesis_pow_bits(
            miner_pubkeys.clone(),
            meta.state_root,
            HashVerifier,
            genesis_pow_bits,
        );
        for block in persisted_blocks {
            last_version_commitment = compute_version_commitment(&block.transactions);
            last_proof_commitment = compute_proof_commitment(&block.transactions);
            let _ = consensus.apply_block(block);
        }
        let mut ledger = ledger;
        ledger.version_commitment = last_version_commitment;
        ledger.proof_commitment = last_proof_commitment;
        // If the recorded best hash/height isn't known to consensus, reset to genesis.
        let fork_check = consensus.expected_bits_for_block(meta.best_hash, meta.height + 1);
        if let Err(err) = fork_check {
            tracing::warn!(
                ?err,
                best_hash = ?meta.best_hash,
                height = meta.height,
                "consensus state missing recorded parent"
            );
            #[cfg(not(feature = "test-utils"))]
            {
                storage.reset()?;
                meta.height = 0;
                meta.best_hash = [0u8; 32];
                meta.state_root = [0u8; 32];
                meta.nullifier_root = [0u8; 32];
                meta.supply_digest = 0;
                meta.pow_bits = genesis_pow_bits;
                consensus = PowConsensus::with_genesis_pow_bits(
                    miner_pubkeys.clone(),
                    meta.state_root,
                    HashVerifier,
                    genesis_pow_bits,
                );
                // Wipe in-memory ledger state to match the reset storage/consensus view.
                ledger = LedgerState {
                    tree: state_merkle::CommitmentTree::new(config.note_tree_depth)
                        .map_err(|_| NodeError::Invalid("invalid tree depth"))?,
                    nullifiers: consensus::nullifier::NullifierSet::new(),
                    state_root: meta.state_root,
                    nullifier_root: meta.nullifier_root,
                    supply_digest: meta.supply_digest,
                    version_commitment: [0u8; 32],
                    proof_commitment: [0u8; 48],
                    best_hash: meta.best_hash,
                    height: meta.height,
                    pow_bits: meta.pow_bits,
                };
            }
        }
        let mempool = Mempool::new(config.mempool_max_txs, config.mempool_max_weight);
        let telemetry = Telemetry::new();
        telemetry.set_privacy_posture(config.telemetry.clone());
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_SIZE);
        let (template_tx, template_rx) = watch::channel(None);
        let (solution_tx, mut solution_rx) = mpsc::channel(BLOCK_BROADCAST_CAPACITY);

        let miner_running = Arc::new(AtomicBool::new(true));
        let target_hash_rate = Arc::new(AtomicU64::new(0));
        let thread_count = Arc::new(AtomicUsize::new(config.miner_workers));

        let service = Arc::new(NodeService {
            config: config.clone(),
            storage,
            consensus: Mutex::new(consensus),
            ledger: Mutex::new(ledger),
            mempool,
            verifying_keys,
            miner_secret,
            miner_id,
            miner_payout_address,
            miner_running: miner_running.clone(),
            target_hash_rate: target_hash_rate.clone(),
            thread_count: thread_count.clone(),
            gossip,
            telemetry: telemetry.clone(),
            event_tx,
            template_tx,
        });

        service.rehydrate_mempool()?;
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
                if let Err(err) = miner_service
                    .accept_block(block, BlockOrigin::Own, true)
                    .await
                {
                    eprintln!("miner produced invalid block: {err}");
                    // Unblock miners: refresh the template after a rejected block.
                    let _ = miner_service.publish_template();
                }
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

    fn into_storage(self) -> Storage {
        self.storage
    }

    pub fn spawn_sync(
        self: &Arc<Self>,
        protocol: network::ProtocolHandle,
    ) -> tokio::task::JoinHandle<()> {
        SyncService::new(self.clone(), protocol).spawn()
    }

    pub fn capture_peer_bundle(&self) -> NodeResult<PeerBundle> {
        let mut blocks = self.storage.load_blocks()?;
        blocks.sort_by_key(|block| block.header.height);
        let genesis_block = blocks
            .into_iter()
            .find(|block| block.header.height == 0)
            .map(|block| serialize_block(&block))
            .transpose()?
            .map(ByteBuf::from);

        let mut peer_store =
            PeerStore::new(PeerStoreConfig::with_path(&self.config.peer_store_path));
        peer_store.load()?;
        let peers = peer_store
            .addresses()
            .into_iter()
            .map(|addr| addr.to_string())
            .collect();

        Ok(PeerBundle {
            chain: self.config.chain_profile,
            pow_bits: self.config.pow_bits,
            genesis_block,
            peers,
        })
    }

    pub async fn import_sync_block(&self, block: ConsensusBlock) -> NodeResult<()> {
        self.accept_block(block, BlockOrigin::NetworkInitialSync, false)
            .await
    }

    async fn run_gossip(&self, router: GossipHandle) {
        let mut rx = router.subscribe();
        while let Ok(message) = rx.recv().await {
            match message {
                GossipMessage::Transaction(data) => {
                    if let Ok(bundle) = bincode::deserialize::<TransactionBundle>(&data) {
                        let _ = self.validate_and_add_transaction(bundle, false).await;
                    }
                }
                GossipMessage::Block(data) => {
                    if let Ok(block) = deserialize_block(&data) {
                        let _ = self
                            .accept_block(block, BlockOrigin::NetworkBroadcast, false)
                            .await;
                    }
                }
                GossipMessage::Evidence(_) => {}
                GossipMessage::Addresses(_) => {}
            }
        }
    }

    pub fn telemetry_snapshot(&self) -> TelemetrySnapshot {
        self.telemetry.snapshot()
    }

    pub fn update_privacy_posture(&self, posture: TelemetryPosture) {
        self.telemetry.set_privacy_posture(posture);
    }

    pub(crate) fn storage(&self) -> &Storage {
        &self.storage
    }

    fn rehydrate_mempool(&self) -> NodeResult<()> {
        let mut failures = Vec::new();
        for (id, bundle) in self.storage.load_mempool()? {
            match self.validate_bundle(&bundle) {
                Ok(validated) => {
                    if let Err(err) = self.insert_validated_transaction(validated, false, false) {
                        tracing::warn!(?err, tx_id = %hex::encode(id), "failed to reinsert persisted mempool tx");
                        failures.push(id);
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, tx_id = %hex::encode(id), "dropping invalid persisted mempool tx");
                    failures.push(id);
                }
            }
        }
        if !failures.is_empty() {
            self.storage.remove_mempool_bundles(&failures)?;
        }
        self.telemetry.set_mempool_depth(self.mempool.len());
        self.publish_template()?;
        Ok(())
    }

    pub fn consensus_status(&self) -> ConsensusStatus {
        let ledger = self.ledger.lock();
        ConsensusStatus {
            height: ledger.height,
            best_hash: ledger.best_hash,
            pow_bits: ledger.pow_bits,
            version_commitment: ledger.version_commitment,
            proof_commitment: ledger.proof_commitment.to_vec(),
            telemetry: self.telemetry.snapshot(),
        }
    }

    #[cfg(feature = "test-utils")]
    pub fn mempool_len(&self) -> usize {
        self.mempool.len()
    }

    #[cfg(feature = "test-utils")]
    pub fn mempool_ids(&self) -> Vec<[u8; 32]> {
        self.mempool.ids()
    }

    #[cfg(feature = "test-utils")]
    pub fn flush_storage(&self) -> NodeResult<()> {
        self.storage.flush()
    }

    #[cfg(feature = "test-utils")]
    pub fn storage_meta(&self) -> NodeResult<ChainMeta> {
        self.storage
            .load_meta()?
            .ok_or(NodeError::Invalid("missing chain metadata"))
    }

    #[cfg(feature = "test-utils")]
    pub fn block_count(&self) -> NodeResult<usize> {
        Ok(self.storage.load_blocks()?.len())
    }

    pub fn miner_status(&self) -> MinerStatus {
        MinerStatus {
            metrics: self.telemetry.snapshot(),
            is_running: self.miner_running.load(Ordering::Relaxed),
            target_hash_rate: self.target_hash_rate.load(Ordering::Relaxed),
            thread_count: self.thread_count.load(Ordering::Relaxed),
            last_updated: current_time_ms(),
        }
    }

    pub fn miner_ids(&self) -> Vec<[u8; 32]> {
        let consensus = self.consensus.lock();
        consensus.miner_ids()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    pub fn control_miner(
        &self,
        action: MinerAction,
        target_hash_rate: Option<u64>,
        thread_count: Option<usize>,
    ) -> NodeResult<MinerStatus> {
        if let Some(target) = target_hash_rate {
            self.target_hash_rate.store(target, Ordering::Relaxed);
        }
        if let Some(count) = thread_count {
            self.thread_count.store(count, Ordering::Relaxed);
        }
        match action {
            MinerAction::Start => {
                self.miner_running.store(true, Ordering::Relaxed);
                self.publish_template().ok();
            }
            MinerAction::Stop => {
                self.miner_running.store(false, Ordering::Relaxed);
                let _ = self.template_tx.send(None);
                self.telemetry.set_difficulty(0);
            }
        }
        Ok(self.miner_status())
    }

    pub fn note_status(&self) -> NoteStatus {
        let ledger = self.ledger.lock();
        NoteStatus {
            leaf_count: ledger.tree.len() as u64,
            depth: ledger.tree.depth() as u64,
            root: ledger.tree.root().as_int(),
            next_index: ledger.tree.len() as u64,
        }
    }

    pub fn commitment_slice(&self, start: u64, limit: usize) -> NodeResult<Vec<(u64, Felt)>> {
        self.storage.load_commitments_range(start, limit)
    }

    pub fn ciphertext_slice(&self, start: u64, limit: usize) -> NodeResult<Vec<(u64, Vec<u8>)>> {
        self.storage.load_ciphertexts(start, limit)
    }

    pub fn nullifier_list(&self) -> NodeResult<Vec<[u8; 32]>> {
        self.storage.load_nullifiers()
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

    pub fn storage_footprint(&self) -> NodeResult<StorageFootprint> {
        let ledger = self.ledger.lock();
        let stats = self.storage.stats();
        let db_bytes = dir_size(&self.config.db_path)?;
        Ok(StorageFootprint {
            height: ledger.height,
            blocks: stats.blocks as u64,
            notes: stats.notes as u64,
            nullifiers: stats.nullifiers as u64,
            ciphertexts: stats.ciphertexts as u64,
            db_bytes,
        })
    }

    pub async fn submit_transaction(&self, bundle: TransactionBundle) -> NodeResult<[u8; 32]> {
        let tx_id = self.validate_and_add_transaction(bundle, true).await?;
        Ok(tx_id)
    }

    pub fn api_addr(&self) -> SocketAddr {
        self.config.api_addr
    }

    pub fn api_token(&self) -> &str {
        &self.config.api_token
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    async fn validate_and_add_transaction(
        &self,
        bundle: TransactionBundle,
        broadcast: bool,
    ) -> NodeResult<[u8; 32]> {
        let validated = self.validate_bundle(&bundle)?;
        self.insert_validated_transaction(validated, broadcast, true)
    }

    fn validate_bundle(&self, bundle: &TransactionBundle) -> NodeResult<ValidatedTransaction> {
        let proof = bundle.proof.clone();
        let ciphertexts = bundle.ciphertexts.clone();
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
            .contains(&proof.public_inputs.merkle_root)
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
        let commitments: Vec<_> = proof
            .public_inputs
            .commitments
            .iter()
            .copied()
            .filter(|value| value.as_int() != 0)
            .collect();
        if ciphertexts.len() != commitments.len() {
            return Err(NodeError::Invalid("ciphertext count mismatch"));
        }
        let tx = proof_to_transaction(&proof, version, ciphertexts.clone());
        let nullifiers = tx.nullifiers.clone();
        let validated = ValidatedTransaction {
            id: tx.hash(),
            proof: proof.clone(),
            transaction: tx,
            fee: proof.public_inputs.native_fee,
            timestamp: Instant::now(),
            commitments,
            nullifiers,
            ciphertexts,
        };
        let weight = validated.weight();
        let min_fee = (self.config.min_tx_fee_per_weight as u128).saturating_mul(weight as u128);
        if (validated.fee as u128) < min_fee {
            return Err(NodeError::Invalid("fee below minimum rate"));
        }
        Ok(validated)
    }

    fn insert_validated_transaction(
        &self,
        validated: ValidatedTransaction,
        broadcast: bool,
        persist: bool,
    ) -> NodeResult<[u8; 32]> {
        let weight = validated.weight();
        self.mempool.insert(validated.clone(), weight)?;
        if persist {
            let bundle = TransactionBundle {
                proof: validated.proof.clone(),
                ciphertexts: validated.ciphertexts.clone(),
            };
            self.storage.record_mempool_bundle(validated.id, &bundle)?;
        }
        self.telemetry.set_mempool_depth(self.mempool.len());
        self.publish_template()?;
        let _ = self.event_tx.send(NodeEvent::Transaction {
            tx_id: validated.id,
        });
        if broadcast {
            let payload = bincode::serialize(&TransactionBundle {
                proof: validated.proof.clone(),
                ciphertexts: validated.ciphertexts.clone(),
            })?;
            let _ = self.gossip.broadcast_transaction(payload);
        }
        Ok(validated.id)
    }

    fn publish_template(&self) -> NodeResult<()> {
        if !self.miner_running.load(Ordering::Relaxed) {
            let _ = self.template_tx.send(None);
            self.telemetry.set_difficulty(0);
            return Ok(());
        }
        match self.assemble_pending_block() {
            Ok(Some(block)) => {
                let bits = block.header.pow.as_ref().map(|s| s.pow_bits).unwrap_or(0);
                self.telemetry.set_difficulty(bits);
                let _ = self.template_tx.send(Some(BlockTemplate { block }));
            }
            Ok(None) => {
                let _ = self.template_tx.send(None);
                self.telemetry.set_difficulty(0);
            }
            Err(err) => {
                // Don't stall miners on template errors; fall back to a best-effort template.
                tracing::warn!(
                    "assemble_pending_block failed, falling back to default template: {}",
                    err
                );

                // If the error is a ForkChoice violation (unknown parent), force_template will also fail validation.
                // In this case, we should not produce a template to avoid spamming invalid blocks.
                if let NodeError::Consensus(consensus::ConsensusError::ForkChoice(_)) = &err {
                    let _ = self.template_tx.send(None);
                    self.telemetry.set_difficulty(0);
                    return Ok(());
                }

                if let Ok(block) = self.force_template() {
                    let bits = block.header.pow.as_ref().map(|s| s.pow_bits).unwrap_or(0);
                    self.telemetry.set_difficulty(bits);
                    let _ = self.template_tx.send(Some(BlockTemplate { block }));
                } else {
                    let _ = self.template_tx.send(None);
                    self.telemetry.set_difficulty(0);
                }
            }
        }
        Ok(())
    }

    fn build_coinbase_transaction(&self, amount: u64) -> NodeResult<Option<Transaction>> {
        if amount == 0 {
            return Ok(None);
        }
        let mut rng = OsRng;
        let memo = MemoPlaintext::new(b"coinbase".to_vec());
        let note = NotePlaintext::random(amount, NATIVE_ASSET_ID, memo, &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&self.miner_payout_address, &note, &mut rng)?;
        let note_data = note.to_note_data(self.miner_payout_address.pk_recipient);
        let commitment_felt = note_data.commitment();
        let commitment = felt_to_bytes(commitment_felt);
        let ciphertext_bytes = bincode::serialize(&ciphertext)?;
        let tx = Transaction::new(
            Vec::new(),
            vec![commitment],
            [0u8; 32],
            DEFAULT_VERSION_BINDING,
            vec![ciphertext_bytes],
        );
        Ok(Some(tx))
    }

    fn assemble_pending_block(&self) -> NodeResult<Option<ConsensusBlock>> {
        let entries = self
            .mempool
            .collect(self.config.template_tx_limit, self.config.max_block_weight)
            .into_iter()
            .collect::<Vec<_>>();
        let ledger = self.ledger.lock();
        let parent_hash = ledger.best_hash;
        // Force an unknown parent to reproduce the error
        // let parent_hash = [1u8; 32];
        let parent_height = ledger.height;
        let base_state_root = ledger.state_root;
        let base_supply = ledger.supply_digest;
        let mut nullifier_set = ledger.nullifiers.clone();
        let pow_bits = {
            let consensus = self.consensus.lock();
            consensus.expected_bits_for_block(parent_hash, parent_height + 1)?
        };
        drop(ledger);

        let mut user_transactions = Vec::new();
        let mut total_fees = 0u64;
        for entry in &entries {
            for nf in &entry.transaction.transaction.nullifiers {
                nullifier_set.insert(*nf)?;
            }
            user_transactions.push(entry.transaction.transaction.clone());
            total_fees = total_fees.saturating_add(entry.transaction.fee);
        }
        let minted = consensus::reward::block_subsidy(parent_height + 1);
        let payout_amount = minted.saturating_add(total_fees);
        let mut transactions = Vec::new();
        if let Some(cb_tx) = self.build_coinbase_transaction(payout_amount)? {
            transactions.push(cb_tx);
        }
        transactions.extend(user_transactions);
        let coinbase_source = if transactions.is_empty() {
            CoinbaseSource::BalanceTag(BalanceTag::default())
        } else {
            CoinbaseSource::TransactionIndex(0)
        };
        let coinbase = CoinbaseData {
            minted,
            fees: total_fees as i64,
            burns: 0,
            source: coinbase_source,
        };
        let supply =
            consensus::reward::update_supply_digest(base_supply, coinbase.net_native_delta())
                .ok_or(NodeError::Invalid("supply overflow"))?;
        let state_root = accumulate_state(base_state_root, &transactions);
        let nullifier_root = nullifier_set.commitment();
        let header_context = HeaderContext {
            parent_hash,
            parent_height,
            state_root,
            nullifier_root,
            supply_digest: supply,
            pow_bits,
            miner_id: self.miner_id,
        };
        let header = build_header(&header_context, &transactions, &self.miner_secret)?;
        Ok(Some(ConsensusBlock {
            header,
            transactions,
            coinbase: Some(coinbase),
        }))
    }

    /// Build a template even if normal assembly fails (e.g., during dev bring-up).
    fn force_template(&self) -> NodeResult<ConsensusBlock> {
        let ledger = self.ledger.lock();
        let parent_hash = ledger.best_hash;
        let parent_height = ledger.height;
        let state_root = ledger.state_root;
        let nullifier_root = ledger.nullifier_root;
        let base_supply = ledger.supply_digest;
        let pow_bits = ledger.pow_bits.max(DEFAULT_GENESIS_POW_BITS);
        drop(ledger);

        let minted = consensus::reward::block_subsidy(parent_height + 1);
        let coinbase = CoinbaseData {
            minted,
            fees: 0,
            burns: 0,
            source: if minted > 0 {
                CoinbaseSource::TransactionIndex(0)
            } else {
                CoinbaseSource::BalanceTag(BalanceTag::default())
            },
        };

        let mut transactions = Vec::new();
        if let Some(tx) = self.build_coinbase_transaction(minted)? {
            transactions.push(tx);
        }

        let supply =
            consensus::reward::update_supply_digest(base_supply, coinbase.net_native_delta())
                .ok_or(NodeError::Invalid("supply overflow"))?;

        let header_context = HeaderContext {
            parent_hash,
            parent_height,
            state_root,
            nullifier_root,
            supply_digest: supply,
            pow_bits,
            miner_id: self.miner_id,
        };
        let header = build_header(&header_context, &transactions, &self.miner_secret)?;
        Ok(ConsensusBlock {
            header,
            transactions,
            coinbase: Some(coinbase),
        })
    }

    #[cfg(feature = "test-utils")]
    pub async fn seal_pending_block(&self) -> NodeResult<Option<ConsensusBlock>> {
        if let Some(block) = self.assemble_pending_block()? {
            let cloned = block.clone();
            self.accept_block(block, BlockOrigin::Own, true).await?;
            Ok(Some(cloned))
        } else {
            Ok(None)
        }
    }

    #[cfg(feature = "test-utils")]
    pub async fn apply_block_for_test(&self, block: ConsensusBlock) -> NodeResult<()> {
        self.accept_block(block, BlockOrigin::File, false).await
    }

    async fn accept_block(
        &self,
        block: ConsensusBlock,
        origin: BlockOrigin,
        propagate: bool,
    ) -> NodeResult<()> {
        let block_miner = block.header.validator_set_commitment;
        let mut consensus = self.consensus.lock();
        if !consensus.has_miner(&block_miner) && block_miner == self.miner_id {
            let recovered = consensus.ensure_miner(&self.miner_secret.verify_key());
            tracing::info!(
                origin = ?origin,
                block_miner = %hex::encode(block_miner),
                recovered = %hex::encode(recovered),
                "re-registered local validator for imported block",
            );
        }
        if !consensus.has_miner(&block_miner) {
            let known_miners: Vec<String> =
                consensus.miner_ids().into_iter().map(hex::encode).collect();
            tracing::warn!(
                origin = ?origin,
                block_miner = %hex::encode(block_miner),
                ?known_miners,
                "block references validator outside configured miner set"
            );
        }
        let receipt = import_pow_block(&mut consensus, origin, block.clone())?;
        let hash = receipt.update.block_hash;
        drop(consensus);

        // Persist the block so it is available for potential reorg replay.
        self.storage.insert_block(hash, &block)?;

        if !receipt.update.committed {
            // Release miners to a fresh template even if this block is not on the best chain.
            // Without this, workers wait on the watch channel after submitting a block and never
            // receive a new template, effectively pausing mining.
            self.publish_template()?;
            return Ok(());
        }

        let mut ledger = self.ledger.lock();
        if block.header.parent_hash != ledger.best_hash {
            let best_tip = {
                let consensus = self.consensus.lock();
                consensus.best_hash()
            };
            tracing::warn!(
                parent = %hex::encode(block.header.parent_hash),
                current_best = %hex::encode(ledger.best_hash),
                best_tip = %hex::encode(best_tip),
                height = ledger.height,
                "reorg detected; rebuilding ledger to best chain"
            );
            drop(ledger);
            self.mempool.clear();
            self.storage.clear_mempool()?;
            self.telemetry.set_mempool_depth(0);
            self.rebuild_ledger_to_tip(best_tip)?;
            self.publish_template()?;
            let meta = self.latest_meta();
            let _ = self.event_tx.send(NodeEvent::Block {
                height: meta.height,
                hash: meta.best_hash,
            });
            if propagate {
                let payload = serialize_block(&block)?;
                let _ = self.gossip.broadcast_block(payload);
            }
            return Ok(());
        }

        ledger.best_hash = hash;
        ledger.height = block.header.height;
        ledger.state_root = block.header.state_root;
        ledger.nullifier_root = block.header.nullifier_root;
        ledger.supply_digest = block.header.supply_digest;
        ledger.version_commitment = receipt.version_commitment;
        ledger.proof_commitment = receipt.proof_commitment;
        ledger.pow_bits = block
            .header
            .pow
            .as_ref()
            .map(|seal| seal.pow_bits)
            .unwrap_or(ledger.pow_bits);
        let mut commitment_index = ledger.tree.len() as u64;
        for tx in &block.transactions {
            for (cm, ciphertext) in tx.commitments.iter().zip(tx.ciphertexts.iter()) {
                if let Some(value) = commitment_to_felt(cm) {
                    let _ = ledger.tree.append(value);
                    self.storage.append_commitment(commitment_index, value)?;
                    self.storage
                        .append_ciphertext(commitment_index, ciphertext)?;
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
        self.storage.store_meta(&self.latest_meta())?;
        if !recorded_nullifiers.is_empty() {
            self.storage.record_nullifiers(&recorded_nullifiers)?;
        }
        let pruned: Vec<[u8; 32]> = block.transactions.iter().map(|tx| tx.hash()).collect();
        self.mempool.prune(&pruned);
        self.storage.remove_mempool_bundles(&pruned)?;
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

    fn rebuild_ledger_to_tip(&self, tip_hash: [u8; 32]) -> NodeResult<()> {
        let chain = self.collect_chain(tip_hash)?;
        self.storage.reset_state()?;

        let mut tree = state_merkle::CommitmentTree::new(self.config.note_tree_depth)
            .map_err(|_| NodeError::Invalid("invalid tree depth"))?;
        let mut nullifiers = consensus::nullifier::NullifierSet::new();
        let mut state_root = [0u8; 32];
        let mut nullifier_root = [0u8; 32];
        let mut supply_digest = 0u128;
        let mut version_commitment = [0u8; 32];
        let mut proof_commitment = [0u8; 48];
        let mut best_hash = [0u8; 32];
        let mut height = 0u64;
        let mut pow_bits = DEFAULT_GENESIS_POW_BITS;
        let mut recorded_nullifiers = Vec::new();

        for (hash, block) in chain {
            let mut commitment_index = tree.len() as u64;
            for (cm, ciphertext) in block
                .transactions
                .iter()
                .flat_map(|tx| tx.commitments.iter().zip(tx.ciphertexts.iter()))
            {
                if let Some(value) = commitment_to_felt(cm) {
                    let _ = tree.append(value);
                    self.storage.append_commitment(commitment_index, value)?;
                    self.storage
                        .append_ciphertext(commitment_index, ciphertext)?;
                    commitment_index += 1;
                }
            }
            for nf in block
                .transactions
                .iter()
                .flat_map(|tx| tx.nullifiers.iter())
            {
                nullifiers.insert(*nf)?;
                recorded_nullifiers.push(*nf);
            }
            state_root = block.header.state_root;
            nullifier_root = block.header.nullifier_root;
            supply_digest = block.header.supply_digest;
            version_commitment = compute_version_commitment(&block.transactions);
            proof_commitment = compute_proof_commitment(&block.transactions);
            pow_bits = block
                .header
                .pow
                .as_ref()
                .map(|seal| seal.pow_bits)
                .unwrap_or(pow_bits);
            best_hash = hash;
            height = block.header.height;
        }

        if !recorded_nullifiers.is_empty() {
            self.storage.record_nullifiers(&recorded_nullifiers)?;
        }

        let rebuilt = LedgerState {
            tree,
            nullifiers,
            state_root,
            nullifier_root,
            supply_digest,
            version_commitment,
            proof_commitment,
            best_hash,
            height,
            pow_bits,
        };
        {
            let mut ledger = self.ledger.lock();
            *ledger = rebuilt;
        }
        let meta = self.latest_meta();
        self.storage.store_meta(&meta)?;
        self.telemetry.set_height(height);
        self.telemetry.set_mempool_depth(self.mempool.len());
        Ok(())
    }

    fn collect_chain(&self, tip_hash: [u8; 32]) -> NodeResult<Vec<([u8; 32], ConsensusBlock)>> {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut cursor = Some(tip_hash);

        while let Some(hash) = cursor {
            if !seen.insert(hash) {
                return Err(NodeError::Invalid("cycle detected in chain"));
            }
            let maybe_block = self.storage.load_block(hash)?;
            let block = match maybe_block {
                Some(block) => block,
                None if hash == [0u8; 32] => break,
                None => return Err(NodeError::Invalid("missing block during ledger rebuild")),
            };
            cursor = if block.header.height == 0 {
                None
            } else {
                Some(block.header.parent_hash)
            };
            chain.push((hash, block));
        }

        chain.reverse();
        Ok(chain)
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

struct HeaderContext {
    parent_hash: [u8; 32],
    parent_height: u64,
    state_root: [u8; 32],
    nullifier_root: [u8; 32],
    supply_digest: u128,
    pow_bits: u32,
    miner_id: [u8; 32],
}

fn build_header(
    context: &HeaderContext,
    transactions: &[Transaction],
    secret: &MlDsaSecretKey,
) -> NodeResult<consensus::header::BlockHeader> {
    use consensus::header::{BlockHeader, PowSeal};
    let proof_commitment = consensus::types::compute_proof_commitment(transactions);
    let version_commitment = compute_version_commitment(transactions);
    let fee_commitment = compute_fee_commitment(transactions);
    let tx_count = transactions.len() as u32;
    let timestamp_ms = current_time_ms();
    let mut header = BlockHeader {
        version: 1,
        height: context.parent_height + 1,
        view: 0,
        timestamp_ms,
        parent_hash: context.parent_hash,
        state_root: context.state_root,
        nullifier_root: context.nullifier_root,
        proof_commitment,
        version_commitment,
        tx_count,
        fee_commitment,
        supply_digest: context.supply_digest,
        validator_set_commitment: context.miner_id,
        signature_aggregate: Vec::new(),
        signature_bitmap: None,
        pow: Some(PowSeal {
            nonce: [0u8; 32],
            pow_bits: context.pow_bits,
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

fn dir_size(path: &Path) -> NodeResult<u64> {
    let metadata = fs::metadata(path)?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        total += dir_size(&entry.path())?;
    }
    Ok(total)
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct NoteStatus {
    pub leaf_count: u64,
    pub depth: u64,
    pub root: u64,
    pub next_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::header::PowSeal;
    use consensus::reward::{block_subsidy, update_supply_digest};
    use consensus::types::{CoinbaseData, CoinbaseSource};
    use tempfile::tempdir;

    fn commitment_bytes(value: u64) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[24..].copy_from_slice(&value.to_be_bytes());
        buf
    }

    fn build_block(
        parent_hash: [u8; 32],
        parent_height: u64,
        parent_state_root: [u8; 32],
        parent_supply: u128,
        miner_id: [u8; 32],
        pow_bits: u32,
        commitment: u64,
    ) -> (ConsensusBlock, [u8; 32], [u8; 32], u128) {
        let cm = commitment_bytes(commitment);
        let tx = Transaction::new(
            Vec::new(),
            vec![cm],
            [0u8; 32],
            DEFAULT_VERSION_BINDING,
            vec![vec![0u8]],
        );
        let transactions = vec![tx];
        let coinbase = CoinbaseData {
            minted: block_subsidy(parent_height + 1),
            fees: 0,
            burns: 0,
            source: CoinbaseSource::TransactionIndex(0),
        };
        let supply = update_supply_digest(parent_supply, coinbase.net_native_delta())
            .expect("supply digest");
        let state_root = accumulate_state(parent_state_root, &transactions);
        let nullifier_root = consensus::nullifier::NullifierSet::new().commitment();
        let header = consensus::header::BlockHeader {
            version: 1,
            height: parent_height + 1,
            view: parent_height + 1,
            timestamp_ms: parent_height + 1,
            parent_hash,
            state_root,
            nullifier_root,
            proof_commitment: compute_proof_commitment(&transactions),
            version_commitment: compute_version_commitment(&transactions),
            tx_count: transactions.len() as u32,
            fee_commitment: compute_fee_commitment(&transactions),
            supply_digest: supply,
            validator_set_commitment: miner_id,
            signature_aggregate: vec![0u8],
            signature_bitmap: None,
            pow: Some(PowSeal {
                nonce: [0u8; 32],
                pow_bits,
            }),
        };
        let block = ConsensusBlock {
            header,
            transactions,
            coinbase: Some(coinbase),
        };
        let hash = block.header.hash().expect("hash");
        (block, hash, state_root, supply)
    }

    #[tokio::test]
    async fn reorg_rebuilds_ledger_and_storage() {
        let dir = tempdir().unwrap();
        let mut config = NodeConfig::with_db_path(dir.path().join("reorg.db"));
        config.api_addr = "127.0.0.1:0".parse().unwrap();
        config.p2p_addr = "127.0.0.1:0".parse().unwrap();
        config.miner_workers = 0;
        config.note_tree_depth = 8;

        let router = config.gossip_router();
        let handle = NodeService::start(config, router).expect("start node");
        let service = handle.service.clone();
        let pow_bits = DEFAULT_GENESIS_POW_BITS;
        let miner_id = service.miner_id;

        // First tip on the primary chain.
        let (block1, hash1, _state1, _supply1) =
            build_block([0u8; 32], 0, [0u8; 32], 0, miner_id, pow_bits, 7);
        service
            .storage
            .insert_block(hash1, &block1)
            .expect("store block1");
        service
            .rebuild_ledger_to_tip(hash1)
            .expect("rebuild to first tip");

        assert_eq!(service.latest_meta().height, 1);
        assert_eq!(service.latest_meta().best_hash, hash1);
        assert_eq!(
            service.storage.load_commitments().unwrap(),
            vec![Felt::new(7)]
        );

        // Alternate chain overtakes with a longer tip.
        let (alt1, alt1_hash, alt_state, alt_supply) =
            build_block([0u8; 32], 0, [0u8; 32], 0, miner_id, pow_bits, 11);
        let (alt2, alt2_hash, _, _) =
            build_block(alt1_hash, 1, alt_state, alt_supply, miner_id, pow_bits, 12);
        service
            .storage
            .insert_block(alt1_hash, &alt1)
            .expect("store alt1");
        service
            .storage
            .insert_block(alt2_hash, &alt2)
            .expect("store alt2");
        service
            .rebuild_ledger_to_tip(alt2_hash)
            .expect("rebuild to alt tip");

        let meta = service.latest_meta();
        assert_eq!(meta.best_hash, alt2_hash);
        assert_eq!(meta.height, 2);
        assert_eq!(
            service.storage.load_commitments().unwrap(),
            vec![Felt::new(11), Felt::new(12)]
        );
        assert_eq!(service.note_status().leaf_count, 2);
        assert_eq!(service.mempool.len(), 0);

        // Clean up background tasks.
        handle.shutdown().await.expect("shutdown node");
    }
}
