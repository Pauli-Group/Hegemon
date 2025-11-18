use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use consensus::PowConsensus;
use consensus::pow::DEFAULT_GENESIS_POW_BITS;
use consensus::proof::HashVerifier;
use consensus::types::{
    BalanceTag, CoinbaseData, CoinbaseSource, ConsensusBlock, Transaction, compute_fee_commitment,
    compute_version_commitment,
};
use crypto::hashes::sha256;
use crypto::ml_dsa::MlDsaSecretKey;
use crypto::traits::{SigningKey, VerifyKey};
use network::{GossipHandle, GossipMessage, GossipRouter};
use parking_lot::Mutex;
use protocol_versioning::{DEFAULT_VERSION_BINDING, VersionBinding};
use rand::rngs::OsRng;
use tokio::sync::{broadcast, mpsc, watch};
use transaction_circuit::constants::NATIVE_ASSET_ID;
use transaction_circuit::hashing::Felt;
use transaction_circuit::keys::{VerifyingKey, generate_keys};
use transaction_circuit::proof::verify;

use crate::codec::{deserialize_block, serialize_block};
use crate::config::NodeConfig;
use crate::error::{NodeError, NodeResult};
use crate::mempool::Mempool;
use crate::miner::{self, BlockTemplate};
use crate::storage::{ChainMeta, Storage};
use crate::telemetry::{Telemetry, TelemetryPosture, TelemetrySnapshot};
use crate::transaction::{ValidatedTransaction, felt_to_bytes, proof_to_transaction};
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
    miner_running: AtomicBool,
    target_hash_rate: AtomicU64,
    thread_count: AtomicUsize,
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
        let miner_payout_address = config.miner_payout_address.clone();
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
        let meta = storage.load_meta()?.unwrap_or(ChainMeta {
            best_hash: [0u8; 32],
            height: 0,
            state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            supply_digest: 0,
            pow_bits: DEFAULT_GENESIS_POW_BITS,
        });
        let pow_bits = if meta.height == 0 {
            DEFAULT_GENESIS_POW_BITS
        } else {
            meta.pow_bits
        };
        let ledger = LedgerState {
            tree,
            nullifiers,
            state_root: meta.state_root,
            nullifier_root: meta.nullifier_root,
            supply_digest: meta.supply_digest,
            best_hash: meta.best_hash,
            height: meta.height,
            pow_bits,
        };
        let miner_pubkeys = vec![miner_secret.verify_key()];
        let mut consensus = PowConsensus::new(miner_pubkeys, meta.state_root, HashVerifier);
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
            miner_payout_address,
            miner_running: AtomicBool::new(true),
            target_hash_rate: AtomicU64::new(0),
            thread_count: AtomicUsize::new(config.miner_workers),
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
                if let Err(err) = miner_service.accept_block(block, true).await {
                    eprintln!("miner produced invalid block: {err}");
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

    pub fn update_privacy_posture(&self, posture: TelemetryPosture) {
        self.telemetry.set_privacy_posture(posture);
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

    async fn validate_and_add_transaction(
        &self,
        bundle: TransactionBundle,
        broadcast: bool,
    ) -> NodeResult<[u8; 32]> {
        let proof = bundle.proof;
        let ciphertexts = bundle.ciphertexts;
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
        self.mempool.insert(validated.clone())?;
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
        match self.assemble_pending_block()? {
            Some(block) => {
                let bits = block.header.pow.as_ref().map(|s| s.pow_bits).unwrap_or(0);
                self.telemetry.set_difficulty(bits);
                let _ = self.template_tx.send(Some(BlockTemplate { block }));
            }
            None => {
                let _ = self.template_tx.send(None);
                self.telemetry.set_difficulty(0);
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
            .collect(self.config.template_tx_limit)
            .into_iter()
            .collect::<Vec<_>>();
        let ledger = self.ledger.lock();
        let parent_hash = ledger.best_hash;
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
            for nf in &entry.transaction.nullifiers {
                nullifier_set.insert(*nf)?;
            }
            user_transactions.push(entry.transaction.clone());
            total_fees = total_fees.saturating_add(entry.fee);
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

    #[cfg(feature = "test-utils")]
    pub async fn seal_pending_block(&self) -> NodeResult<Option<ConsensusBlock>> {
        if let Some(block) = self.assemble_pending_block()? {
            let cloned = block.clone();
            self.accept_block(block, true).await?;
            Ok(Some(cloned))
        } else {
            Ok(None)
        }
    }

    #[cfg(feature = "test-utils")]
    pub async fn apply_block_for_test(&self, block: ConsensusBlock) -> NodeResult<()> {
        self.accept_block(block, false).await
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
