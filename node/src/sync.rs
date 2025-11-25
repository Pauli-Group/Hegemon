use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use network::{PeerId, ProtocolHandle, ProtocolId};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::codec::{
    deserialize_block, deserialize_header, serialize_block, serialize_header, serialize_transaction,
};
use crate::error::NodeResult;
use crate::service::NodeService;

pub const SYNC_PROTOCOL_ID: ProtocolId = 0x5359_4e43; // "SYN C"
const HEADER_BATCH: u64 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncMessage {
    TipRequest,
    Tip {
        height: u64,
        hash: [u8; 32],
    },
    RequestHeaders {
        start: u64,
        limit: u64,
    },
    Headers {
        headers: Vec<Vec<u8>>,
    },
    RequestBlockBodies {
        hashes: Vec<[u8; 32]>,
    },
    BlockBodies {
        blocks: Vec<Vec<u8>>,
    },
    RequestTransactions {
        block: [u8; 32],
    },
    TransactionInventory {
        block: [u8; 32],
        transactions: Vec<Vec<u8>>,
    },
    Reject {
        reason: String,
    },
}

pub struct SyncService {
    node: Arc<NodeService>,
    protocol: ProtocolHandle,
    known_tips: HashMap<PeerId, (u64, [u8; 32])>,
    bad_peers: HashSet<PeerId>,
    active: Option<SyncSession>,
}

struct SyncSession {
    peer: PeerId,
    next_height: u64,
    target_height: u64,
    pending_hashes: Vec<[u8; 32]>,
}

impl SyncService {
    pub fn new(node: Arc<NodeService>, protocol: ProtocolHandle) -> Self {
        Self {
            node,
            protocol,
            known_tips: HashMap::new(),
            bad_peers: HashSet::new(),
            active: None,
        }
    }

    pub fn spawn(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(err) = self.run().await {
                error!(?err, "sync service exited with error");
            }
        })
    }

    async fn run(&mut self) -> NodeResult<()> {
        // Kick off discovery of peer tips so we can choose the best candidate.
        self.broadcast(SyncMessage::TipRequest).await?;

        loop {
            if let Some(session) = &self.active
                && session.next_height > session.target_height
            {
                info!(peer = ?session.peer, "sync reached target height");
                self.active = None;
                self.broadcast(SyncMessage::TipRequest).await?;
            }

            tokio::select! {
                Some((peer_id, msg)) = self.protocol.recv() => {
                    if let Err(err) = self.handle_message(peer_id, msg).await {
                        warn!(?peer_id, ?err, "sync message handling failed; retrying with another peer");
                        self.fail_peer(peer_id).await?;
                    }
                }
                _ = sleep(Duration::from_secs(5)), if self.active.is_none() => {
                    self.broadcast(SyncMessage::TipRequest).await?;
                }
            }
        }
    }

    async fn handle_message(
        &mut self,
        peer_id: PeerId,
        msg: network::ProtocolMessage,
    ) -> NodeResult<()> {
        let decoded: SyncMessage = bincode::deserialize(&msg.payload)?;
        match decoded {
            SyncMessage::TipRequest => {
                let meta = self.node.latest_meta();
                self.protocol
                    .send_to(
                        peer_id,
                        bincode::serialize(&SyncMessage::Tip {
                            height: meta.height,
                            hash: meta.best_hash,
                        })?,
                    )
                    .await?;
            }
            SyncMessage::Tip { height, hash } => {
                self.known_tips.insert(peer_id, (height, hash));
                if self.bad_peers.contains(&peer_id) {
                    return Ok(());
                }
                let local = self.node.latest_meta();
                if height > local.height {
                    self.begin_session(peer_id, height).await?;
                }
            }
            SyncMessage::RequestHeaders { start, limit } => {
                let headers = self.headers_from(start, limit as usize)?;
                self.protocol
                    .send_to(
                        peer_id,
                        bincode::serialize(&SyncMessage::Headers { headers })?,
                    )
                    .await?;
            }
            SyncMessage::Headers { headers } => {
                self.on_headers(peer_id, headers).await?;
            }
            SyncMessage::RequestBlockBodies { hashes } => {
                let blocks = self.blocks_by_hash(hashes)?;
                self.protocol
                    .send_to(
                        peer_id,
                        bincode::serialize(&SyncMessage::BlockBodies { blocks })?,
                    )
                    .await?;
            }
            SyncMessage::BlockBodies { blocks } => {
                self.on_blocks(peer_id, blocks).await?;
            }
            SyncMessage::RequestTransactions { block } => {
                let txs = self.transactions_for_block(block)?;
                self.protocol
                    .send_to(
                        peer_id,
                        bincode::serialize(&SyncMessage::TransactionInventory {
                            block,
                            transactions: txs,
                        })?,
                    )
                    .await?;
            }
            SyncMessage::TransactionInventory { .. } => {
                // Transaction gossip is not yet hooked into the mempool; ignore for now.
            }
            SyncMessage::Reject { reason } => {
                warn!(?peer_id, %reason, "peer rejected sync request");
                self.fail_peer(peer_id).await?;
            }
        }
        Ok(())
    }

    async fn begin_session(&mut self, peer: PeerId, target_height: u64) -> NodeResult<()> {
        let local = self.node.latest_meta();
        let start_height = local.height.saturating_add(1);
        if start_height > target_height {
            return Ok(());
        }
        info!(
            ?peer,
            target_height, start_height, "starting headers-first sync"
        );
        self.active = Some(SyncSession {
            peer,
            next_height: start_height,
            target_height,
            pending_hashes: Vec::new(),
        });
        self.request_headers(peer, start_height).await
    }

    async fn request_headers(&self, peer: PeerId, start: u64) -> NodeResult<()> {
        let payload = SyncMessage::RequestHeaders {
            start,
            limit: HEADER_BATCH,
        };
        self.protocol
            .send_to(peer, bincode::serialize(&payload)?)
            .await?;
        Ok(())
    }

    async fn on_headers(&mut self, peer: PeerId, headers: Vec<Vec<u8>>) -> NodeResult<()> {
        let Some(session) = &mut self.active else {
            return Ok(());
        };
        if session.peer != peer {
            return Ok(());
        }
        if headers.is_empty() {
            // Peer has no more headers to serve.
            session.next_height = session.target_height + 1;
            return Ok(());
        }

        let mut next_height = session.next_height;
        let mut expected_hashes = Vec::new();
        for bytes in headers {
            let header = deserialize_header(&bytes)?;
            if header.height != next_height {
                return Err(crate::error::NodeError::Invalid("header height gap"));
            }
            let hash = header
                .hash()
                .map_err(|_| crate::error::NodeError::Invalid("header hash"))?;
            expected_hashes.push(hash);
            next_height += 1;
        }

        session.pending_hashes = expected_hashes.clone();
        self.protocol
            .send_to(
                peer,
                bincode::serialize(&SyncMessage::RequestBlockBodies {
                    hashes: expected_hashes,
                })?,
            )
            .await?;
        Ok(())
    }

    async fn on_blocks(&mut self, peer: PeerId, blocks: Vec<Vec<u8>>) -> NodeResult<()> {
        let Some(session) = &mut self.active else {
            return Ok(());
        };
        if session.peer != peer {
            return Ok(());
        }
        if blocks.len() != session.pending_hashes.len() {
            return Err(crate::error::NodeError::Invalid("block batch mismatch"));
        }

        for (raw, expected_hash) in blocks.into_iter().zip(session.pending_hashes.drain(..)) {
            let block = deserialize_block(&raw)?;
            let hash = block
                .header
                .hash()
                .map_err(|_| crate::error::NodeError::Invalid("block hash"))?;
            if hash != expected_hash {
                return Err(crate::error::NodeError::Invalid("block hash mismatch"));
            }
            if let Err(err) = self.node.import_sync_block(block.clone()).await {
                warn!(?peer, ?err, "block validation failed during sync");
                return Err(err);
            }
            session.next_height = block.header.height + 1;
        }

        let next_height = session.next_height;
        let target_height = session.target_height;
        let _ = session;

        if next_height <= target_height {
            self.request_headers(peer, next_height).await?;
        }

        Ok(())
    }

    fn headers_from(&self, start: u64, limit: usize) -> NodeResult<Vec<Vec<u8>>> {
        let mut blocks = self.node.storage().load_blocks()?;
        blocks.sort_by_key(|b| b.header.height);
        let headers: Vec<Vec<u8>> = blocks
            .into_iter()
            .filter(|b| b.header.height >= start)
            .take(limit)
            .map(|b| serialize_header(&b.header))
            .collect::<Result<_, _>>()?;
        Ok(headers)
    }

    fn blocks_by_hash(&self, hashes: Vec<[u8; 32]>) -> NodeResult<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for hash in hashes {
            if let Some(block) = self.node.storage().load_block(hash)? {
                out.push(serialize_block(&block)?);
            }
        }
        Ok(out)
    }

    fn transactions_for_block(&self, hash: [u8; 32]) -> NodeResult<Vec<Vec<u8>>> {
        if let Some(block) = self.node.storage().load_block(hash)? {
            let txs = block
                .transactions
                .iter()
                .map(serialize_transaction)
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(txs);
        }
        Ok(Vec::new())
    }

    async fn broadcast(&self, msg: SyncMessage) -> NodeResult<()> {
        self.protocol.send(bincode::serialize(&msg)?).await?;
        Ok(())
    }

    async fn fail_peer(&mut self, peer: PeerId) -> NodeResult<()> {
        self.bad_peers.insert(peer);
        if self.active.as_ref().is_some_and(|s| s.peer == peer) {
            self.active = None;
        }
        self.broadcast(SyncMessage::TipRequest).await
    }
}
