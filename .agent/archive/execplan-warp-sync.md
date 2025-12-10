# Execution Plan: Post-Quantum Warp Sync

**Created**: 2025-11-28  
**Status**: 🔴 NOT STARTED (Deferred)  
**Priority**: Low (optimization, not required for mainnet)  
**Prerequisites**: Phase 11.6 Chain Sync (✅ Complete), Multi-node networking verified

---

## Overview

Warp sync enables new nodes to sync to the latest chain state in minutes instead of hours/days by:
1. Downloading finality/checkpoint proofs instead of all blocks
2. Fetching state snapshot at proven block
3. Skipping historical block execution

### Why This Matters

| Sync Method | Time to Sync (1M blocks) | Data Downloaded |
|-------------|-------------------------|-----------------|
| Full Sync | Hours to days | All blocks + execution |
| **Warp Sync** | Minutes | State snapshot + proof |

---

## Hegemon-Specific Design

Since Hegemon uses **PoW consensus** (not GRANDPA), we use a **checkpoint-based** approach rather than authority signatures. This is actually simpler and fully post-quantum safe.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     WARP SYNC FLOW                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. REQUEST CHECKPOINTS                                         │
│     ┌─────────┐         ┌─────────┐                            │
│     │ New Node│ ──────► │  Peer   │  "What are your checkpoints?"│
│     └─────────┘         └─────────┘                            │
│                              │                                  │
│                              ▼                                  │
│     ┌────────────────────────────────────────┐                 │
│     │ CheckpointSet {                        │                 │
│     │   checkpoints: [(height, hash), ...],  │                 │
│     │   tip_height: u64,                     │                 │
│     │   tip_hash: [u8; 32],                  │                 │
│     │ }                                      │                 │
│     └────────────────────────────────────────┘                 │
│                                                                 │
│  2. VERIFY PoW CHAIN                                           │
│     ┌─────────┐         ┌─────────┐                            │
│     │ New Node│ ──────► │  Peer   │  "Give me headers N to N+100"│
│     └─────────┘         └─────────┘                            │
│           │                                                     │
│           ▼                                                     │
│     Verify PoW difficulty for each header                      │
│     Verify chain continuity (parent_hash matches)              │
│     Confirm checkpoint is 100+ blocks deep                     │
│                                                                 │
│  3. DOWNLOAD STATE                                              │
│     ┌─────────┐         ┌─────────┐                            │
│     │ New Node│ ──────► │  Peer   │  "State trie at block X"   │
│     └─────────┘         └─────────┘                            │
│           │                                                     │
│           ▼                                                     │
│     Stream state key-value pairs                               │
│     Verify against state_root in header                        │
│     Commit to local database                                   │
│                                                                 │
│  4. SWITCH TO NORMAL SYNC                                      │
│     Download and import remaining blocks                       │
│     Continue with full sync from checkpoint                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Protocol Messages

**Goal**: Define warp sync network protocol messages.

### Task 1.1: Warp Sync Request/Response Types

Add to `node/src/substrate/network_bridge.rs`:

```rust
/// Warp sync protocol messages
#[derive(Debug, Clone, Encode, Decode)]
pub enum WarpSyncRequest {
    /// Request known checkpoints from peer
    GetCheckpoints,
    
    /// Request headers for PoW verification
    /// (from_height, count) - request `count` headers starting at `from_height`
    GetHeadersForProof { from_height: u64, count: u32 },
    
    /// Request state entries for a block
    /// (block_hash, start_key, limit)
    GetState { 
        block_hash: [u8; 32], 
        start_key: Option<Vec<u8>>,
        limit: u32,
    },
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum WarpSyncResponse {
    /// Checkpoint set from peer
    Checkpoints(CheckpointSet),
    
    /// Headers for PoW verification
    HeadersForProof(Vec<EncodedHeader>),
    
    /// State entries (key, value pairs) + continuation key
    State {
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        complete: bool,
        next_key: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct CheckpointSet {
    /// Known checkpoints: (height, hash)
    pub checkpoints: Vec<(u64, [u8; 32])>,
    /// Current chain tip height
    pub tip_height: u64,
    /// Current chain tip hash  
    pub tip_hash: [u8; 32],
}

/// Encoded header bytes (to avoid generic in protocol message)
pub type EncodedHeader = Vec<u8>;
```

### Task 1.2: Protocol ID

```rust
pub const WARP_SYNC_PROTOCOL: &str = "/hegemon/warp-sync/1";
```

**Verification**:
```bash
cargo build -p hegemon-node --features substrate
grep -r "WARP_SYNC_PROTOCOL" node/src/
```

---

## Phase 2: Checkpoint Management

**Goal**: Manage hardcoded and discovered checkpoints.

### Task 2.1: Checkpoint Configuration

Create `node/src/substrate/warp_sync.rs`:

```rust
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::collections::BTreeMap;

/// Hardcoded checkpoints for mainnet
/// These are block hashes at known heights that are guaranteed valid
pub const MAINNET_CHECKPOINTS: &[(u64, &str)] = &[
    // Format: (height, hex-encoded block hash)
    // Add checkpoints after mainnet launch
    // (100_000, "0x1234..."),
    // (200_000, "0x5678..."),
];

/// Minimum confirmations for a block to be considered "final" for warp sync
pub const WARP_FINALITY_DEPTH: u64 = 100;

/// Maximum state entries per response
pub const STATE_BATCH_SIZE: u32 = 1000;

pub struct CheckpointManager {
    /// Hardcoded checkpoints from chain spec
    hardcoded: BTreeMap<u64, [u8; 32]>,
    /// Dynamically discovered checkpoints from peers
    discovered: BTreeMap<u64, [u8; 32]>,
}

impl CheckpointManager {
    pub fn new(chain_id: &str) -> Self {
        let mut hardcoded = BTreeMap::new();
        
        if chain_id == "hegemon-mainnet" {
            for (height, hash_hex) in MAINNET_CHECKPOINTS {
                if let Ok(hash) = hex::decode(hash_hex.trim_start_matches("0x")) {
                    if hash.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&hash);
                        hardcoded.insert(*height, arr);
                    }
                }
            }
        }
        
        Self {
            hardcoded,
            discovered: BTreeMap::new(),
        }
    }
    
    /// Get the best checkpoint at or below the given height
    pub fn best_checkpoint_at(&self, max_height: u64) -> Option<(u64, [u8; 32])> {
        // Prefer hardcoded over discovered
        self.hardcoded
            .range(..=max_height)
            .next_back()
            .or_else(|| self.discovered.range(..=max_height).next_back())
            .map(|(h, hash)| (*h, *hash))
    }
    
    /// Add a discovered checkpoint (must be verified first)
    pub fn add_discovered(&mut self, height: u64, hash: [u8; 32]) {
        self.discovered.insert(height, hash);
    }
    
    /// Get all checkpoints for sharing with peers
    pub fn all_checkpoints(&self) -> Vec<(u64, [u8; 32])> {
        let mut all: Vec<_> = self.hardcoded.iter()
            .chain(self.discovered.iter())
            .map(|(h, hash)| (*h, *hash))
            .collect();
        all.sort_by_key(|(h, _)| *h);
        all.dedup_by_key(|(h, _)| *h);
        all
    }
}
```

**Verification**:
```bash
cargo test -p hegemon-node checkpoint
```

---

## Phase 3: Warp Sync State Machine

**Goal**: Implement the warp sync state machine.

### Task 3.1: Warp Sync Service

```rust
use crate::substrate::network_bridge::{WarpSyncRequest, WarpSyncResponse, CheckpointSet};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};

pub enum WarpSyncState {
    /// Not warp syncing
    Idle,
    /// Requesting checkpoints from peers
    RequestingCheckpoints { 
        pending_peers: Vec<PeerId>,
        received: Vec<(PeerId, CheckpointSet)>,
    },
    /// Verifying PoW chain to checkpoint
    VerifyingProof {
        target_height: u64,
        target_hash: [u8; 32],
        headers_received: Vec<EncodedHeader>,
        headers_verified: u64,
    },
    /// Downloading state at checkpoint
    DownloadingState {
        block_hash: [u8; 32],
        block_height: u64,
        entries_received: u64,
        next_key: Option<Vec<u8>>,
    },
    /// Warp sync complete, switching to normal sync
    Complete {
        synced_to_height: u64,
        synced_to_hash: [u8; 32],
    },
    /// Warp sync failed
    Failed { reason: String },
}

pub struct WarpSyncService<Block: BlockT, Client> {
    client: Arc<Client>,
    state: WarpSyncState,
    checkpoint_manager: CheckpointManager,
    /// State entries pending commit
    pending_state: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<Block, Client> WarpSyncService<Block, Client>
where
    Block: BlockT,
    Client: HeaderBackend<Block> + AuxStore,
{
    pub fn new(client: Arc<Client>, chain_id: &str) -> Self {
        Self {
            client,
            state: WarpSyncState::Idle,
            checkpoint_manager: CheckpointManager::new(chain_id),
            pending_state: Vec::new(),
        }
    }
    
    /// Start warp sync if we're far behind
    pub fn maybe_start(&mut self, local_height: u64, network_height: u64) -> bool {
        // Only warp sync if we're significantly behind
        const WARP_THRESHOLD: u64 = 1000;
        
        if network_height.saturating_sub(local_height) > WARP_THRESHOLD {
            self.state = WarpSyncState::RequestingCheckpoints {
                pending_peers: Vec::new(),
                received: Vec::new(),
            };
            true
        } else {
            false
        }
    }
    
    /// Handle incoming warp sync response
    pub fn handle_response(&mut self, peer: PeerId, response: WarpSyncResponse) {
        match (&mut self.state, response) {
            (WarpSyncState::RequestingCheckpoints { received, .. }, 
             WarpSyncResponse::Checkpoints(set)) => {
                received.push((peer, set));
                self.process_checkpoints();
            }
            
            (WarpSyncState::VerifyingProof { headers_received, .. },
             WarpSyncResponse::HeadersForProof(headers)) => {
                headers_received.extend(headers);
                self.verify_pow_chain();
            }
            
            (WarpSyncState::DownloadingState { entries_received, next_key, .. },
             WarpSyncResponse::State { entries, complete, next_key: nk }) => {
                *entries_received += entries.len() as u64;
                self.pending_state.extend(entries);
                
                if complete {
                    self.commit_state();
                } else {
                    *next_key = nk;
                }
            }
            
            _ => {
                tracing::warn!("Unexpected warp sync response in state {:?}", self.state);
            }
        }
    }
    
    /// Process collected checkpoints, select best target
    fn process_checkpoints(&mut self) {
        // Implementation: select checkpoint with most peer agreement
        // Transition to VerifyingProof state
    }
    
    /// Verify PoW chain from headers
    fn verify_pow_chain(&mut self) {
        // Implementation: verify each header's PoW and parent linkage
        // On success, transition to DownloadingState
    }
    
    /// Commit downloaded state to database
    fn commit_state(&mut self) {
        // Implementation: write pending_state to client backend
        // Transition to Complete state
    }
    
    /// Get next request to send (if any)
    pub fn next_request(&mut self) -> Option<(PeerId, WarpSyncRequest)> {
        match &self.state {
            WarpSyncState::RequestingCheckpoints { pending_peers, .. } => {
                pending_peers.first().map(|p| (*p, WarpSyncRequest::GetCheckpoints))
            }
            WarpSyncState::VerifyingProof { target_height, headers_verified, .. } => {
                // Request more headers if needed
                Some((
                    PeerId::default(), // TODO: select peer
                    WarpSyncRequest::GetHeadersForProof {
                        from_height: *headers_verified,
                        count: 100,
                    }
                ))
            }
            WarpSyncState::DownloadingState { block_hash, next_key, .. } => {
                Some((
                    PeerId::default(),
                    WarpSyncRequest::GetState {
                        block_hash: *block_hash,
                        start_key: next_key.clone(),
                        limit: STATE_BATCH_SIZE,
                    }
                ))
            }
            _ => None,
        }
    }
    
    pub fn is_active(&self) -> bool {
        !matches!(self.state, WarpSyncState::Idle | WarpSyncState::Complete { .. } | WarpSyncState::Failed { .. })
    }
    
    pub fn is_complete(&self) -> bool {
        matches!(self.state, WarpSyncState::Complete { .. })
    }
}
```

---

## Phase 4: PoW Verification

**Goal**: Verify PoW chain continuity for checkpoint proofs.

### Task 4.1: Header Chain Verifier

```rust
use consensus::pow::{verify_pow, Difficulty};

pub struct PowChainVerifier {
    /// Expected difficulty at each height (simplified: use latest)
    expected_difficulty: Difficulty,
}

impl PowChainVerifier {
    /// Verify a chain of headers has valid PoW and continuity
    pub fn verify_chain<Block: BlockT>(
        &self,
        headers: &[Block::Header],
        expected_tip_hash: Block::Hash,
    ) -> Result<(), WarpSyncError> {
        if headers.is_empty() {
            return Err(WarpSyncError::EmptyProof);
        }
        
        // Verify chain ends at expected hash
        let last = headers.last().unwrap();
        if last.hash() != expected_tip_hash {
            return Err(WarpSyncError::HashMismatch);
        }
        
        // Verify each header
        for window in headers.windows(2) {
            let parent = &window[0];
            let child = &window[1];
            
            // Check parent linkage
            if child.parent_hash() != &parent.hash() {
                return Err(WarpSyncError::ChainDiscontinuity);
            }
            
            // Verify PoW (Blake3)
            let header_bytes = child.encode();
            if !verify_pow(&header_bytes, &self.expected_difficulty) {
                return Err(WarpSyncError::InvalidPow);
            }
        }
        
        Ok(())
    }
}

#[derive(Debug)]
pub enum WarpSyncError {
    EmptyProof,
    HashMismatch,
    ChainDiscontinuity,
    InvalidPow,
    StateVerificationFailed,
    NetworkError(String),
}
```

---

## Phase 5: State Download & Import

**Goal**: Download and import state snapshot.

### Task 5.1: State Downloader

```rust
pub struct StateDownloader<Block: BlockT> {
    block_hash: Block::Hash,
    state_root: Block::Hash,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    complete: bool,
}

impl<Block: BlockT> StateDownloader<Block> {
    pub fn new(block_hash: Block::Hash, state_root: Block::Hash) -> Self {
        Self {
            block_hash,
            state_root,
            entries: Vec::new(),
            complete: false,
        }
    }
    
    pub fn add_entries(&mut self, entries: Vec<(Vec<u8>, Vec<u8>)>, complete: bool) {
        self.entries.extend(entries);
        self.complete = complete;
    }
    
    /// Verify downloaded state matches state_root
    pub fn verify(&self) -> Result<(), WarpSyncError> {
        // Build merkle trie from entries
        // Compare root to expected state_root
        // This uses Blake3 which is PQ-safe
        todo!("Implement state trie verification")
    }
    
    /// Commit state to backend
    pub fn commit<Client>(&self, client: &Client) -> Result<(), WarpSyncError>
    where
        Client: /* backend traits */
    {
        // Write all entries to database
        // Set canonical block to warp target
        todo!("Implement state commit")
    }
}
```

### Task 5.2: Request Handler (Peer Side)

Handle warp sync requests from other peers:

```rust
impl NetworkBridge {
    pub fn handle_warp_sync_request(
        &self,
        peer: PeerId,
        request: WarpSyncRequest,
    ) -> Option<WarpSyncResponse> {
        match request {
            WarpSyncRequest::GetCheckpoints => {
                let checkpoints = self.checkpoint_manager.all_checkpoints();
                let info = self.client.info();
                Some(WarpSyncResponse::Checkpoints(CheckpointSet {
                    checkpoints,
                    tip_height: info.best_number.saturated_into(),
                    tip_hash: info.best_hash.into(),
                }))
            }
            
            WarpSyncRequest::GetHeadersForProof { from_height, count } => {
                let headers = self.get_headers_range(from_height, count);
                Some(WarpSyncResponse::HeadersForProof(headers))
            }
            
            WarpSyncRequest::GetState { block_hash, start_key, limit } => {
                let (entries, complete, next_key) = 
                    self.get_state_entries(block_hash, start_key, limit);
                Some(WarpSyncResponse::State { entries, complete, next_key })
            }
        }
    }
}
```

---

## Phase 6: Integration

**Goal**: Wire warp sync into node startup.

### Task 6.1: Warp Sync on Startup

```rust
// In service.rs, during node initialization:

async fn maybe_warp_sync(
    client: Arc<Client>,
    network: &NetworkBridge,
) -> Result<(), Error> {
    let local_height = client.info().best_number;
    let network_height = network.best_seen_height();
    
    let mut warp_sync = WarpSyncService::new(Arc::clone(&client), "hegemon-mainnet");
    
    if !warp_sync.maybe_start(local_height, network_height) {
        tracing::info!("Skipping warp sync, only {} blocks behind", 
            network_height - local_height);
        return Ok(());
    }
    
    tracing::info!(
        local = local_height,
        network = network_height,
        "Starting warp sync"
    );
    
    while warp_sync.is_active() {
        if let Some((peer, request)) = warp_sync.next_request() {
            let response = network.send_warp_request(peer, request).await?;
            warp_sync.handle_response(peer, response);
        }
        
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    if warp_sync.is_complete() {
        tracing::info!("Warp sync complete!");
        Ok(())
    } else {
        Err(Error::WarpSyncFailed)
    }
}
```

### Task 6.2: CLI Flag

```rust
/// CLI option to enable/disable warp sync
#[arg(long, default_value = "true")]
pub warp_sync: bool,
```

---

## Post-Quantum Security Analysis

### What Makes This PQ-Safe

| Component | Algorithm | PQ Status |
|-----------|-----------|-----------|
| Block hashes | Blake3 | ✅ PQ-safe (hash function) |
| State root | Blake3 Merkle | ✅ PQ-safe |
| PoW verification | Blake3 | ✅ PQ-safe |
| Network transport | ML-KEM-768 | ✅ PQ-safe |
| Peer authentication | ML-DSA-65 | ✅ PQ-safe |

### No Vulnerable Crypto

Unlike Substrate's GRANDPA warp sync which uses Ed25519:
- **No Ed25519 signatures** (would need Shor-resistance)
- **No authority key derivation** (BIP-32 uses secp256k1)
- **No elliptic curves anywhere in the proof chain**

Hegemon's PoW-based warp sync relies only on:
1. Hash function preimage resistance (Blake3 - classically and quantumly hard)
2. Hash function collision resistance (Blake3 - 128-bit post-quantum security)

---

## Testing Plan

### Unit Tests

```rust
#[test]
fn test_checkpoint_manager() {
    let mgr = CheckpointManager::new("hegemon-testnet");
    assert!(mgr.all_checkpoints().is_empty());
    
    mgr.add_discovered(1000, [1u8; 32]);
    assert_eq!(mgr.best_checkpoint_at(1000), Some((1000, [1u8; 32])));
    assert_eq!(mgr.best_checkpoint_at(999), None);
}

#[test]
fn test_pow_chain_verification() {
    // Create test headers with valid PoW
    // Verify chain passes
    // Verify broken chain fails
}

#[test]
fn test_state_verification() {
    // Create test state entries
    // Build merkle root
    // Verify matches expected
}
```

### Integration Tests

```bash
# Start Node 1, mine 2000+ blocks
HEGEMON_MINE=1 ./target/release/hegemon-node --dev --base-path /tmp/warp1 &
sleep 600  # Mine for 10 minutes

# Start Node 2 with empty database, should warp sync
./target/release/hegemon-node --dev --base-path /tmp/warp2 \
    --bootnodes /ip4/127.0.0.1/tcp/30333 \
    --warp-sync=true &

# Verify Node 2 synced quickly
sleep 60
# Check Node 2 height matches Node 1
```

---

## Success Criteria

1. **Fast Sync**: New node syncs 100k blocks in < 5 minutes (vs hours for full sync)
2. **Correctness**: Warp-synced node has identical state to full-synced node
3. **PQ-Safe**: No ECC, no Ed25519, no vulnerable cryptography
4. **Robust**: Falls back to full sync if warp sync fails

---

## Timeline Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: Protocol Messages | 1 day | None |
| Phase 2: Checkpoint Management | 1 day | Phase 1 |
| Phase 3: State Machine | 2 days | Phase 2 |
| Phase 4: PoW Verification | 1 day | Consensus crate |
| Phase 5: State Download | 2 days | Backend traits |
| Phase 6: Integration | 1 day | All above |
| Testing | 2 days | All above |

**Total: ~10 engineering days**

---

## References

- Substrate Warp Sync: https://docs.substrate.io/learn/light-clients-and-unstoppable-apps/
- GRANDPA Finality: https://wiki.polkadot.network/docs/learn-grandpa
- Bitcoin Checkpoints: https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp

---

## Status Tracking

| Task | Status | Notes |
|------|--------|-------|
| Phase 1: Protocol Messages | 🔴 NOT STARTED | |
| Phase 2: Checkpoint Management | 🔴 NOT STARTED | |
| Phase 3: State Machine | 🔴 NOT STARTED | |
| Phase 4: PoW Verification | 🔴 NOT STARTED | |
| Phase 5: State Download | 🔴 NOT STARTED | |
| Phase 6: Integration | 🔴 NOT STARTED | |
| Testing | 🔴 NOT STARTED | |

**Overall Status**: 🔴 DEFERRED - Will implement after multi-node sync verification
