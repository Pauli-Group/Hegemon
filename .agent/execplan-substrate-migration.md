# Hegemon: Post-Quantum ZCash on Substrate - Execution Plan

**Goal**: Production-ready post-quantum cryptocurrency with shielded transactions built on Substrate.

**CRITICAL SECURITY MANDATE**: This is a **PQ-ONLY** project. **NO ELLIPTIC CURVES. NO GROTH16. NO PAIRINGS. NO CLASSICAL CRYPTO.**

---

## Cryptographic Foundations

### Approved Primitives (PQ-ONLY)

| Category | Primitive | Standard | Usage |
|----------|-----------|----------|-------|
| **Signatures** | ML-DSA-65 (Dilithium) | FIPS 204 | Consensus, governance, identity |
| **Signatures** | SLH-DSA (SPHINCS+) | FIPS 205 | Long-lived trust roots |
| **Key Exchange** | ML-KEM-768 (Kyber) | FIPS 203 | P2P handshake, note encryption |
| **Hash** | Blake3-256 | - | PoW, commitments, general hashing |
| **Hash** | SHA3-256 | FIPS 202 | Fallback, interoperability |
| **Hash** | Poseidon | - | STARK-friendly circuits (Goldilocks field) |
| **ZK Proofs** | STARK (FRI-based) | - | Shielded transactions, transparent setup |

### **FORBIDDEN** Primitives

| Primitive | Reason | Alternative |
|-----------|--------|-------------|
| Groth16 | Pairing-based (BLS12-381), quantum-vulnerable | STARK |
| Halo2 | ECC-based (Pasta curves), quantum-vulnerable | STARK |
| Ed25519 | Elliptic curve, Shor-breakable | ML-DSA-65 |
| X25519 ECDH | Elliptic curve, Shor-breakable | ML-KEM-768 |
| ECDSA/secp256k1 | Elliptic curve, Shor-breakable | ML-DSA-65 |
| RSA | Factoring-based, Shor-breakable | ML-DSA-65 |
| BLS signatures | Pairing-based, quantum-vulnerable | ML-DSA-65 |
| Jubjub/BabyJubjub | Embedded curves for SNARKs | Poseidon hash |
| Pallas/Vesta | Halo2 curves, ECC-based | STARK |

**Any PR introducing ECC, pairings, or Groth16 MUST be rejected.**

---

## Current Status

**Last Updated**: 2025-11-28

### ⚠️ CRITICAL: Scaffold vs Production Status

**The node compiles and tests pass, but core functionality uses MOCK implementations.**

| Component | Code Status | Runtime Status | Blocker |
|-----------|-------------|----------------|---------|
| Substrate Node | ✅ Compiles | ⚠️ SCAFFOLD | Uses `new_full()` not `new_full_with_client()` |
| Blake3 PoW | ✅ Works | ✅ PRODUCTION | Mining produces valid PoW |
| PQ Network | ✅ Works | ✅ PRODUCTION | ML-KEM-768 handshakes succeed |
| Runtime WASM | ✅ Compiles | ⚠️ NOT EXECUTED | Mock state execution ignores runtime |
| Full Client Types | ✅ Defined | ⚠️ NOT USED | `new_full()` doesn't use them |
| Block Import Pipeline | ✅ Defined | ⚠️ NOT WIRED | `PowBlockImport` commented out |
| Transaction Pool | ⚠️ MOCK | ❌ BROKEN | `MockTransactionPool` - txs lost |
| State Execution | ⚠️ MOCK | ❌ BROKEN | Mock hash, not runtime execution |
| Mining Worker | ✅ Works | ⚠️ SCAFFOLD | Mines but blocks have mock state |
| RPC Extensions | ✅ Defined | ⚠️ PARTIAL | Some return errors/mock data |
| Wallet RPC Client | ✅ Works | ⚠️ BLOCKED | Server returns errors |
| Shielded Pool Pallet | ✅ Compiles | ⚠️ ISOLATED | In runtime but not executed |
| Chain Sync | ❌ MISSING | ❌ BROKEN | Task 11.5 not implemented |

### What This Means

**CAN do today:**
- ✅ Start nodes, connect via PQ network
- ✅ Mine blocks with valid Blake3 PoW
- ✅ Propagate block announcements between peers
- ✅ Dashboard shows block numbers increasing

**CANNOT do today:**
- ❌ Submit and execute real transactions
- ❌ Persist blocks to real Substrate storage
- ❌ Sync chain history to new peers
- ❌ Execute shielded transfers (RPC returns error)
- ❌ Query real balances from runtime

### Infrastructure (Code Exists)

| Component | Status | Crypto | Key Files |
|-----------|--------|--------|-----------|
| Substrate Node | ✅ COMPILES | - | `node/src/substrate/service.rs` |
| Blake3 PoW | ✅ PRODUCTION | Blake3 | `consensus/src/substrate_pow.rs` |
| PQ Network | ✅ PRODUCTION | ML-KEM-768 | `pq-noise/src/handshake.rs` |
| Runtime WASM | ✅ COMPILES | - | `runtime/src/lib.rs` |
| Full Client Types | ✅ DEFINED | - | `node/src/substrate/client.rs` |
| Block Import Pipeline | ✅ DEFINED | Blake3 | `node/src/substrate/pow_block_import.rs` |
| Transaction Pool | ⚠️ MOCK ONLY | - | `node/src/substrate/client.rs` |
| Mining Worker | ✅ PRODUCTION | Blake3 | `node/src/substrate/mining_worker.rs` |
| RPC Extensions | ⚠️ PARTIAL | - | `node/src/substrate/rpc/` |
| Wallet RPC Client | ✅ COMPILES | - | `wallet/src/substrate_rpc.rs` |
| Dashboard (Polkadot.js) | ✅ COMPILES | - | `dashboard-ui/src/api/substrate.ts` |
| Shielded Pool Pallet | ✅ COMPILES | STARK, Poseidon | `pallets/shielded-pool/` |
| Identity Pallet (PQ) | ✅ COMPILES | ML-DSA-65 | `pallets/identity/src/lib.rs` |

### Test Results

```bash
# All tests passing
cargo test -p pallet-shielded-pool
# Result: 53 passed

cargo test -p pq-noise  
# Result: 13 passed

cargo test -p network
# Result: 10 passed

cargo check -p hegemon-node
# Result: SUCCESS
```

---

## 🔴 PHASE 11.5-11.8: CRITICAL PATH TO FUNCTIONAL NODE

**These tasks MUST be completed before the node is usable for real transactions.**

### Phase 11.5: Wire Real Substrate Client 🔴 NOT STARTED

**Goal**: Replace `new_full()` scaffold mode with `new_full_with_client()` production mode.

**Current Problem**: `service.rs` line 1061 `new_full()` uses:
- `MockTransactionPool` instead of `sc-transaction-pool`
- Mock state execution (Blake3 hash) instead of runtime WASM execution
- `BlockImportTracker` instead of real `PowBlockImport`

**File**: `node/src/substrate/service.rs`

#### Task 11.5.1: Switch to new_full_with_client() 🔴

**Current code path** (`new_full()`):
```rust
// line 1117 - Mock transaction pool
let mock_pool = Arc::new(MockTransactionPool::new(pool_config.capacity));

// line 1390 - Mock state execution
chain_state.set_execute_extrinsics_fn(move |parent_hash, block_number, extrinsics| {
    // Mock state execution - DOES NOT EXECUTE RUNTIME
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"state_root_v1");
    // ... returns fake state root
});
```

**Required change**:
```rust
// Use new_full_with_client() which creates real client
pub async fn new_full(config: Configuration) -> Result<TaskManager, ServiceError> {
    // Call the production version instead
    new_full_with_client(config).await
}
```

**Verification**:
- [ ] `new_full_with_client()` is called instead of scaffold `new_full()`
- [ ] `PartialComponentsWithClient` returned (has real client, pool, etc.)

---

#### Task 11.5.2: Wire Real Transaction Pool 🔴

**Current**: `MockTransactionPool` - accepts txs, never validates, loses them

**Required**:
```rust
// In new_full_with_client(), transaction_pool is already created:
let PartialComponentsWithClient {
    transaction_pool,  // <-- This is the real sc-transaction-pool
    ...
} = new_partial_with_client(&config)?;

// Wire to ProductionChainStateProvider
let pool_for_pending = transaction_pool.clone();
chain_state.set_pending_txs_fn(move || {
    pool_for_pending.ready()
        .map(|tx| tx.data().encode())
        .collect()
});
```

**Verification**:
- [ ] Transactions submitted via RPC appear in pool
- [ ] Invalid transactions rejected by runtime
- [ ] Pool persists transactions across restarts

---

#### Task 11.5.3: Wire Real State Execution 🔴

**Current**: Mock hash computation, runtime never executed

**Required** (code exists at line 1365, commented):
```rust
// Wire BlockBuilder API for real runtime execution
wire_block_builder_api(&client, &mut chain_state);
```

This uses the runtime to:
1. `initialize_block()` - Set up block execution context
2. `apply_extrinsic()` - Execute each transaction
3. `finalize_block()` - Compute real state root

**Verification**:
- [ ] State root changes when transactions included
- [ ] Invalid transactions fail at execution
- [ ] Balances actually change in storage

---

#### Task 11.5.4: Wire Real Block Import 🔴

**Current**: `BlockImportTracker` - tracks stats but doesn't store blocks

**Required** (code exists at line 1482, commented):
```rust
// Create real PoW block import pipeline
let pow_block_import = sc_consensus_pow::PowBlockImport::new(
    client.clone(),
    client.clone(),
    pow_algorithm.clone(),
    0,  // check_inherents_after
    select_chain.clone(),
);

// Wire to chain state
let import = pow_block_import.clone();
chain_state.set_import_fn(move |template, seal| {
    import.import_block(construct_block(template, seal), ...)
});
```

**Verification**:
- [ ] Mined blocks stored in RocksDB
- [ ] Blocks retrievable via RPC after restart
- [ ] `chain_getBlock` returns real block data

---

### Phase 11.6: Chain Sync 🔴 NOT STARTED

**Goal**: New peers can download and verify full chain history.

#### Task 11.6.1: Block Request Handler 🔴

Respond to `BlockRequest` messages from peers:
```rust
impl NetworkBridge {
    fn handle_block_request(&self, peer: PeerId, request: BlockRequest) {
        let blocks = self.client.block_range(request.from, request.to);
        self.send_to_peer(peer, BlockResponse { blocks });
    }
}
```

#### Task 11.6.2: Chain Sync State Machine 🔴

Implement sync strategy:
```rust
enum SyncState {
    Idle,
    Downloading { target_height: u64, peer: PeerId },
    Importing { queue: Vec<Block> },
    Synced,
}
```

#### Task 11.6.3: Warp Sync (Optional) 🔴

For faster sync, implement finality proof downloading.

---

### Phase 11.7: RPC Service Wiring 🔴 NOT STARTED

**Goal**: RPC endpoints connect to real runtime, not mocks.

#### Task 11.7.1: Create Production RPC Service 🔴

**Current**: RPC traits (HegemonService, WalletService, ShieldedPoolService) only have mock implementations.

**Required**:
```rust
/// Production implementation connecting to real Substrate client
pub struct ProductionRpcService<C, Block> {
    client: Arc<C>,
    pool: Arc<TransactionPool>,
}

impl<C, Block> HegemonService for ProductionRpcService<C, Block>
where
    C: ProvideRuntimeApi<Block>,
    C::Api: ShieldedPoolApi<Block> + DifficultyApi<Block>,
{
    fn consensus_status(&self) -> ConsensusStatus {
        let api = self.client.runtime_api();
        let best = self.client.info().best_hash;
        ConsensusStatus {
            difficulty: api.difficulty_bits(best).unwrap_or(DEFAULT_DIFFICULTY),
            height: self.client.info().best_number,
            ...
        }
    }
}

impl<C, Block> WalletService for ProductionRpcService<C, Block> { ... }
impl<C, Block> ShieldedPoolService for ProductionRpcService<C, Block> { ... }
```

#### Task 11.7.2: Wire to RPC Server 🔴

```rust
// In new_full_with_client():
let rpc_service = Arc::new(ProductionRpcService::new(client.clone(), transaction_pool.clone()));

let rpc_deps = FullDeps {
    service: rpc_service,
    pow_handle: pow_handle.clone(),
};

let rpc_module = rpc::create_full(rpc_deps)?;
```

#### Task 11.7.3: Wire Extrinsic Submission 🔴

**Current**: `submit_shielded_transfer()` returns error

**Required**:
```rust
fn submit_shielded_transfer(&self, ...) -> Result<TxHash, RpcError> {
    // Build extrinsic
    let call = pallet_shielded_pool::Call::shielded_transfer { proof, nullifiers, ... };
    let ext = UncheckedExtrinsic::new_unsigned(call.into());
    
    // Submit to pool
    let hash = self.pool.submit_one(ext)?;
    Ok(hash)
}
```

---

### Phase 11.8: Integration Verification 🔴 NOT STARTED

**Goal**: End-to-end verification that everything works together.

#### Task 11.8.1: Single Node Smoke Test 🔴

```bash
# Start node
HEGEMON_MINE=1 cargo run -p hegemon-node --features substrate -- --dev

# Verify:
# 1. Blocks are mined and stored
curl -X POST -d '{"jsonrpc":"2.0","method":"chain_getBlock","params":[],"id":1}' http://localhost:9944

# 2. Pool accepts transactions
curl -X POST -d '{"jsonrpc":"2.0","method":"author_submitExtrinsic","params":["0x..."],"id":1}' http://localhost:9944

# 3. Balances change
curl -X POST -d '{"jsonrpc":"2.0","method":"state_getStorage","params":["0x..."],"id":1}' http://localhost:9944
```

#### Task 11.8.2: Two Node Sync Test 🔴

```bash
# Node 1 mines blocks
# Node 2 connects and syncs
# Verify Node 2 has same chain state as Node 1
```

#### Task 11.8.3: Shielded Transaction E2E 🔴

```bash
# 1. Shield funds
# 2. Build STARK proof
# 3. Submit shielded transfer
# 4. Verify nullifier spent
# 5. Verify recipient can scan note
```

---

## Production Path: Pallet Implementation Phases

**Note**: These phases describe the PALLET CODE which compiles and passes tests.
The pallets are NOT EXECUTED at runtime until Phase 11.5-11.8 are complete.

### Phase 12: Shielded Pool Pallet ✅ CODE COMPLETE (not wired)

**Goal**: Implement the core shielded transaction pallet with note commitments, nullifiers, and Merkle tree.

**Status**: Code complete, tests pass. **NOT EXECUTED** - requires Phase 11.5 to wire runtime.

---

#### Task 12.2: Merkle Tree Storage ✅ COMPLETE

**Crypto**: Poseidon hash (STARK-friendly)

**Storage**:
```rust
#[pallet::storage]
pub type MerkleTree<T> = StorageValue<_, CompactMerkleTree, ValueQuery>;

#[pallet::storage]
pub type MerkleRoots<T> = StorageMap<_, Blake2_128Concat, u32, [u8; 32]>;
```

**Properties**:
- Depth: 32 (supports ~4 billion notes)
- Hash: **Poseidon** (STARK-friendly, no pairings)
- Incremental append-only structure

---

#### Task 12.3: Nullifier Set ✅ COMPLETE

**Crypto**: Poseidon hash

**Nullifier Computation**:
```rust
/// nullifier = Poseidon(nsk || position || cm)
/// where nsk is derived from ML-DSA spending key
pub fn compute_nullifier(nsk: &[u8; 32], position: u32, cm: &[u8; 32]) -> [u8; 32];
```

---

#### Task 12.4: Shielded Transfer Extrinsic ✅ COMPLETE

**Crypto**: STARK proofs (no Groth16)

**Extrinsic Structure**:
```rust
#[pallet::call]
impl<T: Config> Pallet<T> {
    pub fn shielded_transfer(
        origin: OriginFor<T>,
        /// STARK proof (FRI-based, variable size ~20-50 KB)
        proof: StarkProof,
        /// Nullifiers for spent notes
        nullifiers: BoundedVec<[u8; 32], T::MaxNullifiers>,
        /// New note commitments
        commitments: BoundedVec<[u8; 32], T::MaxCommitments>,
        /// Encrypted notes for recipients (ML-KEM encrypted)
        encrypted_notes: BoundedVec<EncryptedNote, T::MaxCommitments>,
        /// Merkle root the proof was generated against
        anchor: [u8; 32],
        /// Binding signature (ML-DSA-65)
        binding_sig: MlDsaSignature,
    ) -> DispatchResult;
}
```

**STARK Proof Structure**:
```rust
pub struct StarkProof {
    /// FRI commitment layers
    pub fri_commitments: Vec<[u8; 32]>,
    /// FRI query responses
    pub fri_queries: Vec<FriQueryResponse>,
    /// Trace commitment
    pub trace_commitment: [u8; 32],
    /// Constraint polynomial commitment
    pub constraint_commitment: [u8; 32],
    /// DEEP composition polynomial evaluations
    pub deep_evaluations: Vec<GoldilocksField>,
    /// Proof of work nonce (grinding, optional)
    pub pow_nonce: Option<u64>,
}
```

**Verification Logic**:
1. Check anchor is a valid historical root
2. Check nullifiers not in spent set
3. **Verify STARK proof** (FRI verification, hash-based soundness)
4. Verify binding signature (ML-DSA-65)
5. Add nullifiers to spent set
6. Add commitments to Merkle tree

---

#### Task 12.5: STARK Circuit Integration ✅ COMPLETE

**Dependencies**:
- `circuits/transaction/` - STARK circuits (AIR constraints)
- `crypto/src/` - PQ crypto primitives

**STARK Verifier**:
```rust
pub fn verify_stark(
    proof: &StarkProof,
    public_inputs: &StarkPublicInputs,
    verifying_key: &StarkVerifyingKey,
) -> Result<bool, VerificationError> {
    // 1. Verify FRI proximity proof (hash-based)
    // 2. Check constraint polynomial evaluations
    // 3. Verify DEEP composition
    // 4. No pairings, no ECC, pure hash operations
}
```

**Public Inputs**:
```rust
pub struct StarkPublicInputs {
    pub merkle_root: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub value_balance: i64,
}
```

---

### Phase 13: Shielded Wallet Integration 🟡 IN PROGRESS

**Goal**: Update wallet to generate STARK proofs and interact with shielded pool.

**Crypto Requirements**:
- STARK prover (CPU-friendly, no trusted setup)
- ML-KEM-768 for note encryption
- ML-DSA-65 for binding signatures

**Status**: Core implementation complete, integration testing needed.

#### Task 13.1: Note Scanning ✅ COMPLETE

**Goal**: Wallet scans encrypted notes to find owned notes.

**Crypto**: ML-KEM-768 decapsulation

**Implementation**:
- Created `wallet/src/scanner.rs` with `NoteScanner` and `SharedScanner`
- `ScannerConfig` for configurable scanning parameters
- `PositionedNote` and `ScannedNote` types for note tracking
- Trial decryption using ML-KEM viewing keys
- Batch scanning with performance statistics

**Files Created**:
- `wallet/src/scanner.rs` - Note scanning service

---

#### Task 13.2: STARK Proof Generation ✅ COMPLETE

**Goal**: Generate STARK proofs for shielded transfers.

**Files Created**:
- `wallet/src/prover.rs` - STARK prover wrapper

**Implementation**:
```rust
pub struct StarkProver {
    config: StarkProverConfig,
    proving_key: ProvingKey,
    verifying_key: CircuitVerifyingKey,
}

impl StarkProver {
    pub fn prove(&self, witness: &TransactionWitness) -> Result<ProofResult, WalletError>;
    pub fn verify(&self, proof: &TransactionProof) -> Result<bool, WalletError>;
}
```

**Features**:
- Configurable FRI parameters (blowup factor, query count)
- Support for proof grinding (optional)
- Proof serialization/deserialization
- Prover statistics tracking

---

#### Task 13.3: Transaction Building ✅ COMPLETE

**Goal**: Build complete shielded transactions with PQ primitives.

**Files Created**:
- `wallet/src/shielded_tx.rs` - Shielded transaction builder

**Implementation**:
```rust
pub struct ShieldedTxBuilder<'a> {
    store: &'a WalletStore,
    prover: &'a StarkProver,
    outputs: Vec<ShieldedOutput>,
}

impl ShieldedTxBuilder {
    pub fn add_output(&mut self, output: ShieldedOutput) -> Result<&mut Self, WalletError>;
    pub fn build(self, fee: u64) -> Result<BuiltShieldedTx, WalletError>;
}
```

**Transaction Building Flow**:
1. Select input notes (sufficient value)
2. Generate randomness for outputs (CSPRNG)
3. Compute nullifiers (via FullViewingKey)
4. Build STARK witness (trace data)
5. Generate STARK proof (FRI prover)
6. Encrypt output notes (ML-KEM-768)
7. Return complete transaction bundle

---

#### Task 13.4: RPC Integration ✅ COMPLETE

**Goal**: New RPC endpoints for shielded transactions.

**Files Created**:
- `node/src/substrate/rpc/shielded.rs` - Shielded pool RPC endpoints

**New RPC Endpoints**:
- `hegemon_submitShieldedTransfer` - Submit shielded tx with STARK proof
- `hegemon_getEncryptedNotes` - Fetch ML-KEM encrypted notes
- `hegemon_getMerkleWitness` - Get Poseidon Merkle path for note
- `hegemon_getShieldedPoolStatus` - Get pool statistics
- `hegemon_shield` - Shield transparent funds
- `hegemon_isNullifierSpent` - Check nullifier status
- `hegemon_isValidAnchor` - Validate Merkle root anchor

**Wallet Module Updates**:
- Updated `wallet/src/lib.rs` to export new modules
- Added `Default` impl for `ShieldedAddress`
- Added `Default` impl for `TransactionPublicInputs`

---

### Phase 14: End-to-End Transaction Flow 🟡 IN PROGRESS

**Goal**: Complete shielded transaction from wallet to block, with E2E tests.

#### Task 14.1: Pallet Integration & Service Implementation ✅ COMPLETE

**Goal**: Integrate `pallet-shielded-pool` into runtime and implement `ShieldedPoolService` trait.

**Files Modified**:
- `runtime/Cargo.toml` - Added `pallet-shielded-pool` dependency
- `runtime/src/lib.rs` - Added pallet Config and `construct_runtime!` entry
- `runtime/src/chain_spec.rs` - Added `ShieldedPoolConfig` to genesis
- `node/src/substrate/rpc/shielded_service.rs` - Production + Mock implementations

**Pallet Integration**:
```rust
// runtime/src/lib.rs
impl pallet_shielded_pool::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type AdminOrigin = frame_system::EnsureRoot<AccountId>;
    type ProofVerifier = pallet_shielded_pool::verifier::StarkVerifier;
    type MaxNullifiersPerTx = ConstU32<4>;
    type MaxCommitmentsPerTx = ConstU32<4>;
    type MaxEncryptedNotesPerTx = ConstU32<4>;
    type MerkleRootHistorySize = ConstU32<100>;
    type WeightInfo = pallet_shielded_pool::DefaultWeightInfo;
}

construct_runtime!(
    pub enum Runtime {
        // ... other pallets ...
        ShieldedPool: pallet_shielded_pool::{Pallet, Call, Storage, Event<T>, Config<T>},
    }
);
```

**Service Implementation**:
```rust
/// Production implementation connecting to runtime API
pub struct ShieldedPoolServiceImpl<C, Block>

/// Mock implementation for testing  
pub struct MockShieldedPoolService
```

**Runtime API Implementation** (now uses real pallet storage):
- `get_encrypted_notes()` - Queries `EncryptedNotes` and `Commitments` storage
- `get_merkle_witness()` - Generates witness from `MerkleTree` frontier
- `is_nullifier_spent()` - Queries `Nullifiers` storage map
- `is_valid_anchor()` - Queries `MerkleRoots` historical anchors
- `pool_balance()` - Queries `PoolBalance` storage
- `merkle_root()` - Gets root from `MerkleTree` storage
- `nullifier_count()` - Counts entries in `Nullifiers` storage

**Additional Fixes Applied**:
- Added `BLOCK_ANNOUNCES_LEGACY`, `TRANSACTIONS_LEGACY`, `SYNC_LEGACY` protocol constants
- Fixed `MockShieldedPoolService` to use `std::sync::RwLock`
- Added `serde` unconditionally to `pallet-shielded-pool` for genesis deserialization
- Added `sp_std::vec` import for WASM builds

---

#### Task 14.2: E2E Test Suite 🔴 NOT STARTED

**Goal**: Comprehensive end-to-end test coverage for shielded transactions.

**Test Scenarios**:
1. Transparent → Shielded (shield)
2. Shielded → Shielded (private transfer with STARK)
3. Shielded → Transparent (unshield)
4. Multi-input multi-output STARK proof
5. Invalid STARK proof rejection
6. Double-spend rejection
7. **NO ECC/Groth16 anywhere in test suite**

##### Protocol 14.2.1: Create E2E Test Infrastructure

**File to Create**: `tests/shielded_e2e.rs`

**Step 1: Test Node Harness**
```rust
use hegemon_node::substrate::{service::new_full, client::FullClient};
use sp_keyring::AccountKeyring;
use std::sync::Arc;

/// Test harness for E2E shielded pool testing
pub struct TestNode {
    client: Arc<FullClient>,
    task_manager: TaskManager,
}

impl TestNode {
    pub async fn new() -> Self {
        let config = Configuration::default_dev();
        let (client, task_manager) = new_full(config).await.unwrap();
        Self { client, task_manager }
    }
    
    pub async fn mine_blocks(&self, n: u32) -> Result<(), Error>;
    pub fn client(&self) -> Arc<FullClient>;
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.task_manager.terminate();
    }
}
```

**Step 2: Wallet Test Fixture**
```rust
use wallet::{WalletStore, SpendingKey, ViewingKey, scanner::NoteScanner};

pub struct TestWallet {
    store: WalletStore,
    spending_key: SpendingKey,
    viewing_key: ViewingKey,
    scanner: NoteScanner,
}

impl TestWallet {
    pub fn new_random() -> Self {
        let spending_key = SpendingKey::random();
        let viewing_key = spending_key.viewing_key();
        // ... setup
    }
    
    pub fn address(&self) -> ShieldedAddress;
    pub async fn scan_notes(&mut self, from_height: u32) -> Vec<ScannedNote>;
    pub fn balance(&self) -> u64;
}
```

**Step 3: STARK Proof Test Utilities**
```rust
use wallet::prover::StarkProver;
use pallet_shielded_pool::{StarkProof, TransactionWitness};

pub fn generate_test_proof(
    inputs: &[ScannedNote],
    outputs: &[ShieldedOutput],
    anchor: [u8; 32],
) -> Result<StarkProof, ProverError> {
    let prover = StarkProver::new_test_config();
    let witness = TransactionWitness::build(inputs, outputs, anchor)?;
    prover.prove(&witness)
}

pub fn create_invalid_proof() -> StarkProof {
    // Returns a malformed STARK proof for rejection testing
    StarkProof {
        fri_commitments: vec![[0u8; 32]; 5],
        fri_queries: vec![],
        trace_commitment: [0u8; 32],
        constraint_commitment: [0u8; 32],
        deep_evaluations: vec![],
        pow_nonce: None,
    }
}
```

**Verification Checklist**:
- [ ] `cargo test -p tests --test shielded_e2e` compiles
- [ ] Test node starts and mines blocks
- [ ] Wallet fixture generates valid keys
- [ ] Test prover generates verifiable STARK proofs

---

##### Protocol 14.2.2: Shield Transaction Test

**Test**: `test_shield_transparent_to_shielded`

```rust
#[tokio::test]
async fn test_shield_transparent_to_shielded() {
    // SETUP
    let node = TestNode::new().await;
    let wallet = TestWallet::new_random();
    let alice = AccountKeyring::Alice.to_account_id();
    
    // 1. Ensure Alice has transparent balance
    let initial_balance = node.query_balance(&alice).await;
    assert!(initial_balance >= 1_000_000);
    
    // 2. Build shield extrinsic
    let shield_amount = 500_000u64;
    let shield_address = wallet.address();
    let extrinsic = node.build_shield_extrinsic(
        &alice,
        shield_amount,
        &shield_address,
    ).await;
    
    // 3. Submit and wait for inclusion
    let block_hash = node.submit_and_wait(&extrinsic).await?;
    
    // 4. Verify transparent balance decreased
    let final_balance = node.query_balance(&alice).await;
    assert_eq!(final_balance, initial_balance - shield_amount);
    
    // 5. Verify pool balance increased
    let pool_balance = node.query_pool_balance().await;
    assert_eq!(pool_balance, shield_amount);
    
    // 6. Verify note commitment added to Merkle tree
    let root = node.query_merkle_root().await;
    assert_ne!(root, [0u8; 32]);
    
    // 7. Scan and verify wallet received note
    let notes = wallet.scan_notes(0).await;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].value, shield_amount);
    
    // 8. NO ECC CHECK
    // Verify no Ed25519, X25519, or secp256k1 in transaction
}
```

**Verification Checklist**:
- [ ] Shield extrinsic accepted by runtime
- [ ] Transparent balance debited
- [ ] Pool balance credited
- [ ] Merkle tree updated
- [ ] Wallet can scan and decrypt note (ML-KEM)

---

##### Protocol 14.2.3: Shielded Transfer Test

**Test**: `test_shielded_to_shielded_transfer`

```rust
#[tokio::test]
async fn test_shielded_to_shielded_transfer() {
    // SETUP
    let node = TestNode::new().await;
    let sender = TestWallet::new_random();
    let recipient = TestWallet::new_random();
    
    // 1. Shield funds to sender (prerequisite)
    node.shield_to(&sender, 1_000_000).await;
    let sender_notes = sender.scan_notes(0).await;
    assert_eq!(sender_notes.len(), 1);
    
    // 2. Build shielded transfer
    let transfer_amount = 400_000u64;
    let anchor = node.query_merkle_root().await;
    let merkle_witness = node.query_merkle_witness(sender_notes[0].position).await;
    
    // 3. Generate STARK proof
    let proof = generate_test_proof(
        &sender_notes,
        &[ShieldedOutput::new(recipient.address(), transfer_amount)],
        anchor,
    )?;
    
    // 4. Build transfer extrinsic
    let nullifiers = vec![sender_notes[0].nullifier(&sender.spending_key)];
    let commitments = vec![proof.output_commitments[0]];
    let encrypted_notes = vec![proof.encrypted_notes[0].clone()];
    
    let extrinsic = node.build_shielded_transfer_extrinsic(
        proof,
        nullifiers.clone(),
        commitments,
        encrypted_notes,
        anchor,
    ).await;
    
    // 5. Submit and wait
    node.submit_and_wait(&extrinsic).await?;
    
    // 6. Verify nullifier spent
    assert!(node.is_nullifier_spent(&nullifiers[0]).await);
    
    // 7. Verify sender can't spend again (double-spend protection)
    let second_proof = generate_test_proof(
        &sender_notes, // same notes
        &[ShieldedOutput::new(recipient.address(), 100_000)],
        node.query_merkle_root().await,
    )?;
    let result = node.submit_shielded_transfer(second_proof, nullifiers).await;
    assert!(result.is_err()); // Should fail: nullifier already spent
    
    // 8. Verify recipient can scan note
    let recipient_notes = recipient.scan_notes(0).await;
    assert_eq!(recipient_notes.len(), 1);
    assert_eq!(recipient_notes[0].value, transfer_amount);
    
    // 9. Pool balance unchanged (shielded-to-shielded)
    let pool_balance = node.query_pool_balance().await;
    assert_eq!(pool_balance, 1_000_000);
}
```

**Verification Checklist**:
- [ ] STARK proof verifies on-chain
- [ ] Nullifier marked as spent
- [ ] Double-spend rejected
- [ ] Recipient can decrypt note (ML-KEM)
- [ ] Pool balance unchanged

---

##### Protocol 14.2.4: Unshield Test

**Test**: `test_unshield_to_transparent`

```rust
#[tokio::test]
async fn test_unshield_to_transparent() {
    // SETUP
    let node = TestNode::new().await;
    let wallet = TestWallet::new_random();
    let bob = AccountKeyring::Bob.to_account_id();
    
    // 1. Shield funds first
    node.shield_to(&wallet, 1_000_000).await;
    let notes = wallet.scan_notes(0).await;
    
    // 2. Build unshield proof (value_balance > 0 reveals value)
    let unshield_amount = 600_000u64;
    let anchor = node.query_merkle_root().await;
    
    let proof = generate_unshield_proof(
        &notes,
        unshield_amount,
        &bob, // transparent recipient
        anchor,
    )?;
    
    // 3. Submit unshield
    let initial_bob_balance = node.query_balance(&bob).await;
    node.submit_unshield(&proof, unshield_amount, &bob).await?;
    
    // 4. Verify Bob received transparent funds
    let final_bob_balance = node.query_balance(&bob).await;
    assert_eq!(final_bob_balance, initial_bob_balance + unshield_amount);
    
    // 5. Verify pool balance decreased
    let pool_balance = node.query_pool_balance().await;
    assert_eq!(pool_balance, 1_000_000 - unshield_amount);
    
    // 6. Verify nullifier spent
    let nullifier = notes[0].nullifier(&wallet.spending_key);
    assert!(node.is_nullifier_spent(&nullifier).await);
}
```

---

##### Protocol 14.2.5: Invalid Proof Rejection Test

**Test**: `test_invalid_stark_proof_rejected`

```rust
#[tokio::test]
async fn test_invalid_stark_proof_rejected() {
    let node = TestNode::new().await;
    let wallet = TestWallet::new_random();
    
    // Shield funds
    node.shield_to(&wallet, 1_000_000).await;
    let notes = wallet.scan_notes(0).await;
    
    // 1. Create invalid STARK proof
    let invalid_proof = create_invalid_proof();
    let anchor = node.query_merkle_root().await;
    
    let result = node.submit_shielded_transfer(
        invalid_proof,
        vec![notes[0].nullifier(&wallet.spending_key)],
    ).await;
    
    // 2. Verify rejection
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::ProofVerificationFailed
    ));
    
    // 3. Verify nullifier NOT spent (tx failed)
    let nullifier = notes[0].nullifier(&wallet.spending_key);
    assert!(!node.is_nullifier_spent(&nullifier).await);
}
```

---

##### Protocol 14.2.6: Multi-Input Multi-Output Test

**Test**: `test_multi_input_multi_output`

```rust
#[tokio::test]
async fn test_multi_input_multi_output() {
    let node = TestNode::new().await;
    let sender = TestWallet::new_random();
    let recipient1 = TestWallet::new_random();
    let recipient2 = TestWallet::new_random();
    
    // 1. Create multiple input notes
    node.shield_to(&sender, 500_000).await;
    node.shield_to(&sender, 300_000).await;
    node.shield_to(&sender, 200_000).await;
    let notes = sender.scan_notes(0).await;
    assert_eq!(notes.len(), 3);
    
    // 2. Build multi-input multi-output transfer
    let anchor = node.query_merkle_root().await;
    let outputs = vec![
        ShieldedOutput::new(recipient1.address(), 600_000),
        ShieldedOutput::new(recipient2.address(), 400_000),
    ];
    
    let proof = generate_test_proof(&notes, &outputs, anchor)?;
    
    // 3. Submit
    let nullifiers: Vec<_> = notes.iter()
        .map(|n| n.nullifier(&sender.spending_key))
        .collect();
    
    node.submit_shielded_transfer(proof, nullifiers.clone()).await?;
    
    // 4. Verify all nullifiers spent
    for nf in &nullifiers {
        assert!(node.is_nullifier_spent(nf).await);
    }
    
    // 5. Verify recipients received notes
    let r1_notes = recipient1.scan_notes(0).await;
    let r2_notes = recipient2.scan_notes(0).await;
    assert_eq!(r1_notes[0].value, 600_000);
    assert_eq!(r2_notes[0].value, 400_000);
}
```

**Verification Checklist**:
- [ ] STARK proof handles 3 inputs, 2 outputs
- [ ] All 3 nullifiers marked spent
- [ ] Both recipients can scan notes
- [ ] Total value preserved (1M in, 1M out)

---

#### Task 14.3: Integration Tests 🔴 NOT STARTED

**Goal**: Full integration testing with real RPC calls.

##### Protocol 14.3.1: RPC Integration Test Setup

**File to Create**: `tests/rpc_integration.rs`

```rust
use jsonrpsee::{http_client::HttpClient, rpc_params};
use hegemon_node::substrate::rpc::shielded::ShieldedPoolRpc;

pub struct RpcTestClient {
    client: HttpClient,
    base_url: String,
}

impl RpcTestClient {
    pub async fn new(port: u16) -> Self {
        let base_url = format!("http://127.0.0.1:{}", port);
        let client = HttpClient::builder()
            .build(&base_url)
            .unwrap();
        Self { client, base_url }
    }
    
    pub async fn get_encrypted_notes(&self, from: u32, to: u32) 
        -> Result<Vec<EncryptedNote>, Error> 
    {
        self.client.request(
            "hegemon_getEncryptedNotes",
            rpc_params![from, to],
        ).await
    }
    
    pub async fn get_merkle_witness(&self, position: u32) 
        -> Result<MerkleWitness, Error>
    {
        self.client.request(
            "hegemon_getMerkleWitness",
            rpc_params![position],
        ).await
    }
    
    pub async fn submit_shielded_transfer(&self, tx: ShieldedTransaction)
        -> Result<TxHash, Error>
    {
        self.client.request(
            "hegemon_submitShieldedTransfer",
            rpc_params![tx],
        ).await
    }
    
    pub async fn is_nullifier_spent(&self, nf: [u8; 32]) -> Result<bool, Error> {
        self.client.request(
            "hegemon_isNullifierSpent",
            rpc_params![hex::encode(nf)],
        ).await
    }
    
    pub async fn get_pool_status(&self) -> Result<PoolStatus, Error> {
        self.client.request(
            "hegemon_getShieldedPoolStatus",
            rpc_params![],
        ).await
    }
}
```

---

##### Protocol 14.3.2: Full RPC Flow Test

**Test**: `test_full_rpc_shielded_flow`

```rust
#[tokio::test]
async fn test_full_rpc_shielded_flow() {
    // 1. Start node with RPC enabled
    let node = TestNode::new_with_rpc(9944).await;
    let rpc = RpcTestClient::new(9944).await;
    
    // 2. Get initial pool status
    let status = rpc.get_pool_status().await?;
    assert_eq!(status.pool_balance, 0);
    assert_eq!(status.note_count, 0);
    
    // 3. Shield funds via RPC
    let wallet = TestWallet::new_random();
    let shield_result = rpc.shield(
        AccountKeyring::Alice.to_account_id(),
        1_000_000,
        wallet.address(),
    ).await?;
    
    // 4. Mine block to include transaction
    node.mine_blocks(1).await;
    
    // 5. Fetch encrypted notes via RPC
    let notes = rpc.get_encrypted_notes(0, 100).await?;
    assert_eq!(notes.len(), 1);
    
    // 6. Wallet decrypts note (ML-KEM)
    let decrypted = wallet.try_decrypt(&notes[0]);
    assert!(decrypted.is_some());
    assert_eq!(decrypted.unwrap().value, 1_000_000);
    
    // 7. Get Merkle witness via RPC
    let witness = rpc.get_merkle_witness(0).await?;
    assert_eq!(witness.path.len(), 32); // depth 32
    
    // 8. Build transfer using RPC-fetched data
    let recipient = TestWallet::new_random();
    let proof = wallet.build_transfer_proof(
        &[decrypted.unwrap()],
        &[ShieldedOutput::new(recipient.address(), 500_000)],
        witness,
        status.merkle_root,
    )?;
    
    // 9. Submit via RPC
    let tx_hash = rpc.submit_shielded_transfer(proof.into()).await?;
    node.mine_blocks(1).await;
    
    // 10. Verify nullifier spent via RPC
    let nf = wallet.compute_nullifier(&decrypted.unwrap());
    assert!(rpc.is_nullifier_spent(nf).await?);
    
    // 11. Verify pool status updated
    let final_status = rpc.get_pool_status().await?;
    assert_eq!(final_status.note_count, 2); // change note + recipient note
}
```

---

##### Protocol 14.3.3: Concurrent RPC Test

**Test**: `test_concurrent_rpc_submissions`

```rust
#[tokio::test]
async fn test_concurrent_rpc_submissions() {
    let node = TestNode::new_with_rpc(9945).await;
    let rpc = RpcTestClient::new(9945).await;
    
    // Create 5 wallets with shielded funds
    let wallets: Vec<TestWallet> = (0..5)
        .map(|_| TestWallet::new_random())
        .collect();
    
    for wallet in &wallets {
        rpc.shield(AccountKeyring::Alice.to_account_id(), 1_000_000, wallet.address()).await?;
    }
    node.mine_blocks(1).await;
    
    // Scan notes for each wallet
    for wallet in &mut wallets {
        wallet.scan_notes(0).await;
    }
    
    // Submit 5 concurrent transfers
    let recipient = TestWallet::new_random();
    let futures: Vec<_> = wallets.iter().map(|wallet| {
        let rpc = rpc.clone();
        let recipient_addr = recipient.address();
        async move {
            let proof = wallet.build_simple_transfer(recipient_addr, 500_000)?;
            rpc.submit_shielded_transfer(proof.into()).await
        }
    }).collect();
    
    let results = futures::future::join_all(futures).await;
    
    // All should succeed (no conflicts, different nullifiers)
    for result in results {
        assert!(result.is_ok());
    }
    
    node.mine_blocks(1).await;
    
    // Recipient should have 5 notes
    let recipient_notes = recipient.scan_notes(0).await;
    assert_eq!(recipient_notes.len(), 5);
}
```

---

##### Protocol 14.3.4: Extrinsic Submission Implementation

**Goal**: Wire actual extrinsic construction for `submit_shielded_transfer` and `shield` RPC methods.

**File to Modify**: `node/src/substrate/rpc/shielded_service.rs`

**Current State**: Methods return `Err("Use author_submitExtrinsic...")`

**Required Implementation**:

```rust
impl<C, Block> ShieldedPoolService for ShieldedPoolServiceImpl<C, Block>
where
    C: ProvideRuntimeApi<Block> + Send + Sync + 'static,
    C::Api: ShieldedPoolApi<Block>,
    Block: BlockT,
{
    async fn submit_shielded_transfer(
        &self,
        proof: StarkProof,
        nullifiers: Vec<[u8; 32]>,
        commitments: Vec<[u8; 32]>,
        encrypted_notes: Vec<EncryptedNote>,
        anchor: [u8; 32],
        binding_sig: Vec<u8>,
    ) -> Result<TxHash, RpcError> {
        // 1. Encode call
        let call = pallet_shielded_pool::Call::<Runtime>::shielded_transfer {
            proof: proof.into(),
            nullifiers: nullifiers.try_into().map_err(|_| RpcError::InvalidParams)?,
            commitments: commitments.try_into().map_err(|_| RpcError::InvalidParams)?,
            encrypted_notes: encrypted_notes.try_into().map_err(|_| RpcError::InvalidParams)?,
            anchor,
            binding_sig: binding_sig.try_into().map_err(|_| RpcError::InvalidSignature)?,
        };
        
        // 2. Build extrinsic (unsigned, shielded txs don't need origin)
        let ext = UncheckedExtrinsic::new_unsigned(call.into());
        
        // 3. Submit to transaction pool
        let pool = self.pool.clone();
        let hash = pool.submit_one(
            &BlockId::Hash(self.client.info().best_hash),
            TransactionSource::External,
            ext,
        ).await.map_err(|e| RpcError::PoolError(e.to_string()))?;
        
        Ok(hash.into())
    }
    
    async fn shield(
        &self,
        from: AccountId,
        amount: u64,
        to_shielded: ShieldedAddress,
    ) -> Result<TxHash, RpcError> {
        // Shield requires signed extrinsic (transparent origin)
        // Caller must provide signature separately
        Err(RpcError::Custom(
            "shield requires signed extrinsic - use author_submitExtrinsic with \
             pallet_shielded_pool::Call::shield(amount, recipient)".into()
        ))
    }
}
```

**Verification Checklist**:
- [ ] `submit_shielded_transfer` builds valid extrinsic
- [ ] Transaction submitted to pool
- [ ] Transaction included in block
- [ ] RPC returns transaction hash

---

### Phase 15: Production Hardening 🔴 NOT STARTED

**Goal**: Security review, performance optimization, mainnet readiness.

---

#### Task 15.1: Security Audit Preparation

**Goal**: Ensure zero classical crypto vulnerabilities before mainnet.

##### Protocol 15.1.1: ECC/Pairing Dependency Audit

**Step 1: Automated Grep Scan**

```bash
#!/bin/bash
# scripts/security-audit.sh

echo "=== PQ Security Audit: Scanning for Forbidden Primitives ==="

FORBIDDEN_PATTERNS=(
    "groth16"
    "ed25519"
    "x25519"
    "ecdh"
    "ecdsa"
    "secp256k1"
    "secp256r1"
    "bls12"
    "bn254"
    "jubjub"
    "babyjubjub"
    "pallas"
    "vesta"
    "curve25519"
    "dalek"
    "ristretto"
)

VIOLATIONS=0

for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
    echo -n "Checking for '$pattern'... "
    matches=$(grep -rniE "$pattern" \
        --include="*.rs" --include="*.toml" . \
        | grep -v target/ | grep -v ".git/" | grep -v "FORBIDDEN" | grep -v "# ")
    
    if [ -n "$matches" ]; then
        echo "❌ FOUND"
        echo "$matches"
        VIOLATIONS=$((VIOLATIONS + 1))
    else
        echo "✅ Clean"
    fi
done

echo ""
if [ $VIOLATIONS -gt 0 ]; then
    echo "❌ AUDIT FAILED: $VIOLATIONS forbidden primitive(s) found"
    exit 1
else
    echo "✅ AUDIT PASSED: No forbidden primitives"
fi
```

**Step 2: Cargo.lock Dependency Audit**

```bash
# Check for ECC crate dependencies
echo "=== Checking Cargo.lock for ECC dependencies ==="

ECC_CRATES=(
    "curve25519-dalek"
    "ed25519-dalek"
    "x25519-dalek"
    "k256"
    "p256"
    "secp256k1"
    "ark-ec"
    "ark-bls12-381"
    "ark-bn254"
    "bellman"
    "halo2"
    "plonky2"  # Uses Goldilocks but has ECC support
)

for crate in "${ECC_CRATES[@]}"; do
    if grep -q "name = \"$crate\"" Cargo.lock; then
        echo "❌ VIOLATION: $crate found in Cargo.lock"
    fi
done
```

**Step 3: Runtime WASM Binary Audit**

```bash
# Ensure no ECC symbols in WASM
echo "=== Checking runtime WASM for ECC symbols ==="

wasm-objdump -x target/release/wbuild/runtime/runtime.wasm 2>/dev/null \
    | grep -iE "curve|dalek|secp|ecdsa|ed25519" \
    && echo "❌ ECC symbols in WASM" \
    || echo "✅ No ECC symbols in WASM"
```

**Verification Checklist**:
- [ ] `scripts/security-audit.sh` returns 0
- [ ] No ECC crates in `Cargo.lock`
- [ ] No ECC symbols in runtime WASM
- [ ] Manual review of `pallet-identity` (ML-DSA only)
- [ ] Manual review of `pq-noise` (ML-KEM only)

---

##### Protocol 15.1.2: STARK Soundness Verification

**Goal**: Verify FRI parameters provide 128-bit security.

**Parameter Requirements**:

| Parameter | Minimum Value | Our Config | Security |
|-----------|---------------|------------|----------|
| Field Size | 2^64 | Goldilocks (2^64 - 2^32 + 1) | ✅ |
| FRI Blowup Factor | 8 | 8 | 128-bit |
| FRI Query Count | 27 | 30 | ~135-bit |
| Hash Function | 256-bit | Blake3-256 | 128-bit |
| Trace Length | Variable | Depends on circuit | - |

**Verification Script**:

```rust
// tests/stark_soundness.rs

#[test]
fn test_fri_security_parameters() {
    use pallet_shielded_pool::verifier::StarkVerifyingKey;
    
    let vk = StarkVerifyingKey::default();
    
    // Blowup factor must be >= 8 for 128-bit security
    assert!(vk.fri_blowup_factor >= 8, 
        "FRI blowup factor {} < 8", vk.fri_blowup_factor);
    
    // Query count must be >= ceil(128 / log2(blowup))
    let min_queries = (128.0 / (vk.fri_blowup_factor as f64).log2()).ceil() as u32;
    assert!(vk.fri_query_count >= min_queries,
        "FRI query count {} < minimum {}", vk.fri_query_count, min_queries);
    
    // Verify Goldilocks field
    assert_eq!(vk.field_modulus, 0xFFFFFFFF00000001u64,
        "Not Goldilocks field");
}

#[test]
fn test_poseidon_security_margin() {
    // Poseidon should have >= 128-bit algebraic security
    // Full rounds = 8, partial rounds = 22 for Goldilocks
    use pallet_shielded_pool::merkle::PoseidonConfig;
    
    let config = PoseidonConfig::default();
    assert!(config.full_rounds >= 8);
    assert!(config.partial_rounds >= 22);
}
```

**Verification Checklist**:
- [ ] FRI blowup factor >= 8
- [ ] FRI query count >= 27
- [ ] Poseidon rounds match security requirements
- [ ] No statistical attacks on proof system

---

##### Protocol 15.1.3: ML-KEM/ML-DSA Parameter Audit

**Goal**: Verify NIST-compliant post-quantum parameters.

```rust
// tests/pq_params_audit.rs

#[test]
fn test_ml_kem_768_parameters() {
    // ML-KEM-768 (FIPS 203) parameters
    const K: usize = 3;           // Module dimension
    const N: usize = 256;         // Polynomial degree
    const Q: u16 = 3329;          // Modulus
    const ETA1: usize = 2;        // Noise parameter (keygen)
    const ETA2: usize = 2;        // Noise parameter (encrypt)
    const DU: usize = 10;         // Compression bits (u)
    const DV: usize = 4;          // Compression bits (v)
    
    // Verify our implementation matches
    use pq_noise::ml_kem::Params;
    
    let params = Params::ml_kem_768();
    assert_eq!(params.k, K);
    assert_eq!(params.n, N);
    assert_eq!(params.q, Q);
    assert_eq!(params.eta1, ETA1);
    assert_eq!(params.eta2, ETA2);
    
    // Key sizes
    assert_eq!(params.public_key_size(), 1184);   // 32 + 384*k
    assert_eq!(params.secret_key_size(), 2400);   // 768*k + public + 64
    assert_eq!(params.ciphertext_size(), 1088);   // 352*k + 32*(DV+1)
}

#[test]
fn test_ml_dsa_65_parameters() {
    // ML-DSA-65 (FIPS 204) parameters
    const K: usize = 6;           // Matrix rows
    const L: usize = 5;           // Matrix columns
    const ETA: usize = 4;         // Secret key bound
    const TAU: usize = 49;        // Challenge weight
    const GAMMA1: usize = 1 << 19; // y coefficient bound
    const GAMMA2: usize = (8380417 - 1) / 32; // Rounding range
    
    use pallets::identity::ml_dsa::Params;
    
    let params = Params::ml_dsa_65();
    assert_eq!(params.k, K);
    assert_eq!(params.l, L);
    
    // Key sizes
    assert_eq!(params.public_key_size(), 1952);
    assert_eq!(params.secret_key_size(), 4032);
    assert_eq!(params.signature_size(), 3293);
}
```

**Verification Checklist**:
- [ ] ML-KEM-768 matches FIPS 203 parameters
- [ ] ML-DSA-65 matches FIPS 204 parameters
- [ ] Key sizes correct
- [ ] No parameter downgrade attacks

---

#### Task 15.2: Performance Optimization

**Goal**: Meet benchmark targets for production viability.

##### Protocol 15.2.1: STARK Prover Optimization

**Benchmark Targets**:

| Operation | Target | Acceptable |
|-----------|--------|------------|
| STARK prove (single tx) | < 5s | < 10s |
| STARK verify (on-chain) | < 100ms | < 200ms |
| Proof size | < 50KB | < 100KB |

**Optimization Checklist**:

```rust
// benches/stark_bench.rs

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_stark_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("stark_prove");
    
    // Simple 2-input 2-output tx
    let witness = TransactionWitness::simple_transfer();
    let prover = StarkProver::default();
    
    group.bench_function("simple_tx", |b| {
        b.iter(|| prover.prove(&witness))
    });
    
    // Complex 4-input 4-output tx
    let complex_witness = TransactionWitness::complex_transfer(4, 4);
    group.bench_function("complex_tx", |b| {
        b.iter(|| prover.prove(&complex_witness))
    });
    
    group.finish();
}

fn bench_stark_verify(c: &mut Criterion) {
    let prover = StarkProver::default();
    let witness = TransactionWitness::simple_transfer();
    let proof = prover.prove(&witness).unwrap();
    let vk = prover.verifying_key();
    let public_inputs = witness.public_inputs();
    
    c.bench_function("stark_verify", |b| {
        b.iter(|| verify_stark(&proof, &public_inputs, &vk))
    });
}

criterion_group!(benches, bench_stark_prove, bench_stark_verify);
criterion_main!(benches);
```

**Optimizations to Apply**:

1. **FRI Query Parallelization**
   ```rust
   // Use rayon for parallel FRI queries
   pub fn verify_fri_queries_parallel(
       queries: &[FriQuery],
       commitments: &[Commitment],
   ) -> bool {
       queries.par_iter()
           .all(|q| verify_single_query(q, commitments))
   }
   ```

2. **Poseidon Hash Batching**
   ```rust
   // Batch multiple hash operations
   pub fn poseidon_batch(inputs: &[[u64; 12]]) -> Vec<[u64; 4]> {
       inputs.par_iter()
           .map(|input| poseidon_compress(input))
           .collect()
   }
   ```

3. **Trace LDE Caching**
   ```rust
   // Cache low-degree extension for repeated queries
   pub struct TraceLdeCache {
       lde: Vec<Vec<GoldilocksField>>,
       domain_size: usize,
   }
   ```

---

##### Protocol 15.2.2: Note Scanning Optimization

**Target**: < 1 second per 1000 notes

```rust
// benches/scanner_bench.rs

fn bench_note_scanning(c: &mut Criterion) {
    let scanner = NoteScanner::default();
    let viewing_key = ViewingKey::random();
    
    // Generate test encrypted notes
    let notes: Vec<EncryptedNote> = (0..1000)
        .map(|i| {
            // 1% owned by our key
            if i % 100 == 0 {
                encrypt_note_for(&viewing_key, Note::random(1000))
            } else {
                encrypt_note_for(&ViewingKey::random(), Note::random(1000))
            }
        })
        .collect();
    
    c.bench_function("scan_1000_notes", |b| {
        b.iter(|| scanner.scan_batch(&notes, &viewing_key))
    });
}
```

**Optimizations**:

1. **Parallel Trial Decryption**
   ```rust
   impl NoteScanner {
       pub fn scan_parallel(&self, notes: &[EncryptedNote], vk: &ViewingKey) -> Vec<Note> {
           notes.par_iter()
               .filter_map(|enc| self.try_decrypt(enc, vk).ok())
               .collect()
       }
   }
   ```

2. **Early Rejection via Tag Check**
   ```rust
   // Check diversifier tag before full decryption
   pub fn try_decrypt(&self, enc: &EncryptedNote, vk: &ViewingKey) -> Option<Note> {
       // Quick tag check (constant time)
       let expected_tag = derive_tag(&vk.dk, &enc.epk);
       if !constant_time_eq(&enc.tag, &expected_tag) {
           return None;
       }
       // Full decryption only if tag matches
       self.full_decrypt(enc, vk)
   }
   ```

---

##### Protocol 15.2.3: ML-KEM Encapsulation Benchmark

**Target**: < 1ms per encapsulation

```rust
fn bench_ml_kem(c: &mut Criterion) {
    let (pk, sk) = ml_kem_768_keygen();
    
    c.bench_function("ml_kem_encaps", |b| {
        b.iter(|| ml_kem_768_encaps(&pk))
    });
    
    let (ciphertext, _) = ml_kem_768_encaps(&pk);
    c.bench_function("ml_kem_decaps", |b| {
        b.iter(|| ml_kem_768_decaps(&sk, &ciphertext))
    });
}
```

---

#### Task 15.3: Mainnet Configuration

**Goal**: Prepare production-ready genesis and boot node configuration.

##### Protocol 15.3.1: Genesis Configuration

**File**: `config/mainnet-spec.json`

```json
{
  "name": "Hegemon Mainnet",
  "id": "hegemon_mainnet",
  "chainType": "Live",
  "bootNodes": [
    "/dns4/boot1.hegemon.network/tcp/30333/p2p/12D3Koo...",
    "/dns4/boot2.hegemon.network/tcp/30333/p2p/12D3Koo...",
    "/dns4/boot3.hegemon.network/tcp/30333/p2p/12D3Koo..."
  ],
  "telemetryEndpoints": [
    ["wss://telemetry.hegemon.network/submit/", 0]
  ],
  "protocolId": "hegemon",
  "properties": {
    "tokenDecimals": 12,
    "tokenSymbol": "HEG"
  },
  "genesis": {
    "runtime": {
      "system": {
        "code": "0x..."
      },
      "balances": {
        "balances": []
      },
      "shieldedPool": {
        "merkleTreeDepth": 32,
        "maxNullifiersPerTx": 4,
        "maxCommitmentsPerTx": 4,
        "verifyingKey": "0x..."
      },
      "difficulty": {
        "targetBlockTime": 60000,
        "difficultyAdjustmentPeriod": 2016,
        "initialDifficulty": "0x0000ffff00000000..."
      }
    }
  }
}
```

**Genesis Verification Checklist**:
- [ ] Token decimals = 12 (matches existing chain)
- [ ] Merkle tree depth = 32 (4B note capacity)
- [ ] STARK verifying key correctly encoded
- [ ] Initial difficulty appropriate for launch hashrate
- [ ] No pre-mined balances (fair launch)

---

##### Protocol 15.3.2: Boot Node Setup

**Steps**:

1. **Generate PQ Node Keys** (on each boot node):
   ```bash
   # Generate ML-DSA-65 node key (not Ed25519!)
   hegemon-node key generate-node-key --scheme ml-dsa-65 \
       --output /etc/hegemon/node-key.pem
   
   # Derive peer ID from ML-DSA public key
   hegemon-node key inspect-node-key /etc/hegemon/node-key.pem
   # Output: PeerId: 12D3KooW...
   ```

2. **Configure ML-KEM Handshake**:
   ```toml
   # /etc/hegemon/config.toml
   [network]
   node_key_file = "/etc/hegemon/node-key.pem"
   
   # CRITICAL: ML-KEM only, no X25519 fallback
   handshake_protocol = "ml-kem-768"
   require_pq_handshake = true
   
   # Reject legacy Noise-NK handshakes
   allow_legacy_handshake = false
   ```

3. **Firewall Configuration**:
   ```bash
   # Allow P2P port (ML-KEM handshake)
   ufw allow 30333/tcp
   
   # Allow RPC (optional, for load balancer)
   ufw allow from 10.0.0.0/8 to any port 9933
   
   # Allow WebSocket (for dashboard)
   ufw allow from 10.0.0.0/8 to any port 9944
   ```

4. **Systemd Service**:
   ```ini
   # /etc/systemd/system/hegemon-bootnode.service
   [Unit]
   Description=Hegemon Boot Node
   After=network.target
   
   [Service]
   Type=simple
   User=hegemon
   ExecStart=/usr/local/bin/hegemon-node \
       --chain /etc/hegemon/mainnet-spec.json \
       --node-key-file /etc/hegemon/node-key.pem \
       --port 30333 \
       --rpc-port 9933 \
       --ws-port 9944 \
       --prometheus-port 9615 \
       --name "Hegemon-Boot-1" \
       --bootnodes ""
   Restart=always
   RestartSec=10
   
   [Install]
   WantedBy=multi-user.target
   ```

---

##### Protocol 15.3.3: Launch Checklist

**Pre-Launch Verification**:

- [ ] **Code Audit**
  - [ ] External security audit complete
  - [ ] All PQ parameters verified by cryptographer
  - [ ] ECC audit script passes
  - [ ] No known vulnerabilities

- [ ] **Testing**
  - [ ] All E2E tests pass
  - [ ] Testnet running 7+ days without issues
  - [ ] 3+ boot nodes syncing correctly
  - [ ] Shielded transactions verified on testnet

- [ ] **Performance**
  - [ ] STARK prove < 10s (acceptable)
  - [ ] STARK verify < 200ms on-chain
  - [ ] Note scan < 2s/1000 notes
  - [ ] Block time stable at ~60s

- [ ] **Infrastructure**
  - [ ] 3+ boot nodes deployed
  - [ ] Monitoring/alerting configured
  - [ ] Telemetry endpoint operational
  - [ ] Block explorer ready

- [ ] **Documentation**
  - [ ] User guide published
  - [ ] Wallet download available
  - [ ] Mining guide available
  - [ ] Security documentation public

**Launch Day Runbook**:

1. **T-24h**: Final testnet checkpoint, all boot nodes synced
2. **T-6h**: Clear testnet, deploy mainnet genesis
3. **T-1h**: Start boot nodes in listen-only mode
4. **T-0**: Enable P2P connections, announce launch
5. **T+1h**: Verify first shielded transaction
6. **T+24h**: Post-launch stability review

---

##### Protocol 15.3.4: Mock Code Removal

**Files to Update Before Mainnet**:

| Component | File | Action |
|-----------|------|--------|
| `AcceptAllVerifier` | `pallets/shielded-pool/src/verifier.rs` | Remove, use real `StarkVerifier` |
| `MockTransactionPool` | `node/src/substrate/client.rs` | Remove, use `FullPool` |
| `MockChainStateProvider` | `node/src/substrate/mining_worker.rs` | Remove, use real provider |

**Removal Script**:

```bash
#!/bin/bash
# scripts/remove-mocks.sh

echo "=== Removing Mock/Scaffold Code ==="

# 1. Check AcceptAllVerifier is not used
if grep -rn "AcceptAllVerifier\|AcceptAllProofs" runtime/src/lib.rs; then
    echo "❌ AcceptAllVerifier still in runtime config!"
    exit 1
fi

# 2. Check MockTransactionPool is not instantiated
if grep -rn "MockTransactionPool::new" node/src/; then
    echo "❌ MockTransactionPool still instantiated!"
    exit 1
fi

# 3. Check MockChainStateProvider is not used
if grep -rn "MockChainStateProvider::new" node/src/; then
    echo "❌ MockChainStateProvider still used!"
    exit 1
fi

echo "✅ All mocks removed or unused"
```

**Verification Checklist**:
- [ ] `scripts/remove-mocks.sh` passes
- [ ] Release build has no mock code
- [ ] Mainnet genesis uses real `StarkVerifier`

---

## Mock/Scaffold Code to Remove

| Component | File | Remove When |
|-----------|------|-------------|
| `AcceptAllVerifier` | `pallets/shielded-pool/src/verifier.rs` | Real STARK verifier integrated |
| `new_full()` scaffold mode | `node/src/substrate/service.rs` | Phase 14 complete |
| `MockTransactionPool` | `node/src/substrate/client.rs` | Real pool validated |
| `MockChainStateProvider` | `node/src/substrate/mining_worker.rs` | Production validated |

---

## Quick Reference

### Build Commands

```bash
# Check compilation
cargo check -p hegemon-node
cargo check -p runtime

# Run tests
cargo test -p pallet-shielded-pool
cargo test -p pq-noise
cargo test -p network

# Build release
cargo build --release -p hegemon-node

# Start dev node
HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
```

### Critical Files

| Purpose | File | Crypto |
|---------|------|--------|
| Node service | `node/src/substrate/service.rs` | - |
| Full client | `node/src/substrate/client.rs` | - |
| Mining worker | `node/src/substrate/mining_worker.rs` | Blake3 |
| Block import | `node/src/substrate/pow_block_import.rs` | Blake3 |
| Blake3 PoW | `consensus/src/substrate_pow.rs` | Blake3 |
| Runtime | `runtime/src/lib.rs` | - |
| PQ Handshake | `pq-noise/src/handshake.rs` | ML-KEM-768 |
| Shielded Pool | `pallets/shielded-pool/src/lib.rs` | STARK, Poseidon |
| STARK Verifier | `pallets/shielded-pool/src/verifier.rs` | STARK |
| Identity (PQ) | `pallets/identity/src/lib.rs` | ML-DSA-65 |

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `HEGEMON_MINE` | `0` | Enable mining |
| `HEGEMON_MINE_THREADS` | `1` | Mining threads |
| `HEGEMON_MINE_TEST` | `false` | Use test difficulty |
| `HEGEMON_PQ_REQUIRE` | `true` | Require PQ handshake (ML-KEM-768) |

---

## Timeline Estimate

### 🔴 CRITICAL PATH: Make Node Functional

**These must be done FIRST before any other work matters.**

| Task | Blocker For |
|------|-------------|
| **11.5.1**: Switch to `new_full_with_client()` | Everything |
| **11.5.2**: Wire real transaction pool | Tx submission |
| **11.5.3**: Wire real state execution | Tx execution |
| **11.5.4**: Wire real block import | Block storage |
| **11.6.1-11.6.3**: Chain sync | Multi-node |
| **11.7.1-11.7.3**: Production RPC service | Wallet/Dashboard |
| **11.8.1-11.8.3**: Integration verification | Confidence |

### Phase Status (Code vs Runtime)

| Phase | Code Status | Runtime Status | Notes |
|-------|-------------|----------------|-------|
| Phase 11.5-11.8: Node Wiring | 🔴 NOT DONE | ❌ BROKEN | **DO THIS FIRST** |
| Phase 12: Shielded Pool | ✅ CODE DONE | ⚠️ Not executed | Blocked by 11.5 |
| Phase 13: Wallet Integration | ✅ CODE DONE | ⚠️ RPC errors | Blocked by 11.7 |
| Phase 14: E2E Flow | 🔴 NOT DONE | ❌ Cannot test | Blocked by 11.5-11.8 |
| Phase 15: Hardening | 🔴 NOT DONE | N/A | After everything works |

### Remaining Work

| Phase | Actual Status |
|-------|---------------|
| Phase 11.5-11.8: Make It Work | 🔴 **BLOCKING** - must do first |
| Phase 12: Shielded Pool Pallet | ✅ Code complete (not running) |
| Phase 13: Wallet Integration | ✅ Code complete (RPC blocked) |
| Phase 14: E2E Testing | 🔴 Blocked by 11.5-11.8 |
| Phase 15: Hardening | 🔴 After E2E verified |

---

## Success Criteria

When complete, Hegemon will:

1. **Mine blocks** with Blake3 PoW on Substrate runtime
2. **Connect peers** using **ML-KEM-768** post-quantum encryption (NO X25519)
3. **Process shielded transactions** with **STARK ZK proofs** (NO Groth16)
4. **Support wallet operations** with **ML-DSA-65** signatures (NO Ed25519)
5. **Encrypt notes** with **ML-KEM-768** (NO ECIES)
6. **Run testnet** with 3+ nodes mining and syncing
7. **Pass security audit** for mainnet deployment

**ZERO elliptic curve, pairing, or Groth16 code will remain in the production codebase.**

---

## Appendix: Why No Groth16/ECC?

### Shor's Algorithm Threat

Groth16 relies on BLS12-381 pairings, which are defined over elliptic curves. Shor's algorithm running on a sufficiently large quantum computer can:

1. Solve discrete log on elliptic curves in polynomial time
2. Break ALL pairing-based assumptions
3. Forge Groth16 proofs by computing the trapdoor

### STARK Advantages

| Property | Groth16 | STARK |
|----------|---------|-------|
| Trusted Setup | Required | **None** |
| Post-Quantum | ❌ No | ✅ Yes |
| Proof Size | ~200 bytes | ~20-50 KB |
| Prover Time | Fast | Moderate |
| Verify Time | ~5ms | ~50-100ms |
| Assumptions | Pairing, DLOG | **Hash collision only** |

The larger proof size and slower verification are acceptable tradeoffs for **quantum resistance** and **transparency**.

### ML-DSA vs Ed25519

| Property | Ed25519 | ML-DSA-65 |
|----------|---------|-----------|
| Key Size | 32 B | 1,952 B |
| Sig Size | 64 B | 3,293 B |
| Quantum Safe | ❌ No | ✅ Yes |
| Standard | - | FIPS 204 |

The size increase is the cost of quantum resistance.

---

**END OF EXECUTION PLAN**

*This project assumes adversaries already possess Shor/Grover-class hardware. Classical crypto is not a fallback—it is a vulnerability.*
