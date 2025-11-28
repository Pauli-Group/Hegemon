# Hegemon: PQC ZCash on Substrate - Execution Plan

**Goal**: Production-ready post-quantum cryptocurrency with shielded transactions built on Substrate.

**Archive**: Previous detailed execution history archived to `.agent/archive/execplan-substrate-migration-archive-2025-01-13.md`

---

## Current Status

**Last Updated**: 2025-01-13

### ✅ Completed Infrastructure

| Component | Status | Key Files |
|-----------|--------|-----------|
| Substrate Node | ✅ COMPLETE | `node/src/substrate/service.rs` |
| Blake3 PoW | ✅ COMPLETE | `consensus/src/substrate_pow.rs` |
| PQ Network (ML-KEM-768) | ✅ COMPLETE | `network/src/network_backend.rs` |
| Runtime WASM | ✅ COMPLETE | `runtime/src/lib.rs` |
| Full Client Types | ✅ COMPLETE | `node/src/substrate/client.rs` |
| Block Import Pipeline | ✅ COMPLETE | `node/src/substrate/pow_block_import.rs` |
| Transaction Pool | ✅ COMPLETE | `node/src/substrate/client.rs` |
| Mining Worker | ✅ COMPLETE | `node/src/substrate/mining_worker.rs` |
| RPC Extensions | ✅ COMPLETE | `node/src/substrate/rpc/` |
| Wallet RPC Client | ✅ COMPLETE | `wallet/src/substrate_rpc.rs` |
| Dashboard (Polkadot.js) | ✅ COMPLETE | `dashboard-ui/src/api/substrate.ts` |

### Test Results

```bash
# All tests passing
cargo test -p security-tests --test multi_node_substrate --features substrate
# Result: 14 passed, 4 ignored

cargo check -p hegemon-node --features substrate  
# Result: SUCCESS
```

---

## Production Path: Remaining Phases

### Phase 12: Shielded Pool Pallet 🔴 NOT STARTED

**Goal**: Implement the core shielded transaction pallet with note commitments, nullifiers, and Merkle tree.

**Priority**: CRITICAL - This is the core ZCash-like functionality.

#### Task 12.1: Note Commitment Scheme

**Goal**: Implement Sapling-style note commitments using Poseidon hash.

**Files to Create**:
- `pallets/shielded-pool/Cargo.toml`
- `pallets/shielded-pool/src/lib.rs`
- `pallets/shielded-pool/src/commitment.rs`
- `pallets/shielded-pool/src/types.rs`

**Note Structure**:
```rust
pub struct Note {
    /// Recipient's diversified address (PQ public key derived)
    pub recipient: [u8; 43],
    /// Value in atomic units
    pub value: u64,
    /// Unique randomness for commitment hiding
    pub rcm: [u8; 32],
    /// Memo field (512 bytes)
    pub memo: [u8; 512],
}

/// commitment = Poseidon(recipient || value || rcm)
pub fn note_commitment(note: &Note) -> [u8; 32];
```

**Verification**:
- [ ] Note commitment is deterministic
- [ ] Commitment hides note contents (binding)
- [ ] Unit tests for commitment computation

---

#### Task 12.2: Merkle Tree Storage

**Goal**: On-chain incremental Merkle tree for note commitments.

**Files to Create**:
- `pallets/shielded-pool/src/merkle.rs`

**Storage**:
```rust
#[pallet::storage]
pub type MerkleTree<T> = StorageValue<_, IncrementalMerkleTree, ValueQuery>;

#[pallet::storage]
pub type MerkleRoots<T> = StorageMap<_, Blake2_128Concat, u32, [u8; 32]>;

#[pallet::storage]  
pub type CommitmentIndex<T> = StorageValue<_, u32, ValueQuery>;
```

**Merkle Tree Properties**:
- Depth: 32 (supports ~4 billion notes)
- Hash: Poseidon (SNARK-friendly)
- Incremental append-only structure

**Verification**:
- [ ] Append commitment updates root correctly
- [ ] Historical roots are preserved
- [ ] Merkle path generation works

---

#### Task 12.3: Nullifier Set

**Goal**: Track spent notes via nullifiers to prevent double-spending.

**Files to Create**:
- `pallets/shielded-pool/src/nullifier.rs`

**Storage**:
```rust
#[pallet::storage]
pub type Nullifiers<T> = StorageMap<_, Blake2_128Concat, [u8; 32], (), OptionQuery>;
```

**Nullifier Computation**:
```rust
/// nullifier = Poseidon(nsk || position || cm)
/// where nsk is the nullifier spending key
pub fn compute_nullifier(nsk: &[u8; 32], position: u32, cm: &[u8; 32]) -> [u8; 32];
```

**Verification**:
- [ ] Nullifier uniquely identifies a note
- [ ] Double-spend attempts rejected
- [ ] Nullifier storage is efficient

---

#### Task 12.4: Shielded Transfer Extrinsic

**Goal**: Implement the core `shielded_transfer` extrinsic.

**Extrinsic Structure**:
```rust
#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::weight(/* ZK verify weight */)]
    pub fn shielded_transfer(
        origin: OriginFor<T>,
        /// Groth16 proof
        proof: [u8; 192],
        /// Nullifiers for spent notes
        nullifiers: Vec<[u8; 32]>,
        /// New note commitments
        commitments: Vec<[u8; 32]>,
        /// Encrypted notes for recipients
        ciphertexts: Vec<EncryptedNote>,
        /// Merkle root the proof was generated against
        anchor: [u8; 32],
        /// Binding signature
        binding_sig: [u8; 64],
    ) -> DispatchResult;
}
```

**Verification Logic**:
1. Check anchor is a valid historical root
2. Check nullifiers not in spent set
3. Verify Groth16 proof
4. Verify binding signature
5. Add nullifiers to spent set
6. Add commitments to Merkle tree

**Verification**:
- [ ] Valid proofs accepted
- [ ] Invalid proofs rejected
- [ ] Double-spend rejected
- [ ] State updated correctly

---

#### Task 12.5: Circuit Integration

**Goal**: Integrate existing ZK circuits with the pallet.

**Dependencies**:
- `circuits/transaction/` - Existing Groth16 circuits
- `crypto/src/` - Existing crypto primitives

**Files to Modify**:
- `pallets/shielded-pool/src/verifier.rs` - Groth16 verification

**Verification**:
- [ ] Proof verification uses correct verifying key
- [ ] Verification completes within block time
- [ ] Benchmarks establish accurate weights

---

### Phase 13: Shielded Wallet Integration 🔴 NOT STARTED

**Goal**: Update wallet to generate proofs and interact with shielded pool.

#### Task 13.1: Note Scanning

**Goal**: Wallet scans encrypted notes to find owned notes.

**Files to Modify**:
- `wallet/src/scanning.rs` (create)
- `wallet/src/substrate_rpc.rs` (add scanning RPC)

**Process**:
1. Fetch encrypted notes from chain
2. Trial decrypt with viewing key
3. Store decrypted notes locally

---

#### Task 13.2: Proof Generation

**Goal**: Generate Groth16 proofs for shielded transfers.

**Files to Modify**:
- `wallet/src/prover.rs` (create)
- `wallet/src/transaction.rs`

**Dependencies**:
- `circuits/transaction/` - Proving system
- `crypto/src/` - Key derivation

---

#### Task 13.3: Transaction Building

**Goal**: Build complete shielded transactions.

**Files to Modify**:
- `wallet/src/builder.rs` (create)

**Transaction Building**:
1. Select input notes (sufficient value)
2. Generate randomness for outputs
3. Compute nullifiers
4. Build witness for circuit
5. Generate proof
6. Encrypt output notes
7. Sign transaction

---

### Phase 14: End-to-End Transaction Flow 🔴 NOT STARTED

**Goal**: Complete shielded transaction from wallet to block.

#### Task 14.1: RPC Integration

**Goal**: Wire shielded pool RPC to wallet.

**New RPC Endpoints**:
- `hegemon_submitShieldedTransfer` - Submit shielded tx
- `hegemon_getEncryptedNotes` - Fetch encrypted notes
- `hegemon_getMerkleWitness` - Get Merkle path for note

---

#### Task 14.2: E2E Test Suite

**Goal**: Full transaction lifecycle tests.

**Test Scenarios**:
1. Transparent → Shielded (shield)
2. Shielded → Shielded (private transfer)
3. Shielded → Transparent (unshield)
4. Multi-input multi-output
5. Invalid proof rejection
6. Double-spend rejection

---

### Phase 15: Production Hardening 🔴 NOT STARTED

**Goal**: Security review, performance optimization, mainnet readiness.

#### Task 15.1: Security Audit Preparation
- Audit checklist completion
- Threat model review
- Formal verification of critical paths

#### Task 15.2: Performance Optimization
- Block production benchmarks
- ZK verification time optimization
- Storage optimization

#### Task 15.3: Mainnet Configuration
- Genesis configuration
- Boot node setup
- Key ceremony

---

## Mock/Scaffold Code to Remove

When the full implementation is complete, remove these scaffold components:

| Component | File | Remove When |
|-----------|------|-------------|
| `new_full()` scaffold mode | `node/src/substrate/service.rs` | Phase 14 complete |
| `MockTransactionPool` | `node/src/substrate/client.rs` | Real pool validated |
| `MockChainStateProvider` | `node/src/substrate/mining_worker.rs` | Production validated |
| `MockBlockBroadcaster` | `node/src/substrate/mining_worker.rs` | Network validated |
| `MockBlockImport` | `node/src/substrate/block_import.rs` | Real import validated |
| Ignored tests | `tests/multi_node_substrate.rs` | E2E passing |

**Verification**: After Phase 15, running `grep -r "mock\|scaffold\|Mock\|Scaffold" node/src/` should return no matches.

---

## Quick Reference

### Build Commands

```bash
# Check compilation
cargo check -p hegemon-node --features substrate
cargo check -p runtime

# Run tests
cargo test -p security-tests --test multi_node_substrate --features substrate

# Build release
cargo build --release -p hegemon-node --features substrate

# Start dev node
HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
```

### Critical Files

| Purpose | File |
|---------|------|
| Node service | `node/src/substrate/service.rs` |
| Full client | `node/src/substrate/client.rs` |
| Mining worker | `node/src/substrate/mining_worker.rs` |
| Block import | `node/src/substrate/pow_block_import.rs` |
| Blake3 PoW | `consensus/src/substrate_pow.rs` |
| Runtime | `runtime/src/lib.rs` |
| PQ Network | `network/src/network_backend.rs` |

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `HEGEMON_MINE` | `0` | Enable mining |
| `HEGEMON_MINE_THREADS` | `1` | Mining threads |
| `HEGEMON_MINE_TEST` | `false` | Use test difficulty |
| `HEGEMON_PQ_REQUIRE` | `false` | Require PQ handshake |

---

## Timeline Estimate

| Phase | Duration | Status |
|-------|----------|--------|
| Phase 12: Shielded Pool | 2-3 weeks | NOT STARTED |
| Phase 13: Wallet Integration | 1-2 weeks | NOT STARTED |
| Phase 14: E2E Flow | 1 week | NOT STARTED |
| Phase 15: Hardening | 2-3 weeks | NOT STARTED |

**Total Remaining**: ~6-9 weeks to production-ready PQC ZCash on Substrate.

---

## Success Criteria

When complete, Hegemon will:

1. **Mine blocks** with Blake3 PoW on Substrate runtime
2. **Connect peers** using ML-KEM-768 post-quantum encryption
3. **Process shielded transactions** with Groth16 ZK proofs
4. **Support wallet operations** for private sends/receives
5. **Run testnet** with 3+ nodes mining and syncing
6. **Pass security audit** for mainnet deployment

**No mock or scaffold code will remain in the production codebase.**
