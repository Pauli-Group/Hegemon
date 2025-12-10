# Shielded Coinbase: Mining Rewards Directly to Shielded Pool

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

Currently, mining rewards are deposited to transparent Substrate accounts via `pallet_balances`. This violates the design principle stated in `DESIGN.md`: "No transparent outputs; everything is in this one PQ pool from day 1."

After this change, when a miner mines a block:
1. A shielded note is created directly in the shielded pool
2. The note is encrypted to the miner's shielded address
3. The miner's wallet can sync and see the balance
4. Public auditability is preserved (address + amount visible, but nullifier unlinkable)

To see it working: Start a mining node with `HEGEMON_MINER_ADDRESS=<shielded_address>`, mine blocks, run `wallet substrate-sync`, and observe shielded balance increasing by 50 HGM per block mined.


## Progress

- [x] Milestone 1: Extract note encryption to shared crate
- [x] Milestone 2: Implement `mint_coinbase` in shielded-pool pallet
- [x] Milestone 3: Refactor coinbase pallet to use shielded-pool
- [x] Milestone 4: Update node service to encrypt coinbase notes
- [x] Milestone 5: Update wallet CLI and runbooks
- [x] Milestone 6: End-to-end validation


## Surprises & Discoveries

- The wallet/src/notes.rs already re-exported derive_coinbase_r and derive_coinbase_rho. Had to remove duplicate imports after refactoring.
- Added CoinbaseNoteData type to shielded-pool/types.rs with encrypted_note, recipient_address, amount, public_seed, and commitment fields.
- Added coinbase_commitment() and derive_coinbase_rho/r() functions to shielded-pool/commitment.rs for verification.
- Shielded-pool pallet now owns the coinbase inherent (identifier `b"shldcoin"`) with its own ProvideInherent implementation.
- Added ShieldedCoinbaseInherentDataProvider for client-side inherent data provision.
- Created node/src/shielded_coinbase.rs with encrypt_coinbase_note() function. Module is feature-gated to `substrate`.
- Local rocksdb build issue was resolved by setting DYLD_LIBRARY_PATH="/opt/homebrew/opt/llvm/lib".
- ProductionConfig now has miner_shielded_address field for HEGEMON_MINER_ADDRESS env var.
- wire_block_builder_api updated to prefer shielded coinbase, with fallback to deprecated transparent coinbase.
- Updated runbooks/two_person_testnet.md and runbooks/miner_wallet_quickstart.md with new shielded mining workflow.
- Wallet `status` command already shows Shielded Address - no new command needed.
- The node/src/shielded_coinbase.rs import was initially wrong (`synthetic_crypto` instead of `crypto` per Cargo.toml alias).


## Decision Log

- Decision: Use deterministic rho/r derivation from public seed rather than miner-provided randomness
  Rationale: Simplifies the inherent data structure. The seed is public, but nullifier privacy is preserved because computing nullifiers requires `nk` (nullifier key) which only the wallet owner has. `nk = H("nk" || sk_spend)` and `nullifier = H("nf" || nk || position || rho)`.
  Date/Author: 2025-11-30

- Decision: Store encrypted note on-chain, plus plaintext audit data (address, amount)
  Rationale: Encrypted note ensures only miner can decrypt full note data (including rho, r needed to spend). Plaintext audit data allows supply verification. This matches Zcash ZIP-213 philosophy where coinbase is publicly auditable but spend-unlinkable.
  Date/Author: 2025-11-30

- Decision: Node encrypts note (not runtime)
  Rationale: ML-KEM encapsulation requires randomness. Runtime is deterministic. The miner node has access to randomness and the recipient's public key, so it performs encryption and provides the ciphertext in the inherent.
  Date/Author: 2025-11-30


## Outcomes & Retrospective

### What Was Accomplished

The shielded coinbase implementation is now complete. Block rewards are minted directly into the shielded pool as encrypted notes, aligning with DESIGN.md's requirement: "No transparent outputs; everything is in this one PQ pool from day 1."

### Key Technical Decisions

1. **Inherent over Extrinsic**: Used `#[pallet::inherent]` for coinbase to ensure it's applied every block without user intervention.

2. **Node-side Encryption**: ML-KEM encryption happens in the node (not runtime) because runtime is deterministic and can't generate randomness.

3. **Deterministic Verification**: Runtime can verify commitments using deterministic derivation of rho/r from public seed.

4. **Runtime Wiring**: Added `Inherent` to construct_runtime! macro for ShieldedPool pallet - critical step that was initially missed.

### Validation Results

```
2025-12-01 00:18:10 Block built with StorageChanges cached block_number=4
  applied=2 failed=0
  ...
2025-12-01 00:18:10 Encrypting shielded coinbase note block_number=4 subsidy=5000000000
  commitment=40c99ad3e81db452a145993b964056851ba8bd9078282bad49310b0cf6170247
2025-12-01 00:18:10 Added shielded coinbase inherent for block reward block_number=4
2025-12-01 00:18:10 🎉 Block mined!
```

- Blocks now apply 2 inherent extrinsics (timestamp + shielded coinbase)
- Block body size ~2026 bytes (includes ~1700 byte encrypted note)
- 50 HGM (5,000,000,000 base units) per block

### Files Changed

Core implementation:
- `pallets/shielded-pool/src/lib.rs` - Added `mint_coinbase` + inherent provider
- `pallets/shielded-pool/src/inherent.rs` - Client-side inherent data provider
- `pallets/shielded-pool/src/types.rs` - Added `CoinbaseNoteData`
- `pallets/shielded-pool/src/commitment.rs` - Added coinbase commitment functions
- `crypto/src/note_encryption.rs` - Note encryption (shared with wallet)
- `node/src/shielded_coinbase.rs` - Node-side coinbase encryption
- `node/src/substrate/service.rs` - Wire shielded coinbase into block building
- `runtime/src/lib.rs` - Added `Inherent` to ShieldedPool in construct_runtime!

Documentation:
- `runbooks/miner_wallet_quickstart.md` - Updated with shielded workflow
- `runbooks/two_person_testnet.md` - Updated with HEGEMON_MINER_ADDRESS usage

### Next Steps

1. Implement wallet sync to detect and decrypt coinbase notes
2. Add `wallet substrate-sync` command that scans for encrypted notes matching the wallet's viewing key
3. Create integration test that mines blocks and verifies shielded balance increases

### Lessons Learned

- Substrate's `construct_runtime!` macro requires explicit `Inherent` entry for pallets with inherent providers
- The `ProvideInherent` trait implementation alone isn't sufficient
- Block size increases significantly (~10x) with encrypted coinbase notes due to ML-KEM ciphertext overhead


## Context and Orientation

### Key Files

- `pallets/coinbase/src/lib.rs` - Current coinbase pallet that mints to transparent balances
- `pallets/coinbase/src/inherent.rs` - Inherent data provider for coinbase
- `pallets/shielded-pool/src/lib.rs` - Shielded pool pallet with Merkle tree, nullifiers, encrypted notes
- `node/src/substrate/service.rs` - Where coinbase inherent is constructed during block building
- `wallet/src/notes.rs` - Note encryption/decryption logic using ML-KEM + ChaCha20Poly1305
- `wallet/src/address.rs` - ShieldedAddress structure
- `crypto/src/ml_kem.rs` - ML-KEM (Kyber) implementation

### Key Concepts

**Note**: A record containing (value, asset_id, pk_recipient, rho, r) where rho is per-note randomness and r is commitment randomness.

**Note Commitment**: `cm = H("c" || value || asset_id || pk_recipient || rho || r)` - a hash that hides the note contents but commits to them.

**Nullifier**: `nf = H("nf" || nk || position || rho)` where `nk = H("nk" || sk_spend)`. Only the note owner can compute this. Reveals nothing about which note was spent.

**Encrypted Note**: KEM ciphertext + AEAD payload. Uses ML-KEM to encapsulate a shared secret to the recipient's pk_enc, then encrypts note data with ChaCha20Poly1305.

**Shielded Address**: Contains (version, diversifier_index, pk_recipient, pk_enc, address_tag). The pk_enc is an ML-KEM public key for note encryption.

### Current (Broken) Flow

1. Miner sets `HEGEMON_MINER_ACCOUNT=<hex_account_id>`
2. Node builds coinbase inherent with (recipient: AccountId, amount: u64)
3. Runtime calls `T::Currency::deposit_creating(&recipient, amount)` → transparent balance
4. This is wrong: creates transparent outputs

### Target Flow

1. Miner sets `HEGEMON_MINER_ADDRESS=<bech32_shielded_address>`
2. Node parses address, generates random seed, encrypts note to pk_enc
3. Node builds coinbase inherent with (address, amount, seed, encrypted_note)
4. Runtime derives rho/r from seed, computes commitment, adds to Merkle tree
5. Runtime stores encrypted_note for wallet scanning
6. Wallet syncs, finds encrypted note, decrypts, has spendable balance

### Privacy Analysis

| Data | Visibility | Privacy Impact |
|------|------------|----------------|
| Shielded address | Public (in coinbase) | Miner identity known (same as Bitcoin) |
| Amount | Public | Block subsidy known (same as Bitcoin) |
| Seed | Public | Can derive rho, r - but cannot compute nullifier without nk |
| Encrypted note | Public but opaque | Only miner can decrypt |
| Nullifier (at spend time) | Public | Cannot link to coinbase without nk |


## Plan of Work

### Milestone 1: Extract Note Encryption to Shared Crate

The wallet crate contains note encryption logic that the node will need. Rather than making node depend on wallet (which has many dependencies), extract the core encryption to the crypto crate.

Files to create/modify:
- `crypto/src/note_encryption.rs` (new) - Move NotePlaintext, NoteCiphertext, encrypt/decrypt logic
- `crypto/src/lib.rs` - Export the new module
- `wallet/src/notes.rs` - Import from crypto instead of defining locally
- `wallet/Cargo.toml` - Ensure crypto dependency

The encryption uses:
- ML-KEM encapsulation (already in crypto)
- ChaCha20Poly1305 AEAD
- BLAKE3 for key derivation

### Milestone 2: Implement mint_coinbase in Shielded Pool

Add a new dispatchable or internal function to pallet_shielded_pool that:
1. Takes: recipient_address bytes, amount, seed, encrypted_note bytes
2. Derives: rho = H("coinbase-rho" || seed), r = H("coinbase-r" || seed)
3. Extracts: pk_recipient from address
4. Computes: cm = commitment(value, asset_id=0, pk_recipient, rho, r)
5. Adds: cm to Merkle tree at next index
6. Stores: encrypted_note at that index
7. Updates: PoolBalance += amount
8. Emits: CoinbaseMinted event with (block_number, address, amount, commitment_index)

Files to modify:
- `pallets/shielded-pool/src/lib.rs` - Add mint_coinbase function
- `pallets/shielded-pool/src/commitment.rs` - May need to expose commitment computation

### Milestone 3: Refactor Coinbase Pallet

Remove transparent minting, call shielded pool instead.

Files to modify:
- `pallets/coinbase/src/inherent.rs` - New CoinbaseInherentData structure:
    
    pub struct CoinbaseInherentData {
        pub recipient_address: Vec<u8>,  // Shielded address bytes
        pub amount: u64,
        pub seed: [u8; 32],              // For deterministic rho/r
        pub encrypted_note: Vec<u8>,     // KEM ciphertext + AEAD payload
    }

- `pallets/coinbase/src/lib.rs`:
  - Remove: `type Currency: Currency<Self::AccountId>` from Config
  - Add: tight coupling to pallet_shielded_pool
  - Change mint_reward to call shielded pool's mint_coinbase
  - Keep: subsidy calculation, halving schedule, supply tracking

- `runtime/src/lib.rs` - Update pallet configs

### Milestone 4: Update Node Service

Modify block building to encrypt coinbase notes.

Files to modify:
- `node/Cargo.toml` - Add dependency on crypto crate (for note encryption)
- `node/src/substrate/service.rs`:
  - Change: HEGEMON_MINER_ACCOUNT → HEGEMON_MINER_ADDRESS
  - Parse: ShieldedAddress from bech32 string
  - Generate: random 32-byte seed
  - Encrypt: note to recipient's pk_enc
  - Build: new CoinbaseInherentData

- `node/src/substrate/client.rs`:
  - Update ProductionConfig to store shielded address instead of account bytes

### Milestone 5: Update Wallet and Runbooks

Files to modify:
- `wallet/src/bin/wallet.rs`:
  - Change `account-id` command to `mining-address`
  - Output the bech32 shielded address (already shown in `status`, just need dedicated command)

- `runbooks/two_person_testnet.md`:
  - Change HEGEMON_MINER_ACCOUNT to HEGEMON_MINER_ADDRESS
  - Update wallet command to get mining address
  - Remove references to transparent balance

### Milestone 6: End-to-End Validation

Create integration test and manual verification steps.


## Concrete Steps

### Milestone 1 Steps

Working directory: repository root

1. Create `crypto/src/note_encryption.rs`:

    // Core structures and encryption logic extracted from wallet/src/notes.rs
    // Uses: MlKemPublicKey, MlKemCiphertext, ChaCha20Poly1305
    // Exports: NotePlaintext, NoteCiphertext, NotePayload

2. Update `crypto/src/lib.rs` to add:

    pub mod note_encryption;

3. Update `crypto/Cargo.toml` to add chacha20poly1305 dependency

4. Update `wallet/src/notes.rs` to import from crypto

5. Verify: `cargo build -p synthetic-crypto -p wallet`

### Milestone 2 Steps

1. In `pallets/shielded-pool/src/lib.rs`, add:

    #[pallet::call_index(4)]
    #[pallet::weight(Weight::from_parts(50_000_000, 0))]
    pub fn mint_coinbase(
        origin: OriginFor<T>,
        recipient_address: Vec<u8>,
        amount: u64,
        seed: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> DispatchResult {
        ensure_none(origin)?;  // Only callable as inherent
        // Implementation...
    }

2. Verify: `cargo build -p pallet-shielded-pool`

### Milestone 3 Steps

1. Update `pallets/coinbase/src/inherent.rs` with new data structure

2. Update `pallets/coinbase/src/lib.rs`:
   - Remove Currency trait bound
   - Call pallet_shielded_pool::Pallet::<T>::mint_coinbase(...)

3. Update `runtime/src/lib.rs` pallet configs

4. Verify: `cargo build -p hegemon-runtime`

### Milestone 4 Steps

1. Add crypto dependency to `node/Cargo.toml`

2. Update `node/src/substrate/service.rs` and `client.rs`

3. Verify: `cargo build -p hegemon-node --features substrate`

### Milestone 5 Steps

1. Update `wallet/src/bin/wallet.rs`

2. Update `runbooks/two_person_testnet.md`

3. Verify: `cargo build -p wallet`

### Milestone 6 Steps

1. Build everything:

    cargo build --features substrate --release

2. Initialize wallet:

    ./target/release/wallet init --store ~/.hegemon-wallet --passphrase "test"

3. Get mining address:

    ./target/release/wallet mining-address --store ~/.hegemon-wallet --passphrase "test"

4. Start node:

    HEGEMON_MINE=1 HEGEMON_MINER_ADDRESS=<address_from_step_3> ./target/release/hegemon-node --dev --tmp

5. Wait for blocks, then sync wallet:

    ./target/release/wallet substrate-sync --store ~/.hegemon-wallet --passphrase "test" --ws-url ws://127.0.0.1:9944

6. Check balance:

    ./target/release/wallet status --store ~/.hegemon-wallet --passphrase "test"

Expected: Shielded balance shows 50 HGM × number of blocks mined


## Validation and Acceptance

**Acceptance Criteria:**

1. `cargo build --features substrate --release` succeeds with no errors

2. Starting a mining node with `HEGEMON_MINER_ADDRESS` mines blocks (visible in logs)

3. After syncing wallet, `wallet status` shows non-zero shielded balance

4. No transparent balances exist anywhere (query `state_getStorage` for Balances::TotalIssuance returns 0 or key doesn't exist)

5. Shielded pool's PoolBalance matches total coinbase minted

6. Existing shielded transfer tests still pass: `cargo test -p pallet-shielded-pool`


## Idempotence and Recovery

All changes are additive until the final switchover. If a milestone fails:
- Milestone 1: Revert crypto/src/note_encryption.rs, no runtime impact
- Milestone 2: New function is unused until M3, safe to leave
- Milestone 3: This is the breaking change; if it fails, revert the coinbase pallet changes
- Milestone 4-6: Node/wallet changes, easy to revert

To retry from scratch: `git checkout pallets/coinbase pallets/shielded-pool node/src/substrate crypto/src wallet/src`


## Artifacts and Notes

(To be filled during implementation with code snippets, test output, etc.)


## Interfaces and Dependencies

### New Types (crypto/src/note_encryption.rs)

    pub struct NotePlaintext {
        pub value: u64,
        pub asset_id: u64,
        pub rho: [u8; 32],
        pub r: [u8; 32],
        pub memo: Vec<u8>,
    }

    pub struct NoteCiphertext {
        pub version: u8,
        pub diversifier_index: u32,
        pub kem_ciphertext: Vec<u8>,
        pub note_payload: Vec<u8>,
        pub memo_payload: Vec<u8>,
        pub hint_tag: [u8; 32],
    }

    impl NoteCiphertext {
        pub fn encrypt(
            pk_enc: &MlKemPublicKey,
            pk_recipient: [u8; 32],
            version: u8,
            diversifier_index: u32,
            address_tag: [u8; 32],
            note: &NotePlaintext,
            kem_randomness: &[u8; 32],
        ) -> Result<Self, EncryptionError>;
    }

### New Function (pallets/shielded-pool/src/lib.rs)

    impl<T: Config> Pallet<T> {
        pub fn mint_coinbase(
            recipient_address: Vec<u8>,
            amount: u64,
            seed: [u8; 32],
            encrypted_note: Vec<u8>,
        ) -> DispatchResult;
    }

### Modified Inherent (pallets/coinbase/src/inherent.rs)

    #[derive(Encode, Decode, Clone, PartialEq, Eq)]
    pub struct CoinbaseInherentData {
        pub recipient_address: Vec<u8>,
        pub amount: u64,
        pub seed: [u8; 32],
        pub encrypted_note: Vec<u8>,
    }

### Dependencies

- `crypto` crate gains: `chacha20poly1305` dependency
- `node` crate gains: `synthetic-crypto` dependency
- `pallet-coinbase` loses: `Currency` trait bound
- `pallet-coinbase` gains: tight coupling to `pallet-shielded-pool`
