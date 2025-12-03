# Shielded-to-Shielded Transfer Debug ExecPlan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

After this work, a user can send shielded HGM tokens from Alice's wallet to Bob's wallet on a local dev chain. The observable outcome: Alice's balance decreases and Bob's balance increases after both wallets sync with the chain. The transaction is fully private - only the sender and recipient can decrypt the note contents.

The immediate goal is to debug and complete a shielded-to-shielded transfer (Alice → Bob) that was previously failing with "Custom error: 3" (anchor not found in MerkleRoots). The root cause was a hash function mismatch between the wallet/circuit (Poseidon sponge with 64-bit field elements) and the pallet (previously Blake2b-256). The pallet's Merkle tree has been updated to use the same Poseidon sponge implementation.


## Progress

- [x] (2025-12-02 23:00Z) Analyzed the error: "Custom error: 3" maps to `InvalidAnchor` in `pallets/shielded-pool/src/lib.rs`.
- [x] (2025-12-02 23:05Z) Confirmed the pallet now uses Poseidon sponge in `merkle.rs` matching the circuit's `hashing.rs`.
- [x] (2025-12-02 23:10Z) Verified wallet uses `state_merkle::CommitmentTree` which calls `transaction_circuit::hashing::merkle_node`.
- [x] (2025-12-02 23:15Z) Alice's wallet exists at `/tmp/alice-wallet` and Bob's recipient address is in `recipients_windows.json`.
- [x] (2025-12-02 23:30Z) Wiped chain state at `/tmp/hegemon-dev-node` and wallets.
- [x] (2025-12-02 23:35Z) Created fresh Alice wallet, captured new address.
- [x] (2025-12-02 23:40Z) Started node with Alice as miner. Mined blocks 1-5 with coinbase rewards.
- [x] (2025-12-02 23:45Z) Created Bob's wallet at `/tmp/bob-wallet`.
- [x] (2025-12-02 23:50Z) Synced Alice's wallet: 5 notes, 25B balance (5 × 5B coinbase).
- [x] (2025-12-02 23:52Z) Created `/tmp/recipients.json` with Bob's address, 1B coin transfer.
- [x] (2025-12-02 23:55Z) **FAILED**: `substrate-send` failed with "Custom error: 3" (InvalidAnchor) again.
- [ ] **INVESTIGATING**: Type mismatch between wallet anchor format and pallet storage format.
- [ ] Execute a shielded transfer from Alice to Bob using `substrate-send`.
- [ ] Verify the transaction is included on-chain and Bob's wallet can decrypt the note.


## Surprises & Discoveries

- Observation: The pallet had a completely separate Merkle hash implementation using Blake2b-256, while the circuit and wallet use a Poseidon-like sponge operating on 64-bit Goldilocks field elements.
  Evidence: The pallet's `merkle.rs` now contains a full port of the Poseidon sponge from `circuits/transaction/src/hashing.rs`, with constants `POSEIDON_WIDTH=3`, `POSEIDON_ROUNDS=8`, `MERKLE_DOMAIN_TAG=4`, and `FIELD_MODULUS = 2^64 - 2^32 + 1`.

- Observation: The wallet's `CommitmentTree` (from `state_merkle` crate) uses `transaction_circuit::hashing::merkle_node` directly, ensuring wallet and circuit always produce matching Merkle roots.
  Evidence: `state/merkle/src/lib.rs` line 8: `use transaction_circuit::hashing::{merkle_node, Felt};`

- Observation (2025-12-02 23:58Z): Type mismatch investigation led to discovering the byte order/extraction bug (see below).
  The wallet's `Felt` (u64) and pallet's `[u8; 32]` conversions are actually correct via `felt_to_bytes32` which stores the u64 in the last 8 bytes with big-endian encoding.

- **ROOT CAUSE FOUND (2025-12-03)**: Node RPC commitment byte extraction bug!
  - `node/src/substrate/rpc/production_service.rs` in `commitment_slice()` was extracting commitment Felt values incorrectly:
    ```rust
    // WRONG: first 8 bytes, little-endian
    let value = u64::from_le_bytes(commitment[0..8].try_into().unwrap_or([0u8; 8]));
    ```
  - Should be:
    ```rust
    // CORRECT: last 8 bytes, big-endian (matching felt_to_bytes32 format)
    let value = u64::from_be_bytes(commitment[24..32].try_into().unwrap_or([0u8; 8]));
    ```
  - This caused the wallet to receive wrong commitment values when syncing, so it built a different Merkle tree than the pallet, resulting in non-matching roots.
  
  Evidence:
  - `circuits/transaction/src/hashing.rs:felt_to_bytes32()` puts u64 BE in bytes[24..32]
  - `pallets/shielded-pool/src/merkle.rs:bytes32_to_felt()` reads from bytes[24..32] as BE
  - RPC was using bytes[0..8] with LE - completely wrong!

  - `pallets/shielded-pool/src/lib.rs:716`: `MerkleRoots::<T>::contains_key(anchor)` where `anchor: [u8; 32]`
  
  **This is the root cause**: The wallet sends a u64 anchor but the pallet expects [u8; 32]. They will never match!


## Decision Log

- Decision: Run debugging session with fresh node state (wipe existing chain data).
  Rationale: The old chain state has Merkle roots computed with the old Blake2b hash. Starting fresh ensures the new Poseidon-based Merkle tree is used from genesis.
  Date/Author: 2025-12-02, pldd

- Decision: Use `/tmp/alice-wallet` and `/tmp/bob-wallet` for wallet storage.
  Rationale: Matches the existing setup from previous testing, easy to wipe and recreate.
  Date/Author: 2025-12-02, pldd

- Decision: Fix commitment byte extraction bug in `node/src/substrate/rpc/production_service.rs`.
  Rationale: The RPC was extracting the first 8 bytes with little-endian instead of the last 8 bytes with big-endian. This caused the wallet to build its Merkle tree with wrong commitment Felt values, resulting in a different root than the pallet.
  Date/Author: 2025-12-03, pldd


## Outcomes & Retrospective

(To be filled after the transfer succeeds.)


## Context and Orientation

The Hegemon blockchain has a shielded pool that uses STARK proofs for private transactions. The key files are:

- `pallets/shielded-pool/src/lib.rs` - The Substrate pallet managing the shielded pool state.
- `pallets/shielded-pool/src/merkle.rs` - Merkle tree implementation for note commitments (now uses Poseidon sponge).
- `wallet/src/tx_builder.rs` - Builds shielded transactions with STARK proofs.
- `wallet/src/store.rs` - Wallet storage, including `commitment_tree()` method.
- `state/merkle/src/lib.rs` - The `CommitmentTree` struct used by the wallet.
- `circuits/transaction/src/hashing.rs` - The canonical Poseidon sponge implementation used by circuits.
- `wallet/src/bin/wallet.rs` - CLI commands including `substrate-send`.
- `node/src/substrate/rpc/production_service.rs` - RPC service that serves commitment data to wallet (FIXED: byte order bug).

The Merkle root "anchor" is a proof commitment that tells the verifier "I'm proving against this particular state of the commitment tree." If the anchor isn't in `MerkleRoots` storage, the pallet rejects the transaction with `Error::<T>::InvalidAnchor` (error index 3).


## Plan of Work

1. Kill any running node processes.
2. Wipe existing chain state to start fresh with the new Merkle hash.
3. Get Alice's shielded address from her wallet.
4. Start the node with mining enabled and Alice's address as the miner.
5. Wait for several blocks to be mined (Alice accumulates coinbase rewards).
6. Sync Alice's wallet and verify she has a balance.
7. Create Bob's wallet if needed and get his shielded address.
8. Update recipients file with Bob's address if needed.
9. Execute `substrate-send` from Alice to Bob.
10. Sync both wallets and verify balances.


## Concrete Steps

All commands run from the repository root: `/Users/pldd/Documents/Reflexivity/synthetic-hegemonic-currency`

### Step 1: Stop any running node

    pkill -f "hegemon-node" || true

### Step 2: Wipe chain state

    rm -rf /tmp/hegemon-dev-node

### Step 3: Get Alice's shielded address

    ./target/release/wallet status --store /tmp/alice-wallet --passphrase "alice-test-pass"

Look for the line "Shielded Address: shca1...". Store this in the environment variable `ALICE_ADDR`.

### Step 4: Start the node with Alice as miner

    mkdir -p /tmp/hegemon-dev-node
    HEGEMON_MINE=1 \
    HEGEMON_MINER_ADDRESS="$ALICE_ADDR" \
    ./target/release/hegemon-node \
      --base-path /tmp/hegemon-dev-node \
      --chain dev \
      --rpc-port 9944 \
      --rpc-cors all \
      --tmp \
      --name "DevNode"

The node should start mining blocks. Look for log lines like:
    
    Block #N imported successfully

### Step 5: Wait for blocks

Wait approximately 30-60 seconds for several blocks to be mined. Check block height:

    curl -s -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
      -H "Content-Type: application/json" http://127.0.0.1:9944 | jq '.result.number'

When the number is >= 5 (hex "0x5" or higher), Alice should have accumulated coinbase rewards.

### Step 6: Sync Alice's wallet

    ./target/release/wallet substrate-sync \
      --store /tmp/alice-wallet \
      --passphrase "alice-test-pass" \
      --ws-url ws://127.0.0.1:9944

Then check balance:

    ./target/release/wallet status --store /tmp/alice-wallet --passphrase "alice-test-pass"

Expected output includes:
    
    Balance: <some positive number> HGM

### Step 7: Create Bob's wallet (if needed)

    ./target/release/wallet init --store /tmp/bob-wallet --passphrase "bob-test-pass"
    ./target/release/wallet status --store /tmp/bob-wallet --passphrase "bob-test-pass"

Copy Bob's shielded address.

### Step 8: Create recipients file

Create `/tmp/recipients-bob.json`:

    [
      {
        "address": "<BOB_SHIELDED_ADDRESS>",
        "value": 5000000000,
        "asset_id": 0,
        "memo": "alice to bob test"
      }
    ]

### Step 9: Send from Alice to Bob

    ./target/release/wallet substrate-send \
      --store /tmp/alice-wallet \
      --passphrase "alice-test-pass" \
      --ws-url ws://127.0.0.1:9944 \
      --recipients /tmp/recipients-bob.json

Expected output:

    Connecting to ws://127.0.0.1:9944...
    Syncing wallet...
    Building shielded transaction with STARK proof...
    Submitting unsigned shielded-to-shielded transfer...
      (No transparent account required - ZK proof authenticates the spend)
    ✓ Transaction submitted successfully!
      TX Hash: 0x...

### Step 10: Sync Bob's wallet and verify

    ./target/release/wallet substrate-sync \
      --store /tmp/bob-wallet \
      --passphrase "bob-test-pass" \
      --ws-url ws://127.0.0.1:9944

    ./target/release/wallet status --store /tmp/bob-wallet --passphrase "bob-test-pass"

Expected: Bob's balance shows approximately 5000000000 (5 HGM).


## Validation and Acceptance

The transfer is successful when:

1. `substrate-send` returns "Transaction submitted successfully!" with a TX hash.
2. After syncing, Bob's wallet shows a balance matching the sent amount.
3. After syncing, Alice's wallet shows her balance decreased by the sent amount.
4. The node logs show the transaction was included in a block without errors.

If any step fails with "Custom error: 3" (InvalidAnchor), the Merkle hash mismatch is still present - re-check that the pallet and wallet use the same Poseidon parameters.


## Idempotence and Recovery

- The node can be restarted safely with the same base-path if it crashes.
- Wallets sync idempotently - running sync multiple times is safe.
- If a transaction fails, the wallet marks the spent notes as "not pending" so they can be retried.
- To start completely fresh: wipe `/tmp/hegemon-dev-node`, `/tmp/alice-wallet`, and `/tmp/bob-wallet`.


## Artifacts and Notes

The error code mapping from `pallets/shielded-pool/src/lib.rs`:

    Error index 0: InvalidProofFormat
    Error index 1: ProofVerificationFailed
    Error index 2: <skipped>
    Error index 3: InvalidAnchor  <-- The error we were seeing
    Error index 4: NullifierAlreadyExists
    ...

The key Poseidon constants (must match between pallet and circuit):

    POSEIDON_WIDTH = 3
    POSEIDON_ROUNDS = 8
    MERKLE_DOMAIN_TAG = 4
    FIELD_MODULUS = 2^64 - 2^32 + 1 (Goldilocks-like)


## Interfaces and Dependencies

The wallet depends on:
- `state_merkle::CommitmentTree` - Merkle tree for note commitments
- `transaction_circuit::hashing::merkle_node` - Poseidon Merkle hash
- `transaction_circuit::witness::TransactionWitness` - STARK witness structure

The pallet depends on:
- `CompactMerkleTree` (in `pallets/shielded-pool/src/merkle.rs`) - Uses local Poseidon sponge
- `verifier::ProofVerifier` trait - STARK proof verification

Both must produce identical Merkle roots for the same set of commitments.
