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
- [x] (2025-12-03 00:30Z) Fixed RPC commitment byte extraction bug (was reading bytes[0..8] LE, should be bytes[24..32] BE).
- [x] (2025-12-03 01:00Z) **FAILED**: Transfer failed with "bad signature" error.
- [x] (2025-12-03 01:30Z) Added local proof verification to wallet - discovered proof fails with `InconsistentOodConstraintEvaluations`.
- [x] (2025-12-03 02:00Z) **BUG #1 FIXED**: Wallet was filtering zeros from nullifiers/commitments in ProofResult but STARK proof was generated with padding zeros.
- [x] (2025-12-03 02:30Z) **FAILED**: Still `InconsistentOodConstraintEvaluations` - Merkle path never populated.
- [x] (2025-12-03 03:00Z) **BUG #2 FIXED**: Wallet's `to_input_witness()` never populated `merkle_path`. Fixed `tx_builder.rs` and `shielded_tx.rs` to call `tree.authentication_path()`.
- [x] (2025-12-03 03:30Z) **FAILED**: Still constraint failures - tree depth mismatch.
- [x] (2025-12-03 04:00Z) **BUG #3 FIXED**: Pallet used `MERKLE_TREE_DEPTH=32`, circuit uses `CIRCUIT_MERKLE_DEPTH=8`. Changed pallet and wallet to use 8.
- [x] (2025-12-03 04:30Z) **FAILED**: Still `InconsistentOodConstraintEvaluations` after all fixes.
- [x] (2025-12-03 05:00Z) **ROOT CAUSE FOUND**: Pallet commitment scheme incompatible with circuit!
- [x] (2025-12-03 06:00Z) **FAILED**: 49 commitments synced, 0 notes recovered (wallet can't decrypt coinbase ciphertexts).
- [x] (2025-12-03 07:00Z) **DISCOVERY**: Notes ARE recovering! The "0 notes" was stale wallet data. Fresh wallet showed 5/5 notes, 45B balance.
- [x] (2025-12-03 07:30Z) **FAILED**: Shielded transfer attempt failed with `InconsistentOodConstraintEvaluations` STARK proof error.
- [x] (2025-12-03 08:00Z) **ROOT CAUSE #2 FOUND**: Merkle root mismatch - wallet computed different root than pallet tree.
- [x] (2025-12-03 08:30Z) **BUG #4 FOUND**: `derive_coinbase_rho/r` in pallet used BLAKE2, but crypto lib used SHA256!
  - Pallet: `blake2_256(b"Hegemon_CoinbaseRho_v1" || seed)`
  - Crypto: `SHA256(b"coinbase-rho" || 0u32 || seed)` via `expand_to_length`
- [x] (2025-12-03 09:00Z) **BUG #4 FIXED**: Modified `derive_coinbase_rho/r` in `pallets/shielded-pool/src/commitment.rs` to use SHA256 matching crypto lib.
- [x] (2025-12-03 09:30Z) Rebuilt pallet and node, restarted with fresh wallets.
- [x] (2025-12-03 10:00Z) **SUCCESS**: Wallet synced 4 notes with MATCHING merkle roots! (computed=expected=15576497703102065477)
- [x] (2025-12-03 10:30Z) **SUCCESS**: Local STARK proof verification PASSED!
- [x] (2025-12-03 10:35Z) **FAILED**: Transaction submission failed with "Transaction has a bad signature".
- [ ] **IN PROGRESS**: Debugging binding signature verification failure.
- [ ] Execute a shielded transfer from Alice to Bob using `substrate-send`.
- [ ] Verify the transaction is included on-chain and Bob's wallet can decrypt the note.


## Surprises & Discoveries

### Discovery 1: RPC Byte Order Bug (Fixed)
- Observation: Node RPC `commitment_slice()` was extracting commitment Felt values incorrectly.
- Evidence: Was using `u64::from_le_bytes(commitment[0..8])` but `felt_to_bytes32` stores u64 BE in bytes[24..32].
- Resolution: Fixed to use `u64::from_be_bytes(commitment[24..32])`.

### Discovery 2: Proof Zero-Filtering Bug (Fixed)
- Observation: Wallet filtered zeros from `ProofResult.nullifiers` and `ProofResult.commitments`.
- Evidence: STARK proof was generated with padding zeros, but wallet removed them before sending to pallet.
- Resolution: Removed the `.filter(|x| *x != [0u8; 32])` calls in `prover.rs`.

### Discovery 3: Merkle Path Never Populated (Fixed)
- Observation: `InputNoteWitness.merkle_path` was always empty (default).
- Evidence: `RecoveredNote.to_input_witness()` never set `merkle_path`, and `tx_builder.rs` didn't fetch it from tree.
- Resolution: Added `tree.authentication_path(note.position)` call in `tx_builder.rs` and `shielded_tx.rs`.

### Discovery 4: Tree Depth Mismatch (Fixed)
- Observation: Pallet used `MERKLE_TREE_DEPTH=32`, circuit uses `CIRCUIT_MERKLE_DEPTH=8`.
- Evidence: `pallets/shielded-pool/src/types.rs` had 32, `circuits/transaction/src/constants.rs` had 8.
- Resolution: Changed pallet and wallet `DEFAULT_TREE_DEPTH` to 8.

### Discovery 5: **FUNDAMENTAL COMMITMENT SCHEME MISMATCH** (Root Cause - In Progress)
- Observation: Pallet's `note_commitment()` returns a completely different value than circuit's.
- Evidence:
  1. **Pallet's `commitment.rs::note_commitment()`**:
     - Takes `Note { recipient: [u8; 43], value, rcm, memo }`
     - Uses Blake2-derived domain separator
     - Computes Poseidon hash
     - **THEN WRAPS IN BLAKE2**: `blake2_256(&[NOTE_COMMITMENT_DOMAIN, &hash_bytes].concat())`
     - Returns 32 bytes

  2. **Circuit's `hashing.rs::note_commitment()`**:
     - Takes `(value: u64, asset_id: u64, pk_recipient: [u8; 32], rho: [u8; 32], r: [u8; 32])`
     - Uses `NOTE_DOMAIN_TAG = 1` directly
     - Computes Poseidon sponge
     - Returns raw `Felt` (u64)

  3. **The two schemes are COMPLETELY INCOMPATIBLE**:
     - Different input fields (recipient 43 bytes vs pk_recipient 32 bytes + separate rho/r)
     - Different domain separator approach
     - Pallet wraps in Blake2, circuit doesn't
     - Pallet returns 32 bytes, circuit returns 64-bit Felt

- Impact: When wallet syncs, it receives pallet's Blake2-wrapped commitments. It extracts the last 8 bytes as Felt. But when generating a proof, the circuit computes a pure Poseidon commitment with different inputs. **The Merkle tree leaves don't match**, so the computed root differs from the pallet's root.

- Resolution Attempt (2025-12-03 05:30Z):
  1. Added `circuit_sponge()` function to `commitment.rs` that matches circuit's sponge exactly
  2. Added `circuit_note_commitment()` that matches circuit's note_commitment signature
  3. Added `circuit_coinbase_commitment()` that uses circuit-compatible format
  4. Updated `coinbase_commitment()` to call the circuit-compatible version

- **NEW PROBLEM DISCOVERED** (2025-12-03 06:00Z): 49 commitments synced but 0 notes recovered!
  - The wallet cannot decrypt the coinbase ciphertexts
  - This suggests the encrypted note format or key derivation doesn't match between node and wallet
  - Need to investigate `node/src/shielded_coinbase.rs` encryption vs `wallet/src/notes.rs` decryption

### Discovery 6: Notes WERE Recovering (False Alarm)
- Observation: Previous "0 notes recovered" was stale wallet data.
- Evidence: Fresh wallet synced 5/5 notes correctly with 45B balance.
- Resolution: N/A - the issue was using an old wallet that had synced before the RPC fix.

### Discovery 7: **COINBASE RHO/R DERIVATION MISMATCH** (Root Cause #2 - FIXED!)
- Observation: Merkle root computed by wallet didn't match pallet's stored root.
- Evidence:
  ```
  DEBUG: wallet merkle_root = 14077802134379361009
  DEBUG: computed_root = 14077802134379361009
  DEBUG: expected_root = 8286632674386164380
  ROOT MISMATCH!
  ```
- Root Cause: **Pallet and crypto lib used DIFFERENT hash functions for coinbase rho/r derivation!**
  - **Pallet** (`commitment.rs`): `blake2_256(b"Hegemon_CoinbaseRho_v1" || seed)`
  - **Crypto** (`spend_auth.rs`): `SHA256(b"coinbase-rho" || 0u32 || seed)` via `expand_to_length`
- Impact: Node encrypts coinbase notes using crypto lib's rho/r. Pallet stores commitment using different rho/r. Wallet decrypts and computes commitment with crypto lib's rho/r. **The commitments don't match!**
- Resolution: Modified `pallets/shielded-pool/src/commitment.rs` to use SHA256 with `expand_to_length` pattern matching the crypto library.

### Discovery 8: Merkle Root Now Matches! (After rho/r fix)
- Observation: After fixing rho/r derivation, merkle roots match.
- Evidence:
  ```
  DEBUG: computed_root = 15576497703102065477
  DEBUG: expected_root = 15576497703102065477
  ```
- Resolution: The rho/r fix was correct.

### Discovery 9: STARK Proof Now Passes Locally!
- Observation: Local proof verification succeeds after all fixes.
- Evidence:
  ```
  DEBUG prover: Local verification PASSED
  ```
- Resolution: The circuit constraints are now satisfied.

### Discovery 10: "Bad Signature" Error (Current Issue)
- Observation: Transaction submission fails with "Transaction has a bad signature".
- Evidence:
  ```
  Error: Transaction submission failed: rpc error: author_submitExtrinsic failed: 
  ErrorObject { code: ServerError(1010), message: "Invalid Transaction", 
  data: Some(RawValue("Transaction has a bad signature")) }
  ```
- Analysis: This is a shielded-to-shielded transfer which uses `shielded_transfer_unsigned`. The pallet's `ValidateUnsigned::validate_unsigned()` calls `verifier.verify_binding_signature()` which returns `InvalidTransaction::BadSigner`.
- Next Steps: Investigate binding signature generation in wallet vs verification in pallet.


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

- Decision: Add circuit-compatible commitment functions to pallet instead of modifying circuit.
  Rationale: The circuit is the canonical source of truth for cryptographic operations. The pallet must match the circuit, not vice versa. The circuit's simpler format (pure Poseidon, no Blake2 wrapper) is also more efficient.
  Date/Author: 2025-12-03, pldd

- Decision: Align MERKLE_TREE_DEPTH to 8 everywhere.
  Rationale: The circuit uses CIRCUIT_MERKLE_DEPTH=8. The pallet and wallet must match to produce valid Merkle paths.
  Date/Author: 2025-12-03, pldd

- Decision: Fix coinbase rho/r derivation to use SHA256 matching crypto library.
  Rationale: The node uses crypto lib's `SpendAuthorization::coinbase_rho/r()` to encrypt notes. The pallet must compute commitments with the same rho/r values. Previously pallet used BLAKE2 with different domain separators.
  Date/Author: 2025-12-03, pldd


## Outcomes & Retrospective

### Bugs Fixed and Verified Working
1. **RPC byte extraction**: `commitment[0..8] LE` → `commitment[24..32] BE` ✓
2. **Proof zero-filtering**: Removed `.filter()` calls ✓
3. **Merkle path population**: Added `tree.authentication_path()` calls ✓
4. **Tree depth alignment**: Changed to 8 everywhere ✓
5. **Commitment scheme**: Added `circuit_*` functions ✓
6. **Coinbase rho/r derivation**: Changed from BLAKE2 to SHA256 matching crypto lib ✓

### Verified Working
- Merkle roots now match between wallet computation and pallet storage
- STARK proof verification passes locally
- Balance equation satisfied (total_input = total_output + fee)

### Current Issue
- **Binding signature verification fails**: Pallet's `ValidateUnsigned` rejects with `BadSigner`
- Location: `pallets/shielded-pool/src/lib.rs` line ~1029
- The `verifier.verify_binding_signature()` returns false

### Lessons Learned
1. **Test compatibility at the primitive level first**: Should have written unit tests comparing pallet and circuit hash outputs before integration testing.
2. **Document cryptographic formats explicitly**: The `felt_to_bytes32` format (u64 BE in last 8 bytes) should be documented as canonical.
3. **Don't wrap hashes in more hashes**: The pallet's Blake2 wrapper around Poseidon was unnecessary complexity that caused mismatch.
4. **Trace data through the full pipeline**: The commitment goes: circuit → pallet storage → RPC → wallet tree → proof → verification. Any mismatch breaks everything.
5. **Use the SAME hash derivation everywhere**: The coinbase rho/r mismatch (BLAKE2 vs SHA256) was particularly insidious because both produced valid-looking 32-byte outputs.
6. **Fresh wallet state for testing**: Stale wallet data led to false "0 notes recovered" diagnosis.
7. **Add debug logging generously**: The merkle path and root debug output was essential for diagnosing the mismatch.


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
