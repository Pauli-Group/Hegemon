# Wallet Robustness and Edge Case Handling

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

The Hegemon wallet currently fails silently or catastrophically in edge cases that Zcash handles gracefully. A user who mines 10 blocks (receiving 10 separate 50 HGM notes) cannot send 120 HGM because the circuit limits transactions to 2 inputs. A user who wipes their chain data and restarts finds their wallet permanently broken with phantom balances. Error messages are opaque ("Custom error: 5"). Change outputs may not work correctly. The wallet has no mechanism for automatic note consolidation.

After this work, a user will be able to:
1. Send amounts larger than any single note by having the wallet automatically consolidate notes first
2. See clear error messages explaining what went wrong and how to fix it
3. Recover from chain resets using `--force-rescan`
4. Trust that balances shown are real and spendable
5. Verify change outputs work correctly for partial spends


## Progress

- [ ] M1: Pre-send nullifier validation - check nullifiers before building proof
- [ ] M2: Change output verification - test partial spends create correct change
- [ ] M3: Human-readable error codes - map pallet errors to user messages
- [ ] M4: Multi-step transaction proposals - wallet builds consolidation plan when needed
- [ ] M5: Automatic consolidation command - `wallet consolidate` merges small notes
- [ ] M6: Status sync-first mode - `wallet status` syncs before showing balance
- [ ] M7: Comprehensive test suite - integration tests for all edge cases


## Surprises & Discoveries

(To be populated during implementation)


## Decision Log

- Decision: Address nullifier validation first before consolidation
  Rationale: Nullifier validation is a prerequisite for safe consolidation - we need to know which notes are actually spendable before planning multi-step transactions
  Date/Author: 2025-12-04


## Outcomes & Retrospective

(To be populated at completion)


## Context and Orientation

The wallet is a CLI tool in `wallet/src/bin/wallet.rs` that manages shielded notes for the Hegemon privacy chain. Key components:

- `wallet/src/store.rs` - `WalletStore` persists encrypted wallet state including notes, commitments, and sync cursors
- `wallet/src/async_sync.rs` - `AsyncWalletSyncEngine` syncs wallet state with chain via WebSocket RPC
- `wallet/src/tx_builder.rs` - Builds shielded transactions with STARK proofs
- `wallet/src/shielded_tx.rs` - Core transaction construction logic
- `wallet/src/substrate_rpc.rs` - `SubstrateRpcClient` communicates with Substrate node
- `pallets/shielded-pool/src/lib.rs` - On-chain pallet that validates and processes shielded transfers

Key constraints:
- `MAX_INPUTS = 2` - Circuit supports at most 2 input notes per transaction
- `MAX_OUTPUTS = 2` - Circuit supports at most 2 output notes per transaction
- Mining creates 50 HGM notes - each coinbase reward is a separate note
- Notes are encrypted with ML-KEM and can only be decrypted by the recipient's incoming viewing key

Error code 5 from the pallet means `NullifierAlreadySpent` - the transaction tried to spend a note that was already spent on-chain.


## Plan of Work


### Milestone 1: Pre-Send Nullifier Validation

Currently the wallet builds a complete STARK proof before discovering that nullifiers are already spent. This wastes significant computation time (proofs take seconds to generate).

Add a pre-flight check in `wallet/src/tx_builder.rs` function `build_shielded_transfer` that queries the chain for nullifier status before proof generation. The check should call a new RPC method or use existing nullifier queries from `substrate_rpc.rs`.

Files to modify:
- `wallet/src/substrate_rpc.rs` - Add `check_nullifiers(&[nullifier]) -> Vec<bool>` method
- `wallet/src/tx_builder.rs` - Add nullifier check before `generate_proof` call
- `wallet/src/shielded_tx.rs` - Add nullifier check in `build_transaction`


### Milestone 2: Change Output Verification

When spending 2 notes of 50 HGM each (100 HGM total) to send 75 HGM, the wallet must create a change output of 25 HGM back to the sender. Verify this works correctly.

Create an integration test in `wallet/tests/` that:
1. Creates a wallet
2. Simulates receiving 2 notes of 50 HGM each
3. Builds a transaction sending 75 HGM to another address
4. Verifies the transaction has 2 inputs, 2 outputs (recipient + change)
5. Verifies change output value is 25 HGM
6. Verifies change output is addressed to sender

Files to create/modify:
- `wallet/tests/change_output_test.rs` - New integration test


### Milestone 3: Human-Readable Error Codes

Map pallet error codes to human-readable messages. The pallet defines errors in `pallets/shielded-pool/src/lib.rs` in the `Error<T>` enum.

Create an error mapping module:

    wallet/src/pallet_errors.rs:
    
    pub fn decode_pallet_error(code: u8) -> &'static str {
        match code {
            0 => "Invalid proof: the STARK proof failed verification",
            1 => "Invalid anchor: the merkle root is not recognized",
            2 => "Invalid nullifier: malformed nullifier data",
            3 => "Invalid commitment: malformed commitment data", 
            4 => "Balance mismatch: inputs do not equal outputs plus fee",
            5 => "Nullifier already spent: one or more notes were already consumed",
            6 => "Invalid binding signature: transaction integrity check failed",
            7 => "Invalid ciphertext: encrypted note data is malformed",
            _ => "Unknown error",
        }
    }

Update error handling in `wallet/src/substrate_rpc.rs` to parse RPC errors and translate them.


### Milestone 4: Multi-Step Transaction Proposals

When a user requests a send that requires more than MAX_INPUTS notes, the wallet should:
1. Calculate how many consolidation transactions are needed
2. Show the user the full plan (N consolidation txs, then final send)
3. Execute each step, waiting for confirmation between steps

Add a `TransactionPlan` type:

    wallet/src/tx_planner.rs:
    
    pub struct TransactionPlan {
        pub consolidation_steps: Vec<ConsolidationStep>,
        pub final_send: FinalSend,
        pub total_fee: u64,
    }
    
    pub struct ConsolidationStep {
        pub input_notes: Vec<SpendableNote>,
        pub output_value: u64,
    }
    
    pub struct FinalSend {
        pub input_notes: Vec<SpendableNote>,
        pub recipients: Vec<Recipient>,
        pub change: Option<u64>,
    }
    
    impl TransactionPlan {
        pub fn build(notes: Vec<SpendableNote>, recipients: Vec<Recipient>, fee: u64) -> Result<Self, WalletError>;
    }

The planner should be greedy: consolidate the 2 largest notes first to minimize steps.


### Milestone 5: Automatic Consolidation Command

Add `wallet consolidate` command that merges all small notes into fewer large notes:

    wallet consolidate --store ~/.hegemon-wallet --passphrase "..." --ws-url ws://127.0.0.1:9944

The command should:
1. Sync wallet
2. List all unspent notes
3. If more than 2 notes, consolidate 2 into 1, wait for confirmation, repeat
4. Show progress: "Consolidating notes: step 1/5..."
5. Final output: "Consolidated N notes into M notes. Largest note: X HGM"

Files to modify:
- `wallet/src/bin/wallet.rs` - Add `Consolidate` command variant and handler


### Milestone 6: Status Sync-First Mode

The `wallet status` command currently shows cached local balances which may be stale. Add a `--sync` flag (or make sync the default) that syncs before showing status.

    wallet status --store ~/.hegemon-wallet --passphrase "..." --sync --ws-url ws://127.0.0.1:9944

Also show:
- Number of unspent notes and their sizes
- Warning if any notes are locked by pending transactions
- Genesis hash the wallet is synced with


### Milestone 7: Comprehensive Test Suite

Create integration tests covering:

1. **test_send_exact_single_note** - Send exactly 50 HGM from one 50 HGM note
2. **test_send_with_change** - Send 30 HGM from 50 HGM note, verify 20 HGM change
3. **test_send_two_notes** - Send 75 HGM using two 50 HGM notes
4. **test_send_requires_consolidation** - Send 120 HGM with three 50 HGM notes (should fail or plan consolidation)
5. **test_double_spend_prevention** - Try to spend same note twice, verify rejection
6. **test_chain_reset_detection** - Sync wallet, reset chain, verify wallet detects mismatch
7. **test_force_rescan** - After chain reset, verify --force-rescan recovers wallet
8. **test_consolidation** - Run consolidate on 5 notes, verify result
9. **test_dust_note_handling** - Create very small note, verify proper handling
10. **test_concurrent_sends** - Start two sends simultaneously, verify no double-spend

Location: `wallet/tests/integration/`


## Concrete Steps

For Milestone 1 (pre-send nullifier validation):

    cd /Users/pldd/Documents/Reflexivity/synthetic-hegemonic-currency
    
    # 1. Add nullifier check RPC method
    # Edit wallet/src/substrate_rpc.rs, add after line ~450:
    
    pub async fn check_nullifier_spent(&self, nullifier: &[u8; 32]) -> Result<bool, WalletError> {
        let client = self.client.read().await;
        let nullifier_hex = hex::encode(nullifier);
        let result: Option<bool> = client
            .request("hegemon_isNullifierSpent", rpc_params![nullifier_hex])
            .await
            .map_err(|e| WalletError::Rpc(e.to_string()))?;
        Ok(result.unwrap_or(false))
    }
    
    # 2. Add pallet RPC handler (if not exists)
    # Check pallets/shielded-pool/src/lib.rs for RPC definitions
    
    # 3. Integrate check into tx_builder.rs before proof generation
    # Find the generate_proof call and add validation before it
    
    # 4. Test
    cargo build --release -p wallet
    
    # Create test scenario: spend a note, try to spend it again
    # First spend should succeed, second should fail with clear message


## Validation and Acceptance

For each milestone, acceptance is defined as:

**M1 - Nullifier Validation:**
- Spending an already-spent note fails BEFORE proof generation
- Error message says "Note at position X was already spent on-chain"
- Time to failure is <1 second (not proof generation time)

**M2 - Change Output:**
- Test passes: `cargo test --package wallet change_output`
- Transaction with partial spend shows correct change amount

**M3 - Error Codes:**
- "Custom error: 5" is replaced with "Nullifier already spent: one or more notes were already consumed"
- All error codes 0-7 have human-readable messages

**M4 - Transaction Proposals:**
- Sending 120 HGM with 50 HGM notes shows: "This requires 1 consolidation transaction before sending. Proceed? [y/n]"
- Plan shows expected fees and steps

**M5 - Consolidate Command:**
- `wallet consolidate` successfully merges 5 notes into 2 notes
- Progress is shown during execution
- Final balance unchanged

**M6 - Status Sync:**
- `wallet status --sync` shows current on-chain balance
- Shows note count and sizes
- Shows genesis hash

**M7 - Test Suite:**
- `cargo test --package wallet --test integration` passes all 10 tests
- Each test exercises a specific edge case
- Tests can run against a dev node


## Idempotence and Recovery

All wallet operations should be idempotent:
- Running `wallet consolidate` when notes are already consolidated does nothing
- Running `wallet sync` multiple times is safe
- Failed transactions release locked notes after timeout (already implemented: 5 min)

Recovery paths:
- Chain reset: `wallet substrate-sync --force-rescan` resets wallet state
- Corrupted wallet: Re-initialize from seed (requires M8: seed export, not in this plan)
- Stuck pending tx: Wait 5 minutes for timeout, or sync to detect if tx was mined


## Artifacts and Notes

Example error message improvement:

Before:
    Error: Transaction submission failed: rpc error: author_submitExtrinsic 
    failed: ErrorObject { code: ServerError(1010), message: "Invalid 
    Transaction", data: Some(RawValue("Custom error: 5")) }

After:
    Error: Transaction failed - Nullifier already spent
    
    One or more notes you tried to spend have already been consumed on-chain.
    This can happen if:
    - You submitted the same transaction twice
    - Your wallet is out of sync with the chain
    - The chain was reset since your last sync
    
    Try running: wallet substrate-sync --force-rescan --store <path> --passphrase <pass>

Example consolidation output:

    $ wallet consolidate --store ~/.hegemon-wallet --passphrase "..." 
    Connecting to ws://127.0.0.1:9944...
    Syncing wallet... done (42 notes, 2100 HGM total)
    
    Consolidation plan:
      Step 1: Merge notes #0 (50 HGM) + #1 (50 HGM) → 100 HGM
      Step 2: Merge notes #2 (50 HGM) + #3 (50 HGM) → 100 HGM
      ... (20 more steps)
      Step 21: Merge 100 HGM + 100 HGM → 200 HGM
    
    This will reduce 42 notes to 2 notes. Proceed? [y/n] y
    
    Executing step 1/21... done (block #1234)
    Executing step 2/21... done (block #1235)
    ...
    
    Consolidation complete!
    Final notes: 2
    Largest note: 1100 HGM
    Total balance: 2100 HGM (unchanged)


## Interfaces and Dependencies

New types to add:

In `wallet/src/pallet_errors.rs`:

    pub fn decode_pallet_error(code: u8) -> &'static str;
    pub fn format_transaction_error(rpc_error: &str) -> String;

In `wallet/src/tx_planner.rs`:

    pub struct TransactionPlan { ... }
    pub struct ConsolidationStep { ... }
    pub struct FinalSend { ... }
    
    impl TransactionPlan {
        pub fn build(
            notes: Vec<SpendableNote>,
            recipients: Vec<Recipient>,
            fee: u64,
            max_inputs: usize,
        ) -> Result<Self, WalletError>;
        
        pub fn display(&self) -> String;
        pub fn consolidation_count(&self) -> usize;
    }

In `wallet/src/substrate_rpc.rs`:

    impl SubstrateRpcClient {
        pub async fn check_nullifier_spent(&self, nullifier: &[u8; 32]) -> Result<bool, WalletError>;
        pub async fn check_nullifiers_spent(&self, nullifiers: &[[u8; 32]]) -> Result<Vec<bool>, WalletError>;
    }

In `wallet/src/bin/wallet.rs`:

    enum Commands {
        ...
        Consolidate(ConsolidateArgs),
    }
    
    struct ConsolidateArgs {
        store: PathBuf,
        passphrase: String,
        ws_url: String,
        dry_run: bool,  // Show plan without executing
    }

Dependencies: No new external dependencies required. All changes use existing crates (tokio, jsonrpsee, etc.).
