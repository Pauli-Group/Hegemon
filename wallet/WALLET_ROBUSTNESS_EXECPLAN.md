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

- [x] M1: Nullifier pre-check via storage query (no new RPC needed)
  - Added `is_nullifier_spent()` and `check_nullifiers_spent()` to substrate_rpc.rs
  - Added `NullifierSpent` and `TooManyInputs` error variants
  - Added `precheck_nullifiers()` in tx_builder.rs
  - Integrated into `substrate-send` command
- [x] M2: Human-readable errors with actionable suggestions
  - Already implemented: `user_message()` and `suggested_action()` methods on WalletError
  - CLI displays both on errors
- [x] M3: Auto-consolidate in `wallet send` when inputs > MAX_INPUTS
  - Created `consolidate.rs` with `ConsolidationPlan` using binary tree O(log N) algorithm
  - Added `--auto-consolidate` and `--dry-run` flags to `substrate-send`
  - Exports `ConsolidationPlan`, `execute_consolidation`, `MAX_INPUTS` from lib.rs
- [x] M4: `wallet status --sync` shows current chain state
  - Status now syncs by default (use `--no-sync` to skip)
  - Shows note counts, balance, consolidation warnings
  - Added `StatusArgs` with `--ws-url` and `--no-sync` options
- [x] **CRITICAL FIX: `hegemon_walletNullifiers` RPC was returning empty**
  - Root cause: `production_service.rs` `nullifier_list()` always returned `Ok(Vec::new())`
  - This broke wallet sync - notes were never marked as spent
  - Fixed by adding `list_nullifiers()` runtime API to iterate `ShieldedPool::Nullifiers`
  - Updated production_service to call the new API
- [x] **CRITICAL FIX: Wallet and prover computed different nullifiers**
  - Root cause: FVK stored `Blake3(sk_spend)` as nullifier_key, then applied `prf_key()` again
  - Prover used `prf_key(sk_spend)` directly - one less hash
  - Fixed by storing raw `sk_spend` in FVK and letting `compute_nullifier()` apply `prf_key()`
- [x] **FIX: Zero-padded nullifiers broke pending tx tracking**
  - Root cause: Pending txs stored all nullifiers including `[0u8; 32]` padding
  - The `.all()` check failed because zero nullifier never appeared on chain
  - Fixed by filtering out zero nullifiers before storing in pending tx
- [x] Validation: End-to-end transfer test with balance verification
  - Two transactions sent and mined successfully
  - Pending status correctly transitions from InMempool → Mined { height }
  - Nullifiers correctly appear on chain and match wallet tracking
  - Notes correctly marked as spent after tx mined


## Surprises & Discoveries

- M2 was already implemented - WalletError already has `user_message()` and `suggested_action()` methods, CLI uses them
- SpendableNote doesn't have a height field, only position, so confirmation count display was simplified
- WalletStore doesn't implement Clone, so async sync requires Arc<WalletStore> pattern with re-open after sync
- The existing test `wallet_send_receive_flow` was already failing (encrypted note size mismatch) - pre-existing issue
- **CRITICAL BUG FOUND**: `hegemon_walletNullifiers` RPC was hardcoded to return empty vec! This meant:
  - Wallet sync never detected spent notes
  - Wallet kept trying to spend already-spent notes  
  - Transactions failed with "Custom error: 5" (nullifier already spent)
  - The nullifier pre-check (M1) was working correctly, but sync wasn't marking notes as spent
- The `--no-sync` flag we added for M4 was essential for offline address extraction in node startup scripts
- **CRITICAL BUG FOUND**: Wallet and prover computed different nullifiers for the same note:
  - Wallet FVK stored `nullifier_key = Blake3("nk" || sk_spend)` 
  - Then `compute_nullifier()` called `prf_key(nullifier_key)` = Poseidon hash
  - Net effect: `Poseidon(Blake3(sk_spend))` - double hashing!
  - Prover used `prf_key(sk_spend)` = `Poseidon(sk_spend)` - single hash
  - Result: nullifiers didn't match, pending tx tracking broke
- **BUG FOUND**: Zero-padded nullifiers in pending tx tracking:
  - Circuit outputs `MAX_INPUTS` nullifiers, padding unused slots with zeros
  - Pending tx stored all nullifiers including `[0u8; 32]`
  - `.all()` check failed because zero never appears on chain
  - Notes never marked as spent even when real nullifier was on chain


## Decision Log

- Decision: Address nullifier validation first before consolidation
  Rationale: Nullifier validation is a prerequisite for safe consolidation - we need to know which notes are actually spendable before planning multi-step transactions
  Date/Author: 2025-12-04

- Decision: Study Zcash librustzcash wallet patterns before implementation
  Rationale: Zcash has production-grade solutions for the same problems. Their Proposal/Step architecture, ConfirmationsPolicy, and ChangeStrategy patterns should inform our design.
  Date/Author: 2025-12-04

- Decision: Simplify architecture, don't cargo-cult Zcash complexity
  Rationale: Zcash's Proposal/Step/StepOutput indirection is for multi-pool (Sapling, Orchard, transparent). We have one pool. Use simple `Vec<(usize, usize)>` for consolidation pairs. Plans are ephemeral; chain state is truth.
  Date/Author: 2025-12-04

- Decision: Use storage queries for nullifier checks, not new RPC
  Rationale: Nullifiers are already in `ShieldedPool::Nullifiers` storage. Direct storage query avoids pallet changes.
  Date/Author: 2025-12-04

- Decision: Default min_confirmations to 1, not 3/10 like Zcash
  Rationale: 3+ confirmations adds 18+ second delays. Fine for mainnet, painful for testnet iteration. Make configurable.
  Date/Author: 2025-12-04

- Decision: Remove dust handling entirely
  Rationale: We have flat fees, not per-input fees. Even 1-satoshi notes are economically spendable. Dust thresholds solve a problem we don't have.
  Date/Author: 2025-12-04

- Decision: Stateless recovery for interrupted consolidation
  Rationale: Don't track "consolidation in progress" state. If interrupted, user re-runs command, wallet re-syncs, re-plans from current notes. Simpler, no corrupt state possible.
  Date/Author: 2025-12-04


## Outcomes & Retrospective

### Critical Bugs Found (2025-12-04)

**Bug 1: Nullifier RPC Always Empty**

During end-to-end testing, transactions were failing with "Custom error: 5" (nullifier already spent) even though the wallet showed the notes as unspent. Investigation revealed:

**Root Cause:** `node/src/substrate/rpc/production_service.rs` line 257:
```rust
fn nullifier_list(&self) -> Result<Vec<[u8; 32]>, String> {
    // Note: The runtime API doesn't provide a way to list all nullifiers
    // This would require a custom runtime API or iterating storage
    Ok(Vec::new())  // <-- ALWAYS RETURNS EMPTY!
}
```

This meant the `hegemon_walletNullifiers` RPC always returned 0 nullifiers, so wallet sync never marked notes as spent.

**Fix Applied:**
1. Added `list_nullifiers() -> Vec<[u8; 32]>` to `ShieldedPoolApi` in `runtime/src/apis.rs`
2. Implemented it in `runtime/src/lib.rs` using `Nullifiers::<Runtime>::iter_keys().collect()`
3. Updated `production_service.rs` to call the new runtime API

---

**Bug 2: Wallet/Prover Nullifier Mismatch**

After fixing Bug 1, transactions still showed as "InMempool" forever. Debug output revealed wallet and prover computed different nullifiers:

```
wallet:  322714b81a580a16
prover:  04ed904ff1823fed
```

**Root Cause:** Double-hashing in wallet FVK:
- FVK stored `nullifier_key = Blake3("nk" || sk_spend)` 
- `compute_nullifier()` then called `prf_key(nullifier_key)` which is Poseidon
- Net: `Poseidon(Blake3(sk_spend))` vs prover's `Poseidon(sk_spend)`

**Fix Applied:**
Changed `wallet/src/viewing.rs` `FullViewingKey::from_keys()` to store raw `sk_spend.to_bytes()` instead of `sk_spend.nullifier_key()`. Now both use same single-hash path.

---

**Bug 3: Zero-Padded Nullifiers**

After fix 2, nullifiers matched but transactions still stuck in "InMempool". Debug showed:

```
chain: 1786c56837a4383b
pending: 1786c56837a4383b (found: true)
pending: 0000000000000000 (found: false)  <-- ZERO PADDING!
```

**Root Cause:** 
- Circuit outputs `MAX_INPUTS` (2) nullifiers, padding unused slots with zeros
- Pending tx stored all nullifiers including padding
- `.all()` check required ALL nullifiers on chain, but zeros never appear

**Fix Applied:**
1. `tx_builder.rs`: Filter out `[0u8; 32]` before storing in `BuiltTransaction.nullifiers`
2. `store.rs`: `refresh_pending()` now filters zeros when checking if tx is mined


### Final Test Results (2025-12-04)

**Test Environment:**
- Fresh node and wallet initialized with all fixes
- Mining to wallet address enabled
- Multiple blocks mined, accumulating notes

**Test Case Results:**

| Test | Description | Result | Notes |
|------|-------------|--------|-------|
| ✅ M1 | TooManyInputs error without --auto-consolidate | PASSED | Shows: "Need 3 notes but max is 2 per transaction" + "Add --auto-consolidate flag" |
| ✅ M2 | Human-readable error messages | PASSED | `user_message()` and `suggested_action()` display correctly |
| ✅ M3a | --dry-run shows consolidation plan | PASSED | Shows estimated blocks and txs needed |
| ✅ M3b | Small transfer (no consolidation needed) | PASSED | Direct send works |
| ✅ M4 | Status syncs and shows note breakdown | PASSED | Shows balance, note count, consolidation warning |
| ✅ M4b | --no-sync flag for offline use | PASSED | Essential for extracting miner address before node starts |
| ✅ TX1 | First shielded transfer | PASSED | Tx mined at block 14, status=Mined, confirmations tracked |
| ✅ TX2 | Second shielded transfer | PASSED | Tx mined at block 17, uses different note (not double-spend) |
| ✅ NF | Nullifier tracking | PASSED | 2 nullifiers on chain, match wallet-computed nullifiers |
| ✅ SYNC | Notes marked spent after tx | PASSED | First note correctly excluded from future tx |

**Final Wallet Status (after initial tests):**
```
Balance: 800 HGM
Unspent notes: 18
Last synced: block #18

Pending transactions:
  cf80529b... status=Mined { height: 14 } confirmations=4
  859fac5d... status=Mined { height: 17 } confirmations=1
```

**Chain Nullifiers (2 after initial tests):**
```json
{
  "nullifiers": [
    "0000000000000000000000000000000000000000000000001786c56837a4383b",
    "0000000000000000000000000000000000000000000000000094a70dbf64195b"
  ],
  "count": 2
}
```

### Extended Cross-Wallet Test Results (2025-12-04)

**Test: Stress Tests**
```
✅ 73/73 pallet-shielded-pool tests pass
✅ 23/23 transaction-circuit tests pass  
✅ 13/13 synthetic-crypto tests pass
✅ 4/5 wallet tests pass (1 pre-existing failure: encrypted note size mismatch)
```

**Test: Multiple Rapid Transactions**
```
✅ 3 transactions sent in rapid succession (no double-spend errors)
✅ All 3 mined at same block height (34)
✅ Total 5 transactions, 5 nullifiers on chain, all tracked correctly
```

**Test: Cross-Wallet Transfers**

Created second wallet for receiver testing:
```
Sender Wallet: ~/.hegemon-wallet (passphrase: CHANGE_ME)
Receiver Wallet: ~/.hegemon-wallet-receiver (passphrase: receiver123)
```

Transfer sequence:
1. ✅ Sender → Receiver: 50 HGM (TX: b6bd8168..., mined at block 45)
2. ✅ Sender → Receiver: 50 HGM × 3 rapid txs (all mined at block 52)
3. ✅ Receiver → Sender: 25 units (TX: 548b0a81..., mined at block 62)

**Final Balances:**
| Wallet | Balance | Notes | 
|--------|---------|-------|
| Sender | 2600.00000025 HGM | 56 |
| Receiver | 199.99999975 HGM | 4 |

**Receiver Note Breakdown:**
```
#0: 50 HGM (position 58)
#1: 50 HGM (position 60)  
#2: 50 HGM (position 63)
#3: 49.99999975 HGM (position 77) - change from sending 25 units
```

All pending transactions correctly tracked with mined heights and confirmations.

### Edge Case Validation Tests (2025-12-04)

Comprehensive testing of wallet behavior under adversarial and edge-case inputs.

**Test Environment:**
- Sender wallet: `~/.hegemon-wallet` (passphrase: `CHANGE_ME`)
- Receiver wallet: `~/.hegemon-wallet-receiver` (passphrase: `receiver123`)
- HGM denomination: 8 decimals (1 HGM = 100,000,000 base units)

| Test | Input | Expected Result | Actual Result | Status |
|------|-------|-----------------|---------------|--------|
| Zero-value transfer | `"value": 0` | Reject | ~~Accepted~~ → Fixed: "recipient value must be greater than zero" | ✅ FIXED |
| Dust amount (1 unit) | `"value": 1` | Accept | Accepted, tx mined successfully | ✅ PASS |
| Exceed balance | Send 200 HGM from 149.9 HGM | Reject | "Insufficient funds: have 149.99999975 HGM, need 200 HGM" | ✅ PASS |
| Invalid address (truncated) | `"address": "shca1qy..."` (partial) | Reject | "invalid checksum" | ✅ PASS |
| Negative value | `"value": -100` | Reject | "expected u64" (JSON parse error) | ✅ PASS |
| Empty recipients | `[]` | Reject | "at least one recipient required" | ✅ PASS |
| Malformed JSON | `[{invalid json}` | Reject | Parse error | ✅ PASS |
| Send-to-self | Sender address in recipients | Accept | Transaction mined successfully | ✅ PASS |
| Drain wallet | Send 149.9 HGM from ~150 balance | Accept | Balance goes to 0 HGM, tx mined | ✅ PASS |
| Send from empty wallet | Send any amount from 0 balance | Reject | "Insufficient funds: have 0 HGM, need X HGM" | ✅ PASS |
| Double-spend (post-confirm) | Spend same note twice after confirm | Reject | "Insufficient funds" (sync detects spent) | ✅ PASS |
| Double-spend (rapid fire) | Spend same note twice immediately | Reject | "Insufficient funds" (pending tx tracking) | ✅ PASS |
| Double-spend (sync bypass) | Restore old wallet, spend already-spent note | Reject | TX rejected by chain with `NullifierAlreadyExists` | ✅ PASS |

**Bug Found and Fixed:**

**Zero-Value Transfer Bug**
- **Issue:** Wallet accepted `"value": 0` in recipients, wasting fees on meaningless transactions
- **Root Cause:** No validation for zero values in `build_transaction()`
- **Fix Applied:** Added to `wallet/src/tx_builder.rs`:
```rust
if recipients.iter().any(|r| r.value == 0) {
    return Err(WalletError::InvalidArgument(
        "recipient value must be greater than zero".to_string(),
    ));
}
```

**Consolidation Test:**
- Successfully consolidated 6 notes → 3 notes using `--auto-consolidate`
- Followed by 150 HGM transfer that would otherwise exceed MAX_INPUTS
- Balance correctly reflected after all transactions mined

### Double-Spend Prevention Tests (2025-12-04)

**Test 1: Double-spend after TX confirmed**
1. Sent 50 HGM from receiver wallet (TX1 confirmed)
2. Tried to send another 50 HGM using same notes
3. **Result:** ✅ PASS - Wallet synced and detected spent note
   - Error: "Insufficient funds: have 49.99999974 HGM, need 50 HGM"
   - Sync correctly marked the 99.99 HGM note as spent

**Test 2: Double-spend before TX confirmed (rapid fire)**
1. Sent 25 HGM from receiver wallet (TX1 submitted)
2. Immediately tried to send 25 HGM again (no sync in between)
3. **Result:** ✅ PASS - Wallet tracks pending transactions
   - Error: "Insufficient funds: have 0 HGM, need 25 HGM"
   - Pending tx tracking correctly excludes notes being spent

**Double-Spend Protection Layers:**
| Layer | Protection | Timing |
|-------|------------|--------|
| Wallet sync | Marks spent notes based on chain nullifiers | After TX mined |
| Pending TX tracking | Excludes notes with pending spend | Before TX mined |
| Nullifier pre-check | Queries chain for spent nullifiers | Before proof generation |
| On-chain validation | Pallet rejects duplicate nullifiers | At block inclusion |

**Test 3: On-Chain Protection (Sync Bypass)**
1. Backed up receiver wallet with 50 HGM note
2. Spent 20 HGM from receiver (TX: 8de459..., submitted successfully)
3. Restored OLD wallet backup (still has the spent note)
4. Attempted to spend from restored wallet (TX: 5563021..., appeared to submit)
5. **Result:** ✅ PASS - Chain rejected the double-spend
   - TX was "submitted" to mempool but never mined
   - Node mempool shows 0 pending extrinsics (tx was rejected)
   - Wallet shows tx stuck as "InMempool" forever
   - Pallet error: `NullifierAlreadyExists` (error code 5)

**Conclusion:** Double-spend is prevented at 4 different levels. Even if wallet state is corrupted or maliciously restored, on-chain validation is the final backstop that prevents spending the same note twice.

### Known Issues Remaining

**1. Consolidation Stale Index Bug (M3b partial)**
- When `--auto-consolidate` builds multiple txs, note indices become stale
- After first tx marks notes as pending, `spendable_notes()` returns different list
- Plan uses original indices, second tx builds with wrong notes
- **Workaround:** Send smaller amounts that don't require consolidation
- **Fix needed:** Re-fetch note indices each iteration, or use note positions not list indices

**2. Pre-existing Test Failure**
- `wallet_send_receive_flow` fails with "encrypted note size mismatch"
- This is a test setup issue, not new regression

### Files Modified

**Wallet:**
- `wallet/src/error.rs` - NullifierSpent, TooManyInputs variants
- `wallet/src/substrate_rpc.rs` - is_nullifier_spent(), check_nullifiers_spent()
- `wallet/src/tx_builder.rs` - precheck_nullifiers(), filter zero nullifiers
- `wallet/src/consolidate.rs` - NEW: ConsolidationPlan, execute_consolidation
- `wallet/src/viewing.rs` - Fix nullifier_key to use raw sk_spend
- `wallet/src/store.rs` - Filter zeros in refresh_pending()
- `wallet/src/lib.rs` - Module exports
- `wallet/src/api.rs` - Match new error variants
- `wallet/src/bin/wallet.rs` - CLI: --auto-consolidate, --dry-run, --no-sync

**Runtime/Node:**
- `runtime/src/apis.rs` - Added list_nullifiers() to ShieldedPoolApi
- `runtime/src/lib.rs` - Implemented list_nullifiers()
- `node/src/substrate/rpc/production_service.rs` - Call runtime API for nullifiers

**Documentation:**
- `runbooks/two_person_testnet.md` - Updated with --no-sync usage


## Zcash Patterns Research

Analysis of `librustzcash/zcash_client_backend` wallet implementation reveals production-proven solutions for our edge cases.

### Key Patterns from Zcash

**1. Proposal/Step Architecture (proposal.rs)**

Zcash models complex transactions as `Proposal` objects containing multiple `Step` objects:

```rust
struct Proposal<FeeRuleT, NoteRef> {
    fee_rule: FeeRuleT,
    target_height: TargetHeight,
    steps: NonEmpty<Step<NoteRef>>,  // Always at least one step
}

struct Step<NoteRef> {
    transaction_request: TransactionRequest,
    payment_pools: BTreeMap<usize, PoolType>,
    shielded_inputs: Option<ShieldedInputs<NoteRef>>,
    prior_step_inputs: Vec<StepOutput>,  // Reference outputs from earlier steps
    balance: TransactionBalance,
    is_shielding: bool,
}
```

Key insight: Multi-step transactions reference outputs from prior steps via `StepOutput(step_index, output_index)`. However, **shielded note chaining is NOT supported** because witnesses cannot be computed until the transaction is mined. Only transparent outputs can be chained.

This affects our consolidation design: we cannot build all consolidation transactions upfront. Each must be confirmed before the next can reference its outputs.

**2. ConfirmationsPolicy (ZIP 315)**

Zcash distinguishes trusted vs untrusted notes based on confirmations:

```rust
struct ConfirmationsPolicy {
    trusted: u32,    // Default: 3 - notes from your own transactions
    untrusted: u32,  // Default: 10 - notes from external sources
}
```

This prevents spending notes that might get reorged. For coinbase rewards (like our mining rewards), this is especially important.

**3. Double-Spend Prevention Sets**

During proposal validation, Zcash tracks:

```rust
consumed_chain_inputs: BTreeSet<OutPoint>  // Notes being spent from chain
consumed_prior_inputs: BTreeSet<StepOutput>  // Outputs from earlier steps being spent
```

Before adding any input, they check it's not already in either set. This catches double-spends at proposal time, not after proof generation.

**4. GreedyInputSelector (input_selection.rs)**

Zcash uses a greedy algorithm that:
- Iteratively selects notes until amount_required is satisfied
- Tracks `prior_available` and requires `new_available > prior_available` each iteration
- Returns `InsufficientFunds { available, required }` with exact amounts
- Excludes "dust inputs" that cost more in fees than their value

**5. ChangeError Enum (fees.rs)**

Comprehensive error types with actionable information:

```rust
enum ChangeError<E, NoteRefT> {
    InsufficientFunds { available: Zatoshis, required: Zatoshis },
    DustInputs {
        transparent: Vec<OutPoint>,
        sapling: Vec<NoteRefT>,
        orchard: Vec<NoteRefT>,
    },
    StrategyError(E),
    BundleError(&'static str),
}
```

The `DustInputs` variant returns which specific notes are dust, allowing the caller to retry without them.

**6. SplitPolicy (fees.rs)**

Zcash can split change into multiple notes to maintain a target note count:

```rust
struct SplitPolicy {
    target_output_count: NonZeroUsize,
    min_split_output_value: Option<Zatoshis>,
}
```

This prevents note fragmentation and ensures users always have enough notes for future transactions.

**7. ProposalError Enum (proposal.rs)**

Specific, actionable errors:

```rust
enum ProposalError {
    RequestTotalInvalid,           // Amounts don't add up
    Overflow,                      // Arithmetic overflow
    AnchorNotFound(BlockHeight),   // Can't find merkle anchor
    ReferenceError(StepOutput),    // Invalid reference to prior step
    StepDoubleSpend(StepOutput),   // Same output spent twice
    ChainDoubleSpend,              // Note already spent on-chain
    BalanceError { step_index, expected, actual },
    ShieldedInputsInvalid,
    EphemeralOutputsInvalid,
    EphemeralAddressLinkability,   // Privacy violation
}
```

### Patterns to Adopt

| Zcash Pattern | Hegemon Analog | Adopt? |
|--------------|----------------|--------|
| Proposal/Step architecture | Simple `Vec<(usize, usize)>` pairs | ✅ Simplified |
| ConfirmationsPolicy | `--min-confirmations` flag, default 1 | ✅ Simplified |
| Double-spend prevention sets | Track consumed nullifiers in planner | ✅ |
| InsufficientFunds with amounts | Include `available`/`required` in errors | ✅ |
| DustInputs filtering | N/A - we have flat fees | ❌ Not needed |
| Greedy input selection | Already have | ✅ |
| SplitPolicy | N/A - over-engineering | ❌ Not needed |

### Key Limitation to Match

Zcash explicitly does NOT support spending unconfirmed shielded outputs:

> "Only transparent outputs of earlier steps may be spent in later steps; shielded outputs cannot be spent in later steps because the witnesses required to spend them cannot be computed until the transaction is mined."

Our consolidation must work the same way: each consolidation tx must be mined and confirmed before the next can be built. This means consolidation is inherently slow (1 tx per block * N steps).


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


### Milestone 1: Nullifier Pre-Check via Storage Query

Currently the wallet builds a complete STARK proof before discovering that nullifiers are already spent. This wastes significant computation time (proofs take seconds to generate).

**Approach:** Query chain storage directly for nullifier existence. No new RPC endpoint needed.

```rust
// In substrate_rpc.rs - query storage directly
pub async fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> Result<bool, WalletError> {
    // ShieldedPool::Nullifiers is a StorageMap<[u8;32], ()>
    // If key exists, nullifier is spent
    let key = self.storage_key("ShieldedPool", "Nullifiers", nullifier);
    let result = self.client.read().await
        .storage(&key, None).await
        .map_err(|e| WalletError::Rpc(e.to_string()))?;
    Ok(result.is_some())
}

pub async fn check_nullifiers_spent(&self, nullifiers: &[[u8; 32]]) -> Result<Vec<bool>, WalletError> {
    // Batch query for efficiency
    let mut results = Vec::with_capacity(nullifiers.len());
    for n in nullifiers {
        results.push(self.is_nullifier_spent(n).await?);
    }
    Ok(results)
}
```

**Integration point:** In `tx_builder.rs`, before `generate_proof()` call:

```rust
// Pre-flight nullifier check
let nullifiers: Vec<_> = selected_notes.iter().map(|n| n.nullifier()).collect();
let spent = rpc_client.check_nullifiers_spent(&nullifiers).await?;
for (i, is_spent) in spent.iter().enumerate() {
    if *is_spent {
        return Err(WalletError::NullifierSpent { note_index: i });
    }
}
// Now safe to generate proof
```

**Confirmation policy:** Add `--min-confirmations` flag (default: 1). Notes must have at least N confirmations to be selected. Configurable for mainnet (higher) vs testnet (1).

Files to modify:
- `wallet/src/substrate_rpc.rs` - Add `is_nullifier_spent()` and `check_nullifiers_spent()` using storage queries
- `wallet/src/tx_builder.rs` - Add nullifier check before `generate_proof` call
- `wallet/src/bin/wallet.rs` - Add `--min-confirmations` flag to send command


### Milestone 2: Human-Readable Errors with Actionable Suggestions

Replace opaque errors like "Custom error: 5" with structured errors that tell users what went wrong and what to do.

**Error enum:**

```rust
// wallet/src/errors.rs

pub enum WalletTransactionError {
    /// Nullifier already spent on-chain
    NullifierSpent { note_index: usize },
    
    /// Insufficient balance
    InsufficientFunds { available: u64, required: u64 },
    
    /// Too many inputs needed, consolidation required
    TooManyInputs { needed: usize, max: usize },
    
    /// Merkle anchor not found (stale sync)
    StaleAnchor { wallet_height: u64, chain_height: u64 },
    
    /// Chain mismatch (genesis changed)
    ChainMismatch { expected: String, actual: String },
    
    /// RPC error
    Rpc(String),
    
    /// Proof generation failed  
    Proof(String),
}

impl WalletTransactionError {
    pub fn user_message(&self) -> String {
        match self {
            Self::NullifierSpent { note_index } => 
                format!("Note #{} was already spent on-chain", note_index),
            Self::InsufficientFunds { available, required } =>
                format!("Insufficient funds: have {} HGM, need {} HGM", 
                    available as f64 / 1e8, required as f64 / 1e8),
            Self::TooManyInputs { needed, max } =>
                format!("Need {} notes but max is {}. Run with --auto-consolidate", needed, max),
            Self::StaleAnchor { .. } =>
                "Wallet is out of sync with chain".to_string(),
            Self::ChainMismatch { .. } =>
                "Wallet was synced to a different chain".to_string(),
            Self::Rpc(e) => format!("RPC error: {}", e),
            Self::Proof(e) => format!("Proof error: {}", e),
        }
    }
    
    pub fn suggested_action(&self) -> String {
        match self {
            Self::NullifierSpent { .. } | Self::StaleAnchor { .. } =>
                "Run: wallet substrate-sync --force-rescan".to_string(),
            Self::ChainMismatch { .. } =>
                "Run: wallet substrate-sync --force-rescan (chain was reset)".to_string(),
            Self::TooManyInputs { .. } =>
                "Add --auto-consolidate flag to automatically merge notes first".to_string(),
            _ => String::new(),
        }
    }
}
```

**Parse pallet errors:** Extract error code from RPC response and map to our enum.

Files to modify:
- `wallet/src/errors.rs` - New file with `WalletTransactionError`
- `wallet/src/substrate_rpc.rs` - Parse RPC errors into `WalletTransactionError`
- `wallet/src/bin/wallet.rs` - Display `user_message()` and `suggested_action()`


### Milestone 3: Auto-Consolidate in `wallet send`

When a send requires more inputs than MAX_INPUTS (2), automatically consolidate notes first.

**Simple data structure (not Zcash's complex Proposal/Step):**

```rust
// wallet/src/consolidate.rs

/// A consolidation plan - just pairs of note indices per level
pub struct ConsolidationPlan {
    /// Each level contains pairs of notes to merge (can execute in parallel)
    /// After each level confirms, re-sync and re-index before next level
    pub levels: Vec<Vec<(usize, usize)>>,
}

impl ConsolidationPlan {
    /// Plan consolidation using binary tree for O(log N) block latency
    pub fn plan(note_count: usize, max_inputs: usize) -> Self {
        let mut levels = vec![];
        let mut remaining = note_count;
        
        while remaining > max_inputs {
            let pairs: Vec<(usize, usize)> = (0..remaining/2)
                .map(|i| (i*2, i*2+1))
                .collect();
            let odd_one = if remaining % 2 == 1 { 1 } else { 0 };
            remaining = pairs.len() + odd_one;
            levels.push(pairs);
        }
        
        Self { levels }
    }
    
    pub fn block_latency(&self) -> usize {
        self.levels.len()
    }
    
    pub fn total_txs(&self) -> usize {
        self.levels.iter().map(|l| l.len()).sum()
    }
}
```

**Execution with best-effort parallelism:**

```rust
async fn execute_consolidation(plan: &ConsolidationPlan, wallet: &mut Wallet) -> Result<(), WalletError> {
    for (level_idx, pairs) in plan.levels.iter().enumerate() {
        println!("Level {}/{}: {} parallel transactions", 
            level_idx + 1, plan.levels.len(), pairs.len());
        
        // Submit up to MAX_PARALLEL txs at once (avoid mempool limits)
        const MAX_PARALLEL: usize = 4;
        for chunk in pairs.chunks(MAX_PARALLEL) {
            let mut handles = vec![];
            for (i, j) in chunk {
                let notes = vec![wallet.notes[*i].clone(), wallet.notes[*j].clone()];
                handles.push(submit_consolidation_tx(notes));
            }
            // Wait for all in chunk to confirm
            for h in handles {
                h.await?;
            }
        }
        
        // Re-sync to discover new notes before next level
        wallet.sync().await?;
    }
    Ok(())
}
```

**CLI integration:**

```bash
# Auto-consolidate if needed
wallet send --to <addr> --amount 120 --auto-consolidate

# Or just show what would happen
wallet send --to <addr> --amount 120 --dry-run
```

**Stateless recovery:** If interrupted mid-consolidation, user just re-runs the command. Wallet re-syncs, sees current notes, re-plans from there. No "consolidation in progress" state to corrupt.

Files to add/modify:
- `wallet/src/consolidate.rs` - New module with `ConsolidationPlan`
- `wallet/src/bin/wallet.rs` - Add `--auto-consolidate` and `--dry-run` flags
- `wallet/src/lib.rs` - Export consolidate module


### Milestone 4: `wallet status --sync`

The `wallet status` command currently shows cached local balances which may be stale. Always sync before showing status.

```rust
// In bin/wallet.rs status handler

async fn handle_status(args: StatusArgs) -> Result<(), WalletError> {
    let mut store = WalletStore::open(&args.store, &args.passphrase)?;
    let rpc = SubstrateRpcClient::connect(&args.ws_url).await?;
    
    // Always sync first
    println!("Syncing with chain...");
    let engine = AsyncWalletSyncEngine::new(rpc.clone());
    engine.sync(&mut store).await?;
    
    // Show status
    let notes = store.get_unspent_notes();
    let total: u64 = notes.iter().map(|n| n.value).sum();
    let chain_height = rpc.get_best_block_number().await?;
    
    println!("\nWallet Status");
    println!("═════════════");
    println!("Address: {}", store.address());
    println!("Balance: {} HGM", total as f64 / 1e8);
    println!("Unspent notes: {}", notes.len());
    
    if !notes.is_empty() {
        println!("\nNote breakdown:");
        for (i, note) in notes.iter().enumerate() {
            let confirmations = chain_height.saturating_sub(note.height);
            let conf_str = if confirmations < 3 { " (unconfirmed)" } else { "" };
            println!("  #{}: {} HGM @ block #{}{}", 
                i, note.value as f64 / 1e8, note.height, conf_str);
        }
    }
    
    println!("\nChain: block #{}", chain_height);
    println!("Genesis: {}", hex::encode(&store.genesis_hash().unwrap_or([0u8; 32])[..8]));
    
    Ok(())
}
```

Files to modify:
- `wallet/src/bin/wallet.rs` - Update status command to sync first and show more detail


### Validation: Change Output Manual Test

Not a code milestone - a manual validation that change outputs work.

**Test procedure:**
1. Start fresh dev node
2. Mine 2 blocks (get 2 × 50 HGM notes)
3. Send 30 HGM to another address
4. Verify wallet shows 70 HGM remaining (100 - 30 = 70)
5. Verify the change note (20 HGM) is spendable

If this fails, debug and fix before proceeding. If it works, change outputs are correct.


### Future: Integration Test Suite

After M1-M4 are complete, add integration tests:

1. **test_nullifier_precheck** - Spend note, try again, verify fast rejection
2. **test_auto_consolidate** - Send requiring 3 notes, verify consolidation happens
3. **test_chain_reset_detection** - Reset chain, verify wallet detects mismatch
4. **test_status_shows_notes** - Verify status shows note breakdown

Location: `wallet/tests/integration/`

This is lower priority than shipping M1-M4.


## Concrete Steps

For Milestone 1 (nullifier pre-check via storage):

```bash
cd /Users/pldd/Documents/Reflexivity/synthetic-hegemonic-currency

# 1. Find how storage keys are constructed
grep -r "storage_key\|StorageKey" wallet/src/

# 2. Add is_nullifier_spent() to substrate_rpc.rs
# Use the existing storage query pattern

# 3. Add check before generate_proof() in tx_builder.rs

# 4. Test: spend a note, try to spend again
# First should succeed, second should fail in <1 second with clear message

cargo build --release -p wallet
```

For Milestone 2 (error handling):

```bash
# 1. Create wallet/src/errors.rs with WalletTransactionError enum
# 2. Add user_message() and suggested_action() methods
# 3. Update substrate_rpc.rs to parse "Custom error: N" and convert
# 4. Update bin/wallet.rs to display errors nicely

cargo build --release -p wallet

# Test: try to spend already-spent note
# Should show: "Note #0 was already spent on-chain"
#             "Run: wallet substrate-sync --force-rescan"
```

For Milestone 3 (auto-consolidate):

```bash
# 1. Create wallet/src/consolidate.rs with ConsolidationPlan
# 2. Add --auto-consolidate and --dry-run flags to send command
# 3. Integrate consolidation execution into send flow

cargo build --release -p wallet

# Test: mine 4 blocks, try to send 120 HGM
# With --dry-run: shows plan
# With --auto-consolidate: executes consolidation then sends
```


## Validation and Acceptance

**M1 - Nullifier Pre-Check:**
- Spending an already-spent note fails BEFORE proof generation
- Failure happens in <1 second (not 10+ seconds of proof gen)
- Error identifies which note was spent

**M2 - Human-Readable Errors:**
- "Custom error: 5" becomes "Note #X was already spent on-chain"
- Each error includes a suggested action
- InsufficientFunds shows "have X HGM, need Y HGM"

**M3 - Auto-Consolidate:**
- `wallet send --amount 120 --dry-run` shows consolidation plan when 3+ notes needed
- `wallet send --amount 120 --auto-consolidate` executes plan then sends
- Parallel consolidation within levels (up to 4 txs at once)
- If interrupted, re-running command resumes from current state

**M4 - Status Sync:**
- `wallet status` syncs before showing balance
- Shows individual note values and heights
- Warns about notes with <3 confirmations
- Shows genesis hash (first 8 bytes)

**Change Output Validation:**
- Manual test: Send 30 HGM from 50 HGM note
- Verify 20 HGM change note appears and is spendable


## Idempotence and Recovery

**All operations are stateless and safe to retry:**

- Nullifier check queries chain - always returns current state
- Consolidation has no "in progress" state - if interrupted, re-run and it re-plans from current notes
- Failed tx? Re-sync, notes are still there, try again
- Already-spent note? Detected in <1 second, skip it

**Recovery paths:**
- Chain reset → `wallet substrate-sync --force-rescan`
- Interrupted consolidation → Just re-run the send command
- Corrupted wallet file → Re-init from seed (not in scope)


## Artifacts and Notes

**Example error improvement (M2):**

Before:
```
Error: Transaction submission failed: rpc error: author_submitExtrinsic 
failed: ErrorObject { code: ServerError(1010), message: "Invalid 
Transaction", data: Some(RawValue("Custom error: 5")) }
```

After:
```
Error: Note #0 was already spent on-chain

This can happen if:
- You submitted the same transaction twice
- Your wallet is out of sync with the chain
- The chain was reset since your last sync

Try: wallet substrate-sync --force-rescan --store <path> --passphrase <pass>
```

**Example consolidation output (M3):**

```
$ wallet send --to hgm1abc... --amount 120 --auto-consolidate

This send requires consolidation (need 3 notes, max 2 per tx).

Consolidation plan:
  Level 1 (2 parallel txs):
    Tx 1: notes #0 + #1 → 100 HGM
    Tx 2: notes #2 + #3 → 100 HGM
  Level 2 (1 tx):
    Tx 3: 100 + 100 → 200 HGM

Block latency: 2 levels
Total fees: ~0.003 HGM
Proceed? [y/n] y

Executing level 1...
  Tx 1: submitted... confirmed (block #1234)
  Tx 2: submitted... confirmed (block #1234)
Syncing new notes...

Executing level 2...
  Tx 3: submitted... confirmed (block #1235)
Syncing...

Consolidation complete. Sending 120 HGM...
Transaction confirmed in block #1236

Sent: 120 HGM
Change: 80 HGM (note #0)
Fees: 0.003 HGM
```

**Example status output (M4):**

```
$ wallet status

Syncing with chain... done

Wallet Status
═════════════
Address: hgm1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh...
Balance: 250 HGM
Unspent notes: 5

Note breakdown:
  #0: 50 HGM @ block #100
  #1: 50 HGM @ block #101
  #2: 50 HGM @ block #102
  #3: 50 HGM @ block #103
  #4: 50 HGM @ block #104 (unconfirmed)

Chain: block #105
Genesis: a1b2c3d4...
```


## Interfaces and Dependencies

New types to add:

**`wallet/src/errors.rs`** (new file):

```rust
pub enum WalletTransactionError {
    NullifierSpent { note_index: usize },
    InsufficientFunds { available: u64, required: u64 },
    TooManyInputs { needed: usize, max: usize },
    StaleAnchor { wallet_height: u64, chain_height: u64 },
    ChainMismatch { expected: String, actual: String },
    Rpc(String),
    Proof(String),
}

impl WalletTransactionError {
    pub fn user_message(&self) -> String;
    pub fn suggested_action(&self) -> String;
}
```

**`wallet/src/consolidate.rs`** (new file):

```rust
pub struct ConsolidationPlan {
    pub levels: Vec<Vec<(usize, usize)>>,
}

impl ConsolidationPlan {
    pub fn plan(note_count: usize, max_inputs: usize) -> Self;
    pub fn block_latency(&self) -> usize;
    pub fn total_txs(&self) -> usize;
}
```

**`wallet/src/substrate_rpc.rs`** additions:

```rust
impl SubstrateRpcClient {
    pub async fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> Result<bool, WalletError>;
    pub async fn check_nullifiers_spent(&self, nullifiers: &[[u8; 32]]) -> Result<Vec<bool>, WalletError>;
}
```

**`wallet/src/bin/wallet.rs`** additions:

```rust
// New flags for send command
#[arg(long)]
auto_consolidate: bool,

#[arg(long)]
dry_run: bool,

#[arg(long, default_value = "1")]
min_confirmations: u32,
```

Dependencies: No new external dependencies. Uses existing `subxt` storage queries.
