# Block-size-aware note consolidation batching (wallet + desktop app)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This repository uses ExecPlans as defined in `.agent/PLANS.md`; this document must be maintained in accordance with that file.

## Purpose / Big Picture

Users can send shielded transactions even when their wallet contains many notes, without being surprised by nonsensical “thousands of consolidations” when only a handful of notes are actually needed. When consolidation is truly required (because the transaction circuit supports only 2 inputs per transaction), the wallet submits multiple independent consolidation transactions per block (within a conservative block-size budget) to reduce wall-clock time. The desktop app shows accurate pending/confirmed state (no duplicate “pending forever” activity entries) and estimates consolidation work before sending.

You can see this working by sending a transaction from the Hegemon desktop app with a wallet that has many notes: the send preflight shows the number of notes actually needed for the amount, whether consolidation is needed, and (if enabled) consolidation progresses in batches with status updates until the send confirms.

## Progress

- [x] (2026-01-11 06:58Z) Identify root causes for misleading consolidation counts and “pending forever” UI entries.
- [x] (2026-01-11 06:58Z) Add wallet-side batching for consolidation rounds with a conservative block-size budget.
- [x] (2026-01-11 06:58Z) Add wallet-side exact-input consolidation transaction builder to avoid accidental coin selection overlap.
- [x] (2026-01-11 06:58Z) Extend pending-lock timeout for consolidation transactions (large consolidations can span many blocks).
- [x] (2026-01-11 06:58Z) Add `walletd` method `tx.plan` so the app can estimate required notes and consolidation.
- [x] (2026-01-11 06:58Z) Normalize transaction IDs across walletd + app to prevent duplicate/pending-mismatch activity entries.
- [x] (2026-01-11 06:58Z) Harden contacts persistence with atomic writes and corruption recovery.
- [x] (2026-01-11 07:02Z) Run unit tests and builds (`cargo test -p wallet --lib`, `cargo build -p walletd --release`, `npm run typecheck`, `npm run build`).
- [ ] (2026-01-11 06:58Z) Manual validation in the desktop app (send with/without consolidation; confirm status transitions; confirm contacts persist).

## Surprises & Discoveries

- Observation: The desktop app showed a send as “pending” even when the chain confirmed it, and sometimes showed a duplicate “confirmed” entry alongside a “pending” one.
  Evidence: Walletd pending tx IDs were hex without `0x`, while `tx.send` returned a tx hash with `0x`, so the app never matched the attempt to the pending record.

- Observation: Walletd sometimes produced stdout lines that were not JSON, which broke the app’s line-delimited JSON parsing.
  Evidence: Consolidation code printed human-readable progress when run in verbose mode; those logs appeared on walletd stdout and were parsed as JSON.

- Observation: Contacts could disappear after reload, and JSON parsing errors appeared when loading contacts.
  Evidence: `Unexpected end of JSON input` indicates a partially-written `contacts.json` (non-atomic writes or concurrent writes).

## Decision Log

- Decision: Keep protocol transaction input limit as-is (`MAX_INPUTS = 2`) and improve wallet behavior via consolidation batching rather than expanding transaction arity.
  Rationale: Multi-input proof changes are cryptographic/protocol-level work; batching independent 2→1 merges delivers immediate UX improvements while respecting proof and block-size constraints.
  Date/Author: 2026-01-11 / Codex

- Decision: Add `walletd` preflight method `tx.plan` and use it in the app before `tx.send`.
  Rationale: The app needs a reliable way to estimate note selection and consolidation work without re-implementing wallet internals in the renderer.
  Date/Author: 2026-01-11 / Codex

- Decision: Use conservative per-round limits for consolidation (max txs per round + max bytes per round) and wait for confirmation between rounds.
  Rationale: Notes created in a block cannot be spent until a later commitment-tree root exists, and the network/miners must not be flooded with oversized blocks or mempool spam.
  Date/Author: 2026-01-11 / Codex

- Decision: Normalize tx IDs in the app by stripping `0x` and lowercasing for matching.
  Rationale: Walletd responses and internal statuses use different formatting; normalization prevents status mismatches and duplicate activity entries.
  Date/Author: 2026-01-11 / Codex

## Outcomes & Retrospective

The wallet now consolidates notes in block-size-aware rounds and avoids selecting unintended inputs during consolidation transaction construction. The desktop app can preflight a send to estimate note usage and consolidation work, and it correctly merges “send attempt” activity with wallet pending/confirmed records.

Remaining risk: Protocol-level “many inputs in one proof” is still out of scope; consolidation still costs `note_count - MAX_INPUTS` transactions in the worst case. This change improves wall-clock time and UX, not asymptotic transaction count.

## Context and Orientation

Key terms:

- Note: a shielded UTXO-like value record; the wallet may have many notes.
- Consolidation: self-transfers that merge 2 notes into 1 (2→1), reducing the number of notes needed for a later payment.
- Round: one batch of independent consolidation transactions submitted together, then confirmed, then the wallet syncs and repeats.
- Walletd: a local helper process (`walletd`) that the desktop app talks to via a line-delimited JSON request/response protocol.

Relevant code:

- Wallet consolidation implementation: `wallet/src/consolidate.rs`
- Exact-input consolidation transaction builder: `wallet/src/tx_builder.rs` (`build_consolidation_transaction`)
- Pending transaction tracking and timeouts: `wallet/src/store.rs` (`refresh_pending`)
- Walletd send + plan endpoints: `walletd/src/main.rs` (`tx.send`, `tx.plan`)
- Desktop app send preflight and activity merging: `hegemon-app/src/App.tsx`
- Desktop app contacts persistence (electron main): `hegemon-app/electron/main.ts`
- Runtime block length (upper bound on batch sizing): `runtime/src/lib.rs`

## Plan of Work

Implement consolidation batching as a wallet-side workflow that respects the existing protocol limits:

1. In `wallet/src/tx_builder.rs`, add a builder that constructs a consolidation transaction spending exactly two specified notes and producing exactly one output, to avoid coin-selection choosing overlapping inputs when multiple consolidations are prepared.
2. In `wallet/src/consolidate.rs`, replace single-merge iteration with a round-based batching loop:
   - Select only the notes necessary to cover the target value, including a fee budget for the required consolidation transactions.
   - Prepare and submit a batch of disjoint merges each round, capped by a conservative byte budget and tx-count limit.
   - Wait for confirmation (nullifiers spent) and repeat until the selected notes fit within `MAX_INPUTS`.
3. In `wallet/src/store.rs`, keep consolidation pending locks much longer than normal pending transactions, so long consolidations do not unlock notes prematurely.
4. In `walletd/src/main.rs`, add `tx.plan` so the desktop app can ask “how many notes are needed and how many consolidations are expected” without sending. Update `tx.send` selection logic to include a fee budget when deciding whether consolidation is needed.
5. In `hegemon-app/src/App.tsx`, call `wallet.sendPlan` before `wallet.send` to:
   - show a prompt when consolidation is required,
   - warn when a large consolidation is about to be triggered,
   - store and match tx IDs consistently so activity status reflects wallet confirmations.
6. In `hegemon-app/electron/main.ts`, persist contacts in a stable OS location with atomic writes and corruption backup, so contacts survive reloads.

## Concrete Steps

From the repo root:

    make setup
    make node

Run a local dev chain (mining enabled):

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

In a second terminal, run the desktop app:

    cd hegemon-app
    HEGEMON_BIN_DIR=../target/release npm run dev

## Validation and Acceptance

Acceptance is behavioral:

1. Send planning:
   - With a wallet containing many notes, enter an amount that should require only a few notes.
   - The confirmation prompt (if any) must reference the number of notes needed for that amount, not the total wallet note count.

2. Consolidation batching:
   - Enable auto-consolidate and send an amount that requires consolidation.
   - The wallet should submit multiple consolidation transactions per round (bounded by a conservative block-size budget) and wait for confirmation between rounds.
   - Consolidation should not unlock pending-spent notes after 5 minutes if consolidation is still legitimately in progress.

3. Activity correctness:
   - After the transaction confirms on-chain, the app should not show a separate “pending forever” duplicate entry for the same send.
   - Confirmations should increment and status should flip to confirmed once wallet status reports confirmed.

4. Contacts persistence:
   - Add a contact, reload the app window, and confirm the contact remains.

## Idempotence and Recovery

Idempotence:

- Re-running consolidation is safe; already-spent notes are filtered during sync.
- The desktop app can be restarted mid-consolidation; pending transactions are persisted in the wallet store.

Recovery knobs:

- Pending timeouts can be tuned with:
  - `WALLET_PENDING_TIMEOUT_SECS` (default 300 seconds)
  - `WALLET_CONSOLIDATION_PENDING_TIMEOUT_SECS` (default 12 hours)

If a wallet appears stuck (e.g., after a chain reset), force a rescan from the Wallet screen (“Force rescan on next sync”) and run Sync.

## Artifacts and Notes

`walletd` now supports a preflight planning call:

    {"id":1,"jsonrpc":"2.0","method":"tx.plan","params":{"recipients":[...],"fee":1000000}}

The response includes whether consolidation is needed and an estimate of the work:

    {"assetId":0,"selectedNoteCount":4,"walletNoteCount":2172,"needsConsolidation":true,"plan":{"txsNeeded":2,"blocksNeeded":1}, ...}

## Interfaces and Dependencies

New/updated interfaces:

- In `wallet/src/tx_builder.rs`, the wallet defines:

    pub fn build_consolidation_transaction(
        store: &WalletStore,
        note_a: &SpendableNote,
        note_b: &SpendableNote,
        fee: u64,
    ) -> Result<BuiltTransaction, WalletError>

- In `walletd/src/main.rs`, walletd exposes:
  - `tx.plan` with params `{ recipients: Vec<RecipientSpec>, fee: u64 }`
  - `tx.send` uses fee-aware selection to decide whether consolidation is needed.
