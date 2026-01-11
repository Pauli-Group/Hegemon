# Hegemon App Transaction Activity + Disclosure Entry

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this work, send operations provide immediate, readable feedback in the UI, and the disclosure workflow begins from a real transaction list instead of manual hash entry. An operator can see in-flight transactions, failures, and confirmed sends in one place, including consolidation steps, and can generate a disclosure package by selecting a past transaction output.

Observable outcome: running `npm run dev` in `hegemon-app/` shows a Transaction Activity panel on the Send workspace with in-flight and historical outgoing transactions (including consolidation steps), plus a Disclosure workspace that lists outgoing transaction outputs and lets the operator create a disclosure package from a selected record.

## Progress

- [x] (2026-01-10 19:05Z) Read current wallet send/disclosure flows, walletd status output, and disclosure storage; document constraints in Surprises & Discoveries.
- [x] (2026-01-10 19:05Z) Add walletd `disclosure.list` RPC method and wire it through Electron preload + client + types.
- [x] (2026-01-10 19:18Z) Implement Send workspace Transaction Activity panel with in-flight, failed, pending, and confirmed statuses, including consolidation tree placeholders.
- [x] (2026-01-10 19:22Z) Implement Disclosure workspace list of outgoing disclosure records, with selection populating the generate form.
- [ ] (2026-01-10 19:25Z) Validate locally (dev build + manual send/sync/disclosure flows) and capture any deltas in Outcomes & Retrospective.

## Surprises & Discoveries

- Observation: `walletd` handles `tx.send` synchronously; consolidation executes inside the same request and blocks other requests until complete, so UI progress must be optimistic rather than streamed.  
  Evidence: `walletd/src/main.rs` `tx_send` calls `wallet::execute_consolidation` before submitting the actual send.
- Observation: outgoing transaction history already persists via `WalletStore.pending` and includes mined entries, but failed attempts are not stored.  
  Evidence: `wallet/src/store.rs` keeps `pending` items; failures do not get recorded because `record_pending_submission` is only called on success.
- Observation: outgoing disclosure records are persisted in the wallet store but not exposed over `walletd` IPC, so the UI must add a list method to surface them.  
  Evidence: `wallet/src/store.rs::outgoing_disclosures` exists and is used in CLI, but `walletd` has no list RPC.
- Observation: consolidation transactions can be inferred in UI via `memo == "consolidation"`, which is how the wallet records those interim outputs.  
  Evidence: `wallet/src/consolidate.rs` records pending submissions with `memo: Some("consolidation".to_string())`.

## Decision Log

- Decision: Use `WalletStatus.pending` as the source of truth for historical outgoing transactions and supplement it with in-memory UI attempts for in-flight/failed sends.  
  Rationale: Pending entries persist in the wallet file, while failed attempts are not stored in the backend; this keeps changes scoped to UI without altering wallet storage semantics.  
  Date/Author: 2026-01-10 / Agent

- Decision: Add a new `walletd` RPC method `disclosure.list` to expose stored outgoing disclosure records.  
  Rationale: The disclosure interface must start from a list of recorded outputs, and the wallet already stores them.  
  Date/Author: 2026-01-10 / Agent

- Decision: Render consolidation steps as a tree with placeholders derived from the current note summary plan, and fill actual tx hashes after the send completes.  
  Rationale: The backend does not stream step progress; placeholders provide immediate feedback while still mapping to the recorded consolidation transactions.  
  Date/Author: 2026-01-10 / Agent

- Decision: Detect consolidation steps by matching pending transactions whose memo is exactly "consolidation".  
  Rationale: Wallet consolidation already tags interim outputs with that memo, so the UI can surface them without new backend state.  
  Date/Author: 2026-01-10 / Agent

## Outcomes & Retrospective

TBD after implementation.

## Context and Orientation

The desktop renderer lives in `hegemon-app/src/App.tsx`. Wallet operations go through `window.hegemon.wallet` (typed in `hegemon-app/src/env.d.ts`), which maps to Electron IPC handlers in `hegemon-app/electron/main.ts`. Those handlers call `WalletdClient` in `hegemon-app/electron/walletdClient.ts`, which speaks JSON over stdio to the Rust `walletd` binary.

`walletd` already exposes `status.get` with a `pending` array of outgoing transactions. These entries are persisted in the wallet store (`wallet/src/store.rs`) and include mined transactions, but the store does not persist failed attempts. The wallet also stores outgoing disclosure records (`OutgoingDisclosureRecord`) used by the CLI proof commands, but those records are not surfaced via IPC.

Terminology used here:

Send attempt: a UI-only record created when the operator presses “Send”, used to show in-flight and failed states immediately.

Transaction activity list: the merged view of UI send attempts plus wallet-backed outgoing transactions.

Disclosure record: an outgoing transfer output stored in the wallet, used to create disclosure packages.

## Plan of Work

First, add a new `walletd` RPC method that returns all outgoing disclosure records in a UI-friendly form (tx hash, output index, recipient, value, memo, created time). Wire this through `walletdClient`, `electron/main.ts`, `electron/preload.ts`, and the TypeScript types so the renderer can request it.

Next, update the Send workspace UI in `hegemon-app/src/App.tsx` to maintain an in-memory list of send attempts keyed by the current wallet store path. On send, insert an attempt immediately with a “processing” status and (if auto-consolidate is enabled) a placeholder consolidation plan derived from `walletStatus.notes.plan`. After the send resolves, update the attempt with the tx hash or mark it failed. Compute the Transaction Activity list by merging the attempts with `walletStatus.pending`, and render it as a status timeline with the requested symbols (`...`, `X`, `✓`), including a nested list of consolidation steps when applicable. Provide a small helper action to trigger a wallet sync so mined confirmations can appear.

Finally, update the Disclosure workspace to show a list of outgoing disclosure records grouped by transaction, and allow the operator to select a record to populate the disclosure create form. Keep the manual tx/output inputs available but prefill them when selection occurs.

## Concrete Steps

1) Implement `disclosure.list` in `walletd/src/main.rs`, returning a vector of disclosure records with `tx_id` as a hex string prefixed by `0x`, `output_index`, `recipient_address`, `value`, `asset_id`, optional `memo` (UTF-8 if possible, otherwise base64 with `base64:` prefix), and `created_at` as RFC3339 timestamp.

2) Add a `disclosureList` method to:

   - `hegemon-app/electron/walletdClient.ts`
   - `hegemon-app/electron/main.ts`
   - `hegemon-app/electron/preload.ts`
   - `hegemon-app/src/env.d.ts`
   - `hegemon-app/src/types.ts`

3) In `hegemon-app/src/App.tsx`, add state for send attempts and disclosure records, plus helper functions to merge attempts with `walletStatus.pending`. Add a Transaction Activity card to the Send workspace, and update the Disclosure workspace to list and select disclosure records.

4) Update `hegemon-app/src/styles.css` only if additional reusable styling is required; prefer Tailwind utility classes in the JSX to keep the change localized.

## Validation and Acceptance

Manual validation (no automated tests exist for the UI):

1) Run `cd hegemon-app && npm run dev`.
2) Open the Send workspace. Submit a transaction.
3) Observe: a new entry appears immediately with `...` status, later updating to pending/confirmed with a tx hash. Failed sends show `X` and an error note.
4) If consolidation is required and auto-consolidate is enabled, observe a nested list of consolidation steps under the send entry.
5) Open the Disclosure workspace. Observe a list of outgoing transaction outputs; selecting one populates the tx hash/output fields and allows creating a disclosure package.

## Idempotence and Recovery

These changes are additive and can be applied repeatedly without corrupting wallet data. If the new disclosure list method is incorrect, it can be removed without affecting stored records. UI state for send attempts lives in memory; a reload returns to wallet-backed history only.

## Artifacts and Notes

Keep any observed runtime errors from `walletd` or Electron IPC in this section if they change the plan or require corrective work.

## Interfaces and Dependencies

Add a new walletd method in `walletd/src/main.rs`:

    Method name: disclosure.list
    Request params: {}
    Response: Vec<DisclosureRecord>

Where `DisclosureRecord` includes:

    tx_id: String (0x-prefixed hex)
    output_index: u32
    recipient_address: String
    value: u64
    asset_id: u64
    memo: Option<String>
    commitment: String (0x-prefixed hex)
    created_at: String (RFC3339)

Expose this on the renderer API as:

    window.hegemon.wallet.disclosureList(storePath: string, passphrase: string) -> Promise<WalletDisclosureRecord[]>

Use the existing `WalletStatus.pending` list for historical outgoing transactions, and in-memory send attempts for immediate feedback and failed submissions.

Plan update note (2026-01-10): Marked completed milestones and added the consolidation-memo discovery and decision after implementing the IPC + UI changes so the plan reflects shipped progress.
