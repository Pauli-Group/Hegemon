# Make the dashboard wallet real with an auto-provisioned local key

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Today the dashboard wallet page is a façade: it never talks to a real wallet process, always shows a demo viewing key, falls back to mock transfers, and the miner still pays coinbase rewards to a default address unrelated to the page. A contributor running `make quickstart` should land on a wallet view backed by an actual locally persisted wallet: the dashboard should mint to that wallet, sync it, and expose its balance/view key/transactions without leaking secrets to git or the network. After this change, the dashboard service will auto-create (or reuse) a local wallet store, start a wallet daemon that syncs with the autostarted node, and feed the UI live balances and transfers while pointing the miner’s coinbase to the same key.

## Progress

- [x] (2025-02-18) Draft plan capturing requirements for an auto-provisioned wallet, local persistence, and UI wiring.
- [x] (2025-02-18) Implemented dashboard-service wallet bootstrap: generate/reuse seed+passphrase in `state/dashboard-wallet.meta.json`, auto-init the wallet store, start a wallet daemon, and point miner seed/payout plus WALLET_API_URL at the same seed.
- [x] (2025-02-18) Extended wallet HTTP API with `/status` exposing balances, primary address, incoming viewing key export, pending transfers, and sync height.
- [x] (2025-02-18) Wired the dashboard UI to live wallet data: live status banner, real balance tile, and replacing the demo view key/address with data from the wallet API.
- [ ] Validate end-to-end: run quickstart, observe live blocks mined to the local wallet, confirm balance increments and transfer submission round-trips, and record outcomes/any surprises.

## Surprises & Discoveries

- Wallet daemon already exposed `/transfers`; adding `/status` was straightforward, but balance/pending history only reflect the local store (no incoming ledger history yet). Coinbase visibility will rely on balance growth.

## Decision Log

- Wallet secrets live under `state/` (`dashboard-wallet.meta.json` + `.store`) and `.gitignore` now excludes these paths to avoid accidental commits.
- Node autostart now reuses the wallet seed as `miner_seed` when no explicit miner seed is provided, guaranteeing coinbases land in the autoprovisioned wallet.
- Wallet `/status` returns an easily copyable JSON-encoded incoming viewing key plus the primary address at index 0 so the UI can surface real values without hard-coded placeholders.

## Outcomes & Retrospective

Pending execution.

## Context and Orientation

The dashboard stack has three cooperating pieces:

1. `scripts/dashboard_service.py` (FastAPI proxy) currently autostarts a node and proxies node metrics/events plus wallet-related requests to `WALLET_API_URL` if set; otherwise it serves deterministic mock transfers. It already manages a node process via `NodeProcessSupervisor`.
2. `dashboard-ui/` consumes the proxy. `WalletPage.tsx` uses `/node/wallet/notes`, `/node/metrics`, and `/node/wallet/transfers` but hard-codes a demo view key and renders a placeholder balance because no real wallet data is available.
3. The Rust wallet CLI (`wallet/src/bin/wallet.rs`) can create encrypted stores from a root secret, derive addresses, run a sync daemon against a node RPC, and expose a small HTTP API (`/transfers`) when `wallet daemon --http_listen ...` is used. It already knows how to import a root secret (`--root-hex`) so the same seed can drive both a miner payout address and a wallet store.

The node payout address is derived from the miner seed (`node/src/config.rs`). If we feed the node the same 32-byte seed we used to create the wallet, coinbases land in that wallet. The store files and seeds must not be committed; we should keep them under `state/` (or another ignored path) and ensure `.gitignore` covers them.

## Plan of Work

1. **Service-level wallet bootstrap**
   
   Define a “dashboard wallet” location (e.g., `state/dashboard-wallet.store`) plus a metadata/secret file for the root seed and passphrase. On FastAPI startup, if the seed metadata exists, reuse it; otherwise generate a 32-byte hex seed and a local-only passphrase and persist both to the metadata file. Ensure `.gitignore` ignores the store/db/metadata paths. Use that seed in two places: (a) initialize the wallet store via `wallet init --root-hex ...`, and (b) pass it into the node autostart payload as `miner_seed` so coinbases pay to this wallet’s first address. Add a `WalletProcessSupervisor` in `scripts/dashboard_service.py` that runs `cargo run -p wallet --bin wallet -- daemon --store ... --passphrase ... --rpc_url http://127.0.0.1:<node_port> --auth_token <node_token> --http_listen 127.0.0.1:<wallet_api_port>` with stdout/stderr captured to `state/`. Point `WALLET_API_URL` at this wallet daemon when it is running; otherwise fall back to mocks as today.

2. **Expand the wallet HTTP API for the UI**
   
   Extend `wallet/src/bin/wallet.rs`’s HTTP router to serve a `GET /status` endpoint that returns, at minimum: the primary shielded address (index 0), an exportable incoming viewing key (serialized JSON string), per-asset balances (totals and possibly recovered note count), pending transfer summaries, the last synced height, and whether the store is full or watch-only. Keep `/transfers` for history and submission. Ensure the daemon updates confirmations/pending based on sync height. Preserve existing behavior for callers that only use `/transfers`.

3. **Wire the dashboard UI to live wallet data**
   
   Add a React hook to fetch `/node/wallet/status` from the proxy and surface `shielded balance`, `primary address`, and `view key` fields. Replace the hard-coded demo view key on `WalletPage.tsx` with the live incoming viewing key string, allow copy/export of that value, and show the primary address alongside the QR so users know where coinbases land. Update the `MetricTile` for Shielded balance to show the real total (or a loading/error state) and ensure the transfer table draws from live `/node/wallet/transfers` unless the proxy marks the result as mock. Keep visual treatments aligned with `BRAND.md`.

4. **Validation**
   
   Run `make quickstart` or the equivalent commands described in the README to start the dashboard service and UI. Verify via curl that `/node/metrics` and `/node/wallet/status` return live (non-mock) data, that the miner height advances, and that balances in `/node/wallet/status` increase as coinbases land. Submit a small transfer through the UI and ensure it appears in `/node/wallet/transfers` with confirmations updating. Capture any surprises in this plan’s logs and mark Progress/Outcomes accordingly.
