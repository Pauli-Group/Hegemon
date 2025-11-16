# Node + wallet + dashboard integration hardening

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: `.agent/PLANS.md` defines how ExecPlans must be authored and maintained. Follow it explicitly for any updates.

## Purpose / Big Picture

Operators need a reproducible way to stand up two PoW nodes, keep paired wallet daemons in sync, and observe the resulting balances through both CLI telemetry and the dashboard UI. After implementing this plan someone can follow a runbook to launch miners, fund one wallet, send a transaction to another wallet, watch the subsidized block propagate, and confirm the dashboard surfaces the same metrics. CI must enforce this end-to-end flow and the Playwright suite must smoke test the wallet/network dashboards with screenshots that honor the BRAND system.

## Progress

- [x] (2025-11-16 13:05Z) Authored ExecPlan describing runbook, integration test, CI, Playwright smoke tests, and doc updates.
- [x] (2025-11-16 14:05Z) Added the miner/wallet runbook, linked it from the README whitepaper, and committed deterministic telemetry helpers.
- [x] (2025-11-16 14:15Z) Authored Playwright smoke tests + SVG snapshots for `/wallet` and `/network`, honoring BRAND typography/colors.
- [x] (2025-11-16 14:30Z) Landed the node+wallet integration test, test-utils hooks in `node`, and the `node-wallet-flow` CI job.
- [x] (2025-11-16 14:35Z) Updated DESIGN.md, METHODS.md, and README consensus/wallet/UI sections with runbook + telemetry references.
- [x] (2025-11-16 14:55Z) Validated `cargo test --test node_wallet_daemon -- --nocapture` and `npm run screenshot`, refreshed this ExecPlan with findings.

## Surprises & Discoveries

- Playwright’s CDN downloads 403 behind the workspace proxy; `npx playwright install --with-deps` automatically fell back to `playwright.download.prss.microsoft.com`, so we documented the mirrors for future reruns.
- Manually sealed blocks still pay the configured subsidy, so Alice’s balance can increase while funding Bob; the integration test now asserts for “balance changed” instead of a fixed delta.

## Decision Log

- Exposed `NodeService::seal_pending_block`/`apply_block_for_test` behind the `test-utils` feature so integration tests can finalize deterministic blocks without PoW.
- Wrapped wallet RPC operations invoked from async tests (`sync_wallet`, `submit_transaction`) in `spawn_blocking` to avoid dropping the Tokio runtime inside blocking contexts.
- Snapshot files for Playwright live under SVG wrappers to keep BRAND-aligned gradients/text crisp in git diffs, and the wallet/network smoke tests always run through the deterministic FastAPI fixture.

## Outcomes & Retrospective

- Operators can follow `runbooks/miner_wallet_quickstart.md` plus the README whitepaper link to stand up paired nodes, wallet daemons, miners, and the dashboard UI, then execute a two-party transfer while watching telemetry.
- CI now executes `node_wallet_daemon.rs` via the `node-wallet-flow` job and the Playwright screenshot suite has deterministic SVG baselines for `/mining`, `/wallet`, and `/network`.
- DESIGN.md and METHODS.md record the reward schedule, wallet daemon sync loops, dashboard analytics, and the operational runbook so future contributors have an updated source of truth.

## Context and Orientation

- `node/` exposes the PoW service (`node/src/service.rs`) and HTTP API (`node/src/api.rs`). Tests currently spin up paired nodes via `node/tests/network.rs` but no workspace-level test covers wallet daemons.
- `wallet/` implements the CLI (`wallet/src/bin/wallet.rs`), RPC client (`wallet/src/rpc.rs`), store/daemon logic (`wallet/src/store.rs`, `wallet/src/sync.rs`), and transaction builder (`wallet/src/tx_builder.rs`). Wallet tests such as `wallet/tests/rpc_flow.rs` mock an HTTP service rather than hitting real nodes.
- `dashboard-ui/` is a Vite + React app backed by `scripts/dashboard_service.py`. Playwright already captures a mining screenshot via `dashboard-ui/tests/screenshot.spec.ts` but there are no smoke tests for `/wallet` or `/network` and no automation verifying the transfer form.
- `runbooks/` includes operational guides. We must add a `miner_wallet_quickstart.md` that walks through launching nodes, miners, wallet daemons, dashboard UI, and a two-party transfer.
- `DESIGN.md` and `METHODS.md` describe consensus, wallet, and UI flows. They must be updated to reference the new runbook, the reward schedule (`consensus/src/reward.rs`), and telemetry/analytics metrics.
- CI is defined in `.github/workflows/ci.yml`. It lacks a dedicated job for a node+wallet integration test and does not run Playwright.

## Plan of Work

1. Draft `runbooks/miner_wallet_quickstart.md` detailing prerequisites, launching two nodes with miners, creating/syncing wallet daemons, performing a transfer, and pointing operators to the dashboard UI. Link this runbook from the README’s whitepaper section.
2. Make `scripts/dashboard_service.py` and `dashboard-ui/src/mocks/nodeSamples.ts` deterministic for timestamps/metrics so snapshot tests remain stable. Emphasize BRAND colors and typography in the captured markup.
3. Add `dashboard-ui/tests/smoke.spec.ts` exercising `/wallet` and `/network`: assert telemetry tiles render, submit a mock transfer via the wallet form (against the FastAPI fixture), and capture SVG snapshots committed under `tests/smoke.spec.ts-snapshots/`.
4. Implement a new workspace integration test (e.g., `tests/node_wallet_daemon.rs`) that starts two node services plus their HTTP APIs, launches two wallet daemons syncing against each node, mines a block with subsidy, funds one wallet, submits a wallet-crafted transfer to the peer, and asserts both wallets observe the updated balances. Wire helper threads for daemon loops and ensure cleanup.
5. Update `tests/Cargo.toml` dependencies (add `node`, `consensus`, `tokio`, etc.) and add a CI job `node-wallet-flow` running `cargo test --test node_wallet_daemon -- --nocapture`.
6. Refresh `DESIGN.md` and `METHODS.md` sections describing consensus (supply digest + reward schedule), wallet daemons (RPC sync, send flow), and UI analytics (hash rate, mempool depth, stale rate). Reference the new runbook and telemetry metrics.
7. Run `cargo fmt`, the targeted integration test, and `npm run screenshot`. Update this plan’s Progress, Decision Log, Surprises, and Outcomes with observations.

## Concrete Steps

- From repo root, create `runbooks/miner_wallet_quickstart.md` with sections for prerequisites, launching two nodes, starting miners (`cargo run -p node --bin node ... --miner-workers`), initializing wallet stores (`cargo run -p wallet --bin wallet -- init`), running `wallet daemon`, crafting/sending transactions, and opening the dashboard UI (`uvicorn scripts.dashboard_service:app` + `npm run dev`). Link it from README.
- Edit `scripts/dashboard_service.py` to freeze the genesis transfer timestamp and keep telemetry placeholders deterministic. Mirror the timestamp constant in `dashboard-ui/src/mocks/nodeSamples.ts`.
- Author `dashboard-ui/tests/smoke.spec.ts` with helpers to wrap `#root` markup inside SVG payloads, call `expect().toMatchSnapshot`, and interact with the wallet form. Commit new snapshot SVGs under `dashboard-ui/tests/smoke.spec.ts-snapshots/`.
- Add `tests/node_wallet_daemon.rs` using `tokio::test`. Spin up `NodeService::start` for two nodes with temp DBs, spawn API tasks via `node::api::serve`, create `WalletStore`s, spawn daemon threads calling `WalletSyncEngine::sync_once`, craft a funding transaction by hand (deterministic witness/ciphertexts), and invoke `wallet::build_transaction` for the user-level transfer. Poll wallet stores for balances.
- Update `.github/workflows/ci.yml` with a `node-wallet-flow` job (needs `rust-tests`) that runs the new integration test explicitly.
- Expand `DESIGN.md` (consensus + wallet + UI sections) and `METHODS.md` (operations) to cover reward schedule, telemetry metrics, wallet daemon loops, and dashboard smoke tests. Reference `runbooks/miner_wallet_quickstart.md`.
- Run `cargo fmt`, `cargo test --test node_wallet_daemon -- --nocapture`, and `cd dashboard-ui && npm run screenshot`. Capture terminal output for validation.

## Validation and Acceptance

- `cargo test --test node_wallet_daemon -- --nocapture` must spin two nodes + wallet daemons, mine a block with subsidy, perform a transfer, and assert both wallet balances update.
- `cd dashboard-ui && npm run screenshot` must pass with updated snapshots showing `/wallet` and `/network` routes plus the existing `/mining` capture.
- README, DESIGN.md, METHODS.md must reference the new runbook, reward schedule, and telemetry metrics. The runbook must be self-contained and runnable.

## Idempotence and Recovery

- The runbook relies on temp directories and configurable ports so it can be repeated without clobbering prior state.
- The integration test uses `tempfile::tempdir()` for storage and aborts spawned tasks during teardown; rerunning it should not leave processes behind.
- Playwright snapshots wrap HTML markup into SVG strings, so rerunning `npm run screenshot` will update deterministic artifacts without storing binary assets.

## Artifacts and Notes

- Snapshot SVGs for `/wallet` and `/network` pages stored under `dashboard-ui/tests/smoke.spec.ts-snapshots/`.
- Test log excerpts from `cargo test --test node_wallet_daemon` and `npm run screenshot` attached in the final summary.

## Interfaces and Dependencies

- Integration test relies on `node::NodeService`, `node::api::serve`, `wallet::WalletStore`, `wallet::WalletSyncEngine`, `wallet::rpc::WalletRpcClient`, and `wallet::tx_builder::build_transaction`.
- Deterministic telemetry uses constants in `scripts/dashboard_service.py` and `dashboard-ui/src/mocks/nodeSamples.ts`.
- Playwright tests use `@playwright/test` with the existing configuration in `dashboard-ui/playwright.config.ts` (FastAPI proxy + Vite dev server).
