# Single Binary "Apple-like" Release Plan

This ExecPlan defines the roadmap to collapse the current multi-process, multi-language stack (Rust Node + Rust Wallet + Python Dashboard + Node.js UI) into a single, zero-dependency binary (`hegemon`) that delivers an "Apple-like" user experience. This document follows `.agent/PLANS.md` and remains a living source of truth; update it whenever progress, decisions, or surprises emerge.

## Purpose / Big Picture

Currently, running the full stack requires a developer environment (Rust, Python, Node.js, Make) and multiple terminal windows. The goal is to produce a single executable that: (1) contains the full node and miner logic, (2) embeds the compiled dashboard UI directly into the binary, (3) serves the UI and API from an internal Axum server (replacing the Python middleware), (4) manages the wallet daemon internally without separate process management, and (5) offers a simple `setup` wizard to replace shell scripts. The end-user experience should be: download `hegemon`, run `./hegemon start`, and the browser opens with a fully functional, private, mining node.

## Progress

- [x] (2025-11-19 09:00Z) Drafted the single-binary convergence scope and captured high-level targets for UI embedding, Python migration, wallet integration, and CLI unification.
- [x] (2025-11-22 05:45Z) Reviewed current `node/`, `wallet/`, `dashboard-ui/`, and `scripts/` implementations to align the architecture narrative with the existing Axum router, embedded UI assets, wallet API nesting, and CLI surface.
- [x] (2025-11-22 06:15Z) Sequenced the embedding, routing, and packaging steps across `node/`, `wallet/`, `dashboard-ui/`, and `scripts/`, filled validation and recovery notes, and circulated this revision for maintainer review.

## Surprises & Discoveries

- The Rust side already embeds the dashboard UI under `node/src/dashboard/assets/` via `rust-embed` in both `node/src/dashboard.rs` and `node/src/ui.rs`, so the remaining migration effort is mostly about endpoint parity and build wiring rather than rewriting the UI pipeline.
- Axum’s router already exposes `/node/process`, `/node/process/start`, and `/node/lifecycle` alongside SSE/websocket streams (`/node/events/stream`, `/node/ws`), reducing the number of FastAPI-only orchestration endpoints that need Rust replacements.

## Decision Log

- Decision: Treat `scripts/dashboard_service.py` as legacy scaffolding and drive all dashboard calls through `node/src/api.rs` plus the embedded Axum wallet router.
  Rationale: Axum already exposes `/node/*` aliases and wallet nesting, reducing duplication and simplifying the single-binary goal.
  Date/Author: 2025-11-22 / GPT-5.1-Codex-Max
- Decision: Keep `node/src/dashboard.rs` + `node/src/ui.rs` as the single source of truth for SPA fallbacks and MIME handling while using build scripts to refresh `node/src/dashboard/assets/` from `dashboard-ui/dist/` each release.
  Rationale: Avoids drift between two embed targets and keeps the Axum fallback (`crate::ui::static_handler`) consistent for both API and top-level routers.
  Date/Author: 2025-11-22 / GPT-5.1-Codex-Max
- Decision: Favor embedded wallet startup wired through `node/src/bin/node.rs::run_node` over spawning the standalone wallet binary unless explicitly requested by operators.
  Rationale: Consolidates auth token handling and `/node/wallet/*` routing while keeping `wallet/src/bin/wallet.rs` available for advanced use.
  Date/Author: 2025-11-22 / GPT-5.1-Codex-Max

## Outcomes & Retrospective

- Feasibility check complete: the current Axum router, embedded assets, and CLI afford the single-binary direction without new languages. This plan now names the concrete files, functions, and endpoints to adjust before wider review. Circulate this revision for maintainer feedback prior to implementation and revisit after the first embedded wallet test run.

## Context and Orientation

- `node/src/dashboard.rs::dashboard_router` and `node/src/ui.rs::static_handler` both derive `rust-embed` over `node/src/dashboard/assets/` (populated from `dashboard-ui/dist/`) and implement the SPA fallback, MIME detection, and `/assets/*` handling.
- `node/src/api.rs::node_router` builds the Axum surface the dashboard consumes: transaction submission, consensus snapshots, miner control/status, `/node/process` + `/node/process/start` + `/node/lifecycle` helpers, websocket + SSE streams, `/node/storage/footprint`, and UI-compatible `/node/*` aliases. It nests `wallet::api::wallet_router` when provided a `wallet::api::ApiState` and falls back to `crate::ui::static_handler` so UI routes stay in-process.
- `wallet/src/api.rs::wallet_router` exposes `/status` and `/transfers` with optional auth token enforcement; `wallet/src/bin/wallet.rs` keeps the standalone daemon entry point that shares storage and sync code with the embedded path.
- `dashboard-ui/` remains the React/Vite SPA whose production build must be copied to `node/src/dashboard/assets/` before compiling the Rust binary.
- `scripts/dashboard_service.py` still wires FastAPI routes, NDJSON/SSE streams, and autostart logic (node + wallet) from `scripts/dashboard.py`; its remaining unique behaviors are the action stream and process orchestration helpers that should be mirrored in Rust before deprecating it from operator flows.
- `node/src/bin/node.rs` defines the `hegemon` CLI (`start`, `setup`, `export-peers`) plus flags for API/P2P addresses, miner tuning (`--miner-workers`, `--note-tree-depth`, `--miner-seed`), wallet bootstrapping (`--wallet-store`, `--wallet-passphrase`, `--wallet-auto-create`), and TLS/token generation during setup.

## Architecture Changes

### 1. UI Embedding (`rust-embed`)
- **Current:** `node/src/dashboard.rs` and `node/src/ui.rs` use `rust-embed` to serve prebuilt assets from `node/src/dashboard/assets/`, and the Axum routers fall back to `index.html` for SPA routes.
- **Target:** Keep the embedded asset path stable and replace the checked-in artifacts with `dashboard-ui` release builds (`dashboard-ui/dist/`) during packaging so the binary always serves the compiled UI without an external server.
- **Implementation:** Confirm the `#[derive(RustEmbed)]` stanzas continue to point at `node/src/dashboard/assets/`, refresh comments to reference the `dashboard-ui` build copy, and script a `dashboard-ui` production build step that copies `dist/` into that folder prior to `cargo build -p node`.

### 2. Service Migration (Python -> Rust)
- **Current:** The Axum router in `node/src/api.rs` exposes `/node/*` endpoints (transactions, consensus status, miner control, wallet note/ciphertext feeds, lifecycle/process info) and nests the wallet HTTP API when provided a `wallet::api::ApiState`. `scripts/dashboard_service.py` is now a compatibility script rather than the primary backend.
- **Target:** Fully retire `scripts/dashboard_service.py` by mapping the remaining dashboard routes to Axum handlers (including the NDJSON action stream and autostart/process helpers) and ensuring the SPA consumes `/node/*` endpoints directly.
- **Implementation:** Extend `node/src/api.rs` with any missing dashboard actions (e.g., action streams or process helpers that still live in `scripts/dashboard.py`/`scripts/dashboard_service.py`) and document the endpoint parity so `dashboard-ui` no longer shells out through Python. Ensure the router still falls back to `crate::ui::static_handler` for the embedded UI.

### 3. Wallet Integration
- **Current:** The `node` crate depends on `wallet` and can nest `wallet::api::wallet_router` within the Axum tree. `wallet/src/api.rs` exposes `/status` and `/transfers` while `wallet/src/bin/wallet.rs` still supports daemon mode for external use.
- **Target:** Start the wallet sync engine inside the `node` process when wallet storage and passphrase are available, expose the embedded wallet API under `/node/wallet/*`, and keep the standalone wallet binary for advanced workflows until parity is proven.
- **Implementation:** Wire a wallet bootstrapper within `NodeService::start` or the CLI flow that opens `WalletStore`, initializes `WalletSyncEngine`, and mounts the Axum wallet router behind the shared auth token. Document environment/config flags in `node/src/bin/node.rs` (`--wallet-store`, `--wallet-passphrase`, `--wallet-auto-create`) that govern wallet auto-create and passphrase sourcing; keep `wallet/src/bin/wallet.rs` for operators who want process isolation.

### 4. Unified CLI (`hegemon`)
- **Current:** `node/src/bin/node.rs` (installed as `hegemon`) provides `start`, `setup`, and `export-peers` subcommands with flags for `--miner-workers`, `--note-tree-depth`, `--wallet-store`, `--wallet-passphrase`, `--wallet-auto-create`, TLS selection, peer import/export, and API/p2p addresses. TLS self-signed certificates are generated during `setup` and the CLI seeds API tokens and optional wallet secrets.
- **Target:** Keep the CLI as the single entry point while adding flags to control embedded wallet startup, dashboard asset refresh, and miner presets. Deprecate `scripts/dashboard_service.py` from docs in favor of `hegemon start`.
- **Implementation:** Document the CLI surface within this plan and in `README.md`, ensure the `start` path initializes node + Axum + embedded wallet + UI assets, and maintain backward-compatible flags until the unified binary fully replaces the Python/Node.js processes.

## Plan of Work

1.  **UI Static Build (`dashboard-ui/` → `node/src/dashboard/assets/`):** Wire a release build (`pnpm/npm run build`) that emits to `dashboard-ui/dist/` and copies the output into `node/src/dashboard/assets/` before packaging. Keep SPA route coverage and MIME types intact by leaning on `node/src/dashboard.rs::static_handler` and `node/src/ui.rs::static_handler`.
2.  **Rust UI Server Alignment (`node/src/dashboard.rs`, `node/src/ui.rs`):** Confirm the `RustEmbed` folder and SPA fallback behavior stay pointed at the copied assets, update comments/docs to reflect the build pipeline, and ensure `crate::ui::static_handler` remains the Axum fallback in `node/src/api.rs::node_router`.
3.  **Endpoint Parity (`node/src/api.rs`, `scripts/dashboard_service.py`, `scripts/dashboard.py`):** Inventory the FastAPI routes still consumed by `dashboard-ui` (action streams, orchestration helpers, NDJSON feeds) and implement missing handlers in Axum with `/node/*` prefixes. Remove or stub Python-only behaviors so the UI defaults to the Rust backend while keeping the script as a comparator.
4.  **Wallet Embedding (`node/src/bin/node.rs`, `wallet/src/api.rs`, `wallet/src/bin/wallet.rs`):** Add an embedded wallet bootstrap path that opens a store, unlocks with a provided passphrase, mounts `wallet::api::wallet_router` under `/node/wallet/*`, and runs `WalletSyncEngine` in-process. Retain the standalone wallet CLI but steer docs toward the embedded flow.
5.  **CLI and Docs Refresh (`node/src/bin/node.rs`, `README.md`, `docs/`):** Document the unified `hegemon` workflow, flags controlling wallet/UI embedding, and removal of Python orchestration in favor of the Axum server. Ensure CLI help text and examples match the new defaults.
6.  **Release Packaging (`scripts/`, `Makefile`, `node/Cargo.toml`):** Add build steps that run the UI build, copy assets, and compile the `node` crate with embedded resources. If `scripts/dashboard_service.py` remains for fallback, mark it deprecated in the runbooks.

## Concrete Steps

1. From repo root, run `cd dashboard-ui && npm install && npm run build` (or `pnpm`). Copy `dashboard-ui/dist/` into `node/src/dashboard/assets/` so `RustEmbed` serves production assets; verify `node/src/dashboard/assets/index.html` exists before `cargo build -p node`.
2. In `node/src/dashboard.rs` and `node/src/ui.rs`, keep the embed folder pointing at `src/dashboard/assets/`, confirm SPA fallbacks, and add comments explaining the build copy step to prevent drift. Ensure `node/src/api.rs::node_router` continues to call `crate::ui::static_handler` as the fallback.
3. Audit `scripts/dashboard_service.py` and `scripts/dashboard.py` for endpoints not yet mirrored in `node/src/api.rs` (action streams, autostart helpers, NDJSON feeds). Port or stub them into Axum with `/node/*` prefixes, reusing `NodeService`/wallet APIs instead of subprocess calls, and record parity status in this plan.
4. Extend `node/src/bin/node.rs` to optionally start the embedded wallet: parse `--wallet-store`/`--wallet-passphrase`/`--wallet-auto-create`, open `WalletStore`, initialize `WalletSyncEngine`, and pass a `wallet::api::ApiState` into `node::api::serve` so `/node/wallet/*` is live by default. Keep `wallet/src/bin/wallet.rs` documented as the standalone alternative.
5. Update `README.md` (whitepaper section) and any runbooks under `docs/` to promote `hegemon start` with embedded UI/wallet instead of `scripts/dashboard_service.py`. Remove references to the Python server where redundant and surface the Axum endpoints under `/node/*`.
6. Add a packaging step (Makefile or `scripts/`) that sequences: build UI → copy assets → `cargo build -p node --release`. Document that rerunning the build refreshes embedded assets and that `scripts/dashboard_service.py` is deprecated unless explicitly invoked.

## Validation and Acceptance

- Building the single binary must succeed from a clean tree using `npm run build` in `dashboard-ui/` followed by `cargo build -p node --release`, with the resulting `node` (hegemon) binary serving `/`, `/wallet`, and `/network` from embedded assets.
- `cargo test -p node --test api` and any wallet HTTP tests must pass against the Axum router without relying on `scripts/dashboard_service.py`.
- With `./target/release/node start --wallet-store wallet.store --wallet-passphrase ...`, hitting `http://127.0.0.1:8080/node/metrics`, `/node/miner/status`, `/node/process`, `/node/events/stream` (SSE), `/node/ws` (websocket), and `/node/wallet/status` should respond successfully using the embedded auth token.
- `node/src/bin/node.rs --help` must list wallet embed flags alongside miner and networking options, and docs should no longer instruct running `scripts/dashboard_service.py` for the dashboard.
- The dashboard SPA should load via `http://127.0.0.1:8080/` without external processes, confirming static assets are embedded.

## Idempotence and Recovery

- UI embedding is repeatable: rerunning the `dashboard-ui` build and copy step replaces the contents of `node/src/dashboard/assets/` without manual cleanup; missing assets will cause `rust-embed` lookups to 404 until rebuilt.
- If Axum endpoint parity breaks, fall back to `scripts/dashboard_service.py` for debugging; once parity is achieved, the Python path can be disabled by default and the plan updated to record the retirement.
- Wallet embedding should detect missing stores and either auto-create when flagged or exit with a clear error, allowing reruns after the operator fixes the passphrase/store path. Keep `wallet/src/bin/wallet.rs` as the recovery path for isolated sync while the embedded flow is hardened.
- Binary rebuilds remain deterministic because `rust-embed` bakes whatever is present under `node/src/dashboard/assets/`; the recovery path is to regenerate assets and rebuild. If build scripts fail, clean `node/src/dashboard/assets/` and re-copy from `dashboard-ui/dist/`.

## Artifacts and Notes

- Embedded assets live in `node/src/dashboard/assets/` and should always come from `dashboard-ui/dist/` builds, not hand edits.
- Axum routes for the dashboard sit in `node/src/api.rs`, and UI routing falls back to `node/src/ui.rs` and `node/src/dashboard.rs`.
- `scripts/dashboard_service.py` can be used as a temporary comparator when verifying endpoint parity but should be removed from operator guidance after migration.

## Interfaces and Dependencies

- UI embedding depends on `rust-embed` and `mime_guess` within `node/src/dashboard.rs` and `node/src/ui.rs`.
- Dashboard HTTP interfaces rely on Axum routers in `node/src/api.rs` with `/node/*` aliases and nested wallet routes from `wallet::api::wallet_router`.
- Wallet embedding uses `WalletStore`, `WalletSyncEngine`, `wallet::api::ApiState`, and `WalletRpcClient` from the `wallet/` crate; CLI glue lives in `node/src/bin/node.rs`.
- Build orchestration depends on Node.js tooling (`npm`/`pnpm`) for `dashboard-ui` and Cargo for the Rust workspace.

Updated 2025-11-22 to align the plan with embedded Axum endpoints, rust-embed asset placement, wallet nesting, and the existing `hegemon` CLI surface.
