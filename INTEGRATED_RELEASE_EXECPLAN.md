# Single Binary "Apple-like" Release Plan

This ExecPlan defines the roadmap to collapse the current multi-process, multi-language stack (Rust Node + Rust Wallet + Python Dashboard + Node.js UI) into a single, zero-dependency binary (`hegemon`) that delivers an "Apple-like" user experience.

## Purpose / Big Picture

Currently, running the full stack requires a developer environment (Rust, Python, Node.js, Make) and multiple terminal windows. The goal is to produce a single executable that:
1.  Contains the full Node and Miner logic.
2.  Embeds the compiled Dashboard UI (HTML/JS/CSS) directly into the binary.
3.  Serves the UI and API from an internal HTTP server (replacing the Python middleware).
4.  Manages the Wallet daemon internally without requiring separate process management.
5.  Offers a simple `setup` wizard to replace shell scripts.

The end user experience should be: Download `hegemon`, run `./hegemon start`, and the browser opens with a fully functional, private, mining node.

## Progress

- [ ] (2025-11-19) Draft plan for Single Binary architecture.

## Architecture Changes

### 1. UI Embedding (`rust-embed`)
- **Current:** `dashboard-ui` is served by Vite dev server or Nginx.
- **Target:** Compile `dashboard-ui` to static assets (`dist/`). Use `rust-embed` to bake these files into the `node` binary.
- **Implementation:** Add a `ui` module to the `node` crate that serves these assets via `axum` or `warp`.

### 2. Service Migration (Python -> Rust)
- **Current:** `scripts/dashboard_service.py` (FastAPI) acts as a proxy/orchestrator between the UI and the Node/Wallet.
- **Target:** Port this logic into the `node` binary.
- **Implementation:**
    - The `node` binary's internal API server will handle the dashboard endpoints directly.
    - Replace `subprocess` calls (used by Python to start Node/Wallet) with internal thread spawning or library calls.

### 3. Wallet Integration
- **Current:** `wallet` is a separate binary running a daemon process.
- **Target:** Integrate `wallet` crate as a library into `node`.
- **Implementation:**
    - Add a `--with-wallet` flag (or default behavior) to `hegemon start`.
    - The Node process spawns the Wallet actor internally.
    - Communication happens via internal channels or the existing HTTP interface (bound to localhost).

### 4. Unified CLI (`hegemon`)
- **Current:** `cargo run -p node`, `cargo run -p wallet`, `make quickstart`.
- **Target:** A single `hegemon` CLI.
    - `hegemon start`: Runs Node + UI + (Optional) Wallet + (Optional) Miner.
    - `hegemon setup`: Interactive wizard for creating keys and config.
    - `hegemon mine`: Standalone miner mode.

## Plan of Work

1.  **UI Static Build:** Configure `dashboard-ui` to build completely static assets (ensure no absolute path dependencies).
2.  **Rust UI Server:** Add `rust-embed` and `axum-extra` (for static file serving) to the `node` crate. Serve the dummy UI first.
3.  **API Porting:** Port the critical endpoints from `dashboard_service.py` to the `node`'s Axum router.
    - `/actions` (Mock or implement Rust equivalents for `make` commands? Maybe simplify to just internal actions).
    - `/node/status`, `/node/metrics` (Already exist in Node, just need to ensure UI matches).
    - `/wallet/*` (Proxy to internal wallet actor).
4.  **Wallet Embedding:** Modify `node/Cargo.toml` to depend on `wallet` (or a shared `hegemon-core` crate if circular deps are an issue). Spawn the wallet daemon in a separate Tokio task.
5.  **CLI Polish:** Create the `hegemon` binary entry point (renaming `node` or creating a wrapper) with the new subcommand structure.

## Surprises & Discoveries

- *TBD*

## Decision Log

- *TBD*

## Outcomes & Retrospective

- *TBD*
