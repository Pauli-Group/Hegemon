# Unify dashboard with a live devnet in one interface

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

People running `make quickstart` today still land on a dashboard that shows mock mining data because the FastAPI proxy is not wired to a live node, the service dies if port 8001 is taken, and the UI keeps pointing at that dead port. The goal is to ship a single interface that boots a local devnet automatically, binds the FastAPI proxy and Vite UI to available ports, and streams real node telemetry so the mining page shows real hash rate/blocks without extra terminals or manual env setup. After this change, a new contributor should be able to run one command, open the printed UI URL, and watch actual PoW blocks getting mined from the same interface that lists the CLI actions.

## Progress

- [x] (2025-02-18 06:10Z) Draft plan capturing scope, constraints, and target behavior for the unified dashboard + devnet flow.
- [x] (2025-02-18 06:55Z) Wired dashboard_service to autostart a local node with env-driven defaults, create its db path, and stop the managed process on shutdown while keeping proxy fallbacks intact.
- [x] (2025-02-18 07:00Z) Hardened `scripts/full-quickstart.sh` to choose free ports, export the chosen service URL to the UI, and pass autostart env so the proxy and UI stay aligned.
- [x] (2025-02-18 07:03Z) Documented the single-command devnet/dashboard workflow in README without touching the whitepaper section.
- [ ] Run sanity checks (lint/tests if touched), verify quickstart launches UI + live telemetry, and update this plan with outcomes/any surprises.
- [ ] (2025-11-22 07:50Z) Attempted `make quickstart`, but `cargo clippy` failed in multiple crates (`network`, `node`, `pallet-fee-model`, `pallet-observability`, `pallet-identity`), preventing the stack from launching. Quickstart validation remains blocked pending lint fixes.
- [ ] (2025-02-18 08:25Z) Cleared clippy errors in `pallet-settlement` and `pallet-attestations`, but workspace `cargo clippy --all-features` still fails in upstream `pallet-collective` due to missing `try_successful_origin` implementations across mixed `sp_core` versions.
- [ ] (2025-02-18 09:30Z) Began binary-searching the remaining `cargo clippy -p runtime --all-features` failures; a dependency graph rebuild is still in-flight, so runtime lint errors are not yet surfaced. Need a faster isolation pass (feature-split clippy or `-Z timings`) before reattempting `make quickstart`.

## Surprises & Discoveries

- Clippy surfaced a backlog of warnings/errors across `network`, `node`, `pallet-identity`, `pallet-fee-model`, and `pallet-observability`, which stops `make check` and therefore aborts `make quickstart` before the FastAPI/Vite stack can start. The errors include deprecated `RuntimeEvent` wiring, missing trait imports, and outdated `OnChargeTransaction` implementations.
- Linting with `--all-features` now trips upstream `pallet-collective` because the version pulled in lacks the newer `try_successful_origin` methods while two `sp_core` versions are in the graph. Targeted pallet clippy runs succeed, but full-workspace linting still blocks quickstart validation.
- A full-runtime clippy pass is dominated by dependency rebuild time; without a scoped feature set, simply surfacing the runtime error messages can take several minutes. We need a narrower command sequence to reveal the failing `pallet-collective` bounds and `sp_core` version skew quickly.

## Decision Log

- Adopt a divide-and-conquer lint strategy for the runtime: first run `cargo clippy -p runtime --no-default-features --features std` and then incrementally layer the remaining feature sets (`runtime-benchmarks`, `try-runtime`, `fast-runtime`) to pinpoint the `pallet-collective` regression before attempting another full `--all-features` pass.

## Outcomes & Retrospective

- Quickstart validation is still pending because `make check` fails on clippy lint errors across several crates. Stack launch and telemetry checks could not be observed in this run; fixing the lint regressions is now a prerequisite for confirming the autostarted node and UI bindings.

## Context and Orientation

The dashboard stack has two pieces: `scripts/dashboard_service.py` (FastAPI proxy) and `dashboard-ui/` (Vite/React UI). The service currently proxies metrics from a node only when `NODE_RPC_URL`/`NODE_RPC_TOKEN` are set; otherwise it emits mock telemetry. The service also exposes `NodeProcessSupervisor.start()` to spawn a node via `POST /node/process/start`, but quickstart never calls it. The UI pages (`pages/NodePage.tsx`, `pages/MiningPage.tsx`, etc.) consume the proxy endpoints and render live charts or fall back to placeholders. `scripts/full-quickstart.sh` runs dev setup, tests, benches, wallet demo, and then launches uvicorn on port 8001 and Vite on 5173, but it neither starts a node nor adjusts when those ports are in use, so users often end up with a dead service and mock graphs.

## Plan of Work

1. Add an autostart path inside `scripts/dashboard_service.py`: on startup, optionally spawn a local node using `NodeProcessSupervisor` with defaults suitable for a throwaway devnet (local-only RPC, predictable token, state under `state/`). Extend the launch payload to accept miner/thread/tree params and add a shutdown hook to terminate the child so we do not orphan processes. Keep metrics/event streaming wired to the spawned node and fall back to mocks only if autostart fails.
2. Tighten `scripts/full-quickstart.sh`: choose free ports for the FastAPI proxy and Vite UI, export the chosen service URL to the UI, enable the autostart flag/env for the service, and print the actual URLs. Keep existing wallet-daemon hook intact. Ensure cleanup kills the uvicorn/Vite stack while letting the service stop its child node.
3. Update documentation so a newcomer sees the single-command path: add a short note in README’s getting-started/dashboard section describing that `make quickstart` now launches the UI + autostarted miner on available ports and where to look for the printed URLs. Preserve the whitepaper ordering and branding.
4. Validate: run targeted commands (lint/tests if we touch Rust/Python), then run `make quickstart` to confirm the dashboard service stays up on the chosen port, UI points at it, mining telemetry shows non-zero hash rate/blocks, and the process cleanup works. Capture any gotchas in this plan and conclusions in Outcomes.

## Concrete Steps

Describe edits and commands in the order to perform them.

- Modify `scripts/dashboard_service.py` to:
    - Extend the node launch payload with miner/thread/tree params and add a `stop()` helper.
    - Add startup/shutdown hooks that autostart a local node when `DASHBOARD_AUTOSTART_NODE` is set, using env-driven host/port/token/db defaults, and call `stop()` on shutdown.
    - Keep telemetry/event proxies pointing at the spawned node and leave mock fallbacks untouched for environments that disable autostart.
- Modify `scripts/full-quickstart.sh` to:
    - Detect an available port for the FastAPI proxy (preferring 8001) and Vite UI (preferring 5173), export the actual `VITE_DASHBOARD_SERVICE_URL`, and echo the final URLs.
    - Pass `DASHBOARD_AUTOSTART_NODE=1` and related env (host/port/db/token) into uvicorn so mining data is live by default.
    - Maintain existing cleanup of child processes and optional wallet-daemon launch.
- Update README in the getting-started/dashboard area (not the whitepaper section) to describe the unified quickstart → live dashboard flow and the new port behavior.
- Run `make check` if touched Rust (node changes), otherwise `cargo fmt` not needed; consider `python -m compileall scripts/dashboard_service.py` to catch syntax errors. Run `make quickstart` once to validate the end-to-end experience and note the observed UI/API URLs and telemetry in this plan.

## Validation and Acceptance

Acceptance means a fresh run of `make quickstart` on a clean shell results in: the FastAPI proxy binding to an available host:port without “address already in use” errors; the UI starting on the printed port and loading with `VITE_DASHBOARD_SERVICE_URL` pointing at the live proxy; the mining page showing non-zero hash rate and block events within seconds (confirm by watching the charts or reading the telemetry log panel); and pressing Ctrl+C tears down the UI/proxy while the autostarted node exits cleanly. If tests are run, they must pass (e.g., `make check` stays green).

## Idempotence and Recovery

Autostart should be rerunnable: if the node db already exists under `state/`, the service should reuse it; if the preferred ports are busy, quickstart should choose new ones and print them. If autostart fails, the service should keep running with mock data so the UI still loads; retry by restarting quickstart after freeing ports. Cleanup traps in the script and shutdown hooks in the service should prevent orphaned processes; if a node lingers, kill it by PID from `state/node-process.log`.

## Artifacts and Notes

Record key transcripts once validated: the chosen service/UI URLs, sample telemetry log lines showing mined blocks, and any warnings about port fallbacks. Keep snippets short and focused on proving the behavior works.

## Interfaces and Dependencies

- `scripts/dashboard_service.py`
    - Extend `NodeLaunchPayload` to accept optional `miner_workers: Optional[int]`, `note_tree_depth: Optional[int]`, and `miner_seed: Optional[str]`.
    - Add `NodeProcessSupervisor.stop(&self)` to terminate the managed process and update state.
    - Startup/shutdown hooks should call the new autostart logic and `stop()`.
- `scripts/full-quickstart.sh`
    - Helper to select open ports (prefer 8001/5173) and export `VITE_DASHBOARD_SERVICE_URL` accordingly.
    - Export `DASHBOARD_AUTOSTART_NODE=1`, `DASHBOARD_NODE_HOST`, `DASHBOARD_NODE_PORT`, `DASHBOARD_NODE_DB_PATH`, and `DASHBOARD_NODE_TOKEN` to uvicorn so the service boots a live node.
- README getting-started/dashboard section
    - Add prose describing the single-command path and port fallback expectations without altering the whitepaper heading or ordering.
