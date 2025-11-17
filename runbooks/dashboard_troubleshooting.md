# Dashboard troubleshooting guide

Use this runbook when the graphical operations dashboard needs to be mapped back to the CLI workflows defined in `scripts/dashboard.py`.

## Modes and command mapping

| Workflow | GUI equivalent | CLI / make command |
| --- | --- | --- |
| Open the interactive menu | Launch dashboard UI in a browser | `make dashboard` or `./scripts/dashboard.py` |
| Run a specific action | Click “Run action” on the corresponding detail page | `./scripts/dashboard.py --run <slug>` |
| Full quickstart | Click the quickstart timeline CTA | `make quickstart` (which calls `./scripts/dashboard.py --run quickstart`) |

The FastAPI service (`scripts/dashboard_service.py`) simply wraps `_actions()` and streams the same subprocess commands. Every UI toast, status pill, and log line is derived from the NDJSON event stream emitted by `POST /run/<slug>`.

## Starting the graphical dashboard

1. Install the Python dependencies and start the streaming service:
   ```bash
   pip install -r scripts/dashboard_requirements.txt
   uvicorn scripts.dashboard_service:app --host 0.0.0.0 --port 8001
   ```
2. Launch the Vite UI against that service:
   ```bash
   cd dashboard-ui
   npm install
   VITE_DASHBOARD_SERVICE_URL=http://127.0.0.1:8001 npm run dev
   ```
3. Visit `http://localhost:5173`. Each action card links to `/actions/<slug>`, where the “Run action” button triggers the FastAPI `POST /run/<slug>` endpoint and streams logs into the JetBrains Mono panel.

## Troubleshooting scenarios

### Connection badge turns Guard Rail red
- **Symptom:** The nav pill and panel badges read “Mock data,” banners explain that mock payloads are in use, and telemetry tiles stop updating.
- **Fix:**
  1. Confirm `scripts/dashboard_service.py` is running and reachable at the URL exported via `VITE_DASHBOARD_SERVICE_URL`. If it is not running, restart it with the correct `NODE_RPC_URL`/token so the badge can flip back to Proof Green on the next poll.
  2. If the service is running, tail its stdout/stderr for FastAPI errors (authentication, upstream RPC failures, etc.) and resolve the underlying issue. The `DataStatusBanner` tooltip mirrors the exception message reported by the proxy.
  3. After remediation, refresh the dashboard. The banners disappear automatically once live data flows again.

### Service port conflicts
- **Symptom:** UI cannot connect; fetch calls fail with `ECONNREFUSED`.
- **Fix:** Ensure `uvicorn scripts.dashboard_service:app --port 8001` is running. If port 8001 is occupied, pass `--port 8010` and update `VITE_DASHBOARD_SERVICE_URL` accordingly.

### Missing FastAPI / uvicorn
- **Symptom:** Starting the service fails with `ModuleNotFoundError: fastapi` or `uvicorn`.
- **Fix:** Re-run `pip install -r scripts/dashboard_requirements.txt`. The requirements file lives next to the scripts so contributors do not have to guess versions.

### Missing Rust or cargo when launching the node
- **Symptom:** The Node page shows a Guard Rail red error such as `Required command 'cargo' not found on PATH` and the process stays in the `error` state with no PID.
- **Fix:**
  1. Run `make quickstart` (or `./scripts/dev-setup.sh`) from the repo root to install Rustup and the cargo toolchain that the node launcher shells out to.
  2. Verify the install with `cargo --version` in a fresh shell so the PATH is updated.
  3. Retry launching the node from the dashboard; the status badge should advance to `starting` once cargo is available.

### CLI action failure surfaced in UI
- **Symptom:** Toast turns Guard Rail red, status badge shows “Error”, logs end with `✖ Action <slug> failed…`.
- **Fix:** The UI is reflecting the same exit code you would see via `./scripts/dashboard.py --run <slug>`. Re-run the failing slug directly (e.g., `./scripts/dashboard.py --run check`) or via `make` (`make bench`, `make check`, etc.) to reproduce locally and debug.

### UI sync drift
- **Symptom:** The UI shows different actions than the CLI.
- **Fix:** Run `npm run sync-actions` so `dashboard-ui/src/data/actions.json` is regenerated from `_actions()`. The FastAPI service always uses the live `_actions()` definition, so keeping the static export fresh ensures the catalog and server match.

### Emergency fallback to CLI
- If the graphical dashboard is unavailable, call `make dashboard` for the interactive CLI or `./scripts/dashboard.py --run <slug>` for a single action. These commands execute the same workflows and provide parity with CI.
