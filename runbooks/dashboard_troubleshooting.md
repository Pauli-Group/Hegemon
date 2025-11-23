# Dashboard troubleshooting guide (embedded UI)

Use this runbook when the dashboard served by `hegemon start` looks stale, fails to authenticate, or does not reflect node activity. The Python FastAPI proxy and standalone Vite UI have been removed; new issues should be debugged against the embedded bundle.

## What to expect

- `hegemon start` serves the dashboard on the configured `--api-addr` (default `127.0.0.1:8080`).
- All UI actions map directly to the underlying node RPCs; there is no separate shim or proxy.
- Branding and asset changes must go through `./scripts/build_dashboard.sh` so the embedded bundle stays aligned with `BRAND.md`.

## Common fixes

### Dashboard shows mock/empty data
- **Symptom:** Tiles read "mock data" or stay empty after the node has been mining.
- **Fix:**
  1. Verify the node is running: `ps -ef | grep hegemon` or `curl -s -H "x-auth-token: $TOKEN" http://127.0.0.1:8080/blocks/latest`.
  2. Confirm the dashboard token matches the node token. If you regenerated it, paste the new value into the dashboard "API auth token" field and click **Use for dashboard session**.
  3. Restart the node with the correct `--db-path` if you accidentally pointed the UI at an empty data directory.

### Port or bind conflicts
- **Symptom:** Browser cannot connect to the dashboard, or another service already binds the API port.
- **Fix:** Restart with an explicit bind and port: `./hegemon start --api-addr 127.0.0.1:8085`. If running multiple nodes, ensure each uses a unique `--api-addr`/`--p2p-addr` pair.

### Missing assets after UI edits
- **Symptom:** The UI loads but styling or icons look outdated compared to local `dashboard-ui/` changes.
- **Fix:** Rebuild the embedded assets and rebuild the binary:
  ```bash
  ./scripts/build_dashboard.sh
  cargo build -p node --release
  cp target/release/hegemon .
  ./hegemon start
  ```
  Document any intentional deviations from `BRAND.md` when you commit.

### Emergency fallback to CLI
- **Symptom:** UI remains unavailable after the above steps.
- **Fix:** Interact via CLI until the dashboard returns:
  ```bash
  ./hegemon start --api-addr 127.0.0.1:8080 --api-token $TOKEN
  cargo run -p wallet --bin wallet -- status --store /path/to/wallet --passphrase "$PASS"
  ```
  These commands exercise the same endpoints the UI uses, so you can continue operations while debugging the embedded dashboard.

## Legacy proxy/UI
The historical FastAPI + Vite stack has been removed. If you uncover discrepancies, file an issue against the embedded dashboard instead of reviving the old scripts.
