# Dashboard UI

A Vite + React + TypeScript shell that mirrors the CLI workflows declared in `scripts/dashboard.py`. The UI renders:

- **Action catalog** – grouped cards for every dashboard action with filtering.
- **Action run view** – JetBrains Mono playback of the exact CLI commands.
- **Quickstart summary** – timeline for the `quickstart` action plus dependent prep steps, with a one-click “Run quickstart” CTA that streams the entire setup directly from the page.
- **Wallet console** – balances, shielded send forms, and transaction history sourced from the node RPC.
- **Mining console** – live telemetry, start/stop controls, and target hash-rate configuration.
- **Network analytics** – spark-lines and alerts for stale blocks, mempool depth, and block confirmations.
- **Connection indicator** – a Proof Green nav pill that flips to Guard Rail when the UI falls back to mock payloads.

Design tokens come directly from `docs/ui/brand_tokens.json` (via `src/design/tokens.ts`) so the colors, typography, spacing, and motion rules stay aligned with `BRAND.md`.

## Getting started

```bash
cd dashboard-ui
npm install
npm run sync-actions   # exports scripts/dashboard.py actions and copies docs/ui/brand_tokens.json
pip install -r ../scripts/dashboard_requirements.txt
NODE_RPC_URL=http://127.0.0.1:8080 NODE_RPC_TOKEN=local-dev-token python ../scripts/dashboard_service.py --host 127.0.0.1 --port 8001
# in a second terminal
VITE_DASHBOARD_SERVICE_URL=http://127.0.0.1:8001 npm run dev
```

If no `NODE_RPC_URL` is provided the FastAPI proxy streams the deterministic mock payloads defined in `scripts/dashboard_service.py`, so designers can still develop UI flows offline.

To verify the proxy is reachable:

```bash
curl http://127.0.0.1:8001/node/metrics | jq
curl http://127.0.0.1:8001/node/wallet/notes | jq
```

During development you can pass `--host 0.0.0.0 --port 4173` to `npm run dev` to expose the server externally (useful for screenshots with Playwright).

## Connection badge & fallbacks

- The nav renders a `ConnectionBadge` sourced from `useNodeMetrics()`. When the FastAPI proxy answers requests it glows Proof Green and reads “Live data.”
- If the proxy is unreachable or errors, the badge flips to Guard Rail red with “Mock data,” every panel surfaces a tooltip explaining why mocks are in use, and a `DataStatusBanner` appears above the affected grids.
- Restoring the FastAPI proxy (re-run `python ../scripts/dashboard_service.py` with the correct `NODE_RPC_URL`/token) clears the banner on the next poll and flips the badge back to Proof Green.

## Available scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start Vite dev server with hot reload. |
| `npm run build` | Type-check and build production assets. |
| `npm run preview` | Preview the production build locally. |
| `npm run sync-actions` | Re-export CLI actions into `src/data/actions.json` so the UI matches the CLI. |
| `npm run lint` | Run ESLint using the template defaults. |
| `npm run screenshot` | Start the proxy + Vite dev server and assert the `/mining` vector snapshot via Playwright. |

## Data and design layers

- `scripts/dashboard_actions_export.py` imports `_actions()` from `scripts/dashboard.py` and outputs normalized JSON. The UI never hand-copies action metadata.
- `src/data/actions.ts` exposes typed helpers for listing/grouping actions and formatting command lines.
- `src/design/tokens.ts` imports the shared brand tokens JSON. `src/design/global.css` publishes CSS custom properties, the 12-column desktop grid (4-column mobile), and loads Space Grotesk + JetBrains Mono.
- Shared primitives (`PageShell`, `ActionCard`, `LogPanel`) enforce spacing, typography, and JetBrains Mono log rendering on every page.

## Screenshot guidance

- The Playwright harness (`npm run screenshot`) spins up the FastAPI proxy plus Vite dev server, loads `/mining`, and serializes the `main` region into an SVG snapshot stored at `tests/screenshot.spec.ts-snapshots/mining-console.svg`. This keeps the artifact vector-based so it remains readable in code review without committing binary PNGs.
- When iterating manually you can still start `npm run dev -- --host 0.0.0.0 --port 4173` and capture additional visuals (prefer SVG or other vector exports when checking in artifacts).
