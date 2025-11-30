# Dashboard UI

A Vite + React + TypeScript shell that mirrors the guard-rail workflows captured in `src/data/actions.json` (kept in sync with the repo’s quickstart targets). The UI renders:

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
npm run sync-actions   # copies docs/ui/brand_tokens.json for the design layer
VITE_DASHBOARD_SERVICE_URL=http://127.0.0.1:8080 npm run dev
```

`VITE_DASHBOARD_SERVICE_URL` should point at the unified `Substrate node RPC endpoint (default `http://127.0.0.1:9944`). If it is omitted, the UI assumes it is being served directly by the node and falls back to mock payloads when requests fail.

During development you can pass `--host 0.0.0.0 --port 4173` to `npm run dev` to expose the server externally (useful for screenshots with Playwright). When using mocks, set `VITE_FORCE_MOCK_DATA_INDICATOR=true` to keep the UI in a known offline state.

## Connection badge & fallbacks

- The nav renders a `ConnectionBadge` sourced from `useNodeMetrics()`. When the node RPC answers requests it glows Proof Green and reads “Live.”
- If the RPC is unreachable or errors, the badge flips to Guard Rail red with “Offline,” every panel surfaces a tooltip explaining why mocks are in use, and a `DataStatusBanner` appears above the affected grids.
- Restoring connectivity (restart the node or update the connection URL) clears the banner on the next poll and flips the badge back to Proof Green.

## Log severity & export workflow

- `LogPanel` renders each NDJSON event as a JetBrains Mono row with a left border keyed to severity: Proof Green (`#19B37E`) for completed commands, Guard Rail (`#FF4E4E`) for failures/warnings, and a neutral surface accent for informational telemetry. This mirrors the color roles defined in `BRAND.md` so every dashboard surface reports status consistently.
- A header toolbar now ships with “Copy logs” and “Download .txt” controls. Both buttons bundle the buffered output (up to the last 50 lines) so operators can paste directly into PRs or attach the `.txt` artifact when responding to incidents.
- The 50-line limit matches the evidence request in `runbooks/security_testing.md`, making it trivial to capture the required snippets right after a guard-rail alert fires.
- Copy/export buttons follow the 150–200 ms ease-out motion rule: hover/focus states use the cyan accent ring while keeping the neutral base fill for idle states.

## Available scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start Vite dev server with hot reload. |
| `npm run build` | Type-check and build production assets. |
| `npm run preview` | Preview the production build locally. |
| `npm run sync-actions` | Refresh design tokens from `docs/ui/brand_tokens.json` for the design system. |
| `npm run lint` | Run ESLint using the template defaults. |
| `npm run screenshot` | Start the Vite dev server in mock-data mode and assert the `/mining` vector snapshot via Playwright. |

## Data and design layers

- `src/data/actions.ts` exposes typed helpers for listing/grouping actions and formatting command lines.
- `src/design/tokens.ts` imports the shared brand tokens JSON. `src/design/global.css` publishes CSS custom properties, the 12-column desktop grid (4-column mobile), and loads Space Grotesk + JetBrains Mono.
- Shared primitives (`PageShell`, `ActionCard`, `LogPanel`) enforce spacing, typography, and JetBrains Mono log rendering on every page.

## Screenshot guidance

- The Playwright harness (`npm run screenshot`) spins up the Vite dev server in mock-data mode, loads `/mining`, and serializes the `main` region into an SVG snapshot stored at `tests/screenshot.spec.ts-snapshots/mining-console.svg`. This keeps the artifact vector-based so it remains readable in code review without committing binary PNGs.
- When iterating manually you can still start `npm run dev -- --host 0.0.0.0 --port 4173` and capture additional visuals (prefer SVG or other vector exports when checking in artifacts).
