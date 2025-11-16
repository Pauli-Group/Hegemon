# Dashboard telemetry, wallet, and mining consoles in UI

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: `.agent/PLANS.md` defines how ExecPlans must be authored and maintained. Follow it explicitly for any updates.

## Purpose / Big Picture

The existing dashboard UI mirrors CLI actions but lacks visibility into the running node. This plan connects the UI to the node RPC so operators can review wallet balances, submit transfers, start or pause miners, and watch live telemetry without leaving the browser. After implementation, `npm run dev` plus the FastAPI proxy will expose `/wallet`, `/mining`, and `/network` routes with spark-line analytics, action controls, and real-time confirmation alerts driven by the node’s `/metrics`, `/wallet/*`, and `/ws` endpoints.

## Progress

- [x] (2025-02-15 12:50Z) Authored initial ExecPlan covering proxy design, React Query hooks, new routes, live telemetry stream, and Playwright screenshot harness.
- [x] (2025-02-15 13:35Z) Implemented FastAPI proxy additions (HTTPX client, SSE relay, miner control persistence, transfer log) and documented env vars in code comments.
- [x] (2025-02-15 14:20Z) Added React Query provider + hooks for metrics, wallet notes, miner status, transfers, and node event streams with mock fallbacks.
- [x] (2025-02-15 14:45Z) Built `/wallet`, `/mining`, `/network` pages with PageShell layout, spark-lines, send/receive forms, and mining controls wired to hooks.
- [x] (2025-02-15 15:00Z) Integrated EventSource-driven live updates, refreshed navbar/routes, and ensured BRAND.md typography/color usage.
- [x] (2025-02-15 15:20Z) Configured Playwright screenshot test + baseline, documented setup, and ran lint/build/test suites.

## Surprises & Discoveries

- Observation: Running Playwright inside the container failed because Chromium dependencies (libatk, libgbm, xvfb, etc.) were missing.
  Evidence: `npm run screenshot` errored with "Host system is missing dependencies" until `npx playwright install-deps chromium` installed the required apt packages.

## Decision Log

- Decision: Use FastAPI proxy extensions (instead of direct browser calls) to hit node RPC endpoints so CORS/auth headers stay centralized and devs can run `npm run dev` without reconfiguring browsers.
  Rationale: The CLI action service already runs alongside the UI; extending it with httpx/websocket relays avoids duplicating tokens in the frontend.
  Date/Author: 2025-02-15 / Assistant.

## Outcomes & Retrospective

Delivered proxy-backed wallet, mining, and network dashboards that consume real RPC data (with deterministic fallbacks) plus Playwright screenshot coverage. The UI now surfaces telemetry, spark-lines, and forms that reuse PageShell while the FastAPI proxy bridges CLI commands and node metrics. Future work could replace the in-memory transfer ledger with real transaction submissions once proofs are exposed via the node API.

## Context and Orientation

- `scripts/dashboard_service.py` exposes `/run/{slug}` for CLI actions. It needs to proxy new node data and produce SSE so the UI can consume telemetry without CORS hurdles.
- `dashboard-ui/` holds the Vite React app with shared `PageShell`, `ActionCard`, and `LogPanel` components pulling styles from `src/design/tokens.ts` (sourced via `scripts/sync-brand-tokens.mjs`).
- Node RPC endpoints (documented in `node/README.md` and implemented in `node/src/api.rs`) require the `x-auth-token` header and expose `/metrics`, `/wallet/notes`, and `/ws`.
- There is no global state management; new hooks should rely on React Query and small local reducers.

## Plan of Work

1. **Proxy upgrades**: extend `scripts/dashboard_service.py` with environment-driven node RPC configuration, `httpx` helpers, sample fallback payloads, miner control state (start/stop + target hash rate), a transfer ledger, and SSE endpoint bridging node WebSocket traffic (or synthetic events when RPC is absent). Update `scripts/dashboard_requirements.txt` for new dependencies and document env vars + workflows in `dashboard-ui/README.md`.
2. **Data hooks**: install `@tanstack/react-query`, `react-qr-code`, and `@playwright/test`. Wrap `<App />` with `QueryClientProvider`, create hooks (`useNodeMetrics`, `useMinerStatus`, `useWalletNotes`, `useTransferLedger`, `useNodeEventStream`) that hit the proxy endpoints via `fetch`, honor brand tokens, and surface placeholder data if the proxy responds with mock payloads.
3. **UI routes and components**: add `/wallet`, `/mining`, `/network` pages using `PageShell`. Build shared primitives (`MetricTile`, `Sparkline`, `ControlCard`, `TransactionList`) plus QR/export controls. Integrate mining start/stop buttons, hash-rate target slider, transfer form (address/memo/fee), and live transaction list fed by the hooks + event stream. Ensure typography/color align with `BRAND.md`.
4. **Realtime analytics + alerts**: use the SSE hook to append telemetry snapshots and block confirmations, feeding spark-lines and alert banners (e.g., stale blocks). Update the navbar to include the new routes and provide quick links for wallet/mining/network sections.
5. **Playwright coverage**: add `playwright.config.ts` with dual web servers (dashboard service + Vite dev server) and a `tests/screenshot.spec.ts` that captures a `/mining` snapshot (stored under `tests/__screenshots__`). Document `npm run screenshot` (or `npx playwright test`) in README, ensure `npm run build`, `npm run lint`, and the new Playwright run are included in validation.

## Concrete Steps

1. Edit `scripts/dashboard_requirements.txt` to add `httpx` and `websockets`. Re-install via `pip install -r scripts/dashboard_requirements.txt` when validating.
2. Modify `scripts/dashboard_service.py`:
   - Read `NODE_RPC_URL`/`NODE_RPC_TOKEN`, define fallback sample payloads, and create async helpers using `httpx`.
   - Add GET routes for `/node/metrics`, `/node/wallet/notes`, `/node/miner/status`, `/node/wallet/transfers` plus POST handlers for miner control + new transfer submissions.
   - Implement `/node/events/stream` SSE endpoint bridging to the node `/ws`, emitting synthetic intervals when RPC is disabled.
3. In `dashboard-ui/package.json`, add dependencies (`@tanstack/react-query`, `react-qr-code`) and dev deps (`@playwright/test`). Create npm scripts for `screenshot` (runs Playwright) and ensure `sync-actions` still works.
4. Add `playwright.config.ts` + `tests/screenshot.spec.ts` and commit baseline screenshot under `tests/__screenshots__/screenshot.spec.ts/`.
5. Create new hooks + types (`src/types/node.ts`, `src/hooks/useNodeData.ts`, etc.). Wrap `App` with `QueryClientProvider` in `src/main.tsx`.
6. Build components (`MetricTile`, `Sparkline`, `ControlCard`, `TransactionTable`, etc.) with CSS modules referencing design tokens.
7. Implement `WalletPage.tsx`, `MiningPage.tsx`, `NetworkPage.tsx` plus supporting CSS (grids, forms, charts) and wire them in `src/App.tsx` + nav.
8. Update README instructions detailing proxy env vars, dev workflow (`npm run dev` + `python scripts/dashboard_service.py`), and screenshot expectations. Mention SSE fallback/mocks.
9. Run `npm install`, `npm run sync-actions`, `npm run lint`, `npm run build`, and `npx playwright test --update-snapshots` (or `npm run screenshot`). Capture the generated screenshot artifact in repo.

## Validation and Acceptance

- Starting `python scripts/dashboard_service.py --reload` with `NODE_RPC_URL`/`NODE_RPC_TOKEN` configured should expose `/node/metrics` etc., returning live JSON or documented mock payloads when the node is offline.
- `npm run dev` should show new `/wallet`, `/mining`, `/network` routes using PageShell. Mining controls must toggle state, update target hash rate, and surface toast confirmations. Wallet send form posts to proxy and updates history. Network page shows spark-lines fed by SSE snapshots.
- `npm run screenshot` (Playwright) should boot the dev server(s) and emit a deterministic `/mining` screenshot stored under `tests/__screenshots__` (failing if layout regresses).

## Idempotence and Recovery

- Proxy endpoints rely on stateless httpx calls plus in-memory logs; restarting the FastAPI service resets miner-control + transfer history, which is acceptable for dev. Commands can be re-run without side-effects.
- React Query caches can be invalidated via `queryClient.invalidateQueries`. Playwright snapshots can be regenerated with `npx playwright test --update-snapshots` whenever layout changes.

## Artifacts and Notes

- Include sample JSON payloads for `/node/metrics` and `/node/wallet/notes` in README so engineers can verify responses manually via `curl`.
- Document screenshot path (`dashboard-ui/tests/__screenshots__/screenshot.spec.ts/mining-page-chromium.png`).

## Interfaces and Dependencies

- FastAPI endpoints (under `scripts/dashboard_service.py`):
    - `GET /node/metrics` → `TelemetrySnapshot` JSON.
    - `GET /node/wallet/notes` → `{ leaf_count, depth, root, next_index }`.
    - `GET /node/miner/status` → extends metrics with `is_running`, `thread_count`, `target_hash_rate`.
    - `POST /node/miner/control` body `{ action: 'start'|'stop', target_hash_rate?: float, thread_count?: int }`.
    - `GET/POST /node/wallet/transfers` for transfer history + submissions.
    - `GET /node/events/stream` SSE.
- Frontend hooks using React Query hitting `${dashboardServiceUrl}/node/...` endpoints with TypeScript interfaces for `TelemetrySnapshot`, `NoteStatus`, `TransferRecord`, and `NodeEvent`.
- Sparkline component should accept `data: { timestamp: number; value: number }[]`, `color`, `label`, and render responsive SVG abiding by brand colors.
