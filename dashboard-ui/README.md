# Dashboard UI

A Vite + React + TypeScript shell that mirrors the CLI workflows declared in `scripts/dashboard.py`. The UI renders:

- **Action catalog** – grouped cards for every dashboard action with filtering.
- **Action run view** – JetBrains Mono playback of the exact CLI commands.
- **Quickstart summary** – timeline for the `quickstart` action plus dependent prep steps.

Design tokens come directly from `docs/ui/brand_tokens.json` (via `src/design/tokens.ts`) so the colors, typography, spacing, and motion rules stay aligned with `BRAND.md`.

## Getting started

```bash
cd dashboard-ui
npm install
npm run sync-actions   # exports scripts/dashboard.py actions and copies docs/ui/brand_tokens.json
npm run dev
```

During development you can pass `--host 0.0.0.0 --port 4173` to `npm run dev` to expose the server externally (useful for screenshots with Playwright).

## Available scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start Vite dev server with hot reload. |
| `npm run build` | Type-check and build production assets. |
| `npm run preview` | Preview the production build locally. |
| `npm run sync-actions` | Re-export CLI actions into `src/data/actions.json` so the UI matches the CLI. |
| `npm run lint` | Run ESLint using the template defaults. |

## Data and design layers

- `scripts/dashboard_actions_export.py` imports `_actions()` from `scripts/dashboard.py` and outputs normalized JSON. The UI never hand-copies action metadata.
- `src/data/actions.ts` exposes typed helpers for listing/grouping actions and formatting command lines.
- `src/design/tokens.ts` imports the shared brand tokens JSON. `src/design/global.css` publishes CSS custom properties, the 12-column desktop grid (4-column mobile), and loads Space Grotesk + JetBrains Mono.
- Shared primitives (`PageShell`, `ActionCard`, `LogPanel`) enforce spacing, typography, and JetBrains Mono log rendering on every page.

## Screenshot guidance

When you make visual changes, start the dev server (`npm run dev -- --host 0.0.0.0 --port 4173`) and capture a browser screenshot that highlights the catalog grid or quickstart timeline to document layout updates.
