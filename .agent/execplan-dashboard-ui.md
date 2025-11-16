# Dashboard UI scaffold aligned with CLI actions

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: `.agent/PLANS.md` defines how ExecPlans must be authored and maintained. Follow it explicitly for any updates.

## Purpose / Big Picture

Repository contributors currently interact with project workflows via the CLI defined in `scripts/dashboard.py`. The goal is to add a `dashboard-ui/` web package that visualizes those same actions with a responsive grid using the brand tokens in `docs/ui/brand_tokens.json`. After this change, someone can run `npm install` and `npm run dev` inside `dashboard-ui` to explore three pages: an action catalog, an action detail/log viewer, and a quickstart summary. All action metadata must stay in sync with the CLI by reading the `_actions()` definitions directly via a Python JSON exporter.

## Progress

- [x] (2025-02-14 18:40Z) Authored initial ExecPlan covering UI scaffold, data export, and responsive pages.
- [x] (2025-02-14 19:05Z) Scaffolded `dashboard-ui/` via Vite (React + TS) with npm dependencies installed for routing/utilities.
- [x] (2025-02-14 19:20Z) Added Python exporter (`scripts/dashboard_actions_export.py`) and wired `npm run sync-actions` to materialize `src/data/actions.json`.
- [x] (2025-02-14 19:45Z) Implemented token sync, global CSS, and shared primitives (PageShell, ActionCard, LogPanel) pulling values from `docs/ui/brand_tokens.json`.
- [x] (2025-02-14 20:05Z) Built catalog, action detail, and quickstart pages with responsive 12/4 column grid, JetBrains Mono logs, and router wiring.
- [x] (2025-02-14 20:25Z) Ran `npm run sync-actions`, `npm run build`, updated the package README with dev instructions, and captured a catalog screenshot via Playwright.
- [x] (2025-02-14 20:25Z) Updated progress, surprises, and validation notes per PLANS.md requirements.

## Surprises & Discoveries

- Observation: `npm create vite@latest` now prompts for the experimental rolldown bundler, which stalled in this non-interactive session; using `npm create vite@5.2.0` bypassed the prompt and produced the scaffold deterministically.
  Evidence: repeated prompts halted progress until falling back to the 5.2.0 scaffolder.

## Decision Log

- Decision: Use Vite + React + TypeScript with npm for the `dashboard-ui` package to align with modern tooling and keep dependencies minimal.
  Rationale: Vite scaffolding is fast, supports hot reloads, and integrates easily with design tokens and router requirements without affecting the Rust workspace.
  Date/Author: 2025-02-14 / Assistant

## Outcomes & Retrospective

- Delivered the first iteration of `dashboard-ui/` with synced CLI data, responsive catalog/detail/quickstart pages, and brand-aligned primitives. Future enhancements could add live command execution status or streaming logs sourced from the CLI output.

## Context and Orientation

- CLI actions live in `scripts/dashboard.py` where `_actions()` returns dataclass instances. We must not duplicate their metadata manually; instead, the UI should rely on a generated JSON feed from this source.
- Branding constraints live in `BRAND.md` and the token file `docs/ui/brand_tokens.json`. Typography specifies Space Grotesk and JetBrains Mono along with spacing rules.
- There is no existing `dashboard-ui` package; we will create it at the repository root alongside other top-level directories.
- The new UI will need routing, shared primitives, and pages for: (1) Action catalog (grid of cards grouped by category), (2) Action run view (detailed log panel showing commands), and (3) Quickstart summary (focused view referencing `quickstart` action steps).

## Plan of Work

1. **Scaffold Vite React app** inside `dashboard-ui/` using `npm create vite@latest dashboard-ui -- --template react-ts`. Configure `.gitignore`, `tsconfig`, `vite.config.ts`, and `package.json` scripts for `dev`, `build`, `preview`, plus `sync-actions` pointing to the Python exporter. Install dependencies: `react-router-dom`, `clsx`, and dev typings. Fetch fonts via CSS `@import` from Google Fonts (Space Grotesk, JetBrains Mono).
2. **Author Python exporter** `scripts/dashboard_actions_export.py` that imports `_actions()` from `scripts.dashboard`, normalizes dataclasses to JSON (slugs, titles, descriptions, categories, notes, command arrays with argv/cwd/env). Support `--out` (default prints to stdout). Document usage in package README.
3. **Wire data layer in UI**: add `dashboard-ui/src/data/actions.ts` that loads the generated JSON (e.g., `src/data/actions.json`) and exposes helpers (list all actions, find by slug, group by category). Provide TypeScript interfaces matching the JSON schema so data stays typed.
4. **Integrate design tokens**: create `dashboard-ui/src/design/tokens.ts` derived from `docs/ui/brand_tokens.json` values. Expose color palette, typography scale, spacing constants. Add `src/design/global.css` with CSS variables, font-face declarations, body resets, and responsive grid utilities (12-column desktop, 4-column mobile) per tokens.
5. **Shared primitives**: implement `PageShell` (layout wrapper with nav, responsive grid, accent background), `ActionCard` (display slug, title, description, chips for category, counts), and `LogPanel` (JetBrains Mono, neutral surface, scrollable). Use CSS modules or standard CSS/SCSS? We'll use CSS modules via `.module.css` files or tailwind? Keep simple with CSS modules in same folder referencing CSS variables.
6. **Pages and routing**:
   - `ActionCatalogPage`: group actions by category, render cards within CSS grid responsive layout, include quick filter input.
   - `ActionRunPage`: use router param slug to display action details, list command steps with `LogPanel` showing command text, show metadata.
   - `QuickstartPage`: show summary of `quickstart` action with step timeline, highlight dependency actions (fmt/lint/test?). Provide call-to-action buttons linking to detail.
   - Setup `App.tsx` with router nav (catalog, quickstart). Add default route to catalog and fallback for unknown slug.
7. **Responsive behavior**: use CSS grid with `grid-template-columns: repeat(auto-fit, minmax(...))` but ensure 12-col on desktop (calc). Provide CSS classes (e.g., `.grid-desktop-12` with `display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: var(--grid-gutter)`). On smaller screens use media queries for 4 columns. Use JetBrains Mono for log text.
8. **Validation**: run `npm install`, `npm run sync-actions`, `npm run build`. Optionally `npm run lint` if configured. Document commands in README. Capture screenshot by running `npm run dev -- --host 0.0.0.0 --port 4173` and using Playwright to load `http://127.0.0.1:4173`.
9. **Docs**: update `dashboard-ui/README.md` describing stack, commands, data sync, screenshot instructions referencing brand tokens.

## Concrete Steps

1. From repo root, run `npm create vite@latest dashboard-ui -- --template react-ts`. Enter prompts as needed. `cd dashboard-ui`, run `npm install`. Install additional deps: `npm install react-router-dom clsx` and `npm install -D @types/node`. Ensure `package-lock.json` captured.
2. Create Python exporter `scripts/dashboard_actions_export.py` with CLI `--out` (defaults to stdout). Use `json.dumps` with `indent=2`. Add helper to convert dataclasses to dicts. Provide main guard. Add instructions to README.
3. Inside `dashboard-ui`, add script `"sync-actions": "python ../scripts/dashboard_actions_export.py --out src/data/actions.json"` to `package.json`. Run `npm run sync-actions` to generate file.
4. Implement TypeScript interfaces in `src/data/types.ts`, data loader file referencing JSON, grouping utilities.
5. Copy `docs/ui/brand_tokens.json` values into `src/design/tokens.ts`. Add `src/design/global.css` referencing CSS variables. Import CSS in `src/main.tsx`.
6. Create `src/components/PageShell.tsx`, `ActionCard.tsx`, `LogPanel.tsx` with CSS modules or inline styles referencing tokens.
7. Build pages under `src/pages/` with React components using router. Setup `src/App.tsx` with `<BrowserRouter>` and layout nav.
8. Update `src/main.tsx` to render `<App />`. Remove Vite starter assets.
9. Add README describing dev instructions, data sync, screenshot steps.
10. Run `npm run sync-actions`, `npm run build`, optionally `npm run preview` for smoke. Capture screenshot via Playwright hitting dev server.
11. Update ExecPlan progress, decision log, etc., as work completes if needed.

## Validation and Acceptance

- `cd dashboard-ui && npm run sync-actions && npm run build` should complete without errors. `npm run dev` must start local server showing catalog grid using brand colors/typography and JetBrains Mono logs.
- Visiting `/` shows action catalog with cards grouped by category on desktop (12 columns) and collapsed on mobile (4 columns). `/actions/quickstart` (or dedicated quickstart path) shows detail timeline. `/quickstart` page summarizes steps.
- Running `npm run sync-actions` after editing `scripts/dashboard.py` should refresh `src/data/actions.json` to reflect new actions without manual edits.

## Idempotence and Recovery

- Vite scaffold is deterministic; rerunning `npm install` resets `node_modules`. The Python exporter only overwrites the JSON file specified; re-run `npm run sync-actions` any time. If `dashboard-ui` folder already exists, remove before re-scaffolding. `npm run build` can be re-run safely.

## Artifacts and Notes

- After exporter runs, `dashboard-ui/src/data/actions.json` should contain sorted action entries. Include excerpt example in README to show schema.

## Interfaces and Dependencies

- `scripts/dashboard_actions_export.py` interface: CLI script with optional `--out` path; writes JSON with keys `slug`, `title`, `description`, `category`, `notes`, `commands` (list of `argv`, `cwd`, `env`).
- TypeScript types: `export interface DashboardAction { slug: string; title: string; description: string; category: string; notes?: string; commands: CommandSpec[] }` and `CommandSpec { argv: string[]; cwd?: string; env?: Record<string, string>; }`.
- Components: `PageShell` props for `title`, `intro`, `actions?`, `children`. `ActionCard` props for `action: DashboardAction`. `LogPanel` props for `title`, `lines: string[]`.

