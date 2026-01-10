# Hegemon App UX + Brand Refresh (Operator Cockpit)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintained in accordance with `.agent/PLANS.md`.


## Purpose / Big Picture

After this work, the desktop app feels like an operator-grade control room instead of a long “settings form”: it becomes faster to scan, harder to misuse, and easier to recover when things go wrong.

Observable outcome: running `npm run dev` in `hegemon-app/` opens an Electron window with (1) a global status bar that makes the currently selected node + wallet context unambiguous, (2) a left navigation that separates “Overview”, “Node”, “Wallet”, “Send”, “Disclosure”, and “Console” into focused workspaces, and (3) task-first flows (guided setup, safe sends, mining controls) that surface Hegemon-specific constraints like genesis binding and note consolidation at the moment they matter.

This refresh must remain a real app (not a mockup): every screen is wired to the existing Electron IPC (`window.hegemon.*`) and exercises real `hegemon-node` + `walletd` behavior.


## Progress

- [x] (2026-01-10) Drafted the UX + brand refresh ExecPlan.
- [ ] UX audit: map tasks and failure modes.
- [ ] Build App Shell: nav + global status.
- [ ] Build Overview workspace: “command center”.
- [ ] Extract reusable UI components and tokens.
- [ ] Rebuild Node workspace around “operate + observe”.
- [ ] Rebuild Wallet/Send workspaces around “safe funds flow”.
- [ ] Rebuild Console workspace as timeline + diagnostics.
- [ ] Add E2E + visual regression harness for Electron.
- [ ] Polish pass: copy, empty states, motion, a11y.


## Surprises & Discoveries

- Observation: (none yet)
  Evidence: n/a


## Decision Log

- Decision: Treat the app as an “operator cockpit” with focused workspaces, not a single scrolling dashboard.
  Rationale: The primary users are operators/miners and security-minded wallet users who need scanning, guardrails, and recoverability more than novelty UI.
  Date/Author: 2026-01-10 / Agent

- Decision: Keep the existing base palette and typography from `BRAND.md`, but tighten “semantic tokens” and component hierarchy.
  Rationale: The current system already matches the project’s high-trust neutrality; the improvement is consistency, not a new vibe.
  Date/Author: 2026-01-10 / Agent

- Decision: Ship the redesign incrementally behind a UI version switch until parity is reached, then delete the legacy view.
  Rationale: Preserves a working product throughout the refactor; reduces risk of “half-redesign” regressions.
  Date/Author: 2026-01-10 / Agent

- Decision: Use `react-router-dom` for workspace navigation, with a temporary “Legacy” route during migration.
  Rationale: Clear URL-ish state improves debuggability in Electron, keeps workspaces isolated, and makes incremental migration straightforward.
  Date/Author: 2026-01-10 / Agent


## Outcomes & Retrospective

(Fill in once Milestones ship; compare operator task success rate and error rates against the baseline.)


## Context and Orientation

This repo already contains a working desktop app under `hegemon-app/`. Today, the renderer UI is largely a single file (`hegemon-app/src/App.tsx`) that renders all sections on one page (node connections, node console, wallet store, sending, contacts, disclosure, raw outputs). Styling is Tailwind-based with project tokens in `hegemon-app/tailwind.config.cjs` and component-ish classes in `hegemon-app/src/styles.css`.

The Electron main process lives in `hegemon-app/electron/` and exposes a narrow IPC surface in `hegemon-app/electron/preload.ts` as `window.hegemon`:

- Node operations (`window.hegemon.node.*`) go through `hegemon-app/electron/nodeManager.ts` and are backed by `hegemon-node` + JSON-RPC calls (including Hegemon RPC methods like `hegemon_consensusStatus` and `hegemon_startMining`).
- Wallet operations (`window.hegemon.wallet.*`) go through `hegemon-app/electron/walletdClient.ts` and are backed by the Rust `walletd` sidecar over stdio JSON.

Hegemon-specific UX constraints the app must respect (must appear as guardrails in the UI, not hidden in docs):

- Mining rewards are shielded notes; mining requires a shielded recipient address (a long `shca1...` string).
- The wallet currently has a small `MAX_INPUTS` limit for spends; consolidation is normal and must be explicit in the send flow.
- Wallet stores are bound to a chain genesis hash; switching nodes/chains can require an explicit rescan or a new store.
- Multi-machine dev networks require a shared raw chainspec; `--chain dev` may produce incompatible genesis hashes across platforms (see `runbooks/two_person_testnet.md`).

This plan focuses on renderer UX, layout, and component architecture. It does not change cryptography, wallet semantics, or node RPC behavior.

If you need historical context for the current app’s scope and constraints, read `.agent/HEGEMON_APP_EXECPLAN.md`.


## Plan of Work

### Milestone 0: UX audit and “must-not-happen” failures

Start by enumerating the real tasks the app must support (not features). Use the runbooks as ground truth (`runbooks/miner_wallet_quickstart.md`, `runbooks/two_person_testnet.md`) and the existing UI as a baseline. For each task, write:

1) the desired “happy path” in 5–8 steps, and
2) the top 3 operator mistakes that currently lead to confusion or loss of time (e.g., wrong node selected, genesis mismatch, RPC unreachable, wallet store missing).

From that list, define a small set of “must-not-happen” UX failures. Example class: sending funds without making the node/genesis context obvious, or turning on mining without a verified mining address.

This milestone ends when the audit outputs are written into this ExecPlan under `Surprises & Discoveries` and `Decision Log` (with concrete evidence from the current UI and runbooks).


### Milestone 1: App shell, navigation, and global status bar

Replace the single long page with an app shell: persistent left navigation, a global top status bar, and a main content area for the active workspace. Implement workspace navigation with `react-router-dom`.

The global status bar must, at a glance, answer:

- Which node am I pointed at? (label + endpoint, and whether it’s local vs remote)
- Is the node reachable and synced? (tone + last refresh time)
- Which wallet store is active? (store path) Is it opened? (ready/not ready)
- Does wallet genesis match node genesis? (hard warning state; gate send and mining toggles behind explicit acknowledgement)

Implementation strategy:

- Keep the existing functionality intact by moving the current monolithic view to a “Legacy” route/component, then build new workspaces alongside it.
- Ship the new shell and workspaces behind a UI mode switch until parity is reached (for example `VITE_HEGEMON_UI=2` in dev, and/or a localStorage flag that a developer can toggle from the UI).
- Do not break renderer security assumptions (renderer remains untrusted).


### Milestone 1.5: Overview workspace (“Command Center”)

Add an “Overview” workspace that answers, in one screen, “is my system healthy?” and “what do I do next?”.

This workspace should combine:

- Global health (node reachable/syncing, wallet ready, genesis match)
- Recent key events (mined/imported/sync complete/errors) in a compact timeline
- Quick actions that route to the right workspace (Start node, Enable mining, Sync wallet, Send, Open console)

Acceptance behavior: a user can open the app and decide what to do next in under 5 seconds without scrolling.


### Milestone 2: Tokens + components: make the system hard to misuse

Create a small component set that enforces hierarchy and reduces visual drift:

- Form field patterns (label, help text, validation tone, copy-to-clipboard affordances for long values)
- “Status strip” patterns (health badges, warning banners, confirmations)
- Dense data components (key/value grids, metric tiles, tables for contacts/pending)
- Interaction components (dialogs/confirmations for destructive actions; toasts for “completed <slug>”)

Keep the system aligned with `BRAND.md`:

- Do not exceed two accent colors per view; reserve amber/red for warnings/errors.
- Use determinate progress or shimmer placeholders; avoid spinner-only states for long actions like sync.
- Ensure contrast and keyboard focus are first-class (operator-grade legibility).

Use this milestone to make the brand feel intentional inside the app chrome:

- Add a restrained header treatment (wordmark + optional emblem) and remove any “random gradient” feeling by standardizing the background and surface elevations.
- Standardize iconography to a single stroked style (1.5px, rounded caps) so operational screens read as one system.


### Milestone 3: Node workspace (“Operate + Observe”)

Rebuild the node experience as a workspace with three tight areas:

1) Connections (list + add/edit; clear local vs remote distinction; chainspec warnings live here)
2) Operations (start/stop local node, mining toggle/threads, safe remote mining control when allowed)
3) Observability (health, peers, height, supply digest, storage footprint, telemetry)

Key acceptance behavior: an operator can start a local node for mining in under 30 seconds with no scrolling, and can immediately see whether mining is active and whether blocks are being imported/mined, without opening the Console view.


### Milestone 4: Wallet + Send workspaces (“Safe funds flow”)

Split wallet concerns into “Store” and “Send” so people can’t accidentally conflate setup with spending.

Store workspace must emphasize:

- init vs open semantics (avoid accidental overwrites)
- the primary address with a dedicated copy control and “verify out-of-band” prompts
- sync progress and last synced height, with an explicit “force rescan” path when genesis changes

Send workspace must be pre-flight-driven:

- recipient selection (contacts + direct paste, with address format feedback)
- amount + fee inputs with base-unit clarity and “what will happen next” copy
- consolidation surfaced as a normal step if required (and auto-consolidate explained, not hidden)
- hard gating on genesis mismatch and RPC unreachable states


### Milestone 5: Disclosure workspace and diagnostics-grade Console

Disclosure remains a dedicated workspace because it’s a distinct mental model: generate package, share externally, verify package.

Console becomes a diagnostics surface, not just a log dump:

- timeline of structured events (mined/imported/sync complete/errors)
- filtering/search that feels instant
- export/copy diagnostics bundle (last N logs + node summary + wallet status) for support/debugging


### Milestone 6: Automated validation (E2E + visual regression)

Add an Electron E2E harness that runs against real local binaries:

- Create a fresh temp wallet store, start a local dev node, enable mining to the wallet’s address, sync, and send a small transfer.
- Capture screenshots of core screens and key states (offline, syncing, genesis mismatch, consolidation required) to prevent future UI regressions.

This milestone is accepted when the test harness can be run on a fresh clone following the project’s first-run steps, and failures are actionable (clear diffs / screenshots / logs).


## Concrete Steps

All commands run from repo root unless stated otherwise.

1) Ensure toolchains and binaries exist:

    make setup
    make node
    cargo build -p walletd --release

2) Run the app in dev mode:

    cd hegemon-app
    npm install
    npm run dev

3) Validate baseline behavior (before redesign):

- Create or open a store, sync to a reachable node, and verify address + balances render.
- Start/stop a local node; verify the node summary updates and logs stream.
- Trigger a genesis mismatch and verify the current warning behavior.

Update this section with additional commands as UI test harnesses are added.


## Validation and Acceptance

Acceptance is phrased as operator-visible behavior:

- First run: a user can create a wallet store, copy the primary `shca1...` address, and see where to paste it for mining, without hunting for it in the UI.
- Node safety: starting mining is blocked unless a miner address is configured; remote mining control is clearly labeled and gated by “allow remote mining”.
- Context safety: the active node + wallet + genesis match state are always visible; send actions are gated when context is unsafe.
- Recovery: when RPC is unreachable, the UI explains what’s unreachable (endpoint) and the minimal steps to recover (start node, switch connection, fix URL).
- Console: key events are visible without reading raw logs; raw logs remain accessible and copyable.

If automation exists, add: “run <test command> and expect <N> passed”.


## Idempotence and Recovery

- The redesign should be developed behind a UI version switch so the legacy view remains available until parity is reached.
- Any migrations of localStorage keys must be additive and reversible (read old keys, write new keys, keep backward compatibility during the transition).
- Starting/stopping child processes must remain owned by the Electron main process; renderer changes must not expand privileges.


## Artifacts and Notes

(Add screenshots, before/after transcripts, and E2E run logs once work begins.)


## Interfaces and Dependencies

Renderer constraints:

- Prefer small, stable dependencies. Keep route structure shallow and use workspaces as the main unit of navigation.
- Do not add component frameworks that fight Tailwind; build a small set of primitives aligned with `BRAND.md`.

External processes:

- Dev mode expects `target/release/hegemon-node` and `target/release/walletd` per `hegemon-app/electron/binPaths.ts`.
