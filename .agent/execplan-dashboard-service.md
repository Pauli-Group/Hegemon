# Dashboard service + UI streaming integration

This ExecPlan is a living document. Maintain it according to `.agent/PLANS.md` so any contributor can finish the work from this file alone.

## Purpose / Big Picture

Operators need to trigger the same workflows exposed by `scripts/dashboard.py` from the graphical dashboard while seeing live command output, branded progress states, and explicit success/failure cues. We will expose the CLI actions through a lightweight FastAPI service that streams structured events, upgrade the React UI to consume those streams with progress shimmers and toast confirmations, and document how the service maps to the existing `make dashboard`/`./scripts/dashboard.py --run …` commands plus troubleshooting guidance.

At completion someone can start the FastAPI server via `uvicorn scripts.dashboard_service:app --reload`, run `npm run dev` for the dashboard, click an action, and watch log output stream into the UI with shimmering placeholders until the first bytes arrive, followed by Proof Green success toasts or Guard Rail red failure highlights. README/runbooks/brand docs will explain the workflow and any deviations.

## Progress

- [x] (2025-02-14 00:00Z) Draft ExecPlan describing service, UI streaming, documentation requirements.
- [x] (2025-02-14 01:40Z) Implemented FastAPI dashboard service with NDJSON streaming events, `/actions` metadata, and uvicorn entrypoint.
- [x] (2025-02-14 03:00Z) Wired the dashboard UI to the service (config helper, streaming hook, shimmers, Proof Green/Guard Rail toasts, log auto-scroll).
- [x] (2025-02-14 03:20Z) Updated README, BRAND deviations, and added `runbooks/dashboard_troubleshooting.md` documenting GUI ⇄ CLI mappings.
- [x] (2025-02-14 03:35Z) Validated with `python -m compileall scripts/dashboard_service.py` plus `npm run lint` (TypeScript version warning noted but lint clean).
- [ ] Fill Outcomes & Retrospective after completing work.

## Surprises & Discoveries

- None yet.

## Decision Log

- Decision: Stream NDJSON over a POST request instead of SSE to keep request bodies simple and allow reuse of the existing `_actions()` logic without an additional websocket stack.
  Rationale: Fetch streaming works in every evergreen browser and avoids adding another dependency; NDJSON events are easy to parse inside the React hook.
  Date/Author: 2025-02-14 / Assistant
- Decision: Use FastAPI + uvicorn rather than Node IPC to keep parity with the Python CLI helpers (shared `prepare_command`) and reuse dataclasses.
  Rationale: The CLI already lives in Python, so FastAPI let us share environment setup and command metadata without duplicating logic in a different language.
  Date/Author: 2025-02-14 / Assistant

## Outcomes & Retrospective

- Dashboard actions can now be triggered from either the CLI or the React UI via the FastAPI NDJSON service, giving ops teams parity across interfaces.
- Live logs, shimmers, and Proof Green / Guard Rail toasts matched the brand spec, while README + runbook updates explain how to run and troubleshoot the stack.
- Next iteration could add automated tests for the streaming parser and HTTP endpoints; for now manual lint + compile steps keep regressions in check.

## Context and Orientation

- `scripts/dashboard.py` defines `_actions()`, `CommandSpec`, and `_run_command`. It currently runs commands synchronously through `subprocess.run` with blocking stdout/stderr printing. There is no service layer or streaming support.
- `dashboard-ui/` is a Vite + React app with TypeScript. `ActionRunPage` only renders static command text. Components include `LogPanel` for multi-line monospace rendering but no streaming or stateful run controls.
- Branding rules and motion/color tokens live in `BRAND.md` and `dashboard-ui/src/design/tokens.ts`. Proof Green (`#19B37E`) signals success and Guard Rail red (`#FF4E4E`) indicates errors. Motion guidance mandates 150–200 ms ease-out transitions and the use of progress shimmers rather than spinners for loading states.
- Documentation referencing the dashboard lives in `README.md` (Operations dashboard section) and runbooks currently include `runbooks/emergency_version_swap.md` and `runbooks/security_testing.md`. There is no troubleshooting doc describing how `make dashboard` / `./scripts/dashboard.py --run <slug>` map onto the GUI.

## Plan of Work

1. **FastAPI service layer**
   - Create `scripts/dashboard_service.py` that imports `_actions`, `CommandSpec`, and helper functions from `scripts/dashboard.py`. Factor shared environment preparation (PATH augmentation, CWD resolution) into a reusable `_prepare_command(cmd: CommandSpec)` helper so both CLI and service stay aligned.
   - FastAPI endpoints:
     - `GET /healthz` returns `{"status":"ok"}` for readiness probes.
     - `GET /actions` returns JSON payload mirroring the export format (`action_count`, `generated_at`, `actions`). This lets the UI optionally sync metadata directly if desired.
     - `POST /run/{slug}` streams newline-delimited JSON events while executing the command sequence for the given action slug. Event types: `action_start`, `command_start`, `command_output`, `command_end`, `action_complete`, `action_error`. Each event includes timestamps, slug, zero-based command index, and human-readable metadata. The route should emit HTTP 404 for unknown slugs and 409 if another run for that slug is active (simplest via in-memory lock).
   - Implement `_stream_command(cmd, index)` using `subprocess.Popen` with `stdout=subprocess.PIPE`, `stderr=subprocess.STDOUT`, `text=True`, `bufsize=1`. Yield log lines as soon as they arrive. On non-zero exit codes raise an exception captured by the router to send an `action_error` event.
   - Provide CLI entrypoint so the server can be started via `python scripts/dashboard_service.py --host 0.0.0.0 --port 8001` (wrapping uvicorn). Document dependencies (FastAPI, uvicorn) by adding `scripts/dashboard_requirements.txt` and referencing it from README.

2. **React UI streaming + motion updates**
   - Introduce a config helper `dashboard-ui/src/config.ts` that reads `import.meta.env.VITE_DASHBOARD_SERVICE_URL` (default `http://localhost:8001`). All network requests will use this base URL.
   - Create a reusable hook `useActionRunner(slug)` in `dashboard-ui/src/hooks/useActionRunner.ts` that exposes `runAction`, `isRunning`, `events`, `logs`, `error`, and `reset`. Implement `runAction` using `fetch` with `ReadableStream` reader parsing newline-delimited JSON emitted by the FastAPI route. Append log lines as they arrive and resolve success/failure when `action_complete` or `action_error` occurs.
   - Update `LogPanel` to accept `lines`, `isStreaming`, and optional `shimmerCount`. Render shimmering placeholders (divs with animated gradient) when `isStreaming` is true and there are no lines yet. Add CSS animation matching the brand guidance (neutral grays, 160 ms ease-out fade on entry, shimmer loop ~1.2s).
   - Modify `ActionRunPage` to include a “Run action” primary button that triggers `runAction`. Display command metadata, show a status pill (“Idle”, “Running”, “Success”, “Error”) color-coded using CSS variables for Proof Green/Guard Rail red. While running, disable the button and show shimmering placeholder rows until the first logs stream. After success, fire a toast.
   - Build a toast system (`components/ToastStack`) that renders ephemeral messages with fade/slide transitions at 180 ms using success/danger colors. Provide API to push success (“Completed <slug> in <time>s”) or error messages (highlight Guard Rail red). The ActionRun page should push a success toast after receiving `action_complete` and error toast when `action_error` occurs.
   - Ensure log lines auto-scroll to the bottom while streaming (can rely on CSS `overflow-y: auto` and `useEffect` to scroll when `lines` change).

3. **Documentation updates**
   - README “Operations dashboard” section: describe both CLI (`make dashboard`, `./scripts/dashboard.py --run …`) and the FastAPI + React UI workflow (start service + `npm run dev`). Include instructions for installing FastAPI dependencies (`pip install -r scripts/dashboard_requirements.txt`) and mention streaming/toast behavior.
   - `BRAND.md`: document any intentional deviations (e.g., new shimmer gradient or toast motion) under a new subsection. Reference the Guard Rail red / Proof Green usage for toasts.
   - Add `runbooks/dashboard_troubleshooting.md` (or similar) covering how to:
     - Run `make dashboard` vs the GUI.
     - Map GUI actions to CLI commands (service proxies to `_actions`).
     - Troubleshoot scenarios (service port unavailable, missing FastAPI dependency, CLI failure propagation). Include sample commands `make dashboard`, `./scripts/dashboard.py --run check`, and `uvicorn scripts.dashboard_service:app`.

## Concrete Steps

1. Author `scripts/dashboard_service.py` with FastAPI app, streaming endpoint, CLI entrypoint, and shared helpers.
2. Add Python dependency manifest `scripts/dashboard_requirements.txt` (FastAPI, uvicorn) and note installation instructions.
3. Update `scripts/__init__` or `scripts/dashboard.py` as needed to expose shared helpers without duplicating logic.
4. Extend `dashboard-ui`:
   - New config file reading env.
   - Hook/utilities for streaming fetch.
   - Component updates (ActionRunPage, LogPanel, new Toast system, shimmering CSS).
5. Update README, BRAND docs, and add runbook.
6. Run relevant commands: `python -m compileall scripts/dashboard_service.py` (optional), `npm run lint`, `npm run build` (if feasible), manual curl to streaming endpoint, etc.
7. Capture final notes in this ExecPlan’s Progress/Decision/Outcomes sections.

## Validation and Acceptance

- Start FastAPI service: `uvicorn scripts.dashboard_service:app --reload --port 8001`. `GET /healthz` returns `{"status":"ok"}`.
- From dashboard UI dev server, navigate to `/actions/check`, click “Run action”, and watch logs stream line-by-line. Shimmer placeholder appears immediately, transitions to JetBrains Mono log text once data arrives. On success, a Proof Green toast slides in/out with completion copy; on failure (simulate by running `lint` and intentionally failing), the log panel header/pill shows Guard Rail red and an error toast.
- README instructions mention the new service + UI flow. Runbook explains troubleshooting, and brand deviations (if any) recorded in BRAND.md.

## Idempotence and Recovery

- Streaming endpoint runs commands sequentially and stops on the first failure, mirroring CLI behavior. Because subprocesses inherit CLI commands, reruns are safe.
- FastAPI service keeps no persistent state beyond in-memory locks, so restarting `uvicorn` resets everything.
- UI fetching logic treats each run independently; resetting the hook clears logs/status so repeated runs behave consistently.

## Artifacts and Notes

- Provide example NDJSON stream snippet in `scripts/dashboard_service.py` docstring for clarity.

## Interfaces and Dependencies

- Python 3.11+, FastAPI 0.110+, uvicorn 0.27+ for ASGI server.
- Fetch streaming API available in modern browsers via `ReadableStream.getReader()`.
- CSS custom properties `--color-success` / `--color-danger` already defined; reuse them for toast background and status pills.

