# Node Native Module Split and Desktop App Hardening ExecPlan

```md
# Purpose

Two files dominate review and maintenance risk in this repository:

1. `node/src/native/mod.rs` — 43,514 lines in one file: roughly 18,036 lines of
   production code plus a 25,478-line `#[cfg(test)] mod tests` block starting at
   the `mod tests {` marker. It contains the native node's import, mining, RPC,
   sync, storage, bridge, and admission logic.
2. `hegemon-app/src/App.tsx` — 5,278 lines with a single `App()` React component
   holding ~59 `useState` hooks, plus an Electron `walletdClient` whose requests
   can hang forever (no timeout) and whose shutdown never escalates to SIGKILL.

After this change:

* The node's native module is a directory of focused submodules with the test
  suite in its own file, so diffs, reviews, and incremental builds touch only
  the relevant area. Behavior is unchanged: `hegemon_node::native::{run, NativeCli}`
  remains the only external surface (used by `node/src/bin/native_node.rs`).
* The desktop app has its icon/helper components and shared constants extracted
  from `App.tsx` into modules, the `walletdClient` enforces per-request timeouts
  and SIGKILL escalation, and the app gains an automated unit-test rig (vitest)
  wired into `npm test`.

To see it working: `cargo test -p hegemon-node` passes unchanged, and
`npm --prefix hegemon-app run typecheck && npm --prefix hegemon-app test` pass.

# Constraints and invariants

* Pure mechanical moves for the Rust split: no logic edits, no renames, no
  visibility widening beyond the minimum `pub(super)`/`pub(crate)` needed for
  cross-file references inside `node/src/native/`.
* Rust privacy rule that makes this safe: items private to module `native` are
  visible to all descendant modules (`native::x`), and `impl NativeNode` blocks
  may live in any submodule while accessing private fields, because field
  privacy is module-scoped (`native` and descendants), not file-scoped.
* The `native` module re-exports moved items with `pub(crate) use` /`pub use`
  so `super::*` imports inside the test module and intra-module references keep
  resolving without touching call sites.
* External API frozen: `node/src/lib.rs` keeps `pub mod native;` and
  `native::{run, NativeCli}` keep their paths.
* Desktop app: no behavioral UI changes; extraction only, plus the walletd
  client hardening described below. Electron security posture (sandbox,
  contextIsolation, typed preload) must not regress; `npm run check:ui-guards`
  must keep passing.

# Milestones

## M1. Split tests out of node/src/native/mod.rs — DONE

* Move the `#[cfg(test)] mod tests { ... }` block (from the `mod tests {` line
  to the matching final `}` at end of file) into `node/src/native/tests.rs`,
  dropping the wrapper braces, and replace it in `mod.rs` with:

      #[cfg(test)]
      mod tests;

* `use super::*;` inside the moved file still resolves to `native` because the
  module path `native::tests` is unchanged.
* Verify: `cargo test -p hegemon-node --no-run` compiles; `cargo test -p
  hegemon-node` passes.

## M2. Split production code into submodules — DONE

Move cohesive line ranges of the remaining `mod.rs` into sibling files under
`node/src/native/`, each declared in `mod.rs` and re-exported with
`pub(crate) use name::*;` (plus `pub use` for the public CLI/config/run items).
The sections (line numbers refer to the pre-split `mod.rs`) are:

* `constants.rs` — the `const` block (lines ~91–174) and approved-seed lists.
* `types.rs` — admission/reload input+rejection structs and enums, sync
  message/wire types, RPC request DTOs (lines ~352–3047 minus functions).
* `node_impl.rs` — `struct NativeNode` + `impl NativeNode` (lines ~3049–6660).
* `service.rs` — `run`, `start_native_p2p`, sync loop, sync import/request
  helpers, wire budget helpers (lines ~6661–7887).
* `rpc.rs` — axum handlers, dispatch, chain_* methods, bridge witness export,
  JSON helpers, CORS, method policy tables (lines ~7889–8690).
* `mining.rs` — mining loop and round helpers (lines ~8691–8768).
* `storage.rs` — publish/persist/load/genesis/startup-state validation
  (lines ~8770–10230 approximately, ending before transfer admission).
* `admission.rs` — transfer/action/bridge/coinbase/candidate admission
  evaluators and error mappers, mempool/sidecar/sync admission helpers.
* `block_flow.rs` — block action validation, commitment/atomic-commit
  manifests, replay refinement, materialization, canonical index planning,
  reorg admission, artifact verification.
* `pow.rs` — mined-work/announced-block admission, PoW header/meta helpers,
  miner identity, retarget expectations.
* `util.rs` — CLI/base-path/identity-seed loading, parsing, hex/hash/env
  helpers, bincode/scale exact decoding, serde_array48, shutdown signals.

Exact boundaries follow item granularity (never split an item), and each moved
file starts with the imports it needs. Anything referenced across files keeps
working via the `pub(crate) use` re-exports in `mod.rs`, so `super::*` in
`tests.rs` sees the same namespace as before.

* Verify after each move: `cargo check -p hegemon-node`, then full
  `cargo test -p hegemon-node` at the end.

## M3. Harden hegemon-app walletdClient — DONE

* Add a per-request timeout (default 600000 ms, override via
  `HEGEMON_WALLETD_REQUEST_TIMEOUT_MS`, minimum 1000 ms). On timeout the
  pending promise rejects with a descriptive error and is removed from the
  pending map; the walletd process is left running (long syncs must not kill
  the store) unless the caller stops it.
* Escalate shutdown: `stop()` sends SIGINT, waits 1500 ms, then SIGKILL if the
  process has not exited, and awaits exit afterwards.
* Verify: `npm --prefix hegemon-app run typecheck`.

## M4. Extract modules from App.tsx — DONE

* Move the pre-`App()` helper components and shared constants into:
  `src/components/AppIcon.tsx`, `src/components/EmptyStateIcon.tsx`,
  `src/components/ScrollToTop.tsx`, `src/lib/constants.ts` (nav/config/limits),
  and `src/lib/format.ts` (pure formatting helpers used across the file).
* `App.tsx` imports these; no JSX or behavior changes. Follow-up decomposition
  of `App()` into route pages is future work (requires state architecture
  decisions, tracked below).
* Verify: `npm --prefix hegemon-app run typecheck` and
  `npm --prefix hegemon-app run check:ui-guards`.

## M5. Add vitest unit-test rig — DONE

* Dev-dependency `vitest`; `npm test` runs `vitest run`. Tests cover:
  `electron/walletdClient` response-line parsing and timeout behavior (via
  extracted pure helpers), `src/appGuards.ts`, and the loopback RPC endpoint
  normalizer extracted from `electron/main.ts` into `electron/rpcEndpoint.ts`
  (main.ts imports it; logic unchanged).

## M6. Documentation & verification — DONE

* Update `DESIGN.md` native-node section file references if any point at
  `node/src/native/mod.rs` internals (grep first; whitepaper references
  `node/src/native` directory, which stays true).
* Full gates: `cargo test -p hegemon-node`, `cargo clippy -p hegemon-node`,
  app typecheck + tests + ui-guards.

# Decision log

* 2026-07-08: Chose directory split with `pub(crate) use` re-exports over
  `include!()` tricks — re-exports keep rustdoc/module semantics honest while
  preserving every internal path via the glob re-export namespace.
* 2026-07-08: The formal blueprint (`config/formal-security-blueprint.json`)
  pins 177 implementation bindings to `node/src/native/mod.rs`, and
  `scripts/hegemon_formal_core::validate_rust_implementation_binding` resolved
  callee + required callers inside that single file. Splitting the module
  would have broken the formal-core release gate. Decision: teach the
  validator that a binding on a module root (`.../mod.rs`) denotes the whole
  module namespace — the root file concatenated with each declared non-test
  sibling `<name>.rs` submodule — which is exactly Rust's module semantics.
  `#[cfg(test)] mod tests;` files and modules named `tests` are excluded so
  test-only code still cannot satisfy bindings (covered by new unit tests
  `module_root_binding_resolves_across_split_module_files`,
  `module_root_binding_ignores_cfg_test_module_files`, and
  `rust_non_test_file_submodules_skips_tests_and_inline_modules`). The
  blueprint JSON itself needs no churn, keeping review diffs small.
* 2026-07-08: Deferred full `App()` page decomposition: 59 interleaved state
  hooks need a context/props design decision that should not be bundled with
  mechanical extraction. The extraction in M4 plus the test rig in M5 make the
  follow-up tractable.
* 2026-07-08: walletd request timeout defaults long (600 s) because wallet
  sync over WS can legitimately take minutes on first scan; the goal is to
  eliminate forever-hangs, not to race long syncs.

# Progress

* M1–M5 complete on branch `hardening/monolith-split-and-app-rig`:
  - node/src/native/mod.rs (43,514 lines) is now mod.rs (3,115) plus nine
    production modules and tests.rs; 433 node tests pass, clippy/fmt clean.
  - App.tsx reduced from 5,278 to 4,260 lines with src/lib/{config,appTypes,
    format,logs,connections} and src/components/{AppIcon,EmptyStateIcon,
    ScrollToTop}; check-ui-guards scans the combined renderer sources.
  - walletd client: per-request timeout + SIGINT->SIGKILL escalation;
    protocol helpers extracted and unit-tested (vitest, 37 tests).
* Additional scope beyond the plan: workspace clippy allow-list burned down
  from 17 entries to 4 (needless_borrow, type_complexity, too_many_arguments,
  result_large_err kept); 13 stylistic allows removed and all findings fixed
  across both CI clippy package sets.
* Formal-core gate: `scripts/hegemon_formal_core` now resolves module-root
  (`mod.rs`) implementation bindings across the whole module namespace
  (root file + declared non-test sibling submodule files), excluding
  `#[cfg(test)]` module files. 128 crate unit tests pass (3 new), and the
  full `bash scripts/check_formal_core.sh` release gate passes end-to-end
  on the split module (exit 0), including check-claims, check-blueprint
  with all 177 native-module bindings, formal inventory, system-model
  gates, and every Lean vector regression lane.
* M6 done: full gate suite green — cargo test -p hegemon-node (433),
  wallet --lib (122), consensus/state-da/protocol-shielded-pool (562 incl.
  node), both clippy sets -D warnings clean, cargo fmt --all --check clean,
  native startup policy, app typecheck + vitest (37) + check:ui-guards +
  electron-vite build + packaged-app autostart guard, formal-core gate.
```
