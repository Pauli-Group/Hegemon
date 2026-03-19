# Repair macOS node builds and realign desktop roles with the live network

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

After this work lands, a macOS contributor should be able to follow the repository’s normal setup/build path without hitting the `libclang.dylib` crash from `librocksdb-sys`, and the Electron desktop should stop advertising stale mining/proving behavior. The observable result is that `make node` repairs the local `libclang` lookup on macOS before building, direct `cargo build -p hegemon-node --features substrate --release` works afterward on the same machine, and the desktop app describes the current topology honestly: pooled hashers, an operator-only authoring pool, and a private prover that runs through the external `hegemon-prover-worker`.

## Progress

- [x] (2026-03-18T02:19Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `BRAND.md` before making changes.
- [x] (2026-03-18T02:19Z) Reproduced the local node build failure on macOS. `cargo build -p hegemon-node --features substrate --release` aborts in `librocksdb-sys` because dyld cannot find `libclang.dylib`.
- [x] (2026-03-18T02:19Z) Audited the desktop app and confirmed that the visible mismatches are role/copy drift (`Public author`, `Worker pending`, future-worker language) plus fabricated summary data (`aggregationProofFormat: 'V4'`).
- [x] (2026-03-18T02:22Z) Added `scripts/ensure-macos-libclang.sh` and wired it into `Makefile` plus `scripts/dev-setup.sh` so repo-guided macOS builds create the `$HOME/lib/libclang.dylib` fallback automatically.
- [x] (2026-03-18T02:24Z) Realigned the desktop role model and copy in `hegemon-app/src/App.tsx`, and removed the unused remote-authoring checkbox.
- [x] (2026-03-18T02:24Z) Updated `hegemon-app/electron/nodeManager.ts` to stop fabricating proof format `V4` and to prefer current stage-work telemetry when present.
- [x] (2026-03-18T02:28Z) Validated the node build path and Electron app. `cargo build -p hegemon-node --features substrate --release`, `npm run typecheck`, and `npm run build` all passed.

## Surprises & Discoveries

- Observation: the local blocker is not a missing prover-worker source file. The repository already contains `node/src/bin/prover_worker.rs` and `node/Cargo.toml` still declares `hegemon-prover-worker`.
  Evidence: `find node/src -path '*bin*' -maxdepth 3 -type f -print` shows both `node/src/bin/substrate_node.rs` and `node/src/bin/prover_worker.rs`.

- Observation: stable Cargo accepts target-scoped `env` config syntax but ignores it, so a `.cargo/config.toml` fix cannot safely inject `LIBCLANG_PATH` only on macOS.
  Evidence: a throwaway test project accepted `[target.'cfg(target_os = "macos")'.env]` with `warning: unused key 'env' in [target] config table`.

- Observation: the failing build script’s dyld fallback search path already includes `$HOME/lib/libclang.dylib`.
  Evidence: the reproduced `librocksdb-sys` crash tried `/Users/pldd/lib/libclang.dylib` before giving up.

- Observation: the desktop app is stale in two different ways: visible copy still says the standalone private prover worker is “not shipped yet”, and internal summary data still hardcodes proof format `V4` even though the current node paths emit V5 artifacts.
  Evidence: `hegemon-app/src/App.tsx` contains `Worker pending` / “not shipped yet” strings, and `hegemon-app/electron/nodeManager.ts` returns `aggregationProofFormat: 'V4'`.

## Decision Log

- Decision: fix macOS builds by creating a deterministic `~/lib/libclang.dylib` fallback symlink from the repo’s setup/build scripts instead of relying on shell-local environment exports.
  Rationale: dyld already searches `$HOME/lib`, so this survives direct `cargo build` invocations after one repo-guided setup/build run and avoids unsafe cross-platform Cargo config hacks.
  Date/Author: 2026-03-18 / Codex

- Decision: keep the desktop’s `private_prover` role, but rewrite it to match reality instead of removing it.
  Rationale: the current network really does ship `hegemon-prover-worker`; the desktop just does not launch that worker itself. The app should store/provide operator context without pretending the feature is missing or fully app-managed.
  Date/Author: 2026-03-18 / Codex

- Decision: remove or demote UI controls that are stored-only or not wired into runtime behavior.
  Rationale: the user asked for the UI to match the current network features. Hidden aspirational controls are still misleading if they imply app-managed behavior that does not exist today.
  Date/Author: 2026-03-18 / Codex

## Outcomes & Retrospective

The macOS node build path is now self-healing through the repo’s normal entrypoints. The added helper links `~/lib/libclang.dylib` to the active Command Line Tools/Xcode copy, which matches the dyld fallback path that the failing `librocksdb-sys` build script already searched. After running that helper, the same release node build that previously aborted completed successfully.

The desktop app now better matches the live network. The authoring role is labeled as an operator-only authoring pool instead of a generic public-author path, the private-prover role explicitly points at the external `hegemon-prover-worker`, the unused remote-authoring checkbox is gone, and the telemetry layer no longer invents a `V4` proof format. The remaining gap is that the desktop still does not launch or supervise `hegemon-prover-worker` itself; it stores context for that operator workflow and says so explicitly.

## Context and Orientation

The Substrate node lives under `node/` and is built primarily through the repository `Makefile`. On macOS, `librocksdb-sys` needs `libclang.dylib` at build-script runtime. The current tree partially compensates by exporting `LIBCLANG_PATH` and `DYLD_LIBRARY_PATH` inside `Makefile`, but direct cargo invocations still fail because those environment exports are not present outside `make`.

The desktop app lives under `hegemon-app/`. The renderer is mainly `hegemon-app/src/App.tsx`, shared types are in `hegemon-app/src/types.ts`, and Electron-side node telemetry comes from `hegemon-app/electron/nodeManager.ts`. A “participation role” in this app is the operator intent for a connection profile: verifier-only full node, pooled hasher, authoring pool, or private prover. The current docs (`runbooks/authoring_pool_upgrade.md`, `docs/SCALABILITY_PATH.md`) say the live topology is one public authoring node, one private prover backend, and pooled hashers; the app must describe that topology honestly.

## Plan of Work

First, add one small macOS helper script under `scripts/` that finds `libclang.dylib` in Command Line Tools or Xcode and makes sure `$HOME/lib/libclang.dylib` points at it. Wire that helper into `scripts/dev-setup.sh` and the `Makefile` targets that compile the Substrate node or test it. Keep the helper idempotent and non-destructive: if the fallback symlink already points at a working path, do nothing.

Second, update `hegemon-app/src/App.tsx` so the visible role labels and copy match the current network. “Public author” should become an operator-facing authoring-pool label, the private-prover role must explicitly describe the external `hegemon-prover-worker`, and pooled-hasher text must stop implying that every saved field is directly consumed by the app. Remove the misleading remote-authoring checkbox because the desktop does not actually use it.

Third, update `hegemon-app/electron/nodeManager.ts` so it stops fabricating proof format `V4`. If the app does not have an honest source for that field, return `null` instead. Where stage-package telemetry is still kept, prefer the current stage-work package RPC surface over the older flat-work-only assumption.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Reproduce the local node build failure:

    cargo build -p hegemon-node --features substrate --release

   Expected pre-fix failure:

    error: failed to run custom build command for `librocksdb-sys ...`
    dyld: Library not loaded: @rpath/libclang.dylib

2. Implement the macOS helper and wire it into the repo’s setup/build entrypoints.

3. Update the desktop role/copy flow in:

    hegemon-app/src/App.tsx
    hegemon-app/electron/nodeManager.ts

4. Validate the repaired build path and desktop app:

    ./scripts/ensure-macos-libclang.sh
    cargo build -p hegemon-node --features substrate --release
    cd hegemon-app && npm run typecheck
    cd hegemon-app && npm run build

5. Run a final hygiene pass:

    git diff --check
    rg -n "Public author|Worker pending|not shipped yet|aggregationProofFormat: 'V4'|Allow remote authoring control" \
      hegemon-app Makefile scripts .agent/MACOS_BUILD_AND_DESKTOP_ROLE_ALIGNMENT_EXECPLAN.md

## Validation and Acceptance

This ExecPlan is accepted when all of the following are true:

1. On macOS, the repo’s standard build/setup path creates a working `libclang` fallback without requiring ad hoc shell exports.
2. After that bootstrap runs once, `cargo build -p hegemon-node --features substrate --release` no longer dies at `librocksdb-sys` for missing `libclang.dylib`.
3. The Electron app no longer claims that the private prover worker is unshipped or pending.
4. The Electron app no longer exposes remote-authoring controls that it does not actually apply.
5. The app’s telemetry layer no longer returns a fabricated `V4` proof-format value.

## Idempotence and Recovery

The macOS helper must be safe to run repeatedly. If `$HOME/lib/libclang.dylib` already points at a valid libclang path, leave it unchanged. If Command Line Tools/Xcode are missing, fail with a clear message rather than creating a broken symlink.

The desktop edits are also safe to repeat: they are copy/flow corrections, not data migrations. Existing saved connections should keep the same role identifiers, so there is no profile format migration or rollback procedure beyond reverting the code changes.

## Artifacts and Notes

Key files for this work:

    Makefile
    scripts/dev-setup.sh
    scripts/ensure-macos-libclang.sh
    hegemon-app/src/App.tsx
    hegemon-app/electron/nodeManager.ts
    hegemon-app/src/types.ts

Evidence collected before implementation:

    cargo build -p hegemon-node --features substrate --release
    ...
    dyld: Library not loaded: @rpath/libclang.dylib
    Reason: tried: ... /Users/pldd/lib/libclang.dylib ... /usr/local/lib/libclang.dylib ...

## Interfaces and Dependencies

The new macOS helper should expose one simple executable interface:

    scripts/ensure-macos-libclang.sh

Its contract is: on macOS, locate `libclang.dylib` from Command Line Tools or Xcode and ensure `$HOME/lib/libclang.dylib` is present as a usable fallback for Cargo build scripts; on non-macOS platforms, exit successfully without changing anything.

The desktop side should continue using the existing `NodeParticipationRole` union in `hegemon-app/src/types.ts`, but the user-facing semantics at the end of this work must be:

- `full_node`: verifier/wallet/monitoring role with no local authoring.
- `pooled_hasher`: desktop-managed pooled hashing via `hegemon_poolWork` / `hegemon_submitPoolShare`.
- `authoring_pool`: operator-only public authoring node role.
- `private_prover`: external `hegemon-prover-worker` role whose process lifecycle remains outside the app.

Revision note: created on 2026-03-18 after reproducing the local macOS `librocksdb-sys` failure and auditing stale desktop participation-role copy against the current pooled-hashing / private-prover topology.

Revision note (2026-03-18): Updated Progress, Outcomes, and validation state after implementing the macOS libclang bootstrap, the desktop role/copy cleanup, and the successful node/Electron verification pass.
