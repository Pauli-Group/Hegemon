# Remove Remaining Legacy Paths Across Node, Network, Wallet, and Circuits

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We are removing all remaining legacy and deprecated runtime paths so the codebase only supports the current PQ-first Substrate stack. After this change, there will be no legacy networking protocols, no legacy HTTP wallet flows, no legacy proof or commitment fallbacks, and no legacy session key types. The outcome is observable by running the full CI suite and by confirming that `rg -n "legacy|deprecated" -S` only matches intentional historical commentary (not live code paths or feature flags).

## Progress

- [x] (2026-01-10 20:10Z) Audit all remaining legacy/deprecated references and classify what must be removed or rewritten.
- [x] (2026-01-10 21:57Z) Remove legacy networking protocols and handshake modes; update node/substrate network bridge and network tests accordingly.
- [x] (2026-01-10 21:57Z) Remove legacy wallet HTTP RPC flows and CLI commands; keep only Substrate RPC paths and update docs.
- [x] (2026-01-10 21:57Z) Remove legacy proof/commitment fallbacks in circuits and pallets; drop any legacy feature flags.
- [x] (2026-01-10 21:57Z) Remove legacy session key compatibility and migrations in `pallet_identity`; update runtime/docs.
- [x] (2026-01-10 21:57Z) Update remaining docs/runbooks/scripts that reference removed legacy functionality.
- [x] (2026-01-10 22:47Z) Stabilize `network::PeerStore` TTL test to avoid timing flakiness during full CI.
- [x] (2026-01-10 22:47Z) Run full monorepo CI suite and confirm it passes without legacy paths.

## Surprises & Discoveries

- Observation: The wallet README still documented legacy HTTP `sync`/`daemon`/`send` commands even after the CLI removed them.
  Evidence: `wallet/README.md` command table still referenced `--rpc-url`/`--auth-token` before cleanup.
- Observation: `peer_store::tests::persists_and_prunes_by_ttl` was timing-dependent at millisecond TTLs and flaked under full CI.
  Evidence: `cargo test --workspace` failed on `network/src/peer_store.rs:279` with the active peer pruned.

## Decision Log

- Decision: Treat all remaining `legacy` and deprecated paths as removable unless they are required for the current Substrate PQ stack to boot and pass CI.
  Rationale: The request explicitly asks to finish legacy cleanup and the repository policy discourages keeping deprecated code.
  Date/Author: 2026-01-10 / Codex
- Decision: Remove the remaining wallet HTTP health endpoint and `axum` dependency to fully eliminate legacy HTTP daemon scaffolding.
  Rationale: The Substrate/WebSocket path is the supported wallet surface and the HTTP endpoint was vestigial.
  Date/Author: 2026-01-10 / Codex
- Decision: Increase the peer store test TTL window and set explicit timestamps for deterministic pruning.
  Rationale: The test should verify pruning logic without depending on sub-50ms wall-clock timing.
  Date/Author: 2026-01-10 / Codex

## Outcomes & Retrospective

Legacy code paths for networking, wallet HTTP RPC, circuit fallbacks, and identity session keys were removed with docs updated to match. Full monorepo CI now passes with the PQ-only stack, and the peer store TTL test is stable under CI timing.

## Context and Orientation

Legacy code currently spans network protocol negotiation, wallet HTTP RPC flows, circuit verification fallbacks, and runtime session key compatibility. These paths live in `network/`, `node/src/substrate`, `wallet/`, `circuits/transaction`, `pallets/identity`, and associated docs/runbooks. Removing them means adjusting CLI flags, feature flags, and RPC documentation so only the PQ-first Substrate stack remains.

## Plan of Work

First, audit remaining legacy references and identify concrete removal targets. Then remove legacy networking protocols and handshake modes in `network/` and update node networking integration to use only PQ protocols. Next, remove legacy wallet HTTP RPC flows and CLI commands so only Substrate RPC flows remain. Then remove legacy proof/commitment fallbacks in `circuits/transaction` and `pallets/shielded-pool`, including any `legacy-*` feature flags. After that, remove legacy session key compatibility types and migrations in `pallets/identity` and update runtime docs. Finally, update docs/runbooks/scripts to reflect the new behavior, and run the full CI suite to validate.

## Concrete Steps

Work from the repository root. Use `rg -n "legacy|deprecated" -S` to audit targets, then remove the code paths and update tests/docs. After each major removal, run targeted tests for the affected area, then finish with the full CI suite. Use the same `LIBCLANG_PATH`/`DYLD_LIBRARY_PATH` settings for Rust commands that touch `librocksdb-sys` on macOS.

## Validation and Acceptance

Acceptance is achieved when:

1. No legacy networking protocols or handshake modes remain, and network tests still pass.
2. Wallet CLI only exposes Substrate RPC flows and wallet docs no longer mention legacy HTTP RPC.
3. Circuit verification uses a single modern path with no legacy proof fallbacks or legacy feature flags.
4. `pallet_identity` no longer stores or migrates legacy session keys.
5. Docs/runbooks/scripts reference only current flows.
6. Full CI suite runs successfully.

## Idempotence and Recovery

Removals are safe under version control. If a removal breaks functionality, revert or restore the specific file from git history, then reapply with a smaller change and re-run the relevant tests.

## Artifacts and Notes

Capture `rg` output showing no remaining legacy code paths and summarize CI results after completion.

## Interfaces and Dependencies

At the end of this change, the codebase must not expose legacy protocols, legacy wallet RPC commands, legacy proof fallbacks, or legacy session key types. All remaining interfaces should be the PQ-first Substrate paths documented in `DESIGN.md`, `METHODS.md`, and `docs/API_REFERENCE.md`.

Plan update note (2026-01-10): Marked CI completion, recorded the peer store TTL test fix, and updated discoveries/decisions to capture the flake root cause and resolution.
