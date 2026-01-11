# Remove Legacy Node Test Harness and Integration Tests

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We are removing the legacy node test harness and the legacy-node integration test suite so the repo no longer ships or executes deprecated node paths. After this change, the security-tests crate will no longer expose the legacy-node-tests feature, the legacy node test utilities in the node crate will be gone, and CI will stop invoking the legacy node-wallet daemon test. Success is observable by running the security-tests suite and seeing the legacy test files and features removed, and by verifying that no code references `LegacyNode`, `NodeService`, or `legacy-node-tests` remain in the codebase.

## Progress

- [x] (2026-01-10 19:52Z) Record baseline of legacy-node-tests usage and files to remove.
- [x] (2026-01-10 19:54Z) Remove legacy-node-tests feature and legacy integration test entries from `tests/Cargo.toml`, delete the corresponding test files.
- [x] (2026-01-10 19:54Z) Remove legacy node test utilities (`node/src/test_utils.rs`, `node/src/storage.rs`, `node/src/api.rs`) and drop the `test-utils` feature from `node/Cargo.toml` and exports from `node/src/lib.rs`.
- [x] (2026-01-10 19:54Z) Update CI workflow (`.github/workflows/ci.yml`), runbooks, and documentation/scripts that reference removed legacy tests.
- [x] (2026-01-10 19:56Z) Validate that the remaining CI-equivalent tests pass and that `rg` shows no remaining legacy test harness references.

## Surprises & Discoveries

The first `security_pipeline` test run timed out during the build; a rerun with a longer timeout completed successfully.
Evidence: `cargo test -p security-tests --test security_pipeline -- --nocapture` timed out at 240s, then passed after rerun.

## Decision Log

- Decision: Remove the entire legacy node integration test suite and its harness rather than attempting to fix the failing legacy test.
  Rationale: The user explicitly wants legacy code removed, and the failing test is in the legacy-node-tests suite.
  Date/Author: 2025-09-24 / Codex

## Outcomes & Retrospective

The legacy node integration harness and tests have been removed, CI no longer invokes the legacy node-wallet flow, and the runbook no longer points at deleted legacy tests. The remaining security pipeline test still passes. No legacy-node-tests or legacy harness types remain in the repository.

## Context and Orientation

The legacy node integration tests live under `tests/` and are wired via the `legacy-node-tests` feature in `tests/Cargo.toml`. The node crate provides a legacy test harness in `node/src/test_utils.rs`, `node/src/storage.rs`, and `node/src/api.rs`, all guarded by the `test-utils` feature in `node/Cargo.toml` and `node/src/lib.rs`. CI runs the legacy node-wallet daemon test in `.github/workflows/ci.yml` under the `node-wallet-flow` job. Runbooks refer to `p2p_pq` legacy tests in `runbooks/substrate_integration_testing.md`. These references must be removed or updated so the repo no longer advertises or depends on the legacy harness.

## Plan of Work

First, remove the legacy-node-tests feature and its test entries from `tests/Cargo.toml`, and delete the legacy integration test files that depend on `NodeService` and the legacy harness. Next, remove the legacy harness from the node crate by deleting `node/src/test_utils.rs`, `node/src/storage.rs`, and `node/src/api.rs`, and drop the `test-utils` feature and exports in `node/Cargo.toml` and `node/src/lib.rs`. Then update `.github/workflows/ci.yml` to remove the `node-wallet-flow` job that runs the legacy test. Finally, update `runbooks/substrate_integration_testing.md` to remove references to the deleted tests. Validate by running targeted tests and searching for any remaining references to legacy-node-tests or the legacy harness types.

## Concrete Steps

Work from the repository root. Remove the legacy test entries and delete the legacy test files, then delete the legacy node harness files and adjust feature declarations. Update the CI workflow and runbooks. Use these commands to verify references are gone and to run tests:

    rg -n "legacy-node-tests|LegacyNode|NodeService" -S
    cargo test -p security-tests --test security_pipeline -- --nocapture

Expected output is that `rg` returns no matches for the removed items, and the security pipeline test passes.

## Validation and Acceptance

Acceptance is achieved when:

1. `tests/Cargo.toml` has no `legacy-node-tests` feature or legacy test entries, and the legacy test files are removed from `tests/`.
2. The node crate no longer includes `test-utils` feature code or legacy test harness files.
3. `.github/workflows/ci.yml` no longer invokes the legacy node-wallet daemon test.
4. `runbooks/substrate_integration_testing.md` no longer references the removed legacy tests.
5. `rg -n "legacy-node-tests|LegacyNode|NodeService" -S` finds no matches in the repository.
6. `cargo test -p security-tests --test security_pipeline -- --nocapture` passes.

## Idempotence and Recovery

Deleting files is destructive but safe within version control. If a mistake is made, recover by restoring files from git history. Re-running the `rg` and `cargo test` commands is safe and will confirm the repository state.

## Artifacts and Notes

`rg -n "legacy-node-tests|LegacyNode|NodeService" -S` returned no matches. The security pipeline test passed after a longer build timeout.

## Interfaces and Dependencies

At the end of this change:

The `hegemon-node` crate must not expose a `test-utils` feature, and the types `LegacyNode`, `NodeService`, and `NodeHandle` must not exist in the codebase. The `security-tests` crate must not expose a `legacy-node-tests` feature and must not declare integration tests that depend on the legacy harness.

## Plan Update Notes

2026-01-10 19:56Z: Updated progress to reflect completed deletions and workflow/runbook edits, and recorded the test timeout/rerun outcome after validation.
2026-01-10 20:03Z: Removed remaining documentation and script references to deleted legacy tests so the plan matches the repository state.
2026-01-10 20:04Z: Refined progress wording and artifacts to capture verification evidence after completing the cleanup.
