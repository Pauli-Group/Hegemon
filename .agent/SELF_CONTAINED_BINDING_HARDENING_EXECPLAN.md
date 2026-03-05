# Self-Contained Statement Binding Hardening and RPC Safety

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, self-contained aggregation verification is fail-closed on canonical transaction statement bindings instead of fallback transaction hashing. Flat-batch verification binds its public inputs (anchor, fee, circuit version) to block transaction context, legacy fail-open proofless acceptance is disabled in production builds, sensitive logging is redacted, and Merkle witness RPC paths are guarded against expensive abuse. Operators and reviewers can observe the behavior through consensus unit tests and monorepo CI.

## Progress

- [x] (2026-03-01 08:04Z) Added `TxStatementBinding` to consensus block model and wired verifier-side statement-binding resolution.
- [x] (2026-03-01 08:04Z) Removed self-contained verifier fallback semantics tied to `tx.hash`; self-contained mode now requires statement bindings.
- [x] (2026-03-01 08:04Z) Added flat-batch binding checks for anchor/fee/circuit-version and matching unit tests.
- [x] (2026-03-01 08:04Z) Switched node-side statement commitment derivation to canonical extrinsic-context statement bindings (`tx-statement-v2`).
- [x] (2026-03-01 08:04Z) Production-gated legacy proofless fail-open env flag.
- [x] (2026-03-01 08:04Z) Redacted sensitive shielded logs and lowered verbosity.
- [x] (2026-03-01 08:04Z) Added witness generation guardrails in runtime pallet and RPC service paths.
- [x] (2026-03-01 08:27Z) Ran full monorepo CI-equivalent commands: `cargo fmt --all`, `make lint`, `make test`.

## Surprises & Discoveries

- Observation: Statement commitment derivation in node import and candidate proving was previously coupled to extracted transaction hashes, which can diverge by proof availability state.
  Evidence: `statement_hashes_from_extrinsics` previously delegated to transaction extraction with missing-proof fallbacks.

## Decision Log

- Decision: Add explicit per-transaction statement bindings (`hash + anchor + fee + circuit version`) to consensus block verification inputs.
  Rationale: Flat-batch public inputs must be bound to explicit block transaction context, not inferred from hashes.
  Date/Author: 2026-03-01 / Codex

- Decision: Introduce `tx-statement-v2` derivation from extrinsic context in node service.
  Rationale: Self-contained verification must not depend on proof-byte availability or `tx.hash` fallback semantics.
  Date/Author: 2026-03-01 / Codex

- Decision: Keep legacy fail-open behavior only for non-production builds.
  Rationale: Preserve emergency developer compatibility while hardening production consensus behavior.
  Date/Author: 2026-03-01 / Codex

- Decision: Guard witness RPC at both runtime pallet utility and RPC service layers.
  Rationale: Ensure remote callers cannot trigger unbounded or expensive witness generation on large trees.
  Date/Author: 2026-03-01 / Codex

## Outcomes & Retrospective

The hardening shipped with all requested controls in place: explicit statement bindings are required in self-contained verification, flat-batch anchor/fee/circuit-version binding checks are enforced, production fail-open is disabled, sensitive logs are redacted/demoted, and witness RPC generation is guarded at runtime helper and RPC service levels. Full workspace linting and tests passed after addressing type and logging macro regressions discovered during CI.

## Context and Orientation

The critical verification path is split across `node/src/substrate/service.rs` (block import extraction and statement commitment construction) and `consensus/src/proof.rs` (proof and flat-batch verification). The shielded pallet logging and witness helper paths live in `pallets/shielded-pool/src/lib.rs` and `pallets/shielded-pool/src/verifier.rs`. RPC service guards are in `node/src/substrate/rpc/shielded_service.rs` and `node/src/substrate/rpc/production_service.rs`.

A “statement binding” is a per-transaction record containing the statement hash and key flat-batch context fields (`anchor`, `fee`, `circuit_version`) in canonical transaction order.

## Plan of Work

Implement and wire `TxStatementBinding` through consensus `Block` types, derive commitments from bindings, and require bindings for self-contained mode. In flat-batch verification, assert that batch public inputs match expected binding context per batch range before proof verification. Replace node-side statement commitment derivation with a canonical hash over extrinsic call context (`tx-statement-v2`) including anchor, nullifiers, commitments, ciphertext hashes, fee, value context, version, and stablecoin context. Hard-gate legacy fail-open behavior behind non-production compile targets. Redact sensitive logs to debug/trace and remove partial cryptographic material from logs. Add witness path guards and consensus tests, then run full CI.

## Concrete Steps

Run from repository root:

    cargo fmt --all
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace

Expected result: all commands succeed with no warnings promoted to errors and no test failures.

## Validation and Acceptance

Acceptance criteria:

1. Self-contained aggregation verification rejects blocks lacking statement bindings.
2. Flat-batch binding checks reject anchor/fee/circuit-version mismatches via consensus unit tests.
3. Node import path computes statement commitments from canonical extrinsic context (not `tx.hash` fallback).
4. Production builds ignore `HEGEMON_ACCEPT_LEGACY_PROOFLESS_BLOCKS`.
5. Merkle witness RPC requests on large trees return guard errors rather than attempting expensive generation.
6. Monorepo CI commands pass.

## Idempotence and Recovery

All edits are additive and can be rerun safely. If CI fails, fix the failing crate and rerun only the failing command, then rerun full CI.

## Artifacts and Notes

Primary modified files:

- `consensus/src/types.rs`
- `consensus/src/proof.rs`
- `consensus/src/error.rs`
- `node/src/substrate/service.rs`
- `node/src/substrate/rpc/shielded_service.rs`
- `node/src/substrate/rpc/production_service.rs`
- `pallets/shielded-pool/src/verifier.rs`
- `pallets/shielded-pool/src/lib.rs`
- `consensus/tests/self_contained_mode.rs`
- `consensus/tests/common.rs`
- `node/src/codec.rs`
- `node/src/test_utils.rs`

## Interfaces and Dependencies

End-state interfaces include:

- `consensus::types::TxStatementBinding`
- `consensus::types::Block::tx_statement_bindings: Option<Vec<TxStatementBinding>>`
- `consensus::proof` flat-batch binding enforcement against `TxStatementBinding`
- Node service statement-binding derivation from shielded transfer extrinsics

Change note (2026-03-01 08:27Z): Updated progress and retrospective after successful lint/test completion.
