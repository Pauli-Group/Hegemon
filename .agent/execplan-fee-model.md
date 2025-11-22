# Fee model and freeze-aware runtime integration

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We need a runnable Substrate-like runtime that combines identity tags, balances, and transaction payment. The new fee model should scale fees by call category (attestation, credential updates, settlement) and grant subsidies to identities tagged for fee discounts. Balances must respect freeze tags from the identity pallet so frozen accounts cannot move funds. The result should be verifiable through integration tests that dispatch extrinsics and assert both fee discounts and freeze behavior.

## Progress

- [x] (2025-11-22 01:20Z) Captured current repository state and requirements in this ExecPlan.
- [x] (2025-11-22 01:31Z) Scaffolded `pallets/fee-model` with a custom `OnChargeTransaction`, mock runtime wiring, and initial integration tests (blocked by dependency resolution during `cargo test`).
- [ ] Add benchmarking/WeightInfo stubs for the new pallet and hook them into the runtime.
- [ ] Resolve dependency conflicts and get integration tests passing for discounts and freezes.
- [ ] Run relevant tests to validate the implementation and update retrospective.

## Surprises & Discoveries

- Dependency mismatch: running `cargo test -p pallet-fee-model` pulls `sp-core v18.0.0` alongside `substrate-bip39` requiring different `schnorrkel` versions, causing compilation to fail. Evidence: `sp-core` builds with `schnorrkel` 0.9 while `substrate-bip39` pulls 0.11.5, leading to type mismatches. (See test output in workspace build logs.)

## Decision Log

- Decision: Use a dedicated ExecPlan file (`.agent/execplan-fee-model.md`) because the work spans multiple pallets and a runtime harness.
  Rationale: Keeps the multi-step substrate integration organized and aligned with PLANS.md expectations.
  Date/Author: 2025-11-22 / ChatGPT
- Decision: Avoid pinning `substrate-bip39` via `[patch.crates-io]` after Cargo rejected same-source patches; will address schnorrkel conflicts through dependency alignment instead.
  Rationale: Patching crates.io to the same source is invalid and did not resolve the build failure.
  Date/Author: 2025-11-22 / ChatGPT

## Outcomes & Retrospective

To be completed after implementation and testing.

## Context and Orientation

The workspace currently contains a single FRAME pallet at `pallets/identity` plus non-substrate crates. There is no shared runtime, so we will create a mock runtime (likely under `tests/src` or a new `pallets/fee-model` test module) using `construct_runtime!` to combine `frame-system`, `pallet-balances`, `pallet-transaction-payment`, `pallet-identity`, and a new `pallet-fee-model`. Balances will need `frame_system::Config` types such as `AccountId`, `BlockNumber`, and constants. The identity pallet exposes tags (`IdentityTag::FeeDiscount(u8)` and `IdentityTag::FreezeFlag`) and helper methods (`identity_tags`) we can leverage for fee reductions and freeze detection.

## Plan of Work

First, scaffold a new pallet `pallets/fee-model` that implements `OnChargeTransaction` from `pallet_transaction_payment`. The pallet config should accept per-category weight coefficients and a discount percentage for accounts tagged with `IdentityTag::FeeDiscount`. It should expose a `WeightInfo` trait for benchmarking hooks and optionally a whitelist provider to check identity tags.

Next, build a mock runtime using `construct_runtime!` that wires `pallet-balances` with sensible defaults (ED, MaxLocks, holds/freezes) and implements a freeze guard reading identity tags. Configure `pallet-transaction-payment` to use the custom `OnChargeTransaction` from the new pallet, and ensure balances use the same currency. Provide an implementation of the identity pallet’s `AdminOrigin` for tests.

Then, add benchmarking and `WeightInfo` scaffolding for `pallet-fee-model` (using `frame-benchmarking` patterns or simple placeholder weights if benches are not run) and connect them in the runtime.

Finally, write integration tests (likely in `pallets/fee-model/src/tests.rs` or `tests/src/fee_model.rs`) that instantiate the runtime, set up accounts with different identity tags, and verify: (1) transactions from discount-tagged accounts pay reduced fees using the call category coefficients; (2) accounts tagged with `FreezeFlag` cannot transfer balances due to the freeze hook. Tests should cover at least attestation and credential update calls to exercise the categories.

## Concrete Steps

Run commands from the repository root.

1. Create `pallets/fee-model` with `Cargo.toml`, `lib.rs`, and optional `benchmarking.rs/weights.rs` following FRAME conventions. Add it to the workspace members in `Cargo.toml` if not already present.
2. Implement the `OnChargeTransaction` handler that inspects the call to classify it (attestation, credential update, settlement default), applies the configured coefficient to the weight fee, and applies a subsidy/discount when the origin’s identity has a `FeeDiscount` tag. Expose configuration types for the coefficients and the identity provider.
3. Build a mock runtime using `construct_runtime!` combining system, balances, identity, transaction-payment, and the new fee-model. Configure balances with freeze hooks that check identity tags for `FreezeFlag` and prevent withdrawals/transfers accordingly. Wire transaction-payment to use the custom `OnChargeTransaction`.
4. Provide benchmarking/weight stubs so the new pallet satisfies `WeightInfo` requirements and transaction-payment/balances weight dependencies compile.
5. Write integration tests executing extrinsics through the runtime to assert discounted fees and enforced freezes. Use helper functions to register DIDs with tags, fund accounts, dispatch calls, and inspect balances/fee deductions.
6. Run the test suite or targeted tests (e.g., `cargo test -p pallets-fee-model` or similar) to confirm behavior. Update the `Progress`, `Decision Log`, and `Outcomes & Retrospective` sections accordingly.

## Validation and Acceptance

Acceptance requires a runnable test runtime where dispatching categorized calls charges fees scaled by coefficients and discounted for tagged identities, and where balances operations fail for identities tagged with `FreezeFlag`. Automated tests should fail before the changes and pass after. Running the relevant cargo tests should succeed without panics.

## Idempotence and Recovery

The steps are additive. If a command fails, correct the code and rerun the cargo test/bench commands. Creating the new crate and runtime is repeatable; cargo will rebuild incremental artifacts. No destructive migrations are involved.

## Artifacts and Notes

Include any notable test output or diffs in this section if surprises occur during implementation.

## Interfaces and Dependencies

- New pallet at `pallets/fee-model` exposing an `OnChargeTransaction` implementation `FeeModelHandler<T>` (or similar) and a `WeightInfo` trait.
- Mock runtime using `construct_runtime!` under `tests/src` or within the pallet’s tests, with types: `AccountId = u64`, `Balance = u128`, `BlockNumber = u64`.
- Dependencies: `frame-support`, `frame-system`, `pallet-balances`, `pallet-transaction-payment`, `sp-runtime`, `sp-std`, `sp-io`, `frame-benchmarking` (feature gated for benches), and the existing `pallet-identity` as identity provider.

Note: Update this plan as implementation progresses, including progress timestamps, discoveries, and final outcomes.
