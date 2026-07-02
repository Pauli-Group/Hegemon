# Native Tx Proving-Time Optimization

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

After this work, operators and wallet users should see lower end-to-end latency when building shipped native tx-leaf artifacts, without changing proof semantics or weakening verification on the consuming side. The first visible result is that repeated native tx builds stop paying full backend setup cost on every transaction. The second visible result is that the legacy wallet prover reports prove-vs-self-check time separately and can skip its local post-prove verification outside explicit self-check modes.

The way to see this working is to run the targeted tests and profiling commands in this plan. They must show that repeated native tx-leaf builds hit a setup cache, that artifacts still verify, and that any optional self-check policy only affects local wallet latency rather than artifact correctness.

## Progress

- [x] (2026-04-18 16:34Z) Re-read [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md), [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md), and [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md) before planning changes.
- [x] (2026-04-18 16:48Z) Inspected the real shipped proving path and rejected the initial guess that `wallet::StarkProver` was the highest-value target. The main wallet/API path uses [`wallet/src/tx_builder.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/tx_builder.rs) and [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs).
- [x] (2026-04-18 16:55Z) Confirmed the shipped native tx-leaf builder already skips local self-verification in release by default; the current hot-path redundancy is repeated lattice backend setup.
- [x] (2026-04-18 18:10Z) Implemented Experiment 1 in [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs): native tx-leaf setup is now cached by `(parameter_fingerprint, spec_digest)` and the shipped native tx-leaf build/verify plus adjacent native receipt-root helper paths reuse that context instead of rebuilding `backend.setup(...)` each time.
- [x] (2026-04-18 18:24Z) Measured Experiment 1 with focused cache tests and end-to-end validation. `native_tx_leaf_setup_cache_hits_on_repeated_builds` and `native_tx_leaf_setup_cache_separates_alternate_params` are green, `native_tx_leaf_artifact_round_trip` stayed green, and `cargo check -p wallet -p consensus -p hegemon-node` passed after the cache routing landed.
- [ ] Spawn a hostile-review subagent for Experiment 1, fix every critical/high issue it finds, and rerun until the review is clear.
- [x] (2026-04-18 22:11Z) Implemented Experiment 2 in [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs) and [`wallet/src/shielded_tx.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/shielded_tx.rs): the legacy wallet prover now has an explicit `LocalProofSelfCheckPolicy`, keeps aggregate `proving_time` for compatibility, and also reports `proof_generation_time`, `local_self_check_time`, and `local_self_check_performed`.
- [x] (2026-04-18 22:28Z) Measured Experiment 2 with targeted wallet tests. The focused config/stats tests are green, `cargo check -p wallet` is green, and both ignored prove/verify policy tests are green: the `Never` policy returns externally verifiable proof bytes without local self-check, and the `Always` policy records a real local self-check step.
- [x] (2026-04-18 22:49Z) Ran hostile review for Experiment 2, fixed one real high issue, and reran until clear. The bad regression was that `fast()`, `compact()`, and `recursion()` presets were silently defaulting to `LocalProofSelfCheckPolicy::Never`; those presets are conservative again, and only an explicit caller override can disable local self-check.
- [x] (2026-04-18 22:53Z) Reassessed the remaining evidence and stopped. The high-yield local proving-time work in the current architecture was the shipped native tx-leaf setup cache plus the legacy wallet prover self-check split. The next material gains are backend-level or proof-geometry work, not another local proving-time patch.

## Surprises & Discoveries

- Observation: the first apparent proving-time win, removing post-prove verification in [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs), is not the shipped wallet/API hot path.
  Evidence: [`wallet/src/api.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/api.rs) and [`wallet/src/bin/wallet.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/bin/wallet.rs) call [`wallet::build_transaction`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/tx_builder.rs), which uses [`build_native_tx_leaf_artifact_bytes`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) directly.

- Observation: the shipped native tx-leaf builder recreates `LatticeBackend`, `GoldilocksPayPerBitPacker`, and most importantly `backend.setup(&security, relation.shape())` for every tx build.
  Evidence: [`build_native_tx_leaf_artifact_from_transaction_proof_with_params`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) currently performs setup inline on every call.

- Observation: the shipped native tx-leaf builder already avoids local self-verification in release builds by default, so removing that is not the biggest release-path win.
  Evidence: [`native_tx_leaf_self_verify_enabled`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) defaults to `cfg!(debug_assertions)`.

- Observation: alternate backend parameter sets can legitimately share the same tx-leaf relation shape digest, so the cache tests must assert parameter-bound keys and distinct cached contexts rather than assuming `shape_digest` changes.
  Evidence: the first version of `native_tx_leaf_setup_cache_separates_alternate_params` failed even though the parameter fingerprint and cache key differed.

- Observation: the existing native receipt-root leaf cache was keyed only by artifact hash, which allowed cross-parameter reuse of already-verified leaves in long-lived processes.
  Evidence: hostile review found that [`cached_native_receipt_root_leaf_from_artifact_with_params`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) returned cached verified leaves without binding the lookup to `(parameter_fingerprint, spec_digest)`. The fix now keys that cache on `(parameter_fingerprint, spec_digest, artifact_hash)` and has a regression test proving alternate parameter sets miss and fail closed.

- Observation: the legacy wallet verifier helper was not a trustworthy “external verification” check on the current backend seam because it rebuilt a `TransactionProof` with missing serialized public inputs and the default backend selector.
  Evidence: the first ignored `LocalProofSelfCheckPolicy::Never` proof test failed until [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs) started reconstructing serialized STARK public inputs from the witness and selecting the version-owned backend in its local `verify(...)` helper.

## Decision Log

- Decision: prioritize native tx-leaf setup caching before wallet self-check policy work.
  Rationale: the user asked for the biggest likely proving-time gains first, and the shipped wallet/API route pays native tx-leaf setup on every build while the legacy wallet prover path is not the main production route.
  Date/Author: 2026-04-18 / Codex

- Decision: treat hostile review as part of each experiment rather than a final pass.
  Rationale: each optimization changes trust boundaries or caching behavior. The cheapest time to catch critical/high issues is immediately after each slice lands.
  Date/Author: 2026-04-18 / Codex

## Outcomes & Retrospective

Completed milestones:

- Experiment 1 is done: native tx-leaf setup is cached by `(parameter_fingerprint, spec_digest)`, the adjacent native receipt-root leaf cache is also parameter-bound now, focused build/verify tests are green, and the hostile re-review came back clear on critical/high.
- Experiment 2 is done: the legacy wallet prover now exposes explicit local self-check policy and split timing while keeping conservative presets, focused wallet tests and ignored policy proofs are green, and the hostile re-review came back clear on critical/high.

Retrospective:

- The biggest real proving-time gain in the current shipped architecture was eliminating repeated native tx-leaf lattice setup on the actual wallet/API submission path. That was worth doing first.
- The next local wallet gain was real too, but only after keeping the defaults conservative. The first attempt made convenience presets skip verification; the hostile review caught that regression immediately and the fix was to reserve `Never` for explicit callers only.
- A third local proving-time experiment is not justified by the current evidence. The remaining interesting gains are deeper backend/opening/proof-system work, not another tactical patch in the current stack.

## Context and Orientation

The proving stack currently has two relevant transaction-building routes.

The shipped route is the native tx-leaf path. It starts in [`wallet/src/tx_builder.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/tx_builder.rs), which builds a [`TransactionWitness`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/witness.rs) and calls [`build_native_tx_leaf_artifact_bytes`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). That function first produces a transaction proof through [`transaction_circuit::proof::prove_with_params`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs) and then wraps it inside a native tx-leaf artifact using the SuperNeo lattice backend in [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). This is the path exercised by the wallet API, wallet CLI, and several node-side tests.

The legacy route is the explicit wallet prover in [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs) and the higher-level builder in [`wallet/src/shielded_tx.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/shielded_tx.rs). It still matters for library users and diagnostics, but it is not the main submission route used by the wallet API.

The current proving backend for transaction proofs is Smallwood. The current native artifact wrapper is SuperNeo’s lattice backend. The important observation for this plan is that the native wrapper code repeatedly calls `backend.setup(...)` for the same fixed relation shape and parameter set. In this repository, “setup” means deriving the backend key material from the backend parameters and relation shape. Re-running setup for every tx is avoidable because the native tx-leaf relation shape is fixed and the parameters are version-owned and serializable.

The important files for this plan are:

- [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs): native tx-leaf artifact build and verify code, plus existing receipt-root caches.
- [`circuits/superneo-backend-lattice/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-backend-lattice/src/lib.rs): the lattice backend types. `LatticeBackend`, `BackendKey`, and `NativeBackendParams` are all cloneable, which makes a setup cache feasible.
- [`wallet/src/tx_builder.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/tx_builder.rs): the shipped wallet build path that calls the native tx-leaf builder.
- [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs): the legacy wallet prover path that still pays a full local proof verification after proving.
- [`DESIGN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md) and [`METHODS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md): these must stay aligned with the current proving architecture and any new cache or self-check policy.

## Plan of Work

### Experiment 1: Native tx-leaf setup cache

Add a dedicated cache for native tx-leaf setup context in [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs). The cached context must include the exact relation and backend key material needed by the tx-leaf public relation, plus the packer used to pack the witness. The cache key must bind the parameter fingerprint and spec digest so alternate parameter sets used in tests cannot alias with the default shipping setup. If there is any ambiguity about the cache key, choose the more explicit key and document it in the code.

Do not cache built artifacts or witness-dependent commitments. Only cache setup-derived context that is safe to reuse across many witnesses. This preserves soundness while removing repeated deterministic setup work.

The implementation should add cache statistics similar to the existing native receipt-root build cache statistics in the same file. The point is not vanity metrics. The point is to make the optimization observable and testable: a cold call should miss, a repeated call with the same parameters should hit, and alternate parameters must not reuse the wrong context.

Route the native tx-leaf build hot path through the cache first. Then route the native tx-leaf verification and decode/record helper paths through the same cached context only where it reduces repeated setup without widening trust boundaries. The rule is simple: use the cache anywhere the code recomputes the same fixed tx-leaf relation setup, but do not broaden the cache to unrelated receipt-root or recursive relations in this milestone.

After the code lands, add targeted tests in [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) that prove three things: repeated default tx-leaf builds hit the setup cache, alternate parameter sets miss and populate a distinct cache entry, and native tx-leaf verification still succeeds with the cached context. Add a small measurement-style test or report helper if needed, but prefer deterministic cache-hit assertions over timing-ratio assertions.

Once Experiment 1 compiles and passes, spawn a hostile-review subagent with ownership limited to the touched tx-leaf caching files. The review prompt must ask for critical/high issues only, with attention to cache-key soundness, stale parameter reuse, accidental cross-lane aliasing, and any hidden concurrency hazards. Fix every critical/high issue locally, update this plan, and rerun the focused tests until the review is clear.

### Experiment 2: Legacy wallet self-check policy

After Experiment 1 is closed, modify [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs) so post-prove verification is governed by an explicit policy rather than being unconditionally part of `StarkProver::prove`. The policy must remain conservative for debugging and tests, but it must let release callers skip local self-verification when they only need a proof artifact and downstream verification will happen elsewhere.

Do not remove the ability to self-check. Preserve an explicit “always verify locally” mode for diagnostics and test coverage. Split the reported timing into at least two fields: proof generation time and local self-check time. Keep the existing aggregate time for compatibility, but stop pretending it is a monolithic proving step.

Update [`wallet/src/shielded_tx.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/shielded_tx.rs) and any wallet-facing stats structures so the UI or callers can see whether local self-check happened and how much it cost. Add tests that prove the policy semantics, that `Never` does not perform self-check, that `Always` still verifies, and that the resulting proof bytes remain externally verifiable.

Once Experiment 2 compiles and passes, spawn a second hostile-review subagent for the wallet prover slice. Ask it to look for critical/high issues around accidental silent acceptance of malformed proofs, policy defaults, and any mismatch between reported timing and actual behavior. Fix all critical/high issues before closing the slice.

### Experiment 3: Only if Experiment 1 and 2 still leave a justified next step

Do not guess a third experiment in advance. Reassess after Experiments 1 and 2 using the new evidence. A third experiment is only justified if the measured remaining proving-time surface points to a specific hot path with a plausible material gain. If the remaining candidates are low-yield or speculative, stop and record that rather than adding churn.

## Concrete Steps

All commands in this plan run from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

To implement Experiment 1, edit:

- [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs) to add the native tx-leaf setup cache, stats, and hot-path routing.
- [`DESIGN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md) and [`METHODS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md) to describe the new cache and its scope once the code is real.

Then run:

    cargo test -p superneo-hegemon native_tx_leaf_setup_cache_ -- --nocapture
    cargo test -p superneo-hegemon native_tx_leaf_ -- --nocapture
    cargo check -p wallet -p consensus -p hegemon-node

The first command should show the new cache-focused tests passing. The second command should keep the existing tx-leaf tests green. The final `cargo check` proves the shipped callers still compile against the optimized path.

To implement Experiment 2, edit:

- [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs) to add the self-check policy and split timings.
- [`wallet/src/shielded_tx.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/shielded_tx.rs) and any affected public wallet exports to surface the new timing fields.
- [`DESIGN.md`](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md) and [`METHODS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md) if the behavior or defaults change in a user-visible way.

Then run:

    cargo test -p wallet prover_self_check_ -- --nocapture
    cargo test -p wallet shielded_tx -- --nocapture
    cargo check -p wallet

At the end of each experiment, run a hostile review with a subagent and then rerun the same focused validation commands after fixes land.

## Validation and Acceptance

Experiment 1 is accepted when:

1. Repeated native tx-leaf builds with the same default parameters record at least one cache hit after the initial miss.
2. Alternate parameter sets do not reuse the default setup entry.
3. Native tx-leaf artifact verification still succeeds after the cache is introduced.
4. Shipped wallet, consensus, and node crates still compile cleanly.

Experiment 2 is accepted when:

1. `StarkProver` exposes an explicit self-check policy.
2. The reported timing distinguishes proof generation from local self-check.
3. Skipping local self-check does not change the produced proof bytes’ external verifiability.
4. The hostile review for the wallet slice comes back clear on critical/high issues.

The overall plan is accepted when every completed experiment has a clear hostile-review pass, updated docs, and green focused validation commands.

## Idempotence and Recovery

The cache changes in Experiment 1 must be safe to run repeatedly. Cache warm state is process-local only; restarting the process is an acceptable recovery path if a test needs a cold cache. If tests require explicit cold-start behavior, add helper functions to clear the cache and stats in the same way the existing receipt-root cache helpers work.

The self-check policy in Experiment 2 must default to a conservative, testable mode. If a caller needs the old behavior, the recovery path is to set the policy to the “always” variant explicitly rather than relying on hidden environment behavior.

If an experiment fails its hostile review and the issue cannot be fixed without expanding scope materially, revert only that experiment’s code and update this plan to record the failure and next decision.

## Artifacts and Notes

Expected evidence for Experiment 1 should look like:

    running 2 tests
    test native_tx_leaf_setup_cache_hits_on_repeated_builds ... ok
    test native_tx_leaf_setup_cache_separates_alternate_params ... ok

Expected evidence for Experiment 2 should look like:

    running 2 tests
    test prover_self_check_policy_never_skips_local_verification_step ... ok
    test prover_self_check_policy_always_reports_verify_time ... ok

These example names may change, but the acceptance criteria above may not.

## Interfaces and Dependencies

In [`circuits/superneo-hegemon/src/lib.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/superneo-hegemon/src/lib.rs), define a stable internal setup context for the native tx-leaf relation. It must at minimum carry the relation, backend, packer, prover key, and where useful the verifier key. The cache key must be derived from `NativeBackendParams` in a way that prevents parameter aliasing.

In [`wallet/src/prover.rs`](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs), define an explicit self-check policy enum and thread it through `StarkProverConfig` and `StarkProver::prove`.

Keep the current public proof bytes and verification interfaces intact. This plan is about reducing redundant local work, not changing artifact semantics.

Revision note: this plan was created after direct code inspection showed that the real shipped wallet/API path is the native tx-leaf builder rather than the legacy `StarkProver` path. The experiment order reflects that discovery.
