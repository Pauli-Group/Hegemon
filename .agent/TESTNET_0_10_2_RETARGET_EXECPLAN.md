# Prepare the v0.10.2 testnet retarget correction

This plan follows `.agent/PLANS.md` and is maintained as an executable record. The work is based on the published v0.10.1 commit `89a61f3b341f37dc26d0fc5190ce4571336255e8`, without newer development-network changes.

## Purpose / Big Picture

The existing testnet measures nine elapsed timestamp intervals against a ten-minute target. A perfectly regular sixty-second chain therefore raises difficulty unnecessarily. v0.10.2 prepares a height-selected correction that measures ten intervals. Operators must agree on a future activation block before final release. This preparation leaves that height unset, preserves all historical block rules, and neither publishes nor deploys the candidate.

## Progress

- [x] (2026-10-10) Created an isolated managed worktree and `codex/testnet-0.10.2` branch from v0.10.1.
- [x] Added the compiled optional activation rule and shared height-aware schedule helpers.
- [x] Bound native stored-history, sync, work, replay, and reorganization paths to the same rule.
- [x] Added thirteen Lean theorems, twelve activation vectors, five native integration tests, and a public 145-adjustment historical fixture.
- [x] Prepared v0.10.2 package versions, launcher text, and activation-pending release notes.
- [x] Collected a fresh OVH tip and a seven-day UTC forecast without selecting an activation height.
- [x] (2026-10-10) Completed scoped Rust tests, generated-vector conformance, source-binding validation, native release build, isolated two-node liveness and a bounded live relay check.
- [x] (2026-10-10) Recorded evidence in `testnet-release/VALIDATION-0.10.2.md`; final preparation commit follows.

## Surprises & Discoveries

The retarget denominator and clamps were already correct for ten intervals. The mismatch was the nine-step ancestry lookup. After correction, a bounded retarget query reads one parent plus ten ancestors rather than one plus nine. Generic light-client receipt APIs do not derive a retarget schedule; the native verifier already supplies the computed expected bits to their explicit verifier variant. That existing API limitation is not broadened here.

Formal legacy vectors must explicitly evaluate `None` rather than the compiled release setting, so selecting a future height cannot invalidate historical theorem examples. New activation vectors evaluate the height-aware helper separately.

## Decision Log

Use `consensus::pow::RETARGET_CORRECTION_ACTIVATION_HEIGHT: Option<u64> = None` as the single production rule. A selected value must be greater than ten and divisible by ten, enforced by a compile-time assertion. There is no CLI or environment override, preventing per-operator accidental partitions. Fixture overrides, including a startup configuration override for reopen tests, exist only in code compiled with `cfg(test)`.

Keep the existing 600,000-ms denominator, 150,000..2,400,000-ms clamp, compact encoding, first launch-boundary skip, and inherited bits between retargets. At corrected child height H, compare timestamps at H−1 and H−11. Before activation, compare H−1 and H−10 exactly as v0.10.1 did.

Prepare and validate a local candidate now. The user expressly deferred choosing activation; selecting the height, rebuilding the final artifacts, running publication gates, tagging, publishing, and deploying remain later work.

## Outcomes & Retrospective

The staged correction passes scoped arithmetic, native lifecycle, historical replay, generated-vector and source-binding checks. A production binary built and passed local two-node liveness plus canonical compatibility beyond height512. See `testnet-release/VALIDATION-0.10.2.md` for exact scope and results. Final publication gates remain pending a chosen height. No live node or website was changed by this task.

## Context and Orientation

`consensus/src/pow.rs` defines target scheduling and the generic consensus engine. `node/src/native/pow.rs` derives schedule inputs from full historical slices for startup and replay; `node/src/native/node_impl.rs` derives the same inputs from bounded stored-parent ancestry or compact replay ancestry. `node/src/native/storage.rs` receives the compiled policy selected by startup and calls the full-history helper while validating reopened canonical storage. All production paths use the compiled constant. A retarget is a change in the numerical target encoded in a block's `pow_bits`; smaller target means harder mining.

`formal/lean/Hegemon/Consensus/PowRules.lean` models scheduling, and `GeneratePowVectors.lean` emits independently computed examples consumed by Rust tests. The formal model covers arithmetic and height policy after an ancestor timestamp is supplied. Native integration tests bind actual ancestor selection, missing-history rejection, canonical indexes and reorganization behavior. These bounded tests do not prove mining economics, honest timestamps, or complete distributed consensus safety.

## Plan of Work

Finish Rust conformance by parsing both legacy and new activation vectors. Run consensus regressions, then native activation fixtures and existing schedule/sync regressions. Build the unchanged-network candidate binary from this maintenance branch. Refresh only computed formal review-content digests and preserve every existing independent-review status. Record reproducible commands and source hashes before committing. Keep the final activation constant unset.

## Concrete Steps

Run in the isolated v0.10.2 worktree. Use an isolated copy-on-write clone of the existing test cache at `/private/tmp/hegemon-0102-build`; only the coordinator may run Cargo against it. Set `CARGO_TARGET_DIR` to that directory, `CARGO_BUILD_JOBS=2`, `CARGO_PROFILE_DEV_DEBUG=0`, and `CARGO_PROFILE_TEST_DEBUG=0` to limit disk and concurrent compiler use.

    cargo test -p consensus --locked --lib retarget_activation
    HEGEMON_LEAN_POW_VECTORS=/private/tmp/hegemon-retarget-formal/pow-vectors.json cargo test -p consensus --locked --lib lean_generated_pow_admission_vectors_match_production
    cargo test -p hegemon-node --locked --no-default-features --lib retarget_activation
    cargo test -p hegemon-node --locked --no-default-features --lib pow_schedule
    cargo test -p hegemon-node --locked --no-default-features --lib sync_tip_extension_across_retargets
    make node

Run packaging and launcher regression scripts. The final publication run also requires the full formal-core, dependency audit, native backend review-package/posture, app/no-SSH, four-platform builds and binary manifest/audit gates already wired in `.github/workflows/release.yml`. A clean committed final source tree and activation height must precede regeneration of the native backend review archive. This preparation does not claim those final artifact gates have passed.

## Validation and Acceptance

All 145 sampled historical adjustments must remain byte-identical with no activation or an activation after the sample. With a simulated activation at thirty, a sixty-second chain hardens under the old rule at twenty and preserves parent bits at thirty and forty. Incorrect legacy bits at the activation boundary must reject before import. Mining/status, announced import, sync batches, stored side-parent ancestry, full replay and winning-side reorganization must agree. The corrected metadata path loads at most eleven records and zero complete block-body decodes or full-chain reconstructions. Existing Lean legacy vectors and twelve new activation vectors must both match Rust. The candidate must build and report version 0.10.2.

## Idempotence and Recovery

All tests use disposable databases. The source worktree is isolated from unrelated proof development and retained v0.10.1 artifacts. Tests and builds may be rerun after a failure; no user wallet/node state is involved. Reverting this preparation affects only this branch. An activation height cannot be changed after publication without a coordinated replacement release.

## Artifacts and Notes

The checked-in public fixture contains only block heights, timestamps and compact bits; it contains no operator IPs or private wallet material. The raw audit remains at `/private/tmp/hegemon-difficulty/`. UTC estimates live at `/private/tmp/hegemon-0102-forecast/` and are scenarios rather than promised activation times. Refresh the tip and pace immediately before selecting the height.

## Interfaces and Dependencies

The legacy public helpers `pow_retarget_anchor_steps` and `expected_pow_bits_from_schedule` retain their signatures and delegate to height-aware variants with the compiled constant. New variants accept `Option<u64>` as their final parameter. `None` means the historical rule at every height; `Some(H)` selects ten ancestor steps on eligible retarget boundaries at or after H. The reward arithmetic and dependencies remain unchanged.

Revision 2026-10-10: initial preparation and validation plan, incorporating the user's request for a seven-day activation forecast while leaving activation undecided.

Revision 2026-10-10: completed five activation lifecycle tests including mined import/restart, scoped conformance and source bindings, release build and disposable runtime checks; retained the full final-release gate list pending activation selection.
