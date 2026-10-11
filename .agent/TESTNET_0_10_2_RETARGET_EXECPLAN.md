# Prepare the v0.10.2 testnet retarget correction

This plan follows `.agent/PLANS.md` and is maintained as an executable record. The work is based on the published v0.10.1 commit `89a61f3b341f37dc26d0fc5190ce4571336255e8`, without newer development-network changes.

## Purpose / Big Picture

The existing testnet measures nine elapsed timestamp intervals against a ten-minute target. A perfectly regular sixty-second chain therefore raises difficulty unnecessarily. v0.10.2 corrects the sample to ten intervals beginning at the operator-selected testnet block 120,000. It also removes repeated history traversal during the first wallet scan, which matters for new users joining the existing roughly 117,000-block chain. The user has authorized producing and publishing the maintenance release; upgrading hegemon-ovh remains deferred until a later authorization. Historical rules before activation are preserved.

## Progress

- [x] (2026-10-10) Created isolated `codex/testnet-0.10.2` from published v0.10.1 (`89a61f3b341f37dc26d0fc5190ce4571336255e8`).
- [x] Added and tested the shared ten-interval schedule across mining, import, sync, replay, restart and reorganization, with scoped Lean vectors and historical fixtures.
- [x] Finalized compiled activation at 120,000 and required upgrade instructions; notified the mainnet planning thread to use the corrected rule directly for its own genesis.
- [x] (2026-10-11) Initial seven-job release run `38099641878` and all 37 downloaded draft assets passed on `1b0d631818af1ec98aeea43a600cf89c60a1bf40`. Downloaded fresh sync passed 512, restart and a bounded wallet scan passed.
- [x] The downloaded node opened a separate APFS COW clone of the existing chain, matched OVH at 116,968 and caught up to 116,974. The cold wallet scan exceeded the combined 900-second harness budget; original data remained unchanged and owned processes stopped cleanly.
- [x] Implemented and independently reviewed the disposable canonical source-prefix cache. Seven cache regressions and three existing wallet archive regressions passed; optimized native build passed.
- [x] Renewed only 79 computed source-binding digests. Blueprint and claim checks pass; all 123 external-review statuses and all approval metadata remain unchanged.
- [x] Explorer live API/browser checks passed, including recent block details, public action metadata and commitment lookup. Historical backfill remains partial.
- [ ] Complete local-candidate large-chain wallet performance check; final release artifact acceptance remains separate.
- [ ] Commit revised source, regenerate the source-bound review archive from that clean commit and commit only the archive/hash afterward.
- [ ] Revise the still-unpublished v0.10.2 tag with an exact old-ref lease, rerun all seven release jobs and download-verify the final 37 draft assets against the final source/run.
- [ ] Complete final downloaded fresh/restart/wallet and full-chain wallet/persistence checks with safe errors and separate startup/scan budgets.
- [ ] Publish v0.10.2 as latest and verify public metadata/downloads.
- [ ] Apply the prepared two-HTML quickstart link update without restarting any service, then verify fresh explorer status/block/commitment responses and service PIDs.

## Surprises & Discoveries

The retarget denominator and clamps were already correct for ten intervals. The mismatch was the nine-step ancestry lookup. After correction, a bounded retarget query reads one parent plus ten ancestors rather than one plus nine. Generic light-client receipt APIs do not derive a retarget schedule; the native verifier already supplies the computed expected bits to their explicit verifier variant. That existing API limitation is not broadened here.

Formal legacy vectors must explicitly evaluate `None` rather than the compiled release setting, so selecting a future height cannot invalidate historical theorem examples. New activation vectors evaluate the height-aware helper separately.

## Decision Log

Use `consensus::pow::RETARGET_CORRECTION_ACTIVATION_HEIGHT: Option<u64> = Some(120_000)` as the single production rule. A selected value must be greater than ten and divisible by ten, enforced by a compile-time assertion. There is no CLI or environment override, preventing per-operator accidental partitions. Fixture overrides, including a startup configuration override for reopen tests, exist only in code compiled with `cfg(test)`.

Keep the existing 600,000-ms denominator, 150,000..2,400,000-ms clamp, compact encoding, first launch-boundary skip, and inherited bits between retargets. At corrected child height H, compare timestamps at H−1 and H−11. Before activation, compare H−1 and H−10 exactly as v0.10.1 did.

The user selected activation block 120,000 and authorized tagging and publication after release gates. Finalize source, regenerate the source-bound review archive, run the seven-job release workflow and download-verify its draft artifacts before publishing as latest. OVH deployment remains later work.

## Outcomes & Retrospective

The correction passes scoped arithmetic, native lifecycle, historical replay, generated-vector and source-binding checks. The additional source-prefix cache passes seven native lifecycle/performance regressions and three preserved malformed-row regressions. A production binary built and passed local two-node liveness plus canonical compatibility beyond height512. See `testnet-release/VALIDATION-0.10.2.md` for exact scope and results. The activation height is fixed at 120,000. The first seven-job release pipeline and all 37 downloaded draft assets passed on commit `1b0d631818af1ec98aeea43a600cf89c60a1bf40`; that evidence is retained but does not establish acceptance of the later cache revision. Publication remains on hold for the final revised-source pipeline and actual downloaded full-wallet scan. No OVH node upgrade is authorized in this task.

## Context and Orientation

`consensus/src/pow.rs` defines target scheduling and the generic consensus engine. `node/src/native/pow.rs` derives schedule inputs from full historical slices for startup and replay; `node/src/native/node_impl.rs` derives the same inputs from bounded stored-parent ancestry or compact replay ancestry. `node/src/native/storage.rs` receives the compiled policy selected by startup and calls the full-history helper while validating reopened canonical storage. All production paths use the compiled constant. A retarget is a change in the numerical target encoded in a block's `pow_bits`; smaller target means harder mining.

`formal/lean/Hegemon/Consensus/PowRules.lean` models scheduling, and `GeneratePowVectors.lean` emits independently computed examples consumed by Rust tests. The formal model covers arithmetic and height policy after an ancestor timestamp is supplied. Native integration tests bind actual ancestor selection, missing-history rejection, canonical indexes and reorganization behavior. These bounded tests do not prove mining economics, honest timestamps, or complete distributed consensus safety.

## Plan of Work

Finish Rust conformance by parsing both legacy and new activation vectors. Run consensus regressions, then native activation fixtures and existing schedule/sync regressions. Build the unchanged-network candidate binary from this maintenance branch. Refresh only computed formal review-content digests and preserve every existing independent-review status. Record reproducible commands and source hashes before committing. Keep the final activation constant fixed at `Some(120_000)`.

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

Revision 2026-10-10: the user selected testnet activation 120,000, authorized v0.10.2 publication, requested direct mainnet correction in the mainnet planning thread, and deferred OVH upgrade. That thread received the explicit implementation instruction.

## Cold-wallet RPC milestone

The first full-chain check used the actual downloaded ARM64 binaries on an independent copy-on-write clone of the retained v0.10.1 database. Native startup took about six minutes and twenty-nine seconds, then the node caught up and matched the fresh OVH reference. A new unfunded wallet was still scanning when the overall fifteen-minute harness budget expired. This result is a harness timeout, not a captured released-client RPC error. Inspection nevertheless found a concrete avoidable cost: every 256-commitment RPC page starts source-label extraction at block one and decodes earlier history again. Later pages repeat the same work. Wallet store persistence also rewrites accumulated encrypted state per page, but changing that durability boundary is outside this narrow optimization.

Add only a derived in-memory source-label prefix cache in `node/src/native/mod.rs` and `node/src/native/node_impl.rs`. The cache stores labels for an already scanned canonical prefix, the last fully processed block height/hash, and the next commitment index. A later page advances from that block rather than genesis. Before using a cached prefix, compare its processed-block hash to the current canonical height index and reset on truncation or replacement. Complete a block before advancing the anchor, support out-of-order and overlapping pages, and retain exact existing source labels. Cache state is disposable and rebuilt after restart. It must not change stored formats, consensus, archive validation, or the proof-review policy. Read the canonical state under consistent lock ordering while materializing each response.

Acceptance is observable: a sequence of later pages must return the same commitments/source labels while decoding each canonical block at most once until append or reorg invalidation; a same-height or deep reorg must replace prior source labels; reopen must reconstruct labels correctly. Run those meaningful native regressions plus existing wallet RPC malformed-row/paging tests, source-bound checks and the entire release workflow. Then repeat the actual downloaded full-chain wallet scan with an independent database and a budget that separately allows cold node startup and complete wallet processing, retaining exact errors and safe progress counters rather than masking failures by only raising per-RPC timeouts.

Decision 2026-10-11: fold this scoped RPC performance correction into the still-draft v0.10.2 because the user asked that the latest release work and explicitly requested live synchronization validation. Retain the original draft-run evidence. The unpublished version tag and its draft assets will be revised only after the new source passes local checks; final publication must bind every artifact to the new immutable commit. OVH node changes remain deferred.

Revision 2026-10-11: recorded initial green release/artifact gates, actual full-chain node compatibility and the inconclusive cold-wallet cutoff; added the narrow derived-cache milestone and final artifact revalidation requirements.

Revision 2026-10-11: cache implementation, independent review, ten scoped native tests, optimized build and current-source blueprint/claim checks passed. Consolidated progress in its required section; final source/archive/CI/artifact/runtime/publication gates remain explicit.
