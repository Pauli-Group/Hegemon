# Batch requested native block bodies within existing bounds

This ExecPlan follows `.agent/PLANS.md`. Keep Progress, Surprises & Discoveries, Decision Log, and Outcomes & Retrospective current. Its scope is the transport selector and its exact artifact qualification; it does not authorize deployment.

## Purpose / Big Picture

A requested canonical range should carry medium proof-bearing bodies within the existing response budget. Previously a body above the unsolicited-announcement threshold of256KiB forced a separate single-body locator request, even when the complete requested response fit the8MiB target. After this change a contiguous requested prefix can contain those bodies. Unsolicited announcements, genuinely larger bodies, source authority, proof validation and consensus stay unchanged.

## Progress

- [x] Inspected the active response selector, actual frame sizing and receiver request/import contracts.
- [x] Integrated one production comparison change and nine deterministic transport controls in an isolated source successor of de7a4f31b280eb52ed0c09e055840cec60d1f652.
- [x] Documented separate requested-response and unsolicited-announcement thresholds in DESIGN.md and METHODS.md.
- [x] Prepared read-only pinned CI, source/delta validation, an artifact acceptance contract and offline parser/source controls.
- [ ] Execute Linux native tests, restored-selector negative, build, H0 and backend proof cases on the exact new artifact.
- [ ] Qualify genuine medium proof bodies over the normal inline response path, complete canonical import, seedless restart and full scratch replay on that artifact.
- [ ] Independently accept the resulting source, artifact and runtime receipts.

## Context and Orientation

`node/src/native/service.rs::native_sync_response_message_from_encoded` selects either an inline `Response` or one exact `ResponseLocators` entry. A response is solicited by an already bounded range request. `node/src/native/node_impl.rs::NativeSyncResponseWireSizer` measures the actual postcard payload, protocol envelope and AEAD tag. The existing soft target is8MiB and hard encrypted frame cap is16MiB. The selector separately sums canonical bincode body bytes. Both existing8MiB checks remain mandatory; a first body that cannot fit must retain its locator, and a later non-fitting body ends the contiguous prefix without skipping.

`native_block_announce_message_from_encoded` and inbound Announce admission retain the independent256KiB unsolicited threshold. The receiver already accepts larger requested inline bodies only within an exact in-flight request, authorized contiguous range and parent/target context, followed by bounded import admission and ordinary proof/state validation.

The donor's conservative body egress reservation can allow only one positive body per peer per10-second window: every request first reserves the full maximum body, equal to the complete per-peer window budget, and a prior positive committed body prevents another such reservation until reset. That reservation and the separate2-body-request admission cap are unchanged. This observation explains an efficiency restriction; it is not a throughput measurement or unique network diagnosis.

## Surprises & Discoveries

The unsolicited256KiB threshold was also controlling requested-response packing, despite an independent actual-frame budget. Separating the thresholds requires no wire grammar, receiver, proof or consensus change. Synthetic metadata fixtures prove selection/serialization behavior only; they cannot establish genuine proof import, CPU cost, storage durability or elapsed sync performance.

## Decision Log

Decision: compare a requested body's length with the existing8MiB response target. Keep aggregate body bytes and actual encrypted-frame sizing unchanged. This preserves the current per-peer maximum range-response ceiling of4*8MiB per10-second window while increasing useful body density within it.

Decision: retain unsolicited256KiB selection/admission and all request/egress/worker/queue/reassembly caps. A rate-constant increase or proof skip is outside scope.

Decision: keep build/component success distinct from runtime acceptance. CI reports BUILD_AND_COMPONENT_GATES_PASSED_RUNTIME_PENDING, and the versioned contract names the remaining gates explicitly. A previous artifact's evidence cannot qualify changed source.

## Plan of Work

The implementation changes only the per-body comparison in `native_sync_response_message_from_encoded`; its function signature, message variants, ordered-prefix loop, aggregate checked addition, actual-frame checks and exact-locator fallback remain intact. Four tests are added and three existing threshold expectations updated in `native_sync_inline_prefix_tests`, yielding nine tests.

The new `.github/workflows/qualify-sync-range-transport-linux.yml` uses exact pinned actions, read-only contents permissions, an exact source/delta check, fresh-clone make setup and make node, and the new component executor. `scripts/qualify_sync_range_transport_source.py` pins the three functional/documentation postimages, rejects unexpected changed paths and dirty/untracked build inputs, and records every tracked source file's mode/length/SHA256. Push events retain an explicit external expected-delta acceptance requirement; dispatch pins must match the checked-out commit.

The component executor runs a controlled selector ablation in an owned temporary worktree: restore only the previous256KiB comparison while retaining the new harness, and require exactly the intended single-test assertion failure. It then runs all nine transport tests, twelve existing exact recovery controls, six relevant node/network modules, exact release build, isolated H0 identity and five backend proof cases. It rechecks source/build/artifact hashes afterward. The historical wrong-network fixture is not made applicable or relabeled.

## Concrete Steps

In the isolated source checkout, first run `python3 -I -B scripts/test_qualify_sync_range_transport_source.py`; expect30offline controls to pass. These use disposable Git fixtures and parser strings only, with no Cargo, node or network calls.

On the Linux qualification worker, execute `make setup` followed by `make node` under the pinned toolchain and build knobs in the workflow. Run the component executor with the independently reviewed exact source and complete binary Git-delta SHA256. The executor checks the actual toolchain/platform, test inventory, per-command results, exact built artifacts and post-run source inventory. It preserves bounded command evidence and cleans up its owned ablation worktree.

The direct focused native command is `cargo test --locked --release -p hegemon-node --no-default-features --lib native::service::native_sync_inline_prefix_tests:: -- --nocapture`. It must execute exactly nine nonignored tests. The medium-body and threshold-crossing expectations distinguish the new selector from the restored old comparison.

## Validation and Acceptance

The medium-body batching test includes two2MiB synthetic bodies between small blocks and requires the same ordered metadata, contiguous request prefix, encode/decode roundtrip and actual encrypted frame at or below8MiB. A separate test requires the same medium body to remain a locator for an unsolicited announcement. Another stops before the next body would exceed the remaining aggregate budget and never skips forward. Existing controls preserve exact first-body locator fallback above the range budget, aggregate/frame limits, empty response behavior and encoding-count rejection. A source-level limiter control pins10seconds-minus1ms versus exact-window reset without relaxing the egress cap.

`release-evidence/sync-range-transport-qualification-contract.json` requires a separately accepted complete current-network disposable donor and a wholly fresh H0 importer, both using the new exact built binary. A responder-only change cannot accelerate an importer whose responder still runs the old selector. The donor must perform full current-chain scratch proof replay before serving. The importer must reach the fixed canonical target and validate the unchanged27-block public-body/order-digest fixture with seven ordinary proof carriers, then cleanstop and restart seedlessly with the same canonical prefix and full scratch replay.

The genuine medium-proof control is additional to that27-block fixture: do not assume those rows contain a body above256KiB. Pin an actual current canonical medium body's size/digest and proof-carrier presence before runtime, demonstrate its normal inline `Response` carrier and unchanged native verification, and retain a separate genuinely oversized exact-locator control. Do not publish transaction IDs or private operator data in runtime evidence.

Bind all source, build inputs, node/artifact manifest, current network manifest, fixed public fixture and runtime-control hashes. Require unchanged post-run inputs, clean shutdown/flush markers and every owned donor/importer process group genuinely gone. Backend proof cases and synthetic selectors do not substitute for this runtime gate. Production/deployment authority remains separate.

## Idempotence and Recovery

Use new bounded output directories and owned disposable processes. Never modify an active qualification's source, budget, ledger or receipts. Preserve failed/incomplete receipts with their real statuses. An incomplete disposable history is not a complete donor. No production database copy, source-capability waiver, mining, wallet or payment action is part of this qualification. Any ownership or cleanup uncertainty leaves qualification failed with evidence preserved.

## Interfaces and Dependencies

Keep `NativeSyncMessage`, `NativeBlockMeta`, `NativeSyncResponseWireSizer`, protocol tags, source capability registry, proof verifier, state transitions and manifests unchanged. The existing range/import queues and serializers are the only runtime dependencies; no new package or network authority is introduced.

## Outcomes & Retrospective

The source implementation and bounded qualification path are prepared. Offline source/parser controls pass. Native compilation, tests, real inline-proof import, complete current-chain sync/restart, performance measurement and independent artifact acceptance remain pending. This plan records those boundaries so build/component success cannot be mistaken for complete runtime qualification.
