# Absorb Native Sync PRs 203 and 204 into the SmallWood Production Branch

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

The experimental SmallWood transaction proof branch must retain its complete local proof, formal, carrier, and fail-closed production work while gaining the native node memory and sync corrections merged into `main` by PR 203 and the outbound page pacing correction merged by PR 204. After integration, a node using the experimental proof code must use main's bounded native sync protocol and must withhold a fifth page request until the peer's four-request, ten-second admission window can accept it. The result is demonstrated by the native sync regressions from both pull requests, the SmallWood wallet-to-node lifecycle checks, the formal gates, and a clean release-oriented compile or build.

This plan does not authorize a push, deployment, live-node restart, production proof activation, or replacement of fail-closed proof authority. Generated review bundles and formal digests must be regenerated from the resolved source; neither side's stale generated copy may be selected merely to resolve a conflict.

## Progress

- [x] (2026-08-31 23:26Z) Fetched `origin/main` at PR 204 squash commit `b819911dbf6d045501a3526da1268f1fa83092ea` and confirmed its parent is PR 203 squash commit `38061433bd2087cd5eb956585bf3103598090c8c`.
- [x] (2026-08-31 23:26Z) Audited direct applicability without changing the working tree. PR 204 alone depends on PR 203 and cannot be cherry-picked coherently into this branch.
- [x] (2026-08-31 23:26Z) Checked the disk and process gate: 56,918,748 KiB was free, `target` occupied 41,654,188 KiB, and no Hegemon build, proof, Lean, or node process was active.
- [ ] Create a reversible local checkpoint containing every tracked and non-ignored untracked change, then record a local backup branch at that checkpoint.
- [ ] Merge `origin/main` through PR 204 and resolve source conflicts by retaining main's native sync implementation and reapplying only proof-specific experimental changes.
- [ ] Regenerate formal metadata, vectors, and the native backend review package from the resolved source.
- [ ] Run focused native sync and SmallWood lifecycle tests, followed by formal and release gates within the disk reserve.
- [ ] Record final evidence, residual failures, proof byte measurements, and the unchanged production-authority state.

## Surprises & Discoveries

- Observation: PR 204 is not an independent page-pacing patch on this branch.
  Evidence: Its source assumes `NativeOutboundSyncRequestState`, request context and recovery types, and `node/src/native/sync_chunks.rs`, all introduced by PR 203 and absent from the experimental branch tip.

- Observation: The narrow pacing rule can be reimplemented on the older sync code, but doing so would not inherit the tested PR 203 recovery, chunk, target-expiry, or failover semantics.
  Evidence: The current `ResponseLocators` path installs an ownership placeholder without sending a new page. Charging that placeholder as a request would double-count and stall early; upstream avoids this ambiguity through the PR 203 state model.

- Observation: The checkout cannot safely accept a history-changing operation before a checkpoint.
  Evidence: It contains 167 modified tracked files and 833 non-ignored untracked paths, including retained proofs and proof-specific native-node changes in seven files also touched by PR 204.

## Decision Log

- Decision: Integrate main through PR 204 as one unit rather than cherry-pick PR 204 or invent an older-sync backport.
  Rationale: This preserves the exact upstream runtime and test semantics for memory-bounded sync, chunk fallback, recovery, target failover, and page pacing.
  Date/Author: 2026-08-31 / Codex

- Decision: Resolve native-node source from main first, then reapply proof-specific changes from the preserved checkpoint.
  Rationale: Main's sync changes were reviewed and tested together. Selecting the experimental branch's older sync bodies would silently discard the purpose of both pull requests.
  Date/Author: 2026-08-31 / Codex

- Decision: Regenerate every derived hash, vector registry, and review package after source resolution.
  Rationale: Generated digests describe exact source bytes. Choosing either conflict side would create a plausible-looking but false evidence bundle.
  Date/Author: 2026-08-31 / Codex

- Decision: Keep every proof production capability fail closed throughout integration.
  Rationale: Sync compatibility does not establish complete zero knowledge, composed quantum soundness, verifier refinement, release-manifest closure, or production authorization.
  Date/Author: 2026-08-31 / Codex

## Outcomes & Retrospective

Work is in progress. The pre-merge audit establishes feasibility and the safe integration order, but no source integration claim exists until the merge conflicts, regeneration steps, and validation commands below pass.

## Context and Orientation

The working branch is `codex/smallwood-pq128-experiment` at committed tip `038ec2d1275d7c1d7de4325d071f43a1fd8e66a1`. It forked from `main` at `86a6469f466763cb0df055284bb4abadf51b99da` and has fourteen branch commits. Main has two later squash commits: PR 203 at `38061433bd2087cd5eb956585bf3103598090c8c`, followed by PR 204 at `b819911dbf6d045501a3526da1268f1fa83092ea`.

The native node is implemented under `node/src/native`. PR 203 changes its storage, import, recovery, range response, and oversized-record chunk paths and creates `node/src/native/sync_chunks.rs`. PR 204 adds client-side request pacing so a node does not send a fifth request that the peer's server-side four-request window will deterministically reject. The experimental proof work also changes `node/src/native/mod.rs`, `node_impl.rs`, `service.rs`, `tests.rs`, and adjacent modules to carry and verify the SmallWood candidate through wallet, action, mining, storage, reorganization, restart, and fresh-node paths.

The term checkpoint means a local commit and local backup branch that preserve all non-ignored current files before merging. It is not pushed. A generated artifact means a file whose bytes or hashes are produced by scripts from source, such as `config/formal-security-blueprint.json` and `audits/native-backend-128b/native-backend-128b-review-package.tar.gz`.

## Plan of Work

First, record disk, process, status, and largest-file evidence. Stage every tracked modification and every non-ignored untracked path, verify the staged summary and size, and create a local checkpoint commit. Create a local backup branch whose name identifies the pre-main-204 state. This makes every later conflict resolution reversible without stashing or deleting user work.

Second, merge `origin/main` without committing automatically. Resolve main's native sync files as the base implementation. Compare each conflicted native file against the checkpoint and reapply proof-specific types, trees, semaphores, verifier calls, action routing, carrier checks, and tests without restoring the old sync scheduler or request state. New PR 203 files such as `node/src/native/sync_chunks.rs` remain present. Resolve documentation by retaining both the current proof claims and the new bounded-sync claims, with their evidence boundaries.

Third, resolve source-controlled formal modules by composition rather than side selection. Regenerate vector registries, source hashes, formal blueprint entries, and the native backend review package with repository scripts. The binary tarball and its checksum are accepted only as a newly generated matched pair.

Fourth, format the changed Rust files and run narrowly targeted native sync tests, including the PR 204 pacing, broadcast responder, bounded-state, expiry, and chunk charging cases. Run the proof carrier and lifecycle tests that exercise the experimental SmallWood action. Then run `cargo check -p hegemon-node --lib --locked`, the formal-core and formal-crypto gates relevant to the changed surfaces, the native backend review verifier, and the release policy checks. Monitor free disk before each broad or release build and stop before the available-space reserve falls below 40 GiB.

Finally, update this plan with exact command outputs and commit the integrated source and regenerated artifacts locally. Do not push. Report whether the integration is working, which gates passed or failed, the exact retained proof measurements, and that production authority remains disabled unless every independent production gate actually passes.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Record and preserve the current state:

    df -k .
    git status --short --untracked-files=all
    git add -A
    git diff --cached --check
    git commit -m "Checkpoint SmallWood production campaign before main PR 204"
    git branch codex/smallwood-pq128-pre-main204-checkpoint

Merge main without creating a partially resolved commit:

    git merge --no-ff --no-commit origin/main
    git status --short

Use `git diff --name-only --diff-filter=U` to enumerate unresolved paths. Resolve them with explicit edits and source comparisons against the checkpoint branch. Do not use a repository-wide checkout of either side. After every resolution batch, run `git diff --check` and stage only the inspected paths.

Run the regeneration commands identified by `scripts/package_native_backend_review.sh`, `scripts/check_formal_core.sh`, `scripts/check_formal_crypto.sh`, and their referenced generators. Record the exact invocations and results here before declaring generated conflicts resolved.

Run the focused tests by exact test names from the integrated `node/src/native/tests.rs`, then run:

    cargo check -p hegemon-node --lib --locked
    bash scripts/check_formal_core.sh
    bash scripts/check_formal_crypto.sh
    bash scripts/verify_native_backend_review_package.sh

Before broad compilation or packaging, rerun `df -k .`. If available space is below 40 GiB, do not start another heavy command; record the blocker and keep the tree buildable with the focused evidence already obtained.

## Validation and Acceptance

The integration is accepted only when all merge conflicts are resolved, `node/src/native/sync_chunks.rs` is compiled and exercised, and the PR 204 pacing tests prove that four pages send immediately while page five remains unsent and cannot authorize a response until the ten-second hold expires. Broadcast pagination must charge the responding peer once, per-peer pacing state must remain bounded, and pacing must not extend the existing target expiry or mining gate.

The SmallWood proof carrier must still parse one canonical proof byte string and carry it unchanged through the tested wallet, RPC, peer, mempool, mining, block, reorganization, restart, and fresh-node surfaces. Mutation tests must still reject changed proof, statement, action, and carrier bytes. Any gap in real transport, privacy, quantum accounting, refinement, release manifest, or independent review keeps production authority disabled.

The native backend review tarball must verify against its adjacent checksum and describe the resolved source. Formal blueprint and vector hashes must be regenerated rather than manually edited. The final local merge commit must contain no conflict markers and `git diff --check` must pass.

## Idempotence and Recovery

The pre-merge checkpoint and backup branch are the recovery authority. If conflict resolution becomes incoherent, abort only the in-progress merge with `git merge --abort`; do not reset or delete the checkpoint. Because all prior files are committed locally, no stash or cleanup is required. Regeneration commands must write deterministic artifacts or fail closed when existing outputs differ. No ignored build output is part of the checkpoint.

Do not delete `target`, retained proof artifacts, or user files during this plan. Disk recovery requires a separate explicit decision if the 40 GiB reserve would otherwise be crossed.

## Artifacts and Notes

Pre-merge facts:

    experiment tip: 038ec2d1275d7c1d7de4325d071f43a1fd8e66a1
    common base:    86a6469f466763cb0df055284bb4abadf51b99da
    PR 203 squash:  38061433bd2087cd5eb956585bf3103598090c8c
    PR 204 squash:  b819911dbf6d045501a3526da1268f1fa83092ea
    dirty paths:    167 tracked modifications, 833 untracked paths
    free space:     56,918,748 KiB

PR 204 changes ten paths and adds 748 lines while removing 112. A direct application against the current dirty tree fails every changed path. A clean-tip simulation finds 89 textual conflict regions, one binary review-package conflict, and a modify/delete conflict for `node/src/native/sync_chunks.rs` because the experimental branch does not contain PR 203.

## Interfaces and Dependencies

The integrated native request state must retain upstream's `NativeOutboundSyncRequestState::Paced`, `NativeOutboundSyncRequestContext`, `NativeCompletedSyncRequest`, bounded `outbound_sync_request_rate_limits`, and shared request-rate admission helper. `begin_outbound_sync_request_with_context` must distinguish an actual page dispatch from an unsent paced page. Only an `InFlight` request may authorize a normal or chunk response. A broadcast first page must charge the winning responder exactly once and direct subsequent pages to it.

The experimental proof integration must retain its source-owned proof capability function, fail-closed production registry, exact action and statement binding, Poseidon2 V8 state and verifier modules where still part of the selected candidate, persisted proof carrier, and mutation/restart checks. These interfaces must be ported onto main's native sync implementation without using sync metadata, caches, receipts, or regenerated review artifacts as transaction validity authority.

Revision note (2026-08-31 23:26Z): Created this plan after the read-only PR 204 applicability audit established the PR 203 dependency, dirty-tree overlap, disk state, and safe full-main integration order.
