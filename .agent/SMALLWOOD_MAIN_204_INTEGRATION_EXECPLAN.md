# Absorb Native Sync PRs 203 and 204 into the SmallWood Production Branch

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

The experimental SmallWood transaction proof branch must retain its complete local proof, formal, carrier, and fail-closed production work while gaining the native node memory and sync corrections merged into `main` by PR 203 and the outbound page pacing correction merged by PR 204. After integration, a node using the experimental proof code must use main's bounded native sync protocol and must withhold a fifth page request until the peer's four-request, ten-second admission window can accept it. The result is demonstrated by the native sync regressions from both pull requests, the SmallWood wallet-to-node lifecycle checks, the formal gates, and a clean release-oriented compile or build.

This plan does not authorize a push, deployment, live-node restart, production proof activation, or replacement of fail-closed proof authority. Generated review bundles and formal digests must be regenerated from the resolved source; neither side's stale generated copy may be selected merely to resolve a conflict.

## Progress

- [x] (2026-08-31 23:26Z) Fetched `origin/main` at PR 204 squash commit `b819911dbf6d045501a3526da1268f1fa83092ea` and confirmed its parent is PR 203 squash commit `38061433bd2087cd5eb956585bf3103598090c8c`.
- [x] (2026-08-31 23:26Z) Audited direct applicability without changing the working tree. PR 204 alone depends on PR 203 and cannot be cherry-picked coherently into this branch.
- [x] (2026-08-31 23:26Z) Checked the disk and process gate: 56,918,748 KiB was free, `target` occupied 41,654,188 KiB, and no Hegemon build, proof, Lean, or node process was active.
- [x] (2026-08-31 23:31Z) Created checkpoint commit `effccb72bc06266526ee4525d7e54597d7926acf` and local backup branch `codex/smallwood-pq128-pre-main204-checkpoint`; copied the ignored 99-file retained Poseidon2 artifact tree to `/private/tmp/hegemon-smallwood-poseidon2-v8-pre-main204-20260831` and verified equal file count and size.
- [x] (2026-08-31 23:33Z) Removed the checkpoint's ephemeral absolute Binius source symlink from the integration branch, added its exact ignore rule, and committed that cleanup as `b9dab517d7f18c017fa59d29545888d5993d0c83`; the backup branch still preserves the original snapshot.
- [x] (2026-08-31 23:55Z) Resolved every merge conflict from `origin/main` through PR 204. The resolved native library compiles with `cargo check -p hegemon-node --lib --locked`; it retains the exact V3 proof carrier, PR 203/204 pacing and recovery, and a pre-allocation rejection for incompatible metadata-record chunk tags.
- [x] (2026-09-01 02:14Z) Repaired two validation-before-persistence regressions found while exercising the composed branch. Direct canonical reorganization and mixed noncanonical sync batches now build the exact typed V8 transition plan before any unknown block row is written. Focused regressions prove an invalid SMZ9 suffix leaves every database tree byte-identical, while valid prestorage, reorganization, restart, and streaming controls pass.
- [x] (2026-09-01 02:14Z) Passed the complete structural native memory/sync/recovery gate. After restoring the two upstream multi-megabyte branch controls, the final `bash scripts/check_native_node_memory_sync_recovery.sh --structural-only` run passed all 88 exact tests. A separate read-only merge audit found no carrier-ordinal, fail-closed-authority, reorganization-ordering, atomicity, conflict-marker, or critical-deletion defect.
- [ ] Regenerate formal metadata, vectors, and the native backend review package from the resolved source. (The merged Lean tree independently hashes to `08777fd000a85830db09f7a2cc8ec57da8fea82189d4f1d60a8c64f477c1cf2d`; the independent source-digest test and all 14 governance tests pass. Governance and target-review digest renewal is in progress.)
- [ ] Run focused native sync and SmallWood lifecycle tests, followed by formal and release gates within the disk reserve. (Library compilation, `cargo fmt --all -- --check`, `cargo check -p hegemon-node --lib --locked`, `cargo test -p hegemon-node --lib --no-run --locked`, and the final full node suite pass. The full suite result is 728 passed, 0 failed, 10 ignored in 264.31 seconds. The suite first exposed 79 stale-fixture failures; every one was reconciled through pure admission tests, exact production-used inner parsers, or scoped `cfg(test)` bindings without changing runtime authority. A coverage re-audit then restored non-vacuous negative-cache, parser, valid-cache-refresh, multi-megabyte sync/reopen, persisted orphan-walk, typed-plan rollback, and nonzero historical-row controls. The retained-artifact lifecycle and release-package gates remain.)
- [x] (2026-09-01 05:25Z) Froze the native source after the 728-test and 88-test runs. A timestamp/diff audit confirms no production Rust changed after either run; the later HX512 and V8 coinbase edits are test-only and their exact tests passed in the full suite. The Lean-generated SMZ9 production parser vector, deterministic composed-security report, executable ZK-refinement report, and all three inactive-authority identities pass. `--require-deployed` rejects with the expected fail-closed error.
- [ ] Finish the full formal gates. (At 2026-09-01 06:29Z, `HEGEMON_FORMAL_CRYPTO_MIN_FREE_GIB=8 bash scripts/check_formal_crypto.sh full` passed: all 2,633 Lean jobs built, 64 declarations passed the kernel axiom allowlist, and the formal-crypto sanity gate covered the selected CCS, canonical wire, extraction interfaces, finite-QRO semantics, QROM boundaries, masking proofs, native parser refinement, and compressed-relation lemmas. The repair replaced the rejected private opaque certificate with an irreducible definition plus explicit unfolding proof, removed the adaptive-accounting elaboration blowup, and closed the downstream namespace, cardinality, arithmetic, and exposure-count proofs without `sorry` or `admit`. Production security remains unauthorized. The formal-core blueprint regeneration and full formal-core gate are still running.)
- [ ] Record final evidence, residual failures, proof byte measurements, and the unchanged production-authority state.

## Surprises & Discoveries

- Observation: PR 204 is not an independent page-pacing patch on this branch.
  Evidence: Its source assumes `NativeOutboundSyncRequestState`, request context and recovery types, and `node/src/native/sync_chunks.rs`, all introduced by PR 203 and absent from the experimental branch tip.

- Observation: The narrow pacing rule can be reimplemented on the older sync code, but doing so would not inherit the tested PR 203 recovery, chunk, target-expiry, or failover semantics.
  Evidence: The current `ResponseLocators` path installs an ownership placeholder without sending a new page. Charging that placeholder as a request would double-count and stall early; upstream avoids this ambiguity through the PR 203 state model.

- Observation: The checkout cannot safely accept a history-changing operation before a checkpoint.
  Evidence: It contains 167 modified tracked files and 833 non-ignored untracked paths, including retained proofs and proof-specific native-node changes in seven files also touched by PR 204.

- Observation: The checkpoint contained one absolute symlink to a disposable `/private/tmp` Binius checkout, while the authoritative retained Poseidon2 proof directory was intentionally ignored by Git.
  Evidence: The checkpoint tree had no gitlinks and exactly one mode-120000 entry. The ignored proof tree contains 99 files and occupies 20,160 KiB; its independent local copy has the same count and size.

- Observation: PR 203's oversized metadata-record chunk decoder cannot safely feed the experimental branch's active import seam.
  Evidence: The active node still imports `NativeBlockMeta`, while `NativeBlockMetaV3` and `StoredNativeBlockMetaV3` are additive exact-carrier types with a separately bound action body. Converting PR 203's legacy/current metadata record into the active type would reintroduce the explicitly rejected era/width adapter. The experimental branch already chunks oversized action bodies through its exact locator transport.

- Observation: Resolving production source is not sufficient to compile the combined test target because both branch histories retained fixtures for interfaces that no longer exist.
  Evidence: The production library compiles with zero errors, while the first `--tests` build reports only test-only references to retired miner fields, legacy metadata records, and superseded chunk/sync helpers. The pacing and proof lifecycle tests remain present and are being adapted to the resolved APIs.

- Observation: Formal review-digest regeneration caught a stale retired-source reference introduced by composing the two ledgers.
  Evidence: `print-blueprint-review-digests` rejects `circuits/block/src/p3_commitment_verifier.rs`, which commit `1600257f` intentionally deleted. The stale legacy commitment-proof decoder assumption, gate, and review path must be removed before digest regeneration; the active `native_commitment.rs` and sync-chunk resource surfaces remain.

- Observation: PR 203's write-before-adoption design became unsafe when composed with the experimental typed V8 verifier because legacy replay deliberately does not verify V8 proofs.
  Evidence: Both direct reorganization and mixed noncanonical batch import could persist an unknown suffix after legacy replay but before exact V8 verification. The repaired order is legacy replay, exact typed V8 planning over stored ancestry plus supplied rows, locked classification, one durable batch of only missing rows, then an atomic canonical transaction that reuses the same plan and exact-compares every prestored body.

- Observation: The retained proof pointer remains internally valid as historical regression evidence but is stale for the merged source.
  Evidence: The release source inventory includes the complete active local package closure and both formal trees; 26 inventory files change in this merge. The current proofs remain 122,735 and 122,607 bytes, but a new two-generator candidate must be produced after the merged source and formal trees are committed. The lifecycle test is feature-gated and ignored, so a valid exact invocation requires both `--features poseidon2-v8-retained-test-support` and harness flag `--ignored`; omitting either can falsely report success with zero executed tests.

- Observation: The native backend review package cannot be regenerated before the merge source commit.
  Evidence: Its packager archives `HEAD` and rejects a dirty tree. The current package hash therefore describes a pre-merge source snapshot. Regeneration and verification must occur from a clean committed merge, followed by a separate local evidence commit.

- Observation: A green merged suite can still hide coverage loss when conflict resolution changes the fixtures rather than the runtime.
  Evidence: The first 725/0 run had converted deterministic negative-cache tests into authority-only rejection, full RPC parser checks into direct helper calls, valid cache refresh into quarantine, upstream multi-megabyte branches into empty branches, and persisted orphan walking into a pure in-memory oracle. The repaired suite now exercises the real parent-scoped cache, the production-used JSON/projection/SCALE/resource path, a newly available valid V8 coinbase after cache creation, more than 2 MiB losing and 3 MiB winning stored branches with a four-action live planner peak instead of 48, and the persisted compact orphan walker with five metadata loads and zero full-chain reconstruction.

- Observation: The composed QROM source contained a performance-motivated private opaque certificate that the full formal-crypto policy correctly refuses even though its fields were populated by proved inequalities.
  Evidence: The first full gate stopped at `SmallWoodV8Smz9QromAccounting.lean`. A plain transparent definition made downstream elaboration impractical; a private irreducible definition preserves an explicit unfolding theorem, exact numerator/denominator field proofs, and the conservative inequality while avoiding repeated normalization of `Nat.choose 102400 36`. The isolation gate passes, the affected QROM module rebuilds in 6.6 seconds, and the complete downstream formal-crypto build now passes.

- Observation: The first complete adaptive-accounting build exposed an elaboration blowup and several downstream proof holes that incremental module checks had not reached.
  Evidence: A dependent-subtype `push_neg` path consumed more than an hour before profiling isolated it. Replacing it with explicit witness-selection lemmas and elementary cardinality embeddings reduced the 1,653-line module to a 6.1-second strict compile. The next module then exposed stale namespace references, cardinality rewrites, arithmetic normalization gaps, and four declarations containing `sorry`; all were replaced by kernel-checked proofs. The complete 2,633-job formal-crypto gate now passes and the source contains no `sorry` or `admit` in the affected modules.

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

- Decision: Keep PR 203's incompatible metadata-record chunk import fail closed and retain the experimental exact locator/action-body transport for oversized payloads.
  Rationale: The separated V3 carrier already bounds metadata and chunks the potentially large action body. A silent legacy/current-to-V3 conversion would weaken exact parser and proof-carrier binding. PR 204 pacing and PR 203 recovery scheduling remain independently applicable.
  Date/Author: 2026-08-31 / Codex

- Decision: Preserve validation-before-persistence for every typed V8 suffix, even when PR 203 would otherwise store a noncanonical body before deciding whether it wins.
  Rationale: Content-addressed storage is still a durable mutation. An invalid proof must not create a row merely because canonical indexes remain unchanged. The composed path now verifies the exact V8 relation first and retains PR 203's zero-block-write canonical transaction after valid prestorage.
  Date/Author: 2026-09-01 / Codex

- Decision: Freeze and commit all proof-source inventory files before regenerating retained proof evidence.
  Rationale: The generator records both live source bytes and `git rev-parse HEAD`. Generating during the no-commit merge would falsely pair merged bytes with the pre-merge revision. Candidate generation, manifest verification, and the exact ignored lifecycle test must all run without changing `HEAD`; pointer promotion and the native review package follow as separate evidence work.
  Date/Author: 2026-09-01 / Codex

## Outcomes & Retrospective

Work is in progress. The pre-merge audit establishes feasibility and the safe integration order, but no source integration claim exists until the merge conflicts, regeneration steps, and validation commands below pass.

## Context and Orientation

The working branch is `codex/smallwood-pq128-experiment` in a no-commit merge whose pre-merge committed tip is cleanup commit `b9dab517d7f18c017fa59d29545888d5993d0c83`. The preserved checkpoint is `effccb72bc06266526ee4525d7e54597d7926acf`, and `MERGE_HEAD` is PR 204 squash commit `b819911dbf6d045501a3526da1268f1fa83092ea`, whose parent is PR 203 squash commit `38061433bd2087cd5eb956585bf3103598090c8c`.

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

Revision note (2026-08-31 23:35Z): Recorded the checkpoint and ignored-artifact backup, removed the disposable symlink from the integration branch, and marked the full-main merge conflict resolution in progress.

Revision note (2026-08-31 23:43Z): Recorded the incompatible PR 203 metadata-record chunk seam and the fail-closed decision that preserves the experimental exact locator/action-body carrier instead of adding an era adapter.

Revision note (2026-08-31 23:58Z): Recorded compiler convergence, formal-governance evidence, stale test-fixture repair, and the fail-closed formal-ledger correction found by deterministic review-digest regeneration.

Revision note (2026-09-01 02:14Z): Recorded the two V8 validation-before-persistence repairs, the 86-test structural pass, broad-suite convergence, retained-artifact source staleness, and the commit-before-regeneration provenance rule.

Revision note (2026-09-01): Replaced the intermediate 86-test/682-pass evidence with the final 88-test structural pass and 728-pass node suite, and recorded the read-only coverage audit and non-vacuous fixture restoration.

Revision note (2026-09-01 06:29Z): Recorded the final native compile checks and the complete formal-crypto gate after repairing the adaptive finite-accounting elaboration blowup and downstream kernel proof gaps.
