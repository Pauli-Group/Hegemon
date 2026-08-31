# Bound Native Mining Memory and Restore Forked Sync Progress

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this change, a long-running `hegemon-node` miner can prepare work without decoding and retaining memory proportional to the full chain on every work cycle, a node whose local branch diverges from a longer peer branch can find a common ancestor and resume canonical imports instead of requesting the same unproductive range forever, and two upgraded peers can transfer a valid persisted block record larger than the legacy 16 MiB frame through bounded chunks. The implementation is observable through deterministic retarget-crossing history counters, a production-helper fork fixture that uses two in-process storage-backed nodes, bounded outbound response and chunk construction, and a separately measured release-node RSS/progress run. Those controlled surfaces do not simulate the live chain height or prove the peak memory of a live-depth reorganization.

The work starts from `main` commit `86a6469f466763cb0df055284bb4abadf51b99da` on branch `codex/fix-testnet-node-memory-sync`. It must not import or inherit experimental SmallWood branch state. Live checks against `hegemon-dev` and `hegemon-ovh` are read-only. This plan does not authorize deployment, service restart, database mutation, merge, or other live-node changes.

## Progress

- [x] (2026-08-30 22:03Z) Verified the checkout was clean and exactly matched local and remote `main` at `86a6469f`, then created `codex/fix-testnet-node-memory-sync` from that commit.
- [x] (2026-08-30 22:08Z) Read `.agent/PLANS.md` and consulted the native-node, PoW, sync, validation, and documentation obligations in `DESIGN.md` and `METHODS.md`.
- [x] (2026-08-30 22:12Z) Located the active mining reconstruction path in `node/src/native/node_impl.rs`, `node/src/native/storage.rs`, and `node/src/native/pow.rs`, plus the active sync range path in `node/src/native/service.rs`.
- [x] (2026-08-30) Captured read-only live service, RPC, fork-hash, memory-map, OOM, storage-size, and retry-log evidence from both hosts. No service or live data was changed.
- [x] (2026-08-30) Classified the mining path: repeated full-chain decoded values are confirmed transient allocations; a redundant 128-template action cache is a confirmed retained-live-object surface; allocator arena/high-water retention is strongly supported by the maps and allocation/release pattern but not heap-profile-proven.
- [x] (2026-08-30) Reproduced the sync control-flow defect from source and live hashes: the first returned child is missing its competing parent, `Ok(false)` was collapsed into `AlreadyKnown`, all-known suppressed backfill, and the next request was immediately identical.
- [x] (2026-08-30) Implemented the consensus-preserving mining history substitution, removed the redundant prepared-work action clone cache, and preserved explicit sync import outcomes through scheduling.
- [x] (2026-08-30) Added and passed both primary regressions: canonical mining/status/mined-import use zero full-chain reconstructions, and the exact live-size 64-block missing-parent fixture changes range, acquires the missing fork parent, and advances canonically.
- [x] (2026-08-30) Bounded additional reorg amplification: old-branch recovery walks only the losing suffix, and canonical-index planner temporaries peak at one block while matching the legacy full-chain plan exactly.
- [x] (2026-08-31 00:12Z) Consolidated startup onto one validated canonical metadata snapshot shared by block-index, bridge replay, header-MMR, canonical replay, and ciphertext index/archive checks; the focused reopen regression counts exactly one chain load and one metadata decode per canonical height.
- [x] (2026-08-31) Split outbound sync state into response-authorizing in-flight entries and non-authorizing cooldowns; bound forward pages to the preceding response hash and the announced target hash; preserved the deep-recovery cursor across monotone same-peer target advances.
- [x] (2026-08-31) Added aggregate exact-missing-count manifest admission and reopen tests for validated noncanonical sync batches, plus Lean/vector and production-wiring coverage for both noncanonical and canonical tip-extension batches.
- [x] (2026-08-31) Added equal-height fork coverage: a pure planner test crosses the 255-block backfill horizon, and a signed storage-backed integration stores a connected side page, adopts the better equal-height target, and resolves the mining gate.
- [x] (2026-08-31) Changed outbound sync serving to load only the wire-budgeted canonical prefix (or one first block that exceeds the soft target but fits the hard cap), with exact allocation-free encoded-size accounting, at most one inspected block beyond the retained prefix, and a global cap of two response-building workers.
- [x] (2026-08-31) Added append-only native-sync ordinals 4/5/6 for peer-offered oversized-record chunk fallback and compact tip announcements, with canonical 4 MiB non-final segments plus an exact final remainder, exact schema/digest/context binding, one session per direction per peer and two sessions globally, separate receive-worker caps, bounded expiry, and common legacy-response import handoff.
- [x] (2026-08-31) Replaced the known-prefix assumption with exact per-row classification, so a connected `KnownExact / Missing / KnownExact` response validates the complete path and persists only its missing connector while a same-hash metadata mismatch fails without writes.
- [x] (2026-08-31) Removed pre-import target clearing based on supplied cumulative work. A nonwinning target now clears only after the authorized response is fully processed and its exact target row is validated and durably reloaded from local storage.
- [x] (2026-08-31) Removed avoidable best-tip body clones from scalar/header RPCs; RPCs that return block bodies or bounded historical rows still decode the records they return.
- [x] (2026-08-31) Ran the final focused, broad Rust, formatting, lint, release-build, conformance, and formal-core gates. The 80-test structural gate, both 513-test native configurations, repository test/lint/build gates, and all 14 formal-core phases passed. The dependency audit reproduced the unchanged-from-`main` baseline failure: 7 findings, 4 waived, and 3 unwaived (`RUSTSEC-2026-0258` in `h2 0.4.15`, `RUSTSEC-2026-0253` in `lru 0.7.8`, and yanked `chacha20 0.10.1`).
- [x] (2026-08-31) Ran the final release-node RSS/progress sample and controlled liveness/restart scenarios on isolated loopback ports. The two-node run produced and synchronized 12 blocks in 7 seconds, restart catch-up reached miner/follower height 15, and the verified release process advanced 3 blocks across 45 measured samples with an 80 KiB RSS growth/envelope under the precommitted 256 MiB limits.
- [x] (2026-08-31) Updated `README.md`, `DESIGN.md`, `METHODS.md`, and this plan with operator prerequisites, final invariants, evidence taxonomy, outbound response bounds, compatibility analysis, and residual ownership.
- [x] (2026-08-31) Reviewed, committed, and pushed the focused branch, then opened and read back [PR #203](https://github.com/Pauli-Group/Hegemon/pull/203) targeting `main`. The PR remains open and unmerged; neither live node was deployed, restarted, or mutated.

## Surprises & Discoveries

- Observation: Before this fix, `prepare_work` called `expected_child_pow_bits`, which reconstructed the full ancestor chain, and later called `header_hashes_to_hash`, which reconstructed it again before extracting hashes.
  Evidence: The baseline `node/src/native/node_impl.rs` call graph routed both helpers through `load_chain_to_hash`. The active work/status/mined-revalidation paths now use bounded PoW projections and cached compact MMR peaks, with zero full-chain reconstruction.

- Observation: Earlier native-sync work found that treating every received range as a generic reorg could replay and rebuild canonical state from genesis, and that a fixed shallow backfill can never recover when the common ancestor is deeper than the window.
  Evidence: `.agent/native-sync-liveness-execplan.md` records live measurements and the intended contiguous-tip and adaptive-backfill invariants. These are historical clues; current behavior still requires direct source and test confirmation.

- Observation: The live nodes share canonical hash `0x000003b0...7d45` through height 43,528 and diverge exactly at height 43,529. The returned OVH block at 43,530 names OVH's competing 43,529 block, which dev does not have. Dev nevertheless requested 43,530 through 43,593 repeatedly.
  Evidence: Read-only `chain_getBlockHash`/`chain_getHeader` calls on both loopback RPC endpoints and matching filtered service logs. This disproves the tentative theory that the repeated range itself was already retained on a local fork.

- Observation: OVH advanced from about 69,947 to 69,954 while holding roughly 23.26 GB of anonymous RSS on a host with no swap. Its high-water mark was 23,395,972 kB, only 146,792 kB below the August 25 OOM victim's anonymous RSS. Dev stayed at canonical height 43,529 with about 3.29 GB anonymous RSS and a closed mining sync gate. The measured live database footprints were about 1.1 GB on OVH and 742 MB on dev, far smaller than their anonymous-RSS peaks.
  Evidence: Read-only `/proc`, filesystem-size, kernel journal, RPC, systemd, and log inspection. OVH anonymous RSS fell by 88.1 MB in five seconds and then regrew by 35.8 MB over twenty seconds, proving some allocation/release activity but not the reachability of the remaining baseline. Database size does not measure decoded heap reachability or allocator residency.

- Observation: A full metadata reconstruction at the live height contains at least 350.71 MiB of ML-DSA public-key and signature vectors alone when the historical records use the current signed format. `prepare_work` formerly reconstructed twice, mined import twice, and every mining-status poll once; two mining workers can overlap these values.
  Evidence: `load_chain_to_hash` retains every decoded `NativeBlockMeta`; the ML-DSA vector lengths are 1,952 and 3,309 bytes. This is a source-derived lower bound, not a live heap attribution.

- Observation: Ordinary sync messages and response counts are bounded, and the missing-parent blocks were absent from dev storage, so the observed loop did not confirm an unbounded queue or orphan-object leak. It did confirm repeated response decode/clone/drop churn. The baseline winning-reorganization path was a separate high-amplification path because it could retain decoded new and old history together with serialized records and replay/index plans.
  Evidence: Active queue types and caps, read-only hash lookup, and the before/after import/reorganization ownership graph.

- Observation: Active announced and sync winning-fork adoption no longer materializes a full-body replacement-chain vector. It exact-classifies supplied rows, durability-flushes only missing content-addressed records, rebuilds compact ancestry, and reloads one stored body at a time for replay and canonical planning before a zero-block-write canonical transaction. Reorganization still is not constant-memory: replay state, action-hash/orphan/pending/staged collections, the complete canonical output plan (including ciphertext bytes), height rows, and atomic-commit key collections remain history/state/output-sized.
  Evidence: The compact ancestry and persistence-admission call graph, deterministic zero-reconstruction/body-pass counters, planner peak counters, mixed-tail regression, and reopen comparison. These are structural ownership bounds, not a measured 43,529-block process-RSS bound.

- Observation: Startup independently reconstructed the same canonical metadata chain during block-index validation, bridge replay reload, header-MMR peak reconstruction, and ciphertext index/archive verification.
  Evidence: The pre-fix source call graph contained four direct or wrapped `load_chain_to_hash` calls. The focused archive-bearing reopen regression now observes one lowest-level chain load and exactly `best.height + 1` decoded metadata rows while the existing startup corruption suites remain fail closed.

- Observation: A recovery cursor keyed to one exact advertised height/hash was insufficient: normal higher announcements could discard deep progress, equal-height ancestor pages were rejected as stale, and cooldown entries could authorize duplicate heavy responses.
  Evidence: Independent state-machine review plus focused regressions for monotone target advance, equal-height recovery pages, exact request completion, late cooldown responses, forward-parent binding, and final-target hash binding. The fixed state retains one peer-bound cursor, accepts responses only for `InFlight`, and never treats recovery ancestors as verified target completion.

- Observation: The former pre-import nonwinning fast path could clear the hash-anchored target from unvalidated response fields, including peer-supplied cumulative work, and reopen mining before durable evidence existed.
  Evidence: The active path now routes an exact target row through ordinary validation/import, requires full response consumption, reloads the exact durable target record, and applies local fork choice before clearing. Forged, mismatched, failed, and missing-parent regressions retain the target and closed gate.

- Observation: Besides the removed prepared-work action clone cache, auto-recursive candidate actions were retained after their parent tip became stale and duplicated proof bytes in both encoded public arguments and the candidate artifact.
  Evidence: The cache is bounded, so it cannot explain 23 GB by itself, but it is confirmed reachable ownership. Successful mined, announced-tip, sync-tip-batch, and reorg publication now clear it; failed and nonwinning imports do not mutate it.

- Observation: Scalar and header-only RPC methods previously called `best_meta()` and cloned the complete best-tip action body even when returning only a height, hash, PoW field, or header.
  Evidence: Those handlers now read compact best-state fields directly, and a structural regression rejects `best_meta()` in `rpc.rs`. `chain_getBlock` and bounded body/row methods still decode the requested record because their responses require that data.

- Observation: Serving a maximum-size sync request formerly loaded and decoded the entire requested range before wire truncation. With 256 requested rows and the existing per-block cap, concurrent workers created a source-level peak-amplification path far above the final response frame.
  Evidence: The active `block_range` call graph loaded every row before `truncate_native_sync_response_blocks_to_wire_budget`. The replacement loader stops at the retained wire prefix, may inspect one additional candidate, and admits at most two response builders globally. This is a structural ownership bound, not measured process RSS.

- Observation: A valid first block record larger than the 16 MiB encrypted frame cannot make progress through the legacy `Response` shape, while treating any empty response as fallback authorization would let unsolicited traffic start retained storage/reassembly work.
  Evidence: The replacement server installs an authenticated peer-bound offer before sending the empty legacy response. Only the matching in-flight requester can enter the 4 MiB chunk path, and only after the peer advertises a best height at or above the requested first height. The rolling extension has no capability negotiation, so both sides must be upgraded for this case.

- Observation: Bounding a chunk to 4 MiB and a raw record to `MAX_NATIVE_BLOCK_META_BYTES` does not by itself bound the completion peak or the output-sized residual of a winning reorganization.
  Evidence: Completion can simultaneously own the current protocol frame, segmented chunks, consolidated raw record, decoded metadata, exact decoder work, sled pages, and allocator residency. The common import handoff now avoids a branch-depth full-body vector, but replay state and the canonical output plan/write set remain history/state/output sized.

- Observation: The final disposable macOS soak exercised the release binary built from this branch after the response-prefix and worker-cap changes.
  Evidence: PID 37136 was independently matched to the exact `target/release/hegemon-node` command and the `127.0.0.1:21947` listener before sampling. After 12 warm-up samples, 45 measured samples with five status polls each advanced height 39 to 42 while RSS remained between 35,536 and 35,616 KiB. This is OS RSS/progress evidence on macOS, not anonymous-RSS, HWM, heap-reachability, allocator, live-depth reorg, or Linux-host proof.

## Decision Log

- Decision: Preserve consensus bytes and decisions while changing only how already-persisted ancestry is queried and how no-progress sync requests are scheduled.
  Rationale: The failures are resource/liveness defects. A fix does not need a new block format, difficulty formula, fork-choice rule, or activation boundary.
  Date/Author: 2026-08-30 / Codex

- Decision: Prove boundedness structurally in tests, not only by comparing process RSS.
  Rationale: RSS conflates live allocations with allocator arenas and operating-system accounting. Instrumented read counts, bounded returned collections, queue caps, and deterministic no-progress transitions can catch regressions without relying on a particular allocator.
  Date/Author: 2026-08-30 / Codex

- Decision: Use current live nodes only for read-only diagnosis and post no claims of fixed live behavior before an authorized rollout.
  Rationale: The user explicitly withheld deployment and restart authorization. Controlled local nodes can establish implementation behavior; live hosts can establish only the pre-fix symptom and topology in this task.
  Date/Author: 2026-08-30 / Codex

- Decision: Canonical PoW first exact-verifies the supplied parent against its stored record, follows at most `RETARGET_WINDOW - 1` stored parent links when the retarget schedule requires ancestry, and then binds the supplied parent and reached anchor to their indexed canonical rows. Header-history commitment comes from the validated canonical MMR peak state.
  Rationale: This bounded stored-parent ancestry projection supplies the existing consensus calculation without reconstructing historical bodies; it is not a claim that retargeting performs one anchor read. Focused oracle comparisons prove the resulting difficulty, MMR root/length, and prepared header fields remain identical.
  Date/Author: 2026-08-30 / Codex

- Decision: Preserve distinct sync outcomes for canonical advancement, valid noncanonical storage, already-known data, missing parent, and error. A missing-parent or otherwise no-progress response must move/widen a range that straddles peer ancestry, while an import error backs off instead of immediately replaying the same range.
  Rationale: The old boolean erased the exact recovery signal. Merely reclassifying it is insufficient because a backfill equal to the live request size was a no-op; useful recovery must change the actual requested range and retain at least one forward slot.
  Date/Author: 2026-08-30 / Codex

- Decision: Keep the winning-chain acceptance and canonical publication contract intact, but make exact content-addressed candidate rows a durability-flushed precondition and adopt the stored tip through compact ancestry plus one-body streaming passes. Classify every supplied row so a missing connector followed by a known exact descendant persists only the connector.
  Rationale: A fully replay-validated missing suffix may safely survive a crash as noncanonical content-addressed rows. The later canonical transaction writes zero block records while atomically replacing canonical indexes and the best pointer. Compact adoption removes the admitted full-body chain and transaction-overlay copies without changing consensus, fork choice, row bytes, or publication order; history/state/output-sized replay and index products remain explicit residuals.
  Date/Author: 2026-08-30 / Codex

- Decision: Have the existing block-index validator return a private, non-cloneable validated startup snapshot and borrow it through later reload checks.
  Rationale: This keeps chain reconstruction inside the existing fail-closed formal gate, preserves validation and publication order, and prevents later startup consumers from accidentally owning another full decoded chain. Replay and index planning remain separate streaming action passes, so the change does not overclaim constant-memory startup.
  Date/Author: 2026-08-31 / Codex

- Decision: Treat sync request authorization, cooldown, recovery paging, and advertised-target identity as separate state rather than inferring them from a height range alone.
  Rationale: The live loop was not only a range-selection bug. A durable fix must reject unsolicited/late responses, preserve a branch-bound frontier across dropped pages and target growth, and avoid resolving an equal-height target from an ancestor page.
  Date/Author: 2026-08-31 / Codex

- Decision: Resolve a nonwinning hash-anchored target only from a fully processed authorized response and the exact durable target row reloaded from local storage.
  Rationale: Peer-supplied cumulative work and other pre-import metadata are untrusted. They cannot clear sync state or reopen mining before ordinary validation, persistence, and local fork-choice comparison succeed.
  Date/Author: 2026-08-31 / Codex

- Decision: Admit a connected nonwinning sync page with one aggregate replay, then persist its exact classified-missing rows in one sled batch.
  Rationale: Per-block side-branch import replayed the full ancestor state for every child. One aggregate replay and one exact-missing-count manifest remove the 64-times-per-page amplification while retaining all-or-nothing persistence, durability, known-row exactness, and the existing schema.
  Date/Author: 2026-08-31 / Codex

- Decision: Apply the outbound wire budget during canonical block loading and globally cap response-building work at two workers.
  Rationale: A count-capped request can still represent gigabytes of admitted block data. Loading all requested blocks before truncation defeats the wire cap as a memory control, and a per-peer cap permits the peak to scale with peers. Prefix loading plus one inspected candidate and a global worker cap bound this specific service-owned surface while retaining legacy response order and bytes for records that fit.
  Date/Author: 2026-08-31 / Codex

- Decision: Extend `NativeSyncMessage` append-only with `RequestBlockChunk = 4`, `BlockChunk = 5`, and `AnnounceTip = 6`, preserving legacy ordinals 0 through 3 byte-for-byte.
  Rationale: A valid record above the legacy 16 MiB frame otherwise cannot synchronize. The extension has no capability negotiation: old peers reject the appended variants, and both requester and server must be upgraded for an oversized record. Fallback begins only after the server installs a peer-bound offer and returns the matching empty legacy response. Canonical full-size non-final chunks and an exact final remainder fix the segment count from the record length and 4 MiB cap; the existing record cap, a domain-bound descriptor digest, exact advertised schema, contiguous reassembly, one session per direction per peer with two sessions globally, separate receive-worker one-per-peer/two-global caps, and 30-second idle/120-second hard expiry bound the transport-specific ownership before the common legacy-response import handoff. Opposite-direction sessions may coexist so symmetric oversized offers cannot deadlock both peers.
  Date/Author: 2026-08-31 / Codex

- Decision: Terminally evict and cool down any peer-bound unverified hash target, whether learned through full `Announce` or compact `AnnounceTip`.
  Rationale: One failed target must not pin the mining gate forever. This is a bounded anti-pinning measure, not Sybil resistance, quorum proof, or evidence that another advertised target is valid.
  Date/Author: 2026-08-31 / Codex

## Milestones

1. **Baseline and read-only live diagnosis — complete.** The branch starts exactly at `main` commit `86a6469f`; live service/RPC, fork, RSS/OOM, and retry evidence was collected without a deployment, restart, or database mutation.
2. **Mining/startup ownership repair — complete.** Canonical work and bridge hash history use compact metadata, startup shares one validated metadata snapshot, stale candidate ownership is invalidated at canonical publication, scalar/header RPCs avoid tip-body clones, and active winning adoption streams durable bodies without claiming constant-space reorganization. The final 80-test structural gate and both final 513-test native configurations passed, including `canonical_mining_uses_cached_mmr_without_chain_reconstruction`, bounded retarget history, compact RPC ancestry, and one-snapshot startup regressions.
3. **Fork-sync progress repair — complete.** Missing-parent, all-known, stored-noncanonical, and canonical-advance outcomes remain distinct; every response row is exact-classified, mixed missing/known tails selectively persist and adopt, recovery ranges move across the fork, accepted pages use batch-shaped persistence, and target resolution requires fully processed durable local evidence. The final structural and native runs passed the 64-block missing-parent progression, all-known backfill, mixed `KnownExact / Missing / KnownExact`, equal-height recovery, durable target-authority, cooldown, failover, and reopen regressions.
4. **Outbound response and oversized-record transport bound — complete.** Canonical rows stream into the retained legacy wire prefix (with the explicit single-first-block soft-target exception), sizing avoids a second frame allocation, and no more than two response builders run globally. The final structural/native/formal runs passed legacy-byte pinning, more-than-four-chunk import, exact 4 MiB non-final/final-remainder shape, digest-before-decode, reserve-failure cooldown, session/worker/expiry bounds, symmetric close, malformed input rejection, compact-tip non-authority, and common import handoff.
5. **Final repository and formal gates — complete with one disclosed baseline failure.** `./scripts/check-core.sh test`, lint, build, `make node`, both native configurations, formatting/diff/shell hygiene, the 80-test structural gate, and all 14 formal-core phases passed. Formal results were 123 claims, 2,763 named Lean theorems, 112 production-eligible claims, 54 residual risks, 123 blueprint nodes, 530 edges, 679 falsification cases, 239 implementation bindings, and 177 implementation result obligations. `bash scripts/dependency-audit-gate.sh` failed with the pre-existing 7/4/3 finding split described above; Cargo manifests and `Cargo.lock` are unchanged from `main`, so this focused PR does not hide that failure or attempt unrelated dependency surgery.
6. **Controlled final-binary evidence — complete.** Release binary SHA-256 `160682c2c083d6b26f625b361b4beaef42f3a742341719f662fe6ae3327a02a3` passed two-process liveness (miner/follower 5 to 17, 12 blocks in 7 seconds, maximum 2-second gap), follower restart/reopen catch-up (persisted height 3; miner/follower 15), and the explicit-PID RSS/progress soak (height 39 to 42; RSS 35,536 to 35,616 KiB; 80 KiB envelope/growth; 45 samples after 12 warm-ups). These isolated runs do not reproduce the 43,529-block live fork, a live-depth reorganization, Linux anonymous RSS/HWM, or allocator behavior.
7. **Pull request — complete.** The focused branch was committed and pushed, and [PR #203](https://github.com/Pauli-Group/Hegemon/pull/203) was opened against `main` and read back. It remains open and unmerged; no deployment or live-node restart was performed.

## Outcomes & Retrospective

The source implementation, final controlled validation, and PR publication are complete. Final regressions prove zero full-chain reconstruction in canonical mining, bounded retarget ancestry, one validated canonical metadata snapshot per reopen, compact header-hash history, one-body stored replay passes, exact mixed `KnownExact / Missing / KnownExact` connector persistence, durable post-import target authority, scalar RPC tip reads without action-body clones, retarget-crossing tip-extension behavior, exact 64-block missing-parent range movement, equal-height recovery/adoption, and bounded oversized-record chunk transport. The storage-backed fork fixture is not a live P2P or live-depth reproduction. Separate release-process evidence shows two-node progress/restart recovery and a bounded macOS RSS window, without claiming Linux allocator or heap-object proof. PR #203 contains the root causes, evidence, compatibility analysis, disclosed dependency baseline, and cautious rollout/rollback plan; it is not merged.

The compatibility claim is deliberately narrow: block/header formats, persisted block-record and sled schemas, difficulty and fork-choice rules, consensus acceptance, canonical row order, and publication order remain unchanged; final tests compare the affected difficulty/MMR/header results and storage plans against legacy oracles. Native sync wire compatibility is not unchanged. The postcard enum extension is append-only, so ordinals 0 through 3 retain their legacy bytes, but ordinals 4 through 6 are a mixed-version boundary with no capability negotiation: an old peer rejects `RequestBlockChunk`, `BlockChunk`, and `AnnounceTip`, and both requester and server must upgrade before a record above the legacy 16 MiB frame can synchronize. Final coverage pins the old bytes and exercises a valid record requiring more than four authenticated chunks, invalid floods consuming zero workers, expiry/failover/close release, malformed schema/digest/order/oversize rejection, partial/compact-tip non-authority, and the common import handoff. All formal/conformance phases passed. None of the current evidence proves live-host post-rollout behavior, heap reachability, glibc arena internals, sled/OS durability, the chunk-completion process peak, or the peak of a 43,529-block reorganization. Live measurements establish severe anonymous-RSS/OOM symptoms; source and instrumentation establish repeated allocations and bounded retained surfaces. Allocator high-water retention remains a strong inference, not a heap-profile-confirmed leak.

## Context and Orientation

The native node persists block metadata in sled. `node/src/native/storage.rs` owns raw ancestry and canonical-index access. `node/src/native/node_impl.rs` owns block validation, work preparation, fork choice, reorganization, and import. `node/src/native/service.rs` owns peer sync request/response scheduling. `node/src/native/pow.rs` implements deterministic compact-target and retarget calculations. `node/src/native/tests.rs` contains the large in-crate behavioral suite.

A work cycle is one invocation of `NativeNode::prepare_work`, used by mining workers to construct a candidate header and body. A full-chain reconstruction walks from a requested tip to genesis, decodes every `NativeBlockMeta`, stores the results in a `Vec`, and reverses it. At roughly seventy thousand blocks, doing this more than once per work cycle creates large allocation churn even if all values are dropped. Process RSS alone cannot say whether the allocator retained freed pages, code retained live values, or both.

Native sync uses legacy capped `Request { from_height, to_height }` and `Response` messages plus append-only chunk-request, chunk-response, and compact-tip variants. A count cap alone is not a memory cap because each admitted block can be large, so outbound construction also needs an incremental wire-prefix limit and a global worker limit. If the first record cannot fit the hard legacy frame cap, the server must install a peer-bound offer before the empty legacy response can authorize chunk fallback; an empty response without that offer is not authorization. A normal response directly extending the current canonical tip should validate and commit as a contiguous extension. A forked response must include or cause discovery of a common ancestor before reorganization can succeed. An “unproductive response” is a syntactically valid response that imports no new canonical block and leaves the best height/hash unchanged. Repeating the identical range after such a response is a liveness bug unless the retry state changes toward ancestor discovery or another peer.

## Plan of Work

First, record live facts without changing either host. Resolve actual systemd units, command lines, listeners, and loopback RPC ports before querying status. Capture best and target heights, canonical hashes around the suspected fork, miner/sync status, process RSS/PSS/private-anonymous accounting, cgroup or kernel OOM events, restart times, and narrowly filtered sync logs. Treat those measurements as pre-fix operational evidence only.

Second, trace mining ancestry needs field by field. Difficulty validation exact-verifies the stored parent, walks at most `RETARGET_WINDOW - 1` stored ancestors when the schedule requires them, and binds the canonical parent and reached anchor to their height-index rows. Header-MMR construction reuses validated canonical MMR peaks rather than reconstructing historical metadata. Keep those bounds explicit and fail closed if the persisted canonical parent/ancestry/index binding or derived peak shape is inconsistent. Compare the affected `pow_bits`, header-MMR root/length, and prepared header preimage with the legacy algorithm over deterministic normal, retarget-boundary, reopen, and fork fixtures.

Third, drive the sync response path through a deterministic fork fixture where the requested ahead range is already stored on a noncanonical branch or cannot connect to the canonical tip. Record whether import reports all-known, no canonical progress, missing ancestor, or failed reorg. Make the next request depend on canonical progress and common-ancestor evidence. Ensure retries backfill or switch peers and that decoded response bodies and queued work remain bounded by existing caps.

Fourth, add structural regressions. The mining regression crosses retarget boundaries, invokes work preparation/status/mined revalidation, and proves the metadata decode/read count is independent of total fixture height except for the explicitly required bounded window; it separately verifies the affected header fields against the legacy full-history oracle. The sync regression feeds the exact 64-block child-only range and proves the next scheduling decision changes toward a common ancestor instead of issuing the identical unproductive range forever. Response-serving regressions prove the legacy loader stops at a wire prefix and inspects no more than one additional block, while a capacity regression proves the global two-worker cap. Chunk regressions pin legacy ordinals 0 through 3 byte-for-byte, exercise appended ordinals 4 through 6 and a valid record requiring more than four authenticated chunks, require invalid request/chunk floods to consume zero workers, release retained sessions on idle/hard expiry, failover, and exact close, and reject malformed schema, digest, noncontiguous order/offset, oversized chunk, and oversized total before common import. They also prove that `AnnounceTip` and partial chunks neither import nor open the mining gate. Existing fork, reorg, import, PoW, and publication equivalence tests must continue to pass.

Finally, validate with focused tests, the full native-node library suite, repository lint/test/build, release build, dependency audit, and applicable formal/conformance gates. Use separate controlled evidence for (a) fork behavior in storage-backed production helpers, (b) two-process peer liveness/restart behavior, and (c) final release-binary height/RSS behavior; do not describe any one of these as proving the others. Update documentation and open a PR with exact evidence plus a staged rollout plan: one node at a time, health/memory/tip/hash gates, no database wipe, an explicit rollback binary/config, and no simultaneous miner restart.

## Concrete Steps

Run all repository commands from `/Users/pldd/.codex/worktrees/e2ee/Hegemon`.

Run the exact focused and broad gates recorded by the branch:

    ./scripts/check_native_node_memory_sync_recovery.sh --structural-only
    cargo test -p hegemon-node --lib
    cargo test -p network wire::tests::codec
    cargo fmt --all -- --check
    ./scripts/check-core.sh lint
    ./scripts/check-core.sh test
    ./scripts/check-core.sh build
    make node
    ./scripts/dependency-audit-gate.sh
    bash scripts/check_formal_core.sh

Run controlled local scenarios only with the final release binary, isolated base paths, and alternate loopback ports:

    HEGEMON_NODE_BIN=/absolute/path/to/target/release/hegemon-node scripts/test-node.sh devnet-liveness
    HEGEMON_NODE_BIN=/absolute/path/to/target/release/hegemon-node scripts/test-node.sh two-node-restart
    ./scripts/check_native_node_memory_sync_recovery.sh --pid <verified-pid> --rpc-url http://127.0.0.1:<isolated-port> --output <csv> --max-rss-growth-kib <precommitted-limit> --max-rss-envelope-kib <precommitted-limit>

Final results:

- Structural/focused: `bash scripts/check_native_node_memory_sync_recovery.sh --structural-only` passed all 80 selected regressions. The final RSS invocation reran the same 80 before sampling. This includes mining reconstruction, bounded retarget ancestry, compact RPC/startup/reorg ownership, 64-block missing-parent/all-known/mixed connector recovery, chunk framing/session/resource admission, durable target authority, cooldown, and failover coverage.
- Full native/network: the uninterrupted `./scripts/check-core.sh test` passed the complete workspace suites, `cargo test -p hegemon-node --lib` at 513 passed / 0 failed, the no-default native configuration at 513 passed / 0 failed, the end-to-end adversarial security pipeline, and the release manifest/profile negative tests. Network wire/PQ transport tests and generated vectors passed within the same command.
- Formatting/repository lint-test-build/release: `cargo fmt --all -- --check`, `git diff --check`, and shell syntax checks passed; `./scripts/check-core.sh lint`, `./scripts/check-core.sh test`, `./scripts/check-core.sh build`, and `make node` passed. The release artifact manifest is `target/release/hegemon-release-artifacts.json`; the 10,362,784-byte Mach-O `target/release/hegemon-node` SHA-256 is `160682c2c083d6b26f625b361b4beaef42f3a742341719f662fe6ae3327a02a3`.
- Dependency/formal/conformance: `bash scripts/check_formal_core.sh` passed all 14 phases, including the 2,763-theorem Lean build, generated Rust vectors, 123-claim ledger, 123-node blueprint DAG, independent bridge/native backend vectors, release posture, and explicit non-claim of a model-checker run. `bash scripts/dependency-audit-gate.sh` failed with 7 total / 4 waived / 3 unwaived findings: `RUSTSEC-2026-0258` (`h2 0.4.15`), `RUSTSEC-2026-0253` (`lru 0.7.8`), and yanked `chacha20 0.10.1`. The lockfile/manifests are unchanged from `main`; traced Hegemon DA code uses Reed-Solomon encoding and does not reach the vulnerable `LruCache::pop()` panic path. Remediation remains a separate dependency-scoped change.
- Two-process liveness/restart: with `HEGEMON_SEEDS=""`, isolated bases `/private/tmp/hegemon-final-live-{a,b}`, RPC 21945/21946, P2P 32333/32334, and the final release binary, `scripts/test-node.sh devnet-liveness` advanced miner/follower from 5 to 17, produced 12 blocks in 7 seconds, observed a 2-second maximum gap, and reported hash rate 1,799,668.7487. `scripts/test-node.sh two-node-restart` persisted follower height 3, restarted it, and caught both processes up to height 15.
- Final release-binary RSS/progress: PID 37136 was matched to the exact release command and `127.0.0.1:21947` listener. `scripts/check_native_node_memory_sync_recovery.sh` used 12 warm-up plus 45 measured two-second samples, five status polls per sample, minimum height gain 1, and 256 MiB RSS growth/envelope limits. It passed with height 39 to 42, RSS 35,536 to 35,616 KiB, and 80 KiB growth/envelope. CSV: `/private/tmp/hegemon-final-rss-20260831.csv`; JSON: `/private/tmp/hegemon-final-rss-20260831.json`. macOS did not provide Linux anonymous-RSS/HWM fields; the sampler does not prove heap reachability or allocator behavior. The exact process was stopped and RPC/P2P ports 21947/32335 were verified closed.

The controlled multi-node run must use temporary base paths and alternate local ports. Shared miners must use the approved seeds `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless deliberately isolated for the fork fixture, and mining hosts must have NTP or chrony enabled because future-skewed PoW timestamps are rejected.

## Validation and Acceptance

Acceptance requires a test that fails on `main` because work preparation reads/decodes ancestry proportional to chain height, then passes with a documented constant or retarget-window bound for metadata reads. The affected work fields—`pow_bits`, header-MMR root/length, parent identity, and prepared header preimage—must match the legacy result across representative normal, retarget-boundary, reopen, and fork fixtures. Existing replay/commitment suites remain responsible for state and action-root behavior; this optimization must not claim a new independent oracle for fields it does not recompute.

Acceptance also requires a deterministic same-range fork regression that fails on `main`, proves no canonical progress after the first child-only response, and proves the fixed scheduler changes range, finds the parent, and can advance canonically. Outbound legacy serving must stop loading at the retained wire prefix plus at most one candidate, with no more than two response builders globally. The oversized-record path must require a prior peer-bound offer and matching empty response, transfer a valid record in more than four authenticated 4 MiB chunks under the record maximum, enforce at most one session per direction per peer and two sessions globally plus a separate receive-worker cap of one per peer and two globally, permit a symmetric peer pair to transfer and close in both directions without collision, expire at 30 seconds idle or 120 seconds hard lifetime, exact-decode only the advertised schema after domain-bound digest and contiguous-reassembly checks, and enter the common legacy-response import path only after completion. Old ordinals must retain their bytes; appended variants must be tested as the explicit mixed-version boundary. Separately, a controlled final-binary node must advance while its sampled RSS stays within precommitted growth/envelope limits, and two real local processes must demonstrate peer liveness/restart recovery. Those process runs do not need to reproduce the synthetic fork and must not be presented as a live-depth reorganization measurement or a proof that the record cap bounds RSS.

The relevant existing native node, fork/reorg, PoW, codec/publication, formal-core, formatting, and release-build gates must pass. The PR must state what was measured, what was inferred from source, whether any retained live-object leak was actually confirmed, and why consensus compatibility is preserved.

## Idempotence and Recovery

All reproduction databases and node runs use temporary directories and non-live ports. Tests may be rerun without touching operator data. If a controlled process exits unexpectedly, preserve its logs and measurements, terminate only that test process, and remove only its explicitly recorded temporary directory after evidence has been extracted.

The implementation must not require wiping either live database. The later rollout plan should deploy to one node, retain the previous binary, compare canonical hashes and progress, and roll back the binary without database downgrade if any consensus, memory, or sync gate fails.

## Authorized Rollout and Rollback Plan

This section is a proposal for a later explicitly authorized maintenance window. Nothing in this task authorizes executing it.

1. Build the exact reviewed commit, record the binary SHA-256, service unit/config, active ports, database path, approved seeds, and current canonical height/hash on each host. Configure `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless the approved list has deliberately rotated; every miner must use the same list. Verify NTP or chrony is synchronized before mining because future-skewed PoW timestamps reject.
2. Stage the prior binary and config as the rollback pair. During an authorized stop, take a consistent offline database snapshot before replacing anything; do not copy a live sled database as if it were a consistent backup, and do not delete or reinitialize operator data.
3. Before canarying `hegemon-dev` while `hegemon-ovh` remains on the old binary, inspect every record in the required catch-up/reorg span. Proceed only if each fits the legacy 16 MiB encrypted frame or if an independently upgraded relay can serve the required records. The rolling extension has no capability negotiation, and a record above the cap requires upgraded endpoints on both sides of that transfer; upgrading dev alone cannot make old OVH understand chunk requests. Then canary dev first because it is already stalled and has more immediate memory headroom. Do not touch OVH while the canary is running. After a 10-minute warm-up, require canonical progress at least once in each five-minute window, no unresolved identical no-progress range more than three times in 60 seconds, mining gate behavior consistent with sync state, the expected canonical hash at shared heights, no OOM/restart, RSS below 75% of host RAM, and RSS growth/envelope below 512 MiB over each 15-minute observation window. Keep the canary under observation through catch-up and at least 60 minutes of stable tip tracking before proceeding.
4. Only after dev passes, canary `hegemon-ovh` with the same gates, one node at a time. Confirm at least 4 GiB of available memory before starting the candidate or postpone the rollout; its pre-fix headroom is too small for a safe in-place assumption. Compare canonical hashes against the healthy peer and an independent RPC observation at several shared heights before restoring ordinary mining responsibility.
5. Abort and roll back on hash divergence, no progress for 10 minutes while responsive peers advertise a higher valid target, repeated identical no-progress requests above the limit, RSS growth greater than 512 MiB in 15 minutes after warm-up, RSS above 80% of host RAM, an OOM/restart, database/open error, or a consensus/import/formalized invariant failure. Stop only the affected node, restore the staged binary/config, and reopen the same database. If the database fails integrity/open checks, keep the service stopped and restore the offline snapshot; never wipe the database to force apparent recovery.
6. After rollback, capture logs, binary/config hashes, height/hash, and memory samples. Do not attempt the second host until the failure has been explained and a new candidate has passed the full gates.

## Artifacts and Notes

Pre-fix live evidence, deterministic failure transcripts, read/decode counters, process-memory samples, and test results are summarized in this plan and the pull request. Raw host logs containing unrelated information are not committed. The reusable structural/RSS gate is `scripts/check_native_node_memory_sync_recovery.sh`; the sampler is `scripts/measure_native_node_memory.py`.

## Interfaces and Dependencies

Implementation surfaces are storage-level bounded ancestry/header accessors in `node/src/native/storage.rs`, mining/reorg/startup callers and the streaming response loader in `node/src/native/node_impl.rs`, progress-aware scheduling, chunk-session admission, response-budget accounting, and common import handoff in `node/src/native/service.rs`, sync message/state/capacity types in `node/src/native/mod.rs`, and exact bounded codec sizing in `network/src/wire.rs`. Existing `NativeBlockMeta`, `NativeBlock`, compact-target, header-MMR, fork-choice, legacy sync ordinals 0 through 3, and sled schema formats remain unchanged. The sync wire is deliberately extended at ordinals 4 through 6 without capability negotiation; mixed-version peers can use only legacy variants, and oversized records require both endpoints to upgrade. If final diff review finds any additional schema or consensus-visible change, stop and revise this plan rather than smuggling it into a performance patch.

Revision note (2026-08-30 / Codex): Created this plan from the clean `main` baseline after the initial source and documentation survey. It records the no-deploy boundary, strict memory claim taxonomy, and the two required regression targets.

Revision note (2026-08-30 / Codex): Recorded the implemented mining/sync/reorg bounds, development-test evidence, measured live symptoms, and residual chain/output-sized reorg ownership before final gates and PR creation.

Revision note (2026-08-31 / Codex): Added the startup one-snapshot consolidation, exact chain-load/decode counter evidence, unchanged fail-closed ordering, and the remaining chain-sized startup/action-replay boundaries.

Revision note (2026-08-31 / Codex): Added exact in-flight/cooldown state, branch-bound deep/equal-height recovery, aggregate side-page persistence, formal batch coverage, stale candidate-cache invalidation, and their residual claim boundaries.

Revision note (2026-08-31 / Codex): Added incremental outbound wire-prefix loading, exact allocation-free sizing, the global two-worker cap, milestone/final-result placeholders, corrected controlled-fixture boundaries, and an authorization-gated staged rollout/rollback plan.

Revision note (2026-08-31 / Codex): Recorded the append-only chunk/compact-tip wire extension, explicit mixed-version boundary, peer-offered oversized-record fallback, session/worker/lifetime and completion-ownership bounds, generalized unverified-target cooldown, focused regression matrix, and corrected bounded stored-parent retarget ancestry wording.

Revision note (2026-08-31 / Codex): Removed full-chain block-record serialization and transaction-overlay cloning from canonical reorganization. The reorg now flushes only the validated unknown content-addressed suffix, treats those durable rows as the canonical-commit precondition, writes zero block rows in the canonical transaction, and preserves retryability across the prestorage crash window.

Revision note (2026-08-31 / Codex): Reconciled the final source contracts for mixed known/missing response classification, durable post-import target authority, body-streaming reorganization residuals, scalar RPC tip reads, measured live database sizes, and the legacy-frame preflight required before a one-node mixed-version canary.

Revision note (2026-08-31 / Codex): Recorded the uninterrupted final Rust/formal gates, disclosed dependency-audit baseline failure, exact release binary/manifest identity, isolated two-node liveness/restart results, explicit-PID RSS/progress evidence, sampler shutdown verification, and remaining PR-publication step.

Revision note (2026-08-31 / Codex): Recorded successful publication and readback of PR #203 against `main`, while preserving the no-merge, no-deploy, and no-live-restart boundary.
