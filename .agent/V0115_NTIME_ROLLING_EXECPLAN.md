# Ship bounded ASIC time rolling in v0.11.5

This living ExecPlan follows `.agent/PLANS.md`. Keep Progress, discoveries, decisions and outcomes current.

## Purpose / Big Picture


ASIC miners may change the four-byte `nTime` seconds field of their Bitcoin-shaped work header. At present Hegemon also commits the suggested timestamp inside its mining coinbase, so merely allowing a different submitted field cannot produce the same native block hash. Release v0.11.5 adds a height-selected consensus profile that commits time in the final proof-of-work header and allows any whole-second timestamp strictly after the parent and no more than 90 seconds beyond the receiving node's clock. Before activation, existing fixed-time work and every historical hash remain unchanged. A successful test must solve work with a timestamp both before and after the job suggestion and import exactly that timestamp.

The intended pre-mainnet activation is H28,860, aimed at Friday November 20, 2026 around 09:00 Calgary (UTC-6). Height governs activation; wall-clock timing is an estimate. The user subsequently authorized complete release preparation and finalization with every required CI test passing. Prepare immutable four-platform artifacts and a reviewable ready PR, while keeping tags, GitHub releases, deployment and announcements untouched.

## Progress


- [x] (2026-11-14 01:10Z) Inspected current v0.11.4 network source, prior ASIC discussion, native timestamp checks and canonical hash construction.
- [x] (2026-11-14 01:10Z) Created isolated worktree and `codex/v0.11.5-ntime-rolling` from network maintenance commit `ad77c8d564944972b6ae5e7cab26fcf500972aff`; preserved the unrelated primary workspace.
- [x] (2026-11-14 01:10Z) Obtained live H19,354 and recent timestamp evidence; selected H28,860 for the proposed Friday morning activation.
- [x] (2026-11-14 01:22Z) Added consensus profile and seven new consensus tests; both 72-unit/1-integration suites and no-std check passed.
- [x] (2026-11-14 01:22Z) Implemented native RPC/admission and Stratum reconstruction; adapter suite passed 59 tests. Native optimized qualification remains below.
- [x] (2026-11-14 01:22Z) Updated product label/launcher, protocol/operator docs, source-preparation checker and focused CI. Source gate and 11 mutation tests passed; launcher tests passed with one platform skip.
- [x] (2026-11-14 01:44Z) Completed affected native suites: ASIC 9, timestamp 10, ASERT 5, treasury 4 (1 existing ignored), ordinary production bounds 3.
- [x] (2026-11-14 01:44Z) Independent source review found no correctness defect; draft PR #212 opened.
- [x] (2026-11-14 01:44Z) Reproduced both sync failures on exact unchanged base and PR head; isolated HTTP test passed on both. Recorded all readiness blockers without changing unrelated code or authority.

- [x] (2026-11-14) Expanded authorized scope from source PR to full unpublished release preparation; split fresh artifact qualification, packaging, dependency reachability and final review into owned parallel lanes.
- [x] (2026-11-14) Reconciled the two sync qualification fixtures with the existing anti-pinning design and synchronized the HTTP capacity test with actual blocking-worker start; full minimal native library suite passed 1,017 tests (12 existing ignored).
- [x] (2026-11-14) Full default native suite passed 1,017 tests (12 existing ignored); dependency guard passed all 12 actual release graphs and 27 negative controls.
- [x] (2026-11-14 17:22Z) Initial frozen source `1bcfa01` passed all 22 Monorepo push jobs, the PR workflow with two expected Lean/vector skips, and all three focused nTime jobs.
- [x] (2026-11-14 18:29Z) Initial preparation passed shared policy, proof authorization, security, app and the full Linux job. Windows final proof qualification failed with `cannot assign owned job`; retained the failed-attempt evidence without accepting artifacts.
- [ ] Complete the additive Windows contained-process executor and native regression controls, independently review it, then refreeze source and rerun every required CI lane.
- [ ] Complete additive v0.11.5 final-artifact qualification and four-platform preparation workflow.
- [ ] Freeze source, complete independent delta reviews and renew only truthful internal review bindings; run complete formal/crypto and all required release CI.
- [ ] Download qualified artifacts, verify all four final receipts and deterministic archives, record accepted preparation profile, and mark PR ready without publishing.

## Surprises & Discoveries


The active source is ahead of `main`: v0.11.4 plus sync recovery is on `codex/sync-recovery-current-network-20261110`. The PR must initially stack on that branch to avoid presenting earlier releases as this change. `Cargo.lock` is a transaction-proof relation input, so a product release label must not be implemented by changing internal crate versions or lockfile bytes.

Timestamp is currently bound twice: canonical V2 mining prehash and final 80-byte proof-of-work header. Removing a Stratum equality check alone would admit shares that native consensus reconstructs differently. The new profile therefore normalizes timestamp only in its mining prehash and requires exact whole-second native timestamps. Old rules retain their full-millisecond prehash.

Normal CI initially rejected the new label through its historical v0.11.4 formatting/artifact policy. The additive v0.11.5 formatting checker now retains only the original 38 debt paths when byte-identical to the immutable ad77c8d predecessor; it grants no changed-file exemptions or release authority. The changed node implementation was formatted instead of adding an exception. Dependency audit separately reports four inherited lockfile advisories, recorded in release preparation; the exact lock must remain unchanged because it is a proof-relation input. Read-only triage found the affected crates absent from the resolved release graphs. A short-lived exception may be accepted only after a new fail-closed reachability guard verifies every exact packaged graph, including Windows; a missing graph or activated vulnerable crate must block.

The first four-platform attempt found a Windows process-harness failure after its release build and manifest checks passed. The immutable proof runner starts a child before assigning its Windows job and discards the API error code. Fast exit and inherited-job restrictions cannot be distinguished from that log. Preserve the failed attempt and the proof predicates; require creation-time containment, explicit Win32 errors and actual native Windows lifecycle tests in the additive v0.11.5 executor.

The network only has about seven hours of post-ASERT history at planning time, with a hashpower burst. A week-long extrapolation of its recent 33–52 second intervals is unsuitable; the height estimate uses the 60-second target and records timing uncertainty.

## Decision Log


On November 14 the coordinator selected an additive, source-owned profile rather than changing existing rule hashes. New rules inherit the v0.11.4 version mask, reward cadence and original ASERT anchor; neither retarget reference nor treasury batching restarts at H28,860. Rehearsal activates combined rules at H120 and time rolling at H180, only for the existing dedicated rehearsal chain identity.

The accepted minimum is `floor(parent_timestamp_ms / 1000) + 1`. This is strictly after the parent even if the parent contains fractional seconds. The maximum is `floor((admission_now_ms + 90000) / 1000)`, capped at u32. Submitted seconds reconstruct exactly `ntime * 1000` milliseconds. The node rechecks its clock at final admission. Historical replay uses stored header rules and parent ordering, without applying today's clock.

RPC range fields are snapshots of node time, not extensions to the job lifetime. The adapter advances its observed node clock using monotonic elapsed time, refreshes it on work polls, and never treats a refreshed range as a new 120-second job. Final node admission is authoritative.

H28,860 was chosen from a November 14 01:07 UTC snapshot at H19,354. At 60 seconds per block it projects to November 20 09:31 Calgary; a conditional stable-hash ASERT model gives about 08:54. Refresh the forecast near source freeze without changing an already announced activation unilaterally.

The user expanded the scope on November 14 to finalize an unpublished release with all required CI passing. The stale sync tests assumed that unverified hints could replace a fresh live target, contradicting the accepted anti-pinning design. The runtime remains unchanged; revised tests exercise fresh lease protection, legitimate expiry/release, old completion isolation and real import. The HTTP test race came from treating reserved body-collection slots as proof that blocking workers had started; a per-node bounded test observer now establishes that precondition.

The November 14 16:07 UTC public status refresh reported H20,217 and a tip time of 16:04:25.567 UTC. Target-cadence projection now gives Friday November 20 10:07 Calgary, still within the requested morning. Retain H28,860; no fixed wall-clock activation is claimed.

The Windows failure explicitly unfreezes the first candidate for a scoped qualification-harness fix. `check_v0115_current_binary_proofs.py` loads the hash-checked immutable proof executor and changes only process execution through `v0115_process_ownership.py`, with mandatory new harness attribution and source snapshots. Windows processes must enter their kill-on-close job before any child code executes; the retained suspended primary thread resumes only after membership checks. Exact stdio inheritance, bounded output/deadlines, descendant accounting and failure cleanup remain mandatory. The fast Windows regression job runs independently of expensive builds, and preparation repeats it before building. No proof input, protocol behavior or authority flag changes.

## Outcomes & Retrospective


The earlier source-PR milestone is complete; the expanded unpublished-release milestone remains active. Source implementation, independent review and affected native execution qualification are complete. Draft PR #212 is open; release readiness also requires resolving the inherited dependency-audit findings. Physical ASIC/MRR acceptance remains distinct from software tests; no physical-hardware success is claimed by this PR. Release packaging is now authorized and in progress; production authorization, deployment and publication remain separate. The earlier source PR objective was complete: bounded rolling and its RPC/adapter contract are implemented, the affected suites passed and the reviewable draft is open. The initial draft recorded inherited dependency/sync blockers, the full-suite HTTP race and stale review bindings. The expanded preparation now resolves those specific failures with scoped fixes and fresh evidence; complete CI and accepted packaging still determine release readiness.

## Context and Orientation


`consensus-light-client/src/pow_rules.rs` owns chain/height rule selection and Bitcoin80 target/version helpers. `consensus-light-client/src/lib.rs` owns canonical metadata, mining prehash and validation. The synthetic mining coinbase commits the metadata hash; its hash occupies the final header's Merkle-root field. `node/src/native/asic_mining.rs` retains prepared block snapshots and exposes them through `hegemon_poolWork`, then verifies and imports submitted network-target solutions. `node/src/native/timestamp_admission.rs` owns fresh node-clock checks. Other native files reconstruct headers during import, sync, restart and reorg.

`scripts/bitcoin_asic_stratum.py` turns native jobs into Stratum V1 messages and independently hashes miner submissions. A job's expiry is measured with a monotonic clock, which measures elapsed time without being moved by NTP corrections. `protocol/versioning/src/lib.rs` supplies the displayed product version independently of internal Cargo package versions. `config/ntime-rolling-v0115.json` records the source schedule and planning estimate. `scripts/check_ntime_rolling_source.py` compares those declarations to source and checks unchanged proof inputs; it does not execute behavior or grant artifact authority. Its 11 mutation tests and `.github/workflows/ntime-rolling.yml` provide focused source, adapter, consensus and native CI. DESIGN and METHODS describe the native proof boundary and ASIC contract.

## Plan of Work


First add the new profile and derive its BLAKE3 digest from an explicit preimage. Add a second activation field to the schedule without changing old constructors. Normalize only valid version commitment and timestamp in the new profile's prehash; enforce whole seconds and u32 seconds. Cover old/new rules and H-1/H/H+1 through direct tests.

Next make native prepared work use exact whole seconds under the new profile. Report `ntime_rolling`, `ntime_activation_height`, `min_ntime`, `max_ntime`, `server_time` and `max_future_skew_seconds` from the node. On submission, validate the range against a fresh clock, hash the exact submitted seconds and import a cloned work snapshot carrying that same timestamp. Revalidate time-dependent block content through normal import rather than mutating a cached template. Audit exact comparisons against the combined rules hash so the inherited ASERT, version and treasury behavior remains active.

Update the adapter to accept range metadata, fall back to fixed time if fields are absent, hash the submitted seconds and forward them unchanged. Same-job range refresh changes only range observations and cannot extend expiry. Existing target accounting, duplicate suppression, version rolling and busy retry behavior remain covered by regression tests.

Finally set the product label to 0.11.5, allow exactly matching launcher metadata, document the protocol and activation estimate, run focused and regression tests, inspect the final patch independently and open a scoped PR against the current-network base branch.

## Unpublished release preparation milestone


Add `scripts/check_ntime_rolling_candidate.py` and its source-owned frozen configuration independently of historical v0.11.4 authority. The checker must bind the finite source inventory and independent internal review, preserve all 41 proof relation inputs, and execute fresh final-binary proof verification and a disposable height-zero node identity test. Its time-rolling lifecycle producer must execute the affected consensus, adapter, native time/ASERT/treasury and sync regression suites, reject zero-test filters, and bind every receipt to the actual four-binary artifact manifest. Reusing a low-level executor is permitted; reusing a historical pass as a new binary pass is not.

Add `scripts/prepare_v0115_release.py` to generate the existing nine-job, read-only preparation workflow with the new candidate and formatting routes. Keep the historical generators unchanged. Add `scripts/package_v0115_release.py` and a pending `config/v0115-release-artifacts.json` profile. The pending profile cannot package a release. A successful exact-commit non-PR preparation run must produce ordinary node, wallet, walletd and private-spend binaries on Linux, Intel macOS, ARM macOS and Windows; four final-proof/H0/lifecycle receipts must independently match those bytes. Only the accepted artifact profile may change after that successful build source is frozen. Deterministic archives and checksums are retained as GitHub Actions artifacts and copied into a newly created directory under the primary workspace target/releases/ for durable local handoff, with no tag or GitHub Release creation. Raw ZIP SHA-256 values from the run artifacts API bind the supplied manifests and final receipts to the exact successful run.

Preserve the root lock. Resolve the four inherited advisories through exact expiring policy exceptions only if `scripts/check_release_dependency_reachability.py` successfully resolves all four target triples and all three packaging package/feature selections and proves affected crates absent from normal and build dependencies. The guard pins the packaging script, relevant manifests, unchanged lock and its own implementation; a changed build selection or new advisory cannot borrow the exception. Retain source-grounded upstream triage and patched-version remediation.

After code and workflow changes stabilize, independently review the entire inherited delta since `5c1d278`, including the new tests and audit/packaging routes. Update review dates, notes and exact content hashes only for actually reviewed scopes; keep all 122 external-review statuses pending and every production/hardware/activation authority false. Execute the pinned 14-test governance recipe before renewing its fingerprints in dependency order. Then run full formal-core Lean/vector/policy and formal-crypto CI, all ordinary Monorepo prerequisites, focused time-rolling CI and four-platform release preparation. Any failing or skipped required check remains work to resolve.

## Concrete Steps


All commands below run from the isolated worktree `/private/tmp/hegemon-v0115-ntime-20261113`. Use one compiler coordinator; consensus tests use `/private/tmp/hegemon-v0115-consensus-build` and native builds use `/private/tmp/hegemon-v0115-build`. Keep build jobs at two after the consensus lane finishes, disable incremental compilation and check free disk before a node build. Leave at least 5 GiB free; do not delete retained user artifacts.

    CARGO_TARGET_DIR=/private/tmp/hegemon-v0115-consensus-build CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test --locked -p consensus-light-client
    CARGO_TARGET_DIR=/private/tmp/hegemon-v0115-consensus-build CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test --locked -p consensus-light-client --features combined-upgrade-rehearsal
    python3 -I -B scripts/test_bitcoin_asic_stratum.py
    python3 -B scripts/test_package_v011_release.py
    CARGO_TARGET_DIR=/private/tmp/hegemon-v0115-build CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test --locked -p hegemon-node --no-default-features --features development-candidate,combined-upgrade-rehearsal,asert-rehearsal,wallet/rpc-client,wallet/private-spend-dev-artifacts --lib time_rolling

Native qualification additionally uses `CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_OPT_LEVEL=2`, matching the existing CI optimization of expensive circuit loops. An initial unoptimized lifecycle run was stopped after sustained CPU work; it was not recorded as a pass. The rehearsal suite requires the existing Development candidate and wallet test features listed above.

Record actual results here before completing the plan. A compilation failure or skipped suite is not a pass. Run the broader affected native tests after the focused suite and record any bounded resource limitation.

## Validation and Acceptance


Old fixtures and preactivation headers must produce identical hashes; the new profile must reject subsecond native timestamps, wrong profile commitments and u32 overflow. Boundary tests must select old rules at H28,859 and new rules at H28,860/28,861. Rehearsal must retain its ASERT H120 reference across H180.

Native and adapter tests must accept solved headers at suggested time minus 60 seconds and plus 70 seconds when inside the actual parent/clock range, persist the submitted timestamp and reject parent equality, future bound plus one second and fixed-time changes before activation. Refreshing max time cannot reset job expiry. Node clock rollback must tighten fresh admission without rewriting already issued work; historical replay must remain independent of the current clock. Existing version rolling, extranonce and duplicate/retry tests must pass.

Review the complete diff for accidental Cargo.lock, proof-format, chain identity, reward amount or original anchor changes. Preserve the original package/proof identity and do not reuse v0.11.4 release receipts as authority for new binaries. Local software evidence does not establish physical ASIC compatibility or release authorization.

## Idempotence and Recovery


Tests use temporary directories and disposable chain state. Re-running them must not touch live nodes or wallets. Git changes live only in the isolated branch; a failed build can be resumed in its assigned target directory. Keep diagnostic logs and report the exact failure instead of deleting existing state. Activation is a consensus split after H28,860; operators must update before that height once a release is separately approved.

## Artifacts and Notes


Planning source snapshot: network maintenance `ad77c8d564944972b6ae5e7cab26fcf500972aff`, descendant of v0.11.4 `3fbf18ffec5b104766f5fefc2e515c8059a24c80`. Public network identity: genesis `d9a8cfc158790b0251c7493d7261da771f7d57be63bce750ba8c1af5d92a9ad3`, chain ID `7b7b0899d5444ffd92c38b38188e9ce4f891913ca7cca854fdcae0aa22ca1b49`. H18,660 activated combined rules on November 13 17:50:51.572 UTC. Planning observations are retained in `/private/tmp/hegemon-v0115-activation` and summarized in the checked-in protocol specification.

## Interfaces and Dependencies


Consensus exports `HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING`, `is_time_rolling_rules(&Hash32)`, `is_combined_rules(&Hash32)`, `native_time_rolling_activation_height(&Hash32) -> Option<u64>`, `native_time_rolling_active(&Hash32, u64) -> bool` and `bitcoin80_validate_timestamp_for_rules(&Hash32, u64) -> Result<u32, LightClientError>`. `PowRulesSchedule::combined_with_time_rolling_at(combined_height, time_height)` preserves the old constructor's behavior while adding the later profile.

RPC time fields are eight-character lowercase hexadecimal seconds. Activation height is numeric or null; `ntime_rolling` is boolean; future skew is numeric seconds. Before activation `min_ntime == max_ntime == ntime`. Absent fields mean fixed-time compatibility to old nodes. New code uses existing BLAKE3/SHA256 libraries and adds no dependencies.

Revision November 14, 2026: initial implementation plan records the live-network base, H28,860 estimate and exact consensus/RPC boundary before integration.

Revision November 14, 2026: recorded source completion, exact consensus/adapter/source-gate results, source-only CI, required rehearsal wallet features and optimized test profile after an unoptimized execution was stopped.

Revision November 14, 2026: recorded draft PR #212, native ASIC (9) and timestamp (10) test passes, strict successor formatting integration, and the inherited dependency-audit release blocker. ASERT regression execution explicitly enables its own rehearsal feature to prevent an empty test filter.

Revision November 14, 2026: recorded completed native execution, final strict formatting, fresh governance execution and unchanged review-binding blockers. Broader CI baseline diagnosis completed: two identical failures reproduce on the base, while the HTTP case passes in isolation on both sources. No unrelated sync/RPC fix, dependency waiver, proof requalification or production-review refresh is included.

Revision November 14, 2026: completed baseline comparison and source-preparation outcome; retained draft status and explicit unresolved release/CI boundaries. All focused local tests, formatting and unchanged proof-input checks passed.

Revision November 14, 2026: expanded the plan for the user-authorized unpublished release, recorded the 1,017-test minimal suite pass and concrete sync/HTTP diagnoses, and specified fresh source/artifact qualification, guarded dependency exceptions, four-platform packaging and exact-head CI acceptance.
