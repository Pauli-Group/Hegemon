# Prepare the pre-mainnet ASERT consensus upgrade

This ExecPlan is maintained under `.agent/PLANS.md`. The implementation branch is `codex/asert-activation`, based on main `74910ff865`. It prepares a coordinated upgrade; publication, deployment and selection of the live activation height are separate actions.

## Purpose / Big Picture

Replace the ten-block difficulty controller with ASERT, an integer exponential controller evaluated after every completed block. Keep the existing chain, genesis, wallets, transaction proofs, reward rules and 60-second block interval. The pre-mainnet candidate half-life is one hour: a one-hour schedule lag doubles the target (halves difficulty). ASERT does not lower a target during an ongoing blockless gap. It includes no emergency reset or merged mining.

## Progress

- [x] (2026-10-29) Read current release implementation and rollout requirements; isolate implementation on a local branch without modifying the release commit.
- [x] (2026-10-29) Implement exact reference arithmetic; all 14,000 imported BCH reference vectors match.
- [x] (2026-10-29) Add deterministic per-chain height activation and header rules transition while preserving frozen genesis and wallet pins.
- [x] (2026-10-29) Integrate native authoring, import, sync, historical replay, restart and branch-specific anchor resolution.
- [x] (2026-10-29) Exercise arithmetic, activation, rejected targets/rules, reorganization and restart; compare bounded half-life scenarios.
- [x] (2026-10-29) Bound cold ASERT ancestor lookup to 128 links per call with two 256-entry caches; retain exact work ownership and requeue fairly. The 540-block cold-history and service ownership regressions pass.
- [x] (2026-10-29) Refresh 86 source-bound governance records without changing needs_review, theorem statements or authorization. Final claims, blueprint, active-goal policy and system-assumptions checks pass.
- [x] (2026-10-29) Update design, methods, consensus specification, CI and release prerequisites; retain commands, selected source hashes and log hashes in docs/consensus/asert-validation.json.

## Surprises & Discoveries

A final source review found that cold cache misses walked all the way to activation before invalid announcements rejected. Descending historical parent requests evaded the 256 completed-cache entries. The correction uses bounded resumable lookup and a distinct local deferral; it must not impose a consensus ancestry cutoff or label a valid deep fork invalid.

The genesis manifest commits the original rules hash and derives the chain ID. Replacing the global rules constant would create a different network and invalidate wallets. The header hash function also selects the ASIC envelope by rules hash; both the old and new header profiles must use that envelope. Native sync may validate a suffix before its blocks reach storage, so anchors must resolve through the validated batch as well as persisted parent links.

## Decision Log

On 2026-10-29, choose a bounded resumable cold-lookup path instead of trusting an unauthenticated canonical index or imposing a maximum consensus fork depth. Keep exact parent and resume cursor checks, anchor rereads, and the separate canonical-index check. A local scheduling delay must release the network work slot and preserve retryable work.

Use BCH ASERT's fixed-point polynomial, with integer units in milliseconds and Bitcoin positive compact encoding. The reference block is H-1, the last old-rule block. Its target and height and the timestamp of H-2 define the anchor. The first new block at H therefore accounts for the final old-rule solve interval. This follows the reference convention and avoids an off-by-one block interval.

Preserve the original genesis rules constant and manifest bytes. Select the new header rules by chain ID and height, independently of the frozen manifest. The pre-mainnet activation height remains `None` until release coordination. Add an explicit development rehearsal build feature that activates only the legacy development chain at height 20, allowing complete native lifecycle testing without enabling anything on the pre-mainnet chain. No operator environment or CLI flag may silently select a different production activation.

Use one shared fixed-width no_std arithmetic implementation in `consensus-light-client`, so native validators and light clients can use identical arithmetic. Keep the old consensus schedule and its formal vectors unchanged for historical blocks. Existing transaction-proof evidence remains outside this PoW-only delta.

## Outcomes & Retrospective

Implementation preparation is complete. The ASERT arithmetic, source-owned height schedule, native lifecycle integration and fair bounded ancestry resolution pass the focused acceptance checks below. The one-hour half-life remains the pre-mainnet candidate, with live activation unset. Full release qualification, final activation-height selection, live multi-node rehearsal, publication and deployment remain release follow-through; none is claimed by this preparation task.

The final review identified a local availability issue in unbounded cold ancestry work. The correction preserves consensus history depth while limiting each scheduler turn and retaining admission ownership across retries. The existing implementation-binding checker also caught retry code passing through fresh-admission entry points; the final code retains original admission instead. The checker and its obligations were not weakened.

## Context and Orientation

`consensus/src/pow.rs` owns the legacy unsigned compact retarget calculation. `consensus-light-client/src/bitcoin_pow.rs` converts those outputs to positive canonical Bitcoin targets and builds the 80-byte SHA256d work envelope. `node/src/native/pow.rs` adapts schedule calculations and header checks. `node/src/native/node_impl.rs` resolves canonical, stored-fork and sync-batch ancestry. Startup/replay guards also live in `storage.rs` and `block_flow.rs`; P2P metadata checks live in `service.rs`. `network_profile.rs` authenticates immutable genesis manifests. Wallet pins refer to those genesis manifests and launch proof rules, which must stay stable.

An anchor is a historical block defining ASERT's target and schedule origin. A rules hash identifies the rules used to construct and validate a header. The new rules hash changes at activation, while the chain ID and genesis rules stay fixed. Forks must use their own anchor ancestry rather than the canonical height index.

## Plan of Work

First add `consensus-light-client/src/asert.rs` and official reference fixtures. Add a `pow_rules` module for source-owned schedule selection and the new header rules digest; update V2 verification to admit exactly the configured transition and retain the Bitcoin80 work envelope. Then route native schedule calculations through common anchor requirements, updating all height-bearing header, storage and transport guards. Keep V3 and fixed-difficulty historical bridge proof formats separate and fail closed where they do not support the upgrade.

Add focused native tests using the isolated rehearsal schedule. Compare 30-minute, one-hour and three-hour candidates under seeded steady, arrival, departure and switching traces, clearly retaining first-block-stall limitations. Update `DESIGN.md`, `METHODS.md` and consensus specification with actual final interfaces and evidence.

## Concrete Steps

Work in `/Users/pldd/.codex/worktrees/premainnet-v011-release/Hegemon`. Reuse its existing Cargo target directory, with one coordinator running builds. There were approximately 19 GiB free before implementation; check disk before substantial builds. Do not launch or change shared nodes.

Run focused light-client tests first, then native PoW and lifecycle tests, then required applicable formal/source checks. Record exact commands and results here as they complete. Development rehearsal must use disposable storage and explicitly selected development identity, never the pre-mainnet manifest or retained wallet/database paths.

## Validation and Acceptance

All imported reference vectors must match exactly. Negative and extreme exponent cases must terminate with a valid bounded positive target or a typed error. Old target/rules remain valid below activation; new target/rules are required at and above it. Mining and independent block admission agree, wrong targets and premature/late rules reject, restart and fresh replay reproduce the chain, and a fork crossing activation derives its own anchor. Unchanged default builds must retain historical behavior with no scheduled live activation. Check no_std compilation. Explicitly record that finite tests are not a complete security proof or release authorization.

## Idempotence and Recovery

Tests use disposable state and retained fixtures. Local branch changes are reviewable and do not modify node/wallet state. Do not erase unrelated untracked artifacts. A future live activation is a consensus fork; after crossing it, an old binary is not a compatible rollback.

## Artifacts and Notes

Base main commit: `74910ff865`. Original pre-mainnet rules digest: `a08fc9ec383eec2bff554c64085bed809160241b89cee84cf2c8f27170a7e41f`. Live activation: unset. Official vector provenance belongs alongside the retained test data.

## Interfaces and Dependencies

`AsertAnchor { height: u64, parent_timestamp_ms: u64, pow_bits: u32 }` and `asert_next_bits(anchor, parent_height, parent_timestamp_ms, target_spacing_ms, half_life_ms)` return canonical Bitcoin compact bits. Arithmetic uses bounded fixed-width operations without a new runtime dependency. The schedule selector is a pure function of chain ID and block height. Header validity must never depend on local clock except the unchanged future-timestamp admission bound, or on a mutable operator override.

Revision 2026-10-29: completed implementation, bounded retry correction, focused validation and exact source/log records. The prepared branch does not schedule a live activation.

## Validation Results

The complete command and SHA-256 inventory is docs/consensus/asert-validation.json. Logs and generated Lean axiom/vector evidence are retained locally under .agent/asert-validation-20261029/. Commands run from the worktree named above with at most two Cargo jobs.

The light-client library passed 60 tests, including all 14,000 BCH reference vectors. Its no_std build and seven rehearsal schedule tests passed. The native rehearsal passed 16 tests, including real mining, import, reorg, restart, fresh sync and the 540-block bounded resolver. The final default service suite passed 17 tests and sync-import passed three. Earlier unchanged PoW and ASIC paths passed 12 native PoW, seven Bitcoin80 and seven consensus tests.

The standalone Lean gate rebuilt 14 audited roots and regenerated byte-identical fixtures; the Rust conformance test passed all 62 arithmetic and 45 activation rows. These are scoped arithmetic/schedule lemmas and finite conformance, not a complete Rust refinement proof. The actual Rust scenario runner evaluated 330,777 seeded blocks with explicit horizon and block-cap censoring.

Qualified formatting and Clippy passed with existing exceptions unchanged. CI policy negative tests, native startup policy, 14 governance tests, formal inventory, claims, final blueprint, active-goal policy fixture and system-model assumption gates passed. A structural comparison confirms the three refreshed governance JSON files differ only in source digests and execution timestamps; all review statuses, authority and theorem statements remain identical to the base. No additional release authority follows from these checks.

The 12 imported BCH vector files retain their exact upstream bytes and SHA-256 provenance, including upstream trailing whitespace and final blank lines. The staged whitespace check excludes only those unchanged imported fixture bytes; all authored files pass.
