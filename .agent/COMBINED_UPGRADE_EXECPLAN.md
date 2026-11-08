# Qualify the combined pre-mainnet upgrade

## Purpose / Big Picture

Prepare one reviewable release candidate that consistently admits fresh block timestamps, uses one-hour ASERT, permits the selected mining version bits, and pays accumulated treasury rewards every 60 blocks. Existing pre-mainnet history remains valid below a future common activation height. Operators can install the candidate in advance. No live activation height, announcement, release publication, deployment, or fresh mainnet identity is selected by this work.

The coordinator works in `/private/tmp/hegemon-combined-upgrade-20261108/source`, branch `codex/combined-upgrade-rc-20261108`, based on qualified release `eec3bb141f59865d5efc4d97c86e201415a0b839` (`v0.11.3`). The user's planning checkout is dirty and must remain intact. Parallel workers own separate treasury and mining worktrees under the same temporary parent; only the coordinator integrates their changes. One coordinator schedules heavy builds, at most two compiler jobs, using a distinct target directory and checking free space first.

## Progress

- [x] (2026-11-08) Select the current qualified release base, preserving already integrated sync-import, wallet export, and public-submit fixes.
- [x] (2026-11-08) Compose ASERT input `3f01b14c8148911cc15aebab1922fd6117f4d0b4`; preserve the release RPC availability policy and all current formal-review statuses when resolving conflicts.
- [x] (2026-11-08) Implement the common inactive production schedule and a disposable height-120 rehearsal schedule.
- [x] (2026-11-08) Repair fresh timestamp admission and authoring after independent boundary investigation.
- [x] (2026-11-08) Integrate mining version rolling, BIP310 subset negotiation, and configurable 20+8 / 24+4 extranonces.
- [x] (2026-11-08) Integrate exact treasury batching, mandatory due payout, preserved miner forfeiture, wallet discovery and accounting.
- [x] (2026-11-08) Run focused arithmetic, admission, codec, wallet and adapter checks; conduct one independent timestamp patch review.
- [x] (2026-11-08) Complete the v5 and v6 funded process acceptance runs through H336: six proofs, activation, treasury maturity/spending, HTLC claim/refund, recovery, higher-work reorg and unchanged resubmission, fresh sync, all 337 canonical rows, independent ASERT arithmetic and clean closure.
- [x] (2026-11-08) Verify the v6 CI fixture repairs: node Clippy and all core shards pass; the release audit reaches its outer scope consumer after the combined proof/H0 and six-suite checks succeed.
- [ ] Add the missing strict combined software-candidate audit consumer and its rejection controls; renew only affected source bindings and repeat process acceptance for the replacement freeze.
- [ ] Regenerate composed source bindings without adding security credit, qualify exact artifacts, and run required full CI.
- [ ] Record candidate revision, artifact hashes, passed gates, and remaining physical-hardware or release-authorization limits.

## Context and Orientation

`consensus-light-client/src/pow_rules.rs` owns immutable chain-specific upgrade selection. `asert.rs` implements bounded integer target arithmetic; `node/src/native/pow.rs` projects and validates native headers. `node_impl.rs` owns authoring, fresh import, branch storage and deterministic replay. Fresh admission compares a block against the current clock; replay of previously accepted history must remain deterministic. `service.rs` schedules peer work and retryable local deferrals. The existing future limit is 90,000 milliseconds and timestamp ordering is strictly increasing milliseconds; neither rule is changed.

`scripts/bitcoin_asic_stratum.py` is the bounded pool adapter. Version bits must reach the exact 80-byte hash checked by independent validators and persist through history. Negotiation is an adapter contract, while allowed bits and activation are consensus rules. Physical ASIC firmware qualification is distinct from software reconstruction and accepted blocks.

Treasury batches sum the existing per-height integer-floor(subsidy/5) entitlement. The miner keeps its existing per-block subsidy remainder plus all fees. Active blocks accrue the scheduled treasury share even when the miner forfeits its own reward. A positive boundary payout is mandatory, including when the miner omits its note. Historical omissions before activation are not re-accrued. Pending entitlement and actual issued note value are separate accounting quantities. A reward matures 120 blocks after its creation; batching does not accelerate maturity. Current circuit-12 two-input PrivateSpend geometry remains unchanged.

## Decision Log

On 2026-11-08 the user authorized the combined implementation and testing before activation. Select a common height divisible by 60 only after the candidate is qualified. The planning lead is approximately 4,320 blocks (three days at 60 seconds), rounded up to a multiple of 60; actual production may differ. Monday/Tuesday November 9-10 announcement and Thursday/Friday November 12-13 activation are planning targets, not readiness claims. An exact final height change requires final transition and artifact checks before announcement.

The current release already contains review input `af9a05...` as composed commit `fd3a6f...`, and the qualified sync-import work; do not reapply old dirty source overlays. The ASERT input predates those changes. Preserve `available_rpc_methods(node)?` and merge ASERT metadata separately. Formal governance source bindings must be refreshed for composed bytes while review statuses, assumptions and production authority remain unchanged.

The common production height stays `None` during preparation. Disposable combined rehearsal uses height 120, a multiple of 60, without scheduling the production chain. Existing standalone ASERT test schedules remain independently testable. Fresh mainnet will require an explicit new identity and genesis initialization; no rehearsal height is carried over as a launch waiting period.

## Surprises & Discoveries

The timestamp finding affects local mining and both canonical and noncanonical sync admission. Putting wall-clock checks into deterministic header projection or stored replay would break legitimate historical processing. Known stored branch promotion and cached work during clock rollback also need review. Too-future bytes must remain retryable when they become timely.

The existing release authorization gate permits a narrow sync-import successor. Passing ordinary tests does not authorize newly changed consensus source. Prepare a separately reviewed exact successor path; never widen the old gate or relabel historical receipts to hide changed inputs.

## Plan of Work

First integrate the immutable ASERT source and define a shared schedule. Reconcile the independent timestamp investigator's findings with the coordinator's source trace, then enforce the bound at fresh import and promotion boundaries and make authoring use the minimum valid millisecond timestamp. Retain fixed advertised job times and historical replay. Add deterministic injected-time regression controls rather than waiting for wall-clock expiry.

In parallel, the mining worker supplies a complete version/codec/adapter diff, and the treasury worker supplies pure policy, construction, independent validation and wallet/accounting changes. Integrate each into the coordinator tree with explicit conflict review. Update DESIGN.md, METHODS.md and the integration queue around the final behavior. Keep current proof-source inputs and relation unchanged unless an actual required dependency is discovered and separately qualified.

After focused checks, launch one fresh read-only timestamp bypass/regression reviewer with only the finding, current diff and repository policy. Confirm any reported issue before revising. Then run the complete disposable acceptance matrix, composed formal/source gates, exact binary proof checks and full non-PR preparation CI. Continue through failures with retained evidence; do not equate preparation success with activation or deployment.

## Concrete Steps

From the coordinator root, use `git diff --check` (excluding only unchanged imported upstream ASERT vector whitespace), scoped rustfmt, `cargo test --locked -p consensus-light-client --release -j 2 --lib`, the no-default-features light-client check, `bash scripts/check_asert_formal.sh`, focused native tests, and `python3 -I -B scripts/test_bitcoin_asic_stratum.py`. Record final exact commands and results as implementation stabilizes. The CI investigator supplies the exact release/authorization/formal commands, which must be added here before qualification.

All live acceptance nodes use create-only disposable storage, private test wallets and loopback peers. Public-network setup instructions retain the approved shared seed list `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"` unless deliberately rotated. All miners must share that list to avoid forks and must enable NTP or chrony because future-skewed timestamps reject. Test harnesses never open retained operator wallets or databases.

## Validation and Acceptance

Show H-1/H/H+1 target, version and treasury rules on the same source, first complete batch H..H+59, subsequent boundaries, and explicit rejection of legacy/new rule mismatches. Test exact skew limit, limit+1, full milliseconds, clock rollback, local mining, direct announcements, both sync paths, stored branch promotion, and historical startup/replay. Identical rejected future bytes must later import under an advanced test clock.

Treasury controls cover intermediate and boundary outputs, zero/duplicate/early/missing/incorrect payouts, recipient authorization, checked amount ranges, halvings and subsidy exhaustion, final residual, supply accounting and miner omission. A fork crossing a payout must reverse accrual and issuance. Restart and fresh sync must agree on state, note discovery, maturity rejection and a later current two-input spend. Rehearse current HTLC lock/claim/refund and competing-spend/recovery behavior on the same candidate. Independently reconstruct rolled headers, accept a nonzero rolled-version block, and retain fixed-version miners. Software evidence cannot establish sustained physical ASIC performance.

## Idempotence and Recovery

No production database, wallet, running service or retained release is altered. Do not delete earlier failed experiment evidence. Keep all branch inputs and integration resolutions reproducible. Pre-activation rollback remains the existing release; after a future consensus boundary, an old binary needs coordinated recovery and cannot be advertised as a compatible rollback.

## Outcomes & Retrospective

All four changes are composed, with production activation unset and funded Development activation at H120. The exact combined-rules hash is `ec304529f49e7ddc777e0ca78b189acec753d4fb18aafe15761e686ea3596b7f`, derived from the retained explicit rules preimage. The current proof relation and locked dependencies remain unchanged. Rehearsal node and current private-spend executables are built with separately recorded feature sets. These are source rehearsal artifacts; ordinary final binaries still need their own proof/H0 checks.

Focused evidence so far: 64 light-client tests including the 14,000-reference ASERT vector test; 16 composed native ASERT tests; ten timestamp/ASIC injected-clock tests; 180-block actual-PoW treasury payout/reorg/restart/fresh-sync test; treasury arithmetic, wallet discovery/maturity and packed two-input constraints; adapter socket controls. The new batch-supply Lean model and generated production-helper conformance test distinguish pending scheduled entitlement from actual issued value, including miner omission. Legacy per-block supply refinements are explicitly scoped to inactive heights. No full Rust/chain equivalence, physical ASIC performance or production authority is inferred.

One fresh timestamp candidate review found no confirmed bypass or regression under a fixed admission clock. The admission operation samples the local wall clock; a rollback during subsequent verification is not a claim of continuous clock freshness. Stored replay remains deterministic, while new calls and cached work recheck admission. The user approved publishing candidate commit `3eb4da7` to its isolated CI branch. Final artifact checks and exact-head full CI remain incomplete; no release announcement, deployment or live activation height has been selected.

The first full CI found two test/qualification issues. Three deliberate contention tests held synchronous lock guards in async test futures, causing denied Clippy diagnostics. Bounded helper threads now hold the same locks across the original assertions and release points, with acquisition handshakes and joined cleanup. All three existing tests and the node all-targets qualified Clippy check pass locally. The 180-block lifecycle fixture also rebuilt a timestamp-adjusted header using the constructor's default-chain rules. Under the exact CI feature tuple, its standalone ASERT schedule differed from the fixture's configured network, producing `InsufficientWork`. The fixture now mirrors production's actual-chain rules and version-commitment rebinding; the exact focused qualification passes all six source lifecycle gates. Production authoring and validation are unchanged.

Qualification failures now retain bounded child-output tails in CI error messages while preserving raw command logs and every rejection condition. The producer and candidate regression suites pass, including nested failure propagation, output bounds and rejection of zero-exit commands with stderr. Only the RPC-admission review digest and its executed governance receipt require formal renewal for the fixture edits; classifications, claims, authority and proof inputs remain unchanged. Replacement source freeze, funded runtime evidence, independent command/source review and exact-head full CI are still required. Earlier v5 receipts remain attributed to v5 and cannot be relabeled as replacement qualification.

The v6 replacement passed all 16 funded process gates in 43 minutes 43 seconds, with six 171,281-byte current SMZL proofs, 337 canonical rows, 217 independently recalculated ASERT targets and 16 clean node closures. Its source and public bundle received independent reviews before the user-approved candidate push `cdbedf3`. That commit cleared the prior lint and treasury-fixture failures. The final release audit then exposed an omitted consumer branch: the inner combined checker successfully returned its exact software-candidate result, but the audit shell's historical mode parser rejected that new mode. The correction must give this exact mode a separate attestation with proof/lifecycle evidence and false authority boundaries. It must preserve every historical route and reject missing, mistyped, partial or elevated-authority results. Only the release PQ-binary review digest and its actual governance receipt need renewal. The replacement freeze and full CI remain required; the v6 receipt keeps its original source attribution.
