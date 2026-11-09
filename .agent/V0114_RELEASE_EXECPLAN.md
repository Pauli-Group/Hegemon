# Publish v0.11.4 at H18,660 and deploy dev first

This living ExecPlan follows `.agent/PLANS.md`. Maintain Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective. The completed software-candidate work is recorded in `.agent/COMBINED_UPGRADE_EXECPLAN.md`; this plan adds the selected production schedule and authorized release operations.

## Purpose / Big Picture

Operators must receive a qualified v0.11.4 executable before pre-mainnet block 18,660. At that block the existing network changes to one-hour ASERT difficulty, 24-bit mining version rolling and exact 60-block treasury batches. The timestamp admission repair also ships. Existing chain history, genesis, network manifest, wallet pins and current PrivateSpend proof remain unchanged. The user authorized final checks, publication, then deployment to hegemon-dev before hegemon-ovh. The user will announce on Discord after rollout.

## Progress

- [x] (2026-11-09 04:33–04:36 UTC) Read-only host preflight: both v0.11.3 hosts active, NTP synchronized, same genesis and shared H13,534→13,535 progress, matching binary/config hashes, no observed durability errors.
- [x] (2026-11-09) Set the common pre-mainnet activation to Some(18_660). Default and rehearsal light-client release tests each passed 65/65; no-default-features check passed. Historical chain/profile identities and Cargo.lock unchanged.
- [x] (2026-11-09 04:45 UTC) Stabilized product label, active adapter, joining helper and current documentation. Two actual production helper tests passed; 26 adapter tests, 26 suite-producer controls, 18 join and 18 prepared-packager controls passed. New packager/test remain external until after binary CI.
- [x] (2026-11-09 04:52 UTC) Refreshed 35 dependent review digests and the three governance receipts. Actual 14-test governance run and all six public formal CLIs passed; final digest/semantic rechecks passed. The first failed dependency-order attempt remains recorded externally; no assurance/authority changed.
- [ ] Freeze/review exact source; rebuild separately attributed rehearsal artifacts and complete a fresh funded multi-node lifecycle with reviewed public evidence and six actual suite commands.
- [ ] Commit/push the final binary source; complete exact-head Monorepo CI and all nine full preparation jobs, including four actual platform proof/H0, six-suite checks and asset assembly.
- [ ] Verify downloaded CI bytes; add exactly the three new packaging files after the binary source commit; check reproducible archives and launchers; publish v0.11.4 with verified tag and asset digests.
- [ ] Independently review and bind the deployment helper to actual final artifact pins. Deploy dev with a fresh plan and verified cold backup, then prove shared progression with OVH still old.
- [ ] Deploy OVH with the fresh dev canary; verify both actual new binaries, identities and shared progression. Report release and observed rollout state.

## Surprises & Discoveries

Historical v0.11.3 packaging/deployment helpers enforce exact old tuples. Replacing labels without renewed source, artifact and operational attribution rejects. The old tag workflow also selects historical authorization. Preserve it; publish the successful combined preparation assets through an additive reviewed path.

The PrivateSpend relation hashes Cargo.lock. Change product version in `protocol/versioning/src/lib.rs` and software metadata, preserving internal Cargo versions and all 41 proof inputs. Development H120 process evidence and production H18,660 helper tests have different scopes.

## Decision Log

- Decision: H18,660 is the single production constant for ASERT, version rolling and treasury batching, preserving Development H120 and legacy ASERT H20. Rationale: explicit user selection and consistent consensus activation. Date: 2026-11-09.
- Decision: Retain false technical qualification authority fields and record user authorization and actual deployment separately. Rationale: pre-mainnet release authorization grants no cryptographic production, mainnet or physical ASIC assurance. Date: 2026-11-09.
- Decision: Reuse warm qualified build targets with at most two compiler jobs and exclusive worker file ownership. Rationale: approximately 16 GiB remains on APFS; preserve unrelated data. Date: 2026-11-09.
- Decision: Refuse automatic old-binary rollback when current chain height is uncertain or at/after H18,660. Rationale: v0.11.3 cannot validate activated rules; a stopped local process cannot establish live height. Date: 2026-11-09.

## Outcomes & Retrospective

The selected schedule and light-client boundary checks are complete. Final v0.11.4 source/artifacts, publication and rollout remain pending. Earlier a2a4044 CI passed 22 Monorepo and nine preparation jobs; those retain their original unset-height/v0.11.3 attribution.

## Context and Orientation

Work in `/private/tmp/hegemon-combined-upgrade-20261108/source`, branch `codex/combined-upgrade-rc-20261108`. Preserve the dirty original planning checkout. `consensus-light-client/src/pow_rules.rs` owns the schedule selected by exact chain ID. Native mining/import/treasury use it. `protocol/versioning/src/lib.rs` supplies the product version; `config/testnet/0.11/release.json` labels software separately from the unchanged network manifest. `scripts/check_combined_upgrade_candidate.py` authenticates frozen source, actual proof/H0 and six fresh suites. `scripts/qualify_combined_upgrade.py` executes suites and validates complete source-bound funded runtime evidence. Public evidence lives in `release-evidence/combined-upgrade-20261108/`; exclude wallets, seeds, passphrases and witnesses.

Prepare the new packager and its tests externally until after binary CI. Then add only `scripts/package_v0114_release.py`, `scripts/test_package_v0114_release.py` and `config/v0114-release-artifacts.json` in a separate packaging commit. Join changes belong in binary source. Preserve historical profiles/checkers/pins.

## Plan of Work

Stabilize minimal height/version/launcher changes and production tests. Select the unchanged pre-mainnet chain at H18,659/H18,660/H18,661; check correct/wrong rules, branch-bound H18,659/H18,658 ASERT anchors and mining version payloads. Treasury tests use the actual policy/recipient, payout H18,719 and maturity H18,839. They are helper evidence, separate from an actual current-proof spend.

Correct current documentation. Renew only changed blueprint source digests and executed governance evidence through trusted existing tools. Preserve review status, assumptions, goal progress, theorem/proposition bytes, claim baseline and authority. Freeze the complete source with the established allowlist/debt mechanism. Rebuild rehearsal node/private-spend and run the existing complete funded H120 harness in a new create-only output directory. Require 16 gates, six real proofs, canonical comparison, recovery/reorg/fresh sync and every owned process cleanly closed. Export reviewed public evidence, check absence of actual disposable secrets without printing them, and obtain independent review. Install six exact suite commands and final review pins.

Commit/push the authorized branch and dispatch full preparation. Independently verify exact source commits and successful completion of every required job, including asset assembly. Download/hash actual artifacts, qualify the Linux deployment tuple and package four platforms with new manifests. Add the accepted profile/packager files in a provenance-preserving commit. Publish v0.11.4; verify tag, asset digests and public downloaded bytes. The old tag workflow is not combined qualification.

Adapt the historical observer in `/private/tmp/hegemon-v0114-ship-deploy/` and bind actual final artifact pins. Stage immutable root-owned regular files, verify ELF and traversal permissions, and execute --version as hegemon-v011. Require a fresh plan, sufficient disk and exact PID/invocation/time shutdown marker with clean flush before cold backup. Compare backup against stopped state and fsync/hash it. Replace only the unit's executable token. Preserve loopback unsafe RPC, state, manifest, seeds, mining threads and NTP. Verify actual loaded image and zero restarts. Require dev-new/OVH-old shared advancement before generating an OVH plan with a fresh canary. Finish with both-new shared advancement and original anchors.

## Concrete Steps

From source root use the warm target and at most two jobs:

    cargo test --release --locked --offline -j2 -p consensus-light-client --lib
    cargo check --release --locked --offline -j2 -p consensus-light-client --no-default-features
    cargo test --release --locked --offline -j2 -p hegemon-node --lib premainnet_combined_ -- --nocapture --test-threads=1

Run changed Python unittest modules in isolated mode. Use trusted formal-core CLI commands to print source digests, execute 14 governance tests and validate claims/blueprint/goals. Use `freeze_combined_upgrade_candidate.py --allow-paths PATH --formatting-debt-paths PATH --write`, then the combined checker. External coordinator records retain actual paths, logs, hashes and fresh harness argv. Update actual progress before source freeze; avoid later source edits that invalidate attribution.

After push dispatch `prepare-premainnet-release.yml` at the candidate branch and retain terminal run/job records and manifests. The new packager's --help/tests define accepted provenance/archive commands. Deployment plan/deploy and pair verification must contain actual final hashes; record concrete commands externally after outputs exist.

## Validation and Acceptance

Acceptance requires source transition/formal checks, fresh complete source-bound funded rehearsal, successful exact-head CI, all four platform proof/H0 and six suites, public verified release assets/tag, then dev and OVH running the exact new binary with unchanged identity/config and shared canonical progress. Report observed height and remaining lead. Friday morning Calgary is a projection. No physical ASIC, mainnet or cryptographic production approval is inferred.

## Idempotence and Recovery

Use create-only evidence and immutable artifacts. Preserve old tags/assets and host state. Inspect remote receipts/service state before retrying SSH timeouts. Rollout budget is 7,200 seconds; plans last 1,800 seconds and OVH canary age must be ≤600 seconds. Require at least 120 observed blocks of deployment lead, permitting a higher demand. Recheck the running counterpart before stop/start and old restart. Refuse rollback if live height/anchor cannot be authenticated or H18,660 is reached; preserve stopped state/backup for explicit recovery.

## Artifacts and Notes

Initial schedule receipt: `../reviews/v0114-activation/`. Impact maps: `../reviews/v0114-impact/` and `../reviews/v0114-routing/`. Prepared packaging: `../reviews/v0114-packaging/`. Production tests: `../reviews/v0114-production-tests/`. Formal renewal: `../reviews/v0114-formal/`. Pending records do not imply acceptance. After complete-source freeze, preserve its exact bytes; record subsequent build, runtime, CI, publication and deployment progress in external receipts and a completed copy of this plan, so a progress edit cannot silently invalidate the qualified source.

## Interfaces and Dependencies

Use existing source-owned gates/harness and pinned Rust/Lean tools. Preserve proof formats, lockfile, manifest, rules preimages and historical executors. Production constant is Some(18_660), aliased by ASERT. Product is 0.11.4; network is v0.11. Shared mining uses `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"`; all miners share seeds to avoid forks and keep NTP/chrony enabled because future-skewed timestamps reject.

Created 2026-11-09 for explicit H18,660/publication/dev-then-OVH authorization. The coordinator sends no Discord announcement.
