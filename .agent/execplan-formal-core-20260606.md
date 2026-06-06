# Formal Core Release Gate

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. It is intentionally self-contained so a contributor with only this working tree can continue the rollout.

## Purpose / Big Picture

Hegemon should become a proof-carrying protocol rather than only an audited Rust codebase. In practical terms, this first milestone gives operators and reviewers one command that checks the highest-value formal-security promises that are ready to be enforced now: consensus-critical claims are recorded in a machine-readable ledger, the formal model inventory is checked, and an independent reference tool verifies bridge message canonical encoding, message roots, and replay-key vectors without calling production protocol helpers.

After this change, a contributor can run `bash scripts/check_formal_core.sh` from the repository root and see a concise pass/fail report. CI and release workflows will run the same gate. The branch will then be deployed to `hegemon-dev`, where the normal node binary, PQ audit, mining, action inclusion, and bridge witness smoke will still pass.

## Progress

- [x] (2026-06-06T04:05:25Z) Created branch `codex/formal-verification-core` from `codex/superneo-experiment`.
- [x] (2026-06-06T04:05:25Z) Read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, existing formal model READMEs, CI, release workflow, and current reference-tooling layout.
- [x] (2026-06-06T04:24:00Z) Added `config/formal-security-claims.json` with eight claims, six production-eligible enforced/model-checked claims, and two explicit residual risks.
- [x] (2026-06-06T04:24:00Z) Added an independent standalone script crate at `scripts/hegemon_formal_core` for claims, bridge vectors, and formal inventory checks.
- [x] (2026-06-06T04:24:00Z) Added bridge message and replay-key vectors under `testdata/formal_core_vectors/bridge_messages.json`.
- [x] (2026-06-06T05:20:47Z) Added `scripts/check_formal_core.sh`; it runs the standalone checker, audits the checker crate lockfile with `cargo-audit`, verifies existing native backend reference vectors, and can optionally run installed TLC/Apalache binaries.
- [x] (2026-06-06T04:24:00Z) Wired `scripts/check_formal_core.sh` into CI as `formal-core` and into release `security-gates`.
- [x] (2026-06-06T04:24:00Z) Updated `DESIGN.md`, `METHODS.md`, `docs/SECURITY_REVIEWS.md`, `docs/CONTRIBUTING.md`, and formal READMEs to document the new release standard and remove stale HotStuff/current-CI overclaims.
- [x] (2026-06-06T04:24:00Z) Ran `cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml`; it passed with 2 tests.
- [x] (2026-06-06T05:20:47Z) Ran `bash scripts/check_formal_core.sh`; it passed as an 8-step gate, including standalone checker dependency audit, 2 bridge vectors, and 11 native backend vectors.
- [x] (2026-06-06T05:20:47Z) Ran local formal-core, Rust, dependency, PQ, native review package, release posture, and CI-mode red-team gates. All passed.
- [x] (2026-06-06T05:35:41Z) Committed and pushed `codex/formal-verification-core` to origin.
- [x] (2026-06-06T05:35:41Z) Deployed commit `c2988b23` to `hegemon-dev`, built with `make setup && make node`, ran remote formal/security gates, restarted systemd from `/home/ubuntu/hegemon-current-c2988b23`, and verified mining plus outbound bridge action inclusion and witness export.

## Surprises & Discoveries

- Observation: The design docs say formal specs are part of the security posture, but CI currently has no dedicated formal-core job.
  Evidence: `.github/workflows/ci.yml` has dependency, core, native-path, adversarial, native-backend-security, and release-build jobs, but no job that runs the TLA+ model inventory or a formal/security claim checker.
- Observation: The repository already has the right pattern for independent review tooling.
  Evidence: `tools/native-backend-ref` is a standalone workspace crate with vector verification commands and is already wired into `native-backend-security`.
- Observation: The current TLA+ specs are useful but not enough to cover the newest exploit class.
  Evidence: `circuits/formal/transaction_balance.tla` covers MASP balance/nullifier rules and `consensus/spec/formal/pow_longest_chain.tla` covers PoW fork choice, but neither checks bridge canonical encoding, replay-key derivation, proof artifact profile dispatch, or the formal claim ledger.
- Observation: The active docs contained stale and aspirational formal-verification claims.
  Evidence: `DESIGN.md` said formal models were wired into `security-adversarial`, but `.github/workflows/ci.yml` did not run TLC/Apalache or any formal inventory gate. `docs/SECURITY_REVIEWS.md` also cited a HotStuff `NoDoubleCommit` command even though the native release line is PoW-only.
- Observation: A root workspace member would unnecessarily expand the normal build and lockfile surface.
  Evidence: the existing native backend reference tools are explicit workspace members because they are part of the native backend review package. The formal-core checker is a release script gate, so it now lives under `scripts/hegemon_formal_core` with its own `[workspace]` and isolated `Cargo.lock`.
- Observation: The existing native backend reference vectors are valuable enough to include in the formal-core gate.
  Evidence: `bash scripts/check_formal_core.sh` reported 11 native backend vector cases passed, including invalid spec digest, invalid parameter fingerprint, invalid STARK proof, invalid proof digest, and trailing-byte rejection cases.
- Observation: The standalone checker is release-critical once CI uses it, so its isolated `Cargo.lock` must be audited explicitly.
  Evidence: `bash scripts/check_formal_core.sh` now runs `cargo audit --color never` under `scripts/hegemon_formal_core`, and CI installs `cargo-audit` before the `formal-core` job runs the gate.
- Observation: Regenerating the native backend review package before committing source changes produces a dirty-worktree package fingerprint.
  Evidence: `scripts/package_native_backend_review.sh` records `git diff`, staged diff, and untracked files in `code_fingerprint.json`. The generated tarball and checksum were restored so the branch does not commit a package over an uncommitted worktree.

## Decision Log

- Decision: Implement the first formal-verification milestone as a hard release gate over a claims ledger plus independent vectors, not as an immediate all-in Lean rewrite.
  Rationale: Hegemon needs an enforceable security improvement quickly. Lean proofs for the full verifier boundary are the right long-term direction, but the first branch should establish the release discipline and executable reference checks that future Lean artifacts can plug into.
  Date/Author: 2026-06-06 / Codex.
- Decision: Start with bridge message roots and replay keys for the independent vector checker.
  Rationale: The recent security sweep found bridge/proof-boundary risks, and the bridge root/replay functions are small enough to reimplement independently without production helper calls. They are a good first target for the "goal simpler than implementation" standard.
  Date/Author: 2026-06-06 / Codex.
- Decision: Keep model-checker execution optional locally but make the formal inventory and vector/claim checks mandatory.
  Rationale: TLC and Apalache are not guaranteed on every developer machine or VPS. The hard gate can still enforce the files, configs, claims, and independent vectors everywhere, while CI can be extended later to install and run full model checkers when the dependency story is stable.
  Date/Author: 2026-06-06 / Codex.
- Decision: Put `hegemon-formal-core` under `scripts/hegemon_formal_core` instead of root `tools/` and omit it from root workspace members.
  Rationale: The checker must be reproducible and CI-runnable, but it should not expand the normal root workspace build, root lockfile, or native backend review package. A standalone script crate keeps the gate explicit.
  Date/Author: 2026-06-06 / Codex.
- Decision: Include existing native backend reference-vector verification in `scripts/check_formal_core.sh`.
  Rationale: Bridge vectors cover a small semantic kernel, while native tx-leaf and receipt-root vectors cover proof-artifact byte grammar, exact decode, and invalid-vector rejection. Both are needed for the first practical formal-core standard.
  Date/Author: 2026-06-06 / Codex.
- Decision: Make `cargo-audit` mandatory for the formal-core checker crate.
  Rationale: A release gate must not be an unaudited dependency island. The root dependency waiver gate checks the workspace lockfile; the standalone checker has a separate lockfile and needs a separate audit pass.
  Date/Author: 2026-06-06 / Codex.

## Outcomes & Retrospective

Local and `hegemon-dev` validation are complete. The branch now has a machine-readable formal-security claims ledger, a standalone independent bridge-vector checker, a mandatory checker dependency audit, CI/release wiring, corrected formal/security docs, a refreshed native backend review package, a passing CI-mode proving red-team report, and a live `hegemon-dev` deployment.

The deployed node is running from `/home/ubuntu/hegemon-current-c2988b23` with `HEGEMON_MINE=1`, one mining thread, RPC on `127.0.0.1:9944`, P2P on `0.0.0.0:30333`, and NTP synchronized. The unit backup is `/home/ubuntu/hegemon-devnet/deploy-backups/hegemon-node.service.20260606T053252Z`.

## Context and Orientation

The active branch is `codex/formal-verification-core`. Hegemon is a Rust workspace for a post-quantum proof-native chain. The consensus-critical surfaces for this plan are:

1. `circuits/formal/transaction_balance.tla` and `circuits/formal/transaction_balance.cfg`, which model MASP transaction balance and nullifier uniqueness.
2. `consensus/spec/formal/pow_longest_chain.tla` and `consensus/spec/formal/pow_longest_chain.cfg`, which model PoW fork choice and finality assumptions.
3. `protocol/kernel/src/bridge.rs`, which defines `BridgeMessageV1`, `OutboundBridgeArgsV1`, `InboundBridgeArgsV1`, bridge message root hashing, payload hashing, and inbound replay-key derivation.
4. `node/src/native/mod.rs`, which stages bridge actions, validates inbound message binding preconditions, imports blocks, exports bridge witnesses, and exposes JSON-RPC smoke surfaces.
5. `scripts/security-audit.sh`, `scripts/dependency-audit-gate.sh`, `scripts/run_proving_redteam.sh`, and `scripts/check-core.sh`, which form the current release/security gate set.
6. `tools/native-backend-ref`, which is the existing model for standalone reference verification tooling.

A "claims ledger" in this plan means a JSON file listing every production-relevant security claim, whether the claim is production eligible, what proof or evidence backs it, what CI gates enforce it, and whether any explicit residual risk remains. A "reference vector" means a small JSON test case consumed by an independent checker. The checker must calculate the expected value from first principles and compare it to the committed expected value.

## Plan of Work

First, add `config/formal-security-claims.json`. Each entry will include an id, component, claim class, summary, status, proof model, production eligibility, assumptions, evidence paths, gates, and residual risks. The checker will reject duplicate ids, missing evidence paths, empty gates for production claims, production eligibility for conjectural claims, and expired or malformed residual-risk entries.

Second, add `scripts/hegemon_formal_core` as a small standalone script crate with its own `[workspace]` and isolated lockfile. It will depend on `anyhow`, `blake3`, `clap`, `hex`, `serde`, and `serde_json`. It must not depend on `protocol-kernel` because the bridge-vector check is supposed to be independent. The tool will expose:

    cargo run --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-claims config/formal-security-claims.json
    cargo run --manifest-path scripts/hegemon_formal_core/Cargo.toml -- verify-bridge-vectors testdata/formal_core_vectors/bridge_messages.json
    cargo run --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-formal-inventory

Third, add `testdata/formal_core_vectors/bridge_messages.json`. The vector file will include at least two bridge messages with fixed source/destination chain ids, family id, nonce, source height, payload, payload hash, message hash, message root, and inbound replay key. The checker will reimplement the exact canonical encoding and BLAKE3 XOF-48 derivations independently.

Fourth, add `scripts/check_formal_core.sh` as the user-facing gate. It will run the three tool commands, run `cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors`, and optionally run TLC/Apalache if the environment variable `HEGEMON_FORMAL_RUN_MODEL_CHECKERS=1` is set and the tools are available. The default gate remains useful without external model-checker installation.

Fifth, wire the script into `.github/workflows/ci.yml` as a new job and into `.github/workflows/release.yml` under `security-gates`. Update `DESIGN.md`, `METHODS.md`, and `docs/SECURITY_REVIEWS.md` to describe the new formal-core release standard.

Sixth, run local gates. At minimum run:

    cargo fmt --all
    cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml
    bash scripts/check_formal_core.sh
    bash scripts/dependency-audit-gate.sh
    bash scripts/security-audit.sh --quick
    cargo check -p hegemon-node --no-default-features

If time and resources allow, also run the CI-mode red-team suite before deployment:

    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh

Seventh, push the branch and deploy to `hegemon-dev` from a fresh release directory. Preserve the systemd backup pattern under `/home/ubuntu/hegemon-devnet/deploy-backups/`, restart `hegemon-node.service`, and verify the service runs from the new release path. Then run PQ audit on the VPS, confirm mining is active, submit a real bridge outbound action, wait for inclusion, confirm pending clears, and export a bridge witness for the submitted payload.

## Concrete Steps

Run commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Initial branch evidence:

    git switch -c codex/formal-verification-core
    Switched to a new branch 'codex/formal-verification-core'

Current command evidence:

    cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml
    test result: ok. 2 passed; 0 failed

    bash scripts/check_formal_core.sh
    === Hegemon formal-core gate passed ===

After documentation and workflow updates, the following commands passed:

    cargo fmt --all
    cargo fmt --manifest-path scripts/hegemon_formal_core/Cargo.toml -- --check
    git diff --check
    bash scripts/check_formal_core.sh
    bash scripts/dependency-audit-gate.sh
    cargo check -p hegemon-node --no-default-features
    bash scripts/security-audit.sh --quick
    bash scripts/verify_native_backend_review_package.sh
    bash scripts/check_native_backend_release_posture.sh --package audits/native-backend-128b/native-backend-128b-review-package.tar.gz
    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh

Observed highlights:

    bash scripts/check_formal_core.sh
    claims: 8, production_eligible: 6, residual_risks: 2
    bridge vectors: 2 passed
    native backend vectors: 11 passed

    bash scripts/dependency-audit-gate.sh
    dependency audit findings: 8 total, 8 waived, 0 unwaived

    bash scripts/security-audit.sh --quick
    AUDIT PASSED

    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh
    overall=pass
    summary=/Users/pldd/Projects/Reflexivity/Hegemon/output/proving-redteam/20260606T043025Z/summary.txt

Clean native review package regeneration:

    bash scripts/package_native_backend_review.sh
    sha256=24c7abe2de542426f638cc8f131ea7434ecce20870aef59798d46f77b17ba34e

    tar -xOzf audits/native-backend-128b/native-backend-128b-review-package.tar.gz native-backend-128b-review-package/code_fingerprint.json
    head_commit=9b43cbbbafd90834424c0e1a54c32bf54e35c649
    dirty=false

Remote `hegemon-dev` evidence:

    ssh hegemon-dev 'cd /home/ubuntu/hegemon-current-c2988b23; make setup; make node'
    Finished `release` profile [optimized] target(s) in 1m 55s

    ssh hegemon-dev 'cd /home/ubuntu/hegemon-current-c2988b23; bash scripts/check_formal_core.sh'
    === Hegemon formal-core gate passed ===

    ssh hegemon-dev 'cd /home/ubuntu/hegemon-current-c2988b23; bash scripts/dependency-audit-gate.sh'
    dependency audit findings: 8 total, 8 waived, 0 unwaived

    ssh hegemon-dev 'cd /home/ubuntu/hegemon-current-c2988b23; bash scripts/security-audit.sh --quick'
    AUDIT PASSED

    ssh hegemon-dev 'systemctl show -p MainPID -p ActiveState -p SubState hegemon-node.service'
    MainPID=634215
    ActiveState=active
    SubState=running

    hegemon_miningStatus after smoke
    block_height=398791
    blocks_found=9
    is_mining=true
    threads=1

    outbound bridge smoke
    tx_hash=0x958bce14a26beeb1f3fe85348a7d0216a7fcc06c20c2fc91279448237012ebe9
    included_height=398788
    included_hash=0x00005727c205db8bebdcec39cbd57d8713e91d1219b2a571550495794502bc14
    pending_after=[]
    witness_payload=0x666f726d616c2d636f72652d6465762d736d6f6b652d31373830373234303933

## Validation and Acceptance

The branch is accepted when:

1. `bash scripts/check_formal_core.sh` exits 0 and prints that claims, bridge vectors, and formal inventory passed.
2. `cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml` exits 0.
3. CI and release workflow files contain the formal-core gate.
4. `DESIGN.md`, `METHODS.md`, and `docs/SECURITY_REVIEWS.md` describe the formal-core gate as part of the release standard.
5. Dependency and PQ audits still pass locally.
6. `hegemon-dev` runs from the new branch release path, mining is active, a real outbound bridge action is accepted and mined, pending actions clear, and `hegemon_exportBridgeWitness` returns a witness for the submitted payload.

## Idempotence and Recovery

The local checker is read-only and safe to run repeatedly. The bridge-vector file is static. If the checker reports a mismatch, do not update expected hashes blindly; first inspect whether the independent encoding or production semantics changed. If production bridge semantics changed intentionally, update `DESIGN.md`, `METHODS.md`, the vector file, and the claim ledger together.

Remote deployment must use a new release directory instead of editing the running checkout. Before systemd changes, copy `/etc/systemd/system/hegemon-node.service` to `/home/ubuntu/hegemon-devnet/deploy-backups/`. If the new service fails, restore the backed-up unit, run `sudo systemctl daemon-reload`, and restart `hegemon-node.service`.

## Artifacts and Notes

This plan is the first artifact. Command transcripts and the final `hegemon-dev` smoke evidence will be added as the work proceeds.

## Interfaces and Dependencies

The new tool crate will define:

    scripts/hegemon_formal_core/src/main.rs
        enum Command { CheckClaims, VerifyBridgeVectors, CheckFormalInventory }

    scripts/hegemon_formal_core/src/lib.rs
        pub fn check_claims_file(path: &Path) -> Result<ClaimsReport>
        pub fn verify_bridge_vectors_file(path: &Path) -> Result<BridgeVectorReport>
        pub fn check_formal_inventory(root: &Path) -> Result<InventoryReport>

The crate may share third-party crates such as `blake3` and `serde_json`, but it must not depend on `protocol-kernel` for bridge-vector verification.

Revision note 2026-06-06T04:05:25Z: Created the plan after branching and reading the current formal, design, method, CI, and reference-tooling surfaces.

Revision note 2026-06-06T04:24:00Z: Recorded the implemented standalone formal-core checker, claims ledger, bridge vectors, CI/release wiring, doc corrections, subagent findings, and passing initial formal-core commands.

Revision note 2026-06-06T05:20:47Z: Recorded the mandatory formal-core checker dependency audit, local release/security gate results, CI-mode red-team pass, and review-package artifact handling.

Revision note 2026-06-06T05:35:41Z: Recorded the clean native review package regeneration, pushed commits, `hegemon-dev` deployment, remote gates, mining status, action inclusion, and bridge witness smoke evidence.
