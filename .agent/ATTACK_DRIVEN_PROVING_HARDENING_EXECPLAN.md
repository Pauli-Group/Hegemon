# Attack-Driven Proving Hardening Campaign

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

This plan builds on the already-completed proof-boundary reviews in `.agent/HOSTILE_PROOF_ATTACK_CLASS_REVIEW_EXECPLAN.md`, `.agent/HOSTILE_EXPLOIT_REVIEW_AND_PATCH_EXECPLAN.md`, and `.agent/NATIVE_BACKEND_ASSURANCE_ELEVATION_EXECPLAN.md`, but it is self-contained and names the current remaining work explicitly.

## Purpose / Big Picture

The current proving system is in the awkward middle state that kills teams in production: the obvious malformed-byte bugs are mostly patched, but the remaining attack surface is spread across prover configuration, artifact staging, resource exhaustion, compatibility fallback, and review-package drift. After this work, a maintainer will be able to run one hostile campaign and watch the repository prove four things with code instead of rhetoric: the shipped `tx_leaf -> recursive_block` path rejects forged or swapped proof artifacts, optional sidecar staging cannot be abused into consensus acceptance or unbounded memory growth, local prover shortcuts cannot silently weaken the live path, and the release workflow fails when the proving attack suite regresses.

The visible outcome is not “we wrote more security prose.” The visible outcome is: run one script from the repository root, get a dated artifact directory under `output/proving-redteam/`, see explicit pass/fail lines for each attack class, and watch CI block merges when that hostile suite breaks. A new contributor should be able to reproduce the attack campaign on a laptop or CI runner without reverse-engineering which proof lane is actually shipped.

## Progress

- [x] (2026-04-19 20:34 MDT) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, `.agent/HOSTILE_PROOF_ATTACK_CLASS_REVIEW_EXECPLAN.md`, `.agent/HOSTILE_EXPLOIT_REVIEW_AND_PATCH_EXECPLAN.md`, and `.agent/NATIVE_BACKEND_ASSURANCE_ELEVATION_EXECPLAN.md`.
- [x] (2026-04-19 20:34 MDT) Re-audited the current shipped proving path and confirmed the product line is `tx_leaf -> recursive_block`, with `receipt_root` remaining an explicit alternate compatibility lane rather than the default shipped lane.
- [x] (2026-04-19 20:34 MDT) Identified the main remaining gap: the repository has several focused hostile tests and review artifacts, but it still lacks one attack-driven proving campaign that ties those pieces together and enforces them as a release gate.
- [x] (2026-04-19 20:34 MDT) Identified and recorded a concrete docs-to-CI mismatch: `docs/SECURITY_REVIEWS.md` names a `security-adversarial` CI job that does not currently exist in `.github/workflows/ci.yml`.
- [x] (2026-04-20 03:47 MDT) Added [docs/crypto/proving_attack_matrix.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/proving_attack_matrix.md) and [scripts/run_proving_redteam.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/run_proving_redteam.sh) so the proving system has one explicit hostile runner and one explicit attack inventory.
- [x] (2026-04-20 03:47 MDT) Turned the current byte-boundary, semantic-aliasing, staged-artifact, recursive-block, receipt-root, prover-downgrade, and review-package checks into the merge-blocking `security-adversarial` CI gate in [.github/workflows/ci.yml](/Users/pldd/Projects/Reflexivity/Hegemon/.github/workflows/ci.yml).
- [x] (2026-04-20 03:47 MDT) Added explicit byte budgets plus reject-instead-of-evict semantics for pending ciphertext/proof staging, and narrowed proof-store lock scope so expensive proof prevalidation no longer runs under the shared store mutex.
- [x] (2026-04-20 03:47 MDT) Made the wallet prover’s production floor directly testable, kept fast proving behind explicit override semantics, and added regression coverage for the downgrade boundary in [wallet/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs).
- [x] (2026-04-20 03:47 MDT) Reconciled the docs, runbook, contributor guide, and CI so the proving hardening campaign is now a real release gate instead of an internal note.

## Surprises & Discoveries

- Observation: the repository documentation already describes a stronger adversarial testing posture than the actual workflow file enforces.
  Evidence: [docs/SECURITY_REVIEWS.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/SECURITY_REVIEWS.md:109) says a `security-adversarial` CI job runs the hostile harnesses on every push/PR, but [.github/workflows/ci.yml](/Users/pldd/Projects/Reflexivity/Hegemon/.github/workflows/ci.yml:81) only defines `native-backend-security` plus the ordinary lint, test, and build jobs.

- Observation: the current shipped proving path is narrower than the historical naming still scattered through the repo.
  Evidence: [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md:209) and [DESIGN.md](/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md:557) both say the fresh-chain product line is `tx_leaf -> recursive_block`, while `receipt_root` survives only as an explicit alternate native lane.

- Observation: byte-boundary and statement-binding checks are already stronger than the current public confidence level suggests.
  Evidence: [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs:525) exact-checks the tx-leaf envelope kind, verifier profile, size cap, receipt profile, canonical artifact hash, and proof verification against the public tx view before producing a verified record, and [node/src/substrate/rpc/da.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/rpc/da.rs:282) prevalidates staged native artifacts before inserting them into the pending proof store.

- Observation: the weakest remaining technical seam is not “accepts fake proof bytes”; it is “under pressure, do the bounded local coordination surfaces stay bounded and observable.”
  Evidence: the current DA staging RPC has per-request byte caps in [node/src/substrate/rpc/da.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/rpc/da.rs:342) and [node/src/substrate/rpc/da.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/rpc/da.rs:402), but this plan has not yet confirmed global pending-store caps, eviction policy, or release-time observability for proof-related memory growth.

- Observation: the wallet prover defaults are sensible, but the crate still exposes an explicitly weaker local proving config.
  Evidence: [wallet/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs:90) defaults `local_self_check_policy` to `Always`, but [wallet/src/prover.rs](/Users/pldd/Projects/Reflexivity/Hegemon/wallet/src/prover.rs:109) still exposes `StarkProverConfig::fast()` with `num_queries: 1` and calls it out as “lower security margin.”

- Observation: the adversarial test inventory is fragmented and one of the more useful consensus fuzz tests is still ignored by default.
  Evidence: [tests/security_pipeline.rs](/Users/pldd/Projects/Reflexivity/Hegemon/tests/security_pipeline.rs:73) is intentionally lightweight, while [consensus/tests/fuzz.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/tests/fuzz.rs:21) marks the duplicate-nullifier property test as ignored/manual.

## Decision Log

- Decision: focus this campaign on the current product proof line plus the explicit compatibility lane that still executes real verification code.
  Rationale: the shipped path is `tx_leaf -> recursive_block`, so that is where release-grade hardening matters most. The `receipt_root` lane still needs hostile coverage because it remains executable and documented, but removed historical lanes such as legacy product `InlineTx` should not consume more hardening time than strict reject tests.
  Date/Author: 2026-04-19 / Codex

- Decision: treat attack-driven hardening as one integrated repo capability, not a collection of disconnected “hostile” plans.
  Rationale: the existing plans and tests are useful, but a new contributor cannot currently answer the question “what do I run to attack the proving system and what exactly should fail closed.” One coherent runner, one matrix, and one CI gate are worth more than five scattered notes.
  Date/Author: 2026-04-19 / Codex

- Decision: keep cryptographic external review as a first-class workstream inside this plan, but do not block implementation hardening on review completion.
  Rationale: the code can and should be hardened now against malformed artifacts, resource exhaustion, and unsafe configuration. External cryptanalysis of the native backend remains mandatory, but it is parallel work rather than an excuse to leave obvious operational attack surfaces loose.
  Date/Author: 2026-04-19 / Codex

- Decision: make the attack campaign produce observable evidence on disk.
  Rationale: if the hostile suite only prints scrollback in CI logs, it will rot. A generated artifact directory with a summary file, command transcript, and failing test seed gives operators and reviewers something concrete to compare between runs.
  Date/Author: 2026-04-19 / Codex

## Outcomes & Retrospective

Implemented. The repo can now answer “how hardened is the proving system” with a reproducible hostile campaign, a named CI gate, and a narrower list of remaining cryptographic gaps instead of a mix of notes and tribal memory.

The important shipped deltas are:

- The proving system now has one explicit attack matrix in [docs/crypto/proving_attack_matrix.md](/Users/pldd/Projects/Reflexivity/Hegemon/docs/crypto/proving_attack_matrix.md) and one explicit hostile runner in [scripts/run_proving_redteam.sh](/Users/pldd/Projects/Reflexivity/Hegemon/scripts/run_proving_redteam.sh).
- The `security-adversarial` job now exists in CI and is wired into the blocking release path.
- Pending staged ciphertext/proof memory is now bounded by both entry count and total bytes, and over-cap requests fail closed instead of evicting existing staged sidecars.
- The proof staging RPC no longer holds the shared pending-proof mutex across expensive artifact decode/self-verification.
- Wallet fast-proof downgrades now have direct regression coverage for the production-floor clamp.

The largest remaining out-of-scope item is not implementation hygiene but deeper cryptographic maturity. The native backend still needs external review and continued fuzz/timing work beyond the `ci` red-team minimum.

## Context and Orientation

The proving system in this repository has three layers that matter for hostile input.

The first layer is the transaction proof layer. Wallets build `tx_leaf` artifacts from witnesses in `wallet/src/tx_builder.rs`, `wallet/src/prover.rs`, and the native backend crates under `circuits/superneo-*`. The current consensus-facing verifier for those artifacts is in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs:525). In this repository, a “tx-leaf artifact” means the proof-carrying byte string that proves one shielded transaction’s public semantics and binds them to a receipt, a verifier profile, and a canonical public tx view.

The second layer is the block aggregation layer. The shipped product path uses a constant-size `recursive_block` artifact that replays the verified tx-leaf records plus block semantic inputs, as documented in [METHODS.md](/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md:209) and implemented in [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs:79) and [consensus/src/proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/consensus/src/proof.rs:1728). The alternate `receipt_root` lane remains executable and has a different performance profile and a different attack surface because it verifies a hierarchical root object rather than the shipped recursive block object.

The third layer is the author-local coordination surface. Proof sidecars and ciphertext sidecars can still be staged through the DA RPC in [node/src/substrate/rpc/da.rs](/Users/pldd/Projects/Reflexivity/Hegemon/node/src/substrate/rpc/da.rs:318). Candidate assembly and artifact preparation happen through the node service and production-service code in `node/src/substrate/service.rs`, `node/src/substrate/receipt_root_builder.rs`, and `node/src/substrate/rpc/production_service.rs`. These surfaces are not consensus validity by themselves, but they are still attackable because they consume untrusted or semi-trusted proof bytes before block authoring.

In this plan, “attacking the proving system” means trying to make one of those layers do something it must never do. The important attack classes are:

“Parser malleability,” meaning alternate encodings, trailing bytes, truncated bytes, or cross-profile payloads that are wrongly accepted as the same proof object.

“Semantic aliasing,” meaning valid proof bytes are attached to the wrong transaction, the wrong statement digest, the wrong binding hash, or the wrong block semantic tuple.

“Resource exhaustion,” meaning an attacker cannot forge validity but can still force the node to spend unbounded memory, CPU, or cache capacity on staged proofs, repeated candidate rebuilding, or cold verification work.

“Configuration downgrade,” meaning a weaker proving or verification setting is accidentally available on the live path without an explicit unsafe switch and a visible warning.

“Assurance drift,” meaning the code, docs, and review package make stronger claims than the actual proving object justifies.

## Plan of Work

### Milestone 1: Build one explicit attack inventory and one explicit red-team runner

Start by giving the proving system one single place where the hostile story is written down honestly. Add `docs/crypto/proving_attack_matrix.md`. This file must enumerate the current attack classes, the entry point for each one, the file that enforces rejection today, the file that still needs work, and the exact command that demonstrates the defense. This document must not be a literature survey. It must be an operator-facing map from attack class to code path.

Add `scripts/run_proving_redteam.sh`. This script will be the user-visible entry point for the entire campaign. It must run from the repository root, create `output/proving-redteam/<timestamp>/`, capture command output into named transcript files, and write a compact `summary.json` or `summary.txt` that records pass/fail for each hostile campaign. The initial campaigns should be named directly after the attack classes in the matrix: parser malleability, semantic aliasing, staged-proof abuse, recursive-block mismatch, receipt-root tamper, prover-configuration downgrade, and review-package parity.

Do not make the runner magical. It should be a thin orchestrator around existing cargo tests, fuzz targets, and package checks. The value is that one human or one CI job can run it and know what the proving system’s hostile posture is that day.

At the same time, reconcile the documentation with reality. Update `docs/SECURITY_REVIEWS.md` and `runbooks/security_testing.md` so they no longer claim a CI job that does not exist. The docs must point at the new red-team runner and the actual workflow job that invokes it.

### Milestone 2: Turn proof-byte and semantic-binding attack classes into an explicit hostile suite

The next step is to stop relying on scattered point fixes and instead name the specific proof-boundary attacks the repository promises to reject.

Extend the hostile tests around `consensus/src/proof.rs`, `node/src/substrate/rpc/da.rs`, `node/src/substrate/rpc/production_service.rs`, `node/src/substrate/transaction_pool.rs`, `circuits/block-recursion/src/tests.rs`, and `consensus/tests/raw_active_mode.rs`. Every one of the following cases needs a deterministic regression that fails before the relevant fix and passes after it:

1. A valid native `tx_leaf` artifact is attached to the wrong public transaction and is rejected by tx-view verification.
2. A claim, receipt, or statement commitment is tampered while the underlying proof bytes remain valid, and block verification rejects the mismatch.
3. A staged proof carries the wrong `binding_hash`, the wrong verifier profile, or a different byte string for an already-staged hash, and the DA RPC rejects it.
4. A non-empty shielded block tries to use the wrong aggregation mode or carry forbidden `commitment_proof` bytes on the recursive lane, and import rejects it.
5. A recursive-block artifact with valid shape but mismatched semantic replay data is rejected.
6. A restarted node that lost sidecar RAM state cannot “recover” validity from stale proofless extraction or stale cached artifacts.

Where the repo already has a narrow regression, keep it and rename or regroup it so the attack class is obvious from the test name. Where the current test is too slow or too broad for CI, add a deterministic reduced version that captures the same exploit shape. In particular, the manual/ignored consensus fuzz in `consensus/tests/fuzz.rs` should either be promoted into a cheaper always-on deterministic regression or be mirrored by one that exercises the same invariant on a tiny case.

Extend the fuzz targets under `fuzz/fuzz_targets/` so they are not just decoder smoke tests. The current `native_tx_leaf_artifact` and `receipt_root_artifact` fuzzers already exist; extend them with seeded malicious corpus entries that represent known exploit families from the attack matrix. The goal is not brute-force proof cryptanalysis. The goal is continuous mutation of the wire formats and semantic bindings that real code paths consume.

### Milestone 3: Harden the proof-related bounded local surfaces against exhaustion

The proving system does not need a forged proof to fail operationally. A miner or proposer can be hurt just as badly by proof-related memory blowups, cache churn, or repeated impossible candidate work. This is the next big hardening milestone.

Audit and then bound the pending proof and ciphertext stores in `node/src/substrate/rpc/da.rs`. The current code has per-request caps. This milestone must add explicit global entry and byte caps, deterministic eviction or rejection rules, and visible rejection metrics. The same treatment must be applied to prepared artifact caches or proof-adjacent candidate queues in `node/src/substrate/service.rs`, `node/src/substrate/receipt_root_builder.rs`, and any proof-verification cache that can grow under attacker influence.

Every new bound must come with two tests: one that proves honest small workloads still pass, and one that proves the hostile condition is rejected without silently widening acceptance or leaking unbounded memory. The hostile runner should include at least one repeated-stage or repeated-candidate scenario that drives the code to the new limits and records the correct failure mode.

This milestone also has to capture observability. Add metrics or structured logs that record the reason a staged proof, staged ciphertext, or prepared candidate was rejected. If a red-team run fails because the node hit a cap, the operator needs to know whether that was a proof-size cap, a global pending-store cap, a verifier-profile mismatch, or a stale-parent artifact problem.

### Milestone 4: Lock down local prover shortcuts and timing hygiene

The live path can still be weakened accidentally if the wallet or local prover exposes faster but weaker profiles without clear boundaries. This milestone hardens that operator-facing seam.

Audit every caller of `wallet::StarkProverConfig`, especially `StarkProverConfig::fast()` and any use of `LocalProofSelfCheckPolicy::Never`. If a weaker mode is used only for tests or benchmarks, move it behind `#[cfg(test)]`, a benchmark-only helper, or a name that makes its unsafeness unmistakable. If a weaker mode must remain callable in production binaries, require an explicit unsafe flag or environment variable and log a conspicuous warning that includes the active parameters.

Keep the current good behavior that local self-check defaults to `Always` and make it harder to regress. Add tests that prove the default shipped wallet path still performs the self-check, and add one hostile regression that fails if the live path routes through a weaker proving profile than the witness version expects.

Add one timing-hygiene task that is honest about scope. The repository already says the timing harness is a regression screen, not a proof. Make that concrete by ensuring the red-team runner invokes the timing harness, archives the output, and fails only on obvious regressions such as new data-dependent branches or widened timing deltas beyond an agreed threshold. Do not pretend this delivers a formal constant-time proof. The purpose is to stop accidental timing regressions from landing quietly.

### Milestone 5: Make the attack campaign a real release gate

Once the hostile suite exists, wire it into the actual workflow. Add a real CI job in `.github/workflows/ci.yml` named `security-adversarial` or rename the docs to match the final chosen name exactly. The important point is consistency. That job must run the new red-team runner, the native backend package verification, and the focused adversarial tests that are cheap enough for every PR.

Keep the heavier fuzzers and timing harness in the same job or in a sibling security job, but the top-level docs must describe the real workflow names and the real commands. The release-build job must depend on the proving red-team gate.

Finish by updating `docs/SECURITY_REVIEWS.md`, `runbooks/security_testing.md`, and any proof-assurance docs that currently overstate or scatter the proving hardening story. The documentation must say, in plain language, which exploit families are blocked mechanically today, which are still open research or external-review questions, and which command proves each statement.

## Concrete Steps

All commands in this plan run from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

The implementation sequence should be:

1. Add `docs/crypto/proving_attack_matrix.md` and `scripts/run_proving_redteam.sh`.
2. Add or rename the targeted hostile regressions in:
   `consensus/src/proof.rs`,
   `consensus/tests/raw_active_mode.rs`,
   `node/src/substrate/rpc/da.rs`,
   `node/src/substrate/rpc/production_service.rs`,
   `node/src/substrate/transaction_pool.rs`,
   `circuits/block-recursion/src/tests.rs`,
   and any proof-relevant fuzz targets under `fuzz/fuzz_targets/`.
3. Add bounds, eviction/rejection logic, and observability for proof-adjacent pending stores and caches.
4. Tighten wallet prover configuration boundaries in `wallet/src/prover.rs`.
5. Update `.github/workflows/ci.yml`, `docs/SECURITY_REVIEWS.md`, and `runbooks/security_testing.md`.

The minimum red-team runner should execute and archive the outputs of:

    cargo test -p transaction-circuit --test security_fuzz -- --nocapture
    cargo test -p network --test adversarial -- --nocapture
    cargo test -p wallet --test address_fuzz -- --nocapture
    cargo test security_pipeline -- --nocapture
    cargo test -p consensus --test raw_active_mode -- --ignored --nocapture
    cargo test -p hegemon-node receipt_root -- --nocapture
    cargo test -p hegemon-node extract_inline_transfer_accepts_native_tx_leaf_payload -- --nocapture
    cargo +nightly fuzz run native_tx_leaf_artifact -- -max_total_time=30
    cargo +nightly fuzz run receipt_root_artifact -- -max_total_time=30
    cargo run -p native-backend-ref -- verify-vectors testdata/native_backend_vectors
    cargo run -p native-backend-timing --release
    ./scripts/package_native_backend_review.sh
    ./scripts/verify_native_backend_review_package.sh

After the runner exists, the manual acceptance command should be:

    bash scripts/run_proving_redteam.sh

Expected post-implementation behavior is:

    created output/proving-redteam/2026-.../
    [PASS] parser-malleability
    [PASS] semantic-aliasing
    [PASS] staged-proof-abuse
    [PASS] recursive-block-mismatch
    [PASS] receipt-root-tamper
    [PASS] prover-config-downgrade
    [PASS] review-package-parity
    summary written to output/proving-redteam/.../summary.json

If a campaign fails, the runner must exit non-zero and point at the transcript file or failing test name.

## Validation and Acceptance

This plan is complete only when all of the following are true.

First, a contributor can run `bash scripts/run_proving_redteam.sh` and get one dated output directory with a machine-readable summary plus command transcripts.

Second, the hostile suite covers the current proving exploit families that still matter on the shipped product path: malformed wire bytes, swapped or stale proof semantics, staged-proof misuse, resource exhaustion on proof-related local stores, and local prover configuration downgrade.

Third, the workflow file contains a real release-blocking job that runs the proving red-team suite, and the docs use that job name exactly.

Fourth, the hostile suite includes at least one reduced deterministic regression for every issue class that was previously fixed by the hostile proof-boundary and hostile exploit review plans, so those fixes do not live only in historical narrative.

Fifth, the docs are honest about the remaining cryptographic state. The red-team suite should prove that the implementation rejects known exploit classes. It must not pretend that this replaces the unfinished external cryptanalysis of the native backend.

## Idempotence and Recovery

The runner and the tests in this plan must be safe to rerun. Generated artifacts go under `output/proving-redteam/` and may be deleted between runs without changing repository state. Temporary node base paths or local stores created by hostile tests must live under `output/` or `/tmp` and clean up after themselves on success. If a red-team run is interrupted, it should be safe to delete the partially written timestamped directory and rerun the script.

Bounds introduced by this plan must fail closed by rejection, not by silently dropping into a weaker verification path. When a new cap or eviction rule causes an unexpected honest failure during implementation, raise the cap only with a matching hostile test and an updated rationale in this document.

## Artifacts and Notes

Capture the first good run of:

    bash scripts/run_proving_redteam.sh

and record the resulting summary path here when implementation begins.

Important evidence that should be archived by the runner includes:

    the exact cargo test names for each hostile regression,
    the fuzz target names and durations,
    the native backend review-package verification output,
    and any limit-hit messages from staged-proof or candidate-cache rejection tests.

When the plan is revised during implementation, append a short revision note at the bottom naming what changed and why.

## Interfaces and Dependencies

The final repository state must contain these concrete interfaces and files.

In `scripts/run_proving_redteam.sh`, define one stable entry point that:

    runs the proving-hostile commands from the repository root,
    writes outputs under output/proving-redteam/<timestamp>/,
    emits a compact summary file,
    and exits non-zero on the first or final failed campaign.

In `docs/crypto/proving_attack_matrix.md`, define one prose-first inventory that maps each proving attack class to:

    the trust boundary,
    the enforcing file or module,
    the reproducer command,
    and the current status (covered, partially covered, or remaining work).

In `.github/workflows/ci.yml`, expose one real proving security gate whose name matches the docs exactly and that depends on the runner or the same underlying commands.

In `wallet/src/prover.rs`, the end state must preserve:

    `LocalProofSelfCheckPolicy::Always` as the default for the live path,

and must make any weaker proving profile obviously non-default and explicitly unsafe.

In `consensus/src/proof.rs`, `node/src/substrate/rpc/da.rs`, `node/src/substrate/rpc/production_service.rs`, and `circuits/block-recursion/src/tests.rs`, the end state must include deterministic hostile regressions that demonstrate fail-closed behavior for the attack classes listed in the matrix.

Revision note (2026-04-19 / Codex): created this plan after reassessing the current proving posture. The immediate need is no longer another one-off proof bug fix; it is one coherent attack-driven hardening campaign that turns the existing hostile checks, fuzzers, and review artifacts into a release-grade proving security gate.
