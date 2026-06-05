# Security Sweep to Clear Exploit Reports

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root. It is intentionally self-contained so a contributor with only this working tree can continue the sweep.

## Purpose / Big Picture

The goal is to keep attacking Hegemon’s current 0.10.0 branch until the repository’s security reports come back clear, then deploy the fixed branch to `hegemon-dev` and prove that mining and transaction/action flows still work. A clear report means the dependency audit gate has no unwaived findings, the PQ-only audit does not fail on false positives or real classical-crypto use, the adversarial proving suite passes, and targeted malformed-input tests reject counterfeit or replay attempts on proof, bridge, networking, and transaction trust boundaries.

## Progress

- [x] (2026-06-05T14:43:03Z) Read `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md` to align the sweep with documented protocol posture.
- [x] (2026-06-05T14:43:03Z) Confirmed local branch `codex/superneo-experiment` is clean at `ae4ca57730ed9589b218a57f19e1e37d775697c3`.
- [x] (2026-06-05T14:43:03Z) Located the active security gates: `scripts/dependency-audit-gate.sh`, `scripts/security-audit.sh`, `scripts/run_proving_redteam.sh`, and CI jobs in `.github/workflows/ci.yml`.
- [x] (2026-06-05T14:43:03Z) Ran `bash scripts/dependency-audit-gate.sh`; it passed with 11 total findings, all explicitly waived in `config/dependency-audit-waivers.json`.
- [x] (2026-06-05T14:43:03Z) Ran `bash scripts/security-audit.sh --quick`; it failed on a Groth16 string in the RISC Zero bridge receipt rejection branch.
- [x] (2026-06-05T14:49:00Z) Fixed the PQ-only audit so explicit reject-only code for forbidden primitive names is allowed while accept/verify/use paths still fail.
- [x] (2026-06-05T14:49:00Z) Reran `bash scripts/security-audit.sh --quick`; it passed. The only warning was that the local release node binary did not exist yet for symbol scanning.
- [x] (2026-06-05T15:21:00Z) Ran `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh`; all campaigns passed. Summary is `output/proving-redteam/20260605T144516Z/summary.txt`.
- [x] (2026-06-05T15:21:00Z) Removed generated native backend review package churn caused by running the packaging campaign with a dirty worktree. The audit tarball and checksum are back to their prior tracked state.
- [x] (2026-06-05T15:21:00Z) Tightened the PQ-only audit exemption so it only skips explicit reject strings and explicit reject match arms, then reran `bash scripts/security-audit.sh --quick`; it still passed.
- [x] (2026-06-05T15:21:00Z) Reran `bash scripts/dependency-audit-gate.sh`; it passed with 11 waived and 0 unwaived findings.
- [x] (2026-06-05T15:40:00Z) Added `inbound_bridge_rejects_message_binding_tampering` to reject replay-key mismatch, wrong destination, payload-hash mismatch, and receipt replay against a different internally consistent bridge message.
- [x] (2026-06-05T15:40:00Z) Added bounded trust-boundary byte parsing for `da_submitCiphertexts` and `da_submitProofs`, plus `rpc_byte_parser_rejects_oversized_strings_before_trust_boundary_decode`.
- [x] (2026-06-05T15:40:00Z) Wired both new regressions into `scripts/run_proving_redteam.sh`.
- [x] (2026-06-05T16:03:00Z) Added a `network-transport-abuse` red-team campaign covering PQ Noise public-transcript KEM seed regression, legacy secure-channel key/nonce abuse, and duplex handshake tampering.
- [x] (2026-06-05T16:03:00Z) Fixed `network/tests/adversarial.rs` so the tampered-acceptance proptest is registered and warning-free, then reran the network adversarial test file successfully.
- [x] (2026-06-05T17:22:00Z) Reran `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh`; all eight campaigns passed. Summary is `output/proving-redteam/20260605T163935Z/summary.txt`.
- [x] (2026-06-05T17:31:00Z) Replaced the stale `PROPTEST_MAX_CASES` env name with `PROPTEST_CASES` in active scripts, CI, and security docs; reran `PROPTEST_CASES=64 cargo test -p network --test adversarial -- --nocapture` cleanly.
- [x] (2026-06-05T18:18:00Z) Built the native node locally with `make node`.
- [x] (2026-06-05T19:08:00Z) Reran `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` after the proptest env cleanup; all eight campaigns passed. Summary is `output/proving-redteam/20260605T173053Z/summary.txt`.
- [x] (2026-06-05T19:08:00Z) Review and add focused regression tests for proof counterfeiting, bridge replay/message binding, transaction admission, network/PQ Noise, and codec malleability gaps found during code inspection.
- [ ] Push or otherwise deploy the fixed branch to `hegemon-dev`, restart the service from a clean release directory, and verify mining plus transaction/action inclusion.

## Surprises & Discoveries

- Observation: The dependency audit gate is wired into both CI and release workflows and passed locally, but it currently relies on waivers for 11 findings including `bincode 1.3.3`, yanked `keccak 0.1.5`, and `rand` advisories.
  Evidence: `bash scripts/dependency-audit-gate.sh` printed `dependency audit findings: 11 total, 11 waived, 0 unwaived`.
- Observation: The PQ-only audit fails even though the matching code rejects Groth16 receipts.
  Evidence: `bash scripts/security-audit.sh --quick` reported `node/src/native/mod.rs:3379: risc0_zkvm::InnerReceipt::Groth16(_)` and the next line returns `RISC Zero Groth16 receipts are not accepted on the PQ bridge path`.
- Observation: The fixed PQ-only audit now clears the Groth16 rejection branch while still scanning for actual forbidden primitive names.
  Evidence: `bash scripts/security-audit.sh --quick` exited 0 and printed `No forbidden cryptographic primitives detected`.
- Observation: The CI-mode red-team suite passed all configured campaigns.
  Evidence: `output/proving-redteam/20260605T144516Z/summary.txt` shows `overall=pass` and pass results for parser malleability, semantic aliasing, staged proof abuse, recursive block mismatch, receipt-root tamper, prover configuration downgrade, and review-package parity.
- Observation: The native backend review package campaign mutates the checked-in tarball when the worktree is dirty because `package_native_backend_review.sh` includes a `code_fingerprint.json` over tracked diffs and untracked files.
  Evidence: after the campaign, `git status --short` showed modified `audits/native-backend-128b/native-backend-128b-review-package.tar.gz` and `audits/native-backend-128b/package.sha256`; those changes were restored because they represented packaging churn from this in-progress sweep, not a source fix.
- Observation: Inbound bridge validation had strong checks, but existing tests did not directly cover replay-key mismatch, wrong destination, payload hash mismatch, or receipt replay against a different internally consistent message.
  Evidence: Added `native::tests::inbound_bridge_rejects_message_binding_tampering`; `cargo test -p hegemon-node inbound_bridge_rejects_message_binding_tampering -- --nocapture` passed.
- Observation: DA ciphertext/proof upload decoded base64 or hex before applying the decoded-size cap.
  Evidence: `parse_bytes_value` had no max parameter and callers checked length only after decoding. It now prechecks hex/base64 text length, verifies decoded length after decoding, and the regression `rpc_byte_parser_rejects_oversized_strings_before_trust_boundary_decode` passed.
- Observation: `network/tests/adversarial.rs` had a tampered acceptance proptest in source, but it was not registered as a test because the `#[test]` attribute was missing inside `proptest!`.
  Evidence: `cargo test -p network --test adversarial -- --list` initially listed only 3 tests; after the fix it lists and runs 4 tests, including `tampered_acceptance_is_rejected`.
- Observation: The red-team runner exported `PROPTEST_MAX_CASES`, which current proptest treats as an unknown environment variable.
  Evidence: `network-transport-abuse.log` from `output/proving-redteam/20260605T163935Z/` printed `proptest: Ignoring unknown env-var PROPTEST_MAX_CASES`; active scripts and docs now use `PROPTEST_CASES`, with compatibility migration and `unset PROPTEST_MAX_CASES` inside scripts.
- Observation: The exact-current-worktree red-team rerun is clean after the proptest env cleanup.
  Evidence: `output/proving-redteam/20260605T173053Z/summary.txt` shows `overall=pass` and pass results for parser malleability, semantic aliasing, staged proof abuse, recursive block mismatch, receipt-root tamper, prover configuration downgrade, network transport abuse, and review-package parity.

## Decision Log

- Decision: Treat false-positive audit failures as security defects.
  Rationale: A noisy gate makes it harder to trust “reports are clear” and can lead operators to ignore the gate. The fix must keep the gate strict for actual use of forbidden primitives.
  Date/Author: 2026-06-05 / Codex.
- Decision: Keep `hegemon-dev` as the test target and do not touch `hegemon-ovh`.
  Rationale: The user clarified that `hegemon-dev` is for the new branch and `hegemon-ovh` is the testnet.
  Date/Author: 2026-06-05 / Codex.

## Outcomes & Retrospective

No outcome yet. This section will be updated when the current sweep either clears all reports or records a remaining blocker.

## Context and Orientation

Hegemon is a Rust workspace for a post-quantum proof-native chain. The current branch is `codex/superneo-experiment`. The native node crate is `node`, consensus logic is in `consensus`, proof circuits and native proof adapters are under `circuits`, the bounded PQ transport is in `network` and `pq-noise`, wallet code is in `wallet`, and protocol bridge/action wire types are in `protocol/kernel`.

The most important trust boundaries for this sweep are:

1. Dependency and primitive gates. `scripts/dependency-audit-gate.sh` parses `cargo audit --json` and requires every advisory or yanked crate to match an explicit waiver in `config/dependency-audit-waivers.json`. `scripts/security-audit.sh` scans for forbidden classical primitives such as Groth16, Ed25519, X25519, ECDSA, pairings, and Halo2.
2. Proof bytes and public statement binding. `consensus`, `circuits/tx-proof-manifest`, `circuits/block-recursion`, `circuits/superneo-hegemon`, and `node/src/native/mod.rs` decode proof artifacts and must reject trailing bytes, shape mismatches, stale profile selectors, mismatched public inputs, and legacy downgrade paths.
3. Bridge messages and replay protection. `protocol/kernel/src/bridge.rs` defines bridge message roots and replay keys. `node/src/native/mod.rs` decodes inbound/outbound bridge actions, verifies RISC Zero receipts, rejects Groth16 bridge receipts, stages replay keys, and exports bridge witnesses.
4. Transaction admission and block import. `node/src/native/mod.rs` validates local RPC actions, pending actions, nullifiers, ciphertext counts, proof sidecars, coinbase actions, ordering, and canonical state replay.
5. Network and PQ Noise. `network` and `pq-noise` implement PQ identity, handshake, frame codecs, AEAD keys/nonces, and adversarial handshake tests. These must keep secrets from public transcripts, split send/receive keys, and bound frame sizes.

## Plan of Work

First, fix any report surfaces that already fail before deeper work. The immediate failing report is the PQ-only audit false positive around a branch that rejects RISC Zero Groth16 receipts. The audit script should allow matches only when the nearby source context is clearly reject-only, for example when it contains “not accepted”, “reject”, “unsupported”, or returns an error. It must still fail on dependency names, imports, verification calls, or any code path that accepts a forbidden primitive.

Second, run the existing merge-blocking adversarial proving suite with `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh`. If any campaign fails, inspect the campaign log under `output/proving-redteam/<timestamp>/`, fix the root cause, add or improve a regression test, and rerun the failed campaign plus the full CI-mode red-team script.

Third, inspect active trust-boundary code and add targeted negative tests for any gap not already covered. The expected high-value tests are counterfeit proof rejection, exact/canonical decoding, bridge receipt kind rejection, bridge message payload/replay binding, nullifier duplicates across pending and imported actions, ciphertext/proof sidecar binding, PQ handshake tampering/replay, and bounded frame rejection.

Fourth, run the dependency gate, PQ-only audit, core adversarial tests, and native build. Record command outputs in this plan.

Fifth, deploy the resulting commit to `hegemon-dev` from a clean release directory. Preserve the existing service backup pattern under `/home/ubuntu/hegemon-devnet/deploy-backups`, restart `hegemon-node.service`, verify NTP/chrony health, verify mining height/blocks advance, submit a real `hegemon_submitAction` smoke action, wait for inclusion, confirm pending clears, and export a bridge witness for the included action.

## Concrete Steps

Run commands from the repository root `/Users/pldd/Projects/Reflexivity/Hegemon` unless otherwise stated.

Current command evidence:

    git branch --show-current
    codex/superneo-experiment

    git rev-parse HEAD
    ae4ca57730ed9589b218a57f19e1e37d775697c3

    bash scripts/dependency-audit-gate.sh
    dependency audit findings: 11 total, 11 waived, 0 unwaived

    bash scripts/security-audit.sh --quick
    AUDIT PASSED
    No forbidden cryptographic primitives detected.
    Warning: release node binary not found; run 'make node' for binary scan

After fixes, rerun:

    bash scripts/dependency-audit-gate.sh
    dependency audit findings: 11 total, 11 waived, 0 unwaived

    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh
    Summary: output/proving-redteam/20260605T144516Z/summary.txt
    overall=pass

    cargo test -p hegemon-node inbound_bridge_rejects_message_binding_tampering -- --nocapture
    test native::tests::inbound_bridge_rejects_message_binding_tampering ... ok

    cargo test -p hegemon-node rpc_byte_parser_rejects_oversized_strings_before_trust_boundary_decode -- --nocapture
    test native::tests::rpc_byte_parser_rejects_oversized_strings_before_trust_boundary_decode ... ok

    cargo test -p pq-noise handshake_does_not_use_public_transcript_as_kem_seed -- --nocapture
    test handshake::tests::handshake_does_not_use_public_transcript_as_kem_seed ... ok

    cargo test -p network --test adversarial -- --nocapture
    test result: ok. 4 passed; 0 failed

    cargo test -p network --test handshake duplex_stream_handshake_succeeds_and_rejects_tampering -- --nocapture
    test duplex_stream_handshake_succeeds_and_rejects_tampering ... ok

    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh
    Summary: output/proving-redteam/20260605T163935Z/summary.txt
    overall=pass

    PROPTEST_CASES=64 cargo test -p network --test adversarial -- --nocapture
    test result: ok. 4 passed; 0 failed

    make node
    Finished `release` profile [optimized] target(s) in 9m 29s

    bash scripts/security-audit.sh --quick
    AUDIT PASSED
    Checking: /Users/pldd/Projects/Reflexivity/Hegemon/target/release/hegemon-node
    No forbidden ECC symbols

    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh
    Summary: output/proving-redteam/20260605T173053Z/summary.txt
    overall=pass

After deeper local fixes, rerun:

    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh
    make node

Deployment steps will be written with exact commit and remote paths once local reports clear.

## Validation and Acceptance

The sweep is accepted only when all of the following are true:

1. `bash scripts/security-audit.sh --quick` exits 0 and does not ignore any actual forbidden primitive usage.
2. `bash scripts/dependency-audit-gate.sh` exits 0 and prints no unwaived findings.
3. `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` exits 0 and writes a summary with `overall=pass`.
4. Any newly discovered exploit class has a regression test that fails before the fix and passes after.
5. `make node` builds the native release binary.
6. On `hegemon-dev`, the updated service runs from the new release path, mining is active, height or `blocks_found` increases after restart, a real action is accepted and mined, pending actions clear, and bridge witness export succeeds for the mined action.

## Idempotence and Recovery

Local test commands are safe to rerun. The red-team runner writes timestamped logs under `output/proving-redteam/`. Deployment to `hegemon-dev` must use a new release directory instead of editing the dirty remote source checkout. Before changing systemd, copy the current unit into `/home/ubuntu/hegemon-devnet/deploy-backups/`. If the new service fails, restore the backed-up unit, run `sudo systemctl daemon-reload`, and restart `hegemon-node.service`.

## Artifacts and Notes

The first concrete artifact is this plan. As each report is rerun, paste only concise evidence here: command, exit status, summary line, and the path to detailed logs.

## Interfaces and Dependencies

The sweep uses only existing project tools and standard Rust commands. It may use `ssh hegemon-dev` for deployment and RPC smoke tests. No destructive remote commands are allowed. On shared mining environments, use the approved seed list through `HEGEMON_SEEDS` and keep NTP or chrony enabled; `hegemon-dev` is a dev box and may intentionally have zero peers.

Revision note 2026-06-05T14:43:03Z: Created the plan after initial report discovery so the remaining sweep can be resumed from a concrete checklist and evidence trail.

Revision note 2026-06-05T14:49:00Z: Recorded the PQ-only audit fix and passing rerun before starting the adversarial proving suite.

Revision note 2026-06-05T15:21:00Z: Recorded passing CI-mode red-team evidence, dependency/PQ audit reruns, and the restoration of dirty-worktree review-package churn.

Revision note 2026-06-05T15:40:00Z: Recorded new bridge message-binding and bounded DA byte-parser regressions, plus their inclusion in the red-team runner.

Revision note 2026-06-05T16:03:00Z: Recorded network transport abuse campaign coverage and fixed the unregistered tampered-acceptance proptest.

Revision note 2026-06-05T17:31:00Z: Recorded the passing eight-campaign CI red-team report and the `PROPTEST_CASES` cleanup across scripts/CI/docs.

Revision note 2026-06-05T19:08:00Z: Recorded local release build, binary-inclusive PQ audit, and the exact-current-worktree red-team pass before deployment.
