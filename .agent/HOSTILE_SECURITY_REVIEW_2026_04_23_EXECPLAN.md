# Hostile Security Review and Critical Fixes

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`. It is self-contained so a contributor with only this repository can continue the review, reproduce the evidence, apply fixes, and validate local plus remote node behavior.

## Purpose / Big Picture

The goal is to attack Hegemon as if trying to steal funds, forge shielded transactions, split the chain, crash peers, or smuggle invalid proofs through consensus. After this work, critical and high severity issues found in the local hostile review are fixed, regression tests prove the fixes, the existing adversarial suites return clean, and both the local laptop and the remote `hegemon-dev` host can still mine and process transactions.

## Progress

- [x] (2026-04-23T19:23:32Z) Read the required project instructions, `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, `SECURITY.md`, `docs/THREAT_MODEL.md`, and `docs/SECURITY_REVIEWS.md`.
- [x] (2026-04-23T19:23:32Z) Confirmed the worktree started clean with `git status --short`.
- [x] (2026-04-23T19:23:32Z) Created this hostile-review ExecPlan.
- [x] (2026-04-23T19:56:36Z) Ran `bash scripts/security-audit.sh --quick`; it passed with only the pre-existing `wasm-objdump` warning.
- [x] (2026-04-23T20:00:00Z) Performed targeted manual review of consensus import, proof boundary parsing, unsigned shielded transfer admission, DA/RPC surfaces, mining/timestamp validation, PQ network handshake, and wallet submission paths.
- [x] (2026-04-23T20:02:00Z) Patched confirmed critical/high issues with regression tests covering PoW miner signatures, exact difficulty binding, proof-verification downgrade, and legacy handshake rekeying.
- [x] (2026-04-23T20:27:00Z) Re-ran hostile proving review until clean: `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` passed all campaigns under `output/proving-redteam/20260423T195636Z/`.
- [ ] Validate local laptop behavior: build, tests, mining, and transaction flow.
- [ ] Validate remote `hegemon-dev` behavior through SSH: build or deploy patched tree, mining, and transaction flow.
- [ ] Update `DESIGN.md`, `METHODS.md`, `docs/SECURITY_REVIEWS.md`, and runbooks only if the architecture, methods, or operator security guidance changes.

## Surprises & Discoveries

- Finding SEC-2026-0001: legacy `PowConsensus` accepted valid PoW without verifying that the block was signed by a registered miner key. Exploit impact was arbitrary miner impersonation on the legacy/custom consensus path.
- Finding SEC-2026-0002: the Substrate PoW verifier accepted near compact-difficulty mismatches and checked work against the seal's claimed bits. Exploit impact was block acceptance with slightly easier work than the runtime target selected.
- Finding SEC-2026-0003: non-production node builds could honor `HEGEMON_PARALLEL_PROOF_VERIFICATION=0` in import/production. Because `make node` builds a normal Substrate node, this was a consensus footgun that could follow blocks full verification rejects.
- Finding SEC-2026-0004: the legacy `PeerIdentity` handshake reused deterministic KEM seeds and transcript nonces for the same static identities. Reconnects could derive the same first AEAD key/nonce pair.
- The first red-team attempt before output redirection failed with empty campaign logs and runner exit 141; the redirected rerun wrote to `/tmp/hegemon-redteam-20260423.log` and passed under `output/proving-redteam/20260423T195636Z/`.

## Decision Log

- Decision: Treat proof parsing, consensus import, unsigned extrinsic admission, mining timestamp rules, and unsafe RPC boundaries as the first critical review targets.
  Rationale: The design documents identify these paths as consensus-critical and exposed to hostile network input; a bug here can create invalid state, forks, or remote denial of service.
  Date/Author: 2026-04-23 / Codex.
- Decision: Make proof verification mandatory in every node build rather than only behind the `production` feature.
  Rationale: The documented `make node` path produces a default Substrate build, and consensus validity must not be weakened by an environment variable in the build operators are told to run.
  Date/Author: 2026-04-23 / Codex.
- Decision: Preserve local authoring knobs for proof-lane selection, but bind imported PoW difficulty bits exactly to the runtime value.
  Rationale: Authoring policy can change what a miner chooses to build, but imported block validity must compare against one deterministic runtime target.
  Date/Author: 2026-04-23 / Codex.

## Outcomes & Retrospective

Patched findings so far:

- PoW miner identity binding now requires a registered miner ML-DSA key, exact ML-DSA signature length, no BFT signature bitmap, and signature verification over the header signing hash.
- Substrate PoW verification now rejects any compact difficulty-bit mismatch and checks work against the runtime `difficulty_bits` target.
- Block import/production now ignores `HEGEMON_PARALLEL_PROOF_VERIFICATION=0`.
- Legacy PQ handshakes now rekey every connection with OS-random KEM encapsulation seeds and transcript nonces.

Regression tests passed:

- `cargo test -p network --test handshake --test adversarial -- --nocapture`
- `cargo test -p consensus --test pow_rules -- --nocapture`
- `cargo test -p hegemon-node test_verify_pow_seal -- --nocapture`
- `cargo test -p hegemon-node test_proof_verification_env_disable_is_ignored -- --nocapture`
- `bash scripts/security-audit.sh --quick`
- `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh`

## Context and Orientation

Hegemon is a Rust workspace for a post-quantum, proof-of-work private chain. The consensus path lives in `consensus/` and `node/src/substrate/`. The runtime and pallets live in `runtime/` and `pallets/`. The transaction proof system lives under `circuits/transaction/`, `circuits/block-recursion/`, `circuits/superneo-*`, and the proof manifest crate. Wallet construction and submission live in `wallet/` and `walletd/`. Network and PQ transport live in `network/` and `pq-noise/`.

In this plan, "consensus-critical" means any code path that decides whether a block, transaction, proof artifact, or state transition is accepted by a node. A bug in that class can split honest nodes, mint or spend invalid funds, or let a remote attacker crash or stall nodes.

The repository already has security automation:

- `scripts/security-audit.sh` scans for forbidden non-PQ primitives and runtime symbols.
- `scripts/run_proving_redteam.sh` runs parser malleability, semantic aliasing, staged proof abuse, recursive block mismatch, receipt-root tamper, prover configuration downgrade, and review-package parity campaigns.
- `scripts/check-core.sh`, `scripts/shielded-e2e-test.sh`, `scripts/test-substrate.sh`, and `scripts/start-mining.sh` exercise core build, wallet, node, mining, and Substrate paths.

## Plan of Work

First, run the existing security and red-team scripts to establish a baseline. Capture exact failing commands and logs. Do not patch around failed tests without understanding whether the failure is infrastructure noise or an exploitable condition.

Second, manually inspect the highest-risk exposed paths. In `node/src/substrate/rpc/` inspect unsafe RPC gating, artifact staging, proof submission, and size limits. In `node/src/substrate/block_import.rs`, `template_builder.rs`, `transaction_pool.rs`, `proof_boundary.rs`, and `receipt_root_builder.rs`, inspect canonical decoding, ordering, native artifact verification, duplicate nullifier and binding rejection, and fail-closed behavior. In `consensus/src/`, inspect PoW validation, timestamp bounds, reward and supply digest checks, recursive aggregation, and version policy. In `pallets/shielded-pool/`, inspect unsigned extrinsic validation, aggregation mode, nullifier uniqueness, Merkle updates, reward minting, and artifact caps. In `wallet/`, inspect transaction construction and submission assumptions that could create accepted malformed transactions.

Third, write exploit-shaped tests before or alongside each fix. A useful test demonstrates the bad behavior by constructing hostile input: malformed proof bytes, noncanonical SCALE/bincode bytes, duplicate binding hashes, stale anchors, bad timestamps, mismatched recursive artifacts, unsafe RPC access, or oversized payloads. The fixed code must reject the hostile input without panic and without accepting a degraded mode.

Fourth, re-run the hostile suite. Repeat manual review on any changed path until the critical/high finding list is empty. Medium and low issues may be documented if they do not block the user's request, but critical and high issues must be fixed.

Finally, validate operation from both environments. On the laptop, run build/tests, start a dev node with mining, and submit or exercise a shielded transaction flow. On `hegemon-dev`, use `ssh hegemon-dev` to confirm the host can run the patched node, mine, and process transactions or the available smoke-test equivalent. Record exact command summaries and outcomes here.

## Concrete Steps

Run these commands from `/Users/pldd/Projects/Reflexivity/Hegemon` unless noted otherwise:

    git status --short
    bash scripts/security-audit.sh --quick
    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh
    cargo test -p consensus
    cargo test -p hegemon-node
    cargo test -p pallet-shielded-pool
    cargo test -p wallet

If a test command is too broad for the available time, run the relevant package or test target that covers the changed code and document the reason. Before finalizing, run the hostile suite again.

For local mining and transaction validation, prefer the project runbooks and scripts:

    make setup
    make node
    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
    bash scripts/shielded-e2e-test.sh

For remote validation:

    ssh hegemon-dev

Then locate or clone the Hegemon tree on the remote host, update it to the patched branch or transfer the patch, build the node, run mining, and run the same smoke or shielded e2e script available on that host.

## Validation and Acceptance

The review is accepted only when:

1. All confirmed critical/high issues discovered during this review are patched.
2. Each patch has a regression test or an existing hostile campaign that fails without the fix and passes with it.
3. `HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh` returns overall pass, or any remaining failure is proven unrelated infrastructure noise and documented with evidence.
4. Local laptop validation shows the node still builds, mines, and processes transactions through the available project smoke tests.
5. Remote `hegemon-dev` validation shows the same for the patched build.
6. `git diff` contains only deliberate code, test, and documentation changes.

## Idempotence and Recovery

Most commands are safe to repeat. Dev nodes should use `--tmp` or a disposable base path unless deliberately testing persistent sync. Do not delete user data or reset the repository. If a local node remains running, stop it cleanly before starting a new one on the same ports. If remote validation requires deployment, use a separate checkout or branch on `hegemon-dev` rather than mutating an unknown production directory.

## Artifacts and Notes

Artifacts will be recorded here as they are produced. Red-team logs are written under `output/proving-redteam/<timestamp>/`. Relevant output should be summarized rather than pasted wholesale.

## Interfaces and Dependencies

Critical functions and modules to verify include:

- `node::substrate::proof_boundary` for artifact canonicalization and native proof admission.
- `node::substrate::block_import` for block-level fail-closed validation.
- `node::substrate::template_builder` and `transaction_pool` for local production matching import rules.
- `node::substrate::rpc::{da, shielded, prover}` for unsafe RPC exposure and staging semantics.
- `consensus::{pow, substrate_pow, reward, aggregation, version_policy}` for PoW, timestamp, reward, and version acceptance.
- `pallet_shielded_pool::{validate_unsigned, submit_transfer, submit_proven_batch, submit_candidate_artifact, mint_coinbase}` for runtime admission and state mutation.
- `circuits::transaction::{proof, smallwood_*}` and `circuits::block_recursion` for parser malleability, proof/profile binding, and recursive artifact checks.
- `wallet::{tx_builder, submission, substrate_rpc}` for accepted transaction construction and hostile submission behavior.
