# Formal Blueprint DAG Gate

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md`. It builds on the checked-in formal-core milestone in `.agent/execplan-formal-core-20260606.md`, which created the branch-level formal security claims ledger and the `scripts/check_formal_core.sh` release gate.

## Purpose / Big Picture

Hegemon already has a machine-readable claims ledger and a release gate that checks formal inventory, bridge vectors, native backend vectors, and dependency posture. The next improvement is to prevent the most common formal-verification failure: proving or testing the wrong thing. After this change, each formal-security claim will live in a blueprint-style directed acyclic graph, meaning a graph whose nodes are claims and whose arrows name which claims depend on which others. Every node will carry a formal statement, a human-readable argument, implementation bindings, target-review status, and cheap falsification cases.

A contributor can run `bash scripts/check_formal_core.sh` from the repository root and observe a new blueprint-DAG step pass. If a production claim lacks target review, has a dangling dependency, forms a cycle, omits falsification cases, or names evidence paths that do not exist, the gate fails before CI or release can accept it.

## Progress

- [x] (2026-06-06T05:52:34Z) Created follow-on branch `codex/formal-blueprint-dag` from `codex/formal-verification-core`.
- [x] (2026-06-06T05:52:34Z) Re-read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, the existing formal-core ExecPlan, the claims ledger, the formal-core checker, and the formal-core shell gate.
- [x] (2026-06-06T06:13:00Z) Added `config/formal-security-blueprint.json` with one blueprint node per current security claim: 8 nodes, 10 edges, 6 production nodes, and 12 falsification cases.
- [x] (2026-06-06T06:13:00Z) Extended `scripts/hegemon_formal_core` with a strict `check-blueprint` command that cross-checks the blueprint against `config/formal-security-claims.json`.
- [x] (2026-06-06T06:13:00Z) Wired the blueprint check into `scripts/check_formal_core.sh` as step 6 of 9.
- [x] (2026-06-06T06:13:00Z) Updated `DESIGN.md`, `METHODS.md`, `docs/CONTRIBUTING.md`, `docs/SECURITY_REVIEWS.md`, `circuits/formal/README.md`, `consensus/spec/formal/README.md`, and `scripts/hegemon_formal_core/README.md` to describe the new standard truthfully.
- [x] (2026-06-06T06:13:00Z) Ran `cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml`; it passed 6 tests.
- [x] (2026-06-06T06:13:00Z) Ran `bash scripts/check_formal_core.sh`; it passed the new 9-step gate.
- [x] (2026-06-12T07:19:02Z) Hardened native timestamp RPC implementation equivalence by adding the production helper `timestamp_meta_by_height` in `node/src/native/mod.rs`, requiring `block_timestamps` to propagate hash/header storage decode failures instead of treating corrupt rows as missing data, and binding that helper in `config/formal-security-blueprint.json`.
- [x] (2026-06-12T07:19:02Z) Added the focused regression `timestamp_rpc_rejects_corrupt_explicit_range_header`, updated the formal-core documentation counts to 117 implementation bindings and 102 result obligations, and ran `cargo fmt --all -- --check`, the focused blueprint check, `cargo test -p hegemon-node timestamp_rpc_rejects_corrupt_explicit_range_header --lib --no-default-features -- --nocapture`, `git diff --check`, `bash scripts/check_formal_core.sh`, `cargo test -p hegemon-node --lib --no-default-features -- --nocapture`, and `cargo build --release -p hegemon-node --bin hegemon-node --no-default-features`.
- [x] (2026-06-12T07:31:25Z) Deployed the timestamp RPC fail-closed slice to `hegemon-dev` at commit `5aee82c7f7ef4079e57d2cc0dae9e8c918cce559`. The remote formal-core gate passed with 117 implementation bindings, 94 order constraints covering 276 order edges, 102 result obligations, 78 dominance constraints covering 233 dominance edges, 943 named Lean theorem declarations, and no temporary or unwaived axiom dependencies. The remote release binary SHA was `c20c6525bb640db624727218c9ebb9906ed505be6b008e70f11e4f0578955f76`.
- [x] (2026-06-12T07:31:25Z) Restarted `hegemon-node.service` on `hegemon-dev` after backing up the service unit to `/home/ubuntu/hegemon-devnet/deploy-backups/hegemon-node.service.20260612T072958Z`. Service PID `1311168` stayed active/running with zero restarts. RPC smoke showed `system_health` not syncing, consensus height `436645`, empty pending extrinsics, `rpcExternal=false`, `rpcMethods=unsafe`, NTP synchronized, `HEGEMON_MINE=1`, `HEGEMON_MINE_THREADS=1`, and `HEGEMON_MAX_PEERS=140`. `bash scripts/test-node.sh wallet-send` passed, the focused `timestamp_rpc_rejects_corrupt_explicit_range_header` regression passed, and mining advanced from height `436643`/`blocks_found=3` to height `436644`/`blocks_found=4` during the sample.
- [x] (2026-06-12T07:42:01Z) Hardened the next implementation-equivalence slice locally: `NativeNode::block_range` now materializes every admitted canonical sync row through `load_canonical_sync_block_at_height` and errors on missing height indexes, missing block records, height/hash mismatches, hash/work-hash mismatches, or parent discontinuity; `wallet_commitments` now decodes every commitment archive row through `decode_wallet_commitment_row` and errors on iterator errors, malformed keys, malformed values, or index gaps; `ciphertext_entries_page` now decodes every ciphertext archive row through `decode_wallet_ciphertext_row` and errors on iterator errors, malformed keys, too-short values, or oversized values.
- [x] (2026-06-12T07:42:01Z) Added focused regressions `block_range_rejects_*`, `wallet_commitments_rejects_*`, and `wallet_ciphertexts_rejects_*`; updated the blueprint to 120 implementation bindings, 95 order constraints covering 277 order edges, 105 result obligations, 79 dominance constraints covering 234 dominance edges, and 307 falsification cases; and ran the focused block-range tests, wallet archive tests, and blueprint checker successfully.
- [ ] Run full local formatting, formal-core, node-library, and release-build gates for the sync/wallet materialization slice, then deploy it to `hegemon-dev` and rerun remote smoke/mining/transaction validation.

## Surprises & Discoveries

- Observation: The existing claims ledger is intentionally flat.
  Evidence: `config/formal-security-claims.json` records claim ids, status, proof model, evidence, gates, and residual risks, but no dependency graph, target-review status, or falsification discipline.

- Observation: The current release gate is a good host for the next layer.
  Evidence: `scripts/check_formal_core.sh` already runs an isolated checker crate, audits that crate, checks the inventory, and verifies independent vectors. Adding one command preserves the same operator-facing interface.

- Observation: The real blueprint validates as a nontrivial graph rather than a flat mirror of the ledger.
  Evidence: `cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-blueprint config/formal-security-blueprint.json --claims config/formal-security-claims.json` reported `nodes = 8`, `edges = 10`, `production_nodes = 6`, and `falsification_cases = 12`.

- Observation: Strict parsing and path hygiene needed to be added to the existing checker as well as to the new blueprint structs.
  Evidence: The new checker uses `#[serde(deny_unknown_fields)]` on ledger/vector/blueprint structs and rejects absolute paths, empty paths, and parent-directory components before checking path existence.

- Observation: `hegemon-dev` had `cargo-audit` installed but not visible to non-interactive SSH shells.
  Evidence: `/home/ubuntu/.cargo/bin/cargo-audit` existed, but `bash scripts/check_formal_core.sh` failed with `cargo-audit is not installed` because the SSH PATH did not include `/home/ubuntu/.cargo/bin`.

- Observation: The explicit-range timestamp RPC path had a storage fail-open shape even though timestamp range admission was already Lean-conformance checked.
  Evidence: The old `block_timestamps` path converted `header_by_hash` failures through `.ok().flatten()`, so a corrupt canonical header could be indistinguishable from a missing height. The new `timestamp_meta_by_height` helper returns `Result<Option<NativeBlockMeta>>`, the blueprint requires `block_timestamps` to propagate it, and `timestamp_rpc_rejects_corrupt_explicit_range_header` now corrupts genesis metadata and observes a `trailing bytes` error.

- Observation: Sync range admission was correct but response materialization could still lie by omission.
  Evidence: `native_sync_response_range` capped the requested window correctly, but the old `block_range` loop used `break` on missing canonical height rows or missing block records and then returned `Ok(blocks)`. The new `block_range_rejects_missing_canonical_height_inside_admitted_range`, `block_range_rejects_missing_header_inside_admitted_range`, and `block_range_rejects_height_index_pointing_to_wrong_header` tests prove those cases now return errors.

- Observation: Wallet archive RPCs were weaker than startup reload validation.
  Evidence: Startup canonical state reload already rejects malformed commitment keys/values and gaps before trusting state, but `wallet_commitments` skipped bad rows and `ciphertext_entries_page` skipped bad ciphertext keys while serving unchecked values. The new archive row helpers and focused wallet tests make exported wallet pages fail closed on those corrupt sled rows.

## Decision Log

- Decision: Add a separate blueprint file instead of overloading the claims ledger schema in place.
  Rationale: The claims ledger is the release-facing summary of security posture. The blueprint DAG is a methodology artifact that adds target review, dependencies, and falsification cases. Keeping it separate lets CI cross-check the two files and makes graph drift visible without making each claim entry too large.
  Date/Author: 2026-06-06 / Codex.

- Decision: Enforce the blueprint now with Rust and JSON rather than waiting for Lean.
  Rationale: Lean is the right long-term destination for theorem-grade claims, but the immediate failure mode is not theorem-prover weakness. It is stale or vague claim management. A strict JSON DAG can reject cycles, missing review, missing implementation bindings, and untested production claims today.
  Date/Author: 2026-06-06 / Codex.

- Decision: Keep non-production residual-risk nodes in the blueprint and require them to pass target review as scoped residuals.
  Rationale: Disabled or candidate surfaces still affect the release posture. They should remain visible in the dependency graph, but target review must not be described as production acceptance or cryptographic approval.
  Date/Author: 2026-06-06 / Codex.

- Decision: Require every claims-ledger evidence path to appear in either the blueprint node's implementation paths or evidence paths.
  Rationale: This turns the blueprint into a real cross-check instead of a parallel prose file. If the ledger points at evidence that the blueprint does not cover, the gate fails as claim/blueprint drift.
  Date/Author: 2026-06-06 / Codex.

- Decision: Prepend `$HOME/.cargo/bin` inside `scripts/check_formal_core.sh` when that directory exists.
  Rationale: CI and VPS validation should find Cargo-installed tools in non-interactive shells without requiring global symlinks. The script still fails clearly if `cargo-audit` is genuinely missing.
  Date/Author: 2026-06-06 / Codex.

- Decision: Treat timestamp metadata lookup as part of RPC implementation equivalence, not as advisory display logic.
  Rationale: Wallets, explorers, and monitoring tools use native RPCs to reason about canonical history. Returning a truncated or partially decoded timestamp list after corrupt storage hides a state-integrity fault. Propagating metadata decode errors keeps the RPC aligned with the same fail-closed stance used by startup reload and sync admission.
  Date/Author: 2026-06-12 / Codex.

- Decision: Treat admitted sync response materialization and wallet archive row decoding as implementation-equivalence gates.
  Rationale: A formally checked range or page cap is not enough if the production code can skip corrupt rows after admission. The release branch should either return rows that match the canonical storage invariant or fail closed with an error. This keeps peer sync, wallets, and monitoring from treating local corruption as an empty or shorter valid response.
  Date/Author: 2026-06-12 / Codex.

## Outcomes & Retrospective

The branch now has a stricter formal-core gate that treats formal-security claims as a reviewed dependency graph instead of isolated checklist rows. The new gate catches missing blueprint nodes, claim/blueprint branch drift, dangling dependencies, dependency cycles, path escapes, missing implementation/evidence bindings, missing accepted target review for production claims, and missing falsification cases.

This is still not a full formal proof of Hegemon's Rust implementation. It is an enforceable release methodology layer that makes the next Lean or model-checking work sharper by keeping claim targets, assumptions, scope boundaries, and cheap counterexamples explicit.

2026-06-12 update: The timestamp RPC storage-materialization slice shows how this blueprint work now catches implementation-equivalence failures, not just missing formal metadata. Range admission was already modeled, but storage metadata lookup still swallowed corrupt canonical rows. The new binding forces the production RPC to propagate header lookup/decode failures, and the `hegemon-dev` deployment confirmed the formal gate, focused regression, transaction compatibility test, service restart, and live mining all work on the branch.

## Context and Orientation

The active branch is `codex/formal-blueprint-dag`. Hegemon is a Rust workspace for a post-quantum proof-native chain. The release formal-core gate is the script `scripts/check_formal_core.sh`. It invokes the standalone Rust checker crate under `scripts/hegemon_formal_core`, which is deliberately not a member of the root workspace so its lockfile and dependency audit are isolated.

The file `config/formal-security-claims.json` is the flat security claims ledger. A claim is a named security promise such as `bridge.message-root-replay` or `proof.native-backend-vectors`. A production-eligible claim is one the project treats as enforceable for release. A residual risk is an explicitly tracked reason a claim is not production-ready.

The new term in this plan is "blueprint DAG." A DAG is a directed acyclic graph: each node has an id, and each dependency arrow points from a node to an earlier supporting node. "Acyclic" means no node can depend on itself, directly or indirectly. In this repository the blueprint DAG will be a JSON file at `config/formal-security-blueprint.json`. It is inspired by the Lean blueprint pattern, but it is not a Lean proof file yet. Its purpose is to keep the claim graph explicit and machine-checked until claims are mechanized in Lean or another proof assistant.

## Plan of Work

First, create `config/formal-security-blueprint.json`. The file will have `schema_version`, `generated_for_branch`, `methodology`, and `nodes`. Every node will include:

- `id`, matching a claim id from `config/formal-security-claims.json`.
- `kind`, one of `target_claim`, `supporting_claim`, or `residual_risk`.
- `claim_id`, matching `id`, so the file is easy to query and hard to misread.
- `formal_statement`, a precise statement of what is being claimed.
- `informal_argument`, a human-readable explanation of why the evidence supports the statement.
- `depends_on`, a list of other blueprint node ids.
- `implementation_paths`, repository paths that bind the claim to code or operational scripts.
- `evidence_paths`, repository paths that should overlap or extend the claims ledger evidence.
- `target_review`, with `status`, `reviewer`, `reviewed_at`, and `notes`.
- `falsification_cases`, cheap counterexample or negative-test attempts that must exist for production claims.
- `scope_boundary`, describing what the node does not prove.

Second, extend `scripts/hegemon_formal_core/src/lib.rs` with parsing and validation for this blueprint. The validation must reject:

- Unsupported schema versions.
- Empty node sets.
- Duplicate ids.
- Node ids not present in the claims ledger.
- Claims ledger entries with no blueprint node.
- Mismatched `id` and `claim_id`.
- Unknown `kind` or target-review status.
- Empty formal statements, informal arguments, implementation paths, evidence paths, or scope boundaries.
- Missing repository paths.
- Dangling dependencies.
- Self-dependencies and dependency cycles.
- Production-eligible claims whose target review is not accepted.
- Production-eligible claims with no falsification case.
- Production-eligible claims whose blueprint node is `residual_risk`.

Third, add a `check-blueprint` subcommand in `scripts/hegemon_formal_core/src/main.rs`. It will accept:

    check-blueprint <path> --claims <claims-ledger-path>

Fourth, update `scripts/check_formal_core.sh` so the formal-core gate has a dedicated blueprint-DAG step.

Fifth, update documentation. `DESIGN.md` and `METHODS.md` should say the formal-core gate now checks a claims ledger and a blueprint DAG. The formal READMEs and review docs should remain honest: this is not yet a machine-checked proof of all Hegemon semantics; it is a stricter release methodology gate and an explicit dependency graph.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

Create and validate the branch:

    git switch -c codex/formal-blueprint-dag
    git status --short --branch

After edits, run:

    cargo fmt --manifest-path scripts/hegemon_formal_core/Cargo.toml -- --check
    cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml
    bash scripts/check_formal_core.sh

The expected final script output includes:

    === Hegemon formal-core gate passed ===

Observed output on 2026-06-06:

    [6/9] Checking formal security blueprint DAG
    {
      "edges": 10,
      "falsification_cases": 12,
      "nodes": 8,
      "passed": true,
      "production_nodes": 6
    }
    === Hegemon formal-core gate passed ===

## Validation and Acceptance

The change is accepted when:

1. `bash scripts/check_formal_core.sh` exits 0 and prints a blueprint-DAG report.
2. `cargo test --manifest-path scripts/hegemon_formal_core/Cargo.toml` exits 0 and includes tests for cycle detection and production-review enforcement.
3. `config/formal-security-blueprint.json` contains exactly one node per current security claim.
4. Documentation states the new gate clearly without claiming full machine-checked verification of the implementation.

## Idempotence and Recovery

The new checker is read-only. Running it repeatedly does not mutate repository files. If a blueprint edit fails validation, fix the JSON and rerun `bash scripts/check_formal_core.sh`. If the checker code fails to compile, rerun `cargo fmt --manifest-path scripts/hegemon_formal_core/Cargo.toml` and then the checker tests.

## Artifacts and Notes

The important artifacts will be:

    config/formal-security-blueprint.json
    scripts/hegemon_formal_core/src/lib.rs
    scripts/hegemon_formal_core/src/main.rs
    scripts/check_formal_core.sh
    DESIGN.md
    METHODS.md

## Interfaces and Dependencies

In `scripts/hegemon_formal_core/src/lib.rs`, define:

    pub struct BlueprintReport {
        pub nodes: usize,
        pub edges: usize,
        pub production_nodes: usize,
        pub falsification_cases: usize,
        pub passed: bool,
    }

    pub fn check_blueprint_file(path: &Path, claims_path: &Path) -> Result<BlueprintReport>

The checker must remain standalone and must not depend on production protocol crates such as `protocol-kernel`, `consensus`, or `hegemon-node`.

Revision note 2026-06-06T05:52:34Z: Created this plan after reviewing the existing formal-core branch and deciding to add a JSON blueprint DAG as the next enforceable formal-assurance layer.

Revision note 2026-06-06T06:13:00Z: Recorded the implemented blueprint DAG file, checker command, shell-gate wiring, documentation updates, focused regression tests, and passing local formal-core validation.

Revision note 2026-06-06T06:19:00Z: Recorded the `hegemon-dev` non-interactive PATH discovery and the shell wrapper fix that makes Cargo-installed audit tools visible.

Revision note 2026-06-12T07:19:02Z: Recorded the timestamp RPC fail-closed implementation-equivalence slice, including the new storage metadata helper, blueprint binding, focused regression, and local formal/node/release validation.

Revision note 2026-06-12T07:31:25Z: Recorded `hegemon-dev` deployment evidence for the timestamp RPC slice, including remote formal-core counts, release binary hash, service restart, RPC smoke, wallet submission compatibility, focused regression, NTP/environment posture, and mining advancement.

Revision note 2026-06-12T07:42:01Z: Recorded the local sync response and wallet archive materialization fail-closed slice, including the new production helpers, focused regressions, blueprint count increase, discoveries, and rationale. Remote deployment remains pending until the full local gates pass.
