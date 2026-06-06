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

## Outcomes & Retrospective

The branch now has a stricter formal-core gate that treats formal-security claims as a reviewed dependency graph instead of isolated checklist rows. The new gate catches missing blueprint nodes, claim/blueprint branch drift, dangling dependencies, dependency cycles, path escapes, missing implementation/evidence bindings, missing accepted target review for production claims, and missing falsification cases.

This is still not a full formal proof of Hegemon's Rust implementation. It is an enforceable release methodology layer that makes the next Lean or model-checking work sharper by keeping claim targets, assumptions, scope boundaries, and cheap counterexamples explicit.

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
