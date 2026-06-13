# Highest-Standard Lean Formal Verification for Hegemon

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this file according to `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon should become the highest-standard Lean-formally-verified post-quantum privacy chain without turning the node into a slow research prototype. After this work, an operator, auditor, or contributor should be able to inspect a small set of top-level Lean theorems and see that the shipped native node admits only ledger transitions that preserve private-money safety: no unaccounted supply creation, no double spends, no unauthorized spends, correct commitment-tree evolution, per-asset conservation, exact proof-statement binding, fail-closed bridge and DA behavior, and release posture appropriate for a PQC chain. They should also be able to run one release gate, `bash scripts/check_formal_core.sh`, and see those theorem claims checked against production Rust entry points.

The coordinator thread owns this plan, the theorem matrix in `config/highest-standard-formal-verification-matrix.json`, the completion percentage, and integration back into `codex/superneo-formal-verification`. Subagents may audit or implement bounded slices, but this coordinator keeps the theorem targets coherent and prevents branch proliferation.

## Progress

- [x] (2026-06-13 04:14Z) Created the persistent Codex goal for highest-standard Lean formal verification on `codex/superneo-formal-verification`.
- [x] (2026-06-13 04:14Z) Confirmed the branch is clean at `19acdaab5b6bece8e0afcece57d8b4953ccfe36f`.
- [x] (2026-06-13 04:15Z) Started four read-only audit agents covering ledger invariants, proof-system boundaries, privacy/DA/bridge properties, and node/network/release refinement.
- [x] (2026-06-13 04:16Z) Added the first checked-in theorem matrix with weighted completion tracking. Initial highest-standard completion is 44.35%.
- [x] (2026-06-13 04:30Z) Integrated all four agent audit results into the theorem matrix. Current highest-standard completion is 59.46%.
- [x] (2026-06-13 05:06Z) Promoted supply and nullifier replay fragments into `Hegemon.Native.AcceptedChain` theorem targets. Current tracked completion is 60.00%.
- [x] (2026-06-13 05:18Z) Ran `bash scripts/check_formal_core.sh` for the `AcceptedChain` theorem slice; formal-core passed with 86 claims, 1074 named Lean theorems, 84 production-eligible claims, 365 falsification cases, and 177 implementation bindings.
- [ ] Add or strengthen production bindings for every native import/replay/startup path that can publish accepted state.
- [ ] Repeat `bash scripts/check_formal_core.sh` after each future theorem slice and deploy runtime-affecting validated heads to `hegemon-dev` for mining/transaction smoke.

## Surprises & Discoveries

- Observation: The current formal branch already has a broad formal-core gate, but its coverage is uneven when judged against highest-standard theorem/refinement criteria.
  Evidence: The last passing formal-core run at `19acdaab5b6bece8e0afcece57d8b4953ccfe36f` reported 86 theorem-backed claims and 1069 named Lean theorem declarations, while proof-system soundness and privacy remain mostly assumption-bound rather than fully mechanized.

- Observation: The strongest current areas are nullifier uniqueness, balance/conservation guardrails, statement binding, canonical encoding, replay/admission ordering, PQ channel engineering checks, and release/dependency posture.
  Evidence: Four read-only audit agents independently found no Lean `sorry`/`admit` holes in `formal/lean/Hegemon` and raised those matrix entries where the code has real theorem/vector/refinement evidence.

- Observation: The highest-value claims are still not fully proved: spend authorization, proof-system soundness, privacy/unlinkability/confidentiality, production bridge mint safety, and complete Rust/native-node refinement remain the main blockers.
  Evidence: Agents explicitly reported no end-to-end theorem that accepted spends imply authorized witnesses; no full deployed proof-system soundness theorem; no formal privacy game; and no complete raw-byte-to-state Rust refinement.

- Observation: The generated claim and blueprint metadata still named `codex/formal-equivalence-010`, a deleted historical branch.
  Evidence: `config/formal-security-claims.json` and `config/formal-security-blueprint.json` had `generated_for_branch` set to the old branch until this coordinator update.

- Observation: A local-only action-stream theorem is not enough for chain-wide double-spend safety because two individually accepted blocks can reuse a nullifier unless the modeled chain carries spent state across block boundaries.
  Evidence: The first accepted-chain draft accepted two copies of `validReplay`; the finalized `Hegemon.Native.AcceptedChain.validateNativeReplayChain` now threads `spentNullifiers` and rejects both stale spent-state and cross-block duplicate-nullifier replay.

## Decision Log

- Decision: Track completion with a weighted theorem matrix rather than a single informal percent.
  Rationale: Hegemon has many security properties with different importance. No-counterfeiting and proof-system soundness should count more than release-posture policy, while all of them must be visible. The matrix makes progress auditable and prevents overclaiming.
  Date/Author: 2026-06-13 / Codex.

- Decision: Use `codex/superneo-formal-verification` as the only formal verification branch and keep this coordinator thread responsible for integration.
  Rationale: Formal verification work must not sprawl across branches. The branch was straightened so `codex/superneo-formal-verification` carries the verified head, while `codex/superneo-experiment` remains the base line.
  Date/Author: 2026-06-13 / Codex.

- Decision: Define 100% completion as top-level theorem plus production binding, not just Lean helper lemmas or generated vector tests.
  Rationale: The user explicitly rejected claims without proof. A highest-standard property must be stated as a theorem, have explicit assumptions, be checked by CI, and be connected to the shipped code path.
  Date/Author: 2026-06-13 / Codex.

## Outcomes & Retrospective

The immediate outcome is a concrete target and tracking system: 18 critical formal property families, weighted to 100 total points. The initial conservative completion was 44.35%; after four read-only audits, the branch-local tracked completion is 59.46%. This is not a claim of full formal verification. It means the coordinator now has an evidence-weighted baseline for what is already strong and what still blocks the highest standard.

The first theorem slice adds `formal/lean/Hegemon/Native/AcceptedChain.lean`. It proves `accepted_native_replay_chain_no_counterfeiting` and `accepted_native_replay_chain_nullifier_preconditions` over parent-linked native replay chains with carried spent-nullifier state, plus concrete rejection theorems for counterfeit second-block supply, stale spent state, and duplicate cross-block nullifier replay. This raises the tracked baseline to 60.00% while leaving full raw-byte/native-node refinement, explicit `Nodup` nullifier theorem strength, storage crash semantics, proof-system soundness, and cryptographic assumptions open.

## Context and Orientation

The canonical branch is `codex/superneo-formal-verification`. The baseline commit is `19acdaab5b6bece8e0afcece57d8b4953ccfe36f`, which hard-disables legacy aggregation V4 and passed the full formal-core gate before branch cleanup. The formal sources live under `formal/lean`. The formal claim ledger is `config/formal-security-claims.json`, and the implementation-binding blueprint is `config/formal-security-blueprint.json`. The new theorem matrix is `config/highest-standard-formal-verification-matrix.json`.

The phrase "highest-standard formal verification" means more than having Lean files. For each critical property, the standard is: define the property as a top-level theorem over Hegemon's abstract ledger or node semantics; prove it in Lean or explicitly parameterize the cryptographic assumption needed; generate conformance evidence where Rust computes executable predicates; bind the shipped Rust entry points to those predicates; put the gates in `scripts/check_formal_core.sh`; and measure or avoid runtime cost when production code changes.

The phrase "little to no performance cost" means theorem work and CI gates should carry the weight wherever possible. Production runtime changes should be cheap admission checks, shared-helper reuse, exact parsers before expensive work, or existing replay planning. Any change that adds hashing, decoding, proof verification, tree replay, or sidecar scans on a hot path must include a benchmark or a clear argument that the computation already existed and was merely moved earlier.

## Plan of Work

First, keep the theorem matrix current. Each property entry has a stable id, a weight, a completion percentage, a theorem target, evidence, missing work, and a performance constraint. Whenever an agent proves a theorem, adds a production binding, or finds a gap, update the relevant entry and recompute `overall_completion_percent` as the weighted average.

Second, collapse helper-level facts into top-level theorems. The first target is `AcceptedNativeChainNoCounterfeiting`, which should combine the existing `Supply.lean` and `SupplyInvariant.lean` facts with native replay/import assumptions. The second target is accepted-chain nullifier uniqueness. These two properties have strong current evidence and high safety value.

Third, strengthen implementation refinement. The Rust paths in `node/src/native/mod.rs`, `consensus/src/pow.rs`, `consensus/src/reward.rs`, and proof-admission modules must call theorem-backed helpers before publishing state, mutating durable canonical indexes, or accepting blocks. The blueprint checker already supports implementation bindings, order constraints, result propagation, and dominance constraints; use those before inventing a new checker.

Fourth, make proof-system and privacy boundaries honest. If a theorem depends on STARK soundness, hash collision resistance, ML-KEM confidentiality, ML-DSA unforgeability, OS RNG quality, or native lattice backend assumptions, encode that dependency in the theorem statement or in a named assumption node. Do not mark those properties complete until the theorem target and assumption boundary are explicit.

Fifth, keep validation operational. Every major slice must pass `bash scripts/check_formal_core.sh`. If production code or deployment-relevant scripts change, update `hegemon-dev`, run mining and transaction smoke, and record the result.

## Concrete Steps

Work from `/private/tmp/hegemon-formal-work` on branch `codex/superneo-formal-verification`.

To inspect the goal and matrix:

    git switch codex/superneo-formal-verification
    python3 -m json.tool config/highest-standard-formal-verification-matrix.json >/tmp/hegemon-formal-matrix.pretty.json
    sed -n '1,120p' .agent/HIGHEST_STANDARD_LEAN_FORMAL_VERIFICATION_EXECPLAN.md

To recompute the overall percent after editing property percentages, use a small JSON-aware script or `jq` if available. The formula is:

    sum(property.weight * property.completion_percent) / sum(property.weight)

The current weights sum to 100, so the numerator divided by 100 is the displayed percent.

To validate formal work:

    bash scripts/check_formal_core.sh

To validate branch hygiene:

    cargo fmt --all --check
    git diff --check
    python3 -m json.tool config/highest-standard-formal-verification-matrix.json >/dev/null
    git status --short --branch

## Validation and Acceptance

The coordinator artifacts are accepted when `config/highest-standard-formal-verification-matrix.json` is valid JSON, this ExecPlan names the active branch and baseline commit, the completion percentage is defined by a reproducible formula, and `git status --short --branch` shows only intended changes before commit.

The overall goal is complete only when the matrix reaches 100% and the final branch passes `bash scripts/check_formal_core.sh`, targeted theorem/refinement tests, release/security gates, and `hegemon-dev` mining plus transaction smoke. A property cannot be set to 100% unless it has a named top-level theorem, explicit assumptions, production binding, and formal-core coverage.

## Idempotence and Recovery

The matrix and ExecPlan are additive documentation/control artifacts. They can be edited repeatedly. If an agent overstates a percentage, lower it and record the reason in the Decision Log. If a branch mistake occurs, recover by fetching `origin/codex/superneo-formal-verification` and resetting a clean worktree only after confirming there are no unrelated local edits to preserve.

## Artifacts and Notes

The branch cleanup before this plan left the remote formal surface as:

    codex/superneo-experiment
    codex/superneo-formal-verification

The verified baseline for this plan is:

    19acdaab5b6bece8e0afcece57d8b4953ccfe36f Hard-disable legacy aggregation V4

The last full formal-core pass at that baseline reported:

    claims=86
    named_lean_theorems=1069
    production_eligible_claims=84
    falsification_cases=365
    implementation_bindings=177

## Interfaces and Dependencies

The primary interface for progress tracking is `config/highest-standard-formal-verification-matrix.json`. The primary proof interface is Lean 4 under `formal/lean`. The primary production-binding interface is `config/formal-security-blueprint.json` plus the formal-core checker under `scripts/hegemon_formal_core`. The primary release gate is `scripts/check_formal_core.sh`.

Subagents should report findings in terms of matrix property ids. When a subagent changes code, it must own a disjoint write set and must not delete or rewrite another agent's work. The coordinator integrates, validates, commits, and deploys.

Revision note 2026-06-13 / Codex: Created this plan to turn the user's highest-standard formal verification goal into a branch-local coordinator artifact with explicit theorem targets and percentage tracking.
