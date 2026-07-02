# Formal Essence Core for Hegemon

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md`. It is self-contained: a reader with only this working tree can understand what was added, why it matters, and how to verify it.

## Purpose / Big Picture

Hegemon already has many local Lean proof files and production conformance gates. That is useful, but it makes the security story hard to see. This plan creates a small formal essence layer: one Lean model with `LedgerState`, `Action`, `Block`, `ObserverView`, and `Transition`, one theorem surface for the critical ledger and privacy properties, and one production-path refinement relation that says exact raw parser bytes, admitted action, replay, stored bytes, reload, and publication all refer to the same core action transition. After this change, contributors can point new proof work at `formal/lean/Hegemon/Essence/Core.lean` first, then refine detailed production paths into that model.

The observable result is a new generated vector gate. Running `cd formal/lean && lake exe gen_essence_core_vectors` emits the required core types, theorem names, production path stage order, assumption boundary, canonical term/encoding source, sample encoded cases, and progress items. Running `python3 scripts/check_essence_core_vectors.py <vectors> config/formal-essence-progress.json` verifies the emitted artifact and recomputes the goal percentage.

## Progress

- [x] (2026-06-20T02:07Z) Created `formal/lean/Hegemon/Essence/Core.lean` with the semantic core types, transition relation, action-chain and block lifting, production-path refinement relation, named external assumptions, and canonical encoding helpers.
- [x] (2026-06-20T02:07Z) Created `formal/lean/Hegemon/Essence/GenerateCoreVectors.lean` and exposed it through `formal/lean/lakefile.lean` as `gen_essence_core_vectors`.
- [x] (2026-06-20T02:07Z) Added `scripts/check_essence_core_vectors.py` and `config/formal-essence-progress.json` so the goal percent is checked from generated evidence.
- [x] (2026-06-20T02:07Z) Imported `Hegemon.Essence.Core` from `formal/lean/Hegemon.lean`.
- [x] (2026-06-20T02:07Z) Added the `formal.essence-core` claim and blueprint node.
- [x] (2026-06-20T02:07Z) Wired `gen_essence_core_vectors` and the checker into `scripts/check_formal_core.sh`.
- [x] (2026-06-20T02:07Z) Updated `DESIGN.md`, `METHODS.md`, and `formal/lean/README.md` to make the essence core the intended target for future proof work.
- [x] (2026-06-20T02:35Z) Ran full `bash scripts/check_formal_core.sh`; the 14-stage formal-core gate passed.
- [x] (2026-06-20T03:10Z) Refactored the essence core for elegance: derived nullifier/bridge replay uniqueness, witness-based authorization, per-asset balance semantics, receipt-bound bridge safety, exact-byte production refinement, fail-closed rejected paths, split local/global privacy assumptions, canonical public terms, canonical-term roundtrip/injectivity/non-malleability, and encoding no-truncation bounds.

## Surprises & Discoveries

- Observation: Lake executable entrypoints must expose `main` at the module root, not only inside a namespace.
  Evidence: `lake exe gen_essence_core_vectors` initially failed to link with `undefined symbol: main`; adding a root-level `def main` fixed it.
- Observation: The local Lean environment does not provide `List.bind` as field notation for lists.
  Evidence: `lake build Hegemon.Essence.Core` rejected `action.inputNullifiers.bind u64le`; defining a small `concatMap` helper fixed the canonical encoders.
- Observation: The blueprint DAG uses claim/node ids, not matrix property ids.
  Evidence: `check-blueprint` rejected dependency `node.replay-reorg-startup-refinement`; replacing it with `native.block-replay-refinement` and `native.codec-admission` made the blueprint pass.

## Decision Log

- Decision: Put the formal essence in a new namespace, `Hegemon.Essence.Core`, instead of refactoring the existing `Native` or `Transaction` modules.
  Rationale: The goal is proof compression and architectural clarity without destabilizing existing local proof files or production gates.
  Date/Author: 2026-06-20 / Codex.
- Decision: Model production refinement as an abstract parser -> admitted action -> replay -> storage -> publication relation in Lean, while keeping detailed Rust/native refinement in the existing production gates.
  Rationale: This gives a precise semantic target now and avoids pretending this one slice proves arbitrary Rust parser/storage behavior end to end.
  Date/Author: 2026-06-20 / Codex.
- Decision: Keep primitive crypto, deployed proof-system soundness, DA retention, storage durability, and global traffic privacy as named assumptions in the essence core.
  Rationale: Those are not discharged by small ledger semantics. Naming them prevents proof claims from silently absorbing cryptographic or system-model obligations.
  Date/Author: 2026-06-20 / Codex.
- Decision: Replace boolean action-admission facts with witness records and keep proof-bearing fields out of canonical public data.
  Rationale: The core should state what evidence must exist without pretending those evidence propositions are encoded bytes; canonical terms intentionally cover the public data projection.
  Date/Author: 2026-06-20 / Codex.
- Decision: Treat canonical byte encoding as generated from canonical public terms and prove term roundtrip/injectivity/non-malleability plus explicit fixed-width bounds.
  Rationale: This removes the useless reflexive encoding theorem and names the exact remaining boundary: byte-level parser equivalence remains a production/vector gate, while the Lean core now has a meaningful canonical data object.
  Date/Author: 2026-06-20 / Codex.
- Decision: Measure this goal with `config/formal-essence-progress.json`, not by changing the older highest-standard active-goal matrix.
  Rationale: The older matrix tracks a broader historical goal. This task asked for a new essence goal with its own percent measure.
  Date/Author: 2026-06-20 / Codex.

## Outcomes & Retrospective

The first implementation slice is complete under the formal-essence definition, and the core has been smoothed beyond the first draft. The core types exist; the requested core theorems build; uniqueness is derived instead of stored; authorization is witness-based; per-asset balances and bridge receipt metadata are modeled; production refinement carries exact raw/stored bytes plus fail-closed rejected paths; the named assumption boundary separates local projection privacy from global traffic assumptions; and canonical term/progress evidence is generated from the core source. This does not eliminate the broader detailed implementation-equivalence work; it gives that work a smaller semantic target.

## Context and Orientation

The main Lean import root is `formal/lean/Hegemon.lean`. New Lean modules live under `formal/lean/Hegemon`. Lake executable generators are declared in `formal/lean/lakefile.lean`. The main release/formal gate is `scripts/check_formal_core.sh`. The formal claims ledger is `config/formal-security-claims.json`, and the blueprint DAG is `config/formal-security-blueprint.json`.

The new core file is `formal/lean/Hegemon/Essence/Core.lean`. A `LedgerState` is the abstract chain state relevant to the essence proof: native supply, per-asset balances, spent nullifiers, commitments, and bridge replay keys. An `Action` is an abstract ledger mutation carrying nullifiers, output commitments, ciphertext tags, native mint/burn fields, per-asset deltas, optional spend/mint/asset/bridge authorization witnesses, and proof-statement binding evidence. A `Transition before action after` is the relation that says this action is accepted from one state to the next while satisfying supply integrity, derived nullifier uniqueness, bridge safety, no theft, per-asset conservation/isolation, ciphertext/commitment count binding, and encoding bounds. A `Block` is a list of actions. `ObserverView` is the public projection used for the local privacy theorem.

## Plan of Work

Create the core model in `formal/lean/Hegemon/Essence/Core.lean`. Keep the model small and executable where useful. Prove transition-level theorems for no counterfeiting, no double spend, no theft, asset isolation, bridge safety, and privacy projection. Prove chain/block lifting for supply and nullifier uniqueness. Add `ProductionPath` and `ProductionPathRefinement` so production stages collapse to a core transition. Add `NamedExternalAssumptions` to keep cryptographic and system assumptions visible. Add canonical encoding helpers in the same file so there is one source of truth for essence vectors.

Create `formal/lean/Hegemon/Essence/GenerateCoreVectors.lean` to emit a JSON artifact with the type set, theorem list, stage order, named assumptions, progress items, and sample canonical encodings. Register it as `gen_essence_core_vectors` in `formal/lean/lakefile.lean`.

Create `scripts/check_essence_core_vectors.py` to validate the generated artifact and compare it against `config/formal-essence-progress.json`. Wire that script and generator into `scripts/check_formal_core.sh`. Register the new claim in `config/formal-security-claims.json` and the new node in `config/formal-security-blueprint.json`.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    cd formal/lean && lake build Hegemon.Essence.Core Hegemon.Essence.GenerateCoreVectors Hegemon

Expect a successful Lean build. Then run:

    tmp=$(mktemp)
    (cd formal/lean && lake exe gen_essence_core_vectors > "$tmp")
    python3 scripts/check_essence_core_vectors.py "$tmp" config/formal-essence-progress.json
    rm -f "$tmp"

Expected output:

    formal essence core passed: 100.0%

Run the claims and blueprint checks:

    cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-claims config/formal-security-claims.json
    cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-blueprint config/formal-security-blueprint.json --claims config/formal-security-claims.json

Expect both commands to print JSON with `"passed": true`.

## Validation and Acceptance

Acceptance requires four observable results. First, Lean builds the new core and the full `Hegemon` import. Second, the generated vectors validate and report `formal essence core passed: 100.0%`. Third, the claims ledger resolves every named theorem and passes. Fourth, the blueprint DAG passes with the new node and no cycles or missing evidence paths.

The broader `bash scripts/check_formal_core.sh` should also pass before this work is treated as release-gated. That command is expensive because it runs the full existing formal-core suite.

## Idempotence and Recovery

The generated essence vectors are written to a temporary file and can be regenerated any number of times. The checker reads only the generated JSON and checked-in progress file. If the checker fails, inspect the missing type, theorem, stage, assumption, or progress item named in the error and fix the source in `formal/lean/Hegemon/Essence/Core.lean` or `formal/lean/Hegemon/Essence/GenerateCoreVectors.lean`.

The work is additive. It does not alter native runtime behavior or chain state. Recovery is to remove the `formal.essence-core` claim/node, remove the `Hegemon.Essence.Core` import, remove the generator from `lakefile.lean`, and remove the check from `scripts/check_formal_core.sh`.

## Artifacts and Notes

Targeted validation so far:

    formal essence core passed: 100.0%
    lake build Hegemon.Essence.Core Hegemon.Essence.GenerateCoreVectors Hegemon: Build completed successfully
    check-claims: claims=122, named_lean_theorems=2572, passed=true
    check-blueprint: nodes=122, edges=524, passed=true
    check_formal_core.sh: 14-stage formal-core gate passed; active goal progress measure weighted_completion_percent=100.0

## Interfaces and Dependencies

The new Lean interface is:

    namespace Hegemon.Essence.Core
    structure LedgerState
    structure Action
    structure Block
    structure ObserverView
    structure Transition (before : LedgerState) (action : Action) (after : LedgerState) : Prop
    structure ProductionPath
    structure ProductionPathRefinement (path : ProductionPath) : Prop

The new executable generator is:

    cd formal/lean && lake exe gen_essence_core_vectors

The new checker is:

    python3 scripts/check_essence_core_vectors.py <vectors.json> config/formal-essence-progress.json

Revision note (2026-06-20 / Codex): Created this plan after implementing the first formal essence slice so future contributors can restart from this document and understand why the small core exists, how it is gated, and what remains outside its assumption boundary.
