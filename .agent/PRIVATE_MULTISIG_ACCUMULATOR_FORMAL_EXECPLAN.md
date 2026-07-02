# Private multisig accumulator formal model

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` in this repository. It is self-contained so a contributor can restart from this file and the current working tree.

## Purpose / Big Picture

This change adds a private multisig authorization model for Hegemon shielded notes. After it lands, Hegemon has an executable formal/Rust conformance slice for stateful shielded approvals: each approval privately consumes an accumulator note and a signer capability note, advances the accumulator for one exact spend intent, and the final spender only receives the value note plus the accumulator note. The spender never receives a signer's long-term secret, and the public transaction shape remains the normal shielded transaction surface.

The behavior is visible by running the Lean vector generator and the Rust conformance test. The vectors include accepted and rejected cases for the required approval and final-spend scenarios.

## Progress

- [x] (2026-06-26T03:10Z) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, existing transaction authorization Lean modules, vector generators, Rust conformance tests, and formal-core wiring.
- [x] (2026-06-26T03:10Z) Created branch `codex/private-multisig-accumulator-formal`.
- [x] (2026-06-26T03:10Z) Chose an abstract executable accumulator kernel instead of a wallet UI or transaction-format migration.
- [x] (2026-06-26T03:29Z) Added Lean private multisig accumulator semantics and named theorems for required cases, including exact-intent one-shot approval and final-witness no-signer-long-term-secret facts.
- [x] (2026-06-26T03:29Z) Added generated Lean JSON vectors and the `gen_private_multisig_accumulator_vectors` Lake executable.
- [x] (2026-06-26T03:29Z) Added Rust pure conformance module/tests matching the Lean vectors.
- [x] (2026-06-26T03:29Z) Wired the new generator/test into `scripts/check_lean_formal.sh` and `scripts/check_formal_core.sh`.
- [x] (2026-06-26T03:29Z) Updated `DESIGN.md`, `METHODS.md`, and `README.md` with the private accumulator authorization boundary.
- [x] (2026-06-26T03:29Z) Ran focused Lean/Rust validation and `git diff --check`.
- [ ] Commit coherent changes.

## Surprises & Discoveries

- Observation: The existing transaction authorization slice already uses abstract executable Lean kernels plus generated vectors rather than attempting to prove deployed hash implementations directly.
  Evidence: `formal/lean/Hegemon/Transaction/SmallWoodSpendAuthorization.lean` and `circuits/transaction/src/smallwood_frontend.rs` compare Lean-generated JSON against Rust helpers.

- Observation: A broad `lake build Hegemon` was not needed for this slice and was interrupted under coordinator steering after reaching 175/189 modules without a failure.
  Evidence: Focused `lake build Hegemon.Transaction.PrivateMultisigAccumulator Hegemon.Transaction.GeneratePrivateMultisigAccumulatorVectors gen_private_multisig_accumulator_vectors` passed.

- Observation: The host filesystem reached 100% capacity during a post-format full test-target compile, but removing only Cargo incremental cache data was enough to rerun the focused library conformance test.
  Evidence: `CARGO_INCREMENTAL=0 cargo test -p transaction-circuit --lib private_multisig_accumulator -- --nocapture` passed with one test.

## Decision Log

- Decision: Model private multisig as an accumulator-note transition and final accumulator predicate, not as signatures, threshold signatures, MPC, or public cosigner metadata.
  Rationale: The user explicitly required the stateful shielded accumulator design, and the repo design documents keep shielded authorization inside note/circuit semantics rather than public account signatures.
  Date/Author: 2026-06-26 / Codex

- Decision: Add the model under `Hegemon.Transaction` and a pure Rust module in `transaction-circuit`.
  Rationale: The final authorization predicate is a transaction witness relation, and the existing formal/Rust conformance pattern for spend authorization already lives in that package.
  Date/Author: 2026-06-26 / Codex

- Decision: Do not claim deployed circuit integration.
  Rationale: This work adds a theorem-backed semantics and vector conformance slice only. It does not wire a new AIR/SmallWood witness relation or wallet UX.
  Date/Author: 2026-06-26 / Codex

## Outcomes & Retrospective

The focused formal/Rust semantics slice is implemented. It proves and vector-checks valid approval, duplicate signer rejection, wrong intent rejection, wrong policy rejection, below-threshold final rejection, exact-threshold final acceptance, final intent mismatch rejection, exact-intent one-shot approval, final-witness exclusion of signer long-term secrets, and public-shape exclusion of private accumulator/policy fields. Deployed circuit integration remains future work.

## Context and Orientation

Hegemon uses shielded notes. A note is a private piece of value that is spent by proving facts in a zero-knowledge transaction proof. The normal public transaction shape contains public nullifiers, output commitments, ciphertext hashes, and balance data. Private witness data, such as note openings and authorization secrets, must not become public fields.

The current single-owner authorization path is modeled in `formal/lean/Hegemon/Transaction/SpendAuthorization.lean` and `formal/lean/Hegemon/Transaction/SmallWoodSpendAuthorization.lean`. Their generator `formal/lean/Hegemon/Transaction/GenerateSmallWoodSpendAuthorizationVectors.lean` emits JSON that Rust tests consume in `circuits/transaction/src/smallwood_frontend.rs`.

This plan adds a separate model for private multisig custody. An "accumulator note" is a private note-like witness object that records an account, policy, exact spend intent, approval count, and private approval nullifiers/leaves. A "signer capability note" is a private one-use capability for a signer under a policy. The approval phase consumes both privately and produces the next accumulator note for the same account, policy, and intent with one new signer approval. The final spend consumes the value note plus the accumulator note and accepts only when the accumulator matches the exact account, policy, and spend intent and its private count reaches the private threshold.

## Plan of Work

Create `formal/lean/Hegemon/Transaction/PrivateMultisigAccumulator.lean` with structures for spend intent, policy, accumulator notes, signer capability notes, approval steps, value notes, final spends, and public transaction shape. The approval predicate must reject duplicate signer nullifiers and wrong intent or policy. The final predicate must reject below-threshold accumulators and intent mismatches and accept an exact-threshold accumulator.

Create `formal/lean/Hegemon/Transaction/GeneratePrivateMultisigAccumulatorVectors.lean` to emit JSON cases named for the required scenarios. Register it in `formal/lean/lakefile.lean` and import the model in `formal/lean/Hegemon.lean`.

Create `circuits/transaction/src/private_multisig_accumulator.rs` with pure Rust structures and predicates matching the Lean model. Export the module from `circuits/transaction/src/lib.rs` and add tests that load `HEGEMON_LEAN_PRIVATE_MULTISIG_ACCUMULATOR_VECTORS` when set or run `lake exe gen_private_multisig_accumulator_vectors` otherwise.

Wire `scripts/check_lean_formal.sh` and `scripts/check_formal_core.sh` so formal-core builds the new Lean files, generates the vector bundle, and runs the Rust conformance test.

Update `DESIGN.md` and `METHODS.md` to record the architecture boundary: private accumulator authorization is a shielded witness relation, not public signatures, and the public transaction surface remains unchanged.

## Concrete Steps

From `/Users/pldd/.codex/worktrees/3446/Hegemon`, run:

    cd formal/lean
    lake env lean Hegemon/Transaction/PrivateMultisigAccumulator.lean
    lake env lean Hegemon/Transaction/GeneratePrivateMultisigAccumulatorVectors.lean
    lake exe gen_private_multisig_accumulator_vectors

Then run:

    cargo test -p transaction-circuit private_multisig_accumulator -- --nocapture

The completed focused validation used:

    cd formal/lean && lake build Hegemon.Transaction.PrivateMultisigAccumulator Hegemon.Transaction.GeneratePrivateMultisigAccumulatorVectors gen_private_multisig_accumulator_vectors
    cd formal/lean && lake exe gen_private_multisig_accumulator_vectors
    CARGO_INCREMENTAL=0 cargo test -p transaction-circuit --lib private_multisig_accumulator -- --nocapture
    bash -n scripts/check_formal_core.sh && bash -n scripts/check_lean_formal.sh
    git diff --check

For formal-core wiring, run the focused script pieces first and then, if time permits:

    bash scripts/check_lean_formal.sh
    bash scripts/check_formal_core.sh

## Validation and Acceptance

The Lean generator must emit schema version 1 with exactly the seven required case names: `valid-approval-step`, `duplicate-signer-rejected`, `wrong-intent-rejected`, `wrong-policy-rejected`, `below-threshold-final-rejected`, `exact-threshold-final-accepted`, and `final-intent-mismatch-rejected`.

The Rust conformance test must parse that bundle and report that each Rust predicate result equals the Lean `expected_valid` value. The exact-threshold final case must be accepted, while below-threshold and final intent mismatch must be rejected.

## Idempotence and Recovery

All added commands are read-only or build/test commands except source edits. Vector generation writes to stdout and is safe to repeat. If a generated-vector test fails, inspect the named case first because every vector carries all predicate inputs.

## Artifacts and Notes

The final work should include the new Lean model, generator, Rust module, script wiring, and documentation updates. Do not push the branch.

## Interfaces and Dependencies

In `formal/lean/Hegemon/Transaction/PrivateMultisigAccumulator.lean`, define:

    approvalStepAccepted : ApprovalStep -> Bool
    finalSpendAccepted : FinalSpend -> Bool
    publicShapeFromFinalSpend : FinalSpend -> PublicTransactionShape

In `circuits/transaction/src/private_multisig_accumulator.rs`, define matching public Rust helpers:

    pub fn approval_step_accepted(step: &ApprovalStep) -> bool
    pub fn final_spend_accepted(spend: &FinalSpend) -> bool
    pub fn public_shape_from_final_spend(spend: &FinalSpend) -> PublicTransactionShape

Revision note, 2026-06-26: Initial plan created after source orientation; it records the accumulator-note design and focused validation path.

Revision note, 2026-06-26: Updated after implementation to record the exact theorem/vector/Rust conformance scope, coordinator-directed interruption of the broad aggregate Lean build, focused validation evidence, and the remaining deployed-circuit integration gap.
