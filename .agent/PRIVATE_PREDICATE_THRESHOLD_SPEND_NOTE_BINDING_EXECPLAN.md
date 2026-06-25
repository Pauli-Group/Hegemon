# Private Predicate Threshold Spend Note Binding

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

Hegemon currently has single-key shielded notes: a note commitment hides `value`, `asset_id`, `pk_recipient`, `pk_auth`, `rho`, and `r`, and the spend proof links the hidden `pk_auth` to the spend secret. This work adds the data-model side for private predicate threshold notes without adding public signer sets, public m/n values, public approval counts, public approval nullifiers, or action-layer authorization fields. After the change, code can build a predicate threshold note whose hidden spend-policy opening contains `policy_root`, `threshold`, and policy commitment randomness; changing any of those values changes the consumed note commitment because the policy opening derives the hidden note `pk_auth` commitment slot. Single-key notes keep their existing commitment preimage and behavior.

## Progress

- [x] (2026-06-25T23:08:41Z) Read `AGENTS.md`, `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md`; confirmed the current note model is single-key and commitments are `value/asset_id/pk_recipient/pk_auth/rho/r`.
- [x] (2026-06-25T23:08:41Z) Traced note/witness/proof call sites in `circuits/transaction/src/note.rs`, `circuits/transaction/src/witness.rs`, `circuits/transaction-core/src/hashing_pq.rs`, and the fixed P3/SmallWood note commitment schedule.
- [x] (2026-06-25T23:28:43Z) Added predicate threshold policy-opening types and validation helpers in `circuits/transaction/src/note.rs`.
- [x] (2026-06-25T23:28:43Z) Added focused Rust tests for policy-root, threshold, and randomness binding; legacy single-key commitment preservation; and fail-closed malformed predicate witness data.
- [x] (2026-06-25T23:28:43Z) Updated `DESIGN.md`, `METHODS.md`, and `README.md` to document the private data-model binding and the remaining circuit predicate-satisfaction dependency.
- [x] (2026-06-25T23:28:43Z) Ran focused transaction-circuit tests successfully.
- [ ] Commit coherent changes.

## Surprises & Discoveries

- Observation: The current P3 note hash schedule has `COMMITMENT_ABSORB_CYCLES = 3`, exactly matching the legacy 18-field note commitment input length. Extending the raw note commitment preimage for every note would change legacy single-key commitments unless the circuit also gained a mode-dependent hash path.
  Evidence: `circuits/transaction-core/src/p3_air.rs` names three commitment absorb cycles, and `circuits/transaction-core/src/hashing_pq.rs` builds the legacy 18-element commitment input list.

- Observation: The full `cargo test -p transaction-circuit` run fails in two SmallWood expected-shape assertions outside this patch, while the focused note tests and the related witness-satisfaction checks pass.
  Evidence: `smallwood_frontend::tests::packed_smallwood_frontend_compact_bindings_inline_merkle_skip_initial_mds_matches_expected_shape` and `smallwood_frontend::tests::packed_smallwood_frontend_packed128_compact_bindings_inline_merkle_skip_initial_mds_matches_expected_shape` both reported `left: 84 right: 72` for `statement.raw_witness_len`; this patch does not modify `circuits/transaction/src/smallwood_frontend.rs`.

## Decision Log

- Decision: Keep `NoteData::commitment()` and `note_commitment()` byte-for-byte legacy for single-key notes, and represent predicate threshold note policy by deriving the hidden `pk_auth` commitment slot from `policy_root`, `threshold`, and policy randomness.
  Rationale: The user asked for the note/witness/data-model side and explicitly required preserving existing single-key notes. Reusing the hidden `pk_auth` slot lets predicate policy data affect the consumed note commitment without changing public action fields or forcing a broader circuit schedule change in this patch.
  Date/Author: 2026-06-25 / Codex

- Decision: Fail closed at the predicate witness helper if the witness-selected policy opening does not rederive the note's committed hidden policy key.
  Rationale: A witness-selected `policy_root` or `threshold` must not authorize a spend merely because it is present in witness data. The committed note opening remains the source of truth.
  Date/Author: 2026-06-25 / Codex

## Outcomes & Retrospective

Implemented the private data-model binding for predicate threshold notes. The change does not implement predicate satisfaction or public signature handling; future circuit/DSL work must prove the threshold policy against the already-bound private opening.

## Context and Orientation

The repository root is `/Users/pldd/.codex/worktrees/1ebb/Hegemon`. The key Rust crate is `circuits/transaction`, which exports `NoteData`, `InputNoteWitness`, `OutputNoteWitness`, and `TransactionWitness`. `NoteData` is the hidden note opening used by wallets and provers. Its `commitment()` method calls `transaction-core::hashing_pq::note_commitment`, which hashes the legacy fields into a 48-byte-style field digest. The `pk_auth` field is hidden inside the note opening and is already included in the commitment preimage; it is not a public action field.

A predicate threshold note is a note whose hidden `pk_auth` field is not a spend public key. Instead, it is a deterministic policy commitment key derived from a hidden policy opening. The policy opening contains a 48-byte `policy_root`, a private threshold integer, and 32 bytes of policy commitment randomness. The current patch does not implement the future predicate language or threshold approval checker. It adds the data-model binding needed so that future predicate satisfaction cannot choose an uncommitted policy root or threshold at spend time.

## Plan of Work

In `circuits/transaction/src/note.rs`, add `PredicateThresholdPolicyOpening` with the hidden `policy_root`, `threshold`, and `policy_randomness` fields. Add a method that validates a nonzero threshold and derives a 32-byte policy commitment key using a domain-separated BLAKE3 hash over those fields. Add a helper that builds a `NoteData` for predicate notes by setting `pk_auth` to that derived key, while leaving all other note fields unchanged. Add `PredicateThresholdSpendWitness` as the private witness-side wrapper and make its validation compare the derived key to the consumed note's `pk_auth`, returning `TransactionCircuitError` on any mismatch.

Keep `NoteData` unchanged so all existing single-key note construction remains source-compatible and the legacy commitment helper remains the canonical single-key commitment path. Add tests in the same module to prove the predicate helper changes commitments when policy root, threshold, or randomness changes; the legacy single-key commitment still has the old input shape and equals the old helper; and malformed or uncommitted predicate witness data is rejected.

Update `METHODS.md`, `DESIGN.md`, and `README.md` with a concise statement that this is a private note-opening binding only. The future circuit/predicate-VM work must prove predicate satisfaction and route active predicate notes through that verifier before predicate spends can be accepted.

## Concrete Steps

Run commands from `/Users/pldd/.codex/worktrees/1ebb/Hegemon`.

1. Edit `circuits/transaction/src/note.rs` to add the predicate threshold policy-opening types and tests.
2. Edit `METHODS.md`, `DESIGN.md`, and `README.md` to describe the data-model binding.
3. Run:

    cargo test -p transaction-circuit note::tests::predicate

4. If the focused filter misses tests because of module names, run:

    cargo test -p transaction-circuit predicate

5. Before committing, run:

    cargo test -p transaction-circuit note::tests

## Validation and Acceptance

Acceptance is a focused Rust test suite that demonstrates three behaviors. First, `predicate_note_commitment_changes_when_policy_opening_changes` must show that modifying `policy_root`, `threshold`, or policy randomness changes the derived hidden key and therefore the note commitment. Second, `single_key_note_commitment_shape_remains_legacy` must show that an ordinary `NoteData` still feeds the 18-element legacy commitment preimage and matches the old `note_commitment` helper. Third, `predicate_spend_witness_rejects_uncommitted_policy_opening` must show that a witness-selected policy opening with the wrong root, threshold, randomness, or a zero threshold fails closed before it can be treated as authorized.

## Idempotence and Recovery

The work is additive and safe to rerun. If tests fail, inspect the exact failing assertion and keep edits scoped to the note/witness helper and docs. Do not rewrite the P3/SmallWood note commitment schedule in this plan; that is a separate circuit feature because it would affect proof shape and formal vectors.

## Artifacts and Notes

Focused validation passed:

    cargo test -p transaction-circuit predicate
    result: 2 passed; 0 failed; 116 filtered out

    cargo test -p transaction-circuit note::tests
    result: 9 passed; 0 failed; 109 filtered out

Broader crate validation caveat:

    cargo test -p transaction-circuit
    result: 108 passed; 2 failed; 8 ignored
    failures:
      smallwood_frontend::tests::packed_smallwood_frontend_compact_bindings_inline_merkle_skip_initial_mds_matches_expected_shape
      smallwood_frontend::tests::packed_smallwood_frontend_packed128_compact_bindings_inline_merkle_skip_initial_mds_matches_expected_shape
    shared failure: assertion left == right failed for statement.raw_witness_len, left: 84, right: 72

## Interfaces and Dependencies

In `circuits/transaction/src/note.rs`, the new public interfaces should be:

    pub const PREDICATE_THRESHOLD_POLICY_COMMITMENT_DOMAIN: &[u8];

    pub struct PredicateThresholdPolicyOpening {
        pub policy_root: [u8; 48],
        pub threshold: u16,
        pub policy_randomness: [u8; 32],
    }

    impl PredicateThresholdPolicyOpening {
        pub fn validate(&self) -> Result<(), TransactionCircuitError>;
        pub fn policy_commitment_key(&self) -> Result<[u8; 32], TransactionCircuitError>;
        pub fn to_note_data(...) -> Result<NoteData, TransactionCircuitError>;
        pub fn validate_bound_to_note(&self, note: &NoteData) -> Result<(), TransactionCircuitError>;
    }

    pub struct PredicateThresholdSpendWitness {
        pub policy: PredicateThresholdPolicyOpening,
    }

    impl PredicateThresholdSpendWitness {
        pub fn validate_bound_to_note_opening(&self, note: &NoteData) -> Result<(), TransactionCircuitError>;
    }

Revision note: Initial plan created before code changes to keep the protocol-facing data-model work self-contained and restartable.

Revision note: Updated after implementation and validation to record the focused test pass and the unrelated full-crate SmallWood shape-test caveat.
