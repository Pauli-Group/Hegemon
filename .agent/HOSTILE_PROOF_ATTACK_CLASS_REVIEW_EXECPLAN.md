# Hostile Proof Attack-Class Review

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md).

## Purpose / Big Picture

This work answers a specific security question: whether Hegemon’s proof system is vulnerable to the same broad attack classes highlighted in the 2026 Trail of Bits write-up about Google’s zero-knowledge proof pipeline. After this work, a reviewer should be able to point at the exact proof-carrying byte surfaces, see which ones exact-consume and canonicalize untrusted bytes, and run the recursive and transaction proof tests to confirm that the shipped proof stack rejects malformed or stale encodings instead of silently accepting them.

## Progress

- [x] (2026-04-17 15:11Z) Read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md` before touching proof code.
- [x] (2026-04-17 15:11Z) Read the external attack description and reduced it to two Hegemon-relevant classes: unchecked proof-byte deserialization and verifier-side semantic aliasing/stale assumptions.
- [x] (2026-04-17 15:11Z) Reproduced a live high issue: `cargo test -p block-recursion prove_and_verify_recursive_artifact_succeeds -- --nocapture` fails because recursive witness reconstruction still assumes the retired nested-`bincode` SmallWood inner proof object.
- [x] (2026-04-17 16:02Z) Fixed recursive witness reconstruction to canonicalize the live compact SmallWood proof bytes and removed the stale nested-`bincode` assumption.
- [x] (2026-04-17 17:24Z) Hardened transaction, SmallWood, manifest, disclosure, batch, block-commitment, and tx-leaf proof wrappers to exact-consume and canonical round-trip semantics on the live trust boundaries.
- [x] (2026-04-17 19:41Z) Fixed additional high issues uncovered during reruns: recursive profile routing drift, compact DECS auth-path assumptions in the local recursive verifier, and stale exact-width handling for the padded outer recursive proof field.
- [x] (2026-04-17 22:58Z) Reran targeted hostile security review and proof-boundary tests until no critical or high issues remained on the audited shipped surfaces.

## Surprises & Discoveries

- Observation: the active shipped tx proof is already well-defended at the inner proof layer; the current weak seam is the outer wrapper and older recursive witness-reconstruction glue.
  Evidence: `circuits/transaction/src/smallwood_engine.rs` already exact-consumes the compact proof bytes and reserializes canonically, while `circuits/block-recursion/src/relation.rs` still tries `bincode::deserialize_from::<SmallwoodProof>`.

- Observation: the recursive block lane is not merely at theoretical risk; it is presently broken against the new compact SmallWood inner proof format.
  Evidence:
    `cargo test -p block-recursion prove_and_verify_recursive_artifact_succeeds -- --nocapture`
    failed with:
    `InvalidField("construct StepB relation failed: constraint system violated: recursive proof envelope proof length mismatch")`

- Observation: the first recursive fix exposed a second high issue: recursive prove/verify helpers were still defaulting to the active tx proof profile instead of the arithmetization-specific legacy profile used by `Bridge64V1`.
  Evidence:
    after the first reconstruction fix, the same shipped recursive test failed deeper with
    `recursive proof envelope proof length mismatch` and then `piop transcript hash mismatch`
    until `smallwood_engine`, `smallwood_recursive`, and `local_smallwood_poseidon2` were routed through `smallwood_no_grinding_profile_for_arithmetization(...)`.

- Observation: the current compact DECS auth-path encoding is shorter than the older equal-length path assumption the local recursive verifier still enforced.
  Evidence:
    the local verifier only stabilized after `decs_recompute_root(...)` and shape validation in `circuits/block-recursion/src/local_smallwood_poseidon2.rs` were ported to the compact auth-path semantics already used in the active tx backend.

- Observation: the outer fixed-width recursive artifact field needed prefix decoding, not exact-width decoding.
  Evidence:
    the shipped verifier only became correct after `circuits/block-recursion/src/verifier.rs` switched to `decode_smallwood_proof_trace_prefix_v1(...)`, canonical prefix reserialization, and explicit zero-padding checks on the remainder of the fixed proof field.

## Decision Log

- Decision: treat this as a proof-boundary hardening task, not a broad “audit everything in the monorepo” task.
  Rationale: the user asked about a specific proof-system attack class. The relevant surfaces are untrusted proof/artifact bytes and verifier-side semantic routing, not unrelated networking or storage code.
  Date/Author: 2026-04-17 / Codex

- Decision: fix the live recursive proof-format regression before adding new hardening.
  Rationale: a broken shipped recursive verifier path is a higher-severity issue than theoretical decode malleability.
  Date/Author: 2026-04-17 / Codex

## Outcomes & Retrospective

The hostile review ended clean on the audited proof surfaces.

The exact attack-class answer is now:

1. Hegemon is not a programmable zkVM, so the register-aliasing / semantic-aliasing class from the Trail of Bits write-up does not map directly onto the fixed `TransactionWitness -> statement -> proof` relations shipped here.
2. Hegemon did have real exposure to the malformed-byte / stale-verifier-assumption class. Those issues were live, reproducible, and high-severity on the proof stack until this pass.

The completed fixes are:

* outer `TransactionProof` wrappers and SmallWood candidate wrappers exact-consume and require canonical serialization;
* shipped/compat proof carriers (`tx-proof-manifest`, disclosure proofs, batch proofs, block commitment proofs, tx-leaf artifacts) now do the same at their live trust boundaries;
* recursive witness reconstruction now canonicalizes the compact SmallWood inner proof bytes instead of decoding the retired nested-`bincode` object;
* recursive prove/verify helpers now derive the no-grinding profile from the arithmetization tag instead of silently defaulting to the active tx proof profile;
* the local recursive verifier now accepts and validates compact DECS auth paths using the same reconstruction semantics as the active tx backend;
* the outer recursive artifact verifier now decodes a canonical proof prefix from the padded fixed-width field and requires zero padding after the consumed prefix.

After those fixes and the targeted reruns, no remaining critical or high issues were found on the audited shipped proof-byte boundaries.

## Context and Orientation

The active transaction proof backend lives in `circuits/transaction`. The most relevant files are `circuits/transaction/src/smallwood_engine.rs`, which defines the compact inner SmallWood proof wire format and verifier, `circuits/transaction/src/smallwood_frontend.rs`, which wraps the inner proof in a SmallWood candidate proof object, and `circuits/transaction/src/proof.rs`, which defines the outer `TransactionProof` wrapper used by consensus and artifact builders.

The active recursive block proof path lives in `circuits/block-recursion`. The file `circuits/block-recursion/src/relation.rs` reconstructs recursive witnesses from proof-carrying words, while `circuits/block-recursion/src/tests.rs` provides end-to-end tests for the shipped recursive block artifact.

Consensus consumes these proof objects through `consensus/src/proof.rs`. Historical inline transaction artifacts are still decoded there for explicit compatibility lanes, so those decoders must fail closed even if they are not the shipped default lane.

In this repository, “exact-consume” means a decoder must reject any trailing bytes after the claimed object. “Canonical serialization” means the object must reserialize to the exact same bytes that were provided. “Proof-carrying bytes” means any untrusted byte string that is later interpreted as a transaction proof, a SmallWood candidate proof wrapper, or a recursive proof envelope.

## Plan of Work

First, repair recursive witness reconstruction in `circuits/block-recursion/src/relation.rs`. The current helper that scans witness-carried proof bytes still assumes `SmallwoodProof` can be decoded and reserialized through `bincode`. Replace that assumption with the live compact proof trace helpers from `transaction_circuit`: decode the proof bytes with `decode_smallwood_proof_trace_v1`, then reserialize them with `encode_smallwood_proof_trace_v1`, and accept only byte strings that round-trip exactly.

Second, harden the outer proof wrappers. In `circuits/transaction/src/smallwood_frontend.rs`, rewrite `decode_smallwood_candidate_proof` so it exact-consumes current and legacy wrappers and rejects any non-canonical or trailing-byte encoding. In `circuits/transaction/src/proof.rs`, add a public exact decoder for the outer `TransactionProof` wrapper. Route compatibility proof decoders in `consensus/src/proof.rs` and `circuits/tx-proof-manifest/src/lib.rs` through that helper so untrusted inline proof bytes are handled consistently.

Third, add regression tests close to the affected seams. The transaction proof tests should cover trailing bytes on both the SmallWood wrapper and the outer `TransactionProof` wrapper. The block-recursion regression is the existing shipped recursive artifact test; it failed before the fix and must pass after the fix. If additional critical/high issues appear during reruns, they must be fixed in the same pass and recorded here. That happened in practice: the follow-up reruns exposed recursive profile-routing drift, compact-auth-path assumptions, and stale fixed-width recursive-proof decoding, and those fixes were folded into the same hostile review.

## Concrete Steps

Work from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

Reproduce the recursive regression:

    cargo test -p block-recursion prove_and_verify_recursive_artifact_succeeds -- --nocapture

Expected pre-fix failure:

    InvalidField("construct StepB relation failed: constraint system violated: recursive proof envelope proof length mismatch")

After implementing the fixes, run:

    cargo test -p transaction-circuit malformed_smallwood_wrapper_fails_closed_for_profile_digest -- --nocapture
    cargo test -p transaction-circuit trailing_bytes_in_smallwood_wrapper_fail_closed_for_profile_digest -- --nocapture
    cargo test -p transaction-circuit decode_transaction_proof_bytes_exact_rejects_trailing_bytes -- --nocapture
    cargo test -p block-recursion prove_and_verify_recursive_artifact_succeeds -- --nocapture
    cargo check -p transaction-circuit -p tx-proof-manifest -p consensus -p block-recursion
    git diff --check -- circuits/transaction/src/smallwood_frontend.rs circuits/transaction/src/proof.rs circuits/tx-proof-manifest/src/lib.rs consensus/src/proof.rs circuits/block-recursion/src/relation.rs DESIGN.md METHODS.md .agent/HOSTILE_PROOF_ATTACK_CLASS_REVIEW_EXECPLAN.md

The `block-recursion` test is expensive. If it is still proving, wait; do not interrupt it and assume success.

## Validation and Acceptance

Acceptance is behavioral.

The transaction proof acceptance criteria are:

1. A malformed SmallWood wrapper with random bytes is rejected.
2. A valid SmallWood wrapper with extra trailing bytes is rejected.
3. A valid outer `TransactionProof` with extra trailing bytes is rejected.

The recursive proof acceptance criteria are:

1. The shipped recursive artifact test `prove_and_verify_recursive_artifact_succeeds` passes.
2. The pass is on the current compact SmallWood proof serializer, not by reviving the old nested-`bincode` proof object.
3. The outer recursive artifact verifier accepts only a canonical compact proof prefix plus zero padding inside the fixed proof field.

The security-review acceptance criteria are:

1. No remaining critical or high issues are found on the audited proof-byte boundaries.
2. The closing note explains explicitly whether Hegemon is or is not vulnerable to the same attack classes, and why.

## Idempotence and Recovery

These edits are safe to repeat. The decode hardening is purely additive from a security perspective: it narrows accepted inputs instead of widening them. If a change breaks a test, rerun the exact failing command and inspect the affected decoder. Do not revert unrelated proof-size or backend work; the task is to align decoders with the current compact proof format, not to roll back the proof backend.

## Artifacts and Notes

Relevant evidence from the initial hostile review:

    cargo test -p block-recursion prove_and_verify_recursive_artifact_succeeds -- --nocapture

    thread 'tests::prove_and_verify_recursive_artifact_succeeds' panicked at
    circuits/block-recursion/src/tests.rs:184:53:
    called `Result::unwrap()` on an `Err` value:
    InvalidField("construct StepB relation failed: constraint system violated:
    recursive proof envelope proof length mismatch")

## Interfaces and Dependencies

The exact interfaces that must exist at the end of this work are:

- In `circuits/transaction/src/proof.rs`, define:

    pub fn decode_transaction_proof_bytes_exact(
        proof_bytes: &[u8],
    ) -> Result<TransactionProof, TransactionCircuitError>;

- In `circuits/transaction/src/smallwood_frontend.rs`, keep:

    pub(crate) fn decode_smallwood_candidate_proof(
        proof_bytes: &[u8],
    ) -> Result<SmallwoodCandidateProof, TransactionCircuitError>;

  but make it exact-consume and canonical for both the current wrapper and the legacy compatibility wrapper.

- In `circuits/block-recursion/src/relation.rs`, keep:

    fn decode_canonical_proof_from_witness_words_v1(
        proof_words: &[u64],
    ) -> Result<(Vec<u8>, SmallwoodProofTraceV1), TransactionCircuitError>;

  but make it validate the current compact proof serializer through `decode_smallwood_proof_trace_v1` and `encode_smallwood_proof_trace_v1`.

Revision note: created during the 2026-04-17 hostile proof-surface review after reproducing a live recursive block proof failure caused by stale inner-proof decoding assumptions. The plan records the exact attack classes under review and the concrete shipped surfaces to harden.
