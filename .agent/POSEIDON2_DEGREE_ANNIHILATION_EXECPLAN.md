# Poseidon2 Degree-Annihilation Cryptanalysis

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon uses Poseidon2 over the Goldilocks field inside transaction proofs for note commitments, nullifiers, Merkle nodes, and some SmallWood proof transcript paths. The paper `Top Gun: Degree Annihilation Attacks on Poseidon` introduces a new algebraic cryptanalysis framework against Poseidon-family permutations. After this work, a maintainer can run one script to reproduce the Hegemon-specific parameter extraction and degree-budget analysis, then read a checked-in report explaining whether the paper gives a practical attack against the active Hegemon Poseidon2-384 surface.

The observable outcome is a generated JSON report under `docs/crypto/`, a human cryptanalysis note under `docs/crypto/`, and review-scope text in `docs/SECURITY_REVIEWS.md` requiring future external auditors to consider this attack family.

## Progress

- [x] (2026-06-18T19:04Z) Read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, Hegemon Poseidon2 implementation files, the attached `2026-1254.pdf`, and existing security review docs.
- [x] (2026-06-18T19:04Z) Created this ExecPlan to preserve scope and acceptance criteria.
- [x] (2026-06-18T19:10Z) Added `scripts/analyze_poseidon2_degree_annihilation.py`, which parses active Poseidon2 constants, checks source shape, computes degree/cancellation budgets, and supports `--check`.
- [x] (2026-06-18T19:10Z) Generated `docs/crypto/poseidon2_degree_annihilation_report.json`.
- [x] (2026-06-18T19:10Z) Wrote `docs/crypto/poseidon2_degree_annihilation_cryptanalysis.md` and wired `docs/SECURITY_REVIEWS.md`, `docs/crypto/proving_attack_matrix.md`, `DESIGN.md`, and `METHODS.md`.
- [x] (2026-06-18T19:10Z) Ran focused validation: `python3 scripts/analyze_poseidon2_degree_annihilation.py --check` and `python3 -m py_compile scripts/analyze_poseidon2_degree_annihilation.py` both passed.

## Surprises & Discoveries

- Observation: Hegemon has two relevant Poseidon2 surfaces, not one.
  Evidence: `circuits/transaction-core/src/hashing_pq.rs` uses Poseidon2 for note/Merkle/nullifier hashing, and `circuits/transaction/src/smallwood_engine.rs` has a `SmallwoodTranscriptBackend::Poseidon2` transcript/XOF path.

- Observation: The paper's concrete attacks are reduced-round CICO-2/zero-test attacks, while Hegemon's consensus-critical digest surface exposes six Goldilocks elements.
  Evidence: the paper's Table 1 attacks use RF = 6, RP = 7 or 8, alpha = 3, and two output constraints; Hegemon constants pin width 12, rate 6, capacity 6, alpha = 7, RF = 8, RP = 22.

- Observation: Under an attacker-favorable two-full-round skip, Hegemon's first remaining partial-round input still has degree 49.
  Evidence: `python3 scripts/analyze_poseidon2_degree_annihilation.py --check` reports that reducing one effective alpha factor requires 43 coefficient cancellations before output constraints.

- Observation: A CICO-2-style final solver does not cover Hegemon's six-limb digest surface.
  Evidence: the generated report computes four residual output limbs after CICO-2 reuse, adding about 256 bits of field constraints if handled by root filtering.

## Decision Log

- Decision: Treat this as a cryptanalysis/report artifact, not a hot-path protocol patch.
  Rationale: The paper does not claim a full-round Poseidon2 break, and changing Hegemon's hash primitive without a concrete break would create avoidable migration risk. A reproducible parameter-specific review is the right immediate action.
  Date/Author: 2026-06-18 / Codex

- Decision: Use a conservative degree-budget model and make its assumptions explicit.
  Rationale: Full symbolic Groebner/resultant cryptanalysis of Hegemon's 12-word, 30-round Poseidon2 over Goldilocks is outside a repo-local script. The immediate engineering need is to determine whether the paper's method plausibly collapses below the 128-bit claim and to identify what an external reviewer must reproduce.
  Date/Author: 2026-06-18 / Codex

## Outcomes & Retrospective

Completed. The repository now contains a reproducible local cryptanalysis artifact for the ePrint 2026/1254 degree-annihilation result against Hegemon's active Poseidon2-384 surface. The local judgment is no practical break found, but external review is now explicitly required before treating this as accepted cryptography. The work deliberately avoided changing the primitive because the evidence points to a review obligation, not an emergency hash rotation.

Focused validation output:

    python3 scripts/analyze_poseidon2_degree_annihilation.py --check
    {
      "not_a_proof": "This report is an engineering cryptanalysis note, not a formal lower bound. It should be handed to an external Poseidon/Poseidon2 reviewer for a full Groebner/resultant or dedicated algebraic-search assessment.",
      "status": "no_practical_break_found",
      "summary": "The paper is a real review trigger, but its concrete reduced-round CICO-2 attacks do not transfer to Hegemon's full 6-limb Poseidon2-384 digest. Under a two-full-round skip grant, the first remaining partial input has degree 49; reducing one effective alpha factor requires 43 coefficient cancellations before output constraints, far beyond the paper-style control budget. A CICO-2-style solver also leaves four Hegemon output limbs unchecked, adding about 256 bits of residual field constraints if handled by root filtering."
    }

    python3 -m py_compile scripts/analyze_poseidon2_degree_annihilation.py
    # exited 0

## Context and Orientation

The active Hegemon Poseidon2 implementation lives in `circuits/transaction-core/src/poseidon2.rs`. It uses a width-12 state over Goldilocks, applies an initial linear layer, then four initial full external rounds, twenty-two internal partial rounds, and four final full external rounds. The constants are pinned in `circuits/transaction-core/src/constants.rs` and `circuits/transaction-core/src/poseidon2_constants.rs`.

`circuits/transaction-core/src/hashing_pq.rs` builds a sponge on top of this permutation. A sponge is a hash mode that absorbs input into some state words, repeatedly applies the permutation, and returns selected output words. Hegemon's sponge rate is six field elements and its capacity is six field elements, producing a 48-byte digest as six canonical Goldilocks limbs.

The new attack family is degree annihilation. It tries to choose an algebraic input family whose dominant high-degree terms cancel before selected partial S-boxes. For a one-variable restricted family, making an S-box input affine means cancelling all coefficients above degree one. With an S-box exponent alpha, one full S-box layer can raise the degree by alpha, so alpha = 7 imposes a much larger cancellation budget than the paper's cubic alpha = 3 examples.

## Plan of Work

First, add `scripts/analyze_poseidon2_degree_annihilation.py`. The script will parse the checked-in Rust constants directly, compute the active Poseidon2 shape, compute a conservative degree-budget table under attacker-favorable assumptions, and write `docs/crypto/poseidon2_degree_annihilation_report.json`.

Second, add `docs/crypto/poseidon2_degree_annihilation_cryptanalysis.md`. The note will describe the paper, the exact Hegemon surfaces, the model, the generated results, the judgment, and the residual work for external auditors.

Third, update `docs/SECURITY_REVIEWS.md` and the proving attack matrix so future reviews include degree-annihilation / skipping-class analysis for Poseidon2 and so the report is discoverable from the existing security-review workflow.

## Concrete Steps

Run every command from the repository root:

    cd /Users/pldd/Projects/Reflexivity/Hegemon

The main generation command will be:

    python3 scripts/analyze_poseidon2_degree_annihilation.py

The focused validation will be:

    python3 scripts/analyze_poseidon2_degree_annihilation.py --check

The expected validation behavior is that the script exits 0 after confirming the parsed constants match the expected Hegemon shape and that the conservative attack-cost floor remains above the 128-bit post-quantum claim.

## Validation and Acceptance

Acceptance is met when `python3 scripts/analyze_poseidon2_degree_annihilation.py --check` passes, the generated JSON report exists and contains the active parameter tuple, the human report explains the security judgment without overstating it as a proof, and `docs/SECURITY_REVIEWS.md` names degree annihilation as a required future Poseidon2 review family.

## Idempotence and Recovery

The analysis script is read-only except for rewriting its own generated report JSON. Re-running it should produce a stable file. If constants change, the `--check` mode should fail until the report and cryptanalysis note are deliberately refreshed.

## Artifacts and Notes

The generated JSON report and human cryptanalysis note will be the durable artifacts for this task.
