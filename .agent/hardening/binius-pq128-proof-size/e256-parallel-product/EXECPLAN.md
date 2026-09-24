# Establish the E256 parallel-product claim boundary

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be maintained
as work proceeds. This file follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon's compact proof screen uses two degree-two E256 algebraic branches over
one B128 commitment. Dividing the query budget into 132 bits per branch saves
substantial bytes only if the two complete errors multiply. This work gives a
reviewer one dependency-free command that states the precise conditional
theorem, demonstrates failures when any important hypothesis is removed,
reproduces the conditional byte rows, and refuses to promote them to strict
PQ128 or to the proof-size frontier.

## Progress

- [x] (2026-08-21T19:51:27Z) Read the relevant E256 seam, random-padding wire
  screen, strict PQ scaffold, `DESIGN.md`, `METHODS.md`, and `.agent/PLANS.md`.
- [x] (2026-08-21T19:51:27Z) Derived the filtration-level conditional product
  theorem and the stricter branch-local parallel corollary.
- [x] (2026-08-21T19:51:27Z) Added exact finite positive and negative controls
  for shared schedules, joint responses, average-only soundness, grinding, and
  split relation families.
- [x] (2026-08-21T19:51:27Z) Reproduced the q=44/rate-1/16 and q=33/rate-1/32
  byte formulas without allocating a codeword.
- [x] (2026-08-21T19:51:27Z) Made every current product, ROM, QROM, and frontier
  authority flag fail closed.
- [x] (2026-08-21T19:59:40Z) Ran the checker, 22 dependency-free tests, source
  pin checks, and the isolated whitespace check successfully.

## Surprises & Discoveries

- Observation: one immutable commitment is compatible with a product theorem,
  but the relevant premise is pointwise conditional soundness after every
  reachable accepting history, not marginal soundness.
  Evidence: the chain identity in `README.md` and the average-only finite
  counterexample, whose two half-error marginals have half-error intersection.

- Observation: domain separation does not prevent commitment grinding.
  Evidence: the exhaustive two-root ROM experiment has success `7/16`, versus
  `1/4` for either fixed root.

- Observation: the two source screens do not yet share one canonical root and
  transcript grammar.
  Evidence: `strict-e256x2-iop` uses a 64-byte Merkle root and 32-byte E256 XOF
  draws, while the older `m4-random-padding-zk-pcs` row prices a non-strict
  56-byte root. The corrected local rows charge 64-byte roots and frontiers.

- Observation: the 32-byte salt is a byte hypothesis, not a complete ZK
  parameter.
  Evidence: the direct classical BCS Lemma 3.4 n=`2^18` screen needs a
  148-byte salt charge to reach its stated 128-bit statistical term, and that
  still does not instantiate an adaptive QROM simulator.

- Observation: q=44 and q=33 exceed 132 bits only for the leading query term.
  Evidence: the calculator reports approximately 134.015 and 132.750 bits;
  neither source provides a complete per-branch error certificate.

## Decision Log

- Decision: Prove a conditional information-theoretic theorem locally and keep
  its instantiation flag false.
  Rationale: the chain-rule proof is exact, while the active protocol lacks the
  complete PCS/PIOP transcript and history-robust branch bound needed to invoke
  it.
  Date/Author: 2026-08-21 / Codex.

- Decision: Require independent proximity-query coins, not only independent
  E256 algebraic samples.
  Rationale: a reused query makes the two miss events identical and leaves the
  joint probability at one branch's error.
  Date/Author: 2026-08-21 / Codex.

- Decision: Treat cross-branch messages as forbidden unless the second-branch
  theorem quantifies over the complete resulting history and residual state.
  Rationale: this is the exact condition under which the filtration proof
  remains valid; a syntactic ban is sufficient but not mathematically
  necessary.
  Date/Author: 2026-08-21 / Codex.

- Decision: Preserve the project's square-root QROM arithmetic only as a
  screen, with no authority bit.
  Rationale: Grover-style exponent halving does not instantiate a multi-round
  measure-and-reprogram theorem or its concrete oracle-query loss.
  Date/Author: 2026-08-21 / Codex.

- Decision: Make no shared `DESIGN.md` or `METHODS.md` edits.
  Rationale: the delegated task explicitly scopes all changes to this isolated
  directory.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The isolated artifact now separates three claims that were previously easy to
conflate: exact multiplication in an ideal history-conditional experiment,
independence of fixed random-oracle outputs on disjoint domains, and soundness
of an adversarial Fiat--Shamir/QROM transcript. Only the first is proved. The
byte savings survive arithmetically but remain unauthorized. The executable
grammar now rejects 56-byte roots, emits disjoint 64-byte branch seeds, and
binds commitment order, but it remains plumbing. A future pass must implement
the complete two-branch PCS/PIOP and prove a concrete ROM/QROM compiler before
changing any authority flag.

## Context and Orientation

The committed symbol field B128 is the pinned 128-bit GHASH field. E256 is the
genuine quadratic extension `B128[Y]/(Y^2+X*Y+X)`. The active research idea
runs two E256 verifier branches over one B128 codeword commitment. The compact
random-padding screen prices independent query unions and assigns half of the
264-bit classical query budget to each branch. `parallel_product.py` is an
independent checker for that assignment. `test_parallel_product.py` exercises
the theorem boundary and exact wire formula. `README.md` is the human-review
contract and literature map.

An immutable commitment means that binding fixes one complete B128 oracle
before verifier challenges. A pointwise conditional error bound means that the
same numerical bound holds after conditioning on every reachable prior
history, not merely on average. QROM means the quantum random-oracle model, in
which the adversary may query the hash oracle on superpositions.

## Plan of Work

Keep all implementation in
`.agent/hardening/binius-pq128-proof-size/e256-parallel-product/`. The checker
must rehash its four source inputs, implement exact rational finite games,
reproduce the byte formula from constants rather than importing the candidate,
and serialize a report whose current authority flags remain false. The test
suite must cover both the positive product case and every counterexample.

No Cargo command, Binius prover, production proof, or encoded codeword is part
of this plan. No source outside the isolated directory is modified.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/e256-parallel-product/parallel_product.py \
      --check --report

Expect the first line:

    E256_PARALLEL_PRODUCT_CHECK_PASS

Then run:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-pq128-proof-size/e256-parallel-product/test_parallel_product.py \
      -v

Finally run `git diff --check` and confirm that no bytecode or temporary proof
artifact exists under the isolated directory.

## Validation and Acceptance

Acceptance requires all dependency-free tests to pass, every stable source pin
to match, q values 44 and 33, strict 32-byte-salt raw byte values 83,712 and
69,632, direct-BCS-salt raw values 93,920 and 77,288, and exact finite
counterexample probabilities `1/2`, `7/16`, and `1/2` where documented. The
report must keep `ideal_product_instantiated`, `qrom_product_instantiated`,
`strict_pq128_admitted`, and `frontier_eligible` false.

## Idempotence and Recovery

All commands are read-only except Python's default bytecode cache, which is
disabled with `PYTHONDONTWRITEBYTECODE=1`. They can be repeated safely. If a
source pin fails, inspect the changed source and update the contract only after
re-auditing its semantics; never refresh a digest mechanically.

## Artifacts and Notes

The intended final evidence is one checker pass, a complete unit-test pass, and
a clean whitespace check. The important negative evidence is retained in the
JSON report rather than converted into an authority claim.

## Interfaces and Dependencies

`parallel_product.py` uses only Python's standard library. Its public review
interfaces are `conditional_product_bound`, `TranscriptEvidence`,
`rate_profile`, `conditional_security_screen`, `report`, and `self_check`.
There are no network or third-party runtime dependencies.

Revision note 2026-08-21: created the self-contained plan and recorded the
conditional theorem, counterexamples, byte rows, source mismatches, and
fail-closed QROM boundary discovered during implementation.

Revision note 2026-08-21T19:59:40Z: corrected all qualifying commitment nodes
to SHAKE256-512, retained the 63,320-byte SHAKE448 row only as a negative
control, priced both the unproved 32-byte salt and 148-byte direct-BCS salt
floor, added executable 64-byte branch framing, and completed validation.
